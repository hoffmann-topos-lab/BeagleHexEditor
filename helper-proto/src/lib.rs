//! F-47 — Wire protocol between the privileged helper and its client.
//!
//! Both the root daemon (`helper`) and the client `DataSource`
//! (`core::source::helper`) speak this. Keeping it in one zero-dependency crate
//! is what stops the two sides from drifting apart.
//!
//! Framing: every message is a `u32` little-endian length followed by that many
//! payload bytes. The payload is a `u8` tag then fields, integers little-endian,
//! byte strings as a `u32` length + bytes. The decoder is bounds-checked at
//! every step — on the daemon side it parses input from an (already
//! UID-verified) client, but must still never trust lengths.

use std::io::{self, Read, Write};

/// Default socket path. A root-owned, restricted-permission location.
pub const DEFAULT_SOCKET: &str = "/var/run/hexhelper.sock";

/// Hard cap on a single read/write payload (16 MiB). A client asking for more
/// is malformed; the daemon rejects it rather than allocating unboundedly.
pub const MAX_CHUNK: u32 = 16 << 20;

/// Hard cap on a whole framed message.
pub const MAX_MESSAGE: u32 = MAX_CHUNK + 64;

/// Client → daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Open a device node. `writable` must be explicit (writing is opt-in).
    Open { path: String, writable: bool },
    /// Read `len` bytes at `offset` from an open handle.
    Read { handle: u32, offset: u64, len: u32 },
    /// Write `data` at `offset` to a writable handle.
    Write { handle: u32, offset: u64, data: Vec<u8> },
    /// Close a handle.
    Close { handle: u32 },
}

/// Daemon → client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Opened { handle: u32, size: u64, block_size: u32 },
    Data(Vec<u8>),
    Written,
    Closed,
    Error { kind: WireError, message: String },
}

/// Error categories on the wire. The client maps these to `core::ErrorKind`;
/// this crate stays independent of `core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Io,
    BadBlock,
    PermissionDenied,
    OutOfBounds,
    ReadOnly,
    NotResizable,
    Disconnected,
    /// The request was rejected by the daemon's policy (bad path, bad handle,
    /// oversized request). Never reached the filesystem.
    NotAllowed,
}

impl WireError {
    fn to_u8(self) -> u8 {
        match self {
            WireError::Io => 0,
            WireError::BadBlock => 1,
            WireError::PermissionDenied => 2,
            WireError::OutOfBounds => 3,
            WireError::ReadOnly => 4,
            WireError::NotResizable => 5,
            WireError::Disconnected => 6,
            WireError::NotAllowed => 7,
        }
    }
    fn from_u8(b: u8) -> Option<WireError> {
        Some(match b {
            0 => WireError::Io,
            1 => WireError::BadBlock,
            2 => WireError::PermissionDenied,
            3 => WireError::OutOfBounds,
            4 => WireError::ReadOnly,
            5 => WireError::NotResizable,
            6 => WireError::Disconnected,
            7 => WireError::NotAllowed,
            _ => return None,
        })
    }
}

// ---- payload encoding ----

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    put_u32(buf, b.len() as u32);
    buf.extend_from_slice(b);
}

/// Reads a framed payload with bounds checks.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(short)?;
        if end > self.data.len() {
            return Err(short());
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> io::Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| bad("string is not UTF-8"))
    }
}

fn short() -> io::Error {
    bad("message ended early")
}
fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl Request {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Request::Open { path, writable } => {
                b.push(0);
                put_bytes(&mut b, path.as_bytes());
                b.push(*writable as u8);
            }
            Request::Read { handle, offset, len } => {
                b.push(1);
                put_u32(&mut b, *handle);
                put_u64(&mut b, *offset);
                put_u32(&mut b, *len);
            }
            Request::Write { handle, offset, data } => {
                b.push(2);
                put_u32(&mut b, *handle);
                put_u64(&mut b, *offset);
                put_bytes(&mut b, data);
            }
            Request::Close { handle } => {
                b.push(3);
                put_u32(&mut b, *handle);
            }
        }
        b
    }

    fn decode(payload: &[u8]) -> io::Result<Request> {
        let mut r = Reader::new(payload);
        Ok(match r.u8()? {
            0 => Request::Open { path: r.string()?, writable: r.u8()? != 0 },
            1 => Request::Read { handle: r.u32()?, offset: r.u64()?, len: r.u32()? },
            2 => Request::Write { handle: r.u32()?, offset: r.u64()?, data: r.bytes()? },
            3 => Request::Close { handle: r.u32()? },
            t => return Err(bad(&format!("unknown request tag {t}"))),
        })
    }

    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        write_frame(w, &self.encode())
    }
    pub fn read_from(r: &mut impl Read) -> io::Result<Request> {
        Request::decode(&read_frame(r)?)
    }
}

impl Response {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Response::Opened { handle, size, block_size } => {
                b.push(0);
                put_u32(&mut b, *handle);
                put_u64(&mut b, *size);
                put_u32(&mut b, *block_size);
            }
            Response::Data(bytes) => {
                b.push(1);
                put_bytes(&mut b, bytes);
            }
            Response::Written => b.push(2),
            Response::Closed => b.push(3),
            Response::Error { kind, message } => {
                b.push(4);
                b.push(kind.to_u8());
                put_bytes(&mut b, message.as_bytes());
            }
        }
        b
    }

    fn decode(payload: &[u8]) -> io::Result<Response> {
        let mut r = Reader::new(payload);
        Ok(match r.u8()? {
            0 => Response::Opened { handle: r.u32()?, size: r.u64()?, block_size: r.u32()? },
            1 => Response::Data(r.bytes()?),
            2 => Response::Written,
            3 => Response::Closed,
            4 => {
                let kind = WireError::from_u8(r.u8()?).ok_or_else(|| bad("unknown error kind"))?;
                Response::Error { kind, message: r.string()? }
            }
            t => return Err(bad(&format!("unknown response tag {t}"))),
        })
    }

    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        write_frame(w, &self.encode())
    }
    pub fn read_from(r: &mut impl Read) -> io::Result<Response> {
        Response::decode(&read_frame(r)?)
    }
}

fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len);
    if len > MAX_MESSAGE {
        return Err(bad("framed message exceeds the size cap"));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_roundtrip(req: Request) {
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        let got = Request::read_from(&mut &buf[..]).unwrap();
        assert_eq!(got, req);
    }

    fn resp_roundtrip(resp: Response) {
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        let got = Response::read_from(&mut &buf[..]).unwrap();
        assert_eq!(got, resp);
    }

    #[test]
    fn requests_round_trip() {
        req_roundtrip(Request::Open { path: "/dev/rdisk2".into(), writable: false });
        req_roundtrip(Request::Open { path: "/dev/sda".into(), writable: true });
        req_roundtrip(Request::Read { handle: 7, offset: 0x1000, len: 4096 });
        req_roundtrip(Request::Write { handle: 3, offset: 512, data: vec![1, 2, 3, 4] });
        req_roundtrip(Request::Close { handle: 1 });
    }

    #[test]
    fn responses_round_trip() {
        resp_roundtrip(Response::Opened { handle: 1, size: 1 << 40, block_size: 4096 });
        resp_roundtrip(Response::Data(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        resp_roundtrip(Response::Written);
        resp_roundtrip(Response::Closed);
        resp_roundtrip(Response::Error {
            kind: WireError::PermissionDenied,
            message: "nope".into(),
        });
    }

    #[test]
    fn a_truncated_payload_is_an_error_not_a_panic() {
        // A Read request needs 1 + 4 + 8 + 4 = 17 payload bytes; give it 5.
        assert!(Request::decode(&[1, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn a_lying_length_prefix_does_not_over_allocate() {
        // Claim a byte string of 4 GB inside a 5-byte payload.
        let payload = [0u8, 0xFF, 0xFF, 0xFF, 0xFF]; // Open tag + huge path len
        assert!(Request::decode(&payload).is_err());
    }

    #[test]
    fn an_oversized_frame_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE + 1).to_le_bytes());
        assert!(Response::read_from(&mut &buf[..]).is_err());
    }
}
