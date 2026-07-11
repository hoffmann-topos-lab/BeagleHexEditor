//! F-47 — `DataSource` backed by the privileged helper.
//!
//! When the process itself cannot open a device (not root), it connects to the
//! helper daemon over a Unix socket and asks it to do the raw I/O. The daemon
//! does unaligned-rejecting `pread`/`pwrite`, so this source aligns to sectors
//! exactly like `DiskSource` (via the shared `align` helpers) — the daemon
//! stays a dumb byte pipe. The sector size comes from enumeration (the caller),
//! not the daemon, which keeps the daemon free of `ioctl`.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;

use hexed_helper_proto::{Request, Response, WireError};

use super::{Capabilities, DataSource, align};
use crate::error::{Error, ErrorKind, Result};

pub struct HelperSource {
    stream: Mutex<UnixStream>,
    handle: u32,
    size: u64,
    block_size: u64,
    writable: bool,
}

impl HelperSource {
    /// Connects to the helper at `socket` and opens `device` through it.
    pub fn connect(
        socket: impl AsRef<Path>,
        device: &str,
        block_size: u32,
        writable: bool,
    ) -> Result<Self> {
        let stream = UnixStream::connect(socket)
            .map_err(|e| Error::new(ErrorKind::Disconnected, format!("helper socket: {e}")))?;
        Self::from_stream(stream, device, block_size, writable)
    }

    /// Performs the open handshake over an already-connected stream. Split out
    /// so tests can drive it over an in-process socket pair.
    pub(crate) fn from_stream(
        mut stream: UnixStream,
        device: &str,
        block_size: u32,
        writable: bool,
    ) -> Result<Self> {
        Request::Open { path: device.into(), writable }
            .write_to(&mut stream)
            .map_err(io_err)?;
        match Response::read_from(&mut stream).map_err(io_err)? {
            // block_size from the daemon is ignored: the caller supplies the
            // real sector size (from enumeration).
            Response::Opened { handle, size, .. } => Ok(Self {
                stream: Mutex::new(stream),
                handle,
                size,
                block_size: block_size.max(1) as u64,
                writable,
            }),
            Response::Error { kind, message } => Err(wire_err(kind, message)),
            _ => Err(Error::new(ErrorKind::Io, "unexpected helper reply to open")),
        }
    }

    fn request(&self, req: Request) -> Result<Response> {
        let mut stream = self.stream.lock().unwrap();
        req.write_to(&mut *stream).map_err(io_err)?;
        Response::read_from(&mut *stream).map_err(io_err)
    }

    fn read_aligned(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        let req = Request::Read { handle: self.handle, offset: start, len: (end - start) as u32 };
        match self.request(req)? {
            Response::Data(bytes) => Ok(bytes),
            Response::Error { kind, message } => Err(wire_err(kind, message)),
            _ => Err(Error::new(ErrorKind::Io, "unexpected helper reply to read")),
        }
    }

    fn write_aligned(&self, start: u64, block: &[u8]) -> Result<()> {
        let req = Request::Write { handle: self.handle, offset: start, data: block.to_vec() };
        match self.request(req)? {
            Response::Written => Ok(()),
            Response::Error { kind, message } => Err(wire_err(kind, message)),
            _ => Err(Error::new(ErrorKind::Io, "unexpected helper reply to write")),
        }
    }

    fn check_bounds(&self, offset: u64, len: usize) -> Result<()> {
        let end = offset.checked_add(len as u64).ok_or_else(|| {
            Error::new(ErrorKind::OutOfBounds, "offset + len overflows u64")
        })?;
        if end > self.size {
            return Err(Error::new(
                ErrorKind::OutOfBounds,
                format!("[{offset}, {end}) exceeds device size {}", self.size),
            ));
        }
        Ok(())
    }
}

impl DataSource for HelperSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            writable: self.writable,
            resizable: false,
            block_size: Some(self.block_size as u32),
            sparse: false,
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.check_bounds(offset, buf.len())?;
        align::read_into(offset, buf, self.block_size, |s, e| self.read_aligned(s, e.min(self.size)))
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if !self.writable {
            return Err(Error::new(ErrorKind::ReadOnly, "device opened read-only via helper"));
        }
        self.check_bounds(offset, data.len())?;
        align::write_at(
            offset,
            data,
            self.block_size,
            |s, e| self.read_aligned(s, e),
            |s, block| self.write_aligned(s, block),
        )
    }
}

fn io_err(e: std::io::Error) -> Error {
    Error::new(ErrorKind::Disconnected, format!("helper connection: {e}"))
}

fn wire_err(kind: WireError, message: String) -> Error {
    let kind = match kind {
        WireError::Io => ErrorKind::Io,
        WireError::BadBlock => ErrorKind::BadBlock,
        WireError::PermissionDenied => ErrorKind::PermissionDenied,
        WireError::OutOfBounds => ErrorKind::OutOfBounds,
        WireError::ReadOnly => ErrorKind::ReadOnly,
        WireError::NotResizable => ErrorKind::NotResizable,
        WireError::Disconnected => ErrorKind::Disconnected,
        WireError::NotAllowed => ErrorKind::PermissionDenied,
    };
    Error::new(kind, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in daemon: serves reads/writes from an in-memory device over one
    /// end of a socket pair. Exercises the client + protocol without root.
    fn fake_daemon(mut stream: UnixStream, mut device: Vec<u8>) {
        loop {
            let req = match Request::read_from(&mut stream) {
                Ok(r) => r,
                Err(_) => return,
            };
            let resp = match req {
                Request::Open { .. } => {
                    Response::Opened { handle: 0, size: device.len() as u64, block_size: 0 }
                }
                Request::Read { offset, len, .. } => {
                    let (o, l) = (offset as usize, len as usize);
                    if o + l <= device.len() {
                        Response::Data(device[o..o + l].to_vec())
                    } else {
                        Response::Error { kind: WireError::OutOfBounds, message: "oob".into() }
                    }
                }
                Request::Write { offset, data, .. } => {
                    let o = offset as usize;
                    device[o..o + data.len()].copy_from_slice(&data);
                    Response::Written
                }
                Request::Close { .. } => Response::Closed,
            };
            if resp.write_to(&mut stream).is_err() {
                return;
            }
        }
    }

    fn connect_fake(device: Vec<u8>, writable: bool) -> HelperSource {
        let (client, server) = UnixStream::pair().unwrap();
        std::thread::spawn(move || fake_daemon(server, device));
        HelperSource::from_stream(client, "/dev/rdiskX", 512, writable).unwrap()
    }

    #[test]
    fn an_unaligned_read_through_the_helper_is_exact() {
        let data: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        let src = connect_fake(data.clone(), false);
        assert_eq!(src.size(), 2048);
        let mut buf = [0u8; 100];
        src.read_at(300, &mut buf).unwrap();
        assert_eq!(&buf[..], &data[300..400]);
    }

    #[test]
    fn a_sub_sector_write_through_the_helper_preserves_edges() {
        let src = connect_fake(vec![0xAAu8; 1024], true);
        src.write_at(10, b"XYZ").unwrap();
        let mut buf = [0u8; 16];
        src.read_at(6, &mut buf).unwrap();
        assert_eq!(&buf[4..7], b"XYZ");
        assert_eq!(&buf[..4], &[0xAA; 4], "bytes before untouched");
        assert_eq!(&buf[7..], &[0xAA; 9], "bytes after untouched");
    }

    #[test]
    fn a_read_only_helper_source_refuses_writes() {
        let src = connect_fake(vec![0u8; 512], false);
        assert_eq!(src.write_at(0, b"x").unwrap_err().kind, ErrorKind::ReadOnly);
    }

    #[test]
    fn a_read_past_the_end_is_out_of_bounds() {
        let src = connect_fake(vec![0u8; 512], false);
        let mut buf = [0u8; 8];
        assert_eq!(src.read_at(510, &mut buf).unwrap_err().kind, ErrorKind::OutOfBounds);
    }
}
