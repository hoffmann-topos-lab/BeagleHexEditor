//! F-47 — Privileged helper daemon.
//!
//! Runs as root (installed by `install-helper.sh`; see D3/D5). Its ENTIRE job is
//! raw I/O on `/dev/` nodes on behalf of the unprivileged GUI, over a Unix
//! socket. It does **not** parse file formats, load plugins, or run user code —
//! every byte of interpretation stays in the non-privileged process.
//!
//! Security, non-negotiable (§ I.4):
//!   1. Peer UID check: only the installing user may connect (`getpeereid`).
//!   2. Path whitelist: canonicalize, then require the `/dev/` prefix. This
//!      resolves symlinks and `..`, so nothing outside `/dev/` is reachable.
//!   3. Fixed minimal surface: open / read / write / close. Nothing else.
//!   4. Writing is opt-in per handle; a read-only handle refuses writes.
//!
//! Usage: `hexhelper --socket <path> --uid <n>` (both default sensibly; `--uid`
//! falls back to `$SUDO_UID`). The daemon fails closed if it cannot determine
//! the allowed UID.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use hexed_helper_proto::{MAX_CHUNK, Request, Response, WireError};

// The only two things std does not give us: the peer's credentials, and chown.
//
// `getpeereid` is BSD/macOS API — glibc does not provide it, so on Linux this
// fails at link time (fail closed, nothing weaker ships by accident). The
// Linux port must replace it with `getsockopt(SO_PEERCRED)`; do NOT stub it.
unsafe extern "C" {
    fn getpeereid(fd: i32, euid: *mut u32, egid: *mut u32) -> i32;
    fn chown(path: *const i8, owner: u32, group: u32) -> i32;
}

fn main() -> std::process::ExitCode {
    let mut socket = hexed_helper_proto::DEFAULT_SOCKET.to_string();
    let mut allowed_uid: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok());

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                i += 1;
                let Some(v) = args.get(i) else { return fail("--socket needs a value") };
                socket = v.clone();
            }
            "--uid" => {
                i += 1;
                allowed_uid = args.get(i).and_then(|s| s.parse().ok());
                if allowed_uid.is_none() {
                    return fail("--uid needs a numeric value");
                }
            }
            other => return fail(&format!("unknown argument: {other}")),
        }
        i += 1;
    }

    // Fail closed: without a known allowed UID, anyone at all could connect.
    let Some(allowed_uid) = allowed_uid else {
        return fail("no allowed UID (pass --uid or run via sudo so $SUDO_UID is set)");
    };

    match serve(&socket, allowed_uid) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => fail(&format!("{socket}: {e}")),
    }
}

fn fail(msg: &str) -> std::process::ExitCode {
    eprintln!("hexhelper: {msg}");
    std::process::ExitCode::FAILURE
}

fn serve(socket: &str, allowed_uid: u32) -> std::io::Result<()> {
    // A stale socket file from a previous run blocks bind().
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;

    // Lock the socket to the allowed user: chown to them, mode 0600. The peer
    // UID check is the real gate; this is defense in depth.
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    if let Ok(c) = CString::new(socket) {
        unsafe { chown(c.as_ptr(), allowed_uid, u32::MAX) };
    }

    eprintln!("hexhelper: listening on {socket} for uid {allowed_uid}");
    for stream in listener.incoming() {
        let stream = stream?;
        // One connection per client, isolated handle table. A misbehaving
        // client cannot touch another's handles.
        std::thread::spawn(move || {
            if let Err(e) = handle_client(stream, allowed_uid) {
                eprintln!("hexhelper: connection ended: {e}");
            }
        });
    }
    Ok(())
}

/// A device opened on a client's behalf.
struct Handle {
    file: File,
    writable: bool,
}

/// Cap on simultaneously open handles per connection. A hex editor opens a
/// handful of devices; without a cap, a looping client could exhaust the
/// root daemon's file descriptors.
const MAX_HANDLES: usize = 64;

fn handle_client(mut stream: UnixStream, allowed_uid: u32) -> std::io::Result<()> {
    if peer_uid(&stream) != Some(allowed_uid) {
        // Do not even reply — a wrong peer learns nothing.
        return Ok(());
    }

    // Index = handle id; `None` after close.
    let mut handles: Vec<Option<Handle>> = Vec::new();

    loop {
        let req = match Request::read_from(&mut stream) {
            Ok(r) => r,
            // Clean disconnect or a malformed frame: end this connection.
            Err(_) => return Ok(()),
        };
        let resp = dispatch(req, &mut handles);
        resp.write_to(&mut stream)?;
    }
}

fn dispatch(req: Request, handles: &mut Vec<Option<Handle>>) -> Response {
    match req {
        Request::Open { path, writable } => match open_device(&path, writable) {
            Ok(handle) => {
                let dev_size = match device_size(&handle.file) {
                    Ok(s) => s,
                    Err(e) => return err(&e),
                };
                // Reuse a closed slot before growing the table (capped).
                let id = match handles.iter().position(Option::is_none) {
                    Some(i) => i,
                    None if handles.len() < MAX_HANDLES => {
                        handles.push(None);
                        handles.len() - 1
                    }
                    None => return not_allowed("too many open handles"),
                };
                handles[id] = Some(handle);
                // block_size = 0: the client already knows it (from enumeration)
                // and supplies it. Keeping ioctl out of the daemon keeps it minimal.
                Response::Opened { handle: id as u32, size: dev_size, block_size: 0 }
            }
            Err(e) => e,
        },
        Request::Read { handle, offset, len } => {
            if len > MAX_CHUNK {
                return not_allowed("read length exceeds the cap");
            }
            let Some(Some(h)) = handles.get(handle as usize) else {
                return not_allowed("unknown handle");
            };
            let mut buf = vec![0u8; len as usize];
            match read_exact_at(&h.file, offset, &mut buf) {
                Ok(()) => Response::Data(buf),
                Err(e) => err(&e),
            }
        }
        Request::Write { handle, offset, data } => {
            if data.len() as u32 > MAX_CHUNK {
                return not_allowed("write length exceeds the cap");
            }
            let Some(Some(h)) = handles.get(handle as usize) else {
                return not_allowed("unknown handle");
            };
            if !h.writable {
                return Response::Error {
                    kind: WireError::ReadOnly,
                    message: "handle opened read-only".into(),
                };
            }
            match write_all_at(&h.file, offset, &data) {
                Ok(()) => Response::Written,
                Err(e) => err(&e),
            }
        }
        Request::Close { handle } => {
            if let Some(slot) = handles.get_mut(handle as usize) {
                *slot = None;
            }
            Response::Closed
        }
    }
}

/// Opens a device node after enforcing the whitelist.
fn open_device(path: &str, writable: bool) -> Result<Handle, Response> {
    let canonical = resolve_dev_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(writable)
        .open(&canonical)
        .map_err(|e| err(&e))?;
    Ok(Handle { file, writable })
}

/// The whitelist gate. Canonicalization resolves symlinks and `..`, so a symlink
/// under `/dev/` pointing elsewhere, or any `../` traversal, lands outside
/// `/dev/` and is rejected. A path that does not exist fails to canonicalize.
fn resolve_dev_path(path: &str) -> Result<std::path::PathBuf, Response> {
    let canonical = Path::new(path).canonicalize().map_err(|e| err(&e))?;
    if !canonical.starts_with("/dev/") {
        return Err(not_allowed("only paths under /dev/ are permitted"));
    }
    Ok(canonical)
}

fn device_size(file: &File) -> std::io::Result<u64> {
    // Device nodes report 0 through metadata; seek to the end for the real size.
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::End(0))
}

fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        match file.read_at(&mut buf[done..], offset + done as u64) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short read")),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn write_all_at(file: &File, offset: u64, data: &[u8]) -> std::io::Result<()> {
    let mut done = 0usize;
    while done < data.len() {
        match file.write_at(&data[done..], offset + done as u64) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "short write")),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut uid = u32::MAX;
    let mut gid = u32::MAX;
    let rc = unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

// ---- error mapping ----

fn err(e: &std::io::Error) -> Response {
    const EIO: i32 = 5;
    let kind = match e.kind() {
        std::io::ErrorKind::PermissionDenied => WireError::PermissionDenied,
        std::io::ErrorKind::NotFound => WireError::NotAllowed,
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => {
            WireError::Disconnected
        }
        _ if e.raw_os_error() == Some(EIO) => WireError::BadBlock,
        _ => WireError::Io,
    };
    Response::Error { kind, message: e.to_string() }
}

fn not_allowed(msg: &str) -> Response {
    Response::Error { kind: WireError::NotAllowed, message: msg.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_not_allowed(r: &Result<std::path::PathBuf, Response>) -> bool {
        matches!(r, Err(Response::Error { kind: WireError::NotAllowed, .. }))
    }

    #[test]
    fn a_dev_node_is_accepted() {
        // /dev/null exists on every unix and is world-readable.
        let ok = resolve_dev_path("/dev/null").unwrap();
        assert!(ok.starts_with("/dev/"));
    }

    #[test]
    fn a_path_outside_dev_is_rejected() {
        let r = resolve_dev_path("/etc/hosts");
        assert!(is_not_allowed(&r), "{r:?}");
    }

    #[test]
    fn traversal_out_of_dev_is_rejected() {
        // Canonicalization collapses the `..`, landing outside /dev/.
        let r = resolve_dev_path("/dev/../etc/hosts");
        assert!(is_not_allowed(&r), "{r:?}");
    }

    #[test]
    fn the_handle_table_is_capped_and_reuses_closed_slots() {
        let mut handles = Vec::new();
        let mut open = |handles: &mut Vec<Option<Handle>>| {
            dispatch(Request::Open { path: "/dev/null".into(), writable: false }, handles)
        };
        for _ in 0..MAX_HANDLES {
            assert!(matches!(open(&mut handles), Response::Opened { .. }));
        }
        let denied = open(&mut handles);
        assert!(
            matches!(denied, Response::Error { kind: WireError::NotAllowed, .. }),
            "{denied:?}"
        );

        // Closing frees a slot; the next open reuses it instead of growing.
        assert!(matches!(dispatch(Request::Close { handle: 3 }, &mut handles), Response::Closed));
        match open(&mut handles) {
            Response::Opened { handle, .. } => assert_eq!(handle, 3, "closed slot reused"),
            r => panic!("expected Opened, got {r:?}"),
        }
        assert_eq!(handles.len(), MAX_HANDLES, "the table never grows past the cap");
    }

    #[test]
    fn a_nonexistent_path_does_not_canonicalize() {
        // Fails at canonicalize → mapped from NotFound to NotAllowed.
        let r = resolve_dev_path("/dev/definitely-not-a-real-node-xyz");
        assert!(matches!(r, Err(Response::Error { .. })), "{r:?}");
    }
}
