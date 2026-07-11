mod align;
pub mod disk;
pub mod file;
pub mod helper;
pub mod mem;

pub use disk::DiskSource;
pub use file::FileSource;
pub use helper::HelperSource;
pub use mem::MemSource;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Accepts writes. False by default for disks and RAM (F-40).
    pub writable: bool,
    /// Can change size. Files: yes. Disks and RAM: **no** — so insert (F-35)
    /// and delete (F-36) are disabled on those sources.
    pub resizable: bool,
    /// Block size imposed by the source (512/4096 on disks). `None` = free.
    pub block_size: Option<u32>,
    /// Address space with holes. Process memory: yes.
    pub sparse: bool,
}

impl Capabilities {
    pub const fn file(writable: bool) -> Self {
        Self { writable, resizable: true, block_size: None, sparse: false }
    }
}

pub trait DataSource: Send + Sync {
    fn size(&self) -> u64;

    fn capabilities(&self) -> Capabilities;

    /// Reads exactly `buf.len()` bytes starting at `offset`.
    ///
    /// Must handle short reads internally. An `Err` here refers to this range
    /// only — the caller goes on reading the neighbouring ones.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()>;

    fn flush(&self) -> Result<()> {
        Ok(())
    }
}

/// F-47/F-49 — Opens a device node as a source: directly when the process is
/// permitted (root), otherwise through the privileged helper at `socket` if it
/// is running. Shared by the CLI and GUI so the fallback logic lives in one
/// place; the frontends turn a bare `PermissionDenied` into an F-56 hint.
pub fn open_device(
    node: &std::path::Path,
    block_size: u32,
    writable: bool,
    socket: &str,
) -> Result<Box<dyn DataSource>> {
    use crate::error::ErrorKind;
    match DiskSource::open(node, block_size, writable) {
        Ok(src) => Ok(Box::new(src)),
        Err(e) if e.kind == ErrorKind::PermissionDenied && std::path::Path::new(socket).exists() => {
            let node_str = node.to_string_lossy();
            let src = HelperSource::connect(socket, &node_str, block_size, writable)?;
            Ok(Box::new(src))
        }
        Err(e) => Err(e),
    }
}
