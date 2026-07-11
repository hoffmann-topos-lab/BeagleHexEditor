use std::fmt;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Generic I/O error.
    Io,
    /// Unreadable sector or block (typically `EIO`). Neighbours may be fine.
    BadBlock,
    /// Permission denied. Probably needs the privileged helper (D3).
    PermissionDenied,
    /// Offset outside the source's valid range.
    OutOfBounds,
    /// Source opened read-only (F-40).
    ReadOnly,
    /// Source cannot change size: disks and process memory.
    NotResizable,
    /// The source is gone: device removed, process died, helper crashed.
    Disconnected,
}

impl ErrorKind {
    /// A bad block is permanent enough to be cached; a transient error must not
    /// be memorized.
    pub fn is_cacheable(self) -> bool {
        matches!(self, ErrorKind::BadBlock | ErrorKind::OutOfBounds)
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    pub kind: ErrorKind,
    pub detail: String,
}

impl Error {
    pub fn new(kind: ErrorKind, detail: impl Into<String>) -> Self {
        Self { kind, detail: detail.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let k = match self.kind {
            ErrorKind::Io => "I/O error",
            ErrorKind::BadBlock => "unreadable block",
            ErrorKind::PermissionDenied => "permission denied",
            ErrorKind::OutOfBounds => "offset out of range",
            ErrorKind::ReadOnly => "read-only source",
            ErrorKind::NotResizable => "source is not resizable",
            ErrorKind::Disconnected => "source disconnected",
        };
        if self.detail.is_empty() { write!(f, "{k}") } else { write!(f, "{k}: {}", self.detail) }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        // EIO = 5. It is what the kernel returns for a sector it cannot read.
        const EIO: i32 = 5;
        let kind = match e.kind() {
            io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => ErrorKind::Disconnected,
            _ if e.raw_os_error() == Some(EIO) => ErrorKind::BadBlock,
            _ => ErrorKind::Io,
        };
        Error::new(kind, e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
