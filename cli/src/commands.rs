//! The subcommands, grouped by area, plus the document-opening helpers they
//! all share.

pub(crate) mod analyze;
pub(crate) mod device;
pub(crate) mod edit;
pub(crate) mod io;
pub(crate) mod search;
pub(crate) mod view;

use hexed_core::{Document, Error, ErrorKind, disks};

/// Opens a document from a file path, or from a raw device when the path is
/// under `/dev/` (F-49). Devices open read-only and are accessed by sector.
/// Direct access is tried first; if it is denied and the privileged helper
/// (F-47) is running, the read is routed through it.
pub(crate) fn open_doc(path: &str) -> Result<Document, String> {
    if !path.starts_with("/dev/") {
        return Document::open(path, false).map_err(|e| e.to_string());
    }
    let info = disks::find(path).map_err(|e| e.to_string())?;
    let src = hexed_core::source::open_device(&info.node, info.block_size, false, &helper_socket())
        .map_err(privilege_hint)?;
    Ok(Document::new(src))
}

/// The helper socket path: `$HEXED_HELPER_SOCKET`, else the built-in default.
fn helper_socket() -> String {
    std::env::var("HEXED_HELPER_SOCKET")
        .unwrap_or_else(|_| hexed_core::DEFAULT_HELPER_SOCKET.to_string())
}

/// F-56 — A bare "permission denied" on a device is unhelpful; explain it.
fn privilege_hint(e: Error) -> String {
    match e.kind {
        ErrorKind::PermissionDenied => format!(
            "{e}\n  hint: raw disk access needs privilege — run with `sudo`, \
             or install the privileged helper so it is used automatically"
        ),
        _ => e.to_string(),
    }
}
