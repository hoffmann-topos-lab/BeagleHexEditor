//! F-85 — Format-guided patching (LIEF-lite, narrow scope).
//!
//! Editing a field is served by the structure tree (F-72): clicking a node
//! selects its exact bytes, which you then overwrite in the grid and save
//! in-place (F-05). What editing *can't* do by hand is fix a derived value — so
//! this module recomputes the **PE checksum**, the classic post-patch step.
//!
//! The algorithm is the documented one (matching `pefile.generate_checksum`):
//! sum the file as 32-bit words with the CheckSum field taken as zero (folding
//! carry at 2³²), fold to 16 bits, then add the file length. It is windowed and
//! cancellable so a large image never blocks (F-07), and aborts on an unreadable
//! block — a checksum over invented zeros would be a lie.

#[cfg(test)]
mod tests;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::format::read_exact;
use crate::progress::Progress;

/// The stored vs. recomputed PE checksum, and where the field lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeChecksum {
    /// Document offset of the 4-byte CheckSum field.
    pub field_offset: u64,
    /// The value currently in the header.
    pub stored: u32,
    /// The value the file's bytes imply.
    pub computed: u32,
}

impl PeChecksum {
    pub fn matches(&self) -> bool {
        self.stored == self.computed
    }
}

fn bad(detail: impl Into<String>) -> Error {
    Error::new(ErrorKind::Io, detail)
}

/// Computes the PE checksum of `doc` (a PE image), returning the stored and
/// recomputed values. Does not modify the document.
pub fn pe_checksum(doc: &mut Document, progress: &Progress) -> Result<PeChecksum> {
    let dos = read_exact(doc, 0, 64)?;
    if dos[0..2] != [b'M', b'Z'] {
        return Err(bad("not a PE file (no MZ signature)"));
    }
    let e_lfanew = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]) as u64;

    if read_exact(doc, e_lfanew, 4)? != [b'P', b'E', 0, 0] {
        return Err(bad("not a PE file (no PE signature)"));
    }
    // Optional-header magic (PE32 0x10b / PE32+ 0x20b) — CheckSum is at optional
    // offset 64 in both, i.e. file offset e_lfanew + 4 (sig) + 20 (COFF) + 64.
    let magic = read_exact(doc, e_lfanew + 24, 2)?;
    let magic = u16::from_le_bytes([magic[0], magic[1]]);
    if magic != 0x10b && magic != 0x20b {
        return Err(bad("PE has no recognised optional header (no checksum field)"));
    }
    let field_offset = e_lfanew + 88;

    let sb = read_exact(doc, field_offset, 4)?;
    let stored = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
    let computed = compute(doc, field_offset, progress)?;
    Ok(PeChecksum { field_offset, stored, computed })
}

/// Sums the file in 32-bit words with the CheckSum field zeroed, then adds the
/// file length.
fn compute(doc: &mut Document, field_offset: u64, progress: &Progress) -> Result<u32> {
    const WINDOW: u64 = 1 << 20; // a multiple of 4, so only the last window is short
    let len = doc.len();
    progress.set_total(len);

    let mut sum: u64 = 0;
    let mut pos = 0u64;
    while pos < len {
        if progress.is_cancelled() {
            return Err(Error::new(ErrorKind::Io, "cancelled"));
        }
        let n = (len - pos).min(WINDOW);
        let read = doc.read(pos, n as usize);
        if !read.is_clean() {
            return Err(Error::new(
                ErrorKind::BadBlock,
                format!("unreadable block at {:#x}; checksum aborted", read.unreadable[0].start),
            ));
        }
        let mut data = read.data;
        // Take the CheckSum field's bytes as zero.
        for i in 0..4u64 {
            let fo = field_offset + i;
            if (pos..pos + n).contains(&fo) {
                data[(fo - pos) as usize] = 0;
            }
        }

        let full = data.len() / 4 * 4;
        let mut i = 0;
        while i < full {
            let dw = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as u64;
            sum = fold32(sum + dw);
            i += 4;
        }
        // A short tail (only possible in the final window) pads with zeros.
        if i < data.len() {
            let mut b = [0u8; 4];
            b[..data.len() - i].copy_from_slice(&data[i..]);
            sum = fold32(sum + u32::from_le_bytes(b) as u64);
        }
        progress.add_done(n);
        pos += n;
    }

    let mut cs = (sum & 0xffff) + (sum >> 16);
    cs += cs >> 16;
    Ok(((cs & 0xffff) as u32).wrapping_add(len as u32))
}

fn fold32(x: u64) -> u64 {
    (x & 0xffff_ffff) + (x >> 32)
}
