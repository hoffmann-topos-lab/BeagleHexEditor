//! F-73/F-74/F-75 — Static identification (Fase 10): Detect It Easy + PEStudio,
//! offline.
//!
//! Given a parsed executable ([`BinaryInfo`]) and its bytes, three passes:
//! [`signatures`] names the toolchain/packer/protector (F-73), [`entropy`]
//! measures per-section and overlay entropy for a "likely packed" verdict
//! (F-74), and [`indicators`] flags suspicious traits — risky imports, W^X
//! sections, entry anomalies, TLS callbacks, IOC strings (F-75). Everything
//! reads through `Document::read`, so the huge-file invariant (D6) and per-block
//! failure (F-06) hold, and nothing touches the network.

mod entropy;
mod indicators;
mod signatures;
#[cfg(test)]
mod tests;

use crate::document::Document;
use crate::format::{BinaryInfo, Section};
use crate::progress::Progress;

pub use entropy::{PackReport, SectionEntropy};
pub use indicators::{Indicator, Severity};
pub use signatures::{Detection, IdKind};

/// The full identification of one binary.
#[derive(Debug, Clone)]
pub struct IdentifyReport {
    /// Toolchain/packer/protector detections (F-73).
    pub detections: Vec<Detection>,
    /// Entropy per section + overlay and the packing verdict (F-74).
    pub packing: PackReport,
    /// Suspicious static traits (F-75).
    pub indicators: Vec<Indicator>,
}

/// Runs all three passes. Reads section bytes, so it is cooperative through
/// `progress` (the caller may cancel).
pub fn analyze(doc: &mut Document, info: &BinaryInfo, progress: &Progress) -> IdentifyReport {
    let detections = signatures::detect(doc, info);
    let packing = entropy::report(doc, info, progress);
    let indicators = indicators::scan(doc, info, &packing, progress);
    IdentifyReport { detections, packing, indicators }
}

/// The section whose mapped virtual-address range contains `va`, if any.
pub(crate) fn section_at_vaddr(info: &BinaryInfo, va: u64) -> Option<&Section> {
    info.sections.iter().find(|s| s.size > 0 && va >= s.vaddr && va < s.vaddr + s.size)
}

/// Best-effort read of up to `cap` bytes of a section's file range; `None` when
/// the section has no file bytes or the range is unreadable (F-06).
pub(crate) fn read_section(doc: &mut Document, sec: &Section, cap: usize) -> Option<Vec<u8>> {
    if sec.file.is_empty() {
        return None;
    }
    let len = ((sec.file.end - sec.file.start) as usize).min(cap);
    let r = doc.read(sec.file.start, len);
    r.is_clean().then_some(r.data)
}
