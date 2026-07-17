//! F-74 — Entropy and the packer heuristic. Per-section and PE-overlay Shannon
//! entropy (reusing `stats.rs`), turned into a "likely packed" verdict with the
//! reasons that led to it. High entropy in executable code, a writable+executable
//! section, or an entry point buried in high-entropy bytes all point at a packer
//! or an encrypted payload.

use crate::document::Document;
use crate::format::{BinaryInfo, Format};
use crate::progress::Progress;
use crate::stats;

/// Entropy above this (bits/byte, out of 8) reads as compressed/encrypted.
const HIGH: f64 = 7.0;
const HIGH_OVERLAY: f64 = 7.2;

/// One section's entropy and the traits the verdict cares about.
#[derive(Debug, Clone, PartialEq)]
pub struct SectionEntropy {
    pub name: String,
    pub size: u64,
    pub entropy: f64,
    pub executable: bool,
    pub writable: bool,
}

/// The entropy picture of a binary plus the packing verdict (F-74).
#[derive(Debug, Clone, PartialEq)]
pub struct PackReport {
    pub sections: Vec<SectionEntropy>,
    /// PE overlay (bytes after the last raw section): `(size, entropy)`.
    pub overlay: Option<(u64, f64)>,
    pub file_entropy: f64,
    pub likely_packed: bool,
    /// Human-readable reasons behind `likely_packed` (empty when not packed).
    pub reasons: Vec<String>,
}

/// F-74 — Measures entropy and decides whether the binary is likely packed.
pub fn report(doc: &mut Document, info: &BinaryInfo, progress: &Progress) -> PackReport {
    let mut sections = Vec::new();
    for s in &info.sections {
        if s.file.is_empty() {
            continue; // no file bytes (e.g. .bss)
        }
        let e = entropy_of(doc, s.file.clone(), progress);
        sections.push(SectionEntropy {
            name: s.name.clone(),
            size: s.file.end - s.file.start,
            entropy: e,
            executable: s.perms.x,
            writable: s.perms.w,
        });
        if progress.is_cancelled() {
            break;
        }
    }

    // The overlay is a PE concept: appended data past the last mapped section.
    let overlay = (info.format == Format::Pe)
        .then(|| {
            let end = info
                .sections
                .iter()
                .filter(|s| !s.file.is_empty())
                .map(|s| s.file.end)
                .max()
                .unwrap_or(0);
            (end < doc.len()).then(|| (doc.len() - end, entropy_of(doc, end..doc.len(), progress)))
        })
        .flatten();

    let file_entropy = entropy_of(doc, 0..doc.len(), progress);

    let reasons = verdict(info, &sections, overlay);
    let likely_packed = !reasons.is_empty();
    PackReport { sections, overlay, file_entropy, likely_packed, reasons }
}

fn entropy_of(doc: &mut Document, range: std::ops::Range<u64>, progress: &Progress) -> f64 {
    let len = range.end.saturating_sub(range.start).max(1);
    // One block spanning the whole range: we only want the global entropy.
    stats::stats(doc, range, Some(len), progress).entropy()
}

/// Collects the reasons the binary looks packed; empty means it does not.
fn verdict(
    info: &BinaryInfo,
    sections: &[SectionEntropy],
    overlay: Option<(u64, f64)>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for s in sections {
        if s.executable && s.entropy > HIGH {
            reasons.push(format!(
                "executable section '{}' has high entropy ({:.2}/8)",
                s.name, s.entropy
            ));
        }
        if s.executable && s.writable {
            reasons.push(format!("section '{}' is writable and executable", s.name));
        }
    }
    if let Some((size, e)) = overlay
        && e > HIGH_OVERLAY
        && size >= 1024
    {
        reasons.push(format!("high-entropy overlay ({size} bytes, {e:.2}/8)"));
    }
    if let Some(sec) = super::section_at_vaddr(info, info.entry) {
        let buried = sections
            .iter()
            .find(|s| s.name == sec.name)
            .is_some_and(|s| s.entropy > HIGH && !reasons_mention(&reasons, &sec.name));
        if buried {
            reasons.push(format!("entry point lies in high-entropy section '{}'", sec.name));
        }
    }
    reasons
}

fn reasons_mention(reasons: &[String], name: &str) -> bool {
    reasons.iter().any(|r| r.contains(name))
}
