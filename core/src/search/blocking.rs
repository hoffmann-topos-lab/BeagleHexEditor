//! Blocking helpers (CLI and tests; the GUI uses `Searcher::step` per frame).

use std::ops::Range;

use crate::document::Document;
use crate::error::Result;
use crate::progress::Progress;

use super::{Pattern, Searcher, WINDOW};

/// Next match from `from` (F-13a/b). Honours direction and wrap.
pub fn find_next(
    doc: &mut Document,
    pattern: &Pattern,
    range: Range<u64>,
    from: u64,
    backward: bool,
    wrap: bool,
    progress: &Progress,
) -> Option<Range<u64>> {
    let len = doc.len();
    let mut s = Searcher::new(pattern.clone(), range, len, from, backward, wrap);
    progress.set_total(s.total_space());
    let m = s.pattern_len();
    let mut out = Vec::new();
    loop {
        let st = s.step(doc, WINDOW, &mut out);
        progress.add_done(st.scanned);
        if !out.is_empty() {
            // Backwards, the one closest to the cursor is the window's last.
            let at = if backward { *out.last().unwrap() } else { out[0] };
            return Some(at..at + m);
        }
        if st.finished || progress.is_cancelled() {
            return None;
        }
    }
}

/// F-15b — All matches (non-overlapping), up to `limit`. The second value
/// signals truncation.
pub fn find_all(
    doc: &mut Document,
    pattern: &Pattern,
    range: Range<u64>,
    limit: usize,
    progress: &Progress,
) -> (Vec<u64>, bool) {
    let len = doc.len();
    let start = range.start;
    let mut s = Searcher::new(pattern.clone(), range, len, start, false, false);
    progress.set_total(s.total_space());
    let mut out = Vec::new();
    loop {
        let st = s.step(doc, WINDOW, &mut out);
        progress.add_done(st.scanned);
        if out.len() >= limit {
            out.truncate(limit);
            return (out, true);
        }
        if st.finished || progress.is_cancelled() {
            return (out, false);
        }
    }
}

/// Replaces one match as **a single** undo transaction: an equal length is an
/// overwrite; differing lengths become a merged delete+insert.
pub fn apply_replacement(doc: &mut Document, at: Range<u64>, replacement: &[u8]) -> Result<()> {
    if replacement.len() as u64 == at.end - at.start {
        doc.overwrite(at.start, replacement)
    } else {
        doc.delete(at.start, at.end - at.start)?;
        if !replacement.is_empty() {
            doc.insert(at.start, replacement)?;
            doc.merge_with_previous();
        }
        Ok(())
    }
}

/// F-28 — Replace everything inside `range`, with a count and an **atomic
/// undo**: a single Ctrl+Z undoes every replacement. The replacement may change
/// the size (the piece table absorbs the shift); cancelling through `progress`
/// stops on a match boundary, never mid-write.
pub fn replace_all(
    doc: &mut Document,
    pattern: &Pattern,
    replacement: &[u8],
    range: Range<u64>,
    progress: &Progress,
) -> Result<u64> {
    let m = pattern.len() as u64;
    let mut end = range.end.min(doc.len());
    let mut pos = range.start.min(end);
    progress.set_total(end - pos);
    let mut count = 0u64;

    while !progress.is_cancelled() {
        // A fresh Searcher per match: the replacement shifts offsets, and
        // restarting from `pos` with a corrected `end` is always right.
        let mut s = Searcher::new(pattern.clone(), pos..end, doc.len(), pos, false, false);
        let mut out = Vec::new();
        let found = loop {
            let st = s.step(doc, WINDOW, &mut out);
            progress.add_done(st.scanned);
            if let Some(at) = out.first() {
                break Some(*at);
            }
            if st.finished || progress.is_cancelled() {
                break None;
            }
        };
        let Some(at) = found else { break };

        apply_replacement(doc, at..at + m, replacement)?;
        if count > 0 {
            doc.merge_with_previous(); // atomic undo of the whole operation
        }
        count += 1;
        let delta = replacement.len() as i64 - m as i64;
        end = end.checked_add_signed(delta).expect("the delta fits in the document");
        pos = at + replacement.len() as u64;
    }
    Ok(count)
}
