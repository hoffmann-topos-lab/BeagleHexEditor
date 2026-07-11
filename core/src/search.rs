use std::ops::Range;

use crate::charset::Charset;
use crate::document::Document;
use crate::error::Result;
use crate::inspector::{Endian, FieldKind};
use crate::progress::Progress;

/// Largest window scanned by `step` — the granularity of progress and cancellation.
pub const WINDOW: u64 = 4 << 20;

/// What to look for.
#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// Bytes with a per-byte mask: bit 1 = must match, 0 = wildcard (F-15a).
    /// `ci` folds ASCII upper/lowercase (F-15); the pattern's bytes already
    /// come folded from construction.
    Bytes { bytes: Vec<u8>, mask: Vec<u8>, ci: bool },
    /// F-14: float with a tolerance — there is no exact byte sequence.
    Float { double: bool, endian: Endian, target: f64, tol: f64 },
}

fn fold(b: u8, ci: bool) -> u8 {
    if ci && b.is_ascii_uppercase() { b | 0x20 } else { b }
}

impl Pattern {
    /// Exact byte sequence (F-13a).
    pub fn bytes(bytes: Vec<u8>) -> Option<Pattern> {
        if bytes.is_empty() {
            return None;
        }
        let mask = vec![0xFF; bytes.len()];
        Some(Pattern::Bytes { bytes, mask, ci: false })
    }

    /// Hex with per-nibble wildcards (F-15a): `"DE ?? BE EF"`, `"D? ?E"`.
    pub fn parse_hex(s: &str) -> Option<Pattern> {
        let clean: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.is_empty() || !clean.len().is_multiple_of(2) {
            return None;
        }
        let mut bytes = Vec::with_capacity(clean.len() / 2);
        let mut mask = Vec::with_capacity(clean.len() / 2);
        for pair in clean.chunks(2) {
            let nib = |c: char| -> Option<(u8, u8)> {
                match c {
                    '?' => Some((0, 0)),
                    c => c.to_digit(16).map(|d| (d as u8, 0xF)),
                }
            };
            let (hi, hm) = nib(pair[0])?;
            let (lo, lm) = nib(pair[1])?;
            bytes.push(hi << 4 | lo);
            mask.push(hm << 4 | lm);
        }
        if mask.iter().all(|m| *m == 0) {
            return None; // a pattern of nothing but wildcards would match everything
        }
        Some(Pattern::Bytes { bytes, mask, ci: false })
    }

    /// Text in the given charset (F-13b). `ci` ignores ASCII case (F-15).
    pub fn text(s: &str, charset: Charset, ci: bool) -> Option<Pattern> {
        let mut bytes = charset.encode_str(s)?;
        if bytes.is_empty() {
            return None;
        }
        if ci {
            for b in &mut bytes {
                *b = fold(*b, true);
            }
        }
        let mask = vec![0xFF; bytes.len()];
        Some(Pattern::Bytes { bytes, mask, ci })
    }

    /// F-14 — typed value: `("i32", "1234")`, `("f32", "3.14")`. Integers become
    /// the exact byte sequence (via the inspector); floats with `tol > 0` become
    /// a comparison with a tolerance.
    pub fn typed(
        kind: &str,
        value: &str,
        endian: Endian,
        tol: Option<f64>,
    ) -> std::result::Result<Pattern, String> {
        let field = match kind.to_ascii_lowercase().as_str() {
            "i8" => FieldKind::I8,
            "u8" => FieldKind::U8,
            "i16" => FieldKind::I16,
            "u16" => FieldKind::U16,
            "i24" => FieldKind::I24,
            "u24" => FieldKind::U24,
            "i32" => FieldKind::I32,
            "u32" => FieldKind::U32,
            "i64" => FieldKind::I64,
            "u64" => FieldKind::U64,
            "f16" => FieldKind::F16,
            "f32" => FieldKind::F32,
            "f64" => FieldKind::F64,
            other => return Err(format!("unknown type: {other}")),
        };
        let is_float = matches!(field, FieldKind::F32 | FieldKind::F64);
        if is_float && tol.is_some_and(|t| t > 0.0) {
            let target: f64 = value.trim().parse().map_err(|_| "invalid float".to_string())?;
            return Ok(Pattern::Float {
                double: field == FieldKind::F64,
                endian,
                target,
                tol: tol.unwrap(),
            });
        }
        let bytes = field.encode(value, endian, Charset::Ascii)?;
        Ok(Pattern::bytes(bytes).expect("encode never returns empty"))
    }

    pub fn len(&self) -> usize {
        match self {
            Pattern::Bytes { bytes, .. } => bytes.len(),
            Pattern::Float { double, .. } => {
                if *double {
                    8
                } else {
                    4
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        false // the constructors guarantee a length ≥ 1
    }

    fn matches_at(&self, hay: &[u8], at: usize) -> bool {
        match self {
            Pattern::Bytes { bytes, mask, ci } => {
                if at + bytes.len() > hay.len() {
                    return false;
                }
                bytes
                    .iter()
                    .zip(mask)
                    .enumerate()
                    .all(|(i, (b, m))| (fold(hay[at + i], *ci) ^ b) & m == 0)
            }
            Pattern::Float { double, endian, target, tol } => {
                if at + self.len() > hay.len() {
                    return false;
                }
                let v = if *double {
                    let b: [u8; 8] = hay[at..at + 8].try_into().unwrap();
                    match endian {
                        Endian::Little => f64::from_le_bytes(b),
                        Endian::Big => f64::from_be_bytes(b),
                    }
                } else {
                    let b: [u8; 4] = hay[at..at + 4].try_into().unwrap();
                    (match endian {
                        Endian::Little => f32::from_le_bytes(b),
                        Endian::Big => f32::from_be_bytes(b),
                    }) as f64
                };
                (v - target).abs() <= *tol
            }
        }
    }

    /// Scans `hay` with candidates in `[c0, c1)`, without overlap from
    /// `min_start` on. Appends the relative positions to `out`.
    fn scan(&self, hay: &[u8], c0: usize, c1: usize, min_start: usize, out: &mut Vec<usize>) {
        let m = self.len();
        let concrete_bmh = matches!(self, Pattern::Bytes { mask, .. } if mask.iter().all(|b| *b == 0xFF))
            && m > 1;
        let mut i = c0.max(min_start);
        if concrete_bmh {
            let Pattern::Bytes { bytes, ci, .. } = self else { unreachable!() };
            // Boyer–Moore–Horspool: skip table keyed by the window's last byte.
            let mut skip = [m; 256];
            for (k, b) in bytes[..m - 1].iter().enumerate() {
                skip[*b as usize] = m - 1 - k;
            }
            while i < c1 && i + m <= hay.len() {
                let last = fold(hay[i + m - 1], *ci);
                if last == bytes[m - 1] && self.matches_at(hay, i) {
                    out.push(i);
                    i += m;
                } else {
                    i += skip[last as usize];
                }
            }
        } else {
            while i < c1 && i + m <= hay.len() {
                if self.matches_at(hay, i) {
                    out.push(i);
                    i += m;
                } else {
                    i += 1;
                }
            }
        }
    }
}

/// Result of one cooperative step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepResult {
    /// The search space is exhausted (including the wrap pass, if requested).
    pub finished: bool,
    /// Bytes scanned in this step — feeds the caller's `Progress`.
    pub scanned: u64,
}

/// Incremental search (F-15: direction, wrap-around, range restriction).
pub struct Searcher {
    pattern: Pattern,
    range: Range<u64>,
    backward: bool,
    wrap: bool,
    /// Where the search began; the wrap pass stops here.
    origin: u64,
    /// Boundary of the next window: advances (forwards) or retreats.
    pos: u64,
    wrapped: bool,
    finished: bool,
    /// Non-overlap across windows in the forward scan.
    next_candidate: u64,
}

impl Searcher {
    /// `range` bounds the search (F-15, "restricted to the selection"); matches
    /// lie entirely within it. `from` is where to start (clamped to the range).
    pub fn new(
        pattern: Pattern,
        range: Range<u64>,
        doc_len: u64,
        from: u64,
        backward: bool,
        wrap: bool,
    ) -> Self {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len);
        let m = pattern.len() as u64;
        // Last possible candidate start, exclusive.
        let cand_end = (end.saturating_sub(m - 1)).max(start);
        let origin = from.clamp(start, cand_end);
        let finished = start >= cand_end;
        Self {
            pattern,
            range: start..end,
            backward,
            wrap,
            origin,
            pos: origin,
            wrapped: false,
            finished,
            next_candidate: origin,
        }
    }

    /// Total size of the candidate space (for `Progress::set_total`).
    pub fn total_space(&self) -> u64 {
        self.range.end.saturating_sub(self.range.start)
    }

    pub fn pattern_len(&self) -> u64 {
        self.pattern.len() as u64
    }

    fn cand_end(&self) -> u64 {
        let m = self.pattern.len() as u64;
        (self.range.end.saturating_sub(m - 1)).max(self.range.start)
    }

    /// Scans up to `budget` bytes. Matches (start offsets, ascending order) go
    /// into `out`. Forwards they never overlap; backwards the caller only wants
    /// the last one (the closest to the cursor).
    pub fn step(&mut self, doc: &mut Document, budget: u64, out: &mut Vec<u64>) -> StepResult {
        if self.finished {
            return StepResult { finished: true, scanned: 0 };
        }
        let m = self.pattern.len() as u64;
        let window = budget.clamp(1, WINDOW);

        // Candidate bounds of the current pass.
        let (lo, hi) = if self.backward {
            if self.wrapped {
                (self.origin, self.pos)
            } else {
                (self.range.start, self.pos)
            }
        } else if self.wrapped {
            (self.pos, self.origin)
        } else {
            (self.pos, self.cand_end())
        };

        if lo >= hi {
            return self.advance_pass();
        }

        // This call's window, read with an overlap of m−1 (a match may start
        // inside the window and end outside it).
        let (c0, c1) = if self.backward {
            (hi.saturating_sub(window).max(lo), hi)
        } else {
            (lo, (lo + window).min(hi))
        };
        let read_len = (c1 - c0) + (m - 1);
        let read = doc.read(c0, read_len.min(self.range.end - c0) as usize);

        let min_rel = if self.backward {
            0 // no cross-window suppression: only the last match matters
        } else {
            self.next_candidate.saturating_sub(c0) as usize
        };
        let mut rel = Vec::new();
        self.pattern.scan(&read.data, 0, (c1 - c0) as usize, min_rel, &mut rel);
        for r in rel {
            let at = c0 + r as u64;
            // F-06: an unreadable block's zeros are not data — discard.
            let bad = read.unreadable.iter().any(|u| u.start < at + m && at < u.end);
            if !bad {
                out.push(at);
                if !self.backward {
                    self.next_candidate = at + m;
                }
            }
        }

        let scanned = c1 - c0;
        if self.backward {
            self.pos = c0;
            if self.pos <= lo {
                return StepResult { finished: self.advance_pass().finished, scanned };
            }
        } else {
            self.pos = c1;
            if self.pos >= hi {
                return StepResult { finished: self.advance_pass().finished, scanned };
            }
        }
        StepResult { finished: false, scanned }
    }

    /// End of a pass: enter the wrap pass (F-15) or finish.
    fn advance_pass(&mut self) -> StepResult {
        if !self.wrapped && self.wrap {
            self.wrapped = true;
            if self.backward {
                // We already covered [start, origin); now from the top down to the origin.
                self.pos = self.cand_end();
                self.finished = self.pos <= self.origin;
            } else {
                // We already covered [origin, end); now from the start to the origin.
                self.pos = self.range.start;
                self.next_candidate = self.pos;
                self.finished = self.pos >= self.origin;
            }
        } else {
            self.finished = true;
        }
        StepResult { finished: self.finished, scanned: 0 }
    }
}

// ---- blocking helpers (CLI and tests; the GUI uses `step` per frame) ----

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    fn doc(bytes: &[u8]) -> Document {
        Document::new(Box::new(MemSource::new(bytes.to_vec())))
    }

    fn all_bytes(d: &mut Document) -> Vec<u8> {
        d.read(0, d.len() as usize).data
    }

    fn hex(s: &str) -> Pattern {
        Pattern::parse_hex(s).unwrap()
    }

    fn next(d: &mut Document, p: &Pattern, from: u64) -> Option<u64> {
        find_next(d, p, 0..d.len(), from, false, false, &Progress::new()).map(|r| r.start)
    }

    #[test]
    fn parse_hex_with_wildcards() {
        assert_eq!(
            hex("DE ?? BE EF"),
            Pattern::Bytes {
                bytes: vec![0xDE, 0x00, 0xBE, 0xEF],
                mask: vec![0xFF, 0x00, 0xFF, 0xFF],
                ci: false
            }
        );
        assert_eq!(
            hex("D? ?E"),
            Pattern::Bytes { bytes: vec![0xD0, 0x0E], mask: vec![0xF0, 0x0F], ci: false }
        );
        assert!(Pattern::parse_hex("????").is_none(), "wildcards only would match everything");
        assert!(Pattern::parse_hex("ABC").is_none());
        assert!(Pattern::parse_hex("").is_none());
    }

    #[test]
    fn a_simple_forward_and_backward_search() {
        let mut d = doc(b"xxABxxABxx");
        let p = hex("4142"); // "AB"
        assert_eq!(next(&mut d, &p, 0), Some(2));
        assert_eq!(next(&mut d, &p, 3), Some(6));
        assert_eq!(next(&mut d, &p, 7), None);
        let prev = |d: &mut Document, from| {
            find_next(d, &p, 0..d.len(), from, true, false, &Progress::new()).map(|r| r.start)
        };
        assert_eq!(prev(&mut d, 10), Some(6));
        assert_eq!(prev(&mut d, 6), Some(2), "candidates strictly before `from`");
        assert_eq!(prev(&mut d, 2), None);
    }

    #[test]
    fn wrap_finds_matches_before_and_across_the_origin() {
        let mut d = doc(b"ABxxxxxx");
        let p = hex("4142");
        let r = find_next(&mut d, &p, 0..8, 4, false, true, &Progress::new());
        assert_eq!(r, Some(0..2), "wrap returns to the start");
        // A match crossing the origin: starts before, ends after.
        let mut d = doc(b"xxABxx");
        let r = find_next(&mut d, &p, 0..6, 3, false, true, &Progress::new());
        assert_eq!(r, Some(2..4));
        // Without wrap, nothing.
        assert_eq!(find_next(&mut d, &p, 0..6, 3, false, false, &Progress::new()), None);
        // Backward wrap: origin 1, the match lies only above it.
        let mut d = doc(b"xxxxABxx");
        let r = find_next(&mut d, &p, 0..8, 1, true, true, &Progress::new());
        assert_eq!(r, Some(4..6));
    }

    #[test]
    fn matches_do_not_overlap() {
        let mut d = doc(b"AAAAA");
        let (found, trunc) =
            find_all(&mut d, &hex("4141"), 0..5, 100, &Progress::new());
        assert_eq!(found, vec![0, 2], "AAAAA has two matches of AA, not four");
        assert!(!trunc);
    }

    #[test]
    fn small_windows_do_not_miss_a_match_on_the_boundary() {
        // A 3-byte pattern crossing every possible window boundary.
        let mut data = vec![0u8; 64];
        for at in [0usize, 3, 6, 30, 61] {
            data[at..at + 3].copy_from_slice(b"XYZ");
        }
        let mut d = doc(&data);
        let mut s = Searcher::new(hex("58595A"), 0..64, 64, 0, false, false);
        let mut out = Vec::new();
        loop {
            // minimum budget: candidate windows of 1 byte
            if s.step(&mut d, 1, &mut out).finished {
                break;
            }
        }
        assert_eq!(out, vec![0, 3, 6, 30, 61]);
    }

    #[test]
    fn wildcards_and_nibble_masks() {
        let mut d = doc(&[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0x77, 0xBE, 0xEF]);
        let (found, _) = find_all(&mut d, &hex("DE ?? BE EF"), 0..8, 10, &Progress::new());
        assert_eq!(found, vec![0, 4]);
        // Nibble: "?E" does not match AD; it does match DE and BE.
        let (found, _) = find_all(&mut d, &hex("?E"), 0..8, 10, &Progress::new());
        assert_eq!(found, vec![0, 2, 4, 6]);
    }

    #[test]
    fn text_with_and_without_case_sensitivity() {
        let mut d = doc(b"Hello hELLo hello");
        let p = Pattern::text("hello", Charset::Ascii, false).unwrap();
        let (found, _) = find_all(&mut d, &p, 0..17, 10, &Progress::new());
        assert_eq!(found, vec![12]);
        let p = Pattern::text("hello", Charset::Ascii, true).unwrap();
        let (found, _) = find_all(&mut d, &p, 0..17, 10, &Progress::new());
        assert_eq!(found, vec![0, 6, 12]);
    }

    #[test]
    fn text_in_utf16le() {
        // "AB" in UTF-16LE
        let mut d = doc(&[0x00, 0x41, 0x00, 0x42, 0x00, 0x41, 0x00]);
        let p = Pattern::text("A", Charset::Utf16Le, false).unwrap();
        let (found, _) = find_all(&mut d, &p, 0..7, 10, &Progress::new());
        assert_eq!(found, vec![1, 5], "41 00 at positions 1 and 5");
    }

    #[test]
    fn a_search_restricted_to_a_range() {
        let mut d = doc(b"ABxxABxxAB");
        let p = hex("4142");
        let (found, _) = find_all(&mut d, &p, 3..9, 10, &Progress::new());
        assert_eq!(found, vec![4], "only the match entirely inside 3..9");
    }

    #[test]
    fn an_unreadable_block_never_matches() {
        let src = MemSource::new(vec![0u8; 64]).with_bad_range(16..32);
        let mut d = Document::new(Box::new(src));
        d.set_cache(crate::cache::BlockCache::new(16, 8));
        // Real zeros exist outside the bad block; inside it, they are invented.
        let (found, _) = find_all(&mut d, &hex("0000"), 0..64, 100, &Progress::new());
        assert!(found.iter().all(|at| *at + 2 <= 16 || *at >= 32), "{found:?}");
        assert!(!found.is_empty());
    }

    #[test]
    fn typed_search_for_ints_and_floats() {
        let mut data = 1234i32.to_le_bytes().to_vec();
        data.extend_from_slice(&2.75f32.to_le_bytes());
        data.extend_from_slice(&1234i32.to_be_bytes());
        let mut d = doc(&data);

        let p = Pattern::typed("i32", "1234", Endian::Little, None).unwrap();
        let (found, _) = find_all(&mut d, &p, 0..12, 10, &Progress::new());
        assert_eq!(found, vec![0]);
        let p = Pattern::typed("i32", "1234", Endian::Big, None).unwrap();
        let (found, _) = find_all(&mut d, &p, 0..12, 10, &Progress::new());
        assert_eq!(found, vec![8]);
        // Float with a tolerance: 2.7501 is not 2.75, but with tol 0.05 it matches.
        let p = Pattern::typed("f32", "2.7501", Endian::Little, Some(0.05)).unwrap();
        let (found, _) = find_all(&mut d, &p, 0..12, 10, &Progress::new());
        assert_eq!(found, vec![4]);
        let p = Pattern::typed("f32", "2.7501", Endian::Little, Some(0.00001)).unwrap();
        let (found, _) = find_all(&mut d, &p, 0..12, 10, &Progress::new());
        assert!(found.is_empty(), "a tight tolerance does not match 2.75");
    }

    #[test]
    fn replace_all_of_equal_length_is_a_single_undo() {
        let mut d = doc(b"xxABxxABxx");
        let n = replace_all(&mut d, &hex("4142"), b"CD", 0..10, &Progress::new()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(all_bytes(&mut d), b"xxCDxxCDxx");
        assert!(d.undo());
        assert_eq!(all_bytes(&mut d), b"xxABxxABxx");
        assert!(!d.can_undo(), "replacing everything is one transaction");
    }

    #[test]
    fn replace_all_changes_the_size_without_losing_the_rest() {
        let mut d = doc(b"a<>b<>c");
        let n = replace_all(&mut d, &hex("3C3E"), b"---", 0..7, &Progress::new()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(all_bytes(&mut d), b"a---b---c");
        // Shrinking (an empty replacement = deleting the matches).
        let mut d = doc(b"a<>b<>c");
        let n = replace_all(&mut d, &hex("3C3E"), b"", 0..7, &Progress::new()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(all_bytes(&mut d), b"abc");
        assert!(d.undo());
        assert_eq!(all_bytes(&mut d), b"a<>b<>c");
    }

    #[test]
    fn replace_all_does_not_reprocess_the_replacement() {
        // The replacement contains the pattern: it must not loop forever.
        let mut d = doc(b"ab");
        let n = replace_all(&mut d, &hex("6162"), b"abab", 0..2, &Progress::new()).unwrap();
        assert_eq!(n, 1);
        assert_eq!(all_bytes(&mut d), b"abab");
    }

    #[test]
    fn replace_all_cancelled_upfront_does_not_touch_the_document() {
        let mut d = doc(b"xxABxx");
        let p = Progress::new();
        p.cancel();
        let n = replace_all(&mut d, &hex("4142"), b"CD", 0..6, &p).unwrap();
        assert_eq!(n, 0);
        assert!(!d.dirty());
    }
}
