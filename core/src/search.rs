//! F-13/F-14/F-15 — Search. The pattern types live in `pattern`, the blocking
//! helpers (CLI) in `blocking`; the cooperative `Searcher` is here.

mod blocking;
mod pattern;
#[cfg(test)]
mod tests;

use std::ops::Range;

use crate::document::Document;

pub use blocking::{apply_replacement, find_all, find_next, replace_all};
pub use pattern::Pattern;

/// Largest window scanned by `step` — the granularity of progress and cancellation.
pub const WINDOW: u64 = 4 << 20;

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
