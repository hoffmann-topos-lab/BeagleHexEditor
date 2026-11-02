//! F-07 — The shared plumbing of the cooperative jobs (hash, strings, stats,
//! magic, diff, search, export, records, recipe, split/concat).
//!
//! Every job follows one shape: a cursor walks a clamped range in windows,
//! `step(budget)` does one window's worth of work, and the GUI calls it once
//! per frame while the CLI drives it to the end through [`run`] or [`sweep`].

use std::ops::Range;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::progress::Progress;

/// Default largest window per step — the granularity of progress and
/// cancellation. Jobs that turn bytes into much larger text cap it lower
/// ([`RangeCursor::with_window`]).
pub const WINDOW: u64 = 4 << 20;

/// Result of one cooperative step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepResult {
    /// The job's space is exhausted.
    pub finished: bool,
    /// Bytes processed in this step — feeds the caller's `Progress`.
    pub scanned: u64,
}

impl StepResult {
    /// Nothing left to do.
    pub const DONE: Self = Self { finished: true, scanned: 0 };
}

/// A forward cursor over a document range clamped to the document, consumed
/// one window at a time.
#[derive(Debug, Clone)]
pub(crate) struct RangeCursor {
    range: Range<u64>,
    pos: u64,
    window: u64,
}

impl RangeCursor {
    /// Clamps `range` to `[0, doc_len)`; an inverted range becomes empty.
    pub(crate) fn new(range: Range<u64>, doc_len: u64) -> Self {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len).max(start);
        Self { range: start..end, pos: start, window: WINDOW }
    }

    /// Caps each window at `window` bytes instead of [`WINDOW`].
    pub(crate) fn with_window(mut self, window: u64) -> Self {
        self.window = window.max(1);
        self
    }

    pub(crate) fn start(&self) -> u64 {
        self.range.start
    }

    pub(crate) fn end(&self) -> u64 {
        self.range.end
    }

    pub(crate) fn pos(&self) -> u64 {
        self.pos
    }

    pub(crate) fn total(&self) -> u64 {
        self.range.end - self.range.start
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.range.end - self.pos
    }

    pub(crate) fn is_done(&self) -> bool {
        self.pos >= self.range.end
    }

    /// Length of the next window for `budget`, capped by the window size and
    /// by what remains. A `unit` above 1 rounds down to whole units (lines,
    /// records) but never below one unit; the final window may be short.
    pub(crate) fn next_len(&self, budget: u64, unit: u64) -> u64 {
        let want = budget.clamp(1, self.window);
        let want = (want - want % unit).max(unit);
        want.min(self.remaining())
    }

    pub(crate) fn advance(&mut self, n: u64) {
        self.pos = (self.pos + n).min(self.range.end);
    }
}

/// Reads `len` bytes at `at`, refusing unreadable blocks: hashing, exporting or
/// transforming invented zeros would be a silent lie (F-06). `what` names the
/// operation in the error ("export", "split", …).
pub(crate) fn read_clean(doc: &mut Document, at: u64, len: u64, what: &str) -> Result<Vec<u8>> {
    let read = doc.read(at, len as usize);
    match read.unreadable.first() {
        None => Ok(read.data),
        Some(bad) => Err(Error::new(
            ErrorKind::BadBlock,
            format!("unreadable block at {:#x}; {what} aborted", bad.start),
        )),
    }
}

/// Drives a fallible job to the end with [`WINDOW`] budgets (CLI and tests).
/// Cancellation is an error: half a hash or half an export is no result.
pub(crate) fn run(
    progress: &Progress,
    total: u64,
    mut step: impl FnMut(u64) -> Result<StepResult>,
) -> Result<()> {
    progress.set_total(total);
    loop {
        if progress.is_cancelled() {
            return Err(Error::cancelled());
        }
        let st = step(WINDOW)?;
        progress.add_done(st.scanned);
        if st.finished {
            return Ok(());
        }
    }
}

/// Drives a scan whose partial result is still meaningful (strings, stats,
/// signatures, differences, matches): cancellation simply stops it. `step` may
/// report `finished` early — a result limit was reached.
pub(crate) fn sweep(progress: &Progress, total: u64, mut step: impl FnMut(u64) -> StepResult) {
    progress.set_total(total);
    loop {
        let st = step(WINDOW);
        progress.add_done(st.scanned);
        if st.finished || progress.is_cancelled() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    #[test]
    fn the_cursor_clamps_and_walks_in_windows() {
        let mut c = RangeCursor::new(10..100, 50).with_window(16);
        assert_eq!((c.start(), c.end(), c.total()), (10, 50, 40));
        assert_eq!(c.next_len(1000, 1), 16, "capped by the window");
        assert_eq!(c.next_len(0, 1), 1, "a zero budget still progresses");
        assert_eq!(c.next_len(1000, 5), 15, "whole units");
        assert_eq!(c.next_len(3, 5), 5, "never below one unit");
        c.advance(36);
        assert_eq!(c.next_len(1000, 1), 4, "the final window is short");
        c.advance(100);
        assert!(c.is_done());
        assert_eq!(c.pos(), 50, "advance never overshoots");

        #[allow(clippy::reversed_empty_ranges)] // the point of the test
        let inverted = RangeCursor::new(30..10, 50);
        assert_eq!(inverted.total(), 0);
        assert!(inverted.is_done());
    }

    #[test]
    fn read_clean_refuses_unreadable_blocks() {
        let src = MemSource::new(vec![7; 64]).with_bad_range(32..40);
        let mut doc = Document::new(Box::new(src));
        doc.set_cache(crate::cache::BlockCache::new(16, 8)); // bad blocks at 16-byte granularity
        assert_eq!(read_clean(&mut doc, 0, 32, "test").unwrap(), vec![7; 32]);
        let e = read_clean(&mut doc, 16, 32, "test").unwrap_err();
        assert_eq!(e.kind, ErrorKind::BadBlock);
        assert!(e.detail.contains("0x20") && e.detail.contains("test aborted"), "{e}");
    }

    #[test]
    fn run_reports_progress_and_treats_cancel_as_an_error() {
        let p = Progress::new();
        let mut left = 10u64;
        run(&p, 10, |b| {
            let n = left.min(b).min(4);
            left -= n;
            Ok(StepResult { finished: left == 0, scanned: n })
        })
        .unwrap();
        assert_eq!((p.done(), p.total()), (10, 10));

        let p = Progress::new();
        p.cancel();
        let e = run(&p, 10, |_| unreachable!("cancelled before the first step")).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Cancelled);
    }

    #[test]
    fn sweep_stops_quietly_on_cancel() {
        let p = Progress::new();
        let mut steps = 0;
        sweep(&p, 100, |_| {
            steps += 1;
            if steps == 3 {
                p.cancel();
            }
            StepResult { finished: false, scanned: 1 }
        });
        assert_eq!((steps, p.done()), (3, 3));
    }
}
