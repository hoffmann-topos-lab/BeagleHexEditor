use std::ops::Range;

use crate::document::Document;
use crate::progress::Progress;
use crate::search::StepResult;

/// Window per step.
const WINDOW: u64 = 4 << 20;

/// F-32 — "Next difference", cooperative.
pub struct DiffJob {
    pos: u64,
    /// End of the common prefix: `min(len_a, len_b)`.
    common_end: u64,
    lens_differ: bool,
    /// Some window contained unreadable bytes.
    pub approx: bool,
    done: bool,
}

impl DiffJob {
    pub fn new(from: u64, len_a: u64, len_b: u64) -> Self {
        let common_end = len_a.min(len_b);
        Self {
            pos: from.min(common_end),
            common_end,
            lens_differ: len_a != len_b,
            approx: false,
            done: false,
        }
    }

    pub fn total_space(&self) -> u64 {
        self.common_end
    }

    /// Scans up to `budget` bytes; returns the next difference, if found in
    /// this window.
    pub fn step(
        &mut self,
        a: &mut Document,
        b: &mut Document,
        budget: u64,
    ) -> (Option<u64>, StepResult) {
        if self.done {
            return (None, StepResult { finished: true, scanned: 0 });
        }
        if self.pos >= self.common_end {
            self.done = true;
            // Different sizes: the first "difference" is the end of the shorter one.
            let found = self.lens_differ.then_some(self.common_end);
            return (found, StepResult { finished: true, scanned: 0 });
        }
        let n = (self.common_end - self.pos).min(budget.clamp(1, WINDOW));
        let ra = a.read(self.pos, n as usize);
        let rb = b.read(self.pos, n as usize);
        self.approx |= !ra.is_clean() || !rb.is_clean();

        let found = ra
            .data
            .iter()
            .zip(&rb.data)
            .position(|(x, y)| x != y)
            .map(|i| self.pos + i as u64);
        self.pos += n;
        if let Some(at) = found {
            self.pos = at + 1; // the next call resumes right after it
            self.done = true;
            return (Some(at), StepResult { finished: true, scanned: n });
        }
        (None, StepResult { finished: false, scanned: n })
    }
}

/// Next difference from `from` (inclusive). Blocking.
pub fn next_diff(
    a: &mut Document,
    b: &mut Document,
    from: u64,
    progress: &Progress,
) -> Option<u64> {
    let mut job = DiffJob::new(from, a.len(), b.len());
    progress.set_total(job.total_space());
    loop {
        let (found, st) = job.step(a, b, WINDOW);
        progress.add_done(st.scanned);
        if found.is_some() || st.finished || progress.is_cancelled() {
            return found;
        }
    }
}

/// Contiguous ranges that differ (for `hexed diff`), up to `limit`. The second
/// value signals truncation.
pub fn diff_ranges(
    a: &mut Document,
    b: &mut Document,
    limit: usize,
    progress: &Progress,
) -> (Vec<Range<u64>>, bool) {
    let common = a.len().min(b.len());
    progress.set_total(common);
    let mut out: Vec<Range<u64>> = Vec::new();
    let mut pos = 0u64;
    while pos < common && !progress.is_cancelled() {
        let n = (common - pos).min(WINDOW);
        let ra = a.read(pos, n as usize);
        let rb = b.read(pos, n as usize);
        for (i, (x, y)) in ra.data.iter().zip(&rb.data).enumerate() {
            if x != y {
                let at = pos + i as u64;
                match out.last_mut() {
                    Some(last) if last.end == at => last.end = at + 1,
                    _ => {
                        if out.len() >= limit {
                            return (out, true);
                        }
                        out.push(at..at + 1);
                    }
                }
            }
        }
        progress.add_done(n);
        pos += n;
    }
    // Tail: the longer document differs entirely from the end of the shorter one.
    if a.len() != b.len() {
        let (s, e) = (common, a.len().max(b.len()));
        if let Some(last) = out.last_mut()
            && last.end == s
        {
            last.end = e;
        } else if out.len() >= limit {
            return (out, true);
        } else {
            out.push(s..e);
        }
    }
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    fn doc(bytes: &[u8]) -> Document {
        Document::new(Box::new(MemSource::new(bytes.to_vec())))
    }

    #[test]
    fn identical_documents_have_no_difference() {
        let (mut a, mut b) = (doc(b"exactly equal"), doc(b"exactly equal"));
        assert_eq!(next_diff(&mut a, &mut b, 0, &Progress::new()), None);
        let (ranges, _) = diff_ranges(&mut a, &mut b, 100, &Progress::new());
        assert!(ranges.is_empty());
    }

    #[test]
    fn the_next_difference_is_navigable() {
        let (mut a, mut b) = (doc(b"aXcdeYg"), doc(b"abcdefg"));
        assert_eq!(next_diff(&mut a, &mut b, 0, &Progress::new()), Some(1));
        assert_eq!(next_diff(&mut a, &mut b, 2, &Progress::new()), Some(5));
        assert_eq!(next_diff(&mut a, &mut b, 6, &Progress::new()), None);
    }

    #[test]
    fn different_sizes_differ_at_the_end_of_the_shorter_one() {
        let (mut a, mut b) = (doc(b"abc"), doc(b"abcdef"));
        assert_eq!(next_diff(&mut a, &mut b, 0, &Progress::new()), Some(3));
        let (ranges, _) = diff_ranges(&mut a, &mut b, 100, &Progress::new());
        assert_eq!(ranges, vec![3..6]);
    }

    #[test]
    fn contiguous_ranges_are_grouped() {
        let (mut a, mut b) = (doc(b"XXcdXXg"), doc(b"abcdefg"));
        let (ranges, trunc) = diff_ranges(&mut a, &mut b, 100, &Progress::new());
        assert_eq!(ranges, vec![0..2, 4..6]);
        assert!(!trunc);
    }

    #[test]
    fn the_range_limit_truncates() {
        let (mut a, mut b) = (doc(b"XbXbXbXb"), doc(b"abababab"));
        let (ranges, trunc) = diff_ranges(&mut a, &mut b, 2, &Progress::new());
        assert_eq!(ranges.len(), 2);
        assert!(trunc);
    }

    #[test]
    fn it_compares_unsaved_edits() {
        let mut a = doc(b"abc");
        let mut b = doc(b"abc");
        b.overwrite(1, b"Z").unwrap();
        assert_eq!(next_diff(&mut a, &mut b, 0, &Progress::new()), Some(1));
    }

    #[test]
    fn small_windows_do_not_miss_a_difference() {
        let mut data = vec![0u8; 1000];
        data[777] = 1;
        let (mut a, mut b) = (doc(&vec![0u8; 1000]), doc(&data));
        let mut job = DiffJob::new(0, 1000, 1000);
        let mut found = None;
        loop {
            let (f, st) = job.step(&mut a, &mut b, 64);
            if f.is_some() {
                found = f;
                break;
            }
            if st.finished {
                break;
            }
        }
        assert_eq!(found, Some(777));
    }
}
