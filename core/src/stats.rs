
use std::ops::Range;

use crate::document::Document;
use crate::progress::Progress;
use crate::search::StepResult;

/// Window per step.
const WINDOW: u64 = 4 << 20;

/// Automatic block size: aims for ~2048 points on the chart, between 256 B and 1 MiB.
pub fn auto_block_size(len: u64) -> u64 {
    let target = (len / 2048).max(1);
    target.next_power_of_two().clamp(256, 1 << 20)
}

#[derive(Debug, Clone)]
pub struct Stats {
    /// How many times each byte value appeared (F-29).
    pub counts: [u64; 256],
    /// Bytes counted (excluding the unreadable ones).
    pub total: u64,
    /// Bytes skipped for being unreadable — if > 0, warn the user.
    pub unreadable: u64,
    /// Block size of the entropy series (F-30a).
    pub block_size: u64,
    /// Shannon entropy of each block, in bits/byte (0–8). `NaN` = a block with
    /// no readable byte at all.
    pub blocks: Vec<f32>,
}

impl Stats {
    /// Shannon entropy of the whole range, in bits per byte.
    pub fn entropy(&self) -> f64 {
        shannon(&self.counts.map(|c| c), self.total)
    }
}

fn shannon(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let mut h = 0.0f64;
    for c in counts {
        if *c > 0 {
            let p = *c as f64 / total as f64;
            h -= p * p.log2();
        }
    }
    h
}

/// F-29/F-30a — Cooperative job: global histogram + entropy per block.
pub struct StatsJob {
    range: Range<u64>,
    pos: u64,
    block_size: u64,
    /// End (absolute offset) of the block in progress.
    block_end: u64,
    counts: [u64; 256],
    total: u64,
    unreadable: u64,
    cur: [u32; 256],
    cur_total: u64,
    blocks: Vec<f32>,
}

impl StatsJob {
    /// `block_size = None` picks one automatically from the range size.
    pub fn new(range: Range<u64>, doc_len: u64, block_size: Option<u64>) -> Self {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len);
        let bs = block_size.unwrap_or_else(|| auto_block_size(end - start)).max(1);
        Self {
            range: start..end,
            pos: start,
            block_size: bs,
            block_end: (start + bs).min(end),
            counts: [0; 256],
            total: 0,
            unreadable: 0,
            cur: [0; 256],
            cur_total: 0,
            blocks: Vec::new(),
        }
    }

    pub fn total_space(&self) -> u64 {
        self.range.end - self.range.start
    }

    fn close_block(&mut self) {
        if self.cur_total == 0 {
            // No readable byte: a hole in the chart, not a zero.
            self.blocks.push(f32::NAN);
        } else {
            let counts: [u64; 256] = std::array::from_fn(|i| self.cur[i] as u64);
            self.blocks.push(shannon(&counts, self.cur_total) as f32);
        }
        self.cur = [0; 256];
        self.cur_total = 0;
    }

    /// Advances `len` positions from `abs`; `data` is `None` over an unreadable
    /// span. Closes blocks when crossing their boundaries.
    fn account(&mut self, mut abs: u64, mut data: Option<&[u8]>, mut len: u64) {
        while len > 0 {
            let take = len.min(self.block_end - abs);
            match &mut data {
                Some(d) => {
                    let (now, rest) = d.split_at(take as usize);
                    for b in now {
                        self.counts[*b as usize] += 1;
                        self.cur[*b as usize] += 1;
                    }
                    self.total += take;
                    self.cur_total += take;
                    *d = rest;
                }
                None => self.unreadable += take,
            }
            abs += take;
            len -= take;
            if abs == self.block_end && self.block_end < self.range.end {
                self.close_block();
                self.block_end = (self.block_end + self.block_size).min(self.range.end);
            }
        }
    }

    pub fn step(&mut self, doc: &mut Document, budget: u64) -> StepResult {
        if self.pos >= self.range.end {
            return StepResult { finished: true, scanned: 0 };
        }
        let n = (self.range.end - self.pos).min(budget.clamp(1, WINDOW));
        let read = doc.read(self.pos, n as usize);

        // Walk the window in readable/unreadable segments, in order.
        let mut at = self.pos;
        let window_end = self.pos + n;
        for bad in &read.unreadable {
            if bad.start > at {
                let rel = (at - self.pos) as usize;
                let len = bad.start - at;
                self.account(at, Some(&read.data[rel..rel + len as usize]), len);
            }
            self.account(bad.start, None, bad.end - bad.start);
            at = bad.end;
        }
        if at < window_end {
            let rel = (at - self.pos) as usize;
            self.account(at, Some(&read.data[rel..]), window_end - at);
        }

        self.pos = window_end;
        let finished = self.pos >= self.range.end;
        if finished {
            self.close_block(); // the last block, possibly partial
        }
        StepResult { finished, scanned: n }
    }

    pub fn finish(self) -> Stats {
        Stats {
            counts: self.counts,
            total: self.total,
            unreadable: self.unreadable,
            block_size: self.block_size,
            blocks: self.blocks,
        }
    }
}

/// Blocking helper (CLI and tests).
pub fn stats(
    doc: &mut Document,
    range: Range<u64>,
    block_size: Option<u64>,
    progress: &Progress,
) -> Stats {
    let mut job = StatsJob::new(range, doc.len(), block_size);
    progress.set_total(job.total_space());
    loop {
        let st = job.step(doc, WINDOW);
        progress.add_done(st.scanned);
        if st.finished || progress.is_cancelled() {
            break;
        }
    }
    job.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    fn stats_of(data: &[u8], block: Option<u64>) -> Stats {
        let mut d = Document::new(Box::new(MemSource::new(data.to_vec())));
        let len = d.len();
        stats(&mut d, 0..len, block, &Progress::new())
    }

    #[test]
    fn the_histogram_counts_every_value() {
        let s = stats_of(b"aabbbc", None);
        assert_eq!(s.total, 6);
        assert_eq!(s.counts[b'a' as usize], 2);
        assert_eq!(s.counts[b'b' as usize], 3);
        assert_eq!(s.counts[b'c' as usize], 1);
        assert_eq!(s.counts.iter().sum::<u64>(), 6);
    }

    #[test]
    fn entropy_of_known_cases() {
        // Constant: 0 bits. Half/half: 1 bit. Uniform 0..=255: 8 bits.
        assert_eq!(stats_of(&[7u8; 1024], None).entropy(), 0.0);
        let mut half = vec![0u8; 512];
        half.extend(vec![1u8; 512]);
        assert!((stats_of(&half, None).entropy() - 1.0).abs() < 1e-9);
        let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!((stats_of(&uniform, None).entropy() - 8.0).abs() < 1e-9);
    }

    #[test]
    fn per_block_entropy_across_window_boundaries() {
        // 4 blocks of 256: constant, uniform, constant, uniform.
        let mut data = vec![0u8; 256];
        data.extend((0..=255u8).collect::<Vec<_>>());
        data.extend(vec![9u8; 256]);
        data.extend((0..=255u8).collect::<Vec<_>>());
        let mut d = Document::new(Box::new(MemSource::new(data)));
        let mut job = StatsJob::new(0..1024, 1024, Some(256));
        // 100-byte windows: block and window boundaries are misaligned.
        while !job.step(&mut d, 100).finished {}
        let s = job.finish();
        assert_eq!(s.blocks.len(), 4);
        assert_eq!(s.blocks[0], 0.0);
        assert!((s.blocks[1] - 8.0).abs() < 1e-6);
        assert_eq!(s.blocks[2], 0.0);
        assert!((s.blocks[3] - 8.0).abs() < 1e-6);
    }

    #[test]
    fn the_partial_final_block_is_counted() {
        let s = stats_of(&[1u8; 300], Some(256));
        assert_eq!(s.blocks.len(), 2, "256 + 44");
        assert_eq!(s.total, 300);
    }

    #[test]
    fn unreadable_bytes_stay_out_of_the_count() {
        let src = MemSource::new(vec![0xAAu8; 64]).with_bad_range(16..32);
        let mut d = Document::new(Box::new(src));
        d.set_cache(crate::cache::BlockCache::new(16, 8));
        let s = stats(&mut d, 0..64, Some(16), &Progress::new());
        assert_eq!(s.total, 48);
        assert_eq!(s.unreadable, 16);
        assert_eq!(s.counts[0xAA], 48, "the bad block's zeros do not count");
        assert_eq!(s.blocks.len(), 4);
        assert!(s.blocks[1].is_nan(), "an unreadable block is a hole, not a zero");
    }

    #[test]
    fn the_automatic_block_size_is_reasonable() {
        assert_eq!(auto_block_size(0), 256);
        assert_eq!(auto_block_size(100_000), 256);
        assert_eq!(auto_block_size(100 << 30), auto_block_size(100 << 30).next_power_of_two());
        assert!(auto_block_size(100 << 30) <= 1 << 20);
    }
}
