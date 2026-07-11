use std::collections::HashMap;
use std::collections::VecDeque;
use std::ops::Range;
use std::sync::Arc;

use crate::error::ErrorKind;
use crate::source::DataSource;

pub const DEFAULT_BLOCK_SIZE: usize = 64 * 1024;
pub const DEFAULT_CAPACITY: usize = 256; // 16 MiB with the default block size

type BlockResult = Result<Arc<[u8]>, ErrorKind>;

pub struct BlockCache {
    block_size: u64,
    capacity: usize,
    blocks: HashMap<u64, BlockResult>,
    /// Use order, least to most recent. `capacity` is small, so the linear
    /// scan here costs less than a `pread`.
    order: VecDeque<u64>,
}

impl BlockCache {
    pub fn new(block_size: usize, capacity: usize) -> Self {
        assert!(block_size > 0 && capacity > 0);
        Self {
            block_size: block_size as u64,
            capacity,
            blocks: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Invalidates everything. Called when the source changes underneath us (F-43).
    pub fn invalidate(&mut self) {
        self.blocks.clear();
        self.order.clear();
    }

    fn touch(&mut self, index: u64) {
        if let Some(pos) = self.order.iter().position(|&i| i == index) {
            self.order.remove(pos);
        }
        self.order.push_back(index);
    }

    fn block(&mut self, src: &dyn DataSource, index: u64) -> BlockResult {
        if let Some(hit) = self.blocks.get(&index) {
            let hit = hit.clone();
            self.touch(index);
            return hit;
        }

        let start = index * self.block_size;
        let len = self.block_size.min(src.size().saturating_sub(start)) as usize;
        let mut buf = vec![0u8; len];
        let result: BlockResult = match src.read_at(start, &mut buf) {
            Ok(()) => Ok(Arc::from(buf.into_boxed_slice())),
            Err(e) => Err(e.kind),
        };

        let cacheable = match &result {
            Ok(_) => true,
            Err(kind) => kind.is_cacheable(),
        };
        if cacheable {
            while self.order.len() >= self.capacity {
                if let Some(evicted) = self.order.pop_front() {
                    self.blocks.remove(&evicted);
                }
            }
            self.blocks.insert(index, result.clone());
            self.order.push_back(index);
        }

        result
    }

    /// Fills `buf` with the bytes of `[offset, offset + buf.len())` from the source.
    ///
    /// Bytes from unreadable blocks are zeroed, and their ranges — in **source**
    /// coordinates — are returned. The UI draws `??` over them.
    pub fn read_into(
        &mut self,
        src: &dyn DataSource,
        offset: u64,
        buf: &mut [u8],
    ) -> Vec<Range<u64>> {
        let mut bad: Vec<Range<u64>> = Vec::new();
        if buf.is_empty() {
            return bad;
        }
        let end = offset + buf.len() as u64;
        let first = offset / self.block_size;
        let last = (end - 1) / self.block_size;

        for index in first..=last {
            let bstart = index * self.block_size;
            let copy_start = offset.max(bstart);
            let copy_end = end.min(bstart + self.block_size);
            let dst = &mut buf[(copy_start - offset) as usize..(copy_end - offset) as usize];

            match self.block(src, index) {
                Ok(block) => {
                    let s = (copy_start - bstart) as usize;
                    dst.copy_from_slice(&block[s..s + dst.len()]);
                }
                Err(_) => {
                    dst.fill(0);
                    match bad.last_mut() {
                        // Merge adjacent bad ranges.
                        Some(prev) if prev.end == copy_start => prev.end = copy_end,
                        _ => bad.push(copy_start..copy_end),
                    }
                }
            }
        }
        bad
    }
}

impl Default for BlockCache {
    fn default() -> Self {
        Self::new(DEFAULT_BLOCK_SIZE, DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    #[test]
    fn reads_across_block_boundaries() {
        let src = MemSource::new((0..=255u8).collect());
        let mut cache = BlockCache::new(16, 4);
        let mut buf = [0u8; 40];
        let bad = cache.read_into(&src, 10, &mut buf);
        assert!(bad.is_empty());
        assert_eq!(buf.to_vec(), (10..50u8).collect::<Vec<_>>());
    }

    #[test]
    fn bad_block_zeroes_and_reports_the_range() {
        // Block 1 = bytes [16, 32).
        let src = MemSource::new((0..=255u8).collect()).with_bad_range(16..32);
        let mut cache = BlockCache::new(16, 4);
        let mut buf = [0u8; 48];
        let bad = cache.read_into(&src, 0, &mut buf);

        assert_eq!(bad, vec![16..32]);
        assert_eq!(&buf[0..16], &(0..16u8).collect::<Vec<_>>()[..]);
        assert_eq!(&buf[16..32], &[0u8; 16]);
        assert_eq!(&buf[32..48], &(32..48u8).collect::<Vec<_>>()[..]);
    }

    #[test]
    fn adjacent_bad_ranges_are_merged() {
        let src = MemSource::new(vec![7u8; 64]).with_bad_range(16..48);
        let mut cache = BlockCache::new(16, 4);
        let mut buf = [0u8; 64];
        let bad = cache.read_into(&src, 0, &mut buf);
        assert_eq!(bad, vec![16..48]);
    }

    #[test]
    fn capacity_is_respected() {
        let src = MemSource::new(vec![0u8; 1024]);
        let mut cache = BlockCache::new(16, 4);
        let mut buf = [0u8; 16];
        for i in 0..10u64 {
            cache.read_into(&src, i * 16, &mut buf);
        }
        assert_eq!(cache.blocks.len(), 4);
        assert_eq!(cache.order.len(), 4);
    }

    #[test]
    fn short_final_block_is_read() {
        let src = MemSource::new(vec![9u8; 20]);
        let mut cache = BlockCache::new(16, 4);
        let mut buf = [0u8; 4];
        let bad = cache.read_into(&src, 16, &mut buf);
        assert!(bad.is_empty());
        assert_eq!(buf, [9u8; 4]);
    }
}
