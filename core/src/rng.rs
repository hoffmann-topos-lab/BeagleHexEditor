//! xorshift64*: a small, dependency-free PRNG, good enough to fill bytes.
//! Shared by `fill` (F-22) and the shredder (F-45). Not cryptographic, and
//! neither use needs it to be.

pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        // splitmix64 spreads the seed; it also avoids state 0, which is
        // absorbing in xorshift.
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Self((z ^ (z >> 31)) | 1)
    }

    pub(crate) fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            let v = self.0.wrapping_mul(0x2545_F491_4F6C_DD1D);
            chunk.copy_from_slice(&v.to_le_bytes()[..chunk.len()]);
        }
    }

    /// A time-derived seed for callers that just want unpredictable bytes.
    pub(crate) fn seed_from_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678)
    }
}
