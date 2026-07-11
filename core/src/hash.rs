use std::ops::Range;

use md5::Digest as _;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::progress::Progress;

/// Window per step — the granularity of progress and cancellation.
const WINDOW: u64 = 4 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    // F-25 — cryptographic hashes.
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Blake3,
    // F-26 — checksums.
    Crc16,
    Crc32,
    Crc64,
    Adler32,
    Sum64,
    Xor8,
}

impl Algo {
    pub const ALL: [Algo; 11] = [
        Algo::Md5,
        Algo::Sha1,
        Algo::Sha256,
        Algo::Sha512,
        Algo::Blake3,
        Algo::Crc16,
        Algo::Crc32,
        Algo::Crc64,
        Algo::Adler32,
        Algo::Sum64,
        Algo::Xor8,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Algo::Md5 => "MD5",
            Algo::Sha1 => "SHA-1",
            Algo::Sha256 => "SHA-256",
            Algo::Sha512 => "SHA-512",
            Algo::Blake3 => "BLAKE3",
            Algo::Crc16 => "CRC-16",
            Algo::Crc32 => "CRC-32",
            Algo::Crc64 => "CRC-64",
            Algo::Adler32 => "Adler-32",
            Algo::Sum64 => "Sum-64",
            Algo::Xor8 => "XOR-8",
        }
    }

    pub fn from_name(s: &str) -> Option<Algo> {
        let k: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>()
            .to_lowercase();
        Some(match k.as_str() {
            "md5" => Algo::Md5,
            "sha1" => Algo::Sha1,
            "sha256" => Algo::Sha256,
            "sha512" => Algo::Sha512,
            "blake3" => Algo::Blake3,
            "crc16" => Algo::Crc16,
            "crc32" => Algo::Crc32,
            "crc64" => Algo::Crc64,
            "adler32" => Algo::Adler32,
            // `soma` is kept as a legacy Portuguese alias.
            "sum" | "sum64" | "soma" | "soma64" => Algo::Sum64,
            "xor" | "xor8" => Algo::Xor8,
            _ => return None,
        })
    }
}

/// Incremental state of one algorithm.
enum State {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Blake3(Box<blake3::Hasher>),
    /// Reflected CRCs with a 256-entry table built at creation (on the heap so
    /// that the enum's variants have comparable sizes).
    Crc16 { crc: u16, table: Box<[u16; 256]> },
    Crc32 { crc: u32, table: Box<[u32; 256]> },
    Crc64 { crc: u64, table: Box<[u64; 256]> },
    Adler32 { a: u32, b: u32 },
    Sum64(u64),
    Xor8(u8),
}

/// Reflected CRC table; valid for any width ≤ 64 (the high bits zero out on
/// their own).
fn crc_table(poly: u64) -> [u64; 256] {
    let mut table = [0u64; 256];
    for (i, e) in table.iter_mut().enumerate() {
        let mut v = i as u64;
        for _ in 0..8 {
            v = if v & 1 != 0 { (v >> 1) ^ poly } else { v >> 1 };
        }
        *e = v;
    }
    table
}

pub struct Hasher {
    algo: Algo,
    state: State,
}

impl Hasher {
    pub fn new(algo: Algo) -> Self {
        let state = match algo {
            Algo::Md5 => State::Md5(md5::Md5::new()),
            Algo::Sha1 => State::Sha1(sha1::Sha1::new()),
            Algo::Sha256 => State::Sha256(sha2::Sha256::new()),
            Algo::Sha512 => State::Sha512(sha2::Sha512::new()),
            Algo::Blake3 => State::Blake3(Box::new(blake3::Hasher::new())),
            Algo::Crc16 => {
                // CRC-16/ARC: poly 0x8005 reflected, init 0, no final xor.
                let t = crc_table(0xA001);
                State::Crc16 { crc: 0, table: Box::new(std::array::from_fn(|i| t[i] as u16)) }
            }
            Algo::Crc32 => {
                // CRC-32/ISO-HDLC (zlib): poly 0x04C11DB7 reflected.
                let t = crc_table(0xEDB8_8320);
                State::Crc32 { crc: !0, table: Box::new(std::array::from_fn(|i| t[i] as u32)) }
            }
            Algo::Crc64 => {
                // CRC-64/XZ: ECMA-182 poly, reflected.
                State::Crc64 { crc: !0, table: Box::new(crc_table(0xC96C_5795_D787_0F42)) }
            }
            Algo::Adler32 => State::Adler32 { a: 1, b: 0 },
            Algo::Sum64 => State::Sum64(0),
            Algo::Xor8 => State::Xor8(0),
        };
        Self { algo, state }
    }

    pub fn algo(&self) -> Algo {
        self.algo
    }

    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            State::Md5(h) => h.update(data),
            State::Sha1(h) => h.update(data),
            State::Sha256(h) => h.update(data),
            State::Sha512(h) => h.update(data),
            State::Blake3(h) => {
                h.update(data);
            }
            State::Crc16 { crc, table } => {
                for b in data {
                    *crc = (*crc >> 8) ^ table[((*crc ^ *b as u16) & 0xFF) as usize];
                }
            }
            State::Crc32 { crc, table } => {
                for b in data {
                    *crc = (*crc >> 8) ^ table[((*crc ^ *b as u32) & 0xFF) as usize];
                }
            }
            State::Crc64 { crc, table } => {
                for b in data {
                    *crc = (*crc >> 8) ^ table[((*crc ^ *b as u64) & 0xFF) as usize];
                }
            }
            State::Adler32 { a, b } => {
                // Deferred modulo in chunks (the classic 5552-byte limit).
                for chunk in data.chunks(5552) {
                    for byte in chunk {
                        *a += *byte as u32;
                        *b += *a;
                    }
                    *a %= 65521;
                    *b %= 65521;
                }
            }
            State::Sum64(s) => {
                for b in data {
                    *s = s.wrapping_add(*b as u64);
                }
            }
            State::Xor8(x) => {
                for b in data {
                    *x ^= *b;
                }
            }
        }
    }

    /// The result in hexadecimal (lowercase, like the system tools).
    pub fn finalize(self) -> String {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        match self.state {
            State::Md5(h) => hex(&h.finalize()),
            State::Sha1(h) => hex(&h.finalize()),
            State::Sha256(h) => hex(&h.finalize()),
            State::Sha512(h) => hex(&h.finalize()),
            State::Blake3(h) => h.finalize().to_hex().to_string(),
            State::Crc16 { crc, .. } => format!("{crc:04x}"),
            State::Crc32 { crc, .. } => format!("{:08x}", !crc),
            State::Crc64 { crc, .. } => format!("{:016x}", !crc),
            State::Adler32 { a, b } => format!("{:08x}", b << 16 | a),
            State::Sum64(s) => format!("{s:016x}"),
            State::Xor8(x) => format!("{x:02x}"),
        }
    }
}

/// F-25/F-26 — Cooperative computation: every algorithm in a single pass.
pub struct DigestJob {
    hashers: Vec<Hasher>,
    range: Range<u64>,
    pos: u64,
}

impl DigestJob {
    pub fn new(algos: &[Algo], range: Range<u64>, doc_len: u64) -> Self {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len);
        Self {
            hashers: algos.iter().map(|a| Hasher::new(*a)).collect(),
            range: start..end,
            pos: start,
        }
    }

    pub fn total(&self) -> u64 {
        self.range.end - self.range.start
    }

    pub fn is_finished(&self) -> bool {
        self.pos >= self.range.end
    }

    /// Processes up to `budget` bytes. Returns the bytes consumed; an
    /// unreadable block is a fatal error — a hash of invented data is no hash.
    pub fn step(&mut self, doc: &mut Document, budget: u64) -> Result<u64> {
        if self.is_finished() {
            return Ok(0);
        }
        let n = (self.range.end - self.pos).min(budget.clamp(1, WINDOW));
        let read = doc.read(self.pos, n as usize);
        if !read.is_clean() {
            return Err(Error::new(
                ErrorKind::BadBlock,
                format!("unreadable block at {:#x}; computation aborted", read.unreadable[0].start),
            ));
        }
        for h in &mut self.hashers {
            h.update(&read.data);
        }
        self.pos += n;
        Ok(n)
    }

    /// Consumes the finished job and returns `(algorithm, hex)` in the requested order.
    pub fn finish(self) -> Vec<(Algo, String)> {
        debug_assert!(self.is_finished());
        self.hashers.into_iter().map(|h| (h.algo(), h.finalize())).collect()
    }
}

/// Blocking helper (CLI and tests): the GUI drives `DigestJob::step` per frame.
pub fn digest(
    doc: &mut Document,
    algos: &[Algo],
    range: Range<u64>,
    progress: &Progress,
) -> Result<Vec<(Algo, String)>> {
    let mut job = DigestJob::new(algos, range, doc.len());
    progress.set_total(job.total());
    while !job.is_finished() {
        if progress.is_cancelled() {
            return Err(Error::new(ErrorKind::Io, "cancelled"));
        }
        let n = job.step(doc, WINDOW)?;
        progress.add_done(n);
    }
    Ok(job.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    fn hash_of(algo: Algo, data: &[u8]) -> String {
        let mut d = Document::new(Box::new(MemSource::new(data.to_vec())));
        let len = d.len();
        digest(&mut d, &[algo], 0..len, &Progress::new()).unwrap().remove(0).1
    }

    #[test]
    fn known_vectors_for_abc() {
        // The classic public vectors for "abc".
        assert_eq!(hash_of(Algo::Md5, b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hash_of(Algo::Sha1, b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hash_of(Algo::Sha256, b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_of(Algo::Sha512, b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hash_of(Algo::Blake3, b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn checksum_vectors_for_123456789() {
        // The classic check value of the CRC catalogues: "123456789".
        let data = b"123456789";
        assert_eq!(hash_of(Algo::Crc16, data), "bb3d");
        assert_eq!(hash_of(Algo::Crc32, data), "cbf43926");
        assert_eq!(hash_of(Algo::Crc64, data), "995dc9bbdf1939fa");
        assert_eq!(hash_of(Algo::Adler32, data), "091e01de");
        // Sum of the ASCII digits: 0x31+…+0x39 = 0x1DD.
        assert_eq!(hash_of(Algo::Sum64, data), "00000000000001dd");
        // XOR of 0x31..0x39 = 0x31.
        assert_eq!(hash_of(Algo::Xor8, data), "31");
    }

    #[test]
    fn the_empty_input_is_well_defined() {
        assert_eq!(hash_of(Algo::Md5, b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hash_of(Algo::Crc32, b""), "00000000");
        assert_eq!(hash_of(Algo::Adler32, b""), "00000001");
    }

    #[test]
    fn adler_does_not_overflow_on_large_data() {
        // 1 MiB of 0xFF: forces the deferred modulos to happen.
        let data = vec![0xFFu8; 1 << 20];
        let got = hash_of(Algo::Adler32, &data);
        // Reference: adler32 of 0xFF repeated 1048576 times (via zlib).
        let mut a = 1u64;
        let mut b = 0u64;
        for _ in 0..data.len() {
            a = (a + 0xFF) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!(got, format!("{:08x}", (b << 16 | a) as u32));
    }

    #[test]
    fn a_selection_differs_from_the_whole() {
        let mut d = Document::new(Box::new(MemSource::new(b"xxabcxx".to_vec())));
        let r = digest(&mut d, &[Algo::Sha256], 2..5, &Progress::new()).unwrap();
        assert_eq!(
            r[0].1,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "hash of the selection 'abc'"
        );
    }

    #[test]
    fn all_in_one_pass_match_one_at_a_time() {
        let data: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let mut d = Document::new(Box::new(MemSource::new(data.clone())));
        let len = d.len();
        let all = digest(&mut d, &Algo::ALL, 0..len, &Progress::new()).unwrap();
        for (algo, hex) in all {
            assert_eq!(hex, hash_of(algo, &data), "{}", algo.name());
        }
    }

    #[test]
    fn an_unreadable_block_aborts_the_computation() {
        let src = MemSource::new(vec![1u8; 64]).with_bad_range(16..32);
        let mut d = Document::new(Box::new(src));
        d.set_cache(crate::cache::BlockCache::new(16, 8));
        let err = digest(&mut d, &[Algo::Sha256], 0..64, &Progress::new()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::BadBlock);
    }

    #[test]
    fn the_hash_sees_unsaved_edits() {
        let mut d = Document::new(Box::new(MemSource::new(b"abd".to_vec())));
        d.overwrite(2, b"c").unwrap();
        let r = digest(&mut d, &[Algo::Md5], 0..3, &Progress::new()).unwrap();
        assert_eq!(r[0].1, "900150983cd24fb0d6963f7d28e17f72", "md5 of the edited 'abc'");
    }
}
