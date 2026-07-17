//! F-79/F-80 — Transformations (Fase 12), the CyberChef of the toolkit.
//!
//! A [`Recipe`] is an ordered list of [`Op`]s applied to a byte buffer. Each op
//! is a pure function `Vec<u8> -> Result<Vec<u8>>`: encodings ([`codec`]),
//! bitwise/arithmetic ([`bitwise`]), compression ([`compress`], via
//! `miniz_oxide`), symmetric ciphers ([`crypto`], via RustCrypto) and digests
//! ([`digest`], reusing [`crate::hash`]).
//!
//! Transforms need the whole input in RAM (you cannot base64 a stream a window
//! at a time), so a recipe runs on a *selection*, not the whole 100 GB file:
//! [`RecipeJob`] reads the range cooperatively (F-07 — cancellable, aborts on an
//! unreadable block like every other reader) into a capped buffer, then applies
//! the recipe. Everything is CLI-exercisable through `hexed recipe`.

mod bitwise;
mod codec;
mod compress;
mod crypto;
mod digest;
mod parse;
#[cfg(test)]
mod tests;

use std::ops::Range;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::hash::Algo;
use crate::progress::Progress;

pub use compress::MAX_OUTPUT;
pub use crypto::AesMode;

/// Read window per cooperative step.
const WINDOW: u64 = 1 << 20;

/// Default ceiling on the selection a recipe will materialize (256 MiB). A
/// larger range is refused, not truncated — narrow it, or raise the cap.
pub const DEFAULT_CAP: u64 = 256 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Variant {
    Standard,
    UrlSafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base85Variant {
    Ascii85,
    Z85,
}

/// One transformation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Base64 { variant: Base64Variant, encode: bool },
    Base32 { encode: bool },
    Base85 { variant: Base85Variant, encode: bool },
    Hex { encode: bool },
    Url { encode: bool },
    Xor { key: Vec<u8> },
    Add { delta: u8 },
    Sub { delta: u8 },
    Rotate { left: bool, bits: u32 },
    Not,
    Reverse,
    Deflate { encode: bool },
    Zlib { encode: bool },
    Gzip { encode: bool },
    Aes { mode: AesMode, key: Vec<u8>, iv: Vec<u8>, encrypt: bool },
    Rc4 { key: Vec<u8> },
    Hash { algo: Algo },
}

impl Op {
    /// Applies this single step, consuming and returning the buffer.
    pub fn apply(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        Ok(match self {
            Op::Base64 { variant, encode: true } => {
                codec::base64_encode(&input, *variant == Base64Variant::UrlSafe)
            }
            Op::Base64 { encode: false, .. } => codec::base64_decode(&input)?,
            Op::Base32 { encode: true } => codec::base32_encode(&input),
            Op::Base32 { encode: false } => codec::base32_decode(&input)?,
            Op::Base85 { variant: Base85Variant::Ascii85, encode: true } => {
                codec::ascii85_encode(&input)
            }
            Op::Base85 { variant: Base85Variant::Ascii85, encode: false } => {
                codec::ascii85_decode(&input)?
            }
            Op::Base85 { variant: Base85Variant::Z85, encode: true } => codec::z85_encode(&input)?,
            Op::Base85 { variant: Base85Variant::Z85, encode: false } => codec::z85_decode(&input)?,
            Op::Hex { encode: true } => codec::hex_encode(&input),
            Op::Hex { encode: false } => codec::hex_decode(&input)?,
            Op::Url { encode: true } => codec::url_encode(&input),
            Op::Url { encode: false } => codec::url_decode(&input)?,
            Op::Xor { key } => bitwise::xor(input, key),
            Op::Add { delta } => bitwise::add(input, *delta),
            Op::Sub { delta } => bitwise::sub(input, *delta),
            Op::Rotate { left, bits } => bitwise::rotate(input, *left, *bits),
            Op::Not => bitwise::not(input),
            Op::Reverse => bitwise::reverse(input),
            Op::Deflate { encode: true } => compress::deflate(&input),
            Op::Deflate { encode: false } => compress::inflate(&input)?,
            Op::Zlib { encode: true } => compress::zlib_compress(&input),
            Op::Zlib { encode: false } => compress::zlib_decompress(&input)?,
            Op::Gzip { encode: true } => compress::gzip_compress(&input),
            Op::Gzip { encode: false } => compress::gunzip(&input)?,
            Op::Aes { mode, key, iv, encrypt } => crypto::aes(*mode, *encrypt, key, iv, &input)?,
            Op::Rc4 { key } => crypto::rc4(key, &input)?,
            Op::Hash { algo } => digest::hash(*algo, &input),
        })
    }
}

/// A composed pipeline of transformations (F-80).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recipe {
    pub ops: Vec<Op>,
}

impl Recipe {
    pub fn new(ops: Vec<Op>) -> Self {
        Self { ops }
    }

    /// Parses a `|`-separated recipe spec (see [`parse`]).
    pub fn parse(spec: &str) -> Result<Recipe> {
        parse::parse(spec)
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Applies every step in order. The step index is reported on failure so a
    /// long pipeline points at the op that broke.
    pub fn apply(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let mut buf = input;
        for (i, op) in self.ops.iter().enumerate() {
            buf = op.apply(buf).map_err(|e| {
                Error::new(e.kind, format!("recipe step {} ({op:?}): {}", i + 1, e.detail))
            })?;
        }
        Ok(buf)
    }
}

/// F-80 — Cooperative reader for a recipe's input selection. Reads the range in
/// windows (cancellable, progress-reporting), then [`finish`](Self::finish)
/// applies the recipe to what it gathered.
pub struct RecipeJob {
    recipe: Recipe,
    range: Range<u64>,
    pos: u64,
    buf: Vec<u8>,
}

impl RecipeJob {
    /// Fails when the selection is larger than `cap` — a recipe materializes its
    /// input, so an unbounded range would be an unbounded allocation.
    pub fn new(recipe: Recipe, range: Range<u64>, doc_len: u64, cap: u64) -> Result<Self> {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len).max(start);
        let len = end - start;
        if len > cap {
            return Err(Error::new(
                ErrorKind::Io,
                format!(
                    "selection is {len} bytes; the recipe cap is {cap} — \
                     narrow it with --start/--end or raise --cap"
                ),
            ));
        }
        Ok(Self { recipe, range: start..end, pos: start, buf: Vec::with_capacity(len as usize) })
    }

    pub fn total(&self) -> u64 {
        self.range.end - self.range.start
    }

    /// True once the whole selection has been read into the buffer.
    pub fn is_read_done(&self) -> bool {
        self.pos >= self.range.end
    }

    /// Reads up to `budget` bytes of the selection. An unreadable block aborts
    /// (transforming invented zeros would be a silent lie — same rule as export).
    pub fn step(&mut self, doc: &mut Document, budget: u64) -> Result<u64> {
        if self.is_read_done() {
            return Ok(0);
        }
        let n = (self.range.end - self.pos).min(budget.clamp(1, WINDOW));
        let read = doc.read(self.pos, n as usize);
        if !read.is_clean() {
            return Err(Error::new(
                ErrorKind::BadBlock,
                format!("unreadable block at {:#x}; recipe aborted", read.unreadable[0].start),
            ));
        }
        self.buf.extend_from_slice(&read.data);
        self.pos += n;
        Ok(n)
    }

    /// Applies the recipe to the gathered selection.
    pub fn finish(self) -> Result<Vec<u8>> {
        self.recipe.apply(self.buf)
    }
}

/// Blocking helper (CLI and tests): the GUI would drive `RecipeJob::step` per
/// frame, then call `finish`.
pub fn run(
    doc: &mut Document,
    range: Range<u64>,
    recipe: &Recipe,
    cap: u64,
    progress: &Progress,
) -> Result<Vec<u8>> {
    let mut job = RecipeJob::new(recipe.clone(), range, doc.len(), cap)?;
    progress.set_total(job.total());
    while !job.is_read_done() {
        if progress.is_cancelled() {
            return Err(Error::new(ErrorKind::Io, "cancelled"));
        }
        let n = job.step(doc, WINDOW)?;
        progress.add_done(n);
    }
    job.finish()
}
