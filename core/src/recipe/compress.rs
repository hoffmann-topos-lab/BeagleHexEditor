//! F-79 — DEFLATE / zlib / gzip, via `miniz_oxide` (pure Rust, D8). Only the raw
//! DEFLATE and zlib codecs come from the crate; the gzip framing (RFC 1952
//! header + CRC-32/ISIZE trailer) is wrapped here by hand.
//!
//! Decompression is bounded ([`MAX_OUTPUT`]) so a decompression bomb cannot
//! exhaust memory — the same defensive stance as the record-import cap.

use miniz_oxide::inflate::decompress_to_vec_with_limit;
use miniz_oxide::inflate::decompress_to_vec_zlib_with_limit;

use crate::error::{Error, ErrorKind, Result};

/// Cap on any single decompression step's output (512 MiB).
pub const MAX_OUTPUT: usize = 512 << 20;

/// A middle-of-the-road level: good ratio without the slowest search.
const LEVEL: u8 = 6;

fn bad(detail: impl Into<String>) -> Error {
    Error::new(ErrorKind::Io, detail)
}

fn inflate_err<E: std::fmt::Debug>(e: E) -> Error {
    bad(format!("decompression failed: {e:?}"))
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, LEVEL)
}

pub fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    decompress_to_vec_with_limit(data, MAX_OUTPUT).map_err(inflate_err)
}

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, LEVEL)
}

pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    decompress_to_vec_zlib_with_limit(data, MAX_OUTPUT).map_err(inflate_err)
}

pub fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2 + 18);
    // Fixed 10-byte header: magic, method DEFLATE, no flags, no mtime, unknown
    // extra flags, OS 0xFF ("unknown").
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff]);
    out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(data, LEVEL));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

pub fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b {
        return Err(bad("not a gzip stream (bad magic)"));
    }
    if data[2] != 0x08 {
        return Err(bad(format!("unsupported gzip method {}", data[2])));
    }
    let flags = data[3];
    let mut pos = 10;
    // Optional fields, in header order: FEXTRA, FNAME, FCOMMENT, FHCRC.
    if flags & 0x04 != 0 {
        let xlen = *data.get(pos).ok_or_else(trunc)? as usize
            | (*data.get(pos + 1).ok_or_else(trunc)? as usize) << 8;
        pos += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        pos = skip_cstr(data, pos)?;
    }
    if flags & 0x10 != 0 {
        pos = skip_cstr(data, pos)?;
    }
    if flags & 0x02 != 0 {
        pos += 2;
    }
    if pos + 8 > data.len() {
        return Err(trunc());
    }
    let body = &data[pos..data.len() - 8];
    let out = decompress_to_vec_with_limit(body, MAX_OUTPUT).map_err(inflate_err)?;

    let trailer = &data[data.len() - 8..];
    let want_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let want_len = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if crc32(&out) != want_crc {
        return Err(bad("gzip CRC-32 mismatch"));
    }
    if out.len() as u32 != want_len {
        return Err(bad("gzip length mismatch"));
    }
    Ok(out)
}

fn trunc() -> Error {
    bad("truncated gzip header")
}

fn skip_cstr(data: &[u8], mut pos: usize) -> Result<usize> {
    while *data.get(pos).ok_or_else(trunc)? != 0 {
        pos += 1;
    }
    Ok(pos + 1)
}

/// CRC-32/ISO-HDLC, the gzip/zlib variant. Kept local so the gzip framing does
/// not depend on the digest module's `Hasher` (which yields hex text).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}
