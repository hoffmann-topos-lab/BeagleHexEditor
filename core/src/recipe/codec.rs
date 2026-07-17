//! F-79 — Text encodings: Base64/32/85, hex and URL. All hand-rolled (no crate
//! is warranted, D8): each is a small, well-understood alphabet mapping.
//!
//! Decoders are deliberately tolerant — they skip ASCII whitespace and accept
//! both the standard and URL-safe Base64 alphabets — so a value pasted from
//! elsewhere round-trips. Encoders emit the canonical form.

use crate::error::{Error, ErrorKind, Result};

fn bad(detail: impl Into<String>) -> Error {
    Error::new(ErrorKind::Io, detail)
}

// ---- Base64 (RFC 4648) ----

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64_encode(data: &[u8], url_safe: bool) -> Vec<u8> {
    let alpha = if url_safe { B64_URL } else { B64_STD };
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(alpha[(n >> 18 & 0x3f) as usize]);
        out.push(alpha[(n >> 12 & 0x3f) as usize]);
        out.push(if chunk.len() > 1 { alpha[(n >> 6 & 0x3f) as usize] } else { b'=' });
        out.push(if chunk.len() > 2 { alpha[(n & 0x3f) as usize] } else { b'=' });
    }
    out
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

pub fn base64_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in data {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = b64_val(c).ok_or_else(|| bad(format!("invalid base64 character {:?}", c as char)))?;
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

// ---- Base32 (RFC 4648) ----

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(5) * 8);
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        // 8 output symbols; how many carry data depends on the input length
        // (1..=5 input bytes -> 2, 4, 5, 7, 8 data symbols).
        let symbols = [2, 4, 5, 7, 8][chunk.len() - 1];
        for i in 0..8 {
            if i < symbols {
                out.push(B32[(n >> (35 - i * 5) & 0x1f) as usize]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

fn b32_val(c: u8) -> Option<u8> {
    match c.to_ascii_uppercase() {
        b'A'..=b'Z' => Some(c.to_ascii_uppercase() - b'A'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

pub fn base32_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 8 * 5);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in data {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = b32_val(c).ok_or_else(|| bad(format!("invalid base32 character {:?}", c as char)))?;
        acc = acc << 5 | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

// ---- Base85 (Ascii85 and Z85) ----

const Z85: &[u8; 85] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

/// Ascii85 (Adobe/btoa), no `<~ ~>` wrapper. `z` abbreviates an all-zero group.
pub fn ascii85_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(4) * 5);
    for chunk in data.chunks(4) {
        let mut buf = [0u8; 4];
        buf[..chunk.len()].copy_from_slice(chunk);
        let mut n = u32::from_be_bytes(buf);
        if chunk.len() == 4 && n == 0 {
            out.push(b'z');
            continue;
        }
        let mut group = [0u8; 5];
        for g in group.iter_mut().rev() {
            *g = b'!' + (n % 85) as u8;
            n /= 85;
        }
        out.extend_from_slice(&group[..chunk.len() + 1]);
    }
    out
}

pub fn ascii85_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut group = [0u8; 5];
    let mut count = 0;
    for &c in data {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'z' && count == 0 {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !(b'!'..=b'u').contains(&c) {
            return Err(bad(format!("invalid ascii85 character {:?}", c as char)));
        }
        group[count] = c - b'!';
        count += 1;
        if count == 5 {
            push_ascii85_group(&mut out, &group, 4);
            count = 0;
        }
    }
    if count > 0 {
        for g in group.iter_mut().skip(count) {
            *g = 84; // pad with the maximum digit, per the spec
        }
        push_ascii85_group(&mut out, &group, count - 1);
    }
    Ok(out)
}

fn push_ascii85_group(out: &mut Vec<u8>, group: &[u8; 5], bytes: usize) {
    let mut n = 0u32;
    for &g in group {
        n = n.wrapping_mul(85).wrapping_add(g as u32);
    }
    out.extend_from_slice(&n.to_be_bytes()[..bytes]);
}

/// Z85 (ZeroMQ RFC 32/Z85). Input must be a multiple of 4 bytes to encode.
pub fn z85_encode(data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(4) {
        return Err(bad("Z85 input length must be a multiple of 4"));
    }
    let mut out = Vec::with_capacity(data.len() / 4 * 5);
    for chunk in data.chunks_exact(4) {
        let mut n = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let mut group = [0u8; 5];
        for g in group.iter_mut().rev() {
            *g = Z85[(n % 85) as usize];
            n /= 85;
        }
        out.extend_from_slice(&group);
    }
    Ok(out)
}

pub fn z85_decode(data: &[u8]) -> Result<Vec<u8>> {
    let clean: Vec<u8> = data.iter().copied().filter(|c| !c.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(5) {
        return Err(bad("Z85 input length must be a multiple of 5"));
    }
    let mut out = Vec::with_capacity(clean.len() / 5 * 4);
    for chunk in clean.chunks_exact(5) {
        let mut n = 0u32;
        for &c in chunk {
            let v = Z85.iter().position(|&x| x == c).ok_or_else(|| {
                bad(format!("invalid Z85 character {:?}", c as char))
            })?;
            n = n.wrapping_mul(85).wrapping_add(v as u32);
        }
        out.extend_from_slice(&n.to_be_bytes());
    }
    Ok(out)
}

// ---- Hex ----

pub fn hex_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2);
    for &b in data {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0xf));
    }
    out
}

fn nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}

/// Tolerant of whitespace and the usual delimiters (`0x`, `,`, `:`, `-`).
pub fn hex_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut digits = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let c = data[i];
        if c == b'0' && i + 1 < data.len() && (data[i + 1] | 0x20) == b'x' {
            i += 2;
            continue;
        }
        match c {
            b'0'..=b'9' => digits.push(c - b'0'),
            b'a'..=b'f' => digits.push(c - b'a' + 10),
            b'A'..=b'F' => digits.push(c - b'A' + 10),
            b' ' | b'\t' | b'\n' | b'\r' | b',' | b':' | b'-' | b'_' => {}
            _ => return Err(bad(format!("invalid hex character {:?}", c as char))),
        }
        i += 1;
    }
    if !digits.len().is_multiple_of(2) {
        return Err(bad("hex input has an odd number of digits"));
    }
    Ok(digits.chunks_exact(2).map(|p| p[0] << 4 | p[1]).collect())
}

// ---- URL percent-encoding ----

pub fn url_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(nibble(b >> 4).to_ascii_uppercase());
            out.push(nibble(b & 0xf).to_ascii_uppercase());
        }
    }
    out
}

pub fn url_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'%' => {
                let hi = data.get(i + 1).copied().and_then(hex_digit);
                let lo = data.get(i + 2).copied().and_then(hex_digit);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push(h << 4 | l);
                        i += 3;
                    }
                    _ => return Err(bad("truncated percent-escape in URL input")),
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
