//! F-80 — Recipe spec parser: `step | step | …`, each step a name plus
//! whitespace-separated arguments. Kept in `core` so it is unit-tested here and
//! reused verbatim by the CLI (a GUI would build [`Recipe`] from widgets, not a
//! string). Grammar is documented in the CLI `USAGE` and mirrored in the tests.

use super::{AesMode, Base64Variant, Base85Variant, Op, Recipe};
use crate::error::{Error, ErrorKind, Result};
use crate::hash::Algo;

fn bad(detail: impl Into<String>) -> Error {
    Error::new(ErrorKind::Io, detail)
}

pub fn parse(spec: &str) -> Result<Recipe> {
    let mut ops = Vec::new();
    for segment in spec.split('|') {
        let words: Vec<&str> = segment.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        ops.push(parse_op(words[0], &words[1..])?);
    }
    if ops.is_empty() {
        return Err(bad("empty recipe"));
    }
    Ok(Recipe::new(ops))
}

fn parse_op(name: &str, args: &[&str]) -> Result<Op> {
    let lname = name.to_ascii_lowercase();
    Ok(match lname.as_str() {
        "to-base64" | "base64" => Op::Base64 { variant: Base64Variant::Standard, encode: true },
        "from-base64" | "unbase64" => Op::Base64 { variant: Base64Variant::Standard, encode: false },
        "to-base64url" => Op::Base64 { variant: Base64Variant::UrlSafe, encode: true },
        "from-base64url" => Op::Base64 { variant: Base64Variant::UrlSafe, encode: false },
        "to-base32" | "base32" => Op::Base32 { encode: true },
        "from-base32" | "unbase32" => Op::Base32 { encode: false },
        "to-base85" | "base85" | "to-ascii85" => {
            Op::Base85 { variant: Base85Variant::Ascii85, encode: true }
        }
        "from-base85" | "from-ascii85" => {
            Op::Base85 { variant: Base85Variant::Ascii85, encode: false }
        }
        "to-z85" | "z85" => Op::Base85 { variant: Base85Variant::Z85, encode: true },
        "from-z85" => Op::Base85 { variant: Base85Variant::Z85, encode: false },
        "to-hex" | "hex" => Op::Hex { encode: true },
        "from-hex" | "unhex" => Op::Hex { encode: false },
        "to-url" | "url-encode" => Op::Url { encode: true },
        "from-url" | "url-decode" => Op::Url { encode: false },

        "xor" => Op::Xor { key: hex_arg(args, name)? },
        "add" => Op::Add { delta: u8_arg(args, name)? },
        "sub" => Op::Sub { delta: u8_arg(args, name)? },
        "rol" => Op::Rotate { left: true, bits: u32_arg(args, name)? },
        "ror" => Op::Rotate { left: false, bits: u32_arg(args, name)? },
        "not" => Op::Not,
        "reverse" => Op::Reverse,

        "deflate" => Op::Deflate { encode: true },
        "inflate" => Op::Deflate { encode: false },
        "zlib" | "zlib-deflate" => Op::Zlib { encode: true },
        "unzlib" | "zlib-inflate" => Op::Zlib { encode: false },
        "gzip" => Op::Gzip { encode: true },
        "gunzip" => Op::Gzip { encode: false },

        "aes-enc" | "aes-encrypt" => parse_aes(args, name, true)?,
        "aes-dec" | "aes-decrypt" => parse_aes(args, name, false)?,
        "rc4" => Op::Rc4 { key: hex_arg(args, name)? },

        _ => match Algo::from_name(&lname) {
            Some(algo) => Op::Hash { algo },
            None => return Err(bad(format!("unknown recipe step: {name}"))),
        },
    })
}

fn parse_aes(args: &[&str], name: &str, encrypt: bool) -> Result<Op> {
    let mode_s = args.first().ok_or_else(|| bad(format!("{name} needs a mode (cbc/ctr/ecb)")))?;
    let mode = AesMode::from_name(mode_s)
        .ok_or_else(|| bad(format!("unknown AES mode {mode_s} (use cbc, ctr or ecb)")))?;
    let key = hex(args.get(1).ok_or_else(|| bad(format!("{name} needs a hex key")))?)?;
    let iv = match args.get(2) {
        Some(s) => hex(s)?,
        None => Vec::new(),
    };
    Ok(Op::Aes { mode, key, iv, encrypt })
}

fn hex_arg(args: &[&str], name: &str) -> Result<Vec<u8>> {
    let s = args.first().ok_or_else(|| bad(format!("{name} needs a hex argument")))?;
    hex(s)
}

fn u8_arg(args: &[&str], name: &str) -> Result<u8> {
    let n = num(args.first().ok_or_else(|| bad(format!("{name} needs a number")))?)?;
    u8::try_from(n).map_err(|_| bad(format!("{name} argument must fit in a byte (0..=255)")))
}

fn u32_arg(args: &[&str], name: &str) -> Result<u32> {
    let n = num(args.first().ok_or_else(|| bad(format!("{name} needs a number")))?)?;
    u32::try_from(n).map_err(|_| bad(format!("{name} argument does not fit in 32 bits")))
}

/// Decimal or `0x`-hex integer.
fn num(s: &str) -> Result<u64> {
    let t = s.trim();
    let r = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => t.parse(),
    };
    r.map_err(|_| bad(format!("invalid number: {s}")))
}

/// A hex byte string (whitespace tolerated), like the CLI's `parse_hex`.
fn hex(s: &str) -> Result<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err(bad(format!("hex value with an odd number of digits: {s}")));
    }
    clean
        .as_bytes()
        .chunks(2)
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16)
                .map_err(|_| bad(format!("invalid hex byte: {}", std::str::from_utf8(p).unwrap())))
        })
        .collect()
}
