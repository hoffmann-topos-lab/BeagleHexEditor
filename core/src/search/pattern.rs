//! What to look for: byte/mask patterns, text per charset, typed values.

use crate::charset::Charset;
use crate::inspector::{Endian, FieldKind};

/// What to look for.
#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// Bytes with a per-byte mask: bit 1 = must match, 0 = wildcard (F-15a).
    /// `ci` folds ASCII upper/lowercase (F-15); the pattern's bytes already
    /// come folded from construction.
    Bytes { bytes: Vec<u8>, mask: Vec<u8>, ci: bool },
    /// F-14: float with a tolerance — there is no exact byte sequence.
    Float { double: bool, endian: Endian, target: f64, tol: f64 },
}

fn fold(b: u8, ci: bool) -> u8 {
    if ci && b.is_ascii_uppercase() { b | 0x20 } else { b }
}

impl Pattern {
    /// Exact byte sequence (F-13a).
    pub fn bytes(bytes: Vec<u8>) -> Option<Pattern> {
        if bytes.is_empty() {
            return None;
        }
        let mask = vec![0xFF; bytes.len()];
        Some(Pattern::Bytes { bytes, mask, ci: false })
    }

    /// Hex with per-nibble wildcards (F-15a): `"DE ?? BE EF"`, `"D? ?E"`.
    pub fn parse_hex(s: &str) -> Option<Pattern> {
        let clean: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.is_empty() || !clean.len().is_multiple_of(2) {
            return None;
        }
        let mut bytes = Vec::with_capacity(clean.len() / 2);
        let mut mask = Vec::with_capacity(clean.len() / 2);
        for pair in clean.chunks(2) {
            let nib = |c: char| -> Option<(u8, u8)> {
                match c {
                    '?' => Some((0, 0)),
                    c => c.to_digit(16).map(|d| (d as u8, 0xF)),
                }
            };
            let (hi, hm) = nib(pair[0])?;
            let (lo, lm) = nib(pair[1])?;
            bytes.push(hi << 4 | lo);
            mask.push(hm << 4 | lm);
        }
        if mask.iter().all(|m| *m == 0) {
            return None; // a pattern of nothing but wildcards would match everything
        }
        Some(Pattern::Bytes { bytes, mask, ci: false })
    }

    /// Text in the given charset (F-13b). `ci` ignores ASCII case (F-15).
    pub fn text(s: &str, charset: Charset, ci: bool) -> Option<Pattern> {
        let mut bytes = charset.encode_str(s)?;
        if bytes.is_empty() {
            return None;
        }
        if ci {
            for b in &mut bytes {
                *b = fold(*b, true);
            }
        }
        let mask = vec![0xFF; bytes.len()];
        Some(Pattern::Bytes { bytes, mask, ci })
    }

    /// F-14 — typed value: `("i32", "1234")`, `("f32", "3.14")`. Integers become
    /// the exact byte sequence (via the inspector); floats with `tol > 0` become
    /// a comparison with a tolerance.
    pub fn typed(
        kind: &str,
        value: &str,
        endian: Endian,
        tol: Option<f64>,
    ) -> std::result::Result<Pattern, String> {
        let field = match kind.to_ascii_lowercase().as_str() {
            "i8" => FieldKind::I8,
            "u8" => FieldKind::U8,
            "i16" => FieldKind::I16,
            "u16" => FieldKind::U16,
            "i24" => FieldKind::I24,
            "u24" => FieldKind::U24,
            "i32" => FieldKind::I32,
            "u32" => FieldKind::U32,
            "i64" => FieldKind::I64,
            "u64" => FieldKind::U64,
            "f16" => FieldKind::F16,
            "f32" => FieldKind::F32,
            "f64" => FieldKind::F64,
            other => return Err(format!("unknown type: {other}")),
        };
        let is_float = matches!(field, FieldKind::F32 | FieldKind::F64);
        if is_float && tol.is_some_and(|t| t > 0.0) {
            let target: f64 = value.trim().parse().map_err(|_| "invalid float".to_string())?;
            return Ok(Pattern::Float {
                double: field == FieldKind::F64,
                endian,
                target,
                tol: tol.unwrap(),
            });
        }
        let bytes = field.encode(value, endian, Charset::Ascii)?;
        Ok(Pattern::bytes(bytes).expect("encode never returns empty"))
    }

    pub fn len(&self) -> usize {
        match self {
            Pattern::Bytes { bytes, .. } => bytes.len(),
            Pattern::Float { double, .. } => {
                if *double {
                    8
                } else {
                    4
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        false // the constructors guarantee a length ≥ 1
    }

    fn matches_at(&self, hay: &[u8], at: usize) -> bool {
        match self {
            Pattern::Bytes { bytes, mask, ci } => {
                if at + bytes.len() > hay.len() {
                    return false;
                }
                bytes
                    .iter()
                    .zip(mask)
                    .enumerate()
                    .all(|(i, (b, m))| (fold(hay[at + i], *ci) ^ b) & m == 0)
            }
            Pattern::Float { double, endian, target, tol } => {
                if at + self.len() > hay.len() {
                    return false;
                }
                let v = if *double {
                    let b: [u8; 8] = hay[at..at + 8].try_into().unwrap();
                    match endian {
                        Endian::Little => f64::from_le_bytes(b),
                        Endian::Big => f64::from_be_bytes(b),
                    }
                } else {
                    let b: [u8; 4] = hay[at..at + 4].try_into().unwrap();
                    (match endian {
                        Endian::Little => f32::from_le_bytes(b),
                        Endian::Big => f32::from_be_bytes(b),
                    }) as f64
                };
                (v - target).abs() <= *tol
            }
        }
    }

    /// Scans `hay` with candidates in `[c0, c1)`, without overlap from
    /// `min_start` on. Appends the relative positions to `out`.
    pub(super) fn scan(
        &self,
        hay: &[u8],
        c0: usize,
        c1: usize,
        min_start: usize,
        out: &mut Vec<usize>,
    ) {
        let m = self.len();
        let concrete_bmh = matches!(self, Pattern::Bytes { mask, .. } if mask.iter().all(|b| *b == 0xFF))
            && m > 1;
        let mut i = c0.max(min_start);
        if concrete_bmh {
            let Pattern::Bytes { bytes, ci, .. } = self else { unreachable!() };
            // Boyer–Moore–Horspool: skip table keyed by the window's last byte.
            let mut skip = [m; 256];
            for (k, b) in bytes[..m - 1].iter().enumerate() {
                skip[*b as usize] = m - 1 - k;
            }
            while i < c1 && i + m <= hay.len() {
                let last = fold(hay[i + m - 1], *ci);
                if last == bytes[m - 1] && self.matches_at(hay, i) {
                    out.push(i);
                    i += m;
                } else {
                    i += skip[last as usize];
                }
            }
        } else {
            while i < c1 && i + m <= hay.len() {
                if self.matches_at(hay, i) {
                    out.push(i);
                    i += m;
                } else {
                    i += 1;
                }
            }
        }
    }
}
