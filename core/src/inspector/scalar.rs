//! Integer, LEB128 and float16 helpers shared by the field dispatch.

use super::Endian;

// ---- integers ----

pub(super) fn insufficient() -> String {
    "not enough bytes before the end of the document".into()
}

pub(super) fn take<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes.get(..N).and_then(|s| s.try_into().ok()).ok_or_else(insufficient)
}

/// Reads `N` bytes as an unsigned integer in the given order.
pub(super) fn int<const N: usize>(bytes: &[u8], endian: Endian) -> Result<u64, String> {
    let b = take::<N>(bytes)?;
    let mut v = 0u64;
    match endian {
        Endian::Little => {
            for x in b.iter().rev() {
                v = v << 8 | *x as u64;
            }
        }
        Endian::Big => {
            for x in b.iter() {
                v = v << 8 | *x as u64;
            }
        }
    }
    Ok(v)
}

pub(super) fn sign_extend(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

pub(super) fn parse_u(s: &str, max: u64) -> Result<u64, String> {
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse::<u64>(),
    }
    .map_err(|_| format!("invalid integer: {s}"))?;
    if v > max {
        return Err(format!("above the maximum {max}"));
    }
    Ok(v)
}

pub(super) fn parse_i(s: &str, min: i64, max: i64) -> Result<i64, String> {
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let mag = match rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        Some(h) => i128::from_str_radix(h, 16),
        None => rest.parse::<i128>(),
    }
    .map_err(|_| format!("invalid integer: {s}"))?;
    let v = if neg { -mag } else { mag };
    if v < min as i128 || v > max as i128 {
        return Err(format!("outside the range [{min}, {max}]"));
    }
    Ok(v as i64)
}

// ---- LEB128 ----

pub(super) fn decode_uleb128(bytes: &[u8]) -> Result<(u64, usize), String> {
    let mut v = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        if i == 9 && b & 0x7F > 1 || i > 9 {
            return Err("varint overflows 64 bits".into());
        }
        v |= ((b & 0x7F) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    Err(insufficient())
}

pub(super) fn decode_sleb128(bytes: &[u8]) -> Result<(i64, usize), String> {
    let mut v = 0i64;
    for (i, &b) in bytes.iter().enumerate() {
        if i > 9 {
            return Err("varint overflows 64 bits".into());
        }
        let shift = 7 * i as u32;
        if shift < 64 {
            v |= ((b & 0x7F) as i64) << shift;
        }
        if b & 0x80 == 0 {
            let used = shift + 7;
            if b & 0x40 != 0 && used < 64 {
                v |= -1i64 << used; // extends the sign
            }
            return Ok((v, i + 1));
        }
    }
    Err(insufficient())
}

pub(super) fn encode_uleb128(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

pub(super) fn encode_sleb128(mut v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7; // arithmetic shift: preserves the sign
        let done = (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

// ---- float16 (IEEE 754 half) ----

pub(super) fn f16_to_f32(h: u16) -> f32 {
    let sign = (h as u32 >> 15) << 31;
    let exp = (h >> 10) as u32 & 0x1F;
    let frac = h as u32 & 0x3FF;
    let bits = match (exp, frac) {
        (0, 0) => sign,
        (0, mut f) => {
            // A half subnormal is a single normal: normalize the mantissa.
            let mut e = 127 - 15 + 1;
            while f & 0x400 == 0 {
                f <<= 1;
                e -= 1;
            }
            sign | (e << 23) | ((f & 0x3FF) << 13)
        }
        (31, 0) => sign | 0x7F80_0000,
        (31, _) => sign | 0x7FC0_0000,
        _ => sign | ((exp + 127 - 15) << 23) | (frac << 13),
    };
    f32::from_bits(bits)
}

pub(super) fn f32_to_f16(x: f32) -> u16 {
    let b = x.to_bits();
    let sign = (b >> 16) & 0x8000;
    let exp = (b >> 23 & 0xFF) as i32;
    let mut m = b & 0x007F_FFFF;
    if exp == 255 {
        return (sign | 0x7C00 | if m != 0 { 0x200 } else { 0 }) as u16;
    }
    let e = exp - 127 + 15;
    if e >= 31 {
        return (sign | 0x7C00) as u16; // overflows: ±inf
    }
    if e <= 0 {
        if e < -10 {
            return sign as u16; // too small: ±0
        }
        m |= 0x0080_0000; // the implicit 1 becomes explicit in the subnormal
        let shift = (14 - e) as u32;
        let half = 1u32 << (shift - 1);
        let rem = m & ((1 << shift) - 1);
        let mut hm = m >> shift;
        if rem > half || (rem == half && hm & 1 == 1) {
            hm += 1; // a carry here produces the smallest normal — correct
        }
        return (sign | hm) as u16;
    }
    let mut h = sign | ((e as u32) << 10) | (m >> 13);
    let rem = m & 0x1FFF;
    if rem > 0x1000 || (rem == 0x1000 && h & 1 == 1) {
        h += 1; // a carry into the exponent is the correct rounding
    }
    h as u16
}
