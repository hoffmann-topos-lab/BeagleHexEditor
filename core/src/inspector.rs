use crate::charset::{Charset, UNPRINTABLE, is_printable};

/// F-17 — The active byte order. Toggleable globally and per field in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endian {
    #[default]
    Little,
    Big,
}

impl Endian {
    pub fn name(self) -> &'static str {
        match self {
            Endian::Little => "little-endian",
            Endian::Big => "big-endian",
        }
    }
}

/// Seconds between 1601-01-01 (the FILETIME epoch) and 1970-01-01.
const FILETIME_EPOCH_DELTA: i64 = 11_644_473_600;
/// Days between 1899-12-30 (the OLE DATE epoch) and 1970-01-01.
const OLE_EPOCH_DAYS: i64 = 25_569;
/// Scan limit for the NUL-terminated string.
const CSTRING_SCAN: usize = 256;
/// Display limit for the string (in characters).
const CSTRING_SHOW: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Binary,
    Octal,
    I8,
    U8,
    I16,
    U16,
    I24,
    U24,
    I32,
    U32,
    I64,
    U64,
    ULeb128,
    SLeb128,
    F16,
    F32,
    F64,
    Char,
    CString,
    TimeT32,
    TimeT64,
    FileTime,
    DosDateTime,
    OleDate,
    Guid,
    Rgb,
    Rgba,
}

/// A decoded value: the displayed text and how many document bytes the field
/// covers (that is what the grid highlights).
pub type Decoded = (String, usize);

impl FieldKind {
    pub const ALL: [FieldKind; 27] = [
        FieldKind::Binary,
        FieldKind::Octal,
        FieldKind::I8,
        FieldKind::U8,
        FieldKind::I16,
        FieldKind::U16,
        FieldKind::I24,
        FieldKind::U24,
        FieldKind::I32,
        FieldKind::U32,
        FieldKind::I64,
        FieldKind::U64,
        FieldKind::SLeb128,
        FieldKind::ULeb128,
        FieldKind::F16,
        FieldKind::F32,
        FieldKind::F64,
        FieldKind::Char,
        FieldKind::CString,
        FieldKind::TimeT32,
        FieldKind::TimeT64,
        FieldKind::FileTime,
        FieldKind::DosDateTime,
        FieldKind::OleDate,
        FieldKind::Guid,
        FieldKind::Rgb,
        FieldKind::Rgba,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FieldKind::Binary => "Binary",
            FieldKind::Octal => "Octal",
            FieldKind::I8 => "Int8",
            FieldKind::U8 => "UInt8",
            FieldKind::I16 => "Int16",
            FieldKind::U16 => "UInt16",
            FieldKind::I24 => "Int24",
            FieldKind::U24 => "UInt24",
            FieldKind::I32 => "Int32",
            FieldKind::U32 => "UInt32",
            FieldKind::I64 => "Int64",
            FieldKind::U64 => "UInt64",
            FieldKind::ULeb128 => "ULEB128",
            FieldKind::SLeb128 => "SLEB128",
            FieldKind::F16 => "Float16",
            FieldKind::F32 => "Float32",
            FieldKind::F64 => "Float64",
            FieldKind::Char => "Character",
            FieldKind::CString => "String (NUL)",
            FieldKind::TimeT32 => "time_t (32-bit)",
            FieldKind::TimeT64 => "time_t (64-bit)",
            FieldKind::FileTime => "FILETIME",
            FieldKind::DosDateTime => "DOS date/time",
            FieldKind::OleDate => "OLE DATE",
            FieldKind::Guid => "GUID",
            FieldKind::Rgb => "RGB",
            FieldKind::Rgba => "RGBA",
        }
    }

    /// Does the active endianness change this field's interpretation?
    pub fn uses_endian(self) -> bool {
        !matches!(
            self,
            FieldKind::Binary
                | FieldKind::Octal
                | FieldKind::I8
                | FieldKind::U8
                | FieldKind::ULeb128
                | FieldKind::SLeb128
                | FieldKind::CString
                | FieldKind::Rgb
                | FieldKind::Rgba
        )
    }

    /// Editable fields write bytes back through `encode` (F-16, in-place
    /// editing). The NUL string is read-only.
    pub fn editable(self) -> bool {
        !matches!(self, FieldKind::CString)
    }

    /// Interprets the bytes at the start of `bytes` (the window read from the
    /// cursor, already clipped at the end of the document).
    pub fn decode(self, bytes: &[u8], endian: Endian, charset: Charset) -> Result<Decoded, String> {
        match self {
            FieldKind::Binary => take::<1>(bytes).map(|[b]| (format!("{b:08b}"), 1)),
            FieldKind::Octal => take::<1>(bytes).map(|[b]| (format!("{b:03o}"), 1)),
            FieldKind::I8 => take::<1>(bytes).map(|[b]| ((b as i8).to_string(), 1)),
            FieldKind::U8 => take::<1>(bytes).map(|[b]| (b.to_string(), 1)),
            FieldKind::I16 => int::<2>(bytes, endian).map(|v| ((v as i16).to_string(), 2)),
            FieldKind::U16 => int::<2>(bytes, endian).map(|v| ((v as u16).to_string(), 2)),
            FieldKind::I24 => int::<3>(bytes, endian).map(|v| (sign_extend(v, 24).to_string(), 3)),
            FieldKind::U24 => int::<3>(bytes, endian).map(|v| (v.to_string(), 3)),
            FieldKind::I32 => int::<4>(bytes, endian).map(|v| ((v as i32).to_string(), 4)),
            FieldKind::U32 => int::<4>(bytes, endian).map(|v| ((v as u32).to_string(), 4)),
            FieldKind::I64 => int::<8>(bytes, endian).map(|v| ((v as i64).to_string(), 8)),
            FieldKind::U64 => int::<8>(bytes, endian).map(|v| (v.to_string(), 8)),
            FieldKind::ULeb128 => decode_uleb128(bytes).map(|(v, n)| (v.to_string(), n)),
            FieldKind::SLeb128 => decode_sleb128(bytes).map(|(v, n)| (v.to_string(), n)),
            FieldKind::F16 => {
                int::<2>(bytes, endian).map(|v| (f16_to_f32(v as u16).to_string(), 2))
            }
            FieldKind::F32 => {
                int::<4>(bytes, endian).map(|v| (f32::from_bits(v as u32).to_string(), 4))
            }
            FieldKind::F64 => int::<8>(bytes, endian).map(|v| (f64::from_bits(v).to_string(), 8)),
            FieldKind::Char => decode_char(bytes, endian, charset),
            FieldKind::CString => decode_cstring(bytes, endian, charset),
            FieldKind::TimeT32 => int::<4>(bytes, endian)
                .and_then(|v| format_unix(v as i32 as i64).map(|s| (s, 4))),
            FieldKind::TimeT64 => {
                int::<8>(bytes, endian).and_then(|v| format_unix(v as i64).map(|s| (s, 8)))
            }
            FieldKind::FileTime => int::<8>(bytes, endian).and_then(|ticks| {
                let secs = (ticks / 10_000_000) as i64 - FILETIME_EPOCH_DELTA;
                format_unix(secs).map(|s| (s, 8))
            }),
            FieldKind::DosDateTime => {
                int::<4>(bytes, endian).and_then(|v| decode_dos(v as u32).map(|s| (s, 4)))
            }
            FieldKind::OleDate => {
                int::<8>(bytes, endian).and_then(|v| decode_ole(f64::from_bits(v)).map(|s| (s, 8)))
            }
            FieldKind::Guid => decode_guid(bytes, endian),
            FieldKind::Rgb => take::<3>(bytes)
                .map(|[r, g, b]| (format!("#{r:02X}{g:02X}{b:02X}"), 3)),
            FieldKind::Rgba => take::<4>(bytes)
                .map(|[r, g, b, a]| (format!("#{r:02X}{g:02X}{b:02X}{a:02X}"), 4)),
        }
    }

    /// Turns the edited text into the bytes to write (in-place editing, F-16).
    pub fn encode(self, text: &str, endian: Endian, charset: Charset) -> Result<Vec<u8>, String> {
        let text = text.trim();
        match self {
            FieldKind::Binary => {
                let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                if digits.is_empty() || digits.len() > 8 {
                    return Err("expected 1 to 8 binary digits".into());
                }
                u8::from_str_radix(&digits, 2)
                    .map(|b| vec![b])
                    .map_err(|_| "invalid binary digit".into())
            }
            FieldKind::Octal => u8::from_str_radix(text, 8)
                .map(|b| vec![b])
                .map_err(|_| "invalid octal (000–377)".into()),
            FieldKind::I8 => parse_i(text, i8::MIN as i64, i8::MAX as i64)
                .map(|v| vec![v as u8]),
            FieldKind::U8 => parse_u(text, u8::MAX as u64).map(|v| vec![v as u8]),
            FieldKind::I16 => parse_i(text, i16::MIN as i64, i16::MAX as i64)
                .map(|v| endian.bytes_n((v as u16) as u64, 2)),
            FieldKind::U16 => parse_u(text, u16::MAX as u64).map(|v| endian.bytes_n(v, 2)),
            FieldKind::I24 => parse_i(text, -(1 << 23), (1 << 23) - 1)
                .map(|v| endian.bytes_n((v as u64) & 0xFF_FFFF, 3)),
            FieldKind::U24 => parse_u(text, (1 << 24) - 1).map(|v| endian.bytes_n(v, 3)),
            FieldKind::I32 => parse_i(text, i32::MIN as i64, i32::MAX as i64)
                .map(|v| endian.bytes_n((v as u32) as u64, 4)),
            FieldKind::U32 => parse_u(text, u32::MAX as u64).map(|v| endian.bytes_n(v, 4)),
            FieldKind::I64 => parse_i(text, i64::MIN, i64::MAX)
                .map(|v| endian.bytes_n(v as u64, 8)),
            FieldKind::U64 => parse_u(text, u64::MAX).map(|v| endian.bytes_n(v, 8)),
            FieldKind::ULeb128 => parse_u(text, u64::MAX).map(encode_uleb128),
            FieldKind::SLeb128 => parse_i(text, i64::MIN, i64::MAX).map(encode_sleb128),
            FieldKind::F16 => text
                .parse::<f32>()
                .map(|v| endian.bytes_n(f32_to_f16(v) as u64, 2))
                .map_err(|_| "invalid float".into()),
            FieldKind::F32 => text
                .parse::<f32>()
                .map(|v| endian.bytes_n(v.to_bits() as u64, 4))
                .map_err(|_| "invalid float".into()),
            FieldKind::F64 => text
                .parse::<f64>()
                .map(|v| endian.bytes_n(v.to_bits(), 8))
                .map_err(|_| "invalid float".into()),
            FieldKind::Char => encode_char(text, endian, charset),
            FieldKind::CString => Err("the NUL string is read-only".into()),
            FieldKind::TimeT32 => {
                let secs = parse_datetime(text)?;
                i32::try_from(secs)
                    .map(|v| endian.bytes_n((v as u32) as u64, 4))
                    .map_err(|_| "fora do intervalo de time_t de 32 bits".into())
            }
            FieldKind::TimeT64 => parse_datetime(text).map(|s| endian.bytes_n(s as u64, 8)),
            FieldKind::FileTime => {
                let secs = parse_datetime(text)?;
                let ticks = secs
                    .checked_add(FILETIME_EPOCH_DELTA)
                    .filter(|s| *s >= 0)
                    .and_then(|s| s.checked_mul(10_000_000))
                    .ok_or("anterior a 1601, fora do FILETIME")?;
                Ok(endian.bytes_n(ticks as u64, 8))
            }
            FieldKind::DosDateTime => encode_dos(text).map(|v| endian.bytes_n(v as u64, 4)),
            FieldKind::OleDate => {
                encode_ole(text).map(|v| endian.bytes_n(v.to_bits(), 8))
            }
            FieldKind::Guid => encode_guid(text, endian),
            FieldKind::Rgb => parse_color(text, 3),
            FieldKind::Rgba => parse_color(text, 4),
        }
    }
}

impl Endian {
    /// Os `n` bytes menos significativos de `v`, na ordem ativa.
    fn bytes_n(self, v: u64, n: usize) -> Vec<u8> {
        let le = v.to_le_bytes();
        match self {
            Endian::Little => le[..n].to_vec(),
            Endian::Big => le[..n].iter().rev().copied().collect(),
        }
    }
}

// ---- integers ----

fn insufficient() -> String {
    "not enough bytes before the end of the document".into()
}

fn take<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes.get(..N).and_then(|s| s.try_into().ok()).ok_or_else(insufficient)
}

/// Reads `N` bytes as an unsigned integer in the given order.
fn int<const N: usize>(bytes: &[u8], endian: Endian) -> Result<u64, String> {
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

fn sign_extend(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

fn parse_u(s: &str, max: u64) -> Result<u64, String> {
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

fn parse_i(s: &str, min: i64, max: i64) -> Result<i64, String> {
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
        return Err(format!("fora do intervalo [{min}, {max}]"));
    }
    Ok(v as i64)
}

// ---- LEB128 ----

fn decode_uleb128(bytes: &[u8]) -> Result<(u64, usize), String> {
    let mut v = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        if i == 9 && b & 0x7F > 1 || i > 9 {
            return Err("varint estoura 64 bits".into());
        }
        v |= ((b & 0x7F) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    Err(insufficient())
}

fn decode_sleb128(bytes: &[u8]) -> Result<(i64, usize), String> {
    let mut v = 0i64;
    for (i, &b) in bytes.iter().enumerate() {
        if i > 9 {
            return Err("varint estoura 64 bits".into());
        }
        let shift = 7 * i as u32;
        if shift < 64 {
            v |= ((b & 0x7F) as i64) << shift;
        }
        if b & 0x80 == 0 {
            let used = shift + 7;
            if b & 0x40 != 0 && used < 64 {
                v |= -1i64 << used; // estende o sinal
            }
            return Ok((v, i + 1));
        }
    }
    Err(insufficient())
}

fn encode_uleb128(mut v: u64) -> Vec<u8> {
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

fn encode_sleb128(mut v: i64) -> Vec<u8> {
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

fn f16_to_f32(h: u16) -> f32 {
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

fn f32_to_f16(x: f32) -> u16 {
    let b = x.to_bits();
    let sign = (b >> 16) & 0x8000;
    let exp = (b >> 23 & 0xFF) as i32;
    let mut m = b & 0x007F_FFFF;
    if exp == 255 {
        return (sign | 0x7C00 | if m != 0 { 0x200 } else { 0 }) as u16;
    }
    let e = exp - 127 + 15;
    if e >= 31 {
        return (sign | 0x7C00) as u16; // estoura: ±inf
    }
    if e <= 0 {
        if e < -10 {
            return sign as u16; // pequeno demais: ±0
        }
        m |= 0x0080_0000; // the implicit 1 becomes explicit in the subnormal
        let shift = (14 - e) as u32;
        let half = 1u32 << (shift - 1);
        let rem = m & ((1 << shift) - 1);
        let mut hm = m >> shift;
        if rem > half || (rem == half && hm & 1 == 1) {
            hm += 1; // um carry aqui produz o menor normal — correto
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

// ---- character and string ----

fn decode_char(bytes: &[u8], endian: Endian, charset: Charset) -> Result<Decoded, String> {
    if bytes.is_empty() {
        return Err(insufficient());
    }
    // In the UTF-16 charsets the inspector honours the active endianness, not
    // the LE/BE variant chosen for the text pane.
    let cs = match charset {
        Charset::Utf16Le | Charset::Utf16Be => match endian {
            Endian::Little => Charset::Utf16Le,
            Endian::Big => Charset::Utf16Be,
        },
        other => other,
    };
    match cs.decode_char_at(bytes) {
        Some((c, n)) if is_printable(c) => Ok((c.to_string(), n)),
        Some((c, n)) => Ok((format!("U+{:04X}", c as u32), n)),
        None => Err("byte sem caractere neste charset".into()),
    }
}

fn encode_char(text: &str, endian: Endian, charset: Charset) -> Result<Vec<u8>, String> {
    let mut chars = text.chars();
    let (Some(c), None) = (chars.next(), chars.next()) else {
        return Err("digite exatamente um caractere".into());
    };
    // As in decode: in UTF-16 the active endianness rules, not the text
    // pane's variant.
    let cs = match charset {
        Charset::Utf16Le | Charset::Utf16Be => match endian {
            Endian::Little => Charset::Utf16Le,
            Endian::Big => Charset::Utf16Be,
        },
        other => other,
    };
    cs.encode_char(c).ok_or_else(|| format!("'{c}' does not exist in {}", cs.name()))
}

fn decode_cstring(bytes: &[u8], endian: Endian, charset: Charset) -> Result<Decoded, String> {
    let window = &bytes[..bytes.len().min(CSTRING_SCAN)];
    let (content, terminated): (&[u8], bool) = match charset {
        Charset::Utf16Le | Charset::Utf16Be => {
            let mut end = None;
            let mut i = 0;
            while i + 2 <= window.len() {
                if window[i] == 0 && window[i + 1] == 0 {
                    end = Some(i);
                    break;
                }
                i += 2;
            }
            (&window[..end.unwrap_or(window.len() & !1)], end.is_some())
        }
        _ => match window.iter().position(|b| *b == 0) {
            Some(i) => (&window[..i], true),
            None => (window, false),
        },
    };
    let _ = endian; // the LE/BE variant is already in the text pane's charset
    let mut s: String = charset
        .decode_cells(0, content)
        .into_iter()
        .filter(|c| *c != crate::charset::CONTINUATION)
        .map(|c| if c == UNPRINTABLE { ' ' } else { c })
        .collect();
    let mut truncated = !terminated;
    if s.chars().count() > CSTRING_SHOW {
        s = s.chars().take(CSTRING_SHOW).collect();
        truncated = true;
    }
    let suffix = if truncated { "…" } else { "" };
    Ok((format!("\"{s}\"{suffix}"), content.len()))
}

// ---- dates ----

/// (year, month, day) from days since 1970-01-01 (Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days since 1970-01-01 from (year, month, day) (Hinnant).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

fn format_unix(secs: i64) -> Result<String, String> {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    if !(0..=9999).contains(&y) {
        return Err(format!("year {y} outside the displayable range"));
    }
    Ok(format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        sod / 3600,
        sod / 60 % 60,
        sod % 60
    ))
}

/// Accepts `YYYY-MM-DD`, `YYYY-MM-DD HH:MM` and `YYYY-MM-DD HH:MM:SS` (UTC).
fn parse_datetime(s: &str) -> Result<i64, String> {
    let bad = || format!("invalid date: {s} (use YYYY-MM-DD HH:MM:SS)");
    let mut it = s.split_whitespace();
    let date = it.next().ok_or_else(bad)?;
    let time = it.next();
    if it.next().is_some() {
        return Err(bad());
    }

    let mut dp = date.split('-');
    let y: i64 = dp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
    let m: u32 = dp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
    let d: u32 = dp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
    if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }

    let (mut h, mut mi, mut sec) = (0u32, 0u32, 0u32);
    if let Some(t) = time {
        let mut tp = t.split(':');
        h = tp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
        mi = tp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
        sec = tp.next().map(|x| x.parse().map_err(|_| bad())).transpose()?.unwrap_or(0);
        if tp.next().is_some() || h > 23 || mi > 59 || sec > 59 {
            return Err(bad());
        }
    }
    Ok(days_from_civil(y, m, d) * 86_400 + (h * 3600 + mi * 60 + sec) as i64)
}

fn decode_dos(v: u32) -> Result<String, String> {
    // FAT layout: low word = time, high word = date.
    let time = v & 0xFFFF;
    let date = v >> 16;
    let (d, m, y) = (date & 0x1F, date >> 5 & 0x0F, (date >> 9) + 1980);
    let (s, mi, h) = ((time & 0x1F) * 2, time >> 5 & 0x3F, time >> 11);
    if !(1..=12).contains(&m) || d == 0 || h > 23 || mi > 59 || s > 59 {
        return Err("not a valid DOS date/time".into());
    }
    Ok(format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}"))
}

fn encode_dos(text: &str) -> Result<u32, String> {
    let secs = parse_datetime(text)?;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    if !(1980..=2107).contains(&y) {
        return Err("a DOS date only covers 1980–2107".into());
    }
    let date = ((y - 1980) as u32) << 9 | m << 5 | d;
    let time = (sod / 3600) << 11 | (sod / 60 % 60) << 5 | ((sod % 60) / 2);
    Ok(date << 16 | time)
}

fn decode_ole(v: f64) -> Result<String, String> {
    if !v.is_finite() || v.abs() >= 3_000_000.0 {
        return Err("not a plausible OLE DATE".into());
    }
    // Integer part = days since 1899-12-30; fraction = time of day, always as
    // a magnitude (the OLE convention for negative dates).
    let days = v.trunc() as i64;
    let sod = ((v - v.trunc()).abs() * 86_400.0).round() as i64;
    format_unix((days - OLE_EPOCH_DAYS) * 86_400 + sod)
}

fn encode_ole(text: &str) -> Result<f64, String> {
    let secs = parse_datetime(text)?;
    let days = secs.div_euclid(86_400) + OLE_EPOCH_DAYS;
    let frac = secs.rem_euclid(86_400) as f64 / 86_400.0;
    Ok(if days >= 0 { days as f64 + frac } else { days as f64 - frac })
}

// ---- GUID and colours ----

fn decode_guid(bytes: &[u8], endian: Endian) -> Result<Decoded, String> {
    let b = take::<16>(bytes)?;
    let d1 = int::<4>(&b[0..4], endian)? as u32;
    let d2 = int::<2>(&b[4..6], endian)? as u16;
    let d3 = int::<2>(&b[6..8], endian)? as u16;
    let t = &b[8..16];
    Ok((
        format!(
            "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]
        ),
        16,
    ))
}

fn encode_guid(text: &str, endian: Endian) -> Result<Vec<u8>, String> {
    let clean = text.trim().trim_start_matches('{').trim_end_matches('}');
    let hex: String = clean.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid GUID (32 hex digits)".into());
    }
    let nib = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
    let d1 = u32::from_str_radix(&hex[0..8], 16).unwrap();
    let d2 = u16::from_str_radix(&hex[8..12], 16).unwrap();
    let d3 = u16::from_str_radix(&hex[12..16], 16).unwrap();
    let mut out = Vec::with_capacity(16);
    match endian {
        Endian::Little => {
            out.extend_from_slice(&d1.to_le_bytes());
            out.extend_from_slice(&d2.to_le_bytes());
            out.extend_from_slice(&d3.to_le_bytes());
        }
        Endian::Big => {
            out.extend_from_slice(&d1.to_be_bytes());
            out.extend_from_slice(&d2.to_be_bytes());
            out.extend_from_slice(&d3.to_be_bytes());
        }
    }
    for i in (16..32).step_by(2) {
        out.push(nib(i));
    }
    Ok(out)
}

fn parse_color(text: &str, n: usize) -> Result<Vec<u8>, String> {
    let hex = text.trim().trim_start_matches('#');
    if hex.len() != n * 2 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid colour (expected #{})", "RR".repeat(n)));
    }
    Ok((0..n).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(k: FieldKind, bytes: &[u8], e: Endian) -> String {
        k.decode(bytes, e, Charset::Ascii).unwrap().0
    }

    fn enc(k: FieldKind, text: &str, e: Endian) -> Vec<u8> {
        k.encode(text, e, Charset::Ascii).unwrap()
    }

    #[test]
    fn integers_in_both_orders() {
        let b = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(dec(FieldKind::U16, &b, Endian::Little), "513");
        assert_eq!(dec(FieldKind::U16, &b, Endian::Big), "258");
        assert_eq!(dec(FieldKind::U32, &b, Endian::Little), "67305985");
        assert_eq!(dec(FieldKind::U32, &b, Endian::Big), "16909060");
        assert_eq!(dec(FieldKind::U24, &b, Endian::Little), "197121");
        assert_eq!(dec(FieldKind::I8, &[0xFF], Endian::Little), "-1");
        assert_eq!(dec(FieldKind::I16, &[0xFF, 0xFF], Endian::Little), "-1");
        assert_eq!(dec(FieldKind::I24, &[0xFF, 0xFF, 0xFF], Endian::Little), "-1");
        assert_eq!(dec(FieldKind::U64, &b, Endian::Little), "578437695752307201");
    }

    #[test]
    fn encode_and_decode_of_integers_are_inverses() {
        for e in [Endian::Little, Endian::Big] {
            assert_eq!(enc(FieldKind::I32, "-1234", e).len(), 4);
            let bytes = enc(FieldKind::I32, "-1234", e);
            assert_eq!(dec(FieldKind::I32, &bytes, e), "-1234");
            let bytes = enc(FieldKind::U24, "0xABCDEF", e);
            assert_eq!(dec(FieldKind::U24, &bytes, e), (0xABCDEFu32).to_string());
        }
    }

    #[test]
    fn not_enough_bytes_is_a_clear_error() {
        let r = FieldKind::U64.decode(&[1, 2, 3], Endian::Little, Charset::Ascii);
        assert!(r.unwrap_err().contains("not enough bytes"));
    }

    #[test]
    fn binary_and_octal() {
        assert_eq!(dec(FieldKind::Binary, &[0b0101_1010], Endian::Little), "01011010");
        assert_eq!(dec(FieldKind::Octal, &[0o132], Endian::Little), "132");
        assert_eq!(enc(FieldKind::Binary, "1010", Endian::Little), vec![0b1010]);
        assert_eq!(enc(FieldKind::Octal, "377", Endian::Little), vec![0xFF]);
        assert!(FieldKind::Octal.encode("400", Endian::Little, Charset::Ascii).is_err());
    }

    #[test]
    fn floats() {
        assert_eq!(dec(FieldKind::F32, &1.5f32.to_le_bytes(), Endian::Little), "1.5");
        assert_eq!(dec(FieldKind::F64, &(-2.25f64).to_be_bytes(), Endian::Big), "-2.25");
        assert_eq!(enc(FieldKind::F32, "1.5", Endian::Little), 1.5f32.to_le_bytes());
    }

    #[test]
    fn float16_known_values() {
        assert_eq!(f16_to_f32(0x3C00), 1.0);
        assert_eq!(f16_to_f32(0xC000), -2.0);
        assert_eq!(f16_to_f32(0x7BFF), 65504.0); // maior finito
        assert_eq!(f16_to_f32(0x0001), 5.960_464_5e-8); // menor subnormal
        assert!(f16_to_f32(0x7C01).is_nan());
        assert_eq!(f16_to_f32(0xFC00), f32::NEG_INFINITY);
        for h in [0x3C00u16, 0xC000, 0x7BFF, 0x0001, 0x03FF, 0x0400, 0x8000] {
            assert_eq!(f32_to_f16(f16_to_f32(h)), h, "roundtrip de {h:#06X}");
        }
        assert_eq!(f32_to_f16(1e9), 0x7C00, "estouro vira +inf");
        assert_eq!(f32_to_f16(1e-10), 0x0000, "underflow vira zero");
    }

    #[test]
    fn leb128() {
        // 624485 = the canonical Wikipedia example: E5 8E 26
        assert_eq!(dec(FieldKind::ULeb128, &[0xE5, 0x8E, 0x26], Endian::Little), "624485");
        assert_eq!(enc(FieldKind::ULeb128, "624485", Endian::Little), vec![0xE5, 0x8E, 0x26]);
        // -123456 in SLEB128: C0 BB 78
        assert_eq!(dec(FieldKind::SLeb128, &[0xC0, 0xBB, 0x78], Endian::Little), "-123456");
        assert_eq!(enc(FieldKind::SLeb128, "-123456", Endian::Little), vec![0xC0, 0xBB, 0x78]);
        assert_eq!(dec(FieldKind::SLeb128, &[0x7F], Endian::Little), "-1");
        // An unterminated continuation within the window.
        assert!(FieldKind::ULeb128.decode(&[0x80, 0x80], Endian::Little, Charset::Ascii).is_err());
        // u64::MAX and i64::MIN go all the way round.
        let b = enc(FieldKind::ULeb128, &u64::MAX.to_string(), Endian::Little);
        assert_eq!(dec(FieldKind::ULeb128, &b, Endian::Little), u64::MAX.to_string());
        let b = enc(FieldKind::SLeb128, &i64::MIN.to_string(), Endian::Little);
        assert_eq!(dec(FieldKind::SLeb128, &b, Endian::Little), i64::MIN.to_string());
    }

    #[test]
    fn time_t_and_dates() {
        assert_eq!(dec(FieldKind::TimeT32, &0u32.to_le_bytes(), Endian::Little), "1970-01-01 00:00:00");
        // 2004-02-29 12:00:00 UTC = 1078056000 (a leap year).
        assert_eq!(
            dec(FieldKind::TimeT32, &1_078_056_000u32.to_le_bytes(), Endian::Little),
            "2004-02-29 12:00:00"
        );
        // Negative: before the epoch.
        assert_eq!(
            dec(FieldKind::TimeT32, &(-86_400i32).to_le_bytes(), Endian::Little),
            "1969-12-31 00:00:00"
        );
        assert_eq!(
            enc(FieldKind::TimeT32, "2004-02-29 12:00:00", Endian::Little),
            1_078_056_000u32.to_le_bytes()
        );
        assert_eq!(
            enc(FieldKind::TimeT64, "1969-12-31", Endian::Big),
            (-86_400i64).to_be_bytes()
        );
    }

    #[test]
    fn filetime() {
        // 1601-01-01 is tick zero.
        assert_eq!(dec(FieldKind::FileTime, &0u64.to_le_bytes(), Endian::Little), "1601-01-01 00:00:00");
        // The Unix epoch in FILETIME.
        let ft = 116_444_736_000_000_000u64;
        assert_eq!(dec(FieldKind::FileTime, &ft.to_le_bytes(), Endian::Little), "1970-01-01 00:00:00");
        assert_eq!(enc(FieldKind::FileTime, "1970-01-01 00:00:00", Endian::Little), ft.to_le_bytes());
    }

    #[test]
    fn dos_date() {
        // 1999-12-31 23:59:58: date = (19<<9)|(12<<5)|31, time = (23<<11)|(59<<5)|29
        let date = (19u32 << 9 | 12 << 5 | 31) << 16;
        let time = 23u32 << 11 | 59 << 5 | 29;
        let v = date | time;
        assert_eq!(dec(FieldKind::DosDateTime, &v.to_le_bytes(), Endian::Little), "1999-12-31 23:59:58");
        assert_eq!(enc(FieldKind::DosDateTime, "1999-12-31 23:59:58", Endian::Little), v.to_le_bytes());
        assert!(FieldKind::DosDateTime.encode("1975-01-01", Endian::Little, Charset::Ascii).is_err());
        // Month 0 is not a DOS date.
        assert!(FieldKind::DosDateTime.decode(&0u32.to_le_bytes(), Endian::Little, Charset::Ascii).is_err());
    }

    #[test]
    fn ole_date() {
        // 25569.5 = 1970-01-01 12:00 (days since 1899-12-30).
        assert_eq!(
            dec(FieldKind::OleDate, &25_569.5f64.to_le_bytes(), Endian::Little),
            "1970-01-01 12:00:00"
        );
        // -1.25 = 1899-12-29 06:00 (the OLE convention for negatives).
        assert_eq!(
            dec(FieldKind::OleDate, &(-1.25f64).to_le_bytes(), Endian::Little),
            "1899-12-29 06:00:00"
        );
        assert_eq!(enc(FieldKind::OleDate, "1970-01-01 12:00:00", Endian::Little), 25_569.5f64.to_le_bytes());
        assert_eq!(enc(FieldKind::OleDate, "1899-12-29 06:00:00", Endian::Little), (-1.25f64).to_le_bytes());
    }

    #[test]
    fn guid_little_endian_is_the_windows_layout() {
        // {00112233-4455-6677-8899-AABBCCDDEEFF} written the way Windows writes it.
        let bytes = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let s = "{00112233-4455-6677-8899-AABBCCDDEEFF}";
        assert_eq!(dec(FieldKind::Guid, &bytes, Endian::Little), s);
        assert_eq!(enc(FieldKind::Guid, s, Endian::Little), bytes);
        // Big-endian: the 16 bytes in the order they appear.
        let be: Vec<u8> = (0..16).map(|i| [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF][i]).collect();
        assert_eq!(dec(FieldKind::Guid, &be, Endian::Big), s);
    }

    #[test]
    fn colours() {
        assert_eq!(dec(FieldKind::Rgb, &[0x12, 0x34, 0x56], Endian::Little), "#123456");
        assert_eq!(dec(FieldKind::Rgba, &[0x12, 0x34, 0x56, 0x78], Endian::Little), "#12345678");
        assert_eq!(enc(FieldKind::Rgb, "#FF00AA", Endian::Little), vec![0xFF, 0x00, 0xAA]);
        assert!(FieldKind::Rgb.encode("#XYZ", Endian::Little, Charset::Ascii).is_err());
    }

    #[test]
    fn a_character_honours_the_charset() {
        let r = FieldKind::Char.decode("é".as_bytes(), Endian::Little, Charset::Utf8).unwrap();
        assert_eq!(r, ("é".to_string(), 2));
        let r = FieldKind::Char.decode(&[0xE9], Endian::Little, Charset::Windows1252).unwrap();
        assert_eq!(r, ("é".to_string(), 1));
        // Reverse encoding through the table.
        assert_eq!(
            FieldKind::Char.encode("é", Endian::Little, Charset::Windows1252).unwrap(),
            vec![0xE9]
        );
        assert!(FieldKind::Char.encode("€", Endian::Little, Charset::Ascii).is_err());
        // UTF-16 follows the active endianness.
        let r = FieldKind::Char.decode(&[0x00, 0x41], Endian::Big, Charset::Utf16Le).unwrap();
        assert_eq!(r, ("A".to_string(), 2));
    }

    #[test]
    fn a_cstring_stops_at_the_nul_and_reports_its_length() {
        let (s, n) =
            FieldKind::CString.decode(b"hello\0world", Endian::Little, Charset::Ascii).unwrap();
        assert_eq!(s, "\"hello\"");
        assert_eq!(n, 5, "covers the content only, without the NUL");
        // No NUL in the window: shows an ellipsis.
        let (s, _) = FieldKind::CString.decode(b"abc", Endian::Little, Charset::Ascii).unwrap();
        assert_eq!(s, "\"abc\"…");
        // UTF-16: the terminator is two aligned zero bytes.
        let bytes = [0x41, 0x00, 0x42, 0x00, 0x00, 0x00, 0x43, 0x00];
        let (s, n) = FieldKind::CString.decode(&bytes, Endian::Little, Charset::Utf16Le).unwrap();
        assert_eq!(s, "\"AB\"");
        assert_eq!(n, 4);
    }

    #[test]
    fn the_hinnant_calendar_is_consistent() {
        for days in [-1_000_000i64, -25_569, -1, 0, 1, 10_957, 20_000, 1_000_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-OLE_EPOCH_DAYS), (1899, 12, 30));
    }
}
