//! F-16/F-17 — Data Inspector: bidirectional decode/encode per field. Scalar
//! helpers live in `scalar`, dates in `dates`, char/string/GUID/colours in
//! `text`.

mod dates;
mod scalar;
#[cfg(test)]
mod tests;
mod text;

use crate::charset::Charset;

use dates::*;
use scalar::*;
use text::*;

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

    /// The `n` least significant bytes of `v`, in the active order.
    fn bytes_n(self, v: u64, n: usize) -> Vec<u8> {
        let le = v.to_le_bytes();
        match self {
            Endian::Little => le[..n].to_vec(),
            Endian::Big => le[..n].iter().rev().copied().collect(),
        }
    }
}

/// Seconds between 1601-01-01 (the FILETIME epoch) and 1970-01-01.
const FILETIME_EPOCH_DELTA: i64 = 11_644_473_600;

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
                    .map_err(|_| "outside the 32-bit time_t range".into())
            }
            FieldKind::TimeT64 => parse_datetime(text).map(|s| endian.bytes_n(s as u64, 8)),
            FieldKind::FileTime => {
                let secs = parse_datetime(text)?;
                let ticks = secs
                    .checked_add(FILETIME_EPOCH_DELTA)
                    .filter(|s| *s >= 0)
                    .and_then(|s| s.checked_mul(10_000_000))
                    .ok_or("before 1601, outside FILETIME")?;
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