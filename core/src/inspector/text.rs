//! Character, NUL string, GUID and colour fields.

use crate::charset::{Charset, UNPRINTABLE, is_printable};

use super::scalar::{insufficient, int, take};
use super::{Decoded, Endian};

/// Scan limit for the NUL-terminated string.
const CSTRING_SCAN: usize = 256;
/// Display limit for the string (in characters).
const CSTRING_SHOW: usize = 64;

pub(super) fn decode_char(
    bytes: &[u8],
    endian: Endian,
    charset: Charset,
) -> Result<Decoded, String> {
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
        None => Err("byte with no character in this charset".into()),
    }
}

pub(super) fn encode_char(
    text: &str,
    endian: Endian,
    charset: Charset,
) -> Result<Vec<u8>, String> {
    let mut chars = text.chars();
    let (Some(c), None) = (chars.next(), chars.next()) else {
        return Err("type exactly one character".into());
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

pub(super) fn decode_cstring(
    bytes: &[u8],
    endian: Endian,
    charset: Charset,
) -> Result<Decoded, String> {
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

// ---- GUID and colours ----

pub(super) fn decode_guid(bytes: &[u8], endian: Endian) -> Result<Decoded, String> {
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

pub(super) fn encode_guid(text: &str, endian: Endian) -> Result<Vec<u8>, String> {
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

pub(super) fn parse_color(text: &str, n: usize) -> Result<Vec<u8>, String> {
    let hex = text.trim().trim_start_matches('#');
    if hex.len() != n * 2 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid colour (expected #{})", "RR".repeat(n)));
    }
    Ok((0..n).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect())
}
