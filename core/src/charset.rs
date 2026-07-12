//! F-20 — Charsets: one display cell per byte. The generated single-byte
//! tables live in `tables`.

mod tables;
#[cfg(test)]
mod tests;

use tables::*;

/// Marker for a continuation byte of a multi-byte character.
pub const CONTINUATION: char = '·';
/// Marker for a byte that is unprintable or invalid in the active charset.
pub const UNPRINTABLE: char = '.';

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Charset {
    #[default]
    Ascii,
    Windows1252,
    /// DOS / IBM PC (CP437): box drawing, Greek letters, mathematical symbols.
    Cp437,
    /// EBCDIC code page 037 (IBM mainframes).
    Ebcdic,
    MacRoman,
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Charset {
    pub const ALL: [Charset; 8] = [
        Charset::Ascii,
        Charset::Windows1252,
        Charset::Cp437,
        Charset::Ebcdic,
        Charset::MacRoman,
        Charset::Utf8,
        Charset::Utf16Le,
        Charset::Utf16Be,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Charset::Ascii => "ASCII",
            Charset::Windows1252 => "Windows-1252",
            Charset::Cp437 => "DOS (CP437)",
            Charset::Ebcdic => "EBCDIC (CP037)",
            Charset::MacRoman => "Mac Roman",
            Charset::Utf8 => "UTF-8",
            Charset::Utf16Le => "UTF-16LE",
            Charset::Utf16Be => "UTF-16BE",
        }
    }

    /// Accepts the usual CLI aliases (`--charset cp437`, `utf-16le`…).
    pub fn from_name(s: &str) -> Option<Charset> {
        let k: String =
            s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
        Some(match k.as_str() {
            "ascii" => Charset::Ascii,
            "windows1252" | "cp1252" | "latin1" | "1252" => Charset::Windows1252,
            "cp437" | "dos" | "ibm437" | "437" => Charset::Cp437,
            "ebcdic" | "cp037" | "037" => Charset::Ebcdic,
            "macroman" | "mac" => Charset::MacRoman,
            "utf8" => Charset::Utf8,
            "utf16le" | "utf16" => Charset::Utf16Le,
            "utf16be" => Charset::Utf16Be,
            _ => return None,
        })
    }

    pub fn is_single_byte(self) -> bool {
        !matches!(self, Charset::Utf8 | Charset::Utf16Le | Charset::Utf16Be)
    }

    /// Single-byte charsets: this byte's printable character, if any.
    pub fn decode_byte(self, b: u8) -> Option<char> {
        let table = match self {
            Charset::Ascii => return (0x20..0x7F).contains(&b).then_some(b as char),
            Charset::Windows1252 => &CP1252,
            Charset::Cp437 => &CP437,
            Charset::Ebcdic => &CP037,
            Charset::MacRoman => &MAC_ROMAN,
            _ => return None,
        };
        char::from_u32(table[b as usize]).filter(|c| *c != '\0')
    }

    /// One display cell per byte of `bytes`. `base` is the absolute offset of
    /// the first byte in the document — it is what aligns the UTF-16 units.
    pub fn decode_cells(self, base: u64, bytes: &[u8]) -> Vec<char> {
        match self {
            Charset::Utf8 => decode_utf8_cells(bytes),
            Charset::Utf16Le => decode_utf16_cells(base, bytes, false),
            Charset::Utf16Be => decode_utf16_cells(base, bytes, true),
            _ => bytes.iter().map(|b| self.decode_byte(*b).unwrap_or(UNPRINTABLE)).collect(),
        }
    }

    /// Encodes one character in this charset. Single-byte charsets use a
    /// reverse lookup over the 256-entry table.
    pub fn encode_char(self, c: char) -> Option<Vec<u8>> {
        match self {
            Charset::Utf8 => {
                let mut buf = [0u8; 4];
                Some(c.encode_utf8(&mut buf).as_bytes().to_vec())
            }
            Charset::Utf16Le | Charset::Utf16Be => {
                let mut units = [0u16; 2];
                let units = c.encode_utf16(&mut units);
                let big = self == Charset::Utf16Be;
                Some(
                    units
                        .iter()
                        .flat_map(|u| if big { u.to_be_bytes() } else { u.to_le_bytes() })
                        .collect(),
                )
            }
            single => (0u16..256)
                .map(|b| b as u8)
                .find(|b| single.decode_byte(*b) == Some(c))
                .map(|b| vec![b]),
        }
    }

    /// Encodes a whole string (text search, F-13b). `None` if some character
    /// does not exist in the charset — better to refuse than to search wrongly.
    pub fn encode_str(self, s: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(s.len());
        for c in s.chars() {
            out.extend(self.encode_char(c)?);
        }
        Some(out)
    }

    /// Decodes **one** character at the start of `bytes` (Data Inspector).
    /// Returns the character and how many bytes it consumed.
    pub fn decode_char_at(self, bytes: &[u8]) -> Option<(char, usize)> {
        if bytes.is_empty() {
            return None;
        }
        match self {
            Charset::Utf8 => {
                let len = utf8_len(bytes[0])?;
                let s = std::str::from_utf8(bytes.get(..len)?).ok()?;
                s.chars().next().map(|c| (c, len))
            }
            Charset::Utf16Le | Charset::Utf16Be => {
                let unit = |i: usize| -> Option<u16> {
                    let pair: [u8; 2] = bytes.get(i..i + 2)?.try_into().ok()?;
                    Some(if self == Charset::Utf16Le {
                        u16::from_le_bytes(pair)
                    } else {
                        u16::from_be_bytes(pair)
                    })
                };
                let u0 = unit(0)?;
                if (0xD800..0xDC00).contains(&u0) {
                    let u1 = unit(2)?;
                    char::decode_utf16([u0, u1]).next()?.ok().map(|c| (c, 4))
                } else {
                    char::decode_utf16([u0]).next()?.ok().map(|c| (c, 2))
                }
            }
            _ => self.decode_byte(bytes[0]).map(|c| (c, 1)),
        }
    }
}

/// Printable for the grid's purposes: not a control character, not an exotic
/// space, not an invisible formatting character.
pub fn is_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    // The most common invisible formatting (Cf): soft hyphen, zero-width, BOM, bidi.
    !matches!(c, '\u{AD}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{FEFF}')
}

fn utf8_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

fn decode_utf8_cells(bytes: &[u8]) -> Vec<char> {
    let mut cells = vec![UNPRINTABLE; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        let Some(len) = utf8_len(bytes[i]) else {
            i += 1; // orphaned or invalid continuation byte
            continue;
        };
        if i + len > bytes.len() {
            break; // character cut at the window's edge: stays as '.'
        }
        match std::str::from_utf8(&bytes[i..i + len]) {
            Ok(s) => {
                let c = s.chars().next().unwrap();
                cells[i] = if is_printable(c) { c } else { UNPRINTABLE };
                for cell in &mut cells[i + 1..i + len] {
                    *cell = CONTINUATION;
                }
                i += len;
            }
            Err(_) => i += 1,
        }
    }
    cells
}

fn decode_utf16_cells(base: u64, bytes: &[u8], big: bool) -> Vec<char> {
    let mut cells = vec![UNPRINTABLE; bytes.len()];
    // 16-bit units aligned to the even absolute offset.
    let mut i = if base.is_multiple_of(2) { 0 } else { 1 };
    let unit = |i: usize| -> Option<u16> {
        let pair: [u8; 2] = bytes.get(i..i + 2)?.try_into().ok()?;
        Some(if big { u16::from_be_bytes(pair) } else { u16::from_le_bytes(pair) })
    };
    while i + 2 <= bytes.len() {
        let u0 = unit(i).unwrap();
        let (decoded, consumed) = if (0xD800..0xDC00).contains(&u0) {
            match unit(i + 2) {
                Some(u1) => match char::decode_utf16([u0, u1]).next() {
                    Some(Ok(c)) => (Some(c), 4),
                    _ => (None, 2),
                },
                None => break, // surrogate pair cut at the edge
            }
        } else {
            match char::decode_utf16([u0]).next() {
                Some(Ok(c)) => (Some(c), 2),
                _ => (None, 2),
            }
        };
        if let Some(c) = decoded {
            cells[i] = if is_printable(c) { c } else { UNPRINTABLE };
            for cell in &mut cells[i + 1..i + consumed] {
                *cell = CONTINUATION;
            }
        }
        i += consumed;
    }
    cells
}

