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
                None => break, // par substituto cortado na borda
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

// ---- generated tables (0 = unprintable) ----

#[rustfmt::skip]
const CP1252: [u32; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x00
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x10
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,                                    // 0x20
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,                                    // 0x30
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,                                    // 0x40
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,                                    // 0x50
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,                                    // 0x60
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0,                                       // 0x70
    0x20AC, 0, 0x201A, 0x192, 0x201E, 0x2026, 0x2020, 0x2021,
    0x2C6, 0x2030, 0x160, 0x2039, 0x152, 0, 0x17D, 0,                                  // 0x80
    0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x2DC, 0x2122, 0x161, 0x203A, 0x153, 0, 0x17E, 0x178,                              // 0x90
    0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0, 0xAE, 0xAF,                                       // 0xA0
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,                                    // 0xB0
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,                                    // 0xC0
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,                                    // 0xD0
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,                                    // 0xE0
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,                                    // 0xF0
];

#[rustfmt::skip]
const CP437: [u32; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x00
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x10
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,                                    // 0x20
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,                                    // 0x30
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,                                    // 0x40
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,                                    // 0x50
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,                                    // 0x60
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0,                                       // 0x70
    0xC7, 0xFC, 0xE9, 0xE2, 0xE4, 0xE0, 0xE5, 0xE7,
    0xEA, 0xEB, 0xE8, 0xEF, 0xEE, 0xEC, 0xC4, 0xC5,                                    // 0x80
    0xC9, 0xE6, 0xC6, 0xF4, 0xF6, 0xF2, 0xFB, 0xF9,
    0xFF, 0xD6, 0xDC, 0xA2, 0xA3, 0xA5, 0x20A7, 0x192,                                 // 0x90
    0xE1, 0xED, 0xF3, 0xFA, 0xF1, 0xD1, 0xAA, 0xBA,
    0xBF, 0x2310, 0xAC, 0xBD, 0xBC, 0xA1, 0xAB, 0xBB,                                  // 0xA0
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,                    // 0xB0
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,                    // 0xC0
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B,
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,                    // 0xD0
    0x3B1, 0xDF, 0x393, 0x3C0, 0x3A3, 0x3C3, 0xB5, 0x3C4,
    0x3A6, 0x398, 0x3A9, 0x3B4, 0x221E, 0x3C6, 0x3B5, 0x2229,                          // 0xE0
    0x2261, 0xB1, 0x2265, 0x2264, 0x2320, 0x2321, 0xF7, 0x2248,
    0xB0, 0x2219, 0xB7, 0x221A, 0x207F, 0xB2, 0x25A0, 0,                               // 0xF0
];

#[rustfmt::skip]
const MAC_ROMAN: [u32; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x00
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x10
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,                                    // 0x20
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,                                    // 0x30
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,                                    // 0x40
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,                                    // 0x50
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,                                    // 0x60
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0,                                       // 0x70
    0xC4, 0xC5, 0xC7, 0xC9, 0xD1, 0xD6, 0xDC, 0xE1,
    0xE0, 0xE2, 0xE4, 0xE3, 0xE5, 0xE7, 0xE9, 0xE8,                                    // 0x80
    0xEA, 0xEB, 0xED, 0xEC, 0xEE, 0xEF, 0xF1, 0xF3,
    0xF2, 0xF4, 0xF6, 0xF5, 0xFA, 0xF9, 0xFB, 0xFC,                                    // 0x90
    0x2020, 0xB0, 0xA2, 0xA3, 0xA7, 0x2022, 0xB6, 0xDF,
    0xAE, 0xA9, 0x2122, 0xB4, 0xA8, 0x2260, 0xC6, 0xD8,                                // 0xA0
    0x221E, 0xB1, 0x2264, 0x2265, 0xA5, 0xB5, 0x2202, 0x2211,
    0x220F, 0x3C0, 0x222B, 0xAA, 0xBA, 0x3A9, 0xE6, 0xF8,                              // 0xB0
    0xBF, 0xA1, 0xAC, 0x221A, 0x192, 0x2248, 0x2206, 0xAB,
    0xBB, 0x2026, 0, 0xC0, 0xC3, 0xD5, 0x152, 0x153,                                   // 0xC0
    0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0xF7, 0x25CA,
    0xFF, 0x178, 0x2044, 0x20AC, 0x2039, 0x203A, 0xFB01, 0xFB02,                       // 0xD0
    0x2021, 0xB7, 0x201A, 0x201E, 0x2030, 0xC2, 0xCA, 0xC1,
    0xCB, 0xC8, 0xCD, 0xCE, 0xCF, 0xCC, 0xD3, 0xD4,                                    // 0xE0
    0, 0xD2, 0xDA, 0xDB, 0xD9, 0x131, 0x2C6, 0x2DC,
    0xAF, 0x2D8, 0x2D9, 0x2DA, 0xB8, 0x2DD, 0x2DB, 0x2C7,                              // 0xF0
];

#[rustfmt::skip]
const CP037: [u32; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x00
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x10
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x20
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                    // 0x30
    0x20, 0, 0xE2, 0xE4, 0xE0, 0xE1, 0xE3, 0xE5,
    0xE7, 0xF1, 0xA2, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,                                    // 0x40
    0x26, 0xE9, 0xEA, 0xEB, 0xE8, 0xED, 0xEE, 0xEF,
    0xEC, 0xDF, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0xAC,                                    // 0x50
    0x2D, 0x2F, 0xC2, 0xC4, 0xC0, 0xC1, 0xC3, 0xC5,
    0xC7, 0xD1, 0xA6, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,                                    // 0x60
    0xF8, 0xC9, 0xCA, 0xCB, 0xC8, 0xCD, 0xCE, 0xCF,
    0xCC, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,                                    // 0x70
    0xD8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0xAB, 0xBB, 0xF0, 0xFD, 0xFE, 0xB1,                                    // 0x80
    0xB0, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
    0x71, 0x72, 0xAA, 0xBA, 0xE6, 0xB8, 0xC6, 0xA4,                                    // 0x90
    0xB5, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7A, 0xA1, 0xBF, 0xD0, 0xDD, 0xDE, 0xAE,                                    // 0xA0
    0x5E, 0xA3, 0xA5, 0xB7, 0xA9, 0xA7, 0xB6, 0xBC,
    0xBD, 0xBE, 0x5B, 0x5D, 0xAF, 0xA8, 0xB4, 0xD7,                                    // 0xB0
    0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0, 0xF4, 0xF6, 0xF2, 0xF3, 0xF5,                                       // 0xC0
    0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0xB9, 0xFB, 0xFC, 0xF9, 0xFA, 0xFF,                                    // 0xD0
    0x5C, 0xF7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0xB2, 0xD4, 0xD6, 0xD2, 0xD3, 0xD5,                                    // 0xE0
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0xB3, 0xDB, 0xDC, 0xD9, 0xDA, 0,                                       // 0xF0
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_prints_only_the_visible_range() {
        assert_eq!(Charset::Ascii.decode_byte(b'A'), Some('A'));
        assert_eq!(Charset::Ascii.decode_byte(0x1F), None);
        assert_eq!(Charset::Ascii.decode_byte(0x7F), None);
        assert_eq!(Charset::Ascii.decode_byte(0xE9), None);
    }

    #[test]
    fn single_byte_tables() {
        assert_eq!(Charset::Windows1252.decode_byte(0x80), Some('€'));
        assert_eq!(Charset::Windows1252.decode_byte(0xE9), Some('é'));
        assert_eq!(Charset::Windows1252.decode_byte(0x81), None, "unassigned");
        assert_eq!(Charset::Cp437.decode_byte(0xB0), Some('░'));
        assert_eq!(Charset::Cp437.decode_byte(0xE1), Some('ß'));
        assert_eq!(Charset::MacRoman.decode_byte(0xA5), Some('•'));
        // EBCDIC CP037: letters, digits and punctuation at the classic code points.
        assert_eq!(Charset::Ebcdic.decode_byte(0xC1), Some('A'));
        assert_eq!(Charset::Ebcdic.decode_byte(0x81), Some('a'));
        assert_eq!(Charset::Ebcdic.decode_byte(0xF0), Some('0'));
        assert_eq!(Charset::Ebcdic.decode_byte(0x40), Some(' '));
        assert_eq!(Charset::Ebcdic.decode_byte(0x4B), Some('.'));
    }

    #[test]
    fn utf8_shows_the_character_on_the_first_byte_and_continuation_on_the_rest() {
        // "é" = C3 A9; "€" = E2 82 AC
        let cells = Charset::Utf8.decode_cells(0, "aé€".as_bytes());
        assert_eq!(cells, vec!['a', 'é', CONTINUATION, '€', CONTINUATION, CONTINUATION]);
    }

    #[test]
    fn invalid_utf8_becomes_a_dot() {
        let cells = Charset::Utf8.decode_cells(0, &[0xFF, 0x41, 0xA9]);
        assert_eq!(cells, vec![UNPRINTABLE, 'A', UNPRINTABLE]);
    }

    #[test]
    fn utf8_truncated_at_the_edge_does_not_panic() {
        // "€" truncated: only the first 2 bytes are visible.
        let cells = Charset::Utf8.decode_cells(0, &[0xE2, 0x82]);
        assert_eq!(cells, vec![UNPRINTABLE, UNPRINTABLE]);
    }

    #[test]
    fn utf16le_aligns_by_the_absolute_offset() {
        // "AB" in UTF-16LE: 41 00 42 00
        let bytes = [0x41, 0x00, 0x42, 0x00];
        let cells = Charset::Utf16Le.decode_cells(0, &bytes);
        assert_eq!(cells, vec!['A', CONTINUATION, 'B', CONTINUATION]);
        // Window starting at an odd offset: the first byte is mid-unit.
        let cells = Charset::Utf16Le.decode_cells(1, &bytes[1..]);
        assert_eq!(cells[0], UNPRINTABLE);
    }

    #[test]
    fn utf16_surrogate_pair() {
        // U+1F600 in UTF-16LE: 3D D8 00 DE
        let bytes = [0x3D, 0xD8, 0x00, 0xDE];
        let cells = Charset::Utf16Le.decode_cells(0, &bytes);
        assert_eq!(cells, vec!['😀', CONTINUATION, CONTINUATION, CONTINUATION]);
        assert_eq!(Charset::Utf16Le.decode_char_at(&bytes), Some(('😀', 4)));
    }

    #[test]
    fn decode_char_at_per_charset() {
        assert_eq!(Charset::Ascii.decode_char_at(b"Z"), Some(('Z', 1)));
        assert_eq!(Charset::Utf8.decode_char_at("é!".as_bytes()), Some(('é', 2)));
        assert_eq!(Charset::Utf16Be.decode_char_at(&[0x00, 0x41]), Some(('A', 2)));
        assert_eq!(Charset::Utf8.decode_char_at(&[0xC3]), None, "truncated");
    }

    #[test]
    fn from_name_accepts_aliases() {
        assert_eq!(Charset::from_name("CP437"), Some(Charset::Cp437));
        assert_eq!(Charset::from_name("utf-16le"), Some(Charset::Utf16Le));
        assert_eq!(Charset::from_name("Windows-1252"), Some(Charset::Windows1252));
        assert_eq!(Charset::from_name("ebcdic"), Some(Charset::Ebcdic));
        assert_eq!(Charset::from_name("klingon"), None);
    }
}
