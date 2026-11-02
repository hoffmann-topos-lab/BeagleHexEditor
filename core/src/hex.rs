//! Hexadecimal text: the one place every layer (core, CLI, GUI) parses
//! `"0x1F4"`/`"500"` and `"DE AD BE EF"`, and formats bytes as hex.
//!
//! Parsers return `Option`; each caller wraps `None` in an error that names
//! its own context (line number, flag, dialog).

/// Decimal, or hexadecimal with a `0x`/`0X` prefix. Surrounding whitespace is
/// ignored.
pub fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// A byte string as hex digit pairs; whitespace anywhere is tolerated
/// (`"DEADBEEF"`, `"DE AD"`, line breaks). An odd digit count or a non-hex
/// digit is `None`; the empty string is an empty vector.
pub fn parse_bytes(s: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits.chunks(2).map(|p| Some(nibble(p[0])? << 4 | nibble(p[1])?)).collect()
}

fn nibble(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// Lowercase hex with no separator (`"deadbeef"`), like the system hash tools.
pub fn encode(bytes: &[u8]) -> String {
    encode_with(bytes, "")
}

/// Lowercase hex pairs joined by `sep` (`"de ad be ef"` for `" "`).
pub fn encode_with(bytes: &[u8], sep: &str) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * (2 + sep.len()));
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push_str(sep);
        }
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xF) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_in_both_bases() {
        assert_eq!(parse_u64("500"), Some(500));
        assert_eq!(parse_u64(" 0x1F4 "), Some(0x1F4));
        assert_eq!(parse_u64("0X1f4"), Some(0x1F4));
        assert_eq!(parse_u64("0x"), None);
        assert_eq!(parse_u64("-1"), None);
        assert_eq!(parse_u64("12z"), None);
    }

    #[test]
    fn byte_strings_tolerate_whitespace() {
        assert_eq!(parse_bytes("DEADBEEF"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(parse_bytes("de ad\nbe\tef"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(parse_bytes(""), Some(vec![]));
        assert_eq!(parse_bytes("ABC"), None);
        assert_eq!(parse_bytes("ZZ"), None);
        assert_eq!(parse_bytes("+1"), None);
    }

    #[test]
    fn encoding_round_trips() {
        let bytes = [0x00, 0x0F, 0xA5, 0xFF];
        assert_eq!(encode(&bytes), "000fa5ff");
        assert_eq!(encode_with(&bytes, " "), "00 0f a5 ff");
        assert_eq!(encode(&[]), "");
        assert_eq!(parse_bytes(&encode_with(&bytes, " ")), Some(bytes.to_vec()));
    }
}
