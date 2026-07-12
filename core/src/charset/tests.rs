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
