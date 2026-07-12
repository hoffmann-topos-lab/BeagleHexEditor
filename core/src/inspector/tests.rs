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
    assert_eq!(f16_to_f32(0x7BFF), 65504.0); // largest finite
    assert_eq!(f16_to_f32(0x0001), 5.960_464_5e-8); // smallest subnormal
    assert!(f16_to_f32(0x7C01).is_nan());
    assert_eq!(f16_to_f32(0xFC00), f32::NEG_INFINITY);
    for h in [0x3C00u16, 0xC000, 0x7BFF, 0x0001, 0x03FF, 0x0400, 0x8000] {
        assert_eq!(f32_to_f16(f16_to_f32(h)), h, "roundtrip of {h:#06X}");
    }
    assert_eq!(f32_to_f16(1e9), 0x7C00, "overflow becomes +inf");
    assert_eq!(f32_to_f16(1e-10), 0x0000, "underflow becomes zero");
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
