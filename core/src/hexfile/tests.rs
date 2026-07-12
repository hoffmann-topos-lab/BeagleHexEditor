use super::*;
use crate::document::Document;
use crate::error::ErrorKind;
use crate::progress::Progress;
use crate::source::MemSource;

fn doc(bytes: &[u8]) -> Document {
    Document::new(Box::new(MemSource::new(bytes.to_vec())))
}

fn export_str(data: &[u8], fmt: RecordFormat, base: u64, rec_len: usize) -> String {
    let mut d = doc(data);
    let len = d.len();
    let mut out = Vec::new();
    write_records(&mut d, 0..len, fmt, base, rec_len, &mut out, &Progress::new()).unwrap();
    String::from_utf8(out).unwrap()
}

// The classic example from the Intel HEX format documentation.
const IHEX_SAMPLE: &str = "\
:10010000214601360121470136007EFE09D2190140
:100110002146017E17C20001FF5F16002148011928
:00000001FF
";

// The classic example from the S-record format documentation ("hello world").
const SREC_SAMPLE: &str = "\
S00F000068656C6C6F202020202000003C
S11F00007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000026
S11F001C4BFFFFE5398000007D83637880010014382100107C0803A64E800020E9
S111003848656C6C6F20776F726C642E0A0042
S5030003F9
S9030000FC
";

#[test]
fn ihex_parses_the_classic_example() {
    let img = parse_ihex(IHEX_SAMPLE).unwrap();
    assert_eq!(img.segments.len(), 1, "contiguous records are merged");
    assert_eq!(img.segments[0].addr, 0x0100);
    assert_eq!(img.segments[0].data.len(), 32);
    assert_eq!(&img.segments[0].data[..4], &[0x21, 0x46, 0x01, 0x36]);
    assert_eq!(img.data_len(), 32);
    assert_eq!(img.span(), Some(0x0100..0x0120));
}

#[test]
fn srec_parses_the_classic_example() {
    let img = parse_srec(SREC_SAMPLE).unwrap();
    assert_eq!(img.segments.len(), 1);
    assert_eq!(img.segments[0].addr, 0);
    assert_eq!(img.data_len(), 0x1F + 0x1F + 0x11 - 3 * 3);
    assert_eq!(img.entry, Some(0));
    let text: Vec<u8> = img.segments[0].data[0x38..].to_vec();
    assert_eq!(&text, b"Hello world.\x0A\x00");
}

#[test]
fn automatic_format_detection() {
    assert_eq!(parse(IHEX_SAMPLE).unwrap().0, RecordFormat::IntelHex);
    assert_eq!(parse(SREC_SAMPLE).unwrap().0, RecordFormat::Srec);
    assert!(parse("hello\n").is_err());
    assert!(parse("").is_err());
}

#[test]
fn a_bad_ihex_checksum_aborts_with_the_line_number() {
    let bad = IHEX_SAMPLE.replace("D2190140", "D2190141");
    let err = parse_ihex(&bad).unwrap_err();
    assert!(err.detail.contains("line 1"), "{err}");
    assert!(err.detail.contains("checksum"), "{err}");
}

#[test]
fn a_bad_srec_checksum_aborts_with_the_line_number() {
    let bad = SREC_SAMPLE.replace("0A0042", "0A0043");
    let err = parse_srec(&bad).unwrap_err();
    assert!(err.detail.contains("line 4"), "{err}");
}

#[test]
fn a_bad_srec_count_aborts() {
    let bad = SREC_SAMPLE.replace("S5030003F9", "S5030004F8");
    let err = parse_srec(&bad).unwrap_err();
    assert!(err.detail.contains("count"), "{err}");
}

#[test]
fn ihex_without_eof_and_srec_without_a_terminator_both_abort() {
    assert!(parse_ihex(":100100002146013601214701360\n").is_err());
    let without_eof = IHEX_SAMPLE.replace(":00000001FF\n", "");
    assert!(parse_ihex(&without_eof).unwrap_err().detail.contains("EOF"));
    let without_term = SREC_SAMPLE.replace("S9030000FC\n", "");
    assert!(parse_srec(&without_term).unwrap_err().detail.contains("terminator"));
}

#[test]
fn overlap_is_refused() {
    let mut img = Image {
        segments: vec![
            Segment { addr: 0, data: vec![1, 2, 3] },
            Segment { addr: 2, data: vec![4] },
        ],
        entry: None,
    };
    assert!(img.normalize().is_err());
}

#[test]
fn flatten_fills_the_gaps() {
    let img = Image {
        segments: vec![
            Segment { addr: 4, data: vec![0xAA] },
            Segment { addr: 8, data: vec![0xBB, 0xCC] },
        ],
        entry: None,
    };
    let (base, bytes) = img.flatten(0xFF).unwrap();
    assert_eq!(base, 4);
    assert_eq!(bytes, vec![0xAA, 0xFF, 0xFF, 0xFF, 0xBB, 0xCC]);
}

#[test]
fn ihex_export_and_reimport_return_the_bytes() {
    let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let text = export_str(&data, RecordFormat::IntelHex, 0, DEFAULT_REC_LEN);
    let img = parse_ihex(&text).unwrap();
    let (base, bytes) = img.flatten(0xFF).unwrap();
    assert_eq!(base, 0);
    assert_eq!(bytes, data);
}

#[test]
fn srec_export_and_reimport_return_the_bytes() {
    let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let text = export_str(&data, RecordFormat::Srec, 0x100, 32);
    let img = parse_srec(&text).unwrap();
    let (base, bytes) = img.flatten(0xFF).unwrap();
    assert_eq!(base, 0x100);
    assert_eq!(bytes, data);
    assert!(text.starts_with("S0"), "the header is present");
    assert!(text.contains("\nS5"), "the count is present");
}

#[test]
fn ihex_crosses_the_64k_boundary_with_an_extended_record() {
    // 32 bytes placed at 0xFFF0: half before, half after 0x10000.
    let data = vec![0x5A; 32];
    let text = export_str(&data, RecordFormat::IntelHex, 0xFFF0, DEFAULT_REC_LEN);
    assert!(!text.contains(":020000040000"), "base 0 is implicit\n{text}");
    assert!(text.contains(":020000040001F9"), "base 0x0001 after the boundary\n{text}");
    let img = parse_ihex(&text).unwrap();
    let (base, bytes) = img.flatten(0).unwrap();
    assert_eq!(base, 0xFFF0);
    assert_eq!(bytes, data);
}

#[test]
fn srec_picks_the_type_from_the_address() {
    let text = export_str(&[1], RecordFormat::Srec, 0, 16);
    assert!(text.contains("\nS104"), "16-bit addresses use S1\n{text}");
    assert!(text.trim_end().ends_with("S9030000FC"), "{text}");
    let text = export_str(&[1], RecordFormat::Srec, 0x123456, 16);
    assert!(text.contains("\nS2"), "24 bits use S2\n{text}");
    assert!(text.contains("\nS8"), "{text}");
    let text = export_str(&[1], RecordFormat::Srec, 0x0100_0000, 16);
    assert!(text.contains("\nS3"), "32 bits use S3\n{text}");
    assert!(text.contains("\nS7"), "{text}");
}

#[test]
fn export_refuses_addresses_beyond_32_bits() {
    let d = doc(&[0u8; 8]);
    // The sum overflows u64: refused.
    assert!(RecordExportJob::new(RecordFormat::IntelHex, 0..8, u64::MAX - 4, 16, d.len())
        .is_err());
    // Past 2^32: refused.
    let err = RecordExportJob::new(RecordFormat::Srec, 0..8, ADDR_LIMIT - 4, 16, d.len())
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::OutOfBounds);
    // At the exact limit it still fits (last byte at 2^32 - 1).
    assert!(RecordExportJob::new(RecordFormat::Srec, 0..8, ADDR_LIMIT - 8, 16, d.len())
        .is_ok());
}

#[test]
fn an_export_with_an_unreadable_block_aborts() {
    let src = MemSource::new(vec![1u8; 64]).with_bad_range(16..32);
    let mut d = Document::new(Box::new(src));
    d.set_cache(crate::cache::BlockCache::new(16, 8));
    let mut out = Vec::new();
    let err =
        write_records(&mut d, 0..64, RecordFormat::IntelHex, 0, 16, &mut out, &Progress::new())
            .unwrap_err();
    assert_eq!(err.kind, ErrorKind::BadBlock);
}

#[test]
fn small_steps_produce_the_same_as_one_giant_step() {
    let data: Vec<u8> = (0..200u8).collect();
    for fmt in [RecordFormat::IntelHex, RecordFormat::Srec] {
        let mut d = doc(&data);
        let mut job = RecordExportJob::new(fmt, 0..d.len(), 0x8000, 16, d.len()).unwrap();
        let mut small = Vec::new();
        while !job.is_finished() {
            job.step(&mut d, 5, &mut small).unwrap();
        }
        let big = export_str(&data, fmt, 0x8000, 16);
        assert_eq!(String::from_utf8(small).unwrap(), big, "{}", fmt.name());
    }
}

#[test]
fn the_entry_address_of_the_entry_records() {
    let ihex = "\
:0400000512345678E3
:00000001FF
";
    assert_eq!(parse_ihex(ihex).unwrap().entry, Some(0x12345678));
    // Type 03: CS:IP → CS*16 + IP.
    let ihex = "\
:040000031234000AA9
:00000001FF
";
    assert_eq!(parse_ihex(ihex).unwrap().entry, Some(0x1234 * 16 + 0x000A));
}

#[test]
fn the_ihex_type_02_record_shifts_by_paragraph() {
    let text = "\
:020000021000EC
:0100000041BE
:00000001FF
";
    let img = parse_ihex(text).unwrap();
    assert_eq!(img.segments[0].addr, 0x10000);
    assert_eq!(img.segments[0].data, vec![0x41]);
}
