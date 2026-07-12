use super::*;
use crate::source::MemSource;

fn doc(bytes: &[u8]) -> Document {
    Document::new(Box::new(MemSource::new(bytes.to_vec())))
}

fn export_of(bytes: &[u8], fmt: ExportFormat, opts: ExportOptions) -> String {
    let mut d = doc(bytes);
    let len = d.len();
    export_string(&mut d, 0..len, fmt, opts, &Progress::new()).unwrap()
}

#[test]
fn raw_hex_wraps_by_columns() {
    let opts = ExportOptions { cols: 4, ..Default::default() };
    let got = export_of(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01], ExportFormat::HexText, opts);
    assert_eq!(got, "DE AD BE EF\n00 01\n");
}

#[test]
fn c_has_a_size_commas_and_no_trailing_comma() {
    let opts = ExportOptions { cols: 4, ..Default::default() };
    let got = export_of(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00], ExportFormat::C, opts);
    assert_eq!(
        got,
        "unsigned char data[5] = {\n    0xDE, 0xAD, 0xBE, 0xEF,\n    0x00\n};\n"
    );
}

#[test]
fn java_uses_signed_decimal() {
    let got = export_of(&[0xFF, 0x00, 0x7F], ExportFormat::Java, ExportOptions::default());
    assert_eq!(got, "byte[] data = {\n    -1, 0, 127\n};\n");
}

#[test]
fn csharp_pascal_and_python() {
    let bytes = [0xAB, 0xCD];
    assert_eq!(
        export_of(&bytes, ExportFormat::CSharp, ExportOptions::default()),
        "byte[] data = new byte[2] {\n    0xAB, 0xCD\n};\n"
    );
    assert_eq!(
        export_of(&bytes, ExportFormat::Pascal, ExportOptions::default()),
        "const\n  data: array[0..1] of Byte = (\n    $AB, $CD\n  );\n"
    );
    assert_eq!(
        export_of(&bytes, ExportFormat::Python, ExportOptions::default()),
        "data = bytes([\n    0xAB, 0xCD\n])\n"
    );
}

#[test]
fn the_variable_name_is_configurable() {
    let opts = ExportOptions { var_name: "firmware".into(), ..Default::default() };
    let got = export_of(&[0x01], ExportFormat::C, opts);
    assert!(got.starts_with("unsigned char firmware[1] = {"));
}

#[test]
fn the_txt_dump_has_offset_hex_and_text() {
    let opts = ExportOptions { cols: 8, ..Default::default() };
    let got = export_of(b"ABCDEFGHIJ", ExportFormat::Txt, opts);
    let lines: Vec<&str> = got.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "00000000  41 42 43 44 45 46 47 48  |ABCDEFGH|");
    assert_eq!(lines[1], "00000008  49 4A                    |IJ|");
}

#[test]
fn the_dump_honours_the_starting_offset_and_the_base() {
    let opts = ExportOptions {
        cols: 4,
        offset_start: 0x1000,
        base: OffsetBase::Hex,
        ..Default::default()
    };
    let got = export_of(&[0u8; 4], ExportFormat::Txt, opts);
    assert!(got.starts_with("00001000  "), "{got}");
}

#[test]
fn html_escapes_the_text_column() {
    let got = export_of(b"<&>", ExportFormat::Html, ExportOptions::default());
    assert!(got.contains("|&lt;&amp;&gt;|"), "{got}");
    assert!(got.starts_with("<!DOCTYPE html>"));
    assert!(got.trim_end().ends_with("</html>"));
}

#[test]
fn rtf_escapes_braces_and_backslashes() {
    let got = export_of(b"{a\\b}", ExportFormat::Rtf, ExportOptions::default());
    assert!(got.contains("|\\{a\\\\b\\}|"), "{got}");
    assert!(got.starts_with("{\\rtf1"));
    assert!(got.trim_end().ends_with('}'));
}

#[test]
fn tex_wraps_in_verbatim() {
    let got = export_of(b"x", ExportFormat::Tex, ExportOptions::default());
    assert!(got.contains("\\begin{verbatim}\n"));
    assert!(got.contains("|x|"));
    assert!(got.trim_end().ends_with("\\end{document}"));
}

#[test]
fn small_steps_produce_the_same_as_one_giant_step() {
    let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    for fmt in ExportFormat::ALL {
        let mut d = doc(&data);
        let mut job =
            ExportJob::new(fmt, ExportOptions::default(), 0..d.len(), d.len());
        let mut small = Vec::new();
        while !job.is_finished() {
            job.step(&mut d, 7, &mut small).unwrap();
        }
        let big = export_of(&data, fmt, ExportOptions::default());
        assert_eq!(String::from_utf8(small).unwrap(), big, "{}", fmt.name());
    }
}

#[test]
fn a_clipped_range_is_honoured() {
    let mut d = doc(b"xxabcxx");
    let got = export_string(
        &mut d,
        2..5,
        ExportFormat::HexText,
        ExportOptions::default(),
        &Progress::new(),
    )
    .unwrap();
    assert_eq!(got, "61 62 63\n");
}

#[test]
fn an_empty_range_still_emits_the_header_and_footer() {
    let mut d = doc(b"abc");
    let got = export_string(
        &mut d,
        1..1,
        ExportFormat::C,
        ExportOptions::default(),
        &Progress::new(),
    )
    .unwrap();
    assert_eq!(got, "unsigned char data[0] = {\n};\n");
}

#[test]
fn an_unreadable_block_aborts_the_export() {
    let src = MemSource::new(vec![1u8; 64]).with_bad_range(16..32);
    let mut d = Document::new(Box::new(src));
    d.set_cache(crate::cache::BlockCache::new(16, 8));
    let err = export_string(
        &mut d,
        0..64,
        ExportFormat::Txt,
        ExportOptions::default(),
        &Progress::new(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::BadBlock);
}

#[test]
fn it_exports_unsaved_edits() {
    let mut d = doc(b"ab");
    d.overwrite(1, b"c").unwrap();
    let got = export_string(
        &mut d,
        0..2,
        ExportFormat::HexText,
        ExportOptions::default(),
        &Progress::new(),
    )
    .unwrap();
    assert_eq!(got, "61 63\n");
}

#[test]
fn from_name_and_extension_cover_every_format() {
    for fmt in ExportFormat::ALL {
        assert_eq!(ExportFormat::from_name(fmt.name()), Some(fmt));
        assert!(!fmt.extension().is_empty());
    }
    assert_eq!(ExportFormat::from_name("cs"), Some(ExportFormat::CSharp));
    assert_eq!(ExportFormat::from_name("latex"), Some(ExportFormat::Tex));
    assert_eq!(ExportFormat::from_name("nope"), None);
}
