use std::io::Write;
use std::ops::Range;

use crate::charset::Charset;
use crate::display::OffsetBase;
use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::progress::Progress;
use crate::search::StepResult;

/// Largest window per step.
const WINDOW: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    // F-30 — byte literals.
    HexText,
    C,
    Java,
    CSharp,
    Pascal,
    Python,
    // F-30/F-31 — offset + hex + text dumps.
    Txt,
    Html,
    Rtf,
    Tex,
}

impl ExportFormat {
    pub const ALL: [ExportFormat; 10] = [
        ExportFormat::HexText,
        ExportFormat::C,
        ExportFormat::Java,
        ExportFormat::CSharp,
        ExportFormat::Pascal,
        ExportFormat::Python,
        ExportFormat::Txt,
        ExportFormat::Html,
        ExportFormat::Rtf,
        ExportFormat::Tex,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ExportFormat::HexText => "hex",
            ExportFormat::C => "C",
            ExportFormat::Java => "Java",
            ExportFormat::CSharp => "C#",
            ExportFormat::Pascal => "Pascal",
            ExportFormat::Python => "Python",
            ExportFormat::Txt => "text",
            ExportFormat::Html => "HTML",
            ExportFormat::Rtf => "RTF",
            ExportFormat::Tex => "TeX",
        }
    }

    pub fn from_name(s: &str) -> Option<ExportFormat> {
        Some(match s.trim().to_lowercase().as_str() {
            "hex" => ExportFormat::HexText,
            "c" => ExportFormat::C,
            "java" => ExportFormat::Java,
            "c#" | "cs" | "csharp" => ExportFormat::CSharp,
            "pascal" | "pas" => ExportFormat::Pascal,
            "python" | "py" => ExportFormat::Python,
            // `texto` is kept as a legacy Portuguese alias.
            "txt" | "texto" | "text" => ExportFormat::Txt,
            "html" => ExportFormat::Html,
            "rtf" => ExportFormat::Rtf,
            "tex" | "latex" => ExportFormat::Tex,
            _ => return None,
        })
    }

    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::HexText | ExportFormat::Txt => "txt",
            ExportFormat::C => "c",
            ExportFormat::Java => "java",
            ExportFormat::CSharp => "cs",
            ExportFormat::Pascal => "pas",
            ExportFormat::Python => "py",
            ExportFormat::Html => "html",
            ExportFormat::Rtf => "rtf",
            ExportFormat::Tex => "tex",
        }
    }

    /// Dumps carry an offset and a text column; literals carry the bytes only.
    pub fn is_dump(self) -> bool {
        matches!(
            self,
            ExportFormat::Txt | ExportFormat::Html | ExportFormat::Rtf | ExportFormat::Tex
        )
    }
}

#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Bytes per line (F-18 holds on paper too).
    pub cols: usize,
    /// Charset of the dumps' text column (F-20).
    pub charset: Charset,
    /// Base of the dumps' offsets (F-19).
    pub base: OffsetBase,
    /// Starting display offset, added to every offset (F-19).
    pub offset_start: u64,
    /// Variable name in the code formats.
    pub var_name: String,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            cols: 16,
            charset: Charset::Ascii,
            base: OffsetBase::Hex,
            offset_start: 0,
            var_name: "data".into(),
        }
    }
}

/// F-30/F-31 — Cooperative export. The caller picks the destination: a file
/// (the report), or a `Vec<u8>` (the GUI's clipboard).
pub struct ExportJob {
    fmt: ExportFormat,
    opts: ExportOptions,
    range: Range<u64>,
    pos: u64,
    /// Width of the offset column, fixed by the end of the range.
    digits: usize,
    header_done: bool,
    finished: bool,
}

impl ExportJob {
    pub fn new(fmt: ExportFormat, opts: ExportOptions, range: Range<u64>, doc_len: u64) -> Self {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len).max(start);
        let opts = ExportOptions { cols: opts.cols.max(1), ..opts };
        let digits = opts.base.digits_for(end.saturating_add(opts.offset_start));
        Self { fmt, opts, range: start..end, pos: start, digits, header_done: false, finished: false }
    }

    pub fn total(&self) -> u64 {
        self.range.end - self.range.start
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Processes up to `budget` bytes (rounded to whole lines) and appends the
    /// generated text to `out`. An unreadable block is a fatal error.
    pub fn step(
        &mut self,
        doc: &mut Document,
        budget: u64,
        out: &mut impl Write,
    ) -> Result<StepResult> {
        if self.finished {
            return Ok(StepResult { finished: true, scanned: 0 });
        }
        if !self.header_done {
            out.write_all(self.header().as_bytes())?;
            self.header_done = true;
        }

        let mut scanned = 0u64;
        if self.pos < self.range.end {
            // Always whole lines: a step never cuts a line in half.
            let cols = self.opts.cols as u64;
            let want = budget.clamp(1, WINDOW);
            let want = (want - want % cols).max(cols);
            let n = want.min(self.range.end - self.pos);

            let read = doc.read(self.pos, n as usize);
            if !read.is_clean() {
                return Err(Error::new(
                    ErrorKind::BadBlock,
                    format!("unreadable block at {:#x}; export aborted", read.unreadable[0].start),
                ));
            }
            let text = if self.fmt.is_dump() {
                self.dump_chunk(self.pos, &read.data)
            } else {
                self.literal_chunk(self.pos, &read.data)
            };
            out.write_all(text.as_bytes())?;
            self.pos += n;
            scanned = n;
        }

        if self.pos >= self.range.end {
            out.write_all(self.footer().as_bytes())?;
            self.finished = true;
        }
        Ok(StepResult { finished: self.finished, scanned })
    }

    fn header(&self) -> String {
        let name = &self.opts.var_name;
        let len = self.total();
        match self.fmt {
            ExportFormat::HexText | ExportFormat::Txt => String::new(),
            ExportFormat::C => format!("unsigned char {name}[{len}] = {{"),
            ExportFormat::Java => format!("byte[] {name} = {{"),
            ExportFormat::CSharp => format!("byte[] {name} = new byte[{len}] {{"),
            ExportFormat::Pascal => {
                format!("const\n  {name}: array[0..{}] of Byte = (", len.saturating_sub(1))
            }
            ExportFormat::Python => format!("{name} = bytes(["),
            ExportFormat::Html => concat!(
                "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n",
                "<title>hexed</title>\n",
                "<style>pre { font-family: monospace; }</style>\n",
                "</head>\n<body>\n<pre>\n"
            )
            .into(),
            ExportFormat::Rtf => concat!(
                "{\\rtf1\\ansi\\deff0",
                "{\\fonttbl{\\f0\\fmodern Courier New;}}\n",
                "\\f0\\fs16\n"
            )
            .into(),
            ExportFormat::Tex => concat!(
                "\\documentclass{article}\n",
                "\\usepackage[T1]{fontenc}\n",
                "\\begin{document}\n",
                "\\begin{verbatim}\n"
            )
            .into(),
        }
    }

    fn footer(&self) -> String {
        match self.fmt {
            ExportFormat::HexText | ExportFormat::Txt => String::new(),
            ExportFormat::C | ExportFormat::Java | ExportFormat::CSharp => "\n};\n".into(),
            ExportFormat::Pascal => "\n  );\n".into(),
            ExportFormat::Python => "\n])\n".into(),
            ExportFormat::Html => "</pre>\n</body>\n</html>\n".into(),
            ExportFormat::Rtf => "}\n".into(),
            ExportFormat::Tex => "\\end{verbatim}\n\\end{document}\n".into(),
        }
    }

    /// Literals: separator and line break decided by the global index — there
    /// is never a dangling comma, even with the range cut into steps.
    fn literal_chunk(&self, chunk_start: u64, data: &[u8]) -> String {
        let cols = self.opts.cols;
        let mut s = String::with_capacity(data.len() * 8);
        for (k, b) in data.iter().enumerate() {
            let i = (chunk_start - self.range.start) as usize + k;
            match self.fmt {
                ExportFormat::HexText => {
                    if i > 0 {
                        s.push_str(if i.is_multiple_of(cols) { "\n" } else { " " });
                    }
                    s.push_str(&format!("{b:02X}"));
                }
                _ => {
                    if i > 0 {
                        s.push(',');
                    }
                    if i.is_multiple_of(cols) {
                        s.push_str("\n    ");
                    } else {
                        s.push(' ');
                    }
                    match self.fmt {
                        ExportFormat::C | ExportFormat::CSharp | ExportFormat::Python => {
                            s.push_str(&format!("0x{b:02X}"));
                        }
                        // Java has no unsigned byte: signed decimal compiles
                        // without a cast and without a warning.
                        ExportFormat::Java => s.push_str(&format!("{}", *b as i8)),
                        ExportFormat::Pascal => s.push_str(&format!("${b:02X}")),
                        _ => unreachable!("formato de dump em literal_chunk"),
                    }
                }
            }
        }
        // The last step closes the final line; the footer supplies the rest.
        if chunk_start + data.len() as u64 == self.range.end && self.fmt == ExportFormat::HexText {
            s.push('\n');
        }
        s
    }

    /// Dumps: one line per `cols` bytes — offset, hex column, text column.
    fn dump_chunk(&self, chunk_start: u64, data: &[u8]) -> String {
        let cols = self.opts.cols;
        // Decode the chunk in one go: multi-byte characters crossing a line
        // boundary stay correct (F-20).
        let cells = self.opts.charset.decode_cells(chunk_start, data);
        let mut s = String::with_capacity(data.len() * 5);

        for (row, chunk) in data.chunks(cols).enumerate() {
            let display_off = chunk_start
                .saturating_add((row * cols) as u64)
                .saturating_add(self.opts.offset_start);
            let mut line = String::with_capacity(cols * 4 + self.digits + 4);
            line.push_str(&self.opts.base.format(display_off, self.digits));
            line.push_str("  ");
            for i in 0..cols {
                match chunk.get(i) {
                    Some(b) => line.push_str(&format!("{b:02X} ")),
                    None => line.push_str("   "),
                }
            }
            line.push_str(" |");
            for (i, _) in chunk.iter().enumerate() {
                line.push(cells[row * cols + i]);
            }
            line.push('|');

            match self.fmt {
                ExportFormat::Txt | ExportFormat::Tex => {
                    s.push_str(&line);
                    s.push('\n');
                }
                ExportFormat::Html => {
                    s.push_str(&escape_html(&line));
                    s.push('\n');
                }
                ExportFormat::Rtf => {
                    s.push_str(&escape_rtf(&line));
                    s.push_str("\\par\n");
                }
                _ => unreachable!("formato literal em dump_chunk"),
            }
        }
        s
    }
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn escape_rtf(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            c if (c as u32) < 0x80 => out.push(c),
            // \uN? — N is a signed 16-bit value; '?' is the fallback for older
            // readers. Outside the BMP it would be a surrogate pair; the grid's
            // charsets (F-20) only produce BMP, so one character is enough.
            c => {
                for unit in c.encode_utf16(&mut [0u16; 2]) {
                    out.push_str(&format!("\\u{}?", *unit as i16));
                }
            }
        }
    }
    out
}

/// Blocking helper (CLI and tests): the GUI drives `ExportJob::step` per frame.
pub fn export(
    doc: &mut Document,
    range: Range<u64>,
    fmt: ExportFormat,
    opts: ExportOptions,
    w: &mut impl Write,
    progress: &Progress,
) -> Result<()> {
    let mut job = ExportJob::new(fmt, opts, range, doc.len());
    progress.set_total(job.total());
    while !job.is_finished() {
        if progress.is_cancelled() {
            return Err(Error::new(ErrorKind::Io, "cancelled"));
        }
        let st = job.step(doc, WINDOW, w)?;
        progress.add_done(st.scanned);
    }
    Ok(())
}

/// Exports into a `String` (clipboard, tests).
pub fn export_string(
    doc: &mut Document,
    range: Range<u64>,
    fmt: ExportFormat,
    opts: ExportOptions,
    progress: &Progress,
) -> Result<String> {
    let mut buf = Vec::new();
    export(doc, range, fmt, opts, &mut buf, progress)?;
    String::from_utf8(buf).map_err(|_| Error::new(ErrorKind::Io, "output is not UTF-8"))
}

#[cfg(test)]
mod tests {
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
}
