use std::io::Write;
use std::ops::Range;

use super::{ExportFormat, ExportOptions, WINDOW};
use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::search::StepResult;

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
                        _ => unreachable!("dump format in literal_chunk"),
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
                _ => unreachable!("literal format in dump_chunk"),
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
