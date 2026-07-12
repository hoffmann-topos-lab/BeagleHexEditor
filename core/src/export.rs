//! F-30/F-31 — Copy-as / report export. Formats and options live here; the
//! cooperative worker is in `job`.

mod job;
#[cfg(test)]
mod tests;

use std::io::Write;
use std::ops::Range;

use crate::charset::Charset;
use crate::display::OffsetBase;
use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::progress::Progress;

pub use job::ExportJob;

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
