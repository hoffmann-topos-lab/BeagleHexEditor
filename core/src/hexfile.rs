//! F-27/F-27a — Intel HEX and Motorola S-record. Shared types and format
//! detection live here; the parsers in `import`, the generators in `export`.

mod export;
mod import;
#[cfg(test)]
mod tests;

use std::io::Write;
use std::ops::Range;

use crate::error::{Error, ErrorKind, Result};

pub use export::{RecordExportJob, write_records};
pub use import::{parse_ihex, parse_srec};

/// Data bytes per record on export (the classic value of both formats).
pub const DEFAULT_REC_LEN: usize = 16;

/// End of the address space of both format families.
const ADDR_LIMIT: u64 = 1 << 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordFormat {
    IntelHex,
    Srec,
}

impl RecordFormat {
    pub fn name(self) -> &'static str {
        match self {
            RecordFormat::IntelHex => "Intel HEX",
            RecordFormat::Srec => "Motorola S-record",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            RecordFormat::IntelHex => "hex",
            RecordFormat::Srec => "srec",
        }
    }
}

/// A contiguous span of addressed data, as it came from the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub addr: u64,
    pub data: Vec<u8>,
}

/// Result of an import: sorted, merged segments plus the entry address
/// (Intel HEX records 03/05; S-record S7/S8/S9).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Image {
    pub segments: Vec<Segment>,
    pub entry: Option<u64>,
}

impl Image {
    /// Address range covered: from the first byte to the end of the last.
    pub fn span(&self) -> Option<Range<u64>> {
        let first = self.segments.first()?;
        let last = self.segments.last()?;
        Some(first.addr..last.addr + last.data.len() as u64)
    }

    /// Total data bytes (gaps not counted).
    pub fn data_len(&self) -> u64 {
        self.segments.iter().map(|s| s.data.len() as u64).sum()
    }

    /// Sorts, merges contiguous segments and refuses overlap — two records
    /// writing to the same address means a corrupt file.
    fn normalize(&mut self) -> Result<()> {
        self.segments.retain(|s| !s.data.is_empty());
        self.segments.sort_by_key(|s| s.addr);
        let mut merged: Vec<Segment> = Vec::with_capacity(self.segments.len());
        for seg in self.segments.drain(..) {
            match merged.last_mut() {
                Some(prev) => {
                    let prev_end = prev.addr + prev.data.len() as u64;
                    if seg.addr < prev_end {
                        return Err(Error::new(
                            ErrorKind::Io,
                            format!("overlapping segments at address {:#x}", seg.addr),
                        ));
                    }
                    if seg.addr == prev_end {
                        prev.data.extend_from_slice(&seg.data);
                    } else {
                        merged.push(seg);
                    }
                }
                None => merged.push(seg),
            }
        }
        self.segments = merged;
        Ok(())
    }

    /// Flattens the image into a contiguous binary starting at the lowest
    /// address, filling gaps with `fill`. Returns `(base address, bytes)`.
    /// For small images only — the caller must check `span()` first; to write
    /// straight to a file use `write_flattened`.
    pub fn flatten(&self, fill: u8) -> Result<(u64, Vec<u8>)> {
        let base = self.span().map(|s| s.start).unwrap_or(0);
        let mut out = Vec::new();
        write_flattened(self, fill, &mut out)?;
        Ok((base, out))
    }
}

/// Writes the flattened image (gaps become `fill`, in chunks — the gap is never
/// materialized). Returns the total bytes written.
pub fn write_flattened(image: &Image, fill: u8, w: &mut impl Write) -> Result<u64> {
    let Some(span) = image.span() else { return Ok(0) };
    let fill_chunk = vec![fill; 64 * 1024];
    let mut cursor = span.start;
    for seg in &image.segments {
        let mut gap = seg.addr - cursor;
        while gap > 0 {
            let n = gap.min(fill_chunk.len() as u64) as usize;
            w.write_all(&fill_chunk[..n])?;
            gap -= n as u64;
        }
        w.write_all(&seg.data)?;
        cursor = seg.addr + seg.data.len() as u64;
    }
    Ok(span.end - span.start)
}

/// Detects the format from the first non-empty line and imports it.
pub fn parse(text: &str) -> Result<(RecordFormat, Image)> {
    match text.lines().map(str::trim).find(|l| !l.is_empty()) {
        Some(l) if l.starts_with(':') => Ok((RecordFormat::IntelHex, parse_ihex(text)?)),
        Some(l) if l.starts_with('S') || l.starts_with('s') => {
            Ok((RecordFormat::Srec, parse_srec(text)?))
        }
        Some(_) => Err(Error::new(
            ErrorKind::Io,
            "looks like neither Intel HEX (':' lines) nor S-record ('S' lines)",
        )),
        None => Err(Error::new(ErrorKind::Io, "empty file")),
    }
}
