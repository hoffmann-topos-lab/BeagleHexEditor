use std::io::Write;
use std::ops::Range;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::progress::Progress;
use crate::search::StepResult;

/// Data bytes per record on export (the classic value of both formats).
pub const DEFAULT_REC_LEN: usize = 16;

/// Data ceiling per record: the tighter limit of the two families (S3: 255 in
/// the count byte − 4 of address − 1 of checksum).
const MAX_REC_LEN: usize = 250;

/// Largest window per export step.
const WINDOW: u64 = 1 << 20;

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

// ---- import ----

fn parse_err(fmt: RecordFormat, line_no: usize, detail: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, format!("{}, line {line_no}: {detail}", fmt.name()))
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
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

/// F-27 — Intel HEX. Supported types: 00 (data), 01 (EOF), 02/04 (extended
/// address), 03/05 (entry address). Reading stops at the EOF record.
pub fn parse_ihex(text: &str) -> Result<Image> {
    let fmt = RecordFormat::IntelHex;
    let mut image = Image::default();
    // Base added to each data record's 16-bit address: record 02 (segment ×16)
    // or 04 (upper 16 bits).
    let mut base: u64 = 0;

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some(hex) = line.strip_prefix(':') else {
            return Err(parse_err(fmt, line_no, "record does not start with ':'"));
        };
        let bytes = hex_bytes(hex)
            .ok_or_else(|| parse_err(fmt, line_no, "invalid hexadecimal digits"))?;
        if bytes.len() < 5 {
            return Err(parse_err(fmt, line_no, "record too short"));
        }
        let len = bytes[0] as usize;
        if bytes.len() != len + 5 {
            return Err(parse_err(
                fmt,
                line_no,
                format!("declared length {len} does not match the record"),
            ));
        }
        let sum = bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        if sum != 0 {
            return Err(parse_err(fmt, line_no, "invalid checksum"));
        }
        let addr = u16::from_be_bytes([bytes[1], bytes[2]]) as u64;
        let rec_type = bytes[3];
        let data = &bytes[4..4 + len];
        match rec_type {
            0x00 => image.segments.push(Segment { addr: base + addr, data: data.to_vec() }),
            0x01 => {
                image.normalize()?;
                return Ok(image);
            }
            0x02 | 0x04 => {
                if len != 2 {
                    return Err(parse_err(fmt, line_no, "an address record requires 2 bytes"));
                }
                let v = u16::from_be_bytes([data[0], data[1]]) as u64;
                base = if rec_type == 0x02 { v << 4 } else { v << 16 };
            }
            0x03 | 0x05 => {
                if len != 4 {
                    return Err(parse_err(fmt, line_no, "an entry address requires 4 bytes"));
                }
                let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
                // 03 is the 8086's CS:IP; 05 is linear.
                image.entry =
                    Some(if rec_type == 0x03 { (v >> 16 << 4) + (v & 0xFFFF) } else { v });
            }
            t => return Err(parse_err(fmt, line_no, format!("record type {t:#04x}"))),
        }
    }
    Err(Error::new(ErrorKind::Io, "Intel HEX without an EOF record (:00000001FF)"))
}

/// F-27a — Motorola S-record. S0 (header), S1/S2/S3 (data), S5/S6 (count,
/// validated), S7/S8/S9 (terminator carrying the entry address).
pub fn parse_srec(text: &str) -> Result<Image> {
    let fmt = RecordFormat::Srec;
    let mut image = Image::default();
    let mut data_records: u64 = 0;
    let mut terminated = false;

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if terminated {
            return Err(parse_err(fmt, line_no, "record after the terminator"));
        }
        let rest = line
            .strip_prefix('S')
            .or_else(|| line.strip_prefix('s'))
            .ok_or_else(|| parse_err(fmt, line_no, "record does not start with 'S'"))?;
        let (t, hex) = rest.split_at(rest.len().min(1));
        let bytes =
            hex_bytes(hex).ok_or_else(|| parse_err(fmt, line_no, "invalid hexadecimal digits"))?;
        if bytes.len() < 3 {
            return Err(parse_err(fmt, line_no, "record too short"));
        }
        let count = bytes[0] as usize;
        if bytes.len() != count + 1 {
            return Err(parse_err(
                fmt,
                line_no,
                format!("declared count {count} does not match the record"),
            ));
        }
        // Checksum: one's complement of the sum of count + address + data.
        let sum = bytes[..bytes.len() - 1].iter().fold(0u8, |a, b| a.wrapping_add(*b));
        if !sum != bytes[bytes.len() - 1] {
            return Err(parse_err(fmt, line_no, "invalid checksum"));
        }
        let addr_len = match t {
            "0" | "1" | "5" | "9" => 2,
            "2" | "6" | "8" => 3,
            "3" | "7" => 4,
            t => return Err(parse_err(fmt, line_no, format!("record type S{t}"))),
        };
        if count < addr_len + 1 {
            return Err(parse_err(fmt, line_no, "record shorter than its address"));
        }
        let addr = bytes[1..1 + addr_len].iter().fold(0u64, |a, b| (a << 8) | *b as u64);
        let data = &bytes[1 + addr_len..bytes.len() - 1];
        match t {
            "0" => {} // header: only the checksum matters
            "1" | "2" | "3" => {
                image.segments.push(Segment { addr, data: data.to_vec() });
                data_records += 1;
            }
            "5" | "6" => {
                if addr != data_records {
                    return Err(parse_err(
                        fmt,
                        line_no,
                        format!("count {addr} differs from the {data_records} data records"),
                    ));
                }
            }
            "7" | "8" | "9" => {
                image.entry = Some(addr);
                terminated = true;
            }
            _ => unreachable!(),
        }
    }
    if !terminated {
        return Err(Error::new(ErrorKind::Io, "S-record without a terminator record (S7/S8/S9)"));
    }
    image.normalize()?;
    Ok(image)
}

// ---- export ----

fn ihex_record(rec_type: u8, addr: u16, data: &[u8]) -> String {
    let mut sum = (data.len() as u8)
        .wrapping_add((addr >> 8) as u8)
        .wrapping_add(addr as u8)
        .wrapping_add(rec_type);
    let mut s = format!(":{:02X}{addr:04X}{rec_type:02X}", data.len());
    for b in data {
        s.push_str(&format!("{b:02X}"));
        sum = sum.wrapping_add(*b);
    }
    s.push_str(&format!("{:02X}\n", sum.wrapping_neg()));
    s
}

fn srec_record(t: u8, addr_len: usize, addr: u64, data: &[u8]) -> String {
    let count = (addr_len + data.len() + 1) as u8;
    let mut sum = count;
    let mut s = format!("S{t}{count:02X}");
    for i in (0..addr_len).rev() {
        let b = (addr >> (8 * i)) as u8;
        s.push_str(&format!("{b:02X}"));
        sum = sum.wrapping_add(b);
    }
    for b in data {
        s.push_str(&format!("{b:02X}"));
        sum = sum.wrapping_add(*b);
    }
    s.push_str(&format!("{:02X}\n", !sum));
    s
}

/// F-27/F-27a — Cooperative export of a document range, with the bytes
/// addressed from `base` onwards.
pub struct RecordExportJob {
    fmt: RecordFormat,
    range: Range<u64>,
    base: u64,
    rec_len: usize,
    pos: u64,
    /// Intel HEX: the current upper 16 bits (record type 04). Starts at 0 —
    /// files that fit in 64 KiB get no address record at all.
    linear_base: u16,
    /// S-record: the data record type (1/2/3) and the count for the S5/S6.
    srec_type: u8,
    data_records: u64,
    header_done: bool,
    finished: bool,
}

impl RecordExportJob {
    pub fn new(
        fmt: RecordFormat,
        range: Range<u64>,
        base: u64,
        rec_len: usize,
        doc_len: u64,
    ) -> Result<Self> {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len).max(start);
        let end_addr = base
            .checked_add(end - start)
            .filter(|e| *e <= ADDR_LIMIT)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::OutOfBounds,
                    format!("{} addresses at most 32 bits", fmt.name()),
                )
            })?;
        // S1/S2/S3 according to the largest address actually used.
        let srec_type = match end_addr.saturating_sub(1) {
            a if a < 1 << 16 => 1,
            a if a < 1 << 24 => 2,
            _ => 3,
        };
        Ok(Self {
            fmt,
            range: start..end,
            base,
            rec_len: rec_len.clamp(1, MAX_REC_LEN),
            pos: start,
            linear_base: 0,
            srec_type,
            data_records: 0,
            header_done: false,
            finished: false,
        })
    }

    pub fn total(&self) -> u64 {
        self.range.end - self.range.start
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Processes up to `budget` bytes and appends the records to `out`. An
    /// unreadable block is a fatal error.
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
            if self.fmt == RecordFormat::Srec {
                out.write_all(srec_record(0, 2, 0, b"hexed").as_bytes())?;
            }
            self.header_done = true;
        }

        let mut scanned = 0u64;
        if self.pos < self.range.end {
            let rec = self.rec_len as u64;
            let want = budget.clamp(1, WINDOW);
            let want = (want - want % rec).max(rec);
            let n = want.min(self.range.end - self.pos);

            let read = doc.read(self.pos, n as usize);
            if !read.is_clean() {
                return Err(Error::new(
                    ErrorKind::BadBlock,
                    format!(
                        "unreadable block at {:#x}; export aborted",
                        read.unreadable[0].start
                    ),
                ));
            }

            let mut text = String::with_capacity(read.data.len() * 3);
            let mut off = 0usize;
            while off < read.data.len() {
                let addr = self.base + (self.pos + off as u64 - self.range.start);
                let mut take = self.rec_len.min(read.data.len() - off);
                if self.fmt == RecordFormat::IntelHex {
                    // Never cross the 64 KiB boundary: that is where the
                    // extended address record changes.
                    take = take.min((0x10000 - (addr & 0xFFFF)) as usize);
                    let upper = (addr >> 16) as u16;
                    if self.linear_base != upper {
                        text.push_str(&ihex_record(0x04, 0, &upper.to_be_bytes()));
                        self.linear_base = upper;
                    }
                    text.push_str(&ihex_record(0x00, addr as u16, &read.data[off..off + take]));
                } else {
                    let addr_len = 1 + self.srec_type as usize;
                    text.push_str(&srec_record(
                        self.srec_type,
                        addr_len,
                        addr,
                        &read.data[off..off + take],
                    ));
                    self.data_records += 1;
                }
                off += take;
            }
            out.write_all(text.as_bytes())?;
            self.pos += n;
            scanned = n;
        }

        if self.pos >= self.range.end {
            match self.fmt {
                RecordFormat::IntelHex => out.write_all(b":00000001FF\n")?,
                RecordFormat::Srec => {
                    // Count (S5/S6, optional above 24 bits) and the terminator
                    // paired with the data type, pointing at the start.
                    if self.data_records < 1 << 16 {
                        out.write_all(srec_record(5, 2, self.data_records, &[]).as_bytes())?;
                    } else if self.data_records < 1 << 24 {
                        out.write_all(srec_record(6, 3, self.data_records, &[]).as_bytes())?;
                    }
                    let (t, addr_len) = match self.srec_type {
                        1 => (9, 2),
                        2 => (8, 3),
                        _ => (7, 4),
                    };
                    out.write_all(srec_record(t, addr_len, self.base, &[]).as_bytes())?;
                }
            }
            self.finished = true;
        }
        Ok(StepResult { finished: self.finished, scanned })
    }
}

/// Blocking helper (CLI and tests): the GUI drives `RecordExportJob::step`.
pub fn write_records(
    doc: &mut Document,
    range: Range<u64>,
    fmt: RecordFormat,
    base: u64,
    rec_len: usize,
    w: &mut impl Write,
    progress: &Progress,
) -> Result<()> {
    let mut job = RecordExportJob::new(fmt, range, base, rec_len, doc.len())?;
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
