//! F-27/F-27a export — record generators and the cooperative export job.

use std::io::Write;
use std::ops::Range;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::job::{self, RangeCursor, StepResult};
use crate::progress::Progress;

use super::{ADDR_LIMIT, RecordFormat};

/// Data ceiling per record: the tighter limit of the two families (S3: 255 in
/// the count byte − 4 of address − 1 of checksum).
const MAX_REC_LEN: usize = 250;

/// Largest window per export step: each byte becomes ~2.5 characters of text.
const WINDOW: u64 = 1 << 20;

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
    cursor: RangeCursor,
    base: u64,
    rec_len: usize,
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
        let cursor = RangeCursor::new(range, doc_len).with_window(WINDOW);
        let end_addr = base
            .checked_add(cursor.total())
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
            cursor,
            base,
            rec_len: rec_len.clamp(1, MAX_REC_LEN),
            linear_base: 0,
            srec_type,
            data_records: 0,
            header_done: false,
            finished: false,
        })
    }

    pub fn total(&self) -> u64 {
        self.cursor.total()
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
            return Ok(StepResult::DONE);
        }
        if !self.header_done {
            if self.fmt == RecordFormat::Srec {
                out.write_all(srec_record(0, 2, 0, b"hexed").as_bytes())?;
            }
            self.header_done = true;
        }

        let mut scanned = 0u64;
        if !self.cursor.is_done() {
            let pos = self.cursor.pos();
            let n = self.cursor.next_len(budget, self.rec_len as u64);
            let data = job::read_clean(doc, pos, n, "export")?;

            let mut text = String::with_capacity(data.len() * 3);
            let mut off = 0usize;
            while off < data.len() {
                let addr = self.base + (pos + off as u64 - self.cursor.start());
                let mut take = self.rec_len.min(data.len() - off);
                if self.fmt == RecordFormat::IntelHex {
                    // Never cross the 64 KiB boundary: that is where the
                    // extended address record changes.
                    take = take.min((0x10000 - (addr & 0xFFFF)) as usize);
                    let upper = (addr >> 16) as u16;
                    if self.linear_base != upper {
                        text.push_str(&ihex_record(0x04, 0, &upper.to_be_bytes()));
                        self.linear_base = upper;
                    }
                    text.push_str(&ihex_record(0x00, addr as u16, &data[off..off + take]));
                } else {
                    let addr_len = 1 + self.srec_type as usize;
                    text.push_str(&srec_record(
                        self.srec_type,
                        addr_len,
                        addr,
                        &data[off..off + take],
                    ));
                    self.data_records += 1;
                }
                off += take;
            }
            out.write_all(text.as_bytes())?;
            self.cursor.advance(n);
            scanned = n;
        }

        if self.cursor.is_done() {
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
    job::run(progress, job.total(), |budget| job.step(doc, budget, w))
}
