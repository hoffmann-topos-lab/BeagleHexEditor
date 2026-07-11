use std::ops::Range;

use crate::charset::is_printable;
use crate::document::Document;
use crate::progress::Progress;
use crate::search::StepResult;

/// Window per step.
const WINDOW: u64 = 4 << 20;
/// The displayed text is truncated at this length (the real one is reported).
const TEXT_CAP: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrEncoding {
    /// ASCII is the 1-byte subset; there is no reason to separate them.
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl StrEncoding {
    pub const ALL: [StrEncoding; 3] =
        [StrEncoding::Utf8, StrEncoding::Utf16Le, StrEncoding::Utf16Be];

    pub fn name(self) -> &'static str {
        match self {
            StrEncoding::Utf8 => "UTF-8",
            StrEncoding::Utf16Le => "UTF-16LE",
            StrEncoding::Utf16Be => "UTF-16BE",
        }
    }

    pub fn from_name(s: &str) -> Option<StrEncoding> {
        let k: String =
            s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
        Some(match k.as_str() {
            "utf8" | "ascii" => StrEncoding::Utf8,
            "utf16le" | "utf16" => StrEncoding::Utf16Le,
            "utf16be" => StrEncoding::Utf16Be,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FoundString {
    pub offset: u64,
    /// Real length in bytes (the displayed text may be truncated).
    pub len: u64,
    pub chars: usize,
    pub encoding: StrEncoding,
    pub text: String,
}

enum Kind {
    Utf8 {
        /// Incomplete multi-byte sequence crossing the window.
        pend: [u8; 4],
        pend_len: usize,
        expect: usize,
        pend_start: u64,
    },
    Utf16 {
        big: bool,
        /// First byte of a unit cut short (by the window or by the phase).
        pending: Option<(u64, u8)>,
    },
}

/// The run under construction — kept apart from the decoder's state so that
/// both can be mutably borrowed at the same time.
struct Run {
    encoding: StrEncoding,
    start: Option<u64>,
    chars: usize,
    bytes: u64,
    text: String,
}

impl Run {
    fn new(encoding: StrEncoding) -> Self {
        Self { encoding, start: None, chars: 0, bytes: 0, text: String::new() }
    }

    fn extend(&mut self, start: u64, nbytes: u64, c: char) {
        self.start.get_or_insert(start);
        self.chars += 1;
        self.bytes += nbytes;
        if self.chars <= TEXT_CAP {
            self.text.push(c);
        }
    }

    fn flush(&mut self, min_chars: usize, out: &mut Vec<FoundString>) {
        if let Some(offset) = self.start.take()
            && self.chars >= min_chars
        {
            let mut text = std::mem::take(&mut self.text);
            if self.chars > TEXT_CAP {
                text.push('…');
            }
            out.push(FoundString {
                offset,
                len: self.bytes,
                chars: self.chars,
                encoding: self.encoding,
                text,
            });
        }
        self.text.clear();
        self.chars = 0;
        self.bytes = 0;
    }
}

struct Scanner {
    kind: Kind,
    run: Run,
}

impl Scanner {
    fn utf8() -> Self {
        Self {
            kind: Kind::Utf8 { pend: [0; 4], pend_len: 0, expect: 0, pend_start: 0 },
            run: Run::new(StrEncoding::Utf8),
        }
    }

    fn utf16(encoding: StrEncoding, skip_first: bool) -> Self {
        Self {
            kind: Kind::Utf16 {
                big: encoding == StrEncoding::Utf16Be,
                // The odd phase starts "mid-way" through a fictitious unit.
                pending: skip_first.then_some((0, 0)),
            },
            run: Run::new(encoding),
        }
    }

    fn feed(&mut self, base: u64, data: &[u8], min_chars: usize, out: &mut Vec<FoundString>) {
        let run = &mut self.run;
        match &mut self.kind {
            Kind::Utf8 { pend, pend_len, expect, pend_start } => {
                let mut i = 0;
                while i < data.len() {
                    let o = base + i as u64;
                    let b = data[i];
                    if *pend_len == 0 {
                        if (0x20..0x7F).contains(&b) {
                            run.extend(o, 1, b as char);
                        } else if let Some(n @ 2..=4) = utf8_len(b) {
                            pend[0] = b;
                            *pend_len = 1;
                            *expect = n;
                            *pend_start = o;
                        } else {
                            run.flush(min_chars, out);
                        }
                        i += 1;
                    } else if (0x80..0xC0).contains(&b) {
                        pend[*pend_len] = b;
                        *pend_len += 1;
                        i += 1;
                        if pend_len == expect {
                            let decoded = std::str::from_utf8(&pend[..*expect])
                                .ok()
                                .and_then(|s| s.chars().next())
                                .filter(|c| is_printable(*c));
                            match decoded {
                                Some(c) => run.extend(*pend_start, *expect as u64, c),
                                None => run.flush(min_chars, out),
                            }
                            *pend_len = 0;
                        }
                    } else {
                        // Broken continuation: end the run and reprocess `b`.
                        *pend_len = 0;
                        run.flush(min_chars, out);
                    }
                }
            }
            Kind::Utf16 { big, pending } => {
                for (i, b) in data.iter().enumerate() {
                    let o = base + i as u64;
                    match pending.take() {
                        None => *pending = Some((o, *b)),
                        Some((first_o, first_b)) => {
                            let unit = if *big {
                                (first_b as u16) << 8 | *b as u16
                            } else {
                                (*b as u16) << 8 | first_b as u16
                            };
                            // Printable Latin-1 only: filters out binary noise.
                            let c = char::from_u32(unit as u32)
                                .filter(|c| unit <= 0xFF && is_printable(*c));
                            match c {
                                Some(c) => run.extend(first_o, 2, c),
                                None => run.flush(min_chars, out),
                            }
                        }
                    }
                }
            }
        }
    }
}

fn utf8_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

/// F-24 — Cooperative extraction (one window per `step`, like search).
pub struct StringsJob {
    scanners: Vec<Scanner>,
    min_chars: usize,
    range: Range<u64>,
    pos: u64,
}

impl StringsJob {
    pub fn new(
        encodings: &[StrEncoding],
        min_chars: usize,
        range: Range<u64>,
        doc_len: u64,
    ) -> Self {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len);
        let mut scanners = Vec::new();
        for e in encodings {
            match e {
                StrEncoding::Utf8 => scanners.push(Scanner::utf8()),
                enc => {
                    // Two alignment phases per endianness.
                    scanners.push(Scanner::utf16(*enc, false));
                    scanners.push(Scanner::utf16(*enc, true));
                }
            }
        }
        Self { scanners, min_chars: min_chars.max(1), range: start..end, pos: start }
    }

    pub fn total(&self) -> u64 {
        self.range.end - self.range.start
    }

    pub fn step(&mut self, doc: &mut Document, budget: u64, out: &mut Vec<FoundString>) -> StepResult {
        if self.pos >= self.range.end {
            return StepResult { finished: true, scanned: 0 };
        }
        let n = (self.range.end - self.pos).min(budget.clamp(1, WINDOW));
        let read = doc.read(self.pos, n as usize);
        for s in &mut self.scanners {
            s.feed(self.pos, &read.data, self.min_chars, out);
        }
        self.pos += n;
        let finished = self.pos >= self.range.end;
        if finished {
            for s in &mut self.scanners {
                s.run.flush(self.min_chars, out); // runs abertos no fim do intervalo
            }
        }
        StepResult { finished, scanned: n }
    }
}

/// Blocking helper: extracts, sorts by offset and truncates at `limit`.
pub fn extract(
    doc: &mut Document,
    encodings: &[StrEncoding],
    min_chars: usize,
    range: Range<u64>,
    limit: usize,
    progress: &Progress,
) -> (Vec<FoundString>, bool) {
    let mut job = StringsJob::new(encodings, min_chars, range, doc.len());
    progress.set_total(job.total());
    let mut out = Vec::new();
    loop {
        let st = job.step(doc, WINDOW, &mut out);
        progress.add_done(st.scanned);
        if st.finished || progress.is_cancelled() || out.len() > limit.saturating_mul(2) {
            break;
        }
    }
    out.sort_by_key(|s| s.offset);
    let truncated = out.len() > limit;
    out.truncate(limit);
    (out, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    fn doc(bytes: &[u8]) -> Document {
        Document::new(Box::new(MemSource::new(bytes.to_vec())))
    }

    fn extract_all(data: &[u8], min: usize) -> Vec<FoundString> {
        let mut d = doc(data);
        let len = d.len();
        extract(&mut d, &StrEncoding::ALL, min, 0..len, 1000, &Progress::new()).0
    }

    #[test]
    fn ascii_with_a_minimum_length() {
        let found = extract_all(b"\x01hi\x02hello\x03worlds\x04", 4);
        let texts: Vec<&str> = found.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, vec!["hello", "worlds"], "hi has 2 < 4 chars");
        assert_eq!(found[0].offset, 4);
        assert_eq!(found[0].len, 5);
    }

    #[test]
    fn multibyte_utf8_counts_characters_not_bytes() {
        // "café!" = 6 bytes, 5 chars.
        let mut data = vec![0u8; 3];
        data.extend_from_slice("café!".as_bytes());
        data.push(0);
        let found = extract_all(&data, 5);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "café!");
        assert_eq!(found[0].chars, 5);
        assert_eq!(found[0].len, 6);
        assert_eq!(found[0].offset, 3);
    }

    #[test]
    fn utf16le_and_be_at_any_alignment() {
        // "hello" in UTF-16LE at an odd offset.
        let mut data = vec![0xFFu8];
        for c in "hello".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.push(0xFF);
        let found = extract_all(&data, 4);
        let hit = found.iter().find(|s| s.encoding == StrEncoding::Utf16Le).unwrap();
        assert_eq!(hit.text, "hello");
        assert_eq!(hit.offset, 1);
        assert_eq!(hit.len, 10);

        let mut data = Vec::new();
        for c in "WORLD".encode_utf16() {
            data.extend_from_slice(&c.to_be_bytes());
        }
        let found = extract_all(&data, 4);
        let hit = found.iter().find(|s| s.encoding == StrEncoding::Utf16Be).unwrap();
        assert_eq!(hit.text, "WORLD");
        assert_eq!(hit.offset, 0);
    }

    #[test]
    fn a_string_crosses_a_window_boundary() {
        let mut data = vec![0u8; 100];
        data.extend_from_slice(b"boundary");
        data.extend(vec![0u8; 100]);
        let mut d = doc(&data);
        let mut job = StringsJob::new(&[StrEncoding::Utf8], 4, 0..d.len(), d.len());
        let mut out = Vec::new();
        // 16-byte windows: the string crosses several boundaries.
        while !job.step(&mut d, 16, &mut out).finished {}
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].text, "boundary");
        assert_eq!(out[0].offset, 100);
    }

    #[test]
    fn a_run_still_open_at_the_end_of_the_document_is_emitted() {
        let found = extract_all(b"\x00\x00tail", 4);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "tail");
    }

    #[test]
    fn utf16_does_not_find_cjk_in_noise() {
        // Random "CJK" bytes: units > 0xFF do not count.
        let data: Vec<u8> = (0..64).map(|i| (0x4E + i % 32) as u8).collect();
        let found = extract_all(&data, 4);
        assert!(
            found.iter().all(|s| s.encoding == StrEncoding::Utf8),
            "UTF-16 restricted to Latin-1: {found:?}"
        );
    }

    #[test]
    fn long_text_is_truncated_but_the_length_is_real() {
        let data: Vec<u8> = std::iter::repeat_n(b'a', 500).collect();
        let found = extract_all(&data, 4);
        let hit = found.iter().find(|s| s.encoding == StrEncoding::Utf8).unwrap();
        assert_eq!(hit.chars, 500);
        assert_eq!(hit.len, 500);
        assert!(hit.text.ends_with('…'));
        assert_eq!(hit.text.chars().count(), TEXT_CAP + 1);
    }
}
