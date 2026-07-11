use std::ops::Range;
use std::sync::OnceLock;

use crate::document::Document;
use crate::progress::Progress;
use crate::search::StepResult;

/// Window per step.
const WINDOW: u64 = 4 << 20;

#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    pub name: &'static str,
    pub extension: &'static str,
    /// Fixed offset where the magic lives (for `identify`).
    pub offset: u64,
    pub magic: &'static [u8],
    /// Extra check relative to the start of the file (RIFF needs it to tell
    /// WAV, AVI and WEBP apart).
    pub also: Option<(u64, &'static [u8])>,
}

/// Table of known signatures. Source: widely published values (file(1),
/// Wikipedia "List of file signatures").
pub const SIGNATURES: &[Signature] = &[
    sig("PNG", "png", 0, &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
    sig("JPEG", "jpg", 0, &[0xFF, 0xD8, 0xFF]),
    sig("GIF (87a)", "gif", 0, b"GIF87a"),
    sig("GIF (89a)", "gif", 0, b"GIF89a"),
    sig("PDF", "pdf", 0, b"%PDF-"),
    sig("ZIP (and docx/xlsx/jar/apk)", "zip", 0, &[b'P', b'K', 0x03, 0x04]),
    sig("RAR", "rar", 0, &[b'R', b'a', b'r', b'!', 0x1A, 0x07]),
    sig("7-Zip", "7z", 0, &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]),
    sig("gzip", "gz", 0, &[0x1F, 0x8B, 0x08]),
    sig("bzip2", "bz2", 0, b"BZh"),
    sig("XZ", "xz", 0, &[0xFD, b'7', b'z', b'X', b'Z', 0x00]),
    sig("Zstandard", "zst", 0, &[0x28, 0xB5, 0x2F, 0xFD]),
    sig("LZ4", "lz4", 0, &[0x04, 0x22, 0x4D, 0x18]),
    sig("tar (ustar)", "tar", 257, b"ustar"),
    sig("ELF", "elf", 0, &[0x7F, b'E', b'L', b'F']),
    sig("Mach-O 64-bit", "macho", 0, &[0xCF, 0xFA, 0xED, 0xFE]),
    sig("Mach-O 32-bit", "macho", 0, &[0xCE, 0xFA, 0xED, 0xFE]),
    sig("Mach-O universal / Java class", "", 0, &[0xCA, 0xFE, 0xBA, 0xBE]),
    sig("DOS/Windows executable (MZ)", "exe", 0, b"MZ"),
    sig("WebAssembly", "wasm", 0, &[0x00, b'a', b's', b'm']),
    sig("SQLite 3", "sqlite", 0, b"SQLite format 3\0"),
    sig("MP3 (ID3)", "mp3", 0, b"ID3"),
    sig("MP4/MOV (ftyp)", "mp4", 4, b"ftyp"),
    sig("Ogg", "ogg", 0, b"OggS"),
    sig("FLAC", "flac", 0, b"fLaC"),
    sig("MIDI", "mid", 0, b"MThd"),
    sig_also("WAV", "wav", 0, b"RIFF", (8, b"WAVE")),
    sig_also("AVI", "avi", 0, b"RIFF", (8, b"AVI ")),
    sig_also("WebP", "webp", 0, b"RIFF", (8, b"WEBP")),
    sig("Bitmap (BM)", "bmp", 0, b"BM"),
    sig("TIFF (little-endian)", "tif", 0, &[b'I', b'I', 0x2A, 0x00]),
    sig("TIFF (big-endian)", "tif", 0, &[b'M', b'M', 0x00, 0x2A]),
    sig("Photoshop", "psd", 0, b"8BPS"),
    sig("ISO 9660", "iso", 0x8001, b"CD001"),
    sig("Binary property list", "plist", 0, b"bplist00"),
    sig("LUKS", "", 0, &[b'L', b'U', b'K', b'S', 0xBA, 0xBE]),
    sig("GPT", "", 0x200, b"EFI PART"),
    sig("DICOM", "dcm", 0x80, b"DICM"),
    sig("pcap", "pcap", 0, &[0xD4, 0xC3, 0xB2, 0xA1]),
    sig("pcapng", "pcapng", 0, &[0x0A, 0x0D, 0x0D, 0x0A]),
    sig("Dalvik (dex)", "dex", 0, b"dex\n"),
    sig("SquashFS", "squashfs", 0, b"hsqs"),
];

const fn sig(
    name: &'static str,
    extension: &'static str,
    offset: u64,
    magic: &'static [u8],
) -> Signature {
    Signature { name, extension, offset, magic, also: None }
}

const fn sig_also(
    name: &'static str,
    extension: &'static str,
    offset: u64,
    magic: &'static [u8],
    also: (u64, &'static [u8]),
) -> Signature {
    Signature { name, extension, offset, magic, also: Some(also) }
}

impl Signature {
    /// How many bytes from the start of the magic the full check covers.
    fn span(&self) -> u64 {
        let base = self.magic.len() as u64;
        match self.also {
            // `also` is relative to the start of the file; the magic lives at a
            // fixed offset, so in the sweep the span is relative to the magic.
            Some((off, extra)) => base.max(off - self.offset + extra.len() as u64),
            None => base,
        }
    }

    /// Does the signature match `hay` positioned as if `hay[0]` were byte
    /// `self.offset` of the file?
    fn matches(&self, hay: &[u8]) -> bool {
        if hay.len() < self.magic.len() || &hay[..self.magic.len()] != self.magic {
            return false;
        }
        match self.also {
            Some((off, extra)) => {
                let rel = (off - self.offset) as usize;
                hay.len() >= rel + extra.len() && &hay[rel..rel + extra.len()] == extra
            }
            None => true,
        }
    }
}

/// F-33 — Identifies the document's type by the magics at fixed offsets.
pub fn identify(doc: &mut Document) -> Vec<&'static Signature> {
    let mut out = Vec::new();
    for s in SIGNATURES {
        let span = s.span() as usize;
        if s.offset >= doc.len() {
            continue;
        }
        let read = doc.read(s.offset, span);
        if read.is_clean() && s.matches(&read.data) {
            out.push(s);
        }
    }
    out
}

/// Bucket by the magic's first byte: only the "sweepable" signatures (3+ bytes).
fn buckets() -> &'static [Vec<&'static Signature>; 256] {
    static BUCKETS: OnceLock<[Vec<&'static Signature>; 256]> = OnceLock::new();
    BUCKETS.get_or_init(|| {
        let mut b: [Vec<&'static Signature>; 256] = std::array::from_fn(|_| Vec::new());
        for s in SIGNATURES {
            if s.magic.len() >= 3 {
                b[s.magic[0] as usize].push(s);
            }
        }
        b
    })
}

/// Sweep for embedded signatures (carving), cooperative.
pub struct MagicScanJob {
    range: Range<u64>,
    pos: u64,
    max_span: u64,
}

impl MagicScanJob {
    pub fn new(range: Range<u64>, doc_len: u64) -> Self {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len);
        let max_span = SIGNATURES.iter().map(|s| s.span()).max().unwrap_or(1);
        Self { range: start..end, pos: start, max_span }
    }

    pub fn total(&self) -> u64 {
        self.range.end - self.range.start
    }

    pub fn step(
        &mut self,
        doc: &mut Document,
        budget: u64,
        out: &mut Vec<(u64, &'static Signature)>,
    ) -> StepResult {
        if self.pos >= self.range.end {
            return StepResult { finished: true, scanned: 0 };
        }
        let n = (self.range.end - self.pos).min(budget.clamp(1, WINDOW));
        // Overlap: a header may start at the very end of the window.
        let read_len = (n + self.max_span - 1).min(self.range.end - self.pos);
        let read = doc.read(self.pos, read_len as usize);
        let buckets = buckets();

        for i in 0..n as usize {
            let hay = &read.data[i..];
            for s in &buckets[hay[0] as usize] {
                if s.matches(hay) {
                    let at = self.pos + i as u64;
                    // F-06: a header over an unreadable block is not a header.
                    let span = s.span();
                    let bad =
                        read.unreadable.iter().any(|u| u.start < at + span && at < u.end);
                    if !bad {
                        out.push((at, s));
                    }
                }
            }
        }
        self.pos += n;
        StepResult { finished: self.pos >= self.range.end, scanned: n }
    }
}

/// Blocking helper (CLI): sweeps and returns up to `limit` hits.
pub fn scan(
    doc: &mut Document,
    range: Range<u64>,
    limit: usize,
    progress: &Progress,
) -> (Vec<(u64, &'static Signature)>, bool) {
    let mut job = MagicScanJob::new(range, doc.len());
    progress.set_total(job.total());
    let mut out = Vec::new();
    loop {
        let st = job.step(doc, WINDOW, &mut out);
        progress.add_done(st.scanned);
        if out.len() >= limit {
            out.truncate(limit);
            return (out, true);
        }
        if st.finished || progress.is_cancelled() {
            return (out, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    fn doc(bytes: &[u8]) -> Document {
        Document::new(Box::new(MemSource::new(bytes.to_vec())))
    }

    #[test]
    fn it_identifies_png_by_the_header() {
        let mut d = doc(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3]);
        let found = identify(&mut d);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "PNG");
    }

    #[test]
    fn it_identifies_a_magic_at_a_fixed_offset() {
        // tar: "ustar" at offset 257.
        let mut data = vec![0u8; 300];
        data[257..262].copy_from_slice(b"ustar");
        let mut d = doc(&data);
        assert!(identify(&mut d).iter().any(|s| s.name == "tar (ustar)"));
        // A file shorter than the offset does not blow up.
        let mut d = doc(b"short");
        assert!(identify(&mut d).is_empty());
    }

    #[test]
    fn riff_tells_wav_avi_and_webp_apart() {
        let mut wav = b"RIFF\x24\x08\x00\x00WAVE".to_vec();
        wav.extend([0u8; 8]);
        let mut d = doc(&wav);
        let names: Vec<&str> = identify(&mut d).iter().map(|s| s.name).collect();
        assert!(names.contains(&"WAV"));
        assert!(!names.contains(&"AVI"));
        assert!(!names.contains(&"WebP"));
    }

    #[test]
    fn the_sweep_finds_embedded_headers() {
        let mut data = vec![0u8; 100];
        data.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        data.extend(vec![0u8; 50]);
        data.extend_from_slice(&[b'P', b'K', 0x03, 0x04]);
        data.extend(vec![0u8; 50]);
        let mut d = doc(&data);
        let len = d.len();
        let (found, trunc) = scan(&mut d, 0..len, 100, &Progress::new());
        let hits: Vec<(u64, &str)> = found.iter().map(|(o, s)| (*o, s.name)).collect();
        assert!(hits.contains(&(100, "PNG")), "{hits:?}");
        assert!(hits.contains(&(158, "ZIP (and docx/xlsx/jar/apk)")), "{hits:?}");
        assert!(!trunc);
    }

    #[test]
    fn a_sweep_with_small_windows_finds_a_hit_on_the_boundary() {
        let mut data = vec![0u8; 61];
        data.extend_from_slice(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]); // XZ crosses the 64-byte window
        let mut d = doc(&data);
        let mut job = MagicScanJob::new(0..d.len(), d.len());
        let mut out = Vec::new();
        while !job.step(&mut d, 64, &mut out).finished {}
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 61);
        assert_eq!(out[0].1.name, "XZ");
    }

    #[test]
    fn two_byte_magics_stay_out_of_the_sweep() {
        // "MZ" and "BM" anywhere would be pure noise.
        let mut d = doc(b"xxMZxxBMxx");
        let len = d.len();
        let (found, _) = scan(&mut d, 0..len, 100, &Progress::new());
        assert!(found.is_empty(), "{found:?}");
        // But identify at offset 0 does recognize them.
        let mut d = doc(b"MZ\x90\x00");
        assert!(identify(&mut d).iter().any(|s| s.extension == "exe"));
    }
}
