use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::progress::Progress;
use crate::search::StepResult;

/// Window per step — the granularity of progress and cancellation.
const WINDOW: u64 = 4 << 20;

/// Name of part `index` out of `total`: `prefix.000`, `prefix.001`, …
/// (three digits, more if there are over a thousand parts).
pub fn part_name(prefix: &Path, index: usize, total: usize) -> PathBuf {
    let digits = total.saturating_sub(1).to_string().len().max(3);
    let mut name = prefix.as_os_str().to_owned();
    name.push(format!(".{index:0digits$}"));
    PathBuf::from(name)
}

/// F-57 — Splits `doc` into parts of `part_size` bytes (the last one may be
/// smaller), written as `prefix.000`, `prefix.001`, …
pub struct SplitJob {
    part_size: u64,
    prefix: PathBuf,
    doc_len: u64,
    total_parts: usize,
    pos: u64,
    /// Current part: temporary file + how many bytes it has taken so far.
    current: Option<(tempfile::NamedTempFile, u64)>,
    /// Parts already sealed (so they can be undone on error).
    written: Vec<PathBuf>,
}

impl SplitJob {
    pub fn new(doc_len: u64, part_size: u64, prefix: impl Into<PathBuf>) -> Result<Self> {
        if part_size == 0 {
            return Err(Error::new(ErrorKind::Io, "part size is zero"));
        }
        if doc_len == 0 {
            return Err(Error::new(ErrorKind::Io, "empty document; nothing to split"));
        }
        let total_parts = doc_len.div_ceil(part_size);
        // Guard rail: a million files is a typo, not an intention.
        if total_parts > 1_000_000 {
            return Err(Error::new(
                ErrorKind::Io,
                format!("{total_parts} parts; check the part size"),
            ));
        }
        Ok(Self {
            part_size,
            prefix: prefix.into(),
            doc_len,
            total_parts: total_parts as usize,
            pos: 0,
            current: None,
            written: Vec::new(),
        })
    }

    pub fn total(&self) -> u64 {
        self.doc_len
    }

    pub fn total_parts(&self) -> usize {
        self.total_parts
    }

    pub fn is_finished(&self) -> bool {
        self.pos >= self.doc_len && self.current.is_none()
    }

    fn dir(&self) -> &Path {
        self.prefix.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."))
    }

    /// Copies up to `budget` bytes from the document into the parts. An error
    /// (unreadable block, I/O) leaves the job unusable — call `abort()` to
    /// clean up.
    pub fn step(&mut self, doc: &mut Document, budget: u64) -> Result<StepResult> {
        if self.is_finished() {
            return Ok(StepResult { finished: true, scanned: 0 });
        }
        let mut remaining = budget.clamp(1, WINDOW);
        let mut scanned = 0u64;

        while remaining > 0 && self.pos < self.doc_len {
            if self.current.is_none() {
                self.current = Some((tempfile::NamedTempFile::new_in(self.dir())?, 0));
            }
            let (tmp, filled) = self.current.as_mut().unwrap();

            let n = (self.part_size - *filled).min(remaining).min(self.doc_len - self.pos);
            let read = doc.read(self.pos, n as usize);
            if !read.is_clean() {
                return Err(Error::new(
                    ErrorKind::BadBlock,
                    format!("unreadable block at {:#x}; split aborted", read.unreadable[0].start),
                ));
            }
            tmp.as_file_mut().write_all(&read.data)?;
            *filled += n;
            self.pos += n;
            scanned += n;
            remaining -= n;

            // Part complete (or end of document): seal it with its final name.
            if *filled == self.part_size || self.pos == self.doc_len {
                let (tmp, _) = self.current.take().unwrap();
                let path = part_name(&self.prefix, self.written.len(), self.total_parts);
                tmp.as_file().sync_all()?;
                tmp.persist(&path).map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
                self.written.push(path);
            }
        }
        Ok(StepResult { finished: self.is_finished(), scanned })
    }

    /// Consumes the finished job and returns the parts' paths.
    pub fn finish(self) -> Vec<PathBuf> {
        debug_assert!(self.is_finished());
        self.written
    }

    /// Cancellation or error: deletes the parts already written (the current
    /// part's temporary file dies on its own at drop).
    pub fn abort(self) {
        for p in &self.written {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// F-58 — Concatenates files in the given order. The output is born as a
/// temporary file and becomes `out` only once complete.
pub struct ConcatJob {
    inputs: Vec<PathBuf>,
    out: PathBuf,
    tmp: Option<tempfile::NamedTempFile>,
    /// The currently open input and its index in `inputs`.
    current: Option<File>,
    index: usize,
    total: u64,
    written: u64,
}

impl ConcatJob {
    pub fn new(inputs: &[PathBuf], out: impl Into<PathBuf>) -> Result<Self> {
        let out: PathBuf = out.into();
        if inputs.is_empty() {
            return Err(Error::new(ErrorKind::Io, "no input file"));
        }
        // The output cannot be one of the inputs: we would read back what we
        // just wrote. Compares canonical paths (the output may not exist yet;
        // in that case no conflict is possible).
        let mut total = 0u64;
        let out_canon = out.canonicalize().ok();
        for p in inputs {
            let meta = std::fs::metadata(p)
                .map_err(|e| Error::new(ErrorKind::Io, format!("{}: {e}", p.display())))?;
            total = total.saturating_add(meta.len());
            if let (Ok(pc), Some(oc)) = (p.canonicalize(), &out_canon)
                && pc == *oc
            {
                return Err(Error::new(
                    ErrorKind::Io,
                    format!("the output {} is also an input", out.display()),
                ));
            }
        }
        let dir = out.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let tmp = tempfile::NamedTempFile::new_in(dir)?;
        Ok(Self {
            inputs: inputs.to_vec(),
            out,
            tmp: Some(tmp),
            current: None,
            index: 0,
            total,
            written: 0,
        })
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn is_finished(&self) -> bool {
        self.index >= self.inputs.len()
    }

    /// Copies up to `budget` bytes. Reading less than expected is not an error
    /// — the file may have shrunk since `new`; what matters is copying each
    /// input whole, in order.
    pub fn step(&mut self, budget: u64) -> Result<StepResult> {
        if self.is_finished() {
            return Ok(StepResult { finished: true, scanned: 0 });
        }
        let tmp = self.tmp.as_mut().expect("a live job has a temporary file");
        let mut remaining = budget.clamp(1, WINDOW) as usize;
        let mut scanned = 0u64;
        let mut buf = vec![0u8; remaining.min(WINDOW as usize)];

        while remaining > 0 && self.index < self.inputs.len() {
            if self.current.is_none() {
                let p = &self.inputs[self.index];
                self.current = Some(File::open(p).map_err(|e| {
                    Error::new(ErrorKind::Io, format!("{}: {e}", p.display()))
                })?);
            }
            let f = self.current.as_mut().unwrap();
            let want = remaining.min(buf.len());
            let n = f.read(&mut buf[..want])?;
            if n == 0 {
                self.current = None;
                self.index += 1;
                continue;
            }
            tmp.as_file_mut().write_all(&buf[..n])?;
            self.written += n as u64;
            scanned += n as u64;
            remaining -= n;
        }
        Ok(StepResult { finished: self.is_finished(), scanned })
    }

    /// Seals the output with its final name. Returns the total bytes written.
    pub fn finish(mut self) -> Result<u64> {
        debug_assert!(self.is_finished());
        let tmp = self.tmp.take().expect("finish only once");
        tmp.as_file().sync_all()?;
        tmp.persist(&self.out).map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
        Ok(self.written)
    }
}

/// Blocking helper (CLI and tests). Cancelling deletes the parts already made.
pub fn split(
    doc: &mut Document,
    part_size: u64,
    prefix: impl Into<PathBuf>,
    progress: &Progress,
) -> Result<Vec<PathBuf>> {
    let mut job = SplitJob::new(doc.len(), part_size, prefix)?;
    progress.set_total(job.total());
    while !job.is_finished() {
        if progress.is_cancelled() {
            job.abort();
            return Err(Error::new(ErrorKind::Io, "cancelled"));
        }
        match job.step(doc, WINDOW) {
            Ok(st) => progress.add_done(st.scanned),
            Err(e) => {
                job.abort();
                return Err(e);
            }
        }
    }
    Ok(job.finish())
}

/// Blocking helper (CLI and tests).
pub fn concat(inputs: &[PathBuf], out: impl Into<PathBuf>, progress: &Progress) -> Result<u64> {
    let mut job = ConcatJob::new(inputs, out)?;
    progress.set_total(job.total());
    while !job.is_finished() {
        if progress.is_cancelled() {
            return Err(Error::new(ErrorKind::Io, "cancelled"));
        }
        let st = job.step(WINDOW)?;
        progress.add_done(st.scanned);
    }
    job.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    fn doc(bytes: &[u8]) -> Document {
        Document::new(Box::new(MemSource::new(bytes.to_vec())))
    }

    #[test]
    fn part_name_has_at_least_three_digits() {
        let p = Path::new("/tmp/output.bin");
        assert_eq!(part_name(p, 0, 4), Path::new("/tmp/output.bin.000"));
        assert_eq!(part_name(p, 12, 100), Path::new("/tmp/output.bin.012"));
        assert_eq!(part_name(p, 0, 20_000), Path::new("/tmp/output.bin.00000"));
    }

    #[test]
    fn it_splits_and_the_last_part_is_smaller() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("p.bin");
        let mut d = doc(b"0123456789");
        let parts = split(&mut d, 4, &prefix, &Progress::new()).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(std::fs::read(&parts[0]).unwrap(), b"0123");
        assert_eq!(std::fs::read(&parts[1]).unwrap(), b"4567");
        assert_eq!(std::fs::read(&parts[2]).unwrap(), b"89");
    }

    #[test]
    fn it_splits_into_a_single_part_when_the_size_exceeds_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = doc(b"abc");
        let parts = split(&mut d, 100, dir.path().join("x"), &Progress::new()).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(std::fs::read(&parts[0]).unwrap(), b"abc");
    }

    #[test]
    fn split_sees_unsaved_edits() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = doc(b"ab");
        d.insert(2, b"cd").unwrap();
        let parts = split(&mut d, 3, dir.path().join("x"), &Progress::new()).unwrap();
        assert_eq!(std::fs::read(&parts[0]).unwrap(), b"abc");
        assert_eq!(std::fs::read(&parts[1]).unwrap(), b"d");
    }

    #[test]
    fn split_refuses_zero_size_an_empty_document_and_a_flood_of_parts() {
        assert!(SplitJob::new(10, 0, "x").is_err());
        assert!(SplitJob::new(0, 4, "x").is_err());
        assert!(SplitJob::new(u64::MAX, 1, "x").is_err());
    }

    #[test]
    fn a_split_with_an_unreadable_block_aborts_and_leaves_no_parts() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("p.bin");
        let src = MemSource::new(vec![1u8; 64]).with_bad_range(48..64);
        let mut d = Document::new(Box::new(src));
        d.set_cache(crate::cache::BlockCache::new(16, 8));
        let err = split(&mut d, 16, &prefix, &Progress::new()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::BadBlock);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(leftovers.is_empty(), "abort deletes the parts already written: {leftovers:?}");
    }

    #[test]
    fn a_cancelled_split_deletes_what_it_made() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = doc(&[7u8; 32]);
        let progress = Progress::new();
        progress.cancel();
        assert!(split(&mut d, 8, dir.path().join("p"), &progress).is_err());
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn it_concatenates_in_the_given_order() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"hello ").unwrap();
        std::fs::write(&b, b"world").unwrap();
        let out = dir.path().join("out");
        let n = concat(&[b.clone(), a.clone()], &out, &Progress::new()).unwrap();
        assert_eq!(n, 11);
        assert_eq!(std::fs::read(&out).unwrap(), b"worldhello ");
    }

    #[test]
    fn concat_refuses_an_output_that_is_an_input() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        std::fs::write(&a, b"x").unwrap();
        let err = concat(std::slice::from_ref(&a), &a, &Progress::new()).unwrap_err();
        assert!(err.detail.contains("is also an input"), "{err}");
        assert_eq!(std::fs::read(&a).unwrap(), b"x", "the input is intact");
    }

    #[test]
    fn concat_refuses_a_missing_input_without_creating_the_output() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let err =
            concat(&[dir.path().join("does-not-exist")], &out, &Progress::new()).unwrap_err();
        assert!(err.detail.contains("does-not-exist"), "{err}");
        assert!(!out.exists());
    }

    #[test]
    fn splitting_and_concatenating_is_the_identity() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let mut d = doc(&data);
        let parts = split(&mut d, 999, dir.path().join("p"), &Progress::new()).unwrap();
        assert_eq!(parts.len(), 11);
        let out = dir.path().join("roundtrip.bin");
        concat(&parts, &out, &Progress::new()).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data);
    }

    #[test]
    fn small_steps_produce_the_same_parts() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..100u8).collect();
        let mut d = doc(&data);
        let mut job = SplitJob::new(d.len(), 30, dir.path().join("p")).unwrap();
        while !job.is_finished() {
            job.step(&mut d, 7).unwrap();
        }
        let parts = job.finish();
        assert_eq!(parts.len(), 4);
        let mut got = Vec::new();
        for p in &parts {
            got.extend(std::fs::read(p).unwrap());
        }
        assert_eq!(got, data);
    }
}
