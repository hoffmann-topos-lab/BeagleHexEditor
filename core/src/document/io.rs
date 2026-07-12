use std::io::Write;
use std::ops::Range;
use std::path::Path;

use crate::error::{Error, ErrorKind, Result};
use crate::piece_table::StoreId;

use super::{Document, ReadResult};

/// Block size used when serializing the document (`write_to`).
const STREAM_CHUNK: usize = 1 << 20;

impl Document {
    // ---- reading ----

    pub fn read(&mut self, offset: u64, len: usize) -> ReadResult {
        let end = offset.saturating_add(len as u64).min(self.table.len());
        if offset >= end {
            return ReadResult { data: Vec::new(), unreadable: Vec::new() };
        }

        // Destructuring avoids a borrow conflict between `cache` (&mut) and `source` (&).
        let Document { source, cache, add, table, .. } = self;
        let mut data = Vec::with_capacity((end - offset) as usize);
        let mut unreadable: Vec<Range<u64>> = Vec::new();
        let mut doc_pos = offset;

        for p in table.pieces_in(offset..end) {
            let mut buf = vec![0u8; p.len as usize];
            match p.store {
                StoreId::Added => {
                    add.read_at(p.offset, &mut buf).expect("the add buffer is infallible");
                }
                StoreId::Original => {
                    for r in cache.read_into(source.as_ref(), p.offset, &mut buf) {
                        let s = doc_pos + (r.start - p.offset);
                        let e = doc_pos + (r.end - p.offset);
                        match unreadable.last_mut() {
                            Some(prev) if prev.end == s => prev.end = e,
                            _ => unreadable.push(s..e),
                        }
                    }
                }
            }
            data.extend_from_slice(&buf);
            doc_pos += p.len;
        }

        ReadResult { data, unreadable }
    }

    // ---- F-05 ----

    /// Serializes the whole document. Returns the ranges that could not be read
    /// from the source — if it is not empty, the output holds zeros there.
    pub fn write_to(&mut self, w: &mut impl Write) -> Result<Vec<Range<u64>>> {
        let Document { source, cache, add, table, .. } = self;
        let mut unreadable: Vec<Range<u64>> = Vec::new();
        let mut buf = Vec::with_capacity(STREAM_CHUNK);
        let mut doc_pos = 0u64;

        for p in table.pieces() {
            let mut done = 0u64;
            while done < p.len {
                let n = (p.len - done).min(STREAM_CHUNK as u64) as usize;
                let src_base = p.offset + done;
                let doc_base = doc_pos + done;
                buf.clear();
                buf.resize(n, 0);

                match p.store {
                    StoreId::Added => add.read_at(src_base, &mut buf)?,
                    StoreId::Original => {
                        for r in cache.read_into(source.as_ref(), src_base, &mut buf) {
                            let s = doc_base + (r.start - src_base);
                            let e = doc_base + (r.end - src_base);
                            match unreadable.last_mut() {
                                Some(prev) if prev.end == s => prev.end = e,
                                _ => unreadable.push(s..e),
                            }
                        }
                    }
                }
                w.write_all(&buf)?;
                done += n as u64;
            }
            doc_pos += p.len;
        }
        Ok(unreadable)
    }

    /// Atomic save: writes to a temporary file in the **same directory**, syncs
    /// it, and only then renames it over the destination. A power cut halfway
    /// through leaves the original intact.
    ///
    /// Refuses to save if any source block is unreadable — silently writing
    /// zeros over data that merely could not be read would be the worst thing
    /// this program could do.
    pub fn save_as(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));

        // The temporary file must live on the same filesystem, otherwise the
        // rename fails with EXDEV.
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        let unreadable = {
            let mut w = std::io::BufWriter::new(tmp.as_file_mut());
            let bad = self.write_to(&mut w)?;
            w.flush()?;
            bad
        };

        if !unreadable.is_empty() {
            // `tmp` is dropped here and the temporary file disappears. Nothing
            // was touched.
            return Err(Error::new(
                ErrorKind::BadBlock,
                format!("{} unreadable range(s); save aborted", unreadable.len()),
            ));
        }

        // The tempfile is created 0600; saving over an existing file must not
        // silently tighten its permissions.
        if let Ok(meta) = std::fs::metadata(path) {
            tmp.as_file().set_permissions(meta.permissions())?;
        }

        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
        self.saved_depth = self.undo.len();
        Ok(())
    }
}

/// F-65 — Copies `path` to `path.bak` before it is overwritten, so a save that
/// goes wrong still leaves the previous version recoverable. Returns the backup
/// path, or `None` if `path` does not exist yet (nothing to back up).
pub fn backup_file(path: impl AsRef<Path>) -> Result<Option<std::path::PathBuf>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(None);
    }
    let mut backup = path.as_os_str().to_os_string();
    backup.push(".bak");
    let backup = std::path::PathBuf::from(backup);
    std::fs::copy(path, &backup)?;
    Ok(Some(backup))
}
