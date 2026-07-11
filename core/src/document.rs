use std::io::Write;
use std::ops::Range;
use std::path::Path;

use crate::add_buffer::AddBuffer;
use crate::cache::BlockCache;
use crate::error::{Error, ErrorKind, Result};
use crate::piece_table::{Piece, PieceTable, StoreId, total_len};
use crate::rng::Rng;
use crate::source::{DataSource, FileSource};

/// Block size used when serializing the document (`write_to`).
const STREAM_CHUNK: usize = 1 << 20;

/// Chunk generated at a time by `fill` (F-22). Filling 2 GB must not
/// materialize 2 GB at once — the `AddBuffer` spill (D7) handles the rest.
const FILL_CHUNK: u64 = 1 << 20;

/// F-22 — What to write into each byte of the selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FillPattern {
    /// Repeats the sequence from the start to the end of the selection (a
    /// single byte being the common case).
    Repeat(Vec<u8>),
    /// Pseudo-random bytes. The seed makes the operation reproducible — which
    /// is what lets it be tested through the CLI.
    Random { seed: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Edit {
    Insert { offset: u64, pieces: Vec<Piece> },
    Delete { offset: u64, pieces: Vec<Piece> },
}

/// One undo unit. Overwriting is `[Delete, Insert]`: a single Ctrl+Z.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transaction {
    edits: Vec<Edit>,
}

fn apply(table: &mut PieceTable, e: &Edit) {
    match e {
        Edit::Insert { offset, pieces } => table.splice(*offset, pieces),
        Edit::Delete { offset, pieces } => {
            let removed = table.delete(*offset, total_len(pieces));
            debug_assert_eq!(&removed, pieces, "redo of delete diverged from the table");
        }
    }
}

fn revert(table: &mut PieceTable, e: &Edit) {
    match e {
        Edit::Insert { offset, pieces } => {
            table.delete(*offset, total_len(pieces));
        }
        Edit::Delete { offset, pieces } => table.splice(*offset, pieces),
    }
}

/// Result of a read. Bytes from unreadable blocks come back zeroed, and their
/// ranges — in document coordinates — come in `unreadable` (F-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    pub data: Vec<u8>,
    pub unreadable: Vec<Range<u64>>,
}

impl ReadResult {
    pub fn is_clean(&self) -> bool {
        self.unreadable.is_empty()
    }
}

pub struct Document {
    source: Box<dyn DataSource>,
    cache: BlockCache,
    add: AddBuffer,
    table: PieceTable,
    undo: Vec<Transaction>,
    redo: Vec<Transaction>,
    /// Depth of the undo stack at the last save.
    saved_depth: usize,
}

impl Document {
    pub fn new(source: Box<dyn DataSource>) -> Self {
        let table = PieceTable::new(source.size());
        Self {
            source,
            cache: BlockCache::default(),
            add: AddBuffer::default(),
            table,
            undo: Vec::new(),
            redo: Vec::new(),
            saved_depth: 0,
        }
    }

    pub fn open(path: impl AsRef<Path>, writable: bool) -> Result<Self> {
        Ok(Self::new(Box::new(FileSource::open(path, writable)?)))
    }

    pub fn len(&self) -> u64 {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn pieces(&self) -> &[Piece] {
        self.table.pieces()
    }

    /// Tests only: small blocks exercise partial read failures.
    #[cfg(test)]
    pub(crate) fn set_cache(&mut self, cache: BlockCache) {
        self.cache = cache;
    }

    /// F-43: true when there are unsaved changes.
    pub fn dirty(&self) -> bool {
        self.undo.len() != self.saved_depth
    }

    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    fn resizable(&self) -> bool {
        self.source.capabilities().resizable
    }

    fn check_offset(&self, offset: u64) -> Result<()> {
        if offset > self.len() {
            return Err(Error::new(
                ErrorKind::OutOfBounds,
                format!("offset {offset} > size {}", self.len()),
            ));
        }
        Ok(())
    }

    fn commit(&mut self, tx: Transaction) {
        self.undo.push(tx);
        self.redo.clear();
        // If we undid past the saved point and then edited, that point became
        // unreachable: the document is dirty forever.
        if self.saved_depth > self.undo.len() {
            self.saved_depth = usize::MAX;
        }
    }

    // ---- F-35 / F-36 / F-37 ----

    pub fn insert(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.check_offset(offset)?;
        if !self.resizable() {
            return Err(Error::new(ErrorKind::NotResizable, "this source does not accept insertion"));
        }
        let at = self.add.append(data)?;
        let piece = Piece { store: StoreId::Added, offset: at, len: data.len() as u64 };
        let edit = Edit::Insert { offset, pieces: vec![piece] };
        apply(&mut self.table, &edit);
        self.commit(Transaction { edits: vec![edit] });
        Ok(())
    }

    pub fn delete(&mut self, offset: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        self.check_offset(offset.saturating_add(len))?;
        if !self.resizable() {
            return Err(Error::new(ErrorKind::NotResizable, "this source does not accept deletion"));
        }
        let removed = self.table.delete(offset, len);
        self.commit(Transaction { edits: vec![Edit::Delete { offset, pieces: removed }] });
        Ok(())
    }

    /// Replaces bytes without shifting the rest. It is the only edit allowed on
    /// disks and process memory.
    pub fn overwrite(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.check_offset(offset)?;
        let end = offset + data.len() as u64;
        if end > self.len() && !self.resizable() {
            return Err(Error::new(
                ErrorKind::NotResizable,
                "overwrite would run past the end of a fixed-size source",
            ));
        }

        let mut edits = Vec::with_capacity(2);
        let overlap = (self.len() - offset).min(data.len() as u64);
        if overlap > 0 {
            let removed = self.table.delete(offset, overlap);
            edits.push(Edit::Delete { offset, pieces: removed });
        }
        let at = self.add.append(data)?;
        let piece = Piece { store: StoreId::Added, offset: at, len: data.len() as u64 };
        let insert = Edit::Insert { offset, pieces: vec![piece] };
        apply(&mut self.table, &insert);
        edits.push(insert);

        self.commit(Transaction { edits });
        Ok(())
    }

    /// F-22 — Fills `offset..offset + len` with the pattern, as **a single**
    /// undo transaction. It is an overwrite: the document size does not change,
    /// so it works on non-resizable sources too.
    ///
    /// The range must fit inside the document — filling past the end would be
    /// an insertion in disguise.
    pub fn fill(&mut self, offset: u64, len: u64, pattern: &FillPattern) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let end = offset.checked_add(len).ok_or_else(|| {
            Error::new(ErrorKind::OutOfBounds, "offset + length overflows 64 bits")
        })?;
        self.check_offset(end)?;
        let mut rng = match pattern {
            FillPattern::Repeat(p) if p.is_empty() => {
                return Err(Error::new(ErrorKind::Io, "empty fill pattern"));
            }
            FillPattern::Repeat(_) => None,
            FillPattern::Random { seed } => Some(Rng::new(*seed)),
        };

        let mut done = 0u64;
        while done < len {
            let n = (len - done).min(FILL_CHUNK) as usize;
            let mut buf = vec![0u8; n];
            match (pattern, &mut rng) {
                (FillPattern::Repeat(p), _) => {
                    // Align by the offset within the selection: the pattern
                    // stays correct across chunk boundaries.
                    for (i, b) in buf.iter_mut().enumerate() {
                        *b = p[(done as usize + i) % p.len()];
                    }
                }
                (FillPattern::Random { .. }, Some(rng)) => rng.fill(&mut buf),
                (FillPattern::Random { .. }, None) => unreachable!(),
            }
            self.overwrite(offset + done, &buf)?;
            if done > 0 {
                self.merge_with_previous(); // a single Ctrl+Z for the whole selection
            }
            done += n as u64;
        }
        Ok(())
    }

    /// F-41: ranges within `range` modified in this session (see
    /// `PieceTable::modified_in`).
    pub fn modified_in(&mut self, range: Range<u64>) -> Vec<Range<u64>> {
        self.table.modified_in(range)
    }

    // ---- F-03 ----

    /// F-39 — Merges the last transaction with the previous one, forming a
    /// single undo.
    ///
    /// This is how the UI groups typing: each typed byte is a commit, and the
    /// caller decides whether it continues the previous run. **Do not call it
    /// across a save point** (the UI ends the run on save): the saved point
    /// between the two would become unreachable and the document would be
    /// considered dirty forever.
    pub fn merge_with_previous(&mut self) -> bool {
        if self.undo.len() < 2 {
            return false;
        }
        let last = self.undo.pop().unwrap();
        if self.saved_depth == self.undo.len() {
            // The saved point was the boundary between the two: it disappears.
            self.saved_depth = usize::MAX;
        } else if self.saved_depth == self.undo.len() + 1 {
            // The saved point was the top: it remains the top.
            self.saved_depth = self.undo.len();
        }
        self.undo.last_mut().unwrap().edits.extend(last.edits);
        true
    }

    pub fn undo(&mut self) -> bool {
        let Some(tx) = self.undo.pop() else { return false };
        for e in tx.edits.iter().rev() {
            revert(&mut self.table, e);
        }
        self.redo.push(tx);
        true
    }

    pub fn redo(&mut self) -> bool {
        let Some(tx) = self.redo.pop() else { return false };
        for e in &tx.edits {
            apply(&mut self.table, e);
        }
        self.undo.push(tx);
        true
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    fn doc(bytes: &[u8]) -> Document {
        Document::new(Box::new(MemSource::new(bytes.to_vec())))
    }

    fn all(d: &mut Document) -> Vec<u8> {
        d.read(0, d.len() as usize).data
    }

    #[test]
    fn insertion_at_start_middle_and_end() {
        let mut d = doc(b"world");
        d.insert(0, b"hello ").unwrap();
        assert_eq!(all(&mut d), b"hello world");
        d.insert(5, b",").unwrap();
        assert_eq!(all(&mut d), b"hello, world");
        d.insert(12, b"!").unwrap();
        assert_eq!(all(&mut d), b"hello, world!");
    }

    #[test]
    fn deletion() {
        let mut d = doc(b"hello, world!");
        d.delete(5, 2).unwrap();
        assert_eq!(all(&mut d), b"helloworld!");
    }

    #[test]
    fn overwrite_preserves_the_size() {
        let mut d = doc(b"hello");
        d.overwrite(1, b"appy").unwrap();
        assert_eq!(all(&mut d), b"happy");
        assert_eq!(d.len(), 5);
    }

    #[test]
    fn overwrite_at_the_end_extends_the_file() {
        let mut d = doc(b"abc");
        d.overwrite(2, b"XYZ").unwrap();
        assert_eq!(all(&mut d), b"abXYZ");
    }

    #[test]
    fn overwrite_is_a_single_undo() {
        let mut d = doc(b"hello");
        d.overwrite(1, b"appy").unwrap();
        assert!(d.undo());
        assert_eq!(all(&mut d), b"hello");
        assert!(!d.can_undo());
    }

    #[test]
    fn undo_and_redo_walk_the_history() {
        let mut d = doc(b"a");
        d.insert(1, b"b").unwrap();
        d.insert(2, b"c").unwrap();
        assert_eq!(all(&mut d), b"abc");
        assert!(d.undo());
        assert_eq!(all(&mut d), b"ab");
        assert!(d.undo());
        assert_eq!(all(&mut d), b"a");
        assert!(!d.undo());
        assert!(d.redo());
        assert!(d.redo());
        assert_eq!(all(&mut d), b"abc");
        assert!(!d.redo());
    }

    #[test]
    fn editing_after_undo_discards_the_redo() {
        let mut d = doc(b"a");
        d.insert(1, b"b").unwrap();
        d.undo();
        assert!(d.can_redo());
        d.insert(1, b"z").unwrap();
        assert!(!d.can_redo());
        assert_eq!(all(&mut d), b"az");
    }

    #[test]
    fn a_non_resizable_source_refuses_insertion_and_deletion() {
        struct Fixed(MemSource);
        impl DataSource for Fixed {
            fn size(&self) -> u64 {
                self.0.size()
            }
            fn capabilities(&self) -> crate::source::Capabilities {
                crate::source::Capabilities {
                    writable: true,
                    resizable: false,
                    block_size: Some(512),
                    sparse: false,
                }
            }
            fn read_at(&self, o: u64, b: &mut [u8]) -> Result<()> {
                self.0.read_at(o, b)
            }
            fn write_at(&self, o: u64, b: &[u8]) -> Result<()> {
                self.0.write_at(o, b)
            }
        }

        let mut d = Document::new(Box::new(Fixed(MemSource::new(vec![0u8; 512]))));
        assert_eq!(d.insert(0, b"x").unwrap_err().kind, ErrorKind::NotResizable);
        assert_eq!(d.delete(0, 1).unwrap_err().kind, ErrorKind::NotResizable);
        assert_eq!(d.overwrite(511, b"xx").unwrap_err().kind, ErrorKind::NotResizable);
        // An overwrite that fits is allowed.
        d.overwrite(0, b"ok").unwrap();
        assert_eq!(d.len(), 512);
    }

    #[test]
    fn a_read_reports_the_unreadable_range_in_document_coordinates() {
        let src = MemSource::new(vec![0xAAu8; 128]).with_bad_range(64..80);
        let mut d = Document::new(Box::new(src));
        d.cache = BlockCache::new(16, 8);

        // Shift everything 4 bytes to the right: the source's bad block
        // [64,80) becomes [68,84) in the document.
        d.insert(0, b"XXXX").unwrap();
        let r = d.read(0, 132);
        assert_eq!(r.unreadable, vec![68..84]);
        assert_eq!(&r.data[0..4], b"XXXX");
        assert_eq!(&r.data[68..84], &[0u8; 16]);
    }

    #[test]
    fn dirty_reflects_the_save_state() {
        let mut d = doc(b"abc");
        assert!(!d.dirty());
        d.insert(0, b"x").unwrap();
        assert!(d.dirty());
        d.undo();
        assert!(!d.dirty());
    }

    #[test]
    fn merge_forms_a_single_undo() {
        let mut d = doc(b"ab");
        d.overwrite(0, b"X").unwrap();
        d.overwrite(1, b"Y").unwrap();
        assert!(d.merge_with_previous());
        assert_eq!(all(&mut d), b"XY");
        assert!(d.undo());
        assert_eq!(all(&mut d), b"ab");
        assert!(!d.can_undo());
        assert!(d.redo());
        assert_eq!(all(&mut d), b"XY");
    }

    #[test]
    fn merge_preserves_a_save_point_at_the_top() {
        let mut d = doc(b"abcd");
        d.overwrite(0, b"X").unwrap();
        d.saved_depth = d.undo.len(); // simulates a save here
        d.overwrite(1, b"Y").unwrap();
        d.overwrite(2, b"Z").unwrap();
        d.merge_with_previous(); // merges Y+Z; the save stays reachable
        assert!(d.dirty());
        d.undo();
        assert!(!d.dirty());
    }

    #[test]
    fn merging_across_the_save_point_dirties_forever() {
        let mut d = doc(b"abcd");
        d.overwrite(0, b"X").unwrap();
        d.saved_depth = d.undo.len();
        d.overwrite(1, b"Y").unwrap();
        d.merge_with_previous(); // swallows the saved boundary
        while d.undo() {}
        assert!(d.dirty(), "the saved state no longer exists as a boundary");
    }

    #[test]
    fn merge_without_enough_history_does_nothing() {
        let mut d = doc(b"ab");
        assert!(!d.merge_with_previous());
        d.overwrite(0, b"X").unwrap();
        assert!(!d.merge_with_previous());
    }

    #[test]
    fn modified_in_reflects_edits_and_undo() {
        let mut d = doc(b"\x00\x00\x00\x00\x00\x00\x00\x00");
        d.overwrite(2, b"AB").unwrap();
        d.insert(6, b"C").unwrap();
        assert_eq!(d.modified_in(0..9), vec![2..4, 6..7]);
        assert_eq!(d.modified_in(3..7), vec![3..4, 6..7]);
        d.undo();
        d.undo();
        assert!(d.modified_in(0..8).is_empty());
    }

    #[test]
    fn fill_repeats_the_pattern_and_is_a_single_undo() {
        let mut d = doc(b"aaaaaaaaaa");
        d.fill(2, 6, &FillPattern::Repeat(vec![0xDE, 0xAD])).unwrap();
        assert_eq!(all(&mut d), b"aa\xDE\xAD\xDE\xAD\xDE\xADaa");
        assert!(d.undo());
        assert_eq!(all(&mut d), b"aaaaaaaaaa");
        assert!(!d.can_undo());
    }

    #[test]
    fn fill_crosses_chunk_boundaries_without_misaligning_the_pattern() {
        let len = super::FILL_CHUNK * 2 + 5;
        let mut d = Document::new(Box::new(MemSource::new(vec![0u8; len as usize])));
        d.fill(1, len - 1, &FillPattern::Repeat(vec![1, 2, 3])).unwrap();
        let r = d.read(0, len as usize);
        assert_eq!(r.data[0], 0);
        for i in 1..len as usize {
            assert_eq!(r.data[i], [1, 2, 3][(i - 1) % 3], "byte {i}");
        }
        assert!(d.undo(), "the whole selection is one transaction");
        assert!(!d.can_undo());
        assert_eq!(d.read(0, 8).data, vec![0u8; 8]);
    }

    #[test]
    fn random_fill_is_reproducible_from_the_seed() {
        let mut a = doc(&[0u8; 64]);
        let mut b = doc(&[0u8; 64]);
        a.fill(0, 64, &FillPattern::Random { seed: 42 }).unwrap();
        b.fill(0, 64, &FillPattern::Random { seed: 42 }).unwrap();
        assert_eq!(all(&mut a), all(&mut b));
        let mut c = doc(&[0u8; 64]);
        c.fill(0, 64, &FillPattern::Random { seed: 43 }).unwrap();
        assert_ne!(all(&mut a), all(&mut c), "different seeds diverge");
    }

    #[test]
    fn fill_refuses_a_range_past_the_end_and_an_empty_pattern() {
        let mut d = doc(b"abc");
        let err = d.fill(1, 3, &FillPattern::Repeat(vec![0])).unwrap_err();
        assert_eq!(err.kind, ErrorKind::OutOfBounds);
        assert!(d.fill(0, 2, &FillPattern::Repeat(vec![])).is_err());
        assert!(!d.dirty(), "nothing was written");
    }

    #[test]
    fn save_as_refuses_an_unreadable_block() {
        let src = MemSource::new(vec![1u8; 64]).with_bad_range(16..32);
        let mut d = Document::new(Box::new(src));
        d.cache = BlockCache::new(16, 8);

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("output.bin");
        let err = d.save_as(&out).unwrap_err();
        assert_eq!(err.kind, ErrorKind::BadBlock);
        assert!(!out.exists(), "nothing may be written when the read fails");
    }

    #[test]
    fn save_as_writes_the_edited_content() {
        let mut d = doc(b"hello world");
        d.overwrite(6, b"rust!").unwrap();
        d.insert(0, b">> ").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("output.bin");
        d.save_as(&out).unwrap();

        assert_eq!(std::fs::read(&out).unwrap(), b">> hello rust!");
        assert!(!d.dirty());
    }

    #[test]
    fn backup_copies_an_existing_file_and_skips_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");

        // Nothing to back up yet.
        assert_eq!(backup_file(&path).unwrap(), None);

        std::fs::write(&path, b"original").unwrap();
        let bak = backup_file(&path).unwrap().expect("a backup path");
        assert_eq!(bak, dir.path().join("data.bin.bak"));
        assert_eq!(std::fs::read(&bak).unwrap(), b"original");

        // A second backup overwrites the first with the newer contents.
        std::fs::write(&path, b"changed").unwrap();
        backup_file(&path).unwrap();
        assert_eq!(std::fs::read(&bak).unwrap(), b"changed");
    }
}
