//! F-01/F-03 — The document: a piece table over a `DataSource`, with undo,
//! granular reads and atomic saves. Reading/serialization lives in `io`,
//! F-22 fill in `fill`.

mod fill;
mod io;
#[cfg(test)]
mod tests;

use std::ops::Range;
use std::path::Path;

use crate::add_buffer::AddBuffer;
use crate::cache::BlockCache;
use crate::error::{Error, ErrorKind, Result};
use crate::piece_table::{Piece, PieceTable, StoreId, total_len};
use crate::source::{DataSource, FileSource};

pub use fill::FillPattern;
pub use io::backup_file;

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
            // An undo splices deleted pieces back as standalone fragments, so a
            // later redo may see the same bytes split differently — compare the
            // referenced byte runs, not the exact fragmentation.
            debug_assert!(
                same_byte_runs(&removed, pieces),
                "redo of delete diverged from the table: {removed:?} vs {pieces:?}"
            );
        }
    }
}

/// True when both piece lists reference the same byte sequence, merging
/// store-contiguous fragments before comparing. Only exercised by the
/// `debug_assert!` above (release builds fold the call away).
fn same_byte_runs(a: &[Piece], b: &[Piece]) -> bool {
    fn normalized(pieces: &[Piece]) -> Vec<Piece> {
        let mut out: Vec<Piece> = Vec::new();
        for p in pieces.iter().filter(|p| p.len > 0) {
            match out.last_mut() {
                Some(prev) if prev.store == p.store && prev.offset + prev.len == p.offset => {
                    prev.len += p.len;
                }
                _ => out.push(*p),
            }
        }
        out
    }
    normalized(a) == normalized(b)
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
}
