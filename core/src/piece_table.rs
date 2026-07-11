use std::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreId {
    /// The original data source. Never modified.
    Original,
    /// The add buffer, append-only.
    Added,
}

/// A contiguous span of a store. `offset` is relative to the store, not to the document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Piece {
    pub store: StoreId,
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PieceTable {
    pieces: Vec<Piece>,
    len: u64,
}

pub fn total_len(pieces: &[Piece]) -> u64 {
    pieces.iter().map(|p| p.len).sum()
}

impl PieceTable {
    pub fn new(original_len: u64) -> Self {
        let mut pieces = Vec::new();
        if original_len > 0 {
            pieces.push(Piece { store: StoreId::Original, offset: 0, len: original_len });
        }
        Self { pieces, len: original_len }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn pieces(&self) -> &[Piece] {
        &self.pieces
    }

    /// The pieces covering `range`, clipped at the edges. This is what the UI
    /// uses to draw only the visible rows.
    pub fn pieces_in(&self, range: Range<u64>) -> Vec<Piece> {
        let mut out = Vec::new();
        if range.start >= range.end {
            return out;
        }
        let mut acc = 0u64;
        for p in &self.pieces {
            let (ps, pe) = (acc, acc + p.len);
            acc = pe;
            if pe <= range.start {
                continue;
            }
            if ps >= range.end {
                break;
            }
            let s = range.start.max(ps);
            let e = range.end.min(pe);
            out.push(Piece { store: p.store, offset: p.offset + (s - ps), len: e - s });
        }
        out
    }

    /// F-41 — The ranges within `range` that come from the add buffer, i.e.
    /// bytes modified/inserted in this session. In document coordinates, with
    /// adjacent ranges merged. This is what the grid paints in another colour.
    pub fn modified_in(&self, range: Range<u64>) -> Vec<Range<u64>> {
        let mut out: Vec<Range<u64>> = Vec::new();
        if range.start >= range.end {
            return out;
        }
        let mut acc = 0u64;
        for p in &self.pieces {
            let (ps, pe) = (acc, acc + p.len);
            acc = pe;
            if pe <= range.start {
                continue;
            }
            if ps >= range.end {
                break;
            }
            if p.store == StoreId::Added {
                let s = range.start.max(ps);
                let e = range.end.min(pe);
                match out.last_mut() {
                    Some(prev) if prev.end == s => prev.end = e,
                    _ => out.push(s..e),
                }
            }
        }
        out
    }

    /// Inserts `new` at logical position `offset`, splitting the piece that contains it.
    pub fn splice(&mut self, offset: u64, new: &[Piece]) {
        assert!(offset <= self.len, "splice outside the document");
        let added = total_len(new);
        if added == 0 {
            return;
        }
        let mut out = Vec::with_capacity(self.pieces.len() + new.len() + 1);
        let mut acc = 0u64;
        let mut inserted = false;

        for p in &self.pieces {
            let (ps, pe) = (acc, acc + p.len);
            acc = pe;
            if !inserted && offset < pe {
                let cut = offset - ps;
                if cut > 0 {
                    out.push(Piece { len: cut, ..*p });
                }
                out.extend(new.iter().copied().filter(|p| p.len > 0));
                inserted = true;
                if p.len > cut {
                    out.push(Piece { store: p.store, offset: p.offset + cut, len: p.len - cut });
                }
                continue;
            }
            out.push(*p);
        }
        if !inserted {
            // offset == self.len: append at the end.
            out.extend(new.iter().copied().filter(|p| p.len > 0));
        }

        self.pieces = out;
        self.len += added;
    }

    /// Removes `len` bytes starting at `offset` and returns the removed pieces,
    /// already clipped. Keeping them is what makes undo cheap: undoing a delete
    /// is a `splice` of those same pieces back in, without copying bytes.
    pub fn delete(&mut self, offset: u64, len: u64) -> Vec<Piece> {
        assert!(offset + len <= self.len, "delete outside the document");
        if len == 0 {
            return Vec::new();
        }
        let end = offset + len;
        let mut kept = Vec::with_capacity(self.pieces.len() + 1);
        let mut removed = Vec::new();
        let mut acc = 0u64;

        for p in &self.pieces {
            let (ps, pe) = (acc, acc + p.len);
            acc = pe;
            if pe <= offset || ps >= end {
                kept.push(*p);
                continue;
            }
            if ps < offset {
                kept.push(Piece { len: offset - ps, ..*p });
            }
            let (rs, re) = (offset.max(ps), end.min(pe));
            removed.push(Piece { store: p.store, offset: p.offset + (rs - ps), len: re - rs });
            if pe > end {
                kept.push(Piece { store: p.store, offset: p.offset + (end - ps), len: pe - end });
            }
        }

        self.pieces = kept;
        self.len -= len;
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn orig(offset: u64, len: u64) -> Piece {
        Piece { store: StoreId::Original, offset, len }
    }
    fn add(offset: u64, len: u64) -> Piece {
        Piece { store: StoreId::Added, offset, len }
    }

    #[test]
    fn a_new_table_has_one_piece() {
        let t = PieceTable::new(100);
        assert_eq!(t.pieces(), &[orig(0, 100)]);
        assert_eq!(t.len(), 100);
    }

    #[test]
    fn an_empty_table_has_no_pieces() {
        let t = PieceTable::new(0);
        assert!(t.pieces().is_empty());
        assert!(t.is_empty());
    }

    #[test]
    fn inserting_in_the_middle_splits_the_piece() {
        let mut t = PieceTable::new(100);
        t.splice(40, &[add(0, 4)]);
        assert_eq!(t.pieces(), &[orig(0, 40), add(0, 4), orig(40, 60)]);
        assert_eq!(t.len(), 104);
    }

    #[test]
    fn inserting_at_the_start_creates_no_empty_piece() {
        let mut t = PieceTable::new(100);
        t.splice(0, &[add(0, 4)]);
        assert_eq!(t.pieces(), &[add(0, 4), orig(0, 100)]);
    }

    #[test]
    fn inserting_at_the_end_appends() {
        let mut t = PieceTable::new(100);
        t.splice(100, &[add(0, 4)]);
        assert_eq!(t.pieces(), &[orig(0, 100), add(0, 4)]);
    }

    #[test]
    fn delete_returns_the_removed_pieces() {
        let mut t = PieceTable::new(100);
        let removed = t.delete(40, 20);
        assert_eq!(removed, vec![orig(40, 20)]);
        assert_eq!(t.pieces(), &[orig(0, 40), orig(60, 40)]);
        assert_eq!(t.len(), 80);
    }

    #[test]
    fn delete_spanning_several_pieces() {
        let mut t = PieceTable::new(100);
        t.splice(50, &[add(0, 10)]); // [orig(0,50), add(0,10), orig(50,50)]
        let removed = t.delete(45, 20); // cuts orig, all of add, and part of orig
        assert_eq!(removed, vec![orig(45, 5), add(0, 10), orig(50, 5)]);
        assert_eq!(t.pieces(), &[orig(0, 45), orig(55, 45)]);
        assert_eq!(t.len(), 90);
    }

    #[test]
    fn delete_followed_by_splice_restores_the_table() {
        let mut t = PieceTable::new(100);
        t.splice(50, &[add(0, 10)]);
        let before = t.clone();
        let removed = t.delete(45, 20);
        t.splice(45, &removed);
        assert_eq!(t.len(), before.len());
        // The pieces may be fragmented differently, but the sequence of bytes
        // they reference is identical.
        assert_eq!(t.pieces_in(0..t.len()).len(), 5);
    }

    #[test]
    fn pieces_in_clips_at_the_edges() {
        let mut t = PieceTable::new(100);
        t.splice(50, &[add(0, 10)]);
        assert_eq!(t.pieces_in(45..65), vec![orig(45, 5), add(0, 10), orig(50, 5)]);
        assert_eq!(t.pieces_in(0..0), vec![]);
        assert_eq!(t.pieces_in(110..120), vec![]);
    }

    #[test]
    fn deleting_everything_empties_the_table() {
        let mut t = PieceTable::new(100);
        t.delete(0, 100);
        assert!(t.is_empty());
        assert!(t.pieces().is_empty());
    }
}
