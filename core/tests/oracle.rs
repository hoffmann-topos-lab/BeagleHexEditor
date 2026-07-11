//! F-09 — Differential test against a naive oracle.
//!
//! The piece table exists to be fast. A `Vec<u8>` exists to be obviously
//! correct. Here we apply the same random sequence of operations to both and
//! demand that the content be identical after every step.
//!
//! The undo/redo oracle is a linear history of complete states: exactly the
//! semantics the user expects from Ctrl+Z, and far too expensive to be the real
//! implementation.

use hexed_core::{Document, FillPattern, MemSource, Pattern, Progress, Searcher};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    Insert(usize, Vec<u8>),
    Delete(usize, usize),
    Overwrite(usize, Vec<u8>),
    Fill(usize, usize, Vec<u8>),
    Undo,
    Redo,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0usize..64, prop::collection::vec(any::<u8>(), 1..12)).prop_map(|(p, d)| Op::Insert(p, d)),
        3 => (0usize..64, 1usize..12).prop_map(|(p, n)| Op::Delete(p, n)),
        3 => (0usize..64, prop::collection::vec(any::<u8>(), 1..12)).prop_map(|(p, d)| Op::Overwrite(p, d)),
        2 => (0usize..64, 1usize..24, prop::collection::vec(any::<u8>(), 1..4)).prop_map(|(p, n, pat)| Op::Fill(p, n, pat)),
        2 => Just(Op::Undo),
        2 => Just(Op::Redo),
    ]
}

/// Oracle: `history[cursor]` is the current content.
struct Oracle {
    history: Vec<Vec<u8>>,
    cursor: usize,
}

impl Oracle {
    fn new(initial: Vec<u8>) -> Self {
        Self { history: vec![initial], cursor: 0 }
    }

    fn current(&self) -> &Vec<u8> {
        &self.history[self.cursor]
    }

    fn commit(&mut self, next: Vec<u8>) {
        self.history.truncate(self.cursor + 1);
        self.history.push(next);
        self.cursor += 1;
    }

    fn undo(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        self.cursor -= 1;
        true
    }

    fn redo(&mut self) -> bool {
        if self.cursor + 1 >= self.history.len() {
            return false;
        }
        self.cursor += 1;
        true
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn the_piece_table_agrees_with_the_oracle(
        initial in prop::collection::vec(any::<u8>(), 0..40),
        ops in prop::collection::vec(op_strategy(), 1..60),
    ) {
        let mut doc = Document::new(Box::new(MemSource::new(initial.clone())));
        let mut oracle = Oracle::new(initial);

        for op in ops {
            let cur = oracle.current().clone();
            match op {
                Op::Insert(pos, data) => {
                    let pos = pos.min(cur.len());
                    doc.insert(pos as u64, &data).unwrap();
                    let mut next = cur;
                    next.splice(pos..pos, data);
                    oracle.commit(next);
                }
                Op::Delete(pos, n) => {
                    // Clip into the document; an empty delete is a no-op on
                    // both sides, so we never even record it.
                    let pos = pos.min(cur.len());
                    let n = n.min(cur.len() - pos);
                    if n == 0 { continue; }
                    doc.delete(pos as u64, n as u64).unwrap();
                    let mut next = cur;
                    next.drain(pos..pos + n);
                    oracle.commit(next);
                }
                Op::Overwrite(pos, data) => {
                    let pos = pos.min(cur.len());
                    doc.overwrite(pos as u64, &data).unwrap();
                    let mut next = cur;
                    let end = (pos + data.len()).min(next.len());
                    next.splice(pos..end, data);
                    oracle.commit(next);
                }
                Op::Fill(pos, n, pattern) => {
                    // Clip into the document (fill does not extend it).
                    let pos = pos.min(cur.len());
                    let n = n.min(cur.len() - pos);
                    if n == 0 { continue; }
                    doc.fill(pos as u64, n as u64, &FillPattern::Repeat(pattern.clone())).unwrap();
                    let mut next = cur;
                    for i in 0..n {
                        next[pos + i] = pattern[i % pattern.len()];
                    }
                    oracle.commit(next); // a single undo transaction
                }
                Op::Undo => {
                    prop_assert_eq!(doc.undo(), oracle.undo());
                }
                Op::Redo => {
                    prop_assert_eq!(doc.redo(), oracle.redo());
                }
            }

            prop_assert_eq!(doc.len(), oracle.current().len() as u64);
            let got = doc.read(0, doc.len() as usize);
            prop_assert!(got.is_clean());
            prop_assert_eq!(&got.data, oracle.current());
        }
    }

    /// Reading an arbitrary slice must equal slicing the full read.
    #[test]
    fn a_partial_read_matches_the_full_read(
        initial in prop::collection::vec(any::<u8>(), 1..80),
        inserts in prop::collection::vec((0usize..80, prop::collection::vec(any::<u8>(), 1..8)), 0..10),
        start in 0usize..80,
        len in 0usize..80,
    ) {
        let mut doc = Document::new(Box::new(MemSource::new(initial)));
        for (pos, data) in inserts {
            let pos = (pos as u64).min(doc.len());
            doc.insert(pos, &data).unwrap();
        }

        let full = doc.read(0, doc.len() as usize).data;
        let start = start.min(full.len());
        let end = (start + len).min(full.len());

        let part = doc.read(start as u64, len);
        prop_assert_eq!(&part.data, &full[start..end]);
    }

    /// Non-overlapping search agrees with a naive scan, even with tiny
    /// windows (boundaries everywhere).
    #[test]
    fn search_agrees_with_the_oracle(
        hay in prop::collection::vec(0u8..4, 0..120),
        pat in prop::collection::vec(0u8..4, 1..5),
        budget in 1u64..16,
    ) {
        // Oracle: left-to-right scan, skipping the pattern.
        let mut naive = Vec::new();
        let mut i = 0;
        while i + pat.len() <= hay.len() {
            if hay[i..i + pat.len()] == pat[..] {
                naive.push(i as u64);
                i += pat.len();
            } else {
                i += 1;
            }
        }

        let mut doc = Document::new(Box::new(MemSource::new(hay.clone())));
        let pattern = Pattern::bytes(pat.clone()).unwrap();

        // The blocking find_all…
        let len = doc.len();
        let (found, trunc) =
            hexed_core::find_all(&mut doc, &pattern, 0..len, usize::MAX, &Progress::new());
        prop_assert!(!trunc);
        prop_assert_eq!(&found, &naive);

        // …and the same result with arbitrary-budget stepping (which is what
        // the GUI does, one window per frame).
        let len = doc.len();
        let mut s = Searcher::new(pattern, 0..len, len, 0, false, false);
        let mut stepped = Vec::new();
        while !s.step(&mut doc, budget, &mut stepped).finished {}
        prop_assert_eq!(&stepped, &naive);
    }

    /// Replace-all agrees with the naive replace and is a single undo.
    #[test]
    fn replace_agrees_with_the_oracle(
        hay in prop::collection::vec(0u8..4, 0..120),
        pat in prop::collection::vec(0u8..4, 1..4),
        repl in prop::collection::vec(0u8..4, 0..6),
    ) {
        // Oracle: rebuild the vector, without overlap.
        let mut expect = Vec::new();
        let mut count = 0u64;
        let mut i = 0;
        while i < hay.len() {
            if i + pat.len() <= hay.len() && hay[i..i + pat.len()] == pat[..] {
                expect.extend_from_slice(&repl);
                count += 1;
                i += pat.len();
            } else {
                expect.push(hay[i]);
                i += 1;
            }
        }

        let mut doc = Document::new(Box::new(MemSource::new(hay.clone())));
        let pattern = Pattern::bytes(pat).unwrap();
        let len = doc.len();
        let n = hexed_core::replace_all(&mut doc, &pattern, &repl, 0..len, &Progress::new())
            .unwrap();
        prop_assert_eq!(n, count);
        prop_assert_eq!(doc.read(0, doc.len() as usize).data, expect);

        // Atomic undo (F-28): a single Ctrl+Z restores everything.
        if n > 0 {
            prop_assert!(doc.undo());
            prop_assert_eq!(doc.read(0, doc.len() as usize).data, hay);
            prop_assert!(!doc.can_undo());
        }
    }

    /// Undoing everything must rebuild exactly the original content.
    #[test]
    fn a_full_undo_restores_the_original(
        initial in prop::collection::vec(any::<u8>(), 0..40),
        ops in prop::collection::vec(op_strategy(), 1..30),
    ) {
        let mut doc = Document::new(Box::new(MemSource::new(initial.clone())));
        for op in ops {
            let len = doc.len();
            match op {
                Op::Insert(p, d) => { doc.insert((p as u64).min(len), &d).unwrap(); }
                Op::Delete(p, n) => {
                    let p = (p as u64).min(len);
                    let n = (n as u64).min(len - p);
                    if n > 0 { doc.delete(p, n).unwrap(); }
                }
                Op::Overwrite(p, d) => { doc.overwrite((p as u64).min(len), &d).unwrap(); }
                Op::Fill(p, n, pat) => {
                    let p = (p as u64).min(len);
                    let n = (n as u64).min(len - p);
                    if n > 0 { doc.fill(p, n, &FillPattern::Repeat(pat)).unwrap(); }
                }
                _ => {}
            }
        }
        while doc.undo() {}
        prop_assert_eq!(doc.read(0, doc.len() as usize).data, initial);
    }
}
