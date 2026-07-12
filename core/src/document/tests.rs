use super::*;
use crate::cache::BlockCache;
use crate::error::ErrorKind;
use crate::source::{DataSource, MemSource};

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
        fn read_at(&self, o: u64, b: &mut [u8]) -> crate::error::Result<()> {
            self.0.read_at(o, b)
        }
        fn write_at(&self, o: u64, b: &[u8]) -> crate::error::Result<()> {
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
fn redo_after_undo_tolerates_refragmented_pieces() {
    // An undo splices deleted pieces back as standalone fragments, finer than
    // the original table. A redo of a later delete then removes the same bytes
    // split differently — this must not trip the redo consistency check.
    let mut d = doc(b"");
    d.insert(0, b"abcd").unwrap(); // one piece: Added(0,4)
    d.delete(1, 2).unwrap(); // splits it
    assert!(d.undo()); // content back, but as 3 fragments
    d.delete(0, 4).unwrap(); // records the 3 fragments
    assert!(d.undo());
    assert!(d.undo());
    assert_eq!(all(&mut d), b"");
    assert!(d.redo()); // reinserts Added(0,4) whole
    assert!(d.redo()); // redo of delete sees 1 piece where 3 were recorded
    assert_eq!(all(&mut d), b"");
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
    let len = fill::FILL_CHUNK * 2 + 5;
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
fn save_as_preserves_the_permissions_of_an_existing_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("output.bin");
    std::fs::write(&out, b"old").unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut d = doc(b"new content");
    d.save_as(&out).unwrap();

    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "the tempfile's 0600 must not replace the file's mode");
    assert_eq!(std::fs::read(&out).unwrap(), b"new content");
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
