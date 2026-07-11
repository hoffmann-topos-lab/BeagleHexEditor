//! F-09, scenario 5 of the validation suite: robustness on a huge file.
//!
//! This is the piece table's reason to exist. An editor that loads the file
//! into a `bytearray` fails here for lack of RAM; one that uses `mmap` fails on
//! the insertion, because shifting 100 GB to make room for 1 byte is unfeasible.
//!
//! Ignored by default: it creates a 100 GB sparse file. It consumes no real
//! space, but it does require a filesystem that supports sparseness (APFS,
//! ext4, btrfs, XFS — all of them do).
//!
//!     cargo test --test huge_file -- --ignored --nocapture

use std::time::Instant;

use hexed_core::Document;

const ONE_HUNDRED_GB: u64 = 100 * 1024 * 1024 * 1024;
const SIXTY_FOUR_GB: u64 = 64 * 1024 * 1024 * 1024;

#[test]
#[ignore = "creates a 100 GB sparse file"]
fn editing_a_100gb_file_is_instantaneous() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.bin");

    let file = std::fs::File::create(&path).unwrap();
    file.set_len(ONE_HUNDRED_GB).unwrap();
    drop(file);

    let t = Instant::now();
    let mut doc = Document::open(&path, false).unwrap();
    let opening = t.elapsed();
    assert_eq!(doc.len(), ONE_HUNDRED_GB);

    // The operation that kills the naive architectures.
    let t = Instant::now();
    doc.insert(0, b"X").unwrap();
    let insertion = t.elapsed();
    assert_eq!(doc.len(), ONE_HUNDRED_GB + 1);

    // One extra byte at the start: everything after it shifts, without touching disk.
    let t = Instant::now();
    let r = doc.read(SIXTY_FOUR_GB, 8);
    let reading = t.elapsed();
    assert!(r.is_clean());

    // Deleting in the middle is cheap too, and it fragments the table.
    let t = Instant::now();
    doc.delete(SIXTY_FOUR_GB, 4096).unwrap();
    let deletion = t.elapsed();
    assert_eq!(doc.len(), ONE_HUNDRED_GB + 1 - 4096);

    // Undoing everything restores the original size.
    while doc.undo() {}
    assert_eq!(doc.len(), ONE_HUNDRED_GB);

    eprintln!("opening:   {opening:?}");
    eprintln!("insertion: {insertion:?}");
    eprintln!("reading:   {reading:?}");
    eprintln!("deletion:  {deletion:?}");
    eprintln!("final pieces: {}", doc.pieces().len());

    // Generous limits. The point is not the exact number, it is the order of
    // magnitude: nothing here may scale with the file size.
    assert!(insertion.as_millis() < 50, "insertion took {insertion:?}");
    assert!(deletion.as_millis() < 50, "deletion took {deletion:?}");
}

#[test]
#[ignore = "creates a 100 GB sparse file"]
fn a_thousand_scattered_edits_do_not_degrade() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.bin");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(ONE_HUNDRED_GB).unwrap();
    drop(file);

    let mut doc = Document::open(&path, false).unwrap();

    let t = Instant::now();
    for i in 0..1000u64 {
        doc.insert(i * 97_000_000, b"marker").unwrap();
    }
    let total = t.elapsed();

    eprintln!("1000 insertions: {total:?} ({} pieces)", doc.pieces().len());
    assert_eq!(doc.len(), ONE_HUNDRED_GB + 6 * 1000);
    assert!(total.as_millis() < 2000, "1000 insertions took {total:?}");
}
