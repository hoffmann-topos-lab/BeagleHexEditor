use super::*;
use crate::charset::Charset;
use crate::document::Document;
use crate::inspector::Endian;
use crate::progress::Progress;
use crate::source::MemSource;

fn doc(bytes: &[u8]) -> Document {
    Document::new(Box::new(MemSource::new(bytes.to_vec())))
}

fn all_bytes(d: &mut Document) -> Vec<u8> {
    d.read(0, d.len() as usize).data
}

fn hex(s: &str) -> Pattern {
    Pattern::parse_hex(s).unwrap()
}

fn next(d: &mut Document, p: &Pattern, from: u64) -> Option<u64> {
    find_next(d, p, 0..d.len(), from, false, false, &Progress::new()).map(|r| r.start)
}

#[test]
fn parse_hex_with_wildcards() {
    assert_eq!(
        hex("DE ?? BE EF"),
        Pattern::Bytes {
            bytes: vec![0xDE, 0x00, 0xBE, 0xEF],
            mask: vec![0xFF, 0x00, 0xFF, 0xFF],
            ci: false
        }
    );
    assert_eq!(
        hex("D? ?E"),
        Pattern::Bytes { bytes: vec![0xD0, 0x0E], mask: vec![0xF0, 0x0F], ci: false }
    );
    assert!(Pattern::parse_hex("????").is_none(), "wildcards only would match everything");
    assert!(Pattern::parse_hex("ABC").is_none());
    assert!(Pattern::parse_hex("").is_none());
}

#[test]
fn a_simple_forward_and_backward_search() {
    let mut d = doc(b"xxABxxABxx");
    let p = hex("4142"); // "AB"
    assert_eq!(next(&mut d, &p, 0), Some(2));
    assert_eq!(next(&mut d, &p, 3), Some(6));
    assert_eq!(next(&mut d, &p, 7), None);
    let prev = |d: &mut Document, from| {
        find_next(d, &p, 0..d.len(), from, true, false, &Progress::new()).map(|r| r.start)
    };
    assert_eq!(prev(&mut d, 10), Some(6));
    assert_eq!(prev(&mut d, 6), Some(2), "candidates strictly before `from`");
    assert_eq!(prev(&mut d, 2), None);
}

#[test]
fn wrap_finds_matches_before_and_across_the_origin() {
    let mut d = doc(b"ABxxxxxx");
    let p = hex("4142");
    let r = find_next(&mut d, &p, 0..8, 4, false, true, &Progress::new());
    assert_eq!(r, Some(0..2), "wrap returns to the start");
    // A match crossing the origin: starts before, ends after.
    let mut d = doc(b"xxABxx");
    let r = find_next(&mut d, &p, 0..6, 3, false, true, &Progress::new());
    assert_eq!(r, Some(2..4));
    // Without wrap, nothing.
    assert_eq!(find_next(&mut d, &p, 0..6, 3, false, false, &Progress::new()), None);
    // Backward wrap: origin 1, the match lies only above it.
    let mut d = doc(b"xxxxABxx");
    let r = find_next(&mut d, &p, 0..8, 1, true, true, &Progress::new());
    assert_eq!(r, Some(4..6));
}

#[test]
fn matches_do_not_overlap() {
    let mut d = doc(b"AAAAA");
    let (found, trunc) =
        find_all(&mut d, &hex("4141"), 0..5, 100, &Progress::new());
    assert_eq!(found, vec![0, 2], "AAAAA has two matches of AA, not four");
    assert!(!trunc);
}

#[test]
fn small_windows_do_not_miss_a_match_on_the_boundary() {
    // A 3-byte pattern crossing every possible window boundary.
    let mut data = vec![0u8; 64];
    for at in [0usize, 3, 6, 30, 61] {
        data[at..at + 3].copy_from_slice(b"XYZ");
    }
    let mut d = doc(&data);
    let mut s = Searcher::new(hex("58595A"), 0..64, 64, 0, false, false);
    let mut out = Vec::new();
    loop {
        // minimum budget: candidate windows of 1 byte
        if s.step(&mut d, 1, &mut out).finished {
            break;
        }
    }
    assert_eq!(out, vec![0, 3, 6, 30, 61]);
}

#[test]
fn wildcards_and_nibble_masks() {
    let mut d = doc(&[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0x77, 0xBE, 0xEF]);
    let (found, _) = find_all(&mut d, &hex("DE ?? BE EF"), 0..8, 10, &Progress::new());
    assert_eq!(found, vec![0, 4]);
    // Nibble: "?E" does not match AD; it does match DE and BE.
    let (found, _) = find_all(&mut d, &hex("?E"), 0..8, 10, &Progress::new());
    assert_eq!(found, vec![0, 2, 4, 6]);
}

#[test]
fn text_with_and_without_case_sensitivity() {
    let mut d = doc(b"Hello hELLo hello");
    let p = Pattern::text("hello", Charset::Ascii, false).unwrap();
    let (found, _) = find_all(&mut d, &p, 0..17, 10, &Progress::new());
    assert_eq!(found, vec![12]);
    let p = Pattern::text("hello", Charset::Ascii, true).unwrap();
    let (found, _) = find_all(&mut d, &p, 0..17, 10, &Progress::new());
    assert_eq!(found, vec![0, 6, 12]);
}

#[test]
fn text_in_utf16le() {
    // "AB" in UTF-16LE
    let mut d = doc(&[0x00, 0x41, 0x00, 0x42, 0x00, 0x41, 0x00]);
    let p = Pattern::text("A", Charset::Utf16Le, false).unwrap();
    let (found, _) = find_all(&mut d, &p, 0..7, 10, &Progress::new());
    assert_eq!(found, vec![1, 5], "41 00 at positions 1 and 5");
}

#[test]
fn a_search_restricted_to_a_range() {
    let mut d = doc(b"ABxxABxxAB");
    let p = hex("4142");
    let (found, _) = find_all(&mut d, &p, 3..9, 10, &Progress::new());
    assert_eq!(found, vec![4], "only the match entirely inside 3..9");
}

#[test]
fn an_unreadable_block_never_matches() {
    let src = MemSource::new(vec![0u8; 64]).with_bad_range(16..32);
    let mut d = Document::new(Box::new(src));
    d.set_cache(crate::cache::BlockCache::new(16, 8));
    // Real zeros exist outside the bad block; inside it, they are invented.
    let (found, _) = find_all(&mut d, &hex("0000"), 0..64, 100, &Progress::new());
    assert!(found.iter().all(|at| *at + 2 <= 16 || *at >= 32), "{found:?}");
    assert!(!found.is_empty());
}

#[test]
fn typed_search_for_ints_and_floats() {
    let mut data = 1234i32.to_le_bytes().to_vec();
    data.extend_from_slice(&2.75f32.to_le_bytes());
    data.extend_from_slice(&1234i32.to_be_bytes());
    let mut d = doc(&data);

    let p = Pattern::typed("i32", "1234", Endian::Little, None).unwrap();
    let (found, _) = find_all(&mut d, &p, 0..12, 10, &Progress::new());
    assert_eq!(found, vec![0]);
    let p = Pattern::typed("i32", "1234", Endian::Big, None).unwrap();
    let (found, _) = find_all(&mut d, &p, 0..12, 10, &Progress::new());
    assert_eq!(found, vec![8]);
    // Float with a tolerance: 2.7501 is not 2.75, but with tol 0.05 it matches.
    let p = Pattern::typed("f32", "2.7501", Endian::Little, Some(0.05)).unwrap();
    let (found, _) = find_all(&mut d, &p, 0..12, 10, &Progress::new());
    assert_eq!(found, vec![4]);
    let p = Pattern::typed("f32", "2.7501", Endian::Little, Some(0.00001)).unwrap();
    let (found, _) = find_all(&mut d, &p, 0..12, 10, &Progress::new());
    assert!(found.is_empty(), "a tight tolerance does not match 2.75");
}

#[test]
fn replace_all_of_equal_length_is_a_single_undo() {
    let mut d = doc(b"xxABxxABxx");
    let n = replace_all(&mut d, &hex("4142"), b"CD", 0..10, &Progress::new()).unwrap();
    assert_eq!(n, 2);
    assert_eq!(all_bytes(&mut d), b"xxCDxxCDxx");
    assert!(d.undo());
    assert_eq!(all_bytes(&mut d), b"xxABxxABxx");
    assert!(!d.can_undo(), "replacing everything is one transaction");
}

#[test]
fn replace_all_changes_the_size_without_losing_the_rest() {
    let mut d = doc(b"a<>b<>c");
    let n = replace_all(&mut d, &hex("3C3E"), b"---", 0..7, &Progress::new()).unwrap();
    assert_eq!(n, 2);
    assert_eq!(all_bytes(&mut d), b"a---b---c");
    // Shrinking (an empty replacement = deleting the matches).
    let mut d = doc(b"a<>b<>c");
    let n = replace_all(&mut d, &hex("3C3E"), b"", 0..7, &Progress::new()).unwrap();
    assert_eq!(n, 2);
    assert_eq!(all_bytes(&mut d), b"abc");
    assert!(d.undo());
    assert_eq!(all_bytes(&mut d), b"a<>b<>c");
}

#[test]
fn replace_all_does_not_reprocess_the_replacement() {
    // The replacement contains the pattern: it must not loop forever.
    let mut d = doc(b"ab");
    let n = replace_all(&mut d, &hex("6162"), b"abab", 0..2, &Progress::new()).unwrap();
    assert_eq!(n, 1);
    assert_eq!(all_bytes(&mut d), b"abab");
}

#[test]
fn replace_all_cancelled_upfront_does_not_touch_the_document() {
    let mut d = doc(b"xxABxx");
    let p = Progress::new();
    p.cancel();
    let n = replace_all(&mut d, &hex("4142"), b"CD", 0..6, &p).unwrap();
    assert_eq!(n, 0);
    assert!(!d.dirty());
}
