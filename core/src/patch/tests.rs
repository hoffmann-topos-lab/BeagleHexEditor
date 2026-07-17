use super::*;
use crate::source::MemSource;

fn doc(bytes: Vec<u8>) -> Document {
    Document::new(Box::new(MemSource::new(bytes)))
}

/// A minimal PE shell: MZ, `e_lfanew` = 64, PE signature, a PE32+ optional-header
/// magic, non-trivial content, and a CheckSum field (at 152) starting at 0.
fn minimal_pe() -> Vec<u8> {
    let mut v = vec![0u8; 512];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());
    v[64..68].copy_from_slice(b"PE\0\0");
    v[88..90].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    for (i, b) in v.iter_mut().enumerate().skip(160) {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    v
}

#[test]
fn pe_checksum_locates_the_field_and_is_stale_when_zero() {
    let mut d = doc(minimal_pe());
    let c = pe_checksum(&mut d, &Progress::new()).unwrap();
    assert_eq!(c.field_offset, 152);
    assert_ne!(c.computed, 0, "non-trivial content yields a non-zero checksum");
    assert_eq!(c.stored, 0);
    assert!(!c.matches());
}

#[test]
fn writing_the_computed_value_makes_it_validate() {
    let mut d = doc(minimal_pe());
    let c = pe_checksum(&mut d, &Progress::new()).unwrap();
    d.overwrite(c.field_offset, &c.computed.to_le_bytes()).unwrap();

    // Recomputing (the field is zeroed internally, so the value is stable) now agrees.
    let c2 = pe_checksum(&mut d, &Progress::new()).unwrap();
    assert_eq!(c2.stored, c.computed);
    assert!(c2.matches(), "the fixed checksum verifies");
}

#[test]
fn the_field_content_does_not_affect_the_computed_value() {
    let mut base = minimal_pe();
    let mut a = doc(base.clone());
    let ca = pe_checksum(&mut a, &Progress::new()).unwrap().computed;
    // Put garbage in the CheckSum field: the computed value must be unchanged.
    base[152..156].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let mut b = doc(base);
    let cb = pe_checksum(&mut b, &Progress::new()).unwrap().computed;
    assert_eq!(ca, cb);
}

#[test]
fn rejects_a_non_pe() {
    let mut d = doc(vec![0u8; 64]);
    assert!(pe_checksum(&mut d, &Progress::new()).is_err());
}
