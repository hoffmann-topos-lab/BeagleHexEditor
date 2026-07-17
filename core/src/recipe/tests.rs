use super::*;
use crate::document::Document;
use crate::source::MemSource;

fn hx(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn apply(spec: &str, input: &[u8]) -> Vec<u8> {
    Recipe::parse(spec).unwrap().apply(input.to_vec()).unwrap()
}

fn text(spec: &str, input: &[u8]) -> String {
    String::from_utf8(apply(spec, input)).unwrap()
}

// ---- Encodings, against canonical vectors ----

#[test]
fn base64_known_vectors_and_padding() {
    assert_eq!(text("to-base64", b"foobar"), "Zm9vYmFy");
    assert_eq!(text("to-base64", b"f"), "Zg==");
    assert_eq!(text("to-base64", b"fo"), "Zm8=");
    assert_eq!(text("to-base64", b"foo"), "Zm9v");
    assert_eq!(apply("from-base64", b"Zm9vYmFy"), b"foobar");
    // Tolerant of whitespace and missing padding.
    assert_eq!(apply("from-base64", b"Zm9v\nYmFy"), b"foobar");
    assert_eq!(apply("from-base64", b"Zg"), b"f");
}

#[test]
fn base64_url_safe_uses_dash_underscore() {
    let data = hx("fbffbf");
    assert_eq!(text("to-base64", &data), "+/+/");
    assert_eq!(text("to-base64url", &data), "-_-_");
    // The tolerant decoder accepts either alphabet.
    assert_eq!(apply("from-base64", b"-_-_"), data);
}

#[test]
fn base32_known_vector() {
    assert_eq!(text("to-base32", b"foobar"), "MZXW6YTBOI======");
    assert_eq!(apply("from-base32", b"MZXW6YTBOI======"), b"foobar");
    assert_eq!(text("to-base32", b"fo"), "MZXQ====");
}

#[test]
fn ascii85_roundtrip_and_zero_abbreviation() {
    let data = b"Man is distinguished".to_vec();
    let enc = apply("to-base85", &data);
    assert_eq!(apply("from-base85", &enc), data);
    // Four zero bytes collapse to a single 'z'.
    assert_eq!(text("to-base85", &[0, 0, 0, 0]), "z");
    assert_eq!(apply("from-base85", b"z"), vec![0, 0, 0, 0]);
}

#[test]
fn z85_rfc32_vector() {
    // RFC 32/Z85 reference: 8 bytes -> "HelloWorld".
    let data = hx("864FD26FB559F75B");
    assert_eq!(text("to-z85", &data), "HelloWorld");
    assert_eq!(apply("from-z85", b"HelloWorld"), data);
}

#[test]
fn hex_roundtrip_and_tolerant_decode() {
    assert_eq!(text("to-hex", &[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    assert_eq!(apply("from-hex", b"DE AD BE EF"), hx("deadbeef"));
    assert_eq!(apply("from-hex", b"0xDE,0xAD"), hx("dead"));
}

#[test]
fn url_encode_decode() {
    assert_eq!(text("to-url", b"a b/c?"), "a%20b%2Fc%3F");
    assert_eq!(apply("from-url", b"a%20b%2Fc%3F"), b"a b/c?");
    assert_eq!(apply("from-url", b"a+b"), b"a b");
}

// ---- Bitwise ----

#[test]
fn xor_is_its_own_inverse() {
    let data = b"secret payload".to_vec();
    let enc = apply("xor deadbeef", &data);
    assert_ne!(enc, data);
    assert_eq!(apply("xor deadbeef", &enc), data);
    // Single-byte key.
    assert_eq!(apply("xor ff", &[0x00, 0xff, 0x0f]), vec![0xff, 0x00, 0xf0]);
}

#[test]
fn add_sub_and_rotate_are_inverses() {
    let data = b"rotate me".to_vec();
    assert_eq!(apply("add 0x10 | sub 16", &data), data);
    assert_eq!(apply("rol 3 | ror 3", &data), data);
    assert_eq!(apply("not | not", &data), data);
    assert_eq!(apply("reverse | reverse", &data), data);
    assert_eq!(apply("reverse", b"abc"), b"cba");
    assert_eq!(apply("rol 1", &[0b1000_0001]), vec![0b0000_0011]);
}

// ---- Compression ----

#[test]
fn deflate_zlib_gzip_roundtrip() {
    let data = b"the quick brown fox jumps over the lazy dog. ".repeat(40);
    assert_eq!(apply("deflate | inflate", &data), data);
    assert_eq!(apply("zlib | unzlib", &data), data);
    assert_eq!(apply("gzip | gunzip", &data), data);
    // Compression actually shrinks this repetitive input.
    assert!(apply("gzip", &data).len() < data.len());
}

#[test]
fn gzip_stream_has_the_expected_framing() {
    let gz = apply("gzip", b"hello");
    assert_eq!(&gz[..3], &[0x1f, 0x8b, 0x08], "magic + DEFLATE method");
    // A non-gzip stream is rejected, not silently mishandled.
    assert!(Recipe::parse("gunzip").unwrap().apply(b"not gzip".to_vec()).is_err());
}

// ---- Crypto ----

#[test]
fn aes_ctr_matches_nist_sp800_38a_f55() {
    // AES-256-CTR, first block of the NIST reference vectors.
    let key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    let iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let pt = hx("6bc1bee22e409f96e93d7e117393172a");
    let ct = apply(&format!("aes-enc ctr {key} {iv}"), &pt);
    assert_eq!(ct, hx("601ec313775789a5b7a7f504bbf3d228"));
    // CTR is symmetric.
    assert_eq!(apply(&format!("aes-dec ctr {key} {iv}"), &ct), pt);
}

#[test]
fn aes_cbc_ecb_roundtrip_all_key_sizes() {
    let data = b"attack at dawn, or maybe not".to_vec();
    let iv = "000102030405060708090a0b0c0d0e0f";
    for key in ["00112233445566778899aabbccddeeff", // 128
                "000102030405060708090a0b0c0d0e0f1011121314151617", // 192
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"]
    {
        let ct = apply(&format!("aes-enc cbc {key} {iv}"), &data);
        assert_eq!(apply(&format!("aes-dec cbc {key} {iv}"), &ct), data);
        let ecb = apply(&format!("aes-enc ecb {key}"), &data);
        assert_eq!(apply(&format!("aes-dec ecb {key}"), &ecb), data);
    }
}

#[test]
fn aes_rejects_bad_key_and_iv_lengths() {
    assert!(Recipe::parse("aes-enc cbc 0011").unwrap().apply(b"x".to_vec()).is_err());
    // 16-byte key but a short IV for CBC.
    let r = Recipe::parse("aes-enc cbc 00112233445566778899aabbccddeeff 0011").unwrap();
    assert!(r.apply(b"x".to_vec()).is_err());
}

#[test]
fn rc4_classic_vector() {
    // Key "Key" = 4b6579, plaintext "Plaintext".
    let out = apply("rc4 4b6579", b"Plaintext");
    assert_eq!(out, hx("bbf316e8d940af0ad3"));
    // Symmetric.
    assert_eq!(apply("rc4 4b6579", &out), b"Plaintext");
}

// ---- Digests reuse F-25/F-26 ----

#[test]
fn hash_step_emits_hex_digest() {
    assert_eq!(
        text("sha256", b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(text("md5", b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(text("crc32", b"123456789"), "cbf43926");
    // Composes: hash of the decoded bytes.
    assert_eq!(
        text("from-hex | sha256", b"616263"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// ---- Pipelines and the CyberChef "magic" feel ----

#[test]
fn a_multi_step_pipeline_unwinds_a_wrapped_payload() {
    // xor -> zlib -> base64, then the exact inverse pipeline recovers it.
    let secret = b"the treasure is buried under the oak".to_vec();
    let wrapped = apply("xor cafe | zlib | to-base64", &secret);
    let recovered = apply("from-base64 | unzlib | xor cafe", &wrapped);
    assert_eq!(recovered, secret);
}

// ---- Parsing ----

#[test]
fn parse_rejects_unknown_and_empty() {
    assert!(Recipe::parse("").is_err());
    assert!(Recipe::parse("   ").is_err());
    assert!(Recipe::parse("bogus-step").is_err());
    assert!(Recipe::parse("add").is_err(), "add needs an argument");
    // A trailing pipe is tolerated (empty segment skipped).
    assert_eq!(Recipe::parse("to-hex |").unwrap().ops.len(), 1);
}

// ---- RecipeJob over a Document (F-07 discipline) ----

#[test]
fn run_applies_to_a_selection_of_the_document() {
    let mut doc = Document::new(Box::new(MemSource::new(b"xxfoobarxx".to_vec())));
    let out = run(&mut doc, 2..8, &Recipe::parse("to-base64").unwrap(), DEFAULT_CAP, &Progress::new())
        .unwrap();
    assert_eq!(out, b"Zm9vYmFy");
}

#[test]
fn run_refuses_a_selection_beyond_the_cap() {
    let mut doc = Document::new(Box::new(MemSource::new(vec![0u8; 1000])));
    let err = run(&mut doc, 0..1000, &Recipe::parse("to-hex").unwrap(), 100, &Progress::new())
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Io);
    assert!(err.detail.contains("cap"), "{}", err.detail);
}

#[test]
fn run_aborts_on_an_unreadable_block() {
    let src = MemSource::new(vec![1u8; 64]).with_bad_range(16..32);
    let mut doc = Document::new(Box::new(src));
    doc.set_cache(crate::cache::BlockCache::new(16, 8));
    let err = run(&mut doc, 0..64, &Recipe::parse("to-hex").unwrap(), DEFAULT_CAP, &Progress::new())
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::BadBlock);
}

#[test]
fn the_recipe_sees_unsaved_edits() {
    let mut doc = Document::new(Box::new(MemSource::new(b"abd".to_vec())));
    doc.overwrite(2, b"c").unwrap();
    let out = run(&mut doc, 0..3, &Recipe::parse("sha256").unwrap(), DEFAULT_CAP, &Progress::new())
        .unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
