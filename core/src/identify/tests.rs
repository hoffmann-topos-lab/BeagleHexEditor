//! F-73/F-74/F-75 tests. The passes take a `BinaryInfo` + bytes, so the fixtures
//! build `BinaryInfo` directly (public fields) over a `MemSource` — no need to
//! reconstruct a whole ELF/PE image, and each trait can be exercised in isolation.

use std::ops::Range;

use super::*;
use crate::document::Document;
use crate::format::{Arch, BinaryInfo, Bits, ExtraEntry, Format, Import, Node, Perms, Section};
use crate::inspector::Endian;
use crate::progress::Progress;
use crate::source::MemSource;

fn perms(r: bool, w: bool, x: bool) -> Perms {
    Perms { r, w, x }
}

fn section(name: &str, file: Range<u64>, vaddr: u64, size: u64, p: Perms) -> Section {
    Section { name: name.to_string(), file, vaddr, size, perms: p }
}

fn import(library: &str, name: &str) -> Import {
    Import { library: library.to_string(), name: name.to_string(), ordinal: None }
}

/// A `BinaryInfo` skeleton; callers override the fields their test cares about.
fn info(format: Format) -> BinaryInfo {
    BinaryInfo {
        format,
        arch: Arch::X86_64,
        bits: Bits::B64,
        endian: Endian::Little,
        entry: 0,
        sections: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        libs: Vec::new(),
        relocs: Vec::new(),
        extra_entries: Vec::new(),
        tree: Node::group("root", 0..0, Vec::new()),
    }
}

fn doc(bytes: Vec<u8>) -> Document {
    Document::new(Box::new(MemSource::new(bytes)))
}

// ---- F-73: signatures ----

#[test]
fn a_upx_section_names_the_packer() {
    let mut info = info(Format::Pe);
    info.sections = vec![section("UPX0", 0..0, 0x1000, 0x2000, perms(true, true, false))];
    let mut d = doc(vec![0u8; 16]);
    let found = signatures::detect(&mut d, &info);
    assert!(found.iter().any(|x| x.kind == IdKind::Packer && x.name == "UPX"), "{found:?}");
}

#[test]
fn the_msvc_runtime_library_names_the_compiler() {
    let mut info = info(Format::Pe);
    info.libs = vec!["VCRUNTIME140.dll".to_string(), "KERNEL32.dll".to_string()];
    let mut d = doc(vec![0u8; 16]);
    let found = signatures::detect(&mut d, &info);
    assert!(found.iter().any(|x| x.name == "Microsoft Visual C/C++"), "{found:?}");
}

#[test]
fn an_elf_comment_yields_the_compiler_and_version() {
    let comment = b"\0GCC: (Ubuntu 13.2.0-4) 13.2.0\0";
    let mut d = doc(comment.to_vec());
    let mut info = info(Format::Elf);
    info.sections =
        vec![section(".comment", 0..comment.len() as u64, 0, comment.len() as u64, perms(false, false, false))];
    let found = signatures::detect(&mut d, &info);
    let gcc = found.iter().find(|x| x.name == "GCC").expect("GCC detected");
    assert!(gcc.details.contains("13.2.0"), "{:?}", gcc.details);
}

#[test]
fn a_dotnet_entry_import_is_identified() {
    let mut info = info(Format::Pe);
    info.imports = vec![import("mscoree.dll", "_CorExeMain")];
    let mut d = doc(vec![0u8; 16]);
    let found = signatures::detect(&mut d, &info);
    assert!(found.iter().any(|x| x.name == ".NET"), "{found:?}");
}

// ---- F-74: entropy / packing ----

/// A document whose `[0, len)` bytes cycle 0..=255 (entropy ~8) after `pad`
/// leading zeros — a stand-in for a compressed/encrypted section.
fn high_entropy_doc(pad: usize, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; pad];
    v.extend((0..len).map(|i| (i % 256) as u8));
    v
}

#[test]
fn a_high_entropy_executable_section_reads_as_packed() {
    let bytes = high_entropy_doc(0, 8192);
    let mut d = doc(bytes);
    let mut info = info(Format::Elf);
    info.sections = vec![section(".text", 0..8192, 0x1000, 0x2000, perms(true, false, true))];
    let report = entropy::report(&mut d, &info, &Progress::new());
    assert!(report.likely_packed, "{:?}", report.reasons);
    assert!(report.sections[0].entropy > 7.5);
    assert!(report.reasons.iter().any(|r| r.contains("high entropy")));
}

#[test]
fn ordinary_low_entropy_code_is_not_packed() {
    let mut d = doc(vec![0x90u8; 8192]); // all NOPs: entropy 0
    let mut info = info(Format::Elf);
    info.sections = vec![section(".text", 0..8192, 0x1000, 0x2000, perms(true, false, true))];
    let report = entropy::report(&mut d, &info, &Progress::new());
    assert!(!report.likely_packed, "{:?}", report.reasons);
    assert_eq!(report.sections[0].entropy, 0.0);
}

#[test]
fn a_high_entropy_pe_overlay_is_measured() {
    // section covers 0..1024 of NOPs; the overlay is 1024..end of cycling bytes.
    let mut bytes = vec![0x90u8; 1024];
    bytes.extend((0..8192).map(|i| (i % 256) as u8));
    let mut d = doc(bytes);
    let mut info = info(Format::Pe);
    info.sections = vec![section(".text", 0..1024, 0x1000, 0x1000, perms(true, false, true))];
    let report = entropy::report(&mut d, &info, &Progress::new());
    let (size, e) = report.overlay.expect("overlay present");
    assert_eq!(size, 8192);
    assert!(e > 7.5, "overlay entropy {e}");
    assert!(report.reasons.iter().any(|r| r.contains("overlay")));
}

// ---- F-75: indicators ----

fn scan(info: &BinaryInfo, d: &mut Document) -> Vec<Indicator> {
    let packing = entropy::report(d, info, &Progress::new());
    indicators::scan(d, info, &packing, &Progress::new())
}

#[test]
fn a_suspicious_import_is_flagged() {
    let mut info = info(Format::Pe);
    info.imports = vec![import("KERNEL32.dll", "VirtualAllocEx"), import("KERNEL32.dll", "lstrlenA")];
    let mut d = doc(vec![0u8; 16]);
    let found = scan(&info, &mut d);
    let hit = found.iter().find(|i| i.category == "import").expect("import flagged");
    assert!(hit.detail.contains("VirtualAllocEx"));
    assert_eq!(hit.severity, Severity::Suspicious);
    // a benign import is not flagged
    assert!(!found.iter().any(|i| i.detail.contains("lstrlen")));
}

#[test]
fn the_ansi_wide_suffix_is_stripped_when_matching() {
    let mut info = info(Format::Pe);
    info.imports = vec![import("KERNEL32.dll", "CreateProcessW")];
    let mut d = doc(vec![0u8; 16]);
    let found = scan(&info, &mut d);
    assert!(found.iter().any(|i| i.detail.contains("CreateProcessW") && i.detail.contains("spawns")));
}

#[test]
fn a_posix_import_is_flagged_after_underscore_strip() {
    let mut info = info(Format::MachO);
    info.imports = vec![import("/usr/lib/libSystem.B.dylib", "_ptrace")];
    let mut d = doc(vec![0u8; 16]);
    let found = scan(&info, &mut d);
    assert!(found.iter().any(|i| i.detail.contains("_ptrace") && i.detail.contains("anti-debug")));
}

#[test]
fn a_writable_executable_section_is_flagged() {
    let mut info = info(Format::Pe);
    info.sections = vec![section(".text", 0..16, 0x1000, 0x1000, perms(true, true, true))];
    let mut d = doc(vec![0u8; 16]);
    let found = scan(&info, &mut d);
    assert!(found.iter().any(|i| i.category == "section" && i.detail.contains("W^X")));
}

#[test]
fn an_entry_point_outside_every_section_is_flagged() {
    let mut info = info(Format::Pe);
    info.entry = 0x9999;
    info.sections = vec![section(".text", 0..16, 0x1000, 0x100, perms(true, false, true))];
    let mut d = doc(vec![0u8; 16]);
    let found = scan(&info, &mut d);
    assert!(found
        .iter()
        .any(|i| i.category == "header" && i.detail.contains("not inside any section")));
}

#[test]
fn tls_callbacks_are_flagged() {
    let mut info = info(Format::Pe);
    info.extra_entries = vec![ExtraEntry { kind: "TLS callback", vaddr: 0x140001000 }];
    let mut d = doc(vec![0u8; 16]);
    let found = scan(&info, &mut d);
    assert!(found.iter().any(|i| i.category == "tls" && i.detail.contains("TLS callback")));
}

#[test]
fn ioc_strings_surface_urls_and_lolbins() {
    let mut payload = b"harmless text ".to_vec();
    payload.extend_from_slice(b"connect to http://evil.example.com/beacon then run ");
    payload.extend_from_slice(b"powershell -enc AAAA and phone home to 203.0.113.7\0");
    let mut d = doc(payload);
    let info = info(Format::Pe);
    let found = scan(&info, &mut d);
    assert!(found.iter().any(|i| i.detail == "URL: http://evil.example.com/beacon"), "{found:?}");
    assert!(found.iter().any(|i| i.detail.contains("powershell")), "{found:?}");
    assert!(found.iter().any(|i| i.detail == "IPv4: 203.0.113.7"), "{found:?}");
}

// ---- orchestration ----

#[test]
fn analyze_runs_every_pass() {
    let bytes = high_entropy_doc(0, 8192);
    let mut d = doc(bytes);
    let mut info = info(Format::Pe);
    info.sections = vec![section("UPX1", 0..8192, 0x1000, 0x2000, perms(true, false, true))];
    info.imports = vec![import("KERNEL32.dll", "VirtualAlloc")];
    let report = analyze(&mut d, &info, &Progress::new());
    assert!(report.detections.iter().any(|d| d.name == "UPX"));
    assert!(report.packing.likely_packed);
    assert!(report.indicators.iter().any(|i| i.category == "import"));
}
