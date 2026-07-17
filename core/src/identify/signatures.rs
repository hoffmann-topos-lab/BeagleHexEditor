//! F-73 — Signature engine: name the compiler, packer, protector, installer,
//! language runtime or key library, in the spirit of Detect It Easy.
//!
//! High-signal, hand-curated rules over facts the parsers already produced —
//! section names, imported libraries/functions — plus a few targeted reads
//! (ELF `.comment` for the producer string). No entry-point byte database: the
//! packing verdict (F-74) covers renamed-section packers.

use crate::document::Document;
use crate::format::{BinaryInfo, Format};

/// What a detection identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    Compiler,
    Runtime,
    Packer,
    Protector,
    Installer,
    Library,
}

impl IdKind {
    pub fn name(self) -> &'static str {
        match self {
            IdKind::Compiler => "compiler",
            IdKind::Runtime => "runtime",
            IdKind::Packer => "packer",
            IdKind::Protector => "protector",
            IdKind::Installer => "installer",
            IdKind::Library => "library",
        }
    }
}

/// One identification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub kind: IdKind,
    pub name: String,
    /// How it was found, or an extracted version string. May be empty.
    pub details: String,
}

/// Section-name → (kind, name). Matched as a case-insensitive prefix, which is
/// how packers name their sections (`UPX0`/`UPX1`, `.vmp0`/`.vmp1`, …).
const SECTION_RULES: &[(&str, IdKind, &str)] = &[
    ("upx", IdKind::Packer, "UPX"),
    (".aspack", IdKind::Packer, "ASPack"),
    (".adata", IdKind::Packer, "ASPack"),
    (".mpress", IdKind::Packer, "MPRESS"),
    (".pec", IdKind::Packer, "PECompact"),
    ("pec1", IdKind::Packer, "PECompact"),
    (".mew", IdKind::Packer, "MEW"),
    (".petite", IdKind::Packer, "Petite"),
    (".nsp", IdKind::Packer, "NsPack"),
    ("nsp0", IdKind::Packer, "NsPack"),
    (".fsg", IdKind::Packer, "FSG"),
    (".themida", IdKind::Protector, "Themida/WinLicense"),
    (".winlice", IdKind::Protector, "Themida/WinLicense"),
    (".vmp", IdKind::Protector, "VMProtect"),
    (".enigma", IdKind::Protector, "Enigma Protector"),
    (".taz", IdKind::Protector, "PESpin"),
    (".yp", IdKind::Protector, "Y0da Protector"),
    (".ndata", IdKind::Installer, "NSIS"),
    (".gentee", IdKind::Installer, "Gentee installer"),
    // language runtimes
    (".gopclntab", IdKind::Runtime, "Go"),
    (".go.buildinfo", IdKind::Runtime, "Go"),
    (".note.go.buildid", IdKind::Runtime, "Go"),
    (".rustc", IdKind::Runtime, "Rust"),
    ("__swift", IdKind::Runtime, "Swift"),
    ("__objc", IdKind::Runtime, "Objective-C"),
];

/// Library-name substring → (kind, name).
const LIB_RULES: &[(&str, IdKind, &str)] = &[
    ("mscoree.dll", IdKind::Runtime, ".NET"),
    ("msvbvm60", IdKind::Runtime, "Visual Basic 6"),
    ("vcruntime", IdKind::Compiler, "Microsoft Visual C/C++"),
    ("msvcp", IdKind::Compiler, "Microsoft Visual C/C++"),
    ("msvcr", IdKind::Compiler, "Microsoft Visual C/C++"),
    ("api-ms-win-crt", IdKind::Compiler, "Microsoft Visual C/C++ (UCRT)"),
    ("mingw", IdKind::Compiler, "MinGW (GCC)"),
    ("libgcc_s", IdKind::Compiler, "GCC"),
    ("libstdc++", IdKind::Compiler, "GCC (libstdc++)"),
    ("libc++.1.dylib", IdKind::Compiler, "Clang (libc++)"),
    ("libswiftcore", IdKind::Runtime, "Swift"),
    ("libobjc", IdKind::Runtime, "Objective-C"),
    ("libc.so", IdKind::Library, "glibc"),
    ("libsystem.b.dylib", IdKind::Library, "macOS libSystem"),
];

/// Imported-function name → (kind, name), for functions that pin a runtime even
/// when the library name does not.
const IMPORT_RULES: &[(&str, IdKind, &str)] = &[
    ("_corexemain", IdKind::Runtime, ".NET"),
    ("_cordllmain", IdKind::Runtime, ".NET"),
    ("__libc_start_main", IdKind::Library, "glibc"),
];

/// F-73 — Names the toolchain / packer / protector / runtime of a binary.
pub fn detect(doc: &mut Document, info: &BinaryInfo) -> Vec<Detection> {
    let mut out = Vec::new();

    for s in &info.sections {
        let name = s.name.to_ascii_lowercase();
        for (needle, kind, label) in SECTION_RULES {
            if name.starts_with(needle) {
                push(&mut out, *kind, label, format!("section {}", s.name));
            }
        }
    }

    for lib in &info.libs {
        let l = lib.to_ascii_lowercase();
        for (needle, kind, label) in LIB_RULES {
            if l.contains(needle) {
                push(&mut out, *kind, label, format!("imports {lib}"));
            }
        }
    }

    for imp in &info.imports {
        let n = imp.name.to_ascii_lowercase();
        for (needle, kind, label) in IMPORT_RULES {
            if n == *needle {
                push(&mut out, *kind, label, format!("imports {}", imp.name));
            }
        }
    }

    if info.format == Format::Elf {
        detect_elf_producer(doc, info, &mut out);
    }

    out
}

/// Reads ELF `.comment`, whose NUL-separated producer strings name the exact
/// compiler and version (`GCC: (…) 13.2.0`, `clang version 17.0.6`, `rustc …`).
fn detect_elf_producer(doc: &mut Document, info: &BinaryInfo, out: &mut Vec<Detection>) {
    let Some(sec) = info.sections.iter().find(|s| s.name == ".comment") else {
        return;
    };
    let Some(bytes) = super::read_section(doc, sec, 64 << 10) else {
        return;
    };
    for chunk in bytes.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(chunk);
        let low = s.to_ascii_lowercase();
        if low.contains("clang") {
            push(out, IdKind::Compiler, "Clang", s.trim().to_string());
        } else if low.starts_with("gcc") || low.contains("gcc:") {
            push(out, IdKind::Compiler, "GCC", s.trim().to_string());
        } else if low.contains("rustc") {
            push(out, IdKind::Compiler, "Rust", s.trim().to_string());
        }
    }
}

/// Appends a detection unless the same (kind, name) is already present.
fn push(out: &mut Vec<Detection>, kind: IdKind, name: &str, details: String) {
    if out.iter().any(|d| d.kind == kind && d.name == name) {
        return;
    }
    out.push(Detection { kind, name: name.to_string(), details });
}
