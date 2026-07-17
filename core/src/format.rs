//! F-68/F-69/F-70/F-71 — Executable format model (Fase 9).
//!
//! One model for ELF, PE and Mach-O: high-level facts (arch, entry, sections,
//! symbols, imports, libraries, relocations) plus a provenance `tree` mapping
//! every field back to its document bytes (F-68). Each parser is hand-written
//! (D8) over a [`Cursor`], reading the target through `Document::read` so the
//! huge-file invariant (D6) and per-block failure (F-06) hold: a header over an
//! unreadable block is not a header.
//!
//! All three formats are parsed: ELF (F-69), PE (F-70) and Mach-O (F-71).

mod elf;
mod macho;
mod pe;
#[cfg(test)]
mod tests;
mod tree;

use std::ops::Range;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::inspector::Endian;

pub use tree::{Cursor, Node};

/// Executable container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    Pe,
    MachO,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Elf => "ELF",
            Format::Pe => "PE",
            Format::MachO => "Mach-O",
        }
    }
}

/// Word size of the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bits {
    B32,
    B64,
}

impl Bits {
    pub fn name(self) -> &'static str {
        match self {
            Bits::B32 => "32-bit",
            Bits::B64 => "64-bit",
        }
    }
}

/// Processor architecture, common subset across the three formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    Ppc,
    Ppc64,
    RiscV,
    Sparc,
    Unknown,
}

impl Arch {
    pub fn name(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86-64",
            Arch::Arm => "ARM",
            Arch::Aarch64 => "AArch64",
            Arch::Mips => "MIPS",
            Arch::Ppc => "PowerPC",
            Arch::Ppc64 => "PowerPC64",
            Arch::RiscV => "RISC-V",
            Arch::Sparc => "SPARC",
            Arch::Unknown => "unknown",
        }
    }
}

/// Coarse, cross-format section/segment permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Perms {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl Perms {
    /// `rwx`, with a dash for each missing bit (like `ls`).
    pub fn rwx(self) -> String {
        let bit = |b, c| if b { c } else { '-' };
        format!("{}{}{}", bit(self.r, 'r'), bit(self.w, 'w'), bit(self.x, 'x'))
    }
}

/// A named region of the binary. `file` is where its bytes live in the document
/// (empty when the section occupies no file space, e.g. ELF `.bss`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub file: Range<u64>,
    pub vaddr: u64,
    pub size: u64,
    pub perms: Perms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymKind {
    Func,
    Object,
    Section,
    File,
    Other,
}

impl SymKind {
    pub fn name(self) -> &'static str {
        match self {
            SymKind::Func => "func",
            SymKind::Object => "object",
            SymKind::Section => "section",
            SymKind::File => "file",
            SymKind::Other => "other",
        }
    }
}

/// A symbol-table entry (nm-style). `defined == false` marks an imported /
/// undefined symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub kind: SymKind,
    pub global: bool,
    pub defined: bool,
}

/// An imported symbol: a function or object the binary resolves at load time.
/// `library` names the owning module (PE DLL, Mach-O dylib); it is empty for
/// ELF, whose dynamic symbols are matched by name across every `DT_NEEDED`.
/// `ordinal` is set for PE import-by-ordinal, where no name is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub library: String,
    pub name: String,
    pub ordinal: Option<u16>,
}

/// A relocation: a fixup the loader applies at `offset` (a virtual address for
/// ELF/PE, a file offset otherwise). `symbol` is the target's name when the
/// relocation references one; `kind` is the arch-specific type mnemonic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    pub offset: u64,
    pub kind: String,
    pub symbol: String,
    pub addend: i64,
}

/// A pre-`entry` code pointer the loader runs before the main entry point — a PE
/// TLS callback today. Anti-analysis code hides here, so identification (F-75)
/// surfaces them. `vaddr` is the virtual address it runs at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraEntry {
    pub kind: &'static str,
    pub vaddr: u64,
}

/// The parsed binary: high-level facts plus the provenance tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryInfo {
    pub format: Format,
    pub arch: Arch,
    pub bits: Bits,
    pub endian: Endian,
    /// Entry-point virtual address (0 when the format has none).
    pub entry: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    /// Imported symbols (PE/Mach-O carry the owning library; ELF resolves by
    /// name, so its entries have an empty `library`).
    pub imports: Vec<Import>,
    /// Dynamic library dependencies (ELF `DT_NEEDED`, PE import DLLs, Mach-O
    /// `LC_LOAD_DYLIB`).
    pub libs: Vec<String>,
    /// Relocations, in the order the tables list them.
    pub relocs: Vec<Reloc>,
    /// Pre-`entry` code pointers (PE TLS callbacks). Usually empty.
    pub extra_entries: Vec<ExtraEntry>,
    pub tree: Node,
}

/// Peeks the leading bytes and names the executable format, if recognised.
/// Returns `None` when the header is unreadable (F-06) or unknown.
pub fn detect(doc: &mut Document) -> Option<Format> {
    let head = doc.read(0, 4);
    if !head.is_clean() || head.data.len() < 4 {
        return None;
    }
    let m = [head.data[0], head.data[1], head.data[2], head.data[3]];
    match m {
        [0x7F, b'E', b'L', b'F'] => Some(Format::Elf),
        // Mach-O thin (LE/BE, 32/64) and fat/universal.
        [0xCE, 0xFA, 0xED, 0xFE]
        | [0xCF, 0xFA, 0xED, 0xFE]
        | [0xFE, 0xED, 0xFA, 0xCE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xCA, 0xFE, 0xBA, 0xBE] => Some(Format::MachO),
        [b'M', b'Z', ..] => Some(Format::Pe),
        _ => None,
    }
}

/// Parses the document as an executable, dispatching on [`detect`].
pub fn parse(doc: &mut Document) -> Result<BinaryInfo> {
    match detect(doc) {
        Some(Format::Elf) => elf::parse(doc),
        Some(Format::Pe) => pe::parse(doc),
        Some(Format::MachO) => macho::parse(doc),
        None => Err(Error::new(ErrorKind::Io, "unrecognised executable format")),
    }
}

/// Reads exactly `len` bytes at `off`, turning a short read or an unreadable
/// block into a parse error — the same principle `save_as` uses: never treat
/// zeros from an unread block as real bytes.
pub(crate) fn read_exact(doc: &mut Document, off: u64, len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let r = doc.read(off, len);
    if r.data.len() < len {
        return Err(Error::new(
            ErrorKind::OutOfBounds,
            format!("structure runs past end of file at {off:#x}"),
        ));
    }
    if !r.is_clean() {
        return Err(Error::new(ErrorKind::BadBlock, format!("unreadable bytes at {off:#x}")));
    }
    Ok(r.data)
}
