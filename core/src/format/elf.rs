//! F-69 — ELF parser (readelf/nm scope): header, program headers, section
//! headers, the symbol table, the dynamic table and relocations, for ELF32/64
//! in either byte order. Hand-written over `Cursor` (D8); every field records
//! its document span for the tree.
//!
//! Split across submodules to stay within the file-size budget: this parent
//! owns the header and the shared low-level helpers; [`segments`] the program
//! headers, [`sections`] the section headers, [`symbols`] the symbol table and
//! [`dynamic`] the `.dynamic` table and the relocations.

mod dynamic;
mod sections;
mod segments;
mod symbols;

use std::ops::Range;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::inspector::Endian;

use super::tree::{Cursor, Node};
use super::{Arch, BinaryInfo, Bits, Format, Import, read_exact};

// Section header types the parser follows.
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;

/// Parsed ELF header: the facts the rest of the parse needs, plus its tree node.
struct Ehdr {
    bits: Bits,
    endian: Endian,
    arch: Arch,
    entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    shoff: u64,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
    node: Node,
}

/// Raw section header, kept so later passes can follow `sh_link` and read bytes.
struct RawShdr {
    name_off: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
}

pub(super) fn parse(doc: &mut Document) -> Result<BinaryInfo> {
    let e = parse_header(doc)?;
    let ph_node = segments::parse_phdrs(doc, &e)?;
    let (sh_node, sections, shdrs) = sections::parse_sections(doc, &e)?;
    let symbols = symbols::parse_symbols(doc, &e, &shdrs)?;
    let (dyn_node, libs) = dynamic::parse_dynamic(doc, &e, &shdrs)?;
    let (rel_node, relocs) = dynamic::parse_relocs(doc, &e, &shdrs)?;

    // ELF imports are its undefined dynamic references, resolved by name at load
    // time — no owning library, unlike PE/Mach-O.
    let imports = symbols
        .iter()
        .filter(|s| !s.defined && !s.name.is_empty())
        .map(|s| Import { library: String::new(), name: s.name.clone(), ordinal: None })
        .collect();

    let mut kids = vec![e.node, ph_node, sh_node];
    kids.extend(dyn_node);
    kids.extend(rel_node);
    let tree = Node::group("ELF", 0..doc.len(), kids);

    Ok(BinaryInfo {
        format: Format::Elf,
        arch: e.arch,
        bits: e.bits,
        endian: e.endian,
        entry: e.entry,
        sections,
        symbols,
        imports,
        libs,
        relocs,
        extra_entries: Vec::new(),
        tree,
    })
}

fn parse_header(doc: &mut Document) -> Result<Ehdr> {
    let ident = read_exact(doc, 0, 16)?;
    if ident[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(Error::new(ErrorKind::Io, "not an ELF file"));
    }
    let bits = match ident[4] {
        1 => Bits::B32,
        2 => Bits::B64,
        c => return Err(Error::new(ErrorKind::Io, format!("invalid ELF class {c}"))),
    };
    let endian = match ident[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        d => return Err(Error::new(ErrorKind::Io, format!("invalid ELF data encoding {d}"))),
    };
    let hsize = match bits {
        Bits::B32 => 52,
        Bits::B64 => 64,
    };
    let hdr = read_exact(doc, 0, hsize)?;
    let mut c = Cursor::new(&hdr, 0, endian);

    let ident_node = Node::group(
        "e_ident",
        0..16,
        vec![
            Node::leaf("magic", "7F 45 4C 46 (\\x7FELF)", 0..4),
            Node::leaf("class", format!("{} ({})", bits.name(), ident[4]), 4..5),
            Node::leaf("data", format!("{} ({})", endian.name(), ident[5]), 5..6),
            Node::leaf("version", format!("{}", ident[6]), 6..7),
            Node::leaf("osabi", format!("{}", ident[7]), 7..8),
        ],
    );
    c.seek(16)?;

    let mut f = vec![ident_node];
    let (e_type, sp) = c.take_u16()?;
    f.push(Node::leaf("e_type", format!("{} ({:#x})", et_name(e_type), e_type), sp));
    let (machine, sp) = c.take_u16()?;
    let arch = arch_of(machine);
    f.push(Node::leaf("e_machine", format!("{} ({:#x})", arch.name(), machine), sp));
    let (ver, sp) = c.take_u32()?;
    f.push(Node::leaf("e_version", format!("{ver:#x}"), sp));
    let (entry, sp) = take_native(&mut c, bits)?;
    f.push(Node::leaf("e_entry", format!("{entry:#x}"), sp));
    let (phoff, sp) = take_native(&mut c, bits)?;
    f.push(Node::leaf("e_phoff", format!("{phoff:#x}"), sp));
    let (shoff, sp) = take_native(&mut c, bits)?;
    f.push(Node::leaf("e_shoff", format!("{shoff:#x}"), sp));
    let (flags, sp) = c.take_u32()?;
    f.push(Node::leaf("e_flags", format!("{flags:#x}"), sp));
    let (ehsize, sp) = c.take_u16()?;
    f.push(Node::leaf("e_ehsize", format!("{ehsize}"), sp));
    let (phentsize, sp) = c.take_u16()?;
    f.push(Node::leaf("e_phentsize", format!("{phentsize}"), sp));
    let (phnum, sp) = c.take_u16()?;
    f.push(Node::leaf("e_phnum", format!("{phnum}"), sp));
    let (shentsize, sp) = c.take_u16()?;
    f.push(Node::leaf("e_shentsize", format!("{shentsize}"), sp));
    let (shnum, sp) = c.take_u16()?;
    f.push(Node::leaf("e_shnum", format!("{shnum}"), sp));
    let (shstrndx, sp) = c.take_u16()?;
    f.push(Node::leaf("e_shstrndx", format!("{shstrndx}"), sp));

    let node = Node::group("ELF Header", 0..hsize as u64, f);
    Ok(Ehdr {
        bits,
        endian,
        arch,
        entry,
        phoff,
        phentsize,
        phnum,
        shoff,
        shentsize,
        shnum,
        shstrndx,
        node,
    })
}

// ---- shared low-level helpers ----

/// Reads a word whose width follows the ELF class: 4 bytes on ELF32, 8 on ELF64.
fn native(c: &mut Cursor, bits: Bits) -> Result<u64> {
    match bits {
        Bits::B32 => Ok(c.u32()? as u64),
        Bits::B64 => c.u64(),
    }
}

/// [`native`] with the document span it consumed, for the tree.
fn take_native(c: &mut Cursor, bits: Bits) -> Result<(u64, Range<u64>)> {
    match bits {
        Bits::B32 => {
            let (v, s) = c.take_u32()?;
            Ok((v as u64, s))
        }
        Bits::B64 => c.take_u64(),
    }
}

/// The NUL-terminated string at `off` in a string table, empty when out of range.
fn cstr(tab: &[u8], off: u32) -> String {
    let off = off as usize;
    if off >= tab.len() {
        return String::new();
    }
    let rest = &tab[off..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

fn arch_of(machine: u16) -> Arch {
    match machine {
        2 | 18 | 43 => Arch::Sparc,
        3 => Arch::X86,
        8 => Arch::Mips,
        20 => Arch::Ppc,
        21 => Arch::Ppc64,
        40 => Arch::Arm,
        62 => Arch::X86_64,
        183 => Arch::Aarch64,
        243 => Arch::RiscV,
        _ => Arch::Unknown,
    }
}

fn et_name(t: u16) -> &'static str {
    match t {
        0 => "ET_NONE",
        1 => "ET_REL",
        2 => "ET_EXEC",
        3 => "ET_DYN",
        4 => "ET_CORE",
        _ => "?",
    }
}
