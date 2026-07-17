//! F-69 — ELF section headers and the section list they yield.

use crate::document::Document;
use crate::error::Result;
use crate::format::tree::{Cursor, Node};
use crate::format::{Perms, Section, read_exact};

use super::{Bits, Ehdr, RawShdr, SHT_NOBITS, cstr, native, take_native};

pub(super) fn parse_sections(
    doc: &mut Document,
    e: &Ehdr,
) -> Result<(Node, Vec<Section>, Vec<RawShdr>)> {
    if e.shnum == 0 || e.shentsize == 0 || e.shoff == 0 {
        let empty = Node::group("Section Headers", e.shoff..e.shoff, Vec::new());
        return Ok((empty, Vec::new(), Vec::new()));
    }
    let ent = e.shentsize as usize;
    let total = e.shnum as usize * ent;
    let raw = read_exact(doc, e.shoff, total)?;

    let mut shdrs = Vec::with_capacity(e.shnum as usize);
    for i in 0..e.shnum as usize {
        let mut c = Cursor::new(&raw[i * ent..i * ent + ent], e.shoff + (i * ent) as u64, e.endian);
        shdrs.push(parse_shdr(&mut c, e.bits)?);
    }

    // Section-name string table, if the index is valid and not the null section.
    let shstr = shdrs
        .get(e.shstrndx as usize)
        .filter(|s| s.sh_type != 0)
        .map(|s| read_exact(doc, s.offset, s.size as usize))
        .transpose()?
        .unwrap_or_default();

    let mut kids = Vec::with_capacity(shdrs.len());
    let mut sections = Vec::new();
    for (i, sh) in shdrs.iter().enumerate() {
        let name = cstr(&shstr, sh.name_off);
        let base = e.shoff + (i * ent) as u64;
        kids.push(shdr_node(base, &raw[i * ent..i * ent + ent], e, &name)?);
        if i == 0 {
            continue; // the null section is not a real section
        }
        let file = if sh.sh_type == SHT_NOBITS {
            sh.offset..sh.offset
        } else {
            sh.offset..sh.offset + sh.size
        };
        sections.push(Section {
            name,
            file,
            vaddr: sh.addr,
            size: sh.size,
            perms: Perms {
                r: sh.flags & 0x2 != 0, // SHF_ALLOC
                w: sh.flags & 0x1 != 0, // SHF_WRITE
                x: sh.flags & 0x4 != 0, // SHF_EXECINSTR
            },
        });
    }
    let node = Node::group("Section Headers", e.shoff..e.shoff + total as u64, kids);
    Ok((node, sections, shdrs))
}

fn parse_shdr(c: &mut Cursor, bits: Bits) -> Result<RawShdr> {
    let name_off = c.u32()?;
    let sh_type = c.u32()?;
    let flags = native(c, bits)?;
    let addr = native(c, bits)?;
    let offset = native(c, bits)?;
    let size = native(c, bits)?;
    let link = c.u32()?;
    let _info = c.u32()?;
    let _align = native(c, bits)?;
    let _entsize = native(c, bits)?;
    Ok(RawShdr { name_off, sh_type, flags, addr, offset, size, link })
}

fn shdr_node(base: u64, slice: &[u8], e: &Ehdr, name: &str) -> Result<Node> {
    let mut c = Cursor::new(slice, base, e.endian);
    let mut f = Vec::new();
    let (name_off, sp) = c.take_u32()?;
    f.push(Node::leaf("sh_name", format!("{name} ({name_off:#x})"), sp));
    let (ty, sp) = c.take_u32()?;
    f.push(Node::leaf("sh_type", format!("{} ({:#x})", sht_name(ty), ty), sp));
    let (flags, sp) = take_native(&mut c, e.bits)?;
    f.push(Node::leaf("sh_flags", shflags(flags), sp));
    for name in ["sh_addr", "sh_offset", "sh_size"] {
        let (v, sp) = take_native(&mut c, e.bits)?;
        f.push(Node::leaf(name, format!("{v:#x}"), sp));
    }
    let (link, sp) = c.take_u32()?;
    f.push(Node::leaf("sh_link", format!("{link}"), sp));
    let (info, sp) = c.take_u32()?;
    f.push(Node::leaf("sh_info", format!("{info}"), sp));
    for name in ["sh_addralign", "sh_entsize"] {
        let (v, sp) = take_native(&mut c, e.bits)?;
        f.push(Node::leaf(name, format!("{v:#x}"), sp));
    }
    Ok(Node::group(format!("{name} [{}]", sht_name(ty)), base..c.abs(), f))
}

fn sht_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        17 => "GROUP",
        0x6fff_fff6 => "GNU_HASH",
        0x6fff_fffd => "VERDEF",
        0x6fff_fffe => "VERNEED",
        0x6fff_ffff => "VERSYM",
        _ => "?",
    }
}

fn shflags(f: u64) -> String {
    let mut s = String::new();
    if f & 0x2 != 0 {
        s.push('A');
    }
    if f & 0x1 != 0 {
        s.push('W');
    }
    if f & 0x4 != 0 {
        s.push('X');
    }
    if s.is_empty() {
        s.push('-');
    }
    format!("{s} ({f:#x})")
}
