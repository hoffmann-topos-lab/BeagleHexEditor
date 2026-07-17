//! F-69 — ELF symbol table (`.symtab`, falling back to `.dynsym`).

use crate::document::Document;
use crate::error::Result;
use crate::format::tree::Cursor;
use crate::format::{SymKind, Symbol, read_exact};

use super::{Bits, Ehdr, RawShdr, SHT_DYNSYM, SHT_SYMTAB, cstr};

/// Bytes per symbol entry for the ELF class.
fn entsize(bits: Bits) -> usize {
    match bits {
        Bits::B64 => 24,
        Bits::B32 => 16,
    }
}

pub(super) fn parse_symbols(doc: &mut Document, e: &Ehdr, shdrs: &[RawShdr]) -> Result<Vec<Symbol>> {
    // Prefer the full .symtab; fall back to .dynsym.
    let Some(tab) = shdrs
        .iter()
        .find(|s| s.sh_type == SHT_SYMTAB)
        .or_else(|| shdrs.iter().find(|s| s.sh_type == SHT_DYNSYM))
    else {
        return Ok(Vec::new());
    };
    if tab.size == 0 {
        return Ok(Vec::new());
    }
    let entsize = entsize(e.bits);
    let strtab = shdrs
        .get(tab.link as usize)
        .map(|s| read_exact(doc, s.offset, s.size as usize))
        .transpose()?
        .unwrap_or_default();
    let bytes = read_exact(doc, tab.offset, tab.size as usize)?;
    let count = bytes.len() / entsize;

    let mut out = Vec::new();
    for i in 0..count {
        let mut c = Cursor::new(&bytes[i * entsize..i * entsize + entsize], 0, e.endian);
        let (name_off, value, size, info, shndx) = match e.bits {
            Bits::B64 => {
                let name_off = c.u32()?;
                let info = c.u8()?;
                let _other = c.u8()?;
                let shndx = c.u16()?;
                let value = c.u64()?;
                let size = c.u64()?;
                (name_off, value, size, info, shndx)
            }
            Bits::B32 => {
                let name_off = c.u32()?;
                let value = c.u32()? as u64;
                let size = c.u32()? as u64;
                let info = c.u8()?;
                let _other = c.u8()?;
                let shndx = c.u16()?;
                (name_off, value, size, info, shndx)
            }
        };
        let name = cstr(&strtab, name_off);
        if name.is_empty() {
            continue;
        }
        out.push(Symbol {
            name,
            value,
            size,
            kind: sym_kind(info & 0xf),
            global: (info >> 4) != 0, // STB_LOCAL == 0
            defined: shndx != 0,      // SHN_UNDEF == 0
        });
    }
    Ok(out)
}

/// Symbol names of the table at section index `idx`, indexed by symbol number
/// (the empty string for unnamed entries). Relocations use it to name targets:
/// `st_name` is the first `u32` of a symbol in both ELF classes, so only the
/// entry width differs.
pub(super) fn names_in(
    doc: &mut Document,
    e: &Ehdr,
    shdrs: &[RawShdr],
    idx: u32,
) -> Result<Vec<String>> {
    let Some(tab) = shdrs.get(idx as usize) else {
        return Ok(Vec::new());
    };
    if !matches!(tab.sh_type, SHT_SYMTAB | SHT_DYNSYM) || tab.size == 0 {
        return Ok(Vec::new());
    }
    let entsize = entsize(e.bits);
    let strtab = shdrs
        .get(tab.link as usize)
        .map(|s| read_exact(doc, s.offset, s.size as usize))
        .transpose()?
        .unwrap_or_default();
    let bytes = read_exact(doc, tab.offset, tab.size as usize)?;
    let count = bytes.len() / entsize;

    let mut names = Vec::with_capacity(count);
    for i in 0..count {
        let mut c = Cursor::new(&bytes[i * entsize..i * entsize + entsize], 0, e.endian);
        let name_off = c.u32()?;
        names.push(cstr(&strtab, name_off));
    }
    Ok(names)
}

fn sym_kind(t: u8) -> SymKind {
    match t {
        1 => SymKind::Object,
        2 => SymKind::Func,
        3 => SymKind::Section,
        4 => SymKind::File,
        _ => SymKind::Other,
    }
}
