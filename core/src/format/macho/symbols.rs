//! F-71 — Mach-O symbol table (`LC_SYMTAB` nlist array).
//!
//! Undefined external symbols are the binary's imports; the two-level-namespace
//! library ordinal in `n_desc` names the owning dylib from the load-command
//! list, so an import shows where it comes from (like `otool -L` + `nm -m`).

use crate::document::Document;
use crate::error::Result;
use crate::format::tree::Cursor;
use crate::format::{Bits, Import, SymKind, Symbol, read_exact};
use crate::inspector::Endian;

use super::SymtabCmd;

// n_type masks.
const N_STAB: u8 = 0xe0; // debug-symbol entries (skipped)
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x0;

// Special library ordinals that name no real dylib.
const SELF_LIBRARY_ORDINAL: u8 = 0x0;
const DYNAMIC_LOOKUP_ORDINAL: u8 = 0xfe;
const EXECUTABLE_ORDINAL: u8 = 0xff;

pub(super) fn parse_symtab(
    doc: &mut Document,
    base: u64,
    bits: Bits,
    endian: Endian,
    st: &SymtabCmd,
    libs: &[String],
) -> Result<(Vec<Symbol>, Vec<Import>)> {
    let entsize = if bits == Bits::B64 { 16 } else { 12 };
    let doc_len = doc.len();

    // Clamp both tables to what the file actually holds, so a corrupt count can
    // never trigger a huge allocation.
    let sym_start = base + st.symoff as u64;
    let max_syms = (doc_len.saturating_sub(sym_start) / entsize as u64) as usize;
    let count = (st.nsyms as usize).min(max_syms);

    let str_start = base + st.stroff as u64;
    let strsize = (st.strsize as u64).min(doc_len.saturating_sub(str_start)) as usize;
    let strtab = read_exact(doc, str_start, strsize)?;
    let bytes = read_exact(doc, sym_start, count * entsize)?;

    let mut symbols = Vec::new();
    let mut imports = Vec::new();
    for i in 0..count {
        let mut c = Cursor::new(&bytes[i * entsize..i * entsize + entsize], 0, endian);
        let n_strx = c.u32()?;
        let n_type = c.u8()?;
        let _n_sect = c.u8()?;
        let n_desc = c.u16()?;
        let n_value = match bits {
            Bits::B64 => c.u64()?,
            Bits::B32 => c.u32()? as u64,
        };
        if n_type & N_STAB != 0 {
            continue; // debug symbol, not a linker symbol
        }
        let name = cstr(&strtab, n_strx);
        if name.is_empty() {
            continue;
        }
        let defined = (n_type & N_TYPE) != N_UNDF;
        let global = n_type & N_EXT != 0;
        symbols.push(Symbol {
            name: name.clone(),
            value: n_value,
            size: 0,
            kind: if defined { SymKind::Func } else { SymKind::Other },
            global,
            defined,
        });
        if !defined && global {
            imports.push(Import {
                library: library_of(n_desc, libs),
                name,
                ordinal: None,
            });
        }
    }
    Ok((symbols, imports))
}

/// Resolves the two-level-namespace library ordinal (high byte of `n_desc`) to
/// a dylib name, or an empty string for the flat/self/executable ordinals.
fn library_of(n_desc: u16, libs: &[String]) -> String {
    let ord = (n_desc >> 8) as u8;
    match ord {
        SELF_LIBRARY_ORDINAL | DYNAMIC_LOOKUP_ORDINAL | EXECUTABLE_ORDINAL => String::new(),
        n => libs.get(n as usize - 1).cloned().unwrap_or_default(),
    }
}

fn cstr(tab: &[u8], off: u32) -> String {
    let off = off as usize;
    if off >= tab.len() {
        return String::new();
    }
    let rest = &tab[off..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}
