//! F-70 — PE import and export tables.
//!
//! Both are best-effort: a truncated or unreadable table stops the walk and
//! yields what was parsed so far rather than failing the whole PE (unlike the
//! fixed headers, where an unreadable block is fatal — F-06). Every string is
//! resolved through the section table's RVA→offset map.

use crate::document::Document;
use crate::error::Result;
use crate::format::tree::{Cursor, Node};
use crate::format::{Import, SymKind, Symbol};
use crate::inspector::Endian;

use super::{DIR_EXPORT, DIR_IMPORT, PeCtx};
use crate::format::Bits;

// Guards against runaway loops over a malformed table.
const MAX_ENTRIES: usize = 1 << 16;

/// Reads exactly `len` clean bytes at document offset `off`, or `None` if the
/// range is short or unreadable — the signal to stop walking an optional table.
fn read_at(doc: &mut Document, off: u64, len: usize) -> Option<Vec<u8>> {
    let r = doc.read(off, len);
    (r.is_clean() && r.data.len() == len).then_some(r.data)
}

/// A NUL-terminated string at an RVA, empty if it maps nowhere or is unreadable.
fn cstr_at(doc: &mut Document, ctx: &PeCtx, rva: u32) -> String {
    let Some(off) = ctx.rva_to_off(rva) else {
        return String::new();
    };
    let r = doc.read(off, 256);
    if !r.is_clean() {
        return String::new();
    }
    let end = r.data.iter().position(|&b| b == 0).unwrap_or(r.data.len());
    String::from_utf8_lossy(&r.data[..end]).into_owned()
}

pub(super) fn parse_imports(
    doc: &mut Document,
    ctx: &PeCtx,
) -> Result<(Option<Node>, Vec<Import>, Vec<String>)> {
    let Some((dir_rva, _)) = ctx.dir(DIR_IMPORT) else {
        return Ok((None, Vec::new(), Vec::new()));
    };
    let Some(dir_off) = ctx.rva_to_off(dir_rva) else {
        return Ok((None, Vec::new(), Vec::new()));
    };

    let mut imports = Vec::new();
    let mut libs = Vec::new();
    let mut dll_nodes = Vec::new();
    let mut i = 0usize;
    while i < MAX_ENTRIES {
        let desc_off = dir_off + (i * 20) as u64;
        let Some(raw) = read_at(doc, desc_off, 20) else { break };
        if raw.iter().all(|&b| b == 0) {
            break; // the all-zero descriptor terminates the array
        }
        let mut c = Cursor::new(&raw, desc_off, Endian::Little);
        let (oft, oft_sp) = c.take_u32()?;
        c.skip(8)?; // TimeDateStamp, ForwarderChain
        let (name_rva, name_sp) = c.take_u32()?;
        let (iat_rva, iat_sp) = c.take_u32()?;

        let dll = cstr_at(doc, ctx, name_rva);
        libs.push(dll.clone());
        // Prefer the import lookup table; fall back to the IAT if OFT is null.
        let thunk_rva = if oft != 0 { oft } else { iat_rva };
        let funcs = walk_thunks(doc, ctx, thunk_rva, &dll, &mut imports);

        let mut fields = vec![
            Node::leaf("OriginalFirstThunk", format!("{oft:#x}"), oft_sp),
            Node::leaf("Name", format!("{dll} ({name_rva:#x})"), name_sp),
            Node::leaf("FirstThunk", format!("{iat_rva:#x}"), iat_sp),
        ];
        fields.extend(funcs);
        dll_nodes.push(Node::group(dll, desc_off..desc_off + 20, fields));
        i += 1;
    }

    if dll_nodes.is_empty() {
        return Ok((None, imports, libs));
    }
    let node = Node::group("Imports", dir_off..dir_off + (i * 20) as u64, dll_nodes);
    Ok((Some(node), imports, libs))
}

/// Walks one DLL's thunk array, appending its imports and returning tree leaves.
fn walk_thunks(
    doc: &mut Document,
    ctx: &PeCtx,
    thunk_rva: u32,
    dll: &str,
    imports: &mut Vec<Import>,
) -> Vec<Node> {
    let Some(mut off) = ctx.rva_to_off(thunk_rva) else {
        return Vec::new();
    };
    let (width, ord_flag) = match ctx.bits {
        Bits::B32 => (4usize, 0x8000_0000u64),
        Bits::B64 => (8, 0x8000_0000_0000_0000),
    };
    let mut leaves = Vec::new();
    let mut n = 0usize;
    while n < MAX_ENTRIES {
        let Some(raw) = read_at(doc, off, width) else { break };
        let thunk = match ctx.bits {
            Bits::B32 => u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as u64,
            Bits::B64 => u64::from_le_bytes(raw.try_into().unwrap()),
        };
        if thunk == 0 {
            break; // the null thunk terminates the array
        }
        let span = off..off + width as u64;
        if thunk & ord_flag != 0 {
            let ordinal = (thunk & 0xffff) as u16;
            leaves.push(Node::leaf("import", format!("{dll}!#{ordinal}"), span));
            imports.push(Import { library: dll.to_string(), name: String::new(), ordinal: Some(ordinal) });
        } else {
            // Low bits are an RVA to IMAGE_IMPORT_BY_NAME: u16 hint, then the name.
            let name_rva = (thunk & (ord_flag - 1)) as u32;
            let name = cstr_at(doc, ctx, name_rva.wrapping_add(2));
            leaves.push(Node::leaf("import", format!("{dll}!{name}"), span));
            imports.push(Import { library: dll.to_string(), name, ordinal: None });
        }
        off += width as u64;
        n += 1;
    }
    leaves
}

pub(super) fn parse_exports(doc: &mut Document, ctx: &PeCtx) -> Result<(Option<Node>, Vec<Symbol>)> {
    let Some((dir_rva, _)) = ctx.dir(DIR_EXPORT) else {
        return Ok((None, Vec::new()));
    };
    let Some(dir_off) = ctx.rva_to_off(dir_rva) else {
        return Ok((None, Vec::new()));
    };
    let Some(raw) = read_at(doc, dir_off, 40) else {
        return Ok((None, Vec::new()));
    };
    let mut c = Cursor::new(&raw, dir_off, Endian::Little);
    c.skip(12)?; // Characteristics, TimeDateStamp, Major/MinorVersion
    let (name_rva, name_sp) = c.take_u32()?;
    let (base, base_sp) = c.take_u32()?;
    let (num_funcs, nf_sp) = c.take_u32()?;
    let (num_names, nn_sp) = c.take_u32()?;
    let (funcs_rva, fr_sp) = c.take_u32()?;
    let (names_rva, nr_sp) = c.take_u32()?;
    let (ords_rva, or_sp) = c.take_u32()?;

    let module = cstr_at(doc, ctx, name_rva);
    let funcs = read_u32_array(doc, ctx, funcs_rva, num_funcs);
    let names = read_u32_array(doc, ctx, names_rva, num_names);
    let ords = read_u16_array(doc, ctx, ords_rva, num_names);

    let mut symbols = Vec::new();
    for (idx, &name_ptr) in names.iter().enumerate() {
        let name = cstr_at(doc, ctx, name_ptr);
        if name.is_empty() {
            continue;
        }
        let func_rva = ords.get(idx).and_then(|&o| funcs.get(o as usize)).copied().unwrap_or(0);
        symbols.push(Symbol {
            name,
            value: ctx.image_base + func_rva as u64,
            size: 0,
            kind: SymKind::Func,
            global: true,
            defined: true,
        });
    }

    let node = Node::group(
        format!("Exports ({module})"),
        dir_off..dir_off + 40,
        vec![
            Node::leaf("Name", format!("{module} ({name_rva:#x})"), name_sp),
            Node::leaf("Base", format!("{base}"), base_sp),
            Node::leaf("NumberOfFunctions", format!("{num_funcs}"), nf_sp),
            Node::leaf("NumberOfNames", format!("{num_names}"), nn_sp),
            Node::leaf("AddressOfFunctions", format!("{funcs_rva:#x}"), fr_sp),
            Node::leaf("AddressOfNames", format!("{names_rva:#x}"), nr_sp),
            Node::leaf("AddressOfNameOrdinals", format!("{ords_rva:#x}"), or_sp),
        ],
    );
    Ok((Some(node), symbols))
}

fn read_u32_array(doc: &mut Document, ctx: &PeCtx, rva: u32, count: u32) -> Vec<u32> {
    let count = (count as usize).min(MAX_ENTRIES);
    let Some(off) = ctx.rva_to_off(rva) else {
        return Vec::new();
    };
    let Some(raw) = read_at(doc, off, count * 4) else {
        return Vec::new();
    };
    raw.chunks_exact(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).collect()
}

fn read_u16_array(doc: &mut Document, ctx: &PeCtx, rva: u32, count: u32) -> Vec<u16> {
    let count = (count as usize).min(MAX_ENTRIES);
    let Some(off) = ctx.rva_to_off(rva) else {
        return Vec::new();
    };
    let Some(raw) = read_at(doc, off, count * 2) else {
        return Vec::new();
    };
    raw.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect()
}
