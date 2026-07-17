//! F-69 — ELF `.dynamic` table and relocations.
//!
//! The dynamic table drives the loader: `DT_NEEDED` entries name the shared
//! libraries this object depends on (surfaced as [`BinaryInfo::libs`]). The
//! relocation tables (`SHT_REL`/`SHT_RELA`) list the fixups the loader applies;
//! each target symbol is resolved through the relocation section's `sh_link`.

use crate::document::Document;
use crate::error::Result;
use crate::format::tree::{Cursor, Node};
use crate::format::{Arch, Reloc, read_exact};

use super::{Bits, Ehdr, RawShdr, SHT_DYNAMIC, SHT_REL, SHT_RELA, cstr, symbols, take_native};

// Dynamic-table tags whose value is an offset into the dynamic string table.
const DT_NEEDED: u64 = 1;
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

/// Parses the `.dynamic` table, returning its tree node and the `DT_NEEDED`
/// library list. Absent (statically linked) when there is no dynamic section.
pub(super) fn parse_dynamic(
    doc: &mut Document,
    e: &Ehdr,
    shdrs: &[RawShdr],
) -> Result<(Option<Node>, Vec<String>)> {
    let Some(dynsh) = shdrs.iter().find(|s| s.sh_type == SHT_DYNAMIC) else {
        return Ok((None, Vec::new()));
    };
    if dynsh.size == 0 {
        return Ok((None, Vec::new()));
    }
    // The .dynamic section's sh_link is its associated string table (.dynstr).
    let strtab = shdrs
        .get(dynsh.link as usize)
        .map(|s| read_exact(doc, s.offset, s.size as usize))
        .transpose()?
        .unwrap_or_default();
    let bytes = read_exact(doc, dynsh.offset, dynsh.size as usize)?;
    let ent = match e.bits {
        Bits::B64 => 16,
        Bits::B32 => 8,
    };
    let count = bytes.len() / ent;

    let mut libs = Vec::new();
    let mut kids = Vec::new();
    for i in 0..count {
        let base = dynsh.offset + (i * ent) as u64;
        let mut c = Cursor::new(&bytes[i * ent..i * ent + ent], base, e.endian);
        let (tag, tag_sp) = take_native(&mut c, e.bits)?;
        let (val, val_sp) = take_native(&mut c, e.bits)?;
        let name = dt_name(tag);

        let val_str = if matches!(tag, DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH) {
            let s = cstr(&strtab, val as u32);
            if tag == DT_NEEDED {
                libs.push(s.clone());
            }
            format!("{s} ({val:#x})")
        } else {
            format!("{val:#x}")
        };
        kids.push(Node::group(
            format!("[{i}] {name}"),
            base..c.abs(),
            vec![
                Node::leaf("d_tag", format!("{name} ({tag:#x})"), tag_sp),
                Node::leaf("d_val", val_str, val_sp),
            ],
        ));
        if tag == 0 {
            break; // DT_NULL terminates the table
        }
    }
    let span = dynsh.offset..dynsh.offset + dynsh.size;
    Ok((Some(Node::group("Dynamic", span, kids)), libs))
}

/// Parses every `SHT_REL`/`SHT_RELA` section, resolving each target symbol via
/// the relocation section's `sh_link`. Returns the combined tree node (absent
/// when there are none) and the flat relocation list.
pub(super) fn parse_relocs(
    doc: &mut Document,
    e: &Ehdr,
    shdrs: &[RawShdr],
) -> Result<(Option<Node>, Vec<Reloc>)> {
    let mut relocs = Vec::new();
    let mut groups = Vec::new();
    for (si, sh) in shdrs.iter().enumerate() {
        let rela = match sh.sh_type {
            SHT_RELA => true,
            SHT_REL => false,
            _ => continue,
        };
        if sh.size == 0 || sh.offset == 0 {
            continue;
        }
        let ent = reloc_entsize(e.bits, rela);
        let names = symbols::names_in(doc, e, shdrs, sh.link)?;
        let bytes = read_exact(doc, sh.offset, sh.size as usize)?;
        let count = bytes.len() / ent;

        let mut kids = Vec::with_capacity(count);
        for i in 0..count {
            let base = sh.offset + (i * ent) as u64;
            let mut c = Cursor::new(&bytes[i * ent..i * ent + ent], base, e.endian);
            let (offset, off_sp) = take_native(&mut c, e.bits)?;
            let (info, info_sp) = take_native(&mut c, e.bits)?;
            let (sym_idx, rtype) = split_info(info, e.bits);
            let addend_field = if rela {
                let (a, sp) = take_native(&mut c, e.bits)?;
                Some((sign_extend(a, e.bits), sp))
            } else {
                None
            };
            let addend = addend_field.as_ref().map_or(0, |(a, _)| *a);
            let symbol = names.get(sym_idx as usize).cloned().unwrap_or_default();
            let kind = rel_type_name(e.arch, rtype);

            let mut f = vec![
                Node::leaf("r_offset", format!("{offset:#x}"), off_sp),
                Node::leaf("r_info", format!("{kind} (sym {sym_idx}, type {rtype})"), info_sp),
            ];
            if let Some((_, sp)) = addend_field {
                f.push(Node::leaf("r_addend", format!("{addend:#x}"), sp));
            }
            let label = if symbol.is_empty() {
                format!("[{i}] {kind}")
            } else {
                format!("[{i}] {kind} {symbol}")
            };
            kids.push(Node::group(label, base..c.abs(), f));
            relocs.push(Reloc { offset, kind, symbol, addend });
        }
        let tag = if rela { "RELA" } else { "REL" };
        groups.push(Node::group(
            format!("[{si}] {tag} @ {:#x}", sh.offset),
            sh.offset..sh.offset + sh.size,
            kids,
        ));
    }
    if groups.is_empty() {
        return Ok((None, relocs));
    }
    let start = groups.first().map(|n| n.span.start).unwrap_or(0);
    let end = groups.last().map(|n| n.span.end).unwrap_or(start);
    Ok((Some(Node::group("Relocations", start..end, groups)), relocs))
}

fn reloc_entsize(bits: Bits, rela: bool) -> usize {
    match (bits, rela) {
        (Bits::B32, false) => 8,
        (Bits::B32, true) => 12,
        (Bits::B64, false) => 16,
        (Bits::B64, true) => 24,
    }
}

/// Splits `r_info` into (symbol index, relocation type). The split point differs
/// by class: 8 bits of type on ELF32, 32 on ELF64.
fn split_info(info: u64, bits: Bits) -> (u32, u32) {
    match bits {
        Bits::B32 => ((info >> 8) as u32, (info & 0xff) as u32),
        Bits::B64 => ((info >> 32) as u32, info as u32),
    }
}

/// `r_addend` is signed; sign-extend from the class width read as unsigned.
fn sign_extend(v: u64, bits: Bits) -> i64 {
    match bits {
        Bits::B32 => v as u32 as i32 as i64,
        Bits::B64 => v as i64,
    }
}

fn rel_type_name(arch: Arch, ty: u32) -> String {
    let name = match arch {
        Arch::X86_64 => match ty {
            0 => "R_X86_64_NONE",
            1 => "R_X86_64_64",
            2 => "R_X86_64_PC32",
            5 => "R_X86_64_COPY",
            6 => "R_X86_64_GLOB_DAT",
            7 => "R_X86_64_JUMP_SLOT",
            8 => "R_X86_64_RELATIVE",
            9 => "R_X86_64_GOTPCREL",
            _ => "",
        },
        Arch::X86 => match ty {
            0 => "R_386_NONE",
            1 => "R_386_32",
            2 => "R_386_PC32",
            5 => "R_386_COPY",
            6 => "R_386_GLOB_DAT",
            7 => "R_386_JMP_SLOT",
            8 => "R_386_RELATIVE",
            _ => "",
        },
        Arch::Aarch64 => match ty {
            257 => "R_AARCH64_ABS64",
            1024 => "R_AARCH64_COPY",
            1025 => "R_AARCH64_GLOB_DAT",
            1026 => "R_AARCH64_JUMP_SLOT",
            1027 => "R_AARCH64_RELATIVE",
            _ => "",
        },
        Arch::Arm => match ty {
            2 => "R_ARM_ABS32",
            20 => "R_ARM_COPY",
            21 => "R_ARM_GLOB_DAT",
            22 => "R_ARM_JUMP_SLOT",
            23 => "R_ARM_RELATIVE",
            _ => "",
        },
        _ => "",
    };
    if name.is_empty() {
        format!("type {ty}")
    } else {
        name.to_string()
    }
}

fn dt_name(tag: u64) -> &'static str {
    match tag {
        0 => "DT_NULL",
        1 => "DT_NEEDED",
        2 => "DT_PLTRELSZ",
        3 => "DT_PLTGOT",
        4 => "DT_HASH",
        5 => "DT_STRTAB",
        6 => "DT_SYMTAB",
        7 => "DT_RELA",
        8 => "DT_RELASZ",
        9 => "DT_RELAENT",
        10 => "DT_STRSZ",
        11 => "DT_SYMENT",
        12 => "DT_INIT",
        13 => "DT_FINI",
        14 => "DT_SONAME",
        15 => "DT_RPATH",
        16 => "DT_SYMBOLIC",
        17 => "DT_REL",
        18 => "DT_RELSZ",
        19 => "DT_RELENT",
        20 => "DT_PLTREL",
        21 => "DT_DEBUG",
        22 => "DT_TEXTREL",
        23 => "DT_JMPREL",
        24 => "DT_BIND_NOW",
        25 => "DT_INIT_ARRAY",
        26 => "DT_FINI_ARRAY",
        27 => "DT_INIT_ARRAYSZ",
        28 => "DT_FINI_ARRAYSZ",
        29 => "DT_RUNPATH",
        30 => "DT_FLAGS",
        0x6fff_fef5 => "DT_GNU_HASH",
        0x6fff_fff0 => "DT_VERSYM",
        0x6fff_fff9 => "DT_RELACOUNT",
        0x6fff_fffb => "DT_FLAGS_1",
        0x6fff_fffe => "DT_VERNEED",
        0x6fff_ffff => "DT_VERNEEDNUM",
        _ => "DT_?",
    }
}
