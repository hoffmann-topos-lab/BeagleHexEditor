//! F-69 — ELF program headers (the segment view the loader uses).

use crate::document::Document;
use crate::error::Result;
use crate::format::tree::{Cursor, Node};
use crate::format::{Perms, read_exact};

use super::{Bits, Ehdr};

pub(super) fn parse_phdrs(doc: &mut Document, e: &Ehdr) -> Result<Node> {
    if e.phnum == 0 || e.phentsize == 0 || e.phoff == 0 {
        return Ok(Node::group("Program Headers", e.phoff..e.phoff, Vec::new()));
    }
    let ent = e.phentsize as usize;
    let total = e.phnum as usize * ent;
    let raw = read_exact(doc, e.phoff, total)?;
    let mut kids = Vec::with_capacity(e.phnum as usize);
    for i in 0..e.phnum as usize {
        let base = e.phoff + (i * ent) as u64;
        let mut c = Cursor::new(&raw[i * ent..i * ent + ent], base, e.endian);
        let mut f = Vec::new();
        let (p_type, sp) = c.take_u32()?;
        f.push(Node::leaf("p_type", format!("{} ({:#x})", pt_name(p_type), p_type), sp));
        match e.bits {
            Bits::B64 => {
                let (fl, sp) = c.take_u32()?;
                f.push(Node::leaf("p_flags", pflags(fl), sp));
                for name in ["p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_align"] {
                    let (v, sp) = c.take_u64()?;
                    f.push(Node::leaf(name, format!("{v:#x}"), sp));
                }
            }
            Bits::B32 => {
                for name in ["p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz"] {
                    let (v, sp) = c.take_u32()?;
                    f.push(Node::leaf(name, format!("{v:#x}"), sp));
                }
                let (fl, sp) = c.take_u32()?;
                f.push(Node::leaf("p_flags", pflags(fl), sp));
                let (v, sp) = c.take_u32()?;
                f.push(Node::leaf("p_align", format!("{v:#x}"), sp));
            }
        }
        kids.push(Node::group(format!("[{i}] {}", pt_name(p_type)), base..base + ent as u64, f));
    }
    Ok(Node::group("Program Headers", e.phoff..e.phoff + total as u64, kids))
}

fn pt_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        0x6474_e551 => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        _ => "?",
    }
}

fn pflags(f: u32) -> String {
    let p = Perms { r: f & 4 != 0, w: f & 2 != 0, x: f & 1 != 0 };
    format!("{} ({f:#x})", p.rwx())
}
