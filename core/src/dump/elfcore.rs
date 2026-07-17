//! F-84 — ELF core-dump parsing: the memory map (`PT_LOAD`) and the process /
//! thread / module notes (`PT_NOTE`). 64-bit is parsed in full; a 32-bit core's
//! regions still enumerate, but its `NT_PRPSINFO`/`NT_FILE` layouts differ and
//! are left for later.

use super::{DumpKind, DumpReport, MemRegion, Module, ProcInfo, perms_from_pflags};
use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::format::{Arch, Bits, Cursor, read_exact};
use crate::inspector::Endian;
use crate::progress::Progress;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;
const NT_FILE: u32 = 0x4649_4c45; // "FILE"
/// Cap on a single PT_NOTE we will read into RAM.
const MAX_NOTE: usize = 64 << 20;

fn bad(detail: impl Into<String>) -> Error {
    Error::new(ErrorKind::Io, detail)
}

pub(super) fn inspect(doc: &mut Document, progress: &Progress) -> Result<DumpReport> {
    let ident = read_exact(doc, 0, 16)?;
    let bits = match ident[4] {
        1 => Bits::B32,
        2 => Bits::B64,
        c => return Err(bad(format!("invalid ELF class {c}"))),
    };
    let endian = match ident[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        d => return Err(bad(format!("invalid ELF data encoding {d}"))),
    };
    let hsize = if bits == Bits::B64 { 64 } else { 52 };
    let hdr = read_exact(doc, 0, hsize)?;
    let mut c = Cursor::new(&hdr, 0, endian);

    c.seek(18)?;
    let arch = arch_from_machine(c.u16()?);
    let (phoff, phentsize, phnum) = match bits {
        Bits::B64 => {
            c.seek(0x20)?;
            let phoff = c.u64()?;
            c.seek(0x36)?;
            (phoff, c.u16()?, c.u16()?)
        }
        Bits::B32 => {
            c.seek(0x1C)?;
            let phoff = c.u32()? as u64;
            c.seek(0x2A)?;
            (phoff, c.u16()?, c.u16()?)
        }
    };
    if phentsize as usize == 0 {
        return Err(bad("core has zero-size program headers"));
    }

    progress.set_total(phnum as u64);
    let mut regions = Vec::new();
    let mut note_spans = Vec::new();
    for i in 0..phnum as u64 {
        progress.add_done(1);
        let ph = read_exact(doc, phoff + i * phentsize as u64, phentsize as usize)?;
        let mut p = Cursor::new(&ph, 0, endian);
        let p_type = p.u32()?;
        let (offset, vaddr, filesz, memsz, flags) = read_phdr_body(&mut p, bits)?;
        match p_type {
            PT_LOAD => regions.push(MemRegion { vaddr, size: memsz, file_off: offset, perms: perms_from_pflags(flags) }),
            PT_NOTE => note_spans.push((offset, filesz)),
            _ => {}
        }
    }

    let mut processes = Vec::new();
    let mut modules = Vec::new();
    let mut threads = 0usize;
    for (off, size) in &note_spans {
        if *size == 0 {
            continue;
        }
        let data = read_exact(doc, *off, (*size as usize).min(MAX_NOTE))?;
        parse_notes(&data, endian, bits, &mut processes, &mut modules, &mut threads);
    }
    dedup_modules(&mut modules);

    let note = if bits == Bits::B32 {
        "32-bit core: regions only (NT_PRPSINFO/NT_FILE parsing is 64-bit)".into()
    } else {
        String::new()
    };
    Ok(DumpReport {
        kind: DumpKind::ElfCore,
        arch: Some(arch),
        bits: Some(bits),
        endian: Some(endian),
        processes,
        threads,
        regions,
        modules,
        note,
    })
}

/// Reads the size-dependent body of a program header, past `p_type`.
/// Returns `(p_offset, p_vaddr, p_filesz, p_memsz, p_flags)`.
fn read_phdr_body(p: &mut Cursor, bits: Bits) -> Result<(u64, u64, u64, u64, u32)> {
    match bits {
        Bits::B64 => {
            let flags = p.u32()?;
            let offset = p.u64()?;
            let vaddr = p.u64()?;
            let _paddr = p.u64()?;
            let filesz = p.u64()?;
            let memsz = p.u64()?;
            Ok((offset, vaddr, filesz, memsz, flags))
        }
        Bits::B32 => {
            let offset = p.u32()? as u64;
            let vaddr = p.u32()? as u64;
            let _paddr = p.u32()?;
            let filesz = p.u32()? as u64;
            let memsz = p.u32()? as u64;
            let flags = p.u32()?;
            Ok((offset, vaddr, filesz, memsz, flags))
        }
    }
}

fn parse_notes(
    data: &[u8],
    endian: Endian,
    bits: Bits,
    procs: &mut Vec<ProcInfo>,
    mods: &mut Vec<Module>,
    threads: &mut usize,
) {
    let mut c = Cursor::new(data, 0, endian);
    while c.remaining() >= 12 {
        let (Ok(namesz), Ok(descsz), Ok(ntype)) = (c.u32(), c.u32(), c.u32()) else { break };
        if c.skip(pad4(namesz as usize)).is_err() {
            break;
        }
        let start = c.pos();
        let descsz = descsz as usize;
        if c.remaining() < descsz {
            break;
        }
        let desc = &data[start..start + descsz];
        match ntype {
            NT_PRSTATUS => *threads += 1,
            NT_PRPSINFO if bits == Bits::B64 => {
                if let Some(p) = parse_prpsinfo64(desc, endian) {
                    procs.push(p);
                }
            }
            NT_FILE if bits == Bits::B64 => parse_nt_file64(desc, endian, mods),
            _ => {}
        }
        if c.skip(pad4(descsz)).is_err() {
            break;
        }
    }
}

/// `struct elf_prpsinfo` (LP64): pr_pid@24, pr_ppid@28, pr_fname[16]@40, pr_psargs[80]@56.
fn parse_prpsinfo64(desc: &[u8], endian: Endian) -> Option<ProcInfo> {
    if desc.len() < 56 {
        return None;
    }
    let mut c = Cursor::new(desc, 0, endian);
    c.seek(24).ok()?;
    let pid = c.u32().ok()? as i32;
    let ppid = c.u32().ok()? as i32;
    let name = cstr(&desc[40..56]);
    let args = if desc.len() >= 136 { cstr(&desc[56..136]) } else { String::new() };
    Some(ProcInfo { pid, ppid, name, args })
}

/// `NT_FILE` (64-bit): count, page_size, count×(start,end,file_off), then count
/// NUL-terminated filenames.
fn parse_nt_file64(desc: &[u8], endian: Endian, mods: &mut Vec<Module>) {
    let mut c = Cursor::new(desc, 0, endian);
    let (Ok(count), Ok(_page)) = (c.u64(), c.u64()) else { return };
    let count = (count as usize).min(1 << 16);
    let mut ranges = Vec::with_capacity(count);
    for _ in 0..count {
        let (Ok(start), Ok(end), Ok(_off)) = (c.u64(), c.u64(), c.u64()) else { return };
        ranges.push((start, end));
    }
    for (start, end) in ranges {
        mods.push(Module { name: read_cstr(&mut c), start, end });
    }
}

fn read_cstr(c: &mut Cursor) -> String {
    let mut bytes = Vec::new();
    while let Ok(b) = c.u8() {
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn pad4(n: usize) -> usize {
    n.next_multiple_of(4)
}

/// The same file is mapped many times (one per segment); collapse to one entry
/// per name, spanning the union of its ranges.
fn dedup_modules(mods: &mut Vec<Module>) {
    mods.sort_by(|a, b| a.name.cmp(&b.name).then(a.start.cmp(&b.start)));
    let mut out: Vec<Module> = Vec::new();
    for m in mods.drain(..) {
        match out.last_mut() {
            Some(prev) if prev.name == m.name => prev.end = prev.end.max(m.end),
            _ => out.push(m),
        }
    }
    out.sort_by_key(|m| m.start);
    *mods = out;
}

fn arch_from_machine(machine: u16) -> Arch {
    match machine {
        3 => Arch::X86,
        62 => Arch::X86_64,
        40 => Arch::Arm,
        183 => Arch::Aarch64,
        8 | 10 => Arch::Mips,
        20 => Arch::Ppc,
        21 => Arch::Ppc64,
        243 => Arch::RiscV,
        2 | 18 | 43 => Arch::Sparc,
        _ => Arch::Unknown,
    }
}
