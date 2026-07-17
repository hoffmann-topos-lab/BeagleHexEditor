//! F-70 — PE parser (PE-bear scope): DOS stub, COFF file header, optional header
//! (PE32 and PE32+), data directories, section table, and the import/export
//! tables. Hand-written over `Cursor` (D8); every field records its document
//! span. PE is always little-endian.
//!
//! The import and export tables live in [`imports`]; this parent owns the
//! headers, the section table and the RVA→file-offset map they all need.

mod imports;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::inspector::Endian;

use super::tree::{Cursor, Node};
use super::{Arch, BinaryInfo, Bits, ExtraEntry, Format, Perms, Section, read_exact};

const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_TLS: usize = 9;

/// A section table entry, kept raw for RVA mapping (imports/exports resolve RVAs
/// against it).
struct RawSection {
    vaddr: u32, // RVA, relative to ImageBase
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
}

/// What the header pass hands to the table passes.
struct PeCtx {
    bits: Bits,
    image_base: u64,
    sections: Vec<RawSection>,
    dirs: Vec<(u32, u32)>, // (RVA, size) per data directory
}

pub(super) fn parse(doc: &mut Document) -> Result<BinaryInfo> {
    // DOS header: "MZ", then e_lfanew at 0x3C points to the PE header.
    let dos = read_exact(doc, 0, 64)?;
    if dos[0..2] != [b'M', b'Z'] {
        return Err(Error::new(ErrorKind::Io, "not a PE file (no MZ signature)"));
    }
    let e_lfanew = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]) as u64;
    let dos_node = Node::group(
        "DOS Header",
        0..64,
        vec![
            Node::leaf("e_magic", "MZ", 0..2),
            Node::leaf("e_lfanew", format!("{e_lfanew:#x}"), 0x3C..0x40),
        ],
    );

    let sig = read_exact(doc, e_lfanew, 4)?;
    if sig != [b'P', b'E', 0, 0] {
        return Err(Error::new(ErrorKind::Io, "not a PE file (no PE signature)"));
    }

    let (coff_node, machine, num_sections, opt_size) = parse_coff(doc, e_lfanew + 4)?;
    let opt_off = e_lfanew + 4 + 20;
    let (opt_node, arch, bits, image_base, entry_rva, mut ctx) =
        parse_optional(doc, opt_off, opt_size as usize, machine)?;

    let sec_off = opt_off + opt_size as u64;
    let (sec_node, sections) = parse_sections(doc, sec_off, num_sections, image_base, &mut ctx)?;

    let (imp_node, imports, libs) = imports::parse_imports(doc, &ctx)?;
    let (exp_node, symbols) = imports::parse_exports(doc, &ctx)?;
    let extra_entries = parse_tls_callbacks(doc, &ctx);

    let mut kids = vec![dos_node, coff_node, opt_node, sec_node];
    kids.extend(imp_node);
    kids.extend(exp_node);
    let tree = Node::group("PE", 0..doc.len(), kids);

    Ok(BinaryInfo {
        format: Format::Pe,
        arch,
        bits,
        endian: Endian::Little,
        entry: if entry_rva == 0 { 0 } else { image_base + entry_rva as u64 },
        sections,
        symbols,
        imports,
        libs,
        relocs: Vec::new(),
        extra_entries,
        tree,
    })
}

/// Reads the TLS directory's callback array (F-75 flags these — anti-analysis
/// code runs here before `entry`). Best-effort: any misread yields no callbacks.
/// `AddressOfCallBacks` is a virtual address pointing at a null-terminated array
/// of virtual addresses.
fn parse_tls_callbacks(doc: &mut Document, ctx: &PeCtx) -> Vec<ExtraEntry> {
    let Some((tls_rva, _)) = ctx.dir(DIR_TLS) else {
        return Vec::new();
    };
    let Some(tls_off) = ctx.rva_to_off(tls_rva) else {
        return Vec::new();
    };
    let word = match ctx.bits {
        Bits::B32 => 4usize,
        Bits::B64 => 8,
    };
    // AddressOfCallBacks is the 4th pointer-sized field of the TLS directory.
    let cb_ptr_off = tls_off + 3 * word as u64;
    let Some(cb_va) = read_ptr(doc, cb_ptr_off, ctx.bits) else {
        return Vec::new();
    };
    if cb_va < ctx.image_base {
        return Vec::new();
    }
    let Some(mut off) = ctx.rva_to_off((cb_va - ctx.image_base) as u32) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    while out.len() < 1024 {
        match read_ptr(doc, off, ctx.bits) {
            Some(0) | None => break, // null terminator ends the array
            Some(va) => out.push(ExtraEntry { kind: "TLS callback", vaddr: va }),
        }
        off += word as u64;
    }
    out
}

/// Reads a pointer-sized little-endian value, or `None` if unreadable.
fn read_ptr(doc: &mut Document, off: u64, bits: Bits) -> Option<u64> {
    let len = match bits {
        Bits::B32 => 4,
        Bits::B64 => 8,
    };
    let r = doc.read(off, len);
    if !r.is_clean() || r.data.len() < len {
        return None;
    }
    Some(match bits {
        Bits::B32 => u32::from_le_bytes([r.data[0], r.data[1], r.data[2], r.data[3]]) as u64,
        Bits::B64 => u64::from_le_bytes(r.data[..8].try_into().unwrap()),
    })
}

fn parse_coff(doc: &mut Document, off: u64) -> Result<(Node, u16, u16, u16)> {
    let raw = read_exact(doc, off, 20)?;
    let mut c = Cursor::new(&raw, off, Endian::Little);
    let (machine, m_sp) = c.take_u16()?;
    let (num_sections, ns_sp) = c.take_u16()?;
    let (timestamp, ts_sp) = c.take_u32()?;
    let (sym_ptr, sp_sp) = c.take_u32()?;
    let (num_syms, nsym_sp) = c.take_u32()?;
    let (opt_size, os_sp) = c.take_u16()?;
    let (chars, ch_sp) = c.take_u16()?;
    let node = Node::group(
        "COFF File Header",
        off..off + 20,
        vec![
            Node::leaf("Machine", format!("{} ({:#x})", machine_arch(machine).0.name(), machine), m_sp),
            Node::leaf("NumberOfSections", format!("{num_sections}"), ns_sp),
            Node::leaf("TimeDateStamp", format!("{timestamp:#x}"), ts_sp),
            Node::leaf("PointerToSymbolTable", format!("{sym_ptr:#x}"), sp_sp),
            Node::leaf("NumberOfSymbols", format!("{num_syms}"), nsym_sp),
            Node::leaf("SizeOfOptionalHeader", format!("{opt_size:#x}"), os_sp),
            Node::leaf("Characteristics", format!("{chars:#x}"), ch_sp),
        ],
    );
    Ok((node, machine, num_sections, opt_size))
}

#[allow(clippy::type_complexity)]
fn parse_optional(
    doc: &mut Document,
    off: u64,
    size: usize,
    machine: u16,
) -> Result<(Node, Arch, Bits, u64, u32, PeCtx)> {
    if size < 2 {
        return Err(Error::new(ErrorKind::Io, "PE optional header is missing"));
    }
    let raw = read_exact(doc, off, size)?;
    let mut c = Cursor::new(&raw, off, Endian::Little);
    let (magic, magic_sp) = c.take_u16()?;
    let bits = match magic {
        0x10b => Bits::B32,
        0x20b => Bits::B64,
        m => return Err(Error::new(ErrorKind::Io, format!("unknown optional header magic {m:#x}"))),
    };
    let (arch, _) = machine_arch(machine);

    let mut f = vec![Node::leaf("Magic", format!("{} ({magic:#x})", bits.name()), magic_sp)];
    f.push(byte_field(&mut c, "MajorLinkerVersion")?);
    f.push(byte_field(&mut c, "MinorLinkerVersion")?);
    for name in ["SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData"] {
        f.push(u32_field(&mut c, name)?);
    }
    let (entry_rva, sp) = c.take_u32()?;
    f.push(Node::leaf("AddressOfEntryPoint", format!("{entry_rva:#x}"), sp));
    f.push(u32_field(&mut c, "BaseOfCode")?);
    if bits == Bits::B32 {
        f.push(u32_field(&mut c, "BaseOfData")?);
    }
    let (image_base, sp) = take_word(&mut c, bits)?;
    f.push(Node::leaf("ImageBase", format!("{image_base:#x}"), sp));
    for name in ["SectionAlignment", "FileAlignment"] {
        f.push(u32_field(&mut c, name)?);
    }
    for name in [
        "MajorOperatingSystemVersion",
        "MinorOperatingSystemVersion",
        "MajorImageVersion",
        "MinorImageVersion",
        "MajorSubsystemVersion",
        "MinorSubsystemVersion",
    ] {
        f.push(u16_field(&mut c, name)?);
    }
    f.push(u32_field(&mut c, "Win32VersionValue")?);
    for name in ["SizeOfImage", "SizeOfHeaders", "CheckSum"] {
        f.push(u32_field(&mut c, name)?);
    }
    let (subsystem, sp) = c.take_u16()?;
    f.push(Node::leaf("Subsystem", format!("{} ({subsystem})", subsystem_name(subsystem)), sp));
    f.push(u16_field(&mut c, "DllCharacteristics")?);
    for name in [
        "SizeOfStackReserve",
        "SizeOfStackCommit",
        "SizeOfHeapReserve",
        "SizeOfHeapCommit",
    ] {
        let (v, sp) = take_word(&mut c, bits)?;
        f.push(Node::leaf(name, format!("{v:#x}"), sp));
    }
    f.push(u32_field(&mut c, "LoaderFlags")?);
    let (num_dirs, sp) = c.take_u32()?;
    f.push(Node::leaf("NumberOfRvaAndSizes", format!("{num_dirs}"), sp));

    let mut dirs = Vec::new();
    let mut dir_nodes = Vec::new();
    for i in 0..num_dirs.min(16) as usize {
        let (rva, rva_sp) = c.take_u32()?;
        let (dsize, size_sp) = c.take_u32()?;
        dirs.push((rva, dsize));
        dir_nodes.push(Node::group(
            format!("[{i}] {}", dir_name(i)),
            rva_sp.start..size_sp.end,
            vec![
                Node::leaf("VirtualAddress", format!("{rva:#x}"), rva_sp),
                Node::leaf("Size", format!("{dsize:#x}"), size_sp),
            ],
        ));
    }
    f.push(Node::group("DataDirectories", off..off + size as u64, dir_nodes));

    let node = Node::group("Optional Header", off..off + size as u64, f);
    let ctx = PeCtx { bits, image_base, sections: Vec::new(), dirs };
    Ok((node, arch, bits, image_base, entry_rva, ctx))
}

fn parse_sections(
    doc: &mut Document,
    off: u64,
    count: u16,
    image_base: u64,
    ctx: &mut PeCtx,
) -> Result<(Node, Vec<Section>)> {
    let total = count as usize * 40;
    let raw = read_exact(doc, off, total)?;
    let mut kids = Vec::with_capacity(count as usize);
    let mut sections = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let base = off + (i * 40) as u64;
        let mut c = Cursor::new(&raw[i * 40..i * 40 + 40], base, Endian::Little);
        let (name_bytes, name_sp) = c.take_bytes(8)?;
        let name = section_name(name_bytes);
        let (vsize, vs_sp) = c.take_u32()?;
        let (vaddr, va_sp) = c.take_u32()?;
        let (raw_size, rs_sp) = c.take_u32()?;
        let (raw_ptr, rp_sp) = c.take_u32()?;
        c.skip(4)?; // PointerToRelocations
        c.skip(4)?; // PointerToLinenumbers
        c.skip(2)?; // NumberOfRelocations
        c.skip(2)?; // NumberOfLinenumbers
        let (chars, ch_sp) = c.take_u32()?;

        kids.push(Node::group(
            name.clone(),
            base..base + 40,
            vec![
                Node::leaf("Name", name.clone(), name_sp),
                Node::leaf("VirtualSize", format!("{vsize:#x}"), vs_sp),
                Node::leaf("VirtualAddress", format!("{vaddr:#x}"), va_sp),
                Node::leaf("SizeOfRawData", format!("{raw_size:#x}"), rs_sp),
                Node::leaf("PointerToRawData", format!("{raw_ptr:#x}"), rp_sp),
                Node::leaf("Characteristics", section_chars(chars), ch_sp),
            ],
        ));
        let file = raw_ptr as u64..raw_ptr as u64 + raw_size as u64;
        sections.push(Section {
            name: name.clone(),
            file,
            vaddr: image_base + vaddr as u64,
            size: vsize as u64,
            perms: Perms {
                r: chars & 0x4000_0000 != 0, // IMAGE_SCN_MEM_READ
                w: chars & 0x8000_0000 != 0, // IMAGE_SCN_MEM_WRITE
                x: chars & 0x2000_0000 != 0, // IMAGE_SCN_MEM_EXECUTE
            },
        });
        ctx.sections.push(RawSection { vaddr, vsize, raw_ptr, raw_size });
    }
    Ok((Node::group("Section Headers", off..off + total as u64, kids), sections))
}

impl PeCtx {
    /// Maps a relative virtual address to a document offset, using the section
    /// whose mapped range contains it. `None` for an RVA in a virtual-only
    /// region (no file bytes) or outside every section.
    fn rva_to_off(&self, rva: u32) -> Option<u64> {
        for s in &self.sections {
            let vsize = if s.vsize == 0 { s.raw_size } else { s.vsize };
            if rva >= s.vaddr && rva < s.vaddr.saturating_add(vsize) {
                let delta = rva - s.vaddr;
                return (delta < s.raw_size).then(|| s.raw_ptr as u64 + delta as u64);
            }
        }
        None
    }

    fn dir(&self, i: usize) -> Option<(u32, u32)> {
        self.dirs.get(i).copied().filter(|&(rva, size)| rva != 0 && size != 0)
    }
}

// ---- small helpers ----

fn byte_field(c: &mut Cursor, name: &str) -> Result<Node> {
    let start = c.abs();
    let v = c.u8()?;
    Ok(Node::leaf(name, format!("{v}"), start..c.abs()))
}

fn u16_field(c: &mut Cursor, name: &str) -> Result<Node> {
    let (v, sp) = c.take_u16()?;
    Ok(Node::leaf(name, format!("{v:#x}"), sp))
}

fn u32_field(c: &mut Cursor, name: &str) -> Result<Node> {
    let (v, sp) = c.take_u32()?;
    Ok(Node::leaf(name, format!("{v:#x}"), sp))
}

fn take_word(c: &mut Cursor, bits: Bits) -> Result<(u64, std::ops::Range<u64>)> {
    match bits {
        Bits::B32 => {
            let (v, sp) = c.take_u32()?;
            Ok((v as u64, sp))
        }
        Bits::B64 => c.take_u64(),
    }
}

fn section_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn machine_arch(m: u16) -> (Arch, Bits) {
    match m {
        0x014c => (Arch::X86, Bits::B32),
        0x8664 => (Arch::X86_64, Bits::B64),
        0x01c0 | 0x01c4 => (Arch::Arm, Bits::B32),
        0xaa64 => (Arch::Aarch64, Bits::B64),
        0x0166 | 0x0366 | 0x0466 => (Arch::Mips, Bits::B32),
        _ => (Arch::Unknown, Bits::B32),
    }
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        0 => "UNKNOWN",
        1 => "NATIVE",
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        5 => "OS2_CUI",
        7 => "POSIX_CUI",
        9 => "WINDOWS_CE_GUI",
        10 => "EFI_APPLICATION",
        11 => "EFI_BOOT_SERVICE_DRIVER",
        12 => "EFI_RUNTIME_DRIVER",
        13 => "EFI_ROM",
        14 => "XBOX",
        _ => "?",
    }
}

fn dir_name(i: usize) -> &'static str {
    match i {
        DIR_EXPORT => "Export",
        DIR_IMPORT => "Import",
        2 => "Resource",
        3 => "Exception",
        4 => "Certificate",
        5 => "BaseReloc",
        6 => "Debug",
        7 => "Architecture",
        8 => "GlobalPtr",
        9 => "TLS",
        10 => "LoadConfig",
        11 => "BoundImport",
        12 => "IAT",
        13 => "DelayImport",
        14 => "CLRRuntime",
        _ => "?",
    }
}

fn section_chars(c: u32) -> String {
    let mut s = String::new();
    if c & 0x2000_0000 != 0 {
        s.push('X');
    }
    if c & 0x4000_0000 != 0 {
        s.push('R');
    }
    if c & 0x8000_0000 != 0 {
        s.push('W');
    }
    if c & 0x20 != 0 {
        s.push('C'); // CODE
    }
    if s.is_empty() {
        s.push('-');
    }
    format!("{s} ({c:#x})")
}
