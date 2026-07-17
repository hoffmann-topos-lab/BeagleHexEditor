//! F-71 — Mach-O parser (otool scope): fat/universal and thin images, the load
//! commands (segments + sections, `LC_SYMTAB`, dylib dependencies, the entry
//! point) in either byte order and word size. Hand-written over `Cursor` (D8).
//!
//! The symbol table lives in [`symbols`]; this parent owns the headers, the
//! load-command walk and the segment/section view.

mod symbols;

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::inspector::Endian;

use super::tree::{Cursor, Node};
use super::{Arch, BinaryInfo, Bits, Format, Perms, Section, read_exact};

// Load commands the parser follows. `LC_REQ_DYLD` (0x8000_0000) is OR'd into the
// commands the loader must understand.
const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_LOAD_DYLIB: u32 = 0xC;
const LC_ID_DYLIB: u32 = 0xD;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
const LC_SEGMENT_64: u32 = 0x19;
const LC_REEXPORT_DYLIB: u32 = 0x1F | LC_REQ_DYLD;
const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;

/// `LC_SYMTAB` payload: where the symbol and string tables live.
struct SymtabCmd {
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

/// A parsed segment's file/VM mapping, kept to turn the `LC_MAIN` file offset
/// into a virtual address.
struct SegMap {
    fileoff: u64,
    filesize: u64,
    vmaddr: u64,
}

pub(super) fn parse(doc: &mut Document) -> Result<BinaryInfo> {
    let magic = read_exact(doc, 0, 4)?;
    if magic == [0xCA, 0xFE, 0xBA, 0xBE] {
        parse_fat(doc)
    } else {
        parse_thin(doc, 0)
    }
}

/// Universal binary: a big-endian header of arch entries pointing at thin slices.
/// The first slice is parsed for the facts; every slice is listed in the tree.
fn parse_fat(doc: &mut Document) -> Result<BinaryInfo> {
    let head = read_exact(doc, 0, 8)?;
    let nfat = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    if nfat == 0 || nfat > 64 {
        return Err(Error::new(ErrorKind::Io, "implausible fat arch count"));
    }
    let mut arch_nodes = Vec::with_capacity(nfat as usize);
    let mut first_slice = None;
    for i in 0..nfat as usize {
        let off = 8 + (i * 20) as u64;
        let raw = read_exact(doc, off, 20)?;
        let mut c = Cursor::new(&raw, off, Endian::Big);
        let (cputype, ct_sp) = c.take_u32()?;
        c.skip(4)?; // cpusubtype
        let (slice_off, so_sp) = c.take_u32()?;
        let (slice_size, ss_sp) = c.take_u32()?;
        arch_nodes.push(Node::group(
            format!("[{i}] {}", arch_of(cputype).name()),
            off..off + 20,
            vec![
                Node::leaf("cputype", format!("{} ({cputype:#x})", arch_of(cputype).name()), ct_sp),
                Node::leaf("offset", format!("{slice_off:#x}"), so_sp),
                Node::leaf("size", format!("{slice_size:#x}"), ss_sp),
            ],
        ));
        first_slice.get_or_insert(slice_off as u64);
    }
    let slice_off = first_slice.expect("nfat > 0 checked");
    let mut info = parse_thin(doc, slice_off)?;
    let fat_node = Node::group("Fat Header", 0..8 + (nfat * 20) as u64, arch_nodes);
    info.tree = Node::group("Mach-O (universal)", 0..doc.len(), vec![fat_node, info.tree]);
    Ok(info)
}

/// A single (thin) image starting at document offset `base` — 0 for a plain
/// Mach-O, or a slice offset inside a fat binary.
fn parse_thin(doc: &mut Document, base: u64) -> Result<BinaryInfo> {
    let magic = read_exact(doc, base, 4)?;
    let (endian, bits) = match magic[..] {
        [0xCE, 0xFA, 0xED, 0xFE] => (Endian::Little, Bits::B32),
        [0xCF, 0xFA, 0xED, 0xFE] => (Endian::Little, Bits::B64),
        [0xFE, 0xED, 0xFA, 0xCE] => (Endian::Big, Bits::B32),
        [0xFE, 0xED, 0xFA, 0xCF] => (Endian::Big, Bits::B64),
        _ => return Err(Error::new(ErrorKind::Io, "not a Mach-O image")),
    };
    let hdrsize = if bits == Bits::B64 { 32 } else { 28 };
    let hdr = read_exact(doc, base, hdrsize)?;
    let mut c = Cursor::new(&hdr, base, endian);
    c.skip(4)?; // magic
    let (cputype, ct_sp) = c.take_u32()?;
    let (_subtype, _) = c.take_u32()?;
    let (filetype, ft_sp) = c.take_u32()?;
    let (ncmds, nc_sp) = c.take_u32()?;
    let (sizeofcmds, soc_sp) = c.take_u32()?;
    let (flags, fl_sp) = c.take_u32()?;
    let arch = arch_of(cputype);

    let hdr_node = Node::group(
        "Mach Header",
        base..base + hdrsize as u64,
        vec![
            Node::leaf("magic", format!("{} {}", arch.name(), bits.name()), base..base + 4),
            Node::leaf("cputype", format!("{} ({cputype:#x})", arch.name()), ct_sp),
            Node::leaf("filetype", format!("{} ({filetype:#x})", filetype_name(filetype)), ft_sp),
            Node::leaf("ncmds", format!("{ncmds}"), nc_sp),
            Node::leaf("sizeofcmds", format!("{sizeofcmds:#x}"), soc_sp),
            Node::leaf("flags", format!("{flags:#x}"), fl_sp),
        ],
    );

    let cmds_off = base + hdrsize as u64;
    let cmd_raw = read_exact(doc, cmds_off, sizeofcmds as usize)?;

    let mut cmd_nodes = Vec::new();
    let mut sections = Vec::new();
    let mut segmaps = Vec::new();
    let mut libs = Vec::new();
    let mut symtab = None;
    let mut entry_off = None;

    let mut pos = 0usize;
    for _ in 0..ncmds {
        if pos + 8 > cmd_raw.len() {
            break;
        }
        let cmd_doc = cmds_off + pos as u64;
        let mut cc = Cursor::new(&cmd_raw[pos..], cmd_doc, endian);
        let cmd = cc.u32()?;
        let cmdsize = cc.u32()? as usize;
        if cmdsize < 8 || pos + cmdsize > cmd_raw.len() {
            break; // malformed command size
        }
        let body = &cmd_raw[pos..pos + cmdsize];

        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => {
                let node =
                    parse_segment(body, base, cmd_doc, endian, bits, &mut sections, &mut segmaps)?;
                cmd_nodes.push(node);
            }
            LC_SYMTAB => {
                let (st, node) = parse_symtab_cmd(body, cmd_doc, endian)?;
                symtab = Some(st);
                cmd_nodes.push(node);
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_ID_DYLIB => {
                let name = dylib_name(body, endian);
                if cmd != LC_ID_DYLIB {
                    libs.push(name.clone());
                }
                cmd_nodes.push(Node::leaf(lc_name(cmd), name, cmd_doc..cmd_doc + cmdsize as u64));
            }
            LC_MAIN => {
                let mut mc = Cursor::new(&body[8..], cmd_doc + 8, endian);
                let (eoff, sp) = mc.take_u64()?;
                entry_off = Some(eoff);
                cmd_nodes.push(Node::group(
                    "LC_MAIN",
                    cmd_doc..cmd_doc + cmdsize as u64,
                    vec![Node::leaf("entryoff", format!("{eoff:#x}"), sp)],
                ));
            }
            _ => cmd_nodes.push(Node::leaf(
                lc_name(cmd),
                format!("{cmdsize} bytes"),
                cmd_doc..cmd_doc + cmdsize as u64,
            )),
        }
        pos += cmdsize;
    }

    let entry = entry_off.map(|off| off_to_vaddr(&segmaps, off)).unwrap_or(0);
    let (symbols, imports) = match symtab {
        Some(st) => symbols::parse_symtab(doc, base, bits, endian, &st, &libs)?,
        None => (Vec::new(), Vec::new()),
    };

    let mut kids = vec![hdr_node];
    kids.append(&mut cmd_nodes);
    let tree = Node::group("Mach-O", base..doc.len(), kids);

    Ok(BinaryInfo {
        format: Format::MachO,
        arch,
        bits,
        endian,
        entry,
        sections,
        symbols,
        imports,
        libs,
        relocs: Vec::new(),
        extra_entries: Vec::new(),
        tree,
    })
}

/// `base` is the image origin (0 for a thin file, the slice offset for a fat
/// binary); a section's `offset` field is relative to it, so a section's
/// document offset is `base + offset`. `doc` is where this command sits.
fn parse_segment(
    body: &[u8],
    base: u64,
    doc: u64,
    endian: Endian,
    bits: Bits,
    sections: &mut Vec<Section>,
    segmaps: &mut Vec<SegMap>,
) -> Result<Node> {
    let mut c = Cursor::new(body, doc, endian);
    c.skip(8)?; // cmd, cmdsize
    let (segname, name_sp) = c.take_bytes(16)?;
    let name = fixed_name(segname);
    let (vmaddr, vm_sp) = take_word(&mut c, bits)?;
    let (vmsize, vs_sp) = take_word(&mut c, bits)?;
    let (fileoff, fo_sp) = take_word(&mut c, bits)?;
    let (filesize, _) = take_word(&mut c, bits)?;
    let _maxprot = c.u32()?;
    let (initprot, ip_sp) = c.take_u32()?;
    let (nsects, ns_sp) = c.take_u32()?;
    let _flags = c.u32()?;
    segmaps.push(SegMap { fileoff, filesize, vmaddr });
    let perms = prot_perms(initprot);

    let mut fields = vec![
        Node::leaf("segname", name.clone(), name_sp),
        Node::leaf("vmaddr", format!("{vmaddr:#x}"), vm_sp),
        Node::leaf("vmsize", format!("{vmsize:#x}"), vs_sp),
        Node::leaf("fileoff", format!("{fileoff:#x}"), fo_sp),
        Node::leaf("initprot", perms.rwx(), ip_sp),
        Node::leaf("nsects", format!("{nsects}"), ns_sp),
    ];
    let sect_size = if bits == Bits::B64 { 80 } else { 68 };
    for _ in 0..nsects.min(1024) {
        let start = c.pos();
        if start + sect_size > body.len() {
            break;
        }
        let sect_doc = doc + start as u64;
        let mut sc = Cursor::new(&body[start..start + sect_size], sect_doc, endian);
        let (sectname, sn_sp) = sc.take_bytes(16)?;
        sc.skip(16)?; // segname (owning segment, redundant here)
        let addr = take_word(&mut sc, bits)?.0;
        let size = take_word(&mut sc, bits)?.0;
        let offset = sc.u32()?;
        let sname = fixed_name(sectname);
        let file = if offset == 0 {
            0..0 // zero-fill section: no file bytes
        } else {
            base + offset as u64..base + offset as u64 + size
        };
        fields.push(Node::leaf(format!("{name},{sname}"), format!("{size:#x} @ {addr:#x}"), sn_sp));
        sections.push(Section { name: sname, file, vaddr: addr, size, perms });
        c.seek(start + sect_size)?;
    }
    Ok(Node::group(name, doc..doc + body.len() as u64, fields))
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

fn parse_symtab_cmd(body: &[u8], doc: u64, endian: Endian) -> Result<(SymtabCmd, Node)> {
    let mut c = Cursor::new(body, doc, endian);
    c.skip(8)?; // cmd, cmdsize
    let (symoff, so_sp) = c.take_u32()?;
    let (nsyms, ns_sp) = c.take_u32()?;
    let (stroff, sto_sp) = c.take_u32()?;
    let (strsize, sts_sp) = c.take_u32()?;
    let node = Node::group(
        "LC_SYMTAB",
        doc..doc + body.len() as u64,
        vec![
            Node::leaf("symoff", format!("{symoff:#x}"), so_sp),
            Node::leaf("nsyms", format!("{nsyms}"), ns_sp),
            Node::leaf("stroff", format!("{stroff:#x}"), sto_sp),
            Node::leaf("strsize", format!("{strsize:#x}"), sts_sp),
        ],
    );
    Ok((SymtabCmd { symoff, nsyms, stroff, strsize }, node))
}

/// The name string of a dylib load command lives at `name.offset` within the
/// command body and runs to the command's end.
fn dylib_name(body: &[u8], endian: Endian) -> String {
    if body.len() < 12 {
        return String::new();
    }
    let off = match endian {
        Endian::Little => u32::from_le_bytes([body[8], body[9], body[10], body[11]]),
        Endian::Big => u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
    } as usize;
    if off >= body.len() {
        return String::new();
    }
    let rest = &body[off..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

fn off_to_vaddr(segmaps: &[SegMap], file_off: u64) -> u64 {
    for s in segmaps {
        if file_off >= s.fileoff && file_off < s.fileoff + s.filesize {
            return s.vmaddr + (file_off - s.fileoff);
        }
    }
    0
}

fn fixed_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn prot_perms(prot: u32) -> Perms {
    Perms { r: prot & 1 != 0, w: prot & 2 != 0, x: prot & 4 != 0 }
}

fn arch_of(cputype: u32) -> Arch {
    match cputype {
        7 => Arch::X86,
        0x0100_0007 => Arch::X86_64,
        12 => Arch::Arm,
        0x0100_000C => Arch::Aarch64,
        18 => Arch::Ppc,
        0x0100_0012 => Arch::Ppc64,
        14 => Arch::Sparc,
        _ => Arch::Unknown,
    }
}

fn filetype_name(t: u32) -> &'static str {
    match t {
        1 => "OBJECT",
        2 => "EXECUTE",
        3 => "FVMLIB",
        4 => "CORE",
        5 => "PRELOAD",
        6 => "DYLIB",
        7 => "DYLINKER",
        8 => "BUNDLE",
        9 => "DYLIB_STUB",
        10 => "DSYM",
        11 => "KEXT_BUNDLE",
        _ => "?",
    }
}

fn lc_name(cmd: u32) -> &'static str {
    match cmd {
        LC_SEGMENT => "LC_SEGMENT",
        LC_SEGMENT_64 => "LC_SEGMENT_64",
        LC_SYMTAB => "LC_SYMTAB",
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
        LC_ID_DYLIB => "LC_ID_DYLIB",
        LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
        LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
        LC_MAIN => "LC_MAIN",
        0x5 => "LC_UNIXTHREAD",
        0xB => "LC_DYSYMTAB",
        0xE => "LC_LOAD_DYLINKER",
        0x1B => "LC_UUID",
        0x22 => "LC_DYLD_INFO",
        0x80000022 => "LC_DYLD_INFO_ONLY",
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x26 => "LC_FUNCTION_STARTS",
        0x29 => "LC_DATA_IN_CODE",
        0x2B => "LC_SOURCE_VERSION",
        0x32 => "LC_BUILD_VERSION",
        _ => "LC_?",
    }
}
