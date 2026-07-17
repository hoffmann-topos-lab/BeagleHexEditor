//! F-71 — Mach-O parser, over a hand-built thin little-endian x86-64 executable
//! with a `__TEXT`/`__text`, an `LC_SYMTAB` (a defined `_main` and an imported
//! `_printf`), an `LC_LOAD_DYLIB` and an `LC_MAIN`.

use super::{W, doc};
use crate::format::{parse, Arch, Bits, Format, Perms};
use crate::inspector::Endian;

fn name16(s: &str) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..s.len()].copy_from_slice(s.as_bytes());
    a
}

fn tiny_macho64() -> Vec<u8> {
    let mut w = W::new();

    // ---- mach_header_64 (32 bytes) ----
    w.u32(0xFEED_FACF); // magic (little-endian, 64-bit)
    w.u32(0x0100_0007); // cputype = x86-64
    w.u32(3); // cpusubtype
    w.u32(2); // filetype = MH_EXECUTE
    w.u32(4); // ncmds
    w.u32(256); // sizeofcmds
    w.u32(0x0020_0085); // flags
    w.u32(0); // reserved
    assert_eq!(w.len(), 32);

    // ---- LC_SEGMENT_64 __TEXT (152 bytes) ----
    let seg = w.len();
    w.u32(0x19); // LC_SEGMENT_64
    w.u32(152); // cmdsize
    w.bytes(&name16("__TEXT"));
    w.u64(0x1_0000_0000); // vmaddr
    w.u64(0x1000); // vmsize
    w.u64(0); // fileoff
    w.u64(0x400); // filesize
    w.u32(7); // maxprot rwx
    w.u32(5); // initprot r-x
    w.u32(1); // nsects
    w.u32(0); // flags
    // section_64 __text
    w.bytes(&name16("__text"));
    w.bytes(&name16("__TEXT"));
    w.u64(0x1_0000_0120); // addr
    w.u64(4); // size
    w.u32(0x120); // offset
    w.u32(0); // align
    w.u32(0); // reloff
    w.u32(0); // nreloc
    w.u32(0); // flags
    w.u32(0); // reserved1
    w.u32(0); // reserved2
    w.u32(0); // reserved3
    assert_eq!(w.len() - seg, 152);

    // ---- LC_SYMTAB (24 bytes) ----
    w.u32(0x2); // LC_SYMTAB
    w.u32(24); // cmdsize
    w.u32(0x130); // symoff
    w.u32(2); // nsyms
    w.u32(0x150); // stroff
    w.u32(15); // strsize

    // ---- LC_LOAD_DYLIB (56 bytes) ----
    let dylib = w.len();
    w.u32(0xC); // LC_LOAD_DYLIB
    w.u32(56); // cmdsize
    w.u32(24); // name.offset
    w.u32(0); // timestamp
    w.u32(0); // current_version
    w.u32(0); // compatibility_version
    w.bytes(b"/usr/lib/libSystem.B.dylib\0");
    while w.len() - dylib < 56 {
        w.u8(0);
    }
    assert_eq!(w.len() - dylib, 56);

    // ---- LC_MAIN (24 bytes) ----
    w.u32(0x8000_0028); // LC_MAIN
    w.u32(24); // cmdsize
    w.u64(0x120); // entryoff (file offset of __text)
    w.u64(0); // stacksize
    assert_eq!(w.len(), 0x120); // header (32) + sizeofcmds (256)

    // ---- __text code at 0x120 ----
    w.bytes(&[0x55, 0x48, 0x89, 0xE5]); // push rbp; mov rbp, rsp
    while w.len() < 0x130 {
        w.u8(0);
    }

    // ---- symbol table (2 x nlist_64) at 0x130 ----
    // _main: defined in section 1, external
    w.u32(1); // n_strx -> "_main"
    w.u8(0x0f); // n_type = N_SECT | N_EXT
    w.u8(1); // n_sect
    w.u16(0); // n_desc
    w.u64(0x1_0000_0120); // n_value
    // _printf: undefined, external, library ordinal 1
    w.u32(7); // n_strx -> "_printf"
    w.u8(0x01); // n_type = N_UNDF | N_EXT
    w.u8(0); // n_sect
    w.u16(0x0100); // n_desc: library ordinal 1 (high byte)
    w.u64(0); // n_value
    assert_eq!(w.len(), 0x150);

    // ---- string table (15 bytes) at 0x150 ----
    w.u8(0);
    w.bytes(b"_main\0"); // offset 1
    w.bytes(b"_printf\0"); // offset 7
    assert_eq!(w.len(), 0x150 + 15);

    while w.len() < 0x400 {
        w.u8(0);
    }
    w.done()
}

#[test]
fn parses_the_macho_header_facts() {
    let mut d = doc(tiny_macho64());
    let info = parse(&mut d).unwrap();
    assert_eq!(info.format, Format::MachO);
    assert_eq!(info.arch, Arch::X86_64);
    assert_eq!(info.bits, Bits::B64);
    assert_eq!(info.endian, Endian::Little);
    // LC_MAIN entryoff mapped through the __TEXT segment to a virtual address
    assert_eq!(info.entry, 0x1_0000_0120);
}

#[test]
fn lists_macho_sections_with_file_ranges() {
    let mut d = doc(tiny_macho64());
    let info = parse(&mut d).unwrap();
    let text = info.sections.iter().find(|s| s.name == "__text").expect("__text present");
    assert_eq!(text.vaddr, 0x1_0000_0120);
    assert_eq!(text.size, 4);
    assert_eq!(text.perms, Perms { r: true, w: false, x: true });
    let bytes = d.read(text.file.start, 4);
    assert_eq!(bytes.data, vec![0x55, 0x48, 0x89, 0xE5]);
}

#[test]
fn reads_dylibs_symbols_and_imports() {
    let mut d = doc(tiny_macho64());
    let info = parse(&mut d).unwrap();
    assert_eq!(info.libs, vec!["/usr/lib/libSystem.B.dylib"]);
    assert!(info.symbols.iter().any(|s| s.name == "_main" && s.defined));
    let printf = info.imports.iter().find(|i| i.name == "_printf").expect("_printf imported");
    // two-level namespace: the ordinal resolves to the dylib it comes from
    assert_eq!(printf.library, "/usr/lib/libSystem.B.dylib");
}

#[test]
fn the_segment_and_symtab_are_in_the_tree() {
    let mut d = doc(tiny_macho64());
    let info = parse(&mut d).unwrap();
    assert!(info.tree.find("__TEXT").is_some());
    assert!(info.tree.find("LC_SYMTAB").is_some());
    assert!(info.tree.find("LC_MAIN").is_some());
}
