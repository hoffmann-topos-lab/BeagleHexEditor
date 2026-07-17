//! F-68/F-69 tests over a hand-built ELF64 image (hermetic, like the rest of the
//! suite — no real toolchain, which on this host emits Mach-O anyway). The
//! dynamic/relocation (F-69), PE (F-70) and Mach-O (F-71) fixtures live in the
//! submodules, sharing the `W` writer and `doc` helper here.

mod dynamic;
mod macho;
mod pe;

use super::*;
use crate::document::Document;
use crate::inspector::Endian;
use crate::source::MemSource;

/// A little writer that lays bytes down sequentially and can patch back-references.
struct W {
    buf: Vec<u8>,
}

impl W {
    fn new() -> Self {
        W { buf: Vec::new() }
    }
    fn len(&self) -> u64 {
        self.buf.len() as u64
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn align(&mut self, a: u64) {
        while !self.len().is_multiple_of(a) {
            self.buf.push(0);
        }
    }
    fn patch_u64(&mut self, at: u64, v: u64) {
        let at = at as usize;
        self.buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn done(self) -> Vec<u8> {
        self.buf
    }
    #[allow(clippy::too_many_arguments)]
    fn shdr(
        &mut self,
        name: u32,
        ty: u32,
        flags: u64,
        addr: u64,
        offset: u64,
        size: u64,
        link: u32,
        info: u32,
        addralign: u64,
        entsize: u64,
    ) {
        self.u32(name);
        self.u32(ty);
        self.u64(flags);
        self.u64(addr);
        self.u64(offset);
        self.u64(size);
        self.u32(link);
        self.u32(info);
        self.u64(addralign);
        self.u64(entsize);
    }
}

/// Minimal but structurally valid ELF64 executable: one LOAD segment, a `.text`
/// with three bytes of code, and a symbol table holding `main`.
fn tiny_elf64() -> Vec<u8> {
    let mut w = W::new();

    // ---- ELF header (64 bytes); e_shoff is patched once known ----
    w.bytes(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]); // magic, class64, LE, version, osabi
    w.bytes(&[0u8; 8]); // e_ident padding
    w.u16(2); // e_type = ET_EXEC
    w.u16(62); // e_machine = EM_X86_64
    w.u32(1); // e_version
    w.u64(0x401000); // e_entry
    w.u64(64); // e_phoff
    let shoff_at = w.len();
    w.u64(0); // e_shoff (patched below)
    w.u32(0); // e_flags
    w.u16(64); // e_ehsize
    w.u16(56); // e_phentsize
    w.u16(1); // e_phnum
    w.u16(64); // e_shentsize
    w.u16(5); // e_shnum
    w.u16(1); // e_shstrndx
    assert_eq!(w.len(), 64);

    // ---- program header: one LOAD segment ----
    w.u32(1); // p_type = PT_LOAD
    w.u32(5); // p_flags = R|X
    w.u64(0); // p_offset
    w.u64(0x400000); // p_vaddr
    w.u64(0x400000); // p_paddr
    w.u64(0x1000); // p_filesz
    w.u64(0x1000); // p_memsz
    w.u64(0x1000); // p_align
    assert_eq!(w.len(), 120);

    // ---- .text ----
    let text_off = w.len();
    w.bytes(&[0x90, 0x90, 0xC3, 0x00]); // nop; nop; ret; pad
    let text_size = w.len() - text_off;

    // ---- .shstrtab (section-name string table) ----
    let shstr_off = w.len();
    w.u8(0);
    let n_shstrtab = w.len() - shstr_off;
    w.bytes(b".shstrtab\0");
    let n_text = w.len() - shstr_off;
    w.bytes(b".text\0");
    let n_symtab = w.len() - shstr_off;
    w.bytes(b".symtab\0");
    let n_strtab = w.len() - shstr_off;
    w.bytes(b".strtab\0");
    let shstr_size = w.len() - shstr_off;

    // ---- .symtab ----
    w.align(8);
    let symtab_off = w.len();
    w.bytes(&[0u8; 24]); // null entry [0]
    w.u32(1); // st_name -> "main"
    w.u8(0x12); // st_info = (STB_GLOBAL << 4) | STT_FUNC
    w.u8(0); // st_other
    w.u16(2); // st_shndx -> .text (section index 2)
    w.u64(0x401000); // st_value
    w.u64(4); // st_size
    let symtab_size = w.len() - symtab_off;

    // ---- .strtab (symbol names) ----
    let strtab_off = w.len();
    w.u8(0);
    w.bytes(b"main\0");
    let strtab_size = w.len() - strtab_off;

    // ---- section header table ----
    w.align(8);
    let shoff = w.len();
    w.shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0); // [0] NULL
    w.shdr(n_shstrtab as u32, 3, 0, 0, shstr_off, shstr_size, 0, 0, 1, 0); // [1] .shstrtab
    w.shdr(n_text as u32, 1, 0x6, 0x401000, text_off, text_size, 0, 0, 16, 0); // [2] .text (ALLOC|EXEC)
    w.shdr(n_symtab as u32, 2, 0, 0, symtab_off, symtab_size, 4, 1, 8, 24); // [3] .symtab -> .strtab
    w.shdr(n_strtab as u32, 3, 0, 0, strtab_off, strtab_size, 0, 0, 1, 0); // [4] .strtab

    w.patch_u64(shoff_at, shoff);
    w.buf
}

fn doc(bytes: Vec<u8>) -> Document {
    Document::new(Box::new(MemSource::new(bytes)))
}

#[test]
fn detects_elf_by_its_magic() {
    let mut d = doc(tiny_elf64());
    assert_eq!(detect(&mut d), Some(Format::Elf));
    let mut mz = doc(b"MZ\x90\x00 not really a PE".to_vec());
    assert_eq!(detect(&mut mz), Some(Format::Pe));
    let mut junk = doc(b"just text".to_vec());
    assert_eq!(detect(&mut junk), None);
}

#[test]
fn parses_the_header_facts() {
    let mut d = doc(tiny_elf64());
    let info = parse(&mut d).unwrap();
    assert_eq!(info.format, Format::Elf);
    assert_eq!(info.bits, Bits::B64);
    assert_eq!(info.endian, Endian::Little);
    assert_eq!(info.arch, Arch::X86_64);
    assert_eq!(info.entry, 0x401000);
}

#[test]
fn lists_sections_with_names_and_file_ranges() {
    let mut d = doc(tiny_elf64());
    let info = parse(&mut d).unwrap();
    // the null section [0] is not surfaced as a real section
    assert!(info.sections.iter().all(|s| !s.name.is_empty()));
    let text = info.sections.iter().find(|s| s.name == ".text").expect(".text present");
    assert_eq!(text.vaddr, 0x401000);
    assert_eq!(text.size, 4);
    assert_eq!(text.perms, Perms { r: true, w: false, x: true });
    // the recorded file range points at the actual code bytes
    let bytes = d.read(text.file.start, text.size as usize);
    assert_eq!(bytes.data, vec![0x90, 0x90, 0xC3, 0x00]);
}

#[test]
fn reads_the_symbol_table() {
    let mut d = doc(tiny_elf64());
    let info = parse(&mut d).unwrap();
    let main = info.symbols.iter().find(|s| s.name == "main").expect("main symbol");
    assert_eq!(main.value, 0x401000);
    assert_eq!(main.size, 4);
    assert_eq!(main.kind, SymKind::Func);
    assert!(main.global);
    assert!(main.defined);
}

#[test]
fn every_field_carries_its_document_span() {
    let mut d = doc(tiny_elf64());
    let info = parse(&mut d).unwrap();
    // e_entry occupies bytes [24, 32) of an ELF64 header.
    let entry = info.tree.find("e_entry").expect("e_entry node");
    assert_eq!(entry.span, 24..32);
    // a section header is exactly e_shentsize (64) bytes wide.
    let text = info.tree.find(".text [PROGBITS]").expect(".text tree node");
    assert_eq!(text.span.end - text.span.start, 64);
}

#[test]
fn a_truncated_header_is_an_error() {
    let mut short = tiny_elf64();
    short.truncate(20);
    let mut d = doc(short);
    assert!(parse(&mut d).is_err());
}

#[test]
fn an_unreadable_header_is_not_parsed() {
    // F-06: a header over a bad block is not a header.
    let src = MemSource::new(tiny_elf64()).with_bad_range(0..8);
    let mut d = Document::new(Box::new(src));
    assert!(parse(&mut d).is_err());
}
