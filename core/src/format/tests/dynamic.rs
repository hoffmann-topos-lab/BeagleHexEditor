//! F-69 — dynamic table and relocations, over a hand-built ELF64 shared object
//! with a `.dynamic` (one `DT_NEEDED`), a `.dynsym` and a `.rela.plt` that
//! references one of its symbols.

use super::{W, doc};
use crate::format::{parse, Reloc};

/// ELF64 `ET_DYN` with `.dynstr`/`.dynsym`/`.dynamic`/`.rela.plt`. The single
/// relocation is an `R_X86_64_JUMP_SLOT` against the undefined symbol `printf`.
fn dynamic_elf64() -> Vec<u8> {
    let mut w = W::new();

    // ---- ELF header (64 bytes); e_shoff patched once known ----
    w.bytes(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
    w.bytes(&[0u8; 8]);
    w.u16(3); // e_type = ET_DYN
    w.u16(62); // e_machine = EM_X86_64
    w.u32(1);
    w.u64(0); // e_entry
    w.u64(0); // e_phoff (no program headers)
    let shoff_at = w.len();
    w.u64(0); // e_shoff (patched below)
    w.u32(0); // e_flags
    w.u16(64); // e_ehsize
    w.u16(0); // e_phentsize
    w.u16(0); // e_phnum
    w.u16(64); // e_shentsize
    w.u16(6); // e_shnum
    w.u16(1); // e_shstrndx
    assert_eq!(w.len(), 64);

    // ---- .shstrtab ----
    let shstr_off = w.len();
    w.u8(0);
    let n_shstrtab = (w.len() - shstr_off) as u32;
    w.bytes(b".shstrtab\0");
    let n_dynstr = (w.len() - shstr_off) as u32;
    w.bytes(b".dynstr\0");
    let n_dynsym = (w.len() - shstr_off) as u32;
    w.bytes(b".dynsym\0");
    let n_dynamic = (w.len() - shstr_off) as u32;
    w.bytes(b".dynamic\0");
    let n_relaplt = (w.len() - shstr_off) as u32;
    w.bytes(b".rela.plt\0");
    let shstr_size = w.len() - shstr_off;

    // ---- .dynstr: libc.so.6 at offset 1, printf right after ----
    let dynstr_off = w.len();
    w.u8(0);
    w.bytes(b"libc.so.6\0");
    let printf_name = (w.len() - dynstr_off) as u32;
    w.bytes(b"printf\0");
    let dynstr_size = w.len() - dynstr_off;

    // ---- .dynsym: null entry, then undefined printf ----
    w.align(8);
    let dynsym_off = w.len();
    w.bytes(&[0u8; 24]); // null entry [0]
    w.u32(printf_name); // st_name -> "printf"
    w.u8(0x12); // st_info = (STB_GLOBAL << 4) | STT_FUNC
    w.u8(0); // st_other
    w.u16(0); // st_shndx = SHN_UNDEF -> imported
    w.u64(0); // st_value
    w.u64(0); // st_size
    let dynsym_size = w.len() - dynsym_off;

    // ---- .dynamic: DT_NEEDED(libc.so.6), DT_NULL ----
    w.align(8);
    let dyn_off = w.len();
    w.u64(1); // DT_NEEDED
    w.u64(1); // -> "libc.so.6" at dynstr offset 1
    w.u64(0); // DT_NULL
    w.u64(0);
    let dyn_size = w.len() - dyn_off;

    // ---- .rela.plt: one JUMP_SLOT against symbol 1 (printf) ----
    w.align(8);
    let rela_off = w.len();
    w.u64(0x4000); // r_offset
    w.u64((1u64 << 32) | 7); // r_info: sym 1, type R_X86_64_JUMP_SLOT (7)
    w.u64(0); // r_addend
    let rela_size = w.len() - rela_off;

    // ---- section header table ----
    w.align(8);
    let shoff = w.len();
    w.shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0); // [0] NULL
    w.shdr(n_shstrtab, 3, 0, 0, shstr_off, shstr_size, 0, 0, 1, 0); // [1] .shstrtab
    w.shdr(n_dynstr, 3, 0, 0, dynstr_off, dynstr_size, 0, 0, 1, 0); // [2] .dynstr
    w.shdr(n_dynsym, 11, 0, 0, dynsym_off, dynsym_size, 2, 1, 8, 24); // [3] .dynsym -> .dynstr
    w.shdr(n_dynamic, 6, 0, 0, dyn_off, dyn_size, 2, 0, 8, 16); // [4] .dynamic -> .dynstr
    w.shdr(n_relaplt, 4, 0, 0, rela_off, rela_size, 3, 0, 8, 24); // [5] .rela.plt -> .dynsym

    w.patch_u64(shoff_at, shoff);
    w.done()
}

#[test]
fn needed_libraries_come_from_dt_needed() {
    let mut d = doc(dynamic_elf64());
    let info = parse(&mut d).unwrap();
    assert_eq!(info.libs, vec!["libc.so.6"]);
}

#[test]
fn relocations_resolve_their_target_symbol() {
    let mut d = doc(dynamic_elf64());
    let info = parse(&mut d).unwrap();
    assert_eq!(
        info.relocs,
        vec![Reloc {
            offset: 0x4000,
            kind: "R_X86_64_JUMP_SLOT".to_string(),
            symbol: "printf".to_string(),
            addend: 0,
        }]
    );
}

#[test]
fn undefined_dynamic_symbols_are_imports() {
    let mut d = doc(dynamic_elf64());
    let info = parse(&mut d).unwrap();
    assert!(info.imports.iter().any(|i| i.name == "printf" && i.library.is_empty()));
}

#[test]
fn the_dynamic_and_relocation_tables_are_in_the_tree() {
    let mut d = doc(dynamic_elf64());
    let info = parse(&mut d).unwrap();
    assert!(info.tree.find("Dynamic").is_some());
    assert!(info.tree.find("Relocations").is_some());
    // the reloc leaf names its symbol
    let relocs = info.tree.find("Relocations").unwrap();
    assert!(format!("{relocs:?}").contains("printf"));
}
