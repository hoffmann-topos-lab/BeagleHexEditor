//! F-70 — PE parser, over a hand-built PE32+ executable with one `.text`
//! section carrying an import of `MessageBoxA` from `USER32.dll`.

use super::{W, doc};
use crate::format::{parse, Arch, Bits, Format, Perms};

/// Minimal PE32+ (x86-64) image: DOS header, PE signature, COFF header, optional
/// header with an import data directory, one `.text` section whose raw data
/// holds the import descriptor, lookup table and name strings.
fn tiny_pe64() -> Vec<u8> {
    let mut w = W::new();

    // ---- DOS header: MZ, then e_lfanew at 0x3C -> 0x40 ----
    w.bytes(b"MZ");
    while w.len() < 0x3C {
        w.u8(0);
    }
    w.u32(0x40); // e_lfanew
    assert_eq!(w.len(), 0x40);

    // ---- PE signature + COFF file header ----
    w.bytes(&[b'P', b'E', 0, 0]);
    w.u16(0x8664); // Machine = x86-64
    w.u16(1); // NumberOfSections
    w.u32(0); // TimeDateStamp
    w.u32(0); // PointerToSymbolTable
    w.u32(0); // NumberOfSymbols
    w.u16(0xF0); // SizeOfOptionalHeader
    w.u16(0x22); // Characteristics (EXECUTABLE | LARGE_ADDRESS_AWARE)

    // ---- optional header (PE32+), 0xF0 bytes ----
    let opt_start = w.len();
    w.u16(0x20b); // Magic = PE32+
    w.u8(14); // MajorLinkerVersion
    w.u8(0); // MinorLinkerVersion
    w.u32(0x200); // SizeOfCode
    w.u32(0); // SizeOfInitializedData
    w.u32(0); // SizeOfUninitializedData
    w.u32(0x1000); // AddressOfEntryPoint
    w.u32(0x1000); // BaseOfCode
    w.u64(0x1_4000_0000); // ImageBase
    w.u32(0x1000); // SectionAlignment
    w.u32(0x200); // FileAlignment
    w.u16(6); // MajorOperatingSystemVersion
    w.u16(0);
    w.u16(0); // MajorImageVersion
    w.u16(0);
    w.u16(6); // MajorSubsystemVersion
    w.u16(0);
    w.u32(0); // Win32VersionValue
    w.u32(0x3000); // SizeOfImage
    w.u32(0x200); // SizeOfHeaders
    w.u32(0); // CheckSum
    w.u16(3); // Subsystem = WINDOWS_CUI
    w.u16(0); // DllCharacteristics
    w.u64(0x100000); // SizeOfStackReserve
    w.u64(0x1000); // SizeOfStackCommit
    w.u64(0x100000); // SizeOfHeapReserve
    w.u64(0x1000); // SizeOfHeapCommit
    w.u32(0); // LoaderFlags
    w.u32(16); // NumberOfRvaAndSizes
    // data directories: only the import table (index 1) is set.
    for i in 0..16u32 {
        if i == 1 {
            w.u32(0x1000); // Import table RVA
            w.u32(0x28); // size
        } else {
            w.u32(0);
            w.u32(0);
        }
    }
    assert_eq!(w.len() - opt_start, 0xF0);

    // ---- section header: .text ----
    w.bytes(b".text\0\0\0");
    w.u32(0x1000); // VirtualSize
    w.u32(0x1000); // VirtualAddress
    w.u32(0x200); // SizeOfRawData
    w.u32(0x200); // PointerToRawData
    w.u32(0); // PointerToRelocations
    w.u32(0); // PointerToLinenumbers
    w.u16(0); // NumberOfRelocations
    w.u16(0); // NumberOfLinenumbers
    w.u32(0x6000_0020); // CODE | EXECUTE | READ

    // ---- pad to the section's raw data at 0x200 ----
    while w.len() < 0x200 {
        w.u8(0);
    }

    // ---- .text raw data (RVA 0x1000 == file 0x200) ----
    // import descriptor[0]
    w.u32(0x1028); // OriginalFirstThunk (ILT)
    w.u32(0); // TimeDateStamp
    w.u32(0); // ForwarderChain
    w.u32(0x1046); // Name (RVA of "USER32.dll")
    w.u32(0x1028); // FirstThunk (reuse the ILT as the IAT)
    // import descriptor[1]: null terminator
    w.bytes(&[0u8; 20]);
    // import lookup table at RVA 0x1028
    w.u64(0x1038); // -> IMAGE_IMPORT_BY_NAME
    w.u64(0); // null terminator
    // IMAGE_IMPORT_BY_NAME at RVA 0x1038: hint, then the name
    w.u16(0); // Hint
    w.bytes(b"MessageBoxA\0");
    // DLL name at RVA 0x1046
    w.bytes(b"USER32.dll\0");
    // pad the raw section to its full size
    while w.len() < 0x400 {
        w.u8(0);
    }

    w.done()
}

#[test]
fn parses_the_pe_header_facts() {
    let mut d = doc(tiny_pe64());
    let info = parse(&mut d).unwrap();
    assert_eq!(info.format, Format::Pe);
    assert_eq!(info.arch, Arch::X86_64);
    assert_eq!(info.bits, Bits::B64);
    // entry = ImageBase + AddressOfEntryPoint
    assert_eq!(info.entry, 0x1_4000_1000);
}

#[test]
fn lists_the_pe_section() {
    let mut d = doc(tiny_pe64());
    let info = parse(&mut d).unwrap();
    let text = info.sections.iter().find(|s| s.name == ".text").expect(".text present");
    assert_eq!(text.vaddr, 0x1_4000_1000);
    assert_eq!(text.size, 0x1000);
    assert_eq!(text.file, 0x200..0x400);
    assert_eq!(text.perms, Perms { r: true, w: false, x: true });
}

#[test]
fn parses_the_import_table() {
    let mut d = doc(tiny_pe64());
    let info = parse(&mut d).unwrap();
    assert_eq!(info.libs, vec!["USER32.dll"]);
    let imp = info
        .imports
        .iter()
        .find(|i| i.name == "MessageBoxA")
        .expect("MessageBoxA imported");
    assert_eq!(imp.library, "USER32.dll");
    assert_eq!(imp.ordinal, None);
}

#[test]
fn the_optional_header_and_imports_are_in_the_tree() {
    let mut d = doc(tiny_pe64());
    let info = parse(&mut d).unwrap();
    assert!(info.tree.find("Optional Header").is_some());
    assert!(info.tree.find("Imports").is_some());
    assert!(info.tree.find("USER32.dll").is_some());
}
