use super::*;
use crate::source::MemSource;

fn le32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn le64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// One ELF note: header + NUL-terminated name (padded) + desc (padded).
fn note(name: &str, ntype: u32, desc: &[u8]) -> Vec<u8> {
    let mut nm = name.as_bytes().to_vec();
    nm.push(0);
    let mut v = Vec::new();
    le32(&mut v, nm.len() as u32);
    le32(&mut v, desc.len() as u32);
    le32(&mut v, ntype);
    v.extend_from_slice(&nm);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v.extend_from_slice(desc);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

fn prpsinfo(pid: u32, ppid: u32, fname: &str, args: &str) -> Vec<u8> {
    let mut d = vec![0u8; 136];
    d[24..28].copy_from_slice(&pid.to_le_bytes());
    d[28..32].copy_from_slice(&ppid.to_le_bytes());
    let f = fname.as_bytes();
    d[40..40 + f.len().min(15)].copy_from_slice(&f[..f.len().min(15)]);
    let a = args.as_bytes();
    d[56..56 + a.len().min(79)].copy_from_slice(&a[..a.len().min(79)]);
    d
}

fn nt_file(entries: &[(u64, u64, &str)]) -> Vec<u8> {
    let mut d = Vec::new();
    le64(&mut d, entries.len() as u64);
    le64(&mut d, 4096); // page size
    for (start, end, _) in entries {
        le64(&mut d, *start);
        le64(&mut d, *end);
        le64(&mut d, 0); // file offset (pages)
    }
    for (_, _, name) in entries {
        d.extend_from_slice(name.as_bytes());
        d.push(0);
    }
    d
}

/// A minimal but valid 64-bit LE ELF core: one PT_NOTE (two PRSTATUS, a
/// PRPSINFO, an NT_FILE) and one PT_LOAD region.
fn synthetic_core() -> Vec<u8> {
    let mut notes = Vec::new();
    notes.extend(note("CORE", 1, &[0u8; 8])); // NT_PRSTATUS (thread 1)
    notes.extend(note("CORE", 1, &[0u8; 8])); // NT_PRSTATUS (thread 2)
    notes.extend(note("CORE", 3, &prpsinfo(1234, 1, "testproc", "testproc --run")));
    notes.extend(note("CORE", 0x4649_4c45, &nt_file(&[(0x400000, 0x401000, "/lib/libtest.so")])));

    let phoff = 64u64;
    let phentsize = 56u64;
    let notes_off = phoff + phentsize * 2; // 176

    let mut hdr = Vec::new();
    hdr.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]); // ident: 64-bit LE
    hdr.extend_from_slice(&[0; 8]);
    let mut h = hdr;
    // e_type=ET_CORE, e_machine=x86-64, e_version
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&62u16.to_le_bytes());
    le32(&mut h, 1);
    le64(&mut h, 0); // e_entry
    le64(&mut h, phoff); // e_phoff
    le64(&mut h, 0); // e_shoff
    le32(&mut h, 0); // e_flags
    h.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    h.extend_from_slice(&(phentsize as u16).to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes()); // e_phnum
    h.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    h.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    h.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    assert_eq!(h.len(), 64);

    // PT_NOTE
    le32(&mut h, 4);
    le32(&mut h, 0);
    le64(&mut h, notes_off);
    le64(&mut h, 0);
    le64(&mut h, 0);
    le64(&mut h, notes.len() as u64);
    le64(&mut h, 0);
    le64(&mut h, 0);
    // PT_LOAD
    le32(&mut h, 1);
    le32(&mut h, 5); // R+X
    le64(&mut h, notes_off + notes.len() as u64);
    le64(&mut h, 0x400000);
    le64(&mut h, 0);
    le64(&mut h, 0x1000);
    le64(&mut h, 0x1000);
    le64(&mut h, 0x1000);
    assert_eq!(h.len() as u64, notes_off);

    h.extend(notes);
    h
}

fn inspect_bytes(data: Vec<u8>) -> DumpReport {
    let mut doc = Document::new(Box::new(MemSource::new(data)));
    inspect(&mut doc, &Progress::new()).unwrap()
}

#[test]
fn an_elf_core_yields_process_threads_regions_and_modules() {
    let r = inspect_bytes(synthetic_core());
    assert_eq!(r.kind, DumpKind::ElfCore);
    assert_eq!(r.arch, Some(Arch::X86_64));
    assert_eq!(r.bits, Some(Bits::B64));
    assert_eq!(r.endian, Some(Endian::Little));

    assert_eq!(r.processes.len(), 1);
    assert_eq!(r.processes[0].pid, 1234);
    assert_eq!(r.processes[0].ppid, 1);
    assert_eq!(r.processes[0].name, "testproc");
    assert!(r.processes[0].args.starts_with("testproc --run"));

    assert_eq!(r.threads, 2, "two NT_PRSTATUS notes");

    assert_eq!(r.regions.len(), 1);
    assert_eq!(r.regions[0].vaddr, 0x400000);
    assert_eq!(r.regions[0].size, 0x1000);
    assert_eq!(r.regions[0].perms.rwx(), "r-x");

    assert_eq!(r.modules.len(), 1);
    assert_eq!(r.modules[0].name, "/lib/libtest.so");
    assert_eq!((r.modules[0].start, r.modules[0].end), (0x400000, 0x401000));
}

#[test]
fn detect_names_the_container() {
    let mut core = Document::new(Box::new(MemSource::new(synthetic_core())));
    assert_eq!(detect(&mut core), DumpKind::ElfCore);

    let mut win = Document::new(Box::new(MemSource::new(b"PAGEDU64\0\0\0\0\0\0\0\0\0\0\0\0".to_vec())));
    assert_eq!(detect(&mut win), DumpKind::WindowsCrashDump);

    let mut raw = Document::new(Box::new(MemSource::new(vec![0u8; 4096])));
    assert_eq!(detect(&mut raw), DumpKind::Raw);
}

#[test]
fn a_regular_elf_binary_is_not_a_core() {
    // ELF magic but e_type = ET_EXEC (2), not a memory image.
    let mut data = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0];
    data.extend_from_slice(&[0; 8]);
    data.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    data.resize(64, 0);
    let mut doc = Document::new(Box::new(MemSource::new(data)));
    assert_eq!(detect(&mut doc), DumpKind::Raw);
}

#[test]
fn a_non_core_reports_a_caveat_not_an_error() {
    let r = inspect_bytes(vec![0u8; 4096]);
    assert_eq!(r.kind, DumpKind::Raw);
    assert!(r.processes.is_empty());
    assert!(!r.note.is_empty(), "explains why enumeration is limited");
}
