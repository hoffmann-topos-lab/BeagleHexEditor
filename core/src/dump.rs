//! F-84 — Memory-image inspector (Fase 15), the Volatility idea kept narrow.
//!
//! A dump is just a file read as a `DataSource` (D9), so this fits the existing
//! model: no live process, no host lock, cross-platform. [`detect`] names the
//! container; [`inspect`] parses what is structurally self-describing.
//!
//! **ELF core dumps** are parsed in full ([`elfcore`]): the `PT_LOAD` segments
//! give the memory map, and the `PT_NOTE` segment gives the process (pid/command
//! from `NT_PRPSINFO`), the thread count (`NT_PRSTATUS`) and the mapped modules
//! (`NT_FILE`). Raw physical dumps, Windows crashdumps and hibernation files are
//! detected and reported, but enumerating their processes needs OS-version kernel
//! profiles (`task_struct` / `EPROCESS` scanning) — full Volatility parity is out.

mod elfcore;
#[cfg(test)]
mod tests;

use crate::document::Document;
use crate::error::Result;
use crate::format::{Arch, Bits, Perms};
use crate::inspector::Endian;
use crate::progress::Progress;

/// The container format of a memory image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpKind {
    /// A parsed ELF core (userspace process core, or an ELF-format kernel dump).
    ElfCore,
    /// A Mach-O core (macOS). Detected; region/process parsing is not done yet.
    MachoCore,
    /// A Windows kernel crashdump (`PAGEDU64`/`PAGEDUMP`).
    WindowsCrashDump,
    /// A Windows hibernation file (`hiberfil.sys`).
    WindowsHiberfil,
    /// A raw physical memory image, or an unrecognised container.
    Raw,
}

impl DumpKind {
    pub fn name(self) -> &'static str {
        match self {
            DumpKind::ElfCore => "ELF core dump",
            DumpKind::MachoCore => "Mach-O core dump",
            DumpKind::WindowsCrashDump => "Windows crashdump",
            DumpKind::WindowsHiberfil => "Windows hibernation file",
            DumpKind::Raw => "raw / unrecognised",
        }
    }
}

/// A process recovered from a dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: i32,
    pub ppid: i32,
    pub name: String,
    pub args: String,
}

/// A mapped memory region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemRegion {
    pub vaddr: u64,
    pub size: u64,
    pub file_off: u64,
    pub perms: Perms,
}

/// A file mapped into the image (a shared library / the main binary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub name: String,
    pub start: u64,
    pub end: u64,
}

/// The result of inspecting a memory image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpReport {
    pub kind: DumpKind,
    pub arch: Option<Arch>,
    pub bits: Option<Bits>,
    pub endian: Option<Endian>,
    pub processes: Vec<ProcInfo>,
    pub threads: usize,
    pub regions: Vec<MemRegion>,
    pub modules: Vec<Module>,
    /// A human-readable caveat (e.g. why enumeration is limited), or empty.
    pub note: String,
}

impl DumpReport {
    fn header_only(kind: DumpKind, note: impl Into<String>) -> Self {
        Self {
            kind,
            arch: None,
            bits: None,
            endian: None,
            processes: Vec::new(),
            threads: 0,
            regions: Vec::new(),
            modules: Vec::new(),
            note: note.into(),
        }
    }
}

/// Names the container format from its leading bytes.
pub fn detect(doc: &mut Document) -> DumpKind {
    let head = doc.read(0, 24);
    if !head.is_clean() || head.data.len() < 8 {
        return DumpKind::Raw;
    }
    let d = &head.data;

    if d[0..4] == [0x7F, b'E', b'L', b'F'] {
        // e_type (offset 16) == ET_CORE (4)?
        if d.len() >= 18 {
            let big = d[5] == 2;
            let et = if big { u16::from_be_bytes([d[16], d[17]]) } else { u16::from_le_bytes([d[16], d[17]]) };
            if et == 4 {
                return DumpKind::ElfCore;
            }
        }
        return DumpKind::Raw; // a regular ELF binary is not a memory image
    }

    // Mach-O: filetype (offset 12) == MH_CORE (4)?
    let magic = [d[0], d[1], d[2], d[3]];
    let macho = matches!(
        magic,
        [0xCF, 0xFA, 0xED, 0xFE] | [0xCE, 0xFA, 0xED, 0xFE] | [0xFE, 0xED, 0xFA, 0xCF] | [0xFE, 0xED, 0xFA, 0xCE]
    );
    if macho && d.len() >= 16 {
        let big = magic[0] == 0xFE;
        let ft = if big { u32::from_be_bytes([d[12], d[13], d[14], d[15]]) } else { u32::from_le_bytes([d[12], d[13], d[14], d[15]]) };
        if ft == 4 {
            return DumpKind::MachoCore;
        }
    }

    if d.starts_with(b"PAGEDU64") || d.starts_with(b"PAGEDUMP") {
        return DumpKind::WindowsCrashDump;
    }
    if d.starts_with(b"HIBR") || d.starts_with(b"hibr") || d.starts_with(b"WAKE") {
        return DumpKind::WindowsHiberfil;
    }
    DumpKind::Raw
}

/// Inspects a memory image: full enumeration for ELF cores, detection plus a
/// caveat for the rest.
pub fn inspect(doc: &mut Document, progress: &Progress) -> Result<DumpReport> {
    match detect(doc) {
        DumpKind::ElfCore => elfcore::inspect(doc, progress),
        kind @ (DumpKind::MachoCore
        | DumpKind::WindowsCrashDump
        | DumpKind::WindowsHiberfil
        | DumpKind::Raw) => Ok(DumpReport::header_only(
            kind,
            "process / module enumeration needs an OS kernel profile \
             (task_struct / EPROCESS) — out of scope (full Volatility parity is out)",
        )),
    }
}

/// Perms from ELF program-header flags (`PF_R`/`PF_W`/`PF_X`).
pub(crate) fn perms_from_pflags(flags: u32) -> Perms {
    Perms { r: flags & 4 != 0, w: flags & 2 != 0, x: flags & 1 != 0 }
}
