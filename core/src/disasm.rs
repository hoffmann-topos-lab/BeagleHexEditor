//! F-76/F-77/F-78 — Disassembly (Fase 11).
//!
//! The x86/x64/ARM64 decoders (yaxpeax, D8) are isolated in [`x86`]/[`arm`];
//! everything else — the [`Insn`] model, the control-flow classification, the
//! linear/recursive view ([`view`]) — is decoder-agnostic. A binary is decoded
//! by virtual address; the view maps VA↔file offset through the section table,
//! reading via `Document::read` (D6 + F-06).

mod arm;
#[cfg(test)]
mod tests;
mod view;
mod x86;

use crate::format::{Arch, Bits};

pub use view::{DisasmJob, DisasmMode, DisasmOptions, Listing, build};

/// An architecture the disassembler supports (a subset of [`Arch`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisArch {
    X86,
    X86_64,
    Aarch64,
}

impl DisArch {
    /// The supported disassembly arch for a parsed binary, or `None` when the
    /// architecture has no decoder here.
    pub fn from_format(arch: Arch, bits: Bits) -> Option<DisArch> {
        match (arch, bits) {
            (Arch::X86, _) => Some(DisArch::X86),
            (Arch::X86_64, _) => Some(DisArch::X86_64),
            (Arch::Aarch64, _) => Some(DisArch::Aarch64),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            DisArch::X86 => "x86",
            DisArch::X86_64 => "x86-64",
            DisArch::Aarch64 => "aarch64",
        }
    }
}

/// The control-flow role of an instruction, all the recursive-descent walk needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Falls through to the next instruction (arithmetic, moves, …).
    Normal,
    /// A call: follows the target and returns (so both successors are code).
    Call,
    /// An unconditional jump: only the target is a successor.
    Jump,
    /// A conditional branch: both the target and the fall-through are code.
    CondJump,
    /// A return: no static successor.
    Return,
    /// A trap/halt (`ud2`, `hlt`, `udf`): no successor.
    Halt,
}

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insn {
    /// Virtual address.
    pub address: u64,
    /// Encoded length in bytes.
    pub len: u8,
    /// The raw encoded bytes (`len` of them).
    pub bytes: Vec<u8>,
    /// Rendered assembly (mnemonic + operands).
    pub text: String,
    pub flow: Flow,
    /// The resolved target of a direct branch/call, when statically known.
    pub target: Option<u64>,
}

impl Insn {
    /// A stand-in for a byte the decoder could not turn into an instruction.
    fn bad(address: u64, byte: u8) -> Insn {
        Insn {
            address,
            len: 1,
            bytes: vec![byte],
            text: format!(".byte {byte:#04x}"),
            flow: Flow::Normal,
            target: None,
        }
    }
}

/// A printable string reconstructed from stack stores (F-78).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackString {
    /// Virtual address of the first store that built it.
    pub address: u64,
    pub text: String,
}

/// Decodes a single instruction at virtual address `addr` from `bytes` (which
/// must begin at `addr`). `None` when the bytes are not a valid instruction.
pub fn decode_one(arch: DisArch, bytes: &[u8], addr: u64) -> Option<Insn> {
    match arch {
        DisArch::X86 => x86::decode(Bits::B32, bytes, addr),
        DisArch::X86_64 => x86::decode(Bits::B64, bytes, addr),
        DisArch::Aarch64 => arm::decode(bytes, addr),
    }
}

/// F-78 — Recovers stack strings from a code blob starting at virtual address
/// `base`. Implemented for x86/x64 (the classic `mov`-immediate-to-stack idiom);
/// other architectures return nothing.
pub fn stack_strings(arch: DisArch, bytes: &[u8], base: u64, min: usize) -> Vec<StackString> {
    match arch {
        DisArch::X86 => x86::stack_strings(Bits::B32, bytes, base, min),
        DisArch::X86_64 => x86::stack_strings(Bits::B64, bytes, base, min),
        DisArch::Aarch64 => Vec::new(),
    }
}
