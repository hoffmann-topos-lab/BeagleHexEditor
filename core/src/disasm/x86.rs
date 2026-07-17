//! F-76/F-78 — x86 and x86-64 backend (yaxpeax-x86, D8).
//!
//! yaxpeax exposes 32-bit and 64-bit as separate `Instruction`/`Opcode`/`Operand`
//! types with identical variant names, so one macro generates both from the same
//! source, parameterised by the mode module and its frame/stack registers.

use crate::disasm::{Insn, StackString};
use crate::format::Bits;

pub(super) fn decode(bits: Bits, bytes: &[u8], addr: u64) -> Option<Insn> {
    match bits {
        Bits::B64 => long::decode(bytes, addr),
        Bits::B32 => prot::decode(bytes, addr),
    }
}

pub(super) fn stack_strings(bits: Bits, bytes: &[u8], base: u64, min: usize) -> Vec<StackString> {
    match bits {
        Bits::B64 => long::stack_strings(bytes, base, min),
        Bits::B32 => prot::stack_strings(bytes, base, min),
    }
}

/// Generates a mode-specific backend module (`decode` + `stack_strings`).
macro_rules! x86_backend {
    ($modname:ident, $m:path, $bp:ident, $sp:ident) => {
        mod $modname {
            use $m::{InstDecoder, Instruction, Opcode, Operand, RegSpec};
            use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};

            use crate::disasm::{Flow, Insn, StackString};

            pub(super) fn decode(bytes: &[u8], addr: u64) -> Option<Insn> {
                let mut reader = U8Reader::new(bytes);
                let inst = InstDecoder::default().decode(&mut reader).ok()?;
                let len = inst.len().to_const() as u8;
                let flow = classify(inst.opcode());
                let target = branch_target(&inst, addr, len, flow);
                Some(Insn {
                    address: addr,
                    len,
                    bytes: bytes[..len as usize].to_vec(),
                    text: inst.to_string(),
                    flow,
                    target,
                })
            }

            fn classify(op: Opcode) -> Flow {
                use Opcode::*;
                match op {
                    RETURN | RETF | IRET | IRETD | IRETQ => Flow::Return,
                    CALL | CALLF => Flow::Call,
                    JMP | JMPF => Flow::Jump,
                    JO | JNO | JB | JNB | JZ | JNZ | JNA | JA | JS | JNS | JP | JNP | JL | JGE
                    | JLE | JG | JECXZ | LOOP | LOOPZ | LOOPNZ => Flow::CondJump,
                    HLT | UD0 | UD1 | UD2 => Flow::Halt,
                    _ => Flow::Normal,
                }
            }

            /// A direct relative branch's target: `addr + len + rel`. Indirect
            /// (register/memory) branches have no static target.
            fn branch_target(inst: &Instruction, addr: u64, len: u8, flow: Flow) -> Option<u64> {
                if !matches!(flow, Flow::Call | Flow::Jump | Flow::CondJump) {
                    return None;
                }
                let rel = match inst.operand(0) {
                    Operand::ImmediateI8 { imm } => imm as i64,
                    Operand::ImmediateI16 { imm } => imm as i64,
                    Operand::ImmediateI32 { imm } => imm as i64,
                    _ => return None,
                };
                Some(addr.wrapping_add(len as u64).wrapping_add(rel as u64))
            }

            /// F-78 — Reassembles strings written to consecutive stack slots by
            /// `mov [rbp/rsp ± disp], imm` sequences.
            pub(super) fn stack_strings(bytes: &[u8], base: u64, min: usize) -> Vec<StackString> {
                let frame = [RegSpec::$bp(), RegSpec::$sp()];
                let dec = InstDecoder::default();
                let mut out = Vec::new();
                let mut run: Vec<u8> = Vec::new();
                let mut run_addr = 0u64;
                let mut expect: Option<i32> = None;
                let mut pos = 0usize;

                while pos < bytes.len() {
                    let mut reader = U8Reader::new(&bytes[pos..]);
                    let Ok(inst) = dec.decode(&mut reader) else {
                        pos += 1;
                        continue;
                    };
                    let addr = base + pos as u64;
                    pos += inst.len().to_const() as usize;

                    let Some((disp, imm)) = stack_store(&inst, &frame) else {
                        continue;
                    };
                    if expect == Some(disp) {
                        run.extend_from_slice(&imm);
                    } else {
                        emit(&run, run_addr, min, &mut out);
                        run = imm.clone();
                        run_addr = addr;
                    }
                    expect = Some(disp + imm.len() as i32);
                }
                emit(&run, run_addr, min, &mut out);
                out
            }

            /// A `mov`-immediate into a stack slot: returns `(displacement, bytes)`.
            fn stack_store(inst: &Instruction, frame: &[RegSpec; 2]) -> Option<(i32, Vec<u8>)> {
                if inst.opcode() != Opcode::MOV {
                    return None;
                }
                let disp = match inst.operand(0) {
                    Operand::Disp { base, disp } if frame.contains(&base) => disp,
                    _ => return None,
                };
                let imm = match inst.operand(1) {
                    Operand::ImmediateI8 { imm } => vec![imm as u8],
                    Operand::ImmediateI16 { imm } => (imm as u16).to_le_bytes().to_vec(),
                    Operand::ImmediateI32 { imm } => (imm as u32).to_le_bytes().to_vec(),
                    _ => return None,
                };
                Some((disp, imm))
            }

            /// Flushes a run: emits the printable prefix if it is long enough.
            fn emit(run: &[u8], addr: u64, min: usize, out: &mut Vec<StackString>) {
                let end =
                    run.iter().position(|&b| !(0x20..=0x7e).contains(&b)).unwrap_or(run.len());
                if end >= min {
                    let text = String::from_utf8_lossy(&run[..end]).into_owned();
                    out.push(StackString { address: addr, text });
                }
            }
        }
    };
}

x86_backend!(long, yaxpeax_x86::long_mode, rbp, rsp);
x86_backend!(prot, yaxpeax_x86::protected_mode, ebp, esp);
