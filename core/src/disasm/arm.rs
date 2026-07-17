//! F-76 — AArch64 (ARM64) backend (yaxpeax-arm, D8).
//!
//! Fixed 4-byte instructions. PC-relative branches carry an already-scaled
//! `PCOffset`, and ARM's program counter is the instruction's own address, so a
//! target is simply `addr + offset`.

use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode, Operand};

use crate::disasm::{Flow, Insn};

pub(super) fn decode(bytes: &[u8], addr: u64) -> Option<Insn> {
    let mut reader = U8Reader::new(bytes);
    let inst = InstDecoder::default().decode(&mut reader).ok()?;
    let len = inst.len().to_const() as u8;
    let flow = classify(inst.opcode);
    let target = flow_target(&inst, addr, flow);
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
    match op {
        Opcode::RET | Opcode::ERET => Flow::Return,
        Opcode::BL | Opcode::BLR => Flow::Call,
        Opcode::B | Opcode::BR => Flow::Jump,
        Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => Flow::CondJump,
        Opcode::BRK | Opcode::HLT | Opcode::UDF => Flow::Halt,
        _ => Flow::Normal,
    }
}

/// The target of a direct branch: the first `PCOffset` operand added to `addr`.
/// Register-indirect branches (`br`/`blr`) carry no offset, so no target.
fn flow_target(inst: &yaxpeax_arm::armv8::a64::Instruction, addr: u64, flow: Flow) -> Option<u64> {
    if !matches!(flow, Flow::Call | Flow::Jump | Flow::CondJump) {
        return None;
    }
    inst.operands.iter().find_map(|op| match op {
        Operand::PCOffset(off) => Some(addr.wrapping_add(*off as u64)),
        _ => None,
    })
}
