//! F-76/F-77/F-78 tests over hand-assembled machine code (hermetic — no external
//! assembler). Byte sequences are annotated with their instructions.

use super::view::{DisasmJob, DisasmMode, Region};
use super::*;

// ---- F-76: decoding + flow ----

#[test]
fn decodes_x86_64_and_classifies_flow() {
    // push rbp; call $+5; ret; jz $+16; nop
    let code = [0x55, 0xe8, 0x05, 0x00, 0x00, 0x00, 0xc3, 0x74, 0x10, 0x90];
    let push = decode_one(DisArch::X86_64, &code, 0x1000).unwrap();
    assert_eq!(push.len, 1);
    assert_eq!(push.flow, Flow::Normal);
    assert!(push.text.contains("push"));

    let call = decode_one(DisArch::X86_64, &code[1..], 0x1001).unwrap();
    assert_eq!(call.flow, Flow::Call);
    // target = addr + len + rel = 0x1001 + 5 + 5
    assert_eq!(call.target, Some(0x100b));

    let ret = decode_one(DisArch::X86_64, &code[6..], 0x1006).unwrap();
    assert_eq!(ret.flow, Flow::Return);
    assert_eq!(ret.target, None);

    let jz = decode_one(DisArch::X86_64, &code[7..], 0x1007).unwrap();
    assert_eq!(jz.flow, Flow::CondJump);
    assert_eq!(jz.target, Some(0x1007 + 2 + 0x10));
}

#[test]
fn decodes_aarch64_branches() {
    // ret
    let ret = decode_one(DisArch::Aarch64, &[0xc0, 0x03, 0x5f, 0xd6], 0x2000).unwrap();
    assert_eq!(ret.flow, Flow::Return);
    assert_eq!(ret.len, 4);
    // bl $+8
    let bl = decode_one(DisArch::Aarch64, &[0x02, 0x00, 0x00, 0x94], 0x2000).unwrap();
    assert_eq!(bl.flow, Flow::Call);
    assert_eq!(bl.target, Some(0x2008));
    // b.eq $+8 (conditional)
    let beq = decode_one(DisArch::Aarch64, &[0x40, 0x00, 0x00, 0x54], 0x2000).unwrap();
    assert_eq!(beq.flow, Flow::CondJump);
    assert_eq!(beq.target, Some(0x2008));
    // br x0 (indirect: no static target)
    let br = decode_one(DisArch::Aarch64, &[0x00, 0x00, 0x1f, 0xd6], 0x2000).unwrap();
    assert_eq!(br.flow, Flow::Jump);
    assert_eq!(br.target, None);
}

#[test]
fn an_unsupported_arch_has_no_disassembler() {
    use crate::format::{Arch, Bits};
    assert!(DisArch::from_format(Arch::Mips, Bits::B32).is_none());
    assert_eq!(DisArch::from_format(Arch::Aarch64, Bits::B64), Some(DisArch::Aarch64));
}

// ---- F-77: linear + recursive ----

/// x86-64: `jmp $+2` (skips one byte) then `int3; ret`. Recursive descent must
/// skip the `int3` that linear disassembly would decode.
fn skip_code() -> Vec<u8> {
    // 0: eb 01     jmp 0x3
    // 2: cc        int3   (unreachable)
    // 3: c3        ret
    vec![0xeb, 0x01, 0xcc, 0xc3]
}

#[test]
fn linear_decodes_every_byte() {
    let job = DisasmJob::new(
        DisArch::X86_64,
        vec![Region { vaddr: 0, bytes: skip_code() }],
        DisasmMode::Linear,
        vec![0],
    );
    let listing = job.run();
    let addrs: Vec<u64> = listing.insns.iter().map(|i| i.address).collect();
    // linear covers the int3 at offset 2
    assert!(addrs.contains(&2), "{addrs:?}");
}

#[test]
fn recursive_descent_follows_the_jump_and_skips_dead_code() {
    let job = DisasmJob::new(
        DisArch::X86_64,
        vec![Region { vaddr: 0, bytes: skip_code() }],
        DisasmMode::Recursive,
        vec![0],
    );
    let listing = job.run();
    let addrs: Vec<u64> = listing.insns.iter().map(|i| i.address).collect();
    assert!(addrs.contains(&0), "jmp decoded");
    assert!(addrs.contains(&3), "ret at jump target decoded");
    assert!(!addrs.contains(&2), "unreachable int3 not decoded: {addrs:?}");
    // the jump records an xref to its target
    assert_eq!(listing.xrefs.get(&3), Some(&vec![0]));
}

#[test]
fn recursive_descent_follows_a_call_and_its_fallthrough() {
    // 0: e8 01 00 00 00   call 0x6
    // 5: c3               ret   (fall-through after the call)
    // 6: c3               ret   (call target)
    let code = vec![0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3];
    let job = DisasmJob::new(
        DisArch::X86_64,
        vec![Region { vaddr: 0, bytes: code }],
        DisasmMode::Recursive,
        vec![0],
    );
    let listing = job.run();
    let addrs: Vec<u64> = listing.insns.iter().map(|i| i.address).collect();
    assert_eq!(addrs, vec![0, 5, 6], "call target and fall-through both decoded");
}

// ---- F-78: stack strings ----

#[test]
fn recovers_a_stack_string_from_byte_stores() {
    // mov byte [rbp-0x10], 'H' ; 'i' ; '!' ; 0   (then ret)
    let mut code = Vec::new();
    for (i, ch) in [b'H', b'i', b'!', 0u8].iter().enumerate() {
        let disp = (0xf0 + i) as u8; // -0x10, -0xf, -0xe, -0xd
        code.extend_from_slice(&[0xc6, 0x45, disp, *ch]);
    }
    code.push(0xc3);
    let found = stack_strings(DisArch::X86_64, &code, 0x400000, 3);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].text, "Hi!");
    assert_eq!(found[0].address, 0x400000);
}

#[test]
fn a_dword_store_builds_part_of_a_stack_string() {
    // mov dword [rbp-0x10], "hell" (0x6c6c6568) ; mov dword [rbp-0xc], "o!\0\0"
    let code = [
        0xc7, 0x45, 0xf0, 0x68, 0x65, 0x6c, 0x6c, // "hell"
        0xc7, 0x45, 0xf4, 0x6f, 0x21, 0x00, 0x00, // "o!\0\0"
    ];
    let found = stack_strings(DisArch::X86_64, &code, 0, 4);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].text, "hello!");
}

#[test]
fn ordinary_code_has_no_stack_strings() {
    // push rbp; mov rbp, rsp; pop rbp; ret
    let code = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
    assert!(stack_strings(DisArch::X86_64, &code, 0, 4).is_empty());
}
