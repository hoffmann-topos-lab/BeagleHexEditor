//! F-81 — Turning a binary's functions into fingerprints.
//!
//! For each defined function symbol, an intra-procedural recursive walk from its
//! entry (following branches, *not* calls) collects the instructions the
//! function actually reaches; each is normalized ([`normalize`]) and the whole
//! address-ordered sequence is hashed (FNV-1a). The walk is bounded by a span
//! window and an instruction cap so a mis-sized symbol cannot run away.

use std::collections::{BTreeMap, BTreeSet};

use super::Function;
use crate::disasm::{DisArch, Flow, decode_one};
use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::format::{BinaryInfo, SymKind};
use crate::progress::Progress;

/// Bytes loaded per executable section.
const CAP: u64 = 256 << 20;
/// A function body is assumed to live within this window of its entry.
const MAX_SPAN: u64 = 0x40000;
/// Ceiling on instructions collected per function.
const MAX_INSNS: usize = 20_000;

struct Region {
    vaddr: u64,
    bytes: Vec<u8>,
}

pub(super) fn functions(
    doc: &mut Document,
    info: &BinaryInfo,
    arch: DisArch,
    progress: &Progress,
) -> Result<Vec<Function>> {
    let regions = load_regions(doc, info);

    // Defined function symbols, one per address (keep the first name).
    let mut syms: Vec<(&str, u64)> = info
        .symbols
        .iter()
        .filter(|s| s.defined && s.kind == SymKind::Func && s.value != 0)
        .map(|s| (s.name.as_str(), s.value))
        .collect();
    syms.sort_by_key(|&(_, v)| v);
    syms.dedup_by_key(|&mut (_, v)| v);

    let mut out = Vec::with_capacity(syms.len());
    for (name, va) in syms {
        if progress.is_cancelled() {
            return Err(Error::new(ErrorKind::Io, "cancelled"));
        }
        progress.add_done(1);
        let seq = walk(arch, &regions, va);
        if !seq.is_empty() {
            out.push(Function { name: name.to_string(), address: va, insns: seq.len(), hash: fnv(&seq) });
        }
    }
    Ok(out)
}

fn load_regions(doc: &mut Document, info: &BinaryInfo) -> Vec<Region> {
    let mut regions = Vec::new();
    for s in &info.sections {
        if !s.perms.x || s.file.is_empty() {
            continue;
        }
        let len = (s.file.end - s.file.start).min(CAP) as usize;
        let r = doc.read(s.file.start, len);
        if r.is_clean() && !r.data.is_empty() {
            regions.push(Region { vaddr: s.vaddr, bytes: r.data });
        }
    }
    regions
}

/// Intra-procedural recursive descent from `start`: follows fall-through and
/// direct branches, stops at returns/traps, and never follows a call target
/// (that is a different function). Returns the normalized instruction texts,
/// ordered by address.
fn walk(arch: DisArch, regions: &[Region], start: u64) -> Vec<String> {
    let mut visited = BTreeSet::new();
    let mut work = vec![start];
    let mut insns: BTreeMap<u64, String> = BTreeMap::new();
    let limit = start.saturating_add(MAX_SPAN);

    while let Some(va) = work.pop() {
        if va < start || va >= limit || !visited.insert(va) {
            continue;
        }
        if insns.len() >= MAX_INSNS {
            break;
        }
        let Some(bytes) = bytes_at(regions, va) else { continue };
        let Some(insn) = decode_one(arch, bytes, va) else { continue };
        let next = va + insn.len as u64;
        insns.insert(va, normalize(&insn.text));
        match insn.flow {
            Flow::Return | Flow::Halt => {}
            Flow::Jump => {
                if let Some(t) = insn.target {
                    work.push(t);
                }
            }
            Flow::CondJump => {
                if let Some(t) = insn.target {
                    work.push(t);
                }
                work.push(next);
            }
            // A call's target belongs to another function; keep going after it.
            Flow::Call | Flow::Normal => work.push(next),
        }
    }
    insns.into_values().collect()
}

fn bytes_at(regions: &[Region], va: u64) -> Option<&[u8]> {
    let r = regions.iter().find(|r| va >= r.vaddr && va < r.vaddr + r.bytes.len() as u64)?;
    Some(&r.bytes[(va - r.vaddr) as usize..])
}

/// Canonicalizes an instruction's text so address shifts and immediate values
/// don't defeat matching: every hex literal becomes `0x?` and every decimal
/// immediate `?`. Register indices (`x0`, `w1`) are preserved — a digit that
/// follows an identifier character is part of a name, not a literal.
pub(super) fn normalize(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        let after_ident = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        // 0x-hex literal (not part of an identifier).
        if !after_ident
            && b[i] == b'0'
            && i + 2 < b.len()
            && (b[i + 1] | 0x20) == b'x'
            && b[i + 2].is_ascii_hexdigit()
        {
            out.push_str("0x?");
            i += 2;
            while i < b.len() && b[i].is_ascii_hexdigit() {
                i += 1;
            }
            continue;
        }
        // Standalone decimal literal (not a register index).
        if b[i].is_ascii_digit() && !after_ident {
            out.push('?');
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// FNV-1a over the normalized sequence, with a separator between instructions.
pub(super) fn fnv(seq: &[String]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for s in seq {
        for &byte in s.as_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_masks_addresses_and_immediates_keeping_registers() {
        assert_eq!(normalize("mov rax, 0x140001000"), "mov rax, 0x?");
        assert_eq!(normalize("mov eax, 0x2"), "mov eax, 0x?");
        assert_eq!(normalize("add x0, x1, #0x10"), "add x0, x1, #0x?");
        assert_eq!(normalize("ldr w1, [sp, #16]"), "ldr w1, [sp, #?]");
        assert_eq!(normalize("b.eq 0x1000"), "b.eq 0x?");
        // Register indices survive; only literals are masked.
        assert_eq!(normalize("mov x28, x29"), "mov x28, x29");
    }

    #[test]
    fn two_functions_differing_only_by_an_address_fingerprint_equal() {
        let a = vec![normalize("call 0x1000"), normalize("mov eax, 0x10")];
        let b = vec![normalize("call 0x9abc"), normalize("mov eax, 0x20")];
        assert_eq!(fnv(&a), fnv(&b), "normalization hides the differing addresses");
    }

    #[test]
    fn a_mnemonic_change_changes_the_fingerprint() {
        let a = vec![normalize("mov eax, 0x1")];
        let b = vec![normalize("xor eax, 0x1")];
        assert_ne!(fnv(&a), fnv(&b));
    }
}
