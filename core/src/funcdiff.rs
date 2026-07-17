//! F-81 — Function-aware binary diff (Fase 13), the BinDiff/Diaphora idea kept
//! deliberately lite (full graph isomorphism is out of scope, D-note).
//!
//! Each function is reduced to a *fingerprint*: the sequence of its
//! instructions, disassembled intra-procedurally (calls are not followed) and
//! normalized so addresses and immediates don't defeat matching (see
//! [`extract`]). Two passes then pair the functions:
//!
//! 1. **by symbol name** — same name in both binaries;
//! 2. **by fingerprint** — leftovers with an identical normalized fingerprint
//!    (a rename / moved function).
//!
//! What is left is *added* (only in B) or *removed* (only in A); a name-matched
//! pair whose fingerprints differ is *changed*. Because the fingerprint
//! normalizes immediates away, a change touching only a constant reads as
//! identical — the known price of normalization, and why this is the lite tier.

mod extract;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use crate::disasm::DisArch;
use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::format;
use crate::progress::Progress;

/// A function reduced to what the diff needs.
#[derive(Debug, Clone)]
struct Function {
    name: String,
    address: u64,
    insns: usize,
    hash: u64,
}

/// A function present in only one binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncRef {
    pub name: String,
    pub address: u64,
    pub insns: usize,
}

/// A name-matched pair whose fingerprints differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncChange {
    pub name: String,
    pub addr_a: u64,
    pub addr_b: u64,
    pub insns_a: usize,
    pub insns_b: usize,
}

/// A fingerprint-matched pair with different names (rename / moved code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renamed {
    pub name_a: String,
    pub name_b: String,
    pub address_a: u64,
    pub address_b: u64,
    pub insns: usize,
}

/// The result of a function-level diff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FuncDiffReport {
    pub total_a: usize,
    pub total_b: usize,
    /// Name-matched, fingerprint-equal functions (A side).
    pub identical: Vec<FuncRef>,
    pub changed: Vec<FuncChange>,
    /// Only in B.
    pub added: Vec<FuncRef>,
    /// Only in A.
    pub removed: Vec<FuncRef>,
    pub renamed: Vec<Renamed>,
}

impl FuncDiffReport {
    /// True when anything is added, removed, changed or renamed.
    pub fn differs(&self) -> bool {
        !self.changed.is_empty()
            || !self.added.is_empty()
            || !self.removed.is_empty()
            || !self.renamed.is_empty()
    }
}

/// Diffs two binaries by function. Both must parse as executables of the same
/// disassemblable architecture (the fingerprints are instruction sequences).
pub fn diff(a: &mut Document, b: &mut Document, progress: &Progress) -> Result<FuncDiffReport> {
    let info_a = format::parse(a)?;
    let info_b = format::parse(b)?;
    let arch_a = DisArch::from_format(info_a.arch, info_a.bits)
        .ok_or_else(|| unsupported(info_a.arch.name()))?;
    let arch_b = DisArch::from_format(info_b.arch, info_b.bits)
        .ok_or_else(|| unsupported(info_b.arch.name()))?;
    if arch_a != arch_b {
        return Err(Error::new(
            ErrorKind::Io,
            format!("architecture mismatch: {} vs {}", info_a.arch.name(), info_b.arch.name()),
        ));
    }

    progress.set_total((count_funcs(&info_a) + count_funcs(&info_b)) as u64);
    let fa = extract::functions(a, &info_a, arch_a, progress)?;
    let fb = extract::functions(b, &info_b, arch_b, progress)?;
    Ok(match_functions(fa, fb))
}

fn unsupported(arch: &str) -> Error {
    Error::new(ErrorKind::Io, format!("no disassembler for {arch}; function diff needs x86/x64/ARM64"))
}

fn count_funcs(info: &format::BinaryInfo) -> usize {
    use crate::format::SymKind;
    info.symbols.iter().filter(|s| s.defined && s.kind == SymKind::Func && s.value != 0).count()
}

/// The matching + classification, split out so it is unit-tested without a
/// disassembler.
fn match_functions(fa: Vec<Function>, fb: Vec<Function>) -> FuncDiffReport {
    let total_a = fa.len();
    let total_b = fb.len();
    let mut used_b = vec![false; fb.len()];

    // All b indices for each name, so duplicate names (outlined functions,
    // `GCC_except_table*`, …) pair one-to-one instead of all colliding on one.
    let mut name_to_b: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, f) in fb.iter().enumerate() {
        name_to_b.entry(f.name.as_str()).or_default().push(i);
    }

    let mut identical = Vec::new();
    let mut changed = Vec::new();
    let mut unmatched_a = Vec::new();

    // Pass 1 — by name.
    for a in &fa {
        let ib = name_to_b
            .get(a.name.as_str())
            .and_then(|list| list.iter().copied().find(|&ib| !used_b[ib]));
        match ib {
            Some(ib) => {
                used_b[ib] = true;
                if a.hash == fb[ib].hash {
                    identical.push(FuncRef { name: a.name.clone(), address: a.address, insns: a.insns });
                } else {
                    changed.push(FuncChange {
                        name: a.name.clone(),
                        addr_a: a.address,
                        addr_b: fb[ib].address,
                        insns_a: a.insns,
                        insns_b: fb[ib].insns,
                    });
                }
            }
            None => unmatched_a.push(a),
        }
    }

    // Pass 2 — by fingerprint, among the leftovers.
    let mut hash_to_b: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, f) in fb.iter().enumerate() {
        if !used_b[i] {
            hash_to_b.entry(f.hash).or_default().push(i);
        }
    }
    let mut renamed = Vec::new();
    let mut removed = Vec::new();
    for a in unmatched_a {
        let paired = hash_to_b
            .get(&a.hash)
            .and_then(|list| list.iter().copied().find(|&ib| !used_b[ib]));
        match paired {
            // Same name reaching here means the name lists had uneven counts;
            // an equal fingerprint still makes it the same function, not a rename.
            Some(ib) if a.name == fb[ib].name => {
                used_b[ib] = true;
                identical.push(FuncRef { name: a.name.clone(), address: a.address, insns: a.insns });
            }
            Some(ib) => {
                used_b[ib] = true;
                renamed.push(Renamed {
                    name_a: a.name.clone(),
                    name_b: fb[ib].name.clone(),
                    address_a: a.address,
                    address_b: fb[ib].address,
                    insns: a.insns,
                });
            }
            None => removed.push(FuncRef { name: a.name.clone(), address: a.address, insns: a.insns }),
        }
    }

    let added = fb
        .iter()
        .zip(used_b)
        .filter(|(_, used)| !used)
        .map(|(f, _)| FuncRef { name: f.name.clone(), address: f.address, insns: f.insns })
        .collect();

    let mut report = FuncDiffReport { total_a, total_b, identical, changed, added, removed, renamed };
    report.changed.sort_by_key(|c| c.addr_a);
    report.added.sort_by_key(|f| f.address);
    report.removed.sort_by_key(|f| f.address);
    report.renamed.sort_by_key(|r| r.address_a);
    report
}
