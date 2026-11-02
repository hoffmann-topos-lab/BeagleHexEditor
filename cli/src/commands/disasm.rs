//! Fase 11 — `disasm`: linear / recursive disassembly (F-77), objdump-style.

use std::collections::BTreeMap;

use hexed_core::disasm::{self, DisasmMode, DisasmOptions, Insn, Listing};
use hexed_core::{BinaryInfo, format};

use crate::args::split_flags;

use super::open_doc;

/// Loaded code cap: refuse to pull more than this into RAM per section.
const CAP: u64 = 256 << 20;

pub(crate) fn cmd_disasm(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["linear"])?;
    let path = pos.first().ok_or("missing file")?;
    let mut doc = open_doc(path)?;
    let info = format::parse(&mut doc)?;

    let mode = if flags.has("linear") { DisasmMode::Linear } else { DisasmMode::Recursive };
    let extra_seeds: Vec<u64> = flags.u64("from")?.into_iter().collect();
    let limit = flags.usize_or("limit", 4096)?;
    let opts = DisasmOptions {
        mode,
        section: flags.get("section").map(str::to_string),
        extra_seeds,
        cap: CAP,
    };

    let job = disasm::build(&mut doc, &info, &opts)?;
    let listing = job.run();

    println!(
        "{} — {} {} ({})",
        info.format.name(),
        info.arch.name(),
        info.bits.name(),
        match mode {
            DisasmMode::Linear => "linear",
            DisasmMode::Recursive => "recursive",
        }
    );
    print_listing(&listing, &info, limit);
    Ok(())
}

fn print_listing(listing: &Listing, info: &BinaryInfo, limit: usize) {
    let symbols = symbol_map(info);
    for (i, insn) in listing.insns.iter().enumerate() {
        if i >= limit {
            println!("  … stopped at {limit} instructions (--limit)");
            break;
        }
        if let Some(label) = label_for(insn.address, &symbols, listing) {
            println!("\n{label}:");
        }
        println!(
            "  {:#010x}:  {:<21}  {}{}",
            insn.address,
            hexed_core::hex::encode_with(&insn.bytes, " "),
            insn.text,
            annotate_target(insn, &symbols)
        );
    }
}

/// A label for an address that is a symbol or a branch target, else `None`.
fn label_for(addr: u64, symbols: &BTreeMap<u64, String>, listing: &Listing) -> Option<String> {
    if let Some(name) = symbols.get(&addr) {
        return Some(name.clone());
    }
    listing.xrefs.contains_key(&addr).then(|| format!("loc_{addr:x}"))
}

/// Appends the resolved branch/call target (as a symbol name when known).
fn annotate_target(insn: &Insn, symbols: &BTreeMap<u64, String>) -> String {
    match insn.target {
        Some(t) => match symbols.get(&t) {
            Some(name) => format!("        -> {name}"),
            None => format!("        -> {t:#x}"),
        },
        None => String::new(),
    }
}

fn symbol_map(info: &BinaryInfo) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    for s in &info.symbols {
        if s.defined && s.value != 0 {
            map.entry(s.value).or_insert_with(|| s.name.clone());
        }
    }
    map
}
