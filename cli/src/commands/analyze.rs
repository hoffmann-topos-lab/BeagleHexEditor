//! Fase 4 analysis commands: hash, strings, stats, magic, diff.

use hexed_core::disasm::{self, DisArch};
use hexed_core::hash::Algo;
use hexed_core::strings::StrEncoding;
use hexed_core::{Document, Progress, format};

use crate::args::{flag, parse_u64, search_range, split_flags};

use super::open_doc;

/// F-25/F-26 — Hashes and checksums, of the file or of a range.
pub(crate) fn cmd_hash(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["all"])?;
    let path = pos.first().ok_or("missing file")?;
    let algos: Vec<Algo> = if flag(&flags, "all").is_some() {
        Algo::ALL.to_vec()
    } else {
        match flag(&flags, "algos") {
            Some(list) => list
                .split(',')
                .map(|a| Algo::from_name(a).ok_or(format!("unknown algorithm: {a}")))
                .collect::<Result<_, _>>()?,
            None => vec![Algo::Sha256],
        }
    };

    let mut doc = open_doc(path)?;
    let range = search_range(&flags, doc.len())?;
    let results = hexed_core::hash::digest(&mut doc, &algos, range, &Progress::new())
        .map_err(|e| e.to_string())?;
    for (algo, hex) in results {
        println!("{:<10} {hex}", algo.name());
    }
    Ok(())
}

/// F-24/F-78 — String extraction. With `--stack`, recovers strings built on the
/// stack by `mov`-immediate sequences in code (x86/x64) instead of scanning bytes.
pub(crate) fn cmd_strings(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["stack"])?;
    let path = pos.first().ok_or("missing file")?;
    let min = match flag(&flags, "min") {
        Some(s) => parse_u64(s)? as usize,
        None => 4,
    };
    if flag(&flags, "stack").is_some() {
        let mut doc = open_doc(path)?;
        return cmd_stack_strings(&mut doc, min);
    }
    let encodings: Vec<StrEncoding> = match flag(&flags, "enc") {
        Some(list) => list
            .split(',')
            .map(|e| StrEncoding::from_name(e).ok_or(format!("unknown encoding: {e}")))
            .collect::<Result<_, _>>()?,
        None => StrEncoding::ALL.to_vec(),
    };
    let limit = match flag(&flags, "limit") {
        Some(s) => parse_u64(s)? as usize,
        None => 10_000,
    };

    let mut doc = open_doc(path)?;
    let range = search_range(&flags, doc.len())?;
    let (found, truncated) =
        hexed_core::strings::extract(&mut doc, &encodings, min, range, limit, &Progress::new());
    for s in &found {
        println!("{:#010x}  {:<8}  {}", s.offset, s.encoding.name(), s.text);
    }
    if truncated {
        eprintln!("hexed: stopped at the limit of {limit} strings (--limit)");
    }
    eprintln!("hexed: {} string(s)", found.len());
    Ok(())
}

/// F-78 — Recovers stack strings from every executable section of a binary.
fn cmd_stack_strings(doc: &mut Document, min: usize) -> Result<(), String> {
    let info = format::parse(doc).map_err(|e| e.to_string())?;
    let Some(arch) = DisArch::from_format(info.arch, info.bits) else {
        return Err(format!(
            "no disassembler for {} — stack strings need x86/x64",
            info.arch.name()
        ));
    };
    let mut total = 0;
    for s in &info.sections {
        if !s.perms.x || s.file.is_empty() {
            continue;
        }
        let len = (s.file.end - s.file.start).min(64 << 20) as usize;
        let r = doc.read(s.file.start, len);
        if !r.is_clean() {
            continue;
        }
        for ss in disasm::stack_strings(arch, &r.data, s.vaddr, min) {
            println!("{:#010x}  {}", ss.address, ss.text);
            total += 1;
        }
    }
    eprintln!("hexed: {total} stack string(s)");
    Ok(())
}

/// F-29/F-30a — Histogram and entropy.
pub(crate) fn cmd_stats(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["full"])?;
    let path = pos.first().ok_or("missing file")?;
    let block = match flag(&flags, "block") {
        Some(s) => Some(parse_u64(s)?),
        None => None,
    };

    let mut doc = open_doc(path)?;
    let range = search_range(&flags, doc.len())?;
    let s = hexed_core::stats::stats(&mut doc, range, block, &Progress::new());

    println!("bytes           {}", s.total);
    println!("entropy         {:.4} bits/byte", s.entropy());
    let distinct = s.counts.iter().filter(|c| **c > 0).count();
    println!("values used     {distinct}/256");
    if s.unreadable > 0 {
        println!("unreadable      {} byte(s) left out of the count", s.unreadable);
    }
    let mut top: Vec<(usize, u64)> =
        s.counts.iter().enumerate().map(|(b, c)| (b, *c)).filter(|(_, c)| *c > 0).collect();
    top.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    println!("most common     {}", top
        .iter()
        .take(5)
        .map(|(b, c)| format!("{b:02X}×{c}"))
        .collect::<Vec<_>>()
        .join("  "));

    if flag(&flags, "full").is_some() {
        println!("\nhistogram:");
        for (b, c) in s.counts.iter().enumerate() {
            if *c > 0 {
                println!("{b:02X}  {c}");
            }
        }
        println!("\nentropy per block ({} bytes):", s.block_size);
        for (i, h) in s.blocks.iter().enumerate() {
            let off = i as u64 * s.block_size;
            if h.is_nan() {
                println!("{off:#010x}  (unreadable)");
            } else {
                println!("{off:#010x}  {h:.3}");
            }
        }
    }
    Ok(())
}

/// F-33 — Signatures: identifies the file and, with `--scan`, sweeps for embedded ones.
pub(crate) fn cmd_magic(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["scan"])?;
    let path = pos.first().ok_or("missing file")?;
    let mut doc = open_doc(path)?;

    let found = hexed_core::magic::identify(&mut doc);
    if found.is_empty() {
        println!("(no known signature in the header)");
    }
    for s in found {
        println!("{}{}", s.name, if s.extension.is_empty() {
            String::new()
        } else {
            format!(" (.{})", s.extension)
        });
    }

    if flag(&flags, "scan").is_some() {
        let limit = match flag(&flags, "limit") {
            Some(s) => parse_u64(s)? as usize,
            None => 1_000,
        };
        let range = search_range(&flags, doc.len())?;
        let (hits, truncated) =
            hexed_core::magic::scan(&mut doc, range, limit, &Progress::new());
        println!("\nsweep (carving):");
        for (off, s) in &hits {
            println!("{off:#010x}  {}", s.name);
        }
        if truncated {
            eprintln!("hexed: stopped at the limit of {limit} hits (--limit)");
        }
        eprintln!("hexed: {} embedded signature(s)", hits.len());
    }
    Ok(())
}

/// F-32 — Byte-by-byte comparison. Exits with failure when the files differ,
/// like cmp(1) — usable from scripts.
pub(crate) fn cmd_diff(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let a_path = pos.first().ok_or("missing both files")?;
    let b_path = pos.get(1).ok_or("missing the second file")?;
    let limit = match flag(&flags, "limit") {
        Some(s) => parse_u64(s)? as usize,
        None => 100,
    };

    let mut a = open_doc(a_path)?;
    let mut b = open_doc(b_path)?;
    let (ranges, truncated) = hexed_core::compare::diff_ranges(&mut a, &mut b, limit, &Progress::new());

    if ranges.is_empty() {
        eprintln!("hexed: identical ({} bytes)", a.len());
        return Ok(());
    }
    for r in &ranges {
        println!("{:#010x}..{:#010x}  {} byte(s)", r.start, r.end, r.end - r.start);
    }
    if truncated {
        eprintln!("hexed: stopped at the limit of {limit} ranges (--limit)");
    }
    if a.len() != b.len() {
        eprintln!("hexed: sizes differ: {} vs {} bytes", a.len(), b.len());
    }
    Err(format!("{} range(s) differ", ranges.len()))
}

/// F-81 — Function-aware structural diff (Fase 13). Exits 1 when the binaries
/// differ at the function level, like `diff` does for bytes.
pub(crate) fn cmd_bindiff(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["all"])?;
    let a_path = pos.first().ok_or("missing both files")?;
    let b_path = pos.get(1).ok_or("missing the second file")?;
    let show_all = flag(&flags, "all").is_some();
    let limit = match flag(&flags, "limit") {
        Some(s) => parse_u64(s)? as usize,
        None => 200,
    };

    let mut a = open_doc(a_path)?;
    let mut b = open_doc(b_path)?;
    let report =
        hexed_core::funcdiff::diff(&mut a, &mut b, &Progress::new()).map_err(|e| e.to_string())?;

    println!("A: {a_path}  ({} function(s))", report.total_a);
    println!("B: {b_path}  ({} function(s))", report.total_b);
    println!(
        "\nsummary: {} identical, {} changed, {} added, {} removed, {} renamed",
        report.identical.len(),
        report.changed.len(),
        report.added.len(),
        report.removed.len(),
        report.renamed.len(),
    );
    if report.total_a == 0 && report.total_b == 0 {
        eprintln!("hexed: no function symbols in either file (stripped?) — nothing to compare");
        return Ok(());
    }

    if !report.changed.is_empty() {
        println!("\nchanged:");
        for c in report.changed.iter().take(limit) {
            println!(
                "  {}  {:#x} ({} insns) -> {:#x} ({} insns)",
                c.name, c.addr_a, c.insns_a, c.addr_b, c.insns_b
            );
        }
        more(report.changed.len(), limit);
    }
    if !report.renamed.is_empty() {
        println!("\nrenamed:");
        for r in report.renamed.iter().take(limit) {
            println!(
                "  {} -> {}  ({:#x} -> {:#x}, {} insns)",
                r.name_a, r.name_b, r.address_a, r.address_b, r.insns
            );
        }
        more(report.renamed.len(), limit);
    }
    if !report.removed.is_empty() {
        println!("\nremoved (in A only):");
        for f in report.removed.iter().take(limit) {
            println!("  {}  {:#x} ({} insns)", f.name, f.address, f.insns);
        }
        more(report.removed.len(), limit);
    }
    if !report.added.is_empty() {
        println!("\nadded (in B only):");
        for f in report.added.iter().take(limit) {
            println!("  {}  {:#x} ({} insns)", f.name, f.address, f.insns);
        }
        more(report.added.len(), limit);
    }
    if show_all && !report.identical.is_empty() {
        println!("\nidentical:");
        for f in report.identical.iter().take(limit) {
            println!("  {}  {:#x} ({} insns)", f.name, f.address, f.insns);
        }
        more(report.identical.len(), limit);
    }

    if report.differs() {
        Err(format!(
            "{} changed, {} added, {} removed, {} renamed",
            report.changed.len(),
            report.added.len(),
            report.removed.len(),
            report.renamed.len(),
        ))
    } else {
        eprintln!("hexed: functionally identical ({} function(s))", report.identical.len());
        Ok(())
    }
}

fn more(total: usize, limit: usize) {
    if total > limit {
        println!("  … and {} more (--limit)", total - limit);
    }
}

/// F-84 — Memory-image inspector (Fase 15). Full enumeration for ELF cores;
/// detection plus a caveat for raw / Mach-O core / Windows dumps.
pub(crate) fn cmd_memscan(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let path = pos.first().ok_or("missing file")?;
    let limit = match flag(&flags, "limit") {
        Some(s) => parse_u64(s)? as usize,
        None => 40,
    };

    let mut doc = open_doc(path)?;
    let r = hexed_core::dump::inspect(&mut doc, &Progress::new()).map_err(|e| e.to_string())?;

    println!("format    {}", r.kind.name());
    if let (Some(a), Some(b), Some(e)) = (r.arch, r.bits, r.endian) {
        println!("target    {} {}, {}", a.name(), b.name(), e.name());
    }
    if !r.note.is_empty() {
        println!("note      {}", r.note);
    }

    if !r.processes.is_empty() {
        println!("\nprocesses:");
        for p in &r.processes {
            println!("  pid {:>7}  ppid {:>7}  {}", p.pid, p.ppid, p.name);
            if !p.args.is_empty() {
                println!("                             args: {}", p.args);
            }
        }
    }
    if r.threads > 0 {
        println!("\nthreads   {}", r.threads);
    }
    if !r.regions.is_empty() {
        let total: u64 = r.regions.iter().map(|x| x.size).sum();
        println!("\nregions   {} ({total} bytes mapped)", r.regions.len());
        for reg in r.regions.iter().take(limit) {
            println!(
                "  {:#018x}  {:>12}  {}  file@{:#x}",
                reg.vaddr,
                reg.size,
                reg.perms.rwx(),
                reg.file_off
            );
        }
        more(r.regions.len(), limit);
    }
    if !r.modules.is_empty() {
        println!("\nmodules   {}", r.modules.len());
        for m in r.modules.iter().take(limit) {
            println!("  {:#014x}-{:#014x}  {}", m.start, m.end, m.name);
        }
        more(r.modules.len(), limit);
    }
    Ok(())
}
