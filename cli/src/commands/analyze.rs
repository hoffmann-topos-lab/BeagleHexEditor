//! Fase 4 analysis commands: hash, strings, stats, magic, diff.

use hexed_core::Progress;
use hexed_core::hash::Algo;
use hexed_core::strings::StrEncoding;

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

/// F-24 — String extraction.
pub(crate) fn cmd_strings(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let path = pos.first().ok_or("missing file")?;
    let min = match flag(&flags, "min") {
        Some(s) => parse_u64(s)? as usize,
        None => 4,
    };
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
