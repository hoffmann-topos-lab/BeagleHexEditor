//! F-08 — Headless CLI.
//!
//! Not an extra: it is what lets the core be exercised in CI without simulating
//! clicks. No dependencies beyond `core` — argument parsing by hand, to keep the
//! dependency tree empty while it still fits in one's head.

use std::process::ExitCode;

use hexed_core::hash::Algo;
use hexed_core::hexfile::{self, RecordFormat};
use hexed_core::inspector::FieldKind;
use hexed_core::strings::StrEncoding;
use hexed_core::{
    Bookmark, Bookmarks, Charset, Document, Endian, Error, ErrorKind, ExportFormat, ExportOptions,
    FillPattern, OffsetBase, Pattern, Progress, disks,
};

const USAGE: &str = "\
hexed — hex editor (headless frontend)

USAGE:
    hexed len <file>
    hexed dump <file> [offset] [length] [--charset <name>] [--base hex|dec|oct]
    hexed patch <input> <offset> <hex> -o <output>
    hexed inspect <file> [offset] [--be] [--charset <name>]
    hexed fill <input> <offset> <length> <hex> -o <output>
    hexed fill <input> <offset> <length> --random [--seed <n>] -o <output>
    hexed find <file> <hex-with-??> [search options]
    hexed find <file> --text <s> [--charset <name>] [--ci] [search options]
    hexed find <file> --typed <i32=1234|f32~3.14> [--be] [--tol <x>] [options]
    hexed replace <input> <hex> <new-hex> -o <output> [--all] [options]
    hexed replace <input> --text <s> --with <new-s> -o <output> [--all] [options]
    hexed hash <file> [--algos md5,sha256,crc32,…|--all] [--start/--end]
    hexed strings <file> [--min <n>] [--enc utf8,utf16le,utf16be] [--limit <n>]
    hexed stats <file> [--full] [--block <n>] [--start/--end]
    hexed magic <file> [--scan] [--limit <n>]
    hexed diff <a> <b> [--limit <n>]
    hexed bookmarks <file>
    hexed bookmarks <file> add <offset> <length> <name> [description]
    hexed bookmarks <file> rm <index>
    hexed export <file> [--format <fmt>] [--cols <n>] [--name <var>]
                 [--charset <name>] [--base hex|dec|oct] [--offset-start <off>]
                 [--start/--end] [-o <output>]       (default: stdout)
    hexed ihex import <input.hex> -o <output.bin> [--fill <byte>]
    hexed ihex export <input.bin> -o <output.hex> [--addr <base>] [--width <n>]
    hexed srec import <input.srec> -o <output.bin> [--fill <byte>]
    hexed srec export <input.bin> -o <output.srec> [--addr <base>] [--width <n>]
    hexed split <file> <size> -o <prefix>            (writes prefix.000, .001…)
    hexed concat <input>… -o <output>
    hexed disks                                      (list disks and partitions)
    hexed shred <file> [--passes <n>] [--keep] --yes  (overwrite, then delete)

Any <file> argument may be a raw device under /dev/ (e.g. /dev/rdisk2, /dev/sda);
it opens read-only and by sector. Raw device access needs privilege — run with
sudo, or install the privileged helper.

SEARCH OPTIONS: --from <off> (default 0), --back, --all, --limit <n>,
    --start <off> and --end <off> restrict the range (F-15).
OFFSETS accept decimal (4096) or hexadecimal (0x1000).
SIZES also accept the suffixes k, m and g: 512k, 16m, 2g.
HEX is a byte sequence; ?? and ? nibbles are wildcards: \"DE ?? BE EF\", \"D?\".
CHARSETS: ascii, cp1252, cp437, ebcdic, macroman, utf8, utf16le, utf16be.
ALGOS: md5, sha1, sha256, sha512, blake3, crc16, crc32, crc64, adler32, sum, xor8.
EXPORT FORMATS: hex (default), c, java, csharp, pascal, python — byte literals;
    txt, html, rtf, tex — a report with offset + hex + text (F-31).

EXAMPLES:
    hexed find firmware.bin \"DE AD BE EF\" --all
    hexed find savegame.bin --typed i32=9999
    hexed replace config.bin --text v1.0 --with v2.0 --ci --all -o new.bin
    hexed hash evidence.dd --algos sha256,blake3
    hexed magic image.dd --scan
    hexed export payload.bin --format c --name payload -o payload.c
    hexed ihex export firmware.bin --addr 0x8000 -o firmware.hex
    hexed split image.dd 512m -o image.dd.part
    hexed concat image.dd.part.000 image.dd.part.001 -o image.dd
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("hexed: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        return Ok(());
    };

    match cmd.as_str() {
        "len" => cmd_len(&args[1..]),
        "dump" => cmd_dump(&args[1..]),
        "patch" => cmd_patch(&args[1..]),
        "inspect" => cmd_inspect(&args[1..]),
        "fill" => cmd_fill(&args[1..]),
        "find" => cmd_find(&args[1..]),
        "replace" => cmd_replace(&args[1..]),
        "hash" => cmd_hash(&args[1..]),
        "strings" => cmd_strings(&args[1..]),
        "stats" => cmd_stats(&args[1..]),
        "magic" => cmd_magic(&args[1..]),
        "diff" => cmd_diff(&args[1..]),
        "bookmarks" => cmd_bookmarks(&args[1..]),
        "export" => cmd_export(&args[1..]),
        "ihex" => cmd_records(RecordFormat::IntelHex, &args[1..]),
        "srec" => cmd_records(RecordFormat::Srec, &args[1..]),
        "split" => cmd_split(&args[1..]),
        "concat" => cmd_concat(&args[1..]),
        "disks" => cmd_disks(&args[1..]),
        "shred" => cmd_shred(&args[1..]),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command: {other}\n\n{USAGE}")),
    }
}

/// (name, value) pairs of a command's flags; boolean flags have value "".
type Flags = Vec<(String, String)>;

/// Separates `--flag [value]` from the positional arguments. `boolean` lists
/// the flags that carry no value.
fn split_flags(args: &[String], boolean: &[&str]) -> Result<(Vec<String>, Flags), String> {
    let mut positional = Vec::new();
    let mut flags = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(name) = a.strip_prefix("--").or_else(|| a.strip_prefix('-')) {
            if boolean.contains(&name) {
                flags.push((name.to_string(), String::new()));
            } else {
                i += 1;
                let value = args.get(i).ok_or(format!("--{name} requires a value"))?;
                flags.push((name.to_string(), value.clone()));
            }
        } else {
            positional.push(a.clone());
        }
        i += 1;
    }
    Ok((positional, flags))
}

fn flag<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

fn parse_charset(flags: &[(String, String)]) -> Result<Charset, String> {
    match flag(flags, "charset") {
        Some(name) => Charset::from_name(name).ok_or(format!("unknown charset: {name}")),
        None => Ok(Charset::Ascii),
    }
}

fn cmd_len(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("missing file")?;
    let doc = open_doc(path)?;
    println!("{}", doc.len());
    Ok(())
}

fn cmd_dump(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let path = pos.first().ok_or("missing file")?;
    let charset = parse_charset(&flags)?;
    let base = match flag(&flags, "base") {
        Some(name) => OffsetBase::from_name(name).ok_or(format!("unknown base: {name}"))?,
        None => OffsetBase::Hex,
    };
    let mut doc = open_doc(path)?;

    let offset = match pos.get(1) {
        Some(s) => parse_u64(s)?,
        None => 0,
    };
    let len = match pos.get(2) {
        Some(s) => parse_u64(s)? as usize,
        None => (doc.len() - offset.min(doc.len())).min(256) as usize,
    };

    let r = doc.read(offset, len);
    hexdump(offset, &r.data, &r.unreadable, charset, base);
    if !r.is_clean() {
        eprintln!("hexed: {} unreadable range(s) marked with ??", r.unreadable.len());
    }
    Ok(())
}

fn cmd_patch(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("missing input file")?;
    let offset = parse_u64(args.get(1).ok_or("missing offset")?)?;
    let bytes = parse_hex(args.get(2).ok_or("missing hex sequence")?)?;

    let out = match args.iter().position(|a| a == "-o" || a == "--out") {
        Some(i) => args.get(i + 1).ok_or("-o requires a path")?,
        None => return Err("missing -o <output>. This command never overwrites its input.".into()),
    };

    let mut doc = open_doc(path)?;
    doc.overwrite(offset, &bytes).map_err(|e| e.to_string())?;
    doc.save_as(out).map_err(|e| e.to_string())?;

    eprintln!("hexed: {} byte(s) written at {offset:#x} → {out}", bytes.len());
    Ok(())
}

/// F-16/F-17 — The Data Inspector from the CLI: every field at the given offset.
fn cmd_inspect(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["be", "le"])?;
    let path = pos.first().ok_or("missing file")?;
    let offset = match pos.get(1) {
        Some(s) => parse_u64(s)?,
        None => 0,
    };
    let endian = if flag(&flags, "be").is_some() { Endian::Big } else { Endian::Little };
    let charset = parse_charset(&flags)?;

    let mut doc = open_doc(path)?;
    if offset > doc.len() {
        return Err(format!("offset {offset:#x} past the end ({:#x})", doc.len()));
    }
    // A window large enough for the biggest field (GUID: 16; NUL string: 256).
    let r = doc.read(offset, 512);
    if !r.is_clean() {
        eprintln!("hexed: the window contains unreadable bytes; values may be wrong");
    }

    println!("offset {offset:#x} · {} · charset {}", endian.name(), charset.name());
    for kind in FieldKind::ALL {
        let text = match kind.decode(&r.data, endian, charset) {
            Ok((value, _)) => value,
            Err(e) => format!("— {e}"),
        };
        println!("{:<18} {text}", kind.label());
    }
    Ok(())
}

/// F-22 — Fill a range. Like `patch`, it never overwrites its input.
fn cmd_fill(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["random"])?;
    let path = pos.first().ok_or("missing input file")?;
    let offset = parse_u64(pos.get(1).ok_or("missing offset")?)?;
    let len = parse_u64(pos.get(2).ok_or("missing length")?)?;
    let out = flag(&flags, "o")
        .or_else(|| flag(&flags, "out"))
        .ok_or("missing -o <output>. This command never overwrites its input.")?;

    let pattern = if flag(&flags, "random").is_some() {
        let seed = match flag(&flags, "seed") {
            Some(s) => parse_u64(s)?,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
        };
        FillPattern::Random { seed }
    } else {
        let hex = pos.get(3).ok_or("missing hex pattern (or use --random)")?;
        FillPattern::Repeat(parse_hex(hex)?)
    };

    let mut doc = open_doc(path)?;
    doc.fill(offset, len, &pattern).map_err(|e| e.to_string())?;
    doc.save_as(out).map_err(|e| e.to_string())?;

    eprintln!("hexed: {len} byte(s) filled from {offset:#x} → {out}");
    Ok(())
}

/// Builds the `Pattern` from the flags shared by `find` and `replace`:
/// positional hex (with wildcards), `--text` + `--charset`/`--ci`, or `--typed`.
fn build_pattern(hex_arg: Option<&String>, flags: &Flags) -> Result<Pattern, String> {
    if let Some(spec) = flag(flags, "typed") {
        // "i32=1234" is an exact search; "f32~3.14" searches with a tolerance (--tol).
        let endian = if flag(flags, "be").is_some() { Endian::Big } else { Endian::Little };
        let (kind, value, approx) = match (spec.split_once('='), spec.split_once('~')) {
            (Some((k, v)), _) => (k, v, false),
            (None, Some((k, v))) => (k, v, true),
            _ => return Err(format!("--typed expects type=value or type~value: {spec}")),
        };
        let tol = match flag(flags, "tol") {
            Some(t) => Some(t.parse::<f64>().map_err(|_| format!("invalid tolerance: {t}"))?),
            None if approx => {
                let v: f64 = value.trim().parse().map_err(|_| "invalid float".to_string())?;
                Some(1e-6 * v.abs().max(1.0))
            }
            None => None,
        };
        return Pattern::typed(kind, value, endian, tol);
    }
    if let Some(text) = flag(flags, "text") {
        let charset = parse_charset(flags)?;
        let ci = flag(flags, "ci").is_some();
        return Pattern::text(text, charset, ci)
            .ok_or(format!("text not representable in {}", charset.name()));
    }
    let hex = hex_arg.ok_or("missing pattern (positional hex, --text or --typed)")?;
    Pattern::parse_hex(hex).ok_or(format!("invalid hex pattern: {hex}"))
}

/// The search's restricted range (F-15): `--start`/`--end`, else the document.
fn search_range(flags: &Flags, doc_len: u64) -> Result<std::ops::Range<u64>, String> {
    let start = match flag(flags, "start") {
        Some(s) => parse_u64(s)?,
        None => 0,
    };
    let end = match flag(flags, "end") {
        Some(s) => parse_u64(s)?,
        None => doc_len,
    };
    if start > end {
        return Err(format!("inverted range: {start:#x} > {end:#x}"));
    }
    Ok(start..end.min(doc_len))
}

/// F-13a/b, F-14, F-15, F-15a/b — headless search.
fn cmd_find(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["ci", "be", "back", "all"])?;
    let path = pos.first().ok_or("missing file")?;
    let pattern = build_pattern(pos.get(1), &flags)?;

    let mut doc = open_doc(path)?;
    let range = search_range(&flags, doc.len())?;
    let backward = flag(&flags, "back").is_some();
    let from = match flag(&flags, "from") {
        Some(s) => parse_u64(s)?,
        None if backward => range.end,
        None => range.start,
    };
    let progress = Progress::new();

    if flag(&flags, "all").is_some() {
        let limit = match flag(&flags, "limit") {
            Some(s) => parse_u64(s)? as usize,
            None => 10_000,
        };
        let (found, truncated) = hexed_core::find_all(&mut doc, &pattern, range, limit, &progress);
        for at in &found {
            println!("{at:#x}");
        }
        if truncated {
            eprintln!("hexed: stopped at the limit of {limit} matches (--limit)");
        }
        eprintln!("hexed: {} match(es)", found.len());
        if found.is_empty() {
            return Err("no match".into());
        }
    } else {
        match hexed_core::find_next(&mut doc, &pattern, range, from, backward, false, &progress) {
            Some(r) => println!("{:#x}", r.start),
            None => return Err("no match".into()),
        }
    }
    Ok(())
}

/// F-28 — Replace the first match or all of them (`--all`), with a count.
/// Like `patch`, it never overwrites its input.
fn cmd_replace(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["ci", "be", "all"])?;
    let path = pos.first().ok_or("missing input file")?;
    let out = flag(&flags, "o")
        .or_else(|| flag(&flags, "out"))
        .ok_or("missing -o <output>. This command never overwrites its input.")?;

    // Pattern and replacement travel together: positional hex with positional
    // hex, --text with --with.
    let (pattern, replacement) = if let Some(text) = flag(&flags, "with") {
        let charset = parse_charset(&flags)?;
        let repl = charset
            .encode_str(text)
            .ok_or(format!("replacement not representable in {}", charset.name()))?;
        (build_pattern(None, &flags)?, repl)
    } else {
        let pattern = build_pattern(pos.get(1), &flags)?;
        let hex = pos.get(2).ok_or("missing replacement (hex, or --with together with --text)")?;
        (pattern, parse_hex(hex)?)
    };

    let mut doc = open_doc(path)?;
    let range = search_range(&flags, doc.len())?;
    let progress = Progress::new();

    let count = if flag(&flags, "all").is_some() {
        hexed_core::replace_all(&mut doc, &pattern, &replacement, range, &progress)
            .map_err(|e| e.to_string())?
    } else {
        match hexed_core::find_next(&mut doc, &pattern, range, 0, false, false, &progress) {
            Some(at) => {
                hexed_core::search::apply_replacement(&mut doc, at, &replacement)
                    .map_err(|e| e.to_string())?;
                1
            }
            None => 0,
        }
    };
    if count == 0 {
        return Err("no match; nothing written".into());
    }
    doc.save_as(out).map_err(|e| e.to_string())?;
    eprintln!("hexed: {count} replacement(s) → {out}");
    Ok(())
}

/// F-25/F-26 — Hashes and checksums, of the file or of a range.
fn cmd_hash(args: &[String]) -> Result<(), String> {
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
fn cmd_strings(args: &[String]) -> Result<(), String> {
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
fn cmd_stats(args: &[String]) -> Result<(), String> {
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
fn cmd_magic(args: &[String]) -> Result<(), String> {
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
fn cmd_diff(args: &[String]) -> Result<(), String> {
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

/// F-23 — Bookmarks in the sidecar file (`<file>.hexed-bookmarks`).
fn cmd_bookmarks(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("missing file")?;
    let sidecar = Bookmarks::sidecar_for(std::path::Path::new(path));
    let mut marks = Bookmarks::load(&sidecar).map_err(|e| e.to_string())?;

    match args.get(1).map(String::as_str) {
        None | Some("list") => {
            if marks.is_empty() {
                eprintln!("hexed: no bookmarks in {}", sidecar.display());
                return Ok(());
            }
            for (i, b) in marks.items().iter().enumerate() {
                println!("{i:>3}  {:#010x}  {:>8}  {}  {}", b.offset, b.len, b.name, b.description);
            }
            Ok(())
        }
        Some("add") => {
            let offset = parse_u64(args.get(2).ok_or("missing offset")?)?;
            let len = parse_u64(args.get(3).ok_or("missing length (0 = a position only)")?)?;
            let name = args.get(4).ok_or("missing name")?.clone();
            let description = args.get(5).cloned().unwrap_or_default();
            marks.add(Bookmark { offset, len, name, description });
            marks.save(&sidecar).map_err(|e| e.to_string())?;
            eprintln!("hexed: {} bookmark(s) em {}", marks.len(), sidecar.display());
            Ok(())
        }
        Some("rm") => {
            let index = parse_u64(args.get(2).ok_or("missing index (see `bookmarks`)")?)? as usize;
            let removed = marks
                .remove(index)
                .ok_or(format!("index {index} does not exist ({} bookmarks)", marks.len()))?;
            marks.save(&sidecar).map_err(|e| e.to_string())?;
            eprintln!("hexed: removed \"{}\"", removed.name);
            Ok(())
        }
        Some(other) => Err(format!("unknown subcommand: bookmarks {other}")),
    }
}

/// F-30/F-31 — Copy-as / report. Without `-o` it writes to stdout, which makes
/// the command composable (`hexed export a.bin --format c | pbcopy`).
fn cmd_export(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let path = pos.first().ok_or("missing file")?;
    let fmt = match flag(&flags, "format") {
        Some(name) => {
            ExportFormat::from_name(name).ok_or(format!("unknown format: {name}"))?
        }
        None => ExportFormat::HexText,
    };
    let mut opts = ExportOptions { charset: parse_charset(&flags)?, ..Default::default() };
    if let Some(s) = flag(&flags, "cols") {
        opts.cols = parse_u64(s)?.clamp(1, 256) as usize;
    }
    if let Some(s) = flag(&flags, "name") {
        opts.var_name = s.to_string();
    }
    if let Some(s) = flag(&flags, "base") {
        opts.base = OffsetBase::from_name(s).ok_or(format!("unknown base: {s}"))?;
    }
    if let Some(s) = flag(&flags, "offset-start") {
        opts.offset_start = parse_u64(s)?;
    }

    let mut doc = open_doc(path)?;
    let range = search_range(&flags, doc.len())?;
    match flag(&flags, "o").or_else(|| flag(&flags, "out")) {
        Some(out) => {
            let mut w = std::io::BufWriter::new(
                std::fs::File::create(out).map_err(|e| e.to_string())?,
            );
            hexed_core::export::export(&mut doc, range, fmt, opts, &mut w, &Progress::new())
                .map_err(|e| e.to_string())?;
            use std::io::Write;
            w.flush().map_err(|e| e.to_string())?;
            eprintln!("hexed: exported as {} → {out}", fmt.name());
        }
        None => {
            let mut w = std::io::stdout().lock();
            hexed_core::export::export(&mut doc, range, fmt, opts, &mut w, &Progress::new())
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// F-27/F-27a — Intel HEX and S-record. `import` validates every checksum and
/// flattens into a binary (gaps become `--fill`, default 0xFF, a flash's erased
/// state); `export` emits records starting at `--addr`.
fn cmd_records(fmt: RecordFormat, args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let dir = pos.first().map(String::as_str).ok_or("missing `import` or `export`")?;
    let path = pos.get(1).ok_or("missing input file")?;
    let out = flag(&flags, "o")
        .or_else(|| flag(&flags, "out"))
        .ok_or("missing -o <output>. This command never overwrites its input.")?;

    match dir {
        "import" => {
            let fill = match flag(&flags, "fill") {
                Some(s) => u8::try_from(parse_u64(s)?)
                    .map_err(|_| format!("--fill must fit in one byte: {s}"))?,
                None => 0xFF,
            };
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let image = match fmt {
                RecordFormat::IntelHex => hexfile::parse_ihex(&text),
                RecordFormat::Srec => hexfile::parse_srec(&text),
            }
            .map_err(|e| e.to_string())?;

            let mut w = std::io::BufWriter::new(
                std::fs::File::create(out).map_err(|e| e.to_string())?,
            );
            let n = hexfile::write_flattened(&image, fill, &mut w).map_err(|e| e.to_string())?;
            use std::io::Write;
            w.flush().map_err(|e| e.to_string())?;

            let base = image.span().map(|s| s.start).unwrap_or(0);
            eprintln!(
                "hexed: {n} byte(s) from address {base:#x} ({} of data) → {out}",
                image.data_len()
            );
            if let Some(entry) = image.entry {
                eprintln!("hexed: entry address {entry:#x}");
            }
            Ok(())
        }
        "export" => {
            let base = match flag(&flags, "addr") {
                Some(s) => parse_u64(s)?,
                None => 0,
            };
            let width = match flag(&flags, "width") {
                Some(s) => parse_u64(s)?.clamp(1, 250) as usize,
                None => hexfile::DEFAULT_REC_LEN,
            };
            let mut doc = open_doc(path)?;
            let range = search_range(&flags, doc.len())?;
            let mut w = std::io::BufWriter::new(
                std::fs::File::create(out).map_err(|e| e.to_string())?,
            );
            hexfile::write_records(&mut doc, range, fmt, base, width, &mut w, &Progress::new())
                .map_err(|e| e.to_string())?;
            use std::io::Write;
            w.flush().map_err(|e| e.to_string())?;
            eprintln!("hexed: {} written → {out}", fmt.name());
            Ok(())
        }
        other => Err(format!("unknown subcommand: {other} (use import|export)")),
    }
}

/// F-57 — Split into fixed-size parts.
fn cmd_split(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let path = pos.first().ok_or("missing file")?;
    let part_size = parse_size(pos.get(1).ok_or("missing part size")?)?;
    let prefix = flag(&flags, "o")
        .or_else(|| flag(&flags, "out"))
        .ok_or("missing -o <prefix> for the parts")?;

    let mut doc = open_doc(path)?;
    let parts = hexed_core::transform::split(&mut doc, part_size, prefix, &Progress::new())
        .map_err(|e| e.to_string())?;
    for p in &parts {
        println!("{}", p.display());
    }
    eprintln!("hexed: {} part(s) of up to {part_size} byte(s)", parts.len());
    Ok(())
}

/// F-58 — Concatenate in the given order.
fn cmd_concat(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    if pos.is_empty() {
        return Err("missing input files".into());
    }
    let out = flag(&flags, "o")
        .or_else(|| flag(&flags, "out"))
        .ok_or("missing -o <output>. This command never overwrites its input.")?;
    let inputs: Vec<std::path::PathBuf> =
        pos.iter().map(std::path::PathBuf::from).collect();
    let n = hexed_core::transform::concat(&inputs, out, &Progress::new())
        .map_err(|e| e.to_string())?;
    eprintln!("hexed: {} file(s), {n} byte(s) → {out}", inputs.len());
    Ok(())
}

/// F-48 — List disks and partitions (needs no privilege).
fn cmd_disks(_args: &[String]) -> Result<(), String> {
    let list = disks::enumerate().map_err(|e| e.to_string())?;
    if list.is_empty() {
        eprintln!("hexed: no disks reported");
        return Ok(());
    }
    println!("{:<12} {:<18} {:>14}  {:>5}  DESCRIPTION", "ID", "NODE", "SIZE", "SECT");
    for d in &list {
        let kind = if d.whole { "disk" } else { "part" };
        let loc = if d.internal { "internal" } else { "external" };
        let mount = d
            .mount_point
            .as_ref()
            .map(|m| format!("  mounted at {}", m.display()))
            .unwrap_or_default();
        println!(
            "{:<12} {:<18} {:>14}  {:>5}  {kind} · {loc} · {}{mount}",
            d.id,
            d.node.display(),
            d.size,
            d.block_size,
            if d.model.is_empty() { "—" } else { &d.model },
        );
    }
    Ok(())
}

/// F-45 — Shred a file: overwrite its bytes, then delete it (unless `--keep`).
/// Requires `--yes` because it is irreversible; prints the SSD/COW caveat.
fn cmd_shred(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["keep", "yes"])?;
    let path = pos.first().ok_or("missing file")?;
    if path.starts_with("/dev/") {
        return Err("refusing to shred a device node".into());
    }
    let passes = match flag(&flags, "passes") {
        Some(s) => parse_u64(s)?.clamp(1, 35) as u32,
        None => 1,
    };
    let remove = flag(&flags, "keep").is_none();
    let fate = if remove { "overwritten and deleted" } else { "overwritten in place" };

    eprintln!("hexed: {}", hexed_core::shred::WARNING);
    if flag(&flags, "yes").is_none() {
        return Err(format!("refusing without --yes ({path} would be {fate})"));
    }

    hexed_core::shred_file(std::path::Path::new(path), passes, remove, &Progress::new())
        .map_err(|e| e.to_string())?;
    eprintln!("hexed: {path} {fate} ({passes} pass(es))");
    Ok(())
}

// ---- helpers ----

/// Opens a document from a file path, or from a raw device when the path is
/// under `/dev/` (F-49). Devices open read-only and are accessed by sector.
/// Direct access is tried first; if it is denied and the privileged helper
/// (F-47) is running, the read is routed through it.
fn open_doc(path: &str) -> Result<Document, String> {
    if !path.starts_with("/dev/") {
        return Document::open(path, false).map_err(|e| e.to_string());
    }
    let info = disks::find(path).map_err(|e| e.to_string())?;
    let src = hexed_core::source::open_device(&info.node, info.block_size, false, &helper_socket())
        .map_err(privilege_hint)?;
    Ok(Document::new(src))
}

/// The helper socket path: `$HEXED_HELPER_SOCKET`, else the built-in default.
fn helper_socket() -> String {
    std::env::var("HEXED_HELPER_SOCKET")
        .unwrap_or_else(|_| hexed_core::DEFAULT_HELPER_SOCKET.to_string())
}

/// F-56 — A bare "permission denied" on a device is unhelpful; explain it.
fn privilege_hint(e: Error) -> String {
    match e.kind {
        ErrorKind::PermissionDenied => format!(
            "{e}\n  hint: raw disk access needs privilege — run with `sudo`, \
             or install the privileged helper so it is used automatically"
        ),
        _ => e.to_string(),
    }
}

/// Sizes accept a k/m/g suffix (binary: 512k = 512 × 1024).
fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let (num, shift) = match t.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('k') => (&t[..t.len() - 1], 10u32),
        Some('m') => (&t[..t.len() - 1], 20),
        Some('g') => (&t[..t.len() - 1], 30),
        _ => (t, 0),
    };
    let v = parse_u64(num)?;
    if v != 0 && v.leading_zeros() < shift {
        return Err(format!("size overflows 64 bits: {s}"));
    }
    Ok(v << shift)
}

fn parse_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let r = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse::<u64>(),
    };
    r.map_err(|_| format!("invalid number: {s}"))
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err(format!("hex sequence with an odd number of digits: {s}"));
    }
    clean
        .as_bytes()
        .chunks(2)
        .map(|p| {
            let pair = std::str::from_utf8(p).unwrap();
            u8::from_str_radix(pair, 16).map_err(|_| format!("invalid hex byte: {pair}"))
        })
        .collect()
}

fn is_unreadable(offset: u64, ranges: &[std::ops::Range<u64>]) -> bool {
    ranges.iter().any(|r| r.contains(&offset))
}

fn hexdump(
    base: u64,
    data: &[u8],
    unreadable: &[std::ops::Range<u64>],
    charset: Charset,
    offset_base: OffsetBase,
) {
    const COLS: usize = 16;
    // Decode the whole chunk in one go: multi-byte characters crossing a line
    // boundary stay correct (F-20).
    let cells = charset.decode_cells(base, data);
    let digits = offset_base.digits_for(base + data.len() as u64);

    for (row, chunk) in data.chunks(COLS).enumerate() {
        let row_off = base + (row * COLS) as u64;
        print!("{}  ", offset_base.format(row_off, digits));

        for i in 0..COLS {
            match chunk.get(i) {
                Some(b) if !is_unreadable(row_off + i as u64, unreadable) => print!("{b:02X} "),
                Some(_) => print!("?? "),
                None => print!("   "),
            }
            if i == 7 {
                print!(" ");
            }
        }

        print!(" |");
        for (i, _) in chunk.iter().enumerate() {
            if is_unreadable(row_off + i as u64, unreadable) {
                print!("?");
            } else {
                print!("{}", cells[row * COLS + i]);
            }
        }
        println!("|");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u64_accepts_decimal_and_hex() {
        assert_eq!(parse_u64("4096").unwrap(), 4096);
        assert_eq!(parse_u64("0x1000").unwrap(), 4096);
        assert_eq!(parse_u64("0X1000").unwrap(), 4096);
        assert!(parse_u64("nope").is_err());
    }

    #[test]
    fn parse_size_accepts_binary_suffixes() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("512k").unwrap(), 512 << 10);
        assert_eq!(parse_size("16M").unwrap(), 16 << 20);
        assert_eq!(parse_size("2g").unwrap(), 2 << 30);
        assert_eq!(parse_size("0x10k").unwrap(), 16 << 10);
        assert!(parse_size("999999999999g").is_err(), "overflow detected");
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn parse_hex_accepts_spaces() {
        assert_eq!(parse_hex("DEADBEEF").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(parse_hex("DE AD BE EF").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(parse_hex("ABC").is_err());
        assert!(parse_hex("ZZ").is_err());
    }

    #[test]
    fn split_flags_separates_positionals_from_flags() {
        let args: Vec<String> =
            ["a.bin", "--charset", "cp437", "0x10", "--random", "-o", "out.bin"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let (pos, flags) = split_flags(&args, &["random"]).unwrap();
        assert_eq!(pos, vec!["a.bin", "0x10"]);
        assert_eq!(flag(&flags, "charset"), Some("cp437"));
        assert_eq!(flag(&flags, "random"), Some(""));
        assert_eq!(flag(&flags, "o"), Some("out.bin"));
        assert_eq!(flag(&flags, "seed"), None);
    }

    #[test]
    fn split_flags_requires_a_value_for_a_non_boolean_flag() {
        let args: Vec<String> = ["x", "--charset"].iter().map(|s| s.to_string()).collect();
        assert!(split_flags(&args, &[]).is_err());
    }
}
