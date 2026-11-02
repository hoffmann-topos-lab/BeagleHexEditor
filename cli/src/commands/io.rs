//! Fase 6 import/export commands: export, ihex/srec, split, concat.

use hexed_core::hexfile::{self, RecordFormat};
use hexed_core::{ExportFormat, ExportOptions, OffsetBase, Progress};

use crate::args::{parse_u64, split_flags};

use super::open_doc;

/// F-30/F-31 — Copy-as / report. Without `-o` it writes to stdout, which makes
/// the command composable (`hexed export a.bin --format c | pbcopy`).
pub(crate) fn cmd_export(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let path = pos.first().ok_or("missing file")?;
    let fmt = flags.named("format", "format", ExportFormat::from_name)?.unwrap_or(ExportFormat::HexText);
    let mut opts = ExportOptions { charset: flags.charset()?, ..Default::default() };
    if let Some(s) = flags.get("cols") {
        opts.cols = parse_u64(s)?.clamp(1, 256) as usize;
    }
    if let Some(s) = flags.get("name") {
        opts.var_name = s.to_string();
    }
    if let Some(base) = flags.named("base", "base", OffsetBase::from_name)? {
        opts.base = base;
    }
    opts.offset_start = flags.u64_or("offset-start", opts.offset_start)?;

    let mut doc = open_doc(path)?;
    let range = flags.range(doc.len())?;
    match flags.out() {
        Some(out) => {
            let mut w = std::io::BufWriter::new(
                std::fs::File::create(out).map_err(|e| e.to_string())?,
            );
            hexed_core::export::export(&mut doc, range, fmt, opts, &mut w, &Progress::new())
                ?;
            use std::io::Write;
            w.flush().map_err(|e| e.to_string())?;
            eprintln!("hexed: exported as {} → {out}", fmt.name());
        }
        None => {
            let mut w = std::io::stdout().lock();
            hexed_core::export::export(&mut doc, range, fmt, opts, &mut w, &Progress::new())
                ?;
        }
    }
    Ok(())
}

/// F-27/F-27a — Intel HEX and S-record. `import` validates every checksum and
/// flattens into a binary (gaps become `--fill`, default 0xFF, a flash's erased
/// state); `export` emits records starting at `--addr`.
pub(crate) fn cmd_records(fmt: RecordFormat, args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let dir = pos.first().map(String::as_str).ok_or("missing `import` or `export`")?;
    let path = pos.get(1).ok_or("missing input file")?;
    let out = flags.required_out()?;

    match dir {
        "import" => {
            let fill = match flags.get("fill") {
                Some(s) => u8::try_from(parse_u64(s)?)
                    .map_err(|_| format!("--fill must fit in one byte: {s}"))?,
                None => 0xFF,
            };
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let image = match fmt {
                RecordFormat::IntelHex => hexfile::parse_ihex(&text),
                RecordFormat::Srec => hexfile::parse_srec(&text),
            }
            ?;

            let mut w = std::io::BufWriter::new(
                std::fs::File::create(out).map_err(|e| e.to_string())?,
            );
            let n = hexfile::write_flattened(&image, fill, &mut w)?;
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
            let base = flags.u64_or("addr", 0)?;
            let width = flags.usize_or("width", hexfile::DEFAULT_REC_LEN)?.clamp(1, 250);
            let mut doc = open_doc(path)?;
            let range = flags.range(doc.len())?;
            let mut w = std::io::BufWriter::new(
                std::fs::File::create(out).map_err(|e| e.to_string())?,
            );
            hexfile::write_records(&mut doc, range, fmt, base, width, &mut w, &Progress::new())
                ?;
            use std::io::Write;
            w.flush().map_err(|e| e.to_string())?;
            eprintln!("hexed: {} written → {out}", fmt.name());
            Ok(())
        }
        other => Err(format!("unknown subcommand: {other} (use import|export)")),
    }
}

/// F-57 — Split into fixed-size parts.
pub(crate) fn cmd_split(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let path = pos.first().ok_or("missing file")?;
    let part_size = crate::args::parse_size(pos.get(1).ok_or("missing part size")?)?;
    let prefix = flags.out()
        .ok_or("missing -o <prefix> for the parts")?;

    let mut doc = open_doc(path)?;
    let parts = hexed_core::transform::split(&mut doc, part_size, prefix, &Progress::new())
        ?;
    for p in &parts {
        println!("{}", p.display());
    }
    eprintln!("hexed: {} part(s) of up to {part_size} byte(s)", parts.len());
    Ok(())
}

/// F-58 — Concatenate in the given order.
pub(crate) fn cmd_concat(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    if pos.is_empty() {
        return Err("missing input files".into());
    }
    let out = flags.required_out()?;
    let inputs: Vec<std::path::PathBuf> =
        pos.iter().map(std::path::PathBuf::from).collect();
    let n = hexed_core::transform::concat(&inputs, out, &Progress::new())
        ?;
    eprintln!("hexed: {} file(s), {n} byte(s) → {out}", inputs.len());
    Ok(())
}
