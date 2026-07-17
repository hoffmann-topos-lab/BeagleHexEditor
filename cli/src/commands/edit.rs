//! Editing commands: patch, fill, bookmarks.

use hexed_core::{Bookmark, Bookmarks, FillPattern};

use crate::args::{flag, parse_hex, parse_u64, split_flags};

use super::open_doc;

pub(crate) fn cmd_patch(args: &[String]) -> Result<(), String> {
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

/// F-05/F-51 — In-place overwrite: writes only the changed bytes back to the
/// file. Unlike `patch`, this **modifies the input** (only existing bytes, never
/// growing the file), so it is guarded by `--yes`.
pub(crate) fn cmd_poke(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["yes"])?;
    let path = pos.first().ok_or("missing file")?;
    let offset = parse_u64(pos.get(1).ok_or("missing offset")?)?;
    let bytes = parse_hex(pos.get(2).ok_or("missing hex sequence")?)?;
    if flag(&flags, "yes").is_none() {
        return Err("poke overwrites the file in place; pass --yes to confirm".into());
    }

    let mut doc = open_doc(path)?;
    doc.overwrite(offset, &bytes).map_err(|e| e.to_string())?;
    if !doc.can_save_in_place() {
        return Err(
            "the edit would grow the file; poke only overwrites existing bytes (use patch -o)"
                .into(),
        );
    }
    let n = doc.save_in_place(path).map_err(|e| e.to_string())?;
    eprintln!("hexed: {n} byte(s) written in place at {offset:#x} → {path}");
    Ok(())
}

/// F-22 — Fill a range. Like `patch`, it never overwrites its input.
pub(crate) fn cmd_fill(args: &[String]) -> Result<(), String> {
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

/// F-23 — Bookmarks in the sidecar file (`<file>.hexed-bookmarks`).
pub(crate) fn cmd_bookmarks(args: &[String]) -> Result<(), String> {
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
            eprintln!("hexed: {} bookmark(s) in {}", marks.len(), sidecar.display());
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
