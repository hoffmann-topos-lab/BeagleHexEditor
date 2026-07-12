//! Read-only commands: len, dump, inspect.

use hexed_core::inspector::FieldKind;
use hexed_core::{Charset, Endian, OffsetBase};

use crate::args::{flag, parse_charset, parse_u64, split_flags};

use super::open_doc;

pub(crate) fn cmd_len(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("missing file")?;
    let doc = open_doc(path)?;
    println!("{}", doc.len());
    Ok(())
}

pub(crate) fn cmd_dump(args: &[String]) -> Result<(), String> {
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

/// F-16/F-17 — The Data Inspector from the CLI: every field at the given offset.
pub(crate) fn cmd_inspect(args: &[String]) -> Result<(), String> {
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
