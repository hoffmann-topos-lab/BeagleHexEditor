//! Fase 9 — Executable format inspection (F-69/F-70/F-71/F-72).
//!
//! `elf`/`pe`/`macho` are readelf/dumpbin/otool-style dumps for one format;
//! `struct` auto-detects the format and prints the provenance tree (F-68) so
//! every field's document byte range is visible. All four share one inspector.

use hexed_core::Progress;
use hexed_core::format::{self, BinaryInfo, Format, Node};

use crate::args::{flag, split_flags};

use super::open_doc;

const VIEWS: &[&str] = &["sections", "symbols", "imports", "relocs", "tree", "all"];

/// F-69 — ELF (readelf/nm).
pub(crate) fn cmd_elf(args: &[String]) -> Result<(), String> {
    inspect(args, Format::Elf)
}

/// F-70 — PE (dumpbin/PE-bear). `--checksum` recomputes the PE checksum (F-85).
pub(crate) fn cmd_pe(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "--checksum") {
        return pe_checksum_cmd(args);
    }
    inspect(args, Format::Pe)
}

/// F-85 — Recompute the PE checksum; with `-o`, write the corrected file.
fn pe_checksum_cmd(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["checksum"])?;
    let path = pos.first().ok_or("missing file")?;
    let mut doc = open_doc(path)?;
    let c = hexed_core::pe_checksum(&mut doc, &Progress::new()).map_err(|e| e.to_string())?;

    println!("checksum field  {:#x}", c.field_offset);
    println!("stored          {:#010x}", c.stored);
    println!("computed        {:#010x}", c.computed);
    println!("status          {}", if c.matches() { "OK" } else { "MISMATCH" });

    match flag(&flags, "o").or_else(|| flag(&flags, "out")) {
        Some(out) => {
            doc.overwrite(c.field_offset, &c.computed.to_le_bytes()).map_err(|e| e.to_string())?;
            doc.save_as(out).map_err(|e| e.to_string())?;
            eprintln!("hexed: wrote corrected checksum {:#010x} → {out}", c.computed);
        }
        None if !c.matches() => {
            eprintln!("hexed: run with -o <output> to write the file with the corrected checksum");
        }
        None => {}
    }
    Ok(())
}

/// F-71 — Mach-O (otool).
pub(crate) fn cmd_macho(args: &[String]) -> Result<(), String> {
    inspect(args, Format::MachO)
}

/// Parses the file, checks it is the expected format, and prints the requested
/// views. With no view flag it prints the summary, sections and libraries.
fn inspect(args: &[String], want: Format) -> Result<(), String> {
    let (pos, flags) = split_flags(args, VIEWS)?;
    let path = pos.first().ok_or("missing file")?;
    let mut doc = open_doc(path)?;
    let info = format::parse(&mut doc).map_err(|e| e.to_string())?;
    if info.format != want {
        let article = if want == Format::Elf { "an" } else { "a" };
        return Err(format!(
            "not {article} {} file (detected {})",
            want.name(),
            info.format.name()
        ));
    }

    let all = flag(&flags, "all").is_some();
    let selected = |name| all || flag(&flags, name).is_some();
    let default = !VIEWS.iter().any(|f| flag(&flags, f).is_some());

    print_summary(&info);
    if default || selected("sections") {
        print_sections(&info);
    }
    if default || selected("imports") {
        print_libs(&info);
    }
    if selected("imports") {
        print_imports(&info);
    }
    if selected("symbols") {
        print_symbols(&info);
    }
    if selected("relocs") {
        print_relocs(&info);
    }
    if selected("tree") {
        println!("\nstructure:");
        print_tree(&info.tree, 0);
    }
    Ok(())
}

/// F-72 — Auto-detect and print the whole provenance tree for any parsed format.
pub(crate) fn cmd_struct(args: &[String]) -> Result<(), String> {
    let (pos, _flags) = split_flags(args, &[])?;
    let path = pos.first().ok_or("missing file")?;
    let mut doc = open_doc(path)?;
    let info = format::parse(&mut doc).map_err(|e| e.to_string())?;
    println!(
        "{} — {} {}, {}",
        info.format.name(),
        info.arch.name(),
        info.bits.name(),
        info.endian.name()
    );
    print_tree(&info.tree, 0);
    Ok(())
}

fn print_summary(info: &BinaryInfo) {
    println!("format    {}", info.format.name());
    println!("arch      {} ({})", info.arch.name(), info.bits.name());
    println!("endian    {}", info.endian.name());
    println!("entry     {:#x}", info.entry);
    println!("sections  {}", info.sections.len());
    println!("symbols   {}", info.symbols.len());
    println!("imports   {}", info.imports.len());
    println!("libraries {}", info.libs.len());
    println!("relocs    {}", info.relocs.len());
}

fn print_sections(info: &BinaryInfo) {
    println!("\nsections:");
    println!("  {:<20} {:>10} {:>18} {:>12}  perms", "name", "size", "vaddr", "file off");
    for s in &info.sections {
        let off = if s.file.is_empty() {
            "-".to_string()
        } else {
            format!("{:#x}", s.file.start)
        };
        println!(
            "  {:<20} {:>10} {:>#18x} {:>12}  {}",
            s.name, s.size, s.vaddr, off, s.perms.rwx()
        );
    }
}

fn print_libs(info: &BinaryInfo) {
    if info.libs.is_empty() {
        return;
    }
    println!("\nlibraries:");
    for l in &info.libs {
        println!("  {l}");
    }
}

fn print_imports(info: &BinaryInfo) {
    println!("\nimports:");
    for imp in &info.imports {
        let sym = match imp.ordinal {
            Some(o) => format!("#{o}"),
            None => imp.name.clone(),
        };
        if imp.library.is_empty() {
            println!("  {sym}");
        } else {
            println!("  {}!{sym}", imp.library);
        }
    }
}

fn print_symbols(info: &BinaryInfo) {
    println!("\nsymbols:");
    for sym in &info.symbols {
        let scope = if sym.global { 'g' } else { 'l' };
        let undef = if sym.defined { ' ' } else { 'U' };
        println!("  {:#018x} {scope}{undef} {:<8} {}", sym.value, sym.kind.name(), sym.name);
    }
}

fn print_relocs(info: &BinaryInfo) {
    println!("\nrelocations:");
    for r in &info.relocs {
        let sym = if r.symbol.is_empty() { String::new() } else { format!(" {}", r.symbol) };
        let add = if r.addend != 0 { format!(" (+{:#x})", r.addend) } else { String::new() };
        println!("  {:#018x} {}{sym}{add}", r.offset, r.kind);
    }
}

fn print_tree(node: &Node, depth: usize) {
    let indent = "  ".repeat(depth);
    let span = format!("[{:#x}..{:#x}]", node.span.start, node.span.end);
    if node.value.is_empty() {
        println!("{indent}{}  {span}", node.name);
    } else {
        println!("{indent}{} = {}  {span}", node.name, node.value);
    }
    for child in &node.children {
        print_tree(child, depth + 1);
    }
}
