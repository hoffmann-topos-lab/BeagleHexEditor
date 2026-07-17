//! Fase 10 — `detect`: Detect It Easy + PEStudio, offline (F-73/F-74/F-75).
//!
//! Prints the container type (evolving `magic`), then, for a recognised
//! executable, the toolchain/packer detections, the packing verdict and the
//! static indicators. For anything else it still reports the file's entropy.

use hexed_core::identify::{Detection, Indicator, PackReport, Severity};
use hexed_core::{Progress, format, identify, magic, stats};

use crate::args::{flag, split_flags};

use super::open_doc;

pub(crate) fn cmd_detect(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["entropy", "indicators", "all"])?;
    let path = pos.first().ok_or("missing file")?;
    let mut doc = open_doc(path)?;

    let all = flag(&flags, "all").is_some();
    let show_entropy = all || flag(&flags, "entropy").is_some();
    let show_indicators = all || flag(&flags, "indicators").is_some();

    let sigs = magic::identify(&mut doc);
    let type_line = if sigs.is_empty() {
        "unknown".to_string()
    } else {
        sigs.iter().map(|s| s.name).collect::<Vec<_>>().join(", ")
    };
    println!("type      {type_line}");

    let Ok(info) = format::parse(&mut doc) else {
        // Not a parseable executable: entropy is still the useful signal.
        let len = doc.len();
        let s = stats::stats(&mut doc, 0..len, Some(len.max(1)), &Progress::new());
        println!("entropy   {:.3} bits/byte", s.entropy());
        println!("(not a recognised executable — deeper analysis needs ELF/PE/Mach-O)");
        return Ok(());
    };

    println!(
        "format    {} — {} {}, {}",
        info.format.name(),
        info.arch.name(),
        info.bits.name(),
        info.endian.name()
    );
    if info.entry != 0 {
        println!("entry     {:#x}", info.entry);
    }

    let report = identify::analyze(&mut doc, &info, &Progress::new());
    print_detections(&report.detections);
    print_packing(&report.packing, show_entropy);
    if show_indicators {
        print_indicators(&report.indicators);
    } else if !report.indicators.is_empty() {
        println!("\nindicators  {} (use --indicators to list)", report.indicators.len());
    }
    Ok(())
}

fn print_detections(detections: &[Detection]) {
    println!("\ndetected:");
    if detections.is_empty() {
        println!("  (no known toolchain, packer or protector)");
        return;
    }
    for d in detections {
        let details = if d.details.is_empty() {
            String::new()
        } else {
            format!("  ({})", d.details)
        };
        println!("  {:<10} {}{details}", d.kind.name(), d.name);
    }
}

fn print_packing(p: &PackReport, show_entropy: bool) {
    let verdict = if p.likely_packed { "likely packed" } else { "not packed" };
    println!("\npacking   {verdict}  (file entropy {:.2}/8)", p.file_entropy);
    for r in &p.reasons {
        println!("  - {r}");
    }
    if show_entropy {
        println!("\nentropy per section:");
        println!("  {:<20} {:>12} {:>9}  perms", "name", "size", "entropy");
        for s in &p.sections {
            let perms = format!(
                "{}{}",
                if s.executable { "x" } else { "-" },
                if s.writable { "w" } else { "-" }
            );
            println!("  {:<20} {:>12} {:>9.3}  {perms}", s.name, s.size, s.entropy);
        }
        if let Some((size, e)) = p.overlay {
            println!("  {:<20} {:>12} {:>9.3}  overlay", "(overlay)", size, e);
        }
    }
}

fn print_indicators(indicators: &[Indicator]) {
    println!("\nindicators:");
    if indicators.is_empty() {
        println!("  (none)");
        return;
    }
    for i in indicators {
        let tag = match i.severity {
            Severity::Suspicious => "suspicious",
            Severity::Info => "info",
        };
        println!("  [{tag:<10}] {:<8} {}", i.category, i.detail);
    }
}
