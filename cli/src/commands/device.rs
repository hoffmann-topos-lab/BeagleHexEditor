//! Fase 5/8 device commands: disks, shred.

use hexed_core::{Progress, disks};

use crate::args::{flag, parse_u64, split_flags};

/// F-48 — List disks and partitions (needs no privilege).
pub(crate) fn cmd_disks(_args: &[String]) -> Result<(), String> {
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
pub(crate) fn cmd_shred(args: &[String]) -> Result<(), String> {
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
