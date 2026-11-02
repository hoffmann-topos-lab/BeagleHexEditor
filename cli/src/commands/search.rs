//! F-13/F-14/F-15/F-28 — find and replace.

use hexed_core::{Endian, Pattern, Progress};

use crate::args::{Flags, parse_hex, split_flags};

use super::open_doc;

/// Builds the `Pattern` from the flags shared by `find` and `replace`:
/// positional hex (with wildcards), `--text` + `--charset`/`--ci`, or `--typed`.
fn build_pattern(hex_arg: Option<&String>, flags: &Flags) -> Result<Pattern, String> {
    if let Some(spec) = flags.get("typed") {
        // "i32=1234" is an exact search; "f32~3.14" searches with a tolerance (--tol).
        let endian = if flags.has("be") { Endian::Big } else { Endian::Little };
        let (kind, value, approx) = match (spec.split_once('='), spec.split_once('~')) {
            (Some((k, v)), _) => (k, v, false),
            (None, Some((k, v))) => (k, v, true),
            _ => return Err(format!("--typed expects type=value or type~value: {spec}")),
        };
        let tol = match flags.get("tol") {
            Some(t) => Some(t.parse::<f64>().map_err(|_| format!("invalid tolerance: {t}"))?),
            None if approx => {
                let v: f64 = value.trim().parse().map_err(|_| "invalid float".to_string())?;
                Some(1e-6 * v.abs().max(1.0))
            }
            None => None,
        };
        return Pattern::typed(kind, value, endian, tol);
    }
    if let Some(text) = flags.get("text") {
        let charset = flags.charset()?;
        let ci = flags.has("ci");
        return Pattern::text(text, charset, ci)
            .ok_or(format!("text not representable in {}", charset.name()));
    }
    let hex = hex_arg.ok_or("missing pattern (positional hex, --text or --typed)")?;
    Pattern::parse_hex(hex).ok_or(format!("invalid hex pattern: {hex}"))
}

/// F-13a/b, F-14, F-15, F-15a/b — headless search.
pub(crate) fn cmd_find(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["ci", "be", "back", "all"])?;
    let path = pos.first().ok_or("missing file")?;
    let pattern = build_pattern(pos.get(1), &flags)?;

    let mut doc = open_doc(path)?;
    let range = flags.range(doc.len())?;
    let backward = flags.has("back");
    let from = flags.u64_or("from", if backward { range.end } else { range.start })?;
    let progress = Progress::new();

    if flags.has("all") {
        let limit = flags.usize_or("limit", 10_000)?;
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
pub(crate) fn cmd_replace(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &["ci", "be", "all"])?;
    let path = pos.first().ok_or("missing input file")?;
    let out = flags.required_out()?;

    // Pattern and replacement travel together: positional hex with positional
    // hex, --text with --with.
    let (pattern, replacement) = if let Some(text) = flags.get("with") {
        let charset = flags.charset()?;
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
    let range = flags.range(doc.len())?;
    let progress = Progress::new();

    let count = if flags.has("all") {
        hexed_core::replace_all(&mut doc, &pattern, &replacement, range, &progress)
            ?
    } else {
        match hexed_core::find_next(&mut doc, &pattern, range, 0, false, false, &progress) {
            Some(at) => {
                hexed_core::search::apply_replacement(&mut doc, at, &replacement)
                    ?;
                1
            }
            None => 0,
        }
    };
    if count == 0 {
        return Err("no match; nothing written".into());
    }
    doc.save_as(out)?;
    eprintln!("hexed: {count} replacement(s) → {out}");
    Ok(())
}
