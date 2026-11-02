//! Fase 12 — `recipe`: apply a CyberChef-style transformation pipeline (F-80)
//! to a selection. Without `-o` the raw output goes to stdout, so recipes
//! compose with the shell (`hexed recipe f.bin "from-base64" | file -`).

use hexed_core::recipe::{self, DEFAULT_CAP};
use hexed_core::{Progress, Recipe};

use crate::args::{parse_size, split_flags};

use super::open_doc;

pub(crate) fn cmd_recipe(args: &[String]) -> Result<(), String> {
    let (pos, flags) = split_flags(args, &[])?;
    let path = pos.first().ok_or("missing file")?;
    let spec = pos
        .get(1)
        .ok_or("missing recipe. Example: hexed recipe payload.bin \"from-hex | gunzip\"")?;
    let recipe = Recipe::parse(spec)?;

    let cap = match flags.get("cap") {
        Some(s) => parse_size(s)?,
        None => DEFAULT_CAP,
    };

    let mut doc = open_doc(path)?;
    let range = flags.range(doc.len())?;
    let output =
        recipe::run(&mut doc, range, &recipe, cap, &Progress::new())?;

    match flags.out() {
        Some(out) => {
            std::fs::write(out, &output).map_err(|e| e.to_string())?;
            eprintln!("hexed: {} step(s), {} byte(s) → {out}", recipe.ops.len(), output.len());
        }
        None => {
            use std::io::Write;
            std::io::stdout().write_all(&output).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
