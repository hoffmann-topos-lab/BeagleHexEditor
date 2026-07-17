//! F-80 — Recipe window: compose transformations (Fase 12) into a pipeline and
//! preview the result on the current selection.
//!
//! The pipeline is built by hand (add / remove / reorder steps, each with its
//! arguments), assembled into the same spec string the CLI accepts, and run
//! through the core `Recipe` — so the GUI and CLI never diverge on semantics.
//! Small inputs preview live as you edit; a large selection waits for "Apply"
//! so a keystroke never blocks on a 200 MB transform.

use eframe::egui::{self, Color32, ComboBox, RichText, TextEdit};
use hexed_core::recipe::{self, DEFAULT_CAP};
use hexed_core::{Progress, Recipe};

use crate::app::Tab;

/// Largest selection previewed automatically (bigger needs an explicit Apply).
const AUTO_MAX: u64 = 256 << 10;
/// Bytes of output shown in the preview pane.
const PREVIEW_BYTES: usize = 4096;

/// A selectable operation: its menu label, the spec name it maps to, and the
/// hint text for each argument (0..=3).
struct OpDef {
    label: &'static str,
    name: &'static str,
    args: &'static [&'static str],
}

const OPS: &[OpDef] = &[
    OpDef { label: "To Hex", name: "to-hex", args: &[] },
    OpDef { label: "From Hex", name: "from-hex", args: &[] },
    OpDef { label: "To Base64", name: "to-base64", args: &[] },
    OpDef { label: "From Base64", name: "from-base64", args: &[] },
    OpDef { label: "To Base64 (URL)", name: "to-base64url", args: &[] },
    OpDef { label: "From Base64 (URL)", name: "from-base64url", args: &[] },
    OpDef { label: "To Base32", name: "to-base32", args: &[] },
    OpDef { label: "From Base32", name: "from-base32", args: &[] },
    OpDef { label: "To Base85", name: "to-base85", args: &[] },
    OpDef { label: "From Base85", name: "from-base85", args: &[] },
    OpDef { label: "To Z85", name: "to-z85", args: &[] },
    OpDef { label: "From Z85", name: "from-z85", args: &[] },
    OpDef { label: "URL Encode", name: "to-url", args: &[] },
    OpDef { label: "URL Decode", name: "from-url", args: &[] },
    OpDef { label: "XOR", name: "xor", args: &["hex key"] },
    OpDef { label: "Add", name: "add", args: &["n"] },
    OpDef { label: "Sub", name: "sub", args: &["n"] },
    OpDef { label: "Rotate left", name: "rol", args: &["bits"] },
    OpDef { label: "Rotate right", name: "ror", args: &["bits"] },
    OpDef { label: "NOT", name: "not", args: &[] },
    OpDef { label: "Reverse", name: "reverse", args: &[] },
    OpDef { label: "Deflate", name: "deflate", args: &[] },
    OpDef { label: "Inflate", name: "inflate", args: &[] },
    OpDef { label: "Zlib deflate", name: "zlib", args: &[] },
    OpDef { label: "Zlib inflate", name: "unzlib", args: &[] },
    OpDef { label: "Gzip", name: "gzip", args: &[] },
    OpDef { label: "Gunzip", name: "gunzip", args: &[] },
    OpDef { label: "AES encrypt", name: "aes-enc", args: &["cbc/ctr/ecb", "hex key", "hex iv"] },
    OpDef { label: "AES decrypt", name: "aes-dec", args: &["cbc/ctr/ecb", "hex key", "hex iv"] },
    OpDef { label: "RC4", name: "rc4", args: &["hex key"] },
    OpDef { label: "MD5", name: "md5", args: &[] },
    OpDef { label: "SHA-1", name: "sha1", args: &[] },
    OpDef { label: "SHA-256", name: "sha256", args: &[] },
    OpDef { label: "SHA-512", name: "sha512", args: &[] },
    OpDef { label: "BLAKE3", name: "blake3", args: &[] },
    OpDef { label: "CRC-32", name: "crc32", args: &[] },
];

#[derive(Default)]
struct Step {
    op: usize,
    args: [String; 3],
}

#[derive(Default)]
pub struct RecipeState {
    pub open: bool,
    steps: Vec<Step>,
    in_selection: bool,
    as_hex: bool,
    /// Output of the last run for `last_sig`, or an error message.
    output: Option<Result<Vec<u8>, String>>,
    /// The (spec, range) `output` was computed for.
    last_sig: Option<(String, std::ops::Range<u64>)>,
    /// The input changed but is too large to auto-preview: awaiting Apply.
    stale: bool,
}

impl RecipeState {
    pub fn window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.open {
            return;
        }
        let mut open = true;
        let mut apply = false;
        let mut save: Option<Vec<u8>> = None;

        egui::Window::new("Recipe — transform")
            .open(&mut open)
            .default_width(480.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("Pipeline");
                    if ui.small_button("＋ step").clicked() {
                        self.steps.push(Step::default());
                    }
                    if !self.steps.is_empty() && ui.small_button("clear").clicked() {
                        self.steps.clear();
                    }
                });

                let mut remove = None;
                let mut move_up = None;
                for (i, step) in self.steps.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        ui.monospace(format!("{}.", i + 1));
                        ComboBox::from_id_salt(("op", i))
                            .width(140.0)
                            .selected_text(OPS[step.op].label)
                            .show_ui(ui, |ui| {
                                for (j, d) in OPS.iter().enumerate() {
                                    ui.selectable_value(&mut step.op, j, d.label);
                                }
                            });
                        for (k, hint) in OPS[step.op].args.iter().enumerate() {
                            ui.add(
                                TextEdit::singleline(&mut step.args[k])
                                    .desired_width(80.0)
                                    .hint_text(*hint),
                            );
                        }
                        if ui.small_button("✕").on_hover_text("remove").clicked() {
                            remove = Some(i);
                        }
                        if i > 0 && ui.small_button("↑").on_hover_text("move up").clicked() {
                            move_up = Some(i);
                        }
                    });
                }
                if let Some(i) = remove {
                    self.steps.remove(i);
                }
                if let Some(i) = move_up {
                    self.steps.swap(i - 1, i);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.in_selection, "selection only");
                    ui.checkbox(&mut self.as_hex, "output as hex");
                    apply = ui.button("Apply").on_hover_text("run on a large selection").clicked();
                });
                ui.separator();

                match &self.output {
                    None => {
                        ui.weak("output appears here as you build the recipe");
                    }
                    Some(Err(e)) => {
                        ui.colored_label(Color32::from_rgb(220, 90, 90), e);
                    }
                    Some(Ok(bytes)) => {
                        ui.horizontal(|ui| {
                            ui.label(format!("{} byte(s) out", bytes.len()));
                            if self.stale {
                                ui.weak("· input changed — press Apply");
                            }
                            if ui.small_button("Save output…").clicked() {
                                save = Some(bytes.clone());
                            }
                        });
                        let text = preview_text(bytes, self.as_hex);
                        egui::ScrollArea::vertical()
                            .max_height(180.0)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.add(egui::Label::new(RichText::new(text).monospace()).wrap());
                            });
                    }
                }
            });
        self.open = open;

        self.recompute(tabs, active, apply);
        if let Some(bytes) = save {
            save_output(&bytes);
        }
    }

    /// Re-runs the recipe when the spec or selection changed (auto for small
    /// inputs, on `apply` for any size).
    fn recompute(&mut self, tabs: &mut [Tab], active: usize, apply: bool) {
        let Some(tab) = tabs.get_mut(active) else { return };
        let spec = self.build_spec();
        if spec.is_empty() {
            self.output = None;
            self.last_sig = None;
            self.stale = false;
            return;
        }
        let range = match tab.view.selection() {
            Some(sel) if self.in_selection => sel,
            _ => 0..tab.doc.len(),
        };
        let sig = (spec.clone(), range.clone());
        if self.last_sig.as_ref() == Some(&sig) && !apply {
            return;
        }
        let input_len = range.end - range.start;
        if apply || input_len <= AUTO_MAX {
            self.output = Some(run(&mut tab.doc, range, &spec));
            self.last_sig = Some(sig);
            self.stale = false;
        } else {
            self.stale = true;
        }
    }

    /// Assembles the steps into a CLI-compatible spec string.
    fn build_spec(&self) -> String {
        let mut segs = Vec::with_capacity(self.steps.len());
        for s in &self.steps {
            let def = &OPS[s.op];
            let mut seg = String::from(def.name);
            for k in 0..def.args.len() {
                let a = s.args[k].trim();
                if !a.is_empty() {
                    seg.push(' ');
                    seg.push_str(a);
                }
            }
            segs.push(seg);
        }
        segs.join(" | ")
    }
}

fn run(doc: &mut hexed_core::Document, range: std::ops::Range<u64>, spec: &str) -> Result<Vec<u8>, String> {
    let recipe = Recipe::parse(spec).map_err(|e| e.to_string())?;
    recipe::run(doc, range, &recipe, DEFAULT_CAP, &Progress::new()).map_err(|e| e.to_string())
}

fn preview_text(bytes: &[u8], as_hex: bool) -> String {
    let shown = &bytes[..bytes.len().min(PREVIEW_BYTES)];
    let mut s = if as_hex {
        let mut h = String::with_capacity(shown.len() * 3);
        for (i, b) in shown.iter().enumerate() {
            if i > 0 {
                h.push(if i % 16 == 0 { '\n' } else { ' ' });
            }
            h.push_str(&format!("{b:02x}"));
        }
        h
    } else {
        String::from_utf8_lossy(shown).into_owned()
    };
    if bytes.len() > shown.len() {
        s.push_str(&format!("\n… {} more byte(s)", bytes.len() - shown.len()));
    }
    s
}

fn save_output(bytes: &[u8]) {
    if let Some(path) = rfd::FileDialog::new().set_file_name("recipe-output.bin").save_file() {
        let _ = std::fs::write(path, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window's op table must stay in lockstep with the core parser: every
    /// entry's spec name (plus a placeholder for each argument) has to parse.
    #[test]
    fn every_op_maps_to_a_valid_spec() {
        for def in OPS {
            let mut seg = String::from(def.name);
            for hint in def.args {
                let v = if hint.contains("cbc") {
                    "cbc"
                } else if hint.contains("hex") {
                    "00"
                } else {
                    "1"
                };
                seg.push(' ');
                seg.push_str(v);
            }
            assert!(
                Recipe::parse(&seg).is_ok(),
                "op {:?} produced an unparsable spec {seg:?}",
                def.label,
            );
        }
    }
}
