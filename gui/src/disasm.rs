//! Fase 11 (F-77) — Disassembly window: linear/recursive listing (objdump-style)
//! for x86/x64/ARM64, over the active file's executable sections.
//!
//! Like the structure tree, it closes the provenance loop: **clicking an
//! instruction selects its bytes in the grid** (the VA is mapped back to a file
//! offset through the section table). Button-driven and bounded — the region
//! load and the instruction count are capped so a linear sweep of a huge section
//! can never hang the UI.

use std::collections::BTreeMap;
use std::ops::Range;

use eframe::egui::{self, Color32, ComboBox, RichText, Sense, TextStyle};
use hexed_core::{BinaryInfo, DisasmMode, DisasmOptions, Insn, format, hex};

use crate::app::Tab;

const ACCENT: Color32 = Color32::from_rgb(64, 140, 220);
const ERR: Color32 = Color32::from_rgb(220, 90, 90);
/// Bytes loaded per section — plenty to read, bounded against a giant sweep.
const CAP: u64 = 16 << 20;
/// Stop decoding after this many instructions (a linear sweep is unbounded).
const MAX_INSNS: u64 = 60_000;
/// Cap on rendered rows (labels included).
const MAX_ROWS: usize = 80_000;

#[derive(Clone, PartialEq, Default)]
enum SectionChoice {
    #[default]
    Auto,
    Named(String),
}

pub struct DisasmState {
    pub open: bool,
    result: Option<Result<Rendered, String>>,
    /// `(tab, doc len)` the section list + result are for.
    for_tab: Option<(usize, u64)>,
    recursive: bool,
    section: SectionChoice,
    sections: Vec<String>,
}

impl Default for DisasmState {
    fn default() -> Self {
        Self {
            open: false,
            result: None,
            for_tab: None,
            recursive: true,
            section: SectionChoice::Auto,
            sections: Vec::new(),
        }
    }
}

struct Rendered {
    header: String,
    entries: Vec<Entry>,
}

enum Entry {
    Label(String),
    Insn { line: String, file: Option<Range<u64>> },
}

impl DisasmState {
    pub fn window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.open {
            return;
        }
        if tabs.get(active).is_none() {
            let mut open = true;
            egui::Window::new("Disassembly").open(&mut open).show(ctx, |ui| {
                ui.weak("open a file to disassemble");
            });
            self.open = open;
            return;
        }
        self.ensure_sections(tabs, active);

        let mut open = true;
        let mut go = false;
        let Some(tab) = tabs.get_mut(active) else { return };
        let doc_len = tab.doc.len();
        let view = &mut tab.view;

        egui::Window::new("Disassembly").open(&mut open).default_width(600.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.recursive, true, "recursive");
                ui.selectable_value(&mut self.recursive, false, "linear");
                ComboBox::from_id_salt("disasm-section")
                    .selected_text(match &self.section {
                        SectionChoice::Auto => "auto".to_string(),
                        SectionChoice::Named(n) => n.clone(),
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.section,
                            SectionChoice::Auto,
                            "auto (exec sections)",
                        );
                        for name in &self.sections {
                            ui.selectable_value(
                                &mut self.section,
                                SectionChoice::Named(name.clone()),
                                name,
                            );
                        }
                    });
                go = ui.button("Disassemble").clicked();
            });
            ui.separator();

            match &self.result {
                None => {
                    ui.weak("choose a section and press Disassemble");
                }
                Some(Err(e)) => {
                    ui.colored_label(ERR, e);
                }
                Some(Ok(r)) => {
                    ui.label(RichText::new(&r.header).strong());
                    ui.weak("click an instruction to jump to its bytes");
                    ui.separator();
                    let row_h = ui.text_style_height(&TextStyle::Monospace);
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
                        ui,
                        row_h,
                        r.entries.len(),
                        |ui, rows| {
                            for i in rows {
                                match &r.entries[i] {
                                    Entry::Label(l) => {
                                        ui.label(RichText::new(l).monospace().color(ACCENT));
                                    }
                                    Entry::Insn { line, file } => {
                                        let w = egui::Label::new(RichText::new(line).monospace())
                                            .sense(Sense::click());
                                        let resp = ui.add(w);
                                        if let Some(f) = file {
                                            if resp.hovered() {
                                                view.highlight = Some(f.clone());
                                            }
                                            if resp.clicked() {
                                                view.select_range(f.clone(), doc_len);
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    );
                }
            }
        });
        self.open = open;
        if go {
            self.run(tabs, active);
        }
    }

    /// Parses the active file (cheap) to populate the section dropdown, on the
    /// first open and on any tab/length change.
    fn ensure_sections(&mut self, tabs: &mut [Tab], active: usize) {
        let want = tabs.get(active).map(|t| (active, t.doc.len()));
        if self.for_tab == want {
            return;
        }
        self.for_tab = want;
        self.result = None;
        self.sections.clear();
        if let Some(tab) = tabs.get_mut(active)
            && let Ok(info) = format::parse(&mut tab.doc)
        {
            self.sections = info
                .sections
                .iter()
                .filter(|s| s.perms.x && !s.file.is_empty())
                .map(|s| s.name.clone())
                .collect();
        }
        if let SectionChoice::Named(n) = &self.section
            && !self.sections.contains(n)
        {
            self.section = SectionChoice::Auto;
        }
    }

    fn run(&mut self, tabs: &mut [Tab], active: usize) {
        let recursive = self.recursive;
        let section = self.section.clone();
        let Some(tab) = tabs.get_mut(active) else { return };
        self.result = Some(build(&mut tab.doc, recursive, &section));
    }
}

fn build(
    doc: &mut hexed_core::Document,
    recursive: bool,
    section: &SectionChoice,
) -> Result<Rendered, String> {
    let info = format::parse(doc)?;
    let opts = DisasmOptions {
        mode: if recursive { DisasmMode::Recursive } else { DisasmMode::Linear },
        section: match section {
            SectionChoice::Auto => None,
            SectionChoice::Named(n) => Some(n.clone()),
        },
        extra_seeds: Vec::new(),
        cap: CAP,
    };
    let mut job = hexed_core::disasm::build(doc, &info, &opts)?;

    // Bound the sweep: stop after MAX_INSNS decoded instructions.
    let mut scanned = 0u64;
    loop {
        let st = job.step(4096);
        scanned += st.scanned;
        if st.finished || scanned >= MAX_INSNS {
            break;
        }
    }
    let listing = job.finish();

    let symbols = symbol_map(&info);
    let mut entries = Vec::new();
    let mut truncated = false;
    for insn in &listing.insns {
        if entries.len() >= MAX_ROWS {
            truncated = true;
            break;
        }
        if let Some(label) = label_for(insn.address, &symbols, &listing.xrefs) {
            entries.push(Entry::Label(format!("{label}:")));
        }
        let line = format!(
            "{:#010x}:  {:<21}  {}{}",
            insn.address,
            hex::encode_with(&insn.bytes, " "),
            insn.text,
            annotate(insn, &symbols)
        );
        entries.push(Entry::Insn {
            line,
            file: format::va_to_file(&info.sections, insn.address, insn.len as u64),
        });
    }
    if truncated {
        entries.push(Entry::Label(format!("… stopped at {MAX_ROWS} rows")));
    }

    let header = format!(
        "{} — {} {} ({})",
        info.format.name(),
        info.arch.name(),
        info.bits.name(),
        if recursive { "recursive" } else { "linear" }
    );
    Ok(Rendered { header, entries })
}

fn symbol_map(info: &BinaryInfo) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    for s in &info.symbols {
        if s.defined && s.value != 0 {
            map.entry(s.value).or_insert_with(|| s.name.clone());
        }
    }
    map
}

fn label_for(
    addr: u64,
    symbols: &BTreeMap<u64, String>,
    xrefs: &BTreeMap<u64, Vec<u64>>,
) -> Option<String> {
    if let Some(name) = symbols.get(&addr) {
        return Some(name.clone());
    }
    xrefs.contains_key(&addr).then(|| format!("loc_{addr:x}"))
}

fn annotate(insn: &Insn, symbols: &BTreeMap<u64, String>) -> String {
    match insn.target {
        Some(t) => match symbols.get(&t) {
            Some(name) => format!("        -> {name}"),
            None => format!("        -> {t:#x}"),
        },
        None => String::new(),
    }
}
