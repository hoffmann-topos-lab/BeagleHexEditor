//! Fase 10 (F-73/F-74/F-75) — Identify window: Detect It Easy + PEStudio, in the
//! GUI. Runs the core `identify::analyze` on the active file and shows the
//! toolchain/packer detections, the packing verdict (with per-section entropy)
//! and the static indicators. Offline, like the core (nothing touches the net).
//!
//! Analysis reads section bytes, so it is button-driven and cached per
//! `(tab, len)` rather than run every frame.

use eframe::egui::{self, Color32, RichText, Ui};
use hexed_core::identify::{self, IdentifyReport, Severity};
use hexed_core::{Progress, format, magic, stats};

use crate::app::Tab;

const SUSPICIOUS: Color32 = Color32::from_rgb(220, 150, 60);
const ERR: Color32 = Color32::from_rgb(220, 90, 90);

#[derive(Default)]
pub struct DetectState {
    pub open: bool,
    /// The analysis, or an error string. `None` before the first run.
    result: Option<Result<Report, String>>,
    /// `(tab, doc len)` the result is for — a mismatch marks it stale.
    for_tab: Option<(usize, u64)>,
    show_entropy: bool,
    show_indicators: bool,
}

struct Report {
    type_line: String,
    /// Executable analysis, or `None` for a non-executable (entropy only).
    exe: Option<ExeReport>,
    file_entropy: Option<f64>,
}

struct ExeReport {
    summary: String,
    entry: u64,
    report: IdentifyReport,
}

impl DetectState {
    pub fn window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.open {
            return;
        }
        let mut open = true;
        let mut run = false;
        let stale = self.for_tab.map(|(t, _)| t) != Some(active) && self.result.is_some();

        egui::Window::new("Identify — packer / toolchain / indicators")
            .open(&mut open)
            .default_width(470.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    run = ui.button("Analyze active file").clicked();
                    ui.checkbox(&mut self.show_entropy, "entropy per section");
                    ui.checkbox(&mut self.show_indicators, "indicators");
                });
                if stale {
                    ui.weak("· switched files — press Analyze to refresh");
                }
                ui.separator();
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    match &self.result {
                        None => {
                            ui.weak("click Analyze to identify the active file");
                        }
                        Some(Err(e)) => {
                            ui.colored_label(ERR, e);
                        }
                        Some(Ok(rep)) => {
                            render(ui, rep, self.show_entropy, self.show_indicators);
                        }
                    }
                });
            });
        self.open = open;
        if run {
            self.analyze(tabs, active);
        }
    }

    fn analyze(&mut self, tabs: &mut [Tab], active: usize) {
        let Some(tab) = tabs.get_mut(active) else { return };
        self.for_tab = Some((active, tab.doc.len()));

        let sigs = magic::identify(&mut tab.doc);
        let type_line = if sigs.is_empty() {
            "unknown".to_string()
        } else {
            sigs.iter().map(|s| s.name).collect::<Vec<_>>().join(", ")
        };

        let report = match format::parse(&mut tab.doc) {
            Ok(info) => {
                let summary = format!(
                    "{} — {} {}, {}",
                    info.format.name(),
                    info.arch.name(),
                    info.bits.name(),
                    info.endian.name()
                );
                let report = identify::analyze(&mut tab.doc, &info, &Progress::new());
                Report {
                    type_line,
                    exe: Some(ExeReport { summary, entry: info.entry, report }),
                    file_entropy: None,
                }
            }
            Err(_) => {
                // Not a parseable executable: entropy is still a useful signal.
                let len = tab.doc.len().max(1);
                let s = stats::stats(&mut tab.doc, 0..len, Some(len), &Progress::new());
                Report { type_line, exe: None, file_entropy: Some(s.entropy()) }
            }
        };
        self.result = Some(Ok(report));
    }
}

fn render(ui: &mut Ui, rep: &Report, show_entropy: bool, show_indicators: bool) {
    ui.monospace(format!("type    {}", rep.type_line));

    let Some(exe) = &rep.exe else {
        if let Some(e) = rep.file_entropy {
            ui.monospace(format!("entropy {e:.3} bits/byte"));
        }
        ui.weak("not a recognised executable — deeper analysis needs ELF/PE/Mach-O");
        return;
    };

    ui.monospace(format!("format  {}", exe.summary));
    if exe.entry != 0 {
        ui.monospace(format!("entry   {:#x}", exe.entry));
    }
    ui.separator();

    ui.strong("Detected");
    if exe.report.detections.is_empty() {
        ui.weak("no known toolchain, packer or protector");
    } else {
        for d in &exe.report.detections {
            let line = if d.details.is_empty() {
                format!("{:<10} {}", d.kind.name(), d.name)
            } else {
                format!("{:<10} {}  ({})", d.kind.name(), d.name, d.details)
            };
            ui.monospace(line);
        }
    }

    ui.separator();
    let p = &exe.report.packing;
    let verdict = if p.likely_packed { "likely packed" } else { "not packed" };
    ui.label(format!("Packing: {verdict}  (file entropy {:.2}/8)", p.file_entropy));
    for r in &p.reasons {
        ui.monospace(format!("  - {r}"));
    }
    if show_entropy {
        ui.add_space(4.0);
        ui.monospace(format!("{:<20}{:>12}{:>9}  perms", "section", "size", "entropy"));
        for s in &p.sections {
            let perms = format!("{}{}", tick(s.executable, 'x'), tick(s.writable, 'w'));
            ui.monospace(format!("{:<20}{:>12}{:>9.3}  {perms}", s.name, s.size, s.entropy));
        }
        if let Some((size, e)) = p.overlay {
            ui.monospace(format!("{:<20}{:>12}{:>9.3}  overlay", "(overlay)", size, e));
        }
    }

    if show_indicators {
        ui.separator();
        ui.strong("Indicators");
        if exe.report.indicators.is_empty() {
            ui.weak("none");
        } else {
            for i in &exe.report.indicators {
                let text = format!("[{:<10}] {:<8} {}", i.severity.name(), i.category, i.detail);
                match i.severity {
                    Severity::Suspicious => {
                        ui.label(RichText::new(text).monospace().color(SUSPICIOUS));
                    }
                    Severity::Info => {
                        ui.monospace(text);
                    }
                }
            }
        }
    } else if !exe.report.indicators.is_empty() {
        ui.weak(format!("{} indicator(s) — tick “indicators”", exe.report.indicators.len()));
    }
}

fn tick(b: bool, c: char) -> char {
    if b { c } else { '-' }
}
