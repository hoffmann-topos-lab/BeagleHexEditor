//! The four analysis windows (hash, strings, stats, signatures).

use super::charts::{entropy_chart, histogram_chart};
use super::*;

impl AnalyzeState {
    // ---- windows ----

    pub fn windows(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        self.hash_window(ctx, tabs, active);
        self.strings_window(ctx, tabs, active);
        self.stats_window(ctx, tabs, active);
        self.magic_window(ctx, tabs, active);
    }

    fn hash_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.hash_open {
            return;
        }
        let mut open = true;
        egui::Window::new("Hashes and checksums").open(&mut open).resizable(false).show(ctx, |ui| {
            ui.columns(3, |cols| {
                for (i, a) in Algo::ALL.iter().enumerate() {
                    cols[i % 3].checkbox(&mut self.hash_selected[i], a.name());
                }
            });
            ui.checkbox(&mut self.hash_in_selection, "selection only");
            ui.horizontal(|ui| {
                let can = !self.busy() && self.hash_selected.iter().any(|s| *s);
                if ui.add_enabled(can, egui::Button::new("Compute")).clicked()
                    && let Some(tab) = tabs.get(active)
                {
                    let algos: Vec<Algo> = Algo::ALL
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| self.hash_selected[*i])
                        .map(|(_, a)| *a)
                        .collect();
                    let range = Self::range_for(tab, self.hash_in_selection);
                    self.hash_results.clear();
                    let job = DigestJob::new(&algos, range, tab.doc.len());
                    let total = job.total();
                    self.start(Job::Digest { tab: active, job }, total);
                }
            });
            self.progress_row(ui);
            if !self.hash_results.is_empty() {
                ui.separator();
                for (algo, hex) in &self.hash_results {
                    ui.horizontal(|ui| {
                        ui.label(format!("{:<9}", algo.name()));
                        ui.monospace(hex);
                    });
                }
            }
        });
        self.hash_open = open;
    }

    fn strings_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.strings_open {
            return;
        }
        let mut open = true;
        let mut goto: Option<(u64, u64)> = None;
        egui::Window::new("Extract strings")
            .open(&mut open)
            .default_width(430.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("minimum:");
                    ui.add(egui::DragValue::new(&mut self.str_min).range(2..=64));
                    ui.checkbox(&mut self.str_utf8, "UTF-8/ASCII");
                    ui.checkbox(&mut self.str_utf16le, "UTF-16LE");
                    ui.checkbox(&mut self.str_utf16be, "UTF-16BE");
                });
                ui.horizontal(|ui| {
                    let any = self.str_utf8 || self.str_utf16le || self.str_utf16be;
                    if ui.add_enabled(!self.busy() && any, egui::Button::new("Extract")).clicked()
                        && let Some(tab) = tabs.get(active)
                    {
                        let mut encodings = Vec::new();
                        if self.str_utf8 {
                            encodings.push(StrEncoding::Utf8);
                        }
                        if self.str_utf16le {
                            encodings.push(StrEncoding::Utf16Le);
                        }
                        if self.str_utf16be {
                            encodings.push(StrEncoding::Utf16Be);
                        }
                        self.str_results.clear();
                        self.str_truncated = false;
                        let job = StringsJob::new(
                            &encodings,
                            self.str_min,
                            0..tab.doc.len(),
                            tab.doc.len(),
                        );
                        let total = job.total();
                        self.start(Job::Strings { tab: active, job }, total);
                    }
                });
                self.progress_row(ui);
                if !self.str_results.is_empty() {
                    ui.separator();
                    let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                    egui::ScrollArea::vertical().max_height(300.0).show_rows(
                        ui,
                        row_h,
                        self.str_results.len(),
                        |ui, rows| {
                            for i in rows {
                                let s = &self.str_results[i];
                                let label = format!(
                                    "{:#010x} {:<8} {}",
                                    s.offset,
                                    s.encoding.name(),
                                    s.text
                                );
                                if ui
                                    .selectable_label(false, egui::RichText::new(label).monospace())
                                    .clicked()
                                {
                                    goto = Some((s.offset, s.len));
                                }
                            }
                        },
                    );
                }
            });
        self.strings_open = open;
        if let Some((off, len)) = goto
            && let Some(tab) = tabs.get_mut(active)
        {
            tab.view.select_range(off..off + len, tab.doc.len());
        }
    }

    fn stats_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.stats_open {
            return;
        }
        let mut open = true;
        let mut goto: Option<u64> = None;
        egui::Window::new("Statistics").open(&mut open).default_width(560.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.add_enabled(!self.busy(), egui::Button::new("Compute")).clicked()
                    && let Some(tab) = tabs.get(active)
                {
                    self.stats_result = None;
                    let job = Box::new(StatsJob::new(0..tab.doc.len(), tab.doc.len(), None));
                    let total = job.total_space();
                    self.start(Job::Stats { tab: active, job }, total);
                }
            });
            self.progress_row(ui);
            if let Some(s) = &self.stats_result {
                ui.separator();
                let distinct = s.counts.iter().filter(|c| **c > 0).count();
                ui.monospace(format!(
                    "{} byte(s) · entropy {:.3} bits/byte · {distinct}/256 values",
                    s.total,
                    s.entropy()
                ));
                if s.unreadable > 0 {
                    ui.colored_label(
                        Color32::from_rgb(180, 40, 40),
                        format!("⚠ {} unreadable byte(s) left out of the count", s.unreadable),
                    );
                }
                ui.add_space(6.0);
                ui.label("Histogram of the 256 values (F-29):");
                histogram_chart(ui, &s.counts, s.total);
                ui.add_space(6.0);
                ui.label(format!(
                    "Entropy per {}-byte block — click to navigate (F-30a):",
                    s.block_size
                ));
                goto = entropy_chart(ui, &s.blocks, s.block_size);
            }
        });
        self.stats_open = open;
        if let Some(off) = goto
            && let Some(tab) = tabs.get_mut(active)
        {
            tab.view.goto(off, tab.doc.len());
        }
    }

    fn magic_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.magic_open {
            return;
        }
        let mut open = true;
        let mut goto: Option<u64> = None;
        egui::Window::new("Signatures").open(&mut open).default_width(380.0).show(ctx, |ui| {
            if self.magic_identified.is_empty() {
                ui.weak("no known signature in the header");
            } else {
                for s in &self.magic_identified {
                    ui.label(format!("● {}", s.name));
                }
            }
            ui.separator();
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Sweep embedded (carving)"))
                .clicked()
                && let Some(tab) = tabs.get(active)
            {
                self.magic_scan.clear();
                let job = MagicScanJob::new(0..tab.doc.len(), tab.doc.len());
                let total = job.total();
                self.start(Job::Magic { tab: active, job }, total);
            }
            self.progress_row(ui);
            if !self.magic_scan.is_empty() {
                ui.separator();
                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::vertical().max_height(280.0).show_rows(
                    ui,
                    row_h,
                    self.magic_scan.len(),
                    |ui, rows| {
                        for i in rows {
                            let (off, s) = &self.magic_scan[i];
                            let label = format!("{off:#010x}  {}", s.name);
                            if ui
                                .selectable_label(false, egui::RichText::new(label).monospace())
                                .clicked()
                            {
                                goto = Some(*off);
                            }
                        }
                    },
                );
            }
        });
        self.magic_open = open;
        if let Some(off) = goto
            && let Some(tab) = tabs.get_mut(active)
        {
            tab.view.goto(off, tab.doc.len());
        }
    }

    /// Opens the signatures window, identifying the document on the spot.
    pub fn open_magic(&mut self, tab: &mut Tab) {
        self.magic_identified = magic::identify(&mut tab.doc);
        self.magic_scan.clear();
        self.magic_open = true;
    }
}
