//! The search bar and the results list.

use eframe::egui::{self, Key, ProgressBar, TextEdit};

use crate::app::Tab;

use super::{Mode, SearchState, TYPED_KINDS};

impl SearchState {
    /// The search bar (top panel). Returns `true` if focus changed so the grid
    /// does not steal the keyboard.
    pub fn bar_ui(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: &mut usize) {
        if !self.open {
            return;
        }
        let mut find_now = false;
        egui::TopBottomPanel::top("searchbar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                for (mode, label) in
                    [(Mode::Hex, "Hex"), (Mode::Text, "Text"), (Mode::Typed, "Typed")]
                {
                    if ui.selectable_label(self.mode == mode, label).clicked() {
                        self.mode = mode;
                    }
                }
                ui.separator();

                if self.mode == Mode::Typed {
                    egui::ComboBox::from_id_salt("typed_kind")
                        .selected_text(TYPED_KINDS[self.typed_kind])
                        .width(60.0)
                        .show_ui(ui, |ui| {
                            for (i, k) in TYPED_KINDS.iter().enumerate() {
                                ui.selectable_value(&mut self.typed_kind, i, *k);
                            }
                        });
                }
                let hint = match self.mode {
                    Mode::Hex => "DE ?? BE EF",
                    Mode::Text => "text in the active charset",
                    Mode::Typed => "value (1234, 3.14…)",
                };
                let r = ui.add(
                    TextEdit::singleline(&mut self.pattern_text)
                        .hint_text(hint)
                        .desired_width(220.0),
                );
                find_now |= r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));

                if self.mode == Mode::Typed {
                    ui.label("±");
                    ui.add(
                        TextEdit::singleline(&mut self.typed_tol)
                            .hint_text("exact")
                            .desired_width(60.0),
                    )
                    .on_hover_text("tolerance for floats (empty = exact bytes)");
                    ui.checkbox(&mut self.big_endian, "BE");
                } else {
                    ui.label("→");
                    ui.add(
                        TextEdit::singleline(&mut self.replace_text)
                            .hint_text("replacement")
                            .desired_width(160.0),
                    );
                }

                if self.mode == Mode::Text {
                    ui.checkbox(&mut self.ci, "ignore case");
                }
                ui.checkbox(&mut self.wrap, "wrap around");
                ui.checkbox(&mut self.in_selection, "in selection");
                ui.checkbox(&mut self.all_tabs, "all tabs")
                    .on_hover_text("applies to Find all");
            });

            ui.horizontal(|ui| {
                if let Some(job) = &self.job {
                    ui.add(ProgressBar::new(job.progress.fraction()).desired_width(180.0));
                    if ui.button("Cancel").clicked() {
                        job.progress.cancel();
                    }
                } else {
                    if ui.button("◀ Previous").clicked() {
                        self.start_next(tabs, *active, true);
                    }
                    find_now |= ui.button("Next ▶").clicked();
                    if ui.button("Find all").clicked() {
                        self.start_all(tabs, *active);
                    }
                    if self.mode != Mode::Typed {
                        ui.separator();
                        if ui.button("Replace").clicked() {
                            self.replace_current(tabs, *active);
                        }
                        if ui.button("Replace all").clicked() {
                            self.start_replace_all(tabs, *active);
                        }
                    }
                }
                if !self.status.is_empty() {
                    ui.separator();
                    ui.weak(&self.status);
                }
                if ui.input(|i| i.key_pressed(Key::Escape)) {
                    self.open = false;
                }
            });
        });
        if find_now {
            self.start_next(tabs, *active, false);
        }
    }

    /// F-15b — Navigable results list (bottom panel).
    pub fn results_ui(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: &mut usize) {
        if !self.results_open || self.results.is_empty() {
            return;
        }
        egui::TopBottomPanel::bottom("results").resizable(true).default_height(140.0).show(
            ctx,
            |ui| {
                ui.horizontal(|ui| {
                    ui.heading(format!("Results ({})", self.results.len()));
                    if ui.small_button("✕").clicked() {
                        self.results_open = false;
                    }
                });
                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::vertical().show_rows(
                    ui,
                    row_h,
                    self.results.len(),
                    |ui, rows| {
                        for i in rows {
                            let hit = &self.results[i];
                            let title = tabs
                                .get(hit.tab)
                                .map(|t| t.title.as_str())
                                .unwrap_or("(tab closed)");
                            let label = format!("{:#010x}  {}", hit.at, title);
                            if ui.selectable_label(false, egui::RichText::new(label).monospace())
                                .clicked()
                                && let Some(tab) = tabs.get_mut(hit.tab)
                            {
                                *active = hit.tab;
                                tab.view.select_range(hit.at..hit.at + hit.len, tab.doc.len());
                            }
                        }
                    },
                );
            },
        );
    }
}
