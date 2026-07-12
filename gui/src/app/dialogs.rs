//! Modal dialogs: go-to, unsaved changes, select range, fill, starting offset,
//! add bookmark.

use eframe::egui::{self, Align2, Key};
use hexed_core::{Bookmark, FillPattern};

use crate::hexview::{self, parse_goto};
use crate::util::{enter_in, parse_num};

use super::{App, PendingClose};

impl App {
    /// "Go to offset" dialog (F-13).
    pub(super) fn show_goto_dialog(&mut self, ctx: &egui::Context) {
        if !self.goto_open {
            return;
        }
        let mut submitted = false;
        egui::Window::new("Go to offset")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Absolute (0x1F4, 500) or relative (+0x10, -32):");
                let r = ui.text_edit_singleline(&mut self.goto_text);
                r.request_focus();
                submitted = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                ui.horizontal(|ui| {
                    submitted |= ui.button("Go").clicked();
                    if ui.button("Cancel").clicked()
                        || ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.goto_open = false;
                    }
                });
            });
        if submitted
            && let Some(tab) = self.tabs.get_mut(self.active)
        {
            // F-19: the user types offsets as they see them — with the
            // starting offset added. Convert back to the document.
            let start = tab.view.offset_start;
            let target = parse_goto(
                &self.goto_text,
                tab.view.cursor.saturating_add(start),
                tab.doc.len().saturating_add(start),
            )
            .and_then(|display| display.checked_sub(start));
            match target {
                Some(off) => {
                    tab.view.goto(off, tab.doc.len());
                    self.goto_open = false;
                    self.goto_text.clear();
                }
                None => tab.view.status = "invalid offset".into(),
            }
        }
    }

    /// Unsaved-changes dialog (F-44).
    pub(super) fn show_unsaved_dialog(&mut self, ctx: &egui::Context) {
        let Some(pending) = &self.pending_close else { return };
        let (title, names) = match pending {
            PendingClose::Tab(i) => {
                ("Close tab with unsaved changes?", vec![self.tabs[*i].title.clone()])
            }
            PendingClose::Quit => (
                "Quit with unsaved changes?",
                self.tabs
                    .iter()
                    .filter(|t| t.doc.dirty())
                    .map(|t| t.title.clone())
                    .collect(),
            ),
        };
        let mut action: Option<&str> = None;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                for n in &names {
                    ui.label(format!("● {n}"));
                }
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        action = Some("save");
                    }
                    if ui.button("Discard").clicked() {
                        action = Some("discard");
                    }
                    if ui.button("Cancel").clicked() {
                        action = Some("cancel");
                    }
                });
            });
        match (action, self.pending_close.take()) {
            (Some("save"), Some(PendingClose::Tab(i))) => {
                self.active = i;
                self.save_active(false);
                if !self.tabs[i].doc.dirty() {
                    self.close_tab(i);
                }
            }
            (Some("discard"), Some(PendingClose::Tab(i))) => self.close_tab(i),
            (Some("save"), Some(PendingClose::Quit)) => {
                for i in 0..self.tabs.len() {
                    if self.tabs[i].doc.dirty() {
                        self.active = i;
                        self.save_active(false);
                    }
                }
                if !self.tabs.iter().any(|t| t.doc.dirty()) {
                    self.allow_quit = true;
                    self.save_prefs(); // F-61: session may have new save-as paths
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
            (Some("discard"), Some(PendingClose::Quit)) => {
                self.allow_quit = true;
                self.save_prefs(); // F-61
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            // No decision yet: hand the request back for the next frame.
            (None, Some(p)) => self.pending_close = Some(p),
            // "cancel" (or impossible states): just closes the dialog.
            _ => {}
        }
    }

    /// F-21 — Selection by range: starting offset + size or ending offset.
    pub(super) fn show_select_dialog(&mut self, ctx: &egui::Context) {
        if !self.select_open {
            return;
        }
        let mut submitted = false;
        egui::Window::new("Select range")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Starting offset:");
                submitted |= enter_in(ui.text_edit_singleline(&mut self.select_start), ui);
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.select_end_mode, false, "Size");
                    ui.radio_value(&mut self.select_end_mode, true, "Ending offset (inclusive)");
                });
                submitted |= enter_in(ui.text_edit_singleline(&mut self.select_value), ui);
                ui.horizontal(|ui| {
                    submitted |= ui.button("Select").clicked();
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.select_open = false;
                    }
                });
            });
        if !submitted {
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        // The fields are display offsets (F-19): subtract the starting offset.
        let start = parse_num(&self.select_start)
            .and_then(|v| v.checked_sub(tab.view.offset_start));
        let value = parse_num(&self.select_value);
        let range = match (start, value, self.select_end_mode) {
            (Some(s), Some(end), true) => {
                end.checked_sub(tab.view.offset_start).and_then(|e| {
                    (e >= s).then_some(s..e.saturating_add(1))
                })
            }
            (Some(s), Some(len), false) if len > 0 => Some(s..s.saturating_add(len)),
            _ => None,
        };
        match range {
            Some(r) if r.start <= tab.doc.len() => {
                tab.view.select_range(r, tab.doc.len());
                tab.view.pane = hexview::Pane::Hex;
                self.select_open = false;
            }
            _ => tab.view.status = "invalid range".into(),
        }
    }

    /// F-22 — Fill the selection with a repeated pattern or random bytes.
    pub(super) fn show_fill_dialog(&mut self, ctx: &egui::Context) {
        if !self.fill_open {
            return;
        }
        let selected = self
            .tabs
            .get(self.active)
            .and_then(|t| t.view.selection())
            .map(|s| s.end - s.start);
        let mut submitted = false;
        egui::Window::new("Fill selection")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                match selected {
                    Some(n) => ui.label(format!("{n} byte(s) selected")),
                    None => ui.colored_label(egui::Color32::YELLOW, "nothing selected"),
                };
                ui.radio_value(&mut self.fill_random, false, "Repeated hex pattern:");
                ui.add_enabled(
                    !self.fill_random,
                    egui::TextEdit::singleline(&mut self.fill_hex).hint_text("00, DE AD…"),
                );
                ui.radio_value(&mut self.fill_random, true, "Random bytes");
                ui.horizontal(|ui| {
                    submitted |= ui.button("Fill").clicked();
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.fill_open = false;
                    }
                });
            });
        if !submitted {
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        let Some(sel) = tab.view.selection() else {
            tab.view.status = "nothing selected".into();
            return;
        };
        if tab.read_only {
            tab.view.status = "read-only".into();
            return;
        }
        let pattern = if self.fill_random {
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            FillPattern::Random { seed }
        } else {
            match hexview::parse_hex(&self.fill_hex) {
                Some(bytes) => FillPattern::Repeat(bytes),
                None => {
                    tab.view.status = "the pattern is not valid hexadecimal".into();
                    return;
                }
            }
        };
        tab.view.end_typing(); // the fill does not merge with typing
        match tab.doc.fill(sel.start, sel.end - sel.start, &pattern) {
            Ok(()) => {
                tab.view.status = format!("{} byte(s) filled", sel.end - sel.start);
                self.fill_open = false;
            }
            Err(e) => tab.view.status = e.to_string(),
        }
    }

    /// F-19 — Custom starting offset (display only).
    pub(super) fn show_offset_start_dialog(&mut self, ctx: &egui::Context) {
        if !self.offstart_open {
            return;
        }
        let mut submitted = false;
        egui::Window::new("Starting offset")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Added to every displayed offset (0x1000, 4096…):");
                let r = ui.text_edit_singleline(&mut self.offstart_text);
                r.request_focus();
                submitted |= enter_in(r, ui);
                ui.horizontal(|ui| {
                    submitted |= ui.button("Apply").clicked();
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.offstart_open = false;
                    }
                });
            });
        if !submitted {
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        match parse_num(&self.offstart_text) {
            Some(v) => {
                tab.view.offset_start = v;
                self.offstart_open = false;
            }
            None => tab.view.status = "invalid number".into(),
        }
    }

    /// F-23 — Add a bookmark at the cursor or over the selection.
    pub(super) fn show_bookmark_dialog(&mut self, ctx: &egui::Context) {
        if !self.bm_open {
            return;
        }
        let mut submitted = false;
        egui::Window::new("Add bookmark")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                if let Some(tab) = self.tabs.get(self.active) {
                    match tab.view.selection() {
                        Some(s) => ui.label(format!(
                            "Region: {:#x} + {} byte(s)",
                            s.start,
                            s.end - s.start
                        )),
                        None => ui.label(format!("Position: {:#x}", tab.view.cursor)),
                    };
                }
                ui.label("Name:");
                submitted |= enter_in(ui.text_edit_singleline(&mut self.bm_name), ui);
                ui.label("Description:");
                submitted |= enter_in(ui.text_edit_singleline(&mut self.bm_desc), ui);
                ui.horizontal(|ui| {
                    submitted |= ui.button("Add").clicked();
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.bm_open = false;
                    }
                });
            });
        if !submitted {
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        if self.bm_name.trim().is_empty() {
            tab.view.status = "the bookmark needs a name".into();
            return;
        }
        let (offset, len) = match tab.view.selection() {
            Some(s) => (s.start, s.end - s.start),
            None => (tab.view.cursor, 0),
        };
        tab.marks.add(Bookmark {
            offset,
            len,
            name: std::mem::take(&mut self.bm_name).trim().to_string(),
            description: std::mem::take(&mut self.bm_desc).trim().to_string(),
        });
        tab.persist_marks();
        self.bm_open = false;
        self.bookmarks_open = true; // show the result
    }
}
