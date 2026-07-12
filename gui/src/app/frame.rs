//! The per-frame loop: panel order matters — egui stacks panels in the order
//! they are created, so this sequence defines the layout.

use eframe::egui;
use hexed_core::Document;

use super::menus::Actions;
use super::{App, PendingClose, fingerprint};
use crate::shortcuts::{self, Action};

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_external_changes(ctx);

        // The inspector highlight (F-16) and the comparison diff (F-32) last
        // one frame: whoever wants to highlight does so again.
        for tab in &mut self.tabs {
            tab.view.highlight = None;
            tab.view.diff.clear();
        }

        // F-61: persist the open session whenever the window is asked to close.
        if ctx.input(|i| i.viewport().close_requested()) {
            self.save_prefs();
            // F-44: intercept the close if there are unsaved changes.
            if !self.allow_quit && self.tabs.iter().any(|t| t.doc.dirty()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.pending_close = Some(PendingClose::Quit);
            }
        }

        let actions = self.menus_and_shortcuts(ctx);
        self.tab_bar_ui(ctx);
        self.drive_jobs(ctx, actions);
        self.status_bar_ui(ctx);

        // F-15b: results list (above the status bar).
        self.search.results_ui(ctx, &mut self.tabs, &mut self.active);

        self.external_change_banner(ctx);
        self.side_panels_ui(ctx);

        // The grid.
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(tab) = self.tabs.get_mut(self.active) {
                let ro = tab.read_only;
                tab.view.show(ui, &mut tab.doc, ro);
            } else {
                ui.centered_and_justified(|ui| {
                    let open = shortcuts::symbol(&self.shortcuts[Action::Open]);
                    let new = shortcuts::symbol(&self.shortcuts[Action::New]);
                    ui.label(format!("{open} to open a file, {new} for a new document"));
                });
            }
        });

        self.show_goto_dialog(ctx); // F-13
        self.show_unsaved_dialog(ctx); // F-44
        self.show_select_dialog(ctx); // F-21
        self.show_fill_dialog(ctx); // F-22
        self.show_offset_start_dialog(ctx); // F-19
        self.show_bookmark_dialog(ctx); // F-23
        self.show_disk_picker(ctx); // F-48/F-49
        self.show_shred_dialog(ctx); // F-45
        self.show_rebind_dialog(ctx); // F-60
    }
}

impl App {
    /// Tab bar (F-10).
    fn tab_bar_ui(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                let mut close_req: Option<usize> = None;
                for (i, tab) in self.tabs.iter().enumerate() {
                    let dirty = if tab.doc.dirty() { "● " } else { "" };
                    let selected = i == self.active;
                    if ui.selectable_label(selected, format!("{dirty}{}", tab.title)).clicked() {
                        self.active = i;
                    }
                    if selected && ui.small_button("✕").clicked() {
                        close_req = Some(i);
                    }
                }
                if let Some(i) = close_req {
                    self.request_close_tab(i);
                }
            });
        });
    }

    /// Cooperative jobs (F-07) and the actions the menus handed over.
    fn drive_jobs(&mut self, ctx: &egui::Context, actions: Actions) {
        // Phase 3: search bar (below the tabs) and cooperative job (F-07).
        self.search.bar_ui(ctx, &mut self.tabs, &mut self.active);
        self.search.drive(&mut self.tabs, &mut self.active, ctx);
        // Phase 4: analysis jobs and windows.
        self.analyze.drive(&mut self.tabs, ctx);
        if actions.magic && let Some(tab) = self.tabs.get_mut(self.active) {
            self.analyze.open_magic(tab);
        }
        self.analyze.windows(ctx, &mut self.tabs, self.active);
        // Phase 5: open a disk.
        if actions.open_disk {
            self.open_disk_picker();
        }
        // Phase 8: pick a file to shred (F-45).
        if actions.shred && let Some(p) = rfd::FileDialog::new().pick_file() {
            self.shred_path = Some(p);
            self.shred_ack = false;
        }
        // Phase 6: import/export, copy-as, split/concatenate.
        if actions.import {
            self.import_records();
        }
        if actions.concat
            && let Some(inputs) = rfd::FileDialog::new().pick_files()
            && let Some(out) =
                rfd::FileDialog::new().set_file_name("concatenated.bin").save_file()
        {
            // The order is the file picker's; the CLI gives explicit control.
            self.tools.start_concat(&inputs, out);
        }
        if let Some(fmt) = actions.copy_as
            && let Some(tab) = self.tabs.get_mut(self.active)
        {
            self.tools.copy_as(tab, fmt, ctx);
        }
        self.tools.drive(&mut self.tabs, ctx);
        self.tools.windows(ctx, &mut self.tabs, self.active);
        self.compare_mode(ctx, actions.next_diff);
    }

    /// Status bar.
    fn status_bar_ui(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(tab) = self.tabs.get_mut(self.active) {
                    let c = tab.view.cursor;
                    ui.monospace(format!("Offset: {c:#X} ({c})"));
                    if let Some(sel) = tab.view.selection() {
                        ui.monospace(format!("Sel: {} byte(s)", sel.end - sel.start));
                    }
                    ui.separator();
                    // F-34: clickable, as in HxD.
                    let mode = if tab.view.insert_mode { "INS" } else { "OVR" };
                    if ui.selectable_label(false, mode).clicked() {
                        tab.view.insert_mode = !tab.view.insert_mode;
                    }
                    if tab.read_only {
                        ui.colored_label(egui::Color32::YELLOW, "read-only");
                    }
                    ui.separator();
                    ui.monospace(format!("{} byte(s)", tab.doc.len()));
                    if !tab.view.status.is_empty() {
                        ui.separator();
                        ui.label(&tab.view.status);
                    }
                } else if !self.global_status.is_empty() {
                    ui.label(&self.global_status);
                }
                // Phase 6: the last tool's result (progress has its own window
                // while it runs).
                if !self.tools.busy() && !self.tools.status.is_empty() {
                    ui.separator();
                    ui.label(&self.tools.status);
                }
            });
        });
    }

    /// F-43: external-modification banner.
    fn external_change_banner(&mut self, ctx: &egui::Context) {
        if let Some(tab) = self.tabs.get_mut(self.active)
            && tab.external_change
        {
            egui::TopBottomPanel::top("external").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 160, 40),
                        "⚠ the file changed on disk",
                    );
                    if ui.button("Reload").clicked()
                        && let Some(path) = tab.path.clone()
                        && let Ok(doc) = Document::open(&path, false)
                    {
                        let cursor = tab.view.cursor.min(doc.len());
                        let old = std::mem::take(&mut tab.view);
                        tab.doc = doc;
                        // Display options (F-18/F-19/F-20) survive the reload.
                        tab.view.cols = old.cols;
                        tab.view.group = old.group;
                        tab.view.offset_base = old.offset_base;
                        tab.view.offset_start = old.offset_start;
                        tab.view.charset = old.charset;
                        tab.view.goto(cursor, tab.doc.len());
                        tab.fp = fingerprint(&path);
                        tab.external_change = false;
                    }
                    if ui.button("Ignore").clicked() {
                        tab.external_change = false;
                        tab.fp = tab.path.as_deref().and_then(fingerprint);
                    }
                });
            });
        }
    }

    /// F-23 bookmarks (left) and F-16/F-17 Data Inspector (right), both before
    /// the central panel.
    fn side_panels_ui(&mut self, ctx: &egui::Context) {
        if self.bookmarks_open
            && let Some(tab) = self.tabs.get_mut(self.active)
        {
            let bm_open = &mut self.bm_open;
            egui::SidePanel::left("bookmarks").default_width(230.0).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Bookmarks");
                    if ui.small_button("＋").on_hover_text("bookmark cursor/selection").clicked() {
                        *bm_open = true;
                    }
                });
                ui.separator();
                if tab.marks.is_empty() {
                    ui.weak("no bookmarks");
                    return;
                }
                let mut remove: Option<usize> = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, b) in tab.marks.items().iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui.small_button("✕").on_hover_text("remove").clicked() {
                                remove = Some(i);
                            }
                            let label = format!("{:#x}  {}", b.offset, b.name);
                            let resp = ui.selectable_label(false, label);
                            let resp = if b.description.is_empty() {
                                resp
                            } else {
                                resp.on_hover_text(&b.description)
                            };
                            if resp.clicked() {
                                if b.len > 0 {
                                    tab.view
                                        .select_range(b.offset..b.offset + b.len, tab.doc.len());
                                } else {
                                    tab.view.goto(b.offset, tab.doc.len());
                                }
                            }
                        });
                    }
                });
                if let Some(i) = remove {
                    tab.marks.remove(i);
                    tab.persist_marks();
                }
            });
        }

        if let Some(tab) = self.tabs.get_mut(self.active)
            && tab.inspector.open
        {
            let ro = tab.read_only;
            egui::SidePanel::right("inspector").default_width(330.0).show(ctx, |ui| {
                ui.heading("Data Inspector");
                ui.separator();
                tab.inspector.show(ui, &mut tab.doc, &mut tab.view, ro);
            });
        }
    }
}
