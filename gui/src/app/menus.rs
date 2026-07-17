//! The menu bar, the global shortcuts, and the immediate handling of the
//! actions they trigger. Actions consumed later in the frame (jobs, dialogs)
//! travel back in `Actions`.

use std::path::PathBuf;

use eframe::egui;
use hexed_core::{Charset, ExportFormat, OffsetBase, RecordFormat};

use crate::config::Theme;
use crate::hexview::{COLS_CHOICES, GROUP_CHOICES};
use crate::shortcuts::{self, Action};
use crate::util::clipboard_text;

use super::{App, Tab};

/// Menu/shortcut actions handled after the menu bar is drawn.
#[derive(Default)]
pub(super) struct Actions {
    pub magic: bool,
    pub open_disk: bool,
    pub import: bool,
    pub concat: bool,
    pub shred: bool,
    pub copy_as: Option<ExportFormat>,
    pub next_diff: bool,
}

impl App {
    /// Consumes the global shortcuts, draws the menu bar and applies whatever
    /// can be applied on the spot (new/open/save/undo/…). Returns the actions
    /// that the rest of the frame handles.
    pub(super) fn menus_and_shortcuts(&mut self, ctx: &egui::Context) -> Actions {
        // Global shortcuts (F-60). While recording a rebind, none of them fire —
        // the keystrokes are being captured by the dialog instead.
        let (mut do_open, mut do_new, mut do_save, mut do_save_as, mut do_close) =
            (false, false, false, false, false);
        let (mut do_undo, mut do_redo, mut do_goto, mut do_selall) = (false, false, false, false);
        let (mut do_find, mut do_find_next, mut do_find_prev) = (false, false, false);
        let mut act = Actions::default();
        if self.rebind_recording.is_none() {
            let sc = &self.shortcuts;
            ctx.input_mut(|i| {
                do_open = i.consume_shortcut(&sc[Action::Open]);
                do_new = i.consume_shortcut(&sc[Action::New]);
                do_save_as = i.consume_shortcut(&sc[Action::SaveAs]); // before Cmd+S
                do_save = i.consume_shortcut(&sc[Action::Save]);
                do_close = i.consume_shortcut(&sc[Action::Close]);
                do_redo = i.consume_shortcut(&sc[Action::Redo]); // before Cmd+Z
                do_undo = i.consume_shortcut(&sc[Action::Undo]);
                do_goto = i.consume_shortcut(&sc[Action::Goto]);
                do_selall = i.consume_shortcut(&sc[Action::SelectAll]);
                do_find = i.consume_shortcut(&sc[Action::Find]);
                do_find_prev = i.consume_shortcut(&sc[Action::FindPrev]); // before F3
                do_find_next = i.consume_shortcut(&sc[Action::FindNext]);
                act.next_diff = i.consume_shortcut(&sc[Action::NextDiff]);
            });
        }
        // Phase 8: preferences captured into locals, applied after the menu so
        // the menu closure never mutably borrows `self.prefs`.
        let recent = self.prefs.recent.clone();
        let mut open_recent: Option<PathBuf> = None;
        let mut clear_recent = false;
        let mut theme_pref = self.prefs.theme;
        let mut backup_pref = self.prefs.backup_before_save;
        let mut restore_pref = self.prefs.restore_session;
        let mut insert_def_pref = self.prefs.insert_default;
        let mut open_rebind = false;
        // Menu accelerator hints, from the live bindings (F-60) so they stay
        // correct after a rebind.
        let hint: [String; Action::ALL.len()] =
            std::array::from_fn(|i| shortcuts::symbol(&self.shortcuts.0[i]));

        // Menus.
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    do_new |= ui.button(format!("New\t{}", hint[Action::New.index()])).clicked();
                    do_open |= ui.button(format!("Open…\t{}", hint[Action::Open.index()])).clicked();
                    if ui.button("Open disk…").clicked() {
                        act.open_disk = true;
                    }
                    ui.menu_button("Open recent", |ui| {
                        if recent.is_empty() {
                            ui.weak("no recent files");
                        }
                        for p in &recent {
                            if ui.button(p.display().to_string()).clicked() {
                                open_recent = Some(p.clone());
                            }
                        }
                        if !recent.is_empty() {
                            ui.separator();
                            if ui.button("Clear").clicked() {
                                clear_recent = true;
                            }
                        }
                    });
                    ui.separator();
                    do_save |= ui.button(format!("Save\t{}", hint[Action::Save.index()])).clicked();
                    do_save_as |= ui.button(format!("Save as…\t{}", hint[Action::SaveAs.index()])).clicked();
                    if ui.button("Save selection as…").clicked() {
                        self.save_selection();
                    }
                    ui.separator();
                    // Phase 6 — F-27/F-27a/F-30/F-31.
                    if ui.button("Import Intel HEX / S-record…").clicked() {
                        act.import = true;
                    }
                    ui.menu_button("Export", |ui| {
                        if ui.button("Intel HEX…").clicked() {
                            self.tools.record_open = Some(RecordFormat::IntelHex);
                        }
                        if ui.button("Motorola S-record…").clicked() {
                            self.tools.record_open = Some(RecordFormat::Srec);
                        }
                        if ui.button("As text (report, code)…").clicked() {
                            self.tools.report_open = true;
                        }
                    });
                    ui.separator();
                    do_close |= ui.button(format!("Close tab\t{}", hint[Action::Close.index()])).clicked();
                });
                ui.menu_button("Edit", |ui| {
                    do_undo |= ui.button(format!("Undo\t{}", hint[Action::Undo.index()])).clicked();
                    do_redo |= ui.button(format!("Redo\t{}", hint[Action::Redo.index()])).clicked();
                    ui.separator();
                    if let Some(tab) = self.tabs.get_mut(self.active) {
                        if ui.button("Copy\t⌘ + C").clicked() {
                            tab.view.copy_selection(&mut tab.doc, ctx);
                        }
                        if ui.button("Cut\t⌘ + X").clicked() {
                            let ro = tab.read_only;
                            tab.view.cut_selection(&mut tab.doc, ro, ctx);
                        }
                        // F-38: the two paste modes, made explicit.
                        for (label, ins) in
                            [("Paste overwriting", false), ("Paste inserting", true)]
                        {
                            if ui.button(label).clicked() {
                                let ro = tab.read_only;
                                if let Some(s) = clipboard_text() {
                                    tab.view.paste(&mut tab.doc, ro, &s, ins);
                                }
                            }
                        }
                        // F-30: the selection as text, in a chosen format.
                        ui.menu_button("Copy as", |ui| {
                            for fmt in ExportFormat::ALL {
                                if ui.button(fmt.name()).clicked() {
                                    act.copy_as = Some(fmt);
                                }
                            }
                        });
                    }
                    ui.separator();
                    // Phase 3: search and replace.
                    do_find |= ui.button(format!("Find…\t{}", hint[Action::Find.index()])).clicked();
                    do_find_next |= ui.button(format!("Find next\t{}", hint[Action::FindNext.index()])).clicked();
                    do_find_prev |= ui.button(format!("Find previous\t{}", hint[Action::FindPrev.index()])).clicked();
                    ui.separator();
                    do_selall |= ui.button(format!("Select all\t{}", hint[Action::SelectAll.index()])).clicked();
                    // F-21: selection by range.
                    if ui.button("Select range…").clicked() {
                        self.select_open = true;
                    }
                    do_goto |= ui.button(format!("Go to offset…\t{}", hint[Action::Goto.index()])).clicked();
                    ui.separator();
                    // F-22: fill the selection.
                    if ui.button("Fill selection…").clicked() {
                        self.fill_open = true;
                    }
                    // F-23: a bookmark at the cursor or over the selection.
                    if ui.button("Add bookmark…").clicked() {
                        self.bm_open = true;
                    }
                });
                // Phase 4 — outside the active-tab borrow: the comparison
                // submenu needs to list every tab.
                ui.menu_button("Analyze", |ui| {
                    if ui.button("Hashes and checksums…").clicked() {
                        self.analyze.hash_open = true;
                    }
                    if ui.button("Extract strings…").clicked() {
                        self.analyze.strings_open = true;
                    }
                    if ui.button("Statistics…").clicked() {
                        self.analyze.stats_open = true;
                    }
                    act.magic |= ui.button("Signatures…").clicked();
                    ui.separator();
                    // F-32: byte-by-byte comparison with another tab.
                    ui.menu_button("Compare with", |ui| {
                        if self.tabs.len() < 2 {
                            ui.weak("open another tab to compare");
                        }
                        for i in 0..self.tabs.len() {
                            if i != self.active
                                && ui.button(&self.tabs[i].title).clicked()
                            {
                                self.compare = Some((self.active, i));
                                self.diff_job = None;
                            }
                        }
                    });
                    if self.compare.is_some() {
                        act.next_diff |= ui.button(format!("Next difference\t{}", hint[Action::NextDiff.index()])).clicked();
                        if ui.button("Stop comparison").clicked() {
                            self.compare = None;
                            self.diff_job = None;
                        }
                    }
                });
                // Phase 6 — F-57/F-58.
                ui.menu_button("Tools", |ui| {
                    // Fase 12 (F-80): CyberChef-style transform pipeline.
                    if ui.button("Recipe (transform)…").clicked() {
                        self.recipe.open = true;
                    }
                    ui.separator();
                    if ui.button("Split file into parts…").clicked() {
                        self.tools.split_open = true;
                    }
                    if ui.button("Concatenate files…").clicked() {
                        act.concat = true;
                    }
                    ui.separator();
                    if ui.button("Shred file…").clicked() {
                        act.shred = true; // F-45
                    }
                });
                if let Some(tab) = self.tabs.get_mut(self.active) {
                    // F-18/F-19/F-20 — all per tab, as in HxD.
                    ui.menu_button("View", |ui| {
                        ui.checkbox(&mut tab.inspector.open, "Data Inspector");
                        ui.checkbox(&mut self.bookmarks_open, "Bookmarks");
                        // F-72: the executable structure tree.
                        ui.checkbox(&mut self.structure.open, "Structure (executable)");
                        ui.separator();
                        ui.menu_button("Bytes per line", |ui| {
                            for n in COLS_CHOICES {
                                if ui
                                    .radio(tab.view.cols == n, n.to_string())
                                    .clicked()
                                {
                                    tab.view.cols = n;
                                }
                            }
                        });
                        ui.menu_button("Grouping", |ui| {
                            for n in GROUP_CHOICES {
                                if ui
                                    .radio(tab.view.group == n, format!("{n} byte(s)"))
                                    .clicked()
                                {
                                    tab.view.group = n;
                                }
                            }
                        });
                        ui.menu_button("Offset base", |ui| {
                            for base in OffsetBase::ALL {
                                if ui.radio(tab.view.offset_base == base, base.name()).clicked() {
                                    tab.view.offset_base = base;
                                }
                            }
                        });
                        ui.menu_button("Charset", |ui| {
                            for cs in Charset::ALL {
                                if ui.radio(tab.view.charset == cs, cs.name()).clicked() {
                                    tab.view.charset = cs;
                                }
                            }
                        });
                        if ui.button("Starting offset…").clicked() {
                            self.offstart_text = format!("{:#x}", tab.view.offset_start);
                            self.offstart_open = true;
                        }
                        // F-62 — theme (persisted).
                        ui.separator();
                        ui.menu_button("Theme", |ui| {
                            for t in Theme::ALL {
                                ui.radio_value(&mut theme_pref, t, t.label());
                            }
                        });
                    });
                    ui.menu_button("Mode", |ui| {
                        ui.checkbox(&mut tab.view.insert_mode, "Insert (Insert key)");
                        ui.checkbox(&mut tab.read_only, "Read-only");
                    });
                    // F-60/F-61/F-65 — persistent preferences.
                    ui.menu_button("Preferences", |ui| {
                        ui.checkbox(&mut backup_pref, "Back up before saving (.bak)");
                        ui.checkbox(&mut restore_pref, "Restore session on start");
                        ui.checkbox(&mut insert_def_pref, "New tabs start in insert mode");
                        ui.separator();
                        if ui.button("Keyboard shortcuts…").clicked() {
                            open_rebind = true;
                        }
                    });
                }
            });
        });

        // Phase 8: apply any preference changes made in the menus (F-60/F-62).
        let mut prefs_dirty = false;
        if theme_pref != self.prefs.theme {
            self.prefs.theme = theme_pref;
            self.apply_theme(ctx);
            prefs_dirty = true;
        }
        if backup_pref != self.prefs.backup_before_save {
            self.prefs.backup_before_save = backup_pref;
            prefs_dirty = true;
        }
        if restore_pref != self.prefs.restore_session {
            self.prefs.restore_session = restore_pref;
            prefs_dirty = true;
        }
        if insert_def_pref != self.prefs.insert_default {
            self.prefs.insert_default = insert_def_pref;
            prefs_dirty = true;
        }
        if clear_recent {
            self.prefs.recent.clear();
            prefs_dirty = true;
        }
        if prefs_dirty {
            self.save_prefs();
        }
        if open_rebind {
            self.rebind_open = true;
        }
        if let Some(p) = open_recent {
            self.open_path(p, ctx);
        }

        if do_new {
            self.untitled_seq += 1;
            let mut tab = Tab::untitled(self.untitled_seq);
            self.apply_view_defaults(&mut tab.view);
            self.tabs.push(tab);
            self.active = self.tabs.len() - 1;
        }
        if do_open {
            self.open_dialog(ctx);
        }
        if do_save {
            self.save_active(false);
        }
        if do_save_as {
            self.save_active(true);
        }
        if do_close && !self.tabs.is_empty() {
            self.request_close_tab(self.active);
        }
        if do_goto {
            self.goto_open = true;
        }
        // Phase 3: search.
        if do_find {
            self.search.open = true;
        }
        if do_find_next {
            self.search.start_next(&self.tabs, self.active, false);
        }
        if do_find_prev {
            self.search.start_next(&self.tabs, self.active, true);
        }
        if let Some(tab) = self.tabs.get_mut(self.active) {
            if do_undo {
                tab.view.end_typing();
                tab.doc.undo();
            }
            if do_redo {
                tab.view.end_typing();
                tab.doc.redo();
            }
            if do_selall {
                let len = tab.doc.len();
                tab.view.select_all(len);
            }
        }

        act
    }
}
