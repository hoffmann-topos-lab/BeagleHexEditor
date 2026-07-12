//! The disk picker, the shred confirmation and the shortcut-rebind dialog.

use eframe::egui::{self, Align2, Key};

use crate::shortcuts::{self, Action, Shortcuts};
use crate::util::{capture_combo, human_size};

use super::App;

impl App {
    /// F-48/F-49/F-51 — The disk picker: pick a device to open read-only.
    /// A mounted volume is flagged (F-51 — writing it is blocked until it is
    /// unmounted; for now disks open read-only anyway).
    pub(super) fn show_disk_picker(&mut self, ctx: &egui::Context) {
        if !self.disk_picker_open {
            return;
        }
        let mut open = true;
        let mut chosen: Option<usize> = None;
        egui::Window::new("Open disk")
            .open(&mut open)
            .default_width(560.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Devices open read-only. Raw access needs privilege (sudo / helper).");
                if ui.button("↻ Refresh").clicked() {
                    match hexed_core::disks::enumerate() {
                        Ok(list) => self.disk_list = list,
                        Err(e) => self.global_status = format!("could not list disks: {e}"),
                    }
                }
                ui.separator();
                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::vertical().max_height(340.0).show_rows(
                    ui,
                    row_h,
                    self.disk_list.len(),
                    |ui, rows| {
                        for i in rows {
                            let d = &self.disk_list[i];
                            let indent = if d.whole { "" } else { "    " };
                            let mount = d
                                .mount_point
                                .as_ref()
                                .map(|m| format!("  ⚠ mounted at {}", m.display()))
                                .unwrap_or_default();
                            let label = format!(
                                "{indent}{:<12} {:>13}  {:>4}B  {}{mount}",
                                d.id,
                                human_size(d.size),
                                d.block_size,
                                if d.model.is_empty() { "—" } else { &d.model },
                            );
                            if ui
                                .selectable_label(false, egui::RichText::new(label).monospace())
                                .clicked()
                            {
                                chosen = Some(i);
                            }
                        }
                    },
                );
            });
        self.disk_picker_open = open;
        if let Some(i) = chosen {
            let info = self.disk_list[i].clone();
            self.open_disk(&info);
        }
    }

    /// F-45 — The shred confirmation. The warning is not dismissable: the button
    /// stays disabled until the user checks the acknowledgement.
    pub(super) fn show_shred_dialog(&mut self, ctx: &egui::Context) {
        let Some(path) = self.shred_path.clone() else { return };
        let mut open = true;
        let mut go = false;
        egui::Window::new("Shred file")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(egui::RichText::new(format!("Permanently shred:\n{}", path.display())).strong());
                ui.add_space(4.0);
                ui.colored_label(egui::Color32::from_rgb(200, 80, 40), format!("⚠ {}", hexed_core::shred::WARNING));
                ui.add_space(4.0);
                ui.checkbox(&mut self.shred_ack, "I understand this may not destroy the data");
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.shred_ack, egui::Button::new("Shred and delete"))
                        .clicked()
                    {
                        go = true;
                    }
                    if ui.button("Cancel").clicked() {
                        self.shred_path = None;
                    }
                });
            });
        if !open {
            self.shred_path = None;
        }
        if go {
            let status = match hexed_core::shred_file(&path, 1, true, &hexed_core::Progress::new()) {
                Ok(()) => format!("shredded and deleted {}", path.display()),
                Err(e) => format!("shred failed: {e}"),
            };
            self.global_status = status;
            self.shred_path = None;
        }
    }

    /// F-60 — Rebind keyboard shortcuts. "Rebind" starts recording; the next key
    /// combination is captured (Esc cancels). Changes persist immediately.
    pub(super) fn show_rebind_dialog(&mut self, ctx: &egui::Context) {
        if !self.rebind_open {
            return;
        }
        let mut open = true;
        let mut changed = false;
        let mut reset_all = false;
        egui::Window::new("Keyboard shortcuts")
            .open(&mut open)
            .default_width(380.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                if let Some(action) = self.rebind_recording {
                    ui.label(
                        egui::RichText::new(format!(
                            "Press a key combination for “{}” — Esc to cancel",
                            action.label()
                        ))
                        .strong(),
                    );
                    if ctx.input(|i| i.key_pressed(Key::Escape)) {
                        self.rebind_recording = None;
                    } else if let Some(sc) = capture_combo(ctx) {
                        self.shortcuts.0[action.index()] = sc;
                        self.prefs
                            .shortcuts
                            .insert(action.config_key().to_string(), shortcuts::format(&sc));
                        self.rebind_recording = None;
                        changed = true;
                    }
                }
                ui.separator();
                egui::Grid::new("shortcuts").num_columns(3).spacing([12.0, 4.0]).show(ui, |ui| {
                    for a in Action::ALL {
                        ui.label(a.label());
                        ui.monospace(shortcuts::format(&self.shortcuts[a]));
                        ui.horizontal(|ui| {
                            let recording = self.rebind_recording == Some(a);
                            if ui.selectable_label(recording, "Rebind").clicked() {
                                self.rebind_recording = Some(a);
                            }
                            if ui.small_button("Reset").clicked() {
                                self.shortcuts.0[a.index()] = a.default_shortcut();
                                self.prefs.shortcuts.remove(a.config_key());
                                changed = true;
                            }
                        });
                        ui.end_row();
                    }
                });
                ui.separator();
                if ui.button("Reset all to defaults").clicked() {
                    reset_all = true;
                }
            });
        self.rebind_open = open;
        if !open {
            self.rebind_recording = None;
        }
        if reset_all {
            self.shortcuts = Shortcuts::default();
            self.prefs.shortcuts.clear();
            changed = true;
        }
        if changed {
            self.save_prefs();
        }
    }
}
