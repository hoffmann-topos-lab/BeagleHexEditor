
use eframe::egui::{self, Key, TextEdit, TextStyle, Ui};
use hexed_core::inspector::{Endian, FieldKind};
use hexed_core::Document;

use crate::hexview::HexView;

/// Window read from the cursor: covers the largest field (GUID: 16 bytes;
/// NUL string: up to 256).
const WINDOW: usize = 512;

pub struct InspectorPanel {
    pub open: bool,
    /// F-17: the document's global endianness.
    global: Endian,
    /// F-17: effective per-field endianness. Toggling the global resets them all.
    per_field: [Endian; FieldKind::ALL.len()],
    /// Index of the field being edited and the text typed so far.
    editing: Option<(usize, String)>,
}

impl Default for InspectorPanel {
    fn default() -> Self {
        Self {
            open: true,
            global: Endian::Little,
            per_field: [Endian::Little; FieldKind::ALL.len()],
            editing: None,
        }
    }
}

impl InspectorPanel {
    fn set_global(&mut self, endian: Endian) {
        self.global = endian;
        self.per_field = [endian; FieldKind::ALL.len()];
    }

    /// Draws the panel. Writes edits into the document and uses `view` for
    /// the cursor, the active charset, the highlight and the status bar.
    pub fn show(&mut self, ui: &mut Ui, doc: &mut Document, view: &mut HexView, read_only: bool) {
        let cursor = view.cursor;
        let window = doc.read(cursor, WINDOW);

        ui.horizontal(|ui| {
            ui.label("Endianness:");
            if ui.selectable_label(self.global == Endian::Little, "LE").clicked() {
                self.set_global(Endian::Little);
            }
            if ui.selectable_label(self.global == Endian::Big, "BE").clicked() {
                self.set_global(Endian::Big);
            }
        });
        if !window.is_clean() {
            ui.colored_label(
                egui::Color32::from_rgb(180, 40, 40),
                "⚠ unreadable bytes in the window: values are suspect",
            );
        }
        ui.separator();

        let mut commit: Option<(FieldKind, Endian, String)> = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("inspector_grid").num_columns(3).spacing([6.0, 2.0]).show(ui, |ui| {
                for (i, kind) in FieldKind::ALL.into_iter().enumerate() {
                    let endian = self.per_field[i];
                    let decoded = kind.decode(&window.data, endian, view.charset);

                    ui.label(kind.label());

                    let is_editing = matches!(&self.editing, Some((j, _)) if *j == i);
                    let mut text = if is_editing {
                        self.editing.as_ref().unwrap().1.clone()
                    } else {
                        match &decoded {
                            Ok((s, _)) => s.clone(),
                            Err(e) => format!("— {e}"),
                        }
                    };
                    let editable = kind.editable() && decoded.is_ok() && !read_only;
                    let resp = ui.add(
                        TextEdit::singleline(&mut text)
                            .interactive(editable)
                            .desired_width(200.0)
                            .font(TextStyle::Monospace),
                    );

                    if editable {
                        if resp.changed() || resp.gained_focus() {
                            self.editing = Some((i, text.clone()));
                        }
                        if is_editing && resp.lost_focus() {
                            if ui.input(|inp| inp.key_pressed(Key::Enter)) {
                                commit = Some((kind, endian, text.clone()));
                            }
                            self.editing = None; // Esc / click-away discard
                        }
                    }

                    // Highlight in the grid: the bytes this field covers (F-16).
                    if (resp.hovered() || resp.has_focus())
                        && let Ok((_, consumed)) = &decoded
                    {
                        view.highlight = Some(cursor..cursor + *consumed as u64);
                    }

                    // F-17: per-field endianness toggle.
                    if kind.uses_endian() {
                        let tag = match endian {
                            Endian::Little => "LE",
                            Endian::Big => "BE",
                        };
                        if ui.small_button(tag).on_hover_text("toggle only this field").clicked()
                        {
                            self.per_field[i] = match endian {
                                Endian::Little => Endian::Big,
                                Endian::Big => Endian::Little,
                            };
                        }
                    } else {
                        ui.label("");
                    }

                    ui.end_row();
                }
            });
        });

        // In-place editing: the field's bytes overwrite from the cursor.
        if let Some((kind, endian, text)) = commit {
            match kind.encode(&text, endian, view.charset) {
                Ok(bytes) => {
                    view.end_typing(); // never merge with the grid's typing
                    match doc.overwrite(cursor, &bytes) {
                        Ok(()) => {
                            view.status =
                                format!("{}: {} byte(s) written", kind.label(), bytes.len());
                        }
                        Err(e) => view.status = e.to_string(),
                    }
                }
                Err(e) => view.status = format!("{}: {e}", kind.label()),
            }
        }
    }
}
