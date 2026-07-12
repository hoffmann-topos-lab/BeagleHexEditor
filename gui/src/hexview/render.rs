//! Drawing and input for the grid. `HexView` owns `top_row: u64` and its own
//! f64 scrollbar because egui's `ScrollArea` measures in f32 pixels — broken
//! beyond ~16M px. Never replace this with `ScrollArea::show_rows`.

use std::ops::Range;

use eframe::egui::{
    self, Align2, Color32, CursorIcon, Event, FontId, Key, Pos2, Rect, Sense, Stroke, Ui, Vec2,
};
use hexed_core::Document;

use super::{HexView, Pane};

impl HexView {
    pub fn show(&mut self, ui: &mut Ui, doc: &mut Document, read_only: bool) {
        let font = FontId::monospace(14.0);
        let char_w = ui.fonts(|f| f.glyph_width(&font, '0'));
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 3.0;

        let len = doc.len();
        let cols = self.cols.max(1);
        let group = self.group.clamp(1, cols);
        // +1: the cursor can sit at `len` (the append position).
        let rows_total = (len / cols) + 1;
        let off_digits = self.offset_base.digits_for(self.offset_start.saturating_add(len));

        // F-18: position, in characters, of byte `col` within the hex pane.
        // Each group takes 2·group digits + 1 separator space.
        let hex_chars_of =
            |col: u64| -> f32 { ((col / group) * (2 * group + 1) + 2 * (col % group)) as f32 };

        let x_off = 8.0;
        let x_hex = x_off + (off_digits as f32 + 2.0) * char_w;
        let hex_w = (hex_chars_of(cols - 1) + 3.0) * char_w;
        let x_text = x_hex + hex_w + 2.0 * char_w;
        let text_w = cols as f32 * char_w;
        let sb_w = 14.0;

        let avail = ui.available_size();
        let (rect, resp) = ui.allocate_exact_size(avail, Sense::click_and_drag());
        let painter = ui.painter_at(rect);
        let widget_id = resp.id;

        self.rows_visible = ((rect.height() / row_h).floor() as u64).max(1);
        let max_top = rows_total.saturating_sub(self.rows_visible);

        // -- wheel/trackpad scrolling (f32 is safe: the delta is per frame) --
        if resp.hovered() {
            self.scroll_accum += ui.input(|i| i.smooth_scroll_delta.y);
            let step = self.scroll_accum / row_h;
            if step.abs() >= 1.0 {
                let n = step.trunc();
                self.scroll_accum -= n * row_h;
                if n > 0.0 {
                    self.top_row = self.top_row.saturating_sub(n as u64);
                } else {
                    self.top_row = (self.top_row + (-n) as u64).min(max_top);
                }
            }
        }

        // -- click and drag: maps position → offset --
        if resp.clicked() || resp.drag_started() {
            resp.request_focus();
        }
        let hit = |pos: Pos2| -> Option<(u64, Pane)> {
            let row = self.top_row + ((pos.y - rect.top()) / row_h).floor().max(0.0) as u64;
            let x = pos.x - rect.left();
            if (x_hex - char_w..x_hex + hex_w).contains(&x) {
                // Inverts `hex_chars_of`: the group first, then the byte within it.
                let c = ((x - x_hex) / char_w).max(0.0);
                let g = (c / (2 * group + 1) as f32).floor() as u64;
                let within = c - (g * (2 * group + 1)) as f32;
                let k = ((within / 2.0).floor() as u64).min(group - 1);
                let col = (g * group + k).min(cols - 1);
                Some(((row * cols + col).min(len), Pane::Hex))
            } else if (x_text - char_w..x_text + text_w + char_w).contains(&x) {
                let col_txt = ((x - x_text) / char_w).floor();
                let col = (col_txt.max(0.0) as u64).min(cols - 1);
                Some(((row * cols + col).min(len), Pane::Text))
            } else {
                None
            }
        };
        if let Some(pos) = resp.interact_pointer_pos()
            && pos.x < rect.right() - sb_w
            && let Some((off, pane)) = hit(pos)
        {
            let extend = resp.dragged() && !resp.drag_started()
                || ui.input(|i| i.modifiers.shift);
            self.pane = pane;
            self.move_cursor(off, extend);
        }

        // -- keyboard --
        if resp.has_focus() {
            self.handle_keys(ui, doc, read_only, len);
        }

        // -- keep the cursor visible --
        if self.scroll_to_cursor {
            self.scroll_to_cursor = false;
            let crow = self.cursor / cols;
            if crow < self.top_row {
                self.top_row = crow;
            } else if crow >= self.top_row + self.rows_visible {
                self.top_row = crow + 1 - self.rows_visible;
            }
        }
        self.top_row = self.top_row.min(max_top);

        // -- single read of what is on screen --
        let first_byte = self.top_row * cols;
        let want = (self.rows_visible * cols).min(len.saturating_sub(first_byte)) as usize;
        let read = doc.read(first_byte, want);
        let modified = doc.modified_in(first_byte..first_byte + want as u64);
        let sel = self.selection();
        // F-20: one display cell per byte, in the active charset.
        let cells = self.charset.decode_cells(first_byte, &read.data);

        // -- colours --
        let v = ui.visuals();
        let col_bg_sel = v.selection.bg_fill.gamma_multiply(0.55);
        let col_modified = Color32::from_rgb(196, 92, 32).gamma_multiply(0.35); // F-41
        let col_bad = Color32::from_rgb(180, 40, 40).gamma_multiply(0.45);
        let col_inspect = Color32::from_rgb(60, 140, 220).gamma_multiply(0.35); // F-16
        let col_text = v.text_color();
        let col_dim = v.weak_text_color();
        let col_cursor = v.selection.stroke.color;

        let byte_rect = |off: u64, pane: Pane| -> Rect {
            let row = (off / cols - self.top_row) as f32;
            let col = off % cols;
            let y = rect.top() + row * row_h;
            match pane {
                Pane::Hex => {
                    let x = rect.left() + x_hex + hex_chars_of(col) * char_w;
                    Rect::from_min_size(Pos2::new(x, y), Vec2::new(2.0 * char_w, row_h))
                }
                Pane::Text => {
                    let x = rect.left() + x_text + col as f32 * char_w;
                    Rect::from_min_size(Pos2::new(x, y), Vec2::new(char_w, row_h))
                }
            }
        };

        // Per-byte background: selection, inspector highlight (F-16), modified
        // (F-41), unreadable (F-06).
        let paint_ranges = |ranges: &[Range<u64>], color: Color32| {
            for r in ranges {
                let (s, e) = (r.start.max(first_byte), r.end.min(first_byte + want as u64));
                let mut off = s;
                while off < e {
                    let row_end = (off / cols + 1) * cols;
                    let run_end = e.min(row_end);
                    for pane in [Pane::Hex, Pane::Text] {
                        let a = byte_rect(off, pane);
                        let b = byte_rect(run_end - 1, pane);
                        painter.rect_filled(a.union(b), 2.0, color);
                    }
                    off = run_end;
                }
            }
        };
        if let Some(s) = &sel {
            paint_ranges(std::slice::from_ref(s), col_bg_sel);
        }
        if let Some(h) = &self.highlight {
            paint_ranges(std::slice::from_ref(h), col_inspect);
        }
        // F-32: bytes that differ in the comparison (violet, distinct from everything).
        paint_ranges(&self.diff, Color32::from_rgb(150, 70, 200).gamma_multiply(0.35));
        paint_ranges(&modified, col_modified);
        paint_ranges(&read.unreadable, col_bad);

        // Cursor: filled in the active pane, outlined in the other (F-12).
        if self.cursor >= first_byte && self.cursor <= first_byte + want as u64 {
            let coff = self.cursor.min(len.saturating_sub(1));
            if len > 0 || self.cursor == 0 {
                let active = byte_rect(coff.min(self.cursor), self.pane);
                let other = byte_rect(
                    coff.min(self.cursor),
                    if self.pane == Pane::Hex { Pane::Text } else { Pane::Hex },
                );
                painter.rect_filled(active, 2.0, col_cursor.gamma_multiply(0.5));
                painter.rect_stroke(other, 2.0, Stroke::new(1.0, col_cursor), egui::StrokeKind::Inside);
                if self.nibble_low && self.pane == Pane::Hex {
                    // Underlines the low half of the byte being edited.
                    let half = Rect::from_min_max(active.center_top(), active.right_bottom());
                    painter.rect_filled(half, 0.0, col_cursor.gamma_multiply(0.35));
                }
            }
        }

        // Row text.
        let is_bad = |off: u64| read.unreadable.iter().any(|r| r.contains(&off));
        for vrow in 0..self.rows_visible {
            let row_off = (self.top_row + vrow) * cols;
            if row_off > len {
                break;
            }
            let y = rect.top() + vrow as f32 * row_h;
            painter.text(
                Pos2::new(rect.left() + x_off, y),
                Align2::LEFT_TOP,
                self.offset_base.format(self.offset_start.saturating_add(row_off), off_digits),
                font.clone(),
                col_dim,
            );

            let in_row = ((len.saturating_sub(row_off)).min(cols)) as usize;
            let base = (row_off - first_byte) as usize;
            let mut hex = String::with_capacity(cols as usize * 3 + 8);
            for i in 0..in_row {
                let off = row_off + i as u64;
                let b = read.data[base + i];
                if is_bad(off) {
                    hex.push_str("??");
                } else {
                    hex.push_str(&format!("{b:02X}"));
                }
                if (i as u64 + 1).is_multiple_of(group) {
                    hex.push(' ');
                }
            }
            painter.text(
                Pos2::new(rect.left() + x_hex, y),
                Align2::LEFT_TOP,
                hex,
                font.clone(),
                col_text,
            );
            // Text pane: one cell per byte, drawn individually so that wide
            // characters (CJK, CP437 symbols) do not misalign the columns.
            for i in 0..in_row {
                let off = row_off + i as u64;
                let c = if is_bad(off) { '?' } else { cells[base + i] };
                painter.text(
                    Pos2::new(rect.left() + x_text + i as f32 * char_w, y),
                    Align2::LEFT_TOP,
                    c,
                    font.clone(),
                    col_text,
                );
            }
        }

        // -- own scrollbar (f64: must work with billions of rows) --
        if rows_total > self.rows_visible {
            let track = Rect::from_min_max(
                Pos2::new(rect.right() - sb_w, rect.top()),
                rect.right_bottom(),
            );
            let frac_vis = self.rows_visible as f64 / rows_total as f64;
            let thumb_h = (track.height() as f64 * frac_vis).max(24.0) as f32;
            let frac_pos = if max_top == 0 { 0.0 } else { self.top_row as f64 / max_top as f64 };
            let thumb_y = track.top() + frac_pos as f32 * (track.height() - thumb_h);
            let thumb = Rect::from_min_size(
                Pos2::new(track.left() + 2.0, thumb_y),
                Vec2::new(sb_w - 4.0, thumb_h),
            );

            let sb_resp = ui.interact(track, widget_id.with("sb"), Sense::click_and_drag());
            if sb_resp.dragged() || sb_resp.clicked() {
                if let Some(pos) = sb_resp.interact_pointer_pos() {
                    let f = ((pos.y - track.top() - thumb_h / 2.0)
                        / (track.height() - thumb_h).max(1.0))
                    .clamp(0.0, 1.0) as f64;
                    self.top_row = (f * max_top as f64).round() as u64;
                }
                ui.ctx().set_cursor_icon(CursorIcon::Grabbing);
            }
            painter.rect_filled(track, 0.0, v.faint_bg_color);
            painter.rect_filled(thumb, 4.0, v.widgets.inactive.bg_fill);
        }
    }

    fn handle_keys(&mut self, ui: &mut Ui, doc: &mut Document, read_only: bool, len: u64) {
        let cols = self.cols.max(1);
        let events = ui.input(|i| i.events.clone());
        for ev in events {
            match ev {
                Event::Key { key, pressed: true, modifiers, .. } if !modifiers.command => {
                    let extend = modifiers.shift;
                    let c = self.cursor;
                    match key {
                        Key::ArrowLeft => self.move_cursor(c.saturating_sub(1), extend),
                        Key::ArrowRight => self.move_cursor((c + 1).min(doc.len()), extend),
                        Key::ArrowUp => self.move_cursor(c.saturating_sub(cols), extend),
                        Key::ArrowDown => self.move_cursor((c + cols).min(doc.len()), extend),
                        Key::PageUp => {
                            let d = self.rows_visible * cols;
                            self.top_row = self.top_row.saturating_sub(self.rows_visible);
                            self.move_cursor(c.saturating_sub(d), extend);
                        }
                        Key::PageDown => {
                            let d = self.rows_visible * cols;
                            self.move_cursor((c + d).min(doc.len()), extend);
                        }
                        Key::Home => self.move_cursor(c - c % cols, extend),
                        Key::End => {
                            self.move_cursor(((c - c % cols) + cols - 1).min(doc.len()), extend)
                        }
                        Key::Tab => {
                            self.pane =
                                if self.pane == Pane::Hex { Pane::Text } else { Pane::Hex };
                            self.end_typing();
                        }
                        Key::Escape => self.anchor = None,
                        Key::Backspace => {
                            if let Some(sel) = self.selection() {
                                self.delete_range(doc, read_only, sel);
                            } else if c > 0 {
                                if self.insert_mode {
                                    self.delete_range(doc, read_only, c - 1..c);
                                } else {
                                    self.move_cursor(c - 1, false);
                                }
                            }
                        }
                        Key::Delete => {
                            if let Some(sel) = self.selection() {
                                self.delete_range(doc, read_only, sel);
                            } else if c < doc.len() {
                                self.delete_range(doc, read_only, c..c + 1);
                            }
                        }
                        Key::Insert => self.insert_mode = !self.insert_mode, // F-34
                        _ => {}
                    }
                }
                Event::Key { key, pressed: true, modifiers, .. } if modifiers.command => {
                    match key {
                        Key::Home => self.move_cursor(0, modifiers.shift),
                        Key::End => self.move_cursor(len, modifiers.shift),
                        _ => {}
                    }
                }
                Event::Text(s) => match self.pane {
                    Pane::Hex => {
                        for ch in s.chars() {
                            if let Some(d) = ch.to_digit(16) {
                                self.type_hex_digit(doc, read_only, d as u8);
                            }
                        }
                    }
                    Pane::Text => self.type_text(doc, read_only, &s),
                },
                // Cmd+C/X/V arrive as egui's own events.
                Event::Copy => self.copy_selection(doc, ui.ctx()),
                Event::Cut => self.cut_selection(doc, read_only, ui.ctx()),
                Event::Paste(s) => {
                    let ins = self.insert_mode;
                    self.paste(doc, read_only, &s, ins);
                }
                _ => {}
            }
        }
    }
}
