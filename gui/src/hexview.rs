use eframe::egui::{
    self, Align2, Color32, CursorIcon, Event, FontId, Key, Pos2, Rect, Sense, Stroke, Ui, Vec2,
};
use hexed_core::{Charset, Document, OffsetBase};
use std::ops::Range;

/// Copy limit for the clipboard (F-38).
const MAX_CLIPBOARD: u64 = 16 * 1024 * 1024;

/// F-18 — Options offered in the View menu.
pub const COLS_CHOICES: [u64; 6] = [8, 16, 24, 32, 48, 64];
pub const GROUP_CHOICES: [u64; 5] = [1, 2, 4, 8, 16];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Hex,
    Text,
}

/// View and edit state of a tab. The policy (grouping typing, interpreting a
/// paste) lives here; the mechanics live in the `Document`.
pub struct HexView {
    pub top_row: u64,
    pub cursor: u64,
    pub anchor: Option<u64>,
    pub pane: Pane,
    /// F-34: false = overwrite, true = insert.
    pub insert_mode: bool,
    pub status: String,
    /// F-18: bytes per line.
    pub cols: u64,
    /// F-18: bytes per group in the hex pane (1/2/4/8/16).
    pub group: u64,
    /// F-19: display base of the offset column.
    pub offset_base: OffsetBase,
    /// F-19: added to every displayed offset (the document stays at 0).
    pub offset_start: u64,
    /// F-20: charset of the text pane.
    pub charset: Charset,
    /// F-16: range highlighted by the Data Inspector (bytes covered by the
    /// field under the mouse). Reset each frame by whoever uses it.
    pub highlight: Option<Range<u64>>,
    /// F-32: bytes that differ from the compared document (visible window).
    /// Reset each frame by the comparison mode.
    pub diff: Vec<Range<u64>>,
    /// Typing in the hex pane: the next digit completes the low nibble.
    nibble_low: bool,
    /// F-39: offset where the next edit would continue the typing run.
    typing_next: Option<u64>,
    scroll_accum: f32,
    scroll_to_cursor: bool,
    rows_visible: u64,
}

impl Default for HexView {
    fn default() -> Self {
        Self {
            top_row: 0,
            cursor: 0,
            anchor: None,
            pane: Pane::Hex,
            insert_mode: false,
            status: String::new(),
            cols: 16,
            group: 8,
            offset_base: OffsetBase::Hex,
            offset_start: 0,
            charset: Charset::Ascii,
            highlight: None,
            diff: Vec::new(),
            nibble_low: false,
            typing_next: None,
            scroll_accum: 0.0,
            scroll_to_cursor: false,
            rows_visible: 1,
        }
    }
}

impl HexView {
    pub fn selection(&self) -> Option<Range<u64>> {
        let a = self.anchor?;
        if a == self.cursor {
            return None;
        }
        Some(a.min(self.cursor)..a.max(self.cursor))
    }

    /// F-13: moves the cursor and keeps it visible.
    pub fn goto(&mut self, offset: u64, doc_len: u64) {
        self.cursor = offset.min(doc_len);
        self.anchor = None;
        self.end_typing();
        self.scroll_to_cursor = true;
    }

    /// F-21: selects a range and brings the cursor to it.
    pub fn select_range(&mut self, range: Range<u64>, doc_len: u64) {
        let start = range.start.min(doc_len);
        let end = range.end.min(doc_len);
        self.anchor = Some(start);
        self.cursor = end;
        self.end_typing();
        self.scroll_to_cursor = true;
    }

    /// The byte range currently on screen (for the visible diff, F-32).
    pub fn visible_range(&self, doc_len: u64) -> Range<u64> {
        let first = (self.top_row * self.cols).min(doc_len);
        let want = (self.rows_visible * self.cols).min(doc_len - first);
        first..first + want
    }

    /// Ends the typing run (F-39). Called by the UI on save, undo or navigate
    /// — runs never group across those boundaries.
    pub fn end_typing(&mut self) {
        self.typing_next = None;
        self.nibble_low = false;
    }

    fn move_cursor(&mut self, to: u64, extend: bool) {
        if extend {
            self.anchor.get_or_insert(self.cursor);
        } else {
            self.anchor = None;
        }
        self.cursor = to;
        self.end_typing();
        self.scroll_to_cursor = true;
    }

    /// Does it continue the typing run? If so, the just-committed transaction
    /// is merged with the previous one.
    fn commit_typing(&mut self, doc: &mut Document, next: u64) {
        if self.typing_next == Some(self.cursor) {
            doc.merge_with_previous();
        }
        self.typing_next = Some(next);
    }

    // ---- editing (F-35/36/37 via core; policy here) ----

    fn type_hex_digit(&mut self, doc: &mut Document, read_only: bool, d: u8) {
        if read_only {
            self.status = "read-only".into();
            return;
        }
        self.anchor = None;
        let cur = self.cursor;
        let old = if cur < doc.len() { doc.read(cur, 1).data[0] } else { 0 };

        if !self.nibble_low {
            // High nibble: creates the byte's edit.
            let b = d << 4 | (old & 0x0F);
            let r = if self.insert_mode && cur <= doc.len() {
                doc.insert(cur, &[d << 4])
            } else {
                doc.overwrite(cur, &[b])
            };
            match r {
                Ok(()) => {
                    self.commit_typing(doc, cur);
                    self.nibble_low = true;
                }
                Err(e) => self.status = e.to_string(),
            }
        } else {
            // Low nibble: completes the byte and advances. Merges with the high nibble.
            let cur_byte = doc.read(cur, 1).data[0];
            match doc.overwrite(cur, &[(cur_byte & 0xF0) | d]) {
                Ok(()) => {
                    doc.merge_with_previous();
                    self.nibble_low = false;
                    self.cursor = cur + 1;
                    self.typing_next = Some(self.cursor);
                    self.scroll_to_cursor = true;
                }
                Err(e) => self.status = e.to_string(),
            }
        }
    }

    fn type_text(&mut self, doc: &mut Document, read_only: bool, s: &str) {
        if read_only {
            self.status = "read-only".into();
            return;
        }
        self.anchor = None;
        let bytes = s.as_bytes();
        let cur = self.cursor;
        let r = if self.insert_mode {
            doc.insert(cur, bytes)
        } else {
            doc.overwrite(cur, bytes)
        };
        match r {
            Ok(()) => {
                self.commit_typing(doc, cur + bytes.len() as u64);
                self.cursor = cur + bytes.len() as u64;
                self.scroll_to_cursor = true;
            }
            Err(e) => self.status = e.to_string(),
        }
    }

    fn delete_range(&mut self, doc: &mut Document, read_only: bool, r: Range<u64>) {
        if read_only {
            self.status = "read-only".into();
            return;
        }
        match doc.delete(r.start, r.end - r.start) {
            Ok(()) => {
                self.cursor = r.start;
                self.anchor = None;
                self.end_typing();
                self.scroll_to_cursor = true;
            }
            Err(e) => self.status = e.to_string(),
        }
    }

    // ---- F-38: clipboard ----

    pub fn copy_selection(&mut self, doc: &mut Document, ctx: &egui::Context) {
        let Some(sel) = self.selection() else {
            self.status = "nothing selected".into();
            return;
        };
        if sel.end - sel.start > MAX_CLIPBOARD {
            self.status = format!("selection above {} MiB", MAX_CLIPBOARD >> 20);
            return;
        }
        let r = doc.read(sel.start, (sel.end - sel.start) as usize);
        let text = match self.pane {
            Pane::Hex => {
                let mut s = String::with_capacity(r.data.len() * 3);
                for (i, b) in r.data.iter().enumerate() {
                    if i > 0 {
                        s.push(' ');
                    }
                    s.push_str(&format!("{b:02X}"));
                }
                s
            }
            // In the text pane, copy the bytes as characters (lossy).
            Pane::Text => String::from_utf8_lossy(&r.data).into_owned(),
        };
        ctx.copy_text(text);
        self.status = format!("{} byte(s) copied", r.data.len());
    }

    pub fn cut_selection(&mut self, doc: &mut Document, read_only: bool, ctx: &egui::Context) {
        let Some(sel) = self.selection() else { return };
        self.copy_selection(doc, ctx);
        self.delete_range(doc, read_only, sel);
    }

    /// Paste: in the hex pane the text is interpreted as hexadecimal bytes;
    /// in the text pane, as UTF-8. `insert` chooses between paste-inserting and
    /// paste-overwriting (F-38).
    pub fn paste(&mut self, doc: &mut Document, read_only: bool, s: &str, insert: bool) {
        if read_only {
            self.status = "read-only".into();
            return;
        }
        let bytes: Vec<u8> = match self.pane {
            Pane::Hex => match parse_hex(s) {
                Some(b) => b,
                None => {
                    self.status = "the paste is not valid hexadecimal".into();
                    return;
                }
            },
            Pane::Text => s.as_bytes().to_vec(),
        };
        if bytes.is_empty() {
            return;
        }
        // Pasting over a selection replaces the selection.
        if let Some(sel) = self.selection() {
            self.delete_range(doc, read_only, sel);
            if let Err(e) = doc.insert(self.cursor, &bytes) {
                self.status = e.to_string();
                return;
            }
            doc.merge_with_previous();
        } else {
            let r = if insert {
                doc.insert(self.cursor, &bytes)
            } else {
                doc.overwrite(self.cursor, &bytes)
            };
            if let Err(e) = r {
                self.status = e.to_string();
                return;
            }
        }
        self.cursor += bytes.len() as u64;
        self.end_typing();
        self.scroll_to_cursor = true;
        self.status = format!("{} byte(s) pasted", bytes.len());
    }

    pub fn select_all(&mut self, doc_len: u64) {
        self.anchor = Some(0);
        self.cursor = doc_len;
        self.end_typing();
    }

    // ---- drawing and input ----

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

/// Accepts "DE AD BE EF", "DEADBEEF", with line breaks etc.
pub(crate) fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() || !clean.len().is_multiple_of(2) {
        return None;
    }
    clean
        .as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

/// F-13: absolute offsets ("1000", "0x1F4") and relative ("+100", "-0x40").
pub fn parse_goto(s: &str, current: u64, len: u64) -> Option<u64> {
    let s = s.trim();
    let (sign, rest) = match s.as_bytes().first()? {
        b'+' => (1i8, &s[1..]),
        b'-' => (-1i8, &s[1..]),
        _ => (0, s),
    };
    let rest = rest.trim();
    let n = match rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok()?,
        None => rest.parse::<u64>().ok()?,
    };
    let target = match sign {
        1 => current.saturating_add(n),
        -1 => current.checked_sub(n)?,
        _ => n,
    };
    Some(target.min(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_goto_absolute_and_relative() {
        assert_eq!(parse_goto("0x40", 0, 1000), Some(0x40));
        assert_eq!(parse_goto("100", 0, 1000), Some(100));
        assert_eq!(parse_goto("+0x10", 32, 1000), Some(48));
        assert_eq!(parse_goto("-16", 32, 1000), Some(16));
        assert_eq!(parse_goto("-64", 32, 1000), None, "before the start");
        assert_eq!(parse_goto("5000", 0, 1000), Some(1000), "clamps at the end");
        assert_eq!(parse_goto("xyz", 0, 1000), None);
    }

    #[test]
    fn parse_hex_is_flexible() {
        assert_eq!(parse_hex("DE AD"), Some(vec![0xDE, 0xAD]));
        assert_eq!(parse_hex("dead"), Some(vec![0xDE, 0xAD]));
        assert_eq!(parse_hex("DE\nAD"), Some(vec![0xDE, 0xAD]));
        assert_eq!(parse_hex("DEA"), None);
        assert_eq!(parse_hex(""), None);
        assert_eq!(parse_hex("zz"), None);
    }
}
