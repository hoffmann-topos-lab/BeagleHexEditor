//! The hex grid: view/edit state and editing policy. Drawing and input live in
//! `render`.

mod render;

use eframe::egui;
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
