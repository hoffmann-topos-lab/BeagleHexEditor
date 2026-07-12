//! Phase 3 — search/replace state and job setup. The per-frame execution
//! lives in `drive`, the bar and results list in `ui`.

mod drive;
mod ui;

use hexed_core::search::{self, Pattern, Searcher};
use hexed_core::{Endian, Progress};

use crate::app::Tab;

/// Bytes scanned per frame. 16 MiB ≈ a few ms per frame and ~1 GB/s.
const FRAME_BUDGET: u64 = 16 << 20;
/// Cap on the GUI's results list (F-15b).
const MAX_RESULTS: usize = 10_000;

const TYPED_KINDS: [&str; 13] =
    ["i8", "u8", "i16", "u16", "i24", "u24", "i32", "u32", "i64", "u64", "f16", "f32", "f64"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Hex,
    Text,
    Typed,
}

/// One match in the results list (F-15b).
struct Hit {
    tab: usize,
    at: u64,
    len: u64,
}

enum JobKind {
    Next { backward: bool },
    All,
    ReplaceAll { replacement: Vec<u8>, count: u64 },
}

/// A search in progress: one core window per `drive` call.
struct Job {
    kind: JobKind,
    tab: usize,
    searcher: Searcher,
    pattern: Pattern,
    /// End of the search range; replacements shift it (F-28).
    range_end: u64,
    /// Tabs not yet scanned (F-15c, only for "Find all").
    queue: Vec<usize>,
    progress: Progress,
}

pub struct SearchState {
    pub open: bool,
    mode: Mode,
    pattern_text: String,
    replace_text: String,
    typed_kind: usize,
    typed_tol: String,
    big_endian: bool,
    ci: bool,
    wrap: bool,
    in_selection: bool,
    all_tabs: bool,
    status: String,
    results: Vec<Hit>,
    results_open: bool,
    job: Option<Job>,
}

impl Default for SearchState {
    fn default() -> Self {
        Self {
            open: false,
            mode: Mode::Hex,
            pattern_text: String::new(),
            replace_text: String::new(),
            typed_kind: 6, // i32, the most common guess in savegames
            typed_tol: String::new(),
            big_endian: false,
            ci: false,
            wrap: true,
            in_selection: false,
            all_tabs: false,
            status: String::new(),
            results: Vec::new(),
            results_open: false,
            job: None,
        }
    }
}

impl SearchState {
    fn endian(&self) -> Endian {
        if self.big_endian { Endian::Big } else { Endian::Little }
    }

    /// Builds the `Pattern` from the fields; errors become the status.
    fn build_pattern(&self, tab: &Tab) -> Result<Pattern, String> {
        match self.mode {
            Mode::Hex => Pattern::parse_hex(&self.pattern_text)
                .ok_or("invalid hex pattern (wildcards: ??, D?)".into()),
            Mode::Text => Pattern::text(&self.pattern_text, tab.view.charset, self.ci)
                .ok_or(format!("text not representable in {}", tab.view.charset.name())),
            Mode::Typed => {
                let tol = match self.typed_tol.trim() {
                    "" => None,
                    t => Some(t.parse::<f64>().map_err(|_| "invalid tolerance".to_string())?),
                };
                Pattern::typed(
                    TYPED_KINDS[self.typed_kind],
                    &self.pattern_text,
                    self.endian(),
                    tol,
                )
            }
        }
    }

    /// The replacement bytes, in the same mode as the pattern (F-28).
    fn build_replacement(&self, tab: &Tab) -> Result<Vec<u8>, String> {
        match self.mode {
            Mode::Hex => crate::hexview::parse_hex(&self.replace_text)
                .or_else(|| self.replace_text.trim().is_empty().then(Vec::new))
                .ok_or("invalid hex replacement".into()),
            Mode::Text => tab
                .view
                .charset
                .encode_str(&self.replace_text)
                .ok_or(format!("replacement not representable in {}", tab.view.charset.name())),
            Mode::Typed => Err("replacement does not apply to a typed search".into()),
        }
    }

    /// The search range (F-15): the selection, if requested, else the document.
    fn range_for(&self, tab: &Tab) -> std::ops::Range<u64> {
        if self.in_selection
            && let Some(sel) = tab.view.selection()
        {
            return sel;
        }
        0..tab.doc.len()
    }

    // ---- job starts ----

    pub fn start_next(&mut self, tabs: &[Tab], active: usize, backward: bool) {
        let Some(tab) = tabs.get(active) else { return };
        let pattern = match self.build_pattern(tab) {
            Ok(p) => p,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        let range = self.range_for(tab);
        // From the current selection (the next after the current match) or
        // the cursor. Backwards, the candidates are already strictly earlier.
        let from = match (backward, tab.view.selection()) {
            (false, Some(sel)) => sel.start + 1,
            (false, None) => tab.view.cursor,
            (true, Some(sel)) => sel.start,
            (true, None) => tab.view.cursor,
        };
        let progress = Progress::new();
        let searcher =
            Searcher::new(pattern.clone(), range.clone(), tab.doc.len(), from, backward, self.wrap);
        progress.set_total(searcher.total_space());
        self.status = "searching…".into();
        self.job = Some(Job {
            kind: JobKind::Next { backward },
            tab: active,
            searcher,
            pattern,
            range_end: range.end,
            queue: Vec::new(),
            progress,
        });
    }

    fn start_all(&mut self, tabs: &[Tab], active: usize) {
        let Some(tab) = tabs.get(active) else { return };
        let pattern = match self.build_pattern(tab) {
            Ok(p) => p,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        self.results.clear();
        self.results_open = true;
        let range = self.range_for(tab);
        // F-15c: the other tabs join the queue (whole-document search on each
        // — restricting to the selection only makes sense on the active tab).
        let queue: Vec<usize> = if self.all_tabs && !self.in_selection {
            (0..tabs.len()).rev().filter(|i| *i != active).collect()
        } else {
            Vec::new()
        };
        let progress = Progress::new();
        let searcher = Searcher::new(
            pattern.clone(),
            range.clone(),
            tab.doc.len(),
            range.start,
            false,
            false,
        );
        progress.set_total(searcher.total_space());
        self.status = "searching…".into();
        self.job = Some(Job {
            kind: JobKind::All,
            tab: active,
            searcher,
            pattern,
            range_end: range.end,
            queue,
            progress,
        });
    }

    fn start_replace_all(&mut self, tabs: &[Tab], active: usize) {
        let Some(tab) = tabs.get(active) else { return };
        if tab.read_only {
            self.status = "read-only".into();
            return;
        }
        let (pattern, replacement) =
            match self.build_pattern(tab).and_then(|p| Ok((p, self.build_replacement(tab)?))) {
                Ok(x) => x,
                Err(e) => {
                    self.status = e;
                    return;
                }
            };
        let range = self.range_for(tab);
        let progress = Progress::new();
        let searcher = Searcher::new(
            pattern.clone(),
            range.clone(),
            tab.doc.len(),
            range.start,
            false,
            false,
        );
        progress.set_total(searcher.total_space());
        self.status = "replacing…".into();
        self.job = Some(Job {
            kind: JobKind::ReplaceAll { replacement, count: 0 },
            tab: active,
            searcher,
            pattern,
            range_end: range.end,
            queue: Vec::new(),
            progress,
        });
    }

    /// F-28 — Replace the selected match and search for the next one.
    fn replace_current(&mut self, tabs: &mut [Tab], active: usize) {
        let Some(tab) = tabs.get_mut(active) else { return };
        if tab.read_only {
            self.status = "read-only".into();
            return;
        }
        let (pattern, replacement) =
            match self.build_pattern(tab).and_then(|p| Ok((p, self.build_replacement(tab)?))) {
                Ok(x) => x,
                Err(e) => {
                    self.status = e;
                    return;
                }
            };
        // Only replace if the selection is exactly one match of the pattern —
        // the flow is always "find, check, replace".
        let m = pattern.len() as u64;
        let confirmed = tab.view.selection().filter(|sel| {
            sel.end - sel.start == m
                && hexed_core::find_next(
                    &mut tab.doc,
                    &pattern,
                    sel.clone(),
                    sel.start,
                    false,
                    false,
                    &Progress::new(),
                )
                .is_some_and(|r| r == *sel)
        });
        if let Some(sel) = confirmed {
            tab.view.end_typing();
            match search::apply_replacement(&mut tab.doc, sel.clone(), &replacement) {
                Ok(()) => {
                    tab.view.goto(sel.start + replacement.len() as u64, tab.doc.len());
                    self.status = "replaced".into();
                }
                Err(e) => {
                    self.status = e.to_string();
                    return;
                }
            }
        }
        self.start_next(tabs, active, false);
    }
}

