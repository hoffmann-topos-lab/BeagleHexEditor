
use eframe::egui::{self, Key, ProgressBar, TextEdit};
use hexed_core::search::{self, Pattern, Searcher};
use hexed_core::{Endian, Progress};

use crate::Tab;

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

    // ---- disparo de jobs ----

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

    // ---- per-frame execution (F-07) ----

    pub fn drive(&mut self, tabs: &mut [Tab], active: &mut usize, ctx: &egui::Context) {
        let Some(mut job) = self.job.take() else { return };
        if job.tab >= tabs.len() {
            return; // the tab was closed mid-search: drop the job
        }
        ctx.request_repaint();

        let mut budget = FRAME_BUDGET;
        let mut out: Vec<u64> = Vec::new();
        let m = job.searcher.pattern_len();

        while budget > 0 {
            if job.progress.is_cancelled() {
                self.status = match &job.kind {
                    JobKind::ReplaceAll { count, .. } => {
                        format!("cancelled after {count} replacement(s)")
                    }
                    _ => "search cancelled".into(),
                };
                return;
            }
            let tab = &mut tabs[job.tab];
            let st = job.searcher.step(&mut tab.doc, budget, &mut out);
            job.progress.add_done(st.scanned);
            budget = budget.saturating_sub(st.scanned.max(1));

            match &mut job.kind {
                JobKind::Next { backward } => {
                    if !out.is_empty() {
                        let at = if *backward { *out.last().unwrap() } else { out[0] };
                        tab.view.select_range(at..at + m, tab.doc.len());
                        *active = job.tab;
                        self.status = format!("match at {at:#x}");
                        return;
                    }
                    if st.finished {
                        self.status = "no match".into();
                        return;
                    }
                }
                JobKind::All => {
                    for at in out.drain(..) {
                        if self.results.len() >= MAX_RESULTS {
                            self.status =
                                format!("stopped at {MAX_RESULTS} matches (list limit)");
                            return;
                        }
                        self.results.push(Hit { tab: job.tab, at, len: m });
                    }
                    if st.finished {
                        if let Some(next_tab) = job.queue.pop() {
                            // F-15c: the next tab in the queue.
                            let len = tabs[next_tab].doc.len();
                            job.tab = next_tab;
                            job.range_end = len;
                            job.searcher =
                                Searcher::new(job.pattern.clone(), 0..len, len, 0, false, false);
                            job.progress.set_total(job.progress.total() + len);
                        } else {
                            self.status = format!("{} match(es)", self.results.len());
                            return;
                        }
                    }
                }
                JobKind::ReplaceAll { replacement, count } => {
                    let mut delta_acc: i64 = 0;
                    let mut resume_at = 0u64;
                    for at in out.drain(..) {
                        let at = at.checked_add_signed(delta_acc).expect("valid offset");
                        if let Err(e) =
                            search::apply_replacement(&mut tab.doc, at..at + m, replacement)
                        {
                            self.status = e.to_string();
                            return;
                        }
                        if *count > 0 {
                            tab.doc.merge_with_previous(); // atomic undo (F-28)
                        }
                        *count += 1;
                        delta_acc += replacement.len() as i64 - m as i64;
                        resume_at = at + replacement.len() as u64;
                    }
                    if delta_acc != 0 {
                        // The document changed size: the old Searcher points at
                        // shifted offsets. Restart from the end of the last
                        // replacement.
                        job.range_end =
                            job.range_end.checked_add_signed(delta_acc).expect("within the doc");
                        job.searcher = Searcher::new(
                            job.pattern.clone(),
                            resume_at..job.range_end,
                            tab.doc.len(),
                            resume_at,
                            false,
                            false,
                        );
                    }
                    if st.finished {
                        tab.view.end_typing();
                        self.status = format!("{count} replacement(s) — a single undo");
                        return;
                    }
                }
            }
        }
        // Frame budget exhausted: the job continues in the next one.
        self.job = Some(job);
    }

    // ---- UI ----

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
