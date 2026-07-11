use eframe::egui::{self, Color32, Pos2, ProgressBar, Rect, Sense, Stroke, Ui, Vec2};
use hexed_core::hash::{Algo, DigestJob};
use hexed_core::magic::{self, MagicScanJob, Signature};
use hexed_core::stats::{Stats, StatsJob};
use hexed_core::strings::{FoundString, StrEncoding, StringsJob};
use hexed_core::Progress;

use crate::Tab;

/// Bytes processed per frame.
const FRAME_BUDGET: u64 = 16 << 20;
/// Cap on results in the GUI lists.
const MAX_RESULTS: usize = 10_000;
/// The accent hue of the charts and highlights (the same as the inspector's).
const ACCENT: Color32 = Color32::from_rgb(64, 140, 220);

enum Job {
    Digest { tab: usize, job: DigestJob },
    Strings { tab: usize, job: StringsJob },
    // On the heap: StatsJob carries two whole histograms.
    Stats { tab: usize, job: Box<StatsJob> },
    Magic { tab: usize, job: MagicScanJob },
}

pub struct AnalyzeState {
    job: Option<Job>,
    progress: Progress,
    pub status: String,

    // F-25/F-26.
    pub hash_open: bool,
    hash_selected: [bool; Algo::ALL.len()],
    hash_in_selection: bool,
    hash_results: Vec<(Algo, String)>,

    // F-24.
    pub strings_open: bool,
    str_min: usize,
    str_utf8: bool,
    str_utf16le: bool,
    str_utf16be: bool,
    str_results: Vec<FoundString>,
    str_truncated: bool,

    // F-29/F-30a.
    pub stats_open: bool,
    stats_result: Option<Stats>,

    // F-33.
    pub magic_open: bool,
    magic_identified: Vec<&'static Signature>,
    magic_scan: Vec<(u64, &'static Signature)>,
}

impl Default for AnalyzeState {
    fn default() -> Self {
        // SHA-256 and CRC-32 are the most requested pair; the rest is opt-in.
        let hash_selected =
            std::array::from_fn(|i| matches!(Algo::ALL[i], Algo::Sha256 | Algo::Crc32));
        Self {
            job: None,
            progress: Progress::new(),
            status: String::new(),
            hash_open: false,
            hash_selected,
            hash_in_selection: false,
            hash_results: Vec::new(),
            strings_open: false,
            str_min: 4,
            str_utf8: true,
            str_utf16le: false,
            str_utf16be: false,
            str_results: Vec::new(),
            str_truncated: false,
            stats_open: false,
            stats_result: None,
            magic_open: false,
            magic_identified: Vec::new(),
            magic_scan: Vec::new(),
        }
    }
}

impl AnalyzeState {
    fn range_for(tab: &Tab, in_selection: bool) -> std::ops::Range<u64> {
        match tab.view.selection() {
            Some(sel) if in_selection => sel,
            _ => 0..tab.doc.len(),
        }
    }

    fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Runs the active job with the frame's budget (F-07).
    pub fn drive(&mut self, tabs: &mut [Tab], ctx: &egui::Context) {
        let Some(mut job) = self.job.take() else { return };
        ctx.request_repaint();
        if self.progress.is_cancelled() {
            self.status = "analysis cancelled".into();
            return;
        }
        let tab_idx = match &job {
            Job::Digest { tab, .. }
            | Job::Strings { tab, .. }
            | Job::Stats { tab, .. }
            | Job::Magic { tab, .. } => *tab,
        };
        let Some(tab) = tabs.get_mut(tab_idx) else { return };

        let mut budget = FRAME_BUDGET;
        while budget > 0 {
            match &mut job {
                Job::Digest { job: j, .. } => match j.step(&mut tab.doc, budget) {
                    Ok(n) => {
                        self.progress.add_done(n);
                        budget = budget.saturating_sub(n.max(1));
                        if j.is_finished() {
                            let Job::Digest { job: j, .. } = job else { unreachable!() };
                            self.hash_results = j.finish();
                            self.status = "computation finished".into();
                            return;
                        }
                    }
                    Err(e) => {
                        self.status = e.to_string();
                        return;
                    }
                },
                Job::Strings { job: j, .. } => {
                    let st = j.step(&mut tab.doc, budget, &mut self.str_results);
                    self.progress.add_done(st.scanned);
                    budget = budget.saturating_sub(st.scanned.max(1));
                    if self.str_results.len() > MAX_RESULTS {
                        self.str_results.truncate(MAX_RESULTS);
                        self.str_truncated = true;
                        self.status = format!("stopped at {MAX_RESULTS} strings");
                        return;
                    }
                    if st.finished {
                        self.str_results.sort_by_key(|s| s.offset);
                        self.status = format!("{} string(s)", self.str_results.len());
                        return;
                    }
                }
                Job::Stats { job: j, .. } => {
                    let st = j.step(&mut tab.doc, budget);
                    self.progress.add_done(st.scanned);
                    budget = budget.saturating_sub(st.scanned.max(1));
                    if st.finished {
                        let Job::Stats { job: j, .. } = job else { unreachable!() };
                        self.stats_result = Some(j.finish());
                        self.status = "statistics ready".into();
                        return;
                    }
                }
                Job::Magic { job: j, .. } => {
                    let st = j.step(&mut tab.doc, budget, &mut self.magic_scan);
                    self.progress.add_done(st.scanned);
                    budget = budget.saturating_sub(st.scanned.max(1));
                    if self.magic_scan.len() > MAX_RESULTS {
                        self.magic_scan.truncate(MAX_RESULTS);
                        self.status = format!("stopped at {MAX_RESULTS} hits");
                        return;
                    }
                    if st.finished {
                        self.status = format!("{} embedded signature(s)", self.magic_scan.len());
                        return;
                    }
                }
            }
        }
        self.job = Some(job); // budget exhausted: continue next frame
    }

    /// The windows' standard progress/cancel bar.
    fn progress_row(&mut self, ui: &mut Ui) {
        if self.busy() {
            ui.horizontal(|ui| {
                ui.add(ProgressBar::new(self.progress.fraction()).desired_width(180.0));
                if ui.button("Cancel").clicked() {
                    self.progress.cancel();
                }
            });
        } else if !self.status.is_empty() {
            ui.weak(&self.status);
        }
    }

    fn start(&mut self, job: Job, total: u64) {
        self.progress = Progress::new();
        self.progress.set_total(total);
        self.status = "processing…".into();
        self.job = Some(job);
    }

    // ---- windows ----

    pub fn windows(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        self.hash_window(ctx, tabs, active);
        self.strings_window(ctx, tabs, active);
        self.stats_window(ctx, tabs, active);
        self.magic_window(ctx, tabs, active);
    }

    fn hash_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.hash_open {
            return;
        }
        let mut open = true;
        egui::Window::new("Hashes and checksums").open(&mut open).resizable(false).show(ctx, |ui| {
            ui.columns(3, |cols| {
                for (i, a) in Algo::ALL.iter().enumerate() {
                    cols[i % 3].checkbox(&mut self.hash_selected[i], a.name());
                }
            });
            ui.checkbox(&mut self.hash_in_selection, "selection only");
            ui.horizontal(|ui| {
                let can = !self.busy() && self.hash_selected.iter().any(|s| *s);
                if ui.add_enabled(can, egui::Button::new("Compute")).clicked()
                    && let Some(tab) = tabs.get(active)
                {
                    let algos: Vec<Algo> = Algo::ALL
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| self.hash_selected[*i])
                        .map(|(_, a)| *a)
                        .collect();
                    let range = Self::range_for(tab, self.hash_in_selection);
                    self.hash_results.clear();
                    let job = DigestJob::new(&algos, range, tab.doc.len());
                    let total = job.total();
                    self.start(Job::Digest { tab: active, job }, total);
                }
            });
            self.progress_row(ui);
            if !self.hash_results.is_empty() {
                ui.separator();
                for (algo, hex) in &self.hash_results {
                    ui.horizontal(|ui| {
                        ui.label(format!("{:<9}", algo.name()));
                        ui.monospace(hex);
                    });
                }
            }
        });
        self.hash_open = open;
    }

    fn strings_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.strings_open {
            return;
        }
        let mut open = true;
        let mut goto: Option<(u64, u64)> = None;
        egui::Window::new("Extract strings")
            .open(&mut open)
            .default_width(430.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("minimum:");
                    ui.add(egui::DragValue::new(&mut self.str_min).range(2..=64));
                    ui.checkbox(&mut self.str_utf8, "UTF-8/ASCII");
                    ui.checkbox(&mut self.str_utf16le, "UTF-16LE");
                    ui.checkbox(&mut self.str_utf16be, "UTF-16BE");
                });
                ui.horizontal(|ui| {
                    let any = self.str_utf8 || self.str_utf16le || self.str_utf16be;
                    if ui.add_enabled(!self.busy() && any, egui::Button::new("Extract")).clicked()
                        && let Some(tab) = tabs.get(active)
                    {
                        let mut encodings = Vec::new();
                        if self.str_utf8 {
                            encodings.push(StrEncoding::Utf8);
                        }
                        if self.str_utf16le {
                            encodings.push(StrEncoding::Utf16Le);
                        }
                        if self.str_utf16be {
                            encodings.push(StrEncoding::Utf16Be);
                        }
                        self.str_results.clear();
                        self.str_truncated = false;
                        let job = StringsJob::new(
                            &encodings,
                            self.str_min,
                            0..tab.doc.len(),
                            tab.doc.len(),
                        );
                        let total = job.total();
                        self.start(Job::Strings { tab: active, job }, total);
                    }
                });
                self.progress_row(ui);
                if !self.str_results.is_empty() {
                    ui.separator();
                    let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                    egui::ScrollArea::vertical().max_height(300.0).show_rows(
                        ui,
                        row_h,
                        self.str_results.len(),
                        |ui, rows| {
                            for i in rows {
                                let s = &self.str_results[i];
                                let label = format!(
                                    "{:#010x} {:<8} {}",
                                    s.offset,
                                    s.encoding.name(),
                                    s.text
                                );
                                if ui
                                    .selectable_label(false, egui::RichText::new(label).monospace())
                                    .clicked()
                                {
                                    goto = Some((s.offset, s.len));
                                }
                            }
                        },
                    );
                }
            });
        self.strings_open = open;
        if let Some((off, len)) = goto
            && let Some(tab) = tabs.get_mut(active)
        {
            tab.view.select_range(off..off + len, tab.doc.len());
        }
    }

    fn stats_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.stats_open {
            return;
        }
        let mut open = true;
        let mut goto: Option<u64> = None;
        egui::Window::new("Statistics").open(&mut open).default_width(560.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.add_enabled(!self.busy(), egui::Button::new("Compute")).clicked()
                    && let Some(tab) = tabs.get(active)
                {
                    self.stats_result = None;
                    let job = Box::new(StatsJob::new(0..tab.doc.len(), tab.doc.len(), None));
                    let total = job.total_space();
                    self.start(Job::Stats { tab: active, job }, total);
                }
            });
            self.progress_row(ui);
            if let Some(s) = &self.stats_result {
                ui.separator();
                let distinct = s.counts.iter().filter(|c| **c > 0).count();
                ui.monospace(format!(
                    "{} byte(s) · entropy {:.3} bits/byte · {distinct}/256 values",
                    s.total,
                    s.entropy()
                ));
                if s.unreadable > 0 {
                    ui.colored_label(
                        Color32::from_rgb(180, 40, 40),
                        format!("⚠ {} unreadable byte(s) left out of the count", s.unreadable),
                    );
                }
                ui.add_space(6.0);
                ui.label("Histogram of the 256 values (F-29):");
                histogram_chart(ui, &s.counts, s.total);
                ui.add_space(6.0);
                ui.label(format!(
                    "Entropy per {}-byte block — click to navigate (F-30a):",
                    s.block_size
                ));
                goto = entropy_chart(ui, &s.blocks, s.block_size);
            }
        });
        self.stats_open = open;
        if let Some(off) = goto
            && let Some(tab) = tabs.get_mut(active)
        {
            tab.view.goto(off, tab.doc.len());
        }
    }

    fn magic_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.magic_open {
            return;
        }
        let mut open = true;
        let mut goto: Option<u64> = None;
        egui::Window::new("Signatures").open(&mut open).default_width(380.0).show(ctx, |ui| {
            if self.magic_identified.is_empty() {
                ui.weak("no known signature in the header");
            } else {
                for s in &self.magic_identified {
                    ui.label(format!("● {}", s.name));
                }
            }
            ui.separator();
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Sweep embedded (carving)"))
                .clicked()
                && let Some(tab) = tabs.get(active)
            {
                self.magic_scan.clear();
                let job = MagicScanJob::new(0..tab.doc.len(), tab.doc.len());
                let total = job.total();
                self.start(Job::Magic { tab: active, job }, total);
            }
            self.progress_row(ui);
            if !self.magic_scan.is_empty() {
                ui.separator();
                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::vertical().max_height(280.0).show_rows(
                    ui,
                    row_h,
                    self.magic_scan.len(),
                    |ui, rows| {
                        for i in rows {
                            let (off, s) = &self.magic_scan[i];
                            let label = format!("{off:#010x}  {}", s.name);
                            if ui
                                .selectable_label(false, egui::RichText::new(label).monospace())
                                .clicked()
                            {
                                goto = Some(*off);
                            }
                        }
                    },
                );
            }
        });
        self.magic_open = open;
        if let Some(off) = goto
            && let Some(tab) = tabs.get_mut(active)
        {
            tab.view.goto(off, tab.doc.len());
        }
    }

    /// Opens the signatures window, identifying the document on the spot.
    pub fn open_magic(&mut self, tab: &mut Tab) {
        self.magic_identified = magic::identify(&mut tab.doc);
        self.magic_scan.clear();
        self.magic_open = true;
    }
}

/// F-29 — Histogram: 256 thin bars, anchored at zero, hover for detail.
fn histogram_chart(ui: &mut Ui, counts: &[u64; 256], total: u64) {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 130.0), Sense::hover());
    let painter = ui.painter_at(rect);
    let weak = ui.visuals().weak_text_color().gamma_multiply(0.5);
    let max = counts.iter().max().copied().unwrap_or(0).max(1);
    let bw = rect.width() / 256.0;

    // Recessive grid: the baseline only.
    painter.line_segment(
        [rect.left_bottom(), rect.right_bottom()],
        Stroke::new(1.0, weak),
    );

    let hovered = resp
        .hover_pos()
        .map(|p| (((p.x - rect.left()) / bw) as usize).min(255));
    for (b, c) in counts.iter().enumerate() {
        if *c == 0 {
            continue;
        }
        let h = (*c as f64 / max as f64) as f32 * (rect.height() - 4.0);
        let x = rect.left() + b as f32 * bw;
        let color = if hovered == Some(b) { ACCENT } else { ACCENT.gamma_multiply(0.75) };
        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(x, rect.bottom() - h.max(1.0)),
                Pos2::new(x + bw.max(1.0), rect.bottom()),
            ),
            0.0,
            color,
        );
    }
    if let Some(b) = hovered
        && total > 0
    {
        let c = counts[b];
        let ch = if (0x20..0x7F).contains(&(b as u32)) {
            format!(" '{}'", b as u8 as char)
        } else {
            String::new()
        };
        resp.on_hover_text(format!(
            "{b:#04X}{ch} — {c} ({:.2}%)",
            c as f64 / total as f64 * 100.0
        ));
    }
}

/// F-30a — Entropy per block: a 0-to-8-bit range, gaps for unreadable blocks,
/// a click navigates to the block.
fn entropy_chart(ui: &mut Ui, blocks: &[f32], block_size: u64) -> Option<u64> {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 90.0), Sense::click());
    let painter = ui.painter_at(rect);
    let weak = ui.visuals().weak_text_color().gamma_multiply(0.5);
    let n = blocks.len().max(1);
    let bw = rect.width() / n as f32;

    // Reference lines: 0 and 8 bits (a fixed scale — entropy is comparable
    // across files, so the ceiling does not float).
    painter.line_segment([rect.left_bottom(), rect.right_bottom()], Stroke::new(1.0, weak));
    painter.line_segment([rect.left_top(), rect.right_top()], Stroke::new(1.0, weak));

    let hovered = resp
        .hover_pos()
        .map(|p| (((p.x - rect.left()) / bw) as usize).min(n - 1));
    for (i, e) in blocks.iter().enumerate() {
        if e.is_nan() {
            continue; // unreadable block: a gap, not a zero
        }
        let h = (e / 8.0).clamp(0.0, 1.0) * rect.height();
        let x = rect.left() + i as f32 * bw;
        let color = if hovered == Some(i) { ACCENT } else { ACCENT.gamma_multiply(0.65) };
        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(x, rect.bottom() - h.max(1.0)),
                Pos2::new(x + bw.max(1.0), rect.bottom()),
            ),
            0.0,
            color,
        );
    }
    let mut clicked = None;
    if let Some(i) = hovered {
        let off = i as u64 * block_size;
        let e = blocks[i];
        let text = if e.is_nan() {
            format!("{off:#x} — unreadable block")
        } else {
            format!("{off:#x} — {e:.3} bits/byte")
        };
        if resp.clicked() {
            clicked = Some(off);
        }
        resp.on_hover_text(text);
    }
    clicked
}
