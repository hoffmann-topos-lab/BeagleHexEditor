mod charts;
mod windows;

use eframe::egui::{self, Color32, Pos2, ProgressBar, Rect, Sense, Stroke, Ui, Vec2};
use hexed_core::hash::{Algo, DigestJob};
use hexed_core::magic::{self, MagicScanJob, Signature};
use hexed_core::stats::{Stats, StatsJob};
use hexed_core::strings::{FoundString, StrEncoding, StringsJob};
use hexed_core::Progress;

use crate::app::Tab;

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
}
