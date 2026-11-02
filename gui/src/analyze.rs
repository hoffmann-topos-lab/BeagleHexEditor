mod charts;
mod windows;

use eframe::egui::{self, Color32, Pos2, Rect, Sense, Stroke, Ui, Vec2};
use hexed_core::StepResult;
use hexed_core::hash::{Algo, DigestJob};
use hexed_core::magic::{self, MagicScanJob, Signature};
use hexed_core::stats::{Stats, StatsJob};
use hexed_core::strings::{FoundString, StrEncoding, StringsJob};

use crate::app::Tab;
use crate::jobs::{self, JobRunner};
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

impl Job {
    fn tab(&self) -> usize {
        match self {
            Job::Digest { tab, .. }
            | Job::Strings { tab, .. }
            | Job::Stats { tab, .. }
            | Job::Magic { tab, .. } => *tab,
        }
    }
}

/// A list scan stops early once it holds more than the GUI shows.
fn until_full(st: StepResult, found: usize) -> StepResult {
    StepResult { finished: st.finished || found > MAX_RESULTS, ..st }
}

pub struct AnalyzeState {
    run: JobRunner<Job>,

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
            run: JobRunner::default(),
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
    /// Runs the active job with the frame's budget (F-07).
    pub fn drive(&mut self, tabs: &mut [Tab], ctx: &egui::Context) {
        let Some(mut job) = self.run.take() else { return };
        ctx.request_repaint();
        if self.run.progress.is_cancelled() {
            self.run.status = "analysis cancelled".into();
            return;
        }
        let Some(tab) = tabs.get_mut(job.tab()) else { return };
        let (doc, progress) = (&mut tab.doc, &self.run.progress);
        let finished = match &mut job {
            Job::Digest { job: j, .. } => jobs::run_frame(progress, |b| j.step(doc, b)),
            Job::Strings { job: j, .. } => {
                let out = &mut self.str_results;
                Ok(jobs::sweep_frame(progress, |b| until_full(j.step(doc, b, out), out.len())))
            }
            Job::Stats { job: j, .. } => Ok(jobs::sweep_frame(progress, |b| j.step(doc, b))),
            Job::Magic { job: j, .. } => {
                let out = &mut self.magic_scan;
                Ok(jobs::sweep_frame(progress, |b| until_full(j.step(doc, b, out), out.len())))
            }
        };
        match finished {
            Ok(true) => self.finish(job),
            Ok(false) => self.run.resume(job), // budget exhausted: continue next frame
            Err(e) => self.run.status = e.to_string(),
        }
    }

    /// Collects a finished job's result and reports it.
    fn finish(&mut self, job: Job) {
        self.run.status = match job {
            Job::Digest { job, .. } => {
                self.hash_results = job.finish();
                "computation finished".into()
            }
            Job::Strings { .. } => {
                self.str_results.sort_by_key(|s| s.offset);
                self.str_truncated = self.str_results.len() > MAX_RESULTS;
                if self.str_truncated {
                    self.str_results.truncate(MAX_RESULTS);
                    format!("stopped at {MAX_RESULTS} strings")
                } else {
                    format!("{} string(s)", self.str_results.len())
                }
            }
            Job::Stats { job, .. } => {
                self.stats_result = Some(job.finish());
                "statistics ready".into()
            }
            Job::Magic { .. } => {
                if self.magic_scan.len() > MAX_RESULTS {
                    self.magic_scan.truncate(MAX_RESULTS);
                    format!("stopped at {MAX_RESULTS} hits")
                } else {
                    format!("{} embedded signature(s)", self.magic_scan.len())
                }
            }
        };
    }
}
