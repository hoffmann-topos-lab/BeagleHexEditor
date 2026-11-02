//! F-07 — Per-frame job plumbing shared by the analysis, tools and search
//! windows: the frame budget, the step loop and the progress/cancel row. The
//! GUI-side twin of `hexed_core::job` (whose `run`/`sweep` drive the same jobs
//! to the end for the CLI).

use std::convert::Infallible;
use std::ops::Range;

use eframe::egui::{ProgressBar, Ui};
use hexed_core::{Progress, StepResult};

use crate::app::Tab;

/// Bytes processed per frame. 16 MiB ≈ a few ms per frame and ~1 GB/s.
pub(crate) const FRAME_BUDGET: u64 = 16 << 20;

/// The selection when `in_selection` and there is one, else the whole document.
pub(crate) fn tab_range(tab: &Tab, in_selection: bool) -> Range<u64> {
    match tab.view.selection() {
        Some(sel) if in_selection => sel,
        _ => 0..tab.doc.len(),
    }
}

/// Spends one frame's budget on `step`: `Ok(true)` once the job finished,
/// `Ok(false)` when it continues next frame.
pub(crate) fn run_frame<E>(
    progress: &Progress,
    mut step: impl FnMut(u64) -> Result<StepResult, E>,
) -> Result<bool, E> {
    let mut budget = FRAME_BUDGET;
    while budget > 0 {
        let st = step(budget)?;
        progress.add_done(st.scanned);
        if st.finished {
            return Ok(true);
        }
        budget = budget.saturating_sub(st.scanned.max(1));
    }
    Ok(false)
}

/// [`run_frame`] for scans that cannot fail.
pub(crate) fn sweep_frame(progress: &Progress, mut step: impl FnMut(u64) -> StepResult) -> bool {
    match run_frame(progress, |budget| Ok::<_, Infallible>(step(budget))) {
        Ok(finished) => finished,
    }
}

/// A progress bar with its Cancel button.
pub(crate) fn progress_bar(ui: &mut Ui, progress: &Progress, width: f32) {
    ui.horizontal(|ui| {
        ui.add(ProgressBar::new(progress.fraction()).desired_width(width));
        if ui.button("Cancel").clicked() {
            progress.cancel();
        }
    });
}

/// One background job at a time — idle or running — with its progress and
/// the last status line. The owner's `drive` takes the job each frame, steps
/// it with [`run_frame`], and either resumes it or reports the outcome.
pub(crate) struct JobRunner<J> {
    job: Option<J>,
    pub(crate) progress: Progress,
    pub(crate) status: String,
}

impl<J> Default for JobRunner<J> {
    fn default() -> Self {
        Self { job: None, progress: Progress::new(), status: String::new() }
    }
}

impl<J> JobRunner<J> {
    pub(crate) fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Starts `job` with fresh progress over `total` bytes.
    pub(crate) fn start(&mut self, job: J, total: u64) {
        self.progress = Progress::new();
        self.progress.set_total(total);
        self.status = "processing…".into();
        self.job = Some(job);
    }

    /// Takes the job for this frame; the owner must [`resume`](Self::resume)
    /// it unless it finished, failed or was cancelled.
    pub(crate) fn take(&mut self) -> Option<J> {
        self.job.take()
    }

    pub(crate) fn resume(&mut self, job: J) {
        self.job = Some(job);
    }

    /// The windows' standard row: progress + Cancel while busy, else the last
    /// status (if any).
    pub(crate) fn status_ui(&self, ui: &mut Ui, width: f32) {
        if self.busy() {
            progress_bar(ui, &self.progress, width);
        } else if !self.status.is_empty() {
            ui.weak(&self.status);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_stops_at_the_budget_or_at_the_end() {
        let p = Progress::new();
        let mut calls = 0;
        let done = sweep_frame(&p, |b| {
            calls += 1;
            StepResult { finished: false, scanned: b.min(4 << 20) }
        });
        assert!(!done);
        assert_eq!((calls, p.done()), (4, FRAME_BUDGET), "16 MiB in 4 MiB steps");

        let p = Progress::new();
        assert!(sweep_frame(&p, |_| StepResult { finished: true, scanned: 7 }));
        assert_eq!(p.done(), 7);
    }

    #[test]
    fn a_failing_step_ends_the_frame_with_its_error() {
        let p = Progress::new();
        let r = run_frame(&p, |_| Err::<StepResult, _>("bad block"));
        assert_eq!(r, Err("bad block"));
    }
}
