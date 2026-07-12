//! Per-frame execution of the search job (F-07).

use eframe::egui;
use hexed_core::search::{self, Searcher};

use crate::app::Tab;

use super::{FRAME_BUDGET, Hit, JobKind, MAX_RESULTS, SearchState};

impl SearchState {
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
}
