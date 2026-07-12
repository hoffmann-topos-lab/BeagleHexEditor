//! F-32 — Tab comparison.

use eframe::egui;
use hexed_core::compare::DiffJob;

use crate::shortcuts::{self, Action};

use super::App;

impl App {
    /// F-32 — Comparison mode: banner, synchronized scroll, highlight of the
    /// visible bytes that differ and a cooperative "next difference".
    pub(super) fn compare_mode(&mut self, ctx: &egui::Context, mut do_next_diff: bool) {
        let Some((ia, ib)) = self.compare else { return };
        if ia >= self.tabs.len() || ib >= self.tabs.len() || ia == ib {
            self.compare = None;
            self.diff_job = None;
            return;
        }

        // Banner with the controls.
        let (title_a, title_b) = (self.tabs[ia].title.clone(), self.tabs[ib].title.clone());
        let nd_hint = shortcuts::symbol(&self.shortcuts[Action::NextDiff]);
        let mut stop = false;
        egui::TopBottomPanel::top("compare").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("⇄ comparing  {title_a}  ↔  {title_b}"));
                do_next_diff |= ui.button(format!("Next difference\t{nd_hint}")).clicked();
                if ui.button("✕").on_hover_text("stop comparison").clicked() {
                    stop = true;
                }
            });
        });
        if stop {
            self.compare = None;
            self.diff_job = None;
            return;
        }

        // The leader is the active tab (if it takes part); the other follows it.
        let leader = if self.active == ib { ib } else { ia };
        let follower = if leader == ia { ib } else { ia };
        let Ok([ta, tb]) = self.tabs.get_disjoint_mut([leader, follower]) else { return };
        tb.view.top_row = ta.view.top_row;

        // Diff of the visible window: cheap enough for every frame.
        let (la, lb) = (ta.doc.len(), tb.doc.len());
        let vis = ta.view.visible_range(la.max(lb));
        let n = (vis.end - vis.start) as usize;
        let ra = ta.doc.read(vis.start, n);
        let rb = tb.doc.read(vis.start, n);
        let mut ranges: Vec<std::ops::Range<u64>> = Vec::new();
        for i in 0..n {
            // Past the end of the shorter document, everything differs (get returns None).
            if ra.data.get(i) != rb.data.get(i) {
                let at = vis.start + i as u64;
                match ranges.last_mut() {
                    Some(last) if last.end == at => last.end = at + 1,
                    _ => ranges.push(at..at + 1),
                }
            }
        }
        ta.view.diff = ranges.clone();
        tb.view.diff = ranges;

        // Next difference, cooperative (F-07): from the leader's cursor.
        if do_next_diff && self.diff_job.is_none() {
            let from = ta.view.cursor.saturating_add(1);
            self.diff_job = Some(DiffJob::new(from, la, lb));
        }
        if let Some(mut job) = self.diff_job.take() {
            ctx.request_repaint();
            let mut budget: u64 = 16 << 20;
            loop {
                let (found, st) = job.step(&mut ta.doc, &mut tb.doc, budget);
                budget = budget.saturating_sub(st.scanned.max(1));
                if let Some(at) = found {
                    ta.view.goto(at, la);
                    tb.view.goto(at, lb);
                    ta.view.status = format!("difference at {at:#x}");
                    return;
                }
                if st.finished {
                    ta.view.status = "no more differences".into();
                    return;
                }
                if budget == 0 {
                    self.diff_job = Some(job); // continue next frame
                    return;
                }
            }
        }
    }
}
