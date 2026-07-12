//! Per-frame execution of the export/transform jobs (F-07).

use super::*;

impl ToolsState {
    /// Runs the active job with the frame's budget (F-07).
    pub fn drive(&mut self, tabs: &mut [Tab], ctx: &egui::Context) {
        let Some(job) = self.job.take() else { return };
        ctx.request_repaint();
        if self.progress.is_cancelled() {
            self.cleanup(job);
            self.status = "operation cancelled".into();
            return;
        }
        match job {
            ToolJob::Export { tab, mut job, mut w, path } => {
                let Some(t) = tabs.get_mut(tab) else {
                    self.cleanup(ToolJob::Export { tab, job, w, path });
                    self.status = "tab closed; export cancelled".into();
                    return;
                };
                let mut budget = FRAME_BUDGET;
                while budget > 0 {
                    match job.step(&mut t.doc, budget, &mut w) {
                        Ok(st) => {
                            self.progress.add_done(st.scanned);
                            budget = budget.saturating_sub(st.scanned.max(1));
                            if st.finished {
                                self.status = match w.flush() {
                                    Ok(()) => format!("exported → {}", path.display()),
                                    Err(e) => {
                                        drop(w);
                                        let _ = std::fs::remove_file(&path);
                                        e.to_string()
                                    }
                                };
                                return;
                            }
                        }
                        Err(e) => {
                            drop(w);
                            let _ = std::fs::remove_file(&path);
                            self.status = e.to_string();
                            return;
                        }
                    }
                }
                self.job = Some(ToolJob::Export { tab, job, w, path });
            }
            ToolJob::Record { tab, mut job, mut w, path } => {
                let Some(t) = tabs.get_mut(tab) else {
                    self.cleanup(ToolJob::Record { tab, job, w, path });
                    self.status = "tab closed; export cancelled".into();
                    return;
                };
                let mut budget = FRAME_BUDGET;
                while budget > 0 {
                    match job.step(&mut t.doc, budget, &mut w) {
                        Ok(st) => {
                            self.progress.add_done(st.scanned);
                            budget = budget.saturating_sub(st.scanned.max(1));
                            if st.finished {
                                self.status = match w.flush() {
                                    Ok(()) => format!("exported → {}", path.display()),
                                    Err(e) => {
                                        drop(w);
                                        let _ = std::fs::remove_file(&path);
                                        e.to_string()
                                    }
                                };
                                return;
                            }
                        }
                        Err(e) => {
                            drop(w);
                            let _ = std::fs::remove_file(&path);
                            self.status = e.to_string();
                            return;
                        }
                    }
                }
                self.job = Some(ToolJob::Record { tab, job, w, path });
            }
            ToolJob::Split { tab, mut job } => {
                let Some(t) = tabs.get_mut(tab) else {
                    job.abort();
                    self.status = "tab closed; split cancelled".into();
                    return;
                };
                let mut budget = FRAME_BUDGET;
                while budget > 0 {
                    match job.step(&mut t.doc, budget) {
                        Ok(st) => {
                            self.progress.add_done(st.scanned);
                            budget = budget.saturating_sub(st.scanned.max(1));
                            if st.finished {
                                let parts = job.finish();
                                self.status = format!("{} part(s) written", parts.len());
                                return;
                            }
                        }
                        Err(e) => {
                            job.abort();
                            self.status = e.to_string();
                            return;
                        }
                    }
                }
                self.job = Some(ToolJob::Split { tab, job });
            }
            ToolJob::Concat { mut job, out } => {
                let mut budget = FRAME_BUDGET;
                while budget > 0 {
                    match job.step(budget) {
                        Ok(st) => {
                            self.progress.add_done(st.scanned);
                            budget = budget.saturating_sub(st.scanned.max(1));
                            if st.finished {
                                self.status = match job.finish() {
                                    Ok(n) => format!("{n} byte(s) → {}", out.display()),
                                    Err(e) => e.to_string(),
                                };
                                return;
                            }
                        }
                        Err(e) => {
                            self.status = e.to_string();
                            return;
                        }
                    }
                }
                self.job = Some(ToolJob::Concat { job, out });
            }
        }
    }

    /// Undoes what an interrupted job left behind.
    fn cleanup(&mut self, job: ToolJob) {
        match job {
            ToolJob::Export { w, path, .. } | ToolJob::Record { w, path, .. } => {
                drop(w);
                let _ = std::fs::remove_file(&path);
            }
            ToolJob::Split { job, .. } => job.abort(),
            ToolJob::Concat { .. } => {} // the temporary file dies at drop
        }
    }
}
