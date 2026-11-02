//! Per-frame execution of the export/transform jobs (F-07).

use hexed_core::Document;

use super::*;

impl ToolsState {
    /// Runs the active job with the frame's budget (F-07).
    pub fn drive(&mut self, tabs: &mut [Tab], ctx: &egui::Context) {
        let Some(mut job) = self.run.take() else { return };
        ctx.request_repaint();
        if self.run.progress.is_cancelled() {
            job.cleanup();
            self.run.status = "operation cancelled".into();
            return;
        }
        let progress = &self.run.progress;
        let finished: Result<bool, String> = match &mut job {
            ToolJob::Export { tab, job: j, w, .. } => doc_of(tabs, *tab)
                .and_then(|doc| jobs::run_frame(progress, |b| Ok(j.step(doc, b, w)?))),
            ToolJob::Record { tab, job: j, w, .. } => doc_of(tabs, *tab)
                .and_then(|doc| jobs::run_frame(progress, |b| Ok(j.step(doc, b, w)?))),
            ToolJob::Split { tab, job: j } => doc_of(tabs, *tab)
                .and_then(|doc| jobs::run_frame(progress, |b| Ok(j.step(doc, b)?))),
            ToolJob::Concat { job: j, .. } => jobs::run_frame(progress, |b| Ok(j.step(b)?)),
        };
        match finished {
            Ok(true) => self.run.status = job.finish(),
            Ok(false) => self.run.resume(job), // budget exhausted: continue next frame
            Err(e) => {
                job.cleanup();
                self.run.status = e;
            }
        }
    }
}

/// The document a job reads from; its tab may have been closed mid-job.
fn doc_of(tabs: &mut [Tab], tab: usize) -> Result<&mut Document, String> {
    tabs.get_mut(tab).map(|t| &mut t.doc).ok_or_else(|| "tab closed; operation cancelled".into())
}

impl ToolJob {
    /// Seals a finished job; returns the status line.
    fn finish(self) -> String {
        match self {
            ToolJob::Export { mut w, path, .. } | ToolJob::Record { mut w, path, .. } => {
                match w.flush() {
                    Ok(()) => format!("exported → {}", path.display()),
                    Err(e) => {
                        drop(w);
                        let _ = std::fs::remove_file(&path);
                        e.to_string()
                    }
                }
            }
            ToolJob::Split { job, .. } => format!("{} part(s) written", job.finish().len()),
            ToolJob::Concat { job, out } => match job.finish() {
                Ok(n) => format!("{n} byte(s) → {}", out.display()),
                Err(e) => e.to_string(),
            },
        }
    }

    /// Undoes what an interrupted job left behind.
    fn cleanup(self) {
        match self {
            ToolJob::Export { w, path, .. } | ToolJob::Record { w, path, .. } => {
                drop(w);
                let _ = std::fs::remove_file(&path);
            }
            ToolJob::Split { job, .. } => job.abort(),
            ToolJob::Concat { .. } => {} // the temporary file dies at drop
        }
    }
}
