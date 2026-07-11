
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use eframe::egui::{self, Key, ProgressBar};
use hexed_core::export::{self, ExportFormat, ExportJob, ExportOptions};
use hexed_core::hexfile::{DEFAULT_REC_LEN, RecordExportJob, RecordFormat};
use hexed_core::transform::{ConcatJob, SplitJob};
use hexed_core::Progress;

use crate::Tab;

/// Bytes processed per frame.
const FRAME_BUDGET: u64 = 16 << 20;
/// Copy-as cap: the clipboard is no place for gigabytes.
const CLIPBOARD_MAX: u64 = 16 << 20;
/// Import cap: flattening the image materializes it all in RAM (the CLI
/// streams and has no such limit).
pub const IMPORT_MAX: u64 = 512 << 20;

enum ToolJob {
    /// F-30/F-31 — report or byte literal to a file.
    Export { tab: usize, job: ExportJob, w: BufWriter<File>, path: PathBuf },
    /// F-27/F-27a — Intel HEX / S-record.
    Record { tab: usize, job: RecordExportJob, w: BufWriter<File>, path: PathBuf },
    /// F-57.
    Split { tab: usize, job: SplitJob },
    /// F-58.
    Concat { job: ConcatJob, out: PathBuf },
}

pub struct ToolsState {
    job: Option<ToolJob>,
    progress: Progress,
    pub status: String,

    // F-31: the report dialog.
    pub report_open: bool,
    report_fmt: ExportFormat,
    report_sel: bool,

    // F-27/F-27a: the record export dialog.
    pub record_open: Option<RecordFormat>,
    record_addr: String,
    record_sel: bool,

    // F-57: the split dialog.
    pub split_open: bool,
    split_size: String,
}

impl Default for ToolsState {
    fn default() -> Self {
        Self {
            job: None,
            progress: Progress::new(),
            status: String::new(),
            report_open: false,
            report_fmt: ExportFormat::Txt,
            report_sel: false,
            record_open: None,
            record_addr: "0x0".into(),
            record_sel: false,
            split_open: false,
            split_size: "16m".into(),
        }
    }
}

impl ToolsState {
    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Export options inherited from the tab's view: the report comes out as
    /// the grid looks (columns, charset, base, starting offset — F-18/F-19/F-20).
    fn opts_for(tab: &Tab) -> ExportOptions {
        ExportOptions {
            cols: tab.view.cols as usize,
            charset: tab.view.charset,
            base: tab.view.offset_base,
            offset_start: tab.view.offset_start,
            ..Default::default()
        }
    }

    fn range_for(tab: &Tab, in_selection: bool) -> std::ops::Range<u64> {
        match tab.view.selection() {
            Some(sel) if in_selection => sel,
            _ => 0..tab.doc.len(),
        }
    }

    fn start(&mut self, job: ToolJob, total: u64) {
        self.progress = Progress::new();
        self.progress.set_total(total);
        self.status = "processing…".into();
        self.job = Some(job);
    }

    /// F-30 — Copies the selection as text in the given format. Blocking on
    /// purpose: the 16 MiB cap keeps the worst case short.
    pub fn copy_as(&mut self, tab: &mut Tab, fmt: ExportFormat, ctx: &egui::Context) {
        let Some(sel) = tab.view.selection() else {
            tab.view.status = "nothing selected".into();
            return;
        };
        if sel.end - sel.start > CLIPBOARD_MAX {
            tab.view.status = format!(
                "selection too large for the clipboard (max {} MiB); use Export",
                CLIPBOARD_MAX >> 20
            );
            return;
        }
        let opts = Self::opts_for(tab);
        match export::export_string(&mut tab.doc, sel.clone(), fmt, opts, &Progress::new()) {
            Ok(text) => {
                ctx.copy_text(text);
                tab.view.status =
                    format!("{} byte(s) copied as {}", sel.end - sel.start, fmt.name());
            }
            Err(e) => tab.view.status = e.to_string(),
        }
    }

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

    /// F-58 — Concatenates the files in the given order.
    pub fn start_concat(&mut self, inputs: &[PathBuf], out: PathBuf) {
        match ConcatJob::new(inputs, &out) {
            Ok(job) => {
                let total = job.total();
                self.start(ToolJob::Concat { job, out }, total);
            }
            Err(e) => self.status = e.to_string(),
        }
    }

    // ---- windows ----

    pub fn windows(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        self.report_window(ctx, tabs, active);
        self.record_window(ctx, tabs, active);
        self.split_window(ctx, tabs, active);
        self.progress_window(ctx);
    }

    /// The active job's progress bar + cancel button.
    fn progress_window(&mut self, ctx: &egui::Context) {
        if !self.busy() {
            return;
        }
        egui::Window::new("Operation in progress")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add(ProgressBar::new(self.progress.fraction()).desired_width(220.0));
                    if ui.button("Cancel").clicked() {
                        self.progress.cancel();
                    }
                });
            });
    }

    /// F-31 — Report in TXT/HTML/RTF/TeX (and the F-30 literals, if the user
    /// wants a giant .c on disk).
    fn report_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.report_open {
            return;
        }
        let mut open = true;
        let mut go = false;
        egui::Window::new("Export as text").open(&mut open).resizable(false).show(
            ctx,
            |ui| {
                ui.label("Format:");
                ui.horizontal(|ui| {
                    for fmt in [
                        ExportFormat::Txt,
                        ExportFormat::Html,
                        ExportFormat::Rtf,
                        ExportFormat::Tex,
                    ] {
                        ui.radio_value(&mut self.report_fmt, fmt, fmt.name());
                    }
                });
                ui.horizontal(|ui| {
                    for fmt in [
                        ExportFormat::HexText,
                        ExportFormat::C,
                        ExportFormat::Java,
                        ExportFormat::CSharp,
                        ExportFormat::Pascal,
                        ExportFormat::Python,
                    ] {
                        ui.radio_value(&mut self.report_fmt, fmt, fmt.name());
                    }
                });
                ui.checkbox(&mut self.report_sel, "selection only");
                ui.weak("columns, charset and base come out as in the grid");
                go = ui.add_enabled(!self.busy(), egui::Button::new("Export…")).clicked();
            },
        );
        self.report_open = open;
        if !go {
            return;
        }
        let Some(tab) = tabs.get_mut(active) else { return };
        let stem = tab.title.trim_start_matches('*').trim();
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("{stem}.{}", self.report_fmt.extension()))
            .save_file()
        else {
            return;
        };
        let range = Self::range_for(tab, self.report_sel);
        match File::create(&path) {
            Ok(f) => {
                let job =
                    ExportJob::new(self.report_fmt, Self::opts_for(tab), range, tab.doc.len());
                let total = job.total();
                self.start(
                    ToolJob::Export { tab: active, job, w: BufWriter::new(f), path },
                    total,
                );
                self.report_open = false;
            }
            Err(e) => self.status = e.to_string(),
        }
    }

    /// F-27/F-27a — Intel HEX / S-record export with a starting address.
    fn record_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        let Some(fmt) = self.record_open else { return };
        let mut open = true;
        let mut go = false;
        egui::Window::new(format!("Export {}", fmt.name()))
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label("Address of the first byte (0x8000, 4096…):");
                let r = ui.text_edit_singleline(&mut self.record_addr);
                go |= r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                ui.checkbox(&mut self.record_sel, "selection only");
                go |= ui.add_enabled(!self.busy(), egui::Button::new("Export…")).clicked();
            });
        if !open {
            self.record_open = None;
        }
        if !go {
            return;
        }
        let Some(tab) = tabs.get_mut(active) else { return };
        let Some(base) = crate::parse_num(&self.record_addr) else {
            self.status = "invalid address".into();
            return;
        };
        let range = Self::range_for(tab, self.record_sel);
        // Validate the (32-bit) addressing before asking for a path.
        let job = match RecordExportJob::new(fmt, range, base, DEFAULT_REC_LEN, tab.doc.len()) {
            Ok(job) => job,
            Err(e) => {
                self.status = e.to_string();
                return;
            }
        };
        let stem = tab.title.trim_start_matches('*').trim();
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("{stem}.{}", fmt.extension()))
            .save_file()
        else {
            return;
        };
        match File::create(&path) {
            Ok(f) => {
                let total = job.total();
                self.start(
                    ToolJob::Record { tab: active, job, w: BufWriter::new(f), path },
                    total,
                );
                self.record_open = None;
            }
            Err(e) => self.status = e.to_string(),
        }
    }

    /// F-57 — Split the document into parts.
    fn split_window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.split_open {
            return;
        }
        let mut open = true;
        let mut go = false;
        egui::Window::new("Split file").open(&mut open).resizable(false).show(ctx, |ui| {
            ui.label("Size of each part (700m, 0x1000, 512k…):");
            let r = ui.text_edit_singleline(&mut self.split_size);
            go |= r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            if let Some(tab) = tabs.get(active)
                && let Some(size) = parse_size(&self.split_size)
                && size > 0
            {
                ui.weak(format!("{} part(s)", tab.doc.len().div_ceil(size)));
            }
            go |= ui.add_enabled(!self.busy(), egui::Button::new("Split…")).clicked();
        });
        self.split_open = open;
        if !go {
            return;
        }
        let Some(tab) = tabs.get(active) else { return };
        let Some(size) = parse_size(&self.split_size) else {
            self.status = "invalid size".into();
            return;
        };
        let stem = tab.title.trim_start_matches('*').trim();
        let Some(prefix) = rfd::FileDialog::new()
            .set_title("Prefix for the parts (becomes prefix.000, .001…)")
            .set_file_name(stem)
            .save_file()
        else {
            return;
        };
        match SplitJob::new(tab.doc.len(), size, prefix) {
            Ok(job) => {
                let total = job.total();
                self.start(ToolJob::Split { tab: active, job }, total);
                self.split_open = false;
            }
            Err(e) => self.status = e.to_string(),
        }
    }
}

/// Sizes with a k/m/g suffix (binary), in decimal or hex — as in the CLI.
fn parse_size(s: &str) -> Option<u64> {
    let t = s.trim();
    let (num, shift) = match t.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('k') => (&t[..t.len() - 1], 10u32),
        Some('m') => (&t[..t.len() - 1], 20),
        Some('g') => (&t[..t.len() - 1], 30),
        _ => (t, 0),
    };
    let v = crate::parse_num(num)?;
    (v == 0 || v.leading_zeros() >= shift).then(|| v << shift)
}
