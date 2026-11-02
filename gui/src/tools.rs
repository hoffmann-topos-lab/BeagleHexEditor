mod drive;
mod windows;


use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use eframe::egui::{self, Key};
use hexed_core::export::{self, ExportFormat, ExportJob, ExportOptions};
use hexed_core::hexfile::{DEFAULT_REC_LEN, RecordExportJob, RecordFormat};
use hexed_core::transform::{ConcatJob, SplitJob};
use hexed_core::Progress;

use crate::app::Tab;
use crate::jobs::{self, JobRunner};
/// Copy-as cap: the clipboard is no place for gigabytes.
const CLIPBOARD_MAX: u64 = 16 << 20;
/// Import cap: flattening the image materializes it all in RAM (the CLI
/// streams and has no such limit).
pub const IMPORT_MAX: u64 = 512 << 20;

pub(crate) enum ToolJob {
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
    run: JobRunner<ToolJob>,

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
            run: JobRunner::default(),
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
        self.run.busy()
    }

    /// The last job's status line (empty when none has run).
    pub fn status(&self) -> &str {
        &self.run.status
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

    /// F-58 — Concatenates the files in the given order.
    pub fn start_concat(&mut self, inputs: &[PathBuf], out: PathBuf) {
        match ConcatJob::new(inputs, &out) {
            Ok(job) => {
                let total = job.total();
                self.run.start(ToolJob::Concat { job, out }, total);
            }
            Err(e) => self.run.status = e.to_string(),
        }
    }
}
