//! The report, record-export, split and progress windows.

use super::*;

impl ToolsState {
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
        let Some(base) = crate::util::parse_num(&self.record_addr) else {
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
    let v = crate::util::parse_num(num)?;
    (v == 0 || v.leading_zeros() >= shift).then(|| v << shift)
}
