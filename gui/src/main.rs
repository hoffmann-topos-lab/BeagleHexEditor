
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod analyze;
mod config;
mod hexview;
mod inspector;
mod search;
mod shortcuts;
mod tools;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use analyze::AnalyzeState;
use eframe::egui::{self, Align2, Key, KeyboardShortcut};
use hexed_core::compare::DiffJob;
use hexed_core::{
    Bookmark, Bookmarks, Charset, DiskInfo, Document, ExportFormat, FillPattern, OffsetBase,
    RecordFormat, disks,
};
use hexview::{COLS_CHOICES, GROUP_CHOICES, HexView, parse_goto};
use inspector::InspectorPanel;
use search::SearchState;
use tools::ToolsState;

use config::{Preferences, Theme};
use shortcuts::{Action, Shortcuts};

/// Ícone da janela (barra de título / Dock / barra de tarefas), embutido no
/// binário. O mesmo desenho vira o ícone clicável do bundle .app (macOS) e do
/// tema hicolor (Linux) — ver `packaging/`. O PNG é um asset versionado, então
/// um `expect` aqui só dispararia se ele fosse corrompido, o que quebraria o
/// build imediatamente.
fn load_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon-256.png"))
        .expect("ícone embutido inválido")
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_title("Beagle Hex Editor")
            .with_icon(load_icon())
            // Casa com `beagle-hex-editor.desktop` (Wayland/X11) para o
            // compositor associar a janela ao ícone instalado.
            .with_app_id("beagle-hex-editor"),
        ..Default::default()
    };
    eframe::run_native(
        "hexed",
        options,
        Box::new(|cc| {
            let prefs = Preferences::load();
            let shortcuts = shortcuts::resolve(&prefs.shortcuts); // F-60
            let mut app = App { prefs, shortcuts, ..Default::default() };
            app.apply_theme(&cc.egui_ctx); // F-62

            // Files named on the command line win; otherwise restore the last
            // session (F-61).
            let cli: Vec<String> = std::env::args().skip(1).collect();
            if !cli.is_empty() {
                for arg in cli {
                    app.open_path(PathBuf::from(arg), &cc.egui_ctx);
                }
            } else if app.prefs.restore_session {
                for path in app.prefs.session.clone() {
                    if path.exists() {
                        app.open_path(path, &cc.egui_ctx);
                    }
                }
            }
            Ok(Box::new(app))
        }),
    )
}

/// F-43: identity of the on-disk file at the moment we read/saved it.
#[derive(PartialEq, Eq, Clone, Copy)]
struct Fingerprint {
    len: u64,
    mtime_ns: i128,
    ino: u64,
}

fn fingerprint(path: &std::path::Path) -> Option<Fingerprint> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(Fingerprint {
        len: m.len(),
        mtime_ns: m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
        ino: m.ino(),
    })
}

struct Tab {
    doc: Document,
    view: HexView,
    path: Option<PathBuf>,
    title: String,
    /// F-40: blocks editing in the UI (the buffer stays intact).
    read_only: bool,
    fp: Option<Fingerprint>,
    external_change: bool,
    /// F-16/F-17: Data Inspector state.
    inspector: InspectorPanel,
    /// F-23: bookmarks, persisted to the document's sidecar file.
    marks: Bookmarks,
}

impl Tab {
    fn untitled(n: usize) -> Self {
        Self {
            doc: Document::new(Box::new(hexed_core::MemSource::new(Vec::new()))),
            view: HexView::default(),
            path: None,
            title: format!("untitled {n}"),
            read_only: false,
            fp: None,
            external_change: false,
            inspector: InspectorPanel::default(),
            marks: Bookmarks::new(),
        }
    }

    /// F-23: writes the bookmarks to the sidecar file, if the document has a
    /// path. Without one, they live only in the tab until the first save.
    fn persist_marks(&mut self) {
        if let Some(path) = &self.path {
            let sidecar = Bookmarks::sidecar_for(path);
            if let Err(e) = self.marks.save(&sidecar) {
                self.view.status = format!("error saving bookmarks: {e}");
            }
        }
    }
}

/// What the unsaved-changes dialog is holding (F-44).
enum PendingClose {
    Tab(usize),
    Quit,
}

#[derive(Default)]
struct App {
    tabs: Vec<Tab>,
    active: usize,
    untitled_seq: usize,
    goto_open: bool,
    goto_text: String,
    pending_close: Option<PendingClose>,
    allow_quit: bool,
    last_stat: Option<Instant>,
    global_status: String,
    /// F-23: bookmarks side panel.
    bookmarks_open: bool,
    // F-21: the "select range" dialog.
    select_open: bool,
    select_start: String,
    select_value: String,
    select_end_mode: bool,
    // F-22: the "fill selection" dialog.
    fill_open: bool,
    fill_hex: String,
    fill_random: bool,
    // F-19: the "starting offset" dialog.
    offstart_open: bool,
    offstart_text: String,
    // F-23: the "add bookmark" dialog.
    bm_open: bool,
    bm_name: String,
    bm_desc: String,
    // F-48/F-49: the "open disk" picker.
    disk_picker_open: bool,
    disk_list: Vec<DiskInfo>,
    // F-45: the shred confirmation.
    shred_path: Option<PathBuf>,
    shred_ack: bool,
    /// Phase 3: search and replace.
    search: SearchState,
    /// Phase 4: analysis windows.
    analyze: AnalyzeState,
    /// Phase 6: import/export and transform.
    tools: ToolsState,
    /// F-32: tab comparison — (initiator, other).
    compare: Option<(usize, usize)>,
    diff_job: Option<DiffJob>,
    /// F-60/F-61/F-62: persistent preferences.
    prefs: Preferences,
    /// F-60: keyboard shortcuts (defaults + persisted overrides), and the
    /// rebind dialog state.
    shortcuts: Shortcuts,
    rebind_open: bool,
    rebind_recording: Option<Action>,
}

impl App {
    fn open_path(&mut self, path: PathBuf, _ctx: &egui::Context) {
        match Document::open(&path, false) {
            Ok(doc) => {
                let title = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string());
                let fp = fingerprint(&path);
                // F-23: bookmarks from the sidecar file, if it exists.
                let marks = Bookmarks::load(&Bookmarks::sidecar_for(&path)).unwrap_or_default();
                let mut view = HexView::default();
                self.apply_view_defaults(&mut view);
                self.prefs.add_recent(path.clone()); // F-61
                self.tabs.push(Tab {
                    doc,
                    view,
                    title,
                    path: Some(path),
                    read_only: false,
                    fp,
                    external_change: false,
                    inspector: InspectorPanel::default(),
                    marks,
                });
                self.active = self.tabs.len() - 1;
                self.save_prefs();
            }
            Err(e) => self.global_status = format!("error opening: {e}"),
        }
    }

    fn open_dialog(&mut self, ctx: &egui::Context) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.open_path(path, ctx);
        }
    }

    /// F-48 — Enumerate disks and show the picker.
    fn open_disk_picker(&mut self) {
        match disks::enumerate() {
            Ok(list) => {
                self.disk_list = list;
                self.disk_picker_open = true;
            }
            Err(e) => self.global_status = format!("could not list disks: {e}"),
        }
    }

    /// F-49/F-50/F-56 — Open a device as a **read-only** tab (F-40 default for
    /// disks). Direct access is tried first; if denied, the read is routed
    /// through the privileged helper, and a bare permission error becomes a hint.
    fn open_disk(&mut self, info: &DiskInfo) {
        let socket = helper_socket();
        match hexed_core::source::open_device(&info.node, info.block_size, false, &socket) {
            Ok(src) => {
                let mut view = HexView::default();
                self.apply_view_defaults(&mut view);
                view.status = format!(
                    "{} · {} · {} byte sectors{}",
                    info.node.display(),
                    if info.model.is_empty() { "disk" } else { &info.model },
                    info.block_size,
                    if info.is_mounted() { " · mounted (read-only)" } else { "" },
                );
                self.tabs.push(Tab {
                    doc: Document::new(src),
                    view,
                    title: format!("{} (disk)", info.id),
                    path: None, // never "Save" over a device; Save becomes Save-as
                    read_only: true,
                    fp: None,
                    external_change: false,
                    inspector: InspectorPanel::default(),
                    marks: Bookmarks::new(),
                });
                self.active = self.tabs.len() - 1;
                self.disk_picker_open = false;
            }
            Err(e) => self.global_status = privilege_hint(&e),
        }
    }

    /// F-62 — Push the theme preference into egui.
    fn apply_theme(&self, ctx: &egui::Context) {
        let pref = match self.prefs.theme {
            Theme::System => egui::ThemePreference::System,
            Theme::Light => egui::ThemePreference::Light,
            Theme::Dark => egui::ThemePreference::Dark,
        };
        ctx.options_mut(|o| o.theme_preference = pref);
    }

    /// F-18/F-19/F-20 — Seed a new tab's view from the saved defaults.
    fn apply_view_defaults(&self, view: &mut HexView) {
        view.cols = self.prefs.cols.clamp(1, 256);
        view.group = self.prefs.group.clamp(1, view.cols);
        view.offset_base = self.prefs.base;
        view.charset = self.prefs.charset;
        view.insert_mode = self.prefs.insert_default;
    }

    /// F-60/F-61 — Mirror the active tab's view into the defaults, capture the
    /// open session, and write the preferences to disk.
    fn save_prefs(&mut self) {
        if let Some(tab) = self.tabs.get(self.active) {
            self.prefs.cols = tab.view.cols;
            self.prefs.group = tab.view.group;
            self.prefs.base = tab.view.offset_base;
            self.prefs.charset = tab.view.charset;
        }
        self.prefs.session = self.tabs.iter().filter_map(|t| t.path.clone()).collect();
        self.prefs.save();
    }

    fn save_active(&mut self, save_as: bool) {
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        let path = match (&tab.path, save_as) {
            (Some(p), false) => Some(p.clone()),
            _ => rfd::FileDialog::new()
                .set_file_name(tab.title.trim_start_matches('*'))
                .save_file(),
        };
        let Some(path) = path else { return };
        tab.view.end_typing(); // never group typing across a save (F-39)

        // F-65: keep the previous version as a .bak before overwriting it.
        let mut backed_up = None;
        if self.prefs.backup_before_save {
            match hexed_core::backup_file(&path) {
                Ok(Some(bak)) => backed_up = bak.file_name().map(|n| n.to_string_lossy().into_owned()),
                Ok(None) => {}
                Err(e) => {
                    tab.view.status = format!("backup failed, save aborted: {e}");
                    return;
                }
            }
        }

        let saved = match tab.doc.save_as(&path) {
            Ok(()) => {
                tab.title = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string());
                tab.fp = fingerprint(&path);
                tab.path = Some(path.clone());
                tab.external_change = false;
                tab.view.status = match &backed_up {
                    Some(bak) => format!("saved (backup: {bak})"),
                    None => "saved".into(),
                };
                // F-23: a "save as" gives orphaned bookmarks a path.
                if !tab.marks.is_empty() {
                    tab.persist_marks();
                }
                true
            }
            Err(e) => {
                tab.view.status = format!("error saving: {e}");
                false
            }
        };
        if saved {
            self.prefs.add_recent(path); // F-61
            self.save_prefs();
        }
    }

    /// F-42: "Save selection as…"
    fn save_selection(&mut self) {
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        let Some(sel) = tab.view.selection() else {
            tab.view.status = "nothing selected".into();
            return;
        };
        let Some(path) = rfd::FileDialog::new().save_file() else { return };
        let result = (|| -> hexed_core::Result<()> {
            use std::io::Write;
            let mut f = std::fs::File::create(&path)?;
            let mut off = sel.start;
            while off < sel.end {
                let n = (sel.end - off).min(1 << 20) as usize;
                let r = tab.doc.read(off, n);
                if !r.is_clean() {
                    return Err(hexed_core::Error::new(
                        hexed_core::ErrorKind::BadBlock,
                        "the selection contains unreadable bytes",
                    ));
                }
                f.write_all(&r.data)?;
                off += n as u64;
            }
            Ok(())
        })();
        tab.view.status = match result {
            Ok(()) => format!("{} byte(s) exported", sel.end - sel.start),
            Err(e) => format!("error: {e}"),
        };
    }

    fn request_close_tab(&mut self, i: usize) {
        if self.tabs[i].doc.dirty() {
            self.pending_close = Some(PendingClose::Tab(i)); // F-44
        } else {
            self.close_tab(i);
        }
    }

    fn close_tab(&mut self, i: usize) {
        self.tabs.remove(i);
        if self.active >= self.tabs.len() {
            self.active = self.tabs.len().saturating_sub(1);
        }
    }

    /// F-27/F-27a — Imports Intel HEX or S-record (format detected from the
    /// first line) into a new tab, with the file's addresses preserved as the
    /// starting display offset (F-19).
    fn import_records(&mut self) {
        let Some(path) = rfd::FileDialog::new().pick_file() else { return };
        let parsed = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|text| hexed_core::hexfile::parse(&text).map_err(|e| e.to_string()));
        let (fmt, image) = match parsed {
            Ok(v) => v,
            Err(e) => {
                self.global_status = format!("error importing: {e}");
                return;
            }
        };
        let span = image.span().unwrap_or(0..0);
        if span.end - span.start > tools::IMPORT_MAX {
            self.global_status = format!(
                "a {} MiB image does not fit in a tab (max {} MiB); use `hexed {} import`",
                (span.end - span.start) >> 20,
                tools::IMPORT_MAX >> 20,
                if fmt == RecordFormat::IntelHex { "ihex" } else { "srec" },
            );
            return;
        }
        // 0xFF is a flash's erased state — the classic fill.
        let (base, bytes) = match image.flatten(0xFF) {
            Ok(v) => v,
            Err(e) => {
                self.global_status = format!("error importing: {e}");
                return;
            }
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let mut view = HexView::default();
        self.apply_view_defaults(&mut view);
        view.offset_start = base;
        view.status = format!(
            "{}: {} byte(s) of data from {base:#x}{}",
            fmt.name(),
            image.data_len(),
            image.entry.map(|e| format!(" · entry {e:#x}")).unwrap_or_default(),
        );
        self.tabs.push(Tab {
            doc: Document::new(Box::new(hexed_core::MemSource::new(bytes))),
            view,
            path: None, // "Save" becomes "Save as": never overwrite the .hex
            title: format!("{name} (imported)"),
            read_only: false,
            fp: None,
            external_change: false,
            inspector: InspectorPanel::default(),
            marks: Bookmarks::new(),
        });
        self.active = self.tabs.len() - 1;
    }

    /// F-43: once a second, checks whether any file changed on disk.
    fn poll_external_changes(&mut self, ctx: &egui::Context) {
        let now = Instant::now();
        if self.last_stat.is_some_and(|t| now - t < Duration::from_secs(1)) {
            ctx.request_repaint_after(Duration::from_secs(1));
            return;
        }
        self.last_stat = Some(now);
        for tab in &mut self.tabs {
            if let (Some(path), Some(old)) = (&tab.path, tab.fp)
                && let Some(new) = fingerprint(path)
                && new != old
            {
                tab.external_change = true;
            }
        }
        ctx.request_repaint_after(Duration::from_secs(1));
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_external_changes(ctx);

        // The inspector highlight (F-16) and the comparison diff (F-32) last
        // one frame: whoever wants to highlight does so again.
        for tab in &mut self.tabs {
            tab.view.highlight = None;
            tab.view.diff.clear();
        }

        // F-61: persist the open session whenever the window is asked to close.
        if ctx.input(|i| i.viewport().close_requested()) {
            self.save_prefs();
            // F-44: intercept the close if there are unsaved changes.
            if !self.allow_quit && self.tabs.iter().any(|t| t.doc.dirty()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.pending_close = Some(PendingClose::Quit);
            }
        }

        // Global shortcuts (F-60). While recording a rebind, none of them fire —
        // the keystrokes are being captured by the dialog instead.
        let (mut do_open, mut do_new, mut do_save, mut do_save_as, mut do_close) =
            (false, false, false, false, false);
        let (mut do_undo, mut do_redo, mut do_goto, mut do_selall) = (false, false, false, false);
        let (mut do_find, mut do_find_next, mut do_find_prev) = (false, false, false);
        let mut do_next_diff = false;
        if self.rebind_recording.is_none() {
            let sc = &self.shortcuts;
            ctx.input_mut(|i| {
                do_open = i.consume_shortcut(&sc[Action::Open]);
                do_new = i.consume_shortcut(&sc[Action::New]);
                do_save_as = i.consume_shortcut(&sc[Action::SaveAs]); // before Cmd+S
                do_save = i.consume_shortcut(&sc[Action::Save]);
                do_close = i.consume_shortcut(&sc[Action::Close]);
                do_redo = i.consume_shortcut(&sc[Action::Redo]); // before Cmd+Z
                do_undo = i.consume_shortcut(&sc[Action::Undo]);
                do_goto = i.consume_shortcut(&sc[Action::Goto]);
                do_selall = i.consume_shortcut(&sc[Action::SelectAll]);
                do_find = i.consume_shortcut(&sc[Action::Find]);
                do_find_prev = i.consume_shortcut(&sc[Action::FindPrev]); // before F3
                do_find_next = i.consume_shortcut(&sc[Action::FindNext]);
                do_next_diff = i.consume_shortcut(&sc[Action::NextDiff]);
            });
        }
        let mut do_magic = false;
        // Phase 5.
        let mut do_open_disk = false;
        // Phase 6.
        let mut do_import = false;
        let mut do_concat = false;
        let mut do_copy_as: Option<ExportFormat> = None;
        // Phase 8.
        let mut do_shred = false;
        // Phase 8: preferences captured into locals, applied after the menu so
        // the menu closure never mutably borrows `self.prefs`.
        let recent = self.prefs.recent.clone();
        let mut open_recent: Option<PathBuf> = None;
        let mut clear_recent = false;
        let mut theme_pref = self.prefs.theme;
        let mut backup_pref = self.prefs.backup_before_save;
        let mut restore_pref = self.prefs.restore_session;
        let mut insert_def_pref = self.prefs.insert_default;
        let mut open_rebind = false;
        // Menu accelerator hints, from the live bindings (F-60) so they stay
        // correct after a rebind.
        let hint: [String; Action::ALL.len()] =
            std::array::from_fn(|i| shortcuts::symbol(&self.shortcuts.0[i]));

        // Menus.
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    do_new |= ui.button(format!("New\t{}", hint[Action::New.index()])).clicked();
                    do_open |= ui.button(format!("Open…\t{}", hint[Action::Open.index()])).clicked();
                    if ui.button("Open disk…").clicked() {
                        do_open_disk = true;
                    }
                    ui.menu_button("Open recent", |ui| {
                        if recent.is_empty() {
                            ui.weak("no recent files");
                        }
                        for p in &recent {
                            if ui.button(p.display().to_string()).clicked() {
                                open_recent = Some(p.clone());
                            }
                        }
                        if !recent.is_empty() {
                            ui.separator();
                            if ui.button("Clear").clicked() {
                                clear_recent = true;
                            }
                        }
                    });
                    ui.separator();
                    do_save |= ui.button(format!("Save\t{}", hint[Action::Save.index()])).clicked();
                    do_save_as |= ui.button(format!("Save as…\t{}", hint[Action::SaveAs.index()])).clicked();
                    if ui.button("Save selection as…").clicked() {
                        self.save_selection();
                    }
                    ui.separator();
                    // Phase 6 — F-27/F-27a/F-30/F-31.
                    if ui.button("Import Intel HEX / S-record…").clicked() {
                        do_import = true;
                    }
                    ui.menu_button("Export", |ui| {
                        if ui.button("Intel HEX…").clicked() {
                            self.tools.record_open = Some(RecordFormat::IntelHex);
                        }
                        if ui.button("Motorola S-record…").clicked() {
                            self.tools.record_open = Some(RecordFormat::Srec);
                        }
                        if ui.button("As text (report, code)…").clicked() {
                            self.tools.report_open = true;
                        }
                    });
                    ui.separator();
                    do_close |= ui.button(format!("Close tab\t{}", hint[Action::Close.index()])).clicked();
                });
                ui.menu_button("Edit", |ui| {
                    do_undo |= ui.button(format!("Undo\t{}", hint[Action::Undo.index()])).clicked();
                    do_redo |= ui.button(format!("Redo\t{}", hint[Action::Redo.index()])).clicked();
                    ui.separator();
                    if let Some(tab) = self.tabs.get_mut(self.active) {
                        if ui.button("Copy\t⌘C").clicked() {
                            tab.view.copy_selection(&mut tab.doc, ctx);
                        }
                        if ui.button("Cut\t⌘X").clicked() {
                            let ro = tab.read_only;
                            tab.view.cut_selection(&mut tab.doc, ro, ctx);
                        }
                        // F-38: the two paste modes, made explicit.
                        for (label, ins) in
                            [("Paste overwriting", false), ("Paste inserting", true)]
                        {
                            if ui.button(label).clicked() {
                                let ro = tab.read_only;
                                if let Some(s) = clipboard_text() {
                                    tab.view.paste(&mut tab.doc, ro, &s, ins);
                                }
                            }
                        }
                        // F-30: the selection as text, in a chosen format.
                        ui.menu_button("Copy as", |ui| {
                            for fmt in ExportFormat::ALL {
                                if ui.button(fmt.name()).clicked() {
                                    do_copy_as = Some(fmt);
                                }
                            }
                        });
                    }
                    ui.separator();
                    // Phase 3: search and replace.
                    do_find |= ui.button(format!("Find…\t{}", hint[Action::Find.index()])).clicked();
                    do_find_next |= ui.button(format!("Find next\t{}", hint[Action::FindNext.index()])).clicked();
                    do_find_prev |= ui.button(format!("Find previous\t{}", hint[Action::FindPrev.index()])).clicked();
                    ui.separator();
                    do_selall |= ui.button(format!("Select all\t{}", hint[Action::SelectAll.index()])).clicked();
                    // F-21: selection by range.
                    if ui.button("Select range…").clicked() {
                        self.select_open = true;
                    }
                    do_goto |= ui.button(format!("Go to offset…\t{}", hint[Action::Goto.index()])).clicked();
                    ui.separator();
                    // F-22: fill the selection.
                    if ui.button("Fill selection…").clicked() {
                        self.fill_open = true;
                    }
                    // F-23: a bookmark at the cursor or over the selection.
                    if ui.button("Add bookmark…").clicked() {
                        self.bm_open = true;
                    }
                });
                // Phase 4 — outside the active-tab borrow: the comparison
                // submenu needs to list every tab.
                ui.menu_button("Analyze", |ui| {
                    if ui.button("Hashes and checksums…").clicked() {
                        self.analyze.hash_open = true;
                    }
                    if ui.button("Extract strings…").clicked() {
                        self.analyze.strings_open = true;
                    }
                    if ui.button("Statistics…").clicked() {
                        self.analyze.stats_open = true;
                    }
                    do_magic |= ui.button("Signatures…").clicked();
                    ui.separator();
                    // F-32: byte-by-byte comparison with another tab.
                    ui.menu_button("Compare with", |ui| {
                        if self.tabs.len() < 2 {
                            ui.weak("open another tab to compare");
                        }
                        for i in 0..self.tabs.len() {
                            if i != self.active
                                && ui.button(&self.tabs[i].title).clicked()
                            {
                                self.compare = Some((self.active, i));
                                self.diff_job = None;
                            }
                        }
                    });
                    if self.compare.is_some() {
                        do_next_diff |= ui.button(format!("Next difference\t{}", hint[Action::NextDiff.index()])).clicked();
                        if ui.button("Stop comparison").clicked() {
                            self.compare = None;
                            self.diff_job = None;
                        }
                    }
                });
                // Phase 6 — F-57/F-58.
                ui.menu_button("Tools", |ui| {
                    if ui.button("Split file into parts…").clicked() {
                        self.tools.split_open = true;
                    }
                    if ui.button("Concatenate files…").clicked() {
                        do_concat = true;
                    }
                    ui.separator();
                    if ui.button("Shred file…").clicked() {
                        do_shred = true; // F-45
                    }
                });
                if let Some(tab) = self.tabs.get_mut(self.active) {
                    // F-18/F-19/F-20 — all per tab, as in HxD.
                    ui.menu_button("View", |ui| {
                        ui.checkbox(&mut tab.inspector.open, "Data Inspector");
                        ui.checkbox(&mut self.bookmarks_open, "Bookmarks");
                        ui.separator();
                        ui.menu_button("Bytes per line", |ui| {
                            for n in COLS_CHOICES {
                                if ui
                                    .radio(tab.view.cols == n, n.to_string())
                                    .clicked()
                                {
                                    tab.view.cols = n;
                                }
                            }
                        });
                        ui.menu_button("Grouping", |ui| {
                            for n in GROUP_CHOICES {
                                if ui
                                    .radio(tab.view.group == n, format!("{n} byte(s)"))
                                    .clicked()
                                {
                                    tab.view.group = n;
                                }
                            }
                        });
                        ui.menu_button("Offset base", |ui| {
                            for base in OffsetBase::ALL {
                                if ui.radio(tab.view.offset_base == base, base.name()).clicked() {
                                    tab.view.offset_base = base;
                                }
                            }
                        });
                        ui.menu_button("Charset", |ui| {
                            for cs in Charset::ALL {
                                if ui.radio(tab.view.charset == cs, cs.name()).clicked() {
                                    tab.view.charset = cs;
                                }
                            }
                        });
                        if ui.button("Starting offset…").clicked() {
                            self.offstart_text = format!("{:#x}", tab.view.offset_start);
                            self.offstart_open = true;
                        }
                        // F-62 — theme (persisted).
                        ui.separator();
                        ui.menu_button("Theme", |ui| {
                            for t in Theme::ALL {
                                ui.radio_value(&mut theme_pref, t, t.label());
                            }
                        });
                    });
                    ui.menu_button("Mode", |ui| {
                        ui.checkbox(&mut tab.view.insert_mode, "Insert (Insert key)");
                        ui.checkbox(&mut tab.read_only, "Read-only");
                    });
                    // F-60/F-61/F-65 — persistent preferences.
                    ui.menu_button("Preferences", |ui| {
                        ui.checkbox(&mut backup_pref, "Back up before saving (.bak)");
                        ui.checkbox(&mut restore_pref, "Restore session on start");
                        ui.checkbox(&mut insert_def_pref, "New tabs start in insert mode");
                        ui.separator();
                        if ui.button("Keyboard shortcuts…").clicked() {
                            open_rebind = true;
                        }
                    });
                }
            });
        });

        // Phase 8: apply any preference changes made in the menus (F-60/F-62).
        let mut prefs_dirty = false;
        if theme_pref != self.prefs.theme {
            self.prefs.theme = theme_pref;
            self.apply_theme(ctx);
            prefs_dirty = true;
        }
        if backup_pref != self.prefs.backup_before_save {
            self.prefs.backup_before_save = backup_pref;
            prefs_dirty = true;
        }
        if restore_pref != self.prefs.restore_session {
            self.prefs.restore_session = restore_pref;
            prefs_dirty = true;
        }
        if insert_def_pref != self.prefs.insert_default {
            self.prefs.insert_default = insert_def_pref;
            prefs_dirty = true;
        }
        if clear_recent {
            self.prefs.recent.clear();
            prefs_dirty = true;
        }
        if prefs_dirty {
            self.save_prefs();
        }
        if open_rebind {
            self.rebind_open = true;
        }
        if let Some(p) = open_recent {
            self.open_path(p, ctx);
        }

        if do_new {
            self.untitled_seq += 1;
            let mut tab = Tab::untitled(self.untitled_seq);
            self.apply_view_defaults(&mut tab.view);
            self.tabs.push(tab);
            self.active = self.tabs.len() - 1;
        }
        if do_open {
            self.open_dialog(ctx);
        }
        if do_save {
            self.save_active(false);
        }
        if do_save_as {
            self.save_active(true);
        }
        if do_close && !self.tabs.is_empty() {
            self.request_close_tab(self.active);
        }
        if do_goto {
            self.goto_open = true;
        }
        // Phase 3: search.
        if do_find {
            self.search.open = true;
        }
        if do_find_next {
            self.search.start_next(&self.tabs, self.active, false);
        }
        if do_find_prev {
            self.search.start_next(&self.tabs, self.active, true);
        }
        if let Some(tab) = self.tabs.get_mut(self.active) {
            if do_undo {
                tab.view.end_typing();
                tab.doc.undo();
            }
            if do_redo {
                tab.view.end_typing();
                tab.doc.redo();
            }
            if do_selall {
                let len = tab.doc.len();
                tab.view.select_all(len);
            }
        }

        // Tab bar (F-10).
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                let mut close_req: Option<usize> = None;
                for (i, tab) in self.tabs.iter().enumerate() {
                    let dirty = if tab.doc.dirty() { "● " } else { "" };
                    let selected = i == self.active;
                    if ui.selectable_label(selected, format!("{dirty}{}", tab.title)).clicked() {
                        self.active = i;
                    }
                    if selected && ui.small_button("✕").clicked() {
                        close_req = Some(i);
                    }
                }
                if let Some(i) = close_req {
                    self.request_close_tab(i);
                }
            });
        });

        // Phase 3: search bar (below the tabs) and cooperative job (F-07).
        self.search.bar_ui(ctx, &mut self.tabs, &mut self.active);
        self.search.drive(&mut self.tabs, &mut self.active, ctx);
        // Phase 4: analysis jobs and windows.
        self.analyze.drive(&mut self.tabs, ctx);
        if do_magic && let Some(tab) = self.tabs.get_mut(self.active) {
            self.analyze.open_magic(tab);
        }
        self.analyze.windows(ctx, &mut self.tabs, self.active);
        // Phase 5: open a disk.
        if do_open_disk {
            self.open_disk_picker();
        }
        // Phase 8: pick a file to shred (F-45).
        if do_shred && let Some(p) = rfd::FileDialog::new().pick_file() {
            self.shred_path = Some(p);
            self.shred_ack = false;
        }
        // Phase 6: import/export, copy-as, split/concatenate.
        if do_import {
            self.import_records();
        }
        if do_concat
            && let Some(inputs) = rfd::FileDialog::new().pick_files()
            && let Some(out) =
                rfd::FileDialog::new().set_file_name("concatenated.bin").save_file()
        {
            // The order is the file picker's; the CLI gives explicit control.
            self.tools.start_concat(&inputs, out);
        }
        if let Some(fmt) = do_copy_as
            && let Some(tab) = self.tabs.get_mut(self.active)
        {
            self.tools.copy_as(tab, fmt, ctx);
        }
        self.tools.drive(&mut self.tabs, ctx);
        self.tools.windows(ctx, &mut self.tabs, self.active);
        self.compare_mode(ctx, do_next_diff);

        // Status bar.
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(tab) = self.tabs.get_mut(self.active) {
                    let c = tab.view.cursor;
                    ui.monospace(format!("Offset: {c:#X} ({c})"));
                    if let Some(sel) = tab.view.selection() {
                        ui.monospace(format!("Sel: {} byte(s)", sel.end - sel.start));
                    }
                    ui.separator();
                    // F-34: clickable, as in HxD.
                    let mode = if tab.view.insert_mode { "INS" } else { "OVR" };
                    if ui.selectable_label(false, mode).clicked() {
                        tab.view.insert_mode = !tab.view.insert_mode;
                    }
                    if tab.read_only {
                        ui.colored_label(egui::Color32::YELLOW, "read-only");
                    }
                    ui.separator();
                    ui.monospace(format!("{} byte(s)", tab.doc.len()));
                    if !tab.view.status.is_empty() {
                        ui.separator();
                        ui.label(&tab.view.status);
                    }
                } else if !self.global_status.is_empty() {
                    ui.label(&self.global_status);
                }
                // Phase 6: the last tool's result (progress has its own window
                // while it runs).
                if !self.tools.busy() && !self.tools.status.is_empty() {
                    ui.separator();
                    ui.label(&self.tools.status);
                }
            });
        });

        // F-15b: results list (above the status bar).
        self.search.results_ui(ctx, &mut self.tabs, &mut self.active);

        // F-43: external-modification banner.
        if let Some(tab) = self.tabs.get_mut(self.active)
            && tab.external_change
        {
            egui::TopBottomPanel::top("external").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 160, 40),
                        "⚠ the file changed on disk",
                    );
                    if ui.button("Reload").clicked()
                        && let Some(path) = tab.path.clone()
                        && let Ok(doc) = Document::open(&path, false)
                    {
                        let cursor = tab.view.cursor.min(doc.len());
                        let old = std::mem::take(&mut tab.view);
                        tab.doc = doc;
                        // Display options (F-18/F-19/F-20) survive the reload.
                        tab.view.cols = old.cols;
                        tab.view.group = old.group;
                        tab.view.offset_base = old.offset_base;
                        tab.view.offset_start = old.offset_start;
                        tab.view.charset = old.charset;
                        tab.view.goto(cursor, tab.doc.len());
                        tab.fp = fingerprint(&path);
                        tab.external_change = false;
                    }
                    if ui.button("Ignore").clicked() {
                        tab.external_change = false;
                        tab.fp = tab.path.as_deref().and_then(fingerprint);
                    }
                });
            });
        }

        // F-23: bookmarks panel (on the left, before the central panel).
        if self.bookmarks_open
            && let Some(tab) = self.tabs.get_mut(self.active)
        {
            let bm_open = &mut self.bm_open;
            egui::SidePanel::left("bookmarks").default_width(230.0).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Bookmarks");
                    if ui.small_button("＋").on_hover_text("bookmark cursor/selection").clicked() {
                        *bm_open = true;
                    }
                });
                ui.separator();
                if tab.marks.is_empty() {
                    ui.weak("no bookmarks");
                    return;
                }
                let mut remove: Option<usize> = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, b) in tab.marks.items().iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui.small_button("✕").on_hover_text("remove").clicked() {
                                remove = Some(i);
                            }
                            let label = format!("{:#x}  {}", b.offset, b.name);
                            let resp = ui.selectable_label(false, label);
                            let resp = if b.description.is_empty() {
                                resp
                            } else {
                                resp.on_hover_text(&b.description)
                            };
                            if resp.clicked() {
                                if b.len > 0 {
                                    tab.view
                                        .select_range(b.offset..b.offset + b.len, tab.doc.len());
                                } else {
                                    tab.view.goto(b.offset, tab.doc.len());
                                }
                            }
                        });
                    }
                });
                if let Some(i) = remove {
                    tab.marks.remove(i);
                    tab.persist_marks();
                }
            });
        }

        // F-16/F-17: Data Inspector (on the right, before the central panel).
        if let Some(tab) = self.tabs.get_mut(self.active)
            && tab.inspector.open
        {
            let ro = tab.read_only;
            egui::SidePanel::right("inspector").default_width(330.0).show(ctx, |ui| {
                ui.heading("Data Inspector");
                ui.separator();
                tab.inspector.show(ui, &mut tab.doc, &mut tab.view, ro);
            });
        }

        // The grid.
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(tab) = self.tabs.get_mut(self.active) {
                let ro = tab.read_only;
                tab.view.show(ui, &mut tab.doc, ro);
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("⌘O to open a file, ⌘N for a new document");
                });
            }
        });

        // "Go to offset" dialog (F-13).
        if self.goto_open {
            let mut submitted = false;
            egui::Window::new("Go to offset")
                .collapsible(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Absolute (0x1F4, 500) or relative (+0x10, -32):");
                    let r = ui.text_edit_singleline(&mut self.goto_text);
                    r.request_focus();
                    submitted = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                    ui.horizontal(|ui| {
                        submitted |= ui.button("Go").clicked();
                        if ui.button("Cancel").clicked()
                            || ui.input(|i| i.key_pressed(Key::Escape))
                        {
                            self.goto_open = false;
                        }
                    });
                });
            if submitted
                && let Some(tab) = self.tabs.get_mut(self.active)
            {
                // F-19: the user types offsets as they see them — with the
                // starting offset added. Convert back to the document.
                let start = tab.view.offset_start;
                let target = parse_goto(
                    &self.goto_text,
                    tab.view.cursor.saturating_add(start),
                    tab.doc.len().saturating_add(start),
                )
                .and_then(|display| display.checked_sub(start));
                match target {
                    Some(off) => {
                        tab.view.goto(off, tab.doc.len());
                        self.goto_open = false;
                        self.goto_text.clear();
                    }
                    None => tab.view.status = "invalid offset".into(),
                }
            }
        }

        // Unsaved-changes dialog (F-44).
        if let Some(pending) = &self.pending_close {
            let (title, names) = match pending {
                PendingClose::Tab(i) => {
                    ("Close tab with unsaved changes?", vec![self.tabs[*i].title.clone()])
                }
                PendingClose::Quit => (
                    "Quit with unsaved changes?",
                    self.tabs
                        .iter()
                        .filter(|t| t.doc.dirty())
                        .map(|t| t.title.clone())
                        .collect(),
                ),
            };
            let mut action: Option<&str> = None;
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    for n in &names {
                        ui.label(format!("● {n}"));
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            action = Some("save");
                        }
                        if ui.button("Discard").clicked() {
                            action = Some("discard");
                        }
                        if ui.button("Cancel").clicked() {
                            action = Some("cancel");
                        }
                    });
                });
            match (action, self.pending_close.take()) {
                (Some("save"), Some(PendingClose::Tab(i))) => {
                    self.active = i;
                    self.save_active(false);
                    if !self.tabs[i].doc.dirty() {
                        self.close_tab(i);
                    }
                }
                (Some("discard"), Some(PendingClose::Tab(i))) => self.close_tab(i),
                (Some("save"), Some(PendingClose::Quit)) => {
                    for i in 0..self.tabs.len() {
                        if self.tabs[i].doc.dirty() {
                            self.active = i;
                            self.save_active(false);
                        }
                    }
                    if !self.tabs.iter().any(|t| t.doc.dirty()) {
                        self.allow_quit = true;
                        self.save_prefs(); // F-61: session may have new save-as paths
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
                (Some("discard"), Some(PendingClose::Quit)) => {
                    self.allow_quit = true;
                    self.save_prefs(); // F-61
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                // No decision yet: hand the request back for the next frame.
                (None, Some(p)) => self.pending_close = Some(p),
                // "cancel" (or impossible states): just closes the dialog.
                _ => {}
            }
        }

        self.show_select_dialog(ctx); // F-21
        self.show_fill_dialog(ctx); // F-22
        self.show_offset_start_dialog(ctx); // F-19
        self.show_bookmark_dialog(ctx); // F-23
        self.show_disk_picker(ctx); // F-48/F-49
        self.show_shred_dialog(ctx); // F-45
        self.show_rebind_dialog(ctx); // F-60
    }
}

impl App {
    /// F-32 — Comparison mode: banner, synchronized scroll, highlight of the
    /// visible bytes that differ and a cooperative "next difference".
    fn compare_mode(&mut self, ctx: &egui::Context, mut do_next_diff: bool) {
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

    /// F-21 — Selection by range: starting offset + size or ending offset.
    fn show_select_dialog(&mut self, ctx: &egui::Context) {
        if !self.select_open {
            return;
        }
        let mut submitted = false;
        egui::Window::new("Select range")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Starting offset:");
                submitted |= enter_in(ui.text_edit_singleline(&mut self.select_start), ui);
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.select_end_mode, false, "Size");
                    ui.radio_value(&mut self.select_end_mode, true, "Ending offset (inclusive)");
                });
                submitted |= enter_in(ui.text_edit_singleline(&mut self.select_value), ui);
                ui.horizontal(|ui| {
                    submitted |= ui.button("Select").clicked();
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.select_open = false;
                    }
                });
            });
        if !submitted {
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        // The fields are display offsets (F-19): subtract the starting offset.
        let start = parse_num(&self.select_start)
            .and_then(|v| v.checked_sub(tab.view.offset_start));
        let value = parse_num(&self.select_value);
        let range = match (start, value, self.select_end_mode) {
            (Some(s), Some(end), true) => {
                end.checked_sub(tab.view.offset_start).and_then(|e| {
                    (e >= s).then_some(s..e.saturating_add(1))
                })
            }
            (Some(s), Some(len), false) if len > 0 => Some(s..s.saturating_add(len)),
            _ => None,
        };
        match range {
            Some(r) if r.start <= tab.doc.len() => {
                tab.view.select_range(r, tab.doc.len());
                tab.view.pane = hexview::Pane::Hex;
                self.select_open = false;
            }
            _ => tab.view.status = "invalid range".into(),
        }
    }

    /// F-22 — Fill the selection with a repeated pattern or random bytes.
    fn show_fill_dialog(&mut self, ctx: &egui::Context) {
        if !self.fill_open {
            return;
        }
        let selected = self
            .tabs
            .get(self.active)
            .and_then(|t| t.view.selection())
            .map(|s| s.end - s.start);
        let mut submitted = false;
        egui::Window::new("Fill selection")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                match selected {
                    Some(n) => ui.label(format!("{n} byte(s) selected")),
                    None => ui.colored_label(egui::Color32::YELLOW, "nothing selected"),
                };
                ui.radio_value(&mut self.fill_random, false, "Repeated hex pattern:");
                ui.add_enabled(
                    !self.fill_random,
                    egui::TextEdit::singleline(&mut self.fill_hex).hint_text("00, DE AD…"),
                );
                ui.radio_value(&mut self.fill_random, true, "Random bytes");
                ui.horizontal(|ui| {
                    submitted |= ui.button("Fill").clicked();
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.fill_open = false;
                    }
                });
            });
        if !submitted {
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        let Some(sel) = tab.view.selection() else {
            tab.view.status = "nothing selected".into();
            return;
        };
        if tab.read_only {
            tab.view.status = "read-only".into();
            return;
        }
        let pattern = if self.fill_random {
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            FillPattern::Random { seed }
        } else {
            match hexview::parse_hex(&self.fill_hex) {
                Some(bytes) => FillPattern::Repeat(bytes),
                None => {
                    tab.view.status = "the pattern is not valid hexadecimal".into();
                    return;
                }
            }
        };
        tab.view.end_typing(); // the fill does not merge with typing
        match tab.doc.fill(sel.start, sel.end - sel.start, &pattern) {
            Ok(()) => {
                tab.view.status = format!("{} byte(s) filled", sel.end - sel.start);
                self.fill_open = false;
            }
            Err(e) => tab.view.status = e.to_string(),
        }
    }

    /// F-19 — Custom starting offset (display only).
    fn show_offset_start_dialog(&mut self, ctx: &egui::Context) {
        if !self.offstart_open {
            return;
        }
        let mut submitted = false;
        egui::Window::new("Starting offset")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Added to every displayed offset (0x1000, 4096…):");
                let r = ui.text_edit_singleline(&mut self.offstart_text);
                r.request_focus();
                submitted |= enter_in(r, ui);
                ui.horizontal(|ui| {
                    submitted |= ui.button("Apply").clicked();
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.offstart_open = false;
                    }
                });
            });
        if !submitted {
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        match parse_num(&self.offstart_text) {
            Some(v) => {
                tab.view.offset_start = v;
                self.offstart_open = false;
            }
            None => tab.view.status = "invalid number".into(),
        }
    }

    /// F-23 — Add a bookmark at the cursor or over the selection.
    fn show_bookmark_dialog(&mut self, ctx: &egui::Context) {
        if !self.bm_open {
            return;
        }
        let mut submitted = false;
        egui::Window::new("Add bookmark")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                if let Some(tab) = self.tabs.get(self.active) {
                    match tab.view.selection() {
                        Some(s) => ui.label(format!(
                            "Region: {:#x} + {} byte(s)",
                            s.start,
                            s.end - s.start
                        )),
                        None => ui.label(format!("Position: {:#x}", tab.view.cursor)),
                    };
                }
                ui.label("Name:");
                submitted |= enter_in(ui.text_edit_singleline(&mut self.bm_name), ui);
                ui.label("Description:");
                submitted |= enter_in(ui.text_edit_singleline(&mut self.bm_desc), ui);
                ui.horizontal(|ui| {
                    submitted |= ui.button("Add").clicked();
                    if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.bm_open = false;
                    }
                });
            });
        if !submitted {
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        if self.bm_name.trim().is_empty() {
            tab.view.status = "the bookmark needs a name".into();
            return;
        }
        let (offset, len) = match tab.view.selection() {
            Some(s) => (s.start, s.end - s.start),
            None => (tab.view.cursor, 0),
        };
        tab.marks.add(Bookmark {
            offset,
            len,
            name: std::mem::take(&mut self.bm_name).trim().to_string(),
            description: std::mem::take(&mut self.bm_desc).trim().to_string(),
        });
        tab.persist_marks();
        self.bm_open = false;
        self.bookmarks_open = true; // show the result
    }

    /// F-48/F-49/F-51 — The disk picker: pick a device to open read-only.
    /// A mounted volume is flagged (F-51 — writing it is blocked until it is
    /// unmounted; for now disks open read-only anyway).
    fn show_disk_picker(&mut self, ctx: &egui::Context) {
        if !self.disk_picker_open {
            return;
        }
        let mut open = true;
        let mut chosen: Option<usize> = None;
        egui::Window::new("Open disk")
            .open(&mut open)
            .default_width(560.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Devices open read-only. Raw access needs privilege (sudo / helper).");
                if ui.button("↻ Refresh").clicked() {
                    match disks::enumerate() {
                        Ok(list) => self.disk_list = list,
                        Err(e) => self.global_status = format!("could not list disks: {e}"),
                    }
                }
                ui.separator();
                let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::vertical().max_height(340.0).show_rows(
                    ui,
                    row_h,
                    self.disk_list.len(),
                    |ui, rows| {
                        for i in rows {
                            let d = &self.disk_list[i];
                            let indent = if d.whole { "" } else { "    " };
                            let mount = d
                                .mount_point
                                .as_ref()
                                .map(|m| format!("  ⚠ mounted at {}", m.display()))
                                .unwrap_or_default();
                            let label = format!(
                                "{indent}{:<12} {:>13}  {:>4}B  {}{mount}",
                                d.id,
                                human_size(d.size),
                                d.block_size,
                                if d.model.is_empty() { "—" } else { &d.model },
                            );
                            if ui
                                .selectable_label(false, egui::RichText::new(label).monospace())
                                .clicked()
                            {
                                chosen = Some(i);
                            }
                        }
                    },
                );
            });
        self.disk_picker_open = open;
        if let Some(i) = chosen {
            let info = self.disk_list[i].clone();
            self.open_disk(&info);
        }
    }

    /// F-45 — The shred confirmation. The warning is not dismissable: the button
    /// stays disabled until the user checks the acknowledgement.
    fn show_shred_dialog(&mut self, ctx: &egui::Context) {
        let Some(path) = self.shred_path.clone() else { return };
        let mut open = true;
        let mut go = false;
        egui::Window::new("Shred file")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(egui::RichText::new(format!("Permanently shred:\n{}", path.display())).strong());
                ui.add_space(4.0);
                ui.colored_label(egui::Color32::from_rgb(200, 80, 40), format!("⚠ {}", hexed_core::shred::WARNING));
                ui.add_space(4.0);
                ui.checkbox(&mut self.shred_ack, "I understand this may not destroy the data");
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.shred_ack, egui::Button::new("Shred and delete"))
                        .clicked()
                    {
                        go = true;
                    }
                    if ui.button("Cancel").clicked() {
                        self.shred_path = None;
                    }
                });
            });
        if !open {
            self.shred_path = None;
        }
        if go {
            let status = match hexed_core::shred_file(&path, 1, true, &hexed_core::Progress::new()) {
                Ok(()) => format!("shredded and deleted {}", path.display()),
                Err(e) => format!("shred failed: {e}"),
            };
            self.global_status = status;
            self.shred_path = None;
        }
    }

    /// F-60 — Rebind keyboard shortcuts. "Rebind" starts recording; the next key
    /// combination is captured (Esc cancels). Changes persist immediately.
    fn show_rebind_dialog(&mut self, ctx: &egui::Context) {
        if !self.rebind_open {
            return;
        }
        let mut open = true;
        let mut changed = false;
        let mut reset_all = false;
        egui::Window::new("Keyboard shortcuts")
            .open(&mut open)
            .default_width(380.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                if let Some(action) = self.rebind_recording {
                    ui.label(
                        egui::RichText::new(format!(
                            "Press a key combination for “{}” — Esc to cancel",
                            action.label()
                        ))
                        .strong(),
                    );
                    if ctx.input(|i| i.key_pressed(Key::Escape)) {
                        self.rebind_recording = None;
                    } else if let Some(sc) = capture_combo(ctx) {
                        self.shortcuts.0[action.index()] = sc;
                        self.prefs
                            .shortcuts
                            .insert(action.config_key().to_string(), shortcuts::format(&sc));
                        self.rebind_recording = None;
                        changed = true;
                    }
                }
                ui.separator();
                egui::Grid::new("shortcuts").num_columns(3).spacing([12.0, 4.0]).show(ui, |ui| {
                    for a in Action::ALL {
                        ui.label(a.label());
                        ui.monospace(shortcuts::format(&self.shortcuts[a]));
                        ui.horizontal(|ui| {
                            let recording = self.rebind_recording == Some(a);
                            if ui.selectable_label(recording, "Rebind").clicked() {
                                self.rebind_recording = Some(a);
                            }
                            if ui.small_button("Reset").clicked() {
                                self.shortcuts.0[a.index()] = a.default_shortcut();
                                self.prefs.shortcuts.remove(a.config_key());
                                changed = true;
                            }
                        });
                        ui.end_row();
                    }
                });
                ui.separator();
                if ui.button("Reset all to defaults").clicked() {
                    reset_all = true;
                }
            });
        self.rebind_open = open;
        if !open {
            self.rebind_recording = None;
        }
        if reset_all {
            self.shortcuts = Shortcuts::default();
            self.prefs.shortcuts.clear();
            changed = true;
        }
        if changed {
            self.save_prefs();
        }
    }
}

/// F-60 — The first non-Escape key press in this frame, as a shortcut.
fn capture_combo(ctx: &egui::Context) -> Option<KeyboardShortcut> {
    ctx.input(|i| {
        for ev in &i.events {
            if let egui::Event::Key { key, pressed: true, modifiers, .. } = ev
                && *key != Key::Escape
            {
                return Some(KeyboardShortcut::new(shortcuts::normalize(*modifiers), *key));
            }
        }
        None
    })
}

/// Human-readable byte size for the disk picker.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

/// The helper socket path: `$HEXED_HELPER_SOCKET`, else the built-in default (F-47).
fn helper_socket() -> String {
    std::env::var("HEXED_HELPER_SOCKET")
        .unwrap_or_else(|_| hexed_core::DEFAULT_HELPER_SOCKET.to_string())
}

/// F-56 — Turn a bare permission error on a device into actionable guidance.
fn privilege_hint(e: &hexed_core::Error) -> String {
    if e.kind == hexed_core::ErrorKind::PermissionDenied {
        format!(
            "{e} — raw disk access needs privilege. Run with sudo, or install the \
             privileged helper (install-helper.sh) so it is used automatically."
        )
    } else {
        e.to_string()
    }
}

/// Enter inside a text field counts as submitting the dialog.
fn enter_in(resp: egui::Response, ui: &egui::Ui) -> bool {
    resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
}

/// Numbers in decimal or hexadecimal with 0x, as everywhere in the UI.
fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Pasting from the menu needs to read the clipboard outside egui's event
/// flow. `arboard` is the dependency egui itself uses; here, since rfd already
/// pulls in GTK on Linux, we shell out to the system utility as a simple
/// fallback with no new dependency.
fn clipboard_text() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("pbpaste").output().ok()?;
        String::from_utf8(out.stdout).ok()
    }
    #[cfg(not(target_os = "macos"))]
    {
        for (cmd, args) in [
            ("wl-paste", &["--no-newline"][..]),
            ("xclip", &["-selection", "clipboard", "-o"][..]),
        ] {
            if let Ok(out) = std::process::Command::new(cmd).args(args).output()
                && out.status.success()
            {
                return String::from_utf8(out.stdout).ok();
            }
        }
        None
    }
}
