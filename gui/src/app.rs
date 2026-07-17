//! The application state: tabs, preferences, and the per-frame plumbing.
//! File open/save lives in `files`, the menu bar in `menus`, the frame loop in
//! `frame`, modal dialogs in `dialogs` and `pickers`, tab comparison in
//! `compare`.

mod compare;
mod dialogs;
mod files;
mod frame;
mod menus;
mod pickers;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use hexed_core::compare::DiffJob;
use hexed_core::{Bookmarks, DiskInfo, Document};

use crate::analyze::AnalyzeState;
use crate::config::{Preferences, Theme};
use crate::hexview::HexView;
use crate::inspector::InspectorPanel;
use crate::recipe::RecipeState;
use crate::search::SearchState;
use crate::shortcuts::{Action, Shortcuts};
use crate::structure::StructureState;
use crate::tools::ToolsState;

/// F-43: identity of the on-disk file at the moment we read/saved it.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Fingerprint {
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

pub struct Tab {
    pub doc: Document,
    pub view: HexView,
    pub path: Option<PathBuf>,
    pub title: String,
    /// F-40: blocks editing in the UI (the buffer stays intact).
    pub read_only: bool,
    fp: Option<Fingerprint>,
    external_change: bool,
    /// F-16/F-17: Data Inspector state.
    pub inspector: InspectorPanel,
    /// F-23: bookmarks, persisted to the document's sidecar file.
    pub marks: Bookmarks,
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
pub struct App {
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
    /// Fase 9 (F-72): executable structure tree side panel.
    structure: StructureState,
    /// Fase 12 (F-80): transform-recipe window.
    recipe: RecipeState,
    /// F-32: tab comparison — (initiator, other).
    compare: Option<(usize, usize)>,
    diff_job: Option<DiffJob>,
    /// F-60/F-61/F-62: persistent preferences.
    pub prefs: Preferences,
    /// F-60: keyboard shortcuts (defaults + persisted overrides), and the
    /// rebind dialog state.
    pub shortcuts: Shortcuts,
    rebind_open: bool,
    rebind_recording: Option<Action>,
}

impl App {
    pub fn new(prefs: Preferences, shortcuts: Shortcuts) -> Self {
        Self { prefs, shortcuts, ..Default::default() }
    }

    /// F-62 — Push the theme preference into egui.
    pub fn apply_theme(&self, ctx: &egui::Context) {
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
