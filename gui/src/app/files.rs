//! Opening (files, disks, record imports) and saving.

use std::path::PathBuf;

use eframe::egui;
use hexed_core::{Bookmarks, DiskInfo, Document, RecordFormat};

use crate::hexview::HexView;
use crate::inspector::InspectorPanel;
use crate::tools;

use super::{App, Tab, fingerprint};

impl App {
    pub fn open_path(&mut self, path: PathBuf, _ctx: &egui::Context) {
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

    pub(super) fn open_dialog(&mut self, ctx: &egui::Context) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.open_path(path, ctx);
        }
    }

    /// F-48 — Enumerate disks and show the picker.
    pub(super) fn open_disk_picker(&mut self) {
        match hexed_core::disks::enumerate() {
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
    pub(super) fn open_disk(&mut self, info: &DiskInfo) {
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

    pub(super) fn save_active(&mut self, save_as: bool) {
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

        // F-05/F-51: saving over the same file with an unchanged size writes only
        // the dirty bytes (fast on huge files). Save As, or a resized document,
        // takes the atomic full rewrite.
        let in_place = !save_as && tab.doc.can_save_in_place();
        let result =
            if in_place { tab.doc.save_in_place(&path).map(|_| ()) } else { tab.doc.save_as(&path) };
        let saved = match result {
            Ok(()) => {
                tab.title = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string());
                tab.fp = fingerprint(&path);
                tab.path = Some(path.clone());
                tab.external_change = false;
                tab.view.status = match (&backed_up, in_place) {
                    (Some(bak), _) => format!("saved (backup: {bak})"),
                    (None, true) => "saved in place".into(),
                    (None, false) => "saved".into(),
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
    pub(super) fn save_selection(&mut self) {
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

    /// F-27/F-27a — Imports Intel HEX or S-record (format detected from the
    /// first line) into a new tab, with the file's addresses preserved as the
    /// starting display offset (F-19).
    pub(super) fn import_records(&mut self) {
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
