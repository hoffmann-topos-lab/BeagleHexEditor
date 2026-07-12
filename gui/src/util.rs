//! Small UI helpers shared across the GUI modules.

use eframe::egui::{self, Key, KeyboardShortcut};

use crate::shortcuts;

/// Enter inside a text field counts as submitting the dialog.
pub(crate) fn enter_in(resp: egui::Response, ui: &egui::Ui) -> bool {
    resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
}

/// Numbers in decimal or hexadecimal with 0x, as everywhere in the UI.
pub(crate) fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// F-60 — The first non-Escape key press in this frame, as a shortcut.
pub(crate) fn capture_combo(ctx: &egui::Context) -> Option<KeyboardShortcut> {
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
pub(crate) fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

/// Pasting from the menu needs to read the clipboard outside egui's event
/// flow. `arboard` is the dependency egui itself uses; here, since rfd already
/// pulls in GTK on Linux, we shell out to the system utility as a simple
/// fallback with no new dependency.
pub(crate) fn clipboard_text() -> Option<String> {
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
