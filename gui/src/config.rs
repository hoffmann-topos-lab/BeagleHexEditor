//! F-60/F-61/F-62 — Persistent preferences.
//!
//! A human-readable `key = value` file (like the bookmarks sidecar), so the
//! user can read or edit it. No serde: the format is small and hand-rolled.
//! Stored under the platform config dir (`~/Library/Application Support/hexed/`
//! on macOS, `$XDG_CONFIG_HOME/hexed/` or `~/.config/hexed/` on Linux).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hexed_core::{Charset, OffsetBase};

/// F-62 — Which visuals to use.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    /// Follow the OS setting.
    System,
    Light,
    Dark,
}

impl Theme {
    pub const ALL: [Theme; 3] = [Theme::System, Theme::Light, Theme::Dark];

    pub fn label(self) -> &'static str {
        match self {
            Theme::System => "System",
            Theme::Light => "Light",
            Theme::Dark => "Dark",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    fn from_key(s: &str) -> Option<Theme> {
        Some(match s {
            "system" => Theme::System,
            "light" => Theme::Light,
            "dark" => Theme::Dark,
            _ => return None,
        })
    }
}

/// Stable serialization token for a charset. We do **not** use `Charset::name`
/// for this: some display names (e.g. "DOS (CP437)") do not round-trip through
/// `from_name`, whereas these tokens do.
fn charset_key(c: Charset) -> &'static str {
    match c {
        Charset::Ascii => "ascii",
        Charset::Windows1252 => "cp1252",
        Charset::Cp437 => "cp437",
        Charset::Ebcdic => "ebcdic",
        Charset::MacRoman => "macroman",
        Charset::Utf8 => "utf8",
        Charset::Utf16Le => "utf16le",
        Charset::Utf16Be => "utf16be",
    }
}

const RECENT_CAP: usize = 12;

pub struct Preferences {
    pub theme: Theme,
    // New-tab view defaults (F-18/F-19/F-20), mirrored from the last-used tab.
    pub cols: u64,
    pub group: u64,
    pub base: OffsetBase,
    pub charset: Charset,
    pub insert_default: bool,
    // F-65.
    pub backup_before_save: bool,
    // F-61.
    pub restore_session: bool,
    pub recent: Vec<PathBuf>,
    pub session: Vec<PathBuf>,
    // F-60: shortcut overrides, config_key → "cmd+o". Empty = all defaults.
    pub shortcuts: BTreeMap<String, String>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            cols: 16,
            group: 8,
            base: OffsetBase::Hex,
            charset: Charset::Ascii,
            insert_default: false,
            backup_before_save: true,
            restore_session: true,
            recent: Vec::new(),
            session: Vec::new(),
            shortcuts: BTreeMap::new(),
        }
    }
}

impl Preferences {
    /// F-61 — Records a just-opened file, most-recent first, without duplicates.
    pub fn add_recent(&mut self, path: PathBuf) {
        self.recent.retain(|p| p != &path);
        self.recent.insert(0, path);
        self.recent.truncate(RECENT_CAP);
    }

    pub fn load() -> Preferences {
        match config_path().and_then(|p| std::fs::read_to_string(p).ok()) {
            Some(text) => Preferences::parse(&text),
            None => Preferences::default(),
        }
    }

    pub fn save(&self) {
        let Some(path) = config_path() else { return };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, self.serialize());
    }

    fn parse(text: &str) -> Preferences {
        let mut p = Preferences::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            match k {
                "theme" => {
                    if let Some(t) = Theme::from_key(v) {
                        p.theme = t;
                    }
                }
                "cols" => {
                    if let Ok(n) = v.parse() {
                        p.cols = n;
                    }
                }
                "group" => {
                    if let Ok(n) = v.parse() {
                        p.group = n;
                    }
                }
                "base" => {
                    if let Some(b) = OffsetBase::from_name(v) {
                        p.base = b;
                    }
                }
                "charset" => {
                    if let Some(c) = Charset::from_name(v) {
                        p.charset = c;
                    }
                }
                "insert_default" => p.insert_default = v == "true",
                "backup_before_save" => p.backup_before_save = v == "true",
                "restore_session" => p.restore_session = v == "true",
                "recent" => p.recent.push(PathBuf::from(v)),
                "session" => p.session.push(PathBuf::from(v)),
                other => {
                    if let Some(action) = other.strip_prefix("shortcut.") {
                        p.shortcuts.insert(action.to_string(), v.to_string());
                    }
                }
            }
        }
        p.recent.truncate(RECENT_CAP);
        p
    }

    fn serialize(&self) -> String {
        let mut s = String::from("# hexed preferences\n");
        s.push_str(&format!("theme = {}\n", self.theme.key()));
        s.push_str(&format!("cols = {}\n", self.cols));
        s.push_str(&format!("group = {}\n", self.group));
        s.push_str(&format!("base = {}\n", self.base.name()));
        s.push_str(&format!("charset = {}\n", charset_key(self.charset)));
        s.push_str(&format!("insert_default = {}\n", self.insert_default));
        s.push_str(&format!("backup_before_save = {}\n", self.backup_before_save));
        s.push_str(&format!("restore_session = {}\n", self.restore_session));
        for r in &self.recent {
            s.push_str(&format!("recent = {}\n", r.display()));
        }
        for r in &self.session {
            s.push_str(&format!("session = {}\n", r.display()));
        }
        for (k, v) in &self.shortcuts {
            s.push_str(&format!("shortcut.{k} = {v}\n"));
        }
        s
    }
}

/// The preferences file path, or `None` if `$HOME` is unset.
fn config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    let dir = if cfg!(target_os = "macos") {
        PathBuf::from(&home).join("Library/Application Support/hexed")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|x| !x.is_empty())
            .map(|x| Path::new(&x).join("hexed"))
            .unwrap_or_else(|| PathBuf::from(&home).join(".config/hexed"))
    };
    Some(dir.join("config"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip_through_the_text_format() {
        let p = Preferences {
            theme: Theme::Dark,
            cols: 32,
            group: 4,
            base: OffsetBase::Dec,
            charset: Charset::Cp437,
            insert_default: true,
            backup_before_save: false,
            recent: vec![PathBuf::from("/a/b.bin"), PathBuf::from("/c.bin")],
            session: vec![PathBuf::from("/open.bin")],
            shortcuts: BTreeMap::from([("save".to_string(), "cmd+alt+s".to_string())]),
            ..Default::default()
        };

        let back = Preferences::parse(&p.serialize());
        assert!(back.theme == Theme::Dark);
        assert_eq!(back.cols, 32);
        assert_eq!(back.group, 4);
        assert_eq!(back.base, OffsetBase::Dec);
        assert_eq!(back.charset, Charset::Cp437, "CP437 must round-trip");
        assert!(back.insert_default);
        assert!(!back.backup_before_save);
        assert_eq!(back.recent, p.recent);
        assert_eq!(back.session, p.session);
        assert_eq!(back.shortcuts, p.shortcuts, "shortcut overrides round-trip");
    }

    #[test]
    fn every_charset_round_trips() {
        for c in Charset::ALL {
            let p = Preferences { charset: c, ..Default::default() };
            assert_eq!(Preferences::parse(&p.serialize()).charset, c, "{}", c.name());
        }
    }

    #[test]
    fn add_recent_dedups_caps_and_orders_most_recent_first() {
        let mut p = Preferences::default();
        for i in 0..20 {
            p.add_recent(PathBuf::from(format!("/f{i}")));
        }
        assert_eq!(p.recent.len(), RECENT_CAP, "capped");
        assert_eq!(p.recent[0], PathBuf::from("/f19"), "newest first");

        p.add_recent(PathBuf::from("/f10")); // re-open an existing one
        assert_eq!(p.recent[0], PathBuf::from("/f10"));
        assert_eq!(p.recent.iter().filter(|q| *q == &PathBuf::from("/f10")).count(), 1, "no dup");
    }

    #[test]
    fn unknown_keys_and_blank_lines_are_ignored() {
        let text = "# comment\n\nfuture_key = 42\ncols = 24\n";
        let p = Preferences::parse(text);
        assert_eq!(p.cols, 24);
    }
}
