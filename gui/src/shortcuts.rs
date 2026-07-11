//! F-60 — Configurable keyboard shortcuts.
//!
//! Each bindable `Action` has a built-in default; the user may rebind it, and
//! the override is persisted (as a `cmd+shift+s` string) in the preferences.
//! Modifiers are normalized to a canonical form so a binding recorded on macOS
//! and one written by hand compare identically at `consume_shortcut` time.

use std::collections::BTreeMap;

use eframe::egui::{Key, KeyboardShortcut, Modifiers};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Open,
    New,
    Save,
    SaveAs,
    Close,
    Undo,
    Redo,
    Goto,
    SelectAll,
    Find,
    FindNext,
    FindPrev,
    NextDiff,
}

impl Action {
    pub const ALL: [Action; 13] = [
        Action::Open,
        Action::New,
        Action::Save,
        Action::SaveAs,
        Action::Close,
        Action::Undo,
        Action::Redo,
        Action::Goto,
        Action::SelectAll,
        Action::Find,
        Action::FindNext,
        Action::FindPrev,
        Action::NextDiff,
    ];

    pub fn index(self) -> usize {
        self as usize
    }

    pub fn label(self) -> &'static str {
        match self {
            Action::Open => "Open",
            Action::New => "New",
            Action::Save => "Save",
            Action::SaveAs => "Save as",
            Action::Close => "Close tab",
            Action::Undo => "Undo",
            Action::Redo => "Redo",
            Action::Goto => "Go to offset",
            Action::SelectAll => "Select all",
            Action::Find => "Find",
            Action::FindNext => "Find next",
            Action::FindPrev => "Find previous",
            Action::NextDiff => "Next difference",
        }
    }

    /// Stable token used as the config key.
    pub fn config_key(self) -> &'static str {
        match self {
            Action::Open => "open",
            Action::New => "new",
            Action::Save => "save",
            Action::SaveAs => "save_as",
            Action::Close => "close",
            Action::Undo => "undo",
            Action::Redo => "redo",
            Action::Goto => "goto",
            Action::SelectAll => "select_all",
            Action::Find => "find",
            Action::FindNext => "find_next",
            Action::FindPrev => "find_prev",
            Action::NextDiff => "next_diff",
        }
    }

    pub fn default_shortcut(self) -> KeyboardShortcut {
        let cmd = Modifiers::COMMAND;
        let cmd_shift = Modifiers::COMMAND.plus(Modifiers::SHIFT);
        let (m, k) = match self {
            Action::Open => (cmd, Key::O),
            Action::New => (cmd, Key::N),
            Action::Save => (cmd, Key::S),
            Action::SaveAs => (cmd_shift, Key::S),
            Action::Close => (cmd, Key::W),
            Action::Undo => (cmd, Key::Z),
            Action::Redo => (cmd_shift, Key::Z),
            Action::Goto => (cmd, Key::G),
            Action::SelectAll => (cmd, Key::A),
            Action::Find => (cmd, Key::F),
            Action::FindNext => (Modifiers::NONE, Key::F3),
            Action::FindPrev => (Modifiers::SHIFT, Key::F3),
            Action::NextDiff => (Modifiers::NONE, Key::F6),
        };
        KeyboardShortcut::new(m, k)
    }
}

pub type ShortcutMap = [KeyboardShortcut; Action::ALL.len()];

/// The full set of shortcuts, defaulting to the built-ins. `App` holds one.
pub struct Shortcuts(pub ShortcutMap);

impl Default for Shortcuts {
    fn default() -> Self {
        Shortcuts(std::array::from_fn(|i| Action::ALL[i].default_shortcut()))
    }
}

impl std::ops::Index<Action> for Shortcuts {
    type Output = KeyboardShortcut;
    fn index(&self, a: Action) -> &KeyboardShortcut {
        &self.0[a.index()]
    }
}

/// Builds the shortcut set from the defaults plus any persisted overrides.
pub fn resolve(overrides: &BTreeMap<String, String>) -> Shortcuts {
    let mut set = Shortcuts::default();
    for a in Action::ALL {
        if let Some(s) = overrides.get(a.config_key())
            && let Some(sc) = parse(s)
        {
            set.0[a.index()] = sc;
        }
    }
    set
}

/// Collapses a platform's raw modifiers to the canonical logical set, so the
/// same chord is stored identically on every OS.
pub fn normalize(m: Modifiers) -> Modifiers {
    let mut out = Modifiers::NONE;
    if m.command {
        out = out.plus(Modifiers::COMMAND);
    }
    if m.ctrl && !m.command {
        out = out.plus(Modifiers::CTRL);
    }
    if m.alt {
        out = out.plus(Modifiers::ALT);
    }
    if m.shift {
        out = out.plus(Modifiers::SHIFT);
    }
    out
}

/// A human/config string like `cmd+shift+s`, `shift+f3`, `f6`.
pub fn format(sc: &KeyboardShortcut) -> String {
    let m = normalize(sc.modifiers);
    let mut parts: Vec<String> = Vec::new();
    if m.command {
        parts.push("cmd".into());
    }
    if m.ctrl {
        parts.push("ctrl".into());
    }
    if m.alt {
        parts.push("alt".into());
    }
    if m.shift {
        parts.push("shift".into());
    }
    parts.push(sc.logical_key.name().to_lowercase());
    parts.join("+")
}

/// A compact glyph form for menu hints, e.g. `⌘O`, `⇧⌘S`, `F3`.
pub fn symbol(sc: &KeyboardShortcut) -> String {
    let m = normalize(sc.modifiers);
    let mut s = String::new();
    if m.ctrl {
        s.push('⌃');
    }
    if m.alt {
        s.push('⌥');
    }
    if m.shift {
        s.push('⇧');
    }
    if m.command {
        s.push('⌘');
    }
    s.push_str(&sc.logical_key.name().to_uppercase());
    s
}

pub fn parse(s: &str) -> Option<KeyboardShortcut> {
    let mut mods = Modifiers::NONE;
    let mut key = None;
    for token in s.split('+').map(|t| t.trim()) {
        if token.is_empty() {
            continue;
        }
        match token.to_ascii_lowercase().as_str() {
            "cmd" | "command" | "super" | "win" => mods = mods.plus(Modifiers::COMMAND),
            "ctrl" | "control" => mods = mods.plus(Modifiers::CTRL),
            "alt" | "opt" | "option" => mods = mods.plus(Modifiers::ALT),
            "shift" => mods = mods.plus(Modifiers::SHIFT),
            name => key = key_from_name(name),
        }
    }
    key.map(|k| KeyboardShortcut::new(mods, k))
}

fn key_from_name(name: &str) -> Option<Key> {
    Key::ALL.iter().copied().find(|k| k.name().eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_format_as_expected() {
        assert_eq!(format(&Action::Open.default_shortcut()), "cmd+o");
        assert_eq!(format(&Action::SaveAs.default_shortcut()), "cmd+shift+s");
        assert_eq!(format(&Action::FindNext.default_shortcut()), "f3");
        assert_eq!(format(&Action::FindPrev.default_shortcut()), "shift+f3");
        assert_eq!(format(&Action::NextDiff.default_shortcut()), "f6");
    }

    #[test]
    fn every_default_round_trips_through_format_parse() {
        for a in Action::ALL {
            let sc = a.default_shortcut();
            let back = parse(&format(&sc)).expect("parses back");
            assert_eq!(back, sc, "{}", a.label());
        }
    }

    #[test]
    fn parse_is_lenient_about_case_and_aliases() {
        assert_eq!(parse("CMD+O"), parse("cmd+o"));
        assert_eq!(parse("control+shift+z"), parse("ctrl+shift+z"));
        assert!(parse("+++").is_none(), "no key means no shortcut");
        assert!(parse("cmd+notakey").is_none());
    }

    #[test]
    fn overrides_replace_only_the_named_action() {
        let mut ov = BTreeMap::new();
        ov.insert("save".to_string(), "cmd+alt+s".to_string());
        let set = resolve(&ov);
        assert_eq!(format(&set[Action::Save]), "cmd+alt+s", "overridden");
        assert_eq!(format(&set[Action::Open]), "cmd+o", "untouched default");
    }
}
