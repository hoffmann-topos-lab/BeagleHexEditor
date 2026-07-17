
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod analyze;
mod app;
mod bindiff;
mod config;
mod detect;
mod disasm;
mod hexview;
mod inspector;
mod recipe;
mod search;
mod shortcuts;
mod structure;
mod tools;
mod util;

use std::path::PathBuf;

use app::App;
use config::Preferences;
use eframe::egui;

/// Window icon (title bar / Dock / taskbar), embedded in the binary. The same
/// artwork becomes the clickable icon of the .app bundle (macOS) and of the
/// hicolor theme (Linux) — see `packaging/`. The PNG is a versioned asset, so
/// an `expect` here would only fire if it were corrupted, which would break
/// the build immediately.
fn load_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon-256.png"))
        .expect("invalid embedded icon")
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_title("Beagle RE Toolkit")
            .with_icon(load_icon())
            // Matches `beagle-hex-editor.desktop` (Wayland/X11) so the
            // compositor associates the window with the installed icon.
            .with_app_id("beagle-hex-editor"),
        ..Default::default()
    };
    eframe::run_native(
        "hexed",
        options,
        Box::new(|cc| {
            let prefs = Preferences::load();
            let shortcuts = shortcuts::resolve(&prefs.shortcuts); // F-60
            let mut app = App::new(prefs, shortcuts);
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
