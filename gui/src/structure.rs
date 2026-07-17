//! F-72 — Structure panel: the executable's provenance tree (ELF/PE/Mach-O).
//!
//! Realizes the F-46 tree infra on the GUI side. The core parsers (Fase 9) build
//! a `Node` tree where every field carries the document byte range it came from
//! (`Node::span`); this panel renders that tree and wires it to the grid:
//! **clicking** a node selects its bytes, **hovering** highlights them — the
//! "where did this field come from" link the whole toolkit is built on.
//!
//! Parsing walks headers/tables via `Document::read`, so it is cached per tab and
//! only redone on tab switch or an explicit re-parse (the ⟳ button, for after
//! edits) rather than every frame.

use eframe::egui::{self, CollapsingHeader, RichText, Ui};
use hexed_core::format::{self, Node};

use crate::app::Tab;
use crate::hexview::HexView;

#[derive(Default)]
pub struct StructureState {
    pub open: bool,
    /// Parsed tree, or an error message. `None` before the first parse.
    result: Option<Result<Parsed, String>>,
    /// The `(tab index, document length)` the tree was parsed for. Re-parses on
    /// a tab switch or a length-changing edit; the ⟳ button forces the rest.
    parsed: Option<(usize, u64)>,
    force: bool,
}

struct Parsed {
    summary: String,
    tree: Node,
}

impl StructureState {
    pub fn panel(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: usize) {
        if !self.open {
            return;
        }
        let want = tabs.get(active).map(|t| (active, t.doc.len()));
        if self.force || self.parsed != want {
            self.reparse(tabs, active);
        }
        let Some(tab) = tabs.get_mut(active) else { return };
        let doc_len = tab.doc.len();
        let view = &mut tab.view;
        let result = &self.result;
        let mut want_reparse = false;

        egui::SidePanel::left("structure").default_width(300.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Structure");
                if ui.small_button("⟳").on_hover_text("re-parse (after edits)").clicked() {
                    want_reparse = true;
                }
            });
            ui.separator();
            match result {
                None => {
                    ui.weak("open an executable (ELF, PE or Mach-O)");
                }
                Some(Err(e)) => {
                    ui.weak(e);
                }
                Some(Ok(p)) => {
                    ui.label(RichText::new(&p.summary).strong());
                    ui.weak("click a field to select its bytes");
                    ui.separator();
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                        let mut id = 0u64;
                        show_node(ui, &p.tree, doc_len, view, &mut id, 0);
                    });
                }
            }
        });

        // One-frame-late is invisible; keeps the borrow of `self.result` above
        // from colliding with this write.
        if want_reparse {
            self.force = true;
        }
    }

    fn reparse(&mut self, tabs: &mut [Tab], active: usize) {
        self.force = false;
        let Some(tab) = tabs.get_mut(active) else {
            self.result = None;
            self.parsed = None;
            return;
        };
        self.parsed = Some((active, tab.doc.len()));
        self.result = Some(match format::parse(&mut tab.doc) {
            Ok(info) => Ok(Parsed {
                summary: format!(
                    "{} — {} {}, {}",
                    info.format.name(),
                    info.arch.name(),
                    info.bits.name(),
                    info.endian.name()
                ),
                tree: info.tree,
            }),
            Err(e) => Err(format!("not a recognised executable\n({e})")),
        });
    }
}

/// Renders one node and its subtree. `id` gives collapsing headers stable, unique
/// ids across frames (many nodes share a name — e.g. section entries).
fn show_node(ui: &mut Ui, node: &Node, doc_len: u64, view: &mut HexView, id: &mut u64, depth: usize) {
    *id += 1;
    let my_id = *id;

    if node.children.is_empty() {
        let label = if node.value.is_empty() {
            node.name.clone()
        } else {
            format!("{}: {}", node.name, node.value)
        };
        let resp = ui.selectable_label(false, label);
        wire(&resp, node, doc_len, view);
    } else {
        let resp = CollapsingHeader::new(&node.name)
            .id_salt(my_id)
            .default_open(depth < 1)
            .show(ui, |ui| {
                for child in &node.children {
                    show_node(ui, child, doc_len, view, id, depth + 1);
                }
            });
        wire(&resp.header_response, node, doc_len, view);
    }
}

/// Hover → highlight the node's bytes; click → select them and scroll there.
fn wire(resp: &egui::Response, node: &Node, doc_len: u64, view: &mut HexView) {
    if node.span.is_empty() {
        return;
    }
    if resp.hovered() {
        view.highlight = Some(node.span.clone());
    }
    if resp.clicked() {
        view.select_range(node.span.clone(), doc_len);
    }
    resp.clone().on_hover_text(format!("{:#x} … {:#x}", node.span.start, node.span.end));
}
