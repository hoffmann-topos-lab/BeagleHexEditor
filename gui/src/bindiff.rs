//! Fase 13 (F-81) — Function diff window: compares the active tab (A) against
//! another open tab (B) and lists the changed/added/removed/renamed functions.
//!
//! Closes the provenance loop like the rest of the toolkit: **clicking a
//! function jumps to its bytes** — switching to the tab that owns it (A for
//! changed/removed/renamed/identical, B for added) and mapping the function's
//! virtual address back to a file offset through that binary's section table.
//! Button-driven and cached per compared pair.

use eframe::egui::{self, Color32, CollapsingHeader, ComboBox, RichText, Ui};
use hexed_core::{FuncDiffReport, Progress, Section, format, funcdiff};

use crate::app::Tab;

const ERR: Color32 = Color32::from_rgb(220, 90, 90);
/// Rows shown per bucket (a diff can have thousands).
const CAP: usize = 1000;

#[derive(Default)]
pub struct BindiffState {
    pub open: bool,
    /// The chosen B tab.
    other: Option<usize>,
    result: Option<Result<FuncDiffReport, String>>,
    /// The `(a, b)` tab pair the result was computed for.
    for_pair: Option<(usize, usize)>,
    sections_a: Vec<Section>,
    sections_b: Vec<Section>,
    show_identical: bool,
}

impl BindiffState {
    pub fn window(&mut self, ctx: &egui::Context, tabs: &mut [Tab], active: &mut usize) {
        if !self.open {
            return;
        }
        let a_idx = *active;
        // Keep `other` valid: never A, always in range.
        if self.other == Some(a_idx) {
            self.other = None;
        }
        if self.other.is_some_and(|o| o >= tabs.len()) {
            self.other = None;
        }
        let stale = self.result.is_some() && self.for_pair != self.other.map(|b| (a_idx, b));

        let mut open = true;
        let mut compare = false;
        let mut nav: Option<(usize, u64)> = None;

        egui::Window::new("Function diff (bindiff)").open(&mut open).default_width(540.0).show(
            ctx,
            |ui| {
                let a_title = tabs.get(a_idx).map(|t| t.title.as_str()).unwrap_or("—").to_string();
                ui.label(format!("A: {a_title}"));
                if tabs.len() < 2 {
                    ui.weak("open a second file in another tab to compare");
                    return;
                }
                ui.horizontal(|ui| {
                    ui.label("B:");
                    let b_title = self
                        .other
                        .and_then(|o| tabs.get(o))
                        .map(|t| t.title.as_str())
                        .unwrap_or("(pick a tab)");
                    ComboBox::from_id_salt("bindiff-b").selected_text(b_title).show_ui(ui, |ui| {
                        for (i, t) in tabs.iter().enumerate() {
                            if i != a_idx {
                                ui.selectable_value(&mut self.other, Some(i), &t.title);
                            }
                        }
                    });
                    compare = ui
                        .add_enabled(self.other.is_some(), egui::Button::new("Compare"))
                        .clicked();
                    ui.checkbox(&mut self.show_identical, "list identical");
                });
                if stale {
                    ui.weak("· inputs changed — press Compare");
                }
                ui.separator();

                match &self.result {
                    None => {
                        ui.weak("pick a second binary and press Compare");
                    }
                    Some(Err(e)) => {
                        ui.colored_label(ERR, e);
                    }
                    Some(Ok(rep)) => {
                        if let Some((a, b)) = self.for_pair {
                            nav = render(ui, rep, self.show_identical, a, b);
                        }
                    }
                }
            },
        );
        self.open = open;

        if compare {
            self.run(tabs, a_idx);
        }
        if let Some((ti, va)) = nav {
            self.navigate(tabs, active, ti, va);
        }
    }

    fn run(&mut self, tabs: &mut [Tab], a_idx: usize) {
        let Some(b_idx) = self.other else { return };
        let Some((a, b)) = two_mut(tabs, a_idx, b_idx) else { return };
        // Cache each binary's sections for click-to-navigate (cheap re-parse).
        self.sections_a = format::parse(&mut a.doc).map(|i| i.sections).unwrap_or_default();
        self.sections_b = format::parse(&mut b.doc).map(|i| i.sections).unwrap_or_default();
        self.result =
            Some(funcdiff::diff(&mut a.doc, &mut b.doc, &Progress::new()).map_err(|e| e.to_string()));
        self.for_pair = Some((a_idx, b_idx));
    }

    fn navigate(&self, tabs: &mut [Tab], active: &mut usize, ti: usize, va: u64) {
        let Some((a, _)) = self.for_pair else { return };
        let sections = if ti == a { &self.sections_a } else { &self.sections_b };
        let Some(off) = va_offset(sections, va) else { return };
        let Some(tab) = tabs.get_mut(ti) else { return };
        *active = ti;
        let len = tab.doc.len();
        tab.view.goto(off, len);
    }
}

/// Renders the report; returns the `(tab, va)` of a clicked function, if any.
fn render(ui: &mut Ui, rep: &FuncDiffReport, identical: bool, a: usize, b: usize) -> Option<(usize, u64)> {
    ui.label(
        RichText::new(format!(
            "{} identical · {} changed · {} added · {} removed · {} renamed",
            rep.identical.len(),
            rep.changed.len(),
            rep.added.len(),
            rep.removed.len(),
            rep.renamed.len(),
        ))
        .strong(),
    );
    ui.weak(format!("A: {} functions   B: {} functions   (click to jump)", rep.total_a, rep.total_b));
    ui.separator();

    let mut nav = None;
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        bucket(ui, &format!("changed ({})", rep.changed.len()), !rep.changed.is_empty(), |ui| {
            for c in rep.changed.iter().take(CAP) {
                row(ui, format!("{}  ({}→{} insns)", c.name, c.insns_a, c.insns_b), a, c.addr_a, &mut nav);
            }
            more(ui, rep.changed.len());
        });
        bucket(ui, &format!("renamed ({})", rep.renamed.len()), !rep.renamed.is_empty(), |ui| {
            for r in rep.renamed.iter().take(CAP) {
                row(ui, format!("{} → {}  ({} insns)", r.name_a, r.name_b, r.insns), a, r.address_a, &mut nav);
            }
            more(ui, rep.renamed.len());
        });
        bucket(ui, &format!("added in B ({})", rep.added.len()), !rep.added.is_empty(), |ui| {
            for f in rep.added.iter().take(CAP) {
                row(ui, format!("{}  ({} insns)", f.name, f.insns), b, f.address, &mut nav);
            }
            more(ui, rep.added.len());
        });
        bucket(ui, &format!("removed from A ({})", rep.removed.len()), !rep.removed.is_empty(), |ui| {
            for f in rep.removed.iter().take(CAP) {
                row(ui, format!("{}  ({} insns)", f.name, f.insns), a, f.address, &mut nav);
            }
            more(ui, rep.removed.len());
        });
        if identical {
            bucket(ui, &format!("identical ({})", rep.identical.len()), !rep.identical.is_empty(), |ui| {
                for f in rep.identical.iter().take(CAP) {
                    row(ui, f.name.clone(), a, f.address, &mut nav);
                }
                more(ui, rep.identical.len());
            });
        }
        if !rep.differs() {
            ui.weak("the two binaries are functionally identical");
        }
    });
    nav
}

fn bucket(ui: &mut Ui, title: &str, any: bool, body: impl FnOnce(&mut Ui)) {
    if any {
        CollapsingHeader::new(title).default_open(true).show(ui, body);
    }
}

fn row(ui: &mut Ui, label: String, tab: usize, va: u64, nav: &mut Option<(usize, u64)>) {
    let resp = ui.selectable_label(false, label).on_hover_text(format!("{va:#x}"));
    if resp.clicked() {
        *nav = Some((tab, va));
    }
}

fn more(ui: &mut Ui, total: usize) {
    if total > CAP {
        ui.weak(format!("… and {} more", total - CAP));
    }
}

/// Two distinct, in-range mutable references from one slice, as `(items[i], items[j])`.
fn two_mut<T>(items: &mut [T], i: usize, j: usize) -> Option<(&mut T, &mut T)> {
    if i == j || i >= items.len() || j >= items.len() {
        return None;
    }
    if i < j {
        let (l, r) = items.split_at_mut(j);
        Some((&mut l[i], &mut r[0]))
    } else {
        let (l, r) = items.split_at_mut(i);
        Some((&mut r[0], &mut l[j]))
    }
}

fn va_offset(sections: &[Section], va: u64) -> Option<u64> {
    let s = sections.iter().find(|s| !s.file.is_empty() && va >= s.vaddr && va < s.vaddr + s.size)?;
    Some(s.file.start + (va - s.vaddr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexed_core::format::Perms;

    #[test]
    fn two_mut_returns_the_requested_pair_in_order() {
        let mut v = vec![10, 20, 30, 40];
        let (a, b) = two_mut(&mut v, 1, 3).unwrap();
        assert_eq!((*a, *b), (20, 40));
        // Reversed indices keep the (i, j) order of the result.
        let (a, b) = two_mut(&mut v, 3, 1).unwrap();
        assert_eq!((*a, *b), (40, 20));
        *a = 99;
        assert_eq!(v[3], 99);
    }

    #[test]
    fn two_mut_rejects_equal_or_out_of_range() {
        let mut v = vec![1, 2];
        assert!(two_mut(&mut v, 0, 0).is_none());
        assert!(two_mut(&mut v, 0, 5).is_none());
    }

    #[test]
    fn va_offset_maps_through_the_section() {
        let secs = [Section {
            name: ".text".into(),
            file: 0x400..0x800,
            vaddr: 0x1000,
            size: 0x400,
            perms: Perms { r: true, w: false, x: true },
        }];
        assert_eq!(va_offset(&secs, 0x1040), Some(0x440));
        assert_eq!(va_offset(&secs, 0x9999), None);
    }
}
