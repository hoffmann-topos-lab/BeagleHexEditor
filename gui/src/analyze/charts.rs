//! F-29/F-30a charts: histogram and entropy-per-block.

use super::*;

/// F-29 — Histogram: 256 thin bars, anchored at zero, hover for detail.
pub(super) fn histogram_chart(ui: &mut Ui, counts: &[u64; 256], total: u64) {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 130.0), Sense::hover());
    let painter = ui.painter_at(rect);
    let weak = ui.visuals().weak_text_color().gamma_multiply(0.5);
    let max = counts.iter().max().copied().unwrap_or(0).max(1);
    let bw = rect.width() / 256.0;

    // Recessive grid: the baseline only.
    painter.line_segment(
        [rect.left_bottom(), rect.right_bottom()],
        Stroke::new(1.0, weak),
    );

    let hovered = resp
        .hover_pos()
        .map(|p| (((p.x - rect.left()) / bw) as usize).min(255));
    for (b, c) in counts.iter().enumerate() {
        if *c == 0 {
            continue;
        }
        let h = (*c as f64 / max as f64) as f32 * (rect.height() - 4.0);
        let x = rect.left() + b as f32 * bw;
        let color = if hovered == Some(b) { ACCENT } else { ACCENT.gamma_multiply(0.75) };
        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(x, rect.bottom() - h.max(1.0)),
                Pos2::new(x + bw.max(1.0), rect.bottom()),
            ),
            0.0,
            color,
        );
    }
    if let Some(b) = hovered
        && total > 0
    {
        let c = counts[b];
        let ch = if (0x20..0x7F).contains(&(b as u32)) {
            format!(" '{}'", b as u8 as char)
        } else {
            String::new()
        };
        resp.on_hover_text(format!(
            "{b:#04X}{ch} — {c} ({:.2}%)",
            c as f64 / total as f64 * 100.0
        ));
    }
}

/// F-30a — Entropy per block: a 0-to-8-bit range, gaps for unreadable blocks,
/// a click navigates to the block.
pub(super) fn entropy_chart(ui: &mut Ui, blocks: &[f32], block_size: u64) -> Option<u64> {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 90.0), Sense::click());
    let painter = ui.painter_at(rect);
    let weak = ui.visuals().weak_text_color().gamma_multiply(0.5);
    let n = blocks.len().max(1);
    let bw = rect.width() / n as f32;

    // Reference lines: 0 and 8 bits (a fixed scale — entropy is comparable
    // across files, so the ceiling does not float).
    painter.line_segment([rect.left_bottom(), rect.right_bottom()], Stroke::new(1.0, weak));
    painter.line_segment([rect.left_top(), rect.right_top()], Stroke::new(1.0, weak));

    let hovered = resp
        .hover_pos()
        .map(|p| (((p.x - rect.left()) / bw) as usize).min(n - 1));
    for (i, e) in blocks.iter().enumerate() {
        if e.is_nan() {
            continue; // unreadable block: a gap, not a zero
        }
        let h = (e / 8.0).clamp(0.0, 1.0) * rect.height();
        let x = rect.left() + i as f32 * bw;
        let color = if hovered == Some(i) { ACCENT } else { ACCENT.gamma_multiply(0.65) };
        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(x, rect.bottom() - h.max(1.0)),
                Pos2::new(x + bw.max(1.0), rect.bottom()),
            ),
            0.0,
            color,
        );
    }
    let mut clicked = None;
    if let Some(i) = hovered {
        let off = i as u64 * block_size;
        let e = blocks[i];
        let text = if e.is_nan() {
            format!("{off:#x} — unreadable block")
        } else {
            format!("{off:#x} — {e:.3} bits/byte")
        };
        if resp.clicked() {
            clicked = Some(off);
        }
        resp.on_hover_text(text);
    }
    clicked
}
