//! The small set of controls every screen is built from.
//!
//! There are deliberately only four: a switch, a card, a primary button and a
//! link. The brief was that everything is driven by switches — so a control
//! that is not one of these is a design mistake, not a missing widget.

use eframe::egui::{self, CornerRadius, Sense, Stroke};

use super::theme;

/// An iOS-style on/off switch.
///
/// Every capability in this tool is a switch: flipping it off *undoes* the
/// thing rather than hiding a menu item (the old build had separate "disable"
/// entries, which is the state living in two places). `enabled = false` draws
/// the switch dimmed and swallows clicks — used when the action needs admin and
/// the process is not elevated.
pub fn switch(ui: &mut egui::Ui, on: &mut bool, enabled: bool) -> egui::Response {
    let size = egui::vec2(42.0, 23.0);
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, mut resp) = ui.allocate_exact_size(size, sense);

    if enabled && resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }

    if ui.is_rect_visible(rect) {
        let how = ui.ctx().animate_bool_with_time(resp.id, *on, 0.12);
        let track = if *on {
            theme::ACCENT.gamma_multiply(if enabled { 1.0 } else { 0.4 })
        } else {
            theme::SUNKEN
        };
        let knob = if enabled {
            theme::TEXT
        } else {
            theme::MUTED.gamma_multiply(0.7)
        };

        let painter = ui.painter();
        painter.rect_filled(rect, CornerRadius::same(11), track);
        if !*on {
            painter.rect_stroke(
                rect,
                CornerRadius::same(11),
                Stroke::new(1.0, theme::LINE),
                egui::StrokeKind::Inside,
            );
        }
        let r = rect.height() / 2.0 - 3.0;
        let cx = egui::lerp((rect.left() + r + 3.0)..=(rect.right() - r - 3.0), how);
        painter.circle_filled(egui::pos2(cx, rect.center().y), r, knob);
    }

    if enabled {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        resp
    }
}

/// Room reserved on the right of a row for its switch: the 42 px control plus
/// the gap that keeps it off the card's edge.
pub const SWITCH_COLUMN: f32 = 62.0;

/// A row of text with a switch pinned to its right.
///
/// The text column is *allocated first, at a fixed width* rather than being left
/// to take what it wants. A wrapped label given the whole row claims all of it,
/// and the switch is then laid out past the right edge — drawn, but under the
/// text or off the card entirely. Every row that pairs prose with a switch has
/// to go through here for that reason; doing it by hand is how one row gets
/// missed.
///
/// Returns whether the switch was flipped.
pub fn switch_row(
    ui: &mut egui::Ui,
    on: &mut bool,
    enabled: bool,
    text: impl FnOnce(&mut egui::Ui),
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let text_w = (ui.available_width() - SWITCH_COLUMN).max(120.0);
        ui.allocate_ui_with_layout(
            egui::vec2(text_w, 0.0),
            egui::Layout::top_down(egui::Align::LEFT),
            |ui| {
                ui.set_max_width(text_w);
                text(ui);
            },
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            changed = switch(ui, on, enabled).changed();
        });
    });
    changed
}

/// A titled block. Everything on the main screen lives in one of these.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(theme::CARD)
        .corner_radius(CornerRadius::same(theme::RADIUS))
        .inner_margin(egui::Margin::same(14))
        .stroke(Stroke::new(1.0, theme::LINE))
        .show(ui, |ui| {
            // Cards line up only if they are all the same width; sized to their
            // contents, a short one sits visibly narrower than its neighbour.
            ui.set_min_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// The one filled button per screen — the action the user came to press.
pub fn primary(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    let btn = egui::Button::new(
        egui::RichText::new(text)
            .color(if enabled {
                egui::Color32::WHITE
            } else {
                theme::MUTED
            })
            .size(15.0),
    )
    .fill(if enabled {
        theme::ACCENT
    } else {
        theme::SUNKEN
    })
    .corner_radius(CornerRadius::same(theme::RADIUS_SMALL))
    .min_size(egui::vec2(0.0, 34.0));

    ui.add_enabled(enabled, btn)
}

/// A quiet outlined button: everything that is not *the* action.
pub fn ghost(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let btn = egui::Button::new(egui::RichText::new(text).color(theme::TEXT))
        .fill(theme::SUNKEN)
        .stroke(Stroke::new(1.0, theme::LINE))
        .corner_radius(CornerRadius::same(theme::RADIUS_SMALL));
    ui.add(btn)
}

/// Small grey explanatory text — the line under a switch that says what it does.
pub fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).color(theme::MUTED).size(12.5));
}

/// A coloured status dot, for install rows and provider rows.
pub fn dot(ui: &mut egui::Ui, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter().circle_filled(rect.center(), 4.0, color);
    }
}
