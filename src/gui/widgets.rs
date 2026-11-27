//! Controls and Lucide glyphs shared by the native screens.

use eframe::egui::{self, CornerRadius, Sense, Stroke};

use super::theme;

// Glyphs from lucide-static 0.468.0, subset to these code points.
pub const OVERVIEW: &str = "\u{e1c0}";
pub const INTEGRATION: &str = "\u{e4fe}";
pub const SETTINGS: &str = "\u{e244}";
pub const LOG: &str = "\u{e10b}";
pub const POWER: &str = "\u{e143}";
pub const COPY: &str = "\u{e0a2}";
pub const SEND: &str = "\u{e155}";
pub const HEART: &str = "\u{e0f5}";
pub const MOON: &str = "\u{e121}";
pub const SUN: &str = "\u{e17b}";
pub const FOLDER: &str = "\u{e246}";
pub const CHECK: &str = "\u{e070}";
pub const ANSWER: &str = "\u{e225}";
pub const WAIT: &str = "\u{e08b}";
pub const ALERT: &str = "\u{e192}";
pub const REPAIR: &str = "\u{e1b0}";
pub const KEY: &str = "\u{e4a7}";
pub const ROUTE: &str = "\u{e542}";
pub const REFRESH: &str = "\u{e148}";
pub const DNS: &str = "\u{e0eb}";
pub const SERVER: &str = "\u{e156}";
pub const PROXY: &str = "\u{e41b}";
pub const GROUP: &str = "\u{e128}";

pub fn icon_text(icon: &str, label: &str, color: egui::Color32) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        icon,
        0.0,
        egui::TextFormat::simple(theme::icon_font(15.0), color),
    );
    if !label.is_empty() {
        job.append(
            label,
            8.0,
            egui::TextFormat::simple(egui::FontId::proportional(13.5), color),
        );
    }
    job
}

pub fn text_icon(label: &str, icon: &str, color: egui::Color32) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        label,
        0.0,
        egui::TextFormat::simple(egui::FontId::proportional(13.5), color),
    );
    if !icon.is_empty() {
        job.append(
            icon,
            6.0,
            egui::TextFormat::simple(theme::icon_font(14.0), color),
        );
    }
    job
}

pub fn command(
    ui: &mut egui::Ui,
    icon: &str,
    label: &str,
    highlighted: bool,
    enabled: bool,
) -> egui::Response {
    let colors = theme::palette(ui);
    let (ink, fill, border) = if highlighted {
        (colors.on_accent, colors.accent, colors.accent)
    } else {
        (colors.text, colors.sunken, colors.line)
    };
    let response = ui.add_enabled(
        enabled,
        egui::Button::new(icon_text(icon, label, ink))
            .fill(fill)
            .stroke(Stroke::new(1.0, border))
            .min_size(egui::vec2(0.0, 32.0)),
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, label));
    response
}

/// An iOS-style on/off switch.
///
/// Every capability in this tool is a switch: flipping it off *undoes* the
/// thing rather than hiding a menu item (the old build had separate "disable"
/// entries, which is the state living in two places). `enabled = false` draws
/// the switch dimmed and swallows clicks — used when the action needs admin and
/// the process is not elevated.
pub fn switch(ui: &mut egui::Ui, on: &mut bool, enabled: bool, label: &str) -> egui::Response {
    let size = egui::vec2(38.0, 26.0);
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
    resp.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, *on, label)
    });

    if ui.is_rect_visible(rect) {
        let colors = theme::palette(ui);
        let rect = rect.shrink2(egui::vec2(3.0, 4.0));
        let how = ui.ctx().animate_bool_with_time(resp.id, *on, 0.12);
        let track = if *on {
            colors
                .accent
                .gamma_multiply(if enabled { 1.0 } else { 0.4 })
        } else {
            colors.chrome
        };
        let knob = if *on && enabled {
            colors.on_accent
        } else {
            colors.muted
        };

        let painter = ui.painter();
        painter.rect_filled(rect, CornerRadius::same(11), track);
        if !*on {
            painter.rect_stroke(
                rect,
                CornerRadius::same(11),
                Stroke::new(1.0, colors.muted),
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

/// The switch target and the gap separating it from the row label.
pub const SWITCH_COLUMN: f32 = 46.0;

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
    label: &str,
    text: impl FnOnce(&mut egui::Ui),
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let text_w = (ui.available_width() - SWITCH_COLUMN).max(0.0);
        ui.allocate_ui_with_layout(
            egui::vec2(text_w, 0.0),
            egui::Layout::top_down(egui::Align::LEFT),
            |ui| {
                ui.set_max_width(text_w);
                text(ui);
            },
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            changed = switch(ui, on, enabled, label).changed();
        });
    });
    changed
}

/// A titled block. Everything on the main screen lives in one of these.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(theme::palette(ui).card)
        .corner_radius(CornerRadius::same(theme::RADIUS))
        .inner_margin(egui::Margin::same(14))
        .stroke(Stroke::new(1.0, theme::palette(ui).line))
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
                theme::palette(ui).on_accent
            } else {
                theme::palette(ui).muted
            })
            .size(15.0),
    )
    .fill(if enabled {
        theme::palette(ui).accent
    } else {
        theme::palette(ui).sunken
    })
    .corner_radius(CornerRadius::same(theme::RADIUS_SMALL))
    .min_size(egui::vec2(0.0, 34.0));

    ui.add_enabled(enabled, btn)
}

/// A quiet outlined button: everything that is not *the* action.
pub fn ghost(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let btn = egui::Button::new(egui::RichText::new(text).color(theme::palette(ui).text))
        .fill(theme::palette(ui).sunken)
        .stroke(Stroke::new(1.0, theme::palette(ui).line))
        .corner_radius(CornerRadius::same(theme::RADIUS_SMALL));
    ui.add(btn)
}

/// Small grey explanatory text — the line under a switch that says what it does.
pub fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .color(theme::palette(ui).muted)
            .size(12.5),
    );
}

/// The round «i» itself. `lit` while its text is showing.
pub fn info_button(ui: &mut egui::Ui, lit: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), Sense::click());
    if ui.is_rect_visible(rect) {
        let color = if lit || resp.hovered() {
            theme::palette(ui).accent
        } else {
            theme::palette(ui).muted
        };
        let painter = ui.painter();
        painter.circle_stroke(rect.center(), 7.0, Stroke::new(1.2, color));
        painter.text(
            rect.center() + egui::vec2(0.0, 0.5),
            egui::Align2::CENTER_CENTER,
            "i",
            egui::FontId::proportional(11.0),
            color,
        );
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text("Что это")
}

/// A coloured status dot, for install rows and provider rows.
pub fn dot(ui: &mut egui::Ui, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter().circle_filled(rect.center(), 4.0, color);
    }
}

/// Compact pill badge (e.g. FREE / PAID).
pub fn badge(ui: &mut egui::Ui, text: &str, fill: egui::Color32, ink: egui::Color32) {
    egui::Frame::new()
        .fill(fill)
        .corner_radius(CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(6, 1))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(11.0).strong().color(ink));
        });
}
