//! One place for every colour, radius and spacing the GUI uses.
//!
//! The design brief was "simple, buttons": one dark surface, one accent, and a
//! green/red pair that only ever means on/off. Anything that needs a *fourth*
//! colour is a sign the screen is doing too much.

use eframe::egui::{self, Color32, CornerRadius, Stroke};

/// Window background — the darkest surface, nothing sits behind it.
pub const BG: Color32 = Color32::from_rgb(0x14, 0x16, 0x1A);
/// A card: one step lighter than the window so its edge reads without a border.
pub const CARD: Color32 = Color32::from_rgb(0x1C, 0x1F, 0x26);
/// A control inside a card (text field, inactive switch track).
pub const SUNKEN: Color32 = Color32::from_rgb(0x24, 0x28, 0x31);
/// Hairline between rows. Deliberately barely visible.
pub const LINE: Color32 = Color32::from_rgb(0x2E, 0x33, 0x3D);

/// Primary text.
pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xE9, 0xEF);
/// Secondary text: descriptions, paths, hints.
pub const MUTED: Color32 = Color32::from_rgb(0x8B, 0x93, 0xA3);

/// The accent. Used for the active switch, focus rings and primary buttons.
pub const ACCENT: Color32 = Color32::from_rgb(0x4C, 0x8D, 0xFF);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x6A, 0xA1, 0xFF);

/// "On / succeeded".
pub const OK: Color32 = Color32::from_rgb(0x3F, 0xC1, 0x7C);
/// "Needs attention" — admin missing, a provider that stopped answering.
pub const WARN: Color32 = Color32::from_rgb(0xE8, 0xB3, 0x39);
/// "Off / failed".
pub const BAD: Color32 = Color32::from_rgb(0xE5, 0x63, 0x5F);

pub const RADIUS: u8 = 10;
pub const RADIUS_SMALL: u8 = 6;

/// Installs Segoe UI Semibold as the UI face, when the machine has it.
///
/// Loaded from the system font directory rather than embedded: Segoe UI is
/// licensed to Windows, not redistributable, so shipping the file inside the exe
/// would be a licensing problem. Reading the copy the user already has is not.
///
/// egui's own fonts stay behind it as fallbacks, so a glyph Segoe lacks still
/// renders and a machine without the file (any Linux box, a stripped Windows
/// image) simply keeps the default face instead of showing nothing.
fn install_font(ctx: &egui::Context) {
    let dir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
    // Semibold first, as asked; plain Segoe UI is the near-miss worth taking
    // before falling all the way back to Ubuntu-Light.
    let candidates = ["seguisb.ttf", "segoeui.ttf"];
    let Some((name, bytes)) = candidates.iter().find_map(|f| {
        let path = std::path::Path::new(&dir).join("Fonts").join(f);
        std::fs::read(&path).ok().map(|b| (*f, b))
    }) else {
        return;
    };

    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        name.to_string(),
        std::sync::Arc::new(egui::FontData::from_owned(bytes)),
    );
    // Proportional only. Segoe UI is not a monospaced face, and the two places
    // that ask for one — the licence key field and the install paths — are
    // exactly the places where columns lining up is the point.
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, name.to_string());
    ctx.set_fonts(fonts);
}

/// Applies the theme to a context. Called once at startup.
///
/// egui ships Ubuntu-Light and Hack as its default fonts and both carry the
/// Cyrillic block, so a Russian UI renders even when `install_font` finds
/// nothing — verified by running the licence screen, not assumed.
pub fn apply(ctx: &egui::Context) {
    install_font(ctx);

    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = BG;
    visuals.window_fill = BG;
    visuals.extreme_bg_color = SUNKEN;
    visuals.faint_bg_color = CARD;
    visuals.override_text_color = Some(TEXT);
    visuals.hyperlink_color = ACCENT;

    let r = CornerRadius::same(RADIUS_SMALL);
    visuals.widgets.noninteractive.bg_fill = CARD;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
    visuals.widgets.noninteractive.corner_radius = r;

    visuals.widgets.inactive.bg_fill = SUNKEN;
    visuals.widgets.inactive.weak_bg_fill = SUNKEN;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE);
    visuals.widgets.inactive.corner_radius = r;

    visuals.widgets.hovered.bg_fill = LINE;
    visuals.widgets.hovered.weak_bg_fill = LINE;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.hovered.corner_radius = r;

    visuals.widgets.active.bg_fill = ACCENT;
    visuals.widgets.active.weak_bg_fill = ACCENT;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT_HOVER);
    visuals.widgets.active.corner_radius = r;

    visuals.selection.bg_fill = ACCENT.gamma_multiply(0.4);
    visuals.selection.stroke = Stroke::new(1.0, TEXT);

    // Pinned to dark rather than following the OS: every colour above was picked
    // against BG, and half a theme is worse than the wrong one.
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.set_visuals_of(egui::Theme::Dark, visuals);

    ctx.all_styles_mut(|style| {
        use egui::{FontFamily::Proportional, FontId, TextStyle};
        style.text_styles = [
            (TextStyle::Heading, FontId::new(21.0, Proportional)),
            (TextStyle::Body, FontId::new(14.5, Proportional)),
            (TextStyle::Button, FontId::new(14.5, Proportional)),
            (TextStyle::Small, FontId::new(12.5, Proportional)),
            (
                TextStyle::Monospace,
                FontId::new(13.0, egui::FontFamily::Monospace),
            ),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.interact_size.y = 26.0;
        // Always visible and taking its own column, not floating over the
        // content: a bar that only appears on hover leaves no sign that there is
        // more below, and this window is taller than it fits.
        style.spacing.scroll.floating = false;
        style.spacing.scroll.bar_width = 8.0;
        style.spacing.scroll.bar_inner_margin = 2.0;
        style.spacing.scroll.bar_outer_margin = 0.0;
    });
}
