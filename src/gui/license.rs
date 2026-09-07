//! The licence gate — the first thing every start shows.
//!
//! Keys are free and rotate with each release (see `auth.rs`), so the screen's
//! real job is to point at the room they are pinned in. The check itself is a
//! local hash compare and is instant; nothing here sleeps.

use eframe::egui;

use super::{theme, widgets, App, Screen, TELEGRAM_KEYS_URL};
use crate::auth;

pub fn view(app: &mut App, ui: &mut egui::Ui) {
    // The outer frame keeps only 4 px on the right so the main screen's scroll
    // bar can sit in the border strip. This screen has no scroll bar, so it puts
    // the margin back itself instead of running to the window edge.
    ui.set_max_width(ui.available_width() - 14.0);
    ui.add_space(6.0);
    app.update_banner(ui);

    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        ui.label(
            egui::RichText::new("Antigravity Unlocker")
                .size(28.0)
                .strong(),
        );
    });

    ui.add_space(36.0);

    let normalized_len = app
        .key_input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .count();

    let now = std::time::Instant::now();
    let in_cooldown = match app.key_next_attempt {
        Some(target) if target > now => {
            // Wake egui as soon as the throttle expires so the button becomes clickable.
            ui.ctx().request_repaint_after(target.duration_since(now));
            true
        }
        _ => false,
    };
    let can_continue = normalized_len == 24 && !in_cooldown;

    widgets::card(ui, |ui| {
        ui.label(egui::RichText::new("Лицензионный ключ").size(15.0).strong());
        ui.add_space(8.0);

        let field = egui::TextEdit::singleline(&mut app.key_input)
            .hint_text("XXXXXXXXXXXX-XXXXXXXXXXXX")
            .horizontal_align(egui::Align::Center)
            .margin(egui::Margin::symmetric(10, 9))
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace);
        let resp = ui
            .add(field)
            .on_hover_text("Правый клик — вставить ключ из буфера обмена (поле очищается).");
        if app.key_needs_focus {
            resp.request_focus();
            app.key_needs_focus = false;
        }

        // Right click = replace, not append. The field holds exactly one key, so
        // "paste at the cursor" has no useful meaning here: the thing the user
        // wants is the key that is on the clipboard, and whatever half-typed
        // attempt is in the box is in the way. Nothing happens when the clipboard
        // holds no text, so a stray right click cannot wipe a key that was typed
        // by hand.
        if resp.secondary_clicked() {
            if let Some(text) = crate::utils::clipboard_text() {
                app.key_input = text.trim().to_string();
                app.key_rejected = false;
                resp.request_focus();
            }
        }

        // Enter submits, so a pasted key needs no mouse at all.
        let entered = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if resp.changed() {
            app.key_rejected = false;
        }

        ui.add_space(10.0);
        let mut pressed = false;
        ui.horizontal(|ui| {
            pressed = widgets::primary(ui, "Продолжить", can_continue).clicked();
            ui.add_space(8.0);
            if widgets::ghost(ui, "Взять ключ из группы").clicked() {
                crate::utils::open_url(TELEGRAM_KEYS_URL);
            }
        });

        if (entered || pressed) && normalized_len == 24 {
            let attempt_now = std::time::Instant::now();
            let still_cooling = match app.key_next_attempt {
                Some(target) if target > attempt_now => true,
                _ => false,
            };
            if !still_cooling {
                app.key_attempts.push(attempt_now);
                if let Some(cutoff) = attempt_now.checked_sub(std::time::Duration::from_secs(1)) {
                    app.key_attempts.retain(|&t| t >= cutoff);
                }
                if app.key_attempts.len() > 5 {
                    // Back off when attempts burst past 5 per second to throttle automated brute-force.
                    app.key_cooldown = (app.key_cooldown + std::time::Duration::from_millis(100))
                        .min(std::time::Duration::from_millis(1000));
                }
                let valid = auth::verify_key(app.key_input.trim());
                app.key_next_attempt = Some(std::time::Instant::now() + app.key_cooldown);

                if valid {
                    app.screen = Screen::Main;
                    // The key field is about to stop existing. Leaving egui's focus
                    // pointed at it makes the next key press land on whatever claims
                    // focus first on the main screen, and that widget gets scrolled
                    // into view - which reads as the window jumping on its own.
                    ui.ctx().memory_mut(|m| m.surrender_focus(resp.id));
                    // The first snapshot was taken while this screen was up; ask for
                    // a fresh one now in case anything changed in between.
                    app.worker.send(crate::ops::Cmd::Refresh);
                } else {
                    app.key_rejected = true;
                }
            }
        }

        if app.key_rejected {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("Ключ не подходит к этой версии анлокера.")
                    .color(theme::BAD)
                    .size(13.0),
            );
        }
    });

    let now_post = std::time::Instant::now();
    let in_cooldown_post = match app.key_next_attempt {
        Some(target) if target > now_post => {
            ui.ctx()
                .request_repaint_after(target.duration_since(now_post));
            true
        }
        _ => false,
    };

    if in_cooldown_post {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("Подождите…")
                .color(theme::MUTED)
                .size(12.5),
        );
    } else if !app.key_input.trim().is_empty() && normalized_len != 24 {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("Введите ключ подходящей длины")
                .color(theme::MUTED)
                .size(12.5),
        );
    }
}
