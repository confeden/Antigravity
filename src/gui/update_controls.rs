use std::sync::mpsc::{self, Receiver, TryRecvError};

use eframe::egui;

use super::{theme, App};
#[cfg(not(windows))]
use crate::unix_update as installer;
#[cfg(windows)]
use crate::windows_shell as installer;
use installer::PreparedUpdate;

pub(super) type Task<T> = Receiver<Result<T, String>>;

#[derive(Default)]
pub(super) enum Update {
    #[default]
    Idle,
    Manual,
    Preparing(Task<PreparedUpdate>),
    Error(String),
    Restarting,
}

impl Update {
    pub(super) fn progress(&self) -> Option<&'static str> {
        match self {
            Self::Preparing(_) => Some("Скачиваем и проверяем обновление…"),
            Self::Restarting => Some("Перезапускаем AI Unlocker…"),
            _ => None,
        }
    }
}

pub(super) fn work<T: Send + 'static>(
    ctx: &egui::Context,
    job: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<Task<T>, String> {
    let ctx = ctx.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("gui-operation".into())
        .spawn(move || {
            let _ = tx.send(job());
            ctx.request_repaint();
        })
        .map_err(|error| error.to_string())?;
    Ok(rx)
}

pub(super) fn ready<T>(rx: &Task<T>) -> Option<Result<T, String>> {
    match rx.try_recv() {
        Ok(result) => Some(result),
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Disconnected) => Some(Err("Фоновая операция прервана".into())),
    }
}

pub(super) fn update_button(app: &mut App, ui: &mut egui::Ui) {
    let Some(release) = &app.update else { return };
    let color = theme::palette(ui).ok;
    let response = egui::Frame::new()
        .corner_radius(egui::CornerRadius::same(theme::RADIUS_SMALL))
        .shadow(egui::epaint::Shadow {
            offset: [0, 0],
            blur: 10,
            spread: 1,
            color: color.gamma_multiply(0.42),
        })
        .show(ui, |ui| {
            ui.add_enabled(
                !app.is_busy() && matches!(app.app_update, Update::Idle),
                egui::Button::new(
                    egui::RichText::new("Обновить AI Unlocker")
                        .color(color)
                        .strong(),
                )
                .fill(color.gamma_multiply(0.10))
                .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.76)))
                .corner_radius(egui::CornerRadius::same(theme::RADIUS_SMALL)),
            )
        })
        .inner
        .on_hover_text(format!(
            "Версия {} · скачивание и перезапуск",
            release.display_version()
        ));
    if response.clicked() {
        if installer::can_install(release) {
            let release = release.clone();
            app.app_update = match work(ui.ctx(), move || installer::prepare(&release)) {
                Ok(task) => Update::Preparing(task),
                Err(error) => Update::Error(error),
            };
        } else {
            app.app_update = Update::Manual;
        }
    }
}

pub(super) fn update_dialog(app: &mut App, ctx: &egui::Context) {
    if let Update::Preparing(rx) = &app.app_update {
        if let Some(result) = ready(rx) {
            if app.is_busy() && result.is_ok() {
                app.app_update = Update::Error(
                    "Дождитесь применения текущих настроек и повторите обновление.".into(),
                );
                return;
            }
            app.app_update = match result.and_then(PreparedUpdate::launch) {
                Ok(()) => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    Update::Restarting
                }
                Err(error) => Update::Error(error),
            };
        }
    }
    match &app.app_update {
        Update::Idle => {}
        Update::Manual => {
            let modal = egui::Modal::new(egui::Id::new("manual-update")).show(ctx, |ui| {
                ui.heading("Обновление AI Unlocker");
                ui.label("Скачайте установщик для своей системы со страницы релизов.");
                ui.button("Открыть релизы").clicked()
            });
            if modal.inner {
                crate::utils::open_url(crate::update::RELEASES_LATEST_URL);
            }
            if modal.inner || modal.should_close() {
                app.app_update = Update::Idle;
            }
        }
        Update::Preparing(_) | Update::Restarting => {
            egui::Modal::new(egui::Id::new("preparing-update")).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Подготовка обновления AI Unlocker…");
                });
            });
        }
        Update::Error(error) => {
            let modal = egui::Modal::new(egui::Id::new("update-error")).show(ctx, |ui| {
                ui.set_max_width(440.0);
                ui.heading("Обновление остановлено");
                ui.label(error);
                ui.button("Закрыть").clicked()
            });
            if modal.inner || modal.should_close() {
                app.app_update = Update::Idle;
            }
        }
    }
}
