use std::sync::mpsc::{self, Receiver, TryRecvError};

use eframe::egui;

use super::{theme, App};
use crate::windows_shell::{self, PreparedUpdate};

type Task<T> = Receiver<Result<T, String>>;

#[derive(Default)]
pub(super) enum Update {
    #[default]
    Idle,
    Confirm,
    Manual,
    Preparing(Task<PreparedUpdate>),
    Error(String),
    Restarting,
}

#[derive(Default)]
pub(super) struct Startup {
    enabled: Option<bool>,
    error: Option<String>,
    task: Option<Task<bool>>,
}

fn work<T: Send + 'static>(
    ctx: &egui::Context,
    job: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<Task<T>, String> {
    let ctx = ctx.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("windows-shell".into())
        .spawn(move || {
            let _ = tx.send(job());
            ctx.request_repaint();
        })
        .map_err(|error| error.to_string())?;
    Ok(rx)
}

fn ready<T>(rx: &Task<T>) -> Option<Result<T, String>> {
    match rx.try_recv() {
        Ok(result) => Some(result),
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Disconnected) => Some(Err("Операция Windows прервана".into())),
    }
}

impl Startup {
    fn request(&mut self, ctx: &egui::Context, enabled: Option<bool>) {
        self.error = None;
        match work(ctx, move || windows_shell::startup(enabled)) {
            Ok(task) => self.task = Some(task),
            Err(error) => self.error = Some(error),
        }
    }

    pub(super) fn view(&mut self, ui: &mut egui::Ui) {
        if self.task.is_none() && self.enabled.is_none() && self.error.is_none() {
            self.request(ui.ctx(), None);
        }
        if let Some(result) = self.task.as_ref().and_then(ready) {
            self.task = None;
            match result {
                Ok(value) => self.enabled = Some(value),
                Err(error) => self.error = Some(error),
            }
        }
        let mut enabled = self.enabled.unwrap_or(false);
        if ui
            .add_enabled_ui(self.enabled.is_some() && self.task.is_none(), |ui| {
                ui.checkbox(&mut enabled, "Автозапуск оболочки AI Unlocker")
            })
            .inner
            .changed()
        {
            self.request(ui.ctx(), Some(enabled));
        }
        if let Some(error) = &self.error {
            ui.label(error);
            if self.enabled.is_none() && ui.button("Проверить снова").clicked() {
                self.request(ui.ctx(), None);
            }
        }
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
                !app.is_busy() && matches!(app.windows_update, Update::Idle),
                egui::Button::new(
                    egui::RichText::new("Доступно обновление")
                        .color(color)
                        .strong(),
                )
                .fill(color.gamma_multiply(0.10))
                .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.76)))
                .corner_radius(egui::CornerRadius::same(theme::RADIUS_SMALL)),
            )
        })
        .inner
        .on_hover_text(release.display_version());
    if response.clicked() {
        if windows_shell::can_install(release) {
            app.windows_update = Update::Confirm;
        } else {
            app.windows_update = Update::Manual;
        }
    }
}

pub(super) fn update_dialog(app: &mut App, ctx: &egui::Context) {
    if let Update::Preparing(rx) = &app.windows_update {
        if let Some(result) = ready(rx) {
            app.windows_update = match result.and_then(PreparedUpdate::launch) {
                Ok(()) => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    Update::Restarting
                }
                Err(error) => Update::Error(error),
            };
        }
    }
    match &app.windows_update {
        Update::Idle => {}
        Update::Manual => {
            let modal = egui::Modal::new(egui::Id::new("manual-update")).show(ctx, |ui| {
                ui.heading("Обновление AI Unlocker");
                ui.label("Для этой версии доступна ручная установка. Перед запуском установщика сохраните работу и закройте IDE.");
                ui.button("Открыть релизы").clicked()
            });
            if modal.inner {
                crate::utils::open_url(crate::update::RELEASES_LATEST_URL);
            }
            if modal.inner || modal.should_close() {
                app.windows_update = Update::Idle;
            }
        }
        Update::Confirm => {
            let modal = egui::Modal::new(egui::Id::new("confirm-update")).show(ctx, |ui| {
                ui.set_max_width(440.0);
                ui.heading("Обновить AI Unlocker?");
                ui.label("Сохраните работу. Поддерживаемые IDE закроются автоматически. Затем AI Unlocker закроется, обновится и запустится снова. Настройки сохранятся. Если IDE останется открытой, обновление остановится.");
                ui.horizontal(|ui| (ui.button("Обновить и перезапустить").clicked(), ui.button("Отмена").clicked())).inner
            });
            let (confirmed, cancelled) = modal.inner;
            if confirmed {
                if let Some(release) = app.update.clone() {
                    let roots = app
                        .status
                        .iter()
                        .flat_map(|status| status.installs.iter())
                        .filter_map(|row| row.path.clone())
                        .collect();
                    app.windows_update =
                        match work(ctx, move || windows_shell::prepare(&release, roots)) {
                            Ok(task) => Update::Preparing(task),
                            Err(error) => Update::Error(error),
                        };
                }
            } else if cancelled || modal.should_close() {
                app.windows_update = Update::Idle;
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
                app.windows_update = Update::Idle;
            }
        }
    }
}
