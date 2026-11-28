use eframe::egui;

use super::update_controls::{ready, work, Task};
use crate::windows_shell;

#[derive(Default)]
pub(super) struct Startup {
    enabled: Option<bool>,
    error: Option<String>,
    task: Option<Task<bool>>,
    applying: bool,
}
impl Startup {
    fn request(&mut self, ctx: &egui::Context, enabled: Option<bool>) {
        self.error = None;
        self.applying = enabled.is_some();
        match work(ctx, move || windows_shell::startup(enabled)) {
            Ok(task) => self.task = Some(task),
            Err(error) => {
                self.applying = false;
                self.error = Some(error);
            }
        }
    }

    pub(super) fn applying(&self) -> bool {
        self.applying
    }

    pub(super) fn tick(&mut self) {
        if let Some(result) = self.task.as_ref().and_then(ready) {
            self.task = None;
            self.applying = false;
            match result {
                Ok(value) => self.enabled = Some(value),
                Err(error) => self.error = Some(error),
            }
        }
    }

    pub(super) fn view(&mut self, ui: &mut egui::Ui) {
        if self.task.is_none() && self.enabled.is_none() && self.error.is_none() {
            self.request(ui.ctx(), None);
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
