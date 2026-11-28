//! Storefront pairing and explicit PAID routing changes.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;

use crate::paid::PaidApp;

const STOREFRONT_BASE_URL: &str = "https://nova.gratis/store/";
const STATUS_CHECK_EVERY: Duration = Duration::from_secs(240 * 60);
const AWAITING_ISSUE_CHECK_EVERY: Duration = Duration::from_secs(10);
const AWAITING_ISSUE_WINDOW: Duration = Duration::from_secs(15 * 60);
const POST_ENABLE_TIMER_CHECK_DELAY: Duration = Duration::from_secs(15);
const FOCUS_RECHECK_COOLDOWN: Duration = Duration::from_secs(5);

fn storefront_url_with_code(code: &str) -> String {
    format!("{STOREFRONT_BASE_URL}#code={code}")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Clone, Copy)]
enum Action {
    Register,
    Check,
    Inspect,
    Apply,
}

#[derive(Clone)]
struct Transition {
    desired: Vec<PaidApp>,
    inspect_apps: Vec<PaidApp>,
    enable_mode: bool,
}

enum ResultValue {
    Registered,
    License(crate::paid::License),
    Inspected(Vec<&'static str>),
    Applied,
}

#[derive(Default)]
pub(super) struct PaidActivation {
    device: Option<crate::paid::Device>,
    license: crate::paid::License,
    pending: Option<(Action, Receiver<Result<ResultValue, String>>)>,
    pending_transition: Option<Transition>,
    confirm: Option<(Vec<PaidApp>, bool, Vec<&'static str>)>,
    next_check: Option<Instant>,
    last_check: Option<Instant>,
    was_focused: bool,
    checked_once: bool,
    awaiting_issue_until: Option<Instant>,
    open_store_after_register: bool,
    note: Option<String>,
    pending_logs: Vec<String>,
    applied: bool,
}

impl PaidActivation {
    pub(super) fn new() -> Self {
        if !crate::paid::Device::exists() {
            return Self::default();
        }
        match crate::paid::Device::load() {
            Ok(device) => {
                let mut license = crate::paid::License::default();
                if let Some(cache) = crate::paid::load_license_cache(&device.code) {
                    license = cache.license();
                }
                Self {
                    device: Some(device),
                    license,
                    next_check: Some(Instant::now()),
                    ..Self::default()
                }
            }
            Err(note) => Self {
                note: Some(note),
                ..Self::default()
            },
        }
    }

    pub(super) fn busy(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|(action, _)| !matches!(action, Action::Check))
    }

    pub(super) fn eligible(&self) -> bool {
        self.license.eligible
    }

    pub(super) fn checked_once(&self) -> bool {
        self.checked_once
    }

    pub(super) fn has_device(&self) -> bool {
        self.device.is_some()
    }

    pub(super) fn license_started(&self) -> bool {
        self.license.started
    }

    pub(super) fn expires_at(&self) -> Option<u64> {
        self.license.expires_at
    }

    pub(super) fn reason(&self) -> Option<crate::paid::LicenseReason> {
        self.license.reason
    }

    #[cfg(test)]
    pub(super) fn set_test_license(&mut self, license: crate::paid::License) {
        self.license = license;
    }

    pub(super) fn take_logs(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_logs)
    }

    pub(super) fn open_storefront(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        match crate::paid::Device::load_or_create() {
            Ok(device) => {
                let code = device.code.clone();
                self.device = Some(device);
                self.note = None;
                self.awaiting_issue_until = Some(Instant::now() + AWAITING_ISSUE_WINDOW);
                if self.license.eligible {
                    crate::utils::open_url_as_user(&storefront_url_with_code(&code));
                    self.next_check = Some(Instant::now() + Duration::from_secs(5));
                } else {
                    self.open_store_after_register = true;
                    self.launch(Action::Register, ctx);
                }
            }
            Err(error) => self.note = Some(error),
        }
    }

    pub(super) fn progress_message(&self) -> Option<&str> {
        if let Some((action, _)) = &self.pending {
            match action {
                Action::Register => return Some("Подготавливаем код PAID…"),
                Action::Inspect => return Some("Проверяем открытые IDE…"),
                Action::Apply => {
                    let enabling = self
                        .pending_transition
                        .as_ref()
                        .is_none_or(|t| t.enable_mode);
                    return Some(if enabling {
                        "Применяем маршрутизацию PAID…"
                    } else {
                        "Отключаем маршрутизацию PAID…"
                    });
                }
                Action::Check => {}
            }
        }
        None
    }

    pub(super) fn status_message(&self) -> Option<&str> {
        self.note.as_deref()
    }

    pub(super) fn take_applied(&mut self) -> bool {
        std::mem::take(&mut self.applied)
    }

    pub(super) fn request_apps(&mut self, desired: Vec<PaidApp>, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        self.note = None;
        let current = crate::paid::active_apps();
        let added: Vec<PaidApp> = desired
            .iter()
            .copied()
            .filter(|app| !current.contains(app))
            .collect();
        let removed: Vec<PaidApp> = current
            .iter()
            .copied()
            .filter(|app| !desired.contains(app))
            .collect();
        let (inspect_apps, enable_mode) = if !added.is_empty() {
            (added, true)
        } else {
            (removed, false)
        };
        self.pending_transition = Some(Transition {
            desired,
            inspect_apps,
            enable_mode,
        });
        self.launch(Action::Inspect, ctx);
    }

    fn launch(&mut self, action: Action, ctx: &egui::Context) {
        let device = self.device.clone();
        let inspect_apps = self
            .pending_transition
            .as_ref()
            .map(|t| t.inspect_apps.clone())
            .unwrap_or_default();
        let apply_apps = self
            .pending_transition
            .as_ref()
            .map(|t| t.desired.clone())
            .unwrap_or_default();
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        let thread = std::thread::Builder::new()
            .name("paid-activation".into())
            .spawn(move || {
                let result = match action {
                    Action::Inspect => crate::paid_windows::running_for(&inspect_apps)
                        .map(ResultValue::Inspected),
                    Action::Apply => crate::paid_windows::transition_apps(&apply_apps)
                        .map(|()| ResultValue::Applied),
                    Action::Register => device
                        .ok_or("Сначала получите код устройства".to_string())
                        .and_then(|device| device.register().map(|()| ResultValue::Registered)),
                    Action::Check => device
                        .ok_or("Сначала получите код устройства".to_string())
                        .and_then(|device| device.check().map(ResultValue::License)),
                };
                let _ = tx.send(result);
                ctx.request_repaint();
            });
        match thread {
            Ok(_) => self.pending = Some((action, rx)),
            Err(error) => {
                self.pending_transition = None;
                self.note = Some(error.to_string());
            }
        }
    }

    pub(super) fn tick(&mut self, ctx: &egui::Context) {
        if let Some((action, rx)) = &self.pending {
            let action = *action;
            let result = match rx.try_recv() {
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => Err("Операция прервалась".into()),
                Ok(result) => result,
            };
            self.pending = None;
            let now = Instant::now();
            match result {
                Ok(ResultValue::License(license)) => {
                    self.license = license;
                    self.checked_once = true;
                    self.last_check = Some(now);
                    if let Some(device) = &self.device {
                        let _ = crate::paid::save_license_cache(&crate::paid::LicenseCache {
                            device_code: device.code.clone(),
                            checked_at: now_unix(),
                            eligible: license.eligible,
                            started: license.started,
                            expires_at: license.expires_at,
                            reason: license.reason,
                        });
                    }
                    if license.eligible {
                        self.awaiting_issue_until = None;
                        self.next_check = Some(now + STATUS_CHECK_EVERY);
                    } else if self.awaiting_issue_until.is_some_and(|until| until > now) {
                        self.next_check = Some(now + AWAITING_ISSUE_CHECK_EVERY);
                    } else {
                        self.awaiting_issue_until = None;
                        self.next_check = Some(now + STATUS_CHECK_EVERY);
                    }
                }
                Ok(ResultValue::Registered) => {
                    let open_store = std::mem::take(&mut self.open_store_after_register);
                    self.note = self.device.as_ref().map(|device| {
                        let _ = crate::utils::set_clipboard_text(&device.code);
                        if open_store {
                            crate::utils::open_url_as_user(&storefront_url_with_code(&device.code));
                            format!("Витрина открыта с кодом {}", device.code)
                        } else {
                            format!("Код PAID: {}", device.code)
                        }
                    });
                    self.next_check = Some(now + Duration::from_secs(5));
                }
                Ok(ResultValue::Inspected(running)) => {
                    if running.is_empty() {
                        self.launch(Action::Apply, ctx);
                        return;
                    }
                    if let Some(transition) = self.pending_transition.take() {
                        self.confirm =
                            Some((transition.desired, transition.enable_mode, running));
                    }
                }
                Ok(ResultValue::Applied) => {
                    self.pending_transition = None;
                    self.note = None;
                    self.applied = true;
                    if crate::paid::enabled() && self.license.expires_at.is_none() {
                        self.next_check = Some(now + POST_ENABLE_TIMER_CHECK_DELAY);
                    }
                }
                Err(error) if matches!(action, Action::Check) => {
                    self.last_check = Some(now);
                    self.next_check = Some(now + STATUS_CHECK_EVERY);
                    crate::dns_forwarder::log_proxy(&format!(
                        "Проверка срока лицензии PAID не удалась: {error}"
                    ));
                    self.pending_logs
                        .push(format!("Проверка срока лицензии PAID: {error}"));
                }
                Err(error) => {
                    if matches!(action, Action::Register) {
                        self.open_store_after_register = false;
                    }
                    if matches!(action, Action::Inspect | Action::Apply) {
                        self.pending_transition = None;
                    }
                    if matches!(action, Action::Apply) {
                        self.next_check = Some(now);
                    }
                    self.pending_logs.push(error.clone());
                    self.note = Some(error);
                }
            }
        }
        let focused = ctx.input(|input| input.focused);
        let regained = focused && !self.was_focused;
        self.was_focused = focused;
        if self.device.is_some()
            && self.pending.is_none()
            && self.confirm.is_none()
            && focused
        {
            let now = Instant::now();
            if (regained
                && self
                    .last_check
                    .is_none_or(|t| now.duration_since(t) >= FOCUS_RECHECK_COOLDOWN))
                || self.next_check.is_none_or(|until| until <= now)
            {
                self.launch(Action::Check, ctx);
            } else if let Some(next) = self.next_check {
                ctx.request_repaint_after(next.saturating_duration_since(now));
            }
        }
    }

    pub(super) fn view_compact(
        &mut self,
        ui: &mut egui::Ui,
        found_paid_apps: &[PaidApp],
    ) {
        let selected = crate::paid::enabled();
        let idle = !self.busy();
        let colors = super::theme::palette(ui);
        ui.horizontal_wrapped(|ui| {
            if selected {
                if ui
                    .add_enabled(idle, egui::Button::new("Отключить PAID"))
                    .clicked()
                {
                    self.request_apps(Vec::new(), ui.ctx());
                }
            } else if self.license.eligible
                && ui
                    .add_enabled(idle, egui::Button::new("Включить PAID"))
                    .clicked()
            {
                if found_paid_apps.is_empty() {
                    self.note = Some("Поддерживаемые IDE для PAID не найдены.".into());
                } else {
                    self.request_apps(found_paid_apps.to_vec(), ui.ctx());
                }
            }
            if ui
                .add_enabled(idle, egui::Button::new("Открыть Витрину"))
                .clicked()
            {
                self.open_storefront(ui.ctx());
            }
        });
        if let Some(msg) = self.status_message() {
            ui.label(egui::RichText::new(msg).size(12.0).color(colors.muted));
        }
    }

    pub(super) fn dialog(&mut self, ctx: &egui::Context) {
        let Some((desired, enable_mode, names)) = &self.confirm else {
            return;
        };
        let desired = desired.clone();
        let enable_mode = *enable_mode;
        let dialog = egui::Modal::new(egui::Id::new("paid-routing-confirmation")).show(ctx, |ui| {
            ui.set_max_width(430.0);
            ui.heading(if enable_mode {
                "Активировать лицензию PAID"
            } else {
                "Отключить маршрутизацию PAID"
            });
            ui.label(if enable_mode {
                "Рекомендуется вручную закрыть следующие программы перед активацией:"
            } else if names.contains(&PaidApp::ClaudeDesktop.label()) {
                "Перед отключением PAID выйдите из Claude Desktop через значок в трее."
            } else {
                "Следующие IDE перестанут использовать серверы PAID. Закрывать их не нужно."
            });
            for name in names {
                ui.label(*name);
            }
            if enable_mode {
                ui.label(if names.contains(&PaidApp::ClaudeDesktop.label()) {
                    "Выйдите из Claude через трей и снова откройте его из меню «Пуск»."
                } else {
                    "Если IDE останется открытой, запустите её заново, чтобы применить настройки."
                });
            }
            ui.horizontal(|ui| {
                (
                    ui.button(if enable_mode {
                        "Продолжить активацию"
                    } else {
                        "Отключить PAID"
                    })
                    .clicked(),
                    ui.button("Отмена").clicked(),
                )
            })
            .inner
        });
        if dialog.inner.0 {
            self.confirm = None;
            self.pending_transition = Some(Transition {
                desired,
                inspect_apps: Vec::new(),
                enable_mode,
            });
            self.launch(Action::Apply, ctx);
        } else if dialog.inner.1 || dialog.should_close() {
            self.confirm = None;
        }
    }
}
