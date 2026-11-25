//! Native navigation and pages shown after the licence gate.

use eframe::egui;
use std::time::{Duration, Instant};

use super::status::{self, Action, Tone};
use super::{theme, widgets, App, DONATE_URL, TELEGRAM_GROUP_URL};
use crate::ops::{Cap, Cmd, InstallRow, Level, State};

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
enum Page {
    #[default]
    Overview,
    Integration,
    Settings,
    Log,
}

impl Page {
    const ALL: [Self; 4] = [Self::Overview, Self::Integration, Self::Settings, Self::Log];

    fn label(self) -> &'static str {
        match self {
            Self::Overview => crate::i18n::tr("Обзор", "Overview"),
            Self::Integration => crate::i18n::tr("Интеграция", "Integration"),
            Self::Settings => crate::i18n::tr("Настройки", "Settings"),
            Self::Log => crate::i18n::tr("Журнал", "Log"),
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Self::Overview => widgets::OVERVIEW,
            Self::Integration => widgets::INTEGRATION,
            Self::Settings => widgets::SETTINGS,
            Self::Log => widgets::LOG,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Setup {
    OwnAddress,
    GroupCopy,
    GroupTelegram,
    GroupCode,
}

impl Setup {
    fn cap(self) -> Cap {
        match self {
            Self::OwnAddress => Cap::OwnProxy,
            Self::GroupCopy | Self::GroupTelegram | Self::GroupCode => Cap::GroupProxy,
        }
    }
}

#[derive(Default)]
pub(super) struct ViewState {
    page: Page,
    setup: Option<Setup>,
    focus_setup: bool,
    saving_proxy: Option<Cap>,
    proxy_saved: Option<(Cap, Result<(), String>)>,
    log_copied: Option<(Instant, bool)>,
    confirm_deactivation: bool,
    antigravity_icon: Option<egui::TextureHandle>,
}

impl ViewState {
    fn open(&mut self, page: Page) {
        self.page = page;
        self.setup = None;
        self.focus_setup = false;
    }

    fn begin_setup(&mut self, setup: Setup) {
        self.open(Page::Settings);
        self.proxy_saved = None;
        self.highlight(setup);
    }

    fn highlight(&mut self, setup: Setup) {
        self.setup = Some(setup);
        self.focus_setup = true;
    }

    fn focus(&mut self, step: Setup, response: &egui::Response) {
        if self.setup == Some(step) && self.focus_setup {
            self.focus_setup = false;
            response.request_focus();
            response.scroll_to_me(Some(egui::Align::Center));
        }
    }

    fn is_setting_up(&self, cap: Cap) -> bool {
        self.setup.is_some_and(|step| step.cap() == cap)
    }

    pub(super) fn proxy_saved(&mut self, cap: Cap, result: Result<(), String>) {
        if self.saving_proxy != Some(cap) {
            return;
        }
        self.saving_proxy = None;
        if result.is_ok() && self.is_setting_up(cap) {
            self.open(Page::Overview);
        }
        self.proxy_saved = Some((cap, result));
    }
}

pub fn view(app: &mut App, ui: &mut egui::Ui) {
    let colors = theme::palette(ui);
    footer_panel(colors).show(ui, |ui| footer(app, ui));

    if app.update.is_some() {
        egui::Panel::top("main-update")
            .frame(strip_frame(colors))
            .show(ui, |ui| app.update_banner(ui));
    }
    egui::Panel::left("main-nav")
        .exact_size(172.0)
        .resizable(false)
        .frame(
            egui::Frame::new()
                .fill(colors.chrome)
                .inner_margin(egui::Margin::symmetric(10, 16)),
        )
        .show_separator_line(true)
        .show(ui, |ui| navigation(app, ui));

    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(colors.bg))
        .show(ui, |ui| {
            if app.main_view.page == Page::Log {
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(24, 20))
                    .show(ui, |ui| page_content(app, ui));
                return;
            }
            egui::ScrollArea::vertical()
                .id_salt(("main-page", app.main_view.page))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Frame::new()
                        .inner_margin(egui::Margin::symmetric(24, 20))
                        .show(ui, |ui| page_content(app, ui));
                });
        });
    deactivation_dialog(app, ui.ctx());
}

fn strip_frame(colors: &theme::Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(colors.chrome)
        .inner_margin(egui::Margin::symmetric(16, 5))
}

fn footer_panel(colors: &theme::Palette) -> egui::Panel {
    egui::Panel::bottom("main-footer")
        .exact_size(44.0)
        .frame(strip_frame(colors))
        .show_separator_line(true)
}

fn navigation(app: &mut App, ui: &mut egui::Ui) {
    let colors = theme::palette(ui);
    ui.spacing_mut().item_spacing.y = 4.0;
    for page in Page::ALL {
        let selected = page == app.main_view.page;
        let color = if selected {
            colors.accent_text
        } else {
            colors.text
        };
        let button = egui::Button::selectable(
            selected,
            widgets::icon_text(page.icon(), page.label(), color),
        )
        .fill(if selected { colors.soft } else { colors.card })
        .stroke(egui::Stroke::NONE)
        .min_size(egui::vec2(ui.available_width(), 36.0));
        if ui.add(button).clicked() && !selected {
            app.main_view.open(page);
            app.log_all_selected = false;
        }
    }
    ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
        if ui
            .link(widgets::text_icon(
                crate::i18n::tr("Поддержать", "Support"),
                widgets::HEART,
                colors.accent_text,
            ))
            .clicked()
        {
            crate::utils::open_url_as_user(DONATE_URL);
        }
        if ui
            .link(widgets::text_icon(
                crate::i18n::tr("Группа в ТГ", "Telegram group"),
                widgets::SEND,
                colors.accent_text,
            ))
            .clicked()
        {
            crate::utils::open_url_as_user(TELEGRAM_GROUP_URL);
        }
    });
}

fn page_content(app: &mut App, ui: &mut egui::Ui) {
    match app.main_view.page {
        Page::Overview => {
            title(app, ui, Page::Overview.label());
            overview(app, ui);
        }
        Page::Integration => {
            title(app, ui, Page::Integration.label());
            integration(app, ui);
        }
        Page::Settings => {
            title(app, ui, Page::Settings.label());
            settings(app, ui);
        }
        Page::Log => journal(app, ui),
    }
}

fn title(app: &mut App, ui: &mut egui::Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(text).size(24.0).strong());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            theme_toggle(app, ui);
            lang_toggle(app, ui);
        });
    });
    ui.add_space(8.0);
}

pub(super) fn lang_toggle(app: &mut App, ui: &mut egui::Ui) {
    let colors = theme::palette(ui);
    let next = app.lang.next();
    let hint = match crate::i18n::current() {
        crate::i18n::Lang::Ru => format!("Язык: {} (нажмите для смены на {})", app.lang.native_name(), next.native_name()),
        crate::i18n::Lang::En => format!("Language: {} (click to switch to {})", app.lang.native_name(), next.native_name()),
    };
    let resp = ui
        .add(
            egui::Button::new(
                egui::RichText::new(app.lang.short_label())
                    .size(12.5)
                    .strong()
                    .color(colors.muted),
            )
            .frame_when_inactive(false)
            .min_size(egui::vec2(34.0, 32.0)),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let resp = widgets::hover_text(resp, ui, &hint);
    if resp.clicked() {
        app.lang = next;
        crate::i18n::set_current(next);
        app.worker.send(Cmd::SetLang(next));
    }
}

fn theme_toggle(app: &mut App, ui: &mut egui::Ui) {
    if let (_, Some(next)) = theme_toggle_button(app.theme, ui) {
        app.theme = next;
        theme::set_preference(ui.ctx(), next);
        app.worker.send(Cmd::SetTheme(next));
    }
}

fn theme_toggle_button(
    current: crate::settings::ThemeMode,
    ui: &mut egui::Ui,
) -> (egui::Response, Option<crate::settings::ThemeMode>) {
    let colors = theme::palette(ui);
    let dark = ui.visuals().dark_mode;
    let icon = if dark { widgets::SUN } else { widgets::MOON };
    let mut hint = if dark {
        crate::i18n::tr(
            "Переключить на светлую тему",
            "Switch to light theme",
        )
        .to_string()
    } else {
        crate::i18n::tr(
            "Переключить на тёмную тему",
            "Switch to dark theme",
        )
        .to_string()
    };
    if current != crate::settings::ThemeMode::System {
        hint.push('\n');
        hint.push_str(crate::i18n::tr(
            "Правый клик — системная тема",
            "Right-click for system theme",
        ));
    }
    let resp = ui
        .add(
            egui::Button::new(
                egui::RichText::new(icon)
                    .font(theme::icon_font(17.0))
                    .color(colors.muted),
            )
            .frame_when_inactive(false)
            .min_size(egui::vec2(32.0, 32.0)),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let resp = widgets::hover_text(resp, ui, &hint);
    let next = if resp.clicked() {
        Some(if dark {
            crate::settings::ThemeMode::Light
        } else {
            crate::settings::ThemeMode::Dark
        })
    } else if resp.secondary_clicked() && current != crate::settings::ThemeMode::System {
        Some(crate::settings::ThemeMode::System)
    } else {
        None
    };
    (resp, next)
}

/// Everything the verdict is made of, read off the window's own state.
fn facts(app: &App) -> Option<status::Facts> {
    let s = app.status.as_ref()?;
    Some(status::Facts::read(s, &app.gate, app.gate_at.elapsed()))
}

fn status_card(app: &mut App, ui: &mut egui::Ui) {
    let colors = theme::palette(ui);
    let Some(f) = facts(app) else {
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(16.0));
                ui.label(
                    egui::RichText::new(
                        crate::i18n::tr(
                            "Проверяю систему…",
                            "Checking system…",
                        ),
                    )
                    .size(15.0),
                );
            });
        });
        return;
    };
    let h = status::headline(&f);
    let (icon, accent, fill) = match h.tone {
        Tone::Ok => (widgets::ANSWER, colors.accent_text, colors.soft),
        Tone::Wait => (widgets::WAIT, colors.accent_text, colors.soft),
        Tone::Fixing => (widgets::REPAIR, colors.warn, colors.card),
        Tone::Action => (widgets::ALERT, colors.bad, colors.card),
        Tone::Off => (widgets::POWER, colors.muted, colors.card),
    };
    // Ages on the card count up on their own; without a repaint «минуту назад»
    // would stay «минуту назад» until the mouse moved.
    if f.refusal.is_some() || f.answer.is_some() || f.verify.is_some() {
        ui.ctx().request_repaint_after(Duration::from_secs(1));
    }

    let busy = app.is_busy();
    let mut pressed: Option<Action> = None;
    let mut copy = false;
    let mut reveal: Option<std::path::PathBuf> = None;
    egui::Frame::new()
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(theme::RADIUS))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(34.0, 34.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, egui::CornerRadius::same(6), colors.bg);
                ui.painter().text(
                    rect.center(), egui::Align2::CENTER_CENTER, icon, theme::icon_font(19.0), accent,
                );
                if h.tone == Tone::Ok {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(
                                crate::i18n::tr(
                                    "Модель ответила",
                                    "Model replied",
                                ),
                            )
                            .size(22.0)
                            .strong(),
                        );
                        if let Some(ago) = f.answer {
                            let ago_s = status::ago_text(ago);
                            let line = match crate::i18n::current() {
                                crate::i18n::Lang::Ru => format!("Последний ответ {ago_s}"),
                                crate::i18n::Lang::En => format!("Last reply {ago_s}"),
                            };
                            ui.label(
                                egui::RichText::new(&line)
                                    .size(12.5)
                                    .color(colors.muted),
                            );
                        }
                    });
                    if let Some(route) = f.route.as_deref().filter(|r| !r.is_empty()) {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.vertical(|ui| {
                                ui.label(
                                    egui::RichText::new(
                                        crate::i18n::tr(
                                            "Маршрут", "Route",
                                        ),
                                    )
                                    .size(12.0)
                                    .color(colors.muted),
                                );
                                ui.label(egui::RichText::new(route).size(13.5));
                            });
                        });
                    }
                } else {
                    ui.label(
                        egui::RichText::new(&h.title)
                            .size(22.0)
                            .strong(),
                    );
                }
            });
            if h.tone != Tone::Ok {
                widgets::wrapped_label(ui, &h.detail, 13.5, colors.text);
            }
            if let Some(action) = h.action {
                ui.add_space(10.0);
                if widgets::primary(ui, action.label(), !busy).clicked() {
                    pressed = Some(action);
                }
            }
            if super::report::ENABLED {
                ui.add_space(10.0);
                // The saved file is named on a line of its own, under the buttons.
                // A report the size of these is pasted into a chat as a wall of
                // text nobody reads and half of them arrive truncated, so the file
                // *is* the deliverable and its name is what the user has to act on;
                // the path is not shown, because «рабочий стол» plus «Показать» is
                // what actually gets them to it.
                let saved = app
                    .report_saved
                    .clone()
                    .filter(|(at, _)| at.elapsed() < REPORT_SHOWN_FOR);
                ui.horizontal(|ui| {
                    let save_resp = ui.add_enabled(
                        !busy,
                        egui::Button::new(
                            egui::RichText::new(
                                crate::i18n::tr(
                                    "Сохранить отчёт",
                                    "Save report",
                                ),
                            )
                            .size(12.5),
                        ),
                    );
                    if widgets::hover_text(
                        save_resp,
                        ui,
                        crate::i18n::tr(
                            "Всё, что нужно, чтобы понять, почему Antigravity отвечает или нет — одним файлом на рабочем столе: приложите его к сообщению",
                            "Everything needed to diagnose why Antigravity is or isn't replying — saved as one file on your Desktop",
                        ),
                    )
                    .clicked()
                    {
                        copy = true;
                    }
                    if let Some((_, path)) = &saved {
                        let show_resp = ui.add(egui::Button::new(
                            egui::RichText::new(
                                crate::i18n::tr(
                                    "Показать файл",
                                    "Show file",
                                ),
                            )
                            .size(12.5),
                        ));
                        if widgets::hover_text(
                            show_resp,
                            ui,
                            crate::i18n::tr(
                                "Открыть папку с отчётом",
                                "Open folder with report",
                            ),
                        )
                        .clicked()
                        {
                            reveal = Some(path.clone());
                        }
                    }
                });
                if let Some((_, path)) = &saved {
                    ui.add_space(4.0);
                    let fname = path
                        .file_name()
                        .map(|f| f.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let msg = match crate::i18n::current() {
                        crate::i18n::Lang::Ru => format!("Отчёт сохранён на рабочий стол: «{fname}». Приложите этот файл к сообщению."),
                        crate::i18n::Lang::En => format!("Report saved to Desktop: \"{fname}\". Attach this file to your message."),
                    };
                    widgets::wrapped_label(ui, &msg, 12.5, theme::palette(ui).ok);
                    ui.ctx().request_repaint_after(Duration::from_millis(500));
                }
                if app
                    .report_clipboard_at
                    .is_some_and(|at| at.elapsed() < REPORT_SHOWN_FOR)
                {
                    ui.add_space(4.0);
                    widgets::wrapped_label(
                        ui,
                        crate::i18n::tr(
                            "Файл сохранить не удалось — отчёт скопирован, вставьте его в сообщение.",
                            "Could not save file — report copied to clipboard.",
                        ),
                        12.5,
                        theme::palette(ui).warn,
                    );
                    ui.ctx().request_repaint_after(Duration::from_millis(500));
                }
            }
        });

    match pressed {
        Some(Action::EnableAll) => app.worker.send(Cmd::EnableAll),
        Some(Action::Repair) => app.worker.send(Cmd::Repair),
        Some(Action::Elevate) => app.request_elevation(),
        Some(Action::Verify) => {
            if let Some((_, url)) = &f.verify {
                crate::utils::open_url_as_user(url);
            }
        }
        None => {}
    }
    if copy {
        let text = super::report::build(app.status.as_ref(), &app.gate);
        // The clipboard as well, always: it costs nothing and a user who would
        // rather paste still can.
        ui.ctx().copy_text(text.clone());
        let now = std::time::Instant::now();
        match crate::utils::desktop_dir()
            .and_then(|dir| crate::utils::save_text_file(&dir, crate::utils::REPORT_FILE, &text))
        {
            Some(path) => {
                app.report_saved = Some((now, path));
                app.report_clipboard_at = None;
            }
            None => {
                app.report_saved = None;
                app.report_clipboard_at = Some(now);
            }
        }
    }
    if let Some(path) = reveal {
        crate::utils::reveal_in_explorer(&path);
    }
    if f.relay_uses_vpn {
        ui.add_space(6.0);
        widgets::wrapped_label(ui, status::vpn_traffic_notice(), 14.0, theme::palette(ui).warn);
        vpn_exclusion_button(app, ui, &f);
    }
}

/// How long the card goes on saying where the report was saved. Four seconds
/// was right for «скопировано»; this one is an instruction to go and find a
/// file and attach it, and the user is in another window by then.
const REPORT_SHOWN_FOR: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Antigravity: the three switches anyone needs, and the installs
// ---------------------------------------------------------------------------

fn overview(app: &mut App, ui: &mut egui::Ui) {
    status_card(app, ui);
    ui.add_space(12.0);
    if ui.available_width() >= 620.0 {
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.x = 24.0;
            let painter = ui.painter().clone();
            ui.columns(2, |columns| {
                account_controls(app, &mut columns[0]);
                network_controls(app, &mut columns[1]);
                let left = columns[0].min_rect();
                let right = columns[1].min_rect();
                painter.vline(
                    (left.right() + right.left()) / 2.0,
                    left.top()..=left.bottom().max(right.bottom()),
                    egui::Stroke::new(1.0, theme::palette(&columns[0]).line),
                );
            });
        });
    } else {
        account_controls(app, ui);
        ui.add_space(8.0);
        network_controls(app, ui);
    }
}

fn section_title(ui: &mut egui::Ui, label: &str) {
    ui.label(
        egui::RichText::new(label)
            .size(15.0)
            .strong(),
    );
}

fn account_controls(app: &mut App, ui: &mut egui::Ui) {
    section_title(ui, crate::i18n::tr("Управление", "Controls"));
    cap_row(app, ui, Cap::ClientPatch);
    ui.separator();
    bypass_master(app, ui);
    ui.separator();
    cap_row(app, ui, Cap::Watchdog);
}

fn network_controls(app: &mut App, ui: &mut egui::Ui) {
    section_title(ui, crate::i18n::tr("Сеть и прокси", "Network & Proxy"));
    let caps = [Cap::Dns, Cap::LocalProxy, Cap::OwnProxy, Cap::GroupProxy];
    for (index, cap) in caps.into_iter().enumerate() {
        if index > 0 {
            ui.separator();
        }
        cap_row(app, ui, cap);
    }
}

fn control_label(ui: &mut egui::Ui, icon: &str, title: &str, hint: &str) {
    let colors = theme::palette(ui);
    let resp = ui.add(egui::Label::new(widgets::icon_text(
        icon,
        title,
        colors.text,
    )));
    widgets::hover_text(resp, ui, hint);
}

fn bypass_master(app: &mut App, ui: &mut egui::Ui) {
    let mut on = app.status.as_ref().is_some_and(|s| s.bypass_on());
    let enabled = app.status.is_some() && !app.is_busy();
    let label = crate::i18n::tr("Обход ошибки 400", "Error 400 bypass");
    let flipped = widgets::switch_row(ui, &mut on, enabled, label, |ui| {
        control_label(ui, widgets::ROUTE, label, status::bypass_text().1);
    });
    if flipped {
        let group_configured = app
            .status
            .as_ref()
            .is_some_and(|s| s.group_proxy_configured);
        for cap in crate::ops::bypass_order(on, group_configured) {
            app.worker.send(Cmd::Set(cap, on));
        }
    }
}

fn integration(app: &mut App, ui: &mut egui::Ui) {
    let Some(status) = app.status.as_ref() else {
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new().size(14.0));
            widgets::hint(
                ui,
                crate::i18n::tr("Идёт поиск…", "Searching…"),
            );
        });
        return;
    };
    let rows = status.installs.clone();
    integration_group(app, ui, "Antigravity", &rows);
}

fn integration_group(app: &mut App, ui: &mut egui::Ui, name: &str, rows: &[InstallRow]) {
    let group_icon = if name == "Antigravity" {
        Some(
            app.main_view
                .antigravity_icon
                .get_or_insert_with(|| {
                    let image = super::icon::antigravity_image().unwrap_or_else(|| {
                        egui::ColorImage::filled([1, 1], egui::Color32::TRANSPARENT)
                    });
                    ui.ctx().load_texture(
                        "antigravity-group-icon",
                        image,
                        egui::TextureOptions::LINEAR,
                    )
                })
                .clone(),
        )
    } else {
        None
    };
    ui.horizontal(|ui| {
        if let Some(tex) = &group_icon {
            ui.add(egui::Image::new((tex.id(), egui::vec2(20.0, 20.0))));
        }
        section_title(ui, name);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let found = rows.iter().filter(|row| row.path.is_some()).count();
            let total = rows.len();
            let found_text = match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("Найдено {found} из {total}"),
                crate::i18n::Lang::En => format!("Found {found} of {total}"),
            };
            ui.label(
                egui::RichText::new(&found_text)
                    .size(12.5)
                    .color(theme::palette(ui).muted),
            );
        });
    });
    ui.separator();
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            ui.separator();
        }
        ui.push_id(index, |ui| integration_row(app, ui, row));
    }
}

fn integration_row(app: &mut App, ui: &mut egui::Ui, row: &InstallRow) {
    let colors = theme::palette(ui);
    let enabled = !app.is_busy();
    ui.horizontal(|ui| {
        let label = ui.label(row.label);
        if let Some(path) = &row.path {
            label.on_hover_text(path.display().to_string());
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let edit = ui.add_enabled(
                enabled,
                egui::Button::new(widgets::icon_text(widgets::FOLDER, "", colors.muted))
                    .frame_when_inactive(false)
                    .min_size(egui::vec2(32.0, 28.0)),
            );
            if widgets::hover_text(
                edit,
                ui,
                crate::i18n::tr(
                    "Указать путь вручную",
                    "Specify path manually",
                ),
            )
            .clicked()
            {
                app.path_dialog = Some(
                    row.path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                );
            }
            if let Some(path) = &row.path {
                if row.manual
                    && ui
                        .add_enabled(
                            enabled,
                            egui::Button::new(
                                crate::i18n::tr(
                                    "Отключить",
                                    "Remove",
                                ),
                            ),
                        )
                        .clicked()
                {
                    app.worker.send(Cmd::ForgetPath(path.clone()));
                }
                if row.patched == Some(false)
                    && widgets::command(
                        ui,
                        widgets::REPAIR,
                        crate::i18n::tr("Пропатчить", "Patch"),
                        false,
                        enabled,
                    )
                    .clicked()
                {
                    app.worker.send(Cmd::PatchInstall(path.clone()));
                }
            }
            let (icon, text, color) = match (&row.path, row.patched) {
                (None, _) => (
                    "",
                    crate::i18n::tr("Не найден", "Not found"),
                    colors.muted,
                ),
                (Some(_), Some(true)) => (
                    widgets::CHECK,
                    crate::i18n::tr("Патч применён", "Patched"),
                    colors.ok,
                ),
                (Some(_), Some(false)) => (
                    "",
                    crate::i18n::tr("Без патча", "Unpatched"),
                    colors.muted,
                ),
                (Some(_), None) => (
                    "",
                    crate::i18n::tr("Патч не проверен", "Not checked"),
                    colors.muted,
                ),
            };
            ui.label(widgets::icon_text(icon, text, color));
        });
    });
}

/// Debug builds can unfold network diagnostics on start.
fn dev_open() -> bool {
    cfg!(debug_assertions) && std::env::var_os("AG_UNLOCKER_DEV_OPEN").is_some()
}

fn advanced_network(app: &mut App, ui: &mut egui::Ui) {
    let facts = facts(app);
    let relay_uses_vpn = facts.as_ref().is_some_and(|f| f.relay_uses_vpn);
    network_facts(app, ui, relay_uses_vpn);
    if let Some(facts) = facts.as_ref().filter(|f| !f.relay_uses_vpn) {
        vpn_exclusion_button(app, ui, facts);
    }
    ui.separator();
    providers_list(app, ui);
}

/// A small «i» that opens or closes the text kept under `key`. Returns whether
/// the text is showing.
fn info_toggle(ui: &mut egui::Ui, key: &str) -> bool {
    let id = egui::Id::new(key);
    let mut open = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    if widgets::info_button(ui, open).clicked() {
        open = !open;
    }
    ui.data_mut(|d| d.insert_temp(id, open));
    open
}

fn info_open(ui: &egui::Ui, key: &str) -> bool {
    ui.data(|d| d.get_temp::<bool>(egui::Id::new(key)))
        .unwrap_or(false)
}

fn vpn_exclusion_path(facts: &status::Facts) -> std::io::Result<std::path::PathBuf> {
    match (facts.relay_running, facts.relay_exe.as_str()) {
        (true, "") => Ok(crate::background::installed_exe()),
        (true, path) => Ok(path.into()),
        (false, _) => std::env::current_exe(),
    }
}

/// Copies the executable path needed by per-app split tunnelling.
fn vpn_exclusion_button(app: &mut App, ui: &mut egui::Ui, facts: &status::Facts) {
    let copied = app
        .vpn_path_copied
        .is_some_and(|at| at.elapsed() < Duration::from_secs(5));
    let label = if copied {
        crate::i18n::tr("Путь скопирован", "Path copied")
    } else {
        crate::i18n::tr(
            "Скопировать путь для исключения VPN",
            "Copy path for VPN exclusion",
        )
    };
    ui.horizontal(|ui| {
        if ui
            .add(egui::Button::new(
                egui::RichText::new(label).size(13.0),
            ))
            .clicked()
        {
            if let Ok(exe) = vpn_exclusion_path(facts) {
                let path = exe.display().to_string();
                if crate::utils::set_clipboard_text(&path) {
                    app.vpn_path_copied = Some(std::time::Instant::now());
                } else {
                    ui.ctx().copy_text(path);
                }
            }
        }
        info_toggle(ui, "vpn-info");
    });
    if info_open(ui, "vpn-info") {
        widgets::hint(
            ui,
            crate::i18n::tr(
                "Копирует путь к запущенной службе обхода или к самому анлокеру, если служба выключена. Вставьте путь в список исключений VPN.",
                "Copies the path to the running bypass service or to the unlocker itself if the service is stopped. Paste it into your VPN exclusion list.",
            ),
        );
    }
    if copied {
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

/// What the relay says about the network right now: the VPN, where it comes
/// out, and the path in use. Facts, not advice - there is nothing here the
/// user has to act on, which is why it sits in the folded section.
fn network_facts(app: &App, ui: &mut egui::Ui, relay_uses_vpn: bool) {
    let Some(r) = app.gate.relay.as_ref() else {
        return;
    };
    let vpn = if !r.tunnel {
        crate::i18n::tr("VPN не обнаружен.", "No VPN detected.").to_string()
    } else if r.vpn_exit.is_empty() {
        crate::i18n::tr(
            "VPN включён — соединения службы с сервисами разблокировки идут мимо него.",
            "VPN is on — service connections to unblocking servers bypass it.",
        )
        .to_string()
    } else if crate::upstream::region_is_blocked(&r.vpn_exit) {
        match crate::i18n::current() {
            crate::i18n::Lang::Ru => format!("VPN включён, выход: {} — там ошибка 400, поэтому соединения идут мимо него.", r.vpn_exit),
            crate::i18n::Lang::En => format!("VPN is on, exit: {} — error 400 there, so connections bypass it.", r.vpn_exit),
        }
    } else {
        match crate::i18n::current() {
            crate::i18n::Lang::Ru => format!("VPN включён, выход: {} — используется как один из путей.", r.vpn_exit),
            crate::i18n::Lang::En => format!("VPN is on, exit: {} — used as one of the routes.", r.vpn_exit),
        }
    };
    if !relay_uses_vpn {
        widgets::hint(ui, &vpn);
    }
    if !r.route.is_empty() {
        let route_msg = match crate::i18n::current() {
            crate::i18n::Lang::Ru => format!("Первый путь сейчас: {}.", r.route),
            crate::i18n::Lang::En => format!("Primary route now: {}.", r.route),
        };
        widgets::hint(ui, &route_msg);
    }
    if !r.loopback {
        widgets::hint(
            ui,
            crate::i18n::tr(
                "Служба ещё не перехватывает имена серверов Google — Antigravity идёт через них, только если перезапущен после включения обхода.",
                "The service is not yet intercepting Google hostnames — Antigravity uses them only if restarted after enabling the bypass.",
            ),
        );
    }
    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);
}

/// How a provider's name is written in the list.
///
/// The pool stores them the way they are typed as hostnames — all lower case —
/// which reads as sloppy in a list of proper names. An acronym stays an acronym
/// (`dns-ai.ru` → `DNS-AI.RU`); everything else just gets its first letter.
/// Presentation only: the stored name is what every switch, the deny-list and
/// the saved order are keyed by, and it never changes.
fn providers_list(app: &mut App, ui: &mut egui::Ui) {
    // Copied out before anything is drawn: the rows below need `&mut app` for
    // the rotation switch, and holding a borrow of `app.status` across that is
    // what the borrow checker (rightly) refuses.
    let Some((dns_on, rotating)) = app
        .status
        .as_ref()
        .map(|s| (s.dns.is_on(), s.dns_rotation.is_on()))
    else {
        return;
    };
    // Drawn from the window's own copy, which a drag rearranges immediately; the
    // worker's snapshot is adopted back into it whenever no drag is in flight.
    let providers = app.providers_local.clone();
    if providers.is_empty() {
        return;
    }
    let mut flip: Option<(String, bool)> = None;
    // (from, to) — set the moment the pointer passes over another row, not on
    // release: the row has to follow the cursor while the button is still down.
    let mut moved: Option<(usize, usize)> = None;
    let mut dropped = false;

    egui::CollapsingHeader::new(
        egui::RichText::new(
            crate::i18n::tr(
                "Какие DNS использовать",
                "Which DNS to use",
            ),
        )
        .size(12.5)
        .color(theme::palette(ui).muted),
    )
    .id_salt("providers")
    .default_open(true)
    .show(ui, |ui| {
        let first_on = providers.iter().position(|p| p.enabled);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(
                    crate::i18n::tr(
                        "Порядок — перетаскиванием за «≡»",
                        "Order — drag by \"≡\"",
                    ),
                )
                .size(12.0)
                .color(theme::palette(ui).muted),
            );
            info_toggle(ui, "providers-info");
        });
        if info_open(ui, "providers-info") {
            widgets::hint(
                ui,
                crate::i18n::tr(
                    "Зажмите полоски слева и перетащите. Первый в списке спрашивается первым.",
                    "Hold the handle on the left and drag. The first in the list is queried first.",
                ),
            );
        }
        ui.add_space(4.0);

        for (i, p) in providers.iter().enumerate() {
            let row = ui
                .horizontal(|ui| {
                    ui.add_space(6.0);
                    // Only the grip drags. Making the whole row a drag source
                    // put a drag sense over the switch too, so aiming at the
                    // switch and moving a pixel dragged the row instead of
                    // toggling it.
                    //
                    // The id is keyed by name, not by index: an id tied to the
                    // position would follow the slot rather than the row.
                    let id = egui::Id::new(("dns-provider", p.name.as_str()));
                    ui.dnd_drag_source(id, i, |ui| {
                        ui.label(
                            egui::RichText::new("≡")
                                .size(15.0)
                                .color(theme::palette(ui).muted),
                        );
                    })
                    .response
                    .on_hover_cursor(egui::CursorIcon::Grab);

                    // Not tied to `busy`: a provider switch is a settings write
                    // and answers at once, so it must not wait behind whatever
                    // the worker is doing for another switch.
                    let mut on = p.enabled;
                    if widgets::switch(ui, &mut on, dns_on && p.available, &p.name).changed() {
                        flip = Some((p.name.clone(), on));
                    }
                    // Without rotation only the first enabled one is ever asked,
                    // so the rest are drawn as what they are: on, but not in use.
                    let idle = !rotating && p.enabled && first_on != Some(i);
                    let text = egui::RichText::new(status::provider_name(&p.name)).size(13.0);
                    ui.label(if idle || !p.available {
                        text.color(theme::palette(ui).muted)
                    } else {
                        text
                    });
                    if !p.available {
                        widgets::hint(
                            ui,
                            crate::i18n::tr("— не задан", "— not set"),
                        );
                    } else if idle {
                        widgets::hint(
                            ui,
                            crate::i18n::tr(
                                "— не используется",
                                "— not in use",
                            ),
                        );
                    }
                })
                .response;

            // The whole row is the drop target, not just the grip: aiming at a
            // 15 px glyph to finish a drag is not something anyone should have
            // to do.
            // Hover, not release: the list rearranges under the pointer while
            // the button is still down, which is what makes a drag feel like
            // moving a thing rather than aiming at a slot.
            if let Some(from) = row.dnd_hover_payload::<usize>() {
                if *from != i {
                    moved = Some((*from, i));
                }
            }
            if row.dnd_release_payload::<usize>().is_some() {
                dropped = true;
            }
        }

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        cap_row(app, ui, Cap::DnsRotation);
    });

    if let Some((name, on)) = flip {
        // The row flips under the pointer this frame; the worker's snapshot
        // confirms (or, for the last provider, takes it back) a moment later.
        if let Some(row) = app.providers_local.iter_mut().find(|r| r.name == name) {
            row.enabled = on;
        }
        app.worker.send(Cmd::SetProvider(name, on));
    }
    if let Some((from, to)) = moved {
        if from < app.providers_local.len() && to < app.providers_local.len() {
            let row = app.providers_local.remove(from);
            app.providers_local.insert(to, row);
            // The payload has to follow the row to its new index, or the next
            // frame would think it is still being dragged from the old slot and
            // move it straight back.
            egui::DragAndDrop::set_payload(ui.ctx(), to);
            app.providers_reordering = true;
        }
    }

    // Saved once, when the button comes up. Writing on every hover would be a
    // file write per frame of a drag.
    if dropped && app.providers_reordering {
        app.providers_reordering = false;
        let order: Vec<String> = app.providers_local.iter().map(|p| p.name.clone()).collect();
        app.worker.send(Cmd::ReorderProviders(order));
    }
    // A drag abandoned outside the list (or one that changed nothing) must not
    // leave the window refusing the worker's snapshots for ever.
    if app.providers_reordering && ui.input(|i| i.pointer.any_released()) {
        app.providers_reordering = false;
        let order: Vec<String> = app.providers_local.iter().map(|p| p.name.clone()).collect();
        app.worker.send(Cmd::ReorderProviders(order));
    }
}

fn settings(app: &mut App, ui: &mut egui::Ui) {
    proxy_heading(app, ui, Cap::OwnProxy);
    proxy_field(app, ui, Cap::OwnProxy);
    ui.add_space(4.0);
    ui.separator();
    proxy_heading(app, ui, Cap::GroupProxy);
    group_proxy_actions(app, ui);
    proxy_field(app, ui, Cap::GroupProxy);
    if crate::group::key_rejected() {
        widgets::wrapped_label(ui, crate::group::key_dead_note(), 12.0, theme::palette(ui).bad);
    }
    ui.add_space(4.0);
    ui.separator();
    custom_dns_field(app, ui);
    ui.add_space(4.0);
    ui.separator();
    ui.add_space(4.0);
    egui::CollapsingHeader::new(
        crate::i18n::tr(
            "Дополнительные параметры сети",
            "Advanced network settings",
        ),
    )
    .default_open(dev_open())
    .show(ui, |ui| advanced_network(app, ui));
}

fn proxy_configured(app: &App, cap: Cap) -> bool {
    app.status.as_ref().is_some_and(|s| match cap {
        Cap::OwnProxy => s.own_proxy_configured,
        Cap::GroupProxy => s.group_proxy_configured,
        _ => false,
    })
}

fn proxy_heading(app: &App, ui: &mut egui::Ui, cap: Cap) {
    let colors = theme::palette(ui);
    let on = app.status.as_ref().is_some_and(|s| s.get(cap).is_on());
    let (text, color) = if on {
        (crate::i18n::tr("Включён", "Enabled"), colors.ok)
    } else if proxy_configured(app, cap) {
        (crate::i18n::tr("Выключен", "Disabled"), colors.muted)
    } else {
        (
            crate::i18n::tr("Не настроен", "Not configured"),
            colors.muted,
        )
    };
    ui.horizontal(|ui| {
        section_title(ui, status::switch_text(cap).0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(text)
                    .size(12.0)
                    .color(color),
            );
        });
    });
}

fn group_proxy_actions(app: &mut App, ui: &mut egui::Ui) {
    ui.horizontal_wrapped(|ui| {
        let copy = widgets::hover_text(
            widgets::command(
                ui,
                widgets::COPY,
                crate::i18n::tr("Скопировать команду", "Copy command"),
                app.main_view.setup == Some(Setup::GroupCopy),
                true,
            ),
            ui,
            crate::i18n::tr(
                "Команда для получения кода в группе Nova",
                "Command to get a code in the Nova group",
            ),
        );
        app.main_view.focus(Setup::GroupCopy, &copy);
        if copy.clicked() {
            let command = format!("/ag+{}", crate::hwid::pc_code());
            if crate::utils::set_clipboard_text(&command) {
                app.main_view.proxy_saved = None;
                if app.main_view.is_setting_up(Cap::GroupProxy) {
                    app.main_view.highlight(Setup::GroupTelegram);
                }
            } else {
                app.main_view.proxy_saved = Some((
                    Cap::GroupProxy,
                    Err(crate::i18n::tr(
                        "Не удалось скопировать команду.",
                        "Failed to copy command.",
                    )
                    .into()),
                ));
            }
        }
        let telegram = widgets::command(
            ui,
            widgets::SEND,
            crate::i18n::tr("Открыть Telegram", "Open Telegram"),
            app.main_view.setup == Some(Setup::GroupTelegram),
            true,
        );
        app.main_view.focus(Setup::GroupTelegram, &telegram);
        if telegram.clicked() {
            crate::utils::open_url_as_user(super::TELEGRAM_KEYS_URL);
            if app.main_view.is_setting_up(Cap::GroupProxy) {
                app.main_view.highlight(Setup::GroupCode);
            }
        }
    });
}

fn proxy_field(app: &mut App, ui: &mut egui::Ui, cap: Cap) {
    let own = cap == Cap::OwnProxy;
    let enabled = !app.is_busy() && app.main_view.saving_proxy.is_none();
    let enabling = app.main_view.is_setting_up(cap);
    let step = if own {
        Setup::OwnAddress
    } else {
        Setup::GroupCode
    };
    let color = theme::palette(ui);
    let (name, hint, value) = if own {
        (
            crate::i18n::tr("Адрес прокси", "Proxy address"),
            crate::i18n::tr("адрес:порт", "host:port"),
            &mut app.own_proxy_input,
        )
    } else {
        (
            crate::i18n::tr("Код из группы", "Group code"),
            crate::i18n::tr("Код из Telegram", "Code from Telegram"),
            &mut app.group_key_input,
        )
    };
    let label = ui.label(
        egui::RichText::new(name)
            .size(12.5)
            .color(color.muted),
    );
    let mut submitted = false;
    ui.horizontal(|ui| {
        let button_width = if enabling { 186.0 } else { 128.0 };
        let available = (ui.available_width() - button_width).max(80.0);
        let selected = app.main_view.setup == Some(step);
        let field = egui::TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(available)
            .margin(egui::Margin::symmetric(9, 7))
            .background_color(if selected { color.soft } else { color.sunken });
        let response = widgets::hover_text(
            ui.add_enabled(enabled, field).labelled_by(label.id),
            ui,
            if own {
                crate::i18n::tr(
                    "адрес:порт или логин:пароль@адрес:порт",
                    "host:port or user:pass@host:port",
                )
            } else {
                crate::i18n::tr(
                    "Правый клик — вставить код из буфера",
                    "Right-click to paste code from clipboard",
                )
            },
        );
        app.main_view.focus(step, &response);
        if !own && response.secondary_clicked() && enabled {
            if let Some(text) = crate::utils::clipboard_text() {
                *value = text.trim().to_string();
            }
        }
        let can_save = enabled && ((!enabling && own) || !value.trim().is_empty());
        let save_text = if enabling {
            crate::i18n::tr(
                "Сохранить и включить",
                "Save and enable",
            )
        } else {
            crate::i18n::tr("Сохранить", "Save")
        };
        let enter = response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        submitted = widgets::command(ui, widgets::CHECK, save_text, false, can_save).clicked()
            || (can_save && enter);
    });
    if submitted {
        let text = value.trim().to_string();
        app.main_view.saving_proxy = Some(cap);
        app.main_view.proxy_saved = None;
        app.worker.send(if own {
            Cmd::SetOwnProxy {
                text,
                enable: enabling,
            }
        } else {
            Cmd::SetGroupKey {
                text,
                enable: enabling,
            }
        });
    }
    if let Some((saved_cap, result)) = &app.main_view.proxy_saved {
        if *saved_cap == cap {
            let (text, ink) = match result {
                Ok(()) => (
                    crate::i18n::tr("Сохранено", "Saved"),
                    color.ok,
                ),
                Err(error) => (error.as_str(), color.bad),
            };
            ui.label(
                egui::RichText::new(text)
                    .size(12.5)
                    .color(ink),
            );
        }
    }
}

/// User DNS joins the existing provider pool.
fn custom_dns_field(app: &mut App, ui: &mut egui::Ui) {
    section_title(ui, crate::i18n::tr("Свой DNS", "Custom DNS"));
    let colors = theme::palette(ui);
    let enabled = !app.is_busy();
    let label = ui.label(
        egui::RichText::new(
            crate::i18n::tr("Адрес DNS", "DNS address"),
        )
        .size(12.5)
        .color(colors.muted),
    );
    ui.horizontal(|ui| {
        let resp = ui
            .add_enabled(
                enabled,
                egui::TextEdit::singleline(&mut app.custom_dns_input)
                    .hint_text(
                        crate::i18n::tr(
                            "IPv4, DoH или DoT",
                            "IPv4, DoH, or DoT",
                        ),
                    )
                    .desired_width((ui.available_width() - 128.0).max(80.0))
                    .margin(egui::Margin::symmetric(9, 7)),
            )
            .labelled_by(label.id);
        let response = widgets::hover_text(
            resp,
            ui,
            crate::i18n::tr(
                "Несколько адресов можно разделить пробелами. Примеры: 77.88.8.8, https://dns.example.com/dns-query, tls://dns.example.com.",
                "Separate multiple addresses with spaces. Examples: 77.88.8.8, https://dns.example.com/dns-query, tls://dns.example.com.",
            ),
        );
        let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if widgets::command(
            ui,
            widgets::CHECK,
            crate::i18n::tr("Сохранить", "Save"),
            false,
            enabled,
        )
        .clicked()
            || (enabled && enter)
        {
            app.worker
                .send(Cmd::SetCustomDns(app.custom_dns_input.clone()));
        }
    });
}

fn cap_row(app: &mut App, ui: &mut egui::Ui, cap: Cap) {
    let (title, icon, setup) = match cap {
        Cap::ClientPatch => (
            crate::i18n::tr(
                "Разблокировать вход",
                "Unlock sign-in",
            ),
            widgets::KEY,
            None,
        ),
        Cap::Watchdog => (
            crate::i18n::tr("Автопатч", "Auto-patch"),
            widgets::REFRESH,
            None,
        ),
        Cap::Dns => (
            crate::i18n::tr("Обход через DNS-AI", "DNS-AI bypass"),
            widgets::DNS,
            None,
        ),
        Cap::LocalProxy => (
            crate::i18n::tr("Локальный прокси", "Local proxy"),
            widgets::SERVER,
            None,
        ),
        Cap::OwnProxy => (
            crate::i18n::tr("Свой HTTP-прокси", "Own HTTP proxy"),
            widgets::PROXY,
            Some(Setup::OwnAddress),
        ),
        Cap::GroupProxy => (
            crate::i18n::tr("Прокси из группы", "Group proxy"),
            widgets::GROUP,
            Some(Setup::GroupCopy),
        ),
        Cap::DnsRotation => (status::switch_text(cap).0, widgets::REFRESH, None),
    };
    let (_, hint) = status::switch_text(cap);
    let state = app
        .status
        .as_ref()
        .map(|s| s.get(cap))
        .unwrap_or(&State::Off);
    let mut on = state.is_on();
    let blocked = matches!(state, State::Blocked(_));
    let enabled = app.status.is_some() && !app.is_busy() && !blocked;
    let new_setup = setup.filter(|_| !on && !proxy_configured(app, cap));
    let colors = theme::palette(ui);

    let flipped = widgets::switch_row(ui, &mut on, enabled, title, |ui| {
        control_label(ui, icon, title, hint);
        let note = state.note().or(if new_setup.is_some() {
            Some(crate::i18n::tr("Не настроен", "Not configured"))
        } else {
            None
        });
        if let Some(note) = note {
            ui.label(
                egui::RichText::new(note)
                    .size(12.0)
                    .color(if blocked { colors.warn } else { colors.muted }),
            );
        }
    });
    if flipped {
        if let Some(step) = new_setup {
            app.main_view.begin_setup(step);
        } else {
            app.worker.send(Cmd::Set(cap, on));
        }
    }
}

/// One log line as it is drawn — and as it is copied, so what lands on the
/// clipboard is what was on screen.
fn log_line(level: Level, line: &str) -> String {
    if level == Level::Step {
        format!("— {line}")
    } else {
        line.to_string()
    }
}

fn journal_text(log: &[(Level, String)]) -> String {
    log.iter()
        .map(|(level, line)| log_line(*level, line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn journal(app: &mut App, ui: &mut egui::Ui) {
    // Consume select-all/copy before egui's per-label selection sees the event.
    log_keys(app, ui);
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(Page::Log.label())
                .size(24.0)
                .strong(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            theme_toggle(app, ui);
            lang_toggle(app, ui);
            if widgets::command(
                ui,
                widgets::COPY,
                crate::i18n::tr("Скопировать журнал", "Copy log"),
                false,
                !app.log.is_empty(),
            )
            .clicked()
            {
                let copied = crate::utils::set_clipboard_text(&journal_text(&app.log));
                app.main_view.log_copied = Some((Instant::now(), copied));
            }
            if let Some((at, copied)) = app.main_view.log_copied {
                let show_for = Duration::from_secs(4);
                if at.elapsed() < show_for {
                    let colors = theme::palette(ui);
                    let (text, color) = if copied {
                        (
                            crate::i18n::tr("Журнал скопирован", "Log copied"),
                            colors.ok,
                        )
                    } else {
                        (
                            crate::i18n::tr(
                                "Не удалось скопировать",
                                "Failed to copy",
                            ),
                            colors.bad,
                        )
                    };
                    ui.label(
                        egui::RichText::new(text)
                            .size(12.0)
                            .color(color),
                    );
                    ui.ctx()
                        .request_repaint_after(show_for.saturating_sub(at.elapsed()));
                }
            }
        });
    });
    ui.separator();
    egui::ScrollArea::vertical()
        .id_salt("journal-lines")
        .stick_to_bottom(true)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if app.log.is_empty() {
                widgets::hint(ui, crate::i18n::tr("Пусто", "Empty"));
            }
            let colors = theme::palette(ui);
            let fill = ui.visuals().selection.bg_fill;
            for (level, line) in &app.log {
                let color = match level {
                    Level::Ok => colors.ok,
                    Level::Warn => colors.warn,
                    Level::Err => colors.bad,
                    Level::Step => colors.text,
                    Level::Info => colors.muted,
                };
                let line_str = log_line(*level, line);
                let mut text = egui::RichText::new(&line_str)
                    .color(color)
                    .size(13.0);
                if *level == Level::Step {
                    text = text.strong();
                }
                if app.log_all_selected {
                    text = text.background_color(fill);
                }
                ui.label(text);
            }
        });
}

/// Ctrl+A over the journal, then Ctrl+C.
///
/// Both work on a Russian layout, and that is not an accident of this code:
/// egui-winit resolves a key as `logical.or(physical)`, so with a Cyrillic
/// layout the logical key («ф», «с») maps to nothing and the *physical* A and C
/// are used instead. What this adds is the select-all, which egui has no notion
/// of across a pile of separate labels — so it is our own flag, drawn as a
/// selection behind every line and copied as one block.
fn log_keys(app: &mut App, ui: &mut egui::Ui) {
    // While a text field has the keyboard, Ctrl+A belongs to that field.
    let typing = ui.memory(|m| m.focused()).is_some();

    if !typing && ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::A)) {
        app.log_all_selected = !app.log.is_empty();
    }

    if app.log_all_selected {
        // Only while our own selection is up, so a selection made with the mouse
        // is still copied by egui's label machinery rather than overwritten with
        // the whole journal.
        let copy = ui.input_mut(|i| {
            let asked = i
                .events
                .iter()
                .any(|e| matches!(e, egui::Event::Copy | egui::Event::Cut));
            if asked {
                i.events
                    .retain(|e| !matches!(e, egui::Event::Copy | egui::Event::Cut));
            }
            asked
        });
        if copy {
            ui.ctx().copy_text(journal_text(&app.log));
        }
        // Any click, or Escape, gives the selection up — otherwise the next
        // Ctrl+C anywhere in the window would still copy the journal.
        let dismissed = ui.input(|i| i.pointer.any_pressed() || i.key_pressed(egui::Key::Escape));
        if dismissed {
            app.log_all_selected = false;
        }
    }
}

fn footer(app: &mut App, ui: &mut egui::Ui) {
    let colors = theme::palette(ui);
    ui.horizontal(|ui| {
        let (label, color) = match app.status.as_ref() {
            Some(s) if s.relay_outdated => (
                crate::i18n::tr("Служба устарела", "Service outdated"),
                colors.warn,
            ),
            Some(s) if s.relay_running => (
                crate::i18n::tr("Служба запущена", "Service running"),
                colors.ok,
            ),
            Some(_) => (
                crate::i18n::tr("Служба остановлена", "Service stopped"),
                colors.muted,
            ),
            None => (
                crate::i18n::tr(
                    "Проверка службы…",
                    "Checking service…",
                ),
                colors.muted,
            ),
        };
        widgets::dot(ui, color);
        ui.label(
            egui::RichText::new(label)
                .size(12.5)
                .color(colors.muted),
        );
        if let Some(what) = &app.busy {
            ui.add(egui::Spinner::new().size(13.0));
            ui.label(
                egui::RichText::new(what)
                    .size(12.5)
                    .color(colors.muted),
            );
        }
        if app.main_view.page == Page::Overview {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if deactivation_button(ui, !app.is_busy()).clicked() {
                    app.main_view.confirm_deactivation = true;
                }
            });
        } else {
            ui.allocate_space(egui::vec2(0.0, 32.0));
        }
    });
}

fn deactivation_button(ui: &mut egui::Ui, enabled: bool) -> egui::Response {
    let colors = theme::palette(ui);
    let resp = ui.add_enabled(
        enabled,
        egui::Button::new(widgets::icon_text(
            widgets::POWER,
            crate::i18n::tr(
                "Полная деактивация",
                "Full deactivation",
            ),
            colors.muted,
        ))
        .frame_when_inactive(false)
        .min_size(egui::vec2(0.0, 32.0)),
    );
    widgets::hover_text(
        resp,
        ui,
        crate::i18n::tr(
            "Снять патчи, выключить обход ошибки 400 и удалить фоновые службы",
            "Remove patches, turn off error 400 bypass, and delete background services",
        ),
    )
}

fn deactivation_dialog(app: &mut App, ctx: &egui::Context) {
    if !app.main_view.confirm_deactivation {
        return;
    }
    let dialog = egui::Modal::new(egui::Id::new("confirm-deactivation")).show(ctx, |ui| {
        ui.set_max_width(420.0);
        section_title(
            ui,
            crate::i18n::tr(
                "Полная деактивация",
                "Full deactivation",
            ),
        );
        widgets::wrapped_label(
            ui,
            crate::i18n::tr(
                "Antigravity будет закрыт. Патчи будут сняты, обход выключен, фоновые службы и данные анлокера удалены.",
                "Antigravity will be closed. Patches will be removed, bypass turned off, and background services and unlocker data deleted.",
            ),
            14.5,
            theme::palette(ui).text,
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let confirm = widgets::command(
                ui,
                widgets::POWER,
                crate::i18n::tr("Деактивировать", "Deactivate"),
                false,
                !app.is_busy(),
            )
            .clicked();
            let cancel = ui
                .button(
                    crate::i18n::tr("Отмена", "Cancel"),
                )
                .clicked();
            (confirm, cancel)
        })
        .inner
    });
    let (confirm, cancel) = dialog.inner;
    if confirm {
        app.busy = Some(
            crate::i18n::tr(
                "Полная деактивация",
                "Full deactivation",
            )
            .into(),
        );
        app.worker.send(Cmd::Deactivate);
    }
    if confirm || cancel || dialog.should_close() {
        app.main_view.confirm_deactivation = false;
    }
}

/// The pencil dialog: type or paste a folder, we resolve it to an install root.
pub fn path_dialog(app: &mut App, ctx: &egui::Context) {
    let Some(mut text) = app.path_dialog.take() else {
        return;
    };
    let mut keep_open = true;
    let mut submit = false;

    egui::Window::new(
        crate::i18n::tr(
            "Путь к Antigravity",
            "Path to Antigravity",
        ),
    )
    .collapsible(false)
    .resizable(false)
    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
    .show(ctx, |ui| {
        ui.set_min_width(420.0);
        widgets::hint(
            ui,
            crate::i18n::tr(
                "Папка установки Antigravity, IDE или CLI. Можно указать вложенную — корень будет найден сам.",
                "Installation folder for Antigravity, IDE, or CLI. A nested folder works too — the root will be found automatically.",
            ),
        );
        ui.add_space(8.0);
        ui.add(
            egui::TextEdit::singleline(&mut text)
                .desired_width(f32::INFINITY)
                .hint_text("C:\\Users\\...\\Programs\\Antigravity"),
        );
        if let Some(err) = &app.path_dialog_error {
            ui.add_space(6.0);
            widgets::wrapped_label(ui, err, 12.5, theme::palette(ui).bad);
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if widgets::primary(
                ui,
                crate::i18n::tr("Добавить", "Add"),
                !text.trim().is_empty(),
            )
            .clicked()
            {
                submit = true;
            }
            if widgets::ghost(
                ui,
                crate::i18n::tr("Отмена", "Cancel"),
            )
            .clicked()
            {
                keep_open = false;
            }
        });
    });

    if submit {
        let cleaned = crate::clean_input_path(&text);
        match crate::ops::resolve_manual_path(std::path::Path::new(&cleaned)) {
            Some(root) => {
                app.worker.send(Cmd::AddPath(root));
                app.path_dialog_error = None;
                keep_open = false;
            }
            None => {
                app.path_dialog_error = Some(
                    crate::i18n::tr(
                        "По этому пути установка Antigravity не найдена.",
                        "Antigravity installation not found at this path.",
                    )
                    .into(),
                );
            }
        }
    }

    if keep_open {
        app.path_dialog = Some(text);
    } else {
        app.path_dialog_error = None;
    }
}

#[cfg(test)]
mod vpn_exclusion_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn copies_the_running_service_path_without_a_vpn_warning() {
        let relay_exe = PathBuf::from("custom-install").join("relay");
        let mut facts = status::Facts {
            relay_running: true,
            relay_exe: relay_exe.display().to_string(),
            ..Default::default()
        };
        assert_eq!(vpn_exclusion_path(&facts).unwrap(), relay_exe);

        facts.relay_uses_vpn = true;
        assert_eq!(vpn_exclusion_path(&facts).unwrap(), relay_exe);

        facts.relay_running = false;
        assert_eq!(
            vpn_exclusion_path(&facts).unwrap(),
            std::env::current_exe().unwrap()
        );
    }

    #[test]
    fn uses_the_installed_service_path_before_the_first_report() {
        let facts = status::Facts {
            relay_running: true,
            ..Default::default()
        };
        assert_eq!(
            vpn_exclusion_path(&facts).unwrap(),
            crate::background::installed_exe()
        );
    }
}

#[cfg(test)]
mod panel_tests {
    use super::*;

    #[test]
    fn deactivation_stays_in_the_footer_while_the_page_scrolls() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut previous = None;
        for offset in [0.0, 500.0] {
            let size = egui::vec2(940.0, 650.0);
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |root| {
                let colors = theme::palette(root);
                let button = footer_panel(colors)
                    .show(root, |ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            deactivation_button(ui, true).rect
                        })
                        .inner
                    })
                    .inner;
                assert!(button.right() >= size.x - 20.0);
                assert!(button.bottom() >= size.y - 12.0);
                if let Some(previous) = previous {
                    assert_eq!(button, previous);
                }
                previous = Some(button);
                egui::CentralPanel::default().show(root, |ui| {
                    let scroll = egui::ScrollArea::vertical()
                        .vertical_scroll_offset(offset)
                        .show(ui, |ui| {
                            ui.label("Scrollable body");
                            ui.add_space(2000.0);
                        });
                    assert!(scroll.inner_rect.bottom() < button.top());
                    assert_eq!(scroll.state.offset.y, offset);
                });
            });
            output.drop_without_applying_deltas();
        }
    }

    #[test]
    fn guided_proxy_setup_waits_for_its_own_successful_save() {
        let mut view = ViewState::default();
        view.begin_setup(Setup::GroupCopy);
        assert_eq!(view.page, Page::Settings);
        view.highlight(Setup::GroupTelegram);
        view.highlight(Setup::GroupCode);
        view.saving_proxy = Some(Cap::GroupProxy);
        view.proxy_saved(Cap::OwnProxy, Ok(()));
        assert_eq!(view.saving_proxy, Some(Cap::GroupProxy));
        view.proxy_saved(Cap::GroupProxy, Err("invalid".into()));
        assert_eq!(view.page, Page::Settings);
        assert_eq!(view.setup, Some(Setup::GroupCode));
        assert!(view.saving_proxy.is_none());
        view.saving_proxy = Some(Cap::GroupProxy);
        view.proxy_saved(Cap::GroupProxy, Ok(()));
        assert_eq!(view.page, Page::Overview);
        assert!(view.setup.is_none());
    }

    #[test]
    fn journal_copy_includes_every_line_in_display_order() {
        let log = [
            (Level::Step, "First".into()),
            (Level::Info, "Middle".into()),
            (Level::Err, "Last".into()),
        ];
        assert_eq!(journal_text(&log), "— First\nMiddle\nLast");
    }

    #[test]
    fn theme_toggle_switches_between_dark_and_light_and_resets_to_system() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut mode = crate::settings::ThemeMode::System;

        let initial_dark = ctx.theme() == egui::Theme::Dark;
        let expected_next = if initial_dark {
            crate::settings::ThemeMode::Light
        } else {
            crate::settings::ThemeMode::Dark
        };

        let size = egui::vec2(200.0, 80.0);
        let mut time = 0.0;
        let run_step = |ctx: &egui::Context,
                        time: &mut f64,
                        mode: &mut crate::settings::ThemeMode,
                        events: Vec<egui::Event>| {
            *time += 0.1;
            let mut center = egui::Pos2::ZERO;
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                time: Some(*time),
                events,
                ..Default::default()
            };
            let out = ctx.run_ui(input, |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    let (resp, next) = theme_toggle_button(*mode, ui);
                    center = resp.rect.center();
                    if let Some(next) = next {
                        *mode = next;
                        theme::set_preference(ui.ctx(), next);
                    }
                });
            });
            out.drop_without_applying_deltas();
            center
        };

        let button_center = run_step(&ctx, &mut time, &mut mode, Vec::new());
        for pressed in [true, false] {
            run_step(
                &ctx,
                &mut time,
                &mut mode,
                vec![
                    egui::Event::PointerMoved(button_center),
                    egui::Event::PointerButton {
                        pos: button_center,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        assert_eq!(mode, expected_next);
        assert_eq!(
            ctx.theme(),
            match expected_next {
                crate::settings::ThemeMode::Dark => egui::Theme::Dark,
                crate::settings::ThemeMode::Light => egui::Theme::Light,
                crate::settings::ThemeMode::System => unreachable!(),
            }
        );

        for pressed in [true, false] {
            run_step(
                &ctx,
                &mut time,
                &mut mode,
                vec![
                    egui::Event::PointerMoved(button_center),
                    egui::Event::PointerButton {
                        pos: button_center,
                        button: egui::PointerButton::Secondary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        assert_eq!(mode, crate::settings::ThemeMode::System);
    }
}
