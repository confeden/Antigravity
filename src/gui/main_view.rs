//! The one screen the tool has once the key is in.
//!
//! Top to bottom, in the order a person who is not a programmer reads it:
//!
//! 1. **One status card** — is Antigravity going to answer, and if not, the one
//!    thing to press (`status`). Everything else on the screen is mechanism.
//! 2. **Antigravity** — the three switches anyone needs (unlock sign-in, get
//!    past the 400, keep the patch after updates) and the installs found.
//! 3. **Для опытных**, folded — the parts of the bypass one by one, the DNS
//!    pool, the user's own proxy, what the network looks like right now.
//! 4. **Журнал**, folded.
//!
//! Everything is still a switch that undoes itself - the rule the window was
//! built on - but the switches are no longer the first thing a user has to
//! understand. The bypass picks its own path on every network (D25), so there
//! is nothing about VPNs, DNS or proxies anyone *has* to decide.

use eframe::egui;

use std::time::Duration;

use super::status::{self, Action, Tone};
use super::{theme, widgets, App, DONATE_URL, TELEGRAM_GROUP_URL};
use crate::ops::{Cap, Cmd, Level, State};
use crate::utils::mask_path;

#[cfg(all(test, windows))]
thread_local! {
    static WSL_ACTION_RECTS: std::cell::RefCell<Vec<egui::Rect>> = const { std::cell::RefCell::new(Vec::new()) };
    static HEADER_RECTS: std::cell::RefCell<Vec<egui::Rect>> = const { std::cell::RefCell::new(Vec::new()) };
    static BODY_META: std::cell::RefCell<Option<(egui::Id, egui::Rect, f32)>> = const { std::cell::RefCell::new(None) };
    static HEADER_MENU: std::cell::RefCell<Option<(egui::Id, bool)>> = const { std::cell::RefCell::new(None) };
    static INSTALL_RECTS: std::cell::RefCell<Vec<(&'static str, egui::Rect)>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(all(test, windows))]
mod layout_tests {
    use super::*;
    use crate::wsl_api::{RegisteredDistro, RegistrationFreshness, RegistrationState, WslPreferences, WslTargetState, TargetApplyResult};

    fn status() -> crate::ops::Status {
        crate::ops::Status {
            wsl: crate::wsl_api::WslStatus {
                preferences: Some(WslPreferences { enabled: true, distros: vec!["Ubuntu".into()] }),
                registration_freshness: RegistrationFreshness::Current,
                distributions: vec![RegisteredDistro { name: "Ubuntu".into(), registration: RegistrationState::Present, selected: true, running: Some(true) }],
                ..Default::default()
            },
            admin: true, installs: Vec::new(), client_patch: State::Off, watchdog: State::Off,
            dns: State::Off, local_proxy: State::Off, own_proxy: State::Off,
            builtin_exits: State::Off, group_proxy: State::Off, dns_rotation: State::Off,
            vpn: None, own_proxy_text: String::new(), custom_dns_text: String::new(),
            relay_outdated: false, relay_running: false, rules: false,
            providers: Vec::new(), relay_egress: None,
        }
    }

    fn frame(ctx: &egui::Context, app: &mut App, size: egui::Vec2) -> (Vec<egui::Rect>, Vec<egui::Rect>) {
        WSL_ACTION_RECTS.with(|r| r.borrow_mut().clear());
        HEADER_RECTS.with(|r| r.borrow_mut().clear());
        let input = egui::RawInput { screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)), ..Default::default() };
        let mut output = ctx.run_ui(input, |ui| view(app, ui));
        // This geometry-only fixture deliberately has no painter.
        output.textures_delta.clear();
        (WSL_ACTION_RECTS.with(|r| r.borrow().clone()), HEADER_RECTS.with(|r| r.borrow().clone()))
    }

    #[test]
    fn wsl_actions_stay_fixed_across_status_only_updates() {
        for (size, scale) in [(egui::vec2(520.0, 620.0), 1.0), (egui::vec2(600.0, 840.0), 1.25), (egui::vec2(1000.0, 900.0), 1.5)] {
            let ctx = egui::Context::default();
            ctx.set_pixels_per_point(scale);
            let (mut app, commands) = App::for_layout_test(status());
            let _ = frame(&ctx, &mut app, size);
            let baseline = frame(&ctx, &mut app, size);
            assert_eq!(baseline.0.len(), 2);
            assert_eq!(baseline.1.len(), 1);
            let wsl = &mut app.status.as_mut().unwrap().wsl;
            wsl.loading = true;
            wsl.pending = true;
            wsl.error = Some("synthetic error with a longer explanation".into());
            wsl.results.push(TargetApplyResult { name: "Ubuntu".into(), state: WslTargetState::Failed, detail: Some("synthetic detail".into()) });
            app.busy = Some("synthetic progress".into());
            let changed = frame(&ctx, &mut app, size);
            assert_eq!(baseline, changed);
            app.busy = None;
            app.update = Some(crate::update::ReleaseInfo { tag_name: "v99.0.0".into(), html_url: String::new(), name: None, body: None, published_at: None, prerelease: false, draft: false, assets: Vec::new() });
            assert_eq!(baseline, frame(&ctx, &mut app, size));
            app.busy = Some("synthetic progress".into());
            assert_eq!(baseline, frame(&ctx, &mut app, size));
            assert!(commands.try_recv().is_err());
        }
    }

    #[test]
    fn disclosure_opens_from_keyboard_without_external_action() {
        let ctx = egui::Context::default();
        let (mut app, commands) = App::for_layout_test(status());
        app.busy = Some("synthetic progress".into());
        let size = egui::vec2(600.0, 840.0);
        let _ = frame(&ctx, &mut app, size);
        let (id, _) = HEADER_MENU.with(|m| m.borrow().expect("menu present"));
        ctx.memory_mut(|m| m.request_focus(id));
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events: vec![egui::Event::Key { key: egui::Key::Enter, physical_key: None, pressed: true, repeat: false, modifiers: egui::Modifiers::NONE }],
            ..Default::default()
        };
        let mut output = ctx.run_ui(input, |ui| view(&mut app, ui));
        output.textures_delta.clear();
        assert!(HEADER_MENU.with(|m| m.borrow().expect("menu present").1));
        assert!(commands.try_recv().is_err());
    }

    #[test]
    fn long_install_path_does_not_overlap_action_rectangles() {
        let mut snapshot = status();
        snapshot.installs.push(crate::ops::InstallRow {
            path: Some(std::path::PathBuf::from(r"C:\Synthetic\A very long installation location\Nested folder\Another nested folder\Antigravity")),
            label: "Antigravity IDE", patched: Some(false), manual: true,
        });
        let ctx = egui::Context::default();
        let (mut app, commands) = App::for_layout_test(snapshot);
        let size = egui::vec2(520.0, 620.0);
        let _ = frame(&ctx, &mut app, size);
        INSTALL_RECTS.with(|r| r.borrow_mut().clear());
        let _ = frame(&ctx, &mut app, size);
        let rows = INSTALL_RECTS.with(|r| r.borrow().clone());
        let path = rows.iter().find(|(name, _)| *name == "path").expect("path rect").1;
        for name in ["edit", "remove", "patch"] {
            let action = rows.iter().find(|(key, _)| *key == name).expect("action rect").1;
            assert!(path.max.x <= action.min.x, "{name} overlaps the path: {path:?}, {action:?}");
        }
        assert!(commands.try_recv().is_err());
    }

    #[test]
    #[ignore = "owned synthetic native visual fixture; requires explicit inputs"]
    fn native_layout_preview() {
        use std::io::Write;
        use winit::platform::windows::EventLoopBuilderExtWindows;

        fn required(name: &str) -> String { std::env::var(name).unwrap_or_else(|_| panic!("missing {name}")) }
        fn number(name: &str, zero: bool) -> f32 {
            let n: f32 = required(name).parse().unwrap_or_else(|_| panic!("invalid {name}"));
            assert!(n.is_finite() && if zero { n >= 0.0 } else { n > 0.0 }, "invalid {name}");
            n
        }
        let case = required("AG_LAYOUT_CASE");
        assert!(["idle", "busy", "update", "combined", "loading", "error", "results", "cancel", "long"].contains(&case.as_str()), "invalid case");
        let width = number("AG_LAYOUT_WIDTH", false);
        let height = number("AG_LAYOUT_HEIGHT", false);
        let zoom = number("AG_LAYOUT_ZOOM", false);
        let duration_ms: u64 = required("AG_LAYOUT_DURATION_MS").parse().expect("invalid duration");
        assert!(duration_ms > 0, "invalid duration");
        let scroll_y = match std::env::var("AG_LAYOUT_SCROLL_Y") {
            Ok(value) => { let n: f32 = value.parse().expect("invalid scroll"); assert!(n.is_finite() && n >= 0.0); n }
            Err(std::env::VarError::NotPresent) => 0.0,
            Err(_) => panic!("invalid scroll"),
        };
        assert!((width * zoom).is_finite() && (height * zoom).is_finite(), "invalid scaled size");
        let mut s = status();
        s.wsl.preferences.as_mut().unwrap().distros.push("Debian".into());
        s.wsl.distributions.push(RegisteredDistro { name: "Debian".into(), registration: RegistrationState::Present, selected: true, running: Some(true) });
        if case == "long" {
            s.wsl.distributions.push(RegisteredDistro { name: "Synthetic long distribution name with spaces and unicode пример extended example".into(), registration: RegistrationState::Present, selected: false, running: Some(false) });
            s.installs.push(crate::ops::InstallRow { path: Some(std::path::PathBuf::from(r"C:\Synthetic\A very long installation location\Nested folder\Another nested folder\Antigravity")), label: "Antigravity IDE", patched: Some(true), manual: true });
        }
        if case == "loading" { s.wsl.loading = true; }
        if case == "error" { s.wsl.error = Some("Синтетическая ошибка обнаружения".into()); }
        if case == "results" {
            for name in ["Ubuntu", "Debian"] { s.wsl.results.push(TargetApplyResult { name: name.into(), state: WslTargetState::ReadyToOpen, detail: Some("Подготовка проверена".into()) }); }
        }
        if case == "cancel" { s.wsl.pending = true; }
        let (mut app, commands) = App::for_layout_test(s);
        if case == "busy" || case == "combined" { app.busy = Some("Синтетическая операция".into()); }
        if case == "update" || case == "combined" {
            app.update = Some(crate::update::ReleaseInfo { tag_name: "v99.0.0".into(), html_url: String::new(), name: None, body: None, published_at: None, prerelease: false, draft: false, assets: Vec::new() });
        }
        struct Preview { app: App, commands: std::sync::mpsc::Receiver<Cmd>, case: String, width: f32, height: f32, zoom: f32, scroll_y: f32, duration: Duration, frames: u32, ready: Option<std::time::Instant> }
        impl eframe::App for Preview {
            fn persist_egui_memory(&self) -> bool { false }
            fn raw_input_hook(&mut self, _: &egui::Context, input: &mut egui::RawInput) { input.events.clear(); }
            fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
                let ctx = ui.ctx().clone();
                WSL_ACTION_RECTS.with(|r| r.borrow_mut().clear());
                HEADER_RECTS.with(|r| r.borrow_mut().clear());
                let avail = ui.available_size();
                egui::Frame::central_panel(&ui.style().clone()).inner_margin(egui::Margin { left: 18, right: 4, top: 18, bottom: 4 }).show(ui, |ui| {
                    ui.set_min_height(avail.y - 22.0);
                    view(&mut self.app, ui);
                });
                self.frames += 1;
                if self.frames == 1 {
                    BODY_META.with(|meta| {
                        let (id, _, _) = meta.borrow().expect("body metadata");
                        let mut state = egui::scroll_area::State::load(&ctx, id).expect("scroll state");
                        state.offset.y = self.scroll_y;
                        state.store(&ctx, id);
                    });
                }
                if self.frames == 4 {
                    let actions = WSL_ACTION_RECTS.with(|r| r.borrow().clone());
                    let header = HEADER_RECTS.with(|r| r.borrow().clone());
                    let (_, body, actual_scroll) = BODY_META.with(|m| m.borrow().expect("body metadata"));
                    let rect = |r: egui::Rect| [r.min.x, r.min.y, r.max.x, r.max.y];
                    let native = ctx.input(|i| i.viewport().native_pixels_per_point);
                    let info = serde_json::json!({"pid": std::process::id(), "case": self.case, "title": format!("Antigravity Unlocker UI fixture - {}", self.case), "logical_width": self.width, "logical_height": self.height, "zoom": self.zoom, "native_ppp": native, "effective_ppp": ctx.pixels_per_point(), "body": rect(body), "header": header.into_iter().map(rect).collect::<Vec<_>>(), "actions": actions.into_iter().map(rect).collect::<Vec<_>>(), "scroll_requested": self.scroll_y, "scroll_actual": actual_scroll});
                    println!("FRAME_READY {info}");
                    std::io::stdout().flush().expect("flush frame marker");
                    self.ready = Some(std::time::Instant::now());
                }
                assert!(self.commands.try_recv().is_err(), "fixture must not submit commands");
                if self.ready.is_some_and(|t| t.elapsed() >= self.duration) {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                } else {
                    ctx.request_repaint_after(Duration::from_millis(100));
                }
            }
        }
        let title = format!("Antigravity Unlocker UI fixture - {case}");
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_title(&title).with_inner_size([width * zoom, height * zoom]).with_active(false).with_mouse_passthrough(false),
            event_loop_builder: Some(Box::new(|builder| { builder.with_any_thread(true); })),
            persist_window: false,
            ..Default::default()
        };
        let preview = Preview { app, commands, case, width, height, zoom, scroll_y, duration: Duration::from_millis(duration_ms), frames: 0, ready: None };
        eframe::run_native(&title, options, Box::new(move |cc| { theme::apply(&cc.egui_ctx); cc.egui_ctx.set_zoom_factor(zoom); Ok(Box::new(preview)) })).expect("preview window failed");
    }
}

pub fn view(app: &mut App, ui: &mut egui::Ui) {
    egui::Panel::top("status-strip")
        .frame(egui::Frame::new())
        .show(ui, |ui| header(app, ui));
    // A bottom panel, reserved *before* the scrolling body. Laid out the other
    // way round — scroll area first, footer after — the scroll area claims every
    // remaining pixel and the footer is positioned past the bottom of the
    // window: measured, painted, and never on screen. A panel is the one
    // construct that takes its strip out of the parent first.
    egui::Panel::bottom("footer")
        .frame(egui::Frame::new().inner_margin(egui::Margin {
            top: 2,
            bottom: 2,
            ..Default::default()
        }))
        .show_separator_line(true)
        .show(ui, footer);

    egui::CentralPanel::default()
        .frame(egui::Frame::new())
        .show(ui, |ui| {
            let scroll = egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // Put back what the outer frame gave up to the scroll bar,
                    // on the inside of it, so the cards keep their margin and the
                    // bar still lands against the window edge.
                    ui.set_max_width(ui.available_width() - 10.0);
                    status_card(app, ui);
                    ui.add_space(12.0);
                    antigravity_card(app, ui);
                    ui.add_space(12.0);
                    advanced_card(app, ui);
                    ui.add_space(6.0);
                    log_card(app, ui);
                    ui.add_space(12.0);
                });
            #[cfg(all(test, windows))]
            BODY_META.with(|meta| *meta.borrow_mut() = Some((scroll.id, scroll.inner_rect, scroll.state.offset.y)));
            #[cfg(not(all(test, windows)))]
            let _ = scroll;
        });
}

// ---------------------------------------------------------------------------

fn header(app: &mut App, ui: &mut egui::Ui) {
    let row = ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if app.update.is_some() && ui.button("Обновление").clicked() {
                crate::utils::open_url(crate::update::RELEASES_LATEST_URL);
            }
            let menu = ui.menu_button("Подробнее", |ui| {
                ui.label(super::title());
                if let Some(what) = &app.busy { ui.label(what); }
                if let Some(rel) = &app.update {
                    ui.label(format!("Доступна новая версия — {}", rel.display_version()));
                }
            });
            #[cfg(all(test, windows))]
            HEADER_MENU.with(|m| *m.borrow_mut() = Some((menu.response.id, menu.inner.is_some())));
            #[cfg(not(all(test, windows)))]
            let _ = menu;
            let text = app.busy.as_deref().map(str::to_owned).unwrap_or_else(super::title);
            ui.add(egui::Label::new(egui::RichText::new(text).size(12.0).color(theme::MUTED)).truncate());
        });
    });
    #[cfg(all(test, windows))]
    HEADER_RECTS.with(|rects| rects.borrow_mut().push(row.response.rect));
    #[cfg(not(all(test, windows)))]
    let _ = row;
}

// ---------------------------------------------------------------------------
// The status card
// ---------------------------------------------------------------------------

/// Everything the verdict is made of, read off the window's own state.
fn facts(app: &App) -> Option<status::Facts> {
    let s = app.status.as_ref()?;
    Some(status::Facts::read(s, &app.gate, app.gate_at.elapsed()))
}

fn status_card(app: &mut App, ui: &mut egui::Ui) {
    let Some(f) = facts(app) else {
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(16.0));
                ui.label(egui::RichText::new("Проверяю систему…").size(15.0));
            });
        });
        return;
    };
    let h = status::headline(&f);
    let accent = match h.tone {
        Tone::Ok => theme::OK,
        Tone::Wait => theme::ACCENT,
        Tone::Fixing => theme::WARN,
        Tone::Action => theme::BAD,
        Tone::Off => theme::MUTED,
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
        .fill(theme::CARD)
        .corner_radius(egui::CornerRadius::same(theme::RADIUS))
        .inner_margin(egui::Margin::same(16))
        .stroke(egui::Stroke::new(1.5, accent))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 6.0, accent);
                ui.label(
                    egui::RichText::new(&h.title)
                        .size(19.0)
                        .strong()
                        .color(theme::TEXT),
                );
            });
            ui.add_space(4.0);
            ui.label(egui::RichText::new(&h.detail).size(13.5).color(theme::TEXT));
            if let Some(action) = h.action {
                ui.add_space(10.0);
                if widgets::primary(ui, action.label(), !busy).clicked() {
                    pressed = Some(action);
                }
            }
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
                if ui
                    .add_enabled(!busy, egui::Button::new(egui::RichText::new("Сохранить отчёт").size(12.5)))
                    .on_hover_text("Всё, что нужно, чтобы понять, почему Antigravity отвечает или нет — одним файлом на рабочем столе: приложите его к сообщению")
                    .clicked()
                {
                    copy = true;
                }
                if let Some((_, path)) = &saved {
                    if ui
                        .add(egui::Button::new(egui::RichText::new("Показать файл").size(12.5)))
                        .on_hover_text("Открыть папку с отчётом")
                        .clicked()
                    {
                        reveal = Some(path.clone());
                    }
                }
            });
            if let Some((_, path)) = &saved {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!(
                        "Отчёт сохранён на рабочий стол: «{}». Приложите этот файл к сообщению.",
                        path.file_name()
                            .map(|f| f.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    ))
                    .size(12.5)
                    .color(theme::OK),
                );
                ui.ctx().request_repaint_after(Duration::from_millis(500));
            }
            if app
                .report_clipboard_at
                .is_some_and(|at| at.elapsed() < REPORT_SHOWN_FOR)
            {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Файл сохранить не удалось — отчёт скопирован, вставьте его в сообщение.",
                    )
                    .size(12.5)
                    .color(theme::WARN),
                );
                ui.ctx().request_repaint_after(Duration::from_millis(500));
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
}

/// How long the card goes on saying where the report was saved. Four seconds
/// was right for «скопировано»; this one is an instruction to go and find a
/// file and attach it, and the user is in another window by then.
const REPORT_SHOWN_FOR: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Antigravity: the three switches anyone needs, and the installs
// ---------------------------------------------------------------------------

fn antigravity_card(app: &mut App, ui: &mut egui::Ui) {
    widgets::card(ui, |ui| {
        cap_row(app, ui, Cap::ClientPatch);

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);
        bypass_master(app, ui);

        // The group proxy is a way of its own: it can be the only one on, so the
        // row is always there.
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);
        cap_row(app, ui, Cap::GroupProxy);
        group_proxy_field(app, ui);

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);
        cap_row(app, ui, Cap::Watchdog);

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("Найденные установки Antigravity")
                .size(12.5)
                .color(theme::MUTED),
        );
        ui.add_space(6.0);
        install_rows(app, ui);

        #[cfg(target_os = "windows")]
        {
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(8.0);
            wsl_options(app, ui);
        }
    });
}

#[cfg(target_os = "windows")]
fn wsl_options(app: &mut App, ui: &mut egui::Ui) {
    use crate::wsl_api::{WslTargetState, RegistrationState, RegistrationFreshness};

    let Some(wsl) = app.status.as_ref().map(|s| s.wsl.clone()) else {
        ui.label("WSL: проверка…");
        return;
    };
    let mut enabled = wsl.preferences.as_ref().is_some_and(|p| p.enabled);
    if ui.add_enabled(!wsl.pending && !wsl.loading, egui::Checkbox::new(&mut enabled, "применить и для WSL")).changed() {
        app.worker.send(Cmd::SetWslEnabled(enabled));
    }
    for distro in &wsl.distributions {
        ui.push_id((&distro.name, "wsl-distro"), |ui| {
            let mut selected = distro.selected;
            if ui.add_enabled(wsl.can_set_distro(&distro.name, !distro.selected), egui::Checkbox::new(&mut selected, &distro.name)).changed() {
                app.worker.send(Cmd::SetWslDistro { name: distro.name.clone(), selected });
            }
        });
    }
    ui.horizontal_wrapped(|ui| {
        let refresh = ui.add_enabled(!wsl.loading && !wsl.pending, egui::Button::new("Обновить список"));
        #[cfg(all(test, windows))]
        WSL_ACTION_RECTS.with(|rects| rects.borrow_mut().push(refresh.rect));
        if refresh.clicked() {
            app.worker.send(Cmd::RefreshWsl);
        }
        let apply = ui.add_enabled(!wsl.pending, egui::Button::new("Применить"));
        #[cfg(all(test, windows))]
        WSL_ACTION_RECTS.with(|rects| rects.borrow_mut().push(apply.rect));
        if apply.clicked() {
            app.worker.send(Cmd::ApplySettings);
        }
        if wsl.pending && ui.button("Отменить").clicked() {
            app.worker.send(Cmd::CancelWsl);
        }
    });
    if wsl.loading {
        ui.label("Поиск дистрибутивов WSL…");
    }
    if let Some(error) = &wsl.error {
        ui.label(format!("WSL: {error}"));
    }
    if wsl.registration_freshness == RegistrationFreshness::Current && wsl.distributions.is_empty() {
        ui.label("Дистрибутивы WSL не найдены.");
    }
    for distro in &wsl.distributions {
        let state = if distro.registration == RegistrationState::Absent {
            Some("Больше не найден")
        } else if distro.registration == RegistrationState::Unknown {
            Some("Список ещё не подтверждён")
        } else if distro.running == Some(false) {
            Some("Остановлен")
        } else {
            None
        };
        if let Some(state) = state {
            ui.label(format!("{}: {state}", distro.name));
        }
    }
    if wsl.pending { ui.label("Операция выполняется или её завершение ещё не подтверждено."); }
    for result in &wsl.results {
        let state = match result.state {
            WslTargetState::Unconfirmed => "Не подтверждено",
            WslTargetState::NotApplied => "Не применено",
            WslTargetState::Preparing => "Подготовка",
            WslTargetState::ReadyToOpen => "Готово к открытию",
            WslTargetState::Blocked => "Заблокировано",
            WslTargetState::Pending => "Выполняется",
            WslTargetState::Failed => "Ошибка",
            WslTargetState::Cancelled => "Отменено",
        };
        let detail = result.detail.as_deref().map(|s| format!(": {s}")).unwrap_or_default();
        ui.label(format!("{}: {state}{detail}", result.name));
    }
}

/// The master switch of the bypass. Derived, never stored: it is on when any
/// part of the bypass is, which keeps one truth instead of two.
fn bypass_master(app: &mut App, ui: &mut egui::Ui) {
    let any_on = app.status.as_ref().is_some_and(|s| s.bypass_on());
    let mut master = any_on;
    let busy = app.is_busy();
    let flipped = widgets::switch_row(ui, &mut master, !busy, |ui| {
        let (title, hint) = status::BYPASS_TEXT;
        ui.label(egui::RichText::new(title).size(14.0));
        widgets::hint(ui, hint);
    });
    if flipped {
        for cap in crate::ops::bypass_order(master) {
            app.worker.send(Cmd::Set(cap, master));
        }
    }
}

fn install_rows(app: &mut App, ui: &mut egui::Ui) {
    let Some(rows) = app.status.as_ref().map(|s| s.installs.clone()) else {
        widgets::hint(ui, "Идёт поиск…");
        return;
    };

    let mut forget: Option<std::path::PathBuf> = None;
    let mut edit: Option<String> = None;
    let mut patch: Option<std::path::PathBuf> = None;

    for row in &rows {
        ui.horizontal(|ui| {
            let color = match (&row.path, row.patched) {
                (None, _) => theme::LINE,
                (Some(_), Some(true)) => theme::OK,
                (Some(_), Some(false)) => theme::MUTED,
                (Some(_), None) => theme::LINE,
            };
            widgets::dot(ui, color);
            ui.label(egui::RichText::new(row.label).size(13.0));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if row.manual {
                    if let Some(p) = &row.path {
                        let button = ui
                            .small_button("✖")
                            .on_hover_text("Убрать указанный путь");
                        #[cfg(all(test, windows))]
                        INSTALL_RECTS.with(|r| r.borrow_mut().push(("remove", button.rect)));
                        if button.clicked() {
                            forget = Some(p.clone());
                        }
                    }
                }
                if let (Some(path), Some(false)) = (&row.path, row.patched) {
                    let button = ui
                        .small_button("Пропатчить")
                        .on_hover_text("Наложить патч на эту установку");
                    #[cfg(all(test, windows))]
                    INSTALL_RECTS.with(|r| r.borrow_mut().push(("patch", button.rect)));
                    if button.clicked() {
                        patch = Some(path.clone());
                    }
                }
                let button = ui
                    .small_button("✏")
                    .on_hover_text("Указать путь вручную");
                #[cfg(all(test, windows))]
                INSTALL_RECTS.with(|r| r.borrow_mut().push(("edit", button.rect)));
                if button.clicked() {
                    edit = Some(
                        row.path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                    );
                }
                // Allocate controls first so the remaining width is the actual
                // space available to the path, including optional controls.
                match &row.path {
                    Some(path) => {
                        let shown = mask_path(&path.display().to_string());
                        let label = ui.add(egui::Label::new(
                            egui::RichText::new(shown).size(12.0).color(theme::MUTED).monospace(),
                        ).truncate()).on_hover_text(path.display().to_string());
                        #[cfg(all(test, windows))]
                        INSTALL_RECTS.with(|r| r.borrow_mut().push(("path", label.rect)));
                        #[cfg(not(all(test, windows)))]
                        let _ = label;
                    }
                    None => {
                        ui.add(egui::Label::new(
                            egui::RichText::new("не найдено — укажите путь").size(12.0).color(theme::MUTED),
                        ).truncate());
                    }
                }
            });
        });
    }

    if let Some(p) = forget {
        app.worker.send(Cmd::ForgetPath(p));
    }
    if let Some(p) = patch {
        app.worker.send(Cmd::PatchInstall(p));
    }
    if let Some(text) = edit {
        app.path_dialog = Some(text);
    }
}

// ---------------------------------------------------------------------------
// Для опытных
// ---------------------------------------------------------------------------

/// Folded sections start open in a *debug* build run with `AG_UNLOCKER_DEV_OPEN`
/// set, so the whole screen can be looked at without clicking. Always folded in
/// a release build.
fn dev_open() -> bool {
    cfg!(debug_assertions) && std::env::var_os("AG_UNLOCKER_DEV_OPEN").is_some()
}

fn advanced_card(app: &mut App, ui: &mut egui::Ui) {
    egui::CollapsingHeader::new(
        egui::RichText::new("Настройки для опытных")
            .size(13.0)
            .color(theme::MUTED),
    )
    .id_salt("advanced")
    .default_open(dev_open())
    .show(ui, |ui| {
        widgets::card(ui, |ui| {
            network_facts(app, ui);

            cap_row(app, ui, Cap::Dns);
            providers_list(app, ui);
            custom_dns_field(app, ui);

            ui.add_space(10.0);
            cap_row(app, ui, Cap::LocalProxy);

            ui.add_space(10.0);
            cap_row(app, ui, Cap::BuiltinExits);

            ui.add_space(10.0);
            cap_row(app, ui, Cap::OwnProxy);
            own_proxy_field(app, ui);
        });
    });
}

/// What the relay says about the network right now: the VPN, where it comes
/// out, and the path in use. Facts, not advice - there is nothing here the
/// user has to act on, which is why it sits in the folded section.
fn network_facts(app: &App, ui: &mut egui::Ui) {
    let Some(r) = app.gate.relay.as_ref() else {
        return;
    };
    let vpn = if !r.tunnel {
        "VPN не обнаружен.".to_string()
    } else if r.vpn_exit.is_empty() {
        "VPN включён — соединения службы с сервисами разблокировки идут мимо него.".to_string()
    } else if crate::upstream::region_is_blocked(&r.vpn_exit) {
        format!(
            "VPN включён, выход: {} — там ошибка 400, поэтому соединения идут мимо него.",
            r.vpn_exit
        )
    } else {
        format!(
            "VPN включён, выход: {} — используется как один из путей.",
            r.vpn_exit
        )
    };
    widgets::hint(ui, &vpn);
    if !r.route.is_empty() {
        widgets::hint(ui, &format!("Первый путь сейчас: {}.", r.route));
    }
    if !r.loopback {
        widgets::hint(
            ui,
            "Служба ещё не перехватывает имена серверов Google — Antigravity идёт через них, \
             только если перезапущен после включения обхода.",
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
    let busy = app.is_busy();

    let mut flip: Option<(String, bool)> = None;
    // (from, to) — set the moment the pointer passes over another row, not on
    // release: the row has to follow the cursor while the button is still down.
    let mut moved: Option<(usize, usize)> = None;
    let mut dropped = false;

    egui::CollapsingHeader::new(
        egui::RichText::new("Какие DNS использовать")
            .size(12.5)
            .color(theme::MUTED),
    )
    .id_salt("providers")
    .default_open(false)
    .show(ui, |ui| {
        let first_on = providers.iter().position(|p| p.enabled);
        widgets::hint(
            ui,
            "Порядок можно менять: зажмите полоски слева и перетащите. \
             Первый в списке спрашивается первым.",
        );
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
                        ui.label(egui::RichText::new("≡").size(15.0).color(theme::MUTED));
                    })
                    .response
                    .on_hover_cursor(egui::CursorIcon::Grab);

                    let mut on = p.enabled;
                    if widgets::switch(ui, &mut on, dns_on && !busy).changed() {
                        flip = Some((p.name.clone(), on));
                    }
                    // Without rotation only the first enabled one is ever asked,
                    // so the rest are drawn as what they are: on, but not in use.
                    let idle = !rotating && p.enabled && first_on != Some(i);
                    let text = egui::RichText::new(status::provider_name(&p.name)).size(13.0);
                    ui.label(if idle { text.color(theme::MUTED) } else { text });
                    if idle {
                        widgets::hint(ui, "— не используется");
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

fn group_proxy_field(app: &mut App, ui: &mut egui::Ui) {
    let busy = app.is_busy();
    ui.add_space(4.0);
    widgets::hint(
        ui,
        "Для активации прокси из группы Nova — отправьте туда команду и вставьте \
         полученный код в поле ниже.",
    );
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        if ui.button("Скопировать команду").clicked() {
            let cmd = format!("/ag+{}", crate::hwid::pc_code());
            crate::utils::set_clipboard_text(&cmd);
            app.log.push((
                Level::Info,
                "Команда скопирована — отправьте её в группе.".to_string(),
            ));
        }
        if ui.button("Открыть группу").clicked() {
            crate::utils::open_url(GROUP_ROOM_URL);
        }
    });
    ui.add_space(4.0);
    let field = egui::TextEdit::singleline(&mut app.group_key_input)
        .hint_text("код из группы")
        .desired_width(ui.available_width());
    let resp = ui
        .add_enabled(!busy, field)
        .on_hover_text("Правая кнопка мыши — вставить код из буфера");
    // Right click pastes: egui's field has no context menu, and the code
    // arrives on the clipboard from Telegram.
    let mut right_pasted = false;
    if resp.secondary_clicked() && !busy {
        if let Some(clip) = crate::utils::clipboard_text() {
            app.group_key_input = clip.trim().to_string();
            right_pasted = true;
        }
    }
    // The field shows the saved code. Sent when it holds a whole new code (a
    // paste), or on Enter - and only when it differs from what was sent last.
    let text = app.group_key_input.trim().to_string();
    let pasted = (resp.changed() || right_pasted) && text.starts_with("agk1.") && text.len() > 40;
    let entered =
        resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !text.is_empty();
    if (pasted || entered) && text != app.group_key_sent {
        app.worker.send(Cmd::SetGroupKey(text.clone()));
        app.group_key_input = text.clone();
        app.group_key_sent = text;
    }
}

/// The group's topic where the bot answers the command.
const GROUP_ROOM_URL: &str = "https://t.me/nova_txt/69864";

/// The user's own DNS server(s) for the bypass: joins the pool as one more provider.
fn custom_dns_field(app: &mut App, ui: &mut egui::Ui) {
    let busy = app.is_busy();
    ui.add_space(6.0);
    ui.label(
        egui::RichText::new("Свой DNS для обхода (IPv4 через пробел)")
            .size(12.0)
            .color(theme::MUTED),
    );
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        let field = egui::TextEdit::singleline(&mut app.custom_dns_input)
            .hint_text("например 77.88.8.8")
            .desired_width(ui.available_width() - 110.0);
        let resp = ui.add_enabled(!busy, field);
        let entered = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if ui
            .add_enabled(!busy, egui::Button::new("Применить"))
            .clicked()
            || entered
        {
            let text = app.custom_dns_input.clone();
            app.worker.send(Cmd::SetCustomDns(text));
        }
    });
}

fn own_proxy_field(app: &mut App, ui: &mut egui::Ui) {
    let busy = app.is_busy();
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        let field = egui::TextEdit::singleline(&mut app.own_proxy_input)
            .hint_text("логин:пароль@адрес:порт или адрес:порт")
            .desired_width(ui.available_width() - 110.0);
        let resp = ui.add_enabled(!busy, field);
        let entered = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if ui
            .add_enabled(!busy, egui::Button::new("Применить"))
            .clicked()
            || entered
        {
            let text = app.own_proxy_input.clone();
            app.worker.send(Cmd::SetOwnProxy(text));
        }
    });
}

// ---------------------------------------------------------------------------

/// One switch with its title, description and — when the system disagrees with
/// the switch — the reason.
fn cap_row(app: &mut App, ui: &mut egui::Ui, cap: Cap) {
    let (title, hint) = status::switch_text(cap);
    let state = app
        .status
        .as_ref()
        .map(|s| s.get(cap).clone())
        .unwrap_or(State::Off);
    let mut on = state.is_on();
    let blocked = matches!(state, State::Blocked(_));
    let enabled = !app.is_busy() && !blocked;

    let note = state.note().map(|s| s.to_string());
    let flipped = widgets::switch_row(ui, &mut on, enabled, |ui| {
        ui.label(egui::RichText::new(title).size(14.0));
        widgets::hint(ui, hint);
        if let Some(note) = note {
            ui.label(egui::RichText::new(note).size(12.0).color(if blocked {
                theme::WARN
            } else {
                theme::MUTED
            }));
        }
    });
    if flipped {
        app.worker.send(Cmd::Set(cap, on));
    }
}

// ---------------------------------------------------------------------------

/// One log line as it is drawn — and as it is copied, so what lands on the
/// clipboard is what was on screen.
fn log_line(level: Level, line: &str) -> String {
    if level == Level::Step {
        format!("— {line}")
    } else {
        line.to_string()
    }
}

fn log_card(app: &mut App, ui: &mut egui::Ui) {
    egui::CollapsingHeader::new(egui::RichText::new("Журнал").size(13.0).color(theme::MUTED))
        .id_salt("log")
        .default_open(dev_open())
        .show(ui, |ui| {
            // **Before** the lines are drawn, and that ordering is the whole
            // trick. egui's `LabelSelectionState` accumulates its copy per label,
            // as each one is drawn, and flushes it to the clipboard in
            // `end_pass` — i.e. after everything here. Consuming the Copy event
            // afterwards was too late: the labels had already accumulated (just
            // the one holding the cursor, hence "copies a single line"), and
            // their flush overwrote ours. Taking the event first means no label
            // ever sees it and our copy is the only one.
            log_keys(app, ui);

            // Selecting with the mouse and copying it is egui's own label
            // selection; the only thing missing was a way to take the lot, which
            // is what Ctrl+A does.
            let all_selected = app.log_all_selected;
            let fill = ui.visuals().selection.bg_fill;

            egui::ScrollArea::vertical()
                .max_height(160.0)
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if app.log.is_empty() {
                        widgets::hint(ui, "Пока ничего не делалось.");
                    }
                    for (level, line) in &app.log {
                        let color = match level {
                            Level::Ok => theme::OK,
                            Level::Warn => theme::WARN,
                            Level::Err => theme::BAD,
                            Level::Step => theme::TEXT,
                            Level::Info => theme::MUTED,
                        };
                        let mut text = egui::RichText::new(log_line(*level, line))
                            .color(color)
                            .size(12.5);
                        if *level == Level::Step {
                            text = text.strong();
                        }
                        if all_selected {
                            text = text.background_color(fill);
                        }
                        ui.label(text);
                    }
                });
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
            let text: String = app
                .log
                .iter()
                .map(|(level, line)| log_line(*level, line))
                .collect::<Vec<_>>()
                .join("\n");
            ui.ctx().copy_text(text);
        }
        // Any click, or Escape, gives the selection up — otherwise the next
        // Ctrl+C anywhere in the window would still copy the journal.
        let dismissed = ui.input(|i| i.pointer.any_pressed() || i.key_pressed(egui::Key::Escape));
        if dismissed {
            app.log_all_selected = false;
        }
    }
}

/// Text size in the footer. One point up from the rest of the small print — it
/// is the line people are meant to read, not a caption under something else.
const FOOTER_TEXT: f32 = 13.0;

fn footer(ui: &mut egui::Ui) {
    // The strip was about twice as tall as its text. Two things made it so, and
    // the margin was the smaller one: a link is an *interactive* widget, so it
    // claims `interact_size.y` (26 px, sized for buttons) however short its text
    // is. Shrinking that here — and only here — is what actually halves the bar.
    ui.spacing_mut().interact_size.y = 18.0;
    ui.spacing_mut().item_spacing.y = 0.0;

    // Wrap the links in reading order when the available width is narrow.
    ui.horizontal_wrapped(|ui| {
        ui.label(
            egui::RichText::new("Отблагодарить копеечкой:")
                .size(FOOTER_TEXT)
                .color(theme::MUTED),
        );
        if ui
            .link(egui::RichText::new("nova-app.eu/donate").size(FOOTER_TEXT))
            .clicked()
        {
            crate::utils::open_url(DONATE_URL);
        }
        ui.label(
            egui::RichText::new("|")
                .size(FOOTER_TEXT)
                .color(theme::LINE),
        );
        ui.label(
            egui::RichText::new("Группа в Telegram:")
                .size(FOOTER_TEXT)
                .color(theme::MUTED),
        );
        if ui
            .link(egui::RichText::new("t.me/nova_txt").size(FOOTER_TEXT))
            .clicked()
        {
            crate::utils::open_url(TELEGRAM_GROUP_URL);
        }
    });
}

/// The pencil dialog: type or paste a folder, we resolve it to an install root.
pub fn path_dialog(app: &mut App, ctx: &egui::Context) {
    let Some(mut text) = app.path_dialog.take() else {
        return;
    };
    let mut keep_open = true;
    let mut submit = false;

    egui::Window::new("Путь к Antigravity")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_min_width(420.0);
            widgets::hint(
                ui,
                "Папка установки Antigravity, IDE или CLI. Можно указать вложенную — \
                 корень будет найден сам.",
            );
            ui.add_space(8.0);
            ui.add(
                egui::TextEdit::singleline(&mut text)
                    .desired_width(f32::INFINITY)
                    .hint_text("C:\\Users\\...\\Programs\\Antigravity"),
            );
            if let Some(err) = &app.path_dialog_error {
                ui.add_space(6.0);
                ui.label(egui::RichText::new(err).color(theme::BAD).size(12.5));
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if widgets::primary(ui, "Добавить", !text.trim().is_empty()).clicked() {
                    submit = true;
                }
                if widgets::ghost(ui, "Отмена").clicked() {
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
                app.path_dialog_error =
                    Some("По этому пути установка Antigravity не найдена.".into());
            }
        }
    }

    if keep_open {
        app.path_dialog = Some(text);
    } else {
        app.path_dialog_error = None;
    }
}
