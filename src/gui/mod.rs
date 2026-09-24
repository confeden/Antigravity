//! The desktop GUI.
//!
//! Replaces the numbered console menu. Two screens: a licence gate, then one
//! window of switches. Nothing here blocks — everything that touches the system
//! goes to the `ops` worker and comes back as status snapshots and log lines.

mod icon;
mod license;
mod main_view;
pub(crate) mod renderer;
pub(crate) mod report;
pub(crate) mod status;
mod theme;
mod tray;
mod widgets;

use eframe::egui;
use std::sync::mpsc::{channel, Receiver};

use crate::gate;
use crate::ops::{self, Cmd, Event, Level, Status, Worker};
use crate::settings::Settings;
use crate::update::{self, ReleaseInfo};

#[allow(dead_code)]
pub const TELEGRAM_GROUP_URL: &str = "https://t.me/nova_txt";
/// The room the free keys are pinned in (spec item 9), not the group root.
pub const TELEGRAM_KEYS_URL: &str = "https://t.me/nova_txt/69864";
#[allow(dead_code)]
pub const DONATE_URL: &str = "https://nova-app.eu/donate";

const WIN_W: f32 = 600.0;
const WIN_H: f32 = 840.0;

/// How many log lines are kept. The window can stay open for days; an unbounded
/// Vec of every line a re-patch loop produced is a slow leak.
const LOG_LIMIT: usize = 400;

enum Screen {
    License,
    Main,
}

pub struct App {
    screen: Screen,
    key_input: String,
    key_rejected: bool,
    /// Cleared after the first frame gives the key field focus, so a paste needs
    /// no click and Enter works straight away.
    key_needs_focus: bool,
    /// When the next licence check may run.
    key_next_attempt: Option<std::time::Instant>,
    /// Timestamps of recent checks, newest last. Only the last second matters.
    key_attempts: Vec<std::time::Instant>,
    /// Current cooldown between checks.
    key_cooldown: std::time::Duration,

    /// Current update status from GitHub (Available, Downloading, Done, Error).
    update: Option<update::UpdateMsg>,
    update_rx: Receiver<update::UpdateMsg>,
    update_cmd_tx: std::sync::mpsc::Sender<update::UpdateCmd>,
    latest_release: Option<ReleaseInfo>,

    worker: Worker,
    events: Receiver<Event>,
    status: Option<Status>,

    /// What the gate watcher last found: the client's own region-400s, and the
    /// relay's record of what it did about them.
    gate: gate::View,
    /// When that arrived. The watcher sends an age measured at its own tick and
    /// then stays quiet while nothing changes (waking the UI three times a
    /// minute to redraw the same line is not worth it), so the window ages its
    /// copy itself from here.
    gate_at: std::time::Instant,
    gate_rx: Receiver<gate::Signal>,
    log: Vec<(Level, String)>,
    /// Ctrl+A over the journal. Our own, because egui's label selection is per
    /// galley and the journal is one label per line.
    log_all_selected: bool,
    busy: Option<String>,

    own_proxy_input: String,
    /// The provider list as the window is drawing it right now.
    ///
    /// Kept beside the worker's snapshot so a drag can reorder it on the spot.
    /// Waiting for the round trip — save, re-read, push a new status — makes the
    /// row snap back under the pointer and the drag feel broken, which is
    /// exactly what it looked like.
    providers_local: Vec<crate::ops::ProviderRow>,
    /// True between picking a row up and the worker acknowledging the new order.
    providers_reordering: bool,
    path_dialog: Option<String>,
    path_dialog_error: Option<String>,
    /// The report file the button last wrote, and when — for as long as the
    /// card keeps telling the user where it is. Longer than a toast on purpose:
    /// this is an instruction to go and attach a file, not an acknowledgement.
    report_saved: Option<(std::time::Instant, std::path::PathBuf)>,
    /// Set instead when there was nowhere to write it and the text went to the
    /// clipboard alone.
    report_clipboard_at: Option<std::time::Instant>,
    /// Frames drawn so far, up to the few it takes to call the renderer proven
    /// (`renderer::confirm`).
    frames: u8,
    tray: Option<tray::TrayHandler>,
    should_exit: bool,
    pub log_expanded: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);

        let settings = Settings::load();

        let (up_tx, update_rx) = channel();
        let up_ctx = cc.egui_ctx.clone();
        let auto_download = settings.auto_update;
        let update_cmd_tx = update::spawn_watch(
            up_tx,
            std::sync::Arc::new(move || up_ctx.request_repaint()),
            auto_download,
        );

        // The worker wakes the UI itself: egui sleeps until something asks it to
        // repaint, so an event that only lands in a channel is an event the user
        // never sees.
        let (ev_tx, events) = channel();
        let ctx = cc.egui_ctx.clone();
        let worker = ops::spawn(ev_tx, Box::new(move || ctx.request_repaint()));

        // Its own thread and its own channel rather than a command on the
        // worker's queue: the worker can be minutes deep in a patch run, and
        // "is Antigravity hitting the gate right now" is exactly the question
        // that must still answer while it is.
        let (gate_tx, gate_rx) = channel();
        let gate_ctx = cc.egui_ctx.clone();
        gate::spawn_watch(gate_tx, Box::new(move || gate_ctx.request_repaint()));

        let screen = first_screen();
        // A debug build told to skip the key never passes the licence screen,
        // which is where `Unlocked` is otherwise sent from.
        if matches!(screen, Screen::Main) {
            worker.send(Cmd::Unlocked);
        }
        Self {
            screen,
            key_input: String::new(),
            key_rejected: false,
            key_needs_focus: true,
            key_next_attempt: None,
            key_attempts: Vec::new(),
            key_cooldown: std::time::Duration::from_millis(100),
            update: None,
            update_rx,
            update_cmd_tx,
            latest_release: None,
            worker,
            events,
            status: None,
            gate: gate::View::default(),
            gate_at: std::time::Instant::now(),
            gate_rx,
            log: Vec::new(),
            log_all_selected: false,
            busy: None,
            own_proxy_input: settings.own_proxy.clone(),
            providers_local: Vec::new(),
            providers_reordering: false,
            path_dialog: None,
            path_dialog_error: None,
            report_saved: None,
            report_clipboard_at: None,
            frames: 0,
            tray: tray::create_tray(),
            should_exit: false,
            log_expanded: false,
        }
    }

    fn is_busy(&self) -> bool {
        self.busy.is_some()
    }

    /// The update banner, drawn on both screens with support for automatic download,
    /// progress reporting, error handling and one-click restart.
    fn update_banner(&self, ui: &mut egui::Ui) {
        let Some(msg) = &self.update else { return };
        match msg {
            update::UpdateMsg::Available(rel) => {
                let v = rel.display_version();
                let frame = egui::Frame::new()
                    .fill(theme::CARD)
                    .stroke(egui::Stroke::new(1.0, theme::WARN))
                    .corner_radius(egui::CornerRadius::same(theme::RADIUS_SMALL))
                    .inner_margin(egui::Margin::symmetric(10, 8));

                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("⬆ Доступна версия v{}", v))
                                .color(theme::WARN)
                                .size(13.0),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button(egui::RichText::new("В браузере").size(12.0)).clicked() {
                                crate::utils::open_url(update::RELEASES_LATEST_URL);
                            }
                            let rel_clone = rel.clone();
                            let btn = egui::Button::new(
                                egui::RichText::new("Обновить сейчас")
                                    .color(egui::Color32::BLACK)
                                    .size(12.0),
                            )
                            .fill(theme::WARN);
                            if ui.add(btn).clicked() {
                                let _ = self.update_cmd_tx.send(update::UpdateCmd::Download(rel_clone));
                            }
                        });
                    });
                });
                ui.add_space(10.0);
            }
            update::UpdateMsg::Progress {
                version,
                downloaded,
                total,
                percent,
            } => {
                let frame = egui::Frame::new()
                    .fill(theme::CARD)
                    .stroke(egui::Stroke::new(1.0, theme::ACCENT))
                    .corner_radius(egui::CornerRadius::same(theme::RADIUS_SMALL))
                    .inner_margin(egui::Margin::symmetric(10, 8));

                frame.show(ui, |ui| {
                    let mb_down = *downloaded as f32 / (1024.0 * 1024.0);
                    let info = match total {
                        Some(tot) => {
                            let mb_tot = *tot as f32 / (1024.0 * 1024.0);
                            format!(
                                "⬇ Скачивание обновления v{}... {:.0}% ({:.1} / {:.1} МБ)",
                                version, percent, mb_down, mb_tot
                            )
                        }
                        None => format!("⬇ Скачивание обновления v{}... ({:.1} МБ)", version, mb_down),
                    };

                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(info)
                                .color(theme::ACCENT)
                                .size(13.0),
                        );
                        ui.add_space(4.0);
                        let fraction = (percent / 100.0).clamp(0.0, 1.0);
                        ui.add(
                            egui::ProgressBar::new(fraction)
                                .animate(true)
                                .desired_height(4.0),
                        );
                    });
                });
                ui.add_space(10.0);
            }
            update::UpdateMsg::Done { version } => {
                let frame = egui::Frame::new()
                    .fill(theme::CARD)
                    .stroke(egui::Stroke::new(1.5, theme::OK))
                    .corner_radius(egui::CornerRadius::same(theme::RADIUS_SMALL))
                    .inner_margin(egui::Margin::symmetric(10, 8));

                frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("✓ Версия v{} установлена!", version))
                                .color(theme::OK)
                                .size(13.0),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let btn = egui::Button::new(
                                egui::RichText::new("⟳ Перезапустить сейчас")
                                    .color(egui::Color32::BLACK)
                                    .size(12.0),
                            )
                            .fill(theme::OK);

                            if ui.add(btn).clicked() {
                                let _ = update::restart_process();
                            }
                        });
                    });
                });
                ui.add_space(10.0);
            }
            update::UpdateMsg::Error { version, error } => {
                let frame = egui::Frame::new()
                    .fill(theme::CARD)
                    .stroke(egui::Stroke::new(1.0, theme::BAD))
                    .corner_radius(egui::CornerRadius::same(theme::RADIUS_SMALL))
                    .inner_margin(egui::Margin::symmetric(10, 8));

                frame.show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!("⚠ Ошибка обновления v{}:", version))
                                    .color(theme::BAD)
                                    .size(13.0),
                            );
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button(egui::RichText::new("В браузере").size(12.0)).clicked() {
                                    crate::utils::open_url(update::RELEASES_LATEST_URL);
                                }
                                if let Some(rel) = &self.latest_release {
                                    let rel_clone = rel.clone();
                                    if ui.button(egui::RichText::new("Повторить").size(12.0)).clicked() {
                                        let _ = self.update_cmd_tx.send(update::UpdateCmd::Download(rel_clone));
                                    }
                                }
                            });
                        });
                        ui.add_space(2.0);
                        ui.label(
                            egui::RichText::new(error)
                                .color(theme::MUTED)
                                .size(12.0),
                        );
                    });
                });
                ui.add_space(10.0);
            }
        }
    }

    /// Re-launches this exe elevated and closes the current window.
    ///
    /// The privileged half cannot be acquired in place — elevation is per
    /// process on Windows and eframe owns the message loop — so the only honest
    /// button is one that starts again. If the user dismisses the UAC prompt
    /// nothing happens and the window stays as it was.
    fn request_elevation(&self) {
        #[cfg(target_os = "windows")]
        {
            if crate::utils::relaunch_elevated() {
                std::process::exit(0);
            }
        }
    }

    fn drain_events(&mut self) {
        while let Ok(msg) = self.update_rx.try_recv() {
            if let update::UpdateMsg::Available(ref rel) = msg {
                self.latest_release = Some(rel.clone());
            }
            self.update = Some(msg);
        }
        while let Ok(signal) = self.gate_rx.try_recv() {
            match signal {
                gate::Signal::Gate(view) => {
                    self.gate = view;
                    self.gate_at = std::time::Instant::now();
                }
                // The watcher decides *when* it is worth re-measuring; the
                // worker is the only thing that may take the measurement, so the
                // request passes through here rather than going around it.
                gate::Signal::MeasureVpn => self.worker.send(Cmd::RemeasureVpn),
            }
        }
        while let Ok(ev) = self.events.try_recv() {
            match ev {
                Event::Log(level, line) => {
                    if self.log.len() >= LOG_LIMIT {
                        self.log.remove(0);
                    }
                    self.log.push((level, line));
                }
                Event::Status(status) => {
                    // The field is only refilled when the user is not mid-typing,
                    // otherwise a status push landing between keystrokes would
                    // overwrite what they are entering.
                    if self.own_proxy_input.is_empty() && !status.own_proxy_text.is_empty() {
                        self.own_proxy_input = status.own_proxy_text.clone();
                    }
                    // A snapshot that arrives mid-drag must not overwrite the
                    // order under the pointer; the worker's copy is adopted
                    // again as soon as the drag is over.
                    if !self.providers_reordering {
                        self.providers_local = status.providers.clone();
                    }
                    self.status = Some(*status);
                }
                Event::Busy(what) => self.busy = what,
            }
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // By the third pass two frames have been presented, which is where a
        // renderer that was going to fail at the swap chain has failed. egui
        // would otherwise sleep after the first one, so it is asked for more.
        if self.frames < 3 {
            if self.frames == 1 {
                renderer::dev_break_frame();
            }
            self.frames += 1;
            ui.ctx().request_repaint();
        } else if self.frames == 3 {
            self.frames += 1;
            renderer::confirm();
        }
        self.drain_events();

        if let Ok(event) = tray_icon::TrayIconEvent::receiver().try_recv() {
            if let tray_icon::TrayIconEvent::Click {
                button: tray_icon::MouseButton::Left,
                button_state: tray_icon::MouseButtonState::Up,
                ..
            } = event
            {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Focus);
            }
        }
        if let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            if let Some(t) = &self.tray {
                if event.id == t.open_id {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Focus);
                } else if event.id == t.enable_id {
                    self.worker.send(Cmd::EnableAll);
                } else if event.id == t.flush_id {
                    crate::dns::flush_client_cache();
                    #[cfg(not(target_os = "windows"))]
                    crate::dns::refresh_pinned_hosts();
                } else if event.id == t.quit_id {
                    self.should_exit = true;
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        if ui.input(|i| i.viewport().close_requested()) {
            if !self.should_exit {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(false));
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
        }

        // The root `Ui` eframe hands over carries no margin and no background of
        // its own; `central_panel` is what puts the window colour behind it.
        //
        // `set_min_size` is not cosmetic padding: a frame sized to its contents
        // paints only as far down as the contents reach, and the rest of the
        // window shows eframe's clear colour instead — a visible seam across the
        // window wherever the screen is shorter than it is.
        const MARGIN: f32 = 18.0;
        // The footer is a bottom panel *inside* this frame, so whatever the frame
        // keeps below itself becomes dead space under the signature — 18 px of it,
        // which was most of the gap between that line and the window edge. The
        // footer pays for its own breathing room (`Panel::bottom`'s margin), so
        // the frame needs almost nothing here.
        const BOTTOM: f32 = 4.0;
        let avail = ui.available_size();
        // Narrow on the right so the scroll bar sits out in the border strip
        // rather than in a gutter of its own; the content keeps its full margin
        // because the scrolling area adds it back on the inside.
        let frame = egui::Frame::central_panel(&ui.style().clone()).inner_margin(egui::Margin {
            left: MARGIN as i8,
            right: 4,
            top: MARGIN as i8,
            bottom: BOTTOM as i8,
        });
        frame.show(ui, |ui| {
            // Height only, and with the margins taken off. Forcing the *width*
            // to the full window pushes the frame's own padding outside it, and
            // everything anchored to the right edge — every switch, every pencil
            // — ends up clipped by exactly that much.
            ui.set_min_height(avail.y - MARGIN - BOTTOM);
            match self.screen {
                Screen::License => license::view(self, ui),
                Screen::Main => main_view::view(self, ui),
            }
        });

        if matches!(self.screen, Screen::Main) {
            let ctx = ui.ctx().clone();
            main_view::path_dialog(self, &ctx);
        }
    }
}

/// Opens the window. Returns only when the user closes it.
///
/// Renderers are tried down `renderer::CHAIN` — on Windows DirectX 12, then
/// DirectX 12 on the software rasteriser, then OpenGL — starting from whatever
/// the last start on this machine learned (`renderer::first`). An error moves
/// to the next one in this process; a panic or a crash inside a driver moves to
/// it on the next start (see `renderer`). Falling back costs nothing at runtime
/// and is the difference between "it starts on other PCs" and a support thread.
pub fn run() -> Result<(), String> {
    fn options(kind: renderer::Kind) -> eframe::NativeOptions {
        eframe::NativeOptions {
            viewport: {
                let mut vp = egui::ViewportBuilder::default()
                    .with_inner_size([WIN_W, WIN_H])
                    .with_min_inner_size([520.0, 620.0])
                    .with_title(title());
                // The exe resource covers Explorer and the taskbar; this is what
                // puts the same picture in the title bar and Alt-Tab.
                if let Some(ico) = icon::window_icon() {
                    vp = vp.with_icon(ico);
                }
                vp
            },
            renderer: kind.renderer(),
            wgpu_options: kind.wgpu_options(),
            ..Default::default()
        }
    }

    renderer::install();
    let mut failures: Vec<String> = Vec::new();
    let mut kind = Some(renderer::first());
    while let Some(k) = kind {
        renderer::attempting(k);
        match eframe::run_native(
            &title(),
            options(k),
            Box::new(|cc| Ok(Box::new(App::new(cc)))),
        ) {
            Ok(()) => return Ok(()),
            // No display to open a window on at all: no X server or Wayland
            // compositor, or one this user may not use (`sudo` — "Authorization
            // required"). Not a renderer's failure, so the next one would fail
            // the same way, and winit would refuse it anyway: an event loop
            // cannot be created twice in one process ("EventLoop can't be
            // recreated", which is all the second attempt used to report).
            Err(e @ eframe::Error::WinitEventLoop(_)) => {
                renderer::forget();
                return Err(format!(
                    "нет доступа к графическому дисплею: {}",
                    without_source_location(&e.to_string())
                ));
            }
            Err(e) => failures.push(format!("{}: {e}", k.label())),
        }
        kind = k.next();
    }
    // Nothing opened, and every renderer said why rather than crashing: that
    // says more about this start (a session with no desktop) than about the
    // machine, so the next start gets the whole chain again.
    renderer::forget();
    Err(format!("не удалось открыть окно ({})", failures.join("; ")))
}

/// winit's `os error at <file>.rs:<line>: <what>` is for its own developers;
/// the user gets `<what>`.
fn without_source_location(msg: &str) -> &str {
    msg.find(".rs:")
        .and_then(|i| msg[i..].find(": ").map(|j| &msg[i + j + 2..]))
        .unwrap_or(msg)
}

fn first_screen() -> Screen {
    Screen::Main
}

fn title() -> String {
    format!("Antigravity Unlocker 2 v{}", update::current_version())
}

#[cfg(test)]
mod tests {
    use super::without_source_location;

    #[test]
    fn a_winit_error_loses_the_build_machine_path_and_keeps_what_happened() {
        assert_eq!(
            without_source_location(
                "os error at /cargo/registry/src/index.crates.io-1949cf8c6b5b557f/winit-0.30.13/src/platform_impl/linux/mod.rs:788: Failed to open connection to X server"
            ),
            "Failed to open connection to X server"
        );
        assert_eq!(without_source_location("no display"), "no display");
    }
}
