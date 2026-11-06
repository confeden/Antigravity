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
mod widgets;

use eframe::egui;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

use crate::gate;
use crate::ops::{self, Cmd, Event, Level, Status, Worker};
use crate::settings::Settings;
use crate::update::{self, ReleaseInfo};

pub const TELEGRAM_GROUP_URL: &str = "https://t.me/nova_txt";
/// The room the free keys are pinned in (spec item 9), not the group root.
pub const TELEGRAM_KEYS_URL: &str = "https://t.me/nova_txt/69864";
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
    shutdown_request_frame: Option<u64>,
    shutdown_ready: bool,
    shutdown_close_sent: bool,
    shutdown_error: Option<String>,
    lifetime: Arc<ops::GuiLifetime>,
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

    /// Raised once a newer release is on GitHub and never lowered — the banner
    /// has to survive the move from the licence screen to the main one.
    update: Option<ReleaseInfo>,
    update_rx: Receiver<ReleaseInfo>,

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
    custom_dns_input: String,
    /// The group code field; sent once it holds something shaped like a code.
    group_key_input: String,
    /// The group code last handed to the worker, so the field (which shows the
    /// saved code) sends only a code that is actually new.
    group_key_sent: String,
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
}

impl App {
    #[cfg(test)]
    fn for_layout_test(status: Status) -> (Self, std::sync::mpsc::Receiver<Cmd>) {
        let lifetime = Arc::new(ops::GuiLifetime::default());
        let (worker, commands) = ops::layout_test_worker(lifetime.clone());
        let (_, update_rx) = channel();
        let (_, events) = channel();
        let (_, gate_rx) = channel();
        (Self {
            screen: Screen::Main,
            shutdown_request_frame: None, shutdown_ready: false, shutdown_close_sent: false,
            shutdown_error: None, lifetime,
            key_input: String::new(), key_rejected: false, key_needs_focus: false,
            key_next_attempt: None, key_attempts: Vec::new(),
            key_cooldown: std::time::Duration::from_millis(100),
            update: None, update_rx, worker, events, status: Some(status),
            gate: gate::View::default(), gate_at: std::time::Instant::now(), gate_rx,
            log: Vec::new(), log_all_selected: false, busy: None,
            own_proxy_input: String::new(), custom_dns_input: String::new(),
            group_key_input: String::new(), group_key_sent: String::new(),
            providers_local: Vec::new(), providers_reordering: false,
            path_dialog: None, path_dialog_error: None, report_saved: None,
            report_clipboard_at: None, frames: 0,
        }, commands)
    }

    fn new(cc: &eframe::CreationContext<'_>, lifetime: Arc<ops::GuiLifetime>) -> Self {
        theme::apply(&cc.egui_ctx);

        let (up_tx, update_rx) = channel();
        let up_ctx = cc.egui_ctx.clone();
        update::spawn_watch(up_tx, Box::new(move || up_ctx.request_repaint()));

        // The worker wakes the UI itself: egui sleeps until something asks it to
        // repaint, so an event that only lands in a channel is an event the user
        // never sees.
        let (ev_tx, events) = channel();
        let ctx = cc.egui_ctx.clone();
        let worker = ops::spawn(ev_tx, Box::new(move || ctx.request_repaint()), lifetime.clone());

        // Its own thread and its own channel rather than a command on the
        // worker's queue: the worker can be minutes deep in a patch run, and
        // "is Antigravity hitting the gate right now" is exactly the question
        // that must still answer while it is.
        let (gate_tx, gate_rx) = channel();
        let gate_ctx = cc.egui_ctx.clone();
        gate::spawn_watch(gate_tx, Box::new(move || gate_ctx.request_repaint()));

        // Read once, only to pre-fill the two fields. The worker owns the file
        // from here on — two writers each saving the whole thing meant whichever
        // saved last silently reverted the other.
        let settings = Settings::load();
        let screen = first_screen(&settings);
        // A debug build told to skip the key never passes the licence screen,
        // which is where `Unlocked` is otherwise sent from.
        if matches!(screen, Screen::Main) {
            worker.send(Cmd::Unlocked);
        }
        Self {
            screen,
            shutdown_request_frame: None,
            shutdown_ready: false,
            shutdown_close_sent: false,
            shutdown_error: None,
            lifetime,
            key_input: String::new(),
            key_rejected: false,
            key_needs_focus: true,
            key_next_attempt: None,
            key_attempts: Vec::new(),
            key_cooldown: std::time::Duration::from_millis(100),
            update: None,
            update_rx,
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
            custom_dns_input: settings.custom_dns.clone(),
            // The saved code stays in the field across restarts and updates,
            // where it can be seen and replaced.
            group_key_input: settings.group_key.clone(),
            group_key_sent: settings.group_key.clone(),
            providers_local: Vec::new(),
            providers_reordering: false,
            path_dialog: None,
            path_dialog_error: None,
            report_saved: None,
            report_clipboard_at: None,
            frames: 0,
        }
    }

    fn is_busy(&self) -> bool {
        self.busy.is_some()
    }

    /// The "новая версия" button, drawn on both screens (spec item 10: it must
    /// not disappear after the key is accepted).
    fn update_banner(&self, ui: &mut egui::Ui) {
        let Some(rel) = &self.update else { return };
        let label = format!("⬆  Доступна новая версия — {}", rel.display_version());
        let btn = egui::Button::new(egui::RichText::new(label).color(egui::Color32::BLACK))
            .fill(theme::WARN)
            .corner_radius(egui::CornerRadius::same(theme::RADIUS_SMALL))
            .min_size(egui::vec2(ui.available_width(), 32.0));
        if ui.add(btn).clicked() {
            // Always /latest, never the tag URL from the API response: the point
            // is to land the user on whatever is newest when they click, not on
            // the release this process happened to see hours ago.
            crate::utils::open_url(update::RELEASES_LATEST_URL);
        }
        ui.add_space(10.0);
    }

    /// Re-launches this exe elevated and closes the current window.
    ///
    /// The privileged half cannot be acquired in place — elevation is per
    /// process on Windows and eframe owns the message loop — so the only honest
    /// button is one that starts again. If the user dismisses the UAC prompt
    /// nothing happens and the window stays as it was.
    fn request_elevation(&self) {
        #[cfg(target_os = "windows")]
        self.worker.send(Cmd::RequestElevation);
    }

    fn drain_events(&mut self) {
        while let Ok(rel) = self.update_rx.try_recv() {
            self.update = Some(rel);
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
                    if self.custom_dns_input.is_empty() && !status.custom_dns_text.is_empty() {
                        self.custom_dns_input = status.custom_dns_text.clone();
                    }
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
                Event::ShutdownReady => self.shutdown_ready = true,
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
        if ui.ctx().input(|i| i.viewport().close_requested()) && !self.shutdown_close_sent {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
            let frame = ui.ctx().cumulative_frame_nr();
            if self.shutdown_request_frame != Some(frame) {
                self.shutdown_request_frame = Some(frame);
                self.lifetime.request_shutdown();
            }
        }
        if self.shutdown_ready && !self.shutdown_close_sent {
            match self.lifetime.poll_close() {
                Ok(true) => {
                    self.shutdown_close_sent = true;
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                Ok(false) => ui.ctx().request_repaint_after(std::time::Duration::from_millis(100)),
                Err(error) => {
                    if self.shutdown_error.as_ref() != Some(&error) {
                        self.log.push((Level::Err, format!("Не удалось завершить работу: {error}")));
                        self.busy = Some(format!("Не удалось завершить работу: {error}"));
                        self.shutdown_error = Some(error);
                    }
                    ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
                }
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
pub fn run(lifetime: Arc<ops::GuiLifetime>) -> Result<(), String> {
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
        let app_lifetime = lifetime.clone();
        match eframe::run_native(
            &title(),
            options(k),
            Box::new(move |cc| Ok(Box::new(App::new(cc, app_lifetime)))),
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
            Err(e) => {
                failures.push(format!("{}: {e}", k.label()));
                if !lifetime.can_retry_renderer() {
                    return Err(format!("окно завершилось после начала работы; повторный запуск интерфейса не выполняется ({})", failures.join("; ")));
                }
            },
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

fn first_screen(settings: &Settings) -> Screen {
    #[cfg(debug_assertions)]
    if std::env::var_os("AG_UNLOCKER_DEV_SKIP_KEY").is_some() {
        return Screen::Main;
    }
    // A key accepted before and still good for this version: no screen.
    if crate::auth::verify_key(&settings.license_key) {
        return Screen::Main;
    }
    Screen::License
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
