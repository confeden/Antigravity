//! The desktop GUI.
//!
//! Replaces the numbered console menu. Two screens: a licence gate, then one
//! window of switches. Nothing here blocks — everything that touches the system
//! goes to the `ops` worker and comes back as status snapshots and log lines.

mod icon;
mod license;
mod main_view;
mod theme;
mod widgets;

use eframe::egui;
use std::sync::mpsc::{channel, Receiver};

use crate::ops::{self, Event, Level, Status, Worker};
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
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);

        let (up_tx, update_rx) = channel();
        let up_ctx = cc.egui_ctx.clone();
        update::spawn_watch(up_tx, Box::new(move || up_ctx.request_repaint()));

        // The worker wakes the UI itself: egui sleeps until something asks it to
        // repaint, so an event that only lands in a channel is an event the user
        // never sees.
        let (ev_tx, events) = channel();
        let ctx = cc.egui_ctx.clone();
        let worker = ops::spawn(ev_tx, Box::new(move || ctx.request_repaint()));

        // Read once, only to pre-fill the two fields. The worker owns the file
        // from here on — two writers each saving the whole thing meant whichever
        // saved last silently reverted the other.
        let settings = Settings::load();
        Self {
            screen: Screen::License,
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
            log: Vec::new(),
            log_all_selected: false,
            busy: None,
            own_proxy_input: settings.own_proxy.clone(),
            providers_local: Vec::new(),
            providers_reordering: false,
            path_dialog: None,
            path_dialog_error: None,
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
        {
            if crate::utils::relaunch_elevated() {
                std::process::exit(0);
            }
        }
    }

    fn drain_events(&mut self) {
        while let Ok(rel) = self.update_rx.try_recv() {
            self.update = Some(rel);
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
        self.drain_events();

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
/// Two renderers are compiled in and tried in order. wgpu goes first because on
/// Windows it lands on DirectX 12, which ships with the OS and needs no vendor
/// OpenGL driver — the case that breaks a fresh install still on the Basic
/// Display Adapter. wgpu also probes Vulkan on its own, so the glow retry is
/// only for a machine old enough that plain WGL is all it has. Falling back
/// costs nothing at runtime and is the difference between "it starts on other
/// PCs" and a support thread.
pub fn run() -> Result<(), String> {
    fn options(renderer: eframe::Renderer) -> eframe::NativeOptions {
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
            renderer,
            ..Default::default()
        }
    }

    let primary = eframe::run_native(
        &title(),
        options(eframe::Renderer::Wgpu),
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    );

    match primary {
        Ok(()) => Ok(()),
        Err(first) => eframe::run_native(
            &title(),
            options(eframe::Renderer::Glow),
            Box::new(|cc| Ok(Box::new(App::new(cc)))),
        )
        .map_err(|second| format!("не удалось открыть окно (DirectX: {first}; OpenGL: {second})")),
    }
}

fn title() -> String {
    format!("Antigravity Unlocker 2 v{}", update::current_version())
}
