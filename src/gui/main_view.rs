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
use super::{theme, widgets, App};
use crate::ops::{Cap, Cmd, Level, State};
use crate::utils::mask_path;

pub fn view(app: &mut App, ui: &mut egui::Ui) {
    header(app, ui);

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
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // Put back what the outer frame gave up to the scroll bar,
                    // on the inside of it, so the cards keep their margin and the
                    // bar still lands against the window edge.
                    ui.set_max_width(ui.available_width() - 10.0);
                    status_card(app, ui);
                    ui.add_space(10.0);
                    hud_card(app, ui);
                    ui.add_space(10.0);
                    targets_card(app, ui);
                    ui.add_space(10.0);
                    antigravity_card(app, ui);
                    ui.add_space(10.0);
                    advanced_card(app, ui);
                    ui.add_space(6.0);
                    log_card(app, ui);
                    ui.add_space(12.0);
                });
        });
}

// ---------------------------------------------------------------------------

fn header(app: &mut App, ui: &mut egui::Ui) {
    app.update_banner(ui);

    // No product name and no version here: both are in the title bar already,
    // and repeating them costs a line of a window this narrow.
    if let Some(what) = &app.busy {
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new().size(14.0));
            ui.label(
                egui::RichText::new(what.clone())
                    .size(12.0)
                    .color(theme::MUTED),
            );
        });
        ui.add_space(8.0);
    }
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
    if f.refusal.is_some() || f.answer.is_some() {
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
                if ui
                    .add(egui::Button::new(egui::RichText::new("Свернуть в трей").size(12.5)))
                    .on_hover_text("Скрыть окно в системный трей (обход продолжит работать в фоне)")
                    .clicked()
                {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(false));
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Minimized(true));
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

fn hud_card(app: &mut App, ui: &mut egui::Ui) {
    let f = facts(app);
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Телеметрия сети")
                    .size(14.5)
                    .strong()
                    .color(theme::TEXT),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(egui::RichText::new("🔄 Сбросить DNS-кэш").size(12.0))
                    .on_hover_text("Очистить кэш DNS и обновить записи в /etc/hosts")
                    .clicked()
                {
                    crate::dns::flush_client_cache();
                    #[cfg(not(target_os = "windows"))]
                    crate::dns::refresh_pinned_hosts();
                }
            });
        });
        ui.add_space(8.0);

        ui.columns(3, |cols| {
            cols[0].vertical(|ui| {
                ui.label(egui::RichText::new("Маршрут").size(11.5).color(theme::MUTED));
                let route_label = f
                    .as_ref()
                    .and_then(|f| f.route.as_deref())
                    .unwrap_or("Прямой (Direct)");
                ui.label(egui::RichText::new(route_label).size(12.5).strong().color(theme::TEXT));
            });

            cols[1].vertical(|ui| {
                ui.label(egui::RichText::new("DNS-слой").size(11.5).color(theme::MUTED));
                let (dns_text, dns_col) = if f.as_ref().is_some_and(|f| f.rules) {
                    #[cfg(not(target_os = "windows"))]
                    let txt = "Активен (/etc/hosts)";
                    #[cfg(target_os = "windows")]
                    let txt = "Активен (NRPT)";
                    (txt, theme::OK)
                } else {
                    ("Не применен", theme::WARN)
                };
                ui.label(egui::RichText::new(dns_text).size(12.5).strong().color(dns_col));
            });

            cols[2].vertical(|ui| {
                ui.label(egui::RichText::new("Служба / Прокси").size(11.5).color(theme::MUTED));
                let (svc_text, svc_col) = if f.as_ref().is_some_and(|f| f.relay_running) {
                    ("Активна (:53129)", theme::OK)
                } else {
                    ("Остановлена", theme::MUTED)
                };
                ui.label(egui::RichText::new(svc_text).size(12.5).strong().color(svc_col));
            });
        });
    });
}

fn targets_card(app: &mut App, ui: &mut egui::Ui) {
    let f = facts(app);
    let active = f.as_ref().is_some_and(|f| f.rules || f.bypass_on);
    widgets::card(ui, |ui| {
        ui.label(
            egui::RichText::new("Перехват целевых доменов Google AI")
                .size(14.0)
                .strong()
                .color(theme::TEXT),
        );
        ui.add_space(6.0);

        let targets = [
            ("cloudcode-pa.googleapis.com", "Antigravity IDE / Language Server"),
            ("daily-cloudcode-pa.googleapis.com", "Daily Staging Gate"),
            ("generativelanguage.googleapis.com", "Gemini API"),
            ("aistudio.google.com", "Google AI Studio"),
        ];

        for (host, desc) in targets {
            ui.horizontal(|ui| {
                let dot_color = if active { theme::OK } else { theme::MUTED };
                let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 3.5, dot_color);
                ui.label(egui::RichText::new(host).size(12.0).monospace().color(theme::TEXT));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(desc).size(11.0).color(theme::MUTED));
                });
            });
            ui.add_space(2.0);
        }
    });
}

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
    });
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

            match &row.path {
                Some(path) => {
                    let shown = mask_path(&path.display().to_string());
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(shown)
                                .size(12.0)
                                .color(theme::MUTED)
                                .monospace(),
                        )
                        // One line, cut with an ellipsis rather than wrapped: a
                        // long install path would push the pencil off the row.
                        .truncate(),
                    )
                    .on_hover_text(path.display().to_string());
                }
                None => {
                    ui.label(
                        egui::RichText::new("не найдено — укажите путь")
                            .size(12.0)
                            .color(theme::MUTED),
                    );
                }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if row.manual {
                    if let Some(p) = &row.path {
                        if ui
                            .small_button("✖")
                            .on_hover_text("Убрать указанный путь")
                            .clicked()
                        {
                            forget = Some(p.clone());
                        }
                    }
                }
                if ui
                    .small_button("✏")
                    .on_hover_text("Указать путь вручную")
                    .clicked()
                {
                    edit = Some(
                        row.path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                    );
                }
            });
        });
    }

    if let Some(p) = forget {
        app.worker.send(Cmd::ForgetPath(p));
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

            ui.add_space(10.0);
            cap_row(app, ui, Cap::LocalProxy);

            ui.add_space(10.0);
            cap_row(app, ui, Cap::BuiltinExits);

            ui.add_space(10.0);
            cap_row(app, ui, Cap::VerifyTls);

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
    widgets::card(ui, |ui| {
        log_keys(app, ui);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Журнал событий (Live Telemetry)")
                    .size(14.0)
                    .strong()
                    .color(theme::TEXT),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(egui::RichText::new("Скопировать").size(11.5))
                    .on_hover_text("Скопировать лог в буфер обмена")
                    .clicked()
                {
                    let text = app
                        .log
                        .iter()
                        .map(|(l, s)| log_line(*l, s))
                        .collect::<Vec<_>>()
                        .join("\n");
                    ui.ctx().copy_text(text);
                }
            });
        });
        ui.add_space(6.0);

        egui::Frame::new()
            .fill(theme::BG)
            .corner_radius(egui::CornerRadius::same(theme::RADIUS_SMALL))
            .inner_margin(egui::Margin::same(8))
            .stroke(egui::Stroke::new(1.0, theme::LINE))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                let lines_to_show = if app.log_expanded {
                    app.log.as_slice()
                } else {
                    let start = app.log.len().saturating_sub(4);
                    &app.log[start..]
                };

                if lines_to_show.is_empty() {
                    ui.label(
                        egui::RichText::new("Служба ожидает подключений...")
                            .size(11.5)
                            .monospace()
                            .color(theme::MUTED),
                    );
                } else {
                    for (level, line) in lines_to_show {
                        let color = match level {
                            Level::Ok => theme::OK,
                            Level::Warn => theme::WARN,
                            Level::Err => theme::BAD,
                            Level::Step => theme::TEXT,
                            Level::Info => theme::MUTED,
                        };
                        ui.label(
                            egui::RichText::new(log_line(*level, line))
                                .size(11.5)
                                .monospace()
                                .color(color),
                        );
                    }
                }
            });

        if app.log.len() > 4 {
            ui.add_space(4.0);
            let toggle_label = if app.log_expanded {
                "▲ Свернуть журнал"
            } else {
                "▼ Развернуть полный журнал"
            };
            if ui
                .link(egui::RichText::new(toggle_label).size(11.5).color(theme::ACCENT))
                .clicked()
            {
                app.log_expanded = !app.log_expanded;
            }
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

    // Built right-to-left, so it reads left-to-right on screen while staying
    // pinned to the right edge.
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        // The outer frame keeps only 4 px on the right, for the scroll bar. The
        // footer is not inside the scrolling area, so it pays that back itself
        // or its last link is cut off by the window edge.
        ui.add_space(12.0);
        if ui
            .link(egui::RichText::new("GitHub").size(FOOTER_TEXT))
            .clicked()
        {
            crate::utils::open_url("https://github.com/SatoKazuma1/Antigravity");
        }
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new("|")
                .size(FOOTER_TEXT)
                .color(theme::LINE),
        );
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new("Antigravity Unlocker")
                .size(FOOTER_TEXT)
                .color(theme::MUTED),
        );
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
