//! The one screen the tool has once the key is in.
//!
//! Two cards, one per thing the user came for: lift the account block, and get
//! past the region 400. Everything inside them is a switch — there are no
//! "disable X" entries any more, because that put the same state in two places
//! and let the two disagree.

use eframe::egui;

use super::{theme, widgets, App, DONATE_URL, TELEGRAM_GROUP_URL};
use crate::ops::{Cap, Cmd, Level, State};
use crate::utils::mask_path;

pub fn view(app: &mut App, ui: &mut egui::Ui) {
    header(app, ui);

    // The footer is placed against the *window's* bottom edge by rect, not by
    // laying it out after the scroll area. Flowed, it lands wherever the scroll
    // area stops claiming space — and with `auto_shrink` off that is past the
    // bottom of the window, so the group and donation links were laid out,
    // measured, and never on screen.
    // `available_rect_before_wrap`, not `max_rect`: the header has already been
    // drawn into the top of this ui, and `max_rect` still includes that strip —
    // the body would be positioned over the title and paint it out.
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
                    client_patch_card(app, ui);
                    ui.add_space(12.0);
                    bypass_card(app, ui);
                    ui.add_space(12.0);
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

    // The admin banner is not a nag: without elevation the DNS cmdlets do not
    // fail, they silently do nothing, so a switch flipped here would look on and
    // be off. Say so once, at the top, with the one button that fixes it.
    let admin = app.status.as_ref().map(|s| s.admin).unwrap_or(true);
    if !admin && cfg!(target_os = "windows") {
        widgets::card(ui, |ui| {
            ui.label(egui::RichText::new("Запущено без прав администратора.").color(theme::WARN));
            widgets::hint(
                ui,
                "Обход ошибки 400 без них установить нельзя — правила DNS и служба \
                 требуют повышения. Патч клиента работает и так.",
            );
            ui.add_space(8.0);
            let busy = app.is_busy();
            let btn = ui.add_enabled_ui(!busy, |ui| {
                widgets::ghost(ui, "Перезапустить от имени администратора")
            });
            if btn.inner.clicked() {
                // Restarting mid-action would abandon a half-applied patch or a
                // half-written rule set; the worker is a queue, not a transaction.
                app.request_elevation();
            }
            if busy {
                widgets::hint(ui, "Дождитесь окончания текущей операции.");
            }
        });
        ui.add_space(10.0);
    }

    if app
        .status
        .as_ref()
        .map(|s| s.relay_outdated)
        .unwrap_or(false)
    {
        ui.label(
            egui::RichText::new(
                "Служба DNS устарела — выключите и включите «Обход через DNS», чтобы обновить.",
            )
            .color(theme::WARN)
            .size(12.5),
        );
        ui.add_space(8.0);
    }
}

// ---------------------------------------------------------------------------

fn client_patch_card(app: &mut App, ui: &mut egui::Ui) {
    widgets::card(ui, |ui| {
        cap_row(
            app,
            ui,
            Cap::ClientPatch,
            "Разблокировать вход в аккаунт",
            "Снимает ограничение на авторизацию Google-аккаунта, \
             у которого регион страны из санкционных.",
        );

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

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);
        cap_row(
            app,
            ui,
            Cap::Watchdog,
            "Автопатч после обновления Antigravity",
            "Antigravity обновляет себя сам и стирает патч. Обновлению это не мешает: \
             патч накладывается на уже доработанный файл, а если приложение успели \
             запустить — оно закрывается, чтобы стартовать уже пропатченным.",
        );
    });
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

fn bypass_card(app: &mut App, ui: &mut egui::Ui) {
    widgets::card(ui, |ui| {
        // The master switch is derived, never stored: it is on when any part of
        // the bypass is. Storing it as well is how a master and its parts end up
        // disagreeing about what is installed.
        let any_on = app
            .status
            .as_ref()
            .map(|s| s.dns.is_on() || s.local_proxy.is_on() || s.builtin_exits.is_on())
            .unwrap_or(false);
        let mut master = any_on;

        let busy = app.is_busy();
        let flipped = widgets::switch_row(ui, &mut master, !busy, |ui| {
            ui.label(egui::RichText::new("Обход ошибки 400").size(15.0).strong());
            widgets::hint(
                ui,
                "«User location is not supported» — подключение к серверам Google \
                 из санкционных территорий.",
            );
        });
        if flipped {
            // Order matters and it is not the same in both directions.
            // ON: the relay has to be answering before the proxy variable may
            // name it (I53) — the worker runs these in order, so DNS finishes
            // first. OFF: the variable comes off *before* the listener it names
            // goes away, or a sign-in that lands in between dials a dead port
            // (G31).
            let order = if master {
                [Cap::Dns, Cap::LocalProxy, Cap::BuiltinExits]
            } else {
                [Cap::LocalProxy, Cap::BuiltinExits, Cap::Dns]
            };
            for cap in order {
                app.worker.send(Cmd::Set(cap, master));
            }
        }

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);

        vpn_indicator(app, ui);

        cap_row(
            app,
            ui,
            Cap::Dns,
            "Обход через DNS",
            "Держит два адреса Google разрешающимися через сервисы разблокировки.",
        );
        providers_list(app, ui);

        ui.add_space(10.0);
        cap_row(
            app,
            ui,
            Cap::VpnDetect,
            "Определять VPN",
            "Если Antigravity ходит через ваш VPN, правила DNS не ставятся — они бы \
             перебили резолвер туннеля, а подменённый адрес всё равно достигается \
             через него. Выключите, если обход нужен поверх VPN.",
        );

        ui.add_space(10.0);
        cap_row(
            app,
            ui,
            Cap::VerifyTls,
            "Сверять TLS",
            "Адрес, который вернул сервис разблокировки, принимается только если он предъявил настоящий сертификат Google на нужное имя. Это то, что отличает рабочий обход от чужого сервера, который читал бы ваш трафик. Выключать без причины не стоит.",
        );

        ui.add_space(10.0);
        cap_row(
            app,
            ui,
            Cap::LocalProxy,
            "Локальный прокси",
            "Antigravity подключается не напрямую, а через маленький посредник внутри \
             вашего компьютера. Он выбирает самый быстрый путь до серверов Google и \
             переключается сам, если путь перестал работать. Содержимое соединения не \
             расшифровывается — посредник только передаёт байты.",
        );

        ui.add_space(10.0);
        cap_row(
            app,
            ui,
            Cap::BuiltinExits,
            "Встроенные выходы",
            // Deliberately says what they are and never which they are: a free
            // service that gets named publicly stops being free (I46).
            "Запасной путь до серверов Google — через страну без ограничений. \
             Включается сам и только если оказался быстрее прямого.",
        );

        ui.add_space(10.0);
        cap_row(
            app,
            ui,
            Cap::OwnProxy,
            "Свой HTTP-прокси",
            "Ваш собственный прокси в разрешённом регионе. Проверяется перед включением. \
             Учтите: Google может не принять прокси даже из страны, которая не под \
             санкциями — адреса дата-центров он различает отдельно.",
        );
        own_proxy_field(app, ui);
    });
}

/// Says what the VPN measurement found, and only when it is worth saying.
///
/// A tunnel that Antigravity does not use is not the user's problem and gets a
/// quiet grey line; a tunnel that carries the client is the reason the bypass is
/// not applied, and that has to be visible without opening the log.
fn vpn_indicator(app: &App, ui: &mut egui::Ui) {
    let Some(status) = &app.status else { return };
    let Some(seen) = status.vpn else { return };
    let detect_on = status.vpn_detect.is_on();

    let (color, text) = match (seen, detect_on) {
        (crate::ops::VpnSeen::None, _) => return,
        (crate::ops::VpnSeen::NotCarryingClient, _) => (
            theme::MUTED,
            "VPN активен, но Antigravity идёт мимо него — обход применяется.".to_string(),
        ),
        (crate::ops::VpnSeen::CarryingClient, true) => (
            theme::WARN,
            "Antigravity идёт через VPN — обход не применяется: правила DNS перебили бы \
             резолвер туннеля, а нужный адрес достигается через него и так."
                .to_string(),
        ),
        (crate::ops::VpnSeen::CarryingClient, false) => (
            theme::WARN,
            "Antigravity идёт через VPN, но определение VPN выключено — обход \
             применяется поверх туннеля."
                .to_string(),
        ),
    };

    ui.horizontal_wrapped(|ui| {
        widgets::dot(ui, color);
        ui.label(egui::RichText::new(text).size(12.5).color(color));
    });
    ui.add_space(8.0);
}

/// How a provider's name is written in the list.
///
/// The pool stores them the way they are typed as hostnames — all lower case —
/// which reads as sloppy in a list of proper names. An acronym stays an acronym
/// (`dns-ai.ru` → `DNS-AI.RU`); everything else just gets its first letter.
/// Presentation only: the stored name is what every switch, the deny-list and
/// the saved order are keyed by, and it never changes.
fn display_name(name: &str) -> String {
    let lead: String = name.chars().take_while(|c| c.is_alphabetic()).collect();
    if lead.eq_ignore_ascii_case("dns") {
        return name.to_uppercase();
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::display_name;

    #[test]
    fn an_acronym_stays_an_acronym_and_everything_else_gets_one_capital() {
        assert_eq!(display_name("dns-ai.ru"), "DNS-AI.RU");
        assert_eq!(display_name("xbox-dns.ru"), "Xbox-dns.ru");
        assert_eq!(display_name("comss.one"), "Comss.one");
        assert_eq!(display_name("geohide.ru"), "Geohide.ru");
        // Must not panic on a name the pool could grow later.
        assert_eq!(display_name(""), "");
        assert_eq!(display_name("1.1.1.1"), "1.1.1.1");
    }
}

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
                    let text = egui::RichText::new(display_name(&p.name)).size(13.0);
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
        cap_row(
            app,
            ui,
            Cap::DnsRotation,
            "Ротация между серверами",
            "Включено: запрос идёт ко всем включённым серверам, ответ сверяется \
             с эталонным резолвером. Выключено: используется только первый \
             включённый в списке, запасных не будет.",
        );
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
            .hint_text("host:port или user:pass@host:port")
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
fn cap_row(app: &mut App, ui: &mut egui::Ui, cap: Cap, title: &str, hint: &str) {
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
        .default_open(true)
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

    // Built right-to-left, so it reads left-to-right on screen while staying
    // pinned to the right edge.
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        // The outer frame keeps only 4 px on the right, for the scroll bar. The
        // footer is not inside the scrolling area, so it pays that back itself
        // or its last link is cut off by the window edge.
        ui.add_space(12.0);
        if ui
            .link(egui::RichText::new("t.me/nova_txt").size(FOOTER_TEXT))
            .clicked()
        {
            crate::utils::open_url(TELEGRAM_GROUP_URL);
        }
        ui.label(
            egui::RichText::new("Группа в Telegram:")
                .size(FOOTER_TEXT)
                .color(theme::MUTED),
        );
        ui.label(
            egui::RichText::new("|")
                .size(FOOTER_TEXT)
                .color(theme::LINE),
        );
        if ui
            .link(egui::RichText::new("nova-app.eu/donate").size(FOOTER_TEXT))
            .clicked()
        {
            crate::utils::open_url(DONATE_URL);
        }
        ui.label(
            egui::RichText::new("Отблагодарить копеечкой:")
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
