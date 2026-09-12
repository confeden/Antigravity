//! The one screen the tool has once the key is in.
//!
//! Two cards, one per thing the user came for: lift the account block, and get
//! past the region 400. Everything inside them is a switch — there are no
//! "disable X" entries any more, because that put the same state in two places
//! and let the two disagree.

use eframe::egui;

use std::time::Duration;

use super::{theme, widgets, App, DONATE_URL, TELEGRAM_GROUP_URL};
use crate::egress::ClientEgress;
use crate::ops::{Cap, Cmd, Level, State, VpnSeen};
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

        gate_strip(app, ui);
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

// ---------------------------------------------------------------------------
// "Is the error being dealt with right now" — what the card is actually for.
// ---------------------------------------------------------------------------

/// How far *before* a refusal the relay's note may be stamped and still be an
/// answer to it: a couple of seconds, for the whole-second quantisation both
/// stamps carry. Deliberately not generous, and the direction matters.
///
/// The note is written when the relay notices, which is up to a warm pass
/// *after* the line — and that direction needs no allowance at all, since any
/// later stamp passes. Slack the other way is nothing but a licence to call an
/// old episode the answer to a new refusal: a relay killed after answering one
/// would have the window saying «перехватил» about the next, for as long as the
/// record stayed fresh, with nothing running to have caught anything (I58).
const EPISODE_SLACK: u64 = 3;

/// How long a refusal may sit unanswered before "обход перестраивается" stops
/// being a description and starts being a guess. Two warm passes and change.
const UNANSWERED_GRACE: Duration = Duration::from_secs(45);

/// No new refusal for this long means it stopped, and the card stops shouting.
///
/// This is the state the owner's first live run ended in and the window had no
/// word for: refusals at 14:58-15:00, the route switched to a built-in exit at
/// 15:00:03, nothing since — and the card still read like an unsolved problem
/// ten minutes later. Longer than the client's own retry burst, which keeps
/// arriving on the pooled connection for about a minute after the route
/// underneath it changed (I35).
const SETTLED: Duration = Duration::from_secs(2 * 60);

/// Whether the region 400 is happening, and whether anything is answering it.
///
/// Two facts from two places, and the split is the whole point (`gate`): the
/// refusal is read from *Antigravity's own log*, so it shows even with every
/// switch here off, and "перехвачена" comes from the relay's record, so it is
/// claimed only when the side that acts wrote down that it acted. A window that
/// inferred the second from a switch being on would tell a user with a dead
/// relay that everything was fine.
fn gate_strip(app: &App, ui: &mut egui::Ui) {
    let Some(status) = &app.status else { return };
    let bypass_on =
        status.dns.is_on() || status.local_proxy.is_on() || status.builtin_exits.is_on();
    let relay = app.gate.relay.as_ref();
    // The watcher measured `ago` at its own tick and then went quiet; the window
    // carries it forward rather than being sent a fresh one every three seconds.
    let seen = app.gate.seen.map(|s| (s.ago + app.gate_at.elapsed(), s.count));

    // Nothing here changes on input, so the repaint has to be asked for:
    // without it «минуту назад» stays «минуту назад» until the user happens to
    // move the mouse over the window.
    if seen.is_some() || relay.is_some_and(|r| r.forced_left().is_some()) {
        ui.ctx().request_repaint_after(Duration::from_secs(1));
    }

    let Some((ago, count)) = seen else {
        gate_quiet(status, relay, bypass_on, ui);
        return;
    };

    // The relay's note answers this refusal when it was written no earlier than
    // the refusal itself, give or take the pass it was noticed on.
    let refusal_at = crate::gate::now_unix().saturating_sub(ago.as_secs());
    // A note about an answer is only worth anything while the thing that wrote
    // it is still running: the local proxy lives in that same process, so a
    // relay that answered a refusal and then died leaves the client with a
    // proxy variable naming a dead port (G31) — and «перехватил, отправьте ещё
    // раз» is the worst sentence to show at that moment. The record outlives
    // the process by up to `STALE_AFTER`, so this cannot be left to staleness.
    let answered = relay
        .filter(|_| status.relay_running)
        .and_then(|r| r.last_400.as_ref())
        .filter(|e| answers(e.at, refusal_at));

    // It happened, and then it stopped. Said quietly and with what is carrying
    // the traffic now, because "is it being fixed" is answered by the silence
    // since, not by the error that started it.
    if ago > SETTLED && bypass_on && status.relay_running {
        gate_settled(relay, answered, ago, ui);
        return;
    }

    let accent = if answered.is_some() {
        theme::OK
    } else if bypass_on && status.relay_running {
        theme::WARN
    } else {
        theme::BAD
    };

    widgets::notice(ui, accent, |ui| {
        ui.horizontal_wrapped(|ui| {
            widgets::dot(ui, accent);
            ui.label(
                egui::RichText::new(headline(count as u64, ago))
                    .size(13.0)
                    .strong()
                    .color(theme::TEXT),
            );
        });
        ui.add_space(4.0);

        let say = |ui: &mut egui::Ui, text: &str| {
            ui.label(egui::RichText::new(text).size(12.5).color(theme::TEXT));
        };
        match (answered, bypass_on, status.relay_running, relay.is_some()) {
            (Some(episode), ..) => {
                say(
                    ui,
                    "Обход её перехватил. Отправьте сообщение в чате ещё раз — \
                     оно пойдёт уже другим путём.",
                );
                if !episode.acted.is_empty() {
                    widgets::hint(ui, &format!("Что сделано: {}.", episode.acted));
                }
            }
            // The relay polls the log once per warm pass, so a refusal it has
            // not answered yet is normal for a few seconds.
            (None, true, true, true) if ago <= UNANSWERED_GRACE => say(
                ui,
                "Обход её видит и перестраивается — это занимает до 15 секунд. \
                 После этого отправьте сообщение ещё раз.",
            ),
            // Past that it is not "about to": the relay takes each log from its
            // end when it starts, so a refusal written before it was running is
            // one it will never see. Saying «сейчас разберётся» for ten minutes
            // would be the window inventing an answer nobody gave.
            (None, true, true, true) => say(
                ui,
                "Обход её не отмечал — скорее всего она была ещё до его запуска. \
                 Отправьте сообщение ещё раз: если ошибка повторится, он её поймает.",
            ),
            // Running and saying nothing. Two different reasons, and guessing
            // at the wrong one hands out advice that cannot work: a service too
            // old to write the record at all needs replacing, one that has
            // simply not finished its first pass needs a few seconds. Only
            // `relay_outdated` can tell them apart, and it is measured.
            (None, true, true, false) if status.relay_outdated => say(
                ui,
                "Служба обхода старее программы и не сообщает, что делает. \
                 Выключите и включите «Обход через DNS», чтобы обновить её.",
            ),
            (None, true, true, false) => say(
                ui,
                "Служба обхода запущена, но пока ничего не сообщила — после \
                 включения ей нужно до минуты. Если строка не изменится, \
                 выключите и включите «Обход через DNS».",
            ),
            (None, true, false, _) => say(
                ui,
                "Служба обхода не запущена — перехватывать ошибку сейчас некому. \
                 Выключите и включите «Обход через DNS».",
            ),
            (None, false, ..) => say(
                ui,
                "Обход ошибки 400 выключен — включите переключатель выше, \
                 и следующая попытка пойдёт уже через него.",
            ),
        }
        if let Some(left) = relay.and_then(|r| r.forced_left()) {
            widgets::hint(
                ui,
                &format!(
                    "Подмена адресов держится принудительно ещё {} мин.",
                    left.as_secs() / 60 + 1
                ),
            );
        }
    });
    ui.add_space(8.0);
}

/// Refusals, and then quiet. The card keeps them on screen until they fall out
/// of `gate::RECENT` — a user who saw the error deserves to know it was seen —
/// but says plainly that nothing has come since, and names the route that is
/// carrying the traffic now.
fn gate_settled(
    relay: Option<&crate::gate::Report>,
    answered: Option<&crate::gate::Episode>,
    ago: Duration,
    ui: &mut egui::Ui,
) {
    // Silence is only evidence when something was *done* about the refusal. The
    // relay reads each log from its end when it starts, so a refusal written
    // before it was running is one it will never answer — and then the quiet
    // means the user stopped asking, not that the route was changed. Saying
    // «этим путём ошибка не повторялась» about the very route it happened on
    // would be the window inventing a verdict out of an absence.
    let repaired = answered.is_some();
    widgets::notice(ui, if repaired { theme::OK } else { theme::MUTED }, |ui| {
        ui.horizontal_wrapped(|ui| {
            widgets::dot(ui, if repaired { theme::OK } else { theme::MUTED });
            ui.label(
                egui::RichText::new(format!(
                    "Ошибка 400 была {}, с тех пор её не было.",
                    ago_text(ago)
                ))
                .size(13.0)
                .strong()
                .color(theme::TEXT),
            );
        });
        ui.add_space(4.0);
        let route = relay.map(|r| r.route.as_str()).filter(|r| !r.is_empty());
        let line = match (repaired, route) {
            (true, Some(route)) => format!(
                "Обход её перехватил, и сейчас трафик идёт «{}» — этим путём ошибка не повторялась.",
                route
            ),
            (true, None) => "Обход её перехватил, и с тех пор отказов не было.".to_string(),
            (false, Some(route)) => format!(
                "Обход её не отмечал — вероятно, она была ещё до его запуска. Сейчас трафик идёт «{}»; проверить можно только новым сообщением в чате.",
                route
            ),
            (false, None) => "Обход её не отмечал — проверить можно только новым сообщением в чате."
                .to_string(),
        };
        ui.label(egui::RichText::new(line).size(12.5).color(theme::TEXT));
        if let Some(episode) = answered {
            if !episode.acted.is_empty() {
                widgets::hint(ui, &format!("Что было сделано: {}.", episode.acted));
            }
        }
    });
    ui.add_space(8.0);
}

/// The ordinary state: nothing has hit the gate for a while. One quiet line,
/// because "it is working" is worth exactly one line — and one loud one when the
/// service that would catch the next refusal is not there.
fn gate_quiet(
    status: &crate::ops::Status,
    relay: Option<&crate::gate::Report>,
    bypass_on: bool,
    ui: &mut egui::Ui,
) {
    if !bypass_on {
        // The master switch above already says it; repeating it here would be a
        // second place for the same state to be wrong in.
        return;
    }
    // Green needs both halves: a service that is running *and* one that is
    // saying what it does. `relay_running` is re-probed at most every five
    // minutes while the client is idle, so on its own it can be five minutes
    // stale — the record going missing is the faster signal of the two.
    let healthy = status.relay_running && relay.is_some();
    ui.horizontal_wrapped(|ui| {
        widgets::dot(ui, if healthy { theme::OK } else { theme::WARN });
        ui.label(
            egui::RichText::new(format!(
                "Ошибка 400 не встречалась последние {} мин.",
                crate::gate::RECENT.as_secs() / 60
            ))
            .size(12.5)
            .color(theme::MUTED),
        );
    });
    if !status.relay_running {
        ui.label(
            egui::RichText::new(
                "Служба обхода не запущена — перехватывать её сейчас некому.",
            )
            .size(12.5)
            .color(theme::WARN),
        );
    } else if let Some(route) = relay.map(|r| r.route.as_str()).filter(|r| !r.is_empty()) {
        widgets::hint(
            ui,
            &format!("Трафик до серверов Google идёт «{}».", route),
        );
    }
    ui.add_space(8.0);
}

/// Whether the relay's note is an answer to *this* refusal — the one claim on
/// this screen that must never be made loosely (I58).
///
/// A note stamped after the refusal is one: the relay reads the log on its warm
/// pass, so it always notices late, and any later stamp qualifies. A note
/// stamped *before* it is not, however recent it looks — that is an answer to
/// something else, and the case it comes from is a relay that answered one
/// refusal and then died.
fn answers(episode_at: u64, refusal_at: u64) -> bool {
    episode_at.saturating_add(EPISODE_SLACK) >= refusal_at
}

/// The first line of the callout. One refusal is an event and reads like one;
/// several are a pattern, and then the count is the news.
fn headline(count: u64, ago: Duration) -> String {
    if count <= 1 {
        return format!("Ошибка 400 — {}.", ago_text(ago));
    }
    format!(
        "Ошибка 400 — {} {} за {} мин, последняя {}.",
        count,
        plural(count, "раз", "раза", "раз"),
        crate::gate::RECENT.as_secs() / 60,
        ago_text(ago)
    )
}

/// «15 секунд назад», «3 минуты назад». Nothing older than `gate::RECENT` ever
/// reaches it, so hours have no form here.
fn ago_text(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 15 {
        return "только что".to_string();
    }
    if secs < 60 {
        return format!(
            "{} {} назад",
            secs,
            plural(secs, "секунду", "секунды", "секунд")
        );
    }
    let mins = secs / 60;
    format!(
        "{} {} назад",
        mins,
        plural(mins, "минуту", "минуты", "минут")
    )
}

/// Russian counts in three forms. Worth its eight lines: «2 минуты назад» and
/// «5 минут назад» are both on this screen within a minute of each other.
fn plural(n: u64, one: &'static str, few: &'static str, many: &'static str) -> &'static str {
    if n % 100 / 10 == 1 {
        return many;
    }
    match n % 10 {
        1 => one,
        2..=4 => few,
        _ => many,
    }
}

/// Which of the two VPN states the window is in, as one pure decision.
///
/// `Some(line)` is a fact worth one grey sentence; `None` means the callout —
/// there is something the user can act on. Split out and tested because this is
/// the table that decides whether the window tells somebody to go and edit their
/// VPN configuration, and getting a cell wrong sends them after a file that
/// would change nothing (G46, N25).
///
/// Our own service is what opens the connection to Google once the proxy route
/// is on, so for `ViaLocalProxy` the question is about *it*, not the client.
fn vpn_quiet_line(seen: VpnSeen, relay: Option<ClientEgress>) -> Option<&'static str> {
    // Our own service first, and regardless of what the client is doing: it is
    // what opens the connection to Google, and a provider that serves Russian
    // addresses only will refuse it from a tunnel. `Mixed` counts as inside —
    // the connections that do leave through the tunnel are refused whatever the
    // others do.
    if matches!(relay, Some(ClientEgress::Tunnel) | Some(ClientEgress::Mixed)) {
        return None;
    }
    match seen {
        // Unreachable: the caller returns on it first. Kept as an arm rather
        // than a catch-all so adding a variant to `VpnSeen` fails to compile
        // here instead of quietly falling into the callout.
        VpnSeen::None => Some(""),
        // Its own sockets in the tunnel, whole or in part: both face the gate
        // from wherever that tunnel exits, and both are the user's to fix.
        VpnSeen::CarryingClient | VpnSeen::PartlyCarryingClient => None,
        VpnSeen::Unmeasured => Some(
            "VPN активен. Antigravity ещё ничего не запрашивал — пойдёт ли его трафик \
             в туннель, будет видно после первого обращения к Google.",
        ),
        VpnSeen::NotCarryingClient => {
            Some("VPN активен, но трафик Antigravity идёт мимо него — обход применяется.")
        }
        // The working combination, and worth saying so: the client hands
        // everything to us and we are outside the tunnel, which is what the
        // unblock services require.
        VpnSeen::ViaLocalProxy if relay == Some(ClientEgress::Physical) => Some(
            "VPN активен. Antigravity ходит через локальный прокси, а служба обхода — \
             мимо туннеля: то, что нужно.",
        ),
        VpnSeen::ViaLocalProxy => Some(
            "VPN активен. Antigravity ходит через локальный прокси; куда пойдёт сама \
             служба обхода, будет видно при первом запросе к Google.",
        ),
    }
}

/// Says where Antigravity's own traffic leaves, and what that means for the 400.
///
/// A tunnel Antigravity does not use is not the user's problem and gets a quiet
/// grey line. A tunnel that carries the client decides the whole question — the
/// gate is lifted by *their* server or not at all — so that one is a callout,
/// with the two ways out of it.
///
/// `Unmeasured` is its own line and deliberately not a reassuring one: a window
/// opened before Antigravity is started used to report it as «идёт мимо VPN»,
/// which is a claim about a measurement nobody had taken.
fn vpn_indicator(app: &App, ui: &mut egui::Ui) {
    let Some(status) = &app.status else { return };
    let Some(seen) = status.vpn else { return };
    // No tunnel, nothing to say. Handled here rather than in the table below so
    // that every arm of the table is a line somebody is meant to read.
    if seen == VpnSeen::None {
        return;
    }
    let detect_on = status.vpn_detect.is_on();

    if let Some(text) = vpn_quiet_line(seen, status.relay_egress) {
        ui.horizontal_wrapped(|ui| {
            widgets::dot(ui, theme::MUTED);
            ui.label(egui::RichText::new(text).size(12.5).color(theme::MUTED));
        });
        ui.add_space(8.0);
        return;
    }

    widgets::notice(ui, theme::WARN, |ui| {
        // Which of the two is in there decides everything below: the headline,
        // the explanation, and which executable the help offers.
        let relay_in = matches!(
            status.relay_egress,
            Some(ClientEgress::Tunnel) | Some(ClientEgress::Mixed)
        );
        let partly = status.relay_egress == Some(ClientEgress::Mixed);
        let via_us = relay_in;
        ui.horizontal_wrapped(|ui| {
            widgets::dot(ui, theme::WARN);
            ui.label(
                egui::RichText::new(match (relay_in, partly) {
                    (true, true) => "Часть соединений службы обхода идёт через ваш VPN.",
                    (true, false) => {
                        "Служба обхода идёт через ваш VPN — из-за этого обход не сработает."
                    }
                    _ if seen == VpnSeen::PartlyCarryingClient => {
                        "Часть трафика Antigravity идёт через ваш VPN."
                    }
                    _ => "Трафик Antigravity идёт через ваш VPN.",
                })
                .size(13.0)
                .strong()
                .color(theme::TEXT),
            );
        });
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(if relay_in {
                "Соединение до серверов Google открывает не Antigravity, а служба обхода, \
                 и сейчас она идёт в туннель. Сервисы разблокировки отвечают только \
                 российским адресам, поэтому из туннеля её надо вывести — а исключение \
                 language_server из VPN ни на что не влияет, он ходит только до \
                 локального прокси."
            } else {
                "Снятие ошибки 400 зависит от вашего сервера: если он в стране без \
                 ограничений — её снимает он, и всё работает. Если ошибка повторяется — \
                 сервер не подходит."
            })
            .size(12.5)
            .color(theme::TEXT),
        );
        if !via_us {
            widgets::hint(
                ui,
                if detect_on {
                    "Правила DNS при этом не ставятся: они перебили бы резолвер туннеля, \
                     а подменённый адрес достигается через него и так."
                } else {
                    "«Определять VPN» выключено — обход применяется поверх туннеля."
                },
            );
        }
        ui.add_space(6.0);
        vpn_help(app, via_us, detect_on, ui);
    });
    ui.add_space(8.0);
}

/// The part a status line cannot do: what to change, and with which file.
///
/// The path is the whole value of this block. Every VPN client spells split
/// tunnelling differently, but all of them ask for an executable, and finding
/// the right one inside an Antigravity install is not something a user should
/// have to do by hand. *Which* one depends on the route: with the local proxy on
/// it is our own service that opens the connection (G46), otherwise the language
/// server — never the shell or the CLI, which carry no gated call.
fn vpn_help(app: &App, via_us: bool, detect_on: bool, ui: &mut egui::Ui) {
    egui::CollapsingHeader::new(
        egui::RichText::new("Что сделать, если ошибка 400 повторяется")
            .size(12.5)
            .color(theme::MUTED),
    )
    .id_salt("vpn-help")
    .default_open(false)
    .show(ui, |ui| {
        // Which file to name is not a detail: with the local-proxy route on, the
        // language server holds no connection to Google at all (measured — ten
        // sockets to `127.0.0.1:53129` and none on 443), so excluding it from a
        // VPN does exactly nothing. The process that opens the connection is the
        // one to exclude.
        //
        // The caller's answer, not a second opinion derived from the switches:
        // the headline above and the file below must be about the same process,
        // and a measurement and a switch can disagree about which that is.
        let via_us = via_us
            && app
                .status
                .as_ref()
                .is_some_and(|s| s.relay_exe.is_some());
        widgets::hint(
            ui,
            if via_us {
                "Первый путь — вывести из туннеля то, что открывает соединение. Сейчас \
                 это служба обхода: в клиенте VPN найдите «раздельное туннелирование», \
                 split tunneling или «исключить приложения» и добавьте туда этот файл."
            } else {
                "Первый путь — вывести Antigravity из туннеля. В клиенте VPN это \
                 «раздельное туннелирование», split tunneling или «исключить приложения»: \
                 добавьте туда файл языкового сервера — весь трафик, который упирается \
                 в ошибку 400, идёт именно из него."
            },
        );
        ui.add_space(4.0);

        let exes = app
            .status
            .as_ref()
            .map(|s| {
                if via_us {
                    s.relay_exe.iter().cloned().collect()
                } else {
                    s.client_exes.clone()
                }
            })
            .unwrap_or_default();
        if exes.is_empty() {
            widgets::hint(
                ui,
                "Путь появится здесь, как только установка Antigravity будет найдена — \
                 карточка выше.",
            );
        }
        for exe in &exes {
            let full = exe.display().to_string();
            ui.horizontal(|ui| {
                // Button first, path second: a truncating label given the row
                // first takes what is left of it, and the button then lands past
                // the edge of the card.
                if ui
                    .small_button("Копировать")
                    .on_hover_text(full.clone())
                    .clicked()
                {
                    ui.ctx().copy_text(full.clone());
                }
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(mask_path(&full))
                            .size(12.0)
                            .color(theme::MUTED)
                            .monospace(),
                    )
                    .truncate(),
                )
                .on_hover_text(full.clone());
            });
        }
        // Only where it is true. With our service in the tunnel the rules are
        // already installed (the client is not in there, so the layer never
        // stood down), and with «Определять VPN» off they are installed over the
        // tunnel by design — in both cases this line would send the user to
        // re-do something that is already done.
        if !via_us && detect_on {
            ui.add_space(4.0);
            widgets::hint(
                ui,
                "После этого включите «Обход через DNS» заново: правила ставятся только \
                 тогда, когда Antigravity вне туннеля.",
            );
        }
        // Only when the *client* is the one in the tunnel. With the proxy route
        // on, the rules are installed already (the layer stands down for the
        // client, and the client is not in there), so this switch would change
        // nothing at all — offering it would send the user to flip something
        // irrelevant and then wonder why the error stayed.
        if !via_us {
            ui.add_space(6.0);
            widgets::hint(
                ui,
                "Второй путь — выключить «Определять VPN» ниже. Тогда обход применяется \
                 поверх туннеля: это то, что нужно, если исключений в вашем VPN нет.",
            );
        }
    });
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
    use super::{ago_text, display_name, plural};
    use std::time::Duration;

    /// The line under the 400 callout is read by someone already annoyed. Three
    /// forms, and the teens are the trap: «11 минут», not «11 минута».
    #[test]
    fn russian_counts_in_three_forms() {
        let minutes = |n| plural(n, "минуту", "минуты", "минут");
        assert_eq!(minutes(1), "минуту");
        assert_eq!(minutes(2), "минуты");
        assert_eq!(minutes(4), "минуты");
        assert_eq!(minutes(5), "минут");
        assert_eq!(minutes(11), "минут");
        assert_eq!(minutes(12), "минут");
        assert_eq!(minutes(14), "минут");
        assert_eq!(minutes(21), "минуту");
        assert_eq!(minutes(22), "минуты");
        assert_eq!(minutes(25), "минут");
        assert_eq!(minutes(0), "минут");
    }

    /// «Обход её перехватил» is the one line here that asserts something
    /// happened. A relay that answered a refusal and was then killed must not
    /// have that answer credited to the next one.
    /// The cell that matters: telling somebody to edit their VPN is only right
    /// when the process that opens the connection is actually inside the tunnel.
    #[test]
    fn the_window_asks_for_a_vpn_change_only_when_one_would_help() {
        use super::vpn_quiet_line;
        use crate::egress::ClientEgress;
        use crate::ops::VpnSeen;
        // Never `use VpnSeen::*` here: its `None` shadows `Option::None` and the
        // second argument silently becomes the wrong kind of nothing.
        let callout = |seen, relay| vpn_quiet_line(seen, relay).is_none();
        const ALL: [Option<ClientEgress>; 5] = [
            Some(ClientEgress::Tunnel),
            Some(ClientEgress::Mixed),
            Some(ClientEgress::Physical),
            Some(ClientEgress::Unknown),
            None,
        ];
        let quiet_relay = [
            Some(ClientEgress::Physical),
            Some(ClientEgress::Unknown),
            None,
        ];

        // Our service in the tunnel decides on its own, whatever the client is
        // doing — that is the state the gate refuses and the user must fix.
        for seen in [
            VpnSeen::ViaLocalProxy,
            VpnSeen::NotCarryingClient,
            VpnSeen::Unmeasured,
            VpnSeen::CarryingClient,
            VpnSeen::PartlyCarryingClient,
        ] {
            assert!(callout(seen, Some(ClientEgress::Tunnel)), "{seen:?}");
            // Half its sockets in there is the same problem for the half in it.
            assert!(callout(seen, Some(ClientEgress::Mixed)), "{seen:?}");
        }
        // The client's own sockets in the tunnel, whole or in part: also ours
        // to point at, whatever the relay does.
        for relay in ALL {
            assert!(callout(VpnSeen::CarryingClient, relay));
            assert!(callout(VpnSeen::PartlyCarryingClient, relay));
        }
        // Everything else is one grey line. `ViaLocalProxy` + relay outside is
        // the working combination and must never ask for anything.
        for relay in quiet_relay {
            assert!(!callout(VpnSeen::ViaLocalProxy, relay));
            assert!(!callout(VpnSeen::NotCarryingClient, relay));
            assert!(!callout(VpnSeen::Unmeasured, relay));
        }
    }

    #[test]
    fn only_a_note_written_after_the_refusal_answers_it() {
        use super::answers;
        // Noticed on the warm pass after the line was logged: the normal case.
        assert!(answers(1_000, 1_000));
        assert!(answers(1_015, 1_000));
        assert!(answers(2_000, 1_000));
        // A second either way is the two stamps' whole-second quantisation.
        assert!(answers(998, 1_000));
        // Anything older is an answer to a different refusal.
        assert!(!answers(940, 1_000));
        assert!(!answers(0, 1_000));
        // A corrupt record must not overflow its way into a true answer.
        assert!(answers(u64::MAX, 1_000));
        assert!(!answers(0, u64::MAX));
    }

    #[test]
    fn one_refusal_is_an_event_and_several_are_a_pattern() {
        use super::headline;
        assert_eq!(headline(1, Duration::from_secs(5)), "Ошибка 400 — только что.");
        assert_eq!(
            headline(3, Duration::from_secs(120)),
            "Ошибка 400 — 3 раза за 10 мин, последняя 2 минуты назад."
        );
        // Never drawn, but a count of zero must not produce «0 раз».
        assert_eq!(
            headline(0, Duration::from_secs(70)),
            "Ошибка 400 — 1 минуту назад."
        );
    }

    #[test]
    fn an_age_reads_as_a_person_would_say_it() {
        assert_eq!(ago_text(Duration::from_secs(3)), "только что");
        assert_eq!(ago_text(Duration::from_secs(22)), "22 секунды назад");
        assert_eq!(ago_text(Duration::from_secs(59)), "59 секунд назад");
        assert_eq!(ago_text(Duration::from_secs(61)), "1 минуту назад");
        assert_eq!(ago_text(Duration::from_secs(9 * 60)), "9 минут назад");
    }


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
