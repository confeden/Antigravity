//! «Сохранить отчёт»: everything needed to say why Antigravity is or is not
//! answering, in one paste.
//!
//! «Поставил анлокер, но не помогает что-то» plus a screenshot of a green card
//! was undiagnosable (G50): the one fact that mattered - the client was not
//! going through us at all - was nowhere on screen. This puts every fact the
//! window and the relay have into plain text a user can send to the group.
//!
//! Nothing secret goes in: paths are masked the way the window shows them, the
//! built-in exits are named only as «встроенный выход» (I46), and the relay's
//! log - which is included - never names an address of ours in the first place.

use std::fmt::Write as _;

use crate::gate::{Report, View};
use crate::ops::{State, Status};
use crate::utils::mask_path;

/// The report exists in development builds only (owner, 2026-11-03: «создавать
/// отчёты больше не надо»). Release builds show no button, no TUI row and no
/// `o` key, and no message sends a user to «Сохранить отчёт»; the relay's logs
/// are untouched.
pub const ENABLED: bool = cfg!(debug_assertions);

/// The tail of a «what to try» message: the report when it can be made, the
/// group otherwise.
pub fn when_stuck() -> &'static str {
    if ENABLED {
        crate::i18n::tr(
            "нажмите «Сохранить отчёт» и пришлите файл с рабочего стола в группу.",
            "click \"Save report\" and send the file from your Desktop to the group.",
        )
    } else {
        crate::i18n::tr(
            "напишите об этом в группу.",
            "write about it in the group.",
        )
    }
}

/// How much of the relay's own log goes in: enough to cover the last few
/// minutes of a busy session, short enough to paste into a chat.
const LOG_LINES: usize = 60;

pub fn build(status: Option<&Status>, view: &View) -> String {
    let mut out = String::new();
    let now = crate::utils::local_clock().map_or_else(String::new, |c| c.hms());
    let _ = writeln!(
        out,
        "Antigravity Unlocker v{} — {} {now}",
        crate::update::current_version(),
        crate::i18n::tr("отчёт", "report"),
    );

    match status {
        Some(s) => status_part(&mut out, s),
        None => {
            let _ = writeln!(
                out,
                "{}",
                crate::i18n::tr(
                    "Состояние системы ещё не прочитано.",
                    "System state has not been read yet.",
                )
            );
        }
    }

    let _ = writeln!(
        out,
        "\n— {}",
        crate::i18n::tr(
            "Antigravity (его собственные логи)",
            "Antigravity (its own logs)",
        )
    );
    match view.answered {
        Some(a) => {
            let ago = super::status::ago_text(a.ago);
            let _ = writeln!(
                out,
                "{}",
                match crate::i18n::current() {
                    crate::i18n::Lang::Ru => format!("Последний ответ модели: {ago} (за 12 ч: {})", a.count),
                    crate::i18n::Lang::En => format!("Last model reply: {ago} (in 12h: {})", a.count),
                }
            );
        }
        None => {
            let _ = writeln!(
                out,
                "{}",
                crate::i18n::tr(
                    "Ответов модели за 12 ч в логах нет.",
                    "No model replies in logs over the last 12h.",
                )
            );
        }
    }
    match view.refused_long {
        Some(r) => {
            let ago = super::status::ago_text(r.ago);
            let cnt = view.seen.map_or(0, |s| s.count);
            let _ = writeln!(
                out,
                "{}",
                match crate::i18n::current() {
                    crate::i18n::Lang::Ru => format!("Последняя ошибка 400: {ago} (строк за 10 мин: {cnt})"),
                    crate::i18n::Lang::En => format!("Last error 400: {ago} (lines in 10m: {cnt})"),
                }
            );
        }
        None => {
            let _ = writeln!(
                out,
                "{}",
                crate::i18n::tr(
                    "Ошибок 400 за 12 ч в логах нет.",
                    "No error 400 in logs over the last 12h.",
                )
            );
        }
    }
    if let Some(o) = &view.overloaded {
        let model = if o.model.is_empty() {
            String::new()
        } else {
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(", модель {}", o.model),
                crate::i18n::Lang::En => format!(", model {}", o.model),
            }
        };
        let ago = super::status::ago_text(o.ago);
        let _ = writeln!(
            out,
            "{}",
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("Ошибка 503 (нет мощностей у Google{model}): {ago}, строк за 10 мин: {}", o.count),
                crate::i18n::Lang::En => format!("Error 503 (Google out of capacity{model}): {ago}, lines in 10m: {}", o.count),
            }
        );
    }
    if let Some(e) = &view.server_errors {
        let ago = super::status::ago_text(e.ago);
        let _ = writeln!(
            out,
            "{}",
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("Ошибки на стороне Google (503/429/500) за 12 ч: {}, последняя {ago}", e.count),
                crate::i18n::Lang::En => format!("Google server errors (503/429/500) in 12h: {}, last {ago}", e.count),
            }
        );
    }
    if let Some(u) = &view.unauthorized {
        let ago = super::status::ago_text(u.ago);
        let _ = writeln!(
            out,
            "{}",
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("Ошибка 401 (учётные данные не приняты): {ago}, строк за 10 мин: {}", u.count),
                crate::i18n::Lang::En => format!("Error 401 (credentials rejected): {ago}, lines in 10m: {}", u.count),
            }
        );
    }
    if let Some(v) = &view.verify {
        let host = v
            .url
            .strip_prefix("https://")
            .and_then(|r| r.split(['/', '?', '#']).next())
            .unwrap_or("");
        let ago = super::status::ago_text(v.ago);
        let _ = writeln!(
            out,
            "{}",
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("Google просил верификацию аккаунта: {ago} ({host})"),
                crate::i18n::Lang::En => format!("Google requested account verification: {ago} ({host})"),
            }
        );
    }

    let _ = writeln!(
        out,
        "\n— {}",
        crate::i18n::tr(
            "Служба обхода (её запись)",
            "Bypass service (its record)",
        )
    );
    match crate::gate::read() {
        Some(r) => relay_part(&mut out, &r),
        None => {
            let _ = writeln!(
                out,
                "{}",
                crate::i18n::tr(
                    "Записи нет — служба не запущена или старая.",
                    "No record — service is not running or outdated.",
                )
            );
        }
    }

    let _ = writeln!(
        out,
        "\n— {}",
        crate::i18n::tr(
            "Журнал службы (последние строки)",
            "Service log (recent lines)",
        )
    );
    let log = std::fs::read_to_string(crate::dns_forwarder::log_path()).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    let from = lines.len().saturating_sub(LOG_LINES);
    let own = crate::upstream::configured().map(|u| u.display());
    for line in &lines[from..] {
        let _ = writeln!(out, "{}", mask_addresses(line, own.as_deref()));
    }
    if lines.is_empty() {
        let _ = writeln!(out, "{}", crate::i18n::tr("(пусто)", "(empty)"));
    }
    out
}

fn onoff(s: &State) -> String {
    match s {
        State::On => crate::i18n::tr("вкл", "on").to_string(),
        State::Off => crate::i18n::tr("выкл", "off").to_string(),
        State::Partial(n) => format!("{} ({n})", crate::i18n::tr("частично", "partial")),
        State::OffNote(n) => format!("{} ({n})", crate::i18n::tr("выкл", "off")),
        State::Blocked(n) => format!("{} ({n})", crate::i18n::tr("недоступно", "unavailable")),
    }
}

fn status_part(out: &mut String, s: &Status) {
    let yes = crate::i18n::tr("да", "yes");
    let no = crate::i18n::tr("нет", "no");
    let _ = writeln!(
        out,
        "{}: {}",
        crate::i18n::tr("Права администратора", "Administrator rights"),
        if s.admin { yes } else { no }
    );
    let _ = writeln!(
        out,
        "\n— {}",
        crate::i18n::tr("Установки", "Installations")
    );
    for row in &s.installs {
        let path = row
            .path
            .as_ref()
            .map(|p| mask_path(&p.display().to_string()))
            .unwrap_or_else(|| crate::i18n::tr("не найдена", "not found").to_string());
        let patched = match row.patched {
            Some(true) => crate::i18n::tr("пропатчена", "patched"),
            Some(false) => crate::i18n::tr("НЕ пропатчена", "NOT patched"),
            None => crate::i18n::tr("не проверена", "not checked"),
        };
        let _ = writeln!(out, "{}: {} — {}", row.label, path, patched);
    }
    let _ = writeln!(
        out,
        "\n— {}",
        crate::i18n::tr("Переключатели", "Switches")
    );
    let _ = writeln!(out, "{}: {}", crate::i18n::tr("Разблокировка входа", "Sign-in unlock"), onoff(&s.client_patch));
    let _ = writeln!(out, "{}: {}", crate::i18n::tr("Автопатч", "Auto-patch"), onoff(&s.watchdog));
    let _ = writeln!(out, "{}: {}", crate::i18n::tr("Обход через DNS", "DNS bypass"), onoff(&s.dns));
    let _ = writeln!(out, "{}: {}", crate::i18n::tr("Локальный прокси", "Local proxy"), onoff(&s.local_proxy));
    let key_present = if crate::settings::group_key().is_empty() {
        crate::i18n::tr("нет", "none")
    } else if crate::group::key_rejected() {
        crate::i18n::tr(
            "есть, но сервер его не принимает (перестал работать)",
            "present, but rejected by server (stopped working)",
        )
    } else {
        crate::i18n::tr("есть", "present")
    };
    let _ = writeln!(
        out,
        "{}",
        match crate::i18n::current() {
            crate::i18n::Lang::Ru => format!(
                "Прокси из группы: {}, ключ: {}, код ПК: {}",
                onoff(&s.group_proxy),
                key_present,
                crate::hwid::pc_code()
            ),
            crate::i18n::Lang::En => format!(
                "Group proxy: {}, key: {}, PC code: {}",
                onoff(&s.group_proxy),
                key_present,
                crate::hwid::pc_code()
            ),
        }
    );
    let _ = writeln!(out, "{}: {}", crate::i18n::tr("Свой прокси", "Own proxy"), onoff(&s.own_proxy));
    let _ = writeln!(
        out,
        "{}: {}{}; {}: {}",
        crate::i18n::tr("Служба", "Service"),
        if s.relay_running {
            crate::i18n::tr("запущена", "running")
        } else {
            crate::i18n::tr("НЕ запущена", "NOT running")
        },
        if s.relay_outdated {
            crate::i18n::tr(", устарела", ", outdated")
        } else {
            ""
        },
        crate::i18n::tr("правила DNS", "DNS rules"),
        if s.rules {
            crate::i18n::tr("есть", "present")
        } else {
            crate::i18n::tr("НЕТ", "NONE")
        }
    );
    if let Some(vpn) = s.vpn {
        let _ = writeln!(out, "VPN: {:?}", vpn);
    }
    if let Some(eg) = s.relay_egress {
        let _ = writeln!(out, "{}: {:?}", crate::i18n::tr("Сокеты службы", "Service sockets"), eg);
    }
}

fn relay_part(out: &mut String, r: &Report) {
    let yes = crate::i18n::tr("да", "yes");
    let no = crate::i18n::tr("нет", "no");
    let age_s = r.age().as_secs();
    let _ = writeln!(
        out,
        "{}",
        match crate::i18n::current() {
            crate::i18n::Lang::Ru => format!(
                "Версия службы: {} (эта программа ждёт {}), запись {age_s} с назад",
                r.version,
                crate::dns_forwarder::RELAY_VERSION,
            ),
            crate::i18n::Lang::En => format!(
                "Service version: {} (expected {}), record {age_s}s ago",
                r.version,
                crate::dns_forwarder::RELAY_VERSION,
            ),
        }
    );
    let _ = writeln!(
        out,
        "{}: {}",
        crate::i18n::tr(
            "Гейт-хосты через локальные адреса",
            "Gate hosts via local addresses",
        ),
        if r.loopback { yes } else { no }
    );
    for b in &r.blockers {
        let _ = writeln!(
            out,
            "{}: {}",
            crate::i18n::tr("Мешает обходу", "Blocking bypass"),
            super::status::blocker_line(b)
        );
    }
    if crate::proxy::port() != crate::proxy::DEFAULT_PORT {
        let _ = writeln!(
            out,
            "{}",
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Порт локального прокси: {} (перенесён со стандартного {})",
                    crate::proxy::port(),
                    crate::proxy::DEFAULT_PORT
                ),
                crate::i18n::Lang::En => format!(
                    "Local proxy port: {} (moved from default {})",
                    crate::proxy::port(),
                    crate::proxy::DEFAULT_PORT
                ),
            }
        );
    }
    if r.started_at != 0 {
        let reached_text = if r.reached_at == 0 {
            crate::i18n::tr(
                "ни разу с запуска",
                "never since start",
            )
            .to_string()
        } else {
            let secs = crate::gate::now_unix().saturating_sub(r.reached_at);
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("{secs} с назад"),
                crate::i18n::Lang::En => format!("{secs}s ago"),
            }
        };
        let _ = writeln!(
            out,
            "{}: {reached_text}",
            crate::i18n::tr(
                "Ответ из интернета служба получала",
                "Service last received internet reply",
            )
        );
    }
    let exit_note = if r.vpn_exit.is_empty() {
        String::new()
    } else {
        match crate::i18n::current() {
            crate::i18n::Lang::Ru => format!(", выход: {}", r.vpn_exit),
            crate::i18n::Lang::En => format!(", exit: {}", r.vpn_exit),
        }
    };
    let _ = writeln!(
        out,
        "{}: {}{exit_note}",
        crate::i18n::tr(
            "VPN держит маршрут по умолчанию",
            "VPN holds default route",
        ),
        if r.tunnel { yes } else { no }
    );
    // The table's own first usable row, not `r.route`: that one is the
    // hysteresis memory (`routes::leader`) and can still name a route the order
    // has moved past, which put a headline in the report contradicting the
    // table printed right under it (field report, 2026-09-20).
    let first = r
        .routes
        .iter()
        .find(|row| row.usable)
        .map(|row| row.label.as_str())
        .unwrap_or(r.route.as_str());
    let _ = writeln!(
        out,
        "{}: {}",
        crate::i18n::tr(
            "Первый маршрут сейчас",
            "Current primary route",
        ),
        non_empty(first)
    );
    if let Some(ok) = &r.last_ok {
        let secs = crate::gate::now_unix().saturating_sub(ok.at);
        let route = non_empty(&ok.route);
        let _ = writeln!(
            out,
            "{}",
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Последний ответ модели, который видела служба: {secs} с назад, маршрут: {route}"
                ),
                crate::i18n::Lang::En => format!(
                    "Last model reply seen by service: {secs}s ago, route: {route}"
                ),
            }
        );
    }
    if let Some(e) = &r.last_400 {
        let secs = crate::gate::now_unix().saturating_sub(e.at);
        let route = non_empty(&e.route);
        let bypassed = if e.bypassed {
            crate::i18n::tr(" (мимо обхода)", " (bypassed unlocker)")
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "{}",
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Последняя ошибка 400, которую видела служба: {secs} с назад, строк: {}, маршрут: {route}{bypassed}",
                    e.count
                ),
                crate::i18n::Lang::En => format!(
                    "Last error 400 seen by service: {secs}s ago, lines: {}, route: {route}{bypassed}",
                    e.count
                ),
            }
        );
        if !e.acted.is_empty() {
            let _ = writeln!(
                out,
                "{}: {}",
                crate::i18n::tr("Что сделано", "Action taken"),
                e.acted
            );
        }
    }
    let _ = writeln!(
        out,
        "{}",
        crate::i18n::tr(
            "Маршруты (в порядке выбора):",
            "Routes (in priority order):",
        )
    );
    for row in &r.routes {
        let mut parts: Vec<String> = Vec::new();
        // One state word, not two: «доступен … отложен ещё на 10 мин» is what a
        // benched-but-still-offered route used to print, and it reads as a
        // contradiction to the person pasting it.
        parts.push(match (row.usable, row.bench_left) {
            (false, _) => crate::i18n::tr(
                "сейчас не используется",
                "currently unused",
            )
            .to_string(),
            (true, Some(b)) => {
                let mins = b / 60 + 1;
                match crate::i18n::current() {
                    crate::i18n::Lang::Ru => format!("отложен ещё на {mins} мин, но в очереди"),
                    crate::i18n::Lang::En => format!("benched for {mins}m more, still queued"),
                }
            }
            (true, None) => crate::i18n::tr("доступен", "available").to_string(),
        });
        if let Some(ms) = row.latency_ms {
            parts.push(match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("{ms} мс"),
                crate::i18n::Lang::En => format!("{ms} ms"),
            });
        }
        if row.proven {
            parts.push(
                crate::i18n::tr(
                    "проверен ответом модели",
                    "verified by model reply",
                )
                .to_string(),
            );
        }
        if let Some(a) = row.ok_ago {
            parts.push(match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("ответ {a} с назад"),
                crate::i18n::Lang::En => format!("reply {a}s ago"),
            });
        }
        if let Some(a) = row.refused_ago {
            parts.push(match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("ошибка 400 {a} с назад"),
                crate::i18n::Lang::En => format!("error 400 {a}s ago"),
            });
        }
        // The tally, not just the two timestamps: «ответ 34 с назад, ошибка 400
        // 14 с назад» is the same line for a route that answers nine times out
        // of ten and for one that answers once in fifty, and three field
        // reports (2026-09-21) turned on telling those apart.
        if row.answers > 0 || row.refusals > 0 {
            parts.push(match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("ответов {}, отказов {}", row.answers, row.refusals),
                crate::i18n::Lang::En => format!("replies {}, refusals {}", row.answers, row.refusals),
            });
        }
        if let Some(b) = row.bench_left.filter(|_| !row.usable) {
            let mins = b / 60 + 1;
            parts.push(match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("отложен ещё на {mins} мин"),
                crate::i18n::Lang::En => format!("benched for {mins}m more"),
            });
        }
        if row.open > 0 {
            parts.push(match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("открытых соединений: {}", row.open),
                crate::i18n::Lang::En => format!("open connections: {}", row.open),
            });
        }
        let _ = writeln!(out, "  {} — {}", row.label, parts.join(", "));
    }
}

/// One line of the relay's log with the user's own proxy, and any route's exit
/// address, taken out.
///
/// Since `2.15.0_1` the relay no longer writes that address at all, but a log
/// written by an older build is still in the file after the upgrade, and it did:
/// `свой прокси user:***@host:port: <why>` - their login and their server, on
/// the way into a public chat. Matching only the proxy configured *now* missed
/// every line from one they had before or had since removed, so this goes by
/// shape: any `…:***@…` credential token, and the address right after
/// «свой прокси», whatever it is. The configured value is masked too, for any
/// line that names it some other way.
fn mask_addresses(line: &str, configured: Option<&str>) -> String {
    const MASK: &str = "<ваш прокси>";
    const LABEL: &str = "свой прокси ";
    let mut out: String = line
        .split(' ')
        .map(|token| {
            if token.contains(":***@") {
                // Keep the colon that separated the address from the reason.
                if token.ends_with(':') {
                    format!("{MASK}:")
                } else {
                    MASK.to_string()
                }
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    // `свой прокси host:port: why` from before the credential form existed: an
    // address token is the one that still has a colon inside it (`host:port`).
    if let Some(at) = out.find(LABEL) {
        let rest = &out[at + LABEL.len()..];
        let token = rest.split(' ').next().unwrap_or("");
        let bare = token.strip_suffix(':').unwrap_or(token);
        if bare.contains(':') && bare != MASK {
            let masked = if token.ends_with(':') {
                format!("{MASK}:")
            } else {
                MASK.to_string()
            };
            out = format!(
                "{}{}{}",
                &out[..at + LABEL.len()],
                masked,
                &rest[token.len()..]
            );
        }
    }
    // Older builds also named a route's exit address when it moved: for the
    // user's own proxy that is their server, for a built-in exit usually the
    // exit itself (I46). The country after it stays - it is what the line says.
    for phrase in ["выходит через ", "сменил выход на "] {
        if let Some(at) = out.find(phrase) {
            let start = at + phrase.len();
            let len = out[start..].find(' ').unwrap_or(out.len() - start);
            out.replace_range(start..start + len, "<адрес>");
        }
    }
    match configured {
        Some(own) if !own.is_empty() => out.replace(own, MASK),
        _ => out,
    }
}

fn non_empty(s: &str) -> &str {
    if s.is_empty() {
        "—"
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    /// What «Сохранить отчёт» writes to the file on this machine, minus the
    /// system scan the window adds. Reads, never asserts content.
    ///
    ///     cargo test prints_the_report -- --ignored --nocapture
    #[test]
    #[ignore = "reads the live relay record and log; run with --ignored"]
    fn prints_the_report() {
        let text = super::build(None, &crate::gate::View::default());
        println!("{text}");
        assert!(text.contains("отчёт"));
    }

    /// The line that says whether a route half-works. Two timestamps read the
    /// same for a route answering nine times in ten and one answering once in
    /// fifty, and three field reports (2026-09-21) turned on telling them
    /// apart.
    #[test]
    fn a_route_row_says_how_often_it_answered_and_how_often_it_was_refused() {
        let relay = crate::gate::Report {
            at: crate::gate::now_unix(),
            routes: vec![crate::routes::Row {
                label: "напрямую".into(),
                usable: true,
                latency_ms: Some(479),
                proven: true,
                ok_ago: Some(34),
                refused_ago: Some(14),
                answers: 21,
                refusals: 30,
                open: 2,
                ..Default::default()
            }],
            ..Default::default()
        };
        // `relay_part`, not `build`: the report reads the live record off the
        // disk on purpose (the table's ages move every pass and nothing wakes
        // the window for them), so a synthesised one only reaches this half.
        let mut text = String::new();
        super::relay_part(&mut text, &relay);
        assert!(
            text.contains("ответов 21, отказов 30"),
            "the tally is missing:\n{text}"
        );
        // …and the refusal is still shown, which is the half the split of
        // `bad_at`/`refused_at` must not have cost (G76).
        assert!(text.contains("ошибка 400 14 с назад"), "{text}");
    }

    use super::mask_addresses as mask;

    /// A line an older relay wrote about a proxy the user has since changed
    /// keeps nothing of it: not the login, not the server.
    #[test]
    fn an_old_credential_line_is_masked_whatever_is_configured_now() {
        let line = "12:00:01 proxy        свой прокси ivan:***@my.server.example:3128: недоступен: время вышло";
        for now in [None, Some("other:***@elsewhere.example:8080")] {
            let got = mask(line, now);
            assert!(
                !got.contains("ivan") && !got.contains("my.server.example"),
                "{got}"
            );
            assert!(
                got.contains("свой прокси <ваш прокси>: недоступен: время вышло"),
                "{got}"
            );
        }
    }

    /// The same from before credentials were masked in the display: a bare
    /// `host:port` after the label.
    #[test]
    fn an_old_bare_address_line_is_masked() {
        let got = mask(
            "12:00:01 proxy        свой прокси 10.0.0.5:1080: прокси закрыл соединение",
            None,
        );
        assert_eq!(
            got,
            "12:00:01 proxy        свой прокси <ваш прокси>: прокси закрыл соединение"
        );
    }

    /// Lines about the route by name stay readable: nothing there is an address.
    #[test]
    fn route_lines_are_left_alone() {
        for line in [
            "12:00:01 proxy        свой прокси -> daily-cloudcode-pa.googleapis.com",
            "12:00:01 proxy        свой прокси: недоступен: время вышло",
            "12:00:01 proxy        маршрут гейт-хостов: свой прокси (378 мс), было напрямую (325 мс)",
            "12:00:01 proxy        встроенный выход #1 не отвечает: недоступен: время вышло",
        ] {
            assert_eq!(mask(line, None), line);
        }
    }

    /// An older relay's exit-change lines keep the country, lose the address.
    #[test]
    fn an_old_exit_address_is_masked_and_the_country_kept() {
        assert_eq!(
            mask("12:00:01 proxy        свой прокси выходит через 203.0.113.9 (RU) — это заблокированный регион", None),
            "12:00:01 proxy        свой прокси выходит через <адрес> (RU) — это заблокированный регион"
        );
        assert_eq!(
            mask("12:00:01 proxy        встроенный выход #1 сменил выход на 203.0.113.9 (NL) — снова используем", None),
            "12:00:01 proxy        встроенный выход #1 сменил выход на <адрес> (NL) — снова используем"
        );
    }

    /// The proxy configured now is masked wherever it appears.
    #[test]
    fn the_configured_proxy_is_masked_anywhere() {
        let got = mask("что-то про 127.0.0.1:1371 и дальше", Some("127.0.0.1:1371"));
        assert_eq!(got, "что-то про <ваш прокси> и дальше");
    }
}
