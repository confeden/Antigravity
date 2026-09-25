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

/// How much of the relay's own log goes in: enough to cover the last few
/// minutes of a busy session, short enough to paste into a chat.
const LOG_LINES: usize = 60;

pub fn build(status: Option<&Status>, view: &View) -> String {
    let mut out = String::new();
    let now = crate::utils::local_clock().map_or_else(String::new, |c| c.hms());
    let _ = writeln!(
        out,
        "Antigravity Unlocker v{} — отчёт {}",
        crate::update::current_version(),
        now
    );

    match status {
        Some(s) => status_part(&mut out, s),
        None => {
            let _ = writeln!(out, "Состояние системы ещё не прочитано.");
        }
    }

    let _ = writeln!(out, "\n— Antigravity (его собственные логи)");
    match view.answered {
        Some(a) => {
            let _ = writeln!(
                out,
                "Последний ответ модели: {} (за 12 ч: {})",
                super::status::ago_text(a.ago),
                a.count
            );
        }
        None => {
            let _ = writeln!(out, "Ответов модели за 12 ч в логах нет.");
        }
    }
    match view.refused_long {
        Some(r) => {
            let _ = writeln!(
                out,
                "Последняя ошибка 400: {} (строк за 10 мин: {})",
                super::status::ago_text(r.ago),
                view.seen.map_or(0, |s| s.count)
            );
        }
        None => {
            let _ = writeln!(out, "Ошибок 400 за 12 ч в логах нет.");
        }
    }
    // When, and on which host - never the link: it carries a one-time token,
    // and the report is made to be sent to someone else.
    if let Some(v) = &view.verify {
        let host = v
            .url
            .strip_prefix("https://")
            .and_then(|r| r.split(['/', '?', '#']).next())
            .unwrap_or("");
        let _ = writeln!(
            out,
            "Google просил верификацию аккаунта: {} ({host})",
            super::status::ago_text(v.ago)
        );
    }

    // Fresh from the file, not the window's copy: the route table's ages move
    // every pass and the watcher does not wake the window for them.
    let _ = writeln!(out, "\n— Служба обхода (её запись)");
    match crate::gate::read() {
        Some(r) => relay_part(&mut out, &r),
        None => {
            let _ = writeln!(out, "Записи нет — служба не запущена или старая.");
        }
    }

    let _ = writeln!(out, "\n— Журнал службы (последние строки)");
    let log = std::fs::read_to_string(crate::dns_forwarder::log_path()).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    let from = lines.len().saturating_sub(LOG_LINES);
    let own = crate::upstream::configured().map(|u| u.display());
    for line in &lines[from..] {
        let _ = writeln!(out, "{}", mask_addresses(line, own.as_deref()));
    }
    if lines.is_empty() {
        let _ = writeln!(out, "(пусто)");
    }
    out
}

fn onoff(s: &State) -> String {
    match s {
        State::On => "вкл".to_string(),
        State::Off => "выкл".to_string(),
        State::Partial(n) => format!("частично ({n})"),
        State::OffNote(n) => format!("выкл ({n})"),
        State::Blocked(n) => format!("недоступно ({n})"),
    }
}

fn status_part(out: &mut String, s: &Status) {
    let _ = writeln!(
        out,
        "Права администратора: {}",
        if s.admin { "да" } else { "нет" }
    );
    let _ = writeln!(out, "\n— Установки");
    for row in &s.installs {
        let path = row
            .path
            .as_ref()
            .map(|p| mask_path(&p.display().to_string()))
            .unwrap_or_else(|| "не найдена".to_string());
        let patched = match row.patched {
            Some(true) => "пропатчена",
            Some(false) => "НЕ пропатчена",
            None => "не проверена",
        };
        let _ = writeln!(out, "{}: {} — {}", row.label, path, patched);
    }
    let _ = writeln!(out, "\n— Переключатели");
    let _ = writeln!(out, "Разблокировка входа: {}", onoff(&s.client_patch));
    let _ = writeln!(out, "Автопатч: {}", onoff(&s.watchdog));
    let _ = writeln!(out, "Обход через DNS: {}", onoff(&s.dns));
    let _ = writeln!(out, "Локальный прокси: {}", onoff(&s.local_proxy));
    let _ = writeln!(out, "Встроенные выходы: {}", onoff(&s.builtin_exits));
    let _ = writeln!(out, "Свой прокси: {}", onoff(&s.own_proxy));
    let _ = writeln!(out, "Сверять TLS: {}", onoff(&s.verify_tls));
    let _ = writeln!(
        out,
        "Служба: {}{}; правила DNS: {}",
        if s.relay_running {
            "запущена"
        } else {
            "НЕ запущена"
        },
        if s.relay_outdated {
            ", устарела"
        } else {
            ""
        },
        if s.rules { "есть" } else { "НЕТ" }
    );
    if let Some(vpn) = s.vpn {
        let _ = writeln!(out, "VPN (по сокетам Antigravity): {:?}", vpn);
    }
    if let Some(eg) = s.relay_egress {
        let _ = writeln!(out, "Сокеты службы: {:?}", eg);
    }
}

fn relay_part(out: &mut String, r: &Report) {
    let _ = writeln!(
        out,
        "Версия службы: {} (эта программа ждёт {}), запись {} с назад",
        r.version,
        crate::dns_forwarder::RELAY_VERSION,
        r.age().as_secs()
    );
    let _ = writeln!(
        out,
        "Гейт-хосты через локальные адреса: {}",
        if r.loopback { "да" } else { "нет" }
    );
    for b in &r.blockers {
        let _ = writeln!(out, "Мешает обходу: {}", super::status::blocker_line(b));
    }
    if crate::proxy::port() != crate::proxy::DEFAULT_PORT {
        let _ = writeln!(
            out,
            "Порт локального прокси: {} (перенесён со стандартного {})",
            crate::proxy::port(),
            crate::proxy::DEFAULT_PORT
        );
    }
    if r.started_at != 0 {
        let _ = writeln!(
            out,
            "Ответ из интернета служба получала: {}",
            if r.reached_at == 0 {
                "ни разу с запуска".to_string()
            } else {
                format!(
                    "{} с назад",
                    crate::gate::now_unix().saturating_sub(r.reached_at)
                )
            }
        );
    }
    let _ = writeln!(
        out,
        "VPN держит маршрут по умолчанию: {}{}",
        if r.tunnel { "да" } else { "нет" },
        if r.vpn_exit.is_empty() {
            String::new()
        } else {
            format!(", выход: {}", r.vpn_exit)
        }
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
    let _ = writeln!(out, "Первый маршрут сейчас: {}", non_empty(first));
    if let Some(ok) = &r.last_ok {
        let _ = writeln!(
            out,
            "Последний ответ модели, который видела служба: {} с назад, маршрут: {}",
            crate::gate::now_unix().saturating_sub(ok.at),
            non_empty(&ok.route)
        );
    }
    if let Some(e) = &r.last_400 {
        let _ = writeln!(
            out,
            "Последняя ошибка 400, которую видела служба: {} с назад, строк: {}, маршрут: {}{}",
            crate::gate::now_unix().saturating_sub(e.at),
            e.count,
            non_empty(&e.route),
            if e.bypassed {
                " (мимо обхода)"
            } else {
                ""
            }
        );
        if !e.acted.is_empty() {
            let _ = writeln!(out, "Что сделано: {}", e.acted);
        }
    }
    let _ = writeln!(out, "Маршруты (в порядке выбора):");
    for row in &r.routes {
        let mut parts: Vec<String> = Vec::new();
        // One state word, not two: «доступен … отложен ещё на 10 мин» is what a
        // benched-but-still-offered route used to print, and it reads as a
        // contradiction to the person pasting it.
        parts.push(match (row.usable, row.bench_left) {
            (false, _) => "сейчас не используется".to_string(),
            (true, Some(b)) => format!("отложен ещё на {} мин, но в очереди", b / 60 + 1),
            (true, None) => "доступен".to_string(),
        });
        if let Some(ms) = row.latency_ms {
            parts.push(format!("{ms} мс"));
        }
        if row.proven {
            parts.push("проверен ответом модели".to_string());
        }
        if let Some(a) = row.ok_ago {
            parts.push(format!("ответ {a} с назад"));
        }
        if let Some(a) = row.refused_ago {
            parts.push(format!("ошибка 400 {a} с назад"));
        }
        // The tally, not just the two timestamps: «ответ 34 с назад, ошибка 400
        // 14 с назад» is the same line for a route that answers nine times out
        // of ten and for one that answers once in fifty, and three field
        // reports (2026-09-21) turned on telling those apart.
        if row.answers > 0 || row.refusals > 0 {
            parts.push(format!(
                "ответов {}, отказов {}",
                row.answers, row.refusals
            ));
        }
        if let Some(b) = row.bench_left.filter(|_| !row.usable) {
            parts.push(format!("отложен ещё на {} мин", b / 60 + 1));
        }
        if row.open > 0 {
            parts.push(format!("открытых соединений: {}", row.open));
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
