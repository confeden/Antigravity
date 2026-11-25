//! The one line at the top of the window: is it working, and if not, what now.
//!
//! Everything below it is mechanism - which DNS answers, which route, which
//! switch - and a user who is not a programmer should not have to read any of
//! it to know whether Antigravity will answer. So the window's whole verdict is
//! derived here, as a pure function of facts the window already has, and it is
//! tested cell by cell: this is the sentence a user acts on.
//!
//! The rules that shaped it, each one a bug that shipped before:
//!
//! * **"Работает" needs proof.** Only a model answer in the client's own log
//!   turns the card green. Silence after a refusal used to read as "fixed" -
//!   and silence is also exactly what a user who gave up produces (G50).
//! * **One action at most, and a real one.** A card that says what is wrong
//!   carries the button that fixes it, or says plainly that there is nothing
//!   to press.
//! * **What was done is said by the side that did it** (the relay's record),
//!   never inferred from a switch being on (I58).

use std::time::Duration;

use crate::gate::View;
use crate::ops::{Cap, Status};

pub fn vpn_traffic_notice() -> &'static str {
    crate::i18n::tr(
        "Трафик анлокера идёт через VPN.\nЕсли возникают ошибки, добавьте анлокер в исключения приложения VPN.",
        "Unlocker traffic is going through VPN.\nIf errors occur, add the unlocker to your VPN app's exclusions.",
    )
}

/// How the card is coloured, and how loud it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Proven working.
    Ok,
    /// Set up, nothing proven yet: waiting for the user's next message.
    Wait,
    /// A refusal was seen and is being dealt with.
    Fixing,
    /// Something only the user can do.
    Action,
    /// Switched off, or nothing to work on.
    Off,
}

/// The one button a card may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Turn everything on.
    EnableAll,
    /// Restart this program elevated.
    Elevate,
    /// Reinstall and restart the service.
    Repair,
    /// Open Google's verification page (`Facts::verify`) in the browser.
    Verify,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Action::EnableAll => crate::i18n::tr("Включить всё", "Enable all"),
            Action::Elevate => crate::i18n::tr(
                "Перезапустить от имени администратора",
                "Restart as administrator",
            ),
            Action::Repair => crate::i18n::tr("Починить", "Repair"),
            Action::Verify => crate::i18n::tr(
                "Пройти верификацию в браузере",
                "Verify in browser",
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headline {
    pub tone: Tone,
    pub title: String,
    pub detail: String,
    pub action: Option<Action>,
}

/// What the relay said it did about the last refusal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answered {
    pub acted: String,
    /// No tunnel of ours carried it: the client went to Google by itself.
    pub bypassed: bool,
}

/// Everything the verdict is made of. Plain values, so a test can build any
/// state the window can be in.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// Windows and elevated (or not Windows, where nothing needs it).
    pub admin: bool,
    /// At least one Antigravity install was found.
    pub installs_found: bool,
    /// The account patch is on everywhere it can be.
    pub patch_on: bool,
    /// The 400 bypass is on: its DNS half, which everything else rides on - the
    /// local proxy lives in the same service, and the loopback door only opens
    /// once the relay answers the gate hosts.
    pub bypass_on: bool,
    pub relay_running: bool,
    pub relay_uses_vpn: bool,
    pub relay_outdated: bool,
    /// Our DNS rules are in. Without them nothing on the machine asks the
    /// service anything, however healthy it is.
    pub rules: bool,
    /// The relay's record is fresh, i.e. it is alive and saying what it does.
    pub relay_reporting: bool,
    /// The newest refusal in a client log (over the same twelve hours as
    /// `answer`): how long ago, and how many lines in the last ten minutes.
    pub refusal: Option<(Duration, usize)>,
    /// The newest model answer in a client log, how long ago.
    pub answer: Option<Duration>,
    /// The relay's answer to that refusal, when it wrote one after it.
    pub answered: Option<Answered>,
    /// The route the relay credited with the last answer, or the one it would
    /// use now.
    pub route: Option<String>,
    /// What keeps the local proxy from listening, as the relay diagnosed it.
    pub proxy_blocked: Option<crate::gate::Blocker>,
    /// What keeps the gate hosts' door on `:443` shut, the same way.
    pub door_blocked: Option<crate::gate::Blocker>,
    /// What keeps the DNS relay off `127.0.0.53:53`. Unlike the other two this
    /// listener cannot be moved - the NRPT rules name an address, not a port -
    /// so naming the holder is the whole of what can be done about it.
    pub dns_blocked: Option<crate::gate::Blocker>,
    /// The relay has run for minutes and nothing on the internet answered it.
    pub cut_off: bool,
    /// Whether this window itself reaches the internet - asked only while the
    /// relay is cut off, and what tells "no internet" from "something blocks
    /// the relay alone".
    pub net_ok: Option<bool>,
    /// The relay's own exe: the file an antivirus exception has to name.
    pub relay_exe: String,
    /// The newest time Google asked for the account to be verified: how long
    /// ago, and the page it gave. `headline` decides whether it still stands.
    pub verify: Option<(Duration, String)>,
    /// The newest 503 "no capacity" in the last ten minutes: how long ago, and
    /// the model it named (empty if none).
    pub overloaded: Option<(Duration, String)>,
    /// The newest 401 in the last ten minutes: how long ago, and how many.
    pub unauthorized: Option<(Duration, usize)>,
}

/// One 401 can be a token refreshed a moment late; a credential Google stopped
/// accepting fails every call, hundreds of times (G11).
const UNAUTH_LINES: usize = 2;

/// How long a verification demand stays on the card with no answer after it.
/// The page carries a one-time token; past this the client has usually asked
/// again and logged a fresh one, and an old link is more likely to fail than
/// help.
const VERIFY_FOR: Duration = Duration::from_secs(30 * 60);

/// About three refused turns (each writes four lines) with no answer in
/// between: past that, "send it again" has been tried and did not help.
const STUCK_LINES: usize = 12;

/// How long a refusal is "happening now" and the card says «Чиним». After it,
/// with no answer since, the card asks for a check instead: nothing is being
/// fixed any more, and nothing has been shown to work either.
const FIXING_FOR: Duration = Duration::from_secs(10 * 60);

/// How far *before* a refusal the relay's note may be stamped and still be an
/// answer to it: the whole-second quantisation both stamps carry, and nothing
/// more. A note stamped earlier is an answer to something else (I58).
const EPISODE_SLACK: u64 = 3;

/// Whether the relay's note answers a refusal stamped at `refusal_at`.
fn answers(episode_at: u64, refusal_at: u64) -> bool {
    episode_at.saturating_add(EPISODE_SLACK) >= refusal_at
}

impl Facts {
    /// Read off a status snapshot and the gate watcher's last view, which is
    /// `gate_age` old: the watcher sends an age measured at its own tick and
    /// then stays quiet while nothing changes, so the front end ages its copy.
    /// Both front ends (window and terminal) call this, so they cannot answer
    /// differently.
    pub fn read(s: &Status, gate: &View, gate_age: Duration) -> Facts {
        let aged = |ago: Duration| ago + gate_age;
        // Newest over twelve hours, so an old refusal still outranks an older
        // answer; counted over the last ten minutes, which is what "it keeps
        // happening" means.
        let refusal = gate
            .refused_long
            .map(|x| (aged(x.ago), gate.seen.map_or(0, |s| s.count)));
        let answer = gate.answered.map(|x| aged(x.ago));
        // The relay's record is only worth anything while the relay runs: a record
        // outlives its writer by up to `STALE_AFTER`, and "обход перехватил" about a
        // dead service is the worst sentence this card could say (I58).
        let relay = gate.relay.as_ref().filter(|_| s.relay_running);
        let answered = refusal.and_then(|(ago, _)| {
            if ago > crate::gate::RECENT {
                return None;
            }
            let refusal_at = crate::gate::now_unix().saturating_sub(ago.as_secs());
            relay
                .and_then(|r| r.last_400.as_ref())
                .filter(|e| answers(e.at, refusal_at))
                .map(|e| Answered {
                    acted: e.acted.clone(),
                    bypassed: e.bypassed,
                })
        });
        // The path of the last answer when the relay saw one recently - and then
        // exactly that, empty included: an answer no tunnel of ours carried went
        // around us, and naming the route we would have used instead would be a
        // claim about traffic that never touched it. Otherwise the route in force.
        let route = relay.and_then(|r| {
            let recent_ok = r.last_ok.as_ref().filter(|ok| {
                crate::gate::now_unix().saturating_sub(ok.at)
                    <= crate::gate::ANSWER_RECENT.as_secs()
            });
            match recent_ok {
                Some(ok) => (!ok.route.is_empty()).then(|| ok.route.clone()),
                None => (!r.route.is_empty()).then(|| r.route.clone()),
            }
        });
        Facts {
            admin: s.admin || !cfg!(target_os = "windows"),
            installs_found: s.installs.iter().any(|r| r.path.is_some()),
            patch_on: s.client_patch.is_on(),
            bypass_on: s.bypass_on(),
            relay_running: s.relay_running,
            relay_uses_vpn: s.relay_running
                && (relay.is_some_and(|r| r.vpn_traffic)
                    || matches!(
                        s.relay_egress,
                        Some(crate::egress::ClientEgress::Tunnel | crate::egress::ClientEgress::Mixed)
                    )),
            relay_outdated: s.relay_outdated,
            // Rules are only owed while the DNS switch is on: a route running alone
            // (own proxy, group, exits) has none by design.
            rules: s.rules || !s.dns.is_on() || !cfg!(target_os = "windows"),
            relay_reporting: relay.is_some(),
            refusal,
            answer,
            answered,
            route,
            proxy_blocked: blocker(relay, "proxy"),
            door_blocked: blocker(relay, "door"),
            dns_blocked: blocker(relay, "dns"),
            cut_off: relay.is_some_and(crate::gate::Report::cut_off),
            net_ok: gate.net_ok,
            relay_exe: relay.map(|r| r.exe.clone()).unwrap_or_default(),
            verify: gate.verify.as_ref().map(|v| (aged(v.ago), v.url.clone())),
            overloaded: gate
                .overloaded
                .as_ref()
                .map(|o| (aged(o.ago), o.model.clone())),
            unauthorized: gate.unauthorized.map(|u| (aged(u.ago), u.count)),
        }
    }
}

fn blocker(relay: Option<&crate::gate::Report>, what: &str) -> Option<crate::gate::Blocker> {
    relay?.blockers.iter().find(|b| b.what == what).cloned()
}

/// A provider's name as it is shown: an acronym stays one, anything else gets
/// one capital.
pub fn provider_name(name: &str) -> String {
    // Keep the built-in provider name as its owner writes it.
    match name {
        "dns-ai.ru" => return "DNS-AI.ru".to_string(),
        _ => {}
    }
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

/// The master switch of the bypass: what it is called and what it does.
pub fn bypass_text() -> (&'static str, &'static str) {
    (
        crate::i18n::tr(
            "Снять ошибку 400 в чате с ИИ",
            "Fix error 400 in AI chat",
        ),
        crate::i18n::tr(
            "Сам находит рабочий путь до серверов Google и переключается, если путь перестал работать — с VPN и без.",
            "Automatically finds a working route to Google servers and switches if a route stops working — with or without VPN.",
        ),
    )
}

/// What a switch is called and what it does, in both front ends.
pub fn switch_text(cap: Cap) -> (&'static str, &'static str) {
    match cap {
        Cap::ClientPatch => (
            crate::i18n::tr(
                "Вход в аккаунт из-под санкций",
                "Account sign-in from restricted regions",
            ),
            crate::i18n::tr(
                "Снимает блокировку входа в Google-аккаунт из санкционного региона.",
                "Lifts the Google account sign-in block from restricted regions.",
            ),
        ),
        Cap::Watchdog => (
            crate::i18n::tr("Автопатч", "Auto-patch"),
            crate::i18n::tr(
                "Сам накладывает патч на найденный Antigravity — сразу после установки и после каждого обновления, которое его стирает.",
                "Automatically patches detected Antigravity — right after installation and after every update that overwrites it.",
            ),
        ),
        Cap::Dns => (
            crate::i18n::tr("Обход через DNS", "DNS bypass"),
            crate::i18n::tr(
                "Служба на этом компьютере отвечает на имена двух серверов Google и держит их разрешающимися через сервисы разблокировки. Без неё обход не работает.",
                "A local service resolves the two Google server hostnames through unblocking DNS providers. Without it, the bypass does not work.",
            ),
        ),
        Cap::LocalProxy => (
            crate::i18n::tr("Локальный прокси", "Local proxy"),
            crate::i18n::tr(
                "Соединения Antigravity с этими двумя серверами идут через посредника внутри вашего компьютера: он выбирает путь, который реально работает, и переключается сам. Содержимое не расшифровывается — посредник только передаёт байты.",
                "Antigravity connections to these two servers go through a local proxy on your computer: it picks a working route and switches automatically. Traffic is not decrypted — it only forwards bytes.",
            ),
        ),
        Cap::GroupProxy => (
            crate::i18n::tr("Прокси из группы", "Group proxy"),
            crate::i18n::tr(
                "Выделенный сервер группы: через него идут только запросы к моделям.",
                "Dedicated group server: only model requests go through it.",
            ),
        ),
        Cap::OwnProxy => (
            crate::i18n::tr("Свой HTTP-прокси", "Own HTTP proxy"),
            crate::i18n::tr(
                "Ваш собственный прокси в разрешённой стране — он всегда пробуется первым. Формат: логин:пароль@адрес:порт — или просто адрес:порт, если пароля нет, например ivan:secret@203.0.113.9:3128. Только HTTP-прокси, SOCKS не подойдёт. Google может не принять прокси из дата-центра даже там.",
                "Your own proxy in an allowed country — always tried first. Format: user:pass@host:port or host:port (e.g. user:secret@203.0.113.9:3128). HTTP proxies only, SOCKS is not supported.",
            ),
        ),
        Cap::DnsRotation => (
            crate::i18n::tr(
                "Ротация между серверами",
                "Server rotation",
            ),
            crate::i18n::tr(
                "Включено: запрос идёт ко всем включённым серверам, ответ сверяется с эталонным резолвером. Выключено: используется только первый включённый в списке, запасных не будет.",
                "On: queries race all enabled servers and answers are verified against a reference resolver. Off: only the first enabled server in the list is used, with no fallback.",
            ),
        ),
    }
}

/// The card for a listener the relay could not bind, by what stopped it.
///
/// Every text ends in something the user can do; the relay retries each minute,
/// so the fixes that need no restart say so.
fn blocked(b: &crate::gate::Blocker, exe: &str) -> Headline {
    let port = b.addr.rsplit(':').next().unwrap_or(&b.addr);
    let effect = match b.what.as_str() {
        "door" => crate::i18n::tr(
            "Antigravity обращается к Google мимо обхода и получает ошибку 400",
            "Antigravity contacts Google directly bypassing the unlocker and gets error 400",
        ),
        "dns" => crate::i18n::tr(
            "подмена адресов не работает и запросы к Google идут медленнее",
            "address substitution is not working and requests to Google are slower",
        ),
        _ => crate::i18n::tr(
            "обход ошибки 400 работает не полностью",
            "error 400 bypass is only partially working",
        ),
    };
    let system_holder = b.by.is_empty() || b.by.eq_ignore_ascii_case("svchost.exe");
    if b.what == "dns" && b.cause == "held" && system_holder {
        return Headline {
            tone: Tone::Action,
            title: match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("Порт {port} занят системной службой"),
                crate::i18n::Lang::En => format!("Port {port} is used by a system service"),
            },
            detail: match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Порт {port} держит системная служба Windows, поэтому {effect}. Обычно это «Общий доступ к подключению к Интернету (ICS)» — его включают Hyper-V, мобильный хот-спот и виртуальные машины. Откройте «Службы», остановите «Общий доступ к подключению к Интернету (ICS)» и поставьте тип запуска «Отключена». Обход займёт порт сам в течение минуты."
                ),
                crate::i18n::Lang::En => format!(
                    "Port {port} is held by a Windows system service, so {effect}. Usually this is Internet Connection Sharing (ICS) — enabled by Hyper-V, mobile hotspot, or virtual machines. Open Services, stop Internet Connection Sharing (ICS), and set its startup type to Disabled. The bypass will claim the port within a minute."
                ),
            },
            action: Some(Action::Repair),
        };
    }
    let (title, detail) = match b.cause.as_str() {
        "held" => {
            let who = if b.by.is_empty() {
                crate::i18n::tr("другая программа", "another program").to_string()
            } else {
                match crate::i18n::current() {
                    crate::i18n::Lang::Ru => format!("программа «{}»", b.by),
                    crate::i18n::Lang::En => format!("program \"{}\"", b.by),
                }
            };
            (
                match crate::i18n::current() {
                    crate::i18n::Lang::Ru => format!("Порт {port} занят другой программой"),
                    crate::i18n::Lang::En => format!("Port {port} is used by another program"),
                },
                match crate::i18n::current() {
                    crate::i18n::Lang::Ru => format!(
                        "Порт {port} на этом компьютере занимает {who}, поэтому {effect}. Закройте её или отключите в ней веб-сервер — обход сам займёт порт в течение минуты. Или нажмите «Починить»."
                    ),
                    crate::i18n::Lang::En => format!(
                        "Port {port} is occupied by {who}, so {effect}. Close it or disable its web server — the bypass will claim the port within a minute, or click \"Repair\"."
                    ),
                },
            )
        }
        "reserved" => (
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("Windows закрыла порт {port}"),
                crate::i18n::Lang::En => format!("Windows reserved port {port}"),
            },
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Порт {port} зарезервирован системой — так делают Hyper-V, WSL и Docker, — поэтому {effect}. Откройте командную строку от имени администратора, выполните «net stop winnat», затем «net start winnat» и нажмите «Починить»."
                ),
                crate::i18n::Lang::En => format!(
                    "Port {port} is reserved by Windows (Hyper-V, WSL, Docker), so {effect}. Run \"net stop winnat\" then \"net start winnat\" in an elevated command prompt, and click \"Repair\"."
                ),
            },
        ),
        "denied" => (
            crate::i18n::tr(
                "Антивирус блокирует обход",
                "Antivirus is blocking the bypass",
            )
            .to_string(),
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Антивирус или файрвол не даёт службе обхода открыть порт {port}, поэтому {effect}. Добавьте в исключения антивируса файл {} — обход заработает сам в течение минуты. Или нажмите «Починить».",
                    exe_or_default(exe)
                ),
                crate::i18n::Lang::En => format!(
                    "Antivirus or firewall prevents the bypass service from opening port {port}, so {effect}. Add {} to your antivirus exclusions or click \"Repair\".",
                    exe_or_default(exe)
                ),
            },
        ),
        _ => (
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("Порт {port} недоступен"),
                crate::i18n::Lang::En => format!("Port {port} is unavailable"),
            },
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Служба обхода не может открыть порт {port} ({}), поэтому {effect}. Нажмите «Починить»; не помогло — {}",
                    b.error,
                    super::report::when_stuck()
                ),
                crate::i18n::Lang::En => format!(
                    "The bypass service cannot open port {port} ({}), so {effect}. Click \"Repair\"; if that doesn't help — {}",
                    b.error,
                    super::report::when_stuck()
                ),
            },
        ),
    };
    Headline {
        tone: Tone::Action,
        title,
        detail,
        action: Some(Action::Repair),
    }
}

/// The relay's exe as it reported it, or where it is installed by default.
fn exe_or_default(exe: &str) -> String {
    if !exe.is_empty() {
        exe.to_string()
    } else if cfg!(target_os = "windows") {
        r"C:\ProgramData\AGUnlocker\ag_dns.exe".to_string()
    } else {
        "~/.local/share/agunlocker/ag_proxy".to_string()
    }
}

/// One blocker as a line of the report: what, where, why.
pub fn blocker_line(b: &crate::gate::Blocker) -> String {
    let what = match b.what.as_str() {
        "door" => crate::i18n::tr(
            "локальные адреса гейт-хостов",
            "local gate host addresses",
        ),
        "dns" => crate::i18n::tr("DNS-релей", "DNS relay"),
        _ => crate::i18n::tr("локальный прокси", "local proxy"),
    };
    let why = match b.cause.as_str() {
        "held" if !b.by.is_empty() => match crate::i18n::current() {
            crate::i18n::Lang::Ru => format!("порт занят программой «{}»", b.by),
            crate::i18n::Lang::En => format!("port held by \"{}\"", b.by),
        },
        "held" => crate::i18n::tr(
            "порт занят другой программой",
            "port held by another program",
        )
        .to_string(),
        "reserved" => crate::i18n::tr(
            "порт зарезервирован Windows (Hyper-V/WSL/Docker)",
            "port reserved by Windows (Hyper-V/WSL/Docker)",
        )
        .to_string(),
        "denied" => crate::i18n::tr(
            "доступ запрещён — антивирус или файрвол",
            "access denied — antivirus or firewall",
        )
        .to_string(),
        _ => crate::i18n::tr(
            "причина не определена",
            "unknown reason",
        )
        .to_string(),
    };
    format!("{what} ({}): {why} — {}", b.addr, b.error)
}

pub fn headline(f: &Facts) -> Headline {
    // Nothing to work on. Said first: every other card assumes Antigravity is
    // installed, and a button that patches nothing is not an action.
    if !f.installs_found && !f.patch_on && !f.bypass_on {
        return Headline {
            tone: Tone::Off,
            title: crate::i18n::tr(
                "Antigravity не найден",
                "Antigravity not found",
            )
            .into(),
            detail: crate::i18n::tr(
                "Установите Antigravity или укажите папку с ним ниже — карандаш рядом с нужной строкой.",
                "Install Antigravity or specify its folder below using the edit icon next to the row.",
            )
            .into(),
            action: None,
        };
    }

    let verify_due = f
        .verify
        .as_ref()
        .filter(|(ago, _)| *ago <= VERIFY_FOR && f.answer.is_none_or(|a| a > *ago));
    if let Some((ago, _)) = verify_due {
        let ago_s = ago_text(*ago);
        return Headline {
            tone: Tone::Action,
            title: crate::i18n::tr(
                "Нужна верификация аккаунта Google",
                "Google account verification required",
            )
            .into(),
            detail: match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Google попросил подтвердить аккаунт — {ago_s}. Antigravity не всегда показывает для этого кнопку. Нажмите кнопку ниже: страница Google откроется в браузере по умолчанию — в нём должен быть выполнен вход в этот же аккаунт. После подтверждения отправьте сообщение в Antigravity ещё раз."
                ),
                crate::i18n::Lang::En => format!(
                    "Google asked to verify your account — {ago_s}. Antigravity doesn't always show a button for this. Click below to open Google's verification page in your default browser (signed into the same account), then send a message in Antigravity again."
                ),
            },
            action: Some(Action::Verify),
        };
    }

    let unanswered = |ago: Duration| f.answer.is_none_or(|a| a > ago);
    let unauthorized = f
        .unauthorized
        .filter(|(ago, n)| *ago <= crate::gate::RECENT && *n >= UNAUTH_LINES && unanswered(*ago));
    if let Some((ago, _)) = unauthorized {
        let ago_s = ago_text(ago);
        return Headline {
            tone: Tone::Action,
            title: crate::i18n::tr(
                "Antigravity нужно перезайти в аккаунт",
                "Antigravity needs to sign in again",
            )
            .into(),
            detail: match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Google отвечает ошибкой 401 — {ago_s}: учётные данные Antigravity перестали совпадать. Выйдите из аккаунта в Antigravity и войдите заново. Обход эту ошибку не исправит."
                ),
                crate::i18n::Lang::En => format!(
                    "Google returned error 401 — {ago_s}: Antigravity credentials no longer match. Sign out in Antigravity and sign back in. The bypass cannot fix this error."
                ),
            },
            action: None,
        };
    }
    let overloaded = f.overloaded.as_ref().filter(|(ago, _)| {
        *ago <= crate::gate::RECENT && unanswered(*ago) && f.refusal.is_none_or(|(r, _)| r > *ago)
    });
    if let Some((ago, model)) = overloaded {
        let ago_s = ago_text(*ago);
        let which = if model.is_empty() {
            String::new()
        } else {
            match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(" для модели «{model}»"),
                crate::i18n::Lang::En => format!(" for model \"{model}\""),
            }
        };
        return Headline {
            tone: Tone::Action,
            title: crate::i18n::tr(
                "Серверы Google перегружены",
                "Google servers are overloaded",
            )
            .into(),
            detail: match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Google отвечает ошибкой 503 — {ago_s}: нет свободных мощностей{which}. Обход тут ни при чём — запрос до Google дошёл. Рекомендуется выбрать в Antigravity другую модель или повторить позже."
                ),
                crate::i18n::Lang::En => format!(
                    "Google returned error 503 — {ago_s}: no available capacity{which}. This is not a bypass issue — the request reached Google. Try another model in Antigravity or retry later."
                ),
            },
            action: None,
        };
    }

    let service_broken = f.bypass_on && (!f.relay_running || f.relay_outdated || !f.rules);
    if !f.admin && (!f.bypass_on || service_broken) {
        return Headline {
            tone: Tone::Action,
            title: crate::i18n::tr(
                "Нужны права администратора",
                "Administrator rights required",
            )
            .into(),
            detail: crate::i18n::tr(
                "Без них обход ошибки 400 не установить и не починить. Разблокировка входа работает и так.",
                "Without them, the error 400 bypass cannot be installed or repaired. Sign-in unlock works without admin rights.",
            )
            .into(),
            action: Some(Action::Elevate),
        };
    }

    if !f.patch_on || !f.bypass_on {
        let what = match (f.patch_on, f.bypass_on) {
            (false, false) => crate::i18n::tr(
                "Разблокировка входа и обход ошибки 400 выключены.",
                "Sign-in unlock and error 400 bypass are turned off.",
            ),
            (false, true) => crate::i18n::tr(
                "Разблокировка входа выключена.",
                "Sign-in unlock is turned off.",
            ),
            _ => crate::i18n::tr(
                "Обход ошибки 400 выключен.",
                "Error 400 bypass is turned off.",
            ),
        };
        let closes = if f.patch_on {
            ""
        } else {
            crate::i18n::tr(
                " Antigravity закроется на пару секунд.",
                " Antigravity will close for a couple of seconds.",
            )
        };
        return Headline {
            tone: Tone::Off,
            title: crate::i18n::tr(
                "Включено не всё",
                "Not everything is enabled",
            )
            .into(),
            detail: format!("{what}{closes}"),
            action: Some(Action::EnableAll),
        };
    }

    if service_broken {
        return Headline {
            tone: Tone::Action,
            title: if !f.relay_running {
                crate::i18n::tr(
                    "Служба обхода не работает",
                    "Bypass service is not running",
                )
                .into()
            } else if f.relay_outdated {
                crate::i18n::tr(
                    "Служба обхода устарела",
                    "Bypass service is outdated",
                )
                .into()
            } else {
                crate::i18n::tr(
                    "Служба обхода работает не полностью",
                    "Bypass service is partially running",
                )
                .into()
            },
            detail: crate::i18n::tr(
                "Без неё ошибка 400 не обходится. Кнопка переустановит и запустит её.",
                "Error 400 cannot be bypassed without it. The button will reinstall and start it.",
            )
            .into(),
            action: Some(Action::Repair),
        };
    }

    if let Some(b) = &f.proxy_blocked {
        return blocked(b, &f.relay_exe);
    }
    if let Some(b) = &f.dns_blocked {
        return blocked(b, &f.relay_exe);
    }
    if f.cut_off {
        match f.net_ok {
            Some(true) => {
                return Headline {
                    tone: Tone::Action,
                    title: crate::i18n::tr(
                        "Антивирус или файрвол не пропускает обход",
                        "Antivirus or firewall is blocking the bypass",
                    )
                    .into(),
                    detail: match crate::i18n::current() {
                        crate::i18n::Lang::Ru => format!(
                            "Служба обхода уже несколько минут не может соединиться ни с одним сервером, хотя у других программ интернет есть. Так бывает, когда её блокирует антивирус или файрвол. Добавьте в исключения антивируса и в разрешённые программы файрвола файл {} и нажмите «Починить».",
                            exe_or_default(&f.relay_exe)
                        ),
                        crate::i18n::Lang::En => format!(
                            "The bypass service hasn't been able to reach any server for minutes, while other apps have internet access. Add {} to your antivirus and firewall exclusions and click \"Repair\".",
                            exe_or_default(&f.relay_exe)
                        ),
                    },
                    action: Some(Action::Repair),
                }
            }
            Some(false) => {
                return Headline {
                    tone: Tone::Off,
                    title: crate::i18n::tr(
                        "Нет подключения к интернету",
                        "No internet connection",
                    )
                    .into(),
                    detail: crate::i18n::tr(
                        "Ни служба обхода, ни анлокер не могут соединиться с серверами в интернете. Проверьте подключение. Если интернет есть — антивирус или файрвол мог заблокировать обе программы: добавьте их в исключения.",
                        "Neither the bypass service nor the unlocker can reach the internet. Check your connection. If internet works, antivirus or firewall may be blocking both.",
                    )
                    .into(),
                    action: None,
                }
            }
            None => {}
        }
    }

    let refused_last = match (f.refusal, f.answer) {
        (Some((r, _)), Some(a)) => r < a,
        (Some(_), None) => true,
        _ => false,
    };
    if refused_last {
        if let Some(b) = &f.door_blocked {
            return blocked(b, &f.relay_exe);
        }
        let (ago, lines) = f.refusal.unwrap_or_default();
        let ago_s = ago_text(ago);
        if ago > FIXING_FOR {
            return Headline {
                tone: Tone::Wait,
                title: crate::i18n::tr("Нужна проверка", "Check needed").into(),
                detail: match crate::i18n::current() {
                    crate::i18n::Lang::Ru => format!(
                        "Последний раз была ошибка 400 — {ago_s}, и после неё модель не отвечала. Напишите что-нибудь в Antigravity: если ошибка повторится, обход её поймает и сам сменит путь."
                    ),
                    crate::i18n::Lang::En => format!(
                        "Last error 400 was {ago_s}, with no model reply since. Send a message in Antigravity: if it happens again, the bypass will catch it and switch routes."
                    ),
                },
                action: None,
            };
        }
        if lines >= STUCK_LINES {
            return Headline {
                tone: Tone::Action,
                title: crate::i18n::tr(
                    "Ошибка 400 повторяется",
                    "Error 400 keeps repeating",
                )
                .into(),
                detail: match crate::i18n::current() {
                    crate::i18n::Lang::Ru => format!(
                        "Последняя — {ago_s}. Обход перебирает пути сам, но ни один пока не сработал. Если у вас включён VPN или прокси, попробуйте выключить его или сменить сервер, и отправьте сообщение ещё раз. Не помогло — {}",
                        super::report::when_stuck()
                    ),
                    crate::i18n::Lang::En => format!(
                        "Last one — {ago_s}. The bypass is trying routes automatically, but none worked yet. If you have a VPN or proxy on, try turning it off or switching servers, then send a message again. Still failing — {}",
                        super::report::when_stuck()
                    ),
                },
                action: None,
            };
        }
        let detail = match &f.answered {
            Some(a) if a.bypassed => match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Ошибка 400 — {ago_s}. Antigravity обратился к Google мимо обхода; через минуту его запросы пойдут через обход. Отправьте сообщение ещё раз — не помогло, перезапустите Antigravity."
                ),
                crate::i18n::Lang::En => format!(
                    "Error 400 — {ago_s}. Antigravity bypassed the unlocker; within a minute its requests will go through the bypass. Send a message again, or restart Antigravity."
                ),
            },
            Some(a) if !a.acted.is_empty() => match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Ошибка 400 — {ago_s}. {}. Отправьте сообщение ещё раз.",
                    capitalise(&a.acted)
                ),
                crate::i18n::Lang::En => format!(
                    "Error 400 — {ago_s}. {}. Send your message again.",
                    capitalise(&a.acted)
                ),
            },
            _ => match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(
                    "Ошибка 400 — {ago_s}. Обход её видит и перестраивается. Отправьте сообщение ещё раз."
                ),
                crate::i18n::Lang::En => format!(
                    "Error 400 — {ago_s}. The bypass detected it and is adapting. Send your message again."
                ),
            },
        };
        return Headline {
            tone: Tone::Fixing,
            title: crate::i18n::tr("Чиним", "Fixing").into(),
            detail,
            action: None,
        };
    }

    if let Some(ago) = f.answer {
        let route = f
            .route
            .as_deref()
            .filter(|r| !r.is_empty())
            .map(|r| match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!(" · путь: {r}"),
                crate::i18n::Lang::En => format!(" · route: {r}"),
            })
            .unwrap_or_default();
        let ago_s = ago_text(ago);
        return Headline {
            tone: Tone::Ok,
            title: crate::i18n::tr("Работает", "Working").into(),
            detail: match crate::i18n::current() {
                crate::i18n::Lang::Ru => format!("Модель ответила {ago_s}{route}."),
                crate::i18n::Lang::En => format!("Model replied {ago_s}{route}."),
            },
            action: None,
        };
    }

    if !f.relay_reporting {
        return Headline {
            tone: Tone::Wait,
            title: crate::i18n::tr(
                "Служба запускается",
                "Service is starting",
            )
            .into(),
            detail: crate::i18n::tr(
                "Это занимает до минуты. Потом напишите что-нибудь в Antigravity.",
                "This takes up to a minute. Then send a message in Antigravity.",
            )
            .into(),
            action: None,
        };
    }

    Headline {
        tone: Tone::Wait,
        title: crate::i18n::tr(
            "Всё включено",
            "Everything is enabled",
        )
        .into(),
        detail: crate::i18n::tr(
            "Напишите что-нибудь в чат Antigravity — здесь появится подтверждение, что модель ответила.",
            "Send something in Antigravity chat — confirmation that the model replied will appear here.",
        )
        .into(),
        action: None,
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// «только что», «22 секунды назад», «3 минуты назад», «2 часа назад».
pub fn ago_text(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 15 {
        return crate::i18n::tr("только что", "just now").to_string();
    }
    if secs < 60 {
        return match crate::i18n::current() {
            crate::i18n::Lang::Ru => format!(
                "{} {} назад",
                secs,
                plural(secs, "секунду", "секунды", "секунд")
            ),
            crate::i18n::Lang::En => format!("{secs}s ago"),
        };
    }
    let mins = secs / 60;
    if mins < 60 {
        return match crate::i18n::current() {
            crate::i18n::Lang::Ru => format!(
                "{} {} назад",
                mins,
                plural(mins, "минуту", "минуты", "минут")
            ),
            crate::i18n::Lang::En => format!("{mins}m ago"),
        };
    }
    let hours = mins / 60;
    match crate::i18n::current() {
        crate::i18n::Lang::Ru => format!("{} {} назад", hours, plural(hours, "час", "часа", "часов")),
        crate::i18n::Lang::En => format!("{hours}h ago"),
    }
}

/// Russian counts in three forms.
pub fn plural(n: u64, one: &'static str, few: &'static str, many: &'static str) -> &'static str {
    if n % 100 / 10 == 1 {
        return many;
    }
    match n % 10 {
        1 => one,
        2..=4 => few,
        _ => many,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn working() -> Facts {
        Facts {
            admin: true,
            installs_found: true,
            patch_on: true,
            bypass_on: true,
            relay_running: true,
            relay_outdated: false,
            rules: true,
            relay_reporting: true,
            ..Facts::default()
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// G50, the report that started this: a refusal, then quiet. Quiet is not
    /// proof - the card must not turn green without a model answer after it.
    #[test]
    fn silence_after_a_refusal_is_not_working() {
        let f = Facts {
            refusal: Some((secs(300), 4)),
            answered: Some(Answered {
                acted: "адреса серверов Google подбираются заново".into(),
                bypassed: false,
            }),
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.tone, Tone::Fixing);
        assert!(
            h.detail.contains("Отправьте сообщение ещё раз"),
            "{}",
            h.detail
        );
    }

    #[test]
    fn an_answer_after_the_refusal_is_working_and_says_by_which_path() {
        let f = Facts {
            refusal: Some((secs(300), 4)),
            answer: Some(secs(60)),
            route: Some("встроенный выход".into()),
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.tone, Tone::Ok);
        assert_eq!(h.title, "Работает");
        assert!(h.detail.contains("1 минуту назад"), "{}", h.detail);
        assert!(h.detail.contains("встроенный выход"), "{}", h.detail);
    }

    /// Found live: an answer, then a refusal, then quiet. Once the refusal is
    /// older than the fixing window the card must not fall back to the answer
    /// before it and say «Работает».
    #[test]
    fn an_old_refusal_after_the_last_answer_asks_for_a_check_not_a_green_card() {
        let f = Facts {
            refusal: Some((secs(13 * 60), 0)),
            answer: Some(secs(14 * 60)),
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.tone, Tone::Wait);
        assert_eq!(h.title, "Нужна проверка");
        // And an answer after that same refusal is working again.
        let f = Facts {
            refusal: Some((secs(13 * 60), 0)),
            answer: Some(secs(60)),
            ..working()
        };
        assert_eq!(headline(&f).tone, Tone::Ok);
    }

    #[test]
    fn a_refusal_after_the_last_answer_is_the_live_problem() {
        let f = Facts {
            refusal: Some((secs(20), 4)),
            answer: Some(secs(600)),
            ..working()
        };
        assert_eq!(headline(&f).tone, Tone::Fixing);
    }

    #[test]
    fn set_up_and_unproven_asks_for_a_message_and_claims_nothing() {
        let h = headline(&working());
        assert_eq!(h.tone, Tone::Wait);
        assert!(!h.detail.contains("работает"), "{}", h.detail);
        assert_eq!(h.action, None);
    }

    #[test]
    fn a_client_that_went_around_us_is_told_so_and_what_to_do() {
        let f = Facts {
            refusal: Some((secs(10), 4)),
            answered: Some(Answered {
                acted: String::new(),
                bypassed: true,
            }),
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.tone, Tone::Fixing);
        assert!(h.detail.contains("мимо обхода"), "{}", h.detail);
        assert!(
            h.detail.contains("перезапустите Antigravity"),
            "{}",
            h.detail
        );
    }

    #[test]
    fn many_refusals_with_no_answer_stop_promising_and_say_what_to_try() {
        let f = Facts {
            refusal: Some((secs(10), STUCK_LINES)),
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.tone, Tone::Action);
        assert_eq!(
            h.detail.contains("Сохранить отчёт"),
            super::super::report::ENABLED,
            "{}",
            h.detail
        );
    }

    #[test]
    fn switched_off_offers_the_one_button_and_warns_when_it_closes_antigravity() {
        let f = Facts {
            patch_on: false,
            bypass_on: false,
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.action, Some(Action::EnableAll));
        assert!(h.detail.contains("закроется"), "{}", h.detail);
        // Only the bypass off: nothing gets closed.
        let f = Facts {
            bypass_on: false,
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.action, Some(Action::EnableAll));
        assert!(!h.detail.contains("закроется"), "{}", h.detail);
    }

    #[test]
    fn without_admin_the_button_is_elevation_but_only_when_there_is_work_for_it() {
        let f = Facts {
            admin: false,
            bypass_on: false,
            ..working()
        };
        assert_eq!(headline(&f).action, Some(Action::Elevate));
        // Everything is installed and running: an unelevated window has nothing
        // to ask for.
        let f = Facts {
            admin: false,
            answer: Some(secs(30)),
            ..working()
        };
        assert_eq!(headline(&f).tone, Tone::Ok);
    }

    #[test]
    fn a_dead_or_old_service_is_repaired_by_one_button() {
        let f = Facts {
            relay_running: false,
            ..working()
        };
        let h = headline(&f);
        assert_eq!((h.tone, h.action), (Tone::Action, Some(Action::Repair)));
        let f = Facts {
            relay_outdated: true,
            ..working()
        };
        assert_eq!(headline(&f).title, "Служба обхода устарела");
        // Running, current, and still useless: nothing asks it anything.
        let f = Facts {
            rules: false,
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.action, Some(Action::Repair));
        assert_eq!(h.title, "Служба обхода работает не полностью");
    }

    #[test]
    fn nothing_installed_is_said_without_a_button() {
        let f = Facts {
            installs_found: false,
            patch_on: false,
            bypass_on: false,
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.tone, Tone::Off);
        assert_eq!(h.action, None);
    }

    #[test]
    fn russian_counts_in_three_forms() {
        let minutes = |n| plural(n, "минуту", "минуты", "минут");
        assert_eq!(minutes(1), "минуту");
        assert_eq!(minutes(2), "минуты");
        assert_eq!(minutes(5), "минут");
        assert_eq!(minutes(11), "минут");
        assert_eq!(minutes(21), "минуту");
        assert_eq!(minutes(22), "минуты");
        assert_eq!(minutes(0), "минут");
    }

    #[test]
    fn an_age_reads_as_a_person_would_say_it() {
        assert_eq!(ago_text(secs(3)), "только что");
        assert_eq!(ago_text(secs(22)), "22 секунды назад");
        assert_eq!(ago_text(secs(61)), "1 минуту назад");
        assert_eq!(ago_text(secs(9 * 60)), "9 минут назад");
        assert_eq!(ago_text(secs(2 * 3600 + 5)), "2 часа назад");
        assert_eq!(ago_text(secs(5 * 3600)), "5 часов назад");
    }

    #[test]
    fn an_acronym_stays_an_acronym_and_everything_else_gets_one_capital() {
        assert_eq!(provider_name("dns-ai.ru"), "DNS-AI.ru");
        assert_eq!(provider_name("свой DNS"), "Свой DNS");
        assert_eq!(provider_name("dns.example"), "DNS.EXAMPLE");
        // Must not panic on a name the pool could grow later.
        assert_eq!(provider_name(""), "");
        assert_eq!(provider_name("1.1.1.1"), "1.1.1.1");
    }

    #[test]
    fn only_a_note_written_after_the_refusal_answers_it() {
        assert!(answers(1_000, 1_000));
        assert!(answers(1_015, 1_000));
        assert!(answers(998, 1_000));
        assert!(!answers(940, 1_000));
        assert!(!answers(0, 1_000));
        assert!(answers(u64::MAX, 1_000));
        assert!(!answers(0, u64::MAX));
    }

    fn blocker(what: &str, cause: &str, by: &str) -> crate::gate::Blocker {
        crate::gate::Blocker {
            what: what.into(),
            addr: if what == "door" {
                "127.65.71.1:443"
            } else {
                "127.0.0.1:53129"
            }
            .into(),
            cause: cause.into(),
            by: by.into(),
            error: "os error 10013".into(),
        }
    }

    /// P53: a proxy the relay cannot bind is said with the fix, even while the
    /// model still answers through what is left of the bypass.
    #[test]
    fn a_blocked_proxy_says_what_to_add_to_the_antivirus() {
        let f = Facts {
            answer: Some(secs(5)),
            proxy_blocked: Some(blocker("proxy", "denied", "")),
            relay_exe: r"C:\ProgramData\AGUnlocker\ag_dns.exe".into(),
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.tone, Tone::Action);
        assert_eq!(h.title, "Антивирус блокирует обход");
        assert!(
            h.detail.contains(r"C:\ProgramData\AGUnlocker\ag_dns.exe"),
            "{}",
            h.detail
        );
        assert!(h.detail.contains("53129"), "{}", h.detail);
        assert_eq!(h.action, Some(Action::Repair));
    }

    /// The door matters when the 400 is happening: then it is the reason, named
    /// with the program holding the port. While answers come, it is not news.
    #[test]
    fn a_shut_door_is_the_reason_for_a_refusal_and_names_who_holds_443() {
        let door = Some(blocker("door", "held", "vmware-hostd.exe"));
        let refused = Facts {
            refusal: Some((secs(20), 4)),
            door_blocked: door.clone(),
            ..working()
        };
        let h = headline(&refused);
        assert_eq!(h.tone, Tone::Action);
        assert_eq!(h.title, "Порт 443 занят другой программой");
        assert!(h.detail.contains("«vmware-hostd.exe»"), "{}", h.detail);
        let answering = Facts {
            answer: Some(secs(5)),
            refusal: Some((secs(60), 4)),
            door_blocked: door,
            ..working()
        };
        assert_eq!(headline(&answering).tone, Tone::Ok);
    }

    #[test]
    fn a_reserved_port_asks_for_winnat_to_be_restarted() {
        let f = Facts {
            refusal: Some((secs(20), 4)),
            door_blocked: Some(blocker("door", "reserved", "")),
            ..working()
        };
        let h = headline(&f);
        assert_eq!(h.title, "Windows закрыла порт 443");
        assert!(h.detail.contains("net stop winnat"), "{}", h.detail);
    }

    /// A relay nothing answers: blocked if this window gets out, offline if it
    /// does not, and no verdict before the window has asked.
    #[test]
    fn a_cut_off_relay_is_told_apart_from_a_machine_with_no_internet() {
        let blocked = Facts {
            cut_off: true,
            net_ok: Some(true),
            ..working()
        };
        let h = headline(&blocked);
        assert_eq!(h.title, "Антивирус или файрвол не пропускает обход");
        assert_eq!(h.action, Some(Action::Repair));
        let offline = Facts {
            cut_off: true,
            net_ok: Some(false),
            ..working()
        };
        assert_eq!(headline(&offline).title, "Нет подключения к интернету");
        let unasked = Facts {
            cut_off: true,
            net_ok: None,
            ..working()
        };
        assert_eq!(headline(&unasked).title, "Всё включено");
    }

    /// Google stopped the account: the card says so above everything, red, with
    /// the one button that helps - even with the bypass switched off, which has
    /// nothing to do with it.
    #[test]
    fn a_verification_demand_tops_the_card_until_an_answer_follows() {
        let url = "https://accounts.google.com/signin/continue?a=1&b=2".to_string();
        let asked = Facts {
            verify: Some((secs(120), url.clone())),
            answer: Some(secs(900)),
            bypass_on: false,
            ..working()
        };
        let h = headline(&asked);
        assert_eq!(h.tone, Tone::Action);
        assert_eq!(h.action, Some(Action::Verify));

        let answered_since = Facts {
            verify: Some((secs(120), url.clone())),
            answer: Some(secs(30)),
            ..working()
        };
        assert_ne!(headline(&answered_since).action, Some(Action::Verify));

        let stale = Facts {
            verify: Some((VERIFY_FOR + secs(1), url)),
            ..working()
        };
        assert_ne!(headline(&stale).action, Some(Action::Verify));
    }

    /// A 503 is Google out of capacity, not the bypass: the card says to pick
    /// another model, and lets go once a model answers or a 400 comes after it.
    #[test]
    fn a_503_asks_for_another_model_until_an_answer_follows() {
        let busy = Facts {
            overloaded: Some((secs(60), "gemini-3.8-flash-high".into())),
            answer: Some(secs(900)),
            ..working()
        };
        let h = headline(&busy);
        assert_eq!(h.title, "Серверы Google перегружены");
        assert!(h.detail.contains("gemini-3.8-flash-high"), "{}", h.detail);
        assert!(h.detail.contains("другую"), "{}", h.detail);

        let answered = Facts {
            overloaded: Some((secs(60), String::new())),
            answer: Some(secs(10)),
            ..working()
        };
        assert_ne!(headline(&answered).title, "Серверы Google перегружены");

        let refused_after = Facts {
            overloaded: Some((secs(300), String::new())),
            refusal: Some((secs(30), 4)),
            ..working()
        };
        assert_ne!(headline(&refused_after).title, "Серверы Google перегружены");
    }

    /// A 401 that keeps coming is a credential Google no longer accepts: the
    /// card asks for a re-login; a single one is a token refreshed late.
    #[test]
    fn repeated_401_asks_to_sign_in_again() {
        let bad = Facts {
            unauthorized: Some((secs(30), 12)),
            ..working()
        };
        let h = headline(&bad);
        assert_eq!(h.title, "Antigravity нужно перезайти в аккаунт");
        assert!(h.detail.contains("Выйдите"), "{}", h.detail);

        let once = Facts {
            unauthorized: Some((secs(30), 1)),
            ..working()
        };
        assert_ne!(headline(&once).title, h.title);

        let answered = Facts {
            unauthorized: Some((secs(30), 12)),
            answer: Some(secs(5)),
            ..working()
        };
        assert_ne!(headline(&answered).title, h.title);
    }
}
