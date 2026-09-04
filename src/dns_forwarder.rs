use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crate::dns;
use crate::dns_client;
use crate::egress;
use crate::ls_log;
use crate::proxy;
use crate::resolvers::{self, Verdict};
use crate::routes;
use crate::upstream;

// A loopback DNS relay, so the answers stay fresh.
//
// Pinning the substituted address into `hosts` works but breaks its own
// contract: xbox-dns answers with **TTL 60**, i.e. it explicitly reserves the
// right to move the address every minute, and a static file holds it forever.
//
// Instead the NRPT rules point at this listener, which relays the query - raw
// bytes, never parsed - to xbox-dns over the ISP link via IP_UNICAST_IF, and
// relays the answer back verbatim. Windows then caches it for exactly the TTL
// the resolver asked for and comes back when it expires, so a rotated address is
// picked up within a minute with no file to go stale. It behaves identically
// with and without a VPN: without one the ISP link is the default path anyway.
//
// Verified before building: the Windows DNS client does send NRPT queries to a
// 127.0.0.0/8 nameserver (a probe rule delivered the question to a listener on
// 127.0.0.53:53).
//
// UDP only, deliberately. Relaying verbatim means a truncated answer would need
// a TCP listener as well, but the routed names answer with a single A record in
// well under 100 bytes, so TC is never set. If that ever changes, Windows falls
// back to the next nameserver in the rule rather than failing outright.

#[cfg(target_os = "macos")]
pub const LISTEN_IP: &str = "127.0.0.1";
#[cfg(not(target_os = "macos"))]
pub const LISTEN_IP: &str = "127.0.0.53";
pub const LISTEN_PORT: u16 = 53;

/// What generation of relay this build ships.
///
/// Separate from the product version on purpose: the relay is installed once,
/// by an administrator, and then keeps running across reboots from
/// `%ProgramData%` - so a user can be running a months-old relay under a fresh
/// unlocker and never be told. The unlocker compares this against what the
/// installed relay wrote and says so.
///
/// **Bump this whenever the relay's own behaviour changes** - the loop, the
/// resolver logic it carries, the warm loop, the watchdog. A pure UI or patcher
/// change does not need it. Never decrease it: the comparison is "older than",
/// and a version that goes backwards asks every user to reinstall.
///
/// 1 = first versioned relay: answer cache + warm loop.
/// 2 = a non-substituted answer can no longer pin the client for its own TTL.
/// 3 = carries the fallback proxy (`proxy.rs`) alongside the DNS relay.
/// 4 = the proxy no longer answers a socket the client has not spoken on.
/// 5 = identity and telemetry hosts are tunnelled, never intercepted.
/// 6 = liveness is re-probed on the warm loop, so a dead address is dropped
///     within seconds instead of being advertised for ten minutes.
/// 7 = a provider choice is only remembered when it actually substituted.
/// 8 = the race log is client-only, so it stops eating its own log budget.
/// 9 = the warm loop gets a generous liveness budget; the client path stays tight.
/// 10 = `enable()` verifies the relay came up instead of trusting the task.
/// 11 = liveness is measured by the TLS handshake, not just the connection.
/// 12 = the fallback route picks its upstream by measured handshake latency.
/// 13 = the byte pump is non-blocking, so it stops adding its own latency.
/// 14-16 = no separate entries were kept for these.
/// 17 = the proxy carries the gate hosts through the cert-free relay route.
/// 18 = the TLS-terminating carrier route is gone with its CA, and the warm loop
///     no longer measures upstreams (there is one relay, nothing to choose).
/// 19 = idle relayed tunnels are closed before they go stale, the relay is
///     benched when it stops carrying, teardown is logged and lines are stamped.
/// 20 = a relay that cuts tunnels at the handshake counts as failing (bytes
///     moved, so "carried nothing" missed it), and the bench backs off.
/// 21 = the relay leg asks for `cloudcode-pa` instead of `daily-`, which costs
///     it a second proxy hop: 2.14 s median down to 0.22 s, and no variance.
/// 22 = the route is checked by a probe on the warm loop instead of by someone's
///     request, and a burst of in-flight failures no longer lengthens the bench.
/// 23 = every child process it shells out to is bounded, so a hung helper can no
///     longer stop it dead.
/// 27 = routes are ordered by measured speed (`routes`), the client's own log is
///     tailed for the region 400 (`ls_log`) and answered by forcing substitution
///     back on and penalising the route it came through, and the direct route
///     fails inside a budget instead of hanging on the OS connect timeout.
pub const RELAY_VERSION: u32 = 27;

/// Written where an unelevated relay can write and an unelevated unlocker can
/// read. Absent means a relay from before versioning, i.e. older than anything.
const VERSION_FILE: &str = "relay.version";

/// Closes the console Windows hands a console subsystem process. Without this
/// the scheduled task leaves an empty black window on screen for as long as the
/// relay lives, which is forever. Everything it has to say goes to the log file
/// anyway, so losing stdout costs nothing.
#[cfg(target_os = "windows")]
pub fn detach_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn FreeConsole() -> i32;
    }
    unsafe {
        FreeConsole();
    }
}

#[cfg(not(target_os = "windows"))]
pub fn detach_console() {}

/// Log prefix for what the answer turned out to be. `substituted` is the only
/// one that means the region gate is actually being defeated for that name;
/// `PASSTHROUGH` shouts because it is the failure the old `ok` used to hide.
fn verdict_tag(v: Verdict) -> &'static str {
    match v {
        Verdict::Substituted => "substituted",
        Verdict::Sibling => "sibling",
        Verdict::Passthrough => "PASSTHROUGH",
        Verdict::Unknown => "ok",
    }
}

/// How long a *detected* interface is trusted. Long on purpose: detection
/// shells out to PowerShell, and an interface that dies is caught by
/// `invalidate_interface()` on the first failed relay, so re-probing on a timer
/// buys nothing and only spawns processes on the user's machine.
const EGRESS_TTL: Duration = Duration::from_secs(30 * 60);
/// How long a *failed* detection is remembered. Short, because it is usually
/// the network not being up yet at logon - but not zero, or a machine with no
/// physical egress at all would spawn a probe per query.
const EGRESS_RETRY: Duration = Duration::from_secs(30);
/// How often the relay re-asks whether a tunnel is carrying the machine.
///
/// Its own clock, and deliberately far shorter than `EGRESS_TTL`: an interface
/// index changes when hardware does, but a VPN is something the user toggles
/// mid-session, and that answer decides whether the relay substitutes at all
/// (G26). Costs one PowerShell spawn per interval and never runs on the query
/// path - a client waits on nothing here. Four minutes rather than fifteen
/// seconds because being late merely means a few minutes of the old, slightly
/// longer route; it breaks nothing.
const VPN_CHECK_EVERY: Duration = Duration::from_secs(4 * 60);
const LOG_LIMIT_BYTES: u64 = 64 * 1024;

/// Interface index, when it was learned, and how long that answer is good for.
static EGRESS_CACHE: Mutex<Option<(u32, Instant, Duration)>> = Mutex::new(None);

/// The log lives under the user profile, not next to the exe: the relay runs
/// unelevated, and the directory an administrator installed it into is not
/// writable for it.
#[cfg(target_os = "windows")]
pub fn log_dir() -> PathBuf {
    PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default()).join("AGUnlocker")
}

/// On macOS, logs live in ~/Library/Logs/agunlocker.
#[cfg(target_os = "macos")]
pub fn log_dir() -> PathBuf {
    let home = if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            format!("/Users/{}", user)
        } else {
            std::env::var("HOME").unwrap_or_default()
        }
    } else {
        std::env::var("HOME").unwrap_or_default()
    };
    PathBuf::from(home).join("Library").join("Logs").join("agunlocker")
}

/// On Linux the per-user state dir follows the XDG base-dir spec
/// (`~/.local/share/agunlocker`), which is also where the own-proxy config and
/// any relay log will live once that layer is ported.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn log_dir() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{}/.local/share", home)
        });
    PathBuf::from(base).join("agunlocker")
}

pub fn log_path() -> PathBuf {
    log_dir().join("forwarder.log")
}

pub fn version_path() -> PathBuf {
    log_dir().join(VERSION_FILE)
}

/// Records which relay generation is in place. Called both by the installer and
/// by the relay itself at startup: the installer's write is what makes the
/// answer correct the moment an upgrade finishes, and the relay's write is what
/// keeps it honest if the exe ever gets there some other way.
pub fn record_version() {
    if let Some(dir) = version_path().parent() {
        fs::create_dir_all(dir).ok();
    }
    fs::write(version_path(), RELAY_VERSION.to_string()).ok();
}

/// The relay generation currently installed. `0` for a relay old enough not to
/// have written one - which is exactly the case worth reporting.
pub fn installed_version() -> u32 {
    parse_version(fs::read_to_string(version_path()).ok().as_deref())
}

/// Anything unreadable counts as the oldest possible relay: the file is written
/// by us and never edited, so a value that will not parse means something else
/// wrote it, and "reinstall" is the right answer to that too.
fn parse_version(raw: Option<&str>) -> u32 {
    raw.and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

/// Local wall-clock `HH:MM:SS` for a log line.
///
/// Local, not UTC: the only reader is a user comparing the log against the moment
/// their editor showed an error, and asking them to do timezone arithmetic on a
/// bug report is how a report becomes useless. `GetLocalTime` rather than a date
/// crate because this is the only place the crate would be used.
#[cfg(target_os = "windows")]
fn stamp() -> String {
    #[repr(C)]
    #[derive(Default)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }
    extern "system" {
        fn GetLocalTime(out: *mut SystemTime);
    }
    let mut t = SystemTime::default();
    unsafe { GetLocalTime(&mut t) };
    format!("{:02}:{:02}:{:02}", t.hour, t.minute, t.second)
}

#[cfg(not(target_os = "windows"))]
fn stamp() -> String {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if !libc::localtime_r(&t, &mut tm).is_null() {
            format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
        } else {
            String::new()
        }
    }
}

/// Best-effort logging: a background process with no console is otherwise
/// impossible to diagnose. Truncated rather than rotated - nothing here is
/// worth keeping across sessions.
///
/// Every line is stamped. Without it a log says what happened but never *when*,
/// so a torn connection cannot be lined up against the error the user saw - which
/// is precisely the question a bug report asks.
fn log(line: &str) {
    let path = log_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).ok();
    }
    if fs::metadata(&path).map_or(false, |m| m.len() > LOG_LIMIT_BYTES) {
        fs::remove_file(&path).ok();
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        writeln!(f, "{} {}", stamp(), line).ok();
    }
}

/// The only way a failed start can be reported: the console is gone by then.
pub fn log_fatal(message: &str) {
    log(&format!("fatal: {}", message));
}

/// The proxy shares the relay's log - it runs in the same process, and one file
/// is what makes a resolve and the connection that followed it readable together.
pub fn log_proxy(message: &str) {
    log(&format!("proxy        {}", message));
}

/// Who answered a race that produced no substitution, and whether a reference
/// was available to judge it. Only logged on that path: it is the one where the
/// interesting question is which provider was missing, and it is rare enough
/// that a line per occurrence is affordable.
pub fn log_race(name: &str, heard: &[&str], had_reference: bool) {
    log(&format!(
        "race         {} heard [{}]{}",
        name,
        heard.join(", "),
        if had_reference { "" } else { " (no reference)" }
    ));
}

fn invalidate_interface() {
    if let Ok(mut c) = EGRESS_CACHE.lock() {
        *c = None;
    }
}

fn isp_interface() -> u32 {
    if let Ok(cache) = EGRESS_CACHE.lock() {
        if let Some((idx, at, good_for)) = *cache {
            if at.elapsed() < good_for {
                return idx;
            }
        }
    }
    // 0 means "use the routing table" - the right degradation when there is no
    // physical egress to name, but a poor thing to remember for long: at logon
    // the network is often simply not up yet, and caching the miss would leave
    // half an hour of unsubstituted answers.
    let (idx, good_for) = match egress::detect() {
        Some(eg) => (eg.if_index, EGRESS_TTL),
        None => (0, EGRESS_RETRY),
    };
    if let Ok(mut cache) = EGRESS_CACHE.lock() {
        *cache = Some((idx, Instant::now(), good_for));
    }
    idx
}

/// Relays one query and reports which provider answered and whether that answer
/// was actually substituted.
///
/// The choice is no longer a constant. A provider can drop a name from its
/// list without any error - the query still resolves, just to the genuine
/// Google address - so every provider is asked at once and compared against a
/// reference resolver that substitutes nothing. See `resolvers`.
fn relay(query: &[u8]) -> Option<(Vec<u8>, &'static str, resolvers::Verdict)> {
    let if_index = isp_interface();
    match resolvers::resolve_best(query, if_index) {
        Some(hit) => Some(hit),
        None => {
            // Nobody answered: the interface may have gone away under us, so
            // the next query re-detects instead of retrying a dead one.
            invalidate_interface();
            None
        }
    }
}

/// How often the routed names are re-resolved in the background.
///
/// Half the substituted TTL, so an entry is always well inside the window the
/// answer cache will serve it from and a client query never finds it expired.
/// Cheap: four names, one upstream query each, once every quarter minute.
const WARM_EVERY: Duration = Duration::from_secs(15);

/// Keeps a vetted answer ready for every routed name, forever.
///
/// The relay has about a second to answer before Windows asks the next
/// nameserver in the NRPT rule - which is a provider's own resolver, handing
/// out addresses that nothing has checked for liveness. A cold resolution does
/// not reliably fit in that second (race, then a liveness probe, and a provider
/// that goes quiet costs the whole timeout), and it does not have to: doing the
/// work on a timer instead means the client's query is answered from memory.
/// How often the relay route is checked while it is being used. Rare, because a
/// working route needs no supervision and the probe is a real request.
const PROBE_HEALTHY_EVERY: Duration = Duration::from_secs(2 * 60);

fn warm_forever() {
    let mut since_probe = PROBE_HEALTHY_EVERY;
    let mut since_upstream = PROBE_HEALTHY_EVERY;
    let mut since_exits = PROBE_HEALTHY_EVERY;
    let mut since_direct = PROBE_HEALTHY_EVERY;
    let mut since_vpn = VPN_CHECK_EVERY;
    loop {
        // First, because everything below depends on it: when a tunnel carries
        // the client the relay stops substituting and answers as the tunnel's
        // own resolver would. The rules cannot be removed from here - the task
        // runs at `RunLevel Limited` and NRPT needs an administrator - so the
        // relay changes what it *answers* instead, which needs no privilege and
        // reaches the same place. Menu 1 removes the rules outright on the next
        // elevated run (`dns::refresh_pinned_hosts`).
        if since_vpn >= VPN_CHECK_EVERY {
            // Not "is a tunnel up" but "is the client in it" - a tunnel the
            // client is excluded from must not turn substitution off, or the
            // rules menu 1 wrote resolve to genuine Google and the gate answers
            // 400 with the whole layer nominally installed (G29). This is also
            // where the excluded case repairs itself: the rules are already in
            // place, and within one interval of Antigravity starting the relay
            // sees its sockets on the ISP link and starts substituting again.
            let eg = egress::detect();
            let (stand_down, client) = egress::vpn_verdict(eg.as_ref());
            // Compared against the raw verdict, not `vpn_is_active()`: while
            // substitution is forced on (region 400 through the tunnel) the
            // latter reads false whatever the tunnel does, and the line below
            // would repeat every pass.
            if stand_down != resolvers::tunnel_carries_client() {
                log(
                    &match (stand_down, eg.is_some_and(|e| e.vpn_active), client) {
                        (true, _, _) => {
                            "VPN поднят — подмена выключена, DNS идёт как настроил VPN".to_string()
                        }
                        (false, true, egress::ClientEgress::Physical) => {
                            "VPN поднят, но трафик Antigravity идёт мимо него — подмена включена"
                                .to_string()
                        }
                        (false, true, _) => {
                            "VPN поднят, маршрут Antigravity неизвестен — подмена включена"
                                .to_string()
                        }
                        (false, false, _) => "VPN отключён — подмена снова включена".to_string(),
                    },
                );
            }
            resolvers::set_vpn_active(stand_down);
            since_vpn = Duration::ZERO;
        }
        let egress = isp_interface();
        // The client's own log is the one place the region 400 is written down
        // (ls_log). Every pass, because a refusal costs the user every request
        // until it is answered, and reading a file's tail costs nothing. Before
        // the warm, not after: answering a refusal expires the cached answers
        // for the gate names, and the warm below is what refills them - in the
        // other order the cache sat empty for a whole pass and a client query
        // in that window paid for a cold race (I23).
        let refusals = ls_log::poll();
        if !refusals.is_empty() {
            answer_region_400(&refusals);
        }
        resolvers::warm(dns::core_namespaces(), egress);
        // Checked on our own time rather than with someone's request. While the
        // route is benched this runs every pass, because the cost being paid then
        // is every client sitting on the slow route for as long as it takes to
        // notice the relay came back - which was twenty minutes after a flap that
        // lasted seconds.
        if proxy::relay_is_benched() || since_probe >= PROBE_HEALTHY_EVERY {
            proxy::probe_relay();
            since_probe = Duration::ZERO;
        }
        // The user's own proxy is checked the same way and for the same reason:
        // it must be stood down before a request meets it, and picked back up
        // the moment it works again - which is what they asked for when they
        // gave us one.
        if upstream::OWN.health.is_benched() || since_upstream >= PROBE_HEALTHY_EVERY {
            upstream::probe_health();
            since_upstream = Duration::ZERO;
        }
        // The built-in exits are checked on the same clock in *both* states, and
        // that is the one place this deviates from the rule above. Probing a
        // benched route every pass is right when the alternative is the seven-second
        // DNS route; these sit above the relay, so what a slower revival costs is a
        // route that is merely quicker - and the cost of the other choice is a
        // connection every fifteen seconds, from every machine running this tool,
        // to somebody's free proxy. Being a considerate guest is what keeps the
        // route working at all.
        if since_exits >= PROBE_HEALTHY_EVERY {
            proxy::probe_exits();
            since_exits = Duration::ZERO;
        }
        // The direct route is timed on the same clock as the others, so the
        // route table compares like with like. Not more often while penalised:
        // a region penalty is a clock, and no measurement shortens it.
        if since_direct >= PROBE_HEALTHY_EVERY {
            proxy::probe_direct(egress);
            since_direct = Duration::ZERO;
        }
        routes::refresh_leader(|k| proxy::route_usable(k, ROUTE_PROBE_HOST));
        thread::sleep(WARM_EVERY);
        since_probe += WARM_EVERY;
        since_upstream += WARM_EVERY;
        since_exits += WARM_EVERY;
        since_direct += WARM_EVERY;
        since_vpn += WARM_EVERY;
    }
}

/// The name the route table is refreshed against: the gate host the IDE uses.
const ROUTE_PROBE_HOST: &str = "daily-cloudcode-pa.googleapis.com";

/// A region 400 is attributed to the route that opened a gate tunnel within
/// this long before it was seen. Longer than the client's pool idle (90 s), so
/// a refusal on a pooled connection still finds the route it rode on.
const ATTRIBUTION_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Does what a region 400 in the client's log calls for.
///
/// Three things, each aimed at a different way the gate can have been met:
/// - the relay was standing down for a tunnel the client is in, and the tunnel
///   exits somewhere blocked -> substitution is forced back on for a while, so
///   the client is sent to a provider's proxy through the tunnel (D13 revised
///   once more: the tunnel decides *until it is measured wrong*);
/// - the relay was substituting, so the address it handed out led to the gate
///   anyway -> every remembered choice and answer for the gate names is
///   dropped, and the next warm pass races the providers from scratch;
/// - a proxy route carried the refusal -> that route goes to the back of the
///   route table for a while, so the client's retry takes another one.
///
/// Anything in flight stays in flight: nothing here touches an open tunnel, and
/// the client's next connection is what takes the new route.
fn answer_region_400(refusals: &[(std::path::PathBuf, usize)]) {
    let total: usize = refusals.iter().map(|(_, n)| n).sum();
    for (path, n) in refusals {
        log_proxy(&format!(
            "region-400 x{} в {} — Antigravity упёрся в гейт",
            n,
            path.file_name()
                .map_or_else(String::new, |f| f.to_string_lossy().into_owned())
        ));
    }
    if resolvers::vpn_is_active() {
        resolvers::force_substitution(resolvers::FORCE_SUBSTITUTE_FOR);
        log(&format!(
            "VPN-выход не снимает гейт — подмена включена принудительно на {} мин",
            resolvers::FORCE_SUBSTITUTE_FOR.as_secs() / 60
        ));
    } else {
        resolvers::forget_names(dns::core_namespaces());
        log("кэш выбора провайдера сброшен — гейт-имена опрашиваются заново");
    }
    // One penalty per episode. The refusal is attributed to the route that most
    // recently opened a gate tunnel, and that is only right for the *first*
    // refusal: the client keeps retrying on the pooled connection it already
    // has - which stays on the penalised route (I35) - while its next tunnel
    // opens on whichever route now comes first. Read naively, every retry would
    // then penalise the route that replaced the bad one, and within a minute
    // all of them were benched by the mechanism meant to switch between them.
    if let Some((kind, ago)) = routes::last_used() {
        let in_episode = LAST_PENALTY
            .lock()
            .ok()
            .and_then(|g| *g)
            .is_some_and(|at| at.elapsed() < PENALTY_EPISODE);
        if ago < ATTRIBUTION_WINDOW && !routes::is_penalised(kind) && !in_episode {
            routes::penalise(kind);
            if let Ok(mut g) = LAST_PENALTY.lock() {
                *g = Some(Instant::now());
            }
            log_proxy(&format!(
                "маршрут «{}» нёс region-400 ({} шт.) — отложен на {} мин",
                kind.label(),
                total,
                routes::REGION_PENALTY.as_secs() / 60
            ));
        }
    }
}

/// When a route was last penalised for a refusal. While the episode lasts,
/// further refusals penalise nobody: they are the client's retries on the
/// connection it still holds to the route already benched.
static LAST_PENALTY: Mutex<Option<Instant>> = Mutex::new(None);
/// Longer than the client's pool idle (Go's 90 s), so the old connection is
/// gone before a refusal can be attributed again.
const PENALTY_EPISODE: Duration = Duration::from_secs(3 * 60);

/// How long the proxy listener is given to appear before the route is treated as
/// absent. Covers `proxy::bind_listener`'s own retries (15 s) with room to spare.
const PROXY_START_BUDGET: Duration = Duration::from_secs(30);

/// Runs until killed. Never returns `Ok` - the only way out is a bind failure,
/// which is worth reporting because it means something else holds the address.
pub fn run() -> Result<(), String> {
    let sock = UdpSocket::bind((LISTEN_IP, LISTEN_PORT))
        .map_err(|e| format!("не удалось занять {}:{} — {}", LISTEN_IP, LISTEN_PORT, e))?;
    log(&format!("start: {}:{}", LISTEN_IP, LISTEN_PORT));
    // Detect once up front. Otherwise the first query pays for a cold probe,
    // which is long enough that Windows gives up on us and falls back to the
    // direct resolvers - and then caches that unsubstituted answer for its full
    // TTL, so one slow startup is felt for minutes.
    log(&format!("egress: if{}", isp_interface()));
    record_version();
    thread::spawn(warm_forever);
    // The proxy variable is user-wide and must never outlive the listener it
    // names, so the watchdog takes it off when the listener is dead for a while
    // (G20). This is the other half: the listener is up, so the route is back.
    // Off the startup path - it is a PowerShell call - and never in front of a
    // proxy the user set themselves.
    //
    // "Is up", not "is coming up": this used to run the moment the relay started,
    // which is a promise about a socket that had not been bound yet. When the bind
    // then failed - the port is inside Windows' dynamic range, so it can be taken
    // (G31) - the variable was restored anyway and the watchdog took it back off
    // ninety seconds later, every logon, and everything proxy-aware on the machine
    // spent that window with no network.
    #[cfg(target_os = "windows")]
    thread::spawn(|| {
        if !proxy::wait_for_listener(PROXY_START_BUDGET) {
            log_proxy("HTTPS_PROXY не выставлена: локальный прокси не поднялся");
            return;
        }
        match crate::endpoint::ensure_proxy_env(&proxy::proxy_url()) {
            Ok(crate::endpoint::Outcome::Applied) => {
                log_proxy("HTTPS_PROXY снова указывает на локальный прокси")
            }
            Ok(crate::endpoint::Outcome::AlreadySet) => {}
            Err(e) => log_proxy(&format!("HTTPS_PROXY не восстановлена: {}", e)),
        }
    });

    // The fallback route lives in this process because it needs the same two
    // things the relay already has: the ISP interface, and the resolver pool
    // that knows which provider is substituting right now. It only ever carries
    // traffic that is actually pointed at it, so starting it here costs a
    // listening socket and nothing else.
    let egress = isp_interface();
    thread::spawn(move || {
        if let Err(e) = proxy::run(egress) {
            log_proxy(&format!("not started: {}", e));
        }
    });

    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Anything shorter than a header is not a query worth relaying.
        if n < 12 {
            continue;
        }
        let query = buf[..n].to_vec();
        let out = match sock.try_clone() {
            Ok(s) => s,
            Err(_) => continue,
        };
        // One thread per query: the volume is a handful per minute, and a slow
        // upstream must not stall the queries behind it.
        thread::spawn(move || {
            let name = dns_client::question_name(&query).unwrap_or_else(|| "?".to_string());
            match relay(&query) {
                Some((reply, provider, verdict)) => {
                    out.send_to(&reply, from).ok();
                    // The verdict is the part worth logging: "ok" used to mean
                    // only that bytes came back, which is precisely what it
                    // still said while the answers had stopped being
                    // substituted.
                    log(&format!(
                        "{:<12} {} [{}]",
                        verdict_tag(verdict),
                        name,
                        provider
                    ));
                }
                None => log(&format!("fail         {}", name)),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Everything the version check does hangs off this: a relay that predates
    /// versioning leaves no file, and it must read as older than this build
    /// rather than as "no relay" or as a parse error nobody handles.
    #[test]
    fn an_unreadable_version_is_the_oldest_one() {
        assert_eq!(parse_version(None), 0);
        assert_eq!(parse_version(Some("")), 0);
        assert_eq!(parse_version(Some("не число")), 0);
        assert_eq!(parse_version(Some(" 7 \r\n")), 7);
        assert!(parse_version(None) < RELAY_VERSION);
    }

    /// The warm loop only exists to beat the ~1 s Windows waits before asking
    /// the next NRPT nameserver, so it has to refresh well inside the window the
    /// answer cache serves from.
    #[test]
    fn warming_runs_more_often_than_an_answer_goes_stale() {
        assert!(WARM_EVERY < resolvers::ANSWER_TTL);
    }

    #[test]
    fn the_listener_address_is_loopback() {
        let ip: Ipv4Addr = LISTEN_IP.parse().expect("valid address");
        assert!(ip.is_loopback());
        // Not .1: something else on the machine may already own it.
        assert_ne!(ip, Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn a_detected_interface_is_cached_and_droppable() {
        invalidate_interface();
        assert!(EGRESS_CACHE.lock().unwrap().is_none());
        if let Ok(mut c) = EGRESS_CACHE.lock() {
            *c = Some((17, Instant::now(), EGRESS_TTL));
        }
        // Served from the cache: no detection runs, so no process is spawned.
        assert_eq!(isp_interface(), 17);
        invalidate_interface();
        assert!(EGRESS_CACHE.lock().unwrap().is_none());
    }

    /// An expired entry must not be served - that is what makes the short retry
    /// after a failed detection actually retry.
    #[test]
    fn an_expired_entry_is_not_served() {
        invalidate_interface();
        if let Ok(mut c) = EGRESS_CACHE.lock() {
            // Learned long ago, and only ever good for a moment.
            *c = Some((17, Instant::now() - Duration::from_secs(60), EGRESS_RETRY));
        }
        let stale = EGRESS_CACHE
            .lock()
            .unwrap()
            .map(|(_, at, good_for)| at.elapsed() >= good_for);
        assert_eq!(stale, Some(true));
        invalidate_interface();
    }

    /// A failed detection has to be forgotten quickly: at logon it usually just
    /// means the network is not up yet.
    #[test]
    fn a_failed_detection_is_remembered_only_briefly() {
        assert!(EGRESS_RETRY < EGRESS_TTL);
        assert!(EGRESS_RETRY <= Duration::from_secs(60));
    }

    /// Relays a real query end to end through the running upstream, and prints
    /// the verdict for every routed name.
    ///
    /// Needs a live network and the VPN OFF: through a tunnel every provider
    /// sees a foreign client and substitutes nothing, so every verdict comes
    /// back `Passthrough` and the run says nothing about the providers.
    ///
    /// The verdict is the assertion that matters now. The old version only
    /// checked that bytes came back - which stayed true through the whole
    /// outage that motivated `resolvers`, because an unsubstituted answer is
    /// still a perfectly well-formed answer.
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn relays_a_real_query() {
        let id: u16 = 0x4242;
        let mut substituted = Vec::new();

        for name in [
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "antigravity-unleash.goog",
        ] {
            let mut query = vec![];
            query.extend_from_slice(&id.to_be_bytes());
            query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            for label in name.split('.') {
                query.push(label.len() as u8);
                query.extend_from_slice(label.as_bytes());
            }
            query.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);

            let (reply, provider, verdict) = relay(&query).expect("a provider answered");
            assert_eq!(&reply[0..2], &id.to_be_bytes(), "id must be echoed");
            assert_eq!(
                dns_client::question_name(&reply).as_deref(),
                Some(name),
                "the reply must answer the question we asked"
            );
            assert!(
                u16::from_be_bytes([reply[6], reply[7]]) > 0,
                "{} came back with no answer",
                name
            );
            println!(
                "{:<38} {:?} via {:<12} {:?}",
                name,
                verdict,
                provider,
                dns_client::answer_addrs(&reply)
            );
            if verdict == Verdict::Substituted {
                substituted.push(name);
            }
        }

        // Not an assertion on any single name: which names a provider proxies
        // is theirs to change, and this test exists to report that, not to fail
        // on it. But if nothing at all is substituted, either the VPN is up or
        // every provider has dropped the whole list - both worth failing on.
        assert!(
            !substituted.is_empty(),
            "no routed name is substituted by any provider - VPN up, or the \
             providers dropped every name"
        );
        println!("substituted: {:?}", substituted);
    }
}
