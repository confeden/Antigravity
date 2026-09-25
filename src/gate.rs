//! What the bypass is doing about the region 400, written where the window can
//! read it — and the window's own live watch of the client's log.
//!
//! The watch that *acts* lives in the relay (`ls_log::poll` →
//! `dns_forwarder::answer_region_400`) and has to: that is the process holding
//! the route table, the resolver cache and the tunnel verdict. The window is a
//! different process, and until now its only view of any of it was
//! `forwarder.log` — a file written for a person to read, not for a parser
//! (P29). So the relay leaves one small record beside that log: what it is doing
//! now, and what it did about the last refusal.
//!
//! Two halves of one answer, and the split is deliberate:
//!
//! * **the symptom** — `ls_log::newest_refusal`, read by the window itself, so
//!   "Antigravity is hitting the gate right now" is visible whether or not
//!   anything of ours is running. That is exactly the case where the user most
//!   needs to be told something (the bypass is off, or the relay died).
//! * **the answer** — this record, written by the side that knows. The window
//!   never infers "it was intercepted" from a switch being on; it says so only
//!   when the relay wrote down that it did something.
//!
//! Best-effort in both directions. A missing, stale or unparsable record means
//! the window says nothing about the answer, never that there was none.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FILE_NAME: &str = "gate.json";

/// A record older than this is not being refreshed by anybody.
///
/// Sized against the **pass**, not against `WARM_EVERY`: a pass is 15 s of sleep
/// plus its work, and that work opens with a PowerShell VPN check every four
/// minutes and runs probes with budgets of seconds each. Ten sleeps' worth of
/// slack, because the cost of being too tight is the window calling a live relay
/// dead, and the cost of being too loose is a dead one described as alive for a
/// couple of minutes - and the second claim is not the one the window rests
/// anything on: whether the service is running is `Status::relay_running`,
/// measured, and this record is only the *answer* half (I58).
pub const STALE_AFTER: Duration = Duration::from_secs(150);

/// The relay's side of the story.
///
/// Unix seconds rather than a formatted stamp: the only question ever asked of
/// these is "how long ago", the two processes share a clock, and neither has to
/// agree with the other about how to print one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    /// When the relay last wrote this.
    pub at: u64,
    /// The route the table currently puts first, by `routes::Kind::label()`.
    /// Empty until the first probe lands.
    pub route: String,
    /// Until when substitution is forced on because of a refusal. 0 = not
    /// forced, which is the ordinary state.
    pub forced_until: u64,
    /// Whether the DNS layer is standing down for a tunnel carrying the client.
    /// Always false since D25 - the bypass carries the gate hosts on every
    /// network - and kept so an older window reading a newer record still parses.
    pub stood_down: bool,
    /// The last refusal episode and what was done about it.
    pub last_400: Option<Episode>,
    /// The last model answer the relay saw in a client log, and the route it
    /// credited with it.
    pub last_ok: Option<Proof>,
    /// Whether gate hosts are answered with the loopback listener's addresses
    /// (`loopback`), i.e. whether every gate connection on the machine is ours
    /// to route, env variable or not.
    pub loopback: bool,
    /// Whether a VPN holds the default route, and where its exit is (a country
    /// code, empty until measured).
    pub tunnel: bool,
    pub vpn_exit: String,
    /// The route table, best first, for the report the window copies out.
    pub routes: Vec<crate::routes::Row>,
    /// The relay generation that wrote this.
    pub version: u32,
    /// What keeps a listener of the relay from coming up (P53, `portcheck`).
    /// Empty when both bound. Written the moment a bind fails or succeeds,
    /// not at the next warm pass: the user is looking at the window then.
    pub blockers: Vec<Blocker>,
    /// Unix time something on the internet last answered the relay (a resolver,
    /// a DoH node, a route probe). 0 = nothing yet.
    pub reached_at: u64,
    /// When this relay process started. With `reached_at` it tells a relay that
    /// is cut off from one that has only just started (`cut_off`).
    pub started_at: u64,
    /// The relay's own exe - the file an antivirus exception has to name.
    pub exe: String,
}

/// Something on this machine that keeps part of the bypass from running, as the
/// relay diagnosed it (`portcheck::diagnose`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Blocker {
    /// `door` (the gate hosts' listeners on `:443`) or `proxy` (the local proxy).
    pub what: String,
    /// The address that could not be bound.
    pub addr: String,
    /// `held`, `reserved`, `denied` or `other` (`portcheck::Cause::code`).
    pub cause: String,
    /// The program listening there, when `held` and its name could be read.
    pub by: String,
    /// The OS's own words, for the report.
    pub error: String,
}

/// How long a relay may run without anything on the internet answering it
/// before the window calls it cut off and asks whether *it* can reach anything.
/// Past two of the route probes' two-minute rounds, and past any DNS the
/// machine asked in between - a relay that works hears back every few seconds.
pub const CUT_OFF_AFTER: Duration = Duration::from_secs(4 * 60);

/// A model answer, as the relay saw it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Proof {
    /// When the relay noticed it.
    pub at: u64,
    /// The route credited with it, by label. Empty when no gate tunnel of ours
    /// was open around it - the client reached Google some other way.
    pub route: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Episode {
    /// When the relay *noticed*, which is up to one warm pass after the client
    /// logged it.
    pub at: u64,
    pub count: u32,
    /// What was done about it, in the words the window shows. Written by the
    /// side that knows, so the window never has to guess from a switch.
    pub acted: String,
    /// The route the refusal was pinned on, by label; empty when none of ours
    /// was open around it.
    pub route: String,
    /// No gate tunnel of ours carried it: the client dialled Google itself, so
    /// nothing the route table does can help until its connections come to us.
    pub bypassed: bool,
}

impl Report {
    /// How long ago this was written. A record stamped in the future — a clock
    /// moved between the two processes — reads as brand new rather than as an
    /// error; the alternative is calling a live relay dead.
    pub fn age(&self) -> Duration {
        Duration::from_secs(now_unix().saturating_sub(self.at))
    }

    pub fn is_stale(&self) -> bool {
        self.age() > STALE_AFTER
    }

    /// The relay has run for `CUT_OFF_AFTER` and nothing outside this machine
    /// has answered it for as long. Only a warm-looping relay of gen 32 or
    /// later publishes `reached_at`: an older one, or the Linux proxy (which
    /// writes this file only to record a blocker), is never called cut off.
    pub fn cut_off(&self) -> bool {
        if self.started_at == 0 || self.version < 32 {
            return false;
        }
        let now = now_unix();
        let limit = CUT_OFF_AFTER.as_secs();
        now.saturating_sub(self.started_at) >= limit
            && now.saturating_sub(self.reached_at.max(self.started_at)) >= limit
    }

    /// How much of the forced-substitution window is left. Only ever set with
    /// the loopback door down (D25's fallback, `resolvers::force_substitution`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn forced_left(&self) -> Option<Duration> {
        self.forced_until
            .checked_sub(now_unix())
            .filter(|left| *left > 0)
            .map(Duration::from_secs)
    }

    /// Everything the window draws, `at` excepted.
    ///
    /// `at` moves every warm pass and changes nothing on screen, so comparing it
    /// would wake the UI every fifteen seconds to redraw the same words.
    /// The route table rows are left out on purpose: their ages move every
    /// pass, and nothing on screen shows them - only the copied report does, and
    /// that reads the file fresh when the button is pressed.
    fn same_state_as(&self, other: &Report) -> bool {
        self.route == other.route
            && self.forced_until == other.forced_until
            && self.stood_down == other.stood_down
            && self.last_400 == other.last_400
            && self.last_ok == other.last_ok
            && self.loopback == other.loopback
            && self.tunnel == other.tunnel
            && self.vpn_exit == other.vpn_exit
            && self.blockers == other.blockers
            && self.reached_at == other.reached_at
            && self.started_at == other.started_at
            && self.exe == other.exe
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn path() -> Option<PathBuf> {
    let dir = crate::dns_forwarder::log_dir();
    if dir.as_os_str().is_empty() {
        return None;
    }
    Some(dir.join(FILE_NAME))
}

pub fn read() -> Option<Report> {
    let raw = std::fs::read_to_string(path()?).ok()?;
    serde_json::from_str(&raw).ok()
}

// ---------------------------------------------------------------------------
// The relay's side
// ---------------------------------------------------------------------------

/// This process's copy, so a partial update never has to read the file back to
/// keep the fields it is not changing.
static CURRENT: Mutex<Option<Report>> = Mutex::new(None);

fn update(change: impl FnOnce(&mut Report)) {
    let snapshot = {
        let Ok(mut guard) = CURRENT.lock() else {
            return;
        };
        let report = guard.get_or_insert_with(Report::default);
        change(report);
        report.at = now_unix();
        if report.started_at == 0 {
            // `CURRENT` starts empty in every process, so the first write is
            // this relay's start.
            report.started_at = report.at;
        }
        report.clone()
    };
    // Outside the lock. Nothing here calls back into this module, but a file
    // write held under a lock the warm pass wants is the shape I50 is about,
    // and keeping it out costs nothing.
    let Some(path) = path() else { return };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let Ok(json) = serde_json::to_string(&snapshot) else {
        return;
    };
    // Temp then rename, the pattern `patch_binary::write_atomic` already sets.
    // `fs::write` truncates first, and the window reads this file every three
    // seconds: a read landing inside that window gets an empty file, fails to
    // parse, and is indistinguishable from "the relay is not reporting" - so a
    // one-in-a-hundred-thousand read would put a wrong sentence on screen. A
    // rename is atomic on both platforms and costs nothing at this size.
    // One temp name per write: the warm pass and a listener thread
    // (`set_blocker`) can both be here at once, and two writers sharing one temp
    // file could rename the other's half-written copy into place.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{seq}.tmp"));
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, json).is_ok() && std::fs::rename(&tmp, &path).is_err() {
        std::fs::remove_file(&tmp).ok();
    }
}

/// What the relay is doing now, as one warm pass sees it.
pub struct Now<'a> {
    pub route: Option<&'a str>,
    pub forced_for: Option<Duration>,
    pub stood_down: bool,
    pub loopback: bool,
    pub tunnel: bool,
    pub vpn_exit: &'a str,
    pub routes: Vec<crate::routes::Row>,
}

/// Called once per warm pass with what the relay is doing now.
pub fn publish(now: Now<'_>) {
    update(|r| {
        if let Some(route) = now.route {
            r.route = route.to_string();
        }
        r.forced_until = now.forced_for.map_or(0, |left| now_unix() + left.as_secs());
        r.stood_down = now.stood_down;
        r.loopback = now.loopback;
        r.tunnel = now.tunnel;
        r.vpn_exit = now.vpn_exit.to_string();
        r.routes = now.routes;
        r.version = crate::dns_forwarder::RELAY_VERSION;
        r.reached_at = crate::net::last_reached();
        if r.exe.is_empty() {
            r.exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
        }
    });
}

/// Writes the record the moment the relay starts, before anything it does has
/// had time to succeed or fail.
///
/// The window decides whether the relay is alive from this file's age: the
/// watchdog is a separate process of the same image name, so the task list
/// cannot tell the two apart (P54). Without a write at start there would be a
/// window after every install where a perfectly live relay has published
/// nothing yet and would read as dead.
pub fn note_started() {
    update(|_| {});
}

/// Records what keeps `what` (`dns`, `door` or `proxy`) from binding, or clears
/// it.
/// Written through at once rather than at the next warm pass.
pub fn set_blocker(what: &str, blocker: Option<Blocker>) {
    update(|r| {
        r.blockers.retain(|b| b.what != what);
        r.blockers.extend(blocker);
        // The exception the window may have to ask for names this file, and a
        // bind fails before the first warm pass would have written it.
        if r.exe.is_empty() {
            r.exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
        }
    });
}

/// Called when a refusal has been answered, with what was done about it.
pub fn record_episode(count: u32, acted: String, route: Option<&str>) {
    update(|r| {
        r.last_400 = Some(Episode {
            at: now_unix(),
            count,
            acted,
            route: route.unwrap_or_default().to_string(),
            bypassed: route.is_none(),
        })
    });
}

/// Called when a model answer shows up in a client log.
pub fn record_answer(route: Option<&str>) {
    update(|r| {
        r.last_ok = Some(Proof {
            at: now_unix(),
            route: route.unwrap_or_default().to_string(),
        })
    });
}

// ---------------------------------------------------------------------------
// The window's side
// ---------------------------------------------------------------------------

/// How far back a refusal still counts as "right now" on screen. Long enough to
/// still be there when a user hits the gate, swears, and goes looking for this
/// window; short enough that it is about this session rather than this morning.
pub const RECENT: Duration = Duration::from_secs(10 * 60);

/// How far back a model answer still counts as proof that the bypass works.
/// Longer than `RECENT`: a working setup is quiet between messages, and a user
/// who opens the window after lunch should still see that it worked this
/// morning - on the same network, which is what the relay's context reset
/// (`routes::set_context`) is for when it is not.
pub const ANSWER_RECENT: Duration = Duration::from_secs(12 * 60 * 60);

/// The whole of what the watcher knows.
#[derive(Debug, Clone, Default)]
pub struct View {
    /// The client's own log. `ago` is measured at the moment this was taken —
    /// the window adds its own elapsed time on top rather than being sent a
    /// fresh one every tick.
    pub seen: Option<crate::ls_log::Sighting>,
    /// The newest model answer in the client's log, the same way.
    pub answered: Option<crate::ls_log::Sighting>,
    /// The newest refusal over the same horizon as `answered`. `seen` stops at
    /// `RECENT`, and without this a refusal eleven minutes old that came *after*
    /// the last answer disappeared, and the answer before it turned the card
    /// green again - a claim about a route that was last seen failing.
    pub refused_long: Option<crate::ls_log::Sighting>,
    /// Google asking the account to verify itself, with the page to do it on.
    pub verify: Option<crate::ls_log::Verification>,
    /// The relay's record, or `None` when there is none or it has gone stale.
    pub relay: Option<Report>,
    /// Whether this window reaches the internet, asked only while the relay is
    /// cut off: the difference between "no internet" and "something on this
    /// machine blocks the relay alone" (P53). `None` = not asked.
    pub net_ok: Option<bool>,
}

/// Watcher → window.
pub enum Signal {
    Gate(View),
    /// "Ask the system again where the client's traffic leaves." Sent rather
    /// than measured here on purpose: `ops` owns that measurement, and the row
    /// it colours must not be able to disagree with the decision the DNS layer
    /// made from the same call.
    MeasureVpn,
}

/// How often the two files are looked at. Both reads are a `metadata` and a
/// bounded tail; the expensive measurement is rate-limited separately below.
const TICK: Duration = Duration::from_secs(3);

/// A refusal this new is one the user is living through right now, and worth
/// re-measuring the tunnel for at once — "is Antigravity inside your VPN" is
/// the first question a fresh 400 raises.
const FRESH: Duration = Duration::from_secs(90);

/// Floors and ceiling for the VPN measurement, which spawns PowerShell and is
/// therefore never put on a plain timer.
///
/// What gates it is the client's own log growing: the question is where
/// *Antigravity's* traffic leaves, which means nothing while Antigravity is not
/// running — and a language server that is running writes as it serves. So an
/// idle machine costs one measurement every `GAP_IDLE`, a working one at most
/// one every `GAP_BUSY`, and a fresh refusal jumps the queue.
const GAP_AFTER_400: Duration = Duration::from_secs(15);
const GAP_BUSY: Duration = Duration::from_secs(45);
const GAP_IDLE: Duration = Duration::from_secs(5 * 60);

/// How often the list of log files is rebuilt. Antigravity can be installed,
/// started or updated while this window is open, and each of those changes the
/// list — but none of them happens on a three-second scale.
const RELIST_EVERY: Duration = Duration::from_secs(60);

/// How often the window re-asks whether it reaches the internet, while the
/// relay stays cut off.
const NET_PROBE_EVERY: Duration = Duration::from_secs(2 * 60);

/// How long the relay must look cut off, to this window, before it asks.
const CUT_OFF_CONFIRM: Duration = Duration::from_secs(60);

/// Whether this process can open a connection to the internet at all: the
/// HTTPS port of three public resolvers, Yandex's first because it answers from
/// inside Russia whatever else is filtered. Plain TCP, no data - the question is
/// only whether a socket of *this* program gets out.
fn reaches_internet() -> bool {
    const TARGETS: [[u8; 4]; 3] = [[77, 88, 8, 8], [8, 8, 8, 8], [1, 1, 1, 1]];
    TARGETS.iter().any(|ip| {
        std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from((*ip, 443)),
            Duration::from_secs(3),
        )
        .is_ok()
    })
}

pub fn spawn_watch(tx: Sender<Signal>, wake: Box<dyn Fn() + Send>) {
    std::thread::Builder::new()
        .name("gate".to_string())
        .spawn(move || watch(tx, wake))
        .ok();
}

fn watch(tx: Sender<Signal>, wake: Box<dyn Fn() + Send>) {
    let mut shown = View::default();
    // The file list is walked, not watched: `%APPDATA%` and then the IDE's
    // per-launch `logs` folders. Once a minute, never on the tick.
    let mut logs = crate::ls_log::candidate_logs();
    let mut listed = Instant::now();
    let mut bytes = crate::ls_log::bytes_of(&logs);
    // The last real scan and when it was taken, so an age can be carried
    // forward without reading the file again.
    let mut found: Option<(crate::ls_log::Sighting, Instant)> = None;
    let mut answered: Option<(crate::ls_log::Sighting, Instant)> = None;
    let mut refused_long: Option<(crate::ls_log::Sighting, Instant)> = None;
    let mut verify: Option<(crate::ls_log::Verification, Instant)> = None;
    // The first tick scans whatever is already there: a user who hits the gate
    // and *then* opens this window is the case this whole path exists for.
    let mut scan = true;
    // `ops` takes a VPN measurement on its first snapshot, so the clock starts
    // now rather than at zero.
    let mut measured = Instant::now();
    // This window's own reach, taken while the relay looks cut off, and since
    // when it has looked so.
    let mut net_ok: Option<(bool, Instant)> = None;
    let mut cut_since: Option<Instant> = None;

    loop {
        std::thread::sleep(TICK);

        if listed.elapsed() >= RELIST_EVERY {
            logs = crate::ls_log::candidate_logs();
            listed = Instant::now();
        }
        // A log that has not grown cannot have gained a refusal, so the tail is
        // only read when it has. Idle, this whole tick is one `metadata` per
        // file; the alternative was scanning a quarter-megabyte of glog every
        // three seconds for the lifetime of the window.
        let grew = {
            let now = crate::ls_log::bytes_of(&logs);
            let grew = now != bytes;
            bytes = now;
            grew
        };
        if grew || scan {
            scan = false;
            // A scan that finds nothing does not disprove what the last one
            // found. The tail read is bounded (`HISTORY_TAIL`), so a client
            // writing hard can push a refusal that is still inside `RECENT` out
            // of the bytes we look at - and flipping from "поймана" to "не
            // встречалась" on that is a positive claim about the part of the
            // file nobody read. Only time retires a sighting, below.
            let h = crate::ls_log::history(&logs, RECENT, ANSWER_RECENT);
            let at = Instant::now();
            found = h.refused_recent.map(|s| (s, at)).or(found);
            answered = h.answered.map(|s| (s, at)).or(answered);
            refused_long = h.refused.map(|s| (s, at)).or(refused_long);
            verify = h.verify.map(|v| (v, at)).or(verify);
        }

        let view = View {
            // Carried forward rather than re-read. `count` is as of the last
            // scan, which is exact whenever anything is happening — a client
            // that is hitting the gate is a client writing to its log — and at
            // worst counts one that has just aged out while it sits silent.
            seen: found.and_then(|(s, at)| {
                let ago = s.ago + at.elapsed();
                (ago <= RECENT).then_some(crate::ls_log::Sighting { ago, ..s })
            }),
            answered: answered.and_then(|(s, at)| {
                let ago = s.ago + at.elapsed();
                (ago <= ANSWER_RECENT).then_some(crate::ls_log::Sighting { ago, ..s })
            }),
            refused_long: refused_long.and_then(|(s, at)| {
                let ago = s.ago + at.elapsed();
                (ago <= ANSWER_RECENT).then_some(crate::ls_log::Sighting { ago, ..s })
            }),
            verify: verify.as_ref().and_then(|(v, at)| {
                let ago = v.ago + at.elapsed();
                (ago <= ANSWER_RECENT).then(|| crate::ls_log::Verification {
                    ago,
                    url: v.url.clone(),
                })
            }),
            relay: read().filter(|r| !r.is_stale()),
            net_ok: None,
        };
        let mut view = view;
        if view.relay.as_ref().is_some_and(Report::cut_off) {
            // A minute of it first: a machine back from sleep reads as cut off
            // until the relay's first answer lands a few seconds later, and a
            // card about the antivirus for that would be a false alarm.
            let since = *cut_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= CUT_OFF_CONFIRM
                && net_ok.is_none_or(|(_, at)| at.elapsed() >= NET_PROBE_EVERY)
            {
                net_ok = Some((reaches_internet(), Instant::now()));
            }
            view.net_ok = net_ok.map(|(ok, _)| ok);
        } else {
            cut_since = None;
            net_ok = None;
        }
        let worth = worth_sending(&view, &shown);
        let fresh = view.seen.is_some_and(|s| s.ago <= FRESH);

        let gap = if worth && fresh {
            GAP_AFTER_400
        } else if grew {
            GAP_BUSY
        } else {
            GAP_IDLE
        };
        if measured.elapsed() >= gap {
            measured = Instant::now();
            if tx.send(Signal::MeasureVpn).is_err() {
                return;
            }
            wake();
        }

        if worth {
            shown = view.clone();
            if tx.send(Signal::Gate(view)).is_err() {
                return;
            }
            wake();
        }
    }
}

/// Whether the window is looking at something other than what it is showing.
///
/// `ago` grows by a tick every tick, so comparing it outright would wake the UI
/// three times a minute for ever. What matters is a refusal *newer* than the one
/// on screen, or a different number of them — the window ages its own copy in
/// between.
fn worth_sending(fresh: &View, shown: &View) -> bool {
    let relay_changed = match (&fresh.relay, &shown.relay) {
        (Some(a), Some(b)) => !a.same_state_as(b),
        (None, None) => false,
        _ => true,
    };
    if relay_changed || fresh.net_ok != shown.net_ok {
        return true;
    }
    let newer = |a: Option<crate::ls_log::Sighting>, b: Option<crate::ls_log::Sighting>| match (a, b) {
        (Some(a), Some(b)) => a.count != b.count || a.ago < b.ago,
        (a, b) => a.is_some() != b.is_some(),
    };
    let verify_changed = match (&fresh.verify, &shown.verify) {
        (Some(a), Some(b)) => a.url != b.url || a.ago < b.ago,
        (a, b) => a.is_some() != b.is_some(),
    };
    newer(fresh.seen, shown.seen)
        || newer(fresh.answered, shown.answered)
        || newer(fresh.refused_long, shown.refused_long)
        || verify_changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ls_log::Sighting;

    fn seen(ago: u64, count: usize) -> Option<Sighting> {
        Some(Sighting {
            ago: Duration::from_secs(ago),
            count,
        })
    }

    /// The tick must not wake the window just because time passed: the only
    /// news is a newer refusal, a different count, or one appearing/expiring.
    #[test]
    fn only_a_change_is_worth_waking_the_window_for() {
        let shown = View {
            seen: seen(120, 2),
            answered: None,
            refused_long: None,
            verify: None,
            relay: None,
            net_ok: None,
        };
        let older = View {
            seen: seen(123, 2),
            ..shown.clone()
        };
        assert!(
            !worth_sending(&older, &shown),
            "the same refusal, three seconds on"
        );
        let newer = View {
            seen: seen(4, 3),
            ..shown.clone()
        };
        assert!(worth_sending(&newer, &shown));
        let link = |ago: u64, url: &str| {
            Some(crate::ls_log::Verification {
                ago: Duration::from_secs(ago),
                url: url.to_string(),
            })
        };
        let asked = View {
            verify: link(10, "https://accounts.google.com/a"),
            ..shown.clone()
        };
        assert!(worth_sending(&asked, &shown), "a verification demand appeared");
        let aged = View {
            verify: link(13, "https://accounts.google.com/a"),
            ..shown.clone()
        };
        assert!(!worth_sending(&aged, &asked), "the same demand, three seconds on");
        let again = View {
            verify: link(2, "https://accounts.google.com/b"),
            ..shown.clone()
        };
        assert!(worth_sending(&again, &asked), "a fresh link");
        let expired = View {
            seen: None,
            ..shown.clone()
        };
        assert!(worth_sending(&expired, &shown));
        assert!(worth_sending(&shown, &expired));
        // A model answer appearing is news too - it is what turns the card green.
        let proved = View {
            answered: seen(5, 1),
            ..shown.clone()
        };
        assert!(worth_sending(&proved, &shown));
        assert!(!worth_sending(
            &View {
                answered: seen(8, 1),
                ..proved.clone()
            },
            &proved
        ));
    }

    /// `at` moves every warm pass and draws nothing, so it must not count as a
    /// change; everything the window prints must.
    #[test]
    fn the_relays_record_counts_as_changed_only_where_it_shows() {
        let base = Report {
            at: 1_000,
            route: "напрямую".into(),
            ..Report::default()
        };
        let later = Report {
            at: 1_015,
            ..base.clone()
        };
        assert!(base.same_state_as(&later));
        let rerouted = Report {
            route: "релей".into(),
            ..base.clone()
        };
        assert!(!base.same_state_as(&rerouted));
        let answered = Report {
            last_400: Some(Episode {
                at: 1_010,
                count: 1,
                acted: "маршрут отложен".into(),
                ..Episode::default()
            }),
            ..base.clone()
        };
        assert!(!base.same_state_as(&answered));

        let shown = View {
            seen: None,
            answered: None,
            refused_long: None,
            verify: None,
            relay: Some(base),
            net_ok: None,
        };
        assert!(!worth_sending(
            &View {
                relay: Some(later),
                ..shown.clone()
            },
            &shown
        ));
        assert!(worth_sending(
            &View {
                relay: Some(answered),
                ..shown.clone()
            },
            &shown
        ));
        // A relay that stopped writing is news: the answer half is gone.
        assert!(worth_sending(
            &View {
                relay: None,
                ..shown.clone()
            },
            &shown
        ));
    }

    /// A record nobody has refreshed for over a minute is not a running relay.
    #[test]
    fn a_record_goes_stale_and_a_future_one_does_not() {
        let fresh = Report {
            at: now_unix(),
            ..Report::default()
        };
        assert!(!fresh.is_stale());
        let old = Report {
            at: now_unix() - STALE_AFTER.as_secs() - 1,
            ..Report::default()
        };
        assert!(old.is_stale());
        // A clock that moved must not be read as a dead relay.
        let ahead = Report {
            at: now_unix() + 30,
            ..Report::default()
        };
        assert!(!ahead.is_stale());
        assert_eq!(ahead.age(), Duration::ZERO);
    }

    #[test]
    fn the_forced_window_counts_down_and_then_stops() {
        let forced = Report {
            forced_until: now_unix() + 600,
            ..Report::default()
        };
        assert!(forced.forced_left().is_some_and(|d| d.as_secs() > 590));
        let over = Report {
            forced_until: now_unix() - 1,
            ..Report::default()
        };
        assert_eq!(over.forced_left(), None);
        assert_eq!(Report::default().forced_left(), None);
    }

    /// A relay nothing answers is cut off only once it has run long enough to
    /// have heard back, and only if it is new enough to say when it did.
    #[test]
    fn a_relay_is_cut_off_only_after_minutes_of_silence() {
        let now = now_unix();
        let long = CUT_OFF_AFTER.as_secs() + 10;
        let r = Report {
            version: 32,
            started_at: now - long,
            reached_at: 0,
            ..Report::default()
        };
        assert!(r.cut_off());
        assert!(!Report { reached_at: now - 5, ..r.clone() }.cut_off());
        assert!(!Report { started_at: now - 30, ..r.clone() }.cut_off());
        assert!(!Report { version: 31, ..r.clone() }.cut_off());
        assert!(!Report { started_at: 0, ..r }.cut_off());
    }
}
