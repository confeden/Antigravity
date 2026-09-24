//! The route table: every way a gate host can be reached, what each was last
//! measured at, what each has *proved*, and the order the proxy should try them
//! in.
//!
//! Why a table and not a ladder. The proxy used to try its routes in a fixed
//! order - own proxy, built-in exit, relay, direct - and the order was a guess
//! about speed that the measurements then contradicted: the direct tunnel to a
//! substituted address answered in 0.28 s while the relay it sat *below* took
//! 0.40-0.80 s (kb/rivals.md Fact 3). A DNS race is not a speed measurement and
//! neither is a list, so every route is timed on the warm loop with the same
//! request.
//!
//! Speed is not the question that matters, though, and since 2.14.0_1 it is
//! only the tie-break. A probe cannot see the region gate - the refusal arrives
//! inside the client's own TLS and an unauthenticated call is answered 401 from
//! every exit alike (kb/dns.md) - so the fastest route can be the one Google
//! refuses, every time. What *can* see the gate is the client's own log: a
//! model answer writes `streamGenerateContent … ResponseID:` and a refusal
//! writes `User location is not supported` (`ls_log`). Each is attributed to the
//! route that carried it, and the order is:
//!
//! 1. the user's own proxy, whenever it is usable - they typed it in;
//! 2. routes that carried a model answer since their last refusal, fastest
//!    first - proof beats speed;
//! 3. the rest by measured speed, then unmeasured in the default order;
//! 4. routes that carried a refusal, last, for a penalty that grows each time
//!    the same route is refused again without a success in between.
//!
//! What the table has learned is about *this network*: a route refused from
//! behind one VPN may be exactly right without it. The relay hands the table a
//! fingerprint of the network (`set_context`), and a new one wipes the evidence
//! while keeping the timings.
//!
//! A route that carried a refusal also has its open gate tunnels closed at once
//! (D26). Every request on them is refused anyway, and a client that keeps its
//! pooled connection would otherwise go on being refused for another minute and
//! a half after the table has already switched - which is exactly what "send
//! the message again" ran into.

use std::cell::RefCell;
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The routes a gate host can take, as the proxy knows them. `Exits` is the
/// whole built-in pool: which exit inside it answers is that module's business,
/// and the table measures the pool as one route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Own,
    Exits,
    Relay,
    /// A tunnel to the address the DNS layer substituted, pinned to the ISP link
    /// while a VPN holds the default route (N25).
    Direct,
    /// Genuine Google through the user's own VPN. Only offered while a tunnel
    /// holds the default route and its exit is not in a blocked region.
    Vpn,
}

pub const ALL: [Kind; 5] = [Kind::Own, Kind::Exits, Kind::Relay, Kind::Direct, Kind::Vpn];
const N: usize = ALL.len();

impl Kind {
    fn index(self) -> usize {
        match self {
            Kind::Own => 0,
            Kind::Exits => 1,
            Kind::Relay => 2,
            Kind::Direct => 3,
            Kind::Vpn => 4,
        }
    }

    /// How the route is named in the log and in the window. Never an address
    /// (I46).
    pub fn label(self) -> &'static str {
        match self {
            Kind::Own => "свой прокси",
            Kind::Exits => "встроенный выход",
            Kind::Relay => "резервный релей",
            Kind::Direct => "напрямую",
            Kind::Vpn => "через ваш VPN",
        }
    }
}

/// The order before anything has been measured. Direct first because that is
/// what the last round of measurements found fastest; the user's VPN next,
/// because a tunnel that lifts the gate is the path they chose; the relay last
/// because it is the one route somebody else can revoke.
///
/// A build without a DNS layer (Linux) has no substituted address for the direct
/// tunnel to reach, so there it goes to the back regardless; see `order_with`.
const DEFAULT_ORDER: [Kind; N] = [Kind::Own, Kind::Direct, Kind::Vpn, Kind::Exits, Kind::Relay];

/// A measurement older than this says nothing about the route now. Probes run
/// every two minutes; three misses in a row and the route is unmeasured again.
const SAMPLE_TTL: Duration = Duration::from_secs(15 * 60);

/// How much faster a challenger must measure to take the lead, in percent.
/// Twenty: the measured spread between two probes of one healthy route is
/// under that, and swapping routes for a difference nobody would notice costs a
/// cold connection to a proxy that was idle.
const SWITCH_MARGIN_PCT: u64 = 20;

/// How long a route that carried a region 400 stays at the back of the line,
/// the first time. Long enough that the client's pooled connections to it have
/// expired and a retry actually takes another route; short enough that a proxy
/// whose exit rotated back into a usable region is not written off.
pub const REGION_PENALTY: Duration = Duration::from_secs(10 * 60);

/// The bench a route gets the *first* time, before anything says the gate is
/// refusing the road rather than the request.
///
/// Short on purpose. A refusal is pinned on whichever tunnel was open around
/// its timestamp (`attribute`), and a client that fans several gate connections
/// out at once makes that an educated guess. Benching on the first one is still
/// right - it is what switches the route inside the two-second watch, which is
/// what the user feels - but a wrong guess should cost two minutes, not ten.
/// Anything that is really being refused is refused again immediately and moves
/// on to the steps below.
const FIRST_PENALTY: Duration = Duration::from_secs(2 * 60);

/// …and each time it is refused again with no model answer in between. A route
/// that keeps being refused on this network is not going to start working in
/// ten minutes, and handing it the next request every ten minutes was one
/// failed message per cycle for the user (the reason proof exists at all).
const PENALTY_STEPS: [Duration; 4] = [
    FIRST_PENALTY,
    REGION_PENALTY,
    Duration::from_secs(60 * 60),
    Duration::from_secs(6 * 60 * 60),
];

/// How long a model answer keeps the route that carried it safe from a bench.
///
/// A field report (2026-09-20, `2.15.0_2`) showed the cost of not having this:
/// the built-in exit carried a model answer at 14:35:16 and was benched for ten
/// minutes by a refusal at 14:35:18 - three times over six minutes, and every
/// route the bench pushed that user onto carried nothing, so the table came
/// back to the same exit half a minute later. A route that delivered an answer
/// two seconds ago is demonstrably not the thing being refused: the refusal
/// belongs to a request the backend turned down whatever the road, or to one of
/// the connections the client made without us. Its tunnels are still cut, which
/// is the half that makes the retry take a fresh connection; the bench is not.
///
/// Ninety seconds: shorter than the shortest bench, and comfortably wider than
/// the answer-to-refusal gaps the field reports show (2-12 s).
const PROOF_PROTECTS_FOR: Duration = Duration::from_secs(90);

/// How long a model answer keeps a route in the proven tier. A working route is
/// re-proved by every answer it carries, so this only matters for a machine
/// that sat idle - and after half a day the network it proved itself on is
/// likely not the one it is on now.
const PROOF_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// A refusal or an answer is attributed to a tunnel that was open within this
/// much of the log line's stamp: whole-second stamps, and a log flushed a
/// moment after the response.
const ATTRIBUTION_SLACK: Duration = Duration::from_secs(3);

/// Closed tunnels are kept this long for attribution. An event older than this
/// is not attributed at all (`dns_forwarder::answer_log`).
pub const TUNNEL_MEMORY: Duration = Duration::from_secs(10 * 60);
/// A cap on remembered closed tunnels, generous enough that a burst of short
/// connections cannot push out one that is still inside `TUNNEL_MEMORY` and
/// matters for attribution. Open tunnels are never dropped.
const MAX_TUNNEL_RECORDS: usize = 512;

/// How long a route that failed to even *open* a tunnel for a live connection
/// sits behind the others. Short: this is a connect failure, not the gate - a
/// pinned direct route behind a kill-switch VPN, an exit that stopped answering
/// - and it only has to keep the next connections from waiting out the same
/// budget until the next probe says something.
const STUMBLE_FOR: Duration = Duration::from_secs(60);

/// …and how long one that failed its *probe* does.
///
/// Longer than `PROBE_HEALTHY_EVERY`, deliberately: a probe failure that wore
/// off before the next probe would leave the route a candidate again with
/// nothing new known about it, which is what a field report showed - «напрямую»
/// failed its handshake every two and a half minutes for an hour and a half and
/// was still picked as the gate route, because a failed probe only cleared the
/// measurement and an unmeasured route is a candidate. This keeps a route that
/// cannot answer a probe out of the way until one succeeds, and no longer: the
/// first successful probe `record`s a sample, and the stumble expires on its
/// own.
const PROBE_STUMBLE_FOR: Duration = Duration::from_secs(3 * 60);

#[derive(Clone, Copy)]
struct Sample {
    latency: Duration,
    at: Instant,
}

/// Everything the table knows, behind one lock: consulted on the path of every
/// gate connection, so the lock is taken once and released immediately.
struct Table {
    samples: [Option<Sample>; N],
    penalised: [Option<Instant>; N],
    /// When each route last carried a model answer.
    ok_at: [Option<Instant>; N],
    /// When each route last carried a refusal that counted *as evidence*
    /// against it - one that was neither protected by a live answer (D32) nor
    /// by a fresh one (D31). This is what `proven` reads.
    ///
    /// Split from `refused_at` because the two answer different questions and
    /// sharing one field made a protected route lose its place anyway: `blame`
    /// declined to bench or cut it and then stamped this, `proven` went false,
    /// and the route dropped out of tier 0 into whatever its measurement said.
    /// A field report (2026-09-21) shows the result - the leader flapping
    /// between the route that was streaming an answer and the next one every
    /// fifteen seconds, so half the client's new connections went to a road
    /// nothing had proved (G76).
    bad_at: [Option<Instant>; N],
    /// When each route last carried a refusal at all, protected or not, for the
    /// window's table. Never evidence.
    refused_at: [Option<Instant>; N],
    /// Refusal episodes and model answers pinned on each route since the relay
    /// started or the network changed. Only the report reads them: "this route
    /// answered twenty times and was refused thirty" is the one line that says
    /// whether a route half-works, which no single timestamp can.
    ok_count: [u32; N],
    bad_count: [u32; N],
    /// Refusals in a row with no answer in between, which sets the next penalty.
    streak: [u8; N],
    /// Until when a route that failed to open for a live connection sits last.
    stumbled: [Option<Instant>; N],
    /// The route the last `refresh_leader` put first, for the hysteresis.
    leader: Option<Kind>,
    /// The route that most recently opened a gate tunnel, and when.
    last_used: Option<(Kind, Instant)>,
    /// The network the evidence was gathered on (`set_context`).
    context: u64,
}

static TABLE: Mutex<Table> = Mutex::new(Table {
    samples: [None; N],
    penalised: [None; N],
    ok_at: [None; N],
    bad_at: [None; N],
    refused_at: [None; N],
    ok_count: [0; N],
    bad_count: [0; N],
    streak: [0; N],
    stumbled: [None; N],
    leader: None,
    last_used: None,
    context: 0,
});

/// Records one measurement of a route. Blended with the previous fresh one, so
/// a single slow probe does not by itself hand the lead to somebody else.
pub fn record(kind: Kind, latency: Duration) {
    crate::net::note_reached();
    let Ok(mut t) = TABLE.lock() else {
        return;
    };
    let now = Instant::now();
    let blended = match t.samples[kind.index()] {
        Some(prev) if now.duration_since(prev.at) < SAMPLE_TTL => (prev.latency + latency) / 2,
        _ => latency,
    };
    t.samples[kind.index()] = Some(Sample {
        latency: blended,
        at: now,
    });
    // Every caller of this is a probe or a health check that just completed a
    // real request over the route, which settles the one question a stumble
    // asks - whether it opens. Without this a route that failed one probe would
    // stay at the back for the rest of `PROBE_STUMBLE_FOR` after the next probe
    // had already succeeded.
    t.stumbled[kind.index()] = None;
}

/// Forgets what was measured: the route failed its probe, so whatever it was
/// timed at last time is not what a request would meet now.
///
/// On its own this does not say the route is *bad* - it says nothing is known
/// about it. For a probe that actually ran and failed, use `probe_failed`.
pub fn record_failure(kind: Kind) {
    if let Ok(mut t) = TABLE.lock() {
        t.samples[kind.index()] = None;
    }
}

/// A probe ran against `kind` and it did not answer: forget the measurement and
/// keep it out of the running until a probe succeeds (`PROBE_STUMBLE_FOR`).
///
/// Not for a probe that was never applicable - a VPN row with no tunnel up is
/// unmeasured, not failing - only for one that tried and got nothing.
pub fn probe_failed(kind: Kind) {
    record_failure(kind);
    stumble_for(kind, PROBE_STUMBLE_FOR);
}

/// The route's last fresh measurement, if it has one.
#[cfg_attr(not(test), allow(dead_code))]
pub fn latency(kind: Kind) -> Option<Duration> {
    let t = TABLE.lock().ok()?;
    fresh(&t.samples, kind)
}

fn fresh(samples: &[Option<Sample>; N], kind: Kind) -> Option<Duration> {
    samples[kind.index()]
        .filter(|s| s.at.elapsed() < SAMPLE_TTL)
        .map(|s| s.latency)
}

/// Whether `kind` is serving a region bench. Only the ordering inside this
/// module consults it now - a bench moves a route to the back, it does not take
/// it out of the table (`proxy::route_usable`).
#[cfg_attr(not(test), allow(dead_code))]
pub fn is_penalised(kind: Kind) -> bool {
    TABLE
        .lock()
        .ok()
        .is_some_and(|t| penalised(&t.penalised, kind))
}

/// Caps the remaining penalty of `kind` to at most `max_duration`.
///
/// Used when a route has no alternative paths (e.g. `Kind::Direct` in a standard build):
/// instead of benching it for 10 or 60 minutes and leaving the client with no usable route,
/// the bench is reduced to a brief pause (e.g. 10 s) to allow DNS cache flush and re-warming.
pub fn cap_penalty(kind: Kind, max_duration: Duration) {
    if let Ok(mut t) = TABLE.lock() {
        let i = kind.index();
        let limit = Instant::now() + max_duration;
        if let Some(until) = t.penalised[i] {
            if until > limit {
                t.penalised[i] = Some(limit);
            }
        }
    }
}

/// Whether any other route than `kind` is currently usable.
pub fn has_other_usable(kind: Kind) -> bool {
    let order = order(|k| crate::proxy::route_usable(k, "daily-cloudcode-pa.googleapis.com"));
    order.into_iter().any(|k| k != kind)
}

fn penalised(list: &[Option<Instant>; N], kind: Kind) -> bool {
    list[kind.index()].is_some_and(|until| Instant::now() < until)
}

fn proven(ok: &[Option<Instant>; N], bad: &[Option<Instant>; N], kind: Kind) -> bool {
    let i = kind.index();
    match (ok[i], bad[i]) {
        (Some(ok), bad) => ok.elapsed() < PROOF_TTL && bad.is_none_or(|b| ok > b),
        (None, _) => false,
    }
}

/// Whether `kind` carried a model answer since its last refusal.
#[cfg_attr(not(test), allow(dead_code))]
pub fn is_proven(kind: Kind) -> bool {
    TABLE
        .lock()
        .ok()
        .is_some_and(|t| proven(&t.ok_at, &t.bad_at, kind))
}

/// A model answer came through `kind`: it works on this network, now.
pub fn credit(kind: Kind) {
    if let Ok(mut t) = TABLE.lock() {
        let i = kind.index();
        t.ok_at[i] = Some(Instant::now());
        t.ok_count[i] = t.ok_count[i].saturating_add(1);
        t.streak[i] = 0;
        // A route that carried an answer is not one to keep behind the others.
        t.penalised[i] = None;
        t.stumbled[i] = None;
    }
}

/// `kind` failed to open a tunnel for a live connection (before any `200`).
/// Not the gate, so no penalty and no evidence - just out of the way of the
/// next few connections, which would otherwise each wait out its budget again.
pub fn stumble(kind: Kind) {
    stumble_for(kind, STUMBLE_FOR);
}

/// The same, for however long the caller knows it needs. Never shortens a
/// stumble already running: a route kept back by a failed probe should not be
/// let out early by one connect failure with a shorter clock.
pub fn stumble_for(kind: Kind, how_long: Duration) {
    if let Ok(mut t) = TABLE.lock() {
        let until = Instant::now() + how_long;
        let slot = &mut t.stumbled[kind.index()];
        if slot.is_none_or(|prev| prev < until) {
            *slot = Some(until);
        }
    }
}

/// What a refusal did to the route it was pinned on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blamed {
    /// Benched for this long, and its open gate tunnels closed.
    Benched(Duration),
    /// Left alone: it carried a model answer this recently
    /// (`PROOF_PROTECTS_FOR`), so the refusal is not evidence against the
    /// route - and its open tunnels are the ones carrying the conversation.
    Proven(Duration),
    /// Tunnels closed, no new bench: it was already serving one. The retries a
    /// client makes on a connection it still held are the same refusal, not a
    /// new one.
    AlreadyBenched,
    /// Left alone, and not on a clock: a tunnel that carried a model answer is
    /// still open on this route, so an answer is still arriving through it
    /// (D32). Carries how long since its last byte and how much it has handed
    /// the client, which is what a field report needs to see that the thing
    /// being protected is a real answer and not an idle socket.
    Streaming { idle: Duration, to_client: u64 },
}

/// A refusal came through `kind`: bench it and close its gate tunnels, unless
/// something says the refusal is not about the route.
///
/// Closing the tunnels is the half that makes the client's retry take a fresh
/// connection instead of going on being refused for another minute and a half
/// on a pooled one (D26). It is exactly the wrong thing to do to a route that
/// is working: a model answer arrives as a stream, so cutting a proven route's
/// sockets is how a user loses an answer halfway through, reported from the
/// field as «to rabotaet, to net».
///
/// Two things can say the route is working, and they answer different
/// questions. An **open tunnel that carried an answer** says one is arriving
/// right now, so nothing is done to the route for as long as that connection
/// lives (D32) - no clock, because a model that is thinking sends nothing while
/// it thinks, and a ninety-second rule measured from the *start* of the stream
/// is what cut long answers in half. A **recent answer with no tunnel left** is
/// the weaker case, the short exchange that is already over: it keeps its place
/// for `PROOF_PROTECTS_FOR`, and then the next refusal benches it as usual.
pub fn blame(kind: Kind) -> Blamed {
    // The tunnel list first, and released before `TABLE` is taken: the two locks
    // are never held together (G30, I50).
    let streaming = live_answer(kind);
    let outcome = blame_table(kind, streaming);
    if !matches!(outcome, Blamed::Proven(_) | Blamed::Streaming { .. }) {
        cut_tunnels(kind);
    }
    outcome
}

/// The table half of `blame`, so the lock is released before `cut_tunnels`
/// takes the tunnel list (the two are never held together - G30, I50).
fn blame_table(kind: Kind, streaming: Option<(Duration, u64)>) -> Blamed {
    let Ok(mut t) = TABLE.lock() else {
        return Blamed::AlreadyBenched;
    };
    let i = kind.index();
    let now = Instant::now();
    // Recorded either way: the window's table shows when each route was last
    // refused, and a protected route is one the user should still see taking
    // refusals.
    let answered_ago = t.ok_at[i].map(|ok| ok.elapsed());
    t.refused_at[i] = Some(now);
    t.bad_count[i] = t.bad_count[i].saturating_add(1);
    // Ahead of everything else, the already-benched arm included: that arm
    // cuts, and this is the one case where cutting is the damage (D32).
    if let Some((idle, to_client)) = streaming {
        // `bad_at` deliberately untouched. "Does nothing at all" (D31) has to
        // include the ordering: a route that is handing the client an answer
        // right now must stay in the proven tier, or the next connection is
        // offered a road nothing has proved while this one works (G76).
        return Blamed::Streaming { idle, to_client };
    }
    if penalised(&t.penalised, kind) {
        t.bad_at[i] = Some(now);
        return Blamed::AlreadyBenched;
    }
    if let Some(ago) = answered_ago.filter(|a| *a < PROOF_PROTECTS_FOR) {
        // Not a strike either: a streak is "refused again with no model answer
        // in between", and there was one - and not evidence either, for the
        // same reason as the arm above.
        return Blamed::Proven(ago);
    }
    t.bad_at[i] = Some(now);
    let step = (t.streak[i] as usize).min(PENALTY_STEPS.len() - 1);
    let penalty = PENALTY_STEPS[step];
    t.streak[i] = t.streak[i].saturating_add(1);
    t.penalised[i] = Some(now + penalty);
    Blamed::Benched(penalty)
}

/// Tells the table which network it is on. A different fingerprint wipes what
/// was learned - proofs, refusals, penalties - and keeps the timings, which the
/// probes refresh on their own. Returns whether it changed.
pub fn set_context(fingerprint: u64) -> bool {
    let Ok(mut t) = TABLE.lock() else {
        return false;
    };
    if t.context == fingerprint {
        return false;
    }
    let first = t.context == 0;
    t.context = fingerprint;
    if !first {
        t.ok_at = [None; N];
        t.bad_at = [None; N];
        t.refused_at = [None; N];
        t.ok_count = [0; N];
        t.bad_count = [0; N];
        t.streak = [0; N];
        t.penalised = [None; N];
        t.stumbled = [None; N];
    }
    !first
}


/// The order to try routes in for the next connection, best first, among those
/// `usable` says are worth trying at all.
///
/// The table is copied out from under its lock before `usable` is consulted:
/// `usable` asks this module questions of its own (`is_penalised`), and a
/// non-reentrant lock held across that call deadlocked the very first live
pub fn has_dns_layer() -> bool {
    true
}

/// connection (G30, I50).
pub fn order(usable: impl Fn(Kind) -> bool) -> Vec<Kind> {
    let s = snapshot();
    order_with(&s, has_dns_layer(), usable)
}

#[derive(Clone, Copy)]
struct Snapshot {
    samples: [Option<Sample>; N],
    penalised: [Option<Instant>; N],
    ok_at: [Option<Instant>; N],
    bad_at: [Option<Instant>; N],
    refused_at: [Option<Instant>; N],
    ok_count: [u32; N],
    bad_count: [u32; N],
    stumbled: [Option<Instant>; N],
    leader: Option<Kind>,
}

/// What the table holds right now, without holding it.
fn snapshot() -> Snapshot {
    match TABLE.lock() {
        Ok(t) => Snapshot {
            samples: t.samples,
            penalised: t.penalised,
            ok_at: t.ok_at,
            bad_at: t.bad_at,
            refused_at: t.refused_at,
            ok_count: t.ok_count,
            bad_count: t.bad_count,
            stumbled: t.stumbled,
            leader: t.leader,
        },
        Err(_) => Snapshot {
            samples: [None; N],
            penalised: [None; N],
            ok_at: [None; N],
            bad_at: [None; N],
            refused_at: [None; N],
            ok_count: [0; N],
            bad_count: [0; N],
            stumbled: [None; N],
            leader: None,
        },
    }
}

/// The route sitting first right now, or `None` before the first pass has
/// picked one. Read by the record the window shows (`gate`).
pub fn leader() -> Option<Kind> {
    snapshot().leader
}

/// Re-derives the leader from the latest evidence and measurements, and says so
/// in the log when it changed. Run once per warm pass, after the probes.
pub fn refresh_leader(usable: impl Fn(Kind) -> bool) {
    let s = snapshot();
    let order = order_with(&s, has_dns_layer(), usable);
    let Some(&best) = order.first() else {
        return;
    };
    if s.leader == Some(best) {
        return;
    }
    if let Ok(mut t) = TABLE.lock() {
        t.leader = Some(best);
    }
    let describe = |k: Kind| match fresh(&s.samples, k) {
        Some(d) => format!("{} ({} мс)", k.label(), d.as_millis()),
        None => format!("{} (не измерен)", k.label()),
    };
    let line = match s.leader {
        Some(prev) => format!(
            "маршрут гейт-хостов: {}, было {}",
            describe(best),
            describe(prev)
        ),
        None => format!("маршрут гейт-хостов: {}", describe(best)),
    };
    note(&line);
}

/// The pure ordering, so it can be tested without the static.
///
/// Own first when usable. Then four tiers, each in the default order inside
/// itself unless measured: proven (fastest first, the sitting leader kept unless
/// clearly beaten), measured, unmeasured, penalised. Without a DNS layer the
/// direct tunnel has nothing substituted to reach, so it counts as penalised.
fn order_with(s: &Snapshot, has_dns_layer: bool, usable: impl Fn(Kind) -> bool) -> Vec<Kind> {
    let mut out: Vec<Kind> = Vec::with_capacity(N);
    if usable(Kind::Own) {
        out.push(Kind::Own);
    }

    let rest: Vec<Kind> = DEFAULT_ORDER
        .iter()
        .copied()
        .filter(|k| *k != Kind::Own && usable(*k))
        .collect();

    let tier = |k: Kind| -> u8 {
        if penalised(&s.penalised, k)
            || penalised(&s.stumbled, k)
            || (k == Kind::Direct && !has_dns_layer)
        {
            3
        } else if proven(&s.ok_at, &s.bad_at, k) {
            0
        } else if fresh(&s.samples, k).is_some() {
            1
        } else {
            2
        }
    };

    for t in 0..=1u8 {
        let mut measured: Vec<(Kind, Duration)> = rest
            .iter()
            .copied()
            .filter(|k| tier(*k) == t)
            // A proven route that has not been timed yet still goes ahead of
            // everything unproven; it simply sorts last among the proven.
            .map(|k| (k, fresh(&s.samples, k).unwrap_or(Duration::MAX)))
            .collect();
        measured.sort_by_key(|(_, d)| *d);
        keep_leader(&mut measured, s.leader);
        out.extend(measured.iter().map(|(k, _)| *k));
    }
    out.extend(rest.iter().copied().filter(|k| tier(*k) == 2));
    // Benched routes last, the one whose bench ends first ahead: when every
    // route has been refused, the likeliest to work again is the one refused
    // longest ago.
    let mut benched: Vec<Kind> = rest.iter().copied().filter(|k| tier(*k) == 3).collect();
    let ends = |k: &Kind| {
        let i = k.index();
        let live = |u: Option<Instant>| u.filter(|u| *u > Instant::now());
        live(s.penalised[i]).max(live(s.stumbled[i]))
    };
    benched.sort_by_key(ends);
    out.extend(benched);
    out
}

/// Hysteresis: the sitting leader stays ahead of a challenger in its own tier
/// that is not clearly faster.
fn keep_leader(tier: &mut Vec<(Kind, Duration)>, leader: Option<Kind>) {
    let Some(lead) = leader else { return };
    let Some(lead_pos) = tier.iter().position(|(k, _)| *k == lead) else {
        return;
    };
    if lead_pos == 0 {
        return;
    }
    let lead_ms = tier[lead_pos].1.as_millis() as u64;
    let best_ms = tier[0].1.as_millis() as u64;
    let clearly_faster =
        best_ms.saturating_mul(100) < lead_ms.saturating_mul(100 - SWITCH_MARGIN_PCT);
    if !clearly_faster {
        let item = tier.remove(lead_pos);
        tier.insert(0, item);
    }
}

// ---------------------------------------------------------------------------
// Open tunnels: who carried what, and closing a refused route's connections.
// ---------------------------------------------------------------------------

/// The clock the lock-free activity stamps count from. An `Instant` does not
/// fit in an atomic, and taking `TUNNELS` on every 8 KB chunk would put a
/// global lock on the byte path of every tunnel at once.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// What a tunnel has moved, written by the threads pumping it and read by the
/// table without touching them.
///
/// Both directions are counted because both are a conversation in flight: the
/// answer streaming back, and the request going out - a long chat is a 100 KB
/// upload before it is anything else (field, `116225 B out`).
#[derive(Default)]
pub struct Activity {
    /// Milliseconds since `epoch()` when the last byte moved, either way.
    /// Zero means nothing has moved yet.
    at_ms: AtomicU64,
    to_client: AtomicU64,
    to_upstream: AtomicU64,
}

impl Activity {
    /// `n` bytes reached the client. Called per chunk, so it does no more than
    /// two relaxed adds and a clock read.
    pub fn to_client(&self, n: u64) {
        self.to_client.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// `n` bytes went out toward Google.
    pub fn to_upstream(&self, n: u64) {
        self.to_upstream.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    fn touch(&self) {
        // `max(1)`: zero is "nothing yet", and the first millisecond of the
        // process would otherwise read as silence for the tunnel's whole life.
        let ms = (epoch().elapsed().as_millis() as u64).max(1);
        self.at_ms.store(ms, Ordering::Relaxed);
    }

    /// How long since the last byte, or `None` if none has moved.
    pub fn idle(&self) -> Option<Duration> {
        match self.at_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(
                epoch()
                    .elapsed()
                    .saturating_sub(Duration::from_millis(ms)),
            ),
        }
    }

    /// Bytes to the client, bytes out.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.to_client.load(Ordering::Relaxed),
            self.to_upstream.load(Ordering::Relaxed),
        )
    }
}

/// One gate tunnel, from the `200` to the end of its splice.
struct Tunnel {
    id: u64,
    kind: Kind,
    /// Which gate host it carries. The client keeps a pool per host, and the two
    /// pools can sit on different routes - an event about one host must not be
    /// pinned on the other's tunnel.
    host: String,
    opened: Instant,
    closed: Option<Instant>,
    /// When a model answer was attributed to *this* tunnel. The one fact that
    /// separates a conversation in flight from a pooled connection the client
    /// keeps feeding refused requests: a refusal-only tunnel is never credited
    /// here, however busy it looks (D32).
    answered_at: Option<Instant>,
    /// What has moved through it and when, shared with its pump threads.
    activity: Arc<Activity>,
    /// The client's socket, kept while the tunnel is open so a refused route's
    /// connections can be closed from outside the thread pumping them.
    client: Option<TcpStream>,
    /// The upstream socket, when the route hands it to `splice`: closing only
    /// the client side left the other direction blocked on an idle Google
    /// connection for minutes (G52).
    upstream: Option<TcpStream>,
}

static TUNNELS: Mutex<Vec<Tunnel>> = Mutex::new(Vec::new());
static NEXT_TUNNEL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The connection the current thread is serving, between `begin` and `end`.
///
/// Thread-local because the routes that commit a tunnel (`note_used`) are
/// called on the thread that serves it, and two of them live in private
/// modules whose signatures carry no socket (I68).
struct Serving {
    client: Option<TcpStream>,
    host: String,
    tunnel: Option<u64>,
    /// Handed to the pump by `serving_activity` once `note_used` has made one.
    activity: Option<Arc<Activity>>,
}

thread_local! {
    static SERVING: RefCell<Option<Serving>> = const { RefCell::new(None) };
}

/// Called by the proxy before it offers a gate connection to the routes. The
/// returned guard ends the record when it goes out of scope, whichever way the
/// serving code leaves - a record left open would pin every later event on a
/// tunnel that no longer exists.
#[must_use]
pub fn begin_gate_connection(client: &TcpStream, host: &str) -> GateConnection {
    let clone = client.try_clone().ok();
    SERVING.with(|s| {
        *s.borrow_mut() = Some(Serving {
            client: clone,
            host: host.trim_end_matches('.').to_ascii_lowercase(),
            tunnel: None,
            activity: None,
        })
    });
    GateConnection { _private: () }
}

/// Ends the current thread's gate-connection record when dropped.
pub struct GateConnection {
    _private: (),
}

impl Drop for GateConnection {
    fn drop(&mut self) {
        end_gate_connection();
    }
}

/// Hands the tunnel being served on this thread its upstream socket, so a cut
/// closes both sides (G52). A no-op outside a gate connection - `splice` also
/// carries every non-gate tunnel.
pub fn attach_upstream(upstream: &TcpStream) {
    let Some(id) = SERVING.with(|s| s.borrow().as_ref().and_then(|s| s.tunnel)) else {
        return;
    };
    let Ok(clone) = upstream.try_clone() else { return };
    if let Ok(mut list) = TUNNELS.lock() {
        if let Some(t) = list.iter_mut().find(|t| t.id == id && t.closed.is_none()) {
            t.upstream = Some(clone);
        }
    }
}

/// Ends the current thread's gate-connection record.
fn end_gate_connection() {
    let tunnel = SERVING.with(|s| s.borrow_mut().take().and_then(|s| s.tunnel));
    let Some(id) = tunnel else { return };
    if let Ok(mut list) = TUNNELS.lock() {
        if let Some(t) = list.iter_mut().find(|t| t.id == id) {
            t.closed = Some(Instant::now());
            t.client = None;
            t.upstream = None;
        }
        prune(&mut list);
    }
}

/// Notes that a gate tunnel was just opened on `kind`. Called where the `200`
/// goes out, i.e. once the route is the one the client is actually on.
pub fn note_used(kind: Kind) {
    let now = Instant::now();
    if let Ok(mut t) = TABLE.lock() {
        t.last_used = Some((kind, now));
    }
    let id = NEXT_TUNNEL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (client, host) = SERVING
        .with(|s| {
            let mut s = s.borrow_mut();
            let serving = s.as_mut()?;
            serving.tunnel = Some(id);
            Some((
                serving.client.as_ref().and_then(|c| c.try_clone().ok()),
                serving.host.clone(),
            ))
        })
        .unwrap_or_default();
    let activity = Arc::new(Activity::default());
    SERVING.with(|s| {
        if let Some(serving) = s.borrow_mut().as_mut() {
            serving.activity = Some(Arc::clone(&activity));
        }
    });
    if let Ok(mut list) = TUNNELS.lock() {
        list.push(Tunnel {
            id,
            kind,
            host,
            opened: now,
            closed: None,
            answered_at: None,
            activity,
            client,
            upstream: None,
        });
        prune(&mut list);
    }
}

/// The activity stamp of the gate tunnel this thread is serving, for its pump
/// to mark as bytes move. `None` outside a gate connection, or before the
/// route committed one: `splice` carries every non-gate tunnel too.
pub fn serving_activity() -> Option<Arc<Activity>> {
    SERVING.with(|s| s.borrow().as_ref().and_then(|s| s.activity.clone()))
}

fn prune(list: &mut Vec<Tunnel>) {
    list.retain(|t| t.closed.is_none_or(|c| c.elapsed() < TUNNEL_MEMORY));
    // Oldest closed first; the list is in opening order.
    while list.len() > MAX_TUNNEL_RECORDS {
        match list.iter().position(|t| t.closed.is_some()) {
            Some(i) => {
                list.remove(i);
            }
            None => break,
        }
    }
}

/// How many gate tunnels each route has open right now.
pub fn open_counts() -> [u32; N] {
    let mut out = [0u32; N];
    if let Ok(list) = TUNNELS.lock() {
        for t in list.iter().filter(|t| t.closed.is_none()) {
            out[t.kind.index()] += 1;
        }
    }
    out
}

/// Closes every open gate tunnel on `kind`. The splice under each ends on the
/// shutdown, the client sees its connection go and dials again - and its next
/// connection is offered to the table afresh.
fn cut_tunnels(kind: Kind) {
    let Ok(mut list) = TUNNELS.lock() else { return };
    // A tunnel that carried a model answer is never cut, whatever brought the
    // route here. `blame` already turns back before this for the same reason,
    // and saying it twice is deliberate: this is the call that destroys a live
    // answer, so it is the call that must not depend on a caller's check (D32).
    for t in list
        .iter_mut()
        .filter(|t| t.kind == kind && t.closed.is_none() && t.answered_at.is_none())
    {
        for sock in [t.client.take(), t.upstream.take()].into_iter().flatten() {
            sock.shutdown(std::net::Shutdown::Both).ok();
        }
    }
}

/// The route that carried a request answered at `at`: the one with a tunnel
/// open around that moment, for `host` when the log line named it. When tunnels
/// on several routes were open, the one opened most recently before it - a
/// client keeps one connection per host and puts new requests on the newest.
///
/// `None` when no tunnel of ours was open around it: the client reached Google
/// some other way, and pinning the event on whichever route last opened a
/// tunnel would bench a route that never saw it.
#[cfg_attr(not(test), allow(dead_code))]
pub fn attribute(at: Instant, host: Option<&str>) -> Option<Kind> {
    attribute_tunnel(at, host).map(|(kind, _)| kind)
}

/// The same, naming the tunnel as well: an answer is credited to the one that
/// carried it, not only to its route, because that tunnel is what tells a
/// conversation in flight from a pooled connection being refused (D32).
pub fn attribute_tunnel(at: Instant, host: Option<&str>) -> Option<(Kind, u64)> {
    let host = host.map(|h| h.trim_end_matches('.').to_ascii_lowercase());
    let list = TUNNELS.lock().ok()?;
    list.iter()
        .filter(|t| host.as_ref().is_none_or(|h| *h == t.host))
        .filter(|t| t.opened <= at + ATTRIBUTION_SLACK)
        .filter(|t| t.closed.is_none_or(|c| c + ATTRIBUTION_SLACK >= at))
        .max_by_key(|t| t.opened)
        .map(|t| (t.kind, t.id))
}

/// Marks the tunnel a model answer came through. Closed tunnels are marked too:
/// the log line is read seconds after the answer started, and a short answer is
/// over by then - what matters is that the credit lands on the right record.
pub fn credit_tunnel(id: u64) {
    if let Ok(mut list) = TUNNELS.lock() {
        if let Some(t) = list.iter_mut().find(|t| t.id == id) {
            t.answered_at = Some(Instant::now());
        }
    }
}

/// What one gate connection looks like, for the line the log writes when a
/// refusal is pinned on it.
///
/// A refusal and a model answer on the **same** connection is a different
/// diagnosis from one on a sibling, and the relay log could not tell them apart
/// until now: three field reports (2026-09-21) showed a route refusing once a
/// minute while answering on the same minute, and nothing in the log said
/// whether the refused request rode the connection that was answering. If it
/// did, no route change can help - the backend is turning single requests down
/// - and the report should say so instead of sending the user round the routes
/// again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// This very connection carried a model answer, and how long ago.
    pub answered_ago: Option<Duration>,
    /// Still open.
    pub open: bool,
    /// Since it was opened.
    pub age: Duration,
    /// Bytes handed to the client on it, and how long since the last one.
    pub to_client: u64,
    pub idle: Duration,
}

/// `Shape` of one tunnel, by the id `attribute_tunnel` gave.
pub fn tunnel_shape(id: u64) -> Option<Shape> {
    let list = TUNNELS.lock().ok()?;
    let t = list.iter().find(|t| t.id == id)?;
    Some(Shape {
        answered_ago: t.answered_at.map(|a| a.elapsed()),
        open: t.closed.is_none(),
        age: t.opened.elapsed(),
        to_client: t.activity.bytes().0,
        idle: t.activity.idle().unwrap_or_else(|| t.opened.elapsed()),
    })
}

/// Closes one gate tunnel by id, and only if it never carried a model answer.
///
/// The narrow half of `cut_tunnels`. When a route is protected because *another*
/// of its connections is streaming an answer (D32), the connection the refusal
/// actually came in on is still a connection the client will go on being
/// refused over, and D26's reason for cutting applies to it and to nothing else
/// on the route. Returns whether anything was closed, so the log can say which
/// of the two cases this was.
pub fn cut_tunnel(id: u64) -> bool {
    let Ok(mut list) = TUNNELS.lock() else {
        return false;
    };
    let Some(t) = list
        .iter_mut()
        .find(|t| t.id == id && t.closed.is_none() && t.answered_at.is_none())
    else {
        return false;
    };
    let mut cut = false;
    for sock in [t.client.take(), t.upstream.take()].into_iter().flatten() {
        sock.shutdown(std::net::Shutdown::Both).ok();
        cut = true;
    }
    cut
}

/// An **open** tunnel of `kind` that carried a model answer, i.e. a conversation
/// still in flight, with how long since its last byte.
///
/// No clock and no idle limit on purpose (D32, owner): a model that is thinking
/// sends nothing for as long as it thinks, and the whole point of this check is
/// that the answer survives it. What ends the protection is the connection
/// closing - the client's own signal that the exchange is over.
fn live_answer(kind: Kind) -> Option<(Duration, u64)> {
    let list = TUNNELS.lock().ok()?;
    list.iter()
        .filter(|t| t.kind == kind && t.closed.is_none() && t.answered_at.is_some())
        .map(|t| {
            let idle = t.activity.idle().unwrap_or_else(|| t.opened.elapsed());
            (idle, t.activity.bytes().0)
        })
        // The liveliest of them: with several open, one gone quiet says nothing
        // while another is still handing the client bytes.
        .min_by_key(|(idle, _)| *idle)
}

// ---------------------------------------------------------------------------
// What the window is told.
// ---------------------------------------------------------------------------

/// One row of the table as the window's report shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Row {
    pub label: String,
    pub usable: bool,
    pub latency_ms: Option<u32>,
    pub proven: bool,
    /// Seconds since the last model answer it carried.
    pub ok_ago: Option<u64>,
    /// Seconds since the last refusal it carried, whether or not that refusal
    /// was held against it.
    pub refused_ago: Option<u64>,
    /// Model answers and refusal episodes pinned on it since the relay started
    /// or the network last changed.
    pub answers: u32,
    pub refusals: u32,
    /// Seconds of bench left.
    pub bench_left: Option<u64>,
    pub open: u32,
}

/// Every route, in the order the table would offer them, for the record the
/// window reads (`gate`).
pub fn rows(usable: impl Fn(Kind) -> bool) -> Vec<Row> {
    let s = snapshot();
    let open = open_counts();
    let order = order_with(&s, has_dns_layer(), &usable);
    let mut kinds: Vec<Kind> = order.clone();
    kinds.extend(ALL.iter().copied().filter(|k| !order.contains(k)));
    kinds
        .into_iter()
        .map(|k| {
            let i = k.index();
            Row {
                label: k.label().to_string(),
                usable: order.contains(&k),
                latency_ms: fresh(&s.samples, k)
                    .map(|d| d.as_millis().min(u32::MAX as u128) as u32),
                proven: proven(&s.ok_at, &s.bad_at, k),
                ok_ago: s.ok_at[i].map(|a| a.elapsed().as_secs()),
                refused_ago: s.refused_at[i].map(|a| a.elapsed().as_secs()),
                answers: s.ok_count[i],
                refusals: s.bad_count[i],
                bench_left: s.penalised[i]
                    .max(s.stumbled[i])
                    .and_then(|u| u.checked_duration_since(Instant::now()))
                    .map(|d| d.as_secs()),
                open: open[i],
            }
        })
        .collect()
}

/// Log sink, silent under test: these lines go to the live relay log (G18).
fn note(message: &str) {
    #[cfg(not(test))]
    crate::dns_forwarder::log_proxy(message);
    #[cfg(test)]
    let _ = message;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn sample(n: u64) -> Option<Sample> {
        Some(Sample {
            latency: ms(n),
            at: Instant::now(),
        })
    }

    /// The tests that change the table's evidence share one process-wide table,
    /// and `set_context` wipes it for everyone - so they take turns.
    static STATEFUL: Mutex<()> = Mutex::new(());

    fn turn() -> std::sync::MutexGuard<'static, ()> {
        let guard = STATEFUL.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut list) = TUNNELS.lock() {
            list.clear();
        }
        guard
    }

    fn blank() -> Snapshot {
        Snapshot {
            samples: [None; N],
            penalised: [None; N],
            ok_at: [None; N],
            bad_at: [None; N],
            refused_at: [None; N],
            ok_count: [0; N],
            bad_count: [0; N],
            stumbled: [None; N],
            leader: None,
        }
    }

    #[test]
    fn unmeasured_routes_take_the_default_order_direct_first() {
        let order = order_with(&blank(), true, |_| true);
        assert_eq!(
            order,
            vec![Kind::Own, Kind::Direct, Kind::Vpn, Kind::Exits, Kind::Relay]
        );
    }

    #[test]
    fn without_a_dns_layer_direct_goes_last_whatever_it_measured() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(50);
        s.samples[Kind::Exits.index()] = sample(400);
        let order = order_with(&s, false, |k| k != Kind::Own && k != Kind::Vpn);
        assert_eq!(order, vec![Kind::Exits, Kind::Relay, Kind::Direct]);
    }

    #[test]
    fn measured_routes_go_fastest_first_and_unmeasured_after_them() {
        let mut s = blank();
        s.samples[Kind::Relay.index()] = sample(1300);
        s.samples[Kind::Exits.index()] = sample(450);
        let order = order_with(&s, true, |k| k != Kind::Own && k != Kind::Vpn);
        assert_eq!(order, vec![Kind::Exits, Kind::Relay, Kind::Direct]);
    }

    #[test]
    fn the_leader_keeps_its_place_unless_beaten_by_the_margin() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(300);
        s.samples[Kind::Exits.index()] = sample(270);
        s.leader = Some(Kind::Direct);
        let usable = |k: Kind| k != Kind::Own && k != Kind::Vpn;
        assert_eq!(order_with(&s, true, usable)[0], Kind::Direct);
        s.samples[Kind::Exits.index()] = sample(180);
        assert_eq!(order_with(&s, true, usable)[0], Kind::Exits);
    }

    #[test]
    fn a_penalised_route_is_last_even_when_fastest() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(100);
        s.samples[Kind::Relay.index()] = sample(1300);
        s.penalised[Kind::Direct.index()] = Some(Instant::now() + ms(60_000));
        s.leader = Some(Kind::Direct);
        let usable = |k: Kind| k != Kind::Own && k != Kind::Vpn;
        assert_eq!(
            order_with(&s, true, usable),
            vec![Kind::Relay, Kind::Exits, Kind::Direct]
        );
        s.penalised[Kind::Direct.index()] = Some(Instant::now() - ms(1));
        s.leader = None;
        assert_eq!(order_with(&s, true, usable)[0], Kind::Direct);
    }

    /// The whole point of proof: the fastest route is not the one that works.
    /// A slower route that carried a model answer goes ahead of a faster one
    /// that never has.
    #[test]
    fn a_route_that_carried_an_answer_beats_a_faster_one_that_did_not() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(120);
        s.samples[Kind::Exits.index()] = sample(900);
        s.ok_at[Kind::Exits.index()] = Some(Instant::now());
        s.leader = Some(Kind::Direct);
        let usable = |k: Kind| k != Kind::Own && k != Kind::Vpn;
        assert_eq!(order_with(&s, true, usable)[0], Kind::Exits);
        // A refusal after the answer takes the proof away again.
        s.bad_at[Kind::Exits.index()] = Some(Instant::now() + ms(1));
        assert_eq!(order_with(&s, true, usable)[0], Kind::Direct);
    }

    /// A route that could not even open for a live connection steps aside for a
    /// minute, so the next connections do not each wait out its budget.
    #[test]
    fn a_route_that_failed_to_open_steps_aside() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(100);
        s.samples[Kind::Exits.index()] = sample(500);
        s.stumbled[Kind::Direct.index()] = Some(Instant::now() + ms(60_000));
        let order = order_with(&s, true, |k| k != Kind::Own && k != Kind::Vpn);
        assert_eq!(order, vec![Kind::Exits, Kind::Relay, Kind::Direct]);
        s.stumbled[Kind::Direct.index()] = Some(Instant::now() - ms(1));
        assert_eq!(order_with(&s, true, |k| k != Kind::Own && k != Kind::Vpn)[0], Kind::Direct);
    }

    #[test]
    fn with_every_route_benched_the_one_benched_longest_ago_goes_first() {
        let mut s = blank();
        let now = Instant::now();
        s.penalised[Kind::Direct.index()] = Some(now + ms(600_000));
        s.penalised[Kind::Exits.index()] = Some(now + ms(60_000));
        s.penalised[Kind::Relay.index()] = Some(now + ms(3_600_000));
        let order = order_with(&s, true, |k| k != Kind::Own && k != Kind::Vpn);
        assert_eq!(order, vec![Kind::Exits, Kind::Direct, Kind::Relay]);
    }

    #[test]
    fn the_users_own_proxy_is_first_whenever_it_is_usable() {
        let mut s = blank();
        s.samples[Kind::Own.index()] = sample(900);
        s.samples[Kind::Direct.index()] = sample(100);
        s.ok_at[Kind::Direct.index()] = Some(Instant::now());
        s.leader = Some(Kind::Direct);
        assert_eq!(order_with(&s, true, |_| true)[0], Kind::Own);
        assert_eq!(order_with(&s, true, |k| k != Kind::Own)[0], Kind::Direct);
    }

    #[test]
    fn unusable_routes_are_not_offered_at_all() {
        let order = order_with(&blank(), true, |k| k == Kind::Relay);
        assert_eq!(order, vec![Kind::Relay]);
        assert!(order_with(&blank(), true, |_| false).is_empty());
    }

    /// `usable` may ask the table questions of its own. This deadlocked once:
    /// `order` held the lock while `is_penalised` tried to take it, and the
    /// first live connection through the proxy never got its 200 (G30).
    #[test]
    fn ordering_may_consult_the_table_from_inside_usable() {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = done.clone();
        std::thread::spawn(move || {
            let _ = order(|k| !is_penalised(k) && latency(k).is_none() || is_proven(k) || true);
            refresh_leader(|k| !is_penalised(k));
            let _ = rows(|k| !is_penalised(k));
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "order() deadlocked on its own table"
            );
            std::thread::sleep(ms(10));
        }
    }

    /// The static half, in one test because it shares process-wide state:
    /// timings blend and expire, a refusal benches for a growing time, an
    /// answer lifts the bench and proves the route, and a new network forgets
    /// both.
    #[test]
    fn the_table_learns_and_forgets() {
        let _turn = turn();
        record_failure(Kind::Relay);
        assert_eq!(latency(Kind::Relay), None);
        record(Kind::Relay, ms(1000));
        record(Kind::Relay, ms(500));
        assert_eq!(latency(Kind::Relay), Some(ms(750)), "blended");
        record_failure(Kind::Relay);
        assert_eq!(latency(Kind::Relay), None);

        set_context(0x1111);
        assert_eq!(blame(Kind::Relay), Blamed::Benched(PENALTY_STEPS[0]));
        assert!(is_penalised(Kind::Relay));
        // Already benched: the client's retries on the old connection are the
        // same refusal, not a new one.
        assert_eq!(blame(Kind::Relay), Blamed::AlreadyBenched);
        credit(Kind::Relay);
        assert!(!is_penalised(Kind::Relay), "an answer lifts the bench");
        assert!(is_proven(Kind::Relay));
        // Refused straight after an answer: the route is left alone entirely -
        // its tier included, which is what Â«Ð½Ðµ Ñ‚Ñ€Ð¾Ð½ÑƒÑ‚Â» has to mean if the next
        // connection is not to be handed to somebody else (G76).
        assert!(matches!(blame(Kind::Relay), Blamed::Proven(_)));
        assert!(!is_penalised(Kind::Relay), "a proven route is not benched");
        assert!(is_proven(Kind::Relay), "and it keeps its place");
        assert!(
            rows(|k| k == Kind::Relay)
                .iter()
                .any(|r| r.label == Kind::Relay.label() && r.refused_ago.is_some()),
            "but the refusal is still on the record the window shows"
        );
        // Once the proof has aged out, the same refusal benches - at the first
        // step, because the answer reset the streak.
        age_out_answer(Kind::Relay);
        assert_eq!(blame(Kind::Relay), Blamed::Benched(PENALTY_STEPS[0]));
        // A new network forgets it all.
        assert!(set_context(0x2222));
        assert!(!is_penalised(Kind::Relay));
        assert!(!set_context(0x2222), "the same network is not a change");
    }

    #[test]
    fn repeated_refusals_bench_for_longer_each_time() {
        let _turn = turn();
        // Uses Vpn so it cannot collide with the test above on the statics.
        set_context(0x3333);
        for step in [0usize, 1, 2, 3, 3] {
            assert_eq!(
                blame(Kind::Vpn),
                Blamed::Benched(PENALTY_STEPS[step]),
                "step {step}"
            );
            if let Ok(mut t) = TABLE.lock() {
                t.penalised[Kind::Vpn.index()] = Some(Instant::now() - ms(1));
            }
        }
        credit(Kind::Vpn);
    }

    /// Pushes `kind`'s last answer out of `PROOF_PROTECTS_FOR` without waiting
    /// ninety seconds for it.
    fn age_out_answer(kind: Kind) {
        if let Ok(mut t) = TABLE.lock() {
            t.ok_at[kind.index()] = Instant::now().checked_sub(PROOF_PROTECTS_FOR + ms(1));
        }
    }

    /// The field case this exists for: a route answers, is refused two seconds
    /// later, and must keep both its place in the table and its open tunnels.
    #[test]
    fn an_answer_just_now_keeps_a_refusal_from_benching_the_route() {
        let _turn = turn();
        set_context(0x4444);
        credit(Kind::Own);
        // Ten refusals in a row while the answers keep coming change nothing:
        // no bench, and no streak to escalate once the protection does lapse.
        for _ in 0..10 {
            assert!(matches!(blame(Kind::Own), Blamed::Proven(_)));
            credit(Kind::Own);
        }
        assert!(!is_penalised(Kind::Own));
        age_out_answer(Kind::Own);
        assert_eq!(
            blame(Kind::Own),
            Blamed::Benched(PENALTY_STEPS[0]),
            "the first step, because every answer reset the streak"
        );
    }

    /// A failed probe is not the same as an unmeasured route: it has to keep the
    /// route out of the running, or the next connection goes straight back to
    /// something that just refused to answer one.
    #[test]
    fn a_failed_probe_keeps_the_route_back_where_a_lost_measurement_did_not() {
        let _turn = turn();
        set_context(0x5555);
        record(Kind::Direct, ms(300));
        record_failure(Kind::Direct);
        assert_eq!(latency(Kind::Direct), None);
        let after_loss = order(|_| true);
        probe_failed(Kind::Direct);
        let after_probe = order(|_| true);
        assert!(
            after_probe.last() == Some(&Kind::Direct) && after_loss.last() != Some(&Kind::Direct),
            "{after_loss:?} then {after_probe:?}"
        );
        assert!(PROBE_STUMBLE_FOR > STUMBLE_FOR, "a probe runs every 2 min");
    }

    /// Attribution by open tunnel, and the tunnel of a refused route closed from
    /// outside the thread that pumps it.
    #[test]
    fn a_refusal_is_pinned_on_the_tunnel_that_was_open_and_that_tunnel_is_closed() {
        let _turn = turn();
        use std::io::Read;
        use std::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bound");
        let addr = listener.local_addr().expect("addr");
        let mut far = TcpStream::connect(addr).expect("connected");
        let (near, _) = listener.accept().expect("accepted");

        // Exits carries a tunnel, on a thread of its own, the way `serve` does.
        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let _gate = begin_gate_connection(&near, "daily-cloudcode-pa.googleapis.com");
            note_used(Kind::Exits);
            tx.send(()).ok();
            // Stands in for the splice: returns when the socket is shut down.
            let mut buf = [0u8; 1];
            let mut near = near;
            let _ = near.read(&mut buf);
        });
        rx.recv().expect("opened");
        assert_eq!(attribute(Instant::now(), None), Some(Kind::Exits));
        assert_eq!(
            attribute(Instant::now(), Some("daily-cloudcode-pa.googleapis.com")),
            Some(Kind::Exits)
        );
        // An event about the other host is not this tunnel's.
        assert_eq!(attribute(Instant::now(), Some("cloudcode-pa.googleapis.com")), None);
        assert!(open_counts()[Kind::Exits.index()] >= 1);

        set_context(0x4444);
        blame(Kind::Exits);
        // The far end sees its connection go.
        far.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut buf = [0u8; 1];
        let got = far.read(&mut buf);
        assert!(matches!(got, Ok(0) | Err(_)), "the tunnel was not closed");
        server.join().expect("server thread");
        credit(Kind::Exits);
    }

    /// D32: while a tunnel that carried an answer is open, a refusal pinned on
    /// that route does nothing at all - no bench, and above all no cut. This is
    /// the field symptom as a test: a long answer streaming while something
    /// else on the machine keeps walking into the gate.
    #[test]
    fn an_answer_still_streaming_keeps_its_route_and_its_socket() {
        let _turn = turn();
        use std::io::{ErrorKind, Read};
        use std::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bound");
        let addr = listener.local_addr().expect("addr");
        let mut far = TcpStream::connect(addr).expect("connected");
        let (near, _) = listener.accept().expect("accepted");

        let (tx, rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let _gate = begin_gate_connection(&near, "daily-cloudcode-pa.googleapis.com");
            note_used(Kind::Exits);
            tx.send(serving_activity()).ok();
            // Stands in for the splice: returns when the socket ends.
            let mut buf = [0u8; 1];
            let mut near = near;
            let _ = near.read(&mut buf);
            done_tx.send(()).ok();
        });
        let activity = rx.recv().expect("opened").expect("a gate tunnel has a stamp");

        set_context(0x5555);
        let (kind, id) = attribute_tunnel(Instant::now(), None).expect("attributed");
        assert_eq!(kind, Kind::Exits);
        credit_tunnel(id);
        // The answer hands the client bytes, the way a stream does.
        activity.to_client(8 * 1024);

        match blame(Kind::Exits) {
            Blamed::Streaming { to_client, .. } => assert_eq!(to_client, 8 * 1024),
            other => panic!("a streaming answer was not recognised: {other:?}"),
        }
        assert!(
            !is_penalised(Kind::Exits),
            "a route carrying an answer must not be benched"
        );
        // And the socket is still there: this is the half that cut answers in two.
        far.set_read_timeout(Some(Duration::from_millis(250))).ok();
        let mut buf = [0u8; 1];
        let got = far.read(&mut buf);
        assert!(
            matches!(&got, Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)),
            "the live answer's socket was cut: {got:?}"
        );

        // The client ends the exchange. Nothing is in flight any more, so the
        // next refusal benches the route exactly as it did before (D26).
        far.shutdown(std::net::Shutdown::Both).ok();
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the tunnel ended");
        server.join().expect("server thread");
        assert!(
            live_answer(Kind::Exits).is_none(),
            "a closed tunnel protects nothing"
        );
        assert!(matches!(blame(Kind::Exits), Blamed::Benched(_)));
        assert!(is_penalised(Kind::Exits));
    }

    /// G76, the flap three field reports (2026-09-21) show: a refusal the table
    /// declines to hold against a route must not cost it its place either.
    ///
    /// It did. `blame` stamped the refusal whatever it decided, `proven` reads
    /// that stamp, and the route dropped out of the proven tier the moment it
    /// was refused - so the leader swapped to whatever measured fastest, swapped
    /// back on the next answer, and did it again fifteen seconds later. Half the
    /// client's new connections went to a road nothing had proved, while the
    /// road that was answering sat second.
    #[test]
    fn a_protected_refusal_does_not_cost_the_route_its_place() {
        let _turn = turn();
        set_context(0x7601);
        let usable = |k: Kind| matches!(k, Kind::Exits | Kind::Relay);
        credit(Kind::Exits);
        record(Kind::Relay, ms(50));
        assert_eq!(order(usable).first(), Some(&Kind::Exits));

        // A refusal inside `PROOF_PROTECTS_FOR`: not evidence (D31).
        assert!(matches!(blame(Kind::Exits), Blamed::Proven(_)));
        assert!(
            is_proven(Kind::Exits),
            "a refusal that was not held against the route must not unprove it"
        );
        assert_eq!(
            order(usable).first(),
            Some(&Kind::Exits),
            "the route that answered must still be the one offered first"
        );

        // The user is still told it happened - that half was never the bug.
        let row = rows(usable)
            .into_iter()
            .find(|r| r.label == Kind::Exits.label())
            .expect("a row for the route");
        assert!(row.refused_ago.is_some(), "the report must still show it");
        assert_eq!((row.answers, row.refusals), (1, 1));
    }

    /// And the other way round, so the fix cannot quietly turn every refusal
    /// into a free one: once nothing protects the route, the refusal is
    /// evidence, the bench lands and the proof goes.
    #[test]
    fn an_unprotected_refusal_still_takes_the_proof_away() {
        let _turn = turn();
        set_context(0x7602);
        let usable = |k: Kind| matches!(k, Kind::Exits | Kind::Relay);
        credit(Kind::Exits);
        age_out_answer(Kind::Exits);
        assert!(matches!(blame(Kind::Exits), Blamed::Benched(_)));
        assert!(!is_proven(Kind::Exits));
        record(Kind::Relay, ms(50));
        assert_eq!(order(usable).first(), Some(&Kind::Relay));
    }

    /// The narrow cut: when one connection on a route is streaming an answer
    /// and the refusal arrived on a *different* one, that other one is closed
    /// and the streaming one is not. Anything else leaves the client retrying
    /// over a pooled connection that is being refused (D26) or cuts the answer
    /// in half (D32) - the two halves of the same field report.
    #[test]
    fn only_the_refused_connection_is_cut_beside_a_live_answer() {
        let _turn = turn();
        use std::io::{ErrorKind, Read};
        use std::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bound");
        let addr = listener.local_addr().expect("addr");

        // Two gate tunnels on one route, the way a client's pool makes them.
        let mut open_one = |host: &'static str| {
            let far = TcpStream::connect(addr).expect("connected");
            let (near, _) = listener.accept().expect("accepted");
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let _gate = begin_gate_connection(&near, host);
                note_used(Kind::Exits);
                tx.send(attribute_tunnel(Instant::now(), Some(host))).ok();
                let mut buf = [0u8; 1];
                let mut near = near;
                let _ = near.read(&mut buf);
            });
            let (_, id) = rx.recv().expect("opened").expect("attributed");
            (far, id, thread)
        };
        let (mut answering, answering_id, t1) = open_one("daily-cloudcode-pa.googleapis.com");
        let (mut refused, refused_id, t2) = open_one("cloudcode-pa.googleapis.com");
        assert_ne!(answering_id, refused_id);

        set_context(0x7603);
        credit(Kind::Exits);
        credit_tunnel(answering_id);

        // The refusal came in on the sibling.
        assert!(matches!(blame(Kind::Exits), Blamed::Streaming { .. }));
        assert!(cut_tunnel(refused_id), "the refused connection must be cut");
        assert!(
            !cut_tunnel(answering_id),
            "the connection carrying the answer must never be cut"
        );

        refused.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut buf = [0u8; 1];
        assert!(
            matches!(refused.read(&mut buf), Ok(0) | Err(_)),
            "the refused connection is still open"
        );
        answering
            .set_read_timeout(Some(Duration::from_millis(250)))
            .ok();
        let got = answering.read(&mut buf);
        assert!(
            matches!(&got, Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)),
            "the answer's own connection was cut: {got:?}"
        );

        // `tunnel_shape` is what the log line reads to tell the two apart.
        assert!(tunnel_shape(answering_id)
            .expect("a shape")
            .answered_ago
            .is_some());
        assert!(tunnel_shape(refused_id)
            .expect("a shape")
            .answered_ago
            .is_none());

        answering.shutdown(std::net::Shutdown::Both).ok();
        t1.join().expect("first tunnel");
        t2.join().expect("second tunnel");
    }

    /// Both directions count as activity: a long chat is a 100 KB upload before
    /// it is an answer (field: `116225 B out` against `4253 B to client`).
    #[test]
    fn a_tunnels_activity_counts_both_directions() {
        let a = Activity::default();
        assert!(a.idle().is_none(), "nothing has moved yet");
        assert_eq!(a.bytes(), (0, 0));
        a.to_upstream(116_225);
        assert_eq!(a.bytes(), (0, 116_225));
        assert!(a.idle().is_some_and(|d| d < Duration::from_secs(1)));
        a.to_client(4_253);
        assert_eq!(a.bytes(), (4_253, 116_225));
    }
}
