//! The route table: every way a gate host can be reached, what each was last
//! measured at, and the order the proxy should try them in.
//!
//! Why a table and not a ladder. The proxy used to try its routes in a fixed
//! order - own proxy, built-in exit, relay, direct - and the order was a guess
//! about speed that the measurements then contradicted: the direct tunnel to a
//! substituted address answered in 0.28 s while the relay it sat *below* took
//! 0.40-0.80 s (kb/rivals.md Fact 3). A DNS race is not a speed measurement and
//! neither is a list, so every route is timed on the warm loop with the same
//! request, and the proxy walks them fastest first.
//!
//! Two rules that are not about speed sit on top of the measurement:
//! - the user's own proxy stays first whenever it is usable. They typed it in;
//!   silently overriding what somebody configured is not an optimisation.
//! - a route that just carried a request Google answered with the region 400 is
//!   penalised for a while (`ls_log`). That refusal is the one fact no probe
//!   can see - it arrives inside the client's own TLS - so when the client's
//!   log shows it, the route it came through goes to the back of the line.
//!
//! Switching has hysteresis: a challenger takes the lead only when it is faster
//! by a clear margin, so two routes measuring within noise of each other do not
//! trade places every pass. Nothing here re-routes a live tunnel - the order is
//! consulted per `CONNECT`, and a connection already established keeps the
//! route it was opened on (I35). That is what makes "switch only when nothing
//! is in flight" hold by construction rather than by a timer.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The routes a gate host can take, as the proxy knows them. `Exits` is the
/// whole built-in pool: which exit inside it answers is that module's business,
/// and the table measures the pool as one route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Own,
    Exits,
    Relay,
    Direct,
}

impl Kind {
    fn index(self) -> usize {
        match self {
            Kind::Own => 0,
            Kind::Exits => 1,
            Kind::Relay => 2,
            Kind::Direct => 3,
        }
    }

    /// How the route is named in the log. Never an address (I46).
    pub fn label(self) -> &'static str {
        match self {
            Kind::Own => "свой прокси",
            Kind::Exits => "встроенный выход",
            Kind::Relay => "релей",
            Kind::Direct => "напрямую",
        }
    }
}

/// The order before anything has been measured. Direct first because that is
/// what the last round of measurements found fastest, and the relay last because
/// it is the one route somebody else can revoke.
///
/// A build without a DNS layer (Linux) has no substituted address for the direct
/// tunnel to reach, so there it goes to the back regardless; see `order_with`.
const DEFAULT_ORDER: [Kind; 4] = [Kind::Own, Kind::Direct, Kind::Exits, Kind::Relay];

/// A measurement older than this says nothing about the route now. Probes run
/// every two minutes; three misses in a row and the route is unmeasured again.
const SAMPLE_TTL: Duration = Duration::from_secs(15 * 60);

/// How much faster a challenger must measure to take the lead, in percent.
/// Twenty: the measured spread between two probes of one healthy route is
/// under that, and swapping routes for a difference nobody would notice costs a
/// cold connection to a proxy that was idle.
const SWITCH_MARGIN_PCT: u64 = 20;

/// How long a route that carried a region 400 stays at the back of the line.
/// Long enough that the client's pooled connections to it have expired and a
/// retry actually takes another route; short enough that a proxy whose exit
/// rotated back into a usable region is not written off for the session.
pub const REGION_PENALTY: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Copy)]
struct Sample {
    latency: Duration,
    at: Instant,
}

/// Everything the table knows, behind one lock: consulted on the path of every
/// gate connection, so the lock is taken once and released immediately.
struct Table {
    samples: [Option<Sample>; 4],
    penalised: [Option<Instant>; 4],
    /// The route the last `refresh_leader` put first, for the hysteresis.
    leader: Option<Kind>,
    /// The route that most recently opened a gate tunnel, and when. This is how
    /// a region 400 seen in the client's log is attributed.
    last_used: Option<(Kind, Instant)>,
}

static TABLE: Mutex<Table> = Mutex::new(Table {
    samples: [None; 4],
    penalised: [None; 4],
    leader: None,
    last_used: None,
});

/// Records one measurement of a route. Blended with the previous fresh one, so
/// a single slow probe does not by itself hand the lead to somebody else.
pub fn record(kind: Kind, latency: Duration) {
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
}

/// Forgets what was measured: the route failed its probe, so whatever it was
/// timed at last time is not what a request would meet now.
pub fn record_failure(kind: Kind) {
    if let Ok(mut t) = TABLE.lock() {
        t.samples[kind.index()] = None;
    }
}

/// The route's last fresh measurement, if it has one.
#[cfg_attr(not(test), allow(dead_code))]
pub fn latency(kind: Kind) -> Option<Duration> {
    let t = TABLE.lock().ok()?;
    fresh(&t.samples, kind)
}

fn fresh(samples: &[Option<Sample>; 4], kind: Kind) -> Option<Duration> {
    samples[kind.index()]
        .filter(|s| s.at.elapsed() < SAMPLE_TTL)
        .map(|s| s.latency)
}

/// Sends a route to the back of the line for `REGION_PENALTY`.
pub fn penalise(kind: Kind) {
    if let Ok(mut t) = TABLE.lock() {
        t.penalised[kind.index()] = Some(Instant::now() + REGION_PENALTY);
    }
}

pub fn is_penalised(kind: Kind) -> bool {
    TABLE
        .lock()
        .ok()
        .is_some_and(|t| penalised(&t.penalised, kind))
}

fn penalised(list: &[Option<Instant>; 4], kind: Kind) -> bool {
    list[kind.index()].is_some_and(|until| Instant::now() < until)
}

/// Notes that a gate tunnel was just opened on `kind`. Called where the `200`
/// goes out, i.e. once the route is the one the client is actually on.
pub fn note_used(kind: Kind) {
    if let Ok(mut t) = TABLE.lock() {
        t.last_used = Some((kind, Instant::now()));
    }
}

/// The route the most recent gate tunnel went through, and how long ago.
pub fn last_used() -> Option<(Kind, Duration)> {
    let t = TABLE.lock().ok()?;
    t.last_used.map(|(k, at)| (k, at.elapsed()))
}

/// The order to try routes in for the next connection, best first, among those
/// `usable` says are worth trying at all.
///
/// The table is copied out from under its lock before `usable` is consulted:
/// `usable` asks this module questions of its own (`is_penalised`), and a
/// non-reentrant lock held across that call deadlocked the very first live
/// connection.
pub fn order(usable: impl Fn(Kind) -> bool) -> Vec<Kind> {
    let (samples, penalised, leader) = snapshot();
    order_with(
        &samples,
        &penalised,
        leader,
        cfg!(target_os = "windows"),
        usable,
    )
}

/// What the table holds right now, without holding it.
fn snapshot() -> ([Option<Sample>; 4], [Option<Instant>; 4], Option<Kind>) {
    match TABLE.lock() {
        Ok(t) => (t.samples, t.penalised, t.leader),
        Err(_) => ([None; 4], [None; 4], None),
    }
}

/// The route sitting first right now, or `None` before the first pass has
/// picked one. Read by the record the window shows (`gate`).
pub fn leader() -> Option<Kind> {
    snapshot().2
}

/// Re-derives the leader from the latest measurements and says so in the log
/// when it changed. Run once per warm pass, after the probes.
pub fn refresh_leader(usable: impl Fn(Kind) -> bool) {
    let (samples, penalised, leader) = snapshot();
    let order = order_with(
        &samples,
        &penalised,
        leader,
        cfg!(target_os = "windows"),
        usable,
    );
    let Some(&best) = order.first() else {
        return;
    };
    if leader == Some(best) {
        return;
    }
    if let Ok(mut t) = TABLE.lock() {
        t.leader = Some(best);
    }
    let describe = |k: Kind| match fresh(&samples, k) {
        Some(d) => format!("{} ({} мс)", k.label(), d.as_millis()),
        None => format!("{} (не измерен)", k.label()),
    };
    let line = match leader {
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
/// Own first when usable. Then, of the rest: penalised routes last; unmeasured
/// routes after measured ones, in default order; measured ones by latency,
/// except that the current leader keeps its place unless the challenger beats
/// it by `SWITCH_MARGIN_PCT`. Without a DNS layer the direct tunnel has nothing
/// substituted to reach, so it goes last whatever it measured.
fn order_with(
    samples: &[Option<Sample>; 4],
    penalty: &[Option<Instant>; 4],
    leader: Option<Kind>,
    has_dns_layer: bool,
    usable: impl Fn(Kind) -> bool,
) -> Vec<Kind> {
    let mut out: Vec<Kind> = Vec::with_capacity(4);
    if usable(Kind::Own) {
        out.push(Kind::Own);
    }

    let rest: Vec<Kind> = DEFAULT_ORDER
        .iter()
        .copied()
        .filter(|k| *k != Kind::Own && usable(*k))
        .collect();

    // Three tiers, each keeping the default order inside itself: fine, then
    // unmeasured, then penalised. Direct without a DNS layer counts as penalised.
    let tier = |k: Kind| -> u8 {
        if penalised(penalty, k) || (k == Kind::Direct && !has_dns_layer) {
            2
        } else if fresh(samples, k).is_none() {
            1
        } else {
            0
        }
    };
    let mut measured: Vec<(Kind, Duration)> = rest
        .iter()
        .copied()
        .filter(|k| tier(*k) == 0)
        .filter_map(|k| fresh(samples, k).map(|d| (k, d)))
        .collect();
    measured.sort_by_key(|(_, d)| *d);

    // Hysteresis: the sitting leader stays ahead of a challenger that is not
    // clearly faster.
    if let Some(lead) = leader {
        if let Some(lead_pos) = measured.iter().position(|(k, _)| *k == lead) {
            if lead_pos > 0 {
                let lead_ms = measured[lead_pos].1.as_millis() as u64;
                let best_ms = measured[0].1.as_millis() as u64;
                let clearly_faster =
                    best_ms.saturating_mul(100) < lead_ms.saturating_mul(100 - SWITCH_MARGIN_PCT);
                if !clearly_faster {
                    let item = measured.remove(lead_pos);
                    measured.insert(0, item);
                }
            }
        }
    }

    out.extend(measured.iter().map(|(k, _)| *k));
    out.extend(rest.iter().copied().filter(|k| tier(*k) == 1));
    out.extend(rest.iter().copied().filter(|k| tier(*k) == 2));
    out
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

    const NONE: [Option<Instant>; 4] = [None; 4];

    #[test]
    fn unmeasured_routes_take_the_default_order_direct_first() {
        let order = order_with(&[None; 4], &NONE, None, true, |_| true);
        assert_eq!(
            order,
            vec![Kind::Own, Kind::Direct, Kind::Exits, Kind::Relay]
        );
    }

    #[test]
    fn without_a_dns_layer_direct_goes_last_whatever_it_measured() {
        let mut samples = [None; 4];
        samples[Kind::Direct.index()] = sample(50);
        samples[Kind::Exits.index()] = sample(400);
        let order = order_with(&samples, &NONE, None, false, |k| k != Kind::Own);
        assert_eq!(order, vec![Kind::Exits, Kind::Relay, Kind::Direct]);
    }

    #[test]
    fn measured_routes_go_fastest_first_and_unmeasured_after_them() {
        let mut samples = [None; 4];
        samples[Kind::Relay.index()] = sample(1300);
        samples[Kind::Exits.index()] = sample(450);
        // Direct unmeasured, own absent.
        let order = order_with(&samples, &NONE, None, true, |k| k != Kind::Own);
        assert_eq!(order, vec![Kind::Exits, Kind::Relay, Kind::Direct]);
    }

    #[test]
    fn the_leader_keeps_its_place_unless_beaten_by_the_margin() {
        let mut samples = [None; 4];
        samples[Kind::Direct.index()] = sample(300);
        samples[Kind::Exits.index()] = sample(270);
        // 10% faster is inside the margin: direct stays.
        let order = order_with(&samples, &NONE, Some(Kind::Direct), true, |k| {
            k != Kind::Own
        });
        assert_eq!(order[0], Kind::Direct);
        // 40% faster is not.
        samples[Kind::Exits.index()] = sample(180);
        let order = order_with(&samples, &NONE, Some(Kind::Direct), true, |k| {
            k != Kind::Own
        });
        assert_eq!(order[0], Kind::Exits);
    }

    #[test]
    fn a_penalised_route_is_last_even_when_fastest() {
        let mut samples = [None; 4];
        samples[Kind::Direct.index()] = sample(100);
        samples[Kind::Relay.index()] = sample(1300);
        let mut penalty = NONE;
        penalty[Kind::Direct.index()] = Some(Instant::now() + ms(60_000));
        let order = order_with(&samples, &penalty, Some(Kind::Direct), true, |k| {
            k != Kind::Own
        });
        assert_eq!(order, vec![Kind::Relay, Kind::Exits, Kind::Direct]);
        // An expired penalty is no penalty.
        penalty[Kind::Direct.index()] = Some(Instant::now() - ms(1));
        let order = order_with(&samples, &penalty, None, true, |k| k != Kind::Own);
        assert_eq!(order[0], Kind::Direct);
    }

    #[test]
    fn the_users_own_proxy_is_first_whenever_it_is_usable() {
        let mut samples = [None; 4];
        samples[Kind::Own.index()] = sample(900);
        samples[Kind::Direct.index()] = sample(100);
        let order = order_with(&samples, &NONE, Some(Kind::Direct), true, |_| true);
        assert_eq!(order[0], Kind::Own);
        let order = order_with(&samples, &NONE, Some(Kind::Direct), true, |k| {
            k != Kind::Own
        });
        assert_eq!(order[0], Kind::Direct);
    }

    #[test]
    fn unusable_routes_are_not_offered_at_all() {
        let order = order_with(&[None; 4], &NONE, None, true, |k| k == Kind::Relay);
        assert_eq!(order, vec![Kind::Relay]);
        let order = order_with(&[None; 4], &NONE, None, true, |_| false);
        assert!(order.is_empty());
    }

    /// `usable` may ask the table questions of its own. This deadlocked once:
    /// `order` held the lock while `is_penalised` tried to take it, and the
    /// first live connection through the proxy never got its 200.
    #[test]
    fn ordering_may_consult_the_table_from_inside_usable() {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = done.clone();
        std::thread::spawn(move || {
            let _ = order(|k| !is_penalised(k) && latency(k).is_none() || true);
            refresh_leader(|k| !is_penalised(k));
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

    /// The static half, in one test because it shares process-wide state.
    #[test]
    fn the_table_records_blends_expires_and_attributes() {
        record_failure(Kind::Relay);
        assert_eq!(latency(Kind::Relay), None);
        record(Kind::Relay, ms(1000));
        assert_eq!(latency(Kind::Relay), Some(ms(1000)));
        record(Kind::Relay, ms(500));
        assert_eq!(
            latency(Kind::Relay),
            Some(ms(750)),
            "blended with the fresh one"
        );
        record_failure(Kind::Relay);
        assert_eq!(latency(Kind::Relay), None);

        note_used(Kind::Relay);
        let (k, ago) = last_used().expect("noted");
        assert_eq!(k, Kind::Relay);
        assert!(ago < Duration::from_secs(5));
    }
}
