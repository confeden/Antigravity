use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crate::dns_client;
use rustls::pki_types::ServerName;
use rustls::ClientConnection;

// Choosing an unblock resolver at query time instead of trusting one forever.
//
// Why this module exists: on 2026-08-24 xbox-dns.ru silently dropped
// `cloudcode-pa.googleapis.com` from the list of names it substitutes. Measured
// over a raw socket, it answers that name with the genuine Google address
// (172.217.x, TTL 300) while still substituting `generativelanguage` to its
// proxy (87.228.47.204, TTL 60). comss.one and geohide.ru had done the same.
// Nothing in the tool noticed: the relay forwarded, the NRPT rules applied, the
// answer arrived - it was simply not a substituted answer any more.
//
// A single hardcoded resolver cannot detect that, so the relay now asks every
// provider at once and, in parallel, a reference resolver that is known NOT to
// substitute anything. An answer equal to the reference is a passthrough, and
// the next provider is tried; an answer that differs is a real substitution.
// When a provider re-adds a name, or a new provider is added below, it starts
// being used with no code change and no release.

/// How a provider is reached.
///
/// The distinction is not cosmetic: `v4`/`v6` are also what an NRPT rule lists
/// as fallback nameservers (I5, I22), and Windows can only be pointed at a
/// plain resolver. A DoH endpoint answers no UDP query at all, so putting one
/// in a rule would hand a name a nameserver that never replies. That is
/// enforced structurally - a `Doh` provider carries **empty** `v4`/`v6`, so
/// `fallback_v4`, `all_v6` and `substituting_addrs` all skip it without needing
/// to know about transports - and asserted by `a_doh_provider_is_never_offered_
/// as_a_nameserver`.
pub enum Transport {
    /// Plain DNS on UDP:53, queried over a socket pinned to the ISP interface.
    Udp,
    /// DNS-over-HTTPS. Reachable only through the relay, never by Windows.
    Doh(&'static crate::doh::Endpoint),
}

/// One unblock service. Addresses are tried in order; the first that answers
/// speaks for the provider, so a dead front-end does not cost it the race.
pub struct Provider {
    pub name: &'static str,
    pub v4: &'static [&'static str],
    pub v6: &'static [&'static str],
    pub transport: Transport,
}

/// Services that substitute Google/AI endpoints for clients they geolocate to a
/// blocked region. All three were verified to answer over plain UDP:53 and to
/// front a real SNI proxy (see kb/dns.md); their lists differ and change
/// without notice, which is exactly why the choice is made per query.
/// The provider names, in pool order, for the window's per-provider switches.
///
/// Names only. The addresses stay where they are: a switch list is a new place
/// for them to be read out of, and what a user needs in order to turn one off is
/// the name they already see in the log line.
pub fn provider_names() -> Vec<&'static str> {
    PROVIDERS.iter().map(|p| p.name).collect()
}

pub const PROVIDERS: &[Provider] = &[
    // First on purpose. Measured 2026-08-30 against 8.8.8.8: it substitutes
    // `cloudcode-pa.googleapis.com` -> 186.246.45.126 (TTL 60), and that address
    // accepts the SNI and answers as Google's own frontend (`Server: ESF`, valid
    // certificate, TLS handshake 0.30 s). `cloudcode-pa` is the name a 22-resolver
    // sweep found **nobody** substituting (S9) - the whole reason the client used
    // to be pushed onto `daily-` instead (N15). It substitutes `daily-` and
    // `generativelanguage` from the same address, and correctly passes
    // `jetski-webchannel` through, so it is not a blanket rewriter.
    //
    // `v4`/`v6` are empty because it speaks **only** DoH over HTTP/2 - HTTP/1.1
    // gets a 505 and its two addresses answer nothing on UDP:53. See `Transport`
    // for why that emptiness is load-bearing rather than an omission.
    Provider {
        name: "dns-ai.ru",
        v4: &[],
        v6: &[],
        transport: Transport::Doh(&DNS_AI),
    },
    Provider {
        name: "comss.one",
        v4: &["83.220.169.155", "212.109.195.93", "195.133.25.16"],
        v6: &[],
        transport: Transport::Udp,
    },
    Provider {
        name: "geohide.ru",
        v4: &["45.155.204.190", "37.230.192.51"],
        v6: &["2a0c:9300:0:54::1"],
        transport: Transport::Udp,
    },
    // Last on purpose (owner). It returns genuine Google for the two gate hosts
    // (kb/routes.md), so it never wins a race as `Substituted` and its place at
    // the back costs the pool nothing; and its resolver is a third party's, so
    // leaning on it least is the same "considerate guest" rule the relay now
    // follows. It stays in the pool - it still recognises an unsubstituted answer
    // - but sits at the tail of the compiled default order (rotation-off single
    // choice, the window's list, and tie-break preference all follow from this).
    Provider {
        name: "xbox-dns.ru",
        v4: &["111.88.96.50", "111.88.96.51"],
        v6: &["2a00:ab00:1233:26::50", "2a00:ab00:1233:26::51"],
        transport: Transport::Udp,
    },
];

/// Addresses are the two `dns.dns-ai.ru` resolves to, hardcoded so the relay can
/// reach it before anything else resolves. Safe because the certificate still has
/// to prove the name (`*.dns-ai.ru`, verified live), so a stale or poisoned
/// address fails the handshake instead of becoming a silent man-in-the-middle.
pub static DNS_AI: crate::doh::Endpoint = crate::doh::Endpoint {
    host: "dns.dns-ai.ru",
    path: "/dns-query",
    addrs: &["217.60.10.20", "186.246.49.127"],
};

/// Resolvers used only to recognise an unsubstituted answer. They must be
/// services with no geo-unblocking of their own - that is the whole point of
/// the comparison - and are never used to answer the client.
pub const REFERENCE_V4: &[&str] = &["8.8.8.8", "1.1.1.1"];

/// Addresses the DPI on the ISP link injects instead of the real answer for
/// some names (measured: both 1.1.1.1 and 8.8.8.8 return this pair for
/// `example.com` and `chatgpt.com` over that link). A reference poisoned this
/// way would make every provider look like it substituted, so these are dropped
/// before the comparison and an all-stub reference counts as no reference.
const REFERENCE_STUBS: &[Ipv4Addr] = &[Ipv4Addr::new(8, 6, 112, 0), Ipv4Addr::new(8, 47, 69, 0)];

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

/// How long a decision is reused before the providers are raced again. Short
/// enough to pick up a list change within minutes, long enough that the routed
/// names - which Windows re-asks every 60 s, the substituted TTL - cost one
/// upstream query each rather than a fan-out to every provider.
const CHOICE_TTL: Duration = Duration::from_secs(5 * 60);

/// Budget for a full race. The Windows DNS client gives a nameserver about a
/// second before moving to the next one in the NRPT rule, and that fallback is
/// a direct provider query whose unsubstituted answer would then be cached for
/// its full TTL. Providers answer in 30-80 ms, so this is generous and still
/// well inside that window.
const RACE_BUDGET: Duration = Duration::from_millis(700);

/// Timeout for a single upstream query once a provider has been chosen.
const QUERY_TIMEOUT: Duration = Duration::from_secs(4);

/// Timeout for that same query when a client is waiting on it.
///
/// The full `QUERY_TIMEOUT` is right for a racer that nothing blocks on, and
/// wrong for the fast path: a provider that goes quiet - measured on geohide,
/// which drops whole query rounds - would hold the client for 4 s per address
/// while Windows, which waits about one, has long since asked the fallback
/// nameserver instead. A provider that has not answered in 250 ms has lost, and
/// the race that follows is budgeted, so the two together stay inside the
/// second.
const FAST_PATH_TIMEOUT: Duration = Duration::from_millis(250);

/// The floor a DoH provider gets on the fast path, in place of
/// `FAST_PATH_TIMEOUT`.
///
/// 250 ms is right for a UDP one-shot and impossible for DoH: the TLS handshake
/// alone measured 0.29 s, so the chosen provider would fail every time, be
/// forgotten, and re-race - the fast path turned into its own slow path. A full
/// DoH exchange measured ~0.35 s, and this still leaves most of the second
/// Windows waits before it asks the fallback nameserver (I23).
const DOH_FAST_TIMEOUT: Duration = Duration::from_millis(600);

/// How long a race will hold a decided answer waiting for the preferred
/// provider. Inside `RACE_BUDGET`, and sized by the same ~0.35 s measurement.
const PREFERRED_GRACE: Duration = Duration::from_millis(500);

/// Names worth waiting a moment longer for the preferred provider on: the two
/// hosts the gate actually lives on.
const PREFERRED_NAMES: &[&str] = &[
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
];

/// How long a vetted answer is handed straight back out of memory.
///
/// This is not about saving upstream queries. Windows gives the relay about a
/// second before it moves to the next nameserver in the NRPT rule, and that one
/// is a provider's own resolver, whose answer nothing has vetted: measured,
/// 2 cold resolutions of `daily-cloudcode-pa` in 6 fell through that way and
/// came back carrying geohide's black-holed `95.182.120.241`, which then cost
/// the client ~21 s on its first connection. An answer already in memory is
/// returned in microseconds, so the fall-through never happens.
///
/// Public because the relay's warm loop has to run inside it: the two together
/// are the guarantee, and a cadence longer than this window would leave gaps in
/// which a client query still pays for a cold resolution.
pub const ANSWER_TTL: Duration = Duration::from_secs(30);

/// How long a vetted answer is still better than nothing. While a provider is
/// quiet the alternative is not a fresher answer, it is the unvetted fallback -
/// so a substituted answer from minutes ago wins. Only substitutions are served
/// stale: prolonging a passthrough would keep the region gate shut for no gain,
/// and there the fallback (a measured substituter, I22) is the better degradation.
const ANSWER_STALE_TTL: Duration = Duration::from_secs(5 * 60);

/// An entry no client has asked for in this long is dropped, so the warm loop
/// stops refreshing a question shape nobody sends any more.
const ANSWER_IDLE: Duration = Duration::from_secs(10 * 60);

/// The longest a *non-substituted* answer may live in the client's cache.
///
/// A TTL is the resolver's opinion about its own answer, and these resolvers
/// disagree wildly: geohide substitutes `daily-cloudcode-pa` with TTL 60, while
/// comss returns the genuine Google address for the same name with TTL 3199.
/// Hand that second one to Windows unchanged and one lost race pins the client
/// to an unsubstituted address for 53 minutes - the relay is never asked again,
/// and every CloudCode call for that hour leaves from the blocked region and
/// answers `User location is not supported`. Measured exactly that way.
///
/// So an answer that did not defeat the gate is only ever believed until the
/// next race, and the warm loop is what runs that race.
const PASSTHROUGH_TTL: u32 = 60;

/// A vetted reply, exactly as it went out to the client.
struct Answer {
    reply: Vec<u8>,
    provider: &'static str,
    verdict: Verdict,
    /// When the reply arrived from upstream - what the TTLs are counted from.
    at: Instant,
    /// `ANSWER_TTL`, or the resolver's own TTL when that is shorter.
    good_for: Duration,
    /// Last time a *client* asked this exact question, as opposed to the warm
    /// loop refreshing it.
    wanted: Instant,
}

/// Vetted answers, keyed by the client's query with its transaction id zeroed.
///
/// Keyed by the whole query rather than by (name, qtype) on purpose: a reply is
/// only valid for the exact question that produced it - same flags, same EDNS
/// options, same spelling of the name - and reusing it for a differently shaped
/// question would mean rebuilding a message this module deliberately never
/// rebuilds. The cost is that an unusual client shape simply misses the cache.
static ANSWERS: Mutex<Option<HashMap<Vec<u8>, Answer>>> = Mutex::new(None);

/// Names every one of these services exists to unblock. Asking a provider for
/// one is how the relay learns what that provider's proxy address actually
/// looks like, instead of trying to recognise Google's netblocks - which span a
/// dozen unrelated /8s and change.
///
/// The answer is only believed when it differs from what the reference resolver
/// says for the same name, so a provider that stops proxying a control name
/// yields an empty set rather than teaching the relay that Cloudflare is a
/// proxy.
///
/// Several names, used in rotation, for two reasons. This source is public, so
/// a provider can read exactly what the relay asks and when: one fixed control
/// name is a crisp signature and a single point to special-case. And they are
/// deliberately spread across unrelated operators (Cloudflare, Anthropic,
/// Google), so no single upstream change takes the whole set out. All five were
/// measured proxied by all three providers.
///
/// Avoid `grok.com` here: the DPI on the ISP link answers it with the stub pair,
/// so the reference is unusable and nothing can be learned from it.
const CONTROL_NAMES: &[&str] = &[
    "chatgpt.com",
    "api.openai.com",
    "claude.ai",
    "gemini.google.com",
    "ai.google.dev",
];

/// How long learned proxy addresses are kept. Long, because they are stable and
/// the set is a union: geohide rotates between three addresses in three
/// unrelated /16s, so a single probe only ever sees part of it.
const PROXY_SET_TTL: Duration = Duration::from_secs(30 * 60);

/// Proxy addresses learned per provider, with the moment the entry was last
/// refreshed.
static PROXY_SET: Mutex<Option<HashMap<usize, (Vec<IpAddr>, Instant)>>> = Mutex::new(None);

/// A substituted address is only useful if the client can actually open a TLS
/// connection to it, and that does not follow from answering DNS: geohide hands
/// out three proxy addresses for `daily-cloudcode-pa` and any of them may be
/// silently dropping SYNs on 443. Handing a dead one to the client costs ~20 s
/// on the first connection - Windows' SYN retransmission budget - before it
/// falls through to a live address. So substituted addresses are probed on the
/// port the client will use, and the dead ones are cut out of the answer.
const LIVENESS_PORT: u16 = 443;
/// Probed on the default route rather than the ISP interface: DNS has to dodge
/// the tunnel, but the client's own connection will not, so this must ask the
/// question the client is going to ask.
const LIVENESS_BUDGET: Duration = Duration::from_millis(500);
/// The same probe on the warm loop, where nothing is waiting on it.
///
/// 500 ms was chosen when a live proxy connected in ~35 ms. On a slower hour the
/// same addresses answered in 124-928 ms, so the tight budget started reporting
/// live-but-slow addresses as dead and cutting them out - the answer shrank from
/// three proxies to one, which is the opposite of the redundancy this is for.
/// Off the client's path there is no reason to be mean about it.
const LIVENESS_BUDGET_WARM: Duration = Duration::from_millis(2500);
/// How long "this address answered" is believed.
///
/// Was ten minutes, on the assumption that a working proxy keeps working. It
/// does not: measured three times inside one hour, geohide's three addresses
/// swapped which of them was dead each time - all three alive, then
/// `37.230.192.51` gone, then `45.155.204.190` gone. A ten-minute verdict meant
/// the relay kept advertising an address that had died nine minutes ago, which
/// is exactly the 20 s stall this whole probe exists to prevent (`State refresh
/// took 17697ms` in the language server's log). Short enough now that the warm
/// loop re-probes on almost every pass.
const LIVENESS_TTL_ALIVE: Duration = Duration::from_secs(20);
/// Short, so an address that comes back is used again within a minute or two
/// rather than being written off for the rest of the session.
const LIVENESS_TTL_DEAD: Duration = Duration::from_secs(60);

static LIVENESS: Mutex<Option<HashMap<IpAddr, (bool, Instant)>>> = Mutex::new(None);

/// Rotates which provider wins a tie, so equally good providers share the load
/// instead of the first entry serving everything.
static ROTATION: AtomicUsize = AtomicUsize::new(0);

/// Winning provider per (name, qtype), with the verdict that won it and the
/// moment it was decided. The verdict is remembered too, so a cache hit can
/// still tell a caller whether the answer it is about to use was substituted.
static CHOICE: Mutex<Option<HashMap<(String, u16), (usize, Verdict, Instant)>>> = Mutex::new(None);

/// Every provider's IPv6 addresses, in provider order. The NRPT rule takes
/// these only when the relay is off - with the relay up a v6 nameserver would
/// let Windows send the query straight out, skipping the relay entirely.
pub fn all_v6() -> Vec<&'static str> {
    let mut list: Vec<&'static str> = in_user_order()
        .into_iter()
        .filter(|p| !denied(p.name))
        .flat_map(|p| p.v6.iter().copied())
        .collect();
    if !crate::settings::rotation_enabled() {
        // Rotation off narrows the nameserver list too, or Windows would still
        // be pointed at providers the user took out of the pool.
        list.truncate(1);
    }
    list
}

/// One address per provider - what goes into an NRPT rule. Windows tries the
/// nameservers in order, so listing every address of one provider ahead of the
/// next provider would make a provider outage look like a total failure.
pub fn fallback_v4() -> Vec<&'static str> {
    // Filtered by the deny-list only, *then* truncated: the head of `PROVIDERS`
    // speaks DoH and carries no UDP address at all (I49), so narrowing by name
    // first would leave Windows a rule with no nameserver in it. Truncating the
    // assembled addresses picks the first enabled provider that actually has
    // one, which is what a nameserver list needs.
    // Windows tries nameservers in the order given, so the user's order is what
    // decides which service sees a lookup first.
    let mut list: Vec<&'static str> = in_user_order()
        .into_iter()
        .filter(|p| !denied(p.name))
        .filter_map(|p| p.v4.first().copied())
        .collect();
    if !crate::settings::rotation_enabled() {
        list.truncate(1);
    }
    list
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Outside every netblock the reference answered from - a proxy address.
    Substituted,
    /// A different address in the same netblock family. Google rotates its edge
    /// per query and per resolver, so this is almost always just another
    /// genuine Google address, not a substitution.
    Sibling,
    /// The same netblock the reference gave: a passthrough.
    Passthrough,
    /// No usable reference, or no addresses to compare.
    Unknown,
}

/// The netblock an address belongs to, coarse enough that Google's per-query
/// edge rotation does not look like a change: a /16 for IPv4, a /32 for IPv6.
fn block(addr: &IpAddr) -> (u8, u32) {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (4, u32::from_be_bytes([o[0], o[1], 0, 0]))
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            (6, u32::from_be_bytes([o[0], o[1], o[2], o[3]]))
        }
    }
}

/// Decides what a provider's answer is worth, given what an honest resolver
/// says for the same name (`reference`) and which addresses that provider is
/// known to hand out as its proxy (`proxy`, from `learn_proxy_addrs`).
///
/// Both inputs are needed, and this is the whole subtlety of the module.
/// Comparing against the reference alone marks `oauth2.googleapis.com` as
/// substituted whenever a provider's recursion lands on 173.194.0.0/16 while
/// the reference landed on 64.233.0.0/16 - both are plain Google, reached
/// through different edges. Nothing about the address itself separates those
/// two cases: Google's netblocks span a dozen unrelated /8s, and reverse DNS
/// does not help either (measured: 172.217.113.4, a perfectly genuine Google
/// answer, has no PTR at all, and neither does the geohide proxy). So the
/// proxy address is measured instead of guessed - see `learn_proxy_addrs`.
///
/// With no proxy knowledge yet, "differs from the honest answer" is the best
/// evidence available and is taken at face value. That is the behaviour the
/// tool had before, and it can only ever prefer a different answer to an
/// identical one - never a passthrough.
pub fn classify(candidate: &[IpAddr], reference: &[IpAddr], proxy: &[IpAddr]) -> Verdict {
    if candidate.is_empty() {
        return Verdict::Unknown;
    }
    let reference: Vec<&IpAddr> = reference
        .iter()
        .filter(|a| match a {
            IpAddr::V4(v4) => !REFERENCE_STUBS.contains(v4),
            IpAddr::V6(_) => true,
        })
        .collect();
    if reference.is_empty() {
        return Verdict::Unknown;
    }
    // Only compare within a family: an AAAA answer says nothing about the A
    // records the reference happened to return.
    let families: Vec<u8> = candidate.iter().map(|a| block(a).0).collect();
    let comparable: Vec<&&IpAddr> = reference
        .iter()
        .filter(|a| families.contains(&block(a).0))
        .collect();
    if comparable.is_empty() {
        return Verdict::Unknown;
    }

    let ref_blocks: Vec<(u8, u32)> = comparable.iter().map(|a| block(a)).collect();
    if candidate.iter().any(|a| ref_blocks.contains(&block(a))) {
        return Verdict::Passthrough;
    }
    if proxy.is_empty() {
        return Verdict::Substituted;
    }
    let proxy_blocks: Vec<(u8, u32)> = proxy.iter().map(block).collect();
    if candidate.iter().any(|a| proxy_blocks.contains(&block(a))) {
        return Verdict::Substituted;
    }
    Verdict::Sibling
}

/// How much a verdict is worth when picking a winner.
fn rank(v: Verdict) -> u8 {
    match v {
        Verdict::Substituted => 3,
        Verdict::Unknown => 2,
        Verdict::Sibling => 1,
        Verdict::Passthrough => 0,
    }
}

fn cached_liveness(addr: &IpAddr) -> Option<bool> {
    let guard = LIVENESS.lock().ok()?;
    let (alive, at) = guard.as_ref()?.get(addr)?;
    let ttl = if *alive {
        LIVENESS_TTL_ALIVE
    } else {
        LIVENESS_TTL_DEAD
    };
    (at.elapsed() < ttl).then_some(*alive)
}

fn remember_liveness(addr: IpAddr, alive: bool) {
    if let Ok(mut guard) = LIVENESS.lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert(addr, (alive, Instant::now()));
    }
}

/// Whether `addr` will actually serve `sni` inside `budget`.
///
/// TCP alone is not the question the client asks. Measured within one minute on
/// one machine: one provider's proxy accepted TCP in 34 ms and then spent 10.5 s
/// on the TLS handshake, while another did the whole handshake in 249 ms. A
/// TCP-only probe calls both healthy and the client pays the difference.
///
/// With `sni` set the handshake is also the **security** check: rustls validates
/// the chain against the public roots and the name against the certificate, so
/// an address that fronts anything other than a genuine Google endpoint fails
/// here rather than in the client. That is why the three "could not even try"
/// paths below answer `false`: giving an unverifiable address the benefit of the
/// doubt is exactly the doubt the check exists to remove.
///
/// With no `sni` — the user switched the check off — it falls back to the
/// connection alone.
fn reachable(addr: IpAddr, budget: Duration, sni: Option<&str>) -> bool {
    let Ok(sock) =
        std::net::TcpStream::connect_timeout(&SocketAddr::new(addr, LIVENESS_PORT), budget)
    else {
        return false;
    };
    let Some(name) = sni else {
        return true;
    };
    let Ok(server) = ServerName::try_from(name.to_string()) else {
        return false;
    };
    let Ok(mut conn) = ClientConnection::new(crate::proxy::probe_config(), server) else {
        return false;
    };
    sock.set_read_timeout(Some(budget)).ok();
    sock.set_write_timeout(Some(budget)).ok();
    let mut sock = sock;
    let deadline = Instant::now() + budget;
    // Driven by hand rather than through `Stream`, so the budget covers the whole
    // handshake and not each syscall inside it.
    while conn.is_handshaking() {
        if Instant::now() >= deadline {
            return false;
        }
        if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
            return false;
        }
        if conn.wants_read() {
            match conn.read_tls(&mut sock) {
                Ok(0) => return false,
                Ok(_) => {
                    if conn.process_new_packets().is_err() {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
    }
    true
}

/// The addresses among `addrs` that will not accept a connection.
///
/// A live proxy completes the handshake in tens of milliseconds; a black hole
/// never answers at all, so the budget separates them without waiting out the
/// operating system's own retransmission schedule. Unknown-because-slow counts
/// as dead only for `LIVENESS_TTL_DEAD`, which is short on purpose.
///
/// `fresh` ignores what is already known and re-probes. The warm loop passes it
/// and a client query never does: the probe costs up to `LIVENESS_BUDGET`, which
/// is affordable on a timer and not while Windows is counting to one. It is what
/// keeps the cached verdict from outliving the thing it describes.
fn dead_addrs(addrs: &[IpAddr], fresh: bool, sni: Option<&str>) -> Vec<IpAddr> {
    let mut dead = Vec::new();
    let mut unknown = Vec::new();
    for a in addrs {
        match if fresh { None } else { cached_liveness(a) } {
            Some(true) => {}
            Some(false) => dead.push(*a),
            None => unknown.push(*a),
        }
    }
    if unknown.is_empty() {
        return dead;
    }

    // Generous when the warm loop is asking, tight when a client is waiting.
    let budget = if fresh {
        LIVENESS_BUDGET_WARM
    } else {
        LIVENESS_BUDGET
    };

    let (tx, rx) = mpsc::channel::<(IpAddr, bool)>();
    for a in &unknown {
        let tx = tx.clone();
        let addr = *a;
        // The switch is read here, at the one place the probe is started, so an
        // answer already in the liveness cache is not re-judged by a rule that
        // changed after it was measured — the cache entry expires on its own.
        let sni = if crate::settings::verify_tls_enabled() {
            sni.map(|s| s.to_string())
        } else {
            None
        };
        thread::spawn(move || {
            let ok = reachable(addr, budget, sni.as_deref());
            tx.send((addr, ok)).ok();
        });
    }
    drop(tx);

    let deadline = Instant::now() + budget;
    let mut answered: Vec<IpAddr> = Vec::new();
    while answered.len() < unknown.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok((addr, alive)) => {
                answered.push(addr);
                remember_liveness(addr, alive);
                if !alive {
                    dead.push(addr);
                }
            }
            Err(_) => break,
        }
    }
    // Whatever did not answer inside the budget is treated as dead for now. It
    // is not written off: the next query re-probes it after LIVENESS_TTL_DEAD.
    //
    // Tracked in a list rather than read back out of the cache: on the `fresh`
    // path the cache is exactly what is being distrusted, and a stale "alive"
    // sitting there would mask a probe that never came back - which is the bug
    // this whole parameter exists to fix.
    for a in unknown {
        if !answered.contains(&a) {
            remember_liveness(a, false);
            dead.push(a);
        }
    }
    dead
}

/// Cuts unreachable addresses out of a substituted answer.
///
/// Only substituted answers are filtered. A passthrough is Google's own edge
/// and needs no vetting, and probing it would put a TCP connection on every
/// name the relay ever sees for nothing.
fn drop_dead_addrs(reply: Vec<u8>, fresh: bool, sni: Option<&str>) -> Vec<u8> {
    let addrs = dns_client::answer_addrs(&reply);
    if addrs.len() < 2 {
        // With a single address there is nothing to fall through to, so
        // removing it would turn a slow answer into no answer.
        return reply;
    }
    let dead = dead_addrs(&addrs, fresh, sni);
    if dead.is_empty() {
        return reply;
    }
    dns_client::without_addrs(&reply, &dead).unwrap_or(reply)
}

/// What is currently known about a provider's proxy addresses.
fn known_proxy_addrs(idx: usize) -> Vec<IpAddr> {
    let Ok(guard) = PROXY_SET.lock() else {
        return Vec::new();
    };
    guard
        .as_ref()
        .and_then(|m| m.get(&idx))
        .filter(|(_, at)| at.elapsed() < PROXY_SET_TTL)
        .map(|(addrs, _)| addrs.clone())
        .unwrap_or_default()
}

/// True when a provider's proxy addresses need probing again.
fn proxy_addrs_are_stale(idx: usize) -> bool {
    let Ok(guard) = PROXY_SET.lock() else {
        return false;
    };
    guard
        .as_ref()
        .and_then(|m| m.get(&idx))
        .map_or(true, |(_, at)| at.elapsed() >= PROXY_SET_TTL)
}

/// Unions freshly seen proxy addresses into what is already known.
///
/// A union rather than a replacement: a provider that rotates between several
/// proxy addresses would otherwise look like it changed its proxy on every
/// probe, and an answer served from the address the last probe missed would be
/// classified as somebody else's.
fn learn_proxy_addrs(idx: usize, addrs: Vec<IpAddr>) {
    if addrs.is_empty() {
        return;
    }
    if let Ok(mut guard) = PROXY_SET.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        let entry = map
            .entry(idx)
            .or_insert_with(|| (Vec::new(), Instant::now()));
        for a in addrs {
            if !entry.0.contains(&a) {
                entry.0.push(a);
            }
        }
        entry.1 = Instant::now();
    }
}

fn cached_choice(key: &(String, u16)) -> Option<(usize, Verdict)> {
    let guard = CHOICE.lock().ok()?;
    let map = guard.as_ref()?;
    let (idx, verdict, at) = map.get(key)?;
    (at.elapsed() < CHOICE_TTL).then_some((*idx, *verdict))
}

fn remember_choice(key: (String, u16), idx: usize, verdict: Verdict) {
    if let Ok(mut guard) = CHOICE.lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert(key, (idx, verdict, Instant::now()));
    }
}

fn forget_choice(key: &(String, u16)) {
    if let Ok(mut guard) = CHOICE.lock() {
        if let Some(map) = guard.as_mut() {
            map.remove(key);
        }
    }
}

/// A query with its transaction id blanked, which is the only part of it that
/// changes between two askings of the same question.
fn answer_key(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut key = query.to_vec();
    key[0] = 0;
    key[1] = 0;
    Some(key)
}

/// A cached answer for `query`, re-stamped so it is a valid reply to *this*
/// asking: the client's transaction id, and TTLs counted down by however long
/// the reply has been sitting here.
fn cached_answer(
    query: &[u8],
    stale: bool,
    from_client: bool,
) -> Option<(Vec<u8>, &'static str, Verdict)> {
    let key = answer_key(query)?;
    let mut guard = ANSWERS.lock().ok()?;
    let hit = guard.as_mut()?.get_mut(&key)?;
    let age = hit.at.elapsed();
    let usable = if stale {
        hit.verdict == Verdict::Substituted && age < ANSWER_STALE_TTL
    } else {
        age < hit.good_for
    };
    if !usable {
        return None;
    }
    if from_client {
        hit.wanted = Instant::now();
    }
    let mut reply = dns_client::age_reply(&hit.reply, age.as_secs() as u32)?;
    reply[0..2].copy_from_slice(&query[0..2]);
    Some((reply, hit.provider, hit.verdict))
}

/// Stores what went out to the client, so the next asking costs nothing.
///
/// Only replies whose records can be walked are kept: a message this cannot age
/// is one it must not hand out later with a stale TTL, and refusing it here
/// keeps the serving path free of that decision.
fn remember_answer(
    query: &[u8],
    reply: &[u8],
    provider: &'static str,
    verdict: Verdict,
    from_client: bool,
) {
    let (Some(key), Some(ttl)) = (answer_key(query), dns_client::answer_ttl(reply)) else {
        return;
    };
    let Ok(mut guard) = ANSWERS.lock() else {
        return;
    };
    let map = guard.get_or_insert_with(HashMap::new);
    // A substitution still inside its stale window outranks a fresh answer that
    // is not one. Overwriting it would throw away the entry `prefer_substituted`
    // exists to serve, and one lost race would again become an hour of them.
    if verdict != Verdict::Substituted {
        if let Some(prev) = map.get(&key) {
            if prev.verdict == Verdict::Substituted && prev.at.elapsed() < ANSWER_STALE_TTL {
                return;
            }
        }
    }
    let now = Instant::now();
    // Read before the sweep below, or an entry evicted mid-refresh would come
    // back looking freshly wanted and never age out again.
    let wanted = match map.get(&key) {
        Some(prev) if !from_client => prev.wanted,
        _ => now,
    };
    map.insert(
        key,
        Answer {
            reply: reply.to_vec(),
            provider,
            verdict,
            at: now,
            good_for: ANSWER_TTL.min(Duration::from_secs(ttl.into())),
            wanted,
        },
    );
    map.retain(|_, a| a.wanted.elapsed() < ANSWER_IDLE);
}

/// The questions the warm loop should re-ask: every shape a client has actually
/// sent for one of `names`, and a plain A query for any name not yet seen.
///
/// Replaying the client's own bytes is what makes warming work at all - a
/// synthesised query is a different key, so its answer would sit in the cache
/// while every real query still went upstream.
fn warm_queries(names: &[&str]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut covered: Vec<String> = Vec::new();
    if let Ok(guard) = ANSWERS.lock() {
        if let Some(map) = guard.as_ref() {
            for key in map.keys() {
                let Some(name) = dns_client::question_name(key) else {
                    continue;
                };
                if names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                    covered.push(name);
                    out.push(key.clone());
                }
            }
        }
    }
    for n in names {
        if !covered.iter().any(|c| c.eq_ignore_ascii_case(n)) {
            out.push(dns_client::build_query(n, 0));
        }
    }
    out
}

/// Re-resolves the routed names off the client's critical path, so a query that
/// does arrive is answered out of memory instead of racing three providers and
/// probing addresses while Windows counts to one.
pub fn warm(names: &[&str], if_index: u32) {
    for mut query in warm_queries(names) {
        let id = ROTATION.fetch_add(1, Ordering::Relaxed) as u16;
        query[0..2].copy_from_slice(&id.to_be_bytes());
        refresh(&query, if_index);
    }
}

/// Sends `query` to every address of one provider in turn, stopping at the
/// first that answers.
/// Whether the user switched this provider off in the window.
///
/// Checked here, at the single point every racing path goes through, rather than
/// by rebuilding the candidate list in each of them — the loops index `PROVIDERS`
/// directly in half a dozen places and one of them would have been missed. A
/// provider that is off simply never answers, which is a state the race already
/// handles: it is what a dead front-end looks like.
///
/// The deny-list only ever *subtracts*, which is what keeps this safe: I22 says a
/// rule's fallbacks list only providers measured to substitute that name, and a
/// subset of a measured set is still measured. Adding one would not be.
///
/// Takes the settings cache's own lock and calls back into nothing, so it cannot
/// take part in the reentrancy that I50 forbids.
/// With rotation off, only this provider may answer: the first one in pool order
/// the user has not switched off.
///
/// Pool order, not "whichever answered last" — the list is ordered by measured
/// substitution, so its head is the one most likely to still be substituting.
fn only_provider() -> Option<&'static str> {
    let disabled = crate::settings::disabled_providers_cached();
    in_user_order()
        .into_iter()
        .map(|p| p.name)
        .find(|n| !disabled.iter().any(|d| d.eq_ignore_ascii_case(n)))
}

/// The pool laid out the way the user arranged it.
///
/// The compiled order is by measured substitution and is the default; a user who
/// dragged the list into a different order gets theirs. Anything they never
/// touched keeps its compiled position at the end, so a provider added in a later
/// release still appears instead of being silently dropped by a saved order that
/// predates it.
fn in_user_order() -> Vec<&'static Provider> {
    let wanted = crate::settings::provider_order_cached();
    if wanted.is_empty() {
        return PROVIDERS.iter().collect();
    }
    let mut out: Vec<&'static Provider> = Vec::new();
    for name in &wanted {
        if let Some(p) = PROVIDERS.iter().find(|p| p.name.eq_ignore_ascii_case(name)) {
            if !out.iter().any(|q| q.name == p.name) {
                out.push(p);
            }
        }
    }
    for p in PROVIDERS {
        if !out.iter().any(|q| q.name == p.name) {
            out.push(p);
        }
    }
    out
}

/// The providers that can be handed to Windows as a nameserver.
///
/// A DoH provider carries no UDP address by construction (I49), so it can answer
/// through the relay and still be useless in an NRPT rule. Leaving *only* those
/// enabled empties the rule's fallback list, and a rule with no nameserver is
/// worse than no rule at all — hence the guard in `ops`.
pub fn udp_provider_names() -> Vec<&'static str> {
    in_user_order()
        .into_iter()
        .filter(|p| !p.v4.is_empty())
        .map(|p| p.name)
        .collect()
}

/// The provider names in the user's order — what the window's list draws.
pub fn ordered_provider_names() -> Vec<&'static str> {
    in_user_order().into_iter().map(|p| p.name).collect()
}

/// Switched off by name in the window.
fn denied(name: &str) -> bool {
    crate::settings::disabled_providers_cached()
        .iter()
        .any(|d| d.eq_ignore_ascii_case(name))
}

fn provider_disabled(name: &str) -> bool {
    if denied(name) {
        return true;
    }
    // Rotation off: everything below the head of the list is treated exactly the
    // way a switched-off provider is, so the race, the fallback list and the
    // NRPT nameservers all narrow together instead of disagreeing.
    if !crate::settings::rotation_enabled() {
        return only_provider() != Some(name);
    }
    false
}

fn ask_provider(
    provider: &Provider,
    query: &[u8],
    if_index: u32,
    timeout: Duration,
) -> Option<Vec<u8>> {
    if provider_disabled(provider.name) {
        return None;
    }
    match provider.transport {
        Transport::Udp => {
            for server in provider.v4 {
                let Ok(ip) = server.parse::<Ipv4Addr>() else {
                    continue;
                };
                if let Ok(reply) = dns_client::query_raw_via(query, ip, if_index, timeout) {
                    return Some(reply);
                }
            }
            None
        }
        Transport::Doh(endpoint) => {
            let mut reply = crate::doh::query(endpoint, query, timeout).ok()?;
            // Re-stamp the transaction id. RFC 8484 tells a DoH client to send 0
            // and a server is free to answer with 0 whatever we asked with, but
            // the reply is handed to Windows over UDP:53, where an id that does
            // not match the question is simply dropped - a failure that would
            // look exactly like the resolver being slow. Nothing else in the
            // message is touched: the relay's contract is that it forwards the
            // provider's own bytes (I23).
            if reply.len() >= 2 && query.len() >= 2 {
                reply[0] = query[0];
                reply[1] = query[1];
            }
            Some(reply)
        }
    }
}

/// What one racer produced.
enum Heat {
    /// A provider's raw reply to the question the client asked.
    Provider(usize, Vec<u8>),
    /// An honest resolver's answer to the same question.
    Reference(Vec<IpAddr>),
    /// A provider's answer for `CONTROL_NAME`, i.e. its proxy address.
    Control(usize, Vec<IpAddr>),
    /// An honest resolver's answer for `CONTROL_NAME`, without which the line
    /// above cannot be believed.
    ControlReference(Vec<IpAddr>),
}

/// Whether a tunnel is carrying **the client's** traffic, as last seen by the
/// relay's warm loop (`VPN_CHECK_EVERY`).
///
/// The client's, not the machine's: a tunnel that holds a default route but
/// excludes `language_server.exe` must leave substitution on, or the rules
/// resolve to genuine Google and the gate answers 400 with the layer nominally
/// installed (G29). `egress::vpn_verdict` is what decides; this only stores it.
///
/// A plain flag rather than a parameter threaded through six call sites, and a
/// flag the *relay* sets rather than something this module probes: detection
/// shells out to PowerShell, and nothing that a client query waits on may do
/// that. Defaults to `false`, which is the pre-existing behaviour - a machine
/// that never learns the answer keeps substituting exactly as before.
static VPN_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Until when substitution is forced on regardless of the tunnel verdict.
///
/// Set by the region-400 watch (`ls_log`): the client was measured inside a
/// tunnel, the relay stood down for it, and the gate answered 400 anyway - so
/// the tunnel exits somewhere blocked and "the VPN decides" (D13) is the wrong
/// call for this tunnel. Substituting then sends the client to a provider's
/// proxy *through* the tunnel, which still lifts the gate. It is a window, not
/// a flag: the tunnel may be replaced by a permitted one, and when the window
/// closes the stand-down logic is back in charge until the log says otherwise.
static FORCE_SUBSTITUTE_UNTIL: Mutex<Option<Instant>> = Mutex::new(None);

/// How long one sighting of the region 400 keeps substitution forced on.
pub const FORCE_SUBSTITUTE_FOR: Duration = Duration::from_secs(30 * 60);

pub fn set_vpn_active(active: bool) {
    VPN_ACTIVE.store(active, Ordering::Relaxed);
}

/// Whether the relay is standing down for a tunnel right now. False while
/// substitution is forced, whatever the tunnel verdict says.
pub fn vpn_is_active() -> bool {
    VPN_ACTIVE.load(Ordering::Relaxed) && !substitution_forced()
}

/// The raw tunnel verdict, ignoring any force. For the log line that explains
/// why the relay is doing what it does.
pub fn tunnel_carries_client() -> bool {
    VPN_ACTIVE.load(Ordering::Relaxed)
}

pub fn force_substitution(for_how_long: Duration) {
    if let Ok(mut until) = FORCE_SUBSTITUTE_UNTIL.lock() {
        *until = Some(Instant::now() + for_how_long);
    }
}

pub fn substitution_forced() -> bool {
    FORCE_SUBSTITUTE_UNTIL
        .lock()
        .ok()
        .and_then(|u| *u)
        .is_some_and(|until| Instant::now() < until)
}

/// The verdict of the answer most recently handed out for each name, by the
/// client path or the warm loop alike. What the proxy asks when deciding
/// whether a direct tunnel to that name has anything substituted to reach.
static SERVED: Mutex<Option<HashMap<String, (Verdict, Instant)>>> = Mutex::new(None);

/// A served verdict older than this is forgotten: the warm loop refreshes every
/// routed name every 15 s, so a name unseen for minutes is one nobody asks for.
const SERVED_TTL: Duration = Duration::from_secs(10 * 60);

fn note_served(name: &str, verdict: Verdict) {
    if let Ok(mut guard) = SERVED.lock() {
        guard.get_or_insert_with(HashMap::new).insert(
            name.trim_end_matches('.').to_ascii_lowercase(),
            (verdict, Instant::now()),
        );
    }
}

/// What the relay last answered `name` with, if it answered recently.
pub fn served_verdict(name: &str) -> Option<Verdict> {
    let guard = SERVED.lock().ok()?;
    let (verdict, at) = guard
        .as_ref()?
        .get(&name.trim_end_matches('.').to_ascii_lowercase())?;
    (at.elapsed() < SERVED_TTL).then_some(*verdict)
}

/// Drops every remembered choice and cached answer for `names`, so the next
/// query - the warm loop's, within 15 s - races the providers from scratch.
///
/// The region-400 watch calls this: an answer that led to the gate is not one
/// to keep serving for the rest of its TTL, whoever gave it.
pub fn forget_names(names: &[&str]) {
    let wanted: Vec<String> = names
        .iter()
        .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    // The choice key carries the name as the client spelt it, so it is compared
    // case-folded rather than looked up.
    if let Ok(mut guard) = CHOICE.lock() {
        if let Some(map) = guard.as_mut() {
            map.retain(|(name, _), _| {
                !wanted.contains(&name.trim_end_matches('.').to_ascii_lowercase())
            });
        }
    }
    // Expired, not removed. The entry's *shape* - the client's own query bytes -
    // is what the warm loop replays (`warm_queries`), and a removed shape means
    // the next client query of that shape misses the cache and pays for a cold
    // race. Zero life and a non-substituted verdict take it out of both the
    // fresh path and the stale-substituted preference, and let the next answer
    // overwrite it whatever its verdict.
    if let Ok(mut guard) = ANSWERS.lock() {
        if let Some(map) = guard.as_mut() {
            for (key, answer) in map.iter_mut() {
                let hit = dns_client::question_name(key)
                    .map(|q| q.trim_end_matches('.').to_ascii_lowercase())
                    .is_some_and(|q| wanted.contains(&q));
                if hit {
                    answer.good_for = Duration::ZERO;
                    answer.verdict = Verdict::Unknown;
                }
            }
        }
    }
}

/// Answers a routed name the way the tunnel's own resolver would, and says so.
///
/// Used while a VPN is up. Substituting there is worse than useless: an NRPT
/// rule overrides the resolver the user deliberately turned on, and the address
/// it hands back points at a provider's proxy that the traffic then reaches
/// *through* the tunnel - a detour to reach what the tunnel already reaches
/// directly, and pure loss when the exit is somewhere the gate does not apply
/// (S25, G26).
///
/// It asks the reference resolvers over the **default route** - `if_index` 0, so
/// the query leaves through the tunnel like everything else - rather than
/// reading the VPN's own configured servers. Same result for these names, and it
/// avoids depending on that configuration being usable: this was written on a
/// machine whose VPN set DNS to two addresses that answer nothing at all on
/// UDP:53, being DoH-only.
///
/// The verdict is honestly `Passthrough`, so the answer is capped at
/// `PASSTHROUGH_TTL` and never outranks a real substitution left in the cache
/// from before the tunnel came up (I26).
fn resolve_through_tunnel(
    query: &[u8],
    from_client: bool,
) -> Option<(Vec<u8>, &'static str, Verdict)> {
    for server in REFERENCE_V4 {
        let Ok(ip) = server.parse::<Ipv4Addr>() else {
            continue;
        };
        let budget = if from_client {
            FAST_PATH_TIMEOUT
        } else {
            QUERY_TIMEOUT
        };
        if let Ok(reply) = dns_client::query_raw_via(query, ip, 0, budget) {
            let reply = dns_client::cap_ttl(&reply, PASSTHROUGH_TTL).unwrap_or(reply);
            remember_answer(query, &reply, "VPN", Verdict::Passthrough, from_client);
            return Some((reply, "VPN", Verdict::Passthrough));
        }
    }
    None
}

/// The provider to prefer for `name`, and how long a racer may be held for it.
///
/// A DoH provider loses a fair race by construction: it pays a TLS handshake
/// where a UDP provider answers in one round trip, so listing it first in
/// `PROVIDERS` buys nothing on its own. What is worth preferring is not the DNS
/// latency but **the proxy the answer points at**, which is the number the IDE
/// actually feels - measured, dns-ai.ru's proxy completes TLS in 0.29 s against
/// comss's 0.37-0.99 s and geohide's 1.3-7.8 s. It is also the owner's own
/// service, so an outage is his to fix rather than a third party's to notice.
///
/// Deliberately narrow: two names, one bounded wait, and no effect at all once
/// the answer cache is warm - which is the state a client query is normally in.
fn preferred_provider(name: &str) -> Option<usize> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if !PREFERRED_NAMES.contains(&name.as_str()) {
        return None;
    }
    PROVIDERS
        .iter()
        .position(|p| matches!(p.transport, Transport::Doh(_)))
}

/// What a one-shot to `provider` needs at minimum, whatever the caller budgeted.
fn one_shot_floor(provider: &Provider, budget: Duration) -> Duration {
    match provider.transport {
        Transport::Doh(_) => budget.max(DOH_FAST_TIMEOUT),
        Transport::Udp => budget,
    }
}

/// Answers `query`, from memory when a recent vetted answer is there and from
/// the providers otherwise.
///
/// The reply is handed back as the raw bytes the provider sent, never rebuilt:
/// the relay's contract is that any record type and any EDNS option survives
/// the round trip untouched. A cached reply is the same bytes with the client's
/// transaction id and its TTLs counted down.
pub fn resolve_best(query: &[u8], if_index: u32) -> Option<(Vec<u8>, &'static str, Verdict)> {
    let hit = cached_answer(query, false, true).or_else(|| resolve_upstream(query, if_index, true));
    note_served_a(query, &hit);
    hit
}

/// Records the verdict of an **A** answer for its name. Only A: Windows asks
/// AAAA for every name too, and the providers answer that with Google's own
/// IPv6 (a passthrough by construction, which is why `dns.rs` re-orders the
/// prefix policy). Keyed by name alone, the AAAA verdict overwrote the A one
/// and took the direct route out of the table on alternate warm passes.
fn note_served_a(query: &[u8], hit: &Option<(Vec<u8>, &'static str, Verdict)>) {
    if dns_client::question_type(query) != Some(QTYPE_A) {
        return;
    }
    if let (Some(name), Some((_, _, verdict))) = (dns_client::question_name(query), hit) {
        note_served(&name, *verdict);
    }
}

/// Asks upstream whatever is cached, and stores the result.
///
/// This is what the warm loop calls: going through `resolve_best` would just
/// hand back the entry it exists to replace.
pub fn refresh(query: &[u8], if_index: u32) -> Option<(Vec<u8>, &'static str, Verdict)> {
    let hit = resolve_upstream(query, if_index, false);
    note_served_a(query, &hit);
    hit
}

/// Asks every provider and every reference resolver at once and returns the
/// answer of the provider that actually substituted the name.
fn resolve_upstream(
    query: &[u8],
    if_index: u32,
    from_client: bool,
) -> Option<(Vec<u8>, &'static str, Verdict)> {
    let qtype = dns_client::question_type(query).unwrap_or(0);
    let name = dns_client::question_name(query).unwrap_or_default();
    let key = (name, qtype);

    // With a tunnel up the VPN decides, not us. Checked before the choice cache
    // as well as before the race, or a provider chosen minutes earlier would go
    // on answering for the whole `CHOICE_TTL` after the user connected.
    if vpn_is_active() {
        if let Some(hit) = resolve_through_tunnel(query, from_client) {
            return Some(hit);
        }
        // The tunnel's resolver is not answering either; fall through rather
        // than hand the client nothing.
    }

    // Anything that is not an address lookup cannot be classified, so it goes
    // to whichever provider is already known good for this name - or the first
    // one that answers.
    let classifiable = qtype == QTYPE_A || qtype == QTYPE_AAAA;

    // Nothing here may outlast what Windows will wait for while a client is
    // blocked on it: past that it asks the fallback nameserver, whose answer no
    // liveness probe and no reference comparison has been anywhere near.
    let one_shot = if from_client {
        FAST_PATH_TIMEOUT
    } else {
        QUERY_TIMEOUT
    };

    if let Some((idx, verdict)) = cached_choice(&key) {
        let budget = one_shot_floor(&PROVIDERS[idx], one_shot);
        if let Some(reply) = ask_provider(&PROVIDERS[idx], query, if_index, budget) {
            let reply = vet(reply, verdict, !from_client, Some(key.0.as_str()));
            remember_answer(query, &reply, PROVIDERS[idx].name, verdict, from_client);
            return prefer_substituted(query, from_client, (reply, PROVIDERS[idx].name, verdict));
        }
        // The chosen provider went away; re-race rather than keep asking it.
        forget_choice(&key);
    }

    if !classifiable {
        let start = ROTATION.fetch_add(1, Ordering::Relaxed);
        for step in 0..PROVIDERS.len() {
            let idx = (start + step) % PROVIDERS.len();
            if let Some(reply) = ask_provider(&PROVIDERS[idx], query, if_index, one_shot) {
                return Some((reply, PROVIDERS[idx].name, Verdict::Unknown));
            }
        }
        return None;
    }

    let (tx, rx) = mpsc::channel::<Heat>();
    for idx in 0..PROVIDERS.len() {
        let tx = tx.clone();
        let q = query.to_vec();
        thread::spawn(move || {
            // The generous timeout is right here: nothing blocks on one racer,
            // the race as a whole is bounded by RACE_BUDGET, and a straggler
            // simply sends into a channel nobody is reading any more.
            if let Some(reply) = ask_provider(&PROVIDERS[idx], &q, if_index, QUERY_TIMEOUT) {
                tx.send(Heat::Provider(idx, reply)).ok();
            }
        });
    }
    for server in REFERENCE_V4 {
        let Ok(ip) = server.parse::<Ipv4Addr>() else {
            continue;
        };
        let tx = tx.clone();
        let q = query.to_vec();
        thread::spawn(move || {
            if let Ok(reply) = dns_client::query_raw_via(&q, ip, if_index, QUERY_TIMEOUT) {
                tx.send(Heat::Reference(dns_client::answer_addrs(&reply)))
                    .ok();
            }
        });
    }

    // The control probes ride along in the same batch rather than on a timer:
    // in wall-clock they cost nothing, because everything here runs in
    // parallel, and they only run at all when something has gone stale -
    // normally once every PROXY_SET_TTL, not once per query.
    let learning = (0..PROVIDERS.len()).any(proxy_addrs_are_stale);
    if learning {
        // A different control name each round: the same one every time would be
        // a signature in a source anyone can read.
        let picked = CONTROL_NAMES[ROTATION.fetch_add(1, Ordering::Relaxed) % CONTROL_NAMES.len()];
        let control = dns_client::build_query(picked, 0x0C71);
        for idx in 0..PROVIDERS.len() {
            let tx = tx.clone();
            let q = control.clone();
            thread::spawn(move || {
                if let Some(reply) = ask_provider(&PROVIDERS[idx], &q, if_index, QUERY_TIMEOUT) {
                    tx.send(Heat::Control(idx, dns_client::answer_addrs(&reply)))
                        .ok();
                }
            });
        }
        if let Ok(ip) = REFERENCE_V4[0].parse::<Ipv4Addr>() {
            let tx = tx.clone();
            thread::spawn(move || {
                if let Ok(reply) = dns_client::query_raw_via(&control, ip, if_index, QUERY_TIMEOUT)
                {
                    tx.send(Heat::ControlReference(dns_client::answer_addrs(&reply)))
                        .ok();
                }
            });
        }
    }
    // Every sender lives in a thread; the local one would otherwise keep the
    // channel open past the last answer.
    drop(tx);

    let deadline = Instant::now() + RACE_BUDGET;
    let preferred = preferred_provider(&key.0);
    let grace_until = Instant::now() + PREFERRED_GRACE;
    let mut reference: Vec<IpAddr> = Vec::new();
    let mut replies: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut control: Vec<(usize, Vec<IpAddr>)> = Vec::new();
    let mut control_reference: Vec<IpAddr> = Vec::new();
    let mut got_reference = false;
    let mut got_control_reference = false;

    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(Heat::Reference(addrs)) => {
                reference.extend(addrs);
                got_reference = true;
            }
            Ok(Heat::Provider(idx, reply)) => replies.push((idx, reply)),
            Ok(Heat::Control(idx, addrs)) => control.push((idx, addrs)),
            Ok(Heat::ControlReference(addrs)) => {
                control_reference = addrs;
                got_control_reference = true;
            }
            // Everyone finished, or nobody is left to answer.
            Err(_) => break,
        }

        // A control answer counts as a proxy address only when it differs from
        // what the honest resolver says for the same name. Without that check a
        // provider that quietly stopped proxying the control name would teach
        // the relay that Cloudflare's addresses are its proxy.
        if got_control_reference {
            while let Some((idx, addrs)) = control.pop() {
                if classify(&addrs, &control_reference, &[]) == Verdict::Substituted {
                    learn_proxy_addrs(idx, addrs);
                }
            }
        }

        // Waiting for the control probes is only worth it while they can still
        // change a verdict. Once they are in - or were never started - the
        // first clear winner ends the race.
        let still_learning = learning && !got_control_reference;
        // Hold a decided race briefly for the preferred provider, but only while
        // it could still turn up and only for the names it is preferred on. Past
        // the grace the pool answers as it always did - preference must never
        // become a way to answer slower than the tool used to.
        let holding_for_preferred = preferred
            .is_some_and(|p| !replies.iter().any(|(i, _)| *i == p) && Instant::now() < grace_until);
        if got_reference && !replies.is_empty() && !still_learning && !holding_for_preferred {
            // The preferred provider wins among equals; `pick` decides otherwise.
            let hit = preferred
                .and_then(|p| replies.iter().position(|(i, _)| *i == p))
                .filter(|&h| {
                    classify(
                        &dns_client::answer_addrs(&replies[h].1),
                        &reference,
                        &known_proxy_addrs(replies[h].0),
                    ) == Verdict::Substituted
                })
                .or_else(|| pick(&replies, &reference, Verdict::Substituted));
            if let Some(hit) = hit {
                let name = key.0.clone();
                remember_choice(key, replies[hit].0, Verdict::Substituted);
                let (idx, reply) = replies.swap_remove(hit);
                let reply = vet(reply, Verdict::Substituted, !from_client, Some(&name));
                remember_answer(
                    query,
                    &reply,
                    PROVIDERS[idx].name,
                    Verdict::Substituted,
                    from_client,
                );
                return Some((reply, PROVIDERS[idx].name, Verdict::Substituted));
            }
        }
        if replies.len() == PROVIDERS.len() && got_reference && !still_learning {
            break;
        }
    }

    if replies.is_empty() {
        // Every provider went quiet. A substituted answer from minutes ago is
        // still the best thing in the building: the alternative is not a fresh
        // answer but Windows falling through to an unvetted fallback.
        return cached_answer(query, true, from_client);
    }
    // Nothing substituted. Hand back the best of what arrived anyway - an
    // unsubstituted answer still resolves the name, and refusing to answer
    // would only push Windows onto the direct fallback for the same result.
    let best = best_of(&replies, &reference);
    // Only for a query a client is actually waiting on. The warm loop races the
    // same names every 15 s, and two of the four never substitute by design, so
    // logging its races would fill the 64 KB budget in about an hour and take
    // the diagnostics with it.
    if from_client && !replies.is_empty() && !dns_client::answer_addrs(&replies[best].1).is_empty()
    {
        let heard: Vec<&str> = replies.iter().map(|(i, _)| PROVIDERS[*i].name).collect();
        crate::dns_forwarder::log_race(&key.0, &heard, got_reference);
    }
    let verdict = classify(
        &dns_client::answer_addrs(&replies[best].1),
        &reference,
        &known_proxy_addrs(replies[best].0),
    );
    // Only a substitution is worth remembering. A choice cached on any weaker
    // verdict is a five-minute promise to stop looking: the fast path re-asks
    // that provider, it keeps answering (with the genuine address), so nothing
    // ever fails and no re-race is triggered. Measured exactly that way - one
    // lost race and the relay served comss's genuine `daily-cloudcode-pa` for as
    // long as the choice lived, while geohide was substituting it in 40 ms the
    // whole time. Forgetting instead costs a race per warm pass, which is off
    // the client's path and is precisely the work this module exists to do.
    forget_choice(&key);
    let (idx, reply) = replies.swap_remove(best);
    let reply = vet(reply, verdict, !from_client, Some(key.0.as_str()));
    remember_answer(query, &reply, PROVIDERS[idx].name, verdict, from_client);
    prefer_substituted(query, from_client, (reply, PROVIDERS[idx].name, verdict))
}

/// Filters a reply before it goes back to the client.
///
/// A substitution gets its dead addresses cut out - those belong to a third
/// party rather than to Google, so they are the only ones worth probing. Every
/// other verdict gets its TTL clamped instead: see `PASSTHROUGH_TTL`.
fn vet(reply: Vec<u8>, verdict: Verdict, fresh: bool, sni: Option<&str>) -> Vec<u8> {
    if verdict == Verdict::Substituted {
        drop_dead_addrs(reply, fresh, sni)
    } else {
        dns_client::cap_ttl(&reply, PASSTHROUGH_TTL).unwrap_or(reply)
    }
}

/// Hands back the best answer available for `query`, preferring a substitution
/// already in memory over a freshly-arrived unsubstituted one.
///
/// Without this a single lost race is not a blip but an outage: the genuine
/// answer goes into the Windows cache and every request for its whole TTL leaves
/// from the blocked region, with the relay never consulted again.
fn prefer_substituted(
    query: &[u8],
    from_client: bool,
    fresh: (Vec<u8>, &'static str, Verdict),
) -> Option<(Vec<u8>, &'static str, Verdict)> {
    if fresh.2 == Verdict::Substituted {
        return Some(fresh);
    }
    cached_answer(query, true, from_client).or(Some(fresh))
}

/// Seeds each provider's proxy-address set from a control name, sequentially.
///
/// `substituting_addrs` runs in the menu process at rule-setup time, which has
/// its own (cold) `PROXY_SET` - the relay's warm loop that normally learns it
/// lives in a different process. Without this the set is empty, and `classify`
/// falls back to its bootstrap rule (`proxy.is_empty()` -> `Substituted`), which
/// flags a genuine answer that merely landed on a different Google /16 (D7).
/// That is exactly how xbox-dns, which returns genuine for `daily-cloudcode-pa`,
/// ended up written into that name's NRPT fallback - the I22 leak. Learning the
/// sets first makes `classify` take the proxy-match path, so a genuine
/// different-/16 answer is `Sibling`, not `Substituted`.
fn ensure_proxy_sets_learned(if_index: u32) {
    if !(0..PROVIDERS.len()).any(proxy_addrs_are_stale) {
        return;
    }
    // Union across two usable control names, not one: geohide rotates its proxy
    // across three addresses in three /16s (see PROXY_SET_TTL), so a single probe
    // can miss the /16 it later answers `daily-cloudcode-pa` from - which would
    // drop its sole substituter and fall the rule back to every provider (the I22
    // leak). `learn_proxy_addrs` unions, so a second name closes most of that gap
    // without paying for all five.
    const ROUNDS: usize = 2;
    let mut done = 0;
    for &picked in CONTROL_NAMES {
        if done >= ROUNDS {
            break;
        }
        let control = dns_client::build_query(picked, 0x0C71);
        let mut cref: Vec<IpAddr> = Vec::new();
        for server in REFERENCE_V4 {
            if let Ok(ip) = server.parse::<Ipv4Addr>() {
                if let Ok(reply) = dns_client::query_raw_via(&control, ip, if_index, QUERY_TIMEOUT)
                {
                    cref.extend(dns_client::answer_addrs(&reply));
                }
            }
        }
        // A control name the ISP link's DPI stubs (e.g. chatgpt.com) yields no
        // usable reference - classify filters those stubs - so try the next.
        let usable = cref.iter().any(|a| match a {
            IpAddr::V4(v) => !REFERENCE_STUBS.contains(v),
            IpAddr::V6(_) => true,
        });
        if !usable {
            continue;
        }
        for idx in 0..PROVIDERS.len() {
            if let Some(reply) = ask_provider(&PROVIDERS[idx], &control, if_index, QUERY_TIMEOUT) {
                let addrs = dns_client::answer_addrs(&reply);
                if classify(&addrs, &cref, &[]) == Verdict::Substituted {
                    learn_proxy_addrs(idx, addrs);
                }
            }
        }
        done += 1;
    }
}

pub fn substituting_addrs(name: &str, if_index: u32) -> Vec<&'static str> {
    ensure_proxy_sets_learned(if_index);
    let query = dns_client::build_query(name, 0x6767);

    let mut reference: Vec<IpAddr> = Vec::new();
    for server in REFERENCE_V4 {
        if let Ok(ip) = server.parse::<Ipv4Addr>() {
            if let Ok(reply) = dns_client::query_raw_via(&query, ip, if_index, QUERY_TIMEOUT) {
                reference.extend(dns_client::answer_addrs(&reply));
            }
        }
    }

    let mut out = Vec::new();
    for (idx, provider) in PROVIDERS.iter().enumerate() {
        let Some(reply) = ask_provider(provider, &query, if_index, QUERY_TIMEOUT) else {
            continue;
        };
        let addrs = dns_client::answer_addrs(&reply);
        let known = known_proxy_addrs(idx);
        // Only a substitution backed by a *known* proxy address is written into
        // an NRPT fallback. classify's empty-set bootstrap exists to learn
        // control names, not to build rules: trusting it here would flag genuine
        // Google on a different /16 and re-open the I22 leak (see
        // `ensure_proxy_sets_learned`).
        if !known.is_empty() && classify(&addrs, &reference, &known) == Verdict::Substituted {
            if let Some(first) = provider.v4.first() {
                out.push(*first);
            }
        }
    }
    out
}

/// Resolves `name` the same way, for callers that want addresses rather than a
/// packet - `hosts_pin` writes literals, not DNS messages.
///
/// The verdict comes back with them so the caller can refuse to pin an answer
/// that was never substituted: freezing a genuine Google address into `hosts`
/// buys nothing and goes stale the moment Google rotates its edge.
pub fn resolve_a_best(name: &str, if_index: u32) -> Option<(Vec<Ipv4Addr>, &'static str, Verdict)> {
    // The id only has to be echoed back; `query_raw_via` matches on it.
    let query = dns_client::build_query(name, 0x5A5A);
    let (reply, provider, verdict) = resolve_best(&query, if_index)?;
    let addrs: Vec<Ipv4Addr> = dns_client::answer_addrs(&reply)
        .into_iter()
        .filter_map(|a| match a {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    if addrs.is_empty() {
        return None;
    }
    Some((addrs, provider, verdict))
}

/// Index of the first reply with exactly `want`, in rotated provider order.
fn pick(replies: &[(usize, Vec<u8>)], reference: &[IpAddr], want: Verdict) -> Option<usize> {
    let start = ROTATION.load(Ordering::Relaxed);
    let mut best: Option<usize> = None;
    for i in 0..replies.len() {
        // Rotate over provider indices so a tie does not always go to the same
        // provider, then map back to the position in `replies`.
        let wanted_provider = (start + i) % PROVIDERS.len();
        let Some(pos) = replies.iter().position(|(idx, _)| *idx == wanted_provider) else {
            continue;
        };
        let verdict = classify(
            &dns_client::answer_addrs(&replies[pos].1),
            reference,
            &known_proxy_addrs(wanted_provider),
        );
        if verdict == want {
            best = Some(pos);
            break;
        }
    }
    if best.is_some() {
        ROTATION.fetch_add(1, Ordering::Relaxed);
    }
    best
}

/// Highest-ranked reply, ties broken by rotation.
fn best_of(replies: &[(usize, Vec<u8>)], reference: &[IpAddr]) -> usize {
    let start = ROTATION.fetch_add(1, Ordering::Relaxed);
    let mut best = 0usize;
    let mut best_rank = 0u8;
    for i in 0..replies.len() {
        let wanted_provider = (start + i) % PROVIDERS.len();
        let Some(pos) = replies.iter().position(|(idx, _)| *idx == wanted_provider) else {
            continue;
        };
        let r = rank(classify(
            &dns_client::answer_addrs(&replies[pos].1),
            reference,
            &known_proxy_addrs(wanted_provider),
        ));
        if r > best_rank {
            best_rank = r;
            best = pos;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    #[test]
    fn served_verdicts_are_kept_per_name_case_folded() {
        note_served("Daily-Cloudcode-PA.googleapis.com.", Verdict::Substituted);
        assert_eq!(
            served_verdict("daily-cloudcode-pa.googleapis.com"),
            Some(Verdict::Substituted)
        );
        assert_eq!(served_verdict("nobody.asked.example"), None);
    }

    #[test]
    fn forgetting_a_name_drops_its_choice_and_its_answers() {
        let name = "forget-me.example";
        remember_choice((name.to_string(), QTYPE_A), 0, Verdict::Substituted);
        assert!(cached_choice(&(name.to_string(), QTYPE_A)).is_some());
        let query = dns_client::build_query(name, 0x1111);
        let mut reply = query.clone();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 1;
        reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]);
        remember_answer(&query, &reply, "test", Verdict::Substituted, true);
        assert!(cached_answer(&query, false, false).is_some());

        forget_names(&["FORGET-ME.example"]);
        assert!(cached_choice(&(name.to_string(), QTYPE_A)).is_none());
        assert!(cached_answer(&query, false, false).is_none());
        assert!(
            cached_answer(&query, true, false).is_none(),
            "not served as a stale substitution either"
        );
        // The shape survives for the warm loop to replay.
        let shapes = warm_queries(&[name]);
        assert!(
            shapes.iter().any(|q| answer_key(q) == answer_key(&query)),
            "the client's query shape must still be warmed"
        );
    }

    #[test]
    fn only_an_a_answer_records_a_served_verdict() {
        let name = "served-a.example";
        let a = dns_client::build_query(name, 1);
        let mut aaaa = a.clone();
        let n = aaaa.len();
        aaaa[n - 3] = 28; // qtype AAAA
        let hit = Some((Vec::new(), "test", Verdict::Substituted));
        note_served_a(&a, &hit);
        assert_eq!(served_verdict(name), Some(Verdict::Substituted));
        let hit = Some((Vec::new(), "test", Verdict::Passthrough));
        note_served_a(&aaaa, &hit);
        assert_eq!(
            served_verdict(name),
            Some(Verdict::Substituted),
            "an AAAA passthrough must not overwrite the A verdict"
        );
    }

    fn udp_providers() -> Vec<&'static Provider> {
        PROVIDERS
            .iter()
            .filter(|p| matches!(p.transport, Transport::Udp))
            .collect()
    }

    #[test]
    fn every_udp_provider_has_at_least_one_address() {
        assert!(!PROVIDERS.is_empty());
        for p in udp_providers() {
            assert!(!p.v4.is_empty(), "{} has no IPv4 address", p.name);
            for a in p.v4 {
                assert!(a.parse::<Ipv4Addr>().is_ok(), "{} is not an address", a);
            }
        }
    }

    /// The NRPT rule takes one address per provider, so a provider outage falls
    /// through to a different service rather than to its own dead sibling.
    #[test]
    fn the_fallback_list_is_one_address_per_udp_provider() {
        let fallback = fallback_v4();
        let udp = udp_providers();
        assert_eq!(fallback.len(), udp.len());
        for (i, p) in udp.iter().enumerate() {
            assert_eq!(fallback[i], p.v4[0]);
        }
    }

    /// The invariant a DoH provider lives or dies by.
    ///
    /// `fallback_v4`/`all_v6` feed NRPT nameserver lists, and Windows can only be
    /// pointed at something that answers UDP:53. A DoH endpoint answers nothing
    /// there - measured: both of dns-ai.ru's addresses time out on 53 - so if one
    /// ever reached a rule, that name would get a nameserver that never replies
    /// and the whole rule would hang on it. Enforced structurally by empty
    /// `v4`/`v6`, which is easy to undo by accident while "filling in" a provider
    /// entry, so it is asserted rather than commented.
    #[test]
    fn a_doh_provider_is_never_offered_as_a_nameserver() {
        let listed: Vec<&str> = fallback_v4().into_iter().chain(all_v6()).collect();
        for p in PROVIDERS {
            let Transport::Doh(endpoint) = p.transport else {
                continue;
            };
            assert!(
                p.v4.is_empty() && p.v6.is_empty(),
                "{} speaks DoH, so its address list must stay empty",
                p.name
            );
            for a in endpoint.addrs {
                assert!(
                    !listed.contains(a),
                    "{} would be handed to Windows as a nameserver",
                    a
                );
            }
        }
    }

    /// The flag defaults to "no tunnel", which is the behaviour every existing
    /// machine already has: a relay that never learns the answer keeps
    /// substituting exactly as before rather than quietly standing down.
    ///
    /// The region-400 override lives in the same test because it shares this
    /// flag: while forced, the relay substitutes even though the tunnel verdict
    /// says stand down, and the force expires on its own.
    #[test]
    fn the_vpn_flag_defaults_to_off_and_round_trips() {
        assert!(!vpn_is_active(), "должно быть выключено по умолчанию");
        set_vpn_active(true);
        assert!(vpn_is_active());

        force_substitution(Duration::from_millis(80));
        assert!(substitution_forced());
        assert!(!vpn_is_active(), "forced: the tunnel no longer decides");
        assert!(tunnel_carries_client(), "the raw verdict is still readable");
        std::thread::sleep(Duration::from_millis(120));
        assert!(!substitution_forced());
        assert!(
            vpn_is_active(),
            "the window closed; the tunnel decides again"
        );

        set_vpn_active(false);
        assert!(!vpn_is_active());
    }

    /// Preference is for the two gate names and nothing else. Widening it would
    /// put a bounded wait on names that never needed one.
    #[test]
    fn only_the_gate_names_have_a_preferred_provider() {
        let doh = PROVIDERS
            .iter()
            .position(|p| matches!(p.transport, Transport::Doh(_)))
            .expect("a DoH provider");
        assert_eq!(preferred_provider("cloudcode-pa.googleapis.com"), Some(doh));
        assert_eq!(
            preferred_provider("daily-cloudcode-pa.googleapis.com"),
            Some(doh)
        );
        // A question name may arrive rooted or in any case; neither changes it.
        assert_eq!(
            preferred_provider("CloudCode-PA.GoogleAPIs.com."),
            Some(doh)
        );
        for other in [
            "generativelanguage.googleapis.com",
            "jetski-webchannel.googleapis.com",
            "accounts.google.com",
            "",
        ] {
            assert_eq!(preferred_provider(other), None, "{}", other);
        }
    }

    /// 250 ms cannot cover a TLS handshake, so a cached choice pointing at the
    /// DoH provider would fail on the fast path every time, be forgotten, and
    /// re-race - the fast path becoming the slow one.
    #[test]
    fn the_fast_path_gives_a_doh_provider_room_to_answer() {
        let doh = PROVIDERS
            .iter()
            .find(|p| matches!(p.transport, Transport::Doh(_)))
            .expect("a DoH provider");
        let udp = PROVIDERS
            .iter()
            .find(|p| matches!(p.transport, Transport::Udp))
            .expect("a UDP provider");
        assert_eq!(one_shot_floor(doh, FAST_PATH_TIMEOUT), DOH_FAST_TIMEOUT);
        assert_eq!(one_shot_floor(udp, FAST_PATH_TIMEOUT), FAST_PATH_TIMEOUT);
        // A caller that already budgeted more keeps it.
        assert_eq!(one_shot_floor(doh, QUERY_TIMEOUT), QUERY_TIMEOUT);
        // And the whole thing still fits inside the second Windows waits (I23).
        assert!(DOH_FAST_TIMEOUT < Duration::from_secs(1));
        assert!(PREFERRED_GRACE <= RACE_BUDGET);
    }

    /// A DoH endpoint's addresses still have to be addresses: they are dialled
    /// directly, precisely so the resolver is reachable before DNS works.
    #[test]
    fn doh_endpoints_carry_parsable_addresses() {
        for p in PROVIDERS {
            if let Transport::Doh(endpoint) = p.transport {
                assert!(!endpoint.addrs.is_empty(), "{} has no address", p.name);
                for a in endpoint.addrs {
                    assert!(a.parse::<IpAddr>().is_ok(), "{} is not an address", a);
                }
                assert!(endpoint.path.starts_with('/'), "path must be absolute");
            }
        }
    }

    /// A reference resolver must never be a provider: it exists to show what an
    /// unsubstituted answer looks like.
    #[test]
    fn reference_resolvers_are_not_providers() {
        let providers: Vec<&str> = PROVIDERS
            .iter()
            .flat_map(|p| p.v4.iter().copied())
            .collect();
        for r in REFERENCE_V4 {
            assert!(!providers.contains(r), "{} is on both lists", r);
        }
    }

    /// The proxy addresses the three providers were measured handing out. In
    /// production these are learned at runtime from `CONTROL_NAME`; here they
    /// stand in for what that probe would have found.
    fn learned_proxies() -> Vec<IpAddr> {
        vec![
            v4("87.228.47.204"),
            v4("45.88.174.254"),
            v4("37.230.192.51"),
        ]
    }

    #[test]
    fn the_same_netblock_is_a_passthrough() {
        // What xbox-dns now answers for cloudcode-pa: Google's own edge, a
        // different host inside the same /16 the reference gave.
        let candidate = [v4("172.217.113.4")];
        let reference = [v4("172.217.114.4"), v4("172.217.112.4")];
        assert_eq!(
            classify(&candidate, &reference, &learned_proxies()),
            Verdict::Passthrough
        );
    }

    #[test]
    fn a_proxy_address_is_a_substitution() {
        let google = [v4("172.217.118.4")];
        for proxy in learned_proxies() {
            assert_eq!(
                classify(&[proxy], &google, &learned_proxies()),
                Verdict::Substituted,
                "{:?} is a measured proxy address",
                proxy
            );
        }
    }

    /// The false positive the proxy set exists to kill: two different Google
    /// netblocks are not a substitution. Nothing about the addresses themselves
    /// says so - only knowing what the provider's proxy looks like does.
    #[test]
    fn another_google_netblock_is_only_a_sibling() {
        assert_eq!(
            classify(
                &[v4("173.194.220.95")],
                &[v4("64.233.163.95")],
                &learned_proxies()
            ),
            Verdict::Sibling
        );
        assert!(rank(Verdict::Sibling) < rank(Verdict::Substituted));
    }

    /// Before the control probe has ever run there is nothing to recognise a
    /// proxy by, so "differs from the honest answer" is taken at face value -
    /// the behaviour the tool had before, which never prefers a passthrough.
    #[test]
    fn without_a_learned_proxy_any_difference_counts() {
        assert_eq!(
            classify(&[v4("173.194.220.95")], &[v4("64.233.163.95")], &[]),
            Verdict::Substituted
        );
        // Still not enough to call an identical answer substituted.
        assert_eq!(
            classify(&[v4("172.217.113.4")], &[v4("172.217.114.4")], &[]),
            Verdict::Passthrough
        );
    }

    /// A DPI-stubbed reference must not turn every answer into a substitution.
    #[test]
    fn a_stubbed_reference_is_no_reference() {
        let stub = [v4("8.6.112.0"), v4("8.47.69.0")];
        assert_eq!(
            classify(&[v4("172.217.118.4")], &stub, &learned_proxies()),
            Verdict::Unknown
        );
        assert_eq!(
            classify(&[v4("87.228.47.204")], &stub, &learned_proxies()),
            Verdict::Unknown
        );
    }

    #[test]
    fn nothing_to_compare_is_unknown() {
        assert_eq!(classify(&[], &[v4("8.8.8.8")], &[]), Verdict::Unknown);
        assert_eq!(classify(&[v4("87.228.47.204")], &[], &[]), Verdict::Unknown);
        // An AAAA answer against an A-only reference says nothing.
        let v6: IpAddr = "2a00:ab00:1233:26::50".parse::<IpAddr>().unwrap();
        assert_eq!(
            classify(&[v6], &[v4("172.217.118.4")], &[]),
            Verdict::Unknown
        );
    }

    #[test]
    fn a_substitution_outranks_everything_else() {
        assert!(rank(Verdict::Substituted) > rank(Verdict::Unknown));
        assert!(rank(Verdict::Unknown) > rank(Verdict::Sibling));
        assert!(rank(Verdict::Sibling) > rank(Verdict::Passthrough));
    }

    /// The reason the whole module exists: the answer that broke the tool must
    /// be recognised as not-a-substitution, so the next provider gets a turn.
    #[test]
    fn the_regression_that_broke_the_tool_is_detected() {
        let xbox_cloudcode = [v4("172.217.113.4")];
        let google = [v4("172.217.114.4")];
        assert_ne!(
            classify(&xbox_cloudcode, &google, &learned_proxies()),
            Verdict::Substituted
        );
    }

    /// The union is what makes a rotating provider recognisable: geohide serves
    /// its proxy from three addresses in three unrelated /16s, so one probe only
    /// ever sees part of the set.
    #[test]
    fn learned_proxy_addresses_accumulate() {
        let idx = PROVIDERS.len() + 41; // a slot no real provider uses
        learn_proxy_addrs(idx, vec![v4("95.182.120.241")]);
        learn_proxy_addrs(idx, vec![v4("37.230.192.51"), v4("95.182.120.241")]);
        let known = known_proxy_addrs(idx);
        assert_eq!(known.len(), 2, "duplicates must not pile up: {:?}", known);
        assert!(known.contains(&v4("37.230.192.51")));

        // An answer served from the address the first probe missed is still
        // recognised as that provider's proxy.
        assert_eq!(
            classify(&[v4("37.230.192.51")], &[v4("172.217.118.4")], &known),
            Verdict::Substituted
        );
    }

    /// The control names are the one place this tool announces itself to a
    /// provider, and the source is public. Several, from unrelated operators,
    /// so no single upstream change - or a rule aimed at this tool - takes the
    /// whole learning mechanism out.
    #[test]
    fn control_names_are_several_and_not_one_operator() {
        assert!(
            CONTROL_NAMES.len() >= 3,
            "one control name is a signature, not a probe"
        );
        let non_google = CONTROL_NAMES
            .iter()
            .filter(|n| !n.contains("google."))
            .count();
        assert!(
            non_google >= 2,
            "the set must survive a Google-side change: {:?}",
            CONTROL_NAMES
        );
        // The DPI on the ISP link stubs this one, so its reference is unusable.
        assert!(!CONTROL_NAMES.contains(&"grok.com"));
    }

    /// An empty learning round must not overwrite what is already known, or a
    /// provider that failed to answer the control probe once would lose its set.
    #[test]
    fn an_empty_probe_does_not_erase_the_set() {
        let idx = PROVIDERS.len() + 42;
        learn_proxy_addrs(idx, vec![v4("87.228.47.204")]);
        learn_proxy_addrs(idx, vec![]);
        assert_eq!(known_proxy_addrs(idx), vec![v4("87.228.47.204")]);
    }

    /// Live: what the NRPT fallback list will be built from for each routed
    /// name. `daily-cloudcode-pa` must come back with geohide only - the bug
    /// was xbox-dns/comss (which return genuine Google for it) sitting in that
    /// list and leaking. Run VPN-off.
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn substituting_addrs_excludes_passthrough_providers() {
        for name in [
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "antigravity-unleash.goog",
        ] {
            let subs = substituting_addrs(name, 0);
            println!("{:<38} substituted by {:?}", name, subs);
            // Whatever is returned must be a real provider address, never a
            // reference resolver - a reference in the fallback would be a leak.
            for s in &subs {
                assert!(
                    !REFERENCE_V4.contains(s),
                    "{} is a reference resolver, not a substituter",
                    s
                );
            }
        }
    }

    /// Live: the whole pool, provider by provider and name by name — what each
    /// answered, what proxy set was learned for it, and the verdict that follows.
    ///
    /// This is the quarterly re-measurement P14 asks for, in one command. It
    /// asserts nothing about *who* substitutes what, because that is exactly the
    /// thing that changes without warning and must not be pinned in a test (N15:
    /// a measurement recorded as a property of a host outlived the measurement by
    /// months). It only pins the two rules that are ours: an NRPT fallback never
    /// names a reference resolver, and never names a DoH provider (I49).
    ///
    ///     cargo test the_pool_measured_provider_by_provider -- --ignored --nocapture
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn the_pool_measured_provider_by_provider() {
        const NAMES: &[&str] = &[
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
        ];

        ensure_proxy_sets_learned(0);
        println!("learned proxy sets:");
        for (idx, p) in PROVIDERS.iter().enumerate() {
            println!("  {:<12} {:?}", p.name, known_proxy_addrs(idx));
        }

        for name in NAMES {
            let query = dns_client::build_query(name, 0x6767);
            let mut reference: Vec<IpAddr> = Vec::new();
            for server in REFERENCE_V4 {
                if let Ok(ip) = server.parse::<Ipv4Addr>() {
                    if let Ok(reply) = dns_client::query_raw_via(&query, ip, 0, QUERY_TIMEOUT) {
                        reference.extend(dns_client::answer_addrs(&reply));
                    }
                }
            }
            println!("\n{}\n  reference {:?}", name, reference);
            for (idx, p) in PROVIDERS.iter().enumerate() {
                let known = known_proxy_addrs(idx);
                match ask_provider(p, &query, 0, QUERY_TIMEOUT) {
                    None => println!("  {:<12} нет ответа", p.name),
                    Some(reply) => {
                        let addrs = dns_client::answer_addrs(&reply);
                        // Wire counts alongside the parsed addresses: an empty
                        // list with ANCOUNT>0 is a parse problem, an empty list
                        // with ANCOUNT=0 is the provider (G24 was the first).
                        let rcode = reply.get(3).map_or(0xFF, |b| b & 0x0F);
                        let ancount = if reply.len() >= 8 {
                            u16::from_be_bytes([reply[6], reply[7]])
                        } else {
                            0
                        };
                        // Both verdicts: the bootstrap one the relay may act on,
                        // and the stricter one an NRPT fallback needs.
                        println!(
                            "  {:<12} rcode={} an={} len={} {:?} -> race {:?}, rule {}",
                            p.name,
                            rcode,
                            ancount,
                            reply.len(),
                            addrs,
                            classify(&addrs, &reference, &known),
                            if known.is_empty() {
                                "исключён (прокси-набор не выучен)".to_string()
                            } else {
                                format!("{:?}", classify(&addrs, &reference, &known))
                            }
                        );
                    }
                }
            }
            for s in substituting_addrs(name, 0) {
                assert!(!REFERENCE_V4.contains(&s), "{} is a reference resolver", s);
                assert!(
                    PROVIDERS
                        .iter()
                        .any(|p| p.v4.contains(&s) && !matches!(p.transport, Transport::Doh(_))),
                    "{} is not a UDP provider address (I49)",
                    s
                );
            }
        }
    }

    /// Live end-to-end: races the real providers and prints what each answered.
    /// Must run with the VPN off, or every provider sees a foreign client and
    /// substitutes nothing.
    #[test]
    #[ignore = "needs a live network; run with --ignored"]
    fn races_the_real_providers() {
        for name in [
            "generativelanguage.googleapis.com",
            "cloudcode-pa.googleapis.com",
        ] {
            let mut query = vec![0x77, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            for label in name.split('.') {
                query.push(label.len() as u8);
                query.extend_from_slice(label.as_bytes());
            }
            query.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);

            match resolve_best(&query, 0) {
                Some((reply, provider, verdict)) => {
                    println!(
                        "{:<38} {:?} via {} -> {:?}",
                        name,
                        verdict,
                        provider,
                        dns_client::answer_addrs(&reply)
                    );
                }
                None => println!("{:<38} no provider answered", name),
            }
        }
    }

    /// Header + question for `name`, shaped the way a real client asks.
    fn query_for(name: &str, id: u16, edns: bool) -> Vec<u8> {
        let mut q = vec![0, 0, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q[0..2].copy_from_slice(&id.to_be_bytes());
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);
        if edns {
            q[11] = 1; // ARCOUNT
            q.extend_from_slice(&[0, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0x00, 0x00]);
        }
        q
    }

    /// One A record for `name`, TTL 60, exactly the shape geohide answers with.
    fn reply_for(name: &str, id: u16, addr: [u8; 4]) -> Vec<u8> {
        let mut b = query_for(name, id, false);
        b[2] = 0x81;
        b[3] = 0x80;
        b[7] = 1; // ANCOUNT
        b.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04]);
        b.extend_from_slice(&addr);
        b
    }

    /// Serialises every test that shares the process-wide answer cache.
    ///
    /// This used to be a bare call, and cargo runs tests in parallel threads of
    /// one process: two of them would each wipe the map the other had just
    /// written, and whichever asserted second failed. Roughly one run in ten, and
    /// it read exactly like a product bug. Holding the guard for the length of a
    /// test is what makes "nothing else may be in the cache" true rather than
    /// merely intended.
    static CACHE_TESTS: Mutex<()> = Mutex::new(());

    #[must_use = "hold the guard for the whole test, or the cache is shared again"]
    fn clear_answers() -> std::sync::MutexGuard<'static, ()> {
        // A panicking test poisons this, and the next one still has to run: what
        // it guards is wiped by every caller anyway, so the poison carries no
        // information worth propagating.
        let guard = CACHE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut g) = ANSWERS.lock() {
            *g = None;
        }
        guard
    }

    #[test]
    fn a_cached_answer_is_restamped_for_the_client_that_asks() {
        let _cache = clear_answers();
        let name = "cache-restamp.example";
        let stored = reply_for(name, 0x1111, [45, 155, 204, 190]);
        remember_answer(
            &query_for(name, 0x1111, false),
            &stored,
            "geohide.ru",
            Verdict::Substituted,
            true,
        );

        // A different client, a different transaction id, the same question.
        let asking = query_for(name, 0xBEEF, false);
        let (reply, provider, verdict) = cached_answer(&asking, false, true).unwrap();
        assert_eq!(&reply[0..2], &[0xBE, 0xEF]);
        assert_eq!(provider, "geohide.ru");
        assert_eq!(verdict, Verdict::Substituted);
        assert_eq!(
            dns_client::answer_addrs(&reply),
            dns_client::answer_addrs(&stored)
        );
    }

    /// A reply is only an answer to the exact question that fetched it. Windows
    /// sends EDNS0; a cache keyed loosely enough to serve that reply to a query
    /// without an OPT record would be handing back a malformed message.
    #[test]
    fn a_differently_shaped_question_is_a_miss() {
        let _cache = clear_answers();
        let name = "cache-shape.example";
        remember_answer(
            &query_for(name, 1, false),
            &reply_for(name, 1, [1, 2, 3, 4]),
            "geohide.ru",
            Verdict::Substituted,
            true,
        );
        assert!(cached_answer(&query_for(name, 2, false), false, true).is_some());
        assert!(cached_answer(&query_for(name, 2, true), false, true).is_none());
    }

    /// Serving a stored reply with its original TTL would keep Windows on it for
    /// the cache window *plus* the resolver's TTL, i.e. past the minute in which
    /// these providers may move the address.
    #[test]
    fn a_served_answer_carries_the_time_it_already_spent_in_the_cache() {
        let _cache = clear_answers();
        let name = "cache-ttl.example";
        let query = query_for(name, 3, false);
        remember_answer(
            &query,
            &reply_for(name, 3, [1, 2, 3, 4]),
            "geohide.ru",
            Verdict::Substituted,
            true,
        );
        if let Ok(mut g) = ANSWERS.lock() {
            let entry = g.as_mut().unwrap().get_mut(&answer_key(&query).unwrap());
            let entry = entry.unwrap();
            entry.at = Instant::now() - Duration::from_secs(20);
        }
        let (reply, _, _) = cached_answer(&query, false, true).unwrap();
        assert_eq!(dns_client::answer_ttl(&reply), Some(40));
    }

    /// Only a substitution is worth serving stale. Keeping a passthrough alive
    /// would hold the region gate shut, and there the NRPT fallback - built from
    /// measured substituters (I22) - is the better thing to fall through to.
    #[test]
    fn only_a_substitution_survives_past_its_freshness() {
        let _cache = clear_answers();
        for (name, verdict, expected) in [
            ("stale-sub.example", Verdict::Substituted, true),
            ("stale-pass.example", Verdict::Passthrough, false),
        ] {
            let query = query_for(name, 4, false);
            remember_answer(
                &query,
                &reply_for(name, 4, [1, 2, 3, 4]),
                "geohide.ru",
                verdict,
                true,
            );
            if let Ok(mut g) = ANSWERS.lock() {
                let key = answer_key(&query).unwrap();
                g.as_mut().unwrap().get_mut(&key).unwrap().at =
                    Instant::now() - ANSWER_TTL - Duration::from_secs(5);
            }
            assert!(cached_answer(&query, false, true).is_none(), "{}", name);
            assert_eq!(
                cached_answer(&query, true, true).is_some(),
                expected,
                "{}",
                name
            );
        }
    }

    /// The whole point of warming: it has to re-ask the shape the client sends,
    /// or every real query still goes upstream while the cache serves nobody.
    #[test]
    fn warming_replays_the_shapes_a_client_actually_sent() {
        let _cache = clear_answers();
        let name = "warm-shape.example";
        let asked = query_for(name, 0x4242, true);
        remember_answer(
            &asked,
            &reply_for(name, 0x4242, [1, 2, 3, 4]),
            "geohide.ru",
            Verdict::Substituted,
            true,
        );

        let queries = warm_queries(&[name]);
        assert_eq!(queries.len(), 1, "the seen shape, and no invented one");
        assert_eq!(answer_key(&queries[0]), answer_key(&asked));
    }

    /// A cached "alive" must not survive the address dying. Measured: geohide
    /// rotated which of its three was dead three times inside an hour, and a
    /// ten-minute verdict meant the relay advertised a corpse for nine of them.
    #[test]
    fn the_warm_path_re_probes_instead_of_trusting_what_it_knows() {
        let addr = v4("203.0.113.9");
        // A blackhole address in TEST-NET-3: nothing there, so a probe says dead.
        remember_liveness(addr, true);
        assert_eq!(cached_liveness(&addr), Some(true));

        // The client path takes the cached word for it and stays cheap...
        assert!(dead_addrs(&[addr], false, None).is_empty());
        // ...while the warm path asks the network and finds out otherwise.
        assert_eq!(dead_addrs(&[addr], true, None), vec![addr]);
    }

    /// Believing "alive" for longer than the providers keep an address alive is
    /// the whole bug; the warm loop has to get at least one pass inside it.
    #[test]
    fn a_live_verdict_expires_faster_than_the_addresses_rotate() {
        assert!(LIVENESS_TTL_ALIVE <= Duration::from_secs(30));
    }

    /// The outage this exists to stop: comss answers `daily-cloudcode-pa` with
    /// the genuine Google address and a TTL of 3199 s. Passed through unchanged,
    /// one lost race pins Windows to a blocked address for 53 minutes.
    #[test]
    fn an_answer_that_did_not_beat_the_gate_expires_quickly() {
        let mut long = reply_for("ttl-cap.example", 5, [172, 217, 115, 4]);
        let at = long.len() - 10;
        long[at..at + 4].copy_from_slice(&3199u32.to_be_bytes());
        assert_eq!(dns_client::answer_ttl(&long), Some(3199));

        for v in [Verdict::Passthrough, Verdict::Sibling, Verdict::Unknown] {
            let out = vet(long.clone(), v, false, None);
            assert_eq!(
                dns_client::answer_ttl(&out),
                Some(PASSTHROUGH_TTL),
                "{:?}",
                v
            );
        }
        // A substitution keeps the resolver's own TTL - it is the answer we want
        // the client to hold, and these providers already publish a short one.
        let subbed = vet(long.clone(), Verdict::Substituted, false, None);
        assert_eq!(dns_client::answer_ttl(&subbed), Some(3199));
    }

    /// A genuine answer must not evict, nor outrank, a substitution we already
    /// hold: that is the difference between one lost race and an hour of them.
    #[test]
    fn a_substitution_in_hand_beats_a_fresh_genuine_answer() {
        let _cache = clear_answers();
        let name = "prefer-sub.example";
        let query = query_for(name, 1, false);
        let good = reply_for(name, 1, [45, 155, 204, 190]);
        remember_answer(&query, &good, "geohide.ru", Verdict::Substituted, true);

        let genuine = reply_for(name, 1, [172, 217, 115, 4]);
        remember_answer(&query, &genuine, "comss.one", Verdict::Passthrough, true);

        // The cache still holds the substitution...
        let (cached, provider, verdict) = cached_answer(&query, false, true).unwrap();
        assert_eq!(provider, "geohide.ru");
        assert_eq!(verdict, Verdict::Substituted);
        assert_eq!(
            dns_client::answer_addrs(&cached),
            dns_client::answer_addrs(&good)
        );

        // ...and it is what goes out, not the genuine answer that just arrived.
        let fresh = (genuine, "comss.one", Verdict::Passthrough);
        let (out, who, v) = prefer_substituted(&query, true, fresh).unwrap();
        assert_eq!((who, v), ("geohide.ru", Verdict::Substituted));
        assert_eq!(
            dns_client::answer_addrs(&out),
            dns_client::answer_addrs(&good)
        );
    }

    /// With nothing better in hand the genuine answer is still served: refusing
    /// to answer would only push Windows onto the unvetted NRPT fallback.
    #[test]
    fn a_genuine_answer_is_served_when_there_is_nothing_better() {
        let _cache = clear_answers();
        let name = "no-sub.example";
        let query = query_for(name, 2, false);
        let genuine = reply_for(name, 2, [172, 217, 115, 4]);
        let fresh = (genuine, "comss.one", Verdict::Passthrough);
        let (_, who, v) = prefer_substituted(&query, true, fresh).unwrap();
        assert_eq!((who, v), ("comss.one", Verdict::Passthrough));
    }

    /// Before any client has asked, there is no shape to replay - warming still
    /// has to prime the name, or the first query pays the full cold price.
    #[test]
    fn an_unseen_name_is_warmed_with_a_plain_query() {
        let _cache = clear_answers();
        let queries = warm_queries(&["warm-unseen.example"]);
        assert_eq!(queries.len(), 1);
        assert_eq!(
            dns_client::question_name(&queries[0]).as_deref(),
            Some("warm-unseen.example")
        );
    }
}
