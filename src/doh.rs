use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, HandshakeKind};

// DNS-over-HTTPS, over a hand-written HTTP/2 client.
//
// Why hand-written. The resolver this exists for answers `505 HTTP Version Not
// Supported` to HTTP/1.1 and offers only `h2` in ALPN - measured on both of its
// addresses. The crate is synchronous and has no HTTP client at all, so the
// alternatives were the `h2` crate (which brings tokio, i.e. an async runtime,
// into a codebase that has none) or the subset of HTTP/2 a DoH exchange
// actually uses. It is a small subset, because one DoH query is one request and
// one response, and a connection carries its queries one after another:
//
// - no multiplexing: one stream at a time per connection, ids 1, 3, 5, ... A
//   connection is kept for the next query (`Pool`), never shared by two at once;
//   a thread that finds none free opens its own.
// - flow control, once: right after the preface the connection-level window is
//   raised to the maximum, so the server never runs out of it however many
//   replies one connection carries. Each stream's own window starts at 65 535,
//   which holds any DNS message, so no per-stream WINDOW_UPDATE is ever needed.
// - no dynamic HPACK table: the request is five headers, and nothing is sent
//   with indexing - on a long connection every unique `?dns=` would otherwise
//   churn the server's table. The *response* headers are never decoded at all,
//   so our decoder's state does not matter. Only DATA frames on the stream
//   being asked are read. The status code is not needed - an error page does
//   not parse as a DNS message, and every caller already handles "no usable
//   reply".
//
// What is deliberately NOT skipped: SETTINGS and PING are acknowledged (a server
// is entitled to drop a connection that ignores them), and GOAWAY/RST_STREAM are
// reported rather than waited out.
//
// Why connections are kept at all: dns-ai.ru measured (2026-09-18) ~195 new
// TCP connections and ~175 DoH handshakes a second per node, 1.06 queries per
// connection, and its CPU going mostly on TLS handshakes. One fresh connection
// per query was the design here, so this client paid for its share of that in
// full.
//
// Pinned to the ISP interface while a tunnel holds the default route, like every
// UDP resolver query (`dns_client::query_raw_via` + IP_UNICAST_IF, I4/N4), so a
// VPN cannot change the geolocation the provider sees. IP_UNICAST_IF has to be
// set *before* connect, which is why the socket comes from `net::connect`
// rather than `TcpStream::connect_timeout` (P13, closed in 2.14.0_1).

/// A DoH service: the name its certificate has to prove, the path that answers
/// RFC 8484 queries, and addresses to reach it at.
pub struct Endpoint {
    pub host: &'static str,
    pub path: &'static str,
    /// Hardcoded so the relay reaches the resolver on a machine whose own DNS is
    /// broken, poisoned, or simply not up yet - the same trick the relay route
    /// uses, and safe for the same reason: the certificate still has to prove
    /// `host`, so a wrong address cannot become a working man-in-the-middle.
    pub addrs: &'static [&'static str],
}

/// One address gets this much for connect + TLS + the exchange.
///
/// Sliced per candidate rather than shared across them: an address that
/// completes TCP and then hangs the handshake would otherwise spend the whole
/// budget and leave its healthy sibling untried - which is G23, one layer up.
const PER_ADDR_BUDGET: Duration = Duration::from_millis(2500);

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// A DNS reply that does not fit this is not a reply we would use.
const MAX_BODY: usize = 64 * 1024;

/// Raises the connection window from its initial 65 535 to 2^31-1, the most
/// RFC 7540 §6.9.1 allows. Without it the window is 65 535 bytes for the WHOLE
/// connection, never refilled: after ~65 KB of replies in total the server
/// stops sending DATA and the next query hangs until its budget runs out.
const CONN_WINDOW_INCREMENT: u32 = 0x7FFF_FFFF - 65_535;

/// A connection idle this long is not taken from the pool. dns-ai.ru's dnsdist
/// closes a DoH connection idle for 30 s (`idleTimeout = 30`); 20 leaves room
/// for a request that leaves just as the server's clock runs out. The warm
/// loop asks every ~15 s, which is what keeps a connection warm in practice.
const IDLE_LIMIT: Duration = Duration::from_secs(20);

/// Requests one connection carries before it is retired. Not a protocol limit:
/// a bound on how long one TLS session, one HPACK context and one stream-id
/// counter live, and a cheap one - a handshake per 500 queries.
const MAX_REQUESTS: u32 = 500;

/// Idle connections kept per address. More than one thread asks at once (the
/// provider race, the warm loop, the client's own A and AAAA), so one would
/// make every burst open fresh connections; the extras age out by `IDLE_LIMIT`.
const MAX_IDLE_PER_ADDR: usize = 2;

fn base_tls_config() -> &'static ClientConfig {
    static CFG: OnceLock<ClientConfig> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // Not shared with `proxy::upstream_config`, which pins http/1.1 for the
        // relay's CONNECT hop. This one must offer h2 and nothing else: if a
        // server were to pick http/1.1 the frames below would be nonsense on the
        // wire, and failing in ALPN is the honest place to find that out.
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        cfg
    })
}

/// The TLS config for one ADDRESS, not one process: each carries its own
/// session store.
///
/// rustls files tickets under the server name, and every address of an
/// `Endpoint` proves the same name - but they are separate machines, each with
/// its own ticket keys (on purpose; the operator will not share them). One
/// store, and a walk that alternates the nodes, meant every connection
/// presented the ticket the *other* node had issued: the store hands out the
/// newest one first. The node cannot decrypt it and falls back to a full
/// handshake - measured on dns-ai.ru 2026-09-18 as ~26 `tlsunknownticketkeys`
/// a second per node, with resumption almost never happening.
///
/// A store per address makes the server name mean one machine again.
fn tls_config(ip: IpAddr) -> Arc<ClientConfig> {
    static PER_ADDR: OnceLock<Mutex<HashMap<IpAddr, Arc<ClientConfig>>>> = OnceLock::new();
    let fresh = || {
        let mut cfg = base_tls_config().clone();
        // The clone copies the `Arc` of the base config's store, so without this
        // line every address would still share one - and nothing would change.
        //
        // 16 and not fewer, although one name is all a store here ever holds:
        // rustls sizes it in server names, (n + 7) / 8, and a one-name store
        // evicts its only entry the moment it is inserted (`LimitedCache` keeps
        // `len < capacity`). Any n <= 8 therefore resumes nothing - measured,
        // a test asking for 4 saw no node resume at all.
        cfg.resumption = Resumption::in_memory_sessions(16);
        Arc::new(cfg)
    };
    let Ok(mut map) = PER_ADDR.get_or_init(Default::default).lock() else {
        // Poisoned only by a panic inside `fresh`; a config that cannot resume
        // still connects, which is all this path has to guarantee.
        return fresh();
    };
    map.entry(ip).or_insert_with(fresh).clone()
}

/// base64url without padding (RFC 4648 §5), which is what `?dns=` takes.
fn base64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(A[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(A[n as usize & 63] as char);
        }
    }
    out
}

/// HPACK integer (RFC 7541 §5.1): `prefix` low bits of `first`, then
/// continuation octets. Written out rather than assumed small - a client query
/// carrying EDNS options pushes the encoded path past the 126 bytes a
/// single-octet length can hold, and that would be a corrupt request rather than
/// a slow one.
fn hpack_int(out: &mut Vec<u8>, mut value: usize, prefix: u32, first: u8) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(first | value as u8);
        return;
    }
    out.push(first | max as u8);
    value -= max;
    while value >= 128 {
        out.push(((value % 128) + 128) as u8);
        value /= 128;
    }
    out.push(value as u8);
}

/// HPACK string literal, never Huffman-coded: the H bit stays 0 so the bytes go
/// out as they are. Huffman would save a few dozen bytes on a request that is
/// already one packet.
fn hpack_string(out: &mut Vec<u8>, s: &[u8]) {
    hpack_int(out, s.len(), 7, 0x00);
    out.extend_from_slice(s);
}

/// The five headers of a DoH GET, HPACK-encoded.
fn request_headers(host: &str, path: &str) -> Vec<u8> {
    let mut h = Vec::with_capacity(192);
    // Indexed header field, static table: 2 = `:method GET`, 7 = `:scheme https`.
    h.push(0x82);
    h.push(0x87);
    // Literal WITHOUT indexing, name from the static table (RFC 7541 §6.2.2).
    // With incremental indexing (0x40) every request on a kept connection would
    // insert its unique `?dns=` path into the server's dynamic table, evicting
    // the last one - work for the server and nothing for us, since we never
    // refer back to the table. `:authority` repeats, but gains no more from it.
    hpack_int(&mut h, 1, 4, 0x00); // :authority
    hpack_string(&mut h, host.as_bytes());
    hpack_int(&mut h, 4, 4, 0x00); // :path
    hpack_string(&mut h, path.as_bytes());
    // Literal without indexing, new name.
    hpack_int(&mut h, 0, 4, 0x00);
    hpack_string(&mut h, b"accept");
    hpack_string(&mut h, b"application/dns-message");
    h
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(9 + payload.len());
    let len = payload.len() as u32;
    f.extend_from_slice(&len.to_be_bytes()[1..]);
    f.push(kind);
    f.push(flags);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// WINDOW_UPDATE (RFC 7540 §6.9): a 31-bit increment, the top bit reserved.
fn window_update(stream: u32, increment: u32) -> Vec<u8> {
    frame(
        FRAME_WINDOW_UPDATE,
        0,
        stream,
        &(increment & 0x7fff_ffff).to_be_bytes(),
    )
}

/// Where the next `query` begins its walk. One counter for the whole process:
/// it only decides an offset, so a second endpoint would still be walked
/// correctly, just phase-shifted.
static NEXT_ADDR: AtomicUsize = AtomicUsize::new(0);

/// The order `query` walks `n` addresses in, for a call that drew `start`.
///
/// Split out from `query` because `query` does network I/O and this does not:
/// the property worth pinning is that the walk is still a PERMUTATION of every
/// index — rotating the start must never cost an address its turn, or a rotation
/// would trade one failure mode for a worse one.
fn walk(n: usize, start: usize) -> impl Iterator<Item = usize> {
    (0..n).map(move |step| start.wrapping_add(step) % n)
}

/// Asks `ep` for `wire`, an RFC 1035 query, and returns the raw reply bytes.
///
/// Every address is tried, within the budget, and the first that answers speaks
/// for the endpoint — exactly as `ask_provider` treats a UDP provider's address
/// list. What differs is WHERE the walk starts: each call begins one further
/// along, round-robin.
///
/// That rotation is not load-balancing politeness, it is a correctness fix for
/// an assumption this function used to make. An `Endpoint`'s addresses are
/// **peer machines of one service**, not a primary and a backup. Walking them
/// from index 0 every time means the first one that works takes 100 % of the
/// queries and the rest are touched only when it breaks — which is what
/// happened: measured 2026-09-12, this tool was the entire reason one of
/// dns-ai.ru's two nodes ran at 48 % of a core while the other sat at 15 %
/// (G43). A counter costs nothing, spreads exactly, needs no RNG or new crate,
/// and keeps the fall-through: a dead address still only costs its own slice.
///
/// The rotation and the kept connections do not fight: each address has its
/// own, so alternating between them costs no handshake.
pub fn query(ep: &Endpoint, wire: &[u8], budget: Duration) -> Result<Vec<u8>, String> {
    let answer = query_via(&POOL, ep, wire, budget);
    if answer.is_ok() {
        crate::net::note_reached();
    }
    answer
}

/// `query` over a given pool - separate so a test can count what one pool
/// opened without the rest of the process sharing it.
fn query_via(pool: &Pool, ep: &Endpoint, wire: &[u8], budget: Duration) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + budget;
    let mut last = "нет адресов".to_string();
    let n = ep.addrs.len();
    if n == 0 {
        return Err(last);
    }
    let start = NEXT_ADDR.fetch_add(1, Ordering::Relaxed);
    let ips: Vec<IpAddr> = ep.addrs.iter().filter_map(|a| a.parse().ok()).collect();
    for ip in plan(&ips, start, Instant::now()) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        // An IPv6 address is tried with a short slice: a line without IPv6 either
        // refuses at once or blackholes, and a blackhole must not cost the full
        // slice of a healthy sibling. A working one completes in well under it.
        let cap = if ip.is_ipv6() {
            V6_BUDGET
        } else {
            PER_ADDR_BUDGET
        };
        let slice = cap.min(deadline - now);
        match query_one(pool, ep, ip, wire, slice) {
            Ok(reply) => {
                unbench(ip);
                return Ok(reply);
            }
            Err(e) => {
                // A slice cut short by the caller's deadline says nothing about
                // the address.
                if slice >= V6_BUDGET {
                    bench(ip, Instant::now());
                }
                last = e;
            }
        }
    }
    Err(last)
}

/// What an IPv6 address gets for connect + TLS + exchange.
const V6_BUDGET: Duration = Duration::from_millis(1200);

/// First and longest a failed address sits out, doubling per consecutive failure.
/// Short first step so a blip costs little; the cap keeps a line that gains IPv6
/// later (or a node that returns) from being forgotten for long.
const BENCH_FIRST: Duration = Duration::from_secs(30);
const BENCH_MAX: Duration = Duration::from_secs(15 * 60);

/// Address -> (benched until, consecutive failures). Process-wide like `POOL`:
/// whether `2a00:...` is reachable is a fact about this machine's line, not
/// about one endpoint or one caller.
static BENCH: Mutex<Option<HashMap<IpAddr, (Instant, u32)>>> = Mutex::new(None);

fn bench(ip: IpAddr, now: Instant) {
    let mut g = BENCH.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    let fails = map.get(&ip).map_or(0, |&(_, f)| f).saturating_add(1);
    map.insert(ip, (now + bench_for(fails), fails));
}

fn unbench(ip: IpAddr) {
    let mut g = BENCH.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = g.as_mut() {
        map.remove(&ip);
    }
}

fn bench_for(fails: u32) -> Duration {
    BENCH_FIRST
        .saturating_mul(1u32 << fails.saturating_sub(1).min(5))
        .min(BENCH_MAX)
}

/// The addresses to try, in walk order, minus the ones sitting out. When every
/// address is benched the whole list is tried anyway: a bench is a preference,
/// never a reason to answer nothing.
fn plan(ips: &[IpAddr], start: usize, now: Instant) -> Vec<IpAddr> {
    let g = BENCH.lock().unwrap_or_else(|e| e.into_inner());
    let out: Vec<IpAddr> = walk(ips.len(), start)
        .map(|i| ips[i])
        .filter(|ip| {
            g.as_ref()
                .and_then(|m| m.get(ip))
                .is_none_or(|&(until, _)| until <= now)
        })
        .collect();
    if out.is_empty() {
        return walk(ips.len(), start).map(|i| ips[i]).collect();
    }
    out
}

/// One address, one query: on a kept connection if there is one, and once
/// more on a fresh one if the kept one turns out to be gone. Both attempts
/// share `budget` - the address's slice - so a retry can never push `query`
/// past its own deadline.
fn query_one(
    pool: &Pool,
    ep: &Endpoint,
    ip: IpAddr,
    wire: &[u8],
    budget: Duration,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + budget;
    let path = format!("{}?dns={}", ep.path, base64url(wire));
    let mut kept = pool.take(ep.host, ip);
    loop {
        let reused = kept.is_some();
        let mut conn = match kept.take() {
            Some(conn) => conn,
            None => pool.open(ep, ip, deadline)?,
        };
        let outcome = conn.ask(&path, deadline);
        if keep_after(&outcome, conn.served) {
            pool.put(conn);
        } else {
            pool.dropped.fetch_add(1, Ordering::Relaxed);
            conn.close();
        }
        match outcome {
            Ok(answer) => return Ok(answer.body),
            Err(fail) if retry_on_fresh(reused, &fail) => {
                pool.retried.fetch_add(1, Ordering::Relaxed);
            }
            Err(fail) => return Err(fail.into_message()),
        }
    }
}

/// How an exchange failed, sorted by what may be done about it.
#[derive(Debug)]
enum Fail {
    /// The connection was gone before any of this stream's answer came back:
    /// EOF, a reset, a request that would not go out, or a GOAWAY stopping
    /// short of our stream (RFC 7540 §6.8: such a stream was not processed).
    /// On a kept connection that is the server having closed it between two
    /// queries - nothing wrong with the address - so the query is asked again
    /// on a fresh one. A DoH GET is idempotent, so asking twice is harmless.
    /// Not a corner case: dns-ai.ru closes kept connections on its own, a clean
    /// close_notify with no GOAWAY after anywhere from 2 to 69 queries, about
    /// one query in twenty on both nodes (measured 2026-09-18).
    Gone(String),
    /// Anything else: a timeout, a reset stream, a malformed frame, an answer
    /// cut off halfway. A second try at the same address would not help;
    /// `query` moves on to the next.
    Broken(String),
}

impl Fail {
    fn into_message(self) -> String {
        match self {
            Fail::Gone(m) | Fail::Broken(m) => m,
        }
    }
}

/// One stream's answer, and whether its connection may carry another.
#[derive(Debug)]
struct Answer {
    body: Vec<u8>,
    /// The server said GOAWAY while this answer was on its way: the answer
    /// stands, the connection is finished.
    last: bool,
}

/// Whether a failed query is asked again on a fresh connection: only when the
/// connection it failed on came from the pool, and only when it failed by
/// being gone. On a fresh connection the same failure is the address failing,
/// and `query` walks on exactly as it did before connections were kept.
fn retry_on_fresh(reused: bool, fail: &Fail) -> bool {
    reused && matches!(fail, Fail::Gone(_))
}

/// Whether a connection goes back to the pool after an exchange: only one that
/// read its answer cleanly, that the server has not said GOAWAY on, and that
/// has requests left. After any error its stream state is unknown - a frame
/// half read, a stream half answered - and the next query would inherit that.
fn keep_after(outcome: &Result<Answer, Fail>, served: u32) -> bool {
    matches!(outcome, Ok(answer) if !answer.last) && served < MAX_REQUESTS
}

/// Whether an idle connection is still worth taking: used for fewer than
/// `MAX_REQUESTS` queries and idle for less than `IDLE_LIMIT`. `now` is a
/// parameter so the rule can be tested without waiting 20 s.
fn takeable(last_used: Instant, served: u32, now: Instant) -> bool {
    served < MAX_REQUESTS && now.saturating_duration_since(last_used) < IDLE_LIMIT
}

/// The process's kept connections.
static POOL: Pool = Pool::new();

/// Idle h2 connections, per address. A connection is in here only while
/// nobody is using it: `take` removes it, `put` returns it, so two threads can
/// never hold the same one. A thread that finds none opens its own rather than
/// waiting for another thread to finish with one.
struct Pool {
    idle: Mutex<Vec<Conn>>,
    /// Connections this pool opened, how many of them resumed a TLS session,
    /// how many were closed after a query instead of kept (an error, a GOAWAY,
    /// the request limit), and how many queries found their kept connection
    /// already closed by the server. Read by the live tests; the relay does
    /// not report them.
    opened: AtomicUsize,
    resumed: AtomicUsize,
    dropped: AtomicUsize,
    retried: AtomicUsize,
}

impl Pool {
    const fn new() -> Pool {
        Pool {
            idle: Mutex::new(Vec::new()),
            opened: AtomicUsize::new(0),
            resumed: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
            retried: AtomicUsize::new(0),
        }
    }

    /// The most recently used idle connection to `ip`, if one is still worth
    /// using. Anything too old, to any address, is closed on the way: the pool
    /// has no thread of its own, so a lookup is when it gets tidied.
    fn take(&self, host: &str, ip: IpAddr) -> Option<Conn> {
        let now = Instant::now();
        let (found, stale) = {
            let Ok(mut idle) = self.idle.lock() else {
                return None;
            };
            let (fresh, stale): (Vec<Conn>, Vec<Conn>) = std::mem::take(&mut *idle)
                .into_iter()
                .partition(|c| takeable(c.last_used, c.served, now));
            *idle = fresh;
            let found = idle
                .iter()
                .rposition(|c| c.ip == ip && c.host == host)
                .map(|i| idle.remove(i));
            (found, stale)
        };
        // Outside the lock: a close writes to a socket.
        for conn in stale {
            conn.close();
        }
        found
    }

    /// Returns a connection for the next query. At most `MAX_IDLE_PER_ADDR` are
    /// kept per address; past that the longest-idle one is closed.
    fn put(&self, conn: Conn) {
        let evicted = {
            let Ok(mut idle) = self.idle.lock() else {
                conn.close();
                return;
            };
            let (ip, host) = (conn.ip, conn.host);
            let same = |c: &Conn| c.ip == ip && c.host == host;
            let evicted = if idle.iter().filter(|c| same(c)).count() >= MAX_IDLE_PER_ADDR {
                idle.iter().position(same).map(|i| idle.remove(i))
            } else {
                None
            };
            idle.push(conn);
            evicted
        };
        if let Some(conn) = evicted {
            conn.close();
        }
    }

    fn open(&self, ep: &Endpoint, ip: IpAddr, deadline: Instant) -> Result<Conn, String> {
        let conn = Conn::open(ep, ip, deadline)?;
        self.opened.fetch_add(1, Ordering::Relaxed);
        if conn.tls.handshake_kind() == Some(HandshakeKind::Resumed) {
            self.resumed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(conn)
    }

    /// Closes every idle connection. For the live tests only: the next query
    /// has to open - and, with its address's session store, resume.
    #[cfg(test)]
    fn clear(&self) {
        let all = match self.idle.lock() {
            Ok(mut idle) => std::mem::take(&mut *idle),
            Err(_) => return,
        };
        for conn in all {
            conn.close();
        }
    }
}

/// The socket under a kept connection: every read and every write is bounded
/// by one deadline, not by a timeout set once per query.
///
/// A timeout bounds a single `recv`, and one `rustls::Stream::read` can make
/// several - it loops until it holds a whole TLS record, taking in any session
/// ticket on the way - so an answer that trickled in could take the timeout
/// several times over and overrun the slice a retry has to fit in. Re-deriving
/// it from the deadline before every syscall is what makes the budget a budget.
struct Bounded {
    sock: TcpStream,
    deadline: Instant,
}

impl Bounded {
    fn left(&self) -> std::io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(ErrorKind::TimedOut.into())
        } else {
            Ok(left)
        }
    }
}

impl Read for Bounded {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.sock.set_read_timeout(Some(self.left()?))?;
        self.sock.read(buf)
    }
}

impl Write for Bounded {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sock.set_write_timeout(Some(self.left()?))?;
        self.sock.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

/// One h2 connection to one address, kept between queries.
struct Conn {
    host: &'static str,
    ip: IpAddr,
    sock: Bounded,
    tls: ClientConnection,
    /// Sent ahead of the first request and never again: the preface, our
    /// SETTINGS and the connection WINDOW_UPDATE. Queued rather than written at
    /// open so the first request still leaves in one write, as it always has.
    unsent: Vec<u8>,
    /// Client streams are odd and strictly increasing (RFC 7540 §5.1.1).
    next_stream: u32,
    /// Frame bytes read but not yet parsed, carried between queries - see
    /// `read_reply`.
    buf: Vec<u8>,
    last_used: Instant,
    /// Requests this connection has carried, `MAX_REQUESTS` at most.
    served: u32,
}

impl Conn {
    fn open(ep: &Endpoint, ip: IpAddr, deadline: Instant) -> Result<Conn, String> {
        let (sock, tls) = handshake(ep, ip, deadline)?;
        let mut unsent = Vec::with_capacity(64);
        unsent.extend_from_slice(PREFACE);
        unsent.extend_from_slice(&frame(FRAME_SETTINGS, 0, 0, &[]));
        unsent.extend_from_slice(&window_update(0, CONN_WINDOW_INCREMENT));
        Ok(Conn {
            host: ep.host,
            ip,
            sock: Bounded { sock, deadline },
            tls,
            unsent,
            next_stream: 1,
            buf: Vec::with_capacity(4096),
            last_used: Instant::now(),
            served: 0,
        })
    }

    /// One request on the next stream, and its answer.
    fn ask(&mut self, path: &str, deadline: Instant) -> Result<Answer, Fail> {
        let ip = self.ip;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Fail::Broken(format!("{}: бюджет истёк до запроса", ip)));
        }
        // A kept socket still carries the deadline of the query before it.
        self.sock.deadline = deadline;

        let stream = self.next_stream;
        self.next_stream += 2;
        self.served += 1;
        let mut out = std::mem::take(&mut self.unsent);
        out.extend_from_slice(&frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            stream,
            &request_headers(self.host, path),
        ));

        let mut tls = rustls::Stream::new(&mut self.tls, &mut self.sock);
        // Disambiguated: `rustls::Stream` offers these names through both
        // `std::io::Write` and `ReadWrite`. The flush is what reports a socket
        // that is already closed - `write` swallows that error by design.
        let sent =
            std::io::Write::write_all(&mut tls, &out).and_then(|_| std::io::Write::flush(&mut tls));
        let answer = match sent {
            Ok(()) => read_reply(&mut tls, &mut self.buf, stream, ip, deadline),
            Err(_) => Err(Fail::Gone(format!("{}: запрос не ушёл", ip))),
        };
        self.last_used = Instant::now();
        answer
    }

    /// Ends the connection politely - close_notify, so the server logs a clean
    /// close rather than a reset - without letting that cost anything: errors
    /// are ignored and the write gets a short leash. The socket closes on drop.
    fn close(mut self) {
        self.sock.deadline = Instant::now() + Duration::from_millis(200);
        self.tls.send_close_notify();
        let _ = self.tls.write_tls(&mut self.sock);
    }
}

/// TCP + TLS to one address, h2 negotiated, all inside `deadline`.
fn handshake(
    ep: &Endpoint,
    ip: IpAddr,
    deadline: Instant,
) -> Result<(TcpStream, ClientConnection), String> {
    let remaining = |d: Instant| d.saturating_duration_since(Instant::now());
    let budget = remaining(deadline);
    if budget.is_zero() {
        return Err(format!("{}: бюджет истёк до соединения", ip));
    }
    // Pinned to the ISP link while a tunnel holds the default route (P13): a
    // provider that substitutes only for Russian addresses answers a query that
    // arrives from the tunnel's foreign exit with the genuine address.
    let mut sock = crate::net::connect(
        SocketAddr::new(ip, 443),
        budget,
        crate::net::pin_interface(),
    )
    .map_err(|_| format!("{}: нет соединения", ip))?;
    sock.set_nodelay(true).ok();

    let server = ServerName::try_from(ep.host.to_string())
        .map_err(|_| "неверное имя DoH-сервера".to_string())?;
    let mut conn = ClientConnection::new(tls_config(ip), server)
        .map_err(|e| format!("TLS не настроен: {}", e))?;

    // Driven by hand so the budget covers the whole handshake rather than each
    // syscall inside it - the same shape `resolvers::reachable` uses, and for
    // the same reason: an address that completes TCP and stalls in TLS is the
    // failure this has to notice quickly (G23).
    while conn.is_handshaking() {
        let left = remaining(deadline);
        if left.is_zero() {
            return Err(format!("{}: TLS не уложился в бюджет", ip));
        }
        sock.set_read_timeout(Some(left)).ok();
        sock.set_write_timeout(Some(left)).ok();
        if conn.wants_write() {
            conn.write_tls(&mut sock)
                .map_err(|_| format!("{}: обрыв при handshake", ip))?;
        }
        if conn.is_handshaking() && conn.wants_read() {
            match conn.read_tls(&mut sock) {
                Ok(0) => return Err(format!("{}: сервер закрыл handshake", ip)),
                Ok(_) => conn
                    .process_new_packets()
                    .map(|_| ())
                    .map_err(|e| format!("{}: TLS отклонён: {}", ip, e))?,
                Err(_) => return Err(format!("{}: обрыв при handshake", ip)),
            }
        }
    }
    if conn.alpn_protocol() != Some(b"h2") {
        return Err(format!("{}: сервер не согласовал h2", ip));
    }
    Ok((sock, conn))
}

/// Reads frames until `stream` ends, collecting its DATA.
///
/// `buf` belongs to the connection, not to this call. One `read` can return the
/// end of this answer together with whatever the server sent next - a PING, a
/// SETTINGS, a WINDOW_UPDATE - and a buffer local to the call dropped those
/// bytes, so the next query on the connection would start parsing in the middle
/// of a frame. Frames already in `buf` are parsed before anything is read, and
/// whatever follows the end of this stream is left there for the next call.
fn read_reply(
    tls: &mut impl ReadWrite,
    buf: &mut Vec<u8>,
    stream: u32,
    ip: IpAddr,
    deadline: Instant,
) -> Result<Answer, Fail> {
    let mut body: Vec<u8> = Vec::new();
    // Whether any frame of THIS stream's answer has arrived. Until one has, a
    // connection that dies has told us nothing about the query (`Fail::Gone`).
    let mut started = false;
    let mut goaway = false;
    let mut chunk = [0u8; 4096];
    let lost = |started: bool, why: String| {
        if started {
            Fail::Broken(why)
        } else {
            Fail::Gone(why)
        }
    };

    loop {
        while buf.len() >= 9 {
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if len > MAX_BODY {
                return Err(Fail::Broken(format!(
                    "{}: кадр длиной {} — не ответ DNS",
                    ip, len
                )));
            }
            if buf.len() < 9 + len {
                break;
            }
            let kind = buf[3];
            let flags = buf[4];
            let id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
            let payload: Vec<u8> = buf[9..9 + len].to_vec();
            buf.drain(..9 + len);
            let word = |at: usize| {
                payload
                    .get(at..at + 4)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .unwrap_or(0)
            };

            match kind {
                FRAME_SETTINGS if flags & FLAG_ACK == 0 => {
                    tls.write_all(&frame(FRAME_SETTINGS, FLAG_ACK, 0, &[])).ok();
                    tls.flush().ok();
                }
                FRAME_PING if flags & FLAG_ACK == 0 => {
                    tls.write_all(&frame(FRAME_PING, FLAG_ACK, 0, &payload))
                        .ok();
                    tls.flush().ok();
                }
                FRAME_DATA if id == stream => {
                    started = true;
                    body.extend_from_slice(&payload);
                    if body.len() > MAX_BODY {
                        return Err(Fail::Broken(format!("{}: ответ слишком велик", ip)));
                    }
                    if flags & FLAG_END_STREAM != 0 {
                        return Ok(Answer { body, last: goaway });
                    }
                }
                FRAME_HEADERS if id == stream => {
                    started = true;
                    // A response with no body: nothing to hand back, and saying
                    // so beats returning bytes that will fail to parse as DNS.
                    if flags & FLAG_END_STREAM != 0 {
                        return if body.is_empty() {
                            Err(Fail::Broken(format!("{}: ответ без тела", ip)))
                        } else {
                            Ok(Answer { body, last: goaway })
                        };
                    }
                }
                FRAME_RST_STREAM if id == stream => {
                    return Err(Fail::Broken(format!(
                        "{}: поток сброшен, код {}",
                        ip,
                        word(0)
                    )));
                }
                FRAME_GOAWAY => {
                    let last_id = word(0) & 0x7fff_ffff;
                    if last_id < stream {
                        return Err(Fail::Gone(format!("{}: GOAWAY, код {}", ip, word(4))));
                    }
                    // Our stream is still answered; nothing after it will be.
                    goaway = true;
                }
                _ => {}
            }
        }

        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Fail::Broken(format!("{}: DoH не ответил в срок", ip)));
        }
        let n = match tls.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return Err(Fail::Broken(format!("{}: DoH не ответил в срок", ip)));
            }
            Err(_) => return Err(lost(started, format!("{}: обрыв ответа", ip))),
        };
        // An end before END_STREAM is a cut, not an answer - even with some
        // DATA in hand, those bytes are a truncated DNS message.
        if n == 0 {
            return Err(lost(started, format!("{}: сервер закрыл соединение", ip)));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// What `read_reply` needs from a connection; a trait only so it can be
/// exercised without a socket. The deadline is not in it: the socket under
/// the real one enforces it on every syscall (`Bounded`).
trait ReadWrite {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;
    fn flush(&mut self) -> std::io::Result<()>;
}

impl ReadWrite for rustls::Stream<'_, ClientConnection, Bounded> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Read::read(self, buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        Write::write_all(self, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Write::flush(self)
    }
}
#[cfg(test)]
mod tests {

    #[test]
    fn a_benched_address_leaves_the_plan_and_returns_when_the_bench_ends() {
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "2001:db8::1".parse().unwrap();
        let t0 = Instant::now();
        bench(b, t0);
        assert_eq!(plan(&[a, b], 0, t0), vec![a]);
        assert_eq!(
            plan(&[a, b], 0, t0 + BENCH_FIRST + Duration::from_secs(1)),
            vec![a, b]
        );
        unbench(b);
        assert_eq!(plan(&[a, b], 1, t0), vec![b, a]);
    }

    #[test]
    fn when_every_address_is_benched_all_are_still_tried() {
        let a: IpAddr = "203.0.113.7".parse().unwrap();
        let b: IpAddr = "2001:db8::7".parse().unwrap();
        let t0 = Instant::now();
        bench(a, t0);
        bench(b, t0);
        assert_eq!(plan(&[a, b], 0, t0).len(), 2);
        unbench(a);
        unbench(b);
    }

    #[test]
    fn the_bench_doubles_and_is_capped() {
        assert_eq!(bench_for(1), BENCH_FIRST);
        assert_eq!(bench_for(2), BENCH_FIRST * 2);
        assert_eq!(bench_for(40), BENCH_MAX);
    }
    use super::*;

    /// The rotation must not cost an address its turn: whatever the start, the
    /// walk is still every index exactly once. This is the half that makes the
    /// fall-through safe, and it is the half a "just start somewhere random"
    /// implementation gets wrong.
    #[test]
    fn walk_visits_every_address_once_from_any_start() {
        for n in 1..=5usize {
            for start in 0..(n * 3) {
                let mut seen: Vec<usize> = walk(n, start).collect();
                assert_eq!(seen.len(), n, "n={n} start={start}: wrong length");
                seen.sort_unstable();
                seen.dedup();
                assert_eq!(seen.len(), n, "n={n} start={start}: an index repeated");
                assert_eq!(
                    *seen.last().unwrap(),
                    n - 1,
                    "n={n} start={start}: out of range"
                );
            }
        }
    }

    /// Consecutive calls start one further along — that is the whole point, and
    /// it is what splits the load across a service's peer machines instead of
    /// pinning every query to whichever one happens to be first in the list.
    #[test]
    fn walk_advances_by_one_per_call() {
        assert_eq!(walk(2, 0).next(), Some(0));
        assert_eq!(walk(2, 1).next(), Some(1));
        assert_eq!(walk(2, 2).next(), Some(0));
        assert_eq!(walk(3, 7).collect::<Vec<_>>(), vec![1, 2, 0]);
    }

    /// `NEXT_ADDR` is a process-lifetime counter, so it wraps eventually. The
    /// `wrapping_add` is why that is a non-event; without it this panics in a
    /// debug build, months after release, on a machine nobody can reproduce.
    #[test]
    fn walk_survives_counter_wraparound() {
        assert_eq!(
            walk(2, usize::MAX).collect::<Vec<_>>(),
            vec![usize::MAX % 2, 0]
        );
        assert_eq!(walk(3, usize::MAX - 1).count(), 3);
    }

    #[test]
    fn base64url_matches_rfc_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_is_url_safe() {
        // 0xfb 0xff produces '+' and '/' in standard base64; here it must not.
        let s = base64url(&[0xfb, 0xff, 0xfe]);
        assert!(
            !s.contains('+') && !s.contains('/') && !s.contains('='),
            "{}",
            s
        );
    }

    #[test]
    fn hpack_int_uses_one_octet_below_the_prefix_maximum() {
        let mut v = Vec::new();
        hpack_int(&mut v, 1, 6, 0x40);
        assert_eq!(v, vec![0x41]);
        let mut v = Vec::new();
        hpack_int(&mut v, 10, 7, 0x00);
        assert_eq!(v, vec![10]);
    }

    /// RFC 7541 §C.1.1-C.1.2: 1337 with a 5-bit prefix is 31, 154, 10.
    #[test]
    fn hpack_int_continues_past_the_prefix() {
        let mut v = Vec::new();
        hpack_int(&mut v, 1337, 5, 0x00);
        assert_eq!(v, vec![31, 154, 10]);
    }

    /// The bug this guards: a query with EDNS options encodes to a path longer
    /// than a single-octet HPACK length can express, and a truncated length is a
    /// corrupt request rather than a slow one.
    #[test]
    fn a_long_path_still_encodes_its_length() {
        let long = "/dns-query?dns=".to_string() + &"A".repeat(400);
        let h = request_headers("dns.example", &long);
        // Length is 415 = 127 + 288 -> prefix octet then two continuation octets.
        let idx = h.windows(3).position(|w| w == [127, 160, 2]).map(|i| i);
        assert!(
            idx.is_some(),
            "длина пути закодирована неверно: {:?}",
            &h[..24]
        );
        assert!(h.ends_with(b"application/dns-message"));
    }

    #[test]
    fn request_headers_start_with_the_indexed_method_and_scheme() {
        let h = request_headers("dns.example", "/dns-query?dns=AAA");
        assert_eq!(h[0], 0x82, ":method GET");
        assert_eq!(h[1], 0x87, ":scheme https");
        assert_eq!(h[2], 0x01, ":authority");
    }

    /// Neither literal may carry the incremental-indexing bit: on a kept
    /// connection each unique `?dns=` would otherwise be inserted into the
    /// server's dynamic table. 0x01 / 0x04 are static-table names 1 and 4 with
    /// the 4-bit "without indexing" prefix (RFC 7541 §6.2.2).
    #[test]
    fn nothing_in_the_request_is_indexed() {
        let host = "dns.example";
        let h = request_headers(host, "/dns-query?dns=AAA");
        let path_at = 2 + 1 + 1 + host.len();
        assert_eq!(h[2], 0x01, ":authority, literal without indexing");
        assert_eq!(h[path_at], 0x04, ":path, literal without indexing");
        for at in [2, path_at] {
            assert_ne!(h[at] & 0xc0, 0x40, "октет {}: incremental indexing", at);
        }
    }

    /// Type 0x8 on stream 0, four payload octets, and the increment that takes
    /// the connection window from 65 535 to exactly 2^31-1.
    #[test]
    fn window_update_raises_the_connection_window_to_the_maximum() {
        let f = window_update(0, CONN_WINDOW_INCREMENT);
        assert_eq!(
            f,
            vec![
                0,
                0,
                4,
                FRAME_WINDOW_UPDATE,
                0,
                0,
                0,
                0,
                0,
                0x7f,
                0xff,
                0x00,
                0x00
            ]
        );
        assert_eq!(65_535u64 + CONN_WINDOW_INCREMENT as u64, (1u64 << 31) - 1);
        // The reserved bit stays clear whatever is asked for.
        assert_eq!(window_update(3, u32::MAX)[9], 0x7f);
    }

    #[test]
    fn frame_header_is_nine_octets_big_endian() {
        let f = frame(FRAME_DATA, FLAG_END_STREAM, 1, b"xy");
        assert_eq!(&f[..3], &[0, 0, 2]);
        assert_eq!(f[3], FRAME_DATA);
        assert_eq!(f[4], FLAG_END_STREAM);
        assert_eq!(&f[5..9], &[0, 0, 0, 1]);
        assert_eq!(&f[9..], b"xy");
    }

    /// A scripted server: SETTINGS, then HEADERS, then DATA split across two
    /// frames with END_STREAM on the last.
    struct Scripted {
        to_read: Vec<u8>,
        pos: usize,
        written: Vec<u8>,
        /// Bytes per `read`: small by default, to split frames across reads.
        max_read: usize,
    }

    impl ReadWrite for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (self.to_read.len() - self.pos)
                .min(buf.len())
                .min(self.max_read);
            buf[..n].copy_from_slice(&self.to_read[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
        fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
            self.written.extend_from_slice(buf);
            Ok(())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn scripted(script: Vec<u8>) -> Scripted {
        Scripted {
            to_read: script,
            pos: 0,
            written: Vec::new(),
            max_read: 7,
        }
    }

    fn read_stream(s: &mut Scripted, buf: &mut Vec<u8>, stream: u32) -> Result<Answer, Fail> {
        read_reply(
            s,
            buf,
            stream,
            "127.0.0.1".parse().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
    }

    fn run(script: Vec<u8>) -> (Result<Vec<u8>, String>, Vec<u8>) {
        let mut s = scripted(script);
        let out = read_stream(&mut s, &mut Vec::new(), 1)
            .map(|a| a.body)
            .map_err(Fail::into_message);
        (out, s.written)
    }

    #[test]
    fn reassembles_data_split_across_frames_and_reads() {
        let mut script = Vec::new();
        script.extend_from_slice(&frame(FRAME_SETTINGS, 0, 0, &[]));
        script.extend_from_slice(&frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x88]));
        script.extend_from_slice(&frame(FRAME_DATA, 0, 1, b"hello "));
        script.extend_from_slice(&frame(FRAME_DATA, FLAG_END_STREAM, 1, b"world"));
        let (out, written) = run(script);
        assert_eq!(out.unwrap(), b"hello world");
        // The server's SETTINGS must have been acknowledged.
        assert_eq!(written, frame(FRAME_SETTINGS, FLAG_ACK, 0, &[]));
    }

    #[test]
    fn a_ping_is_acknowledged_with_its_own_payload() {
        let mut script = Vec::new();
        script.extend_from_slice(&frame(FRAME_PING, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]));
        script.extend_from_slice(&frame(FRAME_DATA, FLAG_END_STREAM, 1, b"ok"));
        let (out, written) = run(script);
        assert_eq!(out.unwrap(), b"ok");
        assert!(written.ends_with(&[1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn goaway_and_rst_stream_are_reported_not_waited_out() {
        let (out, _) = run(frame(FRAME_GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 11]));
        assert!(out.unwrap_err().contains("GOAWAY"));

        let (out, _) = run(frame(FRAME_RST_STREAM, 0, 1, &[0, 0, 0, 8]));
        assert!(out.unwrap_err().contains("сброшен"));
    }

    #[test]
    fn a_headers_only_response_is_an_error_not_an_empty_answer() {
        let script = frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &[0x88],
        );
        let (out, _) = run(script);
        assert!(out.unwrap_err().contains("без тела"));
    }

    /// A length field larger than any DNS reply must be refused outright rather
    /// than used to size an allocation.
    #[test]
    fn an_absurd_frame_length_is_refused() {
        let (out, _) = run(vec![0xff, 0xff, 0xff, FRAME_DATA, 0, 0, 0, 0, 1]);
        assert!(out.unwrap_err().contains("не ответ DNS"));
    }

    /// The second query on a connection is stream 3: DATA for any other stream
    /// is not its answer, and whatever arrives after its END_STREAM stays in
    /// the buffer, whole, for the next query.
    #[test]
    fn a_later_stream_skips_other_streams_and_keeps_the_tail() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&frame(FRAME_DATA, FLAG_END_STREAM, 1, b"stale"));
        buf.extend_from_slice(&frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &[0x88]));
        buf.extend_from_slice(&frame(FRAME_DATA, FLAG_END_STREAM, 3, b"mine"));
        let tail = frame(FRAME_PING, 0, 0, &[9, 9, 9, 9, 9, 9, 9, 9]);
        buf.extend_from_slice(&tail);
        // A partial frame behind it: its first bytes must survive as well.
        buf.extend_from_slice(&frame(FRAME_WINDOW_UPDATE, 0, 0, &[0, 0, 1, 0])[..5]);
        let expected_tail = buf[buf.len() - tail.len() - 5..].to_vec();

        // Nothing to read from the socket: all of it arrived in one piece.
        let mut s = scripted(Vec::new());
        let answer = read_stream(&mut s, &mut buf, 3).unwrap();
        assert_eq!(answer.body, b"mine");
        assert!(!answer.last);
        assert_eq!(buf, expected_tail, "хвост после END_STREAM потерян");
        assert!(s.written.is_empty(), "the PING belongs to the next call");
    }

    /// Two answers in one read: the first call must stop at its own
    /// END_STREAM and the second must find its answer already buffered -
    /// without reading anything more, since nothing more is coming.
    #[test]
    fn two_answers_in_one_piece_are_read_by_two_calls() {
        let mut script = Vec::new();
        script.extend_from_slice(&frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x88]));
        script.extend_from_slice(&frame(FRAME_DATA, FLAG_END_STREAM, 1, b"first"));
        script.extend_from_slice(&frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &[0x88]));
        script.extend_from_slice(&frame(FRAME_DATA, 0, 3, b"sec"));
        script.extend_from_slice(&frame(FRAME_DATA, FLAG_END_STREAM, 3, b"ond"));
        let mut s = scripted(script);
        s.max_read = usize::MAX;
        let mut buf = Vec::new();
        assert_eq!(read_stream(&mut s, &mut buf, 1).unwrap().body, b"first");
        assert_eq!(s.pos, s.to_read.len(), "one read took everything");
        assert_eq!(read_stream(&mut s, &mut buf, 3).unwrap().body, b"second");
        assert!(buf.is_empty());
    }

    /// Frames left from the previous query are handled before anything is
    /// read: a PING that arrived behind the last answer is acknowledged.
    #[test]
    fn frames_left_by_the_last_query_are_handled_first() {
        let mut buf = frame(FRAME_PING, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut s = scripted(frame(FRAME_DATA, FLAG_END_STREAM, 5, b"ok"));
        assert_eq!(read_stream(&mut s, &mut buf, 5).unwrap().body, b"ok");
        assert_eq!(
            s.written,
            frame(FRAME_PING, FLAG_ACK, 0, &[1, 2, 3, 4, 5, 6, 7, 8])
        );
    }

    /// GOAWAY that still covers our stream: the answer is coming, so read it -
    /// and mark the connection finished.
    #[test]
    fn goaway_covering_our_stream_still_delivers_the_answer() {
        let mut script = frame(FRAME_GOAWAY, 0, 0, &[0, 0, 0, 3, 0, 0, 0, 0]);
        script.extend_from_slice(&frame(FRAME_DATA, FLAG_END_STREAM, 3, b"ok"));
        let answer = read_stream(&mut scripted(script), &mut Vec::new(), 3).unwrap();
        assert_eq!(answer.body, b"ok");
        assert!(answer.last, "после GOAWAY соединение не возвращают в пул");
    }

    /// GOAWAY below our stream: the server says it will not process it. That is
    /// `Gone` - worth one retry on a fresh connection - not `Broken`.
    #[test]
    fn goaway_short_of_our_stream_is_gone() {
        let script = frame(FRAME_GOAWAY, 0, 0, &[0, 0, 0, 5, 0, 0, 0, 0]);
        let out = read_stream(&mut scripted(script), &mut Vec::new(), 7);
        assert!(
            matches!(out, Err(Fail::Gone(ref m)) if m.contains("GOAWAY")),
            "{:?}",
            out
        );
    }

    /// EOF before any frame of our answer: the kept connection had been closed
    /// under us, so `Gone`. EOF halfway through the answer: `Broken` - and not
    /// the truncated bytes passed off as an answer.
    #[test]
    fn an_early_eof_is_gone_and_a_late_one_is_broken() {
        let out = read_stream(&mut scripted(Vec::new()), &mut Vec::new(), 3);
        assert!(matches!(out, Err(Fail::Gone(_))), "{:?}", out);

        let script = frame(FRAME_DATA, 0, 3, b"half");
        let out = read_stream(&mut scripted(script), &mut Vec::new(), 3);
        assert!(matches!(out, Err(Fail::Broken(_))), "{:?}", out);
    }

    /// A malformed RST_STREAM (payload shorter than its 4-octet code) is an
    /// error, not an index panic.
    #[test]
    fn a_short_rst_stream_is_an_error_not_a_panic() {
        let (out, _) = run(frame(FRAME_RST_STREAM, 0, 1, &[0]));
        assert!(out.unwrap_err().contains("сброшен"));
    }

    #[test]
    fn a_connection_is_taken_only_while_fresh_and_under_its_request_limit() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        assert!(takeable(t0, 0, t0));
        assert!(takeable(t0, 1, t0 + s(19)));
        assert!(!takeable(t0, 1, t0 + IDLE_LIMIT), "простой 20 с — уже нет");
        assert!(!takeable(t0, 1, t0 + s(29)));
        assert!(takeable(t0, MAX_REQUESTS - 1, t0 + s(1)));
        assert!(!takeable(t0, MAX_REQUESTS, t0 + s(1)));
        // A `now` earlier than `last_used` is not idle time.
        assert!(takeable(t0 + s(5), 1, t0));
    }

    #[test]
    fn a_connection_goes_back_only_after_a_clean_answer() {
        let answer = |last: bool| -> Result<Answer, Fail> {
            Ok(Answer {
                body: b"x".to_vec(),
                last,
            })
        };
        assert!(keep_after(&answer(false), 1));
        assert!(!keep_after(&Err(Fail::Gone("x".into())), 1));
        assert!(!keep_after(&Err(Fail::Broken("x".into())), 1));
        assert!(!keep_after(&answer(true), 1), "GOAWAY");
        assert!(keep_after(&answer(false), MAX_REQUESTS - 1));
        assert!(
            !keep_after(&answer(false), MAX_REQUESTS),
            "исчерпан лимит запросов"
        );
    }

    /// One retry, only for a kept connection that turned out to be gone. A
    /// fresh connection failing is the address failing - `query` walks on.
    #[test]
    fn only_a_gone_kept_connection_is_retried() {
        assert!(retry_on_fresh(true, &Fail::Gone("x".into())));
        assert!(!retry_on_fresh(true, &Fail::Broken("x".into())));
        assert!(!retry_on_fresh(false, &Fail::Gone("x".into())));
        assert!(!retry_on_fresh(false, &Fail::Broken("x".into())));
    }

    /// The whole point, end to end: the hand-written h2 client gets a real answer
    /// out of a real DoH server, and that answer is a **substitution**.
    ///
    /// The second half is the assertion that matters. "It answered" is what let
    /// an upstream change go unnoticed for a release (see `resolvers`), so this
    /// compares against 8.8.8.8 and fails if the reply merely carries genuine
    /// Google - which is what a passthrough looks like and parses perfectly.
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn reaches_a_real_doh_server_and_gets_a_substitution() {
        use crate::dns_client;
        let endpoint = &crate::resolvers::DNS_AI;

        for name in [
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
        ] {
            let q = dns_client::build_query(name, 0x7A7A);
            let reply = query(endpoint, &q, Duration::from_secs(8))
                .unwrap_or_else(|e| panic!("{}: {}", name, e));

            assert_eq!(&reply[0..2], &q[0..2], "id must come back");
            let got = dns_client::answer_addrs(&reply);
            assert!(!got.is_empty(), "{}: пустой ответ", name);

            let reference = dns_client::resolve_a_via(name, "8.8.8.8".parse().unwrap(), 0)
                .expect("reference resolver");
            let ref16: Vec<[u8; 2]> = reference
                .iter()
                .map(|a| [a.octets()[0], a.octets()[1]])
                .collect();
            let passthrough = got.iter().any(|a| match a {
                IpAddr::V4(v) => ref16.contains(&[v.octets()[0], v.octets()[1]]),
                IpAddr::V6(_) => false,
            });
            assert!(
                !passthrough,
                "{}: ответ {:?} лежит в той же /16, что и эталон {:?} - это passthrough, \
                 а не подмена",
                name, got, reference
            );
            println!("{} -> {:?} (эталон {:?})", name, got, reference);
        }
    }

    /// Live: **every** node, not just whichever answers first - each address is
    /// asked for both gate names on its own connection, and each answer has to
    /// be a substitution (P14: "the addresses too"). One dead or passthrough node
    /// in the walk costs a share of all queries a timeout or a wrong answer, and
    /// `reaches_a_real_doh_server_and_gets_a_substitution` would not notice it
    /// as long as another node answered first (G43).
    ///
    ///     cargo test every_node_substitutes_both_gate_names -- --ignored --nocapture
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn every_node_substitutes_both_gate_names() {
        use crate::dns_client;
        let ep = &crate::resolvers::DNS_AI;
        for addr in ep.addrs {
            let ip: IpAddr = addr.parse().expect("an address");
            for name in [
                "cloudcode-pa.googleapis.com",
                "daily-cloudcode-pa.googleapis.com",
            ] {
                let q = dns_client::build_query(name, 0x4E4E);
                let started = Instant::now();
                let reply = query_one(&Pool::new(), ep, ip, &q, Duration::from_secs(8))
                    .unwrap_or_else(|e| panic!("{} {}: {}", addr, name, e));
                let got = dns_client::answer_addrs(&reply);
                let reference = dns_client::resolve_a_via(name, "8.8.8.8".parse().unwrap(), 0)
                    .expect("reference resolver");
                let ref16: Vec<[u8; 2]> = reference
                    .iter()
                    .map(|a| [a.octets()[0], a.octets()[1]])
                    .collect();
                let passthrough = got.iter().any(|a| match a {
                    IpAddr::V4(v) => ref16.contains(&[v.octets()[0], v.octets()[1]]),
                    IpAddr::V6(_) => false,
                });
                println!(
                    "{:<15} {:<34} {:>4} мс  {:?}",
                    addr,
                    name,
                    started.elapsed().as_millis(),
                    got
                );
                assert!(!got.is_empty(), "{} {}: пустой ответ", addr, name);
                assert!(
                    !passthrough,
                    "{} {}: {:?} — подлинный Google, узел не подменяет",
                    addr, name, got
                );
            }
        }
    }

    /// Each address resumes the session **it** issued. The walk alternates the
    /// two nodes, and rustls hands out the newest ticket stored under the server
    /// name - so with one store per process every connection presented the
    /// *other* node's ticket, which that node cannot decrypt (ticket keys are
    /// per node, on purpose). The server side counted it as
    /// `tlsunknownticketkeys`, ~26/s per node, each one a full handshake.
    ///
    /// A, B, then A again is exactly that interleaving: with a shared store the
    /// second round is `Full`.
    ///
    /// A node that resumes nothing at all is left out, and said so: msk1
    /// (`94.232.43.149`, nginx, withdrawn 2026-09-27) issued two tickets on
    /// every handshake and accepted none, measured 2026-09-18 - a server
    /// setting, not something a client store can fix. `node_resumes` asks each node on a store of its own.
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn each_address_resumes_its_own_session() {
        use crate::dns_client;
        use std::sync::atomic::Ordering::Relaxed;
        let ep = &crate::resolvers::DNS_AI;
        let ips: Vec<IpAddr> = ep.addrs.iter().map(|a| a.parse().unwrap()).collect();
        assert!(ips.len() >= 2, "the point is two peer nodes");
        let resuming: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|&ip| node_resumes(ep, ip))
            .collect();
        for ip in ips.iter().filter(|ip| !resuming.contains(ip)) {
            println!("{}: узел не принимает даже свои билеты — пропущен", ip);
        }
        assert!(!resuming.is_empty(), "ни один узел не возобновляет сессии");
        let q = dns_client::build_query("cloudcode-pa.googleapis.com", 0x5151);

        // One exchange per node, in walk order, each on a connection that was
        // a FULL handshake: then every store holds tickets its node has just
        // issued, whatever an earlier test left in it or took out. Reading the
        // reply is what takes the tickets in.
        let pool = Pool::new();
        for &ip in &ips {
            for _ in 0..10 {
                let before = pool.resumed.load(Relaxed);
                query_one(&pool, ep, ip, &q, Duration::from_secs(8))
                    .unwrap_or_else(|e| panic!("{}", e));
                pool.clear();
                if pool.resumed.load(Relaxed) == before {
                    break;
                }
            }
        }
        for &ip in &resuming {
            let (_, conn) = handshake(ep, ip, Instant::now() + Duration::from_secs(8))
                .unwrap_or_else(|e| panic!("{}", e));
            assert_eq!(
                conn.handshake_kind(),
                Some(HandshakeKind::Resumed),
                "{}: полное рукопожатие — предъявлен чужой билет",
                ip
            );
        }
    }

    /// Whether `ip` resumes a session it issued at all, asked on a config of
    /// the test's own so the per-address stores under test are not touched:
    /// the first connection takes in the node's tickets, the second presents
    /// one. `handshake_kind` alone cannot tell "this node resumes nothing"
    /// from "we offered it another node's ticket" - both are `Full`.
    ///
    /// Each connection carries one whole query before it is closed, as every
    /// real one does. Closing as soon as the tickets were in - no exchange at
    /// all - made msk3 and spb1 refuse them on the next connection (observed
    /// 2026-09-18; the mechanism on their side is unmeasured), which read as
    /// "no node resumes".
    fn node_resumes(ep: &Endpoint, ip: IpAddr) -> bool {
        let mut cfg = base_tls_config().clone();
        // 16 like `tls_config`, for the reason given there: 4 stores nothing.
        cfg.resumption = Resumption::in_memory_sessions(16);
        let cfg = Arc::new(cfg);
        let q = crate::dns_client::build_query("cloudcode-pa.googleapis.com", 0x5252);
        let path = format!("{}?dns={}", ep.path, base64url(&q));
        let mut kind = None;
        for _ in 0..2 {
            let deadline = Instant::now() + Duration::from_secs(5);
            let sock =
                TcpStream::connect_timeout(&SocketAddr::new(ip, 443), Duration::from_secs(5))
                    .unwrap_or_else(|e| panic!("{}: {}", ip, e));
            let mut sock = Bounded { sock, deadline };
            let name = ServerName::try_from(ep.host.to_string()).unwrap();
            let mut conn = ClientConnection::new(cfg.clone(), name).unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut sock)
                    .unwrap_or_else(|e| panic!("{}: {}", ip, e));
            }
            kind = conn.handshake_kind();

            let mut out = PREFACE.to_vec();
            out.extend_from_slice(&frame(FRAME_SETTINGS, 0, 0, &[]));
            out.extend_from_slice(&frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                &request_headers(ep.host, &path),
            ));
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            std::io::Write::write_all(&mut tls, &out).unwrap();
            std::io::Write::flush(&mut tls).unwrap();
            read_reply(&mut tls, &mut Vec::new(), 1, ip, deadline)
                .unwrap_or_else(|f| panic!("{}", f.into_message()));
            conn.send_close_notify();
            let _ = conn.write_tls(&mut sock);
        }
        kind == Some(HandshakeKind::Resumed)
    }
    /// A well-formed answer to `q`: same id, a response, NOERROR, and at
    /// least one address. "Valid DNS" and not just "bytes came back" - an
    /// error page or a frame from the wrong stream fails here.
    fn assert_answers(q: &[u8], reply: &[u8]) {
        assert!(reply.len() >= 12, "короткий ответ: {:?}", reply);
        assert_eq!(&reply[0..2], &q[0..2], "id must come back");
        assert_ne!(reply[2] & 0x80, 0, "QR: это не ответ");
        assert_eq!(reply[3] & 0x0f, 0, "RCODE {}", reply[3] & 0x0f);
        assert!(
            !crate::dns_client::answer_addrs(reply).is_empty(),
            "ни одного адреса"
        );
    }

    /// The point of the pool, measured: 50 queries in a row, walked across both
    /// nodes the way the relay walks them. Before the pool that was 50 TCP
    /// connections and 50 TLS handshakes.
    ///
    /// The assertion is on what the CLIENT decides: past the first connection
    /// to each node, a new one is opened only to replace one that was dropped -
    /// closed by the server under us, retired after a GOAWAY, or given up after
    /// an error. The server does close them - measured 2026-09-18, msk3 and spb1,
    /// a clean close_notify with no GOAWAY after anywhere from 2 to 69 queries,
    /// about one query in twenty - so a fixed "at most 4" holds on some runs
    /// and not others, and says nothing either way about this code.
    ///
    /// Then the pool is emptied, and new connections to each node have to
    /// resume the session that node issued. The service issues two tickets
    /// per full handshake and none per resumption (measured: F R R F R R ...),
    /// and a TLS 1.3 ticket is single-use, so a node's store can be empty at
    /// that moment; of any two consecutive new connections, though, one must
    /// resume. Two fulls in a row is the bug step 1 fixed.
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn keeps_one_connection_per_address_and_resumes_after() {
        use crate::dns_client;
        use std::sync::atomic::Ordering::Relaxed;
        let ep = &crate::resolvers::DNS_AI;
        let pool = Pool::new();
        let names = [
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
        ];

        for i in 0..50u16 {
            let q = dns_client::build_query(names[i as usize % 2], 0x1000 + i);
            let reply = query_via(&pool, ep, &q, Duration::from_secs(8))
                .unwrap_or_else(|e| panic!("запрос {}: {}", i, e));
            assert_answers(&q, &reply);
        }
        let opened = pool.opened.load(Relaxed);
        let dropped = pool.dropped.load(Relaxed);
        let retried = pool.retried.load(Relaxed);
        println!(
            "50 запросов: {} соединений; выброшено после запроса {}, из них {} закрыл сервер",
            opened, dropped, retried
        );
        assert!(
            opened <= ep.addrs.len() + dropped,
            "{} соединений на {} адреса при {} выброшенных - клиент открывает лишние",
            opened,
            ep.addrs.len(),
            dropped
        );

        for (i, addr) in ep.addrs.iter().enumerate() {
            let ip: IpAddr = addr.parse().unwrap();
            if !node_resumes(ep, ip) {
                println!("{}: узел не принимает даже свои билеты — пропущен", ip);
                continue;
            }
            let mut kinds = String::new();
            for round in 0..2u16 {
                pool.clear();
                let before = pool.resumed.load(Relaxed);
                let q = dns_client::build_query(names[0], 0x2000 + i as u16 * 8 + round);
                let reply = query_one(&pool, ep, ip, &q, Duration::from_secs(8))
                    .unwrap_or_else(|e| panic!("{}", e));
                assert_answers(&q, &reply);
                kinds.push(if pool.resumed.load(Relaxed) > before {
                    'R'
                } else {
                    'F'
                });
            }
            println!("{}: после сброса пула {}", ip, kinds);
            assert_ne!(kinds, "FF", "{}: два полных рукопожатия подряд", ip);
        }
        pool.clear();
    }

    /// Flow control, against the real server: one connection carries more
    /// than the 65 535 bytes of connection window it starts with. Without the
    /// WINDOW_UPDATE sent at open, the server stops sending DATA somewhere
    /// past that mark and the query waits out its budget.
    ///
    /// TXT with EDNS for two names whose answers are 4.5-5.4 KB (measured), so
    /// the mark is passed in ~14 queries: the server closes a connection about
    /// once in twenty queries, and one that is closed early just means the
    /// count starts again on the next.
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn one_connection_carries_more_than_the_initial_window() {
        use crate::dns_client;
        use std::sync::atomic::Ordering::Relaxed;
        let ep = &crate::resolvers::DNS_AI;
        let ip: IpAddr = ep.addrs[0].parse().unwrap();
        let pool = Pool::new();

        let txt_query = |name: &str, id: u16| {
            let mut q = dns_client::build_query(name, id);
            let at = q.len() - 3;
            q[at] = 16; // TXT
            q[11] = 1; // one additional record: OPT
                       // OPT: root name, type 41, 4096-byte payload, no flags, no data.
            q.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
            q
        };

        let mut carried = 0usize;
        let mut on = 0usize;
        let mut sent = 0u16;
        while carried <= 70_000 {
            assert!(
                sent < 300,
                "за 300 запросов ни одно соединение не набрало 70 КБ"
            );
            let name = ["microsoft.com", "amazon.com"][sent as usize % 2];
            let q = txt_query(name, 0x3000 + sent);
            let reply = query_one(&pool, ep, ip, &q, Duration::from_secs(8))
                .unwrap_or_else(|e| panic!("после {} байт по соединению: {}", carried, e));
            assert_eq!(&reply[0..2], &q[0..2]);
            let now_on = pool.opened.load(Relaxed);
            if now_on != on {
                on = now_on;
                carried = 0;
            }
            carried += reply.len();
            sent += 1;
        }
        println!(
            "{} байт по одному соединению; {} запросов, {} соединений",
            carried,
            sent,
            pool.opened.load(Relaxed)
        );
        pool.clear();
    }
}
