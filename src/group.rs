//! Group proxy: the owner's dedicated server, whitelisted to the 2 gate hosts.
//! Credential is private in `.group`.
//! No region probe because the server refuses trace hosts (cloudflare etc.) by design;
//! its region is known to be correct.

use std::cell::Cell;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::crypto::ring::default_provider;
use rustls::pki_types::ServerName;
use rustls::ClientConnection;
use sha2::{Digest, Sha256};

use crate::group_key::GroupKey;
use crate::settings;
use crate::upstream::{self, Route, Upstream};

/// One server of the pool. The key names the first (the bootstrap); the rest
/// are learned from the servers' own signed status answers, so a server added
/// later needs no new key. Named in logs by number only, never by host (I46).
struct Server {
    host: String,
    port: u16,
    addrs: Option<(Vec<SocketAddr>, Instant)>,
    /// The last status poll reached it. Starts true: untried is not dead.
    ok: bool,
    /// The last tunnel or probe through it worked. Kept apart from `ok`: a
    /// server can answer its status and still fail to reach Google, and a status
    /// answer must not hide that. Only a working probe sets it back.
    tunnel_ok: bool,
    /// CPU load in percent from its last status answer; None = never answered.
    cpu: Option<i64>,
    /// Region-400 came back through it: its exit is not in a permitted country.
    /// Kept apart from `tunnel_ok` too — the tunnel to it opens fine and a
    /// passing probe (which never reaches a gate host) must not clear this.
    benched_until: Option<Instant>,
}

impl Server {
    fn new(host: String, port: u16) -> Self {
        Server {
            host,
            port,
            addrs: None,
            ok: true,
            tunnel_ok: true,
            cpu: None,
            benched_until: None,
        }
    }
    fn benched(&self) -> bool {
        self.benched_until.is_some_and(|t| Instant::now() < t)
    }
    fn name(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

struct GroupState {
    key_string: String,
    parsed: Option<GroupKey>,
    servers: Vec<Server>,
    /// The server new tunnels go to. Changes only while no tunnel is open, or
    /// when it stops answering — a switch never cuts a model answer midway.
    current: Option<usize>,
}

fn group_state() -> &'static Mutex<GroupState> {
    static STATE: OnceLock<Mutex<GroupState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(GroupState {
            key_string: String::new(),
            parsed: None,
            servers: Vec::new(),
            current: None,
        })
    })
}

/// Tunnels open through the group right now (any server).
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

struct ActiveGuard;
impl ActiveGuard {
    fn new() -> Self {
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        ActiveGuard
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A server must be this many CPU points less loaded to take over.
const SWITCH_MARGIN: i64 = 20;
/// Load assumed for a server that has not reported one.
const UNKNOWN_CPU: i64 = 50;
const MAX_SERVERS: usize = 16;
/// Servers asked per poll before giving up until the next one.
const STATUS_TRIES: usize = 3;

#[derive(Clone, Copy)]
struct Cand {
    ok: bool,
    cpu: Option<i64>,
}

fn load(c: Cand) -> i64 {
    c.cpu.filter(|&v| v >= 0).unwrap_or(UNKNOWN_CPU)
}

/// Which server new tunnels use. Sticky: with any tunnel open the current one
/// stays as long as it answers; otherwise the least loaded wins, but only by
/// SWITCH_MARGIN, so two near-equal servers do not trade places every poll.
///
/// A fresh pick is weighted-random, not "the least loaded": every client sees
/// the same pool, and all of them moving to the one idle server at once would
/// load it the moment they arrive. Weight (101 - load)^2 still favours the idle
/// ones strongly. `r` is uniform in [0, 1), passed in so tests can fix it.
fn choose(cands: &[Cand], current: Option<usize>, active: usize, r: f64) -> Option<usize> {
    if cands.is_empty() {
        return None;
    }
    let cur = current.filter(|&c| c < cands.len() && cands[c].ok);
    if let Some(c) = cur {
        if active > 0 {
            return Some(c);
        }
        let best = (0..cands.len())
            .filter(|&i| cands[i].ok)
            .map(|i| load(cands[i]))
            .min()
            .unwrap_or(0);
        if load(cands[c]) <= best + SWITCH_MARGIN {
            return Some(c);
        }
    }
    // Re-pick among the answering servers, the current one excluded when it is
    // being left for its load.
    let pool: Vec<usize> = (0..cands.len())
        .filter(|&i| cands[i].ok && Some(i) != cur)
        .collect();
    if pool.is_empty() {
        // Nothing answered: keep trying where we were, else the bootstrap.
        return Some(cur.or(current.filter(|&c| c < cands.len())).unwrap_or(0));
    }
    let weight = |i: usize| ((101 - load(cands[i]).clamp(0, 100)) as f64).powi(2);
    let total: f64 = pool.iter().map(|&i| weight(i)).sum();
    let mut at = r.clamp(0.0, 0.999_999) * total;
    for &i in &pool {
        at -= weight(i);
        if at < 0.0 {
            return Some(i);
        }
    }
    pool.last().copied()
}

/// Uniform in [0, 1) from the system RNG; 0.5 if it fails (then the pick is
/// still a valid one, just not spread).
fn unit_random() -> f64 {
    let mut b = [0u8; 8];
    match default_provider().secure_random.fill(&mut b) {
        Ok(()) => (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64,
        Err(_) => 0.5,
    }
}

/// A `host:port` a server listed; anything else is dropped.
fn valid_server_name(s: &str) -> Option<(String, u16)> {
    let s = s.trim().to_ascii_lowercase();
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|&p| p != 0)?;
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-']);
    host_ok.then(|| (host.to_string(), port))
}

/// Only the key's bootstrap is authoritative until a live status is verified.
fn initial_servers(key: &GroupKey) -> Vec<Server> {
    vec![Server::new(key.host.to_ascii_lowercase(), key.port)]
}

/// Drops every server the live pool does not list, the key's own bootstrap
/// excepted. Empty `listed` drops nothing: a status with no names says nothing.
fn prune_unlisted(
    servers: &mut Vec<Server>,
    bootstrap: &(String, u16),
    listed: &[(String, u16)],
) -> bool {
    if listed.is_empty() {
        return false;
    }
    let before = servers.len();
    servers.retain(|s| {
        (&s.host, s.port) == (&bootstrap.0, bootstrap.1)
            || listed.iter().any(|(h, p)| *h == s.host && *p == s.port)
    });
    servers.len() != before
}

/// An old request cannot initialize or replace another key's current pool.
fn ensure_pool(key: &GroupKey) {
    let mut state = group_state().lock().unwrap();
    if state.servers.is_empty() && state.parsed.as_ref() == Some(key) {
        state.servers = initial_servers(key);
    }
}

/// The server new tunnels go to: its number (for logs) and its `host:port`
/// (its identity — indices shift when the key and so the pool changes).
fn pick_server(key: &GroupKey) -> Option<(usize, String)> {
    ensure_pool(key);
    let mut state = group_state().lock().unwrap();
    // Another connection may have received a newer settings snapshot. Never
    // send this snapshot's credential to the other snapshot's server pool.
    if state.parsed.as_ref() != Some(key) {
        return None;
    }
    if state.servers.is_empty() {
        return None;
    }
    let cands: Vec<Cand> = state
        .servers
        .iter()
        .map(|s| Cand {
            ok: s.ok && s.tunnel_ok && !s.benched(),
            cpu: s.cpu,
        })
        .collect();
    let pick = choose(
        &cands,
        state.current,
        ACTIVE.load(Ordering::SeqCst),
        unit_random(),
    )
    .unwrap_or(0);
    let name = state.servers[pick].name();
    if state.current != Some(pick) {
        let cpu = state.servers[pick]
            .cpu
            .map_or("?".to_string(), |c| c.to_string());
        let total = state.servers.len();
        state.current = Some(pick);
        drop(state);
        crate::dns_forwarder::log_proxy(&format!(
            "Прокси из группы: сервер #{} из {} (CPU {}%)",
            pick + 1,
            total,
            cpu
        ));
    }
    Some((pick, name))
}

/// How long a server whose exit drew region-400 sits out of the walk.
const REGION_BENCH: Duration = Duration::from_secs(5 * 60);

/// Region-400 came through the group with no answer on it: bench the server new
/// tunnels were going to, so the next one lands on another. Returns whether
/// another server is left to try (with one server there is nothing to switch to).
pub fn bench_current_server() -> bool {
    let mut state = group_state().lock().unwrap();
    let Some(cur) = state.current.filter(|&c| c < state.servers.len()) else {
        return false;
    };
    // One host on two ports is one exit: both entries sit out together.
    let host = state.servers[cur].host.clone();
    let until = Instant::now() + REGION_BENCH;
    for srv in state.servers.iter_mut().filter(|s| s.host == host) {
        srv.benched_until = Some(until);
    }
    state.current = None;
    drop(state);
    crate::dns_forwarder::log_proxy(&format!(
        "Прокси из группы: сервер #{} отдал region-400 — отложен на 5 мин, следующее соединение пойдёт на другой",
        cur + 1
    ));
    group_state()
        .lock()
        .unwrap()
        .servers
        .iter()
        .any(|s| s.ok && s.tunnel_ok && !s.benched())
}

fn set_tunnel_ok(key: &GroupKey, name: &str, ok: bool) {
    let mut state = group_state().lock().unwrap();
    if state.parsed.as_ref() != Some(key) {
        return;
    }
    if let Some(s) = state.servers.iter_mut().find(|s| s.name() == name) {
        s.tunnel_ok = ok;
    }
}

fn server_authorized(key: &GroupKey, server: &str) -> bool {
    let state = group_state().lock().unwrap();
    pool_authorizes(&state, key, server)
}

fn pool_authorizes(state: &GroupState, key: &GroupKey, server: &str) -> bool {
    state.parsed.as_ref() == Some(key) && state.servers.iter().any(|s| s.name() == server)
}

/// A message for the log with every pool host taken out: errors from TLS or
/// the resolver can carry the name, and logs name servers by number only (I46).
fn scrub(msg: &str) -> String {
    let hosts: Vec<String> = group_state()
        .lock()
        .unwrap()
        .servers
        .iter()
        .map(|s| s.host.clone())
        .collect();
    let mut out = msg.to_string();
    for h in hosts {
        if !h.is_empty() {
            out = out.replace(&h, "<сервер>");
        }
    }
    out
}

pub fn get_active_key() -> Option<GroupKey> {
    let mut state = group_state().lock().unwrap();
    let settings_key = settings::group_key();
    receive_key_locked(&mut state, &settings_key)
}

/// Serialize profile capture with pool admission, so an older request cannot
/// later replace the pool selected by a newer settings snapshot.
pub(crate) fn capture_route_profile() -> (settings::Settings, Option<GroupKey>) {
    let mut state = group_state().lock().unwrap();
    let settings = settings::routing_snapshot();
    let key = if settings.group_proxy {
        receive_key_locked(&mut state, &settings.group_key)
    } else {
        None
    };
    (settings, key)
}

fn receive_key_locked(state: &mut GroupState, settings_key: &str) -> Option<GroupKey> {
    if settings_key.is_empty() {
        state.key_string.clear();
        state.parsed = None;
        state.servers.clear();
        state.current = None;
        return None;
    }
    if state.key_string == settings_key {
        return state.parsed.clone();
    }
    let parsed = crate::group_key::parse_key(&settings_key).ok();
    let servers = parsed.as_ref().map(initial_servers).unwrap_or_default();
    state.key_string = settings_key.to_owned();
    state.parsed = parsed;
    state.servers = servers;
    state.current = None;
    state.parsed.clone()
}

fn group_route() -> &'static Route {
    static ROUTE: OnceLock<Route> = OnceLock::new();
    ROUTE.get_or_init(|| {
        Route::new(
            Box::leak("Прокси из группы".into()),
            crate::routes::Kind::Group,
        )
    })
}

pub(crate) fn bound_key_usable(key: Option<&GroupKey>) -> bool {
    let state = group_state().lock().unwrap();
    key.is_some() && state.parsed.as_ref() == key && group_route().usable()
}

pub fn available() -> bool {
    get_active_key().is_some() && group_route().usable()
}

fn agu2_config() -> std::sync::Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<std::sync::Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            obfstr::obfstr! { let alpn = "agu/2"; }
            config.alpn_protocols = vec![alpn.as_bytes().to_vec()];
            std::sync::Arc::new(config)
        })
        .clone()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, &b) in key.iter().enumerate().take(64) {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let inner = Sha256::new()
        .chain_update(&ipad)
        .chain_update(data)
        .finalize();
    let outer = Sha256::new()
        .chain_update(&opad)
        .chain_update(inner)
        .finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&outer);
    res
}

/// The server's name and addresses, resolved at most every 10 minutes.
fn server_addrs(key: &GroupKey, server: &str, force_refresh: bool) -> Result<(String, Vec<SocketAddr>), String> {
    let (host, port) = valid_server_name(server).ok_or("нет сервера")?;
    // (addresses, fresh): a stale answer is kept to fall back on, never dropped.
    let cached = {
        let state = group_state().lock().unwrap();
        if state.parsed.as_ref() != Some(key)
            || !state.servers.iter().any(|s| s.host == host && s.port == port)
        {
            return Err("группа изменилась".to_string());
        }
        state
            .servers
            .iter()
            .find(|s| s.host == host && s.port == port)
            .and_then(|s| s.addrs.as_ref())
            .map(|(a, ts)| {
                (
                    a.clone(),
                    !force_refresh && ts.elapsed() < Duration::from_secs(600),
                )
            })
    };
    if let Some((a, true)) = &cached {
        return Ok((host, a.clone()));
    }
    // Outside the lock: a slow resolver must not stall every other tunnel.
    // The reference resolvers first, asked directly over UDP with a two-second
    // budget: the system resolver on a machine running this tool is the one
    // that is slow or lies, and the first connection to the group waited 16 s
    // for it (measured) while the server itself answered in half a second.
    let mut resolved: Vec<SocketAddr> = crate::resolvers::genuine_a(&host)
        .into_iter()
        .map(|ip| SocketAddr::from((ip, port)))
        .collect();
    if resolved.is_empty() {
        resolved = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map(|it| it.filter(|a| a.is_ipv4()).collect())
            .unwrap_or_default();
    }
    if resolved.is_empty() {
        return match cached {
            Some((a, _)) => Ok((host, a)),
            None => Err("нет IPv4 адресов".to_string()),
        };
    }
    let mut state = group_state().lock().unwrap();
    if state.parsed.as_ref() != Some(key) {
        return Err("группа изменилась".to_string());
    }
    if let Some(s) = state.servers.iter_mut().find(|s| s.host == host && s.port == port) {
        s.addrs = Some((resolved.clone(), Instant::now()));
    } else {
        return Err("сервер больше не входит в группу".to_string());
    }
    Ok((host, resolved))
}

thread_local! {
    /// Milliseconds the last `open_agu2` on this thread spent: name lookup,
    /// TCP connect, and TLS + CONNECT up to the server's `200`. Read by the
    /// probe so its log line says where the time went (numbers only, I46).
    static STAGES: Cell<[u64; 3]> = const { Cell::new([0; 3]) };
}

/// TCP + TLS (ALPN agu/2) to one pool server, within `budget`.
fn open_tls(
    key: &GroupKey,
    server: &str,
    force_refresh: bool,
    budget: Duration,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Result<(ClientConnection, TcpStream), String> {
    let deadline = Instant::now() + budget;
    let t_dns = Instant::now();
    let (host, addrs) = server_addrs(key, server, force_refresh)?;
    let dns_ms = t_dns.elapsed().as_millis() as u64;
    let t_tcp = Instant::now();

    let mut sock = None;
    for addr in addrs {
        if cancelled.is_some_and(|c| c.load(Ordering::Acquire)) { return Err("отменено".to_string()); }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if let Ok(s) = TcpStream::connect_timeout(&addr, remaining) {
            sock = Some(s);
            break;
        }
    }
    let sock = sock.ok_or_else(|| "не удалось подключиться".to_string())?;
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("время вышло".to_string());
    }
    sock.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
    sock.set_write_timeout(Some(left)).map_err(|e| e.to_string())?;
    STAGES.with(|c| c.set([dns_ms, t_tcp.elapsed().as_millis() as u64, 0]));
    let name = ServerName::try_from(host).map_err(|_| "недопустимое имя сервера".to_string())?;
    let tls = ClientConnection::new(agu2_config(), name).map_err(|e| e.to_string())?;
    Ok((tls, sock))
}

fn fresh_nonce() -> Result<String, String> {
    let mut nonce = [0u8; 16];
    default_provider()
        .secure_random
        .fill(&mut nonce)
        .map_err(|_| "генератор случайных чисел отказал")?;
    Ok(hex::encode(nonce))
}

fn open_agu2(
    key: &GroupKey,
    server: &str,
    force_refresh: bool,
    target_host: &str,
) -> Result<(ClientConnection, TcpStream, Vec<u8>), String> {
    open_agu2_with_budget(key, server, force_refresh, target_host, upstream::LIVE_OPEN_BUDGET, None)
}

fn open_agu2_with_budget(
    key: &GroupKey,
    server: &str,
    force_refresh: bool,
    target_host: &str,
    budget: Duration,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Result<(ClientConnection, TcpStream, Vec<u8>), String> {
    let deadline = Instant::now() + budget;
    let (mut tls, mut sock) = open_tls(key, server, force_refresh, budget, cancelled)?;
    if cancelled.is_some_and(|c| c.load(Ordering::Acquire)) || !server_authorized(key, server) {
        return Err("группа изменилась".to_string());
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce_hex = fresh_nonce()?;

    // Signed with this PC's own code, never the one inside the key text.
    let auth_header =
        crate::group_key::auth_header(key, crate::hwid::pc_code(), ts, &nonce_hex, target_host);

    let req = format!(
        "CONNECT {}:443 HTTP/1.1\r\nHost: {}:443\r\nProxy-Authorization: {}\r\n\r\n",
        target_host, target_host, auth_header
    );

    let t_connect = Instant::now();
    let left = deadline.saturating_duration_since(t_connect);
    if left.is_zero() {
        return Err("время вышло".to_string());
    }
    sock.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
    sock.set_write_timeout(Some(left)).map_err(|e| e.to_string())?;
    let mut stream = rustls::Stream::new(&mut tls, &mut sock);
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut acc = Vec::new();
    let mut buf = [0u8; 1024];
    let hdr_end = loop {
        if cancelled.is_some_and(|c| c.load(Ordering::Acquire)) { return Err("отменено".to_string()); }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("время вышло".to_string());
        }
        stream.sock.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        match stream.read(&mut buf) {
            Ok(0) => return Err("сервер группы отказал: соединение закрыто".to_string()),
            Ok(n) => {
                acc.extend_from_slice(&buf[..n]);
                if let Some(pos) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                if acc.len() > 4096 {
                    return Err("сервер группы отказал: ответ слишком велик".to_string());
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        }
    };

    let status = acc
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .unwrap_or_default();

    if !status.contains(" 200") {
        return Err(format!("сервер группы отказал: {}", status));
    }

    STAGES.with(|c| {
        let mut v = c.get();
        v[2] = t_connect.elapsed().as_millis() as u64;
        c.set(v);
    });
    sock.set_read_timeout(None).ok();
    sock.set_write_timeout(None).ok();

    Ok((tls, sock, acc[hdr_end..].to_vec()))
}

const IDLE_PAYLOAD_LIMIT: Duration = Duration::from_secs(60);
const AWAITING_LIMIT: Duration = Duration::from_secs(10 * 60);

fn idle_expired(idle: Duration, awaiting: bool) -> bool {
    idle > if awaiting {
        AWAITING_LIMIT
    } else {
        IDLE_PAYLOAD_LIMIT
    }
}

enum End {
    Client,
    Idle,
    Upstream,
    NoAnswer,
}

#[derive(Clone, Copy)]
pub(crate) enum GroupEof {
    NativeCompatible,
    WslSymmetricFin,
}

pub(crate) struct GroupTransferOutcome {
    pub upload_eof: bool,
    pub download_eof: bool,
    pub error: Option<std::io::Error>,
    pub cancelled: bool,
    pub client_shutdown: std::io::Result<()>,
    pub upstream_shutdown: std::io::Result<()>,
}

/// `closed` is set when the server ended the stream cleanly (close_notify): rustls
/// then stops asking to read, so the socket never reports EOF by itself.
fn drain_tls_reader(conn: &mut ClientConnection, pending: &mut Vec<u8>, closed: &mut bool) -> std::io::Result<bool> {
    let mut moved = false;
    let mut buf = [0u8; 16 * 1024];
    loop {
        match conn.reader().read(&mut buf) {
            Ok(0) => {
                *closed = true;
                break;
            }
            Ok(n) => {
                pending.extend_from_slice(&buf[..n]);
                moved = true;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(moved)
}

fn tls_pump(
    mut client: TcpStream,
    mut conn: ClientConnection,
    mut upstream_sock: TcpStream,
    leftover: Vec<u8>,
    prefetched: Vec<u8>,
    mode: GroupEof,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> GroupTransferOutcome {
    let setup = client.set_nonblocking(true).and_then(|_| upstream_sock.set_nonblocking(true));
    if let Err(error) = setup {
        return GroupTransferOutcome {
            upload_eof: false, download_eof: false, error: Some(error), cancelled: false,
            client_shutdown: client.shutdown(std::net::Shutdown::Both),
            upstream_shutdown: upstream_sock.shutdown(std::net::Shutdown::Both),
        };
    }
    let activity = crate::routes::serving_activity();
    let mut buf = [0u8; 16 * 1024];
    let mut pending: Vec<u8> = leftover;
    let mut idle = Duration::ZERO;
    let mut backoff = crate::proxy::PUMP_MIN_SLEEP;
    let mut client_eof = false;
    let mut upstream_eof = false;
    let mut closed = false;
    let mut _delivered: u64 = 0;
    let mut _sent: u64 = 0;
    let mut awaiting = false;
    let mut _why = End::Client;
    let mut failure = None;
    let mut was_cancelled = false;
    let mut client_write_closed = false;
    let mut upload_clean_eof = false;
    let mut download_clean_eof = false;
    if let Err(error) = conn.writer().write_all(&prefetched) {
        failure = Some(error);
        client_eof = true;
        upstream_eof = true;
    } else if !prefetched.is_empty() {
        if let Some(a) = &activity { a.to_upstream(prefetched.len() as u64); }
        awaiting = true;
    }

    while !(client_eof && upstream_eof && pending.is_empty() && !conn.wants_write()) {
        if failure.is_some() && matches!(mode, GroupEof::WslSymmetricFin) {
            break;
        }
        if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            was_cancelled = true;
            break;
        }
        let mut moved = false;
        let mut payload = false;

        if !upstream_eof && conn.wants_read() {
            match conn.read_tls(&mut upstream_sock) {
                Ok(0) => {
                    let _ = conn.process_new_packets();
                    let m = match drain_tls_reader(&mut conn, &mut pending, &mut closed) {
                        Ok(moved) => moved,
                        Err(error) => {
                            if matches!(mode, GroupEof::WslSymmetricFin) { failure.get_or_insert(error); }
                            false
                        }
                    };
                    moved |= m;
                    if m {
                        payload = true;
                    }
                    upstream_eof = true;
                    download_clean_eof = closed;
                    if failure.is_none() && !closed && matches!(mode, GroupEof::WslSymmetricFin) {
                        failure = Some(std::io::Error::new(ErrorKind::UnexpectedEof, "group TLS ended without close notification"));
                    }
                    _why = End::Upstream;
                }
                Ok(_) => match conn.process_new_packets() {
                    Ok(_) => moved = true,
                    Err(error) => {
                        failure.get_or_insert(std::io::Error::new(ErrorKind::InvalidData, error));
                        let _ = drain_tls_reader(&mut conn, &mut pending, &mut closed);
                        client_eof = true;
                        upstream_eof = true;
                        _why = End::Upstream;
                    }
                },
                Err(e) if crate::proxy::would_block(&e) => {}
                Err(error) => {
                    failure.get_or_insert(error);
                    let _ = drain_tls_reader(&mut conn, &mut pending, &mut closed);
                    client_eof = true;
                    upstream_eof = true;
                    _why = End::Upstream;
                }
            }
        }

        // Drain reader unconditionally if there are decrypted packets waiting
        if pending.is_empty() {
            let m = match drain_tls_reader(&mut conn, &mut pending, &mut closed) {
                Ok(moved) => moved,
                Err(error) => {
                    if matches!(mode, GroupEof::WslSymmetricFin) { failure.get_or_insert(error); }
                    false
                }
            };
            if m {
                moved = true;
                payload = true;
                awaiting = false;
            }
            if closed && !upstream_eof {
                upstream_eof = true;
                download_clean_eof = true;
                _why = End::Upstream;
            }
        }

        while !pending.is_empty() {
            match client.write(&pending) {
                Ok(0) => {
                    failure.get_or_insert(std::io::ErrorKind::WriteZero.into());
                    client_eof = true;
                    upstream_eof = true;
                    pending.clear();
                    _why = End::Client;
                }
                Ok(n) => {
                    pending.drain(..n);
                    _delivered += n as u64;
                    if let Some(a) = &activity {
                        a.to_client(n as u64);
                    }
                    moved = true;
                    payload = true;
                }
                Err(e) if crate::proxy::would_block(&e) => break,
                Err(error) => {
                    failure.get_or_insert(error);
                    client_eof = true;
                    upstream_eof = true;
                    pending.clear();
                    _why = End::Client;
                }
            }
        }
        if !client_eof {
            match client.read(&mut buf) {
                Ok(0) => {
                    conn.send_close_notify();
                    client_eof = true;
                    upload_clean_eof = true;
                    _why = End::Client;
                }
                Ok(n) => {
                    if let Err(error) = conn.writer().write_all(&buf[..n]) {
                        failure.get_or_insert(error);
                        client_eof = true;
                        upstream_eof = true;
                        _why = End::Upstream;
                    } else {
                        _sent += n as u64;
                        if let Some(a) = &activity {
                            a.to_upstream(n as u64);
                        }
                        moved = true;
                        payload = true;
                        awaiting = true;
                    }
                }
                Err(e) if crate::proxy::would_block(&e) => {}
                Err(error) => {
                    failure.get_or_insert(error);
                    conn.send_close_notify();
                    client_eof = true;
                    _why = End::Client;
                }
            }
        }
        while conn.wants_write() {
            match conn.write_tls(&mut upstream_sock) {
                Ok(0) => {
                    failure.get_or_insert(std::io::ErrorKind::WriteZero.into());
                    client_eof = true;
                    upstream_eof = true;
                    break;
                }
                Ok(_) => moved = true,
                Err(e) if crate::proxy::would_block(&e) => break,
                Err(error) => {
                    failure.get_or_insert(error);
                    client_eof = true;
                    upstream_eof = true;
                    _why = End::Upstream;
                    break;
                }
            }
        }

        if upstream_eof {
            // Plaintext rustls already decrypted is still owed to the client:
            // take all of it before calling the upstream finished.
            match drain_tls_reader(&mut conn, &mut pending, &mut closed) {
                Ok(true) => moved = true,
                Ok(false) => {},
                Err(error) => if matches!(mode, GroupEof::WslSymmetricFin) { failure.get_or_insert(error); },
            }
            if pending.is_empty() {
                if matches!(mode, GroupEof::WslSymmetricFin) && !client_write_closed {
                    match client.shutdown(std::net::Shutdown::Write) {
                        Ok(()) => client_write_closed = true,
                        Err(error) => { failure.get_or_insert(error); break; }
                    }
                }
                if matches!(mode, GroupEof::NativeCompatible) && !conn.wants_write() {
                    break;
                }
            }
        }

        if payload {
            idle = Duration::ZERO;
        }
        if moved {
            backoff = crate::proxy::PUMP_MIN_SLEEP;
            continue;
        }
        thread::sleep(backoff);
        idle += backoff;
        backoff = (backoff * 2).min(crate::proxy::PUMP_MAX_SLEEP);
        if idle_expired(idle, awaiting) {
            _why = if awaiting { End::NoAnswer } else { End::Idle };
            failure.get_or_insert(std::io::Error::new(ErrorKind::TimedOut, "group tunnel idle"));
            break;
        }
    }

    conn.send_close_notify();
    let deadline = Instant::now() + crate::proxy::PUMP_MAX_SLEEP;
    while conn.wants_write() && Instant::now() < deadline {
        match conn.write_tls(&mut upstream_sock) {
            Ok(0) => {
                if failure.is_none() { failure = Some(std::io::ErrorKind::WriteZero.into()); }
                break;
            }
            Ok(_) => {},
            Err(error) => {
                if failure.is_none() { failure = Some(error); }
                break;
            }
        }
    }
    if conn.wants_write() && failure.is_none() {
        failure = Some(std::io::Error::new(ErrorKind::TimedOut, "group TLS shutdown incomplete"));
    }
    if let Err(error) = upstream_sock.flush() {
        if failure.is_none() { failure = Some(error); }
    }
    let upstream_shutdown = upstream_sock.shutdown(std::net::Shutdown::Both);

    let client_shutdown = if client_write_closed { Ok(()) } else { client.shutdown(std::net::Shutdown::Write) };
    let deadline = Instant::now() + crate::proxy::PUMP_MAX_SLEEP;
    while Instant::now() < deadline {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if crate::proxy::would_block(&e) => thread::sleep(crate::proxy::PUMP_MIN_SLEEP),
            Err(_) => break,
        }
    }
    GroupTransferOutcome { upload_eof: upload_clean_eof, download_eof: download_clean_eof, error: failure, cancelled: was_cancelled, client_shutdown, upstream_shutdown }
}

pub(crate) struct OpenedGroup {
    tls: ClientConnection,
    socket: TcpStream,
    leftover: Vec<u8>,
    _active: ActiveGuard,
    server_index: usize,
    route: &'static Route,
}

impl OpenedGroup {
    pub(crate) fn prepare_transfer(&self) -> std::io::Result<()> {
        self.socket.set_nonblocking(false)?;
        self.socket.set_read_timeout(None)?;
        self.socket.set_write_timeout(None)
    }

    pub(crate) fn shutdown(&self) -> std::io::Result<()> {
        self.socket.shutdown(std::net::Shutdown::Both)
    }
    pub(crate) fn note_committed(&self, host: &str) {
        crate::routes::note_used(crate::routes::Kind::Group);
        crate::routes::attach_upstream(&self.socket);
        crate::dns_forwarder::log_proxy(&format!(
            "{} #{} -> {}", self.route.label(), self.server_index + 1, host
        ));
    }

    pub(crate) fn transfer(self, client: TcpStream) {
        let _ = tls_pump(client, self.tls, self.socket, self.leftover, Vec::new(), GroupEof::NativeCompatible, None);
    }

    pub(crate) fn transfer_wsl(self, client: TcpStream, prefetched: Vec<u8>, cancelled: &std::sync::atomic::AtomicBool) -> GroupTransferOutcome {
        tls_pump(client, self.tls, self.socket, self.leftover, prefetched, GroupEof::WslSymmetricFin, Some(cancelled))
    }
}

enum GroupAttempt<T> { Opened(T), Retry, Stop }

fn walk_group_attempts<T>(deadline: Instant, cancelled: &std::sync::atomic::AtomicBool, mut attempt: impl FnMut(Duration) -> GroupAttempt<T>) -> Option<T> {
    for _ in 0..2 {
        if cancelled.load(Ordering::Acquire) { return None; }
        let budget = deadline.checked_duration_since(Instant::now())?.min(upstream::LIVE_OPEN_BUDGET);
        if budget.is_zero() { return None; }
        let result = attempt(budget);
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline { return None; }
        match result {
            GroupAttempt::Opened(opened) => return Some(opened),
            GroupAttempt::Retry => {},
            GroupAttempt::Stop => return None,
        }
    }
    None
}

pub(crate) fn open_group(target: &crate::proxy::GateTarget443<'_>, key: &GroupKey, deadline: Instant, cancelled: &std::sync::atomic::AtomicBool) -> Option<OpenedGroup> {
    if !group_route().usable() {
        return None;
    }

    let host = target.host();
    {
        let route = group_route();
        // The chosen server, then — if it fails — the next choice once.
        let opened = walk_group_attempts(deadline, cancelled, |budget| {
            let Some((idx, server)) = pick_server(key) else { return GroupAttempt::Stop; };
            let attempt = open_agu2_with_budget(key, &server, false, host, budget, Some(cancelled));
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline { return GroupAttempt::Stop; }
            match attempt {
                Ok((tls, sock, leftover)) => {
                    if !server_authorized(key, &server) {
                        return GroupAttempt::Stop;
                    }
                    GroupAttempt::Opened(OpenedGroup {
                        tls,
                        socket: sock,
                        leftover,
                        _active: ActiveGuard::new(),
                        server_index: idx,
                        route,
                    })
                }
                Err(why) => {
                    crate::dns_forwarder::log_proxy(&format!(
                        "{} #{}: {}",
                        route.label(),
                        idx + 1,
                        scrub(&why)
                    ));
                    let pool = {
                        let state = group_state().lock().unwrap();
                        if state.parsed.as_ref() != Some(key) {
                            return GroupAttempt::Stop;
                        }
                        state.servers.len()
                    };
                    set_tunnel_ok(key, &server, false);
                    if pool < 2 { GroupAttempt::Stop } else { GroupAttempt::Retry }
                }
            }
        });
        if opened.is_some() { return opened; }
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline { return None; }
        let state = group_state().lock().unwrap();
        if state.parsed.as_ref() == Some(key) {
            route.health.note(false);
        }
    }
    None
}

pub fn tunnel(mut client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    let Some(target) = crate::proxy::GateTarget443::new(host, port) else {
        return Err(client);
    };
    let Some(key) = get_active_key() else {
        return Err(client);
    };
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let Some(opened) = open_group(&target, &key, Instant::now() + 2 * upstream::LIVE_OPEN_BUDGET, &cancelled) else {
        return Err(client);
    };
    if client.write_all(crate::proxy::RESP_ESTABLISHED).is_err() {
        return Ok(());
    }
    opened.note_committed(host);
    opened.transfer(client);
    Ok(())
}

pub fn probe_health() {
    let key = match get_active_key() {
        Some(k) => k,
        None => return,
    };

    poll_pool(&key);
    let started = Instant::now();
    let result = probe_once(&key, true);
    let state = group_state().lock().unwrap();
    record_if_current(&state, &key, || {
        group_route().record_probe(result, started.elapsed());
    });
}

fn record_if_current(state: &GroupState, key: &GroupKey, record: impl FnOnce()) {
    if state.parsed.as_ref() == Some(key) { record(); }
}

/// What a server says about itself, signed with this user's key.
struct Status {
    cpu: i64,
    servers: Vec<String>,
    /// The whole pool's load as that server last saw it (`host:port`, CPU;
    /// -1 = unknown). Empty from a server that predates the pool summary.
    pool: Vec<(String, i64)>,
}

fn fetch_status(key: &GroupKey, server: &str) -> Result<Status, String> {
    obfstr::obfstr! {
        let status_host = "agu2.status";
        let path = "/agu2/status";
        let label = "AGU2-STATUS";
    }
    let budget = upstream::PROBE_BUDGET;
    let deadline = Instant::now() + budget;
    let (mut tls, mut sock) = open_tls(key, server, false, budget, None)?;
    if !server_authorized(key, server) {
        return Err("группа изменилась".to_string());
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce_hex = fresh_nonce()?;
    let auth =
        crate::group_key::auth_header(key, crate::hwid::pc_code(), ts, &nonce_hex, status_host);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {}\r\n\r\n",
        path, auth
    );
    rustls::Stream::new(&mut tls, &mut sock)
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // One budget for the whole answer: a server trickling a byte at a time
        // must not hold the poll for a read timeout per byte.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("нет ответа вовремя".to_string());
        }
        sock.set_read_timeout(Some(left)).ok();
        match rustls::Stream::new(&mut tls, &mut sock).read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 64 * 1024 {
                    return Err("ответ слишком велик".to_string());
                }
            }
            // A peer that closes without close_notify still sent its answer.
            Err(_) if !raw.is_empty() => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("нет ответа")?;
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let body = &raw[end + 4..];
    if !head.lines().next().unwrap_or("").contains(" 200") {
        return Err("сервер отказал".to_string());
    }
    let sig = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("x-agu2-sig"))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    let mut signed = format!("{}\n{}\n", label, nonce_hex).into_bytes();
    signed.extend_from_slice(body);
    let want = hex::encode(hmac_sha256(&key.user_key, &signed));
    if !crate::group_key::ct_eq(want.as_bytes(), sig.as_bytes()) {
        return Err("подпись не сходится".to_string());
    }
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    Ok(Status {
        cpu: v["cpu"].as_i64().unwrap_or(-1),
        servers: v["servers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect(),
        pool: v["pool"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| {
                Some((
                    e["s"].as_str()?.to_string(),
                    e["cpu"].as_i64().unwrap_or(-1),
                ))
            })
            .collect(),
    })
}

/// Asks every pool server how loaded it is, in parallel, and learns the
/// servers they list. Then re-chooses (sticky while tunnels are open).
fn poll_pool(key: &GroupKey) {
    ensure_pool(key);
    // Any one server reports the whole pool's load (servers pull it from each
    // other), so the current server is asked first and the next one only when
    // it does not answer — one request per poll, not one per server.
    let names: Vec<String> = {
        let state = group_state().lock().unwrap();
        if state.parsed.as_ref() != Some(key) {
            return;
        }
        let mut order: Vec<usize> = (0..state.servers.len()).collect();
        if let Some(c) = state.current.filter(|&c| c < order.len()) {
            order.retain(|&i| i != c);
            order.insert(0, c);
        }
        order.iter().map(|&i| state.servers[i].name()).collect()
    };
    let mut asked = Vec::new();
    let mut results = Vec::new();
    for name in names.into_iter().take(STATUS_TRIES) {
        let r = fetch_status(key, &name);
        let done = r.is_ok();
        asked.push(name);
        results.push(r);
        if done {
            break;
        }
    }
    let names = asked;

    let mut state = group_state().lock().unwrap();
    let Some((learned, failed)) = apply_status_results(&mut state, key, &names, results) else { return; };
    let total = state.servers.len();
    // Servers that answer their status but failed a tunnel get one probe to
    // earn `tunnel_ok` back; nothing else sets it.
    let retry: Vec<String> = state
        .servers
        .iter()
        .filter(|s| s.ok && !s.tunnel_ok)
        .map(Server::name)
        .collect();
    drop(state);

    for (n, why) in failed {
        crate::dns_forwarder::log_proxy(&format!(
            "Прокси из группы #{}: статус: {}",
            n,
            scrub(&why)
        ));
    }
    if learned {
        crate::dns_forwarder::log_proxy(&format!("Прокси из группы: серверов в пуле {}", total));
    }
    for name in retry {
        let ok = probe_via(key, &name, false).is_ok();
        set_tunnel_ok(key, &name, ok);
    }
    let _ = pick_server(key);
}

/// The caller holds the pool lock; a late result cannot mutate a newer key.
fn apply_status_results(
    state: &mut GroupState,
    key: &GroupKey,
    names: &[String],
    results: Vec<Result<Status, String>>,
) -> Option<(bool, Vec<(usize, String)>)> {
    if state.parsed.as_ref() != Some(key) { return None; }
    let mut learned = false;
    let mut failed = Vec::new();
    for (name, r) in names.iter().zip(results) {
        let Some(i) = state.servers.iter().position(|s| &s.name() == name) else {
            continue;
        };
        match r {
            Ok(st) => {
                state.servers[i].ok = true;
                state.servers[i].cpu = Some(st.cpu);
                for (name, cpu) in &st.pool {
                    if let Some((h, p)) = valid_server_name(name) {
                        if let Some(s) = state
                            .servers
                            .iter_mut()
                            .find(|s| s.host == h && s.port == p)
                        {
                            s.cpu = (*cpu >= 0).then_some(*cpu);
                        }
                    }
                }
                // What the live servers list is the pool; a name an earlier run
                // saved that they no longer list is a server taken down.
                let listed: Vec<(String, u16)> = st
                    .servers
                    .iter()
                    .chain(st.pool.iter().map(|(n, _)| n))
                    .filter_map(|n| valid_server_name(n))
                    .collect();
                let bootstrap = (key.host.to_ascii_lowercase(), key.port);
                if prune_unlisted(&mut state.servers, &bootstrap, &listed) {
                    state.current = None;
                    learned = true;
                }
                for name in st.servers.iter().chain(st.pool.iter().map(|(n, _)| n)) {
                    if let Some((h, p)) = valid_server_name(name) {
                        if state.servers.len() < MAX_SERVERS
                            && !state.servers.iter().any(|s| s.host == h && s.port == p)
                        {
                            state.servers.push(Server::new(h, p));
                            learned = true;
                        }
                    }
                }
            }
            Err(why) => {
                state.servers[i].ok = false;
                failed.push((i + 1, why));
            }
        }
    }
    Some((learned, failed))
}

/// One request to Google through the group server: proof the tunnel carries
/// TLS end to end, not just that the CONNECT was accepted.
fn probe_once(key: &GroupKey, force_refresh: bool) -> Result<(), String> {
    let (_, server) = pick_server(key).ok_or("группа изменилась")?;
    let r = probe_via(key, &server, force_refresh);
    set_tunnel_ok(key, &server, r.is_ok());
    r.map_err(|e| scrub(&e))
}

fn probe_via(key: &GroupKey, server: &str, force_refresh: bool) -> Result<(), String> {
    {
        let target = "daily-cloudcode-pa.googleapis.com";
        let budget = upstream::PROBE_BUDGET;

        let mut tls = ClientConnection::new(
            crate::proxy::probe_config(),
            ServerName::try_from(target).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;

        let req = format!(
            "GET /v1internal:probe HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            target
        );
        let mut buf = [0u8; 64];

        let t_all = Instant::now();
        let (outer_tls, outer_sock, leftover) = open_agu2(key, server, force_refresh, target)?;
        let outer_ms = t_all.elapsed().as_millis() as u64;
        let [dns_ms, tcp_ms, connect_ms] = STAGES.with(|c| c.get());
        outer_sock.set_read_timeout(Some(budget)).ok();
        outer_sock.set_write_timeout(Some(budget)).ok();

        let mut stream_owned = rustls::StreamOwned::new(outer_tls, outer_sock);
        let mut stream = rustls::Stream::new(&mut tls, &mut stream_owned);

        if !leftover.is_empty() {
            return Err("неожиданные данные после CONNECT".to_string());
        }

        stream
            .write_all(req.as_bytes())
            .map_err(|e| e.to_string())?;
        let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
        if n > 0 && buf.starts_with(b"HTTP/") {
            let total = t_all.elapsed().as_millis() as u64;
            // The system resolver timed apart from the probe, for comparison.
            let t_sys = Instant::now();
            let _ = server.to_socket_addrs();
            crate::dns_forwarder::log_proxy(&format!(
                "замер группы: всего {} мс = имя {} + TCP {} + TLS/CONNECT {} + внутренний TLS и ответ {}; системный DNS для сервера {} мс",
                total,
                dns_ms,
                tcp_ms,
                connect_ms,
                total.saturating_sub(outer_ms),
                t_sys.elapsed().as_millis()
            ));
            Ok(())
        } else {
            Err("ответ не похож на HTTP".to_string())
        }
    }
}

#[cfg(test)]
#[path = "group/tls_test_fixture.rs"]
mod tls_test_fixture;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_cancellation_between_attempts_prevents_second_open() {
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let attempts = std::cell::Cell::new(0);
        let result: Option<()> = walk_group_attempts(Instant::now() + Duration::from_secs(2), &cancelled, |_| {
            attempts.set(attempts.get() + 1);
            cancelled.store(true, Ordering::Release);
            GroupAttempt::Retry
        });
        assert!(result.is_none());
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn group_late_open_is_dropped_on_cancellation() {
        struct Owned<'a>(&'a std::cell::Cell<usize>);
        impl Drop for Owned<'_> { fn drop(&mut self) { self.0.set(self.0.get() + 1); } }
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let dropped = std::cell::Cell::new(0);
        let result = walk_group_attempts(Instant::now() + Duration::from_secs(2), &cancelled, |_| {
            cancelled.store(true, Ordering::Release);
            GroupAttempt::Opened(Owned(&dropped))
        });
        assert!(result.is_none());
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    fn late_status_from_old_full_key_cannot_mutate_current_pool() {
        let old = GroupKey { host: "bootstrap.example".into(), port: 443, tg: 7,
            code: "synthetic".into(), issued: 9, user_key: [1; 32] };
        let mut current = old.clone();
        current.user_key[0] = 2;
        let mut state = GroupState { key_string: String::new(), parsed: Some(current.clone()),
            servers: initial_servers(&current), current: None };
        let names = vec!["bootstrap.example:443".to_string()];
        let status = || Status { cpu: 42, servers: vec!["member.example:443".into()], pool: Vec::new() };
        assert!(apply_status_results(&mut state, &old, &names, vec![Ok(status())]).is_none());
        assert_eq!(state.servers.len(), 1);
        assert!(state.servers[0].cpu.is_none());
        let recorded = std::cell::Cell::new(0);
        record_if_current(&state, &old, || recorded.set(recorded.get() + 1));
        assert_eq!(recorded.get(), 0);
        record_if_current(&state, &current, || recorded.set(recorded.get() + 1));
        assert_eq!(recorded.get(), 1);
        assert!(apply_status_results(&mut state, &current, &names, vec![Ok(status())]).is_some());
        assert_eq!(state.servers.len(), 2);
        assert_eq!(state.servers[0].cpu, Some(42));
    }

    struct TestGroupWorker {
        handle: Option<thread::JoinHandle<GroupTransferOutcome>>,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl TestGroupWorker {
        fn join(mut self) -> thread::Result<GroupTransferOutcome> {
            self.handle.take().unwrap().join()
        }
    }

    impl Drop for TestGroupWorker {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                self.cancelled.store(true, Ordering::Release);
                let _ = handle.join();
            }
        }
    }

    struct TestServerWorker(Option<thread::JoinHandle<std::io::Result<Vec<u8>>>>);
    impl TestServerWorker {
        fn join(mut self) -> thread::Result<std::io::Result<Vec<u8>>> {
            self.0.take().unwrap().join()
        }
    }
    impl Drop for TestServerWorker {
        fn drop(&mut self) {
            if let Some(handle) = self.0.take() { let _ = handle.join(); }
        }
    }

    fn tls_test_pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (b, _) = listener.accept().unwrap();
        for socket in [&a, &b] {
            socket.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(4))).unwrap();
        }
        (a, b)
    }

    fn tls_test_configs() -> (rustls::ClientConfig, rustls::ServerConfig) {
        use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        let cert = CertificateDer::from(hex::decode(tls_test_fixture::CERT_DER_HEX).unwrap());
        let key = PrivatePkcs8KeyDer::from(hex::decode(tls_test_fixture::KEY_DER_HEX).unwrap());
        let server = rustls::ServerConfig::builder().with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        (client, server)
    }

    #[test]
    fn group_tls_download_fin_preserves_late_upload_and_both_prefixes() {
        use rustls::pki_types::ServerName;
        use std::net::Shutdown;
        use std::sync::{Arc, atomic::AtomicBool};

        let (client_config, server_config) = tls_test_configs();
        let mut connection = ClientConnection::new(Arc::new(client_config), ServerName::try_from("localhost").unwrap()).unwrap();
        let (mut peer, client) = tls_test_pair();
        let (mut upstream, server) = tls_test_pair();
        let cancelled = Arc::new(AtomicBool::new(false));
        let server_worker = TestServerWorker(Some(thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let connection = rustls::ServerConnection::new(Arc::new(server_config)).map_err(std::io::Error::other)?;
            let mut stream = rustls::StreamOwned::new(connection, server);
            stream.write_all(b"body")?;
            stream.conn.send_close_notify();
            stream.flush()?;
            let mut upload = Vec::new();
            stream.read_to_end(&mut upload)?;
            Ok(upload)
        })));
        let handshake = (|| -> std::io::Result<()> {
            while connection.is_handshaking() { connection.complete_io(&mut upstream)?; }
            Ok(())
        })();
        if let Err(error) = handshake {
            let _ = upstream.shutdown(Shutdown::Both);
            let _ = server_worker.join();
            panic!("client TLS handshake failed: {error}");
        }
        assert!(!connection.is_handshaking());
        let flag = Arc::clone(&cancelled);
        let worker = TestGroupWorker {
            handle: Some(thread::spawn(move || tls_pump(client, connection, upstream, b"prefix".to_vec(), b"first".to_vec(), GroupEof::WslSymmetricFin, Some(&flag)))),
            cancelled: Arc::clone(&cancelled),
        };
        let mut downloaded = Vec::new();
        let download_result = peer.read_to_end(&mut downloaded);
        let late_result = peer.write_all(b"late");
        let _ = peer.shutdown(Shutdown::Write);
        let server_result = server_worker.join();
        if download_result.is_err() || late_result.is_err() || !matches!(&server_result, Ok(Ok(_))) {
            cancelled.store(true, Ordering::Release);
            let _ = peer.shutdown(Shutdown::Both);
        }
        let outcome = worker.join().unwrap();
        download_result.unwrap();
        late_result.unwrap();
        assert_eq!(downloaded, b"prefixbody", "upload_eof={} download_eof={} error={:?} cancelled={} client_shutdown={:?} upstream_shutdown={:?} server={:?}", outcome.upload_eof, outcome.download_eof, outcome.error, outcome.cancelled, outcome.client_shutdown, outcome.upstream_shutdown, server_result);
        assert_eq!(server_result.unwrap().unwrap(), b"firstlate");
        assert!(outcome.upload_eof && outcome.download_eof && outcome.error.is_none() && !outcome.cancelled);
        assert!(outcome.client_shutdown.is_ok() && outcome.upstream_shutdown.is_ok());
    }

    #[test]
    fn group_tls_upload_fin_keeps_download_open() {
        use rustls::pki_types::ServerName;
        use std::net::Shutdown;
        use std::sync::{Arc, atomic::AtomicBool};

        let (client_config, server_config) = tls_test_configs();
        let mut connection = ClientConnection::new(Arc::new(client_config), ServerName::try_from("localhost").unwrap()).unwrap();
        let (mut peer, client) = tls_test_pair();
        let (mut upstream, server) = tls_test_pair();
        let cancelled = Arc::new(AtomicBool::new(false));
        let server_worker = TestServerWorker(Some(thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let connection = rustls::ServerConnection::new(Arc::new(server_config)).map_err(std::io::Error::other)?;
            let mut stream = rustls::StreamOwned::new(connection, server);
            let mut upload = Vec::new();
            stream.read_to_end(&mut upload)?;
            stream.write_all(b"body")?;
            stream.conn.send_close_notify();
            stream.flush()?;
            Ok(upload)
        })));
        let handshake = (|| -> std::io::Result<()> {
            while connection.is_handshaking() { connection.complete_io(&mut upstream)?; }
            Ok(())
        })();
        if let Err(error) = handshake {
            let _ = upstream.shutdown(Shutdown::Both);
            let _ = server_worker.join();
            panic!("client TLS handshake failed: {error}");
        }
        assert!(!connection.is_handshaking());
        let flag = Arc::clone(&cancelled);
        let worker = TestGroupWorker {
            handle: Some(thread::spawn(move || tls_pump(client, connection, upstream, b"prefix".to_vec(), b"first".to_vec(), GroupEof::WslSymmetricFin, Some(&flag)))),
            cancelled: Arc::clone(&cancelled),
        };
        let sent = peer.write_all(b"late").and_then(|_| peer.shutdown(Shutdown::Write));
        let mut downloaded = Vec::new();
        let download_result = peer.read_to_end(&mut downloaded);
        let server_result = server_worker.join();
        if sent.is_err() || download_result.is_err() || !matches!(&server_result, Ok(Ok(_))) {
            cancelled.store(true, Ordering::Release);
            let _ = peer.shutdown(Shutdown::Both);
        }
        let outcome = worker.join().unwrap();
        sent.unwrap();
        download_result.unwrap();
        assert_eq!(downloaded, b"prefixbody", "upload_eof={} download_eof={} error={:?} cancelled={} client_shutdown={:?} upstream_shutdown={:?} server={:?}", outcome.upload_eof, outcome.download_eof, outcome.error, outcome.cancelled, outcome.client_shutdown, outcome.upstream_shutdown, server_result);
        assert_eq!(server_result.unwrap().unwrap(), b"firstlate");
        assert!(outcome.upload_eof && outcome.download_eof && outcome.error.is_none() && !outcome.cancelled);
        assert!(outcome.client_shutdown.is_ok() && outcome.upstream_shutdown.is_ok());
    }

    #[test]
    fn pool_authority_binds_full_key_and_verified_member() {
        let key = GroupKey {
            host: "bootstrap.example".into(), port: 443, tg: 7,
            code: "synthetic".into(), issued: 9, user_key: [1; 32],
        };
        let state = GroupState {
            key_string: String::new(), parsed: Some(key.clone()),
            servers: initial_servers(&key), current: None,
        };
        assert!(pool_authorizes(&state, &key, "bootstrap.example:443"));
        assert!(!pool_authorizes(&state, &key, "other.example:443"));
        let mut changed = key.clone();
        changed.user_key[0] = 2; // Same legacy tg/issued identifier, different key.
        assert!(!pool_authorizes(&state, &changed, "bootstrap.example:443"));
        changed = key.clone();
        changed.host = "other.example".into();
        assert!(!pool_authorizes(&state, &changed, "bootstrap.example:443"));
    }

    #[test]
    fn a_server_the_pool_no_longer_lists_is_dropped() {
        let mut v = vec![
            Server::new("a.example".into(), 443),
            Server::new("b.example".into(), 8443),
            Server::new("c.example".into(), 443),
        ];
        let listed = vec![("a.example".to_string(), 443), ("c.example".to_string(), 443)];
        assert!(prune_unlisted(&mut v, &("a.example".into(), 443), &listed));
        assert_eq!(v.len(), 2);
        assert!(!prune_unlisted(&mut v, &("a.example".into(), 443), &listed));
        assert!(!prune_unlisted(&mut v, &("a.example".into(), 443), &[]));
    }

    #[test]
    fn benched_server_is_skipped_until_the_bench_ends() {
        let mut a = Server::new("a.example".into(), 443);
        assert!(!a.benched());
        a.benched_until = Some(Instant::now() + Duration::from_secs(60));
        assert!(a.benched());
        a.benched_until = Some(Instant::now() - Duration::from_secs(1));
        assert!(!a.benched());
        // A benched current server is not "ok", so a fresh pick leaves it.
        let cands = [
            Cand { ok: false, cpu: Some(0) },
            Cand { ok: true, cpu: Some(90) },
        ];
        assert_eq!(choose(&cands, Some(0), 0, 0.3), Some(1));
    }

    /// Live: this client against a running agate. The key is built from a test
    /// master (no baked secret); the address is seeded so the SNI/cert name and
    /// the dialled address can differ (an SSH-forwarded port).
    ///   AGU2_E2E_MASTER=<64 hex> AGU2_E2E_HOST=<cert name> AGU2_E2E_ADDR=127.0.0.1:18443
    ///   cargo test group::tests::live_tunnel_reaches_google -- --ignored
    #[test]
    #[ignore]
    fn live_tunnel_reaches_google() {
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{} not set", k));
        let master = hex::decode(env("AGU2_E2E_MASTER")).unwrap();
        let addr: SocketAddr = env("AGU2_E2E_ADDR").parse().unwrap();
        let code = crate::hwid::pc_code().to_string();
        let issued = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10;
        let tg = 4242;
        let key = GroupKey {
            host: env("AGU2_E2E_HOST"),
            port: addr.port(),
            tg,
            code: code.clone(),
            issued,
            user_key: hmac_sha256(
                &master,
                format!("AGU2-UK\n{}\n{}\n{}", tg, code, issued).as_bytes(),
            ),
        };
        {
            let mut st = group_state().lock().unwrap();
            let mut a = Server::new(key.host.clone(), key.port);
            a.addrs = Some((vec![addr], Instant::now()));
            st.servers = vec![a];
            st.current = None;
            st.parsed = Some(key.clone());
        }
        probe_once(&key, false).expect("tunnel to Google");

        // Pool: the server's signed status is read and its listed peer learned.
        // AGU2_E2E_ADDR2 is where that peer is reachable from here.
        poll_pool(&key);
        if let Ok(addr2) = std::env::var("AGU2_E2E_ADDR2") {
            let addr2: SocketAddr = addr2.parse().unwrap();
            {
                let mut st = group_state().lock().unwrap();
                assert!(
                    st.servers[0].ok && st.servers[0].cpu.is_some(),
                    "status from #1"
                );
                assert_eq!(st.servers.len(), 2, "peer learned from the status");
                st.servers[1].addrs = Some((vec![addr2], Instant::now()));
            }
            poll_pool(&key);
            let st = group_state().lock().unwrap();
            assert!(
                st.servers[1].ok && st.servers[1].cpu.is_some(),
                "status from #2"
            );
            drop(st);
            // A tunnel through #2 directly.
            let second = group_state().lock().unwrap().servers[1].name();
            open_agu2(&key, &second, false, "daily-cloudcode-pa.googleapis.com")
                .expect("tunnel via #2");
        }

        // A key derived for another PC's code is refused by the server.
        let mut other = key.clone();
        other.user_key = hmac_sha256(
            &master,
            format!("AGU2-UK\n{}\nzzzzzzzz\n{}", tg, issued).as_bytes(),
        );
        let err = probe_once(&other, false).unwrap_err();
        assert!(err.contains("404"), "{}", err);
    }

    fn c(ok: bool, cpu: Option<i64>) -> Cand {
        Cand { ok, cpu }
    }

    #[test]
    fn a_fresh_pick_favours_the_idle_but_spreads() {
        let cands = [c(true, Some(80)), c(true, Some(10)), c(true, Some(40))];
        let mut hits = [0usize; 3];
        for k in 0..1000 {
            hits[choose(&cands, None, 0, k as f64 / 1000.0).unwrap()] += 1;
        }
        assert!(hits[1] > hits[2] && hits[2] > hits[0], "{:?}", hits);
        assert!(
            hits[0] > 0,
            "a busier server still gets some clients: {:?}",
            hits
        );
        assert!(
            hits[1] < 800,
            "not everyone piles onto the idle one: {:?}",
            hits
        );
    }

    #[test]
    fn open_tunnels_keep_the_current_server() {
        let cands = [c(true, Some(95)), c(true, Some(5))];
        assert_eq!(choose(&cands, Some(0), 3, 0.5), Some(0));
        assert_eq!(
            choose(&cands, Some(0), 0, 0.5),
            Some(1),
            "free to move once idle"
        );
    }

    #[test]
    fn a_dead_current_server_is_left_even_with_tunnels_open() {
        let cands = [c(false, Some(5)), c(true, Some(90))];
        assert_eq!(choose(&cands, Some(0), 3, 0.5), Some(1));
    }

    #[test]
    fn a_small_lead_does_not_move_the_route() {
        let cands = [c(true, Some(50)), c(true, Some(35))];
        assert_eq!(choose(&cands, Some(0), 0, 0.5), Some(0));
        let cands = [c(true, Some(50)), c(true, Some(29))];
        assert_eq!(choose(&cands, Some(0), 0, 0.5), Some(1));
    }

    #[test]
    fn unknown_load_counts_as_middling_and_nothing_alive_keeps_trying() {
        let cands = [c(true, None), c(true, Some(60))];
        assert_eq!(choose(&cands, None, 0, 0.0), Some(0));
        let cands = [c(false, None), c(false, None)];
        assert_eq!(choose(&cands, Some(1), 0, 0.5), Some(1));
        assert_eq!(choose(&cands, None, 0, 0.0), Some(0));
        assert_eq!(choose(&[], None, 0, 0.5), None);
    }

    #[test]
    fn only_plain_host_port_names_are_learned() {
        assert_eq!(
            valid_server_name("AG2.Example.com:443"),
            Some(("ag2.example.com".into(), 443))
        );
        for bad in [
            "ag2.example.com",
            "ag2.example.com:0",
            "a b:443",
            "-x.com:443",
            "x.com.:443",
            "x.com:99999",
            ":443",
        ] {
            assert_eq!(valid_server_name(bad), None, "{}", bad);
        }
    }
}
