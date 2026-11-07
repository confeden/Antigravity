//! Group proxy: the owner's dedicated server, whitelisted to the gate hosts.
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

fn pool_file() -> Option<std::path::PathBuf> {
    if cfg!(test) {
        return None; // a test key must never overwrite a real user's saved pool
    }
    let dir = crate::dns_forwarder::log_dir();
    (!dir.as_os_str().is_empty()).then(|| dir.join("group_servers.json"))
}

fn key_id(key: &GroupKey) -> String {
    format!("{}.{}", key.tg, key.issued)
}

/// The bootstrap from the key, then what an earlier run learned for this key.
fn initial_servers(key: &GroupKey) -> Vec<Server> {
    let mut out = vec![Server::new(key.host.to_ascii_lowercase(), key.port)];
    let saved = pool_file()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
    if let Some(v) = saved {
        if v["key"].as_str() == Some(key_id(key).as_str()) {
            for name in v["servers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|n| n.as_str())
            {
                if let Some((h, p)) = valid_server_name(name) {
                    if out.len() < MAX_SERVERS && !out.iter().any(|s| s.host == h && s.port == p) {
                        out.push(Server::new(h, p));
                    }
                }
            }
        }
    }
    out
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

fn save_servers(key: &GroupKey, names: Vec<String>) {
    if let Some(p) = pool_file() {
        let v = serde_json::json!({ "key": key_id(key), "servers": names });
        let _ = std::fs::write(p, v.to_string());
    }
}

/// Fills an empty pool from the key (and the saved list), reading the file
/// outside the lock.
fn ensure_pool(key: &GroupKey) {
    if !group_state().lock().unwrap().servers.is_empty() {
        return;
    }
    let servers = initial_servers(key);
    let mut state = group_state().lock().unwrap();
    if state.servers.is_empty()
        && state
            .parsed
            .as_ref()
            .map_or(true, |k| key_id(k) == key_id(key))
    {
        state.servers = servers;
    }
}

/// The server new tunnels go to: its number (for logs) and its `host:port`
/// (its identity — indices shift when the key and so the pool changes).
fn pick_server(key: &GroupKey) -> (usize, String) {
    ensure_pool(key);
    let mut state = group_state().lock().unwrap();
    if state.servers.is_empty() {
        return (0, format!("{}:{}", key.host, key.port));
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
    (pick, name)
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

fn set_tunnel_ok(name: &str, ok: bool) {
    let mut state = group_state().lock().unwrap();
    if let Some(s) = state.servers.iter_mut().find(|s| s.name() == name) {
        s.tunnel_ok = ok;
    }
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
    let settings_key = settings::group_key();
    if settings_key.is_empty() {
        return None;
    }
    {
        let state = group_state().lock().unwrap();
        if state.key_string == settings_key {
            return state.parsed.clone();
        }
    }
    // A new key: parse it and read its saved pool outside the lock.
    let parsed = crate::group_key::parse_key(&settings_key).ok();
    let servers = parsed.as_ref().map(initial_servers).unwrap_or_default();
    let mut state = group_state().lock().unwrap();
    if state.key_string != settings_key {
        state.key_string = settings_key;
        state.parsed = parsed;
        state.servers = servers;
        state.current = None;
    }
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
fn server_addrs(server: &str, force_refresh: bool) -> Result<(String, Vec<SocketAddr>), String> {
    let (host, port) = valid_server_name(server).ok_or("нет сервера")?;
    // (addresses, fresh): a stale answer is kept to fall back on, never dropped.
    let cached = {
        let state = group_state().lock().unwrap();
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
    if let Some(s) = group_state()
        .lock()
        .unwrap()
        .servers
        .iter_mut()
        .find(|s| s.host == host && s.port == port)
    {
        s.addrs = Some((resolved.clone(), Instant::now()));
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
    server: &str,
    force_refresh: bool,
    budget: Duration,
) -> Result<(ClientConnection, TcpStream), String> {
    let t_dns = Instant::now();
    let (host, addrs) = server_addrs(server, force_refresh)?;
    let dns_ms = t_dns.elapsed().as_millis() as u64;
    let t_tcp = Instant::now();
    let deadline = Instant::now() + budget;

    let mut sock = None;
    for addr in addrs {
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
    sock.set_read_timeout(Some(budget)).ok();
    sock.set_write_timeout(Some(budget)).ok();
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
    let budget = upstream::LIVE_OPEN_BUDGET;
    let (mut tls, mut sock) = open_tls(server, force_refresh, budget)?;

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
    let mut stream = rustls::Stream::new(&mut tls, &mut sock);
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut acc = Vec::new();
    let mut buf = [0u8; 1024];
    let hdr_end = loop {
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

/// `closed` is set when the server ended the stream cleanly (close_notify): rustls
/// then stops asking to read, so the socket never reports EOF by itself.
fn drain_tls_reader(conn: &mut ClientConnection, pending: &mut Vec<u8>, closed: &mut bool) -> bool {
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
            Err(_) => break,
        }
    }
    moved
}

fn tls_pump(
    mut client: TcpStream,
    mut conn: ClientConnection,
    mut upstream_sock: TcpStream,
    leftover: Vec<u8>,
) {
    client.set_nonblocking(true).ok();
    upstream_sock.set_nonblocking(true).ok();
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

    while !(client_eof && upstream_eof && pending.is_empty()) {
        let mut moved = false;
        let mut payload = false;

        if !upstream_eof && conn.wants_read() {
            match conn.read_tls(&mut upstream_sock) {
                Ok(0) => {
                    let _ = conn.process_new_packets();
                    let m = drain_tls_reader(&mut conn, &mut pending, &mut closed);
                    moved |= m;
                    if m {
                        payload = true;
                    }
                    upstream_eof = true;
                    _why = End::Upstream;
                }
                Ok(_) => match conn.process_new_packets() {
                    Ok(_) => moved = true,
                    Err(_) => {
                        let _ = drain_tls_reader(&mut conn, &mut pending, &mut closed);
                        client_eof = true;
                        upstream_eof = true;
                        _why = End::Upstream;
                    }
                },
                Err(e) if crate::proxy::would_block(&e) => {}
                Err(_) => {
                    let _ = drain_tls_reader(&mut conn, &mut pending, &mut closed);
                    client_eof = true;
                    upstream_eof = true;
                    _why = End::Upstream;
                }
            }
        }

        // Drain reader unconditionally if there are decrypted packets waiting
        if pending.is_empty() {
            let m = drain_tls_reader(&mut conn, &mut pending, &mut closed);
            if m {
                moved = true;
                payload = true;
                awaiting = false;
            }
            if closed && !upstream_eof {
                upstream_eof = true;
                _why = End::Upstream;
            }
        }

        while !pending.is_empty() {
            match client.write(&pending) {
                Ok(0) => {
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
                Err(_) => {
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
                    _why = End::Client;
                }
                Ok(n) => {
                    if conn.writer().write_all(&buf[..n]).is_ok() {
                        _sent += n as u64;
                        if let Some(a) = &activity {
                            a.to_upstream(n as u64);
                        }
                        moved = true;
                        payload = true;
                        awaiting = true;
                    } else {
                        client_eof = true;
                        upstream_eof = true;
                        _why = End::Upstream;
                    }
                }
                Err(e) if crate::proxy::would_block(&e) => {}
                Err(_) => {
                    conn.send_close_notify();
                    client_eof = true;
                    _why = End::Client;
                }
            }
        }
        while conn.wants_write() {
            match conn.write_tls(&mut upstream_sock) {
                Ok(_) => moved = true,
                Err(e) if crate::proxy::would_block(&e) => break,
                Err(_) => {
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
            if drain_tls_reader(&mut conn, &mut pending, &mut closed) {
                moved = true;
            }
            if pending.is_empty() && !conn.wants_write() {
                break;
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
            break;
        }
    }

    conn.send_close_notify();
    let deadline = Instant::now() + crate::proxy::PUMP_MAX_SLEEP;
    while conn.wants_write() && Instant::now() < deadline {
        if conn.write_tls(&mut upstream_sock).is_err() {
            break;
        }
    }
    upstream_sock.flush().ok();
    upstream_sock.shutdown(std::net::Shutdown::Both).ok();

    client.shutdown(std::net::Shutdown::Write).ok();
    let deadline = Instant::now() + crate::proxy::PUMP_MAX_SLEEP;
    while Instant::now() < deadline {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if crate::proxy::would_block(&e) => thread::sleep(crate::proxy::PUMP_MIN_SLEEP),
            Err(_) => break,
        }
    }
}

pub fn tunnel(mut client: TcpStream, host: &str, _port: u16) -> Result<(), TcpStream> {
    if !available() {
        return Err(client);
    }

    if let Some(key) = get_active_key() {
        let route = group_route();
        // The chosen server, then — if it fails — the next choice once.
        for _ in 0..2 {
            let (idx, server) = pick_server(&key);
            match open_agu2(&key, &server, false, host) {
                Ok((tls, sock, leftover)) => {
                    let _active = ActiveGuard::new();
                    if client.write_all(crate::proxy::RESP_ESTABLISHED).is_err() {
                        return Ok(());
                    }
                    crate::routes::note_used(crate::routes::Kind::Group);
                    crate::dns_forwarder::log_proxy(&format!(
                        "{} #{} -> {}",
                        route.label(),
                        idx + 1,
                        host
                    ));

                    tls_pump(client, tls, sock, leftover);
                    return Ok(());
                }
                Err(why) => {
                    crate::dns_forwarder::log_proxy(&format!(
                        "{} #{}: {}",
                        route.label(),
                        idx + 1,
                        scrub(&why)
                    ));
                    let pool = group_state().lock().unwrap().servers.len();
                    set_tunnel_ok(&server, false);
                    if pool < 2 {
                        break;
                    }
                }
            }
        }
        route.health.note(false);
    }
    Err(client)
}

pub fn probe_health() {
    let key = match get_active_key() {
        Some(k) => k,
        None => return,
    };

    poll_pool(&key);
    group_route().probe_with(|| probe_once(&key, true));
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
    let (mut tls, mut sock) = open_tls(server, false, budget)?;
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
    // Results belong to this key's pool; a key changed meanwhile has its own.
    if state.parsed.as_ref().map(key_id) != Some(key_id(key)) {
        return;
    }
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
    let total = state.servers.len();
    let saved: Option<Vec<String>> =
        learned.then(|| state.servers.iter().map(Server::name).collect());
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
    if let Some(names) = saved {
        crate::dns_forwarder::log_proxy(&format!("Прокси из группы: серверов в пуле {}", total));
        save_servers(key, names);
    }
    for name in retry {
        let ok = probe_via(key, &name, false).is_ok();
        set_tunnel_ok(&name, ok);
    }
    pick_server(key);
}

/// One request to Google through the group server: proof the tunnel carries
/// TLS end to end, not just that the CONNECT was accepted.
fn probe_once(key: &GroupKey, force_refresh: bool) -> Result<(), String> {
    let (_, server) = pick_server(key);
    let r = probe_via(key, &server, force_refresh);
    set_tunnel_ok(&server, r.is_ok());
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
mod tests {
    use super::*;

    #[test]
    fn a_server_the_pool_no_longer_lists_is_dropped() {
        let mut v = vec![
            Server::new("a.example".into(), 443),
            Server::new("b.example".into(), 8443),
            Server::new("c.example".into(), 443),
        ];
        let listed = vec![
            ("a.example".to_string(), 443),
            ("c.example".to_string(), 443),
        ];
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
            Cand {
                ok: false,
                cpu: Some(0),
            },
            Cand {
                ok: true,
                cpu: Some(90),
            },
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
