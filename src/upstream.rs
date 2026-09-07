//! "Bring your own exit" - the user's own proxy in a permitted region.
//!
//! Everything else in this tool exists to make Google see a request from a
//! region it allows: an NRPT rule, a substituted address, a relay somebody else
//! runs. A proxy that already egresses in such a region does that directly, and
//! it was proven end to end rather than assumed - through a Dutch CONNECT proxy
//! the language server got a correct answer out of the model while our own relay
//! log stayed empty and not one DNS rule was involved (kb/dns.md).
//!
//! So if a user has one, it is the best route available and it is theirs, not a
//! third party we chose for them. It is asked for once, in menu 1, and may be
//! skipped with Enter.
//!
//! Supports HTTP CONNECT and SOCKS5 / SOCKS5h upstream proxies (RFC 1928, RFC 1929).

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::ClientConnection;

use crate::health::Health;

/// How long `open` may spend reaching a proxy and reading its answer for the
/// region check - which asks a different question from route health, runs rarely,
/// and is worth waiting out rather than repeating.
const PROBE_OPEN_BUDGET: Duration = Duration::from_secs(15);
/// The same for every path a request can take, and for the health probe that
/// stands in for one.
///
/// Much shorter, and the reason is not impatience. Falling from one route to the
/// next is free in correctness - nothing is committed before the `200` (I35) - but
/// it is not free in time, and the two were confused. A route that has not
/// answered a `CONNECT` in three seconds is not going to save this request: the
/// route below it is already there, and whether the slow one is really down is a
/// question for the warm loop, not for the person waiting. With the probe limit on
/// this path a flapping exit cost 15 s per attempt and 30 s before its second
/// failure benched it, which is most of what a long "Authenticating" was.
pub const LIVE_OPEN_BUDGET: Duration = Duration::from_secs(3);
/// Longest a probe's own request may take once the tunnel is open.
const PROBE_BUDGET: Duration = Duration::from_secs(20);

/// The host a probe asks for: the one the IDE actually uses, so a probe measures
/// the path a request will take rather than a neighbouring one.
const PROBE_HOST: &str = "daily-cloudcode-pa.googleapis.com";

/// One route's standing, and the only place the two reasons a route stands down
/// are kept apart (I44).
///
/// `health` is timed: a route that stopped answering is benched and the bench
/// doubles, because waiting is the right response to an outage. `bad_exit` is not
/// timed at all - a proxy that surfaces in the blocked region is useless *at that
/// exit*, and no amount of waiting moves it, only a new address does. So that
/// verdict is pinned to the address and released the moment it changes.
///
/// One of these per route, not one shared: the user's own proxy and each built-in
/// exit fail independently, and a single pair of statics would have one dead exit
/// bench every other route along with it.
pub struct Route {
    pub health: Health,
    bad_exit: Mutex<Option<String>>,
    /// How this route is named in the log - never its address. A built-in exit is
    /// private, and a log file is the one thing users paste into public chats.
    label: &'static str,
    /// Which row of the route table a probe of this route feeds. The user's own
    /// proxy has a row of its own; every built-in exit feeds the one `Exits` row,
    /// because the proxy treats the pool as a single route.
    kind: crate::routes::Kind,
}

impl Route {
    pub const fn new(label: &'static str, kind: crate::routes::Kind) -> Self {
        Route {
            health: Health::new(label),
            bad_exit: Mutex::new(None),
            label,
            kind,
        }
    }

    /// Whether this route is worth trying for the next connection: answering, and
    /// coming out somewhere Google will accept.
    pub fn usable(&self) -> bool {
        self.bad_exit().is_none() && !self.health.is_benched()
    }

    /// How this route is named in the log. Only the built-in exits ask - every
    /// other route knows its own name at the call site - so a build without them
    /// is honest about it rather than carrying a warning.
    #[cfg_attr(not(exits), allow(dead_code))]
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// The exit this route was last found unusable at, while it is standing down
    /// for that reason.
    fn bad_exit(&self) -> Option<String> {
        self.bad_exit.lock().ok().and_then(|g| g.clone())
    }

    /// Records that this exit is in a blocked region, so the route stands down
    /// until the address changes. Quiet when it is the same exit as last time -
    /// this runs on a timer and would otherwise repeat itself forever.
    fn note_blocked_exit(&self, ip: &str, loc: &str) {
        let Ok(mut pinned) = self.bad_exit.lock() else {
            return;
        };
        if pinned.as_deref() == Some(ip) {
            return;
        }
        *pinned = Some(ip.to_string());
        crate::dns_forwarder::log_proxy(&format!(
            "{} выходит через {} ({}) — это заблокированный регион, маршрут отключён до смены выхода",
            self.label, ip, loc
        ));
    }

    /// Releases the pin, because the exit moved somewhere usable.
    fn note_usable_exit(&self, ip: &str, loc: &str) {
        let Ok(mut pinned) = self.bad_exit.lock() else {
            return;
        };
        if pinned.is_none() {
            return;
        }
        *pinned = None;
        crate::dns_forwarder::log_proxy(&format!(
            "{} сменил выход на {} ({}) — снова используем",
            self.label, ip, loc
        ));
    }

    /// The warm loop's whole check for one route, run on our own time and never
    /// with somebody's request (I38).
    ///
    /// `check_region` is separate because the two halves cost differently. The
    /// carry probe is one tunnel to Google; the region check is another full TLS
    /// request, and for a built-in exit shared by every user of this tool that is
    /// load somebody else pays for. So the caller decides how often it is worth
    /// asking again where a route comes out.
    pub fn probe(&self, up: &Upstream, check_region: bool) {
        // Where it comes out is checked first, and separately, because it answers
        // a different question. A proxy can be perfectly responsive and still be
        // useless: if it surfaces in the blocked region Google refuses the request
        // with the very 400 this whole tool exists to remove - and that refusal is
        // invisible from here, because it arrives inside the client's own TLS. The
        // exit address is the one part of it we *can* see, so it is what the route
        // is judged on.
        if check_region {
            match exit_info(up) {
                Some((ip, loc)) if region_is_blocked(&loc) => {
                    self.note_blocked_exit(&ip, &loc);
                    // Nothing else is worth measuring: it is not coming back until
                    // the address changes, and this runs again shortly to see if
                    // it has.
                    return;
                }
                Some((ip, loc)) => self.note_usable_exit(&ip, &loc),
                // No trace host was reachable through it. That is a fault of its
                // own and the carry probe below will say so; it is not evidence
                // about the region, so an existing verdict is left standing.
                None => {}
            }
        }

        // Timed as a whole - reaching the proxy, its CONNECT, the TLS to Google
        // inside it and the answer - because that is what a request through it
        // costs, and the route table ranks routes by exactly that (routes.rs).
        let started = Instant::now();
        match probe(up) {
            Ok(()) => {
                crate::routes::record(self.kind, started.elapsed());
                self.health.revive("проверка прошла");
            }
            Err(why) => {
                crate::dns_forwarder::log_proxy(&format!("{} не отвечает: {}", self.label, why));
                // One built-in exit failing says nothing about the pool's speed -
                // its own bench takes it out of rotation; the row stays as the
                // other exits measured it.
                if self.kind != crate::routes::Kind::Exits {
                    crate::routes::record_failure(self.kind);
                }
                self.health.probe_failed();
            }
        }
    }
}

/// The user's own proxy, as a route. Built-in exits carry one of these each.
pub static OWN: Route = Route::new("свой прокси", crate::routes::Kind::Own);

/// The protocol kind for user upstream proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    Socks5,
    Socks5h,
}

/// A user-supplied HTTP CONNECT or SOCKS5 upstream proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// `user:pass`, already joined; `None` when the proxy needs no credential.
    pub auth: Option<String>,
}

impl Upstream {
    /// How it is shown back to the user - without the password, which they do
    /// not need to see again and which has no business being on screen or in a
    /// screenshot attached to a bug report.
    pub fn display(&self) -> String {
        let prefix = match self.kind {
            ProxyKind::Http => "",
            ProxyKind::Socks5 => "socks5://",
            ProxyKind::Socks5h => "socks5h://",
        };
        let host_disp = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match &self.auth {
            Some(a) => {
                let user = a.split(':').next().unwrap_or("");
                format!("{}{}:***@{}:{}", prefix, user, host_disp, self.port)
            }
            None => format!("{}{}:{}", prefix, host_disp, self.port),
        }
    }

    fn as_line(&self) -> String {
        let prefix = match self.kind {
            ProxyKind::Http => "",
            ProxyKind::Socks5 => "socks5://",
            ProxyKind::Socks5h => "socks5h://",
        };
        let host_disp = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match &self.auth {
            Some(a) => format!("{}{}@{}:{}", prefix, a, host_disp, self.port),
            None => format!("{}{}:{}", prefix, host_disp, self.port),
        }
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Reads what the user typed.
///
/// Deliberately forgiving about the shapes people actually paste - with or
/// without a scheme, with or without a credential - and strict about the one
/// thing that must be right, the port. A silently mis-parsed proxy would look
/// exactly like a proxy that is down.
pub fn parse(input: &str) -> Result<Upstream, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("пустая строка".to_string());
    }

    let (kind, rest) = if let Some(stripped) = strip_prefix_ignore_case(raw, "socks5h://") {
        (ProxyKind::Socks5h, stripped)
    } else if let Some(stripped) = strip_prefix_ignore_case(raw, "socks5://") {
        (ProxyKind::Socks5, stripped)
    } else if let Some(stripped) = strip_prefix_ignore_case(raw, "http://") {
        (ProxyKind::Http, stripped)
    } else if let Some(stripped) = strip_prefix_ignore_case(raw, "https://") {
        (ProxyKind::Http, stripped)
    } else if raw.contains("://") {
        return Err("неподдерживаемый протокол прокси (поддерживаются http://, socks5://, socks5h://)".to_string());
    } else {
        (ProxyKind::Http, raw)
    };

    let rest = rest.trim();
    if rest.is_empty() {
        return Err("не указан адрес".to_string());
    }

    // Split on the LAST '@': a password may contain one, a hostname may not.
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, hp)) => {
            let Some((user, pass)) = a.split_once(':') else {
                return Err("логин без пароля — нужно логин:пароль@хост:порт".to_string());
            };
            if user.is_empty() {
                return Err("пустой логин".to_string());
            }
            if user.len() > 255 {
                return Err("длина логина превышает 255 байт".to_string());
            }
            if pass.len() > 255 {
                return Err("длина пароля превышает 255 байт".to_string());
            }
            (Some(a.to_string()), hp)
        }
        None => (None, rest),
    };

    let hostport = hostport.trim_end_matches('/');
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| "не указан порт — нужно хост:порт".to_string())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("не указан адрес".to_string());
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("порт «{}» не число", port))?;
    if port == 0 {
        return Err("порт не может быть 0".to_string());
    }
    Ok(Upstream {
        kind,
        host: host.to_string(),
        port,
        auth,
    })
}

/// Where the address is kept.
///
/// Beside the relay's log, because both processes have to reach it: menu 1 runs
/// as the user and writes it, and the relay - which is what actually opens the
/// connections - runs under an S4U principal for that same user and reads it.
/// A registry value or an environment variable would need a relay restart to
/// take effect; a file is picked up on the next connection.
pub fn config_path() -> PathBuf {
    crate::dns_forwarder::log_dir().join("upstream.txt")
}

pub fn save(up: &Upstream) -> Result<(), String> {
    let path = config_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(&path, up.as_line()).map_err(|e| e.to_string())
}

pub fn clear() {
    fs::remove_file(config_path()).ok();
}

/// The configured proxy, or `None` when the user skipped the question.
///
/// Read from disk every time rather than cached: the relay runs for weeks, and a
/// user who changes or removes their proxy in menu 1 should not have to restart
/// a background service for it to matter. One small read per connection is
/// nothing beside the handshake that follows it - the same reasoning the old CA
/// lookup used.
pub fn configured() -> Option<Upstream> {
    let raw = fs::read_to_string(config_path()).ok()?;
    parse(&raw).ok()
}

/// Whether the route should be tried for this connection.
///
/// Three things have to hold: the user gave us one, it is answering, and it
/// comes out somewhere Google will accept. The last is checked against a pinned
/// address rather than a clock - see `Route`.
pub fn available() -> bool {
    configured().is_some() && OWN.usable()
}

fn basic(auth: &str) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let data = auth.as_bytes();
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Reaches the proxy itself, inside `deadline` whatever shape its address is in.
///
/// A hostname has to be resolved before `connect_timeout` can be used at all,
/// and the obvious `parse().unwrap_or_else(|_| TcpStream::connect(..))` silently
/// drops the budget for exactly that case: a named proxy whose address black-holes
/// then hangs on the OS default - about 21 s on Windows - with a live client
/// waiting behind it. The budget is spent across every candidate address rather
/// than granted to each, so the whole step is bounded however many a name has.
fn connect_within_budget(host: &str, port: u16, deadline: Instant) -> Result<TcpStream, String> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("адрес не разрешается: {}", e))?
        .collect();
    if addrs.is_empty() {
        return Err("адрес не разрешается".to_string());
    }
    let mut last = String::from("время вышло");
    for addr in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, left) {
            Ok(sock) => return Ok(sock),
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("недоступен: {}", last))
}

/// Opens a tunnel to `host:port` through the given proxy.
///
/// Everything that can fail happens here, before the caller has told its client
/// anything - the same rule the relay route follows (I35). An `Err` means the
/// caller still holds an untouched client socket and can take another route.
///
/// The error says only what went wrong, never which proxy it was: the caller
/// knows that and names the route itself, and a built-in exit must not put its
/// address in a log line (see `Route::label`).
///
/// `budget` covers the **whole** step - resolve, connect and read the answer -
/// because that is the thing a waiting client experiences. Bounding each part
/// separately is how three seconds of patience turns into fifteen (I43).
fn socks5_connect(
    sock: &mut TcpStream,
    up: &Upstream,
    target_host: &str,
    target_port: u16,
    deadline: Instant,
) -> Result<(), String> {
    let check_deadline = || -> Result<Duration, String> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err("прокси не ответил вовремя".to_string())
        } else {
            Ok(left)
        }
    };

    // --- Phase 1: Method Greeting ---
    let left = check_deadline()?;
    sock.set_read_timeout(Some(left)).ok();
    sock.set_write_timeout(Some(left)).ok();

    if up.auth.is_some() {
        // Offer NO AUTH (0x00) and USERNAME/PASSWORD (0x02)
        sock.write_all(&[0x05, 0x02, 0x00, 0x02])
            .map_err(|e| format!("не отправить приветствие SOCKS: {}", e))?;
    } else {
        // Offer only NO AUTH (0x00)
        sock.write_all(&[0x05, 0x01, 0x00])
            .map_err(|e| format!("не отправить приветствие SOCKS: {}", e))?;
    }

    let mut method_reply = [0u8; 2];
    sock.read_exact(&mut method_reply)
        .map_err(|e| format!("прокси закрыл соединение: {}", e))?;

    if method_reply[0] != 0x05 {
        return Err("неверная версия SOCKS-сервера".to_string());
    }

    match method_reply[1] {
        0x00 => {
            // No authentication required
        }
        0x02 => {
            // Username/Password authentication (RFC 1929)
            let Some(ref auth) = up.auth else {
                return Err("прокси требует логин и пароль".to_string());
            };
            let (user, pass) = auth.split_once(':').unwrap_or((auth.as_str(), ""));
            let u_bytes = user.as_bytes();
            let p_bytes = pass.as_bytes();
            if u_bytes.len() > 255 || p_bytes.len() > 255 {
                return Err("логин или пароль превышает 255 байт".to_string());
            }

            let left = check_deadline()?;
            sock.set_read_timeout(Some(left)).ok();
            sock.set_write_timeout(Some(left)).ok();

            let mut auth_req = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
            auth_req.push(0x01); // RFC 1929 subnegotiation version 1
            auth_req.push(u_bytes.len() as u8);
            auth_req.extend_from_slice(u_bytes);
            auth_req.push(p_bytes.len() as u8);
            auth_req.extend_from_slice(p_bytes);

            sock.write_all(&auth_req)
                .map_err(|e| format!("ошибка отправки аутентификации SOCKS: {}", e))?;

            let mut auth_reply = [0u8; 2];
            sock.read_exact(&mut auth_reply)
                .map_err(|e| format!("нет ответа аутентификации SOCKS: {}", e))?;

            if auth_reply[0] != 0x01 {
                return Err("неверная версия ответа аутентификации SOCKS".to_string());
            }
            if auth_reply[1] != 0x00 {
                return Err(format!(
                    "неверный логин или пароль SOCKS-прокси (статус 0x{:02X})",
                    auth_reply[1]
                ));
            }
        }
        0xFF => {
            return Err("прокси отклонил методы аутентификации (0xFF)".to_string());
        }
        other => {
            return Err(format!(
                "неподдерживаемый метод аутентификации SOCKS: 0x{:02X}",
                other
            ));
        }
    }

    // --- Phase 2: CONNECT Request ---
    let left = check_deadline()?;
    sock.set_read_timeout(Some(left)).ok();
    sock.set_write_timeout(Some(left)).ok();

    let mut connect_req = vec![0x05, 0x01, 0x00];

    if up.kind == ProxyKind::Socks5 {
        if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
            connect_req.push(0x01);
            connect_req.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = target_host.parse::<std::net::Ipv6Addr>() {
            connect_req.push(0x04);
            connect_req.extend_from_slice(&ip.octets());
        } else if let Ok(mut addrs) = (target_host, target_port).to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                match addr.ip() {
                    std::net::IpAddr::V4(v4) => {
                        connect_req.push(0x01);
                        connect_req.extend_from_slice(&v4.octets());
                    }
                    std::net::IpAddr::V6(v6) => {
                        connect_req.push(0x04);
                        connect_req.extend_from_slice(&v6.octets());
                    }
                }
            } else {
                if target_host.len() > 255 {
                    return Err("имя хоста превышает 255 байт".to_string());
                }
                connect_req.push(0x03);
                connect_req.push(target_host.len() as u8);
                connect_req.extend_from_slice(target_host.as_bytes());
            }
        } else {
            if target_host.len() > 255 {
                return Err("имя хоста превышает 255 байт".to_string());
            }
            connect_req.push(0x03);
            connect_req.push(target_host.len() as u8);
            connect_req.extend_from_slice(target_host.as_bytes());
        }
    } else {
        // Socks5h: Remote proxy-side resolution
        if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
            connect_req.push(0x01);
            connect_req.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = target_host.parse::<std::net::Ipv6Addr>() {
            connect_req.push(0x04);
            connect_req.extend_from_slice(&ip.octets());
        } else {
            if target_host.len() > 255 {
                return Err("имя хоста превышает 255 байт".to_string());
            }
            connect_req.push(0x03);
            connect_req.push(target_host.len() as u8);
            connect_req.extend_from_slice(target_host.as_bytes());
        }
    }
    connect_req.extend_from_slice(&target_port.to_be_bytes());

    sock.write_all(&connect_req)
        .map_err(|e| format!("не отправить SOCKS CONNECT: {}", e))?;

    // --- Phase 3: SOCKS5 Reply Header & Status ---
    let mut resp_header = [0u8; 4];
    sock.read_exact(&mut resp_header)
        .map_err(|e| format!("нет ответа на SOCKS CONNECT: {}", e))?;

    if resp_header[0] != 0x05 {
        return Err("неверная версия ответа SOCKS".to_string());
    }

    match resp_header[1] {
        0x00 => {} // Success
        0x01 => return Err("общая ошибка SOCKS-сервера".to_string()),
        0x02 => return Err("соединение запрещено правилами SOCKS-сервера".to_string()),
        0x03 => return Err("сеть недоступна".to_string()),
        0x04 => return Err("целевой хост недоступен".to_string()),
        0x05 => return Err("соединение отклонено целевым узлом".to_string()),
        0x06 => return Err("время жизни пакета (TTL) истекло".to_string()),
        0x07 => return Err("команда не поддерживается SOCKS-сервером".to_string()),
        0x08 => return Err("тип адреса не поддерживается SOCKS-сервером".to_string()),
        code => return Err(format!("ошибка SOCKS CONNECT: 0x{:02X}", code)),
    }

    // --- Phase 4: Read & Discard Bound Address and Port ---
    match resp_header[3] {
        0x01 => {
            // IPv4: 4 bytes IP + 2 bytes port = 6 bytes
            let mut buf = [0u8; 6];
            sock.read_exact(&mut buf)
                .map_err(|e| format!("ошибка чтения адреса ответа SOCKS: {}", e))?;
        }
        0x03 => {
            // Domain name: 1 byte len + L bytes domain + 2 bytes port
            let mut len_buf = [0u8; 1];
            sock.read_exact(&mut len_buf)
                .map_err(|e| format!("ошибка чтения длины адреса SOCKS: {}", e))?;
            let dlen = len_buf[0] as usize;
            let mut buf = vec![0u8; dlen + 2];
            sock.read_exact(&mut buf)
                .map_err(|e| format!("ошибка чтения адреса SOCKS: {}", e))?;
        }
        0x04 => {
            // IPv6: 16 bytes IP + 2 bytes port = 18 bytes
            let mut buf = [0u8; 18];
            sock.read_exact(&mut buf)
                .map_err(|e| format!("ошибка чтения IPv6 адреса SOCKS: {}", e))?;
        }
        atyp => {
            return Err(format!(
                "неподдерживаемый тип адреса привязки SOCKS: 0x{:02X}",
                atyp
            ));
        }
    }

    Ok(())
}

pub fn open(up: &Upstream, host: &str, port: u16, budget: Duration) -> Result<TcpStream, String> {
    let deadline = Instant::now() + budget;
    let mut sock = connect_within_budget(&up.host, up.port, deadline)?;
    let left = || deadline.saturating_duration_since(Instant::now());
    // A zero timeout means "block forever" to the OS, so a spent budget has to be
    // an error here rather than a socket option.
    if left().is_zero() {
        return Err("прокси не ответил вовремя".to_string());
    }

    match up.kind {
        ProxyKind::Http => {
            sock.set_read_timeout(Some(left())).ok();
            sock.set_write_timeout(Some(left())).ok();

            let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
            if let Some(a) = &up.auth {
                req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", basic(a)));
            }
            req.push_str("\r\n");
            sock.write_all(req.as_bytes())
                .map_err(|e| format!("не отправить CONNECT: {}", e))?;

            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() > 8 * 1024 {
                    return Err("прокси ответил чем-то очень длинным".to_string());
                }
                // The socket timeout bounds one `read`; this bounds the loop, so a proxy
                // dribbling a byte at a time cannot outlast the budget by repeating.
                if left().is_zero() {
                    return Err("прокси не ответил вовремя".to_string());
                }
                match sock.read(&mut byte) {
                    Ok(0) => return Err("прокси закрыл соединение".to_string()),
                    Ok(_) => head.push(byte[0]),
                    Err(e) => return Err(format!("нет ответа: {}", e)),
                }
            }
            let status = String::from_utf8_lossy(&head)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            // Not `starts_with("HTTP/1.1 200")`: a CONNECT proxy is free to answer on
            // HTTP/1.0, and tinyproxy - which is what the built-in exits run - does.
            if !status.contains(" 200") {
                // Two statuses are worth naming, because neither is an outage and neither
                // fixes itself however long the route is benched: 407 is a credential
                // problem, and 403 means this proxy filters by destination and does not
                // carry the host we asked for.
                if status.contains(" 407") {
                    return Err("прокси требует логин и пароль".to_string());
                }
                if status.contains(" 403") {
                    return Err(format!("прокси не пропускает этот хост: {}", host));
                }
                return Err(format!("прокси отказал: {}", status));
            }
            // The budgets above bounded reaching the proxy and reading its answer. They
            // are mine, not the caller's, so the socket goes back clean - a caller that
            // wants one of its own (`probe`, `exit_info`) sets it immediately, and a
            // tunnel wants none (see `proxy::splice`, and I37).
            sock.set_read_timeout(None).ok();
            sock.set_write_timeout(None).ok();
            Ok(sock)
        }
        ProxyKind::Socks5 | ProxyKind::Socks5h => {
            socks5_connect(&mut sock, up, host, port, deadline)?;
            sock.set_read_timeout(None).ok();
            sock.set_write_timeout(None).ok();
            Ok(sock)
        }
    }
}

/// A full request through the proxy: TLS to Google inside the tunnel, and an
/// answer back. What a probe has to prove is that the route *carries* something,
/// not merely that the proxy accepts a CONNECT - the relay taught that lesson by
/// accepting tunnels for an hour and cutting every one at the handshake.
pub fn probe(up: &Upstream) -> Result<(), String> {
    // Opened on the **live** budget, not the generous one. A probe exists to
    // predict what a request will meet, so the two must agree on what "reachable"
    // means: judge on 15 s and serve on 3 s and a merely-slow proxy flaps forever -
    // revived by every probe, benched by the next two requests. The generosity
    // belongs in the request below, which is measuring something else.
    let mut sock = open(up, PROBE_HOST, 443, LIVE_OPEN_BUDGET)?;
    sock.set_read_timeout(Some(PROBE_BUDGET)).ok();
    sock.set_write_timeout(Some(PROBE_BUDGET)).ok();
    let name = ServerName::try_from(PROBE_HOST).map_err(|e| e.to_string())?;
    let mut tls =
        ClientConnection::new(crate::proxy::probe_config(), name).map_err(|e| e.to_string())?;
    let mut stream = rustls::Stream::new(&mut tls, &mut sock);
    let req = format!(
        "GET /v1internal:probe HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        PROBE_HOST
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("рукопожатие: {}", e))?;
    let mut buf = [0u8; 64];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("ответа нет: {}", e))?;
    // Any status line means the tunnel carried a request end to end; which status
    // it is says nothing, since the path is deliberately not a real API call.
    if n > 0 && buf.starts_with(b"HTTP/") {
        Ok(())
    } else {
        Err("ответ не похож на HTTP".to_string())
    }
}

/// Checked on the warm loop, so the route is judged on our time and never with
/// somebody's request. A no-op when the user never gave us a proxy.
///
/// The region half runs every time here, unlike the built-in exits: this is one
/// proxy belonging to the person in front of us, so there is nobody else to be
/// considerate towards, and it is the route most likely to be a VPN that quietly
/// surfaces next door.
pub fn probe_health() {
    let Some(up) = configured() else {
        return;
    };
    OWN.probe(&up, true);
}

/// Which country the proxy comes out in, as Cloudflare sees it.
///
/// The single most useful thing to tell a user at setup time. A proxy that exits
/// in the blocked region changes the address and nothing else - measured on WARP,
/// which reported `loc=RU` exactly like the direct connection - so it cannot lift
/// the gate, and saying so at once saves them believing otherwise.
pub fn exit_country(up: &Upstream) -> Option<String> {
    exit_info(up).map(|(_, loc)| loc)
}

/// The address the proxy comes out on, and the country Cloudflare puts it in.
///
/// The address matters as much as the country: a proxy that surfaces somewhere
/// blocked is unusable *at that exit*, and the way it becomes usable again is by
/// rotating to another one. Watching the address is how we notice that without
/// asking the user to press anything.
pub fn exit_info(up: &Upstream) -> Option<(String, String)> {
    TRACE_HOSTS.iter().find_map(|h| trace_through(up, h))
}

/// Hosts that will report an exit back, in the order they are tried.
///
/// `www.cloudflare.com` first: it is the canonical one, and it is not something a
/// user's own proxy is likely to have an opinion about. The rest exist because a
/// *filtering* proxy answers `403 Filtered` for it while carrying them perfectly
/// well - which is exactly what the built-in exits are, somebody's AI-unblocking
/// service with a whitelist. Measured through one: cloudflare.com refused, both
/// of the others return a full trace.
///
/// Getting this wrong is not a small thing. A `None` from here leaves the previous
/// region verdict standing, so a route whose exit had quietly moved into the
/// blocked region would keep taking traffic and keep failing inside the client's
/// own TLS, where none of it is visible to us.
const TRACE_HOSTS: &[&str] = &["www.cloudflare.com", "chatgpt.com", "claude.ai"];

fn trace_through(up: &Upstream, host: &'static str) -> Option<(String, String)> {
    let mut sock = open(up, host, 443, PROBE_OPEN_BUDGET).ok()?;
    sock.set_read_timeout(Some(PROBE_BUDGET)).ok();
    sock.set_write_timeout(Some(PROBE_BUDGET)).ok();
    let name = ServerName::try_from(host).ok()?;
    let mut tls = ClientConnection::new(crate::proxy::probe_config(), name).ok()?;
    let mut stream = rustls::Stream::new(&mut tls, &mut sock);
    stream
        .write_all(
            format!(
                "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                host
            )
            .as_bytes(),
        )
        .ok()?;
    let mut body = Vec::new();
    let mut chunk = [0u8; 2048];
    while let Ok(n) = stream.read(&mut chunk) {
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > 8 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&body);
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
            .filter(|v| !v.is_empty())
    };
    Some((field("ip=")?, field("loc=")?))
}

/// The machine's OWN egress, ip and Cloudflare's country for it, over the
/// default route (no proxy). This is the P16 primitive: menu 1 uses it to tell
/// the user whether their exit already lifts the gate, so the DNS layer is
/// insurance rather than load-bearing (G26). Advisory only - it never decides
/// what to install, because the 400 is invisible out of band and a permitted
/// exit is inferred, not proven.
///
/// Same trace hosts and parsing as `exit_info`, just dialed directly. Bounded so
/// a dead network cannot hang the menu.
pub fn machine_exit() -> Option<(String, String)> {
    TRACE_HOSTS.iter().find_map(|h| trace_direct(h))
}

fn trace_direct(host: &'static str) -> Option<(String, String)> {
    let addr = (host, 443u16);
    let mut sock = std::net::TcpStream::connect(addr).ok()?;
    sock.set_read_timeout(Some(PROBE_BUDGET)).ok();
    sock.set_write_timeout(Some(PROBE_BUDGET)).ok();
    let name = ServerName::try_from(host).ok()?;
    let mut tls = ClientConnection::new(crate::proxy::probe_config(), name).ok()?;
    let mut stream = rustls::Stream::new(&mut tls, &mut sock);
    stream
        .write_all(
            format!(
                "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                host
            )
            .as_bytes(),
        )
        .ok()?;
    let mut body = Vec::new();
    let mut chunk = [0u8; 2048];
    while let Ok(n) = stream.read(&mut chunk) {
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > 8 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&body);
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
            .filter(|v| !v.is_empty())
    };
    Some((field("ip=")?, field("loc=")?))
}

/// Regions where a proxy is pointless, because they are the ones being blocked.
/// Not a complete list and not meant to be - it exists to catch the common case
/// of someone pointing this at a VPN that surfaces next door.
const BLOCKED_REGIONS: &[&str] = &["RU", "BY"];

pub fn region_is_blocked(loc: &str) -> bool {
    BLOCKED_REGIONS.iter().any(|r| r.eq_ignore_ascii_case(loc))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live: the P16 primitive reaches Cloudflare directly and reads the exit
    /// country. Ignored (needs the network); the point is that the direct
    /// rustls path works, not the value.
    #[test]
    #[ignore = "needs a live network; run with --ignored"]
    fn machine_exit_reports_a_country() {
        let (ip, loc) = machine_exit().expect("a trace");
        println!("exit ip={} loc={}", ip, loc);
        assert!(!ip.is_empty() && loc.len() == 2, "ip={} loc={}", ip, loc);
    }

    #[test]
    fn reads_the_shapes_people_actually_paste() {
        let plain = Upstream {
            kind: ProxyKind::Http,
            host: "127.0.0.1".into(),
            port: 1371,
            auth: None,
        };
        assert_eq!(parse("127.0.0.1:1371").unwrap(), plain);
        assert_eq!(parse("http://127.0.0.1:1371").unwrap(), plain);
        assert_eq!(parse("  http://127.0.0.1:1371/  ").unwrap(), plain);
        assert_eq!(
            parse("http://user:pw@proxy.example.com:8080").unwrap(),
            Upstream {
                kind: ProxyKind::Http,
                host: "proxy.example.com".into(),
                port: 8080,
                auth: Some("user:pw".into())
            }
        );
        // A password may contain '@'; a hostname may not, so the last one wins.
        assert_eq!(
            parse("user:p@ss@proxy.example.com:8080").unwrap().auth,
            Some("user:p@ss".into())
        );

        // SOCKS5 and SOCKS5h parsing
        assert_eq!(
            parse("socks5://127.0.0.1:1080").unwrap(),
            Upstream {
                kind: ProxyKind::Socks5,
                host: "127.0.0.1".into(),
                port: 1080,
                auth: None,
            }
        );
        assert_eq!(
            parse("SOCKS5://127.0.0.1:1080").unwrap(),
            Upstream {
                kind: ProxyKind::Socks5,
                host: "127.0.0.1".into(),
                port: 1080,
                auth: None,
            }
        );
        assert_eq!(
            parse("socks5h://user:secret@127.0.0.1:1080").unwrap(),
            Upstream {
                kind: ProxyKind::Socks5h,
                host: "127.0.0.1".into(),
                port: 1080,
                auth: Some("user:secret".into()),
            }
        );
    }

    /// A mis-parsed proxy is indistinguishable from a proxy that is down, so
    /// anything ambiguous has to be refused while the user is still looking.
    #[test]
    fn refuses_what_it_cannot_be_sure_of() {
        for bad in [
            "",
            "   ",
            "proxy.example.com",
            "proxy.example.com:",
            "proxy.example.com:port",
            "proxy.example.com:0",
            "socks4://127.0.0.1:1080",
            "ftp://127.0.0.1:1080",
            "user@proxy.example.com:8080",
        ] {
            assert!(parse(bad).is_err(), "should have been refused: {:?}", bad);
        }
    }

    /// A password must not come back out onto the screen.
    #[test]
    fn the_password_is_never_displayed() {
        let up = parse("bob:hunter2@proxy.example.com:8080").unwrap();
        let shown = up.display();
        assert!(!shown.contains("hunter2"), "{}", shown);
        assert!(shown.contains("bob") && shown.contains("proxy.example.com:8080"));

        let socks_up = parse("socks5://bob:hunter2@proxy.example.com:1080").unwrap();
        let socks_shown = socks_up.display();
        assert!(!socks_shown.contains("hunter2"), "{}", socks_shown);
        assert!(socks_shown.starts_with("socks5://"));
    }

    /// Round-trip through the file format, since that is what the relay reads.
    #[test]
    fn survives_the_trip_through_the_config_line() {
        for raw in [
            "127.0.0.1:1371",
            "bob:hunter2@proxy.example.com:8080",
            "[::1]:3128",
            "socks5://127.0.0.1:1080",
            "socks5://bob:hunter2@proxy.example.com:1080",
            "socks5h://127.0.0.1:10808",
            "socks5h://bob:hunter2@proxy.example.com:10808",
        ] {
            let up = parse(raw).unwrap();
            assert_eq!(parse(&up.as_line()).unwrap(), up, "{}", raw);
        }
    }

    #[test]
    fn socks5_handshake_no_auth_mock() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Expect greeting [0x05, 0x01, 0x00]
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).unwrap();
            assert_eq!(buf, [0x05, 0x01, 0x00]);
            // Reply [0x05, 0x00] (No Auth)
            stream.write_all(&[0x05, 0x00]).unwrap();

            // Read CONNECT request: [0x05, 0x01, 0x00, ...]
            let mut req_hdr = [0u8; 4];
            stream.read_exact(&mut req_hdr).unwrap();
            assert_eq!(req_hdr[0..3], [0x05, 0x01, 0x00]);
            if req_hdr[3] == 0x01 {
                let mut ip_port = [0u8; 6];
                stream.read_exact(&mut ip_port).unwrap();
            } else if req_hdr[3] == 0x03 {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).unwrap();
                let mut dom = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut dom).unwrap();
            }

            // Reply Success: [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
                .unwrap();
        });

        let up = Upstream {
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".to_string(),
            port,
            auth: None,
        };
        let sock = open(&up, "127.0.0.1", 8080, Duration::from_secs(3)).unwrap();
        assert!(sock.read_timeout().unwrap().is_none());
        assert!(sock.write_timeout().unwrap().is_none());
        handle.join().unwrap();
    }

    #[test]
    fn socks5_handshake_user_pass_mock() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Expect greeting [0x05, 0x02, 0x00, 0x02]
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).unwrap();
            assert_eq!(buf, [0x05, 0x02, 0x00, 0x02]);
            // Reply [0x05, 0x02] (User/Pass)
            stream.write_all(&[0x05, 0x02]).unwrap();

            // Read Auth Request: [0x01, ulen, user..., plen, pass...]
            let mut ver_ulen = [0u8; 2];
            stream.read_exact(&mut ver_ulen).unwrap();
            assert_eq!(ver_ulen[0], 0x01);
            let ulen = ver_ulen[1] as usize;
            let mut user = vec![0u8; ulen];
            stream.read_exact(&mut user).unwrap();
            assert_eq!(&user, b"alice");

            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut pass).unwrap();
            assert_eq!(&pass, b"secret123");

            // Reply Auth Success: [0x01, 0x00]
            stream.write_all(&[0x01, 0x00]).unwrap();

            // Read CONNECT
            let mut req_hdr = [0u8; 4];
            stream.read_exact(&mut req_hdr).unwrap();
            assert_eq!(req_hdr[0..3], [0x05, 0x01, 0x00]);
            if req_hdr[3] == 0x03 {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).unwrap();
                let mut dom = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut dom).unwrap();
            } else if req_hdr[3] == 0x01 {
                let mut ip_port = [0u8; 6];
                stream.read_exact(&mut ip_port).unwrap();
            }

            // Reply Success: [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
        });

        let up = Upstream {
            kind: ProxyKind::Socks5h,
            host: "127.0.0.1".to_string(),
            port,
            auth: Some("alice:secret123".to_string()),
        };
        let sock = open(&up, "example.com", 443, Duration::from_secs(3)).unwrap();
        assert!(sock.read_timeout().unwrap().is_none());
        assert!(sock.write_timeout().unwrap().is_none());
        handle.join().unwrap();
    }

    /// A blocked exit stands the route down, and only a *different* address
    /// brings it back - not a timer, because waiting does not move a proxy.
    ///
    /// On its own `Route` rather than a global, which is the point of there being
    /// one per route: two of these could now run in parallel without fighting.
    #[test]
    fn a_blocked_exit_stands_the_route_down_until_the_address_changes() {
        let r = Route::new("тест", crate::routes::Kind::Own);

        r.note_blocked_exit("203.0.113.7", "RU");
        assert_eq!(r.bad_exit().as_deref(), Some("203.0.113.7"));
        assert!(!r.usable(), "a blocked exit takes the route out of service");

        // Same exit seen again on the next pass: still down, and it must not
        // announce itself a second time.
        r.note_blocked_exit("203.0.113.7", "RU");
        assert_eq!(r.bad_exit().as_deref(), Some("203.0.113.7"));

        // Rotated, still blocked: down, now pinned to the new address.
        r.note_blocked_exit("198.51.100.4", "BY");
        assert_eq!(r.bad_exit().as_deref(), Some("198.51.100.4"));

        // Rotated somewhere usable: back in service.
        r.note_usable_exit("203.0.113.9", "NL");
        assert_eq!(r.bad_exit(), None);
        assert!(r.usable());
        r.note_usable_exit("203.0.113.9", "NL");
        assert_eq!(r.bad_exit(), None);
    }

    /// One route standing down must not take another with it. This is the whole
    /// reason `Route` exists rather than a pair of statics: with a shared pin, one
    /// dead built-in exit would have benched the user's own proxy too.
    #[test]
    fn routes_stand_down_independently() {
        let a = Route::new("тест A", crate::routes::Kind::Own);
        let b = Route::new("тест B", crate::routes::Kind::Own);
        a.note_blocked_exit("203.0.113.7", "RU");
        a.health.note(false);
        a.health.note(false);
        assert!(!a.usable());
        assert!(
            b.usable(),
            "B was never at fault and must still be in service"
        );
    }

    /// Live: the whole path against a real proxy, which is the only way to know
    /// the parser, the CONNECT and the probe agree with each other. Ignored by
    /// default - it needs an HTTP proxy on `127.0.0.1:1371` and a network.
    ///
    ///     cargo test upstream_route_works_against_a_real_proxy -- --ignored --nocapture
    #[test]
    #[ignore = "needs an HTTP proxy on 127.0.0.1:1371 and a live network"]
    fn upstream_route_works_against_a_real_proxy() {
        let up = parse("127.0.0.1:1371").expect("parsed");
        probe(&up).expect("the proxy carried a request to Google");
        let loc = exit_country(&up).expect("exit country");
        println!(
            "exit country: {} (blocked: {})",
            loc,
            region_is_blocked(&loc)
        );
        assert!(!loc.is_empty());
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(basic("f"), "Zg==");
        assert_eq!(basic("fo"), "Zm8=");
        assert_eq!(basic("foo"), "Zm9v");
        assert_eq!(basic("foobar"), "Zm9vYmFy");
    }

    /// The check that saves a user believing a same-region VPN will help.
    #[test]
    fn a_proxy_that_surfaces_in_the_blocked_region_is_recognised() {
        assert!(region_is_blocked("RU"));
        assert!(region_is_blocked("ru"));
        assert!(!region_is_blocked("NL"));
        assert!(!region_is_blocked(""));
    }
}
