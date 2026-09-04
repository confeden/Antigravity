use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection};

use crate::routes;
use crate::upstream;
use crate::utils::no_window;

// The fallback route: unblock the traffic instead of the name.
//
// The DNS layer can only help with a name some provider still substitutes, and
// it cannot help with how slow that provider's proxy is. `cloudcode-pa` is
// substituted by nobody (S9), and `daily-cloudcode-pa` only by geohide, which
// has been measured taking 1.4-14.8 s over a TLS handshake xbox does in 249 ms
// (P6). So this is a second route, working at the traffic level rather than at
// the name.
//
// It is a loopback CONNECT proxy and nothing else. A gate host goes through the
// authenticated relay in the private `relay` module - a CONNECT tunnel whose TLS
// stays end to end with Google, so no certificate of ours is anywhere near it.
// Everything else, *including* every other `*.googleapis.com`, is a raw byte
// tunnel: sign-in, token refresh and every other program on the machine keep
// exactly the TLS they had before this tool existed.
//
// It used to terminate the client's TLS with a CA generated on this machine and
// carry blocked names in under an SNI the unblock proxies accept - they are
// SNI-whitelisted forwarders (N13), but Google's frontend routes
// `*.googleapis.com` on the HTTP **Host** header, so a carrier SNI reaches the
// right backend. That whole route is gone: the relay reaches the same backends
// with no CA at all, and intercepting the rest black-screened the Desktop app
// with `BadCertificate`. The CA helpers below survive for one purpose - removing
// a certificate an older version installed. Measurements: kb/dns.md.

/// Loopback only. The port is fixed because `HTTPS_PROXY` is a static string in
/// the user's environment - an ephemeral port would need rewriting on every
/// relay start, and would be wrong for any process that read it earlier.
pub const LISTEN_IP: &str = "127.0.0.1";
pub const LISTEN_PORT: u16 = 53129;

/// Common name of the certificate authority older versions generated on this
/// machine. Nothing creates one any more; the name is kept so the three helpers
/// below can find and remove one that is still installed.
const CA_NAME: &str = "AG Unlocker local CA";

// The fast relay route's whole method - host, CONNECT-with-credential logic and
// the credential itself - lives in the gitignored `src/relay.rs`, compiled in
// only under `cfg(relay)` (set by build.rs when that file and `.relay_key` are
// both present). A build from the public source has neither, compiles the stub
// below, and runs the DNS route. `relay_available()` is the only symbol the rest
// of the crate needs; everything else stays private to that module.
#[cfg(relay)]
#[path = "relay.rs"]
mod relay;
// `relay_available` is used inside this module (`relay::relay_available()`); it is
// no longer re-exported because 2.11.0_1 stopped turning the carrier on from
// `main` by default (kb/rivals.md). `#[allow(unused_imports)]` keeps the stub
// build (cfg(not(relay))) honest without a second cfg arm.
#[cfg(relay)]
pub use relay::{probe_relay, relay_is_benched};

#[cfg(not(relay))]
pub fn relay_available() -> bool {
    false
}

/// No relay route to check in a build that has no relay module.
#[cfg(not(relay))]
pub fn probe_relay() {}

#[cfg(not(relay))]
pub fn relay_is_benched() -> bool {
    false
}

// The built-in exits - third-party CONNECT proxies that already egress in a
// permitted region - live in the gitignored `src/exits.rs` with their address
// list in `.exits`, compiled in only under `cfg(exits)`. Same arrangement as the
// relay, for a different reason: the method here is not secret (it is the plain
// CONNECT `upstream.rs` already speaks in public source), the addresses are, and
// only because naming somebody else's free proxy in a public repository is how it
// stops being one.
#[cfg(exits)]
#[path = "exits.rs"]
mod exits;
#[cfg(exits)]
pub use exits::probe_health as probe_exits;

/// No built-in exits to check in a build that has no exits module.
#[cfg(not(exits))]
pub fn probe_exits() {}

// The byte pump's timings, the upstream handshake and `would_block` below are
// the primitives the private relay module is built on, and its only users. A
// public build has no such module, so each is marked dead-code-allowed under
// `cfg(not(relay))` - a clone should compile without a wall of warnings, and
// silencing them one by one is honest about *why* they look unused.

/// How long the byte pump sleeps when both directions are idle. It starts at the
/// minimum and doubles to the maximum, so an active connection never sleeps and
/// an idle one costs a wakeup every 50 ms.
#[cfg_attr(not(relay), allow(dead_code))]
const PUMP_MIN_SLEEP: Duration = Duration::from_millis(1);
#[cfg_attr(not(relay), allow(dead_code))]
const PUMP_MAX_SLEEP: Duration = Duration::from_millis(50);
/// How long a freshly accepted socket may stay silent before it is dropped.
/// Long, because a pooling client legitimately opens sockets before it has
/// anything to send; bounded, so an abandoned one does not hold a thread.
const REQUEST_IDLE: Duration = Duration::from_secs(120);

/// Proxy status lines, kept as named constants rather than written inline.
///
/// The CRLF pairs in them are load-bearing and easy to lose: a tool that
/// normalises line endings turns the escape into a bare newline, rustc accepts
/// that without a word, and the result is a response no HTTP client will parse.
/// `status_lines_are_crlf_terminated` is what stops that reaching a release.
const RESP_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const RESP_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
const RESP_NOT_ALLOWED: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n";

// Cleanup only, from here to `untrust_ca`. Up to 2.9.1_27 the fallback route
// terminated TLS and needed a per-machine CA; the relay route replaced it and
// needs none, so nothing here creates or signs anything. What is left finds the
// old certificate and takes it out, because a machine that ran an earlier build
// still has a root certificate in its user store and both undo paths (menu 4 and
// menu 5) have to remove it. Delete these only once no installed build can still
// have one.

/// Where an older build kept its CA. Beside the relay's log rather than beside
/// its exe: the relay runs unelevated and cannot write into the directory an
/// administrator installed it into (the same reason the log is there).
pub fn ca_dir() -> PathBuf {
    PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default()).join("AGUnlocker")
}

pub fn ca_cert_path() -> PathBuf {
    ca_dir().join("ca.pem")
}

fn ca_key_path() -> PathBuf {
    ca_dir().join("ca.key")
}

/// The proxy URL that goes into the environment of the processes being routed.
pub fn proxy_url() -> String {
    format!("http://{}:{}", LISTEN_IP, LISTEN_PORT)
}

/// The address the listener holds, as a `SocketAddr`. Both parts are literals in
/// this file, so it cannot fail.
fn listen_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from((LISTEN_IP.parse::<Ipv4Addr>().unwrap(), LISTEN_PORT))
}

/// Whether something accepts connections on the proxy's address right now.
///
/// This is the one precondition for `HTTPS_PROXY` naming this port. The variable
/// is user-wide, so a value pointing at a socket nobody holds does not merely
/// leave Antigravity unrouted - it takes every proxy-aware program on the machine
/// with it, the language server's own OAuth call included (G31). Nothing may set
/// that variable without asking this first.
pub fn listener_answers() -> bool {
    answers_at(listen_addr())
}

/// Waits up to `budget` for the listener to come up. `false` means it did not.
///
/// Callers exist because binding is not instant: `run` retries a port that may be
/// held for a moment by somebody else's ephemeral socket (see `bind_listener`).
pub fn wait_for_listener(budget: Duration) -> bool {
    wait_at(listen_addr(), budget)
}

/// The two above, with the address given: the fixed port is what the product
/// asks about, and a test needs one nothing else on the machine can be holding.
///
/// A refused connection means no listener and must read as `false`. Spelled out
/// because the version this replaces answered `true` on its own parse failure, so
/// a mistake there would have hidden a dead proxy rather than reported one.
fn answers_at(addr: std::net::SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
}

fn wait_at(addr: std::net::SocketAddr, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if answers_at(addr) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(POLL_FOR_LISTENER);
    }
}

const POLL_FOR_LISTENER: Duration = Duration::from_millis(250);

/// Takes the CA back out of the trust store and deletes its key.
///
/// Deliberately best-effort and idempotent: revert must not stop half way and
/// leave a root certificate behind, so every step runs even if an earlier one
/// found nothing to do.
pub fn untrust_ca() {
    let mut cmd = std::process::Command::new("certutil");
    cmd.args(["-user", "-delstore", "Root", CA_NAME]);
    no_window(&mut cmd).output().ok();
    fs::remove_file(ca_cert_path()).ok();
    fs::remove_file(ca_key_path()).ok();
}

// There used to be a `ca_is_trusted()` here, to decide whether `untrust_ca` had
// anything to do. It was the gate on the revert, and the gate is what let a
// machine come out of a revert with its proxy variables still set. `untrust_ca`
// is idempotent and costs one `certutil` call, so asking first bought nothing
// and could only ever skip work that needed doing.

/// The same client configuration, for the resolver's handshake probe.
///
/// Shared deliberately: the probe has to negotiate what the real connection will
/// negotiate, or it measures something the client never does.
pub fn probe_config() -> Arc<ClientConfig> {
    upstream_config()
}

fn upstream_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

/// The two region-gated CloudCode endpoints - the only names that ever need a
/// route other than a plain direct tunnel. Everything else reaches genuine
/// Google unaided, so it is never sent through anybody's proxy.
///
/// Lives here rather than in the private relay module because it is policy, not
/// method: every route has to agree on which hosts it applies to, and a second
/// copy of a list like this drifts.
pub fn is_gate_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "cloudcode-pa.googleapis.com"
        || h == "daily-cloudcode-pa.googleapis.com"
        || h == "generativelanguage.googleapis.com"
        || h == "jetski-webchannel.googleapis.com"
}

/// Sends a gate host through the user's own proxy, when they gave us one and it
/// is currently working. `Err` hands the client back untouched for the next
/// route to try - nothing has been said to it yet.
///
/// Health is judged by the warm loop's probe, not by what happens here, with one
/// exception: a proxy that will not even accept the `CONNECT` is unambiguously
/// down and says so immediately. Everything subtler - accepting tunnels and
/// cutting them at the handshake, which is exactly how the relay failed - is left
/// to the probe, because "bytes moved" is not the same question as "it worked"
/// and reading it that way once already let an outage run.
fn try_own_proxy(mut client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    if port != 443 || !is_gate_host(host) || !upstream::available() {
        return Err(client);
    }
    let Some(up) = upstream::configured() else {
        return Err(client);
    };
    let upstream_sock = match upstream::open(&up, host, port, upstream::LIVE_OPEN_BUDGET) {
        Ok(sock) => sock,
        Err(why) => {
            crate::dns_forwarder::log_proxy(&format!("свой прокси {}: {}", up.display(), why));
            upstream::OWN.health.note(false);
            return Err(client);
        }
    };
    // Committed: from here the client is talking to Google through their proxy.
    if client.write_all(RESP_ESTABLISHED).is_err() {
        return Ok(());
    }
    routes::note_used(routes::Kind::Own);
    crate::dns_forwarder::log_proxy(&format!("свой прокси -> {}", host));
    splice(client, upstream_sock);
    Ok(())
}

/// Longest the direct route may spend connecting to a gate host before the next
/// route deserves the client. Spread across every address the name resolves to,
/// so a black-holing first address does not spend it all (G7).
const DIRECT_OPEN_BUDGET: Duration = Duration::from_secs(10);
/// The same for a host that has no other route: long enough for a slow edge,
/// short enough that an abandoned socket does not hold a thread for Windows'
/// own 21 s per address.
const TUNNEL_OPEN_BUDGET: Duration = Duration::from_secs(10);

/// The direct route for a gate host: a plain tunnel to whatever the system
/// resolver - i.e. the NRPT rule, i.e. our own relay - says the name is.
///
/// A route like the others, not the floor under them: it fails *before* the
/// `200` when nothing answers inside its budget, and hands the client back for
/// the next route (I35). The old shape connected with the OS default timeout
/// and answered 502, which cost a client 21 s per dead address and then nothing.
fn try_direct(mut client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    let upstream = match connect_bounded(host, port, DIRECT_OPEN_BUDGET) {
        Ok(sock) => sock,
        Err(why) => {
            crate::dns_forwarder::log_proxy(&format!("напрямую {}: {}", host, why));
            return Err(client);
        }
    };
    if client.write_all(RESP_ESTABLISHED).is_err() {
        return Ok(());
    }
    routes::note_used(routes::Kind::Direct);
    splice(client, upstream);
    Ok(())
}

/// Connects to `host:port` inside `budget`, walking every address the name
/// resolves to and giving each a slice rather than the remainder.
fn connect_bounded(host: &str, port: u16, budget: Duration) -> Result<TcpStream, String> {
    let deadline = Instant::now() + budget;
    let mut addrs: Vec<SocketAddr> = Vec::new();

    // On macOS / Linux there are no Windows NRPT rules to redirect DNS for gate hosts.
    // Use our unblocking resolvers to get the substituted proxy IP for gate hosts.
    #[cfg(not(target_os = "windows"))]
    if is_gate_host(host) {
        if let Some((v4_addrs, _, _)) = crate::resolvers::resolve_a_best(host, 0) {
            addrs = v4_addrs
                .into_iter()
                .map(|ip| SocketAddr::from((ip, port)))
                .collect();
        }
    }

    if addrs.is_empty() {
        addrs = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("имя не разрешается: {}", e))?
            .collect();
    }
    if addrs.is_empty() {
        return Err("имя не разрешается".to_string());
    }
    // IPv4 first. Every substituted address is IPv4 - the providers' proxies
    // are - while an AAAA answer for the same name is genuine Google, and on a
    // machine with global IPv6 the resolver may list it first. Connecting there
    // would reach the gate from the blocked region with the DNS layer "working".
    addrs.sort_by_key(|a| a.is_ipv6());
    // A slice per address, at least a second each, so three addresses get a
    // real attempt inside a four-second budget.
    let slice = (budget / addrs.len().max(1) as u32).max(Duration::from_secs(1));
    let mut last = "время вышло".to_string();
    for addr in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, slice.min(left)) {
            Ok(sock) => return Ok(sock),
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("не подключиться: {}", last))
}

/// Whether `kind` is worth offering the next gate connection to. The route
/// table orders; this says who is in the running at all.
pub fn route_usable(kind: routes::Kind, host: &str) -> bool {
    match kind {
        routes::Kind::Own => upstream::available() && !routes::is_penalised(routes::Kind::Own),
        routes::Kind::Exits => exits_available(),
        routes::Kind::Relay => relay_usable(),
        routes::Kind::Direct => direct_usable(host),
    }
}

/// The direct tunnel reaches something useful when the relay last answered the
/// name with a substituted address, or when the client is inside a tunnel and
/// the tunnel decides (D13) - and in neither case while a region 400 just came
/// through it. An unanswered name gets the benefit of the doubt, as the rules
/// do (S37): a needless hop costs one connection, a missing route costs every
/// request.
fn direct_usable(host: &str) -> bool {
    if routes::is_penalised(routes::Kind::Direct) {
        return false;
    }
    if crate::resolvers::vpn_is_active() {
        return true;
    }
    !matches!(
        crate::resolvers::served_verdict(host),
        Some(crate::resolvers::Verdict::Passthrough) | Some(crate::resolvers::Verdict::Sibling)
    )
}

#[cfg(exits)]
fn exits_available() -> bool {
    exits::available()
}

#[cfg(not(exits))]
fn exits_available() -> bool {
    false
}

#[cfg(relay)]
fn relay_usable() -> bool {
    relay::relay_available() && !relay::relay_is_benched()
}

#[cfg(not(relay))]
fn relay_usable() -> bool {
    // The stub says false; asked through it so a public build keeps the one
    // symbol the rest of the crate is written against.
    relay_available()
}

/// The host the direct-route probe asks for: the one the IDE actually uses, so
/// the row measures the path a request takes.
const DIRECT_PROBE_HOST: &str = "daily-cloudcode-pa.googleapis.com";
/// Longest the probe's own request may take once connected.
const DIRECT_PROBE_BUDGET: Duration = Duration::from_secs(15);

/// Times the direct route the way the other routes are timed: connect, TLS to
/// Google, one small request, an answer. Feeds the `Direct` row of the route
/// table; run on the warm loop, never with a client's request (I38).
///
/// Resolves through the relay's own pool, so it measures the address a client
/// would be handed - a substituted proxy normally, the tunnel's genuine Google
/// while the relay stands down for a VPN.
pub fn probe_direct(if_index: u32) {
    let started = Instant::now();
    match probe_direct_once(if_index) {
        Ok(()) => routes::record(routes::Kind::Direct, started.elapsed()),
        Err(why) => {
            routes::record_failure(routes::Kind::Direct);
            crate::dns_forwarder::log_proxy(&format!("напрямую не отвечает: {}", why));
        }
    }
}

fn probe_direct_once(if_index: u32) -> Result<(), String> {
    let (addrs, _, _) = crate::resolvers::resolve_a_best(DIRECT_PROBE_HOST, if_index)
        .ok_or_else(|| "имя не разрешилось".to_string())?;
    let deadline = Instant::now() + DIRECT_OPEN_BUDGET;
    let slice = (DIRECT_OPEN_BUDGET / addrs.len().max(1) as u32).max(Duration::from_secs(1));
    let mut sock = None;
    for a in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        if let Ok(s) =
            TcpStream::connect_timeout(&std::net::SocketAddr::from((a, 443)), slice.min(left))
        {
            sock = Some(s);
            break;
        }
    }
    let mut sock = sock.ok_or_else(|| "не подключиться".to_string())?;
    sock.set_read_timeout(Some(DIRECT_PROBE_BUDGET)).ok();
    sock.set_write_timeout(Some(DIRECT_PROBE_BUDGET)).ok();
    let name =
        rustls::pki_types::ServerName::try_from(DIRECT_PROBE_HOST).map_err(|e| e.to_string())?;
    let mut tls = ClientConnection::new(probe_config(), name).map_err(|e| e.to_string())?;
    let mut stream = rustls::Stream::new(&mut tls, &mut sock);
    let req = format!(
        "GET /v1internal:probe HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        DIRECT_PROBE_HOST
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("рукопожатие: {}", e))?;
    let mut buf = [0u8; 64];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("ответа нет: {}", e))?;
    if n > 0 && buf.starts_with(b"HTTP/") {
        Ok(())
    } else {
        Err("ответ не похож на HTTP".to_string())
    }
}

/// `CONNECT host:port HTTP/1.1` and the headers after it, up to the blank line.
///
/// Returns the target. Anything that is not a CONNECT is refused rather than
/// guessed at: this proxy exists for one client and one method.
fn read_connect(sock: &mut TcpStream) -> Request {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8 * 1024 {
            return Request::Malformed;
        }
        match sock.read(&mut byte) {
            // The client hung up, or never spoke inside REQUEST_IDLE. Neither is
            // a request to refuse, and answering one is worse than silence: a
            // pooling client - Node opens proxy sockets before it has anything
            // to send - would find a status line where its CONNECT response
            // belongs. That was the whole of "Proxy connection ended before
            // receiving CONNECT response": a 10 s timeout writing 405 into a
            // socket the client had not used yet.
            Ok(0) | Err(_) => return Request::Gone,
            Ok(_) => head.push(byte[0]),
        }
    }
    match parse_connect(&String::from_utf8_lossy(&head)) {
        Some((host, port)) => Request::Connect(host, port),
        None => Request::Malformed,
    }
}

/// What arrived on a freshly accepted socket.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Connect(String, u16),
    /// Something that is not a CONNECT. Answered, because the client is there.
    Malformed,
    /// Nothing arrived. Closed in silence, because there is nobody to answer.
    Gone,
}

fn parse_connect(head: &str) -> Option<(String, u16)> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let target = parts.next()?;
    let (host, port) = target.rsplit_once(':')?;
    // An IPv6 literal is bracketed; strip them so the name is usable as an SNI.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

#[cfg_attr(not(relay), allow(dead_code))]
fn would_block(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

/// Raw byte tunnel, for everything this proxy has no business decrypting.
fn tunnel(mut client: TcpStream, host: &str, port: u16) {
    let Ok(upstream) = connect_bounded(host, port, TUNNEL_OPEN_BUDGET) else {
        // The client is still waiting for a status line; without one it sits
        // there until it gives up, which reads as "the proxy hung" rather than
        // "that host is unreachable".
        client.write_all(RESP_BAD_GATEWAY).ok();
        return;
    };
    if client.write_all(RESP_ESTABLISHED).is_err() {
        return;
    }
    splice(client, upstream);
}

/// Moves raw bytes between two sockets until one of them ends.
///
/// Split out of `tunnel` because a tunnel through the user's proxy is the same
/// splice with a socket that was opened differently - and a second copy of the
/// teardown discipline below would be a second place to get it wrong.
fn splice(mut client: TcpStream, mut upstream: TcpStream) {
    // A tunnel sets its own idle policy, whatever the two sockets were carrying
    // when they got here - the accept loop's silence limit on one, a CONNECT
    // reply budget on the other. Neither is a tunnel policy, and a stray one is
    // not harmless: `upstream::open`'s ten-second reply budget rode into the
    // splice and killed every pooled connection at 10.3 s of silence. `io::copy`
    // reads a timeout as the end of the stream, so the tunnel simply closed; the
    // language server saw its pooled connection die on the next write and
    // reconnected, over and over - 35 tunnels in 25 seconds, which is what a long
    // hang on "Authenticating" looks like from this side. Only the relay route
    // escaped it, because it pumps its own sockets (I37).
    //
    // None, rather than a reaper: expiring an idle tunnel is a real policy with a
    // real risk of cutting a live stream (P4), and it belongs with the payload
    // clock in the relay's pump, not smuggled in as a socket option.
    for s in [&client, &upstream] {
        s.set_read_timeout(None).ok();
        s.set_write_timeout(None).ok();
    }
    let Ok(mut client_w) = client.try_clone() else {
        return;
    };
    let Ok(mut upstream_w) = upstream.try_clone() else {
        return;
    };
    // Raw bytes need no shared TLS state, so the simple two-thread shape works
    // here even though the intercepted path cannot use it.
    let up = thread::spawn(move || io::copy(&mut client, &mut upstream_w));
    io::copy(&mut upstream, &mut client_w).ok();
    // FIN first, and only then the full shutdown that releases the thread still
    // reading from this socket. Going straight to `Both` closes it with whatever
    // the client had already sent still unread, and Windows answers unread bytes
    // with RST - which a pooling client reports as "An existing connection was
    // forcibly closed by the remote host" instead of quietly reconnecting.
    client_w.shutdown(std::net::Shutdown::Write).ok();
    thread::sleep(PUMP_MAX_SLEEP);
    client_w.shutdown(std::net::Shutdown::Both).ok();
    up.join().ok();
}

/// Longest one candidate address may take - connect *and* TLS together - before
/// the next one deserves the rest of the budget.
///
/// Sized so a pool of several is actually walked: the relay's whole-route budget
/// is 8 s, and at this slice three addresses get a real attempt instead of one
/// black-holing address consuming almost all of it.
#[cfg_attr(not(relay), allow(dead_code))]
pub const UPSTREAM_PROBE_BUDGET: Duration = Duration::from_millis(2500);

/// Drives `conn` to a completed handshake over `sock` before `deadline`, or gives
/// up.
///
/// Blocking with timeouts on purpose: this runs before the client has been told
/// anything, so waiting here is honest, and the alternative - discovering a dead
/// upstream halfway through a tunnel - has no way back.
#[cfg_attr(not(relay), allow(dead_code))]
fn handshake(
    conn: &mut ClientConnection,
    sock: &mut TcpStream,
    deadline: Instant,
) -> Result<(), String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("таймаут".to_string());
    }
    sock.set_nonblocking(false).ok();
    // The socket timeouts come from the caller's deadline, not from a constant of
    // our own. A fixed six seconds here is not a local decision: it is spent out of
    // whatever budget the caller is holding, and one address that completes TCP and
    // then black-holes TLS ate almost all of the relay pool's eight seconds, so the
    // address that actually worked was never reached (G7, one layer up).
    sock.set_read_timeout(Some(left)).ok();
    sock.set_write_timeout(Some(left)).ok();
    while conn.is_handshaking() {
        if Instant::now() >= deadline {
            return Err("таймаут".to_string());
        }
        if conn.wants_write() {
            conn.write_tls(sock).map_err(|e| e.to_string())?;
        }
        if conn.wants_read() {
            match conn.read_tls(sock) {
                Ok(0) => return Err("апстрим закрыл соединение".to_string()),
                Ok(_) => conn.process_new_packets().map_err(|e| e.to_string())?,
                Err(e) => return Err(e.to_string()),
            };
        }
    }
    Ok(())
}

/// Tries the fast relay route for a gate host, else hands the client straight
/// back so `serve` uses the direct tunnel. The only place the private relay
/// module is touched: a build compiled from the public source has no such module
/// (`cfg(not(relay))`) and always falls through to the DNS route.
#[cfg(relay)]
fn try_relay_route(client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    if port == 443 && relay::relay_available() && is_gate_host(host) {
        relay::relay_tunnel(client, host, port)
    } else {
        Err(client)
    }
}

#[cfg(not(relay))]
fn try_relay_route(client: TcpStream, _host: &str, _port: u16) -> Result<(), TcpStream> {
    Err(client)
}

/// Tries the built-in exits for a gate host, else hands the client straight back.
/// The only place the private exits module is touched; a build from the public
/// source has no such module and falls through to the relay and the DNS route.
#[cfg(exits)]
fn try_builtin_exit(client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    if port == 443 && is_gate_host(host) && exits::available() {
        exits::tunnel(client, host, port)
    } else {
        Err(client)
    }
}

#[cfg(not(exits))]
fn try_builtin_exit(client: TcpStream, _host: &str, _port: u16) -> Result<(), TcpStream> {
    Err(client)
}

fn serve(mut client: TcpStream, _if_index: u32) {
    client.set_read_timeout(Some(REQUEST_IDLE)).ok();
    let (host, port) = match read_connect(&mut client) {
        Request::Connect(host, port) => (host, port),
        Request::Malformed => {
            client.write_all(RESP_NOT_ALLOWED).ok();
            return;
        }
        Request::Gone => return,
    };

    // Four routes for a gate host, each handing the client back untouched if it
    // cannot serve it, in the order the route table puts them (routes.rs):
    //
    //   - the user's own proxy, when they gave us one, always first. They typed
    //     it in by hand, it is theirs rather than a third party we chose for
    //     them, and silently overriding what somebody configured is not a speed
    //     optimisation.
    //   - the rest by measured speed: a plain direct tunnel to the address the
    //     DNS layer substituted (0.28 s when last measured), a built-in exit -
    //     somebody else's CONNECT proxy in a permitted region, which lifts the
    //     gate outright (S25) - and the relay, cert-free but revocable.
    //
    // The table, not a fixed ladder, because the ladder was a guess about speed
    // that the measurements contradicted (kb/rivals.md Fact 3); and a route
    // that just carried a region 400 goes to the back (ls_log). Nothing is
    // decided before `200 Connection Established` goes out, so falling from
    // one to the next costs the client nothing (I35), and a tunnel already
    // open keeps its route whatever the table says next.
    if port == 443 && is_gate_host(&host) {
        let mut client = client;
        let mut tried_direct = false;
        for kind in routes::order(|k| route_usable(k, &host)) {
            let attempt = match kind {
                routes::Kind::Own => try_own_proxy(client, &host, port),
                routes::Kind::Exits => try_builtin_exit(client, &host, port),
                routes::Kind::Relay => try_relay_route(client, &host, port),
                routes::Kind::Direct => {
                    tried_direct = true;
                    try_direct(client, &host, port)
                }
            };
            client = match attempt {
                Ok(()) => return,
                Err(returned) => returned,
            };
        }
        // Every route refused. The plain tunnel is the last resort when the
        // table left it out - a genuine Google address that answers 400 is
        // still better than a client that gets no status line at all. When the
        // direct route was already tried and found nothing, trying the same
        // name again only delays the 502 by another budget.
        if tried_direct {
            client.write_all(RESP_BAD_GATEWAY).ok();
            return;
        }
        client.set_read_timeout(None).ok();
        tunnel(client, &host, port);
        return;
    }

    // Everything that is not a gate host is a plain direct tunnel - including
    // every other `*.googleapis.com` (e.g. `storage.googleapis.com`, which the
    // Desktop app loads at startup). The proxy terminates no TLS and holds no CA:
    // MITMing those hosts with a certificate no client trusts is exactly what
    // black-screened the Desktop app with `BadCertificate`. The gate hosts are
    // reached cert-free through the routes above; nothing here needs a CA.
    client.set_read_timeout(None).ok();
    tunnel(client, &host, port);
}

/// How long a taken port is given to come free, and how often it is retried.
/// Fifteen seconds: long enough for somebody's ephemeral socket to close, short
/// enough that a permanently reserved port is reported while the user is still
/// looking at the menu.
const BIND_TRIES: u32 = 6;
const BIND_RETRY_WAIT: Duration = Duration::from_secs(3);

/// Takes the fixed port, retrying while something else holds it.
///
/// 53129 is inside Windows' **default dynamic port range** (49152-65535), so it
/// can be sitting in somebody's ephemeral client socket at the moment the relay
/// starts - a race that resolves itself in seconds. It can also be inside a range
/// Hyper-V/WSL/Docker has reserved (`netsh int ipv4 show excludedportrange`),
/// which never resolves; the retries cost 15 s and the log line then says which
/// of the two it was. Either way the caller must not claim the route: without a
/// listener the `HTTPS_PROXY` naming it breaks the machine's proxy-aware traffic
/// (G31), which is why the variable is only set once this has succeeded.
fn bind_listener() -> Result<TcpListener, String> {
    let mut last = String::new();
    for attempt in 0..BIND_TRIES {
        match TcpListener::bind(listen_addr()) {
            Ok(listener) => {
                if attempt > 0 {
                    crate::dns_forwarder::log_proxy(&format!(
                        "порт {} освободился с {}-й попытки",
                        LISTEN_PORT,
                        attempt + 1
                    ));
                }
                return Ok(listener);
            }
            Err(e) => {
                last = e.to_string();
                if attempt + 1 < BIND_TRIES {
                    thread::sleep(BIND_RETRY_WAIT);
                }
            }
        }
    }
    Err(format!(
        "не занять {}:{} — {}",
        LISTEN_IP, LISTEN_PORT, last
    ))
}

/// Runs the proxy until the process ends. Never returns while the socket holds.
pub fn run(if_index: u32) -> Result<(), String> {
    let listener = bind_listener()?;
    // Costs a loopback socket and nothing else: no key is generated, nothing is
    // put in a trust store, and a client that never points at this port never
    // notices it is here.

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        thread::spawn(move || serve(stream, if_index));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The listener check must answer about the socket, and a refused connection
    /// must read as "no listener".
    ///
    /// This is the gate in front of `HTTPS_PROXY` (G31, I53). The helper it
    /// replaces returned `true` when it could not parse its own URL, i.e. it
    /// reported a dead proxy as a live one - the exact direction of error that
    /// leaves a user-wide variable pointing at nothing.
    #[test]
    fn a_socket_nobody_holds_reads_as_no_listener() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral port");
        let addr = listener.local_addr().expect("addr");

        assert!(answers_at(addr), "a bound port must answer");
        assert!(
            wait_at(addr, Duration::from_secs(1)),
            "waiting on a bound port must return at once"
        );

        drop(listener);
        assert!(!answers_at(addr), "a closed port must not answer");
    }

    /// And it must keep looking for the whole budget rather than deciding on one
    /// probe: the port can be held for a few seconds by somebody's ephemeral
    /// socket while `bind_listener` retries it.
    #[test]
    fn waiting_for_a_listener_that_never_comes_costs_the_budget_and_says_no() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral port");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        let budget = Duration::from_millis(600);
        let started = Instant::now();
        assert!(!wait_at(addr, budget));
        assert!(
            started.elapsed() >= budget,
            "gave up after {:?}, before the budget was spent",
            started.elapsed()
        );
    }

    /// A status line that lost its carriage returns is still valid Rust and
    /// still compiles - it just produces a response no HTTP client accepts.
    /// Written as raw byte values so no tool can normalise the test itself.
    #[test]
    fn status_lines_are_crlf_terminated() {
        for line in [RESP_ESTABLISHED, RESP_BAD_GATEWAY, RESP_NOT_ALLOWED] {
            assert_eq!(&line[line.len() - 4..], &[13u8, 10, 13, 10], "{:?}", line);
            assert!(!line[..line.len() - 4].contains(&10u8), "{:?}", line);
        }
    }

    /// A tunnel must not be closed by a budget that was only ever meant to bound
    /// the CONNECT handshake.
    ///
    /// The regression this pins: `upstream::open` left its ten-second reply budget
    /// on the socket it returned, `splice` handed that socket to `io::copy`, and a
    /// timeout reads as end-of-stream - so every tunnel through the user's own
    /// proxy or a built-in exit died at 10.3 s of silence. A pooling client
    /// reconnects on the failed reuse, which showed up as a long hang on
    /// "Authenticating" and 35 tunnels in 25 seconds in the log.
    ///
    /// Sixteen seconds of silence, comfortably past the old ten, then the tunnel
    /// is used - a live client would fail here, not at the handshake.
    ///
    ///     cargo test an_idle_tunnel_outlives_the_connect_budget -- --ignored --nocapture
    #[test]
    #[ignore = "holds a tunnel open for 16 s against a real route; needs a live network"]
    fn an_idle_tunnel_outlives_the_connect_budget() {
        use rustls::pki_types::ServerName;
        use rustls::ClientConnection;
        use std::net::TcpListener;

        const HOST: &str = "daily-cloudcode-pa.googleapis.com";
        const IDLE: Duration = Duration::from_secs(16);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accepted");
            serve(sock, 0);
        });

        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(
                format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes(),
            )
            .expect("sent CONNECT");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(client.read(&mut byte).expect("reply"), 1, "proxy hung up");
            head.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&head).contains(" 200"));

        let name = ServerName::try_from(HOST).expect("name");
        let mut tls = ClientConnection::new(probe_config(), name).expect("tls");
        let mut stream = rustls::Stream::new(&mut tls, &mut client);
        // Complete the handshake before going quiet, so the silence is measured on
        // an established tunnel - which is the state a pooled connection sits in.
        stream.flush().ok();

        thread::sleep(IDLE);

        stream
            .write_all(
                format!(
                    "GET /v1internal:probe HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("the tunnel was closed under an idle client");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).expect("no answer after idling");
        assert!(
            buf[..n].starts_with(b"HTTP/"),
            "not an HTTP answer: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
        println!(
            "tunnel survived {} s idle and still carried a request",
            IDLE.as_secs()
        );
    }

    #[test]
    fn reads_the_connect_target() {
        assert_eq!(
            parse_connect(
                "CONNECT jetski-webchannel.googleapis.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"
            ),
            Some(("jetski-webchannel.googleapis.com".to_string(), 443))
        );
        assert_eq!(
            parse_connect("connect example.com:8443 HTTP/1.1\r\n\r\n"),
            Some(("example.com".to_string(), 8443))
        );
        assert_eq!(
            parse_connect("CONNECT [::1]:443 HTTP/1.1\r\n\r\n"),
            Some(("::1".to_string(), 443))
        );
    }

    /// The bug the IDE actually hit. A client that opens a proxy socket and has
    /// not spoken yet must be closed in silence: answering it puts a status line
    /// where its CONNECT response belongs, and the client reports only "Proxy
    /// connection ended before receiving CONNECT response".
    #[test]
    fn a_socket_that_says_nothing_is_closed_without_an_answer() {
        use std::net::TcpListener;

        fn ask(send: Option<&'static [u8]>) -> Request {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            let writer = thread::spawn(move || {
                let mut c = TcpStream::connect(addr).unwrap();
                match send {
                    Some(bytes) => {
                        c.write_all(bytes).unwrap();
                        // Held open so the read cannot end on the socket closing
                        // instead of on the request being complete.
                        thread::sleep(Duration::from_millis(200));
                    }
                    None => drop(c),
                }
            });
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let got = read_connect(&mut sock);
            writer.join().ok();
            got
        }

        assert_eq!(ask(None), Request::Gone);
        assert_eq!(
            ask(Some(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
            Request::Malformed
        );
        assert_eq!(
            ask(Some(
                b"CONNECT a.googleapis.com:443 HTTP/1.1\r\nHost: a\r\n\r\n"
            )),
            Request::Connect("a.googleapis.com".to_string(), 443)
        );
    }

    /// Anything that is not a CONNECT is refused rather than guessed at.
    #[test]
    fn a_non_connect_request_is_refused() {
        assert_eq!(parse_connect("GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_connect("CONNECT nohost HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_connect("CONNECT :443 HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_connect(""), None);
    }

    #[test]
    fn the_proxy_url_is_loopback() {
        assert!(proxy_url().starts_with("http://127.0.0.1:"));
    }
}
