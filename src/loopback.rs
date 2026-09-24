//! The gate hosts, answered with a loopback address and carried from there.
//!
//! Until 2.14.0_1 the only way the route table ever saw a gate connection was
//! the private proxy variable (`AG_LS_PROXY`, S42) - and an environment
//! variable reaches a process only when it starts. A user who switched the
//! bypass on while Antigravity was open (the ordinary order: patch, launch,
//! then the 400, then this window) had a language server that never asked our
//! proxy for anything, so none of the adaptive part touched their traffic: it
//! dialled Google itself, from wherever the routing table sent it, and the
//! window described a proxy nobody used (G50).
//!
//! DNS reaches a running process on its very next lookup. So while this is up,
//! the relay answers each gate host with an address of its own here, and a
//! connection to it is carried by exactly the route table a `CONNECT` through
//! the proxy variable is: the client's connection never leaves the machine,
//! which also means no VPN can catch it (N25 from the client's side).
//!
//! No TLS is terminated (I27). Each host gets its own loopback address, so the
//! host is known from the address the client dialled and not one byte of its
//! handshake has to be read: the listener hands the socket to the local proxy
//! as a `CONNECT` and splices. The client's TLS goes to Google untouched, and its
//! certificate check is against Google's own certificate.
//!
//! If the listeners cannot be bound - something else holds one of the
//! addresses - the relay simply keeps answering with the substituted addresses
//! it always did.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// One loopback address per gate host. `127.65.71.x` - "A", "G" - to stay clear
/// of `127.0.0.1` and of the relay's own `127.0.0.53`.
pub const HOSTS: [(&str, Ipv4Addr); 4] = [
    ("cloudcode-pa.googleapis.com", Ipv4Addr::new(127, 65, 71, 1)),
    (
        "daily-cloudcode-pa.googleapis.com",
        Ipv4Addr::new(127, 65, 71, 2),
    ),
    (
        "generativelanguage.googleapis.com",
        Ipv4Addr::new(127, 65, 71, 3),
    ),
    ("aistudio.google.com", Ipv4Addr::new(127, 65, 71, 4)),
];

const PORT: u16 = 443;

/// How long a client's loopback answer may live in its cache. Short, because it
/// is also how long a client keeps dialling a dead listener if the relay stops:
/// after that Windows asks the rule's next nameserver and gets the substituted
/// address the old way.
pub const ANSWER_TTL: u32 = 30;

static BOUND: AtomicBool = AtomicBool::new(false);

/// Connections accepted here that have not had their `200` yet. A cap, not a
/// tuning knob: any loop that runs back through this door - a proxy or VPN
/// client resolving a gate host through the system resolver and dialling what
/// it got - shows up as this number climbing without bound, and the cap is what
/// breaks it. Ordinary use is a handful; the CLI opens about ten at once.
static OPENING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const MAX_OPENING: usize = 64;

/// The address a client should be given for `host`, when the listeners are up
/// and the local proxy is wanted. `None` means "answer the old way".
pub fn answer_for(host: &str) -> Option<Ipv4Addr> {
    if !active() {
        return None;
    }
    let host = host.trim_end_matches('.');
    HOSTS
        .iter()
        .find(|(h, _)| h.eq_ignore_ascii_case(host))
        .map(|(_, ip)| *ip)
}

/// Whether gate connections are being taken here right now.
///
/// Tied to the «Локальный прокси» switch: a user who turned the local proxy off
/// asked for Antigravity not to go through it, and this is the same proxy by a
/// different door.
pub fn active() -> bool {
    BOUND.load(Ordering::Relaxed) && crate::proxy::bound() && crate::settings::local_proxy_wanted()
}

/// Binds every listener, then serves them until the process ends. While they
/// cannot be bound it says why (`gate::set_blocker`, the window turns it into
/// what to do - P53) and tries again every `proxy::REBIND_EVERY`, so the door
/// opens by itself once the user has closed the program on `:443` or added the
/// antivirus exception. Returns only if the listeners stop.
pub fn run() -> Result<(), String> {
    let mut said: Option<crate::gate::Blocker> = None;
    let listeners = loop {
        match bind_all() {
            Ok(listeners) => {
                if said.is_some() {
                    crate::dns_forwarder::log_proxy("локальные адреса гейт-хостов заняты");
                    crate::gate::set_blocker("door", None);
                }
                break listeners;
            }
            Err(blocker) => {
                if said.as_ref() != Some(&blocker) {
                    crate::dns_forwarder::log_proxy(&format!(
                        "локальные адреса гейт-хостов не заняты: не занять {}: {} ({}{})",
                        blocker.addr,
                        blocker.error,
                        blocker.cause,
                        if blocker.by.is_empty() {
                            String::new()
                        } else {
                            format!(": {}", blocker.by)
                        }
                    ));
                    said = Some(blocker.clone());
                }
                // Every try, so the record never goes stale under the card.
                crate::gate::set_blocker("door", Some(blocker));
                thread::sleep(crate::proxy::REBIND_EVERY);
            }
        }
    };
    BOUND.store(true, Ordering::Relaxed);
    let mut handles = Vec::new();
    for (host, listener) in listeners {
        handles.push(thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || hop(stream, host));
            }
        }));
    }
    for h in handles {
        h.join().ok();
    }
    BOUND.store(false, Ordering::Relaxed);
    Err("слушатели остановились".to_string())
}

/// Every listener or none: a door open for one gate host and shut for the other
/// would send half of Antigravity's calls somewhere else.
fn bind_all() -> Result<Vec<(&'static str, TcpListener)>, crate::gate::Blocker> {
    let mut listeners = Vec::with_capacity(HOSTS.len());
    for (host, ip) in HOSTS {
        listeners.push((host, bind(ip)?));
    }
    Ok(listeners)
}

/// A few tries, because a port held for a moment at logon frees itself.
fn bind(ip: Ipv4Addr) -> Result<TcpListener, crate::gate::Blocker> {
    let addr = SocketAddr::from((ip, PORT));
    let mut last = None;
    for attempt in 0..3 {
        match TcpListener::bind(addr) {
            Ok(l) => return Ok(l),
            Err(e) => {
                last = Some(e);
                if attempt < 2 {
                    thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }
    let err = last.expect("three attempts were made");
    Err(crate::portcheck::diagnose(addr, &err).blocker("door", addr, &err))
}

/// Longest the local proxy may take to pick a route and say `200`. Its routes
/// fail inside budgets of their own (4 s direct, 8 s relay), and walking all of
/// them in the worst case is what this has to cover.
const ROUTE_BUDGET: Duration = Duration::from_secs(30);

/// Carries one client connection: asks the local proxy for a tunnel to `host`,
/// then moves bytes. The client's first bytes - its TLS ClientHello - wait in
/// the socket buffer meanwhile and go through with everything else.
fn hop(client: TcpStream, host: &'static str) {
    if OPENING.fetch_add(1, Ordering::SeqCst) >= MAX_OPENING {
        OPENING.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let up = open_hop(host);
    OPENING.fetch_sub(1, Ordering::SeqCst);
    if let Some(up) = up {
        crate::proxy::splice(client, up);
    }
}

/// Asks the local proxy for a tunnel to `host`; `None` when it refused.
fn open_hop(host: &'static str) -> Option<TcpStream> {
    let mut up =
        TcpStream::connect_timeout(&crate::proxy::listen_addr(), Duration::from_secs(3)).ok()?;
    up.set_read_timeout(Some(ROUTE_BUDGET)).ok();
    up.write_all(
        format!("CONNECT {host}:{PORT} HTTP/1.1\r\nHost: {host}:{PORT}\r\n\r\n").as_bytes(),
    )
    .ok()?;
    let mut head = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 4096 {
            return None;
        }
        match up.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    // Every route refused: closing the client's connection is the answer. It
    // retries, and its next connection is offered to the table again.
    status_is_200(&head).then_some(up)
}

fn status_is_200(head: &[u8]) -> bool {
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let text = String::from_utf8_lossy(line);
    text.split_whitespace().nth(1) == Some("200")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_gate_host_has_its_own_loopback_address() {
        for (host, ip) in HOSTS {
            assert!(ip.is_loopback(), "{host}");
            assert!(
                crate::proxy::is_gate_host(host),
                "{host} is not a gate host"
            );
            assert_ne!(ip, Ipv4Addr::LOCALHOST);
            assert_ne!(ip, Ipv4Addr::new(127, 0, 0, 53), "the relay's own");
        }
        let ips: std::collections::HashSet<_> = HOSTS.iter().map(|(_, ip)| *ip).collect();
        assert_eq!(ips.len(), HOSTS.len(), "all loopback IPs must be unique");
    }

    #[test]
    fn only_a_200_opens_the_tunnel() {
        assert!(status_is_200(
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        ));
        assert!(!status_is_200(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"));
        assert!(!status_is_200(b""));
        assert!(!status_is_200(b"garbage"));
    }

    /// Nothing is answered with a loopback address while the listeners are down,
    /// whatever the name: the relay must fall back to the old answer.
    #[test]
    fn no_listener_no_loopback_answer() {
        if !BOUND.load(Ordering::Relaxed) {
            assert_eq!(answer_for("daily-cloudcode-pa.googleapis.com"), None);
        }
        assert_eq!(answer_for("example.com"), None);
    }
}
