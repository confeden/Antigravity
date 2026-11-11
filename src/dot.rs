//! DNS-over-TLS (RFC 7858) client, for the user's own DNS server.
//!
//! The pool's built-in providers speak UDP:53 or DoH; this exists for the one
//! slot the user fills in by hand («свой DNS», `tls://host`). The exchange is
//! as small as DNS gets: a TLS connection to port 853 and, in each direction, a
//! two-byte length followed by the ordinary DNS message. One connection per
//! query - a user's own server sees a trickle (the relay's answer cache takes
//! the rest), so keeping connections would buy handshakes saved at the price of
//! a pool to get wrong.
//!
//! Pinned to the ISP link while a tunnel holds the default route, like every
//! other resolver query (`net::connect`, P13): a provider that substitutes only
//! for Russian addresses must see the query arrive from one.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

/// What one address gets for connect + TLS + the exchange.
const PER_ADDR_BUDGET: Duration = Duration::from_millis(2500);

/// Largest message accepted: a DNS message on TCP is bounded by its 16-bit
/// length, and anything over a few KiB from a resolver here is not a reply.
const MAX_MESSAGE: usize = 16 * 1024;

fn tls_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // RFC 7858 §3.1: DoT needs no ALPN, and a server that insists on one
        // would not be speaking DoT.
        cfg.alpn_protocols = Vec::new();
        Arc::new(cfg)
    })
    .clone()
}

/// A DNS message framed for TCP: its length, big-endian, then the message.
pub fn framed(wire: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(wire.len()).ok()?;
    let mut out = Vec::with_capacity(wire.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(wire);
    Some(out)
}

/// Asks `host` (the name its certificate has to prove) at each of `ips` on
/// `port`, in order, until one answers. `budget` bounds the lot.
pub fn query(
    host: &str,
    port: u16,
    ips: &[IpAddr],
    wire: &[u8],
    budget: Duration,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + budget;
    let mut last = "нет адресов".to_string();
    for ip in ips {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let slice = PER_ADDR_BUDGET.min(deadline - now);
        match query_one(host, port, *ip, wire, Instant::now() + slice) {
            Ok(reply) => {
                crate::net::note_reached();
                return Ok(reply);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn query_one(
    host: &str,
    port: u16,
    ip: IpAddr,
    wire: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let left = |d: Instant| d.saturating_duration_since(Instant::now());
    let request = framed(wire).ok_or("запрос слишком длинный")?;
    if left(deadline).is_zero() {
        return Err(format!("{}: бюджет истёк до соединения", ip));
    }
    let mut sock = crate::net::connect(
        SocketAddr::new(ip, port),
        left(deadline),
        crate::net::pin_interface(),
    )
    .map_err(|_| format!("{}: нет соединения", ip))?;
    sock.set_nodelay(true).ok();

    let name = ServerName::try_from(host.to_string())
        .map_err(|_| "неверное имя DoT-сервера".to_string())?;
    let mut conn =
        ClientConnection::new(tls_config(), name).map_err(|e| format!("TLS не настроен: {}", e))?;

    // Driven by hand so the budget covers the whole exchange, not each syscall.
    while conn.is_handshaking() {
        let t = left(deadline);
        if t.is_zero() {
            return Err(format!("{}: TLS не уложился в бюджет", ip));
        }
        sock.set_read_timeout(Some(t)).ok();
        sock.set_write_timeout(Some(t)).ok();
        if conn.wants_write() {
            conn.write_tls(&mut sock)
                .map_err(|_| format!("{}: обрыв при handshake", ip))?;
        }
        if conn.is_handshaking() && conn.wants_read() {
            match conn.read_tls(&mut sock) {
                Ok(0) => return Err(format!("{}: сервер закрыл handshake", ip)),
                Ok(_) => {
                    conn.process_new_packets()
                        .map_err(|e| format!("{}: TLS отклонён: {}", ip, e))?;
                }
                Err(_) => return Err(format!("{}: обрыв при handshake", ip)),
            }
        }
    }

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let t = left(deadline);
    if t.is_zero() {
        return Err(format!("{}: бюджет истёк", ip));
    }
    tls.sock.set_read_timeout(Some(t)).ok();
    tls.sock.set_write_timeout(Some(t)).ok();
    tls.write_all(&request)
        .map_err(|_| format!("{}: запрос не ушёл", ip))?;
    tls.flush().ok();

    let mut len = [0u8; 2];
    read_exact_by(&mut tls, &mut len, deadline).map_err(|_| format!("{}: нет ответа", ip))?;
    let n = u16::from_be_bytes(len) as usize;
    if n < 12 || n > MAX_MESSAGE {
        return Err(format!("{}: ответ неверной длины", ip));
    }
    let mut reply = vec![0u8; n];
    read_exact_by(&mut tls, &mut reply, deadline).map_err(|_| format!("{}: ответ оборван", ip))?;
    // Politely, and best-effort: the answer is already in hand.
    conn.send_close_notify();
    conn.write_tls(&mut sock).ok();
    Ok(reply)
}

/// `read_exact` that re-derives the socket timeout from the deadline before each
/// read, so a reply that trickles in cannot overrun the slice.
fn read_exact_by(
    tls: &mut rustls::Stream<'_, ClientConnection, std::net::TcpStream>,
    mut buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !buf.is_empty() {
        let t = deadline.saturating_duration_since(Instant::now());
        if t.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        tls.sock.set_read_timeout(Some(t)).ok();
        match tls.read(buf) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(k) => buf = &mut buf[k..],
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_is_framed_with_its_big_endian_length() {
        let wire = vec![7u8; 300];
        let f = framed(&wire).unwrap();
        assert_eq!(&f[..2], &[1, 44]);
        assert_eq!(&f[2..], &wire[..]);
    }

    #[test]
    fn a_message_longer_than_the_length_field_is_refused() {
        assert!(framed(&vec![0u8; 70_000]).is_none());
    }

    #[test]
    fn no_addresses_is_an_error_not_a_hang() {
        let r = query(
            "example.com",
            853,
            &[],
            &[0; 12],
            Duration::from_millis(100),
        );
        assert!(r.is_err());
    }
}
