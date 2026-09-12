use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

// DNS-over-HTTPS, over a hand-written HTTP/2 client.
//
// Why hand-written. The resolver this exists for answers `505 HTTP Version Not
// Supported` to HTTP/1.1 and offers only `h2` in ALPN - measured on both of its
// addresses. The crate is synchronous and has no HTTP client at all, so the
// alternatives were the `h2` crate (which brings tokio, i.e. an async runtime,
// into a codebase that has none) or the subset of HTTP/2 a DoH exchange
// actually uses. It is a small subset, because one DoH query is one request and
// one response on a fresh connection:
//
// - no multiplexing: a single stream, id 1, opened and closed immediately;
// - no flow control: a DNS reply is a few hundred bytes, far inside the default
//   65 535-byte window, so no WINDOW_UPDATE is ever needed;
// - no dynamic HPACK table: the request is five fixed headers, sent as literals;
//   and the *response* headers are never decoded at all. Only DATA frames on
//   stream 1 are read. The status code is not needed - an error page does not
//   parse as a DNS message, and every caller already handles "no usable reply".
//
// What is deliberately NOT skipped: SETTINGS and PING are acknowledged (a server
// is entitled to drop a connection that ignores them), and GOAWAY/RST_STREAM are
// reported rather than waited out.
//
// KNOWN GAP: this connection is not pinned to the ISP interface. Every UDP
// resolver query is (`dns_client::query_raw_via` + IP_UNICAST_IF, I4/N4) so a VPN
// cannot change the geolocation the provider sees. IP_UNICAST_IF has to be set
// *before* connect, which a `TcpStream::connect_timeout` cannot do, so pinning
// this needs a raw socket. Until then a DoH provider is queried over the default
// route: correct with no VPN, and under a VPN it sees the tunnel's exit like any
// other traffic. Tracked as P13.

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

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// A DNS reply that does not fit this is not a reply we would use.
const MAX_BODY: usize = 64 * 1024;

fn tls_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
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
        Arc::new(cfg)
    })
    .clone()
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
    // Literal with incremental indexing, name from the static table.
    hpack_int(&mut h, 1, 6, 0x40); // :authority
    hpack_string(&mut h, host.as_bytes());
    hpack_int(&mut h, 4, 6, 0x40); // :path
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
pub fn query(ep: &Endpoint, wire: &[u8], budget: Duration) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + budget;
    let mut last = "нет адресов".to_string();
    let n = ep.addrs.len();
    if n == 0 {
        return Err(last);
    }
    let start = NEXT_ADDR.fetch_add(1, Ordering::Relaxed);
    for idx in walk(n, start) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let addr = ep.addrs[idx];
        let slice = PER_ADDR_BUDGET.min(deadline - now);
        let Ok(ip) = addr.parse::<IpAddr>() else {
            continue;
        };
        match query_one(ep, ip, wire, slice) {
            Ok(reply) => return Ok(reply),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn query_one(ep: &Endpoint, ip: IpAddr, wire: &[u8], budget: Duration) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + budget;

    let mut sock = TcpStream::connect_timeout(&SocketAddr::new(ip, 443), budget)
        .map_err(|_| format!("{}: нет соединения", ip))?;
    sock.set_nodelay(true).ok();

    let server = ServerName::try_from(ep.host.to_string())
        .map_err(|_| "неверное имя DoH-сервера".to_string())?;
    let mut conn = ClientConnection::new(tls_config(), server)
        .map_err(|e| format!("TLS не настроен: {}", e))?;

    // Driven by hand so the budget covers the whole handshake rather than each
    // syscall inside it - the same shape `resolvers::reachable` uses, and for
    // the same reason: an address that completes TCP and stalls in TLS is the
    // failure this has to notice quickly (G23).
    let remaining = |d: Instant| d.saturating_duration_since(Instant::now());
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

    let path = format!("{}?dns={}", ep.path, base64url(wire));
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(PREFACE);
    out.extend_from_slice(&frame(FRAME_SETTINGS, 0, 0, &[]));
    out.extend_from_slice(&frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &request_headers(ep.host, &path),
    ));

    let left = remaining(deadline);
    if left.is_zero() {
        return Err(format!("{}: бюджет истёк до запроса", ip));
    }
    sock.set_read_timeout(Some(left)).ok();
    sock.set_write_timeout(Some(left)).ok();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    // Disambiguated: `ReadWrite` is blanket-implemented for `Read + Write`, so
    // both traits offer these names on a `rustls::Stream`.
    std::io::Write::write_all(&mut tls, &out).map_err(|_| format!("{}: запрос не ушёл", ip))?;
    std::io::Write::flush(&mut tls).ok();

    read_reply(&mut tls, ip, deadline)
}

/// Reads frames until stream 1 ends, collecting its DATA.
fn read_reply(tls: &mut impl ReadWrite, ip: IpAddr, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut body: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        if Instant::now() >= deadline {
            return Err(format!("{}: DoH не ответил в срок", ip));
        }
        let n = tls
            .read(&mut chunk)
            .map_err(|_| format!("{}: обрыв ответа", ip))?;
        if n == 0 {
            return if body.is_empty() {
                Err(format!("{}: пустой ответ", ip))
            } else {
                Ok(body)
            };
        }
        buf.extend_from_slice(&chunk[..n]);

        while buf.len() >= 9 {
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if len > MAX_BODY {
                return Err(format!("{}: кадр длиной {} — не ответ DNS", ip, len));
            }
            if buf.len() < 9 + len {
                break;
            }
            let kind = buf[3];
            let flags = buf[4];
            let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
            let payload: Vec<u8> = buf[9..9 + len].to_vec();
            buf.drain(..9 + len);

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
                FRAME_DATA if stream == 1 => {
                    body.extend_from_slice(&payload);
                    if body.len() > MAX_BODY {
                        return Err(format!("{}: ответ слишком велик", ip));
                    }
                    if flags & FLAG_END_STREAM != 0 {
                        return Ok(body);
                    }
                }
                // A response with no body: nothing to hand back, and saying so
                // beats returning bytes that will fail to parse as DNS.
                FRAME_HEADERS if stream == 1 && flags & FLAG_END_STREAM != 0 => {
                    return if body.is_empty() {
                        Err(format!("{}: ответ без тела", ip))
                    } else {
                        Ok(body)
                    };
                }
                FRAME_RST_STREAM if stream == 1 => {
                    let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    return Err(format!("{}: поток сброшен, код {}", ip, code));
                }
                FRAME_GOAWAY => {
                    let code = payload
                        .get(4..8)
                        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                        .unwrap_or(0);
                    return Err(format!("{}: GOAWAY, код {}", ip, code));
                }
                _ => {}
            }
        }
    }
}

/// Only so `read_reply` can be exercised without a socket.
pub trait ReadWrite {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;
    fn flush(&mut self) -> std::io::Result<()>;
}

impl<T: Read + Write> ReadWrite for T {
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
        assert_eq!(h[2], 0x41, ":authority");
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
    }

    impl ReadWrite for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (self.to_read.len() - self.pos).min(buf.len()).min(7);
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

    fn run(script: Vec<u8>) -> (Result<Vec<u8>, String>, Vec<u8>) {
        let mut s = Scripted {
            to_read: script,
            pos: 0,
            written: Vec::new(),
        };
        let out = read_reply(
            &mut s,
            "127.0.0.1".parse().unwrap(),
            Instant::now() + Duration::from_secs(5),
        );
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
}
