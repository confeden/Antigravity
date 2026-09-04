use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

// A DNS query that is guaranteed to leave through a chosen interface.
//
// The routing table cannot deliver that: a VPN client holds its own /32 for the
// resolver addresses at a metric nothing legal can beat, and its tunnel service
// restores the route as fast as it is deleted. IP_UNICAST_IF names the outgoing
// interface on the socket itself and skips the route lookup, which is why this
// works while the tunnel is up. Measured: through the tunnel xbox-dns answers
// 172.217.114.4 (genuine Google), through the ISP link 87.228.47.204 (proxy).
//
// Resolve-DnsName has no interface parameter, so the query is assembled by hand.
// Only A records are needed - the answers are pinned into `hosts`, which is IPv4
// and IPv6 literals only, no CNAME chains.

const DNS_PORT: u16 = 53;
#[allow(dead_code)]
const TIMEOUT: Duration = Duration::from_secs(5);

/// Transaction IDs only have to differ between concurrent queries; a counter is
/// enough and keeps the crate free of a random-number dependency.
#[allow(dead_code)]
static NEXT_ID: AtomicU16 = AtomicU16::new(0x1234);

#[cfg(target_os = "windows")]
mod sys {
    const IPPROTO_IP: i32 = 0;
    const IP_UNICAST_IF: i32 = 31;

    #[link(name = "ws2_32")]
    extern "system" {
        fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    }

    /// Forces unicast traffic out of `if_index`. Index 0 restores the default,
    /// i.e. "let the routing table decide".
    pub fn bind_socket_to_interface(
        sock: &std::net::UdpSocket,
        if_index: u32,
    ) -> Result<(), String> {
        use std::os::windows::io::AsRawSocket;
        // IP_UNICAST_IF takes the index in network byte order - the one Winsock
        // quirk in this call, and a silent no-op if you get it wrong.
        let value: u32 = if_index.to_be();
        let rc = unsafe {
            setsockopt(
                sock.as_raw_socket() as usize,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err("не удалось привязать сокет к интерфейсу".to_string())
        }
    }
}

#[cfg(target_os = "macos")]
mod sys {
    const IPPROTO_IP: i32 = 0;
    const IP_BOUND_IF: i32 = 25;

    pub fn bind_socket_to_interface(
        sock: &std::net::UdpSocket,
        if_index: u32,
    ) -> Result<(), String> {
        use std::os::unix::io::AsRawFd;
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                IPPROTO_IP,
                IP_BOUND_IF,
                &if_index as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err("не удалось привязать сокет к интерфейсу (IP_BOUND_IF)".to_string())
        }
    }
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
mod sys {
    pub fn bind_socket_to_interface(_: &std::net::UdpSocket, _: u32) -> Result<(), String> {
        Err("поддерживается только на Windows и macOS".to_string())
    }
}

pub fn build_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(name.len() + 18);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    q.extend_from_slice(&[0x00, 0x01]); // one question
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answer/authority/additional
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let len = label.len().min(63);
        q.push(len as u8);
        q.extend_from_slice(&label.as_bytes()[..len]);
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01]); // A
    q.extend_from_slice(&[0x00, 0x01]); // IN
    q
}

/// Steps over a name without expanding it. Names are variable length and may end
/// in a compression pointer, which is why this cannot be a fixed offset.
fn skip_name(buf: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *buf.get(i)? as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            // A pointer is always the last thing in a name.
            return if i + 1 < buf.len() { Some(i + 2) } else { None };
        }
        i += 1 + len;
    }
}

/// Every A record in the answer section. Anything malformed ends the walk
/// instead of panicking - this parses bytes from a third-party resolver.
#[allow(dead_code)]
fn parse_a_records(buf: &[u8], expect_id: u16) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if buf.len() < 12 || u16::from_be_bytes([buf[0], buf[1]]) != expect_id {
        return out;
    }
    let answers = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let questions = u16::from_be_bytes([buf[4], buf[5]]) as usize;

    let mut i = 12;
    for _ in 0..questions {
        match skip_name(buf, i) {
            Some(next) => i = next + 4, // qtype + qclass
            None => return out,
        }
    }

    for _ in 0..answers {
        i = match skip_name(buf, i) {
            Some(next) => next,
            None => return out,
        };
        if i + 10 > buf.len() {
            return out;
        }
        let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        i += 10;
        if i + rdlen > buf.len() {
            return out;
        }
        if rtype == 1 && rdlen == 4 {
            out.push(Ipv4Addr::new(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]));
        }
        i += rdlen;
    }
    out
}

/// Every address in the answer section, A and AAAA alike, with no id check -
/// the caller already matched the id when it accepted the packet.
///
/// The relay needs this to tell a substituted answer from a genuine one, which
/// is a question about addresses rather than about one record type: the routed
/// names are asked for both families and a resolver may substitute only one.
pub fn answer_addrs(buf: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if buf.len() < 12 {
        return out;
    }
    let answers = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let questions = u16::from_be_bytes([buf[4], buf[5]]) as usize;

    let mut i = 12;
    for _ in 0..questions {
        match skip_name(buf, i) {
            Some(next) => i = next + 4,
            None => return out,
        }
    }

    for _ in 0..answers {
        i = match skip_name(buf, i) {
            Some(next) => next,
            None => return out,
        };
        if i + 10 > buf.len() {
            return out;
        }
        let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        i += 10;
        if i + rdlen > buf.len() {
            return out;
        }
        match (rtype, rdlen) {
            (1, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                buf[i],
                buf[i + 1],
                buf[i + 2],
                buf[i + 3],
            ))),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[i..i + 16]);
                out.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        i += rdlen;
    }
    out
}

/// Removes the given addresses from the answer section and fixes ANCOUNT.
///
/// Needed because a provider can hand out an address that answers DNS but not
/// TCP: geohide returns three proxy addresses for `daily-cloudcode-pa` and one
/// of them black-holes port 443, which cost ~20 s on the first connection -
/// Windows' SYN retransmission budget - before the client fell through to a
/// live one.
///
/// Deliberately conservative. Names in a DNS message may be compression
/// pointers, and removing bytes shifts every offset after them, so this edits
/// only the shape it can prove is safe: no authority section, and an additional
/// section that is either empty or a single OPT whose name is the root label.
/// In that shape the only names are the question and back-pointers to it, both
/// of which sit before anything this removes. Anything else is left untouched -
/// `None` means "hand the original back".
pub fn without_addrs(reply: &[u8], drop: &[IpAddr]) -> Option<Vec<u8>> {
    if reply.len() < 12 || drop.is_empty() {
        return None;
    }
    let questions = u16::from_be_bytes([reply[4], reply[5]]) as usize;
    let answers = u16::from_be_bytes([reply[6], reply[7]]) as usize;
    let authority = u16::from_be_bytes([reply[8], reply[9]]) as usize;
    let additional = u16::from_be_bytes([reply[10], reply[11]]) as usize;
    if authority != 0 || additional > 1 || answers == 0 {
        return None;
    }

    let mut i = 12;
    for _ in 0..questions {
        i = skip_name(reply, i)? + 4;
    }
    let question_end = i;

    let mut kept: Vec<(usize, usize)> = Vec::new();
    let mut kept_addrs = 0usize;
    let mut removed = 0usize;
    for _ in 0..answers {
        let start = i;
        let after_name = skip_name(reply, i)?;
        if after_name + 10 > reply.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([reply[after_name], reply[after_name + 1]]);
        let rdlen = u16::from_be_bytes([reply[after_name + 8], reply[after_name + 9]]) as usize;
        let rdata = after_name + 10;
        let end = rdata.checked_add(rdlen)?;
        if end > reply.len() {
            return None;
        }
        let addr = match (rtype, rdlen) {
            (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                reply[rdata],
                reply[rdata + 1],
                reply[rdata + 2],
                reply[rdata + 3],
            ))),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&reply[rdata..rdata + 16]);
                Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
            }
            _ => None,
        };
        if addr.is_some_and(|a| drop.contains(&a)) {
            removed += 1;
        } else {
            if addr.is_some() {
                kept_addrs += 1;
            }
            kept.push((start, end));
        }
        i = end;
    }

    // Nothing to do, or every *address* would go: an answer with no address is
    // worse than a slow one, because the client then has nothing to fall
    // through to.
    //
    // Counted in addresses, not records. It used to ask `kept.is_empty()`, and
    // those two are the same question only while every answer record is an
    // address - which was true of every substitution in the pool until comss
    // started answering `cloudcode-pa` with a CNAME followed by four A records.
    // Cut all four and one record survives, so the record-shaped guard let it
    // through and produced a reply with ANCOUNT=1, a lone CNAME and no address
    // at all: exactly the empty answer this refuses to make, wearing a shape it
    // could not see. It bit the moment `cloudcode-pa` became the primary name.
    if removed == 0 || kept_addrs == 0 {
        return None;
    }
    // The tail is the OPT record, if the reply carried one. Only a root name is
    // accepted, since that is the one name that cannot be a pointer.
    let tail = &reply[i..];
    if additional == 1 && (tail.len() < 11 || tail[0] != 0) {
        return None;
    }

    let mut out = Vec::with_capacity(reply.len());
    out.extend_from_slice(&reply[..12]);
    let count = (answers - removed) as u16;
    out[6..8].copy_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&reply[12..question_end]);
    for (start, end) in kept {
        out.extend_from_slice(&reply[start..end]);
    }
    out.extend_from_slice(tail);
    Some(out)
}

/// An OPT record. Its "TTL" field carries the extended rcode, version and the
/// DO bit rather than a lifetime, so anything that reads or writes TTLs has to
/// step over it.
const RTYPE_OPT: u16 = 41;

/// Where every record's TTL field sits, with the record's type, across the
/// answer, authority and additional sections.
///
/// `None` for anything that cannot be walked to the end: a caller that does not
/// know the shape of a message has no business editing it.
fn ttl_fields(buf: &[u8]) -> Option<Vec<(usize, u16)>> {
    if buf.len() < 12 {
        return None;
    }
    let questions = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let records = u16::from_be_bytes([buf[6], buf[7]]) as usize
        + u16::from_be_bytes([buf[8], buf[9]]) as usize
        + u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut i = 12;
    for _ in 0..questions {
        i = skip_name(buf, i)?.checked_add(4)?;
        if i > buf.len() {
            return None;
        }
    }

    let mut out = Vec::with_capacity(records);
    for _ in 0..records {
        let after_name = skip_name(buf, i)?;
        if after_name + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[after_name], buf[after_name + 1]]);
        let rdlen = u16::from_be_bytes([buf[after_name + 8], buf[after_name + 9]]) as usize;
        out.push((after_name + 4, rtype));
        i = after_name.checked_add(10)?.checked_add(rdlen)?;
        if i > buf.len() {
            return None;
        }
    }
    Some(out)
}

/// The smallest TTL in the answer section - how long the whole reply is good
/// for. `None` when there is no timed record to read one from.
pub fn answer_ttl(reply: &[u8]) -> Option<u32> {
    let answers = u16::from_be_bytes([*reply.get(6)?, *reply.get(7)?]) as usize;
    ttl_fields(reply)?
        .into_iter()
        .take(answers)
        .filter(|(_, rtype)| *rtype != RTYPE_OPT)
        .map(|(at, _)| u32::from_be_bytes([reply[at], reply[at + 1], reply[at + 2], reply[at + 3]]))
        .min()
}

/// Rewrites every record's TTL through `f`, in place.
///
/// Safe where `without_addrs` has to be careful: only the four TTL bytes of each
/// record change, so nothing moves and every compression pointer in the message
/// stays valid whatever shape it has. OPT is skipped. `None` means the message
/// could not be walked - the caller's cue to hand back the original rather than
/// to edit a message it does not understand.
fn rewrite_ttls(reply: &[u8], f: impl Fn(u32) -> u32) -> Option<Vec<u8>> {
    let fields = ttl_fields(reply)?;
    let mut out = reply.to_vec();
    for (at, rtype) in fields {
        if rtype == RTYPE_OPT {
            continue;
        }
        let ttl = u32::from_be_bytes([out[at], out[at + 1], out[at + 2], out[at + 3]]);
        // A record that was already at zero stays there; anything else keeps at
        // least a second, so a rewritten answer never reads as "do not cache".
        let next = if ttl == 0 { 0 } else { f(ttl).max(1) };
        out[at..at + 4].copy_from_slice(&next.to_be_bytes());
    }
    Some(out)
}

/// Ages every record in `reply` by `seconds`, so an answer served out of memory
/// expires when the resolver said it would rather than `seconds` later.
pub fn age_reply(reply: &[u8], seconds: u32) -> Option<Vec<u8>> {
    rewrite_ttls(reply, |ttl| ttl.saturating_sub(seconds))
}

/// Clamps every record's TTL to at most `seconds`.
///
/// The relay needs this because a TTL is the resolver's opinion about its own
/// answer, and an answer that failed to defeat the region gate has no business
/// being believed for as long as the resolver would like: comss hands out the
/// genuine Google address for `daily-cloudcode-pa` with a TTL of 3199 s, which
/// pins the client to it for the best part of an hour.
pub fn cap_ttl(reply: &[u8], seconds: u32) -> Option<Vec<u8>> {
    rewrite_ttls(reply, |ttl| ttl.min(seconds))
}

/// The qtype of the question. Only A and AAAA answers can be compared against a
/// reference resolver, so the relay has to know which it is looking at.
pub fn question_type(buf: &[u8]) -> Option<u16> {
    let end = skip_name(buf, 12)?;
    let bytes = buf.get(end..end + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// The question name of a query, for logging. Cheap enough to run per packet
/// and never fails loudly - a name we cannot read is simply not logged.
pub fn question_name(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let mut i = 12;
    let mut name = String::new();
    loop {
        let len = *buf.get(i)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            return None; // a question name is never compressed
        }
        let label = buf.get(i + 1..i + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        i += 1 + len;
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Sends `packet` verbatim and hands back the raw reply, forcing the query out
/// of `if_index` (0 = let the routing table pick). The forwarder relays bytes it
/// never parses, so this stays transport-only: any record type, EDNS included,
/// passes through untouched.
pub fn query_raw_via(
    packet: &[u8],
    server: Ipv4Addr,
    if_index: u32,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).map_err(|_| "нет UDP-сокета".to_string())?;
    if if_index != 0 {
        sys::bind_socket_to_interface(&sock, if_index)?;
    }
    sock.set_read_timeout(Some(timeout)).ok();
    sock.send_to(packet, SocketAddr::from((server, DNS_PORT)))
        .map_err(|_| "запрос не отправлен".to_string())?;

    let want_id = packet.get(0..2).map(|b| [b[0], b[1]]);
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = sock
            .recv_from(&mut buf)
            .map_err(|_| "резолвер не ответил".to_string())?;
        // A stray packet must not end the wait: keep reading until the deadline
        // for one that came from the resolver and answers the id we sent.
        let right_source = from.ip() == IpAddr::V4(server);
        let right_id = match (want_id, n >= 12) {
            (Some(id), true) => buf[0..2] == id,
            _ => false,
        };
        if right_source && right_id {
            return Ok(buf[..n].to_vec());
        }
        if Instant::now() >= deadline {
            return Err("резолвер не ответил".to_string());
        }
    }
}

/// Asks `server` for the A records of `host`, forcing the query out of
/// `if_index`. Pass 0 to let the routing table pick - useful for comparing what
/// the same resolver answers on the two paths.
///
/// Production traffic goes through `resolvers`, which races every provider and
/// classifies the answers. This single-resolver primitive is what the live
/// `--ignored` diagnostics use to put a direct question to one named server, so
/// it and its helpers are dead code in a normal build on purpose.
#[allow(dead_code)]
pub fn resolve_a_via(host: &str, server: Ipv4Addr, if_index: u32) -> Result<Vec<Ipv4Addr>, String> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let reply = query_raw_via(&build_query(host, id), server, if_index, TIMEOUT)?;
    Ok(parse_a_records(&reply, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_carries_the_name_as_labels() {
        let q = build_query("a.example", 0xBEEF);
        assert_eq!(&q[0..2], &[0xBE, 0xEF]);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1); // one question
        assert_eq!(&q[12..], b"\x01a\x07example\x00\x00\x01\x00\x01");
    }

    #[test]
    fn empty_labels_are_dropped() {
        // A trailing dot is a legal way to write an absolute name.
        assert_eq!(build_query("a.example.", 1), build_query("a.example", 1));
    }

    /// Header + question, then `count` A answers that use a compression pointer
    /// for the name, exactly as a real resolver replies.
    fn response(id: u16, addrs: &[[u8; 4]]) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&[0x81, 0x80]);
        b.extend_from_slice(&[0x00, 0x01]);
        b.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(b"\x01a\x07example\x00");
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        for a in addrs {
            b.extend_from_slice(&[0xC0, 0x0C]); // pointer back to the question
            b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            b.extend_from_slice(&[0, 0, 0, 60]);
            b.extend_from_slice(&[0x00, 0x04]);
            b.extend_from_slice(a);
        }
        b
    }

    #[test]
    fn reads_every_a_record() {
        let msg = response(7, &[[1, 2, 3, 4], [87, 228, 47, 204]]);
        assert_eq!(
            parse_a_records(&msg, 7),
            vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(87, 228, 47, 204)]
        );
    }

    #[test]
    fn a_reply_to_another_query_is_ignored() {
        let msg = response(7, &[[1, 2, 3, 4]]);
        assert!(parse_a_records(&msg, 8).is_empty());
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let msg = response(7, &[[1, 2, 3, 4]]);
        for cut in 0..msg.len() {
            let _ = parse_a_records(&msg[..cut], 7);
        }
    }

    #[test]
    fn a_record_count_larger_than_the_body_is_survivable() {
        let mut msg = response(7, &[[1, 2, 3, 4]]);
        msg[6] = 0x00;
        msg[7] = 0x40; // claim 64 answers, ship one
        assert_eq!(parse_a_records(&msg, 7), vec![Ipv4Addr::new(1, 2, 3, 4)]);
    }

    /// The reply shape this is allowed to edit: question, then A records whose
    /// name is a pointer back to it. `opt` appends an EDNS0 OPT record, whose
    /// root name is the one name that cannot be a compression pointer.
    fn reply_with(id: u16, addrs: &[[u8; 4]], opt: bool) -> Vec<u8> {
        let mut b = response(id, addrs);
        if opt {
            b[11] = 1; // ARCOUNT
            b.extend_from_slice(&[0, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0x00, 0x00]);
        }
        b
    }

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    #[test]
    fn a_dead_address_is_cut_out_and_the_count_fixed() {
        // The real case: geohide's three proxy addresses, the last one a black
        // hole on 443.
        let msg = reply_with(
            9,
            &[[45, 155, 204, 190], [37, 230, 192, 51], [95, 182, 120, 241]],
            false,
        );
        let out = without_addrs(&msg, &[v4("95.182.120.241")]).expect("rewritten");
        assert_eq!(
            u16::from_be_bytes([out[6], out[7]]),
            2,
            "ANCOUNT must follow"
        );
        assert_eq!(
            answer_addrs(&out),
            vec![v4("45.155.204.190"), v4("37.230.192.51")]
        );
        assert_eq!(&out[0..6], &msg[0..6], "header and question untouched");
    }

    /// An OPT record has to survive the edit, or a client that asked with EDNS0
    /// gets a reply that has quietly lost it.
    #[test]
    fn the_opt_record_survives() {
        let msg = reply_with(9, &[[1, 1, 1, 1], [2, 2, 2, 2]], true);
        let out = without_addrs(&msg, &[v4("1.1.1.1")]).expect("rewritten");
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 1, "ARCOUNT kept");
        assert_eq!(&out[out.len() - 11..], &msg[msg.len() - 11..]);
        assert_eq!(answer_addrs(&out), vec![v4("2.2.2.2")]);
    }

    /// Never hand back an empty answer: the client would have nothing to fall
    /// through to, which is worse than one slow address.
    #[test]
    fn removing_everything_is_refused() {
        let msg = reply_with(9, &[[1, 1, 1, 1]], false);
        assert!(without_addrs(&msg, &[v4("1.1.1.1")]).is_none());
    }

    /// The same rule, in the shape that got past it.
    ///
    /// comss answers `cloudcode-pa` with a CNAME and four A records. Cut all
    /// four - which is what happens when every proxy address refuses the SNI -
    /// and a record still survives, so a guard phrased as "did any *record*
    /// remain" said yes and produced an answer with no address in it. The guard
    /// counts addresses now, so this shape is refused like any other.
    #[test]
    fn removing_every_address_is_refused_even_when_a_cname_survives() {
        let mut b = vec![];
        b.extend_from_slice(&9u16.to_be_bytes());
        // QDCOUNT 1, ANCOUNT 3 (CNAME + two A), no authority, no additional.
        b.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0, 0, 0, 0]);
        b.extend_from_slice(&[1, b'a', 0]); // question "a."
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // CNAME "a." -> "b.", name compressed back to the question.
        b.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60, 0, 3]);
        b.extend_from_slice(&[1, b'b', 0]);
        for last in [1u8, 2u8] {
            b.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4]);
            b.extend_from_slice(&[10, 0, 0, last]);
        }

        assert_eq!(answer_addrs(&b), vec![v4("10.0.0.1"), v4("10.0.0.2")]);
        // Both addresses dead -> refuse, rather than leave a lone CNAME.
        assert!(without_addrs(&b, &[v4("10.0.0.1"), v4("10.0.0.2")]).is_none());
        // One dead is still a normal edit, and the CNAME must survive it.
        let out = without_addrs(&b, &[v4("10.0.0.1")]).expect("rewritten");
        assert_eq!(answer_addrs(&out), vec![v4("10.0.0.2")]);
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 2, "CNAME + one A");
    }

    #[test]
    fn nothing_to_remove_leaves_the_reply_alone() {
        let msg = reply_with(9, &[[1, 1, 1, 1], [2, 2, 2, 2]], false);
        assert!(without_addrs(&msg, &[v4("9.9.9.9")]).is_none());
        assert!(without_addrs(&msg, &[]).is_none());
    }

    /// An authority section may carry pointers into the bytes being removed, so
    /// that shape is refused outright rather than edited on a guess.
    #[test]
    fn a_reply_with_an_authority_section_is_refused() {
        let mut msg = reply_with(9, &[[1, 1, 1, 1], [2, 2, 2, 2]], false);
        msg[9] = 1; // NSCOUNT
        assert!(without_addrs(&msg, &[v4("1.1.1.1")]).is_none());
    }

    #[test]
    fn truncated_input_does_not_panic_while_rewriting() {
        let msg = reply_with(9, &[[1, 1, 1, 1], [2, 2, 2, 2]], true);
        for cut in 0..msg.len() {
            let _ = without_addrs(&msg[..cut], &[v4("1.1.1.1")]);
        }
    }

    #[test]
    fn non_a_records_are_skipped() {
        let mut b = vec![];
        b.extend_from_slice(&7u16.to_be_bytes());
        b.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0, 0, 0, 0]);
        b.extend_from_slice(b"\x01a\x07example\x00");
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // CNAME first, then the A record it points at.
        b.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x02]);
        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04]);
        b.extend_from_slice(&[9, 9, 9, 9]);
        assert_eq!(parse_a_records(&b, 7), vec![Ipv4Addr::new(9, 9, 9, 9)]);
    }

    #[test]
    fn the_answer_ttl_is_the_shortest_one() {
        let mut msg = reply_with(9, &[[1, 1, 1, 1], [2, 2, 2, 2]], true);
        assert_eq!(answer_ttl(&msg), Some(60));
        // Second record down to 30: the reply is only good for the shorter one.
        // It ends where the 11-byte OPT begins, and its last 10 bytes are
        // ttl(4) + rdlength(2) + a 4-byte address.
        let ttl_at = msg.len() - 11 - 10;
        msg[ttl_at..ttl_at + 4].copy_from_slice(&30u32.to_be_bytes());
        assert_eq!(answer_ttl(&msg), Some(30));
    }

    #[test]
    fn ageing_shortens_every_record_and_moves_nothing() {
        let msg = reply_with(9, &[[1, 1, 1, 1], [2, 2, 2, 2]], true);
        let aged = age_reply(&msg, 25).unwrap();
        assert_eq!(aged.len(), msg.len());
        assert_eq!(answer_ttl(&aged), Some(35));
        // The addresses still parse, i.e. the pointers still point where they did.
        assert_eq!(answer_addrs(&aged), answer_addrs(&msg));
    }

    /// An OPT record's TTL field is the extended rcode, version and DO bit.
    /// Ageing it would silently turn a plain reply into a DNSSEC-flagged one.
    #[test]
    fn the_opt_record_is_not_aged() {
        let msg = reply_with(9, &[[1, 1, 1, 1]], true);
        let opt = msg.len() - 11;
        let aged = age_reply(&msg, 30).unwrap();
        assert_eq!(&aged[opt..], &msg[opt..]);
    }

    #[test]
    fn ageing_past_the_ttl_leaves_a_second_rather_than_zero() {
        let msg = reply_with(9, &[[1, 1, 1, 1]], false);
        assert_eq!(answer_ttl(&age_reply(&msg, 9_000).unwrap()), Some(1));
    }

    #[test]
    fn ageing_a_message_it_cannot_walk_returns_none() {
        let msg = reply_with(9, &[[1, 1, 1, 1], [2, 2, 2, 2]], true);
        for cut in 0..msg.len() {
            let _ = age_reply(&msg[..cut], 5);
            let _ = answer_ttl(&msg[..cut]);
        }
        let mut lying = msg.clone();
        lying[7] = 0x40; // claim 64 answers, ship two
        assert!(age_reply(&lying, 5).is_none());
    }
}
