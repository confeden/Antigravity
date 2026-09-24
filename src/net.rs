//! Outbound TCP that leaves through the interface we name, not the one the
//! routing table picks.
//!
//! Every UDP resolver query has been pinned to the ISP link since the first VPN
//! report (`dns_client`, IP_UNICAST_IF, I4). TCP was not, and that half is what
//! a VPN broke (N25): the query left through the ISP link and was substituted,
//! the *connection* to the substituted address followed the routing table into
//! the tunnel, and a provider that serves Russian and Belarusian addresses only
//! refused it from the tunnel's foreign exit. The DoH provider had the same gap
//! (P13): its queries rode the tunnel and came back unsubstituted.
//!
//! IP_UNICAST_IF has to be set *before* `connect`, which `TcpStream` cannot do —
//! it creates and connects in one call — so the socket is built with `socket2`
//! and handed back as an ordinary `TcpStream`.
//!
//! Pinning is only switched on while a tunnel holds the default route. With no
//! tunnel the ISP link *is* the default route, and naming it buys nothing while
//! a wrong guess about which adapter that is (two NICs, a dock) would cost the
//! connection.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// The interface third-party-facing sockets are pinned to. 0 = the routing
/// table decides, which is the state with no tunnel up.
static PIN_IF: AtomicU32 = AtomicU32::new(0);

/// Set by the relay's warm loop from the tunnel verdict: the ISP interface while
/// a tunnel holds the default route, 0 otherwise.
pub fn set_pin_interface(if_index: u32) {
    PIN_IF.store(if_index, Ordering::Relaxed);
}

/// The interface to pin to right now, or 0 for "let the routing table decide".
pub fn pin_interface() -> u32 {
    PIN_IF.load(Ordering::Relaxed)
}

/// Unix time something outside this machine last answered this process: a
/// resolver, a DoH node, a route's probe. 0 = nothing yet.
static REACHED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Called wherever an answer from the internet arrives. The relay publishes it
/// (`gate::Report::reached_at`): a relay that has run for minutes with nothing
/// reached is cut off, and when the window - another program on the same
/// network - is not, something on this machine singles the relay out (P53).
pub fn note_reached() {
    REACHED.store(crate::gate::now_unix(), Ordering::Relaxed);
}

pub fn last_reached() -> u64 {
    REACHED.load(Ordering::Relaxed)
}

/// Whether a tunnel holds the default route, as the relay last saw it.
pub fn tunnel_up() -> bool {
    pin_interface() != 0
}

/// Connects to `addr` inside `timeout`, leaving through `if_index` when it is
/// not 0.
///
/// A pinned connect that the interface cannot carry fails like any other
/// connect — a kill-switch VPN drops it, a dead link refuses it — so the caller's
/// ordinary fall-through to the next address or route is what handles it.
pub fn connect(addr: SocketAddr, timeout: Duration, if_index: u32) -> io::Result<TcpStream> {
    if if_index == 0 {
        return TcpStream::connect_timeout(&addr, timeout);
    }
    connect_pinned(addr, timeout, if_index)
}

#[cfg(target_os = "windows")]
fn connect_pinned(addr: SocketAddr, timeout: Duration, if_index: u32) -> io::Result<TcpStream> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::os::windows::io::AsRawSocket;

    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // The one Winsock quirk in this pair: IPv4 takes the index in network byte
    // order, IPv6 in host byte order. Getting it wrong is not an error — the
    // option is silently ignored and the socket follows the routing table.
    let (level, value) = match addr {
        SocketAddr::V4(_) => (sys::IPPROTO_IP, if_index.to_be()),
        SocketAddr::V6(_) => (sys::IPPROTO_IPV6, if_index),
    };
    let rc = unsafe {
        sys::setsockopt(
            sock.as_raw_socket() as usize,
            level,
            sys::UNICAST_IF,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    sock.connect_timeout(&SockAddr::from(addr), timeout)?;
    Ok(sock.into())
}

#[cfg(not(target_os = "windows"))]
fn connect_pinned(addr: SocketAddr, timeout: Duration, if_index: u32) -> io::Result<TcpStream> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::os::unix::io::AsRawFd;

    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    const SOL_SOCKET: i32 = 1;
    const SO_BINDTOIFINDEX: i32 = 62;
    extern "C" {
        fn setsockopt(
            socket: i32,
            level: i32,
            option_name: i32,
            option_value: *const std::ffi::c_void,
            option_len: u32,
        ) -> i32;
    }
    let idx = if_index as i32;
    let rc = unsafe {
        setsockopt(
            sock.as_raw_fd(),
            SOL_SOCKET,
            SO_BINDTOIFINDEX,
            &idx as *const i32 as *const std::ffi::c_void,
            std::mem::size_of::<i32>() as u32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    sock.connect_timeout(&SockAddr::from(addr), timeout)?;
    Ok(sock.into())
}

/// The interface the routing table would send a packet to `dest` through.
///
/// One syscall, no PowerShell: cheap enough for every warm pass, which is what
/// lets the relay notice a VPN coming up within seconds instead of on the
/// four-minute clock the full adapter scan runs on. `None` where it cannot be
/// asked (no route at all, or not Windows).
#[cfg(target_os = "windows")]
pub fn best_interface(dest: Ipv4Addr) -> Option<u32> {
    let mut idx: u32 = 0;
    // IPAddr is the address in network byte order, read as a DWORD.
    let rc = unsafe { sys::GetBestInterface(u32::from_ne_bytes(dest.octets()), &mut idx) };
    (rc == 0 && idx != 0).then_some(idx)
}

#[cfg(not(target_os = "windows"))]
pub fn best_interface(_dest: Ipv4Addr) -> Option<u32> {
    crate::egress::detect().map(|e| e.if_index)
}

#[cfg(target_os = "windows")]
mod sys {
    pub const IPPROTO_IP: i32 = 0;
    pub const IPPROTO_IPV6: i32 = 41;
    /// IP_UNICAST_IF and IPV6_UNICAST_IF share the value.
    pub const UNICAST_IF: i32 = 31;

    #[link(name = "ws2_32")]
    extern "system" {
        pub fn setsockopt(
            s: usize,
            level: i32,
            optname: i32,
            optval: *const u8,
            optlen: i32,
        ) -> i32;
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn GetBestInterface(dest: u32, best_if_index: *mut u32) -> u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn an_unpinned_connect_is_the_plain_one() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bound");
        let addr = listener.local_addr().expect("addr");
        assert!(connect(addr, Duration::from_secs(2), 0).is_ok());
    }

    #[test]
    fn the_pin_is_off_until_the_relay_sets_it() {
        // Process-wide, so the test puts back what it found.
        let before = pin_interface();
        set_pin_interface(0);
        assert!(!tunnel_up());
        set_pin_interface(27);
        assert!(tunnel_up());
        assert_eq!(pin_interface(), 27);
        set_pin_interface(before);
    }

    /// Live: pinning must actually change where a TCP connection leaves, or the
    /// whole VPN fix is a no-op that looks like it works. Pinned to the adapter
    /// that holds the default route, a connection to a public address succeeds;
    /// pinned to an interface index nothing has, it must fail.
    ///
    ///     cargo test pinning_steers_a_tcp_connection -- --ignored --nocapture
    #[test]
    #[ignore = "needs a live network; run with --ignored"]
    fn pinning_steers_a_tcp_connection() {
        let dest: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let best = best_interface(dest).expect("a default route");
        let addr = SocketAddr::from((dest, 443));
        let ok = connect(addr, Duration::from_secs(5), best);
        println!(
            "pinned to if{best}: {:?}",
            ok.as_ref().map(|s| s.local_addr())
        );
        assert!(ok.is_ok(), "pinned to the default interface must connect");
        let bogus = connect(addr, Duration::from_secs(3), 0x7fff);
        println!(
            "pinned to if{}: {:?}",
            0x7fff,
            bogus.as_ref().map(|s| s.local_addr())
        );
        assert!(
            bogus.is_err(),
            "an interface that does not exist must not carry it"
        );
    }
}
