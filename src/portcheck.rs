//! Why a local port could not be bound, in words a user can act on.
//!
//! The relay listens on three loopback ports: the local proxy's TCP port, the
//! gate hosts' door on TCP `:443`, and the DNS relay's UDP `127.0.0.53:53`.
//! A UDP `:53` bind cannot be moved to another port (the NRPT rules that point
//! at the relay carry an IP address with no port), so for that listener the
//! diagnosis is the whole of what we can offer the user. When a bind fails the
//! relay used to log `os error 10013` and carry on without them, and Antigravity
//! went on hitting the 400 with nothing on screen saying why (P53). Three causes
//! cover what the field has shown, and each has a different fix:
//!
//! * **held** — another program already listens on that port (a local web
//!   server, VMware's shared VMs, Docker, IIS through HTTP.sys; on UDP `:53` the
//!   usual holder is Windows' Internet Connection Sharing (the `SharedAccess`
//!   service, which the Hyper-V default switch and the mobile hotspot both
//!   start), a local DNS proxy (AdGuard, DNSCrypt, Docker Desktop) or a
//!   competing tool). We can name it.
//! * **reserved** — the port lies in a range Windows has set aside, which is
//!   what Hyper-V, WSL 2 and Docker do inside the dynamic range (G31).
//! * **denied** — nothing holds it and nothing reserved it, and Windows still
//!   says `WSAEACCES`: security software refusing this program a listening
//!   socket. The fix is an exception for our exe in that software.

use std::net::{Ipv4Addr, SocketAddr};

/// Which transport a failed bind was on. The listener tables and Windows'
/// excluded-port ranges are kept per protocol, so a diagnosis has to ask about
/// the right one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// What stopped a bind, as `gate::Blocker::cause` spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// Another program listens on the port; its image name when it could be
    /// read (a service run as SYSTEM may not tell an unelevated relay).
    Held(Option<String>),
    /// Inside a range Windows excluded from use.
    Reserved,
    /// Access denied with no holder and no reservation: security software.
    Denied,
    /// Anything else; the OS text says what.
    Other,
}

impl Cause {
    pub fn code(&self) -> &'static str {
        match self {
            Cause::Held(_) => "held",
            Cause::Reserved => "reserved",
            Cause::Denied => "denied",
            Cause::Other => "other",
        }
    }

    pub fn holder(&self) -> Option<&str> {
        match self {
            Cause::Held(name) => name.as_deref(),
            _ => None,
        }
    }

    /// The record the relay publishes for the window (`gate::set_blocker`).
    pub fn blocker(
        &self,
        what: &str,
        addr: SocketAddr,
        err: &std::io::Error,
    ) -> crate::gate::Blocker {
        crate::gate::Blocker {
            what: what.to_string(),
            addr: addr.to_string(),
            cause: self.code().to_string(),
            by: self.holder().unwrap_or_default().to_string(),
            error: err.to_string(),
        }
    }

    /// Whether moving to another port gets around it. Security software that
    /// refuses this program a socket refuses it every port.
    ///
    /// Windows only. On Linux nothing would carry a moved port into the
    /// `environment.d` drop-in (the relay's env thread is Windows'), so a move
    /// would leave the variable naming the old port; there the proxy keeps
    /// retrying its own port instead, which a borrowed ephemeral port frees.
    pub fn another_port_helps(&self) -> bool {
        cfg!(windows) && !matches!(self, Cause::Denied)
    }
}

/// Classifies a failed bind of `addr` on TCP.
pub fn diagnose(addr: SocketAddr, err: &std::io::Error) -> Cause {
    diagnose_on(addr, err, Proto::Tcp)
}

/// Classifies a failed bind of `addr` on `proto`. Costs a table read and, only
/// when that finds no holder, one `netsh` call: once per failed bind, which
/// while a blocker lasts is the listener's one retry a minute.
pub fn diagnose_on(addr: SocketAddr, err: &std::io::Error, proto: Proto) -> Cause {
    let port = addr.port();
    if let Some(pid) = listener_pid(addr, proto) {
        return Cause::Held(process_name(pid));
    }
    if excluded_ranges(proto)
        .iter()
        .any(|(lo, hi)| (*lo..=*hi).contains(&port))
    {
        return Cause::Reserved;
    }
    // 10013 on Windows, EACCES elsewhere.
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        return Cause::Denied;
    }
    Cause::Other
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// The image name of the program listening where `addr` points, when it can be
/// read. What tells our own proxy from somebody else's program answering on the
/// same port (`proxy::wait_for_our_listener`).
pub fn listener_image(addr: SocketAddr) -> Option<String> {
    listener_pid(addr, Proto::Tcp).and_then(process_name)
}

#[cfg(windows)]
pub fn listener_path(addr: SocketAddr) -> Option<std::path::PathBuf> {
    listener_pid(addr, Proto::Tcp).and_then(process_image)
}

/// The PID holding `addr` itself, or on the wildcard for its port - the two
/// that can stand in its way. A listener on another loopback address with the
/// same port does not, and blaming it would send the user after the wrong
/// program (a dev server on 127.0.0.1:443 while the door wants 127.65.71.1:443).
#[cfg(windows)]
fn listener_pid(addr: SocketAddr, proto: Proto) -> Option<u32> {
    match proto {
        Proto::Tcp => tcp_listener_pid(addr),
        Proto::Udp => udp_listener_pid(addr),
    }
}

#[cfg(windows)]
fn tcp_listener_pid(addr: SocketAddr) -> Option<u32> {
    let (port, want) = match addr {
        SocketAddr::V4(a) => (a.port(), *a.ip()),
        SocketAddr::V6(_) => return None,
    };
    const TCP_TABLE_OWNER_PID_LISTENER: u32 = 3;
    tcp_owner_pid(TCP_TABLE_OWNER_PID_LISTENER, |row| {
        let local = Ipv4Addr::from(row[1].to_ne_bytes());
        tcp_port(row[2]) == port && (local == want || local.is_unspecified())
    })
}

/// Resolve the client side of a connected loopback socket to its process image.
#[cfg(windows)]
pub fn client_image(stream: &std::net::TcpStream) -> Option<std::path::PathBuf> {
    let SocketAddr::V4(peer) = stream.peer_addr().ok()? else {
        return None;
    };
    let SocketAddr::V4(listener) = stream.local_addr().ok()? else {
        return None;
    };
    const TCP_TABLE_OWNER_PID_CONNECTIONS: u32 = 4;
    const MIB_TCP_STATE_ESTAB: u32 = 5;
    let pid = tcp_owner_pid(TCP_TABLE_OWNER_PID_CONNECTIONS, |row| {
        row[0] == MIB_TCP_STATE_ESTAB
            && Ipv4Addr::from(row[1].to_ne_bytes()) == *peer.ip()
            && tcp_port(row[2]) == peer.port()
            && Ipv4Addr::from(row[3].to_ne_bytes()) == *listener.ip()
            && tcp_port(row[4]) == listener.port()
    })?;
    process_image(pid)
}

#[cfg(windows)]
fn tcp_port(value: u32) -> u16 {
    // MIB_TCPROW_OWNER_PID stores the port in the low 16 bits in network order.
    u16::from_be((value & 0xFFFF) as u16)
}

#[cfg(windows)]
fn tcp_owner_pid(class: u32, matches: impl Fn(&[u32]) -> bool) -> Option<u32> {
    use std::ffi::c_void;
    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
    }
    const AF_INET: u32 = 2;
    const NO_ERROR: u32 = 0;
    // MIB_TCPROW_OWNER_PID: state, local addr, local port, remote addr, remote
    // port, pid - six u32s, after the table's one-u32 count.
    const ROW: usize = 6;

    let mut size = 0u32;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            class,
            0,
        );
    }
    // A little slack: the table can grow between the two calls.
    let mut buf = vec![0u32; (size as usize / 4) + 64];
    let mut size = (buf.len() * 4) as u32;
    let rc = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
            0,
            AF_INET,
            class,
            0,
        )
    };
    if rc != NO_ERROR {
        return None;
    }
    let count = (buf[0] as usize).min((buf.len() - 1) / ROW);
    (0..count).find_map(|i| {
        let row = &buf[1 + i * ROW..1 + (i + 1) * ROW];
        matches(row).then_some(row[5])
    })
}

#[cfg(windows)]
fn udp_listener_pid(addr: SocketAddr) -> Option<u32> {
    let (port, want) = match addr {
        SocketAddr::V4(a) => (a.port(), *a.ip()),
        SocketAddr::V6(_) => return None,
    };
    use std::ffi::c_void;
    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedUdpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
    }
    const AF_INET: u32 = 2;
    const UDP_TABLE_OWNER_PID: u32 = 1;
    const NO_ERROR: u32 = 0;
    // MIB_UDPROW_OWNER_PID: dwLocalAddr, dwLocalPort, dwOwningPid -
    // three u32s, after the table's one-u32 count.
    const ROW: usize = 3;

    let mut size = 0u32;
    unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    // A little slack: the table can grow between the two calls.
    let mut buf = vec![0u32; (size as usize / 4) + 64];
    let mut size = (buf.len() * 4) as u32;
    let rc = unsafe {
        GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if rc != NO_ERROR {
        return None;
    }
    let count = (buf[0] as usize).min((buf.len() - 1) / ROW);
    // Note: UDP has no LISTEN state, so every bound UDP socket is in this table.
    // That is what we want, since an exclusive bind on 0.0.0.0:53 (Windows'
    // Internet Connection Sharing does exactly this) is precisely the holder
    // we need to name.
    (0..count).find_map(|i| {
        let row = &buf[1 + i * ROW..1 + (i + 1) * ROW];
        let local_port = u16::from_be((row[1] & 0xFFFF) as u16);
        let local = Ipv4Addr::from(row[0].to_ne_bytes());
        (local_port == port && (local == want || local.is_unspecified())).then_some(row[2])
    })
}

#[cfg(windows)]
fn process_image(pid: u32) -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0;
        CloseHandle(h);
        ok.then(|| std::ffi::OsString::from_wide(&buf[..len as usize]).into())
    }
}

/// The image name of `pid`, with a tasklist fallback for inaccessible processes.
#[cfg(windows)]
fn process_name(pid: u32) -> Option<String> {
    // PID 4 is the kernel: a listener it owns is HTTP.sys, i.e. IIS or a
    // service that registered a URL with it. Its name would say nothing.
    if pid == 4 {
        return Some("служба Windows HTTP (IIS или похожая)".to_string());
    }
    if let Some(path) = process_image(pid) {
        return path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
    }
    let mut cmd = std::process::Command::new("tasklist");
    cmd.args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"]);
    let out = crate::utils::bounded_output(
        crate::utils::no_window(&mut cmd),
        std::time::Duration::from_secs(5),
    )?;
    let text = String::from_utf8_lossy(&out.stdout);
    let name = text
        .lines()
        .next()?
        .split(',')
        .next()?
        .trim_matches('"')
        .trim();
    // An image name, not tasklist's "INFO: No tasks are running…" for a PID
    // that exited between the two reads (that line has a dot too).
    name.to_ascii_lowercase()
        .ends_with(".exe")
        .then(|| name.to_string())
}

/// The port ranges Windows keeps from use for `proto`.
#[cfg(windows)]
fn excluded_ranges(proto: Proto) -> Vec<(u16, u16)> {
    let proto_arg = match proto {
        Proto::Tcp => "protocol=tcp",
        Proto::Udp => "protocol=udp",
    };
    let mut cmd = std::process::Command::new("netsh");
    cmd.args(["int", "ipv4", "show", "excludedportrange", proto_arg]);
    crate::utils::bounded_output(
        crate::utils::no_window(&mut cmd),
        std::time::Duration::from_secs(5),
    )
    .map(|out| parse_excluded_ranges(&String::from_utf8_lossy(&out.stdout)))
    .unwrap_or_default()
}

/// `netsh`'s table, in whatever language Windows speaks: every line that opens
/// with two port numbers is a range, and nothing else in its output does.
fn parse_excluded_ranges(text: &str) -> Vec<(u16, u16)> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let lo = parts.next()?.parse::<u16>().ok()?;
            let hi = parts.next()?.parse::<u16>().ok()?;
            (lo <= hi).then_some((lo, hi))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Elsewhere: no reservations, and a holder would need /proc walking that no
// field report has asked for yet.
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
fn listener_pid(_addr: SocketAddr, _proto: Proto) -> Option<u32> {
    None
}

#[cfg(not(windows))]
fn process_name(_pid: u32) -> Option<String> {
    None
}

#[cfg(not(windows))]
fn excluded_ranges(_proto: Proto) -> Vec<(u16, u16)> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netsh_ranges_are_read_in_any_language_and_nothing_else_is() {
        let english = "\nProtocol tcp Port Exclusion Ranges\n\nStart Port    End Port\n\
                       ----------    --------\n      5357        5357\n     50000       50059     *\n\
                       \n* - Administered port exclusions.\n";
        assert_eq!(
            parse_excluded_ranges(english),
            vec![(5357, 5357), (50000, 50059)]
        );
        let russian = "\nДиапазоны исключенных портов для протокола tcp\n\n\
                       Начальный порт    Конечный порт\n--------------    -------------\n\
                             53100            53199\n";
        assert_eq!(parse_excluded_ranges(russian), vec![(53100, 53199)]);
        assert!(parse_excluded_ranges("").is_empty());
        assert!(parse_excluded_ranges("  70000 70001\n  9 3\n").is_empty());
    }

    /// Live: a port this test holds is found, with this test's own name.
    #[test]
    #[cfg(windows)]
    fn a_port_we_listen_on_is_held_by_us() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let here = l.local_addr().unwrap();
        let pid = listener_pid(here, Proto::Tcp).expect("our own listener in the table");
        assert_eq!(pid, std::process::id());
        let name = process_name(pid).unwrap_or_default().to_ascii_lowercase();
        assert!(name.ends_with(".exe"), "{name}");
        // The same port on another loopback address is not in its way.
        let elsewhere = SocketAddr::from(([127, 65, 71, 9], here.port()));
        assert_eq!(listener_pid(elsewhere, Proto::Tcp), None);
    }

    #[test]
    #[cfg(windows)]
    fn an_accepted_socket_identifies_its_client() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        assert_eq!(
            client_image(&accepted).expect("loopback client image"),
            process_image(std::process::id()).expect("test image")
        );
    }

    #[test]
    #[cfg(windows)]
    fn a_udp_port_we_hold_is_found() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let here = s.local_addr().unwrap();
        let pid = listener_pid(here, Proto::Udp).expect("our own UDP socket in the table");
        assert_eq!(pid, std::process::id());
        let name = process_name(pid).unwrap_or_default().to_ascii_lowercase();
        assert!(name.ends_with(".exe"), "{name}");
        // The same port on another loopback address is not matched.
        let elsewhere = SocketAddr::from(([127, 65, 71, 9], here.port()));
        assert_eq!(listener_pid(elsewhere, Proto::Udp), None);
    }

    #[test]
    #[cfg(windows)]
    fn tcp_and_udp_tables_are_asked_separately() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        assert_eq!(listener_pid(tcp_addr, Proto::Udp), None);

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp.local_addr().unwrap();
        assert_eq!(listener_pid(udp_addr, Proto::Tcp), None);
    }
}
