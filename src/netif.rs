//! Interfaces and the default route on Linux and macOS: the questions the
//! Windows build asks PowerShell (`egress::detect`) and iphlpapi
//! (`net::best_interface`), answered natively.
//!
//! Two questions, kept apart on purpose:
//! - **where the routing table sends a packet** (`best_interface`) - a UDP
//!   socket `connect`ed to a public address and asked for its local address.
//!   Nothing is sent. It goes through the kernel's own lookup, policy rules
//!   included, so a wg-quick tunnel (its default route sits in table 51820, not
//!   in main) and an OpenVPN `0/1 + 128/1` pair are both seen as the tunnel.
//! - **which link is the ISP's** (`isp_interface`) - the default route that
//!   belongs to a non-tunnel interface: `/proc/net/route` on Linux (the main
//!   table, which a tunnel's policy routing leaves alone), `netstat -rn` on
//!   macOS (which lists the scoped default a VPN pushes aside).
//!
//! A tunnel is a point-to-point interface, a Linux interface whose hardware type
//! is not Ethernet-like (WireGuard and tun are ARPHRD_NONE, PPP is 512), or one
//! named like a VPN's. Deliberately not "has no `/sys/class/net/X/device`": a
//! bridge carrying the real NIC is the ISP link on some desktops.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// Any public address: only ever used for a route lookup, never contacted.
const PROBE_DEST: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

#[derive(Debug, Clone)]
pub struct Iface {
    pub name: String,
    pub index: u32,
    pub v4: Vec<Ipv4Addr>,
    pub flags: u32,
}

/// Every interface with its IPv4 addresses. Empty when `getifaddrs` fails.
pub fn interfaces() -> Vec<Iface> {
    let mut out: Vec<Iface> = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free below and never keep.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: a node of the list getifaddrs returned, alive until freeifaddrs.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: a NUL-terminated name owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let v4 = if ifa.ifa_addr.is_null() {
            None
        } else {
            // SAFETY: ifa_addr points at a sockaddr; its family says how to read it.
            let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
            (family == libc::AF_INET).then(|| {
                // SAFETY: AF_INET means the sockaddr is a sockaddr_in.
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))
            })
        };
        let pos = match out.iter().position(|i| i.name == name) {
            Some(p) => p,
            None => {
                // SAFETY: the same NUL-terminated name.
                let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
                out.push(Iface {
                    name,
                    index,
                    v4: Vec::new(),
                    flags: ifa.ifa_flags as u32,
                });
                out.len() - 1
            }
        };
        if let Some(a) = v4 {
            out[pos].v4.push(a);
        }
    }
    // SAFETY: the list getifaddrs allocated, freed once.
    unsafe { libc::freeifaddrs(head) };
    out
}

/// The local address the routing table would send a packet to `dest` from.
fn local_addr_toward(dest: Ipv4Addr) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.connect(SocketAddr::from((dest, 53))).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(a) if !a.is_unspecified() => Some(a),
        _ => None,
    }
}

fn owner_of(addr: Ipv4Addr, ifaces: &[Iface]) -> Option<&Iface> {
    ifaces.iter().find(|i| i.index != 0 && i.v4.contains(&addr))
}

/// The interface the routing table would send a packet to `dest` through.
pub fn best_interface(dest: Ipv4Addr) -> Option<u32> {
    let addr = local_addr_toward(dest)?;
    owner_of(addr, &interfaces()).map(|i| i.index)
}

/// Name prefixes VPN clients give their interfaces. A backstop for the flag and
/// type checks, never the only evidence on Linux.
const TUNNEL_PREFIXES: &[&str] = &[
    "tun",
    "tap",
    "wg",
    "ppp",
    "utun",
    "ipsec",
    "awg",
    "amn",
    "nordlynx",
    "proton",
    "tailscale",
    "zt",
    "vpn",
    "outline",
    "gpd",
    "cscotun",
];

fn named_like_tunnel(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    TUNNEL_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// Linux hardware types that are not a link to a router: none (WireGuard, tun),
/// PPP, IPIP, IPv6-in-IPv4, GRE, IP6GRE.
#[cfg(target_os = "linux")]
fn tunnel_hw_type(name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{}/type", name))
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
        .is_some_and(|t| matches!(t, 65534 | 512 | 768 | 769 | 776 | 778 | 823))
}

#[cfg(not(target_os = "linux"))]
fn tunnel_hw_type(_: &str) -> bool {
    false
}

pub fn is_tunnel(iface: &Iface) -> bool {
    iface.flags & libc::IFF_POINTOPOINT as u32 != 0
        || tunnel_hw_type(&iface.name)
        || named_like_tunnel(&iface.name)
}

fn is_tunnel_name(name: &str, ifaces: &[Iface]) -> bool {
    match ifaces.iter().find(|i| i.name == name) {
        Some(i) => is_tunnel(i),
        None => named_like_tunnel(name),
    }
}

/// Default-route interfaces from `/proc/net/route`, lowest metric first.
/// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
#[cfg(target_os = "linux")]
fn default_route_ifaces() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    parse_proc_route(&text)
}

/// RTF_UP | RTF_GATEWAY, destination and mask 0: a default route with a next
/// hop. A route without a gateway is a tunnel's or a host-only link's.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_route(text: &str) -> Vec<String> {
    let mut rows: Vec<(u32, String)> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
                return None;
            }
            let flags = u32::from_str_radix(f[3], 16).ok()?;
            if flags & 0x3 != 0x3 {
                return None;
            }
            Some((f[6].parse().unwrap_or(u32::MAX), f[0].to_string()))
        })
        .collect();
    rows.sort_by_key(|r| r.0);
    rows.into_iter().map(|r| r.1).collect()
}

/// Default-route interfaces from `netstat -rn -f inet`, in the table's order.
#[cfg(target_os = "macos")]
fn default_route_ifaces() -> Vec<String> {
    let Ok(out) = std::process::Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    parse_netstat(&String::from_utf8_lossy(&out.stdout))
}

/// `default  192.168.1.1  UGScg  en0` - a gateway flag and an interface. A
/// tunnel's own default (`default  link#20  UCSI  utun3`) has no `G`.
#[cfg(any(target_os = "macos", test))]
fn parse_netstat(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            (f.len() >= 4 && f[0] == "default" && f[2].contains('G')).then(|| f[3].to_string())
        })
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn default_route_ifaces() -> Vec<String> {
    Vec::new()
}

/// The ISP link and whether a tunnel holds the default route, or `None` when
/// there is no non-tunnel default route at all (no network yet, or a tunnel-only
/// setup this cannot see past).
pub fn egress() -> Option<(u32, bool)> {
    let ifaces = interfaces();
    let index_of = |name: &str| {
        ifaces
            .iter()
            .find(|i| i.name == name)
            .map(|i| i.index)
            .filter(|&i| i != 0)
    };
    let best = local_addr_toward(PROBE_DEST).and_then(|a| owner_of(a, &ifaces).cloned());
    let isp = default_route_ifaces()
        .into_iter()
        .find(|name| !is_tunnel_name(name, &ifaces))
        .and_then(|name| index_of(&name))
        // No readable table: the interface the packet leaves through is the
        // ISP link whenever it is not a tunnel.
        .or_else(|| best.as_ref().filter(|b| !is_tunnel(b)).map(|b| b.index))?;
    let vpn = best
        .as_ref()
        .is_some_and(|b| b.index != isp && is_tunnel(b));
    Some((isp, vpn))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_route_keeps_gatewayed_defaults_by_metric() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\
tun0\t00000080\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0\n\
eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_route(text), vec!["eth0", "wlan0"]);
    }

    #[test]
    fn netstat_skips_a_tunnels_gatewayless_default() {
        let text = "Routing tables\n\nInternet:\n\
Destination        Gateway            Flags               Netif Expire\n\
default            link#22            UCSg                utun4\n\
default            192.168.1.1        UGScIg                en0\n\
127                127.0.0.1          UCS                   lo0\n";
        assert_eq!(parse_netstat(text), vec!["en0"]);
    }

    #[test]
    fn vpn_names_are_tunnels_and_nics_are_not() {
        for n in [
            "wg0",
            "tun0",
            "utun3",
            "ppp0",
            "nordlynx",
            "tailscale0",
            "awg0",
        ] {
            assert!(named_like_tunnel(n), "{}", n);
        }
        for n in ["eth0", "en0", "wlan0", "enp3s0", "wlp2s0", "br0"] {
            assert!(!named_like_tunnel(n), "{}", n);
        }
    }

    /// Live: what this machine reports. `cargo test netif_live -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn netif_live() {
        for i in interfaces() {
            println!(
                "{:>3} {:<12} {:?} tunnel={}",
                i.index,
                i.name,
                i.v4,
                is_tunnel(&i)
            );
        }
        println!("best: {:?}", best_interface(PROBE_DEST));
        println!("defaults: {:?}", default_route_ifaces());
        println!("egress (isp, vpn): {:?}", egress());
    }
}
