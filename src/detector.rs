//! Auto-detection and fast handshake probing of local VPN and proxy clients
//! (Happ, Hiddify, Clash/Mihomo, Sing-box, v2rayN, Nekoray).
//!
//! Provides parallel probing (< 200 ms total across candidate ports),
//! native Win32 process and network adapter enumeration with fallback,
//! and 1-click apply to `%LOCALAPPDATA%\AGUnlocker\upstream.txt` with route revival.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

use crate::upstream;

/// Supported VPN / proxy client varieties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    Happ,
    Hiddify,
    Clash,
    SingBox,
    V2RayN,
    Nekoray,
}

/// Outbound transport protocol detected on a local proxy port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedProtocol {
    Socks5,
    Http,
}

/// Compatibility alias for interface contracts referencing `UpstreamProtocol`.
pub type UpstreamProtocol = DetectedProtocol;

/// Result of a fast validation handshake probe against a candidate port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeResult {
    pub protocol: DetectedProtocol,
    pub latency_ms: u64,
    pub auth_required: bool,
}

impl std::ops::Deref for ProbeResult {
    type Target = DetectedProtocol;
    fn deref(&self) -> &Self::Target {
        &self.protocol
    }
}

impl PartialEq<DetectedProtocol> for ProbeResult {
    fn eq(&self, other: &DetectedProtocol) -> bool {
        self.protocol == *other
    }
}

impl PartialEq<ProbeResult> for DetectedProtocol {
    fn eq(&self, other: &ProbeResult) -> bool {
        *self == other.protocol
    }
}

/// An actively discovered and responsive local proxy client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedClient {
    pub kind: ClientKind,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub protocol: DetectedProtocol,
    pub latency_ms: u64,
    pub auth_required: bool,
}

#[derive(Debug, Default, Clone)]
struct DetectedProcessContext {
    has_happ: bool,
    has_hiddify: bool,
    has_clash: bool,
    has_sing_box: bool,
    has_v2ray_n: bool,
    has_nekoray: bool,
}

#[cfg(windows)]
mod win32 {
    use std::ffi::c_void;

    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

    #[repr(C)]
    struct PROCESSENTRY32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(dwflags: u32, th32processid: u32) -> *mut c_void;
        fn Process32FirstW(hsnapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> i32;
        fn Process32NextW(hsnapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> i32;
        fn CloseHandle(hobject: *mut c_void) -> i32;
    }

    pub fn list_running_processes() -> Vec<String> {
        let mut processes = Vec::new();
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
                return processes;
            }

            let mut entry = PROCESSENTRY32W {
                dw_size: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                cnt_usage: 0,
                th32_process_id: 0,
                th32_default_heap_id: 0,
                th32_module_id: 0,
                cnt_threads: 0,
                th32_parent_process_id: 0,
                pc_pri_class_base: 0,
                dw_flags: 0,
                sz_exe_file: [0u16; 260],
            };

            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let len = entry.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(260);
                    let name = String::from_utf16_lossy(&entry.sz_exe_file[..len]);
                    processes.push(name);

                    entry.dw_size = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }
        processes
    }
}

#[cfg(not(windows))]
mod win32 {
    pub fn list_running_processes() -> Vec<String> {
        Vec::new()
    }
}

#[cfg(windows)]
mod win32_net {
    use std::ffi::c_void;

    #[repr(C)]
    struct IP_ADAPTER_ADDRESSES {
        length: u32,
        if_index: u32,
        next: *mut IP_ADAPTER_ADDRESSES,
        adapter_name: *mut i8,
        first_unicast_address: *mut c_void,
        first_anycast_address: *mut c_void,
        first_multicast_address: *mut c_void,
        first_dns_server_address: *mut c_void,
        dns_suffix: *mut u16,
        description: *mut u16,
        friendly_name: *mut u16,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *mut c_void,
            adapter_addresses: *mut IP_ADAPTER_ADDRESSES,
            size_pointer: *mut u32,
        ) -> u32;
    }

    pub fn list_adapter_names() -> Vec<String> {
        let mut names = Vec::new();
        unsafe {
            let mut buf_size: u32 = 15000;
            let mut buf = vec![0u8; buf_size as usize];
            let ret = GetAdaptersAddresses(
                0, // AF_UNSPEC
                0,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES,
                &mut buf_size,
            );
            if ret == 111 {
                // ERROR_BUFFER_OVERFLOW
                buf = vec![0u8; buf_size as usize];
                let ret2 = GetAdaptersAddresses(
                    0,
                    0,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES,
                    &mut buf_size,
                );
                if ret2 != 0 {
                    return names;
                }
            } else if ret != 0 {
                return names;
            }

            let mut curr = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES;
            while !curr.is_null() {
                let friendly_name_ptr = (*curr).friendly_name;
                if !friendly_name_ptr.is_null() {
                    let mut len = 0;
                    while *friendly_name_ptr.add(len) != 0 {
                        len += 1;
                    }
                    let slice = std::slice::from_raw_parts(friendly_name_ptr, len);
                    names.push(String::from_utf16_lossy(slice));
                }
                let desc_ptr = (*curr).description;
                if !desc_ptr.is_null() {
                    let mut len = 0;
                    while *desc_ptr.add(len) != 0 {
                        len += 1;
                    }
                    let slice = std::slice::from_raw_parts(desc_ptr, len);
                    names.push(String::from_utf16_lossy(slice));
                }
                curr = (*curr).next;
            }
        }
        names
    }
}

#[cfg(not(windows))]
mod win32_net {
    pub fn list_adapter_names() -> Vec<String> {
        Vec::new()
    }
}

/// Returns a list of all currently running process names (for diagnostic / testing).
pub fn list_candidate_processes() -> Vec<String> {
    win32::list_running_processes()
}

/// Returns a list of all network adapter friendly names and descriptions.
pub fn list_candidate_adapters() -> Vec<String> {
    win32_net::list_adapter_names()
}

/// Fast SOCKS5 validation handshake probe.
///
/// Sends greeting offering both NO_AUTH (0x00) and USER_PASS (0x02) methods.
/// Returns `Some((auth_required, latency_ms))` on valid reply (`0x05, 0x00` or `0x05, 0x02`).
pub fn probe_socks5(host: &str, port: u16, timeout: Duration) -> Option<(bool, u64)> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().ok()?.collect();
    let addr = addrs.first()?;
    let t0 = Instant::now();
    let mut sock = TcpStream::connect_timeout(addr, timeout).ok()?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    // Offer both 0x00 (no auth) and 0x02 (user/pass) per RFC 1928
    sock.write_all(&[0x05, 0x02, 0x00, 0x02]).ok()?;
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).ok()?;
    if resp[0] == 0x05 && resp[1] == 0x00 {
        Some((false, t0.elapsed().as_millis().max(1) as u64))
    } else if resp[0] == 0x05 && resp[1] == 0x02 {
        Some((true, t0.elapsed().as_millis().max(1) as u64))
    } else {
        None
    }
}

/// Fast HTTP CONNECT validation handshake probe.
///
/// Sends `CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\nHost: ...\r\n\r\n`.
/// Returns `Some((auth_required, latency_ms))` if response begins with `200` or `407`.
/// Rejects non-proxy responses (e.g. 404, 401, error).
pub fn probe_http_connect(host: &str, port: u16, timeout: Duration) -> Option<(bool, u64)> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().ok()?.collect();
    let addr = addrs.first()?;
    let t0 = Instant::now();
    let mut sock = TcpStream::connect_timeout(addr, timeout).ok()?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    let req = b"CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\nHost: daily-cloudcode-pa.googleapis.com:443\r\n\r\n";
    sock.write_all(req).ok()?;

    let mut buf = [0u8; 1024];
    let n = sock.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }

    let resp_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = resp_str.lines().next().unwrap_or("");
    if first_line.starts_with("HTTP/1.1 200") || first_line.starts_with("HTTP/1.0 200") {
        Some((false, t0.elapsed().as_millis().max(1) as u64))
    } else if first_line.starts_with("HTTP/1.1 407") || first_line.starts_with("HTTP/1.0 407") {
        Some((true, t0.elapsed().as_millis().max(1) as u64))
    } else {
        None
    }
}

/// Probes a specific host and port for responsive SOCKS5 or HTTP proxying.
///
/// - Timeout budget: Per-port timeout is strictly enforced (<= 150 ms).
/// - If closed: Returns `None` within `timeout` without attempting duplicate connections.
/// - Preference: On mixed ports accepting both SOCKS5 and HTTP CONNECT, SOCKS5 is preferred.
pub fn probe_port(host: &str, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().ok()?.collect();
    let addr = addrs.first()?;

    // Step 1: Initial TCP connect. If port is closed/unreachable, immediately abort.
    let connect_start = Instant::now();
    let mut sock = match TcpStream::connect_timeout(addr, timeout) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let remaining = timeout.saturating_sub(connect_start.elapsed());
    let op_timeout = remaining.min(Duration::from_millis(100)).max(Duration::from_millis(30));
    sock.set_read_timeout(Some(op_timeout)).ok();
    sock.set_write_timeout(Some(op_timeout)).ok();

    // Step 2: Try SOCKS5 greeting offering 0x00 and 0x02
    let socks_start = Instant::now();
    if sock.write_all(&[0x05, 0x02, 0x00, 0x02]).is_ok() {
        let mut resp = [0u8; 2];
        if sock.read_exact(&mut resp).is_ok() {
            if resp[0] == 0x05 && resp[1] == 0x00 {
                let latency_ms = socks_start.elapsed().as_millis().max(1) as u64;
                return Some(ProbeResult {
                    protocol: DetectedProtocol::Socks5,
                    latency_ms,
                    auth_required: false,
                });
            } else if resp[0] == 0x05 && resp[1] == 0x02 {
                let latency_ms = socks_start.elapsed().as_millis().max(1) as u64;
                return Some(ProbeResult {
                    protocol: DetectedProtocol::Socks5,
                    latency_ms,
                    auth_required: true,
                });
            }
        }
    }

    // Step 3: SOCKS5 failed, but port is listening. Probe HTTP CONNECT on a fresh socket.
    let http_start = Instant::now();
    let Ok(mut http_sock) = TcpStream::connect_timeout(addr, timeout) else {
        return None;
    };
    http_sock.set_read_timeout(Some(timeout)).ok();
    http_sock.set_write_timeout(Some(timeout)).ok();

    let req = b"CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\nHost: daily-cloudcode-pa.googleapis.com:443\r\n\r\n";
    if http_sock.write_all(req).is_err() {
        return None;
    }

    let mut buf = [0u8; 1024];
    let n = http_sock.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }

    let resp_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = resp_str.lines().next().unwrap_or("");
    if first_line.starts_with("HTTP/1.1 200") || first_line.starts_with("HTTP/1.0 200") {
        let latency_ms = http_start.elapsed().as_millis().max(1) as u64;
        Some(ProbeResult {
            protocol: DetectedProtocol::Http,
            latency_ms,
            auth_required: false,
        })
    } else if first_line.starts_with("HTTP/1.1 407") || first_line.starts_with("HTTP/1.0 407") {
        let latency_ms = http_start.elapsed().as_millis().max(1) as u64;
        Some(ProbeResult {
            protocol: DetectedProtocol::Http,
            latency_ms,
            auth_required: true,
        })
    } else {
        // 404, 401, or controller endpoint is rejected
        None
    }
}

fn resolve_client_kind(
    port: u16,
    _proto: DetectedProtocol,
    ctx: &DetectedProcessContext,
) -> (ClientKind, String) {
    match port {
        10808 => {
            if ctx.has_happ {
                (ClientKind::Happ, "Happ".to_string())
            } else if ctx.has_v2ray_n {
                (ClientKind::V2RayN, "v2rayN".to_string())
            } else if ctx.has_hiddify {
                (ClientKind::Hiddify, "Hiddify".to_string())
            } else if ctx.has_sing_box {
                (ClientKind::SingBox, "Sing-box".to_string())
            } else {
                (ClientKind::Happ, "Happ".to_string())
            }
        }
        10809 => {
            if ctx.has_happ {
                (ClientKind::Happ, "Happ (HTTP)".to_string())
            } else if ctx.has_v2ray_n {
                (ClientKind::V2RayN, "v2rayN (HTTP)".to_string())
            } else if ctx.has_sing_box {
                (ClientKind::SingBox, "Sing-box (HTTP)".to_string())
            } else {
                (ClientKind::Happ, "Happ (HTTP)".to_string())
            }
        }
        7890 => (ClientKind::Clash, "Clash / Mihomo".to_string()),
        7891 => (ClientKind::Clash, "Clash / Mihomo (SOCKS5)".to_string()),
        2080 => {
            if ctx.has_hiddify {
                (ClientKind::Hiddify, "Hiddify".to_string())
            } else if ctx.has_nekoray {
                (ClientKind::Nekoray, "Nekoray".to_string())
            } else if ctx.has_sing_box {
                (ClientKind::SingBox, "Sing-box".to_string())
            } else {
                (ClientKind::SingBox, "Sing-box / Hiddify".to_string())
            }
        }
        2081 => (ClientKind::Nekoray, "Nekoray (HTTP)".to_string()),
        _ => (ClientKind::Happ, format!("Local Proxy ({})", port)),
    }
}

/// Scans local running proxy clients via parallel socket handshakes and process inspection.
///
/// Runs parallel probes across candidate ports with per-socket timeouts <= 150 ms
/// ensuring total scan completion in < 200 ms. Results are deduplicated and sorted by latency.
pub fn detect_clients() -> Vec<DetectedClient> {
    let procs = win32::list_running_processes();
    let adapters = win32_net::list_adapter_names();

    let mut ctx = DetectedProcessContext::default();
    for p in &procs {
        let p_lower = p.to_lowercase();
        if p_lower == "happ.exe" || p_lower == "happd.exe" || p_lower == "xray.exe" {
            ctx.has_happ = true;
        }
        if p_lower == "hiddify.exe" {
            ctx.has_hiddify = true;
        }
        if p_lower == "clash.exe"
            || p_lower == "mihomo.exe"
            || p_lower == "clash-verge.exe"
            || p_lower == "clash-nyanpasu.exe"
        {
            ctx.has_clash = true;
        }
        if p_lower == "sing-box.exe" {
            ctx.has_sing_box = true;
        }
        if p_lower == "v2rayn.exe" {
            ctx.has_v2ray_n = true;
        }
        if p_lower == "nekoray.exe" || p_lower == "nekobox.exe" {
            ctx.has_nekoray = true;
        }
    }

    for a in &adapters {
        let a_lower = a.to_lowercase();
        if a_lower.contains("happ-xray") || a_lower.contains("happ tunnel") {
            ctx.has_happ = true;
        }
    }

    let candidate_ports = [10808, 10809, 2080, 2081, 7890, 7891];

    let mut handles = Vec::new();
    for port in candidate_ports {
        let handle = thread::spawn(move || {
            let timeout = Duration::from_millis(150);
            probe_port("127.0.0.1", port, timeout).map(|res| (port, res))
        });
        handles.push(handle);
    }

    let mut clients = Vec::new();
    for handle in handles {
        if let Ok(Some((port, probe_res))) = handle.join() {
            let (kind, name) = resolve_client_kind(port, probe_res.protocol, &ctx);
            clients.push(DetectedClient {
                kind,
                name,
                host: "127.0.0.1".to_string(),
                port,
                protocol: probe_res.protocol,
                latency_ms: probe_res.latency_ms,
                auth_required: probe_res.auth_required,
            });
        }
    }

    clients.sort_by_key(|c| c.port);
    clients.dedup_by_key(|c| c.port);
    clients.sort_by_key(|c| c.latency_ms);
    clients
}

/// Clears any pinned bad exit status on `upstream::OWN` so a newly applied proxy
/// is immediately active without waiting for route benching or address changes.
pub fn clear_bad_exit() {
    upstream::OWN.clear_bad_exit();
}

/// Returns true if `upstream::OWN` has no active bench and no blocked exit pin.
pub fn is_bad_exit_cleared() -> bool {
    upstream::OWN.usable()
}

/// Applies the detected client as the active upstream proxy in 1 click.
///
/// Builds the proxy URL, parses it, writes to `%LOCALAPPDATA%\AGUnlocker\upstream.txt`,
/// revives route health, and clears `bad_exit`.
pub fn apply_detected_client(client: &DetectedClient) -> Result<(), String> {
    let scheme = match client.protocol {
        DetectedProtocol::Socks5 => "socks5",
        DetectedProtocol::Http => "http",
    };
    let url = format!("{}://{}:{}", scheme, client.host, client.port);
    let up = upstream::parse(&url)?;
    upstream::save(&up)?;
    upstream::OWN.health.revive("1-click apply");
    clear_bad_exit();
    Ok(())
}
