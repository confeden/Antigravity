// tests/common/mod.rs
// Shared test architecture, oracles, mock servers, and contracts for ag_unlocker E2E tests.

#![allow(dead_code)]

use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// =========================================================================
// R1: Process Target Inspector & Rules
// =========================================================================

pub struct ProcessTargetInspector;

impl ProcessTargetInspector {
    pub const FORBIDDEN_IDE_TARGETS: &'static [&'static str] = &[
        "Antigravity.exe",
        "Antigravity IDE.exe",
        "Antigravity CLI.exe",
    ];

    pub const VALID_KILL_TARGETS: &'static [&'static str] = &[
        "language_server*.exe",
        "language_server.exe",
        "language_server_windows_x64.exe",
        "agy.exe",
    ];

    pub const VALID_LINUX_KILL_TARGETS: &'static [&'static str] = &[
        "language_server",
        "/agy",
    ];

    /// Verifies that no forbidden IDE shell executable is present in the kill list.
    pub fn contains_forbidden_ide_shell(targets: &[&str]) -> bool {
        targets.iter().any(|target| {
            let t = target.to_lowercase();
            Self::FORBIDDEN_IDE_TARGETS.iter().any(|f| f.to_lowercase() == t)
        })
    }

    /// Matches a process name against a pattern (supports trailing wildcard `*` or `*.exe`).
    pub fn matches_pattern(proc_name: &str, pattern: &str) -> bool {
        let p = proc_name.to_lowercase();
        let pat = pattern.to_lowercase();
        if pat.contains('*') {
            let prefix = pat.trim_end_matches(".exe").trim_end_matches('*');
            p.starts_with(prefix) && (p.ends_with(".exe") || !pat.ends_with(".exe"))
        } else {
            p == pat
        }
    }

    /// Filters running processes to identify which ones would be terminated.
    pub fn filter_to_kill(running: &[&str], kill_patterns: &[&str]) -> Vec<String> {
        running
            .iter()
            .filter(|proc| kill_patterns.iter().any(|pat| Self::matches_pattern(proc, pat)))
            .map(|s| s.to_string())
            .collect()
    }
}

// =========================================================================
// R2: Windows Registry & WinAPI Environment Management Model
// =========================================================================

pub struct RegistryConstants;

impl RegistryConstants {
    pub const HWND_BROADCAST: usize = 0xFFFF;
    pub const WM_SETTINGCHANGE: u32 = 0x001A;
    pub const SMTO_ABORTIFHUNG: u32 = 0x0002;
    pub const BROADCAST_TIMEOUT_MS: u32 = 5000;
    pub const BROADCAST_LPARAM: &'static str = "Environment";
    pub const HKCU_SUBKEY: &'static str = "Environment";
    pub const HKLM_SUBKEY: &'static str =
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment";
}

/// In-memory model simulating Windows Registry HKCU\Environment semantics.
#[derive(Clone, Default)]
pub struct MockRegistryEnv {
    user_vars: Arc<Mutex<HashMap<String, String>>>,
    machine_vars: Arc<Mutex<HashMap<String, String>>>,
    powershell_invocations: Arc<Mutex<Vec<String>>>,
    broadcast_notifications: Arc<Mutex<Vec<(usize, u32, String, u32, u32)>>>,
}

impl MockRegistryEnv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_user_var(&self, name: &str) -> Option<String> {
        let lock = self.user_vars.lock().unwrap();
        lock.get(name).cloned().filter(|s| !s.is_empty())
    }

    pub fn get_machine_var(&self, name: &str) -> Option<String> {
        let lock = self.machine_vars.lock().unwrap();
        lock.get(name).cloned().filter(|s| !s.is_empty())
    }

    pub fn set_user_var(&self, name: &str, value: Option<&str>) -> Result<(), String> {
        let mut lock = self.user_vars.lock().unwrap();
        match value {
            Some(val) => {
                lock.insert(name.to_string(), val.to_string());
            }
            None => {
                lock.remove(name);
            }
        }
        self.record_broadcast();
        Ok(())
    }

    pub fn delete_user_var(&self, name: &str) -> Result<(), String> {
        self.set_user_var(name, None)
    }

    pub fn set_machine_var(&self, name: &str, value: &str) {
        let mut lock = self.machine_vars.lock().unwrap();
        lock.insert(name.to_string(), value.to_string());
    }

    pub fn record_broadcast(&self) {
        let mut list = self.broadcast_notifications.lock().unwrap();
        list.push((
            RegistryConstants::HWND_BROADCAST,
            RegistryConstants::WM_SETTINGCHANGE,
            RegistryConstants::BROADCAST_LPARAM.to_string(),
            RegistryConstants::SMTO_ABORTIFHUNG,
            RegistryConstants::BROADCAST_TIMEOUT_MS,
        ));
    }

    pub fn broadcast_count(&self) -> usize {
        self.broadcast_notifications.lock().unwrap().len()
    }

    pub fn powershell_call_count(&self) -> usize {
        self.powershell_invocations.lock().unwrap().len()
    }

    pub fn record_powershell_call(&self, cmd: &str) {
        self.powershell_invocations.lock().unwrap().push(cmd.to_string());
    }
}

// =========================================================================
// R3: Safe Regex & JavaScript Patch Inspector
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdePatchCaptureGroups {
    pub full_match_range: (usize, usize),
    pub fname: String,
    pub var_t: String,
    pub var_t_send: String,
    pub var_y: String,
    pub var_i: String,
    pub var_func: String,
    pub var_f: String,
    pub var_h: String,
}

pub struct SafeRegexInspector;

impl SafeRegexInspector {
    pub const IDE_JS_PATTERN: &'static str = r"function\s+([a-zA-Z0-9_$]+)\s*\(\s*([a-zA-Z0-9_$]+)\s*,\s*([a-zA-Z0-9_$]+)\s*,\s*([a-zA-Z0-9_$]+)\s*\)\s*\{[^{}]*?let\s+([a-zA-Z0-9_$]+)\s*=[^{}]*?\.([a-zA-Z0-9_$]+)\s*\(\s*\{[^{}]*?\}\s*\)\s*;[^{}]*?let\s+([a-zA-Z0-9_$]+)\s*=[^{}]*?\.([a-zA-Z0-9_$]+)\s*\(\s*([a-zA-Z0-9_$]+)\s*,\s*([a-zA-Z0-9_$]+)\s*,\s*([a-zA-Z0-9_$]+)\s*\)";

    /// Safely extracts regex captures with Result::Err error propagation (eliminating unwrap).
    pub fn safe_extract_captures(content: &str) -> Result<IdePatchCaptureGroups, String> {
        let re = Regex::new(Self::IDE_JS_PATTERN)
            .map_err(|e| format!("Некорректный regex патча IDE: {}", e))?;

        let caps = re
            .captures(content)
            .ok_or_else(|| "Сигнатура не найдена (возможно, установлена другая версия)".to_string())?;

        let full = caps
            .get(0)
            .ok_or_else(|| "Не удалось получить диапазон совпадения".to_string())?;

        let fname = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "Группа 1 (fname) не найдена".to_string())?;
        let var_t = caps
            .get(2)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "Группа 2 (var_t) не найдена".to_string())?;
        let var_t_send = caps
            .get(3)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "Группа 3 (var_t_send) не найдена".to_string())?;
        let var_y = caps
            .get(4)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "Группа 4 (var_y) не найдена".to_string())?;
        let var_i = caps
            .get(7)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "Группа 7 (var_i) не найдена".to_string())?;
        let var_func = caps
            .get(8)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "Группа 8 (var_func) не найдена".to_string())?;
        let var_f = caps
            .get(9)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "Группа 9 (var_f) не найдена".to_string())?;
        let var_h = caps
            .get(10)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "Группа 10 (var_h) не найдена".to_string())?;

        Ok(IdePatchCaptureGroups {
            full_match_range: (full.start(), full.end()),
            fname,
            var_t,
            var_t_send,
            var_y,
            var_i,
            var_func,
            var_f,
            var_h,
        })
    }

    /// Checks if a JavaScript string contains the broken legacy inline JS syntax.
    pub fn contains_broken_inline_js(js: &str) -> bool {
        js.contains("...getUserStatus")
            || js.contains("...getUserStatus({})")
            || js.contains("...getUserStatus({}))")
    }

    /// Modern Desktop v2.4+ architecture detection:
    /// Language Server handles auth directly in native binary.
    pub fn is_new_desktop_architecture(content: &str) -> bool {
        content.contains("language_server")
            || content.contains("LanguageServer")
            || content.contains("cloudcode-pa")
    }
}

// =========================================================================
// R4: License Verification & Cache Oracle
// =========================================================================

pub struct LicenseOracle;

impl LicenseOracle {
    pub const BASE_SECRET: &'static str = ")Q.QFyU+oOs#Z:jmtxonGfZi+w#|XG4<";
    pub const VERSION_SEP: &'static str = "::";

    pub fn key_secret(pkg_version: &str) -> String {
        format!("{}{}{}", Self::BASE_SECRET, Self::VERSION_SEP, pkg_version)
    }

    /// Mints a valid 24-character key for a given 12-char alphanumeric nonce and version.
    pub fn mint_key(nonce: &str, pkg_version: &str) -> String {
        let n: String = nonce.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        let n = format!("{:0<12}", &n[..n.len().min(12)]).to_uppercase();
        let mut hasher = Sha256::new();
        hasher.update(n.as_bytes());
        hasher.update(Self::key_secret(pkg_version).as_bytes());
        let expected = hex::encode(hasher.finalize()).to_uppercase();
        format!("{}{}", n, &expected[..12])
    }

    /// Constant-time verification of a 24-character license key against version salt.
    pub fn verify_key(key: &str, pkg_version: &str) -> bool {
        let k: String = key.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        let k = k.to_uppercase();
        if k.len() != 24 {
            return false;
        }

        let nonce = &k[..12];
        let mut hasher = Sha256::new();
        hasher.update(nonce.as_bytes());
        hasher.update(Self::key_secret(pkg_version).as_bytes());
        let expected = hex::encode(hasher.finalize()).to_uppercase();
        let expected_sig = &expected[..12];

        let mut diff = 0u8;
        for (a, b) in k[12..].bytes().zip(expected_sig.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Normalizes user input: strips surrounding whitespace, quotes, and hyphens.
    pub fn sanitize_key_input(input: &str) -> String {
        input.trim().replace('"', "").replace('\'', "").replace('-', "")
    }
}

// =========================================================================
// R5: SOCKS5 & SOCKS5h Protocol Engine & Mock Server
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    Socks5,
    Socks5h,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSpec {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub auth: Option<String>, // "user:pass"
}

impl UpstreamSpec {
    pub fn parse(s: &str) -> Result<Self, String> {
        let raw = s.trim().trim_end_matches('/');
        if raw.is_empty() {
            return Err("пустая строка".to_string());
        }

        let (kind, rest) = if let Some(stripped) = raw.strip_prefix("socks5h://") {
            (ProxyKind::Socks5h, stripped)
        } else if let Some(stripped) = raw.strip_prefix("socks5://") {
            (ProxyKind::Socks5, stripped)
        } else if let Some(stripped) = raw.strip_prefix("http://") {
            (ProxyKind::Http, stripped)
        } else if let Some(stripped) = raw.strip_prefix("https://") {
            (ProxyKind::Http, stripped)
        } else if raw.contains("://") {
            return Err(
                "неподдерживаемый протокол прокси (поддерживаются http://, socks5://, socks5h://)"
                    .to_string(),
            );
        } else {
            (ProxyKind::Http, raw)
        };

        let (auth, host_port) = match rest.rsplit_once('@') {
            Some((cred, hp)) => {
                if !cred.contains(':') {
                    return Err("логин без пароля — нужно логин:пароль@хост:порт".to_string());
                }
                let (u, p) = cred.split_once(':').unwrap();
                if u.len() > 255 {
                    return Err("длина логина превышает 255 байт".to_string());
                }
                if p.len() > 255 {
                    return Err("длина пароля превышает 255 байт".to_string());
                }
                (Some(cred.to_string()), hp)
            }
            None => (None, rest),
        };

        let (host, port_str) = match host_port.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => return Err("не указан порт — нужно хост:порт".to_string()),
        };

        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err("не указан адрес".to_string());
        }

        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("порт «{}» не число", port_str))?;
        if port == 0 {
            return Err("порт не может быть 0".to_string());
        }

        Ok(UpstreamSpec {
            kind,
            host: host.to_string(),
            port,
            auth,
        })
    }

    pub fn as_line(&self) -> String {
        let scheme = match self.kind {
            ProxyKind::Http => "",
            ProxyKind::Socks5 => "socks5://",
            ProxyKind::Socks5h => "socks5h://",
        };
        let host_fmt = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match &self.auth {
            Some(a) => format!("{}{}{}@{}:{}", scheme, a, if scheme.is_empty() { "" } else { "" }, host_fmt, self.port),
            None => format!("{}{}:{}", scheme, host_fmt, self.port),
        }
    }

    pub fn display_masked(&self) -> String {
        let scheme = match self.kind {
            ProxyKind::Http => "http://",
            ProxyKind::Socks5 => "socks5://",
            ProxyKind::Socks5h => "socks5h://",
        };
        let auth_str = match &self.auth {
            Some(a) => {
                let user = a.split_once(':').map(|(u, _)| u).unwrap_or(a);
                format!("{}:***@", user)
            }
            None => String::new(),
        };
        format!("{}{}{}:{}", scheme, auth_str, self.host, self.port)
    }
}

/// SOCKS5 constants per RFC 1928 and RFC 1929.
pub struct Socks5Constants;

impl Socks5Constants {
    pub const VER_SOCKS5: u8 = 0x05;
    pub const METHOD_NO_AUTH: u8 = 0x00;
    pub const METHOD_GSSAPI: u8 = 0x01;
    pub const METHOD_USER_PASS: u8 = 0x02;
    pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;
    pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAINNAME: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;

    pub const REP_SUCCESS: u8 = 0x00;
    pub const REP_GENERAL_FAILURE: u8 = 0x01;
    pub const REP_CONN_NOT_ALLOWED: u8 = 0x02;
    pub const REP_NET_UNREACHABLE: u8 = 0x03;
    pub const REP_HOST_UNREACHABLE: u8 = 0x04;
    pub const REP_CONN_REFUSED: u8 = 0x05;
    pub const REP_TTL_EXPIRED: u8 = 0x06;
    pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
    pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

    pub const SUBNEG_VER_RFC1929: u8 = 0x01;
    pub const SUBNEG_STATUS_SUCCESS: u8 = 0x00;
}

#[derive(Debug, Clone)]
pub struct MockSocks5ServerConfig {
    pub require_auth: Option<(String, String)>,
    pub force_method_reject: bool,
    pub force_auth_reject: bool,
    pub reply_rep_code: u8,
    pub close_connection_prematurely: bool,
    pub echo_data: bool,
}

impl Default for MockSocks5ServerConfig {
    fn default() -> Self {
        Self {
            require_auth: None,
            force_method_reject: false,
            force_auth_reject: false,
            reply_rep_code: Socks5Constants::REP_SUCCESS,
            close_connection_prematurely: false,
            echo_data: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MockSocks5Stats {
    pub connection_count: usize,
    pub negotiated_method: Option<u8>,
    pub received_username: Option<String>,
    pub received_password: Option<String>,
    pub target_atyp: Option<u8>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub bytes_tunneled: usize,
}

pub struct MockSocks5Server {
    pub port: u16,
    shutdown: Arc<AtomicBool>,
    pub stats: Arc<Mutex<MockSocks5Stats>>,
    _handle: Option<thread::JoinHandle<()>>,
}

impl MockSocks5Server {
    pub fn start(config: MockSocks5ServerConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock socks5 listener");
        let port = listener.local_addr().unwrap().port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Mutex::new(MockSocks5Stats::default()));

        let shutdown_clone = Arc::clone(&shutdown);
        let stats_clone = Arc::clone(&stats);

        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");

        let handle = thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let cfg = config.clone();
                        let st = Arc::clone(&stats_clone);
                        let sd = Arc::clone(&shutdown_clone);
                        thread::spawn(move || {
                            Self::handle_connection(&mut stream, &cfg, &st, &sd);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            shutdown,
            stats,
            _handle: Some(handle),
        }
    }

    fn handle_connection(
        stream: &mut TcpStream,
        config: &MockSocks5ServerConfig,
        stats: &Arc<Mutex<MockSocks5Stats>>,
        shutdown: &Arc<AtomicBool>,
    ) {
        stream.set_nonblocking(false).ok();
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .ok();

        {
            let mut st = stats.lock().unwrap();
            st.connection_count += 1;
        }

        if config.close_connection_prematurely {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }

        // 1. Method negotiation
        let mut header = [0u8; 2];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        if header[0] != Socks5Constants::VER_SOCKS5 {
            return;
        }
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        if stream.read_exact(&mut methods).is_err() {
            return;
        }

        if config.force_method_reject {
            let _ = stream.write_all(&[Socks5Constants::VER_SOCKS5, Socks5Constants::METHOD_NO_ACCEPTABLE]);
            return;
        }

        let chosen_method = match &config.require_auth {
            Some(_) => {
                if methods.contains(&Socks5Constants::METHOD_USER_PASS) {
                    Socks5Constants::METHOD_USER_PASS
                } else {
                    let _ = stream.write_all(&[Socks5Constants::VER_SOCKS5, Socks5Constants::METHOD_NO_ACCEPTABLE]);
                    return;
                }
            }
            None => {
                if methods.contains(&Socks5Constants::METHOD_NO_AUTH) {
                    Socks5Constants::METHOD_NO_AUTH
                } else {
                    let _ = stream.write_all(&[Socks5Constants::VER_SOCKS5, Socks5Constants::METHOD_NO_ACCEPTABLE]);
                    return;
                }
            }
        };

        {
            let mut st = stats.lock().unwrap();
            st.negotiated_method = Some(chosen_method);
        }

        if stream.write_all(&[Socks5Constants::VER_SOCKS5, chosen_method]).is_err() {
            return;
        }

        // 2. RFC 1929 subnegotiation if chosen
        if chosen_method == Socks5Constants::METHOD_USER_PASS {
            let mut sub_ver = [0u8; 1];
            if stream.read_exact(&mut sub_ver).is_err() || sub_ver[0] != Socks5Constants::SUBNEG_VER_RFC1929 {
                return;
            }
            let mut ulen = [0u8; 1];
            if stream.read_exact(&mut ulen).is_err() {
                return;
            }
            let mut u_bytes = vec![0u8; ulen[0] as usize];
            if stream.read_exact(&mut u_bytes).is_err() {
                return;
            }
            let uname = String::from_utf8_lossy(&u_bytes).to_string();

            let mut plen = [0u8; 1];
            if stream.read_exact(&mut plen).is_err() {
                return;
            }
            let mut p_bytes = vec![0u8; plen[0] as usize];
            if stream.read_exact(&mut p_bytes).is_err() {
                return;
            }
            let passwd = String::from_utf8_lossy(&p_bytes).to_string();

            {
                let mut st = stats.lock().unwrap();
                st.received_username = Some(uname.clone());
                st.received_password = Some(passwd.clone());
            }

            let auth_ok = if config.force_auth_reject {
                false
            } else if let Some((expected_u, expected_p)) = &config.require_auth {
                &uname == expected_u && &passwd == expected_p
            } else {
                true
            };

            if auth_ok {
                let _ = stream.write_all(&[Socks5Constants::SUBNEG_VER_RFC1929, Socks5Constants::SUBNEG_STATUS_SUCCESS]);
            } else {
                let _ = stream.write_all(&[Socks5Constants::SUBNEG_VER_RFC1929, 0x01]);
                return;
            }
        }

        // 3. CONNECT Request
        let mut req_header = [0u8; 4];
        if stream.read_exact(&mut req_header).is_err() {
            return;
        }
        if req_header[0] != Socks5Constants::VER_SOCKS5 || req_header[1] != Socks5Constants::CMD_CONNECT {
            return;
        }
        let atyp = req_header[3];

        let target_host = match atyp {
            Socks5Constants::ATYP_IPV4 => {
                let mut ip_bytes = [0u8; 4];
                if stream.read_exact(&mut ip_bytes).is_err() {
                    return;
                }
                Ipv4Addr::from(ip_bytes).to_string()
            }
            Socks5Constants::ATYP_DOMAINNAME => {
                let mut len = [0u8; 1];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let mut domain = vec![0u8; len[0] as usize];
                if stream.read_exact(&mut domain).is_err() {
                    return;
                }
                String::from_utf8_lossy(&domain).to_string()
            }
            Socks5Constants::ATYP_IPV6 => {
                let mut ip_bytes = [0u8; 16];
                if stream.read_exact(&mut ip_bytes).is_err() {
                    return;
                }
                Ipv6Addr::from(ip_bytes).to_string()
            }
            _ => return,
        };

        let mut port_bytes = [0u8; 2];
        if stream.read_exact(&mut port_bytes).is_err() {
            return;
        }
        let target_port = u16::from_be_bytes(port_bytes);

        {
            let mut st = stats.lock().unwrap();
            st.target_atyp = Some(atyp);
            st.target_host = Some(target_host);
            st.target_port = Some(target_port);
        }

        // 4. Server Reply
        let reply_rep = config.reply_rep_code;
        let reply = vec![
            Socks5Constants::VER_SOCKS5,
            reply_rep,
            0x00, // RSV
            Socks5Constants::ATYP_IPV4,
            127, 0, 0, 1, // BND.ADDR
            0x10, 0x80,   // BND.PORT
        ];

        if stream.write_all(&reply).is_err() || reply_rep != Socks5Constants::REP_SUCCESS {
            stream.flush().ok();
            return;
        }
        stream.flush().ok();

        // 5. Echo or relay traffic
        let mut buf = [0u8; 1024];
        if config.echo_data {
            while !shutdown.load(Ordering::Relaxed) {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Ok(mut st) = stats.try_lock() {
                            st.bytes_tunneled += n;
                        }
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        stream.flush().ok();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        } else {
            // Drain until client closes (EOF) or server shuts down
            while !shutdown.load(Ordering::Relaxed) {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Ok(mut st) = stats.try_lock() {
                            st.bytes_tunneled += n;
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        }
        stream.flush().ok();
    }
}

impl Drop for MockSocks5Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// SOCKS5 Client Implementation conforming to RFC 1928 and RFC 1929 for testing.
pub struct Socks5Client;

impl Socks5Client {
    pub fn connect(
        proxy_addr: SocketAddr,
        target_host: &str,
        target_port: u16,
        is_remote_dns: bool,
        auth: Option<(&str, &str)>,
        timeout: Duration,
    ) -> Result<TcpStream, String> {
        let deadline = Instant::now() + timeout;

        let mut sock = TcpStream::connect_timeout(&proxy_addr, timeout)
            .map_err(|e| format!("ошибка подключения к SOCKS5: {}", e))?;

        sock.set_read_timeout(Some(timeout)).ok();
        sock.set_write_timeout(Some(timeout)).ok();

        // 1. Method Greeting
        let greeting = match auth {
            Some(_) => vec![
                Socks5Constants::VER_SOCKS5,
                2,
                Socks5Constants::METHOD_NO_AUTH,
                Socks5Constants::METHOD_USER_PASS,
            ],
            None => vec![Socks5Constants::VER_SOCKS5, 1, Socks5Constants::METHOD_NO_AUTH],
        };

        sock.write_all(&greeting)
            .map_err(|e| format!("ошибка отправки приветствия: {}", e))?;

        let mut method_reply = [0u8; 2];
        sock.read_exact(&mut method_reply)
            .map_err(|e| format!("прокси закрыл соединение: {}", e))?;

        if method_reply[0] != Socks5Constants::VER_SOCKS5 {
            return Err("неверная версия SOCKS-сервера".to_string());
        }
        let method = method_reply[1];
        if method == Socks5Constants::METHOD_NO_ACCEPTABLE {
            return Err("прокси отклонил методы аутентификации (0xFF)".to_string());
        }

        // 2. RFC 1929 Auth
        if method == Socks5Constants::METHOD_USER_PASS {
            let (user, pass) = auth.ok_or_else(|| "прокси требует аутентификацию".to_string())?;
            let u_bytes = user.as_bytes();
            let p_bytes = pass.as_bytes();
            if u_bytes.len() > 255 || p_bytes.len() > 255 {
                return Err("логин или пароль превышает 255 байт".to_string());
            }

            let mut auth_req = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
            auth_req.push(Socks5Constants::SUBNEG_VER_RFC1929);
            auth_req.push(u_bytes.len() as u8);
            auth_req.extend_from_slice(u_bytes);
            auth_req.push(p_bytes.len() as u8);
            auth_req.extend_from_slice(p_bytes);

            sock.write_all(&auth_req)
                .map_err(|e| format!("ошибка отправки учетных данных: {}", e))?;

            let mut auth_resp = [0u8; 2];
            sock.read_exact(&mut auth_resp)
                .map_err(|e| format!("ошибка чтения ответа аутентификации: {}", e))?;

            if auth_resp[0] != Socks5Constants::SUBNEG_VER_RFC1929 {
                return Err("неверная версия ответа аутентификации SOCKS".to_string());
            }
            if auth_resp[1] != Socks5Constants::SUBNEG_STATUS_SUCCESS {
                return Err(format!(
                    "неверный логин или пароль SOCKS-прокси (статус 0x{:02X})",
                    auth_resp[1]
                ));
            }
        } else if method != Socks5Constants::METHOD_NO_AUTH {
            return Err(format!("неподдерживаемый метод аутентификации: 0x{:02X}", method));
        }

        // 3. CONNECT Command
        let mut connect_req = Vec::with_capacity(256);
        connect_req.push(Socks5Constants::VER_SOCKS5);
        connect_req.push(Socks5Constants::CMD_CONNECT);
        connect_req.push(0x00); // RSV

        let ip_parsed = target_host.parse::<IpAddr>().ok();

        if is_remote_dns && ip_parsed.is_none() {
            // SOCKS5h: DOMAINNAME
            let host_bytes = target_host.as_bytes();
            if host_bytes.len() > 255 {
                return Err("длина домена превышает 255 байт".to_string());
            }
            connect_req.push(Socks5Constants::ATYP_DOMAINNAME);
            connect_req.push(host_bytes.len() as u8);
            connect_req.extend_from_slice(host_bytes);
        } else {
            match ip_parsed {
                Some(IpAddr::V4(v4)) => {
                    connect_req.push(Socks5Constants::ATYP_IPV4);
                    connect_req.extend_from_slice(&v4.octets());
                }
                Some(IpAddr::V6(v6)) => {
                    connect_req.push(Socks5Constants::ATYP_IPV6);
                    connect_req.extend_from_slice(&v6.octets());
                }
                None => {
                    // Fallback to domain
                    let host_bytes = target_host.as_bytes();
                    connect_req.push(Socks5Constants::ATYP_DOMAINNAME);
                    connect_req.push(host_bytes.len() as u8);
                    connect_req.extend_from_slice(host_bytes);
                }
            }
        }

        connect_req.extend_from_slice(&target_port.to_be_bytes());

        sock.write_all(&connect_req)
            .map_err(|e| format!("ошибка отправки запроса CONNECT: {}", e))?;

        // 4. Read Reply
        let mut reply_head = [0u8; 4];
        sock.read_exact(&mut reply_head)
            .map_err(|e| format!("ошибка чтения ответа CONNECT: {}", e))?;

        if reply_head[0] != Socks5Constants::VER_SOCKS5 {
            return Err("неверная версия в ответе CONNECT".to_string());
        }

        let rep = reply_head[1];
        if rep != Socks5Constants::REP_SUCCESS {
            let desc = match rep {
                Socks5Constants::REP_CONN_NOT_ALLOWED => "соединение запрещено правилами SOCKS-сервера",
                Socks5Constants::REP_NET_UNREACHABLE => "сеть недоступна",
                Socks5Constants::REP_HOST_UNREACHABLE => "целевой хост недоступен",
                Socks5Constants::REP_CONN_REFUSED => "соединение отклонено целевым узлом",
                Socks5Constants::REP_TTL_EXPIRED => "время жизни пакета (TTL) истекло",
                Socks5Constants::REP_CMD_NOT_SUPPORTED => "команда не поддерживается SOCKS-сервером",
                Socks5Constants::REP_ATYP_NOT_SUPPORTED => "тип адреса не поддерживается SOCKS-сервером",
                _ => "общая ошибка SOCKS-сервера",
            };
            return Err(format!("{} (код 0x{:02X})", desc, rep));
        }

        // Drain BND.ADDR and BND.PORT
        let bnd_atyp = reply_head[3];
        match bnd_atyp {
            Socks5Constants::ATYP_IPV4 => {
                let mut bnd = [0u8; 6];
                sock.read_exact(&mut bnd)
                    .map_err(|e| format!("ошибка чтения IPv4 bnd: {}", e))?;
            }
            Socks5Constants::ATYP_DOMAINNAME => {
                let mut dlen = [0u8; 1];
                sock.read_exact(&mut dlen)
                    .map_err(|e| format!("ошибка чтения domain bnd len: {}", e))?;
                let mut domain = vec![0u8; dlen[0] as usize + 2];
                sock.read_exact(&mut domain)
                    .map_err(|e| format!("ошибка чтения domain bnd: {}", e))?;
            }
            Socks5Constants::ATYP_IPV6 => {
                let mut bnd = [0u8; 18];
                sock.read_exact(&mut bnd)
                    .map_err(|e| format!("ошибка чтения IPv6 bnd: {}", e))?;
            }
            _ => return Err(format!("неизвестный ATYP привязки: 0x{:02X}", bnd_atyp)),
        }

        // 5. Clean up timeouts before returning
        sock.set_read_timeout(None).ok();
        sock.set_write_timeout(None).ok();

        if Instant::now() > deadline {
            return Err("прокси не ответил вовремя".to_string());
        }

        Ok(sock)
    }
}
