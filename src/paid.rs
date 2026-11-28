//! Paid gateway transport. Relay ports preserve the primary gateway's TLS identity.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection};
use serde::{Deserialize, Serialize};

const PRIMARY: &str = "eu1-aiu.nova-app.eu";
const RELAY: &str = "ru1.relay-aiu.nova-app.eu";
const ROUTES: [(&str, u16); 4] = [(PRIMARY, 443), (PRIMARY, 8443), (RELAY, 443), (RELAY, 8443)];
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(8);
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
static CONN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn next_conn_id() -> String {
    let mut bytes = [0u8; 6];
    if rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .is_ok()
    {
        return hex::encode(bytes);
    }
    let n = CONN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("c{n:011x}")
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub code: String,
    proof: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseReason {
    DeviceLimit,
    Expired,
    Revoked,
    #[serde(other)]
    Unknown,
}

impl LicenseReason {
    pub fn user_message(self) -> Option<&'static str> {
        match self {
            Self::DeviceLimit => Some(
                "Превышено число устройств по вашей лицензии. Вы можете расширить лицензию, чтобы использовать PAID на дополнительном устройстве",
            ),
            Self::Expired => Some(
                "Срок действия вашей лицензии PAID закончился. Вы можете продлить её действие на любое число устройств.",
            ),
            Self::Revoked => Some(
                "Лицензия PAID отозвана. Проверьте статус заказа в личном кабинете Витрины.",
            ),
            Self::Unknown => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct License {
    pub eligible: bool,
    pub started: bool,
    pub expires_at: Option<u64>,
    pub reason: Option<LicenseReason>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseCache {
    pub device_code: String,
    pub checked_at: u64,
    pub eligible: bool,
    pub started: bool,
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub reason: Option<LicenseReason>,
}

impl LicenseCache {
    pub fn license(&self) -> License {
        License {
            eligible: self.eligible,
            started: self.started,
            expires_at: self.expires_at,
            reason: self.reason,
        }
    }
}

fn license_cache_path() -> PathBuf {
    crate::dns_forwarder::log_dir().join("paid-license-cache.json")
}

pub fn load_license_cache(device_code: &str) -> Option<LicenseCache> {
    load_license_cache_from(&license_cache_path(), device_code)
}

fn load_license_cache_from(path: &std::path::Path, device_code: &str) -> Option<LicenseCache> {
    let data = fs::read(path).ok()?;
    let cache: LicenseCache = serde_json::from_slice(&data).ok()?;
    (cache.device_code == device_code).then_some(cache)
}

pub fn save_license_cache(cache: &LicenseCache) -> Result<(), String> {
    save_license_cache_to(&license_cache_path(), cache)
}

fn save_license_cache_to(path: &std::path::Path, cache: &LicenseCache) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let body = serde_json::to_vec(cache).map_err(|err| err.to_string())?;
    crate::secret_file::create_new(&tmp, &body).map_err(|err| err.to_string())?;
    if let Err(err) = fs::rename(&tmp, path) {
        fs::remove_file(&tmp).ok();
        return Err(err.to_string());
    }
    Ok(())
}

/// Formats a Unix timestamp in Moscow time (UTC+3, fixed offset) as `DD.MM.YYYY HH:MM МСК`.
pub fn format_moscow_expiry(unix_secs: u64) -> String {
    let msk = unix_secs.saturating_add(3 * 3600);
    let days = (msk / 86_400) as i64;
    let day_secs = msk % 86_400;
    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    format!("{day:02}.{month:02}.{year:04} {hour:02}:{minute:02} МСК")
}

impl Device {
    fn generate() -> Result<Self, String> {
        let mut bytes = [0; 44];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut bytes)
            .map_err(|_| "Не удалось создать код устройства")?;
        let code = bytes[..12]
            .iter()
            .map(|byte| CODE_ALPHABET[usize::from(byte & 31)] as char)
            .collect();
        Ok(Self {
            code,
            proof: hex::encode(&bytes[12..]),
        })
    }

    fn path() -> PathBuf {
        crate::dns_forwarder::log_dir().join("paid-device.json")
    }

    pub fn exists() -> bool {
        Self::path().try_exists().unwrap_or(true)
    }

    pub fn load() -> Result<Self, String> {
        let data =
            fs::read(Self::path()).map_err(|err| format!("Не найден код устройства: {err}"))?;
        let device: Self = serde_json::from_slice(&data).map_err(|err| err.to_string())?;
        if device.code.len() != 12
            || !device
                .code
                .bytes()
                .all(|byte| CODE_ALPHABET.contains(&byte))
            || device.proof.len() != 64
            || !device
                .proof
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("Сохранённый код устройства повреждён".into());
        }
        Ok(device)
    }

    pub fn load_or_create() -> Result<Self, String> {
        let path = Self::path();
        if path.try_exists().map_err(|err| err.to_string())? {
            return Self::load();
        }
        let device = Self::generate()?;
        fs::create_dir_all(crate::dns_forwarder::log_dir()).map_err(|err| err.to_string())?;
        let scratch = path.with_extension(format!("{}.tmp", std::process::id()));
        let data = serde_json::to_vec(&device).map_err(|err| err.to_string())?;
        crate::secret_file::create_new(&scratch, &data).map_err(|err| err.to_string())?;
        if let Err(error) = fs::hard_link(&scratch, &path) {
            fs::remove_file(scratch).map_err(|cleanup| format!("{error}; {cleanup}"))?;
            if error.kind() == io::ErrorKind::AlreadyExists {
                return Self::load();
            }
            return Err(error.to_string());
        }
        fs::remove_file(scratch).map_err(|err| err.to_string())?;
        Ok(device)
    }

    pub fn register(&self) -> Result<(), String> {
        self.api("register").map(|_| ())
    }

    pub fn check(&self) -> Result<License, String> {
        let reply = self.api("status")?;
        let reason = reply
            .get("reason")
            .filter(|v| !v.is_null())
            .and_then(|v| serde_json::from_value::<LicenseReason>(v.clone()).ok())
            .filter(|r| *r != LicenseReason::Unknown);
        Ok(License {
            eligible: reply["eligible"]
                .as_bool()
                .ok_or("Витрина вернула неизвестный статус")?,
            started: reply["started"].as_bool().unwrap_or(false),
            expires_at: reply["expires_at"].as_u64(),
            reason,
        })
    }

    fn api(&self, action: &str) -> Result<serde_json::Value, String> {
        let conn_id = next_conn_id();
        let body = serde_json::to_vec(self).map_err(|err| err.to_string())?;
        let mut request = format!(
            "POST /v1/device/{action} HTTP/1.1\r\nHost: {PRIMARY}\r\n\
            X-AIU-Conn-Id: {conn_id}\r\n\
            Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend(body);
        let mut reply = request_gateway(&request)?;
        let length = reply.length.ok_or("Шлюз не указал размер ответа")?;
        if length > 8192 {
            return Err("Слишком большой ответ шлюза".into());
        }
        let mut data = vec![0; length];
        reply
            .stream()
            .read_exact(&mut data)
            .map_err(|err| err.to_string())?;
        let data: serde_json::Value =
            serde_json::from_slice(&data).map_err(|err| err.to_string())?;
        if reply.status == 200 {
            Ok(data)
        } else {
            Err(data["error"]
                .as_str()
                .unwrap_or("Шлюз отклонил запрос")
                .into())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PaidGroup {
    Antigravity,
    Claude,
    Codex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PaidApp {
    AntigravityDesktop,
    AntigravityIde,
    AntigravityCli,
    AntigravityVscode,
    ClaudeCode,
    ClaudeDesktop,
    CodexCli,
    ChatGptDesktop,
}

impl PaidApp {
    pub const ALL: [Self; 8] = [
        Self::AntigravityDesktop,
        Self::AntigravityIde,
        Self::AntigravityCli,
        Self::AntigravityVscode,
        Self::ClaudeCode,
        Self::ClaudeDesktop,
        Self::CodexCli,
        Self::ChatGptDesktop,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::AntigravityDesktop => "antigravity-desktop",
            Self::AntigravityIde => "antigravity-ide",
            Self::AntigravityCli => "antigravity-cli",
            Self::AntigravityVscode => "antigravity-vscode",
            Self::ClaudeCode => "claude-code",
            Self::ClaudeDesktop => "claude-desktop",
            Self::CodexCli => "codex-cli",
            Self::ChatGptDesktop => "chatgpt-desktop",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id.trim() {
            "antigravity-desktop" => Some(Self::AntigravityDesktop),
            "antigravity-ide" => Some(Self::AntigravityIde),
            "antigravity-cli" => Some(Self::AntigravityCli),
            "antigravity-vscode" => Some(Self::AntigravityVscode),
            "claude-code" => Some(Self::ClaudeCode),
            "claude-desktop" => Some(Self::ClaudeDesktop),
            "codex-cli" => Some(Self::CodexCli),
            "chatgpt-desktop" => Some(Self::ChatGptDesktop),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::AntigravityDesktop => "Antigravity 2.0",
            Self::AntigravityIde => "Antigravity IDE",
            Self::AntigravityCli => "Antigravity CLI",
            Self::AntigravityVscode => "Antigravity для VS Code",
            Self::ClaudeCode => "Claude Code",
            Self::ClaudeDesktop => "Claude Desktop",
            Self::CodexCli => "Codex CLI",
            Self::ChatGptDesktop => "ChatGPT",
        }
    }

    pub fn group(self) -> PaidGroup {
        match self {
            Self::AntigravityDesktop
            | Self::AntigravityIde
            | Self::AntigravityCli
            | Self::AntigravityVscode => PaidGroup::Antigravity,
            Self::ClaudeCode | Self::ClaudeDesktop => PaidGroup::Claude,
            Self::CodexCli | Self::ChatGptDesktop => PaidGroup::Codex,
        }
    }

    pub fn is_antigravity(self) -> bool {
        self.group() == PaidGroup::Antigravity
    }

    pub fn supports_free(self) -> bool {
        self.is_antigravity()
    }

    pub fn paid_implemented(self) -> bool {
        matches!(
            self,
            Self::AntigravityDesktop
                | Self::AntigravityIde
                | Self::AntigravityCli
                | Self::AntigravityVscode
                | Self::ClaudeCode
                | Self::ClaudeDesktop
                | Self::CodexCli
        )
    }

    pub fn unavailable_reason(self) -> Option<&'static str> {
        match self {
            Self::ChatGptDesktop => Some("PAID недоступен для приложения из Microsoft Store"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidAppStatus {
    pub app: PaidApp,
    pub found: bool,
    pub path_hint: Option<String>,
    pub active: bool,
}

#[derive(Serialize, Deserialize)]
struct MarkerV2 {
    #[serde(default = "marker_version")]
    version: u32,
    #[serde(default)]
    apps: Vec<String>,
}

fn marker_version() -> u32 {
    2
}

pub fn marker() -> PathBuf {
    crate::dns_forwarder::log_dir().join("paid-proxy-enabled")
}

pub fn ide_marker() -> PathBuf {
    crate::dns_forwarder::log_dir().join("paid-ide-enabled")
}

pub fn parse_marker(text: &str) -> Vec<PaidApp> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed == "ide-bootstrap-v1" {
        return vec![PaidApp::AntigravityIde];
    }
    let Ok(parsed) = serde_json::from_str::<MarkerV2>(trimmed) else {
        return Vec::new();
    };
    let mut apps = Vec::new();
    for id in parsed.apps {
        if let Some(app) = PaidApp::from_id(&id) {
            if !apps.contains(&app) {
                apps.push(app);
            }
        }
    }
    apps
}

pub fn format_marker(apps: &[PaidApp]) -> Result<String, String> {
    let mut ids = Vec::new();
    for &app in apps {
        let id = app.id().to_string();
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    serde_json::to_string_pretty(&MarkerV2 {
        version: 2,
        apps: ids,
    })
    .map_err(|err| err.to_string())
}

pub fn active_apps() -> Vec<PaidApp> {
    if !cfg!(windows) || cfg!(test) {
        return Vec::new();
    }
    match fs::read_to_string(marker()) {
        Ok(text) => parse_marker(&text),
        Err(_) => Vec::new(),
    }
}

pub fn is_app_active(app: PaidApp) -> bool {
    active_apps().contains(&app)
}

pub fn antigravity_enabled() -> bool {
    cfg!(windows) && active_apps().iter().any(|app| app.is_antigravity())
}

pub fn antigravity_env_paid() -> bool {
    cfg!(windows)
        && active_apps().iter().any(|app| {
            matches!(
                app,
                PaidApp::AntigravityDesktop | PaidApp::AntigravityCli | PaidApp::AntigravityVscode
            )
        })
}

pub fn enabled() -> bool {
    cfg!(windows) && !active_apps().is_empty()
}

fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let mut config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols.push(b"http/1.1".to_vec());
            Arc::new(config)
        })
        .clone()
}

struct Reply {
    tls: ClientConnection,
    socket: TcpStream,
    status: u16,
    length: Option<usize>,
    conn_id: Option<String>,
    route: String,
}

impl Reply {
    fn stream(&mut self) -> rustls::Stream<'_, ClientConnection, TcpStream> {
        rustls::Stream::new(&mut self.tls, &mut self.socket)
    }

    fn read_error_body(&mut self) -> Option<serde_json::Value> {
        let want = self.length.unwrap_or(2048).min(4096);
        if want == 0 {
            return None;
        }
        let mut buf = vec![0u8; want];
        let has_length = self.length.is_some();
        let mut stream = self.stream();
        if has_length {
            stream.read_exact(&mut buf).ok()?;
            return serde_json::from_slice(&buf).ok();
        }
        let mut total = 0;
        while total < want {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => break,
            }
        }
        serde_json::from_slice(&buf[..total]).ok()
    }
}

fn first_reachable<T>(mut attempt: impl FnMut(&str, u16) -> io::Result<T>) -> Result<T, String> {
    let mut errors = Vec::new();
    for (host, port) in ROUTES {
        match attempt(host, port) {
            Ok(reply) => return Ok(reply),
            Err(error) => errors.push(format!("{host}:{port} — {error}")),
        }
    }
    Err(format!("Нет связи с платным шлюзом: {}", errors.join(", ")))
}

fn request_gateway(request: &[u8]) -> Result<Reply, String> {
    let mut previous_host = "";
    let mut addresses = Vec::new();
    first_reachable(|host, port| {
        if host != previous_host {
            previous_host = if host == PRIMARY { PRIMARY } else { RELAY };
            addresses.clear();
            addresses = (host, port)
                .to_socket_addrs()?
                .take(4)
                .map(|addr| addr.ip())
                .collect();
        }
        let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "DNS");
        for &ip in &addresses {
            match request_at(SocketAddr::new(ip, port), &format!("{host}:{port}"), request) {
                Ok(reply) => return Ok(reply),
                Err(error) => last = error,
            }
        }
        Err(last)
    })
}

fn request_at(addr: SocketAddr, route_label: &str, request: &[u8]) -> io::Result<Reply> {
    #[cfg(windows)]
    let socket = {
        let isp = crate::dns_forwarder::isp_interface();
        if isp == 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "Нет физического интерфейса для связи со шлюзом PAID",
            ));
        }
        crate::net::connect(addr, CONNECT_TIMEOUT, isp)?
    };
    #[cfg(not(windows))]
    let socket = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    request_on_socket(socket, route_label, request, tls_config())
}

#[cfg(test)]
fn request_with_config(
    addr: SocketAddr,
    route_label: &str,
    request: &[u8],
    config: Arc<ClientConfig>,
) -> io::Result<Reply> {
    let socket = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    request_on_socket(socket, route_label, request, config)
}

fn request_on_socket(
    mut socket: TcpStream,
    route_label: &str,
    request: &[u8],
    config: Arc<ClientConfig>,
) -> io::Result<Reply> {
    socket.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    socket.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    let name = rustls::pki_types::ServerName::try_from(PRIMARY).map_err(io::Error::other)?;
    let mut tls = ClientConnection::new(config, name).map_err(io::Error::other)?;
    tls.complete_io(&mut socket)?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut stream = rustls::Stream::new(&mut tls, &mut socket);
    stream.write_all(request)?;
    stream.flush()?;
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    if !header.ends_with(b"\r\n\r\n") {
        return Err(io::Error::other("Слишком большой заголовок шлюза"));
    }
    let text = std::str::from_utf8(&header).map_err(io::Error::other)?;
    let mut lines = text.lines();
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|tail| tail.split_whitespace().next()?.parse().ok())
        .ok_or_else(|| io::Error::other("Некорректный статус шлюза"))?;
    let mut length = None;
    let mut conn_id = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                length = value.trim().parse().ok();
            } else if name.eq_ignore_ascii_case("X-AIU-Conn-Id") {
                let v = value.trim();
                if !v.is_empty() {
                    conn_id = Some(v.to_string());
                }
            }
        }
    }
    Ok(Reply {
        tls,
        socket,
        status,
        length,
        conn_id,
        route: route_label.to_string(),
    })
}

fn sanitize_token(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect()
}

pub(crate) fn classify_gateway_refusal(
    conn_id: &str,
    host: &str,
    port: u16,
    route: &str,
    status: u16,
    body: Option<&serde_json::Value>,
) -> (String, crate::gate::PaidFailure) {
    let conn = body
        .and_then(|v| v["conn_id"].as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(conn_id);
    let conn = sanitize_token(conn);
    let stage = body
        .and_then(|v| v["stage"].as_str())
        .map(sanitize_token)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "connect".to_string());
    let reason = body
        .and_then(|v| v["reason"].as_str())
        .map(sanitize_token)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("http_{status}"));
    let summary = if status == 503 || reason.starts_with("store_") {
        "Сбой проверки лицензии на Витрине (503)".to_string()
    } else if status == 403 && matches!(reason.as_str(), "destination_forbidden" | "non_public_destination") {
        "Хост запрещён политикой платного шлюза (403)".to_string()
    } else if status == 403 && reason == "device_limit" {
        LicenseReason::DeviceLimit
            .user_message()
            .expect("device_limit message")
            .to_string()
    } else if status == 403 && reason == "expired" {
        LicenseReason::Expired
            .user_message()
            .expect("expired message")
            .to_string()
    } else if status == 403 {
        "Лицензия PAID отклонена шлюзом (403)".to_string()
    } else if status == 502 || reason.starts_with("upstream_") {
        "Платный шлюз не смог подключиться к целевому серверу (502)".to_string()
    } else if status == 429 {
        "Превышен лимит соединений платного шлюза (429)".to_string()
    } else {
        format!("Платный шлюз отклонил соединение ({status})")
    };
    let host_port = format!("{host}:{port}");
    let log_line = format!(
        "PAID отказ [conn={conn}] host={host_port} via={route} stage={stage} status={status} reason={reason} — {summary}"
    );
    let failure = crate::gate::PaidFailure {
        at: crate::gate::now_unix(),
        conn_id: conn,
        host: host_port,
        stage,
        status,
        reason,
        summary,
    };
    (log_line, failure)
}

fn log_and_record_paid_error(log_line: &str, failure: crate::gate::PaidFailure, is_gate: bool) {
    crate::dns_forwarder::log_proxy(log_line);
    if is_gate && !cfg!(test) {
        crate::gate::record_paid_error(failure);
    }
}

pub fn serve(
    client: TcpStream,
    host: &str,
    port: u16,
    http: Option<&[u8]>,
    app: Option<PaidApp>,
) -> Result<(), String> {
    let conn_id = next_conn_id();
    let device = Device::load()?;
    let request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\
        X-AIU-Conn-Id: {conn_id}\r\n\
        Proxy-Authorization: Device {}.{}\r\n\r\n",
        device.code, device.proof
    );
    let reply = match request_gateway(request.as_bytes()) {
        Ok(reply) => reply,
        Err(msg) => {
            let log_line = format!(
                "PAID отказ [conn={conn_id}] host={host}:{port} stage=connect status=0 reason=gateway_unreachable — {msg}"
            );
            let failure = crate::gate::PaidFailure {
                at: crate::gate::now_unix(),
                conn_id,
                host: format!("{host}:{port}"),
                stage: "connect".into(),
                status: 0,
                reason: "gateway_unreachable".into(),
                summary: "Нет связи с платным шлюзом".into(),
            };
            log_and_record_paid_error(&log_line, failure, crate::proxy::is_gate_host(host));
            return Err(log_line);
        }
    };
    serve_with_reply(client, host, port, http, app, &conn_id, reply)
}

fn serve_with_reply(
    client: TcpStream,
    host: &str,
    port: u16,
    http: Option<&[u8]>,
    app: Option<PaidApp>,
    requested_conn_id: &str,
    reply: Reply,
) -> Result<(), String> {
    serve_with_reply_impl(
        client,
        host,
        port,
        http,
        app,
        requested_conn_id,
        reply,
        |line| crate::dns_forwarder::log_proxy(line),
        log_and_record_paid_error,
    )
}

fn serve_with_reply_impl(
    mut client: TcpStream,
    host: &str,
    port: u16,
    http: Option<&[u8]>,
    app: Option<PaidApp>,
    requested_conn_id: &str,
    mut reply: Reply,
    mut on_info: impl FnMut(&str),
    mut on_error: impl FnMut(&str, crate::gate::PaidFailure, bool),
) -> Result<(), String> {
    let is_gate = port == 443 && crate::proxy::is_gate_host(host);
    if reply.status != 200 {
        let body = reply.read_error_body();
        let (log_line, failure) = classify_gateway_refusal(
            requested_conn_id,
            host,
            port,
            &reply.route,
            reply.status,
            body.as_ref(),
        );
        on_error(&log_line, failure, is_gate);
        return Err(log_line);
    }
    let conn_id = reply
        .conn_id
        .clone()
        .unwrap_or_else(|| requested_conn_id.to_string());
    let _paid_gate = is_gate.then(|| {
        on_info(&format!(
            "PAID -> {host}:{port} [conn={conn_id}] via={}",
            reply.route
        ));
        crate::routes::begin_paid_gate_connection(host, &conn_id)
    });
    if let Some(head) = http {
        let mut stream = reply.stream();
        stream
            .write_all(head)
            .and_then(|()| stream.flush())
            .map_err(|err| err.to_string())?;
    } else {
        client
            .write_all(crate::proxy::RESP_ESTABLISHED)
            .map_err(|err| err.to_string())?;
    }
    if is_gate {
        crate::routes::note_paid_used();
    }
    reply.socket.set_read_timeout(None).ok();
    reply.socket.set_write_timeout(None).ok();
    let mut verify_at = Instant::now();
    let outcome = crate::group::tls_pump_report(client, reply.tls, reply.socket, Vec::new(), || {
        let now = Instant::now();
        if now < verify_at {
            return true;
        }
        verify_at = now + Duration::from_millis(250);
        if cfg!(test) {
            true
        } else {
            app.map_or_else(enabled, is_app_active)
        }
    });
    let why_code = match outcome.why {
        crate::group::PumpEnd::Client => "client_eof",
        crate::group::PumpEnd::Upstream => "upstream_eof",
        crate::group::PumpEnd::Idle => "idle_timeout",
        crate::group::PumpEnd::NoAnswer => "no_answer_timeout",
        crate::group::PumpEnd::Stopped => "paid_disabled",
    };
    let dropped_mid_stream = outcome.io_err.is_some()
        || (is_gate
            && (outcome.why == crate::group::PumpEnd::NoAnswer
                || (outcome.to_upstream > 0
                    && outcome.to_client < 512
                    && outcome.why != crate::group::PumpEnd::Stopped)));
    if dropped_mid_stream {
        let err_suffix = outcome
            .io_err
            .as_deref()
            .map(|e| format!(" err={}", sanitize_token(e)))
            .unwrap_or_default();
        let line = format!(
            "PAID обрыв после CONNECT [conn={conn_id}] host={host}:{port} via={} stage=tunnel reason={why_code}{err_suffix} dur={}ms in={}B out={}B",
            reply.route,
            outcome.duration.as_millis(),
            outcome.to_client,
            outcome.to_upstream
        );
        let failure = crate::gate::PaidFailure {
            at: crate::gate::now_unix(),
            conn_id,
            host: format!("{host}:{port}"),
            stage: "tunnel".into(),
            status: 200,
            reason: why_code.into(),
            summary: "Соединение через платный шлюз оборвалось после CONNECT".into(),
        };
        on_error(&line, failure, is_gate);
    }
    Ok(())
}

pub fn plain_http(head: &str) -> Option<(String, u16, Vec<u8>)> {
    let (line, headers) = head.split_once("\r\n")?;
    let mut words = line.split(' ');
    let method = words.next()?;
    if method.is_empty() || !method.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let absolute = words.next()?.strip_prefix("http://")?;
    if words.next()? != "HTTP/1.1" || words.next().is_some() {
        return None;
    }
    let split = absolute.find(['/', '?']).unwrap_or(absolute.len());
    let (authority, tail) = absolute.split_at(split);
    let (host, port) = authority.rsplit_once(':').unwrap_or((authority, "80"));
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
    {
        return None;
    }
    let port = port.parse().ok()?;
    let path = if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}")
    };
    let fields: Vec<_> = headers
        .split("\r\n")
        .take_while(|line| !line.is_empty())
        .map(|line| line.split_once(':'))
        .collect::<Option<_>>()?;
    let excluded: Vec<_> = fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Connection"))
        .flat_map(|(_, value)| value.split(',').map(str::trim))
        .collect();
    let mut forwarded =
        format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
    for (name, value) in &fields {
        if name.trim() != *name || name.is_empty() {
            return None;
        }
        if [
            "Host",
            "Connection",
            "Proxy-Connection",
            "Proxy-Authorization",
        ]
        .iter()
        .chain(excluded.iter())
        .any(|ignored| name.eq_ignore_ascii_case(ignored))
        {
            continue;
        }
        forwarded.push_str(name);
        forwarded.push(':');
        forwarded.push_str(value);
        forwarded.push_str("\r\n");
    }
    forwarded.push_str("\r\n");
    Some((host.to_string(), port, forwarded.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tries_ports_on_primary_before_ports_on_relay() {
        let mut seen = Vec::new();
        let found = first_reachable(|host, port| {
            seen.push((host.to_owned(), port));
            if host == RELAY && port == 8443 {
                Ok(204)
            } else {
                Err(io::Error::other("down"))
            }
        });
        assert_eq!(found.unwrap(), 204);
        assert_eq!(seen, ROUTES.map(|(host, port)| (host.to_owned(), port)));
    }

    #[test]
    fn an_http_response_stops_failover_even_when_authorization_is_denied() {
        let mut count = 0;
        let reply = first_reachable(|_, _| {
            count += 1;
            Ok(403)
        })
        .unwrap();
        assert_eq!((reply, count), (403, 1));
    }

    #[test]
    fn paid_http_rewrites_origin_form_and_drops_proxy_headers() {
        let (host, port, headers) = plain_http(
            "GET http://example.org/?x=1 HTTP/1.1\r\nHost: wrong.test\r\n\
             Proxy-Authorization: private\r\nConnection: Foo\r\nFoo: bar\r\n\r\n",
        )
        .unwrap();
        assert_eq!((host.as_str(), port), ("example.org", 80));
        assert_eq!(
            headers,
            b"GET /?x=1 HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn marker_v2_round_trips_and_parses_legacy_v1() {
        assert_eq!(parse_marker("ide-bootstrap-v1\n"), vec![PaidApp::AntigravityIde]);
        let encoded = format_marker(&[
            PaidApp::AntigravityIde,
            PaidApp::ClaudeCode,
            PaidApp::AntigravityIde,
        ])
        .unwrap();
        assert_eq!(
            parse_marker(&encoded),
            vec![PaidApp::AntigravityIde, PaidApp::ClaudeCode]
        );
        assert!(parse_marker("").is_empty());
        assert!(parse_marker("not-json").is_empty());
    }

    #[test]
    fn paid_app_capabilities_match_free_and_implementation_status() {
        assert!(PaidApp::AntigravityDesktop.is_antigravity());
        assert!(PaidApp::AntigravityIde.supports_free());
        assert!(!PaidApp::ClaudeCode.is_antigravity());
        assert!(!PaidApp::ClaudeCode.supports_free());
        assert!(PaidApp::ClaudeCode.paid_implemented());
        assert!(PaidApp::ClaudeDesktop.paid_implemented());
        assert_eq!(PaidApp::ChatGptDesktop.label(), "ChatGPT");
        assert!(!PaidApp::ChatGptDesktop.paid_implemented());
        assert!(PaidApp::CodexCli.paid_implemented());
        assert_eq!(
            PaidApp::ChatGptDesktop.unavailable_reason(),
            Some("PAID недоступен для приложения из Microsoft Store")
        );
    }

    #[test]
    fn moscow_expiry_formats_day_rollover_and_leap_day() {
        assert_eq!(format_moscow_expiry(0), "01.01.1970 03:00 МСК");
        // 2024-02-29 22:15:00 UTC -> 2024-03-01 01:15 МСК
        assert_eq!(format_moscow_expiry(1_709_244_900), "01.03.2024 01:15 МСК");
        // 2024-02-29 12:34:00 UTC -> 2024-02-29 15:34 МСК
        assert_eq!(format_moscow_expiry(1_709_210_040), "29.02.2024 15:34 МСК");
    }

    #[test]
    fn license_cache_round_trips_and_checks_device_code() {
        let dir = std::env::temp_dir().join(format!(
            "ag-unlocker-paid-cache-{}",
            std::process::id()
        ));
        let path = dir.join("paid-license-cache.json");
        let cache = LicenseCache {
            device_code: "7G9KD3KW3N67".into(),
            checked_at: 1_795_721_247,
            eligible: true,
            started: true,
            expires_at: Some(1_798_313_247),
            reason: Some(LicenseReason::DeviceLimit),
        };
        save_license_cache_to(&path, &cache).unwrap();
        assert_eq!(
            load_license_cache_from(&path, "7G9KD3KW3N67").as_ref(),
            Some(&cache)
        );
        assert_eq!(
            serde_json::from_str::<LicenseReason>("\"device_limit\"").unwrap(),
            LicenseReason::DeviceLimit
        );
        assert_eq!(
            serde_json::from_str::<LicenseReason>("\"expired\"").unwrap(),
            LicenseReason::Expired
        );
        assert_eq!(
            serde_json::from_str::<LicenseReason>("\"other\"").unwrap(),
            LicenseReason::Unknown
        );
        assert!(load_license_cache_from(&path, "OTHER0000000").is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn gateway_refusal_maps_device_limit_and_expired_messages() {
        let lim = serde_json::json!({"reason": "device_limit", "conn_id": "lim1"});
        let (line_lim, fail_lim) = classify_gateway_refusal(
            "cli1",
            "daily-cloudcode-pa.googleapis.com",
            443,
            "eu1-aiu.nova-app.eu:443",
            403,
            Some(&lim),
        );
        assert!(line_lim.contains("Превышено число устройств по вашей лицензии"), "{line_lim}");
        assert!(fail_lim.summary.contains("Вы можете расширить лицензию"));

        let exp = serde_json::json!({"reason": "expired", "conn_id": "exp1"});
        let (line_exp, fail_exp) = classify_gateway_refusal(
            "cli2",
            "daily-cloudcode-pa.googleapis.com",
            443,
            "eu1-aiu.nova-app.eu:443",
            403,
            Some(&exp),
        );
        assert!(line_exp.contains("Срок действия вашей лицензии PAID закончился"), "{line_exp}");
        assert!(fail_exp.summary.contains("Вы можете продлить её действие на любое число устройств."));
    }

    #[test]
    fn gateway_refusal_distinguishes_store_503_license_403_and_dial_502_without_secrets() {
        let body_503 = serde_json::json!({
            "error": "Store unavailable",
            "stage": "pre_connect_status",
            "reason": "store_timeout",
            "conn_id": "srv503aa"
        });
        let (line_503, fail_503) = classify_gateway_refusal(
            "cli0001",
            "daily-cloudcode-pa.googleapis.com",
            443,
            "eu1-aiu.nova-app.eu:443",
            503,
            Some(&body_503),
        );
        assert!(line_503.contains("conn=srv503aa"), "{line_503}");
        assert!(line_503.contains("reason=store_timeout"), "{line_503}");
        assert!(line_503.contains("host=daily-cloudcode-pa.googleapis.com:443"), "{line_503}");
        assert_eq!(fail_503.stage, "pre_connect_status");
        assert_eq!(fail_503.status, 503);
        assert_eq!(fail_503.reason, "store_timeout");

        let body_403 = serde_json::json!({
            "error": "License required",
            "stage": "pre_connect_status",
            "reason": "license_denied",
            "conn_id": "srv403bb"
        });
        let (line_403, fail_403) = classify_gateway_refusal(
            "cli0002",
            "daily-cloudcode-pa.googleapis.com",
            443,
            "eu1-aiu.nova-app.eu:443",
            403,
            Some(&body_403),
        );
        assert!(line_403.contains("Лицензия PAID отклонена шлюзом (403)"), "{line_403}");
        assert_eq!(fail_403.reason, "license_denied");

        let body_502 = serde_json::json!({
            "error": "Destination unavailable",
            "stage": "dial",
            "reason": "upstream_dial_timeout",
            "conn_id": "srv502cc"
        });
        let (line_502, fail_502) = classify_gateway_refusal(
            "cli0003",
            "cloudcode-pa.googleapis.com",
            443,
            "ru1.relay-aiu.nova-app.eu:443",
            502,
            Some(&body_502),
        );
        assert!(line_502.contains("не смог подключиться"), "{line_502}");
        assert_eq!(fail_502.stage, "dial");
        assert_eq!(fail_502.reason, "upstream_dial_timeout");

        let id1 = next_conn_id();
        let id2 = next_conn_id();
        assert_eq!(id1.len(), 12);
        assert_ne!(id1, id2);
    }

    fn loopback_tls_configs() -> (Arc<ClientConfig>, Arc<rustls::ServerConfig>) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::ServerConfig;

        const TEST_CERT_HEX: &str = "3082014d3081f3a003020102020101300a06082a8648ce3d040302301e311c301a06035504030c136575312d6169752e6e6f76612d6170702e6575301e170d3236313132353232333634315a170d3336313132333232333634315a301e311c301a06035504030c136575312d6169752e6e6f76612d6170702e65753059301306072a8648ce3d020106082a8648ce3d030107034200042d4d6662fc70a94c33c31cd3c200310cb097725761455899ed9d6c35ff28e5296215352b675839855fb792c8bf19689750ea2da2600164c933534483c8f11036a3223020301e0603551d110417301582136575312d6169752e6e6f76612d6170702e6575300a06082a8648ce3d0403020349003046022100c1fe3df96371d1742ff2eb0c96dedd96b4b8cb6bc097b5add55072be77055bc0022100c04b8fbddb0cd5e4429e5aa44f71429f3f2225fbd8060e02c7d3a63ef4c10275";
        const TEST_KEY_HEX: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104207e0bc63c517b27162d1c14a49d35bcb90e113faf43a476fd27decbaaddbb3c34a144034200042d4d6662fc70a94c33c31cd3c200310cb097725761455899ed9d6c35ff28e5296215352b675839855fb792c8bf19689750ea2da2600164c933534483c8f11036";

        let cert_bytes = hex::decode(TEST_CERT_HEX).expect("cert hex");
        let key_bytes = hex::decode(TEST_KEY_HEX).expect("key hex");
        let cert = CertificateDer::from(cert_bytes);

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).expect("add test root");
        let client_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_cfg = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes)),
                )
                .expect("server tls cfg"),
        );
        (client_cfg, server_cfg)
    }

    #[test]
    fn tls_socket_reproduces_pre_connect_503_and_post_connect_drop() {
        use rustls::ServerConnection;
        use std::net::TcpListener;

        let (client_cfg, server_cfg) = loopback_tls_configs();

        let fake_code = "DEVSECRET999";
        let fake_proof = "PROOFSECRET999";

        // 1. Pre-CONNECT 503 with JSON diagnostic body and X-AIU-Conn-Id
        let gw = TcpListener::bind(("127.0.0.1", 0)).expect("bind gw1");
        let gw_addr = gw.local_addr().expect("gw1 addr");
        let srv_cfg = server_cfg.clone();
        let gw1_thread = std::thread::spawn(move || {
            let (mut sock, _) = gw.accept().expect("accept gw1");
            let mut tls = ServerConnection::new(srv_cfg).expect("srv conn 1");
            let mut req_buf = Vec::new();
            let mut tmp = [0u8; 256];
            {
                let mut stream = rustls::Stream::new(&mut tls, &mut sock);
                while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut tmp).expect("read connect req");
                    if n == 0 {
                        break;
                    }
                    req_buf.extend_from_slice(&tmp[..n]);
                }
                let body = r#"{"error":"Store unavailable","stage":"pre_connect_status","reason":"store_timeout","conn_id":"gwref503"}"#;
                let resp = format!(
                    "HTTP/1.1 503 Service Unavailable\r\nX-AIU-Conn-Id: gwref503\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(resp.as_bytes()).expect("write 503");
                stream.flush().expect("flush 503");
            }
            tls.send_close_notify();
            tls.write_tls(&mut sock).ok();
        });

        let client_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind cli1");
        let _cli1 = TcpStream::connect(client_listener.local_addr().unwrap()).unwrap();
        let (cli1_srv, _) = client_listener.accept().unwrap();

        let connect_req_503 = format!(
            "CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\nHost: daily-cloudcode-pa.googleapis.com:443\r\nX-AIU-Conn-Id: clireq01\r\nProxy-Authorization: Device {fake_code}.{fake_proof}\r\n\r\n"
        );
        let reply_503 = request_with_config(
            gw_addr,
            "eu1-aiu.nova-app.eu:443",
            connect_req_503.as_bytes(),
            client_cfg.clone(),
        )
        .expect("reply 503");
        let mut errors1 = Vec::new();
        let err = serve_with_reply_impl(
            cli1_srv,
            "daily-cloudcode-pa.googleapis.com",
            443,
            None,
            Some(PaidApp::AntigravityDesktop),
            "clireq01",
            reply_503,
            |_| {},
            |line, failure, is_gate| errors1.push((line.to_string(), failure, is_gate)),
        )
        .expect_err("503 should fail");
        gw1_thread.join().expect("gw1 join");
        assert!(err.contains("conn=gwref503"), "{err}");
        assert!(err.contains("stage=pre_connect_status"), "{err}");
        assert!(err.contains("reason=store_timeout"), "{err}");
        assert!(!err.contains(fake_code) && !err.contains(fake_proof), "{err}");
        let (line1, snap1, is_gate1) = errors1.pop().expect("paid error 1");
        assert!(is_gate1);
        assert!(line1.contains("conn=gwref503"), "{line1}");
        assert_eq!(snap1.conn_id, "gwref503");
        assert_eq!(snap1.status, 503);
        assert_eq!(snap1.reason, "store_timeout");

        // 2. Post-CONNECT 200 followed by abrupt upstream TCP drop (no close_notify)
        let gw2 = TcpListener::bind(("127.0.0.1", 0)).expect("bind gw2");
        let gw2_addr = gw2.local_addr().expect("gw2 addr");
        let srv_cfg2 = server_cfg.clone();
        let gw2_thread = std::thread::spawn(move || {
            let (mut sock, _) = gw2.accept().expect("accept gw2");
            let mut tls = ServerConnection::new(srv_cfg2).expect("srv conn 2");
            let mut req_buf = Vec::new();
            let mut tmp = [0u8; 256];
            {
                let mut stream = rustls::Stream::new(&mut tls, &mut sock);
                while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut tmp).expect("read connect 2");
                    if n == 0 {
                        break;
                    }
                    req_buf.extend_from_slice(&tmp[..n]);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 Connection Established\r\nX-AIU-Conn-Id: gwdrop01\r\n\r\n",
                    )
                    .expect("write 200");
                stream.flush().expect("flush 200");
                let _ = stream.read(&mut tmp);
                stream.write_all(b"partial").expect("write partial");
                stream.flush().expect("flush partial");
            }
            // Drop socket abruptly without TLS close_notify.
            drop(sock);
        });

        let client2_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind cli2");
        let mut cli2_far = TcpStream::connect(client2_listener.local_addr().unwrap()).unwrap();
        cli2_far.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let (cli2_srv, _) = client2_listener.accept().unwrap();

        let connect_req_200 = format!(
            "CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\nHost: daily-cloudcode-pa.googleapis.com:443\r\nX-AIU-Conn-Id: clireq02\r\nProxy-Authorization: Device {fake_code}.{fake_proof}\r\n\r\n"
        );
        let reply_200 = request_with_config(
            gw2_addr,
            "eu1-aiu.nova-app.eu:443",
            connect_req_200.as_bytes(),
            client_cfg.clone(),
        )
        .expect("reply 200");

        let cli2_driver = std::thread::spawn(move || {
            let mut head = vec![0u8; crate::proxy::RESP_ESTABLISHED.len()];
            cli2_far.read_exact(&mut head).expect("read 200");
            cli2_far.write_all(b"POST /stream").expect("write req");
            cli2_far.flush().ok();
            let mut body = [0u8; 32];
            let _ = cli2_far.read(&mut body);
            std::thread::sleep(Duration::from_millis(50));
        });

        let mut infos2 = Vec::new();
        let mut errors2 = Vec::new();
        serve_with_reply_impl(
            cli2_srv,
            "daily-cloudcode-pa.googleapis.com",
            443,
            None,
            Some(PaidApp::AntigravityDesktop),
            "clireq02",
            reply_200,
            |info| infos2.push(info.to_string()),
            |line, failure, is_gate| errors2.push((line.to_string(), failure, is_gate)),
        )
        .expect("tunnel pump completes");
        gw2_thread.join().expect("gw2 join");
        cli2_driver.join().expect("cli2 join");

        assert!(
            infos2.iter().any(|s| s.contains("PAID -> daily-cloudcode-pa.googleapis.com:443 [conn=gwdrop01]")),
            "{infos2:?}"
        );
        let (line2, snap2, is_gate2) = errors2.pop().expect("paid error 2");
        assert!(is_gate2);
        assert!(line2.contains("PAID обрыв после CONNECT [conn=gwdrop01]"), "{line2}");
        assert_eq!(snap2.conn_id, "gwdrop01");
        assert_eq!(snap2.host, "daily-cloudcode-pa.googleapis.com:443");
        assert_eq!(snap2.stage, "tunnel");
        assert_eq!(snap2.status, 200);
        assert_eq!(snap2.reason, "upstream_eof");
        assert!(!snap2.summary.contains(fake_code) && !snap2.summary.contains(fake_proof));

        // 3. Post-CONNECT 200 with full >=512B response + clean TLS close_notify must NOT be flagged as error
        let gw3 = TcpListener::bind(("127.0.0.1", 0)).expect("bind gw3");
        let gw3_addr = gw3.local_addr().expect("gw3 addr");
        let gw3_thread = std::thread::spawn(move || {
            let (mut sock, _) = gw3.accept().expect("accept gw3");
            let mut tls = ServerConnection::new(server_cfg).expect("srv conn 3");
            let mut req_buf = Vec::new();
            let mut tmp = [0u8; 256];
            {
                let mut stream = rustls::Stream::new(&mut tls, &mut sock);
                while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut tmp).expect("read connect 3");
                    if n == 0 {
                        break;
                    }
                    req_buf.extend_from_slice(&tmp[..n]);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 Connection Established\r\nX-AIU-Conn-Id: gwok0001\r\n\r\n",
                    )
                    .expect("write 200 ok");
                stream.flush().expect("flush 200 ok");
                let _ = stream.read(&mut tmp);
                stream.write_all(&vec![b'X'; 1024]).expect("write 1KB");
                stream.flush().expect("flush 1KB");
            }
            tls.send_close_notify();
            tls.write_tls(&mut sock).ok();
        });

        let client3_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind cli3");
        let mut cli3_far = TcpStream::connect(client3_listener.local_addr().unwrap()).unwrap();
        cli3_far.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let (cli3_srv, _) = client3_listener.accept().unwrap();

        let connect_req_ok = format!(
            "CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\nHost: daily-cloudcode-pa.googleapis.com:443\r\nX-AIU-Conn-Id: clireq03\r\nProxy-Authorization: Device {fake_code}.{fake_proof}\r\n\r\n"
        );
        let reply_ok = request_with_config(
            gw3_addr,
            "eu1-aiu.nova-app.eu:443",
            connect_req_ok.as_bytes(),
            client_cfg,
        )
        .expect("reply ok");

        let cli3_driver = std::thread::spawn(move || {
            let mut head = vec![0u8; crate::proxy::RESP_ESTABLISHED.len()];
            cli3_far.read_exact(&mut head).expect("read 200 ok");
            cli3_far.write_all(b"POST /generate").expect("write req ok");
            cli3_far.flush().ok();
            let mut body = vec![0u8; 1024];
            let _ = cli3_far.read_exact(&mut body);
        });

        let mut errors3 = Vec::new();
        serve_with_reply_impl(
            cli3_srv,
            "daily-cloudcode-pa.googleapis.com",
            443,
            None,
            Some(PaidApp::AntigravityDesktop),
            "clireq03",
            reply_ok,
            |_| {},
            |line, failure, is_gate| errors3.push((line.to_string(), failure, is_gate)),
        )
        .expect("clean tunnel completes");
        gw3_thread.join().expect("gw3 join");
        cli3_driver.join().expect("cli3 join");
        assert!(errors3.is_empty(), "clean >=512B close must not emit error: {errors3:?}");
    }

    #[test]
    fn tls_pump_handles_256kb_upload_under_backpressure() {
        use rustls::ServerConnection;
        use std::net::TcpListener;

        const UPLOAD_BYTES: usize = 262_144;
        let (client_cfg, server_cfg) = loopback_tls_configs();
        let gw = TcpListener::bind(("127.0.0.1", 0)).expect("bind gw");
        let gw_addr = gw.local_addr().expect("gw addr");
        let gw_thread = std::thread::spawn(move || {
            let (mut sock, _) = gw.accept().expect("accept gw");
            let mut tls = ServerConnection::new(server_cfg).expect("srv conn");
            let mut req_buf = Vec::new();
            let mut tmp = [0u8; 4096];
            {
                let mut stream = rustls::Stream::new(&mut tls, &mut sock);
                while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut tmp).expect("read connect");
                    if n == 0 {
                        break;
                    }
                    req_buf.extend_from_slice(&tmp[..n]);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 Connection Established\r\nX-AIU-Conn-Id: gw256kb1\r\n\r\n",
                    )
                    .expect("write 200");
                stream.flush().expect("flush 200");
                let mut uploaded = 0usize;
                while uploaded < UPLOAD_BYTES {
                    let n = stream.read(&mut tmp).expect("read upload chunk");
                    if n == 0 {
                        break;
                    }
                    uploaded += n;
                    std::thread::sleep(Duration::from_millis(1));
                }
                assert_eq!(uploaded, UPLOAD_BYTES, "server must receive full 256 KiB upload");
                stream.write_all(&vec![b'Z'; 1024]).expect("write reply");
                stream.flush().expect("flush reply");
            }
            tls.send_close_notify();
            tls.write_tls(&mut sock).ok();
        });

        let cli_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind cli");
        let mut cli_far = TcpStream::connect(cli_listener.local_addr().unwrap()).unwrap();
        cli_far.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let (cli_srv, _) = cli_listener.accept().unwrap();

        let connect_req = "CONNECT play.googleapis.com:443 HTTP/1.1\r\nHost: play.googleapis.com:443\r\nX-AIU-Conn-Id: cli256k1\r\nProxy-Authorization: Device DEV000000001.0000\r\n\r\n";
        let reply = request_with_config(
            gw_addr,
            "eu1-aiu.nova-app.eu:443",
            connect_req.as_bytes(),
            client_cfg,
        )
        .expect("reply 200");

        let cli_driver = std::thread::spawn(move || {
            let mut head = vec![0u8; crate::proxy::RESP_ESTABLISHED.len()];
            cli_far.read_exact(&mut head).expect("read 200");
            cli_far.write_all(&vec![b'A'; UPLOAD_BYTES]).expect("write 256 KiB");
            cli_far.flush().ok();
            cli_far.shutdown(std::net::Shutdown::Write).ok();
            let mut body = vec![0u8; 1024];
            cli_far.read_exact(&mut body).expect("read 1KB reply");
            assert!(body.iter().all(|&b| b == b'Z'));
        });

        let mut errors = Vec::new();
        serve_with_reply_impl(
            cli_srv,
            "play.googleapis.com",
            443,
            None,
            Some(PaidApp::AntigravityDesktop),
            "cli256k1",
            reply,
            |_| {},
            |line, failure, is_gate| errors.push((line.to_string(), failure, is_gate)),
        )
        .expect("256 KiB upload completes");
        gw_thread.join().expect("gw join");
        cli_driver.join().expect("cli join");
        assert!(errors.is_empty(), "256 KiB upload must not error: {errors:?}");
    }
}
