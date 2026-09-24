//! New-version check against the project's GitHub Releases.
//!
//! Synchronous on purpose, like the rest of the crate: one HTTP/1.1 GET over a
//! rustls stream, the same pattern `doh.rs` and `proxy.rs` already use. The GUI
//! runs it on its own thread and never on the paint loop.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use serde::{Deserialize, Serialize};

pub const RELEASES_LATEST_URL: &str = "https://github.com/SatoKazuma1/Antigravity/releases/latest";
const API_HOST: &str = "api.github.com";
const API_PATH: &str = "/repos/SatoKazuma1/Antigravity/releases/latest";
const CHECK_INTERVAL: Duration = Duration::from_secs(8 * 60 * 60);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY: usize = 256 * 1024;

/// The version this binary shipped as, in the form the release tags use.
///
/// `CARGO_PKG_VERSION` only ever holds the three-digit part (`2.12.2`) because
/// `build_rust.py` deliberately keeps the fourth digit out of Cargo.toml — a
/// changed Cargo version re-salts every licence key (I2). So the full shipped
/// name (`2.12.2_3`) comes from build.rs instead. Without it a `_3` build would
/// compare itself against tag `v2.12.2_3` as if it were `2.12.2`, and claim an
/// update that does not exist.
pub fn current_version() -> &'static str {
    option_env!("AG_FULL_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Information about a GitHub release asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub size: u64,
}

/// Details of the latest release fetched from the GitHub API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    pub html_url: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

impl ReleaseInfo {
    /// Returns true if this release is strictly newer than the currently running binary.
    pub fn is_newer_than_current(&self) -> bool {
        is_newer_version(&self.tag_name, current_version())
    }

    /// Strips leading 'v' / 'V' and whitespace from tag name for display.
    pub fn display_version(&self) -> &str {
        self.tag_name
            .trim()
            .trim_start_matches(|c| c == 'v' || c == 'V')
    }

    /// Finds the appropriate binary asset for the current OS.
    pub fn find_binary_asset(&self) -> Option<&ReleaseAsset> {
        #[cfg(windows)]
        {
            if let Some(a) = self
                .assets
                .iter()
                .find(|a| a.name.eq_ignore_ascii_case("ag_unlocker.exe"))
            {
                return Some(a);
            }
            self.assets
                .iter()
                .find(|a| a.name.to_ascii_lowercase().ends_with(".exe"))
        }
        #[cfg(not(windows))]
        {
            self.assets.iter().find(|a| a.name == "ag_unlocker")
        }
    }
}

/// Cached check payload stored on disk.
#[derive(Debug, Serialize, Deserialize)]
struct CachedCheck {
    checked_at_unix: u64,
    release: ReleaseInfo,
}

/// Returns the path to the update check cache file in the system temp directory.
fn cache_path() -> PathBuf {
    std::env::temp_dir().join("ag_unlocker_update_cache.json")
}

/// Compares two version strings (e.g. "v2.11.0_4" vs "2.11.0_1", "2.11.0" vs "2.10.0").
/// Returns true if `remote` is strictly newer than `current`.
pub fn is_newer_version(remote: &str, current: &str) -> bool {
    let parse_segments = |v: &str| -> Vec<u64> {
        let clean = v.trim().trim_start_matches(|c| c == 'v' || c == 'V');
        clean
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<u64>().ok())
            .collect()
    };

    let r_parts = parse_segments(remote);
    let c_parts = parse_segments(current);

    let max_len = r_parts.len().max(c_parts.len());
    for i in 0..max_len {
        let r = r_parts.get(i).copied().unwrap_or(0);
        let c = c_parts.get(i).copied().unwrap_or(0);
        if r > c {
            return true;
        } else if r < c {
            return false;
        }
    }
    false
}

/// Client configuration for TLS. Reuses the project's standard pattern with WebPKI roots
/// and HTTP/1.1 ALPN protocol.
fn tls_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

/// Connects a TCP stream to `host:port` with a connection timeout.
fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {}: {}", host, e))?
        .collect();

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(sock) => {
                sock.set_read_timeout(Some(IO_TIMEOUT)).ok();
                sock.set_write_timeout(Some(IO_TIMEOUT)).ok();
                return Ok(sock);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(format!(
        "could not connect to {}:{}: {}",
        host,
        port,
        last_err.map_or_else(|| "no address resolved".to_string(), |e| e.to_string())
    ))
}

/// Decodes HTTP chunked transfer encoding if present in response.
fn decode_chunked(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while cursor < raw.len() {
        let rem = &raw[cursor..];
        let Some(pos) = rem.windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let line = std::str::from_utf8(&rem[..pos])
            .map_err(|e| format!("invalid chunk size encoding: {}", e))?
            .trim();
        let chunk_size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|e| format!("invalid chunk size hex '{}': {}", line, e))?;
        if chunk_size == 0 {
            break;
        }
        let chunk_start = cursor + pos + 2;
        // Checked: the size comes off the wire, and `chunk_start + chunk_size`
        // on a hostile or corrupt value overflows. `panic = "abort"` makes an
        // overflow panic a dead window rather than a caught error.
        let Some(chunk_end) = chunk_start.checked_add(chunk_size) else {
            return Err("chunk size out of range".to_string());
        };
        if chunk_end > raw.len() {
            return Err("truncated chunk data in HTTP response".to_string());
        }
        out.extend_from_slice(&raw[chunk_start..chunk_end]);
        cursor = chunk_end + 2; // skip trailing \r\n
    }
    Ok(out)
}

/// Synchronously fetches the latest release from the GitHub API over HTTPS.
pub fn fetch_latest_release() -> Result<ReleaseInfo, String> {
    let mut sock = connect_tcp(API_HOST, 443)?;

    let server_name = ServerName::try_from(API_HOST)
        .map_err(|e| format!("invalid TLS server name {}: {}", API_HOST, e))?;
    let mut conn = ClientConnection::new(tls_config(), server_name)
        .map_err(|e| format!("failed to initialize TLS client connection: {}", e))?;
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);

    let req = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: ag_unlocker/{}\r\n\
         Accept: application/vnd.github.v3+json\r\n\
         Connection: close\r\n\r\n",
        API_PATH,
        API_HOST,
        current_version()
    );

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("failed to write HTTP request: {}", e))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush request: {}", e))?;

    let mut response_buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response_buf.extend_from_slice(&chunk[..n]);
                if response_buf.len() > MAX_BODY {
                    return Err(format!("response body exceeded limit ({} bytes)", MAX_BODY));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Connection closed without TLS close_notify alert
                break;
            }
            Err(e) => return Err(format!("error reading HTTPS response: {}", e)),
        }
    }

    if response_buf.is_empty() {
        return Err("empty response received from GitHub API".to_string());
    }

    let header_delim = response_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "missing header delimiter in HTTP response".to_string())?;

    let header_bytes = &response_buf[..header_delim];
    let header_str = String::from_utf8_lossy(header_bytes);
    let body_raw = &response_buf[header_delim + 4..];

    let mut lines = header_str.lines();
    let status_line = lines.next().unwrap_or("");
    if !status_line.contains(" 200") {
        return Err(format!(
            "GitHub API returned non-200 status: {}",
            status_line
        ));
    }

    let is_chunked = lines.any(|l| {
        let lower = l.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });

    let body_bytes = if is_chunked {
        decode_chunked(body_raw)?
    } else {
        body_raw.to_vec()
    };

    let release: ReleaseInfo = serde_json::from_slice(&body_bytes)
        .map_err(|e| format!("failed to deserialize release JSON: {}", e))?;

    Ok(release)
}

/// Checks for updates respecting `CHECK_INTERVAL` (8 hours).
/// If `force` is false, it uses the cached result if available and fresh.
/// If an update is available, returns `Ok(Some(release))`.
pub fn check_update_cached(force: bool) -> Result<Option<ReleaseInfo>, String> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let path = cache_path();
    if !force {
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(cached) = serde_json::from_str::<CachedCheck>(&data) {
                if now_unix >= cached.checked_at_unix
                    && Duration::from_secs(now_unix - cached.checked_at_unix) < CHECK_INTERVAL
                {
                    return if cached.release.is_newer_than_current() {
                        Ok(Some(cached.release))
                    } else {
                        Ok(None)
                    };
                }
            }
        }
    }

    let release = fetch_latest_release()?;
    let cache_entry = CachedCheck {
        checked_at_unix: now_unix,
        release: release.clone(),
    };
    if let Ok(serialized) = serde_json::to_string(&cache_entry) {
        fs::write(&path, serialized).ok();
    }

    if release.is_newer_than_current() {
        Ok(Some(release))
    } else {
        Ok(None)
    }
}

/// Helper to parse https:// URLs into (host, port, path_and_query).
pub fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("Поддерживаются только https:// ссылки: {}", url))?;
    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.find(':') {
        Some(idx) => {
            let host = &host_port[..idx];
            let port = host_port[idx + 1..]
                .parse::<u16>()
                .map_err(|e| format!("Некорректный порт: {}", e))?;
            (host.to_string(), port)
        }
        None => (host_port.to_string(), 443),
    };
    Ok((host, port, path.to_string()))
}

/// Resolves redirect location header (relative or absolute) against base host and port.
pub fn resolve_redirect(base_host: &str, base_port: u16, loc: &str) -> String {
    let loc = loc.trim();
    if loc.starts_with("http://") || loc.starts_with("https://") {
        loc.to_string()
    } else if loc.starts_with('/') {
        if base_port == 443 {
            format!("https://{}{}", base_host, loc)
        } else {
            format!("https://{}:{}{}", base_host, base_port, loc)
        }
    } else {
        if base_port == 443 {
            format!("https://{}/{}", base_host, loc)
        } else {
            format!("https://{}:{}/{}", base_host, base_port, loc)
        }
    }
}

/// Downloads a file over HTTPS directly to disk, following redirects.
pub fn download_file(
    initial_url: &str,
    dest_path: &Path,
    progress_cb: impl Fn(u64, Option<u64>),
) -> Result<(), String> {
    let mut current_url = initial_url.to_string();
    let mut redirects = 0;
    const MAX_REDIRECTS: usize = 10;

    loop {
        if redirects >= MAX_REDIRECTS {
            return Err("Слишком много перенаправлений (redirects) при скачивании".to_string());
        }

        let (host, port, path) = parse_url(&current_url)?;
        let mut sock = connect_tcp(&host, port)?;

        let server_name = ServerName::try_from(host.as_str())
            .map_err(|e| format!("Некорректное имя TLS сервера {}: {}", host, e))?
            .to_owned();
        let mut conn = ClientConnection::new(tls_config(), server_name)
            .map_err(|e| format!("Ошибка TLS соединения: {}", e))?;
        let mut stream = rustls::Stream::new(&mut conn, &mut sock);

        let req = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: ag_unlocker/{}\r\n\
             Accept: application/octet-stream, */*\r\n\
             Connection: close\r\n\r\n",
            path,
            host,
            current_version()
        );

        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("Ошибка отправки HTTP-запроса: {}", e))?;
        stream
            .flush()
            .map_err(|e| format!("Ошибка сброса HTTP-буфера: {}", e))?;

        let mut header_buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut body_start_idx = None;

        while header_buf.len() < 32 * 1024 {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let prev_len = header_buf.len();
                    header_buf.extend_from_slice(&chunk[..n]);
                    let search_from = prev_len.saturating_sub(3);
                    if let Some(pos) = header_buf[search_from..]
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                    {
                        body_start_idx = Some(search_from + pos + 4);
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("Ошибка чтения ответа сервера: {}", e)),
            }
        }

        let body_start = body_start_idx
            .ok_or_else(|| "Не удалось получить HTTP-заголовки ответа".to_string())?;

        let header_str = String::from_utf8_lossy(&header_buf[..body_start]);
        let mut lines = header_str.lines();
        let status_line = lines.next().unwrap_or("");

        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        if status_code == 301
            || status_code == 302
            || status_code == 303
            || status_code == 307
            || status_code == 308
        {
            let mut loc = None;
            for line in lines {
                if let Some(pos) = line.find(':') {
                    let name = line[..pos].trim();
                    if name.eq_ignore_ascii_case("location") {
                        loc = Some(line[pos + 1..].trim().to_string());
                        break;
                    }
                }
            }
            let loc = loc.ok_or_else(|| {
                format!("Редирект {} без заголовка Location", status_code)
            })?;
            current_url = resolve_redirect(&host, port, &loc);
            redirects += 1;
            continue;
        }

        if status_code != 200 {
            return Err(format!(
                "Сервер вернул ошибку при скачивании: {}",
                status_line
            ));
        }

        let mut content_length = None;
        for line in lines {
            if let Some(pos) = line.find(':') {
                let name = line[..pos].trim();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = line[pos + 1..].trim().parse::<u64>().ok();
                    break;
                }
            }
        }

        let mut file = fs::File::create(dest_path)
            .map_err(|e| format!("Не удалось создать файл для записи: {}", e))?;

        let mut downloaded_bytes: u64 = 0;
        let mut last_reported = 0u64;

        progress_cb(0, content_length);

        if body_start < header_buf.len() {
            let initial_body = &header_buf[body_start..];
            file.write_all(initial_body)
                .map_err(|e| format!("Ошибка записи в файл: {}", e))?;
            downloaded_bytes += initial_body.len() as u64;
            last_reported = downloaded_bytes;
            progress_cb(downloaded_bytes, content_length);
        }

        let mut read_buf = [0u8; 64 * 1024];
        loop {
            match stream.read(&mut read_buf) {
                Ok(0) => break,
                Ok(n) => {
                    file.write_all(&read_buf[..n])
                        .map_err(|e| format!("Ошибка записи в файл: {}", e))?;
                    downloaded_bytes += n as u64;

                    if downloaded_bytes.saturating_sub(last_reported) >= 64 * 1024 {
                        last_reported = downloaded_bytes;
                        progress_cb(downloaded_bytes, content_length);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("Ошибка при скачивании данных: {}", e)),
            }
        }

        file.flush()
            .map_err(|e| format!("Ошибка сброса буфера файла: {}", e))?;
        progress_cb(downloaded_bytes, content_length);

        if let Some(expected) = content_length {
            if downloaded_bytes < expected {
                return Err(format!(
                    "Файл загружен не полностью (получено {} из {} байт)",
                    downloaded_bytes, expected
                ));
            }
        }

        return Ok(());
    }
}

/// Downloads binary from release and replaces the currently running executable.
pub fn perform_update(
    release: &ReleaseInfo,
    progress_cb: impl Fn(u64, Option<u64>),
) -> Result<(), String> {
    let asset = release.find_binary_asset().ok_or_else(|| {
        #[cfg(windows)]
        let expected = "ag_unlocker.exe";
        #[cfg(not(windows))]
        let expected = "ag_unlocker";
        format!(
            "В релизе {} не найден файл для обновления ('{}')",
            release.tag_name, expected
        )
    })?;

    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("ag_unlocker_update_{}.tmp", std::process::id()));

    let dl_res = download_file(&asset.browser_download_url, &temp_path, &progress_cb);
    if let Err(e) = dl_res {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    let meta = fs::metadata(&temp_path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        format!("Ошибка чтения файла обновления: {}", e)
    })?;

    if meta.len() < 500 * 1024 {
        let _ = fs::remove_file(&temp_path);
        return Err(format!(
            "Скачанный файл повреждён или слишком мал ({} байт)",
            meta.len()
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        if let Err(e) = fs::set_permissions(&temp_path, perms) {
            let _ = fs::remove_file(&temp_path);
            return Err(format!("Не удалось установить права запуска (+x): {}", e));
        }
    }

    let replace_res = self_replace::self_replace(&temp_path);
    let _ = fs::remove_file(&temp_path);

    replace_res.map_err(|e| {
        format!(
            "Не удалось заменить файл программы: {} (возможно, требуются права администратора)",
            e
        )
    })?;

    Ok(())
}

/// Restarts the application by spawning the updated executable and terminating current process.
pub fn restart_process() -> Result<(), String> {
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к текущей программе: {}", e))?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();

    let mut cmd = std::process::Command::new(&current_exe);
    cmd.args(&args);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }

    cmd.spawn()
        .map_err(|e| format!("Не удалось перезапустить программу: {}", e))?;

    std::process::exit(0);
}

/// Messages emitted by the update background worker.
#[derive(Debug, Clone)]
pub enum UpdateMsg {
    Available(ReleaseInfo),
    Progress {
        version: String,
        downloaded: u64,
        total: Option<u64>,
        percent: f32,
    },
    Done {
        version: String,
    },
    Error {
        version: String,
        error: String,
    },
}

/// Commands sent to the update background worker.
#[derive(Debug, Clone)]
pub enum UpdateCmd {
    Download(ReleaseInfo),
}

/// Watches for updates and manages downloading in the background.
pub fn spawn_watch(
    tx: std::sync::mpsc::Sender<UpdateMsg>,
    wake: Arc<dyn Fn() + Send + Sync>,
    auto_download: bool,
) -> std::sync::mpsc::Sender<UpdateCmd> {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<UpdateCmd>();
    let cmd_tx_clone = cmd_tx.clone();
    let tx_checker = tx.clone();
    let wake_checker = Arc::clone(&wake);

    std::thread::Builder::new()
        .name("update-watch".to_string())
        .spawn(move || {
            let mut first = true;
            loop {
                match check_update_cached(!first) {
                    Ok(Some(rel)) => {
                        let _ = tx_checker.send(UpdateMsg::Available(rel.clone()));
                        wake_checker();

                        if auto_download {
                            let _ = cmd_tx_clone.send(UpdateCmd::Download(rel));
                        }
                    }
                    Ok(None) => {}
                    Err(_e) => {
                        #[cfg(debug_assertions)]
                        eprintln!("update check failed: {}", _e);
                    }
                }
                first = false;
                std::thread::sleep(CHECK_INTERVAL);
            }
        })
        .ok();

    // Worker thread for downloading and updating
    let tx_worker = tx;
    std::thread::Builder::new()
        .name("update-worker".to_string())
        .spawn(move || {
            while let Ok(cmd) = cmd_rx.recv() {
                match cmd {
                    UpdateCmd::Download(rel) => {
                        let version = rel.display_version().to_string();
                        let ver_cb = version.clone();
                        let tx_cb = tx_worker.clone();
                        let wake_cb = Arc::clone(&wake);

                        let res = perform_update(&rel, move |downloaded, total| {
                            let percent = match total {
                                Some(tot) if tot > 0 => {
                                    ((downloaded as f64 / tot as f64) * 100.0) as f32
                                }
                                _ => 0.0,
                            };
                            let _ = tx_cb.send(UpdateMsg::Progress {
                                version: ver_cb.clone(),
                                downloaded,
                                total,
                                percent,
                            });
                            wake_cb();
                        });

                        match res {
                            Ok(()) => {
                                let _ = tx_worker.send(UpdateMsg::Done { version });
                                wake();
                            }
                            Err(e) => {
                                let _ = tx_worker.send(UpdateMsg::Error {
                                    version,
                                    error: e,
                                });
                                wake();
                            }
                        }
                    }
                }
            }
        })
        .ok();

    cmd_tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version_not_empty() {
        assert!(!current_version().is_empty());
    }

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("2.11.0_1", "2.11.0"));
        assert!(is_newer_version("v2.11.0_4", "2.11.0_1"));
        assert!(is_newer_version("2.12.0", "2.11.0_5"));
        assert!(is_newer_version("v3.0.0", "2.11.0"));
        assert!(!is_newer_version("2.11.0", "2.11.0"));
        assert!(!is_newer_version("v2.11.0", "2.11.0"));
        assert!(!is_newer_version("2.11.0_1", "2.11.0_4"));
        assert!(!is_newer_version("2.10.0", "2.11.0"));
    }

    #[test]
    fn test_release_json_deserialization() {
        let sample = r#"{
            "tag_name": "v2.11.0_4",
            "html_url": "https://github.com/confeden/Antigravity/releases/tag/v2.11.0_4",
            "name": "Релиз v2.11.0_4",
            "draft": false,
            "prerelease": false,
            "published_at": "2026-09-02T19:02:18Z",
            "body": "Release notes",
            "assets": [
                {
                    "name": "AG_2.11.0_4.exe",
                    "browser_download_url": "https://example.com/AG.exe",
                    "size": 12345
                }
            ]
        }"#;

        let rel: ReleaseInfo = serde_json::from_str(sample).expect("valid json");
        assert_eq!(rel.tag_name, "v2.11.0_4");
        assert_eq!(rel.display_version(), "2.11.0_4");
        assert_eq!(rel.assets.len(), 1);
        assert_eq!(rel.assets[0].name, "AG_2.11.0_4.exe");
    }

    #[test]
    fn test_decode_chunked() {
        let chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let decoded = decode_chunked(chunked).expect("chunked decode");
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn test_tls_config_init() {
        let cfg = tls_config();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn test_parse_url() {
        let (host, port, path) = parse_url("https://github.com/test/repo").unwrap();
        assert_eq!(host, "github.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/test/repo");

        let (host, port, path) = parse_url("https://example.com:8443/custom/path?query=1").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/custom/path?query=1");

        assert!(parse_url("http://insecure.com").is_err());
    }

    #[test]
    fn test_resolve_redirect() {
        assert_eq!(
            resolve_redirect("github.com", 443, "https://objects.githubusercontent.com/file"),
            "https://objects.githubusercontent.com/file"
        );
        assert_eq!(
            resolve_redirect("github.com", 443, "/relative/redirect"),
            "https://github.com/relative/redirect"
        );
    }

    #[test]
    fn test_find_binary_asset() {
        let sample = r#"{
            "tag_name": "v2.16.0",
            "html_url": "https://github.com/SatoKazuma1/Antigravity/releases/tag/v2.16.0",
            "assets": [
                {
                    "name": "ag_unlocker",
                    "browser_download_url": "https://github.com/downloads/ag_unlocker",
                    "size": 15000000
                },
                {
                    "name": "ag_unlocker.exe",
                    "browser_download_url": "https://github.com/downloads/ag_unlocker.exe",
                    "size": 10000000
                }
            ]
        }"#;

        let rel: ReleaseInfo = serde_json::from_str(sample).unwrap();
        let asset = rel.find_binary_asset();
        assert!(asset.is_some());
        #[cfg(windows)]
        assert_eq!(asset.unwrap().name, "ag_unlocker.exe");
        #[cfg(not(windows))]
        assert_eq!(asset.unwrap().name, "ag_unlocker");
    }

    #[test]
    #[ignore = "performs real HTTPS request to api.github.com; requires internet access"]
    fn test_live_fetch_latest_release() {
        let rel = fetch_latest_release().expect("live fetch succeeded");
        assert!(!rel.tag_name.is_empty());
        assert!(rel.html_url.contains("github.com"));
    }

    #[test]
    #[ignore = "performs real asset download; requires internet access"]
    fn test_live_download_asset() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_dl_ag_unlocker.bin");
        let url = "https://github.com/SatoKazuma1/Antigravity/releases/download/v2.16.0/ag_unlocker";
        let res = download_file(url, &temp_file, |_bytes, _tot| {});
        assert!(res.is_ok(), "download failed: {:?}", res.err());
        assert!(temp_file.exists());
        let meta = std::fs::metadata(&temp_file).unwrap();
        assert!(meta.len() > 10_000_000, "file too small: {}", meta.len());
        std::fs::remove_file(temp_file).ok();
    }
}
