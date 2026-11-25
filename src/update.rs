//! Self-update against GitHub Releases (silent check, download, verify, replace).
//!
//! Synchronous on purpose, like the rest of the crate: HTTPS over `rustls` with
//! HTTP redirect handling and streaming writes to disk, run off the UI thread.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_REPO: &str = "soroka-ilya/Antigravity";
pub const UPDATED_FROM_FLAG: &str = "--updated-from";
pub const INSTALL_UPDATE_FLAG: &str = "--install-update";

pub fn update_repo() -> &'static str {
    option_env!("AG_UPDATE_REPO").unwrap_or(DEFAULT_REPO)
}

pub fn releases_latest_url() -> String {
    format!("https://github.com/{}/releases/latest", update_repo())
}

fn api_path() -> String {
    format!("/repos/{}/releases/latest", update_repo())
}

const API_HOST: &str = "api.github.com";
const CHECK_INTERVAL: Duration = Duration::from_secs(8 * 60 * 60);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const API_IO_TIMEOUT: Duration = Duration::from_secs(10);
const DOWNLOAD_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_API_BODY: usize = 512 * 1024;
const MAX_DOWNLOAD_BYTES: usize = 128 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

/// The version this binary shipped as, in the form the release tags use.
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
        !self.draft && !self.prerelease && is_newer_version(&self.tag_name, current_version())
    }

    /// Strips leading 'v' / 'V' and whitespace from tag name for display.
    pub fn display_version(&self) -> &str {
        self.tag_name
            .trim()
            .trim_start_matches(|c| c == 'v' || c == 'V')
    }
}

#[derive(Debug, Clone)]
pub enum UpdateEvent {
    Checking,
    UpToDate {
        version: String,
        latest: String,
    },
    CheckFailed(String),
    Available(ReleaseInfo),
    Downloading {
        version: String,
        downloaded: u64,
        total: Option<u64>,
    },
    ReadyToRestart {
        version: String,
        exe: PathBuf,
    },
    Failed {
        release: ReleaseInfo,
        reason: String,
        needs_elevation: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFailure {
    pub reason: String,
    pub needs_elevation: bool,
}

impl From<String> for UpdateFailure {
    fn from(reason: String) -> Self {
        Self {
            reason,
            needs_elevation: false,
        }
    }
}

enum UpdateCmd {
    CheckNow,
    Install(ReleaseInfo),
}

#[derive(Clone)]
pub struct UpdateHandle {
    tx: std::sync::mpsc::Sender<UpdateCmd>,
}

impl UpdateHandle {
    pub fn check_now(&self) {
        let _ = self.tx.send(UpdateCmd::CheckNow);
    }

    pub fn install_now(&self, rel: ReleaseInfo) {
        let _ = self.tx.send(UpdateCmd::Install(rel));
    }
}

pub fn up_to_date_label(version: &str, latest: &str) -> String {
    if latest.is_empty() || version == latest {
        format!("Установлена актуальная версия (v{version})")
    } else {
        format!("Версия v{version} (последний релиз v{latest})")
    }
}

/// Compares two version strings (e.g. "v2.11.0_4" vs "2.11.0_1", "2.11.0" vs "2.10.0").
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

fn connect_tcp(host: &str, port: u16, io_timeout: Duration) -> Result<TcpStream, String> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {}: {}", host, e))?
        .collect();

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(sock) => {
                sock.set_read_timeout(Some(io_timeout)).ok();
                sock.set_write_timeout(Some(io_timeout)).ok();
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

fn parse_https_url(url: &str) -> Result<(String, u16, String), String> {
    let url = url.trim();
    if !url.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://")) {
        return Err("supported only over HTTPS".to_string());
    }
    let rest = &url[8..];
    let (authority, raw_path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err("invalid URL authority".to_string());
    }
    let path_part = raw_path.split('#').next().unwrap_or("/");
    let path = if path_part.starts_with('/') {
        path_part.to_string()
    } else {
        format!("/{path_part}")
    };
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']').ok_or_else(|| "invalid IPv6 host".to_string())?;
        let host = &authority[1..close];
        let tail = &authority[close + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| "invalid URL port".to_string())?
        } else if tail.is_empty() {
            443
        } else {
            return Err("invalid URL authority".to_string());
        };
        (host, port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p.parse::<u16>().map_err(|_| "invalid URL port".to_string())?;
        (h, port)
    } else {
        (authority, 443)
    };
    if host.is_empty() || port == 0 {
        return Err("invalid URL host or port".to_string());
    }
    Ok((host.to_string(), port, path.to_string()))
}

fn resolve_redirect(current_url: &str, location: &str) -> Result<String, String> {
    let loc = location.trim();
    if loc.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://")) {
        return Ok(loc.to_string());
    }
    if loc.get(..7).is_some_and(|s| s.eq_ignore_ascii_case("http://")) {
        return Err("refusing insecure http:// redirect".to_string());
    }
    if loc.starts_with("//") {
        return Ok(format!("https:{loc}"));
    }
    if loc.starts_with('/') {
        let (host, port, _) = parse_https_url(current_url)?;
        let origin = if port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{port}")
        };
        return Ok(format!("{origin}{loc}"));
    }
    Err("unsupported relative redirect".to_string())
}

#[derive(Default)]
struct ChunkDecoder {
    buf: Vec<u8>,
    remaining: Option<usize>,
    expect_crlf: bool,
    done: bool,
}

impl ChunkDecoder {
    fn push(
        &mut self,
        data: &[u8],
        out: &mut dyn FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        self.buf.extend_from_slice(data);
        while !self.done {
            if self.expect_crlf {
                if self.buf.len() < 2 {
                    break;
                }
                if &self.buf[..2] != b"\r\n" {
                    return Err("invalid chunk terminator".to_string());
                }
                self.buf.drain(..2);
                self.expect_crlf = false;
                continue;
            }
            if let Some(rem) = self.remaining {
                if self.buf.is_empty() {
                    break;
                }
                let take = rem.min(self.buf.len());
                out(&self.buf[..take])?;
                self.buf.drain(..take);
                if take == rem {
                    self.remaining = None;
                    self.expect_crlf = true;
                } else {
                    self.remaining = Some(rem - take);
                }
                continue;
            }
            let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") else {
                if self.buf.len() > 256 {
                    return Err("chunk header too long".to_string());
                }
                break;
            };
            let line = std::str::from_utf8(&self.buf[..pos])
                .map_err(|e| format!("invalid chunk size encoding: {}", e))?
                .trim();
            let hex = line.split(';').next().unwrap_or("").trim();
            let chunk_size = usize::from_str_radix(hex, 16)
                .map_err(|e| format!("invalid chunk size hex '{}': {}", line, e))?;
            self.buf.drain(..pos + 2);
            if chunk_size == 0 {
                self.done = true;
                break;
            }
            self.remaining = Some(chunk_size);
        }
        Ok(())
    }
}

#[cfg(test)]
fn decode_chunked(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut dec = ChunkDecoder::default();
    dec.push(raw, &mut |slice| {
        out.extend_from_slice(slice);
        Ok(())
    })?;
    if !dec.done {
        return Err("truncated chunk data in HTTP response".to_string());
    }
    Ok(out)
}

fn read_http_headers(stream: &mut dyn Read) -> Result<(String, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let delim = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err("HTTP response headers too large".to_string());
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err("empty or truncated HTTP headers".to_string()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("error reading HTTP headers: {}", e)),
        }
    };
    let headers = String::from_utf8_lossy(&buf[..delim]).into_owned();
    let initial_body = buf[delim + 4..].to_vec();
    Ok((headers, initial_body))
}

fn parse_status_code(header_str: &str) -> Option<u16> {
    header_str
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()
}

fn header_value<'a>(header_str: &'a str, name: &str) -> Option<&'a str> {
    header_str.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

enum FetchOutcome {
    Redirect(String),
    NotModified,
    Done { etag: Option<String> },
}

enum StreamOutcome {
    NotModified,
    Body { etag: Option<String> },
}

enum ConditionalFetch {
    NotModified,
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
    },
}

fn sanitize_etag(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains(['\r', '\n']) {
        return None;
    }
    Some(trimmed.to_string())
}

enum HttpEvent<'a> {
    Start(Option<u64>),
    Chunk(&'a [u8]),
}

fn push_chunk(
    received: &mut usize,
    max_bytes: usize,
    slice: &[u8],
    on_event: &mut dyn FnMut(HttpEvent<'_>) -> Result<(), String>,
) -> Result<(), String> {
    let next = received
        .checked_add(slice.len())
        .ok_or_else(|| "response size overflow".to_string())?;
    if next > max_bytes {
        return Err(format!("response exceeded limit ({} bytes)", max_bytes));
    }
    *received = next;
    on_event(HttpEvent::Chunk(slice))
}

fn stream_body(
    stream: &mut dyn Read,
    initial: &[u8],
    is_chunked: bool,
    content_len: Option<u64>,
    max_bytes: usize,
    on_event: &mut dyn FnMut(HttpEvent<'_>) -> Result<(), String>,
) -> Result<(), String> {
    let mut received: usize = 0;
    let mut buf = [0u8; 16 * 1024];
    if is_chunked {
        let mut dec = ChunkDecoder::default();
        if !initial.is_empty() {
            dec.push(initial, &mut |s| push_chunk(&mut received, max_bytes, s, on_event))?;
        }
        while !dec.done {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    dec.push(&buf[..n], &mut |s| push_chunk(&mut received, max_bytes, s, on_event))?;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("error reading chunked response: {}", e)),
            }
        }
        if !dec.done {
            return Err("truncated chunked HTTP response".to_string());
        }
        return Ok(());
    }

    if !initial.is_empty() {
        push_chunk(&mut received, max_bytes, initial, on_event)?;
    }
    loop {
        if content_len.is_some_and(|l| (received as u64) >= l) {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => push_chunk(&mut received, max_bytes, &buf[..n], on_event)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                if content_len.is_some_and(|l| (received as u64) < l) {
                    return Err("truncated HTTP download (unexpected EOF)".to_string());
                }
                break;
            }
            Err(e) => return Err(format!("error reading HTTP response: {}", e)),
        }
    }
    if let Some(expected) = content_len {
        if (received as u64) != expected {
            return Err(format!(
                "incomplete HTTP response: got {} of {} bytes",
                received, expected
            ));
        }
    }
    Ok(())
}

fn http_get_once(
    url: &str,
    accept: &str,
    if_none_match: Option<&str>,
    io_timeout: Duration,
    max_bytes: usize,
    on_event: &mut dyn FnMut(HttpEvent<'_>) -> Result<(), String>,
) -> Result<FetchOutcome, String> {
    let (host, port, path) = parse_https_url(url)?;
    let mut sock = connect_tcp(&host, port, io_timeout)?;
    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| format!("invalid TLS server name {}: {}", host, e))?;
    let mut conn = ClientConnection::new(tls_config(), server_name)
        .map_err(|e| format!("failed to initialize TLS client connection: {}", e))?;
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);

    let host_header = if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    };
    let inm_header = if_none_match
        .and_then(sanitize_etag)
        .map(|tag| format!("If-None-Match: {tag}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: ag_unlocker/{}\r\n\
         Accept: {accept}\r\n\
         {inm_header}\
         Connection: close\r\n\r\n",
        current_version()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("failed to write HTTP request: {}", e))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush HTTP request: {}", e))?;

    let (header_str, initial_body) = read_http_headers(&mut stream)?;
    let code = parse_status_code(&header_str)
        .ok_or_else(|| "invalid HTTP status line".to_string())?;
    if code == 304 {
        return Ok(FetchOutcome::NotModified);
    }
    if matches!(code, 301 | 302 | 303 | 307 | 308) {
        let loc = header_value(&header_str, "location")
            .ok_or_else(|| format!("redirect HTTP {} without Location", code))?;
        return Ok(FetchOutcome::Redirect(resolve_redirect(url, loc)?));
    }
    if code != 200 {
        return Err(format!("HTTP {} while fetching {}", code, url));
    }

    let etag = header_value(&header_str, "etag").and_then(sanitize_etag);
    let is_chunked = header_value(&header_str, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let content_len = header_value(&header_str, "content-length")
        .and_then(|v| v.parse::<u64>().ok());
    if content_len.is_some_and(|l| l > max_bytes as u64) {
        return Err(format!("response exceeded limit ({} bytes)", max_bytes));
    }
    on_event(HttpEvent::Start(content_len))?;
    stream_body(
        &mut stream,
        &initial_body,
        is_chunked,
        content_len,
        max_bytes,
        on_event,
    )?;
    Ok(FetchOutcome::Done { etag })
}

fn http_get_stream(
    url: &str,
    accept: &str,
    if_none_match: Option<&str>,
    io_timeout: Duration,
    max_bytes: usize,
    on_event: &mut dyn FnMut(HttpEvent<'_>) -> Result<(), String>,
) -> Result<StreamOutcome, String> {
    let mut current = url.to_string();
    for attempt in 0..=MAX_REDIRECTS {
        let etag_hdr = if attempt == 0 { if_none_match } else { None };
        match http_get_once(&current, accept, etag_hdr, io_timeout, max_bytes, on_event)? {
            FetchOutcome::Redirect(next) => current = next,
            FetchOutcome::NotModified => return Ok(StreamOutcome::NotModified),
            FetchOutcome::Done { etag } => return Ok(StreamOutcome::Body { etag }),
        }
    }
    Err("too many HTTP redirects".to_string())
}

fn fetch_conditional(
    url: &str,
    accept: &str,
    if_none_match: Option<&str>,
    timeout: Duration,
    max_bytes: usize,
) -> Result<ConditionalFetch, String> {
    let mut body = Vec::new();
    match http_get_stream(url, accept, if_none_match, timeout, max_bytes, &mut |ev| {
        if let HttpEvent::Chunk(slice) = ev {
            body.extend_from_slice(slice);
        }
        Ok(())
    })? {
        StreamOutcome::NotModified => Ok(ConditionalFetch::NotModified),
        StreamOutcome::Body { etag } => Ok(ConditionalFetch::Body { bytes: body, etag }),
    }
}

fn fetch_bytes(url: &str, accept: &str, timeout: Duration, max_bytes: usize) -> Result<Vec<u8>, String> {
    match fetch_conditional(url, accept, None, timeout, max_bytes)? {
        ConditionalFetch::Body { bytes, .. } => Ok(bytes),
        ConditionalFetch::NotModified => Err("unexpected HTTP 304 Not Modified".to_string()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedRelease {
    repo: String,
    etag: Option<String>,
    release: ReleaseInfo,
}

fn default_cache_path() -> Option<PathBuf> {
    if cfg!(test) {
        return None;
    }
    let dir = crate::dns_forwarder::log_dir();
    (!dir.as_os_str().is_empty()).then(|| dir.join("update_cache.json"))
}

fn load_cached_release(path: &Path, expected_repo: &str) -> Option<CachedRelease> {
    let raw = fs::read_to_string(path).ok()?;
    let cached: CachedRelease = serde_json::from_str(&raw).ok()?;
    (cached.repo == expected_repo).then_some(cached)
}

fn save_cached_release(path: &Path, cached: &CachedRelease) {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(json) = serde_json::to_string(cached) {
        let tmp = sibling_path(path, &format!(".{}.tmp", std::process::id()));
        if fs::write(&tmp, json).is_ok() {
            if fs::rename(&tmp, path).is_err() {
                let _ = fs::remove_file(&tmp);
            }
        }
    }
}

fn fetch_latest_with_cache<F>(
    repo: &str,
    cache_path: Option<&Path>,
    mut fetch: F,
) -> Result<ReleaseInfo, String>
where
    F: FnMut(Option<&str>) -> Result<ConditionalFetch, String>,
{
    let cached = cache_path.and_then(|p| load_cached_release(p, repo));
    let etag_arg = cached.as_ref().and_then(|c| c.etag.as_deref());
    let outcome = match (fetch(etag_arg)?, cached) {
        (ConditionalFetch::NotModified, Some(hit)) => return Ok(hit.release),
        (ConditionalFetch::NotModified, None) => fetch(None)?,
        (other, _) => other,
    };
    let ConditionalFetch::Body { bytes, etag } = outcome else {
        return Err("unexpected HTTP 304 without cached release".to_string());
    };
    let rel: ReleaseInfo = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to deserialize release JSON: {}", e))?;
    if let Some(path) = cache_path {
        save_cached_release(
            path,
            &CachedRelease {
                repo: repo.to_string(),
                etag,
                release: rel.clone(),
            },
        );
    }
    Ok(rel)
}

/// Synchronously fetches the latest release from the GitHub API over HTTPS, using ETag cache.
pub fn fetch_latest_release() -> Result<ReleaseInfo, String> {
    let url = format!("https://{}{}", API_HOST, api_path());
    let cache = default_cache_path();
    fetch_latest_with_cache(update_repo(), cache.as_deref(), |etag| {
        fetch_conditional(&url, "application/vnd.github.v3+json", etag, API_IO_TIMEOUT, MAX_API_BODY)
    })
}

fn underscore_patch_ver(ver: &str) -> String {
    if let Some(pos) = ver.rfind('.') {
        if ver[..pos].contains('.') && ver[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
            let mut s = ver.to_string();
            s.replace_range(pos..=pos, "_");
            return s;
        }
    }
    ver.to_string()
}

fn expected_asset_names(ver: &str, os: &str, arch: &str) -> Vec<String> {
    let clean = ver.trim().trim_start_matches(|c| c == 'v' || c == 'V');
    let alt = underscore_patch_ver(clean);
    let mut forms = vec![clean.to_string()];
    if alt != clean {
        forms.push(alt);
    }
    let mut out = Vec::new();
    for v in forms {
        match os {
            "windows" => out.push(format!("AG_{v}.exe")),
            "linux" if arch == "aarch64" => {
                out.push(format!("AG_{v}_linux_arm64.tar.gz"));
                out.push(format!("AG_{v}_linux_aarch64.tar.gz"));
            }
            "linux" => out.push(format!("AG_{v}_linux.tar.gz")),
            "macos" if arch == "x86_64" => {
                out.push(format!("AG_{v}_macos_x64.tar.gz"));
                out.push(format!("AG_{v}_macos.tar.gz"));
            }
            "macos" => out.push(format!("AG_{v}_macos.tar.gz")),
            _ => {}
        }
    }
    out
}

pub fn select_asset<'a>(rel: &'a ReleaseInfo, os: &str, arch: &str) -> Option<&'a ReleaseAsset> {
    for candidate in expected_asset_names(rel.display_version(), os, arch) {
        if let Some(asset) = rel
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(&candidate))
        {
            return Some(asset);
        }
    }
    if os == "windows" {
        let exes: Vec<&ReleaseAsset> = rel
            .assets
            .iter()
            .filter(|a| {
                let low = a.name.to_ascii_lowercase();
                low.starts_with("ag_") && low.ends_with(".exe")
            })
            .collect();
        if exes.len() == 1 {
            return Some(exes[0]);
        }
    }
    None
}

fn find_checksum_asset<'a>(rel: &'a ReleaseInfo, asset_name: &str) -> Option<&'a ReleaseAsset> {
    let per_asset = format!("{asset_name}.sha256");
    rel.assets.iter().find(|a| {
        a.name.eq_ignore_ascii_case("SHA256SUMS.txt")
            || a.name.eq_ignore_ascii_case("SHA256SUMS")
            || a.name.eq_ignore_ascii_case(&per_asset)
    })
}

pub fn parse_sha256_for_asset(text: &str, asset_name: &str) -> Option<String> {
    let valid_hex = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let mut single_line_hex = None;
    let mut non_empty = 0usize;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        non_empty += 1;
        let mut parts = line.split_whitespace();
        let Some(hash) = parts.next() else { continue };
        if !valid_hex(hash) {
            continue;
        }
        if let Some(file) = parts.next() {
            let clean_file = file.trim_start_matches('*').trim_start_matches("./");
            if clean_file.eq_ignore_ascii_case(asset_name) {
                return Some(hash.to_ascii_lowercase());
            }
        } else {
            single_line_hex = Some(hash.to_ascii_lowercase());
        }
    }
    if non_empty == 1 {
        return single_line_hex;
    }
    None
}

fn sibling_path(exe: &Path, suffix: &str) -> PathBuf {
    let mut s = exe.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaceAccess {
    Writable,
    NeedsElevation,
    Blocked(String),
}

fn classify_write_error(err: &io::Error, can_elevate: bool) -> ReplaceAccess {
    if can_elevate && err.kind() == io::ErrorKind::PermissionDenied {
        ReplaceAccess::NeedsElevation
    } else {
        ReplaceAccess::Blocked(format!("нет прав на запись в папку программы: {err}"))
    }
}

pub fn check_replace_access(exe: &Path) -> ReplaceAccess {
    let Some(dir) = exe.parent() else {
        return ReplaceAccess::Blocked("не определена папка программы".to_string());
    };
    let probe = dir.join(format!(".ag_update_probe_{}", std::process::id()));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            ReplaceAccess::Writable
        }
        Err(e) => classify_write_error(
            &e,
            cfg!(target_os = "windows") && !crate::utils::is_admin(),
        ),
    }
}

fn has_valid_executable_magic(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut head = [0u8; 4];
    if f.read_exact(&mut head).is_err() {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        head.starts_with(b"MZ")
    }
    #[cfg(target_os = "linux")]
    {
        head == *b"\x7fELF"
    }
    #[cfg(target_os = "macos")]
    {
        crate::macos::is_macho(&head)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        true
    }
}

fn update_io_err(context: &str, err: &io::Error) -> UpdateFailure {
    let needs_elevation = cfg!(target_os = "windows")
        && !crate::utils::is_admin()
        && err.kind() == io::ErrorKind::PermissionDenied;
    UpdateFailure {
        reason: format!("{context}: {err}"),
        needs_elevation,
    }
}

fn replace_executable(current_exe: &Path, staged_bin: &Path) -> Result<(), UpdateFailure> {
    #[cfg(target_os = "windows")]
    {
        let old_exe = sibling_path(current_exe, ".old");
        let _ = fs::remove_file(&old_exe);
        fs::rename(current_exe, &old_exe)
            .map_err(|e| update_io_err("не переименовать текущий файл", &e))?;
        if let Err(e) = fs::rename(staged_bin, current_exe) {
            let _ = fs::rename(&old_exe, current_exe);
            return Err(update_io_err("не записать обновление", &e));
        }
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(staged_bin, fs::Permissions::from_mode(0o755))
            .map_err(|e| update_io_err("chmod", &e))?;
        #[cfg(target_os = "macos")]
        crate::macos::strip_quarantine(staged_bin);
        fs::rename(staged_bin, current_exe)
            .map_err(|e| update_io_err("не заменить исполняемый файл", &e))?;
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn find_extracted_binary(dir: &Path) -> Option<PathBuf> {
    let direct = dir.join("ag_unlocker");
    if fs::symlink_metadata(&direct)
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        return Some(direct);
    }
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        if fs::symlink_metadata(&p).map(|m| m.is_dir()).unwrap_or(false) {
            let cand = p.join("ag_unlocker");
            if fs::symlink_metadata(&cand)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                return Some(cand);
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn extract_tar_gz_binary(
    archive: &Path,
    extract_dir: &Path,
    staged_bin: &Path,
) -> Result<(), String> {
    let _ = fs::remove_dir_all(extract_dir);
    fs::create_dir_all(extract_dir).map_err(|e| format!("не создать каталог распаковки: {e}"))?;
    let out = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(extract_dir)
        .output()
        .map_err(|e| format!("не удалось запустить tar: {e}"))?;
    if !out.status.success() {
        let _ = fs::remove_dir_all(extract_dir);
        return Err(format!(
            "tar завершился с ошибкой: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let found = find_extracted_binary(extract_dir)
        .ok_or_else(|| "в архиве не найден ag_unlocker".to_string())?;
    let res = fs::rename(&found, staged_bin).or_else(|_| fs::copy(&found, staged_bin).map(|_| ()));
    let _ = fs::remove_dir_all(extract_dir);
    res.map_err(|e| format!("не подготовить бинарник: {e}"))
}

fn download_to_file(
    url: &str,
    dest: &Path,
    expected_sha256: Option<&str>,
    mut on_progress: impl FnMut(u64, Option<u64>),
) -> Result<u64, String> {
    let mut file = File::create(dest).map_err(|e| format!("не создать {}: {e}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut total_hint: Option<u64> = None;
    let mut last_report = Instant::now();

    http_get_stream(
        url,
        "application/octet-stream",
        None,
        DOWNLOAD_IO_TIMEOUT,
        MAX_DOWNLOAD_BYTES,
        &mut |ev| match ev {
            HttpEvent::Start(total) => {
                total_hint = total;
                on_progress(0, total);
                Ok(())
            }
            HttpEvent::Chunk(slice) => {
                file.write_all(slice)
                    .map_err(|e| format!("ошибка записи обновления: {e}"))?;
                hasher.update(slice);
                downloaded += slice.len() as u64;
                if last_report.elapsed() >= Duration::from_millis(120) {
                    last_report = Instant::now();
                    on_progress(downloaded, total_hint);
                }
                Ok(())
            }
        },
    )?;
    file.flush()
        .map_err(|e| format!("ошибка сохранения обновления: {e}"))?;
    on_progress(downloaded, total_hint.or(Some(downloaded)));

    if let Some(expected) = expected_sha256 {
        let actual = hex::encode(hasher.finalize());
        if !actual.eq_ignore_ascii_case(expected) {
            return Err("контрольная сумма SHA-256 не совпала".to_string());
        }
    }
    Ok(downloaded)
}

pub fn perform_silent_update(
    rel: &ReleaseInfo,
    on_progress: impl FnMut(u64, Option<u64>),
) -> Result<PathBuf, UpdateFailure> {
    let exe = std::env::current_exe()
        .map_err(|e| UpdateFailure::from(format!("не найден путь к программе: {e}")))?;
    match check_replace_access(&exe) {
        ReplaceAccess::Writable => {}
        ReplaceAccess::NeedsElevation => {
            return Err(UpdateFailure {
                reason: "нужны права администратора для замены файла в папке программы".to_string(),
                needs_elevation: true,
            });
        }
        ReplaceAccess::Blocked(reason) => return Err(UpdateFailure::from(reason)),
    }
    let asset = select_asset(rel, std::env::consts::OS, std::env::consts::ARCH)
        .ok_or_else(|| UpdateFailure::from("в релизе нет сборки для этой платформы".to_string()))?;

    let expected_sha = if let Some(sum_asset) = find_checksum_asset(rel, &asset.name) {
        let raw = fetch_bytes(
            &sum_asset.browser_download_url,
            "text/plain",
            API_IO_TIMEOUT,
            MAX_API_BODY,
        )?;
        let text = String::from_utf8_lossy(&raw);
        Some(
            parse_sha256_for_asset(&text, &asset.name)
                .ok_or_else(|| UpdateFailure::from("в SHA256SUMS не найден хеш сборки".to_string()))?,
        )
    } else {
        None
    };

    let part = sibling_path(&exe, ".part");
    let _ = fs::remove_file(&part);

    #[cfg(target_os = "windows")]
    let download_target = part.clone();
    #[cfg(not(target_os = "windows"))]
    let download_target = sibling_path(&exe, ".download.tar.gz");
    #[cfg(not(target_os = "windows"))]
    let _ = fs::remove_file(&download_target);

    let got = match download_to_file(
        &asset.browser_download_url,
        &download_target,
        expected_sha.as_deref(),
        on_progress,
    ) {
        Ok(n) => n,
        Err(e) => {
            let _ = fs::remove_file(&download_target);
            return Err(UpdateFailure::from(e));
        }
    };
    if asset.size > 0 && got != asset.size {
        let _ = fs::remove_file(&download_target);
        return Err(UpdateFailure::from(format!(
            "неполный файл ({got} из {} байт)",
            asset.size
        )));
    }

    #[cfg(not(target_os = "windows"))]
    {
        let extract_dir = sibling_path(&exe, ".update_extract");
        let extracted = extract_tar_gz_binary(&download_target, &extract_dir, &part);
        let _ = fs::remove_file(&download_target);
        if let Err(e) = extracted {
            let _ = fs::remove_file(&part);
            return Err(UpdateFailure::from(e));
        }
    }

    if !has_valid_executable_magic(&part) {
        let _ = fs::remove_file(&part);
        return Err(UpdateFailure::from("скачанный файл не является исполняемым".to_string()));
    }
    if let Err(err) = replace_executable(&exe, &part) {
        let _ = fs::remove_file(&part);
        return Err(err);
    }
    Ok(exe)
}

pub fn updated_from_arg() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == UPDATED_FROM_FLAG {
            return args.next().filter(|v| !v.is_empty());
        }
        if let Some(val) = arg.strip_prefix(&format!("{UPDATED_FROM_FLAG}=")) {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

pub fn cleanup_old_binaries() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let _ = fs::remove_file(sibling_path(&exe, ".part"));
    let _ = fs::remove_file(sibling_path(&exe, ".download.tar.gz"));
    let _ = fs::remove_dir_all(sibling_path(&exe, ".update_extract"));

    let old = sibling_path(&exe, ".old");
    if !old.exists() {
        return;
    }
    if updated_from_arg().is_some() {
        std::thread::Builder::new()
            .name("update-cleanup".to_string())
            .spawn(move || {
                for _ in 0..12 {
                    if fs::remove_file(&old).is_ok() || !old.exists() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
            })
            .ok();
    } else {
        let _ = fs::remove_file(&old);
    }
}

pub fn has_install_update_arg() -> bool {
    std::env::args_os()
        .skip(1)
        .any(|a| a.to_string_lossy() == INSTALL_UPDATE_FLAG)
}

fn filter_relaunch_args(
    args: impl IntoIterator<Item = std::ffi::OsString>,
    old_version: &str,
) -> Vec<std::ffi::OsString> {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let s = arg.to_string_lossy();
        if s == UPDATED_FROM_FLAG {
            skip_next = true;
            continue;
        }
        if s.starts_with(&format!("{UPDATED_FROM_FLAG}=")) || s == INSTALL_UPDATE_FLAG {
            continue;
        }
        out.push(arg);
    }
    out.push(UPDATED_FROM_FLAG.into());
    out.push(old_version.into());
    out
}

pub fn relaunch_updated(exe: &Path, old_version: &str) -> Result<(), String> {
    let args = filter_relaunch_args(std::env::args_os().skip(1), old_version);
    Command::new(exe)
        .args(&args)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("не удалось запустить обновлённую версию: {e}"))
}

fn should_auto_update() -> bool {
    if updated_from_arg().is_some() {
        return false;
    }
    if has_install_update_arg() {
        return true;
    }
    if cfg!(debug_assertions) && std::env::var_os("AG_FORCE_AUTO_UPDATE").is_none() {
        return false;
    }
    crate::settings::Settings::load().auto_update
}

fn send_event(tx: &std::sync::mpsc::Sender<UpdateEvent>, wake: &dyn Fn(), ev: UpdateEvent) -> bool {
    if tx.send(ev).is_err() {
        return false;
    }
    wake();
    true
}

fn install_release(
    rel: ReleaseInfo,
    tx: &std::sync::mpsc::Sender<UpdateEvent>,
    wake: &dyn Fn(),
) -> bool {
    let ver = rel.display_version().to_string();
    if !send_event(
        tx,
        wake,
        UpdateEvent::Downloading {
            version: ver.clone(),
            downloaded: 0,
            total: None,
        },
    ) {
        return true;
    }
    let tx_prog = tx.clone();
    let ver_prog = ver.clone();
    match perform_silent_update(&rel, |downloaded, total| {
        let _ = tx_prog.send(UpdateEvent::Downloading {
            version: ver_prog.clone(),
            downloaded,
            total,
        });
        wake();
    }) {
        Ok(exe) => {
            let _ = send_event(tx, wake, UpdateEvent::ReadyToRestart { version: ver, exe });
            true
        }
        Err(err) => !send_event(
            tx,
            wake,
            UpdateEvent::Failed {
                release: rel,
                reason: err.reason,
                needs_elevation: err.needs_elevation,
            },
        ),
    }
}

fn check_once(
    manual: bool,
    tx: &std::sync::mpsc::Sender<UpdateEvent>,
    wake: &dyn Fn(),
) -> bool {
    if manual && !send_event(tx, wake, UpdateEvent::Checking) {
        return true;
    }
    match fetch_latest_release() {
        Ok(rel) => {
            if rel.is_newer_than_current() {
                if should_auto_update() {
                    return install_release(rel, tx, wake);
                }
                if !send_event(tx, wake, UpdateEvent::Available(rel)) {
                    return true;
                }
            } else if manual {
                let latest = rel.display_version().to_string();
                if !send_event(
                    tx,
                    wake,
                    UpdateEvent::UpToDate {
                        version: current_version().to_string(),
                        latest,
                    },
                ) {
                    return true;
                }
            }
        }
        Err(e) => {
            if manual {
                if !send_event(tx, wake, UpdateEvent::CheckFailed(e)) {
                    return true;
                }
            } else {
                #[cfg(debug_assertions)]
                eprintln!("update check failed: {}", e);
            }
        }
    }
    false
}

pub fn spawn_watch(tx: std::sync::mpsc::Sender<UpdateEvent>, wake: Box<dyn Fn() + Send>) -> UpdateHandle {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("update-watch".to_string())
        .spawn(move || {
            if check_once(false, &tx, &*wake) {
                return;
            }
            loop {
                let first = match cmd_rx.recv_timeout(CHECK_INTERVAL) {
                    Ok(cmd) => Some(cmd),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                };
                let mut cmd = first;
                while let Ok(next) = cmd_rx.try_recv() {
                    if matches!(next, UpdateCmd::Install(_)) || cmd.is_none() {
                        cmd = Some(next);
                    }
                }
                let stop = match cmd {
                    Some(UpdateCmd::Install(rel)) => install_release(rel, &tx, &*wake),
                    Some(UpdateCmd::CheckNow) => check_once(true, &tx, &*wake),
                    None => check_once(false, &tx, &*wake),
                };
                if stop {
                    return;
                }
            }
        })
        .ok();
    UpdateHandle { tx: cmd_tx }
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
            "html_url": "https://github.com/soroka-ilya/Antigravity/releases/tag/v2.11.0_4",
            "name": "Релиз v2.11.0_4",
            "draft": false,
            "prerelease": false,
            "published_at": "2026-09-02T19:02:18Z",
            "body": "Release notes",
            "assets": [{
                "name": "AG_2.11.0_4.exe",
                "browser_download_url": "https://example.com/AG.exe",
                "size": 12345
            }]
        }"#;
        let rel: ReleaseInfo = serde_json::from_str(sample).expect("valid json");
        assert_eq!(rel.tag_name, "v2.11.0_4");
        assert_eq!(rel.display_version(), "2.11.0_4");
        assert_eq!(rel.assets.len(), 1);
    }

    #[test]
    fn test_decode_chunked_and_split_chunks() {
        let chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(chunked).unwrap(), b"hello world");
        let mut out = Vec::new();
        let mut dec = ChunkDecoder::default();
        for b in chunked {
            dec.push(&[*b], &mut |s| {
                out.extend_from_slice(s);
                Ok(())
            })
            .unwrap();
        }
        assert!(dec.done);
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn test_parse_https_url_and_redirects() {
        assert_eq!(
            parse_https_url("https://github.com/a/b?x=1#frag").unwrap(),
            ("github.com".into(), 443, "/a/b?x=1".into())
        );
        assert!(parse_https_url("http://example.com/a").is_err());
        assert!(resolve_redirect("https://github.com/x", "http://evil.com/y").is_err());
        assert_eq!(
            resolve_redirect("https://github.com/x", "/dl/AG.exe").unwrap(),
            "https://github.com/dl/AG.exe"
        );
    }

    #[test]
    fn test_select_asset_per_platform() {
        let rel = ReleaseInfo {
            tag_name: "v2.35.0.1".into(),
            html_url: String::new(),
            name: None,
            body: None,
            published_at: None,
            prerelease: false,
            draft: false,
            assets: vec![
                ReleaseAsset {
                    name: "AG_2.35.0_1.exe".into(),
                    browser_download_url: "https://example.com/win".into(),
                    size: 100,
                },
                ReleaseAsset {
                    name: "AG_2.35.0_1_linux.tar.gz".into(),
                    browser_download_url: "https://example.com/lin".into(),
                    size: 100,
                },
                ReleaseAsset {
                    name: "AG_2.35.0_1_macos.tar.gz".into(),
                    browser_download_url: "https://example.com/mac".into(),
                    size: 100,
                },
            ],
        };
        assert_eq!(select_asset(&rel, "windows", "x86_64").unwrap().name, "AG_2.35.0_1.exe");
        assert_eq!(select_asset(&rel, "linux", "x86_64").unwrap().name, "AG_2.35.0_1_linux.tar.gz");
        assert_eq!(select_asset(&rel, "macos", "aarch64").unwrap().name, "AG_2.35.0_1_macos.tar.gz");
    }

    #[test]
    fn test_parse_sha256_for_asset() {
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sums = format!("{hash}  ./AG_2.35.0.exe\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  other.tar.gz\n");
        assert_eq!(parse_sha256_for_asset(&sums, "AG_2.35.0.exe").as_deref(), Some(hash));
        assert_eq!(parse_sha256_for_asset(&sums, "missing.exe"), None);
    }

    #[test]
    fn test_replace_executable_round_trip() {
        let dir = std::env::temp_dir().join("ag_update_replace_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("ag_test.exe");
        let staged = dir.join("ag_test.exe.part");
        fs::write(&exe, b"old-binary").unwrap();
        fs::write(&staged, b"new-binary").unwrap();
        replace_executable(&exe, &staged).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"new-binary");
        assert!(!staged.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tls_config_init() {
        let cfg = tls_config();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    #[ignore = "performs real HTTPS request to api.github.com; requires internet access"]
    fn test_live_fetch_latest_release() {
        let rel = fetch_latest_release().expect("live fetch succeeded");
        assert!(!rel.tag_name.is_empty());
        assert!(rel.html_url.contains("github.com"));
    }

    #[test]
    fn test_etag_cache_uses_304_and_invalidates_on_repo_change() {
        let dir = std::env::temp_dir().join("ag_update_etag_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cache = dir.join("update_cache.json");

        let body_json = br#"{
            "tag_name": "v2.36.0",
            "html_url": "https://github.com/soroka-ilya/Antigravity/releases/tag/v2.36.0",
            "draft": false,
            "prerelease": false,
            "assets": []
        }"#;
        let mut seen_etag: Option<String> = None;
        let rel = fetch_latest_with_cache("soroka-ilya/Antigravity", Some(&cache), |inm| {
            seen_etag = inm.map(|s| s.to_string());
            Ok(ConditionalFetch::Body {
                bytes: body_json.to_vec(),
                etag: Some("\"etag-1\"".to_string()),
            })
        })
        .unwrap();
        assert!(seen_etag.is_none());
        assert_eq!(rel.tag_name, "v2.36.0");

        let rel_cached = fetch_latest_with_cache("soroka-ilya/Antigravity", Some(&cache), |inm| {
            seen_etag = inm.map(|s| s.to_string());
            Ok(ConditionalFetch::NotModified)
        })
        .unwrap();
        assert_eq!(seen_etag.as_deref(), Some("\"etag-1\""));
        assert_eq!(rel_cached.tag_name, "v2.36.0");

        let _ = fetch_latest_with_cache("other/Antigravity", Some(&cache), |inm| {
            seen_etag = inm.map(|s| s.to_string());
            Ok(ConditionalFetch::Body {
                bytes: body_json.to_vec(),
                etag: Some("\"etag-2\"".to_string()),
            })
        })
        .unwrap();
        assert!(seen_etag.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_elevation_classification_and_arg_filtering() {
        assert_eq!(sanitize_etag(" \"abc\" ").as_deref(), Some("\"abc\""));
        assert!(sanitize_etag("bad\r\nX: 1").is_none());

        let denied = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        assert_eq!(classify_write_error(&denied, true), ReplaceAccess::NeedsElevation);
        assert!(matches!(classify_write_error(&denied, false), ReplaceAccess::Blocked(_)));

        let filtered = filter_relaunch_args(
            [
                std::ffi::OsString::from("--tui"),
                std::ffi::OsString::from("--install-update"),
                std::ffi::OsString::from("--updated-from"),
                std::ffi::OsString::from("2.34.0"),
            ],
            "2.35.0",
        );
        let strs: Vec<String> = filtered.iter().map(|s| s.to_string_lossy().into_owned()).collect();
        assert_eq!(strs, vec!["--tui", "--updated-from", "2.35.0"]);
    }
}
