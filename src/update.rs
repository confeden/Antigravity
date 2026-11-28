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
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RELEASES_LATEST_URL: &str = "https://github.com/confeden/Antigravity/releases/latest";
pub const UPDATED_FLAG: &str = "--updated";
#[cfg(any(unix, test))]
pub const HANDOFF_FLAG: &str = "--finish-app-update";
const API_HOST: &str = "api.github.com";
const API_PATH: &str = "/repos/confeden/Antigravity/releases/latest";
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

pub fn started_after_install() -> bool {
    std::env::args_os().any(|arg| arg == UPDATED_FLAG)
}

/// Information about a GitHub release asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub digest: Option<String>,
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

fn version_parts(version: &str) -> Option<[u64; 4]> {
    let clean = version.trim().strip_prefix(['v', 'V']).unwrap_or(version.trim());
    let (base, build) = clean.split_once('_').map_or((clean, None), |(base, build)| (base, Some(build)));
    let mut parts = base.split('.');
    let mut numbers = [0; 4];
    let number = |value: &str| value.bytes().all(|b| b.is_ascii_digit())
        .then(|| value.parse::<u64>().ok()).flatten();
    for field in &mut numbers[..3] {
        *field = number(parts.next()?)?;
    }
    match (parts.next(), build) {
        (Some(_), Some(_)) => return None,
        (Some(build), None) | (None, Some(build)) => numbers[3] = number(build)?,
        (None, None) => {}
    }
    (parts.next().is_none()).then_some(numbers)
}

pub fn is_newer_version(remote: &str, current: &str) -> bool {
    matches!((version_parts(remote), version_parts(current)), (Some(r), Some(c)) if r > c)
}

#[cfg(not(windows))]
pub fn same_version(first: &str, second: &str) -> bool {
    matches!((version_parts(first), version_parts(second)), (Some(a), Some(b)) if a == b)
}

pub fn asset_versions(release: &ReleaseInfo) -> Vec<String> {
    let tag = &release.tag_name;
    let version = release.display_version();
    if !release.is_newer_than_current() || tag.trim() != tag {
        return Vec::new();
    }
    if let Some((base, build)) = version.rsplit_once('_') {
        vec![version.to_owned(), format!("{base}.{build}")]
    } else if version.matches('.').count() == 3 {
        let (base, build) = version.rsplit_once('.').unwrap();
        vec![version.to_owned(), format!("{base}_{build}")]
    } else {
        vec![version.to_owned()]
    }
}

pub fn verified_asset<'a>(release: &'a ReleaseInfo, name: &str) -> Option<(&'a ReleaseAsset, &'a str)> {
    let releases = RELEASES_LATEST_URL.strip_suffix("/latest")?;
    let expected = format!("{releases}/download/{}/{name}", release.tag_name);
    let asset = release.assets.iter().find(|asset| {
        asset.name == name
            && asset.browser_download_url == expected
            && (1..=200 * 1024 * 1024).contains(&asset.size)
    })?;
    let digest = asset.digest.as_deref()?.strip_prefix("sha256:")?;
    (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then_some((asset, digest))
}

pub fn valid_package(path: &Path, size: u64, digest: &str, magic: &[u8; 2]) -> io::Result<bool> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() != size {
        return Ok(false);
    }
    let mut header = [0; 2];
    file.read_exact(&mut header)?;
    if &header != magic {
        return Ok(false);
    }
    let mut sha = Sha256::new();
    sha.update(header);
    io::copy(&mut file, &mut sha)?;
    Ok(hex::encode(sha.finalize()).eq_ignore_ascii_case(digest))
}

pub fn staging_path_in(directory: &Path) -> Result<PathBuf, String> {
    let mut nonce = [0; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut nonce)
        .map_err(|_| "Не удалось создать временный каталог обновления")?;
    Ok(directory.join(format!("ai-unlocker-update-{}", hex::encode(nonce))))
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

/// Check GitHub Releases at startup and every eight hours while the UI is open.
pub fn spawn_watch(tx: std::sync::mpsc::Sender<Option<ReleaseInfo>>, wake: Box<dyn Fn() + Send>) {
    std::thread::Builder::new()
        .name("update-watch".to_string())
        .spawn(move || loop {
            match fetch_latest_release() {
                Ok(release) => {
                    if tx.send(release.is_newer_than_current().then_some(release)).is_err() {
                        return;
                    }
                    wake();
                }
                Err(error) => {
                    #[cfg(debug_assertions)]
                    eprintln!("update check failed: {}", error);
                    #[cfg(not(debug_assertions))]
                    let _ = error;
                }
            }
            std::thread::sleep(CHECK_INTERVAL);
        })
        .ok();
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
        assert!(is_newer_version("v2.36.0.1", "2.36.0"));
        assert!(!is_newer_version("v2.36.0_1", "2.36.0.1"));
        assert!(!is_newer_version("v2.36.1-rc.1", "2.36.0"));
        assert!(!is_newer_version("v2.36.0.1.2", "2.36.0"));
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
    #[ignore = "performs real HTTPS request to api.github.com; requires internet access"]
    fn test_live_fetch_latest_release() {
        let rel = fetch_latest_release().expect("live fetch succeeded");
        assert!(!rel.tag_name.is_empty());
        assert!(rel.html_url.contains("github.com"));
    }
}
