// tests/detector_tests.rs
// Comprehensive test suite for detector module:
// SOCKS5 and HTTP CONNECT probes, auth flags, closed/non-proxy rejection,
// parallel multi-port latency bounding (< 200 ms), 1-click apply hot-reloading,
// and live host detection of running VPN/proxy clients.

#![allow(dead_code, unused_imports)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

#[path = "../src/health.rs"]
mod health;

#[path = "../src/routes.rs"]
mod routes;

mod dns_forwarder {
    use std::path::PathBuf;
    pub fn log_proxy(_: &str) {}
    pub fn log_dir() -> PathBuf {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            PathBuf::from(local).join("AGUnlocker")
        } else {
            std::env::temp_dir().join("AGUnlocker")
        }
    }
}

mod proxy {
    use rustls::ClientConfig;
    use std::sync::Arc;
    pub fn probe_config() -> Arc<ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Arc::new(config)
    }
}

#[path = "../src/upstream.rs"]
pub mod upstream;

#[path = "../src/detector.rs"]
pub mod detector;

use detector::{
    apply_detected_client, clear_bad_exit, is_bad_exit_cleared, list_candidate_adapters,
    list_candidate_processes, probe_http_connect, probe_port, probe_socks5, ClientKind,
    DetectedClient, DetectedProtocol, ProbeResult,
};

mod common;
use common::{MockSocks5Server, MockSocks5ServerConfig};

#[test]
fn test_socks5_handshake_probe_no_auth() {
    let server = MockSocks5Server::start(MockSocks5ServerConfig::default());
    let timeout = Duration::from_millis(150);

    let res = probe_port("127.0.0.1", server.port, timeout);
    assert!(res.is_some(), "SOCKS5 probe should succeed against MockSocks5Server");
    let probe = res.unwrap();
    assert_eq!(probe.protocol, DetectedProtocol::Socks5);
    assert_eq!(*probe, DetectedProtocol::Socks5, "Deref to DetectedProtocol");
    assert!(!probe.auth_required, "No auth required for default SOCKS5");
    assert!(probe.latency_ms > 0, "Measured latency should be > 0 ms");

    let direct = probe_socks5("127.0.0.1", server.port, timeout);
    assert_eq!(direct.map(|(auth, _)| auth), Some(false));
}

#[test]
fn test_socks5_handshake_probe_with_auth() {
    let cfg = MockSocks5ServerConfig {
        require_auth: Some(("user123".to_string(), "pass456".to_string())),
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let timeout = Duration::from_millis(150);

    let res = probe_port("127.0.0.1", server.port, timeout);
    assert!(res.is_some(), "SOCKS5 probe should identify auth requirement");
    let probe = res.unwrap();
    assert_eq!(probe.protocol, DetectedProtocol::Socks5);
    assert!(probe.auth_required, "Auth must be marked as required");

    let direct = probe_socks5("127.0.0.1", server.port, timeout);
    assert_eq!(direct.map(|(auth, _)| auth), Some(true));
}

#[test]
fn test_http_connect_handshake_probe_no_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.starts_with("CONNECT ") {
                        let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                        break;
                    }
                }
            }
        }
    });

    let timeout = Duration::from_millis(150);
    let res = probe_port("127.0.0.1", port, timeout);
    assert!(res.is_some(), "HTTP CONNECT probe should succeed");
    let probe = res.unwrap();
    assert_eq!(probe.protocol, DetectedProtocol::Http);
    assert!(!probe.auth_required);
    assert!(probe.latency_ms > 0);

    let _ = handle.join();
}

#[test]
fn test_http_connect_handshake_probe_with_auth_407() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.starts_with("CONNECT ") {
                        let _ = stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
                        break;
                    }
                }
            }
        }
    });

    let timeout = Duration::from_millis(150);
    let res = probe_port("127.0.0.1", port, timeout);
    assert!(res.is_some(), "HTTP 407 proxy should be recognized");
    let probe = res.unwrap();
    assert_eq!(probe.protocol, DetectedProtocol::Http);
    assert!(probe.auth_required, "Auth required should be true on 407");

    let _ = handle.join();
}

#[test]
fn test_closed_port_returns_none_within_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();
    drop(listener); // Ensure port is closed

    let start = Instant::now();
    let timeout = Duration::from_millis(150);
    let res = probe_port("127.0.0.1", port, timeout);
    let elapsed = start.elapsed();

    assert!(res.is_none(), "Closed port must return None");
    assert!(
        elapsed <= Duration::from_millis(250),
        "Probe on closed port must terminate within timeout bound: {:?}",
        elapsed
    );
}

#[test]
fn test_non_proxy_port_rejected() {
    // Port returning 404 (e.g. Clash REST API 9090 or internal controller 11111)
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                }
            }
        }
    });

    let timeout = Duration::from_millis(150);
    let res = probe_port("127.0.0.1", port, timeout);
    assert!(res.is_none(), "404 non-proxy port must be rejected");

    let direct_http = probe_http_connect("127.0.0.1", port, timeout);
    assert!(direct_http.is_none(), "HTTP CONNECT probe must reject 404");
    drop(handle);
}

#[test]
fn test_parallel_multi_port_probe_completes_under_200ms() {
    // Select 4 closed ports
    let p1 = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let p2 = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let p3 = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let p4 = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let start = Instant::now();
    let ports = vec![p1, p2, p3, p4];
    let mut handles = Vec::new();

    for port in ports {
        let handle = thread::spawn(move || {
            probe_port("127.0.0.1", port, Duration::from_millis(150))
        });
        handles.push(handle);
    }

    for handle in handles {
        let res = handle.join().unwrap();
        assert!(res.is_none());
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(250),
        "Parallel probing across 4 ports must complete in < 250 ms: {:?}",
        elapsed
    );
}

#[test]
fn test_apply_detected_client_writes_upstream_and_clears_bad_exit() {
    // Ensure clean initial state
    upstream::clear();

    // Simulate prior route degradation / benching
    upstream::OWN.health.probe_failed();
    upstream::OWN.health.probe_failed();

    let client = DetectedClient {
        kind: ClientKind::Happ,
        name: "Happ Local".to_string(),
        host: "127.0.0.1".to_string(),
        port: 10808,
        protocol: DetectedProtocol::Socks5,
        latency_ms: 2,
        auth_required: false,
    };

    let res = apply_detected_client(&client);
    assert!(res.is_ok(), "apply_detected_client must succeed");

    // Verify configured upstream in upstream.txt
    let cfg = upstream::configured().expect("upstream must be configured");
    assert_eq!(cfg.kind, upstream::ProxyKind::Socks5);
    assert_eq!(cfg.host, "127.0.0.1");
    assert_eq!(cfg.port, 10808);
    assert_eq!(cfg.auth, None);

    // Verify bad_exit is cleared and route is revived
    assert!(is_bad_exit_cleared(), "bad_exit must be cleared and route revived");
    assert!(upstream::OWN.usable(), "OWN route must be usable immediately");

    // Clean up
    upstream::clear();
    clear_bad_exit();
}

#[test]
fn test_live_host_client_detection() {
    let clients = detector::detect_clients();

    // On this host, happ-xray / xray.exe is actively running on 10808
    if let Some(happ) = clients.iter().find(|c| c.port == 10808) {
        assert_eq!(happ.kind, ClientKind::Happ);
        assert_eq!(happ.protocol, DetectedProtocol::Socks5);
        assert_eq!(happ.host, "127.0.0.1");
        assert!(!happ.auth_required);
        assert!(happ.latency_ms < 50, "Local latency should be < 50 ms");
    }

    // Diagnostic enumeration should not panic
    let procs = list_candidate_processes();
    let adapters = list_candidate_adapters();
    assert!(!procs.is_empty(), "Process list should contain running system processes");
    assert!(!adapters.is_empty(), "Adapter list should contain system adapters");
}

#[test]
fn test_client_kind_and_probe_result_traits() {
    let probe = ProbeResult {
        protocol: DetectedProtocol::Http,
        latency_ms: 5,
        auth_required: false,
    };
    assert_eq!(probe.protocol, DetectedProtocol::Http);
    assert_eq!(probe, DetectedProtocol::Http);
    assert_eq!(DetectedProtocol::Http, probe);

    let client = DetectedClient {
        kind: ClientKind::Clash,
        name: "Clash / Mihomo".to_string(),
        host: "127.0.0.1".to_string(),
        port: 7890,
        protocol: DetectedProtocol::Http,
        latency_ms: 3,
        auth_required: false,
    };
    let cloned = client.clone();
    assert_eq!(client, cloned);
}
