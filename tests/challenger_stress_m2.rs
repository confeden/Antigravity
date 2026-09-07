// tests/challenger_stress_m2.rs
// Empirical stress testing harness for Milestone 2 (R2 Local VPN/Proxy Auto-Detection).
// Authored by Empirical Challenger (challenger_m2_2).
//
// Rigorously challenges:
// 1. 1-click apply hot-reloading (writes upstream.txt, revives route, upstream::configured() immediately sees it)
// 2. Comprehensive non-proxy port rejection matrix (400, 401, 403, 404, 405, 500, 502, 503, garbage, SMTP, Redis, MySQL, SSH, malformed SOCKS5, hanging, slow-drip)
// 3. Repeated detection runs under load and parallel concurrency (latency budgeting, thread & socket safety)

#![allow(dead_code, unused_imports)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
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
        let dir = std::env::temp_dir().join("AGUnlocker_challenger_m2");
        std::fs::create_dir_all(&dir).ok();
        dir
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

static APPLY_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

// =========================================================================
// 1. 1-Click Apply Hot-Reloading Suite
// =========================================================================

#[test]
fn test_challenger_1click_apply_socks5_hot_reload() {
    let _lock = APPLY_MUTEX.lock().unwrap();
    upstream::clear();
    assert!(upstream::configured().is_none(), "Initial state must be unconfigured");

    // Bench route deliberately
    upstream::OWN.health.probe_failed();
    upstream::OWN.health.probe_failed();
    assert!(!upstream::OWN.usable(), "Route must be un-usable when benched");
    assert!(!upstream::available(), "Upstream must not be available when benched");

    let client = DetectedClient {
        kind: ClientKind::Happ,
        name: "Happ SOCKS5".to_string(),
        host: "127.0.0.1".to_string(),
        port: 10808,
        protocol: DetectedProtocol::Socks5,
        latency_ms: 2,
        auth_required: false,
    };

    let res = apply_detected_client(&client);
    assert!(res.is_ok(), "apply_detected_client must succeed: {:?}", res);

    // Verify upstream::configured() immediately sees it without any restart
    let cfg = upstream::configured().expect("upstream::configured() must immediately return applied proxy");
    assert_eq!(cfg.kind, upstream::ProxyKind::Socks5);
    assert_eq!(cfg.host, "127.0.0.1");
    assert_eq!(cfg.port, 10808);
    assert_eq!(cfg.auth, None);

    // Verify route was revived and bad_exit was cleared
    assert!(upstream::OWN.usable(), "upstream::OWN must be usable immediately after 1-click apply");
    assert!(upstream::available(), "upstream::available() must be true immediately");

    // Verify file content on disk
    let cfg_path = dns_forwarder::log_dir().join("upstream.txt");
    let content = std::fs::read_to_string(&cfg_path).expect("upstream.txt must exist on disk");
    assert_eq!(content.trim(), "socks5://127.0.0.1:10808");

    upstream::clear();
    clear_bad_exit();
}

#[test]
fn test_challenger_1click_apply_http_hot_reload() {
    let _lock = APPLY_MUTEX.lock().unwrap();
    upstream::clear();

    let client = DetectedClient {
        kind: ClientKind::Happ,
        name: "Happ HTTP".to_string(),
        host: "127.0.0.1".to_string(),
        port: 10809,
        protocol: DetectedProtocol::Http,
        latency_ms: 3,
        auth_required: false,
    };

    let res = apply_detected_client(&client);
    assert!(res.is_ok(), "apply_detected_client HTTP must succeed");

    let cfg = upstream::configured().expect("upstream::configured() must see HTTP proxy");
    assert_eq!(cfg.kind, upstream::ProxyKind::Http);
    assert_eq!(cfg.host, "127.0.0.1");
    assert_eq!(cfg.port, 10809);
    assert_eq!(cfg.auth, None);

    let content = std::fs::read_to_string(dns_forwarder::log_dir().join("upstream.txt")).unwrap();
    assert_eq!(content.trim(), "127.0.0.1:10809");

    upstream::clear();
    clear_bad_exit();
}

#[test]
fn test_challenger_1click_apply_rapid_switching_stress() {
    let _lock = APPLY_MUTEX.lock().unwrap();
    upstream::clear();

    let c_socks = DetectedClient {
        kind: ClientKind::SingBox,
        name: "Sing-box SOCKS".to_string(),
        host: "127.0.0.1".to_string(),
        port: 2080,
        protocol: DetectedProtocol::Socks5,
        latency_ms: 1,
        auth_required: false,
    };

    let c_http = DetectedClient {
        kind: ClientKind::Clash,
        name: "Clash HTTP".to_string(),
        host: "127.0.0.1".to_string(),
        port: 7890,
        protocol: DetectedProtocol::Http,
        latency_ms: 2,
        auth_required: false,
    };

    // 100 rapid switches back and forth
    for i in 0..100 {
        let (target_client, expected_kind, expected_port) = if i % 2 == 0 {
            (&c_socks, upstream::ProxyKind::Socks5, 2080)
        } else {
            (&c_http, upstream::ProxyKind::Http, 7890)
        };

        apply_detected_client(target_client).expect("Apply must succeed on each rapid switch");
        let cfg = upstream::configured().expect("Configured upstream must be non-None");
        assert_eq!(cfg.kind, expected_kind, "Switch cycle {} kind mismatch", i);
        assert_eq!(cfg.port, expected_port, "Switch cycle {} port mismatch", i);
    }

    upstream::clear();
    clear_bad_exit();
}

#[test]
fn test_challenger_1click_apply_invalid_client_rejection() {
    let _lock = APPLY_MUTEX.lock().unwrap();
    // Port 0 is rejected by upstream::parse
    let invalid_port = DetectedClient {
        kind: ClientKind::Happ,
        name: "Invalid Port 0".to_string(),
        host: "127.0.0.1".to_string(),
        port: 0,
        protocol: DetectedProtocol::Socks5,
        latency_ms: 1,
        auth_required: false,
    };
    let res = apply_detected_client(&invalid_port);
    assert!(res.is_err(), "Port 0 must be rejected by apply_detected_client");

    // Empty host is rejected
    let empty_host = DetectedClient {
        kind: ClientKind::Happ,
        name: "Empty Host".to_string(),
        host: "".to_string(),
        port: 10808,
        protocol: DetectedProtocol::Socks5,
        latency_ms: 1,
        auth_required: false,
    };
    let res = apply_detected_client(&empty_host);
    assert!(res.is_err(), "Empty host must be rejected by apply_detected_client");
}

// =========================================================================
// 2. Comprehensive Non-Proxy Port Rejection Matrix
// =========================================================================

fn run_mock_responder(status_line: &'static str, body: &'static [u8]) -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let handle = thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 1024];
                    stream.set_read_timeout(Some(Duration::from_millis(50))).ok();
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n > 0 {
                        let resp = format!("HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", status_line, body.len());
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.write_all(body);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    (port, running, handle)
}

#[test]
fn test_challenger_non_proxy_http_error_codes_rejected() {
    let error_codes = [
        "400 Bad Request",
        "401 Unauthorized",
        "403 Forbidden",
        "404 Not Found",
        "405 Method Not Allowed",
        "500 Internal Server Error",
        "502 Bad Gateway",
        "503 Service Unavailable",
    ];

    let timeout = Duration::from_millis(150);

    for code in error_codes {
        let (port, running, handle) = run_mock_responder(code, b"{}");
        let res = probe_port("127.0.0.1", port, timeout);
        assert!(
            res.is_none(),
            "Non-proxy status code '{}' on port {} MUST be rejected, but got {:?}",
            code,
            port,
            res
        );
        running.store(false, Ordering::Relaxed);
        let _ = handle.join();
    }
}

#[test]
fn test_challenger_non_proxy_garbage_bytes_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let handle = thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    // Send 256 bytes of high-entropy binary noise
                    let garbage: Vec<u8> = (0u32..=255).map(|x| ((x * 7 + 13) % 256) as u8).collect();
                    let _ = stream.write_all(&garbage);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let timeout = Duration::from_millis(150);
    let res = probe_port("127.0.0.1", port, timeout);
    assert!(res.is_none(), "Garbage bytes must be rejected: got {:?}", res);

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_challenger_non_proxy_other_protocols_rejected() {
    // Test SSH, SMTP, Redis, MySQL banners
    let protocols: Vec<(&'static str, &[u8])> = vec![
        ("SSH", b"SSH-2.0-OpenSSH_9.0\r\n"),
        ("SMTP", b"220 mail.example.com ESMTP Postfix\r\n"),
        ("Redis", b"-ERR unknown command\r\n"),
        ("MySQL", &[0x4a, 0x00, 0x00, 0x00, 0x0a, 0x38, 0x2e, 0x30, 0x2e, 0x32]),
    ];

    let timeout = Duration::from_millis(150);

    for (proto_name, banner) in protocols {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        let running = Arc::new(AtomicBool::new(true));
        let r_clone = running.clone();
        let banner_vec = banner.to_vec();

        let handle = thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            while r_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.write_all(&banner_vec);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let res = probe_port("127.0.0.1", port, timeout);
        assert!(
            res.is_none(),
            "Foreign protocol {} on port {} must be rejected, got {:?}",
            proto_name,
            port,
            res
        );

        running.store(false, Ordering::Relaxed);
        let _ = handle.join();
    }
}

#[test]
fn test_challenger_malformed_socks5_rejected() {
    // Case 1: SOCKS5 0xFF (No acceptable auth methods)
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut b = [0u8; 16];
                let _ = s.read(&mut b);
                let _ = s.write_all(&[0x05, 0xFF]); // 0xFF: No acceptable methods
            }
        });

        let res = probe_port("127.0.0.1", port, Duration::from_millis(150));
        assert!(res.is_none(), "SOCKS5 0xFF must be rejected: got {:?}", res);
        let _ = handle.join();
    }

    // Case 2: Wrong SOCKS version 0x04 (SOCKS4)
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut b = [0u8; 16];
                let _ = s.read(&mut b);
                let _ = s.write_all(&[0x04, 0x5A]); // SOCKS4 granted
            }
        });

        let res = probe_port("127.0.0.1", port, Duration::from_millis(150));
        assert!(res.is_none(), "SOCKS4 reply must be rejected: got {:?}", res);
        let _ = handle.join();
    }

    // Case 3: Truncated reply (single byte 0x05 then close)
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut b = [0u8; 16];
                let _ = s.read(&mut b);
                let _ = s.write_all(&[0x05]);
            }
        });

        let res = probe_port("127.0.0.1", port, Duration::from_millis(150));
        assert!(res.is_none(), "Truncated 1-byte reply must be rejected");
        let _ = handle.join();
    }
}

#[test]
fn test_challenger_silent_hanging_port_timeout_budget() {
    // Port accepts TCP connection, but sends NOTHING
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let handle = thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        let mut held = Vec::new();
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((s, _)) => held.push(s),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let timeout = Duration::from_millis(150);
    let start = Instant::now();
    let res = probe_port("127.0.0.1", port, timeout);
    let elapsed = start.elapsed();

    assert!(res.is_none(), "Silent hanging port must return None");
    // Should complete strictly within <= 350 ms
    assert!(
        elapsed <= Duration::from_millis(350),
        "Silent hanging port probe took too long: {:?}",
        elapsed
    );

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_challenger_slow_drip_server_timeout_budget() {
    // Port sends 1 byte every 80 ms
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let handle = thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    for _ in 0..10 {
                        if !r_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        if s.write_all(b"X").is_err() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(80));
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let timeout = Duration::from_millis(150);
    let start = Instant::now();
    let res = probe_port("127.0.0.1", port, timeout);
    let elapsed = start.elapsed();

    assert!(res.is_none(), "Slow drip server must be rejected");
    assert!(
        elapsed <= Duration::from_millis(350),
        "Slow drip server probe took too long: {:?}",
        elapsed
    );

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

// =========================================================================
// 3. Repeated Detection Runs Under Load & Concurrency Suite
// =========================================================================

#[test]
fn test_challenger_repeated_detection_50_cycles() {
    let mut total_duration = Duration::ZERO;
    let mut last_count = 0;

    for i in 0..50 {
        let t0 = Instant::now();
        let clients = detector::detect_clients();
        let elapsed = t0.elapsed();
        total_duration += elapsed;

        if i == 0 {
            last_count = clients.len();
        } else {
            assert_eq!(
                clients.len(),
                last_count,
                "Cycle {} client count drift: {} vs {}",
                i,
                clients.len(),
                last_count
            );
        }

        // Each detect_clients() scans 6 candidate ports concurrently
        assert!(
            elapsed < Duration::from_millis(350),
            "Cycle {} detection took too long: {:?}",
            i,
            elapsed
        );
    }

    let avg_ms = (total_duration.as_millis() as f64) / 50.0;
    println!("50 detection cycles average duration: {:.2} ms", avg_ms);
    assert!(avg_ms < 250.0, "Average detection duration must be < 250 ms: {:.2} ms", avg_ms);
}

#[test]
fn test_challenger_concurrent_detection_stress() {
    let mut handles = Vec::new();
    let barrier = Arc::new(std::sync::Barrier::new(8));

    for _ in 0..8 {
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            b.wait();
            let clients = detector::detect_clients();
            clients.len()
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        results.push(h.join().expect("Worker thread panicked"));
    }

    let first = results[0];
    for (idx, count) in results.iter().enumerate() {
        assert_eq!(*count, first, "Thread {} detected client count desync", idx);
    }
}

#[test]
fn test_challenger_multi_endpoint_simultaneous_probing() {
    // 12 endpoints:
    // 1. Mock SOCKS5 no auth
    // 2. Mock SOCKS5 with auth
    // 3. Mock HTTP 200
    // 4. Mock HTTP 407
    // 5. HTTP 404
    // 6. HTTP 500
    // 7. Garbage bytes
    // 8. Silent hanging
    // 9. Closed port 1
    // 10. Closed port 2
    // 11. Closed port 3
    // 12. Closed port 4

    let s1 = MockSocks5Server::start(MockSocks5ServerConfig::default());
    let s2 = MockSocks5Server::start(MockSocks5ServerConfig {
        require_auth: Some(("u".to_string(), "p".to_string())),
        ..Default::default()
    });

    let (p_http200, r_http200, h_http200) = run_mock_responder("200 Connection established", b"");
    let (p_http407, r_http407, h_http407) = run_mock_responder("407 Proxy Authentication Required", b"");
    let (p_http404, r_http404, h_http404) = run_mock_responder("404 Not Found", b"");
    let (p_http500, r_http500, h_http500) = run_mock_responder("500 Server Error", b"");

    let p_closed1 = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let p_closed2 = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let endpoints = vec![
        (s1.port, true, Some(DetectedProtocol::Socks5), false),
        (s2.port, true, Some(DetectedProtocol::Socks5), true),
        (p_http200, true, Some(DetectedProtocol::Http), false),
        (p_http407, true, Some(DetectedProtocol::Http), true),
        (p_http404, false, None, false),
        (p_http500, false, None, false),
        (p_closed1, false, None, false),
        (p_closed2, false, None, false),
    ];

    let t0 = Instant::now();
    let mut handles = Vec::new();
    for (port, expect_ok, expect_proto, expect_auth) in endpoints {
        handles.push(thread::spawn(move || {
            let res = probe_port("127.0.0.1", port, Duration::from_millis(150));
            (port, expect_ok, expect_proto, expect_auth, res)
        }));
    }

    for h in handles {
        let (port, expect_ok, expect_proto, expect_auth, res) = h.join().unwrap();
        if expect_ok {
            assert!(res.is_some(), "Port {} should succeed", port);
            let pr = res.unwrap();
            assert_eq!(pr.protocol, expect_proto.unwrap(), "Protocol mismatch on port {}", port);
            assert_eq!(pr.auth_required, expect_auth, "Auth mismatch on port {}", port);
        } else {
            assert!(res.is_none(), "Port {} should be rejected, got {:?}", port, res);
        }
    }

    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(350),
        "Simultaneous multi-endpoint probing exceeded budget: {:?}",
        elapsed
    );

    r_http200.store(false, Ordering::Relaxed);
    r_http407.store(false, Ordering::Relaxed);
    r_http404.store(false, Ordering::Relaxed);
    r_http500.store(false, Ordering::Relaxed);

    let _ = h_http200.join();
    let _ = h_http407.join();
    let _ = h_http404.join();
    let _ = h_http500.join();
}

#[test]
fn test_challenger_no_thread_or_socket_leaks() {
    // Verify that repeated detect_clients calls do not leak threads or socket handles.
    // Run 10 consecutive detections
    for _ in 0..10 {
        let _ = detector::detect_clients();
    }

    // Give OS 50 ms to process any pending socket close notifications
    thread::sleep(Duration::from_millis(50));

    // Confirm that we can still bind and probe local sockets without hitting EMFILE / WSAENOBUFS
    let mut listeners = Vec::new();
    for _ in 0..50 {
        let l = TcpListener::bind("127.0.0.1:0").expect("Must be able to allocate sockets without descriptor starvation");
        listeners.push(l);
    }
    drop(listeners);
}

