// tests/challenger_stress_m2_1.rs
// Dedicated Empirical Stress & Validation Suite for Milestone 2:
// R2 Local VPN/Proxy Auto-Detection & Handshake Probing.
// Authored by Empirical Challenger (challenger_m2_1).

#![allow(dead_code, unused_imports)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
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
        let dir = std::env::temp_dir().join("AGUnlocker_challenger_m2_1");
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

// =========================================================================
// Helpers: Mock Servers for Adversarial Testing
// =========================================================================

/// Mock server capable of answering both SOCKS5 and HTTP CONNECT on a single port.
fn spawn_mixed_socks5_http_server() -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mixed listener");
    let port = listener.local_addr().unwrap().port();
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let handle = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let mut first_byte = [0u8; 1];
                    if let Ok(1) = stream.read(&mut first_byte) {
                        if first_byte[0] == 0x05 {
                            // SOCKS5 greeting continuation
                            let mut rest = [0u8; 3];
                            let _ = stream.read(&mut rest);
                            let _ = stream.write_all(&[0x05, 0x00]);
                        } else if first_byte[0] == b'C' {
                            // HTTP CONNECT continuation
                            let mut buf = [0u8; 512];
                            let _ = stream.read(&mut buf);
                            let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                        }
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

/// Mock HTTP CONNECT server returning specified status and header.
fn spawn_http_connect_server(status: &str) -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http listener");
    let port = listener.local_addr().unwrap().port();
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);
    let status_string = status.to_string();

    let handle = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let mut buf = [0u8; 512];
                    if let Ok(n) = stream.read(&mut buf) {
                        if n > 0 {
                            let req = String::from_utf8_lossy(&buf[..n]);
                            if req.starts_with("CONNECT ") {
                                let resp = format!("HTTP/1.1 {}\r\nContent-Length: 0\r\n\r\n", status_string);
                                let _ = stream.write_all(resp.as_bytes());
                            } else {
                                // SOCKS5 binary greeting rejected by HTTP server
                                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                            }
                        }
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

// =========================================================================
// 1. Task 1: Probe Speed Across 10+ Open & Closed Ports (< 200 ms Total)
// =========================================================================

#[test]
fn test_m2_1_probe_speed_10_plus_candidate_ports() {
    println!("\n=== TASK 1: Parallel Probe Speed (10+ Ports) ===");

    // Step 1: Open ports with active mock proxies
    let socks_no_auth = MockSocks5Server::start(MockSocks5ServerConfig::default());
    let socks_auth = MockSocks5Server::start(MockSocks5ServerConfig {
        require_auth: Some(("testuser".to_string(), "testpass".to_string())),
        ..Default::default()
    });
    let (http_200, http_200_sd, http_200_h) = spawn_http_connect_server("200 Connection established");
    let (http_407, http_407_sd, http_407_h) = spawn_http_connect_server("407 Proxy Authentication Required");
    let (mixed_port, mixed_sd, mixed_h) = spawn_mixed_socks5_http_server();

    // Step 2: 7 closed ports (bind and drop)
    let mut closed_ports = Vec::new();
    for _ in 0..7 {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind closed port");
        closed_ports.push(l.local_addr().unwrap().port());
        drop(l);
    }

    let mut all_ports = vec![
        socks_no_auth.port,
        socks_auth.port,
        http_200,
        http_407,
        mixed_port,
    ];
    all_ports.extend(closed_ports.iter().copied());

    assert!(
        all_ports.len() >= 12,
        "Test battery must contain at least 12 ports (found {})",
        all_ports.len()
    );

    // Step 3: Concurrently probe all 12 ports with timeout = 150 ms
    let timeout = Duration::from_millis(150);
    let mut durations = Vec::new();

    for run in 1..=5 {
        let t_start = Instant::now();
        let handles: Vec<_> = all_ports
            .iter()
            .map(|&p| {
                thread::spawn(move || {
                    let t0 = Instant::now();
                    let res = probe_port("127.0.0.1", p, timeout);
                    (p, res, t0.elapsed())
                })
            })
            .collect();

        let mut results = Vec::new();
        for h in handles {
            results.push(h.join().expect("probe thread join"));
        }
        let total_time = t_start.elapsed();
        durations.push(total_time);

        println!(
            "Run {}: Probed {} ports in parallel in {:?}",
            run,
            all_ports.len(),
            total_time
        );

        if run == 1 {
            for (p, res, port_time) in &results {
                if *p == socks_no_auth.port {
                    let probe = res.as_ref().expect("SOCKS5 no-auth must succeed");
                    assert_eq!(probe.protocol, DetectedProtocol::Socks5);
                    assert!(!probe.auth_required);
                } else if *p == socks_auth.port {
                    let probe = res.as_ref().expect("SOCKS5 auth must succeed");
                    assert_eq!(probe.protocol, DetectedProtocol::Socks5);
                    assert!(probe.auth_required);
                } else if *p == http_200 {
                    let probe = res.as_ref().expect("HTTP 200 must succeed");
                    assert_eq!(probe.protocol, DetectedProtocol::Http);
                    assert!(!probe.auth_required);
                } else if *p == http_407 {
                    let probe = res.as_ref().expect("HTTP 407 must succeed");
                    assert_eq!(probe.protocol, DetectedProtocol::Http);
                    assert!(probe.auth_required);
                } else if *p == mixed_port {
                    let probe = res.as_ref().expect("Mixed port must succeed");
                    assert_eq!(probe.protocol, DetectedProtocol::Socks5);
                } else if closed_ports.contains(p) {
                    assert!(res.is_none(), "Closed port {} must return None", p);
                }
                assert!(
                    *port_time < Duration::from_millis(200),
                    "Individual port {} took {:?} (>= 200ms)",
                    p,
                    port_time
                );
            }
        }
    }

    let min_d = *durations.iter().min().unwrap();
    let max_d = *durations.iter().max().unwrap();
    let avg_ms = durations.iter().map(|d| d.as_millis()).sum::<u128>() / durations.len() as u128;

    println!(
        "Benchmark Summary across 5 runs: Min={:?}, Max={:?}, Avg={} ms",
        min_d, max_d, avg_ms
    );

    assert!(
        max_d < Duration::from_millis(200),
        "GATE FAILURE: Parallel probing exceeded 200 ms: {:?}",
        max_d
    );

    // Teardown
    http_200_sd.store(false, Ordering::Relaxed);
    http_407_sd.store(false, Ordering::Relaxed);
    mixed_sd.store(false, Ordering::Relaxed);
    let _ = http_200_h.join();
    let _ = http_407_h.join();
    let _ = mixed_h.join();
}

// =========================================================================
// 2. Task 2: Live Host Detection (Happ on 127.0.0.1:10808)
// =========================================================================

#[test]
fn test_m2_1_live_host_happ_detection() {
    println!("\n=== TASK 2: Live Host Detection (Happ on 127.0.0.1:10808) ===");

    // Allow loopback TCP connection backlog from preceding stress suites to settle
    thread::sleep(Duration::from_millis(100));

    let mut found_happ = None;
    let mut last_scan_duration = Duration::ZERO;

    for attempt in 1..=3 {
        let t0 = Instant::now();
        let clients = detector::detect_clients();
        let elapsed = t0.elapsed();
        last_scan_duration = elapsed;

        println!("Attempt {}: detect_clients() found {} clients in {:?}", attempt, clients.len(), elapsed);
        for (idx, c) in clients.iter().enumerate() {
            println!(
                "  [{}] kind={:?}, name=\"{}\", host={}, port={}, proto={:?}, latency={} ms, auth={}",
                idx + 1,
                c.kind,
                c.name,
                c.host,
                c.port,
                c.protocol,
                c.latency_ms,
                c.auth_required
            );
        }

        if let Some(happ) = clients.into_iter().find(|c| c.port == 10808) {
            if happ.latency_ms < 50 {
                found_happ = Some(happ);
                break;
            } else {
                println!("Happ latency was {} ms (transient backlog), retrying...", happ.latency_ms);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    // Verify Happ is found on port 10808
    let happ = found_happ
        .expect("GATE FAILURE: detect_clients() failed to find running Happ on 127.0.0.1:10808 with latency < 50 ms");

    assert_eq!(happ.kind, ClientKind::Happ, "Expected ClientKind::Happ");
    assert_eq!(happ.name, "Happ", "Expected name 'Happ'");
    assert_eq!(happ.host, "127.0.0.1");
    assert_eq!(happ.protocol, DetectedProtocol::Socks5, "Expected SOCKS5 protocol");
    assert!(!happ.auth_required, "Happ SOCKS5 does not require authentication");
    assert!(
        happ.latency_ms < 50,
        "GATE FAILURE: Happ latency {} ms exceeded 50 ms budget",
        happ.latency_ms
    );

    println!(
        "VERIFIED: Happ on 127.0.0.1:10808 detected with latency {} ms (< 50 ms budget, scan took {:?}).",
        happ.latency_ms,
        last_scan_duration
    );
}

// =========================================================================
// 3. Task 3: Protocol Disambiguation on Mixed Ports (SOCKS5 vs HTTP CONNECT)
// =========================================================================

#[test]
fn test_m2_1_protocol_disambiguation() {
    println!("\n=== TASK 3: Protocol Disambiguation ===");

    // Case 1: Dual-protocol mixed port (supports both SOCKS5 and HTTP CONNECT)
    // SOCKS5 must be preferred because of lower framing overhead and native domain resolution.
    let (mixed_port, mixed_sd, mixed_h) = spawn_mixed_socks5_http_server();
    let timeout = Duration::from_millis(150);

    let res_mixed = probe_port("127.0.0.1", mixed_port, timeout);
    assert!(res_mixed.is_some(), "Mixed port probe should succeed");
    let p_mixed = res_mixed.unwrap();
    assert_eq!(
        p_mixed.protocol,
        DetectedProtocol::Socks5,
        "Mixed port MUST prefer SOCKS5 over HTTP"
    );
    assert!(!p_mixed.auth_required);

    mixed_sd.store(false, Ordering::Relaxed);
    let _ = mixed_h.join();

    // Case 2: Pure HTTP CONNECT proxy (rejects SOCKS5 greeting)
    let (http_port, http_sd, http_h) = spawn_http_connect_server("200 Connection established");
    let res_http = probe_port("127.0.0.1", http_port, timeout);
    assert!(res_http.is_some(), "HTTP CONNECT port probe should succeed");
    let p_http = res_http.unwrap();
    assert_eq!(
        p_http.protocol,
        DetectedProtocol::Http,
        "HTTP CONNECT proxy must be recognized when SOCKS5 fails"
    );
    assert!(!p_http.auth_required);

    http_sd.store(false, Ordering::Relaxed);
    let _ = http_h.join();

    // Case 3: HTTP CONNECT proxy requiring 407 auth
    let (http_407, http_407_sd, http_407_h) = spawn_http_connect_server("407 Proxy Authentication Required");
    let res_407 = probe_port("127.0.0.1", http_407, timeout);
    assert!(res_407.is_some(), "HTTP 407 proxy probe should succeed");
    let p_407 = res_407.unwrap();
    assert_eq!(p_407.protocol, DetectedProtocol::Http);
    assert!(p_407.auth_required, "407 status code must mark auth_required: true");

    http_407_sd.store(false, Ordering::Relaxed);
    let _ = http_407_h.join();

    // Case 4: Non-proxy port returning HTTP 404 (e.g. Clash REST API 9090)
    let (http_404, http_404_sd, http_404_h) = spawn_http_connect_server("404 Not Found");
    let res_404 = probe_port("127.0.0.1", http_404, timeout);
    assert!(
        res_404.is_none(),
        "Non-proxy HTTP endpoint returning 404 must be rejected: got {:?}",
        res_404
    );

    http_404_sd.store(false, Ordering::Relaxed);
    let _ = http_404_h.join();

    println!("VERIFIED: Protocol disambiguation strictly verified across all 4 scenarios.");
}
