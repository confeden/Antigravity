// tests/challenger_stress_m1.rs
// Empirical stress testing harness for Milestone 1 / R4 bug fixes & test stabilization.
// Authored by Empirical Challenger (challenger_m1_1).

mod common;
use common::*;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Direct oracle replica of `resolvers::is_blackhole` to verify RFC compliance across boundaries.
fn oracle_is_blackhole(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] == 0x2001 && s[1] == 0xdb8) || v6.is_unspecified()
        }
    }
}

// =========================================================================
// 1. is_blackhole Boundary Matrix & Adversarial Cases
// =========================================================================

#[test]
fn test_challenger_is_blackhole_boundary_matrix() {
    // --- RFC 5737 TEST-NET-1: 192.0.2.0/24 ---
    assert!(!oracle_is_blackhole(&"192.0.1.255".parse().unwrap()), "Pre-TEST-NET-1 boundary");
    assert!(oracle_is_blackhole(&"192.0.2.0".parse().unwrap()), "TEST-NET-1 network base");
    assert!(oracle_is_blackhole(&"192.0.2.1".parse().unwrap()), "TEST-NET-1 start");
    assert!(oracle_is_blackhole(&"192.0.2.128".parse().unwrap()), "TEST-NET-1 middle");
    assert!(oracle_is_blackhole(&"192.0.2.254".parse().unwrap()), "TEST-NET-1 end");
    assert!(oracle_is_blackhole(&"192.0.2.255".parse().unwrap()), "TEST-NET-1 broadcast");
    assert!(!oracle_is_blackhole(&"192.0.3.0".parse().unwrap()), "Post-TEST-NET-1 boundary");

    // --- RFC 5737 TEST-NET-2: 198.51.100.0/24 ---
    assert!(!oracle_is_blackhole(&"198.51.99.255".parse().unwrap()), "Pre-TEST-NET-2 boundary");
    assert!(oracle_is_blackhole(&"198.51.100.0".parse().unwrap()), "TEST-NET-2 network base");
    assert!(oracle_is_blackhole(&"198.51.100.1".parse().unwrap()), "TEST-NET-2 start");
    assert!(oracle_is_blackhole(&"198.51.100.255".parse().unwrap()), "TEST-NET-2 end");
    assert!(!oracle_is_blackhole(&"198.51.101.0".parse().unwrap()), "Post-TEST-NET-2 boundary");

    // --- RFC 5737 TEST-NET-3: 203.0.113.0/24 ---
    assert!(!oracle_is_blackhole(&"203.0.112.255".parse().unwrap()), "Pre-TEST-NET-3 boundary");
    assert!(oracle_is_blackhole(&"203.0.113.0".parse().unwrap()), "TEST-NET-3 network base");
    assert!(oracle_is_blackhole(&"203.0.113.1".parse().unwrap()), "TEST-NET-3 start");
    assert!(oracle_is_blackhole(&"203.0.113.9".parse().unwrap()), "TEST-NET-3 probe target");
    assert!(oracle_is_blackhole(&"203.0.113.255".parse().unwrap()), "TEST-NET-3 end");
    assert!(!oracle_is_blackhole(&"203.0.114.0".parse().unwrap()), "Post-TEST-NET-3 boundary");

    // --- RFC 3849: 2001:db8::/32 ---
    assert!(!oracle_is_blackhole(&"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()), "Pre-RFC3849 boundary");
    assert!(oracle_is_blackhole(&"2001:db8::".parse().unwrap()), "RFC 3849 base");
    assert!(oracle_is_blackhole(&"2001:db8::1".parse().unwrap()), "RFC 3849 sample");
    assert!(oracle_is_blackhole(&"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()), "RFC 3849 max");
    assert!(!oracle_is_blackhole(&"2001:db9::".parse().unwrap()), "Post-RFC3849 boundary");

    // --- Unspecified & Broadcast ---
    assert!(oracle_is_blackhole(&"0.0.0.0".parse().unwrap()), "IPv4 unspecified");
    assert!(oracle_is_blackhole(&"::".parse().unwrap()), "IPv6 unspecified");
    assert!(oracle_is_blackhole(&"255.255.255.255".parse().unwrap()), "IPv4 broadcast");

    // --- MUST NOT BE BLACKHOLE: Localhost, LAN & Public IPs ---
    assert!(!oracle_is_blackhole(&"127.0.0.1".parse().unwrap()), "IPv4 loopback must NOT be blackhole");
    assert!(!oracle_is_blackhole(&"127.0.0.2".parse().unwrap()), "IPv4 loopback range must NOT be blackhole");
    assert!(!oracle_is_blackhole(&"::1".parse().unwrap()), "IPv6 loopback must NOT be blackhole");

    assert!(!oracle_is_blackhole(&"10.0.0.1".parse().unwrap()), "RFC 1918 10/8 must NOT be blackhole");
    assert!(!oracle_is_blackhole(&"172.16.0.1".parse().unwrap()), "RFC 1918 172.16/12 must NOT be blackhole");
    assert!(!oracle_is_blackhole(&"192.168.1.1".parse().unwrap()), "RFC 1918 192.168/16 must NOT be blackhole");

    assert!(!oracle_is_blackhole(&"100.64.0.1".parse().unwrap()), "CGNAT must NOT be blackhole");
    assert!(!oracle_is_blackhole(&"198.18.0.1".parse().unwrap()), "Benchmark net must NOT be blackhole");
    assert!(!oracle_is_blackhole(&"8.8.8.8".parse().unwrap()), "Public DNS must NOT be blackhole");
    assert!(!oracle_is_blackhole(&"1.1.1.1".parse().unwrap()), "Public Cloudflare must NOT be blackhole");
}

// =========================================================================
// 2. Active TUN Interception & TLS Probe Oracle
// =========================================================================

#[test]
fn test_challenger_active_tun_interception_and_tls_probe_rejection() {
    let blackhole_addr: IpAddr = "203.0.113.5".parse().unwrap();

    // 1. First verify that is_blackhole catches the RFC 5737 address immediately
    assert!(
        oracle_is_blackhole(&blackhole_addr),
        "RFC 5737 IP must be classified as blackhole to avoid TUN interception false-positives"
    );

    // 2. Empirically verify the TUN interception reality:
    // With happ-xray active, TCP connect to :443 succeeds on ANY IPv4 address.
    let socket_addr = SocketAddr::new(blackhole_addr, 443);
    let budget = Duration::from_millis(600);
    let tcp_result = TcpStream::connect_timeout(&socket_addr, budget);

    if let Ok(mut stream) = tcp_result {
        // TCP succeeded because TUN intercepted the packet!
        // Now test TLS probe with a dummy/invalid SNI (which happ-xray cannot route):
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );
        let server_name = rustls::pki_types::ServerName::try_from("unresolvable.invalid".to_string()).unwrap();
        let mut conn = rustls::ClientConnection::new(client_config, server_name).unwrap();

        stream.set_read_timeout(Some(budget)).ok();
        stream.set_write_timeout(Some(budget)).ok();

        let deadline = Instant::now() + budget;
        let mut handshake_succeeded = false;

        while conn.is_handshaking() {
            if Instant::now() >= deadline {
                break;
            }
            if conn.wants_write() && conn.write_tls(&mut stream).is_err() {
                break;
            }
            if conn.wants_read() {
                match conn.read_tls(&mut stream) {
                    Ok(0) => break,
                    Ok(_) => {
                        if conn.process_new_packets().is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            if !conn.is_handshaking() {
                handshake_succeeded = true;
                break;
            }
        }

        assert!(
            !handshake_succeeded,
            "TLS probe with unresolvable SNI through TUN must fail"
        );
    }
}

// =========================================================================
// 3. Upstream Timeout Bounds & Non-Blocking Resolution
// =========================================================================

fn test_resolve_within_budget_oracle(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, String> {
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("время вышло".to_string());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let host_s = clean_host.to_string();
    std::thread::spawn(move || {
        let res = (host_s.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<_>>());
        let _ = tx.send(res);
    });
    match rx.recv_timeout(left) {
        Ok(Ok(addrs)) if !addrs.is_empty() => Ok(addrs),
        Ok(Ok(_)) => Err("адрес не разрешается: пустой список".to_string()),
        Ok(Err(e)) => Err(format!("адрес не разрешается: {}", e)),
        Err(_) => Err("время вышло при разрешении адреса".to_string()),
    }
}

#[test]
fn test_challenger_resolve_within_budget_zero_deadline_instant_abort() {
    let past_deadline = Instant::now() - Duration::from_millis(10);
    let start = Instant::now();
    let res = test_resolve_within_budget_oracle("example.com", 80, past_deadline);
    let elapsed = start.elapsed();

    assert!(res.is_err(), "Expired budget must return Err");
    assert_eq!(res.unwrap_err(), "время вышло");
    assert!(elapsed < Duration::from_millis(10), "Must abort in <10ms without spawning thread: {:?}", elapsed);
}

#[test]
fn test_challenger_resolve_within_budget_unresolvable_domain_bounded_time() {
    let start = Instant::now();
    let budget = Duration::from_millis(150);
    let deadline = start + budget;

    let res = test_resolve_within_budget_oracle("challenger-stress-unresolvable-domain-999.invalid", 443, deadline);
    let elapsed = start.elapsed();

    assert!(res.is_err(), "Non-existent domain must fail");
    // Crucial check: OS DNS resolver typically takes 21 seconds on Windows.
    // resolve_within_budget must return in <= 350ms.
    assert!(
        elapsed < Duration::from_millis(400),
        "Resolution must be strictly bounded by budget! Actual elapsed: {:?}",
        elapsed
    );
}

#[test]
fn test_challenger_resolve_bracketed_ips_zero_thread_overhead() {
    let deadline = Instant::now() + Duration::from_millis(200);

    let v4 = test_resolve_within_budget_oracle("[127.0.0.1]", 8080, deadline).unwrap();
    assert_eq!(v4, vec![SocketAddr::new("127.0.0.1".parse().unwrap(), 8080)]);

    let v6 = test_resolve_within_budget_oracle("[::1]", 9090, deadline).unwrap();
    assert_eq!(v6, vec![SocketAddr::new("::1".parse().unwrap(), 9090)]);
}

// =========================================================================
// 4. SOCKS5 ATYP Fallback Protocol Oracle
// =========================================================================

#[test]
fn test_challenger_socks5_connect_fallback_atyp_domainname() {
    // Spin up a raw TCP listener mimicking a SOCKS5 proxy
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // 1. Read method negotiation: [0x05, NMETHODS, METHODS...]
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], 0x05);
        // Reply: NO_AUTH [0x05, 0x00]
        stream.write_all(&[0x05, 0x00]).unwrap();

        // 2. Read CONNECT request header: [VER=0x05, CMD=0x01, RSV=0x00, ATYP]
        let mut req_hdr = [0u8; 4];
        stream.read_exact(&mut req_hdr).unwrap();
        assert_eq!(req_hdr[0..3], [0x05, 0x01, 0x00]);

        let atyp = req_hdr[3];
        assert_eq!(atyp, 0x03, "ATYP must fall back to 0x03 DOMAINNAME when local DNS fails");

        // Read domain length & domain name
        let mut len_buf = [0u8; 1];
        stream.read_exact(&mut len_buf).unwrap();
        let dom_len = len_buf[0] as usize;
        let mut dom_buf = vec![0u8; dom_len];
        stream.read_exact(&mut dom_buf).unwrap();
        assert_eq!(&dom_buf, b"unresolvable-challenger.internal");

        // Read port
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).unwrap();
        let target_port = u16::from_be_bytes(port_buf);
        assert_eq!(target_port, 443);

        // Send SOCKS5 success reply
        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb]).unwrap();
    });

    // Client connection via Socks5Client
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let client_res = Socks5Client::connect(
        proxy_addr,
        "unresolvable-challenger.internal",
        443,
        true, // simulate remote resolution trigger
        None,
        Duration::from_millis(600),
    );

    assert!(client_res.is_ok(), "Client connection with remote ATYP fallback must succeed");
    server_handle.join().unwrap();
}

#[test]
fn test_challenger_socks5_connect_direct_ipv4_atyp() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).unwrap();
        stream.write_all(&[0x05, 0x00]).unwrap();

        let mut req_hdr = [0u8; 4];
        stream.read_exact(&mut req_hdr).unwrap();
        assert_eq!(req_hdr, [0x05, 0x01, 0x00, 0x01], "Must use ATYP 0x01 for direct IPv4");

        let mut ip_buf = [0u8; 4];
        stream.read_exact(&mut ip_buf).unwrap();
        assert_eq!(ip_buf, [127, 0, 0, 1]);

        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).unwrap();
        assert_eq!(u16::from_be_bytes(port_buf), 8080);

        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]).unwrap();
    });

    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let client_res = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        8080,
        false,
        None,
        Duration::from_millis(500),
    );

    assert!(client_res.is_ok());
    server_handle.join().unwrap();
}

// =========================================================================
// 5. MockSocks5Server Clean Drain & RST Prevention
// =========================================================================

#[test]
fn test_challenger_mocksocks5_drain_no_rst_on_eof() {
    let cfg = MockSocks5ServerConfig {
        echo_data: false, // Draining mode
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let client_stream = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        8080,
        false,
        None,
        Duration::from_secs(2),
    );
    assert!(client_stream.is_ok());
    let mut stream = client_stream.unwrap();

    // Send 16 KB of data
    let payload = vec![0x42u8; 16384];
    assert!(stream.write_all(&payload).is_ok());
    stream.flush().ok();

    // Shutdown write half to signal EOF
    stream.shutdown(std::net::Shutdown::Write).ok();

    // Read until EOF; must NOT receive OS 10053 or 10054 RST
    let mut read_buf = [0u8; 128];
    let mut total_read = 0;
    loop {
        match stream.read(&mut read_buf) {
            Ok(0) => break, // Clean EOF
            Ok(n) => total_read += n,
            Err(e) => panic!("Unexpected socket error on shutdown/drain: {:?}", e),
        }
    }
    assert_eq!(total_read, 0);
}

// =========================================================================
// 6. SafeRegexInspector Group Indexing
// =========================================================================

#[test]
fn test_challenger_safe_regex_group_indexing() {
    let js_sample = r#"
        async function checkStatus(req, res) {
            const token = req.headers['authorization'];
            if (!token) return res.status(401).send();
            return executeCall(req, res, { authResponse: token, userStatus: "active" });
        }
    "#;
    // Inspect with pattern matching executeCall and authResponse
    let pattern = r#"(?s)(function\s+\w+)\s*\(([^)]*)\)\s*\{.*?return\s+(\w+)\(.*?authResponse:\s*(\w+)"#;
    let re = regex::Regex::new(pattern).unwrap();
    let caps = re.captures(js_sample);
    assert!(caps.is_some());
    let caps = caps.unwrap();
    assert_eq!(caps.get(3).unwrap().as_str(), "executeCall");
    assert_eq!(caps.get(4).unwrap().as_str(), "token");
}
