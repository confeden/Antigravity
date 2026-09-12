// tests/challenger_stress_tests.rs
// Empirical stress testing harness for challenger_m1_2
// Stress-testing MockSocks5Server, SafeRegexInspector, and boundary conditions.

mod common;
use common::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// =========================================================================
// 1. MockSocks5Server: Rapid Connect / Disconnect Stress
// =========================================================================

#[test]
fn test_mock_socks5_rapid_connect_disconnect_without_data() {
    let server = MockSocks5Server::start(MockSocks5ServerConfig::default());
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    // 50 connections that connect and immediately drop without sending anything
    for _ in 0..50 {
        let sock = TcpStream::connect(proxy_addr);
        assert!(sock.is_ok(), "Rapid raw connection must succeed");
        drop(sock);
    }

    // 50 connections that send partial greeting and drop immediately
    for _ in 0..50 {
        if let Ok(mut sock) = TcpStream::connect(proxy_addr) {
            let _ = sock.write_all(&[0x05]); // Incomplete header
            drop(sock);
        }
    }

    // 50 connections that send full greeting, read method, then drop before CONNECT
    for _ in 0..50 {
        if let Ok(mut sock) = TcpStream::connect(proxy_addr) {
            let _ = sock.write_all(&[0x05, 0x01, 0x00]);
            let mut reply = [0u8; 2];
            let _ = sock.read_exact(&mut reply);
            drop(sock);
        }
    }

    // Verify the server is still healthy and accepts a full standard connection
    let client_res = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        8080,
        false,
        None,
        Duration::from_secs(3),
    );
    assert!(client_res.is_ok(), "Server must remain fully operational after 150 rapid drops");
}

#[test]
fn test_mock_socks5_rapid_concurrent_connect_disconnect() {
    let server = MockSocks5Server::start(MockSocks5ServerConfig::default());
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let mut handles = Vec::new();
    for _ in 0..20 {
        let addr = proxy_addr;
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                if let Ok(mut sock) = TcpStream::connect(addr) {
                    let _ = sock.write_all(&[0x05, 0x01, 0x00]);
                    let mut reply = [0u8; 2];
                    let _ = sock.read_exact(&mut reply);
                    drop(sock);
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let client_res = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        8080,
        false,
        None,
        Duration::from_secs(3),
    );
    assert!(client_res.is_ok(), "Server must handle concurrent rapid connects");
}

// =========================================================================
// 2. MockSocks5Server: echo_data: false Connection Drain & No 10053/10054 Errors
// =========================================================================

#[test]
fn test_mock_socks5_drain_mode_no_windows_rst_errors() {
    let cfg = MockSocks5ServerConfig {
        echo_data: false, // Drain mode: server reads until EOF, does not echo
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let payload_size = 64 * 1024; // 64 KB
    let payload = vec![0xABu8; payload_size];

    let mut sock = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        8080,
        false,
        None,
        Duration::from_secs(3),
    )
    .expect("SOCKS5 connect must succeed");

    // Write all data in 4KB chunks
    for chunk in payload.chunks(4096) {
        sock.write_all(chunk).expect("Write must not produce 10053/10054");
    }

    // Half-close: shutdown WRITE to send FIN to server
    sock.shutdown(Shutdown::Write)
        .expect("Shutdown write must succeed");

    // In drain mode, reading from server should return Ok(0) (EOF) once server finishes draining
    let mut read_buf = [0u8; 128];
    let mut total_read = 0;
    loop {
        match sock.read(&mut read_buf) {
            Ok(0) => break, // Clean EOF
            Ok(n) => total_read += n,
            Err(e) => {
                panic!(
                    "Unexpected socket error during drain read (check for 10053/10054): raw_os_error={:?}, kind={:?}, msg={}",
                    e.raw_os_error(),
                    e.kind(),
                    e
                );
            }
        }
    }

    assert_eq!(total_read, 0, "Drain mode should not echo any bytes");

    // Allow server thread a moment to finish stats update
    thread::sleep(Duration::from_millis(100));
    let stats = server.stats.lock().unwrap();
    assert_eq!(
        stats.bytes_tunneled, payload_size,
        "Server drain loop must drain exactly all 64KB sent by client"
    );
}

#[test]
fn test_mock_socks5_drain_mode_zero_payload_immediate_eof() {
    let cfg = MockSocks5ServerConfig {
        echo_data: false,
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let mut sock = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        8080,
        false,
        None,
        Duration::from_secs(3),
    )
    .expect("SOCKS5 connect");

    // Immediately shutdown write (0 payload bytes)
    sock.shutdown(Shutdown::Write).expect("shutdown write");

    let mut buf = [0u8; 16];
    let n = sock.read(&mut buf).expect("read should see clean EOF");
    assert_eq!(n, 0, "Immediate EOF expected");
}

#[test]
fn test_mock_socks5_client_abrupt_disconnect_handled_cleanly() {
    let cfg = MockSocks5ServerConfig {
        echo_data: true,
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    // Connect, send handshake, send small data, then immediately drop socket without shutdown
    for _ in 0..20 {
        if let Ok(mut sock) = Socks5Client::connect(
            proxy_addr,
            "127.0.0.1",
            8080,
            false,
            None,
            Duration::from_secs(2),
        ) {
            let _ = sock.write_all(b"abrupt disconnect test data");
            // Abrupt drop
            drop(sock);
        }
    }

    // Server must still accept new connections cleanly
    let verify = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        8080,
        false,
        None,
        Duration::from_secs(3),
    );
    assert!(verify.is_ok(), "Server must remain functional after abrupt drops");
}

// =========================================================================
// 3. MockSocks5Server: Large Payload Echo & SHA-256 Integrity
// =========================================================================

#[test]
fn test_mock_socks5_large_payload_transfer_integrity() {
    let cfg = MockSocks5ServerConfig {
        echo_data: true,
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let mut sock = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        9090,
        false,
        None,
        Duration::from_secs(5),
    )
    .expect("SOCKS5 connect");

    // 1 MB payload of pseudo-random bytes
    let total_bytes = 1024 * 1024;
    let mut test_data = Vec::with_capacity(total_bytes);
    let mut hasher = Sha256::new();
    for i in 0..total_bytes {
        let b = ((i * 37 + 13) % 256) as u8;
        test_data.push(b);
        hasher.update([b]);
    }
    let expected_hash = hasher.finalize();

    // Spawn reader thread to receive echoed stream
    let mut read_sock = sock.try_clone().expect("try_clone socket");
    let reader_handle = thread::spawn(move || {
        let mut received = Vec::with_capacity(total_bytes);
        let mut buf = [0u8; 8192];
        while received.len() < total_bytes {
            let n = read_sock.read(&mut buf).expect("read echoed data");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        received
    });

    // Write in 16 KB chunks
    for chunk in test_data.chunks(16384) {
        sock.write_all(chunk).expect("write data chunk");
    }

    let received = reader_handle.join().expect("reader thread join");
    assert_eq!(received.len(), total_bytes, "Must receive full 1 MB back");

    let mut recv_hasher = Sha256::new();
    recv_hasher.update(&received);
    let received_hash = recv_hasher.finalize();

    assert_eq!(
        received_hash, expected_hash,
        "Echoed payload SHA-256 must match exactly"
    );
}

// =========================================================================
// 4. MockSocks5Server: Concurrency & Lock Contention on Stats
// =========================================================================

#[test]
fn test_mock_socks5_echo_loop_high_concurrency() {
    let cfg = MockSocks5ServerConfig {
        echo_data: true,
        ..Default::default()
    };
    let server = Arc::new(MockSocks5Server::start(cfg));
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let num_threads = 10;
    let msgs_per_thread = 20;
    let msg_size = 512;

    let mut handles = Vec::new();
    let error_count = Arc::new(AtomicUsize::new(0));

    for thread_id in 0..num_threads {
        let addr = proxy_addr;
        let errs = Arc::clone(&error_count);
        handles.push(thread::spawn(move || {
            let mut client = match Socks5Client::connect(
                addr,
                "127.0.0.1",
                8000 + thread_id as u16,
                false,
                None,
                Duration::from_secs(5),
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Thread {} connect error: {}", thread_id, e);
                    errs.fetch_add(1, Ordering::SeqCst);
                    return;
                }
            };

            let send_buf = vec![(thread_id as u8).wrapping_add(1); msg_size];
            let mut recv_buf = vec![0u8; msg_size];

            for _ in 0..msgs_per_thread {
                if let Err(e) = client.write_all(&send_buf) {
                    eprintln!("Thread {} write error: {}", thread_id, e);
                    errs.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                if let Err(e) = client.read_exact(&mut recv_buf) {
                    eprintln!("Thread {} read error: {}", thread_id, e);
                    errs.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                if recv_buf != send_buf {
                    eprintln!("Thread {} data mismatch", thread_id);
                    errs.fetch_add(1, Ordering::SeqCst);
                    return;
                }
            }
        }));
    }

    // In parallel, stress-test stats lock contention to ensure no deadlocks occur
    let server_clone = Arc::clone(&server);
    let stop_poller = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_poller);
    let poller_handle = thread::spawn(move || {
        let mut locks_acquired = 0;
        while !stop_clone.load(Ordering::Relaxed) {
            if let Ok(_guard) = server_clone.stats.try_lock() {
                locks_acquired += 1;
            }
            thread::sleep(Duration::from_micros(200));
        }
        locks_acquired
    });

    for h in handles {
        h.join().unwrap();
    }
    stop_poller.store(true, Ordering::Relaxed);
    let poller_locks = poller_handle.join().unwrap();

    assert_eq!(
        error_count.load(Ordering::SeqCst),
        0,
        "Zero errors across concurrent SOCKS5 clients"
    );
    assert!(poller_locks > 0, "Poller must acquire lock at least once");
}

// =========================================================================
// 5. SafeRegexInspector: Permutations of JS Code Snippets & Minified Code
// =========================================================================

#[test]
fn test_safe_regex_minified_single_line_js() {
    let minified = "function $a(_b,$c,$d){let _e=_f.$g({});let _h=_i.$j(_b,$c,$d);return _h;}";
    let res = SafeRegexInspector::safe_extract_captures(minified);
    assert!(res.is_ok(), "Minified single line JS must parse cleanly: {:?}", res.err());

    let groups = res.unwrap();
    assert_eq!(groups.fname, "$a");
    assert_eq!(groups.var_t, "_b");
    assert_eq!(groups.var_t_send, "$c");
    assert_eq!(groups.var_y, "$d");
    assert_eq!(groups.var_i, "_h");
    assert_eq!(groups.var_func, "$j");
    assert_eq!(groups.var_f, "_b");
    assert_eq!(groups.var_h, "$c");
}

#[test]
fn test_safe_regex_variable_name_shapes_and_dollar_signs() {
    let js_with_dollars = r#"
        function _0x1a2b($arg1, _arg_2, $ARG_3) {
            let $cfg = $module._getSettings({});
            let $callResult = $transport._invokeRemote($arg1, _arg_2, $ARG_3);
            return $callResult;
        }
    "#;

    let res = SafeRegexInspector::safe_extract_captures(js_with_dollars);
    assert!(res.is_ok(), "Variables with $, _, and hex digits must be supported: {:?}", res.err());

    let groups = res.unwrap();
    assert_eq!(groups.fname, "_0x1a2b");
    assert_eq!(groups.var_t, "$arg1");
    assert_eq!(groups.var_t_send, "_arg_2");
    assert_eq!(groups.var_y, "$ARG_3");
    assert_eq!(groups.var_i, "$callResult");
    assert_eq!(groups.var_func, "_invokeRemote");
    assert_eq!(groups.var_f, "$arg1");
    assert_eq!(groups.var_h, "_arg_2");
}

#[test]
fn test_safe_regex_whitespace_and_newline_permutations() {
    let whitespace_variations = [
        // Tab-separated
        "function\tfoo\t(\ta\t,\tb\t,\tc\t)\t{\tlet\td\t=\te.f({});\tlet\tg\t=\th.i(a,b,c);\t}",
        // Multi-newline spaced
        "function   \n\r  foo  \n ( \n a , \n b , \n c ) \n { \n let d = e.f({ \n }); \n let g = h.i(a, b, c); \n }",
        // Dense spacing
        "function foo(a,b,c){let d=e.f({});let g=h.i(a,b,c);}",
    ];

    for (idx, js) in whitespace_variations.iter().enumerate() {
        let res = SafeRegexInspector::safe_extract_captures(js);
        assert!(
            res.is_ok(),
            "Whitespace permutation {} must succeed: {:?}",
            idx,
            res.err()
        );
        let g = res.unwrap();
        assert_eq!(g.fname, "foo");
        assert_eq!(g.var_t, "a");
        assert_eq!(g.var_t_send, "b");
        assert_eq!(g.var_y, "c");
        assert_eq!(g.var_i, "g");
        assert_eq!(g.var_func, "i");
        assert_eq!(g.var_f, "a");
        assert_eq!(g.var_h, "b");
    }
}

#[test]
fn test_safe_regex_rejection_of_invalid_shapes() {
    let invalid_cases = [
        // Only 2 arguments to outer function
        ("function fn(a, b) { let x = m.f({}); let y = t.c(a, b, c); }", "insufficient outer args"),
        // Only 2 arguments to inner call
        ("function fn(a, b, c) { let x = m.f({}); let y = t.c(a, b); }", "insufficient inner args"),
        // 4 arguments to inner call
        ("function fn(a, b, c) { let x = m.f({}); let y = t.c(a, b, c, d); }", "too many inner args"),
        // Missing let keyword
        ("function fn(a, b, c) { var x = m.f({}); const y = t.c(a, b, c); }", "var/const instead of let"),
        // Missing method dot
        ("function fn(a, b, c) { let x = f({}); let y = c(a, b, c); }", "bare function call instead of method"),
    ];

    for (js, desc) in invalid_cases {
        let res = SafeRegexInspector::safe_extract_captures(js);
        assert!(
            res.is_err(),
            "Case '{}' should be rejected with Err, but returned Ok: {:?}",
            desc,
            res
        );
    }
}

#[test]
fn test_safe_regex_redos_resistance() {
    // Generate pathological input with many opening braces and spaces
    let evil_input = format!(
        "function test(a,b,c){{ let x = obj.call({}let y = obj.call(a,b,c);",
        " { ".repeat(200)
    );

    let start = Instant::now();
    let res = SafeRegexInspector::safe_extract_captures(&evil_input);
    let elapsed = start.elapsed();

    assert!(res.is_err(), "Pathological input must return Err");
    assert!(
        elapsed < Duration::from_millis(500),
        "Regex evaluation must terminate quickly (<500ms), took {:?}",
        elapsed
    );
}

// =========================================================================
// 6. Upstream Bracketed IP and Deadline Enforcements
// =========================================================================

#[test]
fn test_upstream_spec_bracketed_ipv6_and_ipv4() {
    // IPv6 standard bracketed
    let s1 = UpstreamSpec::parse("socks5://[::1]:1080").unwrap();
    assert_eq!(s1.host, "::1");
    assert_eq!(s1.port, 1080);
    assert_eq!(s1.as_line(), "socks5://[::1]:1080");

    // IPv4 bracketed (unusual but supported)
    let s2 = UpstreamSpec::parse("socks5://[127.0.0.1]:9050").unwrap();
    assert_eq!(s2.host, "127.0.0.1");
    assert_eq!(s2.port, 9050);
}

#[test]
fn test_upstream_spec_bracketed_ipv6_with_credentials() {
    let s = UpstreamSpec::parse("socks5h://admin:pass@[2001:db8::1]:1080").unwrap();
    assert_eq!(s.host, "2001:db8::1");
    assert_eq!(s.port, 1080);
    assert_eq!(s.auth, Some("admin:pass".to_string()));
    assert_eq!(s.as_line(), "socks5h://admin:pass@[2001:db8::1]:1080");
}
