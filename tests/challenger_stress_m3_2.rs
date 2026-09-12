// tests/challenger_stress_m3_2.rs
// Dedicated Empirical Stress & Validation Suite for Milestone 3:
// R1/R3 System Tray, Dark Theme Context Menu & State Synchronization.
// Authored by Empirical Challenger (challenger_m3_2).

#![allow(dead_code, unused_imports)]

use std::path::PathBuf;
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
        let dir = std::env::temp_dir().join("AGUnlocker_stress_m3_2");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }
}

mod proxy {
    use std::path::PathBuf;
    use std::sync::Arc;
    pub fn probe_config() -> Arc<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Arc::new(config)
    }
    pub fn ca_cert_path() -> PathBuf {
        std::env::temp_dir().join("ca.crt")
    }
    pub fn proxy_url() -> String {
        "http://127.0.0.1:53129".to_string()
    }
}

mod endpoint {
    pub fn remove_proxy_if_ours(_url: &str, _ca: &str) -> Result<bool, String> {
        Ok(true)
    }
    pub fn apply_proxy(_url: &str, _ca: &str) -> Result<bool, String> {
        Ok(true)
    }
}

mod dns {
    pub fn setup_dns_nrpt() {}
    pub fn remove_dns_nrpt() {}
}

pub fn handle_revert_all() {}

#[path = "../src/upstream.rs"]
pub mod upstream;

#[path = "../src/detector.rs"]
pub mod detector;

#[path = "../src/tray.rs"]
pub mod tray;

static PAUSE_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

// =========================================================================
// Dimension 1: Pause/Resume State Synchronization Stress Tests
// =========================================================================

#[test]
fn test_pause_resume_rapid_toggle_storm() {
    let _lock = PAUSE_MUTEX.lock().unwrap();
    let paused_file = tray::paused_file_path();
    let _ = std::fs::remove_file(&paused_file);
    let _ = tray::set_paused(false);

    assert!(!tray::is_paused());
    assert!(!paused_file.exists());

    // 200 rapid toggles
    for i in 0..200 {
        let expected_paused = (i % 2) == 0;
        let next_state = tray::toggle_pause().expect("toggle_pause failed in storm");
        assert_eq!(
            next_state, expected_paused,
            "Toggle {} returned unexpected state {}",
            i, next_state
        );

        // Check synchronization immediately
        let is_p = tray::is_paused();
        assert_eq!(
            is_p, expected_paused,
            "is_paused() mismatch at iteration {}: expected {}, got {}",
            i, expected_paused, is_p
        );

        let file_exists = paused_file.exists();
        assert_eq!(
            file_exists, expected_paused,
            "paused_file exists mismatch at iteration {}: expected {}, got {}",
            i, expected_paused, file_exists
        );

        if expected_paused {
            let content = std::fs::read_to_string(&paused_file).unwrap_or_default();
            assert!(
                content.contains("paused"),
                "Paused file content corrupted at iteration {}",
                i
            );
        }
    }

    // Cleanup
    let _ = tray::set_paused(false);
    assert!(!tray::is_paused());
    assert!(!paused_file.exists());
}

#[test]
fn test_pause_resume_concurrent_readers_and_writers() {
    let _lock = PAUSE_MUTEX.lock().unwrap();
    let paused_file = tray::paused_file_path();
    let _ = std::fs::remove_file(&paused_file);
    let _ = tray::set_paused(false);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    // 8 concurrent reader threads
    for _ in 0..8 {
        let stop = Arc::clone(&stop_flag);
        handles.push(thread::spawn(move || {
            let mut read_count = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let _ = tray::is_paused();
                read_count += 1;
                thread::yield_now();
            }
            read_count
        }));
    }

    // 2 concurrent writer threads toggling states
    for _ in 0..2 {
        let stop = Arc::clone(&stop_flag);
        handles.push(thread::spawn(move || {
            let mut toggle_count = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let _ = tray::toggle_pause();
                toggle_count += 1;
                thread::sleep(Duration::from_micros(200));
            }
            toggle_count
        }));
    }

    // Run concurrency storm for 400ms
    thread::sleep(Duration::from_millis(400));
    stop_flag.store(true, Ordering::SeqCst);

    for h in handles {
        let count = h.join().expect("Thread panicked during concurrency storm");
        assert!(count > 0, "Thread did not perform any operations");
    }

    // Assert final synchronization is strictly coherent
    let is_p = tray::is_paused();
    let file_exists = paused_file.exists();
    assert_eq!(
        is_p, file_exists,
        "Final state desynchronized: is_paused={}, file_exists={}",
        is_p, file_exists
    );

    // Cleanup
    let _ = tray::set_paused(false);
}

#[test]
fn test_pause_resume_tampering_and_edge_cases() {
    let _lock = PAUSE_MUTEX.lock().unwrap();
    let paused_file = tray::paused_file_path();
    let _ = std::fs::remove_file(&paused_file);
    let _ = tray::set_paused(false);

    // Idempotent set_paused(false)
    assert!(tray::set_paused(false).is_ok());
    assert!(!tray::is_paused());
    assert!(!paused_file.exists());

    // Idempotent set_paused(true)
    assert!(tray::set_paused(true).is_ok());
    assert!(tray::set_paused(true).is_ok());
    assert!(tray::is_paused());
    assert!(paused_file.exists());

    // External file emptied (0 bytes) -> is_paused() should still return true because file exists
    std::fs::write(&paused_file, b"").expect("write empty file");
    assert!(
        tray::is_paused(),
        "is_paused() must return true even if paused file is 0 bytes"
    );

    // External file with 64KB garbage -> is_paused() should still return true
    let garbage = vec![0xCC; 65536];
    std::fs::write(&paused_file, &garbage).expect("write garbage file");
    assert!(
        tray::is_paused(),
        "is_paused() must return true with arbitrary file contents"
    );

    // External file deleted -> is_paused() must detect deletion and return false
    std::fs::remove_file(&paused_file).expect("remove file");
    assert!(
        !tray::is_paused(),
        "is_paused() must detect external file deletion"
    );

    // set_paused(true) when parent directory was removed
    let parent = paused_file.parent().unwrap();
    let _ = std::fs::remove_dir_all(parent);
    assert!(!parent.exists());
    assert!(
        tray::set_paused(true).is_ok(),
        "set_paused(true) must recreate missing parent directories"
    );
    assert!(paused_file.exists());
    assert!(tray::is_paused());

    // Cleanup
    let _ = tray::set_paused(false);
}

// =========================================================================
// Dimension 2: Tray Thread Lifecycle & Exit Idempotency
// =========================================================================

#[test]
fn test_tray_thread_repeated_lifecycle() {
    for iter in 0..5 {
        let handle = tray::spawn_tray_thread()
            .unwrap_or_else(|e| panic!("spawn_tray_thread failed at iteration {}: {}", iter, e));

        #[cfg(target_os = "windows")]
        assert_eq!(
            handle.thread().name(),
            Some("tray-ui"),
            "Tray thread name must be 'tray-ui'"
        );

        // Wait for Win32 message pump to initialize
        thread::sleep(Duration::from_millis(60));

        // Signal exit
        tray::exit_tray();

        // Must join cleanly within 2 seconds
        let start = Instant::now();
        let res = handle.join();
        let elapsed = start.elapsed();

        assert!(
            res.is_ok(),
            "Tray thread panicked on iteration {}: {:?}",
            iter,
            res
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "Tray thread took {:?} to exit on iteration {}, exceeding 2s bound",
            elapsed,
            iter
        );
    }
}

#[test]
fn test_exit_tray_idempotency_when_no_tray_running() {
    // Calling exit_tray when no tray is running must be completely safe and not panic
    tray::exit_tray();
    tray::exit_tray();
    tray::exit_tray();
}

// =========================================================================
// Dimension 3: Dynamic Tooltip Formatting & Buffer Safety
// =========================================================================

#[test]
fn test_tooltip_formatting_adversarial_inputs() {
    // 1. Long route name (exceeding typical length)
    let long_name = "A".repeat(300);
    let tip = tray::format_tooltip(false, &long_name, Some(9999));
    assert!(tip.contains("Статус: Активен"));
    assert!(tip.contains(&long_name));
    assert!(tip.contains("9999 мс"));

    // 2. Latency edge cases: None, 0, max u64
    let tip_zero = tray::format_tooltip(false, "Direct", Some(0));
    assert_eq!(
        tip_zero,
        "Antigravity Unlocker\nСтатус: Активен\nМаршрут: Direct (0 мс)"
    );

    let tip_max = tray::format_tooltip(false, "Direct", Some(u64::MAX));
    assert!(tip_max.contains(&format!("({} мс)", u64::MAX)));

    let tip_none = tray::format_tooltip(false, "Direct", None);
    assert_eq!(
        tip_none,
        "Antigravity Unlocker\nСтатус: Активен\nМаршрут: Direct"
    );

    // 3. Paused tooltip always ignores latency and route name
    let tip_paused = tray::format_tooltip(true, "IgnoredRoute", Some(1234));
    assert_eq!(
        tip_paused,
        "Antigravity Unlocker\nСтатус: Приостановлен\nМаршрут: Прямой (обход выключен)"
    );

    // 4. Unicode / Cyrillic / Emoji route name
    let tip_unicode = tray::format_tooltip(false, "🚀 Мой VPN (Швеция #4)", Some(42));
    assert!(tip_unicode.contains("🚀 Мой VPN (Швеция #4) (42 мс)"));
}

// =========================================================================
// Dimension 4: Upstream & Detector Integration (clear_bad_exit & 1-Click Apply)
// =========================================================================

#[test]
fn test_detector_clear_bad_exit_and_1click_apply() {
    // 1. Direct clear_bad_exit verification
    detector::clear_bad_exit();
    assert!(
        detector::is_bad_exit_cleared(),
        "is_bad_exit_cleared() must be true after clear_bad_exit()"
    );

    // 2. Test 1-click apply of SOCKS5 detected client
    let socks5_client = detector::DetectedClient {
        kind: detector::ClientKind::V2RayN,
        name: "v2rayN".to_string(),
        host: "127.0.0.1".to_string(),
        port: 10808,
        protocol: detector::DetectedProtocol::Socks5,
        latency_ms: 12,
        auth_required: false,
    };

    let res = detector::apply_detected_client(&socks5_client);
    assert!(res.is_ok(), "apply_detected_client failed: {:?}", res);

    let configured = upstream::configured().expect("Upstream must be configured after apply");
    assert_eq!(configured.host, "127.0.0.1");
    assert_eq!(configured.port, 10808);
    assert_eq!(configured.kind, upstream::ProxyKind::Socks5);
    assert!(detector::is_bad_exit_cleared());

    // 3. Test 1-click apply of HTTP detected client
    let http_client = detector::DetectedClient {
        kind: detector::ClientKind::Hiddify,
        name: "Hiddify".to_string(),
        host: "127.0.0.1".to_string(),
        port: 2080,
        protocol: detector::DetectedProtocol::Http,
        latency_ms: 8,
        auth_required: false,
    };

    let res_http = detector::apply_detected_client(&http_client);
    assert!(res_http.is_ok(), "apply_detected_client failed: {:?}", res_http);

    let configured_http = upstream::configured().expect("Upstream must be configured after apply");
    assert_eq!(configured_http.host, "127.0.0.1");
    assert_eq!(configured_http.port, 2080);
    assert_eq!(configured_http.kind, upstream::ProxyKind::Http);

    // 4. Reset upstream
    upstream::clear();
    assert!(upstream::configured().is_none());
}

// =========================================================================
// Dimension 5: Dark Theme Hooks Resolution Concurrency
// =========================================================================

#[test]
fn test_uxtheme_hooks_resolution_concurrency() {
    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(thread::spawn(|| {
            let hooks = tray::load_dark_theme_hooks();
            #[cfg(target_os = "windows")]
            {
                assert!(hooks.set_preferred_app_mode);
                assert!(hooks.allow_dark_mode_for_window);
                assert!(hooks.flush_menu_themes);
                assert!(hooks.set_window_theme);
            }
            hooks
        }));
    }

    let first = handles.remove(0).join().expect("thread join failed");
    for h in handles {
        let next = h.join().expect("thread join failed");
        assert_eq!(first, next, "Concurrent hook loads returned inconsistent results");
    }
}
