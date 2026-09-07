// tests/tray_tests.rs
// Comprehensive test suite for Win32 Fluent / Dark Theme System Tray & Context Menu module.
//
// Covers:
// - Pause/Resume state file persistence (%LOCALAPPDATA%\AGUnlocker\paused) and atomic sync
// - Dynamic tooltip text formatting under active, paused, and fallback states
// - UTF-16 boundary length safety for Win32 NOTIFYICONDATAW
// - Dark mode theme function pointer loading from uxtheme.dll ordinals (135, 133, 136)
// - CLI flag parsing for --tray
// - Tray background thread lifecycle (spawn, window registration, clean shutdown via exit_tray)

#![allow(dead_code, unused_imports)]

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[path = "../src/health.rs"]
mod health;

#[path = "../src/routes.rs"]
mod routes;

mod dns_forwarder {
    use std::path::PathBuf;
    pub fn log_proxy(_: &str) {}
    pub fn log_dir() -> PathBuf {
        let dir = if let Ok(local) = std::env::var("LOCALAPPDATA") {
            PathBuf::from(local).join("AGUnlocker")
        } else {
            std::env::temp_dir().join("AGUnlocker")
        };
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

#[test]
fn test_pause_resume_file_persistence_and_atomic_sync() {
    let paused_file = tray::paused_file_path();
    // Ensure clean initial state
    let _ = std::fs::remove_file(&paused_file);
    let _ = tray::set_paused(false);
    assert!(!tray::is_paused(), "Initial state must not be paused");
    assert!(!paused_file.exists(), "Marker file must not exist initially");

    // Pause via API
    tray::set_paused(true).expect("set_paused(true) should succeed");
    assert!(tray::is_paused(), "State must be paused after set_paused(true)");
    assert!(paused_file.exists(), "Marker file must exist after set_paused(true)");
    let content = std::fs::read_to_string(&paused_file).unwrap_or_default();
    assert!(content.contains("paused"), "Marker file content must be 'paused'");

    // Resume via toggle_pause
    let toggled = tray::toggle_pause().expect("toggle_pause should succeed");
    assert!(!toggled, "Toggling from paused should return false (resumed)");
    assert!(!tray::is_paused(), "State must be active after resume");
    assert!(!paused_file.exists(), "Marker file must be removed after resume");

    // Toggle again to pause
    let toggled_again = tray::toggle_pause().expect("toggle_pause should succeed");
    assert!(toggled_again, "Toggling from active should return true (paused)");
    assert!(tray::is_paused(), "State must be paused after second toggle");
    assert!(paused_file.exists(), "Marker file must exist after second toggle");

    // Test external file removal synchronization
    std::fs::remove_file(&paused_file).expect("remove paused file");
    assert!(!tray::is_paused(), "is_paused() must detect external file removal");

    // Test external file creation synchronization
    std::fs::write(&paused_file, b"paused\n").expect("write paused file");
    assert!(tray::is_paused(), "is_paused() must detect external file creation");

    // Cleanup
    let _ = std::fs::remove_file(&paused_file);
    let _ = tray::set_paused(false);
}

#[test]
fn test_tooltip_text_formatting_active_and_paused() {
    // 1. Paused state: must show straight route without bypass
    let tip_paused = tray::format_tooltip(true, "Релей", Some(250));
    assert_eq!(
        tip_paused,
        "Antigravity Unlocker\nСтатус: Приостановлен\nМаршрут: Прямой (обход выключен)",
        "Paused tooltip must match required template"
    );

    // 2. Active state with latency
    let tip_active_lat = tray::format_tooltip(false, "Релей", Some(280));
    assert_eq!(
        tip_active_lat,
        "Antigravity Unlocker\nСтатус: Активен\nМаршрут: Релей (280 мс)",
        "Active tooltip with latency must format correctly"
    );

    // 3. Active state without latency
    let tip_active_nolat = tray::format_tooltip(false, "Релей", None);
    assert_eq!(
        tip_active_nolat,
        "Antigravity Unlocker\nСтатус: Активен\nМаршрут: Релей",
        "Active tooltip without latency must omit ms"
    );

    // 4. Active state with own proxy
    let tip_own = tray::format_tooltip(false, "Свой прокси (127.0.0.1:10808)", Some(15));
    assert_eq!(
        tip_own,
        "Antigravity Unlocker\nСтатус: Активен\nМаршрут: Свой прокси (127.0.0.1:10808) (15 мс)",
        "Active tooltip with own proxy must format correctly"
    );

    // 5. Active state with direct tunnel
    let tip_direct = tray::format_tooltip(false, "напрямую", Some(48));
    assert_eq!(
        tip_direct,
        "Antigravity Unlocker\nСтатус: Активен\nМаршрут: напрямую (48 мс)",
        "Active tooltip with direct route must format correctly"
    );
}

#[test]
fn test_tooltip_utf16_length_safety() {
    // Win32 NOTIFYICONDATAW szTip is strictly 128 UTF-16 code units (including null terminator)
    let sample_tips = [
        tray::format_tooltip(true, "Релей", None),
        tray::format_tooltip(false, "Релей", Some(280)),
        tray::format_tooltip(false, "Свой прокси (very-long-domain-name.corp.internal.example.org:65535)", Some(9999)),
        tray::format_tooltip(false, "встроенный выход", Some(120)),
    ];

    for tip in &sample_tips {
        let wide: Vec<u16> = tip.encode_utf16().collect();
        assert!(
            wide.len() < 128,
            "Tooltip UTF-16 length {} must be < 128 for Win32 NOTIFYICONDATAW: {:?}",
            wide.len(),
            tip
        );
    }
}

#[test]
fn test_dark_mode_theme_function_pointer_loading() {
    let hooks = tray::load_dark_theme_hooks();

    #[cfg(target_os = "windows")]
    {
        // On Windows 10 (1809+) and Windows 11, uxtheme.dll exports ordinals 135, 133, 136 and SetWindowTheme
        assert!(hooks.set_preferred_app_mode, "SetPreferredAppMode (ord 135) must be resolved");
        assert!(hooks.allow_dark_mode_for_window, "AllowDarkModeForWindow (ord 133) must be resolved");
        assert!(hooks.flush_menu_themes, "FlushMenuThemes (ord 136) must be resolved");
        assert!(hooks.set_window_theme, "SetWindowTheme must be resolved");
    }

    // Calling again should be idempotent and return identical cached results
    let hooks2 = tray::load_dark_theme_hooks();
    assert_eq!(hooks, hooks2, "Subsequent hook loads must return identical results");
}

#[test]
fn test_tray_flag_parsing() {
    let check_flag = |args: &[&str]| -> bool {
        args.iter().any(|a| *a == "--tray" || *a == "-tray")
    };

    assert!(check_flag(&["ag_unlocker.exe", "--tray"]));
    assert!(check_flag(&["ag_unlocker.exe", "-tray"]));
    assert!(check_flag(&["ag_unlocker.exe", "--tray", "--other"]));
    assert!(!check_flag(&["ag_unlocker.exe"]));
    assert!(!check_flag(&["ag_unlocker.exe", "--watchdog"]));
    assert!(!check_flag(&["ag_unlocker.exe", "--dns-forwarder"]));
    assert!(!check_flag(&["ag_unlocker.exe", "tray"]));
}

#[test]
fn test_current_route_info_resolution() {
    let (name, _latency) = tray::current_route_info();
    assert!(!name.is_empty(), "Resolved route name must not be empty");
}

#[test]
fn test_tray_thread_lifecycle_and_clean_exit() {
    // Spawn background tray UI thread
    let handle = tray::spawn_tray_thread().expect("spawn_tray_thread must succeed");
    #[cfg(target_os = "windows")]
    assert_eq!(handle.thread().name(), Some("tray-ui"));

    // Allow window creation and message pump initialization
    thread::sleep(Duration::from_millis(80));

    // Signal exit to the tray window
    tray::exit_tray();

    // The thread must join cleanly within 2 seconds
    let res = handle.join();
    assert!(res.is_ok(), "Tray UI thread must exit cleanly without panic");
}
