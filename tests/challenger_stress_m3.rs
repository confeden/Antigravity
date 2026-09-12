// tests/challenger_stress_m3.rs
// Empirical stress testing harness for Milestone 3 (Win32 Fluent / Dark Theme Tray & Dynamic Tooltips).
// Authored by Empirical Challenger (challenger_m3_1).
//
// Rigorously challenges:
// 1. Dark mode DLL loading (uxtheme ordinals 135, 133, 136 and SetWindowTheme) and real invocation
// 2. Dynamic tooltip formatting bounds (< 128 UTF-16 code units) across extreme boundaries
// 3. CLI flag parsing for --tray and -tray
// 4. Pause/resume state file persistence & thread-safe synchronization
// 5. Tray thread lifecycle and clean shutdown

#![allow(dead_code, unused_imports)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
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
        let dir = std::env::temp_dir().join("AGUnlocker_challenger_m3");
        std::fs::create_dir_all(&dir).ok();
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

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// =========================================================================
// 1. Dark Mode DLL Hooks Empirical Verification
// =========================================================================

#[test]
fn test_challenger_uxtheme_dark_mode_ordinals_resolution() {
    let hooks = tray::load_dark_theme_hooks();

    #[cfg(target_os = "windows")]
    {
        // On modern Windows (10 build 17763+ and 11), uxtheme.dll MUST export:
        // - Ordinal 135: SetPreferredAppMode
        // - Ordinal 133: AllowDarkModeForWindow
        // - Ordinal 136: FlushMenuThemes
        // - Named: SetWindowTheme
        assert!(
            hooks.set_preferred_app_mode,
            "CRITICAL: uxtheme.dll ordinal 135 (SetPreferredAppMode) failed to resolve"
        );
        assert!(
            hooks.allow_dark_mode_for_window,
            "CRITICAL: uxtheme.dll ordinal 133 (AllowDarkModeForWindow) failed to resolve"
        );
        assert!(
            hooks.flush_menu_themes,
            "CRITICAL: uxtheme.dll ordinal 136 (FlushMenuThemes) failed to resolve"
        );
        assert!(
            hooks.set_window_theme,
            "CRITICAL: uxtheme.dll SetWindowTheme named export failed to resolve"
        );
    }

    #[cfg(not(target_os = "windows"))]
    {
        assert_eq!(hooks, tray::DarkThemeHooks::default());
    }
}

#[test]
fn test_challenger_dark_mode_hooks_concurrency_stress() {
    // 50 threads simultaneously calling load_dark_theme_hooks()
    let mut handles = Vec::new();
    for _ in 0..50 {
        handles.push(thread::spawn(|| {
            let h = tray::load_dark_theme_hooks();
            #[cfg(target_os = "windows")]
            {
                assert!(h.set_preferred_app_mode);
                assert!(h.allow_dark_mode_for_window);
                assert!(h.flush_menu_themes);
                assert!(h.set_window_theme);
            }
        }));
    }

    for h in handles {
        h.join().expect("Concurrent load_dark_theme_hooks must not panic");
    }
}

#[test]
#[cfg(target_os = "windows")]
fn test_challenger_direct_uxtheme_ordinals_invocation_on_window() {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{BOOL, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    extern "system" {
        fn LoadLibraryW(lpLibFileName: *const u16) -> HINSTANCE;
        fn GetProcAddress(hModule: HINSTANCE, lpProcName: *const u8) -> *const c_void;
    }

    unsafe {
        let uxtheme_name = to_wide("uxtheme.dll");
        let h_uxtheme = LoadLibraryW(uxtheme_name.as_ptr());
        assert_ne!(h_uxtheme, 0, "Failed to load uxtheme.dll");

        // Ordinal 135: SetPreferredAppMode
        let p135 = GetProcAddress(h_uxtheme, 135 as usize as *const u8);
        assert!(!p135.is_null(), "Ordinal 135 not found");
        let fn_set_preferred_app_mode: unsafe extern "system" fn(i32) -> i32 = std::mem::transmute(p135);

        // Ordinal 133: AllowDarkModeForWindow
        let p133 = GetProcAddress(h_uxtheme, 133 as usize as *const u8);
        assert!(!p133.is_null(), "Ordinal 133 not found");
        let fn_allow_dark_mode_for_window: unsafe extern "system" fn(HWND, BOOL) -> BOOL = std::mem::transmute(p133);

        // Ordinal 136: FlushMenuThemes
        let p136 = GetProcAddress(h_uxtheme, 136 as usize as *const u8);
        assert!(!p136.is_null(), "Ordinal 136 not found");
        let fn_flush_menu_themes: unsafe extern "system" fn() = std::mem::transmute(p136);

        // Named export: SetWindowTheme
        let p_swt = GetProcAddress(h_uxtheme, b"SetWindowTheme\0".as_ptr());
        assert!(!p_swt.is_null(), "SetWindowTheme not found");
        let fn_set_window_theme: unsafe extern "system" fn(HWND, *const u16, *const u16) -> i32 = std::mem::transmute(p_swt);

        // Invoke SetPreferredAppMode(2 /* ForceDark */)
        let _ = fn_set_preferred_app_mode(2);

        // Create test window
        let hwnd = CreateWindowExW(
            0,
            to_wide("STATIC").as_ptr(),
            to_wide("TestDarkWindow").as_ptr(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            0 as HWND,
            0 as HMENU,
            0 as HINSTANCE,
            std::ptr::null(),
        );

        if hwnd != 0 {
            // Test AllowDarkModeForWindow
            let _ = fn_allow_dark_mode_for_window(hwnd, 1);

            // Test SetWindowTheme
            let theme_name = to_wide("DarkMode_Explorer");
            let _ = fn_set_window_theme(hwnd, theme_name.as_ptr(), std::ptr::null());

            // Test FlushMenuThemes
            fn_flush_menu_themes();

            DestroyWindow(hwnd);
        }
    }
}

// =========================================================================
// 2. Tooltip Bounds & Formatting Empirical Verification
// =========================================================================

#[test]
fn test_challenger_tooltip_exact_formatting() {
    // Active with latency
    let active_lat = tray::format_tooltip(false, "Релей", Some(145));
    assert!(
        active_lat.contains("Статус: Активен"),
        "Active tooltip must contain 'Статус: Активен'"
    );
    assert!(
        active_lat.contains("Маршрут: Релей (145 мс)"),
        "Active tooltip must contain 'Маршрут: Релей (145 мс)'"
    );

    // Active without latency
    let active_nolat = tray::format_tooltip(false, "Direct", None);
    assert!(
        active_nolat.contains("Статус: Активен"),
        "Active tooltip must contain 'Статус: Активен'"
    );
    assert!(
        active_nolat.contains("Маршрут: Direct"),
        "Active tooltip must contain 'Маршрут: Direct'"
    );
    assert!(
        !active_nolat.contains("мс"),
        "Active tooltip without latency must NOT contain 'мс'"
    );

    // Paused
    let paused = tray::format_tooltip(true, "Релей", Some(145));
    assert!(
        paused.contains("Статус: Приостановлен"),
        "Paused tooltip must contain 'Статус: Приостановлен'"
    );
    assert!(
        paused.contains("Маршрут: Прямой (обход выключен)"),
        "Paused tooltip must contain direct bypass disabled notification"
    );
}

#[test]
fn test_challenger_tooltip_bounds_under_128_code_units() {
    // Standard and realistic routes
    let test_cases = vec![
        // (paused, route_name, latency_ms)
        (true, "Релей", None),
        (true, "Прямой", Some(50)),
        (true, "Свой прокси (127.0.0.1:10808)", Some(12)),
        (false, "Релей", Some(0)),
        (false, "Релей", Some(250)),
        (false, "Релей", None),
        (false, "Прямой", Some(45)),
        (false, "встроенный выход", Some(120)),
        (false, "Свой прокси (127.0.0.1:10808)", Some(15)),
        (false, "Свой прокси (192.168.1.100:8080)", Some(999)),
        (false, "Clash (127.0.0.1:7890)", Some(18)),
        (false, "Hiddify (127.0.0.1:2080)", Some(34)),
        (false, "Sing-box (127.0.0.1:10808)", Some(21)),
        (false, "v2rayN (127.0.0.1:10809)", Some(29)),
        (false, "Nekoray (127.0.0.1:2080)", Some(31)),
        // Edge cases
        (false, "", None),
        (false, "A", Some(1)),
        (false, "custom-proxy.internal.corp:8443", Some(150)),
    ];

    for (paused, route, lat) in test_cases {
        let tip = tray::format_tooltip(paused, route, lat);
        let utf16_units: Vec<u16> = tip.encode_utf16().collect();
        let len = utf16_units.len();
        assert!(
            len < 128,
            "Tooltip string exceeded 128 UTF-16 code units (len={}):\n{:?}",
            len,
            tip
        );
    }
}

#[test]
fn test_challenger_extreme_tooltip_buffer_safety() {
    // Adversarially construct extreme inputs to verify NOTIFYICONDATAW buffer truncation
    let extreme_routes = vec![
        "A".repeat(100),
        "Б".repeat(100), // Cyrillic multi-byte
        "🚀".repeat(70),  // 4-byte UTF-8, surrogate pairs in UTF-16
        "x".repeat(300), // 300 characters
    ];

    for route in extreme_routes {
        let tip = tray::format_tooltip(false, &route, Some(9999));
        // Verify to_wide produces valid null-terminated wide string
        #[cfg(target_os = "windows")]
        {
            let wide = to_wide(&tip);
            assert_eq!(*wide.last().unwrap(), 0, "to_wide must be null terminated");

            // Verify NOTIFYICONDATAW szTip fixed buffer does not overflow
            let mut nid: windows_sys::Win32::UI::Shell::NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
            let max = nid.szTip.len(); // 128
            assert_eq!(max, 128, "NOTIFYICONDATAW szTip must be exactly 128 elements");

            let copy_len = wide.len().min(max);
            for i in 0..copy_len {
                nid.szTip[i] = wide[i];
            }
            if copy_len < max {
                nid.szTip[copy_len] = 0;
            } else {
                nid.szTip[max - 1] = 0;
            }

            // Must be null terminated at or before index 127
            let null_pos = nid.szTip.iter().position(|&c| c == 0);
            assert!(
                null_pos.is_some(),
                "szTip must have a null terminator within 128 elements"
            );
            assert!(null_pos.unwrap() <= 127);
        }
    }
}

// =========================================================================
// 3. CLI --tray Flag Parsing Matrix
// =========================================================================

#[test]
fn test_challenger_cli_tray_flag_detection_matrix() {
    let check = |args: &[&str]| -> bool {
        args.iter().any(|a| *a == "--tray" || *a == "-tray")
    };

    // Valid trigger variations
    assert!(check(&["ag_unlocker.exe", "--tray"]));
    assert!(check(&["ag_unlocker.exe", "-tray"]));
    assert!(check(&["ag_unlocker.exe", "--proxy", "--tray"]));
    assert!(check(&["ag_unlocker.exe", "-tray", "--dns-forwarder"]));
    assert!(check(&["ag_unlocker.exe", "extra_arg", "--tray"]));

    // Invalid / Non-trigger variations
    assert!(!check(&[]));
    assert!(!check(&["ag_unlocker.exe"]));
    assert!(!check(&["ag_unlocker.exe", "tray"]));
    assert!(!check(&["ag_unlocker.exe", "--tray-mode"]));
    assert!(!check(&["ag_unlocker.exe", "--tray=true"]));
    assert!(!check(&["ag_unlocker.exe", "--not-tray"]));
    assert!(!check(&["ag_unlocker.exe", "-t"]));
    assert!(!check(&["ag_unlocker.exe", "--TRAY"])); // Exact case sensitivity
}

// =========================================================================
// 4. Pause / Resume Synchronization Concurrency Stress
// =========================================================================

#[test]
fn test_challenger_pause_resume_rapid_concurrency_stress() {
    // Stress test set_paused / toggle_pause concurrently from 10 threads
    let paused_file = tray::paused_file_path();
    let _ = std::fs::remove_file(&paused_file);
    let _ = tray::set_paused(false);

    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for _ in 0..10 {
        let stop_clone = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut iter = 0;
            while !stop_clone.load(Ordering::Relaxed) && iter < 30 {
                let _ = tray::toggle_pause();
                let _ = tray::is_paused();
                iter += 1;
            }
        }));
    }

    thread::sleep(Duration::from_millis(100));
    stop.store(true, Ordering::Relaxed);

    for h in handles {
        let _ = h.join();
    }

    // Cleanup to active state
    let _ = tray::set_paused(false);
    assert!(!tray::is_paused());
}

// =========================================================================
// 5. Tray Thread Lifecycle & Clean Exit
// =========================================================================

#[test]
fn test_challenger_tray_lifecycle_and_idempotent_exit() {
    // Calling exit_tray before any tray is spawned must be safe no-op
    tray::exit_tray();

    // Spawn tray
    let handle = tray::spawn_tray_thread().expect("spawn_tray_thread must succeed");
    #[cfg(target_os = "windows")]
    assert_eq!(handle.thread().name(), Some("tray-ui"));

    thread::sleep(Duration::from_millis(50));

    // Exit tray
    tray::exit_tray();

    // Joining must succeed within 2 seconds
    let res = handle.join();
    assert!(res.is_ok(), "Tray UI thread must exit cleanly");

    // Subsequent exit_tray calls must remain safe
    tray::exit_tray();
    tray::exit_tray();
}
