// tests/tier3_cross_feature.rs
// Tier 3: Cross-Feature Interactions & Combinations (Pairwise Coverage)
// Tests interactions between R1, R2, R3, R4, and R5.

mod common;
use common::*;
use std::fs;
use std::net::SocketAddr;
use std::time::Duration;

// =========================================================================
// 1. R1 + R3: Process Lifecycle + Safe IDE Bundle Patching
// =========================================================================

#[test]
fn test_r1_r3_patch_workflow_with_safe_process_lifecycle() {
    // 1. Prepare sample IDE JavaScript bundle
    let pristine_bundle = r#"
        // Antigravity Electron Bundle
        function authHandler(req, token, client) {
            let uCfg = authMod.getUserSettings({});
            let resp = transport.executeCall(req, token, client);
            return resp;
        }
    "#;

    // 2. Safely extract regex groups (R3)
    let extracted = SafeRegexInspector::safe_extract_captures(pristine_bundle);
    assert!(extracted.is_ok(), "R3: Extraction must succeed");
    let _groups = extracted.unwrap();

    // 3. Construct patch payload
    let patch_marker = "// UNLOCKED\n";
    let patched_bundle = format!("{}{}", patch_marker, pristine_bundle);
    assert!(patched_bundle.starts_with(patch_marker));
    assert!(!SafeRegexInspector::contains_broken_inline_js(&patched_bundle));

    // 4. Simulate process termination before binary/bundle write (R1)
    let running = &[
        "Antigravity IDE.exe",
        "Antigravity.exe",
        "language_server_windows_x64.exe",
        "agy.exe",
    ];
    let to_kill = ProcessTargetInspector::filter_to_kill(running, ProcessTargetInspector::VALID_KILL_TARGETS);

    // 5. Verify IDE shell is NOT killed while language servers ARE killed
    assert!(
        !to_kill.contains(&"Antigravity IDE.exe".to_string()),
        "R1+R3: Antigravity IDE.exe must remain running during IDE patch"
    );
    assert!(
        !to_kill.contains(&"Antigravity.exe".to_string()),
        "R1+R3: Antigravity.exe must remain running during IDE patch"
    );
    assert!(
        to_kill.contains(&"language_server_windows_x64.exe".to_string()),
        "R1+R3: language_server must be terminated to unlock binaries"
    );
    assert!(
        to_kill.contains(&"agy.exe".to_string()),
        "R1+R3: agy must be terminated to unlock binaries"
    );
}

// =========================================================================
// 2. R2 + R5: Windows Registry Proxy Configuration + SOCKS5 Upstream
// =========================================================================

#[test]
fn test_r2_r5_registry_stores_socks5_proxy_and_reads_back() {
    let reg = MockRegistryEnv::new();

    // 1. Parse SOCKS5 upstream spec (R5)
    let upstream_str = "socks5://127.0.0.1:10808";
    let spec = UpstreamSpec::parse(upstream_str).unwrap();
    assert_eq!(spec.kind, ProxyKind::Socks5);

    // 2. Apply proxy into HKCU\Environment (R2)
    reg.set_user_var("HTTPS_PROXY", Some(&spec.as_line())).unwrap();
    reg.set_user_var("ALL_PROXY", Some(&spec.as_line())).unwrap();

    // 3. Verify zero PowerShell calls and broadcast notification triggered
    assert_eq!(reg.powershell_call_count(), 0, "R2: Zero PowerShell");
    assert_eq!(reg.broadcast_count(), 2, "R2: Broadcast sent for both variables");

    // 4. Read back and re-parse into SOCKS5 UpstreamSpec (R5)
    let raw_https = reg.get_user_var("HTTPS_PROXY").unwrap();
    let re_parsed = UpstreamSpec::parse(&raw_https).unwrap();
    assert_eq!(re_parsed.kind, ProxyKind::Socks5);
    assert_eq!(re_parsed.host, "127.0.0.1");
    assert_eq!(re_parsed.port, 10808);

    // 5. Cleanup proxy from registry (R2)
    reg.delete_user_var("HTTPS_PROXY").unwrap();
    reg.delete_user_var("ALL_PROXY").unwrap();
    assert_eq!(reg.get_user_var("HTTPS_PROXY"), None);
    assert_eq!(reg.get_user_var("ALL_PROXY"), None);
}

// =========================================================================
// 3. R4 + R5: Authenticated Session with Cached License + SOCKS5 Tunnel
// =========================================================================

#[test]
fn test_r4_r5_authenticated_session_with_cached_license_and_socks5() {
    let temp_dir = std::env::temp_dir().join(format!("ag_test_r4_r5_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let license_path = temp_dir.join("license.key");

    // 1. Setup valid cached license (R4)
    let version = "2.11.0";
    let valid_key = LicenseOracle::mint_key("R4_R5_NONCE", version);
    fs::write(&license_path, &valid_key).unwrap();

    // 2. Verify auto-login succeeds without prompting
    let login_bypassed = if license_path.exists() {
        let content = fs::read_to_string(&license_path).unwrap();
        let k = LicenseOracle::sanitize_key_input(&content);
        LicenseOracle::verify_key(&k, version)
    } else {
        false
    };
    assert!(login_bypassed, "R4: Startup auto-login must succeed");

    // 3. Spin up Mock SOCKS5 Server with RFC 1929 Auth (R5)
    let server_cfg = MockSocks5ServerConfig {
        require_auth: Some(("ag_user".to_string(), "ag_pass".to_string())),
        ..Default::default()
    };
    let server = MockSocks5Server::start(server_cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    // 4. Connect SOCKS5 tunnel with credentials
    let client_res = Socks5Client::connect(
        proxy_addr,
        "daily-cloudcode-pa.googleapis.com",
        443,
        true, // remote DNS
        Some(("ag_user", "ag_pass")),
        Duration::from_secs(3),
    );
    assert!(client_res.is_ok(), "R5: SOCKS5 tunnel must establish successfully");

    // 5. Verify server recorded expected parameters
    let stats = server.stats.lock().unwrap();
    assert_eq!(stats.received_username, Some("ag_user".to_string()));
    assert_eq!(stats.target_host, Some("daily-cloudcode-pa.googleapis.com".to_string()));

    let _ = fs::remove_dir_all(&temp_dir);
}

// =========================================================================
// 4. R2 + R4: LocalAppData Registry Environment and License Cache Path Coexistence
// =========================================================================

#[test]
fn test_r2_r4_localappdata_registry_and_license_cache_coexistence() {
    let reg = MockRegistryEnv::new();
    let temp_root = std::env::temp_dir().join(format!("ag_test_r2_r4_{}", std::process::id()));
    let appdata_dir = temp_root.join("AppData").join("Local").join("AGUnlocker");
    fs::create_dir_all(&appdata_dir).unwrap();

    let license_path = appdata_dir.join("license.key");
    let version = "2.11.0";
    let key = LicenseOracle::mint_key("COEXIST_NONCE", version);
    fs::write(&license_path, &key).unwrap();

    // Registry manages environment variables while LocalAppData stores key
    reg.set_user_var("NODE_EXTRA_CA_CERTS", Some(appdata_dir.join("ca.crt").to_str().unwrap())).unwrap();
    reg.set_user_var("HTTPS_PROXY", Some("http://127.0.0.1:53129")).unwrap();

    assert!(license_path.exists());
    assert_eq!(LicenseOracle::verify_key(&key, version), true);
    assert!(reg.get_user_var("NODE_EXTRA_CA_CERTS").is_some());
    assert!(reg.get_user_var("HTTPS_PROXY").is_some());

    let _ = fs::remove_dir_all(&temp_root);
}

// =========================================================================
// 5. R1 + R2: Watchdog Proxy Cleanup and Safe Process Lifecycle
// =========================================================================

#[test]
fn test_r1_r2_watchdog_proxy_cleanup_and_safe_process_restart() {
    let reg = MockRegistryEnv::new();

    // 1. Apply proxy initially (R2)
    reg.set_user_var("HTTPS_PROXY", Some("http://127.0.0.1:53129")).unwrap();

    // 2. Watchdog detects dead listener and removes proxy without PowerShell (R2)
    let our_url = "http://127.0.0.1:53129";
    if reg.get_user_var("HTTPS_PROXY").as_deref() == Some(our_url) {
        reg.delete_user_var("HTTPS_PROXY").unwrap();
    }
    assert_eq!(reg.get_user_var("HTTPS_PROXY"), None);
    assert_eq!(reg.powershell_call_count(), 0, "Watchdog must not spawn powershell.exe");

    // 3. Language server restart checks process list without killing IDE (R1)
    let running = &["Antigravity IDE.exe", "language_server.exe"];
    let to_kill = ProcessTargetInspector::filter_to_kill(running, ProcessTargetInspector::VALID_KILL_TARGETS);
    assert_eq!(to_kill, vec!["language_server.exe".to_string()]);
    assert!(!to_kill.contains(&"Antigravity IDE.exe".to_string()));
}

// =========================================================================
// 6. R3 + R5: Clean v2.4+ Desktop Architecture and SOCKS5h Remote Resolution
// =========================================================================

#[test]
fn test_r3_r5_desktop_patch_v24_and_socks5h_remote_resolution() {
    // 1. v2.4+ Electron desktop bundle with Language Server architecture (R3)
    let modern_bundle = r#"
        const isLS = content.includes("language_server");
        const client = new LanguageServer();
    "#;
    assert!(SafeRegexInspector::is_new_desktop_architecture(modern_bundle));
    assert!(!SafeRegexInspector::contains_broken_inline_js(modern_bundle));

    // 2. Remote DNS delegation through SOCKS5h (R5)
    let upstream = UpstreamSpec::parse("socks5h://tunnel-exit.internal:1080").unwrap();
    assert_eq!(upstream.kind, ProxyKind::Socks5h);

    let server = MockSocks5Server::start(MockSocks5ServerConfig::default());
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    // 3. Connect to Google PA endpoint via SOCKS5h
    let client_res = Socks5Client::connect(
        proxy_addr,
        "daily-cloudcode-pa.googleapis.com",
        443,
        true, // remote DNS (ATYP 0x03)
        None,
        Duration::from_secs(3),
    );
    assert!(client_res.is_ok());

    let stats = server.stats.lock().unwrap();
    assert_eq!(stats.target_atyp, Some(Socks5Constants::ATYP_DOMAINNAME));
    assert_eq!(stats.target_host, Some("daily-cloudcode-pa.googleapis.com".to_string()));
}

// =========================================================================
// 7. R2 + R3: Proxy Removal and Clean IDE Patch Revert Status
// =========================================================================

#[test]
fn test_r2_r3_proxy_removal_and_clean_ide_patch_status() {
    let reg = MockRegistryEnv::new();

    // Revert scenario: remove environment proxy and revert JS bundle
    reg.set_user_var("HTTPS_PROXY", Some("http://127.0.0.1:53129")).unwrap();
    reg.delete_user_var("HTTPS_PROXY").unwrap();

    let patched_bundle = "// UNLOCKED\nfunction test() { return 1; }";
    let stripped = patched_bundle.trim_start_matches("// UNLOCKED\n");
    assert!(!stripped.starts_with("// UNLOCKED"));
    assert_eq!(stripped, "function test() { return 1; }");
    assert_eq!(reg.get_user_var("HTTPS_PROXY"), None);
}

// =========================================================================
// 8. R4 + R1: Cached License Startup Leaves IDE Untouched
// =========================================================================

#[test]
fn test_r4_r1_cached_license_startup_leaves_ide_untouched() {
    let temp_dir = std::env::temp_dir().join(format!("ag_test_r4_r1_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let license_path = temp_dir.join("license.key");

    let version = "2.11.0";
    let key = LicenseOracle::mint_key("STARTUP_VER", version);
    fs::write(&license_path, &key).unwrap();

    // Verify key
    assert!(LicenseOracle::verify_key(&key, version));

    // Verify no kill commands issued on IDE
    let running = &["Antigravity IDE.exe", "Antigravity CLI.exe", "Antigravity.exe"];
    let to_kill = ProcessTargetInspector::filter_to_kill(running, ProcessTargetInspector::VALID_KILL_TARGETS);
    assert!(to_kill.is_empty(), "Startup check must never kill IDE shell");

    let _ = fs::remove_dir_all(&temp_dir);
}
