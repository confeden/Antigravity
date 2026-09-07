// tests/tier1_feature_coverage.rs
// Tier 1: Feature Coverage (>=5 test cases per feature for R1, R2, R3, R4, R5)
// Derived strictly from user requirements in ORIGINAL_REQUEST.md and PROJECT.md.

mod common;
use common::*;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

// =========================================================================
// R1: Safe Process Termination (Excluding IDE Shell)
// =========================================================================

#[test]
fn test_r1_kill_list_excludes_antigravity_ide_executable() {
    let kill_list = ProcessTargetInspector::VALID_KILL_TARGETS;
    assert!(
        !kill_list.contains(&"Antigravity IDE.exe"),
        "R1 VIOLATION: 'Antigravity IDE.exe' must never be in kill_platform_processes targets"
    );
    assert!(
        !ProcessTargetInspector::contains_forbidden_ide_shell(kill_list),
        "R1 VIOLATION: Forbidden IDE shell found in kill targets"
    );
}

#[test]
fn test_r1_kill_list_excludes_antigravity_executable() {
    let kill_list = ProcessTargetInspector::VALID_KILL_TARGETS;
    assert!(
        !kill_list.contains(&"Antigravity.exe"),
        "R1 VIOLATION: 'Antigravity.exe' must never be in kill_platform_processes targets"
    );
}

#[test]
fn test_r1_kill_list_excludes_antigravity_cli_executable() {
    let kill_list = ProcessTargetInspector::VALID_KILL_TARGETS;
    assert!(
        !kill_list.contains(&"Antigravity CLI.exe"),
        "R1 VIOLATION: 'Antigravity CLI.exe' must not be in kill targets"
    );
}

#[test]
fn test_r1_kill_list_includes_language_server_targets() {
    let kill_list = ProcessTargetInspector::VALID_KILL_TARGETS;
    let has_ls_pattern = kill_list
        .iter()
        .any(|t| t.starts_with("language_server") && t.ends_with(".exe"));
    assert!(
        has_ls_pattern,
        "R1 REQUIREMENT: Must target language_server*.exe"
    );
}

#[test]
fn test_r1_kill_list_includes_agy_executable() {
    let kill_list = ProcessTargetInspector::VALID_KILL_TARGETS;
    assert!(
        kill_list.contains(&"agy.exe"),
        "R1 REQUIREMENT: Must target agy.exe"
    );
}

#[test]
fn test_r1_filter_preserves_running_ide_processes() {
    let running_processes = &[
        "Antigravity IDE.exe",
        "Antigravity.exe",
        "language_server_windows_x64.exe",
        "agy.exe",
        "Code.exe",
    ];

    let kill_patterns = ProcessTargetInspector::VALID_KILL_TARGETS;
    let to_kill = ProcessTargetInspector::filter_to_kill(running_processes, kill_patterns);

    assert!(
        !to_kill.contains(&"Antigravity IDE.exe".to_string()),
        "R1 VIOLATION: Filter targeted 'Antigravity IDE.exe'"
    );
    assert!(
        !to_kill.contains(&"Antigravity.exe".to_string()),
        "R1 VIOLATION: Filter targeted 'Antigravity.exe'"
    );
    assert!(
        to_kill.contains(&"language_server_windows_x64.exe".to_string()),
        "R1 REQUIREMENT: Filter must target language server"
    );
    assert!(
        to_kill.contains(&"agy.exe".to_string()),
        "R1 REQUIREMENT: Filter must target agy.exe"
    );
}

#[test]
fn test_r1_linux_targets_only_language_server_and_agy() {
    let targets = ProcessTargetInspector::VALID_LINUX_KILL_TARGETS;
    assert_eq!(targets, &["language_server", "/agy"]);
    assert!(!targets.contains(&"Antigravity"));
    assert!(!targets.contains(&"Antigravity IDE"));
}

// =========================================================================
// R2: Windows Registry HKCU\Environment & WinAPI WM_SETTINGCHANGE
// =========================================================================

#[test]
fn test_r2_registry_set_and_get_user_environment_variable() {
    let reg = MockRegistryEnv::new();
    let proxy_url = "http://127.0.0.1:53129";

    let res = reg.set_user_var("HTTPS_PROXY", Some(proxy_url));
    assert!(res.is_ok(), "Setting user environment variable must succeed");

    let read_val = reg.get_user_var("HTTPS_PROXY");
    assert_eq!(
        read_val,
        Some(proxy_url.to_string()),
        "Registry read must match written value"
    );
}

#[test]
fn test_r2_registry_delete_user_environment_variable() {
    let reg = MockRegistryEnv::new();
    reg.set_user_var("HTTPS_PROXY", Some("http://127.0.0.1:53129")).unwrap();
    assert!(reg.get_user_var("HTTPS_PROXY").is_some());

    let del_res = reg.delete_user_var("HTTPS_PROXY");
    assert!(del_res.is_ok(), "Deleting variable must succeed");
    assert_eq!(
        reg.get_user_var("HTTPS_PROXY"),
        None,
        "Variable must be absent after deletion"
    );
}

#[test]
fn test_r2_registry_delete_nonexistent_variable_succeeds() {
    let reg = MockRegistryEnv::new();
    assert_eq!(reg.get_user_var("NON_EXISTENT_VAR"), None);

    let res = reg.delete_user_var("NON_EXISTENT_VAR");
    assert!(
        res.is_ok(),
        "R2 SPEC: Deleting absent variable must return Ok(()) without error"
    );
}

#[test]
fn test_r2_settingchange_broadcast_parameters_contract() {
    let reg = MockRegistryEnv::new();
    reg.set_user_var("HTTPS_PROXY", Some("http://127.0.0.1:53129")).unwrap();

    assert_eq!(
        reg.broadcast_count(),
        1,
        "R2 REQUIREMENT: Must broadcast WM_SETTINGCHANGE after registry write"
    );

    assert_eq!(RegistryConstants::HWND_BROADCAST, 0xFFFF);
    assert_eq!(RegistryConstants::WM_SETTINGCHANGE, 0x001A);
    assert_eq!(RegistryConstants::SMTO_ABORTIFHUNG, 0x0002);
    assert_eq!(RegistryConstants::BROADCAST_TIMEOUT_MS, 5000);
    assert_eq!(RegistryConstants::BROADCAST_LPARAM, "Environment");
}

#[test]
fn test_r2_zero_powershell_spawned_for_registry_operations() {
    let reg = MockRegistryEnv::new();
    reg.set_user_var("HTTPS_PROXY", Some("http://127.0.0.1:53129")).unwrap();
    let _ = reg.get_user_var("HTTPS_PROXY");
    reg.delete_user_var("HTTPS_PROXY").unwrap();

    assert_eq!(
        reg.powershell_call_count(),
        0,
        "R2 CRITICAL: Native registry operations must spawn ZERO powershell.exe processes"
    );
}

#[test]
fn test_r2_registry_foreign_proxy_detects_machine_and_user_scopes() {
    let reg = MockRegistryEnv::new();
    reg.set_machine_var("HTTPS_PROXY", "http://corporate-proxy:8080");

    assert_eq!(
        reg.get_machine_var("HTTPS_PROXY"),
        Some("http://corporate-proxy:8080".to_string())
    );
    assert_eq!(reg.get_user_var("HTTPS_PROXY"), None);

    reg.set_user_var("HTTPS_PROXY", Some("http://127.0.0.1:53129")).unwrap();
    assert_eq!(
        reg.get_user_var("HTTPS_PROXY"),
        Some("http://127.0.0.1:53129".to_string())
    );
}

// =========================================================================
// R3: Safe Regex Capture Handling & Obsolete JS Cleanup in patch_ide.rs
// =========================================================================

#[test]
fn test_r3_safe_regex_capture_extracts_all_valid_groups() {
    let sample_js = r#"
        function sendAuthRequest(req, token, client) {
            let userConfig = authModule.getUserSettings({});
            let authResponse = transport.executeCall(req, token, client);
            return authResponse;
        }
    "#;

    let res = SafeRegexInspector::safe_extract_captures(sample_js);
    assert!(
        res.is_ok(),
        "Valid JS matching regex must return Ok(captures)"
    );

    let groups = res.unwrap();
    assert_eq!(groups.fname, "sendAuthRequest");
    assert_eq!(groups.var_t, "req");
    assert_eq!(groups.var_t_send, "token");
    assert_eq!(groups.var_y, "client");
    assert_eq!(groups.var_func, "executeCall");
}

#[test]
fn test_r3_safe_regex_capture_returns_err_on_missing_group() {
    let corrupted_js = r#"
        function incomplete(a, b) {
            let x = mod.get({});
        }
    "#;

    let res = SafeRegexInspector::safe_extract_captures(corrupted_js);
    assert!(
        res.is_err(),
        "R3 SPEC: Missing regex capture groups must return Err, NEVER panic"
    );
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("Сигнатура не найдена") || err_msg.contains("не найдена"),
        "Error message must be descriptive in Russian: {}",
        err_msg
    );
}

#[test]
fn test_r3_safe_regex_capture_returns_err_on_signature_mismatch() {
    let random_content = "console.log('hello world from unpatched bundle');";
    let res = SafeRegexInspector::safe_extract_captures(random_content);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Сигнатура не найдена"));
}

#[test]
fn test_r3_obsolete_broken_js_getUserStatus_rejected() {
    let broken_inline_js = r#"
        let auth = ...getUserStatus({}))).userStatus;
        return auth;
    "#;

    assert!(
        SafeRegexInspector::contains_broken_inline_js(broken_inline_js),
        "R3 REQUIREMENT: Must detect broken '...getUserStatus' JavaScript"
    );
}

#[test]
fn test_r3_modern_v24_architecture_detection_positive() {
    let modern_bundle = r#"
        const lsPath = path.join(resources, "language_server.exe");
        const client = new LanguageServerClient(lsPath);
        client.start();
    "#;

    assert!(
        SafeRegexInspector::is_new_desktop_architecture(modern_bundle),
        "R3 REQUIREMENT: Must detect v2.4+ modern desktop architecture"
    );
}

#[test]
fn test_r3_modern_v24_architecture_detection_negative() {
    let legacy_bundle = r#"
        const oldDesktop = new LegacyDesktopApp();
        oldDesktop.runInlineAuth();
    "#;

    assert!(
        !SafeRegexInspector::is_new_desktop_architecture(legacy_bundle),
        "Legacy bundle without Language Server auth must not be flagged as v2.4+"
    );
}

// =========================================================================
// R4: License Verification & Cache Persistence
// =========================================================================

#[test]
fn test_r4_verify_key_accepts_valid_key_for_current_version() {
    let version = "2.11.0";
    let valid_key = LicenseOracle::mint_key("A1B2C3D4E5F6", version);
    assert_eq!(valid_key.len(), 24);

    let verified = LicenseOracle::verify_key(&valid_key, version);
    assert!(
        verified,
        "R4 REQUIREMENT: Valid key minted for current version must pass verification"
    );
}

#[test]
fn test_r4_verify_key_rejects_stale_version_key() {
    let current_version = "2.11.0";
    let old_version = "2.10.0";
    let stale_key = LicenseOracle::mint_key("A1B2C3D4E5F6", old_version);

    let verified = LicenseOracle::verify_key(&stale_key, current_version);
    assert!(
        !verified,
        "R4 REQUIREMENT: Key minted for old version 2.10.0 must be rejected under 2.11.0"
    );
}

#[test]
fn test_r4_verify_key_rejects_corrupted_or_garbage_key() {
    let version = "2.11.0";
    assert!(!LicenseOracle::verify_key("INVALID_KEY_LENGTH", version));
    assert!(!LicenseOracle::verify_key("", version));
    assert!(!LicenseOracle::verify_key("123456789012345678901234", version));
    assert!(!LicenseOracle::verify_key("!@#$%^&*()_+{}|:<>?1234", version));
}

#[test]
fn test_r4_cached_license_saved_and_loaded_successfully() {
    let temp_dir = std::env::temp_dir().join(format!("ag_test_r4_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let license_file = temp_dir.join("license.key");

    let version = "2.11.0";
    let key = LicenseOracle::mint_key("CACHE_TEST_01", version);

    fs::write(&license_file, &key).unwrap();
    assert!(license_file.exists());

    let loaded = fs::read_to_string(&license_file).unwrap();
    let clean = LicenseOracle::sanitize_key_input(&loaded);
    assert_eq!(clean, key);
    assert!(LicenseOracle::verify_key(&clean, version));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_r4_cached_license_bypasses_login_screen() {
    let temp_dir = std::env::temp_dir().join(format!("ag_test_r4_bypass_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let license_file = temp_dir.join("license.key");

    let version = "2.11.0";
    let key = LicenseOracle::mint_key("BYPASS_NONCE", version);
    fs::write(&license_file, &key).unwrap();

    // Auto-login check simulation
    let cached_ok = if license_file.exists() {
        let content = fs::read_to_string(&license_file).unwrap_or_default();
        let k = LicenseOracle::sanitize_key_input(&content);
        LicenseOracle::verify_key(&k, version)
    } else {
        false
    };

    assert!(
        cached_ok,
        "R4 REQUIREMENT: Valid cached license must return true to bypass login prompt"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_r4_corrupted_cached_license_fails_gracefully() {
    let temp_dir = std::env::temp_dir().join(format!("ag_test_r4_corrupt_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let license_file = temp_dir.join("license.key");

    fs::write(&license_file, "MALFORMED_GARBAGE_KEY").unwrap();

    let version = "2.11.0";
    let cached_ok = if license_file.exists() {
        let content = fs::read_to_string(&license_file).unwrap_or_default();
        let k = LicenseOracle::sanitize_key_input(&content);
        LicenseOracle::verify_key(&k, version)
    } else {
        false
    };

    assert!(
        !cached_ok,
        "R4 REQUIREMENT: Corrupted cache must return false, requiring user prompt"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_r4_license_key_normalizes_whitespace_and_quotes() {
    let raw_input = "  \"A1B2-C3D4-E5F6-1234-5678-9ABC\" \n";
    let cleaned = LicenseOracle::sanitize_key_input(raw_input);
    assert_eq!(cleaned, "A1B2C3D4E5F6123456789ABC");
}

// =========================================================================
// R5: SOCKS5 & SOCKS5h Protocol Engine & URL Parsing
// =========================================================================

#[test]
fn test_r5_socks5_url_parsing_without_auth() {
    let spec = UpstreamSpec::parse("socks5://127.0.0.1:10808").unwrap();
    assert_eq!(spec.kind, ProxyKind::Socks5);
    assert_eq!(spec.host, "127.0.0.1");
    assert_eq!(spec.port, 10808);
    assert_eq!(spec.auth, None);
}

#[test]
fn test_r5_socks5_url_parsing_with_auth() {
    let spec = UpstreamSpec::parse("socks5://alice:secret123@192.168.1.100:9050").unwrap();
    assert_eq!(spec.kind, ProxyKind::Socks5);
    assert_eq!(spec.host, "192.168.1.100");
    assert_eq!(spec.port, 9050);
    assert_eq!(spec.auth, Some("alice:secret123".to_string()));
}

#[test]
fn test_r5_socks5h_url_parsing_remote_dns() {
    let spec = UpstreamSpec::parse("socks5h://vpn-gateway.internal:1080").unwrap();
    assert_eq!(spec.kind, ProxyKind::Socks5h);
    assert_eq!(spec.host, "vpn-gateway.internal");
    assert_eq!(spec.port, 1080);
    assert_eq!(spec.auth, None);
}

#[test]
fn test_r5_socks5_rfc1928_handshake_no_auth() {
    let server = MockSocks5Server::start(MockSocks5ServerConfig::default());
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let client_res = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        8080,
        false,
        None,
        Duration::from_secs(3),
    );

    assert!(client_res.is_ok(), "No-auth SOCKS5 connection must succeed: {:?}", client_res.err());

    let stats = server.stats.lock().unwrap();
    assert_eq!(stats.negotiated_method, Some(Socks5Constants::METHOD_NO_AUTH));
    assert_eq!(stats.target_atyp, Some(Socks5Constants::ATYP_IPV4));
    assert_eq!(stats.target_port, Some(8080));
}

#[test]
fn test_r5_socks5_rfc1929_handshake_with_user_password() {
    let cfg = MockSocks5ServerConfig {
        require_auth: Some(("testuser".to_string(), "testpass".to_string())),
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let client_res = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        9000,
        false,
        Some(("testuser", "testpass")),
        Duration::from_secs(3),
    );

    assert!(client_res.is_ok(), "Authenticated SOCKS5 connection must succeed: {:?}", client_res.err());

    let stats = server.stats.lock().unwrap();
    assert_eq!(stats.negotiated_method, Some(Socks5Constants::METHOD_USER_PASS));
    assert_eq!(stats.received_username, Some("testuser".to_string()));
    assert_eq!(stats.received_password, Some("testpass".to_string()));
}

#[test]
fn test_r5_socks5_connect_command_ipv4_and_domain() {
    let server = MockSocks5Server::start(MockSocks5ServerConfig::default());
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    // Test Domain (SOCKS5h)
    let domain_res = Socks5Client::connect(
        proxy_addr,
        "daily-cloudcode-pa.googleapis.com",
        443,
        true, // remote DNS
        None,
        Duration::from_secs(3),
    );

    assert!(domain_res.is_ok(), "SOCKS5h domain connect must succeed");

    let stats = server.stats.lock().unwrap();
    assert_eq!(stats.target_atyp, Some(Socks5Constants::ATYP_DOMAINNAME));
    assert_eq!(
        stats.target_host,
        Some("daily-cloudcode-pa.googleapis.com".to_string())
    );
    assert_eq!(stats.target_port, Some(443));
}

#[test]
fn test_r5_socks5_config_roundtrip_persistence() {
    let original = "socks5://operator:vpnpass@10.0.0.1:1080";
    let spec = UpstreamSpec::parse(original).unwrap();
    let serialized = spec.as_line();
    let re_parsed = UpstreamSpec::parse(&serialized).unwrap();

    assert_eq!(spec, re_parsed, "Round-trip parse must yield identical UpstreamSpec");
    assert_eq!(spec.display_masked(), "socks5://operator:***@10.0.0.1:1080");
}
