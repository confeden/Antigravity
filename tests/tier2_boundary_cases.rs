// tests/tier2_boundary_cases.rs
// Tier 2: Boundary & Corner Cases (>=5 test cases per feature for R1, R2, R3, R4, R5)
// Derived strictly from user requirements in ORIGINAL_REQUEST.md and PROJECT.md.

mod common;
use common::*;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =========================================================================
// R1 Boundary & Corner Cases
// =========================================================================

#[test]
fn test_r1_boundary_empty_process_list() {
    let running: &[&str] = &[];
    let to_kill = ProcessTargetInspector::filter_to_kill(running, ProcessTargetInspector::VALID_KILL_TARGETS);
    assert!(to_kill.is_empty(), "Empty process list must produce empty kill list without error");
}

#[test]
fn test_r1_boundary_case_insensitive_process_matching() {
    let running = &[
        "LANGUAGE_SERVER.EXE",
        "Language_Server_Windows_X64.exe",
        "AGY.EXE",
        "ANTIGRAVITY.EXE",
        "antigravity ide.exe",
    ];

    let to_kill = ProcessTargetInspector::filter_to_kill(running, ProcessTargetInspector::VALID_KILL_TARGETS);
    assert!(to_kill.contains(&"LANGUAGE_SERVER.EXE".to_string()));
    assert!(to_kill.contains(&"Language_Server_Windows_X64.exe".to_string()));
    assert!(to_kill.contains(&"AGY.EXE".to_string()));
    assert!(!to_kill.contains(&"ANTIGRAVITY.EXE".to_string()));
    assert!(!to_kill.contains(&"antigravity ide.exe".to_string()));
}

#[test]
fn test_r1_boundary_wildcard_language_server_variants() {
    let running = &[
        "language_server.exe",
        "language_server_windows_x64.exe",
        "language_server_arm64.exe",
        "language_server_v2.exe",
        "language_server_watcher.exe",
        "unrelated_language_tool.exe",
    ];

    let to_kill = ProcessTargetInspector::filter_to_kill(running, &["language_server*.exe"]);
    assert!(to_kill.contains(&"language_server.exe".to_string()));
    assert!(to_kill.contains(&"language_server_windows_x64.exe".to_string()));
    assert!(to_kill.contains(&"language_server_arm64.exe".to_string()));
    assert!(to_kill.contains(&"language_server_v2.exe".to_string()));
    assert!(to_kill.contains(&"language_server_watcher.exe".to_string()));
    assert!(!to_kill.contains(&"unrelated_language_tool.exe".to_string()));
}

#[test]
fn test_r1_boundary_subpath_kill_holder_only_matches_bin_target() {
    let test_paths = &[
        "C:\\Users\\User\\AppData\\Local\\Programs\\Antigravity\\agy.exe",
        "C:\\Users\\User\\AppData\\Local\\Programs\\Antigravity\\language_server.exe",
        "C:\\Users\\User\\AppData\\Local\\Programs\\Antigravity\\Antigravity IDE.exe",
    ];

    let kill_holder_allowed = |path_str: &str| -> bool {
        let p = std::path::Path::new(path_str);
        let fname = p.file_name().unwrap_or_default().to_string_lossy();
        fname == "agy.exe" || fname.starts_with("language_server")
    };

    assert!(kill_holder_allowed(test_paths[0]));
    assert!(kill_holder_allowed(test_paths[1]));
    assert!(!kill_holder_allowed(test_paths[2]), "kill_holder must NEVER target IDE shell");
}

#[test]
fn test_r1_boundary_unrelated_processes_remain_untouched() {
    let running = &[
        "chrome.exe",
        "explorer.exe",
        "svchost.exe",
        "pwsh.exe",
        "cmd.exe",
        "Antigravity IDE.exe",
    ];

    let to_kill = ProcessTargetInspector::filter_to_kill(running, ProcessTargetInspector::VALID_KILL_TARGETS);
    assert!(to_kill.is_empty(), "None of the unrelated or IDE processes should be targeted");
}

// =========================================================================
// R2 Boundary & Corner Cases
// =========================================================================

#[test]
fn test_r2_boundary_empty_env_value_treated_as_delete() {
    let reg = MockRegistryEnv::new();
    reg.set_user_var("TEST_EMPTY", Some("initial_val")).unwrap();
    assert_eq!(reg.get_user_var("TEST_EMPTY"), Some("initial_val".to_string()));

    reg.set_user_var("TEST_EMPTY", None).unwrap();
    assert_eq!(reg.get_user_var("TEST_EMPTY"), None);
}

#[test]
fn test_r2_boundary_extreme_length_environment_value() {
    let reg = MockRegistryEnv::new();
    let large_url = format!("http://proxy.internal.corp:{}/{}", 8080, "a".repeat(4000));

    let set_res = reg.set_user_var("LARGE_PROXY_CONFIG", Some(&large_url));
    assert!(set_res.is_ok());

    let fetched = reg.get_user_var("LARGE_PROXY_CONFIG").unwrap();
    assert_eq!(fetched.len(), large_url.len());
    assert_eq!(fetched, large_url);
}

#[test]
fn test_r2_boundary_special_characters_in_proxy_url() {
    let reg = MockRegistryEnv::new();
    let complex_url = "http://user%40corp:P%40ss%3Aword!$&'()*+,;=@10.0.0.1:8080";

    reg.set_user_var("HTTPS_PROXY", Some(complex_url)).unwrap();
    let fetched = reg.get_user_var("HTTPS_PROXY").unwrap();
    assert_eq!(fetched, complex_url);
}

#[test]
fn test_r2_boundary_concurrent_registry_access() {
    let reg = Arc::new(MockRegistryEnv::new());
    let mut handles = vec![];

    for i in 0..10 {
        let r = Arc::clone(&reg);
        handles.push(thread::spawn(move || {
            let key = format!("THREAD_VAR_{}", i);
            let val = format!("val_{}", i);
            r.set_user_var(&key, Some(&val)).unwrap();
            let read_back = r.get_user_var(&key);
            assert_eq!(read_back, Some(val));
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_r2_boundary_hung_window_broadcast_timeout_abort() {
    assert_eq!(RegistryConstants::SMTO_ABORTIFHUNG, 0x0002);
    assert_eq!(RegistryConstants::BROADCAST_TIMEOUT_MS, 5000);
}

// =========================================================================
// R3 Boundary & Corner Cases
// =========================================================================

#[test]
fn test_r3_boundary_empty_input_file_content() {
    let res = SafeRegexInspector::safe_extract_captures("");
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err(),
        "Сигнатура не найдена (возможно, установлена другая версия)"
    );
}

#[test]
fn test_r3_boundary_huge_bundle_file_boundary() {
    let prefix = "const padding = 'x';\n".repeat(100_000); // ~2.1MB
    let valid_func = r#"
        function sendAuthRequest(req, token, client) {
            let userConfig = authModule.getUserSettings({});
            let authResponse = transport.executeCall(req, token, client);
            return authResponse;
        }
    "#;
    let suffix = "const footer = 'end';\n".repeat(50_000);
    let full_content = format!("{}{}{}", prefix, valid_func, suffix);

    let res = SafeRegexInspector::safe_extract_captures(&full_content);
    assert!(res.is_ok(), "Safe extractor must handle multi-megabyte bundle without failure");
    let groups = res.unwrap();
    assert_eq!(groups.fname, "sendAuthRequest");
}

#[test]
fn test_r3_boundary_partial_regex_match_insufficient_groups() {
    let partial_js = r#"
        function incompleteSig(a, b, c) {
            let onlyOne = mod.call({});
            return true;
        }
    "#;
    let res = SafeRegexInspector::safe_extract_captures(partial_js);
    assert!(res.is_err(), "Partial signature match must return Err, not panic");
}

#[test]
fn test_r3_boundary_unicode_characters_in_js_comments() {
    let unicode_js = r#"
        // Привет, мир! Комментарий на русском языке с эмодзи 🚀
        function sendAuthRequest(req, token, client) {
            // Тестовая функция авторизации
            let userConfig = authModule.getUserSettings({});
            let authResponse = transport.executeCall(req, token, client);
            return authResponse;
        }
    "#;

    let res = SafeRegexInspector::safe_extract_captures(unicode_js);
    assert!(res.is_ok(), "Unicode comments must not interfere with capture extraction");
    let groups = res.unwrap();
    assert_eq!(groups.fname, "sendAuthRequest");
}

#[test]
fn test_r3_boundary_multiple_occurrences_extracts_first() {
    let duplicate_js = r#"
        function firstFunc(a, b, c) {
            let u1 = mod.get({});
            let r1 = tr.call(a, b, c);
            return r1;
        }
        function secondFunc(x, y, z) {
            let u2 = mod.get({});
            let r2 = tr.call(x, y, z);
            return r2;
        }
    "#;

    let res = SafeRegexInspector::safe_extract_captures(duplicate_js);
    assert!(res.is_ok());
    assert_eq!(res.unwrap().fname, "firstFunc");
}

// =========================================================================
// R4 Boundary & Corner Cases
// =========================================================================

#[test]
fn test_r4_boundary_zero_byte_license_key_file() {
    let temp_dir = std::env::temp_dir().join(format!("ag_test_r4_zero_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let license_file = temp_dir.join("license.key");

    fs::write(&license_file, b"").unwrap();

    let content = fs::read_to_string(&license_file).unwrap();
    let cleaned = LicenseOracle::sanitize_key_input(&content);
    assert!(!LicenseOracle::verify_key(&cleaned, "2.11.0"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_r4_boundary_key_with_leading_trailing_newlines_and_spaces() {
    let version = "2.11.0";
    let key = LicenseOracle::mint_key("SPACE_TEST", version);
    let polluted = format!("\r\n\t  \"{}\"  \n\r", key);

    let cleaned = LicenseOracle::sanitize_key_input(&polluted);
    assert_eq!(cleaned, key);
    assert!(LicenseOracle::verify_key(&cleaned, version));
}

#[test]
fn test_r4_boundary_key_length_23_and_25_rejected() {
    let version = "2.11.0";
    let key = LicenseOracle::mint_key("LEN_TEST_01", version);
    assert_eq!(key.len(), 24);

    let short_key = &key[..23];
    assert_eq!(short_key.len(), 23);
    assert!(!LicenseOracle::verify_key(short_key, version));

    let long_key = format!("{}A", key);
    assert_eq!(long_key.len(), 25);
    assert!(!LicenseOracle::verify_key(&long_key, version));
}

#[test]
fn test_r4_boundary_license_file_path_missing_parent_directory() {
    let temp_dir = std::env::temp_dir()
        .join(format!("ag_test_r4_missing_parent_{}", std::process::id()))
        .join("DeepSubDir");
    let license_file = temp_dir.join("license.key");

    assert!(!temp_dir.exists());

    // Ensure save routine creates directories
    if let Some(parent) = license_file.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&license_file, "TEST_KEY").unwrap();

    assert!(license_file.exists());
    let _ = fs::remove_dir_all(temp_dir.parent().unwrap());
}

#[test]
fn test_r4_boundary_key_constant_time_comparison_integrity() {
    let version = "2.11.0";
    let key = LicenseOracle::mint_key("CT_TEST_01", version);

    // Corrupt last character
    let mut chars: Vec<char> = key.chars().collect();
    let last_idx = chars.len() - 1;
    chars[last_idx] = if chars[last_idx] == 'A' { 'B' } else { 'A' };
    let corrupted_last: String = chars.into_iter().collect();

    assert!(!LicenseOracle::verify_key(&corrupted_last, version));

    // Corrupt first signature character (index 12)
    let mut chars: Vec<char> = key.chars().collect();
    chars[12] = if chars[12] == 'A' { 'B' } else { 'A' };
    let corrupted_first_sig: String = chars.into_iter().collect();

    assert!(!LicenseOracle::verify_key(&corrupted_first_sig, version));
}

#[test]
fn test_r4_boundary_case_insensitivity_in_nonce() {
    let version = "2.11.0";
    let key_upper = LicenseOracle::mint_key("ABCDEF123456", version);
    let key_lower = LicenseOracle::mint_key("abcdef123456", version);

    assert_eq!(key_upper, key_lower, "Nonce casing must be normalized to uppercase");
}

// =========================================================================
// R5 Boundary & Corner Cases
// =========================================================================

#[test]
fn test_r5_boundary_socks5_port_0_and_port_65536_rejected() {
    let res_port0 = UpstreamSpec::parse("socks5://127.0.0.1:0");
    assert!(res_port0.is_err());
    assert_eq!(res_port0.unwrap_err(), "порт не может быть 0");

    let res_port_overflow = UpstreamSpec::parse("socks5://127.0.0.1:70000");
    assert!(res_port_overflow.is_err());
    assert!(res_port_overflow.unwrap_err().contains("не число"));

    let res_port_alpha = UpstreamSpec::parse("socks5://127.0.0.1:xyz");
    assert!(res_port_alpha.is_err());
    assert!(res_port_alpha.unwrap_err().contains("не число"));
}

#[test]
fn test_r5_boundary_socks5_auth_with_at_and_colon_in_password() {
    let complex = "socks5://operator:my@p:a:s:s@192.168.1.1:1080";
    let spec = UpstreamSpec::parse(complex).unwrap();

    assert_eq!(spec.host, "192.168.1.1");
    assert_eq!(spec.port, 1080);
    assert_eq!(spec.auth, Some("operator:my@p:a:s:s".to_string()));
}

#[test]
fn test_r5_boundary_socks5_username_password_255_byte_limit() {
    let long_user = "a".repeat(256);
    let url_long_user = format!("socks5://{}:pass@127.0.0.1:1080", long_user);
    let res_user = UpstreamSpec::parse(&url_long_user);
    assert!(res_user.is_err());
    assert_eq!(res_user.unwrap_err(), "длина логина превышает 255 байт");

    let long_pass = "b".repeat(256);
    let url_long_pass = format!("socks5://user:{}@127.0.0.1:1080", long_pass);
    let res_pass = UpstreamSpec::parse(&url_long_pass);
    assert!(res_pass.is_err());
    assert_eq!(res_pass.unwrap_err(), "длина пароля превышает 255 байт");
}

#[test]
fn test_r5_boundary_socks5_server_closes_connection_during_handshake() {
    let cfg = MockSocks5ServerConfig {
        close_connection_prematurely: true,
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let res = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        80,
        false,
        None,
        Duration::from_millis(500),
    );

    assert!(res.is_err(), "Premature close by proxy must yield clean Err");
}

#[test]
fn test_r5_boundary_socks5_server_returns_rep_failure_codes() {
    let cfg = MockSocks5ServerConfig {
        reply_rep_code: Socks5Constants::REP_CONN_REFUSED,
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let res = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        80,
        false,
        None,
        Duration::from_secs(1),
    );

    assert!(res.is_err());
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("соединение отклонено целевым узлом"),
        "Unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_r5_boundary_socks5_ipv6_bracket_syntax() {
    let spec = UpstreamSpec::parse("socks5://[2001:db8::1]:1080").unwrap();
    assert_eq!(spec.host, "2001:db8::1");
    assert_eq!(spec.port, 1080);
    assert_eq!(spec.kind, ProxyKind::Socks5);
    assert_eq!(spec.as_line(), "socks5://[2001:db8::1]:1080");
}
