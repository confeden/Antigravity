// tests/e2e_tests.rs
// Master End-to-End Integration Suite for ag_unlocker
// Covering Requirements R1-R5 per ORIGINAL_REQUEST.md & PROJECT.md.

mod common;
use common::*;
use std::fs;
use std::net::SocketAddr;
use std::time::Duration;

#[test]
fn test_e2e_complete_unlocker_pipeline() {
    // -------------------------------------------------------------------------
    // R1 Verification: Process Protection
    // -------------------------------------------------------------------------
    let running = &[
        "Antigravity IDE.exe",
        "Antigravity.exe",
        "language_server_windows_x64.exe",
        "agy.exe",
    ];
    let to_kill = ProcessTargetInspector::filter_to_kill(running, ProcessTargetInspector::VALID_KILL_TARGETS);
    assert!(!to_kill.contains(&"Antigravity IDE.exe".to_string()));
    assert!(!to_kill.contains(&"Antigravity.exe".to_string()));
    assert!(to_kill.contains(&"language_server_windows_x64.exe".to_string()));
    assert!(to_kill.contains(&"agy.exe".to_string()));

    // -------------------------------------------------------------------------
    // R2 Verification: Registry Management & Zero PowerShell
    // -------------------------------------------------------------------------
    let reg = MockRegistryEnv::new();
    let proxy_url = "http://127.0.0.1:53129";
    reg.set_user_var("HTTPS_PROXY", Some(proxy_url)).unwrap();
    assert_eq!(reg.get_user_var("HTTPS_PROXY"), Some(proxy_url.to_string()));
    assert_eq!(reg.powershell_call_count(), 0);
    assert_eq!(reg.broadcast_count(), 1);

    reg.delete_user_var("HTTPS_PROXY").unwrap();
    assert_eq!(reg.get_user_var("HTTPS_PROXY"), None);
    assert_eq!(reg.powershell_call_count(), 0);

    // -------------------------------------------------------------------------
    // R3 Verification: Safe Regex Extraction & Obsolete JS Elimination
    // -------------------------------------------------------------------------
    let js_sample = r#"
        function sendAuthRequest(req, token, client) {
            let u = authMod.getUserSettings({});
            let r = transport.executeCall(req, token, client);
            return r;
        }
    "#;
    let safe_res = SafeRegexInspector::safe_extract_captures(js_sample);
    assert!(safe_res.is_ok());
    let groups = safe_res.unwrap();
    assert_eq!(groups.fname, "sendAuthRequest");
    assert!(!SafeRegexInspector::contains_broken_inline_js(js_sample));

    // -------------------------------------------------------------------------
    // R4 Verification: License Validation & LocalAppData Caching
    // -------------------------------------------------------------------------
    let temp_dir = std::env::temp_dir().join(format!("ag_e2e_master_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let key_path = temp_dir.join("license.key");

    let version = "2.11.0";
    let key = LicenseOracle::mint_key("E2E_MASTER_KEY", version);
    fs::write(&key_path, &key).unwrap();

    let cached_content = fs::read_to_string(&key_path).unwrap();
    let cleaned = LicenseOracle::sanitize_key_input(&cached_content);
    assert!(LicenseOracle::verify_key(&cleaned, version));
    let _ = fs::remove_dir_all(&temp_dir);

    // -------------------------------------------------------------------------
    // R5 Verification: SOCKS5 & SOCKS5h Protocol Engine
    // -------------------------------------------------------------------------
    let s5_url = "socks5://operator:secret@127.0.0.1:1080";
    let spec = UpstreamSpec::parse(s5_url).unwrap();
    assert_eq!(spec.kind, ProxyKind::Socks5);
    assert_eq!(spec.host, "127.0.0.1");
    assert_eq!(spec.port, 1080);
    assert_eq!(spec.auth, Some("operator:secret".to_string()));

    let s5h_url = "socks5h://remote-resolver.corp:1080";
    let spec_h = UpstreamSpec::parse(s5h_url).unwrap();
    assert_eq!(spec_h.kind, ProxyKind::Socks5h);

    let server = MockSocks5Server::start(MockSocks5ServerConfig::default());
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    let client_stream = Socks5Client::connect(
        proxy_addr,
        "daily-cloudcode-pa.googleapis.com",
        443,
        true,
        None,
        Duration::from_secs(3),
    );
    assert!(client_stream.is_ok());
}
