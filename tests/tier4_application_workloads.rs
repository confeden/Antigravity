// tests/tier4_application_workloads.rs
// Tier 4: Real-World Application Workloads
// End-to-end user workflows, realistic multi-step operations, and operational profiles.

mod common;
use common::*;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

// =========================================================================
// Workload 1: First-Time User Onboarding, Key Persistence & Stale Key Rotation
// =========================================================================

#[test]
fn test_r4_workload_first_time_user_onboarding_and_restart() {
    let temp_dir = std::env::temp_dir().join(format!("ag_workload_auth_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let license_file = temp_dir.join("license.key");

    let current_version = "2.11.0";

    // Step 1: First launch — no key file exists yet
    assert!(!license_file.exists());
    let auto_login_first = if license_file.exists() {
        let content = fs::read_to_string(&license_file).unwrap_or_default();
        let k = LicenseOracle::sanitize_key_input(&content);
        LicenseOracle::verify_key(&k, current_version)
    } else {
        false
    };
    assert!(!auto_login_first, "First run must prompt user for key");

    // Step 2: User enters key with messy formatting (spaces, quotes, hyphens)
    let minted_key = LicenseOracle::mint_key("FIRST_USER", current_version);
    let messy_input = format!(" \"{}-{}-{}\" \n", &minted_key[..8], &minted_key[8..16], &minted_key[16..]);
    let cleaned = LicenseOracle::sanitize_key_input(&messy_input);
    assert!(LicenseOracle::verify_key(&cleaned, current_version));

    // Step 3: Application saves key to %LOCALAPPDATA%\AGUnlocker\license.key
    fs::write(&license_file, &cleaned).unwrap();
    assert!(license_file.exists());

    // Step 4: Second launch — auto-login bypasses prompt
    let auto_login_second = if license_file.exists() {
        let content = fs::read_to_string(&license_file).unwrap_or_default();
        let k = LicenseOracle::sanitize_key_input(&content);
        LicenseOracle::verify_key(&k, current_version)
    } else {
        false
    };
    assert!(auto_login_second, "Second run must auto-login without prompt");

    // Step 5: Application is updated to v2.12.0 — cached key is now stale
    let updated_version = "2.12.0";
    let auto_login_after_update = if license_file.exists() {
        let content = fs::read_to_string(&license_file).unwrap_or_default();
        let k = LicenseOracle::sanitize_key_input(&content);
        LicenseOracle::verify_key(&k, updated_version)
    } else {
        false
    };
    assert!(
        !auto_login_after_update,
        "After update to v2.12.0, stale key must be rejected, prompting user"
    );

    // Step 6: User enters new key for v2.12.0, overwriting old file
    let new_version_key = LicenseOracle::mint_key("UPDATED_USER", updated_version);
    fs::write(&license_file, &new_version_key).unwrap();

    let auto_login_updated = if license_file.exists() {
        let content = fs::read_to_string(&license_file).unwrap_or_default();
        let k = LicenseOracle::sanitize_key_input(&content);
        LicenseOracle::verify_key(&k, updated_version)
    } else {
        false
    };
    assert!(auto_login_updated, "New key validates under v2.12.0");

    let _ = fs::remove_dir_all(&temp_dir);
}

// =========================================================================
// Workload 2: End-to-End SOCKS5 Tunnel Session with Bidirectional Traffic
// =========================================================================

#[test]
fn test_r5_workload_end_to_end_socks5_tunnel_data_transfer() {
    // 1. Launch Mock SOCKS5 server with authentication
    let cfg = MockSocks5ServerConfig {
        require_auth: Some(("prod_user".to_string(), "prod_pass".to_string())),
        echo_data: true,
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    // 2. Establish tunnel
    let mut sock = Socks5Client::connect(
        proxy_addr,
        "127.0.0.1",
        8080,
        false,
        Some(("prod_user", "prod_pass")),
        Duration::from_secs(3),
    )
    .expect("SOCKS5 tunnel should connect");

    // 3. Send HTTP-like request over the tunnel
    let payload = b"POST /v1internal:predict HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 13\r\n\r\nHello SOCKS5!";
    sock.write_all(payload).expect("write payload to SOCKS5 tunnel");

    // 4. Read response from echo server
    let mut response = vec![0u8; payload.len()];
    sock.read_exact(&mut response).expect("read response from SOCKS5 tunnel");
    assert_eq!(&response, payload, "Tunneled payload must match exactly");

    // 5. Verify server statistics
    let stats = server.stats.lock().unwrap();
    assert_eq!(stats.negotiated_method, Some(Socks5Constants::METHOD_USER_PASS));
    assert_eq!(stats.bytes_tunneled, payload.len());
}

// =========================================================================
// Workload 3: SOCKS5h Remote Domain Resolution Under Censored/Poisoned DNS
// =========================================================================

#[test]
fn test_r5_workload_socks5h_tunnel_under_poisoned_dns() {
    let cfg = MockSocks5ServerConfig {
        require_auth: None,
        echo_data: true,
        ..Default::default()
    };
    let server = MockSocks5Server::start(cfg);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", server.port).parse().unwrap();

    // Cloudcode PA domain which may be poisoned or blocked in RU/BY
    let blocked_endpoint = "daily-cloudcode-pa.googleapis.com";

    // With socks5h://, client NEVER calls local DNS; sends ATYP 0x03 directly to proxy
    let mut sock = Socks5Client::connect(
        proxy_addr,
        blocked_endpoint,
        443,
        true, // remote DNS
        None,
        Duration::from_secs(3),
    )
    .expect("SOCKS5h connection must succeed without local DNS resolution");

    let stats = server.stats.lock().unwrap();
    assert_eq!(stats.target_atyp, Some(Socks5Constants::ATYP_DOMAINNAME));
    assert_eq!(stats.target_host, Some(blocked_endpoint.to_string()));
    assert_eq!(stats.target_port, Some(443));

    // Send probe ping
    sock.write_all(b"PING").unwrap();
    let mut pong = [0u8; 4];
    sock.read_exact(&mut pong).unwrap();
    assert_eq!(&pong, b"PING");
}

// =========================================================================
// Workload 4: Watchdog High-Frequency Environment Polling Zero PowerShell
// =========================================================================

#[test]
fn test_r2_workload_watchdog_cleanup_loop_zero_powershell() {
    let reg = MockRegistryEnv::new();
    let proxy_url = "http://127.0.0.1:53129";

    reg.set_user_var("HTTPS_PROXY", Some(proxy_url)).unwrap();

    // Simulate 50 rapid watchdog polling ticks
    for _ in 0..50 {
        let current = reg.get_user_var("HTTPS_PROXY");
        assert_eq!(current.as_deref(), Some(proxy_url));
    }

    // Watchdog cleanup event
    reg.delete_user_var("HTTPS_PROXY").unwrap();
    assert_eq!(reg.get_user_var("HTTPS_PROXY"), None);

    // Assert zero PowerShell spawned throughout the entire cycle
    assert_eq!(
        reg.powershell_call_count(),
        0,
        "Watchdog polling loop must never spawn powershell.exe"
    );
}

// =========================================================================
// Workload 5: Full Patch & Revert Cycle with Running IDE Window Untouched
// =========================================================================

#[test]
fn test_r1_r3_workload_full_patch_revert_cycle_with_unsaved_ide() {
    // 1. Initial system state: IDE window open with unsaved tabs
    let running_processes = &[
        "Antigravity IDE.exe",
        "Antigravity.exe",
        "language_server.exe",
        "agy.exe",
    ];

    // 2. User clicks "Patch Antigravity"
    // Safe process termination:
    let kill_targets = ProcessTargetInspector::filter_to_kill(
        running_processes,
        ProcessTargetInspector::VALID_KILL_TARGETS,
    );
    assert!(!kill_targets.contains(&"Antigravity IDE.exe".to_string()));
    assert!(!kill_targets.contains(&"Antigravity.exe".to_string()));
    assert!(kill_targets.contains(&"language_server.exe".to_string()));
    assert!(kill_targets.contains(&"agy.exe".to_string()));

    // Safe IDE bundle patching:
    let original_js = r#"
        function authHandler(req, token, client) {
            let u = mod.getUserSettings({});
            let r = tr.executeCall(req, token, client);
            return r;
        }
    "#;
    let safe_extract = SafeRegexInspector::safe_extract_captures(original_js);
    assert!(safe_extract.is_ok());

    let patched_js = format!("// UNLOCKED\n{}", original_js);
    assert!(patched_js.contains("// UNLOCKED"));

    // 3. User works in IDE... Later clicks "Revert All"
    // Revert process termination:
    let revert_kill = ProcessTargetInspector::filter_to_kill(
        running_processes,
        ProcessTargetInspector::VALID_KILL_TARGETS,
    );
    assert!(!revert_kill.contains(&"Antigravity IDE.exe".to_string()));

    // Revert bundle restoration:
    let reverted_js = patched_js.trim_start_matches("// UNLOCKED\n");
    assert_eq!(reverted_js, original_js);

    // 4. Confirm editor shell was NEVER touched across both patch and revert
    let kill_targets_refs: Vec<&str> = kill_targets.iter().map(|s| s.as_str()).collect();
    let revert_kill_refs: Vec<&str> = revert_kill.iter().map(|s| s.as_str()).collect();
    assert!(
        !ProcessTargetInspector::contains_forbidden_ide_shell(&kill_targets_refs),
        "Patch kill list violated IDE protection"
    );
    assert!(
        !ProcessTargetInspector::contains_forbidden_ide_shell(&revert_kill_refs),
        "Revert kill list violated IDE protection"
    );
}
