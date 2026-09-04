use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

// Pinning the proxy addresses into the hosts file.
//
// This is the fallback for the case NRPT cannot serve: with a VPN up, Windows
// sends the NRPT query through the tunnel no matter what the routing table says
// (see `split_route`), so the resolver answers with genuine Google addresses and
// the region gate fires again. `dns_client` gets the substituted address over
// the ISP link instead, and writing it here takes the DNS layer out of the loop
// entirely - both the Go language server and the Electron shell read this file.
//
// Only written while a tunnel is up. Without one the NRPT rules do the same job
// and stay correct as the proxy rotates addresses, which a static file does not.

const BEGIN: &str = "# AG_UNLOCKER_HOSTS_BEGIN";
const END: &str = "# AG_UNLOCKER_HOSTS_END";

#[cfg(target_os = "windows")]
const EOL: &str = "\r\n";
#[cfg(not(target_os = "windows"))]
const EOL: &str = "\n";

#[cfg(target_os = "windows")]
pub fn hosts_path() -> PathBuf {
    let root = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    PathBuf::from(root)
        .join("System32")
        .join("drivers")
        .join("etc")
        .join("hosts")
}

#[cfg(not(target_os = "windows"))]
pub fn hosts_path() -> PathBuf {
    PathBuf::from("/etc/hosts")
}

fn render_block(entries: &[(String, Ipv4Addr)]) -> String {
    // The markers carry the canaries: unlike the binary, this file is readable
    // on a victim machine without access to the tool that wrote it.
    let mut out = format!(
        "{} {} {}{}",
        BEGIN,
        crate::canary::STATIC_CANARY,
        crate::canary::RELEASE_TOKEN,
        EOL
    );
    for (host, ip) in entries {
        out.push_str(&format!("{} {}{}", ip, host, EOL));
    }
    out.push_str(END);
    out.push_str(EOL);
    out
}

/// Swaps our block for `block`, or drops it when `block` is `None`. Everything
/// outside the markers is preserved byte for byte - this file belongs to the
/// system and other tools write to it too.
fn replace_block(existing: &str, block: Option<&str>) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut inside = false;
    for line in existing.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with(BEGIN) {
            inside = true;
            continue;
        }
        if inside {
            if trimmed.starts_with(END) {
                inside = false;
            }
            continue;
        }
        kept.push(line);
    }

    let mut out: String = kept.concat();
    if let Some(block) = block {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(EOL);
        }
        out.push_str(block);
    }
    out
}

fn rewrite(block: Option<&str>) -> Result<(), String> {
    let path = hosts_path();
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let updated = replace_block(&existing, block);
    if updated == existing {
        return Ok(());
    }
    fs::write(&path, updated).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            "hosts: требуются права администратора".to_string()
        } else {
            format!("hosts: {}", e)
        }
    })
}

pub fn write_entries(entries: &[(String, Ipv4Addr)]) -> Result<(), String> {
    if entries.is_empty() {
        return remove_entries();
    }
    rewrite(Some(&render_block(entries)))
}

pub fn remove_entries() -> Result<(), String> {
    rewrite(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<(String, Ipv4Addr)> {
        vec![(
            "cloudcode-pa.googleapis.com".to_string(),
            Ipv4Addr::new(87, 228, 47, 204),
        )]
    }

    #[test]
    fn foreign_lines_survive_untouched() {
        let original = "127.0.0.1 localhost\r\n# a comment\r\n10.0.0.1 intranet\r\n";
        let written = replace_block(original, Some(&render_block(&entries())));
        assert!(written.starts_with(original));
        assert!(written.contains("87.228.47.204 cloudcode-pa.googleapis.com"));
        assert_eq!(replace_block(&written, None), original);
    }

    #[test]
    fn rewriting_replaces_instead_of_appending() {
        let base = "127.0.0.1 localhost\r\n";
        let once = replace_block(base, Some(&render_block(&entries())));
        let twice = replace_block(&once, Some(&render_block(&entries())));
        assert_eq!(once, twice);
        assert_eq!(twice.matches(BEGIN).count(), 1);
    }

    #[test]
    fn a_file_without_a_trailing_newline_still_gets_a_clean_block() {
        let written = replace_block("127.0.0.1 localhost", Some(&render_block(&entries())));
        assert!(written.contains("localhost\r\n# AG_UNLOCKER_HOSTS_BEGIN"));
    }

    #[test]
    fn an_empty_file_gains_only_the_block() {
        let written = replace_block("", Some(&render_block(&entries())));
        assert!(written.starts_with(BEGIN));
        assert_eq!(replace_block(&written, None), "");
    }

    #[test]
    fn an_unterminated_block_does_not_eat_the_rest_of_the_file() {
        // Truncated write or hand edit: everything after the opening marker is
        // ours to drop, but the file must stay valid.
        let broken = format!("127.0.0.1 localhost\r\n{} x\r\n1.2.3.4 stray\r\n", BEGIN);
        assert_eq!(replace_block(&broken, None), "127.0.0.1 localhost\r\n");
    }

    #[test]
    fn the_block_carries_the_release_canary() {
        let block = render_block(&entries());
        assert!(block.contains(crate::canary::RELEASE_TOKEN));
        assert!(block.trim_end().ends_with(END));
    }
}
