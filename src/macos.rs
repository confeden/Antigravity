//! What macOS needs that Linux does not (P7, S80).
//!
//! The patch itself is the same string rename as everywhere else; four things
//! around it are not:
//! - **Signatures.** An edited Mach-O carries page hashes that no longer match,
//!   and Apple Silicon kills it at exec («Code Signature Invalid»). Every binary
//!   the patcher writes is re-signed ad hoc *before* it is renamed into place, so
//!   the name never points at a file the kernel would refuse.
//! - **Bundles.** Installs are `.app` bundles in `/Applications` or
//!   `~/Applications`; the install root is `<bundle>/Contents`, whose `Resources`
//!   is capitalised (`Antigravity.app/Contents/Resources/bin/language_server`,
//!   measured from the 2.29.0 arm64 dmg). A patched bundle no longer matches its
//!   outer seal, so its quarantine flag is taken off: a still-quarantined bundle
//!   would be assessed by Gatekeeper on first launch and called damaged.
//! - **Services.** launchd user agents in `~/Library/LaunchAgents`, in place of
//!   systemd user units.
//! - **Environment.** `launchctl setenv` is what an app started from the Dock or
//!   Finder inherits; a RunAtLoad agent sets it again after a reboot.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Label prefix of every launchd job this tool owns.
pub const LABEL_PREFIX: &str = "com.agunlocker";

/// The job that re-sets the proxy variable at every login.
pub const ENV_LABEL: &str = "com.agunlocker.env";

pub fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
}

/// `~/Library/Application Support` - where an Electron app keeps its profile
/// (`Antigravity/logs`, `Antigravity/User/settings.json`).
pub fn application_support() -> PathBuf {
    home().join("Library").join("Application Support")
}

/// The `Resources` directory of an install root, whichever case it is spelled
/// in. A bundle has `Contents/Resources`; on the default case-insensitive APFS
/// `resources` reaches it too, but a case-sensitive volume would not.
pub fn resources_dir(inst: &Path) -> PathBuf {
    let upper = inst.join("Resources");
    if upper.is_dir() {
        upper
    } else {
        inst.join("resources")
    }
}

/// Every Antigravity bundle in the two Applications folders, as install roots
/// (`<bundle>/Contents`).
pub fn app_bundles() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in [PathBuf::from("/Applications"), home().join("Applications")] {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".app") && name.contains("antigravity") {
                let contents = e.path().join("Contents");
                if contents.is_dir() {
                    out.push(contents);
                }
            }
        }
    }
    out
}

/// The `.app` directory `path` lives in, if any.
pub fn bundle_of(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("app")))
        .map(Path::to_path_buf)
}

/// Whether `data` is a Mach-O image (thin 64-bit, thin 32-bit or universal).
pub fn is_macho(data: &[u8]) -> bool {
    matches!(
        data.get(..4),
        Some([0xcf, 0xfa, 0xed, 0xfe])
            | Some([0xce, 0xfa, 0xed, 0xfe])
            | Some([0xca, 0xfe, 0xba, 0xbe])
            | Some([0xca, 0xfe, 0xba, 0xbf])
    )
}

/// Signs `path` ad hoc, keeping the identifier it had. Without the hardened
/// runtime flag, so the vendor's runtime entitlements (`allow-jit`, measured on
/// the 2.29.0 language server) are not needed; restricted ones would make AMFI
/// kill an ad-hoc binary, which is why entitlements are not carried over.
pub fn resign(path: &Path) -> Result<(), String> {
    let run = |preserve: bool| {
        let mut cmd = Command::new("/usr/bin/codesign");
        cmd.args(["--force", "--sign", "-"]);
        if preserve {
            cmd.arg("--preserve-metadata=identifier");
        }
        cmd.arg(path).stdout(Stdio::null()).output()
    };
    match run(true) {
        Ok(o) if o.status.success() => return Ok(()),
        _ => {}
    }
    // A binary that was never signed has no identifier to preserve.
    match run(false) {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "codesign: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Err(format!("codesign не запустился: {e}")),
    }
}

/// Takes the quarantine flag off `path` (recursively for a directory). Best
/// effort: a file that never had one makes `xattr` fail, which is fine.
pub fn strip_quarantine(path: &Path) {
    let _ = Command::new("/usr/bin/xattr")
        .args(["-dr", "com.apple.quarantine"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// The hint for a write into a bundle that macOS refused. Since Ventura a
/// signed app's bundle is protected: only a process with «Управление
/// приложениями» (App Management) may change it, even when the files are the
/// user's own - and the error is a plain EPERM.
pub fn app_management_hint(path: &Path, err: &str) -> String {
    if bundle_of(path).is_some()
        && (err.contains("Operation not permitted") || err.contains("os error 1)"))
    {
        format!(
            "{err}. macOS не дал изменить приложение: Системные настройки → \
             Конфиденциальность и безопасность → Управление приложениями → \
             включите Терминал (или программу, из которой запущен разблокировщик), \
             затем повторите"
        )
    } else {
        err.to_string()
    }
}

// ---------------------------------------------------------------------------
// launchd
// ---------------------------------------------------------------------------

extern "C" {
    fn getuid() -> u32;
}

fn gui_domain() -> String {
    // SAFETY: getuid has no preconditions and cannot fail.
    format!("gui/{}", unsafe { getuid() })
}

fn launchctl(args: &[&str]) -> Option<std::process::Output> {
    Command::new("/bin/launchctl")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()
}

pub fn agent_plist_path(label: &str) -> PathBuf {
    home()
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist"))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A user agent's plist. `keep_alive` restarts it when it exits (a service);
/// without it the job runs once per login (the environment setter).
pub fn agent_plist(
    label: &str,
    args: &[String],
    env: &[(&str, String)],
    keep_alive: bool,
) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n",
    );
    s.push_str(&format!(
        "  <key>Label</key>\n  <string>{}</string>\n",
        xml_escape(label)
    ));
    s.push_str("  <key>ProgramArguments</key>\n  <array>\n");
    for a in args {
        s.push_str(&format!("    <string>{}</string>\n", xml_escape(a)));
    }
    s.push_str("  </array>\n");
    if !env.is_empty() {
        s.push_str("  <key>EnvironmentVariables</key>\n  <dict>\n");
        for (k, v) in env {
            s.push_str(&format!(
                "    <key>{}</key>\n    <string>{}</string>\n",
                xml_escape(k),
                xml_escape(v)
            ));
        }
        s.push_str("  </dict>\n");
    }
    s.push_str("  <key>RunAtLoad</key>\n  <true/>\n");
    if keep_alive {
        s.push_str("  <key>KeepAlive</key>\n  <true/>\n");
        s.push_str("  <key>ThrottleInterval</key>\n  <integer>5</integer>\n");
    }
    s.push_str("</dict>\n</plist>\n");
    s
}

/// Whether launchd has the job loaded in this user's GUI domain.
pub fn agent_is_loaded(label: &str) -> bool {
    launchctl(&["print", &format!("{}/{label}", gui_domain())]).is_some_and(|o| o.status.success())
}

/// Whether the job's process is up right now.
pub fn agent_is_running(label: &str) -> bool {
    launchctl(&["print", &format!("{}/{label}", gui_domain())]).is_some_and(|o| {
        o.status.success() && String::from_utf8_lossy(&o.stdout).contains("state = running")
    })
}

/// Writes the plist and (re)loads the job. A job whose plist changed, or that
/// is not loaded, is booted out and bootstrapped again so launchd reads the
/// new file; one already loaded from the same file is left running.
pub fn agent_install(label: &str, plist: &str) -> Result<bool, String> {
    let path = agent_plist_path(label);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("не создать {}: {e}", dir.display()))?;
    }
    let changed = fs::read_to_string(&path).map_or(true, |old| old != plist);
    if changed {
        fs::write(&path, plist).map_err(|e| format!("не записать {}: {e}", path.display()))?;
    }
    let loaded = agent_is_loaded(label);
    if changed && loaded {
        launchctl(&["bootout", &format!("{}/{label}", gui_domain())]);
    }
    if changed || !loaded {
        let p = path.display().to_string();
        let ok = launchctl(&["bootstrap", &gui_domain(), &p]).is_some_and(|o| o.status.success())
            // Older launchctl, or a session where bootstrap is refused.
            || launchctl(&["load", "-w", &p]).is_some_and(|o| o.status.success());
        if !ok && !agent_is_loaded(label) {
            return Err(format!("launchd не загрузил {label}"));
        }
    }
    Ok(changed)
}

/// Kills and restarts the job's process (it keeps its plist).
pub fn agent_restart(label: &str) -> bool {
    launchctl(&["kickstart", "-k", &format!("{}/{label}", gui_domain())])
        .is_some_and(|o| o.status.success())
}

/// Unloads the job and removes its plist. Quiet when there was none.
pub fn agent_remove(label: &str) {
    launchctl(&["bootout", &format!("{}/{label}", gui_domain())]);
    let _ = fs::remove_file(agent_plist_path(label));
}

pub fn agent_exists(label: &str) -> bool {
    agent_plist_path(label).exists()
}

// ---------------------------------------------------------------------------
// The launchd environment
// ---------------------------------------------------------------------------

/// A variable as launchd hands it to apps started from now on.
pub fn getenv(name: &str) -> Option<String> {
    let out = launchctl(&["getenv", name])?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !v.is_empty()).then_some(v)
}

pub fn setenv(name: &str, value: &str) -> bool {
    launchctl(&["setenv", name, value]).is_some_and(|o| o.status.success())
}

pub fn unsetenv(name: &str) -> bool {
    launchctl(&["unsetenv", name]).is_some_and(|o| o.status.success())
}

/// The value the login agent sets `name` to, read back from its plist.
pub fn persisted_env(name: &str) -> Option<String> {
    let text = fs::read_to_string(agent_plist_path(ENV_LABEL)).ok()?;
    let needle = format!("<string>{}</string>", xml_escape(name));
    let rest = &text[text.find(&needle)? + needle.len()..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")? + start;
    let v = rest[start..end]
        .replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&");
    (!v.trim().is_empty()).then_some(v)
}

/// Sets `name` now and at every later login. Returns whether anything changed.
pub fn persist_env(name: &str, value: &str) -> Result<bool, String> {
    let plist = agent_plist(
        ENV_LABEL,
        &[
            "/bin/launchctl".to_string(),
            "setenv".to_string(),
            name.to_string(),
            value.to_string(),
        ],
        &[],
        false,
    );
    let changed = agent_install(ENV_LABEL, &plist)?;
    let live = getenv(name).as_deref() == Some(value);
    if !live && !setenv(name, value) {
        return Err(format!("launchctl setenv {name} не удался"));
    }
    Ok(changed || !live)
}

/// Takes `name` off now and drops the login agent. Returns whether either was there.
pub fn unpersist_env(name: &str) -> bool {
    let had_file = agent_exists(ENV_LABEL);
    if had_file {
        agent_remove(ENV_LABEL);
    }
    let had_live = getenv(name).is_some();
    if had_live {
        unsetenv(name);
    }
    had_file || had_live
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macho_magics_are_recognised() {
        assert!(is_macho(&[0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]));
        assert!(is_macho(&[0xca, 0xfe, 0xba, 0xbe]));
        assert!(!is_macho(b"\x7fELF"));
        assert!(!is_macho(b"MZ"));
    }

    #[test]
    fn a_plist_escapes_what_xml_would_choke_on() {
        let p = agent_plist(
            "com.agunlocker.x",
            &["/a b/c&d".into()],
            &[("K", "<v>".into())],
            true,
        );
        assert!(p.contains("<string>/a b/c&amp;d</string>"));
        assert!(p.contains("<string>&lt;v&gt;</string>"));
        assert!(p.contains("<key>KeepAlive</key>"));
    }

    #[test]
    fn the_bundle_of_a_language_server_is_its_app() {
        let p = Path::new("/Applications/Antigravity.app/Contents/Resources/bin/language_server");
        assert_eq!(
            bundle_of(p),
            Some(PathBuf::from("/Applications/Antigravity.app"))
        );
        assert_eq!(bundle_of(Path::new("/Users/x/.gemini/bin/agy")), None);
    }
}
