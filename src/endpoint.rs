use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::utils::powershell;

// Which CloudCode host the client talks to, and why that is the whole fix.
//
// The region gate lives on the CloudCode API. `cloudcode-pa.googleapis.com` was
// substituted by the unblock resolvers until they dropped it, and their proxies
// refuse it by SNI, so that host cannot be reached through a permitted region
// any more (kb/dns.md). `daily-cloudcode-pa.googleapis.com` is the *same
// service* - its 401 names `service: cloudcode-pa.googleapis.com` - it is still
// substituted by geohide.ru, and geohide's proxy accepts its SNI. So the fix is
// to send the client at the host that still has a route.
//
// Nothing here patches a binary. Each surface already has a supported way to
// choose the endpoint:
//
// - Desktop passes `--cloud_code_endpoint https://daily-cloudcode-pa...` as a
//   literal in app.asar. Already on the working host; nothing to do.
// - IDE builds the argument from `getCloudCodeUrl()`, which returns
//   `cloudCodeUrlOverride` first if the `jetski.cloudCodeUrl` setting is set,
//   and otherwise the production host for any account without GCP terms - i.e.
//   every ordinary user. That setting is what we write.
// - CLI reads the `CLOUD_CODE_URL` environment variable ("UpdateEndpointURL
//   called with CLOUD_CODE_URL: %q" in agy.exe).
//
// Being configuration rather than a patch matters twice over: an app update
// cannot silently undo it the way it undoes the binary rename (G2), and a
// revert is a key removal rather than a byte-level restore.

/// The CloudCode host that still has a substituted route.
pub const DAILY_ENDPOINT: &str = "https://daily-cloudcode-pa.googleapis.com";

/// IDE setting that overrides the CloudCode base URL.
pub const IDE_SETTING: &str = "jetski.cloudCodeUrl";

/// Environment variable the CLI reads for the same purpose.
pub const CLI_ENV_VAR: &str = "CLOUD_CODE_URL";

/// What a run did, so the caller can say it out loud rather than change the
/// user's configuration silently.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The setting was written or corrected.
    Applied,
    /// Already pointing at the right host.
    AlreadySet,
}

/// Where the IDE keeps its user settings.
///
/// Derived from `product.json` rather than hardcoded: the folder is named after
/// `nameShort`, so a rebranded or renamed build still resolves correctly.
pub fn ide_settings_path(install: &Path) -> Option<PathBuf> {
    let product = crate::utils::resources_dir(install).join("app").join("product.json");
    let text = fs::read_to_string(product).ok()?;
    let name = Regex::new(r#""nameShort"\s*:\s*"([^"]+)""#)
        .ok()?
        .captures(&text)?
        .get(1)?
        .as_str()
        .to_string();
    // The user-config root is `%APPDATA%` on Windows, `~/Library/Application Support` on macOS,
    // and `~/.config` on Linux - the same VS Code layout underneath (`<root>/<nameShort>/User/settings.json`).
    #[cfg(target_os = "windows")]
    let root = PathBuf::from(std::env::var("APPDATA").ok()?);
    #[cfg(target_os = "macos")]
    let root = {
        let home = if let Ok(user) = std::env::var("SUDO_USER") {
            if !user.is_empty() && user != "root" {
                format!("/Users/{}", user)
            } else {
                std::env::var("HOME").ok()?
            }
        } else {
            std::env::var("HOME").ok()?
        };
        PathBuf::from(home).join("Library").join("Application Support")
    };
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    let root = {
        // An empty XDG_CONFIG_HOME (elevation can pass it through blank) is "unset",
        // not a relative root - fall back to ~/.config in that case.
        match std::env::var("XDG_CONFIG_HOME") {
            Ok(xdg) if !xdg.is_empty() => PathBuf::from(xdg),
            _ => PathBuf::from(std::env::var("HOME").ok()?).join(".config"),
        }
    };
    Some(root.join(name).join("User").join("settings.json"))
}

/// Rewrites `key` to `value`, leaving every other byte of the file alone.
///
/// A settings file is JSONC - comments and trailing commas are legal - and it
/// is the user's, not ours. Parsing and re-serialising would silently drop
/// their comments and reorder their keys, so this edits the text in place, the
/// same rule `hosts_pin` follows for the hosts file.
///
/// Unused since 2.11.0 removed the endpoint override (D11); kept because it is
/// the write half of the pair `remove_key` belongs to, its eight tests are what
/// pin that JSONC discipline (I18), and restoring an override - or writing any
/// other IDE setting - would otherwise start by rewriting it from scratch.
/// Delete it if a release passes with nothing needing to write a settings key.
#[allow(dead_code)]
fn upsert_key(text: &str, key: &str, value: &str) -> Result<String, String> {
    let existing = Regex::new(&format!(r#""{}"\s*:\s*"[^"]*""#, regex::escape(key)))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    let entry = format!("\"{}\": \"{}\"", key, value);

    if existing.is_match(text) {
        return Ok(existing.replace(text, entry.as_str()).into_owned());
    }
    if text.trim().is_empty() {
        return Ok(format!("{{\n    {}\n}}\n", entry));
    }

    let cut = text
        .rfind('}')
        .ok_or_else(|| "settings.json без закрывающей скобки".to_string())?;
    let head = text[..cut].trim_end();
    let mut out = String::with_capacity(text.len() + entry.len() + 8);
    out.push_str(head);
    // An empty object needs no separator; anything else does, unless the user
    // already left a trailing comma.
    if !head.ends_with('{') && !head.ends_with(',') {
        out.push(',');
    }
    out.push_str("\n    ");
    out.push_str(&entry);
    out.push('\n');
    out.push_str(&text[cut..]);
    Ok(out)
}

/// Drops `key`, taking the separating comma with it so the file stays valid.
fn remove_key(text: &str, key: &str) -> Result<String, String> {
    let escaped = regex::escape(key);
    // As a later entry it carries a comma in front of it; as the only or first
    // entry, the comma (if any) follows.
    let trailing = Regex::new(&format!(r#",\s*"{}"\s*:\s*"[^"]*""#, escaped))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    if trailing.is_match(text) {
        return Ok(trailing.replace(text, "").into_owned());
    }
    let alone = Regex::new(&format!(r#""{}"\s*:\s*"[^"]*"\s*,?\s*"#, escaped))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    Ok(alone.replace(text, "").into_owned())
}

// `apply_ide`/`apply_cli` were deleted in 2.11.0 together with the policy they
// served: the client is no longer pushed onto `daily-cloudcode-pa`, because the
// host it picks for itself is routed now (see `main::process_install`). The two
// `remove_*` below stay, and are called from menu 1 as well as the undo paths -
// a machine patched by an earlier build still carries the override, and nothing
// else would ever take it back off.

/// Takes our override back out of the IDE's settings.
///
/// Scoped to **our** value, the same rule `remove_cli` follows. Before 2.11.0
/// this stripped the key whatever it held, which was harmless while only we ever
/// wrote it; now that menu 1 calls it on every run, a user who points
/// `jetski.cloudCodeUrl` somewhere themselves would have it silently deleted on
/// the next patch. Deleting somebody's own configuration is the worse of the two
/// failures (G20), so a value we did not write is left alone.
pub fn remove_ide(install: &Path) -> Result<(), String> {
    let Some(path) = ide_settings_path(install) else {
        return Ok(());
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(());
    };
    if !text.contains(DAILY_ENDPOINT) {
        return Ok(());
    }
    let updated = remove_key(&text, IDE_SETTING)?;
    fs::write(&path, updated).map_err(|e| format!("не записать {}: {}", path.display(), e))
}

/// Removes the variable, but only when it still holds the value we wrote: a
/// user (or another tool) may have pointed it somewhere themselves.
pub fn remove_cli() -> Result<(), String> {
    if current_cli_endpoint().as_deref() != Some(DAILY_ENDPOINT) {
        return Ok(());
    }
    let script = format!(
        "[Environment]::SetEnvironmentVariable('{}',$null,'User')",
        CLI_ENV_VAR
    );
    powershell(&script).ok_or_else(|| "не удалось удалить переменную среды".to_string())?;
    Ok(())
}

/// Variables that point a Go client at the local fallback proxy.
///
/// `HTTPS_PROXY` is what `net/http` reads, and the language server is a Go
/// program - which is the whole reason no binary patch is needed to route it.
pub const PROXY_ENV_VAR: &str = "HTTPS_PROXY";
pub const NO_PROXY_ENV_VAR: &str = "NO_PROXY";
/// Node keeps its own bundled trust store and does not read the Windows one, so
/// installing the CA as a system root is not enough: Antigravity's extension
/// host is Node, it calls the gate host itself, and it answered `self signed
/// certificate in certificate chain` until this was set. Points at the same
/// per-machine CA that is already in the user's root store, so it widens nothing
/// that was not already trusted.
pub const NODE_CA_ENV_VAR: &str = "NODE_EXTRA_CA_CERTS";
/// Loopback never goes through the proxy: the language server serves its own
/// gRPC on 127.0.0.1 and talks to the extension host there.
const NO_PROXY_VALUE: &str = "127.0.0.1,localhost,::1";

/// Routes this user's Go clients through the local proxy.
///
/// Set for the whole user rather than one process because the language server is
/// launched by the IDE, not by us - there is no parent to inject an environment
/// into. That breadth is the cost of the design, and the reason the proxy
/// tunnels everything it does not carry straight through instead of failing:
/// anything else on the machine that picks the variable up keeps working.
#[cfg(target_os = "windows")]
pub fn apply_proxy(url: &str, ca_path: &str) -> Result<Outcome, String> {
    if current_env(PROXY_ENV_VAR).as_deref() == Some(url) {
        return Ok(Outcome::AlreadySet);
    }
    set_env(PROXY_ENV_VAR, Some(url))?;
    set_env(NO_PROXY_ENV_VAR, Some(NO_PROXY_VALUE))?;
    // The relay route terminates no TLS and installs no CA, so it needs no
    // `NODE_EXTRA_CA_CERTS`; only the legacy carrier route passes a real path.
    if !ca_path.is_empty() {
        set_env(NODE_CA_ENV_VAR, Some(ca_path))?;
    }
    Ok(Outcome::Applied)
}

/// The Linux path uses **two** mechanisms so the language server the IDE spawns
/// sees the proxy: a `~/.config/environment.d` drop-in makes it survive a reboot,
/// and `systemctl --user set-environment` sets it in the running user manager, so
/// a freshly-launched app inherits it **without a full re-login** - the user only
/// has to quit and reopen Antigravity. Lower-case aliases too, since Go reads
/// `HTTPS_PROXY` but other tooling reads `https_proxy`.
/// On macOS, sets environment variables for GUI apps and user sessions using launchctl.
#[cfg(target_os = "macos")]
pub fn apply_proxy(url: &str, _ca_path: &str) -> Result<Outcome, String> {
    for (k, v) in [
        (PROXY_ENV_VAR, url),
        ("https_proxy", url),
        (NO_PROXY_ENV_VAR, NO_PROXY_VALUE),
        ("no_proxy", NO_PROXY_VALUE),
    ] {
        crate::utils::run_macos_launchctl(&["setenv", k, v]);
    }
    Ok(Outcome::Applied)
}

/// The Linux path uses **two** mechanisms so the language server the IDE spawns
/// sees the proxy: a `~/.config/environment.d` drop-in makes it survive a reboot,
/// and `systemctl --user set-environment` sets it in the running user manager, so
/// a freshly-launched app inherits it **without a full re-login** - the user only
/// has to quit and reopen Antigravity. Lower-case aliases too, since Go reads
/// `HTTPS_PROXY` but other tooling reads `https_proxy`.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn apply_proxy(url: &str, _ca_path: &str) -> Result<Outcome, String> {
    use std::process::Command;
    let path = environment_d_path()?;
    let body = format!(
        "# Antigravity Unlocker — гейт-хосты через локальный прокси. Удалите файл,\n\
         # чтобы отключить.\n\
         HTTPS_PROXY={u}\nhttps_proxy={u}\nNO_PROXY={np}\nno_proxy={np}\n",
        u = url,
        np = NO_PROXY_VALUE,
    );
    if fs::read_to_string(&path).ok().as_deref() == Some(body.as_str()) {
        return Ok(Outcome::AlreadySet);
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    }
    fs::write(&path, &body).map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    // Immediate effect for newly-launched apps in this session (best-effort).
    for (k, v) in [
        (PROXY_ENV_VAR, url),
        ("https_proxy", url),
        (NO_PROXY_ENV_VAR, NO_PROXY_VALUE),
        ("no_proxy", NO_PROXY_VALUE),
    ] {
        Command::new("systemctl")
            .args(["--user", "set-environment", &format!("{}={}", k, v)])
            .status()
            .ok();
    }
    Ok(Outcome::Applied)
}

/// `~/.config/environment.d/ag-unlocker.conf`, honouring `XDG_CONFIG_HOME`.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn environment_d_path() -> Result<PathBuf, String> {
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.is_empty() => PathBuf::from(x),
        _ => PathBuf::from(std::env::var("HOME").map_err(|_| "HOME не задан".to_string())?)
            .join(".config"),
    };
    Ok(base.join("environment.d").join("ag-unlocker.conf"))
}

/// Removes them, but only while they still hold what we wrote - a user may have
/// a proxy of their own, and taking that away would be worse than any bug here.
#[cfg(target_os = "windows")]
pub fn remove_proxy(url: &str, ca_path: &str) -> Result<(), String> {
    // Every variable is judged and removed on its own, and nothing stops at the
    // first failure. A half-removed proxy is worse than either state: the value
    // left behind names a loopback port whose listener the revert has just
    // deleted, so every program that honours it loses the network. That was
    // reported from a real machine as "не работает выход в интернет".
    let mut trouble: Vec<String> = Vec::new();

    if current_env(PROXY_ENV_VAR).is_some_and(|v| is_our_proxy_value(&v, url)) {
        if let Err(e) = set_env(PROXY_ENV_VAR, None) {
            trouble.push(e);
        }
    }
    if current_env(NO_PROXY_ENV_VAR).as_deref() == Some(NO_PROXY_VALUE) {
        if let Err(e) = set_env(NO_PROXY_ENV_VAR, None) {
            trouble.push(e);
        }
    }
    if let Err(e) = clear_node_ca(ca_path) {
        trouble.push(e);
    }

    if trouble.is_empty() {
        Ok(())
    } else {
        Err(trouble.join("; "))
    }
}

/// macOS: unsets proxy environment variables using launchctl.
#[cfg(target_os = "macos")]
pub fn remove_proxy(_url: &str, _ca_path: &str) -> Result<(), String> {
    for k in [PROXY_ENV_VAR, "https_proxy", NO_PROXY_ENV_VAR, "no_proxy"] {
        crate::utils::run_macos_launchctl(&["unsetenv", k]);
    }
    Ok(())
}

/// Linux: delete the `environment.d` drop-in and unset the live session vars.
/// Only ever removes our own file, so a proxy the user set another way is left
/// alone (the file path is ours by construction).
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn remove_proxy(_url: &str, _ca_path: &str) -> Result<(), String> {
    use std::process::Command;
    if let Ok(path) = environment_d_path() {
        let _ = fs::remove_file(&path);
    }
    for k in [PROXY_ENV_VAR, "https_proxy", NO_PROXY_ENV_VAR, "no_proxy"] {
        Command::new("systemctl")
            .args(["--user", "unset-environment", k])
            .status()
            .ok();
    }
    Ok(())
}

/// A proxy the user set up themselves, which this tool must not get in front of.
///
/// Two places one can live. `HTTPS_PROXY` in the User or Machine environment is
/// what the language server (Go, `net/http`) actually reads; `http.proxy` in
/// Antigravity's own `settings.json` is what the Node side reads, and whether
/// the language server inherits it is **unverified** - so it is respected as a
/// statement of intent either way. A value naming our own listener is not
/// foreign; anything else is, and the answer says where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignProxy {
    pub value: String,
    pub found_in: String,
}

/// The user's own proxy, if they configured one anywhere the client would read.
#[cfg(target_os = "windows")]
pub fn foreign_proxy(ours: &str) -> Option<ForeignProxy> {
    for scope in ["User", "Machine"] {
        if let Some(value) = current_env_in(PROXY_ENV_VAR, scope) {
            if !is_our_proxy_value(&value, ours) {
                return Some(ForeignProxy {
                    value,
                    found_in: format!("переменная среды {} ({})", PROXY_ENV_VAR, scope),
                });
            }
        }
    }
    antigravity_proxy_setting(ours)
}

#[cfg(not(target_os = "windows"))]
pub fn foreign_proxy(ours: &str) -> Option<ForeignProxy> {
    antigravity_proxy_setting(ours)
}

/// `http.proxy` from the `settings.json` of every Antigravity product under the
/// user's profile. Product folders are matched by prefix, so a rebranded build
/// and the Desktop app - which ships no loose `product.json` for
/// `ide_settings_path` to read - are both covered.
fn antigravity_proxy_setting(ours: &str) -> Option<ForeignProxy> {
    let root = profile_root()?;
    let entries = fs::read_dir(&root).ok()?;
    for entry in entries.flatten().take(64) {
        let name = entry.file_name();
        if !name
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("antigravity")
        {
            continue;
        }
        let path = entry.path().join("User").join("settings.json");
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if let Some(value) = proxy_setting_in(&text) {
            if !is_our_proxy_value(&value, ours) {
                return Some(ForeignProxy {
                    value,
                    found_in: format!(
                        "http.proxy в {}",
                        crate::utils::mask_path(&path.to_string_lossy())
                    ),
                });
            }
        }
    }
    None
}

/// The `http.proxy` value in a settings file, if it is set to something.
///
/// Textual, like every other look at this file (I18), and line-wise so a
/// commented-out setting - JSONC allows them, and a user trying things out leaves
/// them - is not read as a live one. A URL contains `//` too, which is why the
/// test is "the line starts with a comment", not "the line contains one".
fn proxy_setting_in(text: &str) -> Option<String> {
    let re = Regex::new(r#""http\.proxy"\s*:\s*"([^"]*)""#).ok()?;
    text.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .find_map(|l| {
            re.captures(l)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().trim().to_string())
        })
        .filter(|v| !v.is_empty())
}

#[cfg(target_os = "windows")]
fn profile_root() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn profile_root() -> Option<PathBuf> {
    let home = if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            format!("/Users/{}", user)
        } else {
            std::env::var("HOME").ok()?
        }
    } else {
        std::env::var("HOME").ok()?
    };
    Some(PathBuf::from(home).join("Library").join("Application Support"))
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn profile_root() -> Option<PathBuf> {
    match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.is_empty() => Some(PathBuf::from(x)),
        _ => std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config")),
    }
}

/// Puts `HTTPS_PROXY` back on our listener when it has gone missing and nothing
/// of the user's has taken its place. The relay calls this at start: the
/// watchdog takes the variable off when the listener is dead for a while (so a
/// dead relay cannot take the machine's network with it, G20), and this is the
/// other half - the listener is back, so the route is too. A variable already
/// pointing here, or a proxy the user set themselves, is left exactly as it is.
#[cfg(target_os = "windows")]
pub fn ensure_proxy_env(ours: &str) -> Result<Outcome, String> {
    if current_env(PROXY_ENV_VAR).is_some_and(|v| is_our_proxy_value(&v, ours)) {
        return Ok(Outcome::AlreadySet);
    }
    if foreign_proxy(ours).is_some() {
        return Ok(Outcome::AlreadySet);
    }
    apply_proxy(ours, "")
}

/// Takes `HTTPS_PROXY` off only when it names our listener. `Ok(true)` when it
/// did and was removed, `Ok(false)` when there was nothing of ours to remove.
/// The watchdog's primitive: it must never touch a value the user set.
#[cfg(target_os = "windows")]
pub fn remove_proxy_if_ours(url: &str, ca_path: &str) -> Result<bool, String> {
    if !current_env(PROXY_ENV_VAR).is_some_and(|v| is_our_proxy_value(&v, url)) {
        return Ok(false);
    }
    remove_proxy(url, ca_path).map(|()| true)
}

#[cfg(not(target_os = "windows"))]
pub fn remove_proxy_if_ours(_url: &str, _ca_path: &str) -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "windows")]
fn current_env_in(name: &str, scope: &str) -> Option<String> {
    let out = powershell(&format!(
        "[Environment]::GetEnvironmentVariable('{}','{}')",
        name, scope
    ))?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// Whether an `HTTPS_PROXY` value is one this tool wrote.
///
/// Compared on the **address**, not on the exact string. A value that has been
/// through a settings dialog, a shell or another tool's rewrite can differ from
/// what we wrote by a trailing slash or the case of the scheme and still be
/// ours - and an exact comparison used to bail on that, leaving the variable
/// pointing at a port that no longer answers.
///
/// Safe because the address is loopback and a fixed port that only this tool
/// listens on: a proxy the user chose for themselves never names it. Their own
/// value is left alone, which matters more than removing ours.
fn is_our_proxy_value(value: &str, url: &str) -> bool {
    let strip = |s: &str| {
        s.trim()
            .trim_end_matches('/')
            .to_ascii_lowercase()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string()
    };
    let ours = strip(url);
    // Equality, not `contains`: a test caught `socks5://127.0.0.1:53129x`
    // passing a substring check, and `…:531290` would have too. Removing a
    // proxy that is not ours is the worse of the two failures here.
    !ours.is_empty() && strip(value) == ours
}

/// Drops `NODE_EXTRA_CA_CERTS` if it still holds `ca_path`, leaving a value the
/// user set themselves alone.
///
/// Separate from `remove_proxy` because an *upgrade* has to drop the old CA
/// without turning the proxy off: a machine coming from the carrier route
/// (<= 2.9.1_27) already has `HTTPS_PROXY` pointing here, so `apply_proxy`
/// returns `AlreadySet` and never reaches this. Leaving it behind would keep
/// every Node process on the machine trusting a CA nothing uses any more -
/// harmless today, and exactly the kind of leftover that is impossible to
/// explain a year from now.
pub fn clear_node_ca(ca_path: &str) -> Result<(), String> {
    if current_env(NODE_CA_ENV_VAR).as_deref() == Some(ca_path) {
        set_env(NODE_CA_ENV_VAR, None)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_env(name: &str, value: Option<&str>) -> Result<(), String> {
    let literal = match value {
        Some(v) => format!("'{}'", v),
        None => "$null".to_string(),
    };
    let script = format!(
        "[Environment]::SetEnvironmentVariable('{}',{},'User')",
        name, literal
    );
    powershell(&script).ok_or_else(|| format!("не удалось записать {}", name))?;
    Ok(())
}

/// Persisting a per-user environment variable for GUI-launched processes on
/// Linux has no single mechanism (systemd `environment.d`, `~/.profile`,
/// `~/.pam_environment` all reach different launchers), so it is deferred with
/// the proxy carrier that needs it. Removal is a trivial success - there is
/// nothing of ours in a persistent store to take out - while a request to *set*
/// one is refused honestly rather than silently doing nothing.
#[cfg(not(target_os = "windows"))]
fn set_env(name: &str, value: Option<&str>) -> Result<(), String> {
    match value {
        None => Ok(()),
        Some(_) => Err(format!(
            "{} на Linux пока не задаётся (нужен свой прокси-слой порта)",
            name
        )),
    }
}

#[cfg(target_os = "windows")]
fn current_env(name: &str) -> Option<String> {
    let out = powershell(&format!(
        "[Environment]::GetEnvironmentVariable('{}','User')",
        name
    ))?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// We manage no persistent user-env store on Linux yet, so there is nothing of
/// ours to read back. `None` makes every "remove if it is still ours" guard a
/// clean no-op.
#[cfg(not(target_os = "windows"))]
fn current_env(_name: &str) -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn current_cli_endpoint() -> Option<String> {
    let out = powershell(&format!(
        "[Environment]::GetEnvironmentVariable('{}','User')",
        CLI_ENV_VAR
    ))?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(not(target_os = "windows"))]
fn current_cli_endpoint() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The user's own `http.proxy` is read as intent: set means set, empty or
    /// commented out means nothing, and a URL's own `//` is not a comment.
    #[test]
    fn a_proxy_setting_is_found_only_when_it_is_live_and_non_empty() {
        assert_eq!(
            proxy_setting_in(r#"{ "http.proxy": "http://10.0.0.1:3128", "x": 1 }"#).as_deref(),
            Some("http://10.0.0.1:3128")
        );
        assert_eq!(
            proxy_setting_in("{\n    \"http.proxy\" : \"socks5://h:1080\"\n}").as_deref(),
            Some("socks5://h:1080")
        );
        assert_eq!(proxy_setting_in(r#"{ "http.proxy": "" }"#), None);
        assert_eq!(
            proxy_setting_in(r#"{ "http.proxyStrictSSL": "yes" }"#),
            None
        );
        assert_eq!(
            proxy_setting_in("{\n    // \"http.proxy\": \"http://old:3128\",\n    \"a\": 1\n}"),
            None,
            "a commented-out setting is not a setting"
        );
        assert_eq!(proxy_setting_in("{}"), None);
    }

    /// Our own listener in the settings file is not a foreign proxy.
    #[test]
    fn our_own_listener_in_settings_is_not_foreign() {
        let ours = "http://127.0.0.1:53129";
        let value = proxy_setting_in(r#"{ "http.proxy": "http://127.0.0.1:53129/" }"#).unwrap();
        assert!(is_our_proxy_value(&value, ours));
        let value = proxy_setting_in(r#"{ "http.proxy": "http://127.0.0.1:8080" }"#).unwrap();
        assert!(!is_our_proxy_value(&value, ours));
    }

    /// The bug users hit: a revert that left `HTTPS_PROXY` naming a port it had
    /// just deleted, so nothing on the machine could reach the network. Part of
    /// it was an exact string comparison - a value that had been through a
    /// settings dialog or another tool came back with a trailing slash or a
    /// different case and was not recognised as ours.
    #[test]
    fn our_proxy_value_is_recognised_however_it_was_written_back() {
        let url = "http://127.0.0.1:53129";
        for shape in [
            "http://127.0.0.1:53129",
            "http://127.0.0.1:53129/",
            "HTTP://127.0.0.1:53129",
            "  http://127.0.0.1:53129  ",
            "127.0.0.1:53129",
            "https://127.0.0.1:53129",
        ] {
            assert!(
                is_our_proxy_value(shape, url),
                "should be ours: {:?}",
                shape
            );
        }
    }

    /// The other half, and the more important one: a proxy the user chose for
    /// themselves must survive our revert untouched. Removing someone else's
    /// proxy is a worse failure than leaving ours behind.
    #[test]
    fn a_proxy_the_user_chose_is_never_removed() {
        let url = "http://127.0.0.1:53129";
        for theirs in [
            "http://127.0.0.1:1371",
            "http://proxy.example.com:8080",
            "http://10.0.0.1:53129",
            "socks5://127.0.0.1:53129x",
            "",
        ] {
            assert!(
                !is_our_proxy_value(theirs, url),
                "must be left alone: {:?}",
                theirs
            );
        }
    }

    const REAL: &str = "{\n    \"workbench.colorTheme\": \"Solarized Dark\",\n    \"securecoder.enabled\": true\n}";

    #[test]
    fn the_key_is_added_and_the_rest_kept_byte_for_byte() {
        let out = upsert_key(REAL, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert!(
            out.contains("\"jetski.cloudCodeUrl\": \"https://daily-cloudcode-pa.googleapis.com\"")
        );
        // Every line the user had must survive, unchanged apart from the comma
        // that now separates it from ours.
        assert!(out.contains("\"workbench.colorTheme\": \"Solarized Dark\""));
        assert!(out.contains("\"securecoder.enabled\": true"));
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
    }

    #[test]
    fn writing_twice_changes_nothing_the_second_time() {
        let once = upsert_key(REAL, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        let twice = upsert_key(&once, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert_eq!(once, twice);
    }

    /// A value the user (or an older build) left behind must be corrected, not
    /// duplicated - two entries for one key is invalid JSON.
    #[test]
    fn a_stale_value_is_replaced_not_duplicated() {
        let stale = REAL.replace(
            "\"securecoder.enabled\": true",
            "\"securecoder.enabled\": true,\n    \"jetski.cloudCodeUrl\": \"https://cloudcode-pa.googleapis.com\"",
        );
        let out = upsert_key(&stale, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert_eq!(out.matches(IDE_SETTING).count(), 1);
        assert!(out.contains(DAILY_ENDPOINT));
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
    }

    #[test]
    fn an_empty_or_missing_file_becomes_a_valid_object() {
        for text in ["", "   \n"] {
            let out = upsert_key(text, IDE_SETTING, DAILY_ENDPOINT).expect("created");
            let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
            assert_eq!(parsed[IDE_SETTING], DAILY_ENDPOINT);
        }
    }

    #[test]
    fn an_empty_object_gets_no_stray_comma() {
        let out = upsert_key("{}", IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
        assert!(!out.contains("{,"));
    }

    /// The user's own trailing comma is legal JSONC and must not produce two.
    #[test]
    fn a_trailing_comma_is_not_doubled() {
        let out =
            upsert_key("{\n    \"a\": \"b\",\n}", IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert!(!out.contains(",,"), "{}", out);
    }

    #[test]
    fn a_file_without_a_closing_brace_is_refused() {
        assert!(upsert_key("not json at all", IDE_SETTING, DAILY_ENDPOINT).is_err());
    }

    #[test]
    fn removal_restores_valid_json_without_our_key() {
        for original in [REAL, "{}", "{\n    \"a\": \"b\"\n}"] {
            let with = upsert_key(original, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
            let without = remove_key(&with, IDE_SETTING).expect("removed");
            assert!(!without.contains(IDE_SETTING), "{}", without);
            assert!(
                serde_json::from_str::<serde_json::Value>(&without).is_ok(),
                "{}",
                without
            );
        }
    }

    /// Removing ours must not take the user's settings with it.
    #[test]
    fn removal_keeps_everything_else() {
        let with = upsert_key(REAL, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        let without = remove_key(&with, IDE_SETTING).expect("removed");
        let parsed: serde_json::Value = serde_json::from_str(&without).expect("valid json");
        assert_eq!(parsed["workbench.colorTheme"], "Solarized Dark");
        assert_eq!(parsed["securecoder.enabled"], true);
    }

    #[test]
    fn removing_a_key_that_is_not_there_is_a_no_op() {
        assert_eq!(remove_key(REAL, IDE_SETTING).expect("no-op"), REAL);
    }

    /// The endpoint has to be the host that is actually still substituted; the
    /// production one is exactly what stopped working.
    #[test]
    fn the_endpoint_is_the_daily_host() {
        assert!(DAILY_ENDPOINT.starts_with("https://daily-cloudcode-pa."));
        assert!(!DAILY_ENDPOINT.contains("sandbox"));
    }

    /// Against the real install. It used to also assert that the build still
    /// reads `jetski.cloudCodeUrl`; nothing writes that key since 2.11.0, so the
    /// question left is the one `remove_ide` depends on - does the path resolve
    /// to the folder the IDE actually reads, so an override left by an earlier
    /// build is found and taken out.
    #[test]
    #[ignore = "needs a real Antigravity IDE install; run with --ignored"]
    fn finds_the_real_ide_settings_file() {
        let install = PathBuf::from(std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA"))
            .join("Programs")
            .join("Antigravity IDE");
        if !install.exists() {
            println!("no IDE install at {}", install.display());
            return;
        }
        let path = ide_settings_path(&install).expect("settings path");
        println!("settings: {} (exists: {})", path.display(), path.exists());
        assert!(
            path.ends_with("User\\settings.json"),
            "unexpected shape: {}",
            path.display()
        );
    }
}
