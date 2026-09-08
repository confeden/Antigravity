use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

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
    let product = install.join("resources").join("app").join("product.json");
    let text = fs::read_to_string(product).ok()?;
    let name = Regex::new(r#""nameShort"\s*:\s*"([^"]+)""#)
        .ok()?
        .captures(&text)?
        .get(1)?
        .as_str()
        .to_string();
    // The user-config root is `%APPDATA%` on Windows and `~/.config` on Linux -
    // the same VS Code layout underneath (`<root>/<nameShort>/User/settings.json`).
    #[cfg(target_os = "windows")]
    let root = PathBuf::from(std::env::var("APPDATA").ok()?);
    #[cfg(not(target_os = "windows"))]
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
    set_env(CLI_ENV_VAR, None)
}

/// The variable that points the language server at the local gate proxy.
///
/// **Not** `HTTPS_PROXY`. It is a private name that only the patched binaries
/// read, because `patch_binary` renames the lower-case literal in their
/// `httpproxy.getEnvAny("HTTPS_PROXY", "https_proxy")` to exactly this. The full
/// argument is on `patch_binary::PROXY_VAR_NEW`; the short version is that the
/// variable has to be user-wide (nothing spawns the language server for us) and
/// a user-wide `HTTPS_PROXY` put every program on the machine through
/// `127.0.0.1:53129`. Same reach for the language server, no reach at all for
/// anything else.
pub const PROXY_ENV_VAR: &str = crate::patch_binary::PROXY_VAR_NEW;

/// What builds up to `2.11.0_4` wrote into the User environment, and what every
/// machine upgrading from one still carries. Removed on sight - but only when
/// the value is one of ours (I45) - by `remove_legacy_proxy_env`.
///
/// `HTTPS_PROXY` doubles as the name a *user's own* proxy lives under, which is
/// why removal is value-scoped and why `foreign_proxy` still reads it.
pub const LEGACY_PROXY_ENV_VAR: &str = "HTTPS_PROXY";
pub const NO_PROXY_ENV_VAR: &str = "NO_PROXY";
/// Node keeps its own bundled trust store and does not read the Windows one, so
/// installing the CA as a system root is not enough: Antigravity's extension
/// host is Node, it calls the gate host itself, and it answered `self signed
/// certificate in certificate chain` until this was set. Points at the same
/// per-machine CA that is already in the user's root store, so it widens nothing
/// that was not already trusted.
pub const NODE_CA_ENV_VAR: &str = "NODE_EXTRA_CA_CERTS";
/// The companion `NO_PROXY` those builds wrote, kept only so the value can be
/// recognised as ours and taken back off.
///
/// Nothing writes it any more, and nothing needs to: `httpproxy.useProxy`
/// bypasses `localhost` and every loopback address unconditionally, in the
/// library, so the one thing this value protected - the language server's own
/// gRPC on `127.0.0.1` - was never at risk. It existed for the Node side, which
/// only ever saw it because the variable was user-wide.
const NO_PROXY_VALUE: &str = "127.0.0.1,localhost,::1";

/// Points the patched language server at the local proxy.
///
/// Still a user-wide variable - the language server is launched by the IDE, not
/// by us, so there is no parent process to inject an environment into, and
/// Windows has no per-image environment. What changed in `2.11.0_5` is the
/// *name*: `PROXY_ENV_VAR` is read by nothing but the binaries this tool has
/// patched, so the breadth that used to be the cost of the design is gone. A
/// leftover from the old scheme is taken off in the same step, since a machine
/// upgrading passes through here and through no undo path.
#[cfg(target_os = "windows")]
pub fn apply_proxy(url: &str, ca_path: &str) -> Result<Outcome, String> {
    let migrated = remove_legacy_proxy_env(url).unwrap_or(false);
    if current_env(PROXY_ENV_VAR).as_deref() == Some(url) {
        return Ok(if migrated {
            Outcome::Applied
        } else {
            Outcome::AlreadySet
        });
    }
    set_env(PROXY_ENV_VAR, Some(url))?;
    // The relay route terminates no TLS and installs no CA, so it needs no
    // `NODE_EXTRA_CA_CERTS`; only the legacy carrier route passes a real path.
    if !ca_path.is_empty() {
        set_env(NODE_CA_ENV_VAR, Some(ca_path))?;
    }
    Ok(Outcome::Applied)
}

/// Takes the user-wide `HTTPS_PROXY`/`NO_PROXY` of builds up to `2.11.0_4` back
/// off, and only when the values are the ones this tool wrote.
///
/// This is the migration that has to happen on *every* path a machine can take
/// out of an old build: menu 1 (via `apply_proxy`), the relay's
/// `ensure_proxy_env`, and both undo paths. Skipping it would leave the exact
/// state the owner asked to be rid of - and, worse, one naming a port that the
/// new scheme still binds, so it would keep silently working and nobody would
/// notice the whole machine was still routed through loopback.
///
/// `Ok(true)` when something came off. A value that is not ours is never
/// touched: `HTTPS_PROXY` is also where a user's own proxy lives (I45).
#[cfg(target_os = "windows")]
pub fn remove_legacy_proxy_env(url: &str) -> Result<bool, String> {
    let (drop_proxy, drop_no_proxy) = legacy_removals(
        current_env(LEGACY_PROXY_ENV_VAR).as_deref(),
        current_env(NO_PROXY_ENV_VAR).as_deref(),
        url,
    );
    let mut removed = false;
    let mut trouble: Vec<String> = Vec::new();

    if drop_proxy {
        match set_env(LEGACY_PROXY_ENV_VAR, None) {
            Ok(()) => removed = true,
            Err(e) => trouble.push(e),
        }
    }
    if drop_no_proxy {
        match set_env(NO_PROXY_ENV_VAR, None) {
            Ok(()) => removed = true,
            Err(e) => trouble.push(e),
        }
    }

    if trouble.is_empty() {
        Ok(removed)
    } else {
        Err(trouble.join("; "))
    }
}

/// Which of the two legacy variables this tool may take off, given what they
/// currently hold. Pure, so the one rule that can destroy a user's configuration
/// is testable without an environment.
///
/// `NO_PROXY` goes **only alongside** ours, and that condition is the whole
/// safety of this step. It carries no address to recognise, so the only evidence
/// it is ours is the exact value - and `127.0.0.1,localhost,::1` is an entirely
/// ordinary thing for someone to set for themselves. Since `_5` this runs on the
/// *patch* path and at every relay start, not only on an undo, so an
/// unconditional match would delete that user's variable, and delete it again
/// after every reboot they re-set it. Our `HTTPS_PROXY` sitting beside it is the
/// evidence that the pair was written by an older build of this tool.
fn legacy_removals(https: Option<&str>, no_proxy: Option<&str>, url: &str) -> (bool, bool) {
    let drop_proxy = https.is_some_and(|v| is_our_proxy_value(v, url));
    (drop_proxy, drop_proxy && no_proxy == Some(NO_PROXY_VALUE))
}

/// Linux keeps the persistent half in the drop-in file, which `apply_proxy`
/// rewrites in place - so upgrading drops the old names from the next session by
/// itself. What survives is the *running* user manager, which an older build
/// filled with `systemctl --user set-environment`, and which would otherwise keep
/// the whole session pointed at loopback until the user logs out.
///
/// Value-scoped, unlike the blanket unset `remove_proxy` does: this runs on the
/// patch path, where a `https_proxy` the user exported for themselves is none of
/// our business.
#[cfg(not(target_os = "windows"))]
pub fn remove_legacy_proxy_env(url: &str) -> Result<bool, String> {
    use std::process::Command;
    let Ok(out) = Command::new("systemctl")
        .args(["--user", "show-environment"])
        .output()
    else {
        return Ok(false);
    };
    let env = String::from_utf8_lossy(&out.stdout);
    let mut removed = false;
    for name in [
        LEGACY_PROXY_ENV_VAR,
        "https_proxy",
        NO_PROXY_ENV_VAR,
        "no_proxy",
    ] {
        let prefix = format!("{}=", name);
        let Some(value) = env
            .lines()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .map(str::trim)
        else {
            continue;
        };
        // `NO_PROXY` only once one of ours has already been recognised, for the
        // reason spelled out in the Windows arm: the value is a plausible thing
        // for a user to have set. The proxy names come first in the list, so
        // `removed` is already decided by the time it is reached.
        let ours = if name.eq_ignore_ascii_case(NO_PROXY_ENV_VAR) {
            removed && value == NO_PROXY_VALUE
        } else {
            is_our_proxy_value(value, url)
        };
        if !ours {
            continue;
        }
        // `.success()`, not `.is_ok()`: the latter is true for any process that
        // merely started, so a failed unset would be reported as a removal.
        if Command::new("systemctl")
            .args(["--user", "unset-environment", name])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            removed = true;
        }
    }
    Ok(removed)
}

/// The Linux path uses **two** mechanisms so the language server the IDE spawns
/// sees the proxy: a `~/.config/environment.d` drop-in makes it survive a reboot,
/// and `systemctl --user set-environment` sets it in the running user manager, so
/// a freshly-launched app inherits it **without a full re-login** - the user only
/// has to quit and reopen Antigravity.
///
/// Both carry `PROXY_ENV_VAR` and nothing else now. The drop-in used to export
/// `HTTPS_PROXY`/`https_proxy`/`NO_PROXY`/`no_proxy`, which is session-wide on
/// Linux exactly as the User environment is machine-wide on Windows - every
/// shell, every `curl`, every package manager through `127.0.0.1:53129`. The
/// private name reaches the patched binaries and nothing else; rewriting the
/// file in place is also what retires the old names on an upgrade.
#[cfg(not(target_os = "windows"))]
pub fn apply_proxy(url: &str, _ca_path: &str) -> Result<Outcome, String> {
    use std::process::Command;
    let path = environment_d_path()?;
    let body = format!(
        "# Antigravity Unlocker — гейт-хосты через локальный прокси. Переменную\n\
         # читает только пропатченный language server. Удалите файл, чтобы\n\
         # отключить.\n\
         {k}={u}\n",
        k = PROXY_ENV_VAR,
        u = url,
    );
    let already = fs::read_to_string(&path).ok().as_deref() == Some(body.as_str());
    let migrated = remove_legacy_proxy_env(url).unwrap_or(false);
    if already && !migrated {
        return Ok(Outcome::AlreadySet);
    }
    if !already {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
        }
        fs::write(&path, &body).map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    }
    // Immediate effect for newly-launched apps in this session (best-effort).
    Command::new("systemctl")
        .args([
            "--user",
            "set-environment",
            &format!("{}={}", PROXY_ENV_VAR, url),
        ])
        .status()
        .ok();
    Ok(Outcome::Applied)
}

/// `~/.config/environment.d/ag-unlocker.conf`, honouring `XDG_CONFIG_HOME`.
#[cfg(not(target_os = "windows"))]
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

    // Unconditional, unlike everything else here: `PROXY_ENV_VAR` is a name only
    // this tool ever writes, so any value under it is ours whatever port it
    // names. That matters for the day the listener moves off 53129 (P26) - a
    // value-scoped removal would leave the old one behind forever.
    if current_env(PROXY_ENV_VAR).is_some() {
        if let Err(e) = set_env(PROXY_ENV_VAR, None) {
            trouble.push(e);
        }
    }
    // The user-wide variables of builds up to `2.11.0_4`, value-scoped because
    // `HTTPS_PROXY` is also where a user's own proxy lives.
    if let Err(e) = remove_legacy_proxy_env(url) {
        trouble.push(e);
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

/// Linux: delete the `environment.d` drop-in and unset the live session vars.
/// Only ever removes our own file (the path is ours by construction) and our own
/// variable; the standard names an older build exported are unset by value, so a
/// proxy the user set another way survives the revert.
#[cfg(not(target_os = "windows"))]
pub fn remove_proxy(url: &str, _ca_path: &str) -> Result<(), String> {
    use std::process::Command;
    if let Ok(path) = environment_d_path() {
        let _ = fs::remove_file(&path);
    }
    Command::new("systemctl")
        .args(["--user", "unset-environment", PROXY_ENV_VAR])
        .status()
        .ok();
    remove_legacy_proxy_env(url).ok();
    Ok(())
}

/// A proxy the user set up themselves, which this tool must not get in front of.
///
/// Two places one can live. `HTTPS_PROXY` in the User or Machine environment is
/// still what the patched language server reads *first* - the rename left that
/// literal alone precisely so this keeps working - and `http.proxy` in
/// Antigravity's own `settings.json` is what the Node side reads, with the
/// language server's inheritance of it **unverified** (P25), so it is respected
/// as a statement of intent either way. A value naming our own listener is not
/// foreign (a leftover from a build that wrote `HTTPS_PROXY` itself); anything
/// else is, and the answer says where it was found.
///
/// Since `2.11.0_5` this is the **only** thing keeping a user's own proxy in
/// front of ours. The first draft assumed lookup order would do it - `HTTPS_PROXY`
/// is the first argument of `getEnvAny` - and the probe measured the opposite:
/// with both variables set the patched server takes ours
/// (`patch_binary::PROXY_VAR_NEW`). So every caller that could write ours has to
/// ask this first and remove ours when the answer is `Some`, and every one does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignProxy {
    pub value: String,
    pub found_in: String,
}

/// The user's own proxy, if they configured one anywhere the client would read.
#[cfg(target_os = "windows")]
pub fn foreign_proxy(ours: &str) -> Option<ForeignProxy> {
    for scope in ["User", "Machine"] {
        if let Some(value) = current_env_in(LEGACY_PROXY_ENV_VAR, scope) {
            if !is_our_proxy_value(&value, ours) {
                return Some(ForeignProxy {
                    value,
                    found_in: format!("переменная среды {} ({})", LEGACY_PROXY_ENV_VAR, scope),
                });
            }
        }
    }
    antigravity_proxy_setting(ours)
}

/// Linux has no User environment to read, so the same question is asked of the
/// two places a session proxy can actually live: this process's own environment
/// (which is the user's login session, since the unlocker is launched from it)
/// and the systemd user manager, which is where a drop-in or an earlier build's
/// `set-environment` ends up.
///
/// This used to be `antigravity_proxy_setting` alone - and until `_5` that was
/// merely incomplete, because the old drop-in wrote `HTTPS_PROXY` too and which
/// of the two won depended on how the app was launched. Now that ours outranks
/// theirs inside the patched server (S42), silence here would mean a user behind
/// a corporate proxy is routed into a loopback port that cannot reach anything -
/// including their sign-in - with nothing on screen to say why.
#[cfg(not(target_os = "windows"))]
pub fn foreign_proxy(ours: &str) -> Option<ForeignProxy> {
    for name in [LEGACY_PROXY_ENV_VAR, "https_proxy"] {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim().to_string();
            if !value.is_empty() && !is_our_proxy_value(&value, ours) {
                return Some(ForeignProxy {
                    value,
                    found_in: format!("переменная среды {}", name),
                });
            }
        }
    }
    if let Some(found) = session_manager_proxy(ours) {
        return Some(found);
    }
    antigravity_proxy_setting(ours)
}

/// `HTTPS_PROXY`/`https_proxy` as the systemd user manager holds it - what a
/// `environment.d` drop-in or a `systemctl --user set-environment` leaves behind,
/// and what every app launched from the desktop inherits.
#[cfg(not(target_os = "windows"))]
fn session_manager_proxy(ours: &str) -> Option<ForeignProxy> {
    use std::process::Command;
    let out = Command::new("systemctl")
        .args(["--user", "show-environment"])
        .output()
        .ok()?;
    let env = String::from_utf8_lossy(&out.stdout);
    for name in [LEGACY_PROXY_ENV_VAR, "https_proxy"] {
        let prefix = format!("{}=", name);
        let Some(value) = env
            .lines()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .map(str::trim)
        else {
            continue;
        };
        if !value.is_empty() && !is_our_proxy_value(value, ours) {
            return Some(ForeignProxy {
                value: value.to_string(),
                found_in: format!("{} в сессии systemd --user", name),
            });
        }
    }
    None
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

#[cfg(not(target_os = "windows"))]
fn profile_root() -> Option<PathBuf> {
    match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.is_empty() => Some(PathBuf::from(x)),
        _ => std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config")),
    }
}

/// Puts the proxy variable back on our listener when it has gone missing and
/// nothing of the user's has taken its place. The relay calls this at start: the
/// watchdog takes the variable off when the listener is dead for a while, and
/// this is the other half - the listener is back, so the route is too. A variable
/// already pointing here, or a proxy the user set themselves, is left exactly as
/// it is.
///
/// It also runs the legacy migration on a machine that never opens menu 1 again:
/// `apply_proxy` does that, and this is the only other caller of it. Without that
/// an upgraded machine that just reboots would keep its user-wide `HTTPS_PROXY`
/// indefinitely.
///
/// **The foreign check comes first, and that order is load bearing.** The patched
/// server prefers our variable over the user's `HTTPS_PROXY` when both are set
/// (measured - see `patch_binary::PROXY_VAR_NEW`), so a user who configures a
/// proxy *after* being patched would silently keep going through ours. Menu 1
/// catches that only if they run it again; this runs at every relay start, which
/// is every boot, so at worst they are back on their own proxy after a restart.
#[cfg(target_os = "windows")]
pub fn ensure_proxy_env(ours: &str) -> Result<Outcome, String> {
    if foreign_proxy(ours).is_some() {
        // Theirs, not ours - and ours would win over it, so it has to go.
        remove_proxy(ours, "")?;
        return Ok(Outcome::AlreadySet);
    }
    if current_env(PROXY_ENV_VAR).is_some_and(|v| is_our_proxy_value(&v, ours)) {
        // Still ours and still current - but an old user-wide pair may be sitting
        // beside it, and this path is the one a rebooted machine takes.
        return match remove_legacy_proxy_env(ours) {
            Ok(true) => Ok(Outcome::Applied),
            _ => Ok(Outcome::AlreadySet),
        };
    }
    apply_proxy(ours, "")
}

/// Takes our proxy variable off. `Ok(true)` when there was one and it was
/// removed, `Ok(false)` when there was nothing of ours.
///
/// The watchdog's primitive: it must never touch a value the user set. That is
/// now true by the *name* - `PROXY_ENV_VAR` is written by nothing else - where it
/// used to rest on matching the value under a shared name.
#[cfg(target_os = "windows")]
pub fn remove_proxy_if_ours(url: &str, ca_path: &str) -> Result<bool, String> {
    if current_env(PROXY_ENV_VAR).is_none() {
        // Nothing of ours under our own name; a legacy pair may still be there.
        return remove_legacy_proxy_env(url);
    }
    remove_proxy(url, ca_path).map(|()| true)
}

#[cfg(not(target_os = "windows"))]
pub fn remove_proxy_if_ours(_url: &str, _ca_path: &str) -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "windows")]
fn current_env_in(name: &str, scope: &str) -> Option<String> {
    win_env::get_env(name, scope)
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
mod win_env {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::Registry::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn get_env(name: &str, scope: &str) -> Option<String> {
        unsafe {
            let is_machine = scope.eq_ignore_ascii_case("machine");
            let root = if is_machine {
                HKEY_LOCAL_MACHINE
            } else {
                HKEY_CURRENT_USER
            };
            let subkey = if is_machine {
                "System\\CurrentControlSet\\Control\\Session Manager\\Environment"
            } else {
                "Environment"
            };

            let mut hkey: HKEY = 0;
            if RegOpenKeyExW(root, to_wide(subkey).as_ptr(), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
                return None;
            }

            let wide_name = to_wide(name);
            let mut val_type: u32 = 0;
            let mut size: u32 = 0;

            let status = RegQueryValueExW(
                hkey,
                wide_name.as_ptr(),
                ptr::null_mut(),
                &mut val_type,
                ptr::null_mut(),
                &mut size,
            );
            if status != ERROR_SUCCESS || size == 0 {
                RegCloseKey(hkey);
                return None;
            }

            let num_u16 = (size as usize + 1) / 2;
            let mut buffer: Vec<u16> = vec![0; num_u16];
            let status = RegQueryValueExW(
                hkey,
                wide_name.as_ptr(),
                ptr::null_mut(),
                &mut val_type,
                buffer.as_mut_ptr() as *mut u8,
                &mut size,
            );
            RegCloseKey(hkey);

            if status != ERROR_SUCCESS {
                return None;
            }

            if val_type != REG_SZ && val_type != REG_EXPAND_SZ {
                return None;
            }

            let len = (size as usize) / 2;
            let slice = &buffer[..len];
            let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
            let val = String::from_utf16_lossy(&slice[..end]).trim().to_string();
            (!val.is_empty()).then_some(val)
        }
    }

    pub fn set_env(name: &str, value: Option<&str>) -> Result<(), String> {
        unsafe {
            let subkey = to_wide("Environment");
            let wide_name = to_wide(name);
            let mut hkey: HKEY = 0;

            match value {
                Some(val) => {
                    let status = RegCreateKeyW(
                        HKEY_CURRENT_USER,
                        subkey.as_ptr(),
                        &mut hkey,
                    );
                    if status != ERROR_SUCCESS {
                        return Err(format!("не удалось открыть HKCU\\Environment: {}", status));
                    }

                    let wide_val = to_wide(val);
                    let byte_len = (wide_val.len() * 2) as u32;
                    let set_status = RegSetValueExW(
                        hkey,
                        wide_name.as_ptr(),
                        0,
                        REG_SZ,
                        wide_val.as_ptr() as *const u8,
                        byte_len,
                    );
                    RegCloseKey(hkey);

                    if set_status != ERROR_SUCCESS {
                        return Err(format!("не удалось записать {}: {}", name, set_status));
                    }
                }
                None => {
                    let status = RegOpenKeyExW(
                        HKEY_CURRENT_USER,
                        subkey.as_ptr(),
                        0,
                        KEY_SET_VALUE,
                        &mut hkey,
                    );
                    if status == ERROR_SUCCESS {
                        let del_status = RegDeleteValueW(hkey, wide_name.as_ptr());
                        RegCloseKey(hkey);
                        if del_status != ERROR_SUCCESS && del_status != ERROR_FILE_NOT_FOUND {
                            return Err(format!("не удалось удалить {}: {}", name, del_status));
                        }
                    }
                }
            }

            broadcast_setting_change();
            Ok(())
        }
    }

    pub fn broadcast_setting_change() {
        unsafe {
            let env_str = to_wide("Environment");
            let mut result: usize = 0;
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                env_str.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                5000,
                &mut result,
            );
        }
    }
}

#[cfg(target_os = "windows")]
fn set_env(name: &str, value: Option<&str>) -> Result<(), String> {
    win_env::set_env(name, value)
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
    win_env::get_env(name, "User")
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
    current_env(CLI_ENV_VAR)
}

#[cfg(not(target_os = "windows"))]
fn current_cli_endpoint() -> Option<String> {
    None
}

/// The value of our proxy variable as the user environment has it right now.
/// Read-only; `None` when it is not set.
#[allow(dead_code)]
pub fn proxy_env_value() -> Option<String> {
    current_env(PROXY_ENV_VAR)
}

/// True when the variable is set AND names our own local listener rather than
/// something the user configured themselves.
#[allow(dead_code)]
pub fn proxy_env_is_ours() -> bool {
    let ours = crate::proxy::proxy_url();
    proxy_env_value().is_some_and(|v| is_our_proxy_value(&v, &ours))
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

    /// `NO_PROXY` is the one variable this tool can delete without being able to
    /// recognise it: the value is all there is, and `127.0.0.1,localhost,::1` is
    /// something a user may well have set. Since `_5` the migration runs on the
    /// patch path and at every relay start, so an unconditional match would take
    /// it off a machine that had never run this tool - and again after every
    /// reboot they put it back. It goes only in company.
    #[test]
    fn no_proxy_is_only_removed_beside_a_proxy_value_of_ours() {
        let url = "http://127.0.0.1:53129";
        let ours = Some("http://127.0.0.1:53129");
        let theirs = Some("http://corp.example:3128");
        let np = Some(NO_PROXY_VALUE);

        // The pair an older build wrote: both go.
        assert_eq!(legacy_removals(ours, np, url), (true, true));
        // Never used this tool, but happens to have that NO_PROXY: nothing goes.
        assert_eq!(legacy_removals(None, np, url), (false, false));
        // Their own proxy plus that NO_PROXY: still nothing.
        assert_eq!(legacy_removals(theirs, np, url), (false, false));
        // Ours, but a NO_PROXY they changed: only ours goes.
        assert_eq!(
            legacy_removals(ours, Some("127.0.0.1,corp.example"), url),
            (true, false)
        );
        // Ours alone.
        assert_eq!(legacy_removals(ours, None, url), (true, false));
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

    #[test]
    #[cfg(target_os = "windows")]
    fn win_registry_env_round_trip() {
        let test_var = "AG_UNLOCKER_TEST_VAR_R2";
        let test_val = "http://127.0.0.1:9999";
        // Clean up beforehand
        let _ = set_env(test_var, None);
        assert_eq!(current_env(test_var), None);

        // Set value
        set_env(test_var, Some(test_val)).expect("set_env succeeds");
        assert_eq!(current_env(test_var).as_deref(), Some(test_val));

        // Delete value
        set_env(test_var, None).expect("delete succeeds");
        assert_eq!(current_env(test_var), None);
    }

    #[test]
    fn proxy_env_queries_run_without_panic() {
        let _ = proxy_env_value();
        let _ = proxy_env_is_ours();
    }
}
