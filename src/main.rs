// The Windows build is the shipping platform and is fully linted. The Linux port
// is partial (phase 1: the client patch; the NRPT/relay/systemd layer is stubbed,
// P7 phase 5), so a large Windows-only surface is legitimately dead code there.
// Silence exactly that noise on non-Windows targets, and only there, so a real
// dead symbol on Windows is still caught.
#![cfg_attr(
    not(target_os = "windows"),
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

mod asar;
mod auth;
mod background;
mod canary;
#[cfg(target_os = "windows")]
mod console_style;
mod dns;
mod dns_client;
mod dns_forwarder;
mod doh;
mod egress;
mod endpoint;
mod health;
mod hosts_pin;
mod ls_log;
mod patch_binary;
mod patch_ide;
mod proxy;
mod resolvers;
mod routes;
mod upstream;
mod utils;
mod watchdog;

use asar::extract_asar;
use auth::login_screen;
use dns::{is_nrpt_applied, refresh_pinned_hosts, remove_dns_nrpt, setup_dns_nrpt};
use patch_binary::{kill_affected_processes, patch_all_binaries, unpatch_all_binaries};
use patch_ide::{is_new_desktop_architecture, patch_desktop, patch_extension_js, patch_ide};
use utils::{clear_screen, is_admin, link, mask_path, open_url, print_results, prompt, short_path};

// Title shown at the top of the main menu.
const APP_TITLE: &str = "Antigravity Unlocker 2";
// Version is read from Cargo.toml at compile time (build_rust.py keeps
// Cargo.toml in sync). Bumping the version here also rotates the license keys,
// since keys are salted with this value in auth.rs.
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

const TELEGRAM_URL: &str = "https://t.me/nova_txt";
const DONATE_URL: &str = "https://nova-app.eu/donate";

fn clean_input_path(input: &str) -> String {
    let mut s = input.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        if s.len() >= 2 {
            s = &s[1..s.len() - 1];
        }
    }
    s = s.trim();
    s = s.trim_matches('"').trim_matches('\'').trim();
    s.to_string()
}

fn is_install_root(path: &Path) -> bool {
    if !path.exists() || !path.is_dir() {
        return false;
    }

    let path_str = path.to_string_lossy().to_lowercase();
    if path_str == "c:\\windows"
        || path_str.starts_with("c:\\windows\\")
        || path_str.contains("\\windows\\system32")
        || path_str.contains("\\windows\\syswow64")
    {
        return false;
    }

    let resources = crate::utils::resources_dir(path);
    if resources.exists() && resources.is_dir() {
        if resources.join("app.asar").exists()
            || resources.join("app").exists()
            || resources.join("bin").exists()
        {
            return true;
        }
    }
    // macOS .app bundle checks.
    #[cfg(target_os = "macos")]
    {
        if path.extension().map_or(false, |ext| ext == "app") {
            let contents = path.join("Contents");
            if contents.exists()
                && (contents.join("MacOS").exists() || contents.join("Resources").exists())
            {
                return true;
            }
        }
        if path.join("Contents").join("MacOS").join("Antigravity").is_file()
            || path.join("Contents").join("MacOS").join("Antigravity IDE").is_file()
            || path.join("Contents").join("MacOS").join("Electron").is_file()
        {
            return true;
        }
    }
    // `is_file`, not `exists`: `%LOCALAPPDATA%\agy` is the CLI's *directory*, and
    // an `exists()` check there made the parent-walk treat `%LOCALAPPDATA%` itself
    // as an install root. A launcher/CLI is always a file.
    if path.join("agy.exe").is_file() || path.join("agy").is_file() {
        return true;
    }
    if path.join("Antigravity.exe").is_file()
        || path.join("Antigravity IDE.exe").is_file()
        || path.join("antigravity.exe").is_file()
    {
        return true;
    }
    // Linux/macOS launcher names (no extension).
    #[cfg(not(target_os = "windows"))]
    if path.join("antigravity").is_file()
        || path.join("Antigravity").is_file()
        || path.join("antigravity-ide").is_file()
    {
        return true;
    }
    if path.join("out").join("main.js").exists() || path.join("dist").join("main.js").exists() {
        return true;
    }
    false
}

pub fn resolve_install_root(raw: &Path) -> Option<PathBuf> {
    let mut p = raw.to_path_buf();

    if p.is_file() {
        if let Some(parent) = p.parent() {
            p = parent.to_path_buf();
        }
    }

    if !p.exists() {
        return None;
    }

    if is_install_root(&p) {
        return Some(p);
    }

    let mut current = p.clone();
    for _ in 0..4 {
        if let Some(parent) = current.parent() {
            if is_install_root(parent) {
                return Some(parent.to_path_buf());
            }
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    let subfolder_candidates = [
        "Antigravity IDE.app",
        "Antigravity.app",
        "Antigravity IDE",
        "Antigravity",
        "agy",
        "Programs\\Antigravity IDE",
        "Programs\\Antigravity",
        "resources",
        "Contents/Resources",
    ];
    for sub in subfolder_candidates {
        let candidate = p.join(sub);
        if is_install_root(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// The fixed install locations, before any resolution. Kept separate from
/// `find_all_installs` so the watchdog can enumerate installs without the
/// PowerShell registry scan - spawning PowerShell on a timer inside the
/// background relay would be both wasteful and a stray-window risk.
#[cfg(target_os = "windows")]
fn standard_install_candidates() -> Vec<PathBuf> {
    let local_appdata = env::var("LOCALAPPDATA").unwrap_or_default();
    let prog_files = env::var("PROGRAMFILES").unwrap_or_default();
    let prog_files_x86 = env::var("PROGRAMFILES(X86)").unwrap_or_default();

    vec![
        PathBuf::from(&local_appdata)
            .join("Programs")
            .join("Antigravity"),
        PathBuf::from(&local_appdata)
            .join("Programs")
            .join("Antigravity IDE"),
        PathBuf::from(&prog_files).join("Antigravity"),
        PathBuf::from(&prog_files).join("Antigravity IDE"),
        PathBuf::from(&prog_files_x86).join("Antigravity"),
        PathBuf::from(&prog_files_x86).join("Antigravity IDE"),
        PathBuf::from(&local_appdata).join("Antigravity"),
        PathBuf::from(&local_appdata).join("Antigravity IDE"),
        PathBuf::from(&local_appdata).join("agy").join("bin"),
        PathBuf::from(&local_appdata).join("agy"),
    ]
}

/// The macOS equivalents. Electron applications on macOS are packaged as .app bundles
/// in /Applications or ~/Applications, while user data and CLI configs live under
/// ~/Library/Application Support and ~/.local/bin or Homebrew (/opt/homebrew/bin).
#[cfg(target_os = "macos")]
fn standard_install_candidates() -> Vec<PathBuf> {
    let home = env::var("HOME").unwrap_or_default();
    let mut v: Vec<PathBuf> = Vec::new();
    let apps_bases = ["/Applications", "/System/Applications"];
    let app_names = [
        "Antigravity.app",
        "Antigravity IDE.app",
        "antigravity.app",
        "antigravity-ide.app",
        "Antigravity",
    ];
    for base in apps_bases {
        for name in app_names {
            v.push(PathBuf::from(base).join(name));
        }
    }
    if !home.is_empty() {
        let h = PathBuf::from(&home);
        v.push(h.join("Applications/Antigravity.app"));
        v.push(h.join("Applications/Antigravity IDE.app"));
        v.push(h.join("Library/Application Support/Antigravity"));
        v.push(h.join("Library/Application Support/Antigravity IDE"));
        v.push(h.join(".local/bin"));
        v.push(h.join(".agy/bin"));
        v.push(h.join(".agy"));
    }
    v.push(PathBuf::from("/opt/homebrew/bin"));
    v.push(PathBuf::from("/usr/local/bin"));
    v
}

/// The Linux equivalents. Antigravity ships as an Electron/VS Code fork, which on
/// Linux lands in one of the system prefixes (`.deb` → `/usr/share` or `/opt`;
/// tarball → `/opt` or under the home dir) with the language server at
/// `resources/app/extensions/antigravity/bin/`. The CLI keeps a per-user `agy`
/// tree. Anything not covered here is reachable through menu 2 (manual path),
/// which is why this list can stay short rather than scanning the whole disk.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn standard_install_candidates() -> Vec<PathBuf> {
    let home = env::var("HOME").unwrap_or_default();
    let mut v: Vec<PathBuf> = Vec::new();
    // System-wide install roots, both capitalisations the packaging might use.
    for base in ["/opt", "/usr/share", "/usr/lib", "/usr/local/share"] {
        for name in [
            "Antigravity",
            "Antigravity IDE",
            "antigravity",
            "antigravity-ide",
        ] {
            v.push(PathBuf::from(base).join(name));
        }
    }
    // Per-user installs (tarball / AppImage extraction / `agy` CLI).
    if !home.is_empty() {
        let h = PathBuf::from(&home);
        v.push(h.join(".local/share/Antigravity"));
        v.push(h.join(".local/share/Antigravity IDE"));
        v.push(h.join("Antigravity"));
        v.push(h.join("Antigravity IDE"));
        // The `agy` CLI: measured at `~/.local/bin/agy` on a real install, so its
        // bin dir is an install root in its own right (binary_targets scopes to
        // `agy`/`language_server*`, so a shared bin dir patches only ours).
        v.push(h.join(".local/bin"));
        v.push(h.join(".agy/bin"));
        v.push(h.join(".agy"));
        v.push(h.join(".local/share/agy/bin"));
    }
    v
}

/// The directory holding the `agy` CLI, found via PATH first and then the common
/// per-user/system bin dirs. Unix only; returns the dir (an install root once
/// `agy` is in it), not the file.
#[cfg(not(target_os = "windows"))]
fn find_agy_dir() -> Option<PathBuf> {
    let home = env::var("HOME").unwrap_or_default();
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(path) = env::var("PATH") {
        dirs.extend(path.split(':').filter(|d| !d.is_empty()).map(PathBuf::from));
    }
    dirs.push(PathBuf::from(format!("{}/.local/bin", home)));
    dirs.push(PathBuf::from(format!("{}/.agy/bin", home)));
    dirs.push(PathBuf::from("/opt/homebrew/bin"));
    dirs.push(PathBuf::from("/usr/local/bin"));
    dirs.push(PathBuf::from("/usr/bin"));
    // Never a snap dir: `/snap/bin/agy` is a read-only wrapper, not the real
    // binary - patching it always fails (no signature, read-only mount) and only
    // produces a scary "signature not found". A snap CLI is out of scope; the
    // native `~/.local/bin/agy` is what gets patched.
    dirs.into_iter()
        .find(|d| !is_snap_path(d) && d.join("agy").is_file())
}

/// True for a path served by snapd's read-only squashfs mounts, which cannot be
/// patched in place.
#[cfg(not(target_os = "windows"))]
fn is_snap_path(p: &Path) -> bool {
    p.starts_with("/snap") || p.starts_with("/var/lib/snapd")
}

/// Scans macOS applications and app support for any `*antigravity*` bundles or directories.
#[cfg(target_os = "macos")]
fn scan_antigravity_dirs() -> Vec<PathBuf> {
    let home = env::var("HOME").unwrap_or_default();
    let mut out = Vec::new();
    let mut bases = vec!["/Applications".to_string()];
    if !home.is_empty() {
        bases.push(format!("{}/Applications", home));
        bases.push(format!("{}/Library/Application Support", home));
    }
    for base in bases {
        if let Ok(entries) = fs::read_dir(&base) {
            for e in entries.flatten() {
                let p = e.path();
                let hit = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.to_lowercase().contains("antigravity"));
                if hit && (p.is_dir() || p.extension().map_or(false, |ext| ext == "app")) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// Scans the usual Linux prefixes for any `*antigravity*` directory, so an
/// install whose name is not hardcoded is still found - the analogue of the
/// Windows registry scan. Returns candidate roots to be resolved.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn scan_antigravity_dirs() -> Vec<PathBuf> {
    let home = env::var("HOME").unwrap_or_default();
    let mut out = Vec::new();
    let bases = [
        "/opt".to_string(),
        "/usr/share".to_string(),
        "/usr/lib".to_string(),
        "/usr/local/share".to_string(),
        format!("{}/.local/share", home),
    ];
    for base in bases {
        if let Ok(entries) = fs::read_dir(&base) {
            for e in entries.flatten() {
                let p = e.path();
                let hit = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.to_lowercase().contains("antigravity"));
                if hit && p.is_dir() {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// Resolves the standard install locations only - filesystem checks, no
/// PowerShell. This is what the watchdog polls.
pub fn discover_installs_fast() -> Vec<PathBuf> {
    let mut installs = Vec::new();
    for cand in standard_install_candidates() {
        if let Some(resolved) = resolve_install_root(&cand) {
            if !installs.contains(&resolved) {
                installs.push(resolved);
            }
        }
    }
    installs
}

fn find_all_installs() -> Vec<PathBuf> {
    let mut installs = Vec::new();
    let mut candidates = standard_install_candidates();

    // Linux: augment the fixed list with a scan of the usual prefixes for
    // *antigravity* dirs and the `agy` CLI's bin dir, so an install we did not
    // hardcode (or a CLI that lives on PATH) is still found.
    #[cfg(not(target_os = "windows"))]
    {
        candidates.extend(scan_antigravity_dirs());
        if let Some(agy_dir) = find_agy_dir() {
            candidates.push(agy_dir);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let ps_cmd = r#"Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like '*Antigravity*' -or $_.DisplayName -like '*agy*' -or $_.InstallLocation -like '*Antigravity*' } | ForEach-Object { $_.InstallLocation }"#;
        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_cmd])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let cleaned = clean_input_path(line);
                    if !cleaned.is_empty() {
                        candidates.push(PathBuf::from(&cleaned));
                    }
                }
            }
        }
    }

    for cand in candidates {
        if let Some(resolved) = resolve_install_root(&cand) {
            if !installs.contains(&resolved) {
                installs.push(resolved);
            }
        }
    }
    // Never a snap: its squashfs is read-only, so a resolved install (or a symlink
    // that resolved into one) could only ever fail to patch. Drop it here as well
    // as in the CLI search, so nothing snap-served reaches the results.
    #[cfg(not(target_os = "windows"))]
    installs.retain(|p| !is_snap_path(p));
    installs
}

/// Puts a v2.4+ install back into its pristine shape: the extracted
/// `resources/app` from an older patch is removed and `app.asar` is restored.
/// Electron prefers `resources/app` over the archive, so the directory must be
/// gone before the archive is put back.
fn restore_pristine_asar(resources: &Path) -> Result<(), String> {
    let app_dir = resources.join("app");
    let app_asar = resources.join("app.asar");
    let asar_bak = resources.join("app.asar.bak");

    // Only touch resources/app when it demonstrably came from an archive.
    // Antigravity IDE ships resources/app as its real, unpacked layout - with
    // neither app.asar nor a backup present there is nothing to restore, and
    // deleting the directory would destroy the install.
    if !asar_bak.exists() && !app_asar.exists() {
        return Ok(());
    }

    if app_dir.exists() {
        fs::remove_dir_all(&app_dir)
            .map_err(|e| format!("не удалось удалить resources\\app: {}", e))?;
    }
    if asar_bak.exists() && !app_asar.exists() {
        fs::rename(&asar_bak, &app_asar)
            .map_err(|e| format!("не удалось восстановить app.asar: {}", e))?;
    }
    Ok(())
}

fn process_install(install: &Path) -> Result<String, String> {
    // Patch all relevant binaries (Language Server / CLI).
    let bin_summary = patch_all_binaries(install);

    let resources = crate::utils::resources_dir(install);
    let app_dir = resources.join("app");
    let app_asar = resources.join("app.asar");

    if app_asar.exists() {
        // Peek at dist/main.js straight out of the archive. On v2.4+ the shell
        // carries no auth code, so nothing is unpacked and the install stays
        // byte-identical to a fresh one.
        let is_new_arch = asar::read_asar_entry(&app_asar, "dist/main.js")
            .and_then(|b| String::from_utf8(b).ok())
            .map_or(false, |src| is_new_desktop_architecture(&src));

        if is_new_arch {
            // Clean up leftovers from a patch applied before v2.4.
            restore_pristine_asar(&resources)?;
            // The Language Server is the only thing being patched here, so if
            // it did not take there is nothing to report as success.
            if bin_summary.ok == 0 {
                return Err(binary_failure_message(&bin_summary));
            }
            return Ok("Antigravity Desktop".to_string());
        }

        // Older layout: unpack so the JS can be patched.
        if app_dir.exists() {
            let _ = fs::remove_dir_all(&app_dir);
        }
        if !extract_asar(&app_asar, &app_dir) {
            return Err("Ошибка получения доступа к приложению".to_string());
        }
    }

    let ide_js = app_dir.join("out").join("main.js");
    let desktop_js = app_dir.join("dist").join("main.js");

    if ide_js.exists() {
        // Re-scan and patch binaries that were newly unpacked from the archive
        let _ = patch_all_binaries(install);
        patch_ide(install, &ide_js)?;
        if let Err(e) = patch_extension_js(install) {
            // Not reported per install: the progress line is one row wide, and
            // the extension patch is cosmetic next to the Language Server one.
            let _ = e;
        }
        // The endpoint is deliberately NOT overridden any more (2.11.0).
        //
        // Pushing the client onto `daily-cloudcode-pa` was a workaround for one
        // fact: nobody substituted `cloudcode-pa`, so the host Antigravity picks
        // for itself had no route (S9/N15). A provider that substitutes it is now
        // measured and first in the pool, so the workaround costs more than it
        // buys - it is a user-visible setting in *their* settings.json that
        // survives our revert paths only if they run one, and it pins a host
        // choice Antigravity is entitled to make differently per build or
        // account. Leave the host alone; route whichever one it asks for.
        //
        // Upgrade duty, same shape as `remove_legacy_ca` (I27): a machine
        // patched by <= 2.10.x still carries the override, and leaving it would
        // silently keep that machine on the old host. Menu 1 takes it back out.
        if let Err(e) = endpoint::remove_ide(install) {
            println!(
                "  \x1b[33m[WARN] Прежний оверрайд эндпоинта не снят: {}\x1b[0m\x1b[92m",
                e
            );
        }
        #[cfg(target_os = "macos")]
        if install.extension().map_or(false, |ext| ext == "app") {
            let _ = std::process::Command::new("codesign")
                .args(["--force", "--deep", "-s", "-"])
                .arg(install)
                .status();
        }
        return Ok("Antigravity IDE".to_string());
    } else if desktop_js.exists() {
        let js_patched = patch_desktop(install, &desktop_js)?;
        if !js_patched {
            // v2.4+ unpacked by an older build of this tool: undo the unpack.
            restore_pristine_asar(&resources)?;
        }
        #[cfg(target_os = "macos")]
        if install.extension().map_or(false, |ext| ext == "app") {
            let _ = std::process::Command::new("codesign")
                .args(["--force", "--deep", "-s", "-"])
                .arg(install)
                .status();
        }
        return Ok("Antigravity Desktop".to_string());
    } else if install.join("agy.exe").is_file() || install.join("agy").is_file() {
        if bin_summary.ok == 0 {
            return Err(binary_failure_message(&bin_summary));
        }
        // Not overridden any more, for the reason spelled out in the IDE arm
        // above; here the leftover is an environment variable rather than a
        // settings key, and it outlives a reinstall, so taking it back out
        // matters more, not less.
        if let Err(e) = endpoint::remove_cli() {
            println!(
                "  \x1b[33m[WARN] Прежний {} не снят: {}\x1b[0m\x1b[92m",
                endpoint::CLI_ENV_VAR,
                e
            );
        }
        return Ok("Antigravity CLI".to_string());
    }

    Err("Компоненты приложения не найдены".to_string())
}

fn binary_failure_message(summary: &patch_binary::BinarySummary) -> String {
    if summary.total() == 0 {
        "Бинарник Language Server / CLI не найден в этой установке".to_string()
    } else if let Some(err) = &summary.last_error {
        err.clone()
    } else {
        "Сигнатура в Language Server не найдена — вероятно, вышла новая версия Antigravity"
            .to_string()
    }
}

/// Starts the background resolver and installs the NRPT rules. Order matters:
/// the nameserver the rules point at depends on whether the relay is running,
/// so it has to be up before they are written.
#[cfg(not(target_os = "windows"))]
fn apply_dns_patch() {
    // Phase-2 region route (kb/patch.md): start the local CONNECT proxy as a
    // systemd user unit and point the language server at it via HTTPS_PROXY. The
    // proxy carries the gate hosts through a permitted-region exit, so the
    // server-side 400 lifts (S25). No DNS, no root.
    print!("\nЛокальный прокси-маршрут (обход ошибки 400)... ");
    io::stdout().flush().ok();
    match background::ensure_running() {
        Ok(_) => println!("OK"),
        Err(e) => {
            println!("\x1b[33mне удалось: {}\x1b[0m\x1b[92m", e);
            println!("  Прокси-сервис не запустился — обход 400 не включён.");
            println!("  Проверьте, что есть пользовательский systemd (systemctl --user).");
            return;
        }
    }
    // The unit started is not the port bound (`proxy::bind_listener` retries a
    // port something else may hold). Same rule as on Windows, and it matters more
    // here: nothing on Linux takes the variable back off, so a drop-in naming a
    // dead socket would break the whole session's proxy-aware traffic (G31, I53).
    print!("Проверяем локальный прокси... ");
    io::stdout().flush().ok();
    if !proxy::wait_for_listener(Duration::from_secs(20)) {
        println!("\x1b[33mне отвечает\x1b[0m\x1b[92m");
        println!("  HTTPS_PROXY не прописана — иначе без сети остались бы все");
        println!("  программы, которые её читают. Обход 400 не включён.");
        // Only our own drop-in; a proxy the user set another way is not ours to
        // touch and this call cannot reach it.
        endpoint::remove_proxy(&proxy::proxy_url(), "").ok();
        return;
    }
    println!("OK");
    print!("Прописываем HTTPS_PROXY для Antigravity... ");
    io::stdout().flush().ok();
    match endpoint::apply_proxy(&proxy::proxy_url(), "") {
        Ok(_) => println!("OK"),
        Err(e) => {
            println!("\x1b[33m{}\x1b[0m\x1b[92m", e);
            return;
        }
    }
    println!(
        "  \x1b[38;5;154mПервый раз: выйдите из сессии и войдите снова (или\n  \
         перезагрузитесь) — так HTTPS_PROXY применится ко всей сессии. Затем\n  \
         откройте Antigravity обычным способом из меню, и ошибка 400 уйдёт.\x1b[0m\x1b[92m"
    );
}

#[cfg(target_os = "windows")]
fn apply_dns_patch() {
    print!("\nФоновый DNS-резолвер... ");
    io::stdout().flush().ok();
    match background::ensure_running() {
        Ok(_) => println!("OK"),
        // Not fatal: the rules below fall back to the direct resolvers.
        Err(e) => println!("\x1b[33mпропущено ({})\x1b[0m\x1b[92m", e),
    }

    print!("Патч для Google серверов... ");
    io::stdout().flush().ok();
    match setup_dns_nrpt() {
        Ok(outcome) => {
            println!("OK");
            if let Some(note) = dns::outcome_note(&outcome) {
                println!("{}", note);
            }
        }
        Err(_) => println!("пропущено"),
    }
}

/// Menu 5: undoes the DNS half of the patch and nothing else, so the binaries
/// stay patched.
fn handle_restore_dns() {
    print!("Удаление фоновой DNS-службы... ");
    io::stdout().flush().ok();
    match background::disable() {
        Ok(_) => println!("готово."),
        Err(e) => println!("\x1b[33mошибка: {}\x1b[0m\x1b[92m", e),
    }
    background::disable_watchdog();

    print!("Удаление NRPT-правил DNS... ");
    io::stdout().flush().ok();
    remove_dns_nrpt();
    println!("готово.");

    disable_fallback_proxy();

    println!("{}", "Готово!");
    thread::sleep(Duration::from_secs(2));
}

/// Puts the environment back: the proxy variables, and any certificate an older
/// build left in the trust store.
///
/// **Both undo paths call this, and it never returns early.** It used to check
/// first and skip when nothing looked set, and the full revert did not call it
/// at all - so a machine could come out of "Полный откат" with `HTTPS_PROXY`
/// still naming `127.0.0.1:53129`, a port whose listener the same revert had
/// just deleted. Everything that honours that variable then loses the network,
/// which is exactly how it was reported: "не удаляет … и не работает выход в
/// интернет".
///
/// So: no gate, no early return, and every step runs even if the one before it
/// failed. Half of it left behind is worse than either whole state.
fn disable_fallback_proxy() {
    let url = proxy::proxy_url();
    let ca = proxy::ca_cert_path().to_string_lossy().to_string();
    print!("Возврат переменных среды (HTTPS_PROXY, NO_PROXY)... ");
    io::stdout().flush().ok();
    let env = endpoint::remove_proxy(&url, &ca);
    // Runs whatever the variables did: a root certificate left behind after a
    // revert would be the worst thing this tool could do.
    proxy::untrust_ca();
    match env {
        Ok(()) => println!("готово."),
        Err(e) => println!("\x1b[33m{}\x1b[0m\x1b[92m", e),
    }
}

/// Asks, once per run of menu 1, whether the user has a proxy of their own
/// abroad - and takes Enter for an answer.
///
/// This is the best route there is when it exists: proven live, a Dutch CONNECT
/// proxy got a correct answer out of the model with our relay untouched and not
/// one DNS rule involved. It is also *theirs*, which is the part that matters -
/// every other route here leans on a third party we picked. So it is offered
/// plainly, tested before it is believed, and skipped with one keypress.
fn ask_for_own_proxy() {
    let current = upstream::configured();
    println!();
    println!(
        "\x1b[38;5;154mСвой прокси за рубежом — если он у вас есть (необязательно)\x1b[0m\x1b[92m"
    );
    println!("  Трафик Antigravity к Google пойдёт через него — это самый быстрый путь.");
    println!("  HTTP-прокси (не SOCKS): адрес:порт или логин:пароль@адрес:порт");
    match &current {
        Some(up) => {
            println!("  Сейчас задан: {}", up.display());
            println!("  Enter — оставить, «-» — убрать, либо введите другой.");
        }
        None => println!("  Enter — пропустить, всё будет работать как и раньше."),
    }

    let answer = prompt("> ");
    let answer = answer.trim();
    if answer.is_empty() {
        return;
    }
    if answer == "-" {
        upstream::clear();
        println!("Свой прокси убран — трафик пойдёт прежним путём.");
        thread::sleep(Duration::from_secs(2));
        return;
    }

    let up = match upstream::parse(answer) {
        Ok(up) => up,
        Err(why) => {
            println!("\x1b[33mНе понял адрес: {}\x1b[0m\x1b[92m", why);
            thread::sleep(Duration::from_secs(3));
            return;
        }
    };

    // Tested before it is trusted. A proxy that is merely reachable proves
    // nothing - the relay accepted tunnels for an hour while cutting every one -
    // so this does the whole thing: connect, TLS to Google inside it, get an
    // answer back.
    print!("Проверка прокси... ");
    io::stdout().flush().ok();
    if let Err(why) = upstream::probe(&up) {
        println!("\x1b[33mне работает: {}\x1b[0m\x1b[92m", why);
        if !prompt("Сохранить всё равно? (y/N): ").eq_ignore_ascii_case("y") {
            return;
        }
        save_own_proxy(&up);
        return;
    }

    // The one thing worth checking beyond "it works": where it comes out. A proxy
    // that surfaces in the blocked region changes the address and nothing else -
    // measured on WARP, which reported the same country as no proxy at all - so
    // it cannot lift the gate, and saying so now saves a long misunderstanding.
    match upstream::exit_country(&up) {
        Some(loc) if upstream::region_is_blocked(&loc) => {
            println!("работает, но выходит в «{}».", loc);
            println!("\x1b[33mЭто та же страна, что и без прокси, — блокировка так не снимется.");
            println!("Сохранить можно: пока выход такой, трафик идёт прежним путём,");
            println!("а как только прокси сменит адрес выхода на страну без");
            println!("блокировки — он включится сам.\x1b[0m\x1b[92m");
            if !prompt("Сохранить? (y/N): ").eq_ignore_ascii_case("y") {
                return;
            }
        }
        Some(loc) => println!("OK, выход в «{}».", loc),
        None => println!("OK (страну выхода определить не удалось)."),
    }
    save_own_proxy(&up);
}

fn save_own_proxy(up: &upstream::Upstream) {
    match upstream::save(up) {
        Ok(()) => {
            println!("Свой прокси сохранён: {}", up.display());
            println!("Если он перестанет отвечать, трафик сам пойдёт прежним путём,");
            println!("а когда заработает снова — вернётся на него.");
        }
        Err(e) => println!("\x1b[33mНе удалось сохранить: {}\x1b[0m\x1b[92m", e),
    }
    thread::sleep(Duration::from_secs(3));
}

/// Takes out the certificate authority a build up to 2.9.1_27 installed.
///
/// That route is gone - the relay reaches the same backends with no CA at all -
/// but an upgrade goes through neither undo path, and `apply_proxy` returns
/// early on a machine whose `HTTPS_PROXY` already points here. Without this,
/// upgrading leaves a trusted root and its private key sitting in
/// `%LOCALAPPDATA%` for a route nothing uses any more.
///
/// Gated on the certificate file rather than on `ca_is_trusted()`, which costs a
/// PowerShell call: every machine that has the root also still has the file, and
/// the file-deleted-by-hand case is still covered by menu 4 and menu 5.
///
/// **Must run only once the installed relay is this build, and never before.**
/// An out-of-date relay is by definition one that still terminates TLS, signs
/// with this CA, and - the part that makes it dangerous - *regenerates* one the
/// moment the file disappears. Pulling the root out from under a relay that is
/// still running therefore does not disable the old route, it makes it present a
/// certificate nothing trusts: every gate request then dies as `BadCertificate`,
/// which the language server reports as "An existing connection was forcibly
/// closed by the remote host". That is exactly what shipping this call before
/// `apply_dns_patch` did to users whose relay update did not go through - most
/// obviously anyone running without administrator rights, where the relay is
/// never replaced at all.
fn remove_legacy_ca() {
    let cert = proxy::ca_cert_path();
    if !cert.exists() {
        return;
    }
    if background::relay_is_outdated() {
        return;
    }
    print!("Удаление сертификата старого запасного пути... ");
    io::stdout().flush().ok();
    endpoint::clear_node_ca(&cert.to_string_lossy()).ok();
    proxy::untrust_ca();
    println!("готово.");
}

/// Full revert: undoes the binary patch, puts app.asar back and drops the DNS
/// rules, so the machine returns to its pre-patch state without reinstalling.
fn handle_revert_all() {
    clear_screen();
    println!("{}", APP_TITLE);
    println!();
    println!("Полный откат: снятие патча с бинарников, восстановление app.asar,");
    println!("удаление фоновой DNS-службы и NRPT-правил.");
    println!("------------------------------------------------------------");

    kill_affected_processes();

    // Stop the background relay AND the standalone watchdog first: if either
    // were still running it would see each binary revert as an "update" and
    // immediately re-patch, fighting the very revert in progress.
    print!("Остановка фоновой DNS-службы... ");
    io::stdout().flush().ok();
    match background::disable() {
        Ok(_) => println!("готово."),
        Err(e) => println!("\x1b[33mошибка: {}\x1b[0m\x1b[92m", e),
    }
    background::disable_watchdog();

    let installs = find_all_installs();
    if installs.is_empty() {
        println!("Установки Antigravity не найдены.");
    }

    let mut reverted = Vec::new();
    for inst in &installs {
        println!("{}", "--------------------------------------------------");
        println!(
            "{} {}",
            "Обработка:",
            mask_path(&inst.display().to_string())
        );
        let mut n = unpatch_all_binaries(inst);
        // The IDE's main.js / extension.js are REWRITTEN, not marked, so the
        // binary revert above cannot undo them; without this the full revert left
        // main.js patched (G25). Restores from the pristine backup patch_ide kept.
        n += patch_ide::unpatch_ide_js(inst);
        if let Err(e) = restore_pristine_asar(&crate::utils::resources_dir(inst)) {
            println!("  \x1b[33m[ERR] {}\x1b[0m\x1b[92m", e);
        }
        if let Err(e) = endpoint::remove_ide(inst) {
            println!("  \x1b[33m[ERR] {}\x1b[0m\x1b[92m", e);
        }
        if n > 0 {
            reverted.push(mask_path(&inst.display().to_string()));
        }
    }

    println!("{}", "--------------------------------------------------");
    // The relay (and its watchdog) was already stopped up front, before the
    // binaries were reverted. Here only the DNS rules are dropped.
    print!("Удаление NRPT-правил DNS... ");
    io::stdout().flush().ok();
    remove_dns_nrpt();
    println!("готово.");

    print!("Возврат эндпоинта CloudCode... ");
    io::stdout().flush().ok();
    match endpoint::remove_cli() {
        Ok(_) => println!("готово."),
        Err(e) => println!("\x1b[33mошибка: {}\x1b[0m\x1b[92m", e),
    }

    // The variables come out here too, not only in menu 4. This is the path a
    // user takes when they want their machine back, and it was the one leaving
    // `HTTPS_PROXY` pointing at a port it had just deleted.
    disable_fallback_proxy();

    // The user's own proxy address is our configuration file, so a full revert
    // takes it with everything else. Menu 5 deliberately leaves it: that only
    // stops the DNS service, the setting is inert without the relay process
    // anyway, and pressing 1 again should not mean typing it in again.
    upstream::clear();

    print_results(&reverted, &[]);
}

fn handle_patch_antigravity() {
    kill_affected_processes();
    let installs = find_all_installs();

    if installs.is_empty() {
        println!("{}", "Установки Antigravity не найдены.");
        thread::sleep(Duration::from_secs(2));
        return;
    }

    let mut successes = Vec::new();
    let mut failures = Vec::new();

    println!();
    for (i, inst) in installs.iter().enumerate() {
        let path = inst.display().to_string();
        // Printed before the work, so a long patch shows which install it is
        // sitting on rather than a silent pause.
        print!(
            "  [{}/{}] {:<20} {:<34} ",
            i + 1,
            installs.len(),
            install_label(inst),
            short_path(&path)
        );
        io::stdout().flush().ok();
        match process_install(inst) {
            Ok(name) => {
                println!("OK");
                successes.push(name);
            }
            Err(e) => {
                println!("\x1b[33mошибка\x1b[0m\x1b[92m");
                failures.push(format!("{} - {}", mask_path(&path), e));
            }
        }
    }

    let did_something = !successes.is_empty() || !failures.is_empty();

    // Windows: the DNS layer needs admin; bring the relay up and register the
    // watchdog. The user-wide carrier stays off by default (kb/rivals.md).
    #[cfg(target_os = "windows")]
    if did_something && is_admin() {
        // Unconditionally, not only on a fresh machine: this run has to bring the
        // relay up and re-point the rules at it even when the rules already exist.
        apply_dns_patch();
        // Register the standalone watchdog task too, so re-patch-on-update
        // survives the relay being stopped or dying (G9). Best-effort.
        let _ = background::enable_watchdog();
    }

    // Linux: phase-2 proxy route. No admin needed - the local CONNECT proxy is a
    // systemd user unit and HTTPS_PROXY is a user drop-in - so it runs on every
    // patch, not behind an is_admin gate.
    #[cfg(not(target_os = "windows"))]
    if did_something {
        apply_dns_patch();
    }

    // Last, and never earlier: the CA may only go once the relay that signs with
    // it has actually been replaced. See `remove_legacy_ca`. (No-op on Linux.)
    remove_legacy_ca();

    // Asked after the routes are in place, so the answer is "do you have
    // something better" rather than "how should this work".
    if did_something {
        ask_for_own_proxy();
        // Windows only: on Linux HTTPS_PROXY must STAY set (the proxy is the only
        // route), and the running proxy already tries a saved own-proxy first, so
        // there is nothing to reconcile and the exit advisory would mislead (the
        // machine's own exit is not what the gate traffic uses any more).
        #[cfg(target_os = "windows")]
        {
            reconcile_gate_proxy();
            advise_on_exit();
            // No admin banner here. The warning is given up front, on the first
            // screen of an unelevated run (`show_admin_prewarning`), where the
            // user can still act on it without having patched anything.
        }
    }

    print_results(&successes, &failures);
}

/// Tells the user where their traffic comes out and what that means for them.
/// Advisory only (P16): it never changes what is installed, because a permitted
/// exit is inferred from geolocation, not proven - the region 400 is invisible
/// out of band. It exists so a user on a permitted VPN understands the DNS layer
/// is now redundant insurance (G26), and a user in a blocked region understands
/// the substitution is what is doing the work.
fn advise_on_exit() {
    print!("Проверка точки выхода... ");
    io::stdout().flush().ok();
    match upstream::machine_exit() {
        Some((ip, loc)) if upstream::region_is_blocked(&loc) => {
            println!("выход в «{}» ({}).", loc, ip);
            println!(
                "  Регион заблокирован — обход держится на подмене DNS. Всё настроено,\n  \
                 модели должны отвечать. Свой прокси за рубежом (спросили выше) —\n  \
                 самый быстрый путь, если он есть."
            );
        }
        Some((ip, loc)) => {
            println!("выход в «{}» ({}).", loc, ip);
            println!(
                "  Регион не заблокирован: гейт снимается самим выходом, а подмена DNS —\n  \
                 подстраховка. Запросы идут напрямую к серверам Google, это быстрее всего."
            );
        }
        None => {
            // A dead trace is not worth a scary line: everything is already set up.
            println!("не удалось определить (не важно, всё настроено).");
        }
    }
}

/// Points `HTTPS_PROXY` at our local gate proxy - unless the user has a proxy of
/// their own, in which case theirs is left alone and ours is taken off.
///
/// Always on, and the reason is availability, not speed. With the variable off
/// the language server reaches a gate host only by the address the DNS layer
/// substitutes; the day every provider drops a name (S9 happened) nothing on the
/// machine can route around it, because the routes that could - a built-in exit,
/// the relay, the user's own proxy - are only reachable through the local proxy.
/// With it on, the proxy picks the route per connection from a table it measures
/// (routes.rs), and the *default* row for a gate host is a direct tunnel to that
/// same substituted address - so the fast path S32 measured (0.28 s) is kept,
/// and the hop through loopback is the only cost. Non-gate hosts are a raw
/// tunnel either way.
///
/// The user's own proxy comes first: a `HTTPS_PROXY` of theirs, or `http.proxy`
/// in Antigravity's settings, means every request already goes where they want
/// it, and this tool gets out of the way. Whether the language server honours
/// the settings.json value is unverified, so it is treated as intent regardless.
///
/// And the listener comes before both: the variable is only ever set once
/// something actually answers on that port (G31, I53). A run without admin rights
/// installs no relay and therefore no proxy, and pointing a user-wide variable at
/// a socket nobody holds is worse than doing nothing - the language server proxies
/// its sign-in too, so `oauth2.googleapis.com` fails with `connection refused` and
/// the user cannot even log in.
fn reconcile_gate_proxy() {
    let url = proxy::proxy_url();
    if let Some(theirs) = endpoint::foreign_proxy(&url) {
        println!(
            "У вас настроен свой прокси ({}): {}.",
            theirs.found_in, theirs.value
        );
        println!("  Трафик Antigravity идёт через него, анлокер его не перехватывает.");
        // Ours must not sit above theirs (User scope beats Machine scope).
        let ca = proxy::ca_cert_path().to_string_lossy().to_string();
        endpoint::remove_proxy(&url, &ca).ok();
        return;
    }
    // Short budget on purpose: the relay was started a few steps ago and the
    // own-proxy question has been on screen since, so a healthy listener has long
    // been up. A slow one (the port was briefly taken) is picked up by the relay
    // itself, which sets the variable the moment its bind succeeds.
    if !proxy::wait_for_listener(Duration::from_secs(2)) {
        report_gate_proxy_down(&url);
        return;
    }
    match endpoint::apply_proxy(&url, "") {
        Ok(endpoint::Outcome::AlreadySet) => {}
        Ok(_) => {
            println!("Локальный прокси для гейт-хостов включён ({}).", url);
            println!(
                "  \x1b[38;5;154mМаршрут выбирается по замеру: напрямую по подменённому адресу,\n  \
                 а при сбое — через запасные пути. Если Antigravity был запущен до\n  \
                 этого шага, перезапустите его, чтобы он увидел переменную.\x1b[0m\x1b[92m"
            );
        }
        Err(e) => println!("\x1b[33m{}\x1b[0m\x1b[92m", e),
    }
}

/// Says why the local proxy is not being wired up, and makes sure no value of
/// ours is left naming it.
///
/// Two different failures land here and they need different answers. Without
/// admin rights there is no relay and never was one, so the honest line is "the
/// server-side half was skipped, run me elevated". With admin rights the relay is
/// there and the socket is not, which is a port problem - 53129 lives inside
/// Windows' dynamic range and can be taken, or reserved by Hyper-V/WSL - so the
/// answer is where to look. In both cases a value left over from an earlier run
/// would keep the machine's proxy-aware traffic pointed at nothing (G31), so it
/// comes off first, and only ever when it is ours (I45).
fn report_gate_proxy_down(url: &str) {
    let ca = proxy::ca_cert_path().to_string_lossy().to_string();
    if let Ok(true) = endpoint::remove_proxy_if_ours(url, &ca) {
        println!("Снята старая переменная HTTPS_PROXY — она указывала на неработающий прокси.");
        println!("  Без этого Antigravity не смог бы даже войти в аккаунт.");
    }
    if !is_admin() {
        // One line only: the full explanation was the first screen of this run
        // (`show_admin_prewarning`), and repeating it here would say nothing new.
        println!(
            "\x1b[33mЛокальный прокси не запущен — нужны права администратора.\x1b[0m\x1b[92m"
        );
        return;
    }
    println!(
        "\x1b[33mЛокальный прокси не отвечает на {} — переменная HTTPS_PROXY не выставлена.\x1b[0m\x1b[92m",
        url
    );
    println!("  Иначе без сети остались бы все программы, которые её читают.");
    println!(
        "  Причина — в журнале: {} (строки «proxy»).",
        mask_path(&dns_forwarder::log_path().to_string_lossy())
    );
    println!("  Чаще всего порт занят другой программой или зарезервирован Hyper-V/WSL:");
    println!("  netsh int ipv4 show excludedportrange protocol=tcp");
}

/// Which product an install directory is, for the progress line.
///
/// A guess from the layout rather than the name `process_install` returns,
/// because the line is printed before the work starts - that is the whole point
/// of it.
fn install_label(install: &Path) -> &'static str {
    if install.join("agy.exe").is_file() || install.join("agy").is_file() {
        "Antigravity CLI"
    } else if install.join("Antigravity IDE.exe").exists()
        || crate::utils::resources_dir(install).join("app").join("out").exists()
    {
        "Antigravity IDE"
    } else {
        "Antigravity 2.0"
    }
}

fn handle_manual_path() {
    clear_screen();
    println!("{}", APP_TITLE);
    println!("\n============================================================");
    println!("Указать путь к Antigravity вручную");
    println!("Вставьте путь к папке установки или исполняемому файлу");
    println!("(с кавычками или без, например: D:\\Antigravity IDE)");
    println!("------------------------------------------------------------");
    print!("> ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);

    let cleaned = clean_input_path(&input);
    if cleaned.is_empty() {
        return;
    }

    let input_path = PathBuf::from(&cleaned);

    println!("{}", "--------------------------------------------------");
    let resolved = match resolve_install_root(&input_path) {
        Some(path) => path,
        None => {
            println!(
                "\x1b[33m[ERR] По указанному пути установка Antigravity не найдена.\x1b[0m\x1b[92m"
            );
            println!("Проверьте правильность пути: {}", cleaned);
            println!("\nЧтобы вернуться в главное меню, нажмите Enter");
            let mut wait = String::new();
            io::stdin().read_line(&mut wait).ok();
            return;
        }
    };

    println!(
        "{} {}",
        "Обработка:",
        mask_path(&resolved.display().to_string())
    );

    let mut successes = Vec::new();
    let mut failures = Vec::new();

    match process_install(&resolved) {
        Ok(name) => {
            println!("{} {}", "[OK] Успешно пропатчено:", name);
            successes.push(name);
        }
        Err(e) => {
            println!("\x1b[33m[ERR] Ошибка: {}\x1b[0m\x1b[92m", e);
            failures.push(format!(
                "{} - {}",
                mask_path(&resolved.display().to_string()),
                e
            ));
        }
    }

    let did_something = !successes.is_empty() || !failures.is_empty();
    #[cfg(target_os = "windows")]
    if did_something && is_admin() {
        // Unconditionally, not only on a fresh machine: this run has to bring the
        // relay up and re-point the rules at it even when the rules already exist.
        apply_dns_patch();
    }
    // Linux: the proxy route needs no admin (systemd user unit + user drop-in).
    #[cfg(not(target_os = "windows"))]
    if did_something {
        apply_dns_patch();
    }

    remove_legacy_ca();

    print_results(&successes, &failures);
}

/// Says on the very first screen, before the licence prompt and the menu, that
/// this run cannot install the half that answers the region 400.
///
/// Shown on **every** unelevated start. It used to be gated on
/// `!is_nrpt_applied()`, which meant that on a machine unlocked once before the
/// user was told nothing until the patch had already run - the one moment they
/// can no longer act on it cheaply.
///
/// What the flag changes is the wording, not whether the screen appears: with the
/// rules in place the relay carries the 400 from its own scheduled task and is
/// untouched by this process's token, so "the bypass will not work" would simply
/// be false. Saying it anyway trains the user to skip the screen.
#[cfg(target_os = "windows")]
fn show_admin_prewarning(dns_installed: bool) {
    clear_screen();
    println!("{}", APP_TITLE);
    println!();
    println!("\x1b[33mВнимание: анлокер запущен БЕЗ прав администратора.\x1b[0m\x1b[92m");
    println!();
    if dns_installed {
        println!("Обход ошибки 400 («User location is not supported») на этой");
        println!("машине уже установлен и продолжает работать сам по себе.");
        println!();
        println!("Но этот запуск не сможет его обновить, починить или");
        println!("переустановить: DNS-служба, локальный прокси и правила NRPT");
        println!("требуют повышенных привилегий. Доступен только патч клиента.");
    } else {
        println!("\x1b[33mОбход ошибки 400 («User location is not supported») в этом");
        println!("запуске установлен НЕ БУДЕТ.\x1b[0m\x1b[92m");
        println!();
        println!("Без админ-прав доступен только патч клиента. DNS-служба,");
        println!("локальный прокси и правила NRPT — то, что и снимает");
        println!("региональную блокировку, — будут пропущены.");
    }
    println!();
    println!(
        "\x1b[38;5;154mЧтобы это исправить: закройте окно, нажмите на файле анлокера правой\n\
         кнопкой → «Запуск от имени администратора».\x1b[0m\x1b[92m"
    );
    println!();
    print!("Нажмите Enter чтобы продолжить без админ-прав... ");
    io::stdout().flush().ok();
    let mut tmp = String::new();
    io::stdin().read_line(&mut tmp).ok();
}

fn main() {
    // The relay mode has to short-circuit before anything draws or prompts: the
    // scheduled task starts this exe with no console and no user behind it.
    if env::args().any(|a| a == background::FORWARDER_FLAG) {
        // Before anything else: the task launches a console subsystem exe, and
        // the window it gets would otherwise sit on screen for the whole run.
        dns_forwarder::detach_console();
        // Keep the patch alive across Antigravity's own auto-updates. Runs in
        // its own thread; the relay loop below is what keeps the process up.
        watchdog::start();
        if let Err(e) = dns_forwarder::run() {
            dns_forwarder::log_fatal(&e);
            std::process::exit(1);
        }
        return;
    }

    // Standalone watchdog: the same re-patch survival, decoupled from the relay
    // so it keeps working when the relay is stopped or absent (G9). No network,
    // no console. Its own logon task launches this; the loop keeps it alive.
    if env::args().any(|a| a == background::WATCHDOG_FLAG) {
        dns_forwarder::detach_console();
        watchdog::run_forever();
        return;
    }

    // Linux phase-2 proxy mode: run ONLY the local CONNECT proxy (no DNS, no :53).
    // A systemd user unit launches this; `proxy::run` blocks until the process is
    // stopped. `if_index` 0 = let the routing table pick (no VPN-bypass on Linux).
    if env::args().any(|a| a == background::PROXY_FLAG) {
        dns_forwarder::detach_console();
        if let Err(e) = proxy::run(0) {
            eprintln!("proxy: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // `--about` / `--license` / `--version`: prints the copyright notice and the
    // build canaries, then exits. Deliberately before the key prompt so any
    // binary can be fingerprinted without a licence key.
    canary::handle_cli_flags();

    #[cfg(target_os = "windows")]
    {
        let window_title = format!("Antigravity анлокер v{}", APP_VERSION);
        console_style::set(&window_title);
    }

    // The admin pre-warning is about Windows UAC and the DNS layer that needs it.
    // The Linux proxy route needs no root, so there is nothing to warn about.
    // No `is_nrpt_applied()` gate on *whether* to warn - only on what it says.
    #[cfg(target_os = "windows")]
    if !is_admin() {
        show_admin_prewarning(is_nrpt_applied());
    }

    login_screen();

    // The NRPT rules survive a reboot; the host routes that keep their queries
    // off the VPN only survive it while the network stays the same. Windows-only:
    // Linux has no pinned-hosts fallback.
    #[cfg(target_os = "windows")]
    if is_admin() {
        refresh_pinned_hosts();
    }

    loop {
        clear_screen();
        // Users only need the product name and version here; the build canary is
        // not shown (it stays in the binary, the version resource and `--about`
        // for provenance). RELEASE_TOKEN is pinned into the binary by
        // canary::CANARY_ANCHOR, so dropping this reference cannot strip it.
        println!("{} v{}", APP_TITLE, APP_VERSION);
        println!();
        println!("1. Разблокировать Antigravity 2.0 / IDE / CLI");
        println!("2. Указать путь к Antigravity вручную");
        println!(
            "3. Открыть Telegram-группу ({})",
            link(TELEGRAM_URL, TELEGRAM_URL)
        );
        // Yellow-green (256-color 154) for the two "undo" actions; reset then
        // restore the menu's bright-green afterwards.
        println!("\x1b[38;5;154m4. Отключить DNS-службу и NRPT (отключит исправление ошибок \"400\")\x1b[0m\x1b[92m");
        println!("\x1b[38;5;154m5. Полный откат (снять патч и вернуть исходное состояние)\x1b[0m\x1b[92m");
        println!("6. Выход");
        // Last and out of sequence on purpose (owner): the donation is the one
        // item that asks something of the user rather than doing something for
        // them, so it sits after the exit and takes the key nobody reaches for.
        println!(
            "0. Отблагодарить копеечкой ({})",
            link(DONATE_URL, DONATE_URL)
        );
        println!();
        println!("Пункты 3 и 0 открывают ссылку в браузере.");
        // The relay is installed once and then runs from %ProgramData% across
        // reboots, so a newer unlocker sitting next to an older relay is silent
        // by default - and it is the relay that carries the DNS fixes.
        if background::relay_is_outdated() {
            println!(
                "\x1b[33mDNS-служба устарела (v{} → v{}): {}.\x1b[0m\x1b[92m",
                dns_forwarder::installed_version(),
                dns_forwarder::RELAY_VERSION,
                if is_admin() {
                    "выполните пункт 1, чтобы обновить её"
                } else {
                    "запустите анлокер от имени администратора и выполните пункт 1"
                }
            );
        }
        // Windows-only: the admin note is about the DNS layer's UAC requirement.
        // The Linux proxy route needs no root. Same split as the pre-warning
        // screen - the note is always there, and only its claim depends on
        // whether the rules are already installed.
        #[cfg(target_os = "windows")]
        if !is_admin() {
            println!(
                "\x1b[33mЗапущено без админ-прав: {} —\n\
                 запустите от имени администратора.\x1b[0m\x1b[92m",
                if is_nrpt_applied() {
                    "обход региона (ошибка 400) уже стоит, но обновить его не выйдет"
                } else {
                    "обход региона (ошибка 400) установлен не будет"
                }
            );
        }
        println!();

        match prompt("> ").as_str() {
            "1" => handle_patch_antigravity(),
            "2" => handle_manual_path(),
            "3" => open_url(TELEGRAM_URL),
            "4" => handle_restore_dns(),
            "5" => handle_revert_all(),
            "6" => break,
            "0" => open_url(DONATE_URL),
            _ => {
                println!("{}", "Неверный выбор.");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: `%LOCALAPPDATA%` holds an `agy` *directory* (the CLI's folder).
    /// An `exists()` check matched that directory, so the parent-walk in
    /// `resolve_install_root` treated `%LOCALAPPDATA%` itself as an install root and
    /// menu 1 reported `%LOCALAPPDATA% - Компоненты приложения не найдены`. A
    /// launcher/CLI is a *file*, so a directory named `agy` must not qualify.
    #[test]
    fn a_directory_named_agy_does_not_make_its_parent_an_install() {
        let base = env::temp_dir().join("ag_isroot_dir_test");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("agy").join("bin")).unwrap();
        assert!(
            !is_install_root(&base),
            "a subdirectory named agy must not make its parent an install root"
        );
        // The empty agy dir is not a root either, so resolving a path under it must
        // not walk up to `base`.
        assert_ne!(resolve_install_root(&base.join("agy")), Some(base.clone()));
        fs::remove_dir_all(&base).ok();
    }

    /// The real CLI directory - one that actually holds the `agy` binary as a
    /// file - still resolves as an install root.
    #[test]
    fn a_directory_holding_the_agy_binary_is_an_install() {
        let base = env::temp_dir().join("ag_isroot_file_test");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("agy"), b"binary").unwrap();
        assert!(is_install_root(&base));
        fs::remove_dir_all(&base).ok();
    }
}
