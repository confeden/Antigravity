// The GUI is the product; a console subsystem binary would put a black window
// on screen behind it. The CLI flags that still print (--about/--version) and
// the background modes attach to the parent console instead - see attach_console.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
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
use std::path::{Path, PathBuf};
use std::time::Duration;

mod asar;
mod auth;
mod background;
mod binary_profile;
mod canary;
mod connect_wire;
mod dns;
mod dns_client;
mod dns_forwarder;
mod doh;
mod egress;
mod elevate;
mod endpoint;
mod gate;
mod gate_hosts;
mod gui;
mod health;
mod hosts_pin;
mod hwid;
mod instances;
mod group_key;
mod loopback;
mod ls_log;
mod net;
mod ops;
mod patch_binary;
mod patch_ide;
mod portcheck;
mod proxy;
mod resolvers;
mod routes;
mod settings;
mod tui;
mod update;
mod upstream;
mod user_state_location;
pub mod group;
mod utils;
mod watchdog;
mod wsl;
#[path = "wsl_direct/api.rs"]
mod wsl_api;
#[path = "wsl_direct/controller.rs"]
mod wsl_controller;
#[path = "wsl_direct/runtime.rs"]
mod wsl_runtime;
#[cfg(windows)]
#[path = "wsl_direct/windows_coordinator.rs"]
mod windows_coordinator;
#[cfg(windows)]
#[path = "wsl_direct/authority.rs"]
mod wsl_direct_authority;
#[cfg(windows)]
#[path = "wsl_direct/gateway.rs"]
mod wsl_direct_gateway;
#[cfg(windows)]
#[path = "wsl_direct/policy_binding.rs"]
mod wsl_direct_policy_binding;
#[cfg(windows)]
#[path = "wsl_direct/public_policy.rs"]
mod wsl_direct_public_policy;
#[cfg(windows)]
#[path = "wsl_direct/gateway_host.rs"]
mod wsl_direct_gateway_host;
#[cfg(windows)]
#[path = "wsl_direct/vendor_runtime.rs"]
mod vendor_runtime;

use asar::extract_asar;
use patch_binary::patch_all_binaries;
use patch_ide::{is_new_desktop_architecture, patch_desktop, patch_extension_js, patch_ide};

pub fn clean_input_path(input: &str) -> String {
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
    is_install_root_checked(path).unwrap_or(false)
}

fn discovery_metadata(path: &Path) -> Result<Option<fs::Metadata>, String> {
    match fs::metadata(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => Ok(None),
        Err(error) => Err(format!("installation discovery metadata: {error}")),
    }
}

fn is_install_root_checked(path: &Path) -> Result<bool, String> {
    if !discovery_metadata(path)?.is_some_and(|value| value.is_dir()) { return Ok(false); }

    let path_str = path.to_string_lossy().to_lowercase();
    if path_str == "c:\\windows"
        || path_str.starts_with("c:\\windows\\")
        || path_str.contains("\\windows\\system32")
        || path_str.contains("\\windows\\syswow64")
    {
        return Ok(false);
    }

    let resources = path.join("resources");
    if discovery_metadata(&resources)?.is_some_and(|value| value.is_dir()) {
        for child in ["app.asar", "app", "bin"] {
            if discovery_metadata(&resources.join(child))?.is_some() { return Ok(true); }
        }
    }
    // `is_file`, not `exists`: `%LOCALAPPDATA%\agy` is the CLI's *directory*, and
    // an `exists()` check there made the parent-walk treat `%LOCALAPPDATA%` itself
    // as an install root. A launcher/CLI is always a file.
    for file in ["agy.exe", "agy", "Antigravity.exe", "Antigravity IDE.exe", "antigravity.exe"] {
        if discovery_metadata(&path.join(file))?.is_some_and(|value| value.is_file()) { return Ok(true); }
    }
    // Linux/macOS launcher names (no extension).
    #[cfg(not(target_os = "windows"))]
    for file in ["antigravity", "Antigravity", "antigravity-ide"] {
        if discovery_metadata(&path.join(file))?.is_some_and(|value| value.is_file()) { return Ok(true); }
    }
    for entry in ["out", "dist"] {
        if discovery_metadata(&path.join(entry).join("main.js"))?.is_some() { return Ok(true); }
    }
    Ok(false)
}

pub fn resolve_install_root(raw: &Path) -> Option<PathBuf> {
    resolve_install_root_checked(raw).ok().flatten()
}

fn resolve_install_root_checked(raw: &Path) -> Result<Option<PathBuf>, String> {
    let mut p = raw.to_path_buf();
    let Some(metadata) = discovery_metadata(&p)? else { return Ok(None); };
    if metadata.is_file() {
        if let Some(parent) = p.parent() {
            p = parent.to_path_buf();
        }
    }

    if is_install_root_checked(&p)? {
        return Ok(Some(p));
    }

    let mut current = p.clone();
    for _ in 0..4 {
        if let Some(parent) = current.parent() {
            if is_install_root_checked(parent)? {
                return Ok(Some(parent.to_path_buf()));
            }
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    let subfolder_candidates = [
        "Antigravity IDE",
        "Antigravity",
        "agy",
        "Programs\\Antigravity IDE",
        "Programs\\Antigravity",
        "resources",
    ];
    for sub in subfolder_candidates {
        let candidate = p.join(sub);
        if is_install_root_checked(&candidate)? {
            return Ok(Some(candidate));
        }
    }

    Ok(None)
}

/// The fixed install locations, before any resolution. Kept separate from
/// `find_all_installs` so the watchdog can enumerate installs without the
/// PowerShell registry scan - spawning PowerShell on a timer inside the
/// background relay would be both wasteful and a stray-window risk.
#[cfg(target_os = "windows")]
fn standard_install_candidates() -> Vec<PathBuf> {
    windows_standard_candidates(
        env::var_os("LOCALAPPDATA").filter(|value| !value.is_empty()).map(PathBuf::from),
        env::var_os("PROGRAMFILES").filter(|value| !value.is_empty()).map(PathBuf::from),
        env::var_os("PROGRAMFILES(X86)").filter(|value| !value.is_empty()).map(PathBuf::from),
        env::var_os("USERPROFILE").filter(|value| !value.is_empty()).map(PathBuf::from))
}

#[cfg(windows)]
fn windows_standard_candidates(local: Option<PathBuf>, program: Option<PathBuf>,
    program_x86: Option<PathBuf>, home: Option<PathBuf>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(local) = &local {
        for relative in [r"Programs\Antigravity", r"Programs\Antigravity IDE"] {
            candidates.push(local.join(relative));
        }
    }
    for program in [program, program_x86].into_iter().flatten() {
        for relative in ["Antigravity", "Antigravity IDE"] { candidates.push(program.join(relative)); }
    }
    if let Some(local) = local {
        for relative in ["Antigravity", "Antigravity IDE", r"agy\bin", "agy"] { candidates.push(local.join(relative)); }
    }
    if let Some(home) = home { candidates.push(home.join(".gemini").join("bin")); }
    candidates
}

/// The Linux equivalents. Antigravity ships as an Electron/VS Code fork, which on
/// Linux lands in one of the system prefixes (`.deb` → `/usr/share` or `/opt`;
/// tarball → `/opt` or under the home dir) with the language server at
/// `resources/app/extensions/antigravity/bin/`. The CLI keeps a per-user `agy`
/// tree. Anything not covered here is reachable through menu 2 (manual path),
/// which is why this list can stay short rather than scanning the whole disk.
#[cfg(not(target_os = "windows"))]
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
        v.push(h.join(".gemini/bin"));
    }
    v
}

/// The directory holding the `agy` CLI, found via PATH first and then the common
/// per-user/system bin dirs. Linux only; returns the dir (an install root once
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

/// Scans the usual Linux prefixes for any `*antigravity*` directory, so an
/// install whose name is not hardcoded is still found - the analogue of the
/// Windows registry scan. Returns candidate roots to be resolved.
#[cfg(not(target_os = "windows"))]
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

pub fn find_all_installs() -> Vec<PathBuf> {
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
        // This legacy presentation entry may retain a partial standard subset;
        // effect-capable AllTarget Apply uses checked discovery below instead.
        if let Ok(found) = registry_install_candidates_checked() { candidates.extend(found); }
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

#[cfg(windows)]
fn registry_install_candidates_checked() -> Result<Vec<PathBuf>, String> {
    let script = r#"& {
$ErrorActionPreference='Stop'
$roots=@('HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')
$locations=@(foreach($root in $roots) {
 if(!(Test-Path -LiteralPath $root -ErrorAction Stop)){continue}
 foreach($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
  $value=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
  if($value.DisplayName -like '*Antigravity*' -or $value.DisplayName -like '*agy*' -or $value.InstallLocation -like '*Antigravity*') {
   if($null -ne $value.InstallLocation) {
    if($value.InstallLocation -isnot [string]){throw 'Installation location has invalid type'}
    if(![string]::IsNullOrWhiteSpace($value.InstallLocation)){$value.InstallLocation}
   }
  }
 }
})
ConvertTo-Json -InputObject $locations -Compress
'AG_END'
}"#;
    let output = utils::powershell_within(script, Duration::from_secs(20)).ok_or("installation registry query unavailable")?;
    if !output.status.success() { return Err("installation registry query failed or incomplete".into()); }
    receive_registry_install_directories(&output.stdout)
}

#[cfg(windows)]
fn receive_registry_install_directories(bytes: &[u8]) -> Result<Vec<PathBuf>, String> {
    let mut directories = Vec::new();
    for path in receive_registry_install_candidates(bytes)? {
        if let Some(directory) = windows_coordinator::windows_installation::CheckedPath::directory_locator_if_present(path.as_os_str())? {
            directories.push(directory.as_path().to_owned());
        }
    }
    Ok(directories)
}

#[cfg(windows)]
fn receive_registry_install_candidates(bytes: &[u8]) -> Result<Vec<PathBuf>, String> {
    let output = std::str::from_utf8(bytes).map_err(|_| "installation registry query encoding")?;
    let json = output.trim().strip_suffix("\nAG_END").ok_or("installation registry query completion missing")?.trim();
    let locations: Vec<String> = serde_json::from_str(json).map_err(|_| "installation registry query shape")?;
    locations.into_iter().map(|value| {
        let value = clean_input_path(&value);
        let directory = windows_coordinator::windows_installation::WindowsLocalPath::parse_directory_locator(std::ffi::OsStr::new(&value))?;
        Ok(directory.as_path().to_owned())
    }).collect()
}

#[cfg(windows)]
pub(crate) fn find_all_installs_checked(cancel: &std::sync::atomic::AtomicBool) -> Result<Vec<PathBuf>, String> {
    use std::sync::atomic::Ordering;
    let base = |name: &str, required: bool| -> Result<Option<PathBuf>, String> {
        match env::var_os(name) {
            Some(value) if !value.is_empty() => {
                let directory = windows_coordinator::windows_installation::WindowsLocalPath::parse_directory_locator(&value)?;
                Ok(Some(directory.as_path().to_owned()))
            },
            _ if required => Err(format!("installation discovery environment {name} is unavailable")),
            _ => Ok(None),
        }
    };
    let mut candidates = windows_standard_candidates(base("LOCALAPPDATA", true)?, base("PROGRAMFILES", true)?,
        base("PROGRAMFILES(X86)", false)?, base("USERPROFILE", true)?);
    if cancel.load(Ordering::SeqCst) { return Err("installation discovery cancelled".into()); }
    candidates.extend(registry_install_candidates_checked()?);
    let mut installs = Vec::new();
    for candidate in candidates {
        if cancel.load(Ordering::SeqCst) { return Err("installation discovery cancelled".into()); }
        if let Some(root) = resolve_install_root_checked(&candidate)? {
            if !installs.contains(&root) { installs.push(root); }
        }
    }
    Ok(installs)
}

/// Puts a v2.4+ install back into its pristine shape: the extracted
/// `resources/app` from an older patch is removed and `app.asar` is restored.
/// Electron prefers `resources/app` over the archive, so the directory must be
/// gone before the archive is put back.
pub fn restore_pristine_asar(resources: &Path) -> Result<(), String> {
    #[cfg(windows)]
    let _canonical_guard = windows_coordinator::windows_installation::admit_legacy_write(resources)?;
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

/// One install, patched. Carries what used to be printed.
///
/// `summary` is returned rather than folded into a process-wide flag on the way
/// past: the console build died after one run, so a sticky "the proxy rename
/// landed" atomic was harmless there. A window that patches twice would inherit
/// the first run's verdict and go on writing the proxy variable for a rename
/// that has since started failing. The caller owns the verdict for *its* run.
pub struct InstallOutcome {
    pub label: &'static str,
    /// Non-fatal notes — a leftover override that would not come off. The patch
    /// succeeded anyway, so these are not errors.
    pub warnings: Vec<String>,
    pub summary: patch_binary::BinarySummary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstallationKind { Desktop, Ide, Cli }

#[cfg(windows)]
pub(crate) struct InstallationLayout {
    pub(crate) kind: InstallationKind,
    pub(crate) anchor: PathBuf,
    new_desktop: bool,
}

/// The effect branch owns classification; presentation labels cannot mint it.
#[cfg(windows)]
pub(crate) fn receive_installation_layout(root: &Path) -> Result<InstallationLayout, String> {
    let archive = root.join("resources").join("app.asar");
    let scripts = patch_ide::js_targets(root);
    let archive_present = discovery_metadata(&archive)?.is_some();
    let (out, dist, new_desktop) = if archive_present {
        let _pin = windows_coordinator::windows_installation::CheckedPath::open(&archive,
            windows_coordinator::windows_installation::PathKind::File,
            windows_coordinator::windows_installation::PathPurpose::ReplaceSource)?;
        let dist = asar::read_asar_entry_checked(&archive, "dist/main.js")?;
        let new_desktop = match dist.as_ref() {
            Some(bytes) => is_new_desktop_architecture(std::str::from_utf8(bytes).map_err(|_| "Desktop entry point encoding")?),
            None => false,
        };
        (asar::read_asar_entry_checked(&archive, "out/main.js")?.is_some(), dist.is_some(), new_desktop)
    } else {
        (discovery_metadata(&scripts.ide_main)?.is_some_and(|value| value.is_file()),
         discovery_metadata(&scripts.desktop_main)?.is_some_and(|value| value.is_file()), false)
    };
    let file = |name: &str| -> Result<Option<PathBuf>, String> {
        let path = root.join(name);
        Ok(discovery_metadata(&path)?.filter(|value| value.is_file()).map(|_| path))
    };
    if new_desktop || (!out && dist) {
        return Ok(InstallationLayout { kind: InstallationKind::Desktop,
            anchor: file("Antigravity.exe")?.ok_or("Desktop executable is unavailable")?, new_desktop });
    }
    if out {
        let executable = match file("Antigravity IDE.exe")? { Some(path) => Some(path), None => file("Antigravity.exe")? };
        let anchor = match executable {
            Some(anchor) => anchor,
            None if archive_present => archive,
            None => scripts.ide_main,
        };
        return Ok(InstallationLayout { kind: InstallationKind::Ide, anchor, new_desktop: false });
    }
    let cli = match file("agy.exe")? { Some(path) => Some(path), None => file("agy")? };
    if let Some(anchor) = cli {
        return Ok(InstallationLayout { kind: InstallationKind::Cli, anchor, new_desktop: false });
    }
    Err("installation effect kind/anchor is unavailable".into())
}

pub fn process_install(install: &Path) -> Result<InstallOutcome, String> {
    process_install_received(install, None)
}

pub(crate) fn process_install_received(install: &Path, expected: Option<InstallationKind>) -> Result<InstallOutcome, String> {
    #[cfg(windows)]
    let layout = receive_installation_layout(install)?;
    #[cfg(windows)]
    if expected.is_some_and(|expected| expected != layout.kind) { return Err("installation effect kind changed before execution".into()); }
    #[cfg(not(windows))]
    let _ = expected;
    let resources = install.join("resources");
    let app_dir = resources.join("app");
    let app_asar = resources.join("app.asar");
    #[cfg(windows)]
    let is_new_arch = layout.new_desktop;
    #[cfg(windows)]
    let canonical = windows_coordinator::windows_installation::canonical_installed(install)?;
    #[cfg(not(windows))]
    let canonical = false;
    #[cfg(windows)]
    let _archive_guard = if !is_new_arch {
        Some(windows_coordinator::windows_installation::admit_legacy_write(install)?)
    } else { None };
    // Native targets receive their own positive target/settled-slot capability.
    // An owned new Desktop never enters legacy restore/extract code.
    let bin_summary = if expected.is_some() { patch_binary::patch_all_binaries_checked(install)? }
        else { patch_all_binaries(install) };
    let mut warnings: Vec<String> = Vec::new();

    #[cfg(windows)]
    let needs_archive = layout.kind != InstallationKind::Cli;
    #[cfg(not(windows))]
    let needs_archive = true;
    if needs_archive && app_asar.exists() {
        // Peek at dist/main.js straight out of the archive. On v2.4+ the shell
        // carries no auth code, so nothing is unpacked and the install stays
        // byte-identical to a fresh one.
        #[cfg(not(windows))]
        let is_new_arch = asar::read_asar_entry(&app_asar, "dist/main.js")
            .and_then(|bytes| String::from_utf8(bytes).ok()).is_some_and(|source| is_new_desktop_architecture(&source));
        if is_new_arch {
            // Clean up leftovers from a patch applied before v2.4.
            if !canonical { restore_pristine_asar(&resources)?; }
            // The Language Server is the only thing being patched here, so if
            // it did not take there is nothing to report as success.
            if bin_summary.ok == 0 {
                return Err(binary_failure_message(&bin_summary));
            }
            return Ok(InstallOutcome {
                label: "Antigravity Desktop",
                warnings,
                summary: bin_summary,
            });
        }

        // Older layout: unpack so the JS can be patched.
        if app_dir.exists() {
            if let Err(error) = fs::remove_dir_all(&app_dir) {
                if expected.is_some() { return Err(format!("Старая распаковка не удалена; следующие действия остановлены: {error}")); }
            }
        }
        if !extract_asar(&app_asar, &app_dir) {
            return Err("Ошибка получения доступа к приложению".to_string());
        }
    }

    let scripts = patch_ide::js_targets(install);
    let ide_js = scripts.ide_main;
    let desktop_js = scripts.desktop_main;
    #[cfg(windows)]
    let ide_layout = layout.kind == InstallationKind::Ide;
    #[cfg(not(windows))]
    let ide_layout = ide_js.exists();
    #[cfg(windows)]
    let desktop_layout = layout.kind == InstallationKind::Desktop;
    #[cfg(not(windows))]
    let desktop_layout = desktop_js.exists();
    #[cfg(windows)]
    let cli_layout = layout.kind == InstallationKind::Cli;
    #[cfg(not(windows))]
    let cli_layout = install.join("agy.exe").is_file() || install.join("agy").is_file();

    if ide_layout {
        patch_ide(install, &ide_js)?;
        if let Err(e) = patch_extension_js(install) {
            if expected.is_some() { return Err(format!("Основной JS получен, но расширение не изменено: {e}")); }
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
            if expected.is_some() { return Err(format!("Файлы IDE изменены, но прежний оверрайд не снят: {e}")); }
            warnings.push(format!("Прежний оверрайд эндпоинта не снят: {}", e));
        }
        return Ok(InstallOutcome {
            label: "Antigravity IDE",
            warnings,
            summary: bin_summary,
        });
    } else if desktop_layout {
        let js_patched = patch_desktop(install, &desktop_js)?;
        if !js_patched {
            // v2.4+ unpacked by an older build of this tool: undo the unpack.
            restore_pristine_asar(&resources)?;
        }
        return Ok(InstallOutcome {
            label: "Antigravity Desktop",
            warnings,
            summary: bin_summary,
        });
    } else if cli_layout {
        if bin_summary.ok == 0 {
            return Err(binary_failure_message(&bin_summary));
        }
        // Not overridden any more, for the reason spelled out in the IDE arm
        // above; here the leftover is an environment variable rather than a
        // settings key, and it outlives a reinstall, so taking it back out
        // matters more, not less.
        if let Err(e) = endpoint::remove_cli() {
            if expected.is_some() { return Err(format!("Нативный CLI изменён, но прежняя переменная не снята: {e}")); }
            warnings.push(format!("Прежний {} не снят: {}", endpoint::CLI_ENV_VAR, e));
        }
        return Ok(InstallOutcome {
            label: "Antigravity CLI",
            warnings,
            summary: bin_summary,
        });
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

/// The same removal without a word of output, for the window.
///
/// Both guards are load-bearing and neither is cosmetic (I39): nothing to remove
/// is the common case, and pulling the root from under a relay that is still an
/// older build makes every gate request die as `BadCertificate`. Returns whether
/// anything was actually taken out.
pub fn remove_legacy_ca_quiet() -> bool {
    let cert = proxy::ca_cert_path();
    if !cert.exists() {
        return false;
    }
    if background::relay_is_outdated() {
        return false;
    }
    endpoint::clear_node_ca(&cert.to_string_lossy()).ok();
    proxy::untrust_ca();
    true
}

/// Which product an install directory is, for the progress line.
///
/// A guess from the layout rather than the name `process_install` returns,
/// because the line is printed before the work starts - that is the whole point
/// of it.
pub fn install_label(install: &Path) -> &'static str {
    if install.join("agy.exe").is_file() || install.join("agy").is_file() {
        "Antigravity CLI"
    } else if install.join("Antigravity IDE.exe").exists()
        || install.join("resources").join("app").join("out").exists()
    {
        "Antigravity IDE"
    } else {
        "Antigravity 2.0"
    }
}

fn main() {
    #[allow(unused_mut)]
    let mut gui_replacement = false;
    #[cfg(windows)]
    let mut replacement_action = None;
    // Only the exact first role selects a host mode. In particular no argument
    // in an opaque language-server tail can enter console/GUI/service startup.
    #[cfg(windows)]
    {
        let mut args = env::args_os().skip(1);
        let role = args.next();
        if role.as_deref() == Some(std::ffi::OsStr::new("--wsl-gateway")) {
            let code = match wsl_direct_gateway_host::run(args.collect()) { Ok(()) => 0, Err(_) => 1 };
            std::process::exit(code);
        }
        if role.as_deref() == Some(std::ffi::OsStr::new("--serve-wsl")) {
            std::process::exit(vendor_runtime::serve(args.collect()));
        }
        if role.as_deref() == Some(std::ffi::OsStr::new(vendor_runtime::OWNER_ROLE)) {
            std::process::exit(vendor_runtime::owner(args.collect()));
        }
        if role.as_deref() == Some(std::ffi::OsStr::new(instances::GUI_REPLACEMENT_FLAG)) {
            replacement_action = match instances::receive_replacement(args.collect()) {
                Ok(action) => Some(action),
                Err(_) => return,
            };
            gui_replacement = true;
        }
    }
    if !gui_replacement {
    if env::args().skip(1).any(|a| {
        matches!(
            a.trim_start_matches('-').to_ascii_lowercase().as_str(),
            "about" | "license" | "licence" | "version" | "v" | "cli"
        )
    }) {
        utils::attach_parent_console();
    }

    if env::args().any(|a| a == background::FORWARDER_FLAG) {
        dns_forwarder::detach_console();
        watchdog::start();
        if let Err(e) = dns_forwarder::run() {
            dns_forwarder::log_fatal(&e);
            std::process::exit(1);
        }
        return;
    }

    if env::args().any(|a| a == background::WATCHDOG_FLAG) {
        dns_forwarder::detach_console();
        watchdog::run_forever();
        return;
    }

    if env::args().any(|a| a == background::PROXY_FLAG) {
        dns_forwarder::detach_console();
        if let Err(e) = dns_forwarder::run_proxy_service() {
            dns_forwarder::log_fatal(&e);
            std::process::exit(1);
        }
        return;
    }

    // Root's half of patching a root-owned install (`elevate`): started by
    // pkexec from the window, patches the one install named and exits.
    {
        let args: Vec<String> = env::args().collect();
        if let Some(i) = args.iter().position(|a| a == elevate::PATCH_ROOT_FLAG) {
            elevate::run_helper(args.get(i + 1).cloned());
        }
        if let Some(i) = args.iter().position(|a| a == elevate::UNPATCH_ROOT_FLAG) {
            elevate::run_unpatch_helper(args.get(i + 1).cloned());
        }
    }

    canary::handle_cli_flags();
    }

    // A window of an older release left open would keep re-applying its own
    // state under this one.
    #[cfg(windows)]
    let _settings_writer = match instances::acquire_gui_writer() {
        Ok(lease) => lease,
        Err(error) => {
            utils::message_box("Antigravity Unlocker", &format!("Окно уже открыто или передача настроек не завершена: {error}"));
            return;
        }
    };
    #[cfg(not(windows))]
    instances::close_others();

    if !gui_replacement && tui::requested() {
        run_tui(None, None);
        return;
    }
    // A server over SSH: a terminal, and nothing to draw a window into.
    #[cfg(not(target_os = "windows"))]
    if tui::only_terminal() {
        run_tui(None, None);
        return;
    }

    let lifetime = std::sync::Arc::new(ops::GuiLifetime::default());
    #[cfg(windows)]
    if let Some(action) = replacement_action {
        if lifetime.receive_action(action).is_err() { return; }
    }
    let result = gui::run(lifetime.clone());
    if let Err(e) = &result {
        // No renderer opened a window. The terminal UI carries every switch the
        // window does, so it is offered instead of a dead end: on Windows in a
        // console of its own, on Linux only when started from a terminal (a
        // double-clicked launcher has none, and gets the message instead).
        let note = format!("Окно не открылось ({e}) — работаю в терминале.");
        #[cfg(target_os = "windows")]
        if lifetime.can_start_fallback() { run_tui(Some(note), None); return; }
        #[cfg(not(target_os = "windows"))]
        {
            use std::io::IsTerminal;
            if lifetime.can_start_fallback() && std::io::stdin().is_terminal() {
                run_tui(Some(note), None);
                return;
            }
        }
        utils::message_box("Antigravity Unlocker", &format!("{e}\nПовторный интерфейс не запускается. Ожидается завершение собственных операций."));
    }
    settle_gui_lifetime(&lifetime);
    if lifetime.replacement_committed() { return; }
    if result.is_err() { std::process::exit(1); }
}

fn run_tui(note: Option<String>, hold: Option<String>) {
    let lifetime = std::sync::Arc::new(ops::GuiLifetime::default());
    if let Some(reason) = hold {
        if let Err(error) = lifetime.hold_automatic_effects(reason) {
            utils::message_box("Antigravity Unlocker", &error);
            return;
        }
    }
    let result = tui::run(note, lifetime.clone());
    settle_gui_lifetime(&lifetime);
    if lifetime.replacement_committed() { return; }
    if let Err(e) = result {
        utils::message_box("Antigravity Unlocker", &e);
        std::process::exit(1);
    }
}

fn settle_gui_lifetime(lifetime: &std::sync::Arc<ops::GuiLifetime>) {
    lifetime.request_final_retirement();
    let mut last_error = None;
    loop {
        match lifetime.finalize_exit() {
            Ok(true) => return,
            Ok(false) => {},
            Err(error) => {
                let retry = lifetime.save_retry_pending();
                if last_error.as_ref() != Some(&error) || retry {
                    let hint = if retry { "\nПосле исправления причины нажмите OK для повторной попытки закрытия." } else { "\nПроцесс удерживает незавершённую передачу; новый интерфейс не запускается." };
                    utils::message_box("Antigravity Unlocker", &format!("Завершение ещё не подтверждено: {error}{hint}"));
                    last_error = Some(error);
                    if retry { lifetime.request_final_retirement(); }
                }
            }
        }
        #[cfg(windows)]
        std::thread::sleep(wsl_runtime::OWNER_OBSERVATION_CADENCE);
        #[cfg(not(windows))]
        std::thread::sleep(Duration::from_millis(50));
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

#[cfg(all(test, windows))]
mod wsl_discovery_contract_cases {
    use super::*;
    use std::io::Write;

    pub(crate) fn fixture_dir(label: &str) -> PathBuf {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join(".scratch").join("wsl-discovery-cases-01");
        fs::create_dir_all(&parent).unwrap();
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = parent.join(format!("{}-{}-{}", label, std::process::id(), nonce));
        fs::create_dir(&dir).unwrap();
        dir
    }

    pub(crate) fn fixture_file(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    pub(crate) fn fixture_asar(path: &Path, header: &str, payload: &[u8]) {
        let size = header.len() as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&(size + 8).to_le_bytes());
        bytes.extend_from_slice(&(size + 4).to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(payload);
        fixture_file(path, &bytes);
    }

    #[test]
    fn wsl_registry_checked_complete_and_invalid_inputs() {
        assert!(receive_registry_install_candidates(b"[]\nAG_END\n").unwrap().is_empty());
        let received = receive_registry_install_candidates(br#"["C:\\Synthetic\\App"]
AG_END
"#).unwrap();
        assert_eq!(received, vec![PathBuf::from(r"C:\Synthetic\App")]);
        for bytes in [&b"[]"[..], &b"[\nAG_END"[..], &b"{}\nAG_END"[..], &b"[\xff]\nAG_END"[..], &b"[\"relative\"]\nAG_END"[..]] {
            assert!(receive_registry_install_candidates(bytes).is_err());
        }
    }

    #[test]
    fn wsl_registry_directory_locators_preserve_identity_and_reject_aliases() {
        use windows_coordinator::windows_installation::{CheckedPath, PathKind, PathPurpose, WindowsLocalPath};
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let root = fixture_dir("registry-directory-locator");
        let directory = root.join("Directory Ω");
        fs::create_dir(&directory).unwrap();
        let mut noted = directory.as_os_str().to_os_string();
        noted.push("\\");
        // Same JSON array and completion marker as ConvertTo-Json/AG_END.
        let wire = |path: &std::ffi::OsStr| {
            let mut bytes = serde_json::to_vec(&vec![path.to_str().unwrap()]).unwrap();
            bytes.extend_from_slice(b"\r\nAG_END\r\n");
            bytes
        };
        let received = receive_registry_install_directories(&wire(&noted)).unwrap();
        assert_eq!(received.len(), 1);
        let ordinary = CheckedPath::open(&directory, PathKind::Directory, PathPurpose::Source).unwrap();
        let from_notation = CheckedPath::open(Path::new(&noted), PathKind::Directory, PathPurpose::Source).unwrap();
        let from_wire = CheckedPath::open(&received[0], PathKind::Directory, PathPurpose::Source).unwrap();
        assert_eq!(ordinary.native_id(), from_notation.native_id());
        assert_eq!(ordinary.native_id(), from_wire.native_id());
        assert!(WindowsLocalPath::parse(&noted).is_err(), "generic file grammar must remain strict");
        for root in [r"C:\", "C:/"] {
            assert_eq!(WindowsLocalPath::parse_directory_locator(std::ffi::OsStr::new(root)).unwrap().as_path(), Path::new(root));
        }
        for path in [r"C:\one\\two\", r"C:\one\.\two\", r"C:\one\..\two\",
            r"C:\one:stream\", r"C:\one.\", "C:\\one \\", r"\\server\share\", r"\\?\C:\one\"] {
            assert!(WindowsLocalPath::parse_directory_locator(std::ffi::OsStr::new(path)).is_err(), "{path}");
            assert!(receive_registry_install_candidates(&wire(std::ffi::OsStr::new(path))).is_err(), "{path}");
        }
        let units = [67, 58, 92, 0xd800, 92];
        let input = std::ffi::OsString::from_wide(&units);
        let decoded = WindowsLocalPath::parse_directory_locator(&input).unwrap();
        assert_eq!(decoded.as_path().as_os_str().encode_wide().collect::<Vec<_>>(), units[..4]);
        let file = root.join("not-a-directory");
        fixture_file(&file, b"owned file must not become a directory locator");
        let mut file_notation = file.as_os_str().to_os_string();
        file_notation.push("\\");
        assert!(receive_registry_install_directories(&wire(&file_notation)).is_err());
        let absent = root.join("actually-absent");
        assert!(receive_registry_install_directories(&wire(absent.as_os_str())).unwrap().is_empty());
    }

    #[test]
    fn wsl_classifier_uses_branch_owned_anchors_and_rejects_incomplete() {
        let root = fixture_dir("layout");
        let desktop = root.join("desktop");
        fixture_file(&desktop.join("resources/app/dist/main.js"), b"main");
        fixture_file(&desktop.join("Antigravity.exe"), b"exe");
        let layout = receive_installation_layout(&desktop).unwrap();
        assert_eq!((layout.kind, layout.anchor), (InstallationKind::Desktop, desktop.join("Antigravity.exe")));
        let ide = root.join("ide");
        fixture_file(&ide.join("resources/app/out/main.js"), b"main");
        fixture_file(&ide.join("Antigravity IDE.exe"), b"exe");
        let layout = receive_installation_layout(&ide).unwrap();
        assert_eq!((layout.kind, layout.anchor), (InstallationKind::Ide, ide.join("Antigravity IDE.exe")));
        let cli = root.join("cli");
        fixture_file(&cli.join("agy.exe"), b"exe");
        let layout = receive_installation_layout(&cli).unwrap();
        assert_eq!((layout.kind, layout.anchor), (InstallationKind::Cli, cli.join("agy.exe")));
        let incomplete = root.join("incomplete");
        fixture_file(&incomplete.join("resources/app/dist/main.js"), b"main");
        assert!(receive_installation_layout(&incomplete).is_err());
        assert!(receive_installation_layout(&root.join("unknown")).is_err());
    }
}
