use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

// The only edit made to the native binaries: the protobuf field name
// `ineligible` (and `ineligible_tiers`) is renamed to a same-length nonsense
// word. Both the descriptor and the matching Go struct tag are rewritten, so
// they stay consistent; the JSON the client receives no longer carries the
// field it gates on. Same length means offsets, relocations and the PE layout
// are untouched.
//
// The literals live inside obfstr! blocks so they don't show up as plain
// strings in this binary.

fn replace_all(data: &mut [u8], from: &[u8], to: &[u8]) -> usize {
    debug_assert_eq!(from.len(), to.len());
    if data.len() < from.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + from.len() <= data.len() {
        if &data[i..i + from.len()] == from {
            data[i..i + to.len()].copy_from_slice(to);
            count += 1;
            i += from.len();
        } else {
            i += 1;
        }
    }
    count
}

fn count_occurrences(data: &[u8], needle: &[u8]) -> usize {
    if data.len() < needle.len() {
        return 0;
    }
    (0..=data.len() - needle.len())
        .filter(|&i| &data[i..i + needle.len()] == needle)
        .count()
}

/// Writes the binary back atomically: a sibling temp on the same directory, then
/// a rename over the target. A crash or power loss mid-write leaves either the
/// old binary or the new one, never a truncated 135 MB executable that would fail
/// to launch. A running executable is locked on Windows, so the owning process is
/// killed and the write retried only if the first attempt actually fails.
fn write_binary(bin_path: &Path, data: &[u8]) -> Result<(), String> {
    if write_atomic(bin_path, data).is_ok() {
        return Ok(());
    }
    kill_holder(bin_path);
    thread::sleep(Duration::from_millis(500));
    write_atomic(bin_path, data).map_err(|e| e.to_string())
}

/// Kills whatever process holds `bin_path` open so the write can be retried.
/// Windows locks a running image; Linux does not (a rename-over succeeds while
/// the old inode keeps running), so this is a belt-and-braces retry helper there.
#[cfg(target_os = "windows")]
fn kill_holder(bin_path: &Path) {
    let file_name = bin_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    Command::new("taskkill")
        .args(["/F", "/IM", &file_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok();
}

#[cfg(not(target_os = "windows"))]
fn kill_holder(bin_path: &Path) {
    let name = bin_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    if !name.is_empty() {
        Command::new("pkill")
            .args(["-f", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok();
    }
}

/// Temp-on-same-dir + rename. The temp sits beside the target so the rename is a
/// same-volume move (atomic), not a cross-volume copy.
fn write_atomic(bin_path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut tmp = bin_path.as_os_str().to_os_string();
    tmp.push(".agtmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);

    #[cfg(target_os = "macos")]
    crate::patch_ide::prepare_macos_target(bin_path);

    if let Err(e) = fs::write(&tmp, data) {
        #[cfg(target_os = "macos")]
        {
            crate::patch_ide::prepare_macos_target(bin_path);
            fs::write(&tmp, data)?;
        }
        #[cfg(not(target_os = "macos"))]
        return Err(e);
    }

    // On Unix a fresh temp file is created 0644, and renaming it over the language
    // server would strip the execute bit - a non-executable binary the app then
    // cannot launch. Copy the original's mode onto the temp before the rename so
    // the patched file stays exactly as runnable as the one it replaces. No-op on
    // Windows, where executability is not a file-mode bit.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(bin_path)
            .map(|m| m.permissions().mode())
            .unwrap_or(0o755);
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
    }
    let res = match fs::rename(&tmp, bin_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            #[cfg(target_os = "macos")]
            {
                crate::patch_ide::prepare_macos_target(bin_path);
                if fs::rename(&tmp, bin_path).is_ok() {
                    Ok(())
                } else {
                    let _ = fs::remove_file(&tmp);
                    Err(e)
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = fs::remove_file(&tmp);
                Err(e)
            }
        }
    };

    if res.is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(bin_path, fs::Permissions::from_mode(0o755));
        }

        #[cfg(target_os = "macos")]
        {
            // Re-sign the modified binary with ad-hoc signature so Apple Silicon / ARM64
            // doesn't kill it with SIGKILL upon execution (code signing violation).
            let _ = std::process::Command::new("codesign")
                .args(["--force", "-s", "-"])
                .arg(bin_path)
                .status();
        }
    }

    res
}

fn rewrite(bin_path: &Path, from: &str, to: &str) -> Result<usize, String> {
    let mut data = fs::read(bin_path).map_err(|e| e.to_string())?;
    let replaced = replace_all(&mut data, from.as_bytes(), to.as_bytes());
    if replaced == 0 {
        // Nothing to do - report whether the target state is already in place.
        return if count_occurrences(&data, to.as_bytes()) > 0 {
            Ok(0)
        } else {
            Err("Сигнатура не найдена".to_string())
        };
    }
    write_binary(bin_path, &data)?;
    Ok(replaced)
}

pub fn patch_binary(_inst: &Path, bin_path: &Path) -> Result<usize, String> {
    obfstr::obfstr! {
        let old_str = "ineligible";
        let new_str = "inexigible";
    }
    rewrite(bin_path, old_str, new_str)
}

pub fn unpatch_binary(bin_path: &Path) -> Result<usize, String> {
    obfstr::obfstr! {
        let old_str = "ineligible";
        let new_str = "inexigible";
    }
    rewrite(bin_path, new_str, old_str)
}

/// What re-patching one binary found. The background watchdog needs to tell
/// these four apart where menu 1 only needs success/failure:
///
/// - `SignatureMissing` is deliberately distinct from `Failed`. A signature
///   that is simply gone means a new or broken build this patcher does not
///   understand, and the right thing is to **leave it alone** so Antigravity
///   launches and shows its own error - that is the user's cue to fetch a newer
///   patcher. A `Failed` is transient (the file was locked mid-update) and is
///   worth retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepatchOutcome {
    /// Already patched; nothing was done.
    AlreadyPatched,
    /// Was reverted (typically by an app auto-update) and is now patched again.
    Repatched(usize),
    /// The signature is absent - do not touch it, let the app show its error.
    SignatureMissing,
    /// A transient failure, usually a file locked mid-update. Retry later.
    Failed(String),
}

/// Re-applies the rename to a binary that may have been reverted by an update.
///
/// Unlike `patch_binary`, this never conflates "nothing to patch because the
/// signature is gone" with "already patched": that distinction is the whole
/// point of the watchdog. `write_binary` still kills a process holding the file
/// open and retries, so a running-but-unpatched Language Server is replaced in
/// the same step - which is what enforces "no unpatched server keeps running"
/// without ever touching the editor shell.
pub fn repatch_if_needed(bin_path: &Path) -> RepatchOutcome {
    obfstr::obfstr! {
        let from = "ineligible";
        let to = "inexigible";
    }
    let mut data = match fs::read(bin_path) {
        Ok(d) => d,
        Err(e) => return RepatchOutcome::Failed(e.to_string()),
    };
    let replaced = replace_all(&mut data, from.as_bytes(), to.as_bytes());
    if replaced == 0 {
        return if count_occurrences(&data, to.as_bytes()) > 0 {
            RepatchOutcome::AlreadyPatched
        } else {
            RepatchOutcome::SignatureMissing
        };
    }
    match write_binary(bin_path, &data) {
        Ok(()) => RepatchOutcome::Repatched(replaced),
        Err(e) => RepatchOutcome::Failed(e),
    }
}

/// Native binaries that carry the eligibility check, for a given install root.
///
/// The list is cross-platform on purpose: a Windows install never has the Linux
/// names and vice versa, and everything is filtered by `exists()`, so one list
/// serves both. On Linux the language-server filename carries a
/// `_linux_x64`-style platform suffix that can drift between builds, so instead
/// of hardcoding it the two `bin` directories are globbed for any
/// `language_server*` file - whatever the exact suffix, the signature scan then
/// decides whether it is really a target.
pub fn binary_targets(inst: &Path) -> Vec<PathBuf> {
    let res = crate::utils::resources_dir(inst);
    let resources_bin = res.join("bin");
    let ext_bin = res
        .join("app")
        .join("extensions")
        .join("antigravity")
        .join("bin");

    let mut targets: Vec<PathBuf> = vec![
        // CLI: `agy.exe` on Windows, bare `agy` on Linux/macOS.
        inst.join("agy.exe"),
        inst.join("agy"),
        // Desktop's own language server.
        resources_bin.join("language_server.exe"),
        resources_bin.join("language_server"),
        // IDE's bundled language server, Windows-named.
        ext_bin.join("language_server_windows_x64.exe"),
        ext_bin.join("language_server.exe"),
    ];

    #[cfg(target_os = "macos")]
    {
        let macos_dir = inst.join("Contents").join("MacOS");
        targets.push(macos_dir.join("agy"));
        targets.push(macos_dir.join("language_server"));
    }

    // Any other `language_server*` in the two bin dirs - catches the Linux/macOS
    // platform-suffixed names (`language_server_linux_x64`, `..._darwin_arm64`, …)
    // without pinning the exact spelling.
    for dir in [&ext_bin, &resources_bin] {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let is_ls = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("language_server"));
                if is_ls && path.is_file() && !targets.contains(&path) {
                    targets.push(path);
                }
            }
        }
    }

    targets.retain(|p| p.exists());

    // On Unix a CLI like `agy` is frequently a symlink in a PATH dir pointing at
    // the real binary; resolve it so the patch edits the actual file, and dedup by
    // the resolved path so the same file reached two ways is not patched twice.
    #[cfg(unix)]
    {
        let mut seen = std::collections::HashSet::new();
        targets = targets
            .into_iter()
            .map(|p| fs::canonicalize(&p).unwrap_or(p))
            .filter(|p| seen.insert(p.clone()))
            .collect();
    }

    targets.dedup();
    targets
}

pub fn kill_affected_processes() {
    println!("\x1b[93m[INFO] Завершаем запущенные процессы перед патчингом...\x1b[0m\x1b[92m");
    kill_platform_processes();
    thread::sleep(Duration::from_millis(1000));
}

/// Stops the language server / CLI so their files can be replaced. Never the
/// editor shell itself - that would lose the user's unsaved work (D9).
#[cfg(target_os = "windows")]
fn kill_platform_processes() {
    let processes = [
        "Antigravity.exe",
        "Antigravity CLI.exe",
        "Antigravity IDE.exe",
        "agy.exe",
        "language_server.exe",
        "language_server_windows_x64.exe",
    ];
    for p in processes.iter() {
        Command::new("taskkill")
            .args(["/F", "/IM", p])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok();
    }
}

/// The Linux/macOS side. The language server is the process holding the file
/// open; it is matched by the binary's basename via `pkill -f` so whatever the
/// platform suffix is (`language_server_linux_x64`), it is caught. The `agy` CLI
/// and the two language-server basenames are killed; the editor shell is left
/// running, same rule as Windows.
#[cfg(not(target_os = "windows"))]
fn kill_platform_processes() {
    // -f matches against the whole command line, so a full install path still
    // matches; the patterns are the binary basenames the patcher targets.
    let patterns = ["language_server", "/agy", "Antigravity CLI"];
    for pat in patterns.iter() {
        Command::new("pkill")
            .args(["-f", pat])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok();
    }
}

/// Outcome of patching the native binaries of one install.
pub struct BinarySummary {
    /// Binaries that are now in the patched state (freshly patched or already so).
    pub ok: usize,
    /// Binaries where the signature could not be found or written.
    pub failed: usize,
    /// The last failure, so the caller can name it without this module printing.
    pub last_error: Option<String>,
}

impl BinarySummary {
    pub fn total(&self) -> usize {
        self.ok + self.failed
    }
}

pub fn patch_all_binaries(inst: &Path) -> BinarySummary {
    let mut summary = BinarySummary {
        ok: 0,
        failed: 0,
        last_error: None,
    };
    for bin in binary_targets(inst) {
        let label = bin
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // Deliberately silent. The caller prints one progress line per install
        // and then its result on the same row; a line from here lands in the
        // middle of it and pushes the result onto its own. Failures are not
        // lost - they are counted here and named by `binary_failure_message`.
        match patch_binary(inst, &bin) {
            Ok(_) => summary.ok += 1,
            Err(e) => {
                summary.failed += 1;
                summary.last_error = Some(format!("{}: {}", label, e));
            }
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_every_occurrence() {
        let mut data = b"xxineligibleyyineligible".to_vec();
        assert_eq!(replace_all(&mut data, b"ineligible", b"inexigible"), 2);
        assert_eq!(&data, b"xxinexigibleyyinexigible");
    }

    #[test]
    fn matches_at_the_very_end_of_the_buffer() {
        // The previous implementation used `0..len - needle.len()`, which
        // silently skipped a match sitting at the last possible offset.
        let mut data = b"padineligible".to_vec();
        assert_eq!(replace_all(&mut data, b"ineligible", b"inexigible"), 1);
        assert_eq!(&data, b"padinexigible");
    }

    #[test]
    fn shorter_than_needle_is_not_a_panic() {
        let mut data = b"abc".to_vec();
        assert_eq!(replace_all(&mut data, b"ineligible", b"inexigible"), 0);
        assert_eq!(count_occurrences(&data, b"ineligible"), 0);
    }

    /// The watchdog's four outcomes, on real files. The signature strings are
    /// obfuscated in the binary but plain here in the test fixtures - the point
    /// is the classification, not the literals.
    #[test]
    fn repatch_classifies_each_case() {
        let dir = std::env::temp_dir().join("ag_repatch_test");
        fs::create_dir_all(&dir).expect("temp dir");

        // Reverted by an update: contains the original field name → re-patched.
        let reverted = dir.join("reverted.bin");
        fs::write(&reverted, b"..ineligible..ineligible..").unwrap();
        assert_eq!(repatch_if_needed(&reverted), RepatchOutcome::Repatched(2));
        // And now it reads back as patched, so a second pass is a no-op.
        assert_eq!(repatch_if_needed(&reverted), RepatchOutcome::AlreadyPatched);

        // A build whose signature is gone entirely: left untouched on purpose.
        let unknown = dir.join("unknown.bin");
        fs::write(&unknown, b"a totally different binary layout").unwrap();
        assert_eq!(
            repatch_if_needed(&unknown),
            RepatchOutcome::SignatureMissing
        );
        // Crucially it was NOT modified - the app must run and show its error.
        assert_eq!(
            fs::read(&unknown).unwrap(),
            b"a totally different binary layout"
        );

        // A path that does not exist is a failure, not a missing signature:
        // "retry", never "give up and hide the error".
        match repatch_if_needed(&dir.join("nope.bin")) {
            RepatchOutcome::Failed(_) => {}
            other => panic!("expected Failed, got {:?}", other),
        }

        fs::remove_dir_all(&dir).ok();
    }

    /// End-to-end check against the installed Language Server: patch a copy,
    /// confirm the signature is found, the file size is untouched and the
    /// revert is byte-exact. Heavy (copies ~140 MB), so run it explicitly:
    ///   cargo test --bin ag_unlocker -- --ignored
    #[test]
    #[ignore]
    fn patches_and_reverts_the_installed_language_server() {
        let Ok(local) = std::env::var("LOCALAPPDATA") else {
            return;
        };
        let src = Path::new(&local)
            .join("Programs")
            .join("Antigravity")
            .join("resources")
            .join("bin")
            .join("language_server.exe");
        if !src.exists() {
            return;
        }

        let tmp = std::env::temp_dir().join("ag_unlocker_ls_patch_test.exe");
        fs::copy(&src, &tmp).expect("copy language server");
        let original = fs::read(&src).expect("read original");

        let patched = patch_binary(Path::new(""), &tmp).expect("signature found");
        assert!(patched > 0, "no occurrences replaced");
        let after = fs::read(&tmp).expect("read patched");
        assert_eq!(after.len(), original.len(), "patch changed the file size");
        assert_eq!(count_occurrences(&after, b"ineligible"), 0);
        assert_eq!(count_occurrences(&after, b"inexigible"), patched);

        // Re-running must be a no-op, not an error.
        assert_eq!(patch_binary(Path::new(""), &tmp).expect("idempotent"), 0);

        assert_eq!(unpatch_binary(&tmp).expect("revert"), patched);
        assert_eq!(fs::read(&tmp).expect("read reverted"), original);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn round_trip_restores_the_original_bytes() {
        let original = b"a ineligible b ineligible_tiers c".to_vec();
        let mut data = original.clone();
        replace_all(&mut data, b"ineligible", b"inexigible");
        assert_ne!(data, original);
        replace_all(&mut data, b"inexigible", b"ineligible");
        assert_eq!(data, original);
    }
}

/// Reverses the binary patch so an install can be returned to stock without
/// reinstalling.
pub fn unpatch_all_binaries(inst: &Path) -> usize {
    let mut reverted = 0;
    for bin in binary_targets(inst) {
        let label = bin
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        match unpatch_binary(&bin) {
            Ok(0) => println!("  [--] {} — патч не найден", label),
            Ok(n) => {
                println!("  [OK] {} — возвращено вхождений: {}", label, n);
                reverted += 1;
            }
            Err(e) => println!("  [ERR] {}: {}", label, e),
        }
    }
    reverted
}
