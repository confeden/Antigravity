use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

// Two edits are made to the native binaries, both same-length renames of a
// string literal. Same length means offsets, relocations and the PE layout are
// untouched, and the revert is byte-exact.
//
// 1. The protobuf field name `ineligible` (and `ineligible_tiers`) becomes a
//    same-length nonsense word. Both the descriptor and the matching Go struct
//    tag are rewritten, so they stay consistent; the JSON the client receives no
//    longer carries the field it gates on. This one is the patch - without it
//    nothing works, so a build where it does not match is a failure.
//
// 2. The environment variable the language server reads its proxy from is
//    renamed to a private name (`PROXY_VAR_*` below). This one is additive: a
//    build where it does not match still unlocks, it just has no local-proxy
//    route, so it is counted and reported, never fatal.
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
pub fn kill_holder(bin_path: &Path) {
    let file_name = bin_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let mut cmd = Command::new("taskkill");
    cmd.args(["/F", "/IM", &file_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    crate::utils::no_window(&mut cmd).output().ok();
}

#[cfg(not(target_os = "windows"))]
pub fn kill_holder(bin_path: &Path) {
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
    fs::write(&tmp, data)?;
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
    match fs::rename(&tmp, bin_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// The field name rewrites stored in obfuscated literals.
pub(crate) fn field_signatures() -> ([u8; 10], [u8; 10]) {
    obfstr::obfstr! {
        let from = "ineligible";
        let to = "inexigible";
    }
    let mut f = [0u8; 10];
    let mut t = [0u8; 10];
    f.copy_from_slice(from.as_bytes());
    t.copy_from_slice(to.as_bytes());
    (f, t)
}

/// The original proxy variable name stored in an obfuscated literal.
pub(crate) fn proxy_var_original() -> [u8; 11] {
    obfstr::obfstr! {
        let proxy_from = "https_proxy";
    }
    let mut p = [0u8; 11];
    p.copy_from_slice(proxy_from.as_bytes());
    p
}

fn rewrite(bin_path: &Path, from: &[u8], to: &[u8]) -> Result<usize, String> {
    let mut data = fs::read(bin_path).map_err(|e| e.to_string())?;
    let replaced = replace_all(&mut data, from, to);
    if replaced == 0 {
        // Nothing to do - report whether the target state is already in place.
        return if count_occurrences(&data, to) > 0 {
            Ok(0)
        } else {
            Err("Сигнатура не найдена".to_string())
        };
    }
    write_binary(bin_path, &data)?;
    Ok(replaced)
}

pub fn patch_binary(_inst: &Path, bin_path: &Path) -> Result<usize, String> {
    let (old_bytes, new_bytes) = field_signatures();
    rewrite(bin_path, &old_bytes, &new_bytes)
}

pub fn unpatch_binary(bin_path: &Path) -> Result<usize, String> {
    let (old_bytes, new_bytes) = field_signatures();
    rewrite(bin_path, &new_bytes, &old_bytes)
}

/// The name the patched language server reads its proxy URL from, in place of
/// the standard lower-case `https_proxy`.
///
/// **Why this exists.** The local gate proxy is only useful if the language
/// server points at it, and the only channel a Go program offers is a proxy
/// variable in its environment. Nothing spawns the server for us - the IDE and
/// the Desktop shell do - so up to `2.11.0_4` the tool wrote `HTTPS_PROXY` into
/// the *user* environment, and every program on the machine that honours it
/// went through `127.0.0.1:53129` as well: shells, git, npm, package managers.
/// That breadth is what D14 accepted as a cost and what the owner rejected on
/// 2026-09-07 ("мешает в системе"). It is also what made a dead listener a
/// machine-wide outage (G20, G31) rather than an Antigravity one.
///
/// **Why a rename is the whole fix.** `golang.org/x/net/http/httpproxy` reads
/// `getEnvAny("HTTPS_PROXY", "https_proxy")` - two literals, both present in the
/// binary, and the language server carries a second copy of the pair in its own
/// code. Renaming the **lower-case** one hands this tool a channel that nothing
/// else on the machine reads. Windows environment lookups are case-insensitive
/// (`GetEnvironmentVariable`), so the upper-case literal still answers for either
/// spelling and a user's own `HTTPS_PROXY` keeps working untouched.
///
/// **Measured, not assumed** (`tools/proxyvar_probe.py`, 2026-09-07, LS 1.11.0).
/// The server logs the proxy it dialled per request, so all five runs are read
/// off `cloudcode-pa.googleapis.com` itself rather than off whichever telemetry
/// client happened to fire first:
///
/// | binary  | variables set              | gate host went via |
/// |---------|----------------------------|--------------------|
/// | stock   | `HTTPS_PROXY`              | that proxy         |
/// | stock   | `AG_LS_PROXY`              | direct - inert     |
/// | patched | `AG_LS_PROXY`              | **ours**           |
/// | patched | `HTTPS_PROXY`              | theirs - unbroken  |
/// | patched | both                       | **ours**           |
///
/// The last row corrects the reasoning this was built on. The order in
/// `getEnvAny` suggested `HTTPS_PROXY` would win when both are set; it does not,
/// because the copy that actually resolves the gate client's proxy consults the
/// lower-case name first. So the rename does not merely add a channel, it takes
/// **precedence** over a proxy the user set. That makes `foreign_proxy` load
/// bearing rather than cosmetic: `reconcile_gate_proxy` and `ensure_proxy_env`
/// must remove ours whenever one of theirs appears, and both do.
///
/// On Linux, where the environment is case-sensitive, a user who sets *only* the
/// lower-case `https_proxy` loses it inside the language server. That is the one
/// accepted regression.
///
/// Same length as the name it replaces, so this is the same class of edit as the
/// eligibility rename: no relocation moves, no size change, byte-exact revert.
pub const PROXY_VAR_NEW: &str = "AG_LS_PROXY";

/// Points the language server's proxy lookup at [`PROXY_VAR_NEW`].
///
/// Additive, so unlike `patch_binary` a miss is not fatal - `Ok(0)` when the
/// binary is already renamed, `Err` only when neither name is present, which
/// callers report rather than treat as a failed patch.
pub fn patch_proxy_var(bin_path: &Path) -> Result<usize, String> {
    let old_bytes = proxy_var_original();
    rewrite(bin_path, &old_bytes, PROXY_VAR_NEW.as_bytes())
}

/// Puts the standard name back.
pub fn unpatch_proxy_var(bin_path: &Path) -> Result<usize, String> {
    let old_bytes = proxy_var_original();
    rewrite(bin_path, PROXY_VAR_NEW.as_bytes(), &old_bytes)
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
    let (from, to) = field_signatures();
    let proxy_from = proxy_var_original();
    let mut data = match fs::read(bin_path) {
        Ok(d) => d,
        Err(e) => return RepatchOutcome::Failed(e.to_string()),
    };
    let replaced = replace_all(&mut data, &from, &to);
    // Both renames ride in one read and one write. An update restores both at
    // once, and a machine upgrading from a build that only knew the first one
    // gets the second here without a second pass over 150 MB.
    let proxy = replace_all(&mut data, &proxy_from, PROXY_VAR_NEW.as_bytes());
    if replaced == 0 {
        if count_occurrences(&data, &to) == 0 {
            return RepatchOutcome::SignatureMissing;
        }
        // The patch is in place; only the proxy channel was missing. Write for
        // that alone, but report what the watchdog cares about: nothing about
        // the unlock itself changed.
        //
        // `write_atomic`, deliberately not `write_binary`: the latter answers a
        // locked file by killing whatever holds it, and this edit is additive -
        // the server is unlocked and working, it just has no local-proxy route
        // yet. Killing a running language server mid-session for that is a worse
        // outcome than waiting; the file settles and the next poll retries.
        if proxy > 0 {
            let _ = write_atomic(bin_path, &data);
        }
        return RepatchOutcome::AlreadyPatched;
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
    let resources_bin = inst.join("resources").join("bin");
    let ext_bin = inst
        .join("resources")
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

/// Closes Antigravity before a patch run.
///
/// Silent: the only caller left is the window's worker thread, which has no
/// console to print to and reports the step in the log pane itself. The one
/// second afterwards is functional, not cosmetic — `taskkill` returns before the
/// image handle is actually released.
pub fn kill_affected_processes() {
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
        let mut cmd = Command::new("taskkill");
        cmd.args(["/F", "/IM", p])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        crate::utils::no_window(&mut cmd).output().ok();
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
    let patterns = ["language_server", "/agy"];
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
    /// Binaries that now read the private proxy variable ([`PROXY_VAR_NEW`]).
    ///
    /// Tracked separately because it is the precondition for writing that
    /// variable at all: a build whose proxy literal this patcher does not
    /// recognise would otherwise get a variable no process ever reads, and the
    /// local-proxy route would be silently dead rather than reported.
    pub proxy_var: usize,
    /// True when a proxy-var rename failed for a reason that is **not** "the
    /// literal is not in this build".
    ///
    /// The two need telling apart because they need opposite advice. A missing
    /// literal means a new Antigravity this patcher does not understand: the
    /// user needs a newer unlocker. A locked file - antivirus holding
    /// `language_server.exe`, a denied write - means "close Antigravity and run
    /// it again". Reporting the second as the first sends the user looking for
    /// an update that does not exist.
    pub proxy_var_retryable: bool,
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
        proxy_var: 0,
        proxy_var_retryable: false,
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
        // Additive and separately judged: a binary whose proxy literal is not
        // where this build expects it is still unlocked, so it never touches
        // `failed`. `Ok(0)` is "already renamed", which counts as carrying it.
        match patch_proxy_var(&bin) {
            Ok(_) => summary.proxy_var += 1,
            // `rewrite` says "Сигнатура не найдена" for a literal that is not
            // there and anything else for an I/O problem. Only the second is
            // worth telling the user to retry.
            Err(e) if !e.contains("Сигнатура") => summary.proxy_var_retryable = true,
            Err(_) => {}
        }
    }
    summary
}

/// What a read-only look at one install found. Nothing here writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    /// The patched name is present - this file is done.
    Patched,
    /// The original name is present and the patched one is not.
    Unpatched,
    /// Neither name is there: a build we do not know how to patch.
    SignatureMissing,
    /// Could not be read at all (missing file, permissions).
    Unreadable(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallState {
    pub files: Vec<(std::path::PathBuf, FileState)>,
}

#[allow(dead_code)]
impl InstallState {
    /// True only when every native binary we know about is patched.
    pub fn fully_patched(&self) -> bool {
        !self.files.is_empty()
            && self
                .files
                .iter()
                .all(|(_, state)| *state == FileState::Patched)
    }

    /// True when some are patched and some are not - what an interrupted run
    /// or a half-finished auto-update leaves behind.
    pub fn partially_patched(&self) -> bool {
        let has_patched = self
            .files
            .iter()
            .any(|(_, state)| *state == FileState::Patched);
        let has_not_patched = self
            .files
            .iter()
            .any(|(_, state)| *state != FileState::Patched);
        has_patched && has_not_patched
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

const INSPECT_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB stream buffer

fn contains_subslice(data: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if data.len() < needle.len() {
        return false;
    }
    // First-byte skip rather than `windows(k).any(..)`. The Language Server is
    // ~150 MB and this runs over the whole of it twice per install, so the naive
    // form costs a comparison per byte per needle; anchoring on the first byte
    // turns almost all of them into one.
    let first = needle[0];
    let last = data.len() - needle.len();
    let mut i = 0;
    while i <= last {
        match data[i..=last].iter().position(|b| *b == first) {
            Some(off) => {
                let at = i + off;
                if &data[at..at + needle.len()] == needle {
                    return true;
                }
                i = at + 1;
            }
            None => return false,
        }
    }
    false
}

/// Inspects one binary file on disk in a streaming manner using a 1 MiB buffer
/// with overlap to prevent missing matches at buffer boundaries.
#[allow(dead_code)]
pub fn inspect_file(bin_path: &Path) -> FileState {
    inspect_file_stream(bin_path, INSPECT_CHUNK_SIZE)
}

fn inspect_file_stream(bin_path: &Path, chunk_size: usize) -> FileState {
    let (unpatched, patched) = field_signatures();
    let max_needle = unpatched.len().max(patched.len());
    let overlap_len = max_needle.saturating_sub(1);

    let mut file = match fs::File::open(bin_path) {
        Ok(f) => f,
        Err(e) => return FileState::Unreadable(e.to_string()),
    };

    use std::io::Read;
    let mut buf = vec![0u8; chunk_size.max(max_needle)];
    let mut overlap = 0;
    let mut found_unpatched = false;

    loop {
        let mut bytes_read = 0;
        while overlap + bytes_read < buf.len() {
            match file.read(&mut buf[overlap + bytes_read..]) {
                Ok(0) => break,
                Ok(n) => bytes_read += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return FileState::Unreadable(e.to_string()),
            }
        }

        if bytes_read == 0 {
            break;
        }

        let valid_len = overlap + bytes_read;
        let slice = &buf[..valid_len];
        if contains_subslice(slice, &patched) {
            return FileState::Patched;
        }
        if !found_unpatched && contains_subslice(slice, &unpatched) {
            found_unpatched = true;
        }

        if overlap + bytes_read < buf.len() {
            break;
        }

        overlap = overlap_len.min(valid_len);
        buf.copy_within(valid_len - overlap..valid_len, 0);
    }

    if found_unpatched {
        FileState::Unpatched
    } else {
        FileState::SignatureMissing
    }
}

/// Reads every native binary of one install and reports whether each carries the
/// patched name. Read-only: opens files for reading, writes nothing, spawns no
/// child process, kills no process.
#[allow(dead_code)]
pub fn inspect_install(install: &std::path::Path) -> InstallState {
    let targets = binary_targets(install);
    let mut files = Vec::with_capacity(targets.len());
    for target in targets {
        let state = inspect_file(&target);
        files.push((target, state));
    }
    InstallState { files }
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
    ///
    /// The copy is reverted to stock first. Any machine that has actually run
    /// this tool has an already-patched Language Server, and without that step
    /// the test only ever passed on a pristine install - which is the machine
    /// least likely to be running it.
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
        unpatch_proxy_var(&tmp).ok();
        unpatch_binary(&tmp).ok();
        let original = fs::read(&tmp).expect("read stock copy");
        assert!(
            count_occurrences(&original, b"ineligible") > 0,
            "could not get the copy back to stock"
        );

        let patched = patch_binary(Path::new(""), &tmp).expect("signature found");
        assert!(patched > 0, "no occurrences replaced");
        let after = fs::read(&tmp).expect("read patched");
        assert_eq!(after.len(), original.len(), "patch changed the file size");
        assert_eq!(count_occurrences(&after, b"ineligible"), 0);
        assert_eq!(count_occurrences(&after, b"inexigible"), patched);

        // The proxy channel, on the real Go binary: the lower-case literal that
        // `httpproxy.getEnvAny` reads second is renamed, the upper-case one it
        // reads first is left for the user, and nothing else moves.
        let proxied = patch_proxy_var(&tmp).expect("proxy literal found");
        assert!(proxied > 0, "no proxy literal replaced");
        let after = fs::read(&tmp).expect("read patched");
        assert_eq!(after.len(), original.len(), "proxy rename changed the size");
        assert_eq!(count_occurrences(&after, b"https_proxy"), 0);
        assert_eq!(
            count_occurrences(&after, b"HTTPS_PROXY"),
            count_occurrences(&original, b"HTTPS_PROXY"),
            "the user's own variable name must be untouched"
        );

        // Re-running must be a no-op, not an error.
        assert_eq!(patch_binary(Path::new(""), &tmp).expect("idempotent"), 0);
        assert_eq!(patch_proxy_var(&tmp).expect("idempotent"), 0);

        assert_eq!(unpatch_proxy_var(&tmp).expect("revert proxy"), proxied);
        assert_eq!(unpatch_binary(&tmp).expect("revert"), patched);
        assert_eq!(fs::read(&tmp).expect("read reverted"), original);

        let _ = fs::remove_file(&tmp);
    }

    /// The whole edit rests on the two names being the same length: a byte
    /// longer and every offset after it in a 150 MB PE moves. Cheap to assert,
    /// impossible to notice by eye when someone renames the variable.
    #[test]
    fn the_private_proxy_name_is_the_same_length_as_the_one_it_replaces() {
        assert_eq!(PROXY_VAR_NEW.len(), "https_proxy".len());
        // Upper-case `HTTPS_PROXY` stays untouched on purpose: it is looked up
        // first, so a proxy the user set themselves still wins (I54). The name
        // the tool writes is this same constant by definition
        // (`endpoint::PROXY_ENV_VAR`), so the two cannot drift apart.
        assert_ne!(PROXY_VAR_NEW, "HTTPS_PROXY");
        assert_ne!(PROXY_VAR_NEW, crate::endpoint::LEGACY_PROXY_ENV_VAR);
    }

    /// Both renames on one buffer, and back. The proxy rename must not disturb
    /// the eligibility one, and the revert must be byte-exact - the file is a
    /// signed-by-nobody 150 MB executable and a stray byte is unlaunchable.
    #[test]
    fn the_proxy_rename_round_trips_beside_the_eligibility_one() {
        let dir = std::env::temp_dir().join("ag_proxyvar_test");
        fs::create_dir_all(&dir).expect("temp dir");
        let bin = dir.join("both.bin");
        let original = b"..ineligible..https_proxy..HTTPS_PROXY..https_proxy..".to_vec();
        fs::write(&bin, &original).unwrap();

        assert_eq!(patch_binary(Path::new(""), &bin).expect("gate"), 1);
        assert_eq!(patch_proxy_var(&bin).expect("proxy var"), 2);
        let after = fs::read(&bin).unwrap();
        assert_eq!(after.len(), original.len(), "size changed");
        assert_eq!(count_occurrences(&after, b"https_proxy"), 0);
        assert_eq!(
            count_occurrences(&after, b"HTTPS_PROXY"),
            1,
            "the user's own variable name must survive"
        );
        // Re-running either one is a no-op, not an error.
        assert_eq!(patch_proxy_var(&bin).expect("idempotent"), 0);

        assert_eq!(unpatch_proxy_var(&bin).expect("revert proxy"), 2);
        assert_eq!(unpatch_binary(&bin).expect("revert gate"), 1);
        assert_eq!(fs::read(&bin).unwrap(), original);

        fs::remove_dir_all(&dir).ok();
    }

    /// A build whose proxy literal is missing is not a failed patch: the unlock
    /// still applies, only the local-proxy route is unavailable, and the caller
    /// has to be able to tell those apart to avoid writing a dead variable.
    #[test]
    fn a_missing_proxy_literal_is_an_error_not_a_silent_success() {
        let dir = std::env::temp_dir().join("ag_proxyvar_missing_test");
        fs::create_dir_all(&dir).expect("temp dir");
        let bin = dir.join("gate_only.bin");
        fs::write(&bin, b"..ineligible..").unwrap();

        assert!(patch_binary(Path::new(""), &bin).is_ok());
        assert!(patch_proxy_var(&bin).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    /// The watchdog's job after an update that restored both names, and after an
    /// upgrade from a build that only knew the eligibility one.
    #[test]
    fn repatch_restores_the_proxy_name_too() {
        let dir = std::env::temp_dir().join("ag_repatch_proxy_test");
        fs::create_dir_all(&dir).expect("temp dir");

        // An update put the stock binary back: both names are stock again.
        let updated = dir.join("updated.bin");
        fs::write(&updated, b"..ineligible..https_proxy..").unwrap();
        assert_eq!(repatch_if_needed(&updated), RepatchOutcome::Repatched(1));
        assert_eq!(
            count_occurrences(&fs::read(&updated).unwrap(), b"https_proxy"),
            0
        );

        // Patched by <= 2.11.0_4: unlocked, but on the stock proxy channel. The
        // unlock is unchanged, so the outcome stays `AlreadyPatched`, and the
        // proxy name is fixed up in the same pass.
        let legacy = dir.join("legacy.bin");
        fs::write(&legacy, b"..inexigible..https_proxy..").unwrap();
        assert_eq!(repatch_if_needed(&legacy), RepatchOutcome::AlreadyPatched);
        let after = fs::read(&legacy).unwrap();
        assert_eq!(count_occurrences(&after, b"https_proxy"), 0);
        assert_eq!(count_occurrences(&after, PROXY_VAR_NEW.as_bytes()), 1);
        // And a second pass writes nothing more.
        assert_eq!(repatch_if_needed(&legacy), RepatchOutcome::AlreadyPatched);
        assert_eq!(fs::read(&legacy).unwrap(), after);

        fs::remove_dir_all(&dir).ok();
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

    #[test]
    fn inspect_matches_across_buffer_boundary() {
        let dir = std::env::temp_dir().join("ag_inspect_boundary_test");
        fs::create_dir_all(&dir).expect("temp dir");

        let chunk_size = 1024 * 1024;
        let file_len = chunk_size + 100;
        let mut data = vec![b'x'; file_len];

        let offset = chunk_size - 5;
        data[offset..offset + 10].copy_from_slice(b"inexigible");

        let bin = dir.join("boundary_patched.bin");
        fs::write(&bin, &data).expect("write file");
        assert_eq!(inspect_file(&bin), FileState::Patched);

        data[offset..offset + 10].copy_from_slice(b"ineligible");
        let bin_unpatched = dir.join("boundary_unpatched.bin");
        fs::write(&bin_unpatched, &data).expect("write file");
        assert_eq!(inspect_file(&bin_unpatched), FileState::Unpatched);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inspect_missing_signature_when_neither_present() {
        let dir = std::env::temp_dir().join("ag_inspect_missing_test");
        fs::create_dir_all(&dir).expect("temp dir");
        let bin = dir.join("neither.bin");
        fs::write(&bin, b"some content without any known signatures").expect("write");

        assert_eq!(inspect_file(&bin), FileState::SignatureMissing);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inspect_unreadable_on_nonexistent_path() {
        let missing = PathBuf::from("this_file_definitely_does_not_exist_xyz_12345.exe");
        match inspect_file(&missing) {
            FileState::Unreadable(reason) => {
                assert!(!reason.is_empty(), "reason should not be empty");
            }
            other => panic!("expected FileState::Unreadable, got {:?}", other),
        }
    }

    #[test]
    fn install_state_evaluates_fully_and_partially_patched() {
        // Empty
        let empty = InstallState { files: vec![] };
        assert!(empty.is_empty());
        assert!(!empty.fully_patched());
        assert!(!empty.partially_patched());

        // All patched
        let all_patched = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Patched),
                (PathBuf::from("b.exe"), FileState::Patched),
            ],
        };
        assert!(!all_patched.is_empty());
        assert!(all_patched.fully_patched());
        assert!(!all_patched.partially_patched());

        // None patched (all unpatched)
        let all_unpatched = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Unpatched),
                (PathBuf::from("b.exe"), FileState::Unpatched),
            ],
        };
        assert!(!all_unpatched.fully_patched());
        assert!(!all_unpatched.partially_patched());

        // Some patched, some unpatched
        let mixed = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Patched),
                (PathBuf::from("b.exe"), FileState::Unpatched),
            ],
        };
        assert!(!mixed.fully_patched());
        assert!(mixed.partially_patched());

        // Some patched, some signature missing
        let mixed_missing = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Patched),
                (PathBuf::from("b.exe"), FileState::SignatureMissing),
            ],
        };
        assert!(!mixed_missing.fully_patched());
        assert!(mixed_missing.partially_patched());

        // Some patched, some unreadable
        let mixed_unreadable = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Patched),
                (
                    PathBuf::from("b.exe"),
                    FileState::Unreadable("locked".to_string()),
                ),
            ],
        };
        assert!(!mixed_unreadable.fully_patched());
        assert!(mixed_unreadable.partially_patched());
    }
}

/// Reverses the binary patch so an install can be returned to stock without
/// reinstalling.
/// Reverts every native binary of one install and reports each outcome.
///
/// Returns results rather than a count, and prints nothing: a count cannot say
/// that one file failed, and the caller used to read "reverted 1 of 2" as a
/// clean revert. The window has no console for the difference to appear on
/// either.
pub fn unpatch_all_binaries(inst: &Path) -> Vec<(String, Result<usize, String>)> {
    let mut results = Vec::new();
    for bin in binary_targets(inst) {
        let label = bin
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // The proxy rename first: it is the one that stops the binary reading
        // our variable, and a revert that failed halfway should at least leave
        // the language server on the stock proxy channel. Silent - a build that
        // never carried it is not an error to report.
        unpatch_proxy_var(&bin).ok();
        results.push((label, unpatch_binary(&bin)));
    }
    results
}
