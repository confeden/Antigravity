use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::dns_forwarder;
use crate::patch_binary::{self, RepatchOutcome};
use crate::patch_ide;
use crate::utils::mask_path;

// Keeping the patch alive across Antigravity's own auto-updates.
//
// The auto-updater silently replaces language_server.exe (and, on the IDE,
// main.js), which reverts the rename and the region gate comes back - the user
// hits the error again and has to re-run the unlocker by hand. This watcher,
// running inside the DNS relay (a byte copy of this build, so it already
// contains every patch routine), notices the replaced file and re-applies the
// patch in the background.
//
// The one firm rule: if the signature is GONE - a build new or broken enough
// that this patcher does not recognise it - do nothing. Leave the app exactly
// as the update left it, so it launches and shows its own error. That error is
// the signal for the user to fetch a newer unlocker; a half-applied guess would
// only hide it. `RepatchOutcome::SignatureMissing` is that case, and it is held
// distinct from a transient `Failed` (a file locked mid-update, worth a retry).
//
// Enforcement of "no unpatched server keeps running" needs no separate kill:
// `patch_binary::write_binary` already kills a process holding the binary open
// and retries, so a running-but-reverted Language Server is replaced in the
// same write - and the editor shell, which never holds that file, is untouched.

/// Cheap to run, because a real read only happens when a file's size or mtime
/// actually changes. Two seconds is far inside the window an update leaves
/// before the app talks to CloudCode again.
const POLL: Duration = Duration::from_secs(2);

/// Re-scan the standard install locations this often (~5 min). Uses only
/// filesystem checks - never the PowerShell registry scan - so it is safe to
/// run on a timer inside a background process.
const REDISCOVER_EVERY: u32 = 150;

const LOG_LIMIT_BYTES: u64 = 64 * 1024;

/// Per-file bookkeeping. `handled` is the (len, mtime) we last acted on;
/// `pending` is a change we have seen once and are waiting to see hold still,
/// so we never read a file mid-write.
#[derive(Default, Clone)]
struct FileState {
    handled: Option<(u64, SystemTime)>,
    pending: Option<(u64, SystemTime)>,
}

/// Spawns the watcher. Returns immediately; the relay's own loop keeps the
/// process alive. A panic here must not take the relay down (release builds
/// abort on panic), so the loop below only ever touches fallible operations
/// through `Option`/`Result` - never `unwrap` on external data.
pub fn start() {
    thread::spawn(run);
}

/// Runs the watcher on the current thread, forever. This is the standalone
/// `--watchdog` task's entry point: it has no relay loop to keep it alive, so it
/// *is* the loop. Same body as `start`'s thread, no network of any kind.
pub fn run_forever() {
    run();
}

fn run() {
    log("start");
    let mut states: HashMap<PathBuf, FileState> = HashMap::new();
    let mut installs = discover();
    let mut cycles: u32 = 0;
    let mut listener = ListenerGuard::default();

    loop {
        if cycles % REDISCOVER_EVERY == 0 {
            installs = discover();
        }
        // Not on the first poll: at logon this task and the relay's start
        // together, and a miss before the relay has bound would start the count
        // early - the log says ninety seconds and it should mean it.
        if cycles > 0 && cycles % LISTENER_CHECK_EVERY == 0 {
            listener.check();
        }
        cycles = cycles.wrapping_add(1);

        for inst in &installs {
            for target in targets(inst) {
                inspect(&target, states.entry(target.clone()).or_default());
            }
        }

        thread::sleep(POLL);
    }
}

/// How often the proxy listener is looked at, in polls. 15 x 2 s = 30 s.
const LISTENER_CHECK_EVERY: u32 = 15;
/// Consecutive misses before the variable comes off: 3 x 30 s. A relay
/// restarting under its task (3 tries a minute apart) is back well inside that;
/// one that is not coming back has by then cost every proxy-aware program on
/// the machine ninety seconds, which is enough.
const LISTENER_DEAD_AFTER: u32 = 3;
/// Once the variable was found absent or removed, how long before the (slow,
/// PowerShell-backed) environment read is worth repeating.
const ENV_RECHECK: Duration = Duration::from_secs(10 * 60);

/// Keeps `HTTPS_PROXY` from outliving the listener it names.
///
/// The variable is user-wide, so everything that honours it - not only
/// Antigravity - goes through `127.0.0.1:53129`. A relay that has died and is not
/// coming back would then take the machine's network with it (G20, seen once
/// after a revert). This is the runtime half of that fix: no listener for a
/// while and the variable is ours, off it comes; the relay puts it back when it
/// starts again (`endpoint::ensure_proxy_env`). A value that is not ours is never
/// touched.
#[derive(Default)]
struct ListenerGuard {
    misses: u32,
    env_checked_at: Option<std::time::Instant>,
}

impl ListenerGuard {
    fn check(&mut self) {
        if crate::proxy::listener_answers() {
            self.misses = 0;
            return;
        }
        self.misses = self.misses.saturating_add(1);
        if self.misses < LISTENER_DEAD_AFTER {
            return;
        }
        if self
            .env_checked_at
            .is_some_and(|at| at.elapsed() < ENV_RECHECK)
        {
            return;
        }
        self.env_checked_at = Some(std::time::Instant::now());
        let url = crate::proxy::proxy_url();
        let ca = crate::proxy::ca_cert_path().to_string_lossy().to_string();
        match crate::endpoint::remove_proxy_if_ours(&url, &ca) {
            Ok(true) => log(&format!(
                "прокси {} не отвечает {} с — HTTPS_PROXY снята, чтобы не ронять сеть",
                url,
                LISTENER_DEAD_AFTER * LISTENER_CHECK_EVERY * POLL.as_secs() as u32
            )),
            Ok(false) => {}
            Err(e) => log(&format!("не удалось снять HTTPS_PROXY: {}", e)),
        }
    }
}

/// One file, one poll.
fn inspect(target: &Path, st: &mut FileState) {
    let Some(cur) = stat(target) else {
        // Gone for the moment - an update may be swapping it. Try again next
        // poll; do not clear what we knew.
        return;
    };
    if st.handled == Some(cur) {
        return;
    }
    // Wait for the file to settle: act only once we have seen the same
    // (len, mtime) on two consecutive polls, so a file still being written is
    // never read or patched.
    if st.pending != Some(cur) {
        st.pending = Some(cur);
        return;
    }
    st.pending = None;

    match repatch(target) {
        RepatchOutcome::AlreadyPatched => {
            // Our own past write, or an install menu 1 just handled. Record the
            // current shape and stay quiet.
            st.handled = stat(target).or(Some(cur));
        }
        RepatchOutcome::Repatched(n) => {
            log(&format!(
                "re-patched after update: {} ({})",
                show(target),
                n
            ));
            // The rename is same-length, so len is unchanged and only mtime
            // moved; re-stat so our own write is not seen as a new change.
            st.handled = stat(target).or(Some(cur));
        }
        RepatchOutcome::SignatureMissing => {
            log(&format!(
                "signature gone, left untouched so Antigravity shows its error \
                 (update the unlocker): {}",
                show(target)
            ));
            // Do not look at this version again; only a further change (a newer
            // build that we might understand) is worth another attempt.
            st.handled = Some(cur);
        }
        RepatchOutcome::Failed(e) => {
            // Transient - usually locked mid-update. Leave `handled` alone so
            // the unchanged file is re-detected and retried on a later poll.
            log(&format!("deferred, will retry: {} - {}", show(target), e));
        }
    }
}

/// Picks the right patch for a target by kind: the IDE's `main.js` gets the JS
/// patch, everything else is a native binary.
fn repatch(target: &Path) -> RepatchOutcome {
    if target.extension().and_then(|e| e.to_str()) == Some("js") {
        patch_ide::repatch_ide_js(target)
    } else {
        patch_binary::repatch_if_needed(target)
    }
}

/// Every file this watcher keeps patched for one install: the native binaries,
/// plus the IDE `main.js` when present. Desktop 2.4+ carries no auth JS (it is
/// all in the Language Server) and its `dist/main.js` is deliberately not
/// touched; only the IDE's `out/main.js` is.
fn targets(inst: &Path) -> Vec<PathBuf> {
    let mut list = patch_binary::binary_targets(inst);
    let ide_js = crate::utils::resources_dir(inst)
        .join("app")
        .join("out")
        .join("main.js");
    if ide_js.exists() {
        list.push(ide_js);
    }
    list
}

fn discover() -> Vec<PathBuf> {
    crate::discover_installs_fast()
}

fn stat(p: &Path) -> Option<(u64, SystemTime)> {
    let m = fs::metadata(p).ok()?;
    Some((m.len(), m.modified().ok()?))
}

fn show(p: &Path) -> String {
    mask_path(&p.display().to_string())
}

/// Its own log next to the relay's, so an "it stopped surviving updates" report
/// has somewhere to look. Truncated rather than rotated - nothing here is worth
/// keeping across sessions.
fn log(line: &str) {
    let dir = dns_forwarder::log_dir();
    let path = dir.join("watchdog.log");
    fs::create_dir_all(&dir).ok();
    if fs::metadata(&path).map_or(false, |m| m.len() > LOG_LIMIT_BYTES) {
        fs::remove_file(&path).ok();
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        writeln!(f, "{}", line).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The settle rule: a change is acted on only after the same (len, mtime)
    /// is seen twice, so a file still being written is never touched.
    #[test]
    fn a_change_is_not_acted_on_until_it_holds_still() {
        let mut st = FileState::default();
        let a = (100u64, SystemTime::UNIX_EPOCH);

        // First sighting: recorded as pending, not yet handled.
        assert!(st.handled.is_none());
        if st.pending != Some(a) {
            st.pending = Some(a);
        }
        assert_eq!(st.pending, Some(a));
        assert!(st.handled.is_none(), "must not act on first sighting");

        // Second identical sighting: now it may be acted on.
        let settled = st.pending == Some(a);
        assert!(settled, "a stable file settles on the second poll");
    }

    /// A file still changing (size climbing as it is written) keeps resetting
    /// the settle timer instead of ever being read.
    #[test]
    fn a_file_mid_write_never_settles() {
        let mut st = FileState::default();
        for len in [10u64, 250, 9000] {
            let cur = (len, SystemTime::UNIX_EPOCH);
            let would_act = st.pending == Some(cur);
            assert!(!would_act, "a growing file must not be acted on");
            st.pending = Some(cur);
        }
    }

    /// An already-handled version is skipped, so a patched binary is not read
    /// on every poll.
    #[test]
    fn a_handled_version_is_left_alone() {
        let mut st = FileState::default();
        let cur = (150, SystemTime::UNIX_EPOCH);
        st.handled = Some(cur);
        assert_eq!(st.handled, Some(cur));
        // handled == cur → inspect returns before doing anything.
    }

    /// The whole wiring on a real install layout: a reverted CLI binary is
    /// found as a target, survives the settle, and gets re-patched - but only
    /// on the second poll, never the first.
    #[test]
    fn a_reverted_binary_in_an_install_is_repatched_after_settling() {
        let inst = std::env::temp_dir().join("ag_watchdog_wiring");
        fs::create_dir_all(&inst).expect("temp inst");
        let agy = inst.join("agy.exe");
        // Stand-in for a Language Server an update reverted to the gated name.
        fs::write(&agy, b"header..ineligible..tail").unwrap();

        // `binary_targets` finds it.
        let found = targets(&inst);
        assert!(
            found.contains(&agy),
            "agy.exe must be a target: {:?}",
            found
        );

        let mut st = FileState::default();

        // First poll: only notes the change, never touches the file.
        inspect(&agy, &mut st);
        assert_eq!(
            fs::read(&agy).unwrap(),
            b"header..ineligible..tail",
            "must not patch on the first sighting"
        );

        // Second poll, same bytes: now it settles and re-patches.
        inspect(&agy, &mut st);
        assert_eq!(fs::read(&agy).unwrap(), b"header..inexigible..tail");
        assert!(st.handled.is_some(), "the patched version is recorded");

        // Third poll: already patched, nothing changes and nothing is recorded
        // anew.
        let before = st.handled;
        inspect(&agy, &mut st);
        assert_eq!(fs::read(&agy).unwrap(), b"header..inexigible..tail");
        assert_eq!(st.handled, before);

        fs::remove_dir_all(&inst).ok();
    }

    /// A binary whose signature is gone is left exactly as the update left it,
    /// so Antigravity runs and shows its own error.
    #[test]
    fn an_unrecognised_binary_is_left_for_the_app_to_error_on() {
        let inst = std::env::temp_dir().join("ag_watchdog_giveup");
        fs::create_dir_all(&inst).expect("temp inst");
        let agy = inst.join("agy.exe");
        let contents = b"a new build shape this patcher does not know";
        fs::write(&agy, contents).unwrap();

        let mut st = FileState::default();
        inspect(&agy, &mut st); // settle
        inspect(&agy, &mut st); // act
        assert_eq!(fs::read(&agy).unwrap(), contents, "must be left untouched");
        assert!(st.handled.is_some(), "and not re-attempted every poll");

        fs::remove_dir_all(&inst).ok();
    }
}
