use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::dns_forwarder;
use crate::patch_binary::{self, RepatchOutcome};
use crate::patch_ide;
use crate::utils::mask_path;

// Keeping Antigravity patched: after its own auto-updates, and from the moment
// it is installed.
//
// The auto-updater silently replaces language_server.exe (and, on the IDE,
// main.js), which reverts the rename and the region gate comes back - the user
// hits the error again and has to re-run the unlocker by hand. This watcher,
// running inside the DNS relay (a byte copy of this build, so it already
// contains every patch routine), notices the replaced file and re-applies the
// patch in the background.
//
// A fresh install is the same case to this code - an unpatched binary nobody
// asked it to leave alone - and since D27 it is treated the same way. It was
// not before: the watcher also waited for the user to have patched once, so a
// Desktop installed or restored after that point stayed unpatched with
// auto-patch on, and an unpatched Desktop 2.15.0 can take longer to come up than
// its window waits for the page (30 s) - a black window. The only thing that
// stops it is the user having switched the patch off by hand (`patch_declined`).
//
// The one firm rule: if the signature is GONE - a build new or broken enough
// that this patcher does not recognise it - do nothing. Leave the app exactly
// as the update left it, so it launches and shows its own error. That error is
// the signal for the user to fetch a newer unlocker; a half-applied guess would
// only hide it. `RepatchOutcome::SignatureMissing` is that case, and it is held
// distinct from a transient `Failed` (a file locked mid-update, worth a retry).
//
// Windows writes require canonical native-file admission. A busy file remains
// held until its application closes normally; this watcher owns no native
// process termination capability. Unix retains its existing writer behavior.

/// Cheap to run, because a real read only happens when a file's size or mtime
/// actually changes. Two seconds is far inside the window an update leaves
/// before the app talks to CloudCode again.
const POLL: Duration = Duration::from_secs(2);

/// Re-scan the standard install locations (and the user's own paths) this
/// often, in polls: 5 x 2 s = 10 s. Uses only filesystem checks - never the
/// PowerShell registry scan - so it is safe to run on a timer inside a
/// background process, and cheap enough to run this often.
///
/// Was five minutes, when the only case was an update to an install already on
/// the list. A fresh install is a new root, and Antigravity's installer starts
/// the app the moment it finishes: every second of discovery is a second the app
/// runs unpatched, and it is found locked in use when the patch does arrive.
const REDISCOVER_EVERY: u32 = 5;

const LOG_LIMIT_BYTES: u64 = 64 * 1024;

/// Per-file bookkeeping. `handled` is the (len, mtime) we last acted on;
/// `pending` is a change we have seen once and are waiting to see hold still,
/// so we never read a file mid-write.
#[derive(Default, Clone)]
struct FileState {
    handled: Option<(u64, SystemTime)>,
    pending: Option<(u64, SystemTime)>,
    /// How many times the patch has been deferred *for this exact file shape*
    /// because it was in use, and which shape that was.
    ///
    /// The shape is part of the state on purpose. Acting clears `pending`, so
    /// the next poll always takes the "a change I have not seen before" branch —
    /// and a counter reset there is a counter that never reaches its limit. That
    /// is a `taskkill` every four seconds, for ever.
    blocked: u32,
    blocked_for: Option<(u64, SystemTime)>,
}

/// How many times a settled-but-locked target is worth closing the app for.
///
/// The point is to hold the *launch*, not to fight the user: the update itself
/// is never interrupted (a file mid-write never settles, so this code is not
/// even reached), and after this many tries the app is left alone unpatched
/// rather than being killed forever.
const MAX_LAUNCH_HOLDS: u32 = 3;

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
    let mut updaters = updater_dirs();
    let mut fast_until: Option<Instant> = None;
    let mut fast_polls: u32 = 0;
    #[cfg(windows)]
    let mut vendor_states: HashMap<PathBuf, VendorWatchState> = HashMap::new();

    loop {
        // An update being installed is the one moment a poll every two seconds
        // is too slow: the installer starts the new app the instant it has
        // written the files, and the app starts its Language Server at once.
        // While a downloaded update is staged (and for a minute after it goes)
        // the files are looked at every 150 ms instead.
        if updater_busy(&updaters) {
            fast_until = Some(Instant::now() + FAST_FOR);
        }
        let fast = fast_until.is_some_and(|t| Instant::now() < t);
        if fast {
            fast_polls = fast_polls.wrapping_add(1);
            if fast_polls % FAST_REDISCOVER_EVERY == 0 {
                installs = discover();
                updaters = updater_dirs();
            }
            if crate::settings::auto_patch_wanted() {
                #[cfg(windows)]
                inspect_vendor_updates(&installs, &mut vendor_states);
                for inst in &installs {
                    for target in targets(inst) {
                        inspect(&target, states.entry(target.clone()).or_default());
                    }
                }
            }
            thread::sleep(FAST_POLL);
            continue;
        }
        if cycles % REDISCOVER_EVERY == 0 {
            installs = discover();
            updaters = updater_dirs();
        }
        // Not on the first poll: at logon this task and the relay's start
        // together, and a miss before the relay has bound would start the count
        // early - the log says ninety seconds and it should mean it.
        if cycles > 0 && cycles % LISTENER_CHECK_EVERY == 0 {
            listener.check();
        }
        cycles = cycles.wrapping_add(1);

        // Read per cycle rather than once at start: the task stays registered
        // while the switch is off, so the setting is what has to take effect
        // immediately. Cached with a short TTL, so this is not a file read per
        // two seconds.
        // Auto-patch, minus a patch the user switched off by hand: a watchdog
        // that read `auto_patch` alone would treat the unpatched binary as an
        // update and put the patch straight back (G38). Not `client_patch`
        // either - that is false on every machine that has not patched *yet*,
        // which is the fresh install this is also for (D27).
        if crate::settings::auto_patch_wanted() {
            #[cfg(windows)]
            inspect_vendor_updates(&installs, &mut vendor_states);
            for inst in &installs {
                for target in targets(inst) {
                    inspect(&target, states.entry(target.clone()).or_default());
                }
            }
        }

        thread::sleep(POLL);
    }
}

#[cfg(windows)]
#[derive(Default)]
struct VendorWatchState {
    pending: Option<(u64, SystemTime)>,
    handled: Option<(u64, SystemTime)>,
    retry_after: Option<Instant>,
}

#[cfg(windows)]
fn vendor_observation_ready(state: &mut VendorWatchState, current: (u64, SystemTime), now: Instant) -> bool {
    if state.handled == Some(current) || state.retry_after.is_some_and(|until| now < until) { return false; }
    if state.pending != Some(current) { state.pending = Some(current); return false; }
    state.pending = None;
    true
}

/// ASAR observation is independent from the native binary/IDE target list.
/// File timestamps schedule receiving only; the installation owner checks bytes.
#[cfg(windows)]
fn inspect_vendor_updates(installs: &[PathBuf], states: &mut HashMap<PathBuf, VendorWatchState>) {
    let settings = crate::settings::routing_snapshot();
    if !crate::wsl_runtime::automatic_vendor_update_wanted(&settings) { return; }
    let cancel = std::sync::atomic::AtomicBool::new(false);
    for root in installs {
        let archive = root.join("resources").join("app.asar");
        let Some(current) = stat(&archive) else { continue; };
        let state = states.entry(archive.clone()).or_default();
        if !vendor_observation_ready(state, current, Instant::now()) { continue; }
        match crate::wsl_runtime::automatic_vendor_update(root, &settings, &cancel) {
            Ok(changed) => {
                state.retry_after = None;
                state.handled = stat(&archive);
                if changed { log("WSL Desktop hook update received"); }
            }
            Err(error) => {
                // Existing slow-poll cadence bounds repeated busy/hold probes;
                // the same unchanged archive remains eligible for retry.
                state.retry_after = Some(Instant::now() + POLL);
                log(&format!("WSL Desktop update deferred: {error}"));
            }
        }
    }
}

/// Poll interval while an update is staged, and how long that lasts after the
/// staged installer is gone. Re-discovery stays at about nine seconds.
const FAST_POLL: Duration = Duration::from_millis(150);
const FAST_FOR: Duration = Duration::from_secs(90);
const FAST_REDISCOVER_EVERY: u32 = 60;

/// Antigravity's updater keeps a downloaded installer in
/// `%LOCALAPPDATA%\<name>-updater\pending` until it runs it (measured: electron
/// -updater, `antigravity-updater\pending\Antigravity-x64.exe`). Filesystem
/// checks only.
fn updater_dirs() -> Vec<PathBuf> {
    let Some(base) = std::env::var_os("LOCALAPPDATA") else {
        return Vec::new();
    };
    let Ok(rd) = fs::read_dir(PathBuf::from(base)) else {
        return Vec::new();
    };
    rd.flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_lowercase();
            n.contains("antigravity") && n.ends_with("-updater")
        })
        .map(|e| e.path().join("pending"))
        .collect()
}

/// True while a staged installer is in use: opening a running exe for writing
/// fails with a sharing violation, a file that merely waits for the user opens
/// fine (and is left untouched). Without this a downloaded update would keep
/// the fast poll on for as long as it waits - days, if the user never quits.
fn updater_busy(dirs: &[PathBuf]) -> bool {
    dirs.iter().any(|d| {
        let Ok(rd) = fs::read_dir(d) else { return false };
        rd.flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "exe"))
            .any(|p| OpenOptions::new().append(true).open(&p).is_err())
    })
}

/// How often the proxy listener is looked at, in polls. 15 x 2 s = 30 s.
const LISTENER_CHECK_EVERY: u32 = 15;
/// Consecutive misses before the variable comes off: 3 x 30 s. A relay
/// restarting under its task (3 tries a minute apart) is back well inside that;
/// one that is not coming back has by then cost Antigravity ninety seconds of
/// `connection refused` on every request, which is enough.
const LISTENER_DEAD_AFTER: u32 = 3;
/// Once the variable was found absent or removed, how long before the (slow,
/// PowerShell-backed) environment read is worth repeating.
const ENV_RECHECK: Duration = Duration::from_secs(10 * 60);

/// Keeps the proxy variable from outliving the listener it names.
///
/// Originally this guarded the machine: the variable was `HTTPS_PROXY`, user-wide,
/// so a relay that died and did not come back took everything proxy-aware down
/// with it (G20, seen once after a revert). Since `2.11.0_5` the name is private
/// to the patched binaries, so what is at stake is Antigravity alone - but that
/// still means no models and no sign-in, so the guard stays: no listener for a
/// while and off the variable comes; the relay puts it back when it starts again
/// (`endpoint::ensure_proxy_env`). A proxy the user set is under a different name
/// entirely and is never touched.
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
                "прокси {} не отвечает {} с — переменная {} снята",
                url,
                LISTENER_DEAD_AFTER * LISTENER_CHECK_EVERY * POLL.as_secs() as u32,
                crate::endpoint::PROXY_ENV_VAR
            )),
            Ok(false) => {}
            Err(e) => log(&format!(
                "не удалось снять {}: {}",
                crate::endpoint::PROXY_ENV_VAR,
                e
            )),
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
        // Only a genuinely different file restarts the count. Comparing against
        // the shape the count was raised for, rather than resetting on sight,
        // is what keeps MAX_LAUNCH_HOLDS a limit instead of decoration.
        if st.blocked_for != Some(cur) {
            st.blocked = 0;
            st.blocked_for = None;
        }
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
            log(&format!("patched: {} ({})", show(target), n));
            st.blocked = 0;
            st.blocked_for = None;
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
            // The file is settled but the write did not land. Usually that is
            // Antigravity having been launched between the update finishing and
            // this patch: the image is locked, and left alone it stays locked
            // for as long as the app is open, so the user runs an unpatched
            // build indefinitely with the patch "deferred" for ever.
            //
            // The *launch* is what gets undone, never the update — a file still
            // being written never settles, so this branch is not reached while
            // one is in progress.
            log(&format!("deferred, will retry: {} - {}", show(target), e));

            // Only a lock. A permission error, a full disk or a read failure is
            // not something closing Antigravity can fix, and `write_binary` has
            // already killed the holder and retried once by the time a genuine
            // lock reaches here — so a second kill is only worth attempting for
            // the case it addresses.
            let looks_locked = {
                let low = e.to_lowercase();
                low.contains("used by another process")
                    || low.contains("занят")
                    || low.contains("access is denied")
                    || low.contains("отказано в доступе")
                    || low.contains("os error 32")
                    || low.contains("os error 33")
            };
            // `kill_holder` closes processes by image name, so it only means
            // anything for a native binary; asking Windows to kill `main.js`
            // would be a wasted spawn.
            let is_native = target.extension().and_then(|e| e.to_str()) != Some("js");

            if !is_native || !looks_locked {
                return;
            }
            #[cfg(windows)]
            {
                log("файл оставлен без изменений: требуется обычное закрытие приложения или общий владелец WSL");
                return;
            }
            #[cfg(not(windows))]
            {
            if st.blocked >= MAX_LAUNCH_HOLDS {
                if st.blocked == MAX_LAUNCH_HOLDS {
                    st.blocked += 1;
                    log(&format!(
                        "файл занят не Antigravity - оставляю как есть: {}",
                        show(target)
                    ));
                }
                return;
            }
            st.blocked += 1;
            st.blocked_for = Some(cur);
            log(&format!(
                "закрываю запущенный Antigravity, чтобы применить патч ({}/{}): {}",
                st.blocked,
                MAX_LAUNCH_HOLDS,
                show(target)
            ));
            patch_binary::kill_holder(target);
            }
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
    let ide_js = patch_ide::js_targets(inst).ide_main;
    if ide_js.exists() {
        list.push(ide_js);
    }
    list
}

/// Patches every file of one install now, the way the watcher does once a file
/// has settled: both renames in one write per native binary, the IDE's
/// `main.js`. An already-patched file is read and left alone; a busy Windows
/// binary returns its failure without terminating a process.
///
/// The window's half of auto-patch (D27). The watcher runs inside the relay,
/// which a user without admin rights never installed and which may still be an
/// older build after an upgrade; the window is running either way.
pub fn patch_now(inst: &Path) -> Vec<(PathBuf, RepatchOutcome)> {
    patch_now_batch(inst, None)
}

/// The selected GUI operation shares the writer but stops before another
/// target after failure or its actual owner cancellation.
pub(crate) fn patch_now_received(inst: &Path, cancelled: &std::sync::atomic::AtomicBool) -> Vec<(PathBuf, RepatchOutcome)> {
    patch_now_batch(inst, Some(cancelled))
}

fn patch_now_batch(inst: &Path, cancelled: Option<&std::sync::atomic::AtomicBool>) -> Vec<(PathBuf, RepatchOutcome)> {
    let mut received = Vec::new();
    for target in targets(inst) {
            if cancelled.is_some_and(|token| token.load(std::sync::atomic::Ordering::SeqCst)) {
                received.push((target, RepatchOutcome::Failed("Патч отменён перед следующим файлом.".into())));
                break;
            }
            let outcome = repatch(&target);
            if let RepatchOutcome::Repatched(n) = &outcome {
                log(&format!(
                    "patched from the window: {} ({})",
                    show(&target),
                    n
                ));
            }
            let failed = matches!(outcome, RepatchOutcome::Failed(_));
            received.push((target, outcome));
            if cancelled.is_some() && failed { break; }
    }
    received
}

/// The standard locations plus every path the user pointed the window at: an
/// install they had to find by hand is exactly the one no scan knows about.
fn discover() -> Vec<PathBuf> {
    let mut installs = crate::discover_installs_fast();
    for manual in crate::settings::manual_paths() {
        if let Some(root) = crate::resolve_install_root(&manual) {
            if !installs.contains(&root) {
                installs.push(root);
            }
        }
    }
    // A root-owned Linux install (`/opt`) is not this process's to write: every
    // poll would fail with a permission error and be logged as a retry. The
    // window patches it through pkexec when the user asks (`elevate`).
    installs.retain(|inst| !crate::elevate::needs_root(inst));
    installs
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
///
/// Stamped, like the relay's: an unstamped «patched» cannot be lined up against
/// the moment a file changed, and that is the one question this log is read for.
/// Never from a test - the file is the *installed* watchdog's, and the wiring
/// tests below used to append their temp paths to it (G51's twin).
fn log(line: &str) {
    if cfg!(test) {
        return;
    }
    let dir = dns_forwarder::log_dir();
    let path = dir.join("watchdog.log");
    fs::create_dir_all(&dir).ok();
    if fs::metadata(&path).map_or(false, |m| m.len() > LOG_LIMIT_BYTES) {
        fs::remove_file(&path).ok();
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let stamp = crate::utils::local_clock().map_or_else(String::new, |c| c.hms());
        writeln!(f, "{} {}", stamp, line).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn vendor_archive_observation_requires_settled_shape_and_retries_holds() {
        let mut state = VendorWatchState::default();
        let now = Instant::now();
        let first = (10, SystemTime::UNIX_EPOCH);
        let changed = (11, SystemTime::UNIX_EPOCH);
        assert!(!vendor_observation_ready(&mut state, first, now));
        assert!(!vendor_observation_ready(&mut state, changed, now));
        assert!(vendor_observation_ready(&mut state, changed, now));
        state.retry_after = Some(now + POLL);
        assert!(!vendor_observation_ready(&mut state, changed, now));
        assert!(!vendor_observation_ready(&mut state, changed, now + POLL));
        assert!(vendor_observation_ready(&mut state, changed, now + POLL));
        state.handled = Some(changed);
        assert!(!vendor_observation_ready(&mut state, changed, now + POLL));
    }

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
