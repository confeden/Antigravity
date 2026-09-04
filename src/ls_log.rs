//! Reads the one fact no probe can measure: the region 400, out of the
//! language server's own log.
//!
//! `cloudcode-pa` refuses a blocked region with `FAILED_PRECONDITION (code 400):
//! User location is not supported for the API use`. That answer travels inside
//! the client's own TLS, and an unauthenticated probe never sees it -
//! `loadCodeAssist` answers 401 from a permitted and a blocked exit alike
//! (kb/dns.md). Every signal the tool has about a route's region is therefore
//! indirect: the exit's country, whether an address was substituted, whether a
//! tunnel carried bytes. The client's log is the only place the refusal is
//! written down in plain text, so the relay tails it.
//!
//! Tailing, not reading: each pass looks at the bytes appended since the last
//! one and nothing else, so an old refusal from a session hours ago cannot
//! trigger anything now. A file seen for the first time is taken from its end
//! for the same reason. A file that shrank was rotated or the app restarted, and
//! is read from the start - it is new content either way.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The refusal, as the language server logs it. Matched ASCII-case-insensitively
/// and never on the whole `FAILED_PRECONDITION` line: that status wraps other
/// preconditions too, and only this one is about where the request came from.
const REGION_400: &str = "user location is not supported";

/// Longest slice of appended log read in one pass. Anything beyond it is a log
/// that grew by megabytes between two passes, which is not a session anyone is
/// working in; the tail is what carries the news.
const MAX_READ: u64 = 1024 * 1024;

/// How many products the scan is willing to look at. A user profile does not
/// hold more than a handful of `Antigravity*` folders, and a bound keeps a
/// pathological `%APPDATA%` from turning a 15 s tick into a directory walk.
const MAX_PRODUCTS: usize = 8;

/// Where each watched file was read up to.
static OFFSETS: Mutex<Option<HashMap<PathBuf, u64>>> = Mutex::new(None);

/// One pass over every language-server log on the machine. Returns the files
/// that gained refusals since the last pass, with how many each gained.
pub fn poll() -> Vec<(PathBuf, usize)> {
    let mut out = Vec::new();
    let Ok(mut guard) = OFFSETS.lock() else {
        return out;
    };
    let offsets = guard.get_or_insert_with(HashMap::new);
    for path in candidate_logs() {
        let first_sight = !offsets.contains_key(&path);
        let from = offsets.get(&path).copied();
        let (next, hits) = scan(&path, from);
        offsets.insert(path.clone(), next);
        if !first_sight && hits > 0 {
            out.push((path, hits));
        }
    }
    out
}

/// Reads `path` from `from` (or from its end, when it has never been read) and
/// counts refusals in what was appended. Returns where the next read starts.
///
/// Pure in the sense that matters for a test: no static, one file, one answer.
fn scan(path: &Path, from: Option<u64>) -> (u64, usize) {
    let Ok(len) = fs::metadata(path).map(|m| m.len()) else {
        return (from.unwrap_or(0), 0);
    };
    let Some(from) = from else {
        // Never seen: history is not news.
        return (len, 0);
    };
    // Shrunk means rotated or restarted, and everything in it is new.
    let mut start = if len < from { 0 } else { from };
    if len == start {
        return (len, 0);
    }
    // Overlap the previous read by one byte less than the needle, so a refusal
    // the logger's buffer flush split across two passes is still seen whole -
    // and never counted twice, since the overlap alone is too short to match.
    if start > 0 {
        start = start.saturating_sub(REGION_400.len() as u64 - 1);
    }
    if len - start > MAX_READ {
        start = len - MAX_READ;
    }
    let Ok(mut f) = File::open(path) else {
        return (from, 0);
    };
    if f.seek(SeekFrom::Start(start)).is_err() {
        return (from, 0);
    }
    let mut buf = Vec::with_capacity((len - start) as usize);
    if f.take(len - start).read_to_end(&mut buf).is_err() {
        return (from, 0);
    }
    (len, count_refusals(&buf))
}

/// Occurrences of the refusal in a chunk of log, case-insensitively. Byte-wise,
/// because the log is a stream of glog lines that a partial last line may cut
/// anywhere, and a UTF-8 boundary is not something worth failing on.
fn count_refusals(buf: &[u8]) -> usize {
    let needle = REGION_400.as_bytes();
    if buf.len() < needle.len() {
        return 0;
    }
    buf.windows(needle.len())
        .filter(|w| w.eq_ignore_ascii_case(needle))
        .count()
}

/// The language-server logs of every Antigravity product under the user's
/// roaming profile.
///
/// Desktop writes `<product>\logs\language_server.log`; the IDE, a VS Code
/// fork, writes `<product>\logs\<session stamp>\ls-main.log`, one folder per
/// launch - so for it only the newest session is watched. Product folders are
/// matched by prefix rather than listed, so a rebranded build is picked up too.
fn candidate_logs() -> Vec<PathBuf> {
    let Some(root) = profile_root() else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut products = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.to_ascii_lowercase().starts_with("antigravity") {
            continue;
        }
        products += 1;
        if products > MAX_PRODUCTS {
            break;
        }
        let logs = entry.path().join("logs");
        let desktop = logs.join("language_server.log");
        if desktop.is_file() {
            out.push(desktop);
        }
        if let Some(session) = newest_session(&logs) {
            let ide = session.join("ls-main.log");
            if ide.is_file() {
                out.push(ide);
            }
        }
    }
    out
}

/// The most recently modified sub-folder of `logs`, i.e. the IDE's current
/// session.
fn newest_session(logs: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(logs).ok()?;
    entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let modified = e.metadata().ok()?.modified().ok()?;
            Some((modified, e.path()))
        })
        // Ties - same second on a coarse filesystem - go to the later stamp:
        // the folder names are timestamps and sort chronologically.
        .max_by(|(ma, pa), (mb, pb)| ma.cmp(mb).then_with(|| pa.cmp(pb)))
        .map(|(_, p)| p)
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

/// Linux keeps the same layout under `~/.config`; nothing tails it there yet
/// because the DNS layer it would steer is not ported, but the path is right.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn profile_root() -> Option<PathBuf> {
    match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.is_empty() => Some(PathBuf::from(x)),
        _ => std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_log(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("ag_unlocker_ls_log_tests");
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(format!("{}-{}.log", name, std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    fn append(path: &Path, text: &str) {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open");
        f.write_all(text.as_bytes()).expect("write");
    }

    const REFUSAL: &str = "E0901 15:09:24.614939 1 stream_handler.go:101] FAILED_PRECONDITION (code 400): User location is not supported for the API use.\n";
    const NOISE: &str = "I0901 15:09:24.639090 1 server.go:427] Setting GOMAXPROCS to 4\n";

    #[test]
    fn counts_the_refusal_case_insensitively_and_nothing_else() {
        assert_eq!(count_refusals(REFUSAL.as_bytes()), 1);
        assert_eq!(count_refusals(NOISE.as_bytes()), 0);
        assert_eq!(
            count_refusals(b"USER LOCATION IS NOT SUPPORTED x user location is not supported"),
            2
        );
        assert_eq!(
            count_refusals(b"FAILED_PRECONDITION (code 400): something else"),
            0,
            "the status alone is not the region gate"
        );
        assert_eq!(count_refusals(b""), 0);
    }

    #[test]
    fn history_is_not_news_but_what_is_appended_is() {
        let path = temp_log("append");
        append(&path, REFUSAL);
        append(&path, REFUSAL);
        // First sight: taken from the end, old refusals ignored.
        let (off, hits) = scan(&path, None);
        assert_eq!(hits, 0);
        assert_eq!(off, fs::metadata(&path).unwrap().len());
        // Nothing appended: nothing found, offset unchanged.
        assert_eq!(scan(&path, Some(off)), (off, 0));
        // Appended: found once, and only once.
        append(&path, NOISE);
        append(&path, REFUSAL);
        let (off2, hits) = scan(&path, Some(off));
        assert_eq!(hits, 1);
        assert_eq!(scan(&path, Some(off2)), (off2, 0));
        // A refusal split by a buffer flush: half in one pass, half in the next.
        let cut = REFUSAL.len() / 2;
        append(&path, &REFUSAL[..cut]);
        let (off3, hits) = scan(&path, Some(off2));
        assert_eq!(hits, 0);
        append(&path, &REFUSAL[cut..]);
        let (off4, hits) = scan(&path, Some(off3));
        assert_eq!(hits, 1, "the halves must be read together");
        assert_eq!(scan(&path, Some(off4)), (off4, 0), "and not counted again");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_file_that_shrank_is_read_from_the_start() {
        let path = temp_log("shrink");
        for _ in 0..8 {
            append(&path, NOISE);
        }
        let (off, _) = scan(&path, None);
        assert!(
            off > REFUSAL.len() as u64,
            "the rewrite below must shrink it"
        );
        // The app restarted and truncated its log; the new content is news.
        fs::write(&path, REFUSAL).expect("truncate");
        let (off2, hits) = scan(&path, Some(off));
        assert_eq!(hits, 1);
        assert_eq!(off2, REFUSAL.len() as u64);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_changes_nothing() {
        let path = temp_log("missing");
        assert_eq!(scan(&path, None), (0, 0));
        assert_eq!(scan(&path, Some(42)), (42, 0));
    }

    #[test]
    fn the_newest_session_folder_wins() {
        let dir = std::env::temp_dir().join(format!("ag_unlocker_sessions_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let old = dir.join("20260101T000000");
        let new = dir.join("20260901T191103");
        fs::create_dir_all(&old).unwrap();
        // A pause, so the two folders cannot share a timestamp; and the names
        // sort the same way, which is the tie-break either way.
        std::thread::sleep(std::time::Duration::from_millis(40));
        fs::create_dir_all(&new).unwrap();
        assert_eq!(newest_session(&dir), Some(new));
        let _ = fs::remove_dir_all(&dir);
    }
}
