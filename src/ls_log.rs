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
//!
//! Two readers, asking different questions of the same file. `poll` is the
//! relay's: "what came in since I last looked", which is what may be *acted*
//! on. `newest_refusal` is the window's: "is the user hitting the gate right
//! now", which has to be answerable about the minutes before this process
//! started - so it reads the log's own stamps rather than a saved offset. The
//! two share the pattern and the file list and nothing else; they run in
//! different processes and neither moves the other's position.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

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
/// Public because the window holds the list rather than rebuilding it: this
/// walks `%APPDATA%` and then the IDE's `logs` folder, which has one sub-folder
/// per launch, and a window ticking every three seconds must not do that.
pub fn candidate_logs() -> Vec<PathBuf> {
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

/// Linux keeps the same layout under `~/.config`; nothing tails it there yet
/// because the DNS layer it would steer is not ported, but the path is right.
#[cfg(not(target_os = "windows"))]
fn profile_root() -> Option<PathBuf> {
    match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.is_empty() => Some(PathBuf::from(x)),
        _ => std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config")),
    }
}

// ---------------------------------------------------------------------------
// Reading the same log the other way round: what is *there*, not what is new.
// ---------------------------------------------------------------------------

/// The newest refusal a client log carries, as the window needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sighting {
    /// How long ago the newest one was written, by the log's own stamp.
    pub ago: Duration,
    /// How many fall inside the window asked for.
    pub count: usize,
}

/// How much of a log's tail is read looking for one. A session's worth of glog
/// is a few hundred kilobytes an hour, and the window asked for is minutes.
const HISTORY_TAIL: u64 = 256 * 1024;

/// A stamp a second or two ahead of our own read of the clock is *now*, not a
/// line from the future: the logger and this process read the same clock at
/// slightly different moments, and `GetLocalTime` has whole-second resolution.
const CLOCK_SLACK: u32 = 5;

/// The newest refusal in any client log inside `within`, and how many there are.
///
/// `poll` above answers "what is new since I last looked", which is the right
/// question for the relay and the wrong one for a window: a user who hits the
/// gate and *then* opens this tool would be told nothing had happened. So this
/// reads the log's own timestamps rather than a saved position, and it is the
/// only place in the tool that parses them.
///
/// `None` without a local clock to compare against (non-Windows): an age nobody
/// can compute is not one to guess at.
pub fn newest_refusal(paths: &[PathBuf], within: Duration) -> Option<Sighting> {
    let now = crate::utils::local_clock()?;
    let mut newest: Option<Duration> = None;
    let mut count = 0usize;
    for path in paths {
        let Some(text) = tail(path, HISTORY_TAIL) else {
            continue;
        };
        for line in text.lines() {
            // Occurrences, not lines: one line can carry more than one, and
            // `Episode.count` on the relay's side counts them the same way.
            let hits = count_refusals(line.as_bytes());
            if hits == 0 {
                continue;
            }
            // A line whose stamp will not parse is one the tail cut in half, or
            // one some future build writes differently. Either way it cannot be
            // placed in time, and an unplaceable refusal is not evidence of
            // anything happening *now*.
            let Some(ago) = parse_stamp(line).and_then(|at| age_secs(at, now)) else {
                continue;
            };
            let ago = Duration::from_secs(ago as u64);
            if ago > within {
                continue;
            }
            count += hits;
            if newest.is_none_or(|n| ago < n) {
                newest = Some(ago);
            }
        }
    }
    newest.map(|ago| Sighting { ago, count })
}

/// Total size of the given logs. The cheap half of "is Antigravity doing
/// anything" - one `metadata` per file and no read at all - which is what the
/// window gates both its scans and its VPN measurement on. A log that has not
/// grown cannot have gained a refusal, and a client that is not writing is not
/// one whose route can have changed under us.
pub fn bytes_of(paths: &[PathBuf]) -> u64 {
    paths
        .iter()
        .filter_map(|p| fs::metadata(p).ok().map(|m| m.len()))
        .sum()
}

/// The last `max` bytes of a file, as text. The first line usually comes back
/// cut; that is the caller's problem and it handles it by refusing to place a
/// line it cannot parse.
fn tail(path: &Path, max: u64) -> Option<String> {
    let len = fs::metadata(path).ok()?.len();
    let start = len.saturating_sub(max);
    let mut f = File::open(path).ok()?;
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    f.take(len - start).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// glog's header — a level letter, `MMDD`, a space, then local `HH:MM:SS.ffffff`
/// — wherever in the line it sits.
///
/// Searched for rather than sliced off the front, and that is not defensive
/// programming: measured on both real logs, it is never at the front. The
/// Desktop server prefixes *every* line with `ERROR: logging before
/// google.Init: `, and the IDE wraps that same text again in its own
/// `2026-09-12 03:57:46.735 [error] [LS Main stderr] `. Anchoring at byte 0
/// found a stamp in neither file, so the window would have shown "тихо" while
/// the user was staring at the error.
///
/// Returns `(month, day, second of day)`; there is no year in it, which is why
/// `age_secs` only ever places a line today or yesterday.
fn parse_stamp(line: &str) -> Option<(u16, u16, u32)> {
    let b = line.as_bytes();
    let limit = b.len().min(HEADER_SEARCH).saturating_sub(STAMP_LEN);
    (0..=limit).find_map(|i| stamp_at(line, i))
}

/// How far into a line the header is looked for. Both wrappers measured above
/// fit in well under a hundred bytes; the bound is what keeps a stamp-shaped
/// run of text deep inside a message from being read as one.
const HEADER_SEARCH: usize = 200;
/// `E0901 15:09:24` — the part that has to be there.
const STAMP_LEN: usize = 14;

/// The header if it starts exactly at `at`, and nothing otherwise. A slice that
/// lands mid-character answers `None` rather than panicking (`str::get`), which
/// is what makes scanning a line of arbitrary bytes safe.
fn stamp_at(line: &str, at: usize) -> Option<(u16, u16, u32)> {
    let b = line.as_bytes();
    if b.len() < at + STAMP_LEN {
        return None;
    }
    // glog's four levels. `is_ascii_alphabetic` would match the `E` of a word
    // followed by four digits, which is exactly the kind of thing a log message
    // contains.
    if !matches!(b[at], b'I' | b'W' | b'E' | b'F') {
        return None;
    }
    if b[at + 5] != b' ' || b[at + 8] != b':' || b[at + 11] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| line.get(r).and_then(|s| s.parse::<u32>().ok());
    let (month, day) = (num(at + 1..at + 3)?, num(at + 3..at + 5)?);
    let (h, m, s) = (
        num(at + 6..at + 8)?,
        num(at + 9..at + 11)?,
        num(at + 12..at + 14)?,
    );
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || h > 23 || m > 59 || s > 59 {
        return None;
    }
    Some((month as u16, day as u16, h * 3600 + m * 60 + s))
}

/// How long ago a stamp was, against the local clock now.
///
/// Only today and yesterday can be placed: the header carries no year, and the
/// window this is asked about is minutes. Anything else answers `None`, which
/// reads as "not recent" - the safe direction, since the cost of missing an old
/// refusal is nothing and the cost of inventing a fresh one is a false alarm.
fn age_secs(at: (u16, u16, u32), now: crate::utils::LocalClock) -> Option<u32> {
    let (month, day, sod) = at;
    if month == now.month && day == now.day {
        return if sod <= now.second_of_day {
            Some(now.second_of_day - sod)
        } else if sod - now.second_of_day <= CLOCK_SLACK {
            Some(0)
        } else {
            None
        };
    }
    if is_day_before((month, day), now) {
        return Some(now.second_of_day + 86_400 - sod);
    }
    None
}

fn is_day_before(at: (u16, u16), now: crate::utils::LocalClock) -> bool {
    if at.0 == now.month {
        return at.1 + 1 == now.day;
    }
    // The first of a month: yesterday is the last day of the one before, whose
    // number the header does not carry a year to settle. February is therefore
    // allowed both its lengths, and the only stamp that can be misplaced is a
    // 28 February read on 1 March of a leap year - in the first minutes after
    // midnight, once every four years, and the cost is one line of the window
    // saying "a few minutes ago" about a day-old refusal.
    now.day == 1 && at.0 == month_before(now.month) && is_last_day(at.0, at.1)
}

fn is_last_day(month: u16, day: u16) -> bool {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => day == 31,
        4 | 6 | 9 | 11 => day == 30,
        2 => day == 28 || day == 29,
        _ => false,
    }
}

fn month_before(m: u16) -> u16 {
    if m <= 1 {
        12
    } else {
        m - 1
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

    /// The two shapes the real logs are actually written in, copied off this
    /// machine. Neither starts with the glog header: the Desktop server prefixes
    /// every line, and the IDE wraps the prefixed line again.
    const DESKTOP_LINE: &str = "ERROR: logging before google.Init: E0901 15:09:24.614939       1 stream_handler.go:101] FAILED_PRECONDITION (code 400): User location is not supported for the API use.";
    const IDE_LINE: &str = "2026-09-12 03:57:46.735 [error] [LS Main stderr] ERROR: logging before google.Init: E0901 15:09:24.614939       1 stream_handler.go:101] FAILED_PRECONDITION (code 400): User location is not supported for the API use.";

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

    fn clock(month: u16, day: u16, h: u32, m: u32, s: u32) -> crate::utils::LocalClock {
        crate::utils::LocalClock {
            month,
            day,
            second_of_day: h * 3600 + m * 60 + s,
        }
    }

    /// The window's reader, end to end: tail, stamp, age, count. Written with
    /// the machine's own clock so the stamps are the shape the language server
    /// would have written a moment ago.
    #[test]
    fn a_refusal_is_found_by_its_own_stamp_and_an_old_one_is_not() {
        let Some(now) = crate::utils::local_clock() else {
            return; // no local clock (non-Windows): the reader answers None by design
        };
        // Not within the first hour after midnight: the stamps below are built
        // by subtracting from the clock, and "yesterday" is a different test.
        if now.second_of_day < 3600 {
            return;
        }
        // Written the way the real Desktop log writes it, prefix and all, so
        // this exercises the search rather than a shape only a test produces.
        let stamp = |back: u32| {
            let sod = now.second_of_day - back;
            format!(
                "ERROR: logging before google.Init: E{:02}{:02} {:02}:{:02}:{:02}.123456       1 stream_handler.go:101] ",
                now.month,
                now.day,
                sod / 3600,
                (sod / 60) % 60,
                sod % 60
            )
        };
        let path = temp_log("recent");
        append(&path, &format!("{}Setting GOMAXPROCS to 4\n", stamp(30)));
        append(&path, &format!("{}FAILED_PRECONDITION (code 400): User location is not supported for the API use.\n", stamp(1500)));
        append(&path, &format!("{}FAILED_PRECONDITION (code 400): User location is not supported for the API use.\n", stamp(300)));
        append(&path, &format!("{}FAILED_PRECONDITION (code 400): User location is not supported for the API use.\n", stamp(120)));

        let files = [path.clone()];
        let seen = newest_refusal(&files, Duration::from_secs(600)).expect("two are in the window");
        assert_eq!(seen.count, 2, "the 25-minute-old one is outside it");
        assert!(
            (115..=135).contains(&seen.ago.as_secs()),
            "newest was two minutes ago, got {:?}",
            seen.ago
        );
        // A window narrower than the newest refusal finds nothing at all.
        assert_eq!(newest_refusal(&files, Duration::from_secs(60)), None);
        // And a log with nothing in it says so rather than guessing.
        let quiet = temp_log("quiet");
        append(&quiet, &format!("{}Setting GOMAXPROCS to 4\n", stamp(10)));
        assert_eq!(
            newest_refusal(std::slice::from_ref(&quiet), Duration::from_secs(600)),
            None
        );
        assert!(bytes_of(&files) > 0);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quiet);
    }

    /// What the machine has right now. Reads, never asserts: the point is that
    /// the paths and the parse work against a real client log.
    ///
    ///     cargo test reads_what_the_client_actually_logged -- --ignored --nocapture
    #[test]
    #[ignore = "reads the real Antigravity logs on this machine; run with --ignored"]
    fn reads_what_the_client_actually_logged() {
        let logs = candidate_logs();
        println!("логов: {}, байт: {}", logs.len(), bytes_of(&logs));
        for path in &logs {
            println!("  {}", path.display());
        }
        println!(
            "последняя region-400 за сутки: {:?}",
            newest_refusal(&logs, Duration::from_secs(24 * 3600))
        );
    }

    /// The regression this parser was rewritten for: measured on the machine's
    /// own logs, the header is never at the start of the line. Anchored at byte
    /// 0 it matched neither real file, and the window would have reported
    /// silence while the user watched the error.
    #[test]
    fn the_header_is_found_under_both_wrappers_the_real_logs_use() {
        let expected = Some((9, 1, 15 * 3600 + 9 * 60 + 24));
        assert_eq!(parse_stamp(DESKTOP_LINE), expected);
        assert_eq!(parse_stamp(IDE_LINE), expected);
        // The IDE's own `2026-09-12 03:57:46.735` must not be mistaken for it:
        // what is read is the language server's stamp, inside the wrapper.
        assert_eq!(parse_stamp("2026-09-12 03:57:46.735 [info] [LS Main] Args"), None);
        // And a stamp-shaped run deep inside a message is out of reach.
        let deep = format!("{}E0102 03:04:05.000000 x", "y".repeat(HEADER_SEARCH));
        assert_eq!(parse_stamp(&deep), None);
    }

    #[test]
    fn a_glog_header_is_read_and_anything_else_refused() {
        assert_eq!(parse_stamp(REFUSAL), Some((9, 1, 15 * 3600 + 9 * 60 + 24)));
        assert_eq!(parse_stamp(NOISE), Some((9, 1, 15 * 3600 + 9 * 60 + 24)));
        // The tail cuts the first line anywhere, and half a header is not one.
        assert_eq!(parse_stamp("24.614939 1 stream_handler.go:101] blah"), None);
        assert_eq!(parse_stamp(""), None);
        assert_eq!(parse_stamp("E0901 15:09"), None);
        // Not a date and not a time.
        assert_eq!(parse_stamp("E1301 15:09:24.1 x"), None, "month 13");
        assert_eq!(parse_stamp("E0932 15:09:24.1 x"), None, "day 32");
        assert_eq!(parse_stamp("E0901 25:09:24.1 x"), None, "hour 25");
        // A Cyrillic first byte must not panic the slicing.
        assert_eq!(parse_stamp("Э0901 15:09:24.614939 x"), None);
    }

    /// The header carries no year, so only today and yesterday can be placed -
    /// and "yesterday" is what makes a refusal at 23:58 still readable at 00:02.
    #[test]
    fn a_stamp_is_placed_against_the_local_clock() {
        let now = clock(9, 1, 15, 10, 0);
        assert_eq!(age_secs((9, 1, 15 * 3600 + 9 * 60), now), Some(60));
        assert_eq!(age_secs((9, 1, 15 * 3600 + 10 * 60), now), Some(0));
        // A stamp a second ahead of our own read of the clock is now.
        assert_eq!(age_secs((9, 1, 15 * 3600 + 10 * 60 + 2), now), Some(0));
        // Further ahead than that is not a line about now.
        assert_eq!(age_secs((9, 1, 15 * 3600 + 20 * 60), now), None);
        // Another day, and not the one before: unplaceable.
        assert_eq!(age_secs((8, 20, 0), now), None);
        // Just after midnight, looking back over it.
        let midnight = clock(9, 2, 0, 2, 0);
        assert_eq!(age_secs((9, 1, 23 * 3600 + 58 * 60), midnight), Some(240));
        // And over the end of a month.
        let first = clock(9, 1, 0, 1, 0);
        assert_eq!(age_secs((8, 31, 23 * 3600 + 59 * 60), first), Some(120));
        // Not the last day of August, so not the day before 1 September.
        assert_eq!(age_secs((8, 30, 23 * 3600 + 59 * 60), first), None);
        // February is allowed both its lengths.
        assert!(is_last_day(2, 28) && is_last_day(2, 29) && !is_last_day(2, 27));
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
