//! Reads the two facts no probe can measure - the region 400, and a model
//! answer - out of the language server's own log.
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
//! The other half is the one thing that proves the bypass works: a model answer
//! logs `…/v1internal:streamGenerateContent?alt=sse Trace: 0x… ResponseID: …`
//! when it starts streaming, and a refused turn logs no such line (measured on
//! the IDE log of 2026-09-12: refusals 14:58–15:00, first `ResponseID` 15:16).
//! Silence proves nothing - a user who gave up is silent too (G50) - so the
//! window says "работает" only on this line, and the route table ranks routes by
//! it (`routes`).
//!
//! Tailing, not reading: each pass looks at the lines appended since the last
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

/// A model answer, as the language server logs it: the generation call and the
/// id of the response it got back, on one line. Both halves: `loadCodeAssist`
/// and `fetchAvailableModels` are logged the same way on a refused session too,
/// and only the generation call is behind the gate.
const ANSWER_CALL: &str = "streamgeneratecontent";
const ANSWER_ID: &str = "responseid:";

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

/// The gate host each file last named in a `URL:` line, carried across passes:
/// a refusal line names no host, and the call it refused was logged in an
/// earlier chunk more often than not.
static LAST_HOST: Mutex<Option<HashMap<PathBuf, String>>> = Mutex::new(None);

/// Whether the first pass has run. Files found on it hold history and are taken
/// from their end; a file that *appears* later is a new session - an IDE launch,
/// a CLI run - and everything in it is news, from the first byte. Taking those
/// from their end too lost the answer (or the refusal) a short CLI run writes
/// before the next pass comes round.
static FIRST_PASS_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// What one stretch of log said about the gate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tally {
    /// Refusal lines. One refused turn writes several (the stream handler, the
    /// executor and the error report each repeat it), so this counts lines, not
    /// turns.
    pub refusals: usize,
    /// How long ago the newest refusal was stamped. `None` when there was none,
    /// or its stamp could not be placed against the clock.
    pub refused_ago: Option<Duration>,
    /// Model answers: one line per answer that started streaming.
    pub answers: usize,
    pub answered_ago: Option<Duration>,
    /// Which gate host the newest refusal was about: the host of the last
    /// `URL: https://…` line before it in this file. The client keeps a
    /// connection pool per host, and the two can sit on different routes.
    pub refused_host: Option<String>,
    /// The host the newest answer's own line names.
    pub answered_host: Option<String>,
}

impl Tally {
    pub fn is_empty(&self) -> bool {
        self.refusals == 0 && self.answers == 0
    }

    fn add(&mut self, other: Tally) {
        self.refusals += other.refusals;
        self.answers += other.answers;
        // The host goes with whichever event is newer - an unplaceable one
        // (no age) never displaces a placed one.
        if other.refused_ago.is_some() && newer(self.refused_ago, other.refused_ago) == other.refused_ago {
            self.refused_host = other.refused_host.clone();
        } else if self.refused_host.is_none() {
            self.refused_host = other.refused_host.clone();
        }
        if other.answered_ago.is_some()
            && newer(self.answered_ago, other.answered_ago) == other.answered_ago
        {
            self.answered_host = other.answered_host.clone();
        } else if self.answered_host.is_none() {
            self.answered_host = other.answered_host.clone();
        }
        self.refused_ago = newer(self.refused_ago, other.refused_ago);
        self.answered_ago = newer(self.answered_ago, other.answered_ago);
    }
}

fn newer(a: Option<Duration>, b: Option<Duration>) -> Option<Duration> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// One pass over every client log on the machine. Returns the files that
/// gained a refusal or an answer since the last pass, with what each gained.
pub fn poll() -> Vec<(PathBuf, Tally)> {
    let mut out = Vec::new();
    let Ok(mut guard) = OFFSETS.lock() else {
        return out;
    };
    let offsets = guard.get_or_insert_with(HashMap::new);
    let now = crate::utils::local_clock();
    let started = FIRST_PASS_DONE.swap(true, std::sync::atomic::Ordering::Relaxed);
    let mut hosts = LAST_HOST.lock().ok();
    for path in candidate_logs() {
        let first_sight = !offsets.contains_key(&path);
        // A file new since the first pass is read from its start (see above).
        let from = match offsets.get(&path).copied() {
            None if started => Some(0),
            other => other,
        };
        let mut last_host = hosts
            .as_mut()
            .and_then(|h| h.get_or_insert_with(HashMap::new).get(&path).cloned());
        let (next, tally) = scan(&path, from, now, &mut last_host);
        if let (Some(h), Some(host)) = (hosts.as_mut(), last_host) {
            h.get_or_insert_with(HashMap::new).insert(path.clone(), host);
        }
        offsets.insert(path.clone(), next);
        if (!first_sight || started) && !tally.is_empty() {
            out.push((path, tally));
        }
    }
    out
}

/// Reads `path` from `from` (or from its end, when it has never been read) and
/// tallies the complete lines appended since. Returns where the next read
/// starts: just past the last complete line, so a line the logger's buffer
/// flush split across two passes is read once, whole, on the second.
///
/// Pure in the sense that matters for a test: no static, one file, one answer.
fn scan(
    path: &Path,
    from: Option<u64>,
    now: Option<crate::utils::LocalClock>,
    last_host: &mut Option<String>,
) -> (u64, Tally) {
    let Ok(len) = fs::metadata(path).map(|m| m.len()) else {
        return (from.unwrap_or(0), Tally::default());
    };
    let Some(from) = from else {
        // Never seen: history is not news.
        return (len, Tally::default());
    };
    // Shrunk means rotated or restarted, and everything in it is new.
    let mut start = if len < from { 0 } else { from };
    if len == start {
        return (len, Tally::default());
    }
    if len - start > MAX_READ {
        start = len - MAX_READ;
    }
    let Ok(mut f) = File::open(path) else {
        return (from, Tally::default());
    };
    if f.seek(SeekFrom::Start(start)).is_err() {
        return (from, Tally::default());
    }
    let mut buf = Vec::with_capacity((len - start) as usize);
    if f.take(len - start).read_to_end(&mut buf).is_err() {
        return (from, Tally::default());
    }
    let Some(last_nl) = buf.iter().rposition(|b| *b == b'\n') else {
        // No complete line yet. Wait for the rest - unless the slice is the
        // whole read budget, which is one line nobody will ever finish.
        if buf.len() as u64 >= MAX_READ {
            return (len, Tally::default());
        }
        return (start, Tally::default());
    };
    let complete = &buf[..=last_nl];
    (start + last_nl as u64 + 1, tally(complete, now, last_host))
}

/// Refusals and answers in a stretch of complete lines, with the newest of each
/// placed against `now` by the line's own stamp.
fn tally(
    chunk: &[u8],
    now: Option<crate::utils::LocalClock>,
    last_host: &mut Option<String>,
) -> Tally {
    let mut out = Tally::default();
    for line in chunk.split(|b| *b == b'\n') {
        let named = url_host(line);
        if named.is_some() {
            *last_host = named.clone();
        }
        let refusals = count_refusals(line);
        let answered = is_answer(line);
        if refusals == 0 && !answered {
            continue;
        }
        let ago = now.and_then(|now| {
            let text = String::from_utf8_lossy(line);
            parse_stamp(&text)
                .and_then(|at| age_secs(at, now))
                .map(|s| Duration::from_secs(s as u64))
        });
        if refusals > 0 {
            out.add(Tally {
                refusals,
                refused_ago: ago,
                refused_host: last_host.clone(),
                ..Tally::default()
            });
        }
        if answered {
            out.add(Tally {
                answers: 1,
                answered_ago: ago,
                answered_host: named.or_else(|| last_host.clone()),
                ..Tally::default()
            });
        }
    }
    out
}

/// The host of a `URL: https://<host>/…` line, lower-cased; `None` for any
/// other line or a host that is not one of ours.
fn url_host(line: &[u8]) -> Option<String> {
    const MARK: &[u8] = b"URL: https://";
    let at = line.windows(MARK.len()).position(|w| w == MARK)? + MARK.len();
    let rest = &line[at..];
    let end = rest
        .iter()
        .position(|b| *b == b'/' || *b == b':' || b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    let host = String::from_utf8_lossy(&rest[..end]).to_ascii_lowercase();
    crate::proxy::is_gate_host(&host).then_some(host)
}

/// Whether a line is a model answer that started streaming.
fn is_answer(line: &[u8]) -> bool {
    contains_ci(line, ANSWER_CALL.as_bytes()) && contains_ci(line, ANSWER_ID.as_bytes())
}

fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
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
/// roaming profile, and the CLI's.
///
/// Desktop writes `<product>\logs\language_server.log`; the IDE, a VS Code
/// fork, writes `<product>\logs\<session stamp>\ls-main.log`, one folder per
/// launch - so for it only the newest session is watched. Product folders are
/// matched by prefix rather than listed, so a rebranded build is picked up too.
/// The CLI (`agy`) writes `~\.gemini\antigravity-cli\log\cli-<stamp>.log`, one
/// per session, in the same glog format - found 2026-09-18, and watched from
/// 2.14.0_1 on (before that "CLI log location unknown").
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
    if let Some(cli) = newest_cli_log() {
        out.push(cli);
    }
    out
}

/// The CLI's current session log: the newest `cli-*.log`.
fn newest_cli_log() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    let dir = PathBuf::from(home)
        .join(".gemini")
        .join("antigravity-cli")
        .join("log");
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with("cli-") && n.ends_with(".log")
        })
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .max_by(|(ma, pa), (mb, pb)| ma.cmp(mb).then_with(|| pa.cmp(pb)))
        .map(|(_, p)| p)
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
#[cfg_attr(not(test), allow(dead_code))]
pub fn newest_refusal(paths: &[PathBuf], within: Duration) -> Option<Sighting> {
    // Occurrences, not lines: one line can carry more than one, and
    // `Episode.count` on the relay's side counts them the same way.
    newest_matching(paths, within, |line| count_refusals(line.as_bytes()))
}

/// The newest model answer any client log carries inside `within`, and how many
/// there are. The window's proof that the bypass works right now.
#[cfg_attr(not(test), allow(dead_code))]
pub fn newest_answer(paths: &[PathBuf], within: Duration) -> Option<Sighting> {
    newest_matching(paths, within, |line| is_answer(line.as_bytes()) as usize)
}

/// Everything the window asks of the logs, in one read of each tail.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    /// Refusals inside `recent`: the newest, and how many.
    pub refused_recent: Option<Sighting>,
    /// The newest refusal inside `horizon`, however old.
    pub refused: Option<Sighting>,
    /// The newest model answer inside `horizon`, and how many.
    pub answered: Option<Sighting>,
    /// The newest account-verification demand inside `horizon`.
    pub verify: Option<Verification>,
}

/// `newest_refusal` and `newest_answer` over two windows, from a single pass:
/// the window asked three questions of the same tail every time the log grew,
/// and a busy Desktop log grows every second.
pub fn history(paths: &[PathBuf], recent: Duration, horizon: Duration) -> History {
    let Some(now) = crate::utils::local_clock() else {
        return History::default();
    };
    let mut out = History::default();
    let bump = |slot: &mut Option<Sighting>, ago: Duration, hits: usize| {
        *slot = Some(match *slot {
            Some(s) => Sighting {
                ago: s.ago.min(ago),
                count: s.count + hits,
            },
            None => Sighting { ago, count: hits },
        });
    };
    for path in paths {
        let Some(text) = tail(path, HISTORY_TAIL) else {
            continue;
        };
        for line in text.lines() {
            let refusals = count_refusals(line.as_bytes());
            let answered = is_answer(line.as_bytes());
            if refusals == 0 && !answered {
                continue;
            }
            let Some(ago) = parse_stamp(line).and_then(|at| age_secs(at, now)) else {
                continue;
            };
            let ago = Duration::from_secs(ago as u64);
            if ago > horizon {
                continue;
            }
            if refusals > 0 {
                bump(&mut out.refused, ago, refusals);
                if ago <= recent {
                    bump(&mut out.refused_recent, ago, refusals);
                }
            }
            if answered {
                bump(&mut out.answered, ago, 1);
            }
        }
        if let Some(v) = newest_verification(&text, now, horizon) {
            if out.verify.as_ref().is_none_or(|o| v.ago < o.ago) {
                out.verify = Some(v);
            }
        }
    }
    out
}

fn newest_matching(
    paths: &[PathBuf],
    within: Duration,
    hits_in: impl Fn(&str) -> usize,
) -> Option<Sighting> {
    let now = crate::utils::local_clock()?;
    let mut newest: Option<Duration> = None;
    let mut count = 0usize;
    for path in paths {
        let Some(text) = tail(path, HISTORY_TAIL) else {
            continue;
        };
        for line in text.lines() {
            let hits = hits_in(line);
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

/// Google asking the signed-in account to prove itself before it may use the
/// model: a `403` whose `google.rpc.ErrorInfo` says `VALIDATION_REQUIRED` and
/// carries the page to do it on in `metadata.validation_url` (the same field
/// arrives as `validationUrl` on an ineligible tier at sign-in). The client is
/// meant to show «Complete verification» for it, and does not always - the
/// link is then only in its log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// How long ago, by the log's own stamp.
    pub ago: Duration,
    /// The page, decoded from the JSON it came in and checked to be Google's.
    pub url: String,
}

/// The reason code, as the client itself matches it (`reason ===
/// "VALIDATION_REQUIRED"` in the workbench).
const VERIFY_REASON: &[u8] = b"VALIDATION_REQUIRED";
/// How far from the link its reason may be and still be the same error body.
/// Google pretty-prints the body, and `details` holds a handful of short
/// entries; a few kilobytes covers it without reaching a neighbouring error.
const VERIFY_REACH: usize = 4096;
/// How many lines back from the link its entry's stamp is looked for: the body
/// spans lines of its own, and only the line that opens the entry is stamped.
const VERIFY_STAMP_LINES: usize = 200;

/// The newest verification demand in `text` inside `horizon`.
///
/// Searched by bytes, not parsed as JSON, and that is forced by the file: the
/// IDE writes the server's stderr in chunks, with blank lines and its own
/// `[LS Main stderr]` prefix wherever a chunk starts, so a body that spans lines
/// does not survive as one JSON document. The one value needed is short and
/// never broken across lines, so it is read as a JSON string where it stands.
fn newest_verification(
    text: &str,
    now: crate::utils::LocalClock,
    horizon: Duration,
) -> Option<Verification> {
    let bytes = text.as_bytes();
    // ASCII lowercasing keeps every byte offset where it was.
    let lower = text.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let mut best: Option<Verification> = None;
    let mut from = 0usize;
    while let Some(off) = find(&lb[from..], b"validation") {
        let key = from + off;
        from = key + 1;
        let Some(value_at) = url_value_start(lb, key) else {
            continue;
        };
        let lo = key.saturating_sub(VERIFY_REACH);
        let hi = (key + VERIFY_REACH).min(bytes.len());
        if !has_reason(&bytes[lo..hi]) {
            continue;
        }
        let Some(url) = read_value(bytes, value_at).filter(|u| is_google_page(u)) else {
            continue;
        };
        let Some(ago) = stamp_before(text, key).and_then(|at| age_secs(at, now)) else {
            continue;
        };
        let ago = Duration::from_secs(ago as u64);
        if ago > horizon {
            continue;
        }
        // `<=`: of two in the same second, the later one in the file.
        if best.as_ref().is_none_or(|b| ago <= b.ago) {
            best = Some(Verification { ago, url });
        }
    }
    best
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Where the value of a link key starting at `key` begins, or `None` if the
/// word there is not one. Takes `validation_url` and `validationUrl` (and Go's
/// `ValidationURL`) - lowercased by the caller - but not
/// `validation_url_link_text`, which is the button's caption.
fn url_value_start(lower: &[u8], key: usize) -> Option<usize> {
    let rest = &lower[key..];
    let len = if rest.starts_with(b"validation_url") {
        14
    } else if rest.starts_with(b"validationurl") {
        13
    } else {
        return None;
    };
    if key > 0 && is_word(lower[key - 1]) {
        return None;
    }
    let mut i = key + len;
    if lower.get(i).is_some_and(|&c| is_word(c)) {
        return None;
    }
    // The key's own closing quote, escaped once when the body was logged as a
    // quoted string.
    if lower.get(i) == Some(&b'\\') {
        i += 1;
    }
    if lower.get(i) == Some(&b'"') {
        i += 1;
    }
    while lower.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
        i += 1;
    }
    if lower.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    while lower.get(i).is_some_and(|c| *c == b' ' || *c == b'\t') {
        i += 1;
    }
    Some(i)
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// `VALIDATION_REQUIRED` as a word of its own, so an enum listing it among
/// others still counts but a longer name that merely contains it does not.
fn has_reason(window: &[u8]) -> bool {
    let mut from = 0usize;
    while let Some(off) = find(&window[from..], VERIFY_REASON) {
        let at = from + off;
        let end = at + VERIFY_REASON.len();
        let before = at == 0 || !is_word(window[at - 1]);
        let after = window.get(end).is_none_or(|&c| !is_word(c));
        if before && after {
            return true;
        }
        from = at + 1;
    }
    false
}

/// The link at `at`, in whichever of the three shapes it was logged: a JSON
/// string (`"https:…&…"`), that string escaped once more because the whole
/// body was logged as a quoted string (`\"https:…\\u0026…\"`), or bare, as Go
/// prints a struct (`ValidationURL:https://… `). JSON escapes are decoded - a
/// link with `&` left in it opens a page with its parameters broken.
fn read_value(bytes: &[u8], at: usize) -> Option<String> {
    let rest = bytes.get(at..)?;
    if rest.starts_with(b"\\\"") {
        // Undo the outer quoting, then read what is left as the JSON string it was.
        let end = find(&rest[2..], b"\\\"")? + 2;
        let mut inner = Vec::with_capacity(end);
        let mut i = 2;
        while i < end {
            if rest[i] == b'\\' && i + 1 < end {
                inner.push(rest[i + 1]);
                i += 2;
            } else {
                inner.push(rest[i]);
                i += 1;
            }
        }
        let lit = format!("\"{}\"", String::from_utf8(inner).ok()?);
        return serde_json::from_str::<String>(&lit).ok();
    }
    if rest.first() == Some(&b'"') {
        let mut i = 1;
        while i < rest.len() {
            match rest[i] {
                b'\\' => i += 2,
                b'"' => {
                    let lit = std::str::from_utf8(&rest[..=i]).ok()?;
                    return serde_json::from_str::<String>(lit).ok();
                }
                b'\n' | b'\r' => return None,
                _ => i += 1,
            }
        }
        return None;
    }
    if rest.starts_with(b"https://") {
        let end = rest
            .iter()
            .position(|c| c.is_ascii_whitespace() || *c == b'}' || *c == b'"')
            .unwrap_or(rest.len());
        return String::from_utf8(rest[..end].to_vec()).ok();
    }
    None
}

/// Only a Google page over HTTPS is ever opened: the link comes out of a log
/// file, and a button that opens whatever a log line says is a button anyone
/// who can write a line there controls.
fn is_google_page(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    if url.len() > 8192 || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest[..host_end].to_ascii_lowercase();
    // No userinfo and no port: `https://google.com@evil/` names `evil`.
    if host.contains(['@', ':', '\\']) {
        return false;
    }
    host == "google.com" || host.ends_with(".google.com")
}

/// The stamp of the entry holding byte `pos`: the nearest stamped line at or
/// above it.
fn stamp_before(text: &str, pos: usize) -> Option<(u16, u16, u32)> {
    let line_end = text[pos..].find('\n').map_or(text.len(), |i| pos + i);
    text[..line_end]
        .rsplit('\n')
        .take(VERIFY_STAMP_LINES)
        .find_map(parse_stamp)
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

    fn refusals_in(path: &Path, from: Option<u64>) -> (u64, usize) {
        let (off, t) = scan(path, from, None, &mut None);
        (off, t.refusals)
    }

    #[test]
    fn history_is_not_news_but_what_is_appended_is() {
        let path = temp_log("append");
        append(&path, REFUSAL);
        append(&path, REFUSAL);
        // First sight: taken from the end, old refusals ignored.
        let (off, hits) = refusals_in(&path, None);
        assert_eq!(hits, 0);
        assert_eq!(off, fs::metadata(&path).unwrap().len());
        // Nothing appended: nothing found, offset unchanged.
        assert_eq!(refusals_in(&path, Some(off)), (off, 0));
        // Appended: found once, and only once.
        append(&path, NOISE);
        append(&path, REFUSAL);
        let (off2, hits) = refusals_in(&path, Some(off));
        assert_eq!(hits, 1);
        assert_eq!(refusals_in(&path, Some(off2)), (off2, 0));
        // A refusal split by a buffer flush: half in one pass, half in the next.
        let cut = REFUSAL.len() / 2;
        append(&path, &REFUSAL[..cut]);
        let (off3, hits) = refusals_in(&path, Some(off2));
        assert_eq!(hits, 0);
        append(&path, &REFUSAL[cut..]);
        let (off4, hits) = refusals_in(&path, Some(off3));
        assert_eq!(hits, 1, "the halves must be read together");
        assert_eq!(refusals_in(&path, Some(off4)), (off4, 0), "and not counted again");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_file_that_shrank_is_read_from_the_start() {
        let path = temp_log("shrink");
        for _ in 0..8 {
            append(&path, NOISE);
        }
        let (off, _) = refusals_in(&path, None);
        assert!(
            off > REFUSAL.len() as u64,
            "the rewrite below must shrink it"
        );
        // The app restarted and truncated its log; the new content is news.
        fs::write(&path, REFUSAL).expect("truncate");
        let (off2, hits) = refusals_in(&path, Some(off));
        assert_eq!(hits, 1);
        assert_eq!(off2, REFUSAL.len() as u64);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_changes_nothing() {
        let path = temp_log("missing");
        assert_eq!(refusals_in(&path, None), (0, 0));
        assert_eq!(refusals_in(&path, Some(42)), (42, 0));
    }

    /// The two real success lines, copied off this machine (Desktop wraps glog in
    /// its own prefix; the CLI writes bare glog). The refused turn in the IDE log
    /// of 2026-09-12 had no such line at all, and the calls that are logged on a
    /// refused session too must not count.
    #[test]
    fn a_model_answer_is_the_generation_call_with_a_response_id() {
        const DESKTOP_OK: &str = "ERROR: logging before google.Init: I0918 17:07:13.969105    1230 http_helpers.go:296] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse Trace: 0xbf323913e34d92f8 ResponseID: kUWtatHf";
        const CLI_OK: &str = "I0918 18:56:33.939879     359 http_helpers.go:299] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse Trace: 0x26e77a0ae05c274c ResponseID: MV-taof4GP2TvdIPieiCmQs";
        const LOAD: &str = "I0918 17:12:08.722720    2138 http_helpers.go:296] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist Trace: 0x65704d0ab55a0ef7";
        assert!(is_answer(DESKTOP_OK.as_bytes()));
        assert!(is_answer(CLI_OK.as_bytes()));
        assert!(!is_answer(LOAD.as_bytes()));
        assert!(!is_answer(REFUSAL.as_bytes()));
        // The stamp of a success line is placed like a refusal's.
        assert!(parse_stamp(DESKTOP_OK).is_some());
        assert!(parse_stamp(CLI_OK).is_some());

        let mut host = None;
        let t = tally(
            format!("{DESKTOP_OK}\n{LOAD}\n{REFUSAL}{CLI_OK}\n").as_bytes(),
            Some(clock(9, 18, 18, 57, 0)),
            &mut host,
        );
        assert_eq!(t.answers, 2);
        assert_eq!(t.refusals, 1);
        // Newest answer: the CLI line at 18:56:33, 27 s before the clock.
        assert_eq!(t.answered_ago, Some(Duration::from_secs(27)));
        // The refusal's stamp is 1 September, not today: unplaceable.
        assert_eq!(t.refused_ago, None);
        // Hosts: the answer names its own; the refusal takes the last URL line
        // before it, the `loadCodeAssist` one.
        assert_eq!(t.answered_host.as_deref(), Some("daily-cloudcode-pa.googleapis.com"));
        assert_eq!(t.refused_host.as_deref(), Some("daily-cloudcode-pa.googleapis.com"));
        assert_eq!(host.as_deref(), Some("daily-cloudcode-pa.googleapis.com"));
        // A URL line for some other host is not a gate host and changes nothing.
        assert_eq!(url_host(b"I0918 x] URL: https://oauth2.googleapis.com/token"), None);
        assert_eq!(
            url_host(b"I0918 x] URL: https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist Trace"),
            Some("cloudcode-pa.googleapis.com".to_string())
        );
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

    /// The window's one-pass reader must agree with the two single-question ones
    /// it replaced, window by window.
    #[test]
    fn one_pass_history_matches_the_single_questions() {
        let Some(now) = crate::utils::local_clock() else {
            return;
        };
        if now.second_of_day < 3600 {
            return;
        }
        let stamp = |back: u32, level: char| {
            let sod = now.second_of_day - back;
            format!(
                "{}{:02}{:02} {:02}:{:02}:{:02}.123456       1 x.go:1] ",
                level,
                now.month,
                now.day,
                sod / 3600,
                (sod / 60) % 60,
                sod % 60
            )
        };
        let path = temp_log("history");
        let refusal = "FAILED_PRECONDITION (code 400): User location is not supported for the API use.";
        let answer = "URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse Trace: 0x1 ResponseID: abc";
        append(&path, &format!("{}{}
", stamp(1800, 'E'), refusal));
        append(&path, &format!("{}{}
", stamp(900, 'I'), answer));
        append(&path, &format!("{}{}
", stamp(120, 'E'), refusal));
        append(&path, &format!("{}{}
", stamp(60, 'E'), refusal));
        let files = [path.clone()];
        let h = history(&files, Duration::from_secs(600), Duration::from_secs(3600));
        assert_eq!(h.refused_recent, newest_refusal(&files, Duration::from_secs(600)));
        assert_eq!(h.refused, newest_refusal(&files, Duration::from_secs(3600)));
        assert_eq!(h.answered, newest_answer(&files, Duration::from_secs(3600)));
        assert_eq!(h.refused_recent.map(|s| s.count), Some(2));
        assert_eq!(h.refused.map(|s| s.count), Some(3));
        assert_eq!(h.answered.map(|s| s.count), Some(1));
        let _ = fs::remove_file(&path);
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

    const NOW: (u16, u16, u32, u32, u32) = (9, 25, 12, 0, 0);

    fn verify_in(text: &str) -> Option<Verification> {
        let (mo, d, h, mi, s) = NOW;
        newest_verification(text, clock(mo, d, h, mi, s), Duration::from_secs(3600))
    }

    /// Google's own shape: a pretty-printed body, `&` escaped as `\u0026`, in
    /// the IDE's framing with a blank line in the middle of it.
    #[test]
    fn a_verification_link_is_read_from_a_pretty_printed_body() {
        let log = concat!(
            "2026-09-25 11:58:00.100 [error] [LS Main stderr] ERROR: logging before google.Init: E0925 11:58:00.100000 1 http_helpers.go:88] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent Status: 403 Body: {\n",
            "  \"error\": {\n",
            "    \"code\": 403,\n",
            "    \"message\": \"Verify your account to continue.\",\n",
            "    \"status\": \"PERMISSION_DENIED\",\n",
            "\n",
            "    \"details\": [\n",
            "      {\n",
            "        \"@type\": \"type.googleapis.com/google.rpc.ErrorInfo\",\n",
            "        \"reason\": \"VALIDATION_REQUIRED\",\n",
            "        \"metadata\": {\n",
            "          \"validation_url_link_text\": \"Verify\",\n",
            "          \"validation_url\": \"https://accounts.google.com/signin/continue?sarp=1\\u0026continue=https%3A%2F%2Fx\\u0026plt=AKgn\"\n",
            "        }\n",
            "      }\n",
            "    ]\n",
            "  }\n",
            "}\n",
            "I0925 11:58:01.000000 1 server.go:1] after\n",
        );
        let v = verify_in(log).expect("found");
        assert_eq!(
            v.url,
            "https://accounts.google.com/signin/continue?sarp=1&continue=https%3A%2F%2Fx&plt=AKgn"
        );
        assert_eq!(v.ago, Duration::from_secs(120));
    }

    /// The body logged as one quoted string, and Go's struct printing.
    #[test]
    fn a_verification_link_is_read_escaped_once_more_and_bare() {
        let quoted = "E0925 11:59:00.000000 1 x.go:1] details: \"{\\\"error\\\":{\\\"details\\\":[{\\\"reason\\\":\\\"VALIDATION_REQUIRED\\\",\\\"metadata\\\":{\\\"validation_url\\\":\\\"https://accounts.google.com/v?a=1\\\\u0026b=2\\\"}}]}}\"\n";
        assert_eq!(
            verify_in(quoted).map(|v| v.url).as_deref(),
            Some("https://accounts.google.com/v?a=1&b=2")
        );
        let bare = "E0925 11:59:30.000000 1 x.go:1] {Reason:VALIDATION_REQUIRED Metadata:{ValidationURL:https://accounts.google.com/v?a=1&b=2 UIMessage:}}\n";
        let v = verify_in(bare).expect("found");
        assert_eq!(v.url, "https://accounts.google.com/v?a=1&b=2");
        assert_eq!(v.ago, Duration::from_secs(30));
    }

    /// The camelCase field of an ineligible tier at sign-in, newest wins.
    #[test]
    fn the_newest_verification_link_wins() {
        let log = concat!(
            "E0925 11:10:00.000000 1 x.go:1] {\"reasonCode\": \"VALIDATION_REQUIRED\", \"validationUrl\": \"https://accounts.google.com/old\"}\n",
            "E0925 11:50:00.000000 1 x.go:1] {\"reasonCode\": \"VALIDATION_REQUIRED\", \"validationUrl\": \"https://accounts.google.com/new\"}\n",
        );
        assert_eq!(
            verify_in(log).map(|v| v.url).as_deref(),
            Some("https://accounts.google.com/new")
        );
    }

    /// Only a Google page, only next to its reason, only a page that can be
    /// placed in time.
    #[test]
    fn a_link_that_is_not_a_verification_demand_is_ignored() {
        let foreign = "E0925 11:58:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"https://accounts.google.com.evil.example/x\"}\n";
        assert_eq!(verify_in(foreign), None);
        let userinfo = "E0925 11:58:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"https://accounts.google.com@evil.example/x\"}\n";
        assert_eq!(verify_in(userinfo), None);
        let plain = "E0925 11:58:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"http://accounts.google.com/x\"}\n";
        assert_eq!(verify_in(plain), None);
        let other_reason = "E0925 11:58:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED_SOON\", \"validation_url\": \"https://accounts.google.com/x\"}\n";
        assert_eq!(verify_in(other_reason), None);
        let unstamped = "{\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"https://accounts.google.com/x\"}\n";
        assert_eq!(verify_in(unstamped), None);
        let old = "E0925 09:00:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"https://accounts.google.com/x\"}\n";
        assert_eq!(verify_in(old), None);
    }
}
