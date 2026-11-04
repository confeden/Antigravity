use regex::Regex;
use std::fs;
use std::io::Write;
#[cfg(not(windows))]
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::patch_binary::RepatchOutcome;

/// Suffix of the pristine copy kept beside a JS file we rewrite. Same string the
/// bootstrap tooling uses, so they interoperate.
///
/// Why a backup at all (2.11.0_1): `patch_ide` REWRITES the auth function body,
/// which - unlike the same-length binary rename - cannot be reversed from the
/// patched bytes alone. Without a pristine copy, "Полный откат" left the IDE's
/// `main.js` patched forever (G25). The backup is written once, before the first
/// edit, and the revert restores from it.
const JS_BAK: &str = ".ag_backup";

/// The scripts owned by the existing IDE/Desktop JS patch and restore paths.
/// Construction performs no observation; callers receive each optional file
/// with their own checked I/O contract.
pub(crate) struct JsTargets {
    pub(crate) ide_main: PathBuf,
    pub(crate) desktop_main: PathBuf,
    pub(crate) extension: PathBuf,
}
impl JsTargets {
    pub(crate) fn into_paths(self) -> [PathBuf; 3] {
        [self.ide_main, self.desktop_main, self.extension]
    }
}
pub(crate) fn js_targets(inst: &Path) -> JsTargets {
    let app = inst.join("resources").join("app");
    JsTargets { ide_main: app.join("out").join("main.js"),
        desktop_main: app.join("dist").join("main.js"),
        extension: app.join("extensions").join("antigravity").join("dist").join("extension.js") }
}

fn backup_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(JS_BAK);
    PathBuf::from(s)
}

struct PinnedJs {
    path: PathBuf,
    #[cfg(windows)]
    file: crate::windows_coordinator::windows_installation::CheckedPath,
    #[cfg(not(windows))]
    file: fs::File,
}
impl PinnedJs {
    fn open(path: &Path) -> Result<Self, String> {
        #[cfg(windows)]
        let file = {
            use crate::windows_coordinator::windows_installation::{CheckedPath, PathKind, PathPurpose};
            CheckedPath::open(path, PathKind::File, PathPurpose::ReplaceSource)?
        };
        #[cfg(unix)]
        let file = {
            let metadata = fs::symlink_metadata(path).map_err(|e| format!("JS metadata: {e}"))?;
            if !metadata.file_type().is_file() { return Err("JS target is not a regular file".into()); }
            use rustix::fs::{Mode, OFlags};
            let file = fs::File::from(rustix::fs::open(path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())
                .map_err(|e| format!("JS open: {e}"))?);
            if !file.metadata().map_err(|e| format!("JS handle metadata: {e}"))?.is_file() { return Err("JS target is not a regular file".into()); }
            file
        };
        #[cfg(not(any(windows, unix)))]
        return Err("JS checked receiving is unsupported on this platform".into());
        let pin = Self { path: path.to_owned(), file };
        pin.recheck()?;
        Ok(pin)
    }
    fn read(&self) -> Result<Vec<u8>, String> {
        #[cfg(windows)]
        { self.file.read_snapshot() }
        #[cfg(not(windows))]
        {
            let mut file = self.file.try_clone().map_err(|e| format!("JS read handle: {e}"))?;
            file.seek(SeekFrom::Start(0)).map_err(|e| format!("JS seek: {e}"))?;
            let mut bytes = Vec::new(); file.read_to_end(&mut bytes).map_err(|e| format!("JS read: {e}"))?; Ok(bytes)
        }
    }
    fn recheck(&self) -> Result<(), String> {
        #[cfg(windows)]
        { self.file.recheck() }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let held = self.file.metadata().map_err(|e| format!("JS held metadata: {e}"))?;
            let entry = fs::symlink_metadata(&self.path).map_err(|e| format!("JS path metadata: {e}"))?;
            if !entry.file_type().is_file() || held.dev() != entry.dev() || held.ino() != entry.ino() {
                return Err("JS target identity changed".into());
            }
            Ok(())
        }
        #[cfg(not(any(windows, unix)))]
        { Err("JS checked receiving is unsupported on this platform".into()) }
    }
}

fn create_exclusive(path: &Path) -> Result<Option<fs::File>, String> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        match rustix::fs::open(path, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600)) {
            Ok(file) => Ok(Some(fs::File::from(file))),
            Err(rustix::io::Errno::EXIST) => Ok(None),
            Err(error) => Err(format!("JS exclusive creation failed: {error}")),
        }
    }
    #[cfg(windows)]
    {
        match fs::OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(error) => Err(format!("JS exclusive creation failed: {error}")),
        }
    }
    #[cfg(not(any(windows, unix)))]
    { Err("JS checked receiving is unsupported on this platform".into()) }
}

fn receive_backup(path: &Path, expected: &[u8]) -> Result<PinnedJs, String> {
    let pin = PinnedJs::open(path).map_err(|e| format!("JS backup unavailable: {e}"))?;
    let actual = pin.read()?;
    pin.recheck()?;
    if actual != expected { return Err("JS backup conflicts with the exact current preimage".into()); }
    Ok(pin)
}

#[cfg(windows)]
fn publish_backup(stage: &Path, backup: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    let from: Vec<u16> = stage.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = backup.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        Err(std::io::Error::last_os_error())
    } else { Ok(()) }
}
#[cfg(unix)]
fn publish_backup(stage: &Path, backup: &Path) -> std::io::Result<()> { fs::hard_link(stage, backup) }

/// Only a complete, synced and independently received stage may be published
/// to the restore-authority path. Partial stages are retained, never adopted.
fn backup_once(target: &Path, expected: &[u8]) -> Result<(), String> {
    let backup = backup_path(target);
    match fs::symlink_metadata(&backup) {
        Ok(_) => { receive_backup(&backup, expected)?; return Ok(()); }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(format!("JS backup observation failed: {error}")),
    }
    let stage = crate::patch_binary::temp_path(&backup);
    let mut file = create_exclusive(&stage)?.ok_or_else(|| format!("JS backup staging path occupied: {}", stage.display()))?;
            #[cfg(test)]
            if TEST_BACKUP_FAILURE.with(|value| value.get() == 1) {
                return Err(format!("JS backup stage incomplete; entry retained at {}: synthetic write failure", stage.display()));
            }
            file.write_all(expected).map_err(|e|
                format!("JS backup stage incomplete; entry retained at {}: {e}", stage.display()))?;
            #[cfg(test)]
            if TEST_BACKUP_FAILURE.with(|value| value.get() == 2) {
                return Err(format!("JS backup stage incomplete; entry retained at {}: synthetic flush failure", stage.display()));
            }
            file.sync_all().map_err(|e|
                format!("JS backup stage incomplete; entry retained at {}: {e}", stage.display()))?;
            drop(file);
    #[cfg(test)]
    if TEST_BACKUP_FAILURE.with(|value| value.get() == 3) {
        return Err(format!("JS backup stage readback unavailable; entry retained at {}: synthetic read failure", stage.display()));
    }
    let stage_pin = PinnedJs::open(&stage).map_err(|e| format!("JS backup stage unavailable; retained at {}: {e}", stage.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if stage_pin.file.metadata().map_err(|e| format!("JS backup stage metadata unavailable at {}: {e}", stage.display()))?.nlink() != 1 {
            return Err(format!("JS backup stage link count differs; retained at {}", stage.display()));
        }
    }
    if stage_pin.read().map_err(|e| format!("JS backup stage read failed at {}: {e}", stage.display()))? != expected {
        return Err(format!("JS backup stage readback differs; retained at {}", stage.display()));
    }
    stage_pin.recheck().map_err(|e| format!("JS backup stage identity unavailable at {}: {e}", stage.display()))?;
    #[cfg(test)]
    match TEST_BACKUP_FAILURE.with(|value| value.get()) {
        4 | 5 | 7 => {
            let mut competitor = create_exclusive(&backup)?.ok_or("synthetic competing backup already exists")?;
            let same = TEST_BACKUP_FAILURE.with(|value| value.get()) != 5;
            competitor.write_all(if same { expected } else { b"different competitor" }).map_err(|e| e.to_string())?;
            competitor.sync_all().map_err(|e| e.to_string())?;
        }
        _ => {},
    }
    let published = match publish_backup(&stage, &backup) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(format!("JS backup publication failed; stage retained at {}: {error}", stage.display())),
    };
    #[cfg(unix)]
    {
        #[cfg(test)]
        if TEST_BACKUP_FAILURE.with(|value| value.get() == 8) {
            let displaced = stage.with_extension("test-displaced");
            fs::rename(&stage, &displaced).map_err(|e| e.to_string())?;
            fs::write(&stage, b"synthetic substitute").map_err(|e| e.to_string())?;
        }
        #[cfg(test)]
        if TEST_BACKUP_FAILURE.with(|value| matches!(value.get(), 6 | 7)) {
            return Err(format!("JS backup stage cleanup failed; entry state unconfirmed at {}: synthetic failure", stage.display()));
        }
        stage_pin.recheck().map_err(|e| format!("JS backup stage cleanup identity unconfirmed at {}: {e}", stage.display()))?;
        fs::remove_file(&stage).map_err(|e| format!("JS backup stage cleanup failed; entry state unconfirmed at {}: {e}", stage.display()))?;
    }
    #[cfg(windows)]
    if !published {
        #[cfg(test)]
        if TEST_BACKUP_FAILURE.with(|value| value.get() == 7) {
            return Err(format!("JS backup stage cleanup failed; entry state unconfirmed at {}: synthetic failure", stage.display()));
        }
        stage_pin.recheck().map_err(|e| format!("JS backup stage cleanup identity unconfirmed at {}: {e}", stage.display()))?;
        fs::remove_file(&stage).map_err(|e| format!("JS backup stage cleanup failed; entry state unconfirmed at {}: {e}", stage.display()))?;
    }
    let final_pin = receive_backup(&backup, expected).map_err(|e| format!("JS backup final receiving failed; stage settlement completed: {e}"))?;
    #[cfg(windows)]
    if published && stage_pin.file.native_id() != final_pin.file.native_id() {
        return Err("JS backup published identity differs from verified stage".into());
    }
    #[cfg(unix)]
    let _ = published;
    drop(final_pin);
    Ok(())
}

#[cfg(test)]
thread_local! {
    static TEST_READBACK_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TEST_BACKUP_FAILURE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn replace_checked(pin: &PinnedJs, original: &[u8], prepared: &str) -> Result<(), String> {
    pin.recheck()?;
    if pin.read()? != original { return Err("JS preimage changed before backup".into()); }
    backup_once(&pin.path, original)?;
    pin.recheck()?;
    if pin.read()? != original { return Err("JS preimage changed before replacement; backup retained".into()); }
    pin.recheck()?;
    write_atomic(&pin.path, prepared).map_err(|e| format!("JS replacement failed; outcome unconfirmed; backup retained: {e}"))?;
    #[cfg(test)]
    if TEST_READBACK_FAILURE.with(|value| value.replace(false)) {
        return Err("JS replaced; readback unavailable; backup retained: synthetic failure".into());
    }
    let result = PinnedJs::open(&pin.path).map_err(|e| format!("JS replaced; readback unavailable; backup retained: {e}"))?;
    let actual = result.read().map_err(|e| format!("JS replaced; readback failed; backup retained: {e}"))?;
    result.recheck().map_err(|e| format!("JS replaced; readback identity changed; backup retained: {e}"))?;
    if actual != prepared.as_bytes() { return Err("JS replaced; readback differs; backup retained".into()); }
    Ok(())
}

/// Writes `content` to `path` without a torn intermediate state: a sibling temp
/// on the same directory, then a rename over the target (atomic replace on
/// Windows and POSIX). A crash or power loss leaves either the old file or the
/// new one, never a half-written 15 MB `main.js`.
fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    // Per-process naming remains the existing owner; an occupied stage is not
    // deleted or considered ours solely because of its age.
    let tmp = crate::patch_binary::temp_path(path);
    let mut file = create_exclusive(&tmp).map_err(std::io::Error::other)?
        .ok_or_else(|| std::io::Error::other("JS staging path already exists"))?;
    if let Err(e) = file.write_all(content.as_bytes()).and_then(|_| file.sync_all()) {
        drop(file);
        return Err(std::io::Error::other(format!("JS stage state unconfirmed at {}: {e}", tmp.display())));
    }
    drop(file);
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => Err(std::io::Error::other(format!("JS stage state unconfirmed at {}: {e}", tmp.display()))),
    }
}

/// Restores a JS file we rewrote from its pristine backup, and removes the
/// backup. Returns `Ok(true)` when it restored something, `Ok(false)` when there
/// was nothing of ours to undo.
///
/// A backup is the only faithful revert (the body was rewritten, not marked), so
/// this prefers it. If the backup is gone but our marker is present, it strips
/// the marker as a last resort and says so - the auth body then stays rewritten,
/// which still lets Antigravity run; a clean restore needs a reinstall.
fn restore_js(target: &Path) -> Result<bool, String> {
    let outcome = restore_js_result(target)?;
    if outcome == JsRestore::MarkerOnly {
        eprintln!("  [WARN] {}: бэкап отсутствует — снят только маркер, тело патча осталось (для чистого возврата переустановите Antigravity)", target.display());
    }
    Ok(outcome != JsRestore::Unchanged)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JsRestore { Unchanged, BackupRestored, MarkerOnly }

fn restore_js_result(target: &Path) -> Result<JsRestore, String> {
    match fs::metadata(target) {
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(JsRestore::Unchanged),
        Err(error) => return Err(format!("не проверить JS для восстановления: {error}")),
    }
    let bak = backup_path(target);
    let backup_present = match fs::metadata(&bak) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("не проверить бэкап: {error}")),
    };
    if backup_present {
        let data = fs::read(&bak).map_err(|e| format!("не прочитать бэкап: {}", e))?;
        let text = String::from_utf8(data).map_err(|_| "бэкап JS повреждён: недопустимая кодировка")?;
        write_atomic(target, &text)
            .map_err(|e| format!("не записать {}: {}", target.display(), e))?;
        fs::remove_file(&bak).map_err(|error| format!("JS восстановлен, но бэкап не удалён: {error}"))?;
        return Ok(JsRestore::BackupRestored);
    }
    let content = match fs::read_to_string(target) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(JsRestore::Unchanged),
        Err(error) => return Err(format!("не прочитать JS для восстановления: {error}")),
    };
    if let Some(stripped) = strip_marker(&content) {
        write_atomic(target, &stripped)
            .map_err(|e| format!("не записать {}: {}", target.display(), e))?;
        return Ok(JsRestore::MarkerOnly);
    }
    Ok(JsRestore::Unchanged)
}

/// Reverts our IDE JS edits (`main.js` and the extension) for one install.
/// Returns how many files it restored.
/// Restores the IDE's JS from its pristine backups, one result per file.
///
/// Same reasoning as `patch_binary::unpatch_all_binaries`: a bare count turned a
/// failed restore into a silent success, and the messages went to a console the
/// window does not have.
pub fn unpatch_ide_js(inst: &Path) -> Vec<(String, Result<bool, String>)> {
    unpatch_js_batch(inst, false).into_iter().map(|(name, result)| {
        if matches!(result, Ok(JsRestore::MarkerOnly)) { eprintln!("[WARN] {name}: бэкап отсутствует — снят только маркер, тело патча осталось"); }
        (name, result.map(|outcome| outcome != JsRestore::Unchanged))
    }).collect()
}

#[derive(Debug)]
pub(crate) struct JsUndoFailure { pub(crate) completed: Vec<(String, JsRestore)>, pub(crate) cause: String }

pub(crate) fn unpatch_ide_js_checked(inst: &Path) -> Result<Vec<(String, JsRestore)>, JsUndoFailure> {
    let mut received = Vec::new();
    for (name, result) in unpatch_js_batch(inst, true) {
        match result {
            Ok(outcome) => received.push((name, outcome)),
            Err(error) => return Err(JsUndoFailure { completed: received, cause: format!("{name}: {error}") }),
        }
    }
    Ok(received)
}

fn unpatch_js_batch(inst: &Path, stop_on_failure: bool) -> Vec<(String, Result<JsRestore, String>)> {
    let mut out = Vec::new();
    let scripts = js_targets(inst);
    for (name, target) in [("main.js", scripts.ide_main), ("extension.js", scripts.extension)] {
        let result = restore_js_result(&target);
        let failed = result.is_err();
        if !matches!(result, Ok(JsRestore::Unchanged)) { out.push((name.to_owned(), result)); }
        if stop_on_failure && failed { break; }
    }
    out
}

fn detect_stacked_ide(content: &str) -> bool {
    content.contains("/*[AG_PATCHED]*/") || content.contains("[AG_PROXY_HOOK]")
}

/// Every file we rewrite ends with this comment. Releases up to 2.5.0 wrote the
/// bare prefix; newer ones append the canaries (see `canary::file_marker`), so
/// detection matches on the prefix and stays compatible with installs patched by
/// an older build - `has_marker` decides "already patched", and getting that
/// wrong would either re-patch a patched file or refuse to revert one.
const MARKER_PREFIX: &str = "// UNLOCKED";

/// True when the last non-empty line is our marker, tokenised or legacy.
fn has_marker(content: &str) -> bool {
    let trimmed = content.trim_end();
    let last_line = trimmed.rsplit('\n').next().unwrap_or(trimmed);
    last_line.trim_start().starts_with(MARKER_PREFIX)
}

/// Drops a trailing marker line. Returns None when there is none, so callers can
/// tell "nothing to strip" from "stripped".
fn strip_marker(content: &str) -> Option<String> {
    if !has_marker(content) {
        return None;
    }
    let end = content.trim_end().len();
    match content[..end].rfind('\n') {
        Some(nl) => Some(content[..nl].to_string()),
        // Marker is the whole file: nothing but the marker to remove.
        None => Some(String::new()),
    }
}

fn unsupported_ide(detail: &str) -> String {
    format!("Сигнатура не найдена ({}); исходный файл сохранён", detail)
}

// A token-aware delimiter walk: strings, comments and regex tokens never own
// braces; template interpolation owns an explicit stack entry in the scanner.
fn closing_token(tokens: &[ress::Item<&str>], start: usize) -> Option<usize> {
    use ress::tokens::{Punct, Template, Token};
    let mut stack = Vec::new();
    for (index, item) in tokens.iter().enumerate().skip(start) {
        match &item.token {
            Token::Punct(Punct::OpenBrace) => stack.push(0),
            Token::Punct(Punct::OpenParen) => stack.push(1),
            Token::Punct(Punct::OpenBracket) => stack.push(2),
            Token::Template(Template::Head(_)) => stack.push(3),
            Token::Template(Template::Middle(_)) if stack.last() == Some(&3) => {},
            Token::Template(Template::Tail(_)) if stack.pop() == Some(3) => {},
            Token::Punct(Punct::CloseBrace) if stack.pop() == Some(0) => {},
            Token::Punct(Punct::CloseParen) if stack.pop() == Some(1) => {},
            Token::Punct(Punct::CloseBracket) if stack.pop() == Some(2) => {},
            Token::Punct(Punct::CloseBrace | Punct::CloseParen | Punct::CloseBracket)
                | Token::Template(Template::Middle(_) | Template::Tail(_)) => return None,
            _ => {},
        }
        if stack.is_empty() { return Some(index); }
    }
    None
}

struct IdeCandidate<'a> {
    start: usize, method: usize, branch: usize, tryopen: usize, tryclose: usize, catchopen: usize,
    fname: &'a str, arg: &'a str, sender: &'a str, reset: &'a str,
    func: &'a str, mapped: &'a str, push: &'a str, fire: &'a str, valid_roles: bool,
}
struct IdeTokens<'a, 'b> { source: &'a str, tokens: &'b [ress::Item<&'a str>], at: usize }
impl<'a> IdeTokens<'a, '_> {
    fn literal(&mut self, value: &str) -> Option<()> {
        let token = self.tokens.get(self.at)?;
        if token.token.is_string() || token.token.is_regex() || token.token.is_template() || token.token != value { return None; }
        self.at += 1; Some(())
    }
    fn string(&mut self, value: &str) -> Option<()> {
        let token = self.tokens.get(self.at)?;
        if !token.token.is_string() || token.token != value { return None; }
        self.at += 1; Some(())
    }
    fn ident(&mut self) -> Option<&'a str> {
        let token = self.tokens.get(self.at)?;
        if !token.token.is_ident() { return None; }
        self.at += 1; Some(&self.source[token.span.start..token.span.end])
    }
    fn literals(&mut self, values: &[&str]) -> Option<()> {
        for value in values { self.literal(value)?; } Some(())
    }
}
fn ide_candidate<'a>(source: &'a str, tokens: &[ress::Item<&'a str>], start: usize, anchor: &mut bool) -> Option<IdeCandidate<'a>> {
    let mut p = IdeTokens { source, tokens, at: start };
    p.literal("async")?; let fname = p.ident()?; p.literal("(")?; let arg = p.ident()?;
    p.literal(")")?; let method = p.at; p.literals(&["{", "if", "(", "this", "."])?;
    let sender = p.ident()?; p.literals(&[".", "send", "(", "{", "type", ":"])?;
    let signarg = p.ident()?; p.literals(&[".", "isGcpTos", "?"])?;
    p.string("GCP_SIGN_IN")?; p.literal(":")?; p.string("SIGN_IN")?;
    p.literals(&["}", ")", ",", "this", "."])?; let reset = p.ident()?;
    p.literals(&[".", "resetIsTierGCPTos", "(", ")", ","])?;
    *anchor = true;
    if p.tokens.get(p.at)?.token.is_boolean_true() { p.at += 1; }
    else { p.literals(&["this", "."])?; p.ident()?; p.literals(&[".", "isGoogleInternal"])?; }
    p.literal(")")?; let branch = p.at; p.literals(&["{", "try"])?; let tryopen = p.at;
    p.literals(&["{", "await", "this", "."])?; let load = p.ident()?;
    p.literals(&[".", "loadCodeAssist", "("])?; let loadarg = p.ident()?;
    p.literals(&[")", ";", "const", "{", "settings", ":"])?; let settings = p.ident()?;
    p.literals(&[",", "userTier", ":"])?; let tier = p.ident()?;
    p.literals(&["}", "=", "await", "this", ".", "refreshUserStatus", "("])?;
    let refresharg = p.ident()?; p.literals(&[")", ","])?; let mapped = p.ident()?;
    p.literal("=")?; let func = p.ident()?; p.literal("(")?; let maparg = p.ident()?;
    p.literals(&[")", ";", "this", "."])?; let push = p.ident()?;
    p.literals(&[".", "pushUpdate", "("])?; let pusharg = p.ident()?;
    p.literals(&[")", ",", "this", "."])?; let success_sender = p.ident()?;
    p.literals(&[".", "send", "(", "{", "type", ":"])?; p.string("AUTH_SUCCESS")?;
    p.literals(&[",", "tokenInfo", ":"])?; let successarg = p.ident()?;
    p.literals(&["}", ")", ",", "this", "."])?; let fire = p.ident()?;
    p.literals(&[".", "fire", "(", "{", "settings", ":"])?; let event_settings = p.ident()?;
    p.literals(&[",", "userTier", ":"])?; let event_tier = p.ident()?;
    p.literals(&["}", ")"])?; let tryclose = p.at;
    p.literals(&["}", "catch", "("])?; p.ident()?; p.literal(")")?; let catchopen = p.at; p.literal("{")?;
    let valid_roles = arg == signarg && reset == load && arg == loadarg && arg == refresharg
        && arg == maparg && mapped == pusharg && sender == success_sender && arg == successarg
        && settings == event_settings && tier == event_tier;
    Some(IdeCandidate { start, method, branch, tryopen, tryclose, catchopen,
        fname, arg, sender, reset, func, mapped, push, fire, valid_roles })
}

fn transform_ide(content: &str) -> Result<Option<String>, String> {
    if has_marker(content) && !detect_stacked_ide(content) { return Ok(None); }
    if detect_stacked_ide(content) || has_marker(content) {
        return Err("Обнаружена старая версия патча. Пожалуйста, выполните чистую переустановку Antigravity IDE перед повторным патчем.".into());
    }
    let tokens: Vec<_> = ress::Scanner::new(content).filter_map(|item| match item {
        Ok(item) if matches!(item.token, ress::tokens::Token::Comment(_)) => None,
        other => Some(other),
    }).collect::<Result<_, _>>().map_err(|_| unsupported_ide("ошибка разбора JavaScript"))?;
    let mut anchors = 0usize;
    let mut candidates = Vec::new();
    for start in 0..tokens.len() {
        let mut anchor = false;
        if let Some(candidate) = ide_candidate(content, &tokens, start, &mut anchor) { candidates.push(candidate); }
        if anchor { anchors += 1; }
    }
    if anchors != 1 || candidates.len() != 1 { return Err(unsupported_ide("нет единственной структуры IDE")); }
    let candidate = &candidates[0];
    if !candidate.valid_roles { return Err(unsupported_ide("несогласованные связи метода")); }
    let Some(tryclose) = closing_token(&tokens, candidate.tryopen) else { return Err(unsupported_ide("незакрытый try")); };
    if tryclose != candidate.tryclose { return Err(unsupported_ide("неоднозначная граница try")); }
    let Some(catchclose) = closing_token(&tokens, candidate.catchopen) else { return Err(unsupported_ide("незакрытый catch")); };
    let Some(branchclose) = closing_token(&tokens, candidate.branch) else { return Err(unsupported_ide("незакрытая ветвь")); };
    let Some(methodclose) = closing_token(&tokens, candidate.method) else { return Err(unsupported_ide("незакрытый метод")); };
    let mut next = catchclose + 1;
    let mut exit = IdeTokens { source: content, tokens: &tokens, at: next };
    if !matches!(tokens.get(exit.at).map(|item| &item.token), Some(ress::tokens::Token::Keyword(ress::tokens::Keyword::Return(_))))
        || exit.literal("return").is_none() { return Err(unsupported_ide("неизвестный выход ветви")); }
    if matches!(tokens.get(exit.at).map(|item| &item.token), Some(ress::tokens::Token::Punct(ress::tokens::Punct::SemiColon))) {
        let _ = exit.literal(";");
    }
    next = exit.at;
    if next != branchclose || branchclose >= methodclose { return Err(unsupported_ide("неоднозначная граница ветви")); }
    let fname = candidate.fname; let var_t = candidate.arg; let var_t_send = candidate.sender;
    let var_y = candidate.reset; let var_func = candidate.func; let var_f = candidate.push;
    let var_h = candidate.fire; let var_i = candidate.mapped;

        let payload = format!(
            r#"async {fname}({var_t}){{
    this.{var_t_send}.send({{type:{var_t}.isGcpTos?"GCP_SIGN_IN":"SIGN_IN"}});
    this.{var_y}.resetIsTierGCPTos();
    try {{
        try {{ await this.{var_y}.loadCodeAssist({var_t}); }} catch(_) {{}}
        try {{ await this.{var_y}.onboardUser("standard-tier", {var_t}); }} catch(_) {{
            try {{ await this.{var_y}.onboardUser("free-tier", {var_t}); }} catch(__) {{}}
        }}
        let __res = {{ settings: {{}}, userTier: {{ id: "pro", description: "Pro" }} }};
        try {{ __res = await this.refreshUserStatus({var_t}); }} catch(_) {{}}
        const {var_i} = {var_func}({var_t});
        try {{ this.{var_f}.pushUpdate({var_i}); }} catch(_) {{}}
        this.{var_t_send}.send({{type:"AUTH_SUCCESS",tokenInfo:{var_t}}});
        this.{var_h}.fire({{settings:__res.settings, userTier:__res.userTier}});
    }} catch(e) {{}}
    return;
"#
        );

        let new_content = format!(
            "{}\n{}",
            content[..tokens[candidate.start].span.start].to_string()
                + &payload
                + &content[tokens[branchclose].span.end..],
            crate::canary::file_marker()
        );
        Ok(Some(new_content))
}

enum IdeFailure { Structural(String), Effect(String) }
impl IdeFailure { fn message(self) -> String { match self { Self::Structural(value) | Self::Effect(value) => value } } }
fn patch_ide_received(main_js: &Path) -> Result<(), IdeFailure> {
    let pin = PinnedJs::open(main_js).map_err(IdeFailure::Effect)?;
    let original = pin.read().map_err(IdeFailure::Effect)?;
    let content = std::str::from_utf8(&original).map_err(|e| IdeFailure::Effect(format!("JS encoding: {e}")))?;
    match transform_ide(content).map_err(IdeFailure::Structural)? {
        Some(prepared) => replace_checked(&pin, &original, &prepared).map_err(IdeFailure::Effect),
        None => Ok(()),
    }
}
pub fn patch_ide(_inst: &Path, main_js: &Path) -> Result<(), String> {
    patch_ide_received(main_js).map_err(IdeFailure::message)
}

/// Re-applies the IDE `main.js` patch after an update reverted it, classified
/// the same way as the binary rename so the watchdog can treat every target
/// uniformly.
///
/// `patch_ide` is fail-safe by construction - it writes only when its very
/// specific regex matches, and errors otherwise without touching the file - so
/// a build it does not understand yields `SignatureMissing` (leave it, show the
/// user the error) rather than a corrupted `main.js`. An I/O error (the file
/// briefly locked mid-update) stays `Failed` so it is retried, not written off.
pub fn repatch_ide_js(main_js: &Path) -> RepatchOutcome {
    let content = match fs::read_to_string(main_js) {
        Ok(c) => c,
        Err(e) => return RepatchOutcome::Failed(e.to_string()),
    };
    if has_marker(&content) && !detect_stacked_ide(&content) {
        return RepatchOutcome::AlreadyPatched;
    }
    match patch_ide_received(main_js) {
        Ok(()) => RepatchOutcome::Repatched(1),
        // "Signature not found" and "old patch, reinstall" are both give-up
        // conditions - a human has to act, so surface the app's own error
        // instead of guessing. Anything else is an I/O problem worth retrying.
        Err(IdeFailure::Structural(_)) => RepatchOutcome::SignatureMissing,
        Err(IdeFailure::Effect(e)) => RepatchOutcome::Failed(e),
    }
}

/// v2.4+ Desktop: modular Electron shell, auth lives in Language Server binary.
/// Verified against 2.4.2 and 2.5.0 - `dist/main.js` only wires up the shell
/// (`./languageServer`, `./ipcHandlers`) and carries no auth/eligibility code.
pub fn is_new_desktop_architecture(content: &str) -> bool {
    let modular = content.contains("./languageServer") && content.contains("./ipcHandlers");
    let legacy_auth = content.contains("_handleAuthErrorResponse")
        || content.contains("getUserStatus")
        || content.contains("\"AUTH_SUCCESS\"")
        || content.contains("\"SET_INELIGIBLE\"");
    modular && !legacy_auth
}

pub fn patch_desktop(_inst: &Path, main_js: &Path) -> Result<bool, String> {
    let content = fs::read_to_string(main_js).map_err(|e| e.to_string())?;

    let cleaned = strip_desktop_hook(&content);

    // v2.4+: auth handled entirely by Language Server binary (patched separately).
    // No JS modification needed — skip proxy hook and inline patches.
    if is_new_desktop_architecture(&cleaned) {
        if cleaned != content {
            fs::write(main_js, &cleaned).map_err(|e| e.to_string())?;
            println!("  [INFO] Удалён устаревший JS-патч");
        }
        println!("  [INFO] v2.4+ архитектура — JS-патч не требуется (auth в Language Server)");
        return Ok(false);
    }

    let inline_patched = apply_desktop_inline_patches(&cleaned);

    obfstr::obfstr! {
        let hook = r#"// [AG_PROXY_HOOK]
const _elec = require('electron');
const http = require('http');
const https = require('https');
const zlib = require('zlib');

let agProxyPort = 0;
let realLsPort = 0;
let agApiPort = 0;

const proxyServer = http.createServer((req, res) => {
    if (!realLsPort) {
        if (!res.headersSent) res.writeHead(500);
        return res.end('No LS port');
    }
    const options = {
        hostname: '127.0.0.1',
        port: realLsPort,
        path: req.url,
        method: req.method,
        headers: req.headers,
        rejectUnauthorized: false
    };

    const proxyReq = https.request(options, (proxyRes) => {
        if (req.url.includes('main.js')) {
            const chunks = [];
            proxyRes.on('data', c => chunks.push(c));
            proxyRes.on('end', () => {
                let buffer = Buffer.concat(chunks);
                const encoding = (proxyRes.headers['content-encoding'] || '').toLowerCase();
                let wasCompressed = false;
                if (encoding.includes('gzip')) {
                    try { buffer = zlib.gunzipSync(buffer); wasCompressed = true; } catch(e){}
                } else if (encoding.includes('br')) {
                    try { buffer = zlib.brotliDecompressSync(buffer); wasCompressed = true; } catch(e){}
                }

                let body = buffer.toString('utf-8');

                body = body.replace(/_handleAuthErrorResponse\(([a-zA-Z_$]+)\)\{var ([a-zA-Z_$]+)=\1\?\.failureDetails;/g, '_handleAuthErrorResponse($1){var $2=$1?.failureDetails; if($2?.case==="ineligible"){ this._authActor.send({type:"AUTH_SUCCESS",tokenInfo:{accessToken:""},scopes:[],isGcpTos:false}); return; }');
                body = body.replace(/\?\.failureDetails\?\.case==="ineligible"\?this\._authActor\.send\(\{type:"SET_INELIGIBLE"/g, '?.failureDetails?.case==="NEVER_MATCH"?this._authActor.send({type:"SET_INELIGIBLE"');

                const pattern2 = /let ([A-Za-z_$]+)=.*\.getUserStatus\(\{\}\)\)\)\.userStatus;if\(\1\)\{/g;
                body = body.replace(pattern2, (match, p1) => {
                    return match.replace(`if(${p1}){`, `${p1}={planStatus:{planInfo:{planName:"pro"}}, disableTelemetry:false, userDataCollectionForceDisabled:false};if(${p1}){`);
                });

                let outBuffer = Buffer.from(body, 'utf-8');
                if (wasCompressed) {
                    if (encoding.includes('gzip')) outBuffer = zlib.gzipSync(outBuffer);
                    else if (encoding.includes('br')) outBuffer = zlib.brotliCompressSync(outBuffer);
                }

                const headers = { ...proxyRes.headers };
                headers['content-length'] = outBuffer.length;
                if (!res.headersSent) res.writeHead(proxyRes.statusCode, headers);
                res.end(outBuffer);
            });
        } else {
            if (!res.headersSent) res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res, { end: true });
        }
    });

    proxyReq.on('error', (e) => {
        if (!res.headersSent) res.writeHead(500);
        res.end();
    });
    req.pipe(proxyReq, { end: true });
});

proxyServer.listen(0, '127.0.0.1', () => { agProxyPort = proxyServer.address().port; });

const apiProxyServer = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    const body = [];
    req.on('data', c => body.push(c));
    req.on('end', () => {
        const reqBody = Buffer.concat(body).toString('utf-8');
        if (req.url.includes('UserStatus') || req.url.includes('getUserStatus') || req.url.includes('refreshUserStatus') || req.url.includes('userStatus')) {
            return res.end(JSON.stringify({
                userStatus: {
                    userTier: { id: "pro", description: "Pro" },
                    currentTier: { id: "STANDARD", hasOnboardedPreviously: true },
                    planStatus: { planInfo: { planName: "pro", isEligible: true } },
                    eligible: true,
                    ineligibleReason: null,
                    disableTelemetry: false,
                    userDataCollectionForceDisabled: false,
                    allowedTiers: [{ id: "STANDARD", name: "Standard", isDefault: true }]
                }
            }));
        }
        if (req.url.includes('loadCodeAssist')) {
            return res.end(JSON.stringify({
                currentTier: { id: "STANDARD", hasOnboardedPreviously: true },
                cloudaicompanionProject: "",
                allowedTiers: [{ id: "STANDARD", name: "Standard", isDefault: true }],
                paidTier: void 0
            }));
        }
        if (req.url.includes('onboardUser')) {
            return res.end(JSON.stringify({
                done: true,
                response: {
                    cloudaicompanionProject: { id: "" }
                }
            }));
        }
        if (req.url.includes('listExperiments')) {
            return res.end(JSON.stringify({ flags: [], experimentIds: [] }));
        }
        if (req.url.includes('fetchAdminControls')) {
            return res.end(JSON.stringify({}));
        }
        if (req.url.includes('getCodeAssistGlobalUserSetting')) {
            return res.end(JSON.stringify({}));
        }
        if (req.url.includes('refreshUserQuota') || req.url.includes('retrieveUserQuota')) {
            return res.end(JSON.stringify({}));
        }
        if (req.url.includes('listAvailableTiers') || req.url.includes('isEligible')) {
            return res.end(JSON.stringify({ tiers: [], isEligible: true, ineligibleReason: null }));
        }
        return res.end(JSON.stringify({
            eligible: true,
            ineligibleReason: null,
            allowedTiers: [{ id: "STANDARD", name: "Standard", isDefault: true }],
            currentTier: { id: "STANDARD", hasOnboardedPreviously: true },
            planStatus: { planInfo: { planName: "pro", isEligible: true } },
            userTier: { id: "pro", description: "Pro" }
        }));
    });
});

apiProxyServer.listen(0, '127.0.0.1', () => { agApiPort = apiProxyServer.address().port; });

const _origWhenReady = _elec.app.whenReady;
_elec.app.whenReady = function() {
    return _origWhenReady.call(this).then(() => {
        _elec.session.defaultSession.webRequest.onBeforeRequest({ urls: ['*://*.googleapis.com/*', '*://127.0.0.1:*/*', '*://localhost:*/*'] }, (details, callback) => {
            const urlObj = new URL(details.url);
            if (urlObj.hostname.includes('googleapis.com')) {
                return callback({ redirectURL: `http://127.0.0.1:${agApiPort}${urlObj.pathname}` });
            }
            if (urlObj.port != agProxyPort && !details.url.includes('ag_bypass')) {
                realLsPort = urlObj.port;
                if (details.url.includes('.js') || details.url.includes('.css') || details.url.includes('.png') || details.url.includes('.woff') || details.url.includes('main.js') || details.url.includes('index.html') || details.url.includes('/')) {
                    urlObj.protocol = 'http:'; urlObj.port = agProxyPort; urlObj.searchParams.set('ag_bypass', '1');
                    return callback({ redirectURL: urlObj.toString() });
                }
            }
            callback({});
        });
    });
};
// [/AG_PROXY_HOOK]
"#;
    }

    let new_content = format!(
        "{}\n{}\n{}",
        hook,
        inline_patched,
        crate::canary::file_marker()
    );
    fs::write(main_js, new_content).map_err(|e| e.to_string())?;
    Ok(true)
}

fn strip_desktop_hook(content: &str) -> String {
    if let Some(start) = content.find("// [AG_PROXY_HOOK]") {
        if let Some(end) = content[start..].find("// [/AG_PROXY_HOOK]") {
            let after = start + end + "// [/AG_PROXY_HOOK]".len();
            let mut rest = content[after..].to_string();
            if let Some(stripped) = strip_marker(&rest) {
                rest = stripped;
            }
            return content[..start].to_string() + &rest;
        }
    }
    if let Some(stripped) = strip_marker(content) {
        return stripped + "\n";
    }
    content.to_string()
}

fn apply_desktop_inline_patches(content: &str) -> String {
    let mut output = content.to_string();

    output = output.replace("ineligible", "inexigible");

    let re_getus = Regex::new(
        r#"let ([A-Za-z_$]+)=.*\.getUserStatus\(\{\}\)\)\)\.userStatus;if\([A-Za-z_$]+\)\{"#,
    )
    .unwrap();
    output = re_getus.replace_all(&output, |caps: &regex::Captures| {
        if caps.get(1).map_or("", |m| m.as_str()) != caps.get(2).map_or("", |m| m.as_str()) {
            return caps.get(0).map_or("", |m| m.as_str()).to_string();
        }
        let v = caps.get(1).map_or("", |m| m.as_str());
        format!("let {v}=...getUserStatus({{}}))).userStatus;{v}={{\"planStatus\":{{\"planInfo\":{{\"planName\":\"pro\"}}}},\"disableTelemetry\":false,\"userDataCollectionForceDisabled\":false}};if({v}){{")
    }).to_string();

    let re_auth = Regex::new(r#"_handleAuthErrorResponse\(([A-Za-z_$]+)\)\{var ([A-Za-z_$]+)=([A-Za-z_$]+)\?\.failureDetails;"#).unwrap();
    output = re_auth.replace_all(&output, |caps: &regex::Captures| {
        let p = caps.get(1).map_or("", |m| m.as_str());
        let v = caps.get(2).map_or("", |m| m.as_str());
        let s = caps.get(3).map_or("", |m| m.as_str());
        if p != s {
            return caps.get(0).map_or("", |m| m.as_str()).to_string();
        }
        format!("_handleAuthErrorResponse({p}){{var {v}={p}?.failureDetails; if({v}?.case===\"inexigible\"){{ this._authActor.send({{type:\"AUTH_SUCCESS\",tokenInfo:{{accessToken:\"\"}},scopes:[],isGcpTos:false}}); return; }}")
    }).to_string();

    let re_inel = Regex::new(r#"\?\.failureDetails\?\.case===\"ineligible\"\?this\._authActor\.send\(\{type:\"SET_INELIGIBLE\""#).unwrap();
    output = re_inel
        .replace_all(&output, |_caps: &regex::Captures| {
            "?.failureDetails?.case===\"NEVER_MATCH\"?this._authActor.send({type:\"SET_INELIGIBLE\""
        })
        .to_string();

    let re_eligible = Regex::new(r#"(isEligible:\s*)false"#).unwrap();
    output = re_eligible
        .replace_all(&output, |caps: &regex::Captures| {
            format!("{}true", &caps[1])
        })
        .to_string();

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn ide_fixture(condition: &str) -> String {
        format!(r#"const before=1;class Synthetic{{async authenticate(token){{if(this.sender.send({{type:token.isGcpTos?"GCP_SIGN_IN":"SIGN_IN"}}),this.service.resetIsTierGCPTos(),{condition}){{try{{await this.service.loadCodeAssist(token);const{{settings:state,userTier:tier}}=await this.refreshUserStatus(token),mapped=convert(token);this.updater.pushUpdate(mapped),this.sender.send({{type:"AUTH_SUCCESS",tokenInfo:token}}),this.event.fire({{settings:state,userTier:tier}})}}catch(err){{let text="return}}";let r=/return}}/;let t=`return}}`;function nested(){{return}};this.log(err)}}return}}let untouched="tail";return untouched}}}}const after=2;"#)
    }

    #[test]
    fn ide_transform_recognizes_both_conditions_and_preserves_tail() {
        for condition in ["true", "this.policy.isGoogleInternal"] {
            let input = ide_fixture(condition);
            let output = transform_ide(&input).unwrap().unwrap();
            assert!(output.starts_with("const before=1;class Synthetic{"));
            assert!(output.contains("let untouched=\"tail\";return untouched}}const after=2;"));
            assert!(output.contains("onboardUser(\"standard-tier\""));
            assert!(has_marker(&output));
            assert!(transform_ide(&output).unwrap().is_none());
        }
        let renamed = Regex::new(r"\btoken\b").unwrap().replace_all(&ide_fixture("true"), "аргумент").into_owned();
        assert!(transform_ide(&renamed).unwrap().is_some());
        let explicit_semicolon = ide_fixture("true").replace("}return}let untouched", "}return;}let untouched");
        assert!(transform_ide(&explicit_semicolon).unwrap().is_some());
    }

    #[test]
    fn ide_transform_rejects_ambiguous_mismatched_and_unbalanced_inputs() {
        let valid = ide_fixture("true");
        let second = ide_fixture("this.policy.isGoogleInternal");
        assert!(transform_ide(&(valid.clone() + &second)).is_err());
        let malformed = ide_fixture("false");
        assert!(transform_ide(&malformed).is_err());
        assert!(transform_ide(&(valid.clone() + &malformed)).is_err());
        for (from, to) in [
            ("type:token.isGcpTos", "type:other.isGcpTos"),
            ("this.service.loadCodeAssist(token)", "this.other.loadCodeAssist(token)"),
            ("loadCodeAssist(token)", "loadCodeAssist(other)"),
            ("refreshUserStatus(token)", "refreshUserStatus(other)"),
            ("mapped=convert(token)", "mapped=convert(other)"),
            ("pushUpdate(mapped)", "pushUpdate(other)"),
            ("this.sender.send({type:\"AUTH_SUCCESS\"", "this.other.send({type:\"AUTH_SUCCESS\""),
            ("tokenInfo:token", "tokenInfo:other"),
            ("fire({settings:state,userTier:tier})", "fire({settings:other,userTier:tier})"),
            ("fire({settings:state,userTier:tier})", "fire({settings:state,userTier:other})"),
        ] {
            let inconsistent = valid.replace(from, to);
            assert_ne!(inconsistent, valid);
            assert!(transform_ide(&inconsistent).is_err());
            assert!(transform_ide(&(valid.clone() + &inconsistent)).is_err());
        }
        assert!(transform_ide(&valid.replace("}return}let untouched", "}return let untouched")).is_err());
        assert!(transform_ide("async broken( {").is_err());
        let decoy = serde_json::to_string(&valid).unwrap();
        assert!(transform_ide(&format!("const fake={decoy};")).is_err());
        let input = format!("const fake={decoy};{valid}");
        assert!(transform_ide(&input).unwrap().is_some());
        let code_shaped = valid.replace("`return}`", "\"template-safe\"");
        for decoy in [format!("const fake='{code_shaped}';"), format!("/*{code_shaped}*/"),
            format!("const fake=`{code_shaped}`;")] {
            assert!(transform_ide(&decoy).is_err());
            assert!(transform_ide(&(decoy + &valid)).unwrap().is_some());
        }
    }

    #[test]
    fn string_return_cannot_close_branch() {
        let input = ide_fixture("true");
        assert!(transform_ide(&input.replace("}return}let untouched", "}'return'}let untouched")).is_err());
    }
    #[test]
    fn string_semicolon_cannot_close_branch() {
        let input = ide_fixture("true");
        assert!(transform_ide(&input.replace("}return}let untouched", "}return ';'}let untouched")).is_err());
    }

    #[test]
    fn backup_error_path_text_does_not_change_failure_category() {
        let dir = env::temp_dir().join(format!("ag-Сигнатура-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js"); fs::write(&target, ide_fixture("true")).unwrap();
        TEST_BACKUP_FAILURE.with(|value| value.set(1));
        let result = repatch_ide_js(&target);
        TEST_BACKUP_FAILURE.with(|value| value.set(0));
        assert!(matches!(result, RepatchOutcome::Failed(_)));
        assert!(!backup_path(&target).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn incomplete_stage_cannot_be_consumed_by_restore() {
        let dir = env::temp_dir().join(format!("ag-partial-restore-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js"); let input = ide_fixture("true");
        fs::write(&target, &input).unwrap();
        TEST_BACKUP_FAILURE.with(|value| value.set(1));
        let failure = patch_ide(&dir, &target);
        TEST_BACKUP_FAILURE.with(|value| value.set(0));
        assert!(failure.is_err());
        assert!(!backup_path(&target).exists());
        let stage = crate::patch_binary::temp_path(&backup_path(&target));
        assert_eq!(fs::read(&stage).unwrap(), b"");
        assert_eq!(restore_js_result(&target).unwrap(), JsRestore::Unchanged);
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        assert!(!backup_path(&target).exists());
        assert_eq!(fs::read(&stage).unwrap(), b"");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn occupied_backup_stage_is_not_overwritten() {
        let dir = env::temp_dir().join(format!("ag-stage-conflict-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js"); let input = ide_fixture("true");
        fs::write(&target, &input).unwrap();
        let stage = crate::patch_binary::temp_path(&backup_path(&target));
        fs::write(&stage, b"foreign stage").unwrap();
        assert!(patch_ide(&dir, &target).is_err());
        assert_eq!(fs::read(&stage).unwrap(), b"foreign stage");
        assert!(!backup_path(&target).exists());
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn competing_final_backup_is_received_without_overwrite() {
        for same in [true, false] {
            let dir = env::temp_dir().join(format!("ag-backup-race-{}-{same}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            let target = dir.join("main.js"); let input = ide_fixture("true");
            fs::write(&target, &input).unwrap();
            TEST_BACKUP_FAILURE.with(|value| value.set(if same { 4 } else { 5 }));
            let result = patch_ide(&dir, &target);
            TEST_BACKUP_FAILURE.with(|value| value.set(0));
            let backup = backup_path(&target);
            assert!(!crate::patch_binary::temp_path(&backup).exists());
            if same {
                assert!(result.is_ok());
                assert_eq!(fs::read(&backup).unwrap(), input.as_bytes());
                assert!(has_marker(&fs::read_to_string(&target).unwrap()));
            } else {
                assert!(result.is_err());
                assert_eq!(fs::read(&backup).unwrap(), b"different competitor");
                assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
            }
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn competing_final_with_failed_cleanup_stops_target_write() {
        let dir = env::temp_dir().join(format!("ag-existing-cleanup-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js"); let input = ide_fixture("true");
        fs::write(&target, &input).unwrap();
        TEST_BACKUP_FAILURE.with(|value| value.set(7));
        let result = patch_ide(&dir, &target);
        TEST_BACKUP_FAILURE.with(|value| value.set(0));
        assert!(result.is_err());
        let backup = backup_path(&target);
        assert_eq!(fs::read(&backup).unwrap(), input.as_bytes());
        assert_eq!(fs::read(crate::patch_binary::temp_path(&backup)).unwrap(), input.as_bytes());
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn failed_stage_cleanup_retains_final_and_stops_target_write() {
        let dir = env::temp_dir().join(format!("ag-backup-cleanup-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js"); let input = ide_fixture("true");
        fs::write(&target, &input).unwrap();
        TEST_BACKUP_FAILURE.with(|value| value.set(6));
        let result = patch_ide(&dir, &target);
        TEST_BACKUP_FAILURE.with(|value| value.set(0));
        assert!(result.is_err());
        let backup = backup_path(&target);
        assert_eq!(fs::read(&backup).unwrap(), input.as_bytes());
        assert_eq!(fs::read(crate::patch_binary::temp_path(&backup)).unwrap(), input.as_bytes());
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn substituted_stage_is_preserved_and_target_write_stops() {
        let dir = env::temp_dir().join(format!("ag-stage-substituted-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js"); let input = ide_fixture("true");
        fs::write(&target, &input).unwrap();
        TEST_BACKUP_FAILURE.with(|value| value.set(8));
        let result = patch_ide(&dir, &target);
        TEST_BACKUP_FAILURE.with(|value| value.set(0));
        assert!(result.is_err());
        let backup = backup_path(&target);
        let stage = crate::patch_binary::temp_path(&backup);
        assert_eq!(fs::read(&backup).unwrap(), input.as_bytes());
        assert_eq!(fs::read(&stage).unwrap(), b"synthetic substitute");
        assert_eq!(fs::read(stage.with_extension("test-displaced")).unwrap(), input.as_bytes());
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ide_backup_rejects_conflicts_and_preserves_other_backup() {
        let dir = env::temp_dir().join(format!("ag-ide-checked-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js");
        let input = ide_fixture("true").replace(";class", ";\r\nclass");
        fs::write(&target, &input).unwrap();
        let unrelated = dir.join("main.js.bak"); fs::write(&unrelated, b"foreign").unwrap();
        patch_ide(&dir, &target).unwrap();
        let output = fs::read(&target).unwrap();
        assert_eq!(fs::read(backup_path(&target)).unwrap(), input.as_bytes());
        assert_eq!(fs::read(&unrelated).unwrap(), b"foreign");
        patch_ide(&dir, &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), output);
        assert_eq!(fs::read(backup_path(&target)).unwrap(), input.as_bytes());
        restore_js(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        fs::write(backup_path(&target), b"different").unwrap();
        assert!(patch_ide(&dir, &target).is_err());
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        assert_eq!(fs::read(backup_path(&target)).unwrap(), b"different");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn extension_rewrite_uses_exact_backup_and_marked_retry_is_inert() {
        let dir = env::temp_dir().join(format!("ag-extension-checked-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(patch_extension_js(&dir).unwrap(), false);
        let target = js_targets(&dir).extension;
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let input = "const t=await svc.UserStatus.getUserStatus();if(!t)return[];const n=(0,parse)(t,decoder),{email:e,name:q}=n;return\"\"===e?[]:result;\r\n";
        fs::write(&target, input).unwrap();
        fs::write(backup_path(&target), b"other").unwrap();
        assert!(patch_extension_js(&dir).is_err());
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        assert_eq!(fs::read(backup_path(&target)).unwrap(), b"other");
        fs::remove_file(backup_path(&target)).unwrap();
        assert!(patch_extension_js(&dir).unwrap());
        let output = fs::read(&target).unwrap();
        assert_eq!(fs::read(backup_path(&target)).unwrap(), input.as_bytes());
        assert!(patch_extension_js(&dir).unwrap());
        assert_eq!(fs::read(&target).unwrap(), output);
        assert_eq!(fs::read(backup_path(&target)).unwrap(), input.as_bytes());
        restore_js(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        TEST_READBACK_FAILURE.with(|value| value.set(true));
        let error = patch_extension_js(&dir).unwrap_err();
        assert!(error.contains("JS replaced; readback unavailable"));
        assert_eq!(fs::read(backup_path(&target)).unwrap(), input.as_bytes());
        restore_js(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn changed_input_fails_before_backup() {
        let dir = env::temp_dir().join(format!("ag-preimage-checked-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js"); fs::write(&target, b"current").unwrap();
        let pin = PinnedJs::open(&target).unwrap();
        assert!(replace_checked(&pin, b"different", "replacement").is_err());
        assert!(!backup_path(&target).exists());
        assert_eq!(fs::read(&target).unwrap(), b"current");
        drop(pin);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_backup_symlink_is_not_followed() {
        use std::os::unix::fs::symlink;
        let dir = env::temp_dir().join(format!("ag-symlink-checked-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js"); let other = dir.join("other");
        fs::write(&target, b"current").unwrap(); fs::write(&other, b"foreign").unwrap();
        symlink(&other, backup_path(&target)).unwrap();
        assert!(backup_once(&target, b"current").is_err());
        assert_eq!(fs::read(&other).unwrap(), b"foreign");
        assert_eq!(fs::read(&target).unwrap(), b"current");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn checked_replace_reports_attempt_and_retains_verified_backup_on_failures() {
        let dir = env::temp_dir().join(format!("ag-failure-checked-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js"); let input = ide_fixture("true");
        fs::write(&target, &input).unwrap();
        let temporary = crate::patch_binary::temp_path(&target);
        fs::create_dir(&temporary).unwrap();
        let error = patch_ide(&dir, &target).unwrap_err();
        assert!(error.contains("outcome unconfirmed"));
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        assert_eq!(fs::read(backup_path(&target)).unwrap(), input.as_bytes());
        fs::remove_dir(&temporary).unwrap();
        TEST_READBACK_FAILURE.with(|value| value.set(true));
        let error = patch_ide(&dir, &target).unwrap_err();
        assert!(error.contains("JS replaced; readback unavailable"));
        assert!(has_marker(&fs::read_to_string(&target).unwrap()));
        assert_eq!(fs::read(backup_path(&target)).unwrap(), input.as_bytes());
        restore_js(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn backup_write_flush_and_receiving_failures_stop_both_callers() {
        for extension in [false, true] {
            for stage in 1..=3 {
                let dir = env::temp_dir().join(format!("ag-backup-failure-{}-{extension}-{stage}", std::process::id()));
                fs::create_dir_all(&dir).unwrap();
                let target = if extension { js_targets(&dir).extension } else { dir.join("main.js") };
                fs::create_dir_all(target.parent().unwrap()).unwrap();
                let input = if extension {
                    "const t=await svc.UserStatus.getUserStatus();if(!t)return[];const n=(0,parse)(t,decoder),{email:e,name:q}=n;return\"\"===e?[]:result;".to_owned()
                } else { ide_fixture("true") };
                fs::write(&target, &input).unwrap();
                TEST_BACKUP_FAILURE.with(|value| value.set(stage));
                let result = if extension { patch_extension_js(&dir).map(|_| ()) } else { patch_ide(&dir, &target) };
                TEST_BACKUP_FAILURE.with(|value| value.set(0));
                let error = result.unwrap_err();
                assert!(error.contains("entry retained"));
                assert_eq!(fs::read(&target).unwrap(), input.as_bytes());
                let backup = backup_path(&target);
                assert!(!backup.exists());
                let actual = fs::read(crate::patch_binary::temp_path(&backup)).unwrap();
                if stage == 1 { assert!(actual.is_empty()); } else { assert_eq!(actual, input.as_bytes()); }
                fs::remove_dir_all(&dir).unwrap();
            }
        }
    }

    #[test]
    #[ignore = "Root-owned explicit JavaScript engine; synthetic stubs only"]
    fn synthetic_transformed_method_parses_and_preserves_producer_behavior() {
        use std::process::{Command, Stdio};
        let node = env::var_os("AG_IDE_TEST_NODE").expect("explicit JavaScript engine required");
        for condition in ["true", "this.policy.isGoogleInternal"] {
            let output = transform_ide(&ide_fixture(condition)).unwrap().unwrap();
            let run = |args: &[&str], script: &str| {
                let mut child = Command::new(&node).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
                child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
                child.wait_with_output().unwrap()
            };
            let parsed = run(&["--check"], &output);
            assert!(parsed.status.success(), "{}", String::from_utf8_lossy(&parsed.stderr));
            let harness = r#"
function convert(token){return token}
async function exercise(fail){
 let calls=[], x=new Synthetic(), token={isGcpTos:false};
 x.sender={send:v=>calls.push(v.type)};
 x.service={resetIsTierGCPTos:()=>calls.push('reset'),loadCodeAssist:async()=>{calls.push('load');if(fail)throw Error('load')},onboardUser:async(t)=>{calls.push(t);if(fail)throw Error('onboard')}};
 x.refreshUserStatus=async()=>{calls.push('refresh');if(fail)throw Error('refresh');return {settings:{},userTier:{id:'actual'}}};
 x.updater={pushUpdate:()=>calls.push('push')};x.event={fire:v=>calls.push(v.userTier.id)};
 await x.authenticate(token);
 if(!calls.includes('AUTH_SUCCESS') || !calls.includes('standard-tier') || !calls.includes(fail?'pro':'actual'))throw Error('producer behavior differs');
 if(fail && !calls.includes('free-tier'))throw Error('fallback onboarding missing');
}
(async()=>{await exercise(false);await exercise(true)})().catch(e=>{console.error(e);process.exitCode=1});
"#;
            let result = run(&[], &(output + "\n" + harness));
            assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        }
    }

    #[cfg(windows)]
    #[test]
    fn checked_js_restore_failure_blocks_the_second_mutation() {
        let root = crate::wsl_discovery_contract_cases::fixture_dir("js-first-failure");
        let main = root.join("resources/app/out/main.js");
        let extension = root.join("resources/app/extensions/antigravity/dist/extension.js");
        fs::create_dir_all(main.parent().unwrap()).unwrap();
        fs::create_dir_all(extension.parent().unwrap()).unwrap();
        fs::write(&main, b"main rewritten\n// UNLOCKED").unwrap();
        fs::create_dir(backup_path(&main)).unwrap();
        fs::write(&extension, b"extension rewritten\n// UNLOCKED").unwrap();
        fs::write(backup_path(&extension), b"extension pristine").unwrap();
        let before = fs::read(&extension).unwrap();
        let failure = unpatch_ide_js_checked(&root).unwrap_err();
        assert!(failure.completed.is_empty());
        assert_eq!(fs::read(&extension).unwrap(), before);
        assert_eq!(fs::read(backup_path(&extension)).unwrap(), b"extension pristine");
        assert_eq!(fs::read(&main).unwrap(), b"main rewritten\n// UNLOCKED");
        let absent = root.join("deleted.js");
        fs::write(backup_path(&absent), b"not resurrected").unwrap();
        assert_eq!(restore_js_result(&absent).unwrap(), JsRestore::Unchanged);
        assert!(!absent.exists());
    }

    #[test]
    fn detects_a_marker_written_by_this_build() {
        let js = format!("code();\n{}", crate::canary::file_marker());
        assert!(has_marker(&js));
    }

    #[test]
    fn detects_the_legacy_bare_marker() {
        // Installs patched by <=2.5.0 must still read as "already patched",
        // otherwise an upgrade re-patches an already patched file.
        assert!(has_marker("code();\n// UNLOCKED"));
        assert!(has_marker("code();\n// UNLOCKED\n\n"));
    }

    #[test]
    fn an_unpatched_file_has_no_marker() {
        assert!(!has_marker("code();\n// some other trailing comment"));
        assert!(!has_marker("// UNLOCKED is mentioned mid-file\ncode();"));
        assert!(!has_marker(""));
    }

    /// The G25 fix, end to end on real files: a backup taken before a rewrite is
    /// what `restore_js` uses to put the exact original bytes back, and the backup
    /// is then removed. Without this the full revert left main.js patched.
    #[test]
    fn a_backup_restores_the_exact_original_and_is_removed() {
        let dir = std::env::temp_dir().join("ag_js_restore_test");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js");
        let original = "// pristine main.js\nconst x = 1;\n";
        fs::write(&target, original).unwrap();

        // First backup captures the pristine file.
        backup_once(&target, original.as_bytes()).unwrap();
        backup_once(&target, original.as_bytes()).unwrap();
        assert!(backup_path(&target).exists());
        // A "patch": rewrite the body and append a marker.
        write_atomic(&target, "REWRITTEN BODY\n// UNLOCKED").unwrap();
        // A second backup must NOT overwrite the pristine one.
        assert!(backup_once(&target, b"REWRITTEN BODY\n// UNLOCKED").is_err());

        assert_eq!(restore_js(&target).unwrap(), true);
        assert_eq!(fs::read_to_string(&target).unwrap(), original, "byte-exact");
        assert!(!backup_path(&target).exists(), "backup consumed");
        // Nothing left to undo now.
        assert_eq!(restore_js(&target).unwrap(), false);

        fs::remove_dir_all(&dir).ok();
    }

    /// With no backup but our marker present, restore strips the marker as a last
    /// resort (the body stays rewritten) rather than doing nothing.
    #[test]
    fn restore_without_a_backup_at_least_strips_the_marker() {
        let dir = std::env::temp_dir().join("ag_js_restore_nombak");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("main.js");
        fs::write(&target, "body\n// UNLOCKED").unwrap();

        assert_eq!(restore_js(&target).unwrap(), true);
        assert!(!has_marker(&fs::read_to_string(&target).unwrap()));

        fs::remove_dir_all(&dir).ok();
    }

    /// A crash mid-write must never leave a torn target: `write_atomic` replaces
    /// via a rename, so the target is only ever the old or the new content, and
    /// the temp is cleaned up.
    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join("ag_js_atomic");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("f.js");
        fs::write(&target, "old").unwrap();
        write_atomic(&target, "new content").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new content");
        let tmp = crate::patch_binary::temp_path(&target);
        assert!(!tmp.exists(), "temp cleaned up");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn strip_marker_removes_both_shapes_and_nothing_else() {
        let body = "line one\nline two";
        for marker in [crate::canary::file_marker(), "// UNLOCKED".to_string()] {
            let patched = format!("{}\n{}", body, marker);
            assert_eq!(strip_marker(&patched).as_deref(), Some(body));
        }
        assert!(strip_marker(body).is_none());
    }

    #[test]
    fn recognises_the_shipping_v24_plus_shell() {
        let Ok(local) = env::var("LOCALAPPDATA") else {
            return;
        };
        let asar = Path::new(&local)
            .join("Programs")
            .join("Antigravity")
            .join("resources")
            .join("app.asar");
        if !asar.exists() {
            return;
        }
        let src = crate::asar::read_asar_entry(&asar, "dist/main.js")
            .and_then(|b| String::from_utf8(b).ok())
            .expect("dist/main.js");
        assert!(
            is_new_desktop_architecture(&src),
            "installed Desktop build was classified as legacy - the JS patch would be applied"
        );
    }

    #[test]
    fn a_legacy_shell_still_needs_the_js_patch() {
        let legacy = r#"require("./languageServer");require("./ipcHandlers");
            _handleAuthErrorResponse(e){var t=e?.failureDetails;}"#;
        assert!(!is_new_desktop_architecture(legacy));
    }

    #[test]
    fn a_non_modular_shell_is_not_v24() {
        assert!(!is_new_desktop_architecture("const x = 1;"));
    }
}

pub fn patch_extension_js(inst: &Path) -> Result<bool, String> {
    let ext_path = js_targets(inst).extension;
    if !ext_path.exists() {
        return Ok(false);
    }

    let pin = PinnedJs::open(&ext_path)?;
    let original = pin.read()?;
    let content = std::str::from_utf8(&original).map_err(|e| format!("JS encoding: {e}"))?;
    if content.contains("/*[AG_EXT_PATCHED]*/") {
        return Ok(true);
    }

    obfstr::obfstr! {
        let p1_str = r#"const t=await ([A-Za-z_$][A-Za-z_$0-9.]*)\.UserStatus\.getUserStatus\(\);if\(!t\)return\[\];const n=\(0,([A-Za-z_$][A-Za-z_$0-9.]*)\)\(t,([A-Za-z_$][A-Za-z_$0-9.]*)\),\{email:([A-Za-z_$][A-Za-z_$0-9]*),name:([A-Za-z_$][A-Za-z_$0-9]*)\}=n;return""===([A-Za-z_$][A-Za-z_$0-9]*)\?\[\]:"#;
    }
    let p1 = Regex::new(p1_str).unwrap();
    let new_content = p1.replace(content, |caps: &regex::Captures| {
        let ns = &caps[1];
        let p2 = &caps[2];
        let dz7 = &caps[3];
        let email = &caps[4];
        let name = &caps[5];
        format!(
            "const t=await {ns}.UserStatus.getUserStatus();let {email}=\"\",{name}=\"\";try{{if(t){{const n=(0,{p2})(t,{dz7});{email}=n.email||\"\";{name}=n.name||\"\";}}}}catch(_){{}}if({email}===\"\"){{{email}=\"antigravity-user\";{name}=\"User\";}}return false?[]:"
        )
    });

    if new_content == content {
        return Err("Сигнатура extension.js не найдена (возможно, другая версия)".to_string());
    }

    // Leading fence stays the idempotence check; the trailing marker is the
    // canary trailer every rewritten file carries.
    let marked = format!(
        "/*[AG_EXT_PATCHED]*/\n{}\n{}",
        new_content,
        crate::canary::file_marker()
    );
    replace_checked(&pin, &original, &marked)?;
    Ok(true)
}
