//! Registration-only WSL queries. Neither command starts a distribution.
use super::*;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Registration {
    pub name: String,
    pub running: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiscoveryObservation {
    pub registrations: Vec<Registration>,
    pub error: Option<String>,
}

/// Explicit command purpose; the command's script, argv and environment are
/// never themselves rendered into diagnostics.
#[derive(Clone, Copy)]
pub(crate) enum MetadataPurpose { RegisteredNames, RunningNames, DesktopProcessCheck, FirewallProfileQuery,
    GuestNetworkContext, HostAdapterQuery, GuestIdentity, HelperPath, HelperProvision, HelperVerify,
    PrivateServerPreparation, BackgroundStateQuery }
impl MetadataPurpose {
    fn label(self) -> &'static str { match self {
        Self::RegisteredNames => "RegisteredNames", Self::RunningNames => "RunningNames",
        Self::DesktopProcessCheck => "DesktopProcessCheck", Self::FirewallProfileQuery => "FirewallProfileQuery",
        Self::GuestNetworkContext => "GuestNetworkContext", Self::HostAdapterQuery => "HostAdapterQuery",
        Self::GuestIdentity => "GuestIdentity", Self::HelperPath => "HelperPath", Self::HelperProvision => "HelperProvision",
        Self::HelperVerify => "HelperVerify", Self::PrivateServerPreparation => "PrivateServerPreparation",
        Self::BackgroundStateQuery => "BackgroundStateQuery",
    } }
}
#[derive(Clone, Copy)]
pub(crate) struct MetadataContext<'a> {
    pub purpose: MetadataPurpose,
    pub distro: Option<&'a str>,
    pub private_values: &'a [&'a str],
}
impl<'a> MetadataContext<'a> {
    pub(crate) fn new(purpose: MetadataPurpose, distro: Option<&'a str>) -> Self {
        Self { purpose, distro, private_values: &[] }
    }
    pub(super) fn heading(&self) -> String {
        match self.distro {
            Some(name) => format!("{} [{}]", self.purpose.label(), escaped(name)),
            None => self.purpose.label().to_owned(),
        }
    }
    pub(crate) fn safe_stderr(&self, bytes: &[u8]) -> String {
        self.safe_stderr_extra(bytes, &[])
    }
    pub(crate) fn safe_text(&self, text: &str) -> String {
        self.safe_text_extra(text, &[])
    }
    fn safe_text_extra(&self, text: &str, extra: &[String]) -> String {
        self.safe_projected(text.as_bytes(), extra, true)
    }
    fn failure_stdout(&self, bytes: &[u8], extra: &[String]) -> String {
        if private_stdout_payload(self.purpose, bytes) { "[private output withheld]".into() }
        else { self.safe_stderr_extra(bytes, extra) }
    }
    fn safe_stderr_extra(&self, bytes: &[u8], extra: &[String]) -> String {
        self.safe_projected(bytes, extra, false)
    }
    fn safe_projected(&self, bytes: &[u8], extra: &[String], known_utf8: bool) -> String {
        let mut private: Vec<String> = self.private_values.iter().filter(|s| !s.is_empty()).map(|s| (*s).to_owned()).collect();
        private.extend(extra.iter().filter(|s| !s.is_empty()).cloned());
        for name in ["USERPROFILE", "HOME", "LOCALAPPDATA", "APPDATA"] {
            if let Some(value) = std::env::var_os(name).and_then(|s| s.into_string().ok()) {
                if !value.is_empty() { private.push(value); }
            }
        }
        let hidden = private_byte_spans(bytes, &private);
        let render = |text: &str, offset: usize, wide: bool| {
            let mut projected = String::new();
            let mut position = offset;
            let mut masking = false;
            for ch in text.chars() {
                let width = if wide { ch.len_utf16() * 2 } else { ch.len_utf8() };
                let private = hidden[position..position + width].iter().any(|hidden| *hidden);
                if private {
                    if !masking { projected.push_str("[private]"); }
                } else { projected.push(ch); }
                masking = private;
                position += width;
            }
            if projected.is_empty() { return "[empty]".to_owned(); }
            projected.split('\n').map(|line| {
                let trimmed = line.trim_start();
                let category = trimmed.strip_prefix('+').map(str::trim_start)
                    .is_some_and(|s| s.starts_with("CategoryInfo") || s.starts_with("FullyQualifiedErrorId"));
                if (trimmed.starts_with('+') && !category) || trimmed.starts_with("At line:") || trimmed.starts_with("строка:") {
                    "[source excerpt removed]".to_owned()
                } else { escaped(line) }
            }).collect::<Vec<_>>().join("\\n")
        };
        let utf8_bom = !known_utf8 && bytes.starts_with(&[0xef, 0xbb, 0xbf]);
        let utf16_bom = !known_utf8 && bytes.starts_with(&[0xff, 0xfe]);
        let utf8_offset = if utf8_bom { 3 } else { 0 };
        let utf16_offset = if utf16_bom { 2 } else { 0 };
        let utf8 = if utf16_bom { None } else { std::str::from_utf8(&bytes[utf8_offset..]).ok() };
        let raw16 = &bytes[utf16_offset..];
        let utf16 = if known_utf8 || utf8_bom || raw16.len() % 2 != 0 { None } else {
            let units: Vec<u16> = raw16.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
            String::from_utf16(&units).ok()
        };
        match (utf8, utf16) {
            (Some(a), Some(b)) => {
                let a = render(a, utf8_offset, false);
                let b = render(&b, utf16_offset, true);
                if a == b { a } else { format!("[encoding ambiguous; UTF-8] {a}; [UTF-16LE] {b}") }
            },
            (Some(a), None) if utf8_bom || known_utf8 => render(a, utf8_offset, false),
            (Some(a), None) => format!("[encoding unconfirmed; UTF-8] {}", render(a, utf8_offset, false)),
            (None, Some(b)) if utf16_bom => render(&b, utf16_offset, true),
            (None, Some(b)) => format!("[encoding unconfirmed; UTF-16LE] {}", render(&b, utf16_offset, true)),
            (None, None) => format!("[undecodable: {} bytes]", bytes.len()),
        }
    }
}
fn private_byte_spans(bytes: &[u8], values: &[String]) -> Vec<bool> {
    let mut hidden = vec![false; bytes.len()];
    for value in values.iter().filter(|value| !value.is_empty()) {
        let wide: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        for needle in [value.as_bytes(), wide.as_slice()] {
            if needle.len() <= bytes.len() {
                for (start, window) in bytes.windows(needle.len()).enumerate() {
                    if window == needle { hidden[start..start + needle.len()].fill(true); }
                }
            }
        }
    }
    hidden
}
fn escaped(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { c.escape_default().to_string() } else { c.to_string() }).collect()
}
fn private_stdout_payload(purpose: MetadataPurpose, bytes: &[u8]) -> bool {
    let wide_marker = bytes.starts_with(&[b'A', 0, b'G', 0]);
    let wide = if bytes.starts_with(&[0xff, 0xfe]) || wide_marker {
        let raw = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
        if raw.len() % 2 != 0 { return true; }
        let units: Vec<u16> = raw.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
        match String::from_utf16(&units) { Ok(value) => Some(value), Err(_) => return true }
    } else { None };
    let bytes = wide.as_ref().map(|text| text.as_bytes()).unwrap_or(bytes);
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let bytes = bytes.iter().position(|b| !b.is_ascii_whitespace()).map(|start| &bytes[start..]).unwrap_or(bytes);
    let marker = match purpose {
        MetadataPurpose::GuestIdentity => Some(&b"AG_USER_V1"[..]),
        MetadataPurpose::GuestNetworkContext => Some(&b"AG_CONTEXT_V1"[..]),
        MetadataPurpose::HelperVerify => Some(&b"AG_HELPER_V1"[..]),
        _ => None,
    };
    if let Some(marker) = marker {
        if !bytes.is_empty() && (bytes.starts_with(marker) || marker.starts_with(bytes)) { return true; }
    }
    if matches!(purpose, MetadataPurpose::HelperPath | MetadataPurpose::HelperProvision) && bytes.starts_with(b"/") {
        return true;
    }
    if matches!(purpose, MetadataPurpose::PrivateServerPreparation | MetadataPurpose::BackgroundStateQuery) {
        if bytes.starts_with(b"{") { return true; }
        if let Some(rest) = bytes.strip_prefix(b"[") {
            let rest = rest.iter().position(|b| !b.is_ascii_whitespace()).map(|start| &rest[start..]).unwrap_or(&[]);
            let json_literal = [&b"null"[..], &b"true"[..], &b"false"[..]]
                .iter().any(|literal| !rest.is_empty() && (rest.starts_with(literal) || literal.starts_with(rest)));
            if rest.is_empty() || json_literal || matches!(rest[0], b'"' | b'{' | b'[' | b']' | b'-' | b'0'..=b'9') {
                return true;
            }
        }
    }
    false
}
#[cfg(test)]
pub(crate) fn test_diagnostic_text() -> String {
    let context = MetadataContext { purpose: MetadataPurpose::GuestIdentity, distro: Some("Ubuntu"), private_values: &["fixture-secret"] };
    let program = system_program(Path::new(r"WindowsPowerShell\v1.0\powershell.exe")).expect("fixture program");
    let mut command = Command::new(program.as_path());
    command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
        "[Console]::Out.Write('a'); [Console]::Out.Write([char]0); [Console]::Out.Write('b'); [Console]::Out.Write([char]0); [Console]::Out.Write('native error 51 fixture-secret'); exit 51"]);
    metadata_output(&program, command, &AtomicBool::new(false), context).unwrap_err()
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
}

pub(super) fn system_program(relative: &Path) -> Result<Pinned> {
    use std::os::windows::ffi::OsStringExt;
    let needed = unsafe { GetSystemDirectoryW(std::ptr::null_mut(), 0) };
    if needed == 0 {
        return Err(io("Windows system directory size", std::io::Error::last_os_error()));
    }
    let mut path = vec![0u16; needed as usize];
    let written = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), needed) };
    if written == 0 || written >= needed {
        return Err("Windows system directory changed during receiving".into());
    }
    if relative.components().any(|component| !matches!(component, std::path::Component::Normal(_))) {
        return Err("ordinary system program relative path required".into());
    }
    let path = PathBuf::from(OsString::from_wide(&path[..written as usize])).join(relative);
    pin_executable(&path)
}

fn names(bytes: &[u8]) -> Result<Vec<String>> {
    let text = if bytes.contains(&0) {
        if bytes.len() % 2 != 0 {
            return Err("WSL registration output has truncated UTF-16".into());
        }
        let units: Vec<_> = bytes.chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        String::from_utf16(&units).map_err(|_| "WSL registration output has invalid UTF-16")?
    } else {
        String::from_utf8(bytes.to_vec()).map_err(|_| "WSL registration output has invalid UTF-8")?
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let mut result = Vec::new();
    for line in text.lines() {
        if line.is_empty() { continue; }
        if line.chars().any(char::is_control) || result.iter().any(|old| old == line) {
            return Err("WSL registration output has invalid or ambiguous names".into());
        }
        result.push(line.to_owned());
    }
    Ok(result)
}

fn query(program: &Pinned, running: bool, cancelled: &AtomicBool) -> Result<Vec<String>> {
    let context = MetadataContext::new(if running { MetadataPurpose::RunningNames } else { MetadataPurpose::RegisteredNames }, None);
    if cancelled.load(Ordering::SeqCst) { return Err(format!("{}: WSL discovery cancelled", context.heading())); }
    program.recheck().map_err(|error| format!("{}: program receiving: {}", context.heading(), context.safe_text(&error)))?;
    let mut command = Command::new(program.as_path());
    command.args(["--list", "--quiet"]);
    if running { command.arg("--running"); }
    let output = metadata_output(program, command, cancelled, context)?;
    names(&output.stdout).map_err(|error| format!("{}: {error}; exit=success; capture=complete; stderr={}",
        context.heading(), output.diagnostic_stderr(context)))
}

/// One owner for finite metadata-child/pipe custody. Output remains private
/// memory, and cancellation settles the exact creator Child before returning.
#[derive(Debug)]
pub(super) struct MetadataOutput { pub(super) stdout: Vec<u8>, stderr: Vec<u8>, redactions: Vec<String> }
impl MetadataOutput {
    pub(super) fn diagnostic_stderr(&self, context: MetadataContext<'_>) -> String {
        context.safe_stderr_extra(&self.stderr, &self.redactions)
    }
}
pub(super) fn metadata_output(program: &Pinned, command: Command, cancelled: &AtomicBool, context: MetadataContext<'_>) -> Result<MetadataOutput> {
    metadata_output_impl(program, command, cancelled, true, context)
}
pub(super) fn metadata_output_natural(program: &Pinned, command: Command, cancelled: &AtomicBool, context: MetadataContext<'_>) -> Result<MetadataOutput> {
    metadata_output_impl(program, command, cancelled, false, context)
}
fn metadata_output_impl(program: &Pinned, command: Command, cancelled: &AtomicBool, native_only: bool, context: MetadataContext<'_>) -> Result<MetadataOutput> {
    metadata_output_with_context(program, command, cancelled, native_only, start_stdout_reader, start_stderr_reader, Child::try_wait, |p| p.recheck(), context)
}

#[derive(Debug)]
struct PartialRead { bytes: Vec<u8>, message: String }
impl std::fmt::Display for PartialRead { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.message) } }
impl std::error::Error for PartialRead {}
fn drain<R: Read>(mut stream: R) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    match stream.read_to_end(&mut bytes) {
        Ok(_) => Ok(bytes),
        Err(error) => Err(std::io::Error::new(error.kind(), PartialRead { bytes, message: error.to_string() })),
    }
}

fn start_stdout_reader(mut stdout: std::process::ChildStdout)
    -> std::io::Result<thread::JoinHandle<std::io::Result<Vec<u8>>>> {
    thread::Builder::new().name("wsl-registration-output".into()).spawn(move || {
        drain(&mut stdout)
    })
}
fn start_stderr_reader(stderr: std::process::ChildStderr)
    -> std::io::Result<thread::JoinHandle<std::io::Result<Vec<u8>>>> {
    thread::Builder::new().name("metadata-stderr".into()).spawn(move || drain(stderr))
}

/// Private injection seam for the existing reader-start and Child-observation
/// effects. Production and guards use this same acquisition/settlement owner.
fn metadata_output_with<S, O>(program: &Pinned, mut command: Command, cancelled: &AtomicBool,
    native_only: bool, start_reader: S, mut observe_child: O) -> Result<Vec<u8>>
where
    S: FnOnce(std::process::ChildStdout) -> std::io::Result<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
    O: FnMut(&mut Child) -> std::io::Result<Option<std::process::ExitStatus>>,
{
    metadata_output_with_context(program, command, cancelled, native_only, start_reader, start_stderr_reader, observe_child, |p| p.recheck(),
        MetadataContext::new(MetadataPurpose::RegisteredNames, None)).map(|output| output.stdout)
}

fn metadata_output_with_context<S, T, O, R>(program: &Pinned, mut command: Command, cancelled: &AtomicBool,
    native_only: bool, start_reader: S, start_stderr: T, mut observe_child: O, recheck_program: R, context: MetadataContext<'_>) -> Result<MetadataOutput>
where
    S: FnOnce(std::process::ChildStdout) -> std::io::Result<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
    T: FnOnce(std::process::ChildStderr) -> std::io::Result<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
    O: FnMut(&mut Child) -> std::io::Result<Option<std::process::ExitStatus>>,
    R: FnOnce(&Pinned) -> Result<()>,
{
    if cancelled.load(Ordering::SeqCst) { return Err(format!("{}: metadata query cancelled", context.heading())); }
    if command.get_program() != program.as_path().as_os_str() { return Err(format!("{}: metadata program pin differs", context.heading())); }
    program.recheck().map_err(|error| format!("{}: program receiving: {}", context.heading(), context.safe_text(&error)))?;
    let program_name = program.as_path().file_name().and_then(|name| name.to_str()).map(escaped).unwrap_or_else(|| "[name unavailable]".into());
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000);
    // These values are used only for removal from untrusted output. They are
    // never rendered, and flags or short ordinary arguments are not collected.
    let mut command_private = Vec::new();
    for arg in command.get_args().filter_map(|arg| arg.to_str()) {
        if arg.contains('\\') || arg.starts_with('/') || arg.contains('\n') || arg.contains('$') {
            command_private.push(arg.to_owned());
            if arg.contains('\n') { command_private.extend(arg.lines().filter(|line| !line.trim().is_empty()).map(str::to_owned)); }
        }
    }
    let stdin = if native_only { Stdio::null() } else { Stdio::piped() };
    let mut child = command.stdin(stdin).stdout(Stdio::piped())
        .stderr(Stdio::piped()).spawn().map_err(|e| format!("{}: program={program_name}; spawn: {}", context.heading(), context.safe_text_extra(&e.to_string(), &command_private)))?;
    // Only this job holds the natural helper's lifetime writer. It is never
    // written, inherited as console input, or released on stdout EOF alone.
    let mut input = child.stdin.take();
    let stderr_started = match child.stderr.take() {
        Some(stderr) => start_stderr(stderr),
        None => Err(std::io::Error::other("owned piped stderr absent")),
    };
    let (mut stderr_reader, mut stderr_capture) = match stderr_started {
        Ok(reader) => (Some(reader), None),
        Err(error) => (None, Some(Captured { bytes: Vec::new(), error: Some(format!("stderr reader: {error}")) })),
    };
    let started = match child.stdout.take() {
        Some(stdout) => start_reader(stdout),
        None => Err(std::io::Error::other("owned piped stdout absent")),
    };
    let mut stop = None;
    let (mut reader, mut capture) = match started {
        Ok(reader) => (Some(reader), None),
        Err(error) => {
            drop(input.take());
            if native_only { stop = Some(child.kill()); }
            (None, Some(Captured { bytes: Vec::new(), error: Some(format!("stdout reader: {error}")) }))
        }
    };
    if stderr_capture.is_some() { drop(input.take()); if native_only && stop.is_none() { stop = Some(child.kill()); } }
    let mut cancellation_received = false;
    let mut failure = None;
    let exit = loop {
        if cancelled.load(Ordering::SeqCst) && !cancellation_received {
            cancellation_received = true;
            drop(input.take());
            if native_only && stop.is_none() { stop = Some(child.kill()); }
        }
        // A failed/panicked reader cannot leave a helper waiting forever on a
        // live writer. Collect only a finished reader; retain all other actors.
        if reader.as_ref().is_some_and(|reader| reader.is_finished()) {
            capture = Some(receive_stdout(reader.take().unwrap()));
            if capture.as_ref().is_some_and(|result| result.error.is_some()) { drop(input.take()); }
        }
        if stderr_reader.as_ref().is_some_and(|reader| reader.is_finished()) {
            stderr_capture = Some(receive_stdout(stderr_reader.take().unwrap()));
            if stderr_capture.as_ref().is_some_and(|result| result.error.is_some()) { drop(input.take()); }
        }
        match observe_child(&mut child) {
            Ok(Some(exit)) => break exit,
            Ok(None) => {},
            Err(error) => {
                failure.get_or_insert_with(|| format!("child observation: {error}"));
                drop(input.take());
            }
        }
        thread::sleep(Duration::from_millis(20));
    };
    // Actual exit releases the writer on success too. A still-started stdout
    // reader remains owned through its real completion inside this job.
    drop(input.take());
    let capture = match reader { Some(reader) => receive_stdout(reader), None => capture.unwrap() };
    let stderr_capture = match stderr_reader { Some(reader) => receive_stdout(reader), None => stderr_capture.unwrap() };
    let recheck = recheck_program(program);
    if cancellation_received || failure.is_some() || !exit.success() || capture.error.is_some() || stderr_capture.error.is_some()
        || stop.as_ref().is_some_and(|result| result.is_err()) || recheck.is_err() {
        let cause = if cancellation_received { "metadata operation cancelled" }
            else if capture.error.is_some() || stderr_capture.error.is_some() { "metadata output failed" }
            else if failure.is_some() { "metadata observation failed" }
            else if !exit.success() { "metadata query failed" }
            else { "WSL metadata program recheck failed" };
        // Known private output protocols stay private; causal failure text on
        // stdout otherwise follows the same redaction and escaping as stderr.
        let failure_stdout = if !exit.success() {
            context.failure_stdout(&capture.bytes, &command_private)
        } else { "[private output withheld]".into() };
        let stdout_error = capture.error.as_ref().map(|error| context.safe_text_extra(error, &command_private));
        let stderr_error = stderr_capture.error.as_ref().map(|error| context.safe_text_extra(error, &command_private));
        let stderr_text = if stderr_capture.error.is_some() && stderr_capture.bytes.is_empty() {
            "[stderr unavailable or empty; capture failed]".into()
        } else { context.safe_stderr_extra(&stderr_capture.bytes, &command_private) };
        let stop_text = context.safe_text_extra(&format!("{stop:?}"), &command_private);
        let observation = failure.as_ref().map(|error| context.safe_text_extra(error, &command_private));
        let recheck_error = recheck.err().map(|error| context.safe_text_extra(&error, &command_private));
        return Err(format!("{} ({cause}): program={program_name}; {exit}; cancellation={cancellation_received}; stop={stop_text}; observation={observation:?}; capture={stdout_error:?}; stderr_capture={stderr_error:?}; stdout_bytes={}; stdout={failure_stdout}; stderr={stderr_text}; recheck={recheck_error:?}", context.heading(), capture.bytes.len()));
    }
    Ok(MetadataOutput { stdout: capture.bytes, stderr: stderr_capture.bytes, redactions: command_private })
}

struct Captured { bytes: Vec<u8>, error: Option<String> }
fn receive_stdout(reader: thread::JoinHandle<std::io::Result<Vec<u8>>>) -> Captured {
    match reader.join() {
        Ok(Ok(bytes)) => Captured { bytes, error: None },
        Ok(Err(error)) => Captured { bytes: error.get_ref().and_then(|e| e.downcast_ref::<PartialRead>()).map(|e| e.bytes.clone()).unwrap_or_default(), error: Some(error.to_string()) },
        Err(_) => Captured { bytes: Vec::new(), error: Some("reader panicked; bytes unavailable".into()) },
    }
}

fn observe_queries<F>(cancelled: &AtomicBool, mut query_names: F) -> Result<DiscoveryObservation>
where F: FnMut(bool) -> Result<Vec<String>> {
    let registered = query_names(false)?;
    if cancelled.load(Ordering::SeqCst) { return Err("WSL discovery cancelled".into()); }
    let running = query_names(true);
    if cancelled.load(Ordering::SeqCst) { return Err("WSL discovery cancelled".into()); }
    let running = running.and_then(|running| {
        if running.iter().any(|name| !registered.contains(name)) {
            Err("WSL registrations changed during discovery; refresh the list".into())
        } else { Ok(running) }
    });
    let (running, error) = match running {
        Ok(running) => (Some(running), None),
        Err(error) => (None, Some(error)),
    };
    Ok(DiscoveryObservation {
        registrations: registered.into_iter().map(|name| Registration {
            running: running.as_ref().map(|running| running.contains(&name)), name,
        }).collect(),
        error,
    })
}

pub(crate) fn observe_registered_distributions(cancelled: Arc<AtomicBool>) -> Result<DiscoveryObservation> {
    observe_registered_distributions_with_cancel(&cancelled)
}

fn observe_registered_distributions_with_cancel(cancelled: &AtomicBool) -> Result<DiscoveryObservation> {
    let program = system_program(Path::new("wsl.exe")).map_err(|error| format!("WSL is unavailable: {error}"))?;
    observe_queries(cancelled, |running| query(&program, running, cancelled))
}

pub(crate) fn registered_distributions(cancelled: Arc<AtomicBool>) -> Result<Vec<Registration>> {
    registered_distributions_with_cancel(&cancelled)
}

pub(crate) fn registered_distributions_with_cancel(cancelled: &AtomicBool) -> Result<Vec<Registration>> {
    let observation = observe_registered_distributions_with_cancel(cancelled)?;
    match observation.error { Some(error) => Err(error), None => Ok(observation.registrations) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_masks_known_values_and_script_excerpt_without_losing_cause() {
        let context = MetadataContext { purpose: MetadataPurpose::GuestIdentity, distro: Some("Ubuntu"),
            private_values: &["fixture-secret", "/fixture-home"] };
        let input = "native error 51 fixture-secret /fixture-home\n+ invoke-secret fixture-secret\n+ CategoryInfo : denied\r\u{1b}";
        let safe = context.safe_stderr(input.as_bytes());
        assert!(safe.contains("native error 51") && safe.contains("CategoryInfo") && safe.contains("[source excerpt removed]"));
        assert!(!safe.contains("fixture-secret") && !safe.contains("/fixture-home") && !safe.contains('\n') && !safe.contains('\u{1b}'));
        let utf16: Vec<_> = "error 51".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(context.safe_stderr(&utf16).contains("error 51"));
        assert!(context.safe_stderr(&[0xff]).contains("undecodable"));
        assert_eq!(context.safe_stderr(&[]), "[empty]");
        assert!(context.failure_stdout(b"native error 51\0", &[]).contains("native error 51\\u{0}"));
        assert_eq!(context.failure_stdout(b"AG_USER_V1\n1000\n/fixture-home", &[]), "[private output withheld]");
        let wide_error: Vec<_> = "native error 51".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(context.failure_stdout(&wide_error, &[]).contains("native error 51"));
        for purpose in [MetadataPurpose::RegisteredNames, MetadataPurpose::RunningNames, MetadataPurpose::GuestIdentity, MetadataPurpose::HelperPath] {
            let context = MetadataContext::new(purpose, None);
            assert!(context.failure_stdout(b"native error 51\0", &[]).contains("native error 51\\u{0}"));
        }
        let background = MetadataContext::new(MetadataPurpose::BackgroundStateQuery, None);
        assert!(background.failure_stdout(b"[native error 51]", &[]).contains("native error 51"));
        assert_eq!(background.failure_stdout(b"[\"private task\"]", &[]), "[private output withheld]");
        let wide_private: Vec<_> = "AG_USER_V1\n1000\n/fixture-home".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(private_stdout_payload(MetadataPurpose::GuestIdentity, &wide_private));
        let input = b"a\0b\0fixture-secret";
        let safe = context.safe_stderr(input);
        let alias_units: Vec<_> = b"fixture-secret".chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
        let alias = String::from_utf16(&alias_units).unwrap();
        assert!(safe.contains("encoding ambiguous") && safe.contains("a\\u{0}b\\u{0}") && safe.contains("[private]"));
        assert!(!safe.contains("fixture-secret") && !safe.contains(&alias));
        let mut bom = vec![0xff, 0xfe];
        bom.extend("cause fixture-secret".encode_utf16().flat_map(u16::to_le_bytes));
        let safe = context.safe_stderr(&bom);
        assert!(safe.contains("cause") && safe.contains("[private]") && !safe.contains("fixture-secret"));
        let spans = private_byte_spans(b"zabcdx", &["abc".into(), "bcd".into(), "".into()]);
        assert_eq!(spans, [false, true, true, true, true, false]);
        let nonascii = MetadataContext { purpose: MetadataPurpose::GuestIdentity, distro: None, private_values: &["é"] };
        let safe = nonascii.safe_stderr("cause é".as_bytes());
        assert!(safe.contains("cause") && safe.contains("[private]") && !safe.contains('é'));
        assert_eq!(context.safe_text("None"), "None");
        let known = context.safe_text("native cause 91 fixture-secret");
        assert!(known.contains("native cause 91") && known.contains("[private]") && !known.contains("encoding ambiguous"));
        assert!(!known.contains("fixture-secret"));
    }
    #[test]
    fn exact_unicode_registration_names_and_empty_list() {
        let text = "\u{feff}Ubuntu\r\nДистрибутив с пробелом\r\n";
        let utf16: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(names(&utf16).unwrap(), ["Ubuntu", "Дистрибутив с пробелом"]);
        assert_eq!(names(b"Ubuntu\r\n").unwrap(), ["Ubuntu"]);
        assert!(names(b"").unwrap().is_empty());
        assert!(names(b"Ubuntu\nUbuntu\n").is_err());
        assert!(names(&[0, 0, 1]).is_err());
    }
    #[test]
    fn secondary_failure_reaches_first_and_refresh_snapshots() {
        use crate::wsl_api::WslPreferences;
        use crate::wsl_controller::{WslController, test_receive_observation};
        let cancelled = AtomicBool::new(false);
        let preferences = WslPreferences { enabled: true, distros: vec!["Дистрибутив с пробелом".into()] };
        let mut controller = WslController::default();
        let primary: Vec<u8> = "Ubuntu\r\nДистрибутив с пробелом\r\n".encode_utf16().flat_map(u16::to_le_bytes).collect();
        for refresh in [false, true] {
            if refresh {
                let old = observe_queries(&cancelled, |running| if running { Ok(vec!["Ubuntu".into()]) } else { Ok(vec!["Ubuntu".into()]) }).unwrap();
                test_receive_observation(&mut controller, old);
            }
            let observation = observe_queries(&cancelled, |running| if running { Err("synthetic secondary failure".into()) } else { names(&primary) }).unwrap();
            assert_eq!(observation.error.as_deref(), Some("synthetic secondary failure"));
            test_receive_observation(&mut controller, observation);
            let status = controller.snapshot(Some(preferences.clone()));
            assert!(status.error.as_deref().unwrap().contains("Подробности — в журнале"));
            assert_eq!(status.distributions.len(), 2);
            assert!(status.distributions.iter().all(|row| row.registration == crate::wsl_api::RegistrationState::Present && row.running.is_none()));
            assert!(!status.distributions[0].selected);
            assert_eq!(status.distributions[1].name, "Дистрибутив с пробелом");
            assert!(status.distributions[1].selected);
        }
    }
    #[test]
    fn primary_error_and_cancellation_remain_errors() {
        let cancelled = AtomicBool::new(false);
        let mut calls = 0;
        let result = observe_queries(&cancelled, |_| { calls += 1; Err("primary failure".into()) });
        assert_eq!(result.unwrap_err(), "primary failure");
        assert_eq!(calls, 1);
        let result = observe_queries(&cancelled, |running| {
            if running { cancelled.store(true, Ordering::SeqCst); Err("cancelled secondary".into()) }
            else { Ok(vec!["Ubuntu".into()]) }
        });
        assert_eq!(result.unwrap_err(), "WSL discovery cancelled");
    }

    fn fixture_program() -> Pinned {
        system_program(Path::new(r"WindowsPowerShell\v1.0\powershell.exe")).unwrap()
    }
    fn fixture_command(program: &Pinned, script: &str) -> Command {
        let mut command = Command::new(program.as_path());
        command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]);
        command
    }
    #[test]
    #[ignore = "owned Windows metadata actor; Root receives native fixture execution"]
    fn metadata_drains_both_pipes_before_receiving_nonzero_exit() {
        let program = fixture_program();
        let script = "for($i=0;$i -lt 32;$i++){[Console]::Out.Write(('o'*8192));[Console]::Error.Write(('e'*8192))};exit 43";
        let error = metadata_output(&program, fixture_command(&program, script), &AtomicBool::new(false),
            MetadataContext::new(MetadataPurpose::FirewallProfileQuery, None)).unwrap_err();
        assert!(error.contains("FirewallProfileQuery") && error.contains("exit code: 43"));
        assert!(error.contains(&"e".repeat(32 * 8192)));
        assert!(error.contains("stdout_bytes=262144"));
    }
    #[test]
    #[ignore = "owned Windows metadata actor; Root receives native fixture execution"]
    fn metadata_retains_nonzero_cause_and_later_recheck_failure() {
        let program = fixture_program();
        let script = "[Console]::Error.Write('actual cause 91'); exit 17";
        let error = metadata_output_with_context(&program, fixture_command(&program, script), &AtomicBool::new(false),
            true, start_stdout_reader, start_stderr_reader, Child::try_wait,
            |_| Err("injected post-exit recheck".into()), MetadataContext::new(MetadataPurpose::FirewallProfileQuery, None)).unwrap_err();
        assert!(error.contains("exit code: 17") && error.contains("actual cause 91") && error.contains("injected post-exit recheck"));
    }
    #[test]
    #[ignore = "uses pinned Windows system program; does not spawn a child"]
    fn metadata_cancel_and_pin_mismatch_fail_before_spawn() {
        let program = fixture_program();
        let cancelled = AtomicBool::new(true);
        let error = metadata_output(&program, fixture_command(&program, "exit 0"), &cancelled,
            MetadataContext::new(MetadataPurpose::RegisteredNames, None)).unwrap_err();
        assert!(error.contains("cancelled"));
        let error = metadata_output(&program, Command::new("not-the-pinned-program"), &AtomicBool::new(false),
            MetadataContext::new(MetadataPurpose::RunningNames, None)).unwrap_err();
        assert!(error.contains("RunningNames") && error.contains("pin differs"));
    }
    #[test]
    #[ignore = "owned Windows metadata actor; Root receives native fixture execution"]
    fn stderr_reader_failure_retains_partial_safe_cause_and_settles_child() {
        let program = fixture_program();
        let context = MetadataContext { purpose: MetadataPurpose::GuestIdentity, distro: Some("fixture"),
            private_values: &["fixture-secret"] };
        let error = metadata_output_with_context(&program, fixture_command(&program, EOF_FIXTURE),
            &AtomicBool::new(false), false, start_stdout_reader,
            |_stderr| thread::Builder::new().spawn(move || Err(std::io::Error::other(PartialRead {
                bytes: b"native cause 91 fixture-secret".to_vec(), message: "injected stderr read failure".into(),
            }))), Child::try_wait, |p| p.recheck(), context).unwrap_err();
        assert!(error.contains("exit code: 42") && error.contains("native cause 91") && error.contains("injected stderr read failure"));
        assert!(!error.contains("fixture-secret"));
    }
    #[test]
    #[ignore = "owned Windows metadata actor; Root receives native fixture execution"]
    fn stderr_reader_start_failure_still_receives_child_and_stdout() {
        let program = fixture_program();
        let error = metadata_output_with_context(&program, fixture_command(&program, EOF_FIXTURE),
            &AtomicBool::new(false), false, start_stdout_reader,
            |_| Err(std::io::Error::other("injected stderr start failure")), Child::try_wait, |p| p.recheck(),
            MetadataContext::new(MetadataPurpose::RunningNames, None)).unwrap_err();
        assert!(error.contains("exit code: 42") && error.contains("injected stderr start failure") && error.contains("stdout_bytes="));
    }
    #[test]
    #[ignore = "owned Windows metadata actor; Root receives native fixture execution"]
    fn stderr_reader_panic_still_receives_child() {
        let program = fixture_program();
        let error = metadata_output_with_context(&program, fixture_command(&program, EOF_FIXTURE),
            &AtomicBool::new(false), false, start_stdout_reader,
            |_stderr| thread::Builder::new().spawn(move || -> std::io::Result<Vec<u8>> { panic!("synthetic stderr panic") }),
            Child::try_wait, |p| p.recheck(), MetadataContext::new(MetadataPurpose::GuestIdentity, None)).unwrap_err();
        assert!(error.contains("exit code: 42") && error.contains("reader panicked") && error.contains("stderr_capture=Some"));
    }
    // The synthetic actor's five-second failure bound makes a missing EOF a
    // failing, physically settled test rather than an orphaned test process.
    const EOF_FIXTURE: &str = r#"try { [Console]::Out.WriteLine('NATURAL_READY'); [Console]::Out.Flush() } catch {};
$bytes=[byte[]]::new(1); $read=[Console]::OpenStandardInput().ReadAsync($bytes,0,1);
if (!$read.Wait(5000)) { exit 90 }; if ($read.Result -eq 0) { exit 42 }; exit 43"#;

    fn read_ready(stdout: std::process::ChildStdout)
        -> std::io::Result<(std::io::BufReader<std::process::ChildStdout>, Vec<u8>)> {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(stdout);
        let mut bytes = Vec::new();
        loop {
            let mut line = Vec::new();
            if reader.read_until(b'\n', &mut line)? == 0 {
                return Err(std::io::Error::other("synthetic actor exited before readiness"));
            }
            let ready = line == b"NATURAL_READY\r\n" || line == b"NATURAL_READY\n";
            bytes.extend(line);
            if ready { return Ok((reader, bytes)); }
        }
    }

    #[test]
    #[ignore = "owned Windows metadata actors; Root receives native fixture execution"]
    fn metadata_natural_writer_stays_open_unwritten_and_native_input_remains_null() {
        let program = fixture_program();
        let script = r#"$bytes=[byte[]]::new(1); $read=[Console]::OpenStandardInput().ReadAsync($bytes,0,1);
if ($read.Wait(150)) { exit 41 }; [Console]::Out.Write('LIVE_UNWRITTEN'); exit 0"#;
        let cancel = AtomicBool::new(false);
        let bytes = metadata_output_natural(&program, fixture_command(&program, script), &cancel, MetadataContext::new(MetadataPurpose::GuestIdentity, None)).unwrap();
        assert_eq!(bytes.stdout, b"LIVE_UNWRITTEN");
        let error = metadata_output(&program, fixture_command(&program, script), &cancel, MetadataContext::new(MetadataPurpose::RegisteredNames, None)).unwrap_err();
        assert!(error.contains("metadata query failed") && error.contains("exit code: 41"), "{error}");
    }

    #[test]
    #[ignore = "owned Windows metadata actors; Root receives native fixture execution"]
    fn metadata_natural_cancel_closes_writer_after_actual_actor_readiness() {
        let program = fixture_program();
        let cancel = Arc::new(AtomicBool::new(false));
        let reader_cancel = cancel.clone();
        let error = metadata_output_with(&program, fixture_command(&program, EOF_FIXTURE), &cancel, false,
            move |stdout| thread::Builder::new().spawn(move || {
                let (mut reader, mut bytes) = read_ready(stdout)?;
                reader_cancel.store(true, Ordering::SeqCst);
                reader.read_to_end(&mut bytes).map(|_| bytes)
            }), Child::try_wait).unwrap_err();
        assert!(error.contains("metadata operation cancelled") && error.contains("exit code: 42"), "{error}");
        assert!(error.contains("stop=None") && error.contains("capture=None"), "{error}");
    }

    #[test]
    #[ignore = "owned Windows metadata actors; Root receives native fixture execution"]
    fn metadata_natural_reader_spawn_failure_closes_writer_and_observes_exit() {
        let program = fixture_program();
        let error = metadata_output_with(&program, fixture_command(&program, EOF_FIXTURE), &AtomicBool::new(false), false,
            |_| Err(std::io::Error::other("injected reader spawn failure")), Child::try_wait).unwrap_err();
        assert!(error.contains("exit code: 42") && error.contains("injected reader spawn failure"), "{error}");
        assert!(error.contains("stop=None"), "{error}");
    }

    #[test]
    #[ignore = "owned Windows metadata actors; Root receives native fixture execution"]
    fn metadata_natural_reader_failure_closes_writer_and_joins_reader() {
        let program = fixture_program();
        let error = metadata_output_with(&program, fixture_command(&program, EOF_FIXTURE), &AtomicBool::new(false), false,
            |stdout| thread::Builder::new().spawn(move || {
                let _ = read_ready(stdout)?;
                Err(std::io::Error::other("injected stdout read failure"))
            }), Child::try_wait).unwrap_err();
        assert!(error.contains("exit code: 42") && error.contains("injected stdout read failure"), "{error}");
        assert!(error.contains("stop=None"), "{error}");
    }

    #[test]
    #[ignore = "owned Windows metadata actors; Root receives native fixture execution"]
    fn metadata_natural_observation_failure_closes_writer_and_retains_capture() {
        let program = fixture_program();
        let (ready, received) = std::sync::mpsc::channel();
        let mut injected = false;
        let error = metadata_output_with(&program, fixture_command(&program, EOF_FIXTURE), &AtomicBool::new(false), false,
            move |stdout| thread::Builder::new().spawn(move || {
                let (mut reader, mut bytes) = read_ready(stdout)?;
                let _ = ready.send(());
                reader.read_to_end(&mut bytes).map(|_| bytes)
            }), |child| {
                if !injected && received.try_recv().is_ok() {
                    injected = true;
                    Err(std::io::Error::other("injected Child observation failure"))
                } else { child.try_wait() }
            }).unwrap_err();
        assert!(injected && error.contains("exit code: 42") && error.contains("injected Child observation failure"), "{error}");
        assert!(error.contains("capture=None") && error.contains("stop=None"), "{error}");
    }

    #[test]
    #[ignore = "owned Windows metadata actors; Root receives native fixture execution"]
    fn metadata_native_cancel_retains_existing_kill_policy() {
        let program = fixture_program();
        let cancel = Arc::new(AtomicBool::new(false));
        let reader_cancel = cancel.clone();
        let script = "[Console]::Out.WriteLine('NATURAL_READY'); [Console]::Out.Flush(); [Threading.Thread]::Sleep(5000); exit 90";
        let error = metadata_output_with(&program, fixture_command(&program, script), &cancel, true,
            move |stdout| thread::Builder::new().spawn(move || {
                let (mut reader, mut bytes) = read_ready(stdout)?;
                reader_cancel.store(true, Ordering::SeqCst);
                reader.read_to_end(&mut bytes).map(|_| bytes)
            }), Child::try_wait).unwrap_err();
        assert!(error.contains("metadata operation cancelled") && error.contains("stop=Some(Ok(()))"), "{error}");
    }

    #[test]
    #[ignore = "explicit real selected-distro preparation; Root/QA owns cache effects and input receiving"]
    fn metadata_production_natural_prepares_received_helper() {
        let received = |name| std::env::var(name).expect("explicit Root-received preparation input required");
        let distro = received("AG_WSL_METADATA_DISTRO");
        let version = received("AG_WSL_METADATA_SERVER_VERSION");
        let helper_digest = received("AG_WSL_METADATA_HELPER_SHA256");
        let expected_source = received("AG_WSL_METADATA_SOURCE_SHA256");
        assert!(!distro.is_empty() && !distro.chars().any(char::is_control));
        assert!(!version.is_empty() && !version.contains('/') && !matches!(version.as_str(), "." | "..") && !version.chars().any(char::is_control));
        assert!(helper_digest.len() == 64 && helper_digest.bytes().all(|b| b.is_ascii_hexdigit()));
        let program = system_program(Path::new("wsl.exe")).unwrap();
        let mut command = Command::new(program.as_path());
        command.args(["-d", &distro, "--exec", "sh", "-c",
            r#"agLauncher=$HOME/.local/share/ag-unlocker/wsl/$1/ag_wsl_launch; agVersion=$2; exec "$agLauncher" --prepare-only --profile 1 1 "$HOME/.antigravity-server/bin/$agVersion/language_server""#,
            "sh", &helper_digest, &version]);
        let bytes = metadata_output_natural(&program, command, &AtomicBool::new(false), MetadataContext::new(MetadataPurpose::PrivateServerPreparation, None)).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&bytes.stdout).unwrap();
        assert_eq!(manifest.as_object().unwrap().len(), 8);
        assert_eq!(manifest["schema"], 1);
        assert_eq!(manifest["profile"], "wsl-profile-v1");
        assert_eq!(manifest["helper_sha256"], helper_digest);
        assert_eq!(manifest["source_sha256"], expected_source);
        assert!(manifest["cache_hit"].is_boolean());
    }

}
