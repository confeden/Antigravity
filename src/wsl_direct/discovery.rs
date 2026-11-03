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
    if cancelled.load(Ordering::SeqCst) { return Err("WSL discovery cancelled".into()); }
    program.recheck()?;
    let mut command = Command::new(program.as_path());
    command.args(["--list", "--quiet"]);
    if running { command.arg("--running"); }
    let bytes = metadata_output(program, command, cancelled)?;
    names(&bytes)
}

/// One owner for finite metadata-child/pipe custody. Output remains private
/// memory, and cancellation settles the exact creator Child before returning.
pub(super) fn metadata_output(program: &Pinned, command: Command, cancelled: &AtomicBool) -> Result<Vec<u8>> {
    metadata_output_impl(program, command, cancelled, true)
}
pub(super) fn metadata_output_natural(program: &Pinned, command: Command, cancelled: &AtomicBool) -> Result<Vec<u8>> {
    metadata_output_impl(program, command, cancelled, false)
}
fn metadata_output_impl(program: &Pinned, command: Command, cancelled: &AtomicBool, native_only: bool) -> Result<Vec<u8>> {
    metadata_output_with(program, command, cancelled, native_only, start_stdout_reader, Child::try_wait)
}

fn start_stdout_reader(mut stdout: std::process::ChildStdout)
    -> std::io::Result<thread::JoinHandle<std::io::Result<Vec<u8>>>> {
    thread::Builder::new().name("wsl-registration-output".into()).spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    })
}

/// Private injection seam for the existing reader-start and Child-observation
/// effects. Production and guards use this same acquisition/settlement owner.
fn metadata_output_with<S, O>(program: &Pinned, mut command: Command, cancelled: &AtomicBool,
    native_only: bool, start_reader: S, mut observe_child: O) -> Result<Vec<u8>>
where
    S: FnOnce(std::process::ChildStdout) -> std::io::Result<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
    O: FnMut(&mut Child) -> std::io::Result<Option<std::process::ExitStatus>>,
{
    if cancelled.load(Ordering::SeqCst) { return Err("metadata query cancelled".into()); }
    if command.get_program() != program.as_path().as_os_str() { return Err("metadata program pin differs".into()); }
    program.recheck()?;
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000);
    let stdin = if native_only { Stdio::null() } else { Stdio::piped() };
    let mut child = command.stdin(stdin).stdout(Stdio::piped())
        .stderr(Stdio::null()).spawn().map_err(|e| io("WSL registration query", e))?;
    // Only this job holds the natural helper's lifetime writer. It is never
    // written, inherited as console input, or released on stdout EOF alone.
    let mut input = child.stdin.take();
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
            (None, Some(Err(io("registration reader", error))))
        }
    };
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
            if capture.as_ref().is_some_and(|result| result.is_err()) { drop(input.take()); }
        }
        match observe_child(&mut child) {
            Ok(Some(exit)) => break exit,
            Ok(None) => {},
            Err(error) => {
                failure.get_or_insert_with(|| format!("registration observation: {error}"));
                drop(input.take());
            }
        }
        thread::sleep(Duration::from_millis(20));
    };
    // Actual exit releases the writer on success too. A still-started stdout
    // reader remains owned through its real completion inside this job.
    drop(input.take());
    let capture = match reader { Some(reader) => receive_stdout(reader), None => capture.unwrap() };
    let recheck = program.recheck();
    if cancellation_received || failure.is_some() || !exit.success() || capture.is_err()
        || stop.as_ref().is_some_and(|result| result.is_err()) || recheck.is_err() {
        let cause = if cancellation_received { "WSL discovery cancelled" }
            else if capture.is_err() { "WSL registration output failed" }
            else if failure.is_some() { "WSL registration observation failed" }
            else if !exit.success() { "WSL registration query failed" }
            else { "WSL metadata program recheck failed" };
        return Err(format!("{cause}: {exit}; cancellation={cancellation_received}; stop={stop:?}; observation={failure:?}; capture={:?}; recheck={:?}", capture.as_ref().err(), recheck.err()));
    }
    capture
}

fn receive_stdout(reader: thread::JoinHandle<std::io::Result<Vec<u8>>>) -> Result<Vec<u8>> {
    reader.join().map_err(|_| "WSL registration reader panicked".to_owned())?
        .map_err(|error| io("WSL registration output", error))
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
            assert!(status.error.as_deref().unwrap().contains("synthetic secondary failure"));
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
        let bytes = metadata_output_natural(&program, fixture_command(&program, script), &cancel).unwrap();
        assert_eq!(bytes, b"LIVE_UNWRITTEN");
        let error = metadata_output(&program, fixture_command(&program, script), &cancel).unwrap_err();
        assert!(error.contains("WSL registration query failed: exit code: 41"), "{error}");
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
        assert!(error.contains("WSL discovery cancelled: exit code: 42"), "{error}");
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
        assert!(error.starts_with("WSL discovery cancelled") && error.contains("stop=Some(Ok(()))"), "{error}");
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
        let bytes = metadata_output_natural(&program, command, &AtomicBool::new(false)).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(manifest.as_object().unwrap().len(), 8);
        assert_eq!(manifest["schema"], 1);
        assert_eq!(manifest["profile"], "wsl-profile-v1");
        assert_eq!(manifest["helper_sha256"], helper_digest);
        assert_eq!(manifest["source_sha256"], expected_source);
        assert!(manifest["cache_hit"].is_boolean());
    }

}
