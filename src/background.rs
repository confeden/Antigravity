// Keeping the DNS relay alive across reboots.
//
// The Windows implementation is a logon-triggered scheduled task; the Linux
// implementation is, for now, a set of honest stubs - the DNS/relay layer is the
// last part of the port (kb/patch.md), and until it lands the binary/JS patch is
// what lifts the gate on a permitted exit (kb/rivals.md Fact 2). The stubs report
// "not running / nothing to do" so menu 1's DNS branch is simply skipped rather
// than half-run.

/// Hidden flag that turns the unlocker into the relay. Handled before any UI.
pub const FORWARDER_FLAG: &str = "--dns-forwarder";
/// Hidden flag that runs ONLY the update watchdog - no relay, no DNS, no network.
/// Handled before any UI, same as the relay flag.
pub const WATCHDOG_FLAG: &str = "--watchdog";
/// Hidden flag that runs ONLY the local CONNECT proxy (`proxy::run`) - the Linux
/// phase-2 region route. No DNS listener, so no systemd-resolved conflict.
pub const PROXY_FLAG: &str = "--proxy";

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(not(target_os = "windows"))]
pub use unix_impl::*;

#[cfg(target_os = "windows")]
mod windows_impl {
    mod task_scheduler { include!("background/task_scheduler.rs"); }
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    use crate::dns_forwarder;
    use crate::windows_coordinator::{self, process_identity::ProcessIdentity};
    use crate::windows_coordinator::windows_installation::{self, CheckedPath, PathKind, PathPurpose};
    use super::{FORWARDER_FLAG, WATCHDOG_FLAG};
    use crate::utils::{bounded_output, no_window};
    #[cfg(test)]
    use crate::utils::powershell;

    // A scheduled task rather than a real service: a Windows service has to
    // implement StartServiceCtrlDispatcher and a control handler or the SCM kills
    // the process after ~30 seconds, which is a protocol to maintain for exactly
    // the same result. A logon-triggered task is a plain background process, and
    // enable/disable is one cmdlet each.
    //
    // Registered through the ScheduledTasks cmdlets, not schtasks.exe: the
    // defaults of the latter are wrong here in two ways that only surface on a
    // laptop weeks later - a task is stopped when the machine goes on battery, and
    // it is killed after a 72-hour execution limit. Both are switched off below.
    //
    // It also restarts on failure. The relay is compiled with `panic = "abort"`,
    // so any thread that goes down takes the whole process with it - and with it
    // the DNS the routed names depend on, until the next logon. A restart policy
    // is the only backstop available for that, since the panic cannot be caught.

    const TASK_NAME: &str = "AG Unlocker DNS";
    /// The watchdog's own logon task, separate from the relay's. Decoupling the
    /// re-patch survival from the relay is what lets it keep working when the relay
    /// is stopped (menu 4), has died, or was never installed (a future patch-only
    /// machine) - the case G9 describes today, where no relay means no watchdog.
    const WATCHDOG_TASK_NAME: &str = "AG Unlocker Watchdog";

    /// ProgramData, **not** LOCALAPPDATA. Measured on a real machine: a scheduled
    /// task launching anything out of `%LOCALAPPDATA%` fails with 0x80070002, and a
    /// stock `ping.exe` copied there fails identically - it is an anti-persistence
    /// heuristic (a task autostarting an exe from AppData is the classic malware
    /// shape), not something about our binary. The same probe from ProgramData and
    /// Program Files starts cleanly.
    pub fn install_dir() -> Result<PathBuf, String> {
        Ok(windows_installation::background_locations()?.managed_directory().to_path_buf())
    }

    pub fn installed_exe() -> Result<PathBuf, String> {
        Ok(windows_installation::background_locations()?.managed_program().to_path_buf())
    }
    pub(crate) fn relay_process_name() -> String {
        // The native owner supplies one static UTF-8 filename. Both existing
        // consumers require its stem: Get-Process uses it directly, while the
        // tasklist caller appends exactly one executable extension.
        Path::new(windows_installation::background_process_name())
            .file_stem().and_then(|stem| stem.to_str())
            .expect("canonical native background filename must have a UTF-8 stem")
            .to_owned()
    }

    /// Limit for the small status helpers here. Short, because
    /// they answer in milliseconds when they answer at all - and this runs on the
    /// path a user is watching.
    const HELPER_LIMIT: Duration = Duration::from_secs(15);

    /// Whether the scheduled task exists, asked of `schtasks.exe` rather than of
    /// PowerShell.
    ///
    /// Same question, same answer, roughly a tenth of the wall clock: starting
    /// PowerShell costs several hundred milliseconds before it reads the first
    /// character of the script, and this is asked twice on every status refresh —
    /// which is a large part of why flipping a switch took seconds. `schtasks` is
    /// a plain Win32 binary shipped with every Windows since XP; it exits 0 when
    /// the task is there and non-zero when it is not, and the task is registered
    /// in the root folder, so the bare name is the whole query.
    fn task_exists(task_name: &str) -> bool {
        // The task's own file first: no process to spawn, so no timeout to
        // misread. A `schtasks` that did not answer in time once read as "no
        // task", and `ensure_installed` then killed a working relay to copy a
        // file and never started it again (field report, 2.19.1).
        let tasks = PathBuf::from(env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("Tasks");
        if tasks.join(task_name).exists() {
            return true;
        }
        let mut cmd = Command::new("schtasks");
        cmd.args(["/Query", "/TN", task_name]);
        bounded_output(no_window(&mut cmd), HELPER_LIMIT).is_some_and(|o| o.status.success())
    }

    /// Uncached scheduler evidence used before privileged mutations.
    pub(crate) struct TaskState {
        pub(crate) relay_enabled: bool,
        pub(crate) watchdog_enabled: bool,
    }
    #[derive(Clone, Copy, Debug, serde::Serialize)]
    pub(crate) struct BackgroundDesired {
        pub(crate) relay: bool,
        pub(crate) watchdog: bool,
    }

    #[derive(serde::Serialize, Debug)]
    pub(crate) enum BackgroundEffect {
        CompatibleNoop,
        DirectoryCreateRequested,
        DirectoryCreateReturnedSuccess,
        ProgramCreateRequested,
        ProgramCreateReturnedSuccess,
        ProgramReadbackReceived { program: PathBuf, program_native_id: windows_installation::NativeObjectId,
            source_native_id: windows_installation::NativeObjectId, sha256: String, generation: u32 },
        CurrentProgramReceived { program_native_id: windows_installation::NativeObjectId, sha256: String },
        TaskInstancesRetired(Vec<String>),
        GenerationObserved { metadata: Result<Option<u32>, String>, runtime: Option<u32> },
        GenerationWriteRequested,
    }
    #[derive(serde::Serialize, Debug)]
    pub(crate) struct BackgroundNativeReceiving {
        pub(crate) role: String,
        pub(crate) started: bool,
        pub(crate) exit_observed: bool,
        pub(crate) exit_code: Option<i32>,
        pub(crate) stdout: Vec<u8>,
        pub(crate) stderr: Vec<u8>,
        pub(crate) errors: Vec<String>,
        pub(crate) stdout_file: Option<DiagnosticFileRef>,
        pub(crate) stderr_file: Option<DiagnosticFileRef>,
    }
    /// Returned to the existing operation worker on every path. The worker
    /// persists actual progress/partial native outcomes before interpretation;
    /// no mutable global last-result or fabricated completion frame is used.
    #[derive(serde::Serialize, Debug)]
    pub(crate) struct BackgroundReceiving {
        pub(crate) operation: &'static str,
        pub(crate) result: Result<(), String>,
        pub(crate) effects: Vec<BackgroundEffect>,
        pub(crate) native: Vec<BackgroundNativeReceiving>,
        pub(crate) replacements: Vec<serde_json::Value>,
        pub(crate) generation_writes: Vec<serde_json::Value>,
        pub(crate) generation_reads: Vec<serde_json::Value>,
        pub(crate) diagnostic_journal: Option<DiagnosticFileRef>,
        pub(crate) diagnostic: Option<DiagnosticFileRef>,
        pub(crate) persistence_errors: Vec<String>,
        pub(crate) cancellation_received: bool,
        pub(crate) restoration_pending: bool,
        pub(crate) primary_result: Option<serde_json::Value>,
        pub(crate) restoration_result: Option<Result<(), String>>,
        pub(crate) task_events: Vec<task_scheduler::Event>,
    }
    fn empty_receiving(operation: &'static str) -> BackgroundReceiving {
        BackgroundReceiving { operation, result: Ok(()), effects: Vec::new(), native: Vec::new(), replacements: Vec::new(), generation_writes: Vec::new(), generation_reads: Vec::new(),
            diagnostic_journal: None, diagnostic: None, persistence_errors: Vec::new(), cancellation_received: false, restoration_pending: false,
            primary_result: None, restoration_result: None, task_events: Vec::new() }
    }
    struct BackgroundRun<'a> {
        received: BackgroundReceiving,
        cancelled: &'a AtomicBool,
        diagnostic: BackgroundDiagnostic,
        lease: Option<&'a windows_installation::BackgroundLease>,
        program_directory: PathBuf,
        selected_program: PathBuf,
        primary_unwind: Option<Box<dyn std::any::Any + Send>>,
        restoring: bool,
        created_directory: Option<CheckedPath>,
        created_program: Option<CreatedManagedProgram>,
        image: Option<Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>>,
        source_leases: Vec<std::sync::Arc<windows_installation::BackgroundLease>>,
        #[cfg(test)]
        scheduler_fixture: Option<SchedulerFixture>,
    }
    /// Constructed only after this live operation's successful CREATE_NEW and
    /// independent receiving; never decoded from a diagnostic or path/ACL.
    struct CreatedManagedProgram { guard: CheckedPath, source_sha256: String }
    #[derive(Clone, Copy)]
    enum OccupancyOwnership { CurrentManagedBinding, LiveCreator, Unproved }
    fn require_owned_occupancy(proof: OccupancyOwnership) -> Result<(), String> {
        match proof { OccupancyOwnership::CurrentManagedBinding | OccupancyOwnership::LiveCreator => Ok(()),
            OccupancyOwnership::Unproved => Err("OccupiedStateHold: no current managed binding or same-live creator capability".into()) }
    }
    impl std::ops::Deref for BackgroundRun<'_> {
        type Target = BackgroundReceiving;
        fn deref(&self) -> &Self::Target { &self.received }
    }
    impl std::ops::DerefMut for BackgroundRun<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target { &mut self.received }
    }
    impl<'a> BackgroundRun<'a> {
        fn lease(&self) -> Result<&'a windows_installation::BackgroundLease, String> {
            self.lease.ok_or_else(|| "background program lease unavailable".into())
        }
        fn context(&self) -> Option<&'a windows_installation::AncestorAccessContext> {
            self.lease.and_then(|lease| lease.context())
        }
        fn program_path(&self) -> PathBuf { self.selected_program.clone() }
        fn ready(&mut self) -> Result<(), String> {
            if self.cancelled.load(Ordering::SeqCst) {
                self.received.cancellation_received = true;
                if !self.received.restoration_pending {
                    return Err("Cancelled: preserve actual background tasks and received partial effects; health is unverified".into());
                }
            }
            if !self.persistence_errors.is_empty() && !self.restoring { return Err("Diagnostic retention failed: no next independent background effect is granted".into()); }
            Ok(())
        }
        fn record(&mut self, event: &str) -> Result<(), String> {
            if let Err(error) = self.diagnostic.record(event, &self.received) {
                self.received.persistence_errors.push(error.clone());
                return Err(error);
            }
            Ok(())
        }
        fn effect(&mut self, effect: BackgroundEffect) -> Result<(), String> {
            self.received.effects.push(effect);
            self.record("effect")
        }
        fn task_state(&self) -> Result<TaskState, String> {
            #[cfg(test)]
            if let Some(fixture) = &self.scheduler_fixture { return Ok(TaskState {
                relay_enabled: fixture.relay_present, watchdog_enabled: fixture.watchdog_present }); }
            if self.restoration_pending { checked_task_state() }
            else { checked_task_state_with_cancel(self.cancelled) }
        }
        fn relay_compatible(&self) -> Result<bool, String> {
            let task = self.task_state()?.relay_enabled;
            let report = crate::gate::read_checked()?;
            Ok(relay_compatible(task, report.as_ref(), &self.program_path()))
        }
    }
    impl task_scheduler::Receiving for BackgroundRun<'_> {
        fn check_cancel(&mut self) -> Result<(), String> { self.ready() }
        fn before_retirement(&mut self) -> Result<(), String> {
            self.ready()?;
            if !self.restoration_pending {
                self.record("exactInstanceRetirementGrantPending")?;
                self.ready()?;
                self.restoration_pending = true;
            }
            Ok(())
        }
        fn receive(&mut self, event: task_scheduler::Event) -> Result<(), String> {
            self.task_events.push(event);
            match self.record("nativeTaskOutcome") {
                Err(_) if self.restoring => Ok(()),
                result => result,
            }
        }
    }
    fn receiving(operation: &'static str, cancelled: &AtomicBool,
        image: Option<Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>>,
        action: impl FnOnce(&mut BackgroundRun<'_>) -> Result<(), String>) -> BackgroundReceiving {
        let mut received = empty_receiving(operation);
        let locations = match windows_installation::background_locations() {
            Ok(locations) => locations,
            Err(error) => { received.result = Err(error); return received; }
        };
        let directory = locations.managed_directory().to_path_buf();
        let selected_program = locations.managed_program().to_path_buf();
        let diagnostic_parent = dns_forwarder::log_dir();
        let prepared = (|| {
            let inputs = windows_installation::background_inputs(
                locations.managed_root(), &directory,
                None, &diagnostic_parent)?;
            let context = windows_coordinator::receive_for_background(&inputs)?;
            windows_installation::background_lease(inputs, context)
        })();
        let lease = match prepared {
            Ok(lease) => lease,
            Err(error) => { received.result = Err(error); return received; }
        };
        let diagnostic = match BackgroundDiagnostic::begin(operation, diagnostic_parent, lease.context()) {
            Ok(diagnostic) => diagnostic,
            Err(error) => { received.persistence_errors.push(error.clone()); received.result = Err(error); return received; }
        };
        received.diagnostic_journal = Some(diagnostic.journal_reference());
        let mut run = BackgroundRun { received, cancelled, diagnostic, lease: Some(&lease), program_directory: directory, selected_program, primary_unwind: None, restoring: false, created_directory: None, created_program: None, image, source_leases: Vec::new(),
            #[cfg(test)] scheduler_fixture: None };
        run.received.result = run.ready().and_then(|_| action(&mut run));
        if cancelled.load(Ordering::SeqCst) {
            run.received.cancellation_received = true;
            if run.received.result.is_ok() {
                run.received.result = Err("Cancelled: actual background transition is retained; stop subsequent independent actions".into());
            }
        }
        finalize_receiving(&mut run);
        if let Some(payload) = run.primary_unwind.take() { std::panic::resume_unwind(payload); }
        run.received
    }
    fn finalize_receiving(run: &mut BackgroundRun<'_>) {
        match run.diagnostic.finish(&run.received, run.lease.as_ref().and_then(|lease| lease.context())) {
            Ok(reference) => run.received.diagnostic = Some(reference),
            Err(error) => {
                run.received.persistence_errors.push(error.clone());
                run.received.result = Err(match &run.received.result {
                    Ok(()) => error,
                    Err(previous) => format!("{previous}; diagnostic terminal retention: {error}"),
                });
            }
        }
    }

    fn uncancelled_receiving(operation: &'static str, action: impl FnOnce(&mut BackgroundRun<'_>) -> Result<(), String>) -> BackgroundReceiving {
        receiving(operation, &AtomicBool::new(false), None, action)
    }

    #[derive(Clone, Debug, serde::Serialize)]
    pub(crate) struct DiagnosticFileRef {
        pub(crate) path: PathBuf,
        pub(crate) native_id: windows_installation::NativeObjectId,
        pub(crate) sha256: Option<String>,
    }
    struct BackgroundDiagnostic {
        id: String,
        directory: PathBuf,
        journal: windows_installation::BackgroundDiagnosticFile,
        next_output: u64,
        effects_written: usize,
        replacements_written: usize,
        generations_written: usize,
        generation_reads_written: usize,
        task_events_written: usize,
        persistence_errors_written: usize,
        #[cfg(test)]
        injected_write_failure: bool,
    }
    impl BackgroundDiagnostic {
        fn begin(operation: &str, directory: PathBuf, context: Option<&windows_installation::AncestorAccessContext>) -> Result<Self, String> {
            windows_installation::WindowsLocalPath::parse(directory.as_os_str())?;
            let id = windows_installation::new_request_id()?;
            let journal = windows_installation::create_background_diagnostic_file(&directory.join(format!("background-{id}.jsonl")), context)?;
            let mut diagnostic = Self { id, directory, journal, next_output: 0, effects_written: 0,
                replacements_written: 0, generations_written: 0, generation_reads_written: 0, task_events_written: 0, persistence_errors_written: 0,
                #[cfg(test)] injected_write_failure: false };
            diagnostic.write(&serde_json::json!({"event":"begin","operation":operation,"operationId":diagnostic.id}))?;
            Ok(diagnostic)
        }
        fn journal_reference(&self) -> DiagnosticFileRef {
            DiagnosticFileRef { path: self.journal.path.clone(), native_id: self.journal.native_id.clone(), sha256: None }
        }
        fn write(&mut self, value: &serde_json::Value) -> Result<(), String> {
            #[cfg(test)]
            if self.injected_write_failure { return Err("injected diagnostic write failure; actual outcomes retained".into()); }
            let mut bytes = serde_json::to_vec(value).map_err(|e| format!("background diagnostic serialization: {e}"))?;
            bytes.push(b'\n');
            self.journal.file.write_all(&bytes).and_then(|_| self.journal.file.flush()).and_then(|_| self.journal.file.sync_all())
                .map_err(|e| format!("background diagnostic write/flush {}: {e}; preserve actual receipt", self.journal.path.display()))
        }
        fn record(&mut self, event: &str, received: &BackgroundReceiving) -> Result<(), String> {
            // Incremental facts, rather than repeatedly serializing all older
            // native streams during a pending health poll. The full terminal
            // receiving is written exactly once by finish.
            self.write(&serde_json::json!({"event":event,"operation":received.operation,
                "effects":&received.effects[self.effects_written..],
                "replacements":&received.replacements[self.replacements_written..],
                "generationWrites":&received.generation_writes[self.generations_written..],
                "generationReads":&received.generation_reads[self.generation_reads_written..],
                "taskEvents":&received.task_events[self.task_events_written..],
                "persistenceErrors":&received.persistence_errors[self.persistence_errors_written..],
                "nativeIndex":received.native.len().checked_sub(1),"native":received.native.last(),
                "result":received.result,"primary":received.primary_result,"restoration":received.restoration_result,
                "cancelled":received.cancellation_received,"restorationPending":received.restoration_pending}))?;
            self.effects_written = received.effects.len();
            self.replacements_written = received.replacements.len();
            self.generations_written = received.generation_writes.len();
            self.generation_reads_written = received.generation_reads.len();
            self.task_events_written = received.task_events.len();
            self.persistence_errors_written = received.persistence_errors.len();
            Ok(())
        }
        fn output_file(&mut self, stream: &str, context: Option<&windows_installation::AncestorAccessContext>) -> Result<windows_installation::BackgroundDiagnosticFile, String> {
            let index = self.next_output;
            self.next_output = self.next_output.checked_add(1).ok_or("background diagnostic output identity overflow")?;
            windows_installation::create_background_diagnostic_file(&self.directory.join(format!("background-{}-{index}-{stream}.bin", self.id)), context)
        }
        fn finish(&mut self, received: &BackgroundReceiving, context: Option<&windows_installation::AncestorAccessContext>) -> Result<DiagnosticFileRef, String> {
            let bytes = serde_json::to_vec(&serde_json::json!({"operationId":self.id,"journal":self.journal_reference(),"receiving":received}))
                .map_err(|e| format!("background terminal serialization: {e}"))?;
            let mut terminal = windows_installation::create_background_diagnostic_file(&self.directory.join(format!("background-{}-terminal.json", self.id)), context)?;
            terminal.file.write_all(&bytes).and_then(|_| terminal.file.flush()).and_then(|_| terminal.file.sync_all())
                .map_err(|e| format!("background terminal write/flush {}: {e}; preserve actual partial receipt",terminal.path.display()))?;
            let mut reference = DiagnosticFileRef { path: terminal.path.clone(), native_id: terminal.native_id.clone(), sha256: None };
            drop(terminal.file);
            let actual = windows_installation::read_background_diagnostic_file(&reference.path, &reference.native_id, context)?;
            if actual != bytes { return Err(format!("background terminal independent readback differs: {}; preserve it", reference.path.display())); }
            use sha2::Digest;
            reference.sha256 = Some(hex::encode(sha2::Sha256::digest(&actual)));
            Ok(reference)
        }
    }

    /// Actual helpers remain creator-owned until physical exit. Their streams
    /// go directly to retained private files, with no off-path reader resources.
    struct NativeOwner {
        child: Child,
        exited: bool,
        exit_code: Option<i32>,
    }
    impl NativeOwner {
        fn settle(&mut self, errors: &mut Vec<String>) {
            self.settle_with_cancel(errors, None, false);
        }
        fn settle_with_cancel(&mut self, errors: &mut Vec<String>, cancelled: Option<&AtomicBool>, read_only: bool) {
            let mut cancellation_sent = false;
            while !self.exited {
                if !cancellation_sent && cancelled.is_some_and(|value| value.load(Ordering::SeqCst)) {
                    cancellation_sent = true;
                    self.child.stdin.take();
                    if read_only {
                        // Only the exact creator-owned read-only query child.
                        // An already-selected task instance is never killed.
                        if let Err(error) = self.child.kill() { errors.push(format!("native read-only cancellation request: {error}")); }
                    }
                }
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        self.exited = true;
                        self.child.stdin.take();
                        self.exit_code = status.code();
                        if !status.success() { errors.push(format!("scheduler helper exited {status}")); }
                    }
                    Ok(None) => thread::park_timeout(Duration::from_millis(20)),
                    Err(e) => {
                        let error = format!("scheduler helper exit observation: {e}");
                        if !errors.contains(&error) { errors.push(error); }
                        // Keep the creator's handle and readers. A query failure
                        // confers neither termination authority nor completion.
                        thread::park_timeout(Duration::from_millis(20));
                    }
                }
            }
        }
    }
    impl Drop for NativeOwner {
        fn drop(&mut self) { self.child.stdin.take(); self.settle(&mut Vec::new()); }
    }

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct TaskReceipt {
        present: bool,
        compatible: bool,
        instances: Vec<String>,
        created: bool,
        #[serde(deserialize_with = "required_option")]
        started: Option<String>,
        retired: Vec<String>,
        roles_present: Vec<String>,
    }
    fn required_option<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
        <Option<T> as serde::Deserialize>::deserialize(d)
    }

    /// The typed native adapter owns Scheduler truth. The private test transport
    /// below substitutes acquired outcomes without executing product tasks.
    fn scheduler(role: &str, create: bool, program: &CheckedPath, received: &mut BackgroundRun<'_>) -> Result<TaskReceipt, String> {
        scheduler_action(role, if create { "ensure" } else { "inspect" }, program, received)
    }
    fn scheduler_action(role: &str, operation: &str, program: &CheckedPath, received: &mut BackgroundRun<'_>) -> Result<TaskReceipt, String> {
        received.ready()?;
        #[cfg(test)]
        if received.scheduler_fixture.is_some() {
            let fixture = received.scheduler_fixture.as_mut().unwrap();
            fixture.calls.push((role.to_owned(), operation.to_owned()));
            fixture.program_native_ids.push(program.native_id());
            let reply = fixture.replies.pop_front().expect("explicit synthetic transport reply required");
            let latch = role == "shared" && operation == "retire";
            let cancel_after_retire = latch && fixture.cancel_after_retire;
            let fail_after_retire = latch && fixture.fail_after_retire;
            if latch { received.restoration_pending = true; }
            if cancel_after_retire { received.cancelled.store(true, Ordering::SeqCst); }
            if fail_after_retire { received.diagnostic.injected_write_failure = true; }
            if operation == "resume" {
                task_scheduler::Receiving::receive(received, task_scheduler::Event::Call(task_scheduler::Call {
                    operation: "syntheticRestoreRun", role: role.to_owned(), instance: None, returned_hresult: Some(0), output_returned: true,
                    error_info: task_scheduler::ErrorInfo::NoInfo { hresult: 1 },
                }))?;
            }
            return reply;
        }
        let scheduler = task_scheduler::Scheduler::connect()?;
        let programs = task_scheduler::Programs { managed: Some(program), legacy: None };
        let roles: &[&str] = if role == "shared" { &["relay", "watchdog"] } else { &[role] };
        match operation {
            "ensure" => scheduler.ensure(role, &programs, true, received),
            "inspect" => Ok(scheduler.receive(roles, &programs, received)?.receipt()),
            "remove" => scheduler.receive(roles, &programs, received)?.remove(&programs, received),
            _ => Err("unknown native background operation".into()),
        }
    }
    #[cfg(test)]
    struct SchedulerFixture {
        relay_present: bool,
        watchdog_present: bool,
        cancel_after_retire: bool,
        fail_after_retire: bool,
        replies: std::collections::VecDeque<Result<TaskReceipt, String>>,
        calls: Vec<(String, String)>,
        program_native_ids: Vec<windows_installation::NativeObjectId>,
    }
    fn native_output(script: &str, request: Option<&[u8]>, program: Option<&CheckedPath>, role: &str, read_only: bool, starts_transition: bool,
        received: &mut BackgroundRun<'_>) -> Result<Vec<u8>, String> {
        received.ready()?;
        let host = windows_coordinator::system_powershell_program()?;
        let current = ProcessIdentity::current()?;
        host.recheck()?;
        let index = received.native.len();
        received.native.push(BackgroundNativeReceiving { role: role.to_owned(), started: false, exit_observed: false,
            exit_code: None, stdout: Vec::new(), stderr: Vec::new(), errors: Vec::new(), stdout_file: None, stderr_file: None });
        let context = received.lease.as_ref().and_then(|lease| lease.context());
        let stdout = received.diagnostic.output_file("stdout", context)?;
        received.native[index].stdout_file = Some(output_reference(&stdout));
        received.record("nativeStdoutPrepared")?;
        let context = received.lease.as_ref().and_then(|lease| lease.context());
        let stderr = received.diagnostic.output_file("stderr", context)?;
        received.native[index].stderr_file = Some(output_reference(&stderr));
        received.record("nativeStderrPrepared")?;
        let mut command = Command::new(host.as_path());
        command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(stdout.file.try_clone().map_err(|e| format!("clone native stdout file: {e}"))?))
            .stderr(Stdio::from(stderr.file.try_clone().map_err(|e| format!("clone native stderr file: {e}"))?));
        received.ready()?;
        let child = no_window(&mut command).spawn().map_err(|e| format!("scheduler helper spawn: {e}"))?;
        drop(command);
        received.native[index].started = true;
        let mut owner = NativeOwner { child, exited: false, exit_code: None };
        let mut errors = Vec::new();
        // Setup failure closes the still-ungranted stdin and observes real
        // helper exit. Inherited output files stay held throughout settlement.
        let setup = (|| -> Result<(), String> {
            use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
            use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            let mut duplicate = std::ptr::null_mut();
            if unsafe { DuplicateHandle(GetCurrentProcess(), owner.child.as_raw_handle(), GetCurrentProcess(), &mut duplicate, 0, 0, DUPLICATE_SAME_ACCESS) } == 0 {
                return Err(format!("scheduler helper handle receiving: {}", std::io::Error::last_os_error()));
            }
            let identity = ProcessIdentity::receive(unsafe { OwnedHandle::from_raw_handle(duplicate) })?;
            if identity.image() != host.as_path() || identity.sid() != current.sid() { return Err("scheduler helper identity mismatch".into()); }
            identity.recheck()?;
            host.recheck()?;
            if let Some(program) = program { program.recheck()?; }
            received.record("nativeHelperReceived")?;
            received.ready()?;
            if let Some(request) = request {
                if starts_transition {
                    // The JSON grant permits the first exact-instance Stop.
                    // Cancellation after this point is latched, never delivered
                    // as EOF until required wanted-role restoration settles.
                    received.record("sharedRetirementGrantPending")?;
                    received.ready()?;
                    received.restoration_pending = true;
                }
                let input = owner.child.stdin.as_mut().ok_or("scheduler stdin absent")?;
                input.write_all(request).and_then(|_| input.write_all(b"\n")).and_then(|_| input.flush())
                    .map_err(|e| format!("scheduler grant delivery: {e}"))?;
            }
            Ok(())
        })();
        if let Err(e) = setup { errors.push(e); owner.child.stdin.take(); }
        owner.settle_with_cancel(&mut errors,
            if received.restoration_pending { None } else { Some(received.cancelled) }, read_only);
        let (out, out_ref, out_errors) = capture_file(stdout, received.context());
        let (err, err_ref, err_errors) = capture_file(stderr, received.context());
        errors.extend(out_errors);
        errors.extend(err_errors);
        received.native[index] = BackgroundNativeReceiving { role: role.to_owned(), started: true, exit_observed: owner.exited,
            exit_code: owner.exit_code, stdout: out.clone(), stderr: err.clone(), errors: errors.clone(),
            stdout_file: Some(out_ref), stderr_file: Some(err_ref) };
        // Output kernel writes are incremental. Terminal receiving is flushed
        // before interpretation; persistence failure never prevents settlement.
        received.record("nativeHelperRetired")?;
        if !errors.is_empty() {
            return Err(format!("{}; native stdout={}; native stderr={}", errors.join("; "),
                String::from_utf8_lossy(&out), String::from_utf8_lossy(&err)));
        }
        received.ready()?;
        Ok(out)
    }

    fn output_reference(file: &windows_installation::BackgroundDiagnosticFile) -> DiagnosticFileRef {
        DiagnosticFileRef { path: file.path.clone(), native_id: file.native_id.clone(), sha256: None }
    }
    fn capture_file(mut file: windows_installation::BackgroundDiagnosticFile, context: Option<&windows_installation::AncestorAccessContext>) -> (Vec<u8>, DiagnosticFileRef, Vec<String>) {
        let mut reference = output_reference(&file);
        let mut errors = Vec::new();
        if let Err(error) = file.file.flush().and_then(|_| file.file.sync_all()) { errors.push(format!("native capture flush {}: {error}", reference.path.display())); }
        let mut bytes = Vec::new();
        if let Err(error) = file.file.seek(SeekFrom::Start(0)).and_then(|_| file.file.read_to_end(&mut bytes)) {
            errors.push(format!("native capture read {}: {error}; acquired prefix retained", reference.path.display()));
        }
        drop(file.file);
        match windows_installation::read_background_diagnostic_file(&reference.path, &reference.native_id, context) {
            Ok(actual) => {
                if actual.starts_with(&bytes) {
                    bytes = actual;
                    use sha2::Digest;
                    reference.sha256 = Some(hex::encode(sha2::Sha256::digest(&bytes)));
                } else { errors.push(format!("native capture independent readback conflict: {}; preserve actual file", reference.path.display())); }
            }
            Err(error) => errors.push(format!("native capture independent readback: {error}")),
        }
        (bytes, reference, errors)
    }

    fn checked_json_with_cancel(script: &str, cancelled: &AtomicBool) -> Result<serde_json::Value, String> {
        let host = windows_coordinator::system_powershell_program()?;
        let mut command = Command::new(host.as_path());
        command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]);
        let stdout = windows_coordinator::runtime_metadata(&host, command, cancelled, false,
            windows_coordinator::MetadataContext::new(windows_coordinator::MetadataPurpose::BackgroundStateQuery, None))?;
        parse_checked_json(stdout.as_bytes())
    }

    fn parse_checked_json(stdout: &[u8]) -> Result<serde_json::Value, String> {
        let text = std::str::from_utf8(stdout).map_err(|_| "native query invalid UTF-8")?;
        let json = text.trim().strip_suffix("\nAG_END").ok_or("native query incomplete")?.trim();
        serde_json::from_str(json).map_err(|e| format!("invalid native query: {e}"))
    }

    pub(crate) fn checked_task_state() -> Result<TaskState, String> {
        checked_task_state_with_cancel(&AtomicBool::new(false))
    }
    pub(crate) fn checked_task_state_with_cancel(cancelled: &AtomicBool) -> Result<TaskState, String> {
        let script = format!(
            "$ErrorActionPreference='Stop'; $names=@(Get-ScheduledTask -TaskPath '\\' | \
             Where-Object {{ $_.TaskName -in @('{}','{}') }} | ForEach-Object {{ $_.TaskName }}); \
             ConvertTo-Json -InputObject $names -Compress; 'AG_END'", TASK_NAME, WATCHDOG_TASK_NAME
        );
        let names: Vec<String> = serde_json::from_value(checked_json_with_cancel(&script, cancelled)?)
            .map_err(|e| format!("invalid scheduler result: {e}"))?;
        if names.iter().any(|n| n != TASK_NAME && n != WATCHDOG_TASK_NAME) {
            return Err("unexpected scheduler task".into());
        }
        Ok(TaskState { relay_enabled: names.iter().any(|n| n == TASK_NAME),
                       watchdog_enabled: names.iter().any(|n| n == WATCHDOG_TASK_NAME) })
    }

    /// Existing relay health evidence; this does not grant a stop capability.
    pub(crate) fn checked_relay_compatible() -> Result<bool, String> {
        checked_relay_compatible_with_cancel(&AtomicBool::new(false))
    }
    pub(crate) fn checked_relay_compatible_with_cancel(cancelled: &AtomicBool) -> Result<bool, String> {
        let task = checked_task_state_with_cancel(cancelled)?.relay_enabled;
        let report = crate::gate::read_checked()?;
        Ok(relay_compatible(task, report.as_ref(), &installed_exe()?))
    }

    fn relay_compatible(task_present: bool, report: Option<&crate::gate::Report>, exe: &Path) -> bool {
        task_present && report.is_some_and(|r| {
            !r.is_stale() && r.version == dns_forwarder::RELAY_VERSION
                && r.blockers.is_empty() && Path::new(&r.exe) == exe
        })
    }

    pub(crate) fn checked_installed_copy_current() -> Result<bool, String> {
        let src = env::current_exe().map_err(|e| format!("current executable: {e}"))?;
        let current = fs::read(src).map_err(|e| format!("read current executable: {e}"))?;
        match fs::read(installed_exe()?) {
            Ok(installed) => Ok(current == installed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("read installed executable: {e}")),
        }
    }

    pub(crate) fn checked_relay_outdated() -> Result<bool, String> {
        checked_relay_outdated_with_cancel(&AtomicBool::new(false))
    }
    pub(crate) fn checked_relay_outdated_with_cancel(cancelled: &AtomicBool) -> Result<bool, String> {
        let locations = windows_installation::background_locations()?;
        let scheduler = task_scheduler::Scheduler::connect()?;
        if scheduler.references_program(locations.legacy_program())? { return Ok(true); }
        match fs::metadata(locations.managed_program()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let tasks = checked_task_state_with_cancel(cancelled)?;
                if tasks.relay_enabled || tasks.watchdog_enabled {
                    return Err("OwnershipRequired: registered background role references an absent program".into());
                }
                return Ok(false);
            }
            Err(e) => return Err(format!("installed executable metadata: {e}")),
            Ok(_) => {}
        }
        let report = crate::gate::read_checked()?;
        let runtime = runtime_generation(report.as_ref(), locations.managed_program());
        Ok(generation_for_update(&dns_forwarder::checked_installed_version_observation(), runtime)? < dns_forwarder::RELAY_VERSION)
    }

    /// True when the logon task exists. Says nothing about whether the relay is
    /// running right now - `is_running` answers that.
    pub fn is_enabled() -> bool {
        task_exists(TASK_NAME)
    }

    /// True when the watchdog's own logon task exists.
    #[allow(dead_code)]
    pub fn is_watchdog_enabled() -> bool {
        task_exists(WATCHDOG_TASK_NAME)
    }

    pub fn is_running() -> bool {
        let mut cmd = Command::new("tasklist");
        let name = format!("{}.exe", relay_process_name());
        cmd.args(["/FI", &format!("IMAGENAME eq {}", name), "/NH"]);
        bounded_output(no_window(&mut cmd), HELPER_LIMIT).map_or(false, |o| {
            String::from_utf8_lossy(&o.stdout).contains(&name)
        })
    }

    /// Preserve a compatible running relay. Fresh installation is create-only;
    /// an existing unqualified generation is never retired by image name.
    pub fn enable() -> Result<(), String> {
        enable_with_receiving().result
    }
    pub(crate) fn enable_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("enableRelay", enable_inner)
    }
    fn enable_inner(received: &mut BackgroundRun<'_>) -> Result<(), String> {
        let program = ensure_program(received, None)?;
        let receipt = scheduler("relay", true, &program, received)?;
        require_running(&receipt, "relay")?;
        await_relay_health(&receipt, &program, received)
    }
    fn await_relay_health(receipt: &TaskReceipt, program: &CheckedPath, received: &mut BackgroundRun<'_>) -> Result<(), String> {
        received.ready()?;
        if let Some(started) = receipt.started.as_ref().or_else(|| receipt.instances.first()) {
            // Startup is an observed state, not a guessed deadline. While this
            // actual new instance remains present, retain the setup worker and
            // wait for the relay's real health receipt. A stopped instance or
            // explicit blocker returns the actual partial result immediately.
            loop {
                received.ready()?;
                let report = crate::gate::read_checked()?;
                if relay_compatible(true, report.as_ref(), &received.program_path()) { return Ok(()); }
                if report.as_ref().is_some_and(|r| !r.is_stale() && r.version == dns_forwarder::RELAY_VERSION && !r.blockers.is_empty()) {
                    return Err(format!("PreparationIncomplete: created relay instance {started} reports blockers; preserve its task and inspect relay health"));
                }
                let observed = scheduler("relay", false, program, received)?;
                if !observed.instances.contains(started) {
                    return Err(format!("PreparationIncomplete: created relay instance {started} retired before healthy receiving; preserve its task"));
                }
                thread::park_timeout(Duration::from_millis(100));
            }
        }
        if received.relay_compatible()? { return Ok(()); }
        Err("UpdatePending: existing relay instance has no current-generation healthy receipt; selected retirement capability required".into())
    }

    /// True when a relay is installed and it is an older generation than this build
    /// ships - the case the user has to be told about, because the relay keeps
    /// running from `%ProgramData%` across reboots and a newer unlocker on its own
    /// changes nothing about it.
    ///
    /// Deliberately two cheap filesystem calls and no PowerShell: the menu redraws
    /// around this, and `is_enabled()` costs a few hundred milliseconds. The exe
    /// being there is what makes "no version file" mean "a relay from before
    /// versioning" rather than "no relay at all".
    pub fn relay_is_outdated() -> bool {
        checked_relay_outdated().unwrap_or(false)
    }

    /// A compatible, fresh relay report is a no-op. Replacing a different
    /// generation requires an instance-bound stop capability, not a file comparison.
    pub fn ensure_running() -> Result<(), String> {
        enable()
    }

    pub fn ensure_installed() -> Result<(), String> {
        ensure_installed_with_receiving().result
    }
    pub(crate) fn ensure_installed_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("ensureInstalled", |received| {
            ensure_program(received, None).map(|_| ())
        })
    }

    /// The single quiesce/mutate/restore owner used by a required generation
    /// update and Core's temporary native undo window. Retire failure never
    /// grants the primary. Once its grant may have been delivered, restoration
    /// is attempted even after primary failure/cancellation/unwinding.
    fn invoke_primary<T: serde::Serialize>(received: &mut BackgroundRun<'_>, primary: impl FnOnce(&mut BackgroundRun<'_>) -> T)
        -> (Option<T>, Vec<String>) {
        let mut errors = Vec::new();
        let value = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| primary(received))) {
            Ok(value) => {
                match serde_json::to_value(&value) {
                    Ok(actual) => received.primary_result = Some(actual),
                    Err(error) => errors.push(format!("primary outcome serialization: {error}; typed actual outcome retained")),
                }
                Some(value)
            }
            Err(payload) => {
                received.primary_result = Some(serde_json::json!({"execution":"unwound","nativeEffects":"unknown"}));
                received.primary_unwind = Some(payload);
                errors.push("primary callback unwound; actual native effects unknown".into());
                None
            }
        };
        if let Err(error) = received.record("primaryReturned") { errors.push(error); }
        (value, errors)
    }
    fn owned_transition<T: serde::Serialize>(received: &mut BackgroundRun<'_>, program: CheckedPath,
        desired: BackgroundDesired, primary: impl FnOnce(&mut BackgroundRun<'_>, &CheckedPath, &mut Option<CheckedPath>) -> T)
        -> (Option<T>, Result<CheckedPath, String>) {
        #[cfg(test)]
        let synthetic = received.scheduler_fixture.is_some();
        #[cfg(not(test))]
        let synthetic = false;
        let scheduler = if synthetic { None } else {
            match task_scheduler::Scheduler::connect() {
                Ok(scheduler) => Some(scheduler),
                Err(error) => return (None, Err(error)),
            }
        };
        let mut selected = if let Some(scheduler) = &scheduler {
            let programs = task_scheduler::Programs { managed: Some(&program), legacy: None };
            match scheduler.receive(&["relay", "watchdog"], &programs, received) {
                Ok(selected) => Some(selected),
                Err(error) => return (None, Err(error)),
            }
        } else { None };
        owned_transition_selected(received, program, desired, selected.as_mut(), None, false, primary)
    }
    /// One quiesce/update/restore body for normalized migration and ordinary
    /// image updates. A remains pinned; only an actual replacement result can
    /// supply B. The original restore capability is never rebound to B's ID.
    fn owned_transition_selected<T: serde::Serialize>(received: &mut BackgroundRun<'_>, program: CheckedPath,
        desired: BackgroundDesired, mut selected: Option<&mut task_scheduler::TaskSet<'_>>,
        legacy: Option<&windows_installation::LegacyBackgroundInput>, migration: bool,
        primary: impl FnOnce(&mut BackgroundRun<'_>, &CheckedPath, &mut Option<CheckedPath>) -> T)
        -> (Option<T>, Result<CheckedPath, String>) {
        let before = match received.task_state() {
            Ok(before) => before,
            Err(error) => return (None, Err(error)),
        };
        let programs = task_scheduler::Programs { managed: Some(&program), legacy };
        let restore_capability = if let Some(selected) = &selected {
            match selected.prepare_managed_restore(desired, &programs) {
                Ok(capability) => Some(capability),
                Err(error) => return (None, Err(error)),
            }
        } else { None };
        let mut replacement = None;
        let mut errors = Vec::new();
        let retired = if let Some(selected) = &mut selected {
            selected.retire(&programs, migration, received)
        } else { scheduler_action("shared", "retire", &program, received).map(|receipt| receipt.retired) };
        let retirement_returned = retired.is_ok();
        let mut primary_value = None;
        match retired {
            Ok(retired) => {
                if let Err(error) = received.effect(BackgroundEffect::TaskInstancesRetired(retired)) { errors.push(error); }
                if errors.is_empty() {
                    let quiescent = if let Some(selected) = &selected {
                        selected.quiescent(&programs)
                    } else { scheduler_action("shared", "quiescent", &program, received).map(|_| ()) };
                    if let Err(error) = quiescent { errors.push(error); }
                }
                // Cancellation may skip a primary not yet granted. Required
                // restoration still runs under the existing transition latch.
                if received.cancelled.load(Ordering::SeqCst) { received.cancellation_received = true; }
                else if errors.is_empty() {
                    let (value, primary_errors) = invoke_primary(received, |run| primary(run, &program, &mut replacement));
                    primary_value = value;
                    errors.extend(primary_errors);
                }
            }
            Err(error) => errors.push(error),
        }
        if received.restoration_pending || (migration && retirement_returned) {
            received.restoring = received.restoration_pending;
            let mut restoration_errors = Vec::new();
            // Fresh positive zero-instance receiving is required before Run.
            // An already-running qualified wanted role is preserved as a no-op;
            // absent-before roles are provisioned only by normal reconciliation.
            let active = replacement.as_ref().unwrap_or(&program);
            if let (Some(selected), Some(capability)) = (&selected, &restore_capability) {
                let active_programs = task_scheduler::Programs { managed: Some(active), legacy: None };
                let restored = if replacement.is_some() {
                    selected.restore_replaced(capability.prepared_roles(), desired, &active_programs, migration, received)
                } else if migration {
                    selected.restore_migrated(capability, desired, &active_programs, received)
                } else {
                    selected.restore_prepared(capability, desired, &active_programs, received)
                };
                if let Err(error) = restored { restoration_errors.push(error); }
            } else { for (was_present, wanted, role) in [
                (before.watchdog_enabled, desired.watchdog, "watchdog"),
                (before.relay_enabled, desired.relay, "relay"),
            ] {
                if was_present && wanted {
                    match scheduler_action(role, "resume", active, received)
                        .and_then(|receipt| require_running(&receipt, role)) {
                        Ok(()) => {}
                        Err(error) => restoration_errors.push(format!("{role}: {error}")),
                    }
                }
            } }
            received.restoring = false;
            let restoration = if restoration_errors.is_empty() { Ok(()) } else { Err(restoration_errors.join("; ")) };
            received.restoration_result = Some(restoration.clone());
            if restoration.is_ok() {
                received.restoration_pending = false;
            } else if let Err(error) = restoration { errors.push(format!("required restoration: {error}")); }
            if let Err(error) = received.record("wantedRoleRestorationReceivedHealthUnverified") { errors.push(error); }
        }
        if let Err(error) = received.ready() { errors.push(error); }
        drop(restore_capability);
        drop(programs);
        let program = replacement.unwrap_or(program);
        if errors.is_empty() { (primary_value, Ok(program)) }
        else { (primary_value, Err(errors.join("; "))) }
    }

    #[derive(serde::Serialize)]
    pub(crate) struct SuspendedBackgroundReceiving<T> {
        pub(crate) primary: Option<T>,
        pub(crate) background: BackgroundReceiving,
    }
    fn current_program_inputs(received: &BackgroundRun<'_>, scheduler: &task_scheduler::Scheduler)
        -> Result<(Option<CheckedPath>, Option<windows_installation::LegacyBackgroundInput>), String> {
        let locations = windows_installation::background_locations()?;
        let legacy = if scheduler.references_program(locations.legacy_program())? {
            Some(windows_installation::legacy_background_input(&locations)?
                .ok_or("OwnershipRequired: selected legacy program is absent")?)
        } else { None };
        let managed = if scheduler.references_program(locations.managed_program())? {
            Some(windows_installation::checked_background_path(received.lease()?, locations.managed_program(), PathKind::File)?)
        } else { None };
        Ok((managed, legacy))
    }
    /// Core owns the callback's exact result type and external file effects.
    /// The background owner retains the same typed value, its diagnostic form,
    /// and the independent restoration outcome; None means never invoked.
    pub(crate) fn with_suspended_background<T: serde::Serialize>(desired: BackgroundDesired,
        cancelled: &AtomicBool, image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>,
        primary: impl FnOnce() -> T) -> SuspendedBackgroundReceiving<T> {
        let mut actual_primary = None;
        let background = receiving("suspendForNativeClientWork", cancelled, Some(image), |received| {
            received.ready()?;
            let before = received.task_state()?;
            if !before.relay_enabled && !before.watchdog_enabled {
                // No background actor needs suspension. Unrelated leftover
                // program bytes are not a prerequisite for native client work.
                received.ready()?;
                let (actual, errors) = invoke_primary(received, |_| primary());
                actual_primary = actual;
                return if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) };
            }
            let scheduler = task_scheduler::Scheduler::connect()?;
            let (managed, legacy) = current_program_inputs(received, &scheduler)?;
            let programs = task_scheduler::Programs { managed: managed.as_ref(), legacy: legacy.as_ref() };
            let mut selected = scheduler.receive(&["relay", "watchdog"], &programs, received)?;
            let restore_capability = selected.prepare_managed_restore(desired, &programs)?;
            let mut errors = Vec::new();
            match selected.retire(&programs, false, received).and_then(|retired| {
                received.effect(BackgroundEffect::TaskInstancesRetired(retired))?;
                selected.quiescent(&programs)
            }) {
                Ok(()) => {
                    if received.cancelled.load(Ordering::SeqCst) { received.cancellation_received = true; }
                    else {
                        let (actual, primary_errors) = invoke_primary(received, |_| primary());
                        actual_primary = actual;
                        errors.extend(primary_errors);
                    }
                }
                Err(error) => errors.push(error),
            }
            if received.restoration_pending {
                received.restoring = true;
                let restoration = selected.restore_prepared(&restore_capability, desired, &programs, received);
                received.restoring = false;
                received.restoration_result = Some(restoration.clone());
                match restoration { Ok(()) => received.restoration_pending = false,
                    Err(error) => errors.push(format!("required original-role restoration: {error}")) }
                if let Err(error) = received.record("temporaryRoleRestorationReceived") { errors.push(error); }
            }
            if let Err(error) = received.ready() { errors.push(error); }
            if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
        });
        SuspendedBackgroundReceiving { primary: actual_primary, background }
    }

    fn generation_for_update(metadata: &Result<Option<u32>, String>, runtime: Option<u32>) -> Result<u32, String> {
        if let Some(version) = runtime.filter(|version| *version != 0) { return Ok(version); }
        match metadata {
            Ok(Some(version)) if *version != 0 => Ok(*version),
            Ok(None) => Err("OwnershipRequired: generation metadata is absent; no positive older-generation runtime proof".into()),
            Ok(Some(_)) => Err("OwnershipRequired: generation metadata is legacy-zero; no positive older-generation runtime proof".into()),
            Err(error) => Err(format!("OwnershipRequired: generation metadata unavailable and no positive runtime proof: {error}")),
        }
    }
    fn runtime_generation(report: Option<&crate::gate::Report>, program: &Path) -> Option<u32> {
        report.filter(|report| !report.is_stale() && report.version != 0 && Path::new(&report.exe) == program)
            .map(|report| report.version)
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CurrentImageDecision { ReuseCurrent, UpdateRequired }
    fn current_image_decision(metadata: &Result<Option<u32>, String>, runtime: Option<u32>, compatible: bool)
        -> Result<CurrentImageDecision, String> {
        if compatible { return Ok(CurrentImageDecision::ReuseCurrent); }
        let generation = generation_for_update(metadata, runtime)?;
        if generation > dns_forwarder::RELAY_VERSION {
            return Err("UpdatePending: installed generation is newer; downgrade was not admitted".into());
        }
        Ok(if generation == dns_forwarder::RELAY_VERSION { CurrentImageDecision::ReuseCurrent }
            else { CurrentImageDecision::UpdateRequired })
    }
    fn receive_current_image_decision(received: &mut BackgroundRun<'_>, program: &CheckedPath,
        selected: &task_scheduler::TaskSet<'_>, metadata: &Result<Option<u32>, String>) -> Result<CurrentImageDecision, String> {
        let binding = selected.managed_binding(program)?
            .ok_or("OccupiedStateHold: managed image has no current qualified task/program binding")?;
        binding.revalidate()?;
        require_owned_occupancy(OccupancyOwnership::CurrentManagedBinding)?;
        use sha2::Digest;
        let bytes = program.read_snapshot()?;
        binding.revalidate()?;
        received.effect(BackgroundEffect::CurrentProgramReceived { program_native_id: program.native_id(),
            sha256: hex::encode(sha2::Sha256::digest(&bytes)) })?;
        let report = crate::gate::read_checked()?;
        let runtime = runtime_generation(report.as_ref(), program.as_path());
        received.effect(BackgroundEffect::GenerationObserved { metadata: metadata.clone(), runtime })?;
        let compatible = received.relay_compatible()?;
        let decision = current_image_decision(metadata, runtime, compatible)?;
        if compatible { received.effect(BackgroundEffect::CompatibleNoop)?; }
        Ok(decision)
    }
    fn receive_version<'context>(received: &mut BackgroundRun<'context>) -> Result<dns_forwarder::VersionPlan<'context>, String> {
        match dns_forwarder::read_version_checked(received.context()) {
            Ok(plan) => {
                received.generation_reads.push(plan.evidence());
                received.record("generationReadReceived")?;
                Ok(plan)
            }
            Err(failure) => {
                let message = failure.to_string();
                received.generation_reads.push(metadata_failure_evidence(&failure));
                Err(match received.record("generationReadFailed") {
                    Ok(()) => message,
                    Err(retention) => format!("{message}; {retention}"),
                })
            }
        }
    }
    fn metadata_failure_evidence(failure: &windows_installation::MetadataFailure) -> serde_json::Value {
        serde_json::json!({"phase":failure.phase,"cause":failure.cause,
            "replaceResult":failure.replace_result,"evidence":failure.evidence})
    }
    fn record_generation(received: &mut BackgroundRun<'_>, plan: dns_forwarder::VersionPlan<'_>) -> Result<(), String> {
        received.effect(BackgroundEffect::GenerationWriteRequested)?;
        received.ready()?;
        match dns_forwarder::record_version_checked(plan) {
            Ok(evidence) => {
                received.generation_writes.push(evidence);
                received.record("generationWriteReceived")
            }
            Err(failure) => {
                let message = failure.to_string();
                received.generation_writes.push(metadata_failure_evidence(&failure));
                Err(match received.record("generationWriteFailed") {
                    Ok(()) => message,
                    Err(retention) => format!("{message}; {retention}"),
                })
            }
        }
    }
    fn revalidate_generation(received: &mut BackgroundRun<'_>, version: &dns_forwarder::VersionPlan<'_>) -> Result<(), String> {
        if let Err(error) = version.revalidate() {
            let message = error.to_string();
            received.generation_reads.push(metadata_failure_evidence(&error));
            return Err(match received.record("generationRevalidationFailed") {
                Ok(()) => message,
                Err(retention) => format!("{message}; {retention}"),
            });
        }
        Ok(())
    }
    fn apply_program_update(received: &mut BackgroundRun<'_>, program: &CheckedPath,
        source_lease: &windows_installation::BackgroundLease, same_bytes: bool,
        version: dns_forwarder::VersionPlan<'_>, replacement: &mut Option<CheckedPath>) -> Result<(), String> {
        source_lease.source_bytes()?;
        if !same_bytes {
            match windows_installation::background_replace_program(source_lease, program) {
                Ok(actual) => {
                    received.replacements.push(actual.evidence);
                    *replacement = Some(actual.program);
                    received.record("programReplacementReceived")?;
                }
                Err(failure) => {
                    let message = failure.to_string();
                    received.replacements.push(serde_json::json!({"phase":failure.phase,"cause":failure.cause,
                        "replaceResult":failure.replace_result,"evidence":failure.evidence}));
                    return Err(match received.record("programReplacementFailed") {
                        Ok(()) => message,
                        Err(retention) => format!("{message}; {retention}"),
                    });
                }
            }
        }
        source_lease.source_bytes()?;
        record_generation(received, version)
    }
    fn receive_copy_source(received: &mut BackgroundRun<'_>) -> Result<std::sync::Arc<windows_installation::BackgroundLease>, String> {
        received.ready()?;
        let image = received.image.as_ref().ok_or("source-selection hold: current image was not received")?
            .clone().map_err(|error| format!("source-selection hold: {error}"))?;
        let inputs = windows_installation::background_inputs_selected(
            received.program_directory.parent().ok_or("background ProgramData parent absent")?,
            &received.program_directory, image, &received.diagnostic.directory)?;
        let observation = inputs.source_observation()?;
        let context = windows_coordinator::receive_for_background(&inputs)
            .map_err(|cause| format!("{cause}; rejected source observation: {observation}"))?;
        // Same worker/thread, existing reentrant native mutex. The outer
        // namespace lease and version plan remain held; no context is cloned.
        let lease = std::sync::Arc::new(windows_installation::background_lease(inputs, context)
            .map_err(|cause| format!("{cause}; rejected source observation: {observation}"))?);
        received.source_leases.push(lease.clone());
        Ok(lease)
    }

    fn create_managed_image(received: &mut BackgroundRun<'_>, source_lease: &windows_installation::BackgroundLease) -> Result<CheckedPath, String> {
        let destination = received.program_path();
        let (source_native_id, bytes) = source_lease.source_capture()?;
        use sha2::Digest;
        let source_sha256 = hex::encode(sha2::Sha256::digest(bytes));
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                let existing = windows_installation::checked_background_path(source_lease, &destination, PathKind::File)?;
                if let Some(created) = &received.created_program {
                    created.guard.recheck()?;
                    if created.guard.native_id() != existing.native_id() || created.source_sha256 != source_sha256 {
                        return Err("OccupiedStateHold: live creation identity/source receiving differs".into());
                    }
                    require_owned_occupancy(OccupancyOwnership::LiveCreator)?;
                } else { require_owned_occupancy(OccupancyOwnership::Unproved)?; }
                if existing.read_snapshot()? != bytes {
                    return Err("OccupiedStateHold: same-live created image differs from its received source".into());
                }
                return Ok(existing);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("managed program observation: {error}")),
        }
        let directory = received.program_directory.clone();
        match fs::symlink_metadata(&directory) {
            Ok(_) => {
                if received.created_directory.is_none() { require_owned_occupancy(OccupancyOwnership::Unproved)?; }
                let created = received.created_directory.as_ref().ok_or("occupied directory has no creator guard")?;
                created.recheck()?;
                let current = windows_installation::checked_background_path(source_lease, &directory, PathKind::Directory)?;
                if current.native_id() != created.native_id() { return Err("OccupiedStateHold: created directory identity changed".into()); }
                require_owned_occupancy(OccupancyOwnership::LiveCreator)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                source_lease.source_bytes()?;
                received.effect(BackgroundEffect::DirectoryCreateRequested)?;
                received.ready()?;
                windows_installation::create_background_directory(source_lease, &directory)?;
                received.created_directory = Some(windows_installation::checked_background_path(source_lease, &directory, PathKind::Directory)?);
                received.effect(BackgroundEffect::DirectoryCreateReturnedSuccess)?;
            }
            Err(error) => return Err(format!("managed directory observation: {error}")),
        }
        let parent = windows_installation::checked_background_path(source_lease, &directory, PathKind::Directory)?;
        source_lease.source_bytes()?;
        received.effect(BackgroundEffect::ProgramCreateRequested)?;
        received.ready()?;
        let mut output = windows_installation::create_background_executable(source_lease, &destination)?;
        received.effect(BackgroundEffect::ProgramCreateReturnedSuccess)?;
        source_lease.source_bytes()?;
        output.write_all(bytes).and_then(|_| output.sync_all()).map_err(|error| format!("PreparationIncomplete: managed image write: {error}; preserve it"))?;
        drop(output);
        source_lease.source_bytes()?;
        let installed = windows_installation::checked_background_path(source_lease, &destination, PathKind::File)?;
        if installed.read_snapshot()?.as_slice() != bytes { return Err("PreparationIncomplete: new managed image readback differs".into()); }
        parent.recheck()?;
        received.created_program = Some(CreatedManagedProgram {
            guard: windows_installation::checked_background_path(source_lease, &destination, PathKind::File)?, source_sha256,
        });
        received.effect(BackgroundEffect::ProgramReadbackReceived { program: installed.as_path().to_path_buf(),
            program_native_id: installed.native_id(), source_native_id,
            sha256: hex::encode(sha2::Sha256::digest(bytes)), generation: dns_forwarder::RELAY_VERSION })?;
        Ok(installed)
    }

    fn migrate_legacy(received: &mut BackgroundRun<'_>, desired: BackgroundDesired,
        version: dns_forwarder::VersionPlan<'_>) -> Result<CheckedPath, String> {
        let locations = windows_installation::background_locations()?;
        let legacy = windows_installation::legacy_background_input(&locations)?
            .ok_or("OwnershipRequired: selected legacy task has no received legacy program")?;
        let scheduler = task_scheduler::Scheduler::connect()?;
        let existing = match fs::symlink_metadata(locations.managed_program()) {
            Ok(_) => Some(windows_installation::checked_background_path(received.lease()?, locations.managed_program(), PathKind::File)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("managed image inspection: {error}")),
        };
        let before = task_scheduler::Programs { managed: existing.as_ref(), legacy: Some(&legacy) };
        let mut selected = scheduler.receive(&["relay", "watchdog"], &before, received)?;
        if !selected.has_legacy() { return Err("ChangedInput: legacy migration association disappeared before preparation".into()); }
        drop(before);
        let metadata = version.value();
        let (managed, update) = match existing {
            Some(managed) => match receive_current_image_decision(received, &managed, &selected, &metadata)? {
                CurrentImageDecision::ReuseCurrent => (managed, None),
                CurrentImageDecision::UpdateRequired => {
                    let lease = receive_copy_source(received)?;
                    let same_bytes = managed.read_snapshot()?.as_slice() == lease.source_bytes()?;
                    revalidate_generation(received, &version)?;
                    (managed, Some((lease, same_bytes, version)))
                }
            },
            None => {
                let lease = receive_copy_source(received)?;
                let managed = create_managed_image(received, &lease)?;
                lease.source_bytes()?;
                record_generation(received, version)?;
                (managed, None)
            }
        };
        let programs = task_scheduler::Programs { managed: Some(&managed), legacy: Some(&legacy) };
        for lease in &received.source_leases { lease.source_bytes()?; }
        // All fallible definition updates/readbacks finish while OLD retained
        // instances continue. Neither a warning nor a path-only match is Ready.
        if let Err(error) = selected.update_paths(&programs, received) {
            let observed = scheduler.receive(&["relay", "watchdog"], &programs, received);
            return Err(match observed { Ok(_) => error, Err(observation) => format!("{error}; current mixed-state receiving: {observation}") });
        }
        drop(programs);
        if let Some((lease, _, version)) = &update {
            lease.source_bytes()?;
            revalidate_generation(received, version)?;
        }
        let (primary, outcome) = owned_transition_selected(received, managed, desired, Some(&mut selected), Some(&legacy), true,
            |run, program, replacement| match update {
                Some((lease, same_bytes, version)) => apply_program_update(run, program, &lease, same_bytes, version, replacement),
                None => Ok(()),
            });
        let program = outcome?;
        match primary {
            Some(Ok(())) => Ok(program),
            Some(Err(error)) => Err(error),
            None => Err("UpdatePending: association/update primary was not invoked; actual role restoration retained".into()),
        }
    }

    /// Receive the single protected installation owner. CREATE_NEW preserves
    /// any collision, and actual identity/bytes are independently read back
    /// before the scheduler may observe the executable. No source-byte mismatch
    /// can authorize stopping an existing task or overwriting its image.
    fn ensure_program(received: &mut BackgroundRun<'_>, desired: Option<BackgroundDesired>) -> Result<CheckedPath, String> {
        received.ready()?;
        // Receive the actual nonsecret generation leaf even on the no-op path.
        // This one plan, preimage and writer lease survive any chosen update.
        let version = receive_version(received)?;
        let metadata = version.value();
        let destination = received.program_path();
        let locations = windows_installation::background_locations()?;
        let scheduler = task_scheduler::Scheduler::connect()?;
        if scheduler.references_program(locations.legacy_program())? {
            let desired = match desired { Some(desired) => desired, None => {
                let before = received.task_state()?;
                BackgroundDesired { relay: before.relay_enabled, watchdog: before.watchdog_enabled }
            }};
            return migrate_legacy(received, desired, version);
        }
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                let installed = windows_installation::checked_background_path(received.lease()?, &destination, PathKind::File)?;
                let known = task_scheduler::Programs { managed: Some(&installed), legacy: None };
                let selected = scheduler.receive(&["relay", "watchdog"], &known, received)?;
                let decision = receive_current_image_decision(received, &installed, &selected, &metadata)?;
                drop(selected);
                drop(known);
                if decision == CurrentImageDecision::ReuseCurrent { return Ok(installed); }
                let before = received.task_state()?;
                let source_lease = receive_copy_source(received)?;
                let same_bytes = installed.read_snapshot()?.as_slice() == source_lease.source_bytes()?;
                revalidate_generation(received, &version)?;
                let desired = desired.unwrap_or(BackgroundDesired { relay: before.relay_enabled, watchdog: before.watchdog_enabled });
                let (primary, outcome) = owned_transition(received, installed, desired,
                    |run, program, replacement| apply_program_update(run, program, &source_lease, same_bytes, version, replacement));
                let program = outcome?;
                return match primary {
                    Some(Ok(())) => Ok(program),
                    Some(Err(error)) => Err(error),
                    None => Err("UpdatePending: executable update primary was not invoked; received roles were restored".into()),
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("background executable observation: {error}")),
        }
        let tasks = received.task_state()?;
        if tasks.relay_enabled || tasks.watchdog_enabled {
            return Err("OwnershipRequired: existing background task references an absent program; preserve the task".into());
        }
        let source_lease = receive_copy_source(received)?;
        let installed = create_managed_image(received, &source_lease)?;
        source_lease.source_bytes()?;
        record_generation(received, version)?;
        Ok(installed)
    }

    fn require_running(receipt: &TaskReceipt, role: &str) -> Result<(), String> {
        if !receipt.present || !receipt.compatible {
            return Err(format!("OwnershipRequired: {role} definition was not received"));
        }
        if receipt.instances.is_empty() {
            return Err(format!("UpdatePending: {role} definition exists without a running instance; restart requires selected instance ownership"));
        }
        if let Some(started) = &receipt.started {
            if !receipt.instances.contains(started) {
                return Err(format!("PreparationIncomplete: {role} created instance retired or changed before readback; preserve definition"));
            }
        } else if receipt.created {
            return Err(format!("PreparationIncomplete: {role} created definition has no actual run receipt; preserve definition"));
        }
        Ok(())
    }

    /// Existing compatible watchdog instances are a no-op; a fresh definition is
    /// registered create-only and run through its actual COM instance receipt.
    pub fn enable_watchdog() -> Result<(), String> {
        enable_watchdog_with_receiving().result
    }
    pub(crate) fn enable_watchdog_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("enableWatchdog", |received| {
            let program = ensure_program(received, None)?;
            let receipt = scheduler("watchdog", true, &program, received)?;
            require_running(&receipt, "watchdog")
        })
    }

    /// Preserve any task whose exact ownership and instance cannot be established.
    pub fn disable_watchdog() {
        if let Err(e) = disable_watchdog_checked() {
            eprintln!("{e}");
        }
    }

    pub(crate) fn disable_watchdog_checked() -> Result<(), String> {
        disable_watchdog_with_receiving().result
    }
    pub(crate) fn disable_watchdog_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("disableWatchdog", |received| disable_role("watchdog", received))
    }

    /// One full profile operation: the caller supplies both authoritative role
    /// values, including unchanged roles omitted from an Option-valued delta.
    pub(crate) fn reconcile_with_receiving(desired: BackgroundDesired, cancelled: &AtomicBool,
        image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>) -> BackgroundReceiving {
        receiving("reconcileBackgroundProfile", cancelled, Some(image), |received| {
            if desired.relay || desired.watchdog {
                let program = ensure_program(received, Some(desired))?;
                for (wanted, role) in [(desired.watchdog, "watchdog"), (desired.relay, "relay")] {
                    if wanted {
                        let started = scheduler(role, true, &program, received)?;
                        require_running(&started, role)?;
                        if role == "relay" { await_relay_health(&started, &program, received)?; }
                    } else {
                        disable_role(role, received)?;
                    }
                }
                Ok(())
            } else {
                // Independent roles settle independently; preserve both actual
                // outcomes if one definition cannot be qualified.
                let relay = disable_role("relay", received);
                let watchdog = disable_role("watchdog", received);
                match (relay, watchdog) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                    (Err(relay), Err(watchdog)) => Err(format!("relay: {relay}; watchdog: {watchdog}")),
                }
            }
        })
    }

    pub fn disable() -> Result<(), String> {
        disable_with_receiving().result
    }
    pub(crate) fn disable_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("disableRelay", |received| disable_role("relay", received))
    }
    fn disable_role(role: &str, received: &mut BackgroundRun<'_>) -> Result<(), String> {
        received.ready()?;
        let tasks = received.task_state()?;
        let present = match role { "relay" => tasks.relay_enabled, "watchdog" => tasks.watchdog_enabled,
            _ => return Err("invalid background role".into()) };
        if !present { return Ok(()); }
        let scheduler = task_scheduler::Scheduler::connect()?;
        let (managed, legacy) = current_program_inputs(received, &scheduler)?;
        let programs = task_scheduler::Programs { managed: managed.as_ref(), legacy: legacy.as_ref() };
        let retired = scheduler.receive(&[role], &programs, received)?.remove(&programs, received)?;
        received.effect(BackgroundEffect::TaskInstancesRetired(retired.retired))?;
        // The shared executable and diagnostic/version history stay preserved:
        // the other role may still need them and removing a task is no authority
        // to erase user diagnostics. No physical file deletion is claimed.
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn relay_process_stem_preserves_both_windows_query_contracts() {
            let filename = windows_installation::background_process_name();
            let stem = relay_process_name();
            assert!(!stem.is_empty());
            assert_eq!(format!("IMAGENAME eq {stem}.exe"), format!("IMAGENAME eq {filename}"),
                "tasklist must receive the canonical full filename, not a second extension");
            assert_ne!(stem, filename, "Get-Process must receive the stem instead of the full filename");
            assert_eq!(Path::new(filename).file_stem().and_then(|name| name.to_str()), Some(stem.as_str()),
                "egress must keep its documented Get-Process stem contract");
        }

        #[test]
        #[ignore = "read-only existing relay health probe; requires its running task/fresh report; never repairs or restarts"]
        fn native_existing_relay_health_uses_canonical_process_stem() {
            let script = format!("$ErrorActionPreference='Stop'; [int](Get-ScheduledTask -TaskPath '\\' -TaskName '{}').State | ConvertTo-Json -Compress; 'AG_END'", TASK_NAME);
            let state = checked_json_with_cancel(&script, &AtomicBool::new(false)).expect("existing relay task state must be readable");
            assert_eq!(state.as_u64(), Some(4), "existing relay task must already be running");
            let report = crate::gate::read_checked().expect("relay report must be readable").expect("existing report required");
            assert!(!report.is_stale(), "existing report must already be fresh");
            assert!(is_enabled(), "existing relay task must be present");
            assert!(is_running(), "corrected canonical process query must find the already-running relay image");
            assert!(checked_relay_compatible().expect("existing relay compatibility must be readable"));
            println!("existing running task/fresh report and canonical process-name health received; no repair/restart performed");
        }

        #[test]
        fn existing_managed_namespace_requires_owned_binding_not_appearance() {
            assert!(require_owned_occupancy(OccupancyOwnership::Unproved).is_err(), "empty protected directory or same-hash executable is not ownership");
            assert!(require_owned_occupancy(OccupancyOwnership::CurrentManagedBinding).is_ok());
            assert!(require_owned_occupancy(OccupancyOwnership::LiveCreator).is_ok());
        }

        fn fixture_receipt(running: bool) -> TaskReceipt {
            TaskReceipt { present: true, compatible: true,
                instances: if running { vec!["{11111111-1111-4111-8111-111111111111}".into()] } else { Vec::new() },
                created: false, started: if running { Some("{11111111-1111-4111-8111-111111111111}".into()) } else { None },
                retired: Vec::new(), roles_present: vec![TASK_NAME.into(), WATCHDOG_TASK_NAME.into()] }
        }

        #[test]
        #[ignore = "requires the explicit owned private AG_BACKGROUND_FIXTURE_ROOT; executes only a new controlled helper"]
        fn synthetic_native_file_capture_receiving() {
            let directory = PathBuf::from(env::var_os("AG_BACKGROUND_FIXTURE_ROOT").expect("explicit owned fixture root required"));
            let cancelled = AtomicBool::new(false);
            let mut received = BackgroundRun {
                received: empty_receiving("syntheticNativeCaptureOnly"), cancelled: &cancelled,
                diagnostic: BackgroundDiagnostic::begin("syntheticNativeCaptureOnly", directory.clone(), None).unwrap(),
                lease: None, program_directory: directory.clone(), selected_program: directory.join("synthetic-unused-program"), primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None, source_leases: Vec::new(), scheduler_fixture: None,
            };
            // Exceeds Core's 640-character presentation limit. This helper does
            // not connect to Task Scheduler or change product/user state.
            const SCRIPT: &str = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $request=[Console]::In.ReadLine(); if($request -cne '{}'){throw 'fixture grant mismatch'}; [Console]::Out.Write(('X'*641)); [Console]::Error.Write(('Y'*641)); exit 23";
            let outcome = native_output(SCRIPT, Some(b"{}"), None, "synthetic-capture", true, false, &mut received);
            assert!(outcome.is_err());
            let actual = &received.native[0];
            assert!(actual.started && actual.exit_observed);
            assert_eq!(actual.exit_code, Some(23));
            assert_eq!(actual.stdout, vec![b'X'; 641]);
            assert_eq!(actual.stderr, vec![b'Y'; 641]);
            assert!(actual.stdout_file.as_ref().unwrap().sha256.is_some());
            assert!(actual.stderr_file.as_ref().unwrap().sha256.is_some());
            received.received.result = outcome.map(|_| ());
            let reference = received.diagnostic.finish(&received.received, None).unwrap();
            assert!(reference.sha256.is_some());
            println!("controlled helper actual exit/capture/terminal retained at {}", reference.path.display());
        }

        #[test]
        #[ignore = "requires explicit owned private AG_BACKGROUND_FIXTURE_ROOT; synthetic source only"]
        fn source_capture_revalidation_failure_retains_actual_observation_and_cause() {
            let directory = PathBuf::from(env::var_os("AG_BACKGROUND_FIXTURE_ROOT").expect("explicit owned fixture root required"));
            let source = directory.join(format!("source-{}.exe", windows_installation::new_request_id().unwrap()));
            eprintln!("OWN_BACKGROUND_SOURCE_CAPTURE_FIXTURE {}", source.display());
            let mut created = fs::OpenOptions::new().write(true).create_new(true).open(&source).unwrap();
            created.write_all(b"MZ controlled source; never executed").unwrap();
            created.sync_all().unwrap(); drop(created);
            let image = std::sync::Arc::new(windows_coordinator::process_identity::CurrentImage::synthetic(&source).unwrap());
            for terminal_failure in [false, true] {
                let cancelled = AtomicBool::new(false);
                let mut run = BackgroundRun {
                    received: empty_receiving("syntheticSourceCaptureFailure"), cancelled: &cancelled,
                    diagnostic: BackgroundDiagnostic::begin("syntheticSourceCaptureFailure", directory.clone(), None).unwrap(),
                    lease: None, program_directory: directory.join("unused-program"), selected_program: directory.join("unused-program/ag_dns.exe"),
                    primary_unwind: None, restoring: false, created_directory: None, created_program: None,
                    image: Some(Ok(image.clone())), source_leases: Vec::new(), scheduler_fixture: None,
                };
                windows_installation::fail_next_source_capture_revalidation();
                let cause = match receive_copy_source(&mut run) { Ok(_) => panic!("controlled source failure missing"), Err(cause) => cause };
                assert!(cause.starts_with("synthetic source revalidation failure"));
                for key in ["nativeId=", "sha256=", "bytes=", "metadataSha256="] { assert!(cause.contains(key)); }
                assert!(run.received.effects.is_empty() && run.received.replacements.is_empty() && run.received.native.is_empty());
                assert!(run.received.primary_result.is_none());
                run.received.result = Err(cause.clone());
                if terminal_failure { run.diagnostic.directory = directory.join("missing-terminal-parent"); }
                finalize_receiving(&mut run);
                let actual = run.received.result.as_ref().unwrap_err();
                assert!(actual.starts_with(&cause));
                if terminal_failure {
                    assert!(!run.received.persistence_errors.is_empty());
                    assert!(actual.contains("diagnostic terminal retention"));
                } else {
                    let terminal = run.received.diagnostic.as_ref().unwrap();
                    let value: serde_json::Value = serde_json::from_slice(&fs::read(&terminal.path).unwrap()).unwrap();
                    assert_eq!(value["receiving"]["result"]["Err"], cause);
                    assert!(run.received.persistence_errors.is_empty());
                }
                assert!(run.received.effects.is_empty() && run.received.replacements.is_empty() && run.received.native.is_empty());
                assert!(run.received.primary_result.is_none());
            }
        }

        #[test]
        #[ignore = "requires an explicit AG_BACKGROUND_FIXTURE_ROOT owned synthetic directory; never uses product tasks or log_dir"]
        fn synthetic_transition_failure_and_cancellation_receiving() {
            let root = PathBuf::from(env::var_os("AG_BACKGROUND_FIXTURE_ROOT").expect("explicit owned fixture root required"));
            windows_installation::WindowsLocalPath::parse(root.as_os_str()).unwrap();
            for case in ["cancel-before-grant", "cancel-after-retire", "primary-and-restore-fail", "partial-retire-fails", "sink-after-stop", "sink-after-primary"] {
                let directory = root.clone();
                let mut output = windows_installation::create_background_diagnostic_file(&directory.join(format!("{}-{case}-synthetic-file-identity.bin", windows_installation::new_request_id().unwrap())), None).unwrap();
                output.file.write_all(b"synthetic file identity; never executed and grants no runtime authority").unwrap();
                output.file.sync_all().unwrap();
                let path = output.path.clone();
                drop(output.file);
                let program = CheckedPath::open(&path, PathKind::File, PathPurpose::ReplaceSource).unwrap();
                let cancelled = AtomicBool::new(case == "cancel-before-grant");
                let mut replies = std::collections::VecDeque::new();
                if case == "partial-retire-fails" {
                    replies.push_back(Err("synthetic relay retired, watchdog Stop returned failure".into()));
                    replies.push_back(Ok(fixture_receipt(true)));
                    replies.push_back(Ok(fixture_receipt(true)));
                } else if case != "cancel-before-grant" {
                    replies.push_back(Ok(fixture_receipt(false)));
                    if case != "sink-after-stop" { replies.push_back(Ok(fixture_receipt(false))); }
                    replies.push_back(if case == "primary-and-restore-fail" { Err("synthetic watchdog restore failed".into()) } else { Ok(fixture_receipt(true)) });
                    replies.push_back(Ok(fixture_receipt(true)));
                }
                let mut received = BackgroundRun {
                    received: empty_receiving("syntheticTransitionModelOnly"), cancelled: &cancelled,
                    diagnostic: BackgroundDiagnostic::begin("syntheticTransitionModelOnly", directory.clone(), None).unwrap(),
                    lease: None, program_directory: directory.clone(), selected_program: path.clone(), primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None, source_leases: Vec::new(),
                    scheduler_fixture: Some(SchedulerFixture { relay_present: true, watchdog_present: true,
                        cancel_after_retire: case == "cancel-after-retire", fail_after_retire: case == "sink-after-stop", replies, calls: Vec::new(), program_native_ids: Vec::new() }),
                };
                let first_backup = directory.join(format!("{}-first-backup-is-directory", windows_installation::new_request_id().unwrap()));
                fs::create_dir(&first_backup).unwrap();
                let mut invoked = 0;
                let (primary, outcome) = owned_transition(&mut received, program,
                    BackgroundDesired { relay: true, watchdog: true }, |run, _, _| {
                        invoked += 1;
                        if case == "sink-after-primary" { run.diagnostic.injected_write_failure = true; }
                        let error = fs::write(&first_backup, b"first native file backup").unwrap_err();
                        Err::<usize, String>(format!("actual first-file I/O failure: {error}"))
                    });
                assert!(outcome.is_err(), "{case}");
                let calls = &received.scheduler_fixture.as_ref().unwrap().calls;
                if case == "cancel-before-grant" {
                    assert_eq!(invoked, 0);
                    assert!(primary.is_none());
                    assert!(calls.is_empty());
                    assert!(received.restoration_result.is_none());
                    assert!(!received.restoration_pending);
                } else {
                    assert_eq!(calls.iter().filter(|(_, action)| action == "resume").count(), 2, "both wanted roles receive restoration even after an earlier failure");
                    assert!(received.scheduler_fixture.as_ref().unwrap().replies.is_empty());
                    if case == "primary-and-restore-fail" {
                        assert_eq!(invoked, 1);
                        assert!(first_backup.is_dir());
                        assert!(primary.as_ref().unwrap().as_ref().unwrap_err().starts_with("actual first-file I/O failure: "));
                        assert_eq!(serde_json::to_value(&primary).unwrap(), serde_json::to_value(&received.primary_result).unwrap());
                        assert!(received.primary_result.as_ref().unwrap().get("Err").is_some());
                        assert!(received.restoration_result.as_ref().unwrap().is_err());
                        assert!(received.restoration_pending);
                    } else if case == "sink-after-primary" {
                        assert_eq!(invoked, 1);
                        assert!(primary.as_ref().unwrap().is_err());
                        assert!(received.restoration_result.as_ref().unwrap().is_ok());
                        assert!(!received.restoration_pending);
                    } else {
                        assert_eq!(invoked, 0);
                        assert!(primary.is_none());
                        assert!(received.restoration_result.as_ref().unwrap().is_ok());
                        assert!(!received.restoration_pending);
                    }
                }
                if case.starts_with("cancel-") { assert!(received.cancellation_received); }
                if case.starts_with("sink-") {
                    assert!(!received.persistence_errors.is_empty());
                    assert!(received.task_events.iter().filter(|event| matches!(event, task_scheduler::Event::Call(call) if call.operation == "syntheticRestoreRun")).count() == 2);
                    assert!(received.ready().is_err(), "independent next effect remains blocked after safe restoration");
                }
                received.received.result = outcome.map(|_| ());
                let reference = received.diagnostic.finish(&received.received, None).unwrap();
                assert!(reference.sha256.is_some());
                println!("{case}: synthetic transport only; owned terminal retained at {}", reference.path.display());
            }
        }

        #[test]
        fn current_image_decision_reuses_compatible_owned_baseline_without_source() {
            // This SAME decision is called for mixed and fully Managed task
            // sets. Desired GUI bytes are deliberately not an authority input.
            for metadata in [Ok(Some(dns_forwarder::RELAY_VERSION)), Ok(Some(44))] {
                let decision = current_image_decision(&metadata, None, false).unwrap();
                assert_eq!(decision, if metadata == Ok(Some(dns_forwarder::RELAY_VERSION)) {
                    CurrentImageDecision::ReuseCurrent
                } else { CurrentImageDecision::UpdateRequired });
            }
            assert_eq!(current_image_decision(&Ok(None), Some(dns_forwarder::RELAY_VERSION), false).unwrap(), CurrentImageDecision::ReuseCurrent);
            assert_eq!(current_image_decision(&Err("unavailable synthetic metadata".into()), None, true).unwrap(), CurrentImageDecision::ReuseCurrent);
            for unknown in [Ok(None), Ok(Some(0)), Err("malformed synthetic metadata".into())] {
                assert!(current_image_decision(&unknown, None, false).is_err());
            }
            assert!(current_image_decision(&Ok(Some(dns_forwarder::RELAY_VERSION + 1)), None, false).is_err());
            assert!(require_owned_occupancy(OccupancyOwnership::Unproved).is_err(), "generation/equal bytes never adopt an occupied image");
        }

        #[test]
        #[ignore = "requires explicit owned AG_BACKGROUND_FIXTURE_ROOT; synthetic Scheduler only, no product tasks/programs"]
        fn synthetic_current_image_reuse_and_update_receiving() {
            let root = PathBuf::from(env::var_os("AG_BACKGROUND_FIXTURE_ROOT").expect("explicit owned fixture root required"));
            windows_installation::WindowsLocalPath::parse(root.as_os_str()).unwrap();
            for update in [false, true] {
                let decision = current_image_decision(&Ok(Some(if update { 44 } else { dns_forwarder::RELAY_VERSION })), None, false).unwrap();
                let make_program = |bytes: &[u8]| {
                    let path = root.join(format!("{}-current-image-model.bin", windows_installation::new_request_id().unwrap()));
                    let mut output = windows_installation::create_background_diagnostic_file(&path, None).unwrap();
                    output.file.write_all(bytes).unwrap(); output.file.sync_all().unwrap(); drop(output.file);
                    CheckedPath::open(&path, PathKind::File, PathPurpose::ReplaceSource).unwrap()
                };
                let program = make_program(b"owned synthetic A; never executable");
                let baseline_id = program.native_id();
                let mut source_receives = 0;
                let desired_program = if decision == CurrentImageDecision::UpdateRequired {
                    source_receives += 1;
                    Some(make_program(b"different desired synthetic B; never executable"))
                } else { None };
                let expected_id = desired_program.as_ref().map(|program| program.native_id()).unwrap_or_else(|| baseline_id.clone());
                let cancelled = AtomicBool::new(false);
                let replies = [Ok(fixture_receipt(false)), Ok(fixture_receipt(false)), Ok(fixture_receipt(true)), Ok(fixture_receipt(true))].into_iter().collect();
                let mut received = BackgroundRun {
                    received: empty_receiving("syntheticCurrentImageModelOnly"), cancelled: &cancelled,
                    diagnostic: BackgroundDiagnostic::begin("syntheticCurrentImageModelOnly", root.clone(), None).unwrap(),
                    lease: None, program_directory: root.clone(), selected_program: program.as_path().to_path_buf(),
                    primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None, source_leases: Vec::new(),
                    scheduler_fixture: Some(SchedulerFixture { relay_present: true, watchdog_present: true, cancel_after_retire: false,
                        fail_after_retire: false, replies, calls: Vec::new(), program_native_ids: Vec::new() }),
                };
                let mut replacements = 0;
                let (primary, outcome) = owned_transition_selected(&mut received, program,
                    BackgroundDesired { relay: true, watchdog: true }, None, None, true, |_, _, replacement| {
                        if let Some(actual) = desired_program { replacements += 1; *replacement = Some(actual); }
                        Ok::<(), String>(())
                    });
                let active = outcome.unwrap();
                assert!(matches!(primary, Some(Ok(()))));
                assert_eq!(active.native_id(), expected_id);
                assert_eq!((source_receives, replacements), if update { (1, 1) } else { (0, 0) });
                assert!(received.generation_writes.is_empty(), "the model never writes real version metadata");
                let fixture = received.scheduler_fixture.as_ref().unwrap();
                assert_eq!(fixture.calls, [("shared".into(), "retire".into()), ("shared".into(), "quiescent".into()),
                    ("watchdog".into(), "resume".into()), ("relay".into(), "resume".into())]);
                assert_eq!(fixture.program_native_ids, [baseline_id.clone(), baseline_id, expected_id.clone(), expected_id]);
                assert!(fixture.replies.is_empty());
                assert!(received.restoration_result.as_ref().unwrap().is_ok() && !received.restoration_pending);
                received.received.result = Ok(());
                received.diagnostic.finish(&received.received, None).unwrap();
                println!("{}: one modeled retirement cycle and both-role receiving on actual selected fixture pin; no native image replacement", if update { "UpdateRequired" } else { "ReuseCurrent" });
            }
        }

        #[test]
        fn generation_never_promotes_missing_metadata_to_old_runtime_authority() {
            assert!(generation_for_update(&Ok(None), None).is_err());
            assert!(generation_for_update(&Err("malformed synthetic metadata".into()), None).is_err());
            assert_eq!(generation_for_update(&Ok(Some(44)), None).unwrap(), 44);
            assert_eq!(generation_for_update(&Ok(Some(45)), Some(44)).unwrap(), 44);
            assert_eq!(generation_for_update(&Err("malformed synthetic metadata".into()), Some(44)).unwrap(), 44);
            assert!(generation_for_update(&Ok(Some(0)), Some(0)).is_err());
            let expected = Path::new("synthetic-program");
            let mut report = crate::gate::Report { at: u64::MAX, version: 44, exe: "synthetic-program".into(), ..Default::default() };
            assert_eq!(runtime_generation(Some(&report), expected), Some(44));
            report.exe = "different-program".into();
            assert_eq!(runtime_generation(Some(&report), expected), None);
            report.exe = "synthetic-program".into();
            report.at = 0;
            assert_eq!(runtime_generation(Some(&report), expected), None);
        }

        #[test]
        fn created_task_requires_its_actual_running_instance_receipt() {
            let mut receipt = TaskReceipt { present: true, compatible: true,
                instances: vec!["new-instance".into()], created: true, started: Some("new-instance".into()), retired: Vec::new(), roles_present: Vec::new() };
            assert!(require_running(&receipt, "relay").is_ok());
            receipt.started = Some("retired-instance".into());
            assert!(require_running(&receipt, "relay").is_err());
            receipt.started = None;
            assert!(require_running(&receipt, "relay").is_err());
            receipt.created = false;
            assert!(require_running(&receipt, "relay").is_ok());
            receipt.instances.clear();
            assert!(require_running(&receipt, "relay").is_err());
            receipt.instances.push("existing-instance".into());
            receipt.compatible = false;
            assert!(require_running(&receipt, "relay").is_err());
        }

        #[test]
        fn scheduler_receipt_missing_fields_do_not_weaken_the_guard() {
            let receipt = serde_json::json!({"present":true,"compatible":true,"instances":["instance"],"created":false,"started":null,"retired":[],"rolesPresent":[]});
            assert!(serde_json::from_value::<TaskReceipt>(receipt.clone()).is_ok());
            for key in ["present", "compatible", "instances", "created", "started", "retired", "rolesPresent"] {
                let mut incomplete = receipt.clone();
                incomplete.as_object_mut().unwrap().remove(key);
                assert!(serde_json::from_value::<TaskReceipt>(incomplete).is_err(), "missing {key}");
            }
            assert!(serde_json::from_value::<TaskReceipt>(serde_json::json!({})).is_err());
        }

        #[test]
        fn relay_noop_requires_fresh_matching_version_and_executable() {
            let expected = Path::new("fixture-executable");
            let mut report = crate::gate::Report { at: u64::MAX, version: dns_forwarder::RELAY_VERSION,
                exe: "fixture-executable".into(), ..Default::default() };
            assert!(relay_compatible(true, Some(&report), expected));
            assert!(!relay_compatible(false, Some(&report), expected));
            assert!(!relay_compatible(true, None, expected));
            report.version = 0;
            assert!(!relay_compatible(true, Some(&report), expected));
            report.version = dns_forwarder::RELAY_VERSION;
            report.exe = "unrelated-executable".into();
            assert!(!relay_compatible(true, Some(&report), expected));
            report.exe = "fixture-executable".into();
            report.at = 0;
            assert!(!relay_compatible(true, Some(&report), expected));
        }

        #[test]
        fn checked_native_wire_rejects_missing_or_malformed_data() {
            assert_eq!(parse_checked_json(b"[]\r\nAG_END\r\n").unwrap(), serde_json::json!([]));
            assert!(parse_checked_json(b"").is_err());
            assert!(parse_checked_json(b"[]").is_err());
            assert!(parse_checked_json(b"[\nAG_END").is_err());
            assert!(parse_checked_json(b"null\nAG_END").unwrap().as_array().is_none());
            assert!(parse_checked_json(&[0xff]).is_err());
        }

        /// A name nothing could have registered must read as absent — i.e. a
        /// non-zero exit from `schtasks` is "no such task", not "the query
        /// failed". Deterministic on any machine.
        #[test]
        fn a_task_that_cannot_exist_reads_as_absent() {
            assert!(!task_exists("AG Unlocker no-such-task 4f2b9c"));
        }

        /// Live: `schtasks` and PowerShell must give the same answer for the two
        /// real task names.
        ///
        /// The point of the swap is speed (35 ms against 830 ms, and it is asked
        /// twice per status refresh) and speed is only worth having if the answer
        /// is the same one — a reader that silently says "no task" would draw both
        /// switches off on a machine where they are on. Ignored because it can
        /// only assert anything on a machine that has actually installed the
        /// relay:
        ///
        ///     cargo test schtasks_and_powershell_agree -- --ignored --nocapture
        #[test]
        #[ignore = "needs the relay/watchdog tasks registered on this machine"]
        fn schtasks_and_powershell_agree_about_the_tasks() {
            for name in [TASK_NAME, WATCHDOG_TASK_NAME] {
                let via_ps = powershell(&format!(
                    "if (Get-ScheduledTask -TaskName '{}' -ErrorAction SilentlyContinue) \
                     {{ 'yes' }} else {{ 'no' }}",
                    name
                ))
                .map_or(false, |o| {
                    String::from_utf8_lossy(&o.stdout).trim() == "yes"
                });
                let via_schtasks = task_exists(name);
                println!("{name}: schtasks={via_schtasks} powershell={via_ps}");
                assert_eq!(via_schtasks, via_ps, "readers disagree about {name}");
            }
        }

        /// The exe must not sit under the user profile: a scheduled task cannot
        /// launch anything from there on a machine with anti-persistence
        /// heuristics.
        #[test]
        fn the_relay_is_installed_outside_the_user_profile() {
            let exe = installed_exe().unwrap();
            assert_eq!(exe.parent(), Some(install_dir().unwrap().as_path()));
            let locations = windows_installation::background_locations().unwrap();
            assert!(exe.starts_with(locations.managed_root()), "got {}", exe.display());

            if let Ok(local) = env::var("LOCALAPPDATA") {
                assert!(
                    !exe.starts_with(&local),
                    "the task would refuse to start it"
                );
            }
        }

        /// The log goes the other way round - the relay runs unelevated and cannot
        /// write next to an exe an administrator installed.
        #[test]
        fn the_log_stays_in_the_user_profile() {
            let log = dns_forwarder::log_path();
            let local = env::var("LOCALAPPDATA").unwrap_or_default();
            assert!(!local.is_empty());
            assert!(log.starts_with(&local), "got {}", log.display());
            assert_eq!(log.parent(), Some(dns_forwarder::log_dir().as_path()));
            assert_ne!(log.parent(), Some(install_dir().unwrap().as_path()));
        }
    }
}

// Linux: phase 2 is the **proxy route**, not the DNS relay. This runs the local
// CONNECT proxy (`proxy::run`, via `--proxy`) as a systemd **user** unit - no
// root, no `:53` listener, so systemd-resolved is never touched. The DNS relay
// (phase 5) would be a separate, privileged story; this is deliberately the
// unprivileged half that already lifts the region gate through a permitted exit.
#[cfg(not(target_os = "windows"))]
mod unix_impl {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use super::{PROXY_FLAG, WATCHDOG_FLAG};

    const UNIT_NAME: &str = "ag-unlocker-proxy.service";
    const WATCHDOG_UNIT_NAME: &str = "ag-unlocker-watchdog.service";

    fn home() -> String {
        std::env::var("HOME").unwrap_or_default()
    }

    fn xdg(var: &str, default_suffix: &str) -> PathBuf {
        let base = std::env::var(var)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("{}/{}", home(), default_suffix));
        PathBuf::from(base)
    }

    /// The proxy's own copy of the exe, under the XDG data dir - a user unit needs
    /// no root, so unlike Windows there is no `%ProgramData%` anti-persistence
    /// dance.
    pub fn install_dir() -> PathBuf {
        xdg("XDG_DATA_HOME", ".local/share").join("agunlocker")
    }

    pub fn installed_exe() -> PathBuf {
        install_dir().join("ag_proxy")
    }

    fn unit_path() -> PathBuf {
        xdg("XDG_CONFIG_HOME", ".config")
            .join("systemd/user")
            .join(UNIT_NAME)
    }

    fn watchdog_unit_path() -> PathBuf {
        xdg("XDG_CONFIG_HOME", ".config")
            .join("systemd/user")
            .join(WATCHDOG_UNIT_NAME)
    }

    /// Runs `systemctl --user ...`; true on success. Best-effort: a machine
    /// without a user systemd manager (rare on a desktop) just fails the enable.
    fn systemctl(args: &[&str]) -> bool {
        Command::new("systemctl")
            .arg("--user")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// The unit file existing is what "enabled" means here.
    pub fn is_enabled() -> bool {
        unit_path().exists()
    }

    /// The auto-patch watcher is a user unit of its own, beside the proxy's: the
    /// switch must be able to stand without the 400 bypass (it is the whole
    /// reason `ensure_installed` exists), and an update that replaces
    /// `language_server` under a running Antigravity is as real here as on
    /// Windows. The unit file existing is what "enabled" means, as for the proxy.
    pub fn is_watchdog_enabled() -> bool {
        watchdog_unit_path().exists()
    }

    pub fn is_running() -> bool {
        Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", UNIT_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// No versioned relay on Linux, so nothing to call outdated.
    pub fn relay_is_outdated() -> bool {
        false
    }

    /// Installs the exe under the XDG data dir, writes a systemd **user** unit that
    /// runs it with `--proxy`, and starts it. No root: `systemctl --user` targets
    /// the caller's own session manager, which is why the whole Linux flow runs
    /// unprivileged (and "Run as a Program" works without a password prompt).
    pub fn ensure_running() -> Result<(), String> {
        let replaced = install_copy()?;

        let up = unit_path();
        if let Some(p) = up.parent() {
            fs::create_dir_all(p).map_err(|e| format!("не создать {}: {}", p.display(), e))?;
        }
        // The window finds the service's `gate.json` through `log_dir()`, which
        // follows `XDG_DATA_HOME`. The systemd user manager does not always carry
        // the desktop session's value, and a service writing into a different
        // directory than the window reads leaves the card on «Служба запускается»
        // for good - so the unit is given the directory the window uses.
        let unit = unit_text("Antigravity Unlocker local proxy", PROXY_FLAG);
        // A unit from an older build lacks the data-dir line; running on under
        // it keeps the service writing where the window does not look.
        let unit_changed = fs::read_to_string(&up).map_or(true, |old| old != unit);
        fs::write(&up, unit).map_err(|e| format!("не записать юнит: {}", e))?;

        systemctl(&["daemon-reload"]);
        if !systemctl(&["enable", "--now", UNIT_NAME]) {
            return Err("не удалось запустить systemd-юнит (systemctl --user)".to_string());
        }
        // `enable --now` leaves a unit that is already running alone, so a copy
        // just replaced would sit unused until the next login.
        if (replaced || unit_changed) && !systemctl(&["restart", UNIT_NAME]) {
            return Err(
                "новая версия прокси записана, но служба не перезапустилась (systemctl --user)"
                    .to_string(),
            );
        }
        // The watcher runs the same copy: left on the old inode it would keep
        // the previous version's patch routines until the next login.
        if replaced && is_watchdog_enabled() {
            systemctl(&["restart", WATCHDOG_UNIT_NAME]);
        }
        Ok(())
    }

    /// A user unit running the installed copy with `flag`.
    fn unit_text(description: &str, flag: &str) -> String {
        let data_home = crate::dns_forwarder::log_dir()
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%");
        format!(
            "[Unit]\n\
             Description={description}\n\
             After=default.target\n\n\
             [Service]\n\
             Environment=\"XDG_DATA_HOME={data_home}\"\n\
             ExecStart={exe} {flag}\n\
             Restart=on-failure\n\
             RestartSec=5\n\n\
             [Install]\n\
             WantedBy=default.target\n",
            exe = installed_exe().display(),
        )
    }

    /// Puts this exe where the units run it from. True when the copy on disk
    /// changed (a unit already running it then has to be restarted).
    fn install_copy() -> Result<bool, String> {
        let src = std::env::current_exe().map_err(|e| format!("нет пути к exe: {}", e))?;
        let dir = install_dir();
        let exe = installed_exe();
        fs::create_dir_all(&dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
        // Copy self so the unit survives the download folder being moved/removed.
        //
        // Never *over* the installed copy: Linux will not open a file a process
        // is executing for writing - ETXTBSY, «Text file busy (os error 26)» -
        // and that is exactly the state every upgrade finds, the previous
        // version's unit being up. A new file beside it renamed over the name is
        // allowed: the running process keeps the old inode, the name now points at
        // the new one, and the restart below starts it. Skipped when the bytes are
        // already the same, so switching the bypass on again does not cut the
        // tunnels a running proxy is carrying.
        let replaced = src != exe && !same_contents(&src, &exe);
        if replaced {
            use std::os::unix::fs::PermissionsExt;
            let fresh = dir.join(".ag_proxy.new");
            fs::copy(&src, &fresh).map_err(|e| format!("копия exe: {}", e))?;
            let _ = fs::set_permissions(&fresh, fs::Permissions::from_mode(0o755));
            fs::rename(&fresh, &exe).map_err(|e| {
                let _ = fs::remove_file(&fresh);
                format!("замена exe: {}", e)
            })?;
        }
        Ok(replaced)
    }

    /// Whether two files hold the same bytes. Unreadable counts as different, so
    /// the copy is attempted and says what went wrong.
    fn same_contents(a: &std::path::Path, b: &std::path::Path) -> bool {
        match (fs::metadata(a), fs::metadata(b)) {
            (Ok(ma), Ok(mb)) if ma.len() == mb.len() => {}
            _ => return false,
        }
        match (fs::read(a), fs::read(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    pub fn enable() -> Result<(), String> {
        ensure_running()?;
        let _ = systemctl(&["restart", UNIT_NAME]);
        Ok(())
    }

    /// Writes the watcher's user unit and starts it. Only the file and the unit:
    /// the proxy unit is not touched, so auto-patch on its own never switches the
    /// 400 bypass on.
    pub fn enable_watchdog() -> Result<(), String> {
        let replaced = install_copy()?;
        let up = watchdog_unit_path();
        if let Some(p) = up.parent() {
            fs::create_dir_all(p).map_err(|e| format!("не создать {}: {}", p.display(), e))?;
        }
        let unit = unit_text("Antigravity Unlocker auto-patch", WATCHDOG_FLAG);
        let unit_changed = fs::read_to_string(&up).map_or(true, |old| old != unit);
        fs::write(&up, unit).map_err(|e| format!("не записать юнит: {}", e))?;
        systemctl(&["daemon-reload"]);
        if !systemctl(&["enable", "--now", WATCHDOG_UNIT_NAME]) {
            return Err("не удалось запустить systemd-юнит (systemctl --user)".to_string());
        }
        if (replaced || unit_changed) && !systemctl(&["restart", WATCHDOG_UNIT_NAME]) {
            return Err(
                "автопатч записан, но служба не перезапустилась (systemctl --user)".to_string(),
            );
        }
        Ok(())
    }

    /// The copy the units run from has to be there before either of them starts.
    /// Starting the proxy here would switch the 400 bypass on behind the user's
    /// back, so this is only the file.
    pub fn ensure_installed() -> Result<(), String> {
        install_copy().map(|_| ())
    }

    pub fn disable_watchdog() {
        systemctl(&["disable", "--now", WATCHDOG_UNIT_NAME]);
        let _ = fs::remove_file(watchdog_unit_path());
        systemctl(&["daemon-reload"]);
    }

    /// Stops and removes the user unit and the installed copy. Quiet success even
    /// when nothing was installed, so the undo menus never error.
    pub fn disable() -> Result<(), String> {
        systemctl(&["disable", "--now", UNIT_NAME]);
        let _ = fs::remove_file(unit_path());
        systemctl(&["daemon-reload"]);
        // The watcher runs the same copy: while its unit is there the file stays.
        if !is_watchdog_enabled() {
            let _ = fs::remove_file(installed_exe());
            let _ = fs::remove_dir(install_dir());
        }
        Ok(())
    }
}
