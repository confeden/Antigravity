//! Windows creator of one dedicated gateway companion.
//!
//! The caller retains this value through Pending. Dropping an unsettled session
//! is not a stop/settlement operation; this module neither detaches a cleanup
//! task nor blocks Drop indefinitely. Root owns verified topology, executable
//! provenance, access admission, policy receiving and any application launch.
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use super::windows_installation::{CheckedPath, NativeObjectId, PathKind, PathPurpose, WindowsExecutablePath};
use sha2::{Digest, Sha256};

/// Closed reference to the actual pinned Windows host. The role prefix is a
/// protocol constant, never a guessed sibling executable or caller label.
pub(crate) struct GatewayProgramRef {
    executable: CheckedPath,
    binding: String,
}
impl GatewayProgramRef {
    pub(crate) fn receive(path: &std::path::Path, expected_native: &NativeObjectId, expected_sha256: &str) -> Result<Self, String> {
        WindowsExecutablePath::parse(path.as_os_str())?;
        let executable = CheckedPath::open(path, PathKind::File, PathPurpose::Executable)?;
        let binding = hex::encode(Sha256::digest(executable.read_snapshot()?));
        if &executable.native_id() != expected_native || binding != expected_sha256 {
            return Err("gateway host native/content identity mismatch".into());
        }
        Ok(Self { executable, binding })
    }
    pub(crate) fn path(&self) -> &std::path::Path { self.executable.as_path() }
    pub(crate) fn binding(&self) -> &str { &self.binding }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyStatus {
    Received,
    Unavailable,
}
impl PolicyStatus {
    fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "RECEIVED" => Ok(Self::Received),
            "UNAVAILABLE" => Ok(Self::Unavailable),
            _ => Err("policy token"),
        }
    }
}

/// Explicit producer arguments; no machine address, path or port is selected here.
pub struct GatewayConfig {
    pub bind: Ipv4Addr,
    pub source: Ipv4Addr,
    pub opening_ms: u64,
    pub header_bytes: usize,
    pub max_active: usize,
    pub poll_ms: u64,
}
pub struct SessionSpec {
    pub(crate) program: GatewayProgramRef,
    pub selected_distro: String,
    pub selected_user: String,
    pub gateway: GatewayConfig,
    pub expected_policy: PolicyStatus,
    pub startup_budget: Duration,
    pub stop_observation_budget: Duration,
    /// Caller-owned per-record metadata memory budget, not a traffic limit.
    pub status_line_bytes: usize,
}
impl SessionSpec {
    fn validate(&self, now: Instant) -> Result<Instant, &'static str> {
        let g = &self.gateway;
        let address =
            |ip: Ipv4Addr| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast();
        if !self.program.path().is_absolute()
            || self.program.binding().is_empty()
            || self.selected_distro.is_empty()
            || self.selected_user.is_empty()
            || !address(g.bind)
            || !address(g.source)
            || g.opening_ms == 0
            || g.header_bytes == 0
            || g.max_active == 0
            || g.poll_ms == 0
            || i32::try_from(g.max_active).is_err()
            || g.max_active.checked_add(4).is_none()
            || self.startup_budget.is_zero()
            || self.stop_observation_budget.is_zero()
            || self.status_line_bytes == 0
        {
            return Err("missing or invalid explicit session input");
        }
        now.checked_add(Duration::from_millis(g.opening_ms))
            .ok_or("opening budget overflow")?;
        now.checked_add(self.stop_observation_budget)
            .ok_or("stop budget overflow")?;
        now.checked_add(self.startup_budget)
            .ok_or("startup budget overflow")
    }
    fn arguments(&self) -> [String; 12] {
        [
            "--bind-ip".into(),
            self.gateway.bind.to_string(),
            "--source-ip".into(),
            self.gateway.source.to_string(),
            "--opening-ms".into(),
            self.gateway.opening_ms.to_string(),
            "--header-bytes".into(),
            self.gateway.header_bytes.to_string(),
            "--max-active".into(),
            self.gateway.max_active.to_string(),
            "--poll-ms".into(),
            self.gateway.poll_ms.to_string(),
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ready {
    pub endpoint: SocketAddrV4,
    pub source: Ipv4Addr,
    pub policy: PolicyStatus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopAction {
    CloseParentStdin,
    RetainParentStdin,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Ready(Ready),
    /// Exact received metadata; extended opening/pump fields are retained.
    Connection {
        id: u128,
        response_bytes: u128,
        metadata: String,
    },
    StartupError {
        reason: String,
    },
    Stopping {
        reason: String,
        action: StopAction,
    },
    Stopped {
        policy: PolicyStatus,
    },
    Failed {
        policy: PolicyStatus,
    },
}
fn value<'a>(field: &'a str, name: &str) -> Result<&'a str, &'static str> {
    let (key, value) = field.split_once('=').ok_or("missing field value")?;
    if key != name || value.is_empty() {
        return Err("field/order mismatch");
    }
    Ok(value)
}
fn parse_status(line: &[u8]) -> Result<Status, &'static str> {
    let body = line.strip_suffix(b"\n").ok_or("missing LF")?;
    if !body.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err("noncanonical status bytes");
    }
    let body = std::str::from_utf8(body).map_err(|_| "status encoding")?;
    let f: Vec<_> = body.split(' ').collect();
    if f.first() != Some(&"AGWSLGW1") || f.iter().any(|s| s.is_empty()) {
        return Err("status version/framing");
    }
    match f.get(1).copied() {
        Some("READY") if f.len() == 6 => {
            let endpoint = value(f[2], "endpoint")?
                .parse::<SocketAddrV4>()
                .map_err(|_| "IPv4 endpoint")?;
            let source = value(f[3], "source")?
                .parse::<Ipv4Addr>()
                .map_err(|_| "source IPv4")?;
            if value(f[4], "access")? != "SOURCE_ONLY"
                || endpoint.port() == 0
                || value(f[2], "endpoint")? != endpoint.to_string()
                || value(f[3], "source")? != source.to_string()
            {
                return Err("access/endpoint");
            }
            Ok(Status::Ready(Ready {
                endpoint,
                source,
                policy: PolicyStatus::parse(value(f[5], "policy")?)?,
            }))
        }
        Some("CONNECTION") if f.len() == 16 => {
            let names = [
                "id",
                "result",
                "boundary",
                "io",
                "response_bytes",
                "shutdown",
                "opening_io",
                "origin_shutdown",
                "commit",
                "pump_start",
                "upload",
                "download",
                "pump_cancel",
                "cancel_shutdown",
            ];
            for (field, name) in f[2..].iter().zip(names) {
                value(field, name)?;
            }
            let id = value(f[2], "id")?.parse().map_err(|_| "connection id")?;
            let response_bytes = value(f[6], "response_bytes")?
                .parse()
                .map_err(|_| "response count")?;
            if id < 3 {
                return Err("connection identifier range");
            }
            Ok(Status::Connection {
                id,
                response_bytes,
                metadata: body.into(),
            })
        }
        Some("STARTUP_ERROR") if f.len() == 3 => Ok(Status::StartupError {
            reason: value(f[2], "reason")?.into(),
        }),
        Some("STOPPING") if f.len() == 4 => {
            let action = match value(f[3], "action")? {
                "CLOSE_PARENT_STDIN" => StopAction::CloseParentStdin,
                "RETAIN_PARENT_STDIN" => StopAction::RetainParentStdin,
                _ => return Err("stop action"),
            };
            Ok(Status::Stopping {
                reason: value(f[2], "reason")?.into(),
                action,
            })
        }
        Some("STOPPED") if f.len() == 3 => Ok(Status::Stopped {
            policy: PolicyStatus::parse(value(f[2], "policy")?)?,
        }),
        Some("FAILED") if f.len() == 3 => Ok(Status::Failed {
            policy: PolicyStatus::parse(value(f[2], "policy")?)?,
        }),
        _ => Err("status kind/fields"),
    }
}

#[derive(Default)]
struct Protocol {
    ready: Option<Ready>,
    terminal: Option<bool>,
}
impl Protocol {
    fn accept(&mut self, status: &Status, spec: &SessionSpec) -> Result<(), &'static str> {
        if self.terminal.is_some() {
            return Err("record after terminal");
        }
        match status {
            Status::Ready(ready) => {
                if self.ready.is_some()
                    || ready.endpoint.ip() != &spec.gateway.bind
                    || ready.source != spec.gateway.source
                    || ready.policy != spec.expected_policy
                {
                    return Err("READY launch-input mismatch/duplicate");
                }
                self.ready = Some(*ready);
            }
            Status::Connection { .. } if self.ready.is_none() => {
                return Err("connection before READY")
            }
            Status::StartupError { .. } => return Err("companion reported startup failure"),
            Status::Stopped { policy } | Status::Failed { policy } => {
                if *policy != spec.expected_policy {
                    return Err("terminal policy mismatch");
                }
                self.terminal = Some(matches!(status, Status::Stopped { .. }));
                if matches!(status, Status::Failed { .. }) {
                    return Err("companion reported failure");
                }
            }
            _ => {}
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProtocolFault {
    Invalid(&'static str),
    Oversize,
    Truncated,
}
enum Event {
    Status(Status),
    Fault(ProtocolFault),
}
struct ReaderOutcome {
    eof: bool,
    error: Option<io::Error>,
    fault: Option<ProtocolFault>,
    prefix: Vec<u8>,
    unsent: Option<Event>,
}
fn read_status(
    input: impl Read,
    budget: usize,
    mut emit: impl FnMut(Event) -> Result<(), Event>,
) -> ReaderOutcome {
    let mut input = BufReader::new(input);
    let mut result = ReaderOutcome {
        eof: false,
        error: None,
        fault: None,
        prefix: Vec::new(),
        unsent: None,
    };
    loop {
        let bytes = match input.fill_buf() {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                result.error = Some(e);
                return result;
            }
        };
        if bytes.is_empty() {
            result.eof = true;
            if result.fault.is_none() && !result.prefix.is_empty() {
                result.fault = Some(ProtocolFault::Truncated);
                if let Err(event) = emit(Event::Fault(ProtocolFault::Truncated)) {
                    result.unsent = Some(event);
                }
            }
            return result;
        }
        // Once corrupt, drain with BufReader's fixed working buffer; never
        // interpret a later READY as recovery or retain an unbounded transcript.
        if result.fault.is_some() {
            let n = bytes.len();
            input.consume(n);
            continue;
        }
        let n = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |p| p + 1);
        if n > budget.saturating_sub(result.prefix.len()) {
            let take = budget.saturating_sub(result.prefix.len());
            result.prefix.extend_from_slice(&bytes[..take]);
            input.consume(take);
            result.fault = Some(ProtocolFault::Oversize);
            if let Err(event) = emit(Event::Fault(ProtocolFault::Oversize)) {
                result.unsent = Some(event);
                return result;
            }
            continue;
        }
        result.prefix.extend_from_slice(&bytes[..n]);
        input.consume(n);
        if result.prefix.last() == Some(&b'\n') {
            match parse_status(&result.prefix) {
                Ok(status) => {
                    if let Err(event) = emit(Event::Status(status)) {
                        result.unsent = Some(event);
                        return result;
                    }
                    result.prefix.clear();
                }
                Err(reason) => {
                    let fault = ProtocolFault::Invalid(reason);
                    result.fault = Some(fault);
                    if let Err(event) = emit(Event::Fault(fault)) {
                        result.unsent = Some(event);
                        return result;
                    }
                }
            }
        }
    }
}
enum Reader {
    NotStarted,
    Owned(JoinHandle<ReaderOutcome>),
    Finished(thread::Result<ReaderOutcome>),
}

/// The shared slot retains the sole writer even if spawning or the worker fails.
/// Only the worker locks while writing; its owner collects after is_finished.
struct HoldWriter<W> {
    writer: Arc<Mutex<Option<W>>>,
    worker: JoinHandle<thread::Result<io::Result<()>>>,
}
impl<W: Write + Send + 'static> HoldWriter<W> {
    fn spawn(writer: W) -> Result<Self, (W, io::Error)> {
        let writer = Arc::new(Mutex::new(Some(writer)));
        let handoff = Arc::clone(&writer);
        match thread::Builder::new()
            .name("wsl-gateway-hold-writer".into())
            .spawn(move || {
                let mut slot = handoff.lock().unwrap_or_else(|error| error.into_inner());
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    slot.as_mut().unwrap().write_all(b"H")
                }))
            }) {
            Ok(worker) => Ok(Self { writer, worker }),
            Err(error) => {
                let retained = writer
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take()
                    .unwrap();
                Err((retained, error))
            }
        }
    }
    fn finished(&self) -> bool {
        self.worker.is_finished()
    }
    fn collect(self) -> (W, thread::Result<io::Result<()>>) {
        let result = self.worker.join().and_then(|result| result);
        let writer = self
            .writer
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .unwrap();
        (writer, result)
    }
}
#[derive(Debug)]
pub enum SessionError {
    InvalidInput(&'static str),
    Spawn(io::Error),
    ReaderSpawn(io::Error),
    StartupDeadline,
    Protocol(&'static str),
    ReaderIo(io::Error),
    ReaderFault(&'static str),
    ReaderPanic,
    ExitObservation(io::Error),
    ChildFailure,
    GatewayLost,
    HoldWriterSpawn(io::Error),
    HoldWrite(io::Error),
    HoldWriterPanic,
    HoldUnavailable,
    HoldDeadline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Ready,
    Stopping,
    Pending,
    Settled,
}
/// Received diagnostics may include rejected records. Use ready() for validated
/// live metadata, and clean_shutdown() only for the retired process protocol.
pub struct Update {
    pub statuses: Vec<Status>,
    pub phase: Phase,
}
pub struct StartFailure {
    pub error: SessionError,
    pub session: Option<GatewaySession>,
}
#[must_use = "retain the session while Child or status reader is pending"]
pub struct GatewaySession {
    spec: SessionSpec,
    child: Option<Child>,
    control: Option<ChildStdin>,
    reader: Reader,
    received: Receiver<Event>,
    protocol: Protocol,
    errors: Vec<SessionError>,
    startup_deadline: Instant,
    stop_deadline: Option<Instant>,
    hold_deadline: Option<Instant>,
    hold_acknowledged: bool,
    hold_deadline_reported: bool,
    hold_writer: Option<HoldWriter<ChildStdin>>,
    final_release: bool,
    exit: Option<ExitStatus>,
    exit_observer_failed: bool,
    exit_reobservation: bool,
    termination: Option<io::Result<()>>,
}
impl GatewaySession {
    pub fn spawn(spec: SessionSpec, now: Instant) -> Result<Self, StartFailure> {
        let startup_deadline = spec.validate(now).map_err(|reason| StartFailure {
            error: SessionError::InvalidInput(reason),
            session: None,
        })?;
        if !cfg!(windows) {
            return Err(StartFailure {
                error: SessionError::InvalidInput("Windows creator required"),
                session: None,
            });
        }
        let (send, received) = mpsc::sync_channel(1);
        let mut owner = Self {
            spec,
            child: None,
            control: None,
            reader: Reader::NotStarted,
            received,
            protocol: Protocol::default(),
            errors: Vec::new(),
            startup_deadline,
            stop_deadline: None,
            hold_deadline: None,
            hold_acknowledged: false,
            hold_deadline_reported: false,
            hold_writer: None,
            final_release: false,
            exit: None,
            exit_observer_failed: false,
            exit_reobservation: false,
            termination: None,
        };
        if owner.spec.program.executable.recheck().is_err() {
            return Err(StartFailure { error: SessionError::InvalidInput("gateway host pin changed"), session: None });
        }
        match Command::new(owner.spec.program.path())
            .arg("--wsl-gateway")
            .args(owner.spec.arguments())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => owner.child = Some(child),
            Err(error) => {
                return Err(StartFailure {
                    error: SessionError::Spawn(error),
                    session: None,
                })
            }
        }
        owner.control = owner.child.as_mut().unwrap().stdin.take();
        let output = owner.child.as_mut().unwrap().stdout.take().unwrap();
        let budget = owner.spec.status_line_bytes;
        match thread::Builder::new()
            .name("wsl-gateway-status-reader".into())
            .spawn(move || read_status(output, budget, |event| send.send(event).map_err(|e| e.0)))
        {
            Ok(handle) => owner.reader = Reader::Owned(handle),
            Err(error) => {
                owner.request_stop(now);
                return Err(StartFailure {
                    error: SessionError::ReaderSpawn(error),
                    session: Some(owner),
                });
            }
        }
        Ok(owner)
    }
    /// Lifetime signal only. No pipe write, process exit claim, wait or join.
    pub fn request_stop(&mut self, now: Instant) {
        self.final_release = true;
        self.control.take();
        if self.stop_deadline.is_none() {
            self.stop_deadline = Some(match now.checked_add(self.spec.stop_observation_budget) {
                Some(end) => end,
                None => {
                    self.errors
                        .push(SessionError::InvalidInput("stop deadline overflow"));
                    now
                }
            });
        }
    }
    /// Irreversible stop of admissions; publication and acknowledgment are distinct.
    /// This never waits for control I/O, closes its writer or renews its budget.
    pub fn request_hold(&mut self, now: Instant) {
        if self.final_release || self.hold_deadline.is_some() {
            return;
        }
        self.hold_deadline = Some(
            now.checked_add(self.spec.stop_observation_budget)
                .unwrap_or_else(|| {
                    self.errors
                        .push(SessionError::InvalidInput("hold deadline overflow"));
                    now
                }),
        );
        match self.control.take() {
            Some(writer) => match HoldWriter::spawn(writer) {
                Ok(worker) => self.hold_writer = Some(worker),
                Err((writer, error)) => {
                    self.control = Some(writer);
                    self.errors.push(SessionError::HoldWriterSpawn(error));
                }
            },
            None => self.errors.push(SessionError::HoldUnavailable),
        }
    }
    pub fn hold_acknowledged(&self) -> bool {
        self.hold_acknowledged
    }
    fn automatic_stop(&mut self, now: Instant) {
        if self.protocol.ready.is_some() {
            self.request_hold(now);
        } else {
            self.request_stop(now);
        }
    }
    fn observe_hold_writer(&mut self) {
        if !self.hold_writer.as_ref().is_some_and(HoldWriter::finished) {
            return;
        }
        let (writer, result) = self.hold_writer.take().unwrap().collect();
        if !self.final_release {
            self.control = Some(writer);
        } // Otherwise actual ownership has returned; publish final EOF.
        match result {
            Ok(Ok(())) => (),
            Ok(Err(error)) => self.errors.push(SessionError::HoldWrite(error)),
            Err(_) => self.errors.push(SessionError::HoldWriterPanic),
        }
    }
    fn expire_hold(&mut self, now: Instant) {
        if self.hold_deadline.is_some_and(|end| now >= end)
            && !self.hold_acknowledged
            && !self.hold_deadline_reported
        {
            self.hold_deadline_reported = true;
            self.errors.push(SessionError::HoldDeadline);
        }
    }
    /// Caller authorization is explicit in invoking this creator-only method.
    /// Repeated calls return the retained first request; they never retry it.
    pub fn request_termination(&mut self, now: Instant) -> &io::Result<()> {
        self.request_stop(now);
        if self.termination.is_none() {
            self.termination = Some(self.child.as_mut().unwrap().kill());
        }
        self.termination.as_ref().unwrap()
    }
    fn expire_startup(&mut self, now: Instant) {
        if self.protocol.ready.is_none()
            && self.stop_deadline.is_none()
            && now >= self.startup_deadline
        {
            self.errors.push(SessionError::StartupDeadline);
            self.request_stop(now);
        }
    }
    fn event(&mut self, clock: &mut impl FnMut() -> Instant, statuses: &mut Vec<Status>) {
        if let Ok(event) = self.received.try_recv() {
            // Observe after dequeue: neither poll entry nor assumed pipe arrival
            // may grant a first READY credit after the absolute deadline.
            let now = clock();
            self.expire_startup(now);
            match event {
                Event::Status(status) => {
                    let accepted = self.protocol.accept(&status, &self.spec);
                    if let Err(reason) = accepted {
                        self.errors.push(SessionError::Protocol(reason));
                        self.automatic_stop(now);
                    }
                    if let Status::Stopping { reason, action } = &status {
                        match action {
                            StopAction::RetainParentStdin
                                if accepted.is_ok()
                                    && self.hold_deadline.is_some()
                                    && !self.hold_acknowledged
                                    && reason == "PARENT_HOLD" =>
                            {
                                self.hold_acknowledged = true
                            }
                            StopAction::RetainParentStdin => {
                                self.errors.push(SessionError::Protocol(
                                    "unsolicited, duplicate or mismatched HOLD acknowledgment",
                                ))
                            }
                            StopAction::CloseParentStdin if self.hold_deadline.is_some() => self
                                .errors
                                .push(SessionError::Protocol("release action after HOLD request")),
                            _ => (),
                        }
                    }
                    if self.protocol.ready.is_some()
                        && !self.final_release
                        && matches!(status, Status::Stopped { .. } | Status::Failed { .. })
                    {
                        self.errors.push(SessionError::GatewayLost);
                    }
                    if matches!(
                        status,
                        Status::StartupError { .. }
                            | Status::Stopping { .. }
                            | Status::Stopped { .. }
                            | Status::Failed { .. }
                    ) {
                        self.automatic_stop(now);
                    }
                    statuses.push(status);
                }
                Event::Fault(fault) => {
                    self.errors.push(SessionError::ReaderFault(match fault {
                        ProtocolFault::Invalid(reason) => reason,
                        ProtocolFault::Oversize => "status record budget exhausted",
                        ProtocolFault::Truncated => "truncated status record",
                    }));
                    self.automatic_stop(now);
                }
            }
        }
    }
    /// Caller must record materially changed evidence before arming a new
    /// observation. This permits one query, never termination or exit credit.
    pub fn request_exit_reobservation(&mut self) -> bool {
        self.arm_exit_reobservation(self.child.is_some())
    }
    fn arm_exit_reobservation(&mut self, child_owned: bool) -> bool {
        if child_owned
            && self.exit.is_none()
            && self.exit_observer_failed
            && !self.exit_reobservation
        {
            self.exit_reobservation = true;
            true
        } else {
            false
        }
    }
    /// Never waits for a pipe or unfinished thread. Pending retains all owners.
    pub fn poll(&mut self) -> Update {
        self.poll_with(Instant::now, |child| {
            child
                .ok_or_else(|| io::Error::other("session Child absent"))?
                .try_wait()
        })
    }
    fn poll_with(
        &mut self,
        mut clock: impl FnMut() -> Instant,
        mut observe: impl FnMut(Option<&mut Child>) -> io::Result<Option<ExitStatus>>,
    ) -> Update {
        let mut statuses = Vec::new();
        self.observe_hold_writer();
        self.expire_startup(clock());
        self.expire_hold(clock());
        self.event(&mut clock, &mut statuses);
        if self.exit.is_none() && (!self.exit_observer_failed || self.exit_reobservation) {
            // Consume before the actual query, including a failure or None.
            // Historical failure remains latched after every permitted result.
            self.exit_reobservation = false;
            let result = observe(self.child.as_mut());
            let now = clock();
            match result {
                Ok(Some(exit)) => {
                    if !exit.success() {
                        self.errors.push(SessionError::ChildFailure);
                    }
                    self.exit = Some(exit);
                    self.automatic_stop(now);
                }
                Ok(None) => {}
                Err(error) => {
                    self.exit_observer_failed = true;
                    self.errors.push(SessionError::ExitObservation(error));
                    self.automatic_stop(now);
                }
            }
        }
        if matches!(&self.reader, Reader::Owned(handle) if handle.is_finished()) {
            if let Reader::Owned(handle) = std::mem::replace(&mut self.reader, Reader::NotStarted) {
                self.reader = Reader::Finished(handle.join());
            }
            self.finish_reader(&mut clock, &mut statuses);
        }
        Update {
            statuses,
            phase: self.phase(clock()),
        }
    }
    fn finish_reader(&mut self, clock: &mut impl FnMut() -> Instant, statuses: &mut Vec<Status>) {
        // Sender has ended; the possible final record uses the same fresh
        // observation guard before reader completion requests retirement.
        self.event(clock, statuses);
        self.automatic_stop(clock());
        match &mut self.reader {
            Reader::Finished(Ok(outcome)) => {
                if let Some(error) = outcome.error.take() {
                    self.errors.push(SessionError::ReaderIo(error));
                }
                if !outcome.eof || self.protocol.terminal.is_none() {
                    self.errors.push(SessionError::GatewayLost);
                }
            }
            Reader::Finished(Err(_)) => self.errors.push(SessionError::ReaderPanic),
            _ => {}
        }
    }
    pub fn phase(&self, now: Instant) -> Phase {
        phase(
            self.exit.is_some(),
            !matches!(self.reader, Reader::Owned(_))
                && self.hold_writer.is_none()
                && self.control.is_none(),
            self.protocol.ready.is_some(),
            self.stop_deadline.or(self.hold_deadline),
            now,
        )
    }
    /// Validated metadata only; not access admission, trust or a model answer.
    pub fn ready(&self) -> Option<Ready> {
        if self.stop_deadline.is_none() && self.hold_deadline.is_none() && self.errors.is_empty() {
            self.protocol.ready
        } else {
            None
        }
    }
    pub fn errors(&self) -> &[SessionError] {
        &self.errors
    }
    pub fn exit_status(&self) -> Option<ExitStatus> {
        self.exit
    }
    pub fn spec(&self) -> &SessionSpec {
        &self.spec
    }
    pub fn clean_shutdown(&self) -> bool {
        self.exit.is_some_and(|e| e.success())
            && !matches!(self.reader, Reader::Owned(_))
            && self.hold_writer.is_none()
            && self.control.is_none()
            && self.final_release
            && self.protocol.terminal == Some(true)
            && self.errors.is_empty()
    }
}
fn phase(
    exited: bool,
    reader_done: bool,
    ready: bool,
    stop: Option<Instant>,
    now: Instant,
) -> Phase {
    if exited && reader_done {
        Phase::Settled
    } else if let Some(end) = stop {
        if now >= end {
            Phase::Pending
        } else {
            Phase::Stopping
        }
    } else if ready {
        Phase::Ready
    } else {
        Phase::Starting
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const READY: &str = "AGWSLGW1 READY endpoint=192.0.2.1:49152 source=192.0.2.2 access=SOURCE_ONLY policy=UNAVAILABLE\n";
    const CONNECTION: &str = "AGWSLGW1 CONNECTION id=3 result=TUNNEL_COMPLETE boundary=NONE io=NONE response_bytes=39 shutdown=OK opening_io=NONE origin_shutdown=NONE commit=NONE pump_start=NONE upload=EOF:NONE download=EOF:NONE pump_cancel=NONE cancel_shutdown=NONE\n";
    const HOLD: &str = "AGWSLGW1 STOPPING reason=PARENT_HOLD action=RETAIN_PARENT_STDIN\n";
    fn spec() -> SessionSpec {
        let path = std::env::current_exe().unwrap();
        let pinned = CheckedPath::open(&path, PathKind::File, PathPurpose::Executable).unwrap();
        let digest = hex::encode(Sha256::digest(pinned.read_snapshot().unwrap()));
        SessionSpec {
            program: GatewayProgramRef::receive(&path, &pinned.native_id(), &digest).unwrap(),
            selected_distro: "synthetic-distro".into(),
            selected_user: "synthetic-user".into(),
            gateway: GatewayConfig {
                bind: Ipv4Addr::new(192, 0, 2, 1),
                source: Ipv4Addr::new(192, 0, 2, 2),
                opening_ms: 1000,
                header_bytes: 4096,
                max_active: 2,
                poll_ms: 5,
            },
            expected_policy: PolicyStatus::Unavailable,
            startup_budget: Duration::from_secs(1),
            stop_observation_budget: Duration::from_secs(1),
            status_line_bytes: 1024,
        }
    }
    #[test]
    fn exact_producer_ready_and_extended_connection_are_received() {
        let mut protocol = Protocol::default();
        let ready = parse_status(READY.as_bytes()).unwrap();
        protocol.accept(&ready, &spec()).unwrap();
        assert_eq!(protocol.ready.unwrap().endpoint.port(), 49152);
        match parse_status(CONNECTION.as_bytes()).unwrap() {
            Status::Connection {
                id,
                response_bytes,
                metadata,
            } => {
                assert_eq!((id, response_bytes), (3, 39));
                assert!(metadata.ends_with("cancel_shutdown=NONE"));
            }
            _ => panic!("wrong record"),
        }
        assert!(protocol.accept(&ready, &spec()).is_err());
        for replacement in [
            READY.replace("192.0.2.1:49152", "192.0.2.9:49152"),
            READY.replace("source=192.0.2.2", "source=192.0.2.3"),
            READY.replace("UNAVAILABLE", "RECEIVED"),
        ] {
            assert!(Protocol::default()
                .accept(&parse_status(replacement.as_bytes()).unwrap(), &spec())
                .is_err());
        }
    }
    #[test]
    fn malformed_unknown_old_or_incomplete_records_never_become_ready() {
        for record in [
            READY.replace("AGWSLGW1", "AGWSLGW0"),
            READY.replace("SOURCE_ONLY", "ANY"),
            READY.replace(":49152", ":0"),
            READY.replace('\n', "\r\n"),
            READY.trim_end().to_string(),
            CONNECTION.replace(" cancel_shutdown=NONE", ""),
        ] {
            assert!(parse_status(record.as_bytes()).is_err(), "{record}");
        }
    }
    #[test]
    fn reader_is_bounded_drains_after_corruption_and_retains_read_errors() {
        let mut events = Vec::new();
        let outcome = read_status(
            io::Cursor::new([READY, CONNECTION, "AGWSLGW1 STOPPED policy=UNAVAILABLE\n"].concat()),
            1024,
            |event| {
                events.push(event);
                Ok(())
            },
        );
        assert!(outcome.eof);
        assert!(outcome.error.is_none());
        assert_eq!(events.len(), 3);
        for (input, budget) in [
            (format!("bad\n{READY}"), 1024),
            (READY.into(), 8),
            ("AGWSLGW1 READY".into(), 1024),
        ] {
            let mut events = Vec::new();
            let outcome = read_status(io::Cursor::new(input), budget, |event| {
                events.push(event);
                Ok(())
            });
            assert!(outcome.eof);
            assert!(outcome.fault.is_some());
            assert!(events.iter().all(|e| matches!(e, Event::Fault(_))));
            assert!(outcome.prefix.len() <= budget);
        }
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        let outcome = read_status(Broken, 1024, |_| Ok(()));
        assert!(!outcome.eof);
        assert_eq!(
            outcome.error.unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        let outcome = read_status(io::Cursor::new(READY), 1024, Err);
        assert!(outcome.unsent.is_some());
        assert!(!outcome.eof);
    }
    #[test]
    fn exit_and_reader_collection_are_independent_of_stop_requests() {
        let now = Instant::now();
        assert_eq!(phase(false, false, false, None, now), Phase::Starting);
        assert_eq!(phase(false, false, true, None, now), Phase::Ready);
        assert_eq!(phase(false, false, true, Some(now), now), Phase::Pending); // A kill/EOF request is not exit.
        assert_eq!(phase(true, false, true, Some(now), now), Phase::Pending); // Exit alone is not reader completion.
        assert_eq!(phase(false, true, true, Some(now), now), Phase::Pending);
        assert_eq!(phase(true, true, true, Some(now), now), Phase::Settled);
    }
    #[test]
    fn missing_context_and_equal_default_addresses_fail_before_spawn() {
        let now = Instant::now();
        assert!(spec().validate(now).is_ok());
        let mut s = spec();
        s.selected_distro.clear();
        assert!(s.validate(now).is_err());
        let mut s = spec();
        s.selected_user.clear();
        assert!(s.validate(now).is_err());
        let mut s = spec();
        s.program.binding.clear();
        assert!(s.validate(now).is_err());
        let mut s = spec();
        s.gateway.bind = Ipv4Addr::UNSPECIFIED;
        s.gateway.source = Ipv4Addr::UNSPECIFIED;
        assert!(s.validate(now).is_err());
        let mut s = spec();
        s.startup_budget = Duration::ZERO;
        assert!(s.validate(now).is_err());
    }
    // Construct only the existing owner's value and finite queues. No fake
    // native Child/JoinHandle is constructed; injected observations model the
    // decision path, not operating-system ownership or physical settlement.
    fn queued_owner(deadline: Instant) -> (GatewaySession, mpsc::SyncSender<Event>) {
        let (send, received) = mpsc::sync_channel(1);
        (
            GatewaySession {
                spec: spec(),
                child: None,
                control: None,
                reader: Reader::NotStarted,
                received,
                protocol: Protocol::default(),
                errors: Vec::new(),
                startup_deadline: deadline,
                stop_deadline: None,
                hold_deadline: None,
                hold_acknowledged: false,
                hold_deadline_reported: false,
                hold_writer: None,
                final_release: false,
                exit: None,
                exit_observer_failed: false,
                exit_reobservation: false,
                termination: None,
            },
            send,
        )
    }
    fn clock(samples: &[Instant]) -> impl FnMut() -> Instant {
        let mut values = samples.to_vec().into_iter();
        let last = *samples.last().unwrap();
        move || values.next().unwrap_or(last)
    }
    fn deadline_errors(owner: &GatewaySession) -> usize {
        owner
            .errors
            .iter()
            .filter(|error| matches!(error, SessionError::StartupDeadline))
            .count()
    }
    #[test]
    fn hold_is_one_shot_with_distinct_ack_deadline_and_no_automatic_release() {
        let now = Instant::now();
        let (mut owner, send) = queued_owner(now + Duration::from_secs(10));
        owner
            .protocol
            .accept(&parse_status(READY.as_bytes()).unwrap(), &spec())
            .unwrap();
        owner.request_hold(now);
        let deadline = owner.hold_deadline;
        owner.request_hold(now + Duration::from_secs(1));
        assert_eq!(owner.hold_deadline, deadline);
        assert!(owner.ready().is_none() && !owner.final_release && !owner.hold_acknowledged());
        assert_eq!(
            owner
                .errors
                .iter()
                .filter(|e| matches!(e, SessionError::HoldUnavailable))
                .count(),
            1
        );
        send.send(Event::Status(parse_status(HOLD.as_bytes()).unwrap()))
            .unwrap();
        owner.poll_with(clock(&[now]), |_| Ok(None));
        assert!(owner.hold_acknowledged() && !owner.final_release);
        send.send(Event::Status(parse_status(HOLD.as_bytes()).unwrap()))
            .unwrap();
        owner.poll_with(clock(&[now]), |_| Ok(None));
        assert!(owner
            .errors
            .iter()
            .any(|e| matches!(e, SessionError::Protocol(_))));
        assert!(!owner.final_release);
        owner.request_stop(now);
        assert!(owner.final_release);

        let (mut owner, _send) = queued_owner(now + Duration::from_secs(10));
        owner
            .protocol
            .accept(&parse_status(READY.as_bytes()).unwrap(), &spec())
            .unwrap();
        owner.request_hold(now);
        owner.expire_hold(deadline.unwrap());
        owner.expire_hold(deadline.unwrap());
        assert_eq!(
            owner
                .errors
                .iter()
                .filter(|e| matches!(e, SessionError::HoldDeadline))
                .count(),
            1
        );
        assert!(!owner.hold_acknowledged() && !owner.final_release);
        assert_eq!(owner.phase(deadline.unwrap()), Phase::Pending);
    }
    #[test]
    fn post_ready_faults_and_unsolicited_ack_hold_while_pre_ready_faults_release() {
        let now = Instant::now();
        for ready in [false, true] {
            for event in [
                Event::Fault(ProtocolFault::Truncated),
                Event::Status(parse_status(HOLD.as_bytes()).unwrap()),
                Event::Status(Status::Stopping {
                    reason: "INTERNAL".into(),
                    action: StopAction::CloseParentStdin,
                }),
            ] {
                let (mut owner, send) = queued_owner(now + Duration::from_secs(10));
                if ready {
                    owner
                        .protocol
                        .accept(&parse_status(READY.as_bytes()).unwrap(), &spec())
                        .unwrap();
                }
                send.send(event).unwrap();
                owner.poll_with(clock(&[now]), |_| Ok(None));
                assert_eq!(owner.final_release, !ready);
                assert_eq!(owner.hold_deadline.is_some(), ready);
                assert!(!owner.hold_acknowledged());
            }
        }
        let (mut owner, _send) = queued_owner(now + Duration::from_secs(10));
        owner
            .protocol
            .accept(&parse_status(READY.as_bytes()).unwrap(), &spec())
            .unwrap();
        owner.poll_with(clock(&[now]), |_| {
            Err(io::ErrorKind::PermissionDenied.into())
        });
        assert!(owner.hold_deadline.is_some() && !owner.final_release);
        owner.reader = Reader::Finished(Err(Box::new("injected reader failure")));
        owner.finish_reader(&mut clock(&[now]), &mut Vec::new());
        assert!(!owner.final_release);
        for action in ["", "CLOSE", "RETAIN_PARENT_STDIN extra=x"] {
            assert!(parse_status(HOLD.replace("RETAIN_PARENT_STDIN", action).as_bytes()).is_err());
        }
    }
    #[test]
    fn blocked_hold_writer_never_requires_join_and_retains_its_sole_writer() {
        struct Blocked {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            bytes: Vec<u8>,
        }
        impl Write for Blocked {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (entered, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let worker = HoldWriter::spawn(Blocked {
            entered,
            release: released,
            bytes: Vec::new(),
        })
        .ok()
        .unwrap();
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!worker.finished()); // Production poll takes this branch without touching the locked slot.
        release.send(()).unwrap();
        let (writer, result) = worker.collect();
        assert!(matches!(result, Ok(Ok(()))));
        assert_eq!(writer.bytes, b"H");
    }
    #[test]
    fn failed_or_panicked_hold_publication_returns_writer_ownership() {
        struct Fails(bool);
        impl Write for Fails {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                if self.0 {
                    panic!("injected writer panic");
                }
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for panic in [false, true] {
            let publication = HoldWriter::spawn(Fails(panic)).ok().unwrap();
            let (writer, result) = publication.collect();
            assert_eq!(writer.0, panic);
            if panic {
                assert!(result.is_err());
            } else {
                assert!(
                    matches!(result, Ok(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
                );
            }
        }
    }
    #[test]
    fn startup_credit_uses_fresh_owner_observation_on_both_dequeues() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let before = deadline - Duration::from_nanos(1);
        let after = deadline + Duration::from_nanos(1);
        for observed in [before, deadline, after] {
            let (mut owner, send) = queued_owner(deadline);
            send.send(Event::Status(parse_status(READY.as_bytes()).unwrap()))
                .unwrap();
            let update = owner.poll_with(clock(&[observed]), |_| Ok(None));
            assert_eq!(update.statuses.len(), 1);
            assert_eq!(owner.ready().is_some(), observed < deadline);
            assert_eq!(deadline_errors(&owner), usize::from(observed >= deadline));
            let stop = owner.stop_deadline;
            owner.poll_with(clock(&[after]), |_| Ok(None));
            assert_eq!(deadline_errors(&owner), usize::from(observed >= deadline));
            assert_eq!(owner.stop_deadline, stop); // No reset; timely READY stays live.
            assert_eq!(owner.ready().is_some(), observed < deadline);
        }
        // Entry starts in time, but the actual dequeue observation is equality.
        let (mut owner, send) = queued_owner(deadline);
        send.send(Event::Status(parse_status(READY.as_bytes()).unwrap()))
            .unwrap();
        let update = owner.poll_with(clock(&[before, deadline]), |_| Ok(None));
        assert_eq!(update.statuses.len(), 1);
        assert!(owner.ready().is_none());
        assert_eq!(deadline_errors(&owner), 1);
        // Same production final-reader path: READY appears only in final slot.
        let (mut owner, send) = queued_owner(deadline);
        owner.expire_startup(before);
        owner.reader = Reader::Finished(Ok(ReaderOutcome {
            eof: true,
            error: None,
            fault: None,
            prefix: Vec::new(),
            unsent: None,
        }));
        send.send(Event::Status(parse_status(READY.as_bytes()).unwrap()))
            .unwrap();
        let mut statuses = Vec::new();
        owner.finish_reader(&mut clock(&[deadline]), &mut statuses);
        assert_eq!(statuses.len(), 1);
        assert!(owner.ready().is_none());
        assert_eq!(deadline_errors(&owner), 1);
        // Empty queue still expires; an existing stop never resurrects metadata.
        let (mut owner, _send) = queued_owner(deadline);
        owner.poll_with(clock(&[deadline]), |_| Ok(None));
        assert_eq!(deadline_errors(&owner), 1);
        let (mut owner, send) = queued_owner(deadline);
        owner.request_stop(before);
        let original_stop = owner.stop_deadline;
        send.send(Event::Status(parse_status(READY.as_bytes()).unwrap()))
            .unwrap();
        let update = owner.poll_with(clock(&[after]), |_| Ok(None));
        assert_eq!(update.statuses.len(), 1);
        assert!(owner.ready().is_none());
        assert_eq!(owner.stop_deadline, original_stop);
        assert_eq!(deadline_errors(&owner), 0);
    }
    #[test]
    fn exit_reobservation_is_one_query_and_preserves_original_history() {
        let now = Instant::now();
        let later = now + Duration::from_secs(2);
        let (mut owner, _send) = queued_owner(now + Duration::from_secs(10));
        assert!(!owner.request_exit_reobservation());
        assert!(!owner.arm_exit_reobservation(true)); // No failure yet.
        let mut calls = 0;
        owner.poll_with(clock(&[now]), |_| {
            calls += 1;
            Err(io::Error::from_raw_os_error(5))
        });
        assert_eq!(calls, 1);
        assert!(owner.exit_observer_failed);
        assert!(owner.exit.is_none());
        let original_stop = owner.stop_deadline;
        owner.termination = Some(Ok(())); // Model request success is not exit or permission.
        for _ in 0..2 {
            owner.poll_with(clock(&[later]), |_| {
                calls += 1;
                Ok(None)
            });
        }
        assert_eq!(calls, 1);
        assert_eq!(owner.phase(later), Phase::Pending);
        assert!(!owner.arm_exit_reobservation(false));
        // These pure arms stand for caller-justified new evidence; the public
        // operation derives child_owned from its actual retained Child.
        assert!(owner.arm_exit_reobservation(true));
        assert!(!owner.arm_exit_reobservation(true));
        owner.poll_with(clock(&[later]), |_| {
            calls += 1;
            Ok(None)
        });
        owner.poll_with(clock(&[later]), |_| {
            calls += 1;
            Ok(None)
        });
        assert_eq!(calls, 2);
        assert!(owner.exit_observer_failed);
        assert!(!owner.exit_reobservation);
        assert!(owner.arm_exit_reobservation(true));
        owner.poll_with(clock(&[later]), |_| {
            calls += 1;
            Err(io::Error::from_raw_os_error(87))
        });
        owner.poll_with(clock(&[later]), |_| {
            calls += 1;
            Ok(None)
        });
        assert_eq!(calls, 3);
        let codes: Vec<_> = owner
            .errors
            .iter()
            .filter_map(|error| match error {
                SessionError::ExitObservation(error) => error.raw_os_error(),
                _ => None,
            })
            .collect();
        assert_eq!(codes, [5, 87]);
        #[cfg(windows)]
        let exit = {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(0)
        };
        #[cfg(unix)]
        let exit = {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(0)
        };
        assert!(owner.arm_exit_reobservation(true));
        owner.poll_with(clock(&[later]), |_| {
            calls += 1;
            Ok(Some(exit))
        });
        assert_eq!(calls, 4);
        assert_eq!(owner.exit_status(), Some(exit));
        assert_eq!(owner.stop_deadline, original_stop);
        assert!(owner.exit_observer_failed);
        assert!(!owner.arm_exit_reobservation(true));
        owner.poll_with(clock(&[later]), |_| {
            calls += 1;
            Ok(None)
        });
        assert_eq!(calls, 4);
        owner.protocol.terminal = Some(true);
        assert_eq!(owner.phase(later), Phase::Settled);
        assert!(!owner.clean_shutdown());
        assert_eq!(
            owner
                .errors
                .iter()
                .filter(|e| matches!(e, SessionError::ExitObservation(_)))
                .count(),
            2
        );
    }
}
