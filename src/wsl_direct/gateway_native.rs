//! Concrete Windows process adapter for the installation owner's firewall seam.
//! The fixed PowerShell program is gated over private stdin; no mutation may
//! begin before the caller has received the retained native process outcome.
#![cfg(windows)]
use super::process_identity::ProcessIdentity;
use super::windows_installation::gateway_rules::*;
use super::windows_installation::{CheckedPath, PathKind, PathPurpose};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

type Result<T> = std::result::Result<T, String>;
const REPORT_PREFIX: &[u8] = b"AG_GATEWAY_NATIVE_V1 ";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum GatewayNativeStage {
    ReadyToInvoke,
    Progress,
    Done,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayNativeDiagnostic {
    pub(crate) kind: GatewayFailureKind,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayNativeReport {
    pub(crate) version: u32,
    pub(crate) attempt_id: String,
    pub(crate) stage: GatewayNativeStage,
    pub(crate) action: GatewayActionReport,
    #[serde(deserialize_with = "required_option")]
    pub(crate) inspection: Option<GatewayRuleInspection>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) diagnostic: Option<GatewayNativeDiagnostic>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) policy_evidence: Option<GatewayPolicyEvidence>,
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayProfileEvidence {
    mask: u32,
    enabled: bool,
    block_all_inbound: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayConditionalEvidence {
    name: String,
    field: String,
    values: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayPolicyEvidence {
    active_profiles: u32,
    local_modify_state: i32,
    profiles: Vec<GatewayProfileEvidence>,
    blocks: Vec<GatewayNativeRule>,
    unsupported_conditions: Vec<GatewayConditionalEvidence>,
}

/// Physical/capture outcomes are retained together with independent receiving
/// errors. A persistence or interpretation failure never replaces a native
/// success/failure already acquired from the child.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GatewayRunnerReceiving {
    pub(crate) attempt_id: Option<String>,
    pub(crate) outcome: GatewayNativeOutcome,
    pub(crate) reports: Vec<GatewayNativeReport>,
    pub(crate) identity_errors: Vec<String>,
    pub(crate) observation_errors: Vec<String>,
    pub(crate) recorder_errors: Vec<String>,
    pub(crate) control_errors: Vec<String>,
    pub(crate) interpretation_errors: Vec<String>,
    pub(crate) policy_observations: Vec<GatewayPolicyObservation>,
    pub(crate) cancellation_received: bool,
}

/// `run` is called on Core's retained setup worker, never its UI polling thread.
/// It drains and joins both readers and observes actual child retirement, with
/// no timeout, detach or process termination. A hanging native call therefore
/// remains inside the already-retained worker and its canonical Pending hold.
pub(crate) struct WindowsGatewayRuleRunner {
    program: CheckedPath,
    next_attempt_id: Box<dyn FnMut() -> Result<String> + Send>,
    receiving: Vec<GatewayRunnerReceiving>,
    script: &'static str,
    #[cfg(test)]
    reader_fault: Option<Pipe>,
}
impl WindowsGatewayRuleRunner {
    /// Core supplies its existing native UUID owner; no identifier registry or
    /// additional UUID dependency is introduced. The system PowerShell pin is
    /// received through the composition root's existing checked path owner.
    pub(crate) fn new<F>(next_attempt_id: F) -> Result<Self>
    where
        F: FnMut() -> Result<String> + Send + 'static,
    {
        Ok(Self {
            program: super::system_powershell_program()?,
            next_attempt_id: Box::new(next_attempt_id),
            receiving: Vec::new(),
            script: NATIVE_SCRIPT,
            #[cfg(test)]
            reader_fault: None,
        })
    }

    /// Receiving retains every completed attempt, including failed recording
    /// and protocol interpretation. The caller persists/settles this result
    /// through its existing job evidence before dropping the runner.
    pub(crate) fn receiving(&self) -> &[GatewayRunnerReceiving] {
        &self.receiving
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeInput<'a> {
    version: u32,
    attempt_id: &'a str,
    request: &'a GatewayRuleRequest,
    parameters: GatewayRuleParameters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pipe {
    Stdout,
    Stderr,
}
enum ReaderEvent {
    Bytes(Pipe, Vec<u8>),
    End(Pipe, Option<String>),
}
struct ReaderOwner {
    pipe: Pipe,
    handle: Option<JoinHandle<()>>,
}

fn capture() -> GatewayCapture {
    GatewayCapture {
        bytes: Vec::new(),
        reader: GatewayCaptureState::NotStarted,
        truncated: false,
        finalization: GatewayCaptureState::NotStarted,
    }
}
fn empty_outcome(reason: &str) -> GatewayNativeOutcome {
    GatewayNativeOutcome {
        dispatch: GatewayDispatch::NotStarted(reason.into()),
        execution: GatewayExecution::NotStarted,
        stdout: capture(),
        stderr: capture(),
        action: GatewayActionReport::NotInvoked,
        inspection: None,
    }
}
fn receiving(outcome: GatewayNativeOutcome) -> GatewayRunnerReceiving {
    GatewayRunnerReceiving {
        attempt_id: None,
        outcome,
        reports: Vec::new(),
        identity_errors: Vec::new(),
        observation_errors: Vec::new(),
        recorder_errors: Vec::new(),
        control_errors: Vec::new(),
        interpretation_errors: Vec::new(),
        policy_observations: Vec::new(),
        cancellation_received: false,
    }
}

fn address_applies(values: &[String], address: std::net::Ipv4Addr) -> Result<bool> {
    let mut unknown = Vec::new();
    for value in values {
        if value == "Any" {
            return Ok(true);
        }
        if let Ok(ip) = value.parse::<std::net::Ipv4Addr>() {
            if ip == address {
                return Ok(true);
            }
            continue;
        }
        if let Ok(net) = value.parse::<ipnet::Ipv4Net>() {
            if net.contains(&address) {
                return Ok(true);
            }
            continue;
        }
        if let Some((low, high)) = value.split_once('-') {
            if let (Ok(low), Ok(high)) = (
                low.parse::<std::net::Ipv4Addr>(),
                high.parse::<std::net::Ipv4Addr>(),
            ) {
                if low <= address && address <= high {
                    return Ok(true);
                }
                continue;
            }
        }
        unknown.push(value.clone());
    }
    if unknown.is_empty() {
        Ok(false)
    } else {
        Err(format!("unresolved native address selectors: {unknown:?}"))
    }
}
fn effective_policy(
    scope: &GatewayRuleScope,
    evidence: &GatewayPolicyEvidence,
) -> GatewayPolicyObservation {
    if let Err(error) =
        super::windows_installation::gateway_rules::active_profiles(evidence.active_profiles)
    {
        return GatewayPolicyObservation::PolicyDenied(error.to_string());
    }
    if evidence.local_modify_state != 0 {
        return GatewayPolicyObservation::PolicyDenied(format!(
            "native active profiles={} local policy modify state={}",
            evidence.active_profiles, evidence.local_modify_state
        ));
    }
    for mask in [1u32, 2, 4] {
        if evidence.active_profiles & mask == 0 {
            continue;
        }
        let profiles: Vec<_> = evidence
            .profiles
            .iter()
            .filter(|profile| profile.mask == mask)
            .collect();
        if profiles.len() != 1 || !profiles[0].enabled || profiles[0].block_all_inbound {
            return GatewayPolicyObservation::PolicyDenied(format!(
                "effective firewall profile {mask} unavailable/disabled/blocks inbound rules"
            ));
        }
    }
    for rule in &evidence.blocks {
        if !rule.enabled
            || rule.direction != "Inbound"
            || rule.action != "Block"
            || rule.profiles & evidence.active_profiles == 0
            || !matches!(rule.protocol.as_str(), "Any" | "256" | "TCP" | "6")
        {
            continue;
        }
        if rule.program.as_os_str() != "Any" {
            if rule.program.as_os_str().to_string_lossy().contains('%') {
                return GatewayPolicyObservation::Unavailable(format!(
                    "block {} has an unresolved environment-dependent program selector",
                    rule.name
                ));
            }
            match super::windows_installation::same_windows_path(&rule.program, &scope.host.path) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    return GatewayPolicyObservation::Unavailable(format!(
                        "block {} program receiving: {error}",
                        rule.name
                    ))
                }
            }
        }
        let local = address_applies(&rule.local_addresses, scope.namespace.local_address);
        let remote = address_applies(&rule.remote_addresses, scope.namespace.source_address);
        if matches!(local, Ok(false)) || matches!(remote, Ok(false)) {
            continue;
        }
        if let Err(error) = local.and(remote) {
            return GatewayPolicyObservation::Unavailable(format!("block {}: {error}", rule.name));
        }
        if !rule
            .interface_aliases
            .iter()
            .any(|alias| alias == "Any" || alias == &scope.namespace.interface_alias)
        {
            if rule
                .interface_aliases
                .iter()
                .any(|alias| alias.contains(['*', '?', '[', ']']))
            {
                return GatewayPolicyObservation::Unavailable(format!(
                    "block {} has unresolved interface wildcard",
                    rule.name
                ));
            }
            continue;
        }
        let unsupported: Vec<_> = evidence
            .unsupported_conditions
            .iter()
            .filter(|condition| condition.name == rule.name)
            .collect();
        if !unsupported.is_empty() {
            return GatewayPolicyObservation::Unavailable(format!(
                "overlapping block {} has unsupported native conditions: {unsupported:?}",
                rule.name
            ));
        }
        // A rule that overlaps this program/address/interface may cover one of
        // its kernel-selected ports. Conditional selectors are never ignored.
        if rule.interface_types != ["Any"]
            || rule.service != "Any"
            || !package_is_unrestricted(&rule.package)
            || rule.local_users != "Any"
            || rule.remote_users != "Any"
            || rule.remote_machines != "Any"
            || rule.authentication != "NotRequired"
            || rule.encryption != "NotRequired"
        {
            return GatewayPolicyObservation::Unavailable(format!(
                "block {} has unresolved service/user/interface/security applicability",
                rule.name
            ));
        }
        return GatewayPolicyObservation::ExplicitBlock(format!(
            "operative inbound block overlaps kernel-selected gateway ports: {}",
            rule.name
        ));
    }
    GatewayPolicyObservation::Allowed
}
fn request_scope(request: &GatewayRuleRequest) -> &GatewayRuleScope {
    match request {
        GatewayRuleRequest::Inspect { scope, .. }
        | GatewayRuleRequest::InspectOwned { scope, .. }
        | GatewayRuleRequest::Create { scope, .. }
        | GatewayRuleRequest::Remove { scope, .. } => scope,
    }
}
fn is_mutation(request: &GatewayRuleRequest) -> bool {
    !matches!(request, GatewayRuleRequest::Inspect { .. } | GatewayRuleRequest::InspectOwned { .. })
}

fn child_identity(child: &Child) -> Result<ProcessIdentity> {
    let current = unsafe { GetCurrentProcess() };
    let mut duplicate = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            current,
            child.as_raw_handle(),
            current,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(format!(
            "duplicate creator-owned process handle: {}",
            std::io::Error::last_os_error()
        ));
    }
    // The duplicate, not a later PID lookup, proves the child's native binding.
    ProcessIdentity::receive(unsafe { OwnedHandle::from_raw_handle(duplicate) })
}

struct NativeAttempt {
    child: Child,
    identity: Option<ProcessIdentity>,
    control: Option<ChildStdin>,
    readers: Vec<ReaderOwner>,
    events: Receiver<ReaderEvent>,
    received: GatewayRunnerReceiving,
    parsed: usize,
    go_sent: bool,
    call_sent: bool,
    done: bool,
    ready: bool,
    stopped: bool,
    exited: bool,
}
impl NativeAttempt {
    fn pipe(&mut self, pipe: Pipe) -> &mut GatewayCapture {
        match pipe {
            Pipe::Stdout => &mut self.received.outcome.stdout,
            Pipe::Stderr => &mut self.received.outcome.stderr,
        }
    }
    fn start_reader<T: Read + Send + 'static>(
        &mut self,
        pipe: Pipe,
        mut input: T,
        sender: mpsc::Sender<ReaderEvent>,
    ) {
        // The read buffer is a transfer chunk, never an evidence/output limit.
        let handle = thread::Builder::new()
            .name(format!("gateway-native-{pipe:?}"))
            .spawn(move || {
                let mut bytes = [0u8; 4096];
                loop {
                    match input.read(&mut bytes) {
                        Ok(0) => {
                            let _ = sender.send(ReaderEvent::End(pipe, None));
                            break;
                        }
                        Ok(count) => {
                            if sender
                                .send(ReaderEvent::Bytes(pipe, bytes[..count].to_vec()))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            let _ = sender.send(ReaderEvent::End(pipe, Some(error.to_string())));
                            break;
                        }
                    }
                }
            });
        match handle {
            Ok(handle) => {
                let capture = self.pipe(pipe);
                capture.reader = GatewayCaptureState::Pending;
                capture.finalization = GatewayCaptureState::Pending;
                self.readers.push(ReaderOwner {
                    pipe,
                    handle: Some(handle),
                });
            }
            Err(error) => {
                let capture = self.pipe(pipe);
                capture.reader =
                    GatewayCaptureState::Failed(format!("start native stream reader: {error}"));
                capture.finalization = GatewayCaptureState::Failed("reader was not created".into());
                self.stopped = true;
                self.control.take();
            }
        }
    }
    fn record(&mut self, record: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>) {
        if !self.received.recorder_errors.is_empty() {
            return;
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            record(&self.received.outcome)
        }));
        let failure = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(_) => Some("incremental native recorder panicked".into()),
        };
        if let Some(error) = failure {
            self.received.recorder_errors.push(error);
            self.stopped = true;
            self.control.take();
        }
    }
    fn send(&mut self, bytes: &[u8]) -> bool {
        let result = self
            .control
            .as_mut()
            .ok_or_else(|| "native control pipe unavailable".to_owned())
            .and_then(|control| {
                control
                    .write_all(bytes)
                    .and_then(|_| control.flush())
                    .map_err(|e| e.to_string())
            });
        match result {
            Ok(()) => true,
            Err(error) => {
                self.received.control_errors.push(error);
                self.stopped = true;
                self.control.take();
                false
            }
        }
    }
    fn protocol_failure(&mut self, error: String) {
        self.received.interpretation_errors.push(error);
        self.stopped = true;
        self.control.take();
    }
    fn parse_reports(&mut self, request: &GatewayRuleRequest) {
        loop {
            let remaining = &self.received.outcome.stdout.bytes[self.parsed..];
            let Some(end) = remaining.iter().position(|byte| *byte == b'\n') else {
                break;
            };
            let line = remaining[..end]
                .strip_suffix(b"\r")
                .unwrap_or(&remaining[..end]);
            let decoded = line
                .strip_prefix(REPORT_PREFIX)
                .ok_or_else(|| "unexpected bytes on private native report stream".to_owned())
                .and_then(|bytes| {
                    serde_json::from_slice::<GatewayNativeReport>(bytes)
                        .map_err(|e| format!("native report JSON: {e}"))
                });
            self.parsed += end + 1;
            let mut report = match decoded {
                Ok(report) => report,
                Err(error) => {
                    self.protocol_failure(error);
                    continue;
                }
            };
            if report.version != 1
                || self.received.attempt_id.as_deref() != Some(report.attempt_id.as_str())
                || self.done
            {
                self.protocol_failure(
                    "native report version/attempt/terminal sequence differs".into(),
                );
                self.received.reports.push(report);
                continue;
            }
            let valid_stage = match report.stage {
                GatewayNativeStage::ReadyToInvoke => {
                    is_mutation(request)
                        && self.go_sent
                        && !self.call_sent
                        && !self.ready
                        && report.action == GatewayActionReport::NotInvoked
                        && report.inspection.is_none()
                }
                GatewayNativeStage::Progress => {
                    self.go_sent
                        && matches!(report.action, GatewayActionReport::Unknown)
                        && (!is_mutation(request) || self.call_sent)
                }
                GatewayNativeStage::Done => match report.action {
                    GatewayActionReport::ReturnedSuccess => {
                        self.go_sent
                            && (!is_mutation(request) || self.call_sent)
                            && (report.inspection.is_some() != is_mutation(request))
                    }
                    GatewayActionReport::NotInvoked => {
                        !self.call_sent && report.inspection.is_none()
                    }
                    GatewayActionReport::ReturnedFailure { .. } | GatewayActionReport::Unknown => {
                        self.go_sent
                    }
                },
            };
            if !valid_stage {
                self.protocol_failure(
                    "native report is inconsistent with the actual control grants".into(),
                );
            } else {
                if let Some(evidence) = &report.policy_evidence {
                    let mut policy = effective_policy(request_scope(request), evidence);
                    let selected_name = match request {
                        GatewayRuleRequest::Inspect { name, .. } => name.as_deref(),
                        GatewayRuleRequest::InspectOwned { name, .. } => Some(name.as_str()),
                        GatewayRuleRequest::Create { name, .. } => Some(name.as_str()),
                        GatewayRuleRequest::Remove { persistent, .. } => {
                            Some(persistent.name.as_str())
                        }
                    };
                    if let Some(name) = selected_name {
                        let unsupported: Vec<_> = evidence
                            .unsupported_conditions
                            .iter()
                            .filter(|condition| condition.name == name)
                            .collect();
                        if !unsupported.is_empty() {
                            policy = GatewayPolicyObservation::Unavailable(format!(
                                "selected rule has unsupported native conditions: {unsupported:?}"
                            ));
                        }
                    } else if let Some(inspection) = report.inspection.as_mut() {
                        // Preparation can discover concrete external dependencies,
                        // but an unrepresentable conditional rule cannot be adopted.
                        // Preserve it in native policy evidence and leave it untouched.
                        inspection.persistent.retain(|rule| {
                            !evidence
                                .unsupported_conditions
                                .iter()
                                .any(|condition| condition.name == rule.name)
                        });
                        inspection.active.retain(|rule| {
                            !evidence
                                .unsupported_conditions
                                .iter()
                                .any(|condition| condition.name == rule.name)
                        });
                    }
                    if let Some(inspection) = report.inspection.as_mut() {
                        if inspection.active_profiles != evidence.active_profiles {
                            self.protocol_failure(
                                "native profile evidence differs from inspection".into(),
                            );
                        }
                        inspection.policy = policy.clone();
                    }
                    if report.stage == GatewayNativeStage::ReadyToInvoke
                        && policy != GatewayPolicyObservation::Allowed
                    {
                        self.stopped = true;
                        self.control.take();
                    }
                    self.received.policy_observations.push(policy);
                } else if !matches!(request, GatewayRuleRequest::InspectOwned { .. } | GatewayRuleRequest::Remove { .. })
                    && (report.stage == GatewayNativeStage::ReadyToInvoke
                    || (report.stage == GatewayNativeStage::Done && report.inspection.is_some()))
                {
                    self.protocol_failure(
                        "required native effective-policy evidence is absent".into(),
                    );
                }
                self.ready |= report.stage == GatewayNativeStage::ReadyToInvoke;
                self.done |= report.stage == GatewayNativeStage::Done;
                self.received.outcome.action = report.action.clone();
                if report.inspection.is_some() {
                    self.received.outcome.inspection = report.inspection.clone();
                }
            }
            self.received.reports.push(report);
        }
    }
    fn observe(&mut self, request: &GatewayRuleRequest) -> bool {
        let mut changed = false;
        loop {
            match self.events.try_recv() {
                Ok(ReaderEvent::Bytes(pipe, bytes)) => {
                    self.pipe(pipe).bytes.extend_from_slice(&bytes);
                    changed = true;
                }
                Ok(ReaderEvent::End(pipe, error)) => {
                    if error.is_some() {
                        self.stopped = true;
                        self.control.take();
                    }
                    self.pipe(pipe).reader = match error {
                        Some(error) => GatewayCaptureState::Failed(error),
                        None => GatewayCaptureState::Complete,
                    };
                    changed = true;
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        if changed {
            self.parse_reports(request);
        }
        for index in 0..self.readers.len() {
            if self.readers[index]
                .handle
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                let pipe = self.readers[index].pipe;
                let handle = self.readers[index].handle.take().unwrap();
                match handle.join() {
                    Ok(()) => self.pipe(pipe).finalization = GatewayCaptureState::Complete,
                    Err(_) => {
                        self.pipe(pipe).finalization =
                            GatewayCaptureState::Failed("native stream reader panicked".into());
                        self.pipe(pipe).reader =
                            GatewayCaptureState::Failed("reader completion unavailable".into());
                        self.stopped = true;
                        self.control.take();
                    }
                }
                changed = true;
            }
        }
        if !self.exited {
            if let Some(identity) = &self.identity {
                if let Err(error) = identity.recheck() {
                    if !self.received.identity_errors.contains(&error) {
                        self.received.identity_errors.push(error);
                        changed = true;
                    }
                    self.stopped = true;
                    self.control.take();
                }
            }
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.exited = true;
                    self.control.take();
                    self.received.outcome.execution = GatewayExecution::Exited {
                        code: status.code(),
                    };
                    changed = true;
                }
                Ok(None) => {}
                Err(error) => {
                    let message = format!("observe creator-owned native child: {error}");
                    if !self.received.observation_errors.contains(&message) {
                        self.received.observation_errors.push(message.clone());
                        self.received.outcome.execution =
                            GatewayExecution::ObservationError(message);
                        changed = true;
                    }
                    self.stopped = true;
                    self.control.take();
                }
            }
        }
        changed
    }
    fn physically_settled(&self) -> bool {
        self.exited && self.readers.iter().all(|reader| reader.handle.is_none())
    }
    fn finish_protocol(&mut self) {
        if self.parsed != self.received.outcome.stdout.bytes.len() {
            self.protocol_failure("unterminated native report bytes".into());
        }
        if !self.done {
            self.protocol_failure("native terminal action report unavailable".into());
        }
        if !self.received.interpretation_errors.is_empty() {
            // Reader completion remains separate. This is finalization of the
            // captured report channel, including its required wire receiving.
            self.received.outcome.stdout.finalization =
                GatewayCaptureState::Failed(self.received.interpretation_errors.join("; "));
        }
    }
}
impl Drop for NativeAttempt {
    fn drop(&mut self) {
        // Unwinding must not detach a started child or readers. Closing the
        // grant pipe prevents an as-yet uninvoked action; an invoked native call
        // retires naturally. No PID-based stop or invented timeout exists.
        self.control.take();
        while !self.exited {
            match self.child.try_wait() {
                Ok(Some(_)) => self.exited = true,
                _ => thread::park_timeout(super::OWNER_OBSERVATION_CADENCE),
            }
        }
        for reader in &mut self.readers {
            if let Some(handle) = reader.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

impl GatewayRuleRunner for WindowsGatewayRuleRunner {
    fn run(
        &mut self,
        request: &GatewayRuleRequest,
        cancel: &AtomicBool,
        record: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>,
    ) -> GatewayNativeOutcome {
        let mut before = receiving(empty_outcome("native preparation not started"));
        let preparation = (|| {
            if cancel.load(Ordering::SeqCst) {
                before.cancellation_received = true;
                return Err("cancelled before native dispatch".into());
            }
            let attempt_id = (self.next_attempt_id)()?;
            super::windows_installation::validate_request_id(&attempt_id)?;
            if self
                .receiving
                .iter()
                .any(|previous| previous.attempt_id.as_deref() == Some(attempt_id.as_str()))
            {
                return Err("native UUID owner reused a retained attempt ID".into());
            }
            before.attempt_id = Some(attempt_id.clone());
            self.program.recheck()?;
            let scope = request_scope(request);
            let host =
                CheckedPath::open(&scope.host.path, PathKind::File, PathPurpose::Executable)?;
            if host.native_id() != scope.host.native_id
                || hex::encode(Sha256::digest(host.read_snapshot()?)) != scope.host.sha256
            {
                return Err("native request host incarnation differs".into());
            }
            let input = serde_json::to_vec(&NativeInput {
                version: 1,
                attempt_id: &attempt_id,
                request,
                parameters: scope.creation_parameters(),
            })
            .map_err(|e| format!("native request serialization: {e}"))?;
            Ok((attempt_id, host, input))
        })();
        let (attempt_id, _host_pin, input) = match preparation {
            Ok(value) => value,
            Err(error) => {
                before.outcome.dispatch = GatewayDispatch::NotStarted(error);
                if let Err(error) = record(&before.outcome) {
                    before.recorder_errors.push(error);
                }
                let outcome = before.outcome.clone();
                self.receiving.push(before);
                return outcome;
            }
        };
        let mut command = Command::new(self.program.as_path());
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                self.script,
            ])
            .env(
                "PSModulePath",
                self.program.as_path().parent().unwrap().join("Modules"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(0x0800_0000);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                before.outcome.dispatch =
                    GatewayDispatch::NotStarted(format!("spawn pinned native PowerShell: {error}"));
                if let Err(error) = record(&before.outcome) {
                    before.recorder_errors.push(error);
                }
                let outcome = before.outcome.clone();
                self.receiving.push(before);
                return outcome;
            }
        };
        let identity = match child_identity(&child) {
            Ok(identity) => Some(identity),
            Err(error) => {
                before.identity_errors.push(error);
                None
            }
        };
        before.outcome.dispatch = GatewayDispatch::Started {
            attempt_id: attempt_id.clone(),
            process_id: child.id(),
            creation_time: identity.as_ref().map(ProcessIdentity::creation),
            image: identity
                .as_ref()
                .map(|identity| identity.image().to_owned()),
        };
        before.outcome.execution = GatewayExecution::Pending;
        before.outcome.action = GatewayActionReport::Unknown;
        let control = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, events) = mpsc::channel();
        let mut attempt = NativeAttempt {
            child,
            identity,
            control,
            readers: Vec::new(),
            events,
            received: before,
            parsed: 0,
            go_sent: false,
            call_sent: false,
            done: false,
            ready: false,
            stopped: false,
            exited: false,
        };
        attempt.start_reader(Pipe::Stdout, stdout, sender.clone());
        #[cfg(not(test))]
        attempt.start_reader(Pipe::Stderr, stderr, sender.clone());
        #[cfg(test)]
        if self.reader_fault == Some(Pipe::Stderr) {
            attempt.start_reader(Pipe::Stderr, FailingReader(stderr), sender.clone());
        } else {
            attempt.start_reader(Pipe::Stderr, stderr, sender.clone());
        }
        drop(sender);
        attempt.record(record);
        if !attempt.received.identity_errors.is_empty() {
            attempt.stopped = true;
            attempt.control.take();
        }
        if cancel.load(Ordering::SeqCst) {
            attempt.received.cancellation_received = true;
            attempt.stopped = true;
            attempt.control.take();
        }
        if !attempt.stopped {
            let mut bytes = input;
            bytes.push(b'\n');
            bytes.extend_from_slice(format!("GO {attempt_id}\n").as_bytes());
            attempt.go_sent = attempt.send(&bytes);
            if !is_mutation(request) {
                attempt.control.take();
            }
        }
        loop {
            let changed = attempt.observe(request);
            if cancel.load(Ordering::SeqCst) && !attempt.received.cancellation_received {
                attempt.received.cancellation_received = true;
                attempt.stopped = true;
                attempt.control.take();
            }
            if changed {
                attempt.record(record);
            }
            if attempt.ready && !attempt.call_sent && !attempt.stopped {
                // The complete Ready report, its acquired native outcome and
                // any capture state are recorded before the one mutation grant.
                if cancel.load(Ordering::SeqCst) {
                    attempt.received.cancellation_received = true;
                    attempt.stopped = true;
                    attempt.control.take();
                }
                if !attempt.stopped {
                    attempt.call_sent = attempt.send(format!("CALL {attempt_id}\n").as_bytes());
                }
            }
            if attempt.physically_settled() {
                // Joined readers may have queued their final chunks after the
                // preceding drain. Receive those bytes before finalizing.
                if attempt.observe(request) {
                    attempt.record(record);
                }
                break;
            }
            thread::park_timeout(super::OWNER_OBSERVATION_CADENCE);
        }
        attempt.finish_protocol();
        attempt.record(record);
        if let Err(error) = self.program.recheck() {
            attempt.received.identity_errors.push(error);
        }
        let outcome = attempt.received.outcome.clone();
        self.receiving.push(attempt.received.clone());
        outcome
    }
}

// Fixed inspected source. Variable data arrives as typed JSON on private stdin.
const NATIVE_SCRIPT: &str = r#"& {
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$utf8=[Text.UTF8Encoding]::new($false)
[Console]::InputEncoding=$utf8; [Console]::OutputEncoding=$utf8
$x=$null; $action=[ordered]@{state='notInvoked'}; $inspection=$null; $policyEvidence=$null
function Report([string]$stage,$diagnostic) {
 $o=[ordered]@{version=1;attemptId=[string]$x.attemptId;stage=$stage;action=$action;inspection=$inspection;diagnostic=$diagnostic;policyEvidence=$policyEvidence}
 [Console]::Out.WriteLine('AG_GATEWAY_NATIVE_V1 '+($o|ConvertTo-Json -Depth 100 -Compress)); [Console]::Out.Flush()
}
function Diagnostic($e) {
 $code=[string]$e.FullyQualifiedErrorId
 $kind=if([string]$e.CategoryInfo.Category -in @('PermissionDenied','SecurityError') -or $e.Exception -is [UnauthorizedAccessException]){'permission'}
 elseif($code -in @('FreshGatewayInterfaceChanged','FreshGatewayLocalAddressChanged','IntendedNativeRuleNameOccupied','NativeRemovalPreimageMissingOrAmbiguous','NativeRemovalPreimageChangedPreserved')){'missingConfiguration'}
 elseif($code -like 'NativePropertyUnavailable:*' -or $code -like 'NativeFilterAmbiguous:*' -or $code -in @('NativeInputShapeInvalid','NativeInterfaceTypeParameterShapeInvalid','NativePreimageShapeChanged','NativePackageRestrictionUnsupported')){'capture'}
 else{'native'}
 [ordered]@{kind=[ordered]@{state=$kind};message=([string]$e.FullyQualifiedErrorId+': '+[string]$e)}
}
function Required($o,[string]$name) {
 $p=$o.PSObject.Properties[$name]; if($null -eq $p){throw "NativePropertyUnavailable:$name"}; $p.Value
}
function OptionalText($o,[string]$name) {
 $p=$o.PSObject.Properties[$name]; if($null -eq $p -or $null -eq $p.Value){return $null}; [string]$p.Value
}
function One($values,[string]$label) {
 $a=@($values); if($a.Count -ne 1){throw "NativeFilterAmbiguous:$label"}; $a[0]
}
function PackageValue($application) {
 # Present native CIM String-null is default None, not a missing property.
 # Reject shape loss before the existing [string] wire projection below.
 $property=$application.PSObject.Properties['Package']
 if($null -eq $property){throw 'NativePropertyUnavailable:Package'}
 # Read Value directly: a function pipeline would enumerate an invalid empty
 # array into null before its shape could be rejected.
 $value=$property.Value
 try { $native=$application.CimInstanceProperties['Package']; $type=if($null -ne $native){[string]$native.CimType}else{$null} }
 catch { throw 'NativePropertyUnavailable:PackageCimType' }
 if($null -eq $native -or $type -cne 'String'){throw 'NativePropertyUnavailable:PackageCimType'}
 if(($null -ne $native.Value -and $native.Value -isnot [string]) -or ($null -ne $value -and $value -isnot [string])){throw 'NativePropertyUnavailable:PackageValueShape'}
 $value
}
function NativeRule($r,[string]$store,$unsupported) {
 $a=One @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -PolicyStore $store -ErrorAction Stop) 'application'
 $p=One @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -PolicyStore $store -ErrorAction Stop) 'port'
 $n=One @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -PolicyStore $store -ErrorAction Stop) 'address'
 $i=One @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $r -PolicyStore $store -ErrorAction Stop) 'interface'
 $t=One @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $r -PolicyStore $store -ErrorAction Stop) 'interfaceType'
 $s=One @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $r -PolicyStore $store -ErrorAction Stop) 'service'
 $q=One @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $r -PolicyStore $store -ErrorAction Stop) 'security'
 foreach($entry in @(@($r,'Platform'),@($r,'PolicyAppId'),@($r,'PackageFamilyName'),@($p,'DynamicTarget'),@($n,'RemoteDynamicKeywordAddresses'))) {
  $prop=$entry[0].PSObject.Properties[[string]$entry[1]]
  if($null -ne $prop){$values=@($prop.Value|Where-Object {$null -ne $_ -and [string]$_ -ne '' -and [string]$_ -ne 'Any'});if($values.Count){$unsupported.Add([ordered]@{name=[string]$r.Name;field=[string]$entry[1];values=@($values|ForEach-Object {[string]$_})})}}
 }
 foreach($name in @('LooseSourceMapping','LocalOnlyMapping')){$prop=$r.PSObject.Properties[$name];if($null -ne $prop -and [bool]$prop.Value){$unsupported.Add([ordered]@{name=[string]$r.Name;field=$name;values=@('True')})}}
 [ordered]@{
  name=[string](Required $r 'Name');instanceId=(OptionalText $r 'InstanceID');policyStoreSource=(OptionalText $r 'PolicyStoreSource');policyStoreSourceType=(OptionalText $r 'PolicyStoreSourceType')
  enabled=[Convert]::ToBoolean([string](Required $r 'Enabled'));direction=[string](Required $r 'Direction');action=[string](Required $r 'Action')
  program=[string](Required $a 'Program');protocol=[string](Required $p 'Protocol');localPorts=@(Required $p 'LocalPort'|ForEach-Object {[string]$_});remotePorts=@(Required $p 'RemotePort'|ForEach-Object {[string]$_})
  localAddresses=@(Required $n 'LocalAddress'|ForEach-Object {[string]$_});remoteAddresses=@(Required $n 'RemoteAddress'|ForEach-Object {[string]$_})
  interfaceAliases=@(Required $i 'InterfaceAlias'|ForEach-Object {[string]$_});interfaceTypes=@(Required $t 'InterfaceType'|ForEach-Object {[string]$_})
  profiles=[uint32](Required $r 'Profile');edgeTraversal=[string](Required $r 'EdgeTraversalPolicy');service=[string](Required $s 'Service');package=[string](PackageValue $a)
  localUsers=[string](Required $q 'LocalUser');remoteUsers=[string](Required $q 'RemoteUser');remoteMachines=[string](Required $q 'RemoteMachine')
  authentication=[string](Required $q 'Authentication');encryption=[string](Required $q 'Encryption');overrideBlockRules=[bool](Required $q 'OverrideBlockRules')
 }
}
function NamedRules([string]$store,[string]$name) {
 # No wildcard Name input, missing-query catch or discarded native error.
 @(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop|Where-Object {[string]$_.Name -ceq $name})
}
function ActiveEnforcement($r) {
 # Effect is optional observation, never a structural default. Read raw CIM
 # UInt16/UInt16Array from this exact row, not adapted/localized display text.
 $primary=$null; $enforcement=$null
 try {
  $p=$r.CimInstanceProperties['PrimaryStatus']
  if($null -ne $p -and [string]$p.CimType -ceq 'UInt16' -and $p.Value -is [uint16]){$primary=[uint16]$p.Value}
 } catch { $primary=$null }
 try {
  $p=$r.CimInstanceProperties['EnforcementStatus']
  if($null -ne $p -and [string]$p.CimType -ceq 'UInt16Array' -and $p.Value -is [uint16[]]){$enforcement=@($p.Value|ForEach-Object {[uint16]$_})}
 } catch { $enforcement=$null }
 [ordered]@{name=[string](Required $r 'Name');instanceId=(OptionalText $r 'InstanceID');primaryStatus=$primary;enforcementStatus=$enforcement}
}
function Rules([string]$store,$name,$unsupported) {
 $raw=if($null -ne $name){@(NamedRules $store ([string]$name))}else{
  $apps=@(Get-NetFirewallApplicationFilter -PolicyStore $store -ErrorAction Stop|Where-Object {[StringComparer]::OrdinalIgnoreCase.Equals([string]$_.Program,[string]$x.parameters.program)})
  @(foreach($app in $apps){Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $app -PolicyStore $store -ErrorAction Stop})
 }
 # The same retained CIM objects supply normalized snapshots and effect facts.
 [ordered]@{rules=@(foreach($r in $raw){NativeRule $r $store $unsupported});enforcement=if($store -ceq 'ActiveStore'){@(foreach($r in $raw){ActiveEnforcement $r})}else{$null}}
}
function Environment($name) {
 $ns=$x.request.scope.namespace
 $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop|Where-Object {[uint32]$_.ifIndex -eq [uint32]$ns.interfaceIndex -and [string]$_.Status -eq 'Up'})
 if($adapters.Count -ne 1 -or [string]$adapters[0].Name -cne [string]$ns.interfaceAlias){throw 'FreshGatewayInterfaceChanged'}
 $ips=@(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex ([uint32]$ns.interfaceIndex) -ErrorAction Stop|Where-Object {[string]$_.IPAddress -ceq [string]$ns.localAddress -and [string]$_.AddressState -eq 'Preferred'})
 if($ips.Count -ne 1){throw 'FreshGatewayLocalAddressChanged'}
 $fw=New-Object -ComObject HNetCfg.FwPolicy2
 $active=[uint32]$fw.CurrentProfileTypes
 $profiles=@(foreach($mask in @(1,2,4)){if($active -band $mask){[ordered]@{mask=[uint32]$mask;enabled=[bool]$fw.FirewallEnabled($mask);blockAllInbound=[bool]$fw.BlockAllInboundTraffic($mask)}}})
 $unsupported=[Collections.Generic.List[object]]::new()
 $persistentRows=Rules 'PersistentStore' $name $unsupported;$activeRows=Rules 'ActiveStore' $name $unsupported
 $persistent=@($persistentRows.rules);$operative=@($activeRows.rules)
 $blocks=@(foreach($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Block -ErrorAction Stop)){NativeRule $r 'ActiveStore' $unsupported})
 $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
 [ordered]@{
  policyEvidence=[ordered]@{activeProfiles=$active;localModifyState=[int]$fw.LocalPolicyModifyState;profiles=$profiles;blocks=$blocks;unsupportedConditions=@($unsupported)}
  inspection=[ordered]@{administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);activeProfiles=$active
   namespace=[ordered]@{interfaceIndex=[uint32]$adapters[0].ifIndex;interfaceAlias=[string]$adapters[0].Name;localAddress=[string]$ips[0].IPAddress;sourceAddress=[string]$ns.sourceAddress}
   policy=[ordered]@{state='unavailable';detail='native policy facts awaiting caller receiving'};persistent=$persistent;active=$operative;activeEnforcement=@($activeRows.enforcement)}
 }
}
function OwnedEnvironment($name) {
 if([string]::IsNullOrEmpty([string]$name)){throw 'NativeOwnedNameMissing'}
 $fw=New-Object -ComObject HNetCfg.FwPolicy2
 $active=[uint32]$fw.CurrentProfileTypes
 $unsupported=[Collections.Generic.List[object]]::new()
 $persistentRows=Rules 'PersistentStore' $name $unsupported;$activeRows=Rules 'ActiveStore' $name $unsupported
 if($unsupported.Count){throw 'NativeOwnedRuleUnsupportedConditions'}
 $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
 [ordered]@{administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);activeProfiles=$active
  namespace=$null;policy=[ordered]@{state='unavailable';detail='historical custody inspection; no live transport admission'}
  persistent=@($persistentRows.rules);active=@($activeRows.rules)}
}
function SamePreimage($actual,$expected) {
 # This is native preimage equality, using received keys rather than a second
 # scope predicate or an assumption about cross-language JSON member order.
 $ordered=[ordered]@{}
 foreach($p in $expected.PSObject.Properties){if(!$actual.Contains($p.Name)){throw 'NativePreimageShapeChanged'};$ordered[$p.Name]=$actual[$p.Name]}
 if($actual.Count -ne $ordered.Count){throw 'NativePreimageShapeChanged'}
 (($ordered|ConvertTo-Json -Depth 100 -Compress) -ceq ($expected|ConvertTo-Json -Depth 100 -Compress))
}
try {
 $line=[Console]::ReadLine();if($null -eq $line){[Console]::Error.WriteLine('NativeInputNotReceived');exit 3}
 $x=$line|ConvertFrom-Json -ErrorAction Stop
  if($x.version -ne 1 -or [string]::IsNullOrEmpty([string]$x.attemptId) -or [string]$x.request.action -notin @('inspect','inspectOwned','create','remove')){throw 'NativeInputShapeInvalid'}
 if($x.request.action -eq 'create' -and [string](Required $x.parameters 'package') -cne 'Any'){throw 'NativePackageRestrictionUnsupported'}
 if([Console]::ReadLine() -cne ('GO '+[string]$x.attemptId)){Report 'done' $null;exit 0}
 foreach($module in @('NetSecurity','NetAdapter','NetTCPIP')){Import-Module -Name (Join-Path $PSHOME ('Modules\'+$module+'\'+$module+'.psd1')) -ErrorAction Stop}
 if($x.request.action -eq 'inspect') {
  $action=[ordered]@{state='unknown'};Report 'progress' $null
  $environment=Environment $x.request.name;$inspection=$environment.inspection;$policyEvidence=$environment.policyEvidence
  $action=[ordered]@{state='returnedSuccess'};Report 'done' $null;exit 0
 }
  if($x.request.action -eq 'inspectOwned') {
   $action=[ordered]@{state='unknown'};Report 'progress' $null
   $inspection=OwnedEnvironment $x.request.name
   $action=[ordered]@{state='returnedSuccess'};Report 'done' $null;exit 0
  }
 $name=if($x.request.action -eq 'create'){[string]$x.request.name}else{[string]$x.request.persistent.name}
  if($x.request.action -eq 'create'){$prepared=Environment $name;$policyEvidence=$prepared.policyEvidence;$preparedInspection=$prepared.inspection}
  else {$preparedInspection=OwnedEnvironment $name}
  if(!$preparedInspection.administrator){Report 'done' ([ordered]@{kind=[ordered]@{state='permission'};message='native administrator capability unavailable before invocation'});exit 0}
  if($x.request.action -eq 'create' -and (@($preparedInspection.persistent).Count -or @($preparedInspection.active).Count)){throw 'IntendedNativeRuleNameOccupied'}
 Report 'readyToInvoke' $null
 if([Console]::ReadLine() -cne ('CALL '+[string]$x.attemptId)){Report 'done' $null;exit 0}
 if($x.request.action -eq 'create') {
  $p=$x.parameters
  if(@($p.interfaceTypes).Count -ne 1){throw 'NativeInterfaceTypeParameterShapeInvalid'}
  $aliases=@($p.interfaceAliases|ForEach-Object {[Management.Automation.WildcardPattern]::Escape([string]$_)})
  $action=[ordered]@{state='unknown'};Report 'progress' $null
  $null=New-NetFirewallRule -Name $name -DisplayName $name -PolicyStore PersistentStore -Enabled ([string]$p.enabled) -Direction ([string]$p.direction) -Action ([string]$p.action) -Profile ([uint32]$p.profiles) -Program ([string]$p.program) -Protocol ([string]$p.protocol) -LocalPort ([string[]]$p.localPorts) -RemotePort ([string[]]$p.remotePorts) -LocalAddress ([string[]]$p.localAddresses) -RemoteAddress ([string[]]$p.remoteAddresses) -InterfaceAlias $aliases -InterfaceType ([string]$p.interfaceTypes[0]) -EdgeTraversalPolicy ([string]$p.edgeTraversal) -Service ([string]$p.service) -LocalUser ([string]$p.localUsers) -RemoteUser ([string]$p.remoteUsers) -RemoteMachine ([string]$p.remoteMachines) -Authentication ([string]$p.authentication) -Encryption ([string]$p.encryption) -OverrideBlockRules ([bool]$p.overrideBlockRules) -ErrorAction Stop
 } else {
  $unsupported=[Collections.Generic.List[object]]::new()
  $persistent=@(NamedRules 'PersistentStore' $name);$active=@(NamedRules 'ActiveStore' $name)
  if($persistent.Count -ne 1 -or $active.Count -ne 1){throw 'NativeRemovalPreimageMissingOrAmbiguous'}
  $p=NativeRule $persistent[0] 'PersistentStore' $unsupported;$a=NativeRule $active[0] 'ActiveStore' $unsupported
  if($unsupported.Count -or !(SamePreimage $p $x.request.persistent) -or !(SamePreimage $a $x.request.active)){throw 'NativeRemovalPreimageChangedPreserved'}
  $action=[ordered]@{state='unknown'};Report 'progress' $null
  $null=Remove-NetFirewallRule -InputObject $persistent -Confirm:$false -ErrorAction Stop
 }
 $action=[ordered]@{state='returnedSuccess'};$policyEvidence=$null;Report 'done' $null;exit 0
} catch {
 $diagnostic=Diagnostic $_
 [Console]::Error.WriteLine([string]$diagnostic.message)
 if($action.state -eq 'unknown'){$action=[ordered]@{state='returnedFailure';detail=$diagnostic}}
 try {Report 'done' $diagnostic} catch {[Console]::Error.WriteLine('NativeTerminalReportUnavailable: '+[string]$_)}
 exit 1
}
}"#;

#[cfg(test)]
struct FailingReader<T>(T);
#[cfg(test)]
impl<T: Read> Read for FailingReader<T> {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other(
            "controlled native-reader I/O failure",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn package_semantics_are_shared_with_block_policy_without_erasing_restrictions() {
        let scope = scope();
        let mut wire = serde_json::to_value(scope.creation_parameters()).unwrap();
        wire["name"] = "synthetic-block".into(); wire["instanceId"] = serde_json::Value::Null;
        wire["policyStoreSource"] = serde_json::Value::Null; wire["policyStoreSourceType"] = serde_json::Value::Null;
        wire["action"] = "Block".into();
        let block: GatewayNativeRule = serde_json::from_value(wire).unwrap();
        let mut evidence = GatewayPolicyEvidence { active_profiles: 2, local_modify_state: 0,
            profiles: vec![GatewayProfileEvidence { mask: 2, enabled: true, block_all_inbound: false }],
            blocks: vec![block], unsupported_conditions: Vec::new() };
        for value in ["", "Any"] {
            evidence.blocks[0].package = value.into();
            assert!(matches!(effective_policy(&scope, &evidence), GatewayPolicyObservation::ExplicitBlock(_)));
            assert_eq!(evidence.blocks[0].package, value);
        }
        for value in ["S-1-15-2-123456789", " ", "any"] {
            evidence.blocks[0].package = value.into();
            assert!(matches!(effective_policy(&scope, &evidence), GatewayPolicyObservation::Unavailable(_)));
            assert_eq!(evidence.blocks[0].package, value);
        }
    }

    #[test]
    #[ignore = "Root-owned package shape/projection fixture; production functions only, no firewall calls"]
    fn native_package_guard_preserves_present_typed_null_and_rejects_shape_loss() {
        let functions = &NATIVE_SCRIPT[NATIVE_SCRIPT.find("function Required(").unwrap()..NATIVE_SCRIPT.find("function NativeRule(").unwrap()];
        let script = format!("& {{ $ErrorActionPreference='Stop'; Set-StrictMode -Version Latest; {functions} {} }}", r#"
$cases=@(
 [pscustomobject]@{Name='null';Input=[pscustomobject]@{Package=$null;CimInstanceProperties=@{Package=[pscustomobject]@{CimType='String';Value=$null}}}},
 [pscustomobject]@{Name='empty';Input=[pscustomobject]@{Package='';CimInstanceProperties=@{Package=[pscustomobject]@{CimType='String';Value=''}}}},
 [pscustomobject]@{Name='any';Input=[pscustomobject]@{Package='Any';CimInstanceProperties=@{Package=[pscustomobject]@{CimType='String';Value='Any'}}}},
 [pscustomobject]@{Name='sid';Input=[pscustomobject]@{Package='S-1-15-2-123456789';CimInstanceProperties=@{Package=[pscustomobject]@{CimType='String';Value='S-1-15-2-123456789'}}}},
 [pscustomobject]@{Name='missing-property';Input=[pscustomobject]@{CimInstanceProperties=@{Package=[pscustomobject]@{CimType='String';Value=$null}}}},
 [pscustomobject]@{Name='missing-cim';Input=[pscustomobject]@{Package=$null}},
 [pscustomobject]@{Name='wrong-cim';Input=[pscustomobject]@{Package=$null;CimInstanceProperties=@{Package=[pscustomobject]@{CimType='UInt16';Value=[uint16]0}}}},
 [pscustomobject]@{Name='number';Input=[pscustomobject]@{Package=0;CimInstanceProperties=@{Package=[pscustomobject]@{CimType='String';Value=0}}}},
 [pscustomobject]@{Name='empty-adapted-array';Input=[pscustomobject]@{Package=@();CimInstanceProperties=@{Package=[pscustomobject]@{CimType='String';Value=$null}}}},
 [pscustomobject]@{Name='native-array';Input=[pscustomobject]@{Package=$null;CimInstanceProperties=@{Package=[pscustomobject]@{CimType='String';Value=@()}}}}
)
$results=@(foreach($case in $cases){try{$wire=[string](PackageValue $case.Input);[ordered]@{name=$case.Name;ok=$true;wire=$wire}}catch{[ordered]@{name=$case.Name;ok=$false;error=[string]$_}}})
$results|ConvertTo-Json -Depth 8 -Compress
"#);
        let program = super::super::system_powershell_program().unwrap();
        let output = Command::new(program.as_path()).args(["-NoLogo","-NoProfile","-NonInteractive","-Command",&script]).output().unwrap();
        assert!(output.status.success(), "{:?}", String::from_utf8_lossy(&output.stderr));
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(rows.len(), 10);
        for (row, expected) in rows[..4].iter().zip(["", "", "Any", "S-1-15-2-123456789"]) {
            assert_eq!(row["ok"], true); assert_eq!(row["wire"], expected);
        }
        for row in &rows[4..] { assert_eq!(row["ok"], false, "{row}"); }
    }

    #[test]
    fn unrestricted_package_is_absent_from_create_but_read_normalization_stays_any() {
        assert_eq!(scope().creation_parameters().package, "Any");
        let create = NATIVE_SCRIPT.lines().find(|line| line.contains("$null=New-NetFirewallRule ")).unwrap();
        assert!(!create.contains("-Package"));
        let actual: Vec<_> = create.split_whitespace().filter(|part| part.starts_with('-')).collect();
        assert_eq!(actual, ["-Name","-DisplayName","-PolicyStore","-Enabled","-Direction","-Action","-Profile","-Program","-Protocol","-LocalPort","-RemotePort","-LocalAddress","-RemoteAddress","-InterfaceAlias","-InterfaceType","-EdgeTraversalPolicy","-Service","-LocalUser","-RemoteUser","-RemoteMachine","-Authentication","-Encryption","-OverrideBlockRules","-ErrorAction"]);
        assert!(NATIVE_SCRIPT.contains("package=[string](PackageValue $a)"));
        assert!(NATIVE_SCRIPT.find("throw 'NativePackageRestrictionUnsupported'").unwrap()
            < NATIVE_SCRIPT.find("if([Console]::ReadLine() -cne ('GO '").unwrap());
    }

    #[test]
    #[ignore = "Root-owned native parser guard; rejects before GO and imports, no firewall calls"]
    fn genuine_package_restriction_is_rejected_before_native_invocation() {
        let request = create_request();
        let mut input = serde_json::to_value(NativeInput { version: 1, attempt_id: "synthetic-package-rejection", request: &request, parameters: request_scope(&request).creation_parameters() }).unwrap();
        input["parameters"]["package"] = "S-1-15-2-123456789".into();
        let program = super::super::system_powershell_program().unwrap();
        let mut child = Command::new(program.as_path()).args(["-NoLogo","-NoProfile","-NonInteractive","-Command",NATIVE_SCRIPT])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut bytes = serde_json::to_vec(&input).unwrap(); bytes.push(b'\n');
        child.stdin.as_mut().unwrap().write_all(&bytes).unwrap();
        // EOF, not GO/CALL: even a failing candidate cannot invoke a cmdlet.
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        let reports: Vec<_> = output.stdout.split(|b| *b == b'\n').filter_map(|line| line.strip_prefix(REPORT_PREFIX)).collect();
        assert_eq!(reports.len(), 1);
        let report: GatewayNativeReport = serde_json::from_slice(reports[0]).unwrap();
        assert_eq!(report.stage, GatewayNativeStage::Done);
        assert_eq!(report.action, GatewayActionReport::NotInvoked);
        assert!(report.diagnostic.unwrap().message.contains("NativePackageRestrictionUnsupported"));
    }

    // Execute the production script and its actual dispatch/control branches.
    // Only operating-system facts and native effects are replaced. In particular,
    // Environment, OwnedEnvironment, Rules, NativeRule and SamePreimage remain
    // the production functions, and no real firewall command can be reached.
    #[test]
    #[ignore = "Root-owned production-script test with synthetic Windows facts; no real firewall mutation"]
    fn stale_interface_owned_inspection_and_exact_removal_use_production_script() {
        const FACTS: &str = r#"
function Import-Module { [CmdletBinding()] param($Name) }
function Get-NetAdapter { [CmdletBinding()] param([switch]$IncludeHidden) }
function Get-NetIPAddress { [CmdletBinding()] param($AddressFamily,$InterfaceIndex) throw 'UnexpectedOldAddressQuery' }
function New-Object { [CmdletBinding()] param($ComObject) if($ComObject -cne 'HNetCfg.FwPolicy2'){throw 'UnexpectedComObject'}; [pscustomobject]@{CurrentProfileTypes=2} }
function Get-NetFirewallRule {
 [CmdletBinding()] param($PolicyStore,$Enabled,$Direction,$Action,$AssociatedNetFirewallApplicationFilter)
 if($null -ne $Enabled){return}
 $r=[pscustomobject]@{Name='synthetic-owned';InstanceID='synthetic-instance';PolicyStoreSource='synthetic-store';PolicyStoreSourceType='synthetic-source';Enabled='True';Direction='Inbound';Action='Allow';Profile=6;EdgeTraversalPolicy='Block'}
 if($x.request.action -eq 'remove' -and $x.request.persistent.name -ceq 'synthetic-ambiguous'){$r.Name='synthetic-ambiguous';$r;$r;return};$r
}
function Get-NetFirewallApplicationFilter { [CmdletBinding()] param($AssociatedNetFirewallRule,$PolicyStore); [pscustomobject]@{Program=[string]$x.parameters.program;Package='Any';CimInstanceProperties=@{Package=[pscustomobject]@{CimType='String';Value='Any'}}} }
function Get-NetFirewallPortFilter { [CmdletBinding()] param($AssociatedNetFirewallRule,$PolicyStore); [pscustomobject]@{Protocol='TCP';LocalPort=@('Any');RemotePort=@('Any')} }
function Get-NetFirewallAddressFilter { [CmdletBinding()] param($AssociatedNetFirewallRule,$PolicyStore); [pscustomobject]@{LocalAddress=@($x.parameters.localAddresses);RemoteAddress=@($x.parameters.remoteAddresses)} }
function Get-NetFirewallInterfaceFilter { [CmdletBinding()] param($AssociatedNetFirewallRule,$PolicyStore); [pscustomobject]@{InterfaceAlias=@($x.parameters.interfaceAliases)} }
function Get-NetFirewallInterfaceTypeFilter { [CmdletBinding()] param($AssociatedNetFirewallRule,$PolicyStore); [pscustomobject]@{InterfaceType=@('Any')} }
function Get-NetFirewallServiceFilter { [CmdletBinding()] param($AssociatedNetFirewallRule,$PolicyStore); [pscustomobject]@{Service='Any'} }
function Get-NetFirewallSecurityFilter { [CmdletBinding()] param($AssociatedNetFirewallRule,$PolicyStore); [pscustomobject]@{LocalUser='Any';RemoteUser='Any';RemoteMachine='Any';Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules=$false} }
function Remove-NetFirewallRule { [CmdletBinding(SupportsShouldProcess)] param($InputObject); [Console]::Error.WriteLine('SYNTHETIC_REMOVAL') }
function New-NetFirewallRule { [CmdletBinding()] param(); throw 'UnexpectedCreate' }
"#;
        let principal = "$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())";
        let fake_principal = "$principal=[pscustomobject]@{}; $principal | Add-Member ScriptMethod IsInRole { param($role) $true }";
        assert_eq!(NATIVE_SCRIPT.matches(principal).count(), 2);
        let script = NATIVE_SCRIPT.replace(principal, fake_principal)
            .replacen("try {\n $line=[Console]::ReadLine()", &format!("{FACTS}\ntry {{\n $line=[Console]::ReadLine()"), 1);
        assert!(script.contains(FACTS));
        let scope = scope();
        let parameters = scope.creation_parameters();
        let mut wire = serde_json::to_value(&parameters).unwrap();
        wire["name"] = "synthetic-owned".into();
        wire["instanceId"] = "synthetic-instance".into();
        wire["policyStoreSource"] = "synthetic-store".into();
        wire["policyStoreSourceType"] = "synthetic-source".into();
        let rule: GatewayNativeRule = serde_json::from_value(wire).unwrap();
        let program = super::super::system_powershell_program().unwrap();
        let run = |request: GatewayRuleRequest| {
            let input = NativeInput { version: 1, attempt_id: "historical-fixture", request: &request, parameters: scope.creation_parameters() };
            let mut child = Command::new(program.as_path()).args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", &script])
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            let mut bytes = serde_json::to_vec(&input).unwrap();
            bytes.extend_from_slice(b"\nGO historical-fixture\nCALL historical-fixture\n");
            child.stdin.take().unwrap().write_all(&bytes).unwrap();
            let output = child.wait_with_output().unwrap();
            let reports: Vec<GatewayNativeReport> = output.stdout.split(|b| *b == b'\n')
                .filter_map(|line| line.strip_prefix(REPORT_PREFIX))
                .map(|line| serde_json::from_slice(line).unwrap()).collect();
            (output, reports)
        };
        let (output, reports) = run(GatewayRuleRequest::InspectOwned { scope: scope.clone(), name: "synthetic-owned".into() });
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let inspection = reports.last().unwrap().inspection.as_ref().unwrap();
        assert_eq!(inspection.namespace, None);
        assert_eq!(inspection.persistent, [rule.clone()]);
        assert_eq!(inspection.active, [rule.clone()]);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_REMOVAL"));
        let (output, reports) = run(GatewayRuleRequest::InspectOwned { scope: scope.clone(), name: "synthetic-absent".into() });
        assert!(output.status.success());
        let inspection = reports.last().unwrap().inspection.as_ref().unwrap();
        assert!(inspection.persistent.is_empty() && inspection.active.is_empty());
        for request in [GatewayRuleRequest::Inspect { scope: scope.clone(), name: Some("synthetic-owned".into()) },
                        GatewayRuleRequest::Create { scope: scope.clone(), name: "synthetic-owned".into() }] {
            let (output, reports) = run(request);
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("FreshGatewayInterfaceChanged"));
            assert!(reports.iter().all(|r| r.stage != GatewayNativeStage::ReadyToInvoke));
            assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_REMOVAL"));
        }
        let mut variants = Vec::new();
        let mut changed = rule.clone(); changed.instance_id = Some("changed-instance".into()); variants.push((changed, rule.clone()));
        let mut changed = rule.clone(); changed.policy_store_source = Some("changed-source".into()); variants.push((rule.clone(), changed));
        let mut changed = rule.clone(); changed.program = "C:\\synthetic-other.exe".into(); variants.push((changed, rule.clone()));
        let mut changed = rule.clone(); changed.remote_addresses = vec!["192.0.2.99".into()]; variants.push((rule.clone(), changed));
        for (persistent, active) in variants {
            let (output, _) = run(GatewayRuleRequest::Remove { scope: scope.clone(), persistent, active });
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("NativeRemovalPreimageChangedPreserved"));
            assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_REMOVAL"));
        }
        let mut missing = rule.clone(); missing.name = "synthetic-absent".into();
        let (output, _) = run(GatewayRuleRequest::Remove { scope: scope.clone(), persistent: missing.clone(), active: missing });
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("NativeRemovalPreimageMissingOrAmbiguous"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_REMOVAL"));
        let mut ambiguous = rule.clone(); ambiguous.name = "synthetic-ambiguous".into();
        let (output, _) = run(GatewayRuleRequest::Remove { scope: scope.clone(), persistent: ambiguous.clone(), active: ambiguous });
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("NativeRemovalPreimageMissingOrAmbiguous"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_REMOVAL"));
        let (output, reports) = run(GatewayRuleRequest::Remove { scope: scope.clone(), persistent: rule.clone(), active: rule });
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(String::from_utf8_lossy(&output.stderr).matches("SYNTHETIC_REMOVAL").count(), 1);
        assert_eq!(reports.last().unwrap().action, GatewayActionReport::ReturnedSuccess);
    }

    #[test]
    #[ignore = "Root-owned same-function raw CIM fixture; no firewall/module/native rule calls"]
    fn raw_enforcement_collector_uses_numeric_cim_and_keeps_unknown_nullable() {
        let required = &NATIVE_SCRIPT[NATIVE_SCRIPT.find("function Required(").unwrap()..NATIVE_SCRIPT.find("function NativeRule(").unwrap()];
        let effect = &NATIVE_SCRIPT[NATIVE_SCRIPT.find("function ActiveEnforcement(").unwrap()..NATIVE_SCRIPT.find("function Rules(").unwrap()];
        let script = format!("& {{ $ErrorActionPreference='Stop'; Set-StrictMode -Version Latest; {required} {effect} {} }}", r#"
$healthy=[pscustomobject]@{Name='same-row';InstanceID='same-instance';EnforcementStatus='NoLocalUser';CimInstanceProperties=@{PrimaryStatus=[pscustomobject]@{CimType='UInt16';Value=[uint16]1};EnforcementStatus=[pscustomobject]@{CimType='UInt16Array';Value=[uint16[]]@(1)}}}
$inactive=[pscustomobject]@{Name='same-row';InstanceID='same-instance';EnforcementStatus='NoLocalUser';CimInstanceProperties=@{PrimaryStatus=[pscustomobject]@{CimType='UInt16';Value=[uint16]2};EnforcementStatus=[pscustomobject]@{CimType='UInt16Array';Value=[uint16[]]@(20)}}}
$wrong=[pscustomobject]@{Name='same-row';InstanceID='same-instance';CimInstanceProperties=@{PrimaryStatus=[pscustomobject]@{CimType='UInt16';Value='OK'};EnforcementStatus=[pscustomobject]@{CimType='UInt16Array';Value='Full'}}}
$missing=[pscustomobject]@{Name='same-row';InstanceID='same-instance'}
@((ActiveEnforcement $healthy),(ActiveEnforcement $inactive),(ActiveEnforcement $wrong),(ActiveEnforcement $missing))|ConvertTo-Json -Depth 8 -Compress
"#);
        let program = super::super::system_powershell_program().unwrap();
        let output = Command::new(program.as_path()).args(["-NoLogo","-NoProfile","-NonInteractive","-Command",&script]).output().unwrap();
        assert!(output.status.success(), "{:?}", String::from_utf8_lossy(&output.stderr));
        let values: Vec<ActiveRuleEnforcement> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(values.len(), 4);
        assert_eq!(values[0].primary_status, Some(1)); assert_eq!(values[0].enforcement_status, Some(vec![1]));
        assert_eq!(values[1].primary_status, Some(2)); assert_eq!(values[1].enforcement_status, Some(vec![20]));
        for value in &values[2..] { assert_eq!(value.primary_status, None); assert_eq!(value.enforcement_status, None); }
        assert!(values.iter().all(|value| value.name == "same-row" && value.instance_id.as_deref() == Some("same-instance")));
    }

    // Inspected, source-owned synthetic process producer. It never imports or
    // calls a firewall/network cmdlet. The barrier waits for the actual owner
    // to receive cancellation and close its creator-owned stdin, so that test
    // does not depend on a naturally measurable scheduler window.
    macro_rules! fixture_script {
        ($barrier:literal, $profiles:literal) => { concat!("& { $fixtureBarrier=", $barrier, "; $fixtureProfiles=", $profiles, ";", r#"
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$utf8=[Text.UTF8Encoding]::new($false);[Console]::InputEncoding=$utf8;[Console]::OutputEncoding=$utf8
$line=[Console]::ReadLine();if($null -eq $line){[Console]::Error.WriteLine('FixtureInputNotReceived');exit 0}
$x=$line|ConvertFrom-Json
$profileRows=@(foreach($mask in @(1,2,4)){if($fixtureProfiles -band $mask){[ordered]@{mask=$mask;enabled=$true;blockAllInbound=$false}}})
$policy=[ordered]@{activeProfiles=$fixtureProfiles;localModifyState=0;profiles=$profileRows;blocks=@();unsupportedConditions=@()}
function Report([string]$stage,[string]$state,$inspection,$evidence,$diagnostic) {
 $report=[ordered]@{version=1;attemptId=[string]$x.attemptId;stage=$stage;action=[ordered]@{state=$state};inspection=$inspection;diagnostic=$diagnostic;policyEvidence=$evidence}
 [Console]::Out.WriteLine('AG_GATEWAY_NATIVE_V1 '+($report|ConvertTo-Json -Depth 100 -Compress));[Console]::Out.Flush()
}
if([Console]::ReadLine() -cne ('GO '+$x.attemptId)){Report 'done' 'notInvoked' $null $null $null;exit 0}
if($x.request.action -ne 'inspect'){
 Report 'readyToInvoke' 'notInvoked' $null $policy $null
 if([Console]::ReadLine() -cne ('CALL '+$x.attemptId)){Report 'done' 'notInvoked' $null $null $null;exit 0}
}
$diagnostic=[ordered]@{kind=[ordered]@{state='native'};message=('fixture-capture-payload:'+('X'*131072))}
Report 'progress' 'unknown' $null $null $diagnostic
if($fixtureBarrier){$null=[Console]::ReadLine()}
[Console]::Error.Write('fixture-stderr:'+('E'*131072));[Console]::Error.Flush()
$inspection=$null;$evidence=$null
if($x.request.action -eq 'inspect'){
 $rule=[ordered]@{name=[string]$x.request.name;instanceId='synthetic-instance';policyStoreSource='synthetic-store';policyStoreSourceType='synthetic-source'}
 foreach($p in $x.parameters.PSObject.Properties){$rule[$p.Name]=$p.Value}
 $inspection=[ordered]@{administrator=$false;activeProfiles=$fixtureProfiles;namespace=$x.request.scope.namespace;policy=[ordered]@{state='unavailable';detail='synthetic policy facts awaiting receiving'};persistent=@($rule);active=@($rule)}
 $evidence=$policy
}
Report 'done' 'returnedSuccess' $inspection $evidence $null;exit 0
}"#) };
    }
    const FIXTURE: &str = fixture_script!("$false", "2");
    const FIXTURE_BARRIER: &str = fixture_script!("$true", "2");
    const FIXTURE_DOMAIN: &str = fixture_script!("$false", "1");
    const MALFORMED: &str = r#"& {
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$null=[Console]::ReadLine();$null=[Console]::ReadLine()
[Console]::Out.WriteLine('AG_GATEWAY_NATIVE_V1 {"version":1,"incomplete":');[Console]::Error.Write('actual synthetic diagnostic');exit 0
}"#;

    struct FixtureRunner {
        runner: WindowsGatewayRuleRunner,
        persisted: bool,
    }
    impl std::ops::Deref for FixtureRunner {
        type Target = WindowsGatewayRuleRunner;
        fn deref(&self) -> &Self::Target {
            &self.runner
        }
    }
    impl std::ops::DerefMut for FixtureRunner {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.runner
        }
    }
    impl FixtureRunner {
        fn persist(&mut self) -> Result<()> {
            let mut output = std::io::stdout().lock();
            writeln!(output, "AG_GATEWAY_NATIVE_FIXTURE_RECEIVING_BEGIN")
                .map_err(|e| e.to_string())?;
            serde_json::to_writer(&mut output, self.runner.receiving())
                .map_err(|e| e.to_string())?;
            writeln!(output, "\nAG_GATEWAY_NATIVE_FIXTURE_RECEIVING_END")
                .map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
            self.persisted = true;
            Ok(())
        }
        fn run(
            &mut self,
            request: &GatewayRuleRequest,
            cancel: &AtomicBool,
            record: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>,
        ) -> GatewayNativeOutcome {
            self.persisted = false;
            let outcome = self.runner.run(request, cancel, record);
            self.persist()
                .expect("persist actual synthetic native receiving before fixture assertions");
            outcome
        }
    }
    impl Drop for FixtureRunner {
        fn drop(&mut self) {
            if !self.persisted {
                if let Err(error) = self.persist() {
                    if std::thread::panicking() {
                        let _ = writeln!(
                            std::io::stderr(),
                            "synthetic receiving retention failed while unwinding: {error}"
                        );
                    } else {
                        panic!("synthetic receiving retention failed: {error}");
                    }
                }
            }
        }
    }
    fn fixture(script: &'static str) -> FixtureRunner {
        let mut runner =
            WindowsGatewayRuleRunner::new(super::super::windows_installation::new_request_id)
                .unwrap();
        runner.script = script;
        FixtureRunner {
            runner,
            persisted: false,
        }
    }
    fn scope() -> GatewayRuleScope {
        let host = super::super::system_powershell_program().unwrap();
        serde_json::from_value(serde_json::json!({
            "host": {"path":host.as_path(),"nativeId":host.native_id(),"sha256":hex::encode(Sha256::digest(host.read_snapshot().unwrap()))},
            "namespace":{"interfaceIndex":19,"interfaceAlias":"synthetic [interface] Ω","localAddress":"192.0.2.1","sourceAddress":"192.0.2.2"}
        })).unwrap()
    }
    fn inspect_request() -> GatewayRuleRequest {
        GatewayRuleRequest::Inspect {
            scope: scope(),
            name: Some("synthetic ' \" $(ignored) Ω".into()),
        }
    }
    fn create_request() -> GatewayRuleRequest {
        GatewayRuleRequest::Create {
            scope: scope(),
            name: "synthetic-create".into(),
        }
    }
    fn assert_retired(outcome: &GatewayNativeOutcome) {
        assert!(matches!(
            outcome.dispatch,
            GatewayDispatch::Started {
                creation_time: Some(_),
                image: Some(_),
                ..
            }
        ));
        assert!(matches!(outcome.execution, GatewayExecution::Exited { .. }));
    }
    fn assert_captured(outcome: &GatewayNativeOutcome) {
        for capture in [&outcome.stdout, &outcome.stderr] {
            assert_eq!(capture.reader, GatewayCaptureState::Complete);
            assert_eq!(capture.finalization, GatewayCaptureState::Complete);
            assert!(!capture.truncated);
        }
    }

    #[test]
    fn actual_producer_wire_and_two_large_native_streams_are_received() {
        let mut runner = fixture(FIXTURE);
        let request = inspect_request();
        let mut records = Vec::new();
        let outcome = runner.run(&request, &AtomicBool::new(false), &mut |outcome| {
            records.push(outcome.clone());
            Ok(())
        });
        assert_retired(&outcome);
        assert_captured(&outcome);
        assert_eq!(outcome.action, GatewayActionReport::ReturnedSuccess);
        assert!(outcome.stdout.bytes.len() > 131072 && outcome.stderr.bytes.len() > 131072);
        let received = outcome.inspection.as_ref().unwrap();
        let GatewayRuleRequest::Inspect { scope, name } = &request else {
            unreachable!()
        };
        assert_eq!(received.namespace.as_ref(), Some(&scope.namespace));
        assert_eq!(received.persistent[0].name, name.as_ref().unwrap().as_str());
        assert_eq!(received.persistent[0].program, scope.host.path);
        assert_eq!(
            received.persistent[0].profiles,
            scope.creation_parameters().profiles
        );
        assert_eq!(received.active.len(), 1);
        assert_eq!(received.policy, GatewayPolicyObservation::Allowed);
        assert!(matches!(
            records.first().unwrap().execution,
            GatewayExecution::Pending
        ));
        assert_eq!(records.last().unwrap(), &outcome);
        assert!(runner.receiving()[0].identity_errors.is_empty());
        assert!(runner.receiving()[0].interpretation_errors.is_empty());
    }
    #[test]
    fn cancellation_before_dispatch_has_no_started_child() {
        let mut runner = fixture(FIXTURE);
        let outcome = runner.run(&create_request(), &AtomicBool::new(true), &mut |_| Ok(()));
        assert!(matches!(outcome.dispatch, GatewayDispatch::NotStarted(_)));
        assert_eq!(outcome.execution, GatewayExecution::NotStarted);
        assert_eq!(outcome.action, GatewayActionReport::NotInvoked);
        assert!(runner.receiving()[0].cancellation_received);
    }
    #[test]
    fn failed_incremental_recording_preserves_started_binding_and_actual_retirement() {
        let mut runner = fixture(FIXTURE);
        let outcome = runner.run(&create_request(), &AtomicBool::new(false), &mut |_| {
            Err("controlled recorder failure".into())
        });
        assert_retired(&outcome);
        assert_eq!(outcome.action, GatewayActionReport::Unknown);
        assert_eq!(
            runner.receiving()[0].recorder_errors,
            ["controlled recorder failure"]
        );
        assert!(!runner.receiving()[0]
            .reports
            .iter()
            .any(|report| report.stage == GatewayNativeStage::Progress));
        assert!(matches!(
            outcome.stdout.finalization,
            GatewayCaptureState::Failed(_)
        ));
    }
    #[test]
    fn cancellation_at_ready_closes_the_grant_without_invoking_action() {
        let mut runner = fixture(FIXTURE);
        let cancel = AtomicBool::new(false);
        let outcome = runner.run(&create_request(), &cancel, &mut |outcome| {
            if outcome.action == GatewayActionReport::NotInvoked {
                cancel.store(true, Ordering::SeqCst);
            }
            Ok(())
        });
        assert_retired(&outcome);
        assert_captured(&outcome);
        assert_eq!(outcome.action, GatewayActionReport::NotInvoked);
        assert!(runner.receiving()[0]
            .reports
            .iter()
            .any(|report| report.stage == GatewayNativeStage::ReadyToInvoke));
        assert!(!runner.receiving()[0]
            .reports
            .iter()
            .any(|report| report.stage == GatewayNativeStage::Progress));
        assert!(runner.receiving()[0].cancellation_received);
    }
    #[test]
    fn cancellation_after_invocation_waits_for_the_actual_child_and_readers() {
        let mut runner = fixture(FIXTURE_BARRIER);
        let cancel = AtomicBool::new(false);
        let outcome = runner.run(&create_request(), &cancel, &mut |outcome| {
            if outcome.action == GatewayActionReport::Unknown
                && outcome
                    .stdout
                    .bytes
                    .windows(b"\"stage\":\"progress\"".len())
                    .any(|part| part == b"\"stage\":\"progress\"")
            {
                cancel.store(true, Ordering::SeqCst);
            }
            Ok(())
        });
        assert_retired(&outcome);
        assert_captured(&outcome);
        assert_eq!(outcome.action, GatewayActionReport::ReturnedSuccess);
        assert!(runner.receiving()[0].cancellation_received);
        assert!(runner.receiving()[0]
            .reports
            .iter()
            .any(|report| report.stage == GatewayNativeStage::Progress));
        assert_eq!(
            runner.receiving()[0].reports.last().unwrap().stage,
            GatewayNativeStage::Done
        );
    }
    #[test]
    fn actual_reader_failure_is_preserved_and_prevents_a_mutation_grant() {
        let mut runner = fixture(FIXTURE);
        runner.reader_fault = Some(Pipe::Stderr);
        let outcome = runner.run(&create_request(), &AtomicBool::new(false), &mut |_| Ok(()));
        assert_retired(&outcome);
        assert!(
            matches!(&outcome.stderr.reader, GatewayCaptureState::Failed(error) if error.contains("controlled native-reader"))
        );
        assert_ne!(outcome.action, GatewayActionReport::ReturnedSuccess);
        assert!(!runner.receiving()[0]
            .reports
            .iter()
            .any(|report| report.stage == GatewayNativeStage::Progress));
    }
    #[test]
    fn native_exit_zero_with_malformed_output_never_becomes_success() {
        let mut runner = fixture(MALFORMED);
        let outcome = runner.run(&inspect_request(), &AtomicBool::new(false), &mut |_| Ok(()));
        assert_retired(&outcome);
        assert_eq!(
            outcome.execution,
            GatewayExecution::Exited { code: Some(0) }
        );
        assert_eq!(outcome.action, GatewayActionReport::Unknown);
        assert_eq!(outcome.stdout.reader, GatewayCaptureState::Complete);
        assert!(matches!(
            outcome.stdout.finalization,
            GatewayCaptureState::Failed(_)
        ));
        assert!(!outcome.stdout.bytes.is_empty() && !outcome.stderr.bytes.is_empty());
        assert!(!runner.receiving()[0].interpretation_errors.is_empty());
    }
    #[test]
    fn report_wire_requires_explicit_nullable_fields_and_native_address_selectors() {
        let mut report = serde_json::json!({"version":1,"attemptId":"fixture","stage":"done","action":{"state":"notInvoked"},"inspection":null,"diagnostic":null,"policyEvidence":null});
        assert!(serde_json::from_value::<GatewayNativeReport>(report.clone()).is_ok());
        report.as_object_mut().unwrap().remove("policyEvidence");
        assert!(serde_json::from_value::<GatewayNativeReport>(report).is_err());
        let address = Ipv4Addr::new(192, 0, 2, 2);
        assert!(address_applies(&["192.0.2.0/24".into()], address).unwrap());
        assert!(address_applies(&["192.0.2.1-192.0.2.3".into()], address).unwrap());
        assert!(!address_applies(&["198.51.100.0/24".into()], address).unwrap());
        assert!(address_applies(&["LocalSubnet".into()], address).is_err());
    }

    #[test]
    fn ready_policy_uses_the_lower_profile_admission_owner() {
        let scope = scope();
        for (active, allowed) in [
            (0, false),
            (1, false),
            (2, true),
            (4, true),
            (6, true),
            (7, false),
            (8, false),
            (u32::MAX, false),
        ] {
            let evidence = GatewayPolicyEvidence {
                active_profiles: active,
                local_modify_state: 0,
                profiles: [1, 2, 4]
                    .into_iter()
                    .filter(|mask| active & mask != 0)
                    .map(|mask| GatewayProfileEvidence {
                        mask,
                        enabled: true,
                        block_all_inbound: false,
                    })
                    .collect(),
                blocks: Vec::new(),
                unsupported_conditions: Vec::new(),
            };
            let observed = effective_policy(&scope, &evidence);
            assert_eq!(
                observed == GatewayPolicyObservation::Allowed,
                allowed,
                "actual active profiles {active}: {observed:?}"
            );
        }
    }

    #[test]
    fn fresh_domain_ready_after_private_preflight_never_receives_call_grant() {
        let cancel = AtomicBool::new(false);
        let mut preflight_runner = fixture(FIXTURE);
        let preflight = preflight_runner.run(&inspect_request(), &cancel, &mut |_| Ok(()));
        assert_retired(&preflight);
        assert_captured(&preflight);
        let inspection = preflight.inspection.as_ref().unwrap();
        assert_eq!(inspection.active_profiles, 2);
        assert_eq!(inspection.policy, GatewayPolicyObservation::Allowed);

        let mut runner = fixture(FIXTURE_DOMAIN);
        let outcome = runner.run(&create_request(), &cancel, &mut |_| Ok(()));
        assert_retired(&outcome);
        assert_captured(&outcome);
        assert_eq!(outcome.action, GatewayActionReport::NotInvoked);
        assert!(!cancel.load(Ordering::SeqCst));
        let received = &runner.receiving()[0];
        let ready = received
            .reports
            .iter()
            .find(|report| report.stage == GatewayNativeStage::ReadyToInvoke)
            .unwrap();
        assert!(ready.inspection.is_none());
        let evidence = ready.policy_evidence.as_ref().unwrap();
        assert_eq!(evidence.active_profiles, 1);
        assert_eq!(evidence.local_modify_state, 0);
        assert!(evidence.blocks.is_empty());
        assert!(evidence
            .profiles
            .iter()
            .any(|profile| profile.mask == 1 && profile.enabled && !profile.block_all_inbound));
        assert!(received
            .policy_observations
            .iter()
            .any(|policy| matches!(policy, GatewayPolicyObservation::PolicyDenied(_))));
        assert!(!received
            .reports
            .iter()
            .any(|report| report.stage == GatewayNativeStage::Progress));
        assert!(received.interpretation_errors.is_empty());
    }
}
