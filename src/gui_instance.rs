//! One-shot normal-GUI replacement rendezvous. This module never owns Settings.
#![cfg(windows)]

use crate::windows_coordinator::{
    process_identity::ProcessIdentity,
    windows_installation::{CheckedPath, NativeObjectId, PathKind, PathPurpose},
    OWNER_OBSERVATION_CADENCE,
};
use std::ffi::{OsStr, OsString};
use std::os::windows::{
    ffi::{OsStrExt, OsStringExt},
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::Sender,
    Arc,
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
        ERROR_PIPE_LISTENING, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, GetTokenInformation,
        TokenElevation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
    },
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
            GetNamedPipeServerProcessId, PeekNamedPipe, SetNamedPipeHandleState, PIPE_NOWAIT,
            PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
        },
        Threading::{OpenProcessToken, WaitForSingleObject},
    },
    UI::{
        Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

type Result<T> = std::result::Result<T, String>;
pub(crate) const GUI_REPLACEMENT_FLAG: &str = "--gui-replacement";
fn error(stage: &str) -> String {
    format!("{stage}: {}", std::io::Error::last_os_error())
}
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

// The existing lifecycle protocol is unchanged by action-envelope versions.
const READY: &[u8; 8] = b"AGUR\x01RDY";
const COMMIT: &[u8; 8] = b"AGUR\x01CMT";
const COMMITTED: &[u8; 8] = b"AGUR\x01ACK";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum GuiReplacementAction {
    // Empty struct variants make serde reject every extra field, including
    // null continuation fields; a tagged unit variant ignores such fields.
    ShowMain {},
    ResumeApply(GuiApplyContinuation),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuiApplyContinuation {
    // The existing Core UUID owner supplies/qualifies this correlation value.
    // This transport must not reinterpret it as consent or duplicate its policy.
    pub(crate) request_id: String,
    #[serde(with = "sha256_hex")]
    pub(crate) saved_settings_sha256: [u8; 32],
    pub(crate) targets: Vec<GuiTargetExpectation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retirement_input: Option<GuiRetirementInputRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuiRetirementInputRef {
    pub(crate) path: PathBuf,
    pub(crate) native_id: NativeObjectId,
    #[serde(serialize_with = "sha256_hex::serialize", deserialize_with = "lower_sha256")]
    pub(crate) sha256: [u8; 32],
}
fn lower_sha256<'de, D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<[u8; 32], D::Error> {
    use serde::Deserialize;
    let value = String::deserialize(deserializer)?;
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(serde::de::Error::custom("expected lowercase SHA-256"));
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(serde::de::Error::custom)?;
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuiTargetExpectation {
    pub(crate) target: GuiReplacementTarget,
    pub(crate) current: GuiCurrentExpectation,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuiReplacementTarget {
    pub(crate) kind: GuiTargetKind,
    pub(crate) root_path: PathBuf,
    pub(crate) native_root_id: NativeObjectId,
    pub(crate) anchor_path: PathBuf,
    pub(crate) anchor_native_id: NativeObjectId,
}

/// Classification is supplied by Core's checked all-target Apply plan. This
/// closed transport tag must never classify a path or infer a kind itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum GuiTargetKind {
    Desktop,
    Ide,
    Cli,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum GuiCurrentExpectation {
    Absent {},
    Present {
        #[serde(rename = "slotId")]
        slot_id: String,
        #[serde(rename = "currentSha256", with = "sha256_hex")]
        current_sha256: [u8; 32],
    },
    VendorUpdate {
        #[serde(rename = "slotId")]
        slot_id: String,
        #[serde(rename = "priorCurrentSha256", with = "sha256_hex")]
        prior_current_sha256: [u8; 32],
        #[serde(rename = "newParentId")]
        new_parent_id: NativeObjectId,
        #[serde(rename = "newResourcesId")]
        new_resources_id: NativeObjectId,
        #[serde(rename = "newArchiveId")]
        new_archive_id: NativeObjectId,
        #[serde(rename = "newExecutableSha256", with = "sha256_hex")]
        new_executable_sha256: [u8; 32],
        #[serde(rename = "newArchiveSha256", with = "sha256_hex")]
        new_archive_sha256: [u8; 32],
        #[serde(rename = "newBindingSha256", with = "sha256_hex")]
        new_binding_sha256: [u8; 32],
    },
    NotApplicable {},
}

impl GuiReplacementAction {
    fn validate_transport(&self) -> Result<()> {
        if let Self::ResumeApply(continuation) = self {
            if continuation.request_id.is_empty() {
                return Err("GUI Apply continuation request ID is missing".into());
            }
            for expectation in &continuation.targets {
                if expectation.target.root_path.as_os_str().is_empty()
                    || expectation.target.anchor_path.as_os_str().is_empty()
                {
                    return Err("GUI Apply root/anchor path is missing".into());
                }
                match (&expectation.target.kind, &expectation.current) {
                    (
                        GuiTargetKind::Desktop,
                        GuiCurrentExpectation::Absent {} | GuiCurrentExpectation::Present { .. } | GuiCurrentExpectation::VendorUpdate { .. },
                    )
                    | (
                        GuiTargetKind::Ide | GuiTargetKind::Cli,
                        GuiCurrentExpectation::NotApplicable {},
                    ) => {}
                    _ => return Err("GUI Apply target kind/current expectation mismatch".into()),
                }
                if matches!(&expectation.current, GuiCurrentExpectation::Present { slot_id, .. } if slot_id.is_empty())
                    || matches!(&expectation.current, GuiCurrentExpectation::VendorUpdate { slot_id, .. } if slot_id.is_empty())
                {
                    return Err("GUI Apply current slot ID is missing".into());
                }
            }
        }
        Ok(())
    }
    fn receive_json(value: &str) -> Result<Self> {
        let action: Self = serde_json::from_str(value)
            .map_err(|e| format!("invalid GUI replacement action: {e}"))?;
        action.validate_transport()?;
        Ok(action)
    }
}

// Typed SHA-256 transport uses the already installed hex/serde owners. These
// are comparisons supplied by Core, never Settings/current receiving here.
mod sha256_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(
        value: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        let mut digest = [0; 32];
        hex::decode_to_slice(value, &mut digest).map_err(serde::de::Error::custom)?;
        Ok(digest)
    }
}

pub(crate) enum ElevationProgress {
    WaitingForConsent,
    WaitingForReplacement,
    ObservationPending(String),
}

/// Prepared child custody. Core must retain this until acknowledged transfer
/// or observed retirement; dropping it is not a retirement operation.
pub(crate) struct GuiReplacementReady {
    child: OwnedHandle,
    identity: ProcessIdentity,
    _image: CheckedPath,
    pipe: Option<Rendezvous>,
    commit_sent: bool,
    transferred: bool,
}
impl GuiReplacementReady {
    /// Called only by Main after idle, saved Settings and all jobs retired.
    /// False/error leaves custody here and requires the parent to stay alive.
    pub(crate) fn arm_for_exit(&mut self) -> Result<bool> {
        if self.transferred {
            return Ok(true);
        }
        if !self.identity.alive()? {
            return Err("GUI replacement retired before transfer".into());
        }
        self.identity.recheck()?;
        self._image.recheck()?;
        let pipe = self
            .pipe
            .as_ref()
            .ok_or("GUI replacement has been cancelled")?;
        if !self.commit_sent {
            // A failed write can be an uncertain delivery. From this point
            // onward only ACK or actual retirement can settle custody.
            self.commit_sent = true;
            pipe.send(COMMIT)?;
        }
        match pipe.record()? {
            Some(record) if &record == COMMITTED => {
                self.transferred = true;
                Ok(true)
            }
            Some(_) => Err("unexpected GUI replacement transfer record".into()),
            None => Ok(false),
        }
    }
    /// Caller retains this capability and polls retirement after cancellation.
    pub(crate) fn request_abort(&mut self) -> Result<()> {
        if self.transferred {
            return Err("GUI creator-exit custody already transferred".into());
        }
        if self.commit_sent {
            return Err(
                "GUI COMMIT may have reached child; retain parent and handoff Pending".into(),
            );
        }
        self.pipe.take();
        Ok(())
    }
    pub(crate) fn poll_retired(&mut self) -> Result<bool> {
        observe_exit(&self.child)
    }
}

fn observe_exit(process: &OwnedHandle) -> Result<bool> {
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(error("observe GUI replacement retirement")),
    }
}

fn retire_owned(
    child: OwnedHandle,
    pipe: Rendezvous,
    reason: String,
    progress: &Sender<ElevationProgress>,
) -> String {
    drop(pipe);
    let mut last_error = None;
    // Cancellation is not retirement. The exact worker keeps its handle even
    // if progress receiving closes or native lifetime observation fails.
    loop {
        match observe_exit(&child) {
            Ok(true) => {
                return match last_error {
                    Some(e) => format!("{reason}; {e}"),
                    None => reason,
                }
            }
            Ok(false) => {}
            Err(e) => {
                if last_error.as_ref() != Some(&e) {
                    let _ = progress.send(ElevationProgress::ObservationPending(e.clone()));
                    last_error = Some(e);
                }
            }
        }
        std::thread::sleep(OWNER_OBSERVATION_CADENCE);
    }
}

fn require_elevated(process: &ProcessIdentity) -> Result<()> {
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process.handle(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(error("receive elevated GUI token"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut count = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut count,
        )
    } == 0
    {
        return Err(error("receive GUI elevation state"));
    }
    if count as usize != std::mem::size_of::<TOKEN_ELEVATION>() || elevation.TokenIsElevated == 0 {
        return Err("replacement GUI token is not elevated".into());
    }
    Ok(())
}

pub(crate) fn request_elevation(
    action: GuiReplacementAction,
    cancel: Arc<AtomicBool>,
    progress: Sender<ElevationProgress>,
) -> Result<GuiReplacementReady> {
    if cancel.load(Ordering::Acquire) {
        return Err("GUI elevation cancelled".into());
    }
    let creator = ProcessIdentity::current()?;
    let image = checked_image(&creator)?;
    let pipe = Rendezvous::create(&pipe_name(&creator), creator.sid())?;
    let _com = Apartment::initialize()?;
    let verb = wide(OsStr::new("runas"));
    let file = wide(image.as_path().as_os_str());
    let parameters = wide(&ReplacementRequest::parameters(&creator, &action)?);
    let mut launch = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    if cancel.load(Ordering::Acquire) {
        return Err("GUI elevation cancelled".into());
    }
    let _ = progress.send(ElevationProgress::WaitingForConsent);
    // This call may wait for the real manual UAC decision. Cancellation is
    // received immediately after it returns; consent is never automated.
    if unsafe { ShellExecuteExW(&mut launch) } == 0 {
        let cause = std::io::Error::last_os_error();
        let stage = if cause.raw_os_error() == Some(206) {
            "GUI elevation request exceeds Windows command-line or path capacity"
        } else {
            "request GUI administrator consent"
        };
        return Err(format!("{stage}: {cause}"));
    }
    if launch.hProcess.is_null() {
        // The shell contract can return success without a new process handle.
        // That cannot prove a particular child's retirement. Keep this exact
        // worker Pending rather than presenting a settled failure or retrying.
        let _ = progress.send(ElevationProgress::ObservationPending(
            "GUI elevation returned no retained process handle; outcome unverified".into(),
        ));
        let mut pending_pipe = Some(pipe);
        loop {
            if cancel.load(Ordering::Acquire) {
                pending_pipe.take();
            }
            std::thread::sleep(OWNER_OBSERVATION_CADENCE);
        }
    }
    let child = unsafe { OwnedHandle::from_raw_handle(launch.hProcess) };
    let _ = progress.send(ElevationProgress::WaitingForReplacement);
    let receiving = (|| {
        let identity = ProcessIdentity::receive(
            child
                .try_clone()
                .map_err(|e| format!("retain GUI identity: {e}"))?,
        )?;
        let child_image = same_image_user(&creator, &image, &identity)?;
        require_elevated(&identity)?;
        loop {
            if cancel.load(Ordering::Acquire) {
                return Err("GUI elevation cancelled".into());
            }
            if observe_exit(&child)? {
                return Err("replacement GUI exited before READY".into());
            }
            if pipe.connected()? {
                if pipe.peer(true)? != identity.pid() {
                    return Err("GUI rendezvous client identity mismatch".into());
                }
                if let Some(record) = pipe.record()? {
                    if &record != READY {
                        return Err("unexpected GUI replacement readiness record".into());
                    }
                    identity.recheck()?;
                    image.recheck()?;
                    child_image.recheck()?;
                    if !identity.alive()? {
                        return Err("GUI replacement exited during READY receiving".into());
                    }
                    if cancel.load(Ordering::Acquire) {
                        return Err("GUI elevation cancelled".into());
                    }
                    return Ok((identity, child_image));
                }
            }
            std::thread::sleep(OWNER_OBSERVATION_CADENCE);
        }
    })();
    match receiving {
        Ok((identity, child_image)) => Ok(GuiReplacementReady {
            child,
            identity,
            _image: child_image,
            pipe: Some(pipe),
            commit_sent: false,
            transferred: false,
        }),
        Err(reason) => Err(retire_owned(child, pipe, reason, &progress)),
    }
}

/// Early role receiver: success permits only normal Main GUI lease admission.
/// It constructs no Worker and touches no Settings before actual creator exit.
pub(crate) fn receive_replacement(args: Vec<OsString>) -> Result<GuiReplacementAction> {
    let request = ReplacementRequest::receive(args)?;
    let current = ProcessIdentity::current()?;
    require_elevated(&current)?;
    let image = checked_image(&current)?;
    let creator = ProcessIdentity::open(request.creator)?;
    if creator.creation() != request.creation || !creator.alive()? {
        return Err("GUI creator identity is stale".into());
    }
    let _creator_image = same_image_user(&current, &image, &creator)?;
    let pipe = Rendezvous::open(&pipe_name(&creator))?;
    if pipe.peer(false)? != creator.pid() {
        return Err("GUI rendezvous server identity mismatch".into());
    }
    creator.recheck()?;
    pipe.send(READY)?;
    loop {
        if !creator.alive()? {
            return Err("GUI creator exited before COMMIT".into());
        }
        if let Some(record) = pipe.record()? {
            if &record != COMMIT {
                return Err("GUI replacement aborted before COMMIT".into());
            }
            creator.recheck()?;
            image.recheck()?;
            pipe.send(COMMITTED)?;
            break;
        }
        std::thread::sleep(OWNER_OBSERVATION_CADENCE);
    }
    // COMMITTED transfers custody of actual creator-exit observation here.
    // Broken/missing ACK receiving cannot authorize parent exit or abort.
    // Retain the pipe and image while observing the pinned creator lifetime.
    while creator.alive()? {
        std::thread::sleep(OWNER_OBSERVATION_CADENCE);
    }
    creator.recheck()?;
    image.recheck()?;
    Ok(request.action)
}

struct ReplacementRequest {
    creator: u32,
    creation: u64,
    action: GuiReplacementAction,
}
impl ReplacementRequest {
    fn receive(args: Vec<OsString>) -> Result<Self> {
        if !matches!(args.len(), 8 | 10)
            || args[0] != "--version"
            || args[2] != "--creator"
            || args[4] != "--creation"
            || args[6] != "--package"
            || args[7] != env!("CARGO_PKG_VERSION")
        {
            return Err("unsupported GUI replacement request".into());
        }
        let action = if args[1] == "1" && args.len() == 8 {
            GuiReplacementAction::ShowMain {}
        } else if args[1] == "2" && args.len() == 10 && args[8] == "--action" {
            GuiReplacementAction::receive_json(args[9].to_str().ok_or("GUI action encoding")?)?
        } else {
            return Err("unsupported GUI replacement version/action envelope".into());
        };
        let creator = args[3]
            .to_str()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v != 0)
            .ok_or("GUI creator identity missing")?;
        let creation = args[5]
            .to_str()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v != 0)
            .ok_or("GUI creator creation identity missing")?;
        if creator == std::process::id() {
            return Err("GUI cannot replace itself".into());
        }
        Ok(Self {
            creator,
            creation,
            action,
        })
    }
    fn parameters(creator: &ProcessIdentity, action: &GuiReplacementAction) -> Result<OsString> {
        action.validate_transport()?;
        let action = serde_json::to_string(action)
            .map_err(|e| format!("encode GUI replacement action: {e}"))?;
        let mut parameters: OsString = format!(
            "{GUI_REPLACEMENT_FLAG} --version 2 --creator {} --creation {} --package {} --action ",
            creator.pid(),
            creator.creation(),
            env!("CARGO_PKG_VERSION")
        )
        .into();
        parameters.push(quote_windows_argument(OsStr::new(&action))?);
        Ok(parameters)
    }
}

/// ShellExecuteEx exposes a command-line string rather than Command::arg.
/// Apply the Windows backslash/quote rules to one entire JSON argument. No
/// target cap or truncation is added; native capacity errors remain visible.
fn quote_windows_argument(value: &OsStr) -> Result<OsString> {
    let mut quoted = vec![b'"' as u16];
    let mut slashes = 0;
    for unit in value.encode_wide() {
        if unit == 0 {
            return Err("GUI action argument contains NUL".into());
        }
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        let count = if unit == b'"' as u16 {
            slashes * 2 + 1
        } else {
            slashes
        };
        quoted.extend(std::iter::repeat_n(b'\\' as u16, count));
        quoted.push(unit);
        slashes = 0;
    }
    quoted.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    quoted.push(b'"' as u16);
    Ok(OsString::from_wide(&quoted))
}

fn pipe_name(creator: &ProcessIdentity) -> OsString {
    format!(
        r"\\.\pipe\AGUnlocker.gui-replacement.v1.{}.{}.{}",
        creator.sid(),
        creator.pid(),
        creator.creation()
    )
    .into()
}

fn checked_image(process: &ProcessIdentity) -> Result<CheckedPath> {
    process.recheck()?;
    CheckedPath::open(process.image(), PathKind::File, PathPurpose::Executable)
}

fn same_image_user(
    expected: &ProcessIdentity,
    image: &CheckedPath,
    actual: &ProcessIdentity,
) -> Result<CheckedPath> {
    if expected.sid() != actual.sid() {
        return Err("GUI replacement belongs to a different user".into());
    }
    image.recheck()?;
    let actual_image = checked_image(actual)?;
    if actual_image.native_id() != image.native_id() {
        return Err("GUI replacement executable identity mismatch".into());
    }
    Ok(actual_image)
}

/// Positive visible-window receiving only; absence is not certification that
/// an unsupported hidden/startup legacy writer does not exist.
pub(crate) fn receive_visible_gui_conflicts() -> Result<()> {
    use windows_sys::core::BOOL;
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_NO_MORE_FILES, HWND, LPARAM},
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsWindowVisible},
    };
    unsafe extern "system" fn window(hwnd: HWND, target: LPARAM) -> BOOL {
        if unsafe { IsWindowVisible(hwnd) } != 0 {
            let mut pid = 0;
            if unsafe { GetWindowThreadProcessId(hwnd, &mut pid) } != 0 && pid != 0 {
                let pids = unsafe { &mut *(target as *mut Vec<u32>) };
                pids.push(pid);
            }
        }
        1
    }
    let current = ProcessIdentity::current()?;
    let own = current
        .image()
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or("GUI executable name encoding")?;
    let mut visible = Vec::<u32>::new();
    if unsafe { EnumWindows(Some(window), (&mut visible as *mut Vec<u32>) as LPARAM) } == 0 {
        return Err(error("observe existing GUI windows"));
    }
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(error("observe GUI process names"));
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut row = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut row) };
    while found != 0 {
        if row.th32ProcessID != current.pid() && visible.contains(&row.th32ProcessID) {
            let length = row
                .szExeFile
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(row.szExeFile.len());
            let name = String::from_utf16(&row.szExeFile[..length])
                .map_err(|_| "existing GUI image name encoding")?;
            if super::is_window_name(&name, own) {
                // The snapshot is merely a selector. Retained creation/SID and
                // checked executable receiving, never PID/name, drive the hold.
                let actor = ProcessIdentity::open(row.th32ProcessID)
                    .map_err(|e| format!("existing GUI identity unverified; preserve it: {e}"))?;
                let image = checked_image(&actor)?;
                if actor.sid() == current.sid() && actor.alive()? {
                    actor.recheck()?;
                    image.recheck()?;
                    let exact_name = image
                        .as_path()
                        .file_name()
                        .and_then(OsStr::to_str)
                        .ok_or("existing GUI executable name encoding")?;
                    if super::is_window_name(exact_name, own) {
                        return Err("another GUI window for this user is open; close it normally before continuing".into());
                    }
                    return Err(
                        "existing GUI process image changed during receiving; preserve it".into(),
                    );
                }
            }
        }
        found = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut row) };
    }
    if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
        return Err(error("complete GUI process-name observation"));
    }
    Ok(())
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

struct Apartment;
impl Apartment {
    fn initialize() -> Result<Self> {
        use windows_sys::Win32::System::Com::{
            CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
        };
        let status = unsafe {
            CoInitializeEx(
                std::ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        if status < 0 {
            return Err(format!(
                "initialize GUI elevation COM apartment: {status:#x}"
            ));
        }
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::System::Com::CoUninitialize() };
    }
}

const PEER_CLOSED: &str = "GUI handoff peer closed";

struct Rendezvous(OwnedHandle);
impl Rendezvous {
    fn create(name: &OsStr, sid: &str) -> Result<Self> {
        // Protected DACL: only the received creator SID, including its elevated
        // token. Remote clients and second/pre-created pipe instances fail closed.
        let sddl = wide(OsStr::new(&format!("D:P(A;;GA;;;{sid})")));
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(error("GUI handoff descriptor"));
        }
        let descriptor = Descriptor(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let raw = unsafe {
            CreateNamedPipeW(
                wide(name).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE
                    | PIPE_READMODE_MESSAGE
                    | PIPE_NOWAIT
                    | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                READY.len() as u32,
                READY.len() as u32,
                0,
                &attributes,
            )
        };
        Self::receive(raw)
    }
    fn open(name: &OsStr) -> Result<Self> {
        let raw = unsafe {
            CreateFileW(
                wide(name).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        let pipe = Self::receive(raw)?;
        let mode = PIPE_NOWAIT | PIPE_READMODE_MESSAGE;
        if unsafe { SetNamedPipeHandleState(pipe.raw(), &mode, std::ptr::null(), std::ptr::null()) }
            == 0
        {
            return Err(error("GUI handoff client mode"));
        }
        Ok(pipe)
    }
    fn receive(raw: HANDLE) -> Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(error("GUI handoff pipe"));
        }
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(raw) }))
    }
    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
    fn connected(&self) -> Result<bool> {
        if unsafe { ConnectNamedPipe(self.raw(), std::ptr::null_mut()) } != 0 {
            return Ok(true);
        }
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => Ok(true),
            ERROR_PIPE_LISTENING => Ok(false),
            _ => Err(error("connect GUI handoff")),
        }
    }
    fn peer(&self, server: bool) -> Result<u32> {
        let mut pid = 0;
        let ok = unsafe {
            if server {
                GetNamedPipeClientProcessId(self.raw(), &mut pid)
            } else {
                GetNamedPipeServerProcessId(self.raw(), &mut pid)
            }
        };
        if ok == 0 || pid == 0 {
            return Err(error("receive GUI handoff peer"));
        }
        Ok(pid)
    }
    fn send(&self, record: &[u8; 8]) -> Result<()> {
        let mut count = 0;
        if unsafe {
            WriteFile(
                self.raw(),
                record.as_ptr(),
                record.len() as u32,
                &mut count,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(error("send GUI handoff record"));
        }
        if count != record.len() as u32 {
            return Err("incomplete GUI handoff record".into());
        }
        Ok(())
    }
    fn record(&self) -> Result<Option<[u8; 8]>> {
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                self.raw(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return match unsafe { GetLastError() } {
                ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED => {
                    Err(PEER_CLOSED.into())
                }
                _ => Err(error("observe GUI handoff record")),
            };
        }
        if available == 0 {
            return Ok(None);
        }
        if available != READY.len() as u32 {
            return Err("invalid GUI handoff record length".into());
        }
        let mut record = [0; 8];
        let mut count = 0;
        if unsafe {
            ReadFile(
                self.raw(),
                record.as_mut_ptr(),
                record.len() as u32,
                &mut count,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(error("receive GUI handoff record"));
        }
        if count != record.len() as u32 {
            return Err("incomplete GUI handoff record".into());
        }
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn retirement_descriptor_is_optional_closed_and_digest_bound() {
        let mut action = serde_json::to_value(resume_action()).unwrap();
        assert!(action.get("retirementInput").is_none());
        action["retirementInput"] = serde_json::json!({"path":"C:\\synthetic\\selection.json",
            "nativeId":{"volume":7,"file":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]}, "sha256":"a".repeat(64)});
        assert!(serde_json::from_value::<GuiReplacementAction>(action.clone()).is_ok());
        let mut bad = action.clone(); bad["retirementInput"]["sha256"] = "A".repeat(64).into();
        assert!(serde_json::from_value::<GuiReplacementAction>(bad).is_err());
        let mut bad = action.clone(); bad["retirementInput"].as_object_mut().unwrap().remove("nativeId");
        assert!(serde_json::from_value::<GuiReplacementAction>(bad).is_err());
        let mut bad = action; bad["retirementInput"]["extra"] = true.into();
        assert!(serde_json::from_value::<GuiReplacementAction>(bad).is_err());
    }
    use super::*;
    fn request() -> Vec<OsString> {
        [
            "--version",
            "1",
            "--creator",
            "4294967295",
            "--creation",
            "1",
            "--package",
            env!("CARGO_PKG_VERSION"),
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn replacement_wire_requires_every_identity_and_exact_version() {
        let valid = request();
        assert_eq!(
            ReplacementRequest::receive(valid.clone()).unwrap().action,
            GuiReplacementAction::ShowMain {}
        );
        for index in 0..valid.len() {
            let mut missing = valid.clone();
            missing.remove(index);
            assert!(ReplacementRequest::receive(missing).is_err());
        }
        for index in [1, 3, 5, 7] {
            for value in ["", "0", "unknown"] {
                let mut invalid = valid.clone();
                invalid[index] = value.into();
                assert!(ReplacementRequest::receive(invalid).is_err());
            }
        }
        let mut extra = valid;
        extra.push("--watchdog".into());
        assert!(ReplacementRequest::receive(extra).is_err());
    }

    fn resume_action() -> GuiReplacementAction {
        let target = |kind, root: &str, anchor: &str, volume, byte| GuiReplacementTarget {
            kind,
            root_path: root.into(),
            native_root_id: NativeObjectId {
                volume,
                file: [byte; 16],
            },
            anchor_path: anchor.into(),
            anchor_native_id: NativeObjectId {
                volume,
                file: [byte + 1; 16],
            },
        };
        GuiReplacementAction::ResumeApply(GuiApplyContinuation {
            request_id: "synthetic correlation".into(),
            saved_settings_sha256: [3; 32],
            retirement_input: None,
            targets: vec![
                GuiTargetExpectation {
                    target: target(
                        GuiTargetKind::Desktop,
                        r"C:\First target",
                        r"C:\First target\Antigravity.exe",
                        1,
                        1,
                    ),
                    current: GuiCurrentExpectation::Absent {},
                },
                GuiTargetExpectation {
                    target: target(
                        GuiTargetKind::Desktop,
                        r"C:\Второй target",
                        r"C:\Второй target\Antigravity.exe",
                        2,
                        3,
                    ),
                    current: GuiCurrentExpectation::Present {
                        slot_id: "synthetic-slot".into(),
                        current_sha256: [4; 32],
                    },
                },
                GuiTargetExpectation {
                    target: target(
                        GuiTargetKind::Ide,
                        r"C:\Legacy IDE",
                        r"C:\Legacy IDE\resources\app\extensions\antigravity\out\extension.js",
                        3,
                        5,
                    ),
                    current: GuiCurrentExpectation::NotApplicable {},
                },
                GuiTargetExpectation {
                    target: target(GuiTargetKind::Cli, r"C:\CLI", r"C:\CLI\agy.exe", 4, 7),
                    current: GuiCurrentExpectation::NotApplicable {},
                },
            ],
        })
    }

    fn v2_request(action: &str) -> Vec<OsString> {
        let mut args = request();
        args[1] = "2".into();
        args.extend(["--action".into(), action.into()]);
        args
    }

    #[test]
    fn vendor_update_continuation_requires_every_bound_field() {
        let mut action = resume_action();
        let GuiReplacementAction::ResumeApply(ref mut continuation) = action else { panic!("fixture") };
        let id = NativeObjectId { volume: 42, file: [9; 16] };
        continuation.targets[0].current = GuiCurrentExpectation::VendorUpdate {
            slot_id: "vendor-slot".into(), prior_current_sha256: [1; 32], new_parent_id: id.clone(),
            new_resources_id: id.clone(), new_archive_id: id, new_executable_sha256: [2; 32],
            new_archive_sha256: [3; 32], new_binding_sha256: [4; 32],
        };
        let value = serde_json::to_value(&action).unwrap();
        assert_eq!(value["targets"][0]["current"]["state"], "vendorUpdate");
        assert_eq!(value["targets"][0]["current"]["priorCurrentSha256"], hex::encode([1; 32]));
        assert_eq!(GuiReplacementAction::receive_json(&value.to_string()).unwrap(), action);
        #[derive(serde::Deserialize)]
        #[serde(tag = "state", rename_all = "camelCase", deny_unknown_fields)]
        enum OlderCurrent { Absent {}, Present {}, NotApplicable {} }
        assert!(serde_json::from_value::<OlderCurrent>(value["targets"][0]["current"].clone()).is_err());
        for field in ["slotId", "priorCurrentSha256", "newParentId", "newResourcesId", "newArchiveId",
            "newExecutableSha256", "newArchiveSha256", "newBindingSha256"] {
            let mut missing = value.clone();
            missing["targets"][0]["current"].as_object_mut().unwrap().remove(field);
            assert!(GuiReplacementAction::receive_json(&missing.to_string()).is_err(), "{field}");
            let mut null = value.clone();
            null["targets"][0]["current"][field] = serde_json::Value::Null;
            assert!(GuiReplacementAction::receive_json(&null.to_string()).is_err(), "{field}");
        }
        let mut extra = value.clone();
        extra["targets"][0]["current"]["unrecognized"] = true.into();
        assert!(GuiReplacementAction::receive_json(&extra.to_string()).is_err());
        let mut malformed = value.clone();
        malformed["targets"][0]["current"]["newBindingSha256"] = "invalid".into();
        assert!(GuiReplacementAction::receive_json(&malformed.to_string()).is_err());
        let mut wrong_kind = value;
        wrong_kind["targets"][0]["target"]["kind"] = "ide".into();
        assert!(GuiReplacementAction::receive_json(&wrong_kind.to_string()).is_err());
    }

    #[test]
    fn v2_action_requires_complete_all_target_data_and_show_main_has_none() {
        let value = serde_json::to_value(resume_action()).unwrap();
        assert!(ReplacementRequest::receive(v2_request(&value.to_string())).is_ok());
        for field in ["requestId", "savedSettingsSha256", "targets"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(ReplacementRequest::receive(v2_request(&missing.to_string())).is_err());
        }
        for field in ["target", "current"] {
            let mut missing = value.clone();
            missing["targets"][0].as_object_mut().unwrap().remove(field);
            assert!(ReplacementRequest::receive(v2_request(&missing.to_string())).is_err());
        }
        for field in [
            "kind",
            "rootPath",
            "nativeRootId",
            "anchorPath",
            "anchorNativeId",
        ] {
            let mut missing = value.clone();
            missing["targets"][0]["target"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(ReplacementRequest::receive(v2_request(&missing.to_string())).is_err());
        }
        let mut unknown_kind = value.clone();
        unknown_kind["targets"][0]["target"]["kind"] = "unknown".into();
        assert!(GuiReplacementAction::receive_json(&unknown_kind.to_string()).is_err());
        let mut legacy_v2 = value.clone();
        let legacy_target = legacy_v2["targets"][0]["target"].as_object_mut().unwrap();
        let anchor = legacy_target.remove("anchorPath").unwrap();
        legacy_target.insert("desktopPath".into(), anchor);
        let native = legacy_target.remove("anchorNativeId").unwrap();
        legacy_target.insert("desktopNativeId".into(), native);
        assert!(GuiReplacementAction::receive_json(&legacy_v2.to_string()).is_err());
        for (index, current) in [
            (0, serde_json::json!({"state":"notApplicable"})),
            (2, serde_json::json!({"state":"absent"})),
            (
                2,
                serde_json::json!({"state":"present","slotId":"synthetic","currentSha256":hex::encode([4;32])}),
            ),
            (3, serde_json::json!({"state":"absent"})),
            (
                3,
                serde_json::json!({"state":"present","slotId":"synthetic","currentSha256":hex::encode([4;32])}),
            ),
        ] {
            let mut mismatch = value.clone();
            mismatch["targets"][index]["current"] = current;
            assert!(GuiReplacementAction::receive_json(&mismatch.to_string()).is_err());
        }
        // The helper distinguishes an explicit vector from an omitted field;
        // Core owns positive complete-domain qualification, including emptiness.
        let mut explicit_empty = value.clone();
        explicit_empty["targets"] = serde_json::json!([]);
        assert!(GuiReplacementAction::receive_json(&explicit_empty.to_string()).is_ok());
        for invalid in [
            serde_json::json!({"action":"showMain", "targets":[]}),
            serde_json::json!({"action":"showMain", "continuation":null}),
            serde_json::json!({"action":"unknown"}),
            serde_json::json!({"action":"resumeApply"}),
        ] {
            assert!(GuiReplacementAction::receive_json(&invalid.to_string()).is_err());
        }
        let mut empty_id = value.clone();
        empty_id["requestId"] = "".into();
        assert!(GuiReplacementAction::receive_json(&empty_id.to_string()).is_err());
        let mut malformed_hash = value.clone();
        malformed_hash["savedSettingsSha256"] = "not-a-sha256".into();
        assert!(GuiReplacementAction::receive_json(&malformed_hash.to_string()).is_err());
        let show = serde_json::to_string(&GuiReplacementAction::ShowMain {}).unwrap();
        assert_eq!(
            ReplacementRequest::receive(v2_request(&show))
                .unwrap()
                .action,
            GuiReplacementAction::ShowMain {}
        );
        let mut missing_v2_action = request();
        missing_v2_action[1] = "2".into();
        assert!(ReplacementRequest::receive(missing_v2_action).is_err());
        let mut v1_with_action = v2_request(&show);
        v1_with_action[1] = "1".into();
        assert!(ReplacementRequest::receive(v1_with_action).is_err());
    }

    #[test]
    fn current_expectation_is_tagged_required_and_never_defaults_to_absence() {
        let hash = hex::encode([4; 32]);
        for valid in [
            serde_json::json!({"state":"absent"}),
            serde_json::json!({"state":"present","slotId":"synthetic-slot","currentSha256":hash}),
            serde_json::json!({"state":"notApplicable"}),
        ] {
            assert!(serde_json::from_value::<GuiCurrentExpectation>(valid).is_ok());
        }
        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"state":"unknown"}),
            serde_json::json!({"state":"absent","slotId":null}),
            serde_json::json!({"state":"absent","currentSha256":null}),
            serde_json::json!({"state":"present"}),
            serde_json::json!({"state":"present","slotId":"synthetic-slot"}),
            serde_json::json!({"state":"present","currentSha256":hash}),
            serde_json::json!({"state":"present","slotId":"synthetic-slot","currentSha256":""}),
            serde_json::json!({"state":"present","slotId":"synthetic-slot","currentSha256":hash,"extra":true}),
            serde_json::json!({"state":"notApplicable","slotId":null}),
            serde_json::json!({"state":"notApplicable","currentSha256":hash}),
        ] {
            assert!(serde_json::from_value::<GuiCurrentExpectation>(invalid).is_err());
        }
    }

    #[test]
    fn native_windows_argv_roundtrip_preserves_v2_unicode_paths_and_quotes() {
        use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
        let current = ProcessIdentity::current().unwrap();
        let mut action = resume_action();
        if let GuiReplacementAction::ResumeApply(continuation) = &mut action {
            // Correlation text is transported unchanged; Core owns UUID policy.
            continuation.request_id = "synthetic \"quoted\" \\ tail\\".into();
        }
        let parameters = ReplacementRequest::parameters(&current, &action).unwrap();
        let mut command: OsString = "fixture.exe ".into();
        command.push(parameters);
        let mut count = 0;
        let raw = unsafe { CommandLineToArgvW(wide(&command).as_ptr(), &mut count) };
        assert!(!raw.is_null());
        let mut arguments = Vec::new();
        for argument in unsafe { std::slice::from_raw_parts(raw, count as usize) } {
            let mut length = 0;
            unsafe {
                while *(*argument).add(length) != 0 {
                    length += 1;
                }
            }
            arguments.push(OsString::from_wide(unsafe {
                std::slice::from_raw_parts(*argument, length)
            }));
        }
        unsafe { LocalFree(raw.cast()) };
        assert_eq!(arguments[1], GUI_REPLACEMENT_FLAG);
        let mut request = arguments.into_iter().skip(2).collect::<Vec<_>>();
        // Same-process creator must remain invalid even in a native argv fixture.
        assert!(ReplacementRequest::receive(request.clone()).is_err());
        request[3] = "4294967295".into();
        assert_eq!(ReplacementRequest::receive(request).unwrap().action, action);
        assert!(quote_windows_argument(OsStr::new("embedded\0NUL")).is_err());
    }

    #[test]
    fn private_rendezvous_receives_actual_peers_and_exact_transfer_records() {
        // Native pipe fixture only: no process creation, UAC or Settings access.
        let current = ProcessIdentity::current().unwrap();
        let mut name = pipe_name(&current);
        name.push(".native-protocol-test");
        let server = Rendezvous::create(&name, current.sid()).unwrap();
        assert!(Rendezvous::create(&name, current.sid()).is_err());
        assert!(!server.connected().unwrap());
        let client = Rendezvous::open(&name).unwrap();
        assert!(server.connected().unwrap());
        assert_eq!(server.peer(true).unwrap(), current.pid());
        assert_eq!(client.peer(false).unwrap(), current.pid());
        assert_eq!(server.record().unwrap(), None);
        client.send(READY).unwrap();
        assert_eq!(server.record().unwrap(), Some(*READY));
        server.send(COMMIT).unwrap();
        assert_eq!(client.record().unwrap(), Some(*COMMIT));
        client.send(COMMITTED).unwrap();
        assert_eq!(server.record().unwrap(), Some(*COMMITTED));
        drop(client);
        assert_eq!(server.record().unwrap_err(), PEER_CLOSED);
        drop(server);
        assert!(Rendezvous::create(&name, current.sid()).is_ok());
    }
}
