//! Silent adapter for the vendor's original WSL standard streams.
//!
//! The vendor owns the facade's PID, not the actual runtime owner. Neither
//! process copies server bytes: only the final WSL consumer writes the inherited
//! outputs. Original stdin EOF cancels acquisition, while every acquired owner
//! remains in this process until its actual completion has been received.
use crate::windows_coordinator::{
    session, vendor_launch::VendorWslLaunch, OWNER_OBSERVATION_CADENCE as OBSERVATION_CADENCE,
};
use crate::wsl_runtime::{self, VendorAdmission};
use std::ffi::OsString;
use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, RawHandle};
use std::os::windows::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

pub(crate) const OWNER_ROLE: &str = "--wsl-runtime-owner";

const INVALID_LAUNCH: i32 = 64;
const ADMISSION_FAILED: i32 = 71;
const PREPARATION_FAILED: i32 = 72;
const CONSUMER_FAILED: i32 = 73;
const LIFETIME_FAILED: i32 = 74;
const CANCELLED: i32 = 75;

/// Original producer arguments, excluding only the first exact role selector.
/// Even a role-looking value in the opaque server tail is forwarded verbatim.
pub(crate) fn serve(arguments: Vec<OsString>) -> i32 {
    if VendorWslLaunch::receive(arguments.clone()).is_err() {
        return INVALID_LAUNCH;
    }
    let input = match OriginalInput::receive() {
        Ok(input) => input,
        Err(_) => return LIFETIME_FAILED,
    };
    if let Err(code) = input_status(&input) {
        return code;
    }
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(_) => return ADMISSION_FAILED,
    };
    let mut command = Command::new(executable);
    command.arg(OWNER_ROLE).args(arguments);
    inherited_server_streams(&mut command);
    command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW; no Job breakaway.
    if let Err(code) = input_status(&input) {
        return code;
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return CONSUMER_FAILED,
    };
    // Blocking wait is safe only in this facade: it owns no gateway, read lease
    // or preparation task. A failed wait retains the same creator Child.
    loop {
        match child.wait() {
            Ok(exit) => return exit_code(exit),
            Err(_) => thread::sleep(OBSERVATION_CADENCE),
        }
    }
}

pub(crate) fn owner(arguments: Vec<OsString>) -> i32 {
    let launch = match VendorWslLaunch::receive(arguments) {
        Ok(launch) => launch,
        Err(_) => return INVALID_LAUNCH,
    };
    let input = match OriginalInput::receive() {
        Ok(input) => input,
        Err(_) => return LIFETIME_FAILED,
    };
    let cancellation = Arc::new(AtomicBool::new(false));
    let mut input_failure = None;
    if !continue_acquisition(&input, &cancellation, &mut input_failure) {
        return cancelled_code(&input_failure);
    }
    let observer = match InputObserver::spawn(&input, Arc::clone(&cancellation)) {
        Ok(observer) => observer,
        Err(_) => return LIFETIME_FAILED,
    };
    let wanted = crate::settings::routing_snapshot();
    if !continue_acquisition(&input, &cancellation, &mut input_failure) {
        return observer.finish_with_code(cancelled_code(&input_failure));
    }
    // The one admission owner also obtains the vendor-global lane for the
    // pass-through branch. This adapter does not recreate its qualification.
    let admission = match wsl_runtime::receive_vendor(launch, wanted, &cancellation) {
        Ok(admission) => admission,
        Err(_) => return observer.finish_with_code(ADMISSION_FAILED),
    };
    match admission {
        VendorAdmission::PassThrough { program, launch, lane } => {
            let _lane = lane;
            let result = (|| {
                if !continue_acquisition(&input, &cancellation, &mut input_failure) {
                    return cancelled_code(&input_failure);
                }
                let command = match wsl_runtime::passthrough_command(&program, &launch) {
                    Ok(command) => command,
                    Err(_) => return PREPARATION_FAILED,
                };
                run_consumer(command, None, &input, &cancellation, &mut input_failure)
            })();
            observer.finish_with_code(result)
        }
        VendorAdmission::Selected { read, lane, preparation } => {
            // These are deliberately retained on the owner thread. Only the
            // immutable preparation input and cancellation flag cross threads.
            let _read = read;
            let _lane = lane;
            let result = run_selected(preparation, &input, &cancellation, &mut input_failure);
            // Retire the owned input observer before either lane/read pin can
            // leave this scope, including every preparation and spawn failure.
            observer.finish_with_code(result)
        }
    }
}

fn run_selected(
    preparation: wsl_runtime::RuntimePreparationInput,
    input: &OriginalInput,
    cancellation: &Arc<AtomicBool>,
    input_failure: &mut Option<io::Error>,
) -> i32 {
    if !continue_acquisition(input, cancellation, input_failure) {
        return cancelled_code(input_failure);
    }
    let worker_cancel = Arc::clone(cancellation);
    let preparation = match thread::Builder::new()
        .name("wsl-vendor-preparation".into())
        .spawn(move || wsl_runtime::prepare_runtime(preparation, worker_cancel))
    {
        Ok(worker) => worker,
        Err(_) => return PREPARATION_FAILED,
    };
    while !preparation.is_finished() {
        continue_acquisition(input, cancellation, input_failure);
        thread::sleep(OBSERVATION_CADENCE);
    }
    // Join only after actual completion. Cancellation never detaches a
    // blocking preparation command, its readers, or this exact thread.
    let mut recipe = match preparation.join() {
        Ok(Ok(recipe)) => recipe,
        Ok(Err(_)) | Err(_) => return PREPARATION_FAILED,
    };
    if !continue_acquisition(input, cancellation, input_failure) {
        return cancelled_code(input_failure);
    }
    let mut gateway = match recipe.gateway.take() {
        Some(spec) => match session::GatewaySession::spawn(spec, Instant::now()) {
            Ok(gateway) => Some(gateway),
            Err(failure) => {
                if let Some(mut gateway) = failure.session {
                    settle_gateway(&mut gateway);
                }
                return PREPARATION_FAILED;
            }
        },
        None => None,
    };
    let endpoint = if let Some(gateway) = gateway.as_mut() {
        loop {
            let update = gateway.poll();
            if !continue_acquisition(input, cancellation, input_failure) {
                settle_gateway(gateway);
                return cancelled_code(input_failure);
            }
            if let Some(ready) = gateway.ready() {
                break Some(ready.endpoint);
            }
            if !gateway.errors().is_empty() || update.phase == session::Phase::Settled {
                settle_gateway(gateway);
                return PREPARATION_FAILED;
            }
            thread::sleep(OBSERVATION_CADENCE);
        }
    } else {
        None
    };
    // Environment is captured once and is not printed or persisted.
    let inherited = std::env::vars_os().collect::<Vec<_>>();
    if !continue_acquisition(input, cancellation, input_failure) {
        if let Some(gateway) = gateway.as_mut() {
            settle_gateway(gateway);
        }
        return cancelled_code(input_failure);
    }
    let command = match recipe.command(endpoint, &inherited) {
        Ok(command) => command,
        Err(_) => {
            if let Some(gateway) = gateway.as_mut() {
                settle_gateway(gateway);
            }
            return PREPARATION_FAILED;
        }
    };
    run_consumer(command, gateway, input, cancellation, input_failure)
}

fn inherited_server_streams(command: &mut Command) {
    command.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
}

fn run_consumer(
    mut command: Command,
    mut gateway: Option<session::GatewaySession>,
    input: &OriginalInput,
    cancellation: &Arc<AtomicBool>,
    input_failure: &mut Option<io::Error>,
) -> i32 {
    inherited_server_streams(&mut command);
    if let Some(gateway) = gateway.as_mut() {
        gateway.poll();
        if gateway.ready().is_none() {
            settle_gateway(gateway);
            return PREPARATION_FAILED;
        }
    }
    if !continue_acquisition(input, cancellation, input_failure) {
        if let Some(gateway) = gateway.as_mut() {
            settle_gateway(gateway);
        }
        return cancelled_code(input_failure);
    }
    let mut consumer = match command.spawn() {
        Ok(consumer) => consumer,
        Err(_) => {
            if let Some(gateway) = gateway.as_mut() {
                settle_gateway(gateway);
            }
            return CONSUMER_FAILED;
        }
    };
    let mut observation_failure = None;
    let exit = loop {
        // The separately owned observer keeps cancellation responsive during
        // admission and consumer I/O without placing synchronous pipe peeks on
        // this gateway-supervision thread after the consumer has inherited it.
        let accepting = !cancellation.load(Ordering::SeqCst);
        if let Some(gateway) = gateway.as_mut() {
            gateway.poll();
            if !accepting || gateway.ready().is_none() {
                gateway.request_hold(Instant::now());
            }
        }
        // No kill: a Windows WSL relay's forced death is not proof of Linux
        // consumer retirement. Original stdin already reaches the actual LS.
        match consumer.try_wait() {
            Ok(Some(exit)) => break exit,
            Ok(None) => {}
            Err(error) => {
                observation_failure.get_or_insert(error);
                cancellation.store(true, Ordering::SeqCst);
                if let Some(gateway) = gateway.as_mut() {
                    gateway.request_hold(Instant::now());
                }
            }
        }
        thread::sleep(OBSERVATION_CADENCE);
    };
    let gateway_clean = if let Some(gateway) = gateway.as_mut() {
        settle_gateway(gateway);
        gateway.clean_shutdown()
    } else {
        true
    };
    if observation_failure.is_some() || input_failure.is_some() || !gateway_clean {
        LIFETIME_FAILED
    } else {
        exit_code(exit)
    }
}

fn settle_gateway(gateway: &mut session::GatewaySession) {
    gateway.request_stop(Instant::now());
    while gateway.poll().phase != session::Phase::Settled {
        thread::sleep(OBSERVATION_CADENCE);
    }
}

fn continue_acquisition(
    input: &OriginalInput,
    cancellation: &Arc<AtomicBool>,
    failure: &mut Option<io::Error>,
) -> bool {
    if cancellation.load(Ordering::SeqCst) {
        return false;
    }
    match input.is_open() {
        Ok(true) => true,
        Ok(false) => {
            cancellation.store(true, Ordering::SeqCst);
            false
        }
        Err(error) => {
            failure.get_or_insert(error);
            cancellation.store(true, Ordering::SeqCst);
            false
        }
    }
}

fn cancelled_code(failure: &Option<io::Error>) -> i32 {
    if failure.is_some() { LIFETIME_FAILED } else { CANCELLED }
}

fn input_status(input: &OriginalInput) -> Result<(), i32> {
    match input.is_open() {
        Ok(true) => Ok(()),
        Ok(false) => Err(CANCELLED),
        Err(_) => Err(LIFETIME_FAILED),
    }
}

fn exit_code(exit: ExitStatus) -> i32 {
    exit.code().unwrap_or(LIFETIME_FAILED)
}

/// Exactly owned non-consuming reader. It can cancel while the admission owner
/// is inside a synchronous native qualification call. Its duplicate is a read
/// handle only, with no extra writer that could suppress the vendor's EOF.
#[must_use = "finish the input observer before releasing runtime read/lane custody"]
struct InputObserver {
    stop: Arc<AtomicBool>,
    worker: thread::JoinHandle<io::Result<()>>,
}
impl InputObserver {
    fn spawn(input: &OriginalInput, cancellation: Arc<AtomicBool>) -> io::Result<Self> {
        let handle = unsafe { BorrowedHandle::borrow_raw(input.0) }.try_clone_to_owned()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new().name("wsl-vendor-input-observer".into()).spawn(move || {
            let input = OriginalInput(handle.as_raw_handle());
            while !worker_stop.load(Ordering::SeqCst) {
                match input.is_open() {
                    Ok(true) => thread::sleep(OBSERVATION_CADENCE),
                    Ok(false) => {
                        cancellation.store(true, Ordering::SeqCst);
                        return Ok(());
                    }
                    Err(error) => {
                        cancellation.store(true, Ordering::SeqCst);
                        return Err(error);
                    }
                }
            }
            Ok(())
        })?;
        Ok(Self { stop, worker })
    }

    fn finish_with_code(self, code: i32) -> i32 {
        self.stop.store(true, Ordering::SeqCst);
        // The creator retains its thread and read handle even if observation is
        // delayed. Callers still own every applicable lane/read pin here.
        while !self.worker.is_finished() {
            thread::sleep(OBSERVATION_CADENCE);
        }
        match self.worker.join() {
            Ok(Ok(())) => code,
            Ok(Err(_)) | Err(_) => LIFETIME_FAILED,
        }
    }
}

/// A borrowed read handle, never an additional pipe writer or payload reader.
/// Neither facade nor owner closes the process standard-input handle.
struct OriginalInput(RawHandle);
impl OriginalInput {
    fn receive() -> io::Result<Self> {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "original input absent"));
        }
        Ok(Self(handle))
    }

    fn is_open(&self) -> io::Result<bool> {
        // The pinned vendor uses stdin only as an empty lifetime pipe: it never
        // writes a payload. Unknown buffered input is unsupported, not proof of
        // a live parent. Reject it without consuming bytes, including when a
        // closed writer still has buffered data that would hide broken-pipe EOF.
        let mut available = 0;
        let success = unsafe {
            PeekNamedPipe(self.0, std::ptr::null_mut(), 0, std::ptr::null_mut(),
                &mut available, std::ptr::null_mut())
        };
        if success != 0 {
            if available != 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "unsupported vendor lifetime-input payload"));
            }
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error().map(|code| code as u32) {
            Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED) => Ok(false),
            _ => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;

    #[test]
    fn empty_lifetime_pipe_requires_actual_writer_close_and_latches_eof() {
        let (reader, writer) = io::pipe().unwrap();
        let input = OriginalInput(reader.as_raw_handle());
        assert!(input.is_open().unwrap());
        drop(writer);
        assert!(!input.is_open().unwrap());
        let cancel = Arc::new(AtomicBool::new(false));
        let mut failure = None;
        assert!(!continue_acquisition(&input, &cancel, &mut failure));
        assert!(cancel.load(Ordering::SeqCst));
        assert!(!continue_acquisition(&input, &cancel, &mut failure));
        assert!(failure.is_none());
    }

    #[test]
    fn unsupported_buffered_payload_never_counts_as_liveness_or_gets_consumed() {
        let (mut reader, mut writer) = io::pipe().unwrap();
        writer.write_all(b"retained-payload").unwrap();
        drop(writer);
        let input = OriginalInput(reader.as_raw_handle());
        let cancel = Arc::new(AtomicBool::new(false));
        let mut failure = None;
        assert!(!continue_acquisition(&input, &cancel, &mut failure));
        assert_eq!(failure.unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(cancel.load(Ordering::SeqCst));
        let mut payload = Vec::new();
        reader.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, b"retained-payload");
        assert!(!input.is_open().unwrap());
    }

    #[test]
    fn owned_observer_cancels_while_calling_thread_performs_no_input_probes() {
        let (reader, writer) = io::pipe().unwrap();
        let input = OriginalInput(reader.as_raw_handle());
        let cancel = Arc::new(AtomicBool::new(false));
        let observer = InputObserver::spawn(&input, Arc::clone(&cancel)).unwrap();
        drop(writer);
        // The bound is the actual vendor's existing stop window, not a
        // production retirement deadline. Only the observer performs a peek.
        let end = Instant::now() + Duration::from_millis(5000);
        while !cancel.load(Ordering::SeqCst) && Instant::now() < end {
            thread::sleep(OBSERVATION_CADENCE);
        }
        let observed = cancel.load(Ordering::SeqCst);
        let result = observer.finish_with_code(0);
        assert!(observed);
        assert_eq!(result, 0);
    }
}
