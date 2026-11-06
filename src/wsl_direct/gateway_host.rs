//! Console-only source restriction and owned forwarding under the local policy binding.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use crate::wsl_direct_gateway::{
    CommitFailure, DuplexPump, Failure, OpeningFailure, OpeningOutcome, PumpState, RequestHead,
};
use crate::{wsl_direct_authority, wsl_direct_gateway, wsl_direct_policy_binding};

#[derive(Debug)]
struct Config {
    bind: Ipv4Addr,
    source: Ipv4Addr,
    opening: Duration,
    header_bytes: usize,
    max_active: usize,
    poll: Duration,
}
impl Config {
    fn parse(args: &[String]) -> Result<Self, &'static str> {
        let names = [
            "--bind-ip",
            "--source-ip",
            "--opening-ms",
            "--header-bytes",
            "--max-active",
            "--poll-ms",
        ];
        if args.len() != names.len() * 2 {
            return Err("ARGUMENTS");
        }
        let mut values = std::collections::BTreeMap::new();
        for pair in args.chunks_exact(2) {
            if !names.contains(&pair[0].as_str())
                || values.insert(pair[0].as_str(), pair[1].as_str()).is_some()
            {
                return Err("ARGUMENTS");
            }
        }
        let ip = |name| {
            values[name]
                .parse::<Ipv4Addr>()
                .ok()
                .filter(|ip| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast())
                .ok_or("ADDRESS")
        };
        let number = |name| {
            values[name]
                .parse::<u64>()
                .ok()
                .filter(|n| *n != 0)
                .ok_or("BUDGET")
        };
        let max_active = usize::try_from(number("--max-active")?).map_err(|_| "BUDGET")?;
        i32::try_from(max_active).map_err(|_| "BACKLOG")?;
        max_active.checked_add(4).ok_or("BUDGET")?;
        let opening = Duration::from_millis(number("--opening-ms")?);
        Instant::now().checked_add(opening).ok_or("BUDGET")?;
        Ok(Self {
            bind: ip("--bind-ip")?,
            source: ip("--source-ip")?,
            opening,
            header_bytes: usize::try_from(number("--header-bytes")?).map_err(|_| "BUDGET")?,
            max_active,
            poll: Duration::from_millis(number("--poll-ms")?),
        })
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::io::{AsRawHandle, AsRawSocket};

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(socket: usize, level: i32, name: i32, value: *const u8, len: i32) -> i32;
        fn getsockopt(socket: usize, level: i32, name: i32, value: *mut u8, len: *mut i32) -> i32;
        fn WSAGetLastError() -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileType(handle: *mut std::ffi::c_void) -> u32;
    }

    pub fn parent_pipes() -> io::Result<()> {
        // FILE_TYPE_PIPE. The parent must retain the sole writer and drain stdout.
        if unsafe { GetFileType(io::stdin().as_raw_handle()) } != 3
            || unsafe { GetFileType(io::stdout().as_raw_handle()) } != 3
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dedicated parent pipes required",
            ));
        }
        Ok(())
    }

    pub fn reserve(config: &Config) -> io::Result<TcpListener> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        // Winsock SOL_SOCKET and SO_EXCLUSIVEADDRUSE, before bind. socket2 has no wrapper.
        let enabled = 1i32;
        let len = std::mem::size_of_val(&enabled) as i32;
        if unsafe {
            setsockopt(
                socket.as_raw_socket() as usize,
                65535,
                -5,
                (&enabled as *const i32).cast(),
                len,
            )
        } != 0
        {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        let mut observed = 0i32;
        let mut observed_len = len;
        if unsafe {
            getsockopt(
                socket.as_raw_socket() as usize,
                65535,
                -5,
                (&mut observed as *mut i32).cast(),
                &mut observed_len,
            )
        } != 0
        {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        if observed != enabled || observed_len != len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "exclusive reservation not established",
            ));
        }
        socket.bind(&SocketAddr::from((config.bind, 0)).into())?;
        socket
            .listen(i32::try_from(config.max_active).map_err(|_| io::ErrorKind::InvalidInput)?)?;
        socket.set_nonblocking(true)?;
        let listener: TcpListener = socket.into();
        if listener.local_addr()?.ip() != config.bind || listener.local_addr()?.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bound endpoint mismatch",
            ));
        }
        Ok(listener)
    }
}

struct ControlResult {
    eof: bool,
    error: Option<io::Error>,
}
fn control_reader(
    input: &mut impl Read,
    stop: &AtomicBool,
    hold: &AtomicBool,
    invalid: &AtomicBool,
    notify: impl Fn(),
) -> ControlResult {
    let mut error = None;
    loop {
        let mut byte = [0];
        match input.read(&mut byte) {
            Ok(0) => {
                stop.store(true, Ordering::Release);
                notify();
                return ControlResult { eof: true, error };
            }
            Ok(_) => {
                if byte[0] == b'H' {
                    hold.store(true, Ordering::Release);
                } else {
                    invalid.store(true, Ordering::Release);
                    error.get_or_insert_with(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "control accepts H or EOF only")
                    });
                }
                stop.store(true, Ordering::Release);
                notify();
                // Keep observing the parent's lifetime after malformed control input.
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                stop.store(true, Ordering::Release);
                notify();
                return ControlResult {
                    eof: false,
                    error: Some(e),
                };
            }
        }
    }
}

struct Record {
    id: u128,
    line: String,
}
struct StatusFailure {
    id: u128,
    error: io::Error,
}
fn status_writer(
    output: &mut impl Write,
    records: mpsc::Receiver<Record>,
    acknowledged: mpsc::Sender<u128>,
) -> Result<(), StatusFailure> {
    for record in records {
        output
            .write_all(record.line.as_bytes())
            .and_then(|_| output.flush())
            .map_err(|error| StatusFailure {
                id: record.id,
                error,
            })?;
        acknowledged.send(record.id).map_err(|_| StatusFailure {
            id: record.id,
            error: io::Error::new(io::ErrorKind::BrokenPipe, "status owner lost"),
        })?;
    }
    Ok(())
}

enum Phase {
    Header(RequestHead),
    Reply {
        bytes: &'static [u8],
        written: usize,
        cause: Failure,
    },
    Opening,
    Tunnel,
    Done,
}
struct ConnectionOutcome {
    cause: String,
    boundary: Option<Failure>,
    io_error: Option<io::Error>,
    response_bytes: usize,
    shutdown: io::Result<()>,
}
struct Connection {
    id: u128,
    socket: TcpStream,
    deadline: Instant,
    phase: Phase,
    outcome: Option<ConnectionOutcome>,
    queued: bool,
    cancelled: Arc<AtomicBool>,
    committed: Arc<AtomicBool>,
    opening: Option<JoinHandle<OpeningOutcome>>,
    opening_failure: Option<OpeningFailure>,
    commit_failure: Option<CommitFailure>,
    opening_panic: Option<Box<dyn std::any::Any + Send>>,
    pump: Option<DuplexPump>,
    shared_group: Option<crate::group::GroupTransferOutcome>,
    cancel_shutdown: Option<io::Result<()>>,
}
impl Connection {
    fn finish(&mut self, cause: String, response_bytes: usize, io_error: Option<io::Error>) {
        let boundary = match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Reply { cause, .. } => Some(cause),
            _ => None,
        };
        self.outcome = Some(ConnectionOutcome {
            cause,
            boundary,
            io_error,
            response_bytes,
            shutdown: self.socket.shutdown(Shutdown::Both),
        });
        self.phase = Phase::Done;
    }
    fn cancel(&mut self) {
        if self.outcome.is_some() {
            return;
        }
        if self.opening.is_some() || self.pump.is_some() {
            self.cancelled.store(true, Ordering::Release);
            self.cancel_shutdown
                .get_or_insert_with(|| self.socket.shutdown(Shutdown::Both));
            if let Some(pump) = &mut self.pump {
                pump.cancel();
            }
            return;
        }
        let written = match self.phase {
            Phase::Reply { written, .. } => written,
            _ => 0,
        };
        self.finish("CANCELLED".into(), written, None);
    }
    fn collect_opening(&mut self) {
        if !self.opening.as_ref().is_some_and(JoinHandle::is_finished) {
            return;
        }
        match self.opening.take().unwrap().join() {
            Ok(OpeningOutcome::Pump(pump)) => {
                self.pump = Some(pump);
                self.phase = Phase::Tunnel;
            }
            Ok(OpeningOutcome::Shared(wsl_direct_gateway::SharedTransferOutcome::Tcp(pump))) => {
                self.pump = Some(pump);
                self.phase = Phase::Tunnel;
            }
            Ok(OpeningOutcome::Shared(wsl_direct_gateway::SharedTransferOutcome::Group(mut outcome))) => {
                let label = if outcome.cancelled { "TUNNEL_CANCELLED" }
                    else if outcome.error.is_some() || !outcome.upload_eof || !outcome.download_eof
                        || outcome.client_shutdown.is_err() || outcome.upstream_shutdown.is_err() { "TUNNEL_FAILED" }
                    else { "TUNNEL_COMPLETE" };
                let error = outcome.error.take();
                self.shared_group = Some(outcome);
                self.finish(label.into(), crate::proxy::RESP_ESTABLISHED.len(), error);
            }
            Ok(OpeningOutcome::Shared(wsl_direct_gateway::SharedTransferOutcome::Invalid(error))) => {
                self.finish("TUNNEL_FAILED".into(), crate::proxy::RESP_ESTABLISHED.len(), Some(error));
            }
            Ok(OpeningOutcome::CommitFailed(failure)) => {
                let count = failure.success_bytes_written;
                self.commit_failure = Some(failure);
                self.finish("COMMIT_FAILED".into(), count, None);
            }
            Ok(OpeningOutcome::Failed(failure)) => {
                let bytes = failure.error.response();
                self.opening_failure = Some(failure);
                if let Some(bytes) = bytes {
                    self.phase = Phase::Reply {
                        bytes,
                        written: 0,
                        cause: Failure::AlreadyComplete,
                    };
                } else {
                    self.finish("OPENING_CANCELLED".into(), 0, None);
                }
            }
            Err(panic) => {
                self.opening_panic = Some(panic);
                self.finish("OPENING_PANIC".into(), 0, None);
            }
        }
    }
    fn advance(&mut self, now: Instant) {
        if self.cancelled.load(Ordering::Acquire) {
            self.cancel();
        }
        if self.outcome.is_some() {
            return;
        }
        self.collect_opening();
        if self.opening.is_some() && self.committed.load(Ordering::Acquire) {
            self.phase = Phase::Tunnel;
        }
        if let Some(pump) = &mut self.pump {
            if self.cancelled.load(Ordering::Acquire) {
                pump.cancel();
            }
            if pump.poll() == PumpState::NoPendingWorkers && !matches!(self.phase, Phase::Done) {
                let failed = pump.startup_error.is_some()
                    || pump
                        .upload_result()
                        .is_none_or(|r| !matches!(r,Ok(outcome) if outcome.transfer.is_ok()))
                    || pump
                        .download_result()
                        .is_none_or(|r| !matches!(r,Ok(outcome) if outcome.transfer.is_ok()));
                let result = if pump.cancellation.is_some() {
                    "TUNNEL_CANCELLED"
                } else if failed {
                    "TUNNEL_FAILED"
                } else {
                    "TUNNEL_COMPLETE"
                };
                self.finish(
                    result.into(),
                    crate::proxy::RESP_ESTABLISHED.len(),
                    None,
                );
            }
            return;
        }
        if self.opening.is_some() {
            if now >= self.deadline && !self.committed.load(Ordering::Acquire) {
                self.cancel_shutdown
                    .get_or_insert_with(|| self.socket.shutdown(Shutdown::Both));
            }
            return; // DNS/connect remains owned; never join or drop a still-running opener.
        }
        if self.outcome.is_some() {
            return;
        }
        if now >= self.deadline {
            let written = match self.phase {
                Phase::Reply { written, .. } => written,
                _ => 0,
            };
            // At expiry make at most one nonblocking 504 attempt, only before any response byte.
            // No wait/retry or replacement follows a partial response.
            let mut response_bytes = written;
            let mut io_error = None;
            if written == 0 {
                match self
                    .socket
                    .write(Failure::OpeningDeadline.response().unwrap())
                {
                    Ok(n) => response_bytes = n,
                    Err(error) => io_error = Some(error),
                }
            }
            self.finish("OPENING_DEADLINE".into(), response_bytes, io_error);
            return;
        }
        match &mut self.phase {
            Phase::Header(parser) => {
                let mut buffer = [0u8; 8192];
                let read_bytes;
                let request = match self.socket.read(&mut buffer) {
                    Ok(0) => {
                        let failure = Failure::InvalidRequest(
                            wsl_direct_authority::AuthorityError::InvalidRequest,
                        );
                        self.phase = Phase::Reply {
                            bytes: failure.response().unwrap(),
                            written: 0,
                            cause: failure,
                        };
                        return;
                    }
                    Ok(n) => {
                        read_bytes = n;
                        parser.push(&buffer[..n])
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        return
                    }
                    Err(e) => {
                        self.finish(format!("READ_{:?}", e.kind()), 0, Some(e));
                        return;
                    }
                };
                let failure = match request {
                    Ok(step) => match step.authority {
                        None => return,
                        Some(authority) => match wsl_direct_gateway::prepare_open(&authority) {
                            Err(failure) => failure,
                            Ok(prepared) => {
                                let client = match self.socket.try_clone() {
                                    Ok(client) => client,
                                    Err(error) => {
                                        self.finish("OPENING_CLONE_FAILED".into(), 0, Some(error));
                                        return;
                                    }
                                };
                                let prefetched = buffer[step.consumed..read_bytes].to_vec();
                                let deadline = self.deadline;
                                let cancelled = Arc::clone(&self.cancelled);
                                let committed = Arc::clone(&self.committed);
                                let supervisor = thread::current();
                                match thread::Builder::new()
                                    .name("wsl-gateway-open".into())
                                    .spawn(move || {
                                        let outcome = if prepared.is_gate() {
                                            prepared.start_shared(client, prefetched, deadline, &cancelled, &committed, &supervisor)
                                        } else {
                                            prepared.start(client, prefetched, deadline, &cancelled, &committed, &supervisor)
                                        };
                                        supervisor.unpark();
                                        outcome
                                    }) {
                                    Ok(handle) => {
                                        self.opening = Some(handle);
                                        self.phase = Phase::Opening;
                                    }
                                    Err(error) => {
                                        self.finish("OPENING_SPAWN_FAILED".into(), 0, Some(error))
                                    }
                                }
                                return;
                            }
                        },
                    },
                    Err(failure) => failure,
                };
                match failure.response() {
                    Some(bytes) => {
                        self.phase = Phase::Reply {
                            bytes,
                            written: 0,
                            cause: failure,
                        }
                    }
                    None => self.finish("REQUEST_REJECTED".into(), 0, None),
                }
            }
            Phase::Reply {
                bytes,
                written,
                cause,
            } => {
                let (failure, io_error) = match self.socket.write(&bytes[*written..]) {
                    Ok(0) => ("WRITE_ZERO".into(), Some(io::ErrorKind::WriteZero.into())),
                    Ok(n) => {
                        *written += n;
                        if *written != bytes.len() {
                            return;
                        }
                        (
                            match cause {
                                Failure::PolicyUnavailable => "POLICY_UNAVAILABLE".into(),
                                Failure::InvalidRequest(_) => "BAD_REQUEST".into(),
                                _ => "REQUEST_REJECTED".into(),
                            },
                            None,
                        )
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        return
                    }
                    Err(e) => (format!("WRITE_{:?}", e.kind()), Some(e)),
                };
                let written = *written;
                self.finish(failure, written, io_error);
            }
            Phase::Opening | Phase::Tunnel | Phase::Done => {}
        }
    }
    fn record(&self) -> Record {
        let outcome = self.outcome.as_ref().unwrap();
        let io = outcome
            .io_error
            .as_ref()
            .map(|error| {
                format!(
                    "{:?}:{}",
                    error.kind(),
                    error
                        .raw_os_error()
                        .map_or_else(|| "NONE".into(), |n| n.to_string())
                )
            })
            .unwrap_or_else(|| "NONE".into());
        let boundary = match self
            .opening_failure
            .as_ref()
            .map(|f| &f.error)
            .or(outcome.boundary.as_ref())
        {
            Some(Failure::InvalidRequest(error)) => format!("{error:?}"),
            Some(error) => format!("{error:?}"),
            None => "NONE".into(),
        };
        let shutdown = match &outcome.shutdown {
            Ok(()) => "OK".into(),
            Err(e) => format!("{:?}", e.kind()),
        };
        Record {
            id: self.id,
            line: format!(
                "AGWSLGW1 CONNECTION id={} result={} boundary={} io={} response_bytes={} shutdown={} opening_io={} origin_shutdown={} commit={} pump_start={} upload={} download={} pump_cancel={} cancel_shutdown={}\n",
                self.id, outcome.cause, boundary, io, outcome.response_bytes, shutdown,
                io_label(self.opening_failure.as_ref().and_then(|f|f.io_error.as_ref())),
                shutdown_label(self.opening_failure.as_ref().and_then(|f|f.origin_shutdown.as_ref())),
                self.commit_failure.as_ref().map(|f|format!("{}:{}:{}",match &f.error {wsl_direct_gateway::CommitError::Boundary(error)=>format!("{error:?}"),wsl_direct_gateway::CommitError::Io(error)=>io_label(Some(error))},shutdown_label(Some(&f.shutdown.client)),shutdown_label(Some(&f.shutdown.origin)))).unwrap_or_else(||"NONE".into()),
                io_label(self.pump.as_ref().and_then(|p|p.startup_error.as_ref())),
                self.shared_group.as_ref().map(|g| group_direction_label(g.upload_eof, &g.upstream_shutdown)).unwrap_or_else(||direction_label(self.pump.as_ref().and_then(DuplexPump::upload_result))),
                self.shared_group.as_ref().map(|g| group_direction_label(g.download_eof, &g.client_shutdown)).unwrap_or_else(||direction_label(self.pump.as_ref().and_then(DuplexPump::download_result))),
                self.shared_group.as_ref().filter(|g|g.cancelled).map(|g|format!("{}:{}",shutdown_label(Some(&g.client_shutdown)),shutdown_label(Some(&g.upstream_shutdown)))).or_else(||self.pump.as_ref().and_then(|p|p.cancellation.as_ref()).map(|r|format!("{}:{}",shutdown_label(Some(&r.client)),shutdown_label(Some(&r.origin))))).unwrap_or_else(||"NONE".into()),
                shutdown_label(self.cancel_shutdown.as_ref()),
            ),
        }
    }
}

fn io_label(error: Option<&io::Error>) -> String {
    error
        .map(|error| {
            format!(
                "{:?}:{}",
                error.kind(),
                error
                    .raw_os_error()
                    .map_or_else(|| "NONE".into(), |n| n.to_string())
            )
        })
        .unwrap_or_else(|| "NONE".into())
}
fn shutdown_label(result: Option<&io::Result<()>>) -> String {
    match result {
        None => "NONE".into(),
        Some(Ok(())) => "OK".into(),
        Some(Err(error)) => io_label(Some(error)),
    }
}
fn direction_label(
    result: Option<&thread::Result<wsl_direct_gateway::DirectionOutcome>>,
) -> String {
    match result {
        None => "NOT_STARTED".into(),
        Some(Err(_)) => "PANIC".into(),
        Some(Ok(outcome)) => {
            let transfer = match &outcome.transfer {
                Ok(()) => "EOF".into(),
                Err(failure) => format!("{:?}:{}", failure.phase, io_label(Some(&failure.error))),
            };
            let abort = outcome
                .abort
                .as_ref()
                .map(|r| {
                    format!(
                        "{}:{}",
                        shutdown_label(Some(&r.client)),
                        shutdown_label(Some(&r.origin))
                    )
                })
                .unwrap_or_else(|| "NONE".into());
            format!("{transfer}:{abort}")
        }
    }
}

fn group_direction_label(eof: bool, shutdown: &io::Result<()>) -> String {
    match shutdown {
        Ok(()) if eof => "EOF:NONE".into(),
        Ok(()) => "NOT_EOF:NONE".into(),
        Err(error) => format!("WriteShutdown:{}:NONE", io_label(Some(error))),
    }
}

struct Owner {
    listener: Option<TcpListener>,
    connections: Vec<Connection>,
    control: Option<JoinHandle<ControlResult>>,
    control_result: Option<thread::Result<ControlResult>>,
    status: Option<JoinHandle<Result<(), StatusFailure>>>,
    status_result: Option<thread::Result<Result<(), StatusFailure>>>,
    sender: Option<mpsc::SyncSender<Record>>,
    acknowledged: mpsc::Receiver<u128>,
    stop: Arc<AtomicBool>,
    hold: Arc<AtomicBool>,
    control_invalid: Arc<AtomicBool>,
    failure: Option<String>,
    native_error: Option<io::Error>,
    next_id: u128,
}
impl Owner {
    fn fail_io(&mut self, stage: &str, error: io::Error) {
        self.failure
            .get_or_insert_with(|| format!("{}_{:?}", stage, error.kind()));
        self.native_error.get_or_insert(error);
    }
    fn observe(&mut self) {
        if self.control_invalid.load(Ordering::Acquire) {
            self.failure.get_or_insert("CONTROL_InvalidData".into());
        }
        if self.control.as_ref().is_some_and(JoinHandle::is_finished) {
            self.control_result = Some(self.control.take().unwrap().join());
        }
        if self.status.as_ref().is_some_and(JoinHandle::is_finished) {
            self.status_result = Some(self.status.take().unwrap().join());
        }
        while let Ok(id) = self.acknowledged.try_recv() {
            self.connections.retain(|connection| connection.id != id);
        }
        if let Some(result) = &self.control_result {
            match result {
                Ok(ControlResult { error: None, .. }) => {}
                Ok(ControlResult { error: Some(e), .. }) => {
                    self.failure
                        .get_or_insert_with(|| format!("CONTROL_{:?}", e.kind()));
                }
                Err(_) => {
                    self.failure.get_or_insert("CONTROL_PANIC".into());
                }
            }
        }
        if let Some(result) = &self.status_result {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(failure)) => {
                    self.failure.get_or_insert_with(|| {
                        format!("STATUS_{}_{:?}", failure.id, failure.error.kind())
                    });
                }
                Err(_) => {
                    self.failure.get_or_insert("STATUS_PANIC".into());
                }
            }
        }
    }
    fn publish(&mut self, record: Record) -> Result<(), ()> {
        match self.sender.as_ref().ok_or(())?.try_send(record) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.failure.get_or_insert("STATUS_UNAVAILABLE".into());
                Err(())
            }
        }
    }
    fn control_eof(&self) -> bool {
        matches!(
            &self.control_result,
            Some(Ok(ControlResult { eof: true, .. }))
        )
    }
}

#[cfg(windows)]
fn serve(config: Config) -> bool {
    let policy_status = if wsl_direct_policy_binding::BoundPublicV1::bundled().is_ok() {
        "RECEIVED"
    } else {
        "UNAVAILABLE"
    };
    let (sender, records) = mpsc::sync_channel(config.max_active + 4); // Active receipts plus READY/STOPPING/HOLD/STOPPED.
    let (acknowledge, acknowledged) = mpsc::channel();
    let mut owner = Owner {
        listener: None,
        connections: Vec::new(),
        control: None,
        control_result: None,
        status: None,
        status_result: None,
        sender: Some(sender),
        acknowledged,
        stop: Arc::new(AtomicBool::new(false)),
        hold: Arc::new(AtomicBool::new(false)),
        control_invalid: Arc::new(AtomicBool::new(false)),
        failure: None,
        native_error: None,
        next_id: 3,
    };
    let supervisor = thread::current();
    let status = thread::Builder::new()
        .name("wsl-gateway-status".into())
        .spawn(move || {
            let outcome = status_writer(&mut io::stdout().lock(), records, acknowledge);
            supervisor.unpark();
            outcome
        });
    match status {
        Ok(handle) => owner.status = Some(handle),
        Err(error) => {
            let _ = writeln!(
                io::stdout(),
                "AGWSLGW1 STARTUP_ERROR reason=STATUS_SPAWN_{:?}",
                error.kind()
            );
            return false;
        }
    }
    let stop = Arc::clone(&owner.stop);
    let hold = Arc::clone(&owner.hold);
    let invalid = Arc::clone(&owner.control_invalid);
    let supervisor = thread::current();
    match thread::Builder::new()
        .name("wsl-gateway-control".into())
        .spawn(move || {
            control_reader(&mut io::stdin().lock(), &stop, &hold, &invalid, || {
                supervisor.unpark()
            })
        }) {
        Ok(handle) => owner.control = Some(handle),
        Err(e) => {
            owner.fail_io("CONTROL_SPAWN", e);
        }
    }
    if owner.failure.is_none() && !owner.stop.load(Ordering::Acquire) {
        match windows::reserve(&config) {
            Ok(listener) => {
                owner.listener = Some(listener); // Retain the reservation before READY construction/publication.
                match owner.listener.as_ref().unwrap().local_addr() {
                    Ok(endpoint) if !owner.stop.load(Ordering::Acquire) => {
                        let _ = owner.publish(Record { id: 0, line: format!("AGWSLGW1 READY endpoint={} source={} access=SOURCE_ONLY policy={}\n", endpoint, config.source, policy_status) });
                    }
                    Ok(_) => {}
                    Err(e) => owner.fail_io("ENDPOINT", e),
                }
            }
            Err(e) => owner.fail_io("BIND", e),
        }
    }
    let mut stopping_reported = false;
    let mut hold_reported = false;
    let mut retired = false;
    loop {
        owner.observe();
        let stopping = owner.stop.load(Ordering::Acquire) || owner.failure.is_some();
        if !stopping {
            if owner.connections.len() < config.max_active {
                match owner.listener.as_ref().unwrap().accept() {
                    Ok((socket, peer)) => {
                        if owner.stop.load(Ordering::Acquire) {
                            drop(socket);
                            continue;
                        }
                        // The kernel peer comparison precedes parser allocation or reading.
                        let parser =
                            RequestHead::new(config.source.into(), peer, config.header_bytes);
                        let accepted_at = Instant::now();
                        let deadline = accepted_at.checked_add(config.opening);
                        let id = owner.next_id;
                        match owner.next_id.checked_add(1) {
                            Some(next) => owner.next_id = next,
                            None => {
                                owner.failure = Some("IDENTIFIER_OVERFLOW".into());
                            }
                        }
                        let mut connection = Connection {
                            id,
                            socket,
                            deadline: deadline.unwrap_or(accepted_at),
                            phase: Phase::Done,
                            outcome: None,
                            queued: false,
                            cancelled: Arc::clone(&owner.stop),
                            committed: Arc::new(AtomicBool::new(false)),
                            opening: None,
                            opening_failure: None,
                            commit_failure: None,
                            opening_panic: None,
                            pump: None,
                            shared_group: None,
                            cancel_shutdown: None,
                        };
                        if deadline.is_none() {
                            owner.failure = Some("DEADLINE_OVERFLOW".into());
                        }
                        match parser {
                            Err(Failure::ForeignPeer) => {
                                connection.finish("FOREIGN_PEER".into(), 0, None)
                            }
                            Err(_) => connection.finish("REQUEST_REJECTED".into(), 0, None),
                            Ok(parser) => match connection.socket.set_nonblocking(true) {
                                Ok(()) => connection.phase = Phase::Header(parser),
                                Err(e) => {
                                    connection.finish(format!("SOCKET_{:?}", e.kind()), 0, Some(e))
                                }
                            },
                        }
                        owner.connections.push(connection);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => owner.fail_io("ACCEPT", e),
                }
            }
            for connection in &mut owner.connections {
                connection.advance(Instant::now());
            }
        } else {
            for connection in &mut owner.connections {
                connection.cancel();
                connection.advance(Instant::now());
            }
            let held = owner.hold.load(Ordering::Acquire);
            if held && !hold_reported {
                let _ = owner.publish(Record {
                    id: 1,
                    line: "AGWSLGW1 STOPPING reason=PARENT_HOLD action=RETAIN_PARENT_STDIN\n"
                        .into(),
                });
                hold_reported = true;
                stopping_reported = true;
            } else if !stopping_reported {
                let reason = owner
                    .failure
                    .as_deref()
                    .unwrap_or("PARENT_EOF_OR_CONTROL_STOP");
                let record = Record {
                    id: 1,
                    line: format!(
                        "AGWSLGW1 STOPPING reason={} action=CLOSE_PARENT_STDIN\n",
                        reason
                    ),
                };
                let _ = owner.publish(record);
                stopping_reported = true;
            }
        }
        for connection in &mut owner.connections {
            if connection.outcome.is_some() && !connection.queued {
                if let Some(sender) = &owner.sender {
                    match sender.try_send(connection.record()) {
                        Ok(()) => connection.queued = true,
                        Err(_) => {
                            owner.failure.get_or_insert("STATUS_UNAVAILABLE".into());
                        }
                    }
                }
            }
        }
        // A failed control reader never proves parent retirement. Preserve custody for the creator.
        if !retired
            && (owner.control_eof() || owner.control.is_none() && owner.control_result.is_none())
            && owner
                .connections
                .iter()
                .all(|connection| connection.outcome.is_some())
        {
            owner.listener.take();
            let status = if owner.failure.is_none() {
                "STOPPED"
            } else {
                "FAILED"
            };
            let _ = owner.publish(Record {
                id: 2,
                line: format!("AGWSLGW1 {} policy={}\n", status, policy_status),
            });
            owner.sender.take();
            retired = true;
        }
        if retired && owner.control.is_none() && owner.status.is_none() {
            break;
        }
        // The control reader's retained Thread handle interrupts this wait on parent loss.
        thread::park_timeout(config.poll);
    }
    owner.failure.is_none()
}

pub(crate) fn run(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    let args: Vec<String> = match args.into_iter().map(|arg| arg.into_string()).collect() {
        Ok(args) => args,
        Err(_) => {
            let _ = writeln!(io::stdout(), "AGWSLGW1 STARTUP_ERROR reason=ARGUMENTS");
            return Err("ARGUMENTS".into());
        }
    };
    let config = match Config::parse(&args) {
        Ok(config) => config,
        Err(reason) => {
            let _ = writeln!(io::stdout(), "AGWSLGW1 STARTUP_ERROR reason={reason}");
            return Err(reason.into());
        }
    };
    #[cfg(windows)]
    {
        if windows::parent_pipes().is_err() {
            let _ = writeln!(io::stdout(), "AGWSLGW1 STARTUP_ERROR reason=PARENT_PIPES");
            return Err("PARENT_PIPES".into());
        }
        if serve(config) {
            Ok(())
        } else {
            Err("GATEWAY_FAILED".into())
        }
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        let _ = writeln!(
            io::stdout(),
            "AGWSLGW1 STARTUP_ERROR reason=WINDOWS_REQUIRED"
        );
        Err("WINDOWS_REQUIRED".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        [
            "--bind-ip",
            "192.0.2.1",
            "--source-ip",
            "192.0.2.2",
            "--opening-ms",
            "1000",
            "--header-bytes",
            "4096",
            "--max-active",
            "2",
            "--poll-ms",
            "5",
        ]
        .map(String::from)
        .to_vec()
    }
    #[test]
    fn config_requires_explicit_confined_addresses_and_positive_budgets() {
        let config = Config::parse(&args()).unwrap();
        assert_eq!(config.bind, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(config.max_active, 2);
        assert!(Config::parse(&[]).is_err());
        for (index, value) in [
            (1, "0.0.0.0"),
            (1, "224.0.0.1"),
            (3, "255.255.255.255"),
            (5, "0"),
            (7, "0"),
            (9, "0"),
            (11, "0"),
        ] {
            let mut args = args();
            args[index] = value.into();
            assert!(Config::parse(&args).is_err());
        }
        let mut duplicate = args();
        duplicate[2] = "--bind-ip".into();
        assert!(Config::parse(&duplicate).is_err());
    }
    #[test]
    fn control_eof_stops_and_invalid_input_is_retained_until_eof() {
        for input in [b"".as_slice(), b"unexpected"] {
            let stop = AtomicBool::new(false);
            let result = control_reader(
                &mut io::Cursor::new(input),
                &stop,
                &AtomicBool::new(false),
                &AtomicBool::new(false),
                || {},
            );
            assert!(result.eof && stop.load(Ordering::Acquire));
            assert_eq!(result.error.is_some(), !input.is_empty());
        }
        let stop = AtomicBool::new(false);
        let hold = AtomicBool::new(false);
        let invalid = AtomicBool::new(false);
        let result = control_reader(&mut io::Cursor::new(b"HHH"), &stop, &hold, &invalid, || {});
        assert!(result.eof && result.error.is_none() && hold.load(Ordering::Acquire));
        assert!(!invalid.load(Ordering::Acquire));
    }
    #[test]
    fn status_acknowledges_only_a_fully_written_flushed_versioned_record() {
        let (sender, records) = mpsc::sync_channel(1);
        let (ack, received) = mpsc::channel();
        sender.send(Record{id:0,line:"AGWSLGW1 READY endpoint=192.0.2.1:49152 source=192.0.2.2 access=SOURCE_ONLY policy=UNAVAILABLE\n".into()}).unwrap();
        drop(sender);
        let mut output = Vec::new();
        assert!(status_writer(&mut output, records, ack).is_ok());
        assert_eq!(received.recv().unwrap(), 0);
        assert_eq!(output,b"AGWSLGW1 READY endpoint=192.0.2.1:49152 source=192.0.2.2 access=SOURCE_ONLY policy=UNAVAILABLE\n");
    }

    #[test]
    fn status_failure_retains_record_identity_and_never_acknowledges_partial_or_unflushed_output() {
        struct BrokenOutput {
            bytes: Vec<u8>,
            fail_flush: bool,
        }
        impl Write for BrokenOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if !self.fail_flush && !self.bytes.is_empty() {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                let n = if self.fail_flush {
                    bytes.len()
                } else {
                    bytes.len().min(3)
                };
                self.bytes.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        for fail_flush in [false, true] {
            let (sender, records) = mpsc::sync_channel(1);
            let (ack, received) = mpsc::channel();
            let line = "AGWSLGW1 STOPPED policy=UNAVAILABLE\n";
            sender
                .send(Record {
                    id: 2,
                    line: line.into(),
                })
                .unwrap();
            drop(sender);
            let mut output = BrokenOutput {
                bytes: Vec::new(),
                fail_flush,
            };
            let failure = status_writer(&mut output, records, ack).err().unwrap();
            assert_eq!(failure.id, 2);
            assert_eq!(
                failure.error.kind(),
                if fail_flush {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::BrokenPipe
                }
            );
            assert_eq!(
                output.bytes,
                if fail_flush {
                    line.as_bytes()
                } else {
                    &line.as_bytes()[..3]
                }
            );
            assert!(received.try_recv().is_err());
        }
    }

    #[test]
    fn control_read_error_is_retained_and_never_claims_parent_eof() {
        struct BrokenControl;
        impl Read for BrokenControl {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        let stop = AtomicBool::new(false);
        let notifications = std::cell::Cell::new(0);
        let result = control_reader(
            &mut BrokenControl,
            &stop,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            || notifications.set(notifications.get() + 1),
        );
        assert!(stop.load(Ordering::Acquire));
        assert!(!result.eof);
        assert_eq!(
            result.error.unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(notifications.get(), 1);
    }
}
