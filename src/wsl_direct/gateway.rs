//! Gateway request/open boundary and owned duplex forwarding under the local policy binding.

use crate::wsl_direct_authority::{self, Authority, AuthorityError, HeaderPrefix};
use crate::wsl_direct_policy_binding::BoundPublicV1;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Instant;

#[cfg(test)]
const SUCCESS: &[u8] = crate::proxy::RESP_ESTABLISHED;
const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const GATEWAY_TIMEOUT: &[u8] =
    b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

#[derive(Debug)]
pub(crate) enum Failure {
    ForeignPeer,
    InvalidRequest(AuthorityError),
    AlreadyComplete,
    PolicyUnavailable,
    TargetMismatch,
    OpeningDeadline,
    DeniedTarget,
    ResolutionFailed,
    ConnectFailed,
    Cancelled,
}
impl Failure {
    pub fn response(&self) -> Option<&'static [u8]> {
        match self {
            Self::ForeignPeer | Self::AlreadyComplete | Self::Cancelled => None,
            Self::InvalidRequest(_) => Some(BAD_REQUEST),
            Self::PolicyUnavailable
            | Self::TargetMismatch
            | Self::ResolutionFailed
            | Self::ConnectFailed => Some(BAD_GATEWAY),
            Self::OpeningDeadline => Some(GATEWAY_TIMEOUT),
            Self::DeniedTarget => {
                Some(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            }
        }
    }
}

/// Listener owner supplies the actual kernel peer and independently selected source.
/// Retention is bounded by the header budget; input[consumed..] stays caller-owned.
pub(crate) struct RequestHead {
    header: Vec<u8>,
    budget: usize,
    terminal: bool,
}
pub(crate) struct HeaderStep {
    pub consumed: usize,
    pub authority: Option<AdmittedAuthority>,
}
/// Constructed only after the listener's source check and a complete request.
pub(crate) struct AdmittedAuthority(Authority);
impl RequestHead {
    pub fn new(expected: IpAddr, peer: SocketAddr, budget: usize) -> Result<Self, Failure> {
        if peer.ip() != expected {
            return Err(Failure::ForeignPeer);
        }
        Ok(Self {
            header: Vec::new(),
            budget,
            terminal: false,
        })
    }
    pub fn push(&mut self, input: &[u8]) -> Result<HeaderStep, Failure> {
        if self.terminal {
            return Err(Failure::AlreadyComplete);
        }
        let previous = self.header.len();
        // Never retain an arbitrary payload suffix or allocate beyond the opening budget.
        let offered = input.len().min(self.budget.saturating_sub(previous));
        self.header.extend_from_slice(&input[..offered]);
        match wsl_direct_authority::inspect_prefix(&self.header, self.budget) {
            Ok(HeaderPrefix::Partial) => Ok(HeaderStep {
                consumed: offered,
                authority: None,
            }),
            Ok(HeaderPrefix::Complete {
                authority,
                consumed_header_bytes,
            }) => {
                self.terminal = true;
                self.header.clear(); // CONNECT and Proxy-Authorization never enter the pump.
                Ok(HeaderStep {
                    consumed: consumed_header_bytes - previous,
                    authority: Some(AdmittedAuthority(authority)),
                })
            }
            Err(error) => {
                self.terminal = true;
                self.header.clear();
                Err(Failure::InvalidRequest(error))
            }
        }
    }
}

enum OpeningPolicy {
    Received(Arc<BoundPublicV1>),
    #[cfg(test)]
    Candidate(crate::wsl_direct_public_policy::Candidate<'static>),
}
impl OpeningPolicy {
    fn check(&self, literal: SocketAddr) -> Result<(), Failure> {
        let allowed = match self {
            Self::Received(policy) => policy.check(literal).is_ok(),
            #[cfg(test)]
            Self::Candidate(candidate) => {
                let scope = match literal {
                    SocketAddr::V6(v) => v.scope_id(),
                    _ => 0,
                };
                candidate.candidate_only(literal.ip(), literal.port(), scope)
                    == crate::wsl_direct_public_policy::CandidateDecision::Allow
            }
        };
        if allowed {
            Ok(())
        } else {
            Err(Failure::DeniedTarget)
        }
    }
}

/// Only locally received policy can construct a production opening/target.
pub(crate) struct AuthorizedTarget {
    literal: SocketAddr,
    policy: OpeningPolicy,
}
pub(crate) struct PreparedOpen {
    host: url::Host<String>,
    port: u16,
    policy: OpeningPolicy,
}
impl PreparedOpen {
    pub(crate) fn host(&self) -> &url::Host<String> {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Authorize each actual direct-origin address before dialing it.
    pub(crate) fn check_direct_address(&self, literal: SocketAddr) -> Result<(), Failure> {
        if literal.port() != self.port {
            return Err(Failure::TargetMismatch);
        }
        self.policy.check(literal)
    }

    /// Recheck the public address and the actual connected peer before commit.
    pub(crate) fn check_direct_peer(
        &self,
        literal: SocketAddr,
        observed: SocketAddr,
    ) -> Result<(), Failure> {
        self.check_direct_address(literal)?;
        self.policy.check(observed)?;
        if observed == literal {
            Ok(())
        } else {
            Err(Failure::TargetMismatch)
        }
    }
}
pub(crate) fn prepare_open(admitted: &AdmittedAuthority) -> Result<PreparedOpen, Failure> {
    let authority = &admitted.0;
    let policy = BoundPublicV1::bundled().map_err(|_| Failure::PolicyUnavailable)?;
    Ok(PreparedOpen {
        host: authority.host.clone(),
        port: authority.port,
        policy: OpeningPolicy::Received(Arc::new(policy)),
    })
}
#[derive(Debug)]
pub(crate) struct ConnectAttemptFailure {
    pub literal: SocketAddr,
    pub error: io::Error,
}
#[derive(Debug)]
pub(crate) struct OpeningFailure {
    pub error: Failure,
    pub io_error: Option<io::Error>,
    pub origin_shutdown: Option<io::Result<()>>,
    /// Earlier failed dials; the final failure remains in error/io_error.
    pub prior_connect_failures: Vec<ConnectAttemptFailure>,
}
impl From<Failure> for OpeningFailure {
    fn from(error: Failure) -> Self {
        Self {
            error,
            io_error: None,
            origin_shutdown: None,
            prior_connect_failures: Vec::new(),
        }
    }
}
struct ConnectedOrigin<S> {
    target: AuthorizedTarget,
    stream: S,
}
trait OriginIo {
    type Stream;
    fn resolve(&mut self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
    fn connect(
        &mut self,
        literal: SocketAddr,
        remaining: std::time::Duration,
    ) -> io::Result<Self::Stream>;
    fn peer(&mut self, stream: &Self::Stream) -> io::Result<SocketAddr>;
    fn shutdown(&mut self, stream: &Self::Stream) -> io::Result<()>;
    fn now(&self) -> Instant {
        Instant::now()
    }
}
struct SystemOrigin;
impl OriginIo for SystemOrigin {
    type Stream = TcpStream;
    fn resolve(&mut self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
    fn connect(
        &mut self,
        literal: SocketAddr,
        remaining: std::time::Duration,
    ) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&literal, remaining)
    }
    fn peer(&mut self, stream: &TcpStream) -> io::Result<SocketAddr> {
        stream.peer_addr()
    }
    fn shutdown(&mut self, stream: &TcpStream) -> io::Result<()> {
        stream.shutdown(Shutdown::Both)
    }
}
fn opening_budget_at(
    deadline: Instant,
    cancelled: &AtomicBool,
    now: Instant,
) -> Result<std::time::Duration, Failure> {
    if cancelled.load(Ordering::Acquire) {
        return Err(Failure::Cancelled);
    }
    deadline
        .checked_duration_since(now)
        .filter(|left| !left.is_zero())
        .ok_or(Failure::OpeningDeadline)
}
fn connect_with<O: OriginIo>(
    prepared: PreparedOpen,
    deadline: Instant,
    cancelled: &AtomicBool,
    io: &mut O,
) -> Result<ConnectedOrigin<O::Stream>, OpeningFailure> {
    opening_budget_at(deadline, cancelled, io.now())?;
    let candidates = match &prepared.host {
        url::Host::Domain(host) => {
            io.resolve(host, prepared.port)
                .map_err(|error| OpeningFailure {
                    error: Failure::ResolutionFailed,
                    io_error: Some(error),
                    origin_shutdown: None,
                    prior_connect_failures: Vec::new(),
                })?
        }
        url::Host::Ipv4(ip) => vec![SocketAddr::from((*ip, prepared.port))],
        url::Host::Ipv6(ip) => vec![SocketAddr::from((*ip, prepared.port))],
    };
    opening_budget_at(deadline, cancelled, io.now())?; // DNS may finish after cancellation/deadline.
    let permitted: Vec<_> = candidates
        .into_iter()
        .filter(|literal| {
            prepared.check_direct_address(*literal).is_ok()
        })
        .collect();
    let mut failed_attempts = Vec::new();
    for literal in permitted {
        if let Err(error) = prepared.check_direct_address(literal) {
            let mut failure = OpeningFailure::from(error);
            failure.prior_connect_failures = failed_attempts;
            return Err(failure);
        }
        let remaining = match opening_budget_at(deadline, cancelled, io.now()) {
            Ok(remaining) => remaining,
            Err(error) => {
                let mut failure = OpeningFailure::from(error);
                failure.prior_connect_failures = failed_attempts;
                return Err(failure);
            }
        };
        // Only a failed dial advances within this one resolution. No new DNS/route lookup.
        let stream = match io.connect(literal, remaining) {
            Ok(stream) => stream,
            Err(error) => {
                failed_attempts.push(ConnectAttemptFailure { literal, error });
                continue;
            }
        };
        let checked = (|| -> Result<(), OpeningFailure> {
            opening_budget_at(deadline, cancelled, io.now())?;
            let peer = io.peer(&stream).map_err(|error| OpeningFailure {
                error: Failure::ConnectFailed,
                io_error: Some(error),
                origin_shutdown: None,
                prior_connect_failures: Vec::new(),
            })?;
            prepared.check_direct_peer(literal, peer)?;
            opening_budget_at(deadline, cancelled, io.now())?;
            Ok(())
        })();
        if let Err(mut failure) = checked {
            failure.origin_shutdown = Some(io.shutdown(&stream));
            failure.prior_connect_failures = failed_attempts;
            return Err(failure);
        }
        return Ok(ConnectedOrigin {
            target: AuthorizedTarget {
                literal,
                policy: prepared.policy,
            },
            stream,
        });
    }
    if let Err(error) = opening_budget_at(deadline, cancelled, io.now()) {
        let mut failure = OpeningFailure::from(error);
        failure.prior_connect_failures = failed_attempts;
        return Err(failure);
    }
    match failed_attempts.pop() {
        Some(last) => Err(OpeningFailure {
            error: Failure::ConnectFailed,
            io_error: Some(last.error),
            origin_shutdown: None,
            prior_connect_failures: failed_attempts,
        }),
        None => Err(Failure::DeniedTarget.into()),
    }
}

pub(crate) enum OpeningOutcome {
    Pump(DuplexPump),
    Shared(SharedTransferOutcome),
    Failed(OpeningFailure),
    CommitFailed(CommitFailure),
}

pub(crate) enum SharedTransferOutcome {
    Tcp(DuplexPump),
    Group(crate::group::GroupTransferOutcome),
    Invalid(io::Error),
}

impl PreparedOpen {
    pub(crate) fn is_gate(&self) -> bool {
        matches!(&self.host, url::Host::Domain(host) if crate::proxy::is_gate_host(host) && self.port == 443)
    }

    /// Runs on the retained connection worker through actual transfer retirement.
    pub(crate) fn start_shared(
        self,
        client: TcpStream,
        prefetched: Vec<u8>,
        deadline: Instant,
        cancelled: &AtomicBool,
        committed: &AtomicBool,
        supervisor: &thread::Thread,
    ) -> OpeningOutcome {
        use crate::proxy::route_session::{self, DirectChecks, FrontendEof, OpenFailure, WslTransfer};
        let host = match &self.host {
            url::Host::Domain(host) => host.as_str(),
            _ => return OpeningOutcome::Failed(Failure::DeniedTarget.into()),
        };
        let Some(target) = crate::proxy::GateTarget443::new(host, self.port) else {
            return OpeningOutcome::Failed(Failure::DeniedTarget.into());
        };
        let _gate = crate::routes::begin_gate_connection(&client, host);
        let address = |literal| self.check_direct_address(literal).is_ok();
        let peer = |literal, actual| self.check_direct_peer(literal, actual).is_ok();
        let checks = DirectChecks { address: &address, peer: &peer };
        let opened = match route_session::open_selected_route(&target, deadline, cancelled, Some(&checks)) {
            Ok(opened) => opened,
            Err(error) => return OpeningOutcome::Failed(match error {
                OpenFailure::Cancelled => Failure::Cancelled.into(),
                OpenFailure::Deadline => Failure::OpeningDeadline.into(),
                OpenFailure::DeniedTarget => Failure::DeniedTarget.into(),
                OpenFailure::Unavailable(reason) => OpeningFailure {
                    error: Failure::ConnectFailed,
                    io_error: reason.map(io::Error::other),
                    origin_shutdown: None,
                    prior_connect_failures: Vec::new(),
                },
                OpenFailure::UnsupportedPrivateRoutes => Failure::ConnectFailed.into(),
            }),
        };
        let session = match route_session::commit(opened, client, prefetched, host, FrontendEof::WslSymmetricFin, deadline, cancelled) {
            Ok(session) => session,
            Err(failure) => return OpeningOutcome::CommitFailed(shared_commit_failure(failure)),
        };
        committed.store(true, Ordering::Release);
        supervisor.unpark();
        match session.into_wsl_transfer() {
            Ok(WslTransfer::Tcp { client, upstream, prefetched }) => {
                crate::routes::attach_upstream(&upstream);
                let mut pump = DuplexPump::start_with_activity(client, upstream, prefetched, crate::routes::serving_activity());
                loop {
                    if cancelled.load(Ordering::Acquire) { pump.cancel(); }
                    if pump.poll() == PumpState::NoPendingWorkers { break; }
                    thread::park_timeout(crate::proxy::PUMP_MAX_SLEEP);
                }
                OpeningOutcome::Shared(SharedTransferOutcome::Tcp(pump))
            }
            Ok(WslTransfer::Group { client, group, prefetched }) => {
                OpeningOutcome::Shared(SharedTransferOutcome::Group(group.transfer_wsl(client, prefetched, cancelled)))
            }
            Err(error) => OpeningOutcome::Shared(SharedTransferOutcome::Invalid(error)),
        }
    }

    pub(crate) fn start(
        self,
        client: TcpStream,
        prefetched: Vec<u8>,
        deadline: Instant,
        cancelled: &AtomicBool,
        committed: &AtomicBool,
        supervisor: &thread::Thread,
    ) -> OpeningOutcome {
        match connect_with(self, deadline, cancelled, &mut SystemOrigin) {
            Err(failure) => OpeningOutcome::Failed(failure),
            Ok(origin) => {
                use crate::proxy::route_session::{self, DirectChecks, FrontendEof, OpenedRoute, WslTransfer};
                let target = origin.target;
                let address = |literal| literal == target.literal && target.policy.check(literal).is_ok();
                let peer = |literal, observed| literal == target.literal && target.check_peer(observed).is_ok();
                let checks = DirectChecks { address: &address, peer: &peer };
                let opened = OpenedRoute::Tcp { socket: origin.stream, kind: None, direct_proof: Some((target.literal, &checks)) };
                match route_session::commit(opened, client, prefetched, "", FrontendEof::WslSymmetricFin, deadline, cancelled) {
                    Ok(session) => {
                        committed.store(true, Ordering::Release);
                        supervisor.unpark();
                        match session.into_wsl_transfer() {
                            Ok(WslTransfer::Tcp { client, upstream, prefetched }) => OpeningOutcome::Pump(DuplexPump::start(client, upstream, prefetched)),
                            Ok(WslTransfer::Group { .. }) => OpeningOutcome::Shared(SharedTransferOutcome::Invalid(io::Error::new(io::ErrorKind::InvalidData, "unexpected direct transport"))),
                            Err(error) => OpeningOutcome::Shared(SharedTransferOutcome::Invalid(error)),
                        }
                    },
                    Err(failure) => OpeningOutcome::CommitFailed(shared_commit_failure(failure)),
                }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ShutdownReport {
    pub client: io::Result<()>,
    pub origin: io::Result<()>,
}
fn shutdown_both(client: &TcpStream, origin: &TcpStream) -> ShutdownReport {
    ShutdownReport {
        client: client.shutdown(Shutdown::Both),
        origin: origin.shutdown(Shutdown::Both),
    }
}

#[derive(Debug)]
pub(crate) enum CommitError {
    Boundary(Failure),
    Io(io::Error),
}
#[derive(Debug)]
/// Always terminal: commit consumes and shuts down both sockets, even at zero bytes.
/// Never send a replacement HTTP response through a retained clone after this failure.
pub(crate) struct CommitFailure {
    pub error: CommitError,
    /// Bytes accepted by successful local Write calls; not proof of peer receipt.
    pub success_bytes_written: usize,
    pub shutdown: ShutdownReport,
}

fn shared_commit_failure(failure: crate::proxy::route_session::CommitFailure) -> CommitFailure {
    use crate::proxy::route_session::{CommitCause, OpenFailure};
    let error = match failure.error {
        CommitCause::Io(error) => CommitError::Io(error),
        CommitCause::InvalidDirectPeer => CommitError::Boundary(Failure::TargetMismatch),
        CommitCause::Boundary(OpenFailure::Cancelled) => CommitError::Boundary(Failure::Cancelled),
        CommitCause::Boundary(OpenFailure::Deadline) => CommitError::Boundary(Failure::OpeningDeadline),
        CommitCause::Boundary(_) => CommitError::Boundary(Failure::ConnectFailed),
    };
    CommitFailure {
        error,
        success_bytes_written: failure.bytes_written,
        shutdown: ShutdownReport { client: failure.client_shutdown, origin: failure.upstream_shutdown },
    }
}

impl AuthorizedTarget {
    fn check_peer(&self, observed: SocketAddr) -> Result<(), Failure> {
        self.policy.check(self.literal)?;
        self.policy.check(observed)?;
        if self.literal == observed {
            Ok(())
        } else {
            Err(Failure::TargetMismatch)
        }
    }

}

#[cfg(test)]
fn write_opening<W: Write>(
    client: &mut W,
    bytes: &[u8],
    written: &mut usize,
    before_attempt: impl FnMut(&mut W) -> Result<(), CommitError>,
    after_complete: impl FnOnce(&mut W) -> Result<(), CommitError>,
) -> Result<(), CommitError> {
    crate::proxy::route_session::write_response(client, bytes, written, before_attempt, after_complete, CommitError::Io)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TransferPhase {
    Prefetch,
    Copy,
    WriteShutdown,
}
#[derive(Debug)]
pub(crate) struct TransferFailure {
    pub phase: TransferPhase,
    pub error: io::Error,
}
fn transfer_direction<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    prefetched: &[u8],
    shutdown_write: impl FnOnce() -> io::Result<()>,
) -> Result<(), TransferFailure> {
    destination
        .write_all(prefetched)
        .map_err(|error| TransferFailure {
            phase: TransferPhase::Prefetch,
            error,
        })?;
    // std::io::copy supplies a finite working buffer and checked writes, not a traffic cap.
    io::copy(source, destination).map_err(|error| TransferFailure {
        phase: TransferPhase::Copy,
        error,
    })?;
    shutdown_write().map_err(|error| TransferFailure {
        phase: TransferPhase::WriteShutdown,
        error,
    })
}

#[derive(Debug)]
pub(crate) struct DirectionOutcome {
    pub transfer: Result<(), TransferFailure>,
    /// Present only on a genuine transfer/shutdown error; EOF alone never cancels its sibling.
    pub abort: Option<ShutdownReport>,
}

#[derive(Clone, Copy)]
enum Direction {
    Upload,
    Download,
}

fn run_direction(
    client: TcpStream,
    origin: TcpStream,
    prefetched: Vec<u8>,
    direction: Direction,
    activity: Option<Arc<crate::routes::Activity>>,
) -> DirectionOutcome {
    let to_client = matches!(direction, Direction::Download);
    let (source, destination) = match direction {
        Direction::Upload => (&client, &origin),
        Direction::Download => (&origin, &client),
    };
    let mut sink = &*destination;
    let mut marked = crate::proxy::Marked { inner: &mut sink, activity: activity.as_deref(), to_client };
    let transfer = transfer_direction(&mut &*source, &mut marked, &prefetched, || {
        destination.shutdown(Shutdown::Write)
    });
    let abort = transfer
        .as_ref()
        .err()
        .map(|_| shutdown_both(&client, &origin));
    DirectionOutcome { transfer, abort }
}

#[derive(Default)]
struct Worker {
    handle: Option<JoinHandle<DirectionOutcome>>,
    joined: Option<thread::Result<DirectionOutcome>>,
}
impl Worker {
    fn collect_observed(&mut self) {
        if self.handle.as_ref().is_some_and(JoinHandle::is_finished) {
            self.joined = Some(self.handle.take().unwrap().join());
        }
    }
    fn panicked(&self) -> bool {
        matches!(&self.joined, Some(Err(_)))
    }
}

/// Session owner MUST retain this value while poll() is Pending, including all error exits.
/// There is deliberately no Drop join, detached timeout or claim that shutdown proves exit.
#[must_use = "retain pending pump ownership until both worker joins are observed"]
pub(crate) struct DuplexPump {
    client: TcpStream,
    origin: TcpStream,
    upload: Worker,
    download: Worker,
    pub startup_error: Option<io::Error>,
    pub cancellation: Option<ShutdownReport>,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PumpState {
    Pending,
    NoPendingWorkers,
}
impl DuplexPump {
    fn start(client: TcpStream, origin: TcpStream, prefetched: Vec<u8>) -> Self {
        Self::start_with_activity(client, origin, prefetched, None)
    }

    fn start_with_activity(client: TcpStream, origin: TcpStream, prefetched: Vec<u8>, activity: Option<Arc<crate::routes::Activity>>) -> Self {
        // Originals are owned before the first fallible clone/spawn; partial startup uses cancel().
        let mut pump = Self {
            client,
            origin,
            upload: Worker::default(),
            download: Worker::default(),
            startup_error: None,
            cancellation: None,
        };
        let started = (|| -> io::Result<()> {
            let upload_source = pump.client.try_clone()?;
            let upload_destination = pump.origin.try_clone()?;
            let download_source = pump.origin.try_clone()?;
            let download_destination = pump.client.try_clone()?;
            let upload_activity = activity.clone();
            pump.upload.handle = Some(
                thread::Builder::new()
                    .name("wsl-gateway-upload".into())
                    .spawn(move || {
                        run_direction(
                            upload_source,
                            upload_destination,
                            prefetched,
                            Direction::Upload,
                            upload_activity,
                        )
                    })?,
            );
            pump.download.handle = Some(
                thread::Builder::new()
                    .name("wsl-gateway-download".into())
                    .spawn(move || {
                        run_direction(
                            download_destination,
                            download_source,
                            Vec::new(),
                            Direction::Download,
                            activity,
                        )
                    })?,
            );
            Ok(())
        })();
        if let Err(error) = started {
            pump.startup_error = Some(error);
            pump.cancel();
        }
        pump
    }

    /// Idempotent cancellation request; preserve both syscall outcomes independently.
    pub fn cancel(&mut self) -> &ShutdownReport {
        self.cancellation
            .get_or_insert_with(|| shutdown_both(&self.client, &self.origin))
    }
    /// Every started worker is joined before NoPendingWorkers; original sockets remain owned.
    /// Startup errors and actual worker outcomes must still be checked separately.
    pub fn poll(&mut self) -> PumpState {
        self.upload.collect_observed();
        self.download.collect_observed();
        if self.upload.panicked() || self.download.panicked() {
            self.cancel();
        }
        if self.upload.handle.is_none() && self.download.handle.is_none() {
            PumpState::NoPendingWorkers
        } else {
            PumpState::Pending
        }
    }
    pub fn upload_result(&self) -> Option<&thread::Result<DirectionOutcome>> {
        self.upload.joined.as_ref()
    }
    pub fn download_result(&self) -> Option<&thread::Result<DirectionOutcome>> {
        self.download.joined.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;

    #[test]
    fn shared_tcp_fin_keeps_late_upload_and_prefetch() {
        use crate::proxy::route_session::{self, FrontendEof, OpenedRoute, WslTransfer};
        use std::net::{Ipv4Addr, TcpListener};
        use std::time::Duration;

        fn pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (b, _) = listener.accept().unwrap();
            for socket in [&a, &b] {
                socket.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(4))).unwrap();
            }
            (a, b)
        }
        let (mut peer, client) = pair();
        let (mut origin, upstream) = pair();
        let cancelled = AtomicBool::new(false);
        let opened = OpenedRoute::Tcp { socket: upstream, kind: None, direct_proof: None };
        let session = route_session::commit(opened, client, b"first".to_vec(), "", FrontendEof::WslSymmetricFin,
            Instant::now() + Duration::from_secs(4), &cancelled)
            .unwrap_or_else(|e| panic!("commit failed after {} bytes: {:?}", e.bytes_written, e.error));
        let WslTransfer::Tcp { client, upstream, prefetched } = session.into_wsl_transfer().unwrap() else { panic!("not TCP") };
        let mut pump = DuplexPump::start(client, upstream, prefetched);
        let mut response = vec![0; crate::proxy::RESP_ESTABLISHED.len()];
        let response_result = peer.read_exact(&mut response);
        let sent = origin.write_all(b"body").and_then(|_| origin.shutdown(Shutdown::Write));
        let mut downloaded = Vec::new();
        let download_result = peer.read_to_end(&mut downloaded);
        let late = peer.write_all(b"late").and_then(|_| peer.shutdown(Shutdown::Write));
        let mut uploaded = Vec::new();
        let upload_result = origin.read_to_end(&mut uploaded);
        let until = Instant::now() + Duration::from_secs(4);
        while pump.poll() == PumpState::Pending && Instant::now() < until { thread::sleep(Duration::from_millis(2)); }
        if pump.poll() == PumpState::Pending {
            pump.cancel();
            while pump.poll() == PumpState::Pending { thread::sleep(Duration::from_millis(2)); }
        }
        response_result.unwrap();
        sent.unwrap();
        download_result.unwrap();
        late.unwrap();
        upload_result.unwrap();
        assert_eq!(response, crate::proxy::RESP_ESTABLISHED);
        assert_eq!(downloaded, b"body");
        assert_eq!(uploaded, b"firstlate");
        assert!(matches!(pump.upload_result(), Some(Ok(outcome)) if outcome.transfer.is_ok()));
        assert!(matches!(pump.download_result(), Some(Ok(outcome)) if outcome.transfer.is_ok()));
        assert!(pump.cancellation.is_none());
    }

    fn source() -> std::net::IpAddr {
        "192.0.2.2".parse().unwrap()
    }
    fn peer() -> std::net::SocketAddr {
        "192.0.2.2:49152".parse().unwrap()
    }

    #[test]
    fn foreign_peer_is_rejected_before_header_or_policy_work() {
        assert!(matches!(
            RequestHead::new(source(), "192.0.2.3:49152".parse().unwrap(), 0),
            Err(Failure::ForeignPeer)
        ));
    }

    #[test]
    fn fragmented_header_leaves_every_prefetched_byte_with_the_caller() {
        let header =
            b"CONNECT example.com:8443 HTTP/1.1\r\nProxy-Authorization: Basic synthetic\r\n\r\n";
        let payload: Vec<u8> = (0..=255).collect();
        for split in 0..header.len() {
            let mut parser = RequestHead::new(source(), peer(), header.len()).unwrap();
            let first = parser.push(&header[..split]).unwrap();
            assert_eq!(first.consumed, split);
            assert!(first.authority.is_none());
            let rest = [&header[split..], payload.as_slice()].concat();
            let ready = parser.push(&rest).unwrap();
            assert_eq!(ready.consumed, header.len() - split);
            assert_eq!(ready.authority.unwrap().0.port, 8443);
            assert_eq!(&rest[ready.consumed..], payload);
            assert!(matches!(parser.push(&[]), Err(Failure::AlreadyComplete)));
        }
    }

    #[test]
    fn malformed_and_budget_failures_are_terminal_and_never_open() {
        for bytes in [
            b"CONNECT host:0 HTTP/1.1\r\n\r\n".as_slice(),
            b"CONNECT x:443 HTTP/1.1\r\nBad\0: x\r\n\r\n",
        ] {
            let mut parser = RequestHead::new(source(), peer(), bytes.len()).unwrap();
            let failure = parser.push(bytes).err().unwrap();
            assert_eq!(failure.response(), Some(BAD_REQUEST));
            assert!(matches!(
                parser.push(b"CONNECT x:443 HTTP/1.1\r\n\r\n"),
                Err(Failure::AlreadyComplete)
            ));
        }
        let mut parser = RequestHead::new(source(), peer(), 8).unwrap();
        assert!(matches!(
            parser.push(b"CONNECT x:443 HTTP/1.1\r\n\r\n"),
            Err(Failure::InvalidRequest(_))
        ));
        let mut parser = RequestHead::new(source(), peer(), 0).unwrap();
        assert!(parser.push(&[]).is_err());
    }

    #[test]
    fn received_policy_prepares_gate_non_gate_dns_and_literal_ports() {
        for target in [
            "cloudcode-pa.googleapis.com:443",
            "example.com:8443",
            "8.8.8.8:53",
            "[2606:4700:4700::1111]:65535",
        ] {
            let header = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
            let mut parser = RequestHead::new(source(), peer(), header.len()).unwrap();
            let authority = parser.push(header.as_bytes()).unwrap().authority.unwrap();
            // Preparation binds the selected policy only. Resolution and dialing
            // belong to connect_with; no origin operation is invoked here.
            let prepared = prepare_open(&authority).expect("received policy must prepare");
            assert_eq!(prepared.host, authority.0.host);
            assert_eq!(prepared.port, authority.0.port);
            assert!(matches!(prepared.policy, OpeningPolicy::Received(_)));
        }
    }

    #[test]
    fn permit_checks_each_direct_address_and_the_observed_peer() {
        let prepared = fixture_open(url::Host::Domain("example.com".into()), 8443);
        let public: SocketAddr = "8.8.8.8:8443".parse().unwrap();
        let private: SocketAddr = "10.0.0.1:8443".parse().unwrap();
        let wrong_port: SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert!(prepared.check_direct_address(public).is_ok());
        assert!(matches!(prepared.check_direct_address(private), Err(Failure::DeniedTarget)));
        assert!(matches!(prepared.check_direct_address(wrong_port), Err(Failure::TargetMismatch)));
        assert!(prepared.check_direct_peer(public, public).is_ok());
        assert!(matches!(prepared.check_direct_peer(public, "1.1.1.1:8443".parse().unwrap()), Err(Failure::TargetMismatch)));
    }

    struct ShortWriter {
        bytes: Vec<u8>,
        max_write: usize,
        fail_after: Option<usize>,
    }
    impl std::io::Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .fail_after
                .is_some_and(|limit| self.bytes.len() >= limit)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "synthetic write failure",
                ));
            }
            let n = bytes.len().min(self.max_write);
            self.bytes.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn checked_prefix_and_stream_writes_preserve_bytes_once_before_write_fin() {
        let payload: Vec<u8> = (0..=255).cycle().take(65539).collect();
        let prefix = &payload[..19];
        let mut reader = Cursor::new(&payload[19..]);
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            max_write: 3,
            fail_after: None,
        };
        let fin = Cell::new(false);
        transfer_direction(&mut reader, &mut writer, prefix, || {
            fin.set(true);
            Ok(())
        })
        .unwrap();
        assert!(writer.bytes == payload, "prefix/body mismatch");
        assert!(fin.get());
    }

    #[test]
    fn download_fin_does_not_prevent_later_upload_or_reverse_fin_order() {
        for download_first in [true, false] {
            let mut upload = Vec::new();
            let mut download = Vec::new();
            let upload_fin = Cell::new(false);
            let download_fin = Cell::new(false);
            let mut send_upload = || {
                transfer_direction(
                    &mut Cursor::new(b"late-upload"),
                    &mut upload,
                    b"prefetch:",
                    || {
                        upload_fin.set(true);
                        Ok(())
                    },
                )
            };
            let mut send_download = || {
                transfer_direction(&mut Cursor::new(b"reply"), &mut download, b"", || {
                    download_fin.set(true);
                    Ok(())
                })
            };
            if download_first {
                send_download().unwrap();
                assert!(!upload_fin.get());
                send_upload().unwrap();
            } else {
                send_upload().unwrap();
                assert!(!download_fin.get());
                send_download().unwrap();
            }
            assert_eq!(upload, b"prefetch:late-upload");
            assert_eq!(download, b"reply");
            assert!(upload_fin.get() && download_fin.get());
        }
    }

    #[test]
    fn transfer_failures_keep_phase_and_cause_without_false_fin() {
        let fin = Cell::new(false);
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            max_write: 1,
            fail_after: Some(1),
        };
        let failure = transfer_direction(&mut Cursor::new(b"body"), &mut writer, b"prefix", || {
            fin.set(true);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(failure.phase, TransferPhase::Prefetch);
        assert_eq!(failure.error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(!fin.get());
        let failure =
            transfer_direction(&mut Cursor::new(b"body"), &mut std::io::sink(), b"", || {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "synthetic FIN failure",
                ))
            })
            .unwrap_err();
        assert_eq!(failure.phase, TransferPhase::WriteShutdown);
        assert_eq!(failure.error.kind(), std::io::ErrorKind::NotConnected);
    }

    enum WriteAction {
        Accept(usize),
        Interrupt,
        Fail(io::ErrorKind),
        Zero,
    }
    struct OpeningWriter {
        actions: std::collections::VecDeque<WriteAction>,
        bytes: Vec<u8>,
    }
    impl OpeningWriter {
        fn new(actions: impl IntoIterator<Item = WriteAction>) -> Self {
            Self {
                actions: actions.into_iter().collect(),
                bytes: Vec::new(),
            }
        }
    }
    impl Write for OpeningWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            match self
                .actions
                .pop_front()
                .unwrap_or(WriteAction::Accept(bytes.len()))
            {
                WriteAction::Accept(limit) => {
                    let n = limit.min(bytes.len());
                    self.bytes.extend_from_slice(&bytes[..n]);
                    Ok(n)
                }
                WriteAction::Interrupt => Err(io::ErrorKind::Interrupted.into()),
                WriteAction::Fail(kind) => Err(io::Error::new(kind, "synthetic opening write")),
                WriteAction::Zero => Ok(0),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn opening_failure_before_any_write_reports_zero_and_original_cause() {
        for fail_preparation in [true, false] {
            let mut writer = OpeningWriter::new([WriteAction::Fail(io::ErrorKind::BrokenPipe)]);
            let mut written = 0;
            let final_calls = Cell::new(0);
            let error = write_opening(
                &mut writer,
                SUCCESS,
                &mut written,
                |_| {
                    if fail_preparation {
                        Err(CommitError::Io(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "synthetic preparation",
                        )))
                    } else {
                        Ok(())
                    }
                },
                |_| {
                    final_calls.set(final_calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(written, 0);
            assert!(writer.bytes.is_empty());
            assert_eq!(final_calls.get(), 0);
            assert!(
                matches!(error, CommitError::Io(ref e) if e.kind() == if fail_preparation { io::ErrorKind::PermissionDenied } else { io::ErrorKind::BrokenPipe })
            );
        }
    }

    #[test]
    fn opening_partial_failure_retains_exact_prefix_for_each_exit() {
        enum Stop {
            WriteError,
            WriteZero,
            Preparation,
            Deadline,
        }
        for stop in [
            Stop::WriteError,
            Stop::WriteZero,
            Stop::Preparation,
            Stop::Deadline,
        ] {
            let action = match stop {
                Stop::WriteError => WriteAction::Fail(io::ErrorKind::BrokenPipe),
                Stop::WriteZero => WriteAction::Zero,
                _ => WriteAction::Accept(SUCCESS.len()),
            };
            let mut writer = OpeningWriter::new([WriteAction::Accept(3), action]);
            let mut written = 0;
            let attempts = Cell::new(0);
            let final_calls = Cell::new(0);
            let error = write_opening(
                &mut writer,
                SUCCESS,
                &mut written,
                |_| {
                    attempts.set(attempts.get() + 1);
                    if attempts.get() == 2 {
                        match stop {
                            Stop::Preparation => {
                                return Err(CommitError::Io(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "synthetic timeout setup",
                                )))
                            }
                            Stop::Deadline => {
                                return Err(CommitError::Boundary(Failure::OpeningDeadline))
                            }
                            _ => {}
                        }
                    }
                    Ok(())
                },
                |_| {
                    final_calls.set(final_calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(written, 3);
            assert_eq!(writer.bytes, &SUCCESS[..3]);
            assert_eq!(attempts.get(), 2);
            assert_eq!(final_calls.get(), 0);
            match stop {
                Stop::WriteError => assert!(
                    matches!(error, CommitError::Io(ref e) if e.kind() == io::ErrorKind::BrokenPipe)
                ),
                Stop::WriteZero => assert!(
                    matches!(error, CommitError::Io(ref e) if e.kind() == io::ErrorKind::WriteZero)
                ),
                Stop::Preparation => assert!(
                    matches!(error, CommitError::Io(ref e) if e.kind() == io::ErrorKind::PermissionDenied)
                ),
                Stop::Deadline => assert!(matches!(
                    error,
                    CommitError::Boundary(Failure::OpeningDeadline)
                )),
            }
        }
    }

    #[test]
    fn opening_interrupt_retry_rechecks_preparation_without_phantom_progress() {
        for prefix in [0, 3] {
            let mut actions = Vec::new();
            if prefix != 0 {
                actions.push(WriteAction::Accept(prefix));
            }
            actions.push(WriteAction::Interrupt);
            let mut writer = OpeningWriter::new(actions);
            let mut written = 0;
            let attempts = Cell::new(0);
            let error = write_opening(
                &mut writer,
                SUCCESS,
                &mut written,
                |_| {
                    attempts.set(attempts.get() + 1);
                    if attempts.get() == if prefix == 0 { 2 } else { 3 } {
                        Err(CommitError::Boundary(Failure::OpeningDeadline))
                    } else {
                        Ok(())
                    }
                },
                |_| panic!("final reset must not execute after deadline"),
            )
            .unwrap_err();
            assert!(matches!(
                error,
                CommitError::Boundary(Failure::OpeningDeadline)
            ));
            assert_eq!(written, prefix);
            assert_eq!(writer.bytes, &SUCCESS[..prefix]);
            assert_eq!(attempts.get(), if prefix == 0 { 2 } else { 3 });
        }
    }

    #[test]
    fn opening_complete_write_keeps_full_progress_when_final_reset_fails() {
        for fail_reset in [true, false] {
            let mut writer = OpeningWriter::new([
                WriteAction::Interrupt,
                WriteAction::Accept(3),
                WriteAction::Interrupt,
                WriteAction::Accept(SUCCESS.len()),
            ]);
            let mut written = 0;
            let attempts = Cell::new(0);
            let final_calls = Cell::new(0);
            let result = write_opening(
                &mut writer,
                SUCCESS,
                &mut written,
                |_| {
                    attempts.set(attempts.get() + 1);
                    Ok(())
                },
                |writer| {
                    assert_eq!(writer.bytes, SUCCESS);
                    final_calls.set(final_calls.get() + 1);
                    if fail_reset {
                        Err(CommitError::Io(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "synthetic timeout reset",
                        )))
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(written, SUCCESS.len());
            assert_eq!(writer.bytes, SUCCESS);
            assert_eq!(attempts.get(), 4);
            assert_eq!(final_calls.get(), 1);
            if fail_reset {
                assert!(
                    matches!(result, Err(CommitError::Io(ref e)) if e.kind() == io::ErrorKind::Unsupported)
                );
            } else {
                result.unwrap();
            }
        }
    }

    #[test]
    fn commit_failure_receipt_keeps_progress_cause_and_both_shutdown_failures() {
        let failure = CommitFailure {
            error: CommitError::Boundary(Failure::OpeningDeadline),
            success_bytes_written: 3,
            shutdown: ShutdownReport {
                client: Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "synthetic client shutdown",
                )),
                origin: Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "synthetic origin shutdown",
                )),
            },
        };
        assert_eq!(failure.success_bytes_written, 3);
        assert!(matches!(
            failure.error,
            CommitError::Boundary(Failure::OpeningDeadline)
        ));
        assert_eq!(
            failure.shutdown.client.unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            failure.shutdown.origin.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    struct FakeOrigin<'a> {
        addresses: Vec<SocketAddr>,
        peer: SocketAddr,
        calls: Vec<&'static str>,
        cancel_on_resolve: Option<&'a AtomicBool>,
        dialed: Vec<SocketAddr>,
        failures: std::collections::VecDeque<io::ErrorKind>,
        cancel_on_failure: Option<&'a AtomicBool>,
        now: Option<Instant>,
        expire_on_failure: Option<Instant>,
    }
    impl OriginIo for FakeOrigin<'_> {
        type Stream = SocketAddr;
        fn resolve(&mut self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
            self.calls.push("resolve");
            if let Some(cancel) = self.cancel_on_resolve {
                cancel.store(true, Ordering::Release);
            }
            Ok(self.addresses.clone())
        }
        fn connect(
            &mut self,
            literal: SocketAddr,
            remaining: std::time::Duration,
        ) -> io::Result<SocketAddr> {
            assert!(!remaining.is_zero());
            self.calls.push("connect");
            self.dialed.push(literal);
            if let Some(kind) = self.failures.pop_front() {
                if let Some(cancel) = self.cancel_on_failure {
                    cancel.store(true, Ordering::Release);
                }
                if let Some(expired) = self.expire_on_failure {
                    self.now = Some(expired);
                }
                return Err(io::Error::new(kind, format!("synthetic failed {literal}")));
            }
            Ok(literal)
        }
        fn peer(&mut self, _: &SocketAddr) -> io::Result<SocketAddr> {
            self.calls.push("peer");
            Ok(self.peer)
        }
        fn shutdown(&mut self, _: &SocketAddr) -> io::Result<()> {
            self.calls.push("shutdown");
            Ok(())
        }
        fn now(&self) -> Instant {
            self.now.unwrap_or_else(Instant::now)
        }
    }
    fn fixture_open(host: url::Host<String>, port: u16) -> PreparedOpen {
        PreparedOpen {
            host,
            port,
            policy: OpeningPolicy::Candidate(
                crate::wsl_direct_public_policy::Candidate::bundled().unwrap(),
            ),
        }
    }
    fn fake_origin(addresses: &[&str]) -> FakeOrigin<'static> {
        let addresses: Vec<SocketAddr> = addresses.iter().map(|a| a.parse().unwrap()).collect();
        FakeOrigin {
            peer: addresses[0],
            addresses,
            calls: Vec::new(),
            cancel_on_resolve: None,
            dialed: Vec::new(),
            failures: std::collections::VecDeque::new(),
            cancel_on_failure: None,
            now: None,
            expire_on_failure: None,
        }
    }
    #[test]
    fn allowed_non_gate_origin_resolves_once_and_preserves_prefetch_and_late_upload() {
        let header =
            b"CONNECT example.com:8443 HTTP/1.1\r\nProxy-Authorization: Basic synthetic\r\n\r\n";
        let payload: Vec<u8> = (0..=255).collect();
        let input = [header.as_slice(), payload.as_slice()].concat();
        let mut parser = RequestHead::new(source(), peer(), header.len()).unwrap();
        let step = parser.push(&input).unwrap();
        let authority = step.authority.unwrap();
        let mut io = fake_origin(&["8.8.8.8:8443", "10.0.0.1:8443"]);
        let cancelled = AtomicBool::new(false);
        let connected = connect_with(
            fixture_open(authority.0.host, authority.0.port),
            Instant::now() + std::time::Duration::from_secs(1),
            &cancelled,
            &mut io,
        )
        .ok()
        .expect("allowed simulated origin must open");
        assert_eq!(io.calls, ["resolve", "connect", "peer"]);
        assert_eq!(
            connected.stream,
            "8.8.8.8:8443".parse::<SocketAddr>().unwrap()
        );
        connected.target.check_peer(connected.stream).unwrap();
        let mut response = Vec::new();
        let mut written = 0;
        write_opening(&mut response, SUCCESS, &mut written, |_| Ok(()), |_| Ok(())).unwrap();
        assert_eq!(response, SUCCESS);
        assert_eq!(written, SUCCESS.len());
        // The actual directional helper completes download before accepting later upload.
        let mut download = Vec::new();
        transfer_direction(&mut Cursor::new(b"reply"), &mut download, b"", || Ok(())).unwrap();
        let mut origin = Vec::new();
        transfer_direction(
            &mut Cursor::new(b"late-upload"),
            &mut origin,
            &input[step.consumed..],
            || Ok(()),
        )
        .unwrap();
        assert_eq!(origin, [payload.as_slice(), b"late-upload"].concat());
        assert_eq!(download, b"reply");
    }
    #[test]
    fn denied_unknown_cancelled_and_mismatched_origins_never_commit() {
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let cancelled = AtomicBool::new(false);
        for denied in ["10.0.0.1:8443", "[2001:db8::1]:8443"] {
            let mut io = fake_origin(&[denied]);
            let failure = connect_with(
                fixture_open(url::Host::Domain("example.com".into()), 8443),
                deadline,
                &cancelled,
                &mut io,
            )
            .err()
            .unwrap();
            assert!(matches!(failure.error, Failure::DeniedTarget));
            assert_eq!(io.calls, ["resolve"]);
        }
        let mut io = fake_origin(&["8.8.8.8:8443"]);
        io.cancel_on_resolve = Some(&cancelled);
        let failure = connect_with(
            fixture_open(url::Host::Domain("example.com".into()), 8443),
            deadline,
            &cancelled,
            &mut io,
        )
        .err()
        .unwrap();
        assert!(matches!(failure.error, Failure::Cancelled));
        assert_eq!(io.calls, ["resolve"]);
        cancelled.store(false, Ordering::Release);
        let mut io = fake_origin(&["8.8.8.8:8443"]);
        io.peer = "8.8.4.4:8443".parse().unwrap();
        let failure = connect_with(
            fixture_open(url::Host::Ipv4("8.8.8.8".parse().unwrap()), 8443),
            deadline,
            &cancelled,
            &mut io,
        )
        .err()
        .unwrap();
        assert!(matches!(failure.error, Failure::TargetMismatch));
        assert_eq!(io.calls, ["connect", "peer", "shutdown"]);
        assert!(matches!(failure.origin_shutdown, Some(Ok(()))));
        assert!(matches!(
            prepare_open(&AdmittedAuthority(Authority {
                host: url::Host::Domain("example.com".into()),
                port: 8443,
                class: wsl_direct_authority::Class::NonGate
            })),
            Ok(PreparedOpen {
                policy: OpeningPolicy::Received(_),
                ..
            })
        ));
    }

    #[test]
    fn refused_first_permitted_literal_tries_next_from_the_same_resolution() {
        let mut io = fake_origin(&["8.8.8.8:8443", "10.0.0.1:8443", "1.1.1.1:8443"]);
        io.peer = "1.1.1.1:8443".parse().unwrap();
        io.failures.push_back(io::ErrorKind::ConnectionRefused);
        let prepared = fixture_open(url::Host::Domain("example.com".into()), 8443);
        let result = connect_with(
            prepared,
            Instant::now() + std::time::Duration::from_secs(1),
            &AtomicBool::new(false),
            &mut io,
        );
        assert!(
            result.is_ok(),
            "second policy-permitted literal must remain eligible"
        );
        assert_eq!(
            result.ok().unwrap().stream,
            "1.1.1.1:8443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            io.dialed,
            [
                "8.8.8.8:8443".parse::<SocketAddr>().unwrap(),
                "1.1.1.1:8443".parse().unwrap()
            ]
        );
        assert_eq!(io.calls, ["resolve", "connect", "connect", "peer"]);
    }

    #[test]
    fn exhausted_or_interrupted_address_attempts_preserve_causes_and_stop_before_more_dials() {
        let now = Instant::now();
        let deadline = now + std::time::Duration::from_secs(1);
        for stop in ["all_failed", "cancel", "deadline", "peer_mismatch"] {
            let cancelled = AtomicBool::new(false);
            let mut io = fake_origin(&["8.8.8.8:8443", "1.1.1.1:8443", "10.0.0.1:8443"]);
            io.now = Some(now);
            io.failures.push_back(io::ErrorKind::ConnectionRefused);
            match stop {
                "all_failed" => io.failures.push_back(io::ErrorKind::NetworkUnreachable),
                "cancel" => io.cancel_on_failure = Some(&cancelled),
                "deadline" => io.expire_on_failure = Some(deadline),
                "peer_mismatch" => io.peer = "8.8.4.4:8443".parse().unwrap(),
                _ => unreachable!(),
            }
            let failure = connect_with(
                fixture_open(url::Host::Domain("example.com".into()), 8443),
                deadline,
                &cancelled,
                &mut io,
            )
            .err()
            .unwrap();
            assert_eq!(failure.prior_connect_failures.len(), 1);
            let prior = &failure.prior_connect_failures[0];
            assert_eq!(prior.literal, "8.8.8.8:8443".parse::<SocketAddr>().unwrap());
            assert_eq!(prior.error.kind(), io::ErrorKind::ConnectionRefused);
            assert_eq!(prior.error.to_string(), "synthetic failed 8.8.8.8:8443");
            match stop {
                "all_failed" => {
                    assert!(matches!(failure.error, Failure::ConnectFailed));
                    let last = failure.io_error.unwrap();
                    assert_eq!(last.kind(), io::ErrorKind::NetworkUnreachable);
                    assert_eq!(last.to_string(), "synthetic failed 1.1.1.1:8443");
                    assert_eq!(io.calls, ["resolve", "connect", "connect"]);
                }
                "cancel" => {
                    assert!(matches!(failure.error, Failure::Cancelled));
                    assert_eq!(io.calls, ["resolve", "connect"]);
                }
                "deadline" => {
                    assert!(matches!(failure.error, Failure::OpeningDeadline));
                    assert_eq!(io.calls, ["resolve", "connect"]);
                }
                "peer_mismatch" => {
                    assert!(matches!(failure.error, Failure::TargetMismatch));
                    assert_eq!(
                        io.calls,
                        ["resolve", "connect", "connect", "peer", "shutdown"]
                    );
                    assert!(matches!(failure.origin_shutdown, Some(Ok(()))));
                }
                _ => unreachable!(),
            }
            assert!(!io
                .dialed
                .iter()
                .any(|literal| literal.ip() == "10.0.0.1".parse::<IpAddr>().unwrap()));
        }
        for expired in [false, true] {
            let mut io = fake_origin(&["10.0.0.1:8443", "127.0.0.1:8443"]);
            io.now = Some(if expired { deadline } else { now });
            let failure = connect_with(
                fixture_open(url::Host::Domain("example.com".into()), 8443),
                deadline,
                &AtomicBool::new(false),
                &mut io,
            )
            .err()
            .unwrap();
            assert!(io.dialed.is_empty());
            if expired {
                assert!(matches!(failure.error, Failure::OpeningDeadline));
                assert!(io.calls.is_empty());
            } else {
                assert!(matches!(failure.error, Failure::DeniedTarget));
                assert_eq!(io.calls, ["resolve"]);
            }
        }
    }
}
