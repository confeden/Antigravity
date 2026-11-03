//! One captured route profile and pre-commit route selection for a gate request.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// WSL supplies checks backed by its source-admitted PublicV1 permit. Native
/// supplies no direct-address policy; configured hops never use these checks.
pub(crate) struct DirectChecks<'a> {
    pub address: &'a dyn Fn(std::net::SocketAddr) -> bool,
    pub peer: &'a dyn Fn(std::net::SocketAddr, std::net::SocketAddr) -> bool,
}

pub(crate) enum OpenedRoute<'a> {
    Tcp {
        socket: TcpStream,
        kind: Option<routes::Kind>,
        direct_proof: Option<(std::net::SocketAddr, &'a DirectChecks<'a>)>,
    },
    Group(crate::group::OpenedGroup),
}

#[derive(Debug)]
pub(crate) enum OpenFailure {
    Cancelled,
    Deadline,
    Unavailable(Option<String>),
    DeniedTarget,
    UnsupportedPrivateRoutes,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrontendEof {
    NativeCompatible,
    WslSymmetricFin,
}

#[derive(Debug)]
pub(crate) enum CommitCause {
    Boundary(OpenFailure),
    InvalidDirectPeer,
    Io(io::Error),
}

pub(crate) struct CommitFailure {
    pub bytes_written: usize,
    pub error: CommitCause,
    pub client_shutdown: io::Result<()>,
    pub upstream_shutdown: io::Result<()>,
}

fn commit_failed(opened: &OpenedRoute<'_>, client: &TcpStream, bytes_written: usize, error: CommitCause) -> CommitFailure {
    let upstream_shutdown = match opened {
        OpenedRoute::Tcp { socket, .. } => socket.shutdown(std::net::Shutdown::Both),
        OpenedRoute::Group(group) => group.shutdown(),
    };
    CommitFailure { bytes_written, error, client_shutdown: client.shutdown(std::net::Shutdown::Both), upstream_shutdown }
}

/// Shared byte-counted response writer; only its caller decides failure mapping.
pub(crate) fn write_response<W: Write, E>(
    client: &mut W,
    mut bytes: &[u8],
    written: &mut usize,
    mut before_write: impl FnMut(&mut W) -> Result<(), E>,
    after_complete: impl FnOnce(&mut W) -> Result<(), E>,
    map_io: impl Fn(io::Error) -> E,
) -> Result<(), E> {
    while !bytes.is_empty() {
        before_write(client)?;
        match client.write(bytes) {
            Ok(0) => return Err(map_io(io::Error::new(io::ErrorKind::WriteZero, "CONNECT response write returned zero"))),
            Ok(n) => { *written += n; bytes = &bytes[n..]; }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_io(error)),
        }
    }
    after_complete(client)
}

/// Client and transport move together after the one response is committed.
enum CommittedTransport {
    Tcp(TcpStream),
    Group(crate::group::OpenedGroup),
}

pub(crate) enum WslTransfer {
    Tcp { client: TcpStream, upstream: TcpStream, prefetched: Vec<u8> },
    Group { client: TcpStream, group: crate::group::OpenedGroup, prefetched: Vec<u8> },
}

pub(crate) struct CommittedRoute {
    transport: CommittedTransport,
    client: TcpStream,
    prefetched: Vec<u8>,
    eof: FrontendEof,
}

impl CommittedRoute {
    pub(crate) fn into_wsl_transfer(self) -> Result<WslTransfer, io::Error> {
        if self.eof != FrontendEof::WslSymmetricFin {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "wrong frontend EOF contract"));
        }
        Ok(match self.transport {
            CommittedTransport::Tcp(upstream) => WslTransfer::Tcp {
                client: self.client, upstream, prefetched: self.prefetched,
            },
            CommittedTransport::Group(group) => WslTransfer::Group {
                client: self.client, group, prefetched: self.prefetched,
            },
        })
    }

    pub(crate) fn transfer_native(self) -> io::Result<()> {
        if self.eof != FrontendEof::NativeCompatible {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "wrong frontend EOF contract"));
        }
        match self.transport {
            CommittedTransport::Tcp(mut socket) => {
                socket.write_all(&self.prefetched)?;
                splice(self.client, socket);
                Ok(())
            }
            CommittedTransport::Group(opened) => {
                // The native CONNECT parser reads one byte at a time, so it has
                // no prefetched body. WSL needs the GroupTLS transfer owner.
                if !self.prefetched.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected native prefetch"));
                }
                opened.transfer(self.client);
                Ok(())
            }
        }
    }
}

/// Once writing begins, this consumes both sockets even on a partial response;
/// callers must not retry another route or write a replacement response.
pub(crate) fn commit<'a>(
    opened: OpenedRoute<'a>,
    mut client: TcpStream,
    prefetched: Vec<u8>,
    host: &str,
    eof: FrontendEof,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<CommittedRoute, CommitFailure> {
    let mut count = 0;
    if let OpenedRoute::Tcp { socket, direct_proof: Some((literal, checks)), .. } = &opened {
        let peer = socket.peer_addr().map_err(|error| commit_failed(&opened, &client, 0, CommitCause::Io(error)))?;
        if !(checks.address)(*literal) || !(checks.peer)(*literal, peer) {
            return Err(commit_failed(&opened, &client, 0, CommitCause::InvalidDirectPeer));
        }
    }
    let prepare = (|| -> io::Result<()> {
        client.set_nonblocking(false)?;
        client.set_read_timeout(None)?;
        match &opened {
            OpenedRoute::Tcp { socket, .. } => {
                socket.set_nonblocking(false)?;
                socket.set_read_timeout(None)?;
                socket.set_write_timeout(None)?;
            }
            OpenedRoute::Group(group) => group.prepare_transfer()?,
        }
        Ok(())
    })();
    if let Err(error) = prepare {
        return Err(commit_failed(&opened, &client, 0, CommitCause::Io(error)));
    }
    let result = write_response(&mut client, RESP_ESTABLISHED, &mut count,
        |client| {
            let left = remaining(deadline, cancelled).map_err(CommitCause::Boundary)?;
            client.set_write_timeout(Some(left)).map_err(CommitCause::Io)
        },
        |client| client.set_write_timeout(None).map_err(CommitCause::Io),
        CommitCause::Io,
    );
    if let Err(error) = result {
        return Err(commit_failed(&opened, &client, count, error));
    }
    let transport = match opened {
        OpenedRoute::Tcp { socket, kind, .. } => {
            if let Some(kind) = kind { routes::note_used(kind); }
            CommittedTransport::Tcp(socket)
        }
        OpenedRoute::Group(group) => {
            group.note_committed(host);
            CommittedTransport::Group(group)
        }
    };
    Ok(CommittedRoute { transport, client, prefetched, eof })
}

fn remaining(deadline: Instant, cancelled: &AtomicBool) -> Result<Duration, OpenFailure> {
    if cancelled.load(Ordering::Acquire) {
        return Err(OpenFailure::Cancelled);
    }
    deadline.checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(OpenFailure::Deadline)
}

fn walk_routes<T>(
    order: impl IntoIterator<Item = routes::Kind>,
    deadline: Instant,
    cancelled: &AtomicBool,
    mut attempt: impl FnMut(routes::Kind, Duration) -> Option<T>,
    mut failed: impl FnMut(routes::Kind),
) -> Result<Option<T>, OpenFailure> {
    for kind in order {
        let budget = remaining(deadline, cancelled)?;
        let opened = attempt(kind, budget);
        remaining(deadline, cancelled)?;
        if opened.is_some() { return Ok(opened); }
        failed(kind);
    }
    Ok(None)
}

enum DirectFailure {
    Denied,
    Open(String),
}

fn direct(
    target: &GateTarget443<'_>,
    deadline: Instant,
    cancelled: &AtomicBool,
    checks: Option<&DirectChecks<'_>>,
    vpn: bool,
) -> Result<TcpStream, DirectFailure> {
    let (mut addrs, pin) = if vpn {
        (crate::resolvers::genuine_a(target.host()).into_iter()
            .map(|a| std::net::SocketAddr::from((a, 443))).collect(), 0)
    } else {
        gate_direct_addrs(target.host(), 443).map_err(DirectFailure::Open)?
    };
    if let Some(checks) = checks {
        addrs.retain(|address| (checks.address)(*address));
        if addrs.is_empty() { return Err(DirectFailure::Denied); }
    }
    let budget = remaining(deadline, cancelled).map_err(|_| DirectFailure::Open("отменено или время вышло".to_string()))?
        .min(DIRECT_OPEN_BUDGET);
    connect_addrs_checked(addrs, budget, pin,
        |address| !cancelled.load(Ordering::Acquire)
            && Instant::now() < deadline
            && checks.is_none_or(|c| (c.address)(address)),
        |address, socket| checks.is_none_or(|c| {
            socket.peer_addr().is_ok_and(|peer| (c.peer)(address, peer))
        })).map_err(DirectFailure::Open)
}

/// Returns an owned transport, never a client response. A late successful leaf
/// is dropped after the deadline/cancellation check and cannot be committed.
pub(crate) fn open_selected_route<'a>(
    target: &GateTarget443<'_>,
    deadline: Instant,
    cancelled: &AtomicBool,
    checks: Option<&'a DirectChecks<'a>>,
) -> Result<OpenedRoute<'a>, OpenFailure> {
    if cfg!(any(relay, exits)) {
        return Err(OpenFailure::UnsupportedPrivateRoutes);
    }
    remaining(deadline, cancelled)?;
    let profile = DesiredRouteProfile::capture(target);
    let mut tried_direct = false;
    let mut denied_direct = false;
    let mut last_error = None;
    let opened = walk_routes(profile.order(target.host()), deadline, cancelled, |kind, budget| {
        match kind {
            routes::Kind::Own => profile.own.as_ref().and_then(|up| {
                match upstream::open_with_cancellation(up, target.host(), 443, budget.min(upstream::LIVE_OPEN_BUDGET), Some(cancelled)) {
                    Ok(socket) => Some(OpenedRoute::Tcp { socket, kind: Some(kind), direct_proof: None }),
                    Err(why) => {
                        crate::dns_forwarder::log_proxy(&format!("свой прокси: {}", why));
                        upstream::OWN.health.note(false);
                        last_error = Some(why);
                        None
                    }
                }
            }),
            routes::Kind::Group => profile.group.as_ref()
                .and_then(|key| crate::group::open_group(target, key, deadline, cancelled))
                .map(OpenedRoute::Group),
            routes::Kind::Direct => {
                tried_direct = true;
                match direct(target, deadline, cancelled, checks, false) {
                    Ok(socket) => tcp_direct(socket, Some(kind), checks),
                    Err(DirectFailure::Denied) => { denied_direct = true; None }
                    Err(DirectFailure::Open(why)) => {
                        crate::dns_forwarder::log_proxy(&format!("напрямую {}: {}", target.host(), why));
                        last_error = Some(why);
                        None
                    }
                }
            }
            routes::Kind::Vpn => match direct(target, deadline, cancelled, checks, true) {
                Ok(socket) => tcp_direct(socket, Some(kind), checks),
                Err(DirectFailure::Denied) => { denied_direct = true; None }
                Err(DirectFailure::Open(why)) => {
                    crate::dns_forwarder::log_proxy(&format!("через VPN {}: {}", target.host(), why));
                    last_error = Some(why);
                    None
                }
            },
            // The snapshot does not contain the feature-gated private openers.
            routes::Kind::Relay | routes::Kind::Exits => None,
        }
    }, routes::stumble)?;
    if let Some(opened) = opened { return Ok(opened); }
    if !tried_direct {
        remaining(deadline, cancelled)?;
        let opened = match direct(target, deadline, cancelled, checks, false) {
            Ok(socket) => Some(socket),
            Err(DirectFailure::Denied) => { denied_direct = true; None }
            Err(DirectFailure::Open(why)) => { last_error = Some(why); None }
        };
        remaining(deadline, cancelled)?;
        if let Some(socket) = opened {
            return tcp_direct(socket, Some(routes::Kind::Direct), checks).ok_or(OpenFailure::Unavailable(last_error));
        }
    }
    if denied_direct { Err(OpenFailure::DeniedTarget) } else { Err(OpenFailure::Unavailable(last_error)) }
}

pub(crate) fn tcp_direct<'a>(socket: TcpStream, kind: Option<routes::Kind>, checks: Option<&'a DirectChecks<'a>>) -> Option<OpenedRoute<'a>> {
    let direct_proof = match checks {
        Some(checks) => Some((socket.peer_addr().ok()?, checks)),
        None => None,
    };
    Some(OpenedRoute::Tcp { socket, kind, direct_proof })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, TcpListener};

    // Exercise the selection/walk shared by both fronts without reading the
    // user's settings or invoking DNS, a real hop, or a credential store.
    #[test]
    fn disabled_own_endpoint_never_enters_shared_route_walk() {
        let host = "cloudcode-pa.googleapis.com";
        let endpoint = upstream::parse("synthetic:credential@192.0.2.1:8080").unwrap();
        assert!(upstream::OWN.usable(), "the retained endpoint must be healthy for this guard");
        for eof in [FrontendEof::NativeCompatible, FrontendEof::WslSymmetricFin] {
            let profile = DesiredRouteProfile {
                settings: crate::settings::Settings { own_proxy_enabled: false,
                    own_proxy_at: 1, ..Default::default() },
                own: Some(endpoint.clone()), group: None,
            };
            let attempts = std::cell::RefCell::new(Vec::new());
            let credentials = std::cell::Cell::new(0);
            let cancelled = AtomicBool::new(false);
            let selected = walk_routes(profile.order(host), Instant::now() + Duration::from_secs(2),
                &cancelled, |kind, _| {
                    attempts.borrow_mut().push(kind);
                    if kind == routes::Kind::Own {
                        assert!(profile.own.as_ref().unwrap().auth.is_some());
                        credentials.set(credentials.get() + 1);
                    }
                    (kind == routes::Kind::Direct).then_some(eof)
                }, |_| {});
            assert!(!attempts.borrow().contains(&routes::Kind::Own), "disabled Own was attempted");
            assert_eq!(credentials.get(), 0, "disabled Own credentials were used");
            assert!(matches!(selected, Ok(Some(selected)) if selected == eof), "selected Direct fallback was lost");
            assert!(!profile.settings.own_proxy_enabled);
            assert_eq!(profile.own.as_ref(), Some(&endpoint));
        }
    }

    #[test]
    fn enabled_own_endpoint_remains_selected_by_shared_profile() {
        let profile = DesiredRouteProfile {
            settings: crate::settings::Settings { own_proxy_enabled: true,
                debug_route: "own".into(), ..Default::default() },
            own: Some(upstream::parse("synthetic:credential@192.0.2.1:8080").unwrap()), group: None,
        };
        assert_eq!(profile.order("cloudcode-pa.googleapis.com"), [routes::Kind::Own]);
        let missing = DesiredRouteProfile { own: None, ..profile };
        assert!(missing.order("cloudcode-pa.googleapis.com").is_empty());
    }

    #[test]
    fn route_walk_falls_back_only_before_open() {
        let attempted = std::cell::RefCell::new(Vec::new());
        let failed = std::cell::RefCell::new(Vec::new());
        let cancelled = AtomicBool::new(false);
        let result = walk_routes([routes::Kind::Own, routes::Kind::Group, routes::Kind::Direct],
            Instant::now() + Duration::from_secs(2), &cancelled,
            |kind, _| { attempted.borrow_mut().push(kind); (kind == routes::Kind::Group).then_some(7) },
            |kind| failed.borrow_mut().push(kind));
        assert!(matches!(result, Ok(Some(7))));
        assert_eq!(*attempted.borrow(), [routes::Kind::Own, routes::Kind::Group]);
        assert_eq!(*failed.borrow(), [routes::Kind::Own]);
    }

    #[test]
    fn route_walk_discards_opened_transport_after_cancellation() {
        use std::sync::atomic::AtomicUsize;
        struct Owned<'a>(&'a AtomicUsize);
        impl Drop for Owned<'_> { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
        let cancelled = AtomicBool::new(false);
        let drops = AtomicUsize::new(0);
        let result = walk_routes([routes::Kind::Direct], Instant::now() + Duration::from_secs(2), &cancelled,
            |_, _| { cancelled.store(true, Ordering::Release); Some(Owned(&drops)) }, |_| panic!("late open cannot fall back"));
        assert!(matches!(result, Err(OpenFailure::Cancelled)));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_commit_sends_one_response_and_delivers_prefetch() {
        fn pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            let first = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (second, _) = listener.accept().unwrap();
            first.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            second.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            (first, second)
        }
        let (mut peer, client) = pair();
        let (mut origin, upstream) = pair();
        let _gate = routes::begin_gate_connection(&client, "cloudcode-pa.googleapis.com");
        let opened = OpenedRoute::Tcp {
            socket: upstream,
            kind: Some(routes::Kind::Direct),
            direct_proof: None,
        };
        let cancelled = AtomicBool::new(false);
        let committed = commit(opened, client, b"prefix".to_vec(), "cloudcode-pa.googleapis.com", FrontendEof::NativeCompatible,
            Instant::now() + Duration::from_secs(3), &cancelled)
            .unwrap_or_else(|e| panic!("commit failed after {} bytes: {:?}", e.bytes_written, e.error));
        let mut response = vec![0; RESP_ESTABLISHED.len()];
        peer.read_exact(&mut response).unwrap();
        assert_eq!(response, RESP_ESTABLISHED);
        let worker = thread::spawn(move || committed.transfer_native());
        let mut delivered = [0; 6];
        let read = origin.read_exact(&mut delivered);
        let _ = peer.shutdown(Shutdown::Write);
        let _ = origin.shutdown(Shutdown::Write);
        let finished = worker.join();
        read.unwrap();
        assert_eq!(&delivered, b"prefix");
        finished.unwrap().unwrap();
        let mut extra = [0; 1];
        assert_eq!(peer.read(&mut extra).unwrap(), 0);
    }
}
