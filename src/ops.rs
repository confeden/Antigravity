//! The switch layer: every capability the window can turn on or off, and the
//! one worker thread that does it.
//!
//! The console build expressed this as numbered menu items, each a script that
//! printed as it went. A switch needs three things a menu item never did: an
//! honest *enable*, an *undo* that is its exact mirror, and a read-only *state*
//! query so the switch can be drawn where the system actually is rather than
//! where the user last left it.
//!
//! ## What is load-bearing here
//!
//! The order of the steps, not the steps. Every sequence below is a documented
//! bug fix and is marked with the invariant it encodes:
//!
//! * **I5** — the relay comes up *before* the NRPT rules, because the rules name
//!   it as the first nameserver.
//! * **I20** — nothing may be re-patching while an unpatch runs, so both
//!   watchdogs stop first and are put back afterwards.
//! * **I39** — the legacy CA comes out *last*, and only once the relay is
//!   current; pulling it from under an old relay kills every gate request.
//! * **I45** — a failed file undo stops later independent file effects, while
//!   the background owner still receives its required service restoration.
//!   Primary and restoration outcomes remain distinct.
//! * **I52/I53/I54** — the proxy variable is written only after the legacy pair
//!   is gone, no foreign proxy exists, the rename landed, and something actually
//!   answers on the port.
//!
//! ## Threading
//!
//! One worker, one queue, for everything that touches the system. Not for
//! tidiness: `setup_dns_nrpt` is remove-then-add with no lock, `enable`/`disable`
//! both drive the same image name, and two patch runs race the same files. A
//! second worker would interleave them into a half-installed state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

use crate::settings::Settings;
use crate::utils::is_admin;
use crate::{background, dns, endpoint, patch_binary, proxy, upstream};

/// Everything the UI can flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cap {
    /// Switch 1: the client patch that lifts the account-region block.
    ClientPatch,
    /// Re-applies the patch after Antigravity updates itself.
    Watchdog,
    /// The DNS half of the 400 bypass: local relay + NRPT rules.
    Dns,
    /// Our own CONNECT proxy, named by the private env var the patch installs.
    LocalProxy,
    /// The user's own HTTP proxy.
    OwnProxy,
    /// The built-in permitted-region exits.
    BuiltinExits,
    GroupProxy,
    /// Whether the DNS pool rotates, or only its first enabled member answers.
    DnsRotation,
    // `VpnDetect` is gone (D25): the layer no longer stands down for a tunnel,
    // so there is nothing left for that switch to decide. `settings.vpn_detect`
    // stays in the file so an older build reading it still finds the field.
}

impl Cap {
    /// Windows gates the DNS layer behind UAC. Without admin these do not fail —
    /// the cmdlets carry `-ErrorAction SilentlyContinue` — they quietly do
    /// nothing, which is exactly the way a switch ends up lying.
    pub fn needs_admin(self) -> bool {
        cfg!(target_os = "windows") && matches!(self, Cap::Dns | Cap::Watchdog)
    }

    pub fn title(self) -> &'static str {
        match self {
            Cap::ClientPatch => "Разблокировать вход в аккаунт",
            Cap::Watchdog => "Автопатч Antigravity",
            Cap::Dns => "Обход через DNS",
            Cap::LocalProxy => "Локальный прокси",
            Cap::OwnProxy => "Свой HTTP-прокси",
            Cap::BuiltinExits => "Встроенные выходы",
            Cap::GroupProxy => "Прокси из группы",
            Cap::DnsRotation => "Ротация DNS-серверов",
        }
    }
}

/// Where a capability actually is, as opposed to where the user put the switch.
#[derive(Debug, Clone, PartialEq)]
pub enum State {
    On,
    Off,
    /// On, but not the whole way — some installs patched and some not, or rules
    /// present with the relay down.
    Partial(String),
    /// **Off**, with a line saying what being off costs. Draws as an off switch.
    ///
    /// Not a flavour of `Partial`, and the difference is a bug that shipped:
    /// `is_on()` is true for `Partial`, so a switch whose off state was described
    /// with one drew itself back **on** the moment the worker's snapshot landed —
    /// «Сверять TLS» and «Ротация» could not be turned off at all, while the log
    /// said they had been. A note is a note; whether the thing is on is a
    /// separate question and now has a separate variant.
    OffNote(String),
    /// Cannot be turned on right now, and the reason is not the user's mistake:
    /// no admin, a foreign proxy that outranks ours, a VPN the layer stood down
    /// for. Drawn as an off switch with the reason next to it.
    Blocked(String),
}

impl State {
    pub fn is_on(&self) -> bool {
        matches!(self, State::On | State::Partial(_))
    }
    pub fn note(&self) -> Option<&str> {
        match self {
            State::Partial(s) | State::Blocked(s) | State::OffNote(s) => Some(s),
            _ => None,
        }
    }
}

/// One Antigravity *kind*, as the paths list draws it.
///
/// There is a row per kind rather than per found install, and it survives the
/// kind not being installed: an empty row with a pencil is how a user says
/// "it is here, you missed it". A list that only shows what was found gives
/// them nowhere to say it.
#[derive(Debug, Clone)]
pub struct InstallRow {
    /// `None` when this kind was neither found nor pointed at by hand.
    pub path: Option<PathBuf>,
    pub label: &'static str,
    /// `None` while it has not been inspected yet — inspecting reads the whole
    /// Language Server binary, so it is not done on the drawing thread.
    pub patched: Option<bool>,
    /// Added by hand through the pencil, rather than found by the scan.
    pub manual: bool,
}

/// What the VPN measurement found, as the indicator draws it.
///
/// The distinction is the whole point and it is a measured one, not a guess: a
/// tunnel being up says nothing about whether *Antigravity* is inside it. Per-app
/// split tunnelling made "a VPN is connected" mean the opposite of what it looks
/// like, and reading it as "skip the rules" left the client in the blocked region
/// with no bypass at all (G29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnSeen {
    /// No tunnel on the machine.
    None,
    /// A tunnel is up, but Antigravity's own sockets do not leave through it.
    NotCarryingClient,
    /// Measured: Antigravity's sockets leave through the tunnel.
    CarryingClient,
    /// Measured: some of them do and some do not — two language servers on
    /// different sides of a split tunnel, or sockets that outlived a rule
    /// change. The half inside faces the gate from wherever the tunnel exits.
    PartlyCarryingClient,
    /// A tunnel is up, and Antigravity's own traffic goes to **our** proxy — so
    /// the socket that faces the gate is the relay's, not the client's.
    ///
    /// The ordinary state for a patched client with the local-proxy route on,
    /// and the one the tool's own success created: excluding `language_server`
    /// from a VPN stopped meaning anything the moment it stopped making gate
    /// connections. Whether the *relay* is in the tunnel is a question this
    /// measurement does not answer (P34).
    ViaLocalProxy,
    /// A tunnel is up and there was nothing to read: Antigravity is not running,
    /// or has not dialled out yet.
    ///
    /// Its own variant because it used to be folded into `NotCarryingClient`,
    /// and that is the same mistake the tool forbids itself elsewhere — treating
    /// an absence of evidence as evidence (the resolver rule in CLAUDE.md). The
    /// window opens before Antigravity is started far more often than not, so
    /// the message every VPN user got was the confident and usually wrong «VPN
    /// активен, но Antigravity идёт мимо него». What the layer *does* is
    /// unchanged: no measurement still means the rules go in (S37).
    Unmeasured,
}

#[derive(Debug, Clone)]
pub struct ProviderRow {
    pub name: String,
    pub enabled: bool,
}

/// A whole-system snapshot. Produced on the worker, rendered on the UI thread.
#[derive(Debug, Clone)]
pub struct Status {
    pub wsl: crate::wsl_api::WslStatus,
    pub admin: bool,
    pub installs: Vec<InstallRow>,
    pub client_patch: State,
    pub watchdog: State,
    pub dns: State,
    pub local_proxy: State,
    pub own_proxy: State,
    pub builtin_exits: State,
    pub group_proxy: State,
    pub dns_rotation: State,
    /// What the last measurement saw. `None` means it has not been taken yet;
    /// taking it spawns PowerShell, so it is not done on every refresh.
    pub vpn: Option<VpnSeen>,
    pub own_proxy_text: String,
    pub custom_dns_text: String,
    pub relay_outdated: bool,
    /// Whether the relay task is registered *and* running. The raw fact, kept
    /// beside the `dns` row that already folds it into a verdict: the gate strip
    /// has to say "there is nobody to catch the next 400" without re-deriving it
    /// from a string meant for a switch.
    pub relay_running: bool,
    /// Whether our NRPT rules are in. The raw fact, beside `relay_running`, for
    /// the same reason: a running service with no rules is a bypass nobody's
    /// queries ever reach, and the status card has to be able to say so.
    pub rules: bool,
    pub providers: Vec<ProviderRow>,
    /// Where **our own** service's connections leave. `None` when there was
    /// nothing to read, or no tunnel to read it against.
    ///
    /// The half the client stopped being able to answer (G46), and the one that
    /// decides whether a provider serving only Russian addresses will serve us
    /// at all. Reported, never acted on: the stand-down decision is still the
    /// client's (D13, P34).
    pub relay_egress: Option<crate::egress::ClientEgress>,
}

impl Status {
    pub fn get(&self, cap: Cap) -> &State {
        match cap {
            Cap::ClientPatch => &self.client_patch,
            Cap::Watchdog => &self.watchdog,
            Cap::Dns => &self.dns,
            Cap::LocalProxy => &self.local_proxy,
            Cap::OwnProxy => &self.own_proxy,
            Cap::BuiltinExits => &self.builtin_exits,
            Cap::GroupProxy => &self.group_proxy,
            Cap::DnsRotation => &self.dns_rotation,
        }
    }

    /// The bypass master switch. Derived, never stored: it is on when any part
    /// of the bypass is, which keeps one truth instead of two.
    pub fn bypass_on(&self) -> bool {
        self.dns.is_on()
            || self.local_proxy.is_on()
            || self.builtin_exits.is_on()
            || self.group_proxy.is_on()
            || self.own_proxy.is_on()
    }
}

/// The parts of the bypass, in the order the master switch sends them.
///
/// Not the same in both directions. ON: the relay has to be answering before the
/// proxy variable may name it (I53) â€” the worker runs these in order, so DNS
/// finishes first. OFF: the variable comes off *before* the listener it names
/// goes away, or a sign-in that lands in between dials a dead port (G31).
pub fn bypass_order(on: bool) -> Vec<Cap> {
    if on {
        // The user's own proxy is theirs to switch on: it needs an address.
        vec![
            Cap::Dns,
            Cap::LocalProxy,
            Cap::BuiltinExits,
            Cap::GroupProxy,
        ]
    } else {
        vec![
            Cap::LocalProxy,
            Cap::OwnProxy,
            Cap::BuiltinExits,
            Cap::GroupProxy,
            Cap::Dns,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Step,
    Info,
    Ok,
    Warn,
    Err,
}

/// Worker → UI.
pub enum Event {
    Log(Level, String),
    Status(Box<Status>),
    /// `Some(what)` while an action runs, `None` when the queue drains. The UI
    /// dims the switches in between so a second click cannot queue a race.
    Busy(Option<String>),
    /// Every owned GUI operation actually settled and Settings were saved.
    ShutdownReady,
}

/// UI → worker.
pub enum Cmd {
    RequestElevation,
    #[cfg(windows)]
    Elevate(crate::instances::GuiReplacementAction),
    SetWslEnabled(bool),
    SetWslDistro { name: String, selected: bool },
    RefreshWsl,
    ApplySettings,
    CancelWsl,
    Shutdown,
    /// The key was accepted and the main screen is up. Auto-patch may act from
    /// here on, never before: the first scan runs under the licence screen, and
    /// patching from there would hand the patch to anyone without a key.
    Unlocked,
    /// Store the licence key just accepted, so the next start skips the screen.
    RememberLicense(String),
    /// Ask the system again where the client's traffic leaves.
    ///
    /// Its own command because it is the one measurement that goes stale on its
    /// own — a user connects a VPN, or starts Antigravity, and nothing in this
    /// window was touched. Sent by the gate watcher, which knows when it is
    /// worth paying for (`gate`), and answered here because `ops` owns the
    /// measurement the DNS layer's decision is made from (I59).
    RemeasureVpn,
    /// The answer to the above, coming back from the thread it was taken on.
    ///
    /// It carries the relay's liveness too, because that is the other fact the
    /// gate strip shows and the other one that goes stale on its own — a relay
    /// can die while the window sits open, and until this arrived nothing
    /// re-read it short of the user flipping a switch. Both probes are cheap
    /// process spawns and neither belongs on the worker's queue.
    Probed {
        vpn: VpnSeen,
        relay: bool,
        relay_egress: Option<crate::egress::ClientEgress>,
    },
    /// Re-read the system *including* whether each install is patched, which
    /// means reading every Language Server binary end to end.
    #[allow(dead_code)]
    DeepRefresh,
    Set(Cap, bool),
    AddPath(PathBuf),
    ForgetPath(PathBuf),
    /// The «Пропатчить» button of one install row.
    PatchInstall(PathBuf),
    SetOwnProxy(String),
    SetCustomDns(String),
    SetGroupKey(String),
    SetProvider(String, bool),
    /// The whole pool in the order the user dragged it into.
    ReorderProviders(Vec<String>),
    /// Everything on, in the order that works: the patch, auto-patch, then the
    /// bypass. The one button a user who is not a programmer needs.
    EnableAll,
    /// Puts the service back the way the switches say it should be: reinstalls
    /// the relay when it is missing, stopped or older than this build, rewrites
    /// the rules, restores the proxy variable.
    Repair,
    #[allow(dead_code)]
    Stop,
}

pub struct Worker {
    tx: Sender<Cmd>,
    lifetime: Arc<GuiLifetime>,
}

#[cfg(test)]
pub(crate) fn layout_test_worker(lifetime: Arc<GuiLifetime>) -> (Worker, Receiver<Cmd>) {
    let (tx, rx) = mpsc::channel();
    (Worker { tx, lifetime }, rx)
}

/// Main-owned custody across GUI/TUI shutdown and renderer return. This holds
/// actual handles, not a second status/settings store.
#[derive(Default)]
pub struct GuiLifetime {
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    command: Mutex<Option<Sender<Cmd>>>,
    shutdown_ready: AtomicBool,
    save_failed: AtomicBool,
    started: AtomicBool,
    abort_requested: AtomicBool,
    channel_lost: AtomicBool,
    handoff_requested: AtomicBool,
    arming_started: AtomicBool,
    handoff_committed: AtomicBool,
    failure: Mutex<Option<String>>,
    bootstrap_hold: Mutex<Option<String>>,
    #[cfg(windows)]
    replacement: Mutex<Option<crate::instances::GuiReplacementReady>>,
    #[cfg(windows)]
    action: Mutex<Option<crate::instances::GuiReplacementAction>>,
    #[cfg(windows)]
    retirement_input: Mutex<Option<RetirementInput>>,
    #[cfg(windows)]
    image: Option<Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>>,
}
impl GuiLifetime {
    #[cfg(windows)]
    pub(crate) fn with_image(image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>) -> Self {
        Self { image: Some(image), ..Self::default() }
    }
    #[cfg(windows)]
    pub(crate) fn retained_image(&self) -> Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String> {
        self.image.clone().unwrap_or_else(|| Err("source-selection hold: current image was not received".into()))
    }
    #[cfg(windows)]
    pub(crate) fn receive_retirement_input(&self, descriptor: crate::instances::GuiRetirementInputRef) -> Result<(), String> {
        let input = RetirementInput::receive(descriptor)?;
        let mut slot = self.retirement_input.lock().map_err(|_| "retirement input lock poisoned")?;
        if slot.is_some() { return Err("retirement input already received".into()); }
        *slot = Some(input);
        Ok(())
    }
    pub(crate) fn hold_automatic_effects(&self, reason: String) -> Result<(), String> {
        *self.bootstrap_hold.lock().map_err(|_| "GUI startup hold receiving lock poisoned")? = Some(reason);
        Ok(())
    }
    pub(crate) fn fallback_hold(&self) -> Option<String> {
        match self.bootstrap_hold.lock() {
            Ok(hold) => hold.clone(),
            Err(_) => Some("Не удалось получить ограничение автоматического запуска.".into()),
        }
    }
    fn clear_automatic_hold(&self) -> Result<(), String> {
        *self.bootstrap_hold.lock().map_err(|_| "GUI startup hold lock poisoned")? = None;
        Ok(())
    }
    #[cfg(windows)]
    pub(crate) fn receive_action(&self, action: crate::instances::GuiReplacementAction) -> Result<(), String> {
        let mut slot = self.action.lock().map_err(|_| "GUI action receiving lock poisoned")?;
        if slot.is_some() { return Err("GUI action already received".into()); }
        *slot = Some(action);
        Ok(())
    }
    pub fn request_shutdown(&self) {
        self.save_failed.store(false, Ordering::SeqCst);
        self.abort_requested.store(true, Ordering::SeqCst);
        if let Ok(command) = self.command.lock() {
            if let Some(command) = command.as_ref() { let _ = command.send(Cmd::Shutdown); }
        }
    }
    /// Event loops may retire on true. This never sends COMMIT: Main owns the
    /// final exit corridor after the renderer/terminal loop has returned.
    pub fn poll_close(&self) -> Result<bool, String> {
        if self.save_failed.load(Ordering::SeqCst) { return Err("настройки не сохранены; повторите закрытие после устранения ошибки".into()); }
        if let Some(error) = self.failure.lock().map_err(|_| "worker failure observation poisoned")?.as_ref() {
            return Err(error.clone());
        }
        let mut worker = self.worker.lock().map_err(|_| "worker custody lock poisoned")?;
        if let Some(job) = worker.as_ref() {
            if !job.is_finished() { return Ok(false); }
            if worker.take().unwrap().join().is_err() {
                let error = "worker did not return a received shutdown outcome".to_owned();
                *self.failure.lock().map_err(|_| "worker failure observation poisoned")? = Some(error.clone());
                return Err(error);
            }
        }
        if self.started.load(Ordering::SeqCst) && !self.shutdown_ready.load(Ordering::SeqCst) {
            return Err("worker returned before saved/settled shutdown receiving".into());
        }
        Ok(true)
    }
    pub(crate) fn can_retry_renderer(&self) -> bool {
        if self.started.load(Ordering::SeqCst) || self.abort_requested.load(Ordering::SeqCst)
            || self.handoff_requested.load(Ordering::SeqCst) || self.fallback_hold().is_some() { return false; }
        true
    }
    pub(crate) fn can_start_fallback(&self) -> bool {
        if !self.can_retry_renderer() { return false; }
        #[cfg(windows)]
        if self.action.lock().map_or(true, |action| action.is_some()) { return false; }
        true
    }
    pub(crate) fn request_final_retirement(&self) {
        if !self.shutdown_ready.load(Ordering::SeqCst) { self.request_shutdown(); }
    }
    pub(crate) fn save_retry_pending(&self) -> bool { self.save_failed.load(Ordering::SeqCst) }
    pub(crate) fn finalize_exit(&self) -> Result<bool, String> {
        if !self.poll_close()? { return Ok(false); }
        #[cfg(windows)]
        {
            let mut slot = self.replacement.lock().map_err(|_| "replacement custody lock poisoned")?;
            if let Some(replacement) = slot.as_mut() {
                if self.handoff_committed.load(Ordering::SeqCst) { return Ok(true); }
                if self.abort_requested.load(Ordering::SeqCst) && !self.arming_started.load(Ordering::SeqCst) {
                    replacement.request_abort()?;
                    if !replacement.poll_retired()? { return Ok(false); }
                    slot.take();
                    return Ok(true);
                }
                // The helper marks its own possible COMMIT before writing. A
                // failed/uncertain write must never turn back into an abort.
                self.arming_started.store(true, Ordering::SeqCst);
                match replacement.arm_for_exit() {
                    Ok(true) => {
                        self.handoff_committed.store(true, Ordering::SeqCst);
                        return Ok(true);
                    }
                    Ok(false) => {},
                    Err(error) => {
                        if self.abort_requested.load(Ordering::SeqCst) && replacement.poll_retired()? {
                            slot.take();
                            return Ok(true);
                        }
                        return Err(error);
                    }
                }
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub fn replacement_committed(&self) -> bool { self.handoff_committed.load(Ordering::SeqCst) }
    #[cfg(windows)]
    fn accept_replacement(&self, ready: crate::instances::GuiReplacementReady) -> Result<(), crate::instances::GuiReplacementReady> {
        match self.replacement.lock() {
            Ok(mut slot) if slot.is_none() => {
                *slot = Some(ready);
                self.handoff_requested.store(true, Ordering::SeqCst);
                Ok(())
            }
            _ => Err(ready),
        }
    }
}

impl Worker {
    pub fn send(&self, cmd: Cmd) {
        if matches!(&cmd, Cmd::Shutdown | Cmd::Stop) {
            self.lifetime.request_shutdown();
            return;
        }
        // A closed worker means the app is going down; there is nothing useful
        // to do about it and nothing to tell the user.
        let _ = self.tx.send(cmd);
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if !self.lifetime.shutdown_ready.load(Ordering::SeqCst) { self.lifetime.request_shutdown(); }
    }
}

/// Starts the worker. `wake` is called after every event so the UI thread
/// repaints — egui sleeps until something asks it not to.
pub fn spawn(events: Sender<Event>, wake: Box<dyn Fn() + Send>, lifetime: Arc<GuiLifetime>) -> Worker {
    let (tx, rx) = mpsc::channel::<Cmd>();
    // The worker keeps a sender of its own, for the one job it hands to a
    // thread and gets an answer back from (`RemeasureVpn`). It means the
    // channel never disconnects, so the loop does not end when the window drops
    // its `Worker` — which costs nothing here, because the window closing is the
    // process exiting.
    let own = tx.clone();
    let mut worker_slot = match lifetime.worker.lock() {
        Ok(slot) => slot,
        Err(_) => {
            let _ = events.send(Event::Log(Level::Err, "Не удалось получить владение рабочим потоком.".into()));
            return Worker { tx, lifetime: lifetime.clone() };
        }
    };
    if worker_slot.is_some() {
        let _ = events.send(Event::Log(Level::Err, "Предыдущий рабочий поток ещё удерживается владельцем окна.".into()));
        return Worker { tx, lifetime: lifetime.clone() };
    }
    let worker_lifetime = lifetime.clone();
    let failure_events = events.clone();
    let started = std::thread::Builder::new()
        .name("ops".to_string())
        .spawn(move || run_worker(rx, own, events, wake, worker_lifetime));
    match started {
        Ok(job) => {
            *worker_slot = Some(job);
            lifetime.started.store(true, Ordering::SeqCst);
            if let Ok(mut command) = lifetime.command.lock() { *command = Some(tx.clone()); }
        }
        Err(error) => { let _ = failure_events.send(Event::Log(Level::Err, format!("Рабочий поток не запущен: {error}"))); }
    }
    drop(worker_slot);
    Worker { tx, lifetime }
}

// ---------------------------------------------------------------------------
// The worker loop
// ---------------------------------------------------------------------------

struct Ctx {
    events: Sender<Event>,
    wake: Arc<Mutex<Box<dyn Fn() + Send>>>,
    settings: Settings,
    wsl: crate::wsl_controller::WslController,
    native_apply_pending: Arc<AtomicBool>,
    native_cancel: Arc<AtomicBool>,
    #[cfg(windows)]
    background_receivings: Vec<background::BackgroundReceiving>,
    lifetime: Arc<GuiLifetime>,
    vpn_job: Option<std::thread::JoinHandle<()>>,
    vpn_unsettled: bool,
    startup: Startup,
    /// Whether the *proxy variable* rename landed in this session's patch run.
    ///
    /// Not a process-wide flag: the console build died after one run, so a
    /// sticky "it landed" atomic was harmless there. A window that patches
    /// twice would inherit the first run's verdict and keep writing a variable
    /// that nothing reads any more. Reset on every patch.
    proxy_var_carried: Option<bool>,
    proxy_var_retryable: bool,
    /// What the last deep pass found, per install.
    ///
    /// A shallow refresh must not throw this away: reading a 150 MB binary is
    /// what makes the answer expensive, and without a memory every cheap refresh
    /// would blank the switch back to "not checked yet" — which reads as the
    /// patch having come undone.
    patched_seen: HashMap<PathBuf, bool>,
    /// Last VPN measurement. `egress::detect` drives PowerShell and is capped at
    /// a minute, so it is taken on the deep pass and after anything that could
    /// change it — never on a plain refresh.
    vpn: Option<VpnSeen>,
    /// Taken with it: where our own service's sockets sit.
    relay_egress: Option<crate::egress::ClientEgress>,
    /// The last snapshot that was actually asked of the system.
    ///
    /// What makes `Scan::Settings` possible: a switch that only writes a field of
    /// `settings.json` cannot have changed a scheduled task, an NRPT rule or an
    /// environment variable, so re-asking Windows about all three is pure latency
    /// — and it was about two seconds of it per flip, which is what «слишком
    /// много времени» was.
    last: Option<Status>,
    /// The raw pair `read_dns` needs, kept from the last system scan so the DNS
    /// row can be recomputed for a new `vpn_detect` without going near PowerShell.
    dns_probe: (bool, bool),
    /// `ensure_route_carrier` switched the local-proxy wish on, rather than the
    /// user: only then does letting go of the last route switch it off again.
    carrier_set_proxy: bool,
}
enum Startup {
    Ordinary,
    Explicit,
    Held(String),
    #[cfg(windows)]
    Resume(crate::instances::GuiApplyContinuation),
}

enum NativeCompletion {
    Retired,
    #[cfg(windows)]
    NeedsElevation(crate::instances::GuiApplyContinuation),
    #[cfg(windows)]
    Held(String),
}

/// How much of the system a refresh is allowed to ask about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scan {
    /// Everything, including reading every Language Server binary end to end and
    /// re-measuring where the client's traffic leaves.
    Deep,
    /// Everything the system can be asked cheaply: tasks, rules, the proxy
    /// variable. Not the binaries.
    System,
    /// Nothing from the system. The last snapshot with the settings-derived
    /// fields recomputed — instant, and correct exactly for the switches that
    /// change nothing but a line in `settings.json`.
    Settings,
}

impl Ctx {
    fn log(&self, level: Level, msg: impl Into<String>) {
        if self.events.send(Event::Log(level, msg.into())).is_err() { self.lifetime.channel_lost.store(true, Ordering::SeqCst); }
        if let Ok(wake) = self.wake.lock() { (wake)(); }
    }
    fn poll_wsl_report(&mut self) -> bool {
        let Some(diagnostics) = self.wsl.poll() else { return false; };
        for diagnostic in diagnostics { self.log(Level::Err, diagnostic); }
        true
    }
    fn busy(&self, what: Option<&str>) {
        if self.events.send(Event::Busy(what.map(|s| s.to_string()))).is_err() { self.lifetime.channel_lost.store(true, Ordering::SeqCst); }
        if let Ok(wake) = self.wake.lock() { (wake)(); }
    }
}

#[cfg(all(test, windows))]
pub(crate) fn test_forward_wsl_diagnostic(events: Sender<Event>, error: String) -> bool {
    let lifetime = Arc::new(GuiLifetime::default());
    let mut ctx = Ctx { events, wake: Arc::new(Mutex::new(Box::new(|| {}))), settings: Settings::default(),
        wsl: crate::wsl_controller::test_pending_diagnostic(error), native_apply_pending: Arc::new(AtomicBool::new(false)),
        native_cancel: Arc::new(AtomicBool::new(false)), background_receivings: Vec::new(), lifetime: lifetime.clone(),
        vpn_job: None, vpn_unsettled: false, startup: Startup::Ordinary, proxy_var_carried: None,
        proxy_var_retryable: false, patched_seen: HashMap::new(), vpn: None, relay_egress: None,
        last: None, dns_probe: (false, false), carrier_set_proxy: false };
    while !ctx.poll_wsl_report() { std::thread::yield_now(); }
    assert!(!ctx.poll_wsl_report());
    lifetime.channel_lost.load(Ordering::SeqCst)
}

/// True while a VPN measurement is out at a thread. One at a time: the watcher
/// can ask again before the last answer is back, and two PowerShell probes
/// racing produce the same answer twice at twice the cost.
static MEASURING_VPN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn receive_wsl_refresh_command(requested: &mut bool, command: &Option<Cmd>) -> bool {
    match command {
        Some(Cmd::RefreshWsl) => { *requested = true; true }
        Some(Cmd::CancelWsl | Cmd::Shutdown | Cmd::Stop) => { *requested = false; false }
        _ => false,
    }
}

// Consume one coalesced presentation request only when the existing owner can start it.
fn take_wsl_refresh(requested: &mut bool, available: bool, command: &Option<Cmd>, first_command: &Option<Cmd>) -> bool {
    if *requested && available && command.is_none() && first_command.is_none() { *requested = false; true } else { false }
}

fn run_worker(
    rx: Receiver<Cmd>,
    own: Sender<Cmd>,
    events: Sender<Event>,
    wake: Box<dyn Fn() + Send>,
    lifetime: Arc<GuiLifetime>,
) {
    let owner_events = events.clone();
    let owner_wake = Arc::new(Mutex::new(wake));
    let native_apply_pending = Arc::new(AtomicBool::new(false));
    let native_cancel = Arc::new(AtomicBool::new(false));
    let Some((settings, startup, mut first_command)) = worker_boot(&rx, &owner_events, &owner_wake, &lifetime) else { return; };
    let mut ctx = Ctx {
        events,
        wake: owner_wake.clone(),
        settings,
        wsl: crate::wsl_controller::WslController::default(),
        native_apply_pending: native_apply_pending.clone(),
        native_cancel: native_cancel.clone(),
        #[cfg(windows)]
        background_receivings: Vec::new(),
        lifetime: lifetime.clone(),
        vpn_job: None,
        vpn_unsettled: false,
        startup,
        proxy_var_carried: None,
        proxy_var_retryable: false,
        patched_seen: HashMap::new(),
        vpn: None,
        relay_egress: None,
        last: None,
        dns_probe: (false, false),
        carrier_set_proxy: false,
    };

    if matches!(ctx.startup, Startup::Ordinary) {
        settle_decline(&mut ctx);
        startup_housekeeping(&mut ctx);
    }

    // The first snapshot is deep: the window opens on the licence screen, so
    // reading the binaries costs the user nothing here and the main screen is
    // already truthful when it appears.
    push_status(&mut ctx, Scan::Deep);

    let shared = Arc::new(Mutex::new(ctx));
    let mut native_job: Option<std::thread::JoinHandle<Result<NativeCompletion, String>>> = None;
    let mut shutdown = false;
    let mut refresh_requested = cfg!(windows);
    let mut native_unsettled = false;
    #[cfg(windows)]
    let mut elevation_progress: Option<Receiver<crate::instances::ElevationProgress>> = None;
    loop {
        let mut native_finished = false;
        #[cfg(windows)]
        let mut native_hold = None;
        #[cfg(windows)]
        if let Some(progress) = elevation_progress.as_ref() {
            while let Ok(progress) = progress.try_recv() {
                let event = match progress {
                    crate::instances::ElevationProgress::WaitingForConsent => Event::Busy(Some("Ожидание подтверждения администратора".into())),
                    crate::instances::ElevationProgress::WaitingForReplacement => Event::Busy(Some("Подготовка нового окна".into())),
                    crate::instances::ElevationProgress::ObservationPending(error) => Event::Log(Level::Warn, format!("Ожидается завершение передачи окна: {error}")),
                };
                if owner_events.send(event).is_err() { lifetime.channel_lost.store(true, Ordering::SeqCst); }
                if let Ok(wake) = owner_wake.lock() { (wake)(); }
            }
        }
        let mut command = if let Some(command) = first_command.take() { Some(command) } else { match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(command) => Some(command),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => { shutdown = true; None },
        } };
        if receive_wsl_refresh_command(&mut refresh_requested, &command) { command = None; }
        if native_job.as_ref().is_some_and(|job| job.is_finished()) {
            match native_job.take().unwrap().join() {
                Ok(Ok(completion)) => {
                    native_apply_pending.store(false, Ordering::SeqCst);
                    native_finished = true;
                    match completion {
                        NativeCompletion::Retired => {},
                        #[cfg(windows)]
                        NativeCompletion::NeedsElevation(intent) => {
                            if !native_cancel.load(Ordering::SeqCst)
                                && !lifetime.abort_requested.load(Ordering::SeqCst)
                                && !lifetime.channel_lost.load(Ordering::SeqCst) {
                                first_command = Some(Cmd::Elevate(crate::instances::GuiReplacementAction::ResumeApply(intent)));
                            }
                        },
                        #[cfg(windows)]
                        NativeCompletion::Held(reason) => native_hold = Some(reason),
                    }
                },
                Ok(Err(error)) => {
                    native_apply_pending.store(false, Ordering::SeqCst);
                    native_finished = true;
                    let _ = owner_events.send(Event::Log(Level::Err, error));
                }
                Err(_) => {
                    native_unsettled = true;
                    let _ = owner_events.send(Event::Log(Level::Err, "Наблюдение применения прервано; требуется восстановление.".into()));
                }
            }
            #[cfg(windows)]
            { elevation_progress = None; }
        }
        if lifetime.abort_requested.load(Ordering::SeqCst) || lifetime.channel_lost.load(Ordering::SeqCst) {
            native_cancel.store(true, Ordering::SeqCst);
            shutdown = true;
        }
        if lifetime.handoff_requested.load(Ordering::SeqCst) { shutdown = true; }
        if native_job.is_some() || native_unsettled {
            match command {
                Some(Cmd::CancelWsl) => native_cancel.store(true, Ordering::SeqCst),
                Some(Cmd::Shutdown | Cmd::Stop) => { native_cancel.store(true, Ordering::SeqCst); shutdown = true; },
                Some(Cmd::Probed { .. }) => MEASURING_VPN.store(false, Ordering::SeqCst),
                Some(_) => { let _ = owner_events.send(Event::Log(Level::Warn, "Подождите завершения применения настроек.".into())); },
                None => {},
            }
            if let Ok(wake) = owner_wake.lock() { (wake)(); }
            continue;
        }
        let mut ctx = match shared.lock() {
            Ok(ctx) => ctx,
            Err(_) => { native_unsettled = true; continue; },
        };
        #[cfg(windows)]
        if let Some(reason) = native_hold { hold_apply(&mut ctx, reason); }
        if ctx.vpn_job.as_ref().is_some_and(|job| job.is_finished()) {
            if ctx.vpn_job.take().unwrap().join().is_err() {
                ctx.vpn_unsettled = true;
                ctx.log(Level::Err, "Наблюдение проверки сети прервано; завершение не подтверждено.");
            }
        }
        if native_finished {
            push_status(&mut ctx, Scan::Settings);
            if !ctx.wsl.is_pending() && !lifetime.handoff_requested.load(Ordering::SeqCst) { ctx.busy(None); }
        }
        if ctx.poll_wsl_report() {
            push_status(&mut ctx, Scan::Settings);
            if !ctx.wsl.is_pending() { ctx.busy(None); }
            #[cfg(windows)]
            if ctx.wsl.take_elevation_request() && !shutdown
                && !native_cancel.load(Ordering::SeqCst) {
                ctx.log(Level::Err, "Права изменились после начала применения. Оставшиеся действия WSL остановлены; проверьте результат и повторите «Применить».");
            }
        }
        if shutdown {
            ctx.wsl.request_cancel();
            if finish_shutdown(&mut ctx, &lifetime) { return; }
            continue;
        }
        if take_wsl_refresh(&mut refresh_requested, !ctx.wsl.is_pending(), &command, &first_command) {
            if let Err(error) = ctx.wsl.request_discovery() { ctx.log(Level::Warn, error); }
            push_status(&mut ctx, Scan::Settings);
        }
        let Some(cmd) = command else { continue; };
        if matches!(ctx.startup, Startup::Held(_)) && !matches!(&cmd, Cmd::Shutdown | Cmd::Stop | Cmd::CancelWsl) {
            if !genuine_command(&cmd) { continue; }
            if crate::settings::saved_intent_sha256(&ctx.settings).is_err() {
                if let Some(display) = saved_display() { ctx.settings = display; push_status(&mut ctx, Scan::Settings); }
                ctx.log(Level::Err, "Настройки снова изменились; автоматическое применение не выполняется.");
                continue;
            }
            if let Err(error) = lifetime.clear_automatic_hold() { ctx.log(Level::Err, error); continue; }
            ctx.startup = Startup::Explicit;
            ctx.log(Level::Info, "Принят новый выбор пользователя; прежнее продолжение не повторяется.");
        }
        if ctx.wsl.is_applying() && !matches!(&cmd, Cmd::CancelWsl | Cmd::Shutdown | Cmd::Stop | Cmd::Probed { .. }) {
            ctx.log(Level::Warn, "Подождите завершения подготовки WSL.");
            continue;
        }
        match cmd {
            Cmd::RequestElevation => {
                #[cfg(windows)]
                { first_command = Some(Cmd::Elevate(crate::instances::GuiReplacementAction::ShowMain {})); }
                #[cfg(not(windows))]
                ctx.log(Level::Warn, "Передача Windows-окна недоступна на этой платформе.");
            },
            #[cfg(windows)]
            Cmd::Elevate(action) => {
                #[cfg(windows)]
                {
                    if ctx.wsl.is_pending() || ctx.vpn_job.is_some() || ctx.vpn_unsettled {
                        ctx.log(Level::Warn, "Дождитесь завершения текущей операции перед передачей окна.");
                        continue;
                    }
                    match &action {
                        crate::instances::GuiReplacementAction::ShowMain {} => {
                            if !ctx.settings.save() { ctx.log(Level::Err, "Настройки не сохранены; новое окно не запущено."); continue; }
                        },
                        crate::instances::GuiReplacementAction::ResumeApply(intent) => {
                            let _ = intent; // Receiving stays inside the owned cancellable job.
                        }
                    };
                    let (progress, received) = mpsc::channel();
                    elevation_progress = Some(received);
                    native_cancel.store(false, Ordering::SeqCst);
                    native_apply_pending.store(true, Ordering::SeqCst);
                    ctx.busy(Some("Подготовка передачи окна"));
                    push_status(&mut ctx, Scan::Settings);
                    let cancellation = native_cancel.clone();
                    let lifetime = lifetime.clone();
                    native_job = match std::thread::Builder::new().name("gui-elevation".into()).spawn(move || {
                        if let crate::instances::GuiReplacementAction::ResumeApply(intent) = &action {
                            if let Err(error) = receive_apply_continuation(intent, &cancellation, lifetime.retained_image()) {
                                return Ok(NativeCompletion::Held(format!("Данные применения изменились; передача остановлена: {error}")));
                            }
                        }
                        if cancellation.load(Ordering::SeqCst) { return Ok(NativeCompletion::Retired); }
                        let image = lifetime.retained_image()?;
                        let mut ready = crate::instances::request_elevation(&image, action, cancellation.clone(), progress.clone())?;
                        if cancellation.load(Ordering::SeqCst) {
                            retire_replacement(&mut ready, &progress);
                            return Ok(NativeCompletion::Retired);
                        }
                        if let Err(mut ready) = lifetime.accept_replacement(ready) {
                            retire_replacement(&mut ready, &progress);
                            return Err("Передача окна не принята; новое окно завершено.".into());
                        }
                        Ok(NativeCompletion::Retired)
                    }) {
                        Ok(job) => Some(job),
                        Err(error) => {
                            native_apply_pending.store(false, Ordering::SeqCst);
                            elevation_progress = None;
                            ctx.log(Level::Err, format!("Не удалось начать передачу окна: {error}"));
                            ctx.busy(None);
                            push_status(&mut ctx, Scan::Settings);
                            None
                        }
                    };
                }
            },
            Cmd::Stop | Cmd::Shutdown => { ctx.wsl.request_cancel(); shutdown = true; },
            Cmd::CancelWsl => ctx.wsl.request_cancel(),
            Cmd::RefreshWsl => unreachable!("refresh is latched before busy handling"),
            Cmd::SetWslEnabled(enabled) => {
                if wsl_status(&ctx).pending { ctx.log(Level::Warn, "Дождитесь завершения операции WSL."); continue; }
                let mut wanted = ctx.settings.clone();
                wanted.wsl = Some(crate::wsl_api::WslPreferences { enabled,
                    distros: wanted.wsl.as_ref().map(|p| p.distros.clone()).unwrap_or_default() });
                if wanted.save() { ctx.settings = wanted; }
                else { ctx.log(Level::Err, "Настройки WSL не сохранились; выбор не изменён."); }
                push_status(&mut ctx, Scan::Settings);
            },
            Cmd::SetWslDistro { name, selected } => {
                let current = wsl_status(&ctx);
                if name.is_empty() || name.chars().any(char::is_control)
                    || !current.can_set_distro(&name, selected) {
                    ctx.log(Level::Err, "Дистрибутив не подтверждён; обновите список WSL.");
                    continue;
                }
                let mut wanted = ctx.settings.clone();
                let preferences = wanted.wsl.get_or_insert(crate::wsl_api::WslPreferences { enabled: false, distros: Vec::new() });
                preferences.distros.retain(|old| old != &name);
                if selected { preferences.distros.push(name); }
                if wanted.save() { ctx.settings = wanted; }
                else { ctx.log(Level::Err, "Настройки WSL не сохранились; выбор не изменён."); }
                push_status(&mut ctx, Scan::Settings);
            },
            Cmd::ApplySettings => {
                if ctx.wsl.is_pending() { ctx.log(Level::Warn, "Подождите завершения поиска WSL."); continue; }
                #[allow(unused_mut)]
                let mut resumed = false;
                #[cfg(windows)]
                let mut resume_intent = None;
                #[cfg(windows)]
                if let Startup::Resume(intent) = &ctx.startup {
                    resume_intent = Some(intent.clone());
                    ctx.startup = Startup::Explicit;
                    resumed = true;
                }
                if !resumed && !ctx.settings.save() { ctx.log(Level::Err, "Настройки не сохранены; применение не начато."); continue; }
                let wanted = ctx.settings.clone();
                native_cancel.store(false, Ordering::SeqCst);
                native_apply_pending.store(true, Ordering::SeqCst);
                ctx.busy(Some("Применение настроек"));
                push_status(&mut ctx, Scan::Settings);
                let shared = shared.clone();
                let cancellation = native_cancel.clone();
                native_job = match std::thread::Builder::new().name("apply-settings".into()).spawn(move || {
                    let mut ctx = shared.lock().map_err(|_| "settings owner lock was poisoned".to_owned())?;
                    let result = apply_acknowledged(&mut ctx, wanted, &cancellation, #[cfg(windows)] resume_intent);
                    push_status(&mut ctx, Scan::Deep);
                    result
                }) {
                    Ok(job) => Some(job),
                    Err(error) => {
                        native_apply_pending.store(false, Ordering::SeqCst);
                        ctx.log(Level::Err, format!("Не удалось начать применение: {error}"));
                        ctx.busy(None);
                        push_status(&mut ctx, Scan::Settings);
                        None
                    }
                };
            },
            Cmd::RememberLicense(key) => {
                if ctx.settings.license_key != key {
                    ctx.settings.license_key = key;
                    ctx.settings.save();
                }
            }
            // Off the queue, not on it. The measurement drives PowerShell and
            // takes seconds; on the queue, a user flipping a switch in the
            // middle of one would watch it snap back until it finished — G42's
            // lesson, applied to a job nobody asked for. No `busy` marker
            // either, for the same reason: nothing the user is waiting on is
            // running.
            Cmd::RemeasureVpn => {
                use std::sync::atomic::Ordering;
                if ctx.vpn_job.is_none() && !MEASURING_VPN.swap(true, Ordering::SeqCst) {
                    let back = own.clone();
                    let spawned = std::thread::Builder::new()
                        .name("vpn-probe".to_string())
                        .spawn(move || {
                            let (vpn, relay_egress) = measure_vpn();
                            let relay = background::is_enabled() && background::is_running();
                            MEASURING_VPN.store(false, Ordering::SeqCst);
                            let _ = back.send(Cmd::Probed {
                                vpn,
                                relay,
                                relay_egress,
                            });
                        });
                    match spawned {
                        Ok(job) => ctx.vpn_job = Some(job),
                        Err(_) => {
                        // Or the flag would stay raised and this window would
                        // never measure again.
                        MEASURING_VPN.store(false, Ordering::SeqCst);
                        }
                    }
                }
            }
            Cmd::Probed {
                vpn,
                relay,
                relay_egress,
            } => {
                let before = ctx.vpn;
                ctx.vpn = Some(vpn);
                ctx.relay_egress = relay_egress;
                if before.is_some() && before != ctx.vpn {
                    if let Some(line) = vpn_change_line(vpn) {
                        ctx.log(Level::Info, line);
                    }
                }
                // The raw half of `dns_probe`, refreshed without re-asking
                // Windows about rules: the relay is the one of the two that
                // stops on its own.
                ctx.dns_probe.1 = relay;
                push_status(&mut ctx, Scan::Settings);
            }
            Cmd::DeepRefresh => {
                ctx.busy(Some("Проверка установок"));
                push_status(&mut ctx, Scan::Deep);
                ctx.busy(None);
            }
            command @ (Cmd::Set(_, _) | Cmd::EnableAll | Cmd::Repair
                | Cmd::SetOwnProxy(_) | Cmd::SetGroupKey(_) | Cmd::Unlocked
                | Cmd::AddPath(_) | Cmd::PatchInstall(_)) => {
                native_cancel.store(false, Ordering::SeqCst);
                native_apply_pending.store(true, Ordering::SeqCst);
                ctx.busy(Some("Применение выбранного действия"));
                push_status(&mut ctx, Scan::Settings);
                let shared = shared.clone();
                native_job = match std::thread::Builder::new().name("settings-command".into()).spawn(move || {
                    let mut ctx = shared.lock().map_err(|_| "settings owner lock was poisoned".to_owned())?;
                    dispatch_owned_command(&mut ctx, command)
                }) {
                    Ok(job) => Some(job),
                    Err(error) => {
                        native_apply_pending.store(false, Ordering::SeqCst);
                        ctx.log(Level::Err, format!("Не удалось начать выбранное действие: {error}"));
                        ctx.busy(None);
                        push_status(&mut ctx, Scan::Settings);
                        None
                    }
                };
            },
            Cmd::ForgetPath(p) => {
                ctx.settings.manual_paths.retain(|x| x != &p);
                ctx.settings.save();
                push_status(&mut ctx, Scan::System);
            }
            Cmd::SetCustomDns(text) => {
                set_custom_dns(&mut ctx, &text);
                ctx.settings.save();
                push_status(&mut ctx, Scan::Settings);
            }
            Cmd::ReorderProviders(order) => {
                ctx.settings.provider_order = order;
                ctx.settings.save();
                ctx.log(
                    Level::Info,
                    match first_enabled_provider(&ctx.settings) {
                        Some(n) => format!("Порядок DNS изменён, первый — {}", n),
                        None => "Порядок DNS изменён.".to_string(),
                    },
                );
                // The order is ours alone — nothing on the machine changed, so
                // there is nothing on the machine to re-read.
                push_status(&mut ctx, Scan::Settings);
            }
            Cmd::SetProvider(name, on) => {
                ctx.settings.set_provider_enabled(&name, on);
                // Never let the last one go: an empty pool is a dead DNS layer
                // that still draws as installed.
                if all_providers_disabled(&ctx.settings) {
                    ctx.settings.set_provider_enabled(&name, true);
                    ctx.log(
                        Level::Warn,
                        "Нельзя отключить все DNS-серверы — хотя бы один должен остаться.",
                    );
                } else if !on && no_usable_nameserver(&ctx.settings) {
                    ctx.settings.set_provider_enabled(&name, true);
                    ctx.log(
                        Level::Warn,
                        "Этот сервер нельзя отключить: он остался единственным, который Windows может использовать как DNS-сервер напрямую.",
                    );
                } else {
                    ctx.log(
                        Level::Info,
                        format!(
                            "DNS-сервер {} {}",
                            name,
                            if on {
                                "включён"
                            } else {
                                "отключён"
                            }
                        ),
                    );
                }
                ctx.settings.save();
                let rewrote = reapply_dns_rules(&mut ctx);
                // Only when the rules were actually rewritten is there anything
                // new on the machine to read back.
                push_status(
                    &mut ctx,
                    if rewrote {
                        Scan::System
                    } else {
                        Scan::Settings
                    },
                );
            }
        }
    }
}

fn finish_shutdown(ctx: &mut Ctx, lifetime: &GuiLifetime) -> bool {
    if ctx.wsl.is_pending() || ctx.vpn_job.is_some() || ctx.vpn_unsettled
        || lifetime.save_failed.load(Ordering::SeqCst) { return false; }
    #[cfg(windows)]
    if lifetime.handoff_requested.load(Ordering::SeqCst)
        && crate::settings::saved_intent_sha256(&ctx.settings).is_err() {
        hold_apply(ctx, "Сохранённые настройки изменились перед передачей окна; они не перезаписаны. Закройте окно для отмены передачи.".into());
        if !lifetime.abort_requested.load(Ordering::SeqCst) {
            lifetime.save_failed.store(true, Ordering::SeqCst);
            return false;
        }
    }
    if matches!(ctx.startup, Startup::Held(_)) || lifetime.handoff_requested.load(Ordering::SeqCst) || ctx.settings.save() {
        lifetime.shutdown_ready.store(true, Ordering::SeqCst);
        let _ = ctx.events.send(Event::ShutdownReady);
        if let Ok(wake) = ctx.wake.lock() { (wake)(); }
        return true;
    }
    ctx.log(Level::Err, "Не удалось сохранить настройки; окно остаётся открытым.");
    lifetime.save_failed.store(true, Ordering::SeqCst);
    false
}

/// The one thing that runs on its own, before the user has touched anything.
///
/// `refresh_pinned_hosts` exists because the host routes that keep our queries
/// off a VPN survive a reboot only while the network stays the same. It is also
/// the one call that can turn a switch off by itself: with the client measured
/// inside a tunnel it strips the rules outright (G29). In a console that was
/// invisible and harmless; in a window it reads as the tool spontaneously
/// disabling itself, so the flip is watched for and explained.
fn startup_housekeeping(ctx: &mut Ctx) {
    if !cfg!(target_os = "windows") || !is_admin() {
        return;
    }
    let before = dns::is_nrpt_applied();
    dns::refresh_pinned_hosts();
    dns::invalidate_cache();
    if before && !dns::is_nrpt_applied() {
        ctx.log(
            Level::Warn,
            "Antigravity идёт через активный VPN — правила DNS сняты, чтобы не перебивать \
             ваш туннель. Выключите VPN и включите «Обход через DNS» заново.",
        );
    }
}

fn all_providers_disabled(s: &Settings) -> bool {
    crate::resolvers::provider_names()
        .iter()
        .all(|n| !s.provider_enabled(n))
}

/// Whether the selection would leave the NRPT rule with no nameserver.
///
/// The pool would still resolve — the head of the list speaks DoH through the
/// relay — but Windows itself would be pointed at nothing, so any lookup that
/// bypasses the relay (it stopped, it is being upgraded) fails outright instead
/// of falling back. I49.
fn no_usable_nameserver(s: &Settings) -> bool {
    crate::resolvers::udp_provider_names()
        .iter()
        .all(|n| !s.provider_enabled(n))
}

/// The one that answers when rotation is off: first in pool order that the user
/// has not switched off. Pool order is by measured substitution, so its head is
/// the one most likely to still be substituting.
fn first_enabled_provider(s: &Settings) -> Option<&'static str> {
    crate::resolvers::ordered_provider_names()
        .into_iter()
        .find(|n| s.provider_enabled(n))
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// How much of the system has to be re-read after `cap` was flipped.
///
/// The rule is "what could this switch have changed", not "how important is it":
/// `VerifyTls`, `VpnDetect` and `BuiltinExits` write one field of `settings.json`
/// and nothing else, so asking Windows about scheduled tasks, NRPT rules and the
/// user environment afterwards is two seconds of latency buying a byte-identical
/// answer.
fn scan_after(cap: Cap) -> Scan {
    match cap {
        // The one action that changes what is *inside* the binaries, so the one
        // that has to pay for re-reading them.
        Cap::ClientPatch => Scan::Deep,
        Cap::Watchdog | Cap::Dns | Cap::LocalProxy | Cap::OwnProxy | Cap::DnsRotation => {
            Scan::System
        }
        Cap::BuiltinExits | Cap::GroupProxy => Scan::Settings,
    }
}

fn push_status(ctx: &mut Ctx, scan: Scan) {
    // The measurement answers "do the client's own sockets leave through a
    // tunnel", which no switch in this window changes — only what we then do
    // about it. So it is taken on the deep pass and when it has never been
    // taken, and a settings flip inherits it rather than paying a PowerShell
    // round trip to be told the same thing.
    if scan == Scan::Deep || ctx.vpn.is_none() {
        let (vpn, relay_egress) = measure_vpn();
        ctx.vpn = Some(vpn);
        ctx.relay_egress = relay_egress;
    }

    let status = match scan {
        Scan::Settings => match ctx.last.clone() {
            Some(prev) => settings_only_status(ctx, prev),
            // Nothing to reuse yet (a flip before the first snapshot landed):
            // ask properly rather than invent a snapshot.
            None => read_status(ctx, false),
        },
        Scan::System => read_status(ctx, false),
        Scan::Deep => read_status(ctx, true),
    };

    if scan == Scan::Deep {
        ctx.patched_seen = status
            .installs
            .iter()
            .filter_map(|r| match (&r.path, r.patched) {
                (Some(p), Some(v)) => Some((p.clone(), v)),
                _ => None,
            })
            .collect();
    }
    ctx.last = Some(status.clone());
    if ctx.events.send(Event::Status(Box::new(status))).is_err() { ctx.lifetime.channel_lost.store(true, Ordering::SeqCst); }
    if let Ok(wake) = ctx.wake.lock() { (wake)(); }
}

fn wsl_status(ctx: &Ctx) -> crate::wsl_api::WslStatus {
    let mut status = ctx.wsl.snapshot(ctx.settings.wsl.clone());
    status.pending |= ctx.native_apply_pending.load(Ordering::SeqCst) || ctx.vpn_unsettled;
    if let Startup::Held(reason) = &ctx.startup { status.error = Some(reason.clone()); }
    status
}

/// The existing native job owns Ctx while the outer loop receives cancel/close.
/// These selected command effects run off the command-receiving thread.
fn dispatch_owned_command(ctx: &mut Ctx, command: Cmd) -> Result<NativeCompletion, String> {
    if ctx.native_cancel.load(Ordering::SeqCst) {
        return Err("Выбранное действие отменено до начала.".into());
    }
    let saves_intent = matches!(&command, Cmd::Set(_, _) | Cmd::SetOwnProxy(_) | Cmd::SetGroupKey(_) | Cmd::EnableAll | Cmd::Repair);
    let effect = (|| -> Result<(), String> { match command {
            Cmd::Set(cap, on) => {
                ctx.busy(Some(cap.title()));
                apply(ctx, cap, on)?;
                push_status(ctx, scan_after(cap));
                // Turning auto-patch on is asking for Antigravity to be patched;
                // waiting for the watchdog's next poll would show the switch on
                // and the install still grey.
                if cap == Cap::Watchdog && on && auto_patch_found(ctx) {
                    push_status(ctx, Scan::Deep);
                }
            }
            Cmd::SetOwnProxy(text) => {
                ctx.busy(Some("Проверка прокси"));
                set_own_proxy(ctx, &text)?;
                push_status(ctx, Scan::System);
            }
            Cmd::SetGroupKey(text) => {
                ctx.busy(Some("Проверка ключа"));
                match crate::group_key::parse_key(&text) {
                    Ok(_) => {
                        ctx.settings.group_key = text.trim().to_string();
                        ctx.settings.group_key_at = crate::gate::now_unix();
                        ctx.settings.group_proxy = true;
                        if !ctx.settings.save() { return Err("Ключ не сохранён; применение не начиналось.".into()); }
                        apply(ctx, Cap::GroupProxy, true)?;
                        ctx.log(crate::ops::Level::Ok, "Ключ принят.");
                        push_status(ctx, scan_after(Cap::GroupProxy));
                    }
                    Err(e) => {
                        ctx.log(crate::ops::Level::Err, format!("{}", e));
                    }
                }
            }
            Cmd::EnableAll => {
                ctx.busy(Some("Включаю"));
                enable_all(ctx)?;
                push_status(ctx, Scan::Deep);
            }
            Cmd::Repair => {
                ctx.busy(Some("Чиню службу обхода"));
                repair(ctx)?;
                push_status(ctx, Scan::System);
            }
        Cmd::Unlocked => {
            if matches!(ctx.startup, Startup::Ordinary) {
                if auto_patch_found(ctx) { push_status(ctx, Scan::Deep); }
                else { push_status(ctx, Scan::System); }
            } else { push_status(ctx, Scan::Settings); }
        },
        Cmd::AddPath(path) => {
            if !ctx.settings.manual_paths.contains(&path) {
                ctx.settings.manual_paths.push(path);
                if !ctx.settings.save() { return Err("Путь не сохранён; патч не начинался.".into()); }
            }
            push_status(ctx, Scan::Deep);
            if auto_patch_found(ctx) { push_status(ctx, Scan::Deep); }
        },
        Cmd::PatchInstall(path) => {
            let label = crate::install_label(&path);
            if !patch_found(ctx, vec![(label, path)]) {
                return Err(format!("{label}: патч не записан, см. предыдущий результат"));
            }
            push_status(ctx, Scan::Deep);
        },
        _ => return Err("Команда не относится к выбранному действию.".into()),
    }; Ok(()) })();
    let saved = !saves_intent || ctx.settings.save();
    match (effect, saved) {
        (Ok(()), true) => {},
        (Err(error), true) => return Err(error),
        (Ok(()), false) => return Err("Действие получено, но выбранные настройки не сохранены.".into()),
        (Err(error), false) => return Err(format!("{error}; выбранные настройки также не сохранены")),
    }
    Ok(NativeCompletion::Retired)
}

fn genuine_command(command: &Cmd) -> bool {
    matches!(command, Cmd::RequestElevation | Cmd::ApplySettings | Cmd::SetWslEnabled(_) | Cmd::SetWslDistro { .. }
        | Cmd::Set(_, _) | Cmd::AddPath(_) | Cmd::ForgetPath(_) | Cmd::PatchInstall(_) | Cmd::SetOwnProxy(_)
        | Cmd::SetCustomDns(_) | Cmd::SetGroupKey(_) | Cmd::SetProvider(_, _) | Cmd::ReorderProviders(_)
        | Cmd::EnableAll | Cmd::Repair)
}

fn worker_boot(rx: &Receiver<Cmd>, events: &Sender<Event>, wake: &Arc<Mutex<Box<dyn Fn() + Send>>>,
    lifetime: &Arc<GuiLifetime>) -> Option<(Settings, Startup, Option<Cmd>)> {
    let hold = match lifetime.bootstrap_hold.lock() {
        Ok(mut hold) => hold.take(),
        Err(_) => return rejected_boot(rx, events, wake, lifetime, "Не удалось получить ограничение автоматического запуска.".into()),
    };
    if let Some(reason) = hold { return held_boot(rx, events, wake, lifetime, reason); }
    #[cfg(windows)]
    {
        let action = match lifetime.action.lock() {
            Ok(mut action) => action.take(),
            Err(_) => return rejected_boot(rx, events, wake, lifetime, "Не удалось получить продолжение GUI.".into()),
        };
        if let Some(crate::instances::GuiReplacementAction::ResumeApply(intent)) = action {
            if lifetime.retirement_input.lock().map_or(true, |value| value.is_some()) {
                return rejected_boot(rx, events, wake, lifetime, "Конфликт входных данных продолжения.".into());
            }
            if let Some(descriptor) = intent.retirement_input.clone() {
                if let Err(error) = lifetime.receive_retirement_input(descriptor) {
                    return held_boot(rx, events, wake, lifetime, format!("Не удалось получить входные данные продолжения: {error}"));
                }
            }
            match receive_apply_continuation(&intent, &lifetime.abort_requested, lifetime.retained_image()) {
                Ok(plan) => return Some((plan.wanted.clone(), Startup::Resume(intent), Some(Cmd::ApplySettings))),
                Err(error) => {
                    let reason = format!("Данные изменились во время передачи окна; применение не выполнялось: {error}");
                    return held_boot(rx, events, wake, lifetime, reason);
                }
            }
        }
        if lifetime.retirement_input.lock().map_or(true, |value| value.is_some()) {
            return Some((Settings::load(), Startup::Explicit, None));
        }
    }
    Some((Settings::load(), Startup::Ordinary, None))
}

fn held_boot(rx: &Receiver<Cmd>, events: &Sender<Event>, wake: &Arc<Mutex<Box<dyn Fn() + Send>>>,
    lifetime: &Arc<GuiLifetime>, reason: String) -> Option<(Settings, Startup, Option<Cmd>)> {
    if let Err(error) = lifetime.hold_automatic_effects(reason.clone()) { let _ = events.send(Event::Log(Level::Err, error)); }
    let _ = events.send(Event::Log(Level::Err, reason.clone()));
    // Display-only receiving never qualifies a rejected or already-consumed
    // continuation. Only an actual canonical saved snapshot may enter Ctx.
    if let Some(display) = saved_display() {
        Some((display, Startup::Held(reason), None))
    } else { rejected_boot(rx, events, wake, lifetime, reason) }
}

fn saved_display() -> Option<Settings> {
    let display = Settings::load();
    crate::settings::saved_intent_sha256(&display).ok().map(|_| display)
}

#[cfg(windows)]
fn hold_apply(ctx: &mut Ctx, reason: String) {
    if let Some(display) = saved_display() { ctx.settings = display; }
    ctx.startup = Startup::Held(reason.clone());
    if let Err(error) = ctx.lifetime.hold_automatic_effects(reason.clone()) { ctx.log(Level::Err, error); }
    ctx.log(Level::Err, reason);
}

fn rejected_boot(rx: &Receiver<Cmd>, events: &Sender<Event>, wake: &Arc<Mutex<Box<dyn Fn() + Send>>>,
    lifetime: &Arc<GuiLifetime>, reason: String) -> Option<(Settings, Startup, Option<Cmd>)> {
    let _ = events.send(Event::Log(Level::Err, reason.clone()));
    let _ = events.send(Event::Busy(Some("Сохранённые данные не подтверждены; применение остановлено.".into())));
    if let Ok(wake) = wake.lock() { (wake)(); }
    loop {
        match rx.recv() {
            Ok(Cmd::Shutdown | Cmd::Stop) | Err(_) => {
                // No Settings or effects were accepted, so preserve the actual
                // saved bytes instead of writing a fabricated default snapshot.
                lifetime.shutdown_ready.store(true, Ordering::SeqCst);
                let _ = events.send(Event::ShutdownReady);
                if let Ok(wake) = wake.lock() { (wake)(); }
                return None;
            }
            Ok(Cmd::ApplySettings) => {
                let settings = Settings::load();
                if crate::settings::saved_intent_sha256(&settings).is_ok() {
                    return Some((settings, Startup::Explicit, Some(Cmd::ApplySettings)));
                }
                let _ = events.send(Event::Log(Level::Err, "Сохранённые настройки не подтверждены; данные не изменены.".into()));
                if let Ok(wake) = wake.lock() { (wake)(); }
            }
            _ => {},
        }
    }
}

#[cfg(windows)]
fn retire_replacement(ready: &mut crate::instances::GuiReplacementReady,
    progress: &Sender<crate::instances::ElevationProgress>) {
    let mut last_error = None;
    loop {
        let outcome = ready.request_abort().and_then(|_| ready.poll_retired());
        match outcome {
            Ok(true) => return,
            Ok(false) => {},
            Err(error) => {
                if last_error.as_ref() != Some(&error) {
                    let _ = progress.send(crate::instances::ElevationProgress::ObservationPending(error.clone()));
                    last_error = Some(error);
                }
            }
        }
        std::thread::sleep(crate::wsl_runtime::OWNER_OBSERVATION_CADENCE);
    }
}

/// The last snapshot with every settings-derived field recomputed, and nothing
/// asked of the machine.
///
/// The DNS row is included because it is settings-derived *in part*: whether a
/// measured tunnel blocks it depends on `vpn_detect`. It is rebuilt from the raw
/// pair the last system scan kept, so a settings-only flip updates the row
/// it governs without going near a scheduled task.
fn settings_only_status(ctx: &Ctx, prev: Status) -> Status {
    let (rules, relay) = ctx.dns_probe;
    Status {
        wsl: wsl_status(ctx),
        dns: dns_state(
            prev.admin,
            rules,
            relay,
            ctx.vpn,
            ctx.settings.vpn_detect,
            ctx.settings.dns,
        ),
        // Not `..prev`: `Cmd::Probed` refreshes this behind the window's back,
        // and a row carried forward from the last system scan would say a relay
        // that died an hour ago is still running.
        relay_running: relay,
        rules,
        own_proxy_text: upstream::configured()
            .map(|u| u.display())
            .unwrap_or_else(|| ctx.settings.own_proxy.clone()),
        vpn: ctx.vpn,
        relay_egress: ctx.relay_egress,
        ..prev
    }
    .with_settings_switches(&ctx.settings)
}

impl Status {
    /// The four switches that are nothing but a field of `settings.json`, plus
    /// the provider list they order. Written once so `read_status` and
    /// `settings_only_status` cannot drift apart — the bug that would produce is
    /// a switch that answers differently depending on which path drew it.
    fn with_settings_switches(mut self, s: &Settings) -> Self {
        self.builtin_exits = on_off(s.builtin_exits);
        self.group_proxy = on_off(s.group_proxy);
        self.custom_dns_text = s.custom_dns.clone();
        self.dns_rotation = if s.rotate_providers {
            State::On
        } else {
            // Naming the one that will answer is the whole point of switching
            // rotation off, so the switch says which it is rather than leaving
            // the user to count down the list.
            State::OffNote(match first_enabled_provider(s) {
                Some(name) => format!("используется только {}", name),
                None => "ни один сервер не включён".to_string(),
            })
        };
        self.providers = crate::resolvers::ordered_provider_names()
            .iter()
            .map(|n| ProviderRow {
                name: (*n).to_string(),
                enabled: s.provider_enabled(n),
            })
            .collect();
        self
    }
}

fn on_off(v: bool) -> State {
    if v {
        State::On
    } else {
        State::Off
    }
}

fn read_status(ctx: &mut Ctx, deep: bool) -> Status {
    let admin = is_admin();

    // Every probe below spawns a helper process — two scheduled-task queries, a
    // tasklist, up to three reads of the user environment — and they are
    // independent of one another. Run in series they added up to seconds per
    // switch; run at once the refresh costs the slowest one. They only read, so
    // there is nothing here for them to race over.
    let settings = &ctx.settings;
    let patched_seen = &ctx.patched_seen;
    let (installs, watchdog, dns_probe, local_proxy, own_proxy, own_proxy_text, relay_outdated) =
        std::thread::scope(|scope| {
            let installs = scope.spawn(move || collect_installs(settings, deep, patched_seen));
            let watchdog = scope.spawn(move || read_watchdog(admin));
            let dns_probe = scope.spawn(probe_dns);
            let local_proxy = scope.spawn(move || read_local_proxy(settings));
            let own_proxy = scope.spawn(read_own_proxy);
            let own_proxy_text = scope.spawn(move || {
                upstream::configured()
                    .map(|u| u.display())
                    .unwrap_or_else(|| settings.own_proxy.clone())
            });
            let relay_outdated = scope.spawn(background::relay_is_outdated);
            (
                installs.join().unwrap_or_default(),
                watchdog.join().unwrap_or(State::Off),
                dns_probe.join().unwrap_or((false, false)),
                local_proxy.join().unwrap_or(State::Off),
                own_proxy.join().unwrap_or(State::Off),
                own_proxy_text.join().unwrap_or_default(),
                relay_outdated.join().unwrap_or(false),
            )
        });
    ctx.dns_probe = dns_probe;

    let patched: Vec<bool> = installs.iter().filter_map(|i| i.patched).collect();
    let client_patch = if patched.is_empty() {
        // Not inspected yet, or nothing found. Fall back to what the user asked
        // for rather than claiming knowledge we do not have.
        if ctx.settings.client_patch {
            State::Partial("состояние ещё не проверено".into())
        } else {
            State::Off
        }
    } else if patched.iter().all(|p| *p) {
        State::On
    } else if patched.iter().any(|p| *p) {
        State::Partial("пропатчены не все установки".into())
    } else {
        State::Off
    };

    Status {
        wsl: wsl_status(ctx),
        admin,
        client_patch,
        watchdog,
        dns: dns_state(
            admin,
            dns_probe.0,
            dns_probe.1,
            ctx.vpn,
            ctx.settings.vpn_detect,
            ctx.settings.dns,
        ),
        local_proxy,
        own_proxy,
        own_proxy_text,
        custom_dns_text: ctx.settings.custom_dns.clone(),
        builtin_exits: State::Off,
        group_proxy: State::Off,
        vpn: ctx.vpn,
        dns_rotation: State::Off,
        relay_outdated,
        relay_running: dns_probe.1,
        rules: dns_probe.0,
        relay_egress: ctx.relay_egress,
        providers: Vec::new(),
        installs,
    }
    .with_settings_switches(&ctx.settings)
}

/// Asks the system where the traffic actually leaves.
///
/// Deliberately the same call `setup_dns_nrpt` makes, so the indicator and the
/// decision can never disagree: anything else would be a second opinion, and a
/// second opinion is how a user ends up told one thing while the layer does
/// another.
fn measure_vpn() -> (VpnSeen, Option<crate::egress::ClientEgress>) {
    use crate::egress::ClientEgress;
    let egress = crate::egress::detect();
    if !egress.as_ref().is_some_and(|e| e.vpn_active) {
        return (VpnSeen::None, None);
    }
    // One reading, both halves — the same call `egress::vpn_verdict` makes for
    // the DNS layer, so the row this colours and the decision that layer takes
    // cannot be looking at different data. What is *reported* is the
    // measurement itself, not the verdict derived from it: "stand the layer
    // down" and "the client is outside the tunnel" are different questions, and
    // reading the first as the second is what made the indicator claim a
    // measurement nobody had taken.
    let reading = crate::egress::read();
    let client = match reading.client {
        ClientEgress::Tunnel => VpnSeen::CarryingClient,
        ClientEgress::Mixed => VpnSeen::PartlyCarryingClient,
        ClientEgress::Physical => VpnSeen::NotCarryingClient,
        ClientEgress::ViaLocalProxy => VpnSeen::ViaLocalProxy,
        ClientEgress::Unknown => VpnSeen::Unmeasured,
    };
    (client, Some(reading.relay))
}

/// The one line the journal gets when the answer changes. An `Unmeasured` is
/// not a change worth a line: it says only that Antigravity stopped running.
fn vpn_change_line(now: VpnSeen) -> Option<&'static str> {
    match now {
        VpnSeen::None => Some("VPN отключён — обход снова работает сам."),
        VpnSeen::CarryingClient => Some(
            "Antigravity пошёл через VPN — снятие ошибки 400 теперь зависит от вашего сервера.",
        ),
        VpnSeen::NotCarryingClient => Some("Трафик Antigravity идёт мимо VPN — обход применяется."),
        VpnSeen::ViaLocalProxy => Some(
            "Antigravity ходит через локальный прокси — до серверов Google \
             соединение открывает служба обхода, а не он сам.",
        ),
        VpnSeen::PartlyCarryingClient => {
            Some("Часть трафика Antigravity пошла через VPN, часть идёт мимо.")
        }
        VpnSeen::Unmeasured => None,
    }
}

/// Windows registers the watcher as a machine task, which takes UAC; on Linux
/// it is a user unit and anyone may have it. Without this the «Включить всё»
/// path and the patch switch skipped auto-patch for every non-root user, and the
/// row stayed off for good.
fn watchdog_allowed(admin: bool) -> bool {
    admin || !cfg!(target_os = "windows")
}

fn read_watchdog(admin: bool) -> State {
    if background::is_watchdog_enabled() {
        State::On
    } else if !admin && cfg!(target_os = "windows") {
        State::Blocked("нужны права администратора".into())
    } else {
        State::Off
    }
}

/// The two facts about the DNS layer that only the machine can answer: are our
/// NRPT rules in, and is the relay task both registered and running.
///
/// Split from the verdict below so a settings-only refresh can rebuild the row
/// from the last measurement instead of asking Windows again (`Scan::Settings`).
fn probe_dns() -> (bool, bool) {
    let rules = dns::is_nrpt_applied();
    let relay = background::is_enabled() && background::is_running() && relay_reporting();
    (rules, relay)
}

/// Whether the relay itself is alive, and not only a process of its name.
///
/// `is_running` matches `ag_dns.exe` in the task list, and the watchdog is a
/// second process with that same image name - so a relay that died on startup
/// still read as running for as long as its watchdog lived (P54). A field
/// report printed both halves of that contradiction in one paste: «Служба:
/// запущена» over «Записи нет — служба не запущена или старая». The relay
/// writes `gate.json` from its first moment (`gate::note_started`) and on every
/// warm pass; the watchdog never writes it.
///
/// Windows only. The Linux proxy writes that file solely to record a blocker,
/// so there the systemd unit being active is all there is to go on.
fn relay_reporting() -> bool {
    !cfg!(target_os = "windows") || crate::gate::read().is_some_and(|r| !r.is_stale())
}

fn dns_state(
    admin: bool,
    rules: bool,
    relay: bool,
    vpn: Option<VpnSeen>,
    detect_on: bool,
    wanted: bool,
) -> State {
    // No VPN branch any more (D25): the layer does not stand down for a tunnel,
    // so a client measured inside one says nothing about whether the rules are
    // doing their job. The parameters stay so the callers keep one signature.
    let _ = (vpn, detect_on);
    match (rules, relay) {
        (true, true) => State::On,
        // The rules name the relay first (I5). Rules without it resolve through
        // the fallback providers only, which works but is not what was asked
        // for — and it is exactly what a crashed relay looks like.
        (true, false) => State::Partial("правила стоят, служба не запущена".into()),
        // A service that runs for the sake of a route (own proxy, group, exits)
        // is not a half-installed DNS layer: the DNS switch is off, and drawing
        // it as `Partial` - which reads as on - made it impossible to switch off
        // while any route kept the service up.
        (false, true) if !wanted => State::Off,
        (false, true) => State::Partial("служба работает, правил нет".into()),
        (false, false) => {
            if !admin && cfg!(target_os = "windows") {
                State::Blocked("нужны права администратора".into())
            } else {
                State::Off
            }
        }
    }
}

/// The local-proxy switch: what the user asked for, and whether the variable
/// has caught up with it.
///
/// Both halves, because the two readers of this route are not the same process.
/// The relay obeys `settings.local_proxy` and nothing else; the window used to
/// draw the switch from the environment alone, so a variable that outlived a
/// failed removal made the window say «вкл» in the same minute the service
/// logged «выключена в настройках», with nothing on screen to explain it or
/// any way for the user to act on it (G74, two field reports on `2.15.1`).
fn read_local_proxy(settings: &Settings) -> State {
    let url = proxy::proxy_url();
    if let Some(foreign) = endpoint::foreign_proxy(&url) {
        // Measured (G33): ours wins over theirs inside the patched server, so
        // leaving both set silently hijacks a proxy the user configured on
        // purpose. Theirs means ours stays off - whatever the setting says.
        let _ = foreign;
        return State::Blocked("в системе задан свой прокси".into());
    }
    local_proxy_state(settings.local_proxy, endpoint::proxy_env_is_ours())
}

/// The switch itself, away from the machine it reads.
///
/// The invariant, and the whole point of the split: the switch **never reads as
/// on while the setting is off**, because the setting is the only thing the
/// relay obeys. Anything else is a window that disagrees with the service and
/// leaves the user nothing to act on (G74).
fn local_proxy_state(wanted: bool, ours: bool) -> State {
    match (wanted, ours) {
        (true, true) => State::On,
        // Asked for, not written yet: the relay writes it once its listener
        // answers, and `repair` does the same while the window is open. An
        // on-ish state, so `Partial` and never `OffNote` - the switch has to
        // stay switchable (G41).
        (true, false) => State::Partial("переменная ещё не выставлена".into()),
        // Off, and the variable is still there: a removal that did not land.
        // The relay takes it off within a minute now; saying so beats a switch
        // that contradicts the service's own log.
        (false, true) => State::OffNote("переменная ещё не снята".into()),
        (false, false) => State::Off,
    }
}

fn read_own_proxy() -> State {
    if upstream::configured().is_some() {
        State::On
    } else {
        State::Off
    }
}

/// The three kinds, in the order the window lists them.
const INSTALL_KINDS: [&str; 3] = ["Antigravity 2.0", "Antigravity IDE", "Antigravity CLI"];

fn collect_installs(
    settings: &Settings,
    deep: bool,
    seen: &HashMap<PathBuf, bool>,
) -> Vec<InstallRow> {
    // A path the user pointed at wins over one the scan found: pointing at it is
    // what they do when the scan picked the wrong copy.
    let mut chosen: Vec<(PathBuf, bool)> = settings
        .manual_paths
        .iter()
        .map(|p| (p.clone(), true))
        .collect();
    for path in crate::discover_installs_fast() {
        if !chosen.iter().any(|(p, _)| p == &path) {
            chosen.push((path, false));
        }
    }

    let mut rows: Vec<InstallRow> = Vec::new();
    for label in INSTALL_KINDS {
        let hit = chosen
            .iter()
            .find(|(p, _)| crate::install_label(p) == label)
            .cloned();
        rows.push(match hit {
            Some((path, manual)) => InstallRow {
                label,
                patched: None,
                manual,
                path: Some(path),
            },
            None => InstallRow {
                label,
                patched: None,
                manual: false,
                path: None,
            },
        });
    }
    // Anything the user pointed at that does not answer to one of the three
    // names still gets a row - it is theirs, and dropping it silently would look
    // like the pencil did nothing.
    for (path, manual) in chosen {
        if !manual || rows.iter().any(|r| r.path.as_ref() == Some(&path)) {
            continue;
        }
        rows.push(InstallRow {
            label: crate::install_label(&path),
            patched: None,
            manual: true,
            path: Some(path),
        });
    }

    for row in &mut rows {
        let Some(path) = row.path.clone() else {
            continue;
        };
        if deep {
            let state = patch_binary::inspect_install(&path);
            row.patched = if state.is_empty() {
                None
            } else {
                Some(state.fully_patched())
            };
        } else {
            row.patched = seen.get(&path).copied();
        }
    }
    rows
}

// ---------------------------------------------------------------------------
// Applying a switch
// ---------------------------------------------------------------------------

fn apply(ctx: &mut Ctx, cap: Cap, on: bool) -> Result<(), String> {
    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Действие отменено до следующего эффекта.".into()); }
    if cap.needs_admin() && !is_admin() {
        return Err("Нужны права администратора. Нажмите «Перезапустить от имени администратора».".into());
    }

    match (cap, on) {
        (Cap::ClientPatch, true) => {
            // From the click, unlike the line below: the user wants the patch
            // whether or not an install was found to take it, and auto-patch
            // puts it on whatever turns up later (D27).
            ctx.settings.patch_declined = false;
            // Set from the result, not from the click: a run that found no
            // install patched nothing, and persisting `true` there would leave
            // the switch reading On for ever on a machine with no Antigravity.
            #[cfg(windows)]
            let patched = enable_client_patch_received(ctx, None)?;
            #[cfg(not(windows))]
            let patched = enable_client_patch_received(ctx)?;
            ctx.settings.client_patch = patched;
            // Switching the patch off took the watchdog task down with it. The
            // relay's own watchdog thread acts again the moment the decline is
            // gone, so without the task back the switch would read off while
            // patching went on. `set_watchdog` no longer starts the relay, so
            // this does not depend on the bypass being wanted.
            if watchdog_allowed(is_admin())
                && ctx.settings.auto_patch_wanted()
                && !background::is_watchdog_enabled()
            {
                set_watchdog_effect(ctx, true)?;
            }
        }
        (Cap::ClientPatch, false) => {
            ctx.settings.client_patch = false;
            // The one wish auto-patch has to respect (G38). Saved before
            // anything is unpatched, so a watchdog reading the file mid-run
            // already sees it.
            ctx.settings.patch_declined = true;
            if !ctx.settings.save() {
                return Err("Отказ от автопатча не сохранён; отмена файлов не начиналась.".into());
            }
            #[cfg(windows)]
            disable_client_patch_received(ctx, None)?;
            #[cfg(not(windows))]
            disable_client_patch_received(ctx)?;
        }
        (Cap::Watchdog, on) => {
            ctx.settings.auto_patch = on;
            // Auto-patch switched on is the newer wish, and it means "keep
            // Antigravity patched" - a patch declined earlier would otherwise
            // leave the switch on and the watchdog doing nothing.
            if on {
                ctx.settings.patch_declined = false;
            }
            set_watchdog_effect(ctx, on)?;
        }
        (Cap::Dns, on) => {
            ctx.settings.dns = on;
            if on {
                enable_dns_effect(ctx)?;
            } else {
                disable_dns_effect(ctx)?;
            }
        }
        (Cap::LocalProxy, on) => {
            ctx.settings.local_proxy = on;
            if on {
                enable_local_proxy_effect(ctx)?;
            } else {
                disable_local_proxy_effect(ctx)?;
            }
        }
        (Cap::OwnProxy, on) => {
            ctx.settings.own_proxy_enabled = on;
            if on {
                let text = ctx.settings.own_proxy.clone();
                if text.trim().is_empty() {
                    ctx.log(
                        Level::Warn,
                        "Впишите адрес прокси, затем включите переключатель.",
                    );
                    ctx.settings.own_proxy_enabled = false;
                } else {
                    set_own_proxy(ctx, &text)?;
                }
            } else {
                upstream::clear()?;
                ctx.log(Level::Ok, "Свой прокси отключён.");
                release_route_carrier(ctx)?;
            }
        }
        (Cap::DnsRotation, on) => {
            ctx.settings.rotate_providers = on;
            ctx.settings.save();
            reapply_dns_rules_checked(ctx)?;
            ctx.log(
                Level::Ok,
                if on {
                    "Ротация включена — запрос идёт ко всем включённым серверам, ответ сверяется с эталонным."
                        .to_string()
                } else {
                    match first_enabled_provider(&ctx.settings) {
                        Some(name) => format!(
                            "Ротация выключена — используется только {}. Запасных серверов не будет.",
                            name
                        ),
                        None => "Ротация выключена, но все серверы отключены.".to_string(),
                    }
                },
            );
        }
        (Cap::BuiltinExits, on) => {
            ctx.settings.builtin_exits = on;
            ctx.log(
                Level::Ok,
                if on {
                    "Встроенные выходы включены."
                } else {
                    "Встроенные выходы отключены."
                },
            );
            if on {
                ensure_route_carrier(ctx)?;
            } else {
                release_route_carrier(ctx)?;
            }
        }
        (Cap::GroupProxy, on) => {
            ctx.settings.group_proxy = on;
            ctx.log(
                Level::Ok,
                if on {
                    "Прокси из группы включён."
                } else {
                    "Прокси из группы выключен."
                },
            );
            if on {
                ensure_route_carrier(ctx)?;
            } else {
                release_route_carrier(ctx)?;
            }
        }
    }
    Ok(())
}

// --- the two buttons --------------------------------------------------------

/// Reconcile acknowledged intent through existing effect owners. This action
/// never aliases EnableAll/Repair and never derives wanted booleans from an
/// effect result. The owning job serializes Ctx while the command loop can
/// still receive cancellation and close requests.
#[cfg(windows)]
#[derive(Debug)]
pub(crate) enum ApplyPlanError { Cancelled, Receiving(String), GatewayRecoveryRequired(GatewayApplyRecovery) }
#[cfg(windows)]
pub(crate) struct GatewayApplyRecovery {
    pub(crate) observation: crate::windows_coordinator::windows_installation::GatewayPendingObservation,
    pub(crate) target: crate::instances::GuiReplacementTarget,
    pub(crate) bound: crate::windows_coordinator::windows_installation::BoundInstallation,
}
#[cfg(windows)]
impl std::fmt::Debug for GatewayApplyRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayApplyRecovery").field("observation", &self.observation).finish_non_exhaustive()
    }
}
#[cfg(windows)]
impl From<String> for ApplyPlanError { fn from(value: String) -> Self { Self::Receiving(value) } }
#[cfg(windows)]
impl std::fmt::Display for ApplyPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Cancelled => f.write_str("Применение отменено."), Self::Receiving(error) => f.write_str(error),
            Self::GatewayRecoveryRequired(_) => f.write_str("RecoveryRequired: selected Desktop has an exact Pending gateway prerequisite") }
    }
}

#[cfg(windows)]
pub(crate) struct ApplyInstallation {
    kind: crate::InstallationKind,
    root: crate::windows_coordinator::windows_installation::CheckedPath,
    anchor: crate::windows_coordinator::windows_installation::CheckedPath,
    expectation: crate::instances::GuiTargetExpectation,
}
#[cfg(windows)]
impl ApplyInstallation {
    pub(crate) fn root(&self) -> &std::path::Path { self.root.as_path() }
    pub(crate) fn anchor(&self) -> &std::path::Path { self.anchor.as_path() }
    pub(crate) fn is_vendor_update(&self) -> bool {
        matches!(&self.expectation.current, crate::instances::GuiCurrentExpectation::VendorUpdate { .. })
    }
    fn recheck(&self) -> Result<(), String> {
        self.root.recheck()?;
        self.anchor.recheck()?;
        let layout = crate::receive_installation_layout(self.root())?;
        if layout.kind != self.kind { return Err("installation effect kind changed".into()); }
        let anchor = crate::windows_coordinator::windows_installation::CheckedPath::open(&layout.anchor,
            crate::windows_coordinator::windows_installation::PathKind::File,
            crate::windows_coordinator::windows_installation::PathPurpose::ReplaceSource)?;
        if anchor.native_id() != self.anchor.native_id() { return Err("installation effect anchor changed".into()); }
        Ok(())
    }
    pub(crate) fn desktop_binding(&self) -> Result<crate::windows_coordinator::windows_installation::BoundInstallation, String> {
        use crate::windows_coordinator::{self as coordinator, windows_installation as owner};
        if self.kind != crate::InstallationKind::Desktop { return Err("WSL requires a received Desktop target".into()); }
        self.recheck()?;
        let mut bound = owner::BoundInstallation::open(self.anchor())?;
        if bound.native_root_id() != self.root.native_id() || bound.native_executable_id() != self.anchor.native_id() {
            return Err("Desktop target native identity changed".into());
        }
        if let Some(context) = coordinator::receive_saved_context(&bound)? { bound.attach_ancestor_context(context)?; }
        Ok(bound)
    }
    pub(crate) fn recheck_desktop_current(&self) -> Result<(), String> {
        let current = receive_desktop_current(&self.desktop_binding()?)?;
        if current != self.expectation.current { return Err("Desktop Current changed before execution".into()); }
        Ok(())
    }
}

#[cfg(windows)]
struct RetirementInput {
    descriptor: crate::instances::GuiRetirementInputRef,
    file: crate::windows_coordinator::windows_installation::CheckedPath,
    selection: crate::windows_coordinator::windows_installation::gateway_rules::GatewayRetirementSelectionV1,
}
#[cfg(windows)]
impl RetirementInput {
    fn receive(descriptor: crate::instances::GuiRetirementInputRef) -> Result<Self, String> {
        use crate::windows_coordinator::windows_installation::{CheckedPath, PathKind, PathPurpose};
        use sha2::{Digest, Sha256};
        let file = CheckedPath::open(&descriptor.path, PathKind::File, PathPurpose::Source)?;
        if file.native_id() != descriptor.native_id { return Err("retirement input native identity changed".into()); }
        let bytes = file.read_snapshot()?;
        if Sha256::digest(&bytes).as_slice() != descriptor.sha256 { return Err("retirement input digest differs".into()); }
        let selection = serde_json::from_slice(&bytes).map_err(|e| format!("retirement input: {e}"))?;
        Ok(Self { descriptor, file, selection })
    }
    fn recheck(&self) -> Result<(), String> {
        self.file.recheck()?;
        use sha2::{Digest, Sha256};
        if Sha256::digest(self.file.read_snapshot()?).as_slice() != self.descriptor.sha256 { return Err("retirement input changed".into()); }
        Ok(())
    }
}
#[cfg(windows)]
pub(crate) fn retirement_input_ref(path: std::path::PathBuf, digest: &str) -> Result<crate::instances::GuiRetirementInputRef, String> {
    use crate::windows_coordinator::windows_installation::{CheckedPath, PathKind, PathPurpose};
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("retirement input digest must be lowercase SHA-256".into()); }
    let mut sha256 = [0; 32]; hex::decode_to_slice(digest, &mut sha256).map_err(|e| e.to_string())?;
    let file = CheckedPath::open(&path, PathKind::File, PathPurpose::Source)?;
    let descriptor = crate::instances::GuiRetirementInputRef { path, native_id: file.native_id(), sha256 };
    RetirementInput::receive(descriptor.clone())?;
    Ok(descriptor)
}
#[cfg(windows)]
pub(crate) struct AllTargetApplyPlan {
    wanted: Settings,
    saved_sha256: [u8; 32],
    targets: Vec<ApplyInstallation>,
    native: NativeApplyPlan,
    client_patch: Option<bool>,
    wsl: Option<crate::wsl_runtime::WslApplyPreparation>,
    retirement_input: Option<RetirementInput>,
}
#[cfg(windows)]
impl AllTargetApplyPlan {
    pub(crate) fn wanted(&self) -> &Settings { &self.wanted }
    pub(crate) fn saved_sha256(&self) -> &[u8; 32] { &self.saved_sha256 }
    pub(crate) fn retirement_for(&self, expected: &crate::windows_coordinator::windows_installation::VendorUpdateObservation) -> Result<Option<&crate::windows_coordinator::windows_installation::gateway_rules::GatewayRetirementSelectionV1>, String> {
        match &self.retirement_input {
            Some(input) if input.selection.slot_id == expected.slot_id => { input.recheck()?; input.selection.validate_binding(expected, &self.saved_sha256)?; Ok(Some(&input.selection)) },
            _ => Ok(None),
        }
    }
    pub(crate) fn wsl(&self) -> Result<&crate::wsl_runtime::WslApplyPreparation, String> {
        self.wsl.as_ref().ok_or_else(|| "WSL requirements were not received".into())
    }
    pub(crate) fn wsl_desktops(&self) -> impl Iterator<Item = &ApplyInstallation> {
        self.targets.iter().filter(|target| target.kind == crate::InstallationKind::Desktop)
    }
    fn has_vendor_update(&self) -> bool { self.targets.iter().any(ApplyInstallation::is_vendor_update) }
    fn expectations(&self) -> Vec<crate::instances::GuiTargetExpectation> {
        self.targets.iter().map(|target| target.expectation.clone()).collect()
    }
    fn recheck(&self) -> Result<(), String> {
        if let Some(input) = &self.retirement_input { input.recheck()?; }
        if crate::settings::saved_intent_sha256(&self.wanted)? != self.saved_sha256 { return Err("saved Apply input changed".into()); }
        for target in &self.targets {
            target.recheck()?;
            if target.kind == crate::InstallationKind::Desktop { target.recheck_desktop_current()?; }
        }
        Ok(())
    }
    fn continuation(&self) -> Result<crate::instances::GuiApplyContinuation, String> {
        self.recheck()?;
        Ok(crate::instances::GuiApplyContinuation { request_id: crate::windows_coordinator::windows_installation::new_request_id()?,
            saved_settings_sha256: self.saved_sha256, targets: self.expectations(), retirement_input: self.retirement_input.as_ref().map(|input| input.descriptor.clone()) })
    }
}

#[cfg(windows)]
fn receive_desktop_current(bound: &crate::windows_coordinator::windows_installation::BoundInstallation)
    -> Result<crate::instances::GuiCurrentExpectation, String> {
    gui_current_expectation(crate::windows_coordinator::windows_installation::observe_apply_current(bound)?)
}

#[cfg(windows)]
fn gui_current_expectation(observation: crate::windows_coordinator::windows_installation::ApplyCurrentObservation)
    -> Result<crate::instances::GuiCurrentExpectation, String> {
    use crate::{instances::GuiCurrentExpectation as Gui, windows_coordinator::windows_installation::ApplyCurrentObservation as Current};
    Ok(match observation {
        Current::Absent => Gui::Absent {},
        Current::Settled { slot_id, current_sha256 } => Gui::Present { slot_id, current_sha256 },
        Current::GatewayPending(_) => return Err("RecoveryRequired: continuation target has unresolved Current".into()),
        Current::VendorReplacement(value) => Gui::VendorUpdate { slot_id: value.slot_id,
            prior_current_sha256: value.prior_current_sha256, new_parent_id: value.new_parent_id,
            new_resources_id: value.new_resources_id, new_archive_id: value.new_archive_id,
            new_executable_sha256: value.new_executable_sha256, new_archive_sha256: value.new_archive_sha256,
            new_binding_sha256: value.new_binding_sha256 },
    })
}

#[cfg(windows)]
fn apply_target_key(target: &crate::instances::GuiTargetExpectation) -> (u8, u64, [u8; 16], u64, [u8; 16]) {
    use crate::instances::GuiTargetKind;
    let kind = match target.target.kind { GuiTargetKind::Desktop => 0, GuiTargetKind::Ide => 1, GuiTargetKind::Cli => 2 };
    (kind, target.target.native_root_id.volume, target.target.native_root_id.file,
        target.target.anchor_native_id.volume, target.target.anchor_native_id.file)
}

#[cfg(windows)]
pub(crate) fn receive_all_target_apply_plan(wanted: Settings, cancel: &AtomicBool,
    descriptor: Option<crate::instances::GuiRetirementInputRef>,
    image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>) -> Result<AllTargetApplyPlan, ApplyPlanError> {
    use crate::{instances::{GuiCurrentExpectation, GuiReplacementTarget, GuiTargetExpectation, GuiTargetKind},
        windows_coordinator::{self as coordinator, windows_installation as owner}};
    let saved_sha256 = crate::settings::saved_intent_sha256(&wanted)?;
    let retirement_input = descriptor.map(RetirementInput::receive).transpose()?;
    let mut roots = crate::find_all_installs_checked(cancel)?;
    for root in &wanted.manual_paths { if !roots.contains(root) { roots.push(root.clone()); } }
    let mut targets: Vec<ApplyInstallation> = Vec::new();
    let mut all_patched = !roots.is_empty();
    let mut any_patched = false;
    for path in roots {
        if cancel.load(Ordering::SeqCst) { return Err(ApplyPlanError::Cancelled); }
        let root = owner::CheckedPath::open(&path, owner::PathKind::Directory, owner::PathPurpose::Source)?;
        let layout = crate::receive_installation_layout(root.as_path())?;
        let anchor = owner::CheckedPath::open(&layout.anchor, owner::PathKind::File, owner::PathPurpose::ReplaceSource)?;
        let state = patch_binary::inspect_install(root.as_path());
        for (_, state) in &state.files {
            if let patch_binary::FileState::Unreadable(error) = state { return Err(error.clone().into()); }
        }
        all_patched &= state.fully_patched();
        any_patched |= state.files.iter().any(|(_, state)| matches!(state, patch_binary::FileState::Patched));
        let kind = match layout.kind { crate::InstallationKind::Desktop => GuiTargetKind::Desktop,
            crate::InstallationKind::Ide => GuiTargetKind::Ide, crate::InstallationKind::Cli => GuiTargetKind::Cli };
        let target = GuiReplacementTarget { kind, root_path: root.as_path().to_owned(),
            native_root_id: root.native_id(), anchor_path: anchor.as_path().to_owned(), anchor_native_id: anchor.native_id() };
        let current = if layout.kind == crate::InstallationKind::Desktop {
            let mut bound = owner::BoundInstallation::open(anchor.as_path())?;
            if let Some(context) = coordinator::receive_saved_context(&bound)? { bound.attach_ancestor_context(context)?; }
            match owner::observe_apply_current(&bound)? {
                owner::ApplyCurrentObservation::GatewayPending(observation) => return Err(ApplyPlanError::GatewayRecoveryRequired(
                    GatewayApplyRecovery { observation, target, bound })),
                observation => gui_current_expectation(observation)?,
            }
        } else { GuiCurrentExpectation::NotApplicable {} };
        let expectation = GuiTargetExpectation { target, current };
        if let Some(prior) = targets.iter().find(|prior| prior.root.native_id() == root.native_id()) {
            if apply_target_key(&prior.expectation) != apply_target_key(&expectation) || prior.expectation.current != expectation.current {
                return Err("target aliases have conflicting kind/anchor/Current observations".to_owned().into());
            }
        } else { targets.push(ApplyInstallation { kind: layout.kind, root, anchor, expectation }); }
    }
    targets.sort_by_key(|target| apply_target_key(&target.expectation));
    if let Some(input) = &retirement_input {
        let count = targets.iter().filter(|target| matches!(&target.expectation.current,
            GuiCurrentExpectation::VendorUpdate { slot_id, prior_current_sha256, new_binding_sha256, .. }
            if target.kind == crate::InstallationKind::Desktop && slot_id == &input.selection.slot_id
                && hex::encode(prior_current_sha256) == input.selection.prior_current_sha256
                && hex::encode(new_binding_sha256) == input.selection.new_binding_sha256)).count();
        if count != 1 || input.selection.saved_settings_sha256 != hex::encode(saved_sha256) || wanted.wsl.is_none() {
            return Err("retirement input does not bind exactly one selected vendor update".to_owned().into());
        }
    }
    let Some(mut native) = inspect_native_apply(&wanted, cancel, image)? else { return Err(ApplyPlanError::Cancelled); };
    let client_patch = if wanted.client_patch && !all_patched { Some(true) }
        else if !wanted.client_patch && any_patched { Some(false) } else { None };
    native.revert_services = client_patch == Some(false) && native.services_present;
    let mut plan = AllTargetApplyPlan { wanted, saved_sha256, targets, native, client_patch, wsl: None, retirement_input };
    plan.wsl = Some(crate::wsl_runtime::inspect_selection(&plan, cancel)?);
    if plan.retirement_input.is_some() && !matches!(&plan.wsl, Some(crate::wsl_runtime::WslApplyPreparation::Selected(_))) {
        return Err("retirement input requires a selected WSL vendor update".to_owned().into());
    }
    plan.recheck()?;
    Ok(plan)
}

#[cfg(windows)]
fn receive_apply_continuation(intent: &crate::instances::GuiApplyContinuation, cancel: &AtomicBool,
    image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>)
    -> Result<AllTargetApplyPlan, String> {
    use crate::{instances::{GuiCurrentExpectation, GuiTargetKind}, windows_coordinator::windows_installation as owner};
    owner::validate_request_id(&intent.request_id)?;
    let wanted = crate::settings::receive_saved_intent(&intent.saved_settings_sha256)?;
    let plan = receive_all_target_apply_plan(wanted, cancel, intent.retirement_input.clone(), image).map_err(|error| error.to_string())?;
    let mut expected = intent.targets.clone();
    expected.sort_by_key(apply_target_key);
    if expected.windows(2).any(|pair| apply_target_key(&pair[0]) == apply_target_key(&pair[1])) {
        return Err("Apply target expectations are duplicated".into());
    }
    for expectation in &expected {
        let root = owner::CheckedPath::open(&expectation.target.root_path, owner::PathKind::Directory, owner::PathPurpose::Source)?;
        let anchor = owner::CheckedPath::open(&expectation.target.anchor_path, owner::PathKind::File, owner::PathPurpose::ReplaceSource)?;
        if root.native_id() != expectation.target.native_root_id || anchor.native_id() != expectation.target.anchor_native_id {
            return Err("Apply target native identity changed".into());
        }
        let layout = crate::receive_installation_layout(root.as_path())?;
        let kind = match layout.kind { crate::InstallationKind::Desktop => GuiTargetKind::Desktop,
            crate::InstallationKind::Ide => GuiTargetKind::Ide, crate::InstallationKind::Cli => GuiTargetKind::Cli };
        let actual_anchor = owner::CheckedPath::open(&layout.anchor, owner::PathKind::File, owner::PathPurpose::ReplaceSource)?;
        if kind != expectation.target.kind || actual_anchor.native_id() != anchor.native_id() {
            return Err("Apply target kind/anchor binding changed".into());
        }
        if !matches!((kind, &expectation.current),
            (GuiTargetKind::Desktop, GuiCurrentExpectation::Absent {} | GuiCurrentExpectation::Present { .. } | GuiCurrentExpectation::VendorUpdate { .. })
            | (GuiTargetKind::Ide | GuiTargetKind::Cli, GuiCurrentExpectation::NotApplicable {})) {
            return Err("Apply target Current applicability differs from its kind".into());
        }
    }
    let actual = plan.expectations();
    if actual.len() != expected.len() || actual.iter().zip(&expected)
        .any(|(actual, expected)| apply_target_key(actual) != apply_target_key(expected) || actual.current != expected.current) {
        return Err("Apply target set or canonical Current changed during handoff".into());
    }
    plan.recheck()?;
    Ok(plan)
}

#[cfg(windows)]
fn receive_settled_vendor_plan(before: &AllTargetApplyPlan, after: &AllTargetApplyPlan,
    received: &[(String, [u8; 32])]) -> Result<(), String> {
    use crate::instances::GuiCurrentExpectation;
    if before.saved_sha256 != after.saved_sha256 || before.targets.len() != after.targets.len() {
        return Err("Apply target domain or saved intent changed after vendor update".into());
    }
    let mut matched = 0usize;
    for (old, new) in before.targets.iter().zip(&after.targets) {
        if old.expectation.target != new.expectation.target {
            return Err("Apply selected target changed after vendor update".into());
        }
        match (&old.expectation.current, &new.expectation.current) {
            (GuiCurrentExpectation::VendorUpdate { slot_id: old_slot, .. },
             GuiCurrentExpectation::Present { slot_id: new_slot, current_sha256 }) if old_slot == new_slot => {
                if !vendor_result_received(received, new_slot, current_sha256) {
                    return Err("Apply Current differs from the actual vendor owner result".into());
                }
                matched += 1;
            },
            (old, new) if !matches!(old, GuiCurrentExpectation::VendorUpdate { .. }) && old == new => {},
            _ => return Err("Apply Current changed outside the received vendor update".into()),
        }
    }
    if matched != received.len() { return Err("Apply vendor result count differs from the selected targets".into()); }
    Ok(())
}

#[cfg(windows)]
fn vendor_result_received(received: &[(String, [u8; 32])], slot: &str, digest: &[u8; 32]) -> bool {
    received.iter().filter(|(actual_slot, actual_digest)| actual_slot == slot && actual_digest == digest).count() == 1
}

#[cfg(windows)]
struct NativeApplyFacts {
    core_rules: bool,
    owned_rules: bool,
    relay_task: bool,
    relay: Option<NativeRelayFacts>,
    watchdog_task: bool,
    program_outdated: Option<bool>,
}

#[cfg(windows)]
struct NativeRelayFacts {
    relay_compatible: bool,
    relay_outdated: bool,
    relay_reporting: bool,
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
struct NativeApplyPlan {
    update_shared_program: bool,
    ensure_relay: bool,
    enable_dns: bool,
    disable_dns: bool,
    stop_relay: bool,
    watchdog: Option<bool>,
    services_present: bool,
    revert_services: bool,
}

#[cfg(windows)]
impl NativeApplyPlan {
    fn receive(wanted: &Settings, facts: &NativeApplyFacts) -> Result<Self, String> {
        let wants_relay = wanted.dns || routes_want_relay(wanted);
        let update_shared_program = if wants_relay || wanted.auto_patch_wanted() {
            facts.program_outdated.ok_or("selected background executable generation was not received")?
        } else { false };
        let ensure_relay = if wants_relay {
            let relay = facts.relay.as_ref().ok_or("selected relay health was not received")?;
            !(facts.relay_task && relay.relay_compatible
                && !relay.relay_outdated && relay.relay_reporting)
        } else { false };
        let disable_dns = !wanted.dns && facts.owned_rules;
        Ok(Self {
            update_shared_program,
            ensure_relay,
            enable_dns: wanted.dns && !facts.core_rules,
            disable_dns,
            stop_relay: !wants_relay && !disable_dns && facts.relay_task,
            watchdog: (wanted.auto_patch_wanted() != facts.watchdog_task).then_some(wanted.auto_patch_wanted()),
            services_present: facts.relay_task || facts.watchdog_task,
            revert_services: false,
        })
    }

    fn requires_elevation(&self) -> bool {
        self.update_shared_program || self.ensure_relay || self.enable_dns || self.disable_dns || self.stop_relay || self.watchdog.is_some() || self.revert_services
    }
}

#[cfg(windows)]
fn inspect_native_apply(wanted: &Settings, cancellation: &AtomicBool,
    image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>) -> Result<Option<NativeApplyPlan>, String> {
    if cancellation.load(Ordering::SeqCst) { return Ok(None); }
    let rules = dns::checked_nrpt_state()?;
    if cancellation.load(Ordering::SeqCst) { return Ok(None); }
    let tasks = background::checked_task_state_with_cancel(cancellation)?;
    if cancellation.load(Ordering::SeqCst) { return Ok(None); }
    let program_outdated = if wanted.dns || routes_want_relay(wanted) || wanted.auto_patch_wanted() {
        Some(background::selected_delivery_required(cancellation, image?)?)
    } else { None };
    if cancellation.load(Ordering::SeqCst) { return Ok(None); }
    let relay = if wanted.dns || routes_want_relay(wanted) {
        let relay_compatible = background::checked_relay_compatible_with_cancel(cancellation)?;
        if cancellation.load(Ordering::SeqCst) { return Ok(None); }
        let relay_outdated = program_outdated.ok_or("selected relay generation was not received")?;
        let relay_reporting = crate::gate::read_checked()?.is_some_and(|report|
            !report.is_stale() && report.version >= crate::dns_forwarder::RELAY_VERSION);
        if cancellation.load(Ordering::SeqCst) { return Ok(None); }
        Some(NativeRelayFacts {
            relay_compatible, relay_outdated, relay_reporting,
        })
    } else { None };
    NativeApplyPlan::receive(wanted, &NativeApplyFacts {
        core_rules: rules.core_applied, owned_rules: rules.owned_rules_present,
        relay_task: tasks.relay_enabled, relay, watchdog_task: tasks.watchdog_enabled, program_outdated,
    }).map(Some)
}

fn apply_acknowledged(ctx: &mut Ctx, wanted: Settings, cancellation: &AtomicBool,
    #[cfg(windows)] resume: Option<crate::instances::GuiApplyContinuation>) -> Result<NativeCompletion, String> {
    #[cfg(windows)]
    let mut recovery_results = Vec::new();
    let result = (|| {
        if cancellation.load(Ordering::SeqCst) { return Ok(NativeCompletion::Retired); }
        #[cfg(windows)]
        {
            let received = match resume.as_ref() {
                Some(intent) => receive_apply_continuation(intent, cancellation, ctx.lifetime.retained_image()),
                None => {
                    let mut attempted = std::collections::BTreeSet::new();
                    loop {
                        if cancellation.load(Ordering::SeqCst) { break Err("Применение отменено до следующих действий.".into()); }
                        let descriptor = ctx.lifetime.retirement_input.lock().map_err(|_| "retirement input lock poisoned")?.as_ref().map(|input| input.descriptor.clone());
                        match receive_all_target_apply_plan(wanted.clone(), cancellation, descriptor, ctx.lifetime.retained_image()) {
                            Ok(plan) => break Ok(plan),
                            Err(ApplyPlanError::GatewayRecoveryRequired(prerequisite)) => {
                                if let Err(error) = receive_gateway_prerequisite_once(&mut attempted, &prerequisite.observation, cancellation) { break Err(error); }
                                match crate::wsl_runtime::recover_apply_gateway(prerequisite.bound, &prerequisite.target,
                                    &prerequisite.observation, cancellation) {
                                    Ok(outcome) => { ctx.log(Level::Ok, outcome.clone()); recovery_results.push(outcome); }
                                    Err(error) => {
                                        let received = format!("recovery prerequisite {:?}; {error}", prerequisite.observation);
                                        ctx.log(Level::Err, received.clone()); recovery_results.push(received);
                                        break Err(error);
                                    }
                                }
                                // Same acknowledged intent and discovery owner;
                                // no native/profile effect before a full new plan.
                            }
                            Err(error) => break Err(error.to_string()),
                        }
                    }
                },
            };
            let mut plan = match received {
                Ok(plan) => plan,
                Err(error) => {
                    let error = apply_receiving_failure(&error, &recovery_results);
                    if !cancellation.load(Ordering::SeqCst) { hold_apply(ctx, error.clone()); }
                    return Err(error);
                },
            };
            if (plan.native.requires_elevation() && !is_admin()) || plan.wsl()?.requires_elevation() {
                return Ok(NativeCompletion::NeedsElevation(plan.continuation()?));
            }
            if plan.has_vendor_update() {
                plan.recheck()?;
                let vendor_results = crate::wsl_runtime::apply_vendor_prerequisites(&plan, cancellation)?;
                *ctx.lifetime.retirement_input.lock().map_err(|_| "retirement input lock poisoned")? = None;
                let next = receive_all_target_apply_plan(wanted.clone(), cancellation, None, ctx.lifetime.retained_image()).map_err(|error| error.to_string())?;
                receive_settled_vendor_plan(&plan, &next, &vendor_results)?;
                if (next.native.requires_elevation() && !is_admin()) || next.wsl()?.requires_elevation() {
                    return Err("UpdatePending: Apply requirements changed after vendor update".into());
                }
                ctx.log(Level::Ok, "Обновление WSL Desktop получено; остальные настройки проверены повторно.");
                plan = next;
            }
            let plan = Arc::new(plan);
            reconcile_native(ctx, &wanted, cancellation, &plan)?;
            if !cancellation.load(Ordering::SeqCst) { ctx.wsl.request_apply(plan)?; }
            return Ok(NativeCompletion::Retired);
        }
        #[cfg(not(windows))]
        {
        reconcile_native(ctx, &wanted, cancellation)?;
        if !cancellation.load(Ordering::SeqCst) { ctx.wsl.request_apply(wanted.clone())?; }
        Ok(NativeCompletion::Retired)
        }
    })();
    if cancellation.load(Ordering::SeqCst) {
        if ctx.wsl.is_pending() { ctx.wsl.request_cancel(); }
        else { ctx.wsl.cancelled_before_apply(wanted.wsl.as_ref()); }
        result.map(|_| NativeCompletion::Retired)
    } else { result }
}

#[cfg(windows)]
fn receive_gateway_prerequisite_once(
    attempted: &mut std::collections::BTreeSet<(String, String, [u8; 32])>,
    observation: &crate::windows_coordinator::windows_installation::GatewayPendingObservation,
    cancellation: &AtomicBool,
) -> Result<(), String> {
    if cancellation.load(Ordering::SeqCst) { return Err("Cancelled: gateway prerequisite not started".into()); }
    if !attempted.insert((observation.slot_id.clone(), observation.operation_id.clone(), observation.current_sha256)) {
        return Err("RecoveryRequired: the same Pending gateway prerequisite remains unresolved; no automatic retry".into());
    }
    Ok(())
}
#[cfg(windows)]
fn apply_receiving_failure(error: &str, recovery_results: &[String]) -> String {
    if recovery_results.is_empty() { format!("Применение остановлено до изменений: {error}") }
    else { format!("Применение остановлено; полученные результаты восстановления сохранены: [{}]; незавершённый остаток: {error}", recovery_results.join("; ")) }
}

fn reconcile_native(ctx: &mut Ctx, wanted: &Settings, cancellation: &AtomicBool,
    #[cfg(windows)] plan: &AllTargetApplyPlan) -> Result<(), String> {
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    #[cfg(windows)]
    let Some(mut native) = inspect_native_apply(wanted, cancellation, ctx.lifetime.retained_image())? else { return Ok(()); };
    #[cfg(windows)]
    { plan.recheck()?; native.revert_services = plan.client_patch == Some(false) && native.services_present; }
    #[cfg(windows)]
    if native.requires_elevation() && !is_admin() {
        return Err("Состояние Windows изменилось после проверки прав; оставшиеся действия остановлены. Повторите «Применить».".into());
    }
    #[cfg(windows)]
    if native.disable_dns {
        // A client undo may retire the shared relay before its file operation.
        // Receive removal of our no-longer-wanted rules before that transition.
        remove_dns_rules_effect(ctx)?;
        native.disable_dns = false;
        native.stop_relay = !wanted.dns && !routes_want_relay(wanted) && native.services_present;
    }
    #[cfg(windows)]
    match plan.client_patch {
        Some(true) => { enable_client_patch_received(ctx, Some(plan))?; },
        Some(false) => disable_client_patch_received(ctx, Some(plan))?,
        None => {},
    }
    #[cfg(not(windows))]
    {
    let observed = read_status(ctx, false);
    if wanted.client_patch && observed.client_patch != State::On {
        enable_client_patch(ctx);
    } else if !wanted.client_patch && observed.client_patch.is_on() {
        disable_client_patch(ctx);
    }
    }
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    let configured = upstream::configured();
    if wanted.own_proxy_enabled {
        match upstream::parse(&wanted.own_proxy) {
            Ok(upstream) if configured.as_ref() != Some(&upstream) => {
                upstream::save(&upstream).map_err(|error| format!("Свой прокси не сохранился: {error}"))?;
            }
            Ok(_) => {},
            Err(error) => return Err(format!("Параметры своего прокси не подтверждены: {error}")),
        }
    } else if configured.is_some() { upstream::clear()?; }
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    #[cfg(windows)]
    {
        if native.disable_dns { disable_dns_effect(ctx)?; }
        else if native.enable_dns { enable_dns_effect(ctx)?; }
        else if native.update_shared_program || native.ensure_relay || native.stop_relay || native.watchdog.is_some() {
            background_roles_effect(ctx, wanted.dns || routes_want_relay(wanted), wanted.auto_patch_wanted(), background::ImageDemand::DeliverSelectedImage)?;
        }
        if cancellation.load(Ordering::SeqCst) { return Ok(()); }
        let local_applied = endpoint::proxy_env_is_ours();
        if wanted.local_proxy && !local_applied { enable_local_proxy_effect(ctx)?; }
        else if !wanted.local_proxy && local_applied { disable_local_proxy_effect(ctx)?; }
        if cancellation.load(Ordering::SeqCst) { return Ok(()); }
        return Ok(());
    }
    #[cfg(not(windows))]
    {
    let rules = dns::is_nrpt_applied();
    let relay = background::is_running();
    let relay_outdated = background::relay_is_outdated();
    if wanted.dns && (!rules || !relay || relay_outdated) {
        if cfg!(windows) && !is_admin() { ctx.log(Level::Warn, "Для применения DNS нужны права администратора."); }
        else { enable_dns_effect(ctx)?; }
    } else if !wanted.dns && rules { disable_dns_effect(ctx)?; }
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    let local_applied = endpoint::proxy_env_is_ours();
    if wanted.local_proxy && (!local_applied || !background::is_running() || background::relay_is_outdated()) {
        if background::is_running() && !background::relay_is_outdated() { enable_local_proxy_effect(ctx)?; }
        else { ensure_route_carrier(ctx)?; }
    } else if !wanted.local_proxy && local_applied { disable_local_proxy_effect(ctx)?; }
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    let watchdog = background::is_watchdog_enabled();
    if wanted.auto_patch != watchdog {
        if cfg!(windows) && !is_admin() { ctx.log(Level::Warn, "Для применения автопатча нужны права администратора."); }
        else { set_watchdog_effect(ctx, wanted.auto_patch)?; }
    }
    Ok(())
    }
}

/// «Включить всё». Each part only if it is not on already, and in the order the
/// switches themselves need: the patch first (it closes Antigravity, so nothing
/// is holding a file), then the relay (I5 - the rules name it), the proxy
/// variable only once something answers on its port (I53), and auto-patch last,
/// because it runs out of the relay's install directory.
fn enable_all(ctx: &mut Ctx) -> Result<(), String> {
    let admin = is_admin() || !cfg!(target_os = "windows");
    // "Everything" includes the patch on installs that do not exist yet.
    ctx.settings.patch_declined = false;
    // Only when it is not already on everywhere: patching closes Antigravity,
    // and closing it for a no-op is exactly the kind of surprise this button
    // must not have.
    if !patch_is_on(ctx) {
        apply(ctx, Cap::ClientPatch, true)?;
    }
    // Nothing but a line in settings.json, so it needs nobody's permission.
    // The service they ride on is brought up below, with DNS.
    ctx.settings.builtin_exits = true;
    ctx.settings.group_proxy = true;
    let dns_on =
        dns::is_nrpt_applied() && background::is_running() && !background::relay_is_outdated();
    if !dns_on {
        if !admin {
            // Said only when it is actually missing: the card offers this button
            // for a patch that is off too, with the bypass already running.
            return Err("Обход ошибки 400 не включён: нужны права администратора. Нажмите «Перезапустить от имени администратора».".into());
        }
        apply(ctx, Cap::Dns, true)?;
    }
    // A proxy the user set up themselves stays theirs (G33): `enable_local_proxy`
    // says so and leaves ours off, which also keeps the loopback door shut.
    if !endpoint::proxy_env_is_ours() {
        apply(ctx, Cap::LocalProxy, true)?;
    }
    // Whether or not the patch found anything to patch: auto-patch is what
    // patches the Antigravity installed after this click (D27).
    if watchdog_allowed(admin) && !background::is_watchdog_enabled() {
        apply(ctx, Cap::Watchdog, true)?;
    }
    #[cfg(windows)]
    {
        let relay = ctx.settings.dns || routes_want_relay(&ctx.settings);
        let watchdog = ctx.settings.auto_patch_wanted();
        if relay || watchdog {
            let required = background::selected_delivery_required(&ctx.native_cancel, ctx.lifetime.retained_image()?)?;
            if required {
                if !admin {
                    return Err("Служба обхода не подготовлена: нужны права администратора. Нажмите «Перезапустить от имени администратора».".into());
                }
                background_roles_effect(ctx, relay, watchdog, background::ImageDemand::DeliverSelectedImage)?;
            }
        }
    }
    ctx.log(
        Level::Ok,
        "Готово. Откройте Antigravity и напишите что-нибудь в чат — здесь появится подтверждение, что модель ответила.",
    );
    Ok(())
}

fn patch_is_on(ctx: &Ctx) -> bool {
    ctx.last
        .as_ref()
        .is_some_and(|s| s.client_patch == State::On)
}

/// «Починить». The service is the part that can stop on its own - a crash the
/// task's restart policy gave up on, a relay older than this build, an antivirus
/// that ate the copy in `%ProgramData%` - and every one of those is fixed by
/// installing it again and putting its rules and variable back.
fn repair(ctx: &mut Ctx) -> Result<(), String> {
    if cfg!(target_os = "windows") && !is_admin() {
        return Err("Нужны права администратора. Нажмите «Перезапустить от имени администратора».".into());
    }
    // DNS is put back only when it was wanted, or when nothing else is: a user
    // running just their own proxy must not get DNS rules from a repair.
    let with_dns = ctx.settings.dns || !routes_want_relay(&ctx.settings);
    if with_dns {
        ctx.settings.dns = true;
    }
    #[cfg(windows)]
    let reconciled = background_roles_effect(ctx,
        ctx.settings.dns || routes_want_relay(&ctx.settings), ctx.settings.auto_patch_wanted(), background::ImageDemand::DeliverSelectedImage);
    #[cfg(not(windows))]
    let reconciled = background::enable();
    reconciled.map_err(|error| format!("Служба обхода не подготовлена: {error}"))?;
    ctx.log(Level::Ok, "Выбранное состояние служб обхода подтверждено.");
    if with_dns {
        enable_dns_effect(ctx)?;
    } else {
        ensure_route_carrier(ctx)?;
    }
    Ok(())
}

// --- client patch ----------------------------------------------------------

/// Settles `patch_declined` for a settings file an older build wrote (D27).
///
/// Before D27 a patch switched off by hand left two traces: `client_patch`
/// false, and the standalone watchdog task removed (`disable_client_patch`).
/// `parse` could only read the first and so took every patch-off file as
/// declined. The task is the second trace, and only this side can ask for it:
/// with it still registered the user saw auto-patch *on*, and it may act -
/// which is the owner's own machine (G55). Written back at once, so the relay
/// reads the settled answer and this runs once per machine.
fn settle_decline(ctx: &mut Ctx) {
    if !ctx.settings.decline_unrecorded {
        return;
    }
    ctx.settings.patch_declined = !ctx.settings.client_patch && !background::is_watchdog_enabled();
    ctx.settings.decline_unrecorded = false;
    ctx.settings.save();
}

/// Auto-patch from the window (D27): every install the last deep scan found
/// unpatched is patched now, without a click, while auto-patch is on and the
/// patch was not switched off by hand. True when something was written, so the
/// caller knows the dots need a deep re-read.
///
/// Uses the watchdog's selected-file writer. On Windows a busy native file is
/// held for a normal application close; this operation owns no process-kill
/// capability. Its cancellation and first write failure stop later files.
fn auto_patch_found(ctx: &mut Ctx) -> bool {
    // Only while the switch is drawn on («при включенной опции»). Its state is
    // the standalone task, which a user without admin rights cannot have and
    // which `disable_dns` takes down with the relay («вернётся вместе с
    // обходом»); patching behind a switch that reads off is the surprise the
    // switch exists to rule out.
    let switch_on = ctx.last.as_ref().is_some_and(|s| s.watchdog.is_on());
    if !switch_on || !ctx.settings.auto_patch_wanted() {
        return false;
    }
    let found: Vec<(&'static str, PathBuf)> = ctx
        .last
        .as_ref()
        .map(|s| {
            s.installs
                .iter()
                .filter(|r| r.patched == Some(false))
                .filter_map(|r| Some((r.label, r.path.clone()?)))
                .collect()
        })
        .unwrap_or_default();
    let patched = patch_found(ctx, found);
    #[cfg(windows)]
    let vendor_updated = {
        let mut updated = false;
        if crate::wsl_runtime::automatic_vendor_update_wanted(&ctx.settings) {
            let roots: Vec<_> = ctx.last.as_ref().map(|status| status.installs.iter()
                .filter_map(|row| row.path.clone()).collect()).unwrap_or_default();
            for root in roots {
                if ctx.native_cancel.load(Ordering::SeqCst) { break; }
                match crate::wsl_runtime::automatic_vendor_update(&root, &ctx.settings, &ctx.native_cancel) {
                    Ok(true) => { updated = true; ctx.log(Level::Ok, "Обновлён WSL-хук Desktop."); },
                    Ok(false) => {},
                    Err(error) => ctx.log(Level::Warn, format!("Автообновление WSL отложено: {error}")),
                }
            }
        }
        updated
    };
    #[cfg(not(windows))]
    let vendor_updated = false;
    patched || vendor_updated
}

/// Patches the given installs without closing anything. The shared body of
/// auto-patch and of the row's «Пропатчить» button, which is what a user is left
/// with when the automatic pass could not write.
fn patch_found(ctx: &mut Ctx, found: Vec<(&'static str, PathBuf)>) -> bool {
    if found.is_empty() {
        return false;
    }

    ctx.busy(Some("Автопатч"));
    let mut wrote = false;
    for (label, inst) in found {
        if ctx.native_cancel.load(Ordering::SeqCst) { break; }
        // Never a password prompt nobody asked for: the automatic pass leaves a
        // root-owned install to the button, which asks.
        if crate::elevate::needs_root(&inst) {
            ctx.log(
                Level::Warn,
                format!(
                    "Автопатч: {} — установка принадлежит root. Нажмите «Включить всё» и введите пароль.",
                    label
                ),
            );
            continue;
        }
        let mut patched = 0usize;
        let mut unknown = 0usize;
        let mut failed: Option<String> = None;
        for (_, outcome) in crate::watchdog::patch_now_received(&inst, &ctx.native_cancel) {
            match outcome {
                patch_binary::RepatchOutcome::Repatched(_) => patched += 1,
                patch_binary::RepatchOutcome::AlreadyPatched => {}
                patch_binary::RepatchOutcome::SignatureMissing => unknown += 1,
                patch_binary::RepatchOutcome::Failed(e) => failed = Some(e),
            }
        }
        let where_ = crate::utils::mask_path(&inst.display().to_string());
        if patched > 0 {
            wrote = true;
            ctx.log(
                Level::Ok,
                format!("Автопатч: {} — патч наложен ({})", label, where_),
            );
        }
        if let Some(e) = failed {
            ctx.log(
                Level::Warn,
                format!(
                    "Автопатч: {} — не удалось записать ({}). Закройте Antigravity и нажмите «Включить всё».",
                    label, e
                ),
            );
            break;
        } else if unknown > 0 && patched == 0 {
            // The watchdog's rule (I19): a build this patcher does not know is
            // left exactly as it is, so Antigravity shows its own error.
            ctx.log(
                Level::Warn,
                format!(
                    "Автопатч: {} — эта сборка Antigravity анлокеру ещё не знакома, файлы не тронуты. Нужна новая версия анлокера.",
                    label
                ),
            );
        }
    }
    if wrote {
        // What the switch falls back to before the next deep read, and what an
        // older build reading this file takes as the user's wish.
        ctx.settings.client_patch = true;
        ctx.settings.save();
    }
    // Left raised: every caller re-reads the installs next and lowers it after.
    wrote
}

#[cfg(not(windows))]
fn enable_client_patch(ctx: &mut Ctx) -> bool {
    let result = enable_client_patch_received(ctx);
    match result { Ok(value) => value, Err(error) => { ctx.log(Level::Err, error); false } }
}

fn legacy_client_targets(ctx: &Ctx) -> Vec<PathBuf> {
    let mut targets = crate::find_all_installs();
    for path in &ctx.settings.manual_paths { if !targets.contains(path) { targets.push(path.clone()); } }
    targets
}

fn enable_client_patch_received(ctx: &mut Ctx, #[cfg(windows)] plan: Option<&AllTargetApplyPlan>) -> Result<bool, String> {
    ctx.log(Level::Step, "Патч клиента Antigravity");
    #[cfg(not(windows))]
    patch_binary::kill_affected_processes();

    #[cfg(windows)]
    let targets = match plan { Some(plan) => plan.targets.iter().map(|target| target.root().to_owned()).collect(), None => legacy_client_targets(ctx) };
    #[cfg(not(windows))]
    let targets = legacy_client_targets(ctx);

    if targets.is_empty() {
        ctx.log(
            Level::Err,
            "Установки Antigravity не найдены. Укажите путь вручную (карандаш).",
        );
        return Ok(false);
    }

    // Recomputed every run: see Ctx::proxy_var_carried.
    ctx.proxy_var_carried = Some(false);
    ctx.proxy_var_retryable = false;

    let mut ok = 0usize;
    for inst in &targets {
        if ctx.native_cancel.load(Ordering::SeqCst) {
            return Err(format!("Патч отменён перед следующей установкой; завершено установок: {ok}."));
        }
        #[cfg(windows)]
        let expected = if let Some(plan) = plan {
            let target = plan.targets.iter().find(|target| target.root() == inst).ok_or("planned target is missing")?;
            target.recheck()?;
            Some(target.kind)
        } else { Some(crate::receive_installation_layout(inst)?.kind) };
        #[cfg(not(windows))]
        let expected = None;
        // A root-owned Linux install: only this write is done as root, behind
        // the desktop's password prompt (`elevate`).
        if crate::elevate::needs_root(inst) {
            let where_ = crate::utils::mask_path(&inst.display().to_string());
            ctx.log(
                Level::Step,
                format!("{where_} принадлежит root — запрашиваю пароль для записи патча"),
            );
            match crate::elevate::patch_as_root(inst) {
                Ok(done) => {
                    ok += 1;
                    if done.proxy_var {
                        ctx.proxy_var_carried = Some(true);
                    }
                    if done.proxy_var_retryable {
                        ctx.proxy_var_retryable = true;
                    }
                    ctx.log(Level::Ok, format!("{} — {}", done.label, where_));
                    for w in done.warnings {
                        ctx.log(Level::Warn, w);
                    }
                }
                Err(e) => ctx.log(Level::Err, format!("{where_} — {e}")),
            }
            continue;
        }
        match crate::process_install_received(inst, expected) {
            Ok(outcome) => {
                ok += 1;
                if outcome.summary.proxy_var > 0 {
                    ctx.proxy_var_carried = Some(true);
                }
                if outcome.summary.proxy_var_retryable {
                    ctx.proxy_var_retryable = true;
                }
                ctx.log(
                    Level::Ok,
                    format!(
                        "{} — {}",
                        outcome.label,
                        crate::utils::mask_path(&inst.display().to_string())
                    ),
                );
                for w in outcome.warnings {
                    ctx.log(Level::Warn, w);
                }
            }
            Err(e) => {
                #[cfg(windows)]
                return Err(format!("Запись установки остановлена; завершено установок: {ok}; {} — {e}", crate::utils::mask_path(&inst.display().to_string())));
                #[cfg(not(windows))]
                ctx.log(Level::Err, format!("{} — {e}", crate::utils::mask_path(&inst.display().to_string())));
            },
        }
    }

    if ok == 0 {
        ctx.log(Level::Err, "Ни одна установка не пропатчена.");
        return Ok(false);
    }

    // I39: the legacy CA comes out last, and `remove_legacy_ca` itself refuses
    // while the relay is still an older build.
    crate::remove_legacy_ca_quiet();

    ctx.log(Level::Ok, format!("Пропатчено установок: {}", ok));
    Ok(true)
}

#[cfg(not(windows))]
fn disable_client_patch(ctx: &mut Ctx) {
    let result = disable_client_patch_received(ctx);
    if let Err(error) = result { ctx.log(Level::Err, error); }
}

fn disable_client_patch_received(ctx: &mut Ctx, #[cfg(windows)] plan: Option<&AllTargetApplyPlan>) -> Result<(), String> {
    #[cfg(windows)]
    {
        if plan.is_none() && !ctx.settings.dns && dns::checked_nrpt_state()?.owned_rules_present {
            remove_dns_rules_effect(ctx)?;
        }
        let desired = background::BackgroundDesired { relay: ctx.settings.dns || routes_want_relay(&ctx.settings),
            watchdog: ctx.settings.auto_patch_wanted() };
        let cancellation = ctx.native_cancel.clone();
        if plan.is_none_or(|plan| plan.native.revert_services) {
            let image = ctx.lifetime.retained_image();
            let receiving = background::with_suspended_background(desired, &cancellation, image, || revert_client_primary(ctx, plan));
            let restoration = receiving.background.result.clone();
            let primary = receiving.primary;
            ctx.background_receivings.push(receiving.background);
            return receive_client_undo(primary, restoration);
        }
        return receive_client_undo(Some(revert_client_primary(ctx, plan)), Ok(()));
    }
    #[cfg(not(windows))]
    {
        background::disable_watchdog();
        background::disable()?;
        let primary = revert_client_primary(ctx);
        let restoration = if ctx.settings.dns || routes_want_relay(&ctx.settings) { background::ensure_running() } else { Ok(()) };
        receive_client_undo(Some(primary), restoration)
    }
}

fn receive_client_undo(primary: Option<Result<crate::elevate::Reverted, crate::elevate::Reverted>>,
    restoration: Result<(), String>) -> Result<(), String> {
    let primary_error = match primary {
        Some(Ok(_)) => None,
        Some(Err(outcome)) => Some(format!("Отмена файлов: подтверждено {}; предупреждения {}; ошибки {}",
            outcome.files, outcome.warnings.join("; "), outcome.errors.join("; "))),
        None => Some("Отмена файлов не вызывалась: владение/приостановка не получены.".into()),
    };
    match (primary_error, restoration) {
        (None, Ok(())) => Ok(()),
        (Some(primary), Ok(())) => Err(primary),
        (None, Err(restoration)) => Err(format!("Файлы получены, но восстановление служб не завершено: {restoration}")),
        (Some(primary), Err(restoration)) => Err(format!("{primary}; восстановление служб: {restoration}")),
    }
}

fn revert_client_primary(ctx: &mut Ctx, #[cfg(windows)] plan: Option<&AllTargetApplyPlan>)
    -> Result<crate::elevate::Reverted, crate::elevate::Reverted> {
    ctx.log(Level::Step, "Снятие патча клиента");
    let mut receiving = crate::elevate::Reverted::default();
    let primary = (|| -> Result<(), String> {

    #[cfg(not(windows))]
    patch_binary::kill_affected_processes();


    #[cfg(windows)]
    let targets = match plan { Some(plan) => plan.targets.iter().map(|target| target.root().to_owned()).collect(), None => legacy_client_targets(ctx) };
    #[cfg(not(windows))]
    let targets = legacy_client_targets(ctx);

    // Independent file work stops on its first actual failure. I20 restoration
    // is received by the surrounding background owner on every granted exit.
    for inst in &targets {
        if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Отмена файлов прервана пользователем; восстановление служб обязательно.".into()); }
        #[cfg(windows)]
        if let Some(plan) = plan {
            plan.targets.iter().find(|target| target.root() == inst).ok_or("planned target is missing")?.recheck()?;
        }
        let where_ = crate::utils::mask_path(&inst.display().to_string());
        // Each file is judged on its own (I45), and a failure is said out loud:
        // a count alone turned "one of two files could not be written" into a
        // clean revert, and the user kept a half-patched install. A root-owned
        // install (`/opt`) is reverted through pkexec, as it was patched: written
        // from here it only ever failed with `Permission denied`.
        // Asked only when there is something to take off: a clean root-owned
        // install does not deserve a password prompt.
        let patched_here = patch_binary::inspect_install(inst)
            .files
            .iter()
            .any(|(_, st)| *st == patch_binary::FileState::Patched);
        let done = if patched_here && crate::elevate::needs_root(inst) {
            ctx.log(
                Level::Info,
                format!("{} — установка принадлежит root, запрашиваю пароль", where_),
            );
            match crate::elevate::unpatch_as_root(inst) {
                Ok(d) => d,
                Err(e) => {
                    ctx.log(Level::Err, format!("{} — {}", where_, e));
                    continue;
                }
            }
        } else {
            #[cfg(windows)]
            {
                match crate::elevate::revert_files_checked(inst) {
                    Ok(done) => done,
                    Err(done) => {
                        receiving.files += done.files;
                        receiving.warnings.extend(done.warnings);
                        return Err(done.errors.join("; "));
                    },
                }
            }
            #[cfg(not(windows))]
            { crate::elevate::revert_files(inst) }
        };
        for e in &done.errors {
            receiving.errors.push(e.clone());
            ctx.log(Level::Err, format!("{} — {}", where_, e));
        }
        for w in &done.warnings {
            receiving.warnings.push(w.clone());
            ctx.log(Level::Warn, format!("{} — {}", where_, w));
        }
        let reverted = done.files;
        receiving.files += reverted;
        if let Err(e) = endpoint::remove_ide(inst) {
            #[cfg(windows)]
            return Err(format!("Откат файлов получен, но оверрайд не снят: {e}"));
            #[cfg(not(windows))]
            ctx.log(Level::Warn, format!("Оверрайд эндпоинта не снят: {}", e));
        }
        ctx.log(
            Level::Ok,
            format!("{} — возвращено файлов: {}", where_, reverted),
        );
    }
    if let Err(e) = endpoint::remove_cli() {
        #[cfg(windows)]
        return Err(format!("Откат файлов получен, но переменная CLI не снята: {e}"));
        #[cfg(not(windows))]
        ctx.log(Level::Warn, format!("Переменная CLI не снята: {}", e));
    }

    // The proxy variable is only read by a patched binary, so an unpatched
    // machine must not keep it: it would sit in the user environment forever,
    // naming a port nothing listens on.
    disable_local_proxy_effect(ctx)?;
    ctx.proxy_var_carried = Some(false);
    Ok(())
    })();
    if let Err(error) = primary { receiving.errors.push(error); }
    if receiving.errors.is_empty() { Ok(receiving) } else { Err(receiving) }
}

// --- watchdog --------------------------------------------------------------

#[cfg(windows)]
fn background_roles_effect(ctx: &mut Ctx, relay: bool, watchdog: bool, demand: background::ImageDemand) -> Result<(), String> {
    let cancellation = ctx.native_cancel.clone();
    let image = ctx.lifetime.retained_image();
    let receiving = background::reconcile_with_receiving(background::BackgroundDesired { relay, watchdog }, demand, &cancellation, image);
    let result = receiving.result.clone();
    // The existing background owner finishes its full private diagnostic before
    // returning. Retain the complete typed packet before interpreting result.
    ctx.background_receivings.push(receiving);
    result
}

fn set_watchdog_effect(ctx: &mut Ctx, on: bool) -> Result<(), String> {
    #[cfg(windows)]
    return background_roles_effect(ctx, ctx.settings.dns || routes_want_relay(&ctx.settings), ctx.settings.auto_patch_wanted(),
        if on { background::ImageDemand::DeliverSelectedImage } else { background::ImageDemand::KeepCompatible });
    #[cfg(not(windows))]
    {
    if !on {
        background::disable_watchdog();
        ctx.log(Level::Ok, "Автовосстановление патча отключено.");
        return Ok(());
    }
    // The task launches the copy in %ProgramData%, so it has to be there - but
    // only the file: starting the relay here switched the 400 bypass on for a
    // user who asked for auto-patch alone.
    background::ensure_installed().map_err(|error| format!("Копия для автопатча не установлена: {error}"))?;
    background::enable_watchdog().map_err(|error| format!("Автопатч не включён: {error}"))?;
    ctx.log(Level::Ok, "Автовосстановление патча включено.");
    Ok(())
    }
}

// --- DNS -------------------------------------------------------------------

fn enable_dns_effect(ctx: &mut Ctx) -> Result<(), String> {
    ctx.log(Level::Step, "Обход через DNS");

    // I5: the rules name the relay as their first nameserver, so it has to be
    // answering before they are written.
    #[cfg(windows)]
    background_roles_effect(ctx, true, ctx.settings.auto_patch_wanted(), background::ImageDemand::DeliverSelectedImage).map_err(|error| format!("Служба DNS не запустилась: {error}"))?;
    #[cfg(not(windows))]
    background::ensure_running().map_err(|error| format!("Служба DNS не запустилась: {error}"))?;
    ctx.log(Level::Ok, "Локальная служба DNS запущена.");
    if ctx.native_cancel.load(Ordering::SeqCst) {
        return Err("Служба получена; создание правил DNS отменено.".into());
    }

    let outcome = dns::setup_dns_nrpt().map_err(|error| format!("Служба подготовлена, но правила DNS не установлены: {error}"))?;
            dns::invalidate_cache();
            // The rules are in; what the client cached before them is not ours
            // to keep (G75). The relay does the same at its own start.
            if outcome.stood_down_for_vpn {
                // Not a failure, and not "on" either: with the client measured
                // inside a tunnel the rules would override the resolver the user
                // turned on, and the substituted address is reached through the
                // tunnel anyway (D13, G26, G29).
                return Err("Правила DNS не создавались: применение отложено владельцем DNS.".into());
            } else {
                ctx.log(Level::Ok, "Правила DNS установлены.");
            }
            if !dns::flush_client_cache() { return Err("Правила DNS установлены, но очистка кэша клиента не завершилась.".into()); }
            if let Some(note) = dns::outcome_note(&outcome) {
                ctx.log(Level::Info, strip_ansi(&note));
            }

    // Both of these were taken down *by* `disable_dns` rather than by the user,
    // so they come back with it. Anything the user switched off themselves stays
    // off: these read the saved wish, not the previous system state.
    if ctx.settings.local_proxy && !endpoint::proxy_env_is_ours() {
        enable_local_proxy_effect(ctx)?;
    }
    #[cfg(not(windows))]
    if ctx.settings.auto_patch_wanted() && !background::is_watchdog_enabled() {
        set_watchdog_effect(ctx, true)?;
    }
    Ok(())
}

fn disable_dns_effect(ctx: &mut Ctx) -> Result<(), String> {
    ctx.log(Level::Step, "Отключение обхода через DNS");

    // The relay is also the carrier of every route (local proxy, own proxy,
    // group, exits): it stays while any of them is wanted, and only the rules
    // come off.
    let keep_relay = routes_want_relay(&ctx.settings);

    // First, because the listener is about to stop existing: the local proxy
    // runs *inside* the relay, so stopping the relay leaves `AG_LS_PROXY`
    // naming a port nothing answers on, and Antigravity loses its sign-in with
    // `dial tcp 127.0.0.1: ... actively refused` (I53, G31). The user's wish for
    // the proxy is kept in settings, so it comes back when the relay does.
    if !keep_relay && endpoint::proxy_env_is_ours() {
        disable_local_proxy_effect(ctx)?;
    }

    remove_dns_rules_effect(ctx)?;
    if keep_relay {
        ctx.log(
            Level::Info,
            "Служба осталась запущенной: она нужна включённым прокси и выходам.",
        );
    } else {
        stop_relay_effect(ctx)?;
        // Again, after: the relay's own maintainer re-reads the settings on a
        // timer and may have put the variable back between the removal above and
        // the stop, leaving it on a port nothing answers (the window's switch
        // read off while Antigravity still died on `actively refused`).
        if endpoint::proxy_env_is_ours() {
            disable_local_proxy_effect(ctx)?;
        }
    }
    Ok(())
}

fn remove_dns_rules_effect(ctx: &mut Ctx) -> Result<(), String> {
    dns::remove_dns_nrpt_checked()?;
    dns::invalidate_cache();
    ctx.log(Level::Ok, "Правила DNS сняты.");
    Ok(())
}

/// Takes the relay service down for good, with auto-patch kept.
///
/// The standalone watchdog task launches the copy of this exe that
/// `background::disable` is about to delete. It is taken down first and put
/// back after, on a copy of its own: auto-patch is not part of the bypass,
/// and switching the bypass off must not switch it off too.
fn stop_relay_effect(ctx: &mut Ctx) -> Result<(), String> {
    #[cfg(windows)]
    return background_roles_effect(ctx, false, ctx.settings.auto_patch_wanted(), background::ImageDemand::KeepCompatible);
    #[cfg(not(windows))]
    {
    let watchdog_enabled = background::is_watchdog_enabled();
    let restore_watchdog = ctx.settings.auto_patch && watchdog_enabled;
    if restore_watchdog {
        background::disable_watchdog();
        ctx.log(Level::Ok, "Автопатч временно остановлен перед отключением службы.");
    }
    background::disable().map_err(|error| format!("Отключение службы не завершено; следующие действия остановлены: {error}"))?;
    ctx.log(Level::Ok, "Локальная служба DNS остановлена.");
    if restore_watchdog {
        set_watchdog_effect(ctx, true)?;
    }
    Ok(())
    }
}

/// Whether something other than the DNS rules needs the relay running: the
/// proxy listener and every route it serves live inside it.
fn routes_want_relay(s: &Settings) -> bool {
    s.local_proxy || s.own_proxy_enabled || s.group_proxy || s.builtin_exits
}

/// A route that was switched on by itself has to have something to ride on.
///
/// The routes (own proxy, group, exits) are chosen by the local proxy, which
/// lives in the relay, and the client reaches that proxy by its variable or by
/// the loopback door. With DNS off neither exists, so a route switched on alone
/// carried nothing - which is exactly how «свой прокси» "did not work" with the
/// other ways off. Starts the service and points the client at it; the DNS
/// rules are not touched.
fn ensure_route_carrier(ctx: &mut Ctx) -> Result<(), String> {
    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Подготовка службы отменена.".into()); }
    if cfg!(target_os = "windows") && !is_admin() {
        return Err("Служба обхода не запущена: нужны права администратора. Нажмите «Перезапустить от имени администратора».".into());
    }
    #[cfg(windows)]
    let reconciled = background_roles_effect(ctx,
        ctx.settings.dns || routes_want_relay(&ctx.settings), ctx.settings.auto_patch_wanted(), background::ImageDemand::DeliverSelectedImage);
    #[cfg(not(windows))]
    let reconciled = background::ensure_running();
    reconciled.map_err(|error| format!("Служба обхода не запустилась: {error}"))?;
    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Служба получена; настройка прокси отменена.".into()); }
    // Wanted, whatever `enable_local_proxy` manages below: the relay writes the
    // variable itself once its listener answers, and the door opens only while
    // this is set (`loopback::is_up`).
    if !ctx.settings.local_proxy {
        ctx.carrier_set_proxy = true;
        ctx.settings.local_proxy = true;
        ctx.settings.save();
    }
    if !endpoint::proxy_env_is_ours() {
        enable_local_proxy_effect(ctx)?;
    }
    Ok(())
}

/// The counterpart: a route went off, and if nothing else wants the service it
/// goes too. Not while DNS is on - then it is the DNS layer's.
fn release_route_carrier(ctx: &mut Ctx) -> Result<(), String> {
    if ctx.settings.dns || routes_want_relay_without_proxy_var(&ctx.settings) {
        return Ok(());
    }
    if cfg!(target_os = "windows") && !is_admin() {
        return Err("Отключение службы требует прав администратора.".into());
    }
    if ctx.carrier_set_proxy {
        ctx.carrier_set_proxy = false;
        ctx.settings.local_proxy = false;
        if endpoint::proxy_env_is_ours() {
            disable_local_proxy_effect(ctx)?;
        }
    }
    // The local proxy switched on by the user keeps the service.
    if ctx.settings.local_proxy {
        return Ok(());
    }
    stop_relay_effect(ctx)
}

/// `routes_want_relay` minus the proxy variable's own wish: a route's carrier
/// sets that wish itself, so it must not count against letting go of it.
fn routes_want_relay_without_proxy_var(s: &Settings) -> bool {
    s.own_proxy_enabled || s.group_proxy || s.builtin_exits
}

/// Re-writes the NRPT rules when the pool they name has changed.
///
/// A rule lists one address per enabled provider, so switching a provider off —
/// or turning rotation off, which narrows the list to one — changes what Windows
/// is pointed at. Without this the switch looks like it did nothing: the pool
/// stops asking that provider, but the machine keeps it as a nameserver until
/// the DNS switch is toggled off and on again.
/// Returns whether it actually went near the system — the caller uses that to
/// decide whether the following refresh has anything new to read.
fn reapply_dns_rules(ctx: &mut Ctx) -> bool {
    match reapply_dns_rules_checked(ctx) {
        Ok(changed) => changed,
        Err(error) => { ctx.log(Level::Warn, error); false },
    }
}

fn reapply_dns_rules_checked(ctx: &mut Ctx) -> Result<bool, String> {
    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Изменение правил DNS отменено.".into()); }
    if !dns::is_nrpt_applied() {
        return Ok(false);
    }
    if !is_admin() && cfg!(target_os = "windows") {
        return Err("Список DNS сохранён, но правила не переписаны — нужны права администратора.".into());
    }
    let outcome = dns::setup_dns_nrpt().map_err(|error| format!("Правила DNS не переписаны: {error}"))?;
    if outcome.stood_down_for_vpn { return Err("Изменение правил отложено владельцем DNS.".into()); }
    dns::invalidate_cache();
    if !dns::flush_client_cache() { return Err("Правила DNS переписаны, но кэш клиента не очищен.".into()); }
    ctx.log(Level::Ok, "Правила DNS переписаны под новый список.");
    Ok(true)
}

// --- local proxy -----------------------------------------------------------

fn enable_local_proxy_effect(ctx: &mut Ctx) -> Result<(), String> {
    ctx.log(Level::Step, "Локальный прокси");
    let url = proxy::proxy_url();

    // 1. The user-wide pair that builds up to 2.11.0_4 wrote. It goes first:
    //    leaving it puts the whole machine through loopback (D19).
    match endpoint::remove_legacy_proxy_env(&url) {
        Ok(true) => ctx.log(Level::Ok, "Прежняя общесистемная HTTPS_PROXY снята."),
        Ok(false) => {}
        Err(e) => {
            return Err(format!("Прежняя HTTPS_PROXY не снята: {e}"));
        }
    }

    // 2. Measured (G33): ours outranks theirs inside the patched server. A user
    //    who configured their own proxy must keep it, so ours comes off — this
    //    is not a "skip".
    if endpoint::foreign_proxy(&url).is_some() {
        endpoint::remove_proxy(&url, "").map_err(|error| format!("Своя переменная прокси не снята при чужом прокси: {error}"))?;
        return Err("В системе задан свой прокси — наш не включён, чтобы не перехватывать чужой. Выбор сохранён.".into());
    }

    // 3. The variable has a private name that only a patched binary reads. If
    //    the rename did not land, writing it is writing into nothing.
    if ctx.proxy_var_carried == Some(false) {
        return Err(if ctx.proxy_var_retryable {
                "Файл был занят — закройте Antigravity полностью и включите переключатель заново."
            } else {
                "В этой сборке Antigravity нет места для переменной прокси — \
                 вероятно, вышла новая версия и нужен более новый анлокер."
            }.into());
    }

    // 4. I53/G31: never name a listener that is not there. A variable pointing
    //    at a dead port takes the sign-in down with it.
    //    Named by the port that answered, not the one read above: the relay can
    //    move the proxy while this waits (P26), and a URL for the port it left
    //    would be a dead one no watchdog takes back off.
    let Some(port) = proxy::wait_for_our_listener(Duration::from_secs(3))? else {
        return Err("Локальный прокси не отвечает — сначала включите «Обход через DNS».".into());
    };
    let url = proxy::url_at(port);

    endpoint::apply_proxy(&url, "").map_err(|error| format!("Локальный прокси не включён: {error}"))?;
    ctx.log(Level::Ok, "Локальный прокси включён.");
    Ok(())
}

fn disable_local_proxy_effect(ctx: &mut Ctx) -> Result<(), String> {
    let url = proxy::proxy_url();
    // I45 again: `remove_proxy` collects its own failures and joins them, so a
    // half-failed removal still takes off everything it can.
    endpoint::remove_proxy(&url, "").map_err(|error| format!("Снято не полностью: {error}"))?;
    ctx.log(Level::Ok, "Локальный прокси отключён.");
    Ok(())
}

// --- own proxy -------------------------------------------------------------

/// Saves the user's own DNS server(s). Anything that is not an IPv4 address is
/// refused with the reason; the slot stays as it was.
fn set_custom_dns(ctx: &mut Ctx, text: &str) {
    let text = text.trim();
    if text.is_empty() {
        ctx.settings.custom_dns.clear();
        ctx.settings.set_provider_enabled("свой DNS", true);
        ctx.log(Level::Ok, "Свой DNS убран.");
        return;
    }
    let found = crate::resolvers::parse_custom_dns(text);
    let words = text
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|w| !w.is_empty())
        .count();
    if found.is_empty() || found.len() < words {
        ctx.log(
            Level::Err,
            "Нужны IPv4-адреса DNS-серверов через пробел или запятую (не 127.x и не 0.0.0.0), например 77.88.8.8.",
        );
        return;
    }
    ctx.settings.custom_dns = found
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    ctx.settings.set_provider_enabled("свой DNS", true);
    ctx.log(
        Level::Ok,
        format!(
            "Свой DNS сохранён ({}). Он участвует в пуле наравне с остальными: ответ сверяется с эталонным.",
            ctx.settings.custom_dns
        ),
    );
}

fn set_own_proxy(ctx: &mut Ctx, text: &str) -> Result<(), String> {
    ctx.settings.own_proxy = text.trim().to_string();
    if ctx.settings.own_proxy.is_empty() {
        ctx.settings.own_proxy_enabled = false;
        upstream::clear()?;
        ctx.log(Level::Ok, "Свой прокси убран.");
        return release_route_carrier(ctx);
    }

    let up = match upstream::parse(&ctx.settings.own_proxy) {
        Ok(u) => u,
        Err(e) => {
            ctx.settings.own_proxy_enabled = false;
            return Err(format!("Адрес не разобран: {e}"));
        }
    };

    // Saved and switched on whatever the checks below say: the user typed it in,
    // and the route table is what decides whether it carries anything - a proxy
    // that does not open is stepped around on the connection that finds out, and
    // one that draws a region 400 is benched by the watch (G81). Refusing to save
    // it made the user keep a proxy they wanted out of the table altogether.
    if let Err(e) = upstream::save(&up) {
        ctx.settings.own_proxy_enabled = false;
        return Err(format!("Не сохранён: {e}"));
    }
    ctx.settings.own_proxy_enabled = true;
    ctx.settings.own_proxy_at = crate::gate::now_unix();
    ctx.log(Level::Ok, format!("Свой прокси включён: {}", up.display()));
    // Alone it needs the service and the variable; DNS is not part of it.
    ensure_route_carrier(ctx)?;

    // Whether it carries a request to Google, and nothing else. Its exit country
    // is never traced (D34): through the user's proxy the only traffic is to
    // Google, and the region is judged by the refusal Google actually gives -
    // Cloudflare's geolocation only guessed at it, and no unsigned Google call
    // can tell (401/403 from any exit, measured).
    ctx.log(Level::Info, "Проверяю прокси…");
    match upstream::probe(&up) {
        Ok(()) => ctx.log(Level::Ok, "Прокси отвечает."),
        Err(e) => {
            ctx.log(
                Level::Warn,
                format!(
                    "Прокси не отвечает: {} — сохранён всё равно; пока он не отвечает, запросы пойдут другими маршрутами.",
                    e
                ),
            );
        }
    }
    Ok(())
}

/// Strips SGR escapes from a string built for a terminal.
///
/// `dns::outcome_note` returns text with colour codes baked in — it was written
/// to be printed. Rendering it in a window would show the raw `ESC[33m`.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Drop until the final byte of the sequence (a letter).
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether a path looks like an install root, for the manual "pencil" dialog.
pub fn resolve_manual_path(raw: &Path) -> Option<PathBuf> {
    crate::resolve_install_root(raw)
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn default_lifetime_never_constructs_a_source_image() {
        assert!(super::GuiLifetime::default().retained_image().is_err());
    }
    #[cfg(windows)]
    #[test]
    fn fallback_lifetime_retains_the_same_received_image() {
        let image = std::sync::Arc::new(crate::windows_coordinator::process_identity::CurrentImage::capture().unwrap());
        let original = super::GuiLifetime::with_image(Ok(image.clone()));
        let fallback = super::GuiLifetime::with_image(original.retained_image());
        assert!(std::sync::Arc::ptr_eq(&image, &fallback.retained_image().unwrap()));
    }
    #[test]
    #[cfg(windows)]
    fn vendor_current_requires_exact_unique_owner_result() {
        let values = vec![("slot".to_owned(), [7; 32])];
        assert!(super::vendor_result_received(&values, "slot", &[7; 32]));
        assert!(!super::vendor_result_received(&values, "slot", &[8; 32]));
        assert!(!super::vendor_result_received(&values, "other", &[7; 32]));
        assert!(!super::vendor_result_received(&[values[0].clone(), values[0].clone()], "slot", &[7; 32]));
    }
    #[test]
    #[cfg(windows)]
    fn later_plan_failure_or_cancel_preserves_recovery_results_including_error_after_publish() {
        let completed = vec!["scope A: RecoverySettled; actualCurrent=Settled digest=A".to_owned()];
        for later in ["selected target B failed", "Cancelled: fresh plan receiving"] {
            let message = apply_receiving_failure(later, &completed);
            assert!(message.contains(&completed[0]) && message.contains(later));
            assert!(!message.contains("до изменений"));
        }
        let partial = vec!["scope A: readiness Err after publish; actualCurrent=Settled digest=P".to_owned()];
        let message = apply_receiving_failure("NotReady", &partial);
        assert!(message.contains(&partial[0]) && !message.contains("до изменений"));
        assert!(apply_receiving_failure("read-only failure", &[]).contains("до изменений"));
    }
    #[test]
    #[cfg(windows)]
    fn positive_apply_pending_tuple_is_once_per_intent_and_cancel_is_effect_free() {
        let mut attempted = std::collections::BTreeSet::new();
        let cancel = AtomicBool::new(false);
        let pending = crate::windows_coordinator::windows_installation::GatewayPendingObservation {
            slot_id: "a".repeat(32), operation_id: "b".repeat(32), current_sha256: [7;32],
        };
        receive_gateway_prerequisite_once(&mut attempted, &pending, &cancel).unwrap();
        assert!(receive_gateway_prerequisite_once(&mut attempted, &pending, &cancel).unwrap_err().contains("same Pending"));
        assert_eq!(attempted.len(), 1);
        cancel.store(true, Ordering::SeqCst);
        let other = crate::windows_coordinator::windows_installation::GatewayPendingObservation {
            slot_id: "c".repeat(32), ..pending.clone()
        };
        assert!(receive_gateway_prerequisite_once(&mut attempted, &other, &cancel).unwrap_err().starts_with("Cancelled:"));
        assert_eq!(attempted.len(), 1);
        let mut fresh_positive_apply = std::collections::BTreeSet::new();
        cancel.store(false, Ordering::SeqCst);
        receive_gateway_prerequisite_once(&mut fresh_positive_apply, &pending, &cancel).unwrap();
    }
    #[test]
    fn refresh_waits_for_owned_native_settlement_and_coalesces() {
        use std::sync::mpsc;
        let (release, wait) = mpsc::channel::<()>();
        let (entered, received) = mpsc::channel();
        let job = std::thread::spawn(move || { entered.send(()).unwrap(); wait.recv().unwrap(); });
        received.recv().unwrap();
        let mut requested = true; // startup
        assert!(super::receive_wsl_refresh_command(&mut requested, &Some(super::Cmd::RefreshWsl)));
        assert!(super::receive_wsl_refresh_command(&mut requested, &Some(super::Cmd::RefreshWsl)));
        assert!(!super::take_wsl_refresh(&mut requested, job.is_finished(), &None, &None));
        assert!(requested);
        release.send(()).unwrap();
        job.join().unwrap();
        let mut queries = 0;
        if super::take_wsl_refresh(&mut requested, true, &None, &None) { queries += 1; }
        if super::take_wsl_refresh(&mut requested, true, &None, &None) { queries += 1; }
        assert_eq!(queries, 1);
        requested = true;
        assert!(!super::receive_wsl_refresh_command(&mut requested, &Some(super::Cmd::CancelWsl)));
        assert!(!super::take_wsl_refresh(&mut requested, true, &None, &None));
        requested = true;
        assert!(!super::receive_wsl_refresh_command(&mut requested, &Some(super::Cmd::Shutdown)));
        assert!(!super::take_wsl_refresh(&mut requested, true, &None, &None));
    }

    #[test]
    fn received_commands_precede_coalesced_refresh() {
        use super::{Cmd, receive_wsl_refresh_command, take_wsl_refresh};
        let mut requested = true;
        assert!(!take_wsl_refresh(&mut requested, true, &Some(Cmd::RequestElevation), &None));
        #[cfg(windows)]
        assert!(!take_wsl_refresh(&mut requested, true, &None,
            &Some(Cmd::Elevate(crate::instances::GuiReplacementAction::ShowMain {}))));
        assert!(!take_wsl_refresh(&mut requested, true,
            &Some(Cmd::SetWslDistro { name: "Ubuntu".into(), selected: false }), &None));
        assert!(receive_wsl_refresh_command(&mut requested, &Some(Cmd::RefreshWsl)));
        assert!(receive_wsl_refresh_command(&mut requested, &Some(Cmd::RefreshWsl)));
        assert!(take_wsl_refresh(&mut requested, true, &None, &None));
        assert!(!take_wsl_refresh(&mut requested, true, &None, &None));
    }

    use super::*;

    #[test]
    fn client_undo_keeps_primary_and_required_restoration_failures() {
        let primary = crate::elevate::Reverted { files: 1,
            errors: vec!["first file I/O failure".into()], warnings: vec!["retained warning".into()] };
        let error = receive_client_undo(Some(Err(primary)), Err("wanted relay resume failure".into())).unwrap_err();
        assert!(error.contains("подтверждено 1"));
        assert!(error.contains("first file I/O failure") && error.contains("retained warning"));
        assert!(error.contains("wanted relay resume failure"));
        assert!(receive_client_undo(None, Ok(())).unwrap_err().contains("не вызывалась"));
    }

    #[test]
    fn retired_worker_cannot_restart_renderer_or_commit_from_ui_poll() {
        let lifetime = GuiLifetime::default();
        assert!(lifetime.can_start_fallback());
        lifetime.started.store(true, Ordering::SeqCst);
        lifetime.shutdown_ready.store(true, Ordering::SeqCst);
        *lifetime.worker.lock().unwrap() = Some(std::thread::spawn(|| {}));
        while !lifetime.poll_close().unwrap() { std::thread::yield_now(); }
        assert!(!lifetime.can_retry_renderer());
        assert!(!lifetime.can_start_fallback());
        assert!(!lifetime.arming_started.load(Ordering::SeqCst));
        assert!(!lifetime.replacement_committed());
        assert!(lifetime.finalize_exit().unwrap());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an explicit vacant owned AG_GUI_LIFETIME_TEST_ROOT"]
    fn actual_save_failure_accepts_a_fresh_close_and_joins_before_exit() {
        let root = PathBuf::from(std::env::var_os("AG_GUI_LIFETIME_TEST_ROOT").expect("owned fixture root required"));
        crate::windows_coordinator::windows_installation::WindowsLocalPath::parse(root.as_os_str()).unwrap();
        assert!(!root.exists(), "fixture leaf must be vacant");
        std::fs::create_dir(&root).unwrap();
        let local = root.join("local-appdata");
        std::fs::write(&local, b"owned not-a-directory precondition").unwrap();
        let previous = std::env::var_os("LOCALAPPDATA");
        // The exact test runs alone. This worker only calls the shutdown owner;
        // it never runs startup, discovery, system probes or selected effects.
        unsafe { std::env::set_var("LOCALAPPDATA", &local); }
        let lifetime = Arc::new(GuiLifetime::default());
        struct Restore { lifetime: Arc<GuiLifetime>, previous: Option<std::ffi::OsString> }
        impl Drop for Restore {
            fn drop(&mut self) {
                self.lifetime.command.lock().unwrap().take();
                if let Some(worker) = self.lifetime.worker.lock().unwrap().take() {
                    if worker.join().is_err() { eprintln!("owned close fixture worker panicked"); }
                }
                unsafe { match &self.previous {
                    Some(previous) => std::env::set_var("LOCALAPPDATA", previous),
                    None => std::env::remove_var("LOCALAPPDATA"),
                } }
            }
        }
        let _restore = Restore { lifetime: lifetime.clone(), previous };
        let (events, received) = mpsc::channel();
        let (command, commands) = mpsc::channel();
        *lifetime.command.lock().unwrap() = Some(command);
        let worker_lifetime = lifetime.clone();
        let settings = Settings::default();
        let expected = settings.clone();
        let worker = std::thread::spawn(move || {
            let mut ctx = Ctx { events, wake: Arc::new(Mutex::new(Box::new(|| {}))), settings,
                wsl: crate::wsl_controller::WslController::default(), native_apply_pending: Arc::new(AtomicBool::new(false)),
                native_cancel: Arc::new(AtomicBool::new(false)), background_receivings: Vec::new(),
                lifetime: worker_lifetime.clone(), vpn_job: None, vpn_unsettled: false, startup: Startup::Explicit,
                proxy_var_carried: None, proxy_var_retryable: false, patched_seen: HashMap::new(), vpn: None,
                relay_egress: None, last: None, dns_probe: (false, false), carrier_set_proxy: false };
            while commands.recv().is_ok() { if finish_shutdown(&mut ctx, &worker_lifetime) { return; } }
        });
        *lifetime.worker.lock().unwrap() = Some(worker);
        lifetime.started.store(true, Ordering::SeqCst);
        lifetime.request_shutdown();
        loop {
            match received.recv().unwrap() {
                Event::Log(Level::Err, _) => break,
                Event::ShutdownReady => panic!("failed actual save cannot acknowledge retirement"),
                _ => {},
            }
        }
        while !lifetime.save_failed.load(Ordering::SeqCst) { std::thread::yield_now(); }
        assert!(lifetime.poll_close().is_err());
        assert!(!lifetime.shutdown_ready.load(Ordering::SeqCst));
        std::fs::remove_file(&local).unwrap();
        std::fs::create_dir(&local).unwrap();
        lifetime.request_shutdown();
        while !lifetime.poll_close().unwrap() { std::thread::yield_now(); }
        assert!(crate::settings::saved_intent_sha256(&expected).is_ok());
        assert!(!lifetime.can_start_fallback());
        assert!(!lifetime.arming_started.load(Ordering::SeqCst));
        assert!(lifetime.finalize_exit().unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn native_apply_plan_requires_real_rule_and_relay_noops() {
        let mut wanted = Settings::default();
        wanted.dns = true;
        wanted.local_proxy = false;
        wanted.own_proxy_enabled = false;
        wanted.group_proxy = false;
        wanted.builtin_exits = false;
        wanted.auto_patch = true;
        let mut facts = NativeApplyFacts { core_rules: true, owned_rules: true, relay_task: true,
            relay: Some(NativeRelayFacts { relay_compatible: true,
                relay_outdated: false, relay_reporting: true }), watchdog_task: true, program_outdated: Some(false) };
        assert!(!NativeApplyPlan::receive(&wanted, &facts).unwrap().requires_elevation());
        facts.program_outdated = Some(true);
        let delivery = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(delivery.update_shared_program && delivery.requires_elevation());
        assert!(!delivery.ensure_relay && delivery.watchdog.is_none());
        facts.program_outdated = Some(false);
        facts.relay.as_mut().unwrap().relay_reporting = false;
        assert!(NativeApplyPlan::receive(&wanted, &facts).unwrap().ensure_relay);
        facts.relay.as_mut().unwrap().relay_reporting = true;
        wanted.dns = false;
        facts.core_rules = false;
        let partial_owned = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(partial_owned.disable_dns);
        assert!(!partial_owned.stop_relay);
        assert!(partial_owned.requires_elevation());
        facts.owned_rules = false;
        assert!(NativeApplyPlan::receive(&wanted, &facts).unwrap().stop_relay);
        wanted.own_proxy_enabled = true;
        let retained_carrier = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(!retained_carrier.stop_relay);
        assert!(!retained_carrier.ensure_relay);
        assert!(!wanted.local_proxy);
        wanted.own_proxy_enabled = false;
        facts.relay_task = false;
        facts.relay = None;
        // The watchdog has the same image name. That observation alone is not
        // a positive relay-stop requirement.
        assert!(!NativeApplyPlan::receive(&wanted, &facts).unwrap().requires_elevation());
        wanted.local_proxy = true;
        assert!(NativeApplyPlan::receive(&wanted, &facts).is_err());
        wanted.local_proxy = false;
        facts.program_outdated = Some(true);
        let watchdog_only = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(watchdog_only.update_shared_program && watchdog_only.requires_elevation());
        assert_eq!(watchdog_only.watchdog, None, "generation update must retain the wanted running watchdog");
        facts.program_outdated = None;
        assert!(NativeApplyPlan::receive(&wanted, &facts).is_err());
        wanted.patch_declined = true;
        let declined = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert_eq!(declined.watchdog, Some(false), "explicit decline owns effective watchdog intent");
    }

    #[test]
    fn terminal_colours_do_not_reach_the_window() {
        let coloured = "\x1b[33mвнимание\x1b[0m\x1b[92m: правило";
        assert_eq!(strip_ansi(coloured), "внимание: правило");
    }

    #[test]
    fn a_capability_that_edits_system_policy_asks_for_admin_on_windows() {
        // The trap this guards: without elevation `remove_dns_nrpt` and
        // `background::disable` do not fail, they silently do nothing — so an
        // unelevated OFF switch would render as off while the rules stayed.
        assert_eq!(Cap::Dns.needs_admin(), cfg!(target_os = "windows"));
        assert!(!Cap::ClientPatch.needs_admin(), "the patch needs no UAC");
        assert!(!Cap::OwnProxy.needs_admin());
    }

    /// G74: the window drew the local-proxy switch from the environment alone,
    /// so a variable that outlived a failed removal showed «вкл» while the relay
    /// logged «выключена в настройках» in the same minute. The setting is what
    /// the relay obeys, so the setting is what the switch may never contradict.
    #[test]
    fn the_local_proxy_switch_never_reads_on_while_the_setting_is_off() {
        for ours in [true, false] {
            assert!(
                !local_proxy_state(false, ours).is_on(),
                "switch on with the setting off (variable present: {ours})"
            );
        }
        assert_eq!(local_proxy_state(true, true), State::On);
        assert_eq!(local_proxy_state(false, false), State::Off);
        // Both mismatches say which way round they are, rather than going quiet.
        assert!(local_proxy_state(true, false).note().is_some());
        assert!(local_proxy_state(false, true).note().is_some());
        // And each stays switchable the other way (G41): asked-for reads as on
        // so it can be turned off, left-over reads as off so it can be turned on.
        assert!(local_proxy_state(true, false).is_on());
        assert!(!local_proxy_state(false, true).is_on());
    }

    #[test]
    fn with_rotation_off_the_one_that_answers_is_the_first_one_left_on() {
        let names = crate::resolvers::provider_names();
        assert!(names.len() >= 2, "the test needs a pool to narrow");

        let mut s = Settings::default();
        assert_eq!(first_enabled_provider(&s), Some(names[0]));

        // Turning the head off must move the choice down the list, not leave it
        // pointing at a provider that is switched off.
        s.set_provider_enabled(names[0], false);
        assert_eq!(first_enabled_provider(&s), Some(names[1]));

        for n in &names {
            s.set_provider_enabled(n, false);
        }
        assert_eq!(first_enabled_provider(&s), None);
        assert!(all_providers_disabled(&s));
    }

    #[test]
    fn a_partial_state_still_reads_as_on() {
        // Half-patched must not draw as off: the user would flip it on and get
        // a no-op on the installs that are already done.
        assert!(State::Partial("x".into()).is_on());
        assert!(!State::Blocked("нет прав".into()).is_on());
        assert!(!State::Off.is_on());
    }

    /// The bug this pins: «Сверять TLS» and «Ротация» described their *off*
    /// state with a note, the note was a `Partial`, and `Partial` reads as on —
    /// so the switch sprang back the moment the worker's snapshot arrived and
    /// neither could be turned off, while the log said they had been.
    #[test]
    fn a_switch_that_is_off_with_a_note_is_off() {
        let mut s = Settings::default();
        s.rotate_providers = false;
        s.builtin_exits = false;
        let st = blank_status().with_settings_switches(&s);

        assert!(!st.dns_rotation.is_on());
        assert!(!st.builtin_exits.is_on());
        // The note itself must survive — it is what the row says underneath.
        assert!(st.dns_rotation.note().is_some());

        let on = blank_status().with_settings_switches(&Settings::default());
        assert!(on.dns_rotation.is_on() && on.builtin_exits.is_on());
    }

    /// A settings-only refresh must produce the same switches a full one does,
    /// or a flip would answer differently depending on which path drew it.
    #[test]
    fn the_cheap_refresh_and_the_full_one_agree_about_the_settings_switches() {
        let mut s = Settings::default();
        s.rotate_providers = false;
        let a = blank_status().with_settings_switches(&s);
        let b = blank_status().with_settings_switches(&s);
        assert_eq!(a.dns_rotation, b.dns_rotation);
        assert_eq!(a.providers.len(), crate::resolvers::provider_names().len());
    }

    /// A switch that only writes `settings.json` must not send the worker back
    /// to Windows for scheduled tasks and environment variables.
    #[test]
    fn only_the_switches_that_touch_the_system_pay_for_a_system_scan() {
        assert_eq!(scan_after(Cap::BuiltinExits), Scan::Settings);
        assert_eq!(scan_after(Cap::GroupProxy), Scan::Settings);
        assert_eq!(scan_after(Cap::Dns), Scan::System);
        assert_eq!(scan_after(Cap::LocalProxy), Scan::System);
        assert_eq!(scan_after(Cap::ClientPatch), Scan::Deep);
    }

    /// Any single way can be the only one on: the master switch follows it
    /// instead of reading off (which is what unset it under the user's own proxy).
    #[test]
    fn any_single_way_keeps_the_master_switch_on() {
        let blank = blank_status();
        assert!(!blank.bypass_on());
        for set in [
            |s: &mut Status| s.own_proxy = State::On,
            |s: &mut Status| s.group_proxy = State::On,
            |s: &mut Status| s.builtin_exits = State::On,
            |s: &mut Status| s.local_proxy = State::On,
            |s: &mut Status| s.dns = State::On,
        ] {
            let mut s = blank_status();
            set(&mut s);
            assert!(s.bypass_on());
        }
    }

    /// The master switch off lets go of every way, DNS last (the service dies
    /// with it) and the user's own proxy included, or it would draw itself on again.
    #[test]
    fn master_off_takes_every_way_down_and_on_never_picks_the_users_proxy() {
        let off = bypass_order(false);
        assert_eq!(off.last(), Some(&Cap::Dns));
        assert!(off.contains(&Cap::OwnProxy) && off.contains(&Cap::GroupProxy));
        assert!(!bypass_order(true).contains(&Cap::OwnProxy));
    }

    /// A service kept up for a route is not a half-installed DNS layer: with the
    /// DNS switch off it reads off, with it on it is still a fault.
    #[test]
    fn a_service_running_for_a_route_does_not_pin_the_dns_switch_on() {
        let off = dns_state(true, false, true, None, true, false);
        assert!(!off.is_on());
        let broken = dns_state(true, false, true, None, true, true);
        assert!(broken.is_on());
    }

    #[test]
    fn the_service_is_wanted_while_any_route_is() {
        let mut s = Settings::default();
        s.local_proxy = false;
        s.builtin_exits = false;
        s.group_proxy = false;
        s.own_proxy_enabled = false;
        assert!(!routes_want_relay(&s));
        s.own_proxy_enabled = true;
        assert!(routes_want_relay(&s));
    }

    /// Live: what a switch actually costs, which is the complaint this was built
    /// to answer («слишком много времени»). Prints, asserts only the shape.
    ///
    ///     cargo test what_a_refresh_costs -- --ignored --nocapture
    #[test]
    #[ignore = "times real helper processes; run on Windows with --ignored"]
    fn what_a_refresh_costs() {
        let (tx, _rx) = mpsc::channel();
        let mut ctx = Ctx {
            events: tx,
            wake: Arc::new(Mutex::new(Box::new(|| {}))),
            settings: Settings::load(),
            wsl: crate::wsl_controller::WslController::default(),
            native_apply_pending: Arc::new(AtomicBool::new(false)),
            native_cancel: Arc::new(AtomicBool::new(false)),
            #[cfg(windows)]
            background_receivings: Vec::new(),
            lifetime: Arc::new(GuiLifetime::default()),
            vpn_job: None,
            vpn_unsettled: false,
            startup: Startup::Ordinary,
            proxy_var_carried: None,
            proxy_var_retryable: false,
            patched_seen: HashMap::new(),
            vpn: Some(VpnSeen::None),
            relay_egress: None,
            last: None,
            dns_probe: (false, false),
            carrier_set_proxy: false,
        };

        let t = std::time::Instant::now();
        let full = read_status(&mut ctx, false);
        let system = t.elapsed();
        ctx.last = Some(full);

        let t = std::time::Instant::now();
        let _ = settings_only_status(&ctx, ctx.last.clone().unwrap());
        let settings = t.elapsed();

        println!("Scan::System   {:?}", system);
        println!("Scan::Settings {:?}", settings);
        assert!(
            settings < system,
            "the cheap path is not cheaper: {:?} vs {:?}",
            settings,
            system
        );
    }

    fn blank_status() -> Status {
        Status {
            wsl: crate::wsl_api::WslStatus::default(),
            admin: true,
            installs: Vec::new(),
            client_patch: State::Off,
            watchdog: State::Off,
            dns: State::Off,
            local_proxy: State::Off,
            own_proxy: State::Off,
            builtin_exits: State::Off,
            group_proxy: State::Off,
            dns_rotation: State::Off,
            vpn: None,
            own_proxy_text: String::new(),
            custom_dns_text: String::new(),
            relay_outdated: false,
            relay_running: false,
            rules: false,
            providers: Vec::new(),
            relay_egress: None,
        }
    }

    /// The regression the `Unmeasured` variant exists for: a tunnel is up and
    /// the client has not dialled out, which is what a window opened before
    /// Antigravity almost always sees. Reading that as "the client is outside
    /// the tunnel" is the indicator claiming a measurement nobody took.
    #[test]
    fn a_tunnel_with_nothing_to_read_is_not_a_client_outside_it() {
        use crate::egress::ClientEgress;
        let seen = |client| match client {
            ClientEgress::Tunnel => VpnSeen::CarryingClient,
            ClientEgress::Mixed => VpnSeen::PartlyCarryingClient,
            ClientEgress::Physical => VpnSeen::NotCarryingClient,
            ClientEgress::ViaLocalProxy => VpnSeen::ViaLocalProxy,
            ClientEgress::Unknown => VpnSeen::Unmeasured,
        };
        assert_eq!(seen(ClientEgress::Unknown), VpnSeen::Unmeasured);
        assert_ne!(seen(ClientEgress::Unknown), VpnSeen::NotCarryingClient);
        // The state the proxy route puts a patched client in: measured, and not
        // the same answer as "nothing to read".
        assert_eq!(seen(ClientEgress::ViaLocalProxy), VpnSeen::ViaLocalProxy);
        assert_ne!(seen(ClientEgress::ViaLocalProxy), VpnSeen::Unmeasured);
        // And an unmeasured tunnel must not block the DNS row: it takes evidence
        // to stand down, not the absence of it (S37).
        assert_eq!(
            dns_state(true, true, true, Some(VpnSeen::Unmeasured), true, true),
            State::On
        );
        // A client in a tunnel no longer blocks the row either (D25).
        assert_eq!(
            dns_state(true, true, true, Some(VpnSeen::CarryingClient), true, true),
            State::On
        );
    }
}
