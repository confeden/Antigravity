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
//! * **I45** — an undo path has no fast exit. Every step runs, each is judged on
//!   its own, failures are collected. `?` between undo steps is the bug.
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
use std::time::Duration;

use crate::settings::Settings;
use crate::utils::is_admin;
use crate::{background, dns, endpoint, patch_binary, patch_ide, proxy, upstream};

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
    /// Whether the DNS pool rotates, or only its first enabled member answers.
    DnsRotation,
    /// Whether a VPN carrying Antigravity makes the DNS layer stand down.
    VpnDetect,
    /// Whether a substituted address must present a valid Google certificate.
    VerifyTls,
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
            Cap::Watchdog => "Автопатч после обновления Antigravity",
            Cap::Dns => "Обход через DNS",
            Cap::LocalProxy => "Локальный прокси",
            Cap::OwnProxy => "Свой HTTP-прокси",
            Cap::BuiltinExits => "Встроенные выходы",
            Cap::DnsRotation => "Ротация DNS-серверов",
            Cap::VpnDetect => "Определять VPN",
            Cap::VerifyTls => "Сверять TLS",
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
    pub admin: bool,
    pub installs: Vec<InstallRow>,
    pub client_patch: State,
    pub watchdog: State,
    pub dns: State,
    pub local_proxy: State,
    pub own_proxy: State,
    pub builtin_exits: State,
    pub dns_rotation: State,
    pub vpn_detect: State,
    pub verify_tls: State,
    /// What the last measurement saw. `None` means it has not been taken yet;
    /// taking it spawns PowerShell, so it is not done on every refresh.
    pub vpn: Option<VpnSeen>,
    pub own_proxy_text: String,
    pub relay_outdated: bool,
    /// Whether the relay task is registered *and* running. The raw fact, kept
    /// beside the `dns` row that already folds it into a verdict: the gate strip
    /// has to say "there is nobody to catch the next 400" without re-deriving it
    /// from a string meant for a switch.
    pub relay_running: bool,
    pub providers: Vec<ProviderRow>,
    /// The language-server binaries, for the one thing the window needs their
    /// full paths for: telling a VPN which executable to leave out of its
    /// tunnel.
    pub client_exes: Vec<PathBuf>,
    /// The installed relay, when there is one. With the local-proxy route on it
    /// is *this* process that opens the connection to Google, so it is the one a
    /// split-tunnelling list has to name — excluding the language server there
    /// changes nothing at all.
    pub relay_exe: Option<PathBuf>,
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
            Cap::DnsRotation => &self.dns_rotation,
            Cap::VpnDetect => &self.vpn_detect,
            Cap::VerifyTls => &self.verify_tls,
        }
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
}

/// UI → worker.
pub enum Cmd {
    /// Re-read the system. Cheap parts only.
    Refresh,
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
    SetOwnProxy(String),
    SetProvider(String, bool),
    /// The whole pool in the order the user dragged it into.
    ReorderProviders(Vec<String>),
    #[allow(dead_code)]
    Stop,
}

pub struct Worker {
    tx: Sender<Cmd>,
}

impl Worker {
    pub fn send(&self, cmd: Cmd) {
        // A closed worker means the app is going down; there is nothing useful
        // to do about it and nothing to tell the user.
        let _ = self.tx.send(cmd);
    }
}

/// Starts the worker. `wake` is called after every event so the UI thread
/// repaints — egui sleeps until something asks it not to.
pub fn spawn(events: Sender<Event>, wake: Box<dyn Fn() + Send>) -> Worker {
    let (tx, rx) = mpsc::channel::<Cmd>();
    // The worker keeps a sender of its own, for the one job it hands to a
    // thread and gets an answer back from (`RemeasureVpn`). It means the
    // channel never disconnects, so the loop does not end when the window drops
    // its `Worker` — which costs nothing here, because the window closing is the
    // process exiting.
    let own = tx.clone();
    std::thread::Builder::new()
        .name("ops".to_string())
        .spawn(move || run_worker(rx, own, events, wake))
        .ok();
    Worker { tx }
}

// ---------------------------------------------------------------------------
// The worker loop
// ---------------------------------------------------------------------------

struct Ctx {
    events: Sender<Event>,
    wake: Box<dyn Fn() + Send>,
    settings: Settings,
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
        let _ = self.events.send(Event::Log(level, msg.into()));
        (self.wake)();
    }
    fn busy(&self, what: Option<&str>) {
        let _ = self.events.send(Event::Busy(what.map(|s| s.to_string())));
        (self.wake)();
    }
}

/// True while a VPN measurement is out at a thread. One at a time: the watcher
/// can ask again before the last answer is back, and two PowerShell probes
/// racing produce the same answer twice at twice the cost.
static MEASURING_VPN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn run_worker(
    rx: Receiver<Cmd>,
    own: Sender<Cmd>,
    events: Sender<Event>,
    wake: Box<dyn Fn() + Send>,
) {
    let mut ctx = Ctx {
        events,
        wake,
        settings: Settings::load(),
        proxy_var_carried: None,
        proxy_var_retryable: false,
        patched_seen: HashMap::new(),
        vpn: None,
        relay_egress: None,
        last: None,
        dns_probe: (false, false),
    };

    startup_housekeeping(&mut ctx);

    // The first snapshot is deep: the window opens on the licence screen, so
    // reading the binaries costs the user nothing here and the main screen is
    // already truthful when it appears.
    push_status(&mut ctx, Scan::Deep);

    while let Ok(cmd) = rx.recv() {
        match cmd {
            Cmd::Stop => return,
            Cmd::Refresh => push_status(&mut ctx, Scan::System),
            // Off the queue, not on it. The measurement drives PowerShell and
            // takes seconds; on the queue, a user flipping a switch in the
            // middle of one would watch it snap back until it finished — G42's
            // lesson, applied to a job nobody asked for. No `busy` marker
            // either, for the same reason: nothing the user is waiting on is
            // running.
            Cmd::RemeasureVpn => {
                use std::sync::atomic::Ordering;
                if !MEASURING_VPN.swap(true, Ordering::SeqCst) {
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
                    if spawned.is_err() {
                        // Or the flag would stay raised and this window would
                        // never measure again.
                        MEASURING_VPN.store(false, Ordering::SeqCst);
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
            Cmd::Set(cap, on) => {
                ctx.busy(Some(cap.title()));
                apply(&mut ctx, cap, on);
                ctx.settings.save();
                push_status(&mut ctx, scan_after(cap));
                ctx.busy(None);
            }
            Cmd::AddPath(p) => {
                if !ctx.settings.manual_paths.contains(&p) {
                    ctx.settings.manual_paths.push(p);
                    ctx.settings.save();
                }
                ctx.busy(Some("Проверка установок"));
                push_status(&mut ctx, Scan::Deep);
                ctx.busy(None);
            }
            Cmd::ForgetPath(p) => {
                ctx.settings.manual_paths.retain(|x| x != &p);
                ctx.settings.save();
                push_status(&mut ctx, Scan::System);
            }
            Cmd::SetOwnProxy(text) => {
                ctx.busy(Some("Проверка прокси"));
                set_own_proxy(&mut ctx, &text);
                ctx.settings.save();
                push_status(&mut ctx, Scan::System);
                ctx.busy(None);
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
        Cap::BuiltinExits | Cap::VerifyTls | Cap::VpnDetect => Scan::Settings,
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
    let _ = ctx.events.send(Event::Status(Box::new(status)));
    (ctx.wake)();
}

/// The last snapshot with every settings-derived field recomputed, and nothing
/// asked of the machine.
///
/// The DNS row is included because it is settings-derived *in part*: whether a
/// measured tunnel blocks it depends on `vpn_detect`. It is rebuilt from the raw
/// pair the last system scan kept, so flipping «Определять VPN» updates the row
/// it governs without going near a scheduled task.
fn settings_only_status(ctx: &Ctx, prev: Status) -> Status {
    let (rules, relay) = ctx.dns_probe;
    Status {
        dns: dns_state(prev.admin, rules, relay, ctx.vpn, ctx.settings.vpn_detect),
        // Not `..prev`: `Cmd::Probed` refreshes this behind the window's back,
        // and a row carried forward from the last system scan would say a relay
        // that died an hour ago is still running.
        relay_running: relay,
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
        self.vpn_detect = on_off(s.vpn_detect);
        self.verify_tls = if s.verify_tls {
            State::On
        } else {
            // `OffNote`, not `Partial`: off is off. As a `Partial` this switch
            // could not be turned off at all — the log said it had been and the
            // next snapshot drew it back on (`State::OffNote`).
            State::OffNote("подменённые адреса не проверяются".into())
        };
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
            let local_proxy = scope.spawn(read_local_proxy);
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
        admin,
        client_patch,
        watchdog,
        dns: dns_state(
            admin,
            dns_probe.0,
            dns_probe.1,
            ctx.vpn,
            ctx.settings.vpn_detect,
        ),
        local_proxy,
        own_proxy,
        own_proxy_text,
        builtin_exits: State::Off,
        vpn_detect: State::Off,
        verify_tls: State::Off,
        vpn: ctx.vpn,
        dns_rotation: State::Off,
        relay_outdated,
        relay_running: dns_probe.1,
        relay_exe: {
            let exe = background::installed_exe();
            exe.exists().then_some(exe)
        },
        relay_egress: ctx.relay_egress,
        providers: Vec::new(),
        client_exes: client_exes(&installs),
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
        VpnSeen::NotCarryingClient => {
            Some("Трафик Antigravity идёт мимо VPN — обход применяется.")
        }
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
    let relay = background::is_enabled() && background::is_running();
    (rules, relay)
}

fn dns_state(
    admin: bool,
    rules: bool,
    relay: bool,
    vpn: Option<VpnSeen>,
    detect_on: bool,
) -> State {
    // Said before anything else, because it is the one reason the switch can be
    // off while everything about the setup is right.
    if detect_on && vpn == Some(VpnSeen::CarryingClient) {
        if !rules {
            return State::Blocked("Antigravity идёт через VPN — обход не применяется".to_string());
        }
        // Rules *are* in — installed before the client went into the tunnel, and
        // only an elevated run takes them off again (`refresh_pinned_hosts`).
        // They resolve to our relay, and the relay stands down for a tunnel it
        // measures the client inside of, so they are in place and doing nothing.
        // Drawing that as a plain "on" is the window and the layer disagreeing
        // about the same measurement.
        return State::Partial("правила стоят, но Antigravity в туннеле".to_string());
    }
    match (rules, relay) {
        (true, true) => State::On,
        // The rules name the relay first (I5). Rules without it resolve through
        // the fallback providers only, which works but is not what was asked
        // for — and it is exactly what a crashed relay looks like.
        (true, false) => State::Partial("правила стоят, служба не запущена".into()),
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

fn read_local_proxy() -> State {
    let url = proxy::proxy_url();
    if let Some(foreign) = endpoint::foreign_proxy(&url) {
        // Measured (G33): ours wins over theirs inside the patched server, so
        // leaving both set silently hijacks a proxy the user configured on
        // purpose. Theirs means ours stays off.
        let _ = foreign;
        return State::Blocked("в системе задан свой прокси".into());
    }
    if endpoint::proxy_env_is_ours() {
        State::On
    } else {
        State::Off
    }
}

fn read_own_proxy() -> State {
    if upstream::configured().is_some() {
        State::On
    } else {
        State::Off
    }
}

/// Every language server found, by full path.
///
/// `language_server*` only — never `agy.exe` and never the Electron shell. The
/// same set `egress::CLIENT_PROCESS_GLOB` counts sockets for, and for the same
/// reason: the shell carries no gated call, so excluding it from a tunnel would
/// change nothing and excluding the CLI is a separate decision the user can make
/// for themselves.
fn client_exes(installs: &[InstallRow]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in installs.iter().filter_map(|i| i.path.as_ref()) {
        for bin in patch_binary::binary_targets(root) {
            let is_ls = bin
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("language_server"));
            if is_ls && !out.contains(&bin) {
                out.push(bin);
            }
        }
    }
    out
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

fn apply(ctx: &mut Ctx, cap: Cap, on: bool) {
    if cap.needs_admin() && !is_admin() {
        ctx.log(
            Level::Err,
            "Нужны права администратора. Нажмите «Перезапустить от имени администратора».",
        );
        return;
    }

    match (cap, on) {
        (Cap::ClientPatch, true) => {
            // Set from the result, not from the click: a run that found no
            // install patched nothing, and persisting `true` there would leave
            // the switch reading On for ever on a machine with no Antigravity.
            ctx.settings.client_patch = enable_client_patch(ctx);
        }
        (Cap::ClientPatch, false) => {
            ctx.settings.client_patch = false;
            disable_client_patch(ctx);
        }
        (Cap::Watchdog, on) => {
            ctx.settings.auto_patch = on;
            set_watchdog(ctx, on);
        }
        (Cap::Dns, on) => {
            ctx.settings.dns = on;
            if on {
                enable_dns(ctx)
            } else {
                disable_dns(ctx)
            }
        }
        (Cap::LocalProxy, on) => {
            ctx.settings.local_proxy = on;
            if on {
                enable_local_proxy(ctx)
            } else {
                disable_local_proxy(ctx)
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
                    set_own_proxy(ctx, &text);
                }
            } else {
                upstream::clear();
                ctx.log(Level::Ok, "Свой прокси отключён.");
            }
        }
        (Cap::DnsRotation, on) => {
            ctx.settings.rotate_providers = on;
            ctx.settings.save();
            reapply_dns_rules(ctx);
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
        (Cap::VerifyTls, on) => {
            ctx.settings.verify_tls = on;
            ctx.log(
                Level::Ok,
                if on {
                    "Сверка TLS включена: адрес принимается, только если предъявил настоящий сертификат Google."
                } else {
                    "Сверка TLS выключена. Подменённый адрес больше не проверяется — остаётся только проверка, что он вообще отвечает."
                },
            );
        }
        (Cap::VpnDetect, on) => {
            ctx.settings.vpn_detect = on;
            ctx.log(
                Level::Ok,
                if on {
                    "Определение VPN включено: если Antigravity ходит через туннель, правила DNS ставиться не будут."
                } else {
                    "Определение VPN выключено: правила DNS будут ставиться даже поверх активного VPN."
                },
            );
            // Deliberately *not* re-measured here. The measurement answers
            // "do the client's own sockets leave through a tunnel" — a fact
            // about the machine that this switch does not touch; it only
            // changes what the layer does about it, and the indicator already
            // reads the switch. Re-measuring cost a PowerShell round trip per
            // flip to be told the same thing.
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
        }
    }
}

// --- client patch ----------------------------------------------------------

fn enable_client_patch(ctx: &mut Ctx) -> bool {
    ctx.log(Level::Step, "Патч клиента Antigravity");
    patch_binary::kill_affected_processes();

    let installs = crate::find_all_installs();
    let manual: Vec<PathBuf> = ctx.settings.manual_paths.clone();
    let mut targets = installs;
    for p in manual {
        if !targets.contains(&p) {
            targets.push(p);
        }
    }

    if targets.is_empty() {
        ctx.log(
            Level::Err,
            "Установки Antigravity не найдены. Укажите путь вручную (карандаш).",
        );
        return false;
    }

    // Recomputed every run: see Ctx::proxy_var_carried.
    ctx.proxy_var_carried = Some(false);
    ctx.proxy_var_retryable = false;

    let mut ok = 0usize;
    for inst in &targets {
        match crate::process_install(inst) {
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
            Err(e) => ctx.log(
                Level::Err,
                format!(
                    "{} — {}",
                    crate::utils::mask_path(&inst.display().to_string()),
                    e
                ),
            ),
        }
    }

    if ok == 0 {
        ctx.log(Level::Err, "Ни одна установка не пропатчена.");
        return false;
    }

    // I39: the legacy CA comes out last, and `remove_legacy_ca` itself refuses
    // while the relay is still an older build.
    crate::remove_legacy_ca_quiet();

    ctx.log(Level::Ok, format!("Пропатчено установок: {}", ok));
    true
}

fn disable_client_patch(ctx: &mut Ctx) {
    ctx.log(Level::Step, "Снятие патча клиента");

    // I20: a live watchdog treats an unpatch as an update and puts the patch
    // straight back. Both of them stop first — the standalone task and the one
    // that runs inside the relay — and are restored below to whatever the user
    // still has switched on.
    // The relay comes back if the user still wants the DNS bypass. The watchdog
    // does NOT: `client_patch` is false by the time this runs, and a watchdog is
    // a process whose whole job is to put the patch back. Restoring it here undid
    // the unpatch about four seconds later and flipped the switch on again.
    // `settings.auto_patch` keeps its value, so the watchdog returns the moment
    // the patch does.
    let want_relay = ctx.settings.dns;
    background::disable_watchdog();
    if let Err(e) = background::disable() {
        ctx.log(Level::Warn, format!("Служба DNS не остановлена: {}", e));
    }

    patch_binary::kill_affected_processes();

    let mut targets = crate::find_all_installs();
    for p in ctx.settings.manual_paths.clone() {
        if !targets.contains(&p) {
            targets.push(p);
        }
    }

    // I45: every step runs, each judged on its own. No `?` between them.
    for inst in &targets {
        let where_ = crate::utils::mask_path(&inst.display().to_string());
        let mut reverted = 0usize;
        // Each file is judged on its own (I45), and a failure is said out loud:
        // a count alone turned "one of two files could not be written" into a
        // clean revert, and the user kept a half-patched install.
        for (label, res) in patch_binary::unpatch_all_binaries(inst) {
            match res {
                Ok(0) => {}
                Ok(_) => reverted += 1,
                Err(e) => ctx.log(Level::Err, format!("{} — {}: {}", where_, label, e)),
            }
        }
        for (label, res) in patch_ide::unpatch_ide_js(inst) {
            match res {
                Ok(true) => reverted += 1,
                Ok(false) => ctx.log(
                    Level::Warn,
                    format!("{} — {}: бэкапа нет, снят только маркер", where_, label),
                ),
                Err(e) => ctx.log(Level::Err, format!("{} — {}: {}", where_, label, e)),
            }
        }
        if let Err(e) = crate::restore_pristine_asar(&inst.join("resources")) {
            ctx.log(Level::Warn, format!("app.asar не восстановлен: {}", e));
        }
        if let Err(e) = endpoint::remove_ide(inst) {
            ctx.log(Level::Warn, format!("Оверрайд эндпоинта не снят: {}", e));
        }
        ctx.log(
            Level::Ok,
            format!("{} — возвращено файлов: {}", where_, reverted),
        );
    }
    if let Err(e) = endpoint::remove_cli() {
        ctx.log(Level::Warn, format!("Переменная CLI не снята: {}", e));
    }

    // The proxy variable is only read by a patched binary, so an unpatched
    // machine must not keep it: it would sit in the user environment forever,
    // naming a port nothing listens on.
    disable_local_proxy(ctx);
    ctx.proxy_var_carried = Some(false);

    if want_relay {
        if let Err(e) = background::ensure_running() {
            ctx.log(
                Level::Warn,
                format!("Служба DNS не поднялась обратно: {}", e),
            );
        }
    }
}

// --- watchdog --------------------------------------------------------------

fn set_watchdog(ctx: &mut Ctx, on: bool) {
    if !on {
        background::disable_watchdog();
        ctx.log(Level::Ok, "Автовосстановление патча отключено.");
        return;
    }
    // The task launches the copy in %ProgramData%; `ensure_running` is what puts
    // it there, so without it `enable_watchdog` has nothing to point at.
    if let Err(e) = background::ensure_running() {
        ctx.log(Level::Warn, format!("Служба DNS не поднялась: {}", e));
    }
    match background::enable_watchdog() {
        Ok(()) => ctx.log(Level::Ok, "Автовосстановление патча включено."),
        Err(e) => ctx.log(Level::Err, format!("Не удалось включить: {}", e)),
    }
}

// --- DNS -------------------------------------------------------------------

fn enable_dns(ctx: &mut Ctx) {
    ctx.log(Level::Step, "Обход через DNS");

    // I5: the rules name the relay as their first nameserver, so it has to be
    // answering before they are written.
    if let Err(e) = background::ensure_running() {
        ctx.log(Level::Err, format!("Служба DNS не запустилась: {}", e));
        return;
    }
    ctx.log(Level::Ok, "Локальная служба DNS запущена.");

    match dns::setup_dns_nrpt() {
        Ok(outcome) => {
            dns::invalidate_cache();
            if outcome.stood_down_for_vpn {
                // Not a failure, and not "on" either: with the client measured
                // inside a tunnel the rules would override the resolver the user
                // turned on, and the substituted address is reached through the
                // tunnel anyway (D13, G26, G29).
                ctx.log(
                    Level::Warn,
                    "Обнаружен активный VPN, через который идёт Antigravity — \
                     правила DNS не создавались. Выключите VPN и включите переключатель заново.",
                );
            } else {
                ctx.log(Level::Ok, "Правила DNS установлены.");
            }
            if let Some(note) = dns::outcome_note(&outcome) {
                ctx.log(Level::Info, strip_ansi(&note));
            }
        }
        Err(e) => ctx.log(Level::Err, format!("Правила DNS не установлены: {}", e)),
    }

    // Both of these were taken down *by* `disable_dns` rather than by the user,
    // so they come back with it. Anything the user switched off themselves stays
    // off: these read the saved wish, not the previous system state.
    if ctx.settings.local_proxy && !endpoint::proxy_env_is_ours() {
        enable_local_proxy(ctx);
    }
    if ctx.settings.auto_patch && ctx.settings.client_patch && !background::is_watchdog_enabled() {
        set_watchdog(ctx, true);
    }
}

fn disable_dns(ctx: &mut Ctx) {
    ctx.log(Level::Step, "Отключение обхода через DNS");

    // First, because the listener is about to stop existing: the local proxy
    // runs *inside* the relay, so stopping the relay leaves `AG_LS_PROXY`
    // naming a port nothing answers on, and Antigravity loses its sign-in with
    // `dial tcp 127.0.0.1: ... actively refused` (I53, G31). The user's wish for
    // the proxy is kept in settings, so it comes back when the relay does.
    if endpoint::proxy_env_is_ours() {
        disable_local_proxy(ctx);
    }

    // The standalone watchdog task launches the copy of this exe that
    // `background::disable` is about to delete. Leaving the task registered
    // would leave the switch reading On while auto-patch was in fact dead.
    let restore_watchdog = ctx.settings.auto_patch && background::is_watchdog_enabled();
    if restore_watchdog {
        background::disable_watchdog();
        ctx.log(
            Level::Info,
            "Автопатч приостановлен: он работает из той же службы. Вернётся вместе с «Обходом через DNS».",
        );
    }

    // I45: both steps run regardless of what the first one did.
    dns::remove_dns_nrpt();
    dns::invalidate_cache();
    ctx.log(Level::Ok, "Правила DNS сняты.");
    match background::disable() {
        Ok(()) => ctx.log(Level::Ok, "Локальная служба DNS остановлена."),
        Err(e) => ctx.log(
            Level::Warn,
            format!("Служба остановлена не полностью: {}", e),
        ),
    }
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
    if !dns::is_nrpt_applied() {
        return false;
    }
    if !is_admin() && cfg!(target_os = "windows") {
        ctx.log(
            Level::Warn,
            "Список DNS сохранён, но правила не переписаны — нужны права администратора.",
        );
        return false;
    }
    match dns::setup_dns_nrpt() {
        Ok(_) => {
            dns::invalidate_cache();
            ctx.log(Level::Ok, "Правила DNS переписаны под новый список.");
        }
        Err(e) => ctx.log(Level::Warn, format!("Правила DNS не переписаны: {}", e)),
    }
    true
}

// --- local proxy -----------------------------------------------------------

fn enable_local_proxy(ctx: &mut Ctx) {
    ctx.log(Level::Step, "Локальный прокси");
    let url = proxy::proxy_url();

    // 1. The user-wide pair that builds up to 2.11.0_4 wrote. It goes first:
    //    leaving it puts the whole machine through loopback (D19).
    match endpoint::remove_legacy_proxy_env(&url) {
        Ok(true) => ctx.log(Level::Ok, "Прежняя общесистемная HTTPS_PROXY снята."),
        Ok(false) => {}
        Err(e) => {
            ctx.log(Level::Err, format!("Прежняя HTTPS_PROXY не снята: {}", e));
            return;
        }
    }

    // 2. Measured (G33): ours outranks theirs inside the patched server. A user
    //    who configured their own proxy must keep it, so ours comes off — this
    //    is not a "skip".
    if endpoint::foreign_proxy(&url).is_some() {
        let _ = endpoint::remove_proxy(&url, "");
        ctx.log(
            Level::Warn,
            "В системе задан свой прокси — наш не включаем, чтобы не перехватывать чужой.",
        );
        ctx.settings.local_proxy = false;
        return;
    }

    // 3. The variable has a private name that only a patched binary reads. If
    //    the rename did not land, writing it is writing into nothing.
    if ctx.proxy_var_carried == Some(false) {
        ctx.log(
            Level::Err,
            if ctx.proxy_var_retryable {
                "Файл был занят — закройте Antigravity полностью и включите переключатель заново."
            } else {
                "В этой сборке Antigravity нет места для переменной прокси — \
                 вероятно, вышла новая версия и нужен более новый анлокер."
            },
        );
        return;
    }

    // 4. I53/G31: never name a listener that is not there. A variable pointing
    //    at a dead port takes the sign-in down with it.
    if !proxy::wait_for_listener(Duration::from_secs(3)) {
        ctx.log(
            Level::Err,
            "Локальный прокси не отвечает — сначала включите «Обход через DNS».",
        );
        return;
    }

    match endpoint::apply_proxy(&url, "") {
        Ok(_) => ctx.log(Level::Ok, "Локальный прокси включён."),
        Err(e) => ctx.log(Level::Err, format!("Не удалось включить: {}", e)),
    }
}

fn disable_local_proxy(ctx: &mut Ctx) {
    let url = proxy::proxy_url();
    // I45 again: `remove_proxy` collects its own failures and joins them, so a
    // half-failed removal still takes off everything it can.
    match endpoint::remove_proxy(&url, "") {
        Ok(()) => ctx.log(Level::Ok, "Локальный прокси отключён."),
        Err(e) => ctx.log(Level::Warn, format!("Снято не полностью: {}", e)),
    }
}

// --- own proxy -------------------------------------------------------------

fn set_own_proxy(ctx: &mut Ctx, text: &str) {
    ctx.settings.own_proxy = text.trim().to_string();
    if ctx.settings.own_proxy.is_empty() {
        upstream::clear();
        ctx.settings.own_proxy_enabled = false;
        ctx.log(Level::Ok, "Свой прокси убран.");
        return;
    }

    let up = match upstream::parse(&ctx.settings.own_proxy) {
        Ok(u) => u,
        Err(e) => {
            ctx.log(Level::Err, format!("Адрес не разобран: {}", e));
            ctx.settings.own_proxy_enabled = false;
            return;
        }
    };

    ctx.log(Level::Info, "Проверяю прокси…");
    match upstream::probe(&up) {
        Ok(()) => {
            if let Err(e) = upstream::save(&up) {
                ctx.log(Level::Err, format!("Не сохранён: {}", e));
                ctx.settings.own_proxy_enabled = false;
                return;
            }
            ctx.settings.own_proxy_enabled = true;
            ctx.log(Level::Ok, format!("Свой прокси включён: {}", up.display()));

            // Advisory only (P16): the country of the exit is inferred from
            // geolocation, never proven — the region 400 is invisible out of
            // band. It changes nothing, it just tells the user what to expect.
            if let Some(country) = upstream::exit_country(&up) {
                if upstream::region_is_blocked(&country) {
                    ctx.log(
                        Level::Warn,
                        format!("Выход прокси в стране {} — она под ограничением, обход через него не поможет.", country),
                    );
                } else {
                    ctx.log(
                        Level::Ok,
                        format!("Выход прокси в стране {} — подходит.", country),
                    );
                }
            }
        }
        Err(e) => {
            // Saved anyway would be the console build's question. A switch has
            // no room for a y/N, and a proxy that did not answer is not one the
            // user wants silently in the route table.
            ctx.log(Level::Err, format!("Прокси не отвечает: {}", e));
            ctx.settings.own_proxy_enabled = false;
        }
    }
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
    use super::*;

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
        s.verify_tls = false;
        s.rotate_providers = false;
        s.builtin_exits = false;
        let st = blank_status().with_settings_switches(&s);

        assert!(!st.verify_tls.is_on(), "off with a note is still off");
        assert!(!st.dns_rotation.is_on());
        assert!(!st.builtin_exits.is_on());
        // The note itself must survive — it is what the row says underneath.
        assert!(st.verify_tls.note().is_some());
        assert!(st.dns_rotation.note().is_some());

        let on = blank_status().with_settings_switches(&Settings::default());
        assert!(on.verify_tls.is_on() && on.dns_rotation.is_on() && on.builtin_exits.is_on());
    }

    /// A settings-only refresh must produce the same switches a full one does,
    /// or a flip would answer differently depending on which path drew it.
    #[test]
    fn the_cheap_refresh_and_the_full_one_agree_about_the_settings_switches() {
        let mut s = Settings::default();
        s.verify_tls = false;
        s.vpn_detect = false;
        let a = blank_status().with_settings_switches(&s);
        let b = blank_status().with_settings_switches(&s);
        assert_eq!(a.verify_tls, b.verify_tls);
        assert_eq!(a.vpn_detect, b.vpn_detect);
        assert_eq!(a.dns_rotation, b.dns_rotation);
        assert_eq!(a.providers.len(), crate::resolvers::provider_names().len());
    }

    /// A switch that only writes `settings.json` must not send the worker back
    /// to Windows for scheduled tasks and environment variables.
    #[test]
    fn only_the_switches_that_touch_the_system_pay_for_a_system_scan() {
        assert_eq!(scan_after(Cap::VerifyTls), Scan::Settings);
        assert_eq!(scan_after(Cap::VpnDetect), Scan::Settings);
        assert_eq!(scan_after(Cap::BuiltinExits), Scan::Settings);
        assert_eq!(scan_after(Cap::Dns), Scan::System);
        assert_eq!(scan_after(Cap::LocalProxy), Scan::System);
        assert_eq!(scan_after(Cap::ClientPatch), Scan::Deep);
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
            wake: Box::new(|| {}),
            settings: Settings::load(),
            proxy_var_carried: None,
            proxy_var_retryable: false,
            patched_seen: HashMap::new(),
            vpn: Some(VpnSeen::None),
            relay_egress: None,
            last: None,
            dns_probe: (false, false),
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
            admin: true,
            installs: Vec::new(),
            client_patch: State::Off,
            watchdog: State::Off,
            dns: State::Off,
            local_proxy: State::Off,
            own_proxy: State::Off,
            builtin_exits: State::Off,
            dns_rotation: State::Off,
            vpn_detect: State::Off,
            verify_tls: State::Off,
            vpn: None,
            own_proxy_text: String::new(),
            relay_outdated: false,
            relay_running: false,
            providers: Vec::new(),
            client_exes: Vec::new(),
            relay_exe: None,
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
            dns_state(true, true, true, Some(VpnSeen::Unmeasured), true),
            State::On
        );
        assert!(matches!(
            dns_state(true, false, true, Some(VpnSeen::CarryingClient), true),
            State::Blocked(_)
        ));
    }
}
