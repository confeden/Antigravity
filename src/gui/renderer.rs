//! Which renderer opens the window, and how a machine that cannot run one gets
//! the next one instead of a program that does nothing.
//!
//! Three ways a renderer fails, and each needs its own net:
//!
//! * **It says so** — `run_native` returns an error (no adapter, no device).
//!   `gui::run` tries the next renderer in the same process.
//! * **It panics** — wgpu turns a driver's validation error into a panic, and the
//!   release profile is `panic = "abort"`: nothing unwinds back to `run`, and a
//!   windows-subsystem process dies without a word. The panic hook ([`install`])
//!   starts this exe again on the next renderer before the abort lands.
//! * **The driver itself crashes** — an access violation inside a vendor DLL,
//!   which no hook in this process sees. The attempt is written down *before* it
//!   is made ([`attempting`]) and only marked good once frames have gone out
//!   ([`confirm`]); a start that finds an attempt never confirmed begins with the
//!   renderer after it.
//!
//! The file is per user, in the same folder as `settings.json`, so the elevated
//! relaunch (`runas`, which does not carry our environment) reads the same answer.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use eframe::egui_wgpu;
use eframe::wgpu;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// DirectX 12 on the hardware adapter; WARP when there is none (wgpu lists
    /// the software adapter last, so it is picked only when nothing else is).
    #[cfg(windows)]
    Dx12,
    /// DirectX 12 on WARP, the software rasteriser in every Windows 10+. The net
    /// for a hardware adapter that is present and broken: a Haswell iGPU wgpu
    /// hides, a VM without 3D, an RDP session, a driver mid-update.
    #[cfg(windows)]
    Warp,
    /// wgpu's own pick: Vulkan, then GL.
    #[cfg(not(windows))]
    Wgpu,
    /// Plain OpenGL through glow. Last: it depends on a vendor OpenGL driver,
    /// which is exactly what a machine on the Basic Display Adapter lacks.
    Gl,
}

#[cfg(windows)]
pub const CHAIN: &[Kind] = &[Kind::Dx12, Kind::Warp, Kind::Gl];
#[cfg(not(windows))]
pub const CHAIN: &[Kind] = &[Kind::Wgpu, Kind::Gl];

/// Forces a renderer for this start: `dx12`, `warp`, `wgpu` or `gl`. Also what
/// the panic hook hands the next attempt, so the relaunch cannot loop back.
pub const ENV: &str = "AG_UNLOCKER_RENDERER";

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            #[cfg(windows)]
            Kind::Dx12 => "dx12",
            #[cfg(windows)]
            Kind::Warp => "warp",
            #[cfg(not(windows))]
            Kind::Wgpu => "wgpu",
            Kind::Gl => "gl",
        }
    }

    fn parse(s: &str) -> Option<Kind> {
        CHAIN.iter().copied().find(|k| k.name() == s.trim())
    }

    fn index(self) -> usize {
        CHAIN.iter().position(|k| *k == self).unwrap_or(0)
    }

    pub fn next(self) -> Option<Kind> {
        CHAIN.get(self.index() + 1).copied()
    }

    /// What a user would call it, for the one message that names it.
    pub fn label(self) -> &'static str {
        match self {
            #[cfg(windows)]
            Kind::Dx12 => "DirectX 12",
            #[cfg(windows)]
            Kind::Warp => "DirectX 12 (программный)",
            #[cfg(not(windows))]
            Kind::Wgpu => "Vulkan/GL",
            Kind::Gl => "OpenGL",
        }
    }

    pub fn renderer(self) -> eframe::Renderer {
        match self {
            Kind::Gl => eframe::Renderer::Glow,
            #[allow(unreachable_patterns)]
            _ => eframe::Renderer::Wgpu,
        }
    }

    /// The wgpu half of the options. Ignored by glow.
    pub fn wgpu_options(self) -> egui_wgpu::WgpuConfiguration {
        let mut config = egui_wgpu::WgpuConfiguration::default();
        #[cfg(windows)]
        {
            let mut setup = egui_wgpu::WgpuSetupCreateNew::without_display_handle();
            // Only what was compiled in (Cargo.toml), said again so a stray
            // `WGPU_BACKEND` in the user's environment cannot ask for anything
            // else.
            setup.instance_descriptor.backends = wgpu::Backends::DX12;
            // FXC ships with Windows (d3dcompiler_47.dll). The default, `Auto`,
            // first looks for dxcompiler.dll along PATH - a version this build
            // never saw, loaded into a process that usually runs elevated.
            setup
                .instance_descriptor
                .backend_options
                .dx12
                .shader_compiler = wgpu::Dx12Compiler::Fxc;
            // A window of switches needs no discrete GPU. The integrated one is
            // the one driving the screen on a laptop, and waking the other one
            // for this is how hybrid laptops flicker.
            setup.power_preference = wgpu::PowerPreference::LowPower;
            if self == Kind::Warp {
                setup.native_adapter_selector = Some(std::sync::Arc::new(|adapters, surface| {
                    adapters
                        .iter()
                        .find(|a| {
                            a.get_info().device_type == wgpu::DeviceType::Cpu
                                && surface.is_none_or(|s| a.is_surface_supported(s))
                        })
                        .cloned()
                        .ok_or_else(|| {
                            "программный адаптер DirectX 12 (WARP) не найден".to_string()
                        })
                }));
            }
            if dev_break(self) == Some("err") {
                setup.instance_descriptor.backends = wgpu::Backends::empty();
            }
            config.wgpu_setup = egui_wgpu::WgpuSetup::CreateNew(setup);
        }
        config
    }
}

/// A *debug* build's way to make one renderer fail on purpose, so every net
/// above can be watched working on a machine where nothing fails:
/// `AG_UNLOCKER_DEV_BREAK=dx12:err,warp:panic` (`err`, `panic` or `abort`, the
/// last standing in for a driver crash). Absent from release builds.
pub fn dev_break(kind: Kind) -> Option<&'static str> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let spec = std::env::var("AG_UNLOCKER_DEV_BREAK").ok()?;
    spec.split(',').find_map(|part| {
        let (k, how) = part.split_once(':')?;
        if Kind::parse(k) != Some(kind) {
            return None;
        }
        ["err", "panic", "abort"]
            .into_iter()
            .find(|h| *h == how.trim())
    })
}

/// The first-frame half of [`dev_break`].
pub fn dev_break_frame() {
    let Some(kind) = active() else { return };
    match dev_break(kind) {
        Some("panic") => panic!("AG_UNLOCKER_DEV_BREAK: {} panics", kind.name()),
        Some("abort") => std::process::abort(),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// The record of what this machine can run
// ---------------------------------------------------------------------------

fn record_path() -> std::path::PathBuf {
    crate::dns_forwarder::log_dir().join("renderer.txt")
}

/// `ok <kind> <version>` or `trying <kind> <version>`, one line.
///
/// A record another version wrote is no record: every update gets the whole
/// chain again (a newer wgpu, a fixed bug), so a machine is never stranded on
/// the software renderer by one bad start long ago. A machine that really
/// cannot run DirectX 12 pays one relaunch per version for that.
fn read_record() -> Option<(bool, Kind)> {
    if !crate::target_user::is_ready() {
        return None;
    }
    let text = std::fs::read_to_string(record_path()).ok()?;
    let mut parts = text.split_whitespace();
    let (state, kind, version) = (parts.next()?, parts.next()?, parts.next()?);
    if version != crate::update::current_version() {
        return None;
    }
    Some((state == "ok", Kind::parse(kind)?))
}

fn write_record(ok: bool, kind: Kind) {
    if !crate::target_user::is_ready() {
        return;
    }
    let path = record_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let state = if ok { "ok" } else { "trying" };
    // Best effort: a profile we cannot write to still gets the in-process chain
    // and the panic relaunch, which carries its answer in the environment.
    let version = crate::update::current_version();
    std::fs::write(&path, format!("{state} {} {version}\n", kind.name())).ok();
}

/// Persists the confirmed renderer once the target user profile is known.
pub fn persist_confirmed() {
    if !CONFIRMED.load(Ordering::SeqCst) {
        return;
    }
    let start = START
        .load(Ordering::SeqCst)
        .checked_sub(1)
        .and_then(|i| CHAIN.get(i).copied());
    if let Some(kind) = start.or_else(active) {
        write_record(true, kind);
    }
}

pub fn forget() {
    std::fs::remove_file(record_path()).ok();
}

/// Where this start begins. An explicit choice wins; then what the last start
/// learned; then the top of the chain.
pub fn first() -> Kind {
    if let Some(k) = std::env::var(ENV).ok().as_deref().and_then(Kind::parse) {
        return k;
    }
    match read_record() {
        Some((true, k)) => k,
        // Written before an attempt and never confirmed: that renderer took the
        // process down somewhere no error or panic reached us. The last one in
        // the chain is retried rather than skipped - there is nothing after it.
        Some((false, k)) => k.next().unwrap_or(k),
        None => CHAIN[0],
    }
}

// ---------------------------------------------------------------------------
// The attempt in progress, for the panic hook
// ---------------------------------------------------------------------------

/// `CHAIN` index + 1 of the renderer being tried; 0 while none is.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// `CHAIN` index + 1 of the renderer this process began with.
static START: AtomicUsize = AtomicUsize::new(0);
/// Set once enough frames went out that a panic is no longer the renderer's.
static CONFIRMED: AtomicBool = AtomicBool::new(false);

/// Called right before `run_native` with `kind`.
pub fn attempting(kind: Kind) {
    CONFIRMED.store(false, Ordering::SeqCst);
    ACTIVE.store(kind.index() + 1, Ordering::SeqCst);
    let _ = START.compare_exchange(0, kind.index() + 1, Ordering::SeqCst, Ordering::SeqCst);
    write_record(false, kind);
}

/// Called from the frame loop once frames have been presented.
pub fn confirm() {
    if CONFIRMED.swap(true, Ordering::SeqCst) {
        return;
    }
    // What is written is where this process *began*, not the renderer that
    // made it: anything between the two failed with an error, in-process, and
    // that costs the next start nothing to try again. Only a panic (relaunched
    // with the next one forced) or a crash (`trying` left behind) moves the start
    // down, which is when trying again costs a dead process.
    let start = START
        .load(Ordering::SeqCst)
        .checked_sub(1)
        .and_then(|i| CHAIN.get(i).copied());
    if let Some(kind) = start.or_else(active) {
        write_record(true, kind);
    }
}

fn active() -> Option<Kind> {
    ACTIVE
        .load(Ordering::SeqCst)
        .checked_sub(1)
        .and_then(|i| CHAIN.get(i).copied())
}

/// Replaces the default panic output — which a windows-subsystem process sends
/// nowhere — with something that acts on it:
///
/// * while a renderer is still unproven, this exe is started again on the next
///   one, with the choice in [`ENV`] so it holds even where the record cannot be
///   written. Each relaunch moves one step down a finite chain, so it ends;
/// * otherwise (the window was up, or nothing is left to try) the message is
///   shown, instead of the window vanishing with no trace.
pub fn install() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        let what = panic_text(info);
        // Only the main thread draws. A panic on a worker thread is not the
        // renderer's, and moving down the chain for it would only downgrade the
        // next start (and, in a debug build that unwinds, open a second window).
        let drawing = std::thread::current().name() == Some("main");
        if drawing && !CONFIRMED.load(Ordering::SeqCst) {
            // The record already says `trying` for the active one (`attempting`),
            // which is what makes the start after this one skip it too.
            if let Some(next) = active().and_then(Kind::next) {
                if relaunch_with(next) {
                    return;
                }
            }
        }
        // The window was up and the GPU went away under it: not a bug to show,
        // a device to replace. The panic then ends this process as usual.
        if drawing && CONFIRMED.load(Ordering::SeqCst) && is_gpu_loss_panic(&what) {
            if restart_after_gpu_loss() {
                return;
            }
        }
        crate::utils::message_box(
            "Antigravity Unlocker",
            &format!("Программа аварийно завершилась.\n\n{what}"),
        );
    }));
}

fn panic_text(info: &std::panic::PanicHookInfo<'_>) -> String {
    let msg = info
        .payload()
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_default();
    match info.location() {
        Some(l) => format!("{msg}\n({}:{})", l.file(), l.line()),
        None => msg,
    }
}

/// Starts this exe again with the same arguments and `kind` forced. Same token,
/// so an elevated window comes back elevated with no prompt.
fn relaunch_with(kind: Kind) -> bool {
    relaunch_with_env(kind, None)
}

fn relaunch_with_env(kind: Kind, restarts: Option<u32>) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1)).env(ENV, kind.name());
    if let Some(n) = restarts {
        cmd.env(RESTARTS_ENV, n.to_string());
    }
    cmd.spawn().is_ok()
}

// ---------------------------------------------------------------------------
// The GPU going away under a window that was fine
// ---------------------------------------------------------------------------

/// How many times in a row this exe has been started again because its GPU
/// device was lost, so a driver that keeps resetting cannot make a loop.
const RESTARTS_ENV: &str = "AG_UNLOCKER_GPU_RESTARTS";
const MAX_RESTARTS: u32 = 3;
/// Both the device-lost callback (its own thread) and the panic hook (the main
/// one) can see the same loss; only the first starts the new window.
static RESTARTING: AtomicBool = AtomicBool::new(false);

/// A driver reinstall, a TDR reset, or the display going to sleep can take the
/// GPU device away from a window that has been drawing for hours. wgpu then
/// refuses every allocation, and egui-wgpu turns the refusal into a panic
/// ("Failed to create staging buffer for index data", measured after an Nvidia
/// driver reinstall). The window cannot be repaired in place - its device, its
/// surface and every texture are gone - but a new process gets a fresh device,
/// so that is what happens, instead of a crash dialog on a screen that was off.
fn restart_after_gpu_loss() -> bool {
    let Some(kind) = active() else {
        return false;
    };
    let done = std::env::var(RESTARTS_ENV)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    if done >= MAX_RESTARTS || RESTARTING.swap(true, Ordering::SeqCst) {
        return false;
    }
    if relaunch_with_env(kind, Some(done + 1)) {
        return true;
    }
    RESTARTING.store(false, Ordering::SeqCst);
    false
}

/// Whether a panic message is the wgpu allocation failure a lost device ends in.
fn is_gpu_loss_panic(msg: &str) -> bool {
    msg.contains("Failed to create staging buffer")
        || msg.contains("Device is lost")
        || msg.contains("device is lost")
        || msg.contains("DeviceLost")
}

/// Called from `App::new` with the window's own device: when it is lost for any
/// reason but our own `destroy`, this process is replaced by a new one.
pub fn watch_device(device: &wgpu::Device) {
    device.set_device_lost_callback(|reason, _msg| {
        if reason != wgpu::DeviceLostReason::Destroyed && restart_after_gpu_loss() {
            std::process::exit(0);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_staging_buffer_panic_of_a_lost_device_is_recognised() {
        // Verbatim from a crash after an Nvidia driver reinstall.
        assert!(is_gpu_loss_panic(
            "Failed to create staging buffer for index data. Index count: 19776. \
             Required index buffer size: 79104. Actual size 171528 and capacity: 171528 (bytes)"
        ));
        assert!(!is_gpu_loss_panic("index out of bounds: the len is 3"));
    }

    #[test]
    fn every_renderer_round_trips_through_its_name() {
        for k in CHAIN {
            assert_eq!(Kind::parse(k.name()), Some(*k));
        }
        assert_eq!(Kind::parse("vulkan"), None);
    }

    #[test]
    fn the_chain_ends_and_opengl_is_last() {
        assert_eq!(CHAIN.last(), Some(&Kind::Gl));
        assert_eq!(Kind::Gl.next(), None);
        for pair in CHAIN.windows(2) {
            assert_eq!(pair[0].next(), Some(pair[1]));
        }
    }
}
