//! Composition root: every created process is retained until exit observation.
#[path = "child_environment.rs"]
pub(crate) mod child_environment;
#[path = "desktop_hook.rs"]
mod desktop_hook;
#[path = "desktop_launch.rs"]
mod desktop_launch;
#[path = "session.rs"]
pub(crate) mod session;
#[path = "windows_deployment.rs"]
mod windows_deployment;
#[path = "windows_installation.rs"]
pub(crate) mod windows_installation;
#[path = "discovery.rs"]
mod discovery;
pub(crate) use discovery::{registered_distributions, registered_distributions_with_cancel,
    observe_registered_distributions, DiscoveryObservation, Registration, MetadataContext, MetadataPurpose};
#[cfg(test)]
pub(crate) use discovery::test_diagnostic_text;
#[path = "process_identity.rs"]
pub(crate) mod process_identity;
#[path = "vendor_launch.rs"]
pub(crate) mod vendor_launch;
#[path = "gateway_native.rs"]
pub(crate) mod gateway_native;
pub(crate) fn system_wsl_program() -> Result<Pinned> { discovery::system_program(Path::new("wsl.exe")) }
pub(crate) fn receive_saved_context(bound: &Installation) -> Result<Option<windows_installation::AncestorAccessContext>> {
    windows_deployment::receive_for_installation(bound, None)
}
pub(crate) fn receive_for_background(inputs: &windows_installation::BackgroundInputs)
    -> Result<Option<windows_installation::AncestorAccessContext>> {
    windows_deployment::receive_for_background(inputs, None)
}
pub(crate) fn receive_for_diagnostic(inputs: &windows_installation::DiagnosticInputs)
    -> Result<Option<windows_installation::AncestorAccessContext>> {
    windows_deployment::receive_for_diagnostic(inputs, None)
}

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use windows_installation::{
    BoundInstallation as Installation, CheckedPath as Pinned, PathKind, PathPurpose,
    WindowsLocalPath,
};

// Console output is restricted to before actor acquisition or after settlement.
// Ignoring a closed output's write error is not a nonblocking-I/O guarantee.
macro_rules! println { ($($arg:tt)*) => {{ let _ = writeln!(std::io::stdout(), $($arg)*); }}; }

static CANCEL: AtomicBool = AtomicBool::new(false);
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
}
unsafe extern "system" fn cancel(event: u32) -> i32 {
    if event <= 1 {
        CANCEL.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}
struct ConsoleGuard;
impl ConsoleGuard {
    fn install() -> Result<Self> {
        CANCEL.store(false, Ordering::SeqCst);
        if unsafe { SetConsoleCtrlHandler(Some(cancel), 1) } == 0 {
            return Err("cannot install retained-owner console cancellation".into());
        }
        Ok(Self)
    }
}
impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        unsafe {
            SetConsoleCtrlHandler(Some(cancel), 0);
        }
    }
}
type Result<T> = std::result::Result<T, String>;
/// Existing owner observation cadence; this is not a retirement deadline.
pub(crate) const OWNER_OBSERVATION_CADENCE: Duration = Duration::from_millis(50);
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn io(context: &str, error: std::io::Error) -> String {
    format!("{context}: {error}")
}

#[derive(Clone)]
struct Options {
    operation: String,
    values: BTreeMap<String, OsString>,
    namespace: bool,
    clean: bool,
    legacy_expected: Option<windows_installation::ExpectedLegacyAttempt>,
}
impl Options {
    fn parse(args: Vec<OsString>) -> Result<Self> {
        let mut args = args.into_iter();
        let operation = args
            .next()
            .and_then(|v| v.into_string().ok())
            .ok_or("use --help for explicit inspect/stage/apply/revert/run inputs")?;
        if ![
            "--inspect",
            "--stage",
            "--apply",
            "--revert",
            "--run",
            "--recover",
            "--recover-initialization",
            "--import-legacy",
            "--collect-deployment-context",
        ]
        .contains(&operation.as_str())
        {
            return Err("unknown operation".into());
        }
        let mut result = Self {
            operation,
            values: BTreeMap::new(),
            namespace: false,
            clean: false,
            legacy_expected: None,
        };
        while let Some(key) = args.next() {
            let key = key.into_string().map_err(|_| "non-text option")?;
            if key == "--allow-source-namespace" {
                if result.namespace {
                    return Err("duplicate namespace admission".into());
                }
                result.namespace = true;
                continue;
            }
            if key == "--clean-start-window" {
                if result.clean {
                    return Err("duplicate clean-start window".into());
                }
                result.clean = true;
                continue;
            }
            if ![
                "--desktop",
                "--distro",
                "--output",
                "--deployment-context",
                "--provider",
                "--marker",
                "--provider-binary",
                "--delegate-roles",
                "--context-output",
                "--workspace-parent",
                "--operation-id",
                "--expected-current-sha256",
                "--legacy-producer",
                "--expected-manifest-sha256",
                "--expected-preimage-sha256",
                "--expected-candidate-sha256",
                "--expected-intent-sha256",
                "--expected-failure-sha256",
                "--helper-source",
                "--helper-installer",
                "--wsl",
                "--powershell",
                "--launcher",
                "--launcher-sha256",
                "--gateway-sha256",
                "--probe-ms",
                "--probe-bytes",
                "--opening-ms",
                "--header-bytes",
                "--max-active",
                "--poll-ms",
                "--startup-ms",
                "--stop-ms",
                "--status-bytes",
                "--topology-ms",
            ]
            .contains(&key.as_str())
            {
                return Err(format!("unknown option {key}"));
            }
            let value = args.next().ok_or("missing option value")?;
            if result.values.insert(key, value).is_some() {
                return Err("duplicate option".into());
            }
        }
        if result.operation != "--collect-deployment-context" {
            result.text("--distro")?;
        }
        result.path("--desktop")?;
        let pins = [
            "--expected-manifest-sha256",
            "--expected-preimage-sha256",
            "--expected-candidate-sha256",
            "--expected-intent-sha256",
            "--expected-failure-sha256",
        ];
        if result.operation == "--import-legacy" {
            result.legacy_expected = Some(result.parse_expected_legacy()?);
        } else if pins.iter().any(|k| result.values.contains_key(*k)) {
            return Err("expected legacy digests are import-only".into());
        }

        Ok(result)
    }
    fn text(&self, key: &str) -> Result<&str> {
        self.values
            .get(key)
            .and_then(|v| v.to_str())
            .filter(|v| !v.is_empty() && !v.chars().any(char::is_control))
            .ok_or_else(|| format!("missing/invalid {key}"))
    }
    fn path(&self, key: &str) -> Result<PathBuf> {
        let p = PathBuf::from(
            self.values
                .get(key)
                .ok_or_else(|| format!("missing {key}"))?,
        );
        WindowsLocalPath::parse(p.as_os_str())?;
        Ok(p)
    }
    fn expected_legacy(&self) -> Result<&windows_installation::ExpectedLegacyAttempt> {
        self.legacy_expected
            .as_ref()
            .ok_or("explicit five known legacy digests required".into())
    }
    fn parse_expected_legacy(&self) -> Result<windows_installation::ExpectedLegacyAttempt> {
        windows_installation::ExpectedLegacyAttempt::from_hex([
            self.text("--expected-manifest-sha256")?,
            self.text("--expected-preimage-sha256")?,
            self.text("--expected-candidate-sha256")?,
            self.text("--expected-intent-sha256")?,
            self.text("--expected-failure-sha256")?,
        ])
    }
    fn number(&self, key: &str) -> Result<u64> {
        self.text(key)?
            .parse::<u64>()
            .ok()
            .filter(|v| *v > 0)
            .ok_or_else(|| format!("invalid positive budget {key}"))
    }
    fn size(&self, key: &str) -> Result<usize> {
        usize::try_from(self.number(key)?).map_err(|_| format!("budget overflow {key}"))
    }
}
fn pin(path: &Path, directory: bool) -> Result<Pinned> {
    Pinned::open(
        path,
        if directory {
            PathKind::Directory
        } else {
            PathKind::File
        },
        PathPurpose::Source,
    )
}
fn pin_executable(path: &Path) -> Result<Pinned> {
    windows_installation::WindowsExecutablePath::parse(path.as_os_str())?;
    Pinned::open(path, PathKind::File, PathPurpose::Executable)
}
fn read(file: &mut File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0)).map_err(|e| io("seek", e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| io("read", e))?;
    Ok(bytes)
}
fn installation(executable: &Path) -> Result<Installation> {
    Installation::open(executable)
}
fn stage(options: &Options, input: &Installation) -> Result<()> {
    let output = options.path("--output")?;
    windows_installation::stage_review(input, &output, options.text("--distro")?)?;
    println!(
        "ReviewPackageReady: {} (installed application unchanged)",
        output.display()
    );
    Ok(())
}
struct Maintenance<'a> {
    desktop: &'a Path,
    ps: PathBuf,
    _ps_pin: Pinned,
    poll: Duration,
    budget: Duration,
    bytes: usize,
}
impl<'a> Maintenance<'a> {
    fn receive(options: &'a Options, desktop: &'a Path) -> Result<Self> {
        if !options.clean {
            return Err("MaintenanceRequired: complete installer/update/relaunch and hold a genuine no-launch/no-update window with --clean-start-window; installed bytes preserved".into());
        }
        let ps = options.path("--powershell")?;
        let pinned = pin_executable(&ps)?;
        Ok(Self {
            desktop,
            ps,
            _ps_pin: pinned,
            poll: Duration::from_millis(options.number("--poll-ms")?),
            budget: Duration::from_millis(options.number("--probe-ms")?),
            bytes: options.size("--probe-bytes")?,
        })
    }
}
fn desktop_absent(
    ps: &Path,
    desktop: &Path,
    budget: Duration,
    bytes: usize,
    poll: Duration,
) -> Result<()> {
    let target = desktop.to_str().ok_or("Desktop path encoding")?;
    let observation = probe(
        powershell(
            ps,
            r#"& { $target=$env:AG_COORD_TARGET; $ErrorActionPreference='Stop'; $name=[IO.Path]::GetFileName($target); $p=@(Get-CimInstance Win32_Process | Where-Object {$_.Name -ieq $name}); foreach($x in $p) { if (!$x.ExecutablePath -or $x.ExecutablePath -ieq $target) { throw 'DesktopAlreadyRunningOrUnknown' } }; 'AG_DESKTOP_ABSENT_V1' }"#,
            &[target],
        ),
        budget,
        bytes,
        poll,
    )?;
    if observation.trim() != "AG_DESKTOP_ABSENT_V1" {
        return Err(
            "MaintenanceRequired: Desktop active/unknown; preserve existing sessions".into(),
        );
    }
    Ok(())
}
impl windows_installation::MaintenanceWindow for Maintenance<'_> {
    fn ensure_held(&mut self) -> Result<()> {
        if CANCEL.load(Ordering::SeqCst) {
            return Err(
                "maintenance cancelled; preserve actual target/stage/recovery and inspect outcome"
                    .into(),
            );
        }
        // The operator's continuing actual window excludes detached installers and
        // competing launches. This targeted observation corroborates, never creates it.
        desktop_absent(&self.ps, self.desktop, self.budget, self.bytes, self.poll)
    }
}
pub(crate) fn desktop_absent_runtime(ps: &Pinned, desktop: &Path, cancel: &AtomicBool) -> Result<()> {
    let target = desktop.to_str().ok_or("Desktop path encoding")?;
    let command = powershell(ps.as_path(),
        r#"& { $target=$env:AG_COORD_TARGET; $ErrorActionPreference='Stop'; $name=[IO.Path]::GetFileName($target); $p=@(Get-CimInstance Win32_Process | Where-Object {$_.Name -ieq $name}); foreach($x in $p) { if (!$x.ExecutablePath -or $x.ExecutablePath -ieq $target) { throw 'DesktopAlreadyRunningOrUnknown' } }; 'AG_DESKTOP_ABSENT_V1' }"#, &[target]);
    let context = MetadataContext { purpose: MetadataPurpose::DesktopProcessCheck, distro: None, private_values: &[target] };
    let result = runtime_metadata(ps, command, cancel, false, context)?;
    if result.trim() != "AG_DESKTOP_ABSENT_V1" { return Err("MaintenanceRequired: закройте Antigravity обычным способом.".into()); }
    Ok(())
}
fn maintenance(options: &Options, desktop: &Path, input: Installation) -> Result<()> {
    let _console = ConsoleGuard::install()?;
    let mut window = Maintenance::receive(options, desktop)?;
    let workspace = options
        .values
        .get("--workspace-parent")
        .map(|_| options.path("--workspace-parent"))
        .transpose()?;
    if options.operation == "--import-legacy" {
        println!(
            "{}",
            windows_installation::import_legacy(
                input,
                &options.path("--output")?,
                options.text("--distro")?,
                &options.path("--legacy-producer")?,
                options.expected_legacy()?,
                &mut window
            )?
        );
        return Ok(());
    }
    if options.operation == "--recover-initialization" {
        println!(
            "{}",
            windows_installation::recover_initialization(
                input,
                options.text("--expected-current-sha256")?,
                &mut window
            )?
        );
        return Ok(());
    }
    if options.operation == "--recover" {
        // Mixed diagnostic caller supplies the existing gateway capability;
        // actual OperationKind dispatch below decides whether it is needed.
        let mut runner = gateway_native::WindowsGatewayRuleRunner::new(windows_installation::new_request_id)?;
        println!(
            "{}",
            windows_installation::recover(
                input,
                options.text("--operation-id")?,
                options.text("--expected-current-sha256")?,
                Some(windows_installation::GatewayRecoveryContext { runner: &mut runner, cancel: &CANCEL }),
                &mut window
            )?
        );
        return Ok(());
    }
    if options.operation == "--apply" {
        let review = windows_installation::receive_review(
            &input,
            &options.path("--output")?,
            options.text("--distro")?,
        )?;
        windows_installation::prepare_apply(input, review, workspace.as_deref(), &mut window)?
            .execute()?;
        println!("ArchiveApplied: canonical result, exact candidate and retained recovery received; Desktop not launched");
    } else {
        windows_installation::prepare_revert(input, workspace.as_deref(), &mut window)?
            .execute()?;
        println!("ArchiveReverted: canonical result, exact original and retained recovery received; Desktop not launched");
    }
    Ok(())
}

/// Read-only finite metadata command; bounded retained bytes, no detached readers.
/// On deadline/cancellation, keep custody until observed exit rather than lose a Child.
fn probe(mut command: Command, budget: Duration, bytes: usize, poll: Duration) -> Result<String> {
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or("probe deadline overflow")?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| io("metadata probe spawn", e))?;
    let mut pipe = child
        .stdout
        .take()
        .expect("Command with piped stdout owns its pipe");
    let reader = match thread::Builder::new()
        .name("wsl-metadata-reader".into())
        .spawn(move || {
            let mut output = Vec::new();
            let mut oversize = false;
            let mut buffer = [0u8; 4096];
            loop {
                let n = pipe.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                let keep = n.min(bytes.saturating_sub(output.len()));
                output.extend_from_slice(&buffer[..keep]);
                oversize |= keep < n;
            }
            Ok::<_, std::io::Error>((output, oversize))
        }) {
        Ok(r) => r,
        Err(e) => {
            let (exit, observation_error) = observe(&mut child, poll);
            return Err(format!(
                "{}; child={exit}; exit_observation={observation_error:?}",
                io("probe reader spawn", e)
            ));
        }
    };
    let mut expired = false;
    let mut observation_error = None;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(exit)) => break Ok(exit),
            Ok(None) => {}
            Err(error) => {
                observation_error = Some(format!("probe exit observation: {error}"));
                break child
                    .wait()
                    .map_err(|e| format!("probe observation {error}; wait {e}"));
            }
        }
        if !expired && (Instant::now() >= deadline || CANCEL.load(Ordering::SeqCst)) {
            expired = true;
        }
        thread::sleep(poll);
    };
    // A failed native wait must not release the owned handle into an error return.
    let exit = match exit {
        Ok(e) => e,
        Err(e) => {
            let (exit, later_error) = observe(&mut child, poll);
            observation_error = Some(format!("{e}; later_observation={later_error:?}"));
            exit
        }
    };
    while !reader.is_finished() {
        thread::sleep(poll);
    }
    let (output, oversize) = reader
        .join()
        .map_err(|_| "probe reader panic")?
        .map_err(|e| io("probe reader", e))?;
    if expired || !exit.success() || oversize || observation_error.is_some() {
        return Err(format!("metadata probe failed: exit={exit}, deadline_or_cancel={expired}, output_budget_exceeded={oversize}, exit_observation={observation_error:?}; no observation admitted"));
    }
    String::from_utf8(output).map_err(|_| "probe output must be UTF-8".into())
}
fn observe(
    child: &mut Child,
    poll: Duration,
) -> (std::process::ExitStatus, Option<std::io::Error>) {
    let mut first_error = None;
    loop {
        match child.try_wait() {
            Ok(Some(exit)) => return (exit, first_error),
            Ok(None) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
        thread::sleep(poll);
    }
}
fn powershell(path: &Path, script: &str, values: &[&str]) -> Command {
    let mut command = Command::new(path);
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ]);
    // PowerShell parses trailing -Command arguments as code. Supply selected path
    // through this command's private environment, never its command text.
    if let Some(value) = values.first() {
        command.env("AG_COORD_TARGET", value);
    }
    command
}

const DISCOVER: &str = r#"set -eu
printf '%s\n' 'AG_CONTEXT_V1'
id -u; id -g; id -un; printf '%s\n' "$HOME"; uname -m
readlink /proc/self/ns/net
ip -4 route show default
"#;
fn wsl_command(path: &Path, distro: &str, script: &str, values: &[&str]) -> Command {
    let mut command = Command::new(path);
    command
        .args(["-d", distro, "--exec", "sh", "-c", script, "sh"])
        .args(values);
    command
}
fn source_route(text: &str, bind: Ipv4Addr) -> Result<Ipv4Addr> {
    let fields: Vec<_> = text.split_whitespace().collect();
    if fields.first() != Some(&bind.to_string().as_str()) {
        return Err("NoBind: route destination mismatch".into());
    }
    let sources: Vec<_> = fields.windows(2).filter(|p| p[0] == "src").collect();
    if sources.len() != 1 {
        return Err("NoBind: source route ambiguous".into());
    }
    let source: Ipv4Addr = sources[0][1]
        .parse()
        .map_err(|_| "NoBind: invalid source")?;
    if source.is_unspecified()
        || source.is_loopback()
        || source.is_multicast()
        || source.is_broadcast()
    {
        return Err("NoBind: unsupported source".into());
    }
    Ok(source)
}
fn verify_helper(text: &str, expected: &str, architecture: &str) -> Result<()> {
    let mut lines = text.lines();
    if lines.next() != Some("AG_HELPER_V1")
        || lines.next().and_then(|line| line.split_whitespace().next()) != Some(expected)
    {
        return Err(
            "MaintenanceRequired: installed Linux helper identity verification failed".into(),
        );
    }
    let header = lines
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .map(str::parse::<u8>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "invalid helper ELF metadata")?;
    if header.len() != 20
        || header[..6] != [127, b'E', b'L', b'F', 2, 1]
        || u16::from_le_bytes([header[18], header[19]])
            != match architecture {
                "x86_64" => 62,
                "aarch64" => 183,
                _ => return Err("unsupported helper architecture".into()),
            }
    {
        return Err("MaintenanceRequired: installed Linux helper ELF architecture mismatch".into());
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Context {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) user: String,
    pub(crate) home: String,
    pub(crate) architecture: String,
    pub(crate) namespace: String,
    pub(crate) interface: u32,
    pub(crate) interface_alias: String,
    pub(crate) bind: Ipv4Addr,
    pub(crate) source: Ipv4Addr,
}
pub(crate) struct LinuxIdentity {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) user: String,
    pub(crate) home: String,
    pub(crate) architecture: String,
}
fn receive_identity(lines: &mut std::str::Lines<'_>) -> Result<LinuxIdentity> {
    Ok(LinuxIdentity {
        uid: lines.next().ok_or("missing UID")?.parse().map_err(|_| "invalid UID")?,
        gid: lines.next().ok_or("missing GID")?.parse().map_err(|_| "invalid GID")?,
        user: lines.next().filter(|value| !value.is_empty()).ok_or("missing default user")?.to_owned(),
        home: lines.next().filter(|value| value.starts_with('/')).ok_or("missing actual HOME")?.to_owned(),
        architecture: lines.next().filter(|value| ["x86_64", "aarch64"].contains(value))
            .ok_or("unsupported architecture")?.to_owned(),
    })
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsAdapter {
    address: Ipv4Addr,
    interface: u32,
    alias: String,
    #[serde(rename = "virtual")]
    virtual_adapter: bool,
    hardware: bool,
    description: String,
}
fn receive_adapter(text: &str, expected: Ipv4Addr) -> Result<WindowsAdapter> {
    let adapter: WindowsAdapter = serde_json::from_str(text)
        .map_err(|e| format!("NoBind: Windows adapter metadata unavailable: {e}"))?;
    if adapter.address != expected
        || adapter.interface == 0
        || adapter.alias.is_empty()
        || adapter.alias.chars().any(char::is_control)
        || !adapter.virtual_adapter
        || adapter.hardware
        || adapter.description != "Hyper-V Virtual Ethernet Adapter"
    {
        return Err("NoBind: selected route gateway is not an independently recognized active Windows Hyper-V virtual interface; physical/unknown adapters are unsupported".into());
    }
    Ok(adapter)
}
fn discover(
    options: &Options,
    wsl: &Path,
    ps: &Path,
    poll: Duration,
    budget: Duration,
    bytes: usize,
) -> Result<Context> {
    let distro = options.text("--distro")?;
    discover_with(distro, wsl, ps, |_, command, _| probe(command, budget, bytes, poll))
}
fn discover_with(distro: &str, wsl: &Path, ps: &Path, mut receive: impl FnMut(MetadataPurpose, Command, &[&str]) -> Result<String>) -> Result<Context> {
    let context = receive(MetadataPurpose::GuestNetworkContext, wsl_command(wsl, distro, DISCOVER, &[]), &[])?;
    let mut lines = context.lines();
    if lines.next() != Some("AG_CONTEXT_V1") {
        return Err("NoBind: context schema".into());
    }
    let LinuxIdentity { uid, gid, user, home, architecture } = receive_identity(&mut lines)?;
    let namespace = lines
        .next()
        .filter(|v| v.starts_with("net:[") && v.ends_with(']'))
        .ok_or("NoBind: namespace observation unavailable")?;
    let routes: Vec<_> = lines.filter(|line| !line.trim().is_empty()).collect();
    if routes.len() != 1 {
        return Err(
            "NoBind: no unique selected-distro default route; topology needs review".into(),
        );
    }
    let fields: Vec<_> = routes[0].split_whitespace().collect();
    if fields.first() != Some(&"default") {
        return Err("NoBind: default route syntax".into());
    }
    let gateways: Vec<_> = fields.windows(2).filter(|pair| pair[0] == "via").collect();
    if gateways.len() != 1 {
        return Err("NoBind: no unique IPv4 gateway".into());
    }
    let bind: Ipv4Addr = gateways[0][1]
        .parse()
        .map_err(|_| "NoBind: invalid gateway")?;
    if bind.is_unspecified() || bind.is_loopback() || bind.is_multicast() || bind.is_broadcast() {
        return Err("NoBind: unsupported gateway".into());
    }
    // Match the observed Linux next hop to an actual current Windows interface,
    // without assuming adapter alias, fixed IP or distro layout.
    let bind_text = bind.to_string();
    let adapter = receive(MetadataPurpose::HostAdapterQuery,
        powershell(
            ps,
            r#"& { $ErrorActionPreference='Stop'; $target=$env:AG_COORD_TARGET; $ips=@(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -eq $target -and $_.AddressState -eq 'Preferred'}); if($ips.Count -ne 1){throw 'NoBind: Windows interface ambiguity'}; $a=@(Get-NetAdapter -IncludeHidden | Where-Object {$_.ifIndex -eq $ips[0].InterfaceIndex -and $_.Status -eq 'Up'}); if($a.Count -ne 1){throw 'NoBind: Windows adapter unavailable'}; [ordered]@{address=$ips[0].IPAddress; interface=[uint32]$a[0].ifIndex; alias=[string]$a[0].Name; virtual=[bool]$a[0].Virtual; hardware=[bool]$a[0].HardwareInterface; description=[string]$a[0].InterfaceDescription} | ConvertTo-Json -Compress }"#,
            &[&bind_text],
        ), &[&home, &user, &bind_text],
    )?;
    let adapter = receive_adapter(&adapter, bind)?;
    let route = receive(MetadataPurpose::GuestNetworkContext,
        wsl_command(
            wsl,
            distro,
            "set -eu; ip -4 route get \"$1\"",
            &[&bind_text],
        ), &[&home, &user, &bind_text],
    )?;
    let source = source_route(&route, bind)?;
    if source == bind {
        return Err("NoBind: shared/default address cannot establish isolated topology".into());
    }
    Ok(Context {
        uid,
        gid,
        user,
        home,
        architecture,
        namespace: namespace.to_owned(),
        interface: adapter.interface,
        interface_alias: adapter.alias,
        bind,
        source,
    })
}

pub(crate) fn system_powershell_program() -> Result<Pinned> {
    discovery::system_program(Path::new(r"WindowsPowerShell\v1.0\powershell.exe"))
}
pub(crate) fn active_firewall_profiles(program: &Pinned, cancel: &AtomicBool) -> Result<u32> {
    let mut command = Command::new(program.as_path());
    command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); ConvertTo-Json -InputObject ([uint32](New-Object -ComObject HNetCfg.FwPolicy2).CurrentProfileTypes) -Compress"]);
    let output = runtime_metadata(program, command, cancel, false, MetadataContext::new(MetadataPurpose::FirewallProfileQuery, None))?;
    serde_json::from_str(output.trim()).map_err(|_| "active firewall profile receiving failed".into())
}
pub(crate) fn runtime_metadata(program: &Pinned, command: Command, cancel: &AtomicBool, wsl_exec: bool, context: MetadataContext<'_>) -> Result<String> {
    let output = if wsl_exec { discovery::metadata_output_natural(program, command, cancel, context)? }
        else { discovery::metadata_output(program, command, cancel, context)? };
    let stderr = output.diagnostic_stderr(context);
    String::from_utf8(output.stdout).map_err(|_| format!("{}: private metadata output encoding; exit=success; capture=complete; stderr={stderr}", context.heading()))
}
fn discovery_metadata_context<'a>(purpose: MetadataPurpose, distro: &'a str, private_values: &'a [&'a str]) -> MetadataContext<'a> {
    MetadataContext { purpose, distro: Some(distro), private_values }
}
pub(crate) fn discover_runtime_context(wsl: &Pinned, ps: &Pinned, distro: &str, cancel: &AtomicBool) -> Result<Context> {
    discover_with(distro, wsl.as_path(), ps.as_path(), |purpose, command, private_values| {
        let linux = command.get_program() == wsl.as_path().as_os_str();
        runtime_metadata(if linux { wsl } else { ps }, command, cancel, linux,
            discovery_metadata_context(purpose, distro, private_values))
    })
}
pub(crate) fn discover_runtime_identity(wsl: &Pinned, distro: &str, cancel: &AtomicBool) -> Result<LinuxIdentity> {
    let output = runtime_metadata(wsl, wsl_command(wsl.as_path(), distro,
        r#"set -eu; printf '%s\n' AG_USER_V1; id -u; id -g; id -un; printf '%s\n' "$HOME"; uname -m"#, &[]), cancel, true, MetadataContext::new(MetadataPurpose::GuestIdentity, Some(distro)))?;
    let mut lines = output.lines();
    if lines.next() != Some("AG_USER_V1") { return Err("default-user metadata schema".into()); }
    let identity = receive_identity(&mut lines)?;
    if lines.next().is_some() { return Err("default-user metadata trailing fields".into()); }
    Ok(identity)
}
pub(crate) fn provision_runtime_helper(wsl: &Pinned, distro: &str, assets: &windows_installation::PackageAssets,
    architecture: &str, guest_home: &str, cancel: &AtomicBool) -> Result<String> {
    assets.recheck()?;
    let convert = |path: &Path| -> Result<String> {
        let mut command = Command::new(wsl.as_path());
        command.args(["-d", distro, "--exec", "wslpath", "-a", "--"]).arg(path);
        let source_path = path.to_string_lossy();
        let output = runtime_metadata(wsl, command, cancel, true, MetadataContext { purpose: MetadataPurpose::HelperPath, distro: Some(distro), private_values: &[source_path.as_ref(), guest_home] })?;
        let value = output.trim();
        if value.lines().count() != 1 || !child_environment::valid_launcher(value) { return Err("helper deployment path unavailable".into()); }
        Ok(value.into())
    };
    let source = convert(assets.helper_path())?;
    let installer = convert(assets.installer_path())?;
    assets.recheck()?;
    let mut command = Command::new(wsl.as_path());
    command.args(["-d", distro, "--exec", "sh", &installer, &source, assets.helper_digest()]);
    let output = runtime_metadata(wsl, command, cancel, true, MetadataContext { purpose: MetadataPurpose::HelperProvision, distro: Some(distro), private_values: &[&source, &installer, guest_home] })?;
    let launcher = output.trim();
    if launcher.lines().count() != 1 || !child_environment::valid_launcher(launcher) { return Err("helper installation receipt invalid".into()); }
    let receipt = runtime_metadata(wsl, wsl_command(wsl.as_path(), distro, VERIFY_HELPER, &[launcher]), cancel, true,
        MetadataContext { purpose: MetadataPurpose::HelperVerify, distro: Some(distro), private_values: &[launcher, guest_home] })?;
    verify_helper(&receipt, assets.helper_digest(), architecture)?;
    assets.recheck()?;
    Ok(launcher.into())
}

const VERIFY_HELPER: &str = r#"set -eu
p=$1
[ "$(stat -c %u "$p")" = "$(id -u)" ] || exit 62
while [ "$p" != / ]; do
 [ ! -L "$p" ] || exit 61
 owner=$(stat -c %u "$p"); [ "$owner" = "$(id -u)" ] || [ "$owner" = 0 ] || exit 62
 mode=$(stat -c %a "$p"); [ $((0$mode & 022)) = 0 ] || exit 63
 p=${p%/*}; [ -n "$p" ] || p=/
done
[ -f "$1" ] && [ -x "$1" ]
printf '%s\n' AG_HELPER_V1
sha256sum -- "$1"
od -An -tu1 -N20 -- "$1"
"#;

/// Legacy/recovery-test adapter. Production entry points use the typed Main
/// roles and GUI controller; no shipped binary exposes this argv workflow.
pub fn execute(args: Vec<OsString>) -> Result<()> {
    if args == [OsString::from("--help")] {
        println!("{}", concat!(
            "ag_wsl OPERATION --desktop <absolute .exe> --distro <explicit name>\n",
            "--stage: --output <new absolute review folder>; installed application unchanged\n",
            "--inspect: --wsl <absolute wsl.exe> --powershell <absolute powershell.exe>\n",
            "--apply: --output <existing reviewed folder>; --revert uses canonical retained recovery, not --output. Both: --powershell <absolute powershell.exe> --clean-start-window [--workspace-parent <existing private target-volume directory>]\n",
            "--run: canonical settled hook; --wsl/--powershell as above; --helper-source <absolute package helper> --helper-installer <absolute existing installer> (or --launcher <existing absolute Linux path>); --launcher-sha256 HEX --gateway-sha256 HEX --allow-source-namespace --clean-start-window\n",
            "--import-legacy also requires caller-known --expected-manifest-sha256/--expected-preimage-sha256/--expected-candidate-sha256/--expected-intent-sha256/--expected-failure-sha256; no self-derived defaults. Originals are pinned external input, copied only to canonical Pending.\n",
            "--import-legacy: --output <original schema1 review> --legacy-producer <exact received old CLI>; --recover: --operation-id ID --expected-current-sha256 HEX; --recover-initialization: --expected-current-sha256 HEX. All require the qualified maintenance inputs.\n",
            "--collect-deployment-context: --desktop EXE --provider codex-windows-sandbox-v1 --marker FILE --provider-binary <physical signed codex.exe> --delegate-roles offline,online --context-output <new private DATA file>; no launch/canonical operation.\n",
            "--deployment-context <private DATA file> explicitly overrides shared saved DATA; omission uses the protected KnownFolder product default when present. Missing saved DATA supplies empty context; invalid/stale/IO never falls back. Current user/machine, registration, signature, roles, native IDs and issuer facts are freshly received.\n",
            "Every operation except --stage requires --probe-ms N --probe-bytes N --poll-ms N.\n",
            "--run also requires --opening-ms N --header-bytes N --max-active N --startup-ms N --stop-ms N --status-bytes N --topology-ms N.\n",
            "All budgets are explicit; bytes bound metadata/header memory, never stream size.\n",
            "Source-only mode admits ALL processes sharing the observed source IP, including unseen/future peers; no user/distro authentication. Operator must receive current population/trust first.\n",
            "Clean-start window: finished installer/update/relaunch; no competing product launches/updates through completion or recovery. Existing sessions are preserved.\n",
            "WSL inspection can start the explicitly selected distro. Unknown topology returns NoBind.\n",
            "Ctrl+C retains the live endpoint and Desktop until Desktop is closed normally. Exit zero proves neither actual WSL use nor a model response.\n",
            "Canonical recovery lives under the current user KnownFolder/AGUnlocker/wsl-installations; review may be on another volume. Pending holds every apply/revert/run before any helper/probe/gateway/Desktop. Keep original review and recovery evidence private.\n"
        ));
        return Ok(());
    }
    let options = Options::parse(args)?;
    let desktop = options.path("--desktop")?;
    let mut input = installation(&desktop)?;
    let desktop = input.executable().as_path().to_path_buf();
    if options.operation == "--collect-deployment-context" {
        windows_deployment::collect(
            &input,
            options.text("--provider")?,
            options.text("--delegate-roles")?,
            &options.path("--marker")?,
            &options.path("--provider-binary")?,
            &options.path("--context-output")?,
        )?;
        println!("DeploymentContextCollected: private nonauthorizing data independently received; no canonical/native/application operation");
        return Ok(());
    }
    let explicit_context = options
        .values
        .get("--deployment-context")
        .map(|_| options.path("--deployment-context"))
        .transpose()?;
    if let Some(context) =
        windows_deployment::receive_for_installation(&input, explicit_context.as_deref())?
    {
        input.attach_ancestor_context(context)?;
    }

    if [
        "--apply",
        "--revert",
        "--recover",
        "--recover-initialization",
        "--import-legacy",
    ]
    .contains(&options.operation.as_str())
    {
        return maintenance(&options, &desktop, input);
    }
    if options.operation == "--run" {
        let mut runnable = windows_installation::admit_run(input)?;
        if !options.namespace {
            return Err("NoBind: explicit --allow-source-namespace is required; source namespace access is not per-user authentication".into());
        }
        if !options.clean {
            return Err("MaintenanceRequired: finish product installer/update/relaunch, close Desktop normally, and declare --clean-start-window while preventing other launches/updates; current sessions preserved".into());
        }
        return run(&options, &desktop, runnable.installation());
    }
    let inspection = desktop_hook::inspect_archive(input.bytes()).map_err(|e| e.to_string())?;
    println!("DiskInspection: version={} archive={} desktop={} hook={:?}; explicit distro={}; active producer and model use unverified", inspection.version, inspection.digest, input.executable_digest(), inspection.hook_status, options.text("--distro")?);
    if options.operation == "--stage" {
        return stage(&options, &input);
    }
    if options.operation == "--inspect" {
        let _console = ConsoleGuard::install()?;
        let poll = Duration::from_millis(options.number("--poll-ms")?);
        let budget = Duration::from_millis(options.number("--probe-ms")?);
        let bytes = options.size("--probe-bytes")?;
        let wsl = options.path("--wsl")?;
        let ps = options.path("--powershell")?;
        let _wsl = pin_executable(&wsl)?;
        let _ps = pin_executable(&ps)?;
        let context = discover(&options, &wsl, &ps, poll, budget, bytes)?;
        println!("DistroInspection: default-uid/gid={}/{}; architecture={}; namespace={}; HOME observed=true; Windows-interface={}/{}; route-source={}; namespace population/trust not inferred", context.uid, context.gid, context.architecture, context.namespace, context.interface, context.bind, context.source);
        return Ok(());
    }
    Err("unsupported operation after admission".into())
}

fn provision_helper(
    options: &Options,
    wsl: &Path,
    distro: &str,
    poll: Duration,
    budget: Duration,
    bytes: usize,
) -> Result<String> {
    if options.values.contains_key("--helper-source")
        || options.values.contains_key("--helper-installer")
    {
        if options.values.contains_key("--launcher") {
            return Err("choose helper provisioning or existing launcher, not both".into());
        }
        let source = options.path("--helper-source")?;
        let installer = options.path("--helper-installer")?;
        let mut source_pin = pin(&source, false)?;
        let _installer_pin = pin(&installer, false)?;
        if digest(&read(&mut source_pin.file)?) != options.text("--launcher-sha256")? {
            return Err("helper source digest mismatch".into());
        }
        let convert = |path: &Path| -> Result<String> {
            let mut command = Command::new(wsl);
            command
                .args(["-d", distro, "--exec", "wslpath", "-a", "--"])
                .arg(path);
            let value = probe(command, budget, bytes, poll)?;
            let line = value.trim();
            if line.lines().count() != 1
                || !line.starts_with('/')
                || line.chars().any(char::is_control)
            {
                return Err("helper deployment wslpath invalid".into());
            }
            Ok(line.into())
        };
        let linux_source = convert(&source)?;
        let linux_installer = convert(&installer)?;
        let mut command = Command::new(wsl);
        command.args([
            "-d",
            distro,
            "--exec",
            "sh",
            &linux_installer,
            &linux_source,
            options.text("--launcher-sha256")?,
        ]);
        let installed = probe(command, budget, bytes, poll)?;
        let installed = installed.trim();
        if installed.lines().count() != 1 || !child_environment::valid_launcher(installed) {
            return Err("helper installation receipt invalid".into());
        }
        Ok(installed.into())
    } else {
        Ok(options.text("--launcher")?.into())
    }
}

fn run(options: &Options, desktop: &Path, input: &mut Installation) -> Result<()> {
    let poll = Duration::from_millis(options.number("--poll-ms")?);
    let probe_budget = Duration::from_millis(options.number("--probe-ms")?);
    let probe_bytes = options.size("--probe-bytes")?;
    // discover owns three serial metadata commands; derive its total observation
    // deadline from their caller-supplied budgets, not an arbitrary timeout.
    let observation_budget = probe_budget
        .checked_mul(3)
        .ok_or("topology observation budget overflow")?;
    Instant::now()
        .checked_add(observation_budget)
        .ok_or("topology deadline overflow")?;
    let topology_interval = Duration::from_millis(options.number("--topology-ms")?);
    Instant::now()
        .checked_add(topology_interval)
        .ok_or("topology interval overflow")?;
    let ps = options.path("--powershell")?;
    let wsl = options.path("--wsl")?;
    let _ps = pin_executable(&ps)?;
    let _wsl = pin_executable(&wsl)?;
    let distro = options.text("--distro")?;
    let gateway = std::env::current_exe().map_err(|e| io("coordinator identity", e))?;
    let mut gateway_pin = pin_executable(&gateway)?;
    let gateway_digest = digest(&read(&mut gateway_pin.file)?);
    if gateway_digest != options.text("--gateway-sha256")? {
        return Err("gateway input identity mismatch".into());
    }
    let _console = ConsoleGuard::install()?;
    let result = (|| {
        // Unknown executable path for a same-name process is a hold, never absence.
        desktop_absent(&ps, desktop, probe_budget, probe_bytes, poll)?;
        let context = discover(options, &wsl, &ps, poll, probe_budget, probe_bytes)?;
        let launcher = provision_helper(options, &wsl, distro, poll, probe_budget, probe_bytes)?;
        if !child_environment::valid_launcher(&launcher) {
            return Err("invalid absolute Linux helper path".into());
        }
        let helper = probe(
            wsl_command(
                &wsl,
                distro,
                r#"set -eu
p=$1
[ "$(stat -c %u "$p")" = "$(id -u)" ] || exit 62
while [ "$p" != / ]; do
 [ ! -L "$p" ] || exit 61
 owner=$(stat -c %u "$p"); [ "$owner" = "$(id -u)" ] || [ "$owner" = 0 ] || exit 62
 mode=$(stat -c %a "$p"); [ $((0$mode & 022)) = 0 ] || exit 63
 p=${p%/*}; [ -n "$p" ] || p=/
done
[ -f "$1" ] && [ -x "$1" ]
printf '%s\n' AG_HELPER_V1
sha256sum -- "$1"
od -An -tu1 -N20 -- "$1"
"#,
                &[&launcher],
            ),
            probe_budget,
            probe_bytes,
            poll,
        )?;
        verify_helper(
            &helper,
            options.text("--launcher-sha256")?,
            &context.architecture,
        )?;
        println!("SelectedContext: default-uid={} architecture={}; HOME observed={}; source-only namespace admission received", context.uid, context.architecture, !context.home.is_empty());
        println!("Launch supervision is silent while actors are live: on cancellation/failure admissions HOLD and owners remain retained. Close the owned Desktop normally; final errors follow actual process/worker settlement. Exit zero proves neither WSL use nor a model response.");
        if CANCEL.load(Ordering::SeqCst) {
            return Err("cancelled before gateway launch".into());
        }
        input.recheck_archive()?;
        input.revalidate_context()?;
        let spec = session::SessionSpec {
            program: session::GatewayProgramRef::receive(&gateway, &gateway_pin.native_id(), &gateway_digest)?,
            selected_distro: distro.into(),
            selected_user: context.user.clone(),
            gateway: session::GatewayConfig {
                bind: context.bind,
                source: context.source,
                opening_ms: options.number("--opening-ms")?,
                header_bytes: options.size("--header-bytes")?,
                max_active: options.size("--max-active")?,
                poll_ms: options.number("--poll-ms")?,
            },
            expected_policy: session::PolicyStatus::Received,
            startup_budget: Duration::from_millis(options.number("--startup-ms")?),
            stop_observation_budget: Duration::from_millis(options.number("--stop-ms")?),
            status_line_bytes: options.size("--status-bytes")?,
        };
        let mut gateway = match session::GatewaySession::spawn(spec, Instant::now()) {
            Ok(s) => s,
            Err(f) => {
                let mut retirement = None;
                if let Some(mut s) = f.session {
                    settle_gateway(&mut s, poll);
                    retirement = Some(format!(
                        "clean={}; errors={:?}",
                        s.clean_shutdown(),
                        s.errors()
                    ));
                }
                return Err(format!(
                    "gateway startup: {:?}; retirement={retirement:?}",
                    f.error
                ));
            }
        };
        let startup = loop {
            gateway.poll();
            if CANCEL.load(Ordering::SeqCst)
                || !gateway.errors().is_empty()
                || gateway.phase(Instant::now()) == session::Phase::Settled
            {
                break Err("gateway not ready; Desktop not launched".to_owned());
            }
            if let Some(ready) = gateway.ready() {
                break Ok(ready);
            }
            thread::sleep(poll);
        };
        let outcome = match startup {
            Err(error) => Err(error),
            Ok(ready) => {
                let inherited = std::env::vars_os().collect::<Vec<_>>();
                match desktop_launch::plan_hook_desktop_command(
                    input.executable(),
                    distro,
                    &inherited,
                    ready.endpoint,
                    &launcher,
                ) {
                    Err(e) => Err(format!("Desktop command rejected: {e:?}")),
                    Ok(mut plan) => match plan.command.spawn() {
                        Err(e) => Err(io("Desktop spawn", e)),
                        Ok(child) => {
                            retain_desktop(
                                child,
                                &mut gateway,
                                options,
                                &wsl,
                                &ps,
                                &context,
                                poll,
                                probe_budget,
                                probe_bytes,
                                topology_interval,
                                observation_budget,
                            ).map_err(|error| format!("{error}; inherited generic HTTPS_PROXY={} NO_PROXY={}; precedence/actual WSL use remains unverified", plan.routing_uncertainty.https_proxy_present, plan.routing_uncertainty.no_proxy_present))
                        }
                    },
                }
            }
        };
        settle_gateway(&mut gateway, poll);
        outcome.map_err(|error| {
            format!(
                "{error}; gateway_retired_clean={}; gateway_errors={:?}",
                gateway.clean_shutdown(),
                gateway.errors()
            )
        })
    })();
    result
}
fn topology_result(worker: thread::JoinHandle<Result<Context>>, expected: &Context) -> Result<()> {
    match worker.join() {
        Ok(Ok(actual)) if actual == *expected => Ok(()),
        Ok(Ok(_)) => {
            Err("selected user/HOME/namespace/architecture/route/interface changed".into())
        }
        Ok(Err(error)) => Err(format!("topology could not be revalidated: {error}")),
        Err(_) => Err("topology observer panicked".into()),
    }
}
fn retain_desktop(
    mut child: Child,
    gateway: &mut session::GatewaySession,
    options: &Options,
    wsl: &Path,
    ps: &Path,
    expected: &Context,
    poll: Duration,
    probe_budget: Duration,
    probe_bytes: usize,
    interval: Duration,
    observation_budget: Duration,
) -> Result<()> {
    let mut observer: Option<thread::JoinHandle<Result<Context>>> = None;
    let mut observer_deadline = None;
    let mut next = Instant::now();
    let mut hold_reason = None;
    let mut hold_reported = false;
    let mut desktop_observation_error = None;
    let mut topology_failure = None;
    let exit = loop {
        gateway.poll();
        if observer.is_some() && observer_deadline.is_some_and(|end| Instant::now() >= end) {
            hold_reason.get_or_insert(
                "topology observation deadline exceeded; metadata process/reader custody retained"
                    .into(),
            );
        }
        if observer.as_ref().is_some_and(|worker| worker.is_finished()) {
            if let Err(error) = topology_result(observer.take().unwrap(), expected) {
                hold_reason.get_or_insert(error.clone());
                topology_failure = Some(error);
            }
            observer_deadline = None;
        }
        if CANCEL.load(Ordering::SeqCst) {
            hold_reason.get_or_insert("operator cancelled the launch session".into());
        }
        if gateway.ready().is_none() {
            hold_reason.get_or_insert("gateway unavailable or holding admissions".into());
        }
        if hold_reason.is_some() {
            if !hold_reported {
                gateway.request_hold(Instant::now());
                hold_reported = true;
            }
        } else if observer.is_none() && Instant::now() >= next {
            let Some(deadline) = Instant::now().checked_add(observation_budget) else {
                hold_reason = Some("topology observation deadline overflow".into());
                continue;
            };
            let (options, wsl, ps) = (options.clone(), wsl.to_path_buf(), ps.to_path_buf());
            match thread::Builder::new()
                .name("wsl-topology-observer".into())
                .spawn(move || discover(&options, &wsl, &ps, poll, probe_budget, probe_bytes))
            {
                Ok(worker) => {
                    observer = Some(worker);
                    observer_deadline = Some(deadline);
                }
                Err(error) => {
                    hold_reason = Some(format!("topology observer could not start: {error}"));
                }
            }
            if let Some(deadline) = Instant::now().checked_add(interval) {
                next = deadline;
            } else {
                hold_reason = Some("topology interval overflow".into());
            }
        }
        match child.try_wait() {
            Ok(Some(exit)) => break exit,
            Ok(None) => {}
            Err(error) => {
                hold_reason.get_or_insert("Desktop exit observation failed".into());
                desktop_observation_error.get_or_insert(error);
            }
        }
        thread::sleep(poll);
    };
    // The finite metadata command may still own its Child/pipe. Keep the gateway
    // status channel moving while its creator retains and collects every outcome.
    if let Some(observer) = observer {
        while !observer.is_finished() {
            gateway.poll();
            thread::sleep(poll);
        }
        if let Err(error) = topology_result(observer, expected) {
            hold_reason.get_or_insert(error.clone());
            topology_failure = Some(error);
        }
    }
    Err(format!("DesktopExited({exit}); hold={hold_reason:?}; topology_failure={topology_failure:?}; desktop_observation_error={desktop_observation_error:?}; hold_acknowledged={}; launch exit proves neither singleton ownership, actual WSL route nor model reply; application verification remains required", gateway.hold_acknowledged()))
}
fn settle_gateway(gateway: &mut session::GatewaySession, poll: Duration) {
    gateway.request_stop(Instant::now());
    loop {
        let update = gateway.poll();
        if update.phase == session::Phase::Settled {
            break;
        }
        thread::sleep(poll);
    }
}

/// Isolated executable fixture only: synthetic gateway/desktop/probe actors use
/// separate control markers. No vendor launch or production trust override.
#[cfg(test)]
pub fn blocked_diagnostic_fixture(root: &Path, budget: Duration) -> Result<()> {
    let executable = std::env::current_exe().map_err(|e| io("fixture executable", e))?;
    let pinned = pin_executable(&executable)?;
    let binding = digest(&pinned.read_snapshot()?);
    let poll = Duration::from_millis(5);
    let spec = session::SessionSpec {
        program: session::GatewayProgramRef::receive(&executable, &pinned.native_id(), &binding)?,
        selected_distro: "fixture".into(),
        selected_user: "fixture".into(),
        gateway: session::GatewayConfig {
            bind: "192.0.2.1".parse().unwrap(),
            source: "192.0.2.2".parse().unwrap(),
            opening_ms: 100,
            header_bytes: 4096,
            max_active: 1,
            poll_ms: 5,
        },
        expected_policy: session::PolicyStatus::Received,
        startup_budget: budget,
        stop_observation_budget: budget,
        status_line_bytes: 4096,
    };
    let mut gateway = match session::GatewaySession::spawn(spec, Instant::now()) {
        Ok(owner) => owner,
        Err(failure) => {
            if let Some(mut owner) = failure.session {
                settle_gateway(&mut owner, poll);
            }
            return Err(format!("fixture gateway: {:?}", failure.error));
        }
    };
    while gateway.ready().is_none()
        && gateway.errors().is_empty()
        && gateway.phase(Instant::now()) != session::Phase::Settled
    {
        gateway.poll();
        thread::sleep(poll);
    }
    if gateway.ready().is_none() {
        settle_gateway(&mut gateway, poll);
        return Err(format!("fixture readiness: {:?}", gateway.errors()));
    }
    let child = match Command::new(&executable).arg("--fixture-desktop").spawn() {
        Ok(child) => child,
        Err(error) => {
            settle_gateway(&mut gateway, poll);
            return Err(io("fixture Desktop", error));
        }
    };
    let options = Options::parse(vec![
        "--run".into(),
        "--desktop".into(),
        executable.into_os_string(),
        "--distro".into(),
        "fixture".into(),
    ])
    .unwrap();
    let expected = Context {
        uid: 1000,
        gid: 1000,
        user: "fixture".into(),
        home: "/fixture".into(),
        architecture: "x86_64".into(),
        namespace: "net:[42]".into(),
        interface: 1,
        interface_alias: "fixture".into(),
        bind: "192.0.2.1".parse().unwrap(),
        source: "192.0.2.2".parse().unwrap(),
    };
    let fixture_exe = std::env::current_exe()
        .map_err(|e| io("fixture identity", e))
        .unwrap();
    let outcome = retain_desktop(
        child,
        &mut gateway,
        &options,
        &fixture_exe,
        &fixture_exe,
        &expected,
        poll,
        Duration::from_millis(20),
        4096,
        Duration::from_millis(20),
        Duration::from_millis(60),
    );
    settle_gateway(&mut gateway, poll);
    let report = format!(
        "desktop={outcome:?}; hold_ack={}; clean={}; phase={:?}; errors={:?}",
        gateway.hold_acknowledged(),
        gateway.clean_shutdown(),
        gateway.phase(Instant::now()),
        gateway.errors()
    );
    fs::write(root.join("settled"), &report).map_err(|e| io("fixture terminal evidence", e))?;
    if outcome.is_ok()
        || !gateway.hold_acknowledged()
        || !gateway.clean_shutdown()
        || gateway.phase(Instant::now()) != session::Phase::Settled
    {
        return Err(report);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_route_error_masks_received_guest_home() {
        let mut phase = 0;
        let error = match discover_with("fixture", Path::new("wsl.exe"), Path::new("powershell.exe"), |purpose, _command, private| {
            phase += 1;
            match phase {
                1 => { assert!(private.is_empty()); Ok("AG_CONTEXT_V1\n1000\n1000\nfixture-user\n/fixture-home-private\nx86_64\nnet:[123]\ndefault via 192.0.2.1 dev eth0\n".into()) },
                2 => Ok(r#"{"address":"192.0.2.1","interface":47,"alias":"vEthernet (fixture)","virtual":true,"hardware":false,"description":"Hyper-V Virtual Ethernet Adapter"}"#.into()),
                3 => {
                    let context = discovery_metadata_context(purpose, "fixture", private);
                    Err(context.safe_stderr(b"native error 51 /fixture-home-private"))
                },
                _ => panic!("unexpected operation"),
            }
        }) { Ok(_) => panic!("route failure unexpectedly succeeded"), Err(error) => error };
        assert_eq!(phase, 3);
        assert!(error.contains("native error 51"));
        assert!(!error.contains("/fixture-home-private"));
    }
    #[test]
    fn explicit_inputs_and_route_ambiguity_fail_closed() {
        assert!(Options::parse(vec![
            "--run".into(),
            "--desktop".into(),
            r"C:\App\Desktop.exe".into()
        ])
        .is_err());
        assert!(Options::parse(vec![
            "--inspect".into(),
            "--desktop".into(),
            r"C:\App\Desktop.exe".into(),
            "--distro".into(),
            "Selected".into(),
            "--distro".into(),
            "Other".into()
        ])
        .is_err());
        let bind = "192.0.2.1".parse().unwrap();
        assert_eq!(
            source_route("192.0.2.1 dev eth0 src 192.0.2.2 uid 1000", bind).unwrap(),
            "192.0.2.2".parse::<Ipv4Addr>().unwrap()
        );
        for text in [
            "192.0.2.1 dev eth0",
            "192.0.2.1 src 192.0.2.2 src 192.0.2.3",
            "192.0.2.9 src 192.0.2.2",
            "192.0.2.1 src 127.0.0.1",
        ] {
            assert!(source_route(text, bind).is_err());
        }
    }
    #[test]
    fn helper_identity_architecture_and_powershell_data_boundary() {
        let mut header = [0u8; 20];
        header[..6].copy_from_slice(&[127, b'E', b'L', b'F', 2, 1]);
        header[18] = 62;
        let text = format!(
            "AG_HELPER_V1\nexpected  /owned/helper\n{}\n",
            header.map(|v| v.to_string()).join(" ")
        );
        assert!(verify_helper(&text, "expected", "x86_64").is_ok());
        assert!(verify_helper(&text, "other", "x86_64").is_err());
        assert!(verify_helper(&text, "expected", "aarch64").is_err());
        assert!(verify_helper("AG_HELPER_V1\nexpected\n", "expected", "x86_64").is_err());
        let literal = r"C:\literal;$('must remain data')\Desktop.exe";
        let command = powershell(
            Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "fixed script",
            &[literal],
        );
        assert!(!command.get_args().any(|arg| arg == literal));
        assert!(command
            .get_envs()
            .any(|(key, value)| key == "AG_COORD_TARGET"
                && value == Some(std::ffi::OsStr::new(literal))));
    }
    #[test]
    fn topology_worker_results_do_not_revalidate_changed_or_missing_facts() {
        let bind = "192.0.2.1".parse().unwrap();
        let virtual_adapter = r#"{"address":"192.0.2.1","interface":47,"alias":"vEthernet (fixture)","virtual":true,"hardware":false,"description":"Hyper-V Virtual Ethernet Adapter"}"#;
        assert!(receive_adapter(virtual_adapter, bind).is_ok());
        assert!(receive_adapter(&virtual_adapter.replace("\"alias\":\"vEthernet (fixture)\",", ""), bind).is_err());
        assert!(receive_adapter(&virtual_adapter.replace("vEthernet (fixture)", ""), bind).is_err());
        assert!(receive_adapter(
            &virtual_adapter.replace("\"hardware\":false", "\"hardware\":true"),
            bind
        )
        .is_err());
        assert!(receive_adapter(
            &virtual_adapter.replace("\"virtual\":true", "\"virtual\":false"),
            bind
        )
        .is_err());
        assert!(receive_adapter(
            &virtual_adapter.replace("Hyper-V Virtual Ethernet Adapter", "Physical LAN adapter"),
            bind
        )
        .is_err());
        assert!(receive_adapter("{}", bind).is_err());
        let expected = Context {
            uid: 1000,
            gid: 1000,
            user: "selected".into(),
            home: "/test-fixtures/home/selected".into(),
            architecture: "x86_64".into(),
            namespace: "net:[42]".into(),
            interface: 47,
            interface_alias: "vEthernet (fixture)".into(),
            bind: "192.0.2.1".parse().unwrap(),
            source: "192.0.2.2".parse().unwrap(),
        };
        let unchanged = expected.clone();
        assert!(topology_result(thread::spawn(move || Ok(unchanged)), &expected).is_ok());
        let mut changed = expected.clone();
        changed.source = "192.0.2.3".parse().unwrap();
        assert!(topology_result(thread::spawn(move || Ok(changed)), &expected).is_err());
        assert!(topology_result(thread::spawn(|| Err("probe failed".into())), &expected).is_err());
    }
}
