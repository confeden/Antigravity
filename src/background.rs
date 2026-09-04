// Keeping the DNS relay alive across reboots.
//
// The Windows implementation is a logon-triggered scheduled task; the Linux
// implementation is, for now, a set of honest stubs - the DNS/relay layer is the
// last part of the port (kb/patch.md), and until it lands the binary/JS patch is
// what lifts the gate on a permitted exit (kb/rivals.md Fact 2). The stubs report
// "not running / nothing to do" so menu 1's DNS branch is simply skipped rather
// than half-run.

/// Hidden flag that turns the unlocker into the relay. Handled before any UI.
pub const FORWARDER_FLAG: &str = "--dns-forwarder";
/// Hidden flag that runs ONLY the update watchdog - no relay, no DNS, no network.
/// Handled before any UI, same as the relay flag.
pub const WATCHDOG_FLAG: &str = "--watchdog";
/// Hidden flag that runs ONLY the local CONNECT proxy (`proxy::run`) - the Linux
/// phase-2 region route. No DNS listener, so no systemd-resolved conflict.
pub const PROXY_FLAG: &str = "--proxy";

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(target_os = "macos")]
pub use macos_impl::*;

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub use unix_impl::*;

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    use super::{FORWARDER_FLAG, WATCHDOG_FLAG};
    use crate::dns_forwarder;
    use crate::utils::{bounded_output, no_window, powershell};

    // A scheduled task rather than a real service: a Windows service has to
    // implement StartServiceCtrlDispatcher and a control handler or the SCM kills
    // the process after ~30 seconds, which is a protocol to maintain for exactly
    // the same result. A logon-triggered task is a plain background process, and
    // enable/disable is one cmdlet each.
    //
    // Registered through the ScheduledTasks cmdlets, not schtasks.exe: the
    // defaults of the latter are wrong here in two ways that only surface on a
    // laptop weeks later - a task is stopped when the machine goes on battery, and
    // it is killed after a 72-hour execution limit. Both are switched off below.
    //
    // It also restarts on failure. The relay is compiled with `panic = "abort"`,
    // so any thread that goes down takes the whole process with it - and with it
    // the DNS the routed names depend on, until the next logon. A restart policy
    // is the only backstop available for that, since the panic cannot be caught.

    const TASK_NAME: &str = "AG Unlocker DNS";
    /// The watchdog's own logon task, separate from the relay's. Decoupling the
    /// re-patch survival from the relay is what lets it keep working when the relay
    /// is stopped (menu 4), has died, or was never installed (a future patch-only
    /// machine) - the case G9 describes today, where no relay means no watchdog.
    const WATCHDOG_TASK_NAME: &str = "AG Unlocker Watchdog";
    const EXE_NAME: &str = "ag_dns.exe";

    /// ProgramData, **not** LOCALAPPDATA. Measured on a real machine: a scheduled
    /// task launching anything out of `%LOCALAPPDATA%` fails with 0x80070002, and a
    /// stock `ping.exe` copied there fails identically - it is an anti-persistence
    /// heuristic (a task autostarting an exe from AppData is the classic malware
    /// shape), not something about our binary. The same probe from ProgramData and
    /// Program Files starts cleanly.
    pub fn install_dir() -> PathBuf {
        PathBuf::from(env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()))
            .join("AGUnlocker")
    }

    pub fn installed_exe() -> PathBuf {
        install_dir().join(EXE_NAME)
    }

    /// True when the logon task exists. Says nothing about whether the relay is
    /// running right now - `is_running` answers that.
    pub fn is_enabled() -> bool {
        let cmd = format!(
            "if (Get-ScheduledTask -TaskName '{}' -ErrorAction SilentlyContinue) {{ 'yes' }} else {{ 'no' }}",
            TASK_NAME
        );
        powershell(&cmd).map_or(false, |o| {
            String::from_utf8_lossy(&o.stdout).trim() == "yes"
        })
    }

    /// Limit for the small helpers here (`tasklist`, `taskkill`). Short, because
    /// they answer in milliseconds when they answer at all - and this runs on the
    /// path a user is watching.
    const HELPER_LIMIT: Duration = Duration::from_secs(15);

    pub fn is_running() -> bool {
        let mut cmd = Command::new("tasklist");
        cmd.args(["/FI", &format!("IMAGENAME eq {}", EXE_NAME), "/NH"]);
        bounded_output(no_window(&mut cmd), HELPER_LIMIT).map_or(false, |o| {
            String::from_utf8_lossy(&o.stdout).contains(EXE_NAME)
        })
    }

    /// Kills the running relay and waits for it to actually let go.
    ///
    /// `taskkill /F` returns once the kill is *requested*, not once the process
    /// has exited and released its image file. Copying over it immediately then
    /// fails with os error 32 - "the file is in use by another process" - which is
    /// what a user upgrading from an older relay saw instead of an install.
    /// Reported from a real machine, never reproduced here, because it only
    /// happens when a relay is already running.
    fn stop_process() {
        let mut cmd = Command::new("taskkill");
        cmd.args(["/F", "/IM", EXE_NAME]);
        bounded_output(no_window(&mut cmd), HELPER_LIMIT);

        for _ in 0..STOP_WAIT_TRIES {
            if !is_running() {
                // Even gone from the task list, the image handle can outlive the
                // process by a moment. Cheaper to pause once than to explain a
                // failed upgrade.
                thread::sleep(STOP_SETTLE);
                return;
            }
            thread::sleep(STOP_SETTLE);
        }
    }

    const STOP_SETTLE: Duration = Duration::from_millis(300);
    const STOP_WAIT_TRIES: usize = 10;

    /// Copies this exe next to its log and registers the logon task. The copy is
    /// what makes autostart survive the user moving or deleting the download; it is
    /// removed again by `disable`.
    pub fn enable() -> Result<(), String> {
        let src = env::current_exe().map_err(|e| format!("не найден путь к exe: {}", e))?;
        let dir = install_dir();
        let dst = installed_exe();

        fs::create_dir_all(&dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
        // The file cannot be replaced while the previous relay holds it open.
        stop_process();
        if src != dst {
            copy_over(&src, &dst)?;
        }

        // S4U is what keeps the logon silent. A task action run under the default
        // Interactive principal is handed a *visible* console (measured), so the
        // relay flashes a window on every logon during the moment before it can
        // call FreeConsole. S4U runs it outside any interactive session - same
        // user, no password stored, and the console it gets is hidden. It needs
        // the "log on as a batch job" right, so a machine that refuses falls back
        // to the old principal rather than ending up with no task at all.
        let cmd = format!(
            "Stop-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue; \
             $a=New-ScheduledTaskAction -Execute '{exe}' -Argument '{flag}'; \
             $t=New-ScheduledTaskTrigger -AtLogOn; \
             $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries \
                  -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew \
                  -ExecutionTimeLimit ([TimeSpan]::Zero) \
                  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1); \
             $d='Antigravity Unlocker: локальный DNS-релей'; \
             try {{ \
               $p=New-ScheduledTaskPrincipal -UserId \"$env:USERDOMAIN\\$env:USERNAME\" \
                    -LogonType S4U -RunLevel Limited; \
               Register-ScheduledTask -TaskName '{task}' -Action $a -Trigger $t -Settings $s \
                    -Principal $p -Description $d -Force -ErrorAction Stop | Out-Null }} \
             catch {{ \
               Register-ScheduledTask -TaskName '{task}' -Action $a -Trigger $t -Settings $s \
                    -Description $d -Force -ErrorAction Stop | Out-Null }}; \
             Start-ScheduledTask -TaskName '{task}'",
            exe = dst.display(),
            flag = FORWARDER_FLAG,
            task = TASK_NAME
        );

        let out = powershell(&cmd).ok_or_else(|| "не удалось запустить PowerShell".to_string())?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(if stderr.is_empty() {
                "не удалось зарегистрировать задачу".to_string()
            } else {
                stderr
            });
        }
        // Stamped here rather than left to the relay: the answer has to be right
        // the moment the upgrade finishes, not a second later when the new process
        // gets around to writing it, or the menu redraws still saying "outdated".
        dns_forwarder::record_version();

        // Registering the task is not the same as the relay running. It is a
        // console process that exits 1 when it cannot bind 127.0.0.53:53, and the
        // previous one can still be holding the socket for a moment after
        // `stop_process()` returned - the task then sits at Ready with
        // LastTaskResult 1 and there is no relay, while this function has already
        // reported success. Observed exactly once, which is once more than a
        // silent one should happen.
        for attempt in 0..RELAY_START_TRIES {
            thread::sleep(RELAY_START_SETTLE);
            if is_running() {
                return Ok(());
            }
            if attempt + 1 < RELAY_START_TRIES {
                powershell(&format!("Start-ScheduledTask -TaskName '{}'", TASK_NAME));
            }
        }
        Err("задача создана, но релей не запустился".to_string())
    }

    /// How long to give the relay to appear before trying again. Generous enough
    /// for a UPX-packed exe to unpack and bind, short enough not to stall the menu.
    const RELAY_START_SETTLE: Duration = Duration::from_millis(1200);
    const RELAY_START_TRIES: usize = 3;

    /// Replaces `dst` with `src`, retrying while the old file is still held.
    ///
    /// Belt and braces on top of `stop_process`: whatever it is that holds the
    /// image open - antivirus reading it, the loader unmapping it - is transient,
    /// and a second of patience beats an upgrade that silently does not happen.
    fn copy_over(src: &Path, dst: &Path) -> Result<(), String> {
        let mut last = String::new();
        for attempt in 0..COPY_TRIES {
            match fs::copy(src, dst) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    last = e.to_string();
                    if attempt + 1 < COPY_TRIES {
                        thread::sleep(STOP_SETTLE);
                    }
                }
            }
        }
        Err(format!("не скопировать exe: {}", last))
    }

    const COPY_TRIES: usize = 6;

    fn same_file_bytes(a: &Path, b: &Path) -> bool {
        match (fs::read(a), fs::read(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    /// True when the installed relay is byte for byte this build.
    ///
    /// Without this check an upgrade is a no-op: a task exists and a process is
    /// alive, so `ensure_running` would leave the *previous* exe installed. That
    /// is how a build that fixes a background bug would keep reproducing it - the
    /// running relay is still the old one.
    fn installed_copy_is_current() -> bool {
        match env::current_exe() {
            Ok(src) => same_file_bytes(&src, &installed_exe()),
            Err(_) => false,
        }
    }

    /// True when a relay is installed and it is an older generation than this build
    /// ships - the case the user has to be told about, because the relay keeps
    /// running from `%ProgramData%` across reboots and a newer unlocker on its own
    /// changes nothing about it.
    ///
    /// Deliberately two cheap filesystem calls and no PowerShell: the menu redraws
    /// around this, and `is_enabled()` costs a few hundred milliseconds. The exe
    /// being there is what makes "no version file" mean "a relay from before
    /// versioning" rather than "no relay at all".
    pub fn relay_is_outdated() -> bool {
        installed_exe().exists()
            && dns_forwarder::installed_version() < dns_forwarder::RELAY_VERSION
    }

    /// Brings the relay up, reinstalling it whenever the installed copy is not this
    /// build. Cheap when everything is already current, so the patch flow can call
    /// it every time.
    pub fn ensure_running() -> Result<(), String> {
        if is_enabled() && is_running() && installed_copy_is_current() {
            return Ok(());
        }
        enable()
    }

    /// Registers the standalone watchdog logon task, pointing at the same installed
    /// exe as the relay but with `--watchdog`. Additive: it runs a second copy of
    /// the re-patch loop that survives the relay being stopped or absent (G9). The
    /// relay's own in-process watchdog is left in place as well; both are
    /// idempotent and settle-guarded, so a double poll re-applies the same rename
    /// harmlessly.
    ///
    /// Assumes the exe is already in `%ProgramData%` - the relay's `enable()` put
    /// it there, and menu 1 always runs the relay first. Best-effort by design: a
    /// failure here must not fail the patch (the relay's watchdog still covers the
    /// common case), so the caller treats an error as non-fatal.
    pub fn enable_watchdog() -> Result<(), String> {
        let exe = installed_exe();
        if !exe.exists() {
            return Err("exe не установлен в %ProgramData%".to_string());
        }
        let cmd = format!(
            "Stop-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue; \
             $a=New-ScheduledTaskAction -Execute '{exe}' -Argument '{flag}'; \
             $t=New-ScheduledTaskTrigger -AtLogOn; \
             $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries \
                  -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew \
                  -ExecutionTimeLimit ([TimeSpan]::Zero) \
                  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1); \
             $d='Antigravity Unlocker: сторож патча'; \
             try {{ \
               $p=New-ScheduledTaskPrincipal -UserId \"$env:USERDOMAIN\\$env:USERNAME\" \
                    -LogonType S4U -RunLevel Limited; \
               Register-ScheduledTask -TaskName '{task}' -Action $a -Trigger $t -Settings $s \
                    -Principal $p -Description $d -Force -ErrorAction Stop | Out-Null }} \
             catch {{ \
               Register-ScheduledTask -TaskName '{task}' -Action $a -Trigger $t -Settings $s \
                    -Description $d -Force -ErrorAction Stop | Out-Null }}; \
             Start-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue",
            exe = exe.display(),
            flag = WATCHDOG_FLAG,
            task = WATCHDOG_TASK_NAME
        );
        let out = powershell(&cmd).ok_or_else(|| "не удалось запустить PowerShell".to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// Removes the standalone watchdog task. `Stop-ScheduledTask` ends only this
    /// task's own process instance, so it does not disturb the relay (which shares
    /// the exe image name). Called by both undo paths alongside the relay teardown.
    pub fn disable_watchdog() {
        let cmd = format!(
            "Stop-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue; \
             Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false -ErrorAction SilentlyContinue",
            task = WATCHDOG_TASK_NAME
        );
        powershell(&cmd);
    }

    pub fn disable() -> Result<(), String> {
        let cmd = format!(
            "Stop-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue; \
             Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false -ErrorAction SilentlyContinue",
            task = TASK_NAME
        );
        powershell(&cmd);
        stop_process();
        fs::remove_file(installed_exe()).ok();
        fs::remove_file(dns_forwarder::log_path()).ok();
        fs::remove_file(dns_forwarder::version_path()).ok();
        // Both only succeed while the directory is empty, which is what we want.
        fs::remove_dir(install_dir()).ok();
        fs::remove_dir(dns_forwarder::log_dir()).ok();
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The exe must not sit under the user profile: a scheduled task cannot
        /// launch anything from there on a machine with anti-persistence
        /// heuristics.
        #[test]
        fn the_relay_is_installed_outside_the_user_profile() {
            let exe = installed_exe();
            assert_eq!(exe.parent(), Some(install_dir().as_path()));

            let program_data = env::var("ProgramData").unwrap_or_default();
            assert!(!program_data.is_empty());
            assert!(exe.starts_with(&program_data), "got {}", exe.display());

            if let Ok(local) = env::var("LOCALAPPDATA") {
                assert!(
                    !exe.starts_with(&local),
                    "the task would refuse to start it"
                );
            }
        }

        /// The upgrade path depends on spotting a stale installed copy.
        #[test]
        fn a_differing_installed_copy_is_detected() {
            let dir = env::temp_dir().join("ag_relay_copy_test");
            fs::create_dir_all(&dir).expect("temp dir");
            let (a, b) = (dir.join("a.bin"), dir.join("b.bin"));

            fs::write(&a, b"build-one").unwrap();
            fs::write(&b, b"build-one").unwrap();
            assert!(
                same_file_bytes(&a, &b),
                "identical files must compare equal"
            );

            fs::write(&b, b"build-two").unwrap();
            assert!(!same_file_bytes(&a, &b), "a new build must be spotted");

            // A missing installation counts as "not current", so it gets installed.
            assert!(!same_file_bytes(&a, &dir.join("nothing-here.bin")));

            fs::remove_dir_all(&dir).ok();
        }

        /// The log goes the other way round - the relay runs unelevated and cannot
        /// write next to an exe an administrator installed.
        #[test]
        fn the_log_stays_in_the_user_profile() {
            let log = dns_forwarder::log_path();
            let local = env::var("LOCALAPPDATA").unwrap_or_default();
            assert!(!local.is_empty());
            assert!(log.starts_with(&local), "got {}", log.display());
            assert_eq!(log.parent(), Some(dns_forwarder::log_dir().as_path()));
            assert_ne!(log.parent(), Some(install_dir().as_path()));
        }
    }
}

/// macOS: runs the local CONNECT proxy (proxy::run via --proxy) as a LaunchAgent
/// in ~/Library/LaunchAgents/com.antigravity.proxy.plist.
#[cfg(target_os = "macos")]
mod macos_impl {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use super::PROXY_FLAG;

    const LABEL: &str = "com.antigravity.proxy";
    const PLIST_NAME: &str = "com.antigravity.proxy.plist";

    fn home() -> String {
        if let Ok(user) = std::env::var("SUDO_USER") {
            if !user.is_empty() && user != "root" {
                return format!("/Users/{}", user);
            }
        }
        std::env::var("HOME").unwrap_or_default()
    }

    pub fn install_dir() -> PathBuf {
        PathBuf::from(home()).join("Library").join("Application Support").join("agunlocker")
    }

    pub fn installed_exe() -> PathBuf {
        install_dir().join("ag_proxy")
    }

    fn plist_path() -> PathBuf {
        PathBuf::from(home()).join("Library").join("LaunchAgents").join(PLIST_NAME)
    }

    pub fn is_enabled() -> bool {
        plist_path().exists()
    }

    pub fn is_running() -> bool {
        crate::utils::run_macos_launchctl(&["list", LABEL]).status.success()
    }

    pub fn relay_is_outdated() -> bool {
        false
    }

    pub fn ensure_running() -> Result<(), String> {
        let src = std::env::current_exe().map_err(|e| format!("нет пути к exe: {}", e))?;
        let dir = install_dir();
        let exe = installed_exe();
        fs::create_dir_all(&dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;

        if src != exe {
            fs::copy(&src, &exe).map_err(|e| format!("копия exe: {}", e))?;
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&exe, fs::Permissions::from_mode(0o755));
        }

        let pp = plist_path();
        if let Some(p) = pp.parent() {
            fs::create_dir_all(p).map_err(|e| format!("не создать {}: {}", p.display(), e))?;
        }

        let log_dir = crate::dns_forwarder::log_dir();
        fs::create_dir_all(&log_dir).ok();

        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>{flag}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_dir}/proxy.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/proxy.err</string>
</dict>
</plist>
"#,
            label = LABEL,
            exe = exe.display(),
            flag = PROXY_FLAG,
            log_dir = log_dir.display(),
        );

        fs::write(&pp, plist_content).map_err(|e| format!("не записать plist: {}", e))?;

        if let Ok(user) = std::env::var("SUDO_USER") {
            if !user.is_empty() && user != "root" {
                let owner = format!("{}:staff", user);
                let _ = Command::new("chown")
                    .arg("-R")
                    .arg(&owner)
                    .arg(&dir)
                    .status();
                let _ = Command::new("chown")
                    .arg(&owner)
                    .arg(&pp)
                    .status();
                let _ = Command::new("chown")
                    .arg("-R")
                    .arg(&owner)
                    .arg(&log_dir)
                    .status();
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&pp, fs::Permissions::from_mode(0o644));
        }

        // Unload first in case it's currently loaded
        let _ = crate::utils::run_macos_launchctl(&["unload", "-w", &pp.to_string_lossy()]);

        let status = crate::utils::run_macos_launchctl(&["load", "-w", &pp.to_string_lossy()]).status;

        if status.success() {
            Ok(())
        } else {
            Err("не удалось загрузить LaunchAgent через launchctl load".to_string())
        }
    }

    pub fn enable() -> Result<(), String> {
        ensure_running()
    }

    pub fn enable_watchdog() -> Result<(), String> {
        Ok(())
    }

    pub fn disable_watchdog() {}

    pub fn disable() -> Result<(), String> {
        let pp = plist_path();
        let _ = crate::utils::run_macos_launchctl(&["unload", "-w", &pp.to_string_lossy()]);
        let _ = fs::remove_file(&pp);
        let _ = fs::remove_file(installed_exe());
        let _ = fs::remove_dir(install_dir());
        Ok(())
    }
}

// Linux: phase 2 is the **proxy route**, not the DNS relay. This runs the local
// CONNECT proxy (`proxy::run`, via `--proxy`) as a systemd **user** unit - no
// root, no `:53` listener, so systemd-resolved is never touched. The DNS relay
// (phase 5) would be a separate, privileged story; this is deliberately the
// unprivileged half that already lifts the region gate through a permitted exit.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
mod unix_impl {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use super::PROXY_FLAG;

    const UNIT_NAME: &str = "ag-unlocker-proxy.service";

    fn home() -> String {
        std::env::var("HOME").unwrap_or_default()
    }

    fn xdg(var: &str, default_suffix: &str) -> PathBuf {
        let base = std::env::var(var)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("{}/{}", home(), default_suffix));
        PathBuf::from(base)
    }

    /// The proxy's own copy of the exe, under the XDG data dir - a user unit needs
    /// no root, so unlike Windows there is no `%ProgramData%` anti-persistence
    /// dance.
    pub fn install_dir() -> PathBuf {
        xdg("XDG_DATA_HOME", ".local/share").join("agunlocker")
    }

    pub fn installed_exe() -> PathBuf {
        install_dir().join("ag_proxy")
    }

    fn unit_path() -> PathBuf {
        xdg("XDG_CONFIG_HOME", ".config")
            .join("systemd/user")
            .join(UNIT_NAME)
    }

    /// Runs `systemctl --user ...`; true on success. Best-effort: a machine
    /// without a user systemd manager (rare on a desktop) just fails the enable.
    fn systemctl(args: &[&str]) -> bool {
        Command::new("systemctl")
            .arg("--user")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// The unit file existing is what "enabled" means here.
    pub fn is_enabled() -> bool {
        unit_path().exists()
    }

    pub fn is_running() -> bool {
        Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", UNIT_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// No versioned relay on Linux, so nothing to call outdated.
    pub fn relay_is_outdated() -> bool {
        false
    }

    /// Installs the exe under the XDG data dir, writes a systemd **user** unit that
    /// runs it with `--proxy`, and starts it. No root: `systemctl --user` targets
    /// the caller's own session manager, which is why the whole Linux flow runs
    /// unprivileged (and "Run as a Program" works without a password prompt).
    pub fn ensure_running() -> Result<(), String> {
        let src = std::env::current_exe().map_err(|e| format!("нет пути к exe: {}", e))?;
        let dir = install_dir();
        let exe = installed_exe();
        fs::create_dir_all(&dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
        // Copy self so the unit survives the download folder being moved/removed.
        if src != exe {
            fs::copy(&src, &exe).map_err(|e| format!("копия exe: {}", e))?;
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&exe, fs::Permissions::from_mode(0o755));
        }

        let up = unit_path();
        if let Some(p) = up.parent() {
            fs::create_dir_all(p).map_err(|e| format!("не создать {}: {}", p.display(), e))?;
        }
        let unit = format!(
            "[Unit]\n\
             Description=Antigravity Unlocker local proxy\n\
             After=network-online.target\n\n\
             [Service]\n\
             ExecStart={exe} {flag}\n\
             Restart=on-failure\n\
             RestartSec=5\n\n\
             [Install]\n\
             WantedBy=default.target\n",
            exe = exe.display(),
            flag = PROXY_FLAG,
        );
        fs::write(&up, unit).map_err(|e| format!("не записать юнит: {}", e))?;

        systemctl(&["daemon-reload"]);
        if systemctl(&["enable", "--now", UNIT_NAME]) {
            Ok(())
        } else {
            Err("не удалось запустить systemd-юнит (systemctl --user)".to_string())
        }
    }

    pub fn enable() -> Result<(), String> {
        ensure_running()
    }

    /// No separate watchdog on Linux yet - the proxy unit's own `Restart=` covers
    /// the crash case, and there is no auto-updater story to fight here.
    pub fn enable_watchdog() -> Result<(), String> {
        Ok(())
    }

    pub fn disable_watchdog() {}

    /// Stops and removes the user unit and the installed copy. Quiet success even
    /// when nothing was installed, so the undo menus never error.
    pub fn disable() -> Result<(), String> {
        systemctl(&["disable", "--now", UNIT_NAME]);
        let _ = fs::remove_file(unit_path());
        systemctl(&["daemon-reload"]);
        let _ = fs::remove_file(installed_exe());
        let _ = fs::remove_dir(install_dir());
        Ok(())
    }
}
