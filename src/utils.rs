use std::env;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Suppresses the console Windows would otherwise create for a console
/// subsystem child.
///
/// This matters because the DNS relay calls `FreeConsole()` and so has no
/// console of its own: every helper it spawns gets a brand new one, which is a
/// black window flashing on the user's screen (measured - the `conhost.exe`
/// count goes up by one per spawn). Output is read through pipes, so nothing
/// needs a window. Not applied to the `color` call in `console_style`, which
/// deliberately acts on the console it is attached to.
#[cfg(target_os = "windows")]
pub fn no_window(cmd: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW)
}

#[cfg(not(target_os = "windows"))]
pub fn no_window(cmd: &mut Command) -> &mut Command {
    cmd
}

/// Longest any single PowerShell call may take before it is killed.
///
/// There has to be one. `Command::output()` waits forever, and the DNS work runs
/// through `Add-DnsClientNrptRule` and friends, which are CIM cmdlets and
/// therefore go through WMI - a service that on some machines simply stops
/// answering. One of those and the whole program stops on a printed line with no
/// way out, which is what users reported as an eternal hang at "Патч для Google
/// серверов..." while the same build was fine on other machines. Generous, since
/// these cmdlets take a second or two normally, and a slow machine must not lose
/// its rules to an impatient limit.
const PS_LIMIT: Duration = Duration::from_secs(60);

/// Runs a PowerShell snippet and hands back the raw output. Shared by the DNS
/// and routing code, which is all cmdlet-driven.
///
/// `None` on failure *or* timeout: every caller already treats that as "this
/// step did not happen", which is the right answer for a hung WMI too.
pub fn powershell(script: &str) -> Option<std::process::Output> {
    powershell_within(script, PS_LIMIT)
}

/// The same, with the limit given explicitly. Public because `PS_LIMIT` is sized
/// for the CIM cmdlets that write rules, and a read-only probe on a path the user
/// is watching should not be allowed a whole minute of silence; it also makes the
/// timeout itself testable without waiting that minute.
pub fn powershell_within(script: &str, limit: Duration) -> Option<std::process::Output> {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    bounded_output(no_window(&mut cmd), limit)
}

/// Runs a prepared command and gives up on it after `limit`.
///
/// Every helper this tool shells out to can hang - `netsh` and `tasklist` no
/// less than PowerShell - and `Command::output()` has no way to stop waiting.
/// Anything on a path a user is watching should come through here.
pub fn bounded_output(cmd: &mut Command, limit: Duration) -> Option<std::process::Output> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().ok()?;

    // Drained on threads rather than after waiting: a child that fills its pipe
    // blocks on the write, so polling for exit without reading would deadlock on
    // exactly the long outputs most worth having.
    let mut out = child.stdout.take().map(drain);
    let mut err = child.stderr.take().map(drain);

    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            // Killed, or unkillable and abandoned - either way this call is over
            // and the caller gets the same `None` a failure would give it.
            _ => {
                child.kill().ok();
                child.wait().ok();
                return None;
            }
        }
    };

    Some(std::process::Output {
        status,
        stdout: out.take().and_then(|h| h.join().ok()).unwrap_or_default(),
        stderr: err.take().and_then(|h| h.join().ok()).unwrap_or_default(),
    })
}

/// Reads a pipe to end-of-file on its own thread.
fn drain<R: std::io::Read + Send + 'static>(mut pipe: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut pipe, &mut buf).ok();
        buf
    })
}

pub fn clear_screen() {
    // VT is enabled at startup, so the escape sequence works everywhere and
    // avoids spawning a cmd.exe just to clear the screen.
    print!("\x1b[2J\x1b[3J\x1b[1;1H");
    io::stdout().flush().ok();
}

/// True when the host terminal renders OSC 8 hyperlinks (Windows Terminal and
/// most modern emulators). The legacy conhost window does not, so links are
/// printed as plain text there and opened through the menu instead.
pub fn supports_hyperlinks() -> bool {
    env::var("WT_SESSION").is_ok()
        || env::var("TERM_PROGRAM").is_ok()
        || env::var("ConEmuANSI").map(|v| v == "ON").unwrap_or(false)
}

// Format a URL for display. On terminals that support it the text becomes a
// real hyperlink (Ctrl+Click); elsewhere it stays a readable, selectable URL.
pub fn link(url: &str, text: &str) -> String {
    if supports_hyperlinks() {
        format!(
            "\x1b[94;4m\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\\x1b[0m\x1b[92m",
            url, text
        )
    } else {
        format!("\x1b[94;4m{}\x1b[0m\x1b[92m", text)
    }
}

/// Locates the resources directory for an IDE installation.
/// On macOS Electron apps, resources live inside Contents/Resources.
/// On Linux/Windows, resources live directly in resources/.
pub fn resources_dir(inst: &std::path::Path) -> std::path::PathBuf {
    if inst.file_name().map_or(false, |n| n == "Resources" || n == "resources") {
        return inst.to_path_buf();
    }
    let cr = inst.join("Contents").join("Resources");
    if cr.exists() {
        return cr;
    }
    #[cfg(target_os = "macos")]
    if inst.extension().map_or(false, |ext| ext == "app") {
        return cr;
    }
    inst.join("resources")
}

// Open a URL in the system default browser (Windows: cmd /c start "" <url>, macOS: open <url>, Linux: xdg-open <url>).
pub fn open_url(url: &str) {
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
            .ok();
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).status().ok();
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        Command::new("xdg-open").arg(url).status().ok();
    }
}

/// Prints a prompt and returns the trimmed line the user typed.
pub fn prompt(label: &str) -> String {
    print!("{}", label);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);
    input.trim().to_string()
}

#[cfg(target_os = "windows")]
pub fn mask_path(path: &str) -> String {
    let mut result = path.to_string();
    if let Ok(local) = env::var("LOCALAPPDATA") {
        result = result.replace(&local, "%LOCALAPPDATA%");
    }
    if let Ok(appdata) = env::var("APPDATA") {
        result = result.replace(&appdata, "%APPDATA%");
    }
    if let Ok(userprofile) = env::var("USERPROFILE") {
        result = result.replace(&userprofile, "%USERPROFILE%");
    }
    result
}

/// Same idea on Linux, where the one directory worth eliding is the home dir.
#[cfg(not(target_os = "windows"))]
pub fn mask_path(path: &str) -> String {
    if let Ok(user) = env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            let user_home = format!("/Users/{}", user);
            if path.starts_with(&user_home) {
                return path.replace(&user_home, "~");
            }
        }
    }
    match env::var("HOME") {
        Ok(home) if !home.is_empty() => path.replace(&home, "~"),
        _ => path.to_string(),
    }
}

/// Runs a launchctl subcommand targeting the real GUI user session when executed
/// under sudo, avoiding SIP errors (error 150) and LaunchAgent mismatch (error 5).
#[cfg(target_os = "macos")]
pub fn run_macos_launchctl(args: &[&str]) -> std::process::Output {
    let target_uid = env::var("SUDO_UID")
        .ok()
        .filter(|u| !u.is_empty() && u != "0")
        .or_else(|| {
            env::var("SUDO_USER")
                .ok()
                .filter(|u| !u.is_empty() && u != "root")
                .and_then(|user| {
                    Command::new("id")
                        .args(["-u", &user])
                        .output()
                        .ok()
                        .and_then(|out| {
                            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                            if !s.is_empty() && s != "0" {
                                Some(s)
                            } else {
                                None
                            }
                        })
                })
        });

    if let Some(ref uid) = target_uid {
        let mut full_args = vec!["asuser", uid.as_str(), "launchctl"];
        full_args.extend_from_slice(args);
        if let Ok(out) = Command::new("launchctl").args(&full_args).output() {
            return out;
        }
    }

    Command::new("launchctl")
        .args(args)
        .output()
        .unwrap_or_else(|_| {
            Command::new("/bin/sh")
                .args(["-c", "exit 1"])
                .output()
                .unwrap()
        })
}

/// A path short enough to sit in a progress line: the last few components,
/// with anything above them elided.
///
/// `mask_path` replaces the profile directories with their variable names, which
/// keeps a log honest but still runs long. This is for the screen, where the
/// only question is "which of my installs is this".
pub fn short_path(path: &str) -> String {
    // Written as a code point so no tool that rewrites escapes can turn one
    // separator into two, or none. Backslash on Windows, forward slash elsewhere.
    #[cfg(target_os = "windows")]
    const SEP: char = '\u{5C}';
    #[cfg(not(target_os = "windows"))]
    const SEP: char = '/';
    let parts: Vec<&str> = path.split(SEP).filter(|p| !p.is_empty()).collect();
    if parts.len() <= 3 {
        return path.to_string();
    }
    let sep = SEP.to_string();
    format!("...{}{}", sep, parts[parts.len() - 3..].join(&sep))
}

#[cfg(target_os = "windows")]
pub fn is_admin() -> bool {
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
    }
    unsafe { IsUserAnAdmin() != 0 }
}

/// On Linux "admin" means the effective user is root: the DNS/relay layer edits
/// resolver policy and binds a privileged port, both of which need it, while the
/// binary/JS patch only needs write access to the install (checked where it is
/// applied). `geteuid` is the direct question, with no libc dependency.
#[cfg(not(target_os = "windows"))]
pub fn is_admin() -> bool {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hang users reported. `Command::output()` waits forever, and the DNS
    /// step drives CIM cmdlets, i.e. WMI - which on some machines stops
    /// answering. There is no output to see and no key to press: the program
    /// simply stops on a printed line. A limit is what makes that a failed step
    /// instead of a dead program.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_powershell_call_that_never_returns_is_given_up_on() {
        let started = Instant::now();
        let out = powershell_within("Start-Sleep -Seconds 60", Duration::from_secs(2));
        assert!(out.is_none(), "a hung call must not come back with output");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "gave up after {:?}, which is not a limit",
            started.elapsed()
        );
    }

    /// The limit is worth nothing if the rewrite that added it broke the normal
    /// path: every DNS rule this tool installs is read back through here.
    #[cfg(target_os = "windows")]
    #[test]
    fn output_and_exit_status_still_come_back_intact() {
        let out = powershell("Write-Output 'marker-42'").expect("powershell ran");
        assert!(out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("marker-42"),
            "stdout was {:?}",
            String::from_utf8_lossy(&out.stdout)
        );

        let failed = powershell("exit 3").expect("powershell ran");
        assert!(
            !failed.status.success(),
            "a non-zero exit must not read as ok"
        );
    }

    /// Reproduces the relay's situation - a process with no console of its own -
    /// and checks what a spawned helper gets.
    ///
    /// Counting `conhost.exe` is not the measurement to make here:
    /// `CREATE_NO_WINDOW` still gives the child a console, it just never shows
    /// it. So this asks the child directly whether its console window is
    /// visible. Detaches the console of the test process, so run it alone.
    #[test]
    #[ignore = "detaches the console and spawns processes; run alone with --ignored"]
    fn a_helper_spawned_without_a_console_shows_no_window() {
        const SCRIPT: &str = "Add-Type -Name W -Namespace N -MemberDefinition '\
            [DllImport(\"kernel32.dll\")] public static extern System.IntPtr GetConsoleWindow();\
            [DllImport(\"user32.dll\")] public static extern bool IsWindowVisible(System.IntPtr h);'; \
            $h=[N.W]::GetConsoleWindow(); \
            if ($h -eq [System.IntPtr]::Zero) { 'no-console' } \
            elseif ([N.W]::IsWindowVisible($h)) { 'VISIBLE' } else { 'hidden' }";

        let ask = |flagged: bool| -> String {
            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT]);
            let out = if flagged {
                no_window(&mut cmd).output()
            } else {
                cmd.output()
            };
            out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "spawn failed".to_string())
        };

        crate::dns_forwarder::detach_console();

        let bare = ask(false);
        let flagged = ask(true);
        println!("without the flag: {}\nwith the flag:    {}", bare, flagged);

        assert_eq!(bare, "VISIBLE", "the bug should reproduce without the flag");
        assert_ne!(flagged, "VISIBLE", "CREATE_NO_WINDOW must hide the console");
    }
}

pub fn print_results(successes: &[String], failures: &[String]) {
    println!(
        "\n{}",
        "============================================================"
    );
    println!("{}", "ИТОГИ:");
    if !successes.is_empty() {
        println!("{}", "Успешно разблокированы:");
        for s in successes {
            println!("  {} {}", "[+]", s);
        }
    }
    if !failures.is_empty() {
        println!("{}", "Ошибки:");
        for f in failures {
            println!("  \x1b[33m[-] {}\x1b[0m\x1b[92m", f);
        }

        #[cfg(target_os = "macos")]
        {
            let has_perm_err = failures.iter().any(|f| {
                f.contains("Operation not permitted")
                    || f.contains("os error 1")
                    || f.contains("TCC")
            });
            if has_perm_err {
                println!("\n  \x1b[36m────────────────────────────────────────────────────────────\x1b[0m");
                println!("  \x1b[1;33m[!] КАК ИСПРАВИТЬ «Operation not permitted (os error 1)»:\x1b[0m");
                println!("  \x1b[37mmacOS блокирует изменение файлов в /Applications защитой TCC.\x1b[0m");
                println!("  \x1b[32m1.\x1b[0m Откройте «Системные настройки» -> «Конфиденциальность и безопасность»");
                println!("  \x1b[32m2.\x1b[0m Перейдите в раздел «Полный доступ к диску» (Full Disk Access)");
                println!("  \x1b[32m3.\x1b[0m Включите тумблер для вашего Терминала (Terminal или iTerm)");
                println!("  \x1b[32m4.\x1b[0m Перезапустите Терминал и запустите установщик снова");
                println!("  \x1b[36m────────────────────────────────────────────────────────────\x1b[0m");
            }
        }
    }
    println!(
        "{}",
        "============================================================"
    );
    println!("{}", "Чтобы вернуться в главное меню, нажмите Enter");
    let mut wait = String::new();
    io::stdin().read_line(&mut wait).unwrap();
}
