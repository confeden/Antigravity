use std::env;
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

/// Attaches this process to the console of whoever launched it, if there is
/// one, so a windows-subsystem binary can still answer `--about` on stdout.
/// Does nothing when launched from a shortcut (no parent console) - the caller
/// must not depend on output appearing.
#[cfg(target_os = "windows")]
pub fn attach_parent_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(dw_process_id: u32) -> i32;
        fn GetStdHandle(n_std_handle: u32) -> *mut std::ffi::c_void;
        fn SetStdHandle(n_std_handle: u32, h_handle: *mut std::ffi::c_void) -> i32;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *mut std::ffi::c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;
    }

    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
    const STD_ERROR_HANDLE: u32 = (-12i32) as u32;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    let invalid_handle = (-1isize) as *mut std::ffi::c_void;

    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);

        let conout: Vec<u16> = "CONOUT$\0".encode_utf16().collect();
        // Only a stream that has nowhere to go gets repointed at the console.
        //
        // A windows-subsystem process started from a shell normally has no std
        // handles at all, which is why they have to be opened here. But
        // `AG_2.12.2.exe --about > provenance.txt` starts with a perfectly good
        // handle to that file, and repointing stdout at CONOUT$ regardless would
        // put the banner on screen and leave the file empty — breaking the one
        // use the flag exists for.
        for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let existing = GetStdHandle(which);
            if !existing.is_null() && existing != invalid_handle {
                continue;
            }
            let h = CreateFileW(
                conout.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if h != invalid_handle && !h.is_null() {
                SetStdHandle(which, h);
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn attach_parent_console() {}

/// A last-resort message box, for failures that happen before or instead of the
/// window. Nothing else can be shown at that point: a windows-subsystem process
/// has no console to print to.
#[cfg(target_os = "windows")]
pub fn message_box(title: &str, text: &str) {
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(
            hwnd: *mut std::ffi::c_void,
            text: *const u16,
            caption: *const u16,
            utype: u32,
        ) -> i32;
    }
    let wide_text: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide_text.as_ptr(),
            wide_title.as_ptr(),
            0x10, // MB_ICONERROR
        );
    }
}

/// The same on Linux, and it has to be a *dialog* for the same reason it is one
/// on Windows.
///
/// The only caller is `gui::run` failing to open a window at all — no GL driver,
/// no adapter, no X11 and no Wayland. That user started the tool by double
/// clicking a launcher, so there is no terminal for `eprintln!` to reach and the
/// program appears to do nothing whatsoever. stderr still gets the text (for a
/// run from a shell); the dialog is the copy the desktop user can see. Best
/// effort by design: none of these three is guaranteed to be installed, and a
/// missing one must not turn a diagnostic into a second failure.
#[cfg(not(target_os = "windows"))]
pub fn message_box(title: &str, text: &str) {
    eprintln!("{}: {}", title, text);
    let tried = [
        (
            "zenity",
            vec!["--error", "--no-markup", "--title", title, "--text", text],
        ),
        ("kdialog", vec!["--title", title, "--error", text]),
        ("xmessage", vec!["-center", text]),
    ];
    for (bin, args) in tried {
        if Command::new(bin)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
        {
            return;
        }
    }
}

// Open a URL in the system default browser (Windows: cmd /c start "" <url>).
pub fn open_url(url: &str) {
    #[cfg(target_os = "windows")]
    {
        // ShellExecuteW rather than `cmd /C start`: the GUI build has no console
        // of its own, so spawning cmd.exe flashes a black window on screen for
        // every link the user clicks. This asks the shell directly and shows
        // nothing.
        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                hwnd: *mut std::ffi::c_void,
                op: *const u16,
                file: *const u16,
                params: *const u16,
                dir: *const u16,
                show: i32,
            ) -> *mut std::ffi::c_void;
        }
        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }
        const SW_SHOWNORMAL: i32 = 1;
        let op = wide("open");
        let file = wide(url);
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                op.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("xdg-open").arg(url).status().ok();
    }
}

/// The clipboard as text, or `None` if it holds none.
///
/// Through `arboard` rather than a hand-rolled `OpenClipboard`/`GetClipboardData`
/// pair, and it costs nothing to do so: eframe's own clipboard support is
/// `arboard`, so the crate is already linked into this binary — this only asks it
/// a question eframe never exposes. egui hands a *paste* to the focused widget
/// when the user presses Ctrl+V and offers no way to ask for one, which is why
/// the right-click-to-paste on the licence field needs to read the clipboard
/// itself.
pub fn clipboard_text() -> Option<String> {
    let mut cb = arboard::Clipboard::new().ok()?;
    let text = cb.get_text().ok()?;
    (!text.trim().is_empty()).then_some(text)
}

/// Starts this exe again through the shell's `runas` verb, i.e. behind a UAC
/// prompt, and reports whether the new process was actually launched.
///
/// There is no way to gain elevation in place: on Windows it is a property of
/// the process token, fixed at creation. The window therefore cannot "become"
/// admin — the honest button is one that starts over. A user who dismisses the
/// UAC dialog gets `false` here and keeps the window they had.
#[cfg(target_os = "windows")]
pub fn relaunch_elevated() -> bool {
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut std::ffi::c_void,
            op: *const u16,
            file: *const u16,
            params: *const u16,
            dir: *const u16,
            show: i32,
        ) -> *mut std::ffi::c_void;
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let Ok(exe) = env::current_exe() else {
        return false;
    };
    let op = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let dir = exe
        .parent()
        .map(|p| wide(&p.to_string_lossy()))
        .unwrap_or_else(|| wide(""));
    const SW_SHOWNORMAL: i32 = 1;
    // ShellExecuteW returns a value <= 32 for every failure, including the user
    // saying no to the prompt (SE_ERR_ACCESSDENIED). Anything above that means a
    // process really started.
    let rc = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            op.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            dir.as_ptr(),
            SW_SHOWNORMAL,
        )
    };
    rc as isize > 32
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
    match env::var("HOME") {
        Ok(home) if !home.is_empty() => path.replace(&home, "~"),
        _ => path.to_string(),
    }
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

/// Local wall clock, in the fields a log line is stamped with.
///
/// Local rather than UTC because both readers compare it against something a
/// *person* saw: the relay's own log, and the glog header Antigravity writes.
/// `second_of_day` rather than three fields because every question asked of it
/// is "how long ago", and that is one subtraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalClock {
    pub month: u16,
    pub day: u16,
    pub second_of_day: u32,
}

impl LocalClock {
    pub fn hms(&self) -> String {
        format!(
            "{:02}:{:02}:{:02}",
            self.second_of_day / 3600,
            (self.second_of_day / 60) % 60,
            self.second_of_day % 60
        )
    }
}

/// `GetLocalTime`, because this is the only place in the tool that needs a
/// calendar and a date crate for one struct is not worth the dependency.
///
/// `None` where there is no such call: a caller that cannot compare against a
/// local clock says nothing rather than guessing at an offset.
#[cfg(target_os = "windows")]
pub fn local_clock() -> Option<LocalClock> {
    #[repr(C)]
    #[derive(Default)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }
    extern "system" {
        fn GetLocalTime(out: *mut SystemTime);
    }
    let mut t = SystemTime::default();
    unsafe { GetLocalTime(&mut t) };
    Some(LocalClock {
        month: t.month,
        day: t.day,
        second_of_day: t.hour as u32 * 3600 + t.minute as u32 * 60 + t.second as u32,
    })
}

#[cfg(not(target_os = "windows"))]
pub fn local_clock() -> Option<LocalClock> {
    None
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
