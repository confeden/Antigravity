//! The NSIS installer opens the preserved Start Menu shortcut after installing.
//! Only that shortcut uses the helper. IFEO remains retired (N38, G94).
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Threading::*;

pub const FLAG: &str = "--desktop-launch";
pub const SHORTCUT_FLAG: &str = "--desktop-shortcut";
const OWNER: &str = "AGUnlocker";

pub fn shortcut_helper() -> PathBuf {
    crate::dns_forwarder::log_dir().join("ag_launch.exe")
}

// The Desktop NSIS install owns a per-user Antigravity.lnk and sets KeepShortcuts.
// Only opt in an uncustomized target and keep the link's icon and other metadata.
const SHORTCUT_SCRIPT: &str = r#"
function Get-LauncherDigest($file) {
    $stream = [IO.File]::OpenRead($file)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [Convert]::ToBase64String($sha.ComputeHash($stream)) }
    finally { $stream.Dispose(); $sha.Dispose() }
}
if (!(Test-Path -LiteralPath $path -PathType Leaf)) { return }
$link = (New-Object -ComObject WScript.Shell).CreateShortcut($path)
if (!$enable) {
    if ($link.TargetPath -ne $helper) { return }
    if ($link.Arguments -notmatch ('^' + [regex]::Escape($flag) + ' "([^"]+)"$')) {
        throw 'Unexpected arguments on the Unlocker launch shortcut'
    }
    $link.TargetPath = $Matches[1]
    $link.Arguments = ''
    $link.Save()
    return
}
if ($link.TargetPath -eq $helper -and $link.Arguments -ne ($flag + ' "' + $app + '"')) {
    throw 'Unexpected arguments on the Unlocker launch shortcut'
}
if ($link.TargetPath -ne $helper -and ($link.TargetPath -ne $app -or $link.Arguments)) { return }
if (!(Test-Path -LiteralPath $helper -PathType Leaf) -or
    (Get-LauncherDigest $helper) -cne (Get-LauncherDigest $source)) {
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($helper))
    $temp = $helper + '.' + $PID + '.tmp'
    try {
        [IO.File]::Copy($source, $temp)
        if ([IO.File]::Exists($helper)) { [IO.File]::Replace($temp, $helper, [NullString]::Value) }
        else { [IO.File]::Move($temp, $helper) }
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}
if ($link.TargetPath -eq $helper) { return }
if ($link.IconLocation -eq ',0') { $link.IconLocation = $app + ',0' }
$link.TargetPath = $helper
$link.Arguments = $flag + ' "' + $app + '"'
$link.Save()
"#;

pub fn arm_shortcut() -> Result<(), String> {
    if updater_busy(&crate::watchdog::updater_dirs()).map_err(|e| e.to_string())? {
        return Ok(());
    }
    configure_shortcut(true)
}

pub fn restore_shortcut() -> Result<(), String> {
    configure_shortcut(false)
}

fn configure_shortcut(enable: bool) -> Result<(), String> {
    let quote = |p: &Path| p.to_string_lossy().replace('\'', "''");
    let enable = if enable { "$true" } else { "$false" };
    let script = format!(
        r#"$ErrorActionPreference='Stop'; $enable={enable}; $flag='{SHORTCUT_FLAG}';
$helper='{helper}'; $source='{source}';
$path=Join-Path ([Environment]::GetFolderPath('Programs')) 'Antigravity.lnk';
if ($enable) {{
    $key = 'HKCU:\Software\121a0be4-63bd-531e-acf8-fc3924c7e984';
    if (!(Test-Path -LiteralPath $key)) {{ return }}
    $install = Get-ItemProperty -LiteralPath $key;
    if ($install.KeepShortcuts -ne 'true' -or $install.ShortcutName -ne 'Antigravity' -or
        $install.MenuDirectory -or !$install.InstallLocation) {{ return }}
    $app = Join-Path $install.InstallLocation 'Antigravity.exe';
    if (!(Test-Path -LiteralPath $app -PathType Leaf)) {{ return }}
}}
{SHORTCUT_SCRIPT}"#,
        helper = quote(&shortcut_helper()),
        source = quote(&crate::background::installed_exe()),
    );
    let output = crate::utils::powershell_within(&script, Duration::from_secs(8))
        .ok_or("Desktop shortcut: PowerShell timed out")?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Desktop shortcut: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub fn run_shortcut() {
    let mut args = std::env::args_os().skip(2);
    let Some(app) = args.next().map(PathBuf::from).filter(|p| is_desktop_exe(p)) else {
        report_launch_error("Unexpected Desktop path");
        return;
    };
    let args: Vec<_> = args.collect();
    let has_updated = args.iter().any(|a| a == "--updated");
    if crate::settings::auto_patch_wanted() {
        let server = app
            .with_file_name("resources")
            .join("bin")
            .join("language_server.exe");
        let stamp = desktop_patch_stamp_path();
        if let Err(e) = patch_on_shortcut_launch(
            &server,
            &crate::watchdog::updater_dirs(),
            &stamp,
            has_updated,
        ) {
            crate::watchdog::log(&format!("Desktop launch patch skipped: {e}"));
        }
    }
    if let Err(e) = Command::new(&app).args(args).spawn() {
        report_launch_error(&e.to_string());
    }
}

fn desktop_patch_stamp_path() -> PathBuf {
    crate::dns_forwarder::log_dir().join("desktop_patch_stamp.txt")
}

fn server_stamp(server: &Path) -> Option<String> {
    let meta = fs::metadata(server).ok()?;
    let modified = meta.modified().ok()?;
    let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(format!(
        "{}\n{}\n{}:{}",
        server.to_string_lossy().to_ascii_lowercase(),
        meta.len(),
        dur.as_secs(),
        dur.subsec_nanos()
    ))
}

fn stamp_matches(stamp_path: &Path, server: &Path) -> bool {
    let Some(cur) = server_stamp(server) else {
        return false;
    };
    fs::read_to_string(stamp_path).is_ok_and(|saved| saved == cur)
}

fn write_stamp(stamp_path: &Path, server: &Path) {
    let Some(stamp) = server_stamp(server) else {
        return;
    };
    if let Some(parent) = stamp_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(stamp_path, stamp).ok();
}

fn patch_on_shortcut_launch(
    server: &Path,
    dirs: &[PathBuf],
    stamp_path: &Path,
    has_updated: bool,
) -> Result<(), String> {
    if !has_updated {
        if crate::patch_binary::is_image_locked(server) {
            return Ok(());
        }
        if !updater_busy(dirs).unwrap_or(false) && stamp_matches(stamp_path, server) {
            return Ok(());
        }
    }
    patch_after_update(server, dirs)?;
    write_stamp(stamp_path, server);
    Ok(())
}

fn is_desktop_exe(path: &Path) -> bool {
    path.is_absolute()
        && path
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("Antigravity.exe"))
}

fn patch_after_update(server: &Path, dirs: &[PathBuf]) -> Result<(), String> {
    use crate::patch_binary::{self, RepatchOutcome::*};
    let deadline = Instant::now() + Duration::from_secs(8);
    while updater_busy(dirs).map_err(|e| format!("could not check installer: {e}"))? {
        if Instant::now() >= deadline {
            return Err("installer is still running".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    match patch_binary::repatch_before_launch(server) {
        Repatched(n) => {
            crate::watchdog::log(&format!("Desktop launch after update: patched ({n})"));
            Ok(())
        }
        AlreadyPatched => Ok(()),
        SignatureMissing => Err("language server signature not recognized".into()),
        Deferred(e) | Failed(e) => Err(e),
    }
}

fn report_launch_error(error: &str) {
    crate::watchdog::log(&format!("Desktop launch failed: {error}"));
    crate::utils::message_box(crate::APP_NAME, error);
    std::process::exit(1);
}

/// Check the staged NSIS image and electron-updater's fallback installer by
/// process image path. The observer never opens the installer file for writing.
pub(crate) fn updater_busy(dirs: &[PathBuf]) -> io::Result<bool> {
    let mut installers = Vec::new();
    for dir in dirs {
        let cached = dir.with_file_name("installer.exe");
        if cached.try_exists()? {
            installers.push(cached);
        }
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries {
                    let path = entry?.path();
                    if path
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
                    {
                        installers.push(path);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    if installers.is_empty() {
        return Ok(false);
    }
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = Handle(snapshot);
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }
    loop {
        let name = OsString::from_wide(
            entry
                .szExeFile
                .split(|c| *c == 0)
                .next()
                .unwrap_or_default(),
        );
        if installers.iter().any(|path| {
            path.file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case(&name))
        }) {
            match process_image(entry.th32ProcessID) {
                Ok(Some(image))
                    if installers
                        .iter()
                        .any(|path| path.as_os_str().eq_ignore_ascii_case(&image)) =>
                {
                    return Ok(true)
                }
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                Ok(false)
            } else {
                Err(error)
            };
        }
    }
}

fn process_image(pid: u32) -> io::Result<Option<OsString>> {
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if process.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let process = Handle(process);
    let mut path = vec![0; 32_768];
    let mut size = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut size) } == 0 {
        let error = io::Error::last_os_error();
        // Windows can unmap the image while the process is still exiting.
        return if unsafe { WaitForSingleObject(process.0, 50) } == WAIT_OBJECT_0 {
            Ok(None)
        } else {
            Err(error)
        };
    }
    Ok(Some(OsString::from_wide(&path[..size as usize])))
}

fn registry(script: &str) -> Result<(), String> {
    let script = format!("$ErrorActionPreference='Continue'; {script}");
    let out = crate::utils::powershell(&script)
        .ok_or_else(|| "launch guard: PowerShell did not complete".to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "launch guard: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Retired: IFEO Debugger breaks Chromium/Electron multi-process architecture (N38).
/// Always uninstalls any lingering filters.
#[allow(dead_code)]
pub fn install() -> Result<(), String> {
    uninstall()
}

pub fn uninstall() -> Result<(), String> {
    registry(&format!(
        "@('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Antigravity.exe', \
           'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Antigravity.exe') | ForEach-Object {{ \
             $root = $_; \
             if (Test-Path -LiteralPath $root) {{ \
               try {{ \
                 Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {{ \
                   $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue; \
                   if ($p.AGUnlockerOwner -eq '{owner}' -or $_.PSChildName -like '{owner}_*') {{ \
                     Remove-Item -LiteralPath $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue \
                   }} \
                 }}; \
                 $remaining = Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue; \
                 $prop = Get-ItemProperty -LiteralPath $root -ErrorAction SilentlyContinue; \
                 if (($null -eq $remaining -or $remaining.Count -eq 0) -and ($null -eq $prop.Debugger -or $prop.Debugger -like '*ag_dns*')) {{ \
                   Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue \
                 }} \
               }} catch {{}} \
             }} \
           }}; \
         $compat = 'HKCU:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers'; \
         if (Test-Path -LiteralPath $compat) {{ \
           try {{ \
             (Get-ItemProperty -LiteralPath $compat -ErrorAction SilentlyContinue).PSObject.Properties | \
               Where-Object {{ $_.Name -like '*Antigravity.exe' }} | \
               ForEach-Object {{ \
                 if ($_.Value -match '640X480|256COLOR') {{ \
                   Remove-ItemProperty -LiteralPath $compat -Name $_.Name -ErrorAction SilentlyContinue \
                 }} \
               }} \
           }} catch {{}} \
         }}",
        owner = OWNER
    ))
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// Only strip our two simple prefix arguments. The original Windows command
/// line (including quotes, Unicode and backslashes) is forwarded byte for byte.
fn command_tail(raw: &[u16]) -> Option<Vec<u16>> {
    let mut i = 0;
    for _ in 0..2 {
        while raw.get(i).is_some_and(|c| *c == 32 || *c == 9) {
            i += 1;
        }
        let start = i;
        let mut quoted = false;
        while let Some(&c) = raw.get(i) {
            if c == 34 {
                quoted = !quoted;
            }
            if !quoted && (c == 32 || c == 9) {
                break;
            }
            i += 1;
        }
        if i == start || quoted {
            return None;
        }
    }
    while raw.get(i).is_some_and(|c| *c == 32 || *c == 9) {
        i += 1;
    }
    (i < raw.len()).then(|| raw[i..].to_vec())
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn launch(exe: &Path, command: &mut [u16]) -> Result<Handle, String> {
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    unsafe {
        GetStartupInfoW(&mut si);
    }
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.lpReserved = ptr::null_mut();
    si.cbReserved2 = 0;
    si.lpReserved2 = ptr::null_mut();
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            wide(exe.as_os_str()).as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            (si.dwFlags & STARTF_USESTDHANDLES != 0) as i32,
            CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(format!(
            "CreateProcess: {}",
            std::io::Error::last_os_error()
        ));
    }
    let process = Handle(pi.hProcess);
    let thread = Handle(pi.hThread);
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        let error = std::io::Error::last_os_error();
        unsafe {
            TerminateProcess(process.0, 1);
        }
        return Err(format!("Resume Desktop: {error}"));
    }
    Ok(process)
}

pub fn run() {
    let result = (|| {
        let args: Vec<_> = std::env::args_os().collect();
        let exe = PathBuf::from(args.get(2).ok_or("Desktop path is missing")?);
        if !is_desktop_exe(&exe) {
            return Err("Unexpected Desktop path".to_string());
        }
        // Remove lingering IFEO filter and bad compat flags so that child
        // processes and future launches run natively.
        let _ = uninstall();

        unsafe extern "system" {
            fn GetCommandLineW() -> *const u16;
        }
        let raw = unsafe { GetCommandLineW() };
        let mut len = 0;
        while unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        let mut command = command_tail(unsafe { std::slice::from_raw_parts(raw, len) })
            .ok_or("Desktop command line is missing")?;
        command.push(0);
        launch(&exe, &mut command)?;
        Ok::<_, String>(())
    })();
    if let Err(e) = result {
        crate::watchdog::log(&format!("Desktop launch stopped: {e}"));
        crate::utils::message_box(crate::APP_NAME, &e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_is_retargeted_and_restored() {
        let dir = std::env::temp_dir().join(format!("agu-shortcut-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let script = format!(
            r#"$ErrorActionPreference='Stop'; $dir='{}'; $flag='{SHORTCUT_FLAG}';
$app=Join-Path $dir 'Antigravity.exe'; $helper=Join-Path $dir 'ag_launch.exe';
$source=Join-Path $dir 'ag_dns.exe'; $path=Join-Path $dir 'Antigravity.lnk';
[IO.File]::WriteAllText($app, 'fixture'); [IO.File]::WriteAllText($source, 'first');
$shell=New-Object -ComObject WScript.Shell;
$link=$shell.CreateShortcut($path);
$link.TargetPath=$app; $link.WorkingDirectory=$dir; $link.Description='fixture'; $link.Save();
$enable=$true;
& {{ {SHORTCUT_SCRIPT} }}
$link=$shell.CreateShortcut($path);
if ($link.TargetPath -ne $helper -or $link.Arguments -ne ($flag + ' "' + $app + '"') -or
    $link.WorkingDirectory -ne $dir -or $link.Description -ne 'fixture') {{ throw 'Link metadata' }}
[IO.File]::WriteAllText($source, 'second');
& {{ {SHORTCUT_SCRIPT} }}
if ([IO.File]::ReadAllText($helper) -ne 'second') {{ throw 'Helper was not replaced' }}
$enable=$false;
& {{ {SHORTCUT_SCRIPT} }}
$link=$shell.CreateShortcut($path);
if ($link.TargetPath -ne $app -or $link.Arguments -or $link.WorkingDirectory -ne $dir) {{ throw 'Restore failed' }}
"#,
            dir.display().to_string().replace('\'', "''"),
        );
        let out = crate::utils::powershell_within(&script, Duration::from_secs(20)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn post_update_patch_waits_for_the_running_installer_to_exit() {
        use std::fs;
        use std::process::Stdio;

        let dir = std::env::temp_dir().join(format!("agu-update-{}", std::process::id()));
        let pending = dir.join("pending");
        fs::create_dir_all(&pending).unwrap();
        let installer = pending.join("Antigravity-x64.exe");
        let cmd = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/cmd.exe");
        fs::copy(cmd, &installer).unwrap();
        let server = dir.join("language_server.exe");
        fs::write(&server, b"..ineligible..https_proxy..").unwrap();
        let mut child = crate::utils::no_window(&mut Command::new(&installer))
            .args(["/d", "/c", "set /p AG_FIXTURE="])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        assert!(updater_busy(std::slice::from_ref(&pending)).unwrap());
        std::thread::scope(|scope| {
            let patch = scope.spawn(|| patch_after_update(&server, std::slice::from_ref(&pending)));
            std::thread::sleep(Duration::from_millis(150));
            let before_exit = fs::read(&server).unwrap();
            drop(child.stdin.take());
            child.wait().unwrap();
            assert_eq!(before_exit, b"..ineligible..https_proxy..");
            patch.join().unwrap().unwrap();
        });
        assert!(fs::read(&server).unwrap().starts_with(b"..inexigible.."));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn preserves_the_original_command_line() {
        let tail = r#""C:\App\Antigravity.exe" --file "D:\тест\a b" --value="a\\\"b""#;
        let raw: Vec<_> = format!(r#""C:\Program Data\guard.exe" {FLAG} {tail}"#)
            .encode_utf16()
            .collect();
        assert_eq!(
            String::from_utf16(&command_tail(&raw).unwrap()).unwrap(),
            tail
        );
    }

    #[test]
    fn a_released_child_runs_and_keeps_its_exit_code() {
        let exe = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let mut command = wide(OsStr::new(&format!("\"{}\" /d /c exit 7", exe.display())));
        let child = launch(&exe, &mut command).expect("launch and detach");
        assert_eq!(unsafe { WaitForSingleObject(child.0, 10_000) }, 0);
        let mut exit = 0;
        assert_ne!(unsafe { GetExitCodeProcess(child.0, &mut exit) }, 0);
        assert_eq!(exit, 7);
    }

    #[test]
    fn shortcut_launch_patches_without_updated_flag_and_uses_stamp_cache() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = std::env::temp_dir().join(format!("agu-stamp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let server = dir.join("language_server.exe");
        let stamp = dir.join("desktop_patch_stamp.txt");
        let dirs: Vec<PathBuf> = Vec::new();

        fs::write(&server, b"..ineligible..https_proxy..").unwrap();
        patch_on_shortcut_launch(&server, &dirs, &stamp, false).unwrap();
        assert_eq!(fs::read(&server).unwrap(), b"..inexigible..AG_LS_PROXY..");
        assert!(stamp_matches(&stamp, &server));

        // Simulate an already-running Desktop binary while stamp is cached: must skip cleanly.
        {
            let _holder = fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&server)
                .unwrap();
            patch_on_shortcut_launch(&server, &dirs, &stamp, false).unwrap();
        }

        // Replace with a newer build (different length) and launch without --updated.
        fs::write(&server, b"..new-build..ineligible..https_proxy..").unwrap();
        assert!(!stamp_matches(&stamp, &server));
        patch_on_shortcut_launch(&server, &dirs, &stamp, false).unwrap();
        assert_eq!(
            fs::read(&server).unwrap(),
            b"..new-build..inexigible..AG_LS_PROXY.."
        );
        assert!(stamp_matches(&stamp, &server));

        fs::remove_dir_all(&dir).ok();
    }
}
