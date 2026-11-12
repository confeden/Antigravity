//! A Desktop launch barrier cleanup. IFEO is retired: intercepting Chromium
//! child processes breaks Mojo IPC and Sandbox (N38, G94).
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::*;

pub const FLAG: &str = "--desktop-launch";
const OWNER: &str = "AGUnlocker";

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
        if !exe.is_absolute()
            || !exe
                .file_name()
                .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("Antigravity.exe"))
        {
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
        crate::utils::message_box("Antigravity Unlocker", &e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
