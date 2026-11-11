//! A Desktop launch barrier. IFEO redirects only known Desktop paths here;
//! polling alone cannot run before the updater's immediate --force-run launch.
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::DebugActiveProcessStop;
use windows_sys::Win32::System::Threading::*;

use crate::patch_binary::RepatchOutcome;

pub const FLAG: &str = "--desktop-launch";
const IFEO: &str = r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Antigravity.exe";
const OWNER: &str = "AGUnlocker";
const WAIT: Duration = Duration::from_secs(120);

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn registry(script: &str) -> Result<(), String> {
    let script = format!("$ErrorActionPreference='Stop'; {script}");
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

/// A path filter avoids intercepting another user's installation or the IDE.
/// Never overwrite a debugger installed by another tool, or remove its values.
pub fn install() -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let mut roots = crate::discover_installs_fast();
    for manual in crate::settings::manual_paths() {
        if let Some(root) = crate::resolve_install_root(&manual) {
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
    }
    let debugger = format!(
        "\"{}\" {FLAG}",
        crate::background::installed_exe().display()
    );
    let mut script = format!(
        "$root={}; if (!(Test-Path -LiteralPath $root)) {{ New-Item -Path $root | Out-Null }}; \
         $p=Get-ItemProperty -LiteralPath $root; \
         if ($p.Debugger) {{ throw 'Antigravity already has an IFEO debugger' }}; \
         if ($null -ne $p.UseFilter -and $p.UseFilter -ne 1) {{ throw 'IFEO UseFilter conflicts' }}; \
         New-ItemProperty -LiteralPath $root -Name UseFilter -Value 1 -PropertyType DWord -Force | Out-Null; ",
        ps_quote(IFEO)
    );
    for root in roots {
        let exe = root.join("Antigravity.exe");
        if !exe.is_file() || !root.join("resources/bin/language_server.exe").is_file() {
            continue;
        }
        let path = exe.to_string_lossy();
        let id = hex::encode(Sha256::digest(path.to_lowercase().as_bytes()));
        script.push_str(&format!(
            "$key=Join-Path $root '{}_{}'; \
             if (Test-Path -LiteralPath $key) {{ \
               $old=Get-ItemProperty -LiteralPath $key; \
               if ($old.AGUnlockerOwner -ne '{}') {{ throw 'IFEO filter is not ours' }} \
             }}; \
             if (!(Test-Path -LiteralPath $key)) {{ New-Item -Path $key | Out-Null }}; \
             New-ItemProperty -LiteralPath $key -Name AGUnlockerOwner -Value '{}' -PropertyType String -Force | Out-Null; \
             New-ItemProperty -LiteralPath $key -Name FilterFullPath -Value {} -PropertyType String -Force | Out-Null; \
             New-ItemProperty -LiteralPath $key -Name Debugger -Value {} -PropertyType String -Force | Out-Null; ",
            OWNER, &id[..16], OWNER, OWNER, ps_quote(&path), ps_quote(&debugger)
        ));
    }
    registry(&script)
}

pub fn uninstall() -> Result<(), String> {
    registry(&format!(
        "$root={}; if (Test-Path -LiteralPath $root) {{ \
           Get-ChildItem -LiteralPath $root | ForEach-Object {{ \
             $p=Get-ItemProperty -LiteralPath $_.PSPath; \
             if ($p.AGUnlockerOwner -eq '{}') {{ Remove-Item -LiteralPath $_.PSPath -Recurse }} \
           }} \
         }}",
        ps_quote(IFEO),
        OWNER
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

fn prepare(exe: &Path) -> Result<(), String> {
    let root = exe.parent().ok_or("Desktop has no parent directory")?;
    let target = root.join("resources/bin/language_server.exe");
    let deadline = Instant::now() + WAIT;
    let mut previous = None;
    let mut last = "updater is still writing files".to_string();
    crate::watchdog::log("Desktop launch: waiting for update completion and patch");
    loop {
        if !crate::settings::auto_patch_wanted() {
            return Ok(());
        }
        let shape = fs::metadata(&target)
            .and_then(|m| Ok((m.len(), m.modified()?)))
            .ok();
        if !crate::watchdog::updater_busy(&crate::watchdog::updater_dirs())
            && shape.is_some()
            && shape == previous
        {
            match crate::patch_binary::repatch_before_launch(&target) {
                RepatchOutcome::AlreadyPatched | RepatchOutcome::Repatched(_) => {
                    check_stamp(&target)?;
                    crate::watchdog::log("Desktop launch: patch ready, launch allowed");
                    return Ok(());
                }
                RepatchOutcome::SignatureMissing => return Err("Эта версия Language Server не поддерживается. Обновите анлокер; запуск остановлен.".into()),
                RepatchOutcome::Failed(e) | RepatchOutcome::Deferred(e) => last = e,
            }
        }
        previous = shape;
        if Instant::now() >= deadline {
            return Err(format!("Не удалось подготовить Language Server: {last}"));
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn check_stamp(target: &Path) -> Result<(), String> {
    let mut cmd = std::process::Command::new(target);
    cmd.arg("--stamp");
    let out =
        crate::utils::bounded_output(crate::utils::no_window(&mut cmd), Duration::from_secs(15))
            .ok_or("Language Server --stamp did not complete; Desktop launch stopped")?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Language Server --stamp failed ({}): {}",
            out.status,
            crate::utils::mask_path(String::from_utf8_lossy(&out.stderr).trim())
        ))
    }
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// DEBUG_ONLY_THIS_PROCESS bypasses IFEO recursively. Detach before the first
/// instruction executes, then release the explicitly suspended primary thread.
fn launch(exe: &Path, command: &mut [u16]) -> Result<Handle, String> {
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    unsafe {
        GetStartupInfoW(&mut si);
    }
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // The parent's CRT handle table is private to that process; forwarding its
    // reserved blob makes a console child initialise invalid descriptors.
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
            DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
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
    let detached = unsafe { DebugActiveProcessStop(pi.dwProcessId) };
    if detached == 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            TerminateProcess(process.0, 1);
        }
        return Err(format!("Detach Desktop: {error}"));
    }
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
        // Chromium starts its helpers through the same image. They must not
        // wait for the updater or rescan a 150 MB binary on every renderer.
        if !args
            .iter()
            .skip(3)
            .any(|a| a.to_string_lossy().starts_with("--type="))
        {
            prepare(&exe)?;
        }
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
