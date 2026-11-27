//! Full rollback: stop writers, undo independent components concurrently, then
//! remove owned data. Keep the disabled settings on any failure so a retry is
//! possible and a restart cannot silently enable auto-patching again.

use std::path::{Path, PathBuf};

pub fn run(manual: &[PathBuf]) -> Vec<String> {
    if let Err(e) = stop_services() {
        return vec![e];
    }
    let mut targets = crate::find_all_installs();
    targets.extend_from_slice(manual);
    targets = targets
        .into_iter()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .collect();
    targets.sort_by_key(|p| p.to_string_lossy().to_lowercase());
    targets.dedup_by(|a, b| {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    });
    let mut errors = stop_clients();
    if !errors.is_empty() {
        return errors;
    }
    #[cfg(windows)]
    if crate::paid::enabled() {
        if let Err(error) = crate::paid_windows::clean() {
            return vec![error];
        }
    }
    std::thread::scope(|scope| {
        let mut jobs = vec![scope.spawn(remove_network), scope.spawn(remove_environment)];
        for target in &targets {
            jobs.push(scope.spawn(move || revert_install(target)));
        }
        for job in jobs {
            match job.join() {
                Ok(found) => errors.extend(found),
                Err(_) => errors.push("Поток деактивации завершился аварийно".into()),
            }
        }
    });
    if errors.is_empty() {
        for dir in [
            crate::background::install_dir(),
            crate::dns_forwarder::log_dir(),
        ] {
            if let Err(e) = remove_owned_dir(&dir) {
                errors.push(e);
            }
        }
    }
    errors
}

#[cfg(windows)]
fn ps(script: &str) -> Result<(), String> {
    let out = crate::utils::powershell(&format!("$ErrorActionPreference='Stop'; {script}"))
        .ok_or("PowerShell: время ожидания истекло")?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(windows)]
fn stop_services() -> Result<(), String> {
    // Restore the shortcut and clear legacy IFEO filters before removing helpers.
    crate::launch_guard::restore_shortcut()?;
    crate::launch_guard::uninstall()?;
    ps(r#"
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Antigravity.exe',
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Antigravity.exe')) {
  if (Test-Path -LiteralPath $root) {
    foreach ($key in @(Get-ChildItem -LiteralPath $root)) {
      $p=Get-ItemProperty -LiteralPath $key.PSPath
      if ($p.AGUnlockerOwner -eq 'AGUnlocker' -or $key.PSChildName -like 'AGUnlocker_*') {
        throw 'Фильтр запуска анлокера не удалён'
      }
    }
    if ((Get-ItemProperty -LiteralPath $root).Debugger -like '*ag_dns*') { throw 'Перенаправление запуска анлокера не удалено' }
  }
}
"#)?;
    let exe = crate::background::installed_exe()
        .to_string_lossy()
        .replace('\'', "''");
    ps(&format!(
        r#"
$tasks=@(Get-ScheduledTask | Where-Object {{
  $_.TaskPath -eq '\' -and $_.TaskName -in @('AG Unlocker DNS','AG Unlocker Watchdog','AG Unlocker Reopen')
}})
foreach ($t in $tasks) {{ $t | Stop-ScheduledTask; $t | Unregister-ScheduledTask -Confirm:$false }}
$workers=@(Get-CimInstance Win32_Process -Filter "Name='ag_dns.exe'" | Where-Object {{ $_.ExecutablePath -eq '{exe}' }})
foreach ($w in $workers) {{
  try {{ Stop-Process -Id $w.ProcessId -Force }} catch {{
    if (Get-Process -Id $w.ProcessId -ErrorAction SilentlyContinue) {{ throw }}
  }}
}}
$deadline=(Get-Date).AddSeconds(5)
do {{
  $alive=@(Get-CimInstance Win32_Process -Filter "Name='ag_dns.exe'" | Where-Object {{ $_.ExecutablePath -eq '{exe}' }})
  if (!$alive.Count) {{ break }}
  Start-Sleep -Milliseconds 100
}} while ((Get-Date) -lt $deadline)
if ($alive.Count) {{ throw 'Фоновый анлокер не остановлен' }}
"#
    ))
}

#[cfg(not(windows))]
fn stop_services() -> Result<(), String> {
    crate::background::disable_watchdog();
    crate::background::disable()
}

#[cfg(windows)]
fn stop_clients() -> Vec<String> {
    ps(r#"
$names=@('Antigravity','Antigravity IDE','Antigravity CLI','agy','language_server','language_server_windows_x64')
foreach ($p in @(Get-Process -Name $names -ErrorAction SilentlyContinue)) {
  try { Stop-Process -InputObject $p -Force; $p.WaitForExit(5000) | Out-Null }
  catch { if (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) { throw } }
}
if (Get-Process -Name $names -ErrorAction SilentlyContinue) { throw 'Antigravity не закрыт' }
"#).err().into_iter().collect()
}

#[cfg(not(windows))]
fn stop_clients() -> Vec<String> {
    crate::patch_binary::kill_affected_processes();
    Vec::new()
}

fn remove_network() -> Vec<String> {
    crate::dns::remove_dns_nrpt_checked()
        .err()
        .into_iter()
        .collect()
}

fn remove_environment() -> Vec<String> {
    let mut errors = Vec::new();
    for result in [
        crate::endpoint::remove_proxy(&crate::proxy::proxy_url(), ""),
        crate::endpoint::remove_cli(),
        crate::endpoint::clear_node_ca(&crate::proxy::ca_cert_path().to_string_lossy()),
    ] {
        if let Err(e) = result {
            errors.push(e);
        }
    }
    #[cfg(windows)]
    if let Err(e) = ps(r#"
Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -eq 'CN=AG Unlocker local CA' } | Remove-Item -Force
"#)
    {
        errors.push(e);
    }
    errors
}

fn revert_install(inst: &Path) -> Vec<String> {
    let reverted = if crate::elevate::needs_root(inst) {
        match crate::elevate::unpatch_as_root(inst) {
            Ok(out) => out,
            Err(e) => return vec![e],
        }
    } else {
        crate::elevate::revert_files(inst)
    };
    let mut errors = reverted.errors;
    for target in crate::patch_binary::binary_targets(inst) {
        match std::fs::read(&target) {
            Ok(bytes)
                if bytes
                    .windows(crate::endpoint::PROXY_ENV_VAR.len())
                    .any(|w| w == crate::endpoint::PROXY_ENV_VAR.as_bytes()) =>
            {
                errors.push(format!(
                    "{}: переименование прокси осталось в бинарном файле",
                    target.display()
                ));
            }
            Ok(_) => {}
            Err(e) => errors.push(format!("{}: {e}", target.display())),
        }
    }
    errors.extend(reverted.warnings);
    if let Err(e) = crate::endpoint::remove_ide(inst) {
        errors.push(e);
    }
    if errors.is_empty() {
        #[cfg(target_os = "macos")]
        let resources = crate::macos::resources_dir(inst);
        #[cfg(not(target_os = "macos"))]
        let resources = inst.join("resources");
        let backup = resources.join("app.asar.bak");
        if backup.exists() {
            if let Err(e) = std::fs::remove_file(&backup) {
                errors.push(format!("{}: {e}", backup.display()));
            }
        }
    }
    errors
        .into_iter()
        .map(|e| {
            format!(
                "{}: {e}",
                crate::utils::mask_path(&inst.display().to_string())
            )
        })
        .collect()
}

fn remove_owned_dir(path: &Path) -> Result<(), String> {
    let owned = path.is_absolute()
        && path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("AGUnlocker"));
    if !owned {
        return Err(format!(
            "Отказ от удаления неожиданного пути: {}",
            path.display()
        ));
    }
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(format!("Отказ от удаления ссылки: {}", path.display()))
        }
        Ok(_) => std::fs::remove_dir_all(path).map_err(|e| format!("{}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_refuses_unowned_paths() {
        assert!(remove_owned_dir(Path::new(".")).is_err());
        assert!(remove_owned_dir(&std::env::temp_dir()).is_err());
    }

    #[test]
    fn rollback_restores_both_binary_edits_and_js_and_removes_backups() {
        let root = std::env::temp_dir().join(format!("ag_full_rollback_{}", std::process::id()));
        let bin_dir = root.join("resources/bin");
        let js_dir = root.join("resources/app/out");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&js_dir).unwrap();
        #[cfg(windows)]
        let binary = bin_dir.join("language_server.exe");
        #[cfg(not(windows))]
        let binary = bin_dir.join("language_server");
        let (original, patched) = crate::patch_binary::field_signatures();
        let mut bytes = patched.to_vec();
        bytes.extend_from_slice(crate::endpoint::PROXY_ENV_VAR.as_bytes());
        std::fs::write(&binary, bytes).unwrap();
        let js = js_dir.join("main.js");
        std::fs::write(&js, "rewritten body\n// UNLOCKED").unwrap();
        std::fs::write(js_dir.join("main.js.ag_backup"), "original body").unwrap();
        assert!(revert_install(&root).is_empty());
        let mut expected = original.to_vec();
        expected.extend_from_slice(&crate::patch_binary::proxy_var_original());
        assert_eq!(std::fs::read(&binary).unwrap(), expected);
        assert_eq!(std::fs::read_to_string(&js).unwrap(), "original body");
        assert!(!js_dir.join("main.js.ag_backup").exists());
        assert!(
            revert_install(&root).is_empty(),
            "an already clean installation is a successful no-op"
        );
        std::fs::write(&js, "rewritten body\n// UNLOCKED").unwrap();
        assert!(
            !revert_install(&root).is_empty(),
            "a lost backup must prevent a clean success"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_removes_only_the_dedicated_state_directory_and_is_idempotent() {
        let root = std::env::temp_dir().join(format!("ag_cleanup_{}", std::process::id()));
        let owned = root.join("AGUnlocker");
        std::fs::create_dir_all(owned.join("nested")).unwrap();
        std::fs::write(owned.join("nested/settings.json"), b"test").unwrap();
        std::fs::write(root.join("unrelated.txt"), b"keep").unwrap();
        remove_owned_dir(&owned).unwrap();
        remove_owned_dir(&owned).unwrap();
        assert_eq!(std::fs::read(root.join("unrelated.txt")).unwrap(), b"keep");
        std::fs::remove_dir_all(root).unwrap();
    }
}
