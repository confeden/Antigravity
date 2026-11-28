//! Per-user shell integration and the verified Windows installer handoff.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::update::{self, ReleaseAsset, ReleaseInfo};

const SHORTCUT: &str = r#"
$root = (New-Object -ComObject WScript.Shell).SpecialFolders.Item('Startup')
if (!$root) { throw 'Windows Startup folder is unavailable' }
$path = Join-Path $root 'AI Unlocker.lnk'
$shell = New-Object -ComObject WScript.Shell
$marker = 'AI Unlocker (startup)'
$exists = Test-Path -LiteralPath $path -PathType Leaf
if ($exists -and $shell.CreateShortcut($path).Description -ne $marker) {
    throw 'AI Unlocker.lnk is already used by another shortcut'
}
switch ($env:AI_UNLOCKER_SHORTCUT_MODE) {
  'on' {
    if (!(Test-Path -LiteralPath $root -PathType Container)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    $link = $shell.CreateShortcut($path)
    $link.TargetPath = $env:AI_UNLOCKER_SHORTCUT_TARGET
    $link.WorkingDirectory = [IO.Path]::GetDirectoryName($link.TargetPath)
    $link.Description = $marker
    $link.Save()
    Write-Output 'on'
  }
  'off' {
    if ($exists) { Remove-Item -LiteralPath $path }
    Write-Output 'off'
  }
  'read' { if ($exists) { Write-Output 'on' } else { Write-Output 'off' } }
  default { throw 'Invalid startup mode' }
}
"#;

pub fn startup(enabled: Option<bool>) -> Result<bool, String> {
    let mode = match enabled {
        Some(true) => "on",
        Some(false) => "off",
        None => "read",
    };
    let cwd_exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let target = installed_exe()
        .filter(|path| path.is_file())
        .unwrap_or(cwd_exe);
    let mut cmd = powershell(SHORTCUT);
    cmd.env("AI_UNLOCKER_SHORTCUT_MODE", mode)
        .env("AI_UNLOCKER_SHORTCUT_TARGET", target);
    match run(&mut cmd, Duration::from_secs(12))?.trim() {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err("Windows вернула неизвестное состояние автозапуска".into()),
    }
}

fn installed_exe() -> Option<PathBuf> {
    Some(
        PathBuf::from(std::env::var_os("LOCALAPPDATA")?)
            .join(r"Programs\AI Unlocker\ag_unlocker.exe"),
    )
}

fn powershell(script: &str) -> Command {
    let system = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let mut cmd =
        Command::new(PathBuf::from(system).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"));
    cmd.args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; {script}"
    ));
    crate::utils::no_window(&mut cmd);
    cmd
}

fn run(cmd: &mut Command, timeout: Duration) -> Result<String, String> {
    let out =
        crate::utils::bounded_output(cmd, timeout).ok_or("Команда Windows не ответила вовремя")?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let errors = String::from_utf8_lossy(&out.stderr);
    let detail = errors
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default();
    Err(format!("Windows: {detail} ({})", out.status))
}

const DOWNLOAD: &str = r#"
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -TimeoutSec 90 -MaximumRedirection 4 `
  -Uri $env:AI_UNLOCKER_DOWNLOAD_URL -OutFile $env:AI_UNLOCKER_UPDATE_FILE
"#;

const INSTALL: &str = r#"
$old = Get-Process -Id ([int]$env:AI_UNLOCKER_PREVIOUS_PID) -ErrorAction SilentlyContinue
$waited = $false
$package = $null
try {
  if ($old -and !$old.WaitForExit(30000)) { throw 'AI Unlocker did not exit' }
  $waited = $true
  $package = [IO.File]::Open($env:AI_UNLOCKER_UPDATE_FILE, 'Open', 'Read', 'Read')
  if ((Get-FileHash -InputStream $package -Algorithm SHA256).Hash -ne $env:AI_UNLOCKER_PACKAGE_HASH) {
    throw 'The AI Unlocker installer failed verification'
  }
  $args = '/SILENT /NORESTART /SUPPRESSMSGBOXES /NOCLOSEAPPLICATIONS /RESTARTEXITCODE=75'
  $setup = Start-Process -FilePath $env:AI_UNLOCKER_UPDATE_FILE -ArgumentList $args -Wait -PassThru
  if ($setup.ExitCode -ne 0) { throw ('Setup exit code: ' + $setup.ExitCode) }
  Start-Process -FilePath $env:AI_UNLOCKER_INSTALLED_EXE -ArgumentList $env:AI_UNLOCKER_UPDATED_FLAG
} catch {
  $reason = $_.Exception.Message
  try {
    if ($waited -and (Test-Path -LiteralPath $env:AI_UNLOCKER_PREVIOUS_EXE -PathType Leaf)) {
      Start-Process -FilePath $env:AI_UNLOCKER_PREVIOUS_EXE
    }
  } catch { $reason += [Environment]::NewLine + $_.Exception.Message }
  $shell = New-Object -ComObject WScript.Shell
  [void]$shell.Popup($reason, 0, 'AI Unlocker - Setup', 16)
} finally {
  if ($package) { $package.Dispose() }
  Remove-Item -LiteralPath $env:AI_UNLOCKER_UPDATE_FILE
  Remove-Item -LiteralPath ([IO.Path]::GetDirectoryName($env:AI_UNLOCKER_UPDATE_FILE))
}
"#;

fn installer_asset(release: &ReleaseInfo) -> Option<(&ReleaseAsset, &str)> {
    for version in update::asset_versions(release) {
        let name = format!("AI_Unlocker_setup-{version}.exe");
        if let Some(installer) = update::verified_asset(release, &name) {
            return Some(installer);
        }
        let portable = format!("AG_{version}_portable.exe");
        if release.assets.iter().any(|asset| asset.name == portable) {
            if let Some(installer) = update::verified_asset(release, &format!("AG_{version}.exe")) {
                return Some(installer);
            }
        }
    }
    None
}

pub fn can_install(release: &ReleaseInfo) -> bool {
    installed_exe()
        .and_then(|path| path.canonicalize().ok())
        .zip(std::env::current_exe().ok().and_then(|path| path.canonicalize().ok()))
        .is_some_and(|(installed, running)| installed == running)
        && installer_asset(release).is_some()
}

pub struct PreparedUpdate {
    folder: PathBuf,
    digest: String,
    handed_off: bool,
}

impl PreparedUpdate {
    fn package(&self) -> PathBuf {
        self.folder.join("setup.exe")
    }

    pub fn launch(mut self) -> Result<(), String> {
        let previous = std::env::current_exe().map_err(|error| error.to_string())?;
        let installed = installed_exe().ok_or("Windows не сообщила путь профиля пользователя")?;
        let mut command = powershell(INSTALL);
        command
            .env("AI_UNLOCKER_UPDATE_FILE", self.package())
            .env("AI_UNLOCKER_PACKAGE_HASH", &self.digest)
            .env("AI_UNLOCKER_PREVIOUS_PID", std::process::id().to_string())
            .env("AI_UNLOCKER_PREVIOUS_EXE", previous)
            .env("AI_UNLOCKER_INSTALLED_EXE", installed)
            .env("AI_UNLOCKER_UPDATED_FLAG", update::UPDATED_FLAG)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.spawn().map_err(|error| error.to_string())?;
        self.handed_off = true;
        Ok(())
    }
}

impl Drop for PreparedUpdate {
    fn drop(&mut self) {
        if !self.handed_off {
            let _ = fs::remove_file(self.package());
            let _ = fs::remove_dir(&self.folder);
        }
    }
}

pub fn prepare(release: &ReleaseInfo) -> Result<PreparedUpdate, String> {
    let (asset, digest) =
        installer_asset(release).ok_or("Для версии нет проверяемого установщика Windows")?;
    let folder = update::staging_path_in(&std::env::temp_dir())?;
    fs::create_dir(&folder).map_err(|error| error.to_string())?;
    let update = PreparedUpdate {
        folder,
        digest: digest.to_owned(),
        handed_off: false,
    };
    let mut download = powershell(DOWNLOAD);
    download
        .env("AI_UNLOCKER_DOWNLOAD_URL", &asset.browser_download_url)
        .env("AI_UNLOCKER_UPDATE_FILE", update.package());
    run(&mut download, Duration::from_secs(105))?;
    if !update::valid_package(&update.package(), asset.size, digest, b"MZ").map_err(|err| err.to_string())? {
        return Err("Размер или SHA-256 установщика не совпадает с GitHub Releases".into());
    }
    Ok(update)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn only_a_digest_checked_installer_pair_can_update() {
        let tag = "v999.0.0.1";
        let base = crate::update::RELEASES_LATEST_URL
            .strip_suffix("/latest")
            .unwrap();
        let mut release: ReleaseInfo = serde_json::from_value(serde_json::json!({
            "tag_name": tag,
            "html_url": format!("{base}/tag/{tag}"),
            "assets": [
                {"name": "AG_999.0.0_1.exe", "size": 16, "digest": format!("sha256:{}", "a".repeat(64)),
                 "browser_download_url": format!("{base}/download/{tag}/AG_999.0.0_1.exe")},
                {"name": "AG_999.0.0_1_portable.exe", "browser_download_url": ""},
            ],
        })).unwrap();
        assert!(installer_asset(&release).is_some());
        let url = release.assets[0].browser_download_url.clone();
        release.assets[0]
            .browser_download_url
            .push_str("?redirect=1");
        assert!(installer_asset(&release).is_none());
        release.assets[0].browser_download_url = url;
        release.assets[0].digest = None;
        assert!(installer_asset(&release).is_none());
        release.assets[0].digest = Some(format!("sha256:{}", "b".repeat(64)));
        release.assets.pop();
        assert!(installer_asset(&release).is_none());
        let name = "AI_Unlocker_setup-999.0.0_1.exe";
        release.assets[0].name = name.into();
        release.assets[0].browser_download_url = format!("{base}/download/{tag}/{name}");
        assert!(installer_asset(&release).is_some());
    }

    #[test]
    fn installer_hash_and_size_cover_the_exact_payload() {
        let path = std::env::temp_dir().join(format!("ag-installer-{}.test", std::process::id()));
        let bytes = b"MZfake package";
        fs::write(&path, bytes).unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        assert!(update::valid_package(&path, bytes.len() as u64, &hash, b"MZ").unwrap());
        assert!(!update::valid_package(&path, bytes.len() as u64 + 1, &hash, b"MZ").unwrap());
        assert!(!update::valid_package(&path, bytes.len() as u64, &"0".repeat(64), b"MZ").unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn startup_shortcut_can_be_set_and_removed_in_an_isolated_folder() {
        let folder = std::env::temp_dir().join(format!("ag-startup-{}", std::process::id()));
        fs::create_dir(&folder).unwrap();
        let script = SHORTCUT.replace(
            "$root = (New-Object -ComObject WScript.Shell).SpecialFolders.Item('Startup')",
            "$root = $env:AI_UNLOCKER_TEST_STARTUP_FOLDER",
        );
        let exe = std::env::current_exe().unwrap();
        for (mode, expected) in [
            ("read", "off"),
            ("on", "on"),
            ("read", "on"),
            ("off", "off"),
        ] {
            let mut cmd = powershell(&script);
            cmd.env("AI_UNLOCKER_SHORTCUT_MODE", mode)
                .env("AI_UNLOCKER_TEST_STARTUP_FOLDER", &folder)
                .env("AI_UNLOCKER_SHORTCUT_TARGET", &exe);
            assert_eq!(
                run(&mut cmd, Duration::from_secs(10)).unwrap().trim(),
                expected
            );
        }
        fs::remove_dir(folder).unwrap();
    }

    #[test]
    fn update_scripts_parse_in_windows_powershell() {
        for script in [DOWNLOAD, INSTALL, SHORTCUT] {
            let mut command = powershell(
                r#"
                $tokens = $null; $errorsFound = $null
                [void][Management.Automation.Language.Parser]::ParseInput($env:AI_UNLOCKER_TEST_SOURCE, [ref]$tokens, [ref]$errorsFound)
                if ($errorsFound) { throw ($errorsFound | Out-String) }
            "#,
            );
            command.env("AI_UNLOCKER_TEST_SOURCE", script);
            run(&mut command, Duration::from_secs(10)).unwrap();
        }
    }
}
