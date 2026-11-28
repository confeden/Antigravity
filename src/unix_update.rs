//! Installer handoff for the per-user Linux and macOS installations.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::update::{self, ReleaseAsset, ReleaseInfo};

#[cfg(target_os = "macos")]
const PLATFORM: &str = "macos";
#[cfg(not(target_os = "macos"))]
const PLATFORM: &str = "linux";
#[cfg(target_os = "macos")]
const INSTALLER: &str = "Установить.command";
#[cfg(not(target_os = "macos"))]
const INSTALLER: &str = "install.sh";

fn install_parent() -> Option<PathBuf> {
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let directory = home()?.join("Applications");
    #[cfg(not(target_os = "macos"))]
    let directory = match std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => home()?.join(".local/share"),
    }
    .join("ag-unlocker");
    directory.is_absolute().then_some(directory)
}

fn installed_exe() -> Option<PathBuf> {
    let parent = install_parent()?;
    #[cfg(target_os = "macos")]
    return Some(parent.join("AI Unlocker.app/Contents/MacOS/ag_unlocker"));
    #[cfg(not(target_os = "macos"))]
    return Some(parent.join("ag_unlocker"));
}

fn installer_asset(release: &ReleaseInfo) -> Option<(&ReleaseAsset, &str, String)> {
    for version in update::asset_versions(release) {
        let folder = format!("AG_{version}_{PLATFORM}");
        if let Some((asset, digest)) = update::verified_asset(release, &format!("{folder}.tar.gz"))
        {
            return Some((asset, digest, folder));
        }
    }
    None
}

pub fn can_install(release: &ReleaseInfo) -> bool {
    installer_asset(release).is_some()
        && installed_exe()
            .and_then(|path| path.canonicalize().ok())
            .zip(
                std::env::current_exe()
                    .ok()
                    .and_then(|path| path.canonicalize().ok()),
            )
            .is_some_and(|(installed, running)| installed == running)
}

pub struct PreparedUpdate {
    staging: PathBuf,
    bundle: String,
    handed_off: bool,
}

impl PreparedUpdate {
    pub fn launch(mut self) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|error| error.to_string())?;
        Command::new(exe)
            .arg(update::HANDOFF_FLAG)
            .arg(std::process::id().to_string())
            .arg(&self.staging)
            .arg(&self.bundle)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;
        self.handed_off = true;
        Ok(())
    }
}

impl Drop for PreparedUpdate {
    fn drop(&mut self) {
        if !self.handed_off {
            clean_staging(&self.staging);
        }
    }
}

fn clean_staging(staging: &Path) {
    if let Err(error) = fs::remove_dir_all(staging) {
        eprintln!("AI Unlocker update cleanup: {error}");
    }
}

fn run(command: &mut Command, timeout: Duration) -> Result<(), String> {
    let output = crate::utils::bounded_output(command, timeout).ok_or_else(|| {
        format!(
            "Команда {:?} не запустилась или не ответила",
            command.get_program()
        )
    })?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{:?} ({})\n{}",
            command.get_program(),
            output.status,
            stderr.trim()
        ))
    }
}

pub fn prepare(release: &ReleaseInfo) -> Result<PreparedUpdate, String> {
    let (asset, digest, bundle) = installer_asset(release)
        .ok_or("Для версии нет проверяемого установщика для этой системы")?;
    let parent = install_parent().ok_or("Не найден каталог установленного AI Unlocker")?;
    let staging = update::staging_path_in(&parent)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|error| error.to_string())?;
    let prepared = PreparedUpdate {
        staging,
        bundle,
        handed_off: false,
    };
    let archive = prepared.staging.join("update.tar.gz");
    run(
        Command::new("curl")
            .args([
                "-q",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--max-redirs",
                "4",
            ])
            .args([
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-time",
                "120",
            ])
            .arg("--max-filesize")
            .arg(asset.size.to_string())
            .arg("--output")
            .arg(&archive)
            .arg(&asset.browser_download_url),
        Duration::from_secs(125),
    )?;
    if !update::valid_package(&archive, asset.size, digest, b"\x1f\x8b")
        .map_err(|error| error.to_string())?
    {
        return Err("Размер или SHA-256 установщика не совпадает с GitHub Releases".into());
    }
    run(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&prepared.staging)
            .arg("--")
            .arg(&prepared.bundle),
        Duration::from_secs(45),
    )?;
    let payload = prepared.staging.join(&prepared.bundle);
    for name in ["ag_unlocker", INSTALLER] {
        if !fs::symlink_metadata(payload.join(name)).is_ok_and(|meta| meta.is_file()) {
            return Err(format!("В установщике отсутствует {name}"));
        }
    }
    let output = crate::utils::bounded_output(
        Command::new(payload.join("ag_unlocker")).arg("--version"),
        Duration::from_secs(10),
    )
    .ok_or("Не удалось запустить новую версию. Проверьте архитектуру и права на запуск.")?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !output.status.success()
        || !text.lines().any(|line| {
            line.strip_prefix("version: ")
                .is_some_and(|version| update::same_version(version, release.display_version()))
        })
    {
        return Err("Версия программы в установщике не совпадает с тегом GitHub Releases".into());
    }
    Ok(prepared)
}

pub fn finish_if_requested() {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next();
    #[cfg(target_os = "macos")]
    if mode.as_deref() == Some("--install-macos-bundle".as_ref()) {
        if let Err(error) = publish_macos_bundle() {
            eprintln!("Сбой установки AI Unlocker: {error}");
            std::process::exit(1);
        }
        std::process::exit(0);
    }
    if mode.as_deref() != Some(update::HANDOFF_FLAG.as_ref()) {
        return;
    }
    let parent = args
        .next()
        .and_then(|arg| arg.to_str()?.parse::<libc::pid_t>().ok());
    let staging = args.next().map(PathBuf::from);
    let bundle = args.next();
    let (Some(parent), Some(staging), Some(bundle), Some(exe)) =
        (parent, staging, bundle, installed_exe())
    else {
        std::process::exit(2);
    };
    let valid_staging = install_parent().as_deref() == staging.parent()
        && staging
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("ai-unlocker-update-"))
            .is_some_and(|suffix| {
                suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
            })
        && fs::symlink_metadata(&staging).is_ok_and(|meta| {
            meta.is_dir() && meta.mode() & 0o077 == 0 && meta.uid() == unsafe { libc::geteuid() }
        });
    let valid_bundle = bundle
        .to_str()
        .and_then(|name| name.strip_prefix("AG_"))
        .and_then(|name| name.strip_suffix(&format!("_{PLATFORM}")))
        .is_some_and(|version| {
            !version.is_empty()
                && version
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'.' || b == b'_')
        });
    if !valid_staging || !valid_bundle || parent <= 1 {
        std::process::exit(2);
    }
    let result = finish(parent, &staging.join(bundle).join(INSTALLER), &exe);
    clean_staging(&staging);
    if let Err(error) = result {
        crate::utils::message_box("Обновление AI Unlocker", &error);
        std::process::exit(1);
    }
    std::process::exit(0);
}

#[cfg(target_os = "macos")]
fn publish_macos_bundle() -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let directory = install_parent()
        .ok_or("Не найден каталог Applications")?
        .canonicalize()?;
    let new_exe = std::env::current_exe()?.canonicalize()?;
    let staged = new_exe
        .ancestors()
        .nth(3)
        .ok_or("Не найден подготовленный пакет")?;
    let workspace = staged.parent().ok_or("Не найден временный каталог")?;
    if staged.file_name() != Some("AI Unlocker.app".as_ref())
        || workspace.parent() != Some(directory.as_path())
        || !workspace
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".ai-unlocker."))
    {
        return Err("Неожиданное расположение подготовленного пакета".into());
    }
    let installed = directory.join("AI Unlocker.app");
    let mode = match fs::symlink_metadata(&installed) {
        Ok(meta) if meta.is_dir() && installed.join("Contents/MacOS/ag_unlocker").is_file() => {
            libc::RENAME_SWAP
        }
        Ok(_) => return Err("Путь AI Unlocker.app уже занят".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => libc::RENAME_EXCL,
        Err(error) => return Err(error.into()),
    };
    let source = CString::new(staged.as_os_str().as_bytes())?;
    let destination = CString::new(installed.as_os_str().as_bytes())?;
    // The app and its metadata move together. On failure the old path stays usable.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            mode,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn finish(parent: libc::pid_t, installer: &Path, exe: &Path) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    // This helper was spawned directly by the GUI. Reparenting means the old
    // process exited, without mistaking a reused PID for the original GUI.
    while unsafe { libc::getppid() } == parent {
        if Instant::now() >= deadline {
            return Err("AI Unlocker не завершился. Попробуйте обновить его снова.".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let shell = if cfg!(target_os = "macos") {
        "/bin/sh"
    } else {
        "bash"
    };
    let installed = run(
        Command::new(shell).arg(installer).arg("--update"),
        Duration::from_secs(45),
    );
    let mut restart = Command::new(exe);
    if installed.is_ok() {
        restart.arg(crate::update::UPDATED_FLAG);
    }
    let restarted = restart
        .spawn()
        .map_err(|error| format!("Не удалось перезапустить AI Unlocker: {error}"));
    match (installed, restarted) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(_)) | (Ok(()), Err(error)) => Err(error),
        (Err(install), Err(restart)) => Err(format!("{install}\n{restart}")),
    }
}
