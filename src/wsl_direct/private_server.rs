//! The original is read only. This module owns only the helper's private cache.

use crate::binary_profile::{prepare_profile, PatchProfile, ProfilePreparation};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat};
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

type Result<T> = std::result::Result<T, String>;
const PROFILE: &str = "wsl-profile-v1";
const CACHE: &str = "server-cache";

fn failure(stage: &str, error: impl std::fmt::Display) -> String {
    format!("{stage}: {error}")
}

fn cancelled() -> Result<()> {
    let input = rustix::stdio::stdin();
    let mut fds = [PollFd::new(&input, PollFlags::empty())];
    loop {
        match poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(failure("cancelled-before-exec", e)),
            Ok(_) => break,
        }
    }
    if fds[0]
        .revents()
        .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
    {
        return Err("cancelled-before-exec: stdin is closed".into());
    }
    Ok(())
}

fn kind(stat: &Stat) -> FileType {
    FileType::from_raw_mode(stat.st_mode)
}

fn trusted(stat: &Stat, directory: bool, private: bool) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    if (directory && kind(stat) != FileType::Directory)
        || (!directory && kind(stat) != FileType::RegularFile)
        || (stat.st_uid != uid && (private || stat.st_uid != 0))
        || stat.st_mode & 0o022 != 0
        || (private && directory && stat.st_mode & 0o077 != 0)
        || (!directory && stat.st_nlink != 1)
        || stat.st_mode & 0o7000 != 0
    {
        return Err("source-invalid: untrusted owner, mode, links or file type".into());
    }
    Ok(())
}

/// Every component is opened relative to the retained parent without following
/// links. Root-owned ordinary ancestors are allowed; writable shared ones aren't.
fn directory(path: &Path) -> Result<OwnedFd> {
    if !path.is_absolute() {
        return Err("source-invalid: absolute path required".into());
    }
    let mut fd = fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| failure("prepare-I/O", e))?;
    trusted(
        &fs::fstat(&fd).map_err(|e| failure("prepare-I/O", e))?,
        true,
        false,
    )?;
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err("source-invalid: ordinary path components required".into());
        };
        fd = fs::openat(
            &fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| failure("source-invalid", e))?;
        trusted(
            &fs::fstat(&fd).map_err(|e| failure("prepare-I/O", e))?,
            true,
            false,
        )?;
    }
    Ok(fd)
}

fn open_file(parent: &OwnedFd, name: &OsStr) -> Result<File> {
    // NONBLOCK prevents a substituted FIFO/device from blocking before fstat.
    fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|e| failure("source-invalid", e))
}

fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_size == b.st_size
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

fn read_checked(file: &mut File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| failure("prepare-I/O", e))?;
    let mut bytes = Vec::new();
    let mut block = [0; 64 * 1024];
    loop {
        cancelled()?;
        let n = file
            .read(&mut block)
            .map_err(|e| failure("prepare-I/O", e))?;
        if n == 0 {
            return Ok(bytes);
        }
        bytes
            .try_reserve(n)
            .map_err(|e| failure("prepare-I/O", e))?;
        bytes.extend_from_slice(&block[..n]);
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn elf(bytes: &[u8]) -> Result<()> {
    let machine = if cfg!(target_arch = "x86_64") {
        62
    } else if cfg!(target_arch = "aarch64") {
        183
    } else {
        0
    };
    if bytes.len() < 64
        || &bytes[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(u16::from_le_bytes([bytes[16], bytes[17]]), 2 | 3)
        || machine == 0
        || u16::from_le_bytes([bytes[18], bytes[19]]) != machine
        || u32::from_le_bytes(bytes[20..24].try_into().unwrap()) != 1
        || u16::from_le_bytes([bytes[52], bytes[53]]) != 64
    {
        return Err("source-invalid: unsupported ELF architecture or header".into());
    }
    Ok(())
}

fn association(parent: &OwnedFd, name: &OsStr, before: &Stat, file: &File) -> Result<()> {
    let descriptor = fs::fstat(file).map_err(|e| failure("source-changed", e))?;
    let entry = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| failure("source-changed", e))?;
    if !same(before, &descriptor) || !same(before, &entry) {
        return Err("source-changed: descriptor or source association changed".into());
    }
    Ok(())
}

fn parent_association(path: &Path, retained: &OwnedFd) -> Result<()> {
    let current = directory(path)?;
    let current = fs::fstat(&current).map_err(|e| failure("source-changed", e))?;
    let retained = fs::fstat(retained).map_err(|e| failure("source-changed", e))?;
    if current.st_dev != retained.st_dev || current.st_ino != retained.st_ino {
        return Err("source-changed: ancestor association changed".into());
    }
    Ok(())
}

fn lock(cache: &OwnedFd) -> Result<File> {
    let fd = fs::openat(
        cache,
        ".lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| failure("prepare-I/O", e))?;
    let stat = fs::fstat(&fd).map_err(|e| failure("prepare-I/O", e))?;
    trusted(&stat, false, true)?;
    if stat.st_mode & 0o777 != 0o600 {
        return Err("cache-conflict: invalid lock permissions".into());
    }
    loop {
        cancelled()?;
        match fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(File::from(fd)),
            Err(rustix::io::Errno::WOULDBLOCK) => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(e) => return Err(failure("prepare-I/O", e)),
        }
    }
}

/// The guard can remove only this attempt's exact staging inode.
struct Partial<'a> {
    cache: &'a OwnedFd,
    name: String,
    identity: Stat,
    armed: bool,
    report_cleanup: bool,
}
impl Partial<'_> {
    fn remove(&mut self) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        let now = fs::statat(self.cache, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| failure("prepare-I/O: partial cleanup", e))?;
        if now.st_dev != self.identity.st_dev || now.st_ino != self.identity.st_ino {
            return Err("cache-conflict: staging identity changed; preserved".into());
        }
        fs::unlinkat(self.cache, self.name.as_str(), AtFlags::empty())
            .map_err(|e| failure("prepare-I/O: partial cleanup", e))?;
        self.armed = false;
        Ok(())
    }
}
impl Drop for Partial<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            if self.report_cleanup {
                eprintln!("ag-wsl-launch: {error}");
            }
        }
    }
}

fn publish(cache: &OwnedFd, name: &str, output: &[u8], report_cleanup: bool) -> Result<()> {
    let temporary = format!(".partial-{}", std::process::id());
    let fd = fs::openat(
        cache,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| failure("prepare-I/O", e))?;
    let identity = fs::fstat(&fd).map_err(|e| failure("prepare-I/O", e))?;
    let mut partial = Partial {
        cache,
        name: temporary,
        identity,
        armed: true,
        report_cleanup,
    };
    let mut writer = File::from(fd);
    for block in output.chunks(64 * 1024) {
        cancelled()?;
        writer
            .write_all(block)
            .map_err(|e| failure("prepare-I/O", e))?;
    }
    fs::fchmod(&writer, Mode::from_raw_mode(0o500)).map_err(|e| failure("prepare-I/O", e))?;
    writer.sync_all().map_err(|e| failure("prepare-I/O", e))?;
    cancelled()?;
    // linkat is atomic and fails EEXIST rather than replacing a cache entry.
    fs::linkat(cache, partial.name.as_str(), cache, name, AtFlags::empty())
        .map_err(|e| failure("cache-conflict", e))?;
    partial.remove()?;
    drop(writer);
    fs::fsync(cache).map_err(|e| failure("prepare-I/O", e))?;
    Ok(())
}

pub(crate) struct Prepared {
    profile: String,
    executable: File,
    identity: Stat,
    source_digest: String,
    output_digest: String,
    helper_digest: String,
    association_digest: String,
    cache_identity: String,
    cache_hit: bool,
    source: File,
    source_parent: OwnedFd,
    source_path: std::path::PathBuf,
    source_identity: Stat,
}

impl Prepared {
    /// Hash-only output: no paths, environment, credentials or server arguments.
    pub(crate) fn manifest(&self) -> String {
        serde_json::json!({"schema":1,"profile":self.profile,"source_sha256":self.source_digest,
            "output_sha256":self.output_digest,"helper_sha256":self.helper_digest,
            "association_sha256":self.association_digest,"cache_identity":self.cache_identity,
            "cache_hit":self.cache_hit})
        .to_string()
    }

    pub(crate) fn exec(mut self, source: &OsStr, args: &[std::ffi::OsString]) -> Result<()> {
        let actual = read_checked(&mut self.executable)?;
        if digest(&actual) != self.output_digest
            || !same(
                &self.identity,
                &fs::fstat(&self.executable).map_err(|e| failure("exec-failed", e))?,
            )
        {
            return Err("cache-conflict: executable changed before exec".into());
        }
        let strings: Vec<CString> = std::iter::once(source)
            .chain(args.iter().map(|a| a.as_os_str()))
            .map(|a| {
                CString::new(a.as_bytes()).map_err(|_| "exec-failed: NUL in argument".to_owned())
            })
            .collect::<Result<_>>()?;
        let environment: Vec<CString> = std::env::vars_os()
            .map(|(key, value)| {
                let mut pair = key.as_bytes().to_vec();
                pair.push(b'=');
                pair.extend_from_slice(value.as_bytes());
                CString::new(pair).map_err(|_| "exec-failed: NUL in environment".to_owned())
            })
            .collect::<Result<_>>()?;
        let argv: Vec<*const u8> = strings
            .iter()
            .map(|s| s.as_ptr().cast())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<*const u8> = environment
            .iter()
            .map(|s| s.as_ptr().cast())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        parent_association(self.source_path.parent().unwrap(), &self.source_parent)?;
        association(
            &self.source_parent,
            self.source_path.file_name().unwrap(),
            &self.source_identity,
            &self.source,
        )?;
        cancelled()?;
        // SAFETY: both vectors have a trailing null; all preceding pointers refer
        // to live immutable CStrings through this call. Empty path + EMPTY_PATH
        // executes the retained checked ELF descriptor, with no pathname reopen.
        let error = unsafe {
            rustix::runtime::execveat(
                self.executable.as_fd(),
                c"",
                argv.as_ptr(),
                envp.as_ptr(),
                AtFlags::EMPTY_PATH,
            )
        };
        Err(failure("exec-failed", error))
    }
}

pub(crate) fn prepare(source: &Path) -> Result<Prepared> {
    prepare_with_options(source, true, true, true, true)
}

/// Vendor stdout and stderr are both readiness-parser inputs. No preparation
/// diagnostic, including a staging guard's cleanup error, may reach them.
/// The serving adapter preserves failure with its stage-specific exit status.
pub(crate) fn prepare_selected_profile(source: &Path, eligibility: bool, transport: bool) -> Result<Prepared> {
    prepare_with_options(source, eligibility, transport, true, true)
}
pub(crate) fn prepare_vendor_profile(source: &Path, eligibility: bool, transport: bool, automatic: bool) -> Result<Prepared> {
    prepare_with_options(source, eligibility, transport, automatic, false)
}
fn prepare_with_options(source: &Path, eligibility: bool, transport: bool, allow_preparation: bool, report_cleanup: bool) -> Result<Prepared> {
    cancelled()?;
    if rustix::process::getuid() != rustix::process::geteuid() {
        return Err("source-invalid: changed effective user".into());
    }
    let home = std::env::var_os("HOME").ok_or("source-invalid: HOME missing")?;
    let home = Path::new(&home);
    let home_fd = directory(home)?;
    let home_stat = fs::fstat(&home_fd).map_err(|e| failure("source-invalid", e))?;
    trusted(&home_stat, true, false)?;
    if home_stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err("source-invalid: HOME belongs to another user".into());
    }
    if !source.starts_with(home) || source.file_name().is_none() {
        return Err("source-invalid: source must be within the unchanged HOME".into());
    }
    let parent_path = source
        .parent()
        .ok_or("source-invalid: source parent missing")?;
    let parent = directory(parent_path)?;
    let name = source.file_name().unwrap();
    let mut original = open_file(&parent, name)?;
    let before = fs::fstat(&original).map_err(|e| failure("source-invalid", e))?;
    trusted(&before, false, false)?;
    if before.st_mode & 0o111 == 0 {
        return Err("source-invalid: source is not executable".into());
    }
    let input = read_checked(&mut original)?;
    elf(&input)?;
    let source_digest = digest(&input);
    association(&parent, name, &before, &original)?;
    if digest(&read_checked(&mut original)?) != source_digest {
        return Err("source-changed: source digest changed".into());
    }
    association(&parent, name, &before, &original)?;
    let requested_profile = if eligibility && transport { PatchProfile::Wsl }
        else { PatchProfile::WslSelective { eligibility, transport } };
    let profile = if eligibility && transport { PROFILE.to_owned() }
        else { format!("wsl-profile-v2-e{}-t{}", u8::from(eligibility), u8::from(transport)) };
    let output = match prepare_profile(&input, requested_profile) {
        Ok(ProfilePreparation::Prepared(bytes)) => bytes,
        Ok(ProfilePreparation::AlreadyApplied) => {
            return Err("profile-provenance: source is already patched".into())
        }
        Ok(ProfilePreparation::Unsupported) => {
            return Err("unsupported-profile: source signatures absent".into())
        }
        Err(_) => return Err("unsupported-profile: ambiguous source profile".into()),
    };
    elf(&output)?;
    let output_digest = digest(&output);
    let helper_path = std::env::current_exe().map_err(|e| failure("prepare-I/O", e))?;
    let helper_parent = directory(
        helper_path
            .parent()
            .ok_or("source-invalid: helper parent missing")?,
    )?;
    let mut helper = open_file(
        &helper_parent,
        helper_path
            .file_name()
            .ok_or("source-invalid: helper name missing")?,
    )?;
    let helper_before = fs::fstat(&helper).map_err(|e| failure("source-invalid", e))?;
    trusted(&helper_before, false, true)?;
    let running = File::open("/proc/self/exe").map_err(|e| failure("prepare-I/O", e))?;
    if !same(
        &helper_before,
        &fs::fstat(&running).map_err(|e| failure("source-invalid", e))?,
    ) {
        return Err("source-changed: helper path identity changed".into());
    }
    let helper_digest = digest(&read_checked(&mut helper)?);
    association(
        &helper_parent,
        helper_path.file_name().unwrap(),
        &helper_before,
        &helper,
    )?;
    let mut association_hash = Sha256::new();
    for part in [
        source.as_os_str().as_bytes(),
        home.as_os_str().as_bytes(),
        &rustix::process::geteuid().as_raw().to_le_bytes(),
    ] {
        association_hash.update((part.len() as u64).to_le_bytes());
        association_hash.update(part);
    }
    let association_digest = hex::encode(association_hash.finalize());
    let cache_identity = digest(
        format!("{profile}:{source_digest}:{output_digest}:{helper_digest}:{association_digest}")
            .as_bytes(),
    );
    if allow_preparation { match fs::mkdirat(&helper_parent, CACHE, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => (),
        Err(e) => return Err(failure("prepare-I/O", e)),
    } }
    let cache = fs::openat(
        &helper_parent,
        CACHE,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| if !allow_preparation && e == rustix::io::Errno::NOENT {
        "update-pending: explicit Apply is required for this source/profile".to_owned()
    } else { failure("cache-conflict", e) })?;
    trusted(
        &fs::fstat(&cache).map_err(|e| failure("cache-conflict", e))?,
        true,
        true,
    )?;
    let _lock = lock(&cache)?;
    let cache_hit = match fs::statat(&cache, cache_identity.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => true,
        Err(rustix::io::Errno::NOENT) => {
            if !allow_preparation { return Err("update-pending: explicit Apply is required for this source/profile".into()); }
            publish(&cache, &cache_identity, &output, report_cleanup)?;
            false
        }
        Err(e) => return Err(failure("cache-conflict", e)),
    };
    let mut executable = open_file(&cache, OsStr::new(&cache_identity))?;
    let identity = fs::fstat(&executable).map_err(|e| failure("cache-conflict", e))?;
    trusted(&identity, false, true)?;
    if identity.st_mode & 0o777 != 0o500 || read_checked(&mut executable)? != output {
        return Err(
            "cache-conflict: private output does not match source/profile/transform".into(),
        );
    }
    association(&cache, OsStr::new(&cache_identity), &identity, &executable)?;
    association(&parent, name, &before, &original)?;
    parent_association(parent_path, &parent)?;
    parent_association(helper_path.parent().unwrap(), &helper_parent)?;
    parent_association(home, &home_fd)?;
    cancelled()?;
    Ok(Prepared {
        profile,
        executable,
        identity,
        source_digest,
        output_digest,
        helper_digest,
        association_digest,
        cache_identity,
        cache_hit,
        source: original,
        source_parent: parent,
        source_path: source.to_path_buf(),
        source_identity: before,
    })
}
