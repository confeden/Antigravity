//! Private conditional native archive effect adapter. Installation admission,
//! checked paths and the held maintenance layout belong to windows_installation.
#![cfg(windows)]
use super::desktop_hook::{self, HookStatus, PreparedArchive};
use super::*;
use super::native::{create_replacement_file as create_checked, replace_native_file as replace, same_snapshot};
/// Must be backed by the caller's still-held real maintenance arrangement and
/// current known-writer checks. Returning Ok is not proof against arbitrary
/// same-account renames. It must cover the entire call and ensuing recovery.
pub trait MaintenanceWindow {
    fn ensure_held(&mut self) -> Result<(), String>;
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FileObservation {
    Missing,
    Present {
        identity: FileIdentity,
        digest: String,
    },
    Unavailable(String),
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryState {
    pub target: (PathBuf, FileObservation),
    pub staged: Option<(PathBuf, FileObservation)>,
    pub original_backup: Option<(PathBuf, FileObservation)>,
    pub displaced_backup: Option<(PathBuf, FileObservation)>,
}
#[derive(Debug, serde::Serialize)]
pub struct InstallFailure {
    pub phase: &'static str,
    pub cause: String,
    /// None: not called; Some(false): API returned failure, partial effects may
    /// exist; Some(true): API returned success but later receiving may fail.
    pub replace_result: Option<bool>,
    pub recovery: RecoveryState,
}
impl std::fmt::Display for InstallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "archive maintenance {}: {} (replacement {:?}; inspect recovery)",
            self.phase, self.cause, self.replace_result
        )
    }
}
impl std::error::Error for InstallFailure {}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedArchive {
    pub record_version: u32,
    pub target: PathBuf,
    pub original: FileIdentity,
    pub pre_digest: String,
    pub post: FileIdentity,
    pub post_digest: String,
    pub original_backup: PathBuf,
    pub original_backup_identity: FileIdentity,
    pub displaced_backup: PathBuf,
    pub displaced_identity: FileIdentity,
}
#[derive(Debug, Clone)]
pub struct RevertedArchive {
    pub target: SourceSnapshot,
    pub retained_paths: InstallPaths,
    pub displaced_postimage: FileIdentity,
}

pub(super) fn observe(path: &Path) -> FileObservation {
    // symlink_metadata classifies absence without following the leaf. Full read
    // then independently pins and validates all ancestors and the actual leaf.
    let native_path = match NativeFsPath::from_path(path) {
        Ok(path) => path,
        Err(error) => return FileObservation::Unavailable(error),
    };
    match fs::symlink_metadata(native_path.as_path()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileObservation::Missing,
        Err(e) => FileObservation::Unavailable(io("observe path", e)),
        Ok(_) => match read_path(path, READ | DELETE) {
            Ok(s) => FileObservation::Present {
                identity: s.identity,
                digest: s.digest,
            },
            Err(e) => FileObservation::Unavailable(e),
        },
    }
}
fn failure(
    target: &Path,
    paths: Option<&InstallPaths>,
    phase: &'static str,
    cause: String,
    replace_result: Option<bool>,
) -> InstallFailure {
    InstallFailure {
        phase,
        cause,
        replace_result,
        recovery: RecoveryState {
            target: (target.into(), observe(target)),
            staged: paths.map(|p| (p.staged.clone(), observe(&p.staged))),
            original_backup: paths
                .map(|p| (p.original_backup.clone(), observe(&p.original_backup))),
            displaced_backup: paths
                .map(|p| (p.displaced_backup.clone(), observe(&p.displaced_backup))),
        },
    }
}
pub fn snapshot(target: &Path) -> Result<SourceSnapshot, InstallFailure> {
    read_path(target, READ | DELETE).map_err(|e| failure(target, None, "snapshot", e, None))
}
fn absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(NativeFsPath::from_path(path)?.as_path()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("owned output path is already occupied; preserve it".into()),
        Err(e) => Err(io("output vacancy", e)),
    }
}
fn shadow_clear(target: &Path) -> Result<(), String> {
    let shadow = target.parent().ok_or("archive parent missing")?.join("app");
    match fs::symlink_metadata(NativeFsPath::from_path(&shadow)?.as_path()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("resources/app shadow conflict; preserve it".into()),
        Err(e) => Err(io("archive shadow check", e)),
    }
}
fn paths_check(target: &Path, paths: &InstallPaths, volume: u32) -> Result<Vec<File>, String> {
    let mut guards = parents(target)?;
    let all = [
        &paths.staged,
        &paths.original_backup,
        &paths.displaced_backup,
    ];
    for (i, path) in all.iter().enumerate() {
        validate_path(path)?;
        if path.parent() != paths.staged.parent() || *path == target || all[..i].contains(path) {
            return Err("output names must be distinct siblings outside target".into());
        }
        guards.extend(parents(path)?);
        absent(path)?;
    }
    let parent = paths.staged.parent().ok_or("missing private directory")?;
    let dir = OpenOptions::new()
        .read(true)
        .share_mode(READ | WRITE)
        .custom_flags(OPEN_REPARSE | BACKUP_SEMANTICS)
        .open(NativeFsPath::from_path(parent)?.as_path())
        .map_err(|e| io("private directory", e))?;
    if information(&dir)?.volume != volume {
        return Err("staging/recovery must share target volume".into());
    }
    guards.push(dir);
    Ok(guards)
}
pub(super) fn apply(
    source: &SourceSnapshot,
    candidate: &PreparedArchive,
    layout: &NativeLayout,
    window: &mut impl MaintenanceWindow,
) -> Result<AppliedArchive, InstallFailure> {
    apply_profile(source, candidate, layout, window, desktop_hook::HookProfile::Legacy)
}

pub(super) fn apply_profile(
    source: &SourceSnapshot,
    candidate: &PreparedArchive,
    layout: &NativeLayout,
    window: &mut impl MaintenanceWindow,
    profile: desktop_hook::HookProfile<'_>,
) -> Result<AppliedArchive, InstallFailure> {
    let target = &source.target;
    let paths = &layout.paths;
    let mut phase = "preflight";
    let mut called = None;
    let operation = (|| -> Result<AppliedArchive, String> {
        window.ensure_held()?;
        layout.verify(target)?;
        let _guards = paths_check(target, paths, source.identity.volume)?;
        shadow_clear(target)?;
        let mut source_guard = open_regular(target, READ | DELETE)?;
        let current = read_checked(&mut source_guard, target)?;
        if !same_snapshot(&current, source) || hash(&source.bytes) != source.digest {
            return Err("source identity/preimage conflict".into());
        }
        let prepared = desktop_hook::prepare_profile(&source.bytes, profile).map_err(|e| e.to_string())?;
        if prepared.hook_status != HookStatus::Prepared
            || candidate.hook_status != HookStatus::Prepared
            || prepared.bytes != candidate.bytes
            || candidate.pre_digest != source.digest
            || candidate.post_digest != prepared.post_digest
            || candidate.version != prepared.version
        {
            return Err("prepared candidate/source binding conflict".into());
        }
        phase = "stage";
        let backup = create_checked(&paths.original_backup, &source.bytes, &source.identity)?;
        let mut backup_guard = open_regular(&paths.original_backup, READ)?;
        if !same_snapshot(
            &read_checked(&mut backup_guard, &paths.original_backup)?,
            &backup,
        ) {
            return Err("original backup changed before retention".into());
        }
        #[cfg(test)]
        let fixture_metadata = if TEST_WRONG_GROUP_STAGE.with(|value| value.replace(false)) {
            Some(super::native::fixture_wrong_group_metadata(&source.identity)?)
        } else { None };
        #[cfg(test)]
        let stage_metadata = fixture_metadata.as_ref().unwrap_or(&source.identity);
        #[cfg(not(test))]
        let stage_metadata = &source.identity;
        let staged = create_checked(&paths.staged, &candidate.bytes, stage_metadata)?;
        let staged_object = object_id(&open_regular(&paths.staged, READ | DELETE)?)?;
        phase = "publish-precheck";
        window.ensure_held()?;
        shadow_clear(target)?;
        if !same_snapshot(&read_path(target, READ | DELETE)?, source) {
            return Err("target changed immediately before replacement".into());
        }
        if !same_snapshot(&read_path(&paths.staged, READ | DELETE)?, &staged) {
            return Err("staged candidate changed before replacement".into());
        }
        absent(&paths.displaced_backup)?;
        phase = "replace";
        replace(target, &paths.staged, &paths.displaced_backup, &mut called)?;
        phase = "metadata-preservation";
        restore_postimage_security(
            target,
            &staged,
            &staged_object,
            &layout.archive,
            &source,
            &paths.displaced_backup,
            &source.identity.security_descriptor,
            window,
        )?;
        phase = "readback";
        let received = receive_applied_profile(source, &candidate.bytes, paths, profile)?;
        window.ensure_held()?;
        shadow_clear(target)?;
        Ok(received)
    })();
    operation.map_err(|e| failure(target, Some(paths), phase, e, called))
}
#[cfg(test)]
thread_local! {
    // One explicitly owned synthetic vendor fixture. The real archive owner
    // still calls ReplaceFileW and persists its actual strict metadata failure.
    pub(super) static TEST_WRONG_GROUP_STAGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn receive_applied(
    source: &SourceSnapshot,
    candidate: &[u8],
    paths: &InstallPaths,
) -> Result<AppliedArchive, String> {
    receive_applied_profile(source, candidate, paths, desktop_hook::HookProfile::Legacy)
}

pub(super) fn receive_applied_profile(
    source: &SourceSnapshot,
    candidate: &[u8],
    paths: &InstallPaths,
    profile: desktop_hook::HookProfile<'_>,
) -> Result<AppliedArchive, String> {
    let target = &source.target;
    let post = read_path(target, READ | DELETE)?;
    let displaced = read_path(&paths.displaced_backup, READ | DELETE)?;
    let original = read_path(&paths.original_backup, READ)?;
    if original.bytes != source.bytes
        || original.digest != source.digest
        || original.identity.attributes != source.identity.attributes
        || original.identity.creation != source.identity.creation
        || original.identity.write != source.identity.write
    {
        return Err("retained original backup readback conflict".into());
    }
    if post.bytes != candidate
        || post.digest != hash(candidate)
        || !same_snapshot(&displaced, source)
        || post.identity.security_descriptor != source.identity.security_descriptor
        || post.identity.attributes != source.identity.attributes
        || post.identity.creation != source.identity.creation
        || post.identity.write != source.identity.write
        || post.identity.volume != source.identity.volume
    {
        return Err("replacement/displaced bytes or preserved metadata readback conflict".into());
    }
    let inspected = desktop_hook::inspect_profile(&post.bytes, profile).map_err(|e| e.to_string())?;
    if inspected.hook_status != HookStatus::AlreadyApplied || inspected.digest != hash(candidate) {
        return Err("published hook readback conflict".into());
    }
    if !matches!(observe(&paths.staged), FileObservation::Missing) {
        return Err("replacement stage still present".into());
    }
    Ok(AppliedArchive {
        record_version: 1,
        target: target.clone(),
        original: source.identity.clone(),
        pre_digest: source.digest.clone(),
        post: post.identity,
        post_digest: post.digest,
        original_backup: paths.original_backup.clone(),
        original_backup_identity: original.identity,
        displaced_backup: paths.displaced_backup.clone(),
        displaced_identity: displaced.identity,
    })
}

pub(super) fn revert(
    record: &AppliedArchive,
    layout: &NativeLayout,
    window: &mut impl MaintenanceWindow,
) -> Result<RevertedArchive, InstallFailure> {
    revert_profile(record, layout, window, desktop_hook::HookProfile::Legacy)
}

pub(super) fn revert_profile(
    record: &AppliedArchive,
    layout: &NativeLayout,
    window: &mut impl MaintenanceWindow,
    profile: desktop_hook::HookProfile<'_>,
) -> Result<RevertedArchive, InstallFailure> {
    let target = &record.target;
    let paths = &layout.paths;
    let mut phase = "revert-preflight";
    let mut called = None;
    let operation = (|| -> Result<RevertedArchive, String> {
        window.ensure_held()?;
        layout.verify(target)?;
        if record.record_version != 1 {
            return Err("unsupported archive recovery record version".into());
        }
        let _guards = paths_check(target, paths, record.post.volume)?;
        shadow_clear(target)?;
        // Recovery inputs receive their own pinned ancestors and no-write/no-delete guards.
        let _original_parents = parents(&record.original_backup)?;
        let _displaced_parents = parents(&record.displaced_backup)?;
        let mut original_guard = open_regular(&record.original_backup, READ)?;
        let original = read_checked(&mut original_guard, &record.original_backup)?;
        let mut displaced_guard = open_regular(&record.displaced_backup, READ)?;
        let displaced = read_checked(&mut displaced_guard, &record.displaced_backup)?;
        if original.identity != record.original_backup_identity
            || original.digest != record.pre_digest
            || displaced.identity != record.displaced_identity
            || displaced.identity != record.original
            || displaced.bytes != original.bytes
            || displaced.digest != record.pre_digest
        {
            return Err("original recovery binding conflict".into());
        }
        let mut source_guard = open_regular(target, READ | DELETE)?;
        let current = read_checked(&mut source_guard, target)?;
        if current.identity != record.post || current.digest != record.post_digest {
            return Err("RevertConflict: target is not the exact owned postimage".into());
        }
        let prepared = desktop_hook::prepare_profile(&original.bytes, profile).map_err(|e| e.to_string())?;
        if prepared.post_digest != record.post_digest
            || prepared.bytes != current.bytes
            || prepared.hook_status != HookStatus::Prepared
        {
            return Err("recovery original/postimage semantic conflict".into());
        }
        phase = "revert-stage";
        create_checked(&paths.original_backup, &current.bytes, &current.identity)?;
        let staged = create_checked(&paths.staged, &original.bytes, &record.original)?;
        let staged_object = object_id(&open_regular(&paths.staged, READ | DELETE)?)?;
        phase = "revert-publish-precheck";
        window.ensure_held()?;
        shadow_clear(target)?;
        if !same_snapshot(&read_path(target, READ | DELETE)?, &current)
            || !same_snapshot(&read_path(&paths.staged, READ | DELETE)?, &staged)
        {
            return Err("revert target/stage changed before replacement".into());
        }
        absent(&paths.displaced_backup)?;
        phase = "revert-replace";
        replace(target, &paths.staged, &paths.displaced_backup, &mut called)?;
        phase = "revert-metadata-preservation";
        restore_postimage_security(
            target,
            &staged,
            &staged_object,
            &layout.archive,
            &current,
            &paths.displaced_backup,
            &record.original.security_descriptor,
            window,
        )?;
        phase = "revert-readback";
        let received = receive_reverted(record, &original, &current, paths)?;
        window.ensure_held()?;
        shadow_clear(target)?;
        Ok(received)
    })();
    operation.map_err(|e| failure(target, Some(paths), phase, e, called))
}

fn restore_postimage_security(
    target: &Path,
    staged: &SourceSnapshot,
    staged_object: &ObjectId,
    source_object: &ObjectId,
    expected_displaced: &SourceSnapshot,
    displaced: &Path,
    security: &[u8],
    window: &mut impl MaintenanceWindow,
) -> Result<(), String> {
    super::native::restore_replacement_security(
        target,
        staged,
        staged_object,
        source_object,
        expected_displaced,
        displaced,
        security,
        &mut || window.ensure_held(),
    )
}

pub(super) fn receive_reverted(
    record: &AppliedArchive,
    original: &SourceSnapshot,
    current: &SourceSnapshot,
    paths: &InstallPaths,
) -> Result<RevertedArchive, String> {
    let target = &record.target;
    let restored = read_path(target, READ | DELETE)?;
    let replaced = read_path(&paths.displaced_backup, READ | DELETE)?;
    if restored.bytes != original.bytes
        || restored.digest != record.pre_digest
        || !same_snapshot(&replaced, current)
        || restored.identity.security_descriptor != record.original.security_descriptor
        || restored.identity.attributes != record.original.attributes
        || restored.identity.creation != record.original.creation
        || restored.identity.write != record.original.write
    {
        return Err("revert actual target/displacement readback conflict".into());
    }
    if !matches!(observe(&paths.staged), FileObservation::Missing) {
        return Err("revert stage still present".into());
    }
    Ok(RevertedArchive {
        target: restored,
        retained_paths: paths.clone(),
        displaced_postimage: replaced.identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;

    fn apply(
        source: &SourceSnapshot,
        candidate: &PreparedArchive,
        paths: &InstallPaths,
        window: &mut impl MaintenanceWindow,
    ) -> Result<AppliedArchive, InstallFailure> {
        let layout = NativeLayout::for_test(&source.target, paths.clone())
            .map_err(|e| failure(&source.target, Some(paths), "fixture-layout", e, None))?;
        super::apply(source, candidate, &layout, window)
    }
    fn revert(
        record: &AppliedArchive,
        paths: &InstallPaths,
        window: &mut impl MaintenanceWindow,
    ) -> Result<RevertedArchive, InstallFailure> {
        let layout = NativeLayout::for_test(&record.target, paths.clone())
            .map_err(|e| failure(&record.target, Some(paths), "fixture-layout", e, None))?;
        super::revert(record, &layout, window)
    }

    struct Window {
        calls: usize,
        deny: bool,
        lock_target: Option<PathBuf>,
        swap_target: Option<PathBuf>,
        deny_after: Option<usize>,
        held: Option<File>,
    }
    impl Window {
        fn clean() -> Self {
            Self {
                calls: 0,
                deny: false,
                lock_target: None,
                swap_target: None,
                deny_after: None,
                held: None,
            }
        }
    }
    impl MaintenanceWindow for Window {
        fn ensure_held(&mut self) -> Result<(), String> {
            self.calls += 1;
            if self.deny || self.deny_after == Some(self.calls) {
                return Err("maintenance-pending: fixture user arrangement absent".into());
            }
            if self.calls == 2 {
                if let Some(path) = &self.swap_target {
                    let retained = path.with_file_name("foreign-displaced-original");
                    assert!(!retained.exists());
                    fs::rename(path, retained).unwrap();
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)
                        .unwrap();
                    file.write_all(b"foreign rename writer").unwrap();
                    file.sync_all().unwrap();
                }
                if let Some(path) = &self.lock_target {
                    self.held = Some(
                        OpenOptions::new()
                            .read(true)
                            .share_mode(READ)
                            .open(path)
                            .unwrap(),
                    );
                }
            }
            Ok(())
        }
    }
    fn paths(dir: &Path, prefix: &str) -> InstallPaths {
        InstallPaths {
            staged: dir.join(format!("{prefix}.stage")),
            original_backup: dir.join(format!("{prefix}.original")),
            displaced_backup: dir.join(format!("{prefix}.displaced")),
        }
    }
    #[test]
    fn invalid_replace_path_never_crosses_native_invocation_marker() {
        let initial = TEST_NATIVE_CALLS.with(|calls| calls.get());
        for invalid_position in 0..3 {
            let mut paths = [Path::new(r"C:\target"), Path::new(r"C:\stage"), Path::new(r"C:\displaced")];
            paths[invalid_position] = Path::new(r"\\?\C:\external-verbatim");
            let mut called = None;
            assert!(replace(paths[0], paths[1], paths[2], &mut called).is_err());
            assert_eq!(called, None);
            assert_eq!(TEST_NATIVE_CALLS.with(|calls| calls.get()), initial);
        }
    }
    fn setup(name: &str) -> (PathBuf, SourceSnapshot, PreparedArchive) {
        let root = PathBuf::from(
            std::env::var_os("AG_ARCHIVE_INSTALL_TEST_ROOT").expect("explicit owned test root"),
        );
        validate_path(&root).unwrap();
        let dir = root.join(name);
        fs::create_dir(&dir).expect("vacant exact test case directory");
        let bytes = fs::read(
            std::env::var_os("AG_ARCHIVE_INSTALL_FIXTURE")
                .expect("explicit read-only fixture archive"),
        )
        .unwrap();
        let target = dir.join("app.asar");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        initialize_inherited_fixture(&target).unwrap();
        let source = snapshot(&target).unwrap();
        let candidate = desktop_hook::prepare_archive(&bytes).unwrap();
        (dir, source, candidate)
    }

    #[test]
    #[ignore = "requires explicit owned Windows test root and read-only archive fixture"]
    fn native_apply_and_revert_receive_complete_bytes_metadata_and_backups() {
        let (dir, source, candidate) = setup("success");
        let applied = apply(
            &source,
            &candidate,
            &paths(&dir, "apply"),
            &mut Window::clean(),
        )
        .unwrap();
        let encoded = serde_json::to_vec(&applied).unwrap();
        let applied: AppliedArchive = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(snapshot(&source.target).unwrap().bytes, candidate.bytes);
        assert_eq!(
            snapshot(&applied.displaced_backup).unwrap().identity,
            source.identity
        );
        let reverted = revert(&applied, &paths(&dir, "revert"), &mut Window::clean()).unwrap();
        assert_eq!(reverted.target.bytes, source.bytes);
        assert_eq!(reverted.target.digest, source.digest);
        assert_eq!(reverted.target.identity.write, source.identity.write);
        assert_eq!(reverted.target.identity.creation, source.identity.creation);
        assert_eq!(
            reverted.target.identity.security_descriptor,
            source.identity.security_descriptor
        );
        assert_eq!(reverted.displaced_postimage, applied.post);
        assert!(matches!(
            observe(&reverted.retained_paths.staged),
            FileObservation::Missing
        ));
    }

    #[test]
    #[ignore = "requires an explicit owned Windows test root and read-only archive fixture"]
    fn native_long_replace_and_restore_receive_bytes_and_complete_metadata() {
        let (dir, source, candidate) = setup(&"archive-long-native-component-".repeat(5));
        assert!(source.target.as_os_str().encode_wide().count() > 248);
        let initial = TEST_NATIVE_CALLS.with(|calls| calls.get());
        let applied = apply(&source, &candidate, &paths(&dir, "apply"), &mut Window::clean()).unwrap();
        let post = snapshot(&source.target).unwrap();
        assert_eq!(post.bytes, candidate.bytes);
        assert_eq!(post.identity.attributes, source.identity.attributes);
        assert_eq!(post.identity.creation, source.identity.creation);
        assert_eq!(post.identity.write, source.identity.write);
        assert_eq!(post.identity.security_descriptor, source.identity.security_descriptor);
        let restored = revert(&applied, &paths(&dir, "revert"), &mut Window::clean()).unwrap();
        assert_eq!(restored.target.bytes, source.bytes);
        assert_eq!(restored.target.identity.attributes, source.identity.attributes);
        assert_eq!(restored.target.identity.creation, source.identity.creation);
        assert_eq!(restored.target.identity.write, source.identity.write);
        assert_eq!(restored.target.identity.security_descriptor, source.identity.security_descriptor);
        assert_eq!(restored.displaced_postimage, applied.post);
        assert_eq!(TEST_NATIVE_CALLS.with(|calls| calls.get()), initial + 2);
    }

    #[test]
    #[ignore = "requires explicit owned Windows test root and read-only archive fixture"]
    fn conflicts_missing_window_shadow_and_backup_collision_never_publish() {
        let (dir, source, candidate) = setup("conflicts");
        let p = paths(&dir, "absent-window");
        let mut window = Window::clean();
        window.deny = true;
        assert!(apply(&source, &candidate, &p, &mut window)
            .unwrap_err()
            .replace_result
            .is_none());
        assert!(matches!(
            observe(&p.original_backup),
            FileObservation::Missing
        ));
        let mut invalid_candidate = desktop_hook::prepare_archive(&source.bytes).unwrap();
        invalid_candidate.post_digest.clear();
        assert!(apply(&source, &invalid_candidate, &p, &mut Window::clean())
            .unwrap_err()
            .cause
            .contains("binding"));
        assert!(matches!(
            observe(&p.original_backup),
            FileObservation::Missing
        ));
        fs::create_dir(dir.join("app")).unwrap();
        assert!(apply(&source, &candidate, &p, &mut Window::clean())
            .unwrap_err()
            .cause
            .contains("shadow"));
        fs::remove_dir(dir.join("app")).unwrap();
        fs::write(&p.original_backup, b"foreign backup").unwrap();
        assert!(apply(&source, &candidate, &p, &mut Window::clean())
            .unwrap_err()
            .replace_result
            .is_none());
        assert_eq!(fs::read(&p.original_backup).unwrap(), b"foreign backup");
        fs::write(&source.target, b"foreign/newer archive").unwrap();
        let fresh = paths(&dir, "changed-source");
        assert!(apply(&source, &candidate, &fresh, &mut Window::clean())
            .unwrap_err()
            .cause
            .contains("source"));
        assert_eq!(fs::read(&source.target).unwrap(), b"foreign/newer archive");
        assert!(matches!(
            observe(&fresh.original_backup),
            FileObservation::Missing
        ));
    }

    #[test]
    #[ignore = "requires explicit owned Windows test root and read-only archive fixture"]
    fn native_sharing_failure_retains_actual_stage_and_recovery_without_retry() {
        let (dir, source, candidate) = setup("sharing-failure");
        let p = paths(&dir, "apply");
        let mut window = Window::clean();
        window.lock_target = Some(source.target.clone());
        let failure = apply(&source, &candidate, &p, &mut window).unwrap_err();
        assert_eq!(failure.replace_result, Some(false));
        assert_eq!(window.calls, 2);
        assert_eq!(fs::read(&source.target).unwrap(), source.bytes);
        assert_eq!(fs::read(&p.original_backup).unwrap(), source.bytes);
        assert_eq!(fs::read(&p.staged).unwrap(), candidate.bytes);
        assert!(matches!(
            failure.recovery.target.1,
            FileObservation::Present { .. }
        ));
        assert!(matches!(
            failure.recovery.displaced_backup.unwrap().1,
            FileObservation::Missing
        ));
    }

    #[test]
    #[ignore = "requires explicit owned Windows test root and read-only archive fixture"]
    fn foreign_postimage_refuses_revert_and_hardlinked_source_refuses_snapshot() {
        let (dir, source, candidate) = setup("revert-conflict");
        let applied = apply(
            &source,
            &candidate,
            &paths(&dir, "apply"),
            &mut Window::clean(),
        )
        .unwrap();
        fs::write(&source.target, b"newer vendor bytes").unwrap();
        let p = paths(&dir, "revert");
        let failure = revert(&applied, &p, &mut Window::clean()).unwrap_err();
        assert!(failure.cause.contains("RevertConflict"));
        assert_eq!(failure.replace_result, None);
        assert_eq!(fs::read(&source.target).unwrap(), b"newer vendor bytes");
        assert!(matches!(
            observe(&p.original_backup),
            FileObservation::Missing
        ));
        fs::hard_link(&source.target, dir.join("alias")).unwrap();
        assert!(snapshot(&source.target)
            .unwrap_err()
            .cause
            .contains("hardlink"));
    }

    #[test]
    #[ignore = "requires explicit owned Windows test root and read-only archive fixture"]
    fn partial_name_state_is_observed_even_when_replace_result_is_false() {
        let (dir, source, candidate) = setup("partial-receipt");
        let p = paths(&dir, "partial");
        create_checked(&p.original_backup, &source.bytes, &source.identity).unwrap();
        create_checked(&p.staged, &candidate.bytes, &source.identity).unwrap();
        fs::rename(&source.target, &p.displaced_backup).unwrap();
        fs::rename(&p.staged, &source.target).unwrap();
        let failure = failure(
            &source.target,
            Some(&p),
            "replace",
            "synthetic partial API-error state".into(),
            Some(false),
        );
        assert!(
            matches!(failure.recovery.target.1, FileObservation::Present { ref digest, .. } if *digest == candidate.post_digest)
        );
        assert!(matches!(
            failure.recovery.staged.unwrap().1,
            FileObservation::Missing
        ));
        assert!(
            matches!(failure.recovery.displaced_backup.unwrap().1, FileObservation::Present { ref digest, .. } if *digest == source.digest)
        );
    }

    #[test]
    #[ignore = "requires explicit owned Windows test root and read-only archive fixture"]
    fn installation_lease_is_nonwaiting_and_abandonment_requires_recovery() {
        fn fixture_lease(target: &Path) -> Result<Lease, InstallFailure> {
            let dir = CheckedPath::open(
                target.parent().unwrap(),
                PathKind::Directory,
                PathPurpose::Review,
            )
            .map_err(|e| failure(target, None, "lease-fixture", e, None))?;
            Lease::acquire(&dir, "fixture")
                .map_err(|e| failure(target, None, "lease-fixture", e, None))
        }
        let (_, source, _) = setup("installation-lease");
        let lease = fixture_lease(&source.target).unwrap();
        let target = source.target.clone();
        let busy = std::thread::spawn(move || {
            fixture_lease(&target)
                .err()
                .expect("lease must be busy")
                .cause
        })
        .join()
        .unwrap();
        assert!(busy.contains("another owned operation"));
        drop(lease);
        // Transfer the creator-retained native handle to this thread before
        // the owning thread exits. Closing it here settles the abandoned test.
        let target = source.target.clone();
        let retained = std::thread::spawn(move || {
            let mut lease = fixture_lease(&target).unwrap();
            let raw = lease.mutex.0 as usize;
            lease.held = false;
            lease.mutex.0 = std::ptr::null_mut();
            raw
        })
        .join()
        .unwrap();
        let refused = fixture_lease(&source.target)
            .err()
            .expect("abandoned lease must refuse");
        assert!(refused.cause.contains("RecoveryRequired"));
        assert_eq!(unsafe { CloseHandle(retained as *mut c_void) }, 1);
    }

    #[test]
    #[ignore = "requires explicit owned Windows test root and read-only archive fixture"]
    fn observed_rename_before_publication_and_lost_window_after_publication_are_truthful() {
        let (dir, source, candidate) = setup("rename-before-publish-recheck-15");
        let p = paths(&dir, "apply");
        let mut window = Window::clean();
        window.swap_target = Some(source.target.clone());
        let failed = apply(&source, &candidate, &p, &mut window).unwrap_err();
        assert_eq!(failed.phase, "publish-precheck");
        assert_eq!(failed.replace_result, None);
        assert_eq!(fs::read(&source.target).unwrap(), b"foreign rename writer");
        assert_eq!(
            fs::read(dir.join("foreign-displaced-original")).unwrap(),
            source.bytes
        );
        assert_eq!(fs::read(&p.original_backup).unwrap(), source.bytes);
        assert_eq!(fs::read(&p.staged).unwrap(), candidate.bytes);
        let (dir, source, candidate) = setup("window-lost-after-publish-recheck-15");
        let p = paths(&dir, "apply");
        let mut window = Window::clean();
        window.deny_after = Some(3);
        let failed = apply(&source, &candidate, &p, &mut window).unwrap_err();
        assert_eq!(failed.phase, "metadata-preservation");
        assert_eq!(failed.replace_result, Some(true));
        assert_eq!(fs::read(&source.target).unwrap(), candidate.bytes);
        assert_eq!(fs::read(&p.displaced_backup).unwrap(), source.bytes);
        assert!(matches!(
            failed.recovery.staged.unwrap().1,
            FileObservation::Missing
        ));
    }
}
