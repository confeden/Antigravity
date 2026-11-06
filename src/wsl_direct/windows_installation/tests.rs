#[path = "context_test_support.rs"]
mod support;
use super::*;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn DeviceIoControl(
        file: *mut std::ffi::c_void,
        code: u32,
        input: *const std::ffi::c_void,
        input_size: u32,
        output: *mut std::ffi::c_void,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> i32;
}
fn own_junction(path: &Path, target: &Path) {
    create_private_dir(path).unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(READ | WRITE | DELETE)
        .custom_flags(OPEN_REPARSE | BACKUP_SEMANTICS)
        .open(path)
        .unwrap();
    let id = object_id(&file).unwrap();
    let facts =
        serde_json::json!({"schema":1,"kind":"owned-junction-negative","path":path,"nativeId":id});
    write_private(
        &path.parent().unwrap().join("junction-root-facts.json"),
        &json(&facts).unwrap(),
    )
    .unwrap();
    let substitute = format!("\\??\\{}", target.display())
        .encode_utf16()
        .collect::<Vec<_>>();
    let print = target.as_os_str().encode_wide().collect::<Vec<_>>();
    let data_len = 8 + 2 * (substitute.len() + 1 + print.len() + 1);
    let mut buffer = Vec::new();
    buffer.extend(0xa0000003u32.to_le_bytes());
    buffer.extend(u16::try_from(data_len).unwrap().to_le_bytes());
    buffer.extend(0u16.to_le_bytes());
    buffer.extend(0u16.to_le_bytes());
    buffer.extend(u16::try_from(substitute.len() * 2).unwrap().to_le_bytes());
    buffer.extend(
        u16::try_from((substitute.len() + 1) * 2)
            .unwrap()
            .to_le_bytes(),
    );
    buffer.extend(u16::try_from(print.len() * 2).unwrap().to_le_bytes());
    for ch in substitute
        .into_iter()
        .chain(Some(0))
        .chain(print)
        .chain(Some(0))
    {
        buffer.extend(ch.to_le_bytes());
    }
    let mut returned = 0;
    assert_ne!(
        unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                0x000900a4,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        },
        0,
        "owned junction setup failed: {}",
        std::io::Error::last_os_error()
    );
}
fn expected_for(files: &[Vec<u8>]) -> ExpectedLegacyAttempt {
    let values = files.iter().map(|b| hash(b)).collect::<Vec<_>>();
    ExpectedLegacyAttempt::from_hex([&values[0], &values[1], &values[2], &values[3], &values[4]])
        .unwrap()
}
fn copy_external_input(parent: &Path, name: &str, bytes: &[Vec<u8>]) -> PathBuf {
    let path = parent.join(name);
    create_private_dir(&path).unwrap();
    for (name, bytes) in LEGACY_FILES.iter().zip(bytes) {
        write_private(&path.join(name), bytes).unwrap();
    }
    path
}
struct DriftingWindow {
    path: PathBuf,
    done: bool,
}
impl MaintenanceWindow for DriftingWindow {
    fn ensure_held(&mut self) -> Result<()> {
        if !self.done {
            let file = OpenOptions::new()
                .access_mode(0x0006_0000)
                .share_mode(READ | WRITE | DELETE)
                .custom_flags(OPEN_REPARSE)
                .open(&self.path)
                .map_err(|e| io("own degraded input handle", e))?;
            super::context_tests::replace_owned_dacl(&file, "(A;;FA;;;WD)");
            self.done = true;
        }
        Ok(())
    }
}
struct Window {
    calls: usize,
    fail_at: Option<usize>,
    block_at: Option<(usize, PathBuf)>,
    held: Option<File>,
}
impl Window {
    fn clean() -> Self {
        Self {
            calls: 0,
            fail_at: None,
            block_at: None,
            held: None,
        }
    }
}
impl MaintenanceWindow for Window {
    fn ensure_held(&mut self) -> Result<()> {
        self.calls += 1;
        if let Some((at, path)) = &self.block_at {
            if *at == self.calls {
                self.held = Some(
                    OpenOptions::new()
                        .read(true)
                        .share_mode(READ)
                        .open(path)
                        .map_err(|e| io("owned native-failure fixture lock", e))?,
                );
            }
        }
        if self.fail_at == Some(self.calls) {
            Err("fixture window lost".into())
        } else {
            Ok(())
        }
    }
}
struct Fixture {
    local: PathBuf,
    review: PathBuf,
    desktop: PathBuf,
    original: Vec<u8>,
}
fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| {
        panic!("explicit runtime input {name} required; no fixture mutation authorized")
    }));
    WindowsLocalPath::parse(path.as_os_str()).unwrap();
    path
}
struct RuntimeInputs {
    local: CheckedPath,
    review: CheckedPath,
    archive: Vec<u8>,
}
fn runtime_inputs() -> RuntimeInputs {
    // Read every required input before exclusive creation. These are fixture
    // choices only: production KnownFolder/state receiving is unchanged.
    let local_path = required_path("AG_INSTALLATION_TEST_LOCAL");
    let review_path = required_path("AG_INSTALLATION_TEST_ROOT");
    let archive_path = required_path("AG_ARCHIVE_INSTALL_FIXTURE");
    let local = CheckedPath::open(&local_path, PathKind::Directory, PathPurpose::Review).unwrap();
    let review = CheckedPath::open(&review_path, PathKind::Directory, PathPurpose::Review).unwrap();
    // Only the local root contains canonical fixture state. Review is an
    // independent checked location; its children are privately/exclusively made.
    ancestor_integrity(&local.file).unwrap();
    for ancestor in &local._ancestors {
        ancestor_integrity(ancestor).unwrap();
    }
    assert_ne!(
        local.object.volume, review.object.volume,
        "explicit local/review parents must be on distinct native volumes"
    );
    let mut archive =
        CheckedPath::open(&archive_path, PathKind::File, PathPurpose::Source).unwrap();
    let archive = archive.read().unwrap();
    desktop_hook::prepare_archive(&archive).unwrap();
    RuntimeInputs {
        local,
        review,
        archive,
    }
}
#[test]
#[ignore = "explicit caller roots and run ID; no production state-root switch"]
fn snapshot_runtime_allocate() {
    let inputs = runtime_inputs();
    let run = std::env::var("AG_SNAPSHOT_RUN_ID").expect("explicit snapshot run ID");
    assert!(id_valid(&run));
    let facts = required_path("AG_SNAPSHOT_ROOT_FACTS");
    let _parent = CheckedPath::open(
        facts.parent().unwrap(),
        PathKind::Directory,
        PathPurpose::Review,
    )
    .unwrap();
    private(&_parent.file).unwrap();
    absent(&facts).unwrap();
    let local = inputs.local.path.join(format!("owner-test-{run}"));
    let review = inputs.review.path.join(format!("owner-test-{run}"));
    absent(&local).unwrap();
    absent(&review).unwrap();
    create_private_dir(&local).unwrap();
    create_private_dir(&review).unwrap();
    let adapter = local.join("adapter");
    create_private_dir(&adapter).unwrap();
    let value = serde_json::json!({"schema":1,"runId":run,"localParent":inputs.local.object,"reviewParent":inputs.review.object,"local":local,"review":review,"adapter":adapter});
    write_private(&facts, &json(&value).unwrap()).unwrap();
    eprintln!(
        "caller local/review native volume IDs differ; exclusive owned run children received"
    );
}
#[test]
#[ignore = "single admitted owned post-Replace DACL hypothesis; explicit vacant C fixture root"]
fn post_replace_received_dacl_single_native_trial() {
    let f = fixture("post-dacl-single-07");
    let target = f.desktop.parent().unwrap().join("resources/app.asar");
    initialize_inherited_fixture(&target).unwrap();
    let source = read_path(&target, READ | DELETE).unwrap();
    stage(&f);
    let review = CheckedPath::open(&f.review, PathKind::Directory, PathPurpose::Review).unwrap();
    assert_ne!(review.object.volume, bound(&f).resources.object.volume);
    let mut window = Window::clean();
    apply(&f, &mut window).unwrap();
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 1);
    let actual = read_path(&target, READ | DELETE).unwrap();
    assert_eq!(
        actual.identity.security_descriptor,
        source.identity.security_descriptor
    );
    assert_eq!(actual.identity.creation, source.identity.creation);
    assert_eq!(actual.identity.write, source.identity.write);
    assert_eq!(actual.identity.attributes, source.identity.attributes);
    assert!(admit_run(bound(&f)).is_ok());
    assert_eq!(pending(&f).0.mode, Mode::SettledApplied);
}
#[test]
#[ignore = "requires independent private owned C parent; file-only metadata regression"]
fn dacl_only_restorer_reports_actual_status_and_exact_unchanged_object() {
    let f = fixture("dacl-only-regression-11");
    let target = f.desktop.parent().unwrap().join("resources/app.asar");
    let source = read_path(&target, READ | DELETE).unwrap();
    let before = object_id(&open_regular(&target, READ | DELETE).unwrap()).unwrap();
    set_fixture_protection(&target, true).unwrap();
    let file = OpenOptions::new()
        .access_mode(0x0006_0000)
        .share_mode(READ | DELETE)
        .custom_flags(OPEN_REPARSE)
        .open(&target)
        .unwrap();
    assert_ne!(
        security(file.as_raw_handle(), 1 | 2 | 4).unwrap(),
        source.identity.security_descriptor
    );
    assert_eq!(object_id(&file).unwrap(), before);
    restore_received_dacl(&file, &source.identity.security_descriptor).unwrap();
    assert_eq!(TEST_DACL_STATUSES.with(|v| v.borrow().clone()), [0]);
    drop(file);
    let after = read_path(&target, READ | DELETE).unwrap();
    assert_eq!(after.identity, source.identity);
    assert_eq!(after.bytes, source.bytes);
    assert_eq!(
        object_id(&open_regular(&target, READ | DELETE).unwrap()).unwrap(),
        before
    );
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 0);
}
fn fixture(name: &str) -> Fixture {
    TEST_NATIVE_CALLS.with(|v| v.set(0));
    TEST_DACL_STATUSES.with(|v| v.borrow_mut().clear());
    let inputs = runtime_inputs();
    let child = format!("{name}-{}", unique_id().unwrap());
    let local = inputs.local.path.join(&child);
    create_private_dir(&local).unwrap();
    support::record_root(&local, inputs.local.as_path());
    let state = local.join("state");
    create_private_dir(&state).unwrap();
    TEST_BASE.with(|v| *v.borrow_mut() = Some(state));
    let parent = local.join("installation-parent");
    create_private_dir(&parent).unwrap();
    let install = parent.join("Desktop");
    create_private_dir(&install).unwrap();
    let resources = install.join("resources");
    create_private_dir(&resources).unwrap();
    let desktop = install.join("Antigravity.exe");
    fs::write(&desktop, b"MZ synthetic; never executable").unwrap();
    let original = inputs.archive;
    fs::write(resources.join("app.asar"), &original).unwrap();
    initialize_inherited_fixture(&resources.join("app.asar")).unwrap();
    let review_parent = inputs.review.path.join(&child);
    create_private_dir(&review_parent).unwrap();
    support::record_root(&review_parent, inputs.review.as_path());
    Fixture {
        local,
        review: review_parent.join("review"),
        desktop,
        original,
    }
}
fn bound(f: &Fixture) -> BoundInstallation {
    BoundInstallation::open(&f.desktop).unwrap()
}
fn stage(f: &Fixture) {
    stage_review(&bound(f), &f.review, "Fixture").unwrap();
}
fn apply(f: &Fixture, w: &mut Window) -> Result<()> {
    let b = bound(f);
    let r = receive_review(&b, &f.review, "Fixture")?;
    prepare_apply(b, r, None, w)?.execute()
}
fn pending(f: &Fixture) -> (Current, String) {
    let b = bound(f);
    let a = Authority::open(&b, false, true).unwrap();
    (a.current.clone(), a.digest.clone())
}
fn cli_holds(f: &Fixture, desktop: &Path) {
    cli_rejects(f, desktop, "Pending")
}
fn cli_rejects(f: &Fixture, desktop: &Path, expected: &str) {
    for op in ["--apply", "--revert", "--run"] {
        let args = vec![
            op.into(),
            "--desktop".into(),
            desktop.into(),
            "--distro".into(),
            "Fixture".into(),
            "--output".into(),
            f.review.as_os_str().into(),
            "--clean-start-window".into(),
            "--allow-source-namespace".into(),
            "--powershell".into(),
            desktop.as_os_str().into(),
            "--poll-ms".into(),
            "1".into(),
            "--probe-ms".into(),
            "1".into(),
            "--probe-bytes".into(),
            "1".into(),
        ];
        let result = super::super::execute(args);
        assert!(
            result.as_ref().err().is_some_and(|e| e.contains(expected)),
            "{op}: {result:?}"
        );
    }
}
#[test]
fn lexical_policy_is_shared_and_rejects_ordinary_alias_traps() {
    for path in [r"C:\a\Desktop.exe", r"C:\", r"d:\a b\x"] {
        assert!(WindowsLocalPath::parse(OsStr::new(path)).is_ok(), "{path}")
    }
    for path in [
        r"C:foo",
        r"\foo",
        r"\\server\share\x",
        r"\\?\C:\a",
        r"C:\a\.\x",
        r"C:\a\..\x",
        r"C:\a\x.",
        r"C:\a\x ",
        r"C:\a\x:y",
        r"C:\a\CON.txt",
        r"C:\a\Lpt9",
        r"C:\a\x?",
        r"C:\a\\x",
    ] {
        assert!(WindowsLocalPath::parse(OsStr::new(path)).is_err(), "{path}")
    }
}
#[test]
#[ignore = "requires exact owned C/D fixture parents and reviewed preimage"]
fn cross_volume_review_default_slot_apply_alias_revert_and_exact_private_receiving() {
    let f = fixture("positive-regression-11");
    stage(&f);
    let b = bound(&f);
    let review = CheckedPath::open(&f.review, PathKind::Directory, PathPurpose::Review).unwrap();
    assert_ne!(
        b.resources.object.volume, review.object.volume,
        "requires actual distinct native volumes"
    );
    let actual_known = known_folder().unwrap();
    assert!(CheckedPath::open(&actual_known, PathKind::Directory, PathPurpose::Review).is_ok());
    let mut window = Window::clean();
    apply(&f, &mut window).unwrap();
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 1);
    let statuses = TEST_DACL_STATUSES.with(|v| v.borrow().clone());
    assert!(
        statuses.iter().all(|s| *s == 0),
        "metadata setter outcomes: {statuses:?}"
    );
    let mut runnable = admit_run(bound(&f)).unwrap();
    runnable.installation().recheck_archive().unwrap();
    drop(runnable);
    let alias = PathBuf::from(f.desktop.to_str().unwrap().to_uppercase());
    let b = BoundInstallation::open(&alias).unwrap();
    assert_eq!(b.exe.object, bound(&f).exe.object);
    prepare_revert(b, None, &mut window)
        .unwrap()
        .execute()
        .unwrap();
    assert_eq!(
        fs::read(f.desktop.parent().unwrap().join("resources/app.asar")).unwrap(),
        f.original
    );
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 2);
    assert!(admit_run(bound(&f)).is_err());
    let (current, _) = pending(&f);
    assert_eq!(current.mode, Mode::SettledReverted);
}
#[test]
#[ignore = "requires exact owned C/D fixture parents and reviewed preimage"]
fn r0_wrong_volume_and_b1_truthful_footprint_have_zero_native_work() {
    let f = fixture("preparation-private-02");
    stage(&f);
    let b = bound(&f);
    let r = receive_review(&b, &f.review, "Fixture").unwrap();
    let mut window = Window::clean();
    let e = prepare_apply(b, r, Some(f.review.parent().unwrap()), &mut window)
        .err()
        .unwrap();
    assert!(e.contains("RejectedBeforeBootstrap"), "{e}");
    assert!(!f.local.join("state/AGUnlocker").exists());
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 0);
    TEST_BOOTSTRAP_FAILURE.with(|v| v.set(true));
    let b = bound(&f);
    let r = receive_review(&b, &f.review, "Fixture").unwrap();
    let e = prepare_apply(b, r, None, &mut window).err().unwrap();
    assert!(
        e.contains("PreparationIncomplete") && e.contains("footprint"),
        "{e}"
    );
    let ns = f.local.join("state/AGUnlocker/wsl-installations");
    assert!(ns.is_dir());
    assert_eq!(fs::read_dir(ns).unwrap().count(), 0);
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 0);
}
#[test]
#[ignore = "requires independent private owned C parent and reviewed preimage"]
fn interrupted_bootstrap_requires_exact_explicit_initialization_receiving() {
    let f = fixture("bootstrap-recovery-14");
    stage(&f);
    TEST_BOOTSTRAP_SLOT_FAILURE.with(|v| v.set(true));
    let mut w = Window::clean();
    assert!(apply(&f, &mut w)
        .unwrap_err()
        .contains("PreparationIncomplete"));
    assert!(apply(&f, &mut w)
        .unwrap_err()
        .contains("PreparationIncomplete"));
    let ns = f.local.join("state/AGUnlocker/wsl-installations");
    let slot = fs::read_dir(ns).unwrap().next().unwrap().unwrap().path();
    let current = read_private(&slot.join("current.json")).unwrap();
    let state: Current = decode(&current).unwrap();
    assert_eq!(state.mode, Mode::Bootstrap);
    assert!(recover_initialization(bound(&f), "wrong-current", &mut w).is_err());
    recover_initialization(bound(&f), &hash(&current), &mut w).unwrap();
    assert_eq!(pending(&f).0.mode, Mode::SettledUnchanged);
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 0);
}
#[test]
#[ignore = "requires exact owned C/D fixture parents and reviewed preimage"]
fn pending_native_window_failure_blocks_all_entries_aliases_replacements_and_keeps_other_slot_independent(
) {
    let f = fixture("pending-moves-09");
    stage(&f);
    let mut w = Window {
        calls: 0,
        fail_at: Some(3),
        ..Window::clean()
    };
    let result = apply(&f, &mut w);
    assert!(result.is_err(), "{result:?}");
    let (current, _) = pending(&f);
    assert_eq!(current.mode, Mode::Pending);
    let calls = TEST_NATIVE_CALLS.with(|v| v.get());
    cli_holds(&f, &f.desktop);
    let alias = PathBuf::from(f.desktop.to_str().unwrap().to_uppercase());
    cli_holds(&f, &alias);
    // Different review selection cannot select another recovery authority.
    let moved_review = f.review.with_file_name("moved-review");
    fs::rename(&f.review, &moved_review).unwrap();
    let f = Fixture {
        review: moved_review,
        ..f
    };
    cli_holds(&f, &f.desktop);
    let root = f.desktop.parent().unwrap();
    fs::rename(root.join("resources"), root.join("resources-old")).unwrap();
    create_private_dir(&root.join("resources")).unwrap();
    write_private(&root.join("resources/app.asar"), b"unknown updater bytes").unwrap();
    cli_holds(&f, &f.desktop);
    let old_root = root.with_file_name("Desktop-old");
    fs::rename(root, &old_root).unwrap();
    cli_rejects(&f, &old_root.join("Antigravity.exe"), "LocatorConflict");
    create_private_dir(root).unwrap();
    create_private_dir(&root.join("resources")).unwrap();
    write_private(&f.desktop, b"MZ synthetic; never executable").unwrap();
    write_private(&root.join("resources/app.asar"), &f.original).unwrap();
    cli_holds(&f, &f.desktop);
    // Parent replacement is a distinct historical-discovery case.
    let parent = root.parent().unwrap();
    let old_parent = parent.with_file_name("installation-parent-old");
    fs::rename(parent, &old_parent).unwrap();
    create_private_dir(parent).unwrap();
    create_private_dir(root).unwrap();
    create_private_dir(&root.join("resources")).unwrap();
    write_private(&f.desktop, b"MZ synthetic; never executable").unwrap();
    write_private(&root.join("resources/app.asar"), &f.original).unwrap();
    cli_holds(&f, &f.desktop);
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), calls);
    let other = f.local.join("Other");
    create_private_dir(&other).unwrap();
    create_private_dir(&other.join("resources")).unwrap();
    write_private(
        &other.join("Desktop.exe"),
        b"MZ synthetic; never executable",
    )
    .unwrap();
    write_private(&other.join("resources/app.asar"), &f.original).unwrap();
    let b = BoundInstallation::open(&other.join("Desktop.exe")).unwrap();
    let other_review = f.review.with_file_name("other-review");
    stage_review(&b, &other_review, "Fixture").unwrap();
    let r = receive_review(&b, &other_review, "Fixture").unwrap();
    let mut other_window = Window::clean();
    let p = prepare_apply(b, r, None, &mut other_window);
    assert!(p.is_ok());
    drop(p);
}
#[test]
#[ignore = "requires exact owned C/D fixture parents and reviewed preimage"]
fn actual_result_persistence_failure_requires_exact_resolution_and_preserves_failure_authority() {
    let f = fixture("outcome-regression-10");
    stage(&f);
    TEST_OUTCOME_FAILURE.with(|v| v.set(true));
    let mut w = Window::clean();
    let e = apply(&f, &mut w).unwrap_err();
    assert!(e.contains("current remains Pending"));
    cli_holds(&f, &f.desktop);
    let (c, digest) = pending(&f);
    let op = c.active_operation.unwrap();
    assert!(recover(bound(&f), "wrong-operation", &digest, None, &mut w).is_err());
    assert!(recover(bound(&f), &op.id, "wrong-current", None, &mut w).is_err());
    recover(bound(&f), &op.id, &digest, None, &mut w).unwrap();
    assert!(admit_run(bound(&f)).is_ok());
    let (c, _) = pending(&f);
    assert_eq!(c.mode, Mode::SettledApplied);
    let b = bound(&f);
    prepare_revert(b, None, &mut w).unwrap().execute().unwrap();
}
#[test]
#[ignore = "requires independent private owned C parent and reviewed preimage"]
fn foreign_postimage_refuses_before_new_intent_or_native_work() {
    let f = fixture("foreign-refusal-11");
    stage(&f);
    let mut window = Window::clean();
    apply(&f, &mut window).unwrap();
    let source = f.desktop.parent().unwrap().join("resources/app.asar");
    fs::write(&source, b"foreign/newer bytes").unwrap();
    let error = prepare_revert(bound(&f), None, &mut window).err().unwrap();
    assert!(error.contains("RevertConflict"), "{error}");
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 1);
    assert_eq!(fs::read(source).unwrap(), b"foreign/newer bytes");
}
#[test]
#[ignore = "requires independent private owned C parent; actual ReplaceFile sharing failure"]
fn returned_native_failure_retains_pending_before_every_entry() {
    let f = fixture("native-failure-15");
    stage(&f);
    let target = f.desktop.parent().unwrap().join("resources/app.asar");
    let mut window = Window::clean();
    window.block_at = Some((4, target.clone()));
    let error = apply(&f, &mut window).unwrap_err();
    assert!(error.contains("replacement Some(false)"), "{error}");
    drop(window);
    let (current, _) = pending(&f);
    assert_eq!(current.mode, Mode::Pending);
    let operation = current.active_operation.unwrap();
    let b = bound(&f);
    let a = Authority::open(&b, false, true).unwrap();
    let intent: Intent = decode(&reference(&a.slot, &operation.intent).unwrap()).unwrap();
    let failure_path = a
        .slot
        .path
        .join(operation.intent.path)
        .parent()
        .unwrap()
        .join("failure.json");
    let failure: ActualFailure = decode(&read_private(&failure_path).unwrap()).unwrap();
    assert_eq!(failure.replace_result, Some(false));
    assert_eq!(failure.phase, "replace");
    drop(a);
    drop(b);
    let before = TEST_NATIVE_CALLS.with(|v| v.get());
    assert_eq!(before, 1);
    cli_holds(&f, &f.desktop);
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), before);
    assert_eq!(fs::read(&target).unwrap(), f.original);
    assert!(intent.layout.original_backup.is_file());
    assert!(intent.layout.staged.is_file());
    assert!(!intent.layout.displaced_backup.exists());
}
#[test]
#[ignore = "read-only alias receiving for one explicitly named owned settled fixture"]
fn existing_received_fixture_case_and_available_short_aliases_select_same_slot() {
    let f = fixture("aliases");
    stage(&f);
    let mut window = Window::clean();
    let b = bound(&f);
    let reviewed = receive_review(&b, &f.review, "Fixture").unwrap();
    drop(prepare_apply(b, reviewed, None, &mut window).unwrap());
    let desktop = f.desktop;
    let b = BoundInstallation::open(&desktop).unwrap();
    let a = Authority::open(&b, false, false).unwrap();
    let slot = a.current.slot_id.clone();
    let object = b.exe.object.clone();
    drop(a);
    drop(b);
    let upper = PathBuf::from(desktop.to_str().unwrap().to_uppercase());
    let short = short_fixture_path(&desktop).unwrap();
    for alias in [&upper, &short] {
        let b = BoundInstallation::open(alias).unwrap();
        assert_eq!(b.exe.object, object);
        let a = Authority::open(&b, false, false).unwrap();
        assert_eq!(a.current.slot_id, slot);
    }
    eprintln!(
        "short_alias_allocated={}",
        short.as_os_str().encode_wide().any(|c| c == 126)
    );
}
#[test]
#[ignore = "requires exact owned C/D fixture parents and reviewed preimage"]
fn exact_not_called_resolution_and_partial_current_residue_are_distinct() {
    let f = fixture("resolution-before-native");
    stage(&f);
    let mut w = Window {
        calls: 0,
        fail_at: Some(3),
        ..Window::clean()
    };
    assert!(apply(&f, &mut w).is_err());
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 0);
    let (c, digest) = pending(&f);
    let op = c.active_operation.unwrap();
    let mut clean = Window::clean();
    assert!(recover(bound(&f), "wrong-operation", &digest, None, &mut clean).is_err());
    assert!(recover(bound(&f), &op.id, "wrong-current", None, &mut clean).is_err());
    let ns = f.local.join("state/AGUnlocker/wsl-installations");
    let slot = fs::read_dir(ns).unwrap().next().unwrap().unwrap().path();
    let intent: Intent = decode(&read_private(&slot.join(&op.intent.path)).unwrap()).unwrap();
    let operation_dir = slot.join(&op.intent.path).parent().unwrap().to_path_buf();
    let failure_path = operation_dir.join("failure.json");
    let original_failure = read_private(&failure_path).unwrap();
    // A successful-looking unreferenced result never changes receiving authority.
    write_private(&operation_dir.join("unreferenced-outcome.json"), b"{}").unwrap();
    assert_eq!(pending(&f).0.mode, Mode::Pending);
    recover(bound(&f), &op.id, &digest, None, &mut clean).unwrap();
    let (settled, _) = pending(&f);
    assert_eq!(settled.mode, Mode::SettledUnchanged);
    assert_eq!(read_private(&failure_path).unwrap(), original_failure);
    assert!(matches!(
        archive_install::observe(&intent.layout.staged),
        archive_install::FileObservation::Missing
    ));
    assert!(admit_run(bound(&f)).is_err());
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 0);
    let next = slot.join(format!("current.next.{}", settled.revision + 1));
    write_private(&next, b"{ partial metadata").unwrap();
    let b = bound(&f);
    assert!(Authority::open(&b, false, false)
        .err()
        .unwrap()
        .contains("RecoveryRequired"));
}
#[test]
#[ignore = "requires exact old CLI, copied reviewed Desktop exe, C/D parents and preimage"]
fn authentic_legacy_import_resolves_only_complete_proof_and_preserves_all_original_bytes() {
    use std::process::Command;
    let real_exe = required_path("AG_DESKTOP_FIXTURE_EXE");
    let cli = required_path("AG_LEGACY_CLI");
    let ps = required_path("AG_INSTALLATION_POWERSHELL");
    for path in [&real_exe, &cli, &ps] {
        CheckedPath::open(path, PathKind::File, PathPurpose::Executable).unwrap();
    }
    assert_eq!(hash(&fs::read(&cli).unwrap()), LEGACY_PRODUCER);
    for (name, missing_failure) in [
        ("legacy-positive-13", false),
        ("legacy-missing-proof-13", true),
    ] {
        let f = fixture(name);
        fs::copy(&real_exe, &f.desktop).unwrap();
        let parent_handle = OpenOptions::new()
            .access_mode(0x0006_0000)
            .share_mode(READ | WRITE)
            .custom_flags(OPEN_REPARSE | BACKUP_SEMANTICS)
            .open(f.review.parent().unwrap())
            .unwrap();
        super::context_tests::replace_owned_dacl(&parent_handle, "(A;OICI;0x1301ff;;;WD)");
        drop(parent_handle);
        let stage = Command::new(&cli)
            .args([
                OsStr::new("--stage"),
                OsStr::new("--desktop"),
                f.desktop.as_os_str(),
                OsStr::new("--distro"),
                OsStr::new("Fixture"),
                OsStr::new("--output"),
                f.review.as_os_str(),
            ])
            .output()
            .unwrap();
        assert!(
            stage.status.success(),
            "old stage failed: {}",
            String::from_utf8_lossy(&stage.stderr)
        );
        let apply = Command::new(&cli)
            .args([
                OsStr::new("--apply"),
                OsStr::new("--desktop"),
                f.desktop.as_os_str(),
                OsStr::new("--distro"),
                OsStr::new("Fixture"),
                OsStr::new("--output"),
                f.review.as_os_str(),
                OsStr::new("--powershell"),
                ps.as_os_str(),
                OsStr::new("--clean-start-window"),
                OsStr::new("--poll-ms"),
                OsStr::new("20"),
                OsStr::new("--probe-ms"),
                OsStr::new("15000"),
                OsStr::new("--probe-bytes"),
                OsStr::new("1048576"),
            ])
            .output()
            .unwrap();
        assert!(!apply.status.success());
        assert!(String::from_utf8_lossy(&apply.stderr)
            .contains("staging/recovery must share target volume"));
        let names = [
            "manifest.json",
            "app.asar.preimage",
            "app.asar.candidate",
            "apply-intent.json",
            "apply-failure.json",
        ];
        let before = names
            .iter()
            .map(|n| fs::read(f.review.join(n)).unwrap())
            .collect::<Vec<_>>();
        if missing_failure {
            let moved = f.review.with_file_name("retained-original-failure.json");
            fs::rename(f.review.join("apply-failure.json"), moved).unwrap();
        }
        let directory = CheckedPath::open(
            &f.review,
            PathKind::Directory,
            PathPurpose::ExternalLegacyInput,
        )
        .unwrap();
        assert!(existing_private(&directory.file).is_err());
        let original_acls = names
            .iter()
            .filter(|n| !(missing_failure && **n == "apply-failure.json"))
            .map(|n| {
                let p = CheckedPath::open(
                    &f.review.join(n),
                    PathKind::File,
                    PathPurpose::ExternalLegacyInput,
                )
                .unwrap();
                security(p.file.as_raw_handle(), 1 | 2 | 4).unwrap()
            })
            .collect::<Vec<_>>();
        drop(directory);
        let values = before.iter().map(|b| hash(b)).collect::<Vec<_>>();
        let expected = ExpectedLegacyAttempt::from_hex([
            &values[0], &values[1], &values[2], &values[3], &values[4],
        ])
        .unwrap();
        let mut window = Window::clean();
        if missing_failure {
            assert!(import_legacy(
                bound(&f),
                &f.review,
                "Fixture",
                &cli,
                &expected,
                &mut window
            )
            .is_err());
            assert!(!f.local.join("state/AGUnlocker").exists());
            assert_eq!(
                fs::read(f.review.with_file_name("retained-original-failure.json")).unwrap(),
                before[4]
            );
            for (index, name) in names.iter().enumerate().take(4) {
                assert_eq!(fs::read(f.review.join(name)).unwrap(), before[index]);
            }
            continue;
        }
        let mut wrong = expected.clone();
        wrong.digests[0] = "00".repeat(32);
        assert!(import_legacy(bound(&f), &f.review, "Fixture", &cli, &wrong, &mut window).is_err());
        assert!(!f.local.join("state/AGUnlocker").exists());
        let writer = OpenOptions::new()
            .write(true)
            .share_mode(READ | WRITE | DELETE)
            .open(f.review.join("apply-intent.json"))
            .unwrap();
        assert!(receive_legacy_input(&bound(&f), &f.review, "Fixture", &expected).is_err());
        drop(writer);
        assert!(!f.local.join("state/AGUnlocker").exists());
        let held = receive_legacy_input(&bound(&f), &f.review, "Fixture", &expected).unwrap();
        assert!(fs::rename(&f.review, f.review.with_file_name("forbidden-rename")).is_err());
        assert!(OpenOptions::new()
            .write(true)
            .open(f.review.join("apply-intent.json"))
            .is_err());
        held.recheck().unwrap();
        drop(held);
        let junction = f.review.with_file_name("reparse-selection");
        own_junction(&junction, &f.review);
        assert!(receive_legacy_input(&bound(&f), &junction, "Fixture", &expected).is_err());
        assert!(!f.local.join("state/AGUnlocker").exists());
        let drift_input =
            copy_external_input(f.review.parent().unwrap(), "degraded-source-copy", &before);
        let drift_state = f.local.join("degraded-state");
        create_private_dir(&drift_state).unwrap();
        TEST_BASE.with(|v| *v.borrow_mut() = Some(drift_state));
        let mut drifting = DriftingWindow {
            path: drift_input.join("apply-intent.json"),
            done: false,
        };
        let error = import_legacy(
            bound(&f),
            &drift_input,
            "Fixture",
            &cli,
            &expected,
            &mut drifting,
        )
        .unwrap_err();
        assert!(error.contains("after Pending"), "{error}");
        assert_eq!(pending(&f).0.mode, Mode::Pending);
        let mut forged = before.clone();
        let mut failure: serde_json::Value = serde_json::from_slice(&forged[4]).unwrap();
        failure["cause"] = "synthetic conflicting preflight result".into();
        forged[4] = json(&failure).unwrap();
        let forged_expected = expected_for(&forged);
        let forged_input = copy_external_input(
            f.review.parent().unwrap(),
            "conflicting-proof-copy",
            &forged,
        );
        let forged_state = f.local.join("conflicting-proof-state");
        create_private_dir(&forged_state).unwrap();
        TEST_BASE.with(|v| *v.borrow_mut() = Some(forged_state));
        import_legacy(
            bound(&f),
            &forged_input,
            "Fixture",
            &cli,
            &forged_expected,
            &mut window,
        )
        .unwrap();
        let (c, digest) = pending(&f);
        let op = c.active_operation.unwrap();
        assert!(recover(bound(&f), &op.id, &digest, None, &mut window).is_err());
        assert_eq!(pending(&f).0.mode, Mode::Pending);
        TEST_BASE.with(|v| *v.borrow_mut() = Some(f.local.join("state")));
        let imported = import_legacy(
            bound(&f),
            &f.review,
            "Fixture",
            &cli,
            &expected,
            &mut window,
        )
        .unwrap();
        assert!(imported.contains("canonical Pending"));
        let (c, digest) = pending(&f);
        let op = c.active_operation.unwrap();
        let result = recover(bound(&f), &op.id, &digest, None, &mut window);
        if missing_failure {
            assert!(result.is_err());
            assert_eq!(pending(&f).0.mode, Mode::Pending);
            assert!(
                fs::read(f.review.with_file_name("retained-original-failure.json")).unwrap()
                    == before[4]
            );
        } else {
            result.unwrap();
            assert_eq!(pending(&f).0.mode, Mode::SettledUnchanged);
        }
        for (index, name) in names.iter().enumerate() {
            if missing_failure && index == 4 {
                continue;
            }
            assert_eq!(fs::read(f.review.join(name)).unwrap(), before[index]);
        }
        for (i, name) in names.iter().enumerate() {
            let p = CheckedPath::open(
                &f.review.join(name),
                PathKind::File,
                PathPurpose::ExternalLegacyInput,
            )
            .unwrap();
            assert!(
                security(p.file.as_raw_handle(), 1 | 2 | 4).unwrap() == original_acls[i],
                "original legacy ACL changed"
            );
        }
        let strict = bound(&f);
        assert!(receive_review(&strict, &f.review, "Fixture").is_err());
        let fresh = f.review.with_file_name("fresh-private-review");
        stage_review(&strict, &fresh, "Fixture").unwrap();
        receive_review(&strict, &fresh, "Fixture").unwrap();
        assert_eq!(
            fs::read(f.desktop.parent().unwrap().join("resources/app.asar")).unwrap(),
            f.original
        );
        assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), 0);
    }
}
