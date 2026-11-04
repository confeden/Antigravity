//! Synthetic installation files only; the production native owner makes every receipt.
use super::*;

#[test]
#[ignore = "caller-selected vacant owned root; no production state"]
fn runtime_fixture_allocate() {
    let root = PathBuf::from(
        std::env::var_os("AG_RUNTIME_UPGRADE_FIXTURE_PARENT")
            .expect("explicit owned fixture parent"),
    );
    let parent = CheckedPath::open(
        root.parent().unwrap(),
        PathKind::Directory,
        PathPurpose::Review,
    )
    .unwrap();
    absent(&root).unwrap();
    create_private_dir(&root).unwrap();
    let received = CheckedPath::open(&root, PathKind::Directory, PathPurpose::Review).unwrap();
    private(&received.file).unwrap();
    write_private(
        &root.join("fixture-root-facts.json"),
        &json(&serde_json::json!({
            "schema":1, "kind":"owned-runtime-upgrade-fixture-parent", "nativeId":received.object,
            "callerParentNativeId":parent.object
        }))
        .unwrap(),
    )
    .unwrap();
}

struct Window;
impl MaintenanceWindow for Window {
    fn ensure_held(&mut self) -> Result<()> {
        Ok(())
    }
}

#[test]
fn vendor_runtime_choice_never_defaults_to_a_new_package() {
    #[derive(Deserialize)]
    struct LegacyChoice {
        #[serde(default)]
        runtime_input: VendorRuntimeRecord,
    }
    let legacy: LegacyChoice = serde_json::from_str("{}").unwrap();
    assert!(legacy.runtime_input.is_reuse());
    assert!(serde_json::from_str::<VendorRuntimeRecord>(r#"{"kind":"qualifiedPackage"}"#).is_err());
}

struct Fixture {
    root: PathBuf,
    desktop: PathBuf,
    original: Vec<u8>,
    host: CheckedPath,
    assets: PackageAssets,
}
impl Fixture {
    fn bound(&self) -> BoundInstallation {
        received_fixture_bound(&self.desktop).unwrap()
    }
    fn current(&self) -> (Current, String) {
        let authority = Authority::open(&self.bound(), false, true).unwrap();
        (authority.current.clone(), authority.digest.clone())
    }
    fn upgrade(&self) -> Result<()> {
        upgrade_runtime(
            self.bound(),
            &self.host,
            &hash(&self.host.read_snapshot().unwrap()),
            &self.assets,
            None,
            &mut Window,
        )
    }
    fn legacy_apply(&self) {
        let review = self.root.join("review");
        stage_review(&self.bound(), &review, "Fixture").unwrap();
        let bound = self.bound();
        let received = receive_review(&bound, &review, "Fixture").unwrap();
        prepare_apply(bound, received, None, &mut Window)
            .unwrap()
            .execute()
            .unwrap();
    }
    fn archive(&self) -> SourceSnapshot {
        read_path(&self.bound().archive.path, READ | DELETE).unwrap()
    }
    fn recover(&self) -> Result<String> {
        let (current, expected) = self.current();
        let id = &current.active_operation.as_ref().unwrap().id;
        super::super::recover(self.bound(), id, &expected, None, &mut Window)
    }
    fn rollback(&self) -> Result<()> {
        rollback_runtime(self.bound(), &self.current().1, None, &mut Window)
    }
}

fn replace_with_vendor_update(f: &Fixture) -> Vec<u8> {
    let input = PathBuf::from(std::env::var_os("AG_VENDOR_UPDATE_ARCHIVE_FIXTURE")
        .expect("explicit received new pristine archive fixture"));
    let bytes = CheckedPath::open(&input, PathKind::File, PathPurpose::Source).unwrap().read_snapshot().unwrap();
    assert_eq!(desktop_hook::inspect_archive(&bytes).unwrap().hook_status, desktop_hook::HookStatus::Prepared);
    fs::write(NativeFsPath::from_path(&f.desktop).unwrap().as_path(), b"MZ synthetic updated producer; never executed").unwrap();
    let archive = f.desktop.parent().unwrap().join("resources/app.asar");
    fs::write(NativeFsPath::from_path(&archive).unwrap().as_path(), &bytes).unwrap();
    bytes
}

#[test]
#[ignore = "owned qualified fixture, genuine context and explicit new pristine archive; real file replacements"]
fn vendor_reuse_rejects_different_or_missing_engine_before_window() {
    struct CountingWindow(usize);
    impl MaintenanceWindow for CountingWindow {
        fn ensure_held(&mut self) -> Result<()> { self.0 += 1; Ok(()) }
    }
    let f = fixture("vendor-update-engine-mismatch");
    f.upgrade().unwrap();
    let (_, prior_digest) = f.current();
    let original = replace_with_vendor_update(&f);
    let different = CheckedPath::open(&f.desktop, PathKind::File, PathPurpose::Executable).unwrap();
    let different_hash = hash(&different.read_snapshot().unwrap());
    let source_hash = hash(&f.host.read_snapshot().unwrap());
    assert_ne!(different_hash, source_hash);
    let calls = TEST_NATIVE_CALLS.with(|value| value.get());
    for (source, digest) in [(&different, different_hash.as_str()), (&f.host, "")] {
        let mut window = CountingWindow(0);
        let error = match prepare_vendor_update(&prior_digest, f.bound(), None,
            VendorRuntimeInput::ReuseReceivedRuntime { source, source_sha256: digest },
            None, &AtomicBool::new(false), &mut window) {
            Ok(_) => panic!("mismatched engine was admitted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("UpdatePending"));
        assert_eq!(window.0, 0);
        assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), calls);
        assert_eq!(f.archive().bytes, original);
        assert_eq!(hex::encode(observe_vendor_update(&f.bound()).unwrap().prior_current_sha256), prior_digest);
    }
}

#[test]
#[ignore = "owned qualified fixture, genuine context and explicit new pristine archive; real file replacements"]
fn vendor_reuse_rechecks_engine_before_execute_effects() {
    struct CountingWindow(usize);
    impl MaintenanceWindow for CountingWindow {
        fn ensure_held(&mut self) -> Result<()> { self.0 += 1; Ok(()) }
    }
    let f = fixture("vendor-update-engine-changed");
    f.upgrade().unwrap();
    let (_, prior_digest) = f.current();
    let original = replace_with_vendor_update(&f);
    let digest = hash(&f.host.read_snapshot().unwrap());
    let calls = TEST_NATIVE_CALLS.with(|value| value.get());
    let mut window = CountingWindow(0);
    let mut prepared = prepare_vendor_update(&prior_digest, f.bound(), None,
        VendorRuntimeInput::ReuseReceivedRuntime { source: &f.host, source_sha256: &digest },
        None, &AtomicBool::new(false), &mut window).unwrap();
    // Synthetic degraded operation input; the retained Windows source handle
    // intentionally prevents this test from replacing its bytes in place.
    prepared.runtime_input = VendorRuntimeInput::ReuseReceivedRuntime { source: &f.host, source_sha256: "" };
    assert!(prepared.execute(None, &AtomicBool::new(false)).is_err());
    assert_eq!(window.0, 1);
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), calls);
    assert_eq!(f.archive().bytes, original);
    assert_eq!(hex::encode(observe_vendor_update(&f.bound()).unwrap().prior_current_sha256), prior_digest);
}

#[test]
#[ignore = "owned qualified fixture, genuine context and explicit new pristine archive; real file replacements"]
fn vendor_update_receives_new_original_and_retains_runtime_custody() {
    let f = fixture("vendor-update");
    f.upgrade().unwrap();
    let (prior, prior_digest) = f.current();
    let prior_runtime = prior.runtime_deployment.received().unwrap().clone();
    let new_original = replace_with_vendor_update(&f);
    let observed = observe_vendor_update(&f.bound()).unwrap();
    assert_eq!(observed.slot_id, prior.slot_id);
    assert_eq!(hex::encode(observed.prior_current_sha256), prior_digest);
    let before = TEST_NATIVE_CALLS.with(|value| value.get());
    let source_sha256 = hash(&f.host.read_snapshot().unwrap());
    assert!(prepare_vendor_update(&"0".repeat(64), f.bound(), None, VendorRuntimeInput::ReuseReceivedRuntime { source: &f.host, source_sha256: &source_sha256 },
        None, &AtomicBool::new(false), &mut Window).is_err());
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), before);
    let mut window = Window;
    prepare_vendor_update(&prior_digest, f.bound(), None, VendorRuntimeInput::ReuseReceivedRuntime { source: &f.host, source_sha256: &source_sha256 },
        None, &AtomicBool::new(false), &mut window).unwrap().execute(None, &AtomicBool::new(false)).unwrap();
    let (current, _) = f.current();
    let actual = current.runtime_deployment.received().unwrap();
    assert_eq!(actual.host, prior_runtime.host);
    assert_eq!(actual.gate, prior_runtime.gate);
    assert_eq!(actual.gateway_rules, prior_runtime.gateway_rules);
    assert_ne!(actual.receipt, prior_runtime.receipt);
    assert_eq!(current.settled.as_ref().unwrap().applied.as_ref().unwrap().pre_digest, hash(&new_original));
    prepare_revert(f.bound(), None, &mut Window).unwrap().execute().unwrap();
    assert_eq!(f.archive().bytes, new_original);
}

#[test]
#[ignore = "owned qualified fixture, genuine context and explicit new pristine archive; real file replacements"]
fn vendor_update_qualified_package_stages_new_host_without_rules() {
    let f = fixture("vendor-update-package");
    f.upgrade().unwrap();
    let (prior, prior_digest) = f.current();
    let old = prior.runtime_deployment.received().unwrap().clone();
    let new_original = replace_with_vendor_update(&f);
    let source_hash = hash(&f.host.read_snapshot().unwrap());
    let mut window = Window;
    prepare_vendor_update(&prior_digest, f.bound(), None,
        VendorRuntimeInput::QualifiedPackage { source: &f.host, expected_host_sha256: &source_hash, assets: &f.assets, selection: None },
        None, &AtomicBool::new(false), &mut window).unwrap().execute(None, &AtomicBool::new(false)).unwrap();
    let (current, _) = f.current();
    let received = current.runtime_deployment.received().unwrap();
    assert_ne!(received.host.native_id, old.host.native_id);
    assert_eq!(received.host.sha256, source_hash);
    assert_eq!(received.gate, old.gate);
    assert_eq!(received.version, 1);
    assert!(received.gateway_rules.is_none());
    assert_eq!(current.settled.as_ref().unwrap().applied.as_ref().unwrap().pre_digest, hash(&new_original));
    prepare_revert(f.bound(), None, &mut Window).unwrap().execute().unwrap();
    assert_eq!(f.archive().bytes, new_original);
}

#[test]
#[ignore = "owned qualified fixture, genuine context and explicit new pristine archive; real file replacements"]
fn vendor_update_received_success_recovers_without_native_replay() {
    let f = fixture("vendor-update-recovery");
    f.upgrade().unwrap();
    let (_, prior_digest) = f.current();
    replace_with_vendor_update(&f);
    let source_sha256 = hash(&f.host.read_snapshot().unwrap());
    TEST_STOP_AFTER_RECEIPT.with(|value| value.set(Some("apply-v2")));
    let mut window = Window;
    assert!(prepare_vendor_update(&prior_digest, f.bound(), None, VendorRuntimeInput::ReuseReceivedRuntime { source: &f.host, source_sha256: &source_sha256 },
        None, &AtomicBool::new(false), &mut window).unwrap().execute(None, &AtomicBool::new(false)).is_err());
    let calls = TEST_NATIVE_CALLS.with(|value| value.get());
    f.recover().unwrap();
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), calls);
    assert_eq!(f.current().0.mode, Mode::SettledApplied);
}

#[test]
#[ignore = "owned qualified fixture, genuine context and explicit new pristine archive; real file replacements"]
fn vendor_update_lost_receipt_stays_pending_without_replay() {
    let f = fixture("vendor-update-lost-receipt");
    f.upgrade().unwrap();
    let (_, prior_digest) = f.current();
    replace_with_vendor_update(&f);
    let source_sha256 = hash(&f.host.read_snapshot().unwrap());
    TEST_LOSE_RECEIPT.with(|value| value.set(Some("apply-v2")));
    let mut window = Window;
    assert!(prepare_vendor_update(&prior_digest, f.bound(), None, VendorRuntimeInput::ReuseReceivedRuntime { source: &f.host, source_sha256: &source_sha256 },
        None, &AtomicBool::new(false), &mut window).unwrap().execute(None, &AtomicBool::new(false)).is_err());
    let calls = TEST_NATIVE_CALLS.with(|value| value.get());
    assert!(f.recover().is_err());
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), calls);
    assert_eq!(f.current().0.mode, Mode::Pending);
}

/// Test composition only. The fixture state root is intentionally injected, so
/// the real registration carrier is explicitly selected by the caller instead
/// of copying it into fixture storage or changing the production owner.
fn received_fixture_bound(desktop: &Path) -> Result<BoundInstallation> {
    let mut bound =
        BoundInstallation::open(desktop).map_err(|error| format!("fixture-open: {error}"))?;
    let context_path = PathBuf::from(
        std::env::var_os("AG_RUNTIME_UPGRADE_DEPLOYMENT_CONTEXT")
            .ok_or("fixture-context-input: explicit genuine registration path required")?,
    );
    let context = crate::windows_coordinator::windows_deployment::receive_for_installation(
        &bound,
        Some(&context_path),
    )
    .map_err(|error| format!("fixture-context-receive: {error}"))?
    .ok_or("fixture-context-receive: explicit registration was not received")?;
    bound
        .attach_ancestor_context(context)
        .map_err(|error| format!("fixture-context-attach: {error}"))?;
    Ok(bound)
}

#[test]
#[ignore = "owned qualified canonical fixture and genuine context input; synthetic files only"]
fn canonical_native_scope_writes_selected_ls_and_rejects_protected_aliases() {
    fn context(bound: &BoundInstallation) -> Result<Option<AncestorAccessContext>> {
        Ok(received_fixture_bound(bound.executable().as_path())?.ancestor_context)
    }
    let f = fixture("native-binary-scope");
    let install = f.desktop.parent().unwrap();
    let bin = install.join("resources/bin");
    create_private_dir(&bin).unwrap();
    let native = bin.join("language_server.exe");
    write_private(&native, b"synthetic native ineligible").unwrap();
    f.upgrade().unwrap();
    let before = f.archive();
    let before_current = f.current().1;
    let slot = Authority::open(&f.bound(), false, false).unwrap().slot.path;
    let current_path = slot.join("current.json");
    let current_before = read_path(&current_path, READ).unwrap();
    assert_eq!(before_current, current_before.digest);
    let reader = super::super::admit_runtime_read(f.bound(), "wsl-gui-v2").unwrap();
    let original_id = CheckedPath::open(&native, PathKind::File, PathPurpose::ReplaceSource).unwrap().object;
    let guard = super::super::admit_native_binary(&native, crate::patch_binary::binary_targets, context).unwrap();
    let staged = bin.join("selected-stage");
    write_private(&staged, b"synthetic native inexigible").unwrap();
    fs::rename(NativeFsPath::from_path(&staged).unwrap().as_path(), NativeFsPath::from_path(&native).unwrap().as_path()).unwrap();
    guard.recheck().unwrap();
    drop(guard);
    assert_eq!(fs::read(NativeFsPath::from_path(&native).unwrap().as_path()).unwrap(), b"synthetic native inexigible");
    let actual_id = CheckedPath::open(&native, PathKind::File, PathPurpose::ReplaceSource).unwrap().object;
    assert_ne!(actual_id, original_id);
    let js = crate::patch_ide::js_targets(install).ide_main;
    create_private_dir(js.parent().unwrap().parent().unwrap()).unwrap();
    create_private_dir(js.parent().unwrap()).unwrap();
    write_private(&js, b"synthetic JS").unwrap();
    let js_before = read_path(&js, READ | DELETE).unwrap();
    assert!(super::super::admit_native_binary(&js, crate::patch_binary::binary_targets, context).is_err());
    let shadow_error = received_fixture_bound(&f.desktop).err().expect("JS fixture must retain the Desktop shadow hold");
    assert!(shadow_error.contains("shadow conflict"));
    let runtime = reader.host().as_path().to_owned();
    drop(reader);
    let protected = [("desktop", f.desktop.clone()), ("archive", install.join("resources/app.asar")),
        ("runtime", runtime), ("gate", slot.join("runtime-gate")), ("js", js.clone())];
    let mut rejected = Vec::new();
    for (name, source) in protected {
        let alias = bin.join(format!("language_server_{name}.exe"));
        fs::hard_link(NativeFsPath::from_path(&source).unwrap().as_path(), NativeFsPath::from_path(&alias).unwrap().as_path()).unwrap();
        let denied = super::super::admit_native_binary(&alias, crate::patch_binary::binary_targets, context).is_err();
        fs::remove_file(NativeFsPath::from_path(&alias).unwrap().as_path()).unwrap();
        assert!(denied, "protected native alias must be rejected: {name}");
        rejected.push(name);
    }
    // The intentionally introduced JS shadow prevents fresh Desktop run/
    // maintenance admission. Observe the already bound persisted objects;
    // do not weaken that production hold just to read the test oracle.
    let after = read_path(&install.join("resources/app.asar"), READ | DELETE).unwrap();
    assert_eq!(before.bytes, after.bytes);
    assert_eq!(before.identity, after.identity);
    let current_after = read_path(&current_path, READ).unwrap();
    assert_eq!(current_before.bytes, current_after.bytes);
    assert_eq!(current_before.identity, current_after.identity);
    let js_after = read_path(&js, READ | DELETE).unwrap();
    assert_eq!(js_before.identity, js_after.identity);
    assert_eq!(js_before.bytes, js_after.bytes);
    write_private(&f.root.join("native-scope-result.json"), &json(&serde_json::json!({
        "schema":1, "kind":"non-authorizing-owned-native-scope-proof", "selectedNativeWriteReceived":true,
        "runtimeReaderHeld":true, "originalNativeId":original_id, "actualNativeId":actual_id,
        "rejectedAliases":rejected, "archiveBytesAndMetadataUnchanged":true, "jsBytesAndMetadataUnchanged":true,
        "currentUnchanged":true, "jsShadowMaintenanceHoldReceived":true
    })).unwrap()).unwrap();
}

#[test]
#[ignore = "one admitted genuine-context receiving probe; no maintenance or native replacement"]
fn runtime_saved_context_pre_admission_probe() {
    let fixture = fixture("saved-context-admission");
    let archive_path = fixture.desktop.parent().unwrap().join("resources/app.asar");
    let before = read_path(&archive_path, READ | DELETE).unwrap();
    let state = fixture.root.join("state");
    assert_eq!(fs::read_dir(&state).unwrap().count(), 0);
    let (stage, received) = match received_fixture_bound(&fixture.desktop) {
        Ok(bound) => (
            "runtime-installed-admission",
            runtime_installed(&bound).and_then(|installed| {
                if installed {
                    Err("fixture unexpectedly reports an installed runtime".into())
                } else {
                    Ok(())
                }
            }),
        ),
        Err(error) => ("fixture-bound-context-composition", Err(error)),
    };
    let after = read_path(&archive_path, READ | DELETE).unwrap();
    let no_native_calls = TEST_NATIVE_CALLS.with(|value| value.get()) == 0;
    let archive_unchanged = before.identity == after.identity
        && before.digest == after.digest
        && before.bytes == after.bytes;
    let state_empty = fs::read_dir(&state).unwrap().next().is_none();
    let facts = serde_json::json!({
        "schema":1, "kind":"non-authorizing-genuine-context-fixture-admission",
        "stage":stage, "publicReceiverSucceeded":received.is_ok(), "publicReceiverError":received.as_ref().err(),
        "zeroNativeArchiveCalls":no_native_calls, "archiveUnchanged":archive_unchanged, "fixtureStateEmpty":state_empty
    });
    write_private(
        &fixture.root.join("admission-probe-result.json"),
        &json(&facts).unwrap(),
    )
    .unwrap();
    eprintln!("genuine-context fixture admission stage={stage}; success={}; zeroNativeArchiveCalls={no_native_calls}; archiveUnchanged={archive_unchanged}; fixtureStateEmpty={state_empty}", received.is_ok());
    assert!(no_native_calls && archive_unchanged && state_empty);
    received.unwrap();
}

fn fixture(name: &str) -> Fixture {
    // Both paths are caller inputs. There is no production state-root switch.
    let parent = PathBuf::from(
        std::env::var_os("AG_RUNTIME_UPGRADE_FIXTURE_PARENT")
            .expect("explicit owned fixture parent"),
    );
    let input = PathBuf::from(
        std::env::var_os("AG_ARCHIVE_INSTALL_FIXTURE").expect("received pristine archive fixture"),
    );
    let parent = CheckedPath::open(&parent, PathKind::Directory, PathPurpose::Review).unwrap();
    private(&parent.file).unwrap();
    let original = CheckedPath::open(&input, PathKind::File, PathPurpose::Source)
        .unwrap()
        .read_snapshot()
        .unwrap();
    desktop_hook::prepare_archive(&original).unwrap();
    let root = parent.path.join(format!("{name}-{}", unique_id().unwrap()));
    absent(&root).unwrap();
    create_private_dir(&root).unwrap();
    let pin = CheckedPath::open(&root, PathKind::Directory, PathPurpose::Review).unwrap();
    write_private(&root.join("fixture-root-facts.json"), &json(&serde_json::json!({
        "schema":1, "kind":"owned-runtime-upgrade-fixture", "nativeId":pin.object, "callerParentNativeId":parent.object
    })).unwrap()).unwrap();
    let state = root.join("state");
    create_private_dir(&state).unwrap();
    TEST_BASE.with(|value| *value.borrow_mut() = Some(state));
    TEST_NATIVE_CALLS.with(|value| value.set(0));
    TEST_STOP_AFTER_RECEIPT.with(|value| value.set(None));
    TEST_LOSE_RECEIPT.with(|value| value.set(None));
    let install = root.join("Desktop");
    create_private_dir(&install).unwrap();
    create_private_dir(&install.join("resources")).unwrap();
    let desktop = install.join("Antigravity.exe");
    write_private(&desktop, b"MZ synthetic producer; never executed").unwrap();
    let target = install.join("resources/app.asar");
    write_private(&target, &original).unwrap();
    initialize_inherited_fixture(&target).unwrap();
    let package = root.join("package");
    create_private_dir(&package).unwrap();
    write_private(
        &package.join("ag_unlocker.exe"),
        b"MZ synthetic host; never executed",
    )
    .unwrap();
    let helper = b"synthetic Linux helper; never executed";
    write_private(&package.join("ag_wsl_launch"), helper).unwrap();
    write_private(&package.join("helper.sha256"), hash(helper).as_bytes()).unwrap();
    write_private(
        &package.join("install-helper.sh"),
        include_bytes!("../../../wsl/install-helper.sh"),
    )
    .unwrap();
    let host = CheckedPath::open(
        &package.join("ag_unlocker.exe"),
        PathKind::File,
        PathPurpose::Executable,
    )
    .unwrap();
    let assets = PackageAssets::receive(&host, Some(&hash(helper))).unwrap();
    Fixture {
        root,
        desktop,
        original,
        host,
        assets,
    }
}

#[test]
#[ignore = "explicit confined fixture parent and received pristine input; real file replacements"]
fn runtime_fresh_apply_user_revert_and_reapply_use_ultimate_original() {
    let f = fixture("fresh");
    assert!(!runtime_installed(&f.bound()).unwrap());
    f.upgrade().unwrap();
    assert!(runtime_installed(&f.bound()).unwrap());
    let first = f.current().0;
    assert_eq!(first.schema, 3);
    let record = first.settled.as_ref().unwrap().applied.as_ref().unwrap();
    assert_eq!(record.pre_digest, hash(&f.original));
    prepare_revert(f.bound(), None, &mut Window)
        .unwrap()
        .execute()
        .unwrap();
    assert_eq!(f.archive().bytes, f.original);
    assert!(!runtime_installed(&f.bound()).unwrap());
    f.upgrade().unwrap();
    assert!(runtime_installed(&f.bound()).unwrap());
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), 3);
}

#[test]
#[ignore = "explicit confined fixture parent and received pristine input; real file replacements"]
fn runtime_legacy_upgrade_keeps_prior_bytes_and_user_revert_is_ultimate() {
    let f = fixture("legacy-upgrade");
    f.legacy_apply();
    let authority = Authority::open(&f.bound(), false, false).unwrap();
    let prior = json(&authority.current).unwrap();
    let old_record = authority
        .current
        .settled
        .as_ref()
        .unwrap()
        .applied
        .as_ref()
        .unwrap()
        .clone();
    let old_evidence = reference(
        &authority.slot,
        &authority.current.settled.as_ref().unwrap().evidence,
    )
    .unwrap();
    let old_original = read_path(&old_record.original_backup, READ).unwrap();
    drop(authority);
    f.upgrade().unwrap();
    let authority = Authority::open(&f.bound(), false, false).unwrap();
    let current = &authority.current;
    let settlement: Settlement =
        decode(&reference(&authority.slot, &current.settled.as_ref().unwrap().evidence).unwrap())
            .unwrap();
    let intent_ref = match settlement {
        Settlement::RuntimeUpgrade(UpgradeOutcome::Applied { intent, .. }) => intent,
        _ => panic!("actual upgrade receipt absent"),
    };
    let intent = receive_intent(&authority.slot, &intent_ref).unwrap();
    assert_eq!(
        reference(&authority.slot, &intent.prior_current).unwrap(),
        prior
    );
    let old_current: Current = decode(&prior).unwrap();
    assert_eq!(
        reference(&authority.slot, &old_current.settled.unwrap().evidence).unwrap(),
        old_evidence
    );
    assert_eq!(
        read_path(&old_record.original_backup, READ)
            .unwrap()
            .identity,
        old_original.identity
    );
    assert_eq!(
        read_path(&old_record.original_backup, READ).unwrap().bytes,
        old_original.bytes
    );
    let new = current.settled.as_ref().unwrap().applied.as_ref().unwrap();
    assert_eq!(new.pre_digest, hash(&f.original));
    assert_ne!(new.post_digest, old_record.post_digest);
    drop(authority);
    prepare_revert(f.bound(), None, &mut Window)
        .unwrap()
        .execute()
        .unwrap();
    assert_eq!(f.archive().bytes, f.original);
}

#[test]
#[ignore = "explicit confined fixture parent and received pristine input; real file replacements"]
fn runtime_rollback_v2_receives_a_new_v1_record_and_native_identity() {
    let f = fixture("rollback-v2");
    f.legacy_apply();
    let old = f.current().0;
    let old_bytes = f.archive().bytes;
    f.upgrade().unwrap();
    f.rollback().unwrap();
    let restored = f.current().0;
    assert_eq!(restored.schema, 3);
    assert_eq!(restored.mode, Mode::SettledApplied);
    assert!(matches!(
        restored.runtime_deployment,
        DeploymentField::Present(None)
    ));
    assert_ne!(restored.binding.archive, old.binding.archive);
    let new_record = restored.settled.as_ref().unwrap().applied.as_ref().unwrap();
    let old_record = old.settled.as_ref().unwrap().applied.as_ref().unwrap();
    assert_ne!(new_record.post, old_record.post);
    assert_ne!(new_record.original_backup, old_record.original_backup);
    assert_eq!(f.archive().bytes, old_bytes);
    assert!(!runtime_installed(&f.bound()).unwrap());
    prepare_revert(f.bound(), None, &mut Window)
        .unwrap()
        .execute()
        .unwrap();
    assert_eq!(f.archive().bytes, f.original);
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), 6);
}

#[test]
#[ignore = "explicit confined fixture parent and received pristine input; real file replacements"]
fn runtime_restart_after_pristine_receipt_continues_without_replaying_v1_revert() {
    let f = fixture("restart-pristine");
    f.legacy_apply();
    TEST_STOP_AFTER_RECEIPT.with(|value| value.set(Some("revert-v1")));
    assert!(f
        .upgrade()
        .unwrap_err()
        .contains("durable actual native receipt"));
    assert_eq!(f.current().0.mode, Mode::Pending);
    assert_eq!(f.archive().bytes, f.original);
    assert!(admit_runtime_read(f.bound(), "wsl-gui-v2").is_err());
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), 2);
    f.recover().unwrap();
    assert!(runtime_installed(&f.bound()).unwrap());
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), 3);
}

#[test]
#[ignore = "explicit confined fixture parent and received pristine input; real file replacements"]
fn runtime_rollback_from_received_pristine_creates_real_v1_apply() {
    let f = fixture("rollback-pristine");
    f.legacy_apply();
    let old = f.current().0;
    let old_bytes = f.archive().bytes;
    TEST_STOP_AFTER_RECEIPT.with(|value| value.set(Some("revert-v1")));
    assert!(f.upgrade().is_err());
    f.rollback().unwrap();
    assert_eq!(f.archive().bytes, old_bytes);
    assert_ne!(f.current().0.binding.archive, old.binding.archive);
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), 3);
    assert!(!runtime_installed(&f.bound()).unwrap());
}

#[test]
#[ignore = "explicit confined fixture parent and received pristine input; real file replacements"]
fn runtime_restart_after_v2_receipt_publishes_without_any_new_native_call() {
    let f = fixture("restart-v2");
    f.legacy_apply();
    TEST_STOP_AFTER_RECEIPT.with(|value| value.set(Some("apply-v2")));
    assert!(f.upgrade().is_err());
    assert_eq!(f.current().0.mode, Mode::Pending);
    let before = TEST_NATIVE_CALLS.with(|value| value.get());
    f.recover().unwrap();
    assert!(runtime_installed(&f.bound()).unwrap());
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), before);
}

#[test]
#[ignore = "explicit confined fixture parent and received pristine input; real file replacements"]
fn runtime_lost_native_receipt_stays_exact_pending_without_replay_or_rollback() {
    let f = fixture("lost-v2-result");
    f.legacy_apply();
    TEST_LOSE_RECEIPT.with(|value| value.set(Some("apply-v2")));
    assert!(f.upgrade().unwrap_err().contains("capture loss"));
    let before = f.current();
    let calls = TEST_NATIVE_CALLS.with(|value| value.get());
    assert!(f.recover().is_err());
    assert!(f.rollback().is_err());
    assert_eq!(f.current().1, before.1);
    assert_eq!(f.current().0.mode, Mode::Pending);
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), calls);
    assert!(runtime_installed(&f.bound()).is_err());
}

#[test]
#[ignore = "explicit confined fixture parent and received pristine input; real file replacements"]
fn runtime_rollback_restart_uses_its_kind_specific_receipts() {
    let f = fixture("restart-rollback");
    f.legacy_apply();
    f.upgrade().unwrap();
    TEST_STOP_AFTER_RECEIPT.with(|value| value.set(Some("revert-v2")));
    assert!(f.rollback().is_err());
    assert_eq!(
        f.current().0.active_operation.as_ref().unwrap().kind,
        OperationKind::RollbackRuntime
    );
    let before = TEST_NATIVE_CALLS.with(|value| value.get());
    f.recover().unwrap();
    assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), before + 1);
    assert!(!runtime_installed(&f.bound()).unwrap());
}
