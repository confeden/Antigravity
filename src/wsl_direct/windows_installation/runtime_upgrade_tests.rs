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

// Pure wire/field guards use invented in-memory identities, never native call
// evidence or a production Current. Actual failure fixtures below use the owner.
fn synthetic_group_sd(group: u32) -> Vec<u8> {
    let sid = |value: u32| { let mut sid = vec![1, 1, 0, 0, 0, 0, 0, 5]; sid.extend_from_slice(&value.to_le_bytes()); sid };
    let mut sd = vec![1, 0, 4, 128];
    for offset in [20u32, 32, 0, 44] { sd.extend_from_slice(&offset.to_le_bytes()); }
    sd.extend(sid(17)); sd.extend(sid(group));
    sd.extend([2, 0, 8, 0, 0, 0, 0, 0]);
    sd
}
#[test]
fn group_resolution_post_fields_use_failed_index_and_candidate_size_not_source() {
    let source = TargetState { digest: hash(b"old"), metadata: FileIdentity { volume: 1, index: 3, size: 3,
        attributes: 32, creation: 8, write: 9, security_descriptor: synthetic_group_sd(17) } };
    let candidate = b"patched-longer";
    let mut failed = source.clone();
    failed.digest = hash(candidate); failed.metadata.index = 7; failed.metadata.size = candidate.len() as u64;
    failed.metadata.security_descriptor = synthetic_group_sd(18);
    assert!(post_fields(&failed, &failed, &source, candidate));
    for field in ["index", "size", "digest", "volume", "attributes", "creation", "write"] {
        let mut altered = failed.clone();
        match field {
            "index" => altered.metadata.index = source.metadata.index,
            "size" => altered.metadata.size = source.metadata.size,
            "digest" => altered.digest = source.digest.clone(),
            "volume" => altered.metadata.volume += 1,
            "attributes" => altered.metadata.attributes ^= 1,
            "creation" => altered.metadata.creation += 1,
            "write" => altered.metadata.write += 1,
            _ => unreachable!(),
        }
        assert!(!post_fields(&altered, &failed, &source, candidate), "{field}");
    }
    let mut desired = failed.clone(); desired.metadata.security_descriptor = source.metadata.security_descriptor.clone();
    assert!(post_fields(&desired, &failed, &source, candidate));
    let actor = &source.metadata.security_descriptor[20..32];
    assert!(!native::receive_group_metadata(&failed.metadata.security_descriptor, &failed.metadata.security_descriptor, &source.metadata.security_descriptor, actor).unwrap());
    assert!(native::receive_group_metadata(&desired.metadata.security_descriptor, &failed.metadata.security_descriptor, &source.metadata.security_descriptor, actor).unwrap());
    let third_group = synthetic_group_sd(19);
    let mut control = synthetic_group_sd(18); control[2] ^= 0x10;
    let mut owner = synthetic_group_sd(18); owner[28] ^= 1;
    let mut dacl = synthetic_group_sd(18); dacl[45] ^= 1;
    for sd in [third_group, control, owner, dacl] {
        assert!(native::receive_group_metadata(&sd, &failed.metadata.security_descriptor, &source.metadata.security_descriptor, actor).is_err());
    }
    for size in [0, 19, 27, 43, 51] {
        assert!(native::receive_group_metadata(&synthetic_group_sd(18)[..size], &failed.metadata.security_descriptor,
            &source.metadata.security_descriptor, actor).is_err());
    }
    let mut invalid = synthetic_group_sd(18); invalid[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(native::receive_group_metadata(&invalid, &failed.metadata.security_descriptor, &source.metadata.security_descriptor, actor).is_err());
    assert!(native::receive_group_metadata(&failed.metadata.security_descriptor, &failed.metadata.security_descriptor,
        &synthetic_group_sd(18), actor).is_err());
}
#[test]
fn group_unknown_and_returned_codes_never_admit_another_call() {
    assert!(group_call_can_follow(None).unwrap_err().contains("Unknown"));
    for win_error in [0, 5] { assert!(group_call_can_follow(Some(&GroupCallStatus::Returned { win_error })).unwrap_err().contains("no repeat")); }
    assert!(group_call_can_follow(Some(&GroupCallStatus::NotCalled { cause: String::new() })).is_err());
    group_call_can_follow(Some(&GroupCallStatus::NotCalled { cause: "actual access denied before native call".into() })).unwrap();
}

#[test]
fn group_private_wire_is_closed_required_nullable_and_does_not_decode_as_native_success() {
    let reference = EvidenceRef { path: "operation/input.json".into(), digest: "a".repeat(64) };
    let target = TargetState { digest: "b".repeat(64), metadata: FileIdentity { volume: 1, index: 4, size: 3,
        attributes: 32, creation: 8, write: 9, security_descriptor: synthetic_group_sd(18) } };
    let call = GroupCallIntentV1 { schema: 1, kind: GroupFrameKind::GroupCallIntent, resolution_intent: reference.clone(),
        ordinal: 1, previous_not_called: None, pre_call: GroupObject { target, native_id: ObjectId { volume: 1, file: [2; 16] } } };
    let value = serde_json::to_value(&call).unwrap();
    assert!(value.get("previousNotCalled").unwrap().is_null());
    for field in ["kind", "resolutionIntent", "ordinal", "previousNotCalled", "preCall"] {
        let mut missing = value.clone(); missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<GroupCallIntentV1>(missing).is_err(), "{field}");
    }
    let mut unknown = value.clone(); unknown["consent"] = true.into();
    assert!(serde_json::from_value::<GroupCallIntentV1>(unknown).is_err());
    let mut unknown_kind = value; unknown_kind["kind"] = "unrecognized".into();
    assert!(serde_json::from_value::<GroupCallIntentV1>(unknown_kind).is_err());
    assert!(decode::<StepOutcome>(&json(&call).unwrap()).is_err());
    for status in [GroupCallStatus::NotCalled { cause: "actual pre-call denial".into() }, GroupCallStatus::Returned { win_error: 5 }] {
        let result = GroupCallResultV1 { schema: 1, kind: GroupFrameKind::GroupCallResult, call_intent: reference.clone(), outcome: status };
        let mut value = serde_json::to_value(&result).unwrap(); value["outcome"]["unknown"] = true.into();
        assert!(serde_json::from_value::<GroupCallResultV1>(value).is_err());
    }
    let real_failure_shape = serde_json::json!({"phase":"metadata-preservation", "cause":"retained cause", "replace_result":true,
        "recovery":{"target":["synthetic", "Missing"], "staged":null, "original_backup":null, "displaced_backup":null}});
    let actual: ActualFailure = serde_json::from_value(real_failure_shape.clone()).unwrap();
    assert_eq!(actual.replace_result, Some(true));
    assert!(known_vendor_group_failure(&actual));
    for result in [serde_json::Value::Null, false.into()] {
        let mut wrong = real_failure_shape.clone(); wrong["replace_result"] = result;
        assert!(!known_vendor_group_failure(&serde_json::from_value::<ActualFailure>(wrong).unwrap()));
    }
    let mut wrong = real_failure_shape.clone(); wrong["phase"] = "readback".into();
    assert!(!known_vendor_group_failure(&serde_json::from_value::<ActualFailure>(wrong).unwrap()));
    let mut missing = real_failure_shape; missing.as_object_mut().unwrap().remove("replace_result");
    assert!(serde_json::from_value::<ActualFailure>(missing).is_err());
}

fn vendor_group_failure(name: &str) -> Fixture {
    let f = fixture(name);
    native::initialize_token_group_fixture(&f.desktop.parent().unwrap().join("resources/app.asar")).unwrap();
    f.upgrade().unwrap();
    let (_, prior_digest) = f.current();
    replace_with_vendor_update(&f);
    native::TEST_GROUP_CALLS.with(|v| v.set(0));
    TEST_GROUP_STOP.with(|v| v.set(None));
    archive_install::TEST_WRONG_GROUP_STAGE.with(|v| v.set(true));
    let digest = hash(&f.host.read_snapshot().unwrap());
    let mut window = Window;
    let error = prepare_vendor_update(&prior_digest, f.bound(), None,
        VendorRuntimeInput::ReuseReceivedRuntime { source: &f.host, source_sha256: &digest }, None,
        &AtomicBool::new(false), &mut window).unwrap().execute(None, &AtomicBool::new(false)).err()
        .expect("wrong-group fixture must return its actual strict metadata failure");
    assert!(error.contains("metadata-preservation"), "actual OS fixture did not produce the admitted failure: {error}");
    let authority = Authority::open(&f.bound(), false, true).unwrap();
    let op = authority.current.active_operation.as_ref().unwrap();
    let vendor = receive_vendor_intent(&authority.slot, &op.intent).unwrap();
    let input = receive_group_failure(&authority.slot, &op.intent, &vendor).unwrap();
    assert_ne!(input.step.source.metadata.index, input.postimage.metadata.index);
    assert_ne!(input.step.source.metadata.size, input.postimage.metadata.size);
    assert_eq!(object_state(&f.archive()), input.postimage);
    drop(authority);
    assert!(matches!(observe_apply_current(&f.bound()).unwrap(), ApplyCurrentObservation::VendorPending(_)));
    f
}

#[test]
#[ignore = "explicit owned canonical fixture, genuine context and new pristine archive; real ReplaceFileW and group-only API"]
fn vendor_group_recovery_settles_real_failed_postimage_and_preserves_old_failure() {
    let f = vendor_group_failure("vendor-group-settle");
    let archive_calls = TEST_NATIVE_CALLS.with(|v| v.get());
    let before = f.archive();
    let authority = Authority::open(&f.bound(), false, true).unwrap();
    let op = authority.current.active_operation.as_ref().unwrap().clone();
    let dir = operation_dir(&authority.slot, &op.intent).unwrap();
    let failure = read_private(&dir.join("apply-v2-failure.json")).unwrap();
    drop(authority);
    assert!(f.recover().unwrap().contains("RecoverySettled"));
    assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 1);
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), archive_calls);
    let after = f.archive();
    assert_eq!(before.bytes, after.bytes); assert_eq!(before.identity.index, after.identity.index); assert_eq!(before.identity.size, after.identity.size);
    let authority = Authority::open(&f.bound(), false, false).unwrap();
    assert_eq!(authority.current.mode, Mode::SettledApplied);
    assert_eq!(authority.current.binding.archive_metadata, after.identity);
    assert_eq!(authority.current.binding.archive_digest, after.digest);
    assert_eq!(read_private(&dir.join("apply-v2-failure.json")).unwrap(), failure);
    assert!(optional_reference(&authority.slot, &dir.join("apply-v2-outcome.json")).unwrap().is_none());
    let proof = optional_reference(&authority.slot, &dir.join("group-metadata-resolution.json")).unwrap().unwrap();
    assert!(receive_step(&authority.slot, &proof, &op.id, "apply-v2").is_err(), "old success-only receiver must fail closed");
    let result: VendorGroupMetadataResolutionV1 = decode(&reference(&authority.slot, &proof).unwrap()).unwrap();
    assert!(matches!(result.proof, GroupResolutionProof::ReturnedAndVerified { .. }));
    assert_eq!(result.applied.post, after.identity);
    assert_eq!(result.applied.original_backup_identity, read_path(&result.applied.original_backup, READ).unwrap().identity);
    assert_eq!(result.applied.displaced_identity, read_path(&result.applied.displaced_backup, READ).unwrap().identity);
    assert!(receive_vendor_apply(&authority.slot, &result.failure, &op.intent, &receive_vendor_intent(&authority.slot, &op.intent).unwrap()).is_err());
}

#[test]
#[ignore = "explicit owned canonical fixture and genuine context; actual failed replacement, no group replay"]
fn vendor_group_unknown_intent_holds_without_native_or_archive_replay() {
    let f = vendor_group_failure("vendor-group-unknown");
    TEST_GROUP_STOP.with(|v| v.set(Some("after-intent")));
    assert!(f.recover().unwrap_err().contains("after-intent"));
    let calls = TEST_NATIVE_CALLS.with(|v| v.get());
    assert!(f.recover().unwrap_err().contains("Unknown"));
    assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 0);
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), calls);
    assert_eq!(f.current().0.mode, Mode::Pending);
}

#[test]
#[ignore = "explicit owned canonical fixture and genuine context; actual group call, result/capture/publication interruption"]
fn vendor_group_acquired_result_and_observed_convergence_never_repeat_call() {
    for stage in ["after-native-before-result", "after-result", "after-resolution", "before-publish", "after-publish"] {
        let f = vendor_group_failure(&format!("vendor-group-{stage}"));
        let calls = TEST_NATIVE_CALLS.with(|v| v.get());
        TEST_GROUP_STOP.with(|v| v.set(Some(stage)));
        let error = f.recover().unwrap_err();
        assert!(error.contains(stage));
        assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 1);
        if stage != "after-publish" { f.recover().unwrap(); }
        assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 1);
        assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), calls);
        assert_eq!(f.current().0.mode, Mode::SettledApplied);
        if matches!(stage, "after-native-before-result" | "after-result") {
            let authority = Authority::open(&f.bound(), false, false).unwrap();
            let settlement: Settlement = decode(&reference(&authority.slot, &authority.current.settled.as_ref().unwrap().evidence).unwrap()).unwrap();
            let Settlement::VendorUpdate(outcome) = settlement else { panic!("vendor settlement required") };
            let resolved: VendorGroupMetadataResolutionV1 = decode(&reference(&authority.slot, &outcome.step).unwrap()).unwrap();
            assert!(matches!(resolved.proof, GroupResolutionProof::ObservedDesired { .. }));
            assert_eq!(resolved.attempts.len(), 1);
            if stage == "after-native-before-result" { assert!(resolved.attempts[0].result.is_none()); }
        }
    }
}

#[test]
#[ignore = "explicit owned canonical fixture and genuine context; positive NotCalled then distinct later Recover"]
fn vendor_group_not_called_admits_only_a_later_distinct_attempt() {
    let f = vendor_group_failure("vendor-group-not-called");
    let calls = TEST_NATIVE_CALLS.with(|v| v.get());
    TEST_GROUP_STOP.with(|v| v.set(Some("before-call")));
    assert!(f.recover().unwrap_err().contains("NotCalled"));
    assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 0);
    f.recover().unwrap();
    assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 1);
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), calls);
    let authority = Authority::open(&f.bound(), false, false).unwrap();
    let settlement: Settlement = decode(&reference(&authority.slot, &authority.current.settled.as_ref().unwrap().evidence).unwrap()).unwrap();
    let Settlement::VendorUpdate(outcome) = settlement else { panic!("vendor settlement required") };
    let resolved: VendorGroupMetadataResolutionV1 = decode(&reference(&authority.slot, &outcome.step).unwrap()).unwrap();
    assert_eq!(resolved.attempts.len(), 2);
    let second: GroupCallIntentV1 = decode(&reference(&authority.slot, &resolved.attempts[1].intent).unwrap()).unwrap();
    assert_eq!(second.previous_not_called, resolved.attempts[0].result);
}

#[test]
#[ignore = "explicit owned canonical fixture and genuine context; inject persistence failure after real native success"]
fn vendor_group_persistence_failure_retains_acquired_return_and_can_only_observe() {
    for stage in ["save:group-call-1-result.json", "save:group-call-1-readback.json", "save:group-metadata-resolution.json"] {
        let f = vendor_group_failure(&format!("vendor-group-persistence-{}", stage.replace(':', "-")));
        let calls = TEST_NATIVE_CALLS.with(|v| v.get());
        TEST_GROUP_STOP.with(|v| v.set(Some(stage)));
        let error = f.recover().unwrap_err();
        assert!(error.contains(stage));
        if stage.ends_with("-result.json") || stage.ends_with("-readback.json") { assert!(error.contains("win_error: 0"), "acquired native status must survive: {error}"); }
        assert_eq!(f.current().0.mode, Mode::Pending);
        assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 1);
        f.recover().unwrap();
        assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 1);
        assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), calls);
    }
}

#[test]
#[ignore = "explicit owned canonical fixture and genuine context; malformed private fixture evidence never native authority"]
fn vendor_group_corrupt_terminal_and_lineage_holes_hold_without_replay() {
    for name in ["group-call-1-result.json", "group-call-3-intent.json", "group-call-01-result.json"] {
        let f = vendor_group_failure("vendor-group-corrupt");
        TEST_GROUP_STOP.with(|v| v.set(Some("after-intent")));
        f.recover().unwrap_err();
        let authority = Authority::open(&f.bound(), false, true).unwrap();
        let op = authority.current.active_operation.as_ref().unwrap();
        let dir = operation_dir(&authority.slot, &op.intent).unwrap();
        // Deliberately malformed data only, never a forged native terminal.
        write_private(&dir.join(name), b"{").unwrap();
        drop(authority);
        let calls = TEST_NATIVE_CALLS.with(|v| v.get());
        assert!(f.recover().is_err());
        assert_eq!(f.current().0.mode, Mode::Pending);
        assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 0);
        assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), calls);
    }
}

#[test]
#[ignore = "explicit owned canonical fixture and genuine context; production Apply prerequisite receiver only, no package/source or effects"]
fn vendor_pending_reaches_real_apply_prerequisite_before_package_planning() {
    let f = vendor_group_failure("vendor-apply-prerequisite");
    let bound = f.bound();
    let target = crate::instances::GuiReplacementTarget { kind: crate::instances::GuiTargetKind::Desktop,
        root_path: f.desktop.parent().unwrap().to_owned(), native_root_id: bound.native_root_id(),
        anchor_path: f.desktop.clone(), anchor_native_id: bound.native_executable_id() };
    let calls = TEST_NATIVE_CALLS.with(|v| v.get());
    // This is the production classifier used by Cmd::ApplySettings's plan
    // receiver, before inspect_native_apply and selected source/assets receiving.
    let result = crate::ops::receive_desktop_apply_current(bound, &target, [7; 32]);
    let Err(crate::ops::ApplyPlanError::VendorMetadataRecoveryRequired(prerequisite)) = result else { panic!("typed vendor prerequisite required") };
    assert_eq!(prerequisite.saved_sha256, [7; 32]);
    assert_eq!(prerequisite.target, target);
    let (pending, digest) = f.current();
    assert_eq!(prerequisite.observation.slot_id, pending.slot_id);
    assert_eq!(prerequisite.observation.operation_id, pending.active_operation.unwrap().id);
    assert_eq!(hex::encode(prerequisite.observation.current_sha256), digest);
    assert!(super::super::strict_current_expectation(observe_apply_current(&f.bound()).unwrap()).is_err());
    drop(prerequisite);
    let mut changed = target; changed.anchor_native_id.file[0] ^= 1;
    assert!(matches!(crate::ops::receive_desktop_apply_current(f.bound(), &changed, [7; 32]), Err(crate::ops::ApplyPlanError::Receiving(_))));
    assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 0);
    assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), calls);
}

#[test]
#[ignore = "explicit owned canonical fixture and genuine context; actual staged/backup/content drift, zero recovery calls"]
fn vendor_group_actual_drift_holds_before_group_call() {
    for which in ["target", "stage", "backup"] {
        let f = vendor_group_failure(&format!("vendor-group-drift-{which}"));
        let authority = Authority::open(&f.bound(), false, true).unwrap();
        let op = authority.current.active_operation.as_ref().unwrap();
        let vendor = receive_vendor_intent(&authority.slot, &op.intent).unwrap();
        let path = match which {
            "target" => f.desktop.parent().unwrap().join("resources/app.asar"),
            "stage" => vendor.apply_layout.staged,
            "backup" => vendor.apply_layout.original_backup,
            _ => unreachable!(),
        };
        drop(authority);
        if which == "stage" { write_private(&path, b"occupied synthetic stage").unwrap(); }
        else { fs::write(NativeFsPath::from_path(&path).unwrap().as_path(), b"changed synthetic bytes").unwrap(); }
        let calls = TEST_NATIVE_CALLS.with(|v| v.get());
        assert!(f.recover().is_err());
        assert_eq!(native::TEST_GROUP_CALLS.with(|v| v.get()), 0);
        assert_eq!(TEST_NATIVE_CALLS.with(|v| v.get()), calls);
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
