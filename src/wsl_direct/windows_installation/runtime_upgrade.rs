//! Fixed native upgrade and rollback steps under canonical Pending.
//! Unreceived calls are never replayed or inferred from matching bytes.
use super::runtime_deployment::{GateBinding, HookBinding, HostBinding};
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpgradeIntent {
    schema: u32,
    slot_id: String,
    operation_id: String,
    expected_current_digest: String,
    prior_current: EvidenceRef,
    #[serde(deserialize_with = "required_option")]
    prior_applied: Option<archive_install::AppliedArchive>,
    proposed_runtime_deployment: RuntimeDeployment,
    pristine: EvidenceRef,
    candidate: EvidenceRef,
    #[serde(deserialize_with = "required_option")]
    revert_layout: Option<LayoutBinding>,
    apply_layout: LayoutBinding,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StepIntent {
    schema: u32,
    operation_id: String,
    step: String,
    source: TargetState,
    source_native_id: ObjectId,
    preimage: EvidenceRef,
    layout: LayoutBinding,
    #[serde(deserialize_with = "required_option")]
    reverted: Option<archive_install::AppliedArchive>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StepOutcome {
    schema: u32,
    step: String,
    intent: EvidenceRef,
    native_call: NativeCall,
    target: TargetState,
    native_id: ObjectId,
    #[serde(deserialize_with = "required_option")]
    applied: Option<archive_install::AppliedArchive>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RollbackIntent {
    schema: u32,
    slot_id: String,
    operation_id: String,
    expected_current_digest: String,
    prior_current: EvidenceRef,
    upgrade_intent: EvidenceRef,
    source: EvidenceRef,
    #[serde(deserialize_with = "required_option")]
    revert_layout: Option<LayoutBinding>,
    apply_layout: LayoutBinding,
    candidate: EvidenceRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "decision",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum UpgradeOutcome {
    Applied {
        slot_id: String,
        operation_id: String,
        intent: EvidenceRef,
        steps: Vec<EvidenceRef>,
    },
    NoNativeCall {
        slot_id: String,
        operation_id: String,
        intent: EvidenceRef,
        failure: EvidenceRef,
    },
    RolledBack {
        slot_id: String,
        operation_id: String,
        intent: EvidenceRef,
        steps: Vec<EvidenceRef>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VendorUpdateIntent {
    schema: u32,
    slot_id: String,
    operation_id: String,
    expected_current_digest: String,
    prior_current: EvidenceRef,
    new_binding: Binding,
    pristine: EvidenceRef,
    candidate: EvidenceRef,
    apply_layout: LayoutBinding,
    deployment: RuntimeDeployment,
    #[serde(default, skip_serializing_if = "VendorRuntimeRecord::is_reuse")]
    runtime_input: VendorRuntimeRecord,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase", deny_unknown_fields)]
enum VendorRuntimeRecord {
    #[default]
    ReuseReceivedRuntime,
    QualifiedPackage {
        source_path: PathBuf,
        source_native_id: ObjectId,
        source_sha256: String,
        helper_sha256: String,
        retirement: gateway_rules::VendorRetirementPlan,
    },
}
impl VendorRuntimeRecord {
    fn is_reuse(&self) -> bool { matches!(self, Self::ReuseReceivedRuntime) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct VendorUpdateOutcome {
    slot_id: String,
    operation_id: String,
    intent: EvidenceRef,
    step: EvidenceRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retirement_steps: Vec<EvidenceRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retirement_final_checks: Vec<EvidenceRef>,
}

// Private, vendor-only evidence. These records never impersonate StepOutcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum GroupFrameKind { GroupResolutionIntent, GroupCallIntent, GroupCallResult, GroupReadback, VendorGroupMetadataResolution }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupObject { target: TargetState, native_id: ObjectId }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupResolutionIntentV1 {
    schema: u32,
    kind: GroupFrameKind,
    slot_id: String,
    operation_id: String,
    pending_current: EvidenceRef,
    vendor_intent: EvidenceRef,
    step_intent: EvidenceRef,
    failure: EvidenceRef,
    actor_user: Vec<u8>,
    postimage: GroupObject,
    original_backup: GroupObject,
    displaced_backup: GroupObject,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupCallIntentV1 {
    schema: u32,
    kind: GroupFrameKind,
    resolution_intent: EvidenceRef,
    ordinal: u64,
    #[serde(deserialize_with = "required_option")]
    previous_not_called: Option<EvidenceRef>,
    pre_call: GroupObject,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase", deny_unknown_fields)]
enum GroupCallStatus { NotCalled { cause: String }, Returned { win_error: u32 } }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupCallResultV1 { schema: u32, kind: GroupFrameKind, call_intent: EvidenceRef, outcome: GroupCallStatus }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase", deny_unknown_fields)]
enum GroupReadbackState { Captured { object: GroupObject }, Unavailable { cause: String } }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupReadbackV1 {
    schema: u32,
    kind: GroupFrameKind,
    resolution_intent: EvidenceRef,
    #[serde(deserialize_with = "required_option")]
    call_result: Option<EvidenceRef>,
    observed: GroupReadbackState,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupAttemptRefs {
    intent: EvidenceRef,
    #[serde(deserialize_with = "required_option")]
    result: Option<EvidenceRef>,
    #[serde(deserialize_with = "required_option")]
    readback: Option<EvidenceRef>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase", deny_unknown_fields)]
enum GroupResolutionProof {
    ReturnedAndVerified { result: EvidenceRef, readback: EvidenceRef },
    ObservedDesired { readback: EvidenceRef },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VendorGroupMetadataResolutionV1 {
    schema: u32,
    kind: GroupFrameKind,
    slot_id: String,
    operation_id: String,
    vendor_intent: EvidenceRef,
    step_intent: EvidenceRef,
    failure: EvidenceRef,
    resolution_intent: EvidenceRef,
    attempts: Vec<GroupAttemptRefs>,
    proof: GroupResolutionProof,
    postimage: GroupObject,
    applied: archive_install::AppliedArchive,
}
struct VendorReceivedApply {
    intent: EvidenceRef,
    target: TargetState,
    native_id: ObjectId,
    applied: Option<archive_install::AppliedArchive>,
}
impl From<StepOutcome> for VendorReceivedApply {
    fn from(step: StepOutcome) -> Self {
        Self { intent: step.intent, target: step.target, native_id: step.native_id, applied: step.applied }
    }
}

struct GroupFailureInput {
    step_ref: EvidenceRef,
    failure_ref: EvidenceRef,
    step: StepIntent,
    postimage: TargetState,
    original_backup: TargetState,
    displaced_backup: TargetState,
    target_path: PathBuf,
}
fn recorded_group_object(value: &archive_install::FileObservation) -> Result<TargetState> {
    match value {
        archive_install::FileObservation::Present { identity, digest } => Ok(TargetState { metadata: identity.clone(), digest: digest.clone() }),
        _ => Err("RecoveryRequired: recorded group-resolution object unavailable".into()),
    }
}
fn preserved_basic(a: &FileIdentity, source: &FileIdentity) -> bool {
    a.volume == source.volume && a.attributes == source.attributes && a.creation == source.creation && a.write == source.write
}
fn post_fields(a: &TargetState, failed: &TargetState, source: &TargetState, candidate: &[u8]) -> bool {
    a.metadata.index == failed.metadata.index && a.metadata.volume == failed.metadata.volume
        && a.metadata.size == failed.metadata.size && a.metadata.size == candidate.len() as u64
        && a.digest == failed.digest && a.digest == hash(candidate) && preserved_basic(&a.metadata, &source.metadata)
}
fn known_vendor_group_failure(failure: &ActualFailure) -> bool {
    failure.phase == "metadata-preservation" && failure.replace_result == Some(true)
}
fn receive_group_failure(slot: &CheckedPath, vendor_ref: &EvidenceRef, vendor: &VendorUpdateIntent) -> Result<GroupFailureInput> {
    let dir = operation_dir(slot, vendor_ref)?;
    if optional_reference(slot, &dir.join("apply-v2-outcome.json"))?.is_some() {
        return Err("RecoveryRequired: normal outcome conflicts with group resolution".into());
    }
    let step_ref = optional_reference(slot, &dir.join("apply-v2-intent.json"))?.ok_or("group resolution step intent absent")?;
    let failure_ref = optional_reference(slot, &dir.join("apply-v2-failure.json"))?.ok_or("group resolution actual failure absent")?;
    let step: StepIntent = decode(&reference(slot, &step_ref)?)?;
    let failure: ActualFailure = decode(&reference(slot, &failure_ref)?)?;
    let pristine = reference(slot, &vendor.pristine)?;
    let candidate = reference(slot, &vendor.candidate)?;
    if !known_vendor_group_failure(&failure)
        || step.schema != 3 || step.step != "apply-v2" || step.operation_id != vendor.operation_id
        || step.reverted.is_some() || step.layout != vendor.apply_layout
        || step.source.digest != vendor.new_binding.archive_digest || step.source.metadata != vendor.new_binding.archive_metadata
        || step.source_native_id != vendor.new_binding.archive || reference(slot, &step.preimage)? != pristine
        || hash(&pristine) != step.source.digest {
        return Err("RecoveryRequired: not the exact known vendor metadata failure".into());
    }
    let layout = &step.layout;
    let target_path = failure.recovery.target.0.clone();
    validate_path(&target_path)?;
    let postimage = recorded_group_object(&failure.recovery.target.1)?;
    let stages = failure.recovery.staged.as_ref().ok_or("recorded stage absent")?;
    let original = failure.recovery.original_backup.as_ref().ok_or("recorded original backup absent")?;
    let displaced = failure.recovery.displaced_backup.as_ref().ok_or("recorded displaced backup absent")?;
    let original_backup = recorded_group_object(&original.1)?;
    let displaced_backup = recorded_group_object(&displaced.1)?;
    let paths = [&layout.staged, &layout.original_backup, &layout.displaced_backup];
    for (i, path) in paths.iter().enumerate() {
        validate_path(path)?;
        if path.parent() != Some(layout.workspace.as_path()) || **path == target_path || paths[..i].contains(path) {
            return Err("RecoveryRequired: group-resolution layout conflict".into());
        }
    }
    if stages.0 != layout.staged || !matches!(stages.1, archive_install::FileObservation::Missing)
        || original.0 != layout.original_backup || displaced.0 != layout.displaced_backup
        || !post_fields(&postimage, &postimage, &step.source, &candidate)
        || displaced_backup != step.source || original_backup.digest != step.source.digest
        || original_backup.metadata.size != step.source.metadata.size || !preserved_basic(&original_backup.metadata, &step.source.metadata)
        || postimage.metadata.security_descriptor == step.source.metadata.security_descriptor {
        return Err("RecoveryRequired: recorded failed postimage/backup field authority conflict".into());
    }
    Ok(GroupFailureInput { step_ref, failure_ref, step, postimage, original_backup, displaced_backup, target_path })
}
fn validate_group_capture(input: &GroupFailureInput, captured: &GroupResolutionIntentV1, candidate: &[u8], post: &GroupObject) -> Result<bool> {
    if post.native_id != captured.postimage.native_id || post.native_id.volume != input.step.source_native_id.volume
        || !post_fields(&post.target, &input.postimage, &input.step.source, candidate) {
        return Err("RecoveryRequired: group-resolution postimage object/content/basic fields differ".into());
    }
    native::receive_group_metadata(&post.target.metadata.security_descriptor, &input.postimage.metadata.security_descriptor,
        &input.step.source.metadata.security_descriptor, &captured.actor_user)
}
fn receive_group_intent(slot: &CheckedPath, value: &EvidenceRef, vendor_ref: &EvidenceRef,
    vendor: &VendorUpdateIntent, input: &GroupFailureInput) -> Result<GroupResolutionIntentV1> {
    let frame: GroupResolutionIntentV1 = decode(&reference(slot, value)?)?;
    let dir = operation_dir(slot, vendor_ref)?;
    let pending_bytes = reference(slot, &frame.pending_current)?;
    let pending: Current = decode(&pending_bytes)?;
    current_shape(&pending, &vendor.slot_id)?;
    let op = pending.active_operation.as_ref().ok_or("group-resolution retained Pending absent")?;
    if frame.schema != 1 || frame.kind != GroupFrameKind::GroupResolutionIntent
        || frame.slot_id != vendor.slot_id || frame.operation_id != vendor.operation_id
        || frame.vendor_intent != *vendor_ref || frame.step_intent != input.step_ref || frame.failure != input.failure_ref
        || optional_reference(slot, &dir.join("group-metadata-intent.json"))?.as_ref() != Some(value)
        || pending.mode != Mode::Pending || op.id != frame.operation_id || op.intent != *vendor_ref || op.kind != OperationKind::VendorUpdate
        || frame.original_backup.target != input.original_backup || frame.displaced_backup.target != input.displaced_backup
        || frame.displaced_backup.native_id != input.step.source_native_id
        || frame.original_backup.native_id.volume != input.step.source_native_id.volume
        || frame.postimage.native_id == frame.displaced_backup.native_id || frame.postimage.native_id == frame.original_backup.native_id
        || frame.original_backup.native_id == frame.displaced_backup.native_id {
        return Err("RecoveryRequired: group-resolution intent binding conflict".into());
    }
    receive_vendor_pending(slot, &pending, op)?;
    validate_group_capture(input, &frame, &reference(slot, &vendor.candidate)?, &frame.postimage)?;
    Ok(frame)
}
fn capture_group_object(path: &Path) -> Result<(SourceSnapshot, GroupObject)> {
    let _parents = parents(path)?;
    let mut file = open_regular(path, READ | DELETE)?;
    let snapshot = read_checked(&mut file, path)?;
    let captured = GroupObject { target: object_state(&snapshot), native_id: object_id(&file)? };
    Ok((snapshot, captured))
}
fn capture_group_handle(handle: &mut native::GroupMetadataHandle) -> Result<(SourceSnapshot, GroupObject)> {
    let (snapshot, native_id) = handle.readback()?;
    let captured = GroupObject { target: object_state(&snapshot), native_id };
    Ok((snapshot, captured))
}
fn receive_group_actual(bound: &BoundInstallation, slot: &CheckedPath, vendor: &VendorUpdateIntent,
    input: &GroupFailureInput, frame: &GroupResolutionIntentV1) -> Result<(SourceSnapshot, GroupObject, bool)> {
    bound.revalidate_context()?;
    bound.exe.recheck()?;
    if !same_windows_path(&bound.archive.path, &input.target_path)? || bound.parent.object != vendor.new_binding.parent || bound.root.object != vendor.new_binding.root
        || bound.resources.object != vendor.new_binding.resources || bound.exe.object != vendor.new_binding.executable
        || hash(&bound.exe.read_snapshot()?) != vendor.new_binding.executable_digest || current_token_user_sid()? != frame.actor_user {
        return Err("RecoveryRequired: group-resolution selected context/actor changed".into());
    }
    let layout = native_layout(bound, &input.step.layout, frame.postimage.native_id.clone())?;
    layout.workspace.recheck()?;
    if layout.workspace.object.volume != frame.postimage.native_id.volume || !matches!(archive_install::observe(&layout.paths.staged), archive_install::FileObservation::Missing) {
        return Err("RecoveryRequired: group-resolution workspace/stage changed".into());
    }
    let (original_bytes, original) = capture_group_object(&layout.paths.original_backup)?;
    let (displaced_bytes, displaced) = capture_group_object(&layout.paths.displaced_backup)?;
    let pristine = reference(slot, &vendor.pristine)?;
    if original != frame.original_backup || displaced != frame.displaced_backup || original_bytes.bytes != pristine || displaced_bytes.bytes != pristine {
        return Err("RecoveryRequired: group-resolution retained backup changed".into());
    }
    let (snapshot, post) = capture_group_object(&bound.archive.path)?;
    let candidate = reference(slot, &vendor.candidate)?;
    if snapshot.bytes != candidate { return Err("RecoveryRequired: group-resolution candidate bytes changed".into()); }
    let desired = validate_group_capture(input, frame, &candidate, &post)?;
    vendor.deployment.receive_host(slot)?;
    Ok((snapshot, post, desired))
}

fn save_group_frame<T: Serialize>(authority: &Authority, dir: &Path, name: &str, frame: &T) -> Result<EvidenceRef> {
    #[cfg(test)]
    group_checkpoint(&format!("save:{name}"))?;
    let bytes = json(frame)?;
    let value = authority.save(dir, name, &bytes)?;
    if reference(&authority.slot, &value)? != bytes { return Err("group evidence independent readback differs".into()); }
    Ok(value)
}
fn group_call_name(ordinal: u64, part: &str) -> String { format!("group-call-{ordinal}-{part}.json") }

// Only the last attempt may be incomplete. A later attempt requires the actual
// previous NotCalled terminal, never unchanged bytes or a missing result.
fn receive_group_attempts(slot: &CheckedPath, dir: &Path, resolution: &EvidenceRef,
    input: &GroupFailureInput, frame: &GroupResolutionIntentV1, candidate: &[u8]) -> Result<Vec<GroupAttemptRefs>> {
    let mut files = std::collections::BTreeMap::<u64, std::collections::BTreeSet<String>>::new();
    for entry in fs::read_dir(NativeFsPath::from_path(dir)?.as_path()).map_err(|e| io("group attempt inventory", e))? {
        let name = entry.map_err(|e| io("group attempt entry", e))?.file_name();
        let Some(name) = name.to_str() else { return Err("group attempt name encoding".into()); };
        if !name.starts_with("group-") { continue; }
        if matches!(name, "group-metadata-intent.json" | "group-metadata-resolution.json" | "group-final-readback.json") { continue; }
        let (number, part) = name.strip_prefix("group-call-").and_then(|v| v.split_once('-')).ok_or("unknown group evidence file")?;
        let ordinal: u64 = number.parse().map_err(|_| "group call ordinal invalid")?;
        let part = part.strip_suffix(".json").ok_or("group call frame suffix invalid")?;
        if ordinal == 0 || !matches!(part, "intent" | "result" | "readback") || group_call_name(ordinal, part) != name {
            return Err("RecoveryRequired: unknown group call position".into());
        }
        files.entry(ordinal).or_default().insert(part.to_owned());
    }
    let mut attempts = Vec::new();
    let mut previous_not_called = None;
    let mut next = 1u64;
    for (ordinal, parts) in files {
        if ordinal != next || (ordinal > 1 && previous_not_called.is_none()) || !parts.contains("intent") {
            return Err("RecoveryRequired: group call lineage hole/conflict or forbidden replay".into());
        }
        let intent_ref = optional_reference(slot, &dir.join(group_call_name(ordinal, "intent")))?.ok_or("group call intent absent")?;
        let call: GroupCallIntentV1 = decode(&reference(slot, &intent_ref)?)?;
        if call.schema != 1 || call.kind != GroupFrameKind::GroupCallIntent || call.resolution_intent != *resolution
            || call.ordinal != ordinal || call.previous_not_called != previous_not_called
            || validate_group_capture(input, frame, candidate, &call.pre_call)? {
            return Err("RecoveryRequired: group call intent/actor/preimage conflict".into());
        }
        let result_ref = optional_reference(slot, &dir.join(group_call_name(ordinal, "result")))?;
        previous_not_called = None;
        if let Some(value) = &result_ref {
            let result: GroupCallResultV1 = decode(&reference(slot, value)?)?;
            if result.schema != 1 || result.kind != GroupFrameKind::GroupCallResult || result.call_intent != intent_ref {
                return Err("RecoveryRequired: group call result binding conflict".into());
            }
            if let GroupCallStatus::NotCalled { cause } = result.outcome {
                if cause.is_empty() { return Err("group NotCalled cause absent".into()); }
                previous_not_called = Some(value.clone());
            }
        }
        let readback = optional_reference(slot, &dir.join(group_call_name(ordinal, "readback")))?;
        if let Some(value) = &readback {
            let observation = receive_group_readback(slot, value, resolution)?;
            if observation.call_result != result_ref || result_ref.is_none() { return Err("group readback result reference conflict".into()); }
        }
        attempts.push(GroupAttemptRefs { intent: intent_ref, result: result_ref, readback });
        next = next.checked_add(1).ok_or("group call ordinal overflow")?;
    }
    Ok(attempts)
}
fn receive_group_readback(slot: &CheckedPath, value: &EvidenceRef, resolution: &EvidenceRef) -> Result<GroupReadbackV1> {
    let frame: GroupReadbackV1 = decode(&reference(slot, value)?)?;
    if frame.schema != 1 || frame.kind != GroupFrameKind::GroupReadback || frame.resolution_intent != *resolution
        || matches!(&frame.observed, GroupReadbackState::Unavailable { cause } if cause.is_empty()) {
        return Err("RecoveryRequired: group readback binding conflict".into());
    }
    Ok(frame)
}

fn receive_vendor_apply(slot: &CheckedPath, value: &EvidenceRef, vendor_ref: &EvidenceRef,
    vendor: &VendorUpdateIntent) -> Result<VendorReceivedApply> {
    let dir = operation_dir(slot, vendor_ref)?;
    let normal = optional_reference(slot, &dir.join("apply-v2-outcome.json"))?;
    let resolution = optional_reference(slot, &dir.join("group-metadata-resolution.json"))?;
    match (normal, resolution) {
        (Some(normal), None) if normal == *value => {
            if optional_reference(slot, &dir.join("group-metadata-intent.json"))?.is_some() { return Err("normal vendor proof conflicts with group intent".into()); }
            Ok(receive_step(slot, value, &vendor.operation_id, "apply-v2")?.into())
        }
        (None, Some(resolution)) if resolution == *value => receive_group_resolution(slot, value, vendor_ref, vendor),
        _ => Err("RecoveryRequired: vendor proof fixed-kind/reference conflict".into()),
    }
}
fn receive_group_resolution(slot: &CheckedPath, value: &EvidenceRef, vendor_ref: &EvidenceRef,
    vendor: &VendorUpdateIntent) -> Result<VendorReceivedApply> {
    let result: VendorGroupMetadataResolutionV1 = decode(&reference(slot, value)?)?;
    let input = receive_group_failure(slot, vendor_ref, vendor)?;
    let frame = receive_group_intent(slot, &result.resolution_intent, vendor_ref, vendor, &input)?;
    let dir = operation_dir(slot, vendor_ref)?;
    let candidate = reference(slot, &vendor.candidate)?;
    let attempts = receive_group_attempts(slot, &dir, &result.resolution_intent, &input, &frame, &candidate)?;
    if result.schema != 1 || result.kind != GroupFrameKind::VendorGroupMetadataResolution || result.slot_id != vendor.slot_id
        || result.operation_id != vendor.operation_id || result.vendor_intent != *vendor_ref || result.step_intent != input.step_ref
        || result.failure != input.failure_ref || result.attempts != attempts || !validate_group_capture(&input, &frame, &candidate, &result.postimage)? {
        return Err("RecoveryRequired: vendor group resolution binding conflict".into());
    }
    let final_readback = match &result.proof {
        GroupResolutionProof::ReturnedAndVerified { result: call_result, readback } => {
            let last = attempts.last().ok_or("verified group call absent")?;
            if last.result.as_ref() != Some(call_result) || last.readback.as_ref() != Some(readback) { return Err("verified group call refs conflict".into()); }
            let terminal: GroupCallResultV1 = decode(&reference(slot, call_result)?)?;
            if !matches!(terminal.outcome, GroupCallStatus::Returned { win_error: 0 }) { return Err("verified group call did not return zero".into()); }
            readback
        }
        GroupResolutionProof::ObservedDesired { readback } => {
            if optional_reference(slot, &dir.join("group-final-readback.json"))?.as_ref() != Some(readback) { return Err("group observation fixed reference conflict".into()); }
            readback
        }
    };
    let observed = receive_group_readback(slot, final_readback, &result.resolution_intent)?;
    if !matches!(&observed.observed, GroupReadbackState::Captured { object } if object == &result.postimage)
        || (matches!(result.proof, GroupResolutionProof::ObservedDesired { .. }) && observed.call_result.is_some()) {
        return Err("RecoveryRequired: full desired group observation absent".into());
    }
    let a = &result.applied;
    if a.record_version != 1 || a.target != input.target_path || a.original != input.step.source.metadata
        || a.pre_digest != input.step.source.digest || a.post != result.postimage.target.metadata || a.post_digest != result.postimage.target.digest
        || a.original_backup != input.step.layout.original_backup || a.original_backup_identity != frame.original_backup.target.metadata
        || a.displaced_backup != input.step.layout.displaced_backup || a.displaced_identity != frame.displaced_backup.target.metadata {
        return Err("RecoveryRequired: actual group-resolved AppliedArchive differs".into());
    }
    Ok(VendorReceivedApply { intent: input.step_ref, target: result.postimage.target, native_id: result.postimage.native_id, applied: Some(result.applied) })
}

fn group_recovery_precheck<W: MaintenanceWindow>(bound: &BoundInstallation, authority: &Authority,
    frame: &GroupResolutionIntentV1, cancel: &AtomicBool, window: &mut W) -> Result<()> {
    if cancel.load(Ordering::SeqCst) { return Err("Cancelled: vendor metadata recovery held".into()); }
    bound.revalidate_context()?;
    window.ensure_held()?;
    let (_, digest) = receive_current(&authority.slot)?;
    if digest != authority.digest || digest != frame.pending_current.digest {
        return Err("RecoveryRequired: group-resolution Pending changed".into());
    }
    Ok(())
}
fn group_call_can_follow(last: Option<&GroupCallStatus>) -> Result<()> {
    match last {
        Some(GroupCallStatus::NotCalled { cause }) if !cause.is_empty() => Ok(()),
        Some(GroupCallStatus::Returned { win_error }) => Err(format!("RecoveryRequired: retained group call WinError={win_error}; no repeat")),
        _ => Err("RecoveryRequired: group call Unknown or invalid NotCalled; no repeat".into()),
    }
}
fn resolve_vendor_group_metadata<W: MaintenanceWindow>(bound: &BoundInstallation, authority: &Authority,
    op: &Operation, vendor: &VendorUpdateIntent, cancel: &AtomicBool, window: &mut W) -> Result<(EvidenceRef, VendorReceivedApply)> {
    let dir = operation_dir(&authority.slot, &op.intent)?;
    let input = receive_group_failure(&authority.slot, &op.intent, vendor)?;
    let candidate = reference(&authority.slot, &vendor.candidate)?;
    if cancel.load(Ordering::SeqCst) { return Err("Cancelled: vendor metadata recovery not started".into()); }
    window.ensure_held()?;
    let resolution_ref = match optional_reference(&authority.slot, &dir.join("group-metadata-intent.json"))? {
        Some(value) => value,
        None => {
            // These are fresh recovery captures, never invented historical IDs.
            let (_, postimage) = capture_group_object(&bound.archive.path)?;
            let (_, original_backup) = capture_group_object(&input.step.layout.original_backup)?;
            let (_, displaced_backup) = capture_group_object(&input.step.layout.displaced_backup)?;
            let frame = GroupResolutionIntentV1 { schema: 1, kind: GroupFrameKind::GroupResolutionIntent,
                slot_id: vendor.slot_id.clone(), operation_id: op.id.clone(), pending_current: authority.retain_current()?,
                vendor_intent: op.intent.clone(), step_intent: input.step_ref.clone(), failure: input.failure_ref.clone(),
                actor_user: current_token_user_sid()?, postimage, original_backup, displaced_backup };
            // Reject malformed captures before persisting a new recovery lineage.
            if frame.original_backup.target != input.original_backup || frame.displaced_backup.target != input.displaced_backup
                || frame.displaced_backup.native_id != input.step.source_native_id {
                return Err("RecoveryRequired: initial group-resolution backup receiving differs".into());
            }
            validate_group_capture(&input, &frame, &candidate, &frame.postimage)?;
            receive_group_actual(bound, &authority.slot, vendor, &input, &frame)?;
            save_group_frame(authority, &dir, "group-metadata-intent.json", &frame)?
        }
    };
    let frame = receive_group_intent(&authority.slot, &resolution_ref, &op.intent, vendor, &input)?;
    group_recovery_precheck(bound, authority, &frame, cancel, window)?;
    let attempts = receive_group_attempts(&authority.slot, &dir, &resolution_ref, &input, &frame, &candidate)?;
    let (preimage, postimage, desired) = receive_group_actual(bound, &authority.slot, vendor, &input, &frame)?;
    if let Some(value) = optional_reference(&authority.slot, &dir.join("group-metadata-resolution.json"))? {
        let received = receive_vendor_apply(&authority.slot, &value, &op.intent, vendor)?;
        if !desired || received.target != postimage.target || received.native_id != postimage.native_id {
            return Err("RecoveryRequired: group-resolved actual target changed".into());
        }
        return Ok((value, received));
    }
    let (proof, postimage) = if desired {
        // A later genuine Recover may observe convergence after Unknown or a
        // nonzero return. It preserves that entire lineage and makes no call.
        let observed = GroupReadbackV1 { schema: 1, kind: GroupFrameKind::GroupReadback,
            resolution_intent: resolution_ref.clone(), call_result: None,
            observed: GroupReadbackState::Captured { object: postimage.clone() } };
        let value = match optional_reference(&authority.slot, &dir.join("group-final-readback.json"))? {
            Some(value) if reference(&authority.slot, &value)? == json(&observed)? => value,
            Some(_) => return Err("RecoveryRequired: immutable group observation conflict".into()),
            None => save_group_frame(authority, &dir, "group-final-readback.json", &observed)?,
        };
        (GroupResolutionProof::ObservedDesired { readback: value }, postimage)
    } else {
        let previous_not_called = match attempts.last() {
            None => None,
            Some(last) => {
                let result = last.result.as_ref().map(|value| reference(&authority.slot, value).and_then(|bytes| decode::<GroupCallResultV1>(&bytes))).transpose()?;
                group_call_can_follow(result.as_ref().map(|value| &value.outcome))?;
                last.result.clone()
            }
        };
        if optional_reference(&authority.slot, &dir.join("group-final-readback.json"))?.is_some() {
            return Err("RecoveryRequired: immutable desired observation no longer matches".into());
        }
        group_recovery_precheck(bound, authority, &frame, cancel, window)?;
        let ordinal = u64::try_from(attempts.len()).map_err(|_| "group ordinal encoding")?.checked_add(1).ok_or("group ordinal overflow")?;
        // Open first. If admission/open fails, the separately retained terminal
        // truthfully says NotCalled; it never claims acquired native rights.
        let mut handle = native::GroupMetadataHandle::open(&preimage, &postimage.native_id,
            &input.postimage.metadata.security_descriptor, &input.step.source.metadata.security_descriptor, &frame.actor_user);
        let call = GroupCallIntentV1 { schema: 1, kind: GroupFrameKind::GroupCallIntent,
            resolution_intent: resolution_ref.clone(), ordinal, previous_not_called, pre_call: postimage };
        let call_ref = save_group_frame(authority, &dir, &group_call_name(ordinal, "intent"), &call)
            .map_err(|error| format!("RecoveryRequired: group intent persistence={error}; preCallAdmission={:?}; native call not made", handle.as_ref().err()))?;
        group_checkpoint("after-intent")?;
        let status = match handle.as_mut() {
            Err(cause) => GroupCallStatus::NotCalled { cause: cause.clone() },
            Ok(handle) => match (|| -> Result<()> {
                group_recovery_precheck(bound, authority, &frame, cancel, window)?;
                receive_group_actual(bound, &authority.slot, vendor, &input, &frame)?;
                group_checkpoint("before-call")?;
                handle.recheck()
            })() {
                Err(cause) => GroupCallStatus::NotCalled { cause },
                Ok(()) => GroupCallStatus::Returned { win_error: handle.set_group() },
            },
        };
        // Preserve the acquired code before any optional readback/formatting.
        let terminal = GroupCallResultV1 { schema: 1, kind: GroupFrameKind::GroupCallResult, call_intent: call_ref, outcome: status };
        if let Err(error) = group_checkpoint("after-native-before-result") {
            let actual = match handle.as_mut() { Ok(handle) => capture_group_handle(handle), Err(_) => capture_group_object(&bound.archive.path) };
            return Err(format!("RecoveryRequired: acquired group outcome={:?}; {error}; actualReadback={actual:?}; Pending retained", terminal.outcome));
        }
        let persisted = save_group_frame(authority, &dir, &group_call_name(ordinal, "result"), &terminal);
        let actual = match handle.as_mut() { Ok(handle) => capture_group_handle(handle), Err(_) => capture_group_object(&bound.archive.path) };
        let observed = match actual {
            Ok((_, object)) => GroupReadbackState::Captured { object },
            Err(cause) => GroupReadbackState::Unavailable { cause },
        };
        let result_ref = persisted.map_err(|error| format!("RecoveryRequired: acquired group outcome={:?}; resultPersistence={error}; actualReadback={observed:?}; Pending retained", terminal.outcome))?;
        group_checkpoint("after-result")?;
        let readback = GroupReadbackV1 { schema: 1, kind: GroupFrameKind::GroupReadback,
            resolution_intent: resolution_ref.clone(), call_result: Some(result_ref.clone()), observed };
        let readback_ref = save_group_frame(authority, &dir, &group_call_name(ordinal, "readback"), &readback)
            .map_err(|error| format!("RecoveryRequired: acquired group outcome={:?}; readback={:?}; readbackPersistence={error}", terminal.outcome, readback.observed))?;
        match terminal.outcome {
            GroupCallStatus::NotCalled { cause } => return Err(format!("RecoveryRequired: group NotCalled: {cause}; readback={:?}; a later explicit Recover must re-receive", readback.observed)),
            GroupCallStatus::Returned { win_error } if win_error != 0 => return Err(format!("RecoveryRequired: SetSecurityInfo GROUP WinError={win_error}; readback={:?}; no automatic repeat", readback.observed)),
            GroupCallStatus::Returned { .. } => {}
        }
        let actual = match readback.observed {
            GroupReadbackState::Captured { object } => object,
            GroupReadbackState::Unavailable { cause } => return Err(format!("RecoveryRequired: group returned zero; readback unavailable: {cause}")),
        };
        if !validate_group_capture(&input, &frame, &candidate, &actual)? { return Err("RecoveryRequired: group returned zero without full desired metadata".into()); }
        group_recovery_precheck(bound, authority, &frame, cancel, window)?;
        let (_, fresh, full) = receive_group_actual(bound, &authority.slot, vendor, &input, &frame)?;
        if !full || fresh != actual { return Err("RecoveryRequired: group post-call full receiving changed".into()); }
        (GroupResolutionProof::ReturnedAndVerified { result: result_ref, readback: readback_ref }, actual)
    };
    group_recovery_precheck(bound, authority, &frame, cancel, window)?;
    let source = SourceSnapshot { target: input.target_path.clone(), bytes: reference(&authority.slot, &input.step.preimage)?,
        digest: input.step.source.digest.clone(), identity: input.step.source.metadata.clone() };
    let host = vendor.deployment.host.path.to_str().ok_or("group resolution host encoding")?;
    let applied = archive_install::receive_applied_profile(&source, &candidate, &step_paths(&input.step.layout), desktop_hook::HookProfile::GuiHost(host))?;
    let (_, final_post, full) = receive_group_actual(bound, &authority.slot, vendor, &input, &frame)?;
    if !full || final_post != postimage { return Err("RecoveryRequired: group final receiving changed".into()); }
    let attempts = receive_group_attempts(&authority.slot, &dir, &resolution_ref, &input, &frame, &candidate)?;
    let result = VendorGroupMetadataResolutionV1 { schema: 1, kind: GroupFrameKind::VendorGroupMetadataResolution,
        slot_id: vendor.slot_id.clone(), operation_id: op.id.clone(), vendor_intent: op.intent.clone(), step_intent: input.step_ref,
        failure: input.failure_ref, resolution_intent: resolution_ref, attempts, proof, postimage, applied };
    let value = save_group_frame(authority, &dir, "group-metadata-resolution.json", &result)?;
    group_checkpoint("after-resolution")?;
    let received = receive_vendor_apply(&authority.slot, &value, &op.intent, vendor)?;
    Ok((value, received))
}

fn group_checkpoint(_stage: &str) -> Result<()> {
    #[cfg(test)]
    if TEST_GROUP_STOP.with(|value| if value.get() == Some(_stage) { value.set(None); true } else { false }) {
        return Err(format!("RecoveryRequired: injected group recovery interruption {_stage}; Pending/readback receiving required"));
    }
    Ok(())
}

fn same_metadata(a: &FileIdentity, b: &FileIdentity) -> bool {
    a.volume == b.volume
        && a.size == b.size
        && a.attributes == b.attributes
        && a.creation == b.creation
        && a.write == b.write
        && a.security_descriptor == b.security_descriptor
}

fn operation_dir(slot: &CheckedPath, value: &EvidenceRef) -> Result<PathBuf> {
    Ok(slot
        .path
        .join(&value.path)
        .parent()
        .ok_or("runtime evidence directory")?
        .to_owned())
}

fn optional_reference(slot: &CheckedPath, path: &Path) -> Result<Option<EvidenceRef>> {
    match fs::symlink_metadata(NativeFsPath::from_path(path)?.as_path()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io("runtime step observation", e)),
        Ok(_) => {
            let bytes = read_private(path)?;
            let path = path
                .strip_prefix(&slot.path)
                .map_err(|_| "runtime evidence outside slot")?
                .to_str()
                .ok_or("runtime evidence encoding")?
                .replace('\\', "/");
            let value = EvidenceRef {
                path,
                digest: hash(&bytes),
            };
            reference(slot, &value)?;
            Ok(Some(value))
        }
    }
}

fn receive_intent(slot: &CheckedPath, value: &EvidenceRef) -> Result<UpgradeIntent> {
    let intent: UpgradeIntent = decode(&reference(slot, value)?)?;
    let bytes = reference(slot, &intent.prior_current)?;
    let prior: Current = decode(&bytes)?;
    current_shape(&prior, &intent.slot_id)?;
    if intent.schema != 3
        || intent.expected_current_digest != hash(&bytes)
        || !matches!(
            prior.mode,
            Mode::SettledApplied | Mode::SettledUnchanged | Mode::SettledReverted
        )
        || matches!(prior.runtime_deployment, DeploymentField::Present(Some(_)))
        || json(&prior.settled.as_ref().and_then(|s| s.applied.as_ref()))?
            != json(&intent.prior_applied)?
        || intent.revert_layout.is_some() != intent.prior_applied.is_some()
    {
        return Err("RecoveryRequired: runtime upgrade prior binding conflict".into());
    }
    super::receive_settlement(slot, &prior)?;
    let pristine = reference(slot, &intent.pristine)?;
    if let Some(record) = &intent.prior_applied {
        let prepared = desktop_hook::prepare_archive(&pristine).map_err(|e| e.to_string())?;
        if hash(&pristine) != record.pre_digest
            || prepared.post_digest != record.post_digest
            || prior.binding.archive_digest != record.post_digest
            || prior.binding.archive_metadata != record.post
        {
            return Err("RecoveryRequired: retained V1/pristine binding conflict".into());
        }
    } else if hash(&pristine) != prior.binding.archive_digest {
        return Err("RecoveryRequired: pristine input differs from received prior state".into());
    }
    intent.proposed_runtime_deployment.validate_shape()?;
    let host = intent
        .proposed_runtime_deployment
        .host
        .path
        .to_str()
        .ok_or("runtime host encoding")?;
    let prepared = desktop_hook::prepare_gui_archive(&pristine, host).map_err(|e| e.to_string())?;
    if prepared.bytes != reference(slot, &intent.candidate)? {
        return Err("RecoveryRequired: runtime upgrade candidate binding conflict".into());
    }
    Ok(intent)
}

fn receive_vendor_intent(slot: &CheckedPath, value: &EvidenceRef) -> Result<VendorUpdateIntent> {
    let intent: VendorUpdateIntent = decode(&reference(slot, value)?)?;
    let prior_bytes = reference(slot, &intent.prior_current)?;
    let prior: Current = decode(&prior_bytes)?;
    current_shape(&prior, &intent.slot_id)?;
    if !matches!(intent.schema, 3 | 4) || intent.slot_id != prior.slot_id
        || intent.expected_current_digest != hash(&prior_bytes) || prior.mode != Mode::SettledApplied
        || intent.new_binding == prior.binding {
        return Err("RecoveryRequired: vendor update prior Current conflict".into());
    }
    super::receive_settlement(slot, &prior)?;
    let old = prior.runtime_deployment.received()?;
    old.receive_receipt(slot)?;
    let new = &intent.deployment;
    new.validate_shape()?;
    match &intent.runtime_input {
        VendorRuntimeRecord::ReuseReceivedRuntime => {
            if intent.schema != 3 || new.version != old.version || new.gate != old.gate || new.host != old.host
                || new.gateway_rules != old.gateway_rules || new.hook.revision != old.hook.revision {
                return Err("RecoveryRequired: vendor update runtime custody differs".into());
            }
        }
        VendorRuntimeRecord::QualifiedPackage { source_path, source_native_id, source_sha256, helper_sha256, retirement } => {
            WindowsExecutablePath::parse(source_path.as_os_str())?;
            let valid_hash = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if intent.schema != 4 || !valid_hash(source_sha256) || !valid_hash(helper_sha256)
                || new.version != 1 || new.gateway_rules.is_some() || new.gate != old.gate
                || new.host == old.host || new.host.sha256 != *source_sha256
                || source_native_id == &new.host.native_id {
                return Err("RecoveryRequired: vendor qualified package binding differs".into());
            }
            gateway_rules::validate_vendor_retirement(slot, old, retirement)?;
            gateway_rules::validate_vendor_selection_context(retirement, &intent.slot_id, &intent.expected_current_digest, &intent.new_binding)?;
            let host = new.receive_host(slot)?;
            PackageAssets::receive(&host, Some(helper_sha256))?.recheck()?;
        }
    }
    let receipt_path = operation_dir(slot, value)?.join("vendor-runtime-deployment.json");
    let receipt_relative = receipt_path.strip_prefix(&slot.path).map_err(|_| "vendor receipt outside slot")?
        .to_str().ok_or("vendor receipt encoding")?.replace('\\', "/");
    if new.receipt.path != receipt_relative || new.receipt.digest != hash(&json(&new.receipt())?) {
        return Err("RecoveryRequired: vendor update receipt binding differs".into());
    }
    let pristine = reference(slot, &intent.pristine)?;
    if hash(&pristine) != intent.new_binding.archive_digest {
        return Err("RecoveryRequired: vendor update pristine binding differs".into());
    }
    let host = new.host.path.to_str().ok_or("runtime host encoding")?;
    let prepared = desktop_hook::prepare_gui_archive(&pristine, host).map_err(|e| e.to_string())?;
    if prepared.hook_status != desktop_hook::HookStatus::Prepared || prepared.bytes != reference(slot, &intent.candidate)?
        || desktop_hook::gui_member_digest(&prepared.bytes, host).map_err(|e| e.to_string())? != new.hook.member_sha256 {
        return Err("RecoveryRequired: vendor update candidate binding differs".into());
    }
    Ok(intent)
}

pub(super) fn receive_vendor_pending(slot: &CheckedPath, current: &Current, op: &Operation) -> Result<()> {
    let intent = receive_vendor_intent(slot, &op.intent)?;
    let prior: Current = decode(&reference(slot, &intent.prior_current)?)?;
    if current.schema != 3 || current.slot_id != intent.slot_id || op.id != intent.operation_id
        || op.prior_current_digest != intent.expected_current_digest || current.binding != prior.binding
        || current.locator != prior.locator || json(&current.runtime_deployment)? != json(&prior.runtime_deployment)? {
        return Err("RecoveryRequired: vendor update Pending binding conflict".into());
    }
    Ok(())
}
pub(super) fn receive_vendor_pending_target(slot: &CheckedPath, current: &Current, op: &Operation, bound: &BoundInstallation) -> Result<()> {
    receive_vendor_pending(slot, current, op)?;
    let intent = receive_vendor_intent(slot, &op.intent)?;
    bound.revalidate_context()?;
    let actual = bound.binding()?;
    if !ordinal(&current.locator, &bound.root.locator)? || actual.parent != intent.new_binding.parent
        || actual.root != intent.new_binding.root || actual.resources != intent.new_binding.resources
        || actual.executable != intent.new_binding.executable || actual.executable_digest != intent.new_binding.executable_digest {
        return Err("RecoveryRequired: selected VendorPending target changed".into());
    }
    Ok(())
}

pub(super) fn receive_vendor_settled(slot: &CheckedPath, current: &Current, outcome: &VendorUpdateOutcome)
    -> Result<(TargetState, Option<archive_install::AppliedArchive>)> {
    let intent = receive_vendor_intent(slot, &outcome.intent)?;
    let prior: Current = decode(&reference(slot, &intent.prior_current)?)?;
    if current.schema != 3 || current.mode != Mode::SettledApplied || current.slot_id != outcome.slot_id
        || current.locator != prior.locator || intent.slot_id != outcome.slot_id || intent.operation_id != outcome.operation_id {
        return Err("RecoveryRequired: vendor update settlement identity conflict".into());
    }
    let result = receive_vendor_apply(slot, &outcome.step, &outcome.intent, &intent)?;
    match &intent.runtime_input {
        VendorRuntimeRecord::ReuseReceivedRuntime if !outcome.retirement_steps.is_empty() || !outcome.retirement_final_checks.is_empty() => {
            return Err("RecoveryRequired: reused runtime has unexpected retirement evidence".into());
        }
        VendorRuntimeRecord::ReuseReceivedRuntime => {}
        VendorRuntimeRecord::QualifiedPackage { retirement, .. } => {
            let dir = operation_dir(slot, &outcome.intent)?;
            gateway_rules::receive_vendor_retirement(slot, &dir, retirement, &outcome.retirement_steps)?;
            gateway_rules::receive_vendor_final_checks(slot, &dir, retirement, &outcome.retirement_final_checks)?;
        }
    }
    let step: StepIntent = decode(&reference(slot, &result.intent)?)?;
    let applied = result.applied.as_ref().ok_or("vendor update actual apply receipt absent")?;
    if step.layout != intent.apply_layout || step.source.digest != intent.new_binding.archive_digest
        || step.source.metadata != intent.new_binding.archive_metadata || step.source_native_id != intent.new_binding.archive
        || applied.pre_digest != intent.new_binding.archive_digest
        || result.target.digest != hash(&reference(slot, &intent.candidate)?)
        || current.binding.parent != intent.new_binding.parent || current.binding.root != intent.new_binding.root
        || current.binding.resources != intent.new_binding.resources || current.binding.executable != intent.new_binding.executable
        || current.binding.executable_digest != intent.new_binding.executable_digest
        || current.binding.archive != result.native_id || current.binding.archive_digest != result.target.digest
        || current.binding.archive_metadata != result.target.metadata
        || json(&current.runtime_deployment)? != json(&DeploymentField::Present(Some(intent.deployment.clone())))? {
        return Err("RecoveryRequired: vendor update settlement binding conflict".into());
    }
    intent.deployment.receive_receipt(slot)?;
    Ok((result.target, result.applied))
}

fn receive_step(
    slot: &CheckedPath,
    value: &EvidenceRef,
    operation: &str,
    name: &str,
) -> Result<StepOutcome> {
    let result: StepOutcome = decode(&reference(slot, value)?)?;
    let intent: StepIntent = decode(&reference(slot, &result.intent)?)?;
    let dir = operation_dir(slot, value)?;
    let fixed_intent = optional_reference(slot, &dir.join(format!("{name}-intent.json")))?
        .ok_or("native step fixed intent absent")?;
    let fixed_outcome = optional_reference(slot, &dir.join(format!("{name}-outcome.json")))?
        .ok_or("native step fixed outcome absent")?;
    if fixed_intent != result.intent
        || fixed_outcome != *value
        || optional_reference(slot, &dir.join(format!("{name}-failure.json")))?.is_some()
    {
        return Err("RecoveryRequired: immutable native step evidence conflict".into());
    }
    if result.schema != 3
        || intent.schema != 3
        || result.step != name
        || intent.step != name
        || intent.operation_id != operation
        || result.native_call != NativeCall::ReturnedSuccess
        || hash(&reference(slot, &intent.preimage)?) != intent.source.digest
    {
        return Err("RecoveryRequired: native step result/intent conflict".into());
    }
    match (&intent.reverted, &result.applied) {
        (None, Some(record)) if matches!(name, "apply-v2" | "restore-v1") => {
            if record.record_version != 1
                || record.pre_digest != intent.source.digest
                || record.original != intent.source.metadata
                || record.post != result.target.metadata
                || record.post_digest != result.target.digest
                || record.original_backup != intent.layout.original_backup
                || record.displaced_backup != intent.layout.displaced_backup
                || record.displaced_identity != intent.source.metadata
            {
                return Err("RecoveryRequired: actual apply receipt differs from step".into());
            }
        }
        (Some(record), None) if matches!(name, "revert-v1" | "revert-v2") => {
            if record.post != intent.source.metadata
                || record.post_digest != intent.source.digest
                || record.pre_digest != result.target.digest
                || !same_metadata(&result.target.metadata, &record.original)
            {
                return Err(
                    "RecoveryRequired: actual revert receipt differs from ultimate original".into(),
                );
            }
        }
        _ => return Err("RecoveryRequired: native step kind/receipt conflict".into()),
    }
    Ok(result)
}

fn receive_rollback(slot: &CheckedPath, value: &EvidenceRef) -> Result<RollbackIntent> {
    let intent: RollbackIntent = decode(&reference(slot, value)?)?;
    let upgrade = receive_intent(slot, &intent.upgrade_intent)?;
    let bytes = reference(slot, &intent.prior_current)?;
    let prior: Current = decode(&bytes)?;
    current_shape(&prior, &intent.slot_id)?;
    let source: StepOutcome = decode(&reference(slot, &intent.source)?)?;
    let source = receive_step(slot, &intent.source, &upgrade.operation_id, &source.step)?;
    if intent.schema != 3
        || intent.slot_id != upgrade.slot_id
        || intent.expected_current_digest != hash(&bytes)
        || upgrade.prior_applied.is_none()
        || !matches!(source.step.as_str(), "revert-v1" | "apply-v2")
        || (source.step == "apply-v2") != intent.revert_layout.is_some()
    {
        return Err("RecoveryRequired: rollback association/source conflict".into());
    }
    let old_dir = operation_dir(slot, &intent.upgrade_intent)?;
    let fixed_source =
        optional_reference(slot, &old_dir.join(format!("{}-outcome.json", source.step)))?
            .ok_or("rollback source is not a fixed upgrade result")?;
    if fixed_source != intent.source {
        return Err("rollback source reference conflict".into());
    }
    if prior.mode == Mode::Pending {
        let operation = prior
            .active_operation
            .as_ref()
            .ok_or("rollback prior Pending absent")?;
        if operation.kind != OperationKind::UpgradeRuntime
            || operation.intent != intent.upgrade_intent
            || operation.id != upgrade.operation_id
        {
            return Err("rollback does not bind prior upgrade".into());
        }
        receive_pending(slot, &prior, operation)?;
    } else {
        let settled = prior
            .settled
            .as_ref()
            .ok_or("rollback prior settlement absent")?;
        let evidence: Settlement = decode(&reference(slot, &settled.evidence)?)?;
        if !matches!(evidence, Settlement::RuntimeUpgrade(UpgradeOutcome::Applied { intent: ref original, .. }) if *original == intent.upgrade_intent)
        {
            return Err("rollback prior settlement is not this upgrade".into());
        }
        super::receive_settlement(slot, &prior)?;
        if source.target != settled.target || source.native_id != prior.binding.archive {
            return Err("rollback source differs from settled actual native result".into());
        }
    }
    let prepared = desktop_hook::prepare_archive(&reference(slot, &upgrade.pristine)?)
        .map_err(|e| e.to_string())?;
    if prepared.bytes != reference(slot, &intent.candidate)? {
        return Err("rollback versioned V1 candidate conflict".into());
    }
    Ok(intent)
}

pub(super) fn receive_pending(
    slot: &CheckedPath,
    current: &Current,
    operation: &Operation,
) -> Result<()> {
    let (slot_id, id, expected, deployment) = match operation.kind {
        OperationKind::UpgradeRuntime => {
            let i = receive_intent(slot, &operation.intent)?;
            (
                i.slot_id,
                i.operation_id,
                i.expected_current_digest,
                i.proposed_runtime_deployment,
            )
        }
        OperationKind::RollbackRuntime => {
            let i = receive_rollback(slot, &operation.intent)?;
            let u = receive_intent(slot, &i.upgrade_intent)?;
            (
                i.slot_id,
                i.operation_id,
                i.expected_current_digest,
                u.proposed_runtime_deployment,
            )
        }
        _ => return Err("runtime Pending kind conflict".into()),
    };
    if current.schema != 3
        || slot_id != current.slot_id
        || id != operation.id
        || expected != operation.prior_current_digest
        || json(current.runtime_deployment.received()?)? != json(&deployment)?
    {
        return Err("RecoveryRequired: Pending runtime binding conflict".into());
    }
    Ok(())
}

fn original_state(slot: &CheckedPath, intent: &UpgradeIntent) -> Result<TargetState> {
    if let Some(record) = &intent.prior_applied {
        Ok(TargetState {
            digest: record.pre_digest.clone(),
            metadata: record.original.clone(),
        })
    } else {
        let prior: Current = decode(&reference(slot, &intent.prior_current)?)?;
        Ok(TargetState {
            digest: prior.binding.archive_digest,
            metadata: prior.binding.archive_metadata,
        })
    }
}

fn check_pristine(
    slot: &CheckedPath,
    intent: &UpgradeIntent,
    actual: &SourceSnapshot,
) -> Result<()> {
    let original = original_state(slot, intent)?;
    if actual.bytes != reference(slot, &intent.pristine)?
        || actual.digest != original.digest
        || !same_metadata(&actual.identity, &original.metadata)
    {
        return Err("RecoveryRequired: ultimate pristine bytes/metadata differ".into());
    }
    Ok(())
}

fn check_incarnation(
    bound: &BoundInstallation,
    slot: &CheckedPath,
    intent: &UpgradeIntent,
) -> Result<()> {
    let prior: Current = decode(&reference(slot, &intent.prior_current)?)?;
    let actual = bound.binding()?;
    if actual.root != prior.binding.root
        || actual.resources != prior.binding.resources
        || actual.executable != prior.binding.executable
        || actual.executable_digest != prior.binding.executable_digest
    {
        return Err("RecoveryRequired: runtime installation incarnation changed".into());
    }
    bound.revalidate_context()
}

fn check_actual(bound: &BoundInstallation, outcome: &StepOutcome) -> Result<SourceSnapshot> {
    check_actual_target(bound, &outcome.target, &outcome.native_id)
}
fn check_actual_target(bound: &BoundInstallation, expected: &TargetState, native_id: &ObjectId) -> Result<SourceSnapshot> {
    bound.revalidate_context()?;
    let target = read_path(&bound.archive.path, READ | DELETE)?;
    if object_state(&target) != *expected
        || object_id(&open_regular(&target.target, READ | DELETE)?)? != *native_id
    {
        return Err(
            "RecoveryRequired: actual full postimage/native identity differs from received step"
                .into(),
        );
    }
    Ok(target)
}

fn step_paths(value: &LayoutBinding) -> InstallPaths {
    InstallPaths {
        staged: value.staged.clone(),
        original_backup: value.original_backup.clone(),
        displaced_backup: value.displaced_backup.clone(),
    }
}
fn layout(
    bound: &BoundInstallation,
    workspace: &CheckedPath,
    id: &str,
    step: &str,
) -> Result<LayoutBinding> {
    let prefix = format!("{id}-{step}");
    let value = LayoutBinding {
        workspace: workspace.path.clone(),
        workspace_id: workspace.object.clone(),
        staged: workspace.path.join(format!("{prefix}.staged")),
        original_backup: workspace.path.join(format!("{prefix}.original")),
        displaced_backup: workspace.path.join(format!("{prefix}.displaced")),
    };
    for path in [
        &value.staged,
        &value.original_backup,
        &value.displaced_backup,
    ] {
        absent(path)?;
    }
    private(&workspace.file)?;
    bound.outside(workspace)?;
    if workspace.object.volume != bound.resources.object.volume {
        return Err("runtime workspace volume differs".into());
    }
    Ok(value)
}

fn native_layout(
    bound: &BoundInstallation,
    value: &LayoutBinding,
    archive: ObjectId,
) -> Result<NativeLayout> {
    let workspace = CheckedPath::open(&value.workspace, PathKind::Directory, PathPurpose::Review)?;
    if workspace.object != value.workspace_id {
        return Err("RecoveryRequired: runtime workspace identity changed".into());
    }
    private(&workspace.file)?;
    bound.outside(&workspace)?;
    Ok(NativeLayout {
        paths: step_paths(value),
        workspace,
        resources: bound.resources.object.clone(),
        archive,
    })
}

fn run_step<W: MaintenanceWindow>(
    bound: &BoundInstallation,
    authority: &Authority,
    dir: &Path,
    operation: &str,
    name: &str,
    layout: &LayoutBinding,
    reverted: Option<&archive_install::AppliedArchive>,
    profile: desktop_hook::HookProfile<'_>,
    vendor_input: Option<(&Binding, &[u8])>,
    window: &mut W,
) -> Result<(EvidenceRef, StepOutcome)> {
    if let Some(value) =
        optional_reference(&authority.slot, &dir.join(format!("{name}-outcome.json")))?
    {
        let outcome = receive_step(&authority.slot, &value, operation, name)?;
        return Ok((value, outcome));
    }
    if optional_reference(&authority.slot, &dir.join(format!("{name}-intent.json")))?.is_some() {
        return Err(format!("RecoveryRequired: {name} native call lacks received success; Pending retained; no replay"));
    }
    let source = read_path(&bound.archive.path, READ | DELETE)?;
    let native_id = object_id(&open_regular(&source.target, READ | DELETE)?)?;
    let native = native_layout(bound, layout, native_id.clone())?;
    window.ensure_held()?;
    native.verify(&source.target)?;
    let prepared = if reverted.is_none() {
        Some(desktop_hook::prepare_profile(&source.bytes, profile).map_err(|e| e.to_string())?)
    } else {
        None
    };
    if let Some((expected, candidate)) = vendor_input {
        bound.exe.recheck()?;
        if bound.binding()? != *expected || hash(&bound.exe.read_snapshot()?) != expected.executable_digest
            || source.digest != expected.archive_digest || source.identity != expected.archive_metadata
            || native_id != expected.archive || prepared.as_ref().map(|p| p.bytes.as_slice()) != Some(candidate) {
            return Err("RecoveryRequired: vendor update input changed before native call".into());
        }
    }
    let preimage = authority.save(dir, &format!("{name}-preimage"), &source.bytes)?;
    let intent = StepIntent {
        schema: 3,
        operation_id: operation.into(),
        step: name.into(),
        source: object_state(&source),
        source_native_id: native_id,
        preimage,
        layout: layout.clone(),
        reverted: reverted.cloned(),
    };
    let intent_ref = authority.save(dir, &format!("{name}-intent.json"), &json(&intent)?)?;
    let result = if let Some(record) = reverted {
        archive_install::revert_profile(record, &native, window, profile).map(|_| None)
    } else {
        archive_install::apply_profile(
            &source,
            prepared.as_ref().ok_or("prepared candidate absent")?,
            &native,
            window,
            profile,
        )
        .map(Some)
    };
    let applied = match result {
        Ok(value) => value,
        Err(failure) => {
            let persistence = json(&failure)
                .and_then(|bytes| authority.save(dir, &format!("{name}-failure.json"), &bytes));
            return Err(format!("RecoveryRequired: {name}: {failure}; persistence={persistence:?}; Pending retained"));
        }
    };
    let target = read_path(&source.target, READ | DELETE)?;
    let result = StepOutcome {
        schema: 3,
        step: name.into(),
        intent: intent_ref,
        native_call: NativeCall::ReturnedSuccess,
        target: object_state(&target),
        native_id: object_id(&open_regular(&source.target, READ | DELETE)?)?,
        applied,
    };
    #[cfg(test)]
    if TEST_LOSE_RECEIPT.with(|value| {
        if value.get() == Some(name) {
            value.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(
            "RecoveryRequired: injected capture loss after actual native success; Pending retained"
                .into(),
        );
    }
    let value = authority.save(dir, &format!("{name}-outcome.json"), &json(&result)?)?;
    let received = receive_step(&authority.slot, &value, operation, name)?;
    #[cfg(test)]
    if TEST_STOP_AFTER_RECEIPT.with(|value| {
        if value.get() == Some(name) {
            value.set(None);
            true
        } else {
            false
        }
    }) {
        return Err("RecoveryRequired: injected interruption after durable actual native receipt; Pending retained".into());
    }
    Ok((value, received))
}

fn check_chain(slot: &CheckedPath, previous: &StepOutcome, next: &StepOutcome) -> Result<()> {
    let intent: StepIntent = decode(&reference(slot, &next.intent)?)?;
    if intent.source != previous.target || intent.source_native_id != previous.native_id {
        return Err("RecoveryRequired: actual native steps do not form the fixed sequence".into());
    }
    Ok(())
}

fn receive_no_call(
    slot: &CheckedPath,
    intent: &UpgradeIntent,
    failure: &EvidenceRef,
) -> Result<()> {
    let dir = operation_dir(slot, failure)?;
    let name = if intent.prior_applied.is_some() {
        "revert-v1"
    } else {
        "apply-v2"
    };
    let fixed = optional_reference(slot, &dir.join(format!("{name}-failure.json")))?
        .ok_or("no-call failure absent")?;
    if fixed != *failure {
        return Err("no-call fixed failure conflict".into());
    }
    let result: ActualFailure = decode(&reference(slot, failure)?)?;
    let value = optional_reference(slot, &dir.join(format!("{name}-intent.json")))?
        .ok_or("no-call step intent absent")?;
    let step: StepIntent = decode(&reference(slot, &value)?)?;
    let prior: Current = decode(&reference(slot, &intent.prior_current)?)?;
    if step.operation_id != intent.operation_id
        || step.step != name
        || step.source.digest != prior.binding.archive_digest
        || step.source.metadata != prior.binding.archive_metadata
        || step.source_native_id != prior.binding.archive
        || result.replace_result.is_some()
        || result.phase
            != if name == "revert-v1" {
                "revert-preflight"
            } else {
                "preflight"
            }
    {
        return Err("RecoveryRequired: native failure does not establish unchanged no-call".into());
    }
    let source = SourceSnapshot {
        target: result.recovery.target.0.clone(),
        bytes: reference(slot, &step.preimage)?,
        digest: step.source.digest,
        identity: step.source.metadata,
    };
    verify_failure_observations(&result, &source, &step.layout)
}

pub(super) fn receive_settled(
    slot: &CheckedPath,
    current: &Current,
    outcome: &UpgradeOutcome,
) -> Result<(TargetState, Option<archive_install::AppliedArchive>)> {
    let (slot_id, id, value) = match outcome {
        UpgradeOutcome::Applied {
            slot_id,
            operation_id,
            intent,
            ..
        }
        | UpgradeOutcome::NoNativeCall {
            slot_id,
            operation_id,
            intent,
            ..
        }
        | UpgradeOutcome::RolledBack {
            slot_id,
            operation_id,
            intent,
            ..
        } => (slot_id, operation_id, intent),
    };
    if current.schema != 3 || *slot_id != current.slot_id {
        return Err("runtime settlement identity conflict".into());
    }
    let (result, deployment, mode) = match outcome {
        UpgradeOutcome::Applied { steps, .. } => {
            let intent = receive_intent(slot, value)?;
            if intent.operation_id != *id
                || steps.len() != if intent.prior_applied.is_some() { 2 } else { 1 }
            {
                return Err("runtime upgrade fixed steps conflict".into());
            }
            let applied = receive_step(
                slot,
                steps.last().ok_or("apply result absent")?,
                id,
                "apply-v2",
            )?;
            let second: StepIntent = decode(&reference(slot, &applied.intent)?)?;
            if second.layout != intent.apply_layout {
                return Err("runtime V2 apply layout conflict".into());
            }
            let prior: Current = decode(&reference(slot, &intent.prior_current)?)?;
            if let Some(record) = &intent.prior_applied {
                let reverted = receive_step(slot, &steps[0], id, "revert-v1")?;
                let first: StepIntent = decode(&reference(slot, &reverted.intent)?)?;
                if Some(&first.layout) != intent.revert_layout.as_ref()
                    || json(&first.reverted)? != json(&Some(record))?
                    || first.source.metadata != prior.binding.archive_metadata
                    || first.source.digest != prior.binding.archive_digest
                    || first.source_native_id != prior.binding.archive
                {
                    return Err("runtime V1 revert binding conflict".into());
                }
                check_chain(slot, &reverted, &applied)?;
            } else if second.source.digest != prior.binding.archive_digest
                || second.source.metadata != prior.binding.archive_metadata
                || second.source_native_id != prior.binding.archive
            {
                return Err("runtime pristine admission conflict".into());
            }
            let pristine = original_state(slot, &intent)?;
            let record = applied
                .applied
                .as_ref()
                .ok_or("runtime actual V2 receipt absent")?;
            if record.pre_digest != pristine.digest
                || !same_metadata(&record.original, &pristine.metadata)
                || applied.target.digest != hash(&reference(slot, &intent.candidate)?)
            {
                return Err("runtime ultimate original/result conflict".into());
            }
            (
                applied,
                Some(intent.proposed_runtime_deployment),
                Mode::SettledApplied,
            )
        }
        UpgradeOutcome::NoNativeCall { failure, .. } => {
            let intent = receive_intent(slot, value)?;
            if intent.operation_id != *id
                || operation_dir(slot, value)? != operation_dir(slot, failure)?
            {
                return Err("runtime no-call operation conflict".into());
            }
            receive_no_call(slot, &intent, failure)?;
            let prior: Current = decode(&reference(slot, &intent.prior_current)?)?;
            let target = prior
                .settled
                .as_ref()
                .ok_or("no-call prior settlement absent")?
                .target
                .clone();
            let result = StepOutcome {
                schema: 3,
                step: "no-native-call".into(),
                intent: value.clone(),
                native_call: NativeCall::NotCalled,
                target,
                native_id: prior.binding.archive,
                applied: intent.prior_applied,
            };
            (result, None, prior.mode)
        }
        UpgradeOutcome::RolledBack { steps, .. } => {
            let intent = receive_rollback(slot, value)?;
            if intent.operation_id != *id
                || steps.len() != if intent.revert_layout.is_some() { 2 } else { 1 }
            {
                return Err("runtime rollback fixed steps conflict".into());
            }
            let restored = receive_step(
                slot,
                steps.last().ok_or("V1 result absent")?,
                id,
                "restore-v1",
            )?;
            let restore: StepIntent = decode(&reference(slot, &restored.intent)?)?;
            if restore.layout != intent.apply_layout
                || restored.target.digest != hash(&reference(slot, &intent.candidate)?)
            {
                return Err("runtime rollback V1 apply binding conflict".into());
            }
            let source: StepOutcome = decode(&reference(slot, &intent.source)?)?;
            if intent.revert_layout.is_some() {
                let reverted = receive_step(slot, &steps[0], id, "revert-v2")?;
                let first: StepIntent = decode(&reference(slot, &reverted.intent)?)?;
                if Some(&first.layout) != intent.revert_layout.as_ref()
                    || first.source != source.target
                    || first.source_native_id != source.native_id
                    || json(&first.reverted)? != json(&source.applied)?
                {
                    return Err("runtime rollback V2 revert binding conflict".into());
                }
                check_chain(slot, &reverted, &restored)?;
            } else {
                check_chain(slot, &source, &restored)?;
            }
            let upgrade = receive_intent(slot, &intent.upgrade_intent)?;
            let original = original_state(slot, &upgrade)?;
            let record = restored
                .applied
                .as_ref()
                .ok_or("new actual V1 receipt absent")?;
            if record.pre_digest != original.digest
                || !same_metadata(&record.original, &original.metadata)
            {
                return Err("runtime rollback ultimate original binding conflict".into());
            }
            (restored, None, Mode::SettledApplied)
        }
    };
    let actual_deployment = match &current.runtime_deployment {
        DeploymentField::Present(value) => value,
        DeploymentField::Absent => return Err("schema3 deployment field absent".into()),
    };
    if result.native_id != current.binding.archive
        || result.target.digest != current.binding.archive_digest
        || result.target.metadata != current.binding.archive_metadata
        || json(&deployment)? != json(actual_deployment)?
        || current.mode != mode
    {
        return Err("runtime settlement Current binding conflict".into());
    }
    Ok((result.target, result.applied))
}

fn publish_result<W: MaintenanceWindow>(
    bound: &BoundInstallation,
    authority: &mut Authority,
    outcome: UpgradeOutcome,
    result: &StepOutcome,
    deployment: Option<RuntimeDeployment>,
    mode: Mode,
    window: &mut W,
) -> Result<()> {
    let actual = check_actual(bound, result)?;
    window.ensure_held()?;
    if let Some(record) = &result.applied {
        let received = BoundInstallation::open(&bound.exe.path)?;
        let profile = match &deployment {
            Some(value) => desktop_hook::HookProfile::GuiHost(
                value.host.path.to_str().ok_or("runtime host encoding")?,
            ),
            None => desktop_hook::HookProfile::Legacy,
        };
        verify_applied_profile(&received, record, profile)?;
    }
    let operation = authority
        .current
        .active_operation
        .as_ref()
        .ok_or("runtime Pending absent")?;
    let dir = operation_dir(&authority.slot, &operation.intent)?;
    let bytes = json(&Settlement::RuntimeUpgrade(outcome))?;
    let evidence = match optional_reference(&authority.slot, &dir.join("outcome.json"))? {
        Some(value) if reference(&authority.slot, &value)? == bytes => value,
        Some(_) => return Err("RecoveryRequired: immutable runtime settlement conflict".into()),
        None => authority.save(&dir, "outcome.json", &bytes)?,
    };
    let mut current = authority.current.clone();
    current.revision = current.revision.checked_add(1).ok_or("revision overflow")?;
    current.mode = mode;
    current.active_operation = None;
    current.runtime_deployment = DeploymentField::Present(deployment);
    current.binding.archive = result.native_id.clone();
    current.binding.archive_digest = actual.digest;
    current.binding.archive_metadata = actual.identity;
    current.settled = Some(Settled {
        target: result.target.clone(),
        applied: result.applied.clone(),
        evidence,
    });
    super::receive_settlement(&authority.slot, &current)?;
    window.ensure_held()?;
    check_actual(bound, result)?;
    authority.publish(current)
}

fn pin_deployment_host(
    authority: &Authority,
    deployment: &RuntimeDeployment,
) -> Result<CheckedPath> {
    authority
        .runtime_write
        .as_ref()
        .ok_or("runtime writer absent")?
        .recheck(&deployment.gate.native_id)?;
    let host = CheckedPath::open(
        &deployment.host.path,
        PathKind::File,
        PathPurpose::Executable,
    )?;
    private(&host.file)?;
    if host.object != deployment.host.native_id
        || hash(&host.read_snapshot()?) != deployment.host.sha256
    {
        return Err("RecoveryRequired: runtime host changed".into());
    }
    Ok(host)
}

fn receive_deployment(
    authority: &Authority,
    deployment: &RuntimeDeployment,
    actual: &SourceSnapshot,
) -> Result<()> {
    let _host = pin_deployment_host(authority, deployment)?;
    deployment.receive_hook(&actual.bytes)?;
    authority
        .runtime_write
        .as_ref()
        .ok_or("runtime writer absent")?
        .recheck(&deployment.gate.native_id)?;
    let bytes = json(&deployment.receipt())?;
    let path = authority.slot.path.join(&deployment.receipt.path);
    match optional_reference(&authority.slot, &path)? {
        Some(value) if reference(&authority.slot, &value)? == bytes => {}
        Some(_) => return Err("RecoveryRequired: runtime deployment receipt conflict".into()),
        None => write_private(&path, &bytes)?,
    }
    deployment.receive_receipt(&authority.slot)
}

fn continue_upgrade<W: MaintenanceWindow>(
    bound: &BoundInstallation,
    authority: &mut Authority,
    operation: &Operation,
    window: &mut W,
) -> Result<()> {
    let intent = receive_intent(&authority.slot, &operation.intent)?;
    check_incarnation(bound, &authority.slot, &intent)?;
    let _host = pin_deployment_host(authority, &intent.proposed_runtime_deployment)?;
    let dir = operation_dir(&authority.slot, &operation.intent)?;
    let mut steps = Vec::new();
    if optional_reference(&authority.slot, &dir.join("apply-v2-outcome.json"))?.is_none() {
        if let Some(record) = &intent.prior_applied {
            let (value, reverted) = run_step(
                bound,
                authority,
                &dir,
                &operation.id,
                "revert-v1",
                intent.revert_layout.as_ref().ok_or("V1 layout absent")?,
                Some(record),
                desktop_hook::HookProfile::Legacy,
                None,
                window,
            )?;
            check_pristine(&authority.slot, &intent, &check_actual(bound, &reverted)?)?;
            steps.push(value);
        } else {
            let prior: Current = decode(&reference(&authority.slot, &intent.prior_current)?)?;
            if bound.binding()? != prior.binding {
                return Err("RecoveryRequired: pristine input identity changed".into());
            }
            check_pristine(
                &authority.slot,
                &intent,
                &read_path(&bound.archive.path, READ | DELETE)?,
            )?;
        }
    } else if intent.prior_applied.is_some() {
        steps.push(
            optional_reference(&authority.slot, &dir.join("revert-v1-outcome.json"))?
                .ok_or("V1 result absent")?,
        );
    }
    let host = intent
        .proposed_runtime_deployment
        .host
        .path
        .to_str()
        .ok_or("runtime host encoding")?;
    let (value, applied) = run_step(
        bound,
        authority,
        &dir,
        &operation.id,
        "apply-v2",
        &intent.apply_layout,
        None,
        desktop_hook::HookProfile::GuiHost(host),
        None,
        window,
    )?;
    steps.push(value);
    receive_deployment(
        authority,
        &intent.proposed_runtime_deployment,
        &check_actual(bound, &applied)?,
    )?;
    let outcome = UpgradeOutcome::Applied {
        slot_id: intent.slot_id,
        operation_id: operation.id.clone(),
        intent: operation.intent.clone(),
        steps,
    };
    publish_result(
        bound,
        authority,
        outcome,
        &applied,
        Some(intent.proposed_runtime_deployment),
        Mode::SettledApplied,
        window,
    )
}

/// Gate identity comes only from existing received owner evidence, including revert.
fn retained_deployment(slot: &CheckedPath, current: &Current) -> Result<Option<RuntimeDeployment>> {
    if let DeploymentField::Present(Some(value)) = &current.runtime_deployment {
        return Ok(Some(value.clone()));
    }
    let Some(settled) = &current.settled else {
        return Ok(None);
    };
    match decode::<Settlement>(&reference(slot, &settled.evidence)?)? {
        Settlement::RuntimeUpgrade(UpgradeOutcome::NoNativeCall { intent, .. }) => Ok(Some(
            receive_intent(slot, &intent)?.proposed_runtime_deployment,
        )),
        Settlement::RuntimeUpgrade(UpgradeOutcome::RolledBack { intent, .. }) => {
            let rollback = receive_rollback(slot, &intent)?;
            Ok(Some(
                receive_intent(slot, &rollback.upgrade_intent)?.proposed_runtime_deployment,
            ))
        }
        Settlement::Outcome(outcome) if current.mode == Mode::SettledReverted => {
            let intent: Intent = decode(&reference(slot, &outcome.intent)?)?;
            let prior: Current = decode(&reference(slot, &intent.prior_current)?)?;
            if intent.kind != OperationKind::Revert {
                return Err("reverted gate provenance conflict".into());
            }
            retained_deployment(slot, &prior)
        }
        Settlement::Resolution(resolution) if current.mode == Mode::SettledReverted => {
            let intent: Intent = decode(&reference(slot, &resolution.outcome.intent)?)?;
            let prior: Current = decode(&reference(slot, &intent.prior_current)?)?;
            if intent.kind != OperationKind::Revert {
                return Err("reverted recovery gate provenance conflict".into());
            }
            retained_deployment(slot, &prior)
        }
        _ => Ok(None),
    }
}

/// A selected new vendor incarnation and its prior canonical runtime are held
/// together until execution or drop. This does not authorize runtime launch.
pub(crate) struct PreparedVendorUpdate<'a, W: MaintenanceWindow> {
    bound: BoundInstallation,
    authority: Authority,
    _host: CheckedPath,
    candidate: desktop_hook::PreparedArchive,
    new_binding: Binding,
    apply_layout: LayoutBinding,
    id: String,
    runtime_input: VendorRuntimeInput<'a>,
    retirement: Option<gateway_rules::VendorRetirementPlan>,
    window: &'a mut W,
}

pub(crate) enum VendorRuntimeInput<'a> {
    ReuseReceivedRuntime { source: &'a CheckedPath, source_sha256: &'a str },
    QualifiedPackage { source: &'a CheckedPath, expected_host_sha256: &'a str, assets: &'a PackageAssets, selection: Option<&'a gateway_rules::GatewayRetirementSelectionV1> },
}

fn check_reuse_engine(input: &VendorRuntimeInput<'_>, host: &CheckedPath, deployment: &RuntimeDeployment) -> Result<()> {
    if let VendorRuntimeInput::ReuseReceivedRuntime { source, source_sha256 } = input {
        source.recheck()?;
        host.recheck()?;
        if hash(&source.read_snapshot()?) != *source_sha256
            || hash(&host.read_snapshot()?) != deployment.host.sha256
            || *source_sha256 != deployment.host.sha256 {
            return Err("UpdatePending: runtime engine differs; use ordinary Apply with a qualified package".into());
        }
    }
    Ok(())
}

/// Actual owner readback after canonical publication, not a future promise.
pub(crate) struct VendorUpdateCompletion {
    pub(crate) slot_id: String,
    pub(crate) current_sha256: [u8; 32],
}

pub(crate) fn prepare_vendor_update<'a, W: MaintenanceWindow>(
    expected_prior_current_digest: &str,
    mut bound: BoundInstallation,
    parent: Option<&Path>,
    runtime_input: VendorRuntimeInput<'a>,
    runner: Option<&mut dyn gateway_rules::GatewayRuleRunner>,
    cancel: &AtomicBool,
    window: &'a mut W,
) -> std::result::Result<PreparedVendorUpdate<'a, W>, gateway_rules::GatewayRuleError> {
    if cancel.load(Ordering::SeqCst) { return Err(gateway_rules::GatewayRuleError::CancelledBeforeMutation); }
    let chosen = workspace_r0(&bound, parent)?;
    let mut authority = Authority::open_vendor_update(&bound, expected_prior_current_digest)?;
    authority.admit_maintenance_gate()?;
    let deployment = authority.current.runtime_deployment.received()?.clone();
    deployment.receive_receipt(&authority.slot)?;
    let host = deployment.receive_host(&authority.slot)?;
    let _gate_host = pin_deployment_host(&authority, &deployment)?;
    check_reuse_engine(&runtime_input, &host, &deployment)?;
    bound.revalidate_context()?;
    bound.exe.recheck()?;
    bound.recheck_archive()?;
    window.ensure_held()?;
    let new_binding = bound.binding()?;
    if hash(&bound.exe.read_snapshot()?) != new_binding.executable_digest {
        return Err("UpdatePending: selected executable bytes changed".into());
    }
    let host_path = deployment.host.path.to_str().ok_or("runtime host encoding")?;
    let candidate = desktop_hook::prepare_gui_archive(&bound.bytes, host_path).map_err(|e| e.to_string())?;
    if candidate.hook_status != desktop_hook::HookStatus::Prepared || candidate.pre_digest != new_binding.archive_digest {
        return Err("UpdatePending: vendor update requires a supported pristine archive".into());
    }
    let retirement = match &runtime_input {
        VendorRuntimeInput::ReuseReceivedRuntime { .. } => None,
        VendorRuntimeInput::QualifiedPackage { source, expected_host_sha256, assets, selection } => {
            source.recheck()?;
            assets.recheck()?;
            let expected_helper = source.path.parent().ok_or("runtime package parent")?.join("ag_wsl_launch");
            if hash(&source.read_snapshot()?) != *expected_host_sha256
                || assets.helper_path() != expected_helper.as_path() {
                return Err("PackageIncomplete: selected host/assets binding differs".into());
            }
            PackageAssets::receive(source, Some(assets.helper_digest()))?.recheck()?;
            let plan = gateway_rules::plan_vendor_retirement(&authority, runner, *selection, cancel)?;
            gateway_rules::validate_vendor_selection_context(&plan, &authority.current.slot_id, expected_prior_current_digest, &new_binding)?;
            Some(plan)
        }
    };
    let workspace = match chosen {
        Some(value) => value,
        None => CheckedPath::open(&authority.slot.path, PathKind::Directory, PathPurpose::Review)?,
    };
    let id = unique_id()?;
    let apply_layout = layout(&bound, &workspace, &id, "vendor-apply")?;
    Ok(PreparedVendorUpdate { bound, authority, _host: host, candidate, new_binding, apply_layout, id,
        runtime_input, retirement, window })
}

impl<W: MaintenanceWindow> PreparedVendorUpdate<'_, W> {
    pub(crate) fn execute(mut self, mut runner: Option<&mut dyn gateway_rules::GatewayRuleRunner>, cancel: &AtomicBool) -> Result<VendorUpdateCompletion> {
        if cancel.load(Ordering::SeqCst) { return Err("Cancelled: vendor update not started".into()); }
        let mut retained_stage: Option<PathBuf> = None;
        let result = (|| -> Result<VendorUpdateCompletion> {
        self.bound.revalidate_context()?;
        self.bound.exe.recheck()?;
        self.bound.recheck_archive()?;
        if self.bound.binding()? != self.new_binding || hash(&self.bound.exe.read_snapshot()?) != self.new_binding.executable_digest {
            return Err("UpdatePending: selected vendor input changed before intent".into());
        }
        let old = self.authority.current.runtime_deployment.received()?.clone();
        let host = pin_deployment_host(&self.authority, &old)?;
        check_reuse_engine(&self.runtime_input, &host, &old)?;
        self.window.ensure_held()?;
        let mut deployment = old.clone();
        let mut staged_host = None;
        let runtime_input = match &self.runtime_input {
            VendorRuntimeInput::ReuseReceivedRuntime { .. } => VendorRuntimeRecord::ReuseReceivedRuntime,
            VendorRuntimeInput::QualifiedPackage { source, expected_host_sha256, assets, .. } => {
                source.recheck()?;
                assets.recheck()?;
                let bytes = source.read_snapshot()?;
                if hash(&bytes) != *expected_host_sha256 {
                    return Err("PackageIncomplete: selected host changed before staging".into());
                }
                let source_assets = PackageAssets::receive(source, Some(assets.helper_digest()))?;
                source_assets.recheck()?;
                let runtime_dir = self.authority.slot.path.join(format!("runtime-{}", self.id));
                create_private_dir(&runtime_dir)?;
                retained_stage = Some(runtime_dir.clone());
                let (host, candidate) = (|| -> Result<_> {
                    let host_path = runtime_dir.join("ag_unlocker.exe");
                    write_private(&host_path, &bytes)?;
                    source_assets.deploy(&runtime_dir)?;
                    source.recheck()?;
                    source_assets.recheck()?;
                    let host = CheckedPath::open(&host_path, PathKind::File, PathPurpose::Executable)?;
                    private(&host.file)?;
                    if host.read_snapshot()? != bytes { return Err("PackageIncomplete: staged host readback differs".into()); }
                    PackageAssets::receive(&host, Some(assets.helper_digest()))?.recheck()?;
                    let host_text = host.path.to_str().ok_or("runtime host encoding")?;
                    let candidate = desktop_hook::prepare_gui_archive(&self.bound.bytes, host_text).map_err(|e| e.to_string())?;
                    if candidate.hook_status != desktop_hook::HookStatus::Prepared {
                        return Err("UpdatePending: new package requires pristine vendor archive".into());
                    }
                    Ok((host, candidate))
                })().map_err(|error| format!("PreparationIncomplete: {error}; retained staged runtime {}", runtime_dir.display()))?;
                deployment.version = 1;
                deployment.host = HostBinding { path: host.path.clone(), native_id: host.object.clone(), sha256: expected_host_sha256.to_string() };
                deployment.gateway_rules = None;
                self.candidate = candidate;
                let retirement = self.retirement.take().ok_or("vendor retirement plan absent")?;
                staged_host = Some(host);
                VendorRuntimeRecord::QualifiedPackage { source_path: source.path.clone(), source_native_id: source.object.clone(),
                    source_sha256: expected_host_sha256.to_string(), helper_sha256: assets.helper_digest().to_owned(), retirement }
            }
        };
        let dir = self.authority.evidence_dir("vendor-update")?;
        let host = deployment.host.path.to_str().ok_or("runtime host encoding")?;
        deployment.hook.member_sha256 = desktop_hook::gui_member_digest(&self.candidate.bytes, host).map_err(|e| e.to_string())?;
        let receipt_path = dir.join("vendor-runtime-deployment.json");
        deployment.receipt.path = receipt_path.strip_prefix(&self.authority.slot.path).map_err(|_| "vendor receipt outside slot")?
            .to_str().ok_or("vendor receipt encoding")?.replace('\\', "/");
        deployment.receipt.digest = hash(&json(&deployment.receipt())?);
        let intent = VendorUpdateIntent {
            schema: if runtime_input.is_reuse() { 3 } else { 4 }, slot_id: self.authority.current.slot_id.clone(), operation_id: self.id.clone(),
            expected_current_digest: self.authority.digest.clone(), prior_current: self.authority.retain_current()?,
            new_binding: self.new_binding.clone(), pristine: self.authority.save(&dir, "vendor-pristine", &self.bound.bytes)?,
            candidate: self.authority.save(&dir, "vendor-candidate", &self.candidate.bytes)?,
            apply_layout: self.apply_layout.clone(), deployment: deployment.clone(), runtime_input,
        };
        let intent_ref = self.authority.save(&dir, "intent.json", &json(&intent)?)?;
        let op = Operation { id: self.id.clone(), kind: OperationKind::VendorUpdate,
            intent: intent_ref, prior_current_digest: self.authority.digest.clone() };
        let mut pending = self.authority.current.clone();
        pending.revision = pending.revision.checked_add(1).ok_or("revision overflow")?;
        pending.mode = Mode::Pending;
        pending.settled = None;
        pending.active_operation = Some(op.clone());
        self.authority.publish(pending)?;
        let mut window = ContextWindow { context: self.bound.ancestor_context.as_ref(), window: self.window };
        let retirement_steps = match &intent.runtime_input {
            VendorRuntimeRecord::ReuseReceivedRuntime => Vec::new(),
            VendorRuntimeRecord::QualifiedPackage { retirement, .. } => gateway_rules::execute_vendor_retirement(
                &self.bound, &self.authority, &dir, retirement, &mut runner, &mut window, cancel).map_err(|e| e.to_string())?,
        };
        if cancel.load(Ordering::SeqCst) { return Err("RecoveryRequired: vendor update cancelled after Pending; no archive call".into()); }
        if let Some(host) = &staged_host { host.recheck()?; }
        let host_path = deployment.host.path.to_str().ok_or("runtime host encoding")?;
        let (step_ref, step) = run_step(&self.bound, &self.authority, &dir, &op.id, "apply-v2",
            &intent.apply_layout, None, desktop_hook::HookProfile::GuiHost(host_path),
            Some((&intent.new_binding, &self.candidate.bytes)), &mut window)?;
        publish_vendor_result(&self.bound, &mut self.authority, &op, &intent, step_ref, step.into(),
            retirement_steps, &mut runner, cancel, &mut window)?;
        let current_sha256: [u8; 32] = hex::decode(&self.authority.digest).map_err(|_| "current digest encoding")?
            .try_into().map_err(|_| "current digest length")?;
        Ok(VendorUpdateCompletion { slot_id: self.authority.current.slot_id.clone(), current_sha256 })
        })();
        result.map_err(|error| match retained_stage {
            Some(path) => format!("{error}; staged runtime retained at {}", path.display()),
            None => error,
        })
    }
}

fn publish_vendor_result<W: MaintenanceWindow>(bound: &BoundInstallation, authority: &mut Authority,
    op: &Operation, intent: &VendorUpdateIntent, step_ref: EvidenceRef, step: VendorReceivedApply,
    retirement_steps: Vec<EvidenceRef>, runner: &mut Option<&mut dyn gateway_rules::GatewayRuleRunner>,
    cancel: &AtomicBool, window: &mut W) -> Result<()> {
    let actual = check_actual_target(bound, &step.target, &step.native_id)?;
    window.ensure_held()?;
    let received = BoundInstallation::open(&bound.exe.path)?;
    let binding = received.binding()?;
    if binding.parent != intent.new_binding.parent || binding.root != intent.new_binding.root
        || binding.resources != intent.new_binding.resources || binding.executable != intent.new_binding.executable
        || binding.executable_digest != intent.new_binding.executable_digest
        || binding.archive != step.native_id || binding.archive_digest != actual.digest
        || binding.archive_metadata != actual.identity {
        return Err("RecoveryRequired: vendor result incarnation changed".into());
    }
    let applied = step.applied.as_ref().ok_or("vendor actual apply receipt absent")?;
    let host = intent.deployment.host.path.to_str().ok_or("runtime host encoding")?;
    verify_applied_profile(&received, applied, desktop_hook::HookProfile::GuiHost(host))?;
    let dir = operation_dir(&authority.slot, &op.intent)?;
    let retirement_final_checks = if let VendorRuntimeRecord::QualifiedPackage { retirement, .. } = &intent.runtime_input {
        gateway_rules::receive_vendor_retirement(&authority.slot, &dir, retirement, &retirement_steps)?;
        window.ensure_held()?;
        gateway_rules::recheck_vendor_retirement(authority, &dir, retirement, runner, cancel).map_err(|e| e.to_string())?
    } else if !retirement_steps.is_empty() {
        return Err("RecoveryRequired: reused runtime has unexpected retirement evidence".into());
    } else { Vec::new() };
    receive_deployment(authority, &intent.deployment, &actual)?;
    let outcome = VendorUpdateOutcome { slot_id: intent.slot_id.clone(), operation_id: op.id.clone(),
        intent: op.intent.clone(), step: step_ref, retirement_steps, retirement_final_checks };
    let bytes = json(&Settlement::VendorUpdate(outcome))?;
    let evidence = match optional_reference(&authority.slot, &dir.join("outcome.json"))? {
        Some(value) if reference(&authority.slot, &value)? == bytes => value,
        Some(_) => return Err("RecoveryRequired: vendor settlement evidence conflict".into()),
        None => authority.save(&dir, "outcome.json", &bytes)?,
    };
    let mut current = authority.current.clone();
    current.revision = current.revision.checked_add(1).ok_or("revision overflow")?;
    current.mode = Mode::SettledApplied;
    current.active_operation = None;
    current.binding = binding;
    current.runtime_deployment = DeploymentField::Present(Some(intent.deployment.clone()));
    current.settled = Some(Settled { target: step.target.clone(), applied: step.applied.clone(), evidence });
    super::receive_settlement(&authority.slot, &current)?;
    window.ensure_held()?;
    check_actual_target(bound, &step.target, &step.native_id)?;
    authority.publish(current)
}

pub(super) fn recover_vendor_update<W: MaintenanceWindow>(bound: BoundInstallation, mut authority: Authority,
    op: Operation, gateway: Option<GatewayRecoveryContext<'_>>, window: &mut W) -> Result<String> {
    let intent = receive_vendor_intent(&authority.slot, &op.intent)?;
    let prior: Current = decode(&reference(&authority.slot, &intent.prior_current)?)?;
    let actual = bound.binding()?;
    if !ordinal(&prior.locator, &bound.root.locator)? || actual.parent != intent.new_binding.parent
        || actual.root != intent.new_binding.root || actual.resources != intent.new_binding.resources
        || actual.executable != intent.new_binding.executable || actual.executable_digest != intent.new_binding.executable_digest {
        return Err("RecoveryRequired: selected vendor incarnation changed".into());
    }
    let dir = operation_dir(&authority.slot, &op.intent)?;
    let retirement_steps = match &intent.runtime_input {
        VendorRuntimeRecord::ReuseReceivedRuntime => Vec::new(),
        VendorRuntimeRecord::QualifiedPackage { retirement, .. } => gateway_rules::retained_vendor_retirement(
            &authority.slot, &dir, retirement)?,
    };
    let never_cancel = AtomicBool::new(false);
    let (mut runner, cancel) = match gateway {
        Some(context) => (Some(context.runner), context.cancel),
        None => (None, &never_cancel),
    };
    let mut qualified = ContextWindow { context: bound.ancestor_context.as_ref(), window };
    let (step_ref, step) = match optional_reference(&authority.slot, &dir.join("apply-v2-outcome.json"))? {
        Some(value) => {
            let received = receive_vendor_apply(&authority.slot, &value, &op.intent, &intent)?;
            (value, received)
        }
        None => resolve_vendor_group_metadata(&bound, &authority, &op, &intent, cancel, &mut qualified)?,
    };
    group_checkpoint("before-publish")?;
    publish_vendor_result(&bound, &mut authority, &op, &intent, step_ref, step,
        retirement_steps, &mut runner, cancel, &mut qualified)?;
    group_checkpoint("after-publish")?;
    Ok("RecoverySettled: vendor operation received; capable runtime/background delivery remains an ordinary Apply obligation".into())
}

/// Fresh/pristine/reverted input reaches V2 without a dummy V1 native operation.
pub(crate) fn upgrade_runtime<W: MaintenanceWindow>(
    bound: BoundInstallation,
    host_source: &CheckedPath,
    expected_host_sha256: &str,
    assets: &PackageAssets,
    parent: Option<&Path>,
    window: &mut W,
) -> Result<()> {
    let chosen = workspace_r0(&bound, parent)?;
    let mut authority = Authority::open(&bound, true, false)?;
    match (
        &authority.current.mode,
        &authority.current.runtime_deployment,
    ) {
        (Mode::SettledApplied, DeploymentField::Present(Some(_))) => {
            return Err("AlreadyApplied: received V2 runtime installed".into())
        }
        (Mode::SettledApplied | Mode::SettledUnchanged | Mode::SettledReverted, _) => {}
        _ => {
            return Err(
                "MaintenanceRequired: received pristine/reverted/legacy input required".into(),
            )
        }
    }
    let prior_applied = authority
        .current
        .settled
        .as_ref()
        .and_then(|s| s.applied.clone());
    let original = if let Some(record) = &prior_applied {
        verify_applied(&bound, record)?;
        read_path(&record.original_backup, READ)?
    } else {
        read_path(&bound.archive.path, READ | DELETE)?
    };
    host_source.recheck()?;
    assets.recheck()?;
    let host_bytes = host_source.read_snapshot()?;
    if hash(&host_bytes) != expected_host_sha256 {
        return Err("runtime source content binding differs".into());
    }
    window.ensure_held()?;
    let dir = authority.evidence_dir("runtime-upgrade")?;
    let gate_id =
        match retained_deployment(&authority.slot, &authority.current)? {
            Some(value) => {
                authority.runtime_write =
                    Some(runtime_gate::write(&authority.slot, &value.gate.native_id)?);
                value.gate.native_id
            }
            None => {
                let (writer, id) = runtime_gate::initialize(&authority.slot)?;
                authority.runtime_write = Some(writer);
                authority.save(&dir, "gate-bootstrap.json", &json(&serde_json::json!({
                "schema":3, "slotId":authority.current.slot_id, "nativeId":id,
                "purpose":"exclusive preintent runtime gate bootstrap; not applied authority"
            }))?)?;
                id
            }
        };
    let id = unique_id()?;
    let deployment_dir = authority.slot.path.join(format!("runtime-{id}"));
    create_private_dir(&deployment_dir)?;
    let host_path = deployment_dir.join("ag_unlocker.exe");
    write_private(&host_path, &host_bytes)?;
    assets.deploy(&deployment_dir)?;
    let host = CheckedPath::open(&host_path, PathKind::File, PathPurpose::Executable)?;
    private(&host.file)?;
    if host.read_snapshot()? != host_bytes {
        return Err("runtime host readback differs".into());
    }
    let host_text = host.path.to_str().ok_or("runtime host encoding")?;
    let prepared =
        desktop_hook::prepare_gui_archive(&original.bytes, host_text).map_err(|e| e.to_string())?;
    let workspace = match chosen {
        Some(value) => value,
        None => CheckedPath::open(
            &authority.slot.path,
            PathKind::Directory,
            PathPurpose::Review,
        )?,
    };
    let revert_layout = if prior_applied.is_some() {
        Some(layout(&bound, &workspace, &id, "revert-v1")?)
    } else {
        None
    };
    let apply_layout = layout(&bound, &workspace, &id, "apply-v2")?;
    let receipt_path = dir.join("runtime-deployment.json");
    let mut deployment = RuntimeDeployment {
        version: 1,
        gateway_rules: None,
        gate: GateBinding {
            name: "runtime-gate".into(),
            native_id: gate_id,
        },
        host: HostBinding {
            path: host.path.clone(),
            native_id: host.object.clone(),
            sha256: expected_host_sha256.into(),
        },
        hook: HookBinding {
            revision: "wsl-gui-v2".into(),
            member_sha256: desktop_hook::gui_member_digest(&prepared.bytes, host_text)
                .map_err(|e| e.to_string())?,
        },
        receipt: EvidenceRef {
            path: receipt_path
                .strip_prefix(&authority.slot.path)
                .map_err(|_| "receipt location")?
                .to_str()
                .ok_or("receipt encoding")?
                .replace('\\', "/"),
            digest: String::new(),
        },
    };
    deployment.receipt.digest = hash(&json(&deployment.receipt())?);
    deployment.validate_shape()?;
    let intent = UpgradeIntent {
        schema: 3,
        slot_id: authority.current.slot_id.clone(),
        operation_id: id.clone(),
        expected_current_digest: authority.digest.clone(),
        prior_current: authority.retain_current()?,
        prior_applied,
        proposed_runtime_deployment: deployment.clone(),
        pristine: authority.save(&dir, "pristine", &original.bytes)?,
        candidate: authority.save(&dir, "candidate", &prepared.bytes)?,
        revert_layout,
        apply_layout,
    };
    let value = authority.save(&dir, "intent.json", &json(&intent)?)?;
    let operation = Operation {
        id,
        kind: OperationKind::UpgradeRuntime,
        intent: value,
        prior_current_digest: authority.digest.clone(),
    };
    let mut pending = authority.current.clone();
    pending.schema = 3;
    pending.revision = pending.revision.checked_add(1).ok_or("revision overflow")?;
    pending.mode = Mode::Pending;
    pending.settled = None;
    pending.runtime_deployment = DeploymentField::Present(Some(deployment));
    pending.active_operation = Some(operation.clone());
    authority.publish(pending)?;
    let mut qualified = ContextWindow {
        context: bound.ancestor_context.as_ref(),
        window,
    };
    continue_upgrade(&bound, &mut authority, &operation, &mut qualified)
        .map_err(|error| format!("runtime gate/deployment evidence retained: {error}"))
}

pub(super) fn recover<W: MaintenanceWindow>(
    bound: BoundInstallation,
    mut authority: Authority,
    operation: Operation,
    window: &mut W,
) -> Result<String> {
    let mut qualified = ContextWindow {
        context: bound.ancestor_context.as_ref(),
        window,
    };
    qualified.ensure_held()?;
    if operation.kind == OperationKind::RollbackRuntime {
        continue_rollback(&bound, &mut authority, &operation, &mut qualified)?;
    } else {
        let intent = receive_intent(&authority.slot, &operation.intent)?;
        check_incarnation(&bound, &authority.slot, &intent)?;
        let dir = operation_dir(&authority.slot, &operation.intent)?;
        let name = if intent.prior_applied.is_some() {
            "revert-v1"
        } else {
            "apply-v2"
        };
        if let Some(failure) =
            optional_reference(&authority.slot, &dir.join(format!("{name}-failure.json")))?
        {
            receive_no_call(&authority.slot, &intent, &failure)?;
            let prior: Current = decode(&reference(&authority.slot, &intent.prior_current)?)?;
            let actual = read_path(&bound.archive.path, READ | DELETE)?;
            if bound.binding()? != prior.binding
                || object_state(&actual)
                    != prior.settled.as_ref().ok_or("prior state absent")?.target
            {
                return Err("RecoveryRequired: no-call actual prior state differs".into());
            }
            let layout = intent
                .revert_layout
                .as_ref()
                .unwrap_or(&intent.apply_layout);
            if !work_absent(&observe_all(&bound.archive.path, layout)) {
                return Err("RecoveryRequired: no-call native outputs present".into());
            }
            let result = StepOutcome {
                schema: 3,
                step: name.into(),
                intent: operation.intent.clone(),
                native_call: NativeCall::NotCalled,
                target: object_state(&actual),
                native_id: bound.archive.object.clone(),
                applied: intent.prior_applied,
            };
            let outcome = UpgradeOutcome::NoNativeCall {
                slot_id: authority.current.slot_id.clone(),
                operation_id: operation.id,
                intent: operation.intent,
                failure,
            };
            publish_result(
                &bound,
                &mut authority,
                outcome,
                &result,
                None,
                prior.mode,
                &mut qualified,
            )?;
        } else {
            continue_upgrade(&bound, &mut authority, &operation, &mut qualified)?;
        }
    }
    Ok("RecoverySettled: actual fixed runtime steps received; immutable prior/native evidence retained".into())
}

fn continue_rollback<W: MaintenanceWindow>(
    bound: &BoundInstallation,
    authority: &mut Authority,
    operation: &Operation,
    window: &mut W,
) -> Result<()> {
    let intent = receive_rollback(&authority.slot, &operation.intent)?;
    let upgrade = receive_intent(&authority.slot, &intent.upgrade_intent)?;
    check_incarnation(bound, &authority.slot, &upgrade)?;
    let _host = pin_deployment_host(authority, &upgrade.proposed_runtime_deployment)?;
    let dir = operation_dir(&authority.slot, &operation.intent)?;
    let mut steps = Vec::new();
    if optional_reference(&authority.slot, &dir.join("restore-v1-outcome.json"))?.is_none() {
        let source: StepOutcome = decode(&reference(&authority.slot, &intent.source)?)?;
        if let Some(layout) = &intent.revert_layout {
            if optional_reference(&authority.slot, &dir.join("revert-v2-outcome.json"))?.is_none() {
                check_actual(bound, &source)?;
            }
            let host = upgrade
                .proposed_runtime_deployment
                .host
                .path
                .to_str()
                .ok_or("runtime host encoding")?;
            let (value, result) = run_step(
                bound,
                authority,
                &dir,
                &operation.id,
                "revert-v2",
                layout,
                Some(source.applied.as_ref().ok_or("actual V2 receipt absent")?),
                desktop_hook::HookProfile::GuiHost(host),
                None,
                window,
            )?;
            check_pristine(&authority.slot, &upgrade, &check_actual(bound, &result)?)?;
            steps.push(value);
        } else {
            check_pristine(&authority.slot, &upgrade, &check_actual(bound, &source)?)?;
        }
    } else if intent.revert_layout.is_some() {
        steps.push(
            optional_reference(&authority.slot, &dir.join("revert-v2-outcome.json"))?
                .ok_or("V2 result absent")?,
        );
    }
    let (value, result) = run_step(
        bound,
        authority,
        &dir,
        &operation.id,
        "restore-v1",
        &intent.apply_layout,
        None,
        desktop_hook::HookProfile::Legacy,
        None,
        window,
    )?;
    steps.push(value);
    let outcome = UpgradeOutcome::RolledBack {
        slot_id: intent.slot_id,
        operation_id: operation.id.clone(),
        intent: operation.intent.clone(),
        steps,
    };
    publish_result(
        bound,
        authority,
        outcome,
        &result,
        None,
        Mode::SettledApplied,
        window,
    )
}

/// Explicit rollback receives a new V1 apply/identity, never old post-ID authority.
pub(crate) fn rollback_runtime<W: MaintenanceWindow>(
    bound: BoundInstallation,
    expected: &str,
    parent: Option<&Path>,
    window: &mut W,
) -> Result<()> {
    let chosen = workspace_r0(&bound, parent)?;
    let mut authority = Authority::open(&bound, false, true)?;
    if authority.digest != expected {
        return Err("RecoveryRequired: rollback expectedCurrentDigest differs".into());
    }
    authority.admit_maintenance_gate()?;
    let upgrade_ref = if authority.current.mode == Mode::Pending {
        let op = authority
            .current
            .active_operation
            .as_ref()
            .ok_or("rollback operation absent")?;
        if op.kind != OperationKind::UpgradeRuntime {
            return Err("rollback requires exact UpgradeRuntime association".into());
        }
        op.intent.clone()
    } else {
        let settled = authority
            .current
            .settled
            .as_ref()
            .ok_or("rollback settlement absent")?;
        match decode::<Settlement>(&reference(&authority.slot, &settled.evidence)?)? {
            Settlement::RuntimeUpgrade(UpgradeOutcome::Applied { intent, .. }) => intent,
            _ => return Err("rollback requires received upgrade settlement".into()),
        }
    };
    let upgrade = receive_intent(&authority.slot, &upgrade_ref)?;
    check_incarnation(&bound, &authority.slot, &upgrade)?;
    let legacy = upgrade
        .prior_applied
        .as_ref()
        .ok_or("rollback has no received prior V1 association")?;
    let old_dir = operation_dir(&authority.slot, &upgrade_ref)?;
    let applied = optional_reference(&authority.slot, &old_dir.join("apply-v2-outcome.json"))?;
    if applied.is_none()
        && optional_reference(&authority.slot, &old_dir.join("apply-v2-intent.json"))?.is_some()
    {
        return Err("RecoveryRequired: V2 call lacks received success; Pending retained".into());
    }
    let (source, source_result, revert_v2) = match applied {
        Some(value) => {
            let result = receive_step(&authority.slot, &value, &upgrade.operation_id, "apply-v2")?;
            (value, result, true)
        }
        None => {
            let value =
                optional_reference(&authority.slot, &old_dir.join("revert-v1-outcome.json"))?
                    .ok_or("RecoveryRequired: no received pristine/V2 rollback source")?;
            let result = receive_step(&authority.slot, &value, &upgrade.operation_id, "revert-v1")?;
            (value, result, false)
        }
    };
    let actual = check_actual(&bound, &source_result)?;
    if !revert_v2 {
        check_pristine(&authority.slot, &upgrade, &actual)?;
    }
    window.ensure_held()?;
    let workspace = match chosen {
        Some(value) => value,
        None => CheckedPath::open(
            &authority.slot.path,
            PathKind::Directory,
            PathPurpose::Review,
        )?,
    };
    let id = unique_id()?;
    let revert_layout = if revert_v2 {
        Some(layout(&bound, &workspace, &id, "revert-v2")?)
    } else {
        None
    };
    let apply_layout = layout(&bound, &workspace, &id, "restore-v1")?;
    let pristine = reference(&authority.slot, &upgrade.pristine)?;
    let candidate = desktop_hook::prepare_archive(&pristine).map_err(|e| e.to_string())?;
    if candidate.post_digest != legacy.post_digest {
        return Err("retained V1 version conflict".into());
    }
    let dir = authority.evidence_dir("runtime-rollback")?;
    let intent = RollbackIntent {
        schema: 3,
        slot_id: authority.current.slot_id.clone(),
        operation_id: id.clone(),
        expected_current_digest: authority.digest.clone(),
        prior_current: authority.retain_current()?,
        upgrade_intent: upgrade_ref,
        source,
        revert_layout,
        apply_layout,
        candidate: authority.save(&dir, "candidate", &candidate.bytes)?,
    };
    let value = authority.save(&dir, "intent.json", &json(&intent)?)?;
    let operation = Operation {
        id,
        kind: OperationKind::RollbackRuntime,
        intent: value,
        prior_current_digest: authority.digest.clone(),
    };
    let mut pending = authority.current.clone();
    pending.revision = pending.revision.checked_add(1).ok_or("revision overflow")?;
    pending.mode = Mode::Pending;
    pending.settled = None;
    pending.active_operation = Some(operation.clone());
    pending.runtime_deployment =
        DeploymentField::Present(Some(upgrade.proposed_runtime_deployment));
    authority.publish(pending)?;
    let mut qualified = ContextWindow {
        context: bound.ancestor_context.as_ref(),
        window,
    };
    continue_rollback(&bound, &mut authority, &operation, &mut qualified)
}

pub(super) fn runtime_installed(bound: &BoundInstallation) -> Result<bool> {
    if capture_current_expectation(bound)?.is_none() {
        let inspected = desktop_hook::inspect_archive(&bound.bytes).map_err(|e| e.to_string())?;
        if inspected.hook_status == desktop_hook::HookStatus::Prepared {
            return Ok(false);
        }
        return Err(
            "UnreceivedInstallation: hooked/unknown target has no canonical authority".into(),
        );
    }
    let authority = Authority::open(bound, false, false)?;
    match (
        &authority.current.mode,
        &authority.current.runtime_deployment,
    ) {
        (Mode::SettledApplied, DeploymentField::Present(Some(deployment))) => {
            let host = deployment
                .host
                .path
                .to_str()
                .ok_or("runtime host encoding")?;
            verify_applied_profile(
                bound,
                authority
                    .current
                    .settled
                    .as_ref()
                    .and_then(|s| s.applied.as_ref())
                    .ok_or("runtime receipt absent")?,
                desktop_hook::HookProfile::GuiHost(host),
            )?;
            deployment.receive_hook(&bound.bytes)?;
            Ok(true)
        }
        (Mode::SettledApplied, _) => {
            verify_applied(
                bound,
                authority
                    .current
                    .settled
                    .as_ref()
                    .and_then(|s| s.applied.as_ref())
                    .ok_or("legacy receipt absent")?,
            )?;
            Ok(false)
        }
        (Mode::SettledUnchanged | Mode::SettledReverted, _) => {
            if desktop_hook::inspect_archive(&bound.bytes)
                .map_err(|e| e.to_string())?
                .hook_status
                != desktop_hook::HookStatus::Prepared
            {
                return Err(
                    "RecoveryRequired: received pristine/reverted archive is not pristine".into(),
                );
            }
            Ok(false)
        }
        _ => Err("MaintenanceRequired: installation is not a received runtime input".into()),
    }
}

#[cfg(test)]
thread_local! {
    pub(super) static TEST_STOP_AFTER_RECEIPT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    static TEST_LOSE_RECEIPT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    static TEST_GROUP_STOP: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[path = "runtime_upgrade_tests.rs"]
mod tests;
