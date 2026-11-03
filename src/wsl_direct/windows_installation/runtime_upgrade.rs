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
    bound.revalidate_context()?;
    let target = read_path(&bound.archive.path, READ | DELETE)?;
    if object_state(&target) != outcome.target
        || object_id(&open_regular(&target.target, READ | DELETE)?)? != outcome.native_id
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
    static TEST_STOP_AFTER_RECEIPT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    static TEST_LOSE_RECEIPT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[path = "runtime_upgrade_tests.rs"]
mod tests;
