//! Firewall deployment and custody belong to the installation slot. The caller
//! supplies native execution; this module never imports the application runner.
use super::runtime_deployment::{HostBinding, RuntimeDeployment};
use super::*;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

/// The fixed policy is shared by planning, runtime receiving and retirement.
pub(crate) const GATEWAY_RULE_PROFILES: u32 = 6;

/// Read-only facts for Core's whole-Apply merge, never a write/runtime permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GatewayRuleRequirements {
    pub(crate) canonical_install_needed: bool,
    pub(crate) rules: GatewayRuleEffect,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GatewayRuleEffect {
    VerifiedNoop,
    CanonicalCommitOnly,
    NativeWriteRequired { administrator: bool },
}

/// Core supplies freshly received WSL namespaces and actual global native
/// profile/admin facts from its existing read-only requirement collection.
/// An empty/missing wanted set cannot silently become TransportNotWanted.
pub(crate) enum GatewayRequirementNamespaces<'a> {
    TransportNotWanted,
    TransportWanted {
        namespaces: &'a [GatewayNamespace],
        active_profiles: u32,
        administrator: bool,
    },
}

/// Only the constructors below can produce either received input. Neither
/// variant names a hypothetical destination or carries a future native ID.
pub(crate) enum GatewayHostInput {
    Bound(GatewayBoundHost),
    NewDeployment(GatewayNewDeployment),
    VendorPrerequisite(GatewayVendorPrerequisite),
}
pub(crate) struct GatewayVendorPrerequisite {
    source: CheckedPath,
    source_sha256: String,
    state: RequirementState,
    prior: RuntimeDeployment,
    selection: Option<GatewayRetirementSelectionV1>,
}
pub(crate) struct GatewayBoundHost {
    host: CheckedPath,
    state: RequirementState,
    deployment: RuntimeDeployment,
    _read: runtime_gate::ReadGate,
}
pub(crate) struct GatewayNewDeployment {
    source: CheckedPath,
    source_sha256: String,
    state: RequirementState,
}
struct RequirementState {
    binding: Binding,
    known: CheckedPath,
    _namespace: Option<CheckedPath>,
    _slot_lease: Option<Lease>,
    received: Option<(CheckedPath, Current, String)>,
    vendor: Option<VendorUpdateObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayNamespace {
    pub(crate) interface_index: u32,
    pub(crate) interface_alias: String,
    pub(crate) local_address: Ipv4Addr,
    pub(crate) source_address: Ipv4Addr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayRuleScope {
    pub(crate) host: HostBinding,
    pub(crate) namespace: GatewayNamespace,
}

/// Intended NetSecurity parameters, produced only by this policy owner. The
/// caller serializes these actual parameters rather than repeating defaults.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GatewayRuleParameters {
    pub(crate) program: PathBuf,
    pub(crate) enabled: bool,
    pub(crate) direction: String,
    pub(crate) action: String,
    pub(crate) protocol: String,
    pub(crate) local_ports: Vec<String>,
    pub(crate) remote_ports: Vec<String>,
    pub(crate) local_addresses: Vec<String>,
    pub(crate) remote_addresses: Vec<String>,
    pub(crate) interface_aliases: Vec<String>,
    pub(crate) interface_types: Vec<String>,
    pub(crate) profiles: u32,
    pub(crate) edge_traversal: String,
    pub(crate) service: String,
    pub(crate) package: String,
    pub(crate) local_users: String,
    pub(crate) remote_users: String,
    pub(crate) remote_machines: String,
    pub(crate) authentication: String,
    pub(crate) encryption: String,
    pub(crate) override_block_rules: bool,
}
impl GatewayRuleScope {
    pub(crate) fn creation_parameters(&self) -> GatewayRuleParameters {
        GatewayRuleParameters {
            program: self.host.path.clone(),
            enabled: true,
            direction: "Inbound".into(),
            action: "Allow".into(),
            protocol: "TCP".into(),
            local_ports: vec!["Any".into()],
            remote_ports: vec!["Any".into()],
            local_addresses: vec![self.namespace.local_address.to_string()],
            remote_addresses: vec![self.namespace.source_address.to_string()],
            interface_aliases: vec![self.namespace.interface_alias.clone()],
            interface_types: vec!["Any".into()],
            profiles: GATEWAY_RULE_PROFILES,
            edge_traversal: "Block".into(),
            service: "Any".into(),
            package: "Any".into(),
            local_users: "Any".into(),
            remote_users: "Any".into(),
            remote_machines: "Any".into(),
            authentication: "NotRequired".into(),
            encryption: "NotRequired".into(),
            override_block_rules: false,
        }
    }
}

/// All fields are actual native observations, not defaulted desired values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayNativeRule {
    pub(crate) name: String,
    #[serde(deserialize_with = "required_option")]
    pub(crate) instance_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) policy_store_source: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) policy_store_source_type: Option<String>,
    pub(crate) enabled: bool,
    pub(crate) direction: String,
    pub(crate) action: String,
    pub(crate) program: PathBuf,
    pub(crate) protocol: String,
    pub(crate) local_ports: Vec<String>,
    pub(crate) remote_ports: Vec<String>,
    pub(crate) local_addresses: Vec<String>,
    pub(crate) remote_addresses: Vec<String>,
    pub(crate) interface_aliases: Vec<String>,
    pub(crate) interface_types: Vec<String>,
    pub(crate) profiles: u32,
    pub(crate) edge_traversal: String,
    pub(crate) service: String,
    pub(crate) package: String,
    pub(crate) local_users: String,
    pub(crate) remote_users: String,
    pub(crate) remote_machines: String,
    pub(crate) authentication: String,
    pub(crate) encryption: String,
    pub(crate) override_block_rules: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "detail",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum GatewayPolicyObservation {
    Allowed,
    ExplicitBlock(String),
    PolicyDenied(String),
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayRuleInspection {
    pub(crate) administrator: bool,
    pub(crate) active_profiles: u32,
    #[serde(deserialize_with = "required_option")]
    pub(crate) namespace: Option<GatewayNamespace>,
    pub(crate) policy: GatewayPolicyObservation,
    pub(crate) persistent: Vec<GatewayNativeRule>,
    pub(crate) active: Vec<GatewayNativeRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) active_enforcement: Option<Vec<ActiveRuleEnforcement>>,
}

/// Volatile same-row ActiveStore facts. Never part of an immutable V1 rule
/// snapshot or proof of ownership; absent historical facts remain Unknown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActiveRuleEnforcement {
    pub(crate) name: String,
    pub(crate) instance_id: Option<String>,
    pub(crate) primary_status: Option<u16>,
    pub(crate) enforcement_status: Option<Vec<u16>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "detail",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum GatewayDispatch {
    NotStarted(String),
    Started {
        attempt_id: String,
        process_id: u32,
        #[serde(deserialize_with = "required_option")]
        creation_time: Option<u64>,
        #[serde(deserialize_with = "required_option")]
        image: Option<PathBuf>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "detail",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum GatewayExecution {
    NotStarted,
    Pending,
    Exited { code: Option<i32> },
    ObservationError(String),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "detail",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum GatewayCaptureState {
    NotStarted,
    Pending,
    Complete,
    Failed(String),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayCapture {
    pub(crate) bytes: Vec<u8>,
    pub(crate) reader: GatewayCaptureState,
    pub(crate) truncated: bool,
    pub(crate) finalization: GatewayCaptureState,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "detail",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum GatewayFailureKind {
    MissingConfiguration,
    Permission,
    Policy,
    Capture,
    Native,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "detail",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum GatewayActionReport {
    NotInvoked,
    ReturnedSuccess,
    ReturnedFailure {
        kind: GatewayFailureKind,
        message: String,
    },
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayNativeOutcome {
    pub(crate) dispatch: GatewayDispatch,
    pub(crate) execution: GatewayExecution,
    pub(crate) stdout: GatewayCapture,
    pub(crate) stderr: GatewayCapture,
    pub(crate) action: GatewayActionReport,
    #[serde(deserialize_with = "required_option")]
    pub(crate) inspection: Option<GatewayRuleInspection>,
}

/// Inspect(None) is preparation-only discovery of concrete external rules.
/// Inspect(Some) and Remove must query the exact name in both policy stores.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum GatewayRuleRequest {
    Inspect {
        scope: GatewayRuleScope,
        name: Option<String>,
    },
    InspectOwned {
        scope: GatewayRuleScope,
        name: String,
    },
    Create {
        scope: GatewayRuleScope,
        name: String,
    },
    Remove {
        scope: GatewayRuleScope,
        persistent: GatewayNativeRule,
        active: GatewayNativeRule,
    },
}

/// The upper owner retains every Child/reader and any still-pending attempt.
/// It calls record after each acquired outcome, before further native effects.
/// A record error forbids subsequent effects; it does not erase the outcome or
/// release unretired resources. Return the actual final/current outcome even
/// when execution, capture, cancellation or persistence has failed.
pub(crate) trait GatewayRuleRunner {
    fn run(
        &mut self,
        request: &GatewayRuleRequest,
        cancel: &AtomicBool,
        record: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>,
    ) -> GatewayNativeOutcome;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GatewayRuleError {
    NeedsElevation,
    CancelledBeforeMutation,
    MissingConfiguration(String),
    Permission(String),
    Policy(String),
    Capture(String),
    RecoveryRequired(String),
    NativeUnsettled {
        outcome: Box<GatewayNativeOutcome>,
        reason: String,
    },
    Invalid(String),
}
impl std::fmt::Display for GatewayRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NativeUnsettled { reason, .. } => write!(
                f,
                "RecoveryRequired: {reason}; native outcome retained; Pending preserved"
            ),
            _ => write!(f, "{self:?}"),
        }
    }
}
impl From<String> for GatewayRuleError {
    fn from(value: String) -> Self {
        Self::RecoveryRequired(value)
    }
}
impl From<&str> for GatewayRuleError {
    fn from(value: &str) -> Self { Self::RecoveryRequired(value.into()) }
}
type GatewayResult<T> = std::result::Result<T, GatewayRuleError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum RuleCustody {
    CreatedByOperation,
    ObservedExternal,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GatewayRuleReceiptV1 {
    version: u32,
    operation_id: String,
    intended_name: String,
    actual_name: String,
    ownership: RuleCustody,
    scope: GatewayRuleScope,
    persistent: GatewayNativeRule,
    active: GatewayNativeRule,
    readback: EvidenceRef,
    #[serde(deserialize_with = "required_option")]
    creation: Option<EvidenceRef>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum GatewayOperation {
    Configure,
    Retire,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum RuleAction {
    Reuse,
    ObserveExternal,
    Create,
    Remove,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RulePlan {
    scope: GatewayRuleScope,
    name: String,
    action: RuleAction,
    #[serde(deserialize_with = "required_option")]
    receipt: Option<EvidenceRef>,
    #[serde(deserialize_with = "required_option")]
    observation: Option<GatewayRuleInspection>,
}

/// The existing rule owner retains all evidence for rules retired as part of
/// a vendor-update operation. Observed external rules are not removal plans.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct VendorRetirementPlan {
    plans: Vec<RulePlan>,
    #[serde(default, skip_serializing_if = "VendorRetirementAdmission::is_exact")]
    admission: VendorRetirementAdmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GatewayRetirementSelectionV1 {
    pub(crate) version: u32,
    pub(crate) operation: GatewayRetirementSelectionOperation,
    pub(crate) slot_id: String,
    pub(crate) prior_current_sha256: String,
    pub(crate) new_binding_sha256: String,
    pub(crate) saved_settings_sha256: String,
    old_host: HostBinding,
    receipt: EvidenceRef,
    persistent: GatewayNativeRule,
    active: GatewayNativeRule,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum GatewayRetirementSelectionOperation { RetireObservedInterfaceAliases }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum VendorRetirementAdmission { ExactReceipt {}, AcknowledgedInterfaceAliases { selection: GatewayRetirementSelectionV1 } }
impl Default for VendorRetirementAdmission { fn default() -> Self { Self::ExactReceipt {} } }
impl VendorRetirementAdmission { fn is_exact(&self) -> bool { matches!(self, Self::ExactReceipt {}) } }
pub(super) fn validate_vendor_selection_context(plan: &VendorRetirementPlan, slot: &str, prior: &str, binding: &Binding) -> Result<()> {
    if let VendorRetirementAdmission::AcknowledgedInterfaceAliases { selection } = &plan.admission {
        let valid = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if selection.version != 1 || selection.slot_id != slot || selection.prior_current_sha256 != prior
            || selection.new_binding_sha256 != hash(&json(binding)?) || !valid(&selection.saved_settings_sha256) {
            return Err("RecoveryRequired: vendor retirement selection context differs".into());
        }
    }
    Ok(())
}

impl GatewayRetirementSelectionV1 {
    pub(crate) fn validate_binding(&self, expected: &VendorUpdateObservation, saved: &[u8; 32]) -> Result<()> {
        let digest = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if self.version != 1 || !id_valid(&self.slot_id)
            || !digest(&self.prior_current_sha256) || !digest(&self.new_binding_sha256) || !digest(&self.saved_settings_sha256)
            || self.slot_id != expected.slot_id || self.prior_current_sha256 != hex::encode(expected.prior_current_sha256)
            || self.new_binding_sha256 != hex::encode(expected.new_binding_sha256) || self.saved_settings_sha256 != hex::encode(saved) {
            return Err("gateway retirement selection binding differs".into());
        }
        Ok(())
    }
}

fn receive_vendor_pair<'a>(receipt: &GatewayRuleReceiptV1, reference: &EvidenceRef,
    observation: &'a GatewayRuleInspection, selection: Option<&GatewayRetirementSelectionV1>)
    -> GatewayResult<(&'a GatewayNativeRule, &'a GatewayNativeRule)> {
    receive_historical_environment(&receipt.scope, observation)?;
    let selected = selection.filter(|value| &value.receipt == reference);
    if selected.is_none() {
        let pair = receive_pair(&receipt.scope, &receipt.actual_name, observation)?;
        if pair.0 != &receipt.persistent || pair.1 != &receipt.active {
            return Err(GatewayRuleError::MissingConfiguration("changed owned gateway rule preserved".into()));
        }
        return Ok(pair);
    }
    let selected = selected.unwrap();
    if receipt.ownership != RuleCustody::CreatedByOperation || selected.old_host != receipt.scope.host
        || observation.persistent.len() != 1 || observation.active.len() != 1
        || observation.persistent[0] != selected.persistent || observation.active[0] != selected.active
        || selected.persistent.interface_aliases.is_empty() || selected.persistent.interface_aliases != selected.active.interface_aliases
        || (selected.persistent.interface_aliases == receipt.persistent.interface_aliases
            && selected.active.interface_aliases == receipt.active.interface_aliases) {
        return Err(GatewayRuleError::MissingConfiguration("selected retirement preimage differs".into()));
    }
    for (original, actual) in [(&receipt.persistent, &selected.persistent), (&receipt.active, &selected.active)] {
        if actual.instance_id.as_deref().is_none_or(str::is_empty)
            || actual.policy_store_source.as_deref().is_none_or(str::is_empty)
            || actual.policy_store_source_type.as_deref().is_none_or(str::is_empty) {
            return Err(GatewayRuleError::MissingConfiguration("selected retirement identity unavailable".into()));
        }
        let mut restored = actual.clone(); restored.interface_aliases = original.interface_aliases.clone();
        if &restored != original {
            return Err(GatewayRuleError::MissingConfiguration("selected retirement differs beyond acknowledged aliases".into()));
        }
    }
    Ok((&observation.persistent[0], &observation.active[0]))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct VendorRetirementStep {
    mutation: EvidenceRef,
    readback: EvidenceRef,
}

pub(super) fn plan_vendor_retirement(
    authority: &Authority,
    mut runner: Option<&mut dyn GatewayRuleRunner>,
    selection: Option<&GatewayRetirementSelectionV1>,
    cancel: &AtomicBool,
) -> GatewayResult<VendorRetirementPlan> {
    let deployment = authority.current.runtime_deployment.received()?;
    let mut plans = Vec::new();
    for value in deployment.gateway_rules.as_deref().unwrap_or(&[]) {
        let receipt = receive_receipt(&authority.slot, &deployment.host, value)?;
        if receipt.ownership != RuleCustody::CreatedByOperation { continue; }
        if cancel.load(Ordering::SeqCst) { return Err(GatewayRuleError::CancelledBeforeMutation); }
        let active_runner = runner.as_deref_mut().ok_or_else(|| GatewayRuleError::MissingConfiguration(
            "gateway runner required to retire owned prior-host rules".into()))?;
        let inspection = inspect_owned(active_runner, &receipt.scope, &receipt.actual_name, cancel)?;
        receive_vendor_pair(&receipt, value, &inspection, selection)?;
        if !inspection.administrator { return Err(GatewayRuleError::NeedsElevation); }
        plans.push(RulePlan { scope: receipt.scope, name: receipt.actual_name, action: RuleAction::Remove,
            receipt: Some(value.clone()), observation: Some(inspection) });
    }
    let admission = match selection { Some(selection) => VendorRetirementAdmission::AcknowledgedInterfaceAliases { selection: selection.clone() }, None => VendorRetirementAdmission::ExactReceipt {} };
    let plan = VendorRetirementPlan { plans, admission };
    validate_vendor_retirement(&authority.slot, deployment, &plan)?;
    Ok(plan)
}

pub(super) fn validate_vendor_retirement(slot: &CheckedPath, old: &RuntimeDeployment,
    plan: &VendorRetirementPlan) -> Result<()> {
    let selection = match &plan.admission { VendorRetirementAdmission::ExactReceipt {} => None,
        VendorRetirementAdmission::AcknowledgedInterfaceAliases { selection } => Some(selection) };
    let mut required = Vec::new();
    for value in old.gateway_rules.as_deref().unwrap_or(&[]) {
        let receipt = receive_receipt(slot, &old.host, value)?;
        if receipt.ownership == RuleCustody::CreatedByOperation { required.push(value.clone()); }
    }
    let mut seen = Vec::new();
    for item in &plan.plans {
        let value = item.receipt.as_ref().ok_or("vendor retirement receipt absent")?;
        if item.action != RuleAction::Remove || !required.contains(value) || seen.contains(value) {
            return Err("RecoveryRequired: vendor retirement custody conflict".into());
        }
        let receipt = receive_receipt(slot, &old.host, value)?;
        let observation = item.observation.as_ref().ok_or("vendor retirement observation absent")?;
        receive_historical_environment(&item.scope, observation).map_err(|e| e.to_string())?;
        receive_vendor_pair(&receipt, value, observation, selection).map_err(|e| e.to_string())?;
        if !observation.administrator || item.scope != receipt.scope || item.name != receipt.actual_name
        {
            return Err("RecoveryRequired: vendor retirement preimage conflict".into());
        }
        seen.push(value.clone());
    }
    if seen.len() != required.len() { return Err("RecoveryRequired: vendor retirement omitted owned rule".into()); }
    if selection.is_some_and(|selected| seen.iter().filter(|value| *value == &selected.receipt).count() != 1) {
        return Err("RecoveryRequired: selected retirement receipt is not unique".into());
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GatewayIntent {
    schema: u32,
    slot_id: String,
    operation_id: String,
    kind: GatewayOperation,
    expected_current_digest: String,
    prior_current: EvidenceRef,
    prior_deployment: RuntimeDeployment,
    plans: Vec<RulePlan>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GatewayAttempt {
    request: GatewayRuleRequest,
    outcome: GatewayNativeOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GatewayOutcome {
    schema: u32,
    slot_id: String,
    operation_id: String,
    intent: EvidenceRef,
    attempts: Vec<EvidenceRef>,
    readbacks: Vec<EvidenceRef>,
    deployment: RuntimeDeployment,
}

/// No Clone: the plan retains its observed canonical incarnation, host pin and
/// read exclusion until consumed or dropped. Elevation is detected before this
/// capability is returned, without publishing Pending.
pub(crate) struct PreparedGatewayRules<'a> {
    bound: &'a BoundInstallation,
    host: &'a CheckedPath,
    authority: Authority,
    read: Option<runtime_gate::ReadGate>,
    id: String,
    kind: GatewayOperation,
    plans: Vec<RulePlan>,
}

fn namespace_shape(namespace: &GatewayNamespace) -> GatewayResult<()> {
    let unicast = |ip: Ipv4Addr| {
        !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
    };
    if namespace.interface_index == 0
        || namespace.interface_alias.is_empty()
        || namespace.interface_alias.chars().any(char::is_control)
        || !unicast(namespace.local_address)
        || !unicast(namespace.source_address)
        || namespace.local_address == namespace.source_address
    {
        return Err(GatewayRuleError::Invalid(
            "exact isolated IPv4/interface scope required".into(),
        ));
    }
    Ok(())
}
fn normalized_namespaces(values: &[GatewayNamespace]) -> GatewayResult<Vec<GatewayNamespace>> {
    let mut result = Vec::new();
    for value in values {
        namespace_shape(value)?;
        if !result.contains(value) {
            result.push(value.clone());
        }
    }
    Ok(result)
}
fn retirement_requested(receipt: &GatewayRuleReceiptV1, still_wanted: &[GatewayNamespace]) -> bool {
    receipt.ownership == RuleCustody::CreatedByOperation
        && !still_wanted.contains(&receipt.scope.namespace)
}
pub(crate) fn active_profiles(profiles: u32) -> GatewayResult<()> {
    if profiles == 0 || profiles & !GATEWAY_RULE_PROFILES != 0 {
        return Err(GatewayRuleError::Policy(
            "active firewall profiles must be a nonempty subset of Private/Public".into(),
        ));
    }
    Ok(())
}
/// Native present typed String-null/default None projects to wire empty.
/// This is scope meaning only; captured snapshots and receipt equality stay raw.
pub(crate) fn package_is_unrestricted(raw: &str) -> bool {
    matches!(raw, "" | "Any")
}
fn exact_rule(rule: &GatewayNativeRule, scope: &GatewayRuleScope) -> Result<bool> {
    let expected = scope.creation_parameters();
    let same_program = ordinal(
        &rule.program.as_os_str().encode_wide().collect::<Vec<_>>(),
        &scope
            .host
            .path
            .as_os_str()
            .encode_wide()
            .collect::<Vec<_>>(),
    )?;
    Ok(!rule.name.is_empty()
        && !rule.name.chars().any(char::is_control)
        && rule.enabled == expected.enabled
        && rule.direction == expected.direction
        && rule.action == expected.action
        && same_program
        && matches!(rule.protocol.as_str(), "TCP" | "6")
        && rule.local_ports == expected.local_ports
        && rule.remote_ports == expected.remote_ports
        && rule.local_addresses == expected.local_addresses
        && rule.remote_addresses == expected.remote_addresses
        && rule.interface_aliases == expected.interface_aliases
        && rule.interface_types == expected.interface_types
        && rule.profiles == expected.profiles
        && rule.edge_traversal == expected.edge_traversal
        && rule.service == expected.service
        && package_is_unrestricted(&rule.package)
        && rule.local_users == expected.local_users
        && rule.remote_users == expected.remote_users
        && rule.remote_machines == expected.remote_machines
        && rule.authentication == expected.authentication
        && rule.encryption == expected.encryption
        && rule.override_block_rules == expected.override_block_rules)
}
fn receive_environment(
    scope: &GatewayRuleScope,
    inspection: &GatewayRuleInspection,
) -> GatewayResult<()> {
    namespace_shape(&scope.namespace)?;
    if inspection.namespace.as_ref() != Some(&scope.namespace) {
        return Err(GatewayRuleError::MissingConfiguration(
            "fresh adapter/address/source scope changed".into(),
        ));
    }
    active_profiles(inspection.active_profiles)?;
    match &inspection.policy {
        GatewayPolicyObservation::Allowed => Ok(()),
        GatewayPolicyObservation::ExplicitBlock(detail)
        | GatewayPolicyObservation::PolicyDenied(detail) => {
            Err(GatewayRuleError::Policy(detail.clone()))
        }
        GatewayPolicyObservation::Unavailable(detail) => {
            Err(GatewayRuleError::Capture(detail.clone()))
        }
    }
}
fn receive_historical_environment(scope: &GatewayRuleScope, inspection: &GatewayRuleInspection) -> GatewayResult<()> {
    namespace_shape(&scope.namespace)?;
    if inspection.namespace.is_some() {
        return receive_environment(scope, inspection);
    }
    if inspection.policy != GatewayPolicyObservation::Unavailable("historical custody inspection; no live transport admission".into())
        || inspection.active_enforcement.is_some() {
        return Err(GatewayRuleError::Capture("historical inspection claims live admission".into()));
    }
    Ok(())
}
fn receive_pair<'a>(
    scope: &GatewayRuleScope,
    name: &str,
    inspection: &'a GatewayRuleInspection,
) -> GatewayResult<(&'a GatewayNativeRule, &'a GatewayNativeRule)> {
    namespace_shape(&scope.namespace)?;
    if inspection.persistent.len() != 1 || inspection.active.len() != 1 {
        return Err(GatewayRuleError::MissingConfiguration(
            "exact rule is missing/ambiguous in PersistentStore or ActiveStore".into(),
        ));
    }
    let (persistent, active) = (&inspection.persistent[0], &inspection.active[0]);
    if persistent.name != name
        || active.name != name
        || !exact_rule(persistent, scope)?
        || !exact_rule(active, scope)?
    {
        return Err(GatewayRuleError::MissingConfiguration(
            "exact rule filters or identity changed; preserved".into(),
        ));
    }
    Ok((persistent, active))
}
fn receive_ready_pair<'a>(
    scope: &GatewayRuleScope,
    name: &str,
    inspection: &'a GatewayRuleInspection,
) -> GatewayResult<(&'a GatewayNativeRule, &'a GatewayNativeRule)> {
    receive_environment(scope, inspection)?;
    let pair = receive_pair(scope, name, inspection)?;
    let effects = inspection.active_enforcement.as_ref().ok_or_else(||
        GatewayRuleError::MissingConfiguration("fresh ActiveStore enforcement is unavailable; rule custody preserved".into()))?;
    if effects.len() != 1 || effects[0].name != pair.1.name || effects[0].instance_id != pair.1.instance_id {
        return Err(GatewayRuleError::MissingConfiguration("fresh enforcement is not uniquely bound to the exact active rule; preserved".into()));
    }
    let effect = &effects[0];
    if effect.primary_status != Some(1) || !effect.enforcement_status.as_ref()
        .is_some_and(|values| !values.is_empty() && values.iter().all(|value| *value == 1)) {
        return Err(GatewayRuleError::MissingConfiguration(format!("gateway rule is not freshly effective: primary={:?}, enforcement={:?}; custody preserved", effect.primary_status, effect.enforcement_status)));
    }
    Ok(pair)
}
fn capture_complete(capture: &GatewayCapture) -> bool {
    capture.reader == GatewayCaptureState::Complete
        && capture.finalization == GatewayCaptureState::Complete
        && !capture.truncated
}
fn native_success(outcome: &GatewayNativeOutcome) -> GatewayResult<()> {
    match &outcome.dispatch {
        GatewayDispatch::Started {
            attempt_id,
            process_id,
            creation_time: Some(creation_time),
            image: Some(image),
        } if !attempt_id.is_empty()
            && *process_id != 0
            && *creation_time != 0
            && image.is_absolute() => {}
        _ => {
            return Err(GatewayRuleError::RecoveryRequired(
                "native dispatch is not a received process binding".into(),
            ));
        }
    }
    if !matches!(outcome.execution, GatewayExecution::Exited { .. }) {
        return Err(GatewayRuleError::RecoveryRequired(
            "native physical execution has not retired".into(),
        ));
    }
    if !capture_complete(&outcome.stdout) || !capture_complete(&outcome.stderr) {
        return Err(GatewayRuleError::Capture(
            "native stdout/stderr capture or finalization incomplete".into(),
        ));
    }
    match &outcome.action {
        GatewayActionReport::ReturnedSuccess
            if matches!(
                outcome.execution,
                GatewayExecution::Exited { code: Some(0) }
            ) =>
        {
            Ok(())
        }
        GatewayActionReport::ReturnedFailure { kind, message } => Err(match kind {
            GatewayFailureKind::MissingConfiguration => {
                GatewayRuleError::MissingConfiguration(message.clone())
            }
            GatewayFailureKind::Permission => GatewayRuleError::Permission(message.clone()),
            GatewayFailureKind::Policy => GatewayRuleError::Policy(message.clone()),
            GatewayFailureKind::Capture => GatewayRuleError::Capture(message.clone()),
            GatewayFailureKind::Native => GatewayRuleError::RecoveryRequired(message.clone()),
        }),
        _ => Err(GatewayRuleError::RecoveryRequired(
            "native action invocation/result unavailable".into(),
        )),
    }
}
fn inspect<R: GatewayRuleRunner + ?Sized>(
    runner: &mut R,
    scope: &GatewayRuleScope,
    name: Option<&str>,
    cancel: &AtomicBool,
) -> GatewayResult<GatewayRuleInspection> {
    let request = GatewayRuleRequest::Inspect {
        scope: scope.clone(),
        name: name.map(str::to_owned),
    };
    let outcome = runner.run(&request, cancel, &mut |_| Ok(()));
    native_success(&outcome)?;
    let inspection = outcome
        .inspection
        .ok_or_else(|| GatewayRuleError::Capture("native inspection payload absent".into()))?;
    receive_environment(scope, &inspection)?;
    if let Some(name) = name {
        if inspection
            .persistent
            .iter()
            .chain(&inspection.active)
            .any(|rule| rule.name != name)
        {
            return Err(GatewayRuleError::Capture(
                "exact-name query returned another rule".into(),
            ));
        }
    }
    Ok(inspection)
}
fn inspect_owned<R: GatewayRuleRunner + ?Sized>(
    runner: &mut R, scope: &GatewayRuleScope, name: &str, cancel: &AtomicBool,
) -> GatewayResult<GatewayRuleInspection> {
    namespace_shape(&scope.namespace)?;
    let request = GatewayRuleRequest::InspectOwned { scope: scope.clone(), name: name.to_owned() };
    let outcome = runner.run(&request, cancel, &mut |_| Ok(()));
    native_success(&outcome)?;
    let inspection = outcome.inspection.ok_or_else(|| GatewayRuleError::Capture("native inspection payload absent".into()))?;
    receive_historical_environment(scope, &inspection)?;
    if inspection.namespace.is_some() || inspection.persistent.iter().chain(&inspection.active).any(|rule| rule.name != name) {
        return Err(GatewayRuleError::Capture("historical inspection binding differs".into()));
    }
    Ok(inspection)
}
fn receive_receipt(
    slot: &CheckedPath,
    host: &HostBinding,
    reference_value: &EvidenceRef,
) -> Result<GatewayRuleReceiptV1> {
    let receipt: GatewayRuleReceiptV1 = decode(&reference(slot, reference_value)?)?;
    if receipt.version != 1
        || !id_valid(&receipt.operation_id)
        || receipt.scope.host != *host
        || receipt.intended_name != receipt.actual_name
        || receipt.actual_name != receipt.persistent.name
        || receipt.actual_name != receipt.active.name
        || !exact_rule(&receipt.persistent, &receipt.scope)?
        || !exact_rule(&receipt.active, &receipt.scope)?
    {
        return Err("RecoveryRequired: gateway rule receipt binding/filter conflict".into());
    }
    namespace_shape(&receipt.scope.namespace).map_err(|e| e.to_string())?;
    let readback = receive_inspection(
        slot,
        &receipt.readback,
        &receipt.scope,
        &receipt.actual_name,
        false,
    )?;
    if readback.persistent != [receipt.persistent.clone()]
        || readback.active != [receipt.active.clone()]
    {
        return Err(
            "RecoveryRequired: gateway receipt differs from independent native readback".into(),
        );
    }
    match (&receipt.ownership, &receipt.creation) {
        (RuleCustody::ObservedExternal, None) => {}
        (RuleCustody::CreatedByOperation, Some(creation)) => {
            let attempt: GatewayAttempt = decode(&reference(slot, creation)?)?;
            native_success(&attempt.outcome).map_err(|e| e.to_string())?;
            if !matches!(&attempt.request, GatewayRuleRequest::Create { scope, name }
                if scope == &receipt.scope && name == &receipt.intended_name)
                || !receipt
                    .intended_name
                    .starts_with(&format!("AGUnlocker-WSL-{}-", receipt.operation_id))
            {
                return Err(
                    "RecoveryRequired: gateway creation custody not bound to this operation".into(),
                );
            }
        }
        _ => return Err("RecoveryRequired: external/created gateway custody conflict".into()),
    }
    Ok(receipt)
}
pub(super) fn receive_references(
    slot: &CheckedPath,
    host: &HostBinding,
    refs: &[EvidenceRef],
) -> Result<()> {
    let mut names = std::collections::BTreeSet::new();
    let mut scopes = Vec::new();
    for value in refs {
        let receipt = receive_receipt(slot, host, value)?;
        if !names.insert(receipt.actual_name.clone()) || scopes.contains(&receipt.scope) {
            return Err("RecoveryRequired: duplicate gateway rule names/scopes".into());
        }
        scopes.push(receipt.scope);
    }
    Ok(())
}

fn receive_host_binding(
    host: &CheckedPath,
    deployment: &RuntimeDeployment,
    slot: &CheckedPath,
) -> Result<()> {
    host.recheck()?;
    let expected = deployment.receive_host(slot)?;
    if expected.object != host.object
        || expected.path != host.path
        || hash(&host.read_snapshot()?) != deployment.host.sha256
    {
        return Err(
            "MaintenanceRequired: gateway host is not the exact deployed executable".into(),
        );
    }
    deployment.receive_receipt(slot)
}

fn receive_requirement_state(bound: &BoundInstallation) -> GatewayResult<RequirementState> {
    receive_requirement_state_inner(bound, None)
}
fn receive_requirement_state_inner(bound: &BoundInstallation, expected_vendor: Option<&VendorUpdateObservation>) -> GatewayResult<RequirementState> {
    bound.exe.recheck()?;
    bound.root.recheck()?;
    bound.resources.recheck()?;
    bound.archive.recheck()?;
    if bound.archive.read_snapshot()? != bound.bytes() {
        return Err(GatewayRuleError::RecoveryRequired(
            "requirement archive contents changed".into(),
        ));
    }
    let (known, _, namespace_path) = namespace_paths(bound)?;
    let _namespace_lease = Lease::acquire(&known, "wsl_namespace_v2")?;
    let binding = bound.binding()?;
    match fs::symlink_metadata(&namespace_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RequirementState {
                binding,
                known,
                _namespace: None,
                _slot_lease: None,
                received: None,
                vendor: None,
            });
        }
        Err(error) => return Err(io("requirement namespace observation", error).into()),
        Ok(_) => {}
    }
    let namespace = CheckedPath::open(&namespace_path, PathKind::Directory, PathPurpose::Review)?;
    private(&namespace.file)?;
    let Some((slot, _, _)) = lookup(&namespace, bound)? else {
        return Ok(RequirementState {
            binding,
            known,
            _namespace: Some(namespace),
            _slot_lease: None,
            received: None,
            vendor: None,
        });
    };
    let slot_lease = Lease::acquire(&slot, "wsl_slot_v2")?;
    let (current, digest) = receive_current(&slot)?;
    if matches!(current.mode, Mode::Bootstrap | Mode::Pending) {
        return Err(GatewayRuleError::RecoveryRequired(
            "requirement target has unresolved Current".into(),
        ));
    }
    if current.binding != binding {
        let expected = expected_vendor.ok_or_else(|| GatewayRuleError::RecoveryRequired(
            "UpdatePending: requirement target incarnation differs".into()))?;
        let actual = vendor_update_observation(bound, &slot, &current, &digest)?;
        if &actual != expected { return Err(GatewayRuleError::RecoveryRequired("vendor prerequisite changed".into())); }
    } else if expected_vendor.is_some() {
        return Err(GatewayRuleError::RecoveryRequired("vendor prerequisite no longer distinct".into()));
    }
    Ok(RequirementState {
        binding,
        known,
        _namespace: Some(namespace),
        _slot_lease: Some(slot_lease),
        received: Some((slot, current, digest)),
        vendor: expected_vendor.cloned(),
    })
}
impl RequirementState {
    fn recheck(&self, bound: &BoundInstallation) -> GatewayResult<()> {
        bound.revalidate_context()?;
        self.known.recheck()?;
        if self.binding != bound.binding()? {
            return Err(GatewayRuleError::RecoveryRequired(
                "requirement installation binding changed".into(),
            ));
        }
        let fresh = receive_requirement_state_inner(bound, self.vendor.as_ref())?;
        let fingerprint = |state: &RequirementState| {
            state
                .received
                .as_ref()
                .map(|(_, current, digest)| (current.slot_id.clone(), digest.clone()))
        };
        if fingerprint(self) != fingerprint(&fresh) {
            return Err(GatewayRuleError::RecoveryRequired(
                "requirement Current disposition changed".into(),
            ));
        }
        Ok(())
    }
    fn deployment(&self) -> GatewayResult<Option<&RuntimeDeployment>> {
        let Some((_, current, _)) = &self.received else {
            return Ok(None);
        };
        match &current.runtime_deployment {
            DeploymentField::Absent if current.schema == 2 => Ok(None),
            DeploymentField::Present(None) if current.schema == 3 => Ok(None),
            DeploymentField::Present(Some(deployment)) if current.schema == 3 => {
                Ok(Some(deployment))
            }
            _ => Err(GatewayRuleError::RecoveryRequired(
                "requirement runtime disposition conflicts with schema".into(),
            )),
        }
    }
}
fn validate_new_deployment_state(
    bound: &BoundInstallation,
    state: &RequirementState,
) -> GatewayResult<()> {
    if state.deployment()?.is_some() {
        return Ok(());
    }
    if let Some((_, current, _)) = &state.received {
        if current.schema == 2 && current.mode == Mode::SettledApplied {
            let applied = current
                .settled
                .as_ref()
                .and_then(|settled| settled.applied.as_ref())
                .ok_or_else(|| {
                    GatewayRuleError::RecoveryRequired(
                        "legacy requirement Applied evidence absent".into(),
                    )
                })?;
            verify_applied(bound, applied)?;
            return Ok(());
        }
    }
    let inspection = desktop_hook::inspect_archive(bound.bytes()).map_err(|error| {
        GatewayRuleError::RecoveryRequired(format!(
            "requirement archive is not a recognized fresh target: {error}"
        ))
    })?;
    if inspection.hook_status != desktop_hook::HookStatus::Prepared {
        return Err(GatewayRuleError::RecoveryRequired(
            "unreceived hooked target is not positive fresh/new-host evidence".into(),
        ));
    }
    Ok(())
}
impl GatewayHostInput {
    pub(crate) fn vendor_prerequisite(bound: &BoundInstallation, source: &CheckedPath,
        expected_source_sha256: &str, expected: &VendorUpdateObservation,
        selection: Option<&GatewayRetirementSelectionV1>, saved: &[u8; 32]) -> GatewayResult<Self> {
        if let Some(selection) = selection { selection.validate_binding(expected, saved)?; }
        source.recheck()?;
        let pin = CheckedPath::open(source.as_path(), PathKind::File, PathPurpose::Executable)?;
        if pin.native_id() != source.native_id() || hash(&pin.read_snapshot()?) != expected_source_sha256 {
            return Err(GatewayRuleError::Invalid("vendor source executable pin/hash differs".into()));
        }
        let state = receive_requirement_state_inner(bound, Some(expected))?;
        let prior = state.deployment()?.cloned().ok_or_else(|| GatewayRuleError::RecoveryRequired("vendor prior runtime absent".into()))?;
        let (slot, _, _) = state.received.as_ref().ok_or_else(|| GatewayRuleError::RecoveryRequired("vendor prior slot absent".into()))?;
        prior.receive_host(slot)?;
        prior.receive_receipt(slot)?;
        Ok(Self::VendorPrerequisite(GatewayVendorPrerequisite { source: pin,
            source_sha256: expected_source_sha256.into(), state, prior, selection: selection.cloned() }))
    }
    /// Preferred all-target input receiving. Absence/schema2 is observed by the
    /// installation owner; an error never falls through to NewDeployment.
    pub(crate) fn receive(
        bound: &BoundInstallation,
        source: &CheckedPath,
        expected_source_sha256: &str,
    ) -> GatewayResult<Self> {
        source.recheck()?;
        let pin = CheckedPath::open(source.as_path(), PathKind::File, PathPurpose::Executable)?;
        if pin.native_id() != source.native_id()
            || hash(&pin.read_snapshot()?) != expected_source_sha256
        {
            return Err(GatewayRuleError::Invalid(
                "source executable pin/hash differs".into(),
            ));
        }
        let state = receive_requirement_state(bound)?;
        let deployment = state.deployment()?.cloned();
        if let Some(deployment) = deployment {
            let (slot, _, _) = state
                .received
                .as_ref()
                .ok_or_else(|| GatewayRuleError::RecoveryRequired("runtime slot absent".into()))?;
            let host = deployment.receive_host(slot)?;
            deployment.receive_receipt(slot)?;
            deployment.receive_hook(bound.bytes())?;
            if deployment.host.sha256 == expected_source_sha256 {
                let read = runtime_gate::read(slot, &deployment.gate.native_id)?;
                return Ok(Self::Bound(GatewayBoundHost {
                    host,
                    state,
                    deployment,
                    _read: read,
                }));
            }
            // A fully received old runtime with different validated source
            // content positively needs a new host; missing/corrupt host did not
            // reach this branch and is never interpreted as an installation.
        }
        validate_new_deployment_state(bound, &state)?;
        Ok(Self::NewDeployment(GatewayNewDeployment {
            source: pin,
            source_sha256: expected_source_sha256.into(),
            state,
        }))
    }
    /// Closed constructor: only positively received new-deployment cases pass.
    pub(crate) fn new_deployment(
        bound: &BoundInstallation,
        source: &CheckedPath,
        expected_source_sha256: &str,
    ) -> GatewayResult<Self> {
        match Self::receive(bound, source, expected_source_sha256)? {
            input @ Self::NewDeployment(_) => Ok(input),
            Self::Bound(_) | Self::VendorPrerequisite(_) => Err(GatewayRuleError::Invalid(
                "already received current host requires Bound input".into(),
            )),
        }
    }
    /// Existing-runtime receiving needs no guessed path from the composition.
    pub(crate) fn bound(bound: &BoundInstallation) -> GatewayResult<Self> {
        let state = receive_requirement_state(bound)?;
        let deployment = state.deployment()?.cloned().ok_or_else(|| {
            GatewayRuleError::MissingConfiguration(
                "no received runtime host; use validated NewDeployment input".into(),
            )
        })?;
        let (slot, _, _) = state
            .received
            .as_ref()
            .ok_or_else(|| GatewayRuleError::RecoveryRequired("runtime slot absent".into()))?;
        let host = deployment.receive_host(slot)?;
        deployment.receive_receipt(slot)?;
        deployment.receive_hook(bound.bytes())?;
        let read = runtime_gate::read(slot, &deployment.gate.native_id)?;
        Ok(Self::Bound(GatewayBoundHost {
            host,
            state,
            deployment,
            _read: read,
        }))
    }
}

enum ReceivedScope {
    Existing {
        name: String,
        receipt: EvidenceRef,
        observation: GatewayRuleInspection,
    },
    External {
        name: String,
        observation: GatewayRuleInspection,
    },
    Missing {
        observation: GatewayRuleInspection,
    },
}
fn receive_requirement_namespaces(
    input: GatewayRequirementNamespaces<'_>,
) -> GatewayResult<(Vec<GatewayNamespace>, Option<bool>)> {
    match input {
        GatewayRequirementNamespaces::TransportNotWanted => Ok((Vec::new(), None)),
        GatewayRequirementNamespaces::TransportWanted {
            namespaces,
            active_profiles: profiles,
            administrator,
        } => {
            active_profiles(profiles)?;
            let values = normalized_namespaces(namespaces)?;
            if values.is_empty() {
                return Err(GatewayRuleError::MissingConfiguration(
                    "wanted transport has no received namespace facts".into(),
                ));
            }
            Ok((values, Some(administrator)))
        }
    }
}
fn inspect_bound_scope<R: GatewayRuleRunner>(
    slot: &CheckedPath,
    scope: &GatewayRuleScope,
    refs: &[EvidenceRef],
    runner: &mut R,
    cancel: &AtomicBool,
) -> GatewayResult<ReceivedScope> {
    let mut existing = None;
    for value in refs {
        let receipt = receive_receipt(slot, &scope.host, value)?;
        if receipt.scope == *scope {
            if existing.is_some() {
                return Err(GatewayRuleError::RecoveryRequired(
                    "duplicate received gateway scope".into(),
                ));
            }
            existing = Some((value.clone(), receipt));
        }
    }
    if let Some((reference, receipt)) = existing {
        let observation = inspect(runner, scope, Some(&receipt.actual_name), cancel)?;
        let (persistent, active) = receive_ready_pair(scope, &receipt.actual_name, &observation)?;
        if persistent != &receipt.persistent || active != &receipt.active {
            return Err(GatewayRuleError::MissingConfiguration(
                "retained gateway identity/source/filters changed; preserved".into(),
            ));
        }
        return Ok(ReceivedScope::Existing {
            name: receipt.actual_name,
            receipt: reference,
            observation,
        });
    }
    let observation = inspect(runner, scope, None, cancel)?;
    let mut candidates = Vec::new();
    for persistent in &observation.persistent {
        if exact_rule(persistent, scope)? {
            let active: Vec<_> = observation
                .active
                .iter()
                .filter(|rule| rule.name == persistent.name)
                .collect();
            if active.len() != 1 || !exact_rule(active[0], scope)? {
                return Err(GatewayRuleError::MissingConfiguration(
                    "external gateway rule has missing/ambiguous effective filters; preserved"
                        .into(),
                ));
            }
            candidates.push((persistent.clone(), active[0].clone()));
        }
    }
    if candidates.len() > 1 {
        return Err(GatewayRuleError::MissingConfiguration(
            "ambiguous concrete external gateway rules; preserved".into(),
        ));
    }
    if let Some((persistent, active)) = candidates.pop() {
        let active_enforcement = observation.active_enforcement.as_ref().map(|values|
            values.iter().filter(|value| value.name == persistent.name).cloned().collect());
        let exact = GatewayRuleInspection {
            persistent: vec![persistent.clone()],
            active: vec![active],
            active_enforcement,
            ..observation
        };
        receive_ready_pair(scope, &persistent.name, &exact)?;
        Ok(ReceivedScope::External {
            name: persistent.name,
            observation: exact,
        })
    } else {
        Ok(ReceivedScope::Missing { observation })
    }
}

/// Conservative collection before any installation/rule effect. NewDeployment
/// never calls the native rule runner or names a future/source program rule.
pub(crate) fn inspect_requirements<R: GatewayRuleRunner>(
    bound: &BoundInstallation,
    host: GatewayHostInput,
    namespaces: GatewayRequirementNamespaces<'_>,
    runner: &mut R,
    cancel: &AtomicBool,
) -> GatewayResult<GatewayRuleRequirements> {
    if cancel.load(Ordering::SeqCst) {
        return Err(GatewayRuleError::CancelledBeforeMutation);
    }
    let (namespaces, administrator) = receive_requirement_namespaces(namespaces)?;
    match host {
        GatewayHostInput::VendorPrerequisite(input) => {
            input.state.recheck(bound)?;
            input.source.recheck()?;
            if hash(&input.source.read_snapshot()?) != input.source_sha256 {
                return Err(GatewayRuleError::Invalid("vendor source executable changed".into()));
            }
            let (slot, _, _) = input.state.received.as_ref().ok_or_else(|| GatewayRuleError::RecoveryRequired("vendor prior slot absent".into()))?;
            input.prior.receive_host(slot)?;
            input.prior.receive_receipt(slot)?;
            let mut removal_admin = None;
            let mut selected_count = 0;
            for value in input.prior.gateway_rules.as_deref().unwrap_or(&[]) {
                let receipt = receive_receipt(slot, &input.prior.host, value)?;
                if receipt.ownership != RuleCustody::CreatedByOperation { continue; }
                let actual = inspect_owned(runner, &receipt.scope, &receipt.actual_name, cancel)?;
                receive_vendor_pair(&receipt, value, &actual, input.selection.as_ref())?;
                if input.selection.as_ref().is_some_and(|selected| &selected.receipt == value) { selected_count += 1; }
                removal_admin = Some(removal_admin.unwrap_or(true) && actual.administrator);
            }
            if input.selection.is_some() && selected_count != 1 { return Err(GatewayRuleError::MissingConfiguration("selected owned receipt missing or ambiguous".into())); }
            input.state.recheck(bound)?;
            let required = administrator.is_some() || removal_admin.is_some();
            Ok(GatewayRuleRequirements { canonical_install_needed: true,
                rules: if required { GatewayRuleEffect::NativeWriteRequired {
                    administrator: administrator.unwrap_or(true) && removal_admin.unwrap_or(true) } }
                    else { GatewayRuleEffect::VerifiedNoop } })
        }
        GatewayHostInput::NewDeployment(input) => {
            input.state.recheck(bound)?;
            validate_new_deployment_state(bound, &input.state)?;
            input.source.recheck()?;
            if hash(&input.source.read_snapshot()?) != input.source_sha256 {
                return Err(GatewayRuleError::Invalid(
                    "validated source executable changed".into(),
                ));
            }
            if let Some(deployment) = input.state.deployment()? {
                let (slot, _, _) = input.state.received.as_ref().ok_or_else(|| {
                    GatewayRuleError::RecoveryRequired(
                        "new-host requirement prior slot absent".into(),
                    )
                })?;
                deployment.receive_host(slot)?;
                deployment.receive_receipt(slot)?;
                deployment.receive_hook(bound.bytes())?;
            }
            if cancel.load(Ordering::SeqCst) {
                return Err(GatewayRuleError::CancelledBeforeMutation);
            }
            Ok(GatewayRuleRequirements {
                canonical_install_needed: true,
                rules: match administrator {
                    Some(administrator) => GatewayRuleEffect::NativeWriteRequired { administrator },
                    None => GatewayRuleEffect::VerifiedNoop,
                },
            })
        }
        GatewayHostInput::Bound(input) => {
            input.state.recheck(bound)?;
            let (slot, _, _) = input.state.received.as_ref().ok_or_else(|| {
                GatewayRuleError::RecoveryRequired("Bound requirement slot absent".into())
            })?;
            receive_host_binding(&input.host, &input.deployment, slot)?;
            let refs = input.deployment.gateway_rules.as_deref().unwrap_or(&[]);
            let mut canonical = false;
            let mut native_admin = None;
            for namespace in namespaces {
                if cancel.load(Ordering::SeqCst) {
                    return Err(GatewayRuleError::CancelledBeforeMutation);
                }
                let scope = GatewayRuleScope {
                    host: input.deployment.host.clone(),
                    namespace,
                };
                match inspect_bound_scope(slot, &scope, refs, runner, cancel)? {
                    ReceivedScope::Existing { .. } => {}
                    ReceivedScope::External { .. } => canonical = true,
                    ReceivedScope::Missing { observation } => {
                        native_admin =
                            Some(native_admin.unwrap_or(true) && observation.administrator);
                    }
                }
            }
            input.state.recheck(bound)?;
            Ok(GatewayRuleRequirements {
                canonical_install_needed: false,
                rules: match native_admin {
                    Some(administrator) => GatewayRuleEffect::NativeWriteRequired { administrator },
                    None if canonical => GatewayRuleEffect::CanonicalCommitOnly,
                    None => GatewayRuleEffect::VerifiedNoop,
                },
            })
        }
    }
}
fn prepare_base<'a>(
    bound: &'a BoundInstallation,
    host: &'a CheckedPath,
) -> GatewayResult<PreparedGatewayRules<'a>> {
    let authority = Authority::open(bound, false, false)?;
    if authority.current.schema != 3 || authority.current.mode != Mode::SettledApplied {
        return Err(GatewayRuleError::MissingConfiguration(
            "received schema3 applied host required".into(),
        ));
    }
    let deployment = authority.current.runtime_deployment.received()?;
    receive_host_binding(host, deployment, &authority.slot)?;
    let read = runtime_gate::read(&authority.slot, &deployment.gate.native_id)?;
    let (_, current_digest) = receive_current(&authority.slot)?;
    if current_digest != authority.digest {
        return Err(GatewayRuleError::RecoveryRequired(
            "canonical state changed during gateway preparation".into(),
        ));
    }
    Ok(PreparedGatewayRules {
        bound,
        host,
        authority,
        read: Some(read),
        id: unique_id()?,
        kind: GatewayOperation::Configure,
        plans: Vec::new(),
    })
}

pub(crate) fn prepare_gateway_rules<'a, R: GatewayRuleRunner>(
    bound: &'a BoundInstallation,
    host: &'a CheckedPath,
    qualified_namespaces: &[GatewayNamespace],
    runner: &mut R,
    cancel: &AtomicBool,
) -> GatewayResult<PreparedGatewayRules<'a>> {
    let mut prepared = prepare_base(bound, host)?;
    let deployment = prepared.authority.current.runtime_deployment.received()?;
    let refs = deployment.gateway_rules.as_deref().unwrap_or(&[]);
    for namespace in &normalized_namespaces(qualified_namespaces)? {
        if cancel.load(Ordering::SeqCst) {
            return Err(GatewayRuleError::CancelledBeforeMutation);
        }
        let scope = GatewayRuleScope {
            host: deployment.host.clone(),
            namespace: namespace.clone(),
        };
        let plan =
            match inspect_bound_scope(&prepared.authority.slot, &scope, refs, runner, cancel)? {
                ReceivedScope::Existing {
                    name,
                    receipt,
                    observation,
                } => RulePlan {
                    scope,
                    name,
                    action: RuleAction::Reuse,
                    receipt: Some(receipt),
                    observation: Some(observation),
                },
                ReceivedScope::External { name, observation } => RulePlan {
                    scope,
                    name,
                    action: RuleAction::ObserveExternal,
                    receipt: None,
                    observation: Some(observation),
                },
                ReceivedScope::Missing { observation } => {
                    if !observation.administrator {
                        return Err(GatewayRuleError::NeedsElevation);
                    }
                    let name = format!("AGUnlocker-WSL-{}-{}", prepared.id, prepared.plans.len());
                    let vacant = inspect(runner, &scope, Some(&name), cancel)?;
                    if !vacant.persistent.is_empty() || !vacant.active.is_empty() {
                        return Err(GatewayRuleError::RecoveryRequired(
                            "new operation-bound gateway rule name is occupied; preserved".into(),
                        ));
                    }
                    RulePlan {
                        scope,
                        name,
                        action: RuleAction::Create,
                        receipt: None,
                        observation: Some(vacant),
                    }
                }
            };
        prepared.plans.push(plan);
    }
    Ok(prepared)
}

pub(crate) fn prepare_gateway_rule_retirement<'a, R: GatewayRuleRunner>(
    bound: &'a BoundInstallation,
    host: &'a CheckedPath,
    still_wanted: &[GatewayNamespace],
    runner: &mut R,
    cancel: &AtomicBool,
) -> GatewayResult<PreparedGatewayRules<'a>> {
    let still_wanted = normalized_namespaces(still_wanted)?;
    let mut prepared = prepare_base(bound, host)?;
    prepared.kind = GatewayOperation::Retire;
    let deployment = prepared.authority.current.runtime_deployment.received()?;
    for value in deployment.gateway_rules.as_deref().unwrap_or(&[]) {
        if cancel.load(Ordering::SeqCst) {
            return Err(GatewayRuleError::CancelledBeforeMutation);
        }
        let receipt = receive_receipt(&prepared.authority.slot, &deployment.host, value)?;
        if !retirement_requested(&receipt, &still_wanted) {
            continue;
        }
        let inspection = inspect_owned(runner, &receipt.scope, &receipt.actual_name, cancel)?;
        let (persistent, active) = receive_pair(&receipt.scope, &receipt.actual_name, &inspection)?;
        if persistent != &receipt.persistent || active != &receipt.active {
            return Err(GatewayRuleError::MissingConfiguration(
                "changed owned gateway rule preserved during retirement".into(),
            ));
        }
        if !inspection.administrator {
            return Err(GatewayRuleError::NeedsElevation);
        }
        prepared.plans.push(RulePlan {
            scope: receipt.scope,
            name: receipt.actual_name,
            action: RuleAction::Remove,
            receipt: Some(value.clone()),
            observation: Some(inspection),
        });
    }
    Ok(prepared)
}

pub(crate) fn receive_gateway_rule<R: GatewayRuleRunner>(
    runtime_read: &RuntimeRead,
    qualified_namespace: &GatewayNamespace,
    runner: &mut R,
    cancel: &AtomicBool,
) -> GatewayResult<String> {
    runtime_read.host.recheck()?;
    let (current, _) = receive_current(&runtime_read.slot)?;
    if current.revision != runtime_read.revision {
        return Err(GatewayRuleError::RecoveryRequired(
            "runtime reader canonical revision changed".into(),
        ));
    }
    let deployment = current.runtime_deployment.received()?;
    receive_host_binding(&runtime_read.host, deployment, &runtime_read.slot)?;
    let refs = deployment.gateway_rules.as_ref().ok_or_else(|| {
        GatewayRuleError::MissingConfiguration(
            "host-only deployment v1 has no gateway readiness".into(),
        )
    })?;
    let scope = GatewayRuleScope {
        host: deployment.host.clone(),
        namespace: qualified_namespace.clone(),
    };
    let mut selected = None;
    for value in refs {
        let receipt = receive_receipt(&runtime_read.slot, &deployment.host, value)?;
        if receipt.scope == scope {
            if selected.is_some() {
                return Err(GatewayRuleError::RecoveryRequired(
                    "duplicate runtime gateway scope".into(),
                ));
            }
            selected = Some(receipt);
        }
    }
    let receipt = selected.ok_or_else(|| {
        GatewayRuleError::MissingConfiguration("no received rule for this exact namespace".into())
    })?;
    let inspection = inspect(runner, &scope, Some(&receipt.actual_name), cancel)?;
    let (persistent, active) = receive_ready_pair(&scope, &receipt.actual_name, &inspection)?;
    if persistent != &receipt.persistent || active != &receipt.active {
        return Err(GatewayRuleError::MissingConfiguration(
            "runtime gateway identity/source/filters changed; preserved".into(),
        ));
    }
    Ok(receipt.actual_name)
}

fn operation_kind(kind: &GatewayOperation) -> OperationKind {
    match kind {
        GatewayOperation::Configure => OperationKind::ConfigureGatewayRules,
        GatewayOperation::Retire => OperationKind::RetireGatewayRules,
    }
}
fn receive_intent(
    slot: &CheckedPath,
    reference_value: &EvidenceRef,
) -> Result<(GatewayIntent, Current)> {
    let intent: GatewayIntent = decode(&reference(slot, reference_value)?)?;
    let prior_bytes = reference(slot, &intent.prior_current)?;
    let prior: Current = decode(&prior_bytes)?;
    current_shape(&prior, &intent.slot_id)?;
    if intent.schema != 3
        || !id_valid(&intent.operation_id)
        || prior.schema != 3
        || prior.mode != Mode::SettledApplied
        || intent.expected_current_digest != hash(&prior_bytes)
        || json(prior.runtime_deployment.received()?)? != json(&intent.prior_deployment)?
    {
        return Err("RecoveryRequired: gateway intent/prior canonical binding conflict".into());
    }
    intent.prior_deployment.receive_receipt(slot)?;
    let mut scopes = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for plan in &intent.plans {
        namespace_shape(&plan.scope.namespace).map_err(|e| e.to_string())?;
        if plan.scope.host != intent.prior_deployment.host
            || scopes.contains(&plan.scope)
            || !names.insert(plan.name.clone())
        {
            return Err("RecoveryRequired: gateway intent scope/name conflict".into());
        }
        scopes.push(plan.scope.clone());
        match (&intent.kind, &plan.action, &plan.receipt, &plan.observation) {
            (GatewayOperation::Configure, RuleAction::Create, None, Some(observation)) => {
                if !plan
                    .name
                    .starts_with(&format!("AGUnlocker-WSL-{}-", intent.operation_id))
                    || !observation.administrator
                    || !observation.persistent.is_empty()
                    || !observation.active.is_empty()
                {
                    return Err(
                        "RecoveryRequired: gateway create intent is not vacant and operation-bound"
                            .into(),
                    );
                }
                receive_environment(&plan.scope, observation).map_err(|e| e.to_string())?;
            }
            (GatewayOperation::Configure, RuleAction::ObserveExternal, None, Some(observation)) => {
                receive_environment(&plan.scope, observation).map_err(|e| e.to_string())?;
                receive_pair(&plan.scope, &plan.name, observation).map_err(|e| e.to_string())?;
            }
            (GatewayOperation::Configure, RuleAction::Reuse, Some(value), Some(observation))
            | (GatewayOperation::Retire, RuleAction::Remove, Some(value), Some(observation)) => {
                if plan.action == RuleAction::Reuse {
                    receive_environment(&plan.scope, observation).map_err(|e| e.to_string())?;
                } else {
                    receive_historical_environment(&plan.scope, observation).map_err(|e| e.to_string())?;
                }
                let receipt = receive_receipt(slot, &intent.prior_deployment.host, value)?;
                let (persistent, active) = receive_pair(&plan.scope, &plan.name, observation)
                    .map_err(|e| e.to_string())?;
                if !intent
                    .prior_deployment
                    .gateway_rules
                    .as_deref()
                    .unwrap_or(&[])
                    .contains(value)
                    || receipt.scope != plan.scope
                    || receipt.actual_name != plan.name
                    || &receipt.persistent != persistent
                    || &receipt.active != active
                    || (plan.action == RuleAction::Remove
                        && (receipt.ownership != RuleCustody::CreatedByOperation
                            || !observation.administrator))
                {
                    return Err("RecoveryRequired: gateway reuse/removal custody changed".into());
                }
            }
            _ => return Err("RecoveryRequired: gateway intent action shape conflict".into()),
        }
    }
    Ok((intent, prior))
}
pub(super) fn receive_pending(
    slot: &CheckedPath,
    current: &Current,
    operation: &Operation,
) -> Result<()> {
    let (intent, prior) = receive_intent(slot, &operation.intent)?;
    if current.mode != Mode::Pending
        || current.schema != 3
        || intent.slot_id != current.slot_id
        || intent.operation_id != operation.id
        || operation.kind != operation_kind(&intent.kind)
        || intent.expected_current_digest != operation.prior_current_digest
        || current.binding != prior.binding
        || json(current.runtime_deployment.received()?)? != json(&intent.prior_deployment)?
    {
        return Err("RecoveryRequired: Pending gateway operation binding conflict".into());
    }
    Ok(())
}

/// The directory is part of the same canonical slot, not another registry.
fn operation_evidence(authority: &Authority, id: &str) -> Result<PathBuf> {
    let root = authority.slot.path.join("evidence");
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private_dir(&root)?,
        Err(error) => return Err(io("gateway evidence parent", error)),
        Ok(_) => {}
    }
    let root = CheckedPath::open(&root, PathKind::Directory, PathPurpose::Review)?;
    private(&root.file)?;
    if !authority.slot.contains(&root)? {
        return Err("gateway evidence parent escaped slot".into());
    }
    let dir = root.path.join(id);
    absent(&dir)?;
    create_private_dir(&dir)?;
    Ok(dir)
}
fn journal_run<R: GatewayRuleRunner + ?Sized>(
    authority: &Authority,
    dir: &Path,
    phase: &str,
    request: &GatewayRuleRequest,
    runner: &mut R,
    cancel: &AtomicBool,
) -> GatewayResult<EvidenceRef> {
    let mut serial = 0u64;
    let mut last = None;
    let mut last_bytes = None;
    let mut persistence_error = None;
    let outcome = runner.run(request, cancel, &mut |outcome| {
        let bytes = json(&GatewayAttempt {
            request: request.clone(),
            outcome: outcome.clone(),
        })?;
        let result = authority.save(dir, &format!("{phase}-{serial}.json"), &bytes);
        match result {
            Ok(reference) => {
                serial = serial
                    .checked_add(1)
                    .ok_or("gateway observation serial overflow")?;
                last = Some(reference);
                last_bytes = Some(bytes);
                Ok(())
            }
            Err(error) => {
                persistence_error = Some(error.clone());
                Err(error)
            }
        }
    });
    let bytes = json(&GatewayAttempt {
        request: request.clone(),
        outcome: outcome.clone(),
    });
    match bytes {
        Ok(bytes) if last_bytes.as_ref() == Some(&bytes) => {}
        Ok(bytes) => match authority.save(dir, &format!("{phase}-{serial}.json"), &bytes) {
            Ok(reference) => last = Some(reference),
            Err(error) => {
                persistence_error.get_or_insert(error);
            }
        },
        Err(error) => {
            persistence_error.get_or_insert(error);
        }
    }
    if let Some(error) = persistence_error {
        return Err(GatewayRuleError::NativeUnsettled {
            outcome: Box::new(outcome),
            reason: format!("native evidence persistence failed: {error}"),
        });
    }
    if let Err(error) = native_success(&outcome) {
        return Err(GatewayRuleError::NativeUnsettled {
            outcome: Box::new(outcome),
            reason: error.to_string(),
        });
    }
    last.ok_or_else(|| {
        GatewayRuleError::RecoveryRequired("native final outcome reference missing".into())
    })
}
fn receive_mutation(slot: &CheckedPath, value: &EvidenceRef, plan: &RulePlan) -> Result<()> {
    let attempt: GatewayAttempt = decode(&reference(slot, value)?)?;
    native_success(&attempt.outcome).map_err(|e| e.to_string())?;
    let correct = match (&plan.action, &attempt.request) {
        (RuleAction::Create, GatewayRuleRequest::Create { scope, name }) => {
            scope == &plan.scope && name == &plan.name
        }
        (
            RuleAction::Remove,
            GatewayRuleRequest::Remove {
                scope,
                persistent,
                active,
            },
        ) => {
            let observation = plan.observation.as_ref().ok_or("removal preimage absent")?;
            scope == &plan.scope
                && observation.persistent == [persistent.clone()]
                && observation.active == [active.clone()]
        }
        _ => false,
    };
    if !correct {
        return Err("RecoveryRequired: native invocation does not match gateway intent".into());
    }
    Ok(())
}
fn receive_inspection(
    slot: &CheckedPath,
    value: &EvidenceRef,
    scope: &GatewayRuleScope,
    name: &str,
    historical: bool,
) -> Result<GatewayRuleInspection> {
    let attempt: GatewayAttempt = decode(&reference(slot, value)?)?;
    native_success(&attempt.outcome).map_err(|e| e.to_string())?;
    let legacy = matches!(&attempt.request, GatewayRuleRequest::Inspect { scope: actual, name: Some(actual_name) }
        if actual == scope && actual_name == name);
    let owned = matches!(&attempt.request, GatewayRuleRequest::InspectOwned { scope: actual, name: actual_name }
        if actual == scope && actual_name == name);
    if !(legacy || historical && owned) {
        return Err("RecoveryRequired: gateway readback request binding differs".into());
    }
    let observation = attempt
        .outcome
        .inspection
        .ok_or("gateway readback inspection payload absent")?;
    namespace_shape(&scope.namespace).map_err(|e| e.to_string())?;
    if !historical || legacy {
        receive_environment(scope, &observation).map_err(|e| e.to_string())?;
    } else {
        receive_historical_environment(scope, &observation).map_err(|e| e.to_string())?;
        if observation.namespace.is_some() { return Err("gateway historical readback unexpectedly claims live namespace".into()); }
    }
    if observation
        .persistent
        .iter()
        .chain(&observation.active)
        .any(|rule| rule.name != name)
    {
        return Err("gateway exact-name readback contains a different rule".into());
    }
    Ok(observation)
}

pub(super) fn execute_vendor_retirement<W: MaintenanceWindow>(
    bound: &BoundInstallation, authority: &Authority, dir: &Path, plan: &VendorRetirementPlan,
    runner: &mut Option<&mut dyn GatewayRuleRunner>, window: &mut W, cancel: &AtomicBool,
) -> GatewayResult<Vec<EvidenceRef>> {
    let old = authority.current.runtime_deployment.received()?;
    validate_vendor_retirement(&authority.slot, old, plan)?;
    let _host = old.receive_host(&authority.slot)?;
    let selection = match &plan.admission { VendorRetirementAdmission::ExactReceipt {} => None,
        VendorRetirementAdmission::AcknowledgedInterfaceAliases { selection } => Some(selection) };
    let mut steps = Vec::new();
    for (index, item) in plan.plans.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) { return Err(GatewayRuleError::RecoveryRequired("vendor retirement cancelled after Pending".into())); }
        let active_runner = runner.as_deref_mut().ok_or_else(|| GatewayRuleError::RecoveryRequired("vendor retirement runner absent".into()))?;
        bound.revalidate_context()?;
        window.ensure_held()?;
        let actual = inspect_owned(active_runner, &item.scope, &item.name, cancel)?;
        let before = item.observation.as_ref().ok_or("vendor retirement preimage absent")?;
        let reference = item.receipt.as_ref().ok_or("vendor retirement receipt absent")?;
        let receipt = receive_receipt(&authority.slot, &old.host, reference)?;
        let (persistent, active) = receive_vendor_pair(&receipt, reference, &actual, selection)?;
        if !actual.administrator || before.persistent != actual.persistent || before.active != actual.active {
            return Err(GatewayRuleError::MissingConfiguration("vendor retirement preimage changed".into()));
        }
        let request = GatewayRuleRequest::Remove { scope: item.scope.clone(), persistent: persistent.clone(), active: active.clone() };
        let mutation = journal_run(authority, dir, &format!("vendor-rule-native-{index}"), &request, active_runner, cancel)?;
        // Preserve the actual native result before another external call.
        authority.save(dir, &format!("vendor-rule-native-received-{index}.json"), &json(&mutation)?)?;
        let readback = journal_run(authority, dir, &format!("vendor-rule-readback-{index}"),
            &GatewayRuleRequest::InspectOwned { scope: item.scope.clone(), name: item.name.clone() }, active_runner, cancel)?;
        let observed = receive_inspection(&authority.slot, &readback, &item.scope, &item.name, true)?;
        if !observed.persistent.is_empty() || !observed.active.is_empty() {
            return Err(GatewayRuleError::RecoveryRequired("vendor retired rule remains present".into()));
        }
        let step = VendorRetirementStep { mutation, readback };
        steps.push(authority.save(dir, &format!("vendor-rule-complete-{index}.json"), &json(&step)?)?);
    }
    Ok(steps)
}

pub(super) fn receive_vendor_retirement(slot: &CheckedPath, dir: &Path,
    plan: &VendorRetirementPlan, steps: &[EvidenceRef]) -> Result<()> {
    if steps.len() != plan.plans.len() { return Err("RecoveryRequired: vendor retirement results missing".into()); }
    for (index, (item, value)) in plan.plans.iter().zip(steps).enumerate() {
        let expected = dir.join(format!("vendor-rule-complete-{index}.json"));
        let bytes = read_private(&expected)?;
        if hash(&bytes) != value.digest || slot.path.join(&value.path) != expected {
            return Err("RecoveryRequired: vendor retirement fixed result conflict".into());
        }
        let step: VendorRetirementStep = decode(&reference(slot, value)?)?;
        let received: EvidenceRef = decode(&read_private(&dir.join(format!("vendor-rule-native-received-{index}.json")))?)?;
        let belongs = |reference: &EvidenceRef, prefix: &str| {
            let path = slot.path.join(&reference.path);
            path.parent() == Some(dir) && path.file_name().and_then(OsStr::to_str)
                .and_then(|name| name.strip_prefix(prefix)).and_then(|tail| tail.strip_suffix(".json"))
                .is_some_and(|serial| !serial.is_empty() && serial.bytes().all(|b| b.is_ascii_digit()))
        };
        if received != step.mutation || !belongs(&step.mutation, &format!("vendor-rule-native-{index}-"))
            || !belongs(&step.readback, &format!("vendor-rule-readback-{index}-")) {
            return Err("RecoveryRequired: vendor retirement journal association conflict".into());
        }
        receive_mutation(slot, &step.mutation, item)?;
        let readback = receive_inspection(slot, &step.readback, &item.scope, &item.name, true)?;
        if !readback.persistent.is_empty() || !readback.active.is_empty() {
            return Err("RecoveryRequired: vendor retirement readback not empty".into());
        }
    }
    Ok(())
}

pub(super) fn retained_vendor_retirement(slot: &CheckedPath, dir: &Path,
    plan: &VendorRetirementPlan) -> Result<Vec<EvidenceRef>> {
    let mut steps = Vec::new();
    for index in 0..plan.plans.len() {
        let path = dir.join(format!("vendor-rule-complete-{index}.json"));
        let bytes = read_private(&path)?;
        let relative = path.strip_prefix(&slot.path).map_err(|_| "vendor retirement outside slot")?
            .to_str().ok_or("vendor retirement path encoding")?.replace('\\', "/");
        steps.push(EvidenceRef { path: relative, digest: hash(&bytes) });
    }
    receive_vendor_retirement(slot, dir, plan, &steps)?;
    Ok(steps)
}

pub(super) fn recheck_vendor_retirement(authority: &Authority, operation_dir: &Path, plan: &VendorRetirementPlan,
    runner: &mut Option<&mut dyn GatewayRuleRunner>, cancel: &AtomicBool) -> GatewayResult<Vec<EvidenceRef>> {
    if plan.plans.is_empty() { return Ok(Vec::new()); }
    if runner.is_none() { return Err(GatewayRuleError::RecoveryRequired("vendor retirement runner absent".into())); }
    let directory = operation_dir.join(format!("vendor-rule-final-{}", unique_id()?));
    create_private_dir(&directory)?;
    let mut checks = Vec::new();
    for (index, item) in plan.plans.iter().enumerate() {
        let active_runner = runner.as_deref_mut().ok_or_else(|| GatewayRuleError::RecoveryRequired("vendor retirement runner absent".into()))?;
        let value = journal_run(authority, &directory, &format!("final-{index}"),
            &GatewayRuleRequest::InspectOwned { scope: item.scope.clone(), name: item.name.clone() }, active_runner, cancel)?;
        let actual = receive_inspection(&authority.slot, &value, &item.scope, &item.name, true)?;
        if !actual.persistent.is_empty() || !actual.active.is_empty() {
            return Err(GatewayRuleError::RecoveryRequired("retired prior-host rule became present".into()));
        }
        checks.push(value);
    }
    Ok(checks)
}

pub(super) fn receive_vendor_final_checks(slot: &CheckedPath, operation_dir: &Path,
    plan: &VendorRetirementPlan, checks: &[EvidenceRef]) -> Result<()> {
    if checks.len() != plan.plans.len() { return Err("RecoveryRequired: vendor final rule readbacks missing".into()); }
    let mut selected_parent: Option<PathBuf> = None;
    for (index, (item, value)) in plan.plans.iter().zip(checks).enumerate() {
        let path = slot.path.join(&value.path);
        let parent = path.parent().ok_or("vendor final rule directory absent")?;
        let dir_id = parent.file_name().and_then(OsStr::to_str)
            .and_then(|name| name.strip_prefix("vendor-rule-final-"));
        let serial = path.file_name().and_then(OsStr::to_str)
            .and_then(|name| name.strip_prefix(&format!("final-{index}-")))
            .and_then(|name| name.strip_suffix(".json"));
        if parent.parent() != Some(operation_dir) || !dir_id.is_some_and(id_valid)
            || !serial.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            || selected_parent.as_ref().is_some_and(|selected| selected.as_path() != parent) {
            return Err("RecoveryRequired: vendor final rule readback association conflict".into());
        }
        selected_parent.get_or_insert_with(|| parent.to_owned());
        let actual = receive_inspection(slot, value, &item.scope, &item.name, true)?;
        if !actual.persistent.is_empty() || !actual.active.is_empty() {
            return Err("RecoveryRequired: vendor final rule readback not empty".into());
        }
    }
    Ok(())
}
fn store_receipt(
    authority: &Authority,
    dir: &Path,
    index: usize,
    operation_id: &str,
    plan: &RulePlan,
    observation: &GatewayRuleInspection,
    readback: EvidenceRef,
    creation: Option<EvidenceRef>,
) -> GatewayResult<EvidenceRef> {
    let (persistent, active) = receive_pair(&plan.scope, &plan.name, observation)?;
    let receipt = GatewayRuleReceiptV1 {
        version: 1,
        operation_id: operation_id.into(),
        intended_name: plan.name.clone(),
        actual_name: plan.name.clone(),
        ownership: if creation.is_some() {
            RuleCustody::CreatedByOperation
        } else {
            RuleCustody::ObservedExternal
        },
        scope: plan.scope.clone(),
        persistent: persistent.clone(),
        active: active.clone(),
        readback,
        creation,
    };
    let value = authority.save(dir, &format!("rule-{index}.json"), &json(&receipt)?)?;
    receive_receipt(&authority.slot, &plan.scope.host, &value)?;
    Ok(value)
}
fn finish<R: GatewayRuleRunner + ?Sized>(
    authority: &mut Authority,
    intent_ref: &EvidenceRef,
    dir: &Path,
    mutation_refs: &[EvidenceRef],
    runner: &mut R,
    cancel: &AtomicBool,
) -> GatewayResult<()> {
    let (intent, prior) = receive_intent(&authority.slot, intent_ref)?;
    let mut refs = intent
        .prior_deployment
        .gateway_rules
        .clone()
        .unwrap_or_default();
    let mut mutations = mutation_refs.iter();
    let mut readbacks = Vec::new();
    for (index, plan) in intent.plans.iter().enumerate() {
        let creation = match plan.action {
            RuleAction::Create | RuleAction::Remove => {
                let value = mutations.next().ok_or_else(|| {
                    GatewayRuleError::RecoveryRequired(
                        "gateway native outcome missing; no replay permitted".into(),
                    )
                })?;
                receive_mutation(&authority.slot, value, plan)?;
                Some(value.clone())
            }
            _ => None,
        };
        let inspection_ref = journal_run(
            authority,
            dir,
            &format!("readback-{index}"),
            &if plan.action == RuleAction::Remove {
                GatewayRuleRequest::InspectOwned { scope: plan.scope.clone(), name: plan.name.clone() }
            } else { GatewayRuleRequest::Inspect { scope: plan.scope.clone(), name: Some(plan.name.clone()) } },
            runner,
            cancel,
        )?;
        let observation =
            receive_inspection(&authority.slot, &inspection_ref, &plan.scope, &plan.name, plan.action == RuleAction::Remove)?;
        readbacks.push(inspection_ref.clone());
        match plan.action {
            RuleAction::Remove => {
                if !observation.persistent.is_empty() || !observation.active.is_empty() {
                    return Err(GatewayRuleError::RecoveryRequired(
                        "owned gateway removal not confirmed in both stores".into(),
                    ));
                }
                let remove = plan.receipt.as_ref().ok_or_else(|| {
                    GatewayRuleError::RecoveryRequired("retirement receipt absent".into())
                })?;
                refs.retain(|value| value != remove);
            }
            RuleAction::Reuse => {
                let value = plan.receipt.as_ref().ok_or_else(|| {
                    GatewayRuleError::RecoveryRequired("reuse receipt absent".into())
                })?;
                let receipt = receive_receipt(&authority.slot, &plan.scope.host, value)?;
                let (persistent, active) = receive_pair(&plan.scope, &plan.name, &observation)?;
                if persistent != &receipt.persistent || active != &receipt.active {
                    return Err(GatewayRuleError::RecoveryRequired(
                        "reused rule changed after Pending; preserved".into(),
                    ));
                }
            }
            RuleAction::Create | RuleAction::ObserveExternal => {
                if plan.action == RuleAction::ObserveExternal {
                    let before = plan.observation.as_ref().ok_or_else(|| {
                        GatewayRuleError::RecoveryRequired("external observation absent".into())
                    })?;
                    if before.persistent != observation.persistent
                        || before.active != observation.active
                    {
                        return Err(GatewayRuleError::RecoveryRequired(
                            "external rule changed before dependency publication".into(),
                        ));
                    }
                }
                refs.push(store_receipt(
                    authority,
                    dir,
                    index,
                    &intent.operation_id,
                    plan,
                    &observation,
                    inspection_ref,
                    creation,
                )?);
            }
        }
    }
    if mutations.next().is_some() {
        return Err(GatewayRuleError::RecoveryRequired(
            "unexpected gateway native outcome".into(),
        ));
    }
    let mut deployment = intent.prior_deployment.clone();
    deployment.version = 2;
    deployment.gateway_rules = Some(refs);
    deployment.receipt = authority.save(
        dir,
        "runtime-deployment.json",
        &json(&deployment.receipt())?,
    )?;
    deployment.receive_receipt(&authority.slot)?;
    let outcome = GatewayOutcome {
        schema: 3,
        slot_id: intent.slot_id,
        operation_id: intent.operation_id,
        intent: intent_ref.clone(),
        attempts: mutation_refs.into(),
        readbacks,
        deployment: deployment.clone(),
    };
    let evidence = authority.save(
        dir,
        "outcome.json",
        &json(&Settlement::GatewayRules(outcome))?,
    )?;
    let mut next = prior.clone();
    next.revision = authority
        .current
        .revision
        .checked_add(1)
        .ok_or("canonical revision overflow".to_owned())?;
    next.runtime_deployment = DeploymentField::Present(Some(deployment));
    next.settled
        .as_mut()
        .ok_or("gateway prior settlement absent".to_owned())?
        .evidence = evidence;
    authority.publish(next)?;
    // Structural creation/removal custody is now durably published. Fresh
    // effectiveness may deny Ready, but cannot erase an actual created rule's
    // receipt/deployment/Current or strand it behind a new pre-custody veto.
    if intent.kind == GatewayOperation::Configure {
        let published = authority.current.runtime_deployment.received()?;
        let refs = published.gateway_rules.as_ref().ok_or_else(||
            GatewayRuleError::RecoveryRequired("published configure receipts absent".into()))?;
        for plan in &intent.plans {
            // Bind the live check to the incarnation actually published above,
            // not merely a healthy same-name replacement with matching filters.
            let mut selected = None;
            for value in refs {
                let receipt = receive_receipt(&authority.slot, &published.host, value)?;
                if receipt.scope == plan.scope {
                    if selected.is_some() { return Err(GatewayRuleError::RecoveryRequired("duplicate published gateway scope".into())); }
                    selected = Some(receipt);
                }
            }
            let receipt = selected.filter(|receipt| receipt.actual_name == plan.name).ok_or_else(||
                GatewayRuleError::RecoveryRequired("published gateway receipt does not bind the configured rule".into()))?;
            let observation = inspect(runner, &plan.scope, Some(&plan.name), cancel)?;
            let (persistent, active) = receive_ready_pair(&plan.scope, &plan.name, &observation)?;
            if persistent != &receipt.persistent || active != &receipt.active {
                return Err(GatewayRuleError::MissingConfiguration("published gateway incarnation changed before readiness; actual custody preserved".into()));
            }
        }
    }
    Ok(())
}

fn execute<R: GatewayRuleRunner, W: MaintenanceWindow>(
    mut prepared: PreparedGatewayRules<'_>,
    runner: &mut R,
    window: &mut W,
    cancel: &AtomicBool,
) -> GatewayResult<()> {
    if cancel.load(Ordering::SeqCst) {
        return Err(GatewayRuleError::CancelledBeforeMutation);
    }
    if prepared
        .plans
        .iter()
        .all(|plan| plan.action == RuleAction::Reuse)
    {
        // Reuse is a live authorization, not credit from an earlier inspection
        // or an immutable receipt. Requery even when no native effect is needed.
        for plan in &prepared.plans {
            let observation = inspect(runner, &plan.scope, Some(&plan.name), cancel)?;
            receive_ready_pair(&plan.scope, &plan.name, &observation)?;
            let receipt = receive_receipt(&prepared.authority.slot, &plan.scope.host,
                plan.receipt.as_ref().ok_or_else(|| GatewayRuleError::RecoveryRequired("reuse receipt absent".into()))?)?;
            if observation.persistent != vec![receipt.persistent] || observation.active != vec![receipt.active] {
                return Err(GatewayRuleError::MissingConfiguration("reused gateway identity changed; preserved".into()));
            }
        }
        return Ok(());
    }
    // Read-only preparation never requires writer admission or elevation. Only
    // changes retire the preparation reader and acquire the native write gate.
    drop(prepared.read.take());
    prepared.authority.admit_maintenance_gate()?;
    prepared.bound.revalidate_context()?;
    prepared.host.recheck()?;
    window.ensure_held()?;
    for plan in &prepared.plans {
        let observation = if plan.action == RuleAction::Remove {
            inspect_owned(runner, &plan.scope, &plan.name, cancel)?
        } else { inspect(runner, &plan.scope, Some(&plan.name), cancel)? };
        if matches!(plan.action, RuleAction::Create | RuleAction::Remove)
            && !observation.administrator
        {
            return Err(GatewayRuleError::NeedsElevation);
        }
        if plan.action == RuleAction::Create {
            if !observation.persistent.is_empty() || !observation.active.is_empty() {
                return Err(GatewayRuleError::RecoveryRequired(
                    "operation name occupied before Pending; no mutation".into(),
                ));
            }
        } else {
            let before = plan.observation.as_ref().ok_or_else(|| {
                GatewayRuleError::RecoveryRequired("gateway preimage missing".into())
            })?;
            if prepared.kind == GatewayOperation::Configure {
                receive_ready_pair(&plan.scope, &plan.name, &observation)?;
            } else { receive_pair(&plan.scope, &plan.name, &observation)?; }
            if before.persistent != observation.persistent || before.active != observation.active {
                return Err(GatewayRuleError::MissingConfiguration(
                    "gateway preimage changed before Pending; preserved".into(),
                ));
            }
        }
    }
    if cancel.load(Ordering::SeqCst) {
        return Err(GatewayRuleError::CancelledBeforeMutation);
    }
    let prior = prepared.authority.current.clone();
    let dir = operation_evidence(&prepared.authority, &prepared.id)?;
    let intent = GatewayIntent {
        schema: 3,
        slot_id: prior.slot_id.clone(),
        operation_id: prepared.id.clone(),
        kind: prepared.kind,
        expected_current_digest: prepared.authority.digest.clone(),
        prior_current: prepared.authority.retain_current()?,
        prior_deployment: prior.runtime_deployment.received()?.clone(),
        plans: prepared.plans,
    };
    let intent_ref = prepared
        .authority
        .save(&dir, "intent.json", &json(&intent)?)?;
    let mut pending = prior;
    pending.revision = pending
        .revision
        .checked_add(1)
        .ok_or("canonical revision overflow".to_owned())?;
    pending.mode = Mode::Pending;
    pending.settled = None;
    pending.active_operation = Some(Operation {
        id: prepared.id,
        kind: operation_kind(&intent.kind),
        intent: intent_ref.clone(),
        prior_current_digest: prepared.authority.digest.clone(),
    });
    prepared.authority.publish(pending)?;
    let mut mutations = Vec::new();
    for (index, plan) in intent.plans.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            return Err(GatewayRuleError::RecoveryRequired(
                "cancelled after Pending; invocation evidence retained; no replay".into(),
            ));
        }
        prepared.bound.revalidate_context()?;
        prepared.host.recheck()?;
        window.ensure_held()?;
        let request = match plan.action {
            RuleAction::Create => GatewayRuleRequest::Create {
                scope: plan.scope.clone(),
                name: plan.name.clone(),
            },
            RuleAction::Remove => {
                let before = plan.observation.as_ref().ok_or_else(|| {
                    GatewayRuleError::RecoveryRequired("removal observations absent".into())
                })?;
                let (persistent, active) = receive_pair(&plan.scope, &plan.name, before)?;
                GatewayRuleRequest::Remove {
                    scope: plan.scope.clone(),
                    persistent: persistent.clone(),
                    active: active.clone(),
                }
            }
            _ => continue,
        };
        let value = journal_run(
            &prepared.authority,
            &dir,
            &format!("native-{index}"),
            &request,
            runner,
            cancel,
        )?;
        mutations.push(value);
        // Persist exact successful invocation references before another effect.
        prepared.authority.save(
            &dir,
            &format!("completed-{index}.json"),
            &json(mutations.last().unwrap())?,
        )?;
    }
    window.ensure_held()?;
    prepared.bound.revalidate_context()?;
    prepared.host.recheck()?;
    finish(
        &mut prepared.authority,
        &intent_ref,
        &dir,
        &mutations,
        runner,
        cancel,
    )
}
pub(crate) fn ensure_gateway_rules<R: GatewayRuleRunner, W: MaintenanceWindow>(
    prepared: PreparedGatewayRules<'_>,
    runner: &mut R,
    window: &mut W,
    cancel: &AtomicBool,
) -> GatewayResult<()> {
    if prepared.kind != GatewayOperation::Configure {
        return Err(GatewayRuleError::Invalid(
            "configure capability required".into(),
        ));
    }
    execute(prepared, runner, window, cancel)
}
pub(crate) fn retire_gateway_rules<R: GatewayRuleRunner, W: MaintenanceWindow>(
    prepared_owned_refs: PreparedGatewayRules<'_>,
    runner: &mut R,
    window: &mut W,
    cancel: &AtomicBool,
) -> GatewayResult<()> {
    if prepared_owned_refs.kind != GatewayOperation::Retire {
        return Err(GatewayRuleError::Invalid(
            "retirement capability required".into(),
        ));
    }
    execute(prepared_owned_refs, runner, window, cancel)
}

pub(super) fn receive_settled(
    slot: &CheckedPath,
    current: &Current,
    outcome: &GatewayOutcome,
) -> Result<(TargetState, Option<archive_install::AppliedArchive>)> {
    let (intent, prior) = receive_intent(slot, &outcome.intent)?;
    if outcome.schema != 3
        || outcome.slot_id != current.slot_id
        || outcome.operation_id != intent.operation_id
        || current.mode != Mode::SettledApplied
        || current.schema != 3
        || current.binding != prior.binding
        || json(current.runtime_deployment.received()?)? != json(&outcome.deployment)?
    {
        return Err("RecoveryRequired: gateway settlement binding conflict".into());
    }
    if outcome.readbacks.len() != intent.plans.len() {
        return Err("gateway settlement readbacks incomplete".into());
    }
    let mut mutations = outcome.attempts.iter();
    let mut expected = intent
        .prior_deployment
        .gateway_rules
        .clone()
        .unwrap_or_default();
    for (plan, readback_ref) in intent.plans.iter().zip(&outcome.readbacks) {
        let readback = receive_inspection(slot, readback_ref, &plan.scope, &plan.name, plan.action == RuleAction::Remove)?;
        match plan.action {
            RuleAction::Remove => {
                receive_mutation(
                    slot,
                    mutations.next().ok_or("gateway removal evidence absent")?,
                    plan,
                )?;
                if !readback.persistent.is_empty() || !readback.active.is_empty() {
                    return Err("gateway settlement removal not confirmed in both stores".into());
                }
                expected.retain(|value| Some(value) != plan.receipt.as_ref());
            }
            RuleAction::Create | RuleAction::ObserveExternal => {
                let creation = if plan.action == RuleAction::Create {
                    let value = mutations.next().ok_or("gateway creation evidence absent")?;
                    receive_mutation(slot, value, plan)?;
                    Some(value)
                } else {
                    None
                };
                let value = outcome
                    .deployment
                    .gateway_rules
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .find(|value| {
                        receive_receipt(slot, &plan.scope.host, value).is_ok_and(|receipt| {
                            receipt.scope == plan.scope && receipt.actual_name == plan.name
                        })
                    })
                    .ok_or("gateway settlement rule receipt absent")?;
                let receipt = receive_receipt(slot, &plan.scope.host, value)?;
                if receipt.operation_id != intent.operation_id
                    || receipt.creation.as_ref() != creation
                    || &receipt.readback != readback_ref
                {
                    return Err("gateway settlement creation/external custody conflict".into());
                }
                expected.push(value.clone());
            }
            RuleAction::Reuse => {
                let value = plan
                    .receipt
                    .as_ref()
                    .ok_or("gateway reuse receipt absent")?;
                let receipt = receive_receipt(slot, &plan.scope.host, value)?;
                if readback.persistent != [receipt.persistent]
                    || readback.active != [receipt.active]
                {
                    return Err("gateway reuse readback differs from retained custody".into());
                }
            }
        }
    }
    if mutations.next().is_some()
        || outcome.deployment.version != 2
        || outcome.deployment.gateway_rules.as_ref() != Some(&expected)
        || outcome.deployment.gate != intent.prior_deployment.gate
        || outcome.deployment.host != intent.prior_deployment.host
        || outcome.deployment.hook != intent.prior_deployment.hook
    {
        return Err(
            "RecoveryRequired: gateway deployment result is not the exact intent transformation"
                .into(),
        );
    }
    outcome.deployment.receive_receipt(slot)?;
    super::receive_settlement(slot, &prior)
}

/// Recovery performs no create/remove replay. Only complete retained invocation
/// evidence plus fresh exact-name receiving may finish the same Pending action.
pub(crate) fn recover_gateway_rules<R: GatewayRuleRunner + ?Sized, W: MaintenanceWindow>(
    bound: &BoundInstallation,
    operation_id: &str,
    expected_current_sha256: &str,
    runner: &mut R,
    window: &mut W,
    cancel: &AtomicBool,
) -> GatewayResult<()> {
    let mut authority = Authority::open(bound, false, true)?;
    let operation = authority
        .current
        .active_operation
        .clone()
        .filter(|operation| {
            authority.current.mode == Mode::Pending
                && operation.id == operation_id
                && matches!(
                    operation.kind,
                    OperationKind::ConfigureGatewayRules | OperationKind::RetireGatewayRules
                )
        })
        .ok_or_else(|| {
            GatewayRuleError::RecoveryRequired("exact Pending gateway operation required".into())
        })?;
    if authority.digest != expected_current_sha256 {
        return Err(GatewayRuleError::RecoveryRequired(
            "gateway recovery expected current digest differs".into(),
        ));
    }
    receive_pending(&authority.slot, &authority.current, &operation)?;
    authority.admit_maintenance_gate()?;
    bound.revalidate_context()?;
    window.ensure_held()?;
    let (intent, prior) = receive_intent(&authority.slot, &operation.intent)?;
    if prior.binding != bound.binding()? {
        return Err(GatewayRuleError::RecoveryRequired(
            "gateway recovery installation incarnation differs".into(),
        ));
    }
    intent.prior_deployment.receive_host(&authority.slot)?;
    let original_dir = authority.slot.path.join("evidence").join(operation_id);
    let mut refs = Vec::new();
    for (index, plan) in intent.plans.iter().enumerate() {
        if !matches!(plan.action, RuleAction::Create | RuleAction::Remove) {
            continue;
        }
        // Absence, a success-looking native rule, or an unknown old RunAs process
        // cannot manufacture an invocation outcome or confer rollback rights.
        let bytes = read_private(&original_dir.join(format!("completed-{index}.json")))?;
        let value: EvidenceRef = decode(&bytes)?;
        receive_mutation(&authority.slot, &value, plan)?;
        refs.push(value);
    }
    let dir = authority.evidence_dir("gateway-recovery")?;
    finish(
        &mut authority,
        &operation.intent,
        &dir,
        &refs,
        runner,
        cancel,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace() -> GatewayNamespace {
        GatewayNamespace {
            interface_index: 19,
            interface_alias: "vEthernet (fixture)".into(),
            local_address: Ipv4Addr::new(172, 20, 0, 1),
            source_address: Ipv4Addr::new(172, 20, 0, 2),
        }
    }
    fn scope() -> GatewayRuleScope {
        GatewayRuleScope {
            host: HostBinding {
                path: PathBuf::from(r"C:\fixture\host.exe"),
                native_id: ObjectId {
                    volume: 7,
                    file: [9; 16],
                },
                sha256: "a".repeat(64),
            },
            namespace: namespace(),
        }
    }
    fn rule(scope: &GatewayRuleScope) -> GatewayNativeRule {
        GatewayNativeRule {
            name: "fixture-rule".into(),
            instance_id: Some("fixture-native-instance".into()),
            policy_store_source: Some("PersistentStore".into()),
            policy_store_source_type: Some("Local".into()),
            enabled: true,
            direction: "Inbound".into(),
            action: "Allow".into(),
            program: scope.host.path.clone(),
            protocol: "TCP".into(),
            local_ports: vec!["Any".into()],
            remote_ports: vec!["Any".into()],
            local_addresses: vec![scope.namespace.local_address.to_string()],
            remote_addresses: vec![scope.namespace.source_address.to_string()],
            interface_aliases: vec![scope.namespace.interface_alias.clone()],
            interface_types: vec!["Any".into()],
            profiles: GATEWAY_RULE_PROFILES,
            edge_traversal: "Block".into(),
            service: "Any".into(),
            package: "Any".into(),
            local_users: "Any".into(),
            remote_users: "Any".into(),
            remote_machines: "Any".into(),
            authentication: "NotRequired".into(),
            encryption: "NotRequired".into(),
            override_block_rules: false,
        }
    }
    fn inspection() -> GatewayRuleInspection {
        let scope = scope();
        let rule = rule(&scope);
        GatewayRuleInspection {
            administrator: false,
            active_profiles: 2,
            namespace: Some(scope.namespace),
            policy: GatewayPolicyObservation::Allowed,
            persistent: vec![rule.clone()],
            active: vec![rule],
            active_enforcement: Some(vec![ActiveRuleEnforcement {
                name: "fixture-rule".into(),
                instance_id: Some("fixture-native-instance".into()),
                primary_status: Some(1),
                enforcement_status: Some(vec![1]),
            }]),
        }
    }
    #[test]
    fn historical_observation_is_structural_and_never_live_admission() {
        let scope = scope();
        let legacy = inspection();
        let bytes = json(&legacy).unwrap();
        let restored: GatewayRuleInspection = decode(&bytes).unwrap();
        assert_eq!(json(&restored).unwrap(), bytes);
        let mut historical = legacy;
        historical.namespace = None;
        historical.policy = GatewayPolicyObservation::Unavailable("historical custody inspection; no live transport admission".into());
        historical.active_enforcement = None;
        assert!(receive_historical_environment(&scope, &historical).is_ok());
        assert!(receive_pair(&scope, "fixture-rule", &historical).is_ok());
        assert!(receive_environment(&scope, &historical).is_err());
        assert!(receive_ready_pair(&scope, "fixture-rule", &historical).is_err());
        let bytes = json(&historical).unwrap();
        let restored: GatewayRuleInspection = decode(&bytes).unwrap();
        assert_eq!(restored, historical);
        let mut missing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        missing.as_object_mut().unwrap().remove("namespace");
        assert!(serde_json::from_value::<GatewayRuleInspection>(missing).is_err());
        historical.policy = GatewayPolicyObservation::Allowed;
        assert!(receive_historical_environment(&scope, &historical).is_err());
    }
    #[test]
    fn historical_request_wire_is_closed_and_preserves_legacy_inspect() {
        let scope = scope();
        let legacy = GatewayRuleRequest::Inspect { scope: scope.clone(), name: Some("fixture-rule".into()) };
        let bytes = json(&legacy).unwrap();
        let decoded: GatewayRuleRequest = decode(&bytes).unwrap();
        assert_eq!(json(&decoded).unwrap(), bytes);
        let owned = GatewayRuleRequest::InspectOwned { scope, name: "fixture-rule".into() };
        let bytes = json(&owned).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["action"], "inspectOwned");
        assert_eq!(value["name"], "fixture-rule");
        let decoded: GatewayRuleRequest = decode(&bytes).unwrap();
        assert_eq!(json(&decoded).unwrap(), bytes);
        let mut malformed = value.clone(); malformed["action"] = "unknown".into();
        assert!(serde_json::from_value::<GatewayRuleRequest>(malformed).is_err());
        let mut malformed = value; malformed.as_object_mut().unwrap().remove("name");
        assert!(serde_json::from_value::<GatewayRuleRequest>(malformed).is_err());
    }
    #[test]
    fn acknowledged_vendor_preimage_is_only_the_selected_alias_change() {
        let scope = scope();
        let original = rule(&scope);
        let reference = EvidenceRef { path: "evidence/fixture/receipt.json".into(), digest: "a".repeat(64) };
        let mut receipt = GatewayRuleReceiptV1 { version: 1, operation_id: "b".repeat(32),
            intended_name: original.name.clone(), actual_name: original.name.clone(), ownership: RuleCustody::CreatedByOperation,
            scope: scope.clone(), persistent: original.clone(), active: original.clone(), readback: reference.clone(), creation: Some(reference.clone()) };
        let mut current = original.clone(); current.interface_aliases = vec!["synthetic-current-guid".into()];
        let selection = GatewayRetirementSelectionV1 { version: 1, operation: GatewayRetirementSelectionOperation::RetireObservedInterfaceAliases,
            slot_id: "c".repeat(32), prior_current_sha256: "d".repeat(64), new_binding_sha256: "e".repeat(64),
            saved_settings_sha256: "f".repeat(64), old_host: scope.host.clone(), receipt: reference.clone(),
            persistent: current.clone(), active: current.clone() };
        let id = scope.host.native_id.clone();
        let expected = VendorUpdateObservation { slot_id: "c".repeat(32), prior_current_sha256: [0xdd; 32],
            new_parent_id: id.clone(), new_resources_id: id.clone(), new_archive_id: id,
            new_executable_sha256: [1; 32], new_archive_sha256: [2; 32], new_binding_sha256: [0xee; 32] };
        assert!(selection.validate_binding(&expected, &[0xff; 32]).is_ok());
        assert!(selection.validate_binding(&expected, &[0; 32]).is_err());
        let mut stale = expected.clone(); stale.prior_current_sha256[0] ^= 1;
        assert!(selection.validate_binding(&stale, &[0xff; 32]).is_err());
        let mut stale = expected; stale.new_binding_sha256[0] ^= 1;
        assert!(selection.validate_binding(&stale, &[0xff; 32]).is_err());
        let mut observed = inspection(); observed.namespace = None;
        observed.policy = GatewayPolicyObservation::Unavailable("historical custody inspection; no live transport admission".into());
        observed.active_enforcement = None; observed.persistent = vec![current.clone()]; observed.active = vec![current];
        assert!(receive_vendor_pair(&receipt, &reference, &observed, None).is_err());
        assert!(receive_vendor_pair(&receipt, &reference, &observed, Some(&selection)).is_ok());
        let mut altered = observed.clone(); altered.active[0].instance_id = Some("other-instance".into());
        assert!(receive_vendor_pair(&receipt, &reference, &altered, Some(&selection)).is_err());
        let mut selected = selection.clone(); selected.active.remote_addresses = vec!["192.0.2.77".into()];
        altered = observed.clone(); altered.active = vec![selected.active.clone()];
        assert!(receive_vendor_pair(&receipt, &reference, &altered, Some(&selected)).is_err());
        receipt.ownership = RuleCustody::ObservedExternal;
        assert!(receive_vendor_pair(&receipt, &reference, &observed, Some(&selection)).is_err());
        receipt.ownership = RuleCustody::CreatedByOperation;
        let mut wrong = selection.clone(); wrong.receipt.digest = "1".repeat(64);
        assert!(receive_vendor_pair(&receipt, &reference, &observed, Some(&wrong)).is_err());
        let old: VendorRetirementPlan = serde_json::from_str(r#"{"plans":[]}"#).unwrap();
        assert!(old.admission.is_exact());
        assert_eq!(serde_json::to_string(&old).unwrap(), r#"{"plans":[]}"#);
        let selected = VendorRetirementPlan { plans: Vec::new(), admission: VendorRetirementAdmission::AcknowledgedInterfaceAliases { selection } };
        let bytes = json(&selected).unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(wire["admission"]["kind"], "acknowledgedInterfaceAliases");
        assert_eq!(wire["admission"]["selection"]["operation"], "retireObservedInterfaceAliases");
        let roundtrip: VendorRetirementPlan = decode(&bytes).unwrap();
        assert_eq!(json(&roundtrip).unwrap(), bytes);
        for invalid in [r#"{"plans":[],"admission":null}"#, r#"{"plans":[],"admission":{"kind":"other"}}"#] {
            assert!(serde_json::from_str::<VendorRetirementPlan>(invalid).is_err());
        }
    }
    #[test]
    #[ignore = "Root-selected read-only installation and snapshots; creates only the explicit private output"]
    fn export_selected_vendor_retirement_input() {
        let target = PathBuf::from(std::env::var_os("AG_RETIREMENT_TARGET_EXE").expect("explicit selected Desktop executable"));
        let snapshots = PathBuf::from(std::env::var_os("AG_RETIREMENT_SNAPSHOTS").expect("explicit approved snapshot file"));
        let output = PathBuf::from(std::env::var_os("AG_RETIREMENT_OUTPUT").expect("explicit vacant private output file"));
        let receipt_digest = std::env::var("AG_RETIREMENT_RECEIPT_SHA256").expect("explicit selected receipt digest");
        let snapshot_digest = std::env::var("AG_RETIREMENT_SNAPSHOTS_SHA256").expect("explicit approved snapshot digest");
        let pin = CheckedPath::open(&snapshots, PathKind::File, PathPurpose::Source).unwrap();
        let bytes = pin.read_snapshot().unwrap(); assert_eq!(hash(&bytes), snapshot_digest);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let observation = &value["observation"];
        let persistent: Vec<GatewayNativeRule> = serde_json::from_value(observation["capturedPersistent"].clone()).unwrap();
        let active: Vec<GatewayNativeRule> = serde_json::from_value(observation["capturedActive"].clone()).unwrap();
        assert_eq!(persistent.len(), 1); assert_eq!(active.len(), 1);
        let mut bound = BoundInstallation::open(&target).unwrap();
        if let Some(context) = crate::windows_coordinator::receive_saved_context(&bound).unwrap() { bound.attach_ancestor_context(context).unwrap(); }
        let expected = match observe_apply_current(&bound).unwrap() { ApplyCurrentObservation::VendorReplacement(value) => value, _ => panic!("selected target is not a vendor replacement") };
        let state = receive_requirement_state_inner(&bound, Some(&expected)).unwrap();
        let (slot, current, _) = state.received.as_ref().unwrap();
        let old = current.runtime_deployment.received().unwrap();
        let matches: Vec<_> = old.gateway_rules.as_deref().unwrap_or(&[]).iter().filter(|value| value.digest == receipt_digest).collect();
        assert_eq!(matches.len(), 1);
        let receipt_ref = matches[0].clone();
        let receipt = receive_receipt(slot, &old.host, &receipt_ref).unwrap();
        let saved = crate::settings::saved_intent_sha256(&crate::settings::Settings::load()).unwrap();
        let selection = GatewayRetirementSelectionV1 { version: 1, operation: GatewayRetirementSelectionOperation::RetireObservedInterfaceAliases,
            slot_id: expected.slot_id.clone(), prior_current_sha256: hex::encode(expected.prior_current_sha256),
            new_binding_sha256: hex::encode(expected.new_binding_sha256), saved_settings_sha256: hex::encode(saved),
            old_host: old.host.clone(), receipt: receipt_ref.clone(), persistent: persistent[0].clone(), active: active[0].clone() };
        let inspection = GatewayRuleInspection { administrator: observation["administrator"].as_bool().unwrap(),
            active_profiles: observation["activeProfiles"].as_u64().unwrap().try_into().unwrap(), namespace: None,
            policy: GatewayPolicyObservation::Unavailable("historical custody inspection; no live transport admission".into()),
            persistent, active, active_enforcement: None };
        selection.validate_binding(&expected, &saved).unwrap();
        receive_vendor_pair(&receipt, &receipt_ref, &inspection, Some(&selection)).unwrap();
        absent(&output).unwrap();
        write_private(&output, &json(&selection).unwrap()).unwrap();
    }
    #[test]
    fn fresh_ready_requires_bound_healthy_effect_and_historical_shape_is_unchanged() {
        let scope = scope();
        let good = inspection();
        assert!(receive_ready_pair(&scope, "fixture-rule", &good).is_ok());
        let mut legacy = good.clone();
        legacy.active_enforcement = None;
        let bytes = json(&legacy).unwrap();
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("activeEnforcement"));
        let roundtrip: GatewayRuleInspection = decode(&bytes).unwrap();
        assert_eq!(json(&roundtrip).unwrap(), bytes);
        assert!(receive_pair(&scope, "fixture-rule", &roundtrip).is_ok());
        assert!(receive_ready_pair(&scope, "fixture-rule", &roundtrip).is_err());
        for (primary, enforcement) in [
            (None, Some(vec![1])), (Some(1), None), (Some(1), Some(vec![])),
            (Some(2), Some(vec![20])), (Some(1), Some(vec![1,20])),
            (Some(99), Some(vec![1])), (Some(1), Some(vec![99])),
        ] {
            let mut changed = good.clone();
            let effect = &mut changed.active_enforcement.as_mut().unwrap()[0];
            effect.primary_status = primary; effect.enforcement_status = enforcement;
            assert!(receive_pair(&scope, "fixture-rule", &changed).is_ok());
            assert!(receive_ready_pair(&scope, "fixture-rule", &changed).is_err());
        }
        let mut changed = good.clone(); changed.active_enforcement.as_mut().unwrap()[0].name = "other-rule".into();
        assert!(receive_ready_pair(&scope, "fixture-rule", &changed).is_err());
        let mut changed = good.clone(); changed.active_enforcement.as_mut().unwrap()[0].instance_id = Some("other-instance".into());
        assert!(receive_ready_pair(&scope, "fixture-rule", &changed).is_err());
        let mut changed = good.clone(); changed.active_enforcement.as_mut().unwrap().push(good.active_enforcement.as_ref().unwrap()[0].clone());
        assert!(receive_ready_pair(&scope, "fixture-rule", &changed).is_err());
        for field in ["primaryStatus", "enforcementStatus"] {
            let mut malformed = serde_json::to_value(&good).unwrap();
            malformed["activeEnforcement"][0][field] = "localized display string".into();
            assert!(serde_json::from_value::<GatewayRuleInspection>(malformed).is_err());
        }
    }
    #[test]
    fn unrestricted_package_scope_keeps_wire_and_v1_preimages_exact() {
        for value in ["", "Any"] { assert!(package_is_unrestricted(value)); }
        for value in ["any", " Any", "Any ", " ", "*", "S-1-15-2-123456789"] { assert!(!package_is_unrestricted(value)); }
        let scope = scope();
        let old_any = rule(&scope);
        let mut raw_empty = old_any.clone(); raw_empty.package.clear();
        assert!(exact_rule(&old_any, &scope).unwrap());
        assert!(exact_rule(&raw_empty, &scope).unwrap());
        assert_ne!(raw_empty, old_any); // Semantic alias is never raw preimage equality.
        let bytes = json(&raw_empty).unwrap();
        let received: GatewayNativeRule = decode(&bytes).unwrap();
        assert_eq!(received.package, ""); assert_eq!(json(&received).unwrap(), bytes);
        for invalid in [serde_json::Value::Null, serde_json::json!([]), serde_json::json!(0)] {
            let mut wire = serde_json::to_value(&raw_empty).unwrap(); wire["package"] = invalid;
            assert!(serde_json::from_value::<GatewayNativeRule>(wire).is_err());
        }
        let mut missing = serde_json::to_value(&raw_empty).unwrap(); missing.as_object_mut().unwrap().remove("package");
        assert!(serde_json::from_value::<GatewayNativeRule>(missing).is_err());
        let mut restricted = raw_empty; restricted.package = "S-1-15-2-123456789".into();
        assert!(!exact_rule(&restricted, &scope).unwrap());
    }

    #[test]
    #[ignore = "Root supplies exact old immutable V1 receipt path/digest; read only"]
    fn actual_old_v1_receipt_remains_decodable_and_byte_identical() {
        let path = PathBuf::from(std::env::var_os("AG_GATEWAY_EFFECT_OLD_RECEIPT").expect("explicit received old receipt"));
        let expected = std::env::var("AG_GATEWAY_EFFECT_OLD_RECEIPT_SHA256").expect("independent old digest required");
        let received = CheckedPath::open(&path, PathKind::File, PathPurpose::Source).unwrap();
        let before = received.read_snapshot().unwrap();
        assert_eq!(hash(&before), expected);
        let receipt: GatewayRuleReceiptV1 = decode(&before).unwrap();
        assert_eq!(receipt.version, 1);
        assert_eq!(receipt.ownership, RuleCustody::CreatedByOperation);
        assert!(retirement_requested(&receipt, &[]));
        let decoded: GatewayRuleReceiptV1 = decode(&json(&receipt).unwrap()).unwrap();
        assert_eq!(decoded.persistent, receipt.persistent);
        assert_eq!(decoded.active, receipt.active);
        assert_eq!(received.read_snapshot().unwrap(), before);
    }
    fn complete() -> GatewayCapture {
        GatewayCapture {
            bytes: Vec::new(),
            reader: GatewayCaptureState::Complete,
            truncated: false,
            finalization: GatewayCaptureState::Complete,
        }
    }
    fn outcome() -> GatewayNativeOutcome {
        GatewayNativeOutcome {
            dispatch: GatewayDispatch::Started {
                attempt_id: "actual-fixture-attempt".into(),
                process_id: 12,
                creation_time: Some(42),
                image: Some(PathBuf::from(r"C:\Windows\System32\fixture.exe")),
            },
            execution: GatewayExecution::Exited { code: Some(0) },
            stdout: complete(),
            stderr: complete(),
            action: GatewayActionReport::ReturnedSuccess,
            inspection: Some(inspection()),
        }
    }

    #[test]
    fn equal_complete_namespaces_dedupe_without_widening_distinct_scopes() {
        let first = namespace();
        let mut second = first.clone();
        second.source_address = Ipv4Addr::new(172, 20, 0, 3);
        assert_eq!(
            normalized_namespaces(&[first.clone(), first.clone(), second.clone()]).unwrap(),
            [first, second]
        );
        let mut invalid = namespace();
        invalid.interface_index = 0;
        assert!(normalized_namespaces(&[invalid]).is_err());
        let mut equal = namespace();
        equal.source_address = equal.local_address;
        assert!(normalized_namespaces(&[equal]).is_err());
    }
    #[test]
    fn fixed_rule_mask_accepts_nonempty_active_subset_and_rejects_degraded_policy() {
        let scope = scope();
        let mut inspection = inspection();
        for active in [2, 4, 6] {
            inspection.active_profiles = active;
            assert!(receive_environment(&scope, &inspection).is_ok());
        }
        for active in [0, 1, 7, 8] {
            inspection.active_profiles = active;
            assert!(matches!(
                receive_environment(&scope, &inspection),
                Err(GatewayRuleError::Policy(_))
            ));
        }
        inspection.active_profiles = 2;
        inspection.policy =
            GatewayPolicyObservation::ExplicitBlock("actual applicable block".into());
        assert!(matches!(
            receive_environment(&scope, &inspection),
            Err(GatewayRuleError::Policy(_))
        ));
        inspection.policy = GatewayPolicyObservation::Unavailable("query failed".into());
        assert!(matches!(
            receive_environment(&scope, &inspection),
            Err(GatewayRuleError::Capture(_))
        ));
    }
    #[test]
    fn receiving_checks_both_stores_and_full_filters() {
        let scope = scope();
        let base = inspection();
        assert!(receive_pair(&scope, "fixture-rule", &base).is_ok());
        let mut changed = base.clone();
        changed.active.clear();
        assert!(receive_pair(&scope, "fixture-rule", &changed).is_err());
        let mut changed = base.clone();
        changed.persistent.push(changed.persistent[0].clone());
        assert!(receive_pair(&scope, "fixture-rule", &changed).is_err());
        let mut changed = base.clone();
        changed.active[0].profiles = 2;
        assert!(receive_pair(&scope, "fixture-rule", &changed).is_err());
        let mut changed = base.clone();
        changed.active[0].remote_addresses = vec!["172.20.0.0/16".into()];
        assert!(receive_pair(&scope, "fixture-rule", &changed).is_err());
        let mut changed = base.clone();
        changed.active[0].remote_ports = vec!["443".into()];
        assert!(receive_pair(&scope, "fixture-rule", &changed).is_err());
        let mut changed = base.clone();
        changed.active[0].override_block_rules = true;
        assert!(receive_pair(&scope, "fixture-rule", &changed).is_err());
        let mut changed = base.clone();
        changed.active[0].program = PathBuf::from(r"C:\other\host.exe");
        assert!(receive_pair(&scope, "fixture-rule", &changed).is_err());
    }
    #[test]
    fn success_requires_retirement_both_captures_and_actual_action_report() {
        let base = outcome();
        assert!(native_success(&base).is_ok());
        let mut value = base.clone();
        value.execution = GatewayExecution::Pending;
        assert!(native_success(&value).is_err());
        let mut value = base.clone();
        value.action = GatewayActionReport::Unknown;
        assert!(native_success(&value).is_err());
        let mut value = base.clone();
        value.stdout.truncated = true;
        assert!(matches!(
            native_success(&value),
            Err(GatewayRuleError::Capture(_))
        ));
        let mut value = base.clone();
        value.stderr.finalization = GatewayCaptureState::Failed("reader failure".into());
        assert!(native_success(&value).is_err());
        let mut value = base.clone();
        value.dispatch = GatewayDispatch::NotStarted("cancelled".into());
        assert!(native_success(&value).is_err());
        let mut value = base;
        value.execution = GatewayExecution::Exited { code: Some(1) };
        value.action = GatewayActionReport::ReturnedFailure {
            kind: GatewayFailureKind::Permission,
            message: "access denied".into(),
        };
        assert!(matches!(
            native_success(&value),
            Err(GatewayRuleError::Permission(_))
        ));
    }
    #[test]
    fn external_or_still_wanted_shared_scope_has_no_retirement_authority() {
        let scope = scope();
        let rule = rule(&scope);
        let mut receipt = GatewayRuleReceiptV1 {
            version: 1,
            operation_id: "b".repeat(32),
            intended_name: rule.name.clone(),
            actual_name: rule.name.clone(),
            ownership: RuleCustody::ObservedExternal,
            scope,
            persistent: rule.clone(),
            active: rule,
            readback: EvidenceRef {
                path: "evidence/fixture/readback.json".into(),
                digest: "c".repeat(64),
            },
            creation: None,
        };
        assert!(!retirement_requested(&receipt, &[]));
        receipt.ownership = RuleCustody::CreatedByOperation;
        assert!(!retirement_requested(&receipt, &[namespace(), namespace()]));
        assert!(retirement_requested(&receipt, &[]));
    }
    #[test]
    fn native_wire_keeps_uncertain_execution_and_requires_optional_fields_explicitly() {
        let mut original = outcome();
        original.execution = GatewayExecution::ObservationError("retained child".into());
        original.stdout.reader = GatewayCaptureState::Pending;
        original.action = GatewayActionReport::Unknown;
        let encoded = serde_json::to_value(&original).unwrap();
        assert_eq!(
            serde_json::from_value::<GatewayNativeOutcome>(encoded.clone()).unwrap(),
            original
        );
        let mut missing = encoded;
        missing.as_object_mut().unwrap().remove("inspection");
        assert!(serde_json::from_value::<GatewayNativeOutcome>(missing).is_err());
    }

    #[test]
    fn requirement_transport_facts_are_explicit_and_use_the_profile_owner() {
        let (none, admin) =
            receive_requirement_namespaces(GatewayRequirementNamespaces::TransportNotWanted)
                .unwrap();
        assert!(none.is_empty() && admin.is_none());
        let values = [namespace(), namespace()];
        let (deduped, admin) =
            receive_requirement_namespaces(GatewayRequirementNamespaces::TransportWanted {
                namespaces: &values,
                active_profiles: 6,
                administrator: false,
            })
            .unwrap();
        assert_eq!(deduped, [namespace()]);
        assert_eq!(admin, Some(false));
        assert!(
            receive_requirement_namespaces(GatewayRequirementNamespaces::TransportWanted {
                namespaces: &[],
                active_profiles: 2,
                administrator: true,
            })
            .is_err()
        );
        assert!(matches!(
            receive_requirement_namespaces(GatewayRequirementNamespaces::TransportWanted {
                namespaces: &values,
                active_profiles: 1,
                administrator: true,
            }),
            Err(GatewayRuleError::Policy(_))
        ));
    }

    struct NoRuleQueries;
    impl GatewayRuleRunner for NoRuleQueries {
        fn run(
            &mut self,
            _: &GatewayRuleRequest,
            _: &AtomicBool,
            _: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>,
        ) -> GatewayNativeOutcome {
            panic!("NewDeployment must not inspect a source or hypothetical program rule")
        }
    }
    /// Synthetic in-memory native-effect backend, scoped to the existing
    /// explicitly allocated canonical fixture. No firewall/process is invoked.
    struct EffectFixtureRunner {
        rule: Option<GatewayNativeRule>,
        healthy: bool,
        creates: usize,
        removes: usize,
    }
    impl GatewayRuleRunner for EffectFixtureRunner {
        fn run(&mut self, request: &GatewayRuleRequest, _: &AtomicBool,
            record: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>) -> GatewayNativeOutcome {
            let mut result = outcome();
            let scope = match request {
                GatewayRuleRequest::Inspect { scope, .. } | GatewayRuleRequest::InspectOwned { scope, .. } => scope,
                GatewayRuleRequest::Create { scope, name } => {
                    assert!(self.rule.is_none()); self.creates += 1;
                    let mut created = rule(scope); created.name = name.clone(); self.rule = Some(created);
                    scope
                }
                GatewayRuleRequest::Remove { scope, persistent, active } => {
                    assert_eq!(self.rule.as_ref(), Some(persistent)); assert_eq!(persistent, active);
                    self.removes += 1; self.rule = None; scope
                }
            };
            result.inspection = if matches!(request, GatewayRuleRequest::Inspect { .. } | GatewayRuleRequest::InspectOwned { .. }) {
                let rules: Vec<_> = self.rule.iter().cloned().collect();
                let effects = rules.iter().map(|rule| ActiveRuleEnforcement {
                    name: rule.name.clone(), instance_id: rule.instance_id.clone(),
                    primary_status: Some(if self.healthy { 1 } else { 2 }),
                    enforcement_status: Some(vec![if self.healthy { 1 } else { 20 }]),
                }).collect();
                Some(GatewayRuleInspection { administrator: true, active_profiles: 2,
                    namespace: if matches!(request, GatewayRuleRequest::InspectOwned { .. }) { None } else { Some(scope.namespace.clone()) },
                    policy: if matches!(request, GatewayRuleRequest::InspectOwned { .. }) { GatewayPolicyObservation::Unavailable("historical custody inspection; no live transport admission".into()) } else { GatewayPolicyObservation::Allowed },
                    persistent: rules.clone(), active: rules, active_enforcement: if matches!(request, GatewayRuleRequest::InspectOwned { .. }) { None } else { Some(effects) } })
            } else { None };
            record(&result).expect("persist synthetic native result through the actual journal owner");
            result
        }
    }

    #[test]
    #[ignore = "explicit owned requirement fixtures, packaged host and new pristine archive; synthetic rules only"]
    fn vendor_package_retires_owned_old_rule_and_preserves_its_receipt() {
        struct FixtureWindow;
        impl MaintenanceWindow for FixtureWindow { fn ensure_held(&mut self) -> Result<()> { Ok(()) } }
        struct StaleRunner { inner: EffectFixtureRunner, stale: bool, owned_queries: usize }
        impl GatewayRuleRunner for StaleRunner {
            fn run(&mut self, request: &GatewayRuleRequest, cancel: &AtomicBool,
                record: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>) -> GatewayNativeOutcome {
                if self.stale && matches!(request, GatewayRuleRequest::Inspect { .. } | GatewayRuleRequest::Create { .. }) {
                    let mut result = outcome();
                    result.action = GatewayActionReport::ReturnedFailure { kind: GatewayFailureKind::MissingConfiguration, message: "FreshGatewayInterfaceChanged".into() };
                    result.inspection = None;
                    record(&result).unwrap();
                    return result;
                }
                if matches!(request, GatewayRuleRequest::InspectOwned { .. }) { self.owned_queries += 1; }
                self.inner.run(request, cancel, record)
            }
        }
        let fixture = RequirementFixture::open();
        let host_path = PathBuf::from(std::env::var_os("AG_GATEWAY_EFFECT_HOST").expect("packaged fixture host"));
        let source = CheckedPath::open(&host_path, PathKind::File, PathPurpose::Executable).unwrap();
        let assets = PackageAssets::receive(&source, option_env!("AG_WSL_EXPECTED_HELPER_SHA256")).unwrap();
        let source_hash = hash(&source.read_snapshot().unwrap());
        super::super::upgrade_runtime(fixture.bound, &source, &source_hash, &assets, None, &mut FixtureWindow).unwrap();
        let desktop = fixture.source.path.clone();
        let context_path = PathBuf::from(std::env::var_os("AG_GATEWAY_REQUIREMENT_CONTEXT").unwrap());
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let read = super::super::admit_runtime_read(bound, "wsl-gui-v2").unwrap();
        let old_host = CheckedPath::open(read.host().as_path(), PathKind::File, PathPurpose::Executable).unwrap();
        drop(read);
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let cancel = AtomicBool::new(false);
        let mut runner = StaleRunner { inner: EffectFixtureRunner { rule: None, healthy: true, creates: 0, removes: 0 }, stale: false, owned_queries: 0 };
        let plan = prepare_gateway_rules(&bound, &old_host, &[namespace()], &mut runner, &cancel).unwrap();
        ensure_gateway_rules(plan, &mut runner, &mut FixtureWindow, &cancel).unwrap();
        let authority = Authority::open(&bound, false, false).unwrap();
        let expected = authority.digest.clone();
        let old = authority.current.runtime_deployment.received().unwrap().clone();
        let old_ref = old.gateway_rules.as_ref().unwrap()[0].clone();
        let old_receipt = receive_receipt(&authority.slot, &old.host, &old_ref).unwrap();
        let old_bytes = reference(&authority.slot, &old_ref).unwrap();
        runner.stale = true;
        assert!(inspect(&mut runner, &old_receipt.scope, Some(&old_receipt.actual_name), &cancel).is_err());
        runner.inner.rule.as_mut().unwrap().interface_aliases = vec!["synthetic-current-guid".into()];
        drop(authority); drop(bound); drop(old_host); drop(fixture.source);
        let new_archive = PathBuf::from(std::env::var_os("AG_VENDOR_UPDATE_ARCHIVE_FIXTURE").expect("new pristine fixture"));
        let bytes = CheckedPath::open(&new_archive, PathKind::File, PathPurpose::Source).unwrap().read_snapshot().unwrap();
        fs::write(NativeFsPath::from_path(&desktop).unwrap().as_path(), b"MZ updated fixture; never executed").unwrap();
        fs::write(NativeFsPath::from_path(&desktop.parent().unwrap().join("resources/app.asar")).unwrap().as_path(), &bytes).unwrap();
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let observed = match observe_apply_current(&bound).unwrap() { ApplyCurrentObservation::VendorReplacement(value) => value, _ => panic!("vendor replacement expected") };
        let current_rule = runner.inner.rule.as_ref().unwrap().clone();
        let selection = GatewayRetirementSelectionV1 { version: 1, operation: GatewayRetirementSelectionOperation::RetireObservedInterfaceAliases,
            slot_id: observed.slot_id.clone(), prior_current_sha256: hex::encode(observed.prior_current_sha256),
            new_binding_sha256: hex::encode(observed.new_binding_sha256), saved_settings_sha256: hex::encode([7; 32]),
            old_host: old.host.clone(), receipt: old_ref.clone(), persistent: current_rule.clone(), active: current_rule };
        selection.validate_binding(&observed, &[7; 32]).unwrap();
        assert!(super::super::prepare_vendor_update(&expected, bound, None,
            super::super::VendorRuntimeInput::QualifiedPackage { source: &source, expected_host_sha256: &source_hash, assets: &assets, selection: None },
            Some(&mut runner), &cancel, &mut FixtureWindow).is_err());
        assert_eq!(runner.inner.removes, 0);
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let mut window = FixtureWindow;
        let denied = super::super::prepare_vendor_update(&expected, bound, None,
            super::super::VendorRuntimeInput::QualifiedPackage { source: &source, expected_host_sha256: &source_hash, assets: &assets, selection: None },
            None, &cancel, &mut window);
        assert!(matches!(denied, Err(GatewayRuleError::MissingConfiguration(_))));
        assert_eq!(runner.inner.removes, 0);
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let prepared = super::super::prepare_vendor_update(&expected, bound, None,
            super::super::VendorRuntimeInput::QualifiedPackage { source: &source, expected_host_sha256: &source_hash, assets: &assets, selection: Some(&selection) },
            Some(&mut runner), &cancel, &mut window).unwrap();
        super::super::runtime_upgrade::TEST_STOP_AFTER_RECEIPT.with(|value| value.set(Some("apply-v2")));
        assert!(prepared.execute(Some(&mut runner), &cancel).is_err());
        drop(selection);
        assert_eq!(runner.inner.creates, 1); assert_eq!(runner.inner.removes, 1); assert!(runner.inner.rule.is_none());
        assert!(runner.owned_queries >= 3);
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let authority = Authority::open(&bound, false, true).unwrap();
        assert_eq!(authority.current.mode, Mode::Pending);
        let operation = authority.current.active_operation.as_ref().unwrap().clone();
        let digest = authority.digest.clone();
        drop(authority);
        let archive_calls = TEST_NATIVE_CALLS.with(|value| value.get());
        let recovered = super::super::recover(bound, &operation.id, &digest,
            Some(super::super::GatewayRecoveryContext { runner: &mut runner, cancel: &cancel }), &mut window).unwrap();
        assert!(recovered.starts_with("RecoverySettled:"));
        assert_eq!(runner.inner.removes, 1);
        assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), archive_calls);
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let authority = Authority::open(&bound, false, false).unwrap();
        let received = authority.current.runtime_deployment.received().unwrap();
        assert_eq!(received.version, 1); assert!(received.gateway_rules.is_none());
        assert_ne!(received.host.native_id, old.host.native_id);
        assert_eq!(reference(&authority.slot, &old_ref).unwrap(), old_bytes);
    }

    #[test]
    #[ignore = "explicit owned requirement fixture inputs plus AG_GATEWAY_EFFECT_HOST; synthetic files/rules only"]
    fn ineffective_create_publishes_custody_all_reuse_rechecks_and_inactive_owned_rule_retires() {
        struct FixtureWindow;
        impl MaintenanceWindow for FixtureWindow { fn ensure_held(&mut self) -> Result<()> { Ok(()) } }
        let fixture = RequirementFixture::open();
        let host_path = PathBuf::from(std::env::var_os("AG_GATEWAY_EFFECT_HOST").expect("explicit read-only packaged fixture host"));
        let source = CheckedPath::open(&host_path, PathKind::File, PathPurpose::Executable).unwrap();
        let assets = PackageAssets::receive(&source, option_env!("AG_WSL_EXPECTED_HELPER_SHA256")).unwrap();
        super::super::upgrade_runtime(fixture.bound, &source, &hash(&source.read_snapshot().unwrap()), &assets, None, &mut FixtureWindow).unwrap();
        let mut bound = BoundInstallation::open(&fixture.source.path).unwrap();
        let context_path = PathBuf::from(std::env::var_os("AG_GATEWAY_REQUIREMENT_CONTEXT").unwrap());
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let read = super::super::admit_runtime_read(bound, "wsl-gui-v2").unwrap();
        let host = CheckedPath::open(read.host().as_path(), PathKind::File, PathPurpose::Executable).unwrap();
        let desktop = fixture.source.path.clone();
        drop(read);
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let cancel = AtomicBool::new(false);
        let mut runner = EffectFixtureRunner { rule: None, healthy: false, creates: 0, removes: 0 };
        let prepared = prepare_gateway_rules(&bound, &host, &[namespace()], &mut runner, &cancel).unwrap();
        assert!(matches!(ensure_gateway_rules(prepared, &mut runner, &mut FixtureWindow, &cancel), Err(GatewayRuleError::MissingConfiguration(_))));
        let authority = Authority::open(&bound, false, false).unwrap();
        assert_eq!(authority.current.mode, Mode::SettledApplied);
        assert!(authority.current.active_operation.is_none());
        let deployment = authority.current.runtime_deployment.received().unwrap();
        assert_eq!(deployment.version, 2);
        let reference = deployment.gateway_rules.as_ref().unwrap()[0].clone();
        let receipt = receive_receipt(&authority.slot, &deployment.host, &reference).unwrap();
        assert_eq!(receipt.ownership, RuleCustody::CreatedByOperation);
        let receipt_before = self::reference(&authority.slot, &reference).unwrap();
        let current_before = authority.digest.clone();
        drop(authority);
        assert_eq!(runner.creates, 1);
        assert!(prepare_gateway_rules(&bound, &host, &[namespace()], &mut runner, &cancel).is_err());
        assert_eq!(runner.creates, 1); // No blind recreate after NotReady.
        runner.healthy = true;
        let prepared = prepare_gateway_rules(&bound, &host, &[namespace()], &mut runner, &cancel).unwrap();
        runner.healthy = false; // Invalidate effect after preparation, before all-Reuse return.
        assert!(ensure_gateway_rules(prepared, &mut runner, &mut FixtureWindow, &cancel).is_err());
        assert_eq!(Authority::open(&bound, false, false).unwrap().digest, current_before);
        let retirement = prepare_gateway_rule_retirement(&bound, &host, &[], &mut runner, &cancel).unwrap();
        retire_gateway_rules(retirement, &mut runner, &mut FixtureWindow, &cancel).unwrap();
        assert_eq!(runner.creates, 1); assert_eq!(runner.removes, 1); assert!(runner.rule.is_none());
        let authority = Authority::open(&bound, false, false).unwrap();
        assert_eq!(self::reference(&authority.slot, &reference).unwrap(), receipt_before);
        assert!(authority.current.runtime_deployment.received().unwrap().gateway_rules.as_ref().unwrap().is_empty());
    }
    #[test]
    #[ignore = "same explicit qualified requirement fixture inputs and AG_GATEWAY_EFFECT_HOST; synthetic incarnation switch only"]
    fn post_publish_healthy_replacement_is_not_ready_and_keeps_original_custody() {
        struct FixtureWindow;
        impl MaintenanceWindow for FixtureWindow { fn ensure_held(&mut self) -> Result<()> { Ok(()) } }
        struct ReplacementRunner {
            inner: EffectFixtureRunner,
            slot: CheckedPath,
            published: Option<(String, EvidenceRef, Vec<u8>, GatewayRuleReceiptV1)>,
            replacement: Option<GatewayRuleInspection>,
        }
        impl GatewayRuleRunner for ReplacementRunner {
            fn run(&mut self, request: &GatewayRuleRequest, cancel: &AtomicBool,
                record: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>) -> GatewayNativeOutcome {
                if matches!(request, GatewayRuleRequest::Inspect { .. }) && self.inner.rule.is_some() && self.published.is_none() {
                    let (current, digest) = receive_current(&self.slot).unwrap();
                    // A's structural readback is journaled while Pending. Switch
                    // only after the actual owner has published A's custody.
                    if current.mode == Mode::SettledApplied {
                        let deployment = current.runtime_deployment.received().unwrap();
                        if let Some(values) = deployment.gateway_rules.as_ref().filter(|values| !values.is_empty()) {
                            assert_eq!(values.len(), 1);
                            let value = values[0].clone();
                            let receipt = receive_receipt(&self.slot, &deployment.host, &value).unwrap();
                            assert_eq!(receipt.ownership, RuleCustody::CreatedByOperation);
                            assert_eq!(self.inner.rule.as_ref(), Some(&receipt.persistent));
                            let bytes = reference(&self.slot, &value).unwrap();
                            self.published = Some((digest, value, bytes, receipt));
                            self.inner.rule.as_mut().unwrap().instance_id = Some("synthetic-healthy-replacement-instance".into());
                        }
                    }
                }
                let result = self.inner.run(request, cancel, record);
                if self.published.is_some() && matches!(request, GatewayRuleRequest::Inspect { .. }) {
                    self.replacement = result.inspection.clone();
                }
                result
            }
        }
        // Reuse the existing genuine-context fixture and production canonical
        // owners; only the native rule-effect backend is synthetic.
        let host_path = PathBuf::from(std::env::var_os("AG_GATEWAY_EFFECT_HOST").expect("explicit read-only packaged fixture host"));
        let fixture = RequirementFixture::open();
        let source = CheckedPath::open(&host_path, PathKind::File, PathPurpose::Executable).unwrap();
        let assets = PackageAssets::receive(&source, option_env!("AG_WSL_EXPECTED_HELPER_SHA256")).unwrap();
        super::super::upgrade_runtime(fixture.bound, &source, &hash(&source.read_snapshot().unwrap()), &assets, None, &mut FixtureWindow).unwrap();
        let desktop = fixture.source.path.clone();
        let context_path = PathBuf::from(std::env::var_os("AG_GATEWAY_REQUIREMENT_CONTEXT").unwrap());
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let read = super::super::admit_runtime_read(bound, "wsl-gui-v2").unwrap();
        let host = CheckedPath::open(read.host().as_path(), PathKind::File, PathPurpose::Executable).unwrap();
        drop(read);
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let authority = Authority::open(&bound, false, false).unwrap();
        let slot = CheckedPath::open(&authority.slot.path, PathKind::Directory, PathPurpose::Review).unwrap();
        drop(authority);
        let mut runner = ReplacementRunner { inner: EffectFixtureRunner { rule: None, healthy: true, creates: 0, removes: 0 }, slot, published: None, replacement: None };
        let cancel = AtomicBool::new(false);
        let prepared = prepare_gateway_rules(&bound, &host, &[namespace()], &mut runner, &cancel).unwrap();
        let error = ensure_gateway_rules(prepared, &mut runner, &mut FixtureWindow, &cancel).unwrap_err();
        assert!(matches!(&error, GatewayRuleError::MissingConfiguration(message) if message.contains("published gateway incarnation changed")), "{error}");
        let (published_digest, receipt_ref, receipt_bytes, original) = runner.published.as_ref().expect("A custody publication actually observed before B switch");
        let replacement = runner.replacement.as_ref().unwrap();
        assert!(receive_ready_pair(&original.scope, &original.actual_name, replacement).is_ok(), "B itself is healthy/exact-filter; only its incarnation differs");
        assert_ne!(replacement.active[0].instance_id, original.active.instance_id);
        let authority = Authority::open(&bound, false, false).unwrap();
        assert_eq!(&authority.digest, published_digest);
        assert_eq!(authority.current.mode, Mode::SettledApplied);
        assert!(authority.current.active_operation.is_none());
        assert_eq!(reference(&authority.slot, receipt_ref).unwrap(), *receipt_bytes);
        let actual = receive_receipt(&authority.slot, &original.scope.host, receipt_ref).unwrap();
        assert_eq!(actual.ownership, RuleCustody::CreatedByOperation);
        assert_eq!(actual.persistent, original.persistent); assert_eq!(actual.active, original.active);
        assert_eq!(runner.inner.creates, 1); assert_eq!(runner.inner.removes, 0);
        assert_eq!(runner.inner.rule.as_ref().unwrap().instance_id, replacement.active[0].instance_id);
    }

    #[test]
    #[ignore = "same explicit qualified requirement fixture inputs and AG_GATEWAY_EFFECT_HOST; synthetic Pending raw-empty recovery"]
    fn pending_completed_create_recovers_raw_empty_package_without_native_replay() {
        struct FixtureWindow;
        impl MaintenanceWindow for FixtureWindow { fn ensure_held(&mut self) -> Result<()> { Ok(()) } }
        struct PendingRunner {
            inner: EffectFixtureRunner,
            fail_readback: bool,
            fail_removal_readback: bool,
            unknown_removal: bool,
            removal_packages: Option<(String, String)>,
        }
        impl GatewayRuleRunner for PendingRunner {
            fn run(&mut self, request: &GatewayRuleRequest, cancel: &AtomicBool,
                record: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>) -> GatewayNativeOutcome {
                if let GatewayRuleRequest::Remove { persistent, active, .. } = request {
                    self.removal_packages = Some((persistent.package.clone(), active.package.clone()));
                    if self.unknown_removal {
                        self.inner.removes += 1;
                        self.inner.rule = None;
                        let mut result = outcome();
                        result.action = GatewayActionReport::Unknown;
                        result.inspection = None;
                        record(&result).expect("retain uncertain removal outcome");
                        return result;
                    }
                }
                let mut result = self.inner.run(request, cancel, record);
                if matches!(request, GatewayRuleRequest::Create { .. }) {
                    // Faithful native default representation, not an Any rewrite.
                    self.inner.rule.as_mut().unwrap().package.clear();
                } else if matches!(request, GatewayRuleRequest::Inspect { .. }) && self.inner.rule.is_some() && self.fail_readback {
                    self.fail_readback = false;
                    result.stdout.finalization = GatewayCaptureState::Failed("synthetic first readback capture failure after completed create".into());
                    record(&result).expect("retain injected failed readback through actual journal owner");
                } else if matches!(request, GatewayRuleRequest::InspectOwned { .. }) && self.inner.rule.is_none() && self.fail_removal_readback {
                    self.fail_removal_readback = false;
                    result.stdout.finalization = GatewayCaptureState::Failed("synthetic readback capture failure after completed removal".into());
                    record(&result).expect("retain failed removal readback through actual journal owner");
                }
                result
            }
        }
        let host_path = PathBuf::from(std::env::var_os("AG_GATEWAY_EFFECT_HOST").expect("explicit read-only packaged fixture host"));
        let fixture = RequirementFixture::open();
        let source = CheckedPath::open(&host_path, PathKind::File, PathPurpose::Executable).unwrap();
        let assets = PackageAssets::receive(&source, option_env!("AG_WSL_EXPECTED_HELPER_SHA256")).unwrap();
        super::super::upgrade_runtime(fixture.bound, &source, &hash(&source.read_snapshot().unwrap()), &assets, None, &mut FixtureWindow).unwrap();
        let desktop = fixture.source.path.clone();
        let context_path = PathBuf::from(std::env::var_os("AG_GATEWAY_REQUIREMENT_CONTEXT").unwrap());
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let read = super::super::admit_runtime_read(bound, "wsl-gui-v2").unwrap();
        let host = CheckedPath::open(read.host().as_path(), PathKind::File, PathPurpose::Executable).unwrap();
        drop(read);
        let mut bound = BoundInstallation::open(&desktop).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
        bound.attach_ancestor_context(context).unwrap();
        let cancel = AtomicBool::new(false);
        let mut runner = PendingRunner { inner: EffectFixtureRunner { rule: None, healthy: true, creates: 0, removes: 0 }, fail_readback: true, fail_removal_readback: false, unknown_removal: false, removal_packages: None };
        let prepared = prepare_gateway_rules(&bound, &host, &[namespace()], &mut runner, &cancel).unwrap();
        let error = ensure_gateway_rules(prepared, &mut runner, &mut FixtureWindow, &cancel).unwrap_err();
        assert!(matches!(&error, GatewayRuleError::NativeUnsettled { outcome, reason }
            if reason.contains("native stdout/stderr capture or finalization incomplete")
                && matches!(&outcome.stdout.finalization, GatewayCaptureState::Failed(_))
                && matches!(&outcome.execution, GatewayExecution::Exited { code: Some(0) })), "{error:?}");
        let authority = Authority::open(&bound, false, true).unwrap();
        assert_eq!(authority.current.mode, Mode::Pending);
        let operation = authority.current.active_operation.as_ref().unwrap().clone();
        let expected = authority.digest.clone();
        let completed_path = authority.slot.path.join("evidence").join(&operation.id).join("completed-0.json");
        let completed = read_private(&completed_path).unwrap();
        let creation: EvidenceRef = decode(&completed).unwrap();
        let invocation = reference(&authority.slot, &creation).unwrap();
        drop(authority);
        assert_eq!(runner.inner.creates, 1); assert_eq!(runner.inner.removes, 0);
        let observation = super::super::observe_apply_current(&bound).unwrap();
        assert!(matches!(&observation, super::super::ApplyCurrentObservation::GatewayPending(value)
            if value.operation_id == operation.id && hex::encode(value.current_sha256) == expected));
        assert!(super::super::capture_current_expectation(&bound).is_err());
        let receive_bound = || {
            let mut received = BoundInstallation::open(&desktop).unwrap();
            let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&received, Some(&context_path)).unwrap().unwrap();
            received.attach_ancestor_context(context).unwrap();
            received
        };
        let missing_capability = super::super::recover(receive_bound(), &operation.id, &expected, None, &mut FixtureWindow).unwrap_err();
        assert!(missing_capability.contains("gateway recovery capability required"));
        let wrong_digest = super::super::recover(receive_bound(), &operation.id, &"0".repeat(64),
            Some(super::super::GatewayRecoveryContext { runner: &mut runner, cancel: &cancel }), &mut FixtureWindow).unwrap_err();
        assert!(wrong_digest.contains("expectedCurrentDigest differs"));
        let cancelled = AtomicBool::new(true);
        let cancelled_result = super::super::recover(receive_bound(), &operation.id, &expected,
            Some(super::super::GatewayRecoveryContext { runner: &mut runner, cancel: &cancelled }), &mut FixtureWindow).unwrap_err();
        assert!(cancelled_result.starts_with("Cancelled:"));
        assert_eq!(Authority::open(&bound, false, true).unwrap().digest, expected);
        assert_eq!(runner.inner.creates, 1); assert_eq!(runner.inner.removes, 0);
        // Generic typed dispatch drops its Authority/G1 before the gateway API
        // reacquires the exact Pending snapshot; no invocation is replayed.
        let recovered = super::super::recover(receive_bound(), &operation.id, &expected,
            Some(super::super::GatewayRecoveryContext { runner: &mut runner, cancel: &cancel }), &mut FixtureWindow).unwrap();
        assert!(recovered.starts_with("RecoverySettled:"));
        assert_eq!(runner.inner.creates, 1); assert_eq!(runner.inner.removes, 0);
        let authority = Authority::open(&bound, false, false).unwrap();
        assert_eq!(authority.current.mode, Mode::SettledApplied); assert!(authority.current.active_operation.is_none());
        assert_eq!(read_private(&completed_path).unwrap(), completed);
        assert_eq!(reference(&authority.slot, &creation).unwrap(), invocation);
        let deployment = authority.current.runtime_deployment.received().unwrap();
        let receipt_ref = deployment.gateway_rules.as_ref().unwrap()[0].clone();
        let receipt = receive_receipt(&authority.slot, &deployment.host, &receipt_ref).unwrap();
        assert_eq!(receipt.ownership, RuleCustody::CreatedByOperation);
        assert_eq!(receipt.persistent.package, ""); assert_eq!(receipt.active.package, "");
        let receipt_bytes = reference(&authority.slot, &receipt_ref).unwrap();
        drop(authority);
        let retirement = prepare_gateway_rule_retirement(&bound, &host, &[], &mut runner, &cancel).unwrap();
        runner.fail_removal_readback = true;
        let failure = retire_gateway_rules(retirement, &mut runner, &mut FixtureWindow, &cancel).unwrap_err();
        assert!(matches!(failure, GatewayRuleError::NativeUnsettled { .. }));
        let authority = Authority::open(&bound, false, true).unwrap();
        assert_eq!(authority.current.mode, Mode::Pending);
        let operation = authority.current.active_operation.as_ref().unwrap().clone();
        let expected = authority.digest.clone();
        let completed_path = authority.slot.path.join("evidence").join(&operation.id).join("completed-0.json");
        let completed = read_private(&completed_path).unwrap();
        drop(authority);
        assert_eq!(runner.inner.removes, 1);
        let recovered = super::super::recover(receive_bound(), &operation.id, &expected,
            Some(super::super::GatewayRecoveryContext { runner: &mut runner, cancel: &cancel }), &mut FixtureWindow).unwrap();
        assert!(recovered.starts_with("RecoverySettled:"));
        assert_eq!(read_private(&completed_path).unwrap(), completed);
        assert_eq!(runner.removal_packages, Some((String::new(), String::new())));
        assert_eq!(runner.inner.creates, 1); assert_eq!(runner.inner.removes, 1);
        let authority = Authority::open(&bound, false, false).unwrap();
        assert_eq!(reference(&authority.slot, &receipt_ref).unwrap(), receipt_bytes);
        drop(authority);
        let prepared = prepare_gateway_rules(&bound, &host, &[namespace()], &mut runner, &cancel).unwrap();
        ensure_gateway_rules(prepared, &mut runner, &mut FixtureWindow, &cancel).unwrap();
        let retirement = prepare_gateway_rule_retirement(&bound, &host, &[], &mut runner, &cancel).unwrap();
        runner.unknown_removal = true;
        assert!(retire_gateway_rules(retirement, &mut runner, &mut FixtureWindow, &cancel).is_err());
        let authority = Authority::open(&bound, false, true).unwrap();
        assert_eq!(authority.current.mode, Mode::Pending);
        let operation = authority.current.active_operation.as_ref().unwrap().clone();
        let expected = authority.digest.clone();
        let completed_path = authority.slot.path.join("evidence").join(&operation.id).join("completed-0.json");
        assert!(!completed_path.exists());
        drop(authority);
        let removals = runner.inner.removes;
        assert!(super::super::recover(receive_bound(), &operation.id, &expected,
            Some(super::super::GatewayRecoveryContext { runner: &mut runner, cancel: &cancel }), &mut FixtureWindow).is_err());
        assert_eq!(runner.inner.removes, removals);
        let authority = Authority::open(&bound, false, true).unwrap();
        assert_eq!(authority.current.mode, Mode::Pending);
        assert_eq!(authority.digest, expected);
    }

    #[test]
    #[ignore = "same qualified fixture inputs and AG_GATEWAY_EFFECT_HOST; actual canonical publication then synthetic NotReady"]
    fn recovery_error_after_publication_retains_actual_current_in_apply_receiving() {
        struct FixtureWindow;
        impl MaintenanceWindow for FixtureWindow { fn ensure_held(&mut self) -> Result<()> { Ok(()) } }
        struct PendingReadback { inner: EffectFixtureRunner, fail: bool }
        impl GatewayRuleRunner for PendingReadback {
            fn run(&mut self, request: &GatewayRuleRequest, cancel: &AtomicBool,
                record: &mut dyn FnMut(&GatewayNativeOutcome) -> Result<()>) -> GatewayNativeOutcome {
                let mut result = self.inner.run(request, cancel, record);
                if matches!(request, GatewayRuleRequest::Inspect { .. }) && self.inner.rule.is_some() && self.fail {
                    self.fail = false;
                    result.stdout.finalization = GatewayCaptureState::Failed("synthetic initial readback failure".into());
                    record(&result).unwrap();
                }
                result
            }
        }
        let host_path = PathBuf::from(std::env::var_os("AG_GATEWAY_EFFECT_HOST").expect("explicit packaged fixture host"));
        let fixture = RequirementFixture::open();
        let source = CheckedPath::open(&host_path, PathKind::File, PathPurpose::Executable).unwrap();
        let assets = PackageAssets::receive(&source, option_env!("AG_WSL_EXPECTED_HELPER_SHA256")).unwrap();
        super::super::upgrade_runtime(fixture.bound, &source, &hash(&source.read_snapshot().unwrap()), &assets, None, &mut FixtureWindow).unwrap();
        let desktop = fixture.source.path.clone();
        let context_path = PathBuf::from(std::env::var_os("AG_GATEWAY_REQUIREMENT_CONTEXT").unwrap());
        let receive_bound = || {
            let mut bound = BoundInstallation::open(&desktop).unwrap();
            let context = crate::windows_coordinator::windows_deployment::receive_for_installation(&bound, Some(&context_path)).unwrap().unwrap();
            bound.attach_ancestor_context(context).unwrap(); bound
        };
        let bound = receive_bound();
        let target = crate::instances::GuiReplacementTarget { kind: crate::instances::GuiTargetKind::Desktop,
            root_path: bound.root.path.clone(), native_root_id: bound.native_root_id(),
            anchor_path: desktop.clone(), anchor_native_id: bound.native_executable_id() };
        let read = super::super::admit_runtime_read(receive_bound(), "wsl-gui-v2").unwrap();
        let host = CheckedPath::open(read.host().as_path(), PathKind::File, PathPurpose::Executable).unwrap(); drop(read);
        let cancel = AtomicBool::new(false);
        let mut runner = PendingReadback { inner: EffectFixtureRunner { rule: None, healthy: false, creates: 0, removes: 0 }, fail: true };
        let prepared = prepare_gateway_rules(&bound, &host, &[namespace()], &mut runner, &cancel).unwrap();
        assert!(matches!(ensure_gateway_rules(prepared, &mut runner, &mut FixtureWindow, &cancel), Err(GatewayRuleError::NativeUnsettled { .. })));
        let expected = match super::super::observe_apply_current(&bound).unwrap() {
            super::super::ApplyCurrentObservation::GatewayPending(value) => value,
            other => panic!("expected actual Pending: {other:?}"),
        };
        let result = super::super::recover(receive_bound(), &expected.operation_id, &hex::encode(expected.current_sha256),
            Some(super::super::GatewayRecoveryContext { runner: &mut runner, cancel: &cancel }), &mut FixtureWindow);
        assert!(result.as_ref().unwrap_err().contains("not freshly effective"));
        // Feed the real generic-owner Err and genuine post-return Bound into
        // the same production status receiver. No fake status/carrier is used.
        let received = crate::wsl_runtime::receive_apply_gateway_outcome(&target, &expected, result, Ok(receive_bound())).unwrap_err();
        assert!(received.contains("actualCurrent=Ok(Settled") && received.contains(&expected.operation_id), "{received}");
        let authority = Authority::open(&bound, false, false).unwrap();
        assert_eq!(authority.current.mode, Mode::SettledApplied); assert!(authority.current.active_operation.is_none());
        let deployment = authority.current.runtime_deployment.received().unwrap();
        let receipt = receive_receipt(&authority.slot, &deployment.host, &deployment.gateway_rules.as_ref().unwrap()[0]).unwrap();
        assert_eq!(receipt.ownership, RuleCustody::CreatedByOperation);
        assert_eq!(runner.inner.creates, 1); assert_eq!(runner.inner.removes, 0);
    }

    struct RequirementFixture {
        root: PathBuf,
        state: PathBuf,
        bound: BoundInstallation,
        source: CheckedPath,
        sha256: String,
        _overrides: RequirementOverrides,
        _receiving: RequirementReceivingGuard,
    }
    struct RequirementReceivingGuard {
        root: PathBuf,
    }
    impl Drop for RequirementReceivingGuard {
        fn drop(&mut self) {
            match std::panic::catch_unwind(|| fixture_inventory(&self.root)) {
                Ok(inventory) => eprintln!("OWN_GATEWAY_REQUIREMENT_FINAL {}", serde_json::json!({"inventory":inventory})),
                Err(_) if std::thread::panicking() => eprintln!("OWN_GATEWAY_REQUIREMENT_FINAL_INCOMPLETE inventory receiving failed during setup/test unwind"),
                Err(_) => panic!("required final synthetic fixture inventory unavailable"),
            }
        }
    }
    fn report_requirement_case(
        case: &str,
        setup: serde_json::Value,
        result: serde_json::Value,
        before: &[(PathBuf, Option<String>)],
        after: &[(PathBuf, Option<String>)],
    ) {
        eprintln!(
            "OWN_GATEWAY_REQUIREMENT_CASE {}",
            serde_json::json!({"case":case,"setup":setup,"result":result,
            "before":before,"after":after})
        );
    }
    struct RequirementOverrides {
        prior_base: Option<PathBuf>,
    }
    impl Drop for RequirementOverrides {
        fn drop(&mut self) {
            TEST_BASE.with(|value| {
                value.replace(self.prior_base.take());
            });
        }
    }
    impl RequirementFixture {
        fn open() -> Self {
            // Receive all caller-owned inputs before any fixture creation.
            let parent_path = PathBuf::from(
                std::env::var_os("AG_GATEWAY_REQUIREMENT_TEST_PARENT")
                    .expect("explicit owned requirement fixture parent required"),
            );
            let archive_path = PathBuf::from(
                std::env::var_os("AG_GATEWAY_REQUIREMENT_ARCHIVE_FIXTURE")
                    .expect("explicit synthetic prepared ASAR fixture required"),
            );
            let context_path = PathBuf::from(
                std::env::var_os("AG_GATEWAY_REQUIREMENT_CONTEXT")
                    .expect("explicit read-only genuine deployment-context carrier required"),
            );
            WindowsLocalPath::parse(context_path.as_os_str()).unwrap();
            let parent =
                CheckedPath::open(&parent_path, PathKind::Directory, PathPurpose::Review).unwrap();
            let archive_input =
                CheckedPath::open(&archive_path, PathKind::File, PathPurpose::Source).unwrap();
            let archive = archive_input.read_snapshot().unwrap();
            assert_eq!(
                desktop_hook::inspect_archive(&archive).unwrap().hook_status,
                desktop_hook::HookStatus::Prepared
            );
            let root = parent
                .path
                .join(format!("gateway-requirement-{}", unique_id().unwrap()));
            absent(&root).unwrap();
            create_private_dir(&root).unwrap();
            let pin = CheckedPath::open(&root, PathKind::Directory, PathPurpose::Review).unwrap();
            let facts = serde_json::json!({"schema":1,"kind":"owned-synthetic-gateway-requirement-fixture",
                "path":root,"nativeId":pin.native_id(),"callerParentNativeId":parent.native_id(),"archiveSha256":hash(&archive)});
            write_private(
                &root.join("fixture-root-facts.json"),
                &json(&facts).unwrap(),
            )
            .unwrap();
            eprintln!(
                "OWN_GATEWAY_REQUIREMENT_FIXTURE {}",
                serde_json::to_string(&facts).unwrap()
            );
            let receiving = RequirementReceivingGuard { root: root.clone() };
            let state = root.join("state");
            let install = root.join("installation");
            for directory in [&state, &install, &install.join("resources")] {
                create_private_dir(directory).unwrap();
            }
            let desktop = install.join("fixture.exe");
            write_private(
                &desktop,
                b"synthetic executable used only by test producer admission",
            )
            .unwrap();
            write_private(&install.join("resources/app.asar"), &archive).unwrap();
            let prior_base = TEST_BASE.with(|value| value.replace(Some(state.clone())));
            let overrides = RequirementOverrides {
                prior_base,
            };
            let mut bound = BoundInstallation::open(&desktop).unwrap();
            // Explicit receiving is essential: TEST_BASE intentionally redirects
            // implicit product lookup to this isolated synthetic state root.
            // The production receiver alone reads the genuine carrier/provider/
            // marker; no carrier copy, invented group or raw metadata dump.
            let context = crate::windows_coordinator::windows_deployment::receive_for_installation(
                &bound,
                Some(&context_path),
            )
            .expect("genuine production context receiving for owned fixture")
            .expect("explicit context receiving must return an actual context");
            bound.attach_ancestor_context(context).unwrap();
            let source =
                CheckedPath::open(&desktop, PathKind::File, PathPurpose::Executable).unwrap();
            let sha256 = hash(&source.read_snapshot().unwrap());
            Self {
                root,
                state,
                bound,
                source,
                sha256,
                _overrides: overrides,
                _receiving: receiving,
            }
        }
    }
    fn fixture_inventory(root: &Path) -> Vec<(PathBuf, Option<String>)> {
        fn walk(root: &Path, path: &Path, output: &mut Vec<(PathBuf, Option<String>)>) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                assert_eq!(metadata.file_attributes() & REPARSE, 0);
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                if metadata.is_dir() {
                    output.push((relative, None));
                    walk(root, &path, output);
                } else {
                    output.push((relative, Some(hash(&fs::read(&path).unwrap()))));
                }
            }
        }
        use std::os::windows::fs::MetadataExt;
        let mut result = Vec::new();
        walk(root, root, &mut result);
        result.sort();
        result
    }
    #[test]
    #[ignore = "explicit owned requirement parent and synthetic ASAR inputs; no production state root"]
    fn requirement_fresh_target_collects_native_privilege_without_rule_query_or_enrollment() {
        let fixture = RequirementFixture::open();
        let before = fixture_inventory(&fixture.root);
        for administrator in [false, true] {
            let input =
                GatewayHostInput::new_deployment(&fixture.bound, &fixture.source, &fixture.sha256)
                    .unwrap();
            let result = inspect_requirements(
                &fixture.bound,
                input,
                GatewayRequirementNamespaces::TransportWanted {
                    namespaces: &[namespace()],
                    active_profiles: 2,
                    administrator,
                },
                &mut NoRuleQueries,
                &AtomicBool::new(false),
            )
            .unwrap();
            let after = fixture_inventory(&fixture.root);
            report_requirement_case(
                "fresh",
                serde_json::json!({"current":"positivelyAbsent","nativeRuleQueries":0}),
                serde_json::json!({"canonicalInstallNeeded":result.canonical_install_needed,"rules":format!("{:?}",result.rules),"administrator":administrator}),
                &before,
                &after,
            );
            assert_eq!(
                result,
                GatewayRuleRequirements {
                    canonical_install_needed: true,
                    rules: GatewayRuleEffect::NativeWriteRequired { administrator }
                }
            );
        }
        assert_eq!(fixture_inventory(&fixture.root), before);
        assert_eq!(fs::read_dir(&fixture.state).unwrap().count(), 0);
    }
    #[test]
    #[ignore = "explicit owned requirement parent and synthetic ASAR inputs; no production state root"]
    fn requirement_schema2_without_transport_needs_install_but_no_firewall_privilege() {
        let fixture = RequirementFixture::open();
        let authority = Authority::open(&fixture.bound, true, false).unwrap();
        let setup = serde_json::json!({"schema":authority.current.schema,"mode":format!("{:?}",authority.current.mode),
            "currentSha256":authority.digest,"nativeRuleQueries":0});
        assert_eq!(authority.current.schema, 2);
        drop(authority);
        let before = fixture_inventory(&fixture.root);
        let input =
            GatewayHostInput::receive(&fixture.bound, &fixture.source, &fixture.sha256).unwrap();
        assert!(matches!(&input, GatewayHostInput::NewDeployment(_)));
        let result = inspect_requirements(
            &fixture.bound,
            input,
            GatewayRequirementNamespaces::TransportNotWanted,
            &mut NoRuleQueries,
            &AtomicBool::new(false),
        )
        .unwrap();
        let after = fixture_inventory(&fixture.root);
        report_requirement_case(
            "schema2-no-transport",
            setup,
            serde_json::json!({"canonicalInstallNeeded":result.canonical_install_needed,"rules":format!("{:?}",result.rules)}),
            &before,
            &after,
        );
        assert_eq!(
            result,
            GatewayRuleRequirements {
                canonical_install_needed: true,
                rules: GatewayRuleEffect::VerifiedNoop
            }
        );
        assert_eq!(fixture_inventory(&fixture.root), before);
    }
    #[test]
    #[ignore = "explicit owned requirement parent and synthetic ASAR inputs; no production state root"]
    fn requirement_unknown_current_and_wrong_source_never_become_new_deployment() {
        let fixture = RequirementFixture::open();
        let wrong_source =
            GatewayHostInput::receive(&fixture.bound, &fixture.source, &"0".repeat(64));
        eprintln!(
            "OWN_GATEWAY_REQUIREMENT_WRONG_SOURCE {}",
            serde_json::json!({"error":wrong_source.as_ref().err().map(ToString::to_string)})
        );
        assert!(matches!(wrong_source, Err(GatewayRuleError::Invalid(_))));
        let authority = Authority::open(&fixture.bound, true, false).unwrap();
        let path = authority.slot.path.join("current.json");
        drop(authority);
        // This deliberately degrades only the newly created, identity-recorded
        // synthetic Current, never product state or a foreign fixture.
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap()
            .write_all(b"{malformed synthetic Current")
            .unwrap();
        let before = fixture_inventory(&fixture.root);
        let unknown = GatewayHostInput::receive(&fixture.bound, &fixture.source, &fixture.sha256);
        let after = fixture_inventory(&fixture.root);
        report_requirement_case(
            "unknown-current",
            serde_json::json!({"current":"deliberatelyDegradedOwnedSyntheticCurrent","nativeRuleQueries":0}),
            serde_json::json!({"error":unknown.as_ref().err().map(ToString::to_string)}),
            &before,
            &after,
        );
        assert!(matches!(
            unknown,
            Err(GatewayRuleError::RecoveryRequired(_))
        ));
        assert_eq!(fixture_inventory(&fixture.root), before);
    }
}
