//! Versioned runtime wire inside the existing canonical Current record.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GateBinding {
    pub(super) name: String,
    pub(super) native_id: ObjectId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HostBinding {
    pub(crate) path: PathBuf,
    pub(crate) native_id: ObjectId,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct HookBinding {
    pub(super) revision: String,
    pub(super) member_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RuntimeDeployment {
    pub(super) version: u32,
    pub(super) gate: GateBinding,
    pub(super) host: HostBinding,
    pub(super) hook: HookBinding,
    pub(super) receipt: EvidenceRef,
    /// None is the exact host-only version 1 shape. Version 2 requires Some,
    /// including when no transport scope is currently installed.
    pub(super) gateway_rules: Option<Vec<EvidenceRef>>,
}

#[derive(Clone, Debug, Default)]
enum GatewayRulesField {
    #[default]
    Absent,
    Present(Vec<EvidenceRef>),
}
impl GatewayRulesField {
    fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
    fn receive(self, version: u32) -> Result<Option<Vec<EvidenceRef>>> {
        match (version, self) {
            (1, Self::Absent) => Ok(None),
            (2, Self::Present(refs)) => Ok(Some(refs)),
            _ => Err("runtime deployment version/gatewayRules shape conflict".into()),
        }
    }
}
impl Serialize for GatewayRulesField {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Absent => Err(serde::ser::Error::custom(
                "absent gatewayRules must be omitted",
            )),
            Self::Present(refs) => refs.serialize(serializer),
        }
    }
}
impl<'de> Deserialize<'de> for GatewayRulesField {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Vec::<EvidenceRef>::deserialize(deserializer).map(Self::Present)
    }
}
impl From<&Option<Vec<EvidenceRef>>> for GatewayRulesField {
    fn from(value: &Option<Vec<EvidenceRef>>) -> Self {
        match value {
            None => Self::Absent,
            Some(refs) => Self::Present(refs.clone()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeploymentWire {
    version: u32,
    gate: GateBinding,
    host: HostBinding,
    hook: HookBinding,
    receipt: EvidenceRef,
    #[serde(default, skip_serializing_if = "GatewayRulesField::is_absent")]
    gateway_rules: GatewayRulesField,
}
impl Serialize for RuntimeDeployment {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        validate_rules_shape(self.version, &self.gateway_rules)
            .map_err(serde::ser::Error::custom)?;
        DeploymentWire {
            version: self.version,
            gate: self.gate.clone(),
            host: self.host.clone(),
            hook: self.hook.clone(),
            receipt: self.receipt.clone(),
            gateway_rules: (&self.gateway_rules).into(),
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for RuntimeDeployment {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let wire = DeploymentWire::deserialize(deserializer)?;
        let gateway_rules = wire
            .gateway_rules
            .receive(wire.version)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            version: wire.version,
            gate: wire.gate,
            host: wire.host,
            hook: wire.hook,
            receipt: wire.receipt,
            gateway_rules,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub(super) enum DeploymentField {
    #[default]
    Absent,
    Present(Option<RuntimeDeployment>),
}
impl DeploymentField {
    pub(super) fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
    pub(super) fn received(&self) -> Result<&RuntimeDeployment> {
        match self {
            Self::Present(Some(value)) => Ok(value),
            _ => Err("MaintenanceRequired: V2 runtime deployment is not received".into()),
        }
    }
    pub(super) fn validate_schema(&self, schema: u32) -> Result<()> {
        match (schema, self) {
            (2, Self::Absent) | (3, Self::Present(None)) => Ok(()),
            (3, Self::Present(Some(value))) => value.validate_shape(),
            _ => Err("canonical runtimeDeployment presence/schema conflict".into()),
        }
    }
}
impl Serialize for DeploymentField {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Absent => Err(serde::ser::Error::custom(
                "absent legacy field must be omitted",
            )),
            Self::Present(value) => value.serialize(serializer),
        }
    }
}
impl<'de> Deserialize<'de> for DeploymentField {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Option::<RuntimeDeployment>::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DeploymentReceipt {
    pub(super) version: u32,
    pub(super) gate: GateBinding,
    pub(super) host: HostBinding,
    pub(super) hook: HookBinding,
    pub(super) gateway_rules: Option<Vec<EvidenceRef>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptWire {
    version: u32,
    gate: GateBinding,
    host: HostBinding,
    hook: HookBinding,
    #[serde(default, skip_serializing_if = "GatewayRulesField::is_absent")]
    gateway_rules: GatewayRulesField,
}
impl Serialize for DeploymentReceipt {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        validate_rules_shape(self.version, &self.gateway_rules)
            .map_err(serde::ser::Error::custom)?;
        ReceiptWire {
            version: self.version,
            gate: self.gate.clone(),
            host: self.host.clone(),
            hook: self.hook.clone(),
            gateway_rules: (&self.gateway_rules).into(),
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for DeploymentReceipt {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let wire = ReceiptWire::deserialize(deserializer)?;
        let gateway_rules = wire
            .gateway_rules
            .receive(wire.version)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            version: wire.version,
            gate: wire.gate,
            host: wire.host,
            hook: wire.hook,
            gateway_rules,
        })
    }
}
fn validate_rules_shape(version: u32, rules: &Option<Vec<EvidenceRef>>) -> Result<()> {
    match (version, rules) {
        (1, None) => Ok(()),
        (2, Some(refs)) => {
            let mut seen = std::collections::BTreeSet::new();
            for reference in refs {
                if !seen.insert(&reference.path)
                    || reference.path.is_empty()
                    || reference.digest.len() != 64
                    || !reference
                        .digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("runtime gateway rule reference shape conflict".into());
                }
            }
            Ok(())
        }
        _ => Err("runtime deployment version/gatewayRules shape conflict".into()),
    }
}

impl RuntimeDeployment {
    pub(super) fn validate_shape(&self) -> Result<()> {
        let sha = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        validate_rules_shape(self.version, &self.gateway_rules)?;
        if self.gate.name != "runtime-gate"
            || self.hook.revision != "wsl-gui-v2"
            || !sha(&self.host.sha256)
            || !sha(&self.hook.member_sha256)
            || !sha(&self.receipt.digest)
        {
            return Err("RecoveryRequired: runtime deployment shape/revision conflict".into());
        }
        WindowsExecutablePath::parse(self.host.path.as_os_str())?;
        Ok(())
    }

    pub(super) fn receive_host(&self, slot: &CheckedPath) -> Result<CheckedPath> {
        self.validate_shape()?;
        let host = CheckedPath::open(&self.host.path, PathKind::File, PathPurpose::Executable)?;
        identity(&host.file)?;
        private(&host.file)?;
        if !slot.contains(&host)?
            || host.object != self.host.native_id
            || hash(&host.read_snapshot()?) != self.host.sha256
        {
            return Err("MaintenanceRequired: immutable runtime host binding differs".into());
        }
        Ok(host)
    }

    pub(super) fn receive_receipt(&self, slot: &CheckedPath) -> Result<()> {
        let receipt: DeploymentReceipt = decode(&reference(slot, &self.receipt)?)?;
        if receipt.version != self.version
            || receipt.gate != self.gate
            || receipt.host != self.host
            || receipt.hook != self.hook
            || receipt.gateway_rules != self.gateway_rules
        {
            return Err("RecoveryRequired: runtime deployment receipt differs".into());
        }
        if let Some(refs) = &self.gateway_rules {
            gateway_rules::receive_references(slot, &self.host, refs)?;
        }
        Ok(())
    }

    pub(super) fn receive_hook(&self, archive: &[u8]) -> Result<()> {
        let path = self
            .host
            .path
            .to_str()
            .ok_or("runtime host path is not Unicode")?;
        if desktop_hook::gui_member_digest(archive, path).map_err(|e| e.to_string())?
            != self.hook.member_sha256
        {
            return Err("MaintenanceRequired: runtime hook binding differs".into());
        }
        Ok(())
    }

    pub(super) fn receipt(&self) -> DeploymentReceipt {
        DeploymentReceipt {
            version: self.version,
            gate: self.gate.clone(),
            host: self.host.clone(),
            hook: self.hook.clone(),
            gateway_rules: self.gateway_rules.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn deployment() -> RuntimeDeployment {
        let native_id = ObjectId {
            volume: 7,
            file: [8; 16],
        };
        RuntimeDeployment {
            version: 1,
            gate: GateBinding {
                name: "runtime-gate".into(),
                native_id: native_id.clone(),
            },
            host: HostBinding {
                path: PathBuf::from(r"C:\fixture\host.exe"),
                native_id,
                sha256: "a".repeat(64),
            },
            hook: HookBinding {
                revision: "wsl-gui-v2".into(),
                member_sha256: "b".repeat(64),
            },
            receipt: EvidenceRef {
                path: "evidence/fixture/deployment.json".into(),
                digest: "c".repeat(64),
            },
            gateway_rules: None,
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Wire {
        #[serde(default, skip_serializing_if = "DeploymentField::is_absent")]
        runtime_deployment: DeploymentField,
    }
    #[test]
    fn runtime_wire_keeps_legacy_omission_and_requires_v3_presence() {
        let old: Wire = serde_json::from_str("{}").unwrap();
        assert!(old.runtime_deployment.validate_schema(2).is_ok());
        assert!(old.runtime_deployment.validate_schema(3).is_err());
        assert_eq!(serde_json::to_string(&old).unwrap(), "{}");
        let explicit: Wire = serde_json::from_str(r#"{"runtimeDeployment":null}"#).unwrap();
        assert!(explicit.runtime_deployment.validate_schema(2).is_err());
        assert!(explicit.runtime_deployment.validate_schema(3).is_ok());
        assert_eq!(
            serde_json::to_string(&explicit).unwrap(),
            r#"{"runtimeDeployment":null}"#
        );
        assert!(serde_json::from_str::<Wire>(r#"{"runtimeDeployment":{"version":1}}"#).is_err());
        assert!(serde_json::from_str::<Wire>(r#"{"unexpected":null}"#).is_err());
    }
    #[test]
    fn deployment_versions_require_their_exact_gateway_rules_shape() {
        let v1 = deployment();
        let encoded = serde_json::to_value(&v1).unwrap();
        assert!(encoded.get("gatewayRules").is_none());
        assert_eq!(
            serde_json::from_value::<RuntimeDeployment>(encoded.clone()).unwrap(),
            v1
        );
        let mut wrong_v1 = encoded.clone();
        wrong_v1["gatewayRules"] = serde_json::json!([]);
        assert!(serde_json::from_value::<RuntimeDeployment>(wrong_v1).is_err());
        let mut missing_v2 = encoded.clone();
        missing_v2["version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<RuntimeDeployment>(missing_v2.clone()).is_err());
        missing_v2["gatewayRules"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<RuntimeDeployment>(missing_v2).is_err());
        let mut unknown = encoded;
        unknown["version"] = serde_json::json!(3);
        assert!(serde_json::from_value::<RuntimeDeployment>(unknown).is_err());
        let mut v2 = v1;
        v2.version = 2;
        v2.gateway_rules = Some(Vec::new());
        let encoded = serde_json::to_value(&v2).unwrap();
        assert_eq!(encoded["gatewayRules"], serde_json::json!([]));
        assert_eq!(
            serde_json::from_value::<RuntimeDeployment>(encoded).unwrap(),
            v2
        );
        assert_eq!(
            serde_json::from_value::<DeploymentReceipt>(
                serde_json::to_value(v2.receipt()).unwrap()
            )
            .unwrap(),
            v2.receipt()
        );
    }
    #[test]
    fn immutable_receipt_versions_reject_missing_extra_and_null_gateway_rules() {
        let v1 = serde_json::to_value(deployment().receipt()).unwrap();
        assert!(v1.get("gatewayRules").is_none());
        for rules in [serde_json::json!([]), serde_json::Value::Null] {
            let mut wrong = v1.clone();
            wrong["gatewayRules"] = rules;
            assert!(serde_json::from_value::<DeploymentReceipt>(wrong).is_err());
        }
        let mut missing = v1.clone();
        missing["version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<DeploymentReceipt>(missing).is_err());
        let mut extra = v1;
        extra["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DeploymentReceipt>(extra).is_err());
    }
}
