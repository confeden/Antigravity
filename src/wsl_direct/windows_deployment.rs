//! Explicit nonsecret deployment-data acquisition. This module knows the one
//! admitted registration interface; generic path/native code does not parse it.
use super::windows_installation as owner;
use owner::{
    AncestorAccessContext, AncestorInputs, BoundInstallation, CheckedPath, DeploymentVerifier,
    NativeObjectId, PathKind, PathPurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::Path;
type Result<T> = std::result::Result<T, String>;
const PROVIDER: &str = "codex-windows-sandbox-v1";
const PUBLISHER: &str = "OpenAI OpCo, LLC";
fn hash(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err("deployment UTF-8 BOM is unsupported".into());
    }
    std::str::from_utf8(bytes).map_err(|_| "deployment UTF-8 invalid")?;
    serde_json::from_slice(bytes).map_err(|e| {
        format!(
            "deployment schema invalid at line {} column {} ({:?})",
            e.line(),
            e.column(),
            e.classify()
        )
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u32,
    offline_username: String,
    online_username: String,
    created_at: String,
    read_roots: Vec<serde_json::Value>,
    write_roots: Vec<serde_json::Value>,
}
#[derive(Serialize)]
struct Selected<'a> {
    version: u32,
    offline_username: &'a str,
    online_username: &'a str,
}
fn marker(bytes: &[u8]) -> Result<([String; 2], String)> {
    let marker: Marker = decode(bytes)?;
    if marker.version != 5
        || marker.offline_username.is_empty()
        || marker.online_username.is_empty()
        || marker.offline_username == marker.online_username
        || marker
            .offline_username
            .chars()
            .chain(marker.online_username.chars())
            .any(char::is_control)
    {
        return Err(
            "UnsupportedActorContext: registration role/version interface unsupported".into(),
        );
    }
    // Date/root elements are required schema data, never decoded into authority.
    let _non_authorizing = (&marker.created_at, &marker.read_roots, &marker.write_roots);
    let selected = hash(&json(&Selected {
        version: marker.version,
        offline_username: &marker.offline_username,
        online_username: &marker.online_username,
    })?);
    Ok(([marker.offline_username, marker.online_username], selected))
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MarkerData {
    path: std::path::PathBuf,
    native_id: NativeObjectId,
    selected_fields_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BinaryData {
    path: std::path::PathBuf,
    native_id: NativeObjectId,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleSids {
    offline: String,
    online: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Carrier {
    schema: u32,
    provider: String,
    owner_sid: String,
    machine_account_domain_sid: String,
    roles: Vec<String>,
    marker: MarkerData,
    provider_binary: BinaryData,
    group_sid: String,
    role_sids: RoleSids,
}
fn roles(provider: &str, roles: &[String]) -> Result<()> {
    let mut roles = roles.to_vec();
    roles.sort();
    if provider != PROVIDER || roles != ["offline", "online"] {
        return Err(
            "UnsupportedActorContext: deployment provider/selected role scope unsupported".into(),
        );
    }
    Ok(())
}
fn read(path: &CheckedPath) -> Result<Vec<u8>> {
    path.read_snapshot()
}
struct Registration {
    marker: CheckedPath,
    binary: CheckedPath,
    names: [String; 2],
    selected: String,
    binary_digest: String,
    marker_sd: String,
    binary_sd: String,
    signer: String,
}
impl DeploymentVerifier for Registration {
    fn registration_file(&self) -> &File {
        &self.marker.file
    }
    fn revalidate(&self) -> Result<()> {
        self.marker.recheck()?;
        self.binary.recheck()?;
        let (names, selected) = marker(&read(&self.marker)?)?;
        if names != self.names
            || selected != self.selected
            || self.marker.security_digest()? != self.marker_sd
            || self.binary.security_digest()? != self.binary_sd
            || self.binary.read_checked_snapshot()?.digest() != self.binary_digest
        {
            return Err(
                "UnsupportedActorContext: registration/binary/native security binding changed"
                    .into(),
            );
        }
        let signer = owner::verify_signature(&self.binary)?;
        if signer.organization != PUBLISHER
            || signer.simple_name != PUBLISHER
            || signer.certificate_sha256 != self.signer
        {
            return Err("UnsupportedActorContext: expected signed provider changed".into());
        }
        Ok(())
    }
}
fn registration_interface(bytes: &[u8]) -> bool {
    [
        b"setup_marker.json".as_slice(),
        b"offline_username".as_slice(),
        b"online_username".as_slice(),
        b"created_at".as_slice(),
        b"read_roots".as_slice(),
        b"write_roots".as_slice(),
    ]
    .iter()
    .all(|needle| memchr::memmem::find(bytes, needle).is_some())
}
fn registration(marker_path: &Path, binary_path: &Path) -> Result<Registration> {
    let marker_pin = CheckedPath::open(marker_path, PathKind::File, PathPurpose::Source)?;
    owner::WindowsExecutablePath::parse(binary_path.as_os_str())?;
    let binary = CheckedPath::open(binary_path, PathKind::File, PathPurpose::Executable)?;
    let (names, selected) = marker(&read(&marker_pin)?)?;
    let binary_snapshot = binary.read_checked_snapshot()?;
    if !registration_interface(binary_snapshot.bytes()) {
        return Err(
            "UnsupportedActorContext: signed provider registration interface association absent"
                .into(),
        );
    }
    let signer = owner::verify_signature(&binary)?;
    if signer.organization != PUBLISHER || signer.simple_name != PUBLISHER {
        return Err("UnsupportedActorContext: unexpected signed provider identity".into());
    }
    let binary_digest = binary_snapshot.digest().to_owned();
    let marker_sd = marker_pin.security_digest()?;
    let binary_sd = binary.security_digest()?;
    Ok(Registration {
        marker: marker_pin,
        binary,
        names,
        selected,
        binary_digest,
        marker_sd,
        binary_sd,
        signer: signer.certificate_sha256,
    })
}
fn qualify(
    inputs: AncestorInputs,
    proof: Registration,
    expected: Option<&Carrier>,
    prequalified: Option<owner::QualifiedGroup>,
) -> Result<(AncestorAccessContext, Carrier)> {
    let (owner_sid, machine_account_domain_sid) = owner::owner_machine_wire()?;
    let group = match prequalified {
        Some(group) => group,
        None => owner::qualify_group(&inputs, proof.names.clone())?,
    };
    let (group_sid, role_sids) = group.wire()?;
    let data = Carrier {
        schema: 1,
        provider: PROVIDER.into(),
        owner_sid,
        machine_account_domain_sid,
        roles: vec!["offline".into(), "online".into()],
        marker: MarkerData {
            path: proof.marker.as_path().into(),
            native_id: proof.marker.native_id(),
            selected_fields_sha256: proof.selected.clone(),
        },
        provider_binary: BinaryData {
            path: proof.binary.as_path().into(),
            native_id: proof.binary.native_id(),
            sha256: proof.binary_digest.clone(),
        },
        group_sid,
        role_sids: RoleSids {
            offline: role_sids[0].clone(),
            online: role_sids[1].clone(),
        },
    };
    if let Some(e) = expected {
        if e.marker.native_id != data.marker.native_id
            || e.marker.selected_fields_sha256 != data.marker.selected_fields_sha256
            || e.provider_binary.native_id != data.provider_binary.native_id
            || e.provider_binary.sha256 != data.provider_binary.sha256
            || e.group_sid != data.group_sid
            || e.role_sids.offline != data.role_sids.offline
            || e.role_sids.online != data.role_sids.online
        {
            return Err(
                "UnsupportedActorContext: deployment carrier/native registration binding drift"
                    .into(),
            );
        }
    }
    let context = owner::receive_ancestor_context(
        owner::OwnerScope::SelectedDeploymentDelegates,
        inputs,
        group,
        Box::new(proof),
    )?;
    Ok((context, data))
}
pub(crate) fn collect(
    bound: &BoundInstallation,
    provider: &str,
    selected: &str,
    marker: &Path,
    binary: &Path,
    output: &Path,
) -> Result<()> {
    roles(
        provider,
        &selected.split(',').map(str::to_string).collect::<Vec<_>>(),
    )?;
    let output_plan = bound.validate_deployment_output(output)?;
    let (context, data) = qualify(
        bound.ancestor_inputs()?,
        registration(marker, binary)?,
        None,
        None,
    )?;
    context.revalidate()?;
    owner::write_deployment_output(output_plan, &json(&data)?)?;
    let readback: Carrier = decode(&owner::read_deployment_data(output)?)?;
    if json(&readback)? != json(&data)? {
        return Err("deployment data independent readback mismatch".into());
    }
    Ok(())
}
pub(crate) fn receive(bound: &BoundInstallation, path: &Path) -> Result<AncestorAccessContext> {
    receive_from_ancestors(|| bound.ancestor_inputs(), path)
}
fn receive_from_ancestors(inputs: impl FnOnce() -> Result<AncestorInputs>, path: &Path) -> Result<AncestorAccessContext> {
    let data: Carrier = decode(&owner::read_deployment_data(path)?)?;
    let (user, machine) = owner::owner_machine_wire()?;
    // No provider locator is dereferenced until this native user/machine check.
    if data.schema != 1 || data.owner_sid != user || data.machine_account_domain_sid != machine {
        return Err(
            "UnsupportedActorContext: deployment user/machine/schema mismatch before locators"
                .into(),
        );
    }
    roles(&data.provider, &data.roles)?;
    let marker_pin = CheckedPath::open(&data.marker.path, PathKind::File, PathPurpose::Source)?;
    let binary_pin = CheckedPath::open(
        &data.provider_binary.path,
        PathKind::File,
        PathPurpose::Executable,
    )?;
    if marker_pin.native_id() != data.marker.native_id
        || binary_pin.native_id() != data.provider_binary.native_id
    {
        return Err("UnsupportedActorContext: deployment native identity drift".into());
    }
    let (names, selected) = marker(&read(&marker_pin)?)?;
    if selected != data.marker.selected_fields_sha256 {
        return Err("UnsupportedActorContext: marker selected-field drift".into());
    }
    let inputs = inputs()?;
    let group = owner::qualify_group(&inputs, names)?;
    let (sid, roles) = group.wire()?;
    if sid != data.group_sid
        || roles[0] != data.role_sids.offline
        || roles[1] != data.role_sids.online
    {
        return Err("UnsupportedActorContext: deployment role/group binding drift".into());
    }
    let proof = registration(&data.marker.path, &data.provider_binary.path)?;
    qualify(inputs, proof, Some(&data), Some(group)).map(|pair| pair.0)
}
/// Explicit selection wins. Only an omitted, actually missing saved file means
/// empty delegate context; every receiving/requalification error stays visible.
pub(crate) fn receive_for_installation(
    bound: &BoundInstallation,
    explicit: Option<&Path>,
) -> Result<Option<AncestorAccessContext>> {
    receive_for_ancestors(|| bound.ancestor_inputs(), explicit)
}
pub(crate) fn receive_for_background(
    inputs: &owner::BackgroundInputs,
    explicit: Option<&Path>,
) -> Result<Option<AncestorAccessContext>> {
    receive_for_ancestors(|| inputs.ancestor_inputs(), explicit)
}
pub(crate) fn receive_for_diagnostic(
    inputs: &owner::DiagnosticInputs,
    explicit: Option<&Path>,
) -> Result<Option<AncestorAccessContext>> {
    receive_for_ancestors(|| inputs.ancestor_inputs(), explicit)
}
// Delaying projection preserves omitted+NotFound and carrier-error priority;
// the native owner still supplies the sole sealed ancestor input value.
fn receive_for_ancestors(inputs: impl FnOnce() -> Result<AncestorInputs>, explicit: Option<&Path>) -> Result<Option<AncestorAccessContext>> {
    if let Some(path) = explicit {
        return receive_from_ancestors(inputs, path).map(Some);
    }
    let path = owner::saved_deployment_data_path()?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => receive_from_ancestors(inputs, &path).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("saved deployment DATA observation: {e}")),
    }
}
#[cfg(test)]
#[path = "windows_deployment/tests.rs"]
mod tests;
