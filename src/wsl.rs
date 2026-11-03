// This snapshot-only seam is intentionally unused until Root integrates it.
#![allow(dead_code)]

#[derive(Debug)]
pub(crate) struct TargetMetadata<'a> {
    pub distro: &'a str,
    pub user: Option<&'a str>,
    pub home: Option<&'a str>,
    pub version: Option<&'a str>,
    pub architecture: Option<&'a str>,
    pub observed_server_path: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProducerIdentity<'a> {
    pub installation: &'a str,
    pub executable: &'a str,
    pub launch_source_digest: &'a str,
    pub app_version: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum LaunchContract<'a> {
    Missing,
    Failed,
    Unknown,
    VerifiedVersionedServer { producer: ProducerIdentity<'a> },
}

pub(crate) struct SelectionSnapshot<'a> {
    pub explicit: Option<&'a str>,
    pub environment: Option<&'a str>,
    // An actual read/parse failure is distinct from an absent persisted value.
    pub persisted: Result<Option<&'a str>, ()>,
    pub current_producer: Option<ProducerIdentity<'a>>,
    pub launch_contract: LaunchContract<'a>,
    pub desktop_channel: Option<&'a str>,
    pub registered: &'a [&'a str],
    pub targets: &'a [TargetMetadata<'a>],
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Target {
    pub distro: String,
    pub user: String,
    pub home: String,
    pub version: String,
    pub architecture: String,
    pub server_path: String,
    pub producer: OwnedProducerIdentity,
    pub desktop_channel: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OwnedProducerIdentity {
    pub installation: String,
    pub executable: String,
    pub launch_source_digest: String,
    pub app_version: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Selection { Native, Wsl(Target) }

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SelectionError { PersistedRead, Unavailable, Ambiguous, InvalidMetadata, UnsupportedLaunchContract, StaleProducer }

fn component(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".."
        && !value.chars().any(|c| c == '/' || c == '\0' || c.is_control())
}

fn absolute_home(value: &str) -> bool {
    value == "/" || (value.starts_with('/') && value[1..].split('/').all(component))
}

pub(crate) fn select(snapshot: &SelectionSnapshot<'_>) -> Result<Selection, SelectionError> {
    let selected = match snapshot.explicit {
        Some(value) => value,
        None => match snapshot.environment.filter(|value| !value.is_empty()) {
            Some(value) => value,
            None => snapshot.persisted.map_err(|_| SelectionError::PersistedRead)?.unwrap_or(""),
        },
    };
    if selected.is_empty() { return Ok(Selection::Native); }
    let producer = snapshot.current_producer.ok_or(SelectionError::UnsupportedLaunchContract)?;
    if [producer.installation, producer.executable, producer.launch_source_digest].iter()
        .any(|value| value.is_empty() || value.chars().any(char::is_control))
        || !component(producer.app_version) {
        return Err(SelectionError::UnsupportedLaunchContract);
    }
    match snapshot.launch_contract {
        LaunchContract::VerifiedVersionedServer { producer: bound } if bound == producer => {},
        LaunchContract::VerifiedVersionedServer { .. } => return Err(SelectionError::StaleProducer),
        _ => return Err(SelectionError::UnsupportedLaunchContract),
    }
    if !component(selected) { return Err(SelectionError::InvalidMetadata); }
    match snapshot.registered.iter().filter(|name| **name == selected).count() {
        0 => return Err(SelectionError::Unavailable),
        1 => {},
        _ => return Err(SelectionError::Ambiguous),
    }
    let mut matches = snapshot.targets.iter().filter(|target| target.distro == selected);
    let target = matches.next().ok_or(SelectionError::InvalidMetadata)?;
    if matches.next().is_some() { return Err(SelectionError::Ambiguous); }
    let (user, home, version, architecture) = match (target.user, target.home, target.version, target.architecture) {
        (Some(user), Some(home), Some(version), Some(architecture))
            if component(user) && absolute_home(home) && component(version) && component(architecture) =>
                (user, home, version, architecture),
        _ => return Err(SelectionError::InvalidMetadata),
    };
    let server_path = format!("{}/.antigravity-server/bin/{version}/language_server", home.trim_end_matches('/'));
    if target.observed_server_path != Some(server_path.as_str()) {
        return Err(SelectionError::InvalidMetadata);
    }
    if version != producer.app_version {
        return Err(SelectionError::InvalidMetadata);
    }
    if snapshot.desktop_channel.is_some_and(|value| !component(value)) {
        return Err(SelectionError::InvalidMetadata);
    }
    Ok(Selection::Wsl(Target {
        distro: selected.into(), user: user.into(), home: home.into(), version: version.into(),
        architecture: architecture.into(), server_path,
        producer: OwnedProducerIdentity { installation: producer.installation.into(), executable: producer.executable.into(),
            launch_source_digest: producer.launch_source_digest.into(), app_version: producer.app_version.into() },
        desktop_channel: snapshot.desktop_channel.map(String::from),
    }))
}

/// Provenance is a report of the source, never proof of a launch contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Observation<T> {
    Observed { value: T, origin: String },
    Supplied { value: T, origin: String },
    Unavailable { origin: String },
}

impl<T> Observation<T> {
    fn value(&self) -> Option<&T> {
        match self { Self::Observed { value, .. } | Self::Supplied { value, .. } => Some(value), Self::Unavailable { .. } => None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProducerObservation {
    pub installation: String,
    pub executable: String,
    pub launch_digest: String,
    pub version: String,
}

pub(crate) struct InspectionInputs {
    pub disk_producer: Observation<Option<ProducerObservation>>,
    pub active_producer: Observation<Option<ProducerObservation>>,
    pub desktop_switch: Observation<Option<String>>,
    pub desktop_environment: Observation<Option<String>>,
    pub persisted_selection: Observation<Result<Option<String>, ()>>,
    pub inspection_request: Option<InspectionRequest>,
    pub context: Observation<InspectionContext>,
}

pub(crate) struct InspectionRequest { pub distro: String, pub path: String }
pub(crate) struct InspectionContext { pub registrations: Option<Vec<String>>, pub default_user: Option<DefaultUserContext> }
pub(crate) struct DefaultUserContext {
    pub distro: Option<String>, pub uid: Option<u32>, pub gid: Option<u32>, pub user: Option<String>,
    pub home: Option<String>, pub architecture: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CandidateRejection { MissingRequest, InvalidRequest, RequestDistroMismatch, RequestPathMismatch, InvalidCandidate, RegistrationUnavailable, RegistrationAmbiguous, InvalidContext, ContextMismatch }
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CandidateProvenance { Observed(String), Supplied(String) }
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ContextAssessment { Matched, Unverified(Vec<&'static str>) }
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CandidateAssessment {
    Missing(Observation<Option<InspectedCandidate>>),
    Rejected { reason: CandidateRejection, provenance: CandidateProvenance },
    RequestBound { candidate: Observation<Option<InspectedCandidate>>, context: ContextAssessment },
}

#[derive(Debug)]
pub(crate) enum SelectionAssessment { Evaluated(Result<Selection, SelectionError>), InputsUnavailable }

pub(crate) struct InspectionReport {
    pub inputs: InspectionInputs,
    pub selection: SelectionAssessment,
    pub candidate: CandidateAssessment,
    pub unresolved: Vec<&'static str>,
}

/// This entry point has no verifier input and cannot create a verified contract.
pub(crate) fn inspect_report(inputs: InspectionInputs, candidate: Observation<Option<InspectedCandidate>>) -> InspectionReport {
    let explicit = inputs.desktop_switch.value();
    let environment = inputs.desktop_environment.value();
    let persisted = inputs.persisted_selection.value();
    let selector_inputs = match explicit {
        Some(Some(value)) => Some((Some(value.as_str()), None, Ok(None))),
        Some(None) => match environment {
            Some(Some(value)) if !value.is_empty() => Some((None, Some(value.as_str()), Ok(None))),
            Some(_) => persisted.map(|p| (None, None, p.as_ref().map(|v| v.as_deref()).map_err(|_| ()))),
            None => None,
        },
        None => None,
    };
    let selection = match selector_inputs {
        Some((explicit, environment, persisted)) => SelectionAssessment::Evaluated(select(&SelectionSnapshot {
            explicit, environment, persisted, current_producer: None, launch_contract: LaunchContract::Unknown,
            desktop_channel: None, registered: &[], targets: &[],
        })),
        None => SelectionAssessment::InputsUnavailable,
    };
    let candidate = assess_candidate(&inputs, candidate);
    InspectionReport { inputs, selection, candidate, unresolved: vec!["active producer binding", "trusted launch contract", "live target and file identity"] }
}

fn assess_candidate(inputs: &InspectionInputs, envelope: Observation<Option<InspectedCandidate>>) -> CandidateAssessment {
    let (candidate, provenance) = match &envelope {
        Observation::Observed { value: Some(value), origin } => (value, CandidateProvenance::Observed(origin.clone())),
        Observation::Supplied { value: Some(value), origin } => (value, CandidateProvenance::Supplied(origin.clone())),
        _ => return CandidateAssessment::Missing(envelope),
    };
    let rejection = (|| -> Result<ContextAssessment, CandidateRejection> {
        let request = inputs.inspection_request.as_ref().ok_or(CandidateRejection::MissingRequest)?;
        if !safe_argument(&request.distro) || !absolute_home(&request.path) { return Err(CandidateRejection::InvalidRequest); }
        if !valid_candidate(candidate) { return Err(CandidateRejection::InvalidCandidate); }
        if candidate.distro != request.distro { return Err(CandidateRejection::RequestDistroMismatch); }
        if candidate.path != request.path { return Err(CandidateRejection::RequestPathMismatch); }
        let mut missing = Vec::new();
        match inputs.context.value() {
            None => { missing.push("registration context unavailable"); missing.push("default user context unavailable"); }
            Some(context) => {
                match &context.registrations {
                    None => missing.push("registration context unavailable"),
                    Some(names) => match names.iter().filter(|name| *name == &request.distro).count() {
                        0 => return Err(CandidateRejection::RegistrationUnavailable),
                        1 => {},
                        _ => return Err(CandidateRejection::RegistrationAmbiguous),
                    },
                }
                match &context.default_user {
                    None => missing.push("default user context unavailable"),
                    Some(user) => {
                        let (distro, uid, gid, name, home, architecture) = match (&user.distro, user.uid, user.gid, &user.user, &user.home, &user.architecture) {
                            (Some(d), Some(u), Some(g), Some(n), Some(h), Some(a)) if safe_argument(d) && component(n) && absolute_home(h) && component(a) => (d, u, g, n, h, a),
                            _ => return Err(CandidateRejection::InvalidContext),
                        };
                        if *distro != candidate.distro || uid != candidate.uid || gid != candidate.gid || *name != candidate.user || *home != candidate.home || *architecture != candidate.architecture { return Err(CandidateRejection::ContextMismatch); }
                    }
                }
            }
        }
        Ok(if missing.is_empty() { ContextAssessment::Matched } else { ContextAssessment::Unverified(missing) })
    })();
    match rejection {
        Ok(context) => CandidateAssessment::RequestBound { candidate: envelope, context },
        Err(reason) => CandidateAssessment::Rejected { reason, provenance },
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProbeError { ProbeUnavailable, ProbeFailed, InvalidObservation, TargetUnavailable }

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InspectPlan { pub executable: String, pub args: Vec<String> }

fn safe_argument(s: &str) -> bool { !s.is_empty() && !s.chars().any(char::is_control) }

pub(crate) fn inspect_plan(wsl: &str, distro: &str, inspector: &str, path: &str, requested_user: Option<&str>) -> Result<InspectPlan, ProbeError> {
    if requested_user.is_some() { return Err(ProbeError::TargetUnavailable); }
    if !safe_argument(wsl) || !safe_argument(distro) || !safe_argument(inspector) || !absolute_home(path) {
        return Err(ProbeError::InvalidObservation);
    }
    Ok(InspectPlan { executable: wsl.into(), args: vec!["--distribution".into(), distro.into(), "--exec".into(), inspector.into(), "inspect-v1".into(), path.into()] })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileObservation {
    pub before: FileIdentity, pub after: FileIdentity,
    pub elf_class: String, pub elf_machine: String, pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileIdentity { pub device: u64, pub inode: u64, pub mode: u64, pub owner: u64, pub size: u64 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InspectedCandidate {
    pub distro: String, pub uid: u32, pub gid: u32, pub user: String, pub home: String,
    pub directory_version: String, pub architecture: String, pub path: String,
    pub file: Option<FileObservation>,
    pub limitations: Vec<CandidateLimitation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CandidateLimitation { FileNotObserved, FileNotRegular, ChangedIdentity, UnknownArchitecture, UnknownElfMachine, MachineContextLabelsDiffer, UntrustedReadSnapshot, AbiCompatibilityUnverified }

fn candidate_limitations(architecture: &str, file: Option<&FileObservation>) -> Vec<CandidateLimitation> {
    let mut limitations = Vec::new();
    if !matches!(architecture, "x86_64" | "aarch64") { limitations.push(CandidateLimitation::UnknownArchitecture); }
    match file {
        None => limitations.push(CandidateLimitation::FileNotObserved),
        Some(f) => {
            limitations.push(CandidateLimitation::UntrustedReadSnapshot);
            limitations.push(CandidateLimitation::AbiCompatibilityUnverified);
            if !matches!(f.elf_machine.as_str(), "x86_64" | "aarch64") { limitations.push(CandidateLimitation::UnknownElfMachine); }
            if f.elf_machine != architecture { limitations.push(CandidateLimitation::MachineContextLabelsDiffer); }
            if f.before.mode & 0o170000 != 0o100000 || f.after.mode & 0o170000 != 0o100000 { limitations.push(CandidateLimitation::FileNotRegular); }
            if f.before != f.after { limitations.push(CandidateLimitation::ChangedIdentity); }
        }
    }
    limitations
}

fn valid_candidate(candidate: &InspectedCandidate) -> bool {
    safe_argument(&candidate.distro) && component(&candidate.user) && absolute_home(&candidate.home)
        && component(&candidate.directory_version) && component(&candidate.architecture) && absolute_home(&candidate.path)
        && candidate.path == format!("{}/.antigravity-server/bin/{}/language_server", candidate.home.trim_end_matches('/'), candidate.directory_version)
        && candidate.file.as_ref().is_none_or(|f| matches!(f.elf_class.as_str(), "ELF32" | "ELF64") && component(&f.elf_machine) && f.sha256.len() == 64 && f.sha256.bytes().all(|b| b.is_ascii_hexdigit()))
        && candidate.limitations == candidate_limitations(&candidate.architecture, candidate.file.as_ref())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeDocument {
    schema: u64, operation: String, distro: String, uid: u32, gid: u32, user: String,
    home: String, directory_version: String, architecture: String, path: String,
    file: Option<ProbeFile>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeFile { before: ProbeIdentity, after: ProbeIdentity, elf_class: String, elf_machine: String, sha256: String }

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeIdentity { device: u64, inode: u64, mode: u64, owner: u64, size: u64 }

impl From<ProbeIdentity> for FileIdentity {
    fn from(v: ProbeIdentity) -> Self { Self { device: v.device, inode: v.inode, mode: v.mode, owner: v.owner, size: v.size } }
}

/// The bytes are a proposed inspector response, not a trusted producer receipt.
pub(crate) fn decode_inspection(bytes: &[u8], expected_distro: &str, expected_path: &str) -> Result<InspectedCandidate, ProbeError> {
    let v: ProbeDocument = serde_json::from_slice(bytes).map_err(|_| ProbeError::InvalidObservation)?;
    if v.schema != 1 || v.operation != "inspect" { return Err(ProbeError::InvalidObservation); }
    let (distro, user, home, version, architecture, path) = (&v.distro, &v.user, &v.home, &v.directory_version, &v.architecture, &v.path);
    if distro != expected_distro || path != expected_path || !safe_argument(distro) || !component(user) || !absolute_home(home)
        || !component(version) || !component(architecture) || !absolute_home(path)
        || *path != format!("{}/.antigravity-server/bin/{version}/language_server", home.trim_end_matches('/')) {
        return Err(ProbeError::InvalidObservation);
    }
    let file = match v.file {
        None => None,
        Some(f) => {
            if !matches!(f.elf_class.as_str(), "ELF32" | "ELF64") || !component(&f.elf_machine) || f.sha256.len() != 64 || !f.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ProbeError::InvalidObservation);
            }
            let before: FileIdentity = f.before.into();
            let after: FileIdentity = f.after.into();
            Some(FileObservation { before, after, elf_class: f.elf_class, elf_machine: f.elf_machine, sha256: f.sha256 })
        }
    };
    let limitations = candidate_limitations(&v.architecture, file.as_ref());
    let candidate = InspectedCandidate { distro: v.distro, uid: v.uid, gid: v.gid, user: v.user, home: v.home, directory_version: v.directory_version, architecture: v.architecture, path: v.path, file, limitations };
    if !valid_candidate(&candidate) { return Err(ProbeError::InvalidObservation); }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsl_inspection_unknown_and_explicit_empty_keep_precedence() {
        let inputs = InspectionInputs {
            disk_producer: Observation::Unavailable { origin: "not observed".into() }, active_producer: Observation::Unavailable { origin: "not observed".into() }, desktop_switch: Observation::Unavailable { origin: "not observed".into() },
            desktop_environment: Observation::Unavailable { origin: "not observed".into() }, persisted_selection: Observation::Supplied { value: Ok(Some("Ubuntu".into())), origin: "fixture".into() },
            inspection_request: Some(InspectionRequest { distro: "Ubuntu".into(), path: "/test-fixtures/home/u/.antigravity-server/bin/3.1/language_server".into() }),
            context: Observation::Unavailable { origin: "fixture".into() },
        };
        let report = inspect_report(inputs, Observation::Unavailable { origin: "fixture".into() });
        assert!(matches!(report.selection, SelectionAssessment::InputsUnavailable));
        let mut inputs = report.inputs;
        inputs.desktop_switch = Observation::Observed { value: Some("".into()), origin: "fixture".into() };
        inputs.persisted_selection = Observation::Supplied { value: Err(()), origin: "fixture".into() };
        assert!(matches!(inspect_report(inputs, Observation::Unavailable { origin: "fixture".into() }).selection, SelectionAssessment::Evaluated(Ok(Selection::Native))));
    }

    #[test]
    fn wsl_inspection_plan_keeps_arguments_literal() {
        let path = "/test-fixtures/home/u;$(marker)/.antigravity-server/bin/v1/language_server";
        let plan = inspect_plan("C:\\Program Files\\wsl.exe", "Name;$(marker)", "/inspector", path, None).unwrap();
        assert_eq!(plan.args, ["--distribution", "Name;$(marker)", "--exec", "/inspector", "inspect-v1", path]);
        assert_eq!(inspect_plan("wsl", "Ubuntu", "/inspector", path, Some("root")), Err(ProbeError::TargetUnavailable));
        assert_eq!(inspect_plan("wsl", "Ubuntu\n", "/inspector", path, None), Err(ProbeError::InvalidObservation));
        assert_eq!(inspect_plan("wsl", "Ubuntu", "/inspector", "/home/../escape", None), Err(ProbeError::InvalidObservation));
    }

    #[test]
    fn wsl_inspection_decoder_requires_bound_metadata_and_cannot_import_proof() {
        let path = "/test-fixtures/home/u/.antigravity-server/bin/3.1/language_server";
        let mut value = serde_json::json!({"schema":1,"operation":"inspect","distro":"Ubuntu","uid":1000,"gid":1000,"user":"u","home":"/test-fixtures/home/u","directory_version":"3.1","architecture":"x86_64","path":path});
        let decode = |v: &serde_json::Value| decode_inspection(v.to_string().as_bytes(), "Ubuntu", path);
        let candidate = decode(&value).unwrap();
        assert_eq!(candidate.directory_version, "3.1");
        assert!(candidate.limitations.contains(&CandidateLimitation::FileNotObserved));
        let duplicate = value.to_string().replace("\"schema\":1", "\"schema\":1,\"schema\":1");
        assert_eq!(decode_inspection(duplicate.as_bytes(), "Ubuntu", path), Err(ProbeError::InvalidObservation));
        value["architecture"] = "unknown-machine".into();
        assert!(decode(&value).unwrap().limitations.contains(&CandidateLimitation::UnknownArchitecture));
        value["architecture"] = serde_json::Value::Null;
        assert_eq!(decode(&value), Err(ProbeError::InvalidObservation));
        value["architecture"] = "x86_64".into();
        value["verified"] = true.into();
        assert_eq!(decode(&value), Err(ProbeError::InvalidObservation));
        value.as_object_mut().unwrap().remove("verified");
        value["distro"] = "Other".into();
        assert_eq!(decode(&value), Err(ProbeError::InvalidObservation));
        value["distro"] = "Ubuntu".into();
        value["file"] = serde_json::json!({"before":{"device":1,"inode":2,"mode":33188,"owner":1000,"size":3},"after":{"device":1,"inode":4,"mode":33188,"owner":1000,"size":3},"elf_class":"ELF64","elf_machine":"x86_64","sha256":"a".repeat(64)});
        for (class, machine) in [("ELF64", "x86_64"), ("ELF64", "aarch64"), ("ELF32", "x86_64"), ("ELF64", "unknown") ] {
            value["file"]["elf_class"] = class.into();
            value["file"]["elf_machine"] = machine.into();
            assert!(decode(&value).unwrap().limitations.contains(&CandidateLimitation::AbiCompatibilityUnverified));
        }
        let changed_candidate = decode(&value).unwrap();
        assert!(changed_candidate.limitations.contains(&CandidateLimitation::ChangedIdentity));
        assert!(changed_candidate.limitations.contains(&CandidateLimitation::UntrustedReadSnapshot));
        assert!(changed_candidate.limitations.contains(&CandidateLimitation::AbiCompatibilityUnverified));
        let changed = changed_candidate.file.unwrap();
        assert_ne!(changed.before, changed.after);
        value["file"]["before"]["mode"] = 40960.into();
        assert!(decode(&value).unwrap().limitations.contains(&CandidateLimitation::FileNotRegular));
        value["file"]["sha256"] = "bad".into();
        assert_eq!(decode(&value), Err(ProbeError::InvalidObservation));
        value.as_object_mut().unwrap().remove("file");
        value.as_object_mut().unwrap().remove("home");
        assert_eq!(decode(&value), Err(ProbeError::InvalidObservation));
    }

    #[test]
    fn wsl_inspection_report_binds_request_context_and_provenance() {
        let path = "/test-fixtures/home/u/.antigravity-server/bin/3.1/language_server";
        let doc = serde_json::json!({"schema":1,"operation":"inspect","distro":"Other","uid":1000,"gid":1000,"user":"u","home":"/test-fixtures/home/u","directory_version":"3.1","architecture":"x86_64","path":path});
        let candidate = decode_inspection(doc.to_string().as_bytes(), "Other", path).unwrap();
        let mut inputs = InspectionInputs {
            disk_producer: Observation::Unavailable { origin: "disk".into() }, active_producer: Observation::Unavailable { origin: "active".into() },
            desktop_switch: Observation::Observed { value: Some("".into()), origin: "switch".into() }, desktop_environment: Observation::Unavailable { origin: "env".into() },
            persisted_selection: Observation::Unavailable { origin: "persisted".into() },
            inspection_request: Some(InspectionRequest { distro: "Ubuntu".into(), path: path.into() }), context: Observation::Unavailable { origin: "context".into() },
        };
        let supplied = || Observation::Supplied { value: Some(candidate.clone()), origin: "candidate-origin".into() };
        let report = inspect_report(inputs, supplied());
        assert!(matches!(report.selection, SelectionAssessment::Evaluated(Ok(Selection::Native))));
        assert_eq!(report.candidate, CandidateAssessment::Rejected { reason: CandidateRejection::RequestDistroMismatch, provenance: CandidateProvenance::Supplied("candidate-origin".into()) });
        inputs = report.inputs;
        inputs.inspection_request.as_mut().unwrap().distro = "Other".into();
        inputs.inspection_request.as_mut().unwrap().path = "/different".into();
        assert!(matches!(inspect_report(inputs, supplied()).candidate, CandidateAssessment::Rejected { reason: CandidateRejection::RequestPathMismatch, .. }));
        let mut inputs = InspectionInputs {
            disk_producer: Observation::Unavailable { origin: "disk".into() }, active_producer: Observation::Unavailable { origin: "active".into() },
            desktop_switch: Observation::Unavailable { origin: "switch".into() }, desktop_environment: Observation::Unavailable { origin: "env".into() }, persisted_selection: Observation::Unavailable { origin: "persisted".into() },
            inspection_request: Some(InspectionRequest { distro: "Other".into(), path: path.into() }),
            context: Observation::Supplied { origin: "context-origin".into(), value: InspectionContext { registrations: Some(vec!["Other".into()]), default_user: None } },
        };
        let report = inspect_report(inputs, Observation::Observed { value: Some(candidate.clone()), origin: "probe".into() });
        assert!(matches!(report.candidate, CandidateAssessment::RequestBound { candidate: Observation::Observed { ref origin, .. }, context: ContextAssessment::Unverified(_) } if origin == "probe"));
        inputs = report.inputs;
        if let Observation::Supplied { value: ref mut context, .. } = inputs.context {
            context.default_user = Some(DefaultUserContext { distro: Some("Other".into()), uid: Some(1001), gid: Some(1000), user: Some("u".into()), home: Some("/test-fixtures/home/u".into()), architecture: Some("x86_64".into()) });
        }
        let report = inspect_report(inputs, supplied());
        assert!(matches!(report.candidate, CandidateAssessment::Rejected { reason: CandidateRejection::ContextMismatch, .. }));
        inputs = report.inputs;
        if let Observation::Supplied { value: ref mut context, .. } = inputs.context {
            context.default_user.as_mut().unwrap().uid = Some(1000);
        }
        let report = inspect_report(inputs, supplied());
        assert!(matches!(report.candidate, CandidateAssessment::RequestBound { candidate: Observation::Supplied { ref origin, .. }, context: ContextAssessment::Matched } if origin == "candidate-origin"));
        inputs = report.inputs;
        if let Observation::Supplied { value: ref mut context, .. } = inputs.context { context.registrations.as_mut().unwrap().push("Other".into()); }
        let report = inspect_report(inputs, supplied());
        assert!(matches!(report.candidate, CandidateAssessment::Rejected { reason: CandidateRejection::RegistrationAmbiguous, .. }));
        inputs = report.inputs;
        if let Observation::Supplied { value: ref mut context, .. } = inputs.context { context.registrations = Some(vec![]); }
        let report = inspect_report(inputs, supplied());
        assert!(matches!(report.candidate, CandidateAssessment::Rejected { reason: CandidateRejection::RegistrationUnavailable, .. }));
        inputs = report.inputs;
        inputs.inspection_request = None;
        let report = inspect_report(inputs, supplied());
        assert!(matches!(report.candidate, CandidateAssessment::Rejected { reason: CandidateRejection::MissingRequest, .. }));
        inputs = report.inputs;
        inputs.inspection_request = Some(InspectionRequest { distro: "Other".into(), path: "".into() });
        assert!(matches!(inspect_report(inputs, supplied()).candidate, CandidateAssessment::Rejected { reason: CandidateRejection::InvalidRequest, .. }));
    }

    fn producer(version: &str) -> ProducerIdentity<'_> {
        ProducerIdentity { installation: "install", executable: "executable", launch_source_digest: "digest", app_version: version }
    }

    fn verified(version: &str) -> LaunchContract<'_> {
        LaunchContract::VerifiedVersionedServer { producer: producer(version) }
    }

    fn metadata<'a>(distro: &'a str) -> TargetMetadata<'a> {
        TargetMetadata {
            distro,
            user: Some("user"),
            home: Some("/home/user"),
            version: Some("2.28.2"),
            architecture: Some("x86_64"),
            observed_server_path: Some("/home/user/.antigravity-server/bin/2.28.2/language_server"),
        }
    }

    #[test]
    fn wsl_selection_explicit_empty_is_native_and_nondefault_is_exact() {
        let registered = ["Ubuntu", "Разработка"];
        let targets = [metadata("Разработка")];
        let mut snapshot = SelectionSnapshot {
            explicit: Some(""), environment: Some("Ubuntu"), persisted: Ok(Some("Ubuntu")),
            current_producer: Some(producer("2.28.2")), launch_contract: verified("2.28.2"), desktop_channel: None,
            registered: &registered, targets: &targets,
        };
        assert_eq!(select(&snapshot), Ok(Selection::Native));
        snapshot.explicit = Some("Разработка");
        assert_eq!(select(&snapshot), Ok(Selection::Wsl(Target {
            distro: "Разработка".into(), user: "user".into(), home: "/home/user".into(),
            version: "2.28.2".into(), architecture: "x86_64".into(),
            server_path: "/home/user/.antigravity-server/bin/2.28.2/language_server".into(),
            producer: OwnedProducerIdentity { installation: "install".into(), executable: "executable".into(), launch_source_digest: "digest".into(), app_version: "2.28.2".into() }, desktop_channel: None,
        })));
    }

    #[test]
    fn wsl_selection_precedence_and_persisted_errors() {
        let registered = ["Ubuntu", "Other"];
        let targets = [metadata("Ubuntu"), metadata("Other")];
        let mut snapshot = SelectionSnapshot {
            explicit: None, environment: Some("Other"), persisted: Ok(Some("Ubuntu")),
            current_producer: Some(producer("2.28.2")), launch_contract: verified("2.28.2"), desktop_channel: None,
            registered: &registered, targets: &targets,
        };
        assert!(matches!(select(&snapshot), Ok(Selection::Wsl(t)) if t.distro == "Other"));
        snapshot.environment = Some("");
        assert!(matches!(select(&snapshot), Ok(Selection::Wsl(t)) if t.distro == "Ubuntu"));
        snapshot.persisted = Ok(None);
        assert_eq!(select(&snapshot), Ok(Selection::Native));
        snapshot.persisted = Err(());
        assert_eq!(select(&snapshot), Err(SelectionError::PersistedRead));
        snapshot.explicit = Some("");
        assert_eq!(select(&snapshot), Ok(Selection::Native));
    }

    #[test]
    fn wsl_selection_valid_other_version() {
        let registered = ["Ubuntu"];
        let mut targets = [metadata("Ubuntu")];
        targets[0].version = Some("3.7.1");
        targets[0].observed_server_path = Some("/home/user/.antigravity-server/bin/3.7.1/language_server");
        let mut snapshot = SelectionSnapshot {
            explicit: Some("Ubuntu"), environment: None, persisted: Ok(None),
            current_producer: Some(producer("3.7.1")), launch_contract: verified("3.7.1"), desktop_channel: Some("insiders"),
            registered: &registered, targets: &targets,
        };
        let expected = Target {
            distro: "Ubuntu".into(), user: "user".into(), home: "/home/user".into(),
            version: "3.7.1".into(), architecture: "x86_64".into(),
            server_path: "/home/user/.antigravity-server/bin/3.7.1/language_server".into(),
            producer: OwnedProducerIdentity { installation: "install".into(), executable: "executable".into(),
                launch_source_digest: "digest".into(), app_version: "3.7.1".into() },
            desktop_channel: Some("insiders".into()),
        };
        assert_eq!(select(&snapshot), Ok(Selection::Wsl(expected)));
        snapshot.desktop_channel = None;
        assert!(matches!(select(&snapshot), Ok(Selection::Wsl(t)) if t.version == "3.7.1" && t.desktop_channel.is_none()));
        snapshot.launch_contract = LaunchContract::VerifiedVersionedServer {
            producer: ProducerIdentity { installation: "other", ..producer("3.7.1") },
        };
        assert_eq!(select(&snapshot), Err(SelectionError::StaleProducer));
    }

    #[test]
    fn wsl_selection_requires_current_verified_producer() {
        let registered = ["Ubuntu"];
        let targets = [metadata("Ubuntu")];
        let mut snapshot = SelectionSnapshot {
            explicit: Some("Ubuntu"), environment: None, persisted: Err(()),
            current_producer: Some(producer("2.28.2")), launch_contract: verified("2.28.2"),
            desktop_channel: None, registered: &registered, targets: &targets,
        };
        for contract in [LaunchContract::Missing, LaunchContract::Failed, LaunchContract::Unknown] {
            snapshot.launch_contract = contract;
            assert_eq!(select(&snapshot), Err(SelectionError::UnsupportedLaunchContract));
        }
        snapshot.launch_contract = verified("2.28.2");
        for current in [
            ProducerIdentity { installation: "other", ..producer("2.28.2") },
            ProducerIdentity { executable: "other", ..producer("2.28.2") },
            ProducerIdentity { launch_source_digest: "other", ..producer("2.28.2") },
            producer("3.7.1"),
        ] {
            snapshot.current_producer = Some(current);
            assert_eq!(select(&snapshot), Err(SelectionError::StaleProducer));
        }
        snapshot.current_producer = None;
        assert_eq!(select(&snapshot), Err(SelectionError::UnsupportedLaunchContract));
        snapshot.current_producer = Some(ProducerIdentity { installation: "", ..producer("2.28.2") });
        assert_eq!(select(&snapshot), Err(SelectionError::UnsupportedLaunchContract));
        snapshot.explicit = Some("");
        snapshot.current_producer = None;
        snapshot.launch_contract = LaunchContract::Missing;
        assert_eq!(select(&snapshot), Ok(Selection::Native));
    }

    #[test]
    fn wsl_selection_rejects_desktop_server_version_mismatch() {
        let registered = ["Ubuntu"];
        let mut targets = [metadata("Ubuntu")];
        targets[0].version = Some("1.2.3");
        targets[0].observed_server_path = Some("/home/user/.antigravity-server/bin/1.2.3/language_server");
        let snapshot = SelectionSnapshot {
            explicit: Some("Ubuntu"), environment: None, persisted: Ok(None),
            current_producer: Some(producer("2.28.2")), launch_contract: verified("2.28.2"), desktop_channel: None,
            registered: &registered, targets: &targets,
        };
        assert_eq!(select(&snapshot), Err(SelectionError::InvalidMetadata));
        let other = SelectionSnapshot {
            current_producer: Some(producer("3.7.1")), launch_contract: verified("3.7.1"), ..snapshot
        };
        assert_eq!(select(&other), Err(SelectionError::InvalidMetadata));
    }

    #[test]
    fn wsl_selection_rejects_missing_ambiguous_and_unsafe_targets() {
        let registered = ["Ubuntu"];
        let mut missing_home = [metadata("Ubuntu")];
        missing_home[0].home = None;
        let mut unsafe_version = [metadata("Ubuntu")];
        unsafe_version[0].version = Some("../other");
        let mut unsafe_home = [metadata("Ubuntu")];
        unsafe_home[0].home = Some("/home/user/../other");
        let mut wrong_path = [metadata("Ubuntu")];
        wrong_path[0].observed_server_path = Some("/home/user/.antigravity-server/bin/other/language_server");
        let snapshot = |targets| SelectionSnapshot {
            explicit: Some("Ubuntu"), environment: None, persisted: Ok(None),
            current_producer: Some(producer("2.28.2")), launch_contract: verified("2.28.2"), desktop_channel: None,
            registered: &registered, targets,
        };
        assert_eq!(select(&snapshot(&missing_home)), Err(SelectionError::InvalidMetadata));
        assert_eq!(select(&snapshot(&unsafe_version)), Err(SelectionError::InvalidMetadata));
        assert_eq!(select(&snapshot(&unsafe_home)), Err(SelectionError::InvalidMetadata));
        assert_eq!(select(&snapshot(&wrong_path)), Err(SelectionError::InvalidMetadata));
        let duplicates = [metadata("Ubuntu"), metadata("Ubuntu")];
        assert_eq!(select(&snapshot(&duplicates)), Err(SelectionError::Ambiguous));
        let missing = SelectionSnapshot { explicit: Some("Other"), ..snapshot(&unsafe_home) };
        assert_eq!(select(&missing), Err(SelectionError::Unavailable));
    }
}
