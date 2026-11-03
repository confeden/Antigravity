//! Closed per-operation existing-ancestor capability. Managed private objects
//! never consume it. Provider registration is verified by composition.
use super::context_native::*;
use super::*;
use std::ffi::c_void;

pub(crate) struct AncestorInputs {
    files: Vec<File>,
}
impl AncestorInputs {
    pub(super) fn new(files: Vec<File>) -> Self {
        Self { files }
    }
    pub(crate) fn files(&self) -> &[File] {
        &self.files
    }
}
pub(crate) trait DeploymentVerifier {
    fn revalidate(&self) -> Result<()>;
    fn registration_file(&self) -> &File;
}
pub(crate) enum OwnerScope {
    SelectedDeploymentDelegates,
}
pub(crate) struct QualifiedGroup {
    sid: Sid,
    roles: [Sid; 2],
    sam: Sid,
    names: [String; 2],
}
impl QualifiedGroup {
    pub(crate) fn wire(&self) -> Result<(String, [String; 2])> {
        Ok((
            self.sid.text()?,
            [self.roles[0].text()?, self.roles[1].text()?],
        ))
    }
    fn revalidate(&self) -> Result<()> {
        let roles = [
            local_role(&self.names[0], &self.sam)?,
            local_role(&self.names[1], &self.sam)?,
        ];
        let mut expected = self.roles.to_vec();
        expected.sort();
        if !roster_unchanged(
            &self.roles,
            &roles,
            &expected,
            &group_members(&self.sid, &self.sam)?,
        ) {
            return Err("UnsupportedActorContext: deployment role/group membership changed".into());
        }
        Ok(())
    }
}
fn roster_unchanged(
    expected_roles: &[Sid; 2],
    roles: &[Sid; 2],
    expected: &[Sid],
    actual: &[Sid],
) -> bool {
    expected_roles == roles && expected == actual
}
pub(crate) fn qualify_group(inputs: &AncestorInputs, names: [String; 2]) -> Result<QualifiedGroup> {
    let sam = machine_domain()?;
    let roles = [local_role(&names[0], &sam)?, local_role(&names[1], &sam)?];
    let owner = current_user()?;
    if names[0] == names[1] || roles[0] == roles[1] || roles.iter().any(|s| *s == owner) {
        return Err("UnsupportedActorContext: distinct delegated local roles required".into());
    }
    let mut expected = roles.to_vec();
    expected.sort();
    let mut candidates = std::collections::BTreeSet::new();
    for file in inputs.files() {
        let mut sd = security(file.as_raw_handle(), 1 | 4)?;
        for ace in entries(&mut sd)? {
            if !ace.deny
                && ace.mask & DIRECTORY_ENTRY_RIGHTS != 0
                && ace.sid.domain().is_ok_and(|d| d == sam)
            {
                candidates.insert(ace.sid);
            }
        }
    }
    let mut matching = Vec::new();
    for sid in candidates {
        if let Some(actual) = group_members_if_alias(&sid, &sam)? {
            if actual == expected {
                matching.push(sid)
            }
        }
    }
    if matching.len() != 1 {
        return Err("UnsupportedActorContext: no unique complete registered group roster".into());
    }
    Ok(QualifiedGroup {
        sid: matching.remove(0),
        roles,
        sam,
        names,
    })
}
const DIRECTORY_ENTRY_RIGHTS: u32 = 0x000d_0150;
#[derive(Clone, Copy)]
enum IntegrityPurpose {
    DirectoryEntry,
    RegistrationContent,
    NonsecretMetadataContent,
}
impl IntegrityPurpose {
    fn rights(self) -> u32 {
        match self {
            Self::DirectoryEntry => DIRECTORY_ENTRY_RIGHTS,
            Self::RegistrationContent | Self::NonsecretMetadataContent => 0x000d_0116,
        }
    }
}
struct Observation {
    file: File,
    id: ObjectId,
    descriptor: String,
}
pub(crate) struct AncestorAccessContext {
    owner: Sid,
    sam: Option<Sid>,
    observations: Vec<Observation>,
    group: Option<QualifiedGroup>,
    issuer: Option<IssuerSnapshot>,
    verifier: Option<Box<dyn DeploymentVerifier>>,
}
pub(crate) fn receive_ancestor_context(
    _scope: OwnerScope,
    inputs: AncestorInputs,
    group: QualifiedGroup,
    verifier: Box<dyn DeploymentVerifier>,
) -> Result<AncestorAccessContext> {
    verifier.revalidate()?;
    let owner = current_user()?;
    let sam = machine_domain()?;
    group.revalidate()?;
    let mut observations = Vec::new();
    for file in inputs.files {
        let id = object_id(&file)?;
        let descriptor = hash(&security(file.as_raw_handle(), 1 | 4)?);
        if !observations.iter().any(|o: &Observation| o.id == id) {
            observations.push(Observation {
                file,
                id,
                descriptor,
            })
        }
    }
    let mut context = AncestorAccessContext {
        owner,
        sam: Some(sam),
        observations,
        group: Some(group),
        issuer: None,
        verifier: Some(verifier),
    };
    let mut needs_issuer = false;
    for o in &context.observations {
        let mut sd = security(o.file.as_raw_handle(), 1 | 4)?;
        for ace in entries(&mut sd)? {
            if !ace.deny
                && ace.mask & DIRECTORY_ENTRY_RIGHTS != 0
                && !ace.sid.capability_side()
                && ace
                    .sid
                    .domain()
                    .is_ok_and(|d| context.sam.as_ref().is_some_and(|sam| d != *sam))
            {
                needs_issuer = true;
            }
        }
    }
    let marker = context.verifier.as_ref().unwrap().registration_file();
    let mut marker_sd = security(marker.as_raw_handle(), 1 | 4)?;
    for ace in entries(&mut marker_sd)? {
        if !ace.deny
            && ace.mask & IntegrityPurpose::RegistrationContent.rights() != 0
            && !ace.sid.capability_side()
            && ace
                .sid
                .domain()
                .is_ok_and(|d| context.sam.as_ref().is_some_and(|sam| d != *sam))
        {
            needs_issuer = true;
        }
    }
    if needs_issuer {
        context.issuer = Some(IssuerSnapshot::observe()?);
    }
    let marker = context.verifier.as_ref().unwrap().registration_file();
    assess(
        marker,
        &context,
        false,
        IntegrityPurpose::RegistrationContent,
    )?;
    for o in &context.observations {
        assess(&o.file, &context, true, IntegrityPurpose::DirectoryEntry)?;
    }
    context.revalidate()?;
    Ok(context)
}
impl AncestorAccessContext {
    pub(super) fn applies(&self, file: &File) -> Result<bool> {
        let id = object_id(file)?;
        Ok(self.observations.iter().any(|o| o.id == id))
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        if current_user()? != self.owner {
            return Err("UnsupportedActorContext: operation owner changed".into());
        }
        if let Some(sam) = &self.sam {
            if machine_domain()? != *sam {
                return Err("UnsupportedActorContext: operation machine changed".into());
            }
        }
        if let Some(v) = &self.verifier {
            v.revalidate()?;
        }
        if let Some(g) = &self.group {
            g.revalidate()?;
        }
        if let Some(old) = &self.issuer {
            if IssuerSnapshot::observe()? != *old {
                return Err("UnsupportedActorContext: issuer observation changed".into());
            }
        }
        for o in &self.observations {
            case_insensitive(&o.file)?;
            if information(&o.file)?.attributes & REPARSE != 0
                || object_id(&o.file)? != o.id
                || hash(&security(o.file.as_raw_handle(), 1 | 4)?) != o.descriptor
            {
                return Err(
                    "UnsupportedActorContext: selected ancestor identity/descriptor changed".into(),
                );
            }
        }
        Ok(())
    }
    pub(super) fn check(&self, file: &File, system_ancestor: bool) -> Result<()> {
        let id = object_id(file)?;
        let sd = hash(&security(file.as_raw_handle(), 1 | 4)?);
        if !self
            .observations
            .iter()
            .any(|o| o.id == id && o.descriptor == sd)
        {
            return Err("UnsupportedActorContext: ancestor not in held operation context".into());
        }
        assess(
            file,
            self,
            system_ancestor,
            IntegrityPurpose::DirectoryEntry,
        )
    }
    /// Actor qualification for a separately native-pinned nonsecret file plan.
    /// The file is NOT an ancestor observation or an authority source.
    pub(super) fn check_nonsecret_metadata_file(&self, file: &File) -> Result<()> {
        self.revalidate()?;
        assess(
            file,
            self,
            false,
            IntegrityPurpose::NonsecretMetadataContent,
        )
    }
}
pub(super) fn check_empty_nonsecret_metadata_file(file: &File) -> Result<()> {
    let context = AncestorAccessContext {
        owner: current_user()?,
        sam: None,
        observations: Vec::new(),
        group: None,
        issuer: None,
        verifier: None,
    };
    assess(
        file,
        &context,
        false,
        IntegrityPurpose::NonsecretMetadataContent,
    )
}
pub(super) fn check_empty(file: &File, system: bool) -> Result<()> {
    let context = AncestorAccessContext {
        owner: current_user()?,
        sam: None,
        observations: Vec::new(),
        group: None,
        issuer: None,
        verifier: None,
    };
    assess(file, &context, system, IntegrityPurpose::DirectoryEntry)
}
fn trusted(sid: &Sid, context: &AncestorAccessContext, system: bool) -> Result<bool> {
    if *sid == context.owner || sid.well_known(22) || sid.well_known(26) {
        return Ok(true);
    }
    if system {
        let bytes = trusted_installer_sid()?;
        if unsafe { Sid::copy(bytes.as_ptr().cast()) }? == *sid {
            return Ok(true);
        }
    }
    Ok(context
        .group
        .as_ref()
        .is_some_and(|g| g.sid == *sid || g.roles.contains(sid)))
}
fn denied_for_unknown(aces: &[Ace], sid: &Sid, purpose: IntegrityPurpose) -> u32 {
    // Closed ordinary ACE class. These deny trustees necessarily apply to an
    // ordinary authenticated actor; no invented token/group list is used.
    let mut remaining = purpose.rights();
    let mut granted = 0;
    for ace in aces {
        let applies = ace.sid == *sid || ace.sid.well_known(1) || ace.sid.well_known(17);
        if !applies {
            continue;
        }
        let bits = ace.mask & remaining;
        if !ace.deny {
            granted |= bits;
        }
        remaining &= !bits;
    }
    granted
}
fn assess(
    file: &File,
    context: &AncestorAccessContext,
    system: bool,
    purpose: IntegrityPurpose,
) -> Result<()> {
    let mut sd = security(file.as_raw_handle(), 1 | 4)?;
    #[cfg(test)]
    let trace_before = TEST_REJECTIONS.with(|rows| rows.borrow().len());
    let result = assess_descriptor(&mut sd, context, system, purpose);
    #[cfg(test)]
    if result.is_err() {
        TEST_REJECTIONS.with(|rows| {
            let mut rows = rows.borrow_mut();
            for row in rows.iter_mut().skip(trace_before) {
                row["nativeId"] = match object_id(file) {
                    Ok(id) => serde_json::json!(id),
                    Err(error) => serde_json::json!({"unavailable":error}),
                };
                row["privateNativeLocatorUtf16"] = match final_path(file) {
                    Ok(path) => serde_json::json!(path),
                    Err(error) => serde_json::json!({"unavailable":error}),
                };
            }
        });
    }
    result
}
fn assess_descriptor(
    sd: &mut [u8],
    context: &AncestorAccessContext,
    system: bool,
    purpose: IntegrityPurpose,
) -> Result<()> {
    let owner = descriptor_owner(sd)?;
    if matches!(purpose, IntegrityPurpose::RegistrationContent) {
        if !owner.well_known(22) && !owner.well_known(26) {
            return Err(
                "UnsupportedActorContext: registration owner provenance unsupported".into(),
            );
        }
    } else if matches!(purpose, IntegrityPurpose::NonsecretMetadataContent) {
        if owner != context.owner && !owner.well_known(22) && !owner.well_known(26) {
            return Err("UnsupportedActorContext: nonsecret metadata owner is not current/SYSTEM/Administrators".into());
        }
    } else if !trusted(&owner, context, system)? {
        return Err("UnsupportedActorContext: independent ancestor owner".into());
    }
    let aces = entries(sd)?;
    let mut capability_grants = false;
    for ace in &aces {
        if ace.deny || ace.mask & purpose.rights() == 0 {
            continue;
        }
        if ace.sid.capability_side() {
            capability_grants = true;
            continue;
        }
        if trusted(&ace.sid, context, system)? {
            continue;
        }
        let effective = denied_for_unknown(&aces, &ace.sid, purpose);
        if effective == 0 {
            continue;
        }
        if context
            .issuer
            .as_ref()
            .is_some_and(|i| i.no_current_issuer(&ace.sid))
        {
            continue;
        }
        #[cfg(test)]
        TEST_REJECTIONS.with(|rows|rows.borrow_mut().push(serde_json::json!({
            "kind":"test-only-first-assessor-rejection","purpose":match purpose {
                IntegrityPurpose::DirectoryEntry=>"directory-entry",
                IntegrityPurpose::RegistrationContent=>"registration-content",
                IntegrityPurpose::NonsecretMetadataContent=>"nonsecret-metadata-content"},
            "trusteeClass":if ace.sid.well_known(1) {"everyone"} else if ace.sid.well_known(17) {"authenticated-users"}
                else if ace.sid.well_known(27) {"builtin-users"} else {"other-normal-account-or-group"},
            "aceMask":ace.mask,"effectiveGrantedMutationMask":effective,"requiredMutationMask":purpose.rights()
        })));
        return Err(
            "UnsupportedActorContext: independent or unqualified normal-side replacement grant"
                .into(),
        );
    }
    // Package/capability grants are not standalone actors. Their normal-user
    // side was completely confined above; intersection cannot add a new user.
    let _constrained_capability_intersection = capability_grants;
    Ok(())
}

#[cfg(test)]
thread_local! { static TEST_REJECTIONS:std::cell::RefCell<Vec<serde_json::Value>>=const{std::cell::RefCell::new(Vec::new())}; }
#[cfg(test)]
pub(super) fn take_rejection_provenance() -> Vec<serde_json::Value> {
    TEST_REJECTIONS.with(|rows| std::mem::take(&mut *rows.borrow_mut()))
}
pub(crate) fn owner_machine_wire() -> Result<(String, String)> {
    Ok((current_user()?.text()?, machine_domain()?.text()?))
}

#[cfg(test)]
#[path = "ancestor_context_tests.rs"]
mod tests;
