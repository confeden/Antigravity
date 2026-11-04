//! Background program file admission and receiving, without task or ASAR authority.
use super::context_native::{current_user, descriptor_owner, entries, Ace, Sid};
use super::*;

const BACKGROUND_PROGRAM_LEAF: &str = "ag_dns.exe";
/// Diagnostic basename only; it confers no process or executable authority.
pub(crate) fn background_process_name() -> &'static str {
    BACKGROUND_PROGRAM_LEAF
}

/// Locations select no authority. Managed receiving remains a separate,
/// context-bound operation; the legacy location has only a read-only receiver.
pub(crate) struct BackgroundLocations {
    managed_root: PathBuf,
    managed_directory: PathBuf,
    managed_program: PathBuf,
    legacy_program: PathBuf,
}
impl BackgroundLocations {
    fn from_roots(managed_root: PathBuf, legacy_root: PathBuf) -> Result<Self> {
        validate_path(&managed_root)?;
        validate_path(&legacy_root)?;
        let product = super::user_state_location::WINDOWS_STATE_LEAF;
        let managed_directory = managed_root.join(product);
        let managed_program = managed_directory.join(BACKGROUND_PROGRAM_LEAF);
        let legacy_program = legacy_root.join(product).join(BACKGROUND_PROGRAM_LEAF);
        validate_path(&managed_program)?;
        validate_path(&legacy_program)?;
        Ok(Self {
            managed_root,
            managed_directory,
            managed_program,
            legacy_program,
        })
    }
    pub(crate) fn managed_root(&self) -> &Path {
        &self.managed_root
    }
    pub(crate) fn managed_directory(&self) -> &Path {
        &self.managed_directory
    }
    pub(crate) fn managed_program(&self) -> &Path {
        &self.managed_program
    }
    pub(crate) fn legacy_program(&self) -> &Path {
        &self.legacy_program
    }
}
pub(crate) fn background_locations() -> Result<BackgroundLocations> {
    BackgroundLocations::from_roots(
        native_known_folder(NativeKnownFolder::ProgramFiles)?,
        native_known_folder(NativeKnownFolder::ProgramData)?,
    )
}

/// A closed read-only association input, never a managed namespace/Stop grant.
/// File and ancestor handles deny deletion for this capability's lifetime.
pub(crate) struct LegacyBackgroundInput {
    pin: CheckedPath,
    preimage: SourceSnapshot,
    ancestor_ids: Vec<ObjectId>,
}
impl LegacyBackgroundInput {
    pub(crate) fn path(&self) -> &Path {
        self.pin.as_path()
    }
    pub(crate) fn digest(&self) -> &str {
        &self.preimage.digest
    }
    pub(crate) fn native_id(&self) -> &ObjectId {
        &self.pin.object
    }
    pub(crate) fn evidence(&self) -> serde_json::Value {
        serde_json::json!({"schema":1,"kind":"legacy-background-read-only-association",
            "nativeId":self.pin.object,"ancestorNativeIds":self.ancestor_ids,
            "preimage":snapshot_evidence(&self.preimage),
            "authority":"read-only association; no namespace/write/execute/restart/Stop authority"})
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.pin.recheck()?;
        let fresh = parents(self.pin.as_path())?;
        if fresh.len() != self.ancestor_ids.len() {
            return Err("legacy background ancestor identity count changed".into());
        }
        for ((held, fresh), expected) in self
            .pin
            ._ancestors
            .iter()
            .zip(&fresh)
            .zip(&self.ancestor_ids)
        {
            if object_id(held)? != *expected || object_id(fresh)? != *expected {
                return Err("legacy background ancestor identity changed".into());
            }
        }
        file_integrity(&self.pin.file)?;
        let mut file = self
            .pin
            .file
            .try_clone()
            .map_err(|error| io("legacy background read", error))?;
        if !same_snapshot(
            &read_checked(&mut file, self.pin.as_path())?,
            &self.preimage,
        ) {
            return Err("legacy background bytes or full file metadata changed".into());
        }
        Ok(())
    }
}
pub(crate) fn legacy_background_input(
    locations: &BackgroundLocations,
) -> Result<Option<LegacyBackgroundInput>> {
    let path = locations.legacy_program();
    match fs::symlink_metadata(NativeFsPath::from_path(path)?.as_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Observe real absence through a structurally checked existing
            // ancestor. No fake future identity or namespace-integrity credit.
            let parent = NativeDirectoryInput::capture(
                path.parent().ok_or("legacy program parent absent")?,
            )?;
            parent.anchor.recheck()?;
            absent(path)?;
            return Ok(None);
        }
        Err(error) => return Err(io("legacy background presence", error)),
        Ok(_) => {}
    }
    let pin = CheckedPath::open(path, PathKind::File, PathPurpose::Review)?;
    file_integrity(&pin.file)?;
    let ancestor_ids = pin
        ._ancestors
        .iter()
        .map(object_id)
        .collect::<Result<Vec<_>>>()?;
    let mut file = pin
        .file
        .try_clone()
        .map_err(|error| io("legacy background capture", error))?;
    let preimage = read_checked(&mut file, pin.as_path())?;
    let input = LegacyBackgroundInput {
        pin,
        preimage,
        ancestor_ids,
    };
    input.revalidate()?;
    Ok(Some(input))
}

/// Structural existing namespace pins only: no ACL credit, lease or effects.
pub(crate) struct BackgroundInputs {
    managed_root: NativeDirectoryInput,
    program_parent: NativeDirectoryInput,
    source: Option<BackgroundSourceInput>,
    diagnostic_source: Option<DiagnosticSourceInput>,
    diagnostic: DiagnosticInputs,
}
struct DiagnosticSourceInput {
    parent: NativeDirectoryInput,
    pin: CheckedPath,
    descriptor: String,
}
struct BackgroundSourceInput {
    image: std::sync::Arc<crate::windows_coordinator::process_identity::CurrentImage>,
    snapshot: SourceSnapshot,
    ancestors: Vec<(ObjectId, String)>,
}
impl BackgroundSourceInput {
    fn capture(image: std::sync::Arc<crate::windows_coordinator::process_identity::CurrentImage>) -> Result<Self> {
        image.recheck()?;
        let pin = image.file();
        let ancestors = pin._ancestors.iter().map(|file| Ok((object_id(file)?, hash(&security(file.as_raw_handle(), 1 | 4)?))))
            .collect::<Result<Vec<_>>>()?;
        let mut file = pin.file.try_clone().map_err(|e| io("background source capture", e))?;
        let snapshot = read_checked(&mut file, pin.as_path())?;
        let captured = Self { image, snapshot, ancestors };
        #[cfg(test)]
        let validation = if TEST_SOURCE_CAPTURE_FAILURE.with(|value| value.replace(false)) {
            Err("synthetic source revalidation failure".to_owned())
        } else { captured.validate_source() };
        #[cfg(not(test))]
        let validation = captured.validate_source();
        if let Err(cause) = validation {
            return Err(format!("{cause}; rejected source observation: {}", captured.summary()));
        }
        Ok(captured)
    }
    fn summary(&self) -> String {
        let metadata = json(&self.snapshot.identity).map(|bytes| hash(&bytes))
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        format!("nativeId={:?}, sha256={}, bytes={}, metadataSha256={metadata}",
            self.image.file().native_id(), self.snapshot.digest, self.snapshot.bytes.len())
    }
    fn revalidate(&self) -> Result<()> {
        self.validate_source().map_err(|cause| format!("{cause}; rejected source observation: {}", self.summary()))
    }
    fn validate_source(&self) -> Result<()> {
        self.image.recheck()?;
        let pin = self.image.file();
        let fresh = parents(pin.as_path())?;
        if fresh.len() != self.ancestors.len() { return Err("background source ancestor count changed".into()); }
        for ((held, new), (id, descriptor)) in pin._ancestors.iter().zip(&fresh).zip(&self.ancestors) {
            if object_id(held)? != *id || object_id(new)? != *id
                || hash(&security(held.as_raw_handle(), 1 | 4)?) != *descriptor
                || hash(&security(new.as_raw_handle(), 1 | 4)?) != *descriptor {
                return Err("background source ancestor identity/security changed".into());
            }
        }
        let mut file = pin.file.try_clone().map_err(|e| io("background source recheck", e))?;
        if !same_snapshot(&read_checked(&mut file, pin.as_path())?, &self.snapshot) {
            return Err("background source snapshot changed".into());
        }
        Ok(())
    }
}
#[cfg(test)]
thread_local! { static TEST_SOURCE_CAPTURE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn fail_next_source_capture_revalidation() {
    TEST_SOURCE_CAPTURE_FAILURE.with(|value| value.set(true));
}
pub(crate) fn background_inputs(
    managed_root: &Path,
    program_parent: &Path,
    source: Option<&Path>,
    diagnostic_parent: &Path,
) -> Result<BackgroundInputs> {
    #[cfg(not(test))]
    if source.is_some() { return Err("background source selection requires the retained current image".into()); }
    let managed_root = NativeDirectoryInput::capture(managed_root)?;
    if !managed_root.is_existing() {
        return Err("background lease root must already exist".into());
    }
    let diagnostic_source = source
        .map(|path| -> Result<DiagnosticSourceInput> {
            let pin = CheckedPath::open(path, PathKind::File, PathPurpose::ReplaceSource)?;
            let descriptor = hash(&security(pin.file.as_raw_handle(), 1 | 4)?);
            let parent =
                NativeDirectoryInput::capture(pin.path.parent().ok_or("source parent absent")?)?;
            Ok(DiagnosticSourceInput {
                parent,
                pin,
                descriptor,
            })
        })
        .transpose()?;
    Ok(BackgroundInputs {
        managed_root,
        program_parent: NativeDirectoryInput::capture(program_parent)?,
        source: None,
        diagnostic_source,
        diagnostic: diagnostic_inputs(diagnostic_parent)?,
    })
}
pub(crate) fn background_inputs_selected(
    managed_root: &Path, program_parent: &Path,
    image: std::sync::Arc<crate::windows_coordinator::process_identity::CurrentImage>, diagnostic_parent: &Path,
) -> Result<BackgroundInputs> {
    let mut inputs = background_inputs(managed_root, program_parent, None, diagnostic_parent)?;
    inputs.source = Some(BackgroundSourceInput::capture(image)?);
    Ok(inputs)
}
impl BackgroundInputs {
    pub(crate) fn source_observation(&self) -> Result<String> {
        Ok(self.source.as_ref().ok_or("background source selection not received")?.summary())
    }
    fn files(&self) -> impl Iterator<Item = &File> {
        self.managed_root
            .files()
            .chain(self.program_parent.files())
            .chain(self.diagnostic_source.iter().flat_map(|source| source.parent.files()))
            .chain(self.diagnostic.files())
    }
    pub(crate) fn ancestor_inputs(&self) -> Result<AncestorInputs> {
        Ok(AncestorInputs::new(
            self.files()
                .map(|file| {
                    file.try_clone()
                        .map_err(|error| io("retain background namespace input", error))
                })
                .collect::<Result<Vec<_>>>()?,
        ))
    }
    fn recheck(&self, before_effects: bool) -> Result<()> {
        self.managed_root.recheck(before_effects)?;
        self.program_parent.recheck(before_effects)?;
        self.diagnostic.recheck(before_effects)?;
        if let Some(source) = &self.source {
            source.revalidate()?;
        }
        if let Some(source) = &self.diagnostic_source {
            source.parent.recheck(before_effects)?;
            source.pin.recheck()?;
            if hash(&security(source.pin.file.as_raw_handle(), 1 | 4)?) != source.descriptor {
                return Err("background source input descriptor changed".into());
            }
        }
        Ok(())
    }
    fn receive_context(
        &self,
        context: Option<&AncestorAccessContext>,
        before_effects: bool,
    ) -> Result<()> {
        self.recheck(before_effects)?;
        if let Some(context) = context {
            context.revalidate()?;
        }
        for file in self.files() {
            if let Some(context) = context {
                if !context.applies(file)? {
                    return Err(
                        "background context does not cover actual captured namespace".into(),
                    );
                }
            }
            check_context_ancestor(file, context)?;
        }
        match &self.diagnostic_source {
            Some(source) => file_integrity(&source.pin.file),
            None => Ok(()),
        }
    }
}

/// The background owner retains this existing-parent lease across role
/// qualification, retirement, file replacement and wanted-role restart.
pub(crate) struct BackgroundLease {
    _lease: Lease,
    inputs: BackgroundInputs,
    context: Option<AncestorAccessContext>,
}

pub(crate) fn background_lease(
    inputs: BackgroundInputs,
    context: Option<AncestorAccessContext>,
) -> Result<BackgroundLease> {
    inputs.receive_context(context.as_ref(), true)?;
    let lease = Lease::acquire(&inputs.managed_root.anchor, "background_program")?;
    inputs.receive_context(context.as_ref(), true)?;
    Ok(BackgroundLease {
        _lease: lease,
        inputs,
        context,
    })
}
impl BackgroundLease {
    pub(crate) fn context(&self) -> Option<&AncestorAccessContext> {
        self.context.as_ref()
    }
    fn revalidate(&self) -> Result<()> {
        self.inputs.receive_context(self.context(), false)
    }
    pub(crate) fn source_capture(&self) -> Result<(ObjectId, &[u8])> {
        let source = self.inputs.source.as_ref().ok_or("background source selection not received")?;
        source.revalidate()?;
        Ok((source.image.file().native_id(), &source.snapshot.bytes))
    }
    pub(crate) fn source_bytes(&self) -> Result<&[u8]> {
        let source = self.inputs.source.as_ref().ok_or("background source selection not received")?;
        source.revalidate()?;
        Ok(&source.snapshot.bytes)
    }
}

fn trusted_file_principal(sid: &Sid, owner: &Sid) -> bool {
    sid == owner || sid.well_known(22) || sid.well_known(26)
}

/// File mutation, unlike directory-entry mutation, includes WRITE_DATA and
/// APPEND_DATA: DELETE|WRITE_DAC|WRITE_OWNER|WRITE_ATTRIBUTES|WRITE_EA|DATA|APPEND.
const FILE_MUTATION_RIGHTS: u32 = 0x000d_0116;

fn granted_mutation(aces: &[Ace], principal: &Sid) -> u32 {
    let mut remaining = FILE_MUTATION_RIGHTS;
    let mut granted = 0;
    for ace in aces {
        if ace.sid != *principal && !ace.sid.well_known(1) && !ace.sid.well_known(17) {
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

fn file_descriptor_integrity(sd: &mut [u8]) -> Result<()> {
    let user = current_user()?;
    if !trusted_file_principal(&descriptor_owner(sd)?, &user) {
        return Err(
            "background program owner is not current user, SYSTEM or Administrators".into(),
        );
    }
    let aces = entries(sd)?;
    for ace in &aces {
        if ace.deny
            || ace.mask & FILE_MUTATION_RIGHTS == 0
            || trusted_file_principal(&ace.sid, &user)
            || ace.sid.capability_side()
        {
            continue;
        }
        if granted_mutation(&aces, &ace.sid) != 0 {
            return Err("background program ACL grants foreign file mutation".into());
        }
    }
    // Capability-side grants cannot introduce another ordinary actor after
    // every normal-side file mutation grant has been confined above.
    Ok(())
}

fn file_integrity(file: &File) -> Result<()> {
    identity(file)?;
    file_descriptor_integrity(&mut security(file.as_raw_handle(), 1 | 4)?)
}

fn ancestor_guards(pin: &CheckedPath, context: Option<&AncestorAccessContext>) -> Result<()> {
    for ancestor in &pin._ancestors {
        check_context_ancestor(ancestor, context)?;
    }
    Ok(())
}

fn receive_path(
    path: &Path,
    kind: PathKind,
    context: Option<&AncestorAccessContext>,
) -> Result<CheckedPath> {
    let purpose = match kind {
        PathKind::File => PathPurpose::ReplaceSource,
        PathKind::Directory => PathPurpose::Review,
    };
    let pin = CheckedPath::open(path, kind, purpose)?;
    ancestor_guards(&pin, context)?;
    match kind {
        PathKind::File => file_integrity(&pin.file)?,
        PathKind::Directory => check_context_ancestor(&pin.file, context)?,
    }
    Ok(pin)
}
pub(crate) fn checked_background_path(
    lease: &BackgroundLease,
    path: &Path,
    kind: PathKind,
) -> Result<CheckedPath> {
    lease.revalidate()?;
    receive_path(path, kind, lease.context())
}

pub(crate) fn create_background_directory(lease: &BackgroundLease, path: &Path) -> Result<()> {
    let parent = checked_background_path(
        lease,
        path.parent().ok_or("background directory parent absent")?,
        PathKind::Directory,
    )?;
    create_private_dir(path)?;
    parent.recheck()?;
    Ok(())
}

pub(crate) fn create_background_executable(lease: &BackgroundLease, path: &Path) -> Result<File> {
    lease.source_bytes()?;
    let parent = checked_background_path(
        lease,
        path.parent().ok_or("background program parent absent")?,
        PathKind::Directory,
    )?;
    let file = create_owned_file(path)?;
    parent.recheck().map_err(|error| {
        format!(
            "background file created at {}; parent receiving failed: {error}; preserve it",
            path.display()
        )
    })?;
    Ok(file)
}

pub(crate) struct BackgroundReplacementReceiving {
    pub(crate) program: CheckedPath,
    pub(crate) evidence: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct BackgroundReplacementFailure {
    pub(crate) phase: &'static str,
    pub(crate) cause: String,
    /// None: no call; false: native failure/possible partial effects; true:
    /// native success followed by failure while receiving its actual effect.
    pub(crate) replace_result: Option<bool>,
    pub(crate) evidence: serde_json::Value,
}
impl std::fmt::Display for BackgroundReplacementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "background replacement {}: {} (native {:?}; retained evidence)",
            self.phase, self.cause, self.replace_result
        )
    }
}
impl std::error::Error for BackgroundReplacementFailure {}

fn replacement_evidence(
    current: &CheckedPath,
    source: Option<&CheckedPath>,
    id: &Option<String>,
    before: &Option<SourceSnapshot>,
    input: &Option<SourceSnapshot>,
    paths: &Option<InstallPaths>,
    called: Option<bool>,
    phase: &str,
) -> serde_json::Value {
    serde_json::json!({"schema":1,"kind":"background-program-native-replacement",
        "operationId":id,"phase":phase,"replaceResult":called,
        "expectedProgramNativeId":current.object,"sourceNativeId":source.map(|pin| &pin.object),
        "expectedPreimage":before.as_ref().map(snapshot_evidence),
        "validatedSource":input.as_ref().map(snapshot_evidence),
        "program":path_evidence(&current.path),"programObservation":observe(&current.path),
        "work":paths.as_ref().map(|paths|serde_json::json!({
            "staged":path_evidence(&paths.staged),"stagedObservation":observe(&paths.staged),
            "original":path_evidence(&paths.original_backup),"originalObservation":observe(&paths.original_backup),
            "displaced":path_evidence(&paths.displaced_backup),"displacedObservation":observe(&paths.displaced_backup)}))})
}

/// Caller retains BackgroundLease and qualified task retirement throughout.
/// This received pin is replacement-compatible from initial admission. Other
/// deny-DELETE pins must be retired by their owner; a borrowed File is never
/// closed/relabelled here, and no atomic CAS against same-user writers is claimed.
pub(crate) fn background_replace_program(
    lease: &BackgroundLease,
    current: &CheckedPath,
) -> std::result::Result<BackgroundReplacementReceiving, BackgroundReplacementFailure> {
    let source = lease.inputs.source.as_ref().map(|input| input.image.file());
    let mut phase = "preflight";
    let mut called = None;
    let mut id = None;
    let mut paths = None;
    let mut before = None;
    let mut input = None;
    let result = (|| -> Result<CheckedPath> {
        lease.revalidate()?;
        let captured = lease.inputs.source.as_ref().ok_or("background source selection not received")?;
        let source = source.ok_or("background source selection not received")?;
        if !matches!(current.purpose, PathPurpose::ReplaceSource) {
            return Err("background program pin is not replacement-compatible; retain caller guards and re-receive it".into());
        }
        current.recheck()?;
        source.recheck()?;
        ancestor_guards(current, lease.context())?;
        file_integrity(&current.file)?;
        if current.object == source.object {
            return Err("background source and target are the same native file".into());
        }
        let mut old_file = current
            .file
            .try_clone()
            .map_err(|error| io("background preimage clone", error))?;
        let old = read_checked(&mut old_file, &current.path)?;
        let new = captured.snapshot.clone();
        before = Some(old);
        input = Some(new);
        let parent = checked_background_path(
            lease,
            current
                .path
                .parent()
                .ok_or("background program parent absent")?,
            PathKind::Directory,
        )?;
        let operation = unique_id()?;
        let prefix = format!("background-replace-{operation}");
        let work = InstallPaths {
            staged: parent.path.join(format!("{prefix}.staged")),
            original_backup: parent.path.join(format!("{prefix}.original")),
            displaced_backup: parent.path.join(format!("{prefix}.displaced")),
        };
        id = Some(operation);
        paths = Some(work);
        let work = paths.as_ref().ok_or("background work binding absent")?;
        for path in [&work.staged, &work.original_backup, &work.displaced_backup] {
            absent(path)?;
        }
        let old = before.as_ref().ok_or("background preimage absent")?;
        let new = input.as_ref().ok_or("background source absent")?;
        phase = "original-retention";
        let original = create_replacement_file(&work.original_backup, &old.bytes, &old.identity)?;
        if original.bytes != old.bytes || original.digest != old.digest {
            return Err("background retained original readback differs".into());
        }
        phase = "stage";
        let staged = create_replacement_file(&work.staged, &new.bytes, &old.identity)?;
        let staged_id = object_id(&open_regular(&work.staged, READ | DELETE)?)?;
        phase = "publish-precheck";
        parent.recheck()?;
        lease.revalidate()?;
        ancestor_guards(&parent, lease.context())?;
        current.recheck()?;
        source.recheck()?;
        file_integrity(&current.file)?;
        captured.revalidate()?;
        if !same_snapshot(&read_path(&current.path, READ | DELETE)?, old)
            || object_id(&open_regular(&current.path, READ | DELETE)?)? != current.object
            || !same_snapshot(&read_path(&work.staged, READ | DELETE)?, &staged)
        {
            return Err(
                "background expected source/target/stage changed before replacement".into(),
            );
        }
        absent(&work.displaced_backup)?;
        phase = "replace";
        replace_native_file(
            &current.path,
            &work.staged,
            &work.displaced_backup,
            &mut called,
        )?;
        phase = "metadata-preservation";
        restore_replacement_security(
            &current.path,
            &staged,
            &staged_id,
            &current.object,
            old,
            &work.displaced_backup,
            &old.identity.security_descriptor,
            &mut || {
                parent.recheck()?;
                lease.revalidate()?;
                ancestor_guards(&parent, lease.context())
            },
        )?;
        phase = "receiving";
        let program = checked_background_path(lease, &current.path, PathKind::File)?;
        let post = read_path(&current.path, READ | DELETE)?;
        let displaced = read_path(&work.displaced_backup, READ | DELETE)?;
        let retained = read_path(&work.original_backup, READ)?;
        if program.object != staged_id
            || post.bytes != new.bytes
            || post.digest != new.digest
            || post.identity.volume != old.identity.volume
            || post.identity.creation != old.identity.creation
            || post.identity.write != old.identity.write
            || post.identity.attributes != old.identity.attributes
            || post.identity.security_descriptor != old.identity.security_descriptor
            || object_id(&open_regular(&work.displaced_backup, READ | DELETE)?)? != current.object
            || !same_snapshot(&displaced, old)
            || !same_snapshot(&retained, &original)
        {
            return Err(
                "background target/backup full identity, content or metadata receiving differs"
                    .into(),
            );
        }
        absent(&work.staged)?;
        #[cfg(test)]
        if TEST_RECEIVING_FAILURE.with(|value| value.replace(false)) {
            return Err(
                "injected failure after actual replacement and full native receiving".into(),
            );
        }
        parent.recheck()?;
        Ok(program)
    })();
    let evidence =
        replacement_evidence(current, source, &id, &before, &input, &paths, called, phase);
    match result {
        Ok(program) => Ok(BackgroundReplacementReceiving { program, evidence }),
        Err(cause) => Err(BackgroundReplacementFailure {
            phase,
            cause,
            replace_result: called,
            evidence,
        }),
    }
}

#[cfg(test)]
thread_local! { static TEST_RECEIVING_FAILURE:std::cell::Cell<bool>=const{std::cell::Cell::new(false)}; }

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(access: &str) -> Vec<u8> {
        let user = current_user().unwrap().text().unwrap();
        let sddl = format!("O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY)(A;;FA;;;BA){access}");
        let text = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut raw = std::ptr::null_mut();
        let mut size = 0;
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut raw,
                    &mut size,
                )
            },
            0
        );
        let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), size as usize) }.to_vec();
        unsafe {
            LocalFree(raw);
        }
        bytes
    }

    #[test]
    fn file_integrity_accepts_public_rx_but_rejects_foreign_data_and_append() {
        assert!(file_descriptor_integrity(&mut descriptor("(A;;GRGX;;;WD)")).is_ok());
        for right in ["0x2", "0x4"] {
            assert!(
                file_descriptor_integrity(&mut descriptor(&format!("(A;;{right};;;WD)"))).is_err()
            );
        }
        assert!(file_descriptor_integrity(&mut descriptor("(D;;GW;;;WD)(A;;GW;;;WD)")).is_ok());
    }

    #[test]
    #[ignore = "explicit owned private root; synthetic source and held read capability only"]
    fn selected_source_capture_denies_mutation_and_rechecks_snapshot() {
        let root = allocate_owned_root("background-source-read");
        let source = root.path.join("source.exe");
        write_private(&source, b"MZ synthetic source; never executed").unwrap();
        let image = std::sync::Arc::new(crate::windows_coordinator::process_identity::CurrentImage::synthetic(&source).unwrap());
        let mut capture = BackgroundSourceInput::capture(image).unwrap();
        assert_eq!(capture.snapshot.bytes, b"MZ synthetic source; never executed");
        assert!(OpenOptions::new().write(true).open(&source).is_err());
        assert!(OpenOptions::new().append(true).open(&source).is_err());
        assert!(fs::rename(&source, root.path.join("renamed.exe")).is_err());
        assert!(fs::remove_file(&source).is_err());
        capture.revalidate().unwrap();
        let baseline = capture.snapshot.clone();
        capture.snapshot.digest = "0".repeat(64);
        assert!(capture.revalidate().is_err());
        capture.snapshot = baseline.clone();
        capture.snapshot.bytes[0] ^= 1;
        assert!(capture.revalidate().is_err());
        capture.snapshot = baseline.clone();
        capture.snapshot.identity.index ^= 1;
        assert!(capture.revalidate().is_err());
        capture.snapshot = baseline.clone();
        capture.snapshot.identity.security_descriptor.push(0);
        assert!(capture.revalidate().is_err());
        capture.snapshot = baseline;
        let original = capture.ancestors[0].0.clone();
        capture.ancestors[0].0.file[0] ^= 1;
        assert!(capture.revalidate().is_err());
        capture.ancestors[0].0 = original;
        capture.ancestors[0].1.push('0');
        assert!(capture.revalidate().is_err());
    }

    #[test]
    #[ignore = "explicit owned private root; source/managed role overlap is synthetic"]
    fn source_projection_preserves_overlapping_mutation_roles() {
        let root = allocate_owned_root("background-source-overlap");
        let source = root.path.join("source.exe");
        write_private(&source, b"MZ synthetic source; never executed").unwrap();
        let image = std::sync::Arc::new(crate::windows_coordinator::process_identity::CurrentImage::synthetic(&source).unwrap());
        let inputs = background_inputs_selected(&root.path, &root.path, image, &root.path).unwrap();
        let root_id = root.object.clone();
        assert!(inputs.files().any(|file| object_id(file).is_ok_and(|id| id == root_id)));
        assert!(inputs.source.is_some());
        assert!(inputs.diagnostic_source.is_none());
    }

    #[test]
    #[ignore = "explicit owned private root; receives actual current test image without executing or copying it"]
    fn selected_source_uses_the_actual_held_current_image() {
        let root = allocate_owned_root("background-current-image");
        let image = std::sync::Arc::new(crate::windows_coordinator::process_identity::CurrentImage::capture().unwrap());
        let expected_id = image.native_id();
        let inputs = background_inputs_selected(&root.path, &root.path, image.clone(), &root.path).unwrap();
        let lease = background_lease(inputs, None).unwrap();
        let (actual_id, bytes) = lease.source_capture().unwrap();
        assert_eq!(actual_id, expected_id);
        assert!(!bytes.is_empty());
        image.recheck().unwrap();
    }

    #[test]
    #[ignore = "explicit owned private root; source and managed ACL variations are synthetic"]
    fn source_only_broad_directory_is_not_a_managed_grant() {
        let root = allocate_owned_root("background-source-purpose");
        let source_dir = root.path.join("source"); let managed = root.path.join("managed");
        let diagnostic = root.path.join("diagnostic");
        create_private_dir(&source_dir).unwrap(); create_private_dir(&managed).unwrap(); create_private_dir(&diagnostic).unwrap();
        let source = source_dir.join("source.exe");
        write_private(&source, b"MZ synthetic source; never executed").unwrap();
        set_fixture_acl(&source_dir, "(A;;FA;;;AU)");
        let image = std::sync::Arc::new(crate::windows_coordinator::process_identity::CurrentImage::synthetic(&source).unwrap());
        let selected = background_inputs_selected(&managed, &managed, image.clone(), &diagnostic).unwrap();
        selected.receive_context(None, true).unwrap();
        let overlap = background_inputs_selected(&source_dir, &source_dir, image, &diagnostic).unwrap();
        assert!(overlap.receive_context(None, true).is_err());
    }

    fn labelled_rejections(inputs: &BackgroundInputs) -> Vec<serde_json::Value> {
        let mut rows = super::super::ancestor_context::take_rejection_provenance();
        for row in &mut rows {
            let id = row["nativeId"].clone();
            let matches = |file: &File| {
                object_id(file)
                    .ok()
                    .is_some_and(|value| serde_json::json!(value) == id)
            };
            let mut categories = Vec::new();
            if inputs.managed_root.files().any(matches) {
                categories.push("managed-root");
            }
            if inputs.program_parent.files().any(matches) {
                categories.push("product");
            }
            if inputs
                .diagnostic_source
                .iter()
                .flat_map(|source| source.parent.files())
                .any(matches)
            {
                categories.push("source");
            }
            if inputs.diagnostic.files().any(matches) {
                categories.push("diagnostic");
            }
            row["actualInputCategories"] = serde_json::json!(categories);
        }
        rows
    }

    #[test]
    #[ignore = "Root-selected host namespace; actual qualified saved context, no effects or lease"]
    fn selected_existing_background_policy_readonly_probe() {
        let data = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_NATIVE_READONLY_PROGRAM_DATA")
                .expect("selected ProgramData root"),
        );
        let program = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_NATIVE_READONLY_PROGRAM").expect("selected program"),
        );
        let diagnostics = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_NATIVE_READONLY_DIAGNOSTICS")
                .expect("selected existing log namespace"),
        );
        let source = std::env::var_os("AG_BACKGROUND_NATIVE_READONLY_SOURCE").map(PathBuf::from);
        let metadata = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_NATIVE_READONLY_METADATA")
                .expect("selected existing NONSECRET metadata path"),
        );
        let missing = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_NATIVE_MISSING_CONTEXT")
                .expect("selected absent explicit context"),
        );
        let inputs = background_inputs(
            &data,
            program.parent().unwrap(),
            source.as_deref(),
            &diagnostics,
        )
        .unwrap();
        let empty = inputs.receive_context(None, true);
        let empty_trace = labelled_rejections(&inputs);
        let missing_result =
            crate::windows_coordinator::windows_deployment::receive_for_background(
                &inputs,
                Some(&missing),
            )
            .map(|_| ());
        // Keep the positive full-input receiver's provenance separate from
        // the explicit missing-carrier negative observation.
        let _ = super::super::ancestor_context::take_rejection_provenance();
        let context =
            crate::windows_coordinator::windows_deployment::receive_for_background(&inputs, None);
        let full_trace = labelled_rejections(&inputs);
        let (received, qualified, program_result) = match context {
            Ok(context) => (
                Ok(context.is_some()),
                inputs.receive_context(context.as_ref(), true),
                receive_path(&program, PathKind::File, context.as_ref()).map(|_| ()),
            ),
            Err(error) => (Err(error.clone()), Err(error.clone()), Err(error)),
        };
        let diagnostic = diagnostic_inputs(&diagnostics).unwrap();
        let context = crate::windows_coordinator::windows_deployment::receive_for_diagnostic(
            &diagnostic,
            None,
        );
        let (diagnostic_result, metadata_result) = match context {
            Ok(context) => {
                let namespace = diagnostic.receive_context(context.as_ref());
                let leaf = match fs::symlink_metadata(
                    NativeFsPath::from_path(&metadata).unwrap().as_path(),
                ) {
                    Ok(_) => {
                        CheckedPath::open(&metadata, PathKind::File, PathPurpose::ReplaceSource)
                            .and_then(|pin| check_nonsecret_file(&pin.file, context.as_ref()))
                            .map(|_| true)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(error) => Err(io("selected metadata observation", error)),
                };
                (namespace, leaf)
            }
            Err(error) => (Err(error.clone()), Err(error)),
        };
        let metadata_trace = super::super::ancestor_context::take_rejection_provenance();
        eprintln!(
            "BACKGROUND_EXISTING_POLICY {}",
            serde_json::json!({"schema":3,
            "kind":"read-only-qualified-native-background-policy-observation","sourceIncluded":source.is_some(),
            "emptyNamespace":empty,"emptyFirstRejection":empty_trace,"explicitMissingContext":missing_result,
            "savedContextReceived":received,"qualifiedNamespace":qualified,"qualifiedProgram":program_result,
            "fullReceiveFirstRejection":full_trace,"diagnosticNamespace":diagnostic_result,
            "nonsecretMetadataLeafPresentAndQualified":metadata_result,"metadataRejection":metadata_trace,
            "note":"same FULL input receive; no subset/transplant, lease, task or OS mutation"})
        );
    }

    #[test]
    #[ignore = "Root-selected proposed namespace observation only; no creation, lease or program admission"]
    fn selected_proposed_background_namespace_readonly_probe() {
        let selected = |name: &str| {
            PathBuf::from(std::env::var_os(name).expect("explicit proposed-namespace input"))
        };
        let root = selected("AG_BACKGROUND_NATIVE_PROPOSED_ROOT");
        let product = selected("AG_BACKGROUND_NATIVE_PROPOSED_PRODUCT");
        let program = selected("AG_BACKGROUND_NATIVE_PROPOSED_PROGRAM");
        let source = selected("AG_BACKGROUND_NATIVE_PROPOSED_SOURCE");
        let diagnostic = selected("AG_BACKGROUND_NATIVE_PROPOSED_DIAGNOSTICS");
        let inputs = background_inputs(&root, &product, Some(&source), &diagnostic).unwrap();
        let _ = super::super::ancestor_context::take_rejection_provenance();
        let received =
            crate::windows_coordinator::windows_deployment::receive_for_background(&inputs, None);
        let mut first_rejection = labelled_rejections(&inputs);
        for row in &mut first_rejection {
            if let Some(categories) = row["actualInputCategories"].as_array_mut() {
                for category in categories {
                    if category == "managed-root" {
                        *category = serde_json::json!("proposed-root");
                    } else if category == "product" {
                        *category = serde_json::json!("future-product-ancestor");
                    }
                }
            }
        }
        let (context_received, namespace) = match received {
            Ok(context) => (
                Ok(context.is_some()),
                inputs.receive_context(context.as_ref(), true),
            ),
            Err(error) => (Err(error.clone()), Err(error)),
        };
        eprintln!(
            "BACKGROUND_PROPOSED_NAMESPACE {}",
            serde_json::json!({"schema":1,"kind":"proposed-namespace-read-only-feasibility",
                "root":path_evidence(&root),"existingRootNativeId":inputs.managed_root.anchor.object,
                "sourceIncluded":true,"futureProductAbsent":absent(&product),
                "futureProgramAbsent":absent(&program),"savedContextReceived":context_received,
                "qualifiedNamespace":namespace,"firstReceiveRejection":first_rejection,
                "note":"explicit proposed root, not ProgramData substitution; no future object ID, lease, creation or new-image compatibility claim"})
        );
    }

    fn make_file(lease: &BackgroundLease, path: &Path, bytes: &[u8]) -> CheckedPath {
        let mut file = create_background_executable(lease, path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        checked_background_path(lease, path, PathKind::File).unwrap()
    }

    fn allocate_owned_root(kind: &str) -> CheckedPath {
        let parent_path = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT")
                .expect("explicit existing qualified parent"),
        );
        let parent = receive_path(&parent_path, PathKind::Directory, None).unwrap();
        let path = parent.path.join(format!("{kind}-{}", unique_id().unwrap()));
        absent(&path).unwrap();
        create_private_dir(&path).unwrap();
        let root = receive_path(&path, PathKind::Directory, None).unwrap();
        private(&root.file).unwrap();
        write_private(
            &root.path.join("fixture-root-facts.json"),
            &json(&serde_json::json!({
            "schema":1,"kind":kind,"path":path_evidence(&root.path),"nativeId":root.object,
            "callerParentNativeId":parent.object,"protectedPrivateReceiving":true,
            "securityDescriptorSha256":hash(&security(root.file.as_raw_handle(),1|4).unwrap())}))
            .unwrap(),
        )
        .unwrap();
        root
    }

    #[test]
    #[ignore = "Root-authorized new C-direct model resource only; not a PASS criterion"]
    fn allocate_private_background_model_root() {
        let root = allocate_owned_root("background-model");
        eprintln!("OWN_BACKGROUND_MODEL_ROOT {}", root.path.display());
    }

    #[test]
    #[ignore = "Root-owned source-proof resource creation only; not installed or executed"]
    fn prepare_private_background_source_proof() -> Result<()> {
        let parent_path = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_SOURCE_PROOF_PARENT")
                .ok_or("explicit existing source-proof parent required")?,
        );
        let input_path = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_SOURCE_PROOF_INPUT")
                .ok_or("explicit immutable source-proof input required")?,
        );
        let expected = std::env::var("AG_BACKGROUND_SOURCE_PROOF_SHA256")
            .map_err(|_| "explicit Root-bound source-proof hash required")?;
        let input = CheckedPath::open(&input_path, PathKind::File, PathPurpose::Review)?;
        let bytes = input.read_snapshot()?;
        if hash(&bytes) != expected {
            return Err("source-proof input differs from Root-bound immutable executable".into());
        }
        let inputs = diagnostic_inputs(&parent_path)?;
        // Here DiagnosticInputs supplies only the sealed raw directory
        // projection. Programs is an executable parent, not current-owner
        // diagnostic state, so its existing directory guarantee is received
        // through the unchanged context-bound directory owner.
        let context =
            crate::windows_coordinator::windows_deployment::receive_for_diagnostic(&inputs, None)?
                .ok_or("genuine saved context absent for source-proof resource")?;
        let receive_parent = || -> Result<CheckedPath> {
            inputs.recheck(true)?;
            context.revalidate()?;
            receive_path(&parent_path, PathKind::Directory, Some(&context))
        };
        let parent = receive_parent()?;
        let path = parent
            .path
            .join(format!("background-source-{}", unique_id()?));
        eprintln!("SELECTED_BACKGROUND_SOURCE_PROOF_ROOT {}", path.display());
        absent(&path)?;
        create_private_dir(&path)?;
        let root = receive_path(&path, PathKind::Directory, Some(&context))?;
        private(&root.file)?;
        eprintln!("OWN_BACKGROUND_SOURCE_PROOF_ROOT {}", path.display());
        write_private(
            &path.join("source-proof-created.json"),
            &json(&serde_json::json!({
                "stage":"actual private CREATE_NEW directory received","root":path_evidence(&path),
                "rootNativeId":root.object,"parentNativeId":parent.object,
                "rootSecurityDescriptorSha256":hash(&security(root.file.as_raw_handle(),1|4)?),
                "sourceNativeId":input.object,"sourceExpectedSha256":expected,
                "sourceCreator":"Root-bound immutable readonly06 test executable; not an installed program"
            }))?,
        )?;
        let output_path = path.join("background-source-proof.exe");
        absent(&output_path)?;
        let mut output = create_owned_file(&output_path)?;
        let output_id = object_id(&output)?;
        private(&output)?;
        output
            .write_all(&bytes)
            .and_then(|_| output.sync_all())
            .map_err(|error| io("source-proof private copy persist", error))?;
        drop(output);
        let copied = CheckedPath::open(&output_path, PathKind::File, PathPurpose::ReplaceSource)?;
        private(&copied.file)?;
        if copied.object != output_id || hash(&copied.read_snapshot()?) != expected {
            return Err("source-proof actual copy native ID/hash receiving differs".into());
        }
        input.recheck()?;
        if hash(&input.read_snapshot()?) != expected {
            return Err("source-proof immutable input changed during copy".into());
        }
        if receive_parent()?.object != parent.object {
            return Err("source-proof parent native identity changed".into());
        }
        root.recheck()?;
        write_private(
            &path.join("source-proof-received.json"),
            &json(&serde_json::json!({
                "stage":"actual private copy independently received; never executed or installed",
                "root":path_evidence(&path),"rootNativeId":root.object,"parentNativeId":parent.object,
                "source":path_evidence(&input_path),"sourceNativeId":input.object,
                "sourceSha256":expected,"sourceCreator":"immutable readonly06 executable",
                "copy":path_evidence(&output_path),"copyNativeId":copied.object,
                "copySha256":hash(&copied.read_snapshot()?),"privateProtected":true,
                "copySecurityDescriptorSha256":hash(&security(copied.file.as_raw_handle(),1|4)?)
            }))?,
        )?;
        Ok(())
    }

    fn persist_metadata(
        root: &CheckedPath,
        label: &str,
        path: &Path,
        bytes: &[u8],
    ) -> std::result::Result<serde_json::Value, MetadataFailure> {
        let result = write_nonsecret_metadata_checked(path, bytes, None);
        write_private(
            &root.path.join(format!("{label}-actual-result.json")),
            &json(&result).unwrap(),
        )
        .unwrap();
        result
    }

    #[test]
    #[ignore = "own private metadata and degraded namespace inputs; no DNS/product writes"]
    fn nonsecret_metadata_receiving_and_input_drift() {
        let root = allocate_owned_root("background-metadata");
        eprintln!("OWN_BACKGROUND_METADATA_ROOT {}", root.path.display());
        let log = root.path.join("log");
        create_private_dir(&log).unwrap();
        let version = log.join("version");
        let created = persist_metadata(&root, "create", &version, b"44")
            .unwrap_or_else(|error| panic!("{error}"));
        write_private(
            &root.path.join("metadata-created.json"),
            &json(&created).unwrap(),
        )
        .unwrap();
        assert_eq!(created["replaceResult"], serde_json::Value::Null);
        assert_eq!(created["creationReceived"], true);
        let plan = read_nonsecret_metadata_checked(&version, None)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(plan.bytes(), Some(b"44".as_slice()));
        plan.revalidate().unwrap_or_else(|error| panic!("{error}"));
        let result = plan.write_checked(b"45");
        write_private(
            &root.path.join("update-actual-result.json"),
            &json(&result).unwrap(),
        )
        .unwrap();
        let updated = result.unwrap_or_else(|error| panic!("{error}"));
        write_private(
            &root.path.join("metadata-updated.json"),
            &json(&updated).unwrap(),
        )
        .unwrap();
        assert_eq!(updated["replaceResult"], true);
        assert_eq!(read_path(&version, READ | DELETE).unwrap().bytes, b"45");
        set_fixture_public_rx(&version);
        let unchanged = persist_metadata(&root, "unchanged-public-read", &version, b"45")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(unchanged["phase"], "unchanged-received");
        let before_failure = read_path(&version, READ | DELETE).unwrap();
        let deny = CheckedPath::open(&version, PathKind::File, PathPurpose::Review).unwrap();
        let failure = persist_metadata(&root, "native-failure", &version, b"46")
            .err()
            .expect("actual native sharing failure");
        write_private(
            &root.path.join("metadata-native-failure.json"),
            &json(&failure).unwrap(),
        )
        .unwrap();
        assert_eq!(failure.replace_result, Some(false));
        assert!(same_snapshot(
            &read_path(&version, READ | DELETE).unwrap(),
            &before_failure
        ));
        drop(deny);
        TEST_METADATA_RECEIVING_FAILURE.with(|value| value.set(true));
        let failure = persist_metadata(&root, "receiving-failure", &version, b"47")
            .err()
            .expect("post-call receiving failure");
        write_private(
            &root.path.join("metadata-receiving-failure.json"),
            &json(&failure).unwrap(),
        )
        .unwrap();
        assert_eq!(failure.replace_result, Some(true));
        assert_eq!(failure.phase, "receiving");
        assert!(failure.cause.contains("injected failure"));
        assert_eq!(read_path(&version, READ | DELETE).unwrap().bytes, b"47");
        let data = root.path.join("ProgramData");
        create_private_dir(&data).unwrap();
        let source = root.path.join("source.exe");
        write_private(&source, b"MZ owned input; never executed").unwrap();
        let without_source = background_inputs(&data, &data.join("product"), None, &log).unwrap();
        assert!(without_source.source.is_none());
        without_source.receive_context(None, true).unwrap();
        let mut inputs =
            background_inputs(&data, &data.join("product"), Some(&source), &log).unwrap();
        inputs.managed_root.anchor.object.file[0] ^= 1;
        assert!(inputs.receive_context(None, true).is_err());
        let inputs = background_inputs(&data, &data.join("product"), Some(&source), &log).unwrap();
        set_fixture_public_rx(&data);
        assert!(inputs.receive_context(None, true).is_err());
        let source_pin =
            CheckedPath::open(&source, PathKind::File, PathPurpose::ReplaceSource).unwrap();
        assert!(file_integrity(&source_pin.file).is_ok());
    }

    fn set_fixture_public_rx(path: &Path) {
        set_fixture_acl(path, "(A;;GRGX;;;WD)");
    }

    fn set_fixture_acl(path: &Path, access: &str) {
        let mut sd = descriptor(access);
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    sd.as_mut_ptr().cast(),
                    &mut present,
                    &mut acl,
                    &mut defaulted,
                )
            },
            0
        );
        assert_ne!(present, 0);
        let directory = fs::symlink_metadata(NativeFsPath::from_path(path).unwrap().as_path())
            .unwrap()
            .is_dir();
        let file = OpenOptions::new()
            .access_mode(0x0006_0000)
            .share_mode(READ | DELETE)
            .custom_flags(OPEN_REPARSE | if directory { BACKUP_SEMANTICS } else { 0 })
            .open(NativeFsPath::from_path(path).unwrap().as_path())
            .unwrap();
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    1,
                    0x8000_0004,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null_mut(),
                )
            },
            0
        );
    }

    #[test]
    #[ignore = "actual KnownFolder paths and Root-bound source/log inputs; read-only, no legacy leaf or product effects"]
    fn background_known_folder_locations_readonly_probe() -> Result<()> {
        let locations = background_locations()?;
        let source = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_LOCATION_PROBE_SOURCE")
                .ok_or("explicit hash-bound source required")?,
        );
        let diagnostic = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_LOCATION_PROBE_DIAGNOSTICS")
                .ok_or("explicit diagnostic namespace required")?,
        );
        let inputs = background_inputs(
            locations.managed_root(),
            locations.managed_directory(),
            Some(&source),
            &diagnostic,
        )?;
        let _ = super::super::ancestor_context::take_rejection_provenance();
        let received =
            crate::windows_coordinator::windows_deployment::receive_for_background(&inputs, None);
        let rejection = labelled_rejections(&inputs);
        let (saved, namespace) = match received {
            Ok(context) => (
                Ok(context.is_some()),
                inputs.receive_context(context.as_ref(), true),
            ),
            Err(error) => (Err(error.clone()), Err(error)),
        };
        eprintln!(
            "BACKGROUND_KNOWN_FOLDER_LOCATIONS {}",
            serde_json::json!({
            "managedRoot":path_evidence(locations.managed_root()),
            "managedDirectory":path_evidence(locations.managed_directory()),
            "managedProgram":path_evidence(locations.managed_program()),
            "legacyReadOnlyLocator":path_evidence(locations.legacy_program()),
            "managedRootNativeId":inputs.managed_root.anchor.object,
            "managedProductAbsent":absent(locations.managed_directory()),
            "managedProgramAbsent":absent(locations.managed_program()),
            "sourceIncluded":true,"savedContextReceived":saved,"qualifiedNamespace":namespace,
            "firstReceiveRejection":rejection,"note":"no lease, product creation or host legacy-file open"})
        );
        Ok(())
    }

    #[test]
    #[ignore = "Root-owned private legacy association and managed namespace fixture; no host program/task effects"]
    fn legacy_readonly_association_and_managed_namespace_are_separate() -> Result<()> {
        let root = allocate_owned_root("background-pf-native");
        eprintln!("OWN_BACKGROUND_PF_NATIVE_ROOT {}", root.path.display());
        let managed = root.path.join("ProgramFiles");
        let legacy = root.path.join("LegacyProgramData");
        create_private_dir(&managed)?;
        create_private_dir(&legacy)?;
        let locations = BackgroundLocations::from_roots(managed.clone(), legacy.clone())?;
        assert!(legacy_background_input(&locations)?.is_none());
        let legacy_directory = locations
            .legacy_program()
            .parent()
            .ok_or("legacy fixture parent absent")?;
        create_private_dir(legacy_directory)?;
        write_private(
            locations.legacy_program(),
            b"MZ owned legacy association; never executed",
        )?;
        let legacy_before = read_path(locations.legacy_program(), READ)?;
        set_fixture_acl(legacy_directory, "(A;;0x116;;;BU)");
        assert!(receive_path(legacy_directory, PathKind::Directory, None).is_err());
        let association =
            legacy_background_input(&locations)?.ok_or("legacy fixture input absent")?;
        association.revalidate()?;
        assert_eq!(association.digest(), hash(&legacy_before.bytes));
        assert_eq!(association.native_id(), &object_id(&association.pin.file)?);
        write_private(
            &root.path.join("legacy-readonly-received.json"),
            &json(&association.evidence())?,
        )?;
        // Parent ACL mutation grants no namespace authority, but does not
        // invalidate identity-only ancestors of an unchanged read-only input.
        set_fixture_public_rx(legacy_directory);
        association.revalidate()?;
        set_fixture_public_rx(locations.legacy_program());
        assert!(association.revalidate().is_err());
        drop(association);
        let public_rx =
            legacy_background_input(&locations)?.ok_or("legacy fixture input absent")?;
        public_rx.revalidate()?;
        drop(public_rx);
        set_fixture_acl(locations.legacy_program(), "(A;;0x2;;;WD)");
        assert!(legacy_background_input(&locations).is_err());
        assert_eq!(
            read_path(locations.legacy_program(), READ)?.bytes,
            legacy_before.bytes
        );

        let source = root.path.join("new.exe");
        let diagnostic = root.path.join("diagnostic");
        write_private(&source, b"MZ owned managed source; never executed")?;
        create_private_dir(&diagnostic)?;
        let image = std::sync::Arc::new(crate::windows_coordinator::process_identity::CurrentImage::synthetic(&source)?);
        let inputs = background_inputs_selected(
            locations.managed_root(),
            locations.managed_directory(),
            image.clone(),
            &diagnostic,
        )?;
        let lease = background_lease(inputs, None)?;
        create_background_directory(&lease, locations.managed_directory())?;
        let program = make_file(
            &lease,
            locations.managed_program(),
            b"MZ owned managed source; never executed",
        );
        assert_eq!(
            program.read_snapshot()?,
            b"MZ owned managed source; never executed"
        );
        assert!(create_background_executable(&lease, locations.managed_program()).is_err());
        assert!(create_background_directory(&lease, locations.managed_directory()).is_err());
        let later_root = root.path.join("AppearedProgramFiles");
        create_private_dir(&later_root)?;
        let later = BackgroundLocations::from_roots(later_root, legacy)?;
        let inputs = background_inputs_selected(
            later.managed_root(),
            later.managed_directory(),
            image,
            &diagnostic,
        )?;
        create_private_dir(later.managed_directory())?;
        assert!(background_lease(inputs, None).is_err());
        write_private(
            &root.path.join("native-namespace-result.json"),
            &json(&serde_json::json!({
            "legacyReadOnlyAssociation":true,"legacyUnsafeNamespaceNotAdmitted":true,
            "legacyFileMutationRejected":true,"legacyBytesUnchanged":true,
            "managedProgramNativeId":program.object,"managedProgramDigest":hash(&program.read_snapshot()?),
            "createOnlyCollisionRejected":true,"newlyAppearedProductRejected":true,
            "scope":"owned-file adapter proof; no Stop, Task Scheduler or actual product acceptance"}))?,
        )?;
        Ok(())
    }

    #[test]
    #[ignore = "explicit ordinary qualified C-direct parent; own synthetic files only"]
    fn native_program_replacement_receives_metadata_and_distinct_call_outcomes() {
        let parent_path = PathBuf::from(
            std::env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT")
                .expect("explicit admitted existing ordinary fixture parent required"),
        );
        let parent = receive_path(&parent_path, PathKind::Directory, None).unwrap();
        let root_path = parent
            .path
            .join(format!("background-native-{}", unique_id().unwrap()));
        absent(&root_path).unwrap();
        create_private_dir(&root_path).unwrap();
        let root = receive_path(&root_path, PathKind::Directory, None).unwrap();
        write_private(
            &root.path.join("fixture-root-facts.json"),
            &json(&serde_json::json!({
            "schema":1,"kind":"owned-background-native-fixture","path":path_evidence(&root.path),
            "nativeId":root.object,"callerParentNativeId":parent.object}))
            .unwrap(),
        )
        .unwrap();
        eprintln!("OWN_BACKGROUND_NATIVE_FIXTURE {}", root.path.display());
        let data = root.path.join("ProgramData");
        create_private_dir(&data).unwrap();
        let source_dir = root.path.join("source");
        create_private_dir(&source_dir).unwrap();
        let source_path = source_dir.join("new.exe");
        write_private(&source_path, b"MZ synthetic new image; never executed").unwrap();
        let capture_dir = root.path.join("private-log");
        create_private_dir(&capture_dir).unwrap();
        let mut product = data.join("AGUnlocker");
        let image = std::sync::Arc::new(crate::windows_coordinator::process_identity::CurrentImage::synthetic(&source_path).unwrap());
        let inputs = background_inputs_selected(&data, &product, image, &capture_dir).unwrap();
        let lease = background_lease(inputs, None).unwrap();
        create_background_directory(&lease, &product).unwrap();
        // A fixture beyond legacy MAX_PATH is an input, never a runtime cap.
        const LEGACY_WIN32_PATH_UNITS: usize = 260;
        while product
            .join("program.exe")
            .as_os_str()
            .encode_wide()
            .count()
            <= LEGACY_WIN32_PATH_UNITS
        {
            product = product.join("native-long-path-segment");
            create_background_directory(&lease, &product).unwrap();
        }
        let source = lease.inputs.source.as_ref().unwrap().image.file();
        let current = make_file(
            &lease,
            &product.join("program.exe"),
            b"MZ synthetic old image; never executed",
        );
        set_fixture_public_rx(&current.path);
        assert!(file_integrity(&current.file).is_ok());
        let old = read_path(&current.path, READ | DELETE).unwrap();
        let old_id = current.object.clone();
        TEST_NATIVE_CALLS.with(|count| count.set(0));
        let unselected = background_inputs(&data, &product, None, &capture_dir).unwrap();
        let unselected_lease = background_lease(unselected, None).unwrap();
        let denied_source = background_replace_program(&unselected_lease, &current).err().expect("unselected source must fail");
        assert_eq!(denied_source.replace_result, None);
        assert_eq!(TEST_NATIVE_CALLS.with(|count| count.get()), 0);
        drop(unselected_lease);
        let receiving = background_replace_program(&lease, &current)
            .unwrap_or_else(|failure| panic!("{failure}"));
        write_private(
            &root.path.join("replacement-success.json"),
            &json(&receiving.evidence).unwrap(),
        )
        .unwrap();
        assert_eq!(receiving.evidence["replaceResult"], true);
        assert_eq!(
            receiving.program.read_snapshot().unwrap(),
            source.read_snapshot().unwrap()
        );
        assert_ne!(receiving.program.object, old_id);
        let work = receiving.evidence["work"]["displaced"]["path"]
            .as_str()
            .unwrap();
        let displaced = read_path(Path::new(work), READ | DELETE).unwrap();
        assert!(same_snapshot(&displaced, &old));
        assert_eq!(
            object_id(&open_regular(Path::new(work), READ | DELETE).unwrap()).unwrap(),
            old_id
        );
        assert_eq!(TEST_NATIVE_CALLS.with(|count| count.get()), 1);

        // A real incompatible reader produces a native failure, not NotCalled.
        let blocked = make_file(&lease, &product.join("blocked.exe"), b"MZ old held image");
        let reader = CheckedPath::open(&blocked.path, PathKind::File, PathPurpose::Review).unwrap();
        let failure = background_replace_program(&lease, &blocked)
            .err()
            .expect("native sharing failure required");
        write_private(
            &root.path.join("replacement-native-failure.json"),
            &json(&failure).unwrap(),
        )
        .unwrap();
        assert_eq!(failure.replace_result, Some(false));
        assert_eq!(failure.evidence["replaceResult"], false);
        assert_eq!(failure.evidence["programObservation"]["state"], "present");
        drop(reader);

        // Actual success followed by a receiver failure retains Some(true).
        let after_call = make_file(
            &lease,
            &product.join("after-call.exe"),
            b"MZ old receiving fixture",
        );
        TEST_RECEIVING_FAILURE.with(|value| value.set(true));
        let failure = background_replace_program(&lease, &after_call)
            .err()
            .expect("post-call receiving failure required");
        write_private(
            &root.path.join("replacement-receiving-failure.json"),
            &json(&failure).unwrap(),
        )
        .unwrap();
        assert_eq!(failure.replace_result, Some(true));
        assert_eq!(failure.phase, "receiving");
        assert!(failure.cause.contains("injected failure"));
        assert_eq!(failure.evidence["replaceResult"], true);
        assert_eq!(failure.evidence["programObservation"]["state"], "present");
        assert_eq!(
            failure.evidence["work"]["displacedObservation"]["state"],
            "present"
        );

        // Wrong-purpose borrowed pins are never unsafely closed for a call.
        let denied = CheckedPath::open(
            &product.join("after-call.exe"),
            PathKind::File,
            PathPurpose::Review,
        )
        .unwrap();
        let count = TEST_NATIVE_CALLS.with(|value| value.get());
        let failure = background_replace_program(&lease, &denied)
            .err()
            .expect("incompatible receiving must fail before call");
        write_private(
            &root.path.join("replacement-not-called.json"),
            &json(&failure).unwrap(),
        )
        .unwrap();
        assert_eq!(failure.replace_result, None);
        assert_eq!(TEST_NATIVE_CALLS.with(|value| value.get()), count);

        // Existing CREATE_NEW collision preserves the earlier bytes.
        assert!(create_background_executable(&lease, &source.path).is_err());
        assert_eq!(
            source.read_snapshot().unwrap(),
            b"MZ synthetic new image; never executed"
        );

        let mut capture =
            create_private_captured_file(&capture_dir.join("capture.txt"), lease.context())
                .unwrap();
        capture
            .file
            .write_all(b"actual owned file capture")
            .unwrap();
        capture.file.sync_all().unwrap();
        let capture_id = capture.native_id.clone();
        drop(capture.file);
        assert_eq!(
            read_private_captured_file(&capture.path, &capture_id, lease.context()).unwrap(),
            b"actual owned file capture"
        );
        assert!(
            read_private_captured_file(&capture.path, &source.object, lease.context()).is_err()
        );
        assert!(create_private_captured_file(&capture.path, lease.context()).is_err());
        assert_eq!(
            read_private_captured_file(&capture.path, &capture_id, lease.context()).unwrap(),
            b"actual owned file capture"
        );
        write_private(&root.path.join("oracle-result.json"), &json(&serde_json::json!({
            "schema":1,"kind":"owned-background-native-oracle","rootNativeId":root.object,
            "programDirectory":path_evidence(&product),
            "programDirectoryNativeId":checked_background_path(&lease,&product,PathKind::Directory).unwrap().object,
            "nativeReplaceCalls":TEST_NATIVE_CALLS.with(|count|count.get()),
            "privateCaptureNativeId":capture_id,
            "status":"completed actual own-file assertions; not a product task result"
        })).unwrap()).unwrap();
    }
}
