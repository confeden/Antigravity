//! Canonical association receiving before any legacy native write/kill path.
//! An unowned writer retains the existing namespace lease until its effect ends,
//! so enrollment cannot race the decision that this target is unowned.
use super::*;

pub(crate) struct LegacyNativeWrite {
    _lease: Lease,
    _pins: Vec<CheckedPath>,
    bound: Option<BoundInstallation>,
    expected: Option<Binding>,
    _target: Option<CheckedPath>,
    canonical: bool,
}
impl LegacyNativeWrite {
    pub(crate) fn recheck(&self) -> Result<()> {
        if let (Some(bound), Some(expected)) = (&self.bound, &self.expected) {
            bound.revalidate_context()?;
            bound.exe.recheck()?;
            bound.root.recheck()?;
            bound.resources.recheck()?;
            bound.archive.recheck()?;
            if &bound.binding()? != expected || bound.archive.read_snapshot()? != bound.bytes {
                return Err("UpdatePending: canonical inputs changed during native-binary work".into());
            }
        }
        Ok(())
    }
}

pub(crate) fn admit_legacy_write(path: &Path) -> Result<LegacyNativeWrite> {
    admit_write(path, None, false)
}
pub(crate) fn canonical_installed(path: &Path) -> Result<bool> { Ok(admit_write(path, None, true)?.canonical) }
type NativeSelection = (fn(&Path) -> Vec<PathBuf>, fn(&BoundInstallation) -> Result<Option<AncestorAccessContext>>);
pub(crate) fn admit_native_binary(path: &Path, selected: fn(&Path) -> Vec<PathBuf>,
    receive_context: fn(&BoundInstallation) -> Result<Option<AncestorAccessContext>>) -> Result<LegacyNativeWrite> {
    admit_write(path, Some((selected, receive_context)), false)
}
fn admit_write(path: &Path, native: Option<NativeSelection>, inspect: bool) -> Result<LegacyNativeWrite> {
    let parent_path = match fs::symlink_metadata(NativeFsPath::from_path(path)?.as_path()) {
        Ok(metadata) if metadata.is_dir() => path,
        Ok(_) => path.parent().ok_or("legacy target parent absent")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => path.parent().ok_or("legacy target parent absent")?,
        Err(error) => return Err(io("legacy target observation", error)),
    };
    let parent = CheckedPath::open(parent_path, PathKind::Directory, PathPurpose::Source)?;
    let target = if native.is_some() { Some(CheckedPath::open(path, PathKind::File, PathPurpose::ReplaceSource)?) } else { None };
    #[cfg(not(test))]
    let known_path = state_base()?;
    #[cfg(test)]
    let known_path = TEST_BASE.with(|value| value.borrow().clone())
        .or_else(|| std::env::var_os("AG_LEGACY_NATIVE_GUARD_TEST_BASE").map(PathBuf::from))
        .ok_or("explicit synthetic legacy-guard state root required; production state was not read")?;
    let known = CheckedPath::open(&known_path, PathKind::Directory, PathPurpose::Review)?;
    let lease = Lease::acquire(&known, "wsl_namespace_v2")?;
    let mut pins = vec![parent, known];
    let product = known_path.join(user_state_location::WINDOWS_STATE_LEAF);
    let namespace = product.join(INSTALLATIONS_NAMESPACE);
    for directory in [&product, &namespace] {
        match fs::symlink_metadata(NativeFsPath::from_path(directory)?.as_path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(LegacyNativeWrite { _lease: lease, _pins: pins, bound: None, expected: None, _target: target, canonical: false }),
            Err(error) => return Err(io("canonical namespace observation", error)),
            Ok(_) => {
                let pin = CheckedPath::open(directory, PathKind::Directory, PathPurpose::Review)?;
                if directory == &namespace { private(&pin.file)?; }
                pins.push(pin);
            }
        }
    }
    if pins.last().ok_or("canonical namespace pin missing")?.contains(&pins[0])? {
        return Err("canonical metadata/runtime deployment is not a native-binary target".into());
    }
    for entry in fs::read_dir(NativeFsPath::from_path(&namespace)?.as_path()).map_err(|error| io("canonical namespace receiving", error))? {
        let entry = entry.map_err(|error| io("canonical namespace entry", error))?;
        if !entry.file_name().to_str().is_some_and(id_valid) { return Err("canonical namespace identity is unconfirmed".into()); }
        let slot = CheckedPath::open(&namespace.join(entry.file_name()), PathKind::Directory, PathPurpose::Review)?;
        private(&slot.file)?;
        let (current, _) = receive_current(&slot)?;
        if let Some(target) = &target {
            let id = target.native_id();
            let mut protected = vec![current.binding.executable.clone(), current.binding.archive.clone()];
            if let DeploymentField::Present(Some(deployment)) = &current.runtime_deployment {
                protected.extend([deployment.host.native_id.clone(), deployment.gate.native_id.clone()]);
            }
            if protected.contains(&id) { return Err("bound Desktop/archive/runtime/gate identity is not a native-binary target".into()); }
        }
        let target_parent = &pins[0];
        let prefix = current.locator.len();
        let same_locator = target_parent.locator.len() >= prefix
            && ordinal(&target_parent.locator[..prefix], &current.locator)?
            && (target_parent.locator.len() == prefix || target_parent.locator[prefix] == 92);
        let same_native = target_parent.object == current.binding.root || target_parent.object == current.binding.resources
            || target_parent._ancestors.iter().map(object_id).collect::<Result<Vec<_>>>()?.iter()
                .any(|id| *id == current.binding.root || *id == current.binding.resources);
        if same_locator || same_native {
            if inspect {
                let slot_lease = Lease::acquire(&slot, "wsl_slot_v2")?;
                let (fresh, _) = receive_current(&slot)?;
                if matches!(fresh.mode, Mode::Bootstrap | Mode::Pending) { return Err("RecoveryRequired: canonical Current is not settled".into()); }
                pins.push(slot);
                drop(lease);
                return Ok(LegacyNativeWrite { _lease: slot_lease, _pins: pins, bound: None,
                    expected: None, _target: None, canonical: true });
            }
            let Some((selected, receive_context)) = native else {
                return Err("MaintenanceRequired: canonical WSL installation must use its common maintenance owner; legacy archive write refused".into());
            };
            let slot_lease = Lease::acquire(&slot, "wsl_slot_v2")?;
            let (fresh, _) = receive_current(&slot)?;
            if matches!(fresh.mode, Mode::Bootstrap | Mode::Pending) { return Err("RecoveryRequired: canonical native work requires settled Current".into()); }
            let root_path = pins[0].path.ancestors().find_map(|path| {
                CheckedPath::open(path, PathKind::Directory, PathPurpose::Source).ok()
                    .filter(|pin| pin.object == fresh.binding.root).map(|pin| pin.path)
            }).ok_or("UpdatePending: canonical native root identity changed")?;
            // This is the existing GUI's supported Desktop producer path, not
            // discovery of a backup or a same-hash executable under another name.
            let mut bound = BoundInstallation::open(&root_path.join("Antigravity.exe"))?;
            if let Some(context) = receive_context(&bound)? { bound.attach_ancestor_context(context)?; }
            bound.revalidate_context()?;
            let actual_binding = bound.binding()?;
            if actual_binding != fresh.binding { return Err("UpdatePending: canonical native installation incarnation differs".into()); }
            let target = target.ok_or("native target pin absent")?;
            // Basename selection cannot authorize an alias of an existing
            // script owned by the JS patcher. Only NotFound means optional
            // absence; observation or identity failures remain dependent holds.
            for script_path in crate::patch_ide::js_targets(&root_path).into_paths() {
                match fs::symlink_metadata(NativeFsPath::from_path(&script_path)?.as_path()) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(io("JS exclusion observation", error)),
                    Ok(_) => {},
                }
                let script = CheckedPath::open(&script_path, PathKind::File, PathPurpose::Source)?;
                if script.native_id() == target.native_id() {
                    return Err("JS owner object/alias is not a native-binary target".into());
                }
                pins.push(script);
            }
            let mut positively_selected = false;
            for candidate in selected(&root_path) {
                if let Ok(candidate) = CheckedPath::open(&candidate, PathKind::File, PathPurpose::ReplaceSource) {
                    if candidate.native_id() == target.native_id() { positively_selected = true; break; }
                }
            }
            if !positively_selected { return Err("native file was not positively selected by the existing LS/CLI target owner".into()); }
            pins.push(slot);
            drop(lease);
            return Ok(LegacyNativeWrite { _lease: slot_lease, _pins: pins, bound: Some(bound),
                expected: Some(actual_binding), _target: Some(target), canonical: true });
        }
        pins.push(slot);
    }
    Ok(LegacyNativeWrite { _lease: lease, _pins: pins, bound: None, expected: None, _target: target, canonical: false })
}
