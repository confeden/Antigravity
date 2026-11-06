//! Native sharing exclusion for the canonical installation owner. The caller
//! holds the slot admission lease while creating or receiving either handle.
//! Gate bytes carry no authority; its received native identity is mandatory.

use super::*;

const LEAF: &str = "runtime-gate";

/// Retained read access denies every writer and name replacement independently
/// of other readers. Dropping one reader cannot release another reader's hold.
pub(super) struct ReadGate {
    _file: File,
    _slot: CheckedPath,
}

/// Exclusive native access is acquired before the owner can publish Pending or
/// touch an archive. Its lifetime covers actual operation/outcome receiving.
pub(super) struct WriteGate {
    _file: File,
    _slot: CheckedPath,
}
impl WriteGate {
    pub(super) fn recheck(&self, expected: &ObjectId) -> Result<()> {
        receive(&self._file, expected)?;
        self._slot.recheck()
    }
}

fn pin_slot(slot: &CheckedPath) -> Result<CheckedPath> {
    slot.recheck()?;
    private(&slot.file)?;
    let pin = CheckedPath::open(&slot.path, PathKind::Directory, PathPurpose::Review)?;
    private(&pin.file)?;
    if pin.object != slot.object {
        return Err("RuntimeGateConflict: canonical slot identity changed".into());
    }
    Ok(pin)
}

fn receive(file: &File, expected: &ObjectId) -> Result<()> {
    identity(file)?;
    private(file)?;
    if &object_id(file)? != expected {
        return Err("RuntimeGateConflict: native gate identity changed".into());
    }
    Ok(())
}

fn open(slot: &CheckedPath, expected: &ObjectId, writer: bool) -> Result<(File, CheckedPath)> {
    let slot = pin_slot(slot)?;
    let file = OpenOptions::new()
        .read(true)
        .write(writer)
        .share_mode(if writer { 0 } else { READ })
        .custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(&slot.path.join(LEAF))?.as_path())
        .map_err(|error| {
            if error.raw_os_error() == Some(32) {
                "MaintenanceBusy: runtime gate has an incompatible live handle".into()
            } else {
                io("open canonical runtime gate", error)
            }
        })?;
    receive(&file, expected)?;
    slot.recheck()?;
    Ok((file, slot))
}

pub(super) fn read(slot: &CheckedPath, expected: &ObjectId) -> Result<ReadGate> {
    let (file, slot) = open(slot, expected, false)?;
    Ok(ReadGate { _file: file, _slot: slot })
}

pub(super) fn write(slot: &CheckedPath, expected: &ObjectId) -> Result<WriteGate> {
    let (file, slot) = open(slot, expected, true)?;
    Ok(WriteGate { _file: file, _slot: slot })
}

/// V2 preparation only. Never creates a gate for an unreceived runtime read.
/// The owner must bind the returned identity in its existing canonical state
/// while retaining this exclusive handle and the slot admission lease.
pub(super) fn initialize(slot: &CheckedPath) -> Result<(WriteGate, ObjectId)> {
    let slot = pin_slot(slot)?;
    let file = create_owned_file(&slot.path.join(LEAF))?;
    file.sync_all().map_err(|error| io("persist runtime gate", error))?;
    let native_id = object_id(&file)?;
    receive(&file, &native_id)?;
    slot.recheck()?;
    Ok((WriteGate { _file: file, _slot: slot }, native_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(name: &str) -> CheckedPath {
        let parent = PathBuf::from(std::env::var_os("AG_RUNTIME_GATE_FIXTURE_PARENT")
            .expect("explicit owned runtime-gate fixture parent required"));
        let parent = CheckedPath::open(&parent, PathKind::Directory, PathPurpose::Review).unwrap();
        let path = parent.path.join(name);
        absent(&path).unwrap();
        create_private_dir(&path).unwrap();
        let slot = CheckedPath::open(&path, PathKind::Directory, PathPurpose::Review).unwrap();
        write_private(&path.join("fixture-root-facts.json"), &json(&serde_json::json!({
            "schema": 1, "kind": "owned-runtime-gate-fixture", "nativeId": slot.object,
            "callerParentNativeId": parent.object,
        })).unwrap()).unwrap();
        slot
    }

    #[test]
    #[ignore = "explicit owned synthetic root; native Windows sharing receiving"]
    fn runtime_gate_readers_exclude_writer_until_each_retires() {
        let slot = slot("two-readers");
        let _admission = Lease::acquire(&slot, "wsl_slot_v2").unwrap();
        let (initialization, id) = initialize(&slot).unwrap();
        assert!(read(&slot, &id).is_err());
        drop(initialization);
        let first = read(&slot, &id).unwrap();
        let second = read(&slot, &id).unwrap();
        assert!(write(&slot, &id).is_err());
        drop(first);
        assert!(write(&slot, &id).is_err());
        drop(second);
        let writer = write(&slot, &id).unwrap();
        assert!(read(&slot, &id).is_err());
        assert!(write(&slot, &id).is_err());
        drop(writer);
        assert!(read(&slot, &id).is_ok());
    }

    #[test]
    #[ignore = "explicit owned synthetic root; no production state access"]
    fn runtime_gate_missing_changed_and_multilink_fail_closed() {
        let slot = slot("identity-receiving");
        let _admission = Lease::acquire(&slot, "wsl_slot_v2").unwrap();
        let unknown = ObjectId { volume: 0, file: [0; 16] };
        assert!(read(&slot, &unknown).is_err());
        assert!(!slot.path.join(LEAF).exists());
        let (initialization, original_id) = initialize(&slot).unwrap();
        drop(initialization);
        assert!(initialize(&slot).is_err());
        assert!(read(&slot, &unknown).is_err());
        let retained = slot.path.join("original-runtime-gate");
        absent(&retained).unwrap();
        fs::rename(slot.path.join(LEAF), &retained).unwrap();
        let (replacement, replacement_id) = initialize(&slot).unwrap();
        assert_ne!(original_id, replacement_id);
        drop(replacement);
        assert!(read(&slot, &original_id).is_err());
        assert!(write(&slot, &original_id).is_err());
        assert!(read(&slot, &replacement_id).is_ok());
        let alias = slot.path.join("gate-hardlink");
        absent(&alias).unwrap();
        fs::hard_link(slot.path.join(LEAF), alias).unwrap();
        assert!(read(&slot, &replacement_id).is_err());
        assert!(write(&slot, &replacement_id).is_err());
    }
}
