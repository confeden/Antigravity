#[path = "context_test_support.rs"]
mod support;
use super::*;
#[test]
fn legacy_expected_five_cli_set_is_mandatory_and_import_only() {
    let base = vec![
        "--import-legacy".into(),
        "--desktop".into(),
        r"C:\Synthetic\Desktop.exe".into(),
        "--distro".into(),
        "Fixture".into(),
    ];
    assert!(super::super::Options::parse(base.clone()).is_err());
    let flags = [
        "--expected-manifest-sha256",
        "--expected-preimage-sha256",
        "--expected-candidate-sha256",
        "--expected-intent-sha256",
        "--expected-failure-sha256",
    ];
    let mut good = base;
    for flag in flags {
        good.push(flag.into());
        good.push("00".repeat(32).into());
    }
    assert!(super::super::Options::parse(good.clone()).is_ok());
    let mut malformed = good.clone();
    malformed[6] = "bad-hex".into();
    assert!(super::super::Options::parse(malformed).is_err());
    good[0] = "--apply".into();
    assert!(super::super::Options::parse(good).is_err());
}
#[test]
#[ignore = "explicit readonly actual desktop plus own fixture parent; no user DATA writes/copies"]
fn saved_data_foundation_selects_once_and_propagates_all_receiving_errors() {
    use crate::windows_coordinator::windows_deployment as deployment;
    let desktop =
        PathBuf::from(std::env::var_os("AG_CONTEXT_DESKTOP").expect("explicit readonly desktop"));
    TEST_BASE.with(|v| *v.borrow_mut() = None);
    let actual_saved = saved_deployment_data_path().unwrap();
    let bound = BoundInstallation::open(&desktop).unwrap();
    assert!(
        deployment::receive_for_installation(&bound, None)
            .unwrap()
            .is_some(),
        "selected host must have its already-qualified saved DATA"
    );
    let root = own_directory();
    TEST_BASE.with(|v| *v.borrow_mut() = Some(root.clone()));
    let product = root.join(user_state_location::WINDOWS_STATE_LEAF);
    assert!(!product.exists());
    assert!(deployment::receive_for_installation(&bound, None)
        .unwrap()
        .is_none());
    assert!(!product.exists());
    create_private_dir(&product).unwrap();
    let saved = saved_deployment_data_path().unwrap();
    assert_eq!(
        saved,
        product.join(user_state_location::WINDOWS_WSL_DEPLOYMENT_DATA_LEAF)
    );
    write_private(&saved, b"{ malformed own input").unwrap();
    assert!(deployment::receive_for_installation(&bound, None).is_err());
    assert!(
        deployment::receive_for_installation(&bound, Some(&actual_saved))
            .unwrap()
            .is_some(),
        "explicit valid DATA must win over malformed default"
    );
    fs::rename(&saved, product.join("retained-malformed-input.json")).unwrap();
    let stale = serde_json::json!({"schema":1,"provider":"codex-windows-sandbox-v1","ownerSid":"S-1-0-0","machineAccountDomainSid":"S-1-5-21-1-2-3","roles":["offline","online"],"marker":{"path":root.join("never-opened-marker.json"),"nativeId":{"volume":0,"file":vec![0u8;16]},"selectedFieldsSha256":"00"},"providerBinary":{"path":root.join("never-opened.exe"),"nativeId":{"volume":0,"file":vec![0u8;16]},"sha256":"00"},"groupSid":"S-1-0-0","roleSids":{"offline":"S-1-0-0","online":"S-1-0-0"}});
    write_private(&saved, &json(&stale).unwrap()).unwrap();
    let error = deployment::receive_for_installation(&bound, None)
        .err()
        .unwrap();
    assert_eq!(
        error,
        "UnsupportedActorContext: deployment user/machine/schema mismatch before locators"
    );
    let file = OpenOptions::new()
        .access_mode(0x0006_0000)
        .share_mode(READ | WRITE | DELETE)
        .custom_flags(OPEN_REPARSE)
        .open(&saved)
        .unwrap();
    // Establish the owned fixture through the same setter before snapshotting:
    // Windows sets DACL_AUTO_INHERITED on setter receiving, unlike file creation.
    replace_owned_dacl(&file, "");
    private(&file).unwrap();
    let before_id = object_id(&file).unwrap();
    let before_security = security(file.as_raw_handle(), 1 | 2 | 4).unwrap();
    let before_bytes = fs::read(&saved).unwrap();
    replace_owned_dacl(&file, "(A;;FA;;;WD)");
    let changed_security = security(file.as_raw_handle(), 1 | 2 | 4).unwrap();
    let direct_acl_error = private(&file).err().unwrap();
    drop(file);
    let received_acl_error = deployment::receive_for_installation(&bound, None)
        .err()
        .unwrap();
    let file = OpenOptions::new()
        .access_mode(0x0006_0000)
        .share_mode(READ | WRITE | DELETE)
        .custom_flags(OPEN_REPARSE)
        .open(&saved)
        .unwrap();
    let after_id = object_id(&file).unwrap();
    restore_received_dacl(&file, &before_security).unwrap();
    let restored_security = security(file.as_raw_handle(), 1 | 2 | 4).unwrap();
    private(&file).unwrap();
    drop(file);
    assert_ne!(before_security, changed_security);
    assert_eq!(before_security, restored_security);
    assert_eq!(before_id, after_id);
    assert_eq!(before_bytes, fs::read(&saved).unwrap());
    assert_eq!(
        direct_acl_error,
        "private/ancestor ACL grants foreign replacement access"
    );
    assert_eq!(received_acl_error, direct_acl_error);
    assert_ne!(received_acl_error, error);
    assert_eq!(
        deployment::receive_for_installation(&bound, None)
            .err()
            .unwrap(),
        error
    );
    TEST_BASE.with(|v| *v.borrow_mut() = None);
    assert!(
        deployment::receive_for_installation(&bound, Some(&root.join("explicit-missing.json")))
            .is_err(),
        "missing explicit input must never use valid saved default"
    );
}
use std::ffi::c_void;
fn own_directory() -> PathBuf {
    let parent = PathBuf::from(
        std::env::var_os("AG_CONTEXT_FIXTURE_PARENT")
            .expect("explicit owned fixture parent required"),
    );
    let checked = CheckedPath::open(&parent, PathKind::Directory, PathPurpose::Review).unwrap();
    ancestor_integrity(&checked.file).unwrap();
    for file in &checked._ancestors {
        ancestor_integrity(file).unwrap();
    }
    let child = parent.join(format!("context-check-{}", unique_id().unwrap()));
    create_private_dir(&child).unwrap();
    support::record_root(&child, &parent);
    child
}
#[test]
#[ignore = "explicit owned root; readonly hardlink input and strict mutable counterpart"]
fn readonly_executable_hardlink_is_held_but_same_mutable_object_refuses() {
    let root = own_directory();
    let path = root.join("readonly.exe");
    let alias = root.join("alias.exe");
    write_private(&path, b"MZ synthetic readonly file, never executed").unwrap();
    fs::hard_link(&path, &alias).unwrap();
    let mut checked = CheckedPath::open(&path, PathKind::File, PathPurpose::Executable).unwrap();
    let mut second = CheckedPath::open(&alias, PathKind::File, PathPurpose::Executable).unwrap();
    assert_eq!(checked.native_id(), second.native_id());
    assert_eq!(checked.read().unwrap(), second.read().unwrap());
    checked.recheck().unwrap();
    second.recheck().unwrap();
    assert!(OpenOptions::new().write(true).open(&alias).is_err());
    assert!(fs::remove_file(&alias).is_err());
    assert!(CheckedPath::open(&path, PathKind::File, PathPurpose::Source).is_err());
    assert!(CheckedPath::open(&alias, PathKind::File, PathPurpose::ReplaceSource).is_err());
    assert!(identity(&checked.file).is_err());
    assert!(private(&checked.file).is_err() || identity(&checked.file).is_err());
}
pub(super) fn replace_owned_dacl(file: &File, extra: &str) {
    let owner = context_native::current_user().unwrap().text().unwrap();
    let text = format!("O:{owner}D:P(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){extra}")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        },
        0
    );
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) },
        0
    );
    assert_ne!(present, 0);
    assert!(!acl.is_null());
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            1,
            4 | 0x8000_0000,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    assert_eq!(status, 0);
}
#[test]
#[ignore = "explicit owned root; only new own-directory ACL is changed"]
fn capability_normal_side_and_strict_managed_policy_are_separate() {
    let root = own_directory();
    let file = OpenOptions::new()
        .access_mode(0x0006_0000)
        .share_mode(READ | WRITE)
        .custom_flags(OPEN_REPARSE | BACKUP_SEMANTICS)
        .open(&root)
        .unwrap();
    replace_owned_dacl(&file, "(A;OICI;FA;;;S-1-15-3-123)");
    state_parent(&file).unwrap();
    assert!(private(&file).is_err());
    replace_owned_dacl(&file, "(A;OICI;FA;;;WD)");
    assert!(state_parent(&file).is_err());
    assert!(private(&file).is_err());
}
#[test]
#[ignore = "explicit owned root/archive; absent product/store reservations only"]
fn prospective_reserved_product_and_namespace_aliases_have_zero_effect() {
    let archive = PathBuf::from(
        std::env::var_os("AG_ARCHIVE_INSTALL_FIXTURE").expect("explicit readonly archive fixture"),
    );
    let bytes = fs::read(archive).unwrap();
    let root = own_directory();
    let state = root.join("state");
    create_private_dir(&state).unwrap();
    let install = root.join("application");
    create_private_dir(&install).unwrap();
    create_private_dir(&install.join("resources")).unwrap();
    write_private(
        &install.join("Desktop.exe"),
        b"MZ synthetic, never executed",
    )
    .unwrap();
    write_private(&install.join("resources/app.asar"), &bytes).unwrap();
    TEST_BASE.with(|v| *v.borrow_mut() = Some(state.clone()));
    let bound = BoundInstallation::open(&install.join("Desktop.exe")).unwrap();
    assert_eq!(bound.executable_digest(), hash(b"MZ synthetic, never executed"));
    let before = fs::read_dir(&state).unwrap().count();
    for leaf in [
        user_state_location::WINDOWS_STATE_LEAF.to_string(),
        user_state_location::WINDOWS_STATE_LEAF.to_uppercase(),
    ] {
        assert!(bound.validate_deployment_output(&state.join(leaf)).is_err());
    }
    assert_eq!(fs::read_dir(&state).unwrap().count(), before);
    assert!(!state.join(user_state_location::WINDOWS_STATE_LEAF).exists());
    let product = state.join(user_state_location::WINDOWS_STATE_LEAF);
    create_private_dir(&product).unwrap();
    let before = fs::read_dir(&product).unwrap().count();
    for leaf in [
        INSTALLATIONS_NAMESPACE.to_string(),
        INSTALLATIONS_NAMESPACE.to_uppercase(),
    ] {
        assert!(bound
            .validate_deployment_output(&product.join(leaf))
            .is_err());
    }
    assert_eq!(fs::read_dir(&product).unwrap().count(), before);
    assert!(!product.join(INSTALLATIONS_NAMESPACE).exists());
    let sibling = product.join("deployment-data.json");
    let plan = bound.validate_deployment_output(&sibling).unwrap();
    write_deployment_output(plan, b"{}").unwrap();
    assert_eq!(read_deployment_data(&sibling).unwrap(), b"{}");
    assert!(!product.join(INSTALLATIONS_NAMESPACE).exists());
    let namespace = product.join(INSTALLATIONS_NAMESPACE);
    create_private_dir(&namespace).unwrap();
    assert!(bound
        .validate_deployment_output(&namespace.join("data.json"))
        .is_err());
    assert_eq!(fs::read_dir(namespace).unwrap().count(), 0);
}
