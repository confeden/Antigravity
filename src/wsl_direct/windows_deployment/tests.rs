#[path = "../windows_installation/context_test_support.rs"]
mod support;
use super::*;
#[test]
fn registration_predicate_and_strict_codec_have_no_empty_or_label_credit() {
    assert!(!registration_interface(b""));
    assert!(!registration_interface(
        b"setup_marker.json offline_username online_username created_at read_roots"
    ));
    assert!(registration_interface(
        b"setup_marker.json offline_username online_username created_at read_roots write_roots"
    ));
    let valid=br#"{"version":5,"offline_username":"local-offline","online_username":"local-online","created_at":"synthetic","read_roots":[],"write_roots":[]}"#;
    assert!(marker(valid).is_ok());
    assert!(marker(b"").is_err());
    assert!(marker(&[&[0xef, 0xbb, 0xbf], valid.as_slice()].concat()).is_err());
    assert!(marker(br#"{"version":5,"version":5,"offline_username":"a","online_username":"b","created_at":"x","read_roots":[],"write_roots":[]}"#).is_err());
    assert!(marker(br#"{"version":4,"offline_username":"a","online_username":"b","created_at":"x","read_roots":[],"write_roots":[]}"#).is_err());
    assert!(marker(br#"{"version":5,"offline_username":"a","online_username":"a","created_at":"x","read_roots":[],"write_roots":[]}"#).is_err());
    assert!(roles(PROVIDER, &[]).is_err());
    assert!(roles("label-only", &["offline".into(), "online".into()]).is_err());
}
#[test]
#[ignore = "explicit current-host DATA/desktop and owned capture root; no app/state effects"]
fn carrier_omission_and_early_drift_receive_no_locator_or_scope_credit() {
    let desktop = std::env::var_os("AG_CONTEXT_DESKTOP").expect("explicit desktop");
    let source = std::env::var_os("AG_CONTEXT_DATA").expect("explicit DATA");
    let parent = std::env::var_os("AG_CONTEXT_FIXTURE_PARENT").expect("explicit own parent");
    let root = owner::context_fixture_directory(Path::new(&parent)).unwrap();
    support::record_root(&root, Path::new(&parent));
    let bound = BoundInstallation::open(Path::new(&desktop)).unwrap();
    let bytes = owner::read_deployment_data(Path::new(&source)).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut missing = original.clone();
    missing.as_object_mut().unwrap().remove("ownerSid");
    assert!(decode::<Carrier>(&json(&missing).unwrap()).is_err());
    let mut extra = original.clone();
    extra["approval"] = true.into();
    assert!(decode::<Carrier>(&json(&extra).unwrap()).is_err());
    let duplicate = String::from_utf8(json(&original).unwrap())
        .unwrap()
        .replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1);
    assert!(decode::<Carrier>(duplicate.as_bytes()).is_err());
    for (field, value) in [
        ("ownerSid", "S-1-0-0"),
        ("machineAccountDomainSid", "S-1-5-21-1-2-3"),
    ] {
        let mut wrong = original.clone();
        wrong[field] = value.into();
        wrong["marker"]["path"] = root
            .join("never-opened-marker.json")
            .to_str()
            .unwrap()
            .into();
        let path = root.join(format!("{field}.json"));
        owner::write_deployment_data(&path, &json(&wrong).unwrap()).unwrap();
        assert!(receive(&bound, &path)
            .err()
            .unwrap()
            .contains("before locators"));
    }
    let mut drift = original.clone();
    drift["marker"]["nativeId"]["file"][0] =
        serde_json::json!((drift["marker"]["nativeId"]["file"][0].as_u64().unwrap() + 1) % 256);
    let path = root.join("native-drift.json");
    owner::write_deployment_data(&path, &json(&drift).unwrap()).unwrap();
    assert!(receive(&bound, &path)
        .err()
        .unwrap()
        .contains("native identity drift"));
    let mut drift = original.clone();
    drift["marker"]["selectedFieldsSha256"] = "wrong-selected-fields".into();
    let path = root.join("marker-drift.json");
    owner::write_deployment_data(&path, &json(&drift).unwrap()).unwrap();
    assert!(receive(&bound, &path)
        .err()
        .unwrap()
        .contains("selected-field drift"));
    let mut drift = original;
    drift["roleSids"]["online"] = "S-1-0-0".into();
    let path = root.join("role-drift.json");
    owner::write_deployment_data(&path, &json(&drift).unwrap()).unwrap();
    assert!(receive(&bound, &path)
        .err()
        .unwrap()
        .contains("role/group binding drift"));
}
#[test]
#[ignore = "explicit current-host readonly DATA carrier/desktop; no canonical operation"]
fn actual_carrier_standalone_readonly_requalification() {
    let desktop = std::env::var_os("AG_CONTEXT_DESKTOP").expect("explicit readonly desktop");
    let data = std::env::var_os("AG_CONTEXT_DATA").expect("explicit private deployment DATA");
    let mut bound = BoundInstallation::open(Path::new(&desktop)).unwrap();
    assert!(
        bound.receive_state_parents_readonly().is_err(),
        "omission must receive no delegate/issuer credit on this selected host"
    );
    let before = hash(bound.bytes());
    let context = receive(&bound, Path::new(&data)).unwrap();
    bound.attach_ancestor_context(context).unwrap();
    bound.receive_state_parents_readonly().unwrap();
    drop(bound);
    let mut fresh = BoundInstallation::open(Path::new(&desktop)).unwrap();
    let context = receive(&fresh, Path::new(&data)).unwrap();
    fresh.attach_ancestor_context(context).unwrap();
    fresh.receive_state_parents_readonly().unwrap();
    assert_eq!(hash(fresh.bytes()), before);
    eprintln!("fresh standalone DATA requalification and common-owner R0 accepted; no canonical/native/application operation");
}
