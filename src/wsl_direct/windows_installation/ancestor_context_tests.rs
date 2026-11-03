use super::*;
fn synthetic_descriptor(sddl: &str) -> Vec<u8> {
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
    let bytes = unsafe { std::slice::from_raw_parts(raw as *const u8, size as usize) }.to_vec();
    unsafe {
        LocalFree(raw);
    }
    bytes
}
#[test]
fn registration_content_write_append_and_deny_are_purpose_bound() {
    let context = AncestorAccessContext {
        owner: current_user().unwrap(),
        sam: None,
        observations: Vec::new(),
        group: None,
        issuer: None,
        verifier: None,
    };
    for rights in ["0x2", "0x4", "GW"] {
        let mut sd = synthetic_descriptor(&format!("O:BAG:BAD:P(A;;{rights};;;WD)"));
        assert!(assess_descriptor(
            &mut sd,
            &context,
            false,
            IntegrityPurpose::RegistrationContent
        )
        .is_err());
    }
    for rights in ["0x2", "0x4"] {
        let mut sd = synthetic_descriptor(&format!("O:BAG:BAD:P(A;;{rights};;;WD)"));
        assess_descriptor(&mut sd, &context, false, IntegrityPurpose::DirectoryEntry).unwrap();
        let mut sd =
            synthetic_descriptor(&format!("O:BAG:BAD:P(D;;{rights};;;WD)(A;;{rights};;;WD)"));
        assess_descriptor(
            &mut sd,
            &context,
            false,
            IntegrityPurpose::RegistrationContent,
        )
        .unwrap();
        let mut sd =
            synthetic_descriptor(&format!("O:BAG:BAD:P(A;;{rights};;;WD)(D;;{rights};;;WD)"));
        assert!(assess_descriptor(
            &mut sd,
            &context,
            false,
            IntegrityPurpose::RegistrationContent
        )
        .is_err());
    }
    let mut sd = synthetic_descriptor("O:BAG:BAD:P(D;;GW;;;WD)(A;;GW;;;WD)");
    assess_descriptor(
        &mut sd,
        &context,
        false,
        IntegrityPurpose::RegistrationContent,
    )
    .unwrap();
    let mut sd = synthetic_descriptor("O:BAG:BAD:P(A;IO;0x2;;;WD)");
    assess_descriptor(
        &mut sd,
        &context,
        false,
        IntegrityPurpose::RegistrationContent,
    )
    .unwrap();
}
#[test]
fn changed_or_extra_roster_and_role_mapping_do_not_keep_credit() {
    let a = Sid::parse("S-1-5-21-111-222-333-1001").unwrap();
    let b = Sid::parse("S-1-5-21-111-222-333-1002").unwrap();
    let c = Sid::parse("S-1-5-21-111-222-333-1003").unwrap();
    let roles = [a.clone(), b.clone()];
    let expected = vec![a.clone(), b.clone()];
    assert!(roster_unchanged(&roles, &roles, &expected, &expected));
    assert!(!roster_unchanged(
        &roles,
        &[a.clone(), c.clone()],
        &expected,
        &expected
    ));
    assert!(!roster_unchanged(&roles, &roles, &expected, &[a, b, c]));
    assert!(!roster_unchanged(&roles, &roles, &expected, &[]));
}
