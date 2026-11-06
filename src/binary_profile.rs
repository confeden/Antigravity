//! Pure binary profile transforms shared by native maintenance and the private Linux launcher.

pub(crate) fn replace_all(data: &mut [u8], from: &[u8], to: &[u8]) -> usize {
    debug_assert_eq!(from.len(), to.len());
    if data.len() < from.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + from.len() <= data.len() {
        if &data[i..i + from.len()] == from {
            data[i..i + to.len()].copy_from_slice(to);
            count += 1;
            i += from.len();
        } else {
            i += 1;
        }
    }
    count
}

pub(crate) fn count_occurrences(data: &[u8], needle: &[u8]) -> usize {
    if data.len() < needle.len() {
        return 0;
    }
    (0..=data.len() - needle.len())
        .filter(|&i| &data[i..i + needle.len()] == needle)
        .count()
}

/// The field name rewrites stored in obfuscated literals.
pub(crate) fn field_signatures() -> ([u8; 10], [u8; 10]) {
    obfstr::obfstr! {
        let from = "ineligible";
        let to = "inexigible";
    }
    let mut f = [0u8; 10];
    let mut t = [0u8; 10];
    f.copy_from_slice(from.as_bytes());
    t.copy_from_slice(to.as_bytes());
    (f, t)
}

/// The original proxy variable name stored in an obfuscated literal.
pub(crate) fn proxy_var_original() -> [u8; 11] {
    obfstr::obfstr! {
        let proxy_from = "https_proxy";
    }
    let mut p = [0u8; 11];
    p.copy_from_slice(proxy_from.as_bytes());
    p
}

pub const PROXY_VAR_NEW: &str = "AG_LS_PROXY";

/// An explicit proxy channel for a prepared, in-memory patch.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PatchProfile {
    Default,
    Wsl,
    WslSelective { eligibility: bool, transport: bool },
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProfilePreparation {
    Prepared(Vec<u8>),
    AlreadyApplied,
    Unsupported,
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProfileError {
    Ambiguous,
    EmptySelection,
}

/// Prepare only selected substitutions; the input and unselected fields remain unchanged.
#[allow(dead_code)]
pub(crate) fn prepare_profile(
    input: &[u8],
    profile: PatchProfile,
) -> Result<ProfilePreparation, ProfileError> {
    const WSL_PROXY: &[u8; 11] = b"AG_WSLPROXY";
    let (field_original, field_applied) = field_signatures();
    let proxy_original = proxy_var_original();
    let (proxy_applied, proxy_foreign, eligibility, transport): (&[u8], &[u8], bool, bool) = match profile {
        PatchProfile::Default => (PROXY_VAR_NEW.as_bytes(), WSL_PROXY, true, true),
        PatchProfile::Wsl => (WSL_PROXY, PROXY_VAR_NEW.as_bytes(), true, true),
        PatchProfile::WslSelective { eligibility, transport } => (WSL_PROXY, PROXY_VAR_NEW.as_bytes(), eligibility, transport),
    };
    if !eligibility && !transport { return Err(ProfileError::EmptySelection); }
    let field_old = count_occurrences(input, &field_original);
    let field_new = count_occurrences(input, &field_applied);
    let proxy_old = count_occurrences(input, &proxy_original);
    let proxy_new = count_occurrences(input, proxy_applied);
    let foreign = count_occurrences(input, proxy_foreign);

    if (if eligibility { field_old + field_new } else { 0 })
        + (if transport { proxy_old + proxy_new + foreign } else { 0 }) == 0 {
        return Ok(ProfilePreparation::Unsupported);
    }
    if transport && foreign != 0 {
        return Err(ProfileError::Ambiguous);
    }
    if (!eligibility || (field_old > 0 && field_new == 0)) && (!transport || (proxy_old > 0 && proxy_new == 0)) {
        let mut candidate = input.to_vec();
        if eligibility { replace_all(&mut candidate, &field_original, &field_applied); }
        if transport { replace_all(&mut candidate, &proxy_original, proxy_applied); }
        return Ok(ProfilePreparation::Prepared(candidate));
    }
    if (!eligibility || (field_old == 0 && field_new > 0)) && (!transport || (proxy_old == 0 && proxy_new > 0)) {
        return Ok(ProfilePreparation::AlreadyApplied);
    }
    Err(ProfileError::Ambiguous)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selective_wsl_profiles_preserve_every_unselected_byte() {
        let input = b"ineligible|https_proxy|HTTPS_PROXY";
        for (eligibility, transport, expected) in [
            (false, true, &b"ineligible|AG_WSLPROXY|HTTPS_PROXY"[..]),
            (true, false, &b"inexigible|https_proxy|HTTPS_PROXY"[..]),
        ] {
            let profile = PatchProfile::WslSelective { eligibility, transport };
            assert_eq!(prepare_profile(input, profile), Ok(ProfilePreparation::Prepared(expected.to_vec())));
            assert_eq!(prepare_profile(expected, profile), Ok(ProfilePreparation::AlreadyApplied));
        }
        assert_eq!(prepare_profile(input, PatchProfile::WslSelective { eligibility: false, transport: false }), Err(ProfileError::EmptySelection));
        assert_eq!(input, b"ineligible|https_proxy|HTTPS_PROXY");
    }
    #[test]
    fn profile_preparer_transforms_and_recognizes_complete_profiles() {
        let original = b"..ineligible..https_proxy..ineligible..https_proxy..HTTPS_PROXY";
        for (profile, expected) in [
            (
                PatchProfile::Wsl,
                &b"..inexigible..AG_WSLPROXY..inexigible..AG_WSLPROXY..HTTPS_PROXY"[..],
            ),
            (
                PatchProfile::Default,
                &b"..inexigible..AG_LS_PROXY..inexigible..AG_LS_PROXY..HTTPS_PROXY"[..],
            ),
        ] {
            let candidate = match prepare_profile(original, profile) {
                Ok(ProfilePreparation::Prepared(candidate)) => candidate,
                other => panic!("expected candidate, got {other:?}"),
            };
            assert_eq!(candidate, expected);
            assert_eq!(candidate.len(), original.len());
            assert_eq!(
                prepare_profile(&candidate, profile),
                Ok(ProfilePreparation::AlreadyApplied)
            );
        }
        assert_eq!(
            original,
            b"..ineligible..https_proxy..ineligible..https_proxy..HTTPS_PROXY"
        );
    }

    #[test]
    fn profile_preparer_rejects_missing_partial_mixed_and_foreign_states() {
        for input in [&b""[..], &b"unknown"[..]] {
            assert_eq!(
                prepare_profile(input, PatchProfile::Wsl),
                Ok(ProfilePreparation::Unsupported)
            );
        }
        for input in [
            &b"ineligible"[..],
            &b"https_proxy"[..],
            &b"ineligible..AG_WSLPROXY"[..],
            &b"inexigible..https_proxy"[..],
            &b"ineligible..inexigible..https_proxy"[..],
            &b"ineligible..https_proxy..AG_WSLPROXY"[..],
            &b"inexigible..AG_LS_PROXY"[..],
            &b"ineligible..https_proxy..AG_LS_PROXY"[..],
        ] {
            let before = input.to_vec();
            assert_eq!(
                prepare_profile(input, PatchProfile::Wsl),
                Err(ProfileError::Ambiguous)
            );
            assert_eq!(input, before);
        }
        assert_eq!(
            prepare_profile(b"inexigible..AG_WSLPROXY", PatchProfile::Default),
            Err(ProfileError::Ambiguous)
        );
    }
}
