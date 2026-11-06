use super::*;
#[test]
fn issuer_credit_disappears_with_matching_or_incomplete_deployment_class() {
    let sam = Sid::parse("S-1-5-21-1-2-3").unwrap();
    let foreign = Sid::parse("S-1-5-21-4-5-6-1001").unwrap();
    let snapshot = IssuerSnapshot {
        sam: sam.clone(),
        primary: None,
        trusts: Vec::new(),
        join: 2,
        aad_present: false,
    };
    assert!(snapshot.no_current_issuer(&foreign));
    let mut changed = snapshot.clone();
    changed.primary = Some(foreign.domain().unwrap());
    assert!(!changed.no_current_issuer(&foreign));
    let mut changed = snapshot.clone();
    changed.trusts.push(foreign.domain().unwrap());
    assert!(!changed.no_current_issuer(&foreign));
    let mut changed = snapshot.clone();
    changed.aad_present = true;
    assert!(!changed.no_current_issuer(&foreign));
    let mut changed = snapshot;
    changed.join = 0;
    assert!(!changed.no_current_issuer(&foreign));
    assert!(!changed.no_current_issuer(&sam));
}
