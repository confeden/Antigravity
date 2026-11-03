//! Test-only receiving of actual created fixture identities, before test effects.
use crate::windows_coordinator::windows_installation as owner;
use std::path::Path;
pub(super) fn record_root(path: &Path, parent: &Path) {
    let root =
        owner::CheckedPath::open(path, owner::PathKind::Directory, owner::PathPurpose::Review)
            .unwrap();
    let parent = owner::CheckedPath::open(
        parent,
        owner::PathKind::Directory,
        owner::PathPurpose::Review,
    )
    .unwrap();
    let facts = serde_json::json!({"schema":1,"kind":"owned-context-test-root","path":root.as_path(),"nativeId":root.native_id(),"callerParentNativeId":parent.native_id()});
    owner::write_deployment_data(
        &path.join("fixture-root-facts.json"),
        &serde_json::to_vec(&facts).unwrap(),
    )
    .unwrap();
    eprintln!(
        "OWN_CONTEXT_FIXTURE_ROOT {}",
        serde_json::to_string(&facts).unwrap()
    );
}
