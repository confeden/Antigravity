//! Existing package siblings received against immutable build/source inputs.
use super::*;
const INSTALLER: &[u8] = include_bytes!("../../../wsl/install-helper.sh");

pub(crate) struct PackageAssets {
    helper: CheckedPath,
    manifest: CheckedPath,
    installer: CheckedPath,
    expected_helper: String,
}
impl PackageAssets {
    pub(crate) fn receive(host: &CheckedPath, expected_helper: Option<&str>) -> Result<Self> {
        let expected = expected_helper.filter(|value| value.len() == 64
            && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .ok_or("PackageIncomplete: this host has no received Linux helper build input")?;
        host.recheck()?;
        let parent = host.path.parent().ok_or("PackageIncomplete: host package parent absent")?;
        let helper = CheckedPath::open(&parent.join("ag_wsl_launch"), PathKind::File, PathPurpose::Source)
            .map_err(|e| format!("PackageIncomplete: Linux helper absent/unreceived: {e}"))?;
        let manifest = CheckedPath::open(&parent.join("helper.sha256"), PathKind::File, PathPurpose::Source)
            .map_err(|e| format!("PackageIncomplete: Linux helper manifest absent/unreceived: {e}"))?;
        let installer = CheckedPath::open(&parent.join("install-helper.sh"), PathKind::File, PathPurpose::Source)
            .map_err(|e| format!("PackageIncomplete: Linux helper installer absent/unreceived: {e}"))?;
        let result = Self { helper, manifest, installer, expected_helper: expected.to_owned() };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        for value in [&self.helper, &self.manifest, &self.installer] { value.recheck()?; }
        let manifest = self.manifest.read_snapshot()?;
        let manifest = std::str::from_utf8(&manifest).map_err(|_| "PackageIncomplete: helper manifest encoding")?;
        if manifest.trim() != self.expected_helper || hash(&self.helper.read_snapshot()?) != self.expected_helper
            || self.installer.read_snapshot()? != INSTALLER {
            return Err("PackageIncomplete: helper or source-owned installer binding differs".into());
        }
        Ok(())
    }
    pub(crate) fn helper_path(&self) -> &Path { &self.helper.path }
    pub(crate) fn installer_path(&self) -> &Path { &self.installer.path }
    pub(crate) fn helper_digest(&self) -> &str { &self.expected_helper }
    pub(super) fn deploy(&self, directory: &Path) -> Result<()> {
        self.recheck()?;
        for (name, source) in [("ag_wsl_launch", &self.helper), ("helper.sha256", &self.manifest),
            ("install-helper.sh", &self.installer)] {
            write_private(&directory.join(name), &source.read_snapshot()?)?;
        }
        self.recheck()
    }
}
