//! Concrete handoff between admission/preparation and the retained owner.
use crate::settings::Settings;
use crate::windows_coordinator::{vendor_launch::VendorWslLaunch, session,
    windows_installation::{CheckedPath, NativeObjectId, RuntimeRead, VendorLane}};
use std::ffi::OsString;
use std::net::SocketAddrV4;
use std::process::Command;

pub(crate) enum VendorAdmission {
    PassThrough { program: CheckedPath, launch: VendorWslLaunch, lane: VendorLane },
    Selected { read: RuntimeRead, lane: VendorLane, preparation: RuntimePreparationInput },
}

pub(crate) struct RuntimePreparationInput {
    pub(super) launch: VendorWslLaunch,
    pub(super) settings: Settings,
    pub(super) host_path: std::path::PathBuf,
    pub(super) host_native_id: NativeObjectId,
    pub(super) host_sha256: String,
    pub(super) revision: u64,
}

pub(crate) struct RuntimeRecipe {
    pub(crate) gateway: Option<session::SessionSpec>,
    pub(super) program: CheckedPath,
    pub(super) launch: VendorWslLaunch,
    pub(super) launcher: String,
    pub(super) eligibility: bool,
    pub(super) transport: bool,
    pub(super) automatic: bool,
}
impl RuntimeRecipe {
    /// Only the final actual WSL consumer receives the original streams. All
    /// preparation is already received through private metadata channels.
    pub(crate) fn command(&self, endpoint: Option<SocketAddrV4>, inherited: &[(OsString, OsString)]) -> Result<Command, String> {
        self.program.recheck()?;
        let mut command = Command::new(self.program.as_path());
        command.args(["-d", &self.launch.distro, "--exec", "sh", "-c",
            r#"agLauncher=$1; agEligibility=$2; agTransport=$3; agAutomatic=$4; agVersion=$5; shift 5; ANTIGRAVITY_VSCODE_HOST=1 exec "$agLauncher" --vendor-serve --profile "$agEligibility" "$agTransport" "$agAutomatic" "$HOME/.antigravity-server/bin/$agVersion/language_server" -- "$@""#,
            "sh", &self.launcher, if self.eligibility { "1" } else { "0" },
            if self.transport { "1" } else { "0" }, if self.automatic { "1" } else { "0" }, &self.launch.server_version]);
        command.args(&self.launch.server_args);
        if self.transport {
            let plan = crate::windows_coordinator::child_environment::plan_child_environment(inherited,
                endpoint.ok_or("received gateway endpoint required")?).map_err(|_| "private WSL environment binding conflict")?;
            command.env_clear().envs(plan.environment().iter().cloned());
        } else {
            if endpoint.is_some() { return Err("unselected transport endpoint".into()); }
            command.env_clear().envs(inherited.iter().cloned());
        }
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
        Ok(command)
    }
}

pub(crate) fn passthrough_command(program: &CheckedPath, launch: &VendorWslLaunch) -> Result<Command, String> {
    program.recheck()?;
    let mut command = Command::new(program.as_path());
    command.args(["-d", &launch.distro, "--exec", "sh", "-c",
        r#"agVersion=$1; shift; ANTIGRAVITY_VSCODE_HOST=1 exec "$HOME/.antigravity-server/bin/$agVersion/language_server" "$@""#,
        "sh", &launch.server_version]).args(&launch.server_args);
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000);
    Ok(command)
}
