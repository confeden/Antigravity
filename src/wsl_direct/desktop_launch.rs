//! Pure future Desktop command construction; no discovery, launch or target mutation.
#![cfg(windows)]

use super::child_environment::{
    plan_child_environment, plan_hook_environment, EnvironmentError, RoutingUncertainty,
};
use super::windows_installation::WindowsExecutablePath;
use std::ffi::OsString;
use std::net::SocketAddrV4;
use std::os::windows::ffi::OsStrExt;
use std::process::Command;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DesktopCommandError {
    InvalidExecutable,
    InvalidDistro,
    InvalidEnvironment,
    AmbiguousEnvironment,
    Environment(EnvironmentError),
}

/// No Debug: the command retains the caller's potentially sensitive environment.
pub(crate) struct DesktopCommandPlan {
    pub command: Command,
    pub routing_uncertainty: RoutingUncertainty,
}

/// Caller verifies this exact executable/producer, selected registered distro and
/// retained actual gateway endpoint. This builder does not establish those facts,
/// clean-start authority, singleton absence, writer exclusion or model success.
/// The supplied snapshot replaces ambient inheritance only in this unspawned command.
pub(crate) fn plan_desktop_command(
    executable: &WindowsExecutablePath,
    distro: &str,
    inherited: &[(OsString, OsString)],
    endpoint: SocketAddrV4,
) -> Result<DesktopCommandPlan, DesktopCommandError> {
    plan_command(executable, distro, inherited, endpoint, None)
}

/// The caller separately verifies the installed hook and immutable Linux helper.
pub(crate) fn plan_hook_desktop_command(
    executable: &WindowsExecutablePath,
    distro: &str,
    inherited: &[(OsString, OsString)],
    endpoint: SocketAddrV4,
    launcher: &str,
) -> Result<DesktopCommandPlan, DesktopCommandError> {
    plan_command(executable, distro, inherited, endpoint, Some(launcher))
}

fn plan_command(
    executable: &WindowsExecutablePath,
    distro: &str,
    inherited: &[(OsString, OsString)],
    endpoint: SocketAddrV4,
    launcher: Option<&str>,
) -> Result<DesktopCommandPlan, DesktopCommandError> {
    if distro.trim().is_empty() || distro.chars().any(char::is_control) {
        return Err(DesktopCommandError::InvalidDistro);
    }
    let environment = match launcher {
        Some(path) => plan_hook_environment(inherited, endpoint, path),
        None => plan_child_environment(inherited, endpoint),
    }
    .map_err(DesktopCommandError::Environment)?;
    for (key, value) in environment.environment() {
        if key.is_empty()
            || key.encode_wide().any(|c| c == 0 || c == 61)
            || value.encode_wide().any(|c| c == 0)
        {
            return Err(DesktopCommandError::InvalidEnvironment);
        }
    }
    let mut command = Command::new(executable.as_path());
    command.arg(format!("--wsl-distro={distro}"));
    command
        .env_clear()
        .envs(environment.environment().iter().map(|(k, v)| (k, v)));
    // std owns Windows key comparison. Reject lossy duplicate snapshot entries.
    if command.get_envs().count() != environment.environment().len() {
        return Err(DesktopCommandError::AmbiguousEnvironment);
    }
    Ok(DesktopCommandPlan {
        command,
        routing_uncertainty: environment.routing_uncertainty,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStringExt;

    fn endpoint() -> SocketAddrV4 {
        SocketAddrV4::new([192, 0, 2, 10].into(), 54321)
    }
    fn executable() -> WindowsExecutablePath {
        WindowsExecutablePath::parse(OsStr::new(r"C:\Selected Desktop\Desktop.EXE")).unwrap()
    }
    fn build(env: &[(OsString, OsString)]) -> Result<DesktopCommandPlan, DesktopCommandError> {
        plan_desktop_command(&executable(), "Selected Distro", env, endpoint())
    }

    #[test]
    fn exact_program_single_argument_and_received_environment() {
        let opaque = OsString::from_wide(&[0xd800, 65]);
        let inherited = vec![
            ("WSLENV".into(), "FOREIGN/pl:OTHER/u".into()),
            ("AG_LS_PROXY".into(), "native-value".into()),
            ("NO_PROXY".into(), "".into()),
            ("FOREIGN".into(), opaque.clone()),
        ];
        let before = inherited.clone();
        let distro = "Selected Distro; \"quoted\" --other=value";
        let plan = plan_desktop_command(&executable(), distro, &inherited, endpoint()).unwrap();
        assert_eq!(
            plan.command.get_program(),
            executable().as_path().as_os_str()
        );
        assert_eq!(
            plan.command.get_args().collect::<Vec<_>>(),
            [OsStr::new(
                "--wsl-distro=Selected Distro; \"quoted\" --other=value"
            )]
        );
        let entries: Vec<_> = plan.command.get_envs().collect();
        for (key, value) in &inherited {
            if key != "WSLENV" {
                assert!(entries.contains(&(key.as_os_str(), Some(value.as_os_str()))));
            }
        }
        assert!(entries.contains(&(
            OsStr::new("WSLENV"),
            Some(OsStr::new("FOREIGN/pl:OTHER/u:AG_WSLPROXY/u"))
        )));
        assert!(entries.contains(&(
            OsStr::new("AG_WSLPROXY"),
            Some(OsStr::new("http://192.0.2.10:54321"))
        )));
        assert!(plan.routing_uncertainty.no_proxy_present);
        assert!(!plan.routing_uncertainty.https_proxy_present);
        assert_eq!(inherited, before);
        assert!(plan.command.get_current_dir().is_none());
    }

    #[test]
    fn rejects_unsafe_or_missing_command_inputs() {
        for path in [
            "",
            "Desktop.exe",
            r"C:Desktop.exe",
            r"\Desktop.exe",
            r"C:\Desktop.cmd",
            r"C:\a\..\Desktop.exe",
            "C:\\bad\0.exe",
            "C:\\bad\".exe",
        ] {
            assert_eq!(
                WindowsExecutablePath::parse(OsStr::new(path))
                    .err()
                    .map(|_| DesktopCommandError::InvalidExecutable),
                Some(DesktopCommandError::InvalidExecutable)
            );
        }
        for distro in ["", "  ", "Distro\0", "Distro\n", "Distro\t"] {
            assert_eq!(
                plan_desktop_command(&executable(), distro, &[], endpoint()).err(),
                Some(DesktopCommandError::InvalidDistro)
            );
        }
    }

    #[test]
    fn hook_uses_same_structured_desktop_argument_and_windows_only_selector() {
        let plan = plan_hook_desktop_command(
            &executable(),
            "Selected Distro",
            &[],
            endpoint(),
            "/test-fixtures/home/selected/helper/launch",
        )
        .unwrap();
        assert_eq!(
            plan.command.get_args().collect::<Vec<_>>(),
            [OsStr::new("--wsl-distro=Selected Distro")]
        );
        let entries: Vec<_> = plan.command.get_envs().collect();
        assert!(entries.contains(&(
            OsStr::new("AG_WSL_LAUNCHER"),
            Some(OsStr::new("/test-fixtures/home/selected/helper/launch"))
        )));
        assert!(entries.contains(&(OsStr::new("WSLENV"), Some(OsStr::new("AG_WSLPROXY/u")))));
    }

    #[test]
    fn rejects_invalid_or_lossy_environment_without_values_in_errors() {
        for (key, value) in [("", "v"), ("A=B", "v"), ("A\0", "v"), ("A", "v\0")] {
            assert_eq!(
                build(&[(key.into(), value.into())]).err(),
                Some(DesktopCommandError::InvalidEnvironment)
            );
        }
        assert_eq!(
            build(&[
                ("Foreign".into(), "a".into()),
                ("FOREIGN".into(), "b".into())
            ])
            .err(),
            Some(DesktopCommandError::AmbiguousEnvironment)
        );
        assert_eq!(
            build(&[("AG_WSLPROXY".into(), "different".into())]).err(),
            Some(DesktopCommandError::Environment(
                EnvironmentError::PrivateValueConflict
            ))
        );
        assert_eq!(
            build(&[("WSLENV".into(), "AG_WSLPROXY/p".into())]).err(),
            Some(DesktopCommandError::Environment(
                EnvironmentError::PrivateTransferConflict
            ))
        );
        assert_eq!(
            plan_desktop_command(
                &executable(),
                "Distro",
                &[],
                SocketAddrV4::new([0, 0, 0, 0].into(), 0)
            )
            .err(),
            Some(DesktopCommandError::Environment(
                EnvironmentError::InvalidEndpoint
            ))
        );
    }
}
