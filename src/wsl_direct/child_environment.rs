//! Pure Windows future-child environment plan; does not launch or read environment.
#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::net::SocketAddrV4;
use std::process::Command;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EnvironmentError {
    InvalidEndpoint,
    AmbiguousPrivateEntry,
    PrivateValueConflict,
    PrivateTransferConflict,
    TransferEncoding,
    InvalidLauncher,
}

/// Presence only: vendor precedence, bypass and actual child inheritance remain unverified.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct RoutingUncertainty {
    pub https_proxy_present: bool,
    pub no_proxy_present: bool,
}

/// No Debug: inherited values may contain unrelated sensitive settings.
pub(crate) struct ChildEnvironmentPlan {
    environment: Vec<(OsString, OsString)>,
    pub routing_uncertainty: RoutingUncertainty,
}
impl ChildEnvironmentPlan {
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }
}

fn same_key(key: &OsStr, canonical: &str) -> bool {
    // Reuse std's actual Windows environment-key comparison, including Unicode.
    // This builder is never executed and never reads the process environment.
    let mut keys = Command::new("");
    keys.env(key, "").env(canonical, "");
    keys.get_envs().count() == 1
}

/// Session/launch owner supplies its independently validated, retained actual endpoint.
/// This leaf checks URL shape only; it proves neither topology nor Desktop/server route.
pub(crate) fn plan_child_environment(
    inherited: &[(OsString, OsString)],
    endpoint: SocketAddrV4,
) -> Result<ChildEnvironmentPlan, EnvironmentError> {
    let ip = endpoint.ip();
    if endpoint.port() == 0 || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return Err(EnvironmentError::InvalidEndpoint);
    }
    let mut proxy = None;
    let mut transfer = None;
    let mut uncertainty = RoutingUncertainty::default();
    for (index, (key, _)) in inherited.iter().enumerate() {
        if same_key(key, "AG_WSLPROXY") && proxy.replace(index).is_some() {
            return Err(EnvironmentError::AmbiguousPrivateEntry);
        }
        if same_key(key, "WSLENV") && transfer.replace(index).is_some() {
            return Err(EnvironmentError::AmbiguousPrivateEntry);
        }
        uncertainty.https_proxy_present |= same_key(key, "HTTPS_PROXY");
        uncertainty.no_proxy_present |= same_key(key, "NO_PROXY");
    }
    let url = OsString::from(format!("http://{endpoint}"));
    if proxy.is_some_and(|index| inherited[index].1 != url) {
        return Err(EnvironmentError::PrivateValueConflict);
    }
    let existing = match transfer {
        Some(index) => inherited[index]
            .1
            .to_str()
            .ok_or(EnvironmentError::TransferEncoding)?,
        None => "",
    };
    let mut private_transfer = false;
    for entry in existing.split(':') {
        let name = entry.split_once('/').map_or(entry, |(name, _)| name);
        if same_key(OsStr::new(name), "AG_WSLPROXY") {
            if private_transfer {
                return Err(EnvironmentError::AmbiguousPrivateEntry);
            }
            if entry != "AG_WSLPROXY/u" {
                return Err(EnvironmentError::PrivateTransferConflict);
            }
            private_transfer = true;
        }
    }
    let merged = if private_transfer {
        existing.to_owned()
    } else {
        let separator = if existing.is_empty() || existing.ends_with(':') {
            ""
        } else {
            ":"
        };
        format!("{existing}{separator}AG_WSLPROXY/u")
    };
    let mut environment = inherited.to_vec();
    if proxy.is_none() {
        environment.push(("AG_WSLPROXY".into(), url));
    }
    match transfer {
        Some(index) => environment[index].1 = merged.into(),
        None => environment.push(("WSLENV".into(), merged.into())),
    }
    Ok(ChildEnvironmentPlan {
        environment,
        routing_uncertainty: uncertainty,
    })
}

/// Add the Windows-only producer selector. It is passed by JavaScript as argv,
/// never through WSLENV. Keep the existing proxy-plan owner and key semantics.
pub(crate) fn plan_hook_environment(
    inherited: &[(OsString, OsString)],
    endpoint: SocketAddrV4,
    launcher: &str,
) -> Result<ChildEnvironmentPlan, EnvironmentError> {
    if !valid_launcher(launcher) {
        return Err(EnvironmentError::InvalidLauncher);
    }
    let mut found = false;
    for (key, value) in inherited {
        if same_key(key, "AG_WSL_LAUNCHER") {
            if found {
                return Err(EnvironmentError::AmbiguousPrivateEntry);
            }
            found = true;
            if value != OsStr::new(launcher) {
                return Err(EnvironmentError::PrivateValueConflict);
            }
        }
        if same_key(key, "WSLENV") {
            let value = value.to_str().ok_or(EnvironmentError::TransferEncoding)?;
            if value.split(':').any(|entry| {
                let name = entry.split_once('/').map_or(entry, |(name, _)| name);
                same_key(OsStr::new(name), "AG_WSL_LAUNCHER")
            }) {
                return Err(EnvironmentError::PrivateTransferConflict);
            }
        }
    }
    let mut plan = plan_child_environment(inherited, endpoint)?;
    if !found {
        plan.environment
            .push(("AG_WSL_LAUNCHER".into(), launcher.into()));
    }
    Ok(plan)
}

pub(crate) fn valid_launcher(launcher: &str) -> bool {
    launcher.starts_with('/')
        && launcher != "/"
        && !launcher.chars().any(char::is_control)
        && !launcher[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    fn endpoint() -> SocketAddrV4 {
        SocketAddrV4::new([192, 0, 2, 10].into(), 54321)
    }
    fn env(values: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        values.iter().map(|(k, v)| (k.into(), v.into())).collect()
    }
    fn value<'a>(plan: &'a ChildEnvironmentPlan, key: &str) -> &'a OsStr {
        &plan.environment().iter().find(|(k, _)| k == key).unwrap().1
    }

    #[test]
    fn missing_empty_and_foreign_transfer_settings_are_preserved() {
        for inherited in [
            env(&[]),
            env(&[("WSLENV", "")]),
            env(&[("WSLENV", "KEEP/plw:AG_LS_PROXY/u:Other/unknown:")]),
        ] {
            let original = inherited.clone();
            let plan = plan_child_environment(&inherited, endpoint()).unwrap();
            assert_eq!(inherited, original);
            assert_eq!(value(&plan, "AG_WSLPROXY"), "http://192.0.2.10:54321");
            let expected = if original.first().is_some_and(|(_, v)| !v.is_empty()) {
                "KEEP/plw:AG_LS_PROXY/u:Other/unknown:AG_WSLPROXY/u"
            } else {
                "AG_WSLPROXY/u"
            };
            assert_eq!(value(&plan, "WSLENV"), expected);
            assert_eq!(plan.routing_uncertainty, RoutingUncertainty::default());
        }
    }

    #[test]
    fn foreign_values_are_opaque_and_presence_does_not_claim_precedence() {
        let mut inherited = env(&[
            ("AG_LS_PROXY", "native-marker"),
            ("https_proxy", ""),
            ("NO_PROXY", "opaque-bypass"),
            ("WSLENV", "FOREIGN/p"),
        ]);
        inherited.push(("OPAQUE".into(), OsString::from_wide(&[0xd800])));
        let plan = plan_child_environment(&inherited, endpoint()).unwrap();
        for i in [0, 1, 2, 4] {
            assert_eq!(plan.environment()[i], inherited[i]);
        }
        assert!(plan.routing_uncertainty.https_proxy_present);
        assert!(plan.routing_uncertainty.no_proxy_present);
    }

    #[test]
    fn identical_private_plan_is_idempotent() {
        let inherited = env(&[
            ("AG_WSLPROXY", "http://192.0.2.10:54321"),
            ("WSLENV", "KEEP/u:AG_WSLPROXY/u"),
        ]);
        assert_eq!(
            plan_child_environment(&inherited, endpoint())
                .unwrap()
                .environment(),
            inherited.as_slice()
        );
    }

    #[test]
    fn private_conflicts_and_case_insensitive_duplicates_fail_closed() {
        let bad = [
            env(&[("ag_wslproxy", "other")]),
            env(&[("AG_WSLPROXY", "same"), ("ag_wslproxy", "same")]),
            env(&[("WSLENV", ""), ("wslenv", "")]),
            env(&[("WSLENV", "AG_WSLPROXY/p")]),
            env(&[("WSLENV", "AG_WSLPROXY")]),
            env(&[("WSLENV", "ag_wslproxy/u")]),
            env(&[("WSLENV", "AG_WSLPROXY/u:AG_WSLPROXY/u")]),
        ];
        for inherited in bad {
            assert!(plan_child_environment(&inherited, endpoint()).is_err());
        }
    }

    #[test]
    fn unusable_endpoint_or_unmergeable_transfer_list_is_rejected() {
        for endpoint in [
            SocketAddrV4::new([0, 0, 0, 0].into(), 1),
            SocketAddrV4::new([224, 0, 0, 1].into(), 1),
            SocketAddrV4::new([255, 255, 255, 255].into(), 1),
            SocketAddrV4::new([192, 0, 2, 10].into(), 0),
        ] {
            assert!(plan_child_environment(&[], endpoint).is_err());
        }
        assert!(plan_child_environment(
            &[("WSLENV".into(), OsString::from_wide(&[0xd800]))],
            endpoint()
        )
        .is_err());
    }

    #[test]
    fn hook_selector_is_child_only_and_conflicts_fail_closed() {
        let inherited = env(&[("HTTPS_PROXY", "opaque"), ("WSLENV", "KEEP/p")]);
        let launcher = "/test-fixtures/home/selected/helper digest/launch";
        let plan = plan_hook_environment(&inherited, endpoint(), launcher).unwrap();
        assert_eq!(value(&plan, "AG_WSL_LAUNCHER"), launcher);
        assert_eq!(value(&plan, "WSLENV"), "KEEP/p:AG_WSLPROXY/u");
        assert_eq!(value(&plan, "HTTPS_PROXY"), "opaque");
        assert!(plan.routing_uncertainty.https_proxy_present);
        assert_eq!(
            plan_hook_environment(plan.environment(), endpoint(), launcher)
                .unwrap()
                .environment(),
            plan.environment()
        );
        for bad in ["", "/", "relative", "/a/../b", "/a//b", "/a\n"] {
            assert!(plan_hook_environment(&[], endpoint(), bad).is_err());
        }
        for bad in [
            env(&[("ag_wsl_launcher", "other")]),
            env(&[("AG_WSL_LAUNCHER", launcher), ("ag_wsl_launcher", launcher)]),
            env(&[("WSLENV", "AG_WSL_LAUNCHER/u")]),
            env(&[("WSLENV", "ag_wsl_launcher")]),
        ] {
            assert!(plan_hook_environment(&bad, endpoint(), launcher).is_err());
        }
    }
}
