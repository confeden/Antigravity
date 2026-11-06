//! One Settings writer at a time. Windows internal roles never acquire it.
//!
//! The Windows main thread retains a cooperative current-user native lease.
//! Internal gateway/runtime roles dispatch before this owner is constructed.
//! Linux retains its established process-selection behavior below.

/// Whether a process image name is a copy of the unlocker window: the exe this
/// one runs as, or any other release of it (`AG_<version>.exe` on Windows).
fn is_window_name(name: &str, own: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == own.to_ascii_lowercase() {
        return true;
    }
    lower
        .strip_prefix("ag_")
        .and_then(|rest| rest.strip_suffix(".exe"))
        .is_some_and(|ver| ver.chars().next().is_some_and(|c| c.is_ascii_digit()))
}

/// Flags that make a process a service or helper, never a window.
fn is_service_args(args: &[String]) -> bool {
    args.iter().any(|a| {
        matches!(
            a.as_str(),
            "--dns-forwarder" | "--watchdog" | "--proxy" | "--patch-root" | "--unpatch-root"
        )
    })
}

/// Closes every other copy of the window. Best effort and silent: a copy that
/// refuses to die (another user's, a higher integrity level) is left running.
#[cfg(not(target_os = "windows"))]
pub fn close_others() {
    let Ok(me) = std::env::current_exe() else {
        return;
    };
    let own = me
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    platform::close_others(&own);
}

#[cfg(target_os = "windows")]
#[path = "gui_instance.rs"]
mod gui_instance;
#[cfg(target_os = "windows")]
pub(crate) use gui_instance::{
    receive_replacement, request_elevation, ElevationProgress, GuiApplyContinuation, GuiRetirementInputRef,
    GuiCurrentExpectation, GuiReplacementAction, GuiReplacementReady, GuiReplacementTarget, ReceivedReplacement,
    GuiTargetExpectation, GuiTargetKind, GUI_REPLACEMENT_FLAG,
};

#[cfg(target_os = "windows")]
pub fn acquire_gui_writer(
) -> Result<crate::windows_coordinator::windows_installation::SettingsWriterLease, String> {
    let lease = crate::windows_coordinator::windows_installation::admit_settings_writer()?;
    gui_instance::receive_visible_gui_conflicts()?;
    Ok(lease)
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::{is_service_args, is_window_name};

    pub fn close_others(own: &str) {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return;
        };
        let me = std::process::id();
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == me {
                continue;
            }
            let base = entry.path();
            // `comm` is cut at 15 bytes; the exe link is the whole name.
            let Some(name) = std::fs::read_link(base.join("exe"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            else {
                continue;
            };
            if !is_window_name(&name, own) {
                continue;
            }
            let args: Vec<String> = std::fs::read(base.join("cmdline"))
                .map(|raw| {
                    raw.split(|b| *b == 0)
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect()
                })
                .unwrap_or_default();
            if is_service_args(&args) {
                continue;
            }
            // The `kill` tool, not libc: one signal does not earn an `unsafe` block.
            let _ = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .output();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_releases_of_the_window_are_windows_and_the_services_are_not() {
        assert!(is_window_name("AG_2.22.0.exe", "AG_2.23.1.exe"));
        assert!(is_window_name("AG_2.23.1.exe", "AG_2.23.1.exe"));
        assert!(is_window_name("ag_unlocker", "ag_unlocker"));
        assert!(!is_window_name("ag_dns.exe", "AG_2.23.1.exe"));
        assert!(!is_window_name("ag_proxy", "ag_unlocker"));
        assert!(!is_window_name("Antigravity.exe", "AG_2.23.1.exe"));
    }

    #[test]
    fn a_flagged_process_is_a_service() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_service_args(&a(&["ag", "--proxy"])));
        assert!(is_service_args(&a(&["ag", "--unpatch-root", "/opt/x"])));
        assert!(!is_service_args(&a(&["ag"])));
    }
}
