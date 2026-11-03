//! Received producer wire only. The server tail is retained verbatim and is
//! never searched for host roles or interpreted as Unlocker options.
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

#[derive(Clone)]
pub(crate) struct VendorWslLaunch {
    pub(crate) desktop: PathBuf,
    pub(crate) vendor_pid: u32,
    pub(crate) distro: String,
    pub(crate) server_version: String,
    pub(crate) source_contract: String,
    pub(crate) server_args: Vec<OsString>,
}
impl VendorWslLaunch {
    /// Values after the first --serve-wsl/retained-owner role selector.
    pub(crate) fn receive(arguments: Vec<OsString>) -> Result<Self, String> {
        let mut values = arguments.into_iter();
        let mut next = |tag: &str| -> Result<OsString, String> {
            if values.next().as_deref() != Some(OsStr::new(tag)) { return Err("vendor launch wire order/field mismatch".into()); }
            values.next().filter(|value| !value.is_empty()).ok_or_else(|| "vendor launch value missing".into())
        };
        let desktop = PathBuf::from(next("--desktop")?);
        let vendor_pid = next("--vendor-instance")?.to_str().and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value != 0).ok_or("vendor native process identity missing")?;
        let distro = next("--distro")?.into_string().map_err(|_| "vendor distro encoding")?;
        let server_version = next("--server-version")?.into_string().map_err(|_| "vendor version encoding")?;
        let source_contract = next("--source-contract")?.into_string().map_err(|_| "vendor source encoding")?;
        if values.next().as_deref() != Some(OsStr::new("--")) { return Err("vendor opaque argument boundary missing".into()); }
        if distro.chars().any(char::is_control) || server_version.is_empty() || matches!(server_version.as_str(), "." | "..")
            || server_version.chars().any(|c| c == '/' || c.is_control())
            || source_contract != format!("$HOME/.antigravity-server/bin/{server_version}/language_server") {
            return Err("unsupported vendor distro/source/version contract".into());
        }
        #[cfg(windows)]
        super::windows_installation::WindowsExecutablePath::parse(desktop.as_os_str())?;
        Ok(Self { desktop, vendor_pid, distro, server_version, source_contract, server_args: values.collect() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn producer_fields_are_exact_and_server_tail_is_opaque() {
        let args = ["--desktop", r"C:\Owned\Antigravity.exe", "--vendor-instance", "123", "--distro", "Дистрибутив с пробелом",
            "--server-version", "2.28.2", "--source-contract", "$HOME/.antigravity-server/bin/2.28.2/language_server",
            "--", "--watchdog", "--serve-wsl", "", "--exit_on_stdin_close"];
        let received = VendorWslLaunch::receive(args.iter().map(OsString::from).collect()).unwrap();
        assert_eq!(received.distro, "Дистрибутив с пробелом");
        assert_eq!(received.server_args, args[11..].iter().map(OsString::from).collect::<Vec<_>>());
        let mut invalid = args.iter().map(OsString::from).collect::<Vec<_>>();
        invalid[9] = "$HOME/.other/2.28.2/language_server".into();
        assert!(VendorWslLaunch::receive(invalid).is_err());
    }
}
