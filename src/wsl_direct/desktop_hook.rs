//! Pure preparation only: no installed files, processes or environment are read.
#[path = "archive.rs"]
mod archive;

const MEMBER: &str = "dist/languageServer.js";
const PRODUCER_SHA256: &str = "5c781d05050506d7643a88b1eeadc9bb4f320d7133f84b075e6338a6ce158d26";
const ORIGINAL: &str = r#"            spawnArgs = (0, wsl_1.wslShellArgs)(wsl.distro, `ANTIGRAVITY_VSCODE_HOST=1 exec "${wsl.binaryPath}" "$@"`, args);"#;
const HOOK: &str = r#"            const agWslLauncher = process.env.AG_WSL_LAUNCHER;
            if (agWslLauncher === undefined) {
                spawnArgs = (0, wsl_1.wslShellArgs)(wsl.distro, `ANTIGRAVITY_VSCODE_HOST=1 exec "${wsl.binaryPath}" "$@"`, args);
            } else {
                if (!agWslLauncher.startsWith('/') || /[\x00\r\n]/.test(agWslLauncher)) {
                    throw new Error('AG_WSL_LAUNCHER must be a nonempty absolute Linux path');
                }
                spawnArgs = (0, wsl_1.wslShellArgs)(wsl.distro, `agWslLauncher="$1"; shift; ANTIGRAVITY_VSCODE_HOST=1 exec "$agWslLauncher" "${wsl.binaryPath}" "$@"`, [agWslLauncher, ...args]);
            }"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStatus {
    Prepared,
    AlreadyApplied,
}

#[derive(Debug)]
pub struct PreparedArchive {
    pub bytes: Vec<u8>,
    pub version: String,
    pub pre_digest: String,
    pub post_digest: String,
    pub hook_status: HookStatus,
}

#[derive(Debug)]
pub struct ArchiveInspection {
    pub version: String,
    pub digest: String,
    /// Prepared means the recognized pristine producer is ready to prepare.
    pub hook_status: HookStatus,
}

#[derive(Clone, Copy)]
pub(crate) enum HookProfile<'a> {
    Legacy,
    GuiHost(&'a str),
}

pub(crate) fn prepare_profile(input: &[u8], profile: HookProfile<'_>) -> Result<PreparedArchive, HookError> {
    match profile {
        HookProfile::Legacy => prepare_archive(input),
        HookProfile::GuiHost(host) => prepare_gui_archive(input, host),
    }
}

pub(crate) fn inspect_profile(input: &[u8], profile: HookProfile<'_>) -> Result<ArchiveInspection, HookError> {
    match profile {
        HookProfile::Legacy => inspect_archive(input),
        HookProfile::GuiHost(host) => inspect_gui_archive(input, host),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookError(pub String);
impl std::fmt::Display for HookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for HookError {}
impl From<String> for HookError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

fn transform(source: &[u8]) -> Result<(HookStatus, Vec<u8>), HookError> {
    let text = std::str::from_utf8(source)
        .map_err(|_| HookError("producer-unsupported: non-UTF8 member".into()))?;
    if archive::digest(source) == PRODUCER_SHA256 && text.matches(ORIGINAL).count() == 1 {
        return Ok((
            HookStatus::Prepared,
            text.replacen(ORIGINAL, HOOK, 1).into_bytes(),
        ));
    }
    if text.matches(HOOK).count() == 1 {
        let pristine = text.replacen(HOOK, ORIGINAL, 1);
        if archive::digest(pristine.as_bytes()) == PRODUCER_SHA256 {
            return Ok((HookStatus::AlreadyApplied, source.to_vec()));
        }
    }
    Err(HookError(
        "producer-unsupported: unrecognized languageServer.js; review required".into(),
    ))
}

fn version(archive: &archive::Archive<'_>) -> Result<String, HookError> {
    let package = archive::json_unique(archive.member("package.json")?)?;
    if package.get("name").and_then(serde_json::Value::as_str) != Some("antigravity")
        || package.get("version").and_then(serde_json::Value::as_str) != Some("2.28.2")
        || package.get("main").and_then(serde_json::Value::as_str) != Some("dist/main.js")
    {
        return Err(HookError(
            "producer-unsupported: unrecognized package identity".into(),
        ));
    }
    Ok("2.28.2".into())
}

pub fn inspect_archive(input: &[u8]) -> Result<ArchiveInspection, HookError> {
    let archive = archive::Archive::parse(input)?;
    let version = version(&archive)?;
    let (hook_status, _) = transform(archive.member(MEMBER)?)?;
    Ok(ArchiveInspection {
        version,
        digest: archive::digest(input),
        hook_status,
    })
}

pub fn prepare_archive(input: &[u8]) -> Result<PreparedArchive, HookError> {
    let source = archive::Archive::parse(input)?;
    let version = version(&source)?;
    let (hook_status, replacement) = transform(source.member(MEMBER)?)?;
    let bytes = if hook_status == HookStatus::AlreadyApplied {
        input.to_vec()
    } else {
        source.replace(MEMBER, &replacement)?
    };
    // Receive the full candidate, including every packed integrity record,
    // before returning any bytes to the installing owner.
    let inspection = inspect_archive(&bytes)?;
    if inspection.hook_status != HookStatus::AlreadyApplied {
        return Err(HookError(
            "archive-conflict: candidate hook readback".into(),
        ));
    }
    Ok(PreparedArchive {
        pre_digest: archive::digest(input),
        post_digest: inspection.digest,
        bytes,
        version,
        hook_status,
    })
}

fn gui_hook(host: &str) -> Result<String, HookError> {
    if host.is_empty() || host.chars().any(char::is_control) {
        return Err(HookError("runtime host path is missing or invalid".into()));
    }
    let literal = serde_json::to_string(host).map_err(|e| HookError(e.to_string()))?;
    Ok(format!(r#"            const agWslSource = /^\$HOME\/\.antigravity-server\/bin\/([^/]+)\/language_server$/.exec(wsl.binaryPath);
            if (!agWslSource || agWslSource[1] === '.' || agWslSource[1] === '..' || /[\x00-\x1f\x7f]/.test(wsl.binaryPath)) {{
                throw new Error('Unsupported WSL language server source contract');
            }}
            spawnCmd = {literal};
            spawnArgs = ['--serve-wsl', '--desktop', process.execPath, '--vendor-instance', String(process.pid), '--distro', wsl.distro, '--server-version', agWslSource[1], '--source-contract', wsl.binaryPath, '--', ...args];"#))
}

/// Pure V2 preparation from the received pristine producer. The installation
/// owner alone receives and pins the immutable host before calling this.
pub(crate) fn prepare_gui_archive(input: &[u8], host: &str) -> Result<PreparedArchive, HookError> {
    let source = archive::Archive::parse(input)?;
    let version = version(&source)?;
    let member = source.member(MEMBER)?;
    let text = std::str::from_utf8(member).map_err(|_| HookError("producer-unsupported: encoding".into()))?;
    if archive::digest(member) != PRODUCER_SHA256 || text.matches(ORIGINAL).count() != 1 {
        return Err(HookError("producer-unsupported: V2 preparation requires the exact pristine producer".into()));
    }
    let replacement = text.replacen(ORIGINAL, &gui_hook(host)?, 1);
    let bytes = source.replace(MEMBER, replacement.as_bytes())?;
    inspect_gui_archive(&bytes, host)?;
    Ok(PreparedArchive { pre_digest: archive::digest(input), post_digest: archive::digest(&bytes),
        bytes, version, hook_status: HookStatus::Prepared })
}

pub(crate) fn inspect_gui_archive(input: &[u8], host: &str) -> Result<ArchiveInspection, HookError> {
    let source = archive::Archive::parse(input)?;
    let version = version(&source)?;
    let text = std::str::from_utf8(source.member(MEMBER)?)
        .map_err(|_| HookError("producer-unsupported: encoding".into()))?;
    let hook = gui_hook(host)?;
    if text.matches(&hook).count() != 1
        || archive::digest(text.replacen(&hook, ORIGINAL, 1).as_bytes()) != PRODUCER_SHA256 {
        return Err(HookError("producer-unsupported: runtime host or V2 producer binding differs".into()));
    }
    Ok(ArchiveInspection { version, digest: archive::digest(input), hook_status: HookStatus::AlreadyApplied })
}

pub(crate) fn gui_member_digest(input: &[u8], host: &str) -> Result<String, HookError> {
    inspect_gui_archive(input, host)?;
    let source = archive::Archive::parse(input)?;
    Ok(archive::digest(source.member(MEMBER)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn gui_host_path_is_one_json_literal_and_server_argv_stays_opaque() {
        let path = r#"C:\owned path\quote"host.exe"#;
        let hook = gui_hook(path).unwrap();
        assert!(hook.contains(&format!("spawnCmd = {};", serde_json::to_string(path).unwrap())));
        assert!(hook.ends_with("'--', ...args];"));
        assert!(gui_hook("invalid\npath").is_err());
    }

    #[test]
    #[ignore = "exact caller-owned pristine ASAR fixture required"]
    fn gui_hook_receives_actual_producer_and_exact_host_binding() {
        let path = std::env::var_os("AG_GUI_HOOK_PRISTINE").expect("explicit pristine fixture");
        let original = std::fs::read(path).unwrap();
        let host = r"C:\synthetic owned runtime\ag_unlocker.exe";
        let prepared = prepare_gui_archive(&original, host).unwrap();
        assert_ne!(prepared.bytes, original);
        assert_eq!(prepared.pre_digest, archive::digest(&original));
        assert!(inspect_gui_archive(&prepared.bytes, host).is_ok());
        assert!(inspect_gui_archive(&prepared.bytes, r"C:\other\ag_unlocker.exe").is_err());
        assert!(prepare_gui_archive(&prepared.bytes, host).is_err());
        assert!(gui_member_digest(&prepared.bytes, host).is_ok());
    }

    fn file(bytes: &[u8], offset: usize, block_size: usize) -> Value {
        json!({"size": bytes.len(), "offset": offset.to_string(), "integrity": {
            "algorithm": "SHA256", "hash": archive::digest(bytes), "blockSize": block_size,
            "blocks": bytes.chunks(block_size).map(archive::digest).collect::<Vec<_>>()
        }})
    }

    fn fixture() -> (Value, Vec<u8>) {
        let mut unpacked = file(b"external", 0, 3);
        unpacked.as_object_mut().unwrap().remove("offset");
        unpacked["unpacked"] = json!(true);
        (
            json!({"files": {
                "first": file(b"abcde", 0, 3), "second": file(b"xyz", 5, 3),
                "empty": file(b"", 8, 3), "external": unpacked, "alias": {"link": "first"}
            }}),
            b"abcdexyzTAIL".to_vec(),
        )
    }

    #[test]
    fn replacement_preserves_payloads_links_unpacked_and_updates_all_blocks() {
        let (tree, data) = fixture();
        let input = archive::encode(&tree, &data).unwrap();
        let source = archive::Archive::parse(&input).unwrap();
        let output = source.replace("first", b"replacement").unwrap();
        let result = archive::Archive::parse(&output).unwrap();
        assert_eq!(result.member("first").unwrap(), b"replacement");
        assert_eq!(result.member("second").unwrap(), b"xyz");
        assert_eq!(result.tree["files"]["second"]["offset"], "11");
        assert_eq!(result.tree["files"]["empty"]["offset"], "14");
        assert_eq!(result.tree["files"]["external"], tree["files"]["external"]);
        assert_eq!(result.tree["files"]["alias"], tree["files"]["alias"]);
        assert_eq!(&result.data[14..], b"TAIL");
        assert_eq!(
            result.tree["files"]["first"]["integrity"]["blocks"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        let restored = result.replace("first", b"abcde").unwrap();
        assert_eq!(archive::Archive::parse(&restored).unwrap().tree, tree);
        assert_eq!(archive::Archive::parse(&restored).unwrap().data, data);
    }

    #[test]
    fn malformed_metadata_bounds_integrity_and_unknown_producers_fail() {
        let (tree, data) = fixture();
        for mutation in [
            "overlap",
            "bounds",
            "integer",
            "hash",
            "block",
            "path",
            "link",
            "ambiguity",
            "algorithm",
            "unknown",
        ] {
            let mut bad = tree.clone();
            match mutation {
                "overlap" => bad["files"]["second"]["offset"] = json!("1"),
                "bounds" => bad["files"]["second"]["offset"] = json!("999"),
                "integer" => bad["files"]["second"]["offset"] = json!("18446744073709551616"),
                "hash" => bad["files"]["first"]["integrity"]["hash"] = json!("0".repeat(64)),
                "block" => bad["files"]["first"]["integrity"]["blocks"] = json!([]),
                "path" => {
                    let f = bad["files"].as_object_mut().unwrap();
                    let n = f.remove("first").unwrap();
                    f.insert("../first".into(), n);
                }
                "link" => bad["files"]["alias"]["link"] = json!("missing"),
                "ambiguity" => bad["files"]["external"]["offset"] = json!("0"),
                "algorithm" => bad["files"]["first"]["integrity"]["algorithm"] = json!("SHA1"),
                "unknown" => bad["files"]["first"]["otherPayload"] = json!("x"),
                _ => unreachable!(),
            }
            assert!(
                archive::Archive::parse(&archive::encode(&bad, &data).unwrap()).is_err(),
                "{mutation}"
            );
        }
        let encoded = archive::encode(&tree, &data).unwrap();
        for n in [0, 4, 15, encoded.len() - data.len() - 1] {
            assert!(archive::Archive::parse(&encoded[..n]).is_err());
        }
        assert!(archive::json_unique(br#"{"files":{},"files":{}}"#).is_err());
        assert!(archive::json_unique(br#"{"version":"2.28.2","version":"other"}"#).is_err());
        assert!(prepare_archive(&encoded).is_err());
        assert!(transform(ORIGINAL.as_bytes()).is_err());
        assert!(transform(HOOK.as_bytes()).is_err());
        assert!(transform(&[0xff]).is_err());
    }
}
