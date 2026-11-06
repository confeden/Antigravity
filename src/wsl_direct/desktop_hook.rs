//! Pure preparation only: no installed files, processes or environment are read.
#[path = "archive.rs"]
mod archive;

const MEMBER: &str = "dist/languageServer.js";
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

struct LexicalAnchors {
    code: std::collections::HashSet<usize>,
    reserved: bool,
}

fn lexical_anchors(text: &str) -> Result<LexicalAnchors, HookError> {
    use ress::tokens::{Keyword, Token};
    let mut code = std::collections::HashSet::new();
    let mut reserved = false;
    for item in ress::Scanner::new(text) {
        let item = item.map_err(|error| HookError(format!("producer-unsupported: JavaScript lexing: {error}")))?;
        match item.token {
            Token::Ident(ident) => {
                let value: &str = ident.as_ref();
                if value == "spawnArgs" { code.insert(item.span.start); }
                if ["agWslLauncher", "AG_WSL_LAUNCHER", "agWslSource"].contains(&value) { reserved = true; }
            }
            Token::Keyword(Keyword::Const(_)) => { code.insert(item.span.start); }
            Token::String(value) => {
                let value: &str = value.as_ref();
                if ["AG_WSL_LAUNCHER", "--serve-wsl"].contains(&value) { reserved = true; }
            }
            _ => {}
        }
    }
    Ok(LexicalAnchors { code, reserved })
}

fn code_occurrences(text: &str, needle: &str, anchors: &LexicalAnchors) -> Vec<usize> {
    let leading = needle.len() - needle.trim_start().len();
    text.match_indices(needle).filter_map(|(index, _)|
        anchors.code.contains(&(index + leading)).then_some(index)).collect()
}

fn transform(source: &[u8], profile: HookProfile<'_>) -> Result<(HookStatus, Vec<u8>), HookError> {
    let text = std::str::from_utf8(source)
        .map_err(|_| HookError("producer-unsupported: non-UTF8 member".into()))?;
    let hook = match profile {
        HookProfile::Legacy => HOOK.to_owned(),
        HookProfile::GuiHost(host) => gui_hook(host)?,
    };
    let anchors = lexical_anchors(text)?;
    let known = code_occurrences(text, &hook, &anchors);
    let legacy = code_occurrences(text, HOOK, &anchors);
    if known.len() > 1 || legacy.len() > 1 || (!legacy.is_empty() && !matches!(profile, HookProfile::Legacy)) {
        return Err(HookError("producer-conflict: mixed or duplicate hooks".into()));
    }
    // A legacy hook contains ORIGINAL itself. Remove the entire recognized
    // hook first, then check the resulting producer for a single target and
    // any partial, foreign-host, or mixed hook marker.
    let mut pristine = text.to_owned();
    if let Some(&offset) = known.first() { pristine.replace_range(offset..offset + hook.len(), ORIGINAL); }
    let pristine_anchors = lexical_anchors(&pristine)?;
    let targets = code_occurrences(&pristine, ORIGINAL, &pristine_anchors);
    if targets.len() != 1 || pristine_anchors.reserved {
        return Err(HookError("producer-conflict: unrecognized, partial, or ambiguous hook".into()));
    }
    if !known.is_empty() { Ok((HookStatus::AlreadyApplied, source.to_vec())) }
    else {
        let offset = targets[0];
        pristine.replace_range(offset..offset + ORIGINAL.len(), &hook);
        Ok((HookStatus::Prepared, pristine.into_bytes()))
    }
}

fn version(archive: &archive::Archive<'_>) -> Result<String, HookError> {
    let package = archive::json_unique(archive.member("package.json")?)?;
    if package.get("name").and_then(serde_json::Value::as_str) != Some("antigravity")
        || package.get("main").and_then(serde_json::Value::as_str) != Some("dist/main.js") {
        return Err(HookError(
            "producer-unsupported: unrecognized package identity".into(),
        ));
    }
    package.get("version").and_then(serde_json::Value::as_str).filter(|v| !v.is_empty())
        .map(str::to_owned).ok_or_else(|| HookError("producer-unsupported: missing package version".into()))
}

pub fn inspect_archive(input: &[u8]) -> Result<ArchiveInspection, HookError> {
    let archive = archive::Archive::parse(input)?;
    let version = version(&archive)?;
    let (hook_status, _) = transform(archive.member(MEMBER)?, HookProfile::Legacy)?;
    Ok(ArchiveInspection {
        version,
        digest: archive::digest(input),
        hook_status,
    })
}

pub fn prepare_archive(input: &[u8]) -> Result<PreparedArchive, HookError> {
    let source = archive::Archive::parse(input)?;
    let version = version(&source)?;
    let (hook_status, replacement) = transform(source.member(MEMBER)?, HookProfile::Legacy)?;
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
    let (hook_status, replacement) = transform(source.member(MEMBER)?, HookProfile::GuiHost(host))?;
    let bytes = if hook_status == HookStatus::AlreadyApplied { input.to_vec() }
        else { source.replace(MEMBER, &replacement)? };
    if inspect_gui_archive(&bytes, host)?.hook_status != HookStatus::AlreadyApplied {
        return Err(HookError("archive-conflict: candidate hook readback".into()));
    }
    Ok(PreparedArchive { pre_digest: archive::digest(input), post_digest: archive::digest(&bytes),
        bytes, version, hook_status })
}

pub(crate) fn inspect_gui_archive(input: &[u8], host: &str) -> Result<ArchiveInspection, HookError> {
    let source = archive::Archive::parse(input)?;
    let version = version(&source)?;
    let (hook_status, _) = transform(source.member(MEMBER)?, HookProfile::GuiHost(host))?;
    if hook_status != HookStatus::AlreadyApplied {
        return Err(HookError("producer-unsupported: runtime hook not applied".into()));
    }
    Ok(ArchiveInspection { version, digest: archive::digest(input), hook_status })
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
        let repeated = prepare_gui_archive(&prepared.bytes, host).unwrap();
        assert_eq!(repeated.hook_status, HookStatus::AlreadyApplied);
        assert_eq!(repeated.bytes, prepared.bytes);
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

    fn hook_fixture(version: &str, script: &str) -> Vec<u8> {
        let package = serde_json::to_vec(&json!({"name":"antigravity", "version":version,
            "main":"dist/main.js"})).unwrap();
        let source = script.as_bytes();
        let tree = json!({"files": {
            "package.json": file(&package, 0, 32),
            "dist": {"files": {"languageServer.js": file(source, package.len(), 32)}}
        }});
        let mut data = package;
        data.extend_from_slice(source);
        archive::encode(&tree, &data).unwrap()
    }

    #[test]
    fn structural_hook_is_version_independent_and_idempotent() {
        let host = r"C:\synthetic\runtime.exe";
        for version in ["2.28.2", "2.29.0", "2035.4"] {
            let script = format!("// unrelated changed content\n{ORIGINAL}\n// tail");
            let input = hook_fixture(version, &script);
            assert!(inspect_gui_archive(&input, host).is_err());
            let first = prepare_gui_archive(&input, host).unwrap();
            assert_eq!(first.version, version);
            assert_eq!(first.hook_status, HookStatus::Prepared);
            assert_eq!(first.pre_digest, archive::digest(&input));
            assert_eq!(first.post_digest, archive::digest(&first.bytes));
            assert_eq!(inspect_gui_archive(&first.bytes, host).unwrap().hook_status, HookStatus::AlreadyApplied);
            let second = prepare_gui_archive(&first.bytes, host).unwrap();
            assert_eq!(second.hook_status, HookStatus::AlreadyApplied);
            assert_eq!(second.bytes, first.bytes);
            assert!(inspect_gui_archive(&first.bytes, r"C:\other.exe").is_err());
            assert!(prepare_archive(&first.bytes).is_err());
            let legacy = prepare_archive(&input).unwrap();
            assert_eq!(legacy.hook_status, HookStatus::Prepared);
            let repeated = prepare_archive(&legacy.bytes).unwrap();
            assert_eq!(repeated.hook_status, HookStatus::AlreadyApplied);
            assert_eq!(repeated.bytes, legacy.bytes);
            assert!(prepare_gui_archive(&legacy.bytes, host).is_err());
        }
    }

    #[test]
    fn mixed_duplicate_partial_and_foreign_hooks_fail_closed() {
        let host = r"C:\synthetic\runtime.exe";
        let gui = gui_hook(host).unwrap();
        let foreign = gui_hook(r"C:\foreign.exe").unwrap();
        for script in [format!("{ORIGINAL}\n{ORIGINAL}"), format!("{HOOK}\n{ORIGINAL}"),
            format!("{gui}\n{ORIGINAL}"), format!("{gui}\n{gui}"),
            format!("{foreign}\n{ORIGINAL}"), format!("{ORIGINAL}\nconst agWslSource = null;"),
            format!("{ORIGINAL}\nconst agWslLauncher = null;")] {
            let input = hook_fixture("2.29.0", &script);
            assert!(prepare_gui_archive(&input, host).is_err());
            assert!(prepare_archive(&input).is_err());
        }
    }

    #[test]
    fn lexical_non_code_targets_and_hooks_do_not_become_anchors() {
        let host = r"C:\synthetic\runtime.exe";
        let gui = gui_hook(host).unwrap();
        let decoys = [
            format!("/*\n{ORIGINAL}\n*/\n"),
            format!("const decoy = '{ORIGINAL}';\n"),
            format!("const decoy = /{ORIGINAL}/;\n"),
            format!("const decoy = `{gui}`;\n"),
        ];
        for decoy in decoys {
            assert!(prepare_gui_archive(&hook_fixture("2.29.0", &decoy), host).is_err());
            let input = hook_fixture("2.29.0", &format!("{decoy}{ORIGINAL}"));
            let prepared = prepare_gui_archive(&input, host).unwrap();
            let archive = archive::Archive::parse(&prepared.bytes).unwrap();
            let member = std::str::from_utf8(archive.member(MEMBER).unwrap()).unwrap();
            assert!(member.starts_with(&decoy));
            assert_eq!(prepared.hook_status, HookStatus::Prepared);
            assert_eq!(prepare_gui_archive(&prepared.bytes, host).unwrap().hook_status, HookStatus::AlreadyApplied);
        }
    }

    #[test]
    fn lexical_error_does_not_fall_back_to_text_matching() {
        let input = hook_fixture("2.29.0", &format!("{ORIGINAL}\n'unterminated"));
        assert!(prepare_gui_archive(&input, r"C:\runtime.exe").is_err());
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
        assert_eq!(transform(ORIGINAL.as_bytes(), HookProfile::Legacy).unwrap().0, HookStatus::Prepared);
        assert_eq!(transform(HOOK.as_bytes(), HookProfile::Legacy).unwrap().0, HookStatus::AlreadyApplied);
        assert!(transform(&[0xff], HookProfile::Legacy).is_err());
    }
}
