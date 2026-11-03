use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Parsed asar header: the file tree plus the offset where the data section starts.
struct AsarHeader {
    tree: serde_json::Value,
    base_offset: u64,
}

fn read_header(file: &mut File) -> Option<AsarHeader> {
    read_header_checked(file).ok()
}

fn read_header_checked(file: &mut File) -> Result<AsarHeader, String> {
    let mut header_size_bytes = [0u8; 16];
    file.read_exact(&mut header_size_bytes).map_err(|e| format!("ASAR header read: {e}"))?;

    let header_size = u32::from_le_bytes([
        header_size_bytes[4],
        header_size_bytes[5],
        header_size_bytes[6],
        header_size_bytes[7],
    ]);
    let header_string_size = u32::from_le_bytes([
        header_size_bytes[12],
        header_size_bytes[13],
        header_size_bytes[14],
        header_size_bytes[15],
    ]);

    let file_size = file.metadata().map_err(|e| format!("ASAR metadata: {e}"))?.len();
    let json_end = 16u64.checked_add(u64::from(header_string_size)).ok_or("ASAR header extent overflow")?;
    let base_offset = u64::from(header_size).checked_add(8).ok_or("ASAR data offset overflow")?;
    if json_end > base_offset || base_offset > file_size { return Err("ASAR header extent is outside the file".into()); }
    let mut header_bytes = vec![0u8; usize::try_from(header_string_size).map_err(|_| "ASAR header size overflow")?];
    file.read_exact(&mut header_bytes).map_err(|e| format!("ASAR JSON read: {e}"))?;

    let header_json = String::from_utf8(header_bytes).map_err(|_| "ASAR header is not UTF-8")?;
    let tree: serde_json::Value = serde_json::from_str(&header_json).map_err(|e| format!("ASAR header JSON: {e}"))?;
    if tree.get("files").and_then(|value| value.as_object()).is_none() { return Err("ASAR file tree is malformed".into()); }

    Ok(AsarHeader {
        tree,
        base_offset,
    })
}

/// Reads a single file out of an asar archive without unpacking it.
/// `rel_path` uses forward slashes, e.g. "dist/main.js".
pub fn read_asar_entry(app_asar: &Path, rel_path: &str) -> Option<Vec<u8>> {
    read_asar_entry_checked(app_asar, rel_path).ok().flatten()
}

pub(crate) fn read_asar_entry_checked(app_asar: &Path, rel_path: &str) -> Result<Option<Vec<u8>>, String> {
    let mut file = File::open(app_asar).map_err(|e| format!("ASAR open: {e}"))?;
    let header = read_header_checked(&mut file)?;

    let mut node = &header.tree;
    for part in rel_path.split('/') {
        let files = node.get("files").and_then(|value| value.as_object()).ok_or("ASAR member parent is malformed")?;
        let Some(found) = files.get(part) else { return Ok(None); };
        node = found;
    }

    // Directories have no payload, and unpacked entries live on disk instead.
    if node.get("files").is_some() || node.get("unpacked").and_then(|u| u.as_bool()) == Some(true) {
        return Err("ASAR member payload is a directory or unpacked".into());
    }

    let size = node.get("size").and_then(|s| s.as_u64()).ok_or("ASAR member size is malformed")?;
    let offset = node
        .get("offset")
        .and_then(|o| o.as_str())
        .and_then(|o| o.parse::<u64>().ok()).ok_or("ASAR member offset is malformed")?;
    let start = header.base_offset.checked_add(offset).ok_or("ASAR member offset overflow")?;
    let end = start.checked_add(size).ok_or("ASAR member extent overflow")?;
    if end > file.metadata().map_err(|e| format!("ASAR member metadata: {e}"))?.len() {
        return Err("ASAR member extent is outside the file".into());
    }

    file.seek(SeekFrom::Start(start)).map_err(|e| format!("ASAR member seek: {e}"))?;
    let mut buf = vec![0u8; usize::try_from(size).map_err(|_| "ASAR member size overflow")?];
    file.read_exact(&mut buf).map_err(|e| format!("ASAR member read: {e}"))?;
    Ok(Some(buf))
}

fn extract_entry(
    file: &mut File,
    base_offset: u64,
    entry: &serde_json::Value,
    current_path: &Path,
) -> Result<(), std::io::Error> {
    if let Some(files) = entry.get("files") {
        if let Some(obj) = files.as_object() {
            for (name, child) in obj {
                let next_path = current_path.join(name);
                extract_entry(file, base_offset, child, &next_path)?;
            }
        }
        return Ok(());
    }

    let size = entry.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
    let offset_str = entry.get("offset").and_then(|o| o.as_str()).unwrap_or("0");
    let offset = offset_str.parse::<u64>().unwrap_or(0);
    let unpacked = entry
        .get("unpacked")
        .and_then(|u| u.as_bool())
        .unwrap_or(false);

    if let Some(parent) = current_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if !unpacked {
        file.seek(SeekFrom::Start(base_offset + offset))?;
        let mut out_file = File::create(current_path)?;
        let mut remaining = size;
        let mut buffer = [0u8; 65536];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..to_read])?;
            out_file.write_all(&buffer[..to_read])?;
            remaining -= to_read as u64;
        }
    }
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &dest_path)?;
        } else {
            fs::copy(&entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Locates a real Antigravity Desktop install, if one is present. These
    /// tests assert against the shipping archive rather than a fixture, so they
    /// skip cleanly on machines without the app.
    fn installed_asar() -> Option<std::path::PathBuf> {
        let local = env::var("LOCALAPPDATA").ok()?;
        let p = Path::new(&local)
            .join("Programs")
            .join("Antigravity")
            .join("resources")
            .join("app.asar");
        p.exists().then_some(p)
    }

    #[test]
    fn reads_a_file_out_of_the_archive_without_unpacking() {
        let Some(asar) = installed_asar() else { return };
        let pkg = read_asar_entry(&asar, "package.json").expect("package.json in app.asar");
        let text = String::from_utf8(pkg).expect("utf-8");
        assert!(text.contains("\"name\": \"antigravity\""), "got: {}", text);

        let main = read_asar_entry(&asar, "dist/main.js").expect("dist/main.js in app.asar");
        assert!(!main.is_empty());
    }

    #[test]
    fn missing_entries_return_none() {
        let Some(asar) = installed_asar() else { return };
        assert!(read_asar_entry(&asar, "dist/does-not-exist.js").is_none());
        // A directory node carries no payload.
        assert!(read_asar_entry(&asar, "dist").is_none());
    }
}

/// Unpacks app.asar into app_dir and renames the archive to app.asar.bak.
/// Electron prefers resources/app over resources/app.asar, so a half-finished
/// extraction would leave a broken install - on any error the partial output is
/// removed and the archive is left untouched.
pub fn extract_asar(app_asar: &Path, app_dir: &Path) -> bool {
    if !app_asar.exists() || app_dir.exists() {
        return true;
    }

    let mut file = match File::open(app_asar) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let header = match read_header(&mut file) {
        Some(h) => h,
        None => return false,
    };

    if extract_entry(&mut file, header.base_offset, &header.tree, app_dir).is_err() {
        let _ = fs::remove_dir_all(app_dir);
        return false;
    }

    let asar_unpacked_path = app_asar.with_extension("asar.unpacked");
    if asar_unpacked_path.exists() && asar_unpacked_path.is_dir() {
        if copy_dir_all(&asar_unpacked_path, app_dir).is_err() {
            let _ = fs::remove_dir_all(app_dir);
            return false;
        }
    }

    // Drop the file handle before renaming the archive it points at.
    drop(file);

    let bak = app_asar.with_extension("asar.bak");
    if fs::rename(app_asar, bak).is_err() {
        let _ = fs::remove_dir_all(app_dir);
        return false;
    }

    true
}

#[cfg(all(test, windows))]
mod wsl_checked_reader_contract_cases {
    use super::*;
    use crate::wsl_discovery_contract_cases::{fixture_asar, fixture_dir, fixture_file};

    #[test]
    fn wsl_checked_asar_distinguishes_missing_from_invalid() {
        let root = fixture_dir("asar");
        let valid = root.join("valid.asar");
        fixture_asar(&valid, r#"{"files":{"old.js":{"size":3,"offset":"0"}}}"#, b"old");
        assert_eq!(read_asar_entry_checked(&valid, "old.js").unwrap(), Some(b"old".to_vec()));
        assert_eq!(read_asar_entry_checked(&valid, "missing.js").unwrap(), None);
        assert!(read_asar_entry_checked(&root.join("absent.asar"), "old.js").is_err());
        let truncated = root.join("truncated.asar");
        fixture_file(&truncated, b"short");
        assert!(read_asar_entry_checked(&truncated, "old.js").is_err());
        let malformed = root.join("malformed.asar");
        fixture_asar(&malformed, r#"{"files":{"old.js":{"size":3,"offset":"bad"}}}"#, b"old");
        assert!(read_asar_entry_checked(&malformed, "old.js").is_err());
    }
}
