use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

// License model (intentionally soft — keys are free):
//
// * The base secret below is COMMITTED on purpose. A build made from the public
//   GitHub sources must accept the very same keys the author hands out in
//   Telegram, which is only possible if the secret ships in the source.
// * Keys are salted with the crate version (env!("CARGO_PKG_VERSION")), so a key
//   minted for one release does NOT validate on any other release. After every
//   update users grab a fresh, free key from t.me/nova_txt.
//
// This is not DRM: a determined user could derive keys from these public
// sources. The point is simply to route ordinary users through the Telegram
// group for their per-version key.
const LICENSE_BASE_SECRET: &str = ")Q.QFyU+oOs#Z:jmtxonGfZi+w#|XG4<";
// Must match dist_keygen.py exactly (base + separator + version).
const LICENSE_VERSION_SEP: &str = "::";

fn key_secret() -> String {
    format!(
        "{}{}{}",
        LICENSE_BASE_SECRET,
        LICENSE_VERSION_SEP,
        env!("CARGO_PKG_VERSION")
    )
}

/// Constant-time check of a licence key against this build's version salt.
///
/// Deliberately does no sleeping: the throttle that used to live here cost
/// 300 ms on the one screen every start goes through, and it bought nothing —
/// the secret is committed on purpose (see above), so rate-limiting a local
/// guess protects nothing. Any pacing belongs in the caller's UI, not here.
pub fn verify_key(key: &str) -> bool {
    let k: String = key.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let k = k.to_uppercase();
    if k.len() != 24 {
        return false;
    }

    let mut hasher = Sha256::new();
    hasher.update(&k[..12]);
    hasher.update(key_secret().as_bytes());
    let expected = hex::encode(hasher.finalize()).to_uppercase();
    let expected = &expected[..12];

    if k[12..].len() != expected.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in k[12..].chars().zip(expected.chars()) {
        result |= (x as u8) ^ (y as u8);
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mints a key the way dist_keygen.py does, for an arbitrary secret.
    fn mint_key(nonce: &str, secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(nonce.as_bytes());
        hasher.update(secret.as_bytes());
        let sig = hex::encode(hasher.finalize()).to_uppercase();
        format!("{}{}", nonce, &sig[..12])
    }

    #[test]
    fn accepts_a_key_for_the_current_version() {
        let key = mint_key("ABCDEF123456", &key_secret());
        assert!(verify_key(&key));
    }

    #[test]
    fn rejects_a_key_minted_for_another_version() {
        // Same base secret, different version salt -> must not validate. This is
        // what makes old keys stop working after an update.
        let other = format!("{}{}{}", LICENSE_BASE_SECRET, LICENSE_VERSION_SEP, "0.0.0");
        assert_ne!(other, key_secret());
        let stale = mint_key("ABCDEF123456", &other);
        assert!(!verify_key(&stale));
    }

    #[test]
    fn rejects_garbage() {
        assert!(!verify_key("not-a-key"));
        assert!(!verify_key(""));
    }

    #[test]
    fn ignores_separators_and_case_in_input() {
        let key = mint_key("ABCDEF123456", &key_secret());
        let formatted = format!("{}-{}", &key[..4], &key[4..]).to_lowercase();
        assert!(verify_key(&formatted));
    }

    #[test]
    fn cached_license_key_round_trip() {
        let key = mint_key("ABCDEF123456", &key_secret());
        assert!(verify_key(&key));

        let temp_dir = std::env::temp_dir().join("ag_auth_test");
        let _ = fs::create_dir_all(&temp_dir);
        let key_file = temp_dir.join("license.key");

        // Write key and read back
        fs::write(&key_file, &key).unwrap();
        let read_back = fs::read_to_string(&key_file).unwrap();
        assert_eq!(read_back.trim(), key);
        assert!(verify_key(read_back.trim()));

        // Invalid key
        fs::write(&key_file, "INVALID_KEY").unwrap();
        let invalid_read = fs::read_to_string(&key_file).unwrap();
        assert!(!verify_key(invalid_read.trim()));

        let _ = fs::remove_file(&key_file);
        let _ = fs::remove_dir(&temp_dir);
    }
}

/// Returns the path to the cached license key file:
/// `%LOCALAPPDATA%\AGUnlocker\license.key` on Windows.
pub fn license_file_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var("LOCALAPPDATA").ok()?;
        if local.is_empty() {
            return None;
        }
        Some(PathBuf::from(local).join("AGUnlocker").join("license.key"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let base = match std::env::var("XDG_DATA_HOME") {
            Ok(x) if !x.is_empty() => PathBuf::from(x),
            _ => match std::env::var("HOME") {
                Ok(h) if !h.is_empty() => PathBuf::from(h).join(".local").join("share"),
                _ => PathBuf::from("."),
            },
        };
        Some(base.join("AGUnlocker").join("license.key"))
    }
}

/// Attempts to load and verify a previously saved license key.
/// Returns true if a valid key for the current version was found and accepted.
pub fn try_cached_login() -> bool {
    let Some(path) = license_file_path() else {
        return false;
    };
    let Ok(content) = fs::read_to_string(&path) else {
        return false;
    };
    let key = content.trim().replace('"', "");
    if verify_key(&key) {
        true
    } else {
        false
    }
}

/// Saves a successfully verified key to the local user profile.
pub fn save_license_key(key: &str) {
    if let Some(path) = license_file_path() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&path, key.trim());
    }
}
