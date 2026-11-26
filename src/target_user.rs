//! Target Windows user profile selection.
//!
//! Allows running the tool under one Windows account (e.g. an admin account)
//! while performing all per-user operations (data directory, Antigravity
//! discovery/patching, scheduled tasks, environment variables, report path)
//! for another Windows user profile.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct UserProfile {
    pub username: String,
    pub profile_dir: PathBuf,
    pub sid: Option<String>,
    pub is_current: bool,
}

#[cfg(windows)]
mod platform {
    use super::UserProfile;
    use std::env;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::sync::OnceLock;

    struct Selected {
        username: String,
        profile_dir: PathBuf,
        sid: Option<String>,
        is_override: bool,
    }

    static SELECTED: OnceLock<Selected> = OnceLock::new();

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    fn current_username_and_profile() -> (String, PathBuf) {
        let user = env::var("USERNAME").unwrap_or_default();
        let profile = env::var("USERPROFILE").map(PathBuf::from).unwrap_or_default();
        (user, profile)
    }

    fn is_current_profile(username: &str, profile_dir: &Path, cur_user: &str, cur_dir: &Path) -> bool {
        let dir_match = !cur_dir.as_os_str().is_empty()
            && profile_dir
                .to_string_lossy()
                .eq_ignore_ascii_case(&cur_dir.to_string_lossy());
        let user_match = !cur_user.is_empty() && username.eq_ignore_ascii_case(cur_user);
        dir_match || user_match
    }

    pub fn list_profiles() -> Vec<UserProfile> {
        #[link(name = "advapi32")]
        extern "system" {
            fn RegOpenKeyExW(
                hkey: usize,
                lp_sub_key: *const u16,
                ul_options: u32,
                sam_desired: u32,
                phk_result: *mut usize,
            ) -> i32;
            fn RegEnumKeyExW(
                hkey: usize,
                dw_index: u32,
                lp_name: *mut u16,
                lpcch_name: *mut u32,
                lp_reserved: *mut u32,
                lp_class: *mut u16,
                lpcch_class: *mut u32,
                lpft_last_write_time: *mut std::ffi::c_void,
            ) -> i32;
            fn RegGetValueW(
                hkey: usize,
                lp_sub_key: *const u16,
                lp_value: *const u16,
                dw_flags: u32,
                pdw_type: *mut u32,
                pv_data: *mut u8,
                pcb_data: *mut u32,
            ) -> i32;
            fn RegCloseKey(hkey: usize) -> i32;
        }

        const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
        const KEY_READ: u32 = 0x0002_0019;
        const KEY_WOW64_64KEY: u32 = 0x0100;
        const RRF_RT_REG_SZ: u32 = 0x0000_0002;
        const ERROR_SUCCESS: i32 = 0;
        const ERROR_NO_MORE_ITEMS: i32 = 259;

        const PROFILE_LIST: &str =
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

        let (cur_user, cur_dir) = current_username_and_profile();
        let mut profiles: Vec<UserProfile> = Vec::new();

        let root_subkey = wide(PROFILE_LIST);
        let value_name = wide("ProfileImagePath");
        let mut hkey: usize = 0;

        let open_rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                root_subkey.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut hkey,
            )
        };

        if open_rc == ERROR_SUCCESS && hkey != 0 {
            let mut index: u32 = 0;
            let mut name_buf = vec![0u16; 512];
            loop {
                let mut name_len = name_buf.len() as u32;
                let enum_rc = unsafe {
                    RegEnumKeyExW(
                        hkey,
                        index,
                        name_buf.as_mut_ptr(),
                        &mut name_len,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };
                if enum_rc == ERROR_NO_MORE_ITEMS {
                    break;
                }
                index += 1;
                if enum_rc != ERROR_SUCCESS {
                    continue;
                }
                let sid = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                if !sid.starts_with("S-1-5-21-") {
                    continue;
                }
                let subkey = wide(&format!("{PROFILE_LIST}\\{sid}"));
                let mut data_size: u32 = 0;
                let rc1 = unsafe {
                    RegGetValueW(
                        HKEY_LOCAL_MACHINE,
                        subkey.as_ptr(),
                        value_name.as_ptr(),
                        RRF_RT_REG_SZ,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        &mut data_size,
                    )
                };
                if rc1 != ERROR_SUCCESS || data_size == 0 {
                    continue;
                }
                let mut data = vec![0u8; data_size as usize];
                let rc2 = unsafe {
                    RegGetValueW(
                        HKEY_LOCAL_MACHINE,
                        subkey.as_ptr(),
                        value_name.as_ptr(),
                        RRF_RT_REG_SZ,
                        ptr::null_mut(),
                        data.as_mut_ptr(),
                        &mut data_size,
                    )
                };
                if rc2 != ERROR_SUCCESS {
                    continue;
                }
                let u16_data: Vec<u16> = data
                    .chunks_exact(2)
                    .map(|c| u16::from_ne_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                let path_str = String::from_utf16_lossy(&u16_data);
                let profile_dir = PathBuf::from(path_str.trim());
                if !profile_dir.is_dir() {
                    continue;
                }
                let Some(username) = profile_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
                else {
                    continue;
                };
                let is_current = is_current_profile(&username, &profile_dir, &cur_user, &cur_dir);
                profiles.push(UserProfile {
                    username,
                    profile_dir,
                    sid: Some(sid),
                    is_current,
                });
            }
            unsafe { RegCloseKey(hkey) };
        }

        // Fallback: scan C:\Users if registry yielded nothing.
        if profiles.is_empty() {
            let users_root = Path::new(r"C:\Users");
            if let Ok(entries) = std::fs::read_dir(users_root) {
                for entry in entries.flatten() {
                    let profile_dir = entry.path();
                    if !profile_dir.is_dir() {
                        continue;
                    }
                    let Some(username) = profile_dir
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    if matches!(
                        username.to_ascii_lowercase().as_str(),
                        "public" | "default" | "default user" | "all users"
                    ) {
                        continue;
                    }
                    let is_current =
                        is_current_profile(&username, &profile_dir, &cur_user, &cur_dir);
                    profiles.push(UserProfile {
                        username,
                        profile_dir,
                        sid: None,
                        is_current,
                    });
                }
            }
        }

        // Deduplicate by lowercase profile_dir.
        let mut seen = Vec::<String>::new();
        profiles.retain(|p| {
            let key = p.profile_dir.to_string_lossy().to_ascii_lowercase();
            if seen.contains(&key) {
                false
            } else {
                seen.push(key);
                true
            }
        });

        profiles.sort_by(|a, b| {
            b.is_current.cmp(&a.is_current).then_with(|| {
                a.username
                    .to_ascii_lowercase()
                    .cmp(&b.username.to_ascii_lowercase())
            })
        });
        profiles
    }

    fn find_user_arg() -> Option<String> {
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            if let Some(val) = arg.strip_prefix("--user=") {
                let v = val.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            } else if arg == "--user" {
                if let Some(next) = args.next() {
                    let v = next.trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
        env::var("AG_UNLOCKER_USER")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn init_from_args() -> bool {
        let Some(val) = find_user_arg() else {
            return false;
        };
        let profiles = list_profiles();
        if let Some(found) = profiles.into_iter().find(|p| {
            p.username.eq_ignore_ascii_case(&val)
                || p.profile_dir
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&val)
        }) {
            apply(&found);
            return true;
        }
        let direct = PathBuf::from(&val);
        let under_users = PathBuf::from(r"C:\Users").join(&val);
        let dir = if direct.is_dir() {
            Some(direct)
        } else if under_users.is_dir() {
            Some(under_users)
        } else {
            None
        };
        if let Some(profile_dir) = dir {
            let (cur_user, cur_dir) = current_username_and_profile();
            let username = profile_dir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| val.clone());
            let is_current = is_current_profile(&username, &profile_dir, &cur_user, &cur_dir);
            apply(&UserProfile {
                username,
                profile_dir,
                sid: None,
                is_current,
            });
            return true;
        }
        false
    }

    pub fn apply(profile: &UserProfile) {
        let is_override = !profile.is_current;
        if is_override {
            env::set_var("USERPROFILE", &profile.profile_dir);
            env::set_var(
                "LOCALAPPDATA",
                profile.profile_dir.join("AppData").join("Local"),
            );
            env::set_var(
                "APPDATA",
                profile.profile_dir.join("AppData").join("Roaming"),
            );
            env::set_var("USERNAME", &profile.username);
        }
        env::set_var("AG_UNLOCKER_USER", &profile.username);
        let _ = SELECTED.set(Selected {
            username: profile.username.clone(),
            profile_dir: profile.profile_dir.clone(),
            sid: profile.sid.clone(),
            is_override,
        });
    }

    pub fn mark_current_ready() {
        let profiles = list_profiles();
        if let Some(cur) = profiles.into_iter().find(|p| p.is_current) {
            apply(&cur);
            return;
        }
        let (username, profile_dir) = current_username_and_profile();
        let _ = SELECTED.set(Selected {
            username,
            profile_dir,
            sid: None,
            is_override: false,
        });
    }

    pub fn is_ready() -> bool {
        SELECTED.get().is_some()
    }

    pub fn is_override() -> bool {
        SELECTED.get().is_some_and(|s| s.is_override)
    }

    pub fn selected_username() -> Option<&'static str> {
        SELECTED.get().map(|s| s.username.as_str())
    }

    pub fn override_sid() -> Option<&'static str> {
        SELECTED
            .get()
            .filter(|s| s.is_override)
            .and_then(|s| s.sid.as_deref())
    }

    pub fn override_profile_dir() -> Option<&'static Path> {
        SELECTED
            .get()
            .filter(|s| s.is_override)
            .map(|s| s.profile_dir.as_path())
    }

    pub fn task_user_id() -> String {
        if let Some(sid) = override_sid() {
            format!("'{}'", sid.replace('\'', "''"))
        } else if is_override() {
            format!(
                "'{}'",
                selected_username().unwrap_or_default().replace('\'', "''")
            )
        } else {
            r#""$env:USERDOMAIN\$env:USERNAME""#.to_string()
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::UserProfile;
    use std::path::Path;

    pub fn list_profiles() -> Vec<UserProfile> {
        Vec::new()
    }
    pub fn init_from_args() -> bool {
        true
    }
    pub fn apply(_: &UserProfile) {}
    pub fn mark_current_ready() {}
    pub fn is_ready() -> bool {
        true
    }
    pub fn is_override() -> bool {
        false
    }
    pub fn selected_username() -> Option<&'static str> {
        None
    }
    pub fn override_sid() -> Option<&'static str> {
        None
    }
    pub fn override_profile_dir() -> Option<&'static Path> {
        None
    }
    pub fn task_user_id() -> String {
        String::new()
    }
}

pub use platform::*;
