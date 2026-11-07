use std::sync::OnceLock;

pub fn pc_code() -> &'static str {
    static CODE: OnceLock<String> = OnceLock::new();
    CODE.get_or_init(|| {
        let raw = get_raw_hwid();
        agu2_pc_code(&raw)
    })
    .as_str()
}

fn agu2_pc_code(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    obfstr::obfstr! { let salt = "AGU-HWID-v1"; }
    let input = format!("{}\n{}", salt, raw);
    let d = Sha256::digest(input.as_bytes());
    let mut n_bytes = [0u8; 8];
    n_bytes[3..8].copy_from_slice(&d[..5]);
    let n = u64::from_be_bytes(n_bytes);
    let alphabet = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut code = String::with_capacity(8);
    for i in 0..8 {
        let shift = 35 - 5 * i;
        let idx = (n >> shift) & 31;
        code.push(alphabet[idx as usize] as char);
    }
    code
}

#[cfg(windows)]
fn get_raw_hwid() -> String {
    use std::ptr;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemFirmwareTable(
            firmware_table_provider_signature: u32,
            firmware_table_id: u32,
            firmware_table_buffer: *mut u8,
            buffer_size: u32,
        ) -> u32;
    }

    const RSMB: u32 = 0x52534D42;

    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, ptr::null_mut(), 0) };
    if size > 0 {
        let mut buf = vec![0u8; size as usize];
        let res = unsafe { GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr(), size) };
        if res == size && buf.len() >= 8 {
            if let Some(info) = parse_smbios(&buf[8..]) {
                return info;
            }
        }
    }

    // Fallback: Registry MachineGuid
    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            hkey: usize,
            lp_sub_key: *const u16,
            lp_value: *const u16,
            dw_flags: u32,
            pdw_type: *mut u32,
            pv_data: *mut u8,
            pcb_data: *mut u32,
        ) -> i32;
    }

    const HKEY_LOCAL_MACHINE: usize = 0x80000002;
    const RRF_RT_REG_SZ: u32 = 0x00000002;
    const RRF_SUBKEY_WOW6464KEY: u32 = 0x00010000;

    use std::os::windows::ffi::OsStrExt;
    let subkey: Vec<u16> = std::ffi::OsStr::new("SOFTWARE\\Microsoft\\Cryptography")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value: Vec<u16> = std::ffi::OsStr::new("MachineGuid")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut data_size = 0;

    let res = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut data_size,
        )
    };

    if res == 0 && data_size > 0 {
        let mut data = vec![0u8; data_size as usize];
        let res2 = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                ptr::null_mut(),
                data.as_mut_ptr(),
                &mut data_size,
            )
        };
        if res2 == 0 {
            let u16_data: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_ne_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            if let Ok(guid) = String::from_utf16(&u16_data) {
                return format!("machineguid:{}", guid);
            }
        }
    }

    "unknown".to_string()
}

#[cfg(windows)]
fn parse_smbios(mut data: &[u8]) -> Option<String> {
    let mut type2_mfg = String::new();
    let mut type2_serial = String::new();

    while data.len() >= 4 {
        let t = data[0];
        let len = data[1] as usize;
        if len < 4 {
            break;
        }
        if data.len() < len {
            break;
        }

        let formatted = &data[0..len];
        let strings_start = len;

        let mut strings_end = strings_start;
        while strings_end + 1 < data.len() {
            if data[strings_end] == 0 && data[strings_end + 1] == 0 {
                strings_end += 2;
                break;
            }
            strings_end += 1;
        }
        if strings_end > data.len() {
            break;
        }

        let strings_area = &data[strings_start..strings_end];

        if t == 1 && len >= 24 {
            let uuid = &formatted[8..24];
            let all_zero = uuid.iter().all(|&b| b == 0);
            let all_ff = uuid.iter().all(|&b| b == 0xFF);
            if !all_zero && !all_ff {
                return Some(format!("smbios-uuid:{}", hex::encode(uuid)));
            }
        } else if t == 2 && len >= 8 {
            let mfg_idx = formatted[4];
            let ser_idx = formatted[7];

            let get_string = |idx: u8| -> String {
                if idx == 0 {
                    return String::new();
                }
                let mut current_idx = 1;
                let mut start = 0;
                for i in 0..strings_area.len() {
                    if strings_area[i] == 0 {
                        if current_idx == idx {
                            if let Ok(s) = std::str::from_utf8(&strings_area[start..i]) {
                                return s.trim().to_string();
                            }
                            break;
                        }
                        current_idx += 1;
                        start = i + 1;
                    }
                }
                String::new()
            };

            type2_mfg = get_string(mfg_idx);
            type2_serial = get_string(ser_idx);
        }

        data = &data[strings_end..];
    }

    if !type2_serial.is_empty() {
        let s = type2_serial.as_str();
        if s != "Default string"
            && s != "To be filled by O.E.M."
            && !s.chars().all(|c| c.is_whitespace())
        {
            return Some(format!("board:{}|{}", type2_mfg, type2_serial));
        }
    }

    None
}

/// macOS: the hardware UUID (`IOPlatformUUID`), the same quantity the SMBIOS
/// system UUID is on a PC. Without this every Mac fell through to "unknown"
/// and shared one PC code.
#[cfg(target_os = "macos")]
fn get_raw_hwid() -> String {
    let out = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output();
    if let Ok(out) = out {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(uuid) = text
            .lines()
            .find(|l| l.contains("\"IOPlatformUUID\""))
            .and_then(|l| l.rsplit('"').nth(1))
        {
            let uuid = uuid.trim().replace('-', "").to_lowercase();
            if !uuid.is_empty() {
                return format!("smbios-uuid:{}", uuid);
            }
        }
    }
    "unknown".to_string()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn get_raw_hwid() -> String {
    use std::fs;
    if let Ok(uuid) = fs::read_to_string("/sys/class/dmi/id/product_uuid") {
        let uuid = uuid.trim().replace("-", "").to_lowercase();
        if !uuid.is_empty() {
            return format!("smbios-uuid:{}", uuid);
        }
    }
    if let Ok(mid) = fs::read_to_string("/etc/machine-id") {
        let mid = mid.trim();
        if !mid.is_empty() {
            return format!("machine-id:{}", mid);
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pc_code_vectors() {
        assert_eq!(agu2_pc_code("ABC"), "cgcxprbk");
    }

    /// Prints which source the code came from on this machine and the code.
    ///
    ///     cargo test this_pc_code -- --ignored --nocapture
    #[test]
    #[ignore = "reads this machine's firmware tables"]
    fn this_pc_code() {
        let raw = get_raw_hwid();
        let source = raw.split(':').next().unwrap_or("");
        println!("source={} code={}", source, pc_code());
        assert_ne!(source, "unknown");
    }

    #[cfg(windows)]
    #[test]
    fn smbios_walker() {
        // Valid type 1
        let mut buf1 = vec![1, 24, 0, 0, 0, 0, 0, 0];
        let uuid = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef,
        ];
        buf1.extend_from_slice(&uuid);
        buf1.extend_from_slice(&[0, 0]); // Double NUL
        assert_eq!(
            parse_smbios(&buf1),
            Some("smbios-uuid:1234567890abcdef1234567890abcdef".to_string())
        );

        // Type 1 all FF + Type 2 with serial
        let mut buf2 = vec![1, 24, 0, 0, 0, 0, 0, 0];
        buf2.extend_from_slice(&[0xFF; 16]);
        buf2.extend_from_slice(&[0, 0]);

        let type2_start = buf2.len();
        buf2.extend_from_slice(&[2, 8, 0, 0, 1, 0, 0, 2]);
        buf2.extend_from_slice(b"Manuf\0Ser123\0\0");
        assert_eq!(parse_smbios(&buf2), Some("board:Manuf|Ser123".to_string()));

        // Truncated buffer
        let trunc = vec![1, 24, 0, 0];
        assert_eq!(parse_smbios(&trunc), None);
    }
}
