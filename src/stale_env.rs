//! Which running processes still carry an environment variable that has been
//! taken off the user environment.
//!
//! Removing `AG_LS_PROXY` from the registry reaches only processes started
//! afterwards. A running Antigravity got its copy at launch and hands it to every
//! language server it spawns, so once the relay - and the proxy listener inside
//! it - stops, the model request dies on `proxyconnect tcp: dial tcp
//! 127.0.0.1:53129 … actively refused` (field report, 2026-11-08). The variable
//! is read here out of each process's own environment block, so only the
//! processes that really hold it are restarted.

/// One running process whose environment still names the variable.
#[derive(Debug, Clone)]
pub struct Holder {
    pub pid: u32,
    /// Image name, e.g. `Antigravity.exe`.
    pub name: String,
    /// Full image path, when it could be read.
    pub path: Option<std::path::PathBuf>,
}

/// Whether a Windows environment block (`NAME=VALUE\0…\0\0`, UTF-16) has an
/// entry called `name`. Names compare case-insensitively, as Windows does.
pub fn block_has_var(block: &[u16], name: &str) -> bool {
    let want: Vec<u16> = name.encode_utf16().chain([u16::from(b'=')]).collect();
    block
        .split(|&c| c == 0)
        .take_while(|entry| !entry.is_empty())
        .any(|entry| {
            entry.len() >= want.len()
                && entry[..want.len()]
                    .iter()
                    .zip(&want)
                    .all(|(&a, &b)| fold(a) == fold(b))
        })
}

fn fold(c: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&c) {
        c - 32
    } else {
        c
    }
}

/// Every process of this session whose environment holds `name`, except this
/// one. A process that cannot be opened (another user's, a protected one) is
/// skipped: it is not ours to restart anyway.
#[cfg(target_os = "windows")]
pub fn holders(name: &str) -> Vec<Holder> {
    let own = std::process::id();
    win::processes()
        .into_iter()
        .filter(|(pid, _)| *pid != own && *pid != 0)
        .filter_map(|(pid, image)| {
            let (block, path) = win::environment_of(pid)?;
            block_has_var(&block, name).then_some(Holder {
                pid,
                name: image,
                path,
            })
        })
        .collect()
}

/// Linux/macOS: not handled yet - the variable there lives in a systemd
/// drop-in or a launchd plist, and the restart story is different.
#[cfg(not(target_os = "windows"))]
pub fn holders(_name: &str) -> Vec<Holder> {
    Vec::new()
}

#[cfg(target_os = "windows")]
mod win {
    use std::ffi::c_void;
    use std::path::PathBuf;

    type Handle = *mut c_void;

    #[repr(C)]
    struct ProcessEntry32W {
        size: u32,
        usage: u32,
        pid: u32,
        default_heap: usize,
        module: u32,
        threads: u32,
        parent: u32,
        pri_class_base: i32,
        flags: u32,
        exe: [u16; 260],
    }

    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: isize,
        peb: usize,
        affinity: usize,
        base_priority: isize,
        pid: usize,
        parent: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
        fn Process32FirstW(snap: Handle, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snap: Handle, entry: *mut ProcessEntry32W) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        fn ReadProcessMemory(
            process: Handle,
            base: *const c_void,
            buf: *mut c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn QueryFullProcessImageNameW(
            process: Handle,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn IsWow64Process(process: Handle, wow: *mut i32) -> i32;
    }
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process: Handle,
            class: u32,
            info: *mut c_void,
            len: u32,
            ret: *mut u32,
        ) -> i32;
    }

    const TH32CS_SNAPPROCESS: u32 = 0x2;
    const INVALID_HANDLE: Handle = -1isize as Handle;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_VM_READ: u32 = 0x10;
    // x64 layouts: PEB.ProcessParameters, and in RTL_USER_PROCESS_PARAMETERS the
    // Environment pointer and EnvironmentSize (the latter exists since Windows 8).
    const PEB_PARAMS: usize = 0x20;
    const PARAMS_ENV: usize = 0x80;
    const PARAMS_ENV_SIZE: usize = 0x3F0;
    /// A real environment is tens of KB; anything past this is a misread.
    const MAX_ENV: usize = 1 << 20;

    struct Owned(Handle);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn processes() -> Vec<(u32, String)> {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap.is_null() || snap == INVALID_HANDLE {
            return Vec::new();
        }
        let snap = Owned(snap);
        let mut out = Vec::new();
        let mut e: ProcessEntry32W = unsafe { std::mem::zeroed() };
        e.size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut ok = unsafe { Process32FirstW(snap.0, &mut e) };
        while ok != 0 {
            let len = e.exe.iter().position(|&c| c == 0).unwrap_or(e.exe.len());
            out.push((e.pid, String::from_utf16_lossy(&e.exe[..len])));
            ok = unsafe { Process32NextW(snap.0, &mut e) };
        }
        out
    }

    fn read(process: Handle, at: usize, buf: &mut [u8]) -> bool {
        let mut got = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                process,
                at as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut got,
            )
        };
        ok != 0 && got == buf.len()
    }

    fn read_usize(process: Handle, at: usize) -> Option<usize> {
        let mut b = [0u8; 8];
        read(process, at, &mut b).then(|| usize::from_le_bytes(b))
    }

    /// The process's environment block and image path. `None` when it cannot be
    /// opened or read, and for 32-bit processes (their PEB has another layout;
    /// Antigravity is 64-bit).
    pub fn environment_of(pid: u32) -> Option<(Vec<u16>, Option<PathBuf>)> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if h.is_null() {
            return None;
        }
        let h = Owned(h);
        let mut wow = 0i32;
        if unsafe { IsWow64Process(h.0, &mut wow) } == 0 || wow != 0 {
            return None;
        }
        let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let mut ret = 0u32;
        let status = unsafe {
            NtQueryInformationProcess(
                h.0,
                0,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret,
            )
        };
        if status < 0 || pbi.peb == 0 {
            return None;
        }
        let params = read_usize(h.0, pbi.peb + PEB_PARAMS)?;
        let env = read_usize(h.0, params + PARAMS_ENV)?;
        let size = read_usize(h.0, params + PARAMS_ENV_SIZE)?;
        if env == 0 || size == 0 || size > MAX_ENV {
            return None;
        }
        let mut bytes = vec![0u8; size];
        if !read(h.0, env, &mut bytes) {
            return None;
        }
        let block: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();

        let mut name = vec![0u16; 32768];
        let mut len = name.len() as u32;
        let path = (unsafe { QueryFullProcessImageNameW(h.0, 0, name.as_mut_ptr(), &mut len) }
            != 0)
            .then(|| PathBuf::from(String::from_utf16_lossy(&name[..len as usize])));
        Some((block, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(entries: &[&str]) -> Vec<u16> {
        let mut out = Vec::new();
        for e in entries {
            out.extend(e.encode_utf16());
            out.push(0);
        }
        out.push(0);
        out
    }

    #[test]
    fn finds_the_variable_in_any_case() {
        let b = block(&["PATH=C:\\x", "ag_ls_proxy=http://127.0.0.1:53129"]);
        assert!(block_has_var(&b, "AG_LS_PROXY"));
    }

    #[test]
    fn a_prefix_or_a_value_is_not_the_variable() {
        let b = block(&["AG_LS_PROXY_OLD=1", "X=AG_LS_PROXY=1"]);
        assert!(!block_has_var(&b, "AG_LS_PROXY"));
    }

    #[test]
    fn stops_at_the_terminating_empty_entry() {
        let mut b = block(&["PATH=1"]);
        b.extend("AG_LS_PROXY=junk".encode_utf16());
        assert!(!block_has_var(&b, "AG_LS_PROXY"));
    }

    /// This test process has whatever its parent had; it only checks that the
    /// reader runs over the live process table without crashing and never
    /// reports itself.
    #[test]
    fn holders_never_lists_this_process() {
        let own = std::process::id();
        let found = holders("PATH");
        assert!(found.iter().all(|h| h.pid != own));
        // Every user process has PATH; the parent `cargo` at least is readable.
        #[cfg(target_os = "windows")]
        assert!(!found.is_empty(), "no environment block could be read");
        let ag: Vec<_> = holders("AG_LS_PROXY").into_iter().map(|h| h.name).collect();
        eprintln!("AG_LS_PROXY holders: {:?}", ag);
    }
}
