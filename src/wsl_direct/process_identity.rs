//! Read/synchronize-only native process identity. A PID alone is never custody.
use std::ffi::OsString;
use std::os::windows::{ffi::OsStringExt, io::{AsRawHandle, FromRawHandle, OwnedHandle}};
use std::path::PathBuf;
use windows_sys::Win32::{Foundation::{FILETIME, HANDLE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
    Security::Authorization::ConvertSidToStringSidW,
    System::Threading::{GetProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
        QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE}};

type Result<T> = std::result::Result<T, String>;
fn error(stage: &str) -> String { format!("{stage}: {}", std::io::Error::last_os_error()) }

pub(crate) struct ProcessIdentity {
    handle: OwnedHandle,
    pid: u32,
    creation: u64,
    sid: String,
    image: PathBuf,
}
impl ProcessIdentity {
    pub(crate) fn open(pid: u32) -> Result<Self> {
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) };
        if raw.is_null() { return Err(error("open process identity")); }
        Self::receive(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
    pub(crate) fn receive(handle: OwnedHandle) -> Result<Self> {
        let raw = handle.as_raw_handle();
        let pid = unsafe { GetProcessId(raw) };
        if pid == 0 { return Err(error("receive process ID")); }
        let creation = creation_time(raw)?;
        let sid = process_sid(raw)?;
        let image = image_path(raw)?;
        Ok(Self { handle, pid, creation, sid, image })
    }
    pub(crate) fn current() -> Result<Self> { Self::open(std::process::id()) }
    pub(crate) fn pid(&self) -> u32 { self.pid }
    pub(crate) fn creation(&self) -> u64 { self.creation }
    pub(crate) fn sid(&self) -> &str { &self.sid }
    pub(crate) fn image(&self) -> &std::path::Path { &self.image }
    pub(crate) fn handle(&self) -> HANDLE { self.handle.as_raw_handle() }
    pub(crate) fn alive(&self) -> Result<bool> {
        match unsafe { WaitForSingleObject(self.handle(), 0) } {
            WAIT_OBJECT_0 => Ok(false), WAIT_TIMEOUT => Ok(true), _ => Err(error("observe process lifetime")),
        }
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        if unsafe { GetProcessId(self.handle()) } != self.pid || creation_time(self.handle())? != self.creation {
            return Err("native process creation identity changed".into());
        }
        Ok(())
    }
}
fn creation_time(process: HANDLE) -> Result<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(error("receive process creation time"));
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}
fn process_sid(process: HANDLE) -> Result<String> {
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 { return Err(error("open process token")); }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut needed = 0u32;
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 { return Err(error("receive token user length")); }
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut data = vec![0usize; words];
    if unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, data.as_mut_ptr().cast(), needed, &mut needed) } == 0 {
        return Err(error("receive token user"));
    }
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 { return Err(error("receive process SID")); }
    let mut length = 0;
    unsafe { while *text.add(length) != 0 { length += 1; } }
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe { LocalFree(text.cast()) };
    result.map_err(|_| "process SID encoding".into())
}
fn image_path(process: HANDLE) -> Result<PathBuf> {
    let mut capacity = 256u32;
    loop {
        let mut buffer = vec![0u16; capacity as usize];
        let mut written = capacity;
        if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut written) } != 0 {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..written as usize])));
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(122) { return Err(error("receive process image")); }
        capacity = capacity.checked_mul(2).ok_or("native process path length overflow")?;
    }
}
