//! Shared Windows native path, identity, security and resource primitives.
use super::*;
use std::ffi::c_void;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;

/// Internal filesystem spelling of an already admitted ordinary disk path.
/// Persisted paths and native GUID locators keep their existing representations.
pub(super) struct NativeFsPath {
    path: PathBuf,
    units: Vec<u16>,
}
impl NativeFsPath {
    const DOS_PREFIX: [u16; 4] = [92, 92, 63, 92];

    pub(super) fn encode(path: &WindowsLocalPath) -> Result<Self> {
        let mut units = Self::DOS_PREFIX.to_vec();
        units.extend(path.as_path().as_os_str().encode_wide().map(|unit| {
            if unit == 47 { 92 } else { unit }
        }));
        let path = OsString::from_wide(&units).into();
        units.push(0);
        Ok(Self { path, units })
    }

    pub(super) fn from_path(path: &Path) -> Result<Self> {
        Self::encode(&WindowsLocalPath::parse(path.as_os_str())?)
    }

    pub(super) fn as_ptr(&self) -> *const u16 {
        self.units.as_ptr()
    }

    pub(super) fn as_path(&self) -> &Path {
        &self.path
    }

    fn receive_name(&self, units: &[u16]) -> Result<PathBuf> {
        // Only the DOS-disk prefix introduced by this owner may be removed.
        // Other namespaces still go through the unchanged external parser.
        let ordinary = if units.starts_with(&Self::DOS_PREFIX)
            && units.get(4).is_some_and(|c| (65..=90).contains(c) || (97..=122).contains(c))
            && units.get(5) == Some(&58)
            && units.get(6) == Some(&92)
        {
            &units[4..]
        } else {
            units
        };
        WindowsLocalPath::parse(&OsString::from_wide(ordinary)).map(|path| path.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObjectId {
    pub(crate) volume: u64,
    pub(crate) file: [u8; 16],
}
#[repr(C)]
struct FileIdInformation {
    volume: u64,
    file: [u8; 16],
}
#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit: i32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(
        file: *mut c_void,
        class: u32,
        data: *mut c_void,
        size: u32,
    ) -> i32;
    fn GetFinalPathNameByHandleW(file: *mut c_void, out: *mut u16, size: u32, flags: u32) -> u32;
    fn GetLongPathNameW(path: *const u16, out: *mut u16, size: u32) -> u32;
    #[cfg(test)]
    fn GetShortPathNameW(path: *const u16, out: *mut u16, size: u32) -> u32;
    fn CreateDirectoryW(path: *const u16, security: *mut SecurityAttributes) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *mut SecurityAttributes,
        creation: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    pub(super) fn LocalFree(memory: *mut c_void) -> *mut c_void;
    pub(super) fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CompareStringOrdinal(
        first: *const u16,
        n: i32,
        second: *const u16,
        m: i32,
        ignore: i32,
    ) -> i32;
}
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoCreateGuid(guid: *mut Guid) -> i32;
    fn CoTaskMemFree(memory: *mut c_void);
}
#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        id: *const Guid,
        flags: u32,
        token: *mut c_void,
        out: *mut *mut u16,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    pub(super) fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
    pub(super) fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        version: u32,
        out: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    pub(super) fn GetSecurityDescriptorDacl(
        sd: *mut c_void,
        present: *mut i32,
        acl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
    pub(super) fn IsWellKnownSid(sid: *mut c_void, kind: u32) -> i32;
    pub(super) fn GetSecurityDescriptorControl(
        sd: *mut c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorGroup(
        sd: *mut c_void,
        group: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn SetSecurityInfo(
        handle: *mut c_void,
        kind: u32,
        information: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
    fn SetKernelObjectSecurity(handle: *mut c_void, information: u32, descriptor: *mut c_void) -> i32;
    fn LookupAccountNameW(
        system: *const u16,
        name: *const u16,
        sid: *mut c_void,
        sid_size: *mut u32,
        domain: *mut u16,
        domain_size: *mut u32,
        kind: *mut u32,
    ) -> i32;
}
/// DACL-only metadata preservation on an already bound owned postimage handle.
/// Owner/group are observed and never assigned; the caller verifies full final SD.
pub(super) fn restore_received_dacl(file: &File, expected: &[u8]) -> Result<()> {
    let mut before = security(file.as_raw_handle(), 1 | 2 | 4)?;
    if before == expected {
        return Ok(());
    }
    let mut source = expected.to_vec();
    for group in [false, true] {
        let mut old = std::ptr::null_mut();
        let mut new = std::ptr::null_mut();
        let mut d = 0;
        let (a, b) = unsafe {
            if group {
                (
                    GetSecurityDescriptorGroup(source.as_mut_ptr().cast(), &mut old, &mut d),
                    GetSecurityDescriptorGroup(before.as_mut_ptr().cast(), &mut new, &mut d),
                )
            } else {
                (
                    GetSecurityDescriptorOwner(source.as_mut_ptr().cast(), &mut old, &mut d),
                    GetSecurityDescriptorOwner(before.as_mut_ptr().cast(), &mut new, &mut d),
                )
            }
        };
        if a == 0 || b == 0 || old.is_null() || new.is_null() || unsafe { EqualSid(old, new) } == 0
        {
            return Err("postimage owner/group changed; DACL restoration refused".into());
        }
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe {
        GetSecurityDescriptorControl(source.as_mut_ptr().cast(), &mut control, &mut revision)
    } == 0
    {
        return Err(io(
            "received descriptor control",
            std::io::Error::last_os_error(),
        ));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            source.as_mut_ptr().cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err("received DACL absent/null; restoration refused".into());
    }
    let protection = if control & 0x1000 != 0 {
        0x8000_0000
    } else {
        0x2000_0000
    };
    // Preserve the captured inheritance model, without changing identity or
    // masking flags. The FILE API retains AUTO_INHERITED; the existing private
    // path retains its proved non-auto-inherited descriptor contract.
    let (operation, failure) = if control & 0x0400 != 0 {
        let status = unsafe { SetSecurityInfo(file.as_raw_handle(), 1, 4 | protection,
            std::ptr::null_mut(), std::ptr::null_mut(), acl, std::ptr::null_mut()) };
        ("SetSecurityInfo FILE DACL restoration", if status == 0 { None } else { Some(std::io::Error::from_raw_os_error(status as i32)) })
    } else {
        let restored = unsafe { SetKernelObjectSecurity(file.as_raw_handle(), 4 | protection, source.as_mut_ptr().cast()) };
        ("SetKernelObjectSecurity DACL restoration", if restored == 0 { Some(std::io::Error::last_os_error()) } else { None })
    };
    #[cfg(test)]
    TEST_DACL_STATUSES.with(|v| v.borrow_mut().push(failure.as_ref().and_then(|error|error.raw_os_error()).unwrap_or(0) as u32));
    if let Some(error)=failure {
        return Err(io(operation,error));
    }
    if security(file.as_raw_handle(), 1 | 2 | 4)? != expected {
        return Err(
            format!("{operation} returned success but full received security descriptor differs"),
        );
    }
    Ok(())
}

// Only the vendor Recover receiver supplies this helper's admitted snapshots.
// Parse bounded self-relative components before comparing or passing a SID to FFI.
fn group_security_parts(sd: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    validate_captured_identity_descriptor(sd)?;
    let sid = |field: usize| -> Result<&[u8]> {
        let start = u32::from_le_bytes(sd[field..field + 4].try_into().unwrap()) as usize;
        let length = 8 + 4 * usize::from(sd[start + 1]);
        sd.get(start..start + length).ok_or_else(|| "group metadata SID bounds invalid".into())
    };
    let control = u16::from_le_bytes([sd[2], sd[3]]);
    let start = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
    let header = sd.get(start..).filter(|_| start >= 20).ok_or("group metadata DACL absent")?;
    if control & 4 == 0 || header.len() < 8 || sd[12..16] != [0; 4] {
        return Err("group metadata requires the captured non-null DACL and no SACL component".into());
    }
    let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let acl = header.get(..length).filter(|_| length >= 8).ok_or("group metadata ACL bounds invalid")?;
    Ok((sid(4)?, sid(8)?, acl))
}

pub(super) fn current_token_user_sid() -> Result<Vec<u8>> {
    let mut token = token_user()?;
    let pointer = user_sid(&mut token)? as usize;
    let start = pointer.checked_sub(token.as_ptr() as usize).ok_or("token SID outside buffer")?;
    let sid = token.get(start..).ok_or("token SID outside buffer")?;
    if sid.len() < 8 || sid[0] != 1 || sid[1] > 15 {
        return Err("token SID invalid".into());
    }
    Ok(sid.get(..8 + 4 * usize::from(sid[1])).ok_or("token SID truncated")?.to_vec())
}

/// Pure receiving shared by admission, persisted proof and final receiving.
/// True means the complete raw desired descriptor is already present.
pub(super) fn receive_group_metadata(actual: &[u8], recorded: &[u8], desired: &[u8], actor: &[u8]) -> Result<bool> {
    let (owner, group, dacl) = group_security_parts(actual)?;
    let (old_owner, old_group, old_dacl) = group_security_parts(recorded)?;
    let (wanted_owner, wanted_group, wanted_dacl) = group_security_parts(desired)?;
    if wanted_owner != wanted_group || wanted_owner != actor
        || owner != wanted_owner || old_owner != wanted_owner
        || actual[..4] != desired[..4] || recorded[..4] != desired[..4]
        || dacl != wanted_dacl || old_dacl != wanted_dacl
        || (group != old_group && group != wanted_group) {
        return Err("RecoveryRequired: vendor metadata is outside the exact group-only class".into());
    }
    if group == wanted_group && actual != desired {
        return Err("RecoveryRequired: desired group lacks exact full descriptor receiving".into());
    }
    Ok(actual == desired)
}

/// Keeps the exact no-follow object, data and ancestor guards until after return
/// and independent readback. It never adjusts token privileges or DACL/OWNER.
pub(super) struct GroupMetadataHandle {
    file: File,
    _parents: Vec<File>,
    expected: SourceSnapshot,
    object: ObjectId,
    recorded: Vec<u8>,
    desired: Vec<u8>,
    actor: Vec<u8>,
}
impl GroupMetadataHandle {
    pub(super) fn open(expected: &SourceSnapshot, object: &ObjectId, recorded: &[u8], desired: &[u8], actor: &[u8]) -> Result<Self> {
        let parents = parents(&expected.target)?;
        // FILE_READ_DATA/ATTRIBUTES for existing snapshot receiving, plus only
        // READ_CONTROL | WRITE_OWNER for security. No WRITE_DAC or SACL access.
        let file = OpenOptions::new().access_mode(0x000A_0081).share_mode(READ)
            .custom_flags(OPEN_REPARSE).open(NativeFsPath::from_path(&expected.target)?.as_path())
            .map_err(|e| io("vendor group READ_CONTROL/WRITE_OWNER (not called)", e))?;
        let mut received = Self { file, _parents: parents, expected: expected.clone(), object: object.clone(),
            recorded: recorded.to_vec(), desired: desired.to_vec(), actor: actor.to_vec() };
        received.recheck()?;
        Ok(received)
    }
    pub(super) fn recheck(&mut self) -> Result<()> {
        if current_token_user_sid()? != self.actor || object_id(&self.file)? != self.object
            || !same_snapshot(&read_checked(&mut self.file, &self.expected.target)?, &self.expected) {
            return Err("RecoveryRequired: group call actor/postimage changed before call".into());
        }
        receive_group_metadata(&self.expected.identity.security_descriptor, &self.recorded, &self.desired, &self.actor)?;
        Ok(())
    }
    /// The returned WinError is the acquired native outcome. Nothing fallible
    /// runs between the API and returning it to the durable result writer.
    pub(super) fn set_group(&mut self) -> u32 {
        let start = u32::from_le_bytes(self.desired[8..12].try_into().unwrap()) as usize;
        #[cfg(test)]
        TEST_GROUP_CALLS.with(|value| value.set(value.get() + 1));
        unsafe { SetSecurityInfo(self.file.as_raw_handle(), 1, 2, std::ptr::null_mut(),
            self.desired.as_mut_ptr().add(start).cast(), std::ptr::null_mut(), std::ptr::null_mut()) }
    }
    pub(super) fn readback(&mut self) -> Result<(SourceSnapshot, ObjectId)> {
        let snapshot = read_checked(&mut self.file, &self.expected.target)?;
        Ok((snapshot, object_id(&self.file)?))
    }
}
#[cfg(test)]
thread_local! { pub(super) static TEST_GROUP_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
pub(super) fn fixture_wrong_group_metadata(source: &FileIdentity) -> Result<FileIdentity> {
    #[link(name = "advapi32")]
    unsafe extern "system" { fn CheckTokenMembership(token: *mut c_void, sid: *mut c_void, member: *mut i32) -> i32; }
    let actor = current_token_user_sid()?;
    receive_group_metadata(&source.security_descriptor, &source.security_descriptor, &source.security_descriptor, &actor)?;
    let user = sid_text(actor.as_ptr() as *mut c_void)?;
    let text: Vec<_> = format!("O:{user}G:BU").encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    let mut length = 0;
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, &mut length) } == 0 {
        return Err(io("fixture differing group descriptor", std::io::Error::last_os_error()));
    }
    let descriptor = LocalMemory(descriptor);
    let mut group = std::ptr::null_mut();
    let mut defaulted = 0;
    let mut enabled = 0;
    if unsafe { GetSecurityDescriptorGroup(descriptor.0, &mut group, &mut defaulted) } == 0 || group.is_null()
        || unsafe { CheckTokenMembership(std::ptr::null_mut(), group, &mut enabled) } == 0 || enabled == 0
        || unsafe { EqualSid(group, actor.as_ptr() as *mut c_void) } != 0 {
        return Err("owned fixture requires an enabled differing Builtin Users group".into());
    }
    let mut metadata = source.clone();
    metadata.security_descriptor = unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length as usize) }.to_vec();
    Ok(metadata)
}
#[cfg(test)]
pub(super) fn initialize_token_group_fixture(path: &Path) -> Result<()> {
    let _parents = parents(path)?;
    let actor = current_token_user_sid()?;
    let before = read_path(path, READ | DELETE)?;
    let file = OpenOptions::new().access_mode(0x000A_0081).share_mode(READ | DELETE).custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(path)?.as_path()).map_err(|e| io("owned fixture group initialization", e))?;
    let status = unsafe { SetSecurityInfo(file.as_raw_handle(), 1, 2, std::ptr::null_mut(), actor.as_ptr() as *mut c_void,
        std::ptr::null_mut(), std::ptr::null_mut()) };
    if status != 0 { return Err(format!("owned fixture group initialization WinError={status}")); }
    let after = read_path(path, READ | DELETE)?;
    let (owner, group, dacl) = group_security_parts(&after.identity.security_descriptor)?;
    let (old_owner, _, old_dacl) = group_security_parts(&before.identity.security_descriptor)?;
    if owner != actor || group != actor || owner != old_owner || dacl != old_dacl
        || before.bytes != after.bytes || before.identity.index != after.identity.index || before.identity.size != after.identity.size
        || before.identity.volume != after.identity.volume || before.identity.attributes != after.identity.attributes
        || before.identity.creation != after.identity.creation || before.identity.write != after.identity.write {
        return Err("owned fixture group initialization changed another field".into());
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn initialize_inherited_fixture(path: &Path) -> Result<()> {
    set_fixture_protection(path, false)
}
#[cfg(test)]
pub(super) fn set_fixture_protection(path: &Path, protected: bool) -> Result<()> {
    let native_path = NativeFsPath::from_path(path)?;
    let file = OpenOptions::new()
        .access_mode(0x0006_0000)
        .share_mode(READ | DELETE)
        .custom_flags(OPEN_REPARSE)
        .open(native_path.as_path())
        .map_err(|e| io("owned fixture inheritance handle", e))?;
    let mut sd = security(file.as_raw_handle(), 1 | 2 | 4)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            sd.as_mut_ptr().cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err("fixture DACL unavailable".into());
    }
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            1,
            4 | if protected { 0x8000_0000 } else { 0x2000_0000 },
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(format!("fixture inheritance status {status}"));
    }
    let mut sd = security(file.as_raw_handle(), 1 | 2 | 4)?;
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(sd.as_mut_ptr().cast(), &mut control, &mut revision) }
        == 0
        || (control & 0x1000 != 0) != protected
        || (!protected && control & 0x400 == 0)
    {
        return Err("fixture source is not unprotected AutoInherited class".into());
    }
    Ok(())
}
pub(super) fn object_id(file: &File) -> Result<ObjectId> {
    let mut data = FileIdInformation {
        volume: 0,
        file: [0; 16],
    };
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            18,
            (&mut data as *mut FileIdInformation).cast(),
            std::mem::size_of::<FileIdInformation>() as u32,
        )
    } == 0
    {
        return Err(io("full native identity", std::io::Error::last_os_error()));
    }
    Ok(ObjectId {
        volume: data.volume,
        file: data.file,
    })
}
pub(super) fn case_insensitive(file: &File) -> Result<()> {
    let mut flags = 0u32;
    if unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), 23, (&mut flags as *mut u32).cast(), 4)
    } == 0
    {
        return Err(io("directory case mode", std::io::Error::last_os_error()));
    }
    if flags & 1 != 0 {
        return Err("case-sensitive directory unsupported".into());
    }
    Ok(())
}
pub(super) fn ordinal(a: &[u16], b: &[u16]) -> Result<bool> {
    let n = i32::try_from(a.len()).map_err(|_| "native locator length")?;
    let m = i32::try_from(b.len()).map_err(|_| "native locator length")?;
    match unsafe { CompareStringOrdinal(a.as_ptr(), n, b.as_ptr(), m, 1) } {
        0 => Err(io(
            "native ordinal comparison",
            std::io::Error::last_os_error(),
        )),
        2 => Ok(true),
        _ => Ok(false),
    }
}
pub(super) fn final_path(file: &File) -> Result<Vec<u16>> {
    let count =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), std::ptr::null_mut(), 0, 1) };
    if count == 0 {
        return Err(io("native locator length", std::io::Error::last_os_error()));
    }
    let mut out = vec![0u16; count as usize];
    let n = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), out.as_mut_ptr(), count, 1) };
    if n == 0 || n >= count {
        return Err("native locator receiving failed".into());
    }
    out.truncate(n as usize);
    Ok(out)
}
pub(super) fn long_path(path: &Path) -> Result<PathBuf> {
    let path = NativeFsPath::from_path(path)?;
    let count = unsafe { GetLongPathNameW(path.as_ptr(), std::ptr::null_mut(), 0) };
    if count == 0 {
        return Err(io("long path length", std::io::Error::last_os_error()));
    }
    let mut out = vec![0u16; count as usize];
    let n = unsafe { GetLongPathNameW(path.as_ptr(), out.as_mut_ptr(), count) };
    if n == 0 || n >= count {
        return Err("long path receiving failed".into());
    }
    out.truncate(n as usize);
    path.receive_name(&out)
}
#[cfg(test)]
pub(super) fn short_fixture_path(path: &Path) -> Result<PathBuf> {
    let input = NativeFsPath::from_path(path)?;
    let count = unsafe { GetShortPathNameW(input.as_ptr(), std::ptr::null_mut(), 0) };
    if count == 0 {
        return Err(io(
            "short-name fixture observation",
            std::io::Error::last_os_error(),
        ));
    }
    let mut out = vec![0; count as usize];
    let length = unsafe { GetShortPathNameW(input.as_ptr(), out.as_mut_ptr(), count) };
    if length == 0 || length >= count {
        return Err("short-name fixture receiving failed".into());
    }
    out.truncate(length as usize);
    input.receive_name(&out)
}
pub(super) fn unique_id() -> Result<String> {
    let mut g = Guid {
        a: 0,
        b: 0,
        c: 0,
        d: [0; 8],
    };
    if unsafe { CoCreateGuid(&mut g) } < 0 {
        return Err("OS operation identity unavailable".into());
    }
    Ok(format!(
        "{:08x}{:04x}{:04x}{}",
        g.a,
        g.b,
        g.c,
        hex::encode(g.d)
    ))
}
pub(super) fn known_folder() -> Result<PathBuf> {
    native_known_folder(NativeKnownFolder::LocalAppData)
}
pub(super) enum NativeKnownFolder {
    LocalAppData,
    ProgramFiles,
    ProgramData,
}
pub(super) fn native_known_folder(folder: NativeKnownFolder) -> Result<PathBuf> {
    // Windows SDK KnownFolders.h identifiers. ProgramFiles intentionally follows
    // the supported executing package architecture, not ProgramFilesX64/X86.
    let id = match folder {
        NativeKnownFolder::LocalAppData => Guid {
            a: 0xf1b32785,
            b: 0x6fba,
            c: 0x4fcf,
            d: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
        },
        NativeKnownFolder::ProgramFiles => Guid {
            a: 0x905e63b6,
            b: 0xc1bf,
            c: 0x494e,
            d: [0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a],
        },
        NativeKnownFolder::ProgramData => Guid {
            a: 0x62ab5d82,
            b: 0xfdc1,
            c: 0x4dc3,
            d: [0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97],
        },
    };
    let mut out = std::ptr::null_mut();
    let hr = unsafe { SHGetKnownFolderPath(&id, 0, std::ptr::null_mut(), &mut out) };
    if hr < 0 || out.is_null() {
        if !out.is_null() {
            unsafe { CoTaskMemFree(out.cast()) }
        }
        return Err(format!("KnownFolder unavailable: {hr:#x}"));
    }
    let mut n = 0;
    unsafe {
        while *out.add(n) != 0 {
            n += 1
        }
    }
    let path = PathBuf::from(unsafe { OsString::from_wide(std::slice::from_raw_parts(out, n)) });
    unsafe { CoTaskMemFree(out.cast()) }
    validate_path(&path)?;
    Ok(path)
}
pub(super) fn token_user() -> Result<Vec<u8>> {
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) } == 0 {
        return Err(io("current token", std::io::Error::last_os_error()));
    }
    let token = OwnedHandle(raw);
    let mut needed = 0;
    unsafe { GetTokenInformation(token.0, 1, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err("token user length unavailable".into());
    }
    let mut data = vec![0; needed as usize];
    if unsafe { GetTokenInformation(token.0, 1, data.as_mut_ptr().cast(), needed, &mut needed) }
        == 0
    {
        return Err(io("token user", std::io::Error::last_os_error()));
    }
    Ok(data)
}
pub(super) fn user_sid(data: &mut [u8]) -> Result<*mut c_void> {
    if data.len() < std::mem::size_of::<*mut c_void>() {
        return Err("invalid token user".into());
    }
    let sid = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<*mut c_void>()) };
    if sid.is_null() {
        return Err("missing token user".into());
    }
    Ok(sid)
}
pub(super) fn private(file: &File) -> Result<()> {
    check_access(file, true, false, true)
}
pub(super) fn existing_private(file: &File) -> Result<()> {
    check_access(file, false, false, true)
}
pub(super) fn state_parent(file: &File) -> Result<()> {
    check_access(file, false, false, false)
}
pub(super) fn state_parent_context(
    file: &File,
    context: &super::AncestorAccessContext,
) -> Result<()> {
    // Context qualifies ancestor ACL actors, never changes the required owner.
    let mut sd = security(file.as_raw_handle(), 1)?;
    let mut owner = std::ptr::null_mut();
    let mut d = 0;
    let mut token = token_user()?;
    if unsafe { GetSecurityDescriptorOwner(sd.as_mut_ptr().cast(), &mut owner, &mut d) } == 0
        || owner.is_null()
        || unsafe { EqualSid(owner, user_sid(&mut token)?) } == 0
    {
        return Err("state-parent owner conflict".into());
    }
    context.check(file, false)
}
pub(super) fn ancestor_integrity(file: &File) -> Result<()> {
    check_access(file, false, true, false)
}
pub(super) fn trusted_installer_sid() -> Result<Vec<u8>> {
    let name: Vec<_> = "NT SERVICE\\TrustedInstaller"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut size = 0;
    let mut domain_size = 0;
    let mut kind = 0;
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut kind,
        )
    };
    if size == 0 {
        return Err(io(
            "Windows Modules Installer identity unavailable",
            std::io::Error::last_os_error(),
        ));
    }
    let mut sid = vec![0; size as usize];
    let mut domain = vec![0; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut kind,
        )
    } == 0
    {
        return Err(io(
            "Windows Modules Installer identity resolution",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(sid)
}
fn check_access(
    file: &File,
    managed: bool,
    system_ancestor: bool,
    confidential: bool,
) -> Result<()> {
    let mut sd = security(file.as_raw_handle(), 1 | 4)?;
    let mut token = token_user()?;
    let sid = user_sid(&mut token)?;
    let trusted_service = if system_ancestor {
        Some(trusted_installer_sid()?)
    } else {
        None
    };
    let mut owner = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(sd.as_mut_ptr().cast(), &mut owner, &mut defaulted) }
        == 0
        || owner.is_null()
    {
        return Err("object owner unavailable".into());
    }
    if unsafe { EqualSid(owner, sid) } == 0 {
        if !system_ancestor {
            return Err("private/state-parent owner conflict".into());
        }
        if unsafe { IsWellKnownSid(owner, 22) } == 0 && unsafe { IsWellKnownSid(owner, 26) } == 0 {
            if !trusted_service
                .as_ref()
                .is_some_and(|t| unsafe { EqualSid(owner, t.as_ptr() as *mut c_void) } != 0)
            {
                return Err("ancestor owner can replace the state namespace".into());
            }
        }
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(sd.as_mut_ptr().cast(), &mut control, &mut revision) }
        == 0
    {
        return Err(io(
            "private protection control",
            std::io::Error::last_os_error(),
        ));
    }
    if managed && control & 0x1000 == 0 {
        return Err("managed DACL is not protected".into());
    }
    let mut present = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            sd.as_mut_ptr().cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err("private DACL absent/null".into());
    }
    if !confidential {
        return super::ancestor_context::check_empty(file, system_ancestor);
    }
    // ACL header's AceCount is a WORD at offset 4. GetAce validates each entry.
    let count = unsafe { std::ptr::read_unaligned((acl as *const u8).add(4).cast::<u16>()) };
    for i in 0..u32::from(count) {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(acl, i, &mut ace) } == 0 || ace.is_null() {
            return Err("private ACE unavailable".into());
        }
        let header = ace as *const u8;
        let kind = unsafe { *header };
        let size = unsafe { std::ptr::read_unaligned(header.add(2).cast::<u16>()) };
        if kind == 1 || unsafe { *header.add(1) } & 8 != 0 {
            continue;
        } // deny/inherit-only grants no current access.
        if kind != 0 || size < 12 {
            return Err("unsupported private ACL entry".into());
        }
        let principal = unsafe { header.add(8) } as *mut c_void;
        if unsafe { EqualSid(principal, sid) } == 0
            && unsafe { IsWellKnownSid(principal, 22) } == 0
            && unsafe { IsWellKnownSid(principal, 26) } == 0
            && !trusted_service
                .as_ref()
                .is_some_and(|t| unsafe { EqualSid(principal, t.as_ptr() as *mut c_void) } != 0)
        {
            let mask = unsafe { std::ptr::read_unaligned(header.add(4).cast::<u32>()) };
            // Directory sibling creation is not replacement of this held path.
            const REPLACEMENT_RIGHTS: u32 = 0x500D_0150;
            if confidential || mask & REPLACEMENT_RIGHTS != 0 {
                return Err("private/ancestor ACL grants foreign replacement access".into());
            }
        }
    }
    Ok(())
}
struct LocalMemory(*mut c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn private_descriptor() -> Result<LocalMemory> {
    private_descriptor_with_identity(None).map(|(descriptor, _)| descriptor)
}
fn sid_text(sid: *mut c_void) -> Result<String> {
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io(
            "current SID conversion",
            std::io::Error::last_os_error(),
        ));
    }
    let _text = LocalMemory(text.cast());
    let mut n = 0;
    unsafe {
        while *text.add(n) != 0 {
            n += 1
        }
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, n) })
        .map_err(|_| "SID text encoding".into())
}
fn validate_captured_identity_descriptor(descriptor: &[u8]) -> Result<()> {
    // GetSecurityDescriptorOwner/Group expect a complete self-relative header
    // and SID components. Check their bounds before passing captured bytes to FFI.
    if descriptor.len() < 20 || descriptor[0] != 1 ||
        u16::from_le_bytes([descriptor[2], descriptor[3]]) & 0x8000 == 0 {
        return Err("captured security descriptor is absent or invalid".into());
    }
    for field in [4, 8] {
        let offset = u32::from_le_bytes(descriptor[field..field + 4].try_into().unwrap()) as usize;
        let sid = descriptor.get(offset..).filter(|_| offset >= 20)
            .ok_or("captured owner/group is absent or invalid")?;
        // SID revision 1 permits at most 15 subauthorities (Windows SID format).
        if sid.len() < 8 || sid[0] != 1 || sid[1] > 15 || sid.len() < 8 + 4 * usize::from(sid[1]) {
            return Err("captured owner/group is absent or invalid".into());
        }
    }
    Ok(())
}
fn private_descriptor_with_identity(captured: Option<&[u8]>) -> Result<(LocalMemory, u32)> {
    let mut token = token_user()?;
    let user = sid_text(user_sid(&mut token)?)?;
    let identity = if let Some(captured) = captured {
        validate_captured_identity_descriptor(captured)?;
        let mut captured = captured.to_vec();
        let mut owner = std::ptr::null_mut();
        let mut group = std::ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorOwner(captured.as_mut_ptr().cast(), &mut owner, &mut defaulted) } == 0
            || unsafe { GetSecurityDescriptorGroup(captured.as_mut_ptr().cast(), &mut group, &mut defaulted) } == 0
            || owner.is_null() || group.is_null()
        {
            return Err("captured metadata owner/group unavailable before stage creation".into());
        }
        format!("O:{}G:{}", sid_text(owner)?, sid_text(group)?)
    } else {
        format!("O:{user}")
    };
    let sddl: Vec<_> = format!("{identity}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut sd = std::ptr::null_mut();
    let mut length = 0;
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut sd,
            &mut length,
        )
    } == 0
    {
        return Err(io("private descriptor", std::io::Error::last_os_error()));
    }
    let descriptor = LocalMemory(sd);
    if sd.is_null() || length == 0 {
        return Err("private descriptor bytes unavailable".into());
    }
    Ok((descriptor, length))
}
pub(super) fn create_private_dir(path: &Path) -> Result<()> {
    let native_path = NativeFsPath::from_path(path)?;
    let _parents = parents(path)?;
    let sd = private_descriptor()?;
    let mut sa = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: sd.0,
        inherit: 0,
    };
    if unsafe { CreateDirectoryW(native_path.as_ptr(), &mut sa) } == 0 {
        return Err(io(
            "exclusive private directory create",
            std::io::Error::last_os_error(),
        ));
    }
    let receiving = (|| {
        let p = CheckedPath::open(path, PathKind::Directory, PathPurpose::Review)?;
        private(&p.file)
    })();
    receiving.map_err(|e: String| format!("PreparationIncomplete: directory created at {}; actual identity/protection receiving failed: {e}; preserve it",path.display()))
}
pub(super) fn create_owned_file(path: &Path) -> Result<File> {
    create_owned_file_with_identity(path, None)
}
// A self-relative descriptor may pack its components in any order. This
// receiving is only for a fresh authored stage, not stored target snapshots.
fn authored_stage_descriptor_matches(actual: &[u8], authored: &[u8]) -> Result<bool> {
    let mut actual = actual.to_vec();
    let mut authored = authored.to_vec();
    let mut actual_control = 0;
    let mut authored_control = 0;
    let mut actual_revision = 0;
    let mut authored_revision = 0;
    if unsafe { GetSecurityDescriptorControl(actual.as_mut_ptr().cast(), &mut actual_control, &mut actual_revision) } == 0
        || unsafe { GetSecurityDescriptorControl(authored.as_mut_ptr().cast(), &mut authored_control, &mut authored_revision) } == 0
    {
        return Err(io("authored stage descriptor control", std::io::Error::last_os_error()));
    }
    if actual_control != authored_control || actual_revision != authored_revision
        || actual.get(..2) != authored.get(..2)
    {
        return Ok(false);
    }
    for group in [false, true] {
        let getter = if group { GetSecurityDescriptorGroup } else { GetSecurityDescriptorOwner };
        let mut actual_sid = std::ptr::null_mut();
        let mut authored_sid = std::ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { getter(actual.as_mut_ptr().cast(), &mut actual_sid, &mut defaulted) } == 0
            || unsafe { getter(authored.as_mut_ptr().cast(), &mut authored_sid, &mut defaulted) } == 0
            || actual_sid.is_null() || authored_sid.is_null()
        {
            return Err("authored stage owner/group unavailable".into());
        }
        if unsafe { EqualSid(actual_sid, authored_sid) } == 0 { return Ok(false); }
    }
    let acl = |sd: &mut [u8]| -> Result<(i32, i32, Vec<u8>)> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut pointer = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(sd.as_mut_ptr().cast(), &mut present, &mut pointer, &mut defaulted) } == 0
            || present == 0 || pointer.is_null()
        {
            return Err("authored private stage DACL unavailable".into());
        }
        // ACL.AclSize is the native byte size, including all ACE flags/order
        // and padding. Eight bytes is the Windows ACL header, not a policy cap.
        let size = unsafe { std::ptr::read_unaligned(pointer.cast::<u8>().add(2).cast::<u16>()) } as usize;
        if size < 8 { return Err("authored private stage ACL header invalid".into()); }
        Ok((present, defaulted, unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), size) }.to_vec()))
    };
    Ok(acl(&mut actual)? == acl(&mut authored)?)
}
fn create_owned_file_with_identity(path: &Path, captured: Option<&[u8]>) -> Result<File> {
    let native_path = NativeFsPath::from_path(path)?;
    let _parents = parents(path)?;
    let (sd, descriptor_length) = private_descriptor_with_identity(captured)?;
    let mut sa = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: sd.0,
        inherit: 0,
    };
    let raw = unsafe {
        CreateFileW(
            native_path.as_ptr(),
            0xC0000000,
            0,
            &mut sa,
            1,
            OPEN_REPARSE,
            std::ptr::null_mut(),
        )
    };
    if raw as isize == -1 {
        return Err(io(
            "exclusive private file create",
            std::io::Error::last_os_error(),
        ));
    }
    let file = unsafe { File::from_raw_handle(raw) };
    let receiving = if captured.is_some() {
        identity(&file).and_then(|_| {
            let expected = unsafe { std::slice::from_raw_parts(sd.0.cast::<u8>(), descriptor_length as usize) };
            if !authored_stage_descriptor_matches(&security(file.as_raw_handle(), 1 | 2 | 4)?, expected)? {
                return Err("captured metadata identity/private stage descriptor differs before publish".into());
            }
            Ok(())
        })
    } else {
        private(&file)
    };
    receiving.map_err(|e| {
        format!(
            "private file created at {}; protection receiving failed: {e}; preserve it",
            path.display()
        )
    })?;
    Ok(file)
}
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_owned_file(path)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| {
            format!(
                "{}; retained actual file {}",
                io("private file persist", e),
                path.display()
            )
        })?;
    drop(file);
    let mut received = CheckedPath::open(path, PathKind::File, PathPurpose::Review)?;
    private(&received.file)?;
    if received.read()? != bytes {
        return Err("private file readback mismatch".into());
    }
    Ok(())
}
/// Same-thread, zero-wait ownership; abandonment is an unresolved operation.
pub(super) struct Lease {
    pub(super) mutex: OwnedHandle,
    pub(super) held: bool,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.held {
            unsafe {
                ReleaseMutex(self.mutex.0);
            }
        }
    }
}
impl Lease {
    pub(super) fn acquire(directory: &CheckedPath, protocol: &str) -> Result<Self> {
        let name = format!(
            "Global\\AGUnlocker_{protocol}_{:016x}_{}",
            directory.object.volume,
            hex::encode(directory.object.file)
        );
        Self::acquire_name(&name)
    }
    pub(super) fn acquire_name(name: &str) -> Result<Self> {
        if !name.starts_with("Global\\AGUnlocker_") || name.chars().any(char::is_control) {
            return Err("owned native lease namespace invalid".into());
        }
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let sd = private_descriptor()?;
        let mut attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: sd.0,
            inherit: 0,
        };
        let mutex = OwnedHandle(unsafe {
            CreateMutexW((&mut attributes as *mut SecurityAttributes).cast(), 0, name.as_ptr())
        });
        if mutex.0.is_null() {
            return Err(io("owned mutex create", std::io::Error::last_os_error()));
        }
        mutex_current_owner(mutex.0)?;
        match unsafe { WaitForSingleObject(mutex.0, 0) } {
            0 => Ok(Self { mutex, held: true }),
            128 => {
                unsafe {
                    ReleaseMutex(mutex.0);
                };
                Err("RecoveryRequired: prior owner abandoned its mutex".into())
            }
            258 => Err("maintenance-pending: another owned operation holds lease".into()),
            _ => Err(io("owned mutex wait", std::io::Error::last_os_error())),
        }
    }
}
pub(super) const READ: u32 = 1;
pub(super) const WRITE: u32 = 2;
pub(super) const DELETE: u32 = 4;
pub(super) const REPARSE: u32 = 0x400;
pub(super) const DIRECTORY: u32 = 0x10;
pub(super) const OPEN_REPARSE: u32 = 0x0020_0000;
pub(super) const BACKUP_SEMANTICS: u32 = 0x0200_0000;

#[repr(C)]
#[derive(Default)]
pub(super) struct FileTime {
    pub(super) low: u32,
    pub(super) high: u32,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct FileInformation {
    pub(super) attributes: u32,
    pub(super) creation: FileTime,
    pub(super) access: FileTime,
    pub(super) write: FileTime,
    pub(super) volume: u32,
    pub(super) size_high: u32,
    pub(super) size_low: u32,
    pub(super) links: u32,
    pub(super) index_high: u32,
    pub(super) index_low: u32,
}
#[repr(C)]
pub(super) struct BasicInformation {
    pub(super) creation: i64,
    pub(super) access: i64,
    pub(super) write: i64,
    pub(super) change: i64,
    pub(super) attributes: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    pub(super) fn GetFileInformationByHandle(file: *mut c_void, info: *mut FileInformation) -> i32;
    pub(super) fn SetFileInformationByHandle(
        file: *mut c_void,
        class: u32,
        info: *const c_void,
        size: u32,
    ) -> i32;
    pub(super) fn ReplaceFileW(
        target: *const u16,
        replacement: *const u16,
        backup: *const u16,
        flags: u32,
        exclude: *mut c_void,
        reserved: *mut c_void,
    ) -> i32;
    pub(super) fn CreateMutexW(
        attributes: *mut c_void,
        owner: i32,
        name: *const u16,
    ) -> *mut c_void;
    pub(super) fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    pub(super) fn ReleaseMutex(handle: *mut c_void) -> i32;
    pub(super) fn CloseHandle(handle: *mut c_void) -> i32;
    pub(super) fn GetCurrentProcess() -> *mut c_void;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    pub(super) fn GetKernelObjectSecurity(
        object: *mut c_void,
        information: u32,
        descriptor: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    pub(super) fn OpenProcessToken(
        process: *mut c_void,
        access: u32,
        token: *mut *mut c_void,
    ) -> i32;
    pub(super) fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        data: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    pub(super) fn GetSecurityDescriptorOwner(
        descriptor: *mut c_void,
        owner: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn EqualSid(first: *mut c_void, second: *mut c_void) -> i32;
}

pub(super) struct OwnedHandle(pub(super) *mut c_void);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

pub(super) fn mutex_current_owner(handle: *mut c_void) -> Result<(), String> {
    let mut descriptor = security(handle, 1)?;
    let mut owner = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorOwner(descriptor.as_mut_ptr().cast(), &mut owner, &mut defaulted)
    } == 0
        || owner.is_null()
    {
        return Err(io("mutex security owner", std::io::Error::last_os_error()));
    }
    let mut raw_token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw_token) } == 0 {
        return Err(io("current token", std::io::Error::last_os_error()));
    }
    let token = OwnedHandle(raw_token);
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token.0, 1, std::ptr::null_mut(), 0, &mut needed);
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(122) || needed == 0 {
        return Err(io("token user length", std::io::Error::last_os_error()));
    }
    let mut user = vec![0u8; needed as usize];
    if unsafe { GetTokenInformation(token.0, 1, user.as_mut_ptr().cast(), needed, &mut needed) }
        == 0
    {
        return Err(io("token user", std::io::Error::last_os_error()));
    }
    if user.len() < std::mem::size_of::<*mut c_void>() {
        return Err("invalid current token user".into());
    }
    let sid = unsafe { std::ptr::read_unaligned(user.as_ptr().cast::<*mut c_void>()) };
    if sid.is_null() || unsafe { EqualSid(owner, sid) } == 0 {
        return Err("installation mutex owner collision".into());
    }
    Ok(())
}

/// Native identity and recovery-relevant metadata; last-access is deliberately
/// omitted because reading a file may update it. Security bytes stay in memory.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileIdentity {
    pub volume: u32,
    pub index: u64,
    pub size: u64,
    pub attributes: u32,
    pub creation: u64,
    pub write: u64,
    pub security_descriptor: Vec<u8>,
}
impl std::fmt::Debug for FileIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileIdentity")
            .field("volume", &self.volume)
            .field("index", &self.index)
            .field("size", &self.size)
            .field("attributes", &self.attributes)
            .field("creation", &self.creation)
            .field("write", &self.write)
            .field("security_descriptor_bytes", &self.security_descriptor.len())
            .finish()
    }
}
#[derive(Debug, Clone)]
pub(crate) struct SourceSnapshot {
    pub(super) target: PathBuf,
    pub(super) bytes: Vec<u8>,
    pub(super) digest: String,
    pub(super) identity: FileIdentity,
}
impl SourceSnapshot {
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }
    pub(crate) fn digest(&self) -> &str { &self.digest }
}
#[derive(Debug, Clone)]
pub(super) struct InstallPaths {
    pub staged: PathBuf,
    pub original_backup: PathBuf,
    pub displaced_backup: PathBuf,
}
pub(super) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn io(context: &str, e: std::io::Error) -> String {
    format!("{context}: {e}")
}
pub(super) fn time(t: FileTime) -> u64 {
    (u64::from(t.high) << 32) | u64::from(t.low)
}
pub(super) fn information(file: &File) -> Result<FileInformation, String> {
    let mut info = FileInformation::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io("file identity", std::io::Error::last_os_error()));
    }
    Ok(info)
}
pub(super) fn identity(file: &File) -> Result<FileIdentity, String> {
    file_identity(file, true)
}
pub(super) fn executable_identity(file: &File) -> Result<FileIdentity, String> {
    file_identity(file, false)
}
fn file_identity(file: &File, single_link: bool) -> Result<FileIdentity, String> {
    let info = information(file)?;
    if info.attributes & (REPARSE | DIRECTORY) != 0
        || info.links == 0
        || (single_link && info.links != 1)
    {
        return Err("nonregular/reparse/hardlink conflict".into());
    }
    let security = security(file.as_raw_handle(), 1 | 2 | 4)?;
    Ok(FileIdentity {
        volume: info.volume,
        index: (u64::from(info.index_high) << 32) | u64::from(info.index_low),
        size: (u64::from(info.size_high) << 32) | u64::from(info.size_low),
        attributes: info.attributes,
        creation: time(info.creation),
        write: time(info.write),
        security_descriptor: security,
    })
}
pub(super) fn security(handle: *mut c_void, flags: u32) -> Result<Vec<u8>, String> {
    let mut needed = 0;
    let first =
        unsafe { GetKernelObjectSecurity(handle, flags, std::ptr::null_mut(), 0, &mut needed) };
    if first != 0 || std::io::Error::last_os_error().raw_os_error() != Some(122) || needed == 0 {
        return Err(io(
            "security descriptor length",
            std::io::Error::last_os_error(),
        ));
    }
    let mut security = vec![0u8; needed as usize];
    if unsafe {
        GetKernelObjectSecurity(
            handle,
            flags,
            security.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io("security descriptor", std::io::Error::last_os_error()));
    }
    security.truncate(needed as usize);
    Ok(security)
}
pub(super) fn validate_path(path: &Path) -> Result<(), String> {
    WindowsLocalPath::parse(path.as_os_str()).map(|_| ())
}
pub(super) fn parents(path: &Path) -> Result<Vec<File>, String> {
    validate_path(path)?;
    let mut handles = Vec::new();
    let mut current = PathBuf::new();
    let parts: Vec<_> = path.components().collect();
    for part in &parts[..parts.len() - 1] {
        current.push(part.as_os_str());
        if matches!(part, Component::Prefix(_)) {
            continue;
        }
        // Deny ancestor deletion, retaining its identity. Native ReplaceFileW
        // needs directory write sharing; this does not permit source writes.
        let handle = OpenOptions::new()
            .read(true)
            .share_mode(READ | WRITE)
            .custom_flags(OPEN_REPARSE | BACKUP_SEMANTICS)
            .open(NativeFsPath::from_path(&current)?.as_path())
            .map_err(|e| io("open ancestor", e))?;
        let info = information(&handle)?;
        if info.attributes & REPARSE != 0 || info.attributes & DIRECTORY == 0 {
            return Err("ancestor reparse/type conflict".into());
        }
        case_insensitive(&handle)?;
        handles.push(handle);
    }
    Ok(handles)
}
pub(super) fn open_regular(path: &Path, share: u32) -> Result<File, String> {
    let native_path = NativeFsPath::from_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(share)
        .custom_flags(OPEN_REPARSE)
        .open(native_path.as_path())
        .map_err(|e| io("open archive file", e))?;
    identity(&file)?;
    Ok(file)
}
pub(super) fn read_checked(file: &mut File, target: &Path) -> Result<SourceSnapshot, String> {
    read_checked_purpose(file, target, PathPurpose::Source)
}
pub(super) fn read_checked_purpose(
    file: &mut File,
    target: &Path,
    purpose: PathPurpose,
) -> Result<SourceSnapshot, String> {
    let identify = if matches!(purpose, PathPurpose::Executable) {
        executable_identity
    } else {
        identity
    };
    let before = identify(file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| io("seek archive", e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| io("read archive", e))?;
    if before != identify(file)? || u64::try_from(bytes.len()).ok() != Some(before.size) {
        return Err("source changed while reading".into());
    }
    Ok(SourceSnapshot {
        target: target.into(),
        digest: hash(&bytes),
        bytes,
        identity: before,
    })
}
pub(super) fn read_path(path: &Path, share: u32) -> Result<SourceSnapshot, String> {
    let _parents = parents(path)?;
    read_checked(&mut open_regular(path, share)?, path)
}

#[cfg(test)]
mod filesystem_path_tests {
    use super::*;

    #[test]
    #[ignore = "new qualified owned fixture; actual common inherited FILE-dispatch primitive, no product effects"]
    fn inherited_metadata_restore_preserves_raw_sd_after_replace() -> Result<()> {
        let parent_path = PathBuf::from(std::env::var_os("AG_NATIVE_METADATA_IDENTITY_FIXTURE_PARENT")
            .ok_or("explicit owned metadata fixture parent required")?);
        let inputs = diagnostic_inputs(&parent_path)?;
        let context = crate::windows_coordinator::windows_deployment::receive_for_diagnostic(&inputs, None)?
            .ok_or("genuine fixture context required")?;
        inputs.receive_context(Some(&context))?;
        let root = parent_path.join(format!("metadata-inherited-{}", unique_id()?));
        eprintln!("SELECTED_METADATA_INHERITED_FIXTURE {}", root.display());
        absent(&root)?;
        create_private_dir(&root)?;
        eprintln!("OWN_METADATA_INHERITED_FIXTURE {}", root.display());
        let original = root.join("replacement44");
        write_private(&original, b"44")?;
        initialize_inherited_fixture(&original)?;
        let desired = read_path(&original, READ | DELETE)?;
        let mut control = 0;
        let mut revision = 0;
        let mut desired_sd = desired.identity.security_descriptor.clone();
        assert_ne!(unsafe { GetSecurityDescriptorControl(desired_sd.as_mut_ptr().cast(), &mut control, &mut revision) }, 0);
        assert_eq!(control, 0x8404);
        let target = root.join("current45");
        let mut current = create_owned_file(&target)?;
        current.write_all(b"45").and_then(|_| current.sync_all()).map_err(|error|io("fixture45 persist",error))?;
        let basic = BasicInformation { creation:i64::try_from(desired.identity.creation).map_err(|_|"fixture creation overflow")?, access:0, write:0, change:0, attributes:desired.identity.attributes };
        assert_ne!(unsafe { SetFileInformationByHandle(current.as_raw_handle(), 0, (&basic as *const BasicInformation).cast(), std::mem::size_of::<BasicInformation>() as u32) }, 0);
        drop(current);
        let mut token = token_user()?;
        let user = sid_text(user_sid(&mut token)?)?;
        let text: Vec<_> = format!("D:P(A;;RC;;;{user})(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").encode_utf16().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) }, 0);
        let descriptor = LocalMemory(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = std::ptr::null_mut();
        assert_ne!(unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }, 0);
        let access = |path: &Path| OpenOptions::new().access_mode(0x0006_0000).share_mode(READ | DELETE).custom_flags(OPEN_REPARSE).open(NativeFsPath::from_path(path)?.as_path()).map_err(|error|io("fixture DACL handle",error));
        let current = access(&target)?;
        assert_eq!(unsafe { SetSecurityInfo(current.as_raw_handle(), 1, 4 | 0x2000_0000, std::ptr::null_mut(), std::ptr::null_mut(), acl, std::ptr::null_mut()) }, 0);
        drop(current);
        let backup = root.join("retained45");
        absent(&backup)?;
        let mut called = None;
        replace_native_file(&target, &original, &backup, &mut called)?;
        assert_eq!(called, Some(true));
        assert_ne!(read_path(&target, READ | DELETE)?.identity.security_descriptor, desired.identity.security_descriptor);
        let current = access(&target)?;
        let result = restore_received_dacl(&current, &desired.identity.security_descriptor);
        write_private(&root.join("actual-restore-result.json"), &json(&result)?)?;
        result?;
        drop(current);
        let after = read_path(&target, READ | DELETE)?;
        assert_eq!(after.bytes, b"44");
        assert_eq!(after.identity, desired.identity);
        write_private(&root.join("inherited-result.json"), &json(&serde_json::json!({
            "replaceResult":called,"capturedControl":control,"fullRawSdPreserved":true,
            "beforeSdSha256":hash(&desired.identity.security_descriptor),"afterSdSha256":hash(&after.identity.security_descriptor),
            "scope":"actual common FILE dispatch inherited8404; owned fixture, not actual BA permissions"
        }))?)?;
        Ok(())
    }

    #[test]
    fn authored_stage_descriptor_accepts_layout_and_rejects_field_changes() {
        fn convert(text: &str) -> Vec<u8> {
            let text: Vec<_> = text.encode_utf16().chain(Some(0)).collect();
            let mut pointer = std::ptr::null_mut();
            let mut length = 0;
            assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut pointer, &mut length) }, 0);
            let owned = LocalMemory(pointer);
            unsafe { std::slice::from_raw_parts(owned.0.cast::<u8>(), length as usize) }.to_vec()
        }
        let mut token = token_user().unwrap();
        let user = sid_text(user_sid(&mut token).unwrap()).unwrap();
        let authored_text = format!("O:{user}G:BUD:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        let authored = convert(&authored_text);
        let offset = |field| u32::from_le_bytes(authored[field..field+4].try_into().unwrap()) as usize;
        assert_eq!(offset(12), 0); // No authored SACL in this private-stage profile.
        let mut repacked = authored[..20].to_vec(); // SECURITY_DESCRIPTOR_RELATIVE header.
        for field in [4, 8, 16] {
            let start = offset(field);
            let length = if field == 16 {
                u16::from_le_bytes(authored[start+2..start+4].try_into().unwrap()) as usize
            } else {
                8 + 4 * usize::from(authored[start+1]) // Native SID header/subauthorities.
            };
            let relocated = u32::try_from(repacked.len()).unwrap();
            repacked[field..field+4].copy_from_slice(&relocated.to_le_bytes());
            repacked.extend_from_slice(&authored[start..start+length]);
        }
        assert_ne!(repacked, authored);
        assert!(authored_stage_descriptor_matches(&repacked, &authored).unwrap());
        for changed in [
            authored_text.replacen(&format!("O:{user}"), "O:BA", 1),
            authored_text.replacen("G:BU", &format!("G:{user}"), 1),
            authored_text.replacen(";FA;", ";FR;", 1),
            authored_text.replacen("D:P", "D:", 1),
        ] {
            assert!(!authored_stage_descriptor_matches(&convert(&changed), &authored).unwrap());
        }
    }

    #[test]
    #[ignore = "explicit owned fixture parent; enabled-group identity variation, not an elevated BA-owner claim"]
    fn metadata_stage_preserves_captured_group_before_replace() -> Result<()> {
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn CheckTokenMembership(token: *mut c_void, sid: *mut c_void, member: *mut i32) -> i32;
        }
        let mut token = token_user()?;
        let user = sid_text(user_sid(&mut token)?)?;
        let text: Vec<_> = format!("O:{user}G:BU").encode_utf16().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        let mut length = 0;
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, &mut length) } == 0 {
            return Err(io("fixture identity descriptor", std::io::Error::last_os_error()));
        }
        let descriptor = LocalMemory(descriptor);
        let mut group = std::ptr::null_mut();
        let mut defaulted = 0;
        assert_ne!(unsafe { GetSecurityDescriptorGroup(descriptor.0, &mut group, &mut defaulted) }, 0);
        let mut enabled = 0;
        assert_ne!(unsafe { CheckTokenMembership(std::ptr::null_mut(), group, &mut enabled) }, 0);
        assert_ne!(enabled, 0, "fixture requires an actual enabled Builtin Users group; no skipped PASS");
        let parent_path = PathBuf::from(std::env::var_os("AG_NATIVE_METADATA_IDENTITY_FIXTURE_PARENT")
            .ok_or("explicit owned metadata fixture parent required")?);
        let inputs = diagnostic_inputs(&parent_path)?;
        let context = crate::windows_coordinator::windows_deployment::receive_for_diagnostic(&inputs, None)?
            .ok_or("genuine saved context required for metadata fixture parent")?;
        inputs.receive_context(Some(&context))?;
        let parent = CheckedPath::open(&parent_path, PathKind::Directory, PathPurpose::Review)?;
        if parent.object != inputs.directory.anchor.object {
            return Err("metadata fixture parent native identity changed".into());
        }
        check_private_namespace(&parent, Some(&context))?;
        let root = parent.path.join(format!("metadata-identity-{}", unique_id()?));
        eprintln!("SELECTED_METADATA_IDENTITY_FIXTURE {}", root.display());
        absent(&root)?;
        create_private_dir(&root)?;
        eprintln!("OWN_METADATA_IDENTITY_FIXTURE {}", root.display());
        let target = root.join("version");
        let captured = unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length as usize) };
        let mut file = create_owned_file_with_identity(&target, Some(captured))?;
        file.write_all(b"44").and_then(|_| file.sync_all()).map_err(|error|io("fixture old metadata persist",error))?;
        drop(file);
        let before = read_path(&target, READ | DELETE)?;
        let normal = create_owned_file(&root.join("normal-private"))?;
        let mut normal_sd = security(normal.as_raw_handle(), 1 | 2 | 4)?;
        let mut normal_group = std::ptr::null_mut();
        assert_ne!(unsafe { GetSecurityDescriptorGroup(normal_sd.as_mut_ptr().cast(), &mut normal_group, &mut defaulted) }, 0);
        assert_eq!(unsafe { EqualSid(group, normal_group) }, 0, "fixture group must differ from normal private creation");
        drop(normal);
        // Exercise the actual shared replacement-file constructor with the
        // received non-default group, including both backup and stage callers.
        let backup_path = root.join("replacement-backup");
        let stage_path = root.join("replacement-stage");
        let target_path = root.join("replacement-target");
        let displaced_path = root.join("replacement-displaced");
        let backup = create_replacement_file(&backup_path, &before.bytes, &before.identity)?;
        let stage = create_replacement_file(&stage_path, b"candidate", &before.identity)?;
        create_replacement_file(&target_path, &before.bytes, &before.identity)?;
        let identity_matches = |left: &[u8], right: &[u8]| -> Result<bool> {
            let mut left = left.to_vec();
            let mut right = right.to_vec();
            for get in [GetSecurityDescriptorOwner, GetSecurityDescriptorGroup] {
                let mut l = std::ptr::null_mut();
                let mut r = std::ptr::null_mut();
                let mut defaulted = 0;
                if unsafe { get(left.as_mut_ptr().cast(), &mut l, &mut defaulted) } == 0 ||
                    unsafe { get(right.as_mut_ptr().cast(), &mut r, &mut defaulted) } == 0 ||
                    l.is_null() || r.is_null() || unsafe { EqualSid(l, r) } == 0 { return Ok(false); }
            }
            Ok(true)
        };
        assert!(identity_matches(&backup.identity.security_descriptor, &before.identity.security_descriptor)?);
        assert!(identity_matches(&stage.identity.security_descriptor, &before.identity.security_descriptor)?);
        let mut missing = before.identity.clone();
        missing.security_descriptor.clear();
        let missing_path = root.join("replacement-missing-identity");
        assert!(create_replacement_file(&missing_path, b"no write", &missing).is_err());
        assert!(matches!(fs::symlink_metadata(&missing_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound));
        let mut malformed = before.identity.clone();
        malformed.security_descriptor[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let malformed_path = root.join("replacement-malformed-identity");
        assert!(create_replacement_file(&malformed_path, b"no write", &malformed).is_err());
        assert!(matches!(fs::symlink_metadata(&malformed_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound));
        let mut called = None;
        replace_native_file(&target_path, &stage_path, &displaced_path, &mut called)?;
        assert_eq!(called, Some(true));
        let replaced = read_path(&target_path, READ | DELETE)?;
        assert!(identity_matches(&replaced.identity.security_descriptor, &before.identity.security_descriptor)?);
        let access = OpenOptions::new().access_mode(0x0006_0000).share_mode(READ | DELETE)
            .custom_flags(OPEN_REPARSE).open(NativeFsPath::from_path(&target_path)?.as_path())
            .map_err(|error| io("replacement fixture DACL handle", error))?;
        restore_received_dacl(&access, &before.identity.security_descriptor)?;
        drop(access);
        let replaced = read_path(&target_path, READ | DELETE)?;
        assert_eq!(replaced.bytes, b"candidate");
        assert_eq!(replaced.identity.security_descriptor, before.identity.security_descriptor);
        let result = write_nonsecret_metadata_checked(&target, b"45", Some(&context));
        write_private(&root.join("actual-write-result.json"), &json(&result)?)?;
        let evidence = result.map_err(|error|error.to_string())?;
        assert_eq!(evidence["replaceResult"], true);
        let after = read_path(&target, READ | DELETE)?;
        assert_eq!(after.bytes, b"45");
        assert_eq!(after.identity.security_descriptor, before.identity.security_descriptor);
        assert_eq!(after.identity.creation, before.identity.creation);
        assert_eq!(after.identity.attributes, before.identity.attributes);
        write_private(&root.join("identity-result.json"), &json(&serde_json::json!({
            "enabledGroupVariation":true,"fullSecurityDescriptorPreserved":true,
            "replaceResult":true,"beforeDigest":before.digest,"afterDigest":after.digest,
            "beforeSdSha256":hash(&before.identity.security_descriptor),
            "afterSdSha256":hash(&after.identity.security_descriptor),
            "actualElevatedBAOwnerCase":"not executed; separate Root oracle required"
        }))?)?;
        Ok(())
    }

    #[test]
    fn native_mutex_explicit_owner_excludes_other_thread_until_release() {
        let name = format!("Global\\AGUnlocker_mutex_test_{}", unique_id().unwrap());
        let lease = Lease::acquire_name(&name).unwrap();
        mutex_current_owner(lease.mutex.0).unwrap();
        let mut sd = security(lease.mutex.0, 1 | 4).unwrap();
        let aces = super::super::context_native::entries(&mut sd).unwrap();
        let user = super::super::context_native::current_user().unwrap();
        assert_eq!(aces.len(), 3);
        assert!(aces.iter().all(|ace| !ace.deny && ace.mask & 0x001f_0001 == 0x001f_0001));
        assert!(aces.iter().any(|ace| ace.sid == user));
        assert!(aces.iter().any(|ace| ace.sid.well_known(22)));
        assert!(aces.iter().any(|ace| ace.sid.well_known(26)));
        let busy_name = name.clone();
        let busy = std::thread::spawn(move || Lease::acquire_name(&busy_name).map(drop))
            .join().unwrap().unwrap_err();
        assert!(busy.contains("maintenance-pending"), "{busy}");
        drop(lease);
        std::thread::spawn(move || {
            let lease = Lease::acquire_name(&name).unwrap();
            mutex_current_owner(lease.mutex.0).unwrap();
            drop(lease);
        }).join().unwrap();
    }

    #[test]
    fn native_filesystem_encoder_preserves_ordinary_disk_policy_and_utf16() {
        for path in [r"C:\", "c:/native/Ж-λ-🚀.bin", r"D:\ordinary\file"] {
            let ordinary = WindowsLocalPath::parse(OsStr::new(path)).unwrap();
            let encoded = NativeFsPath::encode(&ordinary).unwrap();
            let expected: Vec<_> = NativeFsPath::DOS_PREFIX
                .into_iter()
                .chain(path.encode_utf16().map(|unit| if unit == 47 { 92 } else { unit }))
                .chain(Some(0))
                .collect();
            assert_eq!(encoded.units, expected);
            let received = encoded.receive_name(&encoded.units[..encoded.units.len() - 1]).unwrap();
            assert_eq!(
                received.as_os_str().encode_wide().collect::<Vec<_>>(),
                expected[4..expected.len() - 1]
            );
            assert!(WindowsLocalPath::parse(encoded.as_path().as_os_str()).is_err());
        }
        let unpaired = OsString::from_wide(&[67, 58, 92, 0xd800, 46, 98, 105, 110]);
        let encoded = NativeFsPath::from_path(Path::new(&unpaired)).unwrap();
        assert_eq!(&encoded.units[4..encoded.units.len() - 1], &[67, 58, 92, 0xd800, 46, 98, 105, 110]);
        for rejected in [
            r"relative\file", r"C:file", r"C:\a\.\file", r"C:\a\..\file",
            r"C:\file:stream", r"C:\trailing.", r"C:\trailing ", r"C:\NUL.txt",
            r"\\server\share\file", r"\\?\C:\file", r"\\.\C:\file",
        ] {
            assert!(NativeFsPath::from_path(Path::new(rejected)).is_err(), "{rejected}");
        }
        let encoded = NativeFsPath::from_path(Path::new(r"C:\ordinary")).unwrap();
        for rejected in [r"\\?\UNC\server\share\file", r"\\?\Volume{invalid}\file", r"\\.\C:\file"] {
            assert!(encoded.receive_name(&rejected.encode_utf16().collect::<Vec<_>>()).is_err());
        }
    }

    #[test]
    #[ignore = "requires an explicit vacant owned Windows fixture root"]
    fn native_long_private_create_open_and_name_receivers_preserve_identity() {
        let root = PathBuf::from(std::env::var_os("AG_NATIVE_PATH_TEST_ROOT").expect("explicit owned fixture root"));
        create_private_dir(&root).expect("vacant exact fixture root");
        let directory = root.join("native-private-long-component-".repeat(5));
        assert!(directory.as_os_str().encode_wide().count() > 248);
        create_private_dir(&directory).unwrap();
        let checked = CheckedPath::open(&directory, PathKind::Directory, PathPurpose::Review).unwrap();
        private(&checked.file).unwrap();
        let expanded = long_path(&directory).unwrap();
        let short = short_fixture_path(&directory).unwrap();
        for path in [&expanded, &short] {
            WindowsLocalPath::parse(path.as_os_str()).unwrap();
            assert_eq!(CheckedPath::open(path, PathKind::Directory, PathPurpose::Review).unwrap().native_id(), checked.native_id());
        }
        let file = directory.join("unicode-Ж-λ-🚀.bin");
        write_private(&file, b"owned long native path readback").unwrap();
        let checked = CheckedPath::open(&file, PathKind::File, PathPurpose::Review).unwrap();
        private(&checked.file).unwrap();
        assert_eq!(checked.read_snapshot().unwrap(), b"owned long native path readback");
        let snapshot = checked.read_checked_snapshot().unwrap();
        assert_eq!(snapshot.bytes(), b"owned long native path readback");
        assert_eq!(snapshot.digest(), format!("{:x}", Sha256::digest(snapshot.bytes())));
        assert_ne!(snapshot.digest(), "");
        let empty = directory.join("empty.bin");
        write_private(&empty, b"").unwrap();
        let empty_pin = CheckedPath::open(&empty, PathKind::File, PathPurpose::Review).unwrap();
        let empty_snapshot = empty_pin.read_checked_snapshot().unwrap();
        assert!(empty_snapshot.bytes().is_empty());
        assert_eq!(empty_snapshot.digest(), format!("{:x}", Sha256::digest(b"")));
        assert_ne!(empty_snapshot.digest(), "");
        assert!(CheckedPath::open(&directory.join("missing.bin"), PathKind::File, PathPurpose::Review).is_err());
        assert!(create_private_dir(&directory).is_err());
        assert!(create_owned_file(&file).is_err());
    }
}

/// Read-only namespace input. An absent future directory is bound to its real
/// nearest existing ancestor; IO/type/reparse errors never become absence.
pub(super) struct NativeDirectoryInput {
    requested: PathBuf,
    pub(super) anchor: CheckedPath,
    existed: bool,
    descriptors: Vec<(ObjectId, String)>,
}
impl NativeDirectoryInput {
    pub(super) fn capture(path: &Path) -> Result<Self> {
        validate_path(path)?;
        let mut cursor = path.to_owned();
        let mut existed = true;
        let anchor = loop {
            match fs::symlink_metadata(NativeFsPath::from_path(&cursor)?.as_path()) {
                Ok(_) => {
                    break CheckedPath::open(&cursor, PathKind::Directory, PathPurpose::Review)?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    existed = false;
                    cursor = cursor
                        .parent()
                        .ok_or("namespace has no existing ancestor")?
                        .to_owned();
                }
                Err(error) => return Err(io("namespace observation", error)),
            }
        };
        let descriptors = anchor
            ._ancestors
            .iter()
            .chain(std::iter::once(&anchor.file))
            .map(|file| {
                Ok((
                    object_id(file)?,
                    hash(&security(file.as_raw_handle(), 1 | 4)?),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            requested: path.to_owned(),
            anchor,
            existed,
            descriptors,
        })
    }
    pub(super) fn is_existing(&self) -> bool {
        self.existed
    }
    pub(super) fn files(&self) -> impl Iterator<Item = &File> {
        self.anchor
            ._ancestors
            .iter()
            .chain(std::iter::once(&self.anchor.file))
    }
    pub(super) fn recheck(&self, before_effects: bool) -> Result<()> {
        self.anchor.recheck()?;
        for (file, (id, sd)) in self.files().zip(&self.descriptors) {
            if object_id(file)? != *id || hash(&security(file.as_raw_handle(), 1 | 4)?) != *sd {
                return Err("namespace input identity/security descriptor changed".into());
            }
        }
        if before_effects {
            if self.existed {
                let current =
                    CheckedPath::open(&self.requested, PathKind::Directory, PathPurpose::Review)?;
                if current.object != self.anchor.object {
                    return Err("namespace input locator changed".into());
                }
            } else {
                absent(&self.requested)
                    .map_err(|error| format!("future namespace input became occupied: {error}"))?;
            }
        }
        Ok(())
    }
}

/// Opaque actual user-metadata namespace, projected only by the native owner.
pub(crate) struct DiagnosticInputs {
    directory: NativeDirectoryInput,
}
pub(crate) fn diagnostic_inputs(parent: &Path) -> Result<DiagnosticInputs> {
    Ok(DiagnosticInputs {
        directory: NativeDirectoryInput::capture(parent)?,
    })
}
impl DiagnosticInputs {
    pub(crate) fn ancestor_inputs(&self) -> Result<AncestorInputs> {
        Ok(AncestorInputs::new(
            self.directory
                .files()
                .map(|file| {
                    file.try_clone()
                        .map_err(|error| io("retain diagnostic namespace input", error))
                })
                .collect::<Result<Vec<_>>>()?,
        ))
    }
    pub(super) fn recheck(&self, before_effects: bool) -> Result<()> {
        self.directory.recheck(before_effects)
    }
    pub(super) fn files(&self) -> impl Iterator<Item = &File> {
        self.directory.files()
    }
    pub(super) fn receive_context(&self, context: Option<&AncestorAccessContext>) -> Result<()> {
        self.recheck(true)?;
        if let Some(context) = context {
            context.revalidate()?;
        }
        for file in self.files() {
            if let Some(context) = context {
                if !context.applies(file)? {
                    return Err("diagnostic context does not cover actual namespace".into());
                }
            }
            check_context_ancestor(file, context)?;
        }
        check_private_namespace(&self.directory.anchor, context)
    }
}

pub(super) fn check_context_ancestor(
    file: &File,
    context: Option<&AncestorAccessContext>,
) -> Result<()> {
    if let Some(context) = context {
        if context.applies(file)? {
            return context.check(file, true);
        }
    }
    ancestor_integrity(file)
}
fn check_private_namespace(
    parent: &CheckedPath,
    context: Option<&AncestorAccessContext>,
) -> Result<()> {
    if let Some(context) = context {
        context.revalidate()?;
    }
    for file in &parent._ancestors {
        check_context_ancestor(file, context)?;
    }
    if let Some(context) = context {
        if context.applies(&parent.file)? {
            return state_parent_context(&parent.file, context);
        }
    }
    // Existing user state is current-owner/integrity checked, not rewritten into
    // a managed DACL. Newly created private leaves retain the stricter rule.
    state_parent(&parent.file)
}

/// Neutral private capture stream. The caller owns writer/child retirement,
/// sync and closing `file` before independent receiving; remaining parent pins
/// stay in scope across an owned partial move. No Drop impl prevents that move.
pub(crate) struct PrivateCapturedFile {
    pub(crate) path: PathBuf,
    pub(crate) file: File,
    pub(crate) native_id: ObjectId,
    _parent: CheckedPath,
}

pub(crate) fn create_private_captured_file(
    path: &Path,
    context: Option<&AncestorAccessContext>,
) -> Result<PrivateCapturedFile> {
    let parent = CheckedPath::open(
        path.parent().ok_or("capture parent absent")?,
        PathKind::Directory,
        PathPurpose::Review,
    )?;
    check_private_namespace(&parent, context)?;
    let file = create_owned_file(path)?;
    let native_id = object_id(&file).map_err(|error| {
        format!(
            "private capture file created at {}; identity receiving failed: {error}; preserve it",
            path.display()
        )
    })?;
    parent.recheck().map_err(|error| {
        format!(
            "private capture file created at {}; parent receiving failed: {error}; preserve it",
            path.display()
        )
    })?;
    Ok(PrivateCapturedFile {
        path: path.to_owned(),
        file,
        native_id,
        _parent: parent,
    })
}

pub(crate) fn read_private_captured_file(
    path: &Path,
    expected: &ObjectId,
    context: Option<&AncestorAccessContext>,
) -> Result<Vec<u8>> {
    let parent = CheckedPath::open(
        path.parent().ok_or("capture parent absent")?,
        PathKind::Directory,
        PathPurpose::Review,
    )?;
    check_private_namespace(&parent, context)?;
    let pin = CheckedPath::open(path, PathKind::File, PathPurpose::Review)?;
    private(&pin.file)?;
    if &pin.object != expected {
        return Err("private capture native identity changed".into());
    }
    pin.read_snapshot()
}

#[derive(Debug, Serialize)]
pub(crate) struct MetadataFailure {
    pub(crate) phase: &'static str,
    pub(crate) cause: String,
    /// This describes REPLACE only. CREATE_NEW/write/flush effects are retained
    /// separately in evidence even when replacement was not called.
    pub(crate) replace_result: Option<bool>,
    pub(crate) evidence: serde_json::Value,
}
impl std::fmt::Display for MetadataFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "private metadata {}: {} (replacement {:?}; retained evidence)",
            self.phase, self.cause, self.replace_result
        )
    }
}
impl std::error::Error for MetadataFailure {}

pub(super) fn check_nonsecret_file(
    file: &File,
    context: Option<&AncestorAccessContext>,
) -> Result<()> {
    identity(file)?;
    match context {
        Some(context) => context.check_nonsecret_metadata_file(file),
        None => super::ancestor_context::check_empty_nonsecret_metadata_file(file),
    }
}

/// A real, separately pinned legacy NONSECRET field, not an ancestor/context.
/// Context is borrowed; path and file/preimage/SD/serialization are owned.
pub(crate) struct NonsecretMetadataPlan<'ctx> {
    path: PathBuf,
    parent: CheckedPath,
    parent_descriptor: String,
    pin: Option<CheckedPath>,
    preimage: Option<SourceSnapshot>,
    context: Option<&'ctx AncestorAccessContext>,
    _lease: Lease,
}
impl NonsecretMetadataPlan<'_> {
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        self.preimage.as_ref().map(|value| value.bytes.as_slice())
    }
    pub(crate) fn evidence(&self) -> serde_json::Value {
        serde_json::json!({"schema":1,"kind":"nonsecret-metadata-read-plan","path":path_evidence(&self.path),
            "present":self.pin.is_some(),"preimage":self.preimage.as_ref().map(snapshot_evidence),
            "nativeId":self.pin.as_ref().map(|pin|&pin.object),"parentNativeId":self.parent.object,
            "note":"actual admitted data; numeric/missing/malformed policy belongs to existing field owner"})
    }
    fn recheck(&self) -> Result<()> {
        self.parent.recheck()?;
        if hash(&security(self.parent.file.as_raw_handle(), 1 | 4)?) != self.parent_descriptor {
            return Err("metadata plan parent descriptor changed".into());
        }
        check_private_namespace(&self.parent, self.context)?;
        match (&self.pin, &self.preimage) {
            (Some(pin), Some(expected)) => {
                pin.recheck()?;
                check_nonsecret_file(&pin.file, self.context)?;
                let mut file = pin
                    .file
                    .try_clone()
                    .map_err(|error| io("metadata plan read", error))?;
                if !same_snapshot(&read_checked(&mut file, &self.path)?, expected) {
                    return Err("metadata plan preimage or full descriptor changed".into());
                }
            }
            (None, None) => absent(&self.path)?,
            _ => return Err("metadata plan presence contradiction".into()),
        }
        Ok(())
    }
    pub(crate) fn revalidate(&self) -> std::result::Result<(), MetadataFailure> {
        self.recheck().map_err(|cause| MetadataFailure {
            phase: "read-plan-revalidation",
            cause,
            replace_result: None,
            evidence: self.evidence(),
        })
    }
    pub(crate) fn write_checked(
        self,
        bytes: &[u8],
    ) -> std::result::Result<serde_json::Value, MetadataFailure> {
        write_nonsecret_metadata_plan(self, bytes)
    }
}
pub(crate) fn read_nonsecret_metadata_checked<'ctx>(
    path: &Path,
    context: Option<&'ctx AncestorAccessContext>,
) -> std::result::Result<NonsecretMetadataPlan<'ctx>, MetadataFailure> {
    let result = (|| -> Result<NonsecretMetadataPlan<'ctx>> {
        let parent = CheckedPath::open(
            path.parent().ok_or("metadata parent absent")?,
            PathKind::Directory,
            PathPurpose::Review,
        )?;
        check_private_namespace(&parent, context)?;
        let lease = Lease::acquire(&parent, "private_metadata_writer")?;
        let parent_descriptor = hash(&security(parent.file.as_raw_handle(), 1 | 4)?);
        let present = match fs::symlink_metadata(NativeFsPath::from_path(path)?.as_path()) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(io("metadata plan observation", error)),
        };
        let (pin, preimage) = if present {
            let pin = CheckedPath::open(path, PathKind::File, PathPurpose::ReplaceSource)?;
            check_nonsecret_file(&pin.file, context)?;
            let mut file = pin
                .file
                .try_clone()
                .map_err(|error| io("metadata plan clone", error))?;
            let snapshot = read_checked(&mut file, path)?;
            (Some(pin), Some(snapshot))
        } else {
            (None, None)
        };
        let plan = NonsecretMetadataPlan {
            path: path.to_owned(),
            parent,
            parent_descriptor,
            pin,
            preimage,
            context,
            _lease: lease,
        };
        plan.recheck()?;
        Ok(plan)
    })();
    result.map_err(|cause|MetadataFailure{phase:"read-admission",cause,replace_result:None,
        evidence:serde_json::json!({"schema":1,"kind":"nonsecret-metadata-read-rejection","path":path_evidence(path),
            "replaceResult":serde_json::Value::Null,"note":"no mutation; no file/ancestor authority fabricated"})})
}

/// One existing user-state owner. No path resolver, generation policy or
/// ProgramData authority is introduced here. Missing leaves use CREATE_NEW;
/// existing nonsecret content is replaced conditionally with retained preimage.
pub(crate) fn write_nonsecret_metadata_checked<'ctx>(
    path: &Path,
    bytes: &[u8],
    context: Option<&'ctx AncestorAccessContext>,
) -> std::result::Result<serde_json::Value, MetadataFailure> {
    read_nonsecret_metadata_checked(path, context)?.write_checked(bytes)
}

fn write_nonsecret_metadata_plan(
    plan: NonsecretMetadataPlan<'_>,
    bytes: &[u8],
) -> std::result::Result<serde_json::Value, MetadataFailure> {
    let path = &plan.path;
    let context = plan.context;
    let mut phase = "preflight";
    let mut called = None;
    let mut creation_attempted = false;
    let mut creation_received = false;
    let before = plan.preimage.clone();
    let before_id = plan.pin.as_ref().map(|pin| pin.object.clone());
    let mut paths: Option<InstallPaths> = None;
    let result = (|| -> Result<()> {
        plan.revalidate().map_err(|error| error.to_string())?;
        let parent = &plan.parent;
        let exists = plan.pin.is_some();
        if !exists {
            phase = "create";
            creation_attempted = true;
            let mut file = create_owned_file(path)?;
            creation_received = true;
            let id = object_id(&file)?;
            phase = "persist";
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| io("metadata persist", error))?;
            drop(file);
            phase = "receiving";
            let created = CheckedPath::open(path, PathKind::File, PathPurpose::ReplaceSource)?;
            private(&created.file)?;
            if created.object != id || created.read_snapshot()? != bytes {
                return Err("created metadata full receiving differs".into());
            }
            parent.recheck()?;
            check_private_namespace(parent, context)?;
            return Ok(());
        }
        let pin = plan.pin.as_ref().ok_or("metadata plan leaf absent")?;
        check_nonsecret_file(&pin.file, context)?;
        let old = before.as_ref().ok_or("metadata preimage absent")?;
        if old.bytes == bytes {
            phase = "unchanged-received";
            return Ok(());
        }
        let id = unique_id()?;
        let prefix = format!("private-metadata-{id}");
        paths = Some(InstallPaths {
            staged: parent.path.join(format!("{prefix}.staged")),
            original_backup: parent.path.join(format!("{prefix}.original")),
            displaced_backup: parent.path.join(format!("{prefix}.displaced")),
        });
        let work = paths.as_ref().ok_or("metadata work absent")?;
        for target in [&work.staged, &work.original_backup, &work.displaced_backup] {
            absent(target)?;
        }
        phase = "original-retention";
        let original = create_replacement_file(&work.original_backup, &old.bytes, &old.identity)?;
        phase = "stage";
        let mut staged_file = create_owned_file_with_identity(&work.staged, Some(&old.identity.security_descriptor))?;
        staged_file
            .write_all(bytes)
            .and_then(|_| staged_file.sync_all())
            .map_err(|error| io("metadata stage persist", error))?;
        // Like an ordinary metadata update, retain existing creation/attributes
        // and security while using the actual new write time, not a fake clock.
        let basic = BasicInformation {
            creation: i64::try_from(old.identity.creation)
                .map_err(|_| "metadata creation overflow")?,
            access: 0,
            write: 0,
            change: 0,
            attributes: old.identity.attributes,
        };
        if unsafe {
            SetFileInformationByHandle(
                staged_file.as_raw_handle(),
                0,
                (&basic as *const BasicInformation).cast(),
                std::mem::size_of::<BasicInformation>() as u32,
            )
        } == 0
        {
            return Err(io(
                "metadata stage attributes",
                std::io::Error::last_os_error(),
            ));
        }
        staged_file
            .sync_all()
            .map_err(|error| io("metadata stage flush", error))?;
        let staged_id = object_id(&staged_file)?;
        drop(staged_file);
        let staged = read_path(&work.staged, READ | DELETE)?;
        if staged.bytes != bytes {
            return Err("metadata staged bytes differ".into());
        }
        phase = "publish-precheck";
        check_private_namespace(&parent, context)?;
        pin.recheck()?;
        check_nonsecret_file(&pin.file, context)?;
        if !same_snapshot(&read_path(path, READ | DELETE)?, old)
            || object_id(&open_regular(path, READ | DELETE)?)? != pin.object
            || !same_snapshot(&read_path(&work.staged, READ | DELETE)?, &staged)
        {
            return Err("metadata target/stage changed before replacement".into());
        }
        absent(&work.displaced_backup)?;
        phase = "replace";
        replace_native_file(path, &work.staged, &work.displaced_backup, &mut called)?;
        phase = "metadata-preservation";
        restore_replacement_security(
            path,
            &staged,
            &staged_id,
            &pin.object,
            old,
            &work.displaced_backup,
            &old.identity.security_descriptor,
            &mut || {
                parent.recheck()?;
                check_private_namespace(&parent, context)
            },
        )?;
        phase = "receiving";
        let post = CheckedPath::open(path, PathKind::File, PathPurpose::ReplaceSource)?;
        check_nonsecret_file(&post.file, context)?;
        let target = read_path(path, READ | DELETE)?;
        if post.object != staged_id
            || target.bytes != bytes
            || target.identity.creation != old.identity.creation
            || target.identity.write != staged.identity.write
            || target.identity.attributes != old.identity.attributes
            || target.identity.security_descriptor != old.identity.security_descriptor
            || !same_snapshot(&read_path(&work.displaced_backup, READ | DELETE)?, old)
            || object_id(&open_regular(&work.displaced_backup, READ | DELETE)?)? != pin.object
            || !same_snapshot(&read_path(&work.original_backup, READ)?, &original)
        {
            return Err("metadata full target/backup receiving differs".into());
        }
        absent(&work.staged)?;
        check_private_namespace(&parent, context)?;
        #[cfg(test)]
        if TEST_METADATA_RECEIVING_FAILURE.with(|value| value.replace(false)) {
            return Err("injected failure after actual metadata replacement and receiving".into());
        }
        Ok(())
    })();
    let evidence = serde_json::json!({"schema":1,"kind":"nonsecret-metadata-write","phase":phase,
        "replaceResult":called,"creationAttempted":creation_attempted,"creationReceived":creation_received,
        "target":path_evidence(path),"targetObservation":observe(path),"desiredDigest":hash(bytes),
        "preimage":before.as_ref().map(snapshot_evidence),"preimageNativeId":before_id,
        "work":paths.as_ref().map(|work|serde_json::json!({
            "staged":path_evidence(&work.staged),"stagedObservation":observe(&work.staged),
            "original":path_evidence(&work.original_backup),"originalObservation":observe(&work.original_backup),
            "displaced":path_evidence(&work.displaced_backup),"displacedObservation":observe(&work.displaced_backup)}))});
    match result {
        Ok(()) => Ok(evidence),
        Err(cause) => Err(MetadataFailure {
            phase,
            cause,
            replace_result: called,
            evidence,
        }),
    }
}

#[cfg(test)]
thread_local! { pub(super) static TEST_METADATA_RECEIVING_FAILURE:std::cell::Cell<bool>=const{std::cell::Cell::new(false)}; }

// Neutral file replacement primitives; archive and background keep their own admission.
pub(super) fn create_replacement_file(
    path: &Path,
    bytes: &[u8],
    metadata: &FileIdentity,
) -> Result<SourceSnapshot, String> {
    {
        let mut file = create_owned_file_with_identity(path, Some(&metadata.security_descriptor))?;
        identity(&file)?;
        file.write_all(bytes).map_err(|e| io("stage write", e))?;
        let basic = BasicInformation {
            creation: i64::try_from(metadata.creation).map_err(|_| "creation time overflow")?,
            access: 0,
            write: i64::try_from(metadata.write).map_err(|_| "write time overflow")?,
            change: 0,
            attributes: metadata.attributes,
        };
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                0,
                (&basic as *const BasicInformation).cast(),
                std::mem::size_of::<BasicInformation>() as u32,
            )
        } == 0
        {
            return Err(io("stage metadata", std::io::Error::last_os_error()));
        }
        file.sync_all().map_err(|e| io("stage flush", e))?;
    }
    let actual = read_path(path, READ | DELETE)?;
    if actual.bytes != bytes {
        return Err("staged file readback mismatch".into());
    }
    Ok(actual)
}
pub(super) fn same_snapshot(actual: &SourceSnapshot, expected: &SourceSnapshot) -> bool {
    actual.identity == expected.identity
        && actual.digest == expected.digest
        && actual.bytes == expected.bytes
}
pub(super) fn replace_native_file(
    target: &Path,
    staged: &Path,
    displaced: &Path,
    called: &mut Option<bool>,
) -> Result<(), String> {
    let target = NativeFsPath::from_path(target)?;
    let staged = NativeFsPath::from_path(staged)?;
    let displaced = NativeFsPath::from_path(displaced)?;
    #[cfg(test)]
    TEST_NATIVE_CALLS.with(|v| v.set(v.get() + 1));
    // Flags zero deliberately: IGNORE_MERGE_ERRORS weakens integrity and the
    // documented WRITE_THROUGH flag is unsupported. Stage/backup were flushed.
    *called = Some(false);
    if unsafe {
        ReplaceFileW(
            target.as_ptr(),
            staged.as_ptr(),
            displaced.as_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        Err(io("ReplaceFileW", std::io::Error::last_os_error()))
    } else {
        *called = Some(true);
        Ok(())
    }
}

pub(super) fn restore_replacement_security(
    target: &Path,
    staged: &SourceSnapshot,
    staged_object: &ObjectId,
    source_object: &ObjectId,
    expected_displaced: &SourceSnapshot,
    displaced: &Path,
    security: &[u8],
    guard: &mut impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    let actual = read_path(target, READ | DELETE)?;
    if actual.digest != staged.digest
        || actual.bytes != staged.bytes
        || actual.identity.volume != staged.identity.volume
        || actual.identity.index != staged.identity.index
        || !same_snapshot(&read_path(displaced, READ | DELETE)?, expected_displaced)
    {
        return Err(
            "native postimage/displaced ownership mismatch before metadata restoration".into(),
        );
    }
    if object_id(&open_regular(target, READ | DELETE)?)? != *staged_object
        || object_id(&open_regular(displaced, READ | DELETE)?)? != *source_object
    {
        return Err(
            "full native postimage/displaced identity mismatch before metadata restoration".into(),
        );
    }
    guard()?;
    let file = OpenOptions::new()
        .access_mode(0x0006_0000)
        .share_mode(READ | DELETE)
        .custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(target)?.as_path())
        .map_err(|e| io("owned postimage READ_CONTROL/WRITE_DAC", e))?;
    let actual_id = identity(&file)?;
    if object_id(&file)? != *staged_object
        || actual_id.volume != staged.identity.volume
        || actual_id.index != staged.identity.index
    {
        return Err("postimage handle identity changed before metadata restoration".into());
    }
    restore_received_dacl(&file, security)
}

pub(super) fn path_evidence(path: &Path) -> serde_json::Value {
    // Exact native units remain representable even when no Unicode string is.
    serde_json::json!({"path":path.to_str(), "nativePathUtf16":path.as_os_str().encode_wide().collect::<Vec<_>>()})
}
pub(super) fn snapshot_evidence(snapshot: &SourceSnapshot) -> serde_json::Value {
    serde_json::json!({"path":path_evidence(&snapshot.target), "digest":snapshot.digest, "metadata":snapshot.identity})
}
pub(super) fn observe(path: &Path) -> serde_json::Value {
    let native = match NativeFsPath::from_path(path) {
        Ok(value) => value,
        Err(error) => return serde_json::json!({"state":"unavailable","error":error}),
    };
    match fs::symlink_metadata(native.as_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::json!({"state":"missing"}),
        Err(error) => serde_json::json!({"state":"unavailable","error":io("background observation",error)}),
        Ok(_) => match read_path(path, READ | DELETE).and_then(|snapshot| {
            let id = object_id(&open_regular(path, READ | DELETE)?)?;
            Ok(serde_json::json!({"state":"present","nativeId":id,"snapshot":snapshot_evidence(&snapshot)}))
        }) { Ok(value) => value, Err(error) => serde_json::json!({"state":"unavailable","error":error}) }
    }
}
