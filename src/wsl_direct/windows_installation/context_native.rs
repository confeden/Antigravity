//! Local Windows account/issuer/signature observations for ancestor receiving.
//! No provider discovery, credential reads, process launch or host mutation.
use super::*;
use std::ffi::c_void;
use std::ptr::{null, null_mut};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn IsValidSid(sid: *const c_void) -> i32;
    fn GetLengthSid(sid: *const c_void) -> u32;
    fn ConvertStringSidToSidW(text: *const u16, out: *mut *mut c_void) -> i32;
    fn GetWindowsAccountDomainSid(sid: *const c_void, domain: *mut c_void, size: *mut u32) -> i32;
    fn LookupAccountSidW(
        system: *const u16,
        sid: *const c_void,
        name: *mut u16,
        name_size: *mut u32,
        domain: *mut u16,
        domain_size: *mut u32,
        kind: *mut u32,
    ) -> i32;
    fn LsaOpenPolicy(
        system: *const c_void,
        attributes: *const LsaAttributes,
        access: u32,
        out: *mut *mut c_void,
    ) -> u32;
    fn LsaQueryInformationPolicy(policy: *mut c_void, class: u32, out: *mut *mut c_void) -> u32;
    fn LsaEnumerateTrustedDomainsEx(
        policy: *mut c_void,
        context: *mut u32,
        out: *mut *mut c_void,
        preferred: u32,
        count: *mut u32,
    ) -> u32;
    fn LsaFreeMemory(buffer: *mut c_void) -> u32;
    fn LsaClose(policy: *mut c_void) -> u32;
}
#[link(name = "netapi32")]
unsafe extern "system" {
    fn NetUserGetInfo(
        server: *const u16,
        name: *const u16,
        level: u32,
        out: *mut *mut c_void,
    ) -> u32;
    fn NetLocalGroupGetMembers(
        server: *const u16,
        name: *const u16,
        level: u32,
        out: *mut *mut c_void,
        preferred: u32,
        read: *mut u32,
        total: *mut u32,
        resume: *mut usize,
    ) -> u32;
    fn NetApiBufferFree(buffer: *mut c_void) -> u32;
    fn NetGetJoinInformation(server: *const u16, name: *mut *mut u16, status: *mut u32) -> u32;
    fn NetGetAadJoinInformation(tenant: *const u16, out: *mut *mut c_void) -> i32;
    fn NetFreeAadJoinInformation(info: *mut c_void);
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Sid(Vec<u8>);
impl Sid {
    pub(super) unsafe fn copy(raw: *const c_void) -> Result<Self> {
        if raw.is_null() || unsafe { IsValidSid(raw) } == 0 {
            return Err("native SID unavailable/invalid".into());
        }
        let size = unsafe { GetLengthSid(raw) } as usize;
        Ok(Self(
            unsafe { std::slice::from_raw_parts(raw.cast(), size) }.to_vec(),
        ))
    }
    pub(super) fn raw(&self) -> *const c_void {
        self.0.as_ptr().cast()
    }
    pub(super) fn text(&self) -> Result<String> {
        let mut out = null_mut();
        if unsafe { ConvertSidToStringSidW(self.raw() as *mut c_void, &mut out) } == 0 {
            return Err(io("SID encoding", std::io::Error::last_os_error()));
        }
        let result = unsafe { wide_text(out) };
        unsafe {
            LocalFree(out.cast());
        }
        result
    }
    pub(super) fn parse(text: &str) -> Result<Self> {
        let input = text.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut raw = null_mut();
        if unsafe { ConvertStringSidToSidW(input.as_ptr(), &mut raw) } == 0 {
            return Err("carrier SID syntax invalid".into());
        }
        let result = unsafe { Self::copy(raw) };
        unsafe {
            LocalFree(raw);
        }
        let sid = result?;
        if sid.text()? != text {
            return Err("carrier SID spelling is not canonical".into());
        }
        Ok(sid)
    }
    pub(super) fn domain(&self) -> Result<Self> {
        let mut length = 0;
        unsafe { GetWindowsAccountDomainSid(self.raw(), null_mut(), &mut length) };
        if length == 0 {
            return Err("SID has no account-domain identity".into());
        }
        let mut data = vec![0; length as usize];
        if unsafe { GetWindowsAccountDomainSid(self.raw(), data.as_mut_ptr().cast(), &mut length) }
            == 0
        {
            return Err("account-domain SID unavailable".into());
        }
        unsafe { Self::copy(data.as_ptr().cast()) }
    }
    pub(super) fn capability_side(&self) -> bool {
        // Native SID authority 15 and package/capability subauthority class.
        self.well_known(18)
            || self.0.len() >= 12
                && self.0[1] > 0
                && self.0[2..8] == [0, 0, 0, 0, 0, 15]
                && matches!(u32::from_le_bytes(self.0[8..12].try_into().unwrap()), 2 | 3)
    }
    pub(super) fn well_known(&self, kind: u32) -> bool {
        (unsafe { IsWellKnownSid(self.raw() as *mut c_void, kind) }) != 0
    }
}
unsafe fn wide_text(raw: *const u16) -> Result<String> {
    if raw.is_null() {
        return Err("native string absent".into());
    }
    let mut n = 0;
    unsafe {
        while *raw.add(n) != 0 {
            n += 1
        }
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(raw, n) })
        .map_err(|_| "native string encoding".into())
}
pub(super) fn current_user() -> Result<Sid> {
    let mut token = token_user()?;
    unsafe { Sid::copy(user_sid(&mut token)? as *const c_void) }
}
#[repr(C)]
struct LsaString {
    length: u16,
    maximum: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct LsaAttributes {
    length: u32,
    root: *mut c_void,
    name: *mut c_void,
    attributes: u32,
    descriptor: *mut c_void,
    qos: *mut c_void,
}
#[repr(C)]
struct DomainInfo {
    name: LsaString,
    sid: *mut c_void,
}
#[repr(C)]
struct TrustInfo {
    name: LsaString,
    flat: LsaString,
    sid: *mut c_void,
    direction: u32,
    kind: u32,
    attributes: u32,
}
struct Policy(*mut c_void);
impl Drop for Policy {
    fn drop(&mut self) {
        unsafe {
            LsaClose(self.0);
        }
    }
}
struct LsaBuffer(*mut c_void);
impl Drop for LsaBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LsaFreeMemory(self.0);
            }
        }
    }
}
struct NetBuffer(*mut c_void);
impl Drop for NetBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                NetApiBufferFree(self.0);
            }
        }
    }
}
fn policy() -> Result<Policy> {
    let attributes = LsaAttributes {
        length: std::mem::size_of::<LsaAttributes>() as u32,
        root: null_mut(),
        name: null_mut(),
        attributes: 0,
        descriptor: null_mut(),
        qos: null_mut(),
    };
    let mut out = null_mut();
    let status = unsafe { LsaOpenPolicy(null(), &attributes, 1, &mut out) };
    if status != 0 {
        return Err(format!("local policy read status {status:#x}"));
    }
    Ok(Policy(out))
}
fn domain_info(policy: &Policy, class: u32) -> Result<Option<Sid>> {
    let mut out = null_mut();
    let status = unsafe { LsaQueryInformationPolicy(policy.0, class, &mut out) };
    let buffer = LsaBuffer(out);
    if status != 0 || out.is_null() {
        return Err(format!("local domain observation status {status:#x}"));
    }
    let info = unsafe { &*buffer.0.cast::<DomainInfo>() };
    if info.sid.is_null() {
        Ok(None)
    } else {
        Ok(Some(unsafe { Sid::copy(info.sid) }?))
    }
}
pub(super) fn machine_domain() -> Result<Sid> {
    domain_info(&policy()?, 5)?.ok_or("local SAM domain absent".into())
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct IssuerSnapshot {
    sam: Sid,
    primary: Option<Sid>,
    trusts: Vec<Sid>,
    join: u32,
    aad_present: bool,
}
impl IssuerSnapshot {
    pub(super) fn observe() -> Result<Self> {
        let p = policy()?;
        let sam = domain_info(&p, 5)?.ok_or("SAM domain absent")?;
        let primary = domain_info(&p, 3)?;
        let mut context = 0;
        let mut trusts = Vec::new();
        loop {
            let before = context;
            let mut raw = null_mut();
            let mut count = 0;
            let status = unsafe {
                LsaEnumerateTrustedDomainsEx(p.0, &mut context, &mut raw, u32::MAX, &mut count)
            };
            let buffer = LsaBuffer(raw);
            if ![0, 0x105, 0x8000_001a].contains(&status) {
                return Err(format!(
                    "complete direct-trust observation status {status:#x}"
                ));
            }
            if count != 0 {
                if buffer.0.is_null() {
                    return Err("trust result missing buffer".into());
                }
                for i in 0..count as usize {
                    let item = unsafe { &*buffer.0.cast::<TrustInfo>().add(i) };
                    trusts.push(unsafe { Sid::copy(item.sid) }?);
                }
            }
            if status == 0 || status == 0x8000_001a {
                break;
            }
            if context == before {
                return Err("direct-trust enumeration made no progress".into());
            }
        }
        trusts.sort();
        trusts.dedup();
        let mut name = null_mut();
        let mut join = 0;
        let status = unsafe { NetGetJoinInformation(null(), &mut name, &mut join) };
        let _name = NetBuffer(name.cast());
        if status != 0 {
            return Err(format!("local join observation status {status}"));
        }
        let mut aad = null_mut();
        let status = unsafe { NetGetAadJoinInformation(null(), &mut aad) };
        if status < 0 {
            if !aad.is_null() {
                unsafe { NetFreeAadJoinInformation(aad) }
            }
            return Err(format!("local cloud-join observation status {status:#x}"));
        }
        let aad_present = !aad.is_null();
        if aad_present {
            unsafe { NetFreeAadJoinInformation(aad) }
        }
        Ok(Self {
            sam,
            primary,
            trusts,
            join,
            aad_present,
        })
    }
    pub(super) fn no_current_issuer(&self, sid: &Sid) -> bool {
        // Closed supported standalone class; no claim about transitive forests
        // or historical tokens is made from direct-trust absence.
        sid.domain().is_ok_and(|d| d != self.sam)
            && self.primary.is_none()
            && self.trusts.is_empty()
            && matches!(self.join, 1 | 2)
            && !self.aad_present
    }
}
#[repr(C)]
struct User23 {
    name: *mut u16,
    full: *mut u16,
    comment: *mut u16,
    flags: u32,
    sid: *mut c_void,
}
pub(super) fn local_role(name: &str, sam: &Sid) -> Result<Sid> {
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_control() || c == '\\' || c == '@')
    {
        return Err("local role name unsupported".into());
    }
    let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut raw = null_mut();
    let status = unsafe { NetUserGetInfo(null(), name.as_ptr(), 23, &mut raw) };
    let buffer = NetBuffer(raw);
    if status != 0 || buffer.0.is_null() {
        return Err(format!("local role observation status {status}"));
    }
    let user = unsafe { &*buffer.0.cast::<User23>() };
    let sid = unsafe { Sid::copy(user.sid) }?;
    if user.flags & 2 != 0 || sid.domain()? != *sam {
        return Err("registered role is not an enabled local SAM account".into());
    }
    Ok(sid)
}
fn local_group_name(sid: &Sid, sam: &Sid) -> Result<Option<String>> {
    if sid.domain()? != *sam {
        return Err("group is not local SAM".into());
    }
    let mut names = 0;
    let mut domains = 0;
    let mut kind = 0;
    unsafe {
        LookupAccountSidW(
            null(),
            sid.raw(),
            null_mut(),
            &mut names,
            null_mut(),
            &mut domains,
            &mut kind,
        )
    };
    if names == 0 {
        return Err("local group name unavailable".into());
    }
    let mut name = vec![0; names as usize];
    let mut domain = vec![0; domains as usize];
    if unsafe {
        LookupAccountSidW(
            null(),
            sid.raw(),
            name.as_mut_ptr(),
            &mut names,
            domain.as_mut_ptr(),
            &mut domains,
            &mut kind,
        )
    } == 0
    {
        return Err("local trustee lookup unavailable".into());
    }
    if kind == 1 {
        return Ok(None);
    }
    if kind != 4 {
        return Err("local trustee class unsupported".into());
    }
    String::from_utf16(&name[..names as usize])
        .map(Some)
        .map_err(|_| "group name encoding".into())
}
pub(super) fn group_members(sid: &Sid, sam: &Sid) -> Result<Vec<Sid>> {
    group_members_if_alias(sid, sam)?.ok_or("registered group is no longer a local alias".into())
}
pub(super) fn group_members_if_alias(sid: &Sid, sam: &Sid) -> Result<Option<Vec<Sid>>> {
    let name = match local_group_name(sid, sam)? {
        Some(name) => name,
        None => return Ok(None),
    }
    .encode_utf16()
    .chain(Some(0))
    .collect::<Vec<_>>();
    let mut resume = 0usize;
    let mut all = Vec::new();
    loop {
        let before = resume;
        let mut raw = null_mut();
        let mut read = 0;
        let mut total = 0;
        let status = unsafe {
            NetLocalGroupGetMembers(
                null(),
                name.as_ptr(),
                0,
                &mut raw,
                u32::MAX,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        let buffer = NetBuffer(raw);
        if status != 0 && status != 234 {
            return Err(format!("complete local group roster status {status}"));
        }
        if read != 0 {
            if buffer.0.is_null() {
                return Err("group roster missing buffer".into());
            }
            for i in 0..read as usize {
                let sid = unsafe { *buffer.0.cast::<*mut c_void>().add(i) };
                all.push(unsafe { Sid::copy(sid) }?);
            }
        }
        if status == 0 {
            break;
        }
        if resume == before {
            return Err("group roster enumeration made no progress".into());
        }
    }
    all.sort();
    all.dedup();
    Ok(Some(all))
}
#[derive(Clone)]
pub(super) struct Ace {
    pub(super) deny: bool,
    pub(super) mask: u32,
    pub(super) sid: Sid,
}
pub(super) fn descriptor_owner(sd: &mut [u8]) -> Result<Sid> {
    let mut owner = null_mut();
    let mut d = 0;
    if unsafe { GetSecurityDescriptorOwner(sd.as_mut_ptr().cast(), &mut owner, &mut d) } == 0 {
        return Err("descriptor owner unavailable".into());
    }
    unsafe { Sid::copy(owner) }
}
pub(super) fn entries(sd: &mut [u8]) -> Result<Vec<Ace>> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = null_mut();
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
        return Err("ancestor DACL absent/null".into());
    }
    let count = unsafe { std::ptr::read_unaligned((acl as *const u8).add(4).cast::<u16>()) };
    let mut entries = Vec::new();
    for i in 0..u32::from(count) {
        let mut raw = null_mut();
        if unsafe { GetAce(acl, i, &mut raw) } == 0 || raw.is_null() {
            return Err("ancestor ACE unavailable".into());
        }
        let p = raw as *const u8;
        let kind = unsafe { *p };
        let flags = unsafe { *p.add(1) };
        if flags & 8 != 0 {
            continue;
        }
        if kind > 1 {
            return Err(
                "UnsupportedActorContext: conditional/object ancestor ACE is unsupported".into(),
            );
        }
        let length = unsafe { std::ptr::read_unaligned(p.add(2).cast::<u16>()) };
        if length < 12 {
            return Err("ancestor ACE truncated".into());
        }
        let mut mask = unsafe { std::ptr::read_unaligned(p.add(4).cast::<u32>()) };
        if mask & 0x1000_0000 != 0 {
            mask = (mask & !0x1000_0000) | 0x1f01ff
        }
        if mask & 0x8000_0000 != 0 {
            mask = (mask & !0x8000_0000) | 0x120089
        }
        if mask & 0x4000_0000 != 0 {
            mask = (mask & !0x4000_0000) | 0x120116
        }
        if mask & 0x2000_0000 != 0 {
            mask = (mask & !0x2000_0000) | 0x1200a0
        }
        entries.push(Ace {
            deny: kind == 1,
            mask,
            sid: unsafe { Sid::copy(p.add(8).cast()) }?,
        });
    }
    Ok(entries)
}
#[cfg(test)]
#[path = "context_native_tests.rs"]
mod tests;
