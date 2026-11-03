//! In-process Authenticode receiving; cache-only and no UI/network retrieval.
use super::*;
use std::ffi::c_void;
#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
#[repr(C)]
struct TrustFile {
    size: u32,
    path: *const u16,
    file: *mut c_void,
    subject: *const Guid,
}
#[repr(C)]
struct TrustData {
    size: u32,
    policy: *mut c_void,
    sip: *mut c_void,
    ui: u32,
    revocation: u32,
    choice: u32,
    file: *mut TrustFile,
    action: u32,
    state: *mut c_void,
    url: *mut u16,
    flags: u32,
    ui_context: u32,
    settings: *mut c_void,
}
#[repr(C)]
struct Signer {
    size: u32,
    time: [u32; 2],
    count: u32,
    certs: *const ProviderCert,
    kind: u32,
    info: *mut c_void,
    error: u32,
    counter_count: u32,
    counters: *mut c_void,
    chain: *mut c_void,
}
#[repr(C)]
struct ProviderCert {
    size: u32,
    cert: *const CertContext,
}
#[repr(C)]
struct CertContext {
    encoding: u32,
    bytes: *const u8,
    length: u32,
    info: *mut c_void,
    store: *mut c_void,
}
#[link(name = "wintrust")]
unsafe extern "system" {
    fn WinVerifyTrust(window: *mut c_void, action: *const Guid, data: *mut TrustData) -> i32;
    fn WTHelperProvDataFromStateData(state: *mut c_void) -> *mut c_void;
    fn WTHelperGetProvSignerFromChain(
        provider: *mut c_void,
        index: u32,
        counter: i32,
        counter_index: u32,
    ) -> *const Signer;
}
#[link(name = "crypt32")]
unsafe extern "system" {
    fn CertGetNameStringW(
        cert: *const CertContext,
        kind: u32,
        flags: u32,
        parameter: *const c_void,
        out: *mut u16,
        length: u32,
    ) -> u32;
}
const ACTION: Guid = Guid {
    a: 0x00aac56b,
    b: 0xcd44,
    c: 0x11d0,
    d: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};
struct State(TrustData);
impl Drop for State {
    fn drop(&mut self) {
        self.0.action = 2;
        unsafe {
            WinVerifyTrust(std::ptr::null_mut(), &ACTION, &mut self.0);
        }
    }
}
fn name(cert: *const CertContext, kind: u32, parameter: *const c_void) -> Result<String> {
    let n = unsafe { CertGetNameStringW(cert, kind, 0, parameter, std::ptr::null_mut(), 0) };
    if n <= 1 {
        return Err("provider signer name absent".into());
    }
    let mut text = vec![0; n as usize];
    let actual = unsafe { CertGetNameStringW(cert, kind, 0, parameter, text.as_mut_ptr(), n) };
    if actual != n {
        return Err("provider signer name receiving failed".into());
    }
    String::from_utf16(&text[..n as usize - 1]).map_err(|_| "provider signer name encoding".into())
}
pub(crate) struct SignatureIdentity {
    pub(crate) organization: String,
    pub(crate) simple_name: String,
    pub(crate) certificate_sha256: String,
}
pub(crate) fn verify_signature(executable: &CheckedPath) -> Result<SignatureIdentity> {
    let path = NativeFsPath::from_path(executable.as_path())?;
    let mut file = TrustFile {
        size: std::mem::size_of::<TrustFile>() as u32,
        path: path.as_ptr(),
        file: executable.file.as_raw_handle(),
        subject: std::ptr::null(),
    };
    let mut state = State(TrustData {
        size: std::mem::size_of::<TrustData>() as u32,
        policy: std::ptr::null_mut(),
        sip: std::ptr::null_mut(),
        ui: 2,
        revocation: 0,
        choice: 1,
        file: &mut file,
        action: 1,
        state: std::ptr::null_mut(),
        url: std::ptr::null_mut(),
        flags: 0x1000 | 0x10,
        ui_context: 0,
        settings: std::ptr::null_mut(),
    });
    let status = unsafe { WinVerifyTrust(std::ptr::null_mut(), &ACTION, &mut state.0) };
    if status != 0 {
        return Err(format!(
            "UnsupportedActorContext: native Authenticode status {status:#x}"
        ));
    }
    let provider = unsafe { WTHelperProvDataFromStateData(state.0.state) };
    if provider.is_null() {
        return Err("provider signature state unavailable".into());
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    if signer.is_null() {
        return Err("provider signer unavailable".into());
    }
    let signer = unsafe { &*signer };
    if signer.error != 0 || signer.count == 0 || signer.certs.is_null() {
        return Err("provider signer chain unavailable".into());
    }
    let cert = unsafe { (*signer.certs).cert };
    if cert.is_null() {
        return Err("provider leaf certificate unavailable".into());
    }
    let context = unsafe { &*cert };
    if context.bytes.is_null() || context.length == 0 {
        return Err("provider certificate bytes unavailable".into());
    }
    Ok(SignatureIdentity {
        organization: name(cert, 3, b"2.5.4.10\0".as_ptr().cast())?,
        simple_name: name(cert, 4, std::ptr::null())?,
        certificate_sha256: hash(unsafe {
            std::slice::from_raw_parts(context.bytes, context.length as usize)
        }),
    })
}
