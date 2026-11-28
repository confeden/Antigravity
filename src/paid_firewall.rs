//! Persistent WFP policy for the network identities selected for strict PAID routing.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{FWP_E_ALREADY_EXISTS, FWP_E_SUBLAYER_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::{FreeSid, PSID};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

const SUBLAYER: GUID = GUID::from_u128(0xb6a70f2c_6585_47d5_96cd_eae6d3941303);
const LOOPBACK: u32 = u32::from_be_bytes([127, 0, 0, 1]);

fn check(status: u32, operation: &str) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!("Правила PAID (WFP) — {operation}: 0x{status:08X}"))
    }
}

struct Engine {
    handle: HANDLE,
    sublayer: GUID,
    persistent: bool,
}

impl Engine {
    fn open(sublayer: GUID, persistent: bool) -> Result<Self, String> {
        let mut handle = null_mut();
        // A non-dynamic session owns persistent objects across relay restarts.
        let session = FWPM_SESSION0 {
            flags: if persistent {
                0
            } else {
                FWPM_SESSION_FLAG_DYNAMIC
            },
            txnWaitTimeoutInMSec: 5_000,
            ..Default::default()
        };
        check(
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle) },
            "FwpmEngineOpen0",
        )?;
        Ok(Self {
            handle,
            sublayer,
            persistent,
        })
    }

    fn transaction(&self, work: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
        check(
            unsafe { FwpmTransactionBegin0(self.handle, 0) },
            "FwpmTransactionBegin0",
        )?;
        let result = work().and_then(|()| {
            check(
                unsafe { FwpmTransactionCommit0(self.handle) },
                "FwpmTransactionCommit0",
            )
        });
        if result.is_err() {
            // Closing the engine also aborts an outstanding transaction.
            unsafe { FwpmTransactionAbort0(self.handle) };
        }
        result
    }

    fn clear_filters(&self) -> Result<(), String> {
        let mut enumeration = null_mut();
        check(
            unsafe { FwpmFilterCreateEnumHandle0(self.handle, null(), &mut enumeration) },
            "FwpmFilterCreateEnumHandle0",
        )?;
        let result = self.owned_filter_keys(enumeration);
        let close = check(
            unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enumeration) },
            "FwpmFilterDestroyEnumHandle0",
        );
        for key in result? {
            check(
                unsafe { FwpmFilterDeleteByKey0(self.handle, &key) },
                "FwpmFilterDeleteByKey0",
            )?;
        }
        close
    }

    fn remove_sublayer(&self) -> Result<(), String> {
        self.transaction(|| {
            self.clear_filters()?;
            let status = unsafe { FwpmSubLayerDeleteByKey0(self.handle, &self.sublayer) };
            if status == FWP_E_SUBLAYER_NOT_FOUND as u32 {
                return Ok(());
            }
            check(status, "FwpmSubLayerDeleteByKey0")
        })
    }

    fn owned_filter_keys(&self, enumeration: HANDLE) -> Result<Vec<GUID>, String> {
        let mut keys = Vec::new();
        loop {
            let mut entries = null_mut();
            let mut count = 0;
            check(
                unsafe { FwpmFilterEnum0(self.handle, enumeration, 128, &mut entries, &mut count) },
                "FwpmFilterEnum0",
            )?;
            for index in 0..count {
                // Windows returns count pointers in this allocation.
                let entry = unsafe { &**entries.add(index as usize) };
                let key = entry.subLayerKey;
                if key.data1 == self.sublayer.data1
                    && key.data2 == self.sublayer.data2
                    && key.data3 == self.sublayer.data3
                    && key.data4 == self.sublayer.data4
                {
                    keys.push(entry.filterKey);
                }
            }
            free(entries);
            if count < 128 {
                return Ok(keys);
            }
        }
    }

    fn add_sublayer(&self) -> Result<(), String> {
        let name: Vec<u16> = "AI Unlocker PAID".encode_utf16().chain([0]).collect();
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: self.sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                ..Default::default()
            },
            flags: if self.persistent {
                FWPM_SUBLAYER_FLAG_PERSISTENT
            } else {
                0
            },
            weight: u16::MAX,
            ..Default::default()
        };
        let status = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, null_mut()) };
        if status != FWP_E_ALREADY_EXISTS as u32 {
            return check(status, "FwpmSubLayerAdd0");
        }
        Ok(())
    }

    fn block(&self, layer: GUID, conditions: &mut [FWPM_FILTER_CONDITION0]) -> Result<(), String> {
        self.filter(layer, conditions, FWP_ACTION_BLOCK)
    }

    fn filter(
        &self,
        layer: GUID,
        conditions: &mut [FWPM_FILTER_CONDITION0],
        action: FWP_ACTION_TYPE,
    ) -> Result<(), String> {
        let name: Vec<u16> = "AI Unlocker PAID".encode_utf16().chain([0]).collect();
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                ..Default::default()
            },
            flags: if action == FWP_ACTION_BLOCK {
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
            } else {
                0
            } | if self.persistent {
                FWPM_FILTER_FLAG_PERSISTENT
            } else {
                0
            },
            layerKey: layer,
            subLayerKey: self.sublayer,
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            // Listen exceptions are soft permits at a higher weight in this
            // sublayer only. A block in any other sublayer can still veto them.
            weight: if action == FWP_ACTION_PERMIT {
                FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: 15 },
                }
            } else {
                FWP_VALUE0::default()
            },
            action: FWPM_ACTION0 {
                r#type: action,
                ..Default::default()
            },
            ..Default::default()
        };
        check(
            unsafe { FwpmFilterAdd0(self.handle, &filter, null_mut(), null_mut()) },
            "FwpmFilterAdd0",
        )
    }

    fn reserve_listener(&self, owners: &[AppId], port: u16) -> Result<(), String> {
        let local_port = port_condition(FWPM_CONDITION_IP_LOCAL_PORT, FWP_MATCH_EQUAL, port);
        for layer in [FWPM_LAYER_ALE_AUTH_LISTEN_V4, FWPM_LAYER_ALE_AUTH_LISTEN_V6] {
            for owner in owners {
                self.filter(
                    layer,
                    &mut [owner.condition(FWP_MATCH_EQUAL), local_port],
                    FWP_ACTION_PERMIT,
                )?;
            }
            self.block(layer, &mut [local_port])?;
        }
        Ok(())
    }

    fn allow_only_proxy(
        &self,
        identity: FWPM_FILTER_CONDITION0,
        port: u16,
        ipc_port: Option<u16>,
    ) -> Result<(), String> {
        // Independent blocks express the inverse of one allowed tuple. No
        // permit filter overrides a different policy (for example, a VPN kill switch).
        let remote = condition(
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            FWP_MATCH_NOT_EQUAL,
            FWP_UINT32,
            FWP_CONDITION_VALUE0_0 { uint32: LOOPBACK },
        );
        let not_tcp = condition(
            FWPM_CONDITION_IP_PROTOCOL,
            FWP_MATCH_NOT_EQUAL,
            FWP_UINT8,
            FWP_CONDITION_VALUE0_0 { uint8: 6 },
        );
        for rejected in [remote, not_tcp] {
            self.block(FWPM_LAYER_ALE_AUTH_CONNECT_V4, &mut [identity, rejected])?;
        }

        // Missing tuples are blocked as ranges. Repeating a condition on the
        // same field in WFP is OR, so two inequalities would block every port.
        let allowed = ipc_port.map_or([port, port], |ipc| [port.min(ipc), port.max(ipc)]);
        let bounds = [
            (0, u32::from(allowed[0])),
            (u32::from(allowed[0]) + 1, u32::from(allowed[1])),
            (u32::from(allowed[1]) + 1, 65_536),
        ];
        for (start, end) in bounds {
            if start < end {
                let mut range = FWP_RANGE0 {
                    valueLow: port_value(start as u16),
                    valueHigh: port_value((end - 1) as u16),
                };
                let rejected = condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_MATCH_RANGE,
                    FWP_RANGE_TYPE,
                    FWP_CONDITION_VALUE0_0 {
                        rangeValue: &mut range,
                    },
                );
                self.block(FWPM_LAYER_ALE_AUTH_CONNECT_V4, &mut [identity, rejected])?;
            }
        }
        self.block(FWPM_LAYER_ALE_AUTH_CONNECT_V6, &mut [identity])?;

        // Incoming loopback TCP is used by local login callbacks and IDE IPC.
        for rejected in [remote, not_tcp] {
            self.block(
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                &mut [identity, rejected],
            )?;
        }
        self.block(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, &mut [identity])
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.handle) };
    }
}

fn free<T>(data: *mut T) {
    if !data.is_null() {
        let mut memory: *mut c_void = data.cast();
        unsafe { FwpmFreeMemory0(&mut memory) };
    }
}

struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn from_path(path: &Path) -> Result<Self, String> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let mut blob = null_mut();
        check(
            unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) },
            &format!("FwpmGetAppIdFromFileName0 ({})", path.display()),
        )?;
        Ok(Self(blob))
    }

    fn condition(&self, match_type: FWP_MATCH_TYPE) -> FWPM_FILTER_CONDITION0 {
        condition(
            FWPM_CONDITION_ALE_APP_ID,
            match_type,
            FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_VALUE0_0 { byteBlob: self.0 },
        )
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        free(self.0);
    }
}

struct PackageSid(PSID);

impl PackageSid {
    fn from_name(name: &str) -> Result<Self, String> {
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut sid = null_mut();
        check(
            unsafe { DeriveAppContainerSidFromAppContainerName(wide.as_ptr(), &mut sid) } as u32,
            "DeriveAppContainerSidFromAppContainerName",
        )?;
        Ok(Self(sid))
    }

    fn condition(&self) -> FWPM_FILTER_CONDITION0 {
        condition(
            FWPM_CONDITION_ALE_PACKAGE_ID,
            FWP_MATCH_EQUAL,
            FWP_SID,
            FWP_CONDITION_VALUE0_0 { sid: self.0.cast() },
        )
    }
}

impl Drop for PackageSid {
    fn drop(&mut self) {
        unsafe { FreeSid(self.0) };
    }
}

fn condition(
    field: GUID,
    compare: FWP_MATCH_TYPE,
    value_type: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: compare,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: value_type,
            Anonymous: value,
        },
    }
}

fn port_condition(field: GUID, compare: FWP_MATCH_TYPE, port: u16) -> FWPM_FILTER_CONDITION0 {
    condition(
        field,
        compare,
        FWP_UINT16,
        FWP_CONDITION_VALUE0_0 { uint16: port },
    )
}

fn port_value(port: u16) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: FWP_VALUE0_0 { uint16: port },
    }
}

pub(super) struct IdeIpc<'a> {
    pub port: u16,
    pub programs: &'a [PathBuf],
    pub listeners: &'a [PathBuf],
}

pub(super) fn install(
    programs: &[PathBuf],
    packages: &[&str],
    relay: &Path,
    port: u16,
    ide_ipc: Option<IdeIpc<'_>>,
) -> Result<(), String> {
    let relay = AppId::from_path(relay)?;
    let programs: Vec<(AppId, Option<u16>)> = programs
        .iter()
        .map(|path| {
            let ipc = ide_ipc.as_ref().filter(|ipc| ipc.programs.contains(path));
            Ok((AppId::from_path(path)?, ipc.map(|rule| rule.port)))
        })
        .collect::<Result<_, String>>()?;
    let engine = Engine::open(SUBLAYER, true)?;
    engine.transaction(|| {
        engine.add_sublayer()?;
        engine.clear_filters()?;
        for (program, ipc) in &programs {
            engine.allow_only_proxy(program.condition(FWP_MATCH_EQUAL), port, *ipc)?;
        }

        for package in packages {
            let sid = PackageSid::from_name(package)?;
            engine.allow_only_proxy(sid.condition(), port, None)?;
        }

        engine.reserve_listener(&[relay], port)?;
        if let Some(ipc) = ide_ipc {
            let owners: Vec<AppId> = ipc
                .listeners
                .iter()
                .map(|owner| AppId::from_path(owner))
                .collect::<Result<_, _>>()?;
            engine.reserve_listener(&owners, ipc.port)?;
        }
        Ok(())
    })
}

pub(super) fn remove() -> Result<(), String> {
    Engine::open(SUBLAYER, true)?.remove_sublayer()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::time::Duration;

    struct Fixture(GUID);

    impl Fixture {
        fn remove(&self) -> Result<(), String> {
            Engine::open(self.0, true)?.remove_sublayer()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Err(error) = self.remove() {
                eprintln!("WFP fixture cleanup failed: {error}");
            }
        }
    }

    #[test]
    #[ignore = "requires administrator rights and a live Windows BFE"]
    fn strict_policy_blocks_unapproved_sockets() {
        let own = AppId::from_path(&std::env::current_exe().unwrap()).unwrap();
        let layer = GUID::from_u128(0x19b588b8_e3af_46c4_9fb9_e46a75a0fb88);
        let fixture = Fixture(layer);
        fixture.remove().unwrap();
        let engine = Engine::open(layer, true).unwrap();
        let allowed = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let ipc = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let ipc_addr = ipc.local_addr().unwrap();
        let other = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let other_v6 = TcpListener::bind(("::1", 0)).unwrap();
        let allowed_addr = allowed.local_addr().unwrap();
        let other_addr = other.local_addr().unwrap();
        let v6_addr = other_v6.local_addr().unwrap();
        for addr in [allowed_addr, other_addr, v6_addr] {
            TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        }
        let udp = UdpSocket::bind(allowed_addr).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();

        engine
            .transaction(|| {
                engine.add_sublayer()?;
                engine.allow_only_proxy(
                    own.condition(FWP_MATCH_EQUAL),
                    allowed_addr.port(),
                    Some(ipc_addr.port()),
                )?;
                let sid = PackageSid::from_name("AIUnlocker.Test_0000000000000")?;
                engine.allow_only_proxy(sid.condition(), allowed_addr.port(), None)?;
                engine.reserve_listener(&[own], allowed_addr.port())
            })
            .unwrap();
        drop(engine);

        TcpStream::connect_timeout(&allowed_addr, Duration::from_secs(2)).unwrap();
        TcpStream::connect_timeout(&ipc_addr, Duration::from_secs(2)).unwrap();
        for addr in [other_addr, v6_addr] {
            let error = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(10013), "{addr}: {error}");
        }
        if udp.send_to(b"blocked", allowed_addr).is_ok() {
            assert!(
                udp.recv_from(&mut [0; 16]).is_err(),
                "UDP traversed the PAID port"
            );
        }
        let away = "192.0.2.1:443".parse().unwrap();
        let error = TcpStream::connect_timeout(&away, Duration::from_secs(2)).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(10013), "{away}: {error}");

        drop(allowed);
        assert!(TcpStream::connect_timeout(&allowed_addr, Duration::from_secs(2)).is_err());
        let error = TcpStream::connect_timeout(&other_addr, Duration::from_secs(2)).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(10013),
            "fallback after proxy loss: {error}"
        );
        TcpListener::bind(allowed_addr).expect("the reserved program can reopen the listener");
        let script = format!(
            "$socket = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, {}); try {{ $socket.Start(); exit 1 }} catch {{ if ($_.Exception.InnerException.NativeErrorCode -eq 10013) {{ exit 0 }}; throw }}",
            allowed_addr.port()
        );
        assert!(
            crate::utils::powershell(&script).unwrap().status.success(),
            "unrelated process could take the port"
        );

        fixture.remove().unwrap();
        TcpStream::connect_timeout(&other_addr, Duration::from_secs(2)).unwrap();
    }
}
