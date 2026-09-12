//! Win32 Fluent / Dark Theme System Tray Icon and Context Menu.
//!
//! Provides native Windows 10/11 notification area integration with:
//! - Dynamic tooltip showing service status, active route, and latency
//! - Windows dark theme context menu (`uxtheme.dll` ordinals 135, 133, 136)
//! - Explorer taskbar restart recovery (`TaskbarCreated` window message)
//! - Non-blocking dedicated UI message pump thread (`tray-ui`)
//! - Instant pause/resume synchronization with `%LOCALAPPDATA%\AGUnlocker\paused`
//! - Fast 1-click upstream switching from auto-detected local clients or custom proxy
//! - System rollback modal and application exit handlers

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

// Shared state for pause / resume
static BYPASS_PAUSED: AtomicBool = AtomicBool::new(false);

/// Status of loaded uxtheme dark mode hook ordinals and exports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DarkThemeHooks {
    pub set_preferred_app_mode: bool,
    pub allow_dark_mode_for_window: bool,
    pub flush_menu_themes: bool,
    pub set_window_theme: bool,
}

/// Returns the path to the pause state marker file: `%LOCALAPPDATA%\AGUnlocker\paused`.
pub fn paused_file_path() -> PathBuf {
    crate::dns_forwarder::log_dir().join("paused")
}

/// Checks whether bypass routing is paused.
/// Returns true if either the paused file exists or the atomic flag is set,
/// keeping in-memory and filesystem states strictly synchronized.
pub fn is_paused() -> bool {
    if paused_file_path().exists() {
        BYPASS_PAUSED.store(true, Ordering::SeqCst);
        true
    } else {
        BYPASS_PAUSED.store(false, Ordering::SeqCst);
        false
    }
}

/// Toggles or sets the bypass pause state.
///
/// Pausing:
/// - Creates `%LOCALAPPDATA%\AGUnlocker\paused`
/// - Sets `BYPASS_PAUSED` to true
/// - Removes `HTTPS_PROXY` if ours
/// - Removes DNS NRPT rules
///
/// Resuming:
/// - Removes `%LOCALAPPDATA%\AGUnlocker\paused`
/// - Sets `BYPASS_PAUSED` to false
/// - Reapplies `HTTPS_PROXY`
/// - Reinstalls DNS NRPT rules
pub fn set_paused(paused: bool) -> Result<(), String> {
    let path = paused_file_path();
    if paused {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, b"paused\n")
            .map_err(|e| format!("failed to write paused marker: {}", e))?;
        BYPASS_PAUSED.store(true, Ordering::SeqCst);
        #[cfg(target_os = "windows")]
        {
            let ca = crate::proxy::ca_cert_path().to_string_lossy().to_string();
            let _ = crate::endpoint::remove_proxy_if_ours(&crate::proxy::proxy_url(), &ca);
            crate::dns::remove_dns_nrpt();
        }
    } else {
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        BYPASS_PAUSED.store(false, Ordering::SeqCst);
        #[cfg(target_os = "windows")]
        {
            let _ = crate::endpoint::apply_proxy(&crate::proxy::proxy_url(), "");
            let _ = crate::dns::setup_dns_nrpt();
        }
    }
    Ok(())
}

/// Toggles pause state and returns the new state.
pub fn toggle_pause() -> Result<bool, String> {
    let next = !is_paused();
    set_paused(next)?;
    Ok(next)
}

/// Formats the tray tooltip string according to service state.
/// Maximum 128 UTF-16 code units supported by NOTIFYICONDATAW.
pub fn format_tooltip(paused: bool, route_name: &str, latency_ms: Option<u64>) -> String {
    if paused {
        "Antigravity Unlocker\nСтатус: Приостановлен\nМаршрут: Прямой (обход выключен)".to_string()
    } else {
        match latency_ms {
            Some(lat) => format!(
                "Antigravity Unlocker\nСтатус: Активен\nМаршрут: {} ({} мс)",
                route_name, lat
            ),
            None => format!(
                "Antigravity Unlocker\nСтатус: Активен\nМаршрут: {}",
                route_name
            ),
        }
    }
}

/// Resolves current active route name and latency in milliseconds.
pub fn current_route_info() -> (String, Option<u64>) {
    if let Some(up) = crate::upstream::configured() {
        let lat = crate::routes::latency(crate::routes::Kind::Own).map(|d| d.as_millis() as u64);
        (format!("Свой прокси ({}:{})", up.host, up.port), lat)
    } else if let Some((kind, _ago)) = crate::routes::last_used() {
        let lat = crate::routes::latency(kind).map(|d| d.as_millis() as u64);
        (kind.label().to_string(), lat)
    } else {
        let relay_lat = crate::routes::latency(crate::routes::Kind::Relay).map(|d| d.as_millis() as u64);
        let direct_lat = crate::routes::latency(crate::routes::Kind::Direct).map(|d| d.as_millis() as u64);
        if let Some(l) = relay_lat {
            ("Релей".to_string(), Some(l))
        } else if let Some(l) = direct_lat {
            ("Прямой".to_string(), Some(l))
        } else {
            ("Релей".to_string(), None)
        }
    }
}

#[cfg(target_os = "windows")]
mod win_tray {
    use super::*;
    use std::ffi::c_void;
    use std::ptr::null;
    use std::sync::{Mutex, Once};
    use windows_sys::Win32::Foundation::{BOOL, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NOTIFYICONDATAW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
        NIM_MODIFY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct WNDCLASSEXW {
        cbSize: u32,
        style: u32,
        lpfnWndProc: Option<unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT>,
        cbClsExtra: i32,
        cbWndExtra: i32,
        hInstance: HINSTANCE,
        hIcon: HICON,
        hCursor: isize,
        hbrBackground: isize,
        lpszMenuName: *const u16,
        lpszClassName: *const u16,
        hIconSm: HICON,
    }

    extern "system" {
        fn GetModuleHandleW(lpModuleName: *const u16) -> HINSTANCE;
        fn LoadLibraryW(lpLibFileName: *const u16) -> HINSTANCE;
        fn GetProcAddress(hModule: HINSTANCE, lpProcName: *const u8) -> *const c_void;
        fn RegisterClassExW(lpwcx: *const WNDCLASSEXW) -> u16;
    }

    const WM_TRAYICON: u32 = WM_USER + 100;
    const ID_TRAY_TIMER: usize = 1001;
    const TIMER_INTERVAL_MS: u32 = 3000;

    // Context Menu Item IDs
    const ID_STATUS_HEADER: u32 = 1000;
    const ID_PAUSE_RESUME: u32 = 1001;
    const ID_OPEN_LOGS: u32 = 1003;
    const ID_FULL_ROLLBACK: u32 = 1004;
    const ID_EXIT: u32 = 1005;
    const ID_UPSTREAM_NONE: u32 = 2001;
    const ID_UPSTREAM_CUSTOM: u32 = 2002;
    const ID_UPSTREAM_CLIENT_BASE: u32 = 2100;
    const ID_UPSTREAM_CLIENT_MAX: u32 = 2199;

    static mut TASKBAR_CREATED_MSG: u32 = 0;
    static mut GLOBAL_ICON: HICON = 0;
    static TRAY_HWND: Mutex<Option<HWND>> = Mutex::new(None);
    static DARK_LOADED: Once = Once::new();

    static mut FN_SET_PREFERRED_APP_MODE: Option<unsafe extern "system" fn(i32) -> i32> = None;
    static mut FN_ALLOW_DARK_MODE_FOR_WINDOW: Option<unsafe extern "system" fn(HWND, BOOL) -> BOOL> = None;
    static mut FN_FLUSH_MENU_THEMES: Option<unsafe extern "system" fn()> = None;
    static mut FN_SET_WINDOW_THEME: Option<unsafe extern "system" fn(HWND, *const u16, *const u16) -> i32> = None;
    static mut DARK_HOOKS: DarkThemeHooks = DarkThemeHooks {
        set_preferred_app_mode: false,
        allow_dark_mode_for_window: false,
        flush_menu_themes: false,
        set_window_theme: false,
    };

    pub fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn load_dark_theme_hooks() -> DarkThemeHooks {
        unsafe {
            DARK_LOADED.call_once(|| {
                let uxtheme_name = to_wide("uxtheme.dll");
                let h_uxtheme = LoadLibraryW(uxtheme_name.as_ptr());
                if h_uxtheme != 0 {
                    // Ordinal 135: SetPreferredAppMode
                    let p135 = GetProcAddress(h_uxtheme, 135 as usize as *const u8);
                    if !p135.is_null() {
                        FN_SET_PREFERRED_APP_MODE = Some(std::mem::transmute(p135));
                        DARK_HOOKS.set_preferred_app_mode = true;
                    }
                    // Ordinal 133: AllowDarkModeForWindow
                    let p133 = GetProcAddress(h_uxtheme, 133 as usize as *const u8);
                    if !p133.is_null() {
                        FN_ALLOW_DARK_MODE_FOR_WINDOW = Some(std::mem::transmute(p133));
                        DARK_HOOKS.allow_dark_mode_for_window = true;
                    }
                    // Ordinal 136: FlushMenuThemes
                    let p136 = GetProcAddress(h_uxtheme, 136 as usize as *const u8);
                    if !p136.is_null() {
                        FN_FLUSH_MENU_THEMES = Some(std::mem::transmute(p136));
                        DARK_HOOKS.flush_menu_themes = true;
                    }
                    // Named export: SetWindowTheme
                    let p_swt = GetProcAddress(h_uxtheme, b"SetWindowTheme\0".as_ptr());
                    if !p_swt.is_null() {
                        FN_SET_WINDOW_THEME = Some(std::mem::transmute(p_swt));
                        DARK_HOOKS.set_window_theme = true;
                    }
                }
            });
            DARK_HOOKS
        }
    }

    pub fn apply_dark_theme(hwnd: HWND) {
        unsafe {
            let _ = load_dark_theme_hooks();
            if let Some(set_preferred) = FN_SET_PREFERRED_APP_MODE {
                set_preferred(2); // 2 = ForceDark
            }
            if let Some(allow_dark) = FN_ALLOW_DARK_MODE_FOR_WINDOW {
                allow_dark(hwnd, 1);
            }
            if let Some(set_theme) = FN_SET_WINDOW_THEME {
                let theme_name = to_wide("DarkMode_Explorer");
                set_theme(hwnd, theme_name.as_ptr(), null());
            }
            if let Some(flush) = FN_FLUSH_MENU_THEMES {
                flush();
            }
        }
    }

    fn fill_tooltip(nid: &mut NOTIFYICONDATAW, text: &str) {
        let wide = to_wide(text);
        let max = nid.szTip.len();
        let copy_len = wide.len().min(max);
        for i in 0..copy_len {
            nid.szTip[i] = wide[i];
        }
        if copy_len < max {
            nid.szTip[copy_len] = 0;
        } else {
            nid.szTip[max - 1] = 0;
        }
    }

    fn build_nid(hwnd: HWND) -> NOTIFYICONDATAW {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAYICON;
        nid.hIcon = unsafe { GLOBAL_ICON };
        let paused = is_paused();
        let (route_name, latency_opt) = current_route_info();
        let tip = format_tooltip(paused, &route_name, latency_opt);
        fill_tooltip(&mut nid, &tip);
        nid
    }

    pub fn update_tray_tooltip(hwnd: HWND) {
        let paused = is_paused();
        let (route_name, latency_opt) = current_route_info();
        let tip = format_tooltip(paused, &route_name, latency_opt);

        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_TIP;
        fill_tooltip(&mut nid, &tip);

        unsafe {
            Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if TASKBAR_CREATED_MSG != 0 && msg == TASKBAR_CREATED_MSG {
            let nid = build_nid(hwnd);
            Shell_NotifyIconW(NIM_ADD, &nid);
            return 0;
        }

        match msg {
            WM_TRAYICON => {
                let event = (lparam & 0xFFFF) as u32;
                if event == WM_RBUTTONUP || event == WM_LBUTTONUP || event == WM_CONTEXTMENU {
                    show_context_menu(hwnd);
                }
                0
            }
            WM_TIMER => {
                if wparam == ID_TRAY_TIMER {
                    update_tray_tooltip(hwnd);
                }
                0
            }
            WM_CLOSE => {
                KillTimer(hwnd, ID_TRAY_TIMER);
                let mut del_nid: NOTIFYICONDATAW = std::mem::zeroed();
                del_nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                del_nid.hWnd = hwnd;
                del_nid.uID = 1;
                Shell_NotifyIconW(NIM_DELETE, &del_nid);
                DestroyWindow(hwnd);
                PostQuitMessage(0);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    fn show_context_menu(hwnd: HWND) {
        unsafe {
            apply_dark_theme(hwnd);
            let mut pt: POINT = std::mem::zeroed();
            GetCursorPos(&mut pt);

            let hmenu = CreatePopupMenu();
            if hmenu == 0 {
                return;
            }

            // 1. Status Header
            let paused = is_paused();
            let (route_name, latency_opt) = current_route_info();
            let header_text = if paused {
                "○ Статус: Приостановлен".to_string()
            } else {
                match latency_opt {
                    Some(ms) => format!("● Статус: Активен ({}: {} мс)", route_name, ms),
                    None => format!("● Статус: Активен ({})", route_name),
                }
            };
            AppendMenuW(
                hmenu,
                MF_STRING | MF_DISABLED | MF_GRAYED,
                ID_STATUS_HEADER as usize,
                to_wide(&header_text).as_ptr(),
            );
            AppendMenuW(hmenu, MF_SEPARATOR, 0, null());

            // 2. Pause/Resume Toggle
            let pause_label = if paused {
                "Возобновить обход"
            } else {
                "Приостановить обход"
            };
            AppendMenuW(
                hmenu,
                MF_STRING,
                ID_PAUSE_RESUME as usize,
                to_wide(pause_label).as_ptr(),
            );
            AppendMenuW(hmenu, MF_SEPARATOR, 0, null());

            // 3. Upstream Submenu
            let hsub = CreatePopupMenu();
            let configured_up = crate::upstream::configured();
            let is_none_checked = configured_up.is_none();
            let none_flags = if is_none_checked {
                MF_STRING | MF_CHECKED
            } else {
                MF_STRING
            };
            AppendMenuW(
                hsub,
                none_flags,
                ID_UPSTREAM_NONE as usize,
                to_wide("Отключено (по умолчанию)").as_ptr(),
            );
            AppendMenuW(hsub, MF_SEPARATOR, 0, null());

            let detected_clients = crate::detector::detect_clients();
            let mut any_client_matched = false;
            for (i, client) in detected_clients.iter().enumerate() {
                let id = ID_UPSTREAM_CLIENT_BASE + i as u32;
                if id > ID_UPSTREAM_CLIENT_MAX {
                    break;
                }
                let proto_str = match client.protocol {
                    crate::detector::DetectedProtocol::Socks5 => "SOCKS5",
                    crate::detector::DetectedProtocol::Http => "HTTP",
                };
                let label = format!("{} ({} {}:{})", client.name, proto_str, client.host, client.port);
                let matched = match &configured_up {
                    Some(up) => up.host == client.host && up.port == client.port,
                    None => false,
                };
                if matched {
                    any_client_matched = true;
                }
                let flags = if matched {
                    MF_STRING | MF_CHECKED
                } else {
                    MF_STRING
                };
                AppendMenuW(hsub, flags, id as usize, to_wide(&label).as_ptr());
            }

            AppendMenuW(hsub, MF_SEPARATOR, 0, null());
            let is_custom = configured_up.is_some() && !any_client_matched;
            let custom_label = match &configured_up {
                Some(up) if is_custom => format!("Свой прокси ({}:{})", up.host, up.port),
                _ => "Свой прокси (upstream.txt)".to_string(),
            };
            let custom_flags = if is_custom {
                MF_STRING | MF_CHECKED
            } else {
                MF_STRING
            };
            AppendMenuW(
                hsub,
                custom_flags,
                ID_UPSTREAM_CUSTOM as usize,
                to_wide(&custom_label).as_ptr(),
            );

            AppendMenuW(
                hmenu,
                MF_POPUP,
                hsub as usize,
                to_wide("Выбор Upstream Proxy").as_ptr(),
            );
            AppendMenuW(hmenu, MF_SEPARATOR, 0, null());

            // 4. Open Logs Folder
            AppendMenuW(
                hmenu,
                MF_STRING,
                ID_OPEN_LOGS as usize,
                to_wide("Открыть папку логов").as_ptr(),
            );

            // 5. Full Rollback Modal
            AppendMenuW(
                hmenu,
                MF_STRING,
                ID_FULL_ROLLBACK as usize,
                to_wide("Полный откат...").as_ptr(),
            );
            AppendMenuW(hmenu, MF_SEPARATOR, 0, null());

            // 6. Exit
            AppendMenuW(
                hmenu,
                MF_STRING,
                ID_EXIT as usize,
                to_wide("Выход").as_ptr(),
            );

            // Microsoft KB138971: SetForegroundWindow + PostMessage WM_NULL
            SetForegroundWindow(hwnd);
            let cmd = TrackPopupMenuEx(
                hmenu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
                pt.x,
                pt.y,
                hwnd,
                null(),
            );
            PostMessageW(hwnd, WM_NULL, 0, 0);
            DestroyMenu(hmenu);

            // Dispatch command
            match cmd as u32 {
                0 => {} // dismissed
                ID_PAUSE_RESUME => {
                    let _ = toggle_pause();
                    update_tray_tooltip(hwnd);
                }
                ID_UPSTREAM_NONE => {
                    crate::upstream::clear();
                    update_tray_tooltip(hwnd);
                }
                ID_UPSTREAM_CUSTOM => {
                    let path = crate::dns_forwarder::log_dir().join("upstream.txt");
                    if !path.exists() {
                        let _ = std::fs::write(&path, b"");
                    }
                    let _ = std::process::Command::new("notepad.exe").arg(&path).spawn();
                }
                id if id >= ID_UPSTREAM_CLIENT_BASE
                    && (id - ID_UPSTREAM_CLIENT_BASE) < detected_clients.len() as u32 =>
                {
                    let idx = (id - ID_UPSTREAM_CLIENT_BASE) as usize;
                    if let Some(client) = detected_clients.get(idx) {
                        let _ = crate::detector::apply_detected_client(client);
                        update_tray_tooltip(hwnd);
                    }
                }
                ID_OPEN_LOGS => {
                    let dir = crate::dns_forwarder::log_dir();
                    let _ = std::fs::create_dir_all(&dir);
                    let _ = std::process::Command::new("explorer.exe").arg(&dir).spawn();
                }
                ID_FULL_ROLLBACK => {
                    let prompt_text = to_wide(
                        "Вы уверены, что хотите выполнить полный откат?\n\n\
                        Это остановит фоновые службы, снимет патчи с бинарников и IDE, \
                        удалит правила NRPT и восстановит исходные настройки системы.",
                    );
                    let title_text = to_wide("Antigravity Unlocker");
                    let ret = MessageBoxW(
                        hwnd,
                        prompt_text.as_ptr(),
                        title_text.as_ptr(),
                        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
                    );
                    if ret == IDYES {
                        let mut del_nid: NOTIFYICONDATAW = std::mem::zeroed();
                        del_nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                        del_nid.hWnd = hwnd;
                        del_nid.uID = 1;
                        Shell_NotifyIconW(NIM_DELETE, &del_nid);

                        crate::handle_revert_all();

                        let done_text = to_wide("Полный откат успешно выполнен.");
                        MessageBoxW(
                            0 as HWND,
                            done_text.as_ptr(),
                            title_text.as_ptr(),
                            MB_OK | MB_ICONINFORMATION,
                        );
                        PostQuitMessage(0);
                        std::process::exit(0);
                    }
                }
                ID_EXIT => {
                    let mut del_nid: NOTIFYICONDATAW = std::mem::zeroed();
                    del_nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                    del_nid.hWnd = hwnd;
                    del_nid.uID = 1;
                    Shell_NotifyIconW(NIM_DELETE, &del_nid);
                    PostQuitMessage(0);
                }
                _ => {}
            }
        }
    }

    pub fn exit_tray() {
        if let Ok(guard) = TRAY_HWND.lock() {
            if let Some(hwnd) = *guard {
                unsafe {
                    PostMessageW(hwnd, WM_CLOSE, 0, 0);
                }
            }
        }
    }

    pub fn run_tray_loop() -> Result<(), String> {
        unsafe {
            let hinstance = GetModuleHandleW(null()) as HINSTANCE;
            let sm_cx = GetSystemMetrics(SM_CXSMICON);
            let sm_cy = GetSystemMetrics(SM_CYSMICON);
            let hicon = LoadImageW(
                hinstance,
                1 as usize as *const u16,
                IMAGE_ICON,
                sm_cx,
                sm_cy,
                LR_DEFAULTCOLOR,
            ) as HICON;
            let icon = if hicon != 0 {
                hicon
            } else {
                LoadIconW(0 as HINSTANCE, IDI_APPLICATION)
            };
            GLOBAL_ICON = icon;

            let class_name = to_wide("AGUnlockerTrayWindow");
            let mut wc: WNDCLASSEXW = std::mem::zeroed();
            wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
            wc.lpfnWndProc = Some(window_proc);
            wc.hInstance = hinstance;
            wc.lpszClassName = class_name.as_ptr();
            wc.hIcon = icon;
            wc.hIconSm = icon;
            RegisterClassExW(&wc);

            TASKBAR_CREATED_MSG = RegisterWindowMessageW(to_wide("TaskbarCreated").as_ptr());

            let window_title = to_wide("Antigravity Unlocker Tray");
            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                window_title.as_ptr(),
                WS_POPUP,
                0,
                0,
                0,
                0,
                0 as HWND,
                0 as HMENU,
                hinstance,
                null(),
            );
            if hwnd == 0 {
                return Err("CreateWindowExW failed for tray window".to_string());
            }

            if let Ok(mut lock) = TRAY_HWND.lock() {
                *lock = Some(hwnd);
            }

            let nid = build_nid(hwnd);
            let _ = Shell_NotifyIconW(NIM_ADD, &nid);

            SetTimer(hwnd, ID_TRAY_TIMER, TIMER_INTERVAL_MS, None);

            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, 0 as HWND, 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            KillTimer(hwnd, ID_TRAY_TIMER);
            let mut del_nid: NOTIFYICONDATAW = std::mem::zeroed();
            del_nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            del_nid.hWnd = hwnd;
            del_nid.uID = 1;
            Shell_NotifyIconW(NIM_DELETE, &del_nid);
            DestroyWindow(hwnd);

            if let Ok(mut lock) = TRAY_HWND.lock() {
                *lock = None;
            }

            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
pub use win_tray::{exit_tray, load_dark_theme_hooks};

#[cfg(target_os = "windows")]
pub fn run_tray_standalone() -> Result<(), String> {
    win_tray::run_tray_loop()
}

#[cfg(target_os = "windows")]
pub fn spawn_tray_thread() -> Result<std::thread::JoinHandle<()>, String> {
    std::thread::Builder::new()
        .name("tray-ui".to_string())
        .spawn(|| {
            if let Err(e) = win_tray::run_tray_loop() {
                eprintln!("tray error: {}", e);
            }
        })
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn run_tray_standalone() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn spawn_tray_thread() -> Result<std::thread::JoinHandle<()>, String> {
    std::thread::Builder::new()
        .name("tray-ui-stub".to_string())
        .spawn(|| {})
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn exit_tray() {}

#[cfg(not(target_os = "windows"))]
pub fn load_dark_theme_hooks() -> DarkThemeHooks {
    DarkThemeHooks::default()
}
