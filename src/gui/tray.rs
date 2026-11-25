//! System tray integration for keeping background monitoring out of the taskbar.

use std::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    Show,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseBehavior {
    Exit,
    HideToTray,
}

pub fn close_behavior(screen_is_main: bool, minimize_to_tray: bool, force_quit: bool) -> CloseBehavior {
    if screen_is_main && minimize_to_tray && !force_quit {
        CloseBehavior::HideToTray
    } else {
        CloseBehavior::Exit
    }
}

pub fn format_tooltip(status_label: Option<&str>) -> String {
    match status_label.map(str::trim).filter(|s| !s.is_empty()) {
        Some(label) => format!("Antigravity Unlocker — {label}"),
        None => "Antigravity Unlocker".to_string(),
    }
}

pub fn truncate_tip_utf16(text: &str, buf: &mut [u16; 128]) {
    buf.fill(0);
    for (dst, code) in buf[..127].iter_mut().zip(text.encode_utf16()) {
        *dst = code;
    }
}

pub struct TrayHandle {
    inner: platform::Handle,
}

impl TrayHandle {
    pub fn set_tooltip(&self, text: &str) {
        self.inner.set_tooltip(text);
    }
}

pub fn spawn(wake: Box<dyn Fn() + Send>) -> Option<(TrayHandle, mpsc::Receiver<TrayEvent>)> {
    let (tx, rx) = mpsc::channel();
    platform::spawn(tx, wake).map(|inner| (TrayHandle { inner }, rx))
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::TrayEvent;
    use std::sync::mpsc;

    pub struct Handle;

    impl Handle {
        pub fn set_tooltip(&self, _text: &str) {}
    }

    pub fn spawn(_tx: mpsc::Sender<TrayEvent>, _wake: Box<dyn Fn() + Send>) -> Option<Handle> {
        None
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{truncate_tip_utf16, TrayEvent};
    use std::cell::RefCell;
    use std::mem::size_of;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicIsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
        NIN_SELECT, NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu,
        DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, LoadImageW, PostMessageW,
        PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SetForegroundWindow,
        TrackPopupMenu, TranslateMessage, HICON, IDI_APPLICATION, IMAGE_ICON, LR_DEFAULTCOLOR,
        LR_SHARED, MF_SEPARATOR, MF_STRING, MSG, TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RETURNCMD,
        TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_DESTROY, WM_LBUTTONDBLCLK,
        WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WNDCLASSW, WS_OVERLAPPED,
    };

    const WM_TRAY_CALLBACK: u32 = WM_APP + 1;
    const WM_UPDATE_TIP: u32 = WM_APP + 2;
    const ID_SHOW: u32 = 1001;
    const ID_QUIT: u32 = 1002;
    const TRAY_UID: u32 = 1;

    struct TrayCtx {
        tx: mpsc::Sender<TrayEvent>,
        wake: Box<dyn Fn() + Send>,
        tip_shared: Arc<Mutex<String>>,
        taskbar_created: u32,
        nid: NOTIFYICONDATAW,
        owned_icon: bool,
    }

    thread_local! {
        static TRAY_CTX: RefCell<Option<TrayCtx>> = const { RefCell::new(None) };
    }

    pub struct Handle {
        hwnd: Arc<AtomicIsize>,
        tip_shared: Arc<Mutex<String>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Handle {
        pub fn set_tooltip(&self, text: &str) {
            if let Ok(mut guard) = self.tip_shared.lock() {
                *guard = text.to_string();
            }
            let raw = self.hwnd.load(Ordering::Acquire);
            if raw != 0 {
                unsafe {
                    PostMessageW(raw as HWND, WM_UPDATE_TIP, 0, 0);
                }
            }
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            let raw = self.hwnd.swap(0, Ordering::AcqRel);
            if raw != 0 {
                unsafe {
                    PostMessageW(raw as HWND, WM_CLOSE, 0, 0);
                }
            }
            if let Some(th) = self.thread.take() {
                let _ = th.join();
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn load_tray_icon(hinst: *mut core::ffi::c_void) -> (HICON, bool) {
        let name = wide("1");
        let h = LoadImageW(hinst, name.as_ptr(), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
        if !h.is_null() {
            return (h as HICON, true);
        }
        let by_id = LoadImageW(hinst, 1usize as *const u16, IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
        if !by_id.is_null() {
            return (by_id as HICON, true);
        }
        let fallback = LoadImageW(
            null_mut(),
            IDI_APPLICATION,
            IMAGE_ICON,
            0,
            0,
            LR_DEFAULTCOLOR | LR_SHARED,
        );
        (fallback as HICON, false)
    }

    unsafe fn show_menu(hwnd: HWND, tx: &mpsc::Sender<TrayEvent>, wake: &dyn Fn()) {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let open_lbl = wide("Показать окно");
        let quit_lbl = wide("Выход");
        AppendMenuW(menu, MF_STRING, ID_SHOW as usize, open_lbl.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        AppendMenuW(menu, MF_STRING, ID_QUIT as usize, quit_lbl.as_ptr());

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_BOTTOMALIGN,
            pt.x,
            pt.y,
            0,
            hwnd,
            null(),
        );
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);

        if cmd == ID_SHOW as i32 {
            let _ = tx.send(TrayEvent::Show);
            wake();
        } else if cmd == ID_QUIT as i32 {
            let _ = tx.send(TrayEvent::Quit);
            wake();
        }
    }

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let mut trigger_show = false;
        let mut trigger_menu = false;
        let mut handled = false;

        TRAY_CTX.with(|slot| {
            let mut borrow = slot.borrow_mut();
            let Some(ctx) = borrow.as_mut() else {
                return;
            };
            if msg == ctx.taskbar_created && ctx.taskbar_created != 0 {
                ctx.nid.hWnd = hwnd;
                Shell_NotifyIconW(NIM_ADD, &ctx.nid);
                handled = true;
            } else if msg == WM_UPDATE_TIP {
                let tip = ctx
                    .tip_shared
                    .lock()
                    .map(|g| g.clone())
                    .unwrap_or_else(|_| "Antigravity Unlocker".to_string());
                truncate_tip_utf16(&tip, &mut ctx.nid.szTip);
                Shell_NotifyIconW(NIM_MODIFY, &ctx.nid);
                handled = true;
            } else if msg == WM_TRAY_CALLBACK {
                let ev = lparam as u32;
                if matches!(ev, WM_LBUTTONUP | WM_LBUTTONDBLCLK | NIN_SELECT) {
                    trigger_show = true;
                } else if matches!(ev, WM_RBUTTONUP | WM_CONTEXTMENU) {
                    trigger_menu = true;
                }
                handled = true;
            } else if msg == WM_CLOSE {
                DestroyWindow(hwnd);
                handled = true;
            } else if msg == WM_DESTROY {
                Shell_NotifyIconW(NIM_DELETE, &ctx.nid);
                if ctx.owned_icon && !ctx.nid.hIcon.is_null() {
                    DestroyIcon(ctx.nid.hIcon);
                }
                PostQuitMessage(0);
                *borrow = None;
                handled = true;
            }
        });

        if trigger_show {
            TRAY_CTX.with(|slot| {
                if let Some(ctx) = slot.borrow().as_ref() {
                    let _ = ctx.tx.send(TrayEvent::Show);
                    (ctx.wake)();
                }
            });
        } else if trigger_menu {
            TRAY_CTX.with(|slot| {
                if let Some(ctx) = slot.borrow().as_ref() {
                    show_menu(hwnd, &ctx.tx, &*ctx.wake);
                }
            });
        }

        if handled {
            0
        } else {
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
    }

    pub fn spawn(tx: mpsc::Sender<TrayEvent>, wake: Box<dyn Fn() + Send>) -> Option<Handle> {
        let hwnd_slot = Arc::new(AtomicIsize::new(0));
        let tip_shared = Arc::new(Mutex::new("Antigravity Unlocker".to_string()));
        let hwnd_bg = Arc::clone(&hwnd_slot);
        let tip_bg = Arc::clone(&tip_shared);
        let (ready_tx, ready_rx) = mpsc::sync_channel::<bool>(1);

        let thread = std::thread::Builder::new()
            .name("ag-tray".to_string())
            .spawn(move || unsafe {
                let hinst = GetModuleHandleW(null());
                let class_name = wide("AgUnlockerTrayWindow");
                let wc = WNDCLASSW {
                    style: 0,
                    lpfnWndProc: Some(wndproc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinst,
                    hIcon: null_mut(),
                    hCursor: null_mut(),
                    hbrBackground: null_mut(),
                    lpszMenuName: null(),
                    lpszClassName: class_name.as_ptr(),
                };
                RegisterClassW(&wc);

                let (icon, owned_icon) = load_tray_icon(hinst);
                let taskbar_created = RegisterWindowMessageW(wide("TaskbarCreated").as_ptr());
                let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
                nid.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
                nid.uID = TRAY_UID;
                nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
                nid.uCallbackMessage = WM_TRAY_CALLBACK;
                nid.hIcon = icon;
                truncate_tip_utf16("Antigravity Unlocker", &mut nid.szTip);

                TRAY_CTX.with(|slot| {
                    *slot.borrow_mut() = Some(TrayCtx {
                        tx,
                        wake,
                        tip_shared: tip_bg,
                        taskbar_created,
                        nid,
                        owned_icon,
                    });
                });

                let hwnd = CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    class_name.as_ptr(),
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    null_mut(),
                    null_mut(),
                    hinst,
                    null(),
                );
                if hwnd.is_null() {
                    TRAY_CTX.with(|slot| *slot.borrow_mut() = None);
                    if owned_icon && !icon.is_null() {
                        DestroyIcon(icon);
                    }
                    let _ = ready_tx.send(false);
                    return;
                }
                TRAY_CTX.with(|slot| {
                    if let Some(ctx) = slot.borrow_mut().as_mut() {
                        ctx.nid.hWnd = hwnd;
                        Shell_NotifyIconW(NIM_ADD, &ctx.nid);
                    }
                });
                hwnd_bg.store(hwnd as isize, Ordering::Release);
                let _ = ready_tx.send(true);

                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            })
            .ok()?;

        match ready_rx.recv() {
            Ok(true) => Some(Handle {
                hwnd: hwnd_slot,
                tip_shared,
                thread: Some(thread),
            }),
            _ => {
                let _ = thread.join();
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tooltip_formats_and_truncates_utf16_safely() {
        assert_eq!(format_tooltip(None), "Antigravity Unlocker");
        assert_eq!(
            format_tooltip(Some("Модель ответила")),
            "Antigravity Unlocker — Модель ответила"
        );
        let long = "ф".repeat(200);
        let mut buf = [1u16; 128];
        truncate_tip_utf16(&long, &mut buf);
        assert_eq!(buf[127], 0);
        assert_eq!(buf[126], 'ф' as u16);
    }
}
