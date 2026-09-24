use tray_icon::{
    menu::{Menu, MenuId, MenuItem, PredefinedMenuItem},
    TrayIcon, TrayIconBuilder,
};

pub struct TrayHandler {
    #[cfg(windows)]
    #[allow(dead_code)]
    pub tray: Option<TrayIcon>,
    pub open_id: MenuId,
    pub enable_id: MenuId,
    pub flush_id: MenuId,
    pub quit_id: MenuId,
}

#[cfg(target_os = "linux")]
fn is_appindicator_available() -> bool {
    let candidates: &[&[u8]] = &[
        b"libayatana-appindicator3.so.1\0",
        b"libappindicator3.so.1\0",
        b"libayatana-appindicator3.so\0",
        b"libappindicator3.so\0",
    ];
    for name in candidates {
        unsafe {
            let handle = libc::dlopen(name.as_ptr() as *const libc::c_char, libc::RTLD_LAZY | libc::RTLD_LOCAL);
            if !handle.is_null() {
                libc::dlclose(handle);
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
pub fn create_tray() -> Option<TrayHandler> {
    if !is_appindicator_available() {
        return None;
    }

    let icon = super::icon::tray_icon()?;
    let (tx, rx) = std::sync::mpsc::channel();

    // On Linux with winit/eframe, GTK is not initialized by default.
    // Run GTK and AppIndicator in a dedicated thread with its own GLib/GTK event loop
    // so menu clicks and DBus signals are dispatched without blocking or depending on winit.
    std::thread::Builder::new()
        .name("gtk-tray".into())
        .spawn(move || {
            if gtk::init().is_err() {
                let _ = tx.send(None);
                return;
            }

            let menu = Menu::new();

            let open_item = MenuItem::new("Показать окно", true, None);
            let open_id = open_item.id().clone();
            let enable_item = MenuItem::new("Включить всё", true, None);
            let enable_id = enable_item.id().clone();
            let flush_item = MenuItem::new("Сбросить DNS-кэш", true, None);
            let flush_id = flush_item.id().clone();
            let quit_item = MenuItem::new("Выход", true, None);
            let quit_id = quit_item.id().clone();

            let _ = menu.append(&open_item);
            let _ = menu.append(&enable_item);
            let _ = menu.append(&flush_item);
            let _ = menu.append(&PredefinedMenuItem::separator());
            let _ = menu.append(&quit_item);

            let tray = match TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("Antigravity Unlocker")
                .with_icon(icon)
                .build()
            {
                Ok(t) => t,
                Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
            };

            let _ = tx.send(Some((open_id, enable_id, flush_id, quit_id)));

            // Keep tray icon alive on this thread and process GTK / AppIndicator DBus events
            let _keep_alive = tray;
            gtk::main();
        })
        .ok()?;

    let (open_id, enable_id, flush_id, quit_id) = rx.recv().ok()??;

    Some(TrayHandler {
        open_id,
        enable_id,
        flush_id,
        quit_id,
    })
}

#[cfg(windows)]
pub fn create_tray() -> Option<TrayHandler> {
    let icon = super::icon::tray_icon()?;
    let menu = Menu::new();

    let open_item = MenuItem::new("Показать окно", true, None);
    let open_id = open_item.id().clone();
    let enable_item = MenuItem::new("Включить всё", true, None);
    let enable_id = enable_item.id().clone();
    let flush_item = MenuItem::new("Сбросить DNS-кэш", true, None);
    let flush_id = flush_item.id().clone();
    let quit_item = MenuItem::new("Выход", true, None);
    let quit_id = quit_item.id().clone();

    menu.append(&open_item).ok()?;
    menu.append(&enable_item).ok()?;
    menu.append(&flush_item).ok()?;
    menu.append(&PredefinedMenuItem::separator()).ok()?;
    menu.append(&quit_item).ok()?;

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Antigravity Unlocker")
        .with_icon(icon)
        .build()
        .ok()?;

    Some(TrayHandler {
        tray: Some(tray),
        open_id,
        enable_id,
        flush_id,
        quit_id,
    })
}
