//! The window icon.
//!
//! `icon.ico` is already compiled into the exe as a Windows resource by
//! `build.rs`/winres — that is what File Explorer and the taskbar shortcut show.
//! The *window's* icon is a separate thing: winit sets it on the window class,
//! and with nothing supplied the title bar and Alt-Tab get a blank.
//!
//! The ICO's six layers are all PNG-compressed, and decoding PNG means an
//! inflate implementation — a dependency, for one 64×64 image. So the 64×64
//! layer is unpacked to raw RGBA once, at development time, and included as
//! bytes. `assets/icon_64.rgba` is 64·64·4 and is regenerated from `icon.ico`
//! whenever the icon changes; nothing decodes anything at runtime.

use eframe::egui;

const ICON_W: u32 = 64;
const ICON_H: u32 = 64;
const ICON_RGBA: &[u8] = include_bytes!("../../assets/icon_64.rgba");

/// The window icon, or `None` if the baked asset is not the size it claims.
///
/// Checked rather than trusted: a mismatched blob would have egui read past the
/// end of it, and `panic = "abort"` turns that into a window that never opens.
pub fn window_icon() -> Option<egui::IconData> {
    if ICON_RGBA.len() != (ICON_W * ICON_H * 4) as usize {
        return None;
    }
    Some(egui::IconData {
        rgba: ICON_RGBA.to_vec(),
        width: ICON_W,
        height: ICON_H,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_baked_icon_is_the_size_it_claims() {
        // Guards the regeneration step: an asset re-exported at another size
        // would otherwise fail silently, as a window with no icon.
        let icon = window_icon().expect("the icon asset must match ICON_W x ICON_H");
        assert_eq!(icon.width, ICON_W);
        assert_eq!(icon.height, ICON_H);
        assert_eq!(icon.rgba.len(), (ICON_W * ICON_H * 4) as usize);
        // A fully transparent blob would draw as nothing at all.
        assert!(
            icon.rgba.chunks_exact(4).any(|px| px[3] != 0),
            "the icon is entirely transparent"
        );
    }
}
