#!/usr/bin/env bash
# Installs Antigravity Unlocker into the GNOME/KDE application menu, so from then
# on it launches with a normal double-click from Activities/the app grid - no
# terminal, no commands. Everything lands under the home dir; no root needed to
# install (root is asked for only at patch time, by the launcher).
set -eu

SRC="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/ag-unlocker"
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"

mkdir -p "$APP_DIR" "$DESKTOP_DIR"
install -m 0755 "$SRC/ag_unlocker" "$APP_DIR/ag_unlocker"
install -m 0755 "$SRC/launch.sh" "$APP_DIR/launch.sh"
ICON_LINE=""
if [ -f "$SRC/icon.png" ]; then
    install -m 0644 "$SRC/icon.png" "$APP_DIR/icon.png"
    ICON_LINE="Icon=$APP_DIR/icon.png"
fi

DESKTOP_FILE="$DESKTOP_DIR/ag-unlocker.desktop"
cat >"$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Antigravity Unlocker
Comment=Разблокировать Antigravity 2.0 / IDE / CLI
Exec=$APP_DIR/launch.sh
$ICON_LINE
Terminal=false
Categories=Utility;Development;
StartupNotify=false
EOF
chmod +x "$DESKTOP_FILE"

# Mark trusted where the toolkit supports it, and refresh the menu database.
gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

echo
echo "Готово. «Antigravity Unlocker» добавлен в меню приложений."
echo "Запускайте его двойным кликом из списка программ (Activities / app grid)."
echo
read -r -p "Нажмите Enter для выхода..." _ || true
