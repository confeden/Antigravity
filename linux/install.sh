#!/usr/bin/env bash
# Installs AI Unlocker into the GNOME/KDE application menu, so from then
# on it launches with a normal double-click from Activities/the app grid - no
# terminal, no commands. Everything lands under the home dir; no root needed to
# install (root is asked for only at patch time, by the launcher).
set -eu

SRC="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/ag-unlocker"
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"

if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then
    echo 'Запустите установщик под своим пользователем, без sudo.' >&2
    exit 1
fi

mkdir -p "$APP_DIR" "$DESKTOP_DIR"
STAGE=$(mktemp -d "$APP_DIR/.install.XXXXXX")
DESKTOP_TMP=
trap 'rm -rf -- "$STAGE"; if [ -n "$DESKTOP_TMP" ]; then rm -f -- "$DESKTOP_TMP"; fi' EXIT
trap 'exit 1' HUP INT TERM
DESKTOP_TMP=$(mktemp "$DESKTOP_DIR/.ag-unlocker.XXXXXX")
install -m 0755 "$SRC/ag_unlocker" "$STAGE/ag_unlocker"
install -m 0755 "$SRC/launch.sh" "$STAGE/launch.sh"
"$STAGE/ag_unlocker" --version >/dev/null
ICON_LINE=""
if [ -f "$SRC/icon.png" ]; then
    install -m 0644 "$SRC/icon.png" "$STAGE/icon.png"
fi
if [ -f "$STAGE/icon.png" ] || [ -f "$APP_DIR/icon.png" ]; then
    ICON_LINE="Icon=$APP_DIR/icon.png"
fi

DESKTOP_FILE="$DESKTOP_DIR/ag-unlocker.desktop"
# Desktop Entry has its own quoting rules, including a second layer for Exec.
EXEC_PATH=$(printf '%s' "$APP_DIR/launch.sh" | sed -e 's/\\/\\\\\\\\/g' -e 's/["`$]/\\\\&/g' -e 's/%/%%/g')
cat >"$DESKTOP_TMP" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=AI Unlocker
Comment=Разблокировать Antigravity 2.0 / IDE / CLI
Exec=bash "$EXEC_PATH"
$ICON_LINE
Terminal=false
Categories=Utility;
StartupNotify=false
EOF
chmod 0644 "$DESKTOP_TMP"
mv -fT "$STAGE/launch.sh" "$APP_DIR/launch.sh"
if [ -f "$STAGE/icon.png" ]; then
    mv -fT "$STAGE/icon.png" "$APP_DIR/icon.png"
fi
mv -fT "$DESKTOP_TMP" "$DESKTOP_FILE"
mv -fT "$STAGE/ag_unlocker" "$APP_DIR/ag_unlocker"

# Mark trusted where the toolkit supports it, and refresh the menu database.
gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

if [ "${1:-}" = --update ]; then
    exit 0
fi

echo
echo "Готово. «AI Unlocker» добавлен в меню приложений."
echo "Запускайте его двойным кликом из списка программ (Activities / app grid)."
echo
if [ -t 0 ]; then
    read -r -p "Нажмите Enter для выхода..." _ || true
fi
