#!/usr/bin/env bash
# Uninstalls Antigravity Unlocker from user directory and desktop applications.
set -eu

APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/ag-unlocker"
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
DESKTOP_FILE="$DESKTOP_DIR/ag-unlocker.desktop"

echo "Удаление Antigravity Unlocker..."
rm -rf "$APP_DIR"
rm -f "$DESKTOP_FILE"

update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

echo
echo "Готово. Antigravity Unlocker полностью удалён."
echo
