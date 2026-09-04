#!/usr/bin/env bash
# Antigravity Unlocker - macOS launcher.
#
# Runs as normal user. If no controlling terminal is attached (e.g. launched
# via Finder or .command), reopens itself in Terminal.app using AppleScript (osascript).
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/ag_unlocker"

# Also check parent directory if running from repository macos/ folder
if [ ! -f "$BIN" ] && [ -f "$DIR/../target/release/ag_unlocker" ]; then
    BIN="$DIR/../target/release/ag_unlocker"
elif [ ! -f "$BIN" ] && [ -f "$DIR/../ag_unlocker" ]; then
    BIN="$DIR/../ag_unlocker"
fi

if [ ! -f "$BIN" ]; then
    echo "Ошибка: исполняемый файл ag_unlocker не найден." >&2
    echo "Соберите проект: cargo build --release" >&2
    read -r -p "Нажмите Enter для выхода..." _ || true
    exit 1
fi

chmod +x "$BIN" 2>/dev/null || true
xattr -d com.apple.quarantine "$BIN" 2>/dev/null || true

# If stdout is not a terminal (e.g. double clicked in Finder), launch Terminal.app
if [ ! -t 1 ]; then
    osascript -e "tell application \"Terminal\" to do script \"exec '$BIN'\"" \
              -e "tell application \"Terminal\" to activate"
    exit 0
fi

exec "$BIN" "$@"
