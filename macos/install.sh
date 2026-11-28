#!/bin/sh
set -eu

SRC=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DEST="$HOME/Applications"
APP="$DEST/AI Unlocker.app"
if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then
    echo 'Запустите установщик под своим пользователем, без sudo.' >&2
    exit 1
fi

mkdir -p "$DEST"
STAGE=$(mktemp -d "$DEST/.ai-unlocker.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
trap 'exit 1' HUP INT TERM
NEW="$STAGE/AI Unlocker.app"
mkdir -p "$NEW/Contents/MacOS"
install -m 0755 "$SRC/ag_unlocker" "$NEW/Contents/MacOS/ag_unlocker"
install -m 0644 "$SRC/Info.plist" "$NEW/Contents/Info.plist"
# A linker-signed standalone executable has no sealed bundle resources yet.
# Sign the assembled bundle before verifying its resource envelope.
/usr/bin/codesign --force --sign - "$NEW"
/usr/bin/codesign --verify --strict "$NEW"
if /usr/bin/xattr -p com.apple.quarantine "$NEW/Contents/MacOS/ag_unlocker" >/dev/null 2>&1; then
    /usr/bin/xattr -d com.apple.quarantine "$NEW/Contents/MacOS/ag_unlocker"
fi
"$NEW/Contents/MacOS/ag_unlocker" --install-macos-bundle

if [ "${1:-}" != --update ]; then
    /usr/bin/open "$APP" --args --updated
fi
