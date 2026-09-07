#!/usr/bin/env bash
# Antigravity Unlocker - Linux launcher.
#
# Runs as the normal user - NO sudo. The phase-2 region route is entirely
# unprivileged: the language server that carries the gate lives in
# ~/.local/share (user-writable), the local proxy is a systemd *user* unit, and
# AG_LS_PROXY is a user drop-in. That is also what makes "right-click > Run as a
# Program" work without a password prompt. A system-wide /opt install would need
# root to patch, but the per-user copy is the one the app actually runs.
#
# Since 2.12.2 the tool IS a window (eframe/egui) - there is no numbered menu any
# more. So this script no longer reopens itself inside a terminal emulator: that
# would put an empty black window behind the real one, and on a box with no
# terminal emulator installed the old fallback ("hope stdout is visible") left
# the user with nothing at all. What it does instead is check that there is a
# graphical session to draw into, and say so plainly when there is not.
set -u

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(cd "$(dirname "$SELF")" && pwd)"
BIN="$DIR/ag_unlocker"
chmod +x "$BIN" 2>/dev/null || true

# Anything this script has to say goes to the terminal when there is one, and to
# a desktop dialog when there is not - a double-click has nowhere to print.
say_error() {
    printf '%s\n' "$1" >&2
    if [ ! -t 2 ]; then
        if command -v zenity >/dev/null 2>&1; then
            zenity --error --no-markup --title="Antigravity Unlocker" --text="$1" 2>/dev/null
        elif command -v kdialog >/dev/null 2>&1; then
            kdialog --error "$1" 2>/dev/null
        elif command -v xmessage >/dev/null 2>&1; then
            xmessage -center "$1" 2>/dev/null
        fi
    else
        read -r -p "Нажмите Enter для выхода..." _ || true
    fi
}

if [ ! -x "$BIN" ]; then
    say_error "Не найден исполняемый файл: $BIN

Если папка лежит на общей шаре VM (/mnt/hgfs, /media/sf_*), скопируйте её
в домашнюю папку — оттуда запуск невозможен (монтируется с noexec)."
    exit 1
fi

# No X11 and no Wayland means no window. Better to say that than to let the
# binary fail somewhere inside winit with a message nobody sees.
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    say_error "Нет графической сессии (не заданы DISPLAY и WAYLAND_DISPLAY).
Antigravity Unlocker — это окно; запустите его из графического сеанса."
    exit 1
fi

exec "$BIN" "$@"
