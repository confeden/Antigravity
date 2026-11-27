#!/usr/bin/env bash
# AI Unlocker - Linux launcher.
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
# graphical session to draw into. With none, a terminal still gets the whole
# program as the terminal UI (the binary picks it by itself - `--tui` is only
# said here to be plain about it); with neither, it says so.

# Started as `sh launch.sh`: on Debian/Ubuntu sh is dash, which stops at the
# first bash-only line below. POSIX up to here, so dash can hand over.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi
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
            zenity --error --no-markup --title="AI Unlocker" --text="$1" 2>/dev/null
        elif command -v kdialog >/dev/null 2>&1; then
            kdialog --error "$1" 2>/dev/null
        elif command -v xmessage >/dev/null 2>&1; then
            xmessage -center "$1" 2>/dev/null
        fi
    else
        read -r -p "Нажмите Enter для выхода..." _ || true
    fi
}

# As the user, never through sudo. Root has no key to the user's X/Wayland
# session («Authorization required, but no authorization protocol specified»),
# and everything this tool touches - the installs under ~/.local/share, the
# systemd user unit, ~/.config/environment.d - is the user's: as root it would
# look for Antigravity in root's home and set the proxy up for root. A server
# where root *is* the user (no SUDO_USER) is fine.
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    say_error "Запускайте без sudo: bash launch.sh
Под root программа не видит ваш рабочий стол и искала бы Antigravity
в домашней папке root, а не $SUDO_USER. Права root ей не нужны."
    exit 1
fi

if [ ! -f "$BIN" ]; then
    say_error "Не найден файл программы: $BIN
Распакуйте архив целиком и запустите launch.sh из распакованной папки."
    exit 1
fi

# A folder the program cannot run from: a VM share or a Windows (NTFS/FAT)
# drive mounted noexec, or an archive unpacked by something that dropped the
# permissions - chmod cannot help on the first two, and asking the user for a
# command is what this script is for avoiding. Run a copy from the home folder
# instead, where both always work. `--version` answers and exits at once.
if ! "$BIN" --version >/dev/null 2>&1; then
    HOME_BIN="${XDG_DATA_HOME:-$HOME/.local/share}/agunlocker/ag_unlocker"
    if mkdir -p "$(dirname "$HOME_BIN")" \
        && cp -f "$BIN" "$HOME_BIN.new" \
        && chmod +x "$HOME_BIN.new" \
        && mv -f "$HOME_BIN.new" "$HOME_BIN" \
        && "$HOME_BIN" --version >/dev/null 2>&1; then
        BIN="$HOME_BIN"
    else
        say_error "Программа не запускается ни отсюда, ни из домашней папки: $BIN
Нужен 64-битный Linux (x86-64)."
        exit 1
    fi
fi

# No X11 and no Wayland means no window. In a terminal (a server over SSH) the
# same program runs as a terminal UI; double-clicked with neither, say so rather
# than let the binary fail somewhere inside winit with a message nobody sees.
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    if [ -t 0 ] && [ -t 1 ]; then
        exec "$BIN" --tui "$@"
    fi
    say_error "Нет графической сессии (не заданы DISPLAY и WAYLAND_DISPLAY).
Запустите из терминала: $BIN --tui"
    exit 1
fi

exec "$BIN" "$@"
