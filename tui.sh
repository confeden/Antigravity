#!/bin/sh
# Antigravity Unlocker — терминальный режим одной командой (Linux x86-64):
#
#   curl -fsSL https://raw.githubusercontent.com/confeden/Antigravity/main/tui.sh | sh
#
# Берёт последний релиз с GitHub, кладёт программу в
# ~/.local/share/agunlocker/ и запускает её в этом терминале. Повторный запуск
# той же командой скачивает заново, только если вышла новая версия. Без root.
set -eu

REPO="SatoKazuma1/Antigravity"
DIR="${XDG_DATA_HOME:-$HOME/.local/share}/agunlocker"
BIN="$DIR/ag_unlocker"

case "$(uname -m)" in
    x86_64 | amd64) ;;
    *)
        echo "Antigravity Unlocker собран только для x86-64, а здесь $(uname -m)." >&2
        exit 1
        ;;
esac

# The newest tag from where /releases/latest redirects to: no API call, so no
# rate limit on a server sharing its address with a hundred others.
TAG=""
if URL=$(curl -fsSLo /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest"); then
    TAG="${URL##*/}"
fi
VER="${TAG#v}"

case "$VER" in
    "" | *[!0-9._]*)
        if [ -x "$BIN" ]; then
            echo "GitHub не ответил — запускаю уже скачанную версию." >&2
        else
            echo "Не удалось узнать последнюю версию на github.com/$REPO." >&2
            exit 1
        fi
        ;;
    *)
        if [ ! -x "$BIN" ] || [ "$(cat "$BIN.version" 2>/dev/null)" != "$VER" ]; then
            echo "Скачиваю Antigravity Unlocker $VER…" >&2
            mkdir -p "$DIR"
            TMP=$(mktemp -d)
            trap 'rm -rf "$TMP"' EXIT
            curl -fsSL "https://github.com/$REPO/releases/download/$TAG/antigravity-unlocker-linux-x86_64.tar.gz" |
                tar xz -C "$TMP"
            mv -f "$TMP/antigravity-unlocker-linux-x86_64/ag_unlocker" "$BIN"
            chmod +x "$BIN"
            echo "$VER" >"$BIN.version"
            rm -rf "$TMP"
            trap - EXIT
        fi
        ;;
esac

# `curl … | sh` hands this script to sh on stdin; the program's keys come from
# the terminal itself.
exec "$BIN" --tui </dev/tty
