#!/bin/sh
# AI Unlocker — терминальный режим одной командой (Linux x86-64):
#
#   curl -fsSL https://raw.githubusercontent.com/confeden/Antigravity/main/tui.sh | sh
#
# Устанавливает последний релиз в профиль пользователя и открывает TUI.
set -eu

REPO="confeden/Antigravity"
DIR="${XDG_DATA_HOME:-$HOME/.local/share}/ag-unlocker"
BIN="$DIR/ag_unlocker"
UPDATED=

case "$(uname -m)" in
    x86_64 | amd64) ;;
    *)
        echo "AI Unlocker собран только для x86-64, а здесь $(uname -m)." >&2
        exit 1
        ;;
esac

# The newest tag from where /releases/latest redirects to: no API call, so no
# rate limit on a server sharing its address with a hundred others.
TAG=""
if URL=$(curl -fsSILo /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest"); then
    TAG="${URL##*/}"
fi
VER="${TAG#[vV]}"

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
        CURRENT=
        if [ -x "$BIN" ]; then
            CURRENT=$("$BIN" --version | sed -n 's/^version: //p')
        fi
        if awk -v current="$CURRENT" -v latest="$VER" 'BEGIN {
            split(current, a, /[._]/); split(latest, b, /[._]/)
            for (i=1; i<=4; i++) {
                if (a[i]+0 != b[i]+0) exit (a[i]+0 > b[i]+0)
            }
            exit 1
        }'; then
            echo "Устанавливаю AI Unlocker $VER…" >&2
            TMP=$(mktemp -d)
            trap 'rm -rf "$TMP"' EXIT
            # The tag spells a fourth number with a dot (v2.24.0.1), the asset with
            # an underscore (AG_2.24.0_1_linux.tar.gz): try both.
            ALT=$(printf '%s\n' "$VER" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)$/\1_\2/; t; s/_/./')
            NAME=""
            for cand in "$VER" "$ALT"; do
                if curl -fsIL "https://github.com/$REPO/releases/download/$TAG/AG_${cand}_linux.tar.gz" >/dev/null 2>&1; then
                    NAME="$cand"
                    break
                fi
            done
            if [ -z "$NAME" ]; then
                echo "В релизе $TAG нет сборки для Linux." >&2
                exit 1
            fi
            curl -fsSL "https://github.com/$REPO/releases/download/$TAG/AG_${NAME}_linux.tar.gz" -o "$TMP/setup.tar.gz"
            tar -xzf "$TMP/setup.tar.gz" -C "$TMP"
            bash "$TMP/AG_${NAME}_linux/install.sh" --update </dev/null
            UPDATED=--updated
            rm -rf "$TMP"
            trap - EXIT
        fi
        ;;
esac

# `curl … | sh` hands this script to sh on stdin; the program's keys come from
# the terminal itself.
if [ -n "$UPDATED" ]; then
    exec "$BIN" --tui "$UPDATED" </dev/tty
fi
exec "$BIN" --tui </dev/tty
