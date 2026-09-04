#!/usr/bin/env bash
# Antigravity Unlocker - универсальный скрипт установки «в один клик» для macOS
# Автоматически:
# 1. Проверяет и при необходимости устанавливает Xcode Command Line Tools и Rust.
# 2. Собирает проект в --release.
# 3. Устанавливает утилиту в ~/Library/Application Support/ag-unlocker.
# 4. Создает запускаемый ярлык ~/Applications/Antigravity Unlocker.command.
# 5. Снимает атрибуты карантина Gatekeeper и предлагает немедленный запуск.
set -euo pipefail

echo
echo "============================================================"
echo "    Установка Antigravity Unlocker для macOS"
echo "============================================================"
echo

# 1. Определение каталога с исходным кодом
REPO_DIR=""
CLEANUP_TMP=false

if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SRC/../Cargo.toml" ]; then
        REPO_DIR="$(cd "$SRC/.." && pwd)"
    elif [ -f "$SRC/Cargo.toml" ]; then
        REPO_DIR="$SRC"
    fi
fi

if [ -z "$REPO_DIR" ] && [ -f "./Cargo.toml" ]; then
    REPO_DIR="$(pwd)"
fi

if [ -z "$REPO_DIR" ]; then
    echo "[1/4] Загрузка исходного кода из репозитория..."
    TMP_DIR="$(mktemp -d /tmp/antigravity_build.XXXXXX)"
    git clone --depth 1 https://github.com/Mysechka/AntigravityMacOsTest.git "$TMP_DIR"
    REPO_DIR="$TMP_DIR"
    CLEANUP_TMP=true
else
    echo "[1/4] Исходный код найден: $REPO_DIR"
fi

# 2. Проверка базовых инструментов сборки (Xcode Command Line Tools)
if ! xcode-select -p >/dev/null 2>&1; then
    echo
    echo "[!] Xcode Command Line Tools не обнаружены. Запускаем установку..."
    xcode-select --install || true
    echo "Пожалуйста, подтвердите установку в появившемся окне macOS."
    echo "После завершения установки инструментов запустите этот скрипт снова."
    exit 1
fi

# 3. Проверка и автоматическая установка Rust / Cargo
if ! command -v cargo >/dev/null 2>&1; then
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env"
    fi
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "[2/4] Установка компилятора Rust (rustup)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
else
    echo "[2/4] Компилятор Rust уже установлен: $(cargo --version)"
fi

# 4. Сборка исполняемого файла
echo "[3/4] Сборка оптимизированной версии (cargo build --release)..."
(cd "$REPO_DIR" && cargo build --release)

BIN="$REPO_DIR/target/release/ag_unlocker"
if [ ! -f "$BIN" ]; then
    echo "[-] Ошибка: исполняемый файл $BIN не был создан." >&2
    exit 1
fi

# 5. Установка файлов в систему пользователя
echo "[4/4] Инсталляция файлов..."
APP_DIR="$HOME/Library/Application Support/ag-unlocker"
mkdir -p "$APP_DIR" "$HOME/Applications"

cp -f "$BIN" "$APP_DIR/ag_unlocker"
chmod 0755 "$APP_DIR/ag_unlocker"
xattr -d com.apple.quarantine "$APP_DIR/ag_unlocker" 2>/dev/null || true

# Снятие карантина и ad-hoc подпись установленных приложений Antigravity (обход блокировок Gatekeeper и краша ARM64)
for app in "/Applications/Antigravity IDE.app" "/Applications/Antigravity.app" "$HOME/Applications/Antigravity IDE.app" "$HOME/Applications/Antigravity.app"; do
    if [ -d "$app" ]; then
        xattr -dr com.apple.quarantine "$app" 2>/dev/null || true
        codesign --force --deep -s - "$app" 2>/dev/null || true
    fi
done

# Скрипт запуска
if [ -f "$REPO_DIR/macos/launch.sh" ]; then
    cp -f "$REPO_DIR/macos/launch.sh" "$APP_DIR/launch.sh"
else
    cat >"$APP_DIR/launch.sh" << 'EOF'
#!/usr/bin/env bash
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/ag_unlocker"
chmod +x "$BIN" 2>/dev/null || true
xattr -d com.apple.quarantine "$BIN" 2>/dev/null || true
if [ ! -t 1 ]; then
    osascript -e "tell application \"Terminal\" to do script \"exec '$BIN'\"" \
              -e "tell application \"Terminal\" to activate"
    exit 0
fi
exec "$BIN" "$@"
EOF
fi
chmod 0755 "$APP_DIR/launch.sh"
xattr -d com.apple.quarantine "$APP_DIR/launch.sh" 2>/dev/null || true

# Создание ярлыка в ~/Applications
WRAPPER="$HOME/Applications/Antigravity Unlocker.command"
cat >"$WRAPPER" <<EOF
#!/usr/bin/env bash
exec "$APP_DIR/launch.sh" "\$@"
EOF
chmod 0755 "$WRAPPER"
xattr -d com.apple.quarantine "$WRAPPER" 2>/dev/null || true

# Очистка временного каталога при установке через curl
if [ "$CLEANUP_TMP" = true ]; then
    rm -rf "$REPO_DIR"
fi

echo
echo "============================================================"
echo " [OK] Antigravity Unlocker успешно собран и установлен!"
echo "============================================================"
echo "  • Исполняемый файл: $APP_DIR/ag_unlocker"
echo "  • Ярлык для запуска: $WRAPPER"
echo "    (можно запускать двойным кликом из папки «Программы»)"
echo "============================================================"
echo

read -r -p "Запустить Antigravity Unlocker прямо сейчас? [Y/n]: " choice
case "${choice:-Y}" in
    [nN][oO]|[nN])
        echo
        echo "Для запуска в любое время откройте ярлык в папке «Программы»"
        echo "или выполните в Терминале: \"$APP_DIR/launch.sh\""
        echo
        ;;
    *)
        exec "$APP_DIR/launch.sh"
        ;;
esac
