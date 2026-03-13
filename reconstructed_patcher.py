"""
Reconstructed source code of AG20260309.exe (Antigravity Patcher)
=================================================================
Author: Brent (t.me/nova_txt)
Original binary: AG20260309.exe (SHA256: b052dc9eba0c0dfa7cb69ebe6f1500b991936c71800525acc581baaa5b92860e)
Compiled with: Nuitka + Python 3.12 + GCC MinGW-W64 14.2.0
Build date: 2026.03.09

Reverse-engineered from __build_1.20.4.dll via:
  - Static string extraction (da-string / marshal format patterns)
  - IDA Pro 9.2 Hex-Rays decompilation
  - PE resource analysis, Nuitka payload extraction

Purpose: Patches the Electron-based "Antigravity" IDE (a Cursor/VS Code fork)
         by injecting JavaScript into main.js to bypass OAuth authentication
         and set userTier to "pro".

THIS FILE IS FOR SECURITY ANALYSIS/REPORT ONLY. DO NOT USE FOR SOFTWARE PIRACY.
"""

import os
import sys
import re
import json
import hashlib
import time
import ctypes
import base64
import zlib
import zipfile
import traceback
import io

# ─── Constants ───────────────────────────────────────────────────────────────

VERSION = "2026.03.09"
SUPPORTED_VERSIONS = ["1.20.4", "1.20.3", "1.19.6", "1.19.5"]
BACKUP_FILE = "backup.dat"
BACKUP_MAGIC = b"AGVBK"
PATCH_MARKER = ".ag_patched"
INTERNAL_CFG_SEED = "0XNFSC3WZC7J0088CE49180A"

# Embedded encrypted blob (~1500 chars base64). Contains the expected SHA256 hash
# for key verification and possibly additional configuration/localization data.
# Decoded via: b64decode → XOR decrypt (with INTERNAL_CFG_SEED) → zlib decompress → json.loads
_T_BLOB = (
    "..."  # ~1500 chars of base64 data embedded at 0x596a8c-0x597098 in binary
    # Exact content not fully extractable via static analysis
)

# ANSI color codes used in console output
GREEN = "\033[38;2;19;161;14m"
ORANGE = "\033[38;2;255;165;0m"
YELLOW = "\033[38;2;180;180;60m"
WARN = "\033[33m"
RESET = "\033[0m"

# ─── Localization ────────────────────────────────────────────────────────────

CURRENT_LANG = "RU"  # Global: set during language selection

LANG_RU = {
    "lang": "RU",
    "title": "=== ",                        # + section name + " ==="
    "prompt": "1. Русский\n2. English",
    "ok": "ok",
    "fail": "fail",
    "menu_not_found": "Приложение не найдено",    # reconstructed
    "status_unlocked": "Разблокировано",           # reconstructed
    "status_locked": "Заблокировано",              # reconstructed
    "menu_supported": "Поддерживаемые версии",     # reconstructed
    "menu_ver": "Версия",                          # reconstructed
    "menu_target": "Цель",                         # reconstructed
    "menu_status": "Статус",                       # reconstructed
    "menu_app_ver": "Версия приложения",           # reconstructed
    "menu_unknown": "Неизвестно",                  # reconstructed
    "opt_1": "Активировать",                       # reconstructed
    "opt_1_patched": "Уже активировано",           # reconstructed
    "opt_2_ava": "Создать бэкап",                  # reconstructed
    "opt_2_na": "Бэкап недоступен",                # reconstructed
    "opt_3": "Восстановить из бэкапа",             # reconstructed
    "opt_0": "Выход",                              # reconstructed
    "warn_admin": "Нет прав записи",               # reconstructed
    "err_path": "Путь не найден",                  # reconstructed
    "err_backup": "Ошибка создания бэкапа",        # reconstructed
    "err_restore": "Ошибка восстановления",        # reconstructed
    "msg_done": "Готово",                           # reconstructed
    "msg_success_final": "Успешно!",               # reconstructed
    "msg_patched": "Пропатчено",                   # reconstructed
    "msg_manual": "Укажите путь вручную",          # reconstructed
    "err_manual_path": "Некорректный путь",        # reconstructed
    "warn_partial": "Частичный патч",              # reconstructed
    "warn_restore_confirm": "Восстановить?",      # reconstructed
    "err_target": "Целевая функция не найдена",   # reconstructed
    "proc_backup": "Создание бэкапа...",           # reconstructed
    "proc_backup_ok": "Бэкап создан",             # reconstructed
    "proc_restore": "Восстановление...",           # reconstructed
    "proc_restore_ok": "Восстановлено",            # reconstructed
}

LANG_EN = {
    "lang": "EN",
    "title": "=== ",
    "prompt": "1. Русский\n2. English",
    "ok": "ok",
    "fail": "fail",
    "menu_not_found": "Application not found",
    "status_unlocked": "Unlocked",
    "status_locked": "Locked",
    "menu_supported": "Supported versions",
    "menu_ver": "Version",
    "menu_target": "Target",
    "menu_status": "Status",
    "menu_app_ver": "App version",
    "menu_unknown": "Unknown",
    "opt_1": "Activate",
    "opt_1_patched": "Already patched",
    "opt_2_ava": "Create backup",
    "opt_2_na": "Backup unavailable",
    "opt_3": "Restore from backup",
    "opt_0": "Exit",
    "warn_admin": "No write access",
    "err_path": "Path not found",
    "err_backup": "Backup creation error",
    "err_restore": "Restore error",
    "msg_done": "Done",
    "msg_success_final": "Success!",
    "msg_patched": "Patched",
    "msg_manual": "Enter path manually",
    "err_manual_path": "Invalid path",
    "warn_partial": "Partial patch",
    "warn_restore_confirm": "Restore?",
    "err_target": "Target function not found",
    "proc_backup": "Creating backup...",
    "proc_backup_ok": "Backup created",
    "proc_restore": "Restoring...",
    "proc_restore_ok": "Restored",
}

TRANSLATIONS = {
    "RU": LANG_RU,
    "EN": LANG_EN,
}

# ─── Paths structure ─────────────────────────────────────────────────────────

APP_ROOT = None
PATHS = {}   # {"root": ..., "core": ..., "app": ..., "out": ..., "config": ..., "meta": ...}


# ─── Console styling (Windows) ───────────────────────────────────────────────

def set_console_style():
    """Set console font to Consolas using Windows API (ctypes)."""
    try:
        LF_FACESIZE = 32

        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        class CONSOLE_FONT_INFOEX(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_ulong),
                ("nFont", ctypes.c_ulong),
                ("dwFontSize", COORD),
                ("FontFamily", ctypes.c_uint),
                ("FontWeight", ctypes.c_uint),
                ("FaceName", ctypes.c_wchar * LF_FACESIZE),
            ]

        font = CONSOLE_FONT_INFOEX()
        font.cbSize = ctypes.sizeof(CONSOLE_FONT_INFOEX)
        font.FaceName = "Consolas"

        handle = ctypes.windll.kernel32.GetStdHandle(ctypes.c_long(-11))  # STD_OUTPUT_HANDLE
        ctypes.windll.kernel32.SetCurrentConsoleFontEx(handle, False, ctypes.pointer(font))
    except Exception:
        pass


def clear_screen():
    """Clear terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


# ─── Installation detection ──────────────────────────────────────────────────

def find_install_root():
    """
    Find the Antigravity IDE installation directory.

    Search order:
      1. Windows Registry: HKCU/HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Antigravity
      2. %LOCALAPPDATA%\\Programs\\Antigravity
      3. %PROGRAMFILES%\\Antigravity
      4. %PROGRAMFILES(X86)%\\Antigravity
    """
    global APP_ROOT

    # 1. Try Windows Registry
    try:
        import winreg
        for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            try:
                key = winreg.OpenKey(
                    hive,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Antigravity"
                )
                install_location, _ = winreg.QueryValueEx(key, "InstallLocation")
                winreg.CloseKey(key)
                if install_location and os.path.isdir(install_location):
                    APP_ROOT = install_location
                    return APP_ROOT
            except (FileNotFoundError, OSError):
                continue
    except ImportError:
        pass

    # 2. Try common paths
    candidates = []
    localappdata = os.getenv("LOCALAPPDATA")
    if localappdata:
        candidates.append(os.path.join(localappdata, "Programs", "Antigravity"))

    programfiles = os.getenv("PROGRAMFILES")
    if programfiles:
        candidates.append(os.path.join(programfiles, "Antigravity"))

    programfiles_x86 = os.getenv("PROGRAMFILES(X86)")
    if programfiles_x86:
        candidates.append(os.path.join(programfiles_x86, "Antigravity"))

    for path in candidates:
        if os.path.isdir(path):
            APP_ROOT = path
            return APP_ROOT

    return None


def resolve_paths():
    """Resolve internal paths within the Antigravity installation."""
    global PATHS
    if not APP_ROOT:
        return False

    PATHS = {
        "root": APP_ROOT,
        "core": os.path.join(APP_ROOT, "resources"),  # Electron resources
        "app": os.path.join(APP_ROOT, "resources", "app"),
        "out": os.path.join(APP_ROOT, "resources", "app", "out"),
        "config": os.path.join(APP_ROOT, "resources", "app", "out", "main.js"),
        "meta": os.path.join(APP_ROOT, "resources", "app", "package.json"),
    }
    return True


def get_app_version():
    """Read the IDE version from product.json."""
    try:
        config_path = os.path.join(APP_ROOT, "resources", "app", "product.json")
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("ideVersion", data.get("version", "Unknown"))
    except Exception:
        # Fallback: try package.json
        try:
            meta_path = os.path.join(APP_ROOT, "resources", "app", "package.json")
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("version", "Unknown")
        except Exception:
            return "Unknown"


# ─── Access control ──────────────────────────────────────────────────────────

def _decode_t_blob():
    """
    Decode the embedded _T_BLOB data.

    Pipeline: base64 decode → XOR decrypt (INTERNAL_CFG_SEED) → zlib decompress → JSON loads.
    Returns a dict containing at minimum the expected SHA256 hash for key verification.
    """
    try:
        raw = base64.b64decode(_T_BLOB)
        decrypted = _crypt_buffer(raw)  # XOR with INTERNAL_CFG_SEED
        decompressed = zlib.decompress(decrypted)
        return json.loads(decompressed)
    except Exception:
        return {}


def verify_key(user_input: str) -> bool:
    """
    Verify the access key using SHA256.

    The key is validated by hashing (user_input + INTERNAL_CFG_SEED)
    and comparing the hex digest to the expected hash stored in _T_BLOB.
    """
    combined = user_input.strip().upper().replace("-", "")
    digest = hashlib.sha256((combined + INTERNAL_CFG_SEED).encode()).hexdigest()
    # Expected hash is decoded from the embedded _T_BLOB at runtime
    blob_data = _decode_t_blob()
    expected = blob_data.get("expected_hash", "")
    return digest == expected


# ─── Backup system ───────────────────────────────────────────────────────────

def _crypt_buffer(data: bytes, secret: bytes = INTERNAL_CFG_SEED.encode()) -> bytes:
    """
    Repeating-key XOR cipher for backup data encryption/decryption.
    Uses INTERNAL_CFG_SEED as the default XOR key.
    Symmetric: calling twice with the same key restores original data.
    """
    key_bytes = secret
    key_len = len(key_bytes)
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = b ^ key_bytes[i % key_len]
    return bytes(result)


def create_backup_archive():
    """
    Create a backup of the current main.js and related files.
    Saved as a zip archive with AGVBK magic header.
    """
    try:
        memory_buffer = io.BytesIO()
        with zipfile.ZipFile(memory_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, path in PATHS.items():
                if name in ("root", "core"):
                    continue
                if os.path.isfile(path):
                    relpath = os.path.relpath(path, PATHS["root"])
                    zf.write(path, relpath)

        zip_data = memory_buffer.getvalue()
        encrypted_data = _crypt_buffer(zip_data)

        backup_path = os.path.join(PATHS["root"], BACKUP_FILE)
        with open(backup_path, "wb") as f:
            f.write(BACKUP_MAGIC)
            f.write(encrypted_data)

        return True
    except Exception:
        return False


def restore_from_archive(custom_root=None):
    """Restore files from the AGVBK backup archive."""
    try:
        root_path = custom_root or PATHS["root"]
        backup_path = os.path.join(root_path, BACKUP_FILE)
        with open(backup_path, "rb") as f:
            header = f.read(len(BACKUP_MAGIC))
            if header != BACKUP_MAGIC:
                print(f"{ORANGE}[ERR] Invalid snapshot format.{RESET}")
                return False
            encrypted_data = f.read()

        # Decrypt: XOR with INTERNAL_CFG_SEED key (symmetric)
        decrypted_data = _crypt_buffer(encrypted_data)
        memory_buffer = io.BytesIO(decrypted_data)

        with zipfile.ZipFile(memory_buffer, "r") as zf:
            zf.extractall(root_path)

        # Remove patch marker
        out_path = PATHS.get("out", os.path.join(root_path, "resources", "app", "out"))
        marker_path = os.path.join(out_path, PATCH_MARKER)
        if os.path.exists(marker_path):
            os.remove(marker_path)

        return True
    except Exception:
        return False


# ─── Core patching logic ─────────────────────────────────────────────────────

def phase_1():
    """
    Patch main.js to bypass Antigravity IDE authentication.

    The patch:
      1. Finds the async authentication function via regex
         (looks for isGoogleInternal check pattern)
      2. Identifies dynamic variable names for internal services
         (loadCodeAssist, fire, pushUpdate)
      3. Injects JavaScript that:
         - Logs "[AG] auth ok" with [AG_BRENT] marker
         - Calls loadCodeAssist() to enable AI features
         - Fires fake oauthTokenInfo event
         - Calls onboardUser("standard-tier") / "free-tier"
         - Sets userTier to "pro"
         - Bypasses remaining original auth logic with early return
    """
    main_js_path = PATHS.get("config")
    if not main_js_path or not os.path.isfile(main_js_path):
        print(f"{ORANGE}[ERR] main.js not found.{RESET}")
        return False

    with open(main_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Track errors and state
    phase_errors = []
    success = False
    is_compiled = len(content) > 100000  # heuristic: minified/compiled JS is large

    print("[HACK] FORCE LOGIN")

    # ── Step 1: Find the authentication function ──
    # Regex to locate the auth function with isGoogleInternal check
    auth_pattern = re.compile(
        r'async\s+(?P<fname>[A-Za-z_$]+)\((?P<arg>[A-Za-z_$]+)\)\s*\{'
        r'[^{]*?if\(this\.(?P<vinternal>[A-Za-z_$]+)\.isGoogleInternal\)\s*\{'
        r'(?P<block>.*?return;?\}|.*?return;?\s*\})',
        re.DOTALL
    )

    auth_texts = list(auth_pattern.finditer(content))
    if not auth_texts:
        print("Could not find the authentication function.")
        phase_errors.append("err_target")
        return False

    # Use the first match (primary auth function)
    auth_match = auth_texts[0]
    target_info = {
        "match_count": len(auth_texts),
        "offset": auth_match.start(),
    }

    fname = auth_match.group("fname")
    arg = auth_match.group("arg")
    vinternal = auth_match.group("vinternal")
    block = auth_match.group("block")

    # ── Step 2: Find dynamic variable names ──
    # Find the service variable for loadCodeAssist
    svc_pattern = re.compile(r'this\.([a-zA-Z_$]+)\.loadCodeAssist')
    svc_match = svc_pattern.search(content)
    svc_m = svc_match.group(1) if svc_match else None

    # Find the event emitter variable for fire()
    emit_pattern = re.compile(r'this\.([a-zA-Z_$]+)\.fire')
    emit_match = emit_pattern.search(content)
    emit_m = emit_match.group(1) if emit_match else None

    # Find pushUpdate variable
    push_pattern1 = re.compile(r'([a-zA-Z_$]+)=([a-zA-Z_$]+)\(')
    push_pattern2 = re.compile(r'\);(?:this\.)?([a-zA-Z_$]+)\.pushUpdate\(\1\)')
    push_pattern3 = re.compile(r'(?:this\.)?([a-zA-Z_$]+)\.pushUpdate\([^,]+,\s*')

    if not svc_m or not emit_m:
        print(f"{ORANGE}[ERR] main.js patch failed. Structural mismatch.{RESET}")
        phase_errors.append("structural_mismatch")
        return False

    # ── Step 3: Build the injection payload ──
    # The token variable name comes from the regex match
    var_svc = svc_m
    var_emit = emit_m

    # Construct the state update prefix (pushUpdate calls)
    state_push_code = ""
    uss_match = push_pattern3.search(content)
    if uss_match:
        var_state_push = uss_match.group(1)
        state_push_code = (
            f"const _tk = {arg};\n"
            f"    try {{ this.{var_state_push}.pushUpdate(_tk); }} catch(_) {{}}\n"
            f"    try {{ this.{var_state_push}.pushUpdate(\"oauthTokenInfo\", {arg}); }} catch(_) {{}}\n"
        )

    # Main injection payload
    payload = (
        f'{{console.log("[AG] auth ok");/*[AG_BRENT]*/\n'
        f"{state_push_code}"
        f"try {{\n"
        f"    try {{ await this.{var_svc}.loadCodeAssist({arg}); }} catch(_) {{}}\n"
        f"    this.{var_emit}.fire({{oauthTokenInfo: {arg}}});\n"
        f'    try {{ await this.{var_svc}.onboardUser("standard-tier", {arg}); }} catch(_) {{\n'
        f'        try {{ await this.{var_svc}.onboardUser("free-tier", {arg}); }} catch(__) {{}}\n'
        f"    }}\n"
        f"    try {{\n"
        f'        let __res = {{ settings: {{}}, userTier: "pro" }};\n'
        f"        try {{ __res = await this.refreshUserStatus({arg}); }} catch(_) {{}}\n"
        f"        \n"
        f"        this.{var_emit}.fire({{ settings: __res.settings, userTier: __res.userTier, oauthTokenInfo: {arg} }});\n"
        f"    }} catch(_) {{}}\n"
        f"}} catch(e) {{\n"
        f"    this.{var_emit}.fire({{oauthTokenInfo: {arg}}});\n"
        f"}}\n"
        f"return; /* bypass remaining original logic */"
    )

    # ── Step 4: Inject the payload ──
    # Find the exact insertion point (the opening brace of the auth function body)
    original_match = auth_match.group(0)
    # Find where to insert: after the function signature opening brace
    brace_idx = original_match.index("{")
    safe_start = original_match[:brace_idx + 1]

    new_content = content.replace(
        original_match,
        safe_start + payload + "\n" + original_match[brace_idx + 1:]
    )

    # ── Step 5: Write patched file ──
    with open(main_js_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    # Create patch marker
    marker_path = os.path.join(PATHS["out"], PATCH_MARKER)
    with open(marker_path, "w") as f:
        f.write("")

    success = True
    print(f"{GREEN}Antigravity configured by Brent t.me/nova_txt{RESET}")
    print(f"Version: {VERSION}")

    return success


def check_write_access():
    """Test if we have write permissions in the target directory."""
    try:
        test_path = os.path.join(PATHS["out"], "test_perm.tmp")
        with open(test_path, "w") as f:
            f.write("ok")
        os.remove(test_path)
        return True
    except Exception:
        return False


# ─── UI / Menu ────────────────────────────────────────────────────────────────

def manual_path_selection(strings):
    """Allow user to manually specify the installation path."""
    global APP_ROOT
    print(strings["msg_manual"])
    path = input("> ").strip()
    if os.path.isdir(path):
        APP_ROOT = path
        resolve_paths()
        print(f"{GREEN}[OK]{RESET}")
        time.sleep(1)
    else:
        print(strings["err_manual_path"])


def get_base_dir():
    """Return the directory containing the running script/exe."""
    if getattr(sys, 'frozen', False) or sys.argv[0].endswith(".exe"):
        # Running as Nuitka-compiled exe
        return os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.dirname(os.path.abspath(__file__))


def init_globals():
    """Initialize global variables: SCRIPT_DIR, APP_ROOT, PATHS, TRANSLATIONS, CURRENT_LANG."""
    global SCRIPT_DIR
    SCRIPT_DIR = get_base_dir()


def login_screen():
    """Language selection and key verification screen."""
    global CURRENT_LANG

    # ── Language selection ──
    print("1. Русский")
    print("2. English")
    choice = input("> ").strip()
    CURRENT_LANG = "RU" if choice == "1" else "EN"
    strings = TRANSLATIONS[CURRENT_LANG]

    # ── Access check ──
    print(f"\n=== ACCESS CHECK ===")
    key = input("Enter key: ").strip()
    if verify_key(key):
        print("Access granted.")
    else:
        print("Access denied.")
        return

    # ── Find installation ──
    find_install_root()

    if not APP_ROOT:
        print(strings["menu_not_found"])
        manual_path_selection(strings)
        if not APP_ROOT:
            return

    resolve_paths()
    main_menu(strings)


def main():
    """Main entry point."""
    # Set console encoding and style
    os.system("chcp 65001 >nul")   # UTF-8 codepage
    os.system("color 0A")          # Green on black

    init_globals()
    set_console_style()
    login_screen()


def reload_paths(strings):
    """Refresh paths and version info."""
    resolve_paths()
    main_menu(strings)


def main_menu(strings):
    """Show menu and handle user actions."""
    phase_1_ok = False

    while True:
        clear_screen()

        # Show header
        app_ver = get_app_version()
        is_patched = os.path.exists(os.path.join(PATHS.get("out", ""), PATCH_MARKER))
        unlocked_status = strings["status_unlocked"] if is_patched else strings["status_locked"]
        ver_status = f"{app_ver} ({', '.join(SUPPORTED_VERSIONS)})"
        backup_exists = os.path.exists(os.path.join(PATHS.get("root", ""), BACKUP_FILE))

        print(f"{GREEN}")
        print("------------------------------------------------------------")
        print(f"  {strings['menu_ver']}: {VERSION}")
        print(f"  {strings['menu_target']}: Antigravity")
        print(f"  {strings['menu_status']}: {unlocked_status}")
        print(f"  {strings['menu_app_ver']}: {ver_status}")
        print("------------------------------------------------------------")

        # Check write access
        if not check_write_access():
            print(f"{WARN}[!] {strings['warn_admin']}{RESET}")

        # Menu options
        if is_patched:
            print(f"1. {strings['opt_1_patched']}")
        else:
            print(f"1. {strings['opt_1']}")

        if backup_exists:
            print(f"2. {strings['opt_2_ava']}")
        else:
            print(f"2. {strings['opt_2_na']}")

        if backup_exists:
            print(f"{YELLOW}3. {strings['opt_3']}{RESET}")
        else:
            print(f"3. {strings['opt_3']}")

        print(f"0. {strings['opt_0']}")
        print(f"{RESET}")

        choice = input("> ").strip()

        if choice == "1" and not is_patched:
            # Create backup first, then patch
            print(strings["proc_backup"])
            if create_backup_archive():
                print(f"{GREEN}{strings['proc_backup_ok']}{RESET}")
            else:
                print(f"{ORANGE}[!] {strings['err_backup']}{RESET}")

            # Apply patch
            process_level_1(strings)

        elif choice == "2":
            print(strings["proc_backup"])
            if create_backup_archive():
                print(f"{GREEN}{strings['proc_backup_ok']}{RESET}")
            else:
                print(f"{ORANGE}{strings['err_backup']}{RESET}")
            time.sleep(2)

        elif choice == "3" and backup_exists:
            print(strings["warn_restore_confirm"])
            confirm = input("> ").strip()
            if confirm.lower() in ("y", "д", "1"):
                print(strings["proc_restore"])
                if restore_from_archive():
                    print(f"{GREEN}{strings['proc_restore_ok']}{RESET}")
                else:
                    print(f"{ORANGE}{strings['err_restore']}{RESET}")
                time.sleep(2)

        elif choice == "0":
            break

        elif choice == "3":
            manual_path_selection(strings)


def process_level_1(strings):
    """Execute the patching process."""
    try:
        if phase_1():
            print(f"{GREEN}{strings['msg_success_final']}{RESET}")
        else:
            print(f"{ORANGE}[!] {strings['warn_partial']}{RESET}")
    except Exception:
        traceback.print_exc()
        print(f"{ORANGE}{strings['err_path']}{RESET}")

    print(strings["msg_done"])
    time.sleep(3)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()
