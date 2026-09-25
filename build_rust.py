import json
import os
import re
import shutil
import subprocess
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Must match src\auth.rs (LICENSE_VERSION_SEP): the license key is derived from
# base_secret + SEP + version, so keys are unique per release.
LICENSE_VERSION_SEP = "::"


def read_canary_const(name, canary_rs_path=r"src\canary.rs"):
    """Reads a committed const out of src/canary.rs. Same single-source-of-truth
    trick as read_base_secret, so build.rs, the binary, this script and
    tools/canary_check.py cannot drift apart."""
    with open(canary_rs_path, 'r', encoding='utf-8') as f:
        src = f.read()
    m = re.search(r'pub const %s: &str = "([^"]*)"' % re.escape(name), src)
    if not m:
        raise RuntimeError("%s not found in %s" % (name, canary_rs_path))
    return m.group(1)


def release_token(version):
    """Must match canary::token_for() in Rust and token_for() in build.rs."""
    import hashlib
    seed = read_canary_const("CANARY_SEED")
    sep = read_canary_const("CANARY_SEP")
    d = hashlib.sha256((seed + sep + version).encode('utf-8')).hexdigest().upper()
    return "AGU-%s-%s-%s" % (d[0:5], d[5:10], d[10:15])


def record_canary(version, token, exe_path):
    """Appends this release to CANARIES.md.

    The token is derivable from the sources, so the ledger is a convenience, not
    a secret. Its value is being a dated, committed record of which token belongs
    to which release and which binary hash - i.e. the thing you would actually
    put in front of someone. It therefore lives at the repo root, NOT under
    release/, which is gitignored and would never be committed."""
    import hashlib
    try:
        with open(exe_path, 'rb') as f:
            sha = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        sha = "(unavailable)"

    ledger = "CANARIES.md"
    row = "| %s | `%s` | `%s` | `%s` |\n" % (
        version, token, read_canary_const("STATIC_CANARY"), sha)

    if not os.path.exists(ledger):
        header = (
            "# Release canaries\n\n"
            "Provenance record for every published build. See `src/canary.rs`\n"
            "for what these are and `tools/canary_check.py` for how to scan a\n"
            "suspect file against them. Tokens are derived from the committed\n"
            "seed, so this table is reproducible - it exists so the mapping is\n"
            "dated and committed rather than recomputed after the fact.\n\n"
            "| version | release token | static canary | sha256 of the .exe |\n"
            "|---|---|---|---|\n"
        )
        with open(ledger, 'w', encoding='utf-8') as f:
            f.write(header + row)
        return ledger

    with open(ledger, 'r', encoding='utf-8') as f:
        content = f.read()
    if "| %s |" % version in content:
        # Rebuild of an already-recorded version: refresh its row in place so the
        # hash matches the binary that actually shipped.
        content = re.sub(r'^\| %s \|.*$' % re.escape(version), row.rstrip('\n'),
                         content, flags=re.M)
        with open(ledger, 'w', encoding='utf-8') as f:
            f.write(content)
    else:
        with open(ledger, 'a', encoding='utf-8') as f:
            f.write(row)
    return ledger


# Build caches.
#
# The release profile is the slow part - fat LTO over ~300 crates into a single
# codegen unit - and this script used to end every run with `cargo clean`, so
# every build started from nothing. The caches are kept now, and pruned so they
# cannot grow: whatever the next build can reuse stays, whatever it cannot goes.
#
# A release cache - target\release for Windows, LINUX_CACHE for the Linux build -
# is pruned right after a build that SUCCEEDED, down to exactly the units that
# build used. Liveness is read, not guessed: timestamps cannot say it, because cargo
# touches nothing it finds fresh. cargo's JSON messages can - they report every
# unit the build used, fresh or rebuilt, and name its files, which carry the same
# 16-hex unit hash as the unit's build/ and .fingerprint/ directories. That naming
# is cargo's internals rather than a promise, so it is checked on every run: if
# any unit the build just used has no .fingerprint directory under its hash,
# nothing is deleted. A cache that stops shrinking is a nuisance; one pruned wrong
# makes every next build cold again, which is the thing this exists to prevent.
# A failed or interrupted build prunes nothing - half a build proves nothing about
# what is dead.
CARGO_JSON = "--message-format=json-render-diagnostics"

# `libregex-<hash>.rlib`, `build/regex-<hash>/`, `.fingerprint/regex-<hash>/`.
_UNIT_HASH = re.compile(r"-([0-9a-f]{16})(?=\.|$)")

# The rest of target\ belongs to cargo test, cargo check and rust-analyzer; a unit
# none of them has used for this long is deleted (prune_dev_cache).
DEV_CACHE_KEEP_DAYS = 14


def _unit_hash(name):
    found = _UNIT_HASH.findall(name)
    return found[-1] if found else None


def _package_name(package_id):
    """`path+file:///D:/x/Unlocker#ag_unlocker@2.13.0` -> `ag_unlocker`. The spec
    leaves the name out when it matches the directory (`.../ag_unlocker#2.13.0`)."""
    url, _, fragment = package_id.partition("#")
    if "@" in fragment:
        return fragment.split("@", 1)[0]
    return url.rstrip("/").rsplit("/", 1)[-1]


class BuildReport:
    """What cargo's JSON messages say about one build: the units it used, fresh or
    rebuilt, per profile directory, and where it put the executables."""

    def __init__(self, lines):
        self.finished = False       # cargo's own build-finished {"success": true}
        self.live = {}              # profile dir -> hashes of the units used there
        self.executables = {}       # bin target name -> the uplifted executable
        self.own_packages = set()   # this repo's packages...
        self.own_stems = set()      # ...and their targets' file stems
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            reason = msg.get("reason")
            if reason == "build-finished":
                self.finished = bool(msg.get("success"))
            elif reason == "compiler-artifact":
                if str(msg.get("package_id", "")).startswith("path+"):
                    self.own_packages.add(_package_name(msg["package_id"]))
                    self.own_stems.add(msg["target"]["name"].replace("-", "_"))
                if msg.get("executable"):
                    self.executables[msg["target"]["name"]] = msg["executable"]
                for path in msg.get("filenames") or []:
                    self._note(path)
            elif reason == "build-script-executed" and msg.get("out_dir"):
                self._note(msg["out_dir"])

    def _note(self, path):
        # <profile>/deps/<file>, <profile>/build/<pkg>-<hash>/<file>, or .../out.
        # The executable uplifted beside deps/ carries no hash and is not noted.
        parts = re.split(r"[\\/]", path)
        n = len(parts)
        for i in (n - 2, n - 3):
            if i > 0 and (parts[i] == "deps" and i == n - 2 or parts[i] == "build"):
                unit = _unit_hash(parts[i + 1])
                if unit:
                    profile = os.path.normpath(os.sep.join(parts[:i]))
                    self.live.setdefault(profile, set()).add(unit)
                return


def cargo_build(args, env=None):
    """check_call() for a cargo build, plus its JSON messages: progress and
    diagnostics still render on the console, the messages are read off stdout."""
    proc = subprocess.Popen(args + [CARGO_JSON], stdout=subprocess.PIPE, env=env,
                            text=True, encoding="utf-8", errors="replace")
    report = BuildReport(proc.stdout)
    if proc.wait() != 0:
        raise subprocess.CalledProcessError(proc.returncode, args)
    return report


def _entries(path):
    try:
        return list(os.scandir(path))
    except OSError:
        return []


def _tree_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def _remove(path):
    """Deletes a file or a whole tree; returns the bytes that went. Whatever is
    held open by some process stays, and the next prune tries it again."""
    if os.path.isdir(path) and not os.path.islink(path):
        before = _tree_size(path)
        shutil.rmtree(path, ignore_errors=True)
        return before - (_tree_size(path) if os.path.exists(path) else 0)
    try:
        size = os.lstat(path).st_size
        os.remove(path)
        return size
    except OSError:
        return 0


def _mb(size):
    return ("%.1f МБ" if size < 10 * 1048576 else "%.0f МБ") % (size / 1048576)


def _remove_units(profile, units):
    """Deletes these units from one profile directory: their .fingerprint/ and
    build/ directories and every file in deps/ that carries their hash."""
    freed = 0
    for sub in (".fingerprint", "build", "deps"):
        for entry in _entries(os.path.join(profile, sub)):
            if _unit_hash(entry.name) in units:
                freed += _remove(entry.path)
    return freed


def prune_release_cache(target_dir, report, whole_dir):
    """Leaves in a release cache exactly the units the build in `report` used.
    `whole_dir`: the directory holds nothing but these builds, so a profile or a
    target triple the build did not touch goes too. Returns (bytes freed, bytes
    kept), or a string saying why nothing was deleted."""
    if not report.finished:
        return "cargo не подтвердил, что сборка завершилась"
    root = os.path.normcase(os.path.abspath(target_dir))
    profiles = {}
    for profile, units in report.live.items():
        path = os.path.abspath(profile)
        try:
            inside = (os.path.commonpath([os.path.normcase(path), root]) == root
                      and os.path.normcase(path) != root)
        except ValueError:
            inside = False
        fingerprints = {_unit_hash(e.name) for e in _entries(os.path.join(path, ".fingerprint"))}
        if not inside or not units <= fingerprints:
            return "раскладка кэша не совпала с тем, что сообщил cargo"
        profiles[path] = set(units)
    if not profiles:
        return "cargo не сообщил ни одного модуля"

    freed = 0
    for profile, live in profiles.items():
        # Our own executable's unit is in no message: its report names only the
        # copy uplifted beside deps/. Where the file in deps/ carries a hash (not
        # on MSVC), it is that same file - cargo hardlinks the two - which is how
        # it is told apart from a previous generation's. If no file matches, every
        # file named after our own targets stays.
        own = set()
        for exe in report.executables.values():
            if os.path.normcase(os.path.dirname(os.path.abspath(exe))) == os.path.normcase(profile):
                try:
                    st = os.stat(exe)
                    own.add((st.st_dev, st.st_ino))
                except OSError:
                    pass
        ours, matched = set(), False
        for entry in _entries(os.path.join(profile, "deps")):
            unit = _unit_hash(entry.name)
            stem = entry.name.split(".", 1)[0]
            if unit:
                stem = stem[:-len(unit) - 1]
            if stem.startswith("lib") and stem[3:] in report.own_stems:
                stem = stem[3:]
            if stem not in report.own_stems:
                continue
            try:
                st = os.stat(entry.path)
            except OSError:
                continue
            if (st.st_dev, st.st_ino) in own:
                matched = True
                if unit:
                    live.add(unit)
            elif unit:
                ours.add(unit)
        if not matched:
            live |= ours

        dead = set()
        for sub in (".fingerprint", "build", "deps"):
            for entry in _entries(os.path.join(profile, sub)):
                unit = _unit_hash(entry.name)
                if not unit or unit in live:
                    continue
                # Our executable's fingerprint has a hash no message names (on
                # MSVC not even its file in deps/ has one). A few KB; kept.
                if sub == ".fingerprint" and entry.name[:-len(unit) - 1] in report.own_packages:
                    continue
                dead.add(unit)
        freed += _remove_units(profile, dead)

    if not whole_dir:
        return freed, sum(_tree_size(p) for p in profiles)
    # Whole directories none of this build's units live in: another profile or
    # target triple (the native Linux fallback's layout after a zigbuild, or the
    # other way round).
    kept_profiles = {os.path.normcase(p) for p in profiles}
    ancestors = {root}
    for profile in kept_profiles:
        # Every profile was checked to lie inside root, so this walks up the
        # directories between the two and stops at root.
        parent = os.path.dirname(profile)
        while parent != root and len(parent) > len(root):
            ancestors.add(parent)
            parent = os.path.dirname(parent)
    for directory in ancestors:
        for entry in _entries(directory):
            path = os.path.normcase(entry.path)
            if (entry.is_dir(follow_symlinks=False)
                    and path not in kept_profiles and path not in ancestors):
                freed += _remove(entry.path)
    return freed, _tree_size(target_dir)


def _stat_times(path):
    # os.stat, not the directory listing's copy of the times: NTFS updates the
    # access time kept in a directory's index lazily.
    try:
        st = os.stat(path)
    except OSError:
        return 0
    return max(st.st_atime, st.st_mtime)


def _last_use(path, depth):
    """Latest access or modification time among the files `depth` levels into
    `path`."""
    latest = 0
    for entry in _entries(path):
        if entry.is_dir(follow_symlinks=False):
            if depth > 1:
                latest = max(latest, _last_use(entry.path, depth - 1))
        else:
            latest = max(latest, _stat_times(entry.path))
    return latest


def _unit_last_use(unit_dir):
    """When cargo last looked at a unit: the times of its fingerprint hash file
    (`lib-regex`, beside `lib-regex.json`), which every build with the unit in its
    graph reads, fresh or not. One stat per unit - this runs over a whole test
    cache, and the repo may be on a slow disk."""
    names = {entry.name for entry in _entries(unit_dir)}
    return max([_stat_times(os.path.join(unit_dir, name))
                for name in names if name + ".json" in names] or [0])


def _profile_dirs(target_dir):
    """target/<profile> and target/<triple>/<profile>: whatever holds a .fingerprint."""
    found = []
    for entry in _entries(target_dir):
        if not entry.is_dir(follow_symlinks=False):
            continue
        for candidate in [entry] + _entries(entry.path):
            if (candidate.is_dir(follow_symlinks=False)
                    and os.path.isdir(os.path.join(candidate.path, ".fingerprint"))):
                found.append(candidate.path)
    return found


def prune_dev_cache(target_dir, release_profile):
    """The rest of target\\ - cargo test, cargo check, rust-analyzer - keeps every
    unit used in the last DEV_CACHE_KEEP_DAYS days. Nothing reports what those
    builds use, so the evidence here is the access time of each unit's
    .fingerprint files, which cargo reads for every unit of every build, fresh or
    not. If no unit at all shows a use inside the window, this disk is not keeping
    access times (or nothing was built here lately), and nothing is deleted.
    `release_profile` is prune_release_cache's and is left alone.
    Returns the bytes freed."""
    cutoff = time.time() - DEV_CACHE_KEEP_DAYS * 86400
    skip = os.path.normcase(os.path.abspath(release_profile))
    profiles = [p for p in _profile_dirs(target_dir)
                if os.path.normcase(os.path.abspath(p)) != skip]
    stale, recent = {}, False
    for profile in profiles:
        for entry in _entries(os.path.join(profile, ".fingerprint")):
            unit = _unit_hash(entry.name)
            if not unit:
                continue
            if _unit_last_use(entry.path) >= cutoff:
                recent = True
            else:
                stale.setdefault(profile, set()).add(unit)
    if not recent:
        return 0
    freed = 0
    for profile in profiles:
        if profile in stale:
            freed += _remove_units(profile, stale[profile])
            if not _entries(os.path.join(profile, ".fingerprint")):
                # Nothing of this profile is in use: its leftovers in deps/, its
                # incremental state, all of it.
                freed += _remove(profile)
                continue
        # Incremental state is named by rustc, not by cargo's unit hash, and read
        # only when its crate is compiled again.
        for entry in _entries(os.path.join(profile, "incremental")):
            if entry.is_dir(follow_symlinks=False) and _last_use(entry.path, depth=2) < cutoff:
                freed += _remove(entry.path)
    return freed


def prune_old_releases(release_dir, version):
    """Deletes other versions' build outputs from release/ - the .exe, the Linux
    bundle directory and its .tar.gz - and nothing else: the release notes and
    scripts kept beside them are not the build's to delete. Every published
    version is on GitHub Releases; the others were test builds.
    Returns (entries removed, bytes freed)."""
    output = re.compile(r"^AG_(.+?)(\.exe|_linux\.tar\.gz|_linux)$")
    removed = freed = 0
    for entry in _entries(release_dir):
        m = output.match(entry.name)
        if not m or m.group(1) == version:
            continue
        if entry.is_dir(follow_symlinks=False) != (m.group(2) == "_linux"):
            continue
        freed += _remove(entry.path)
        if not os.path.exists(entry.path):
            removed += 1
    return removed, freed


def print_prune(label, target_dir, result):
    if isinstance(result, str):
        print(f"[i] Кэш {label}-сборки не почищен: {result}. На сборку это не влияет.")
        return
    freed, kept = result
    line = f"[INFO] Кэш {label}-сборки: {_mb(kept)} в {target_dir}"
    if freed:
        line += f", удалено устаревшего {_mb(freed)}"
    print(line + ".")


def prune_linux_cache(target_dir):
    """Run by python3 inside WSL (build_linux_bundle), where the cache is local."""
    with open(os.path.join(target_dir, "messages.json"), encoding="utf-8",
              errors="replace") as f:
        report = BuildReport(f)
    print_prune("Linux", target_dir, prune_release_cache(target_dir, report, whole_dir=True))


# UPX packing is OFF (owner, `_4`). A packed exe is the single biggest source of
# antivirus false positives here, and a user who cannot start the tool at all is a
# worse outcome than a file three times the size. The packer below is deliberately
# kept rather than deleted - set this back to True to ship packed again.
UPX_ENABLED = False


def find_upx():
    """Locate the UPX packer. Returns the executable path or None."""
    import shutil
    found = shutil.which("upx")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\upx\upx.exe",
        r"C:\Program Files (x86)\upx\upx.exe",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "upx.exe"),
    ):
        if os.path.exists(candidate):
            return candidate
    return None


def compress_exe_inplace(exe_path):
    """Shrink the release exe in place with UPX, keeping it a directly-runnable
    .exe (no archive, no separate file).

    UPX is a runtime packer: the file on disk gets ~60-65% smaller, and the exe
    self-decompresses into memory on launch. For a ~1.5 MB binary that unpack is
    single-digit milliseconds - imperceptible - but it is the unavoidable cost of
    compressing the executable itself rather than shipping it in an archive.
    Packed exes also raise more AV false positives (already noted in README).

    Best-effort: if UPX is absent the uncompressed exe still ships.
    """
    upx = find_upx()
    if not upx:
        print("[WARNING] UPX не найден (upx в PATH, C:\\Program Files\\upx или рядом со "
              "скриптом). Сжатие пропущено - будет отгружён несжатый .exe.")
        return

    before = None
    try:
        before = os.path.getsize(exe_path)
    except OSError:
        pass
    try:
        # --best --lzma = maximum compression. UPX rewrites the file in place, so
        # the output stays AG_<ver>.exe.
        subprocess.check_call(
            [upx, "--best", "--lzma", exe_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"[WARNING] Не удалось сжать exe с помощью UPX: {e}")
        return

    try:
        after = os.path.getsize(exe_path)
        if before:
            print(f"[INFO] exe сжат UPX: {before // 1024} КБ -> {after // 1024} КБ "
                  f"({after / before * 100:.0f}%).")
        else:
            print(f"[INFO] exe сжат UPX: {after // 1024} КБ.")
    except OSError:
        print("[INFO] exe сжат UPX.")


# Linux build is produced by driving a WSL distro that has a Rust toolchain, so a
# single `python build_rust.py` on Windows yields both the .exe and the Linux
# bundle. Best-effort: if WSL or cargo is missing the Windows build still ships.
PREFERRED_WSL_DISTROS = ("Ubuntu-26.04", "Ubuntu", "Ubuntu-24.04", "Ubuntu-22.04")


def _wsl_run(distro, bash_cmd, capture=True):
    """Runs a bash command inside a WSL distro (login shell, so ~/.cargo/env is
    reachable via the explicit source below). Returns CompletedProcess.

    `-e`, not `--`: after `--` wsl.exe hands the whole line to the distro's default
    shell first, which expands every `$VAR` before bash sees the command - `$HOME`
    survives that, but a variable the command sets itself arrives empty, and
    `exit $rc` arrives as `exit`, i.e. 0.

    WSL_UTF8: wsl.exe's own notices ("A localhost proxy configuration was detected
    ...", printed on some runs and not others) are UTF-16 otherwise, and their NUL
    bytes land at the start of the next line of the command's output."""
    args = ["wsl.exe", "-d", distro, "-e", "bash", "-lc", bash_cmd]
    res = subprocess.run(
        args,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True, encoding="utf-8", errors="replace",
        env=dict(os.environ, WSL_UTF8="1"),
    )
    if res.stdout:
        res.stdout = res.stdout.replace("\x00", "")  # a WSL too old for WSL_UTF8
    return res


def find_wsl_distro():
    """The first installed WSL distro that has cargo on PATH (after sourcing the
    rustup env). None if WSL is absent or no distro can build."""
    try:
        listing = subprocess.run(
            ["wsl.exe", "-l", "-q"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-16-le", errors="replace",
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    if not listing:
        return None
    installed = [d.strip() for d in listing.splitlines() if d.strip()]
    # Preferred names first, then whatever else is installed.
    ordered = [d for d in PREFERRED_WSL_DISTROS if d in installed]
    ordered += [d for d in installed if d not in ordered]
    for distro in ordered:
        probe = _wsl_run(distro, '. "$HOME/.cargo/env" 2>/dev/null; command -v cargo >/dev/null && echo OK')
        if probe.returncode == 0 and "OK" in (probe.stdout or ""):
            return distro
    return None


def _win_to_wsl_path(win_path):
    """D:\\a\\b -> /mnt/d/a/b, without needing wslpath."""
    p = os.path.abspath(win_path)
    drive, rest = os.path.splitdrive(p)
    rest = rest.replace("\\", "/")
    return "/mnt/%s%s" % (drive.rstrip(":").lower(), rest)


# The build machine's paths, out of the shipped binaries.
#
# Every panic location a dependency carries - winit, wgpu, ring, naga: hundreds
# of them - is an absolute path into CARGO_HOME, i.e. into the builder's home
# directory, and one reached a user's screen inside a winit error ("os error at
# /home/<builder>/.cargo/registry/src/.../winit-0.30.13/..."). rustc rewrites them
# at compile time: the home directory becomes ~, the checkout /ag_unlocker, the
# cargo home /cargo. The last matching rule wins, so the specific ones come last.
# (`profile.trim-paths` does this in one line, but is unstable in cargo 1.95.)
def remap_prefix_flags(home, repo, cargo_home):
    return ["--remap-path-prefix=%s=%s" % (src, dst)
            for src, dst in ((home, "~"), (repo, "/ag_unlocker"), (cargo_home, "/cargo"))
            if src]


def config_rustflags(triple):
    """The rustflags .cargo/config.toml gives `triple`. An environment
    CARGO_ENCODED_RUSTFLAGS *replaces* that list rather than adding to it, so the
    release build hands it over explicitly - or it would ship without the static
    CRT, and a clean Windows would refuse the exe before main (VCRUNTIME140.dll)."""
    import tomllib
    with open(os.path.join(".cargo", "config.toml"), "rb") as f:
        return list(tomllib.load(f)["target"][triple]["rustflags"])


def check_shipped_binary(path, needles, windows):
    """Measured, not assumed: warns when the binary still names the build
    machine, or (Windows) still needs the Visual C++ runtime DLL."""
    try:
        with open(path, "rb") as f:
            data = f.read().lower()
    except OSError as e:
        print(f"[WARNING] {path} не прочитан для проверки: {e}")
        return
    leaked = [n for n in needles if n and n.lower().encode("utf-8") in data]
    if leaked:
        print(f"[WARNING] {os.path.basename(path)} содержит пути сборочной машины: {', '.join(leaked)}")
    else:
        print(f"[INFO] {os.path.basename(path)}: путей сборочной машины нет.")
    if windows and b"vcruntime140.dll" in data:
        print(f"[WARNING] {os.path.basename(path)} требует VCRUNTIME140.dll - "
              f"статический CRT не применился (.cargo/config.toml).")


# Oldest glibc the Linux bundle has to start on.
#
# glibc is backward compatible but not forward, and the baseline is decided by
# where the binary is *linked*, not by what it calls. Built natively on Ubuntu
# 26.04 (glibc 2.43), `_4`'s ELF picked up a GLIBC_2.39 version reference for two
# `pidfd_*` symbols out of Rust std's process-spawn fast path. The symbols
# themselves are weak and std falls back without them - but the `.gnu.version_r`
# entry is `Flags: none`, so ld.so refuses to start the file at all on anything
# older: `version 'GLIBC_2.39' not found`, before main. Nothing else in the binary
# asked for more than GLIBC_2.34.
#
# cargo-zigbuild pins the baseline at link time, so this needs no second distro.
# 2.17 is Rust std's own floor, and zig ships stubs for it: against them
# `__libc_start_main`, `dlsym` and the `pthread_*` family link to their pre-2.34
# homes in libpthread/libdl, so the 2.34 an earlier note called "the floor the
# code itself sets" was only where a *modern* glibc had moved those symbols.
# Measured 2026-09-19: a 2.17 build asks for nothing above GLIBC_2.17 and NEEDED
# holds libc, libm, libpthread, libdl - all glibc. Covers CentOS/RHEL 7, Ubuntu
# 14.04+, Debian 8+: the old servers the terminal mode is for, not only desktops.
# Raise it only if a build starts failing to link, never to make a build pass
# quietly: `linux_glibc_baseline` below is what proves the pin held.
LINUX_GLIBC = "2.17"
LINUX_TARGET = "x86_64-unknown-linux-gnu"

# The Linux build's cache, on the WSL distro's own filesystem. It used to be
# target-linux\ beside the sources, where every file rustc wrote crossed the 9P
# bridge onto the Windows drive - and was deleted after every build anyway.
LINUX_CACHE = "${XDG_CACHE_HOME:-$HOME/.cache}/ag_unlocker/target-linux"


def _version_tuple(v):
    """"2.36" -> (2, 36), so glibc versions compare numerically and 2.9 does not
    outrank 2.36 the way a string compare would."""
    out = []
    for part in str(v).split("."):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple(out)


def linux_glibc_baseline(distro, elf_wsl_path):
    """The highest GLIBC_x.y the ELF asks ld.so for - i.e. the oldest distro it
    actually starts on. Measured, not assumed: the 2.39 above was invisible until
    someone looked, and a silent baseline creep is exactly the failure that ships.
    Returns the version string, or None when binutils is not there to ask."""
    res = _wsl_run(
        distro,
        "objdump -T '%s' 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -1"
        % elf_wsl_path,
    )
    if not res or res.returncode != 0:
        return None
    # The last line: wsl.exe may print a notice of its own ahead of it.
    found = ((res.stdout or "").strip().splitlines() or [""])[-1].strip()
    return found[len("GLIBC_"):] if found.startswith("GLIBC_") else None


def build_linux_bundle(version):
    """Builds the Linux ELF in WSL and assembles release/AG_<ver>_linux/ (+ .tar.gz)
    with the double-click launcher assets. Best-effort; returns the bundle dir or
    None. Never raises - the Windows build must not depend on it."""
    import tarfile

    # Where the Linux target dir lived before LINUX_CACHE.
    shutil.rmtree("target-linux", ignore_errors=True)

    try:
        distro = find_wsl_distro()
        if not distro:
            print("[i] Linux-сборка пропущена: не найден WSL-дистрибутив с cargo "
                  "(установите rustup в WSL: 'curl https://sh.rustup.rs -sSf | sh').")
            return None
        print(f"[INFO] Сборка Linux-версии в WSL ({distro})...")

        repo_wsl = _win_to_wsl_path(os.getcwd())
        probe = _wsl_run(
            distro,
            '. "$HOME/.cargo/env" 2>/dev/null; '
            "command -v cargo-zigbuild >/dev/null && echo OK",
        )
        has_zigbuild = bool(probe and probe.returncode == 0 and "OK" in (probe.stdout or ""))

        if has_zigbuild:
            cargo_cmd = "cargo zigbuild --release --bin ag_unlocker --target %s.%s" % (
                LINUX_TARGET, LINUX_GLIBC)
            elf_in_cache = "%s/release/ag_unlocker" % LINUX_TARGET
        else:
            # Still build - the bundle is better than no bundle - but say plainly
            # what the fallback costs, because the damage is invisible in the
            # output and lands on the user's machine as a refusal to start.
            print(f"[WARNING] cargo-zigbuild не найден в WSL - собираю нативно. Бандл "
                  f"потребует glibc сборочной машины, а не {LINUX_GLIBC}, и не запустится "
                  f"на дистрибутивах старше неё.")
            print("          Поставить: pip3 install --user --break-system-packages ziglang "
                  "&& cargo install cargo-zigbuild")
            cargo_cmd = "cargo build --release --bin ag_unlocker"
            elf_in_cache = "release/ag_unlocker"

        # cargo's JSON messages go to a file in the cache, for the prune below to
        # read there; its console output goes to a log beside them, and only the
        # log's tail comes back here. No pipe: cargo's own exit status is the one
        # that counts. Through `| tail -3` it used to be tail's, so a failed build
        # was noticed only because target-linux had been wiped - over a kept cache
        # it would have shipped the previous ELF.
        # The paths rewritten are the distro's own ($HOME, CARGO_HOME), and the
        # checkout as WSL sees it. \x1f-separated, so a space in a path is safe.
        remap = (
            'export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$HOME=~"$\'\\x1f\''
            '"--remap-path-prefix=%s=/ag_unlocker"$\'\\x1f\''
            '"--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"; '
        ) % repo_wsl
        # The full version, build number included, as the Windows build gets it
        # (build.rs → `update::current_version`). Without it the ELF called itself
        # plain "2.15.0", so every Linux build - `2.15.0_1` too - showed «новая
        # версия» for the very release it was, and the TUI title said 2.15.0.
        full_version = 'export AG_FULL_VERSION="%s"; ' % version
        build_cmd = (
            '. "$HOME/.cargo/env"; cd "%s" || exit 1; T="%s"; mkdir -p "$T" || exit 1; '
            + remap + full_version +
            'echo "TARGET_DIR=$T"; '
            '%s --target-dir "$T" %s >"$T/messages.json" 2>"$T/build.log"; rc=$?; '
            'if [ $rc -eq 0 ]; then tail -n 3 "$T/build.log"; else tail -n 40 "$T/build.log"; fi; '
            'exit $rc'
        ) % (repo_wsl, LINUX_CACHE, cargo_cmd, CARGO_JSON)
        res = _wsl_run(distro, build_cmd, capture=True)
        lines = [l.rstrip() for l in (res.stdout or "").splitlines() if l.strip()]
        marker = [l.strip() for l in lines if l.strip().startswith("TARGET_DIR=")]
        target_dir = marker[0][len("TARGET_DIR="):] if marker else None
        shown = "\n".join(l for l in lines if not l.strip().startswith("TARGET_DIR="))
        if shown:
            print(shown)
        if res.returncode != 0 or not target_dir:
            print("[WARNING] Linux-сборка не удалась (см. вывод выше) - отгружён только .exe.")
            return None

        elf = "%s/%s" % (target_dir, elf_in_cache)
        if _wsl_run(distro, 'test -f "%s"' % elf).returncode != 0:
            print(f"[WARNING] ELF не найден по пути {elf} - Linux-бандл не собран.")
            return None

        # Report the baseline that was actually produced, and complain when it is
        # not the one asked for - the whole point of pinning it is lost if nobody
        # checks (that is how the GLIBC_2.39 bundle shipped).
        baseline = linux_glibc_baseline(distro, elf)
        if baseline is None:
            print("[i] Планку glibc проверить нечем (нет objdump в WSL).")
        elif has_zigbuild and _version_tuple(baseline) > _version_tuple(LINUX_GLIBC):
            print(f"[WARNING] ELF требует glibc {baseline}, хотя собирался под "
                  f"{LINUX_GLIBC} - планка не удержана, проверьте цель сборки.")
        else:
            print(f"[INFO] Linux-бандл требует glibc {baseline} и старше.")

        bundle = os.path.abspath(os.path.join("release", f"AG_{version}_linux"))
        if os.path.exists(bundle):
            shutil.rmtree(bundle, ignore_errors=True)
        os.makedirs(bundle, exist_ok=True)

        # The ELF - on the distro's filesystem, so WSL copies it across - plus the
        # launcher assets from linux/.
        copied = _wsl_run(distro, 'cp "%s" "%s/ag_unlocker"' % (elf, _win_to_wsl_path(bundle)))
        if copied.returncode != 0:
            print(f"[WARNING] ELF не скопирован в бандл: {(copied.stdout or '').strip()}")
            return None
        for name in ("launch.sh", "install.sh", "Antigravity-Unlocker.desktop", "README.md"):
            src = os.path.join("linux", name)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(bundle, name))

        # Best-effort icon: convert icon.ico -> icon.png if Pillow is present.
        try:
            from PIL import Image
            ico = "icon.ico"
            if os.path.exists(ico):
                img = Image.open(ico)
                # Largest frame for a crisp menu icon.
                if hasattr(img, "n_frames") and img.n_frames > 1:
                    best, best_area = 0, 0
                    for i in range(img.n_frames):
                        img.seek(i)
                        area = img.size[0] * img.size[1]
                        if area > best_area:
                            best, best_area = i, area
                    img.seek(best)
                img.convert("RGBA").save(os.path.join(bundle, "icon.png"))
        except Exception:
            pass  # Icon is cosmetic; the .desktop falls back to a theme icon.

        # A .tar.gz for easy transfer to the VM, with the exec bits preserved.
        tar_path = bundle + ".tar.gz"
        if os.path.exists(tar_path):
            os.remove(tar_path)

        def _exec_bits(tarinfo):
            base = os.path.basename(tarinfo.name)
            if base in ("ag_unlocker", "launch.sh", "install.sh") or base.endswith(".desktop"):
                tarinfo.mode = 0o755
            return tarinfo

        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(bundle, arcname=f"AG_{version}_linux", filter=_exec_bits)

        wsl_home = _wsl_run(distro, 'printf %s "$HOME"')
        wsl_home = ((wsl_home.stdout or "").strip().splitlines() or [""])[-1].strip() if wsl_home else ""
        check_shipped_binary(os.path.join(bundle, "ag_unlocker"),
                             [wsl_home + "/", "/.cargo/registry"], windows=False)

        elf_size = os.path.getsize(os.path.join(bundle, "ag_unlocker")) // 1024
        print(f"[УСПЕХ] Linux-бандл: {bundle} (ELF {elf_size} КБ)")
        print(f"        Архив для переноса на машину: {tar_path}")

        # The bundle is assembled; only now is it known what the cache must keep.
        # python3 inside the distro, where the cache's files are local.
        pruned = _wsl_run(
            distro,
            'python3 -B -c "import sys; sys.path.insert(0, sys.argv[1]); '
            'import build_rust; build_rust.prune_linux_cache(sys.argv[2])" "%s" "%s"'
            % (repo_wsl, target_dir),
        )
        said = (pruned.stdout or "").strip().splitlines()
        if pruned.returncode == 0:
            print("\n".join(said))
        else:
            print("[i] Кэш Linux-сборки не почищен (нужен python3 в WSL): %s"
                  % (said[-1] if said else "нет ответа"))
        return bundle
    except Exception as e:
        print(f"[WARNING] Linux-сборка пропущена из-за ошибки: {e}")
        return None


def read_base_secret(auth_rs_path):
    """Reads the committed base secret straight from src\\auth.rs, so the source
    is the single source of truth for both the binary and the key generator."""
    with open(auth_rs_path, 'r', encoding='utf-8') as f:
        src = f.read()
    m = re.search(r'const\s+LICENSE_BASE_SECRET\s*:\s*&str\s*=\s*"([^"]*)"', src)
    if not m:
        raise RuntimeError("LICENSE_BASE_SECRET not found in src/auth.rs")
    return m.group(1)


def main():
    # Set correct working directory to where this script is located
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("[INFO] Starting build process...")

    VERSION = "2.17.0.2"
    version = VERSION
    # env!("CARGO_PKG_VERSION") only sees MAJOR.MINOR.PATCH, so the key salt uses
    # the same trimmed value the binary will compile with.
    #
    # The build number is separated by "_" so it can never be mistaken for a
    # fourth semver component: "2.9.1_14" splits to "2.9.1" here, whereas
    # "2.9.1.14" put through the old ".".join(...[:3]) would have been fine but
    # any future edit to this line could silently write a 4-part version into
    # Cargo.toml - and a changed Cargo version re-salts and invalidates every
    # licence key that has ever been issued. Both spellings are accepted.
    cargo_version = ".".join(version.split("_")[0].split(".")[:3])
    print(f"[INFO] Build version: {version}")

    # `.secrets.json` is now purely an owner marker: when present, this machine
    # is the author's, so the key generator is produced and fresh keys printed.
    # A clone from GitHub has no such file, so it builds a working binary but
    # generates NO keys - users must fetch a free key from t.me/nova_txt.
    is_owner = os.path.exists(".secrets.json")

    main_rs_path = r"src\main.rs"
    auth_rs_path = r"src\auth.rs"

    # The secret is committed in the sources; the key generator derives from the
    # exact same base + version salt, so its keys always match this build.
    base_secret = read_base_secret(auth_rs_path)
    key_secret_phrase = f"{base_secret}{LICENSE_VERSION_SEP}{cargo_version}"

    keygen_code = """import sys
import os
import subprocess
import traceback

SECRET_PHRASE = """ + repr(key_secret_phrase) + """

def copy_to_clipboard(text):
    try:
        import ctypes
        if not ctypes.windll.user32.OpenClipboard(None):
            return False
        ctypes.windll.user32.EmptyClipboard()
        hCd = ctypes.windll.kernel32.GlobalAlloc(2, len(text) + 1)
        if not hCd:
            ctypes.windll.user32.CloseClipboard()
            return False
        pCd = ctypes.windll.kernel32.GlobalLock(hCd)
        if not pCd:
            ctypes.windll.user32.CloseClipboard()
            return False
        ctypes.cdll.msvcrt.strcpy(ctypes.c_char_p(pCd), text.encode('ascii'))
        ctypes.windll.kernel32.GlobalUnlock(hCd)
        ctypes.windll.user32.SetClipboardData(1, hCd)
        ctypes.windll.user32.CloseClipboard()
        return True
    except Exception:
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"Set-Clipboard -Value '{text}'"],
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return True
        except:
            return False

def generate_key():
    import hashlib
    import random
    import string
    chars = string.ascii_uppercase + string.digits
    nonce = ''.join(random.choices(chars, k=12))
    data = f"{nonce}{SECRET_PHRASE}".encode('utf-8')
    signature = hashlib.sha256(data).hexdigest().upper()[:12]
    return f"{nonce}{signature}"

def run_gui_tk():
    import tkinter as tk
    from tkinter import messagebox

    def copy_selected():
        try:
            selected_idx = listbox.curselection()
            if not selected_idx:
                messagebox.showwarning("Warning", "Please select a key first!")
                return
            selected_key = listbox.get(selected_idx[0])
            root.clipboard_clear()
            root.clipboard_append(selected_key)
            root.update()
            status_label.config(text="Selected key copied!", fg="#a6e3a1")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_all():
        try:
            all_keys = listbox.get(0, tk.END)
            keys_str = "\\n".join(all_keys)
            root.clipboard_clear()
            root.clipboard_append(keys_str)
            root.update()
            status_label.config(text="All 5 keys copied!", fg="#a6e3a1")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    global root, listbox, status_label
    root = tk.Tk()
    root.title("Antigravity Keygen v""" + version + """")
    root.geometry("450x420")
    root.configure(bg="#1e1e2e")
    root.resizable(False, False)
    
    title_lbl = tk.Label(root, text="Antigravity Key Generator", bg="#1e1e2e", fg="#89b4fa", font=("Segoe UI", 16, "bold"))
    title_lbl.pack(pady=15)
    
    frame = tk.Frame(root, bg="#1e1e2e")
    frame.pack(pady=10)
    
    listbox = tk.Listbox(
        frame, 
        bg="#181825", 
        fg="#a6e3a1", 
        font=("Consolas", 14, "bold"), 
        width=28, 
        height=5, 
        bd=0, 
        highlightbackground="#313244", 
        highlightcolor="#89b4fa", 
        highlightthickness=2,
        selectbackground="#45475a",
        selectforeground="#ffffff",
        activestyle="none"
    )
    listbox.pack(side=tk.LEFT, fill=tk.BOTH)
    
    for _ in range(5):
        listbox.insert(tk.END, generate_key())
    
    listbox.selection_set(0)
    
    status_label = tk.Label(root, text="Select a key to copy", bg="#1e1e2e", fg="#a6adc8", font=("Segoe UI", 10))
    status_label.pack(pady=5)
    
    btn_style = {
        "bg": "#313244",
        "fg": "#cdd6f4",
        "activebackground": "#45475a",
        "activeforeground": "#ffffff",
        "font": ("Segoe UI", 11, "bold"),
        "bd": 0,
        "height": 2,
        "width": 18,
        "cursor": "hand2"
    }
    
    btn_frame = tk.Frame(root, bg="#1e1e2e")
    btn_frame.pack(pady=15)
    
    btn_copy_sel = tk.Button(btn_frame, text="Copy Selected", command=copy_selected, **btn_style)
    btn_copy_sel.pack(side=tk.LEFT, padx=10)
    
    btn_copy_all = tk.Button(btn_frame, text="Copy All", command=copy_all, **btn_style)
    btn_copy_all.pack(side=tk.LEFT, padx=10)
    
    def on_enter(e):
        e.widget.config(bg="#45475a")
    def on_leave(e):
        e.widget.config(bg="#313244")
    
    btn_copy_sel.bind("<Enter>", on_enter)
    btn_copy_sel.bind("<Leave>", on_leave)
    btn_copy_all.bind("<Enter>", on_enter)
    btn_copy_all.bind("<Leave>", on_leave)
    
    root.mainloop()

def run_gui_dpg():
    import dearpygui.dearpygui as dpg

    keys = [generate_key() for _ in range(5)]
    selected_idx = 0

    dpg.create_context()
    dpg.create_viewport(title='Antigravity Keygen v""" + version + """', width=450, height=420, resizable=False)
    dpg.setup_dearpygui()

    def copy_selected_callback():
        nonlocal selected_idx
        text = keys[selected_idx]
        if copy_to_clipboard(text):
            dpg.set_value(status_text, "Selected key copied!")
        else:
            dpg.set_value(status_text, "Failed to copy key.")

    def copy_all_callback():
        text = "\\n".join(keys)
        if copy_to_clipboard(text):
            dpg.set_value(status_text, "All 5 keys copied!")
        else:
            dpg.set_value(status_text, "Failed to copy keys.")

    def listbox_callback(sender, app_data):
        nonlocal selected_idx
        selected_idx = keys.index(app_data)

    with dpg.window(label="Main Window", width=450, height=420, no_title_bar=True, no_move=True, no_resize=True):
        dpg.add_spacer(height=15)
        dpg.add_text("Antigravity Key Generator", color=[137, 180, 250])
        dpg.add_spacer(height=15)
        
        dpg.add_listbox(items=keys, callback=listbox_callback, width=410, num_items=5)
        dpg.add_spacer(height=10)
        
        status_text = dpg.add_text("Select a key to copy", color=[166, 173, 200])
        dpg.add_spacer(height=15)
        
        with dpg.group(horizontal=True):
            dpg.add_button(label="Copy Selected", callback=copy_selected_callback, width=195, height=40)
            dpg.add_button(label="Copy All", callback=copy_all_callback, width=195, height=40)

    with dpg.theme() as global_theme:
        with dpg.theme_component(dpg.mvAll):
            dpg.add_theme_color(dpg.mvThemeCol_WindowBg, [30, 30, 46])
            dpg.add_theme_color(dpg.mvThemeCol_Button, [49, 50, 68])
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHover, [69, 71, 90])
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, [137, 180, 250])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, [24, 24, 37])
            dpg.add_theme_color(dpg.mvThemeCol_Text, [205, 214, 244])

    dpg.bind_theme(global_theme)
    dpg.show_viewport()
    dpg.start_dearpygui()
    dpg.destroy_context()

def run_console():
    os.system('color 0A' if os.name == 'nt' else 'clear')
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Ключи для v""" + version + """\\n")
    for _ in range(5):
        print(generate_key())
    
    print()
    input("Press Enter to exit...")

def main():
    try:
        run_gui_tk()
        return
    except ImportError:
        try:
            import dearpygui.dearpygui
            run_gui_dpg()
            return
        except ImportError:
            print("GUI module 'tkinter' is missing. Installing 'dearpygui' as alternative...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "dearpygui"])
                import dearpygui.dearpygui
                run_gui_dpg()
                return
            except Exception:
                pass
    except Exception as e:
        pass

    run_console()

if __name__ == "__main__":
    main()
"""

    dist_keygen_path = "dist_keygen.py"

    try:
        # 1. Sync the version in Cargo.toml so env!("CARGO_PKG_VERSION") - which
        #    both the binary and the key salt use - matches this release.
        with open("Cargo.toml", 'r', encoding='utf-8') as f:
            cargo_content = f.read()
        cargo_content = re.sub(r'^version\s*=\s*"[^"]*"', f'version = "{cargo_version}"', cargo_content, flags=re.MULTILINE)
        with open("Cargo.toml", 'w', encoding='utf-8') as f:
            f.write(cargo_content)

        # 2. Owner-only: (re)generate the key generator for THIS version. Never
        #    created on a plain clone from GitHub - those builds ship no keys.
        if is_owner:
            with open(dist_keygen_path, 'w', encoding='utf-8') as f:
                f.write(keygen_code)

        # 3. Build the release binary (only the main target). No source edits are
        #    made, so there is nothing sensitive that could be left behind.
        print("[INFO] Запуск компиляции (Release mode)...")
        cargo_env = os.environ.copy()
        cargo_env["AG_FULL_VERSION"] = version
        home = os.path.expanduser("~")
        cargo_home = os.environ.get("CARGO_HOME") or os.path.join(home, ".cargo")
        cargo_env.pop("RUSTFLAGS", None)
        cargo_env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
            config_rustflags("x86_64-pc-windows-msvc")
            + remap_prefix_flags(home, os.getcwd(), cargo_home))
        # Named explicitly so that a CARGO_TARGET_DIR in the environment is ignored:
        # the prune below deletes every unit this build did not use, which in a
        # directory shared with other projects would be all of theirs. In the repo,
        # not on a faster system drive: measured, the same cold build ran within 3%
        # on the owner's HDD and NVMe - rustc is CPU-bound once the OS caches files.
        target_dir = os.path.abspath("target")
        build = cargo_build(
            ["cargo", "build", "--release", "--bin", "ag_unlocker", "--target-dir", target_dir],
            env=cargo_env,
        )
        built_exe = build.executables.get("ag_unlocker")
        if not built_exe or not os.path.isfile(built_exe):
            raise RuntimeError("cargo не сообщил, где собранный exe")

        os.makedirs("release", exist_ok=True)
        out_path = os.path.abspath(os.path.join("release", f"AG_{version}.exe"))
        # Terminate any running instance of the previous exe to avoid PermissionError
        subprocess.run(["taskkill", "/F", "/IM", f"AG_{version}.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        if os.path.exists(out_path):
            os.remove(out_path)
        # Copy, never move. The exe cargo uplifts is a hardlink to its copy in
        # deps\, which the cache keeps now; moved, the shipped exe would stay one
        # file with the cache's, and whatever touches either touches both.
        shutil.copy2(built_exe, out_path)
        check_shipped_binary(out_path, [home + "\\", "\\.cargo\\registry"], windows=True)

        # Shrink the exe in place; it stays a runnable AG_<ver>.exe.
        if UPX_ENABLED:
            print("[INFO] Сжатие исполняемого файла...")
            compress_exe_inplace(out_path)
        else:
            print("[INFO] UPX-сжатие отключено — отгружается несжатый .exe "
                  "(меньше ложных срабатываний антивирусов).")

        print("\n[УСПЕХ] Сборка завершена!")
        print(f"Ваш исполняемый файл: {out_path}")

        # Provenance record. Written after compression so the hash is of the file
        # that actually ships.
        # Row keyed by the full shipped version (e.g. 2.8.1.1); the token is
        # derived from cargo_version (2.8.1) to match the value baked into the
        # binary, since a 4th version digit doesn't change the canary salt.
        token = release_token(cargo_version)
        ledger = record_canary(version, token, out_path)
        print(f"\n[i] Канарейка релиза: {token}")
        print(f"    Записано в {ledger}. Проверить любой файл/бинарник:")
        print(f"    python tools\\canary_check.py <путь>")

        # The exe is in release\; only now is it known what the cache must keep.
        print()
        print_prune("Windows", target_dir, prune_release_cache(target_dir, build, whole_dir=False))

        # Linux bundle, built via WSL alongside the exe. Best-effort: a machine
        # without WSL/cargo still ships the Windows build above.
        build_linux_bundle(version)

        removed, freed = prune_old_releases("release", version)
        if removed:
            print(f"[INFO] release\\: удалены сборки прошлых версий ({removed} шт., {_mb(freed)}).")
        freed = prune_dev_cache(target_dir, os.path.join(target_dir, "release"))
        if freed:
            print(f"[INFO] target\\ (cargo test, rust-analyzer): удалено {_mb(freed)} того, "
                  f"что не использовалось {DEV_CACHE_KEEP_DAYS} дней.")

        if is_owner:
            print(f"Ваш генератор ключей для этой версии: {dist_keygen_path}")
            print(f"\n[i] Ключи привязаны к версии {cargo_version}: на следующем релизе")
            print("    (после смены VERSION здесь) они перестанут подходить, и людям")
            print("    понадобится новый ключ из t.me/nova_txt.")
            # Auto-generate some keys for convenience.
            print(f"\n5 ключей для версии {cargo_version}:")
            # -B: no __pycache__ left beside the sources for one import.
            subprocess.check_call(["python", "-B", "-c", "import dist_keygen; [print(dist_keygen.generate_key()) for _ in range(5)]"])
        else:
            print("\nДля работы необходим ключ - получить его можно бесплатно в группе t.me/nova_txt")

    except subprocess.CalledProcessError as e:
        # No cache is pruned after a failed build: see "Build caches" above.
        print(f"\n[ОШИБКА] Сборка завершилась с ошибкой: {e}")
    except Exception as e:
        print(f"\n[ОШИБКА] Непредвиденная ошибка сборки: {e}")

if __name__ == "__main__":
    main()
