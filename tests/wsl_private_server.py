#!/usr/bin/env python3
"""Focused Linux smoke: python3 tests/wsl_private_server.py /path/to/ag_wsl_launch.

Only the freshly compiled synthetic ELF below is executed. The helper and all
fixtures live in one owned temporary directory under the unchanged actual HOME.
"""
import hashlib
from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    built = Path(sys.argv[1]).resolve(strict=True)
    home = Path(os.environ["HOME"])
    with tempfile.TemporaryDirectory(prefix="ag-launch-smoke-", dir=home / ".cache") as temporary:
        root = Path(temporary)
        install = root / "helper"
        install.mkdir(mode=0o700)
        helper = install / "launch"
        shutil.copyfile(built, helper)
        helper.chmod(0o500)
        source_dir = root / "vendor" / "version-a"
        source_dir.mkdir(parents=True, mode=0o700)
        source = source_dir / "language_server"
        c_source = root / "fixture.c"
        c_source.write_text(r'''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static const char field[] = "ineligible";
static const char proxy[] = "https_proxy";
int main(int argc, char **argv) {
    printf("EXECUTED\n");
    for (int i=0; i<argc; ++i) fwrite(argv[i], 1, __builtin_strlen(argv[i])+1, stdout);
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) return 2;
    const char *values[] = {getenv("HOME"), cwd, getenv("ANTIGRAVITY_VSCODE_HOST"), field, proxy};
    for (int i=0; i<5; ++i) { if (!values[i]) return 3; fwrite(values[i], 1, __builtin_strlen(values[i])+1, stdout); }
    fflush(stdout);
    char buffer[256]; size_t n;
    while ((n=fread(buffer, 1, sizeof(buffer), stdin))) fwrite(buffer, 1, n, stdout);
    return ferror(stdin) ? 4 : 0;
}
''')
        subprocess.run(["cc", "-O0", "-o", source, c_source], check=True, capture_output=True)
        source.chmod(0o555)
        original = source.read_bytes()
        before = (sha(source), source.stat())

        def run(path=source, success=True):
            result = subprocess.run([helper, "--prepare-only", path], stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=10)
            assert (result.returncode == 0) == success, result.stderr.decode()
            if success:
                assert result.stderr == b"", result.stderr
                return json.loads(result.stdout)
            assert result.stdout == b"", result.stdout
            return result.stderr.decode()

        miss = run()
        hit = run()
        assert not miss["cache_hit"] and hit["cache_hit"]
        assert miss["cache_identity"] == hit["cache_identity"]
        output = install / "server-cache" / miss["cache_identity"]
        assert sha(output) == miss["output_sha256"]
        assert output.stat().st_mode & 0o777 == 0o500
        with ThreadPoolExecutor(max_workers=2) as pool:
            concurrent = list(pool.map(lambda _: run(), range(2)))
        assert all(item["cache_hit"] and item["cache_identity"] == miss["cache_identity"]
                   for item in concurrent)

        args = ["space here", "quote'\"", "$HOME;$(echo no)", "", "--standalone"]
        environment = os.environ.copy()
        environment["ANTIGRAVITY_VSCODE_HOST"] = "1"
        child = subprocess.Popen([helper, source, *args], cwd=root, env=environment,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 bufsize=0)
        try:
            assert select.select([child.stdout], [], [], 10)[0], "exec marker timeout"
            assert child.stdout.readline() == b"EXECUTED\n"
            child.stdin.write(b"exclusive-stdin-payload")
            child.stdin.close()
            child.stdin = None
            stdout, stderr = child.communicate(timeout=10)
            assert child.returncode == 0 and not stderr, stderr
            fields = stdout.split(b"\0")
            expected = [str(source), *args, str(home), str(root), "1", "inexigible", "AG_WSLPROXY"]
            assert fields[:-1] == [os.fsencode(s) for s in expected], fields
            assert fields[-1] == b"exclusive-stdin-payload"
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()

        # A same-name cache hit is recomputed from the source and checked exactly.
        output.chmod(0o700)
        output.write_bytes(b"corrupt")
        output.chmod(0o500)
        assert "cache-conflict" in run(success=False)
        output.chmod(0o700)
        output.write_bytes(original.replace(b"ineligible", b"inexigible").replace(b"https_proxy", b"AG_WSLPROXY"))
        output.chmod(0o500)

        link = root / "source-link"
        link.symlink_to(source)
        assert "source-invalid" in run(link, False)
        directory_link = root / "directory-link"
        directory_link.symlink_to(source_dir, target_is_directory=True)
        assert "source-invalid" in run(directory_link / source.name, False)

        unsupported = root / "unsupported"
        unsupported.write_bytes(original.replace(b"ineligible", b"noeligible").replace(b"https_proxy", b"none__proxy"))
        unsupported.chmod(0o500)
        assert "unsupported-profile" in run(unsupported, False)
        applied = root / "applied"
        applied.write_bytes(output.read_bytes())
        applied.chmod(0o500)
        assert "profile-provenance" in run(applied, False)
        wrong_arch = root / "wrong-architecture"
        data = bytearray(original)
        data[18:20] = b"\0\0"
        wrong_arch.write_bytes(data)
        wrong_arch.chmod(0o500)
        assert "unsupported ELF" in run(wrong_arch, False)

        # No source writes occurred through prepare, exec, cache conflict or rejects.
        after = source.stat()
        assert sha(source) == before[0]
        for attr in ("st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
            assert getattr(before[1], attr) == getattr(after, attr), attr

        # The supported vendor writer publishes a new inode with rename.
        update = source_dir / "partial"
        update.write_bytes(original + b"new-version-payload")
        update.chmod(0o555)
        update.replace(source)
        changed = run()
        assert changed["source_sha256"] != miss["source_sha256"]
        assert changed["cache_identity"] != miss["cache_identity"] and not changed["cache_hit"]

        # The cache lock supplies a deterministic preparation barrier: seeing the
        # child's retained lock fd proves it read the source before our mutation.
        lock_path = install / "server-cache" / ".lock"

        def held_preparation(action, expected):
            with lock_path.open("r+b") as held_lock:
                fcntl.flock(held_lock, fcntl.LOCK_EX)
                child = subprocess.Popen([helper, source], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        descriptors = Path(f"/proc/{child.pid}/fd")
                        observed = []
                        for fd in descriptors.iterdir():
                            try:
                                observed.append(os.readlink(fd))
                            except FileNotFoundError:
                                pass  # A concurrently closed descriptor is not the barrier.
                        if str(lock_path) in observed:
                            break
                        assert child.poll() is None and time.monotonic() < deadline, "preparation barrier missing"
                        time.sleep(0.01)
                    action(child)
                    if expected != b"cancelled-before-exec":
                        fcntl.flock(held_lock, fcntl.LOCK_UN)
                        child.wait(timeout=10)  # Keep liveness open until the source check fails.
                    stdout, stderr = child.communicate(timeout=10)
                    assert child.returncode != 0 and stdout == b"", (stdout, stderr)
                    assert expected in stderr, stderr
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate()

        def replace_during_prepare(_):
            update.write_bytes(original + b"concurrent-rename")
            update.chmod(0o555)
            update.replace(source)

        held_preparation(replace_during_prepare, b"source-changed")

        def close_during_prepare(child):
            child.stdin.close()
            child.stdin = None

        held_preparation(close_during_prepare, b"cancelled-before-exec")
        assert not list((install / "server-cache").glob(".partial-*"))
        print(json.dumps({"result": "PASS", "scope": "synthetic-owned-ELF",
                          "source_sha256": miss["source_sha256"], "output_sha256": miss["output_sha256"],
                          "helper_sha256": miss["helper_sha256"],
                          "checks": ["prepare-miss-hit", "retained-fd-exec-argv-home-cwd-env-stdin",
                                     "serialized-concurrent-cache-hits",
                                     "cache-corruption-rejected", "source-and-ancestor-links-rejected",
                                     "unsupported-applied-architecture-rejected", "readonly-source-preserved",
                                     "renamed-update-new-identity", "source-reassociation-no-exec",
                                     "stdin-hangup-during-prepare-no-exec", "no-partial-residue"]}))


if __name__ == "__main__":
    main()
