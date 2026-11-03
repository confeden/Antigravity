#!/usr/bin/env python3
"""Windows-only owned companion smoke; no origins, user apps or settings."""
import json
from pathlib import Path
import queue
import socket
import subprocess
import sys
import threading
import time


def trial(executable, invalid_first):
    child = subprocess.Popen([str(executable), "--bind-ip", "127.0.0.1", "--source-ip", "127.0.0.1",
                              "--opening-ms", "10000", "--header-bytes", "4096",
                              "--max-active", "4", "--poll-ms", "5"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             bufsize=0)
    records = queue.Queue()
    history = []
    failures = []

    def read():
        try:
            for line in iter(child.stdout.readline, b""):
                records.put(line.decode("ascii").rstrip("\n"))
        except Exception as error:
            failures.append(type(error).__name__)

    reader = threading.Thread(target=read, name="owned-gateway-status")
    reader.start()
    sockets = []

    def until(predicate):
        deadline = time.monotonic() + 10
        while True:
            item = records.get(timeout=max(0.001, deadline - time.monotonic()))
            history.append(item)
            if predicate(item):
                return item

    try:
        ready = until(lambda line: line.startswith("AGWSLGW1 READY "))
        endpoint = ready.split("endpoint=", 1)[1].split(" ", 1)[0]
        host, port = endpoint.split(":")
        endpoint = (host, int(port))
        if invalid_first:
            child.stdin.write(b"X")
            stopped = until(lambda line: " STOPPING " in line)
            assert "reason=CONTROL_InvalidData action=CLOSE_PARENT_STDIN" in stopped, stopped
        else:
            active = socket.create_connection(endpoint, timeout=2)
            active.settimeout(2)
            sockets.append(active)
            active.sendall(b"CONNECT incomplete")
            # An additional denied local-only request witnesses actual gateway
            # progress while the first request stays incomplete, without origin I/O.
            probe = socket.create_connection(endpoint, timeout=2)
            sockets.append(probe)
            probe.sendall(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
            assert b" 403 " in probe.recv(4096)
            until(lambda line: " CONNECTION " in line)
        child.stdin.write(b"H")
        ack = until(lambda line: "action=RETAIN_PARENT_STDIN" in line)
        assert ack == "AGWSLGW1 STOPPING reason=PARENT_HOLD action=RETAIN_PARENT_STDIN", ack
        assert child.poll() is None
        if not invalid_first:
            assert active.recv(4096) == b"", "accepted incomplete request was not cancelled"
            until(lambda line: " CONNECTION " in line and "result=CANCELLED" in line)
        for reuse in [False, True]:
            with socket.socket() as contender:
                if reuse:
                    contender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    contender.bind(endpoint)
                except OSError:
                    pass
                else:
                    raise AssertionError("HOLD released the advertised reservation")
        child.stdin.write(b"HH")
        # These already queued handshakes are not admitted/parsed after HOLD.
        queued = socket.create_connection(endpoint, timeout=2)
        sockets.append(queued)
        queued.sendall(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
        queued.settimeout(0.15)
        try:
            data = queued.recv(4096)
        except socket.timeout:
            data = None
        assert data is None, data
        assert child.poll() is None
        while True:
            try:
                history.append(records.get_nowait())
            except queue.Empty:
                break
        assert sum("action=RETAIN_PARENT_STDIN" in line for line in history) == 1
        assert not any(" STOPPED " in line or " FAILED " in line for line in history)
        for stream in sockets:
            stream.close()
        sockets.clear()  # Synthetic consumer retirement precedes control EOF.
        child.stdin.close()
        child.stdin = None
        code = child.wait(timeout=10)
        reader.join(timeout=2)
        assert not reader.is_alive() and not failures, failures
        while True:
            try:
                history.append(records.get_nowait())
            except queue.Empty:
                break
        assert (code == 0) == (not invalid_first), (code, history)
        terminal = "FAILED" if invalid_first else "STOPPED"
        assert history[-1].startswith(f"AGWSLGW1 {terminal} policy="), history
        assert sum("action=RETAIN_PARENT_STDIN" in line for line in history) == 1
        return {"invalid_before_hold": invalid_first, "exit": code, "reader_joined": True,
                "hold_acks": 1, "reservation_retained_until_eof": True,
                "active_request_cancelled": not invalid_first, "terminal": terminal}
    finally:
        for stream in sockets:
            stream.close()
        if child.stdin:
            child.stdin.close()
        if child.poll() is None:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()  # Exact creator-retained owned synthetic process only.
                child.wait(timeout=5)
        reader.join(timeout=2)
        if reader.is_alive():
            raise RuntimeError("owned status reader remains pending")
        child.stdout.close()


def main():
    assert sys.platform == "win32", "requires actual Windows sockets/processes"
    executable = Path(sys.argv[1]).resolve(strict=True)
    print(json.dumps({"result": "PASS", "scope": "owned-Windows-HOLD",
                      "trials": [trial(executable, False), trial(executable, True)]}))


if __name__ == "__main__":
    main()
