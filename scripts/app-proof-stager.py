#!/usr/bin/env python3
"""The app proofs' stager: apparatus that runs, for the XCUITest proofs, what their sandbox forbids.

Xcode signs the UI-test runner (VoxAppProofs-Runner.app) into the app sandbox, and every process a
test starts inherits it: a `vox daemon` it starts cannot write its scratch data root, and a test
cannot write a file or listen on a port. `scripts/app-proofs.sh` starts this stager outside the
sandbox, on 127.0.0.1, and passes its port and a token to the tests (TEST_RUNNER_ variables). A
test asks it, one JSON line per request, to:

  {"op": "run",   "args": [...], "env": {...}, "stdin": "..."}   -> {"status": n, "out": "..."}
  {"op": "start", "args": [...], "env": {...}, "until": "...", "within": s}
                                                                    -> {"id": n, "line": "..."}
  {"op": "stop",  "id": n}                                          -> {}
  {"op": "write", "path": "...", "base64": "..."}                   -> {}
  {"op": "echo"}                                                    -> {"port": n}

`args[0]` is the program. A process runs with exactly the `env` given, its stdout and stderr
together in "out". Every request carries the token; one without it is refused. Whatever it
started is stopped, by PID, when it is stopped (SIGTERM) or its connection list ends.

    scripts/app-proof-stager.py <port file> <token>

It writes the port it listens on to <port file> once it listens.
"""

import base64
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

port_file, token = sys.argv[1], sys.argv[2]
started = {}
next_id = [1]
lock = threading.Lock()


def run(req):
    p = subprocess.run(req["args"], env=req.get("env", {}), input=req.get("stdin"),
                       capture_output=True, text=True, timeout=req.get("within", 300))
    return {"status": p.returncode, "out": p.stdout + p.stderr}


def start(req):
    p = subprocess.Popen(req["args"], env=req.get("env", {}), stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    seen = []
    found = threading.Event()
    hit = [""]

    def pump():
        for line in p.stdout:
            seen.append(line)
            if not found.is_set() and line.startswith(req["until"]):
                hit[0] = line.rstrip("\n")
                found.set()

    threading.Thread(target=pump, daemon=True).start()
    with lock:
        pid = next_id[0]
        next_id[0] += 1
        started[pid] = p
    if not found.wait(req.get("within", 30)):
        return {"id": pid, "error": "never said " + json.dumps(req["until"]), "out": "".join(seen),
                "exited": p.poll()}
    return {"id": pid, "line": hit[0]}


def stop(req):
    with lock:
        p = started.pop(req["id"], None)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(30)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    return {}


def write(req):
    os.makedirs(os.path.dirname(req["path"]), exist_ok=True)
    with open(req["path"], "wb") as f:
        f.write(base64.b64decode(req["base64"]))
    return {}


def echo(_req):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)

    def serve(conn):
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)

    def accept():
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return {"port": listener.getsockname()[1]}


OPS = {"run": run, "start": start, "stop": stop, "write": write, "echo": echo}


def handle(conn):
    with conn, conn.makefile("rw") as f:
        for line in f:
            try:
                req = json.loads(line)
                if req.get("token") != token:
                    answer = {"error": "refused: no token"}
                else:
                    answer = OPS[req["op"]](req)
            except Exception as e:  # The test is told; the stager goes on.
                answer = {"error": f"{type(e).__name__}: {e}"}
            f.write(json.dumps(answer) + "\n")
            f.flush()


def stop_all(*_):
    with lock:
        for p in started.values():
            if p.poll() is None:
                p.terminate()
        deadline = time.monotonic() + 30
        for p in started.values():
            try:
                p.wait(max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                p.kill()
    os._exit(0)


signal.signal(signal.SIGTERM, stop_all)
signal.signal(signal.SIGINT, stop_all)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 0))
server.listen(8)
with open(port_file, "w", encoding="utf-8") as f:
    f.write(str(server.getsockname()[1]))
while True:
    c, _ = server.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
