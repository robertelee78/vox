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
  {"op": "json-host-start", "args": [...], "env": {...}, "cwd": "...", "stderr": "..."}
                                                                    -> {"handle": "opaque"}
  {"op": "json-host-command", "handle": "...", "command": "...", "within": s}
                                                                    -> {"reply": {...}}
  {"op": "json-host-stop", "handle": "..."}                          -> {}

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
import selectors
import math
import uuid
import socket
import subprocess
import sys
import threading
import time

port_file, token = sys.argv[1], sys.argv[2]
started = {}
json_hosts = {}
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


# Native harness apparatus: one persistent stdin/stdout JSON-line conversation per opaque
# child handle. A timeout retires the child so a late reply cannot satisfy the next command.
class JSONHost:
    def __init__(self, req):
        self.gate = threading.Lock()
        self.pending = bytearray()
        self.child = None
        self.close_gate = threading.Lock()
        self.closed = False
        with open(req["stderr"], "xb", buffering=0) as errors:
            self.child = subprocess.Popen(req["args"], env=req["env"], cwd=req["cwd"],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=errors, bufsize=0)
        try:
            os.set_blocking(self.child.stdin.fileno(), False)
            os.set_blocking(self.child.stdout.fileno(), False)
        except Exception:
            self.close()
            raise

    def close(self):
        with self.close_gate:
            if self.closed:
                return
            p = self.child
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(2)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(2)
            p.stdin.close()
            p.stdout.close()
            self.closed = True

    def exchange(self, command, within):
        if not isinstance(command, str) or "\n" in command or "\r" in command:
            raise ValueError("native host command must be one line")
        payload = command.encode("utf-8") + b"\n"
        if len(payload) > 65536:
            raise ValueError("native host command exceeds 64 KiB")
        if not isinstance(within, (int, float)) or not math.isfinite(within) or not 0 < within <= 120:
            raise ValueError("native host response bound must be between 0 and 120 seconds")
        deadline = time.monotonic() + within
        if not self.gate.acquire(timeout=within):
            raise TimeoutError("native host already has a command in progress")
        try:
            if self.child.poll() is not None:
                raise RuntimeError("native host exited before its command")
            with selectors.DefaultSelector() as ready:
                ready.register(self.child.stdin, selectors.EVENT_WRITE)
                sent = 0
                while sent < len(payload):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not ready.select(remaining):
                        raise TimeoutError("native host command was not written within its bound")
                    sent += os.write(self.child.stdin.fileno(), payload[sent:])
                ready.unregister(self.child.stdin)
                ready.register(self.child.stdout, selectors.EVENT_READ)
                while b"\n" not in self.pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not ready.select(remaining):
                        raise TimeoutError("native host did not answer within its bound")
                    chunk = os.read(self.child.stdout.fileno(), 65536)
                    if not chunk:
                        raise RuntimeError("native host closed stdout before answering")
                    self.pending.extend(chunk)
                    if len(self.pending) > 1048576:
                        raise ValueError("native host response exceeds 1 MiB")
            line, _, rest = self.pending.partition(b"\n")
            self.pending = bytearray(rest)
            if rest:
                raise ValueError("native host emitted more than one response for a command")
            reply = json.loads(line)
            if not isinstance(reply, dict):
                raise ValueError("native host response is not a JSON object")
            if reply.get("kind") == "apparatus":
                raise RuntimeError("native host apparatus: " + str(reply.get("error", "unknown failure")))
            return reply
        finally:
            self.gate.release()


def json_host_start(req):
    host = JSONHost(req)
    handle = uuid.uuid4().hex
    with lock:
        json_hosts[handle] = host
    return {"handle": handle}


def json_host_stop(req):
    with lock:
        host = json_hosts.pop(req["handle"], None)
    if host:
        host.close()
    return {}


def json_host_command(req):
    with lock:
        host = json_hosts.get(req["handle"])
    if host is None:
        raise ValueError("unknown or retired native host handle")
    try:
        return {"reply": host.exchange(req["command"], req.get("within", 30))}
    except Exception:
        json_host_stop(req)
        raise


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


OPS = {"run": run, "start": start, "stop": stop, "write": write, "echo": echo,
       "json-host-start": json_host_start, "json-host-command": json_host_command,
       "json-host-stop": json_host_stop}


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
        hosts = list(json_hosts.values())
        json_hosts.clear()
    for host in hosts:
        host.close()
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


def outlive_no_parent():
    """The run that started this stager gone (killed, or ended without stopping it): stop too,
    with everything it started, instead of staying behind under launchd."""
    parent = os.getppid()
    while os.getppid() == parent:
        time.sleep(1)
    stop_all()


threading.Thread(target=outlive_no_parent, daemon=True).start()
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 0))
server.listen(8)
with open(port_file, "w", encoding="utf-8") as f:
    f.write(str(server.getsockname()[1]))
while True:
    c, _ = server.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
