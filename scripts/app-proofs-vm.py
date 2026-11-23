#!/usr/bin/env python3
"""Run the existing app journey in a headless Tart macOS guest (ADR-014 M-32a).

The VM contains Xcode; this runner installs the pinned Rust toolchain in its account,
copies committed source, and copies results back even when a proof goes red.
No desktop API, clipboard API or host Vox process is used here.
"""
import atexit
import datetime
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import time
import plistlib
import re
import socket
import struct
import tempfile
import pwd

def managed_guest_proof():
    if os.environ.get("VOX_PROOF_VM_GUEST") != "1" or not run(
        ["/usr/sbin/sysctl", "-n", "hw.model"], capture_output=True, text=True
    ).stdout.strip().startswith("VirtualMac"):
        raise RuntimeError("managed daemon proof requires a virtual Mac guest")
    app, scratch = map(Path, sys.argv[2:4])
    mode = sys.argv[4]
    if mode not in ("recovery", "restart"):
        raise RuntimeError("unknown managed guest proof mode")
    helper = app / "Contents/Helpers/vox"
    source = app / "Contents/Library/LaunchAgents/us.vox.daemon.plist"
    target = f"gui/{os.getuid()}/us.vox.daemon"
    domain = f"gui/{os.getuid()}"
    def launch(*args):
        return subprocess.run(["/bin/launchctl", *args], capture_output=True, text=True)
    if launch("print", target).returncode == 0:
        raise RuntimeError(f"{target} already exists; refusing to touch another job")
    fixture = Path(tempfile.mkdtemp(prefix="vox-mg-", dir="/tmp"))
    shipped_defaults = bool(os.environ.get("VOX_PROOF_SHIPPED_DEFAULTS"))
    if shipped_defaults and (mode != "restart" or not os.environ.get("VOX_PROOF_PENDING_START")):
        raise RuntimeError("shipped-default staging requires the pending restart act")
    default_root = (Path(pwd.getpwuid(os.getuid()).pw_dir) / "Library/Application Support/vox"
                    if shipped_defaults else None)
    previous_root = fixture / "previous-default-root"
    root_staged = False
    def restore_default_root():
        if default_root is not None and root_staged:
            if default_root.exists():
                shutil.rmtree(default_root)
            if previous_root.exists():
                previous_root.rename(default_root)
    marker = scratch / "managed-guest-fixture"
    (fixture / "owner.pid").write_text(str(os.getpid()))
    marker.write_text(str(fixture))
    def cleanup_abandoned_fixture():
        if not fixture.exists():
            return
        current = launch("print", target)
        if current.returncode == 0 and str(helper) in current.stdout:
            result = launch("bootout", domain, str(fixture / "job.plist"))
            if result.returncode and launch("print", target).returncode == 0:
                print(f"APPARATUS: cannot boot out owned job: {result.stderr}", file=sys.stderr)
                return
        restore_default_root()
        shutil.rmtree(fixture)
        marker.unlink(missing_ok=True)
    atexit.register(cleanup_abandoned_fixture)
    plist = fixture / "job.plist"
    env = {"HOME": str(fixture), "VOX_DATA_DIR": str(fixture / "data"),
           "VOX_CONFIG_DIR": str(fixture / "config"), "VOX_LISTEN": "127.0.0.1:0",
           "VOX_PROXY": "127.0.0.1:0"}
    if shipped_defaults:
        if default_root.exists():
            default_root.rename(previous_root)
        root_staged = True
        env = {"HOME": str(default_root.parents[2])}
        print(f"[proof] shipped default-root branch: passwd HOME={env['HOME']}; "
              f"data=config={default_root}; no VOX/XDG root overrides", flush=True)
    hold = fixture / "stop-hold"
    daemon_log = fixture / "daemon.stderr"
    gap = bool(os.environ.get("VOX_PROOF_GAP_TIMELINE"))
    news = bool(os.environ.get("VOX_PROOF_LOGIN_ITEM_NEWS"))
    if (gap or news) and (mode != "restart" or shipped_defaults):
        raise RuntimeError("the gap timeline and the news arm need the scratch restart act")
    if mode == "restart" and not shipped_defaults and not gap and not news:
        hold.touch()
        env["VOX_TEST_STOP_HOLD_NODE"] = "default"
        env["VOX_TEST_STOP_HOLD_FILE"] = str(hold)
    if os.environ.get("VOX_PROOF_MANAGER_FIELDS_ABSENT"):
        env["VOX_TEST_MANAGER_FIELDS_ABSENT"] = "1"
    if os.environ.get("VOX_MUTANT_ONESHOT_PENDING_IMMEDIATE"):
        env["VOX_TEST_ONESHOT_PENDING_IMMEDIATE"] = "1"
    for path in ((default_root,) if shipped_defaults else (fixture / "data", fixture / "config")):
        path.mkdir(parents=True)
    job = plistlib.loads(source.read_bytes())
    if job.get("Label") != "us.vox.daemon" or job.get("KeepAlive") != {"SuccessfulExit": False}:
        raise RuntimeError("built bundle does not contain the expected shipped launchd job")
    job.pop("BundleProgram")
    job["Program"] = str(helper)
    job["ProgramArguments"][0] = str(helper)
    if not shipped_defaults:
        job["EnvironmentVariables"] = env
    if mode == "restart" and not shipped_defaults:
        job["StandardErrorPath"] = str(daemon_log)
    if gap:
        job["StandardOutPath"] = str(fixture / "daemon.stdout")
    failure_listener = None
    failure_switch = fixture / "fail-replacement"
    if os.environ.get("VOX_PROOF_FAIL_REPLACEMENT"):
        failure_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        failure_listener.bind(("127.0.0.1", 0))
        address = f"127.0.0.1:{failure_listener.getsockname()[1]}"
        wrapper = fixture / "managed-start"
        wrapper.write_text("#!/bin/sh\nif [ -f " + shlex.quote(str(failure_switch))
                           + " ]; then export VOX_LISTEN=" + shlex.quote(address)
                           + "; fi\nexec \"$@\"\n")
        wrapper.chmod(0o700)
        job["Program"] = str(wrapper)
        job["ProgramArguments"] = [str(wrapper), *job["ProgramArguments"]]
    plist.write_bytes(plistlib.dumps(job))
    control = (default_root if shipped_defaults else fixture / "data") / ".daemon/vox.sock"
    owned = False
    restarter = None
    read_client = None
    one_shot_client = None
    hook_client = None
    stopping_hook = None
    status_client = None
    bootout = None
    extra_pid = None
    caller_log = fixture / "restart-caller.log"
    def interrupted(_sig, _frame):
        raise KeyboardInterrupt
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    def state():
        answer = launch("print", target)
        if answer.returncode:
            raise RuntimeError(f"launchd job disappeared: {answer.stderr}")
        pid = re.search(r"(?m)^\s*pid = (\d+)\s*$", answer.stdout)
        runs = re.search(r"(?m)^\s*runs = (\d+)\s*$", answer.stdout)
        if not runs:
            raise RuntimeError(f"cannot read launchd run count: {answer.stdout}")
        return (int(pid.group(1)) if pid else None, int(runs.group(1)), answer.stdout)
    def until(description, predicate, on_timeout=None):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.02)
        if on_timeout is not None:
            on_timeout()
        raise RuntimeError(f"APPARATUS: watchdog while awaiting {description}; {state()[2]}")
    def frame(s):
        def read(n):
            out = b""
            while len(out) < n:
                chunk = s.recv(n - len(out))
                if not chunk:
                    raise RuntimeError("daemon closed its control frame")
                out += chunk
            return out
        return read(struct.unpack(">I", read(4))[0])
    def greeting():
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(1)
                s.connect(str(control))
                data = frame(s)
                pos = 0
                def item(expected):
                    nonlocal pos
                    head = data[pos]
                    pos += 1
                    if head >> 5 != expected:
                        raise RuntimeError("invalid daemon greeting")
                    value = head & 31
                    if value >= 24:
                        size = {24: 1, 25: 2, 26: 4, 27: 8}[value]
                        value = int.from_bytes(data[pos:pos + size], "big")
                        pos += size
                    return value
                if item(4) != 5 or item(0) != 4000:
                    raise RuntimeError("invalid daemon greeting")
                item(0)
                length = item(3)
                pos += length
                return item(0)
        except (OSError, RuntimeError, IndexError, KeyError):
            return None
    def ready(except_pid=None):
        pid, runs, _ = state()
        return (pid, runs) if pid and pid != except_pid and greeting() == pid else None
    try:
        if os.environ.get("VOX_PROOF_ROOT_PRECEDENCE"):
            passfile = fixture / "roots-passphrase"
            passfile.write_text("\n")
            xdg = {"HOME": str(fixture), "XDG_DATA_HOME": str(fixture / "xdg-data"),
                   "XDG_CONFIG_HOME": str(fixture / "xdg-config")}
            overridden = {**xdg, "VOX_DATA_DIR": str(fixture / "env-data"),
                          "VOX_CONFIG_DIR": str(fixture / "env-config")}
            cases = [
                ("xdg-proof", xdg, []), ("env-proof", overridden, []),
                ("arg-proof", overridden,
                 ["--data-dir", str(fixture / "arg-data"),
                  "--config-dir", str(fixture / "arg-config")]),
            ]
            for name, environment, flags in cases:
                made = subprocess.run(
                    [str(helper), "node", "create", name, "--passphrase-file", str(passfile), *flags],
                    env=environment, capture_output=True, text=True, timeout=120)
                if made.returncode:
                    raise RuntimeError(f"APPARATUS: root precedence node setup failed: {made.stdout}{made.stderr}")
            for name, environment, flags in cases:
                listed = subprocess.run([str(helper), "node", "list", *flags], env=environment,
                                        capture_output=True, text=True, timeout=30)
                print(f"[proof] root precedence {name} exit={listed.returncode}:\n"
                      f"{listed.stdout}{listed.stderr}", flush=True)
                if (listed.returncode or name not in listed.stdout
                        or any(other in listed.stdout for other, _, _ in cases if other != name)):
                    raise RuntimeError(f"PRODUCT: profile roots did not honor precedence: {listed.stdout}{listed.stderr}")
        if os.environ.get("VOX_PROOF_SLOW_HOOK_CHECK"):
            env.pop("VOX_TEST_STOP_HOLD_NODE", None)
            env.pop("VOX_TEST_STOP_HOLD_FILE", None)
            hold.unlink(missing_ok=True)
            passfile = fixture / "passphrase"
            passfile.write_text("\n")
            made = subprocess.run(
                [str(helper), "node", "create", "default", "--passphrase-file", str(passfile)],
                env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
            if made.returncode:
                raise RuntimeError(f"APPARATUS: hook node staging failed: {made.stdout}{made.stderr}")
            setup_pid = greeting()
            if setup_pid is not None:
                with socket.socket(socket.AF_UNIX) as s:
                    s.settimeout(10)
                    s.connect(str(control))
                    frame(s)
                    request = bytes.fromhex("8119100c")
                    s.sendall(struct.pack(">I", len(request)) + request)
                    if frame(s) != bytes.fromhex("81190fa6"):
                        raise RuntimeError("APPARATUS: setup daemon did not acknowledge Stop")
                def setup_exited():
                    process = subprocess.run(
                        ["/bin/ps", "-p", str(setup_pid), "-o", "stat="],
                        capture_output=True, text=True)
                    return not process.stdout.strip() or process.stdout.strip().startswith("Z")
                until("setup daemon exits before the hook", setup_exited)
            hold.touch()
            env["VOX_TEST_LOGIN_ITEM_CHECK_HOLD"] = str(hold)
            began = time.monotonic()
            answer = subprocess.run(
                [str(helper), "agent", "hook", "--node", "default"],
                input=json.dumps({"hook_event_name": "UserPromptSubmit",
                                  "session_id": "rg9-slow-login-item-check"}),
                env=env, capture_output=True, text=True, timeout=30)
            words = answer.stdout + answer.stderr
            print(f"[proof] slow hook check exit={answer.returncode}, "
                  f"elapsed={time.monotonic() - began:.3f}s:\n{words}", flush=True)
            if not hold.with_suffix(".entered").is_file():
                raise RuntimeError("APPARATUS: hook did not enter the staged login-item check")
            if (answer.returncode or "the login-item startup check did not finish; no daemon was started" not in answer.stdout
                    or "ask the operator to restart" in answer.stdout
                    or "waiting for the daemon restart" in words or "Vox is preparing node" in words
                    or greeting() is not None or launch("print", target).returncode == 0):
                raise RuntimeError(f"PRODUCT: slow login-item check falsely promised a restart: {words}")
            return
        boot = launch("bootstrap", domain, str(plist))
        if boot.returncode:
            raise RuntimeError(f"bootstrap failed: {boot.stderr}")
        owned = True
        first, first_runs = until("initial managed daemon", ready)
        print(f"[proof] initial launchd state:\n{state()[2]}", flush=True)
        if shipped_defaults:
            # Only the helper path differs from the shipped job; no environment or log keys.
            os.kill(first, signal.SIGTERM)
        passfile = fixture / "passphrase"
        passfile.write_text("\n")
        for args in (() if shipped_defaults else (
                ["node", "create", "default", "--passphrase-file", str(passfile)],
                ["node", "attach", "default", "--passphrase-file", str(passfile)])):
            staged = subprocess.run([str(helper), *args], env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=120)
            print(f"[proof] vox {' '.join(args)} exit={staged.returncode}\n"
                  f"{staged.stdout}{staged.stderr}", flush=True)
            if staged.returncode:
                raise RuntimeError(f"APPARATUS: could not stage node: {staged.stdout}{staged.stderr}")
        if not shipped_defaults and ready() != (first, first_runs):
            raise RuntimeError("APPARATUS: staging did not retain the initial managed daemon")
        if news:
            login_item_news(helper, env, fixture, state, greeting, until)
            return
        if gap:
            gap_timeline(helper, env, fixture, control, daemon_log, state, greeting, plist)
            return
        if mode == "restart" and not shipped_defaults:
            restart_log_start = daemon_log.stat().st_size if daemon_log.exists() else 0
            with caller_log.open("w+") as output:
                restarter = subprocess.Popen([str(helper), "daemon", "--restart"], env=env,
                                             stdin=subprocess.DEVNULL, stdout=output,
                                             stderr=subprocess.STDOUT)
                def held():
                    if daemon_log.exists() and "test holding stop of node default" in daemon_log.read_text():
                        return True
                    if restarter.poll() is not None:
                        output.flush()
                        raise RuntimeError(f"APPARATUS: restart caller exited before daemon held stop: "
                                           f"{caller_log.read_text()}")
                    pid, runs, text = state()
                    if pid != first or runs != first_runs:
                        raise RuntimeError(f"APPARATUS: initial daemon changed before stop hold: {text}")
                    return False
                until("daemon stop hold", held)
                print(f"[proof] daemon stop hold reached:\n{daemon_log.read_text()}", flush=True)
                if restarter.poll() is not None:
                    raise RuntimeError("APPARATUS: restart caller exited before it could be killed")
                restarter.kill()
                restarter.wait()
                print(f"[proof] killed restart caller exit={restarter.returncode}", flush=True)
            if os.environ.get("VOX_PROOF_HOOK_STOP_DETECTION"):
                stopped_hook_log = fixture / "stopping-hook.log"
                with stopped_hook_log.open("w") as output:
                    stopping_hook = subprocess.Popen(
                        [str(helper), "agent", "hook", "--node", "default"],
                        env=env, stdin=subprocess.PIPE, stdout=output,
                        stderr=subprocess.STDOUT, text=True)
                    stopping_hook.stdin.write(json.dumps({
                        "hook_event_name": "UserPromptSubmit", "session_id": "rg9-stopping-login-item"}))
                    stopping_hook.stdin.close()
                until("stopping hook detection or exit",
                      lambda: "waiting for the daemon restart" in stopped_hook_log.read_text()
                      or stopping_hook.poll() is not None)
                stopped_hook_words = stopped_hook_log.read_text()
                print(f"[proof] managed stopping-refusal detection:\n{stopped_hook_words}", flush=True)
                if "waiting for the daemon restart" not in stopped_hook_words:
                    raise RuntimeError(f"PRODUCT: hook did not follow the stopping daemon: {stopped_hook_words}")
            if failure_listener is not None:
                failure_switch.touch()
                read_log = fixture / "failing-replacement-client.log"
                with read_log.open("w+") as output:
                    read_client = subprocess.Popen([str(helper), "room", "list", "--node", "default"],
                                                   env=env, stdin=subprocess.DEVNULL, stdout=output,
                                                   stderr=subprocess.STDOUT)
                    until("stopping client wait or refusal",
                          lambda: "waiting for the login item" in read_log.read_text()
                          or read_client.poll() is not None)
                    hold.unlink(missing_ok=True)
                    until("client end or repeated failed replacement runs",
                          lambda: read_client.poll() is not None or state()[1] > first_runs + 2)
                    current, runs, manager = state()
                    text = read_log.read_text()
                    failed = daemon_log.read_text()
                    print(f"[proof] failing replacement client exit={read_client.poll()}, runs={runs}:\n"
                          f"{text}\nmanager:\n{manager}\ndaemon:\n{failed}", flush=True)
                    if "address already in use" not in failed.lower():
                        raise RuntimeError("APPARATUS: replacement did not hit the staged occupied listen port")
                    if (read_client.poll() is None or read_client.returncode == 0
                            or "replacement daemon exited before it answered" not in text):
                        raise RuntimeError("PRODUCT: client followed failed replacement runs instead of ending truthfully: "
                                           + text + "\n" + manager)
                return
        if mode == "restart" and os.environ.get("VOX_PROOF_PENDING_START"):
            hold.unlink(missing_ok=True)
            def scheduled():
                pid, runs, text = state()
                return text if pid is None and "state = spawn scheduled" in text else None
            pending = until("young daemon's scheduled spawn", scheduled)
            print(f"[proof] pending before ensure_daemon:\n{pending}", flush=True)
            if not shipped_defaults:
                hook_log = fixture / "pending-hook.log"
                with hook_log.open("w") as output:
                    hook_client = subprocess.Popen(
                        [str(helper), "agent", "hook", "--node", "default"],
                        env=env, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT,
                        text=True)
                    hook_client.stdin.write(json.dumps({"hook_event_name": "UserPromptSubmit",
                                                        "session_id": "rg9-pending-login-item"}))
                    hook_client.stdin.close()
                until("pending hook detection or exit",
                      lambda: "waiting for the daemon restart" in hook_log.read_text()
                      or hook_client.poll() is not None)
                hook_words = hook_log.read_text()
                if state()[0:2] != (None, first_runs):
                    raise RuntimeError("APPARATUS: replacement started before pending hook detection")
                if "waiting for the daemon restart" not in hook_words:
                    raise RuntimeError(f"PRODUCT: hook did not detect the pending manager: {hook_words}")
                print(f"[proof] pending hook detection:\n{hook_words}", flush=True)
                one_shot_log = fixture / "pending-one-shot.log"
                with one_shot_log.open("w") as output:
                    one_shot_client = subprocess.Popen(
                        [str(helper), "room", "list", "--node", "default"],
                        env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
                status_log = fixture / "pending-status.log"
                with status_log.open("w") as output:
                    status_client = subprocess.Popen(
                        [str(helper), "status", "--node", "default"],
                        env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
                until("one-shot manager wait or refusal",
                      lambda: "waiting for the login item" in one_shot_log.read_text()
                      or one_shot_client.poll() is not None)
                one_shot_text = one_shot_log.read_text()
                if one_shot_client.poll() is not None:
                    raise RuntimeError(f"PRODUCT: one-shot did not wait for the pending daemon: {one_shot_text}; status: {status_log.read_text()}")
                if state()[0:2] != (None, first_runs):
                    raise RuntimeError("APPARATUS: replacement started before one-shot wait was observed")
                until("status manager wait or refusal",
                      lambda: "waiting for the login item" in status_log.read_text()
                      or status_client.poll() is not None)
                if status_client.poll() is not None:
                    raise RuntimeError(f"PRODUCT: status did not wait for the pending daemon: {status_log.read_text()}")
                if state()[0:2] != (None, first_runs):
                    raise RuntimeError("APPARATUS: replacement started before status wait was observed")
            read_log = fixture / "pending-start-client.log"
            with read_log.open("w+") as output:
                read_client = subprocess.Popen([str(helper), "daemon", "--detach"],
                                               env=env, stdin=subprocess.DEVNULL, stdout=output,
                                               stderr=subprocess.STDOUT)
                until("ensure_daemon client ends", lambda: read_client.poll() is not None)
                hello = greeting()
                manager_pid, runs, manager = state()
                if hello is not None and hello != manager_pid:
                    extra_pid = hello
                if extra_pid is not None:
                    until("manager attempts its replacement", lambda: state()[1] > first_runs)
                    manager_pid, runs, manager = state()
                    processes = subprocess.run(
                        ["/bin/ps", "-o", "pid,ppid,stat,command", "-p",
                         f"{extra_pid},{manager_pid}"], capture_output=True, text=True)
                    print(f"[proof] competing processes:\n{processes.stdout}{processes.stderr}", flush=True)
                text = read_log.read_text()
                if hook_client is not None:
                    hook_client.wait(timeout=120)
                    hook_words = hook_log.read_text()
                    print(f"[proof] pending hook exit={hook_client.returncode}:\n{hook_words}", flush=True)
                    if hook_client.returncode:
                        raise RuntimeError(f"PRODUCT: pending hook failed: {hook_words}")
                if stopping_hook is not None:
                    stopping_hook.wait(timeout=120)
                    print(f"[proof] stopping hook exit={stopping_hook.returncode}:\n"
                          f"{stopped_hook_log.read_text()}", flush=True)
                    if stopping_hook.returncode:
                        raise RuntimeError("PRODUCT: managed stopping hook failed")
                if status_client is not None:
                    status_client.wait(timeout=120)
                    status_text = status_log.read_text()
                    print(f"[proof] pending status exit={status_client.returncode}:\n{status_text}", flush=True)
                    if (status_client.returncode
                            or "waiting for the login item to start or replace the daemon" not in status_text
                            or not any(line.startswith("node default") for line in status_text.splitlines())):
                        raise RuntimeError(f"PRODUCT: pending status did not wait and report its node: {status_text}")
                if one_shot_client is not None:
                    one_shot_client.wait(timeout=120)
                    one_shot_text = one_shot_log.read_text()
                    print(f"[proof] pending one-shot exit={one_shot_client.returncode}:\n"
                          f"{one_shot_text}", flush=True)
                    if (one_shot_client.returncode
                            or "waiting for the login item to start or replace the daemon" not in one_shot_text):
                        raise RuntimeError(f"PRODUCT: pending one-shot did not wait and succeed: {one_shot_text}")
                    if state()[0:2] != (manager_pid, runs) or greeting() != manager_pid:
                        raise RuntimeError("PRODUCT: one-shot did not use the manager's one replacement")
                print(f"[proof] pending-start client exit={read_client.returncode}; greeting={hello}; "
                      f"manager pid={manager_pid}; runs={runs}:\n{text}\n{manager}", flush=True)
                if "waiting for the login item to start or replace the daemon" not in text:
                    raise RuntimeError(f"PRODUCT: pending manager wait did not say what it awaits: {text}")
                if (read_client.returncode != 0 or hello != manager_pid
                        or manager_pid == first or runs != first_runs + 1):
                    raise RuntimeError("PRODUCT: ensure_daemon raced the manager's pending replacement: "
                                       + text + "\n" + manager)
            return
        if mode == "restart":
            if os.environ.get("VOX_PROOF_REMOVE_MANAGER"):
                read_log = fixture / "stopping-client.log"
                with read_log.open("w+") as output:
                    read_client = subprocess.Popen([str(helper), "room", "list", "--node", "default"],
                                                   env=env, stdin=subprocess.DEVNULL, stdout=output,
                                                   stderr=subprocess.STDOUT)
                    until("stopping client wait or refusal",
                          lambda: "waiting for the login item" in read_log.read_text()
                          or read_client.poll() is not None)
                    paused = read_client.poll() is None
                    if paused:
                        os.kill(read_client.pid, signal.SIGSTOP)
                    bootout = subprocess.Popen(["/bin/launchctl", "bootout", target],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    hold.unlink(missing_ok=True)
                    _, error = bootout.communicate(timeout=120)
                    if bootout.returncode:
                        raise RuntimeError(f"APPARATUS: cannot remove owned manager: {error!r}")
                    owned = False
                    print("[proof] owned launchd job booted out during the client wait", flush=True)
                    if paused:
                        os.kill(read_client.pid, signal.SIGCONT)
                    result = read_client.wait(timeout=120)
                    text = read_log.read_text()
                    print(f"[proof] missing-manager client exit={result}:\n{text}", flush=True)
                    if (result == 0 or "the daemon was stopped; its login item is not starting a replacement" not in text
                            or "test omitting manager phase" not in text):
                        raise RuntimeError(f"PRODUCT: removed-manager wait did not give the current state and fallback: {text}")
                return
            hold.unlink(missing_ok=True)
            def restarted():
                pid, runs, text = state()
                hello = greeting()
                if runs > first_runs + 1 or (pid and pid != first and runs != first_runs + 1):
                    raise RuntimeError(f"PRODUCT: restart created more than one replacement run: {text}")
                return (pid, runs) if pid and pid != first and runs == first_runs + 1 and hello == pid else None
            def restart_timeout():
                pid, _, text = state()
                if not pid and re.search(r"last exit code = 0\b", text) and greeting() is None:
                    raise RuntimeError(f"PRODUCT: killed caller left launchd inactive with exit 0 and no greeting: {text}")
            second, second_runs = until("managed replacement after caller death", restarted, restart_timeout)
            print(f"[proof] replacement before any client:\n{state()[2]}", flush=True)
            stopped_log = daemon_log.read_bytes()[restart_log_start:].decode(errors="replace")
            print(f"[proof] daemon log through replacement:\n{stopped_log}", flush=True)
            if "stopped by SIGTERM" not in stopped_log:
                raise RuntimeError("PRODUCT: launchd replaced the daemon without its clean "
                                   f"stopped-by-SIGTERM line:\n{stopped_log}")
            status = subprocess.run([str(helper), "status", "--node", "default"], env=env,
                                    capture_output=True, text=True, timeout=90)
            print(f"[proof] vox status exit={status.returncode}\n{status.stdout}{status.stderr}", flush=True)
            if status.returncode or not status.stdout.lower().startswith("node "):
                raise RuntimeError(f"PRODUCT: status failed after restart: {status.stdout}{status.stderr}")
            current, runs, text = state()
            if current != second or runs != second_runs or greeting() != second:
                raise RuntimeError(f"PRODUCT: status did not use the single replacement daemon: {text}")
            return
        os.kill(first, signal.SIGTERM)
        def recovered():
            pid, runs, text = state()
            if not pid and re.search(r"last exit code = 0\b", text):
                raise RuntimeError(f"PRODUCT: foreign TERM exited successfully and launchd did not restart it: {text}")
            return (pid, runs) if pid and pid != first and greeting() == pid else None
        second, second_runs = until("launchd replacement after foreign TERM", recovered)
        print(f"[proof] recovered launchd state:\n{state()[2]}", flush=True)
        print(f"[proof] foreign TERM: launchd replaced {first} with {second} without a client")
        status = subprocess.run([str(helper), "status", "--node", "default"], env=env,
                                capture_output=True, text=True, timeout=90)
        print(f"[proof] vox status exit={status.returncode}\n{status.stdout}{status.stderr}", flush=True)
        if status.returncode or not status.stdout.lower().startswith("node "):
            raise RuntimeError(f"PRODUCT: vox status failed after launchd recovery: {status.stdout}{status.stderr}")
        current, runs, text = state()
        if current != second or runs != second_runs or greeting() != second:
            raise RuntimeError(f"PRODUCT: status did not use the recovered daemon: {text}")
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(10)
            s.connect(str(control))
            frame(s)
            request = bytes.fromhex("8119100c")
            s.sendall(struct.pack(">I", len(request)) + request)
            if frame(s) != bytes.fromhex("81190fa6"):
                raise RuntimeError("PRODUCT: explicit Stop was not acknowledged")
        print("[proof] public wire Stop acknowledged", flush=True)
        def stopped():
            pid, runs, text = state()
            return (runs, text) if not pid and re.search(r"last exit code = 0\b", text) else None
        stopped_runs, stopped_text = until("successful explicit Stop", stopped)
        if stopped_runs != second_runs or state()[1] != stopped_runs:
            raise RuntimeError(f"PRODUCT: launchd restarted explicit Stop: {stopped_text}")
        for _ in range(30):
            time.sleep(.1)
            pid, runs, text = state()
            if pid or runs != stopped_runs:
                raise RuntimeError(f"PRODUCT: launchd restarted explicit Stop: {text}")
        print(f"[proof] explicit Stop: launchd reports exit 0, no pid, {stopped_runs} runs")
        print(f"[proof] stopped launchd state:\n{state()[2]}", flush=True)
    finally:
        if restarter is not None and restarter.poll() is None:
            restarter.kill()
            restarter.wait()
        if read_client is not None and read_client.poll() is None:
            read_client.kill()
            read_client.wait()
        if one_shot_client is not None and one_shot_client.poll() is None:
            one_shot_client.kill()
            one_shot_client.wait()
        if hook_client is not None and hook_client.poll() is None:
            hook_client.kill()
            hook_client.wait()
        for child in (stopping_hook, status_client):
            if child is not None and child.poll() is None:
                child.kill()
                child.wait()
        if bootout is not None and bootout.poll() is None:
            hold.unlink(missing_ok=True)
            bootout.communicate(timeout=120)
        hold.unlink(missing_ok=True)
        if extra_pid is not None:
            try:
                os.kill(extra_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        if owned:
            result = launch("bootout", domain, str(plist))
            if result.returncode and launch("print", target).returncode == 0:
                raise RuntimeError(f"APPARATUS: could not boot out owned job: {result.stderr}")
            print("[proof] owned launchd job booted out", flush=True)
        if failure_listener is not None:
            failure_listener.close()
        if restarter is not None and caller_log.exists():
            print(f"[proof] restart caller output:\n{caller_log.read_text()}", flush=True)
        restore_default_root()
        shutil.rmtree(fixture)
        marker.unlink(missing_ok=True)


def login_item_news(helper, env, fixture, state, greeting, until):
    """ADR-052 RG-9 on a Mac's login item: a prompt typed while launchd restarts the daemon.

    A daemon that has run past launchd's minimum runtime is replaced at once, so the prompt's
    turn carries the other member's news, with one launchd generation, after a crash, `vox
    daemon --restart` (one `kickstart -k`) and the update's handoff (the same `kickstart -k` onto
    a swapped helper). A replacement killed as launchd spawns it waits for launchd's throttled
    spawn ("spawn scheduled"); a prompt answered before any replacement greets gets the truthful
    deferral and the NEXT turn has the news.
    """
    news = "news across the restart"
    deferral = "your rooms show from your next turn"
    restarter = fixture / "vox-restarter"
    shutil.copy2(helper, restarter)
    passfile = fixture / "passphrase"
    room_pass = fixture / "room-passphrase"
    room_pass.write_text("rg9 login item room\n")
    home = fixture / "peer"
    peer = {"HOME": str(home), "VOX_DATA_DIR": str(home / "data"),
            "VOX_CONFIG_DIR": str(home / "config"), "VOX_LISTEN": "127.0.0.1:0",
            "VOX_PROXY": "127.0.0.1:0"}
    (home / "data").mkdir(parents=True)
    (home / "config").mkdir(parents=True)
    hook_env = dict(env)
    if os.environ.get("VOX_MUTANT_HOOK_RESTART_IMMEDIATE"):
        hook_env["VOX_TEST_HOOK_RESTART_IMMEDIATE"] = "1"

    def vox(args, environment=env, stdin=None):
        done = subprocess.run([str(helper), *args], env=environment, input=stdin,
                              stdin=None if stdin is not None else subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)
        print(f"[proof] vox {' '.join(args)} exit={done.returncode}\n{done.stdout}{done.stderr}",
              flush=True)
        return done

    def staged(args, environment=env, stdin=None):
        done = vox(args, environment, stdin)
        if done.returncode:
            raise RuntimeError(f"APPARATUS: staging `vox {' '.join(args)}` failed")
        return done.stdout + done.stderr

    def fingerprint(environment):
        found = re.findall(r"\b[a-z2-7]{52}\b", staged(["node", "list"], environment))
        if not found:
            raise RuntimeError("APPARATUS: no node fingerprint listed")
        return found[0]

    # The other member: its own scratch account and client-started daemon on this guest.
    staged(["node", "create", "default", "--passphrase-file", str(passfile)], peer)
    staged(["daemon", "--detach"], peer)
    own, other = fingerprint(env), fingerprint(peer)
    staged(["trust", "add", other, "--name", "peer"])
    staged(["trust", "add", own, "--name", "peer"], peer)
    staged(["room", "create", "--name", "rg9", "--node", "default",
            "--passphrase-file", str(room_pass)])
    rooms = re.findall(r"(?m)^([a-z2-7]{12})\b", staged(["room", "list", "--node", "default"]))
    if not rooms:
        raise RuntimeError("APPARATUS: the created room is not listed")
    room = rooms[0]
    link = next((line for line in staged(["room", "link", room]).splitlines()
                 if line.startswith("vox://")), None)
    if link is None:
        raise RuntimeError("APPARATUS: no room link")
    staged(["room", "join", "--passphrase-file", "-", link], peer, room_pass.read_text())
    staged(["room", "post", room, news], peer)
    until("the other member's news on this node",
          lambda: news in subprocess.run([str(helper), "room", "read", room, "--node", "default"],
                                         env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                         text=True, timeout=60).stdout)
    minimum = int(re.search(r"(?m)^\s*minimum runtime = (\d+)\s*$", state()[2]).group(1))

    def age(pid):
        text = subprocess.run(["/bin/ps", "-o", "etime=", "-p", str(pid)],
                              capture_output=True, text=True).stdout.strip()
        if not text:
            return None
        days, _, rest = text.rpartition("-")
        parts = [int(p) for p in rest.split(":")]
        while len(parts) < 3:
            parts.insert(0, 0)
        return (int(days) if days else 0) * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]

    def alive(pid):
        stat = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)],
                              capture_output=True, text=True).stdout.strip()
        return bool(stat) and not stat.startswith("Z")

    def hook(session):
        child = subprocess.Popen([str(helper), "agent", "hook", "--node", "default", "--room", room],
                                 env=hook_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        return child, json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": session})

    def turn(kind, session):
        """Restart the login item's daemon as `kind` and type a prompt while it is replaced."""
        old, runs, _ = state()
        lived = age(old)
        began = time.monotonic()
        caller = None
        if kind in ("crash", "young"):
            os.kill(old, signal.SIGKILL)
        if kind == "young":
            # The replacement crashes as launchd spawns it: launchd holds the next spawn until
            # its minimum runtime since this spawn has passed.
            killed = old
            spawned = until("launchd spawns the replacement",
                            lambda: (lambda pid: pid if pid and pid != killed else None)(state()[0]))
            lived, runs = age(spawned) or 0, state()[1]

            def crashed():
                # Until launchd's xpcproxy (root) has become the job's own process, it is not ours.
                try:
                    os.kill(spawned, signal.SIGKILL)
                except PermissionError:
                    return False
                return True
            until("launchd's spawn becomes the job's own process", crashed)
            old, began = spawned, time.monotonic()
        elif kind != "crash":
            caller = subprocess.Popen([str(restarter), "daemon", "--restart"], env=env,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True)
            until("launchd stops the old daemon",
                  lambda: "state = SIGTERMed" in state()[2] or not alive(old))
        typed = time.monotonic()
        child, prompt = hook(session)
        phases = []
        greeted = []
        import threading
        watching = threading.Event()

        def watch():
            last = None
            while not watching.is_set():
                pid, count, text = state()
                phase = re.search(r"(?m)^\s*state = (.+)$", text).group(1).strip()
                if (phase, pid, count) != last:
                    phases.append((round((time.monotonic() - began) * 1000), phase, pid, count))
                    last = (phase, pid, count)
                if not greeted and pid and pid != old and greeting() == pid:
                    greeted.append(time.monotonic())
                time.sleep(.02)
        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        out, err = child.communicate(prompt, timeout=120)
        answered = time.monotonic()
        said = caller.communicate(timeout=120)[0] if caller else ""
        until("launchd's replacement greets", lambda: (lambda pid: pid and pid != old and greeting() == pid)(state()[0]))
        until("the watcher sees the greeting", lambda: greeted)
        watching.set()
        watcher.join(timeout=5)
        new, after, text = state()
        before_greeting = answered < greeted[0]
        print(f"[proof] {kind}: old pid {old} had run {lived}s (launchd minimum runtime {minimum}s); "
              f"prompt typed at +{round((typed - began) * 1000)}ms, answered at "
              f"+{round((answered - began) * 1000)}ms; replacement greeted at "
              f"+{round((greeted[0] - began) * 1000)}ms; launchd runs {runs} -> {after}, pid {new}; "
              f"greeting {greeting()}\n[proof] launchd phases (ms, state, pid, runs): {phases}\n"
              f"[proof] hook exit={child.returncode} stdout:\n{out}\n[proof] hook stderr:\n{err}"
              f"[proof] restart caller:\n{said}", flush=True)
        if typed >= greeted[0]:
            raise RuntimeError(f"APPARATUS: the prompt was typed after the {kind} replacement greeted")
        if after != runs + 1 or new == old or greeting() != new:
            raise RuntimeError(f"PRODUCT: the {kind} restart did not leave one launchd generation: {text}")
        return lived, phases, out, child.returncode, before_greeting

    def ready_next_turn(session):
        until("the replacement's room serves", lambda: news in subprocess.run(
            [str(helper), "room", "read", room, "--node", "default"], env=env,
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60).stdout)
        child, prompt = hook(session)
        out, err = child.communicate(prompt, timeout=120)
        print(f"[proof] next turn of {session}: exit={child.returncode}\n{out}\n{err}", flush=True)
        return out

    def mature():
        pid = state()[0]
        until(f"the login item's daemon outlives launchd's {minimum}s minimum runtime",
              lambda: (age(pid) or 0) > minimum)

    def same_turn(kind, session):
        mature()
        lived, _, out, code, _ = turn(kind, session)
        if lived <= minimum:
            raise RuntimeError(f"APPARATUS: the {kind} daemon was not past launchd's minimum runtime")
        if code or news not in out or deferral in out:
            raise RuntimeError(f"PRODUCT: a prompt during a {kind} restart of a login-item daemon "
                               f"that had run {lived}s did not get the other member's news in "
                               f"that turn: {out}")
        print(f"[proof] {kind}: the prompt's own turn carried the other member's news", flush=True)

    # A crash first: its prompt finds no socket, so the hook's admission sees launchd's pending
    # job. `vox daemon --restart` next: its prompt meets the old daemon still stopping.
    same_turn("crash", "rg9-login-item-crash")
    same_turn("restart", "rg9-login-item-restart")
    lived, phases, out, code, before_greeting = turn("young", "rg9-login-item-young")
    if lived >= minimum or not any(phase == "spawn scheduled" for _, phase, _, _ in phases):
        raise RuntimeError(f"APPARATUS: the young replacement was not throttled by launchd: {phases}")
    if not before_greeting:
        raise RuntimeError("APPARATUS: launchd's throttled spawn greeted before the prompt's bound; "
                           "the deferral case was not staged")
    # Answered before any replacement greeted, the turn cannot carry news: it must say so.
    if code or deferral not in out or news in out:
        raise RuntimeError(f"PRODUCT: a prompt during launchd's throttled respawn did not get "
                           f"the truthful deferral: {out}")
    if news not in ready_next_turn("rg9-login-item-young"):
        raise RuntimeError("PRODUCT: the deferred turn's news did not reach the next turn")
    print("[proof] young: launchd held the spawn ('spawn scheduled'); the prompt was answered "
          "before any replacement greeted, deferred truthfully, and its next turn carried the news",
          flush=True)
    # The update's handoff: the same kickstart -k onto a helper swapped under the running daemon.
    swapped = fixture / "vox-next"
    shutil.copy2(restarter, swapped)
    signed = subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier",
                             "us.vox.rg9.next", str(swapped)], capture_output=True, text=True)
    if signed.returncode:
        raise RuntimeError(f"APPARATUS: could not make the swapped helper: {signed.stderr}")
    os.replace(swapped, helper)
    same_turn("update", "rg9-login-item-update")


def gap_timeline(helper, env, fixture, control, daemon_log, state, greeting, plist):
    """Time each segment of a login item's daemon restart; staging and observation only."""
    import threading
    started_wall = datetime.datetime.now()
    daemon_out = fixture / "daemon.stdout"
    restarter_copy = fixture / "vox-restarter"
    shutil.copy2(helper, restarter_copy)

    def say(text):
        print(text, flush=True)

    def vox(*args, binary=helper, timeout=120):
        done = subprocess.run([str(binary), *args], env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=timeout)
        say(f"[gap] vox {' '.join(args)} exit={done.returncode}\n{done.stdout}{done.stderr}")
        return done

    def age(pid):
        text = subprocess.run(["/bin/ps", "-o", "etime=", "-p", str(pid)],
                              capture_output=True, text=True).stdout.strip()
        if not text:
            return None
        days, _, rest = text.rpartition("-")
        parts = [int(p) for p in rest.split(":")]
        while len(parts) < 3:
            parts.insert(0, 0)
        return (int(days) if days else 0) * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]

    def alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        stat = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)],
                              capture_output=True, text=True).stdout.strip()
        return bool(stat) and not stat.startswith("Z")

    # Staging: one room on the passphrase-free node, and a protected node whose passphrase
    # `vox node unlock` keeps in the guest's Keychain, as a person's Mac does.
    room_pass = fixture / "room-passphrase"
    room_pass.write_text("gap room passphrase\n")
    made = vox("room", "create", "--name", "gap", "--node", "default",
               "--passphrase-file", str(room_pass))
    listed = vox("room", "list", "--node", "default")
    found = re.findall(r"\b[a-z2-7]{12,}\b", made.stdout + made.stderr + listed.stdout)
    room = next((candidate for candidate in dict.fromkeys(found)
                 if vox("room", "post", candidate, "before the restarts",
                        "--node", "default").returncode == 0), None)
    if made.returncode or room is None:
        raise RuntimeError("APPARATUS: the gap room could not be staged")
    kept_pass = fixture / "kept-passphrase"
    kept_pass.write_text("gap kept passphrase\n")
    kept = False
    if vox("node", "create", "kept", "--passphrase-file", str(kept_pass)).returncode == 0:
        # A protected node's attach cost (identity unlock) without the Keychain read: the
        # fixture HOME has no keychain, so the daemon cannot remember it across a restart.
        for n in (1, 2, 3):
            began = time.monotonic()
            unlocked = vox("node", "unlock", "kept", "--passphrase-file", str(kept_pass))
            say(f"[gap] protected unlock #{n}: exit={unlocked.returncode} "
                f"elapsed_ms={round((time.monotonic() - began) * 1000)}")
            words = unlocked.stdout + unlocked.stderr
            kept = (unlocked.returncode == 0 and "not remembered" not in words
                    and "no keychain" not in words)
            if n < 3:
                vox("node", "lock", "kept")
    say(f"[gap] protected node remembered across restarts: {kept}")

    def hook(session, log):
        out = log.open("w")
        child = subprocess.Popen([str(helper), "agent", "hook", "--node", "default"], env=env,
                                 stdin=subprocess.PIPE, stdout=out, stderr=subprocess.STDOUT,
                                 text=True)
        child.stdin.write(json.dumps({"hook_event_name": "UserPromptSubmit",
                                      "session_id": session}))
        child.stdin.close()
        out.close()
        return child

    warm = hook("gap-session", fixture / "hook-warm.log")
    warm.wait(timeout=60)
    say(f"[gap] warm-up hook exit={warm.returncode}:\n{(fixture / 'hook-warm.log').read_text()}")

    samples = []

    def sample(kind, n, binary=None, nudge=False):
        old, runs0, before_text = state()
        before_age = age(old)
        events = []
        lock = threading.Lock()
        t0 = time.monotonic()
        t0_wall = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
        stop = threading.Event()

        def record(source, detail, at=None):
            with lock:
                events.append((round(((at or time.monotonic()) - t0) * 1000), source, detail))

        def launchd_poll():
            last = None
            while not stop.is_set():
                at = time.monotonic()
                try:
                    text = state()[2]
                except RuntimeError as error:
                    record("launchd", f"print failed: {error}", at)
                    continue
                fields = "; ".join(line.strip() for line in text.splitlines() if re.match(
                    r"\s*(state|pid|runs|last exit code|immediate reason|last terminating signal)\s*=", line))
                if fields != last:
                    record("launchd", fields, at)
                    last = fields

        def greeting_poll():
            last = "unset"
            while not stop.is_set():
                at = time.monotonic()
                hello = greeting()
                if hello != last:
                    record("greeting", hello, at)
                    last = hello
                time.sleep(.01)

        offsets = {path: (path.stat().st_size if path.exists() else 0)
                   for path in (daemon_log, daemon_out)}

        def log_poll():
            gone = False
            while not stop.is_set():
                at = time.monotonic()
                for path in offsets:
                    if path.exists() and path.stat().st_size > offsets[path]:
                        with path.open("rb") as f:
                            f.seek(offsets[path])
                            data = f.read()
                        end = data.rfind(b"\n") + 1
                        offsets[path] += end
                        for line in data[:end].decode(errors="replace").splitlines():
                            record(path.name, line, at)
                if not gone and not alive(old):
                    record("old", f"pid {old} exited", at)
                    gone = True
                time.sleep(.01)

        threads = [threading.Thread(target=f, daemon=True)
                   for f in (launchd_poll, greeting_poll, log_poll)]
        for thread in threads:
            thread.start()
        restarter = None
        restart_log = fixture / f"restart-{kind}-{n}.log"
        if kind == "crash":
            os.kill(old, signal.SIGKILL)
            record("action", f"SIGKILL to pid {old}")
        elif kind == "signal":
            os.kill(old, signal.SIGTERM)
            record("action", f"foreign SIGTERM to pid {old}")
        else:
            with restart_log.open("w") as out:
                restarter = subprocess.Popen([str(binary or restarter_copy), "daemon", "--restart"],
                                             env=env, stdin=subprocess.DEVNULL, stdout=out,
                                             stderr=subprocess.STDOUT)
            record("action", "vox daemon --restart spawned")

            # The prompt and the command arrive once the old daemon has been told to stop.
            def told():
                with lock:
                    return any(source == "launchd" and "SIGTERMed" in detail
                               for _, source, detail in events) or not alive(old)
            deadline = time.monotonic() + 60
            while not told() and time.monotonic() < deadline:
                time.sleep(.005)
            if nudge:
                # Spike: ask launchd to start the job now while it holds the throttled spawn.
                while time.monotonic() < deadline and not any(
                        source == "launchd" and "spawn scheduled" in (detail or "")
                        for _, source, detail in list(events)):
                    time.sleep(.005)
                full = subprocess.run(["/bin/launchctl", "print", target],
                                      capture_output=True, text=True).stdout
                say(f"[gap] launchctl print while scheduled ({kind} #{n}):\n{full}")
                kicked = subprocess.run(["/bin/launchctl", "kickstart", target],
                                        capture_output=True, text=True)
                record("action", f"launchctl kickstart (no -k) exit={kicked.returncode} "
                       f"{kicked.stdout.strip()} {kicked.stderr.strip()}")
        hook_log = fixture / f"hook-{kind}-{n}.log"
        read_log = fixture / f"read-{kind}-{n}.log"
        hook_child = hook("gap-session", hook_log)
        record("action", "hook spawned")
        with read_log.open("w") as out:
            reader = subprocess.Popen([str(helper), "room", "read", room, "--node", "default"],
                                      env=env, stdin=subprocess.DEVNULL, stdout=out,
                                      stderr=subprocess.STDOUT)
        record("action", "room read spawned")
        ends = {}

        def finished():
            for name, child in (("hook", hook_child), ("read", reader), ("restarter", restarter)):
                if child is not None and name not in ends and child.poll() is not None:
                    record(name, f"exited {child.returncode}")
                    ends[name] = child.returncode
            with lock:
                lines = [d for _, s, d in events if s == daemon_log.name]
                pids = [d for _, s, d in events if s == "greeting" and d not in (None, old)]
            ready = any("node default is Ready" in line for line in lines)
            kept_done = not kept or any(("node kept" in line and ("Ready" in line or "could not" in line))
                                        or "remembered node kept" in line for line in lines)
            return (ready and kept_done and pids and "hook" in ends and "read" in ends
                    and (restarter is None or "restarter" in ends))
        deadline = time.monotonic() + 90
        while not finished() and time.monotonic() < deadline:
            time.sleep(.01)
        complete = finished()
        time.sleep(.3)
        stop.set()
        for thread in threads:
            thread.join(timeout=5)
        for child in (hook_child, reader, restarter):
            if child is not None and child.poll() is None:
                child.kill()
                child.wait()
        new, runs1, after_text = state()
        events.sort(key=lambda event: event[0])

        def first(source, needle=None, after=None):
            for at, s, d in events:
                if s == source and (needle is None or (d is not None and needle(d))) and (after is None or at >= after):
                    return at
            return None
        told_at = 0 if kind in ("crash", "signal") else first("launchd", lambda d: "SIGTERMed" in d)
        exited_at = first("old")
        spawned_at = first("launchd", lambda d: re.search(r"pid = (\d+)", d) is not None
                           and int(re.search(r"pid = (\d+)", d).group(1)) != old)
        serving_at = first("daemon.stdout", lambda d: "serving" in d)
        listening_at = first("greeting", lambda d: d == new)
        ready_at = first(daemon_log.name, lambda d: "node default is Ready" in d, spawned_at)
        kept_at = first(daemon_log.name, lambda d: "node kept" in d and ("Ready" in d or "could not" in d), spawned_at)
        scheduled_at = first("launchd", lambda d: "spawn scheduled" in d)
        hook_words = hook_log.read_text()
        result = {
            "kind": kind, "n": n, "t0_wall": t0_wall, "complete": complete, "old_pid": old, "new_pid": new,
            "runs": [runs0, runs1], "old_age_s": before_age,
            "ms": {"ask": 0 if restarter else None, "told_to_stop": told_at,
                   "old_exited": exited_at, "spawn_scheduled_seen": scheduled_at,
                   "launchd_spawned": spawned_at, "new_serving_line": serving_at,
                   "new_listening": listening_at, "default_ready": ready_at, "kept_ready": kept_at,
                   "hook_spawned": first("action", lambda d: d == "hook spawned"),
                   "hook_exited": first("hook"), "read_exited": first("read"),
                   "restarter_exited": first("restarter")},
            "hook_deferred": "your rooms show from your next turn" in hook_words,
            "hook_exit": ends.get("hook"), "read_exit": ends.get("read"),
            "restarter_exit": ends.get("restarter"),
        }
        samples.append(result)
        say(f"[gap] events {kind} #{n} (ms since ask/kill):")
        for at, source, detail in events:
            say(f"[gap]   {at:>7} {source:<14} {detail}")
        say(f"[gap] hook {kind} #{n}:\n{hook_words}")
        say(f"[gap] read {kind} #{n}:\n{read_log.read_text()}")
        if restarter is not None:
            say(f"[gap] restarter {kind} #{n}:\n{restart_log.read_text()}")
        say("[gap] sample " + json.dumps(result))
        if not complete:
            raise RuntimeError(f"APPARATUS: gap sample {kind} #{n} did not complete within 90 s")

    def mature():
        pid = state()[0]
        until_at = time.monotonic() + 60
        while (age(pid) or 0) < 12 and time.monotonic() < until_at:
            time.sleep(.2)

    target = f"gui/{os.getuid()}/us.vox.daemon"
    domain = f"gui/{os.getuid()}"
    if os.environ.get("VOX_PROOF_GAP_SPIKE"):
        stream_log = fixture / "launchd-stream.log"
        with stream_log.open("w") as out:
            stream = subprocess.Popen(["/usr/bin/log", "stream", "--level", "debug", "--style",
                                       "compact", "--predicate", 'process == "launchd"'],
                                      stdout=out, stderr=subprocess.STDOUT)
        try:
            time.sleep(2)
            for n in (1, 2, 3):
                mature()
                sample("restart", n)
                sample("young", n)
            for n in (1, 2, 3):
                mature()
                sample("restart", n)
                sample("nudge", n, nudge=True)
            # ThrottleInterval 1 in the job, as a changed shipped plist would carry it.
            job = plistlib.loads(plist.read_bytes())
            job["ThrottleInterval"] = 1
            out = subprocess.run(["/bin/launchctl", "bootout", domain, str(plist)],
                                 capture_output=True, text=True)
            say(f"[gap] bootout for ThrottleInterval 1: exit={out.returncode} {out.stderr.strip()}")
            gone_until = time.monotonic() + 60
            while (subprocess.run(["/bin/launchctl", "print", target], capture_output=True).returncode == 0
                   and time.monotonic() < gone_until):
                time.sleep(.1)
            plist.write_bytes(plistlib.dumps(job))
            out = subprocess.run(["/bin/launchctl", "bootstrap", domain, str(plist)],
                                 capture_output=True, text=True)
            say(f"[gap] bootstrap with ThrottleInterval 1: exit={out.returncode} {out.stderr.strip()}")
            if out.returncode:
                raise RuntimeError("APPARATUS: could not bootstrap the ThrottleInterval 1 job")
            ready_until = time.monotonic() + 60
            while time.monotonic() < ready_until:
                pid = state()[0]
                if pid and greeting() == pid:
                    break
                time.sleep(.1)
            minimum = [line.strip() for line in state()[2].splitlines() if "minimum runtime" in line]
            say(f"[gap] job with ThrottleInterval 1: {minimum}")
            for n in (1, 2, 3):
                mature()
                sample("restart", n)
                sample("throttle1", n)
        finally:
            stream.terminate()
            stream.wait(timeout=30)
        lines = stream_log.read_text(errors="replace").splitlines()
        said = [line for line in lines if "us.vox.daemon" in line]
        say(f"[gap] launchd stream: {len(lines)} lines, {len(said)} name us.vox.daemon:\n"
            + "\n".join(said))
        say("[gap] summary " + json.dumps(samples))
        return
    for n in (1, 2, 3):
        mature()
        sample("restart", n)
        sample("young", n)
    for n in (1, 2, 3):
        mature()
        swapped = fixture / f"vox-next-{n}"
        shutil.copy2(restarter_copy, swapped)
        signed = subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier",
                                 f"us.vox.gap.{n}", str(swapped)], capture_output=True, text=True)
        digest = subprocess.run(["/usr/bin/codesign", "-dvvv", str(swapped)],
                                capture_output=True, text=True)
        say(f"[gap] update #{n}: re-signed copy exit={signed.returncode} {signed.stderr.strip()}; "
            + " ".join(line for line in digest.stderr.splitlines() if line.startswith(("CDHash=", "Identifier="))))
        os.replace(swapped, helper)
        sample("update", n)
    for kind in ("crash", "signal"):
        for n in (1, 2, 3):
            mature()
            sample(kind, n)
    say("[gap] summary " + json.dumps(samples))
    own_log = fixture / "data/.daemon/log"
    say(f"[gap] daemon's own log:\n{own_log.read_text(errors='replace') if own_log.exists() else 'absent'}")
    shown = subprocess.run(["/usr/bin/log", "show", "--style", "compact", "--info", "--debug",
                            "--start", started_wall.strftime("%Y-%m-%d %H:%M:%S"),
                            "--predicate", 'eventMessage CONTAINS "us.vox.daemon"'],
                           capture_output=True, text=True, timeout=300)
    say(f"[gap] log show exit={shown.returncode} lines={len(shown.stdout.splitlines())}\n"
        f"{shown.stdout}{shown.stderr}")
    if kept:
        vox("node", "lock", "kept")


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    recovery = len(sys.argv) == 5 and mode in ("--recovery-vm", "--restart-vm", "--bundle-vm")
    if mode in ("--recovery-vm", "--restart-vm", "--bundle-vm") and not recovery:
        raise RuntimeError(f"{mode} needs helper, shipped plist and receipt directory")
    if mode == "--bundle-vm":
        for name in ("VOX_PROOF_NEXT_BINARY", "VOX_PROOF_UPDATE_HARNESS"):
            if not Path(os.environ.get(name, "")).is_file():
                raise RuntimeError(f"bundle proof needs {name}")
    root = Path(__file__).resolve().parent.parent
    tart = os.environ.get("VOX_TART", "tart")
    vm = os.environ.get("VOX_PROOF_VM", "vox-app-proofs")
    user = os.environ.get("VOX_PROOF_VM_USER", "admin")
    if recovery and vm != "vox-app-proofs":
        raise RuntimeError("recovery proof is authorized only for vox-app-proofs")
    if os.environ.get("VOX_PROOF_APP"):
        raise RuntimeError("VOX_PROOF_APP cannot select an installed app in guest mode; unset it to prove the guest build")
    if not shutil.which(tart):
        raise RuntimeError("Tart is missing; see docs/release/app-proof-vm.md")
    if recovery:
        for artifact in sys.argv[2:4]:
            if not Path(artifact).is_file():
                raise RuntimeError(f"recovery artifact missing: {artifact}")
        sha = "snapshot"
    else:
        if run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root,
               capture_output=True, text=True).stdout.strip():
            raise RuntimeError("commit the source first: the guest proves that exact commit")
        sha = run(["git", "rev-parse", "HEAD"], cwd=root,
                  capture_output=True, text=True).stdout.strip()
    inventory = json.loads(run([tart, "list", "--source", "local", "--format", "json"],
                              capture_output=True, text=True).stdout)
    machine = next((row for row in inventory if row.get("Name") == vm or row.get("name") == vm), None)
    if machine is None:
        raise RuntimeError(f"VM {vm!r} is missing; clone the Xcode image as documented first")
    if recovery and str(machine.get("State", machine.get("state", ""))).lower() == "running":
        raise RuntimeError("recovery guest is already running; refusing to stop a guest not started by this run")
    state = Path(os.environ.get("VOX_PROOF_VM_STATE", str(Path.home() / "Library/Caches/vox-app-proofs"))) / vm
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = state / "run.lock"
    try:
        lock.mkdir()
    except FileExistsError:
        raise RuntimeError(f"another guest run holds {lock}; inspect it before removing a stale lock")
    try:
        execute(root, tart, vm, user, sha, state, machine, recovery)
    finally:
        if recovery and (lock / "guest-started").exists():
            stopped = subprocess.run([tart, "stop", vm], capture_output=True, text=True)
            out = Path(sys.argv[4]).resolve()
            (out / "guest-stop.log").write_text(stopped.stdout + stopped.stderr)
            (out / "guest-stop.status").write_text(str(stopped.returncode) + "\n")
            (lock / "guest-started").unlink()
            if stopped.returncode:
                print("app-proofs: APPARATUS: could not stop recovery guest; see guest-stop.log", file=sys.stderr)
                (lock / "cleanup-unconfirmed").touch()
                raise RuntimeError("could not stop the recovery guest; see guest-stop.log")
        if (lock / "cleanup-unconfirmed").exists():
            print(f"app-proofs: APPARATUS: retained {lock}; guest cancellation was not confirmed", file=sys.stderr)
        else:
            lock.rmdir()


def recovery_guest(ssh, options, destination, out):
    guest = run([*ssh, "mktemp -d /tmp/vox-recovery.XXXXXX"],
                capture_output=True, text=True).stdout.strip()
    if not re.fullmatch(r"/tmp/vox-recovery\.[A-Za-z0-9]+", guest):
        raise RuntimeError(f"invalid guest scratch directory: {guest!r}")
    app = guest + "/Vox.app"
    proc = None
    try:
        run([*ssh, "mkdir -p " + shlex.quote(app + "/Contents/Helpers") + " "
             + shlex.quote(app + "/Contents/Library/LaunchAgents")])
        for source, target in (
            (Path(__file__).resolve(), guest + "/proof.py"),
            (Path(sys.argv[2]).resolve(), app + "/Contents/Helpers/vox"),
            (Path(sys.argv[3]).resolve(), app + "/Contents/Library/LaunchAgents/us.vox.daemon.plist"),
        ):
            run(["scp", *options, str(source), destination + ":" + target])
        if sys.argv[1] == "--bundle-vm":
            for name, filename in (("VOX_PROOF_NEXT_BINARY", "vox-next"),
                                   ("VOX_PROOF_UPDATE_HARNESS", "update-proof")):
                run(["scp", *options, os.environ[name], destination + ":" + guest + "/" + filename])
            # The Rust journey owns its scratch-bound shipped job. The outer process
            # also boots it out on cancellation or an aborted test process.
            command = (
                "echo $$ > " + shlex.quote(guest + "/proof.pid") + "; "
                "exec env VOX_PROOF_VM_GUEST=1 "
                + ("VOX_PROOF_BUNDLE_AFTER_SWAP=1 " if os.environ.get("VOX_PROOF_BUNDLE_AFTER_SWAP") else "")
                + ("VOX_PROOF_BUNDLE_PRECOMMIT=1 " if os.environ.get("VOX_PROOF_BUNDLE_PRECOMMIT") else "")
                + ("VOX_PROOF_BUNDLE_PRECOMMIT_THEN_RESTART=1 " if os.environ.get("VOX_PROOF_BUNDLE_PRECOMMIT_THEN_RESTART") else "")
                + ("VOX_PROOF_BUNDLE_UNMANAGED=1 " if os.environ.get("VOX_PROOF_BUNDLE_UNMANAGED") else "")
                + ("VOX_PROOF_MATURE_RESTART=1 " if os.environ.get("VOX_PROOF_MATURE_RESTART") else "")
                + ("VOX_PROOF_MANAGER_FIELDS_ABSENT=1 " if os.environ.get("VOX_PROOF_MANAGER_FIELDS_ABSENT") else "")
                + "/usr/bin/python3 " + shlex.quote(guest + "/proof.py")
                + " --bundle-guest-proof " + shlex.quote(guest)
            )
            proc = subprocess.Popen([*ssh, command])
            result = proc.wait()
            if result:
                raise SystemExit(result)
            return
        command = (
            "chmod 700 " + shlex.quote(app + "/Contents/Helpers/vox") + "; "
            "echo $$ > " + shlex.quote(guest + "/proof.pid") + "; "
            "exec env VOX_PROOF_VM_GUEST=1 "
            + ("VOX_PROOF_FAIL_REPLACEMENT=1 " if os.environ.get("VOX_PROOF_FAIL_REPLACEMENT") else "")
            + ("VOX_PROOF_PENDING_START=1 " if os.environ.get("VOX_PROOF_PENDING_START") else "")
            + ("VOX_PROOF_GAP_TIMELINE=1 " if os.environ.get("VOX_PROOF_GAP_TIMELINE") else "")
            + ("VOX_PROOF_GAP_SPIKE=1 " if os.environ.get("VOX_PROOF_GAP_SPIKE") else "")
            + ("VOX_PROOF_LOGIN_ITEM_NEWS=1 " if os.environ.get("VOX_PROOF_LOGIN_ITEM_NEWS") else "")
            + ("VOX_MUTANT_HOOK_RESTART_IMMEDIATE=1 " if os.environ.get("VOX_MUTANT_HOOK_RESTART_IMMEDIATE") else "")
            + ("VOX_PROOF_HOOK_STOP_DETECTION=1 " if os.environ.get("VOX_PROOF_HOOK_STOP_DETECTION") else "")
            + ("VOX_MUTANT_ONESHOT_PENDING_IMMEDIATE=1 " if os.environ.get("VOX_MUTANT_ONESHOT_PENDING_IMMEDIATE") else "")
            + ("VOX_PROOF_SHIPPED_DEFAULTS=1 " if os.environ.get("VOX_PROOF_SHIPPED_DEFAULTS") else "")
            + ("VOX_PROOF_SLOW_HOOK_CHECK=1 " if os.environ.get("VOX_PROOF_SLOW_HOOK_CHECK") else "")
            + ("VOX_PROOF_ROOT_PRECEDENCE=1 " if os.environ.get("VOX_PROOF_ROOT_PRECEDENCE") else "")
            + ("VOX_PROOF_REMOVE_MANAGER=1 " if os.environ.get("VOX_PROOF_REMOVE_MANAGER") else "")
            + ("VOX_PROOF_MANAGER_FIELDS_ABSENT=1 " if os.environ.get("VOX_PROOF_MANAGER_FIELDS_ABSENT") else "")
            + "/usr/bin/python3 " + shlex.quote(guest + "/proof.py")
            + " --managed-guest-proof " + shlex.quote(app) + " " + shlex.quote(guest)
            + (" restart" if sys.argv[1] == "--restart-vm" else " recovery")
        )
        proc = subprocess.Popen([*ssh, command])
        result = proc.wait()
        if result:
            raise SystemExit(result)
    except KeyboardInterrupt:
        subprocess.run([*ssh, "test ! -f " + shlex.quote(guest + "/proof.pid")
                        + " || kill -TERM \"$(cat " + shlex.quote(guest + "/proof.pid") + ")\""])
        if proc is not None:
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                print("APPARATUS: guest proof cleanup did not acknowledge cancellation", file=sys.stderr)
        raise
    finally:
        removed = subprocess.run([*ssh, "rm -rf -- " + shlex.quote(guest)])
        if removed.returncode:
            raise RuntimeError("could not remove recovery guest scratch")


def execute(root, tart, vm, user, sha, state, machine, recovery=False):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(sys.argv[4]).resolve() if recovery else root / "target/app-proof-results" / (stamp + "-" + sha[:8])
    out.mkdir(parents=True, exist_ok=recovery)
    # VNC is available for guest-only UI evaluations. Never open Tart's host window,
    # forward audio/USB, or share a clipboard. The guest stays up for evaluations.
    status = str(machine.get("State", machine.get("state", ""))).lower()
    if status != "running":
        if not recovery:
            run([tart, "set", vm, "--cpu", "8", "--memory", "16384", "--display", "1512x982"])
        if recovery:
            (state / "run.lock/guest-started").touch()
        with (state / "vm.log").open("wb") as log:
            proc = subprocess.Popen([tart, "run", vm, "--no-graphics", "--no-clipboard",
                                     "--no-audio", "--no-usb-accessories", "--vnc-experimental"],
                                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        (state / "vm.pid").write_text(str(proc.pid))
    else:
        # An existing VM could have been started with a host window or clipboard sharing.
        # Only reuse a live process started with this runner's isolation flags.
        pid = (state / "vm.pid").read_text().strip() if (state / "vm.pid").exists() else ""
        command = subprocess.run(["ps", "-p", pid or "0", "-o", "command="],
                                 capture_output=True, text=True).stdout
        if not all(flag in command for flag in ("--no-graphics", "--no-clipboard", "--no-audio", "--no-usb-accessories")):
            raise RuntimeError("VM already running outside this runner; stop it before the isolated run")
    ip = ""
    for _ in range(120):
        lookup = subprocess.run([tart, "ip", vm], capture_output=True, text=True)
        if lookup.returncode == 0 and lookup.stdout.strip():
            ip = lookup.stdout.strip()
            break
        time.sleep(1)
    if not ip:
        raise RuntimeError(f"guest did not obtain an address; inspect {state / 'vm.log'}")
    key = state / "id_ed25519"
    if not key.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    known = state / "known_hosts"
    if not known.exists():
        for _ in range(60):
            scan = subprocess.run(["ssh-keyscan", "-T", "2", "-t", "ed25519", ip],
                                  capture_output=True, text=True)
            if scan.returncode == 0 and scan.stdout.strip():
                known.write_text("\n".join(vm + " " + line.split(" ", 1)[1]
                                          for line in scan.stdout.strip().splitlines()) + "\n")
                break
            time.sleep(1)
        else:
            raise RuntimeError("guest SSH did not start")
    options = ["-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
               "-o", f"HostKeyAlias={vm}", "-o", "ConnectTimeout=10", "-i", str(key)]
    destination = user + "@" + ip
    ssh = ["ssh", *options, "-o", "BatchMode=yes", destination]
    if subprocess.run([*ssh, "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        # Public image credentials bootstrap this runner's key in the guest only.
        # Pin the scanned guest host key above; never change the person's SSH config.
        public = key.with_suffix(".pub").read_text().strip()
        command = "umask 077; mkdir -p ~/.ssh; printf '%s\\n' " + shlex.quote(public) + " >> ~/.ssh/authorized_keys"
        bootstrap = r'''
set timeout 30
spawn -noecho {*}$argv
expect {
    -nocase -re "password:" {send -- "$env(VOX_VM_BOOTSTRAP_PASSWORD)\r"; exp_continue}
    eof {catch wait result; exit [lindex $result 3]}
    timeout {exit 2}
}
'''
        env = dict(os.environ, VOX_VM_BOOTSTRAP_PASSWORD=os.environ.get("VOX_PROOF_VM_PASSWORD", "admin"))
        driver = state / "bootstrap.exp"
        driver.write_text(bootstrap)
        run(["expect", str(driver), "ssh", *options, "-o", "BatchMode=no", destination, command], env=env)
    if recovery:
        recovery_guest(ssh, options, destination, out)
        return
    home = run([*ssh, "printf '%s' \"$HOME\""], capture_output=True, text=True).stdout
    guest = home + "/vox-app-proofs"
    run([*ssh, "mkdir -p " + shlex.quote(guest)])
    bundle = out / "source.bundle"
    run(["git", "bundle", "create", str(bundle), "HEAD"], cwd=root)
    run(["scp", *options, str(bundle), destination + ":" + guest + "/source.bundle"])
    args = " ".join(shlex.quote(arg) for arg in sys.argv[1:])
    controls = " ".join(name + "=" + shlex.quote(os.environ[name]) for name in
                        ("VOX_PROOF_FROM", "VOX_PROOF_CONTINUE", "VOX_PROOF_SHA", "VOX_PROOF_STEP", "VOX_PROOF_MUTANT") if name in os.environ)
    remote = f'''set -eu
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
cd {shlex.quote(guest)}
if [ -d run.lock ]; then echo 'app-proofs: APPARATUS: another guest proof still owns the desktop' >&2; exit 2; fi
git clone source.bundle source-{stamp}
cd source-{stamp}
git checkout --detach {shlex.quote(sha)}
mkdir -p ../build-cache
ln -s ../build-cache target
xcodebuild -version
if ! command -v rustup >/dev/null; then
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o ../rustup-init.sh
    sh ../rustup-init.sh -y --profile minimal --default-toolchain none
fi
rustup show active-toolchain
# A fresh guest has never answered Vox's first-run question. Stage the default
# account's answer so the existing proof can distinguish it from scratch config:
# only the scratch app should ask the question. Never start Vox on this default.
case "$(sysctl -n hw.model)" in VirtualMac*) ;; *) echo 'app-proofs: APPARATUS: guest is not a virtual Mac' >&2; exit 2 ;; esac
account_app="$HOME/Library/Application Support/vox/app"
if [ ! -e "$account_app/login-item" ]; then
    mkdir -p "$account_app"
    printf 'no\\n' > "$account_app/login-item"
    echo 'app-proofs: staged guest account first-run answer for scratch-profile guard'
fi
python3 - "$account_app/login-item" <<'PY'
import pathlib, sys
if pathlib.Path(sys.argv[1]).read_text().strip() not in ("keep", "no"):
    sys.exit("app-proofs: APPARATUS: guest account first-run answer is invalid; scratch-profile guard cannot rely on it")
PY
mkdir -p {shlex.quote(guest + '/results/' + stamp)}
VOX_PROOF_VM_GUEST=1 VOX_PROOF_RESULTS={shlex.quote(guest + '/results/' + stamp)} {controls} \\
    RUSTC_WRAPPER= CARGO_PROFILE_RELEASE_STRIP=none python3 scripts/app-proofs-vm.py --guest-run {shlex.quote(guest)} {args}
'''
    (out / "source.json").write_text(json.dumps({"commit": sha, "vm": vm, "proofs": sys.argv[1:]}, indent=2) + "\n")
    print(f"app-proofs: guest {vm}, source {sha}; host desktop and clipboard unused", flush=True)
    result = 2
    try:
        with (out / "guest.log").open("wb") as log:
            proc = subprocess.Popen([*ssh, "bash -s"], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            proc.stdin.write(remote.encode())
            proc.stdin.close()
            proc.stdin = None
            for line in proc.stdout:
                log.write(line)
                log.flush()
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
            result = proc.wait()
    except KeyboardInterrupt:
        stop = "kill -TERM \"$(cat " + shlex.quote(guest + "/run.lock/supervisor.pid") + ")\""
        cancelled = subprocess.run([*ssh, stop])
        try:
            remaining, _ = proc.communicate(timeout=45)
            (out / "cancellation.log").write_bytes(remaining or b"")
        except subprocess.TimeoutExpired:
            cancelled = None
        acknowledged = False
        if cancelled is not None and cancelled.returncode == 0:
            for _ in range(45):
                check = subprocess.run([*ssh, "test ! -d " + shlex.quote(guest + "/run.lock")],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if check.returncode == 0:
                    acknowledged = True
                    break
                time.sleep(1)
        if not acknowledged:
            (state / "run.lock/cleanup-unconfirmed").touch()
        result = 130
    finally:
        copied = subprocess.run(["scp", *options, "-r", destination + ":" + guest + "/results/" + stamp + "/.", str(out)])
        if copied.returncode:
            print("app-proofs: APPARATUS: guest results could not be copied", file=sys.stderr)
            result = 2
        bundle.unlink(missing_ok=True)
        print(f"app-proofs: host results: {out}; guest remains running for UI evaluation")
    raise SystemExit(result)


def guest_run():
    """Own the guest desktop until the proof process group acknowledges termination."""
    guest = Path(sys.argv[2])
    lock = guest / "run.lock"
    try:
        lock.mkdir()
    except FileExistsError:
        raise RuntimeError("another guest proof owns the desktop; inspect its run.lock")
    (lock / "supervisor.pid").write_text(str(os.getpid()))
    proc = None
    confirmed = False

    def cancel(_signum, _frame):
        raise KeyboardInterrupt

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, cancel)
    try:
        proc = subprocess.Popen(["bash", "scripts/app-proofs.sh", *sys.argv[3:]], start_new_session=True)
        result = proc.wait()
        confirmed = True
    except KeyboardInterrupt:
        if proc is not None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=30)
                confirmed = True
            except subprocess.TimeoutExpired:
                print("app-proofs: APPARATUS: guest cleanup not acknowledged; lock retained", file=sys.stderr)
        result = 130
    finally:
        if confirmed:
            (lock / "supervisor.pid").unlink()
            lock.rmdir()
    raise SystemExit(result)



def bundle_guest_proof():
    if os.environ.get("VOX_PROOF_VM_GUEST") != "1" or not run(
        ["/usr/sbin/sysctl", "-n", "hw.model"], capture_output=True, text=True
    ).stdout.strip().startswith("VirtualMac"):
        raise RuntimeError("bundle proof requires a virtual Mac")
    guest = Path(sys.argv[2])
    target = f"gui/{os.getuid()}/us.vox.daemon"
    def launch(*args):
        return subprocess.run(["/bin/launchctl", *args], capture_output=True, text=True)
    if launch("print", target).returncode == 0:
        raise RuntimeError("another guest job is loaded")
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, cancel_host)
    temporary = guest / "tmp"
    temporary.mkdir()
    env = dict(os.environ, TMPDIR=str(temporary), VOX_PROOF_BUNDLE_BEFORE_SWAP="1",
               VOX_PROOF_CURRENT_BINARY=str(guest / "Vox.app/Contents/Helpers/vox"),
               VOX_PROOF_NEXT_BINARY=str(guest / "vox-next"),
               VOX_PROOF_LAUNCH_PLIST=str(guest / "Vox.app/Contents/Library/LaunchAgents/us.vox.daemon.plist"))
    if os.environ.get("VOX_PROOF_BUNDLE_AFTER_SWAP"):
        env["VOX_PROOF_BUNDLE_AFTER_SWAP"] = "1"
    if os.environ.get("VOX_PROOF_BUNDLE_PRECOMMIT"):
        env["VOX_PROOF_BUNDLE_PRECOMMIT"] = "1"
    if os.environ.get("VOX_PROOF_BUNDLE_PRECOMMIT_THEN_RESTART"):
        env["VOX_PROOF_BUNDLE_PRECOMMIT_THEN_RESTART"] = "1"
    if os.environ.get("VOX_PROOF_BUNDLE_UNMANAGED"):
        env.pop("VOX_PROOF_BUNDLE_BEFORE_SWAP", None)
    child = None
    try:
        child = subprocess.Popen([str(guest / "update-proof"),
                                  "an_update_restarts_its_daemon_and_uses_a_different_local_version",
                                  "--ignored", "--exact", "--nocapture"], env=env,
                                 start_new_session=True)
        began = time.monotonic()
        last = None
        while child.poll() is None:
            state = launch("print", target)
            fields = "\n".join(line.strip() for line in state.stdout.splitlines()
                               if re.match(r"\s*(state|pid|runs|last exit code|minimum runtime|immediate reason)\s*=", line))
            if fields != last:
                print(f"[proof] manager at +{time.monotonic() - began:.3f}s:\n{fields}", flush=True)
                last = fields
            time.sleep(.2)
        result = child.wait()
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        current = launch("print", target)
        if current.returncode == 0:
            # The job was absent at entry and this journey is its sole owner.
            out = launch("bootout", target)
            if out.returncode:
                raise RuntimeError(f"APPARATUS: guest job cleanup failed: {out.stderr}")
            print("[proof] outer runner booted out owned job", flush=True)
    raise SystemExit(result)

def cancel_host(_signum, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--managed-guest-proof":
            managed_guest_proof()
        elif len(sys.argv) > 1 and sys.argv[1] == "--bundle-guest-proof":
            bundle_guest_proof()
        elif len(sys.argv) > 1 and sys.argv[1] == "--guest-run":
            guest_run()
        else:
            signal.signal(signal.SIGTERM, cancel_host)
            main()
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
        message = str(error)
        print(f"app-proofs: {message if message.startswith(('PRODUCT:', 'APPARATUS:')) else 'APPARATUS: ' + message}", file=sys.stderr)
        raise SystemExit(2)
