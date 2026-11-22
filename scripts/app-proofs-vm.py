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

def stop_managed_workers(helper, fixture):
    """Stop only replacement workers bound to this proof's private account."""
    data = str(fixture / "data")
    config = str(fixture / "config")
    def workers():
        output = run(["/bin/ps", "-axww", "-o", "pid=", "-o", "command="],
                     capture_output=True, text=True).stdout
        found = []
        for line in output.splitlines():
            fields = line.strip().split(None, 1)
            if len(fields) != 2 or not fields[0].isdigit():
                continue
            command = fields[1]
            if (command.startswith(str(helper) + " daemon ")
                    and f" --data-dir {data} " in command
                    and f" --config-dir {config} " in command
                    and " --replace-pid " in command):
                found.append(int(fields[0]))
        return found
    for pid in workers():
        if pid not in workers():
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 10
    while workers():
        if time.monotonic() >= deadline:
            raise RuntimeError("APPARATUS: owned replacement worker did not exit")
        time.sleep(.05)

def managed_guest_proof():
    if os.environ.get("VOX_PROOF_VM_GUEST") != "1" or not run(
        ["/usr/sbin/sysctl", "-n", "hw.model"], capture_output=True, text=True
    ).stdout.strip().startswith("VirtualMac"):
        raise RuntimeError("managed daemon proof requires a virtual Mac guest")
    app, scratch = map(Path, sys.argv[2:4])
    mode = sys.argv[4]
    if mode not in ("journey", "restart", "recovery"):
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
        stop_managed_workers(helper, fixture)
        shutil.rmtree(fixture)
        marker.unlink(missing_ok=True)
    atexit.register(cleanup_abandoned_fixture)
    plist = fixture / "job.plist"
    env = {"HOME": str(fixture), "VOX_DATA_DIR": str(fixture / "data"),
           "VOX_CONFIG_DIR": str(fixture / "config"), "VOX_LISTEN": "127.0.0.1:0"}
    for path in (fixture / "data", fixture / "config"):
        path.mkdir()
    job = plistlib.loads(source.read_bytes())
    if job.get("Label") != "us.vox.daemon" or job.get("KeepAlive") != {"SuccessfulExit": False}:
        raise RuntimeError("built bundle does not contain the expected shipped launchd job")
    job.pop("BundleProgram")
    job["Program"] = str(helper)
    job["ProgramArguments"][0] = str(helper)
    job["EnvironmentVariables"] = env
    plist.write_bytes(plistlib.dumps(job))
    control = fixture / "data/.daemon/vox.sock"
    log = fixture / "data/.daemon/log"
    owned = False
    children = []
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
    def until(description, predicate):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.02)
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
        boot = launch("bootstrap", domain, str(plist))
        if boot.returncode:
            raise RuntimeError(f"bootstrap failed: {boot.stderr}")
        owned = True
        first, first_runs = until("initial managed daemon", ready)
        if mode == "recovery":
            print(f"[proof] initial launchd state:\n{state()[2]}", flush=True)
            passfile = fixture / "passphrase"
            passfile.write_text("\n")
            for args in (["node", "create", "default", "--passphrase-file", str(passfile)],
                         ["node", "attach", "default", "--passphrase-file", str(passfile)]):
                staged = subprocess.run([str(helper), *args], env=env, stdin=subprocess.DEVNULL,
                                        capture_output=True, text=True, timeout=120)
                print(f"[proof] vox {' '.join(args)} exit={staged.returncode}\n"
                      f"{staged.stdout}{staged.stderr}", flush=True)
                if staged.returncode:
                    raise RuntimeError(f"APPARATUS: could not stage node: {staged.stdout}{staged.stderr}")
            if ready() != (first, first_runs):
                raise RuntimeError("APPARATUS: staging did not retain the initial managed daemon")
        if mode in ("journey", "recovery"):
            os.kill(first, signal.SIGTERM)
            def recovered():
                pid, runs, text = state()
                if not pid and re.search(r"last exit code = 0\b", text):
                    raise RuntimeError(f"PRODUCT: foreign TERM exited successfully and launchd did not restart it: {text}")
                return (pid, runs) if pid and pid != first and greeting() == pid else None
            second, second_runs = until("launchd replacement after foreign TERM", recovered)
            if mode == "recovery":
                print(f"[proof] recovered launchd state:\n{state()[2]}", flush=True)
            print(f"[proof] foreign TERM: launchd replaced {first} with {second} without a client")
            if mode == "recovery":
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
            if mode == "recovery":
                print("[proof] public wire Stop acknowledged", flush=True)
            def stopped():
                pid, runs, text = state()
                return (runs, text) if not pid and re.search(r"last exit code = 0\b", text) else None
            stopped_runs, stopped_text = until("successful explicit Stop", stopped)
            if stopped_runs != second_runs or state()[1] != stopped_runs:
                raise RuntimeError(f"PRODUCT: launchd restarted explicit Stop: {stopped_text}")
            if mode == "recovery":
                for _ in range(30):
                    time.sleep(.1)
                    pid, runs, text = state()
                    if pid or runs != stopped_runs:
                        raise RuntimeError(f"PRODUCT: launchd restarted explicit Stop: {text}")
            print(f"[proof] explicit Stop: launchd reports exit 0, no pid, {stopped_runs} runs")
            if mode == "recovery":
                print(f"[proof] stopped launchd state:\n{state()[2]}", flush=True)
            if mode == "recovery":
                return
            kick = launch("kickstart", target)
            if kick.returncode:
                raise RuntimeError(f"cannot restart fixture after Stop: {kick.stderr}")
            old, old_runs = until("restarted fixture", lambda: ready(second))
        else:
            old, old_runs = first, first_runs
        before = log.stat().st_size if log.exists() else 0
        caller = subprocess.Popen([str(helper), "daemon", "--restart"], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        children.append(caller)
        def requested():
            if caller.poll() is not None:
                raise RuntimeError("APPARATUS: restart caller exited before stop boundary")
            return log.exists() and b"shutting down on SIGTERM" in log.read_bytes()[before:]
        until("restart stop request", requested)
        caller.kill()
        caller.wait()
        def gap():
            pid, _, text = state()
            if pid and pid != old:
                raise RuntimeError(f"APPARATUS: manager replacement started before client window: {text}")
            return not pid and greeting() is None
        until("manager stop window", gap)
        client = subprocess.Popen([str(helper), "daemon", "--detach"], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        children.append(client)
        client_out, _ = client.communicate(timeout=90)
        if client.returncode or b"already running" not in client_out:
            raise RuntimeError(f"PRODUCT: client in managed restart window did not find the manager's daemon: {client_out!r}")
        replacement, runs = until("manager-owned replacement", lambda: ready(old))
        current, final_runs, text = state()
        serving = greeting()
        if replacement != current or serving != current or runs != old_runs + 1 or final_runs != runs:
            raise RuntimeError(f"PRODUCT: restart did not retain exactly one launchd replacement: {text}; serving {serving}; client {client_out!r}")
        if b"waiting for the daemon to start or restart" not in client_out:
            raise RuntimeError(f"APPARATUS: client did not observe the admission window: {client_out!r}")
        print(f"[proof] killed restart caller; launchd replaced {old} with {replacement}, runs {old_runs}->{runs}; client: {client_out!r}")
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
        if owned:
            result = launch("bootout", domain, str(plist))
            if result.returncode and launch("print", target).returncode == 0:
                raise RuntimeError(f"APPARATUS: could not boot out owned job: {result.stderr}")
            if mode == "recovery":
                print("[proof] owned launchd job booted out", flush=True)
        stop_managed_workers(helper, fixture)
        shutil.rmtree(fixture)
        marker.unlink(missing_ok=True)


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def main():
    recovery = len(sys.argv) == 5 and sys.argv[1] == "--recovery-vm"
    if sys.argv[1:2] == ["--recovery-vm"] and not recovery:
        raise RuntimeError("--recovery-vm needs helper, shipped plist and receipt directory")
    root = Path(__file__).resolve().parent.parent
    tart = os.environ.get("VOX_TART", "tart")
    vm = os.environ.get("VOX_PROOF_VM", "vox-app-proofs")
    user = os.environ.get("VOX_PROOF_VM_USER", "admin")
    if recovery and vm != "vox-app-proofs":
        raise RuntimeError("recovery proof is authorized only for vox-app-proofs")
    if os.environ.get("VOX_PROOF_APP"):
        raise RuntimeError("VOX_PROOF_APP cannot select an installed app in guest mode; unset it to prove the guest build")
    if sys.argv[1:] == ["ManagedBundleProof"] and not Path(
        os.environ.get("VOX_PROOF_NEXT_BINARY", "")
    ).is_file():
        raise RuntimeError("ManagedBundleProof needs VOX_PROOF_NEXT_BINARY from the same snapshot")
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
        command = (
            "chmod 700 " + shlex.quote(app + "/Contents/Helpers/vox") + "; "
            "echo $$ > " + shlex.quote(guest + "/proof.pid") + "; "
            "exec env VOX_PROOF_VM_GUEST=1 /usr/bin/python3 " + shlex.quote(guest + "/proof.py")
            + " --managed-guest-proof " + shlex.quote(app) + " " + shlex.quote(guest) + " recovery"
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
    next_fixture = ""
    if sys.argv[1:] == ["ManagedBundleProof"]:
        fixture = os.environ.get("VOX_PROOF_NEXT_BINARY")
        if not fixture or not Path(fixture).is_file():
            raise RuntimeError("ManagedBundleProof needs VOX_PROOF_NEXT_BINARY from the same snapshot")
        next_fixture = guest + "/next-vox-" + stamp
        run(["scp", *options, fixture, destination + ":" + next_fixture])
        controls += " VOX_PROOF_NEXT_BINARY=" + shlex.quote(next_fixture)
    cleanup_fixture = ("NEXT_FIXTURE=" + shlex.quote(next_fixture) +
                       "\ntrap 'rm -f -- \"$NEXT_FIXTURE\"' EXIT") if next_fixture else ""
    remote = f'''set -eu
{cleanup_fixture}
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
        if next_fixture and subprocess.run(
            [*ssh, "rm -f -- " + shlex.quote(next_fixture)]
        ).returncode:
            print("app-proofs: APPARATUS: guest next-version fixture cleanup failed", file=sys.stderr)
            result = 2
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


def cancel_host(_signum, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--managed-cleanup":
            if os.environ.get("VOX_PROOF_VM_GUEST") != "1" or not run(
                ["/usr/sbin/sysctl", "-n", "hw.model"], capture_output=True, text=True
            ).stdout.strip().startswith("VirtualMac"):
                raise RuntimeError("managed cleanup requires a virtual Mac guest")
            helper, fixture = map(Path, sys.argv[2:4])
            plist = fixture / "job.plist"
            if (fixture.parent != Path("/tmp") or not fixture.name.startswith("vox-mg-")
                    or not plist.is_file()
                    or plistlib.loads(plist.read_bytes()).get("Program") != str(helper)):
                raise RuntimeError("invalid managed cleanup fixture")
            stop_managed_workers(helper, fixture)
        elif len(sys.argv) > 1 and sys.argv[1] == "--managed-guest-proof":
            managed_guest_proof()
        elif len(sys.argv) > 1 and sys.argv[1] == "--guest-run":
            guest_run()
        else:
            signal.signal(signal.SIGTERM, cancel_host)
            main()
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
        message = str(error)
        print(f"app-proofs: {message if message.startswith(('PRODUCT:', 'APPARATUS:')) else 'APPARATUS: ' + message}", file=sys.stderr)
        raise SystemExit(2)
