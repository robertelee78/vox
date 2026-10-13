#!/usr/bin/env python3
"""Run the existing app journey in a headless Tart macOS guest (ADR-014 M-32a).

The VM contains Xcode; this runner installs the pinned Rust toolchain in its account,
copies committed source, and copies results back even when a proof goes red.
No desktop API, clipboard API or host Vox process is used here.
"""
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


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def main():
    root = Path(__file__).resolve().parent.parent
    tart = os.environ.get("VOX_TART", "tart")
    vm = os.environ.get("VOX_PROOF_VM", "vox-app-proofs")
    user = os.environ.get("VOX_PROOF_VM_USER", "admin")
    if os.environ.get("VOX_PROOF_APP"):
        raise RuntimeError("VOX_PROOF_APP cannot select an installed app in guest mode; unset it to prove the guest build")
    if not shutil.which(tart):
        raise RuntimeError("Tart is missing; see docs/release/app-proof-vm.md")
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
    state = Path(os.environ.get("VOX_PROOF_VM_STATE", str(Path.home() / "Library/Caches/vox-app-proofs"))) / vm
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = state / "run.lock"
    try:
        lock.mkdir()
    except FileExistsError:
        raise RuntimeError(f"another guest run holds {lock}; inspect it before removing a stale lock")
    try:
        execute(root, tart, vm, user, sha, state, machine)
    finally:
        if (lock / "cleanup-unconfirmed").exists():
            print(f"app-proofs: APPARATUS: retained {lock}; guest cancellation was not confirmed", file=sys.stderr)
        else:
            lock.rmdir()


def execute(root, tart, vm, user, sha, state, machine):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = root / "target/app-proof-results" / (stamp + "-" + sha[:8])
    out.mkdir(parents=True)
    # VNC is available for guest-only UI evaluations. Never open Tart's host window,
    # forward audio/USB, or share a clipboard. The guest stays up for evaluations.
    status = str(machine.get("State", machine.get("state", ""))).lower()
    if status != "running":
        run([tart, "set", vm, "--cpu", "8", "--memory", "16384", "--display", "1512x982"])
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
    home = run([*ssh, "printf '%s' \"$HOME\""], capture_output=True, text=True).stdout
    guest = home + "/vox-app-proofs"
    run([*ssh, "mkdir -p " + shlex.quote(guest)])
    bundle = out / "source.bundle"
    run(["git", "bundle", "create", str(bundle), "HEAD"], cwd=root)
    run(["scp", *options, str(bundle), destination + ":" + guest + "/source.bundle"])
    args = " ".join(shlex.quote(arg) for arg in sys.argv[1:])
    controls = " ".join(name + "=" + shlex.quote(os.environ[name]) for name in
                        ("VOX_PROOF_FROM", "VOX_PROOF_CONTINUE", "VOX_PROOF_SHA") if name in os.environ)
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


def cancel_host(_signum, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--guest-run":
            guest_run()
        else:
            signal.signal(signal.SIGTERM, cancel_host)
            main()
    except (RuntimeError, subprocess.CalledProcessError, OSError) as error:
        print(f"app-proofs: APPARATUS: {error}", file=sys.stderr)
        raise SystemExit(2)
