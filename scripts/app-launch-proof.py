#!/usr/bin/env python3
"""ADR-014 M-9, #438: with the login item declined, Vox.app starts the daemon as `vox` does, and
never a second one -- proved by launching the built Vox.app (ADR-018, ADR-014 M-30).

Run by `scripts/app-proofs.sh`, which builds the app and puts the release `vox` in it:

    scripts/app-launch-proof.py <Vox.app>

No UI automation: the app is launched as a person launches it, with a scratch data root and
config directory whose first-run answer to the login item is "Not Now". What must hold, as a
person can check it with `ps` and the daemon's log (`<data root>/.daemon/log`):

1. Launched with no daemon running, the app starts one: within 30 s exactly one `vox daemon`
   serves the data root, and its log holds one start. It is still running 10 s on, the app being
   its client (a daemon a client started exits once it has no node and no client, ADR-026 L-8).
2. Never two: sampled every 50 ms for 10 s after each launch, at most one `vox daemon` names the
   data root, and its log never says "a daemon is already running".
3. Quit and launched again while that daemon runs (a node attached by hand, `vox node attach`,
   keeps it running), the app uses it: the same daemon, by PID, and still one start in its log.

Mutant: the app starts a daemon of its own at every launch (`vox daemon --as-detached`, its output
in the log) as well as reaching the one running: (2) goes red on the second launch.

Every red names its side: PRODUCT (what the app or the daemon did) or APPARATUS (the proof's own
staging).
"""

import os
import signal
import subprocess
import sys
import tempfile
import time

START = "vox daemon: control socket"
SECOND = "a daemon is already running"


def fail(side, why):
    print(f"[launch-proof] {side}: {why}", file=sys.stderr)
    sys.exit(1)


def daemons(data):
    """PIDs of the `vox daemon` processes naming `data` in their arguments."""
    out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        pid, _, command = line.strip().partition(" ")
        if " daemon" in command and data in command and "app-launch-proof" not in command:
            found.append(int(pid))
    return found


def log_text(data):
    try:
        with open(os.path.join(data, ".daemon", "log"), encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def launch(app, env):
    exe = os.path.join(app, "Contents", "MacOS", "Vox")
    return subprocess.Popen([exe], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def watch(data, seconds):
    """The most `vox daemon` processes seen at once over `seconds`, and the last PIDs seen."""
    most, last = 0, []
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        last = daemons(data)
        most = max(most, len(last))
        time.sleep(0.05)
    return most, last


def main():
    if len(sys.argv) != 2:
        fail("APPARATUS", "usage: app-launch-proof.py <Vox.app>")
    app = os.path.abspath(sys.argv[1])
    if not os.access(os.path.join(app, "Contents", "Helpers", "vox"), os.X_OK):
        fail("APPARATUS", f"{app} holds no Contents/Helpers/vox; build it with scripts/app-proofs.sh")
    scratch = tempfile.mkdtemp(prefix="vox-launch-")
    data, config = os.path.join(scratch, "data"), os.path.join(scratch, "config")
    os.makedirs(os.path.join(config, "app"), mode=0o700)
    # The person's first-run answer: Not Now.
    with open(os.path.join(config, "app", "login-item"), "w", encoding="utf-8") as f:
        f.write("no\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("VOX_")}
    env.update({"VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config})

    started = []
    try:
        if daemons(data):
            fail("APPARATUS", "a daemon already names the fresh data root")

        # (1) and (2), first launch: no daemon runs; the app starts one.
        first = launch(app, env)
        started.append(first)
        until = time.monotonic() + 30
        while not daemons(data) and time.monotonic() < until:
            if first.poll() is not None:
                fail("PRODUCT", f"Vox.app exited ({first.returncode}) before any daemon ran")
            time.sleep(0.05)
        if not daemons(data):
            fail("PRODUCT", f"30 s after launch no vox daemon serves the data root; its log: {log_text(data)!r}")
        most, pids = watch(data, 10)
        log = log_text(data)
        print(f"[launch-proof] first launch: at most {most} daemon(s), now {pids}; "
              f"log starts {log.count(START)}, second daemons {log.count(SECOND)}")
        if most != 1 or log.count(START) != 1 or SECOND in log:
            fail("PRODUCT", f"the app must start exactly one daemon: at most {most} ran at once; the "
                            f"daemon's log says: {log!r}")
        if len(pids) != 1:
            fail("PRODUCT", f"the daemon the app started stopped while the app was open; its log: {log!r}")
        daemon = pids[0]

        # (3) A node attached by hand keeps the daemon running; quit, and launch again: the app
        # uses that daemon.
        vox = os.path.join(app, "Contents", "Helpers", "vox")
        passfile = os.path.join(scratch, "bob.pass")
        with open(passfile, "w", encoding="utf-8") as f:
            f.write("bob identity\n")
        for args in (["node", "create", "bob", "--passphrase-file", passfile],
                     ["node", "attach", "bob", "--passphrase-file", passfile]):
            done = subprocess.run([vox, *args], env=env, capture_output=True, text=True,
                                  stdin=subprocess.DEVNULL, timeout=120)
            if done.returncode != 0:
                fail("APPARATUS", f"`vox {' '.join(args)}` exited {done.returncode}: "
                                  f"{done.stdout}{done.stderr}")
        if daemons(data) != [daemon]:
            fail("PRODUCT", f"`vox node attach` must use daemon {daemon}; now {daemons(data)}")
        first.send_signal(signal.SIGTERM)
        first.wait(timeout=30)
        second = launch(app, env)
        started.append(second)
        most, pids = watch(data, 10)
        log = log_text(data)
        print(f"[launch-proof] second launch: at most {most} daemon(s), now {pids}; "
              f"log starts {log.count(START)}, second daemons {log.count(SECOND)}")
        if second.poll() is not None:
            fail("PRODUCT", f"Vox.app exited ({second.returncode}) on its second launch")
        if most != 1 or pids != [daemon] or log.count(START) != 1 or SECOND in log:
            fail("PRODUCT", f"launched again, the app must use daemon {daemon} and start none: at "
                            f"most {most} ran at once, now {pids}; the daemon's log says: {log!r}")
        print("[launch-proof] ok: one daemon, started by the app as vox starts it, used again")
    finally:
        for p in started:
            if p.poll() is None:
                p.kill()
                p.wait()
        for pid in daemons(data):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


if __name__ == "__main__":
    main()
