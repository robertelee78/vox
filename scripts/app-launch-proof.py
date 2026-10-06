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

4. Keep Running kept: with "keep" answered, the app acting as carol (a node with no passphrase,
   so nothing goes in the Keychain) leaves her attached after it quits (SIGTERM, which the app
   takes as ⌘Q); with "no" answered, quitting detaches her (ADR-014 M-6, ADR-028 A-4).

Mutant: the app starts a daemon of its own at every launch (`vox daemon --as-detached`, its output
in the log) as well as reaching the one running: (2) goes red on the second launch. Mutant: the
app detaches its node on quit whatever was chosen: (4) goes red.

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


# What names the agent session running the proof, or an agent's config: never inherited, so the
# result does not depend on who runs it (as the cargo proofs' children, support/temp_home.rs).
AGENT_VARS = ("CODEX_HOME", "CLAUDE_CONFIG_DIR", "OPENCODE_CONFIG_DIR", "CLAUDE_CODE_SESSION_ID",
              "CODEX_THREAD_ID", "CLAUDE_CODE_MESSAGING_SOCKET", "CLAUDE_CODE_MESSAGING_TOKEN")


def clean_env():
    """The environment a proof's app and `vox` get: no VOX_ variable of the runner's, no agent
    session, and the daemon's .vox proxy on a free port, never another daemon's 1080."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("VOX_") and k not in AGENT_VARS}
    env["VOX_PROXY"] = "127.0.0.1:0"
    return env


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


def launch(app, env, out):
    """Start Vox.app's executable as a person's launch does; what it prints goes to `out`. A launch
    the system refuses is the build's, not the product's."""
    exe = os.path.join(app, "Contents", "MacOS", "Vox")
    try:
        return subprocess.Popen([exe], env=env, stdin=subprocess.DEVNULL,
                                stdout=open(out, "ab"), stderr=subprocess.STDOUT)
    except OSError as e:
        fail("APPARATUS", f"could not start {exe}: {e}")


# What the system says when it will not run the built app at all: a build or signing fault.
NOT_LAUNCHED = ("dyld", "Library not loaded", "code signature", "Code Signature", "killed: 9")


def exited(p, out, when):
    """The red for an app that exited `when`: the build's when the system would not run it, the
    product's otherwise, quoting what it printed."""
    try:
        said = open(out, encoding="utf-8", errors="replace").read()
    except FileNotFoundError:
        said = ""
    side = "APPARATUS" if any(n in said for n in NOT_LAUNCHED) or p.returncode in (-9, 137) \
        else "PRODUCT"
    fail(side, f"Vox.app exited ({p.returncode}) {when}; it printed: {said.strip()!r}")


def watch(data, seconds):
    """The most `vox daemon` processes seen at once over `seconds`, and the last PIDs seen."""
    most, last = 0, []
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        last = daemons(data)
        most = max(most, len(last))
        time.sleep(0.05)
    return most, last


def one_daemon(app):
    """(1) to (3)."""
    scratch = tempfile.mkdtemp(prefix="vox-launch-")
    data, config = os.path.join(scratch, "data"), os.path.join(scratch, "config")
    os.makedirs(os.path.join(config, "app"), mode=0o700)
    # The person's first-run answer: Not Now.
    with open(os.path.join(config, "app", "login-item"), "w", encoding="utf-8") as f:
        f.write("no\n")
    env = clean_env()
    env.update({"VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config})

    started = []
    proved = False
    try:
        if daemons(data):
            fail("APPARATUS", "a daemon already names the fresh data root")

        # (1) and (2), first launch: no daemon runs; the app starts one.
        out = os.path.join(scratch, "app.out")
        first = launch(app, env, out)
        started.append(first)
        until = time.monotonic() + 30
        while not daemons(data) and time.monotonic() < until:
            if first.poll() is not None:
                exited(first, out, "before any daemon ran")
            time.sleep(0.05)
        if not daemons(data):
            fail("PRODUCT", f"30 s after launch no vox daemon serves the data root; the daemon's log "
                            f"says: {log_text(data)!r}; the app printed: {open(out, errors='replace').read().strip()!r}")
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
        try:
            first.wait(timeout=30)
        except subprocess.TimeoutExpired:
            fail("PRODUCT", "Vox.app did not quit within 30 s of SIGTERM (a stop signal is a quit, "
                            "ADR-026 S-4)")
        second = launch(app, env, out)
        started.append(second)
        most, pids = watch(data, 10)
        log = log_text(data)
        print(f"[launch-proof] second launch: at most {most} daemon(s), now {pids}; "
              f"log starts {log.count(START)}, second daemons {log.count(SECOND)}")
        if second.poll() is not None:
            exited(second, out, "on its second launch")
        if most != 1 or pids != [daemon] or log.count(START) != 1 or SECOND in log:
            fail("PRODUCT", f"launched again, the app must use daemon {daemon} and start none: at "
                            f"most {most} ran at once, now {pids}; the daemon's log says: {log!r}")
        print("[launch-proof] ok: one daemon, started by the app as vox starts it, used again")
        proved = True
    finally:
        for p in started:
            if p.poll() is None:
                p.kill()
                p.wait()
        # Only this proof's own: the apps it started, and the daemons naming its scratch data root.
        for pid in daemons(data):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        until = time.monotonic() + 15
        while daemons(data) and time.monotonic() < until:
            time.sleep(0.1)
        left = daemons(data) + [p.pid for p in started if p.poll() is None]
        for pid in left:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if left:
            # Said whatever the verdict; it fails a run that had none of its own.
            print(f"[launch-proof] APPARATUS: processes of this proof outlived it and were killed: "
                  f"{left}", file=sys.stderr)
            if proved:
                sys.exit(1)
        else:
            print("[launch-proof] nothing of this proof is left running")


def node_state(vox, env, node):
    """`vox node list`'s word for `node`: attached, detached, or what it said instead."""
    done = subprocess.run([vox, "node", "list"], env=env, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60)
    for line in done.stdout.splitlines():
        words = line.split()
        if words and words[0] == node and len(words) > 1:
            return words[1]
    return f"not listed ({done.stdout.strip()!r}{done.stderr.strip()!r})"


def after_quit(app, answer):
    """(4) and its control: the app acting as carol, a node with no passphrase, with the first-run
    answer `answer`; quit; what `vox node list` says of carol 10 s later."""
    scratch = tempfile.mkdtemp(prefix="vox-keep-")
    data, config = os.path.join(scratch, "data"), os.path.join(scratch, "config")
    os.makedirs(os.path.join(config, "app"), mode=0o700)
    for name, text in (("login-item", answer), ("node", "carol")):
        with open(os.path.join(config, "app", name), "w", encoding="utf-8") as f:
            f.write(text + "\n")
    env = clean_env()
    env.update({"VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config})
    vox = os.path.join(app, "Contents", "Helpers", "vox")
    empty = os.path.join(scratch, "empty.pass")
    open(empty, "w", encoding="utf-8").close()
    made = subprocess.run([vox, "node", "create", "carol", "--passphrase-file", empty], env=env,
                          capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
    if made.returncode != 0:
        fail("APPARATUS", f"`vox node create carol` exited {made.returncode}: {made.stdout}{made.stderr}")
    out = os.path.join(scratch, "app.out")
    app_p = launch(app, env, out)
    try:
        until = time.monotonic() + 60
        state = ""
        while time.monotonic() < until:
            if app_p.poll() is not None:
                exited(app_p, out, "before it attached carol")
            state = node_state(vox, env, "carol")
            if state == "attached":
                break
            time.sleep(0.25)
        if state != "attached":
            fail("PRODUCT", f"answered {answer!r}, the app never attached carol (a node with no "
                            f"passphrase) in 60 s; `vox node list` says {state}; the daemon's log: "
                            f"{log_text(data)!r}")
        # Quit as a person does: the app takes SIGTERM as ⌘Q.
        app_p.send_signal(signal.SIGTERM)
        try:
            app_p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            fail("PRODUCT", "the app did not quit within 30 s of SIGTERM")
        time.sleep(10)
        return node_state(vox, env, "carol")
    finally:
        if app_p.poll() is None:
            app_p.kill()
            app_p.wait()
        for pid in daemons(data):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        until = time.monotonic() + 15
        while daemons(data) and time.monotonic() < until:
            time.sleep(0.1)
        for pid in daemons(data):
            os.kill(pid, signal.SIGKILL)
            print(f"[launch-proof] APPARATUS: daemon {pid} outlived the keep phase and was killed",
                  file=sys.stderr)


def main():
    if len(sys.argv) != 2:
        fail("APPARATUS", "usage: app-launch-proof.py <Vox.app>")
    app = os.path.abspath(sys.argv[1])
    if not os.access(os.path.join(app, "Contents", "Helpers", "vox"), os.X_OK):
        fail("APPARATUS", f"{app} holds no Contents/Helpers/vox; build it with scripts/app-proofs.sh")
    one_daemon(app)
    # (4) Keep Running chosen: carol stays attached after the app quits. The control: Not Now,
    # and quitting detaches her (ADR-028 A-4).
    kept = after_quit(app, "keep")
    print(f"[launch-proof] Keep Running: 10 s after the app quit, `vox node list` says carol is {kept}")
    if kept != "attached":
        fail("PRODUCT", f"with Keep Running chosen, carol (no passphrase) must stay attached after "
                        f"the app quits; `vox node list` says {kept}")
    declined = after_quit(app, "no")
    print(f"[launch-proof] Not Now: 10 s after the app quit, `vox node list` says carol is {declined}")
    if declined != "detached":
        fail("PRODUCT", f"with Not Now chosen, quitting must detach carol; `vox node list` says "
                        f"{declined}")
    print("[launch-proof] ok: kept after quit only with Keep Running")


if __name__ == "__main__":
    main()
