#!/usr/bin/env python3
"""Real-binary RG-4 journeys. OMP's host is a stand-in; its extension is unmodified."""
import fcntl
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import threading
import time

VOX, CASE = sys.argv[1:3]
SUPPORT = Path(__file__).parent
ROOT = Path(tempfile.mkdtemp(prefix="vrg4-", dir="/tmp"))
DATA, CFG, WORK = ROOT / "d", ROOT / "c", ROOT / "work"
for d in (DATA, CFG, WORK, ROOT / "home"):
    d.mkdir()
ENV = {k: os.environ[k] for k in ("PATH", "TMPDIR") if k in os.environ}
ENV.update(VOX_DATA_DIR=str(DATA), VOX_CONFIG_DIR=str(CFG), HOME=str(ROOT / "home"),
           VOX_PROXY="127.0.0.1:0", VOX_LISTEN="127.0.0.1:0",
           VOX_TEST_KEYCHAIN=str(ROOT / "keychain"))
if sys.platform == "darwin":
    made = subprocess.run(["/usr/bin/security", "create-keychain", "-p", "", str(ROOT / "keychain")],
                          capture_output=True, text=True)
    assert made.returncode == 0, "APPARATUS: scratch Keychain: " + made.stderr
PASS = ROOT / "pass"
PASS.write_text("\n")
children = []
paused = set()
print("[RG4] scratch", ROOT, flush=True)

def run(args, text="", extra=None, check=True):
    env = dict(ENV, **(extra or {}))
    p = subprocess.run([VOX, *args], input=text, text=True, capture_output=True,
                       cwd=WORK, env=env)
    print("[command]", json.dumps(args), "exit", p.returncode, "\n" + p.stdout + p.stderr, flush=True)
    if check:
        assert p.returncode == 0, f"PRODUCT: command refused: {args}: {p.stdout}{p.stderr}"
    return p

def wait(pred, what):
    end = time.monotonic() + 90
    while not pred():
        assert time.monotonic() < end, f"APPARATUS: staging not reached: {what}; scratch {ROOT}"
        time.sleep(0.02)

def pid():
    try:
        return int((DATA / ".daemon/lock").read_text().strip())
    except (OSError, ValueError):
        return None

def start(extra=None):
    err = open(ROOT / f"daemon-{len(children)}.log", "w")
    p = subprocess.Popen([VOX, "daemon"],
                         env=dict(ENV, **(extra or {})), stdin=subprocess.DEVNULL,
                         stdout=err, stderr=err)
    children.append(p)
    wait(lambda: (DATA / ".daemon/vox.sock").exists(), "daemon socket")

def create(name):
    run(["node", "create", name, "--passphrase-file", str(PASS)])

def room(name="agent"):
    run(["room", "create", "--node", name, "--name", "retry", "--passphrase-file", "-"], "room passphrase\n")
    return run(["room", "list", "--node", name]).stdout.split()[0]

def hook_command(session, cwd=WORK, room_id=None):
    env = dict(ENV, CLAUDE_CODE_ENTRYPOINT="cli")
    if room_id:
        env["VOX_ROOM"] = room_id
    event = json.dumps(dict(session_id=session, hook_event_name="UserPromptSubmit",
                            cwd=str(cwd), prompt="continue", transcript_path=str(ROOT / "transcript")))
    p = subprocess.Popen([VOX, "agent", "hook", "--node", "agent"], cwd=cwd, env=env,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    p.stdin.write(event)
    p.stdin.close()
    p.stdin = None
    children.append(p)
    return p

def sessions(r):
    return run(["room", "sessions", r, "--node", "agent", "--json"], check=False).stdout

def release(base, phase):
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(str(base.with_suffix(f".{phase}.release")))

def registrations():
    errors = []
    transcript = ROOT / "transcript"
    transcript.write_text("")
    r = room()
    for i in range(9):
        seeded = hook_command(f"rg4-nine-{i}", room_id=r)
        print("[initial registration]", seeded.communicate(), flush=True)
    run(["daemon", "--restart"])
    wait(lambda: "Ready" in run(["node", "list"], check=False).stdout, "restarted agent Ready")
    # The kernel's real registration lock, not a sleep or a fake busy response.
    directory = next(DATA.glob("**/sessions"))
    lock_path = directory.with_suffix(".lock")
    with open(lock_path, "a+") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        hooks = [hook_command(f"rg4-nine-{i}", room_id=r) for i in range(9)]
        def reached():
            if any(p.poll() is not None for p in hooks):
                return True
            result = subprocess.run(["lsof", "-p", str(pid()), "-Fn"], capture_output=True, text=True)
            return str(lock_path) in result.stdout
        wait(reached, "a registration opens the held lock")
        fcntl.flock(held, fcntl.LOCK_UN)
    outputs = [p.communicate() for p in hooks]
    for p, (out, err) in zip(hooks, outputs):
        print("[registration]", p.returncode, out, err, flush=True)
    if any("session registration is busy" in out + err or "LockBusy" in out + err
           for out, err in outputs):
        errors.append("nine restarted Sessions were refused by the held registration lock")
    listed = ""
    for _ in range(30):
        listed = sessions(r)
        if all(f"rg4-nine-{i}" in listed for i in range(9)):
            break
    if not all(f"rg4-nine-{i}" in listed for i in range(9)):
        errors.append("30 answered Session reads did not show all nine restarted Sessions: " + listed)

    run(["room", "create", "--node", "agent", "--name", "retry-two", "--passphrase-file", "-"],
        "room passphrase\n")
    second = next(line.split()[0] for line in run(["room", "list", "--node", "agent"]).stdout.splitlines()
                  if "retry-two" in line)
    mode = directory.stat().st_mode & 0o777
    directory.chmod(0o500)
    try:
        try:
            probe = directory / "permission-probe"
            probe.write_text("must not write")
        except PermissionError:
            pass
        else:
            probe.unlink()
            raise AssertionError("APPARATUS: read-only registration directory did not refuse a real write")
        moved = run(["agent", "room", second, "--node", "agent", "--session", "rg4-nine-1"], check=False)
        if moved.returncode == 0:
            errors.append("a room move was acknowledged while its registration could not be saved: " + moved.stdout)
        with transcript.open("a") as stream:
            stream.write(json.dumps({"type": "custom-title", "customTitle": "rg4-unsaved-name",
                                     "sessionId": "rg4-nine-0"}) + "\n")
        def rename_attempted():
            log = (DATA / ".daemon/log").read_text()
            if (ROOT / "daemon-0.log").exists():
                log += (ROOT / "daemon-0.log").read_text()
            return "Session name was not changed" in log or "rg4-unsaved-name" in sessions(r)
        wait(rename_attempted, "native rename reached the refused registration save")
        if "rg4-unsaved-name" in sessions(r):
            errors.append("the room published a renamed Session even though its registration save was refused")
    finally:
        directory.chmod(mode)

    with transcript.open("a") as stream:
        stream.write(json.dumps({"type": "custom-title", "customTitle": "rg4-saved-name",
                                 "sessionId": "rg4-nine-0"}) + "\n")
    wait(lambda: "rg4-saved-name" in sessions(r), "rename succeeds after storage is writable")
    run(["agent", "room", second, "--node", "agent", "--session", "rg4-nine-1"])
    wait(lambda: "rg4-nine-1" in sessions(second), "the same Session moves after storage is writable")
    assert not errors, "PRODUCT: " + "; ".join(errors)
    print("VERDICT GREEN: nine restarted Sessions waited; refused rename/move saves were not acknowledged; both worked after repair",
          flush=True)

def startup():
    r = room()
    protected = ROOT / "sibling.pass"
    protected.write_text("identity passphrase\n")
    run(["node", "create", "sibling", "--passphrase-file", str(protected)])
    run(["node", "unlock", "sibling", "--passphrase-file", str(protected)])
    room("sibling")
    run(["node", "lock", "sibling"])
    base = ROOT / "startup"
    for phase in ("policy", "rooms"):
        base.with_suffix(f".{phase}.arm").write_text("hold")
    p = subprocess.Popen([VOX, "node", "unlock", "sibling", "--passphrase-file", str(protected)],
                         env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    children.append(p)
    wait(lambda: base.with_suffix(".policy.selected").exists(), "sibling owns policy gate")
    h = hook_command("rg4-opening-during-policy", room_id=r)
    out, err = h.communicate()
    print("[policy registration]", out, err, flush=True)
    # A status command proves the daemon answered while the sibling owns the gate.
    run(["status", "--node", "agent", "--json"])
    release(base, "policy")
    wait(lambda: base.with_suffix(".rooms.selected").exists(), "sibling has installed policy")
    opened = False
    for _ in range(30):
        out = sessions(r)
        if "rg4-opening-during-policy" in out:
            opened = True
            break
    release(base, "rooms")
    attach_out, attach_err = p.communicate()
    print("[sibling attach]", p.returncode, attach_out, attach_err, flush=True)
    assert opened, "PRODUCT: 30 answered Session reads show no opening while sibling room reopening is held"
    assert p.returncode == 0, f"PRODUCT: sibling failed to attach: {attach_out}{attach_err}"
    print("VERDICT GREEN: refused Session opening retried after policy, before sibling rooms reopened", flush=True)

class Host:
    def __init__(self, cwd, room_id=None):
        self.session = "rg4-native-" + os.urandom(8).hex()
        self.lines = []
        self.cv = threading.Condition()
        self.hold = ROOT / "turn-hold"
        ext = ROOT / "extension.mjs"
        ext.write_text(run(["agent", "plugin", "omp", "--node", "agent"]).stdout)
        env = dict(ENV, VOX_BIN=VOX, RCA_HOLD_FILE=str(self.hold))
        if room_id:
            env["VOX_ROOM"] = room_id
        self.p = subprocess.Popen(["node", str(SUPPORT / "omp_turn_host.mjs"), str(ext), self.session, str(cwd)],
                                  cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
        children.append(self.p)
        def pump():
            for line in self.p.stdout:
                print("[extension]", line, end="", flush=True)
                with self.cv:
                    self.lines.append(line)
                    self.cv.notify_all()
        threading.Thread(target=pump, daemon=True).start()
        self.await_line("session_start-done")
    def send(self, text):
        self.p.stdin.write(text + "\n")
        self.p.stdin.flush()
    def await_line(self, text, start=0):
        wait(lambda: any(text in line for line in self.lines[start:]), "extension " + text)
    def turn(self, text):
        mark = len(self.lines)
        self.send("turn " + text)
        self.await_line("turn-end: prompt", mark)
        return mark

def extension():
    r = room()
    create("person")
    link = run(["room", "link", r, "--node", "agent"]).stdout.strip()
    run(["room", "join", link, "--node", "person", "--passphrase-file", "-"], "room passphrase\n")
    person = run(["id", "--node", "person"]).stdout.strip()
    agent = run(["id", "--node", "agent"]).stdout.strip()
    run(["trust", "add", person, "--node", "agent", "--name", "person"], "\n")
    run(["trust", "add", agent, "--node", "person", "--name", "agent"], "\n")
    host = Host(WORK, r)
    host.turn("hello")
    host.hold.with_suffix(".arm").write_text("hold")
    # The stand-in uses <hold>.arm, not Path.with_suffix on a suffixed filename.
    run(["room", "post", r, "--node", "person", "rg4-held-news"])
    host.await_line("hold-begin")
    assert any("INJECTED" in line and "rg4-held-news" in line for line in host.lines), \
        "APPARATUS: held native turn did not carry the room post"
    old = pid()
    restart = subprocess.Popen([VOX, "daemon", "--restart"], env=dict(ENV, VOX_TEST_DAEMON_SERVE_DELAY_MS="5000"),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    children.append(restart)
    def replacement_not_serving():
        if not pid() or pid() == old:
            return False
        with socket.socket(socket.AF_UNIX) as probe:
            try:
                probe.connect(str(DATA / ".daemon/vox.sock"))
                return False
            except OSError:
                return True
    wait(replacement_not_serving, "replacement owns gap")
    replacement = pid()
    os.kill(replacement, signal.SIGSTOP)
    paused.add(replacement)
    # The replacement is physically paused. The already-published turn now gives its decision.
    host.hold.with_suffix(".arm").unlink(missing_ok=True)
    host.hold.write_text("release")
    host.await_line("turn-end: aside")
    # Wait for the hook's local cursor save or its named main failure, not a silence verdict.
    wait(lambda: any("finishing the saved context decision" in l or "delivery in this conversation is uncertain" in l
                     for l in host.lines), "held decision acknowledged or refused")
    os.kill(replacement, signal.SIGCONT)
    paused.remove(replacement)
    out, err = restart.communicate()
    print("[restart]", restart.returncode, out, err, flush=True)
    assert restart.returncode == 0, f"PRODUCT: restart refused: {out}{err}"
    wait(lambda: run(["node", "list"], check=False).stdout.count("Ready") >= 2, "both kept nodes Ready")
    wait(lambda: all("rg4-held-news" in run(["room", "read", r, "--node", node], check=False).stdout
                     for node in ("agent", "person")), "both reopened rooms show the held post")
    run(["room", "post", r, "--node", "person", "rg4-after-restart"])
    wait(lambda: "rg4-after-restart" in run(["room", "read", r, "--node", "agent"], check=False).stdout,
         "later post reaches the native conversation's node")
    for i in range(6):
        host.turn("read after restart " + str(i))
    # Accepted native history is legitimately reconstructed on later provider requests.
    # Count fresh materializations, not those replays, and require actual context injection.
    shown = sum("STAGED:" in line and "rg4-after-restart" in line for line in host.lines)
    injected = any("INJECTED" in line and "rg4-after-restart" in line for line in host.lines)
    assert shown == 1 and injected, f"PRODUCT: after daemon restart the same native conversation showed the later post {shown} fresh times (injected={injected}), not once"
    assert not any("delivery in this conversation is uncertain" in line for line in host.lines), \
        "PRODUCT: a saved native decision made the conversation uncertain"
    # A new undecided publication must retain the old fail-closed meaning.
    host.hold.with_suffix(".arm").write_text("hold")
    before = len(host.lines)
    run(["room", "post", r, "--node", "person", "rg4-no-decision"])
    host.await_line("hold-begin", before)
    host.hold.with_suffix(".undecided").write_text("no decision")
    host.hold.with_suffix(".arm").unlink(missing_ok=True)
    host.hold.write_text("release")
    host.await_line("delivery in this conversation is uncertain", before)
    probe = run(["agent", "hook", "--node", "agent", "--session", host.session, "--omp-check-uncertainty"],
                extra={"VOX_HARNESS": "omp"}, check=False)
    assert probe.returncode == 78, f"PRODUCT: no-decision turn must stay uncertain: {probe.returncode} {probe.stderr}"
    host.send("quit")
    host.p.wait()
    print("VERDICT GREEN: real extension recovers the decided turn, shows later news once, preserves undecided uncertainty", flush=True)

def undecided():
    r = room()
    host = Host(WORK, r)
    host.turn("undecided first publication")
    probe = run(["agent", "hook", "--node", "agent", "--session", host.session, "--omp-check-uncertainty"],
                extra={"VOX_HARNESS": "omp"}, check=False)
    assert probe.returncode == 78, f"PRODUCT: no-decision turn must stay uncertain: {probe.returncode} {probe.stderr}"
    host.send("quit")
    host.p.wait()
    print("VERDICT GREEN: an undecided native turn stays uncertain", flush=True)

def riders():
    repo, linked = ROOT / "repository", ROOT / "linked"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "--orphan", "-b", "linked", str(linked)], check=True)
    h = hook_command("rg4-linked-offer", cwd=linked)
    out, err = h.communicate()
    print("[linked worktree offer]", out, err, flush=True)
    assert f"this repo ({repo.resolve()})" in out, f"PRODUCT: linked-worktree offer must name repository {repo.resolve()}, not {linked.resolve()}: {out}{err}"
    # Bind this registered start explicitly to an operator decision, then try to shadow it.
    (DATA / "rooms").write_text(f"repo {repo}\n    room none\n")
    (DATA / "rooms").chmod(0o600)
    refused = run(["agent", "room", "--node", "agent", "--session", "rg4-linked-offer", "--none"], check=False)
    assert refused.returncode != 0 and "operator" in refused.stderr.lower() and "own terminal" in refused.stderr, \
        f"PRODUCT: --none refusal must name who may change the map: {refused.stdout}{refused.stderr}"
    print("VERDICT GREEN: linked-worktree offer names repository; refusal names operator authority", flush=True)

try:
    startup_env = {"VOX_TEST_HOLD_IDENTITY_STARTUP": str(ROOT / "startup")} if CASE == "startup" else None
    start(startup_env)
    create("agent")
    wait(lambda: "Ready" in run(["node", "list"], check=False).stdout, "agent Ready")
    # Seed the directory with a real saved registration before taking its lock.
    if CASE == "registration":
        h = hook_command("rg4-seed")
        print(h.communicate(), flush=True)
        registrations()
    elif CASE == "startup":
        startup()
    elif CASE == "extension":
        extension()
    elif CASE == "riders":
        riders()
    elif CASE == "undecided":
        undecided()
    else:
        raise AssertionError("APPARATUS: unknown journey " + CASE)
finally:
    for p in paused:
        os.kill(p, signal.SIGCONT)
    current = pid()
    if current:
        try:
            os.kill(current, signal.SIGTERM)
        except ProcessLookupError:
            pass
    for child in reversed(children):
        if child.poll() is None:
            child.kill()
        child.wait()
    print("[RG4] retained scratch", ROOT, flush=True)
