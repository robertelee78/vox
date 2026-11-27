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

def session_rows(r):
    return [json.loads(line) for line in sessions(r).splitlines() if line.startswith("{")]

def open_sessions(r):
    return {row["id"] for row in session_rows(r) if row.get("open") is True}

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
    if not errors:
        wait(lambda: {f"rg4-nine-{i}" for i in range(9)} <= open_sessions(r),
             "all nine restarted Sessions appear in the room")

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
    run(["room", "create", "--node", "agent", "--name", "gate-only", "--passphrase-file", "-"],
        "room passphrase\n")
    gate_room = next(line.split()[0] for line in run(["room", "list", "--node", "agent"]).stdout.splitlines()
                     if "gate-only" in line)
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
    host = Host(WORK, r)
    opening_session = host.session
    # Record what the shipped product answers at both boundaries, not a read-count timer.
    run(["status", "--node", "agent", "--json"])
    # A post that meets the held policy installation is kept, not refused (465f2345e): start it
    # now and judge it only after the release, by its answer and by what the room shows.
    held_post = subprocess.Popen([VOX, "room", "post", gate_room, "--node", "agent", "rg4-policy-held"],
                                 cwd=WORK, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    children.append(held_post)
    assert opening_session not in open_sessions(r), "PRODUCT: Session opening bypassed the held policy installation"
    assert held_post.poll() is None, "PRODUCT: a post made while the policy installation was held was answered before it, not kept: " \
        + " ".join(held_post.communicate())
    assert "rg4-policy-held" not in run(["room", "read", gate_room, "--node", "agent"], check=False).stdout, \
        "PRODUCT: a post was accepted while the policy installation was held"
    release(base, "policy")
    wait(lambda: base.with_suffix(".rooms.selected").exists(), "sibling has installed policy")
    starting = run(["node", "list"])
    assert any(line.split()[:2] == ["sibling", "Attaching"] for line in starting.stdout.splitlines()), \
        "APPARATUS: sibling startup completed before the room-startup hold"
    run(["status", "--node", "sibling", "--json"], check=False)
    gate_answer = run(["room", "post", gate_room, "--node", "agent", "rg4-policy-installed"], check=False)
    release(base, "rooms")
    attach_out, attach_err = p.communicate()
    print("[sibling attach]", p.returncode, attach_out, attach_err, flush=True)
    assert p.returncode == 0, f"PRODUCT: sibling failed to attach: {attach_out}{attach_err}"
    wait(lambda: opening_session in open_sessions(r), "the original registered Session opens with no new hook")
    assert gate_answer.returncode == 0, "PRODUCT: policy is installed but the sibling's room operation was refused: " + gate_answer.stdout + gate_answer.stderr
    held_out, held_err = held_post.communicate()
    print("[held post]", held_post.returncode, held_out, held_err, flush=True)
    assert held_post.returncode == 0, "PRODUCT: the post kept across the policy installation was refused: " + held_out + held_err
    assert "rg4-policy-held" in run(["room", "read", gate_room, "--node", "agent"]).stdout, \
        "PRODUCT: the post kept across the policy installation was accepted but the room does not show it"
    print("VERDICT GREEN: installed policy no longer gates the sibling's room operation; the post kept across it is accepted and shown; the original Session opens without another hook", flush=True)

class Host:
    def __init__(self, cwd, room_id=None, stop_after_decision=False, binary=None):
        self.session = "rg4-native-" + os.urandom(8).hex()
        self.lines = []
        self.cv = threading.Condition()
        self.hold = ROOT / "turn-hold"
        ext = ROOT / "extension.mjs"
        ext.write_text(run(["agent", "plugin", "omp", "--node", "agent"]).stdout)
        env = dict(ENV, VOX_BIN=binary or VOX, RCA_HOLD_FILE=str(self.hold))
        if stop_after_decision:
            env["RCA_STOP_AFTER_ASIDE_DECISION"] = "1"
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

def identity_refusal():
    r = room()
    create("person")
    link = run(["room", "link", r, "--node", "agent"]).stdout.strip()
    run(["room", "join", link, "--node", "person", "--passphrase-file", "-"], "room passphrase\n")
    person = run(["id", "--node", "person"]).stdout.strip()
    original = run(["id", "--node", "agent"]).stdout.strip()
    def room_policy_idle(node):
        status = run(["status", "--json", "--node", node], check=False)
        if status.returncode != 0:
            return False
        view = json.loads(status.stdout)
        return view.get("governance_pending") is False and not view.get("preparing")
    wait(lambda: room_policy_idle("agent") and room_policy_idle("person"),
         "both nodes finish the join's policy work before trust changes")
    run(["trust", "add", person, "--node", "agent", "--name", "person"], "\n")
    run(["trust", "add", original, "--node", "person", "--name", "agent"], "\n")
    # Keep a real prepare's exit pending after its real child has saved the decision.
    # This wrapper preserves its output and exit status; it changes only EOF timing.
    gate = ROOT / "prepare-exit"
    wrapper = ROOT / "vox-gated"
    wrapper.write_text("""#!/bin/bash
printf '%s\\n' "$*" >> "$RG10_GATE.commands"
if [[ " $* " == *" --omp-prepare "* && -e "$RG10_GATE.arm" ]]; then
  "$RG10_REAL" "$@"
  code=$?
  printf '%s\\n' "$code" > "$RG10_GATE.closed"
  while [[ ! -e "$RG10_GATE.release" ]]; do sleep 0.02; done
  exit "$code"
fi
exec "$RG10_REAL" "$@"
""")
    wrapper.chmod(0o700)
    ENV.update(RG10_GATE=str(gate), RG10_REAL=VOX)
    host = Host(WORK, r, binary=str(wrapper))
    host.turn("hello")
    gate.with_suffix(".arm").write_text("hold")
    host.hold.with_suffix(".arm").write_text("hold")
    run(["room", "post", r, "--node", "person", "--type", "ask", "--to", original,
         "--session", "rg10-person", "rg10-decided-before-rebuild"])
    host.await_line("hold-begin")
    old = pid()
    os.kill(old, signal.SIGTERM)
    wait(lambda: children[0].poll() is not None, "owned old daemon exited before decision")
    children[0].wait()
    host.hold.with_suffix(".arm").unlink(missing_ok=True)
    host.hold.write_text("release")
    host.await_line("turn-end: aside")
    wait(lambda: gate.with_suffix(".closed").exists(), "decided prepare reached held EOF")
    assert int(gate.with_suffix(".closed").read_text()) != 0, \
        "APPARATUS: stopped daemon did not leave a failed acknowledgement"
    saved = []
    for file in DATA.glob("**/omp-uncertain/*"):
        try:
            value = json.loads(file.read_text())
        except (OSError, ValueError):
            continue
        if value.get("session") == host.session and value.get("decision") is True:
            saved.append(value)
    assert saved, "APPARATUS: real prepare did not save the native decision"
    # No process owns the old profile now. Rebuild that node, not a live directory.
    (DATA / "nodes/agent").rename(DATA / "nodes/original-agent")
    create("agent")
    rebuilt = run(["id", "--node", "agent"]).stdout.strip()
    assert rebuilt != original, "APPARATUS: rebuilt node kept the original identity"
    host.await_line("This conversation is refused")
    commands_before = gate.with_suffix(".commands").read_text().splitlines()
    gate.with_suffix(".release").write_text("release")
    def preparation_exited():
        rows = subprocess.run(["ps", "-axo", "ppid=,command="], capture_output=True, text=True).stdout
        return not any(line.split(None, 1)[0] == str(host.p.pid) and "--omp-prepare" in line
                       for line in rows.splitlines() if line.split())
    wait(preparation_exited, "held prepare exited after permanent refusal")
    host.turn("after permanent refusal")
    host.turn("refused again")
    host.send("quit")
    host.p.wait()
    notices = [line for line in host.lines if "NOTIFY:" in line]
    assert sum("This conversation is refused" in line for line in notices) == 1, \
        "PRODUCT: rebuilt identity refusal must be said exactly once"
    assert not any("reacquir" in line.lower() for line in notices), \
        "PRODUCT: permanent refusal must not promise reacquiring registration"
    commands_after = gate.with_suffix(".commands").read_text().splitlines()
    assert not any("agent hook" in line for line in commands_after[len(commands_before):]), \
        "PRODUCT: permanent refusal retried a hook against the rebuilt identity"
    assert not (DATA / "nodes/agent/sessions" / f"{host.session}.json").exists(), \
        "PRODUCT: refused conversation registered against its rebuilt identity"
    print("VERDICT GREEN: decided turn's late exit preserves one permanent refusal and never reacquires", flush=True)

def extension(moved=False, resumed=False):
    r = room()
    create("person")
    link = run(["room", "link", r, "--node", "agent"]).stdout.strip()
    run(["room", "join", link, "--node", "person", "--passphrase-file", "-"], "room passphrase\n")
    person = run(["id", "--node", "person"]).stdout.strip()
    agent = run(["id", "--node", "agent"]).stdout.strip()
    run(["trust", "add", person, "--node", "agent", "--name", "person"], "\n")
    run(["trust", "add", agent, "--node", "person", "--name", "agent"], "\n")
    second = None
    if moved:
        run(["room", "create", "--node", "agent", "--name", "after-move", "--passphrase-file", "-"],
            "room passphrase\n")
        second = next(line.split()[0] for line in run(["room", "list", "--node", "agent"]).stdout.splitlines()
                      if "after-move" in line)
        link = run(["room", "link", second, "--node", "agent"]).stdout.strip()
        run(["room", "join", link, "--node", "person", "--passphrase-file", "-"], "room passphrase\n")
    host = Host(WORK, r, stop_after_decision=moved)
    host.turn("hello")
    host.hold.with_suffix(".arm").write_text("hold")
    # The stand-in uses <hold>.arm, not Path.with_suffix on a suffixed filename.
    run(["room", "post", r, "--node", "person", "--type", "ask", "--to", agent,
         "--session", "rg4-person", "rg4-held-news"])
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
    if moved:
        # The stand-in stopped its own event loop immediately after giving the decision,
        # before the extension can handle the hook's exit and schedule another hook.
        paused.add(host.p.pid)
        def saved_receipt():
            for file in DATA.glob("**/omp-uncertain/*"):
                try:
                    saved = json.loads(file.read_text())
                except (OSError, ValueError):
                    continue
                if saved.get("session") == host.session and saved.get("decision") is True and saved.get("receipts"):
                    return True
            return False
        wait(saved_receipt, "a real decided turn leaves its pending attention receipt")
        def preparation_exited():
            rows = subprocess.run(["ps", "-axo", "ppid=,command="], capture_output=True, text=True).stdout
            return not any(line.split(None, 1)[0] == str(host.p.pid) and "--omp-prepare" in line
                           for line in rows.splitlines() if line.split())
        wait(preparation_exited, "the decided preparation exits before the operator moves the room")
    else:
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
    if moved:
        run(["agent", "room", second, "--node", "agent", "--session", host.session])
        wait(lambda: any(row.get("id") == host.session and row.get("open") is False for row in session_rows(r)),
             "the move closes the old room's Session before the next hook")
        if resumed:
            # End A through the real move, then resume this same conversation in A.
            run(["agent", "room", r, "--node", "agent", "--session", host.session])
            wait(lambda: host.session in open_sessions(r), "the conversation resumes a new Session in its original room")
        probe = run(["agent", "hook", "--node", "agent", "--session", host.session, "--omp-check-uncertainty"],
                    extra={"VOX_HARNESS": "omp"}, check=False)
        changed = "a same-room Session resume" if resumed else "a room move"
        assert probe.returncode == 0, f"PRODUCT: the next hook could not finish the saved decision after {changed}: {probe.returncode} {probe.stderr}"
        os.kill(host.p.pid, signal.SIGCONT)
        paused.remove(host.p.pid)
    post_room = r if resumed else second if moved else r
    marker = "rg4-after-session-resume" if resumed else "rg4-after-room-move" if moved else "rg4-after-restart"
    run(["room", "post", post_room, "--node", "person", marker])
    wait(lambda: marker in run(["room", "read", post_room, "--node", "agent"], check=False).stdout,
         "later post reaches the native conversation's node")
    wait(lambda: any(("STAGED:" in line and marker in line)
                     or "delivery in this conversation is uncertain" in line for line in host.lines),
         "the native extension stages later news or refuses the conversation")
    host.turn("read after recovery")
    # Accepted native history is legitimately reconstructed on later provider requests.
    # Count fresh materializations, not those replays, and require actual context injection.
    shown = sum("STAGED:" in line and marker in line for line in host.lines)
    injected = any("INJECTED" in line and marker in line for line in host.lines)
    assert shown == 1 and injected, f"PRODUCT: after daemon restart the same native conversation showed the later post {shown} fresh times (injected={injected}), not once"
    assert not any("delivery in this conversation is uncertain" in line for line in host.lines), \
        "PRODUCT: a saved native decision made the conversation uncertain"
    if moved:
        host.send("quit")
        host.p.wait()
        print(f"VERDICT GREEN: the next hook finished the saved decision after {changed}; later news was shown once", flush=True)
        return
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
    errors = []
    if f"this repo ({repo.resolve()})" not in out:
        errors.append(f"linked-worktree offer must name repository {repo.resolve()}, not {linked.resolve()}: {out}{err}")
    # Bind this registered start explicitly to an operator decision, then try to shadow it.
    (DATA / "rooms").write_text(f"repo {repo}\n    room none\n")
    (DATA / "rooms").chmod(0o600)
    refused = run(["agent", "room", "--node", "agent", "--session", "rg4-linked-offer", "--none"], check=False)
    if not (refused.returncode != 0 and "operator" in refused.stderr.lower() and "own terminal" in refused.stderr):
        errors.append(f"--none refusal must name who may change the map: {refused.stdout}{refused.stderr}")
    assert not errors, "PRODUCT: " + "; ".join(errors)
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
    elif CASE == "moved":
        extension(moved=True)
    elif CASE == "resumed":
        extension(moved=True, resumed=True)
    elif CASE == "riders":
        riders()
    elif CASE == "undecided":
        undecided()
    elif CASE == "identity":
        identity_refusal()
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
