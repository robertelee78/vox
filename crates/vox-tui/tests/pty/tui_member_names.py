#!/usr/bin/env python3
"""tui_member_names.py <vox> <tag> — #198 (V210-24), the TUI half, through the shipped `vox tui`.

Alice creates a room; Bob and Carol join it, all through real daemons. Bob trusts Alice as
"alice" and does not trust Carol. Bob's daemon is stopped and his real `vox tui` is opened in a
pty (pyte at 160x50). His members pane must name Alice "alice" (not her fingerprint), and Carol by
26 characters of her fingerprint followed by "(not in keyring)", whole. Exit 0 = pass, 1 = red,
2 = apparatus. Every process is recorded and killed by PID.

Bounded throughout (`vox_pty.py`, V210-54): past its budget the driver says `HUNG at <stage>`
with its stack, stops everything and exits red.
"""
import os, re, subprocess, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, TAG = sys.argv[1], sys.argv[2]
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "240"))
SP = os.environ.get("VOX_PTY_SCRATCH") or __import__("tempfile").mkdtemp(prefix="vox-tui-names-")
S = f"{SP}/tuin-{TAG}"
subprocess.run(["rm", "-rf", S])
for w in ("anchor", "alice", "bob", "carol"):
    for d in ("data", "cfg"):
        os.makedirs(f"{S}/{w}/{d}")
open(f"{S}/idpass", "w").write("id pass")
PROCS = []
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)"); sys.exit(2)
arm(BUDGET, TAG)

def env(w):
    e = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
    e.update(VOX_DATA_DIR=f"{S}/{w}/data", VOX_CONFIG_DIR=f"{S}/{w}/cfg", TERM="xterm-256color")
    return e

def run(w, *args, stdin=None):
    return subprocess.run([VOX, *args], env=env(w), input=stdin, capture_output=True, text=True, timeout=120)

def spawn(w, *args, out):
    p = subprocess.Popen([VOX, *args], env=env(w), stdin=subprocess.DEVNULL,
                         stdout=open(f"{S}/{out}.out", "w"), stderr=open(f"{S}/{out}.err", "w"))
    PROCS.append(p)
    return p

def stop(p):
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait()

def until(pred, secs, step=0.5):
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False

def apparatus(why):
    print(f"{TAG} APPARATUS: {why}"); sys.exit(2)

tui = None
code = 2
try:
    stage("anchor")
    anchor = spawn("anchor", "node", "--listen", "127.0.0.1:0", out="anchor")
    spec = None
    def got_spec():
        global spec
        m = re.search(r"[a-z2-7]{52}@/ip4/127\.0\.0\.1/udp/\d+", open(f"{S}/anchor.out").read())
        spec = m.group(0) if m else None
        return spec
    if not until(got_spec, 30): apparatus("anchor spec")
    stage("identities and daemons")
    fp = {}
    for w in ("alice", "bob", "carol"):
        r = run(w, "id", "--identity-passphrase-file", f"{S}/idpass")
        if r.returncode != 0: apparatus(f"{w} id: {r.stderr}")
        fp[w] = re.search(r"[a-z2-7]{52}", r.stdout).group(0)
    daemons = {w: spawn(w, "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                        "--passphrase-file", f"{S}/idpass", out=w) for w in ("alice", "bob", "carol")}
    for w in daemons:
        if not until(lambda: run(w, "room", "list").returncode == 0, 60): apparatus(f"{w} daemon")
    stage("room create, invite, join")
    if run("alice", "room", "create", "--name", "m", stdin="room pass").returncode != 0: apparatus("create")
    room = run("alice", "room", "list").stdout.split()[0]
    link = run("alice", "room", "invite", room).stdout.strip()
    for w in ("bob", "carol"):
        j = run(w, "room", "join", link, "--name", "m", stdin="room pass")
        if j.returncode != 0: apparatus(f"{w} join: {j.stderr.strip()}")
    t = run("bob", "trust", "add", fp["alice"], "--name", "alice", "--identity-passphrase-file", f"{S}/idpass")
    if t.returncode != 0: apparatus(f"trust add: {t.stderr}")
    stage("bob's roster")
    # Bob's node must know both members before its TUI is opened.
    def roster():
        r = run("bob", "room", "roster", room)
        return r.returncode == 0 and fp["alice"] in r.stdout and fp["carol"] in r.stdout
    if not until(roster, 90, 1): apparatus("bob never listed both alice and carol: " + run("bob", "room", "roster", room).stdout)
    stop(daemons["bob"])

    stage("bob's tui: unlock and open the room")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec], env("bob"))
    tui.pump(4)
    tui.key("id pass\r", 4)
    tui.key("\r", 2)
    tui.key("room pass\r", 4)
    tui.key("\r", 2)
    tui.key("\t", 1)   # timeline -> composer
    tui.key("\t", 1)   # composer -> members
    # The members pane is the right-hand column; read every row of it from the emulated screen.
    def members():
        return [row[100:] if len(row) > 100 else "" for row in tui.display()]
    want_carol = fp["carol"][:26]
    def seen():
        txt = "\n".join(members())
        return "alice" in txt and want_carol in txt
    stage("bob's members pane")
    tui.until(seen, 30, 1)
    pane = [r.rstrip() for r in members() if r.strip()]
    print(f"{TAG} the TUI drew {tui.bytes} bytes")
    print(f"{TAG} members pane (cols 100+):")
    for r in pane:
        print(f"  |{r}")
    txt = "\n".join(pane)
    alice_ok = re.search(r"(^|[^a-z2-7])alice([^a-z2-7]|$)", txt, re.M) is not None
    alice_fp_shown = fp["alice"][:8] in txt
    carol_row = next((r for r in pane if want_carol in r), None)
    carol_ok = carol_row is not None and "(not in keyring)" in carol_row
    print(f"{TAG} alice named 'alice': {alice_ok}; alice's fingerprint shown: {alice_fp_shown}; "
          f"carol by 26 chars + marker: {carol_ok}")
    code = 0 if (alice_ok and not alice_fp_shown and carol_ok) else 1
    print(f"{TAG} {'PASS' if code == 0 else 'RED'}")
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
finally:
    disarm()
    stage("stopping every process")
    if tui is not None and not tui.stop():
        # A driver that cannot stop what it started has leaked it, and is how a job hangs (#240).
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
    for p in PROCS:
        if p.poll() is None:
            stop(p)
    stage(f"done, exit {code}")
sys.exit(code)
