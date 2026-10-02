#!/usr/bin/env python3
"""tui_expired.py <vox> <tag> — PRD-001 R10 in the TUI, through the shipped `vox tui`.

"An expired message leaves nothing visible." Alice and Bob share a room whose retention is 20 s,
through real daemons and an anchor. Alice posts three messages; Bob reads them. Bob's daemon is
stopped and his real `vox tui` opened in a pty (pyte at 160x50) on the room:

- it draws the three (a TUI that drew nothing would prove nothing);
- once they are past the room's retention, the open TUI no longer shows any of them;
- a later post of Alice's is drawn, so the TUI is still following the room.

Exit 0 = pass, 1 = red (the product's), 2 = apparatus (CANNOT MEASURE). A `vox` step on the way
that fails (an identity, a daemon, create, invite, join, trust, retention, a post, the read) is the
product's red: it prints `PRODUCT:` with what `vox` said and exits 1. Every process is recorded
and killed by PID. Bounded throughout (`vox_pty.py`, V210-54).
"""
import os, re, subprocess, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, TAG = sys.argv[1], sys.argv[2]
# One join in a debug build grinds its proof of work for a minute or more; the rest is waiting on
# the 20 s retention. A release run takes about a minute.
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "900"))
JOIN_SECS = 540
RETENTION = 20
SP = os.environ.get("VOX_PTY_SCRATCH") or __import__("tempfile").mkdtemp(prefix="vox-tui-expired-")
S = f"{SP}/tuix-{TAG}"
subprocess.run(["rm", "-rf", S])
for w in ("anchor", "alice", "bob"):
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
    secs = JOIN_SECS if args[:2] == ("room", "join") else 120
    return subprocess.run([VOX, *args], env=env(w), input=stdin, capture_output=True, text=True, timeout=secs)

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

def product(why):
    global code
    code = 1
    print(f"{TAG} PRODUCT: {why}"); print(f"{TAG} RED"); sys.exit(1)

def must(w, *args, stdin=None):
    r = run(w, *args, stdin=stdin)
    if r.returncode != 0:
        product(f"{w}'s `vox {' '.join(args[:2])}` failed: {r.stderr.strip()}")
    return r

tui = None
code = 2
try:
    stage("anchor")
    spawn("anchor", "node", "--listen", "127.0.0.1:0", out="anchor")
    spec = None
    def got_spec():
        global spec
        m = re.search(r"[a-z2-7]{52}@/ip4/127\.0\.0\.1/udp/\d+", open(f"{S}/anchor.out").read())
        spec = m.group(0) if m else None
        return spec
    if not until(got_spec, 30):
        product("the anchor `vox node` printed no spec within 30 s: " + open(f"{S}/anchor.err").read())
    stage("identities and daemons")
    fp = {}
    for w in ("alice", "bob"):
        r = must(w, "id", "--identity-passphrase-file", f"{S}/idpass")
        m = re.search(r"[a-z2-7]{52}", r.stdout)
        if m is None: product(f"{w}'s `vox id` printed no fingerprint: {r.stdout!r}")
        fp[w] = m.group(0)
    daemons = {w: spawn(w, "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                        "--passphrase-file", f"{S}/idpass", out=w) for w in ("alice", "bob")}
    for w in daemons:
        if not until(lambda: run(w, "room", "list").returncode == 0, 60):
            product(f"{w}'s daemon never answered `vox room list` within 60 s: " + open(f"{S}/{w}.err").read())
    stage("room create, invite, join, trust, retention")
    must("alice", "room", "create", "--name", "m", stdin="room pass")
    listed = must("alice", "room", "list").stdout.split()
    if not listed: product("alice's `vox room list` shows no room after create")
    room = listed[0]
    link = must("alice", "room", "invite", room).stdout.strip()
    must("bob", "room", "join", link, "--name", "m", stdin="room pass")
    must("alice", "trust", "add", fp["bob"], "--name", "bob", "--identity-passphrase-file", f"{S}/idpass")
    must("bob", "trust", "add", fp["alice"], "--name", "alice", "--identity-passphrase-file", f"{S}/idpass")
    must("alice", "room", "retention", room, str(RETENTION))
    stage("alice posts, bob reads")
    for i in (1, 2, 3):
        must("alice", "room", "post", room, f"soon gone {i}")
    def bob_read():
        r = run("bob", "room", "read", room)
        return r.returncode == 0 and r.stdout.count("soon gone ") == 3
    if not until(bob_read, 90, 1):
        last = run("bob", "room", "read", room)
        product(f"bob's node never read alice's three posts within 90 s: {last.stdout}{last.stderr}")
    stop(daemons["bob"])

    stage("bob's tui: unlock and open the room")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec], env("bob"))
    tui.pump(4)
    tui.key("id pass\r", 4)
    tui.key("\r", 2)
    tui.key("room pass\r", 4)
    tui.key("\r", 2)
    screen = lambda: "\n".join(tui.display())
    stage("the tui draws the three")
    if not tui.until(lambda: "soon gone" in screen(), 30, 1):
        product("bob's `vox tui` never drew alice's posts within 30 s of opening the room:\n" + screen())
    drawn = time.time()
    stage("they expire in the open tui")
    gone = tui.until(lambda: "soon gone" not in screen(), RETENTION * 3, 1)
    print(f"{TAG} expired rows left the open TUI: {gone} ({time.time() - drawn:.0f} s after it drew them)")
    if not gone:
        print(f"{TAG} screen:\n{screen()}")
        print(f"{TAG} RED"); code = 1
    else:
        stage("a later post is drawn")
        must("alice", "room", "post", room, "still here")
        later = tui.until(lambda: "still here" in screen(), 60, 1)
        print(f"{TAG} the later post drawn: {later}")
        if not later:
            product("bob's open `vox tui` never drew alice's later post within 60 s:\n" + screen())
        code = 0
        print(f"{TAG} PASS")
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    print(f"{TAG} APPARATUS: the driver ran past its {BUDGET} s budget at {h} with no product "
          f"wait past its bound")
    code = 2
except subprocess.TimeoutExpired as t:
    print(f"{TAG} RED: `vox {' '.join(t.cmd[1:3])}` did not return within {t.timeout:.0f} s")
    code = 1
finally:
    disarm()
    stage("stopping every process")
    if tui is not None and not tui.stop():
        print(f"{TAG} APPARATUS: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 2 if code == 0 else code
    for p in PROCS:
        if p.poll() is None:
            stop(p)
    stage(f"done, exit {code}")
sys.exit(code)
