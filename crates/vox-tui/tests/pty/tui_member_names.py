#!/usr/bin/env python3
"""tui_member_names.py <vox> <tag> — #198 (V210-24), the TUI half, through the shipped `vox tui`.

Alice creates a room; Bob and Carol join it, all through real daemons. Bob trusts Alice as
"alice" and does not trust Carol. Bob's daemon is stopped and his real `vox tui` is opened in a
pty (pyte at 160x50). His members pane must name Alice "alice" (not her fingerprint), and Carol by
26 characters of her fingerprint followed by "(not in keyring)", whole. Exit 0 = pass, 1 = red
(the product's), 2 = apparatus (CANNOT MEASURE). A `vox` step on the way that fails (an identity,
a daemon, create, invite, join, trust, the roster) is the product's red: it prints `PRODUCT:` with
what `vox` said and exits 1. Every process is recorded and killed by PID.

Every wait is bounded by what the product allows: `vox room join` by JOIN_SECS, every other verb
by 120 s, and a verb past its bound is a named product RED. The driver's own budget (`vox_pty.py`,
V210-54) is sized for the debug build: past it the driver says `HUNG at <stage>` with its stack and
exits as APPARATUS, because a verb past its own bound would have been the product's RED first, so
every wait of the product's was still within its bound (V210-111, #307: at a 240 s budget a debug
run was cut off mid-join while both joining daemons were on CPU in the proof of work and the room
key's Argon2id seal, and that read as a hang).
"""
import os, re, subprocess, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, TAG = sys.argv[1], sys.argv[2]
# Sized for the debug build, whose joins grind their proof of work for a minute or more each (40-58 s
# measured at load 65, plus 5-12 s sealing the room key): two joins at JOIN_SECS each, and the rest
# (about 150 s in debug). The Rust wrapper's bound sits above it. A release run takes about 40 s.
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "1260"))
# A member waits 480 s for a joiner's proof of work (V210-87) plus 5 s of slack; the rest of the
# exchange and the seal follow it. A join that has not returned by then is past what the product
# allows, and is a named RED.
JOIN_SECS = 540
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

def apparatus(why):
    print(f"{TAG} APPARATUS: {why}"); sys.exit(2)

def product(why):
    global code
    code = 1
    print(f"{TAG} PRODUCT: {why}"); print(f"{TAG} RED"); sys.exit(1)

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
    if not until(got_spec, 30):
        product("the anchor `vox node` printed no spec within 30 s: " + open(f"{S}/anchor.err").read())
    stage("identities and daemons")
    fp = {}
    for w in ("alice", "bob", "carol"):
        r = run(w, "id", "--identity-passphrase-file", f"{S}/idpass")
        if r.returncode != 0: product(f"{w}'s `vox id` failed: {r.stderr}")
        m = re.search(r"[a-z2-7]{52}", r.stdout)
        if m is None: product(f"{w}'s `vox id` printed no fingerprint: {r.stdout!r}")
        fp[w] = m.group(0)
    daemons = {w: spawn(w, "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                        "--passphrase-file", f"{S}/idpass", out=w) for w in ("alice", "bob", "carol")}
    for w in daemons:
        if not until(lambda: run(w, "room", "list").returncode == 0, 60):
            product(f"{w}'s daemon never answered `vox room list` within 60 s: " + open(f"{S}/{w}.err").read())
    stage("room create, invite, join")
    c = run("alice", "room", "create", "--name", "m", stdin="room pass")
    if c.returncode != 0: product(f"alice's `vox room create` failed: {c.stderr.strip()}")
    listed = run("alice", "room", "list")
    if not listed.stdout.split(): product(f"alice's `vox room list` shows no room after create: {listed.stderr.strip()}")
    room = listed.stdout.split()[0]
    inv = run("alice", "room", "invite", room)
    if inv.returncode != 0: product(f"alice's `vox room invite` failed: {inv.stderr.strip()}")
    link = inv.stdout.strip()
    for w in ("bob", "carol"):
        j = run(w, "room", "join", link, "--name", "m", stdin="room pass")
        if j.returncode != 0: product(f"{w}'s `vox room join` failed: {j.stderr.strip()}")
    t = run("bob", "trust", "add", fp["alice"], "--name", "alice", "--identity-passphrase-file", f"{S}/idpass")
    if t.returncode != 0: product(f"bob's `vox trust add` failed: {t.stderr.strip()}")
    stage("bob's roster")
    # Bob's node must know both members before its TUI is opened.
    def roster():
        r = run("bob", "room", "roster", room)
        return r.returncode == 0 and fp["alice"] in r.stdout and fp["carol"] in r.stdout
    if not until(roster, 90, 1):
        last = run("bob", "room", "roster", room)
        product(f"bob's `vox room roster` never listed both alice and carol within 90 s: {last.stdout}{last.stderr}")
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
    # A verb past the product's bound for it is the RED below, raised before this; so here every
    # wait was still within its bound, and the budget that ran out is the driver's.
    print(f"{TAG} HUNG at {h}")
    print(f"{TAG} APPARATUS: the driver ran past its {BUDGET} s budget at {h} with no product "
          f"wait past its bound")
    code = 2
except subprocess.TimeoutExpired as t:
    # A `vox` verb that never returned is a red of the product's, named, not a driver with no verdict.
    print(f"{TAG} RED: `vox {' '.join(t.cmd[1:3])}` did not return within {t.timeout:.0f} s")
    code = 1
finally:
    disarm()
    stage("stopping every process")
    if tui is not None and not tui.stop():
        # A driver that cannot stop what it started has leaked it, and is how a job hangs (#240).
        # No process can refuse SIGKILL: what keeps one is its pty, which is the driver's to drain.
        # A verdict already given stands; a pass becomes CANNOT MEASURE.
        print(f"{TAG} APPARATUS: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 2 if code == 0 else code
    for p in PROCS:
        if p.poll() is None:
            stop(p)
    stage(f"done, exit {code}")
sys.exit(code)
