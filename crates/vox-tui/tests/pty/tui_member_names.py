#!/usr/bin/env python3
"""tui_member_names.py <vox> <tag> — #198 (V210-24), the TUI half, through the shipped `vox tui`.

Alice creates a room; Bob and Carol join it, all through real daemons. Bob trusts Alice as
"alice" and does not trust Carol. Bob's daemon is stopped and his real `vox tui` is opened in a
pty (pyte at 160x50). His members pane must name Alice "alice" (not her fingerprint), and Carol by
26 characters of her fingerprint, whole, with "not in keyring" on the state line under it (ADR-028
L-4: the pane is too narrow for both on one row beside her trust glyph).

ADR-028 K-1, L-9, W-1 (#472): with Alice selected in the members pane, her card is drawn under her:
her whole fingerprint in groups of four beside five rows of fingerprint art. `k` on the room list
opens the keyring view, which shows each node Bob trusts, Alice and Erin (a node never in the
room), by name with its grouped fingerprint and its art; Alice's art there is her card's, and
Erin's is another. Mutation: the art drawn from the alias instead of the fingerprint turns it red.

ADR-020 §4.9b (#568): a session of Alice's takes part in work coordination, so its `hello` is
posted, carrying the machine Vox says it runs on (data.os, os_version, arch). Alice trusts Bob, so
he reads it; her card in his members pane must say "says it runs on <os> <os_version> (<arch>)",
exactly what that Vox-written hello says. Mutation: the line dropped from the card turns it red.

Exit 0 = pass, 1 = red
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
from vox_pty import Hung, Tui, arm, disarm, pane as pane_of, pyte, stage, is_keyring_change, typed_run  # noqa: E402

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
for w in ("anchor", "alice", "bob", "carol", "erin"):
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
    if is_keyring_change(args):
        # A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
        return typed_run([VOX, *args], env(w), secs)
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
    for w in ("alice", "bob", "carol", "erin"):
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
    c = run("alice", "room", "create", "--passphrase-file", "-", "--name", "m", stdin="room pass")
    if c.returncode != 0: product(f"alice's `vox room create` failed: {c.stderr.strip()}")
    listed = run("alice", "room", "list")
    if not listed.stdout.split(): product(f"alice's `vox room list` shows no room after create: {listed.stderr.strip()}")
    room = listed.stdout.split()[0]
    inv = run("alice", "room", "link", room)
    if inv.returncode != 0: product(f"alice's `vox room link` failed: {inv.stderr.strip()}")
    link = inv.stdout.strip()
    for w in ("bob", "carol"):
        j = run(w, "room", "join", "--passphrase-file", "-", link, stdin="room pass")
        if j.returncode != 0: product(f"{w}'s `vox room join` failed: {j.stderr.strip()}")
    for (who, name) in (("alice", "alice"), ("erin", "erin")):
        t = run("bob", "trust", "add", fp[who], "--name", name, "--identity-passphrase-file", f"{S}/idpass")
        if t.returncode != 0: product(f"bob's `vox trust add` of {name} failed: {t.stderr.strip()}")
    stage("alice's session says hello")
    # Alice trusts Bob, so he reads her; a session of hers takes part in work coordination, so its
    # hello is posted, with the machine Vox fills in (ADR-020 §4.9b).
    t = run("alice", "trust", "add", fp["bob"], "--name", "bob", "--identity-passphrase-file", f"{S}/idpass")
    if t.returncode != 0: product(f"alice's `vox trust add` of bob failed: {t.stderr.strip()}")
    e = env("alice"); e.update(VOX_SESSION="alice-session-1")
    p = subprocess.run([VOX, "room", "post", room, "--type", "status", "--work", "test:568", "-"],
                       env=e, input="checking the machine claim", capture_output=True, text=True, timeout=120)
    if p.returncode != 0: product(f"alice's session's `vox room post --work` failed: {p.stderr.strip()}")
    import json
    hello = {}
    def bob_reads_hello():
        global hello
        r = run("bob", "room", "read", room, "--json")
        for line in r.stdout.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            env_ = row.get("envelope") or {}
            if env_.get("type") == "hello" and env_.get("from") == "alice-session-1":
                hello = env_.get("data") or {}
                return True
        return False
    if not until(bob_reads_hello, 90, 1):
        product("bob never read alice's session's hello within 90 s")
    if not (hello.get("os") and hello.get("arch")):
        product(f"alice's hello carries no machine (ADR-020 §4.9b): its data is {hello!r}")
    machine = " ".join(x for x in (hello["os"], hello.get("os_version", "")) if x) + f" ({hello['arch']})"
    print(f"{TAG} bob reads alice's hello: {hello!r}")
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
    # The members pane, found by its title; read every row of it from the emulated screen.
    def members():
        return pane_of(tui.display(), "Members")
    want_carol = fp["carol"][:26]
    def seen():
        txt = "\n".join(members())
        return "alice" in txt and want_carol in txt
    stage("bob's members pane")
    tui.until(seen, 30, 1)
    pane = [r.rstrip() for r in members() if r.strip()]
    print(f"{TAG} the TUI drew {tui.bytes} bytes")
    print(f"{TAG} members pane:")
    for r in pane:
        print(f"  |{r}")
    txt = "\n".join(pane)
    alice_ok = re.search(r"(^|[^a-z2-7])alice([^a-z2-7]|$)", txt, re.M) is not None
    alice_fp_shown = fp["alice"][:8] in txt
    carol_at = next((i for i, r in enumerate(pane) if want_carol in r), None)
    carol_ok = (carol_at is not None and carol_at + 1 < len(pane)
                and pane[carol_at + 1].strip().strip("│").strip().startswith("not in keyring"))
    print(f"{TAG} alice named 'alice': {alice_ok}; alice's fingerprint shown: {alice_fp_shown}; "
          f"carol by 26 chars, 'not in keyring' under: {carol_ok}")

    stage("alice's card")
    # The art's rows: ten facet characters, two per cell; the grouped fingerprint is beside them.
    art = lambda rows: [m.group(0) for m in (re.search(r"[◢◣◤◥]{10}", r) for r in rows) if m]
    grouped = lambda f: " ".join(f[i:i + 4] for i in range(0, len(f), 4))
    # The selected row is the marker, Alice's trust glyph, then her name: "▶ ⇄ alice" (L-4).
    picked = lambda r: re.search(r"▶ \S+ ?alice\b", r) is not None
    for _ in range(4):
        if any(picked(r) for r in members()):
            break
        tui.key("\x1b[B", 1)  # Down: the next member
    rows = [r.rstrip() for r in members()]
    at = next((i for i, r in enumerate(rows) if picked(r)), None)
    under = rows[at + 1:at + 10] if at is not None else []
    card_art = art(under)
    first_groups = grouped(fp["alice"])[:24]
    card_ok = len(card_art) == 5 and any(first_groups in r for r in under)
    print(f"{TAG} alice selected: {at is not None}; her card: art {card_art!r}, "
          f"'{first_groups}' beside it: {any(first_groups in r for r in under)}")
    machine_ok = any(f"says it runs on {machine}" in r for r in under)
    print(f"{TAG} her card says she runs on {machine!r}: {machine_ok}")
    for r in under:
        print(f"  |{r}")

    stage("the keyring view")
    tui.key("\x1b", 2)  # Esc: back to the room list
    tui.key("k", 2)
    tui.until(lambda: any("Keyring" in r for r in tui.display()), 10, 0.5)
    screen = [r.rstrip() for r in tui.display()]
    def entry(name):
        """The art and grouped text under `name`'s row in the keyring view."""
        i = next((i for i, r in enumerate(screen) if re.search(rf"│\s+{name}\s*│?$", r)), None)
        return ([], []) if i is None else (art(screen[i + 1:i + 6]), screen[i + 1:i + 6])
    (alice_art, alice_rows), (erin_art, erin_rows) = entry("alice"), entry("erin")
    print(f"{TAG} keyring view:")
    for r in screen:
        if r.strip():
            print(f"  |{r}")
    keyring_ok = (len(alice_art) == 5 and len(erin_art) == 5
                  and any(first_groups in r for r in alice_rows)
                  and any(grouped(fp["erin"])[:24] in r for r in erin_rows))
    same_as_card = alice_art == card_art
    differs = alice_art != erin_art
    print(f"{TAG} the keyring shows alice and erin with their grouped fingerprints and art: "
          f"{keyring_ok}; alice's art is her card's: {same_as_card}; erin's is another: {differs}")
    code = 0 if (alice_ok and not alice_fp_shown and carol_ok and card_ok and keyring_ok
                 and same_as_card and differs and machine_ok) else 1
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
