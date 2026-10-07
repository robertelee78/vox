#!/usr/bin/env python3
"""tui_addressee_names.py <vox> <tag> — PRD-001 R15 (#18), the TUI half, through the shipped `vox tui`.

Alice creates a room; Bob and Carol join it, all through real daemons. Alice trusts Bob as "bob" and
Carol as "mom". Bob trusts Alice as "alice" and has no name for Carol. Alice posts an `ask` with
`vox room post --to mom`: the message carries Carol's fingerprint, never "mom". Each node's real
`vox tui` is then opened in a pty (pyte at 160x50), its own daemon stopped first:

- Bob's timeline must show the message as `alice to <26 characters of Carol's fingerprint>:`, and
  never "to mom", which is Alice's name for her and not his;
- Alice's must show it as `you to mom:`, her own name.

Then (ADR-028 K-4, #474) Bob trusts Carol as "Alice", which differs from his "alice" only by case.
His TUI must show them as `alice#<6 characters of Alice's fingerprint>` and `Alice#<6 of Carol's>`,
never either bare; and "@alice …" typed in his composer must carry Alice's whole fingerprint in
`to`.

Exit 0 = pass, 1 = red (the product's), 2 = apparatus (CANNOT MEASURE). A `vox` step on the way that
fails is the product's red (`PRODUCT (staging):`). Every process is recorded and killed by PID.
Every wait is bounded by what the product allows, as in `tui_member_names.py`.
"""
import json, os, re, subprocess, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pane, pyte, stage, is_keyring_change, typed_run  # noqa: E402

VOX, TAG = sys.argv[1], sys.argv[2]
# Sized for the debug build, as `tui_member_names.py` is: two joins at JOIN_SECS each, and the rest.
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "1260"))
JOIN_SECS = 540
MARK = "ADDRESSEE-MARK"
AT_MARK = "AT-ALIAS-MARK"
SP = os.environ.get("VOX_PTY_SCRATCH") or __import__("tempfile").mkdtemp(prefix="vox-tui-to-")
S = f"{SP}/tuito-{TAG}"
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

class Red(Exception):
    """A verdict of the product's, printed before it is raised."""

def apparatus(why):
    print(f"{TAG} APPARATUS: {why}"); sys.exit(2)

def staging(why):
    print(f"{TAG} PRODUCT (staging): {why}"); print(f"{TAG} RED"); raise Red

def trust(w, who, name):
    t = run(w, "trust", "add", fp[who], "--name", name, "--identity-passphrase-file", f"{S}/idpass")
    if t.returncode != 0: staging(f"{w}'s `vox trust add` of {who} failed: {t.stderr.strip()}")

def screen_of(w):
    """`w`'s own `vox tui`, opened on the room: the timeline as drawn, once the mark shows."""
    t = Tui([VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec], env(w))
    try:
        t.pump(4)
        t.key("id pass\r", 4)
        t.key("\r", 2)
        t.key("room pass\r", 4)
        t.key("\r", 2)
        t.until(lambda: MARK in "\n".join(t.display()), 60, 1)
        rows = [r.rstrip() for r in t.display()]
        print(f"{TAG} {w}'s TUI drew {t.bytes} bytes; rows showing the mark:")
        for r in rows:
            if MARK in r or " to " in r:
                print(f"  |{r}")
        return rows
    finally:
        if not t.stop():
            print(f"{TAG} APPARATUS: {w}'s vox tui (pid {t.pid}) outlived SIGKILL and could not be reaped")
            sys.exit(2)

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
    if not until(got_spec, 30): staging("the anchor `vox node` printed no spec within 30 s: " + open(f"{S}/anchor.err").read())
    stage("identities and daemons")
    fp = {}
    for w in ("alice", "bob", "carol"):
        r = run(w, "id", "--identity-passphrase-file", f"{S}/idpass")
        if r.returncode != 0: staging(f"{w}'s `vox id` failed: {r.stderr}")
        fp[w] = re.search(r"[a-z2-7]{52}", r.stdout).group(0)
    daemons = {w: spawn(w, "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                        "--passphrase-file", f"{S}/idpass", out=w) for w in ("alice", "bob", "carol")}
    for w in daemons:
        if not until(lambda: run(w, "room", "list").returncode == 0, 60):
            staging(f"{w}'s daemon never answered `vox room list` within 60 s: " + open(f"{S}/{w}.err").read())
    stage("room create, invite, join")
    c = run("alice", "room", "create", "--passphrase-file", "-", "--name", "m", stdin="room pass")
    if c.returncode != 0: staging(f"alice's `vox room create` failed: {c.stderr.strip()}")
    room = run("alice", "room", "list").stdout.split()[0]
    link = run("alice", "room", "link", room).stdout.strip()
    for w in ("bob", "carol"):
        j = run(w, "room", "join", "--passphrase-file", "-", link, stdin="room pass")
        if j.returncode != 0: staging(f"{w}'s `vox room join` failed: {j.stderr.strip()}")
    stage("each node's own names")
    trust("alice", "bob", "bob")
    trust("alice", "carol", "mom")
    trust("bob", "alice", "alice")
    def roster():
        r = run("alice", "room", "roster", room)
        return r.returncode == 0 and fp["carol"][:12] in r.stdout
    if not until(roster, 90, 1): staging("alice's `vox room roster` never listed carol in 90 s: " + run("alice", "room", "roster", room).stdout)

    stage("alice posts to mom")
    p = run("alice", "room", "post", room, "--session", "alice-s", "--type", "ask", "--to", "mom",
            "-", stdin=f"{MARK} please look")
    if p.returncode != 0:
        print(f"{TAG} RED: alice's `vox room post --to mom` was refused: {p.stderr.strip()}")
        raise Red
    def bob_has_it():
        r = run("bob", "room", "read", room)
        return r.returncode == 0 and MARK in r.stdout
    if not until(bob_has_it, 90, 1): staging("bob's `vox room read` never showed alice's message in 90 s")
    rows = [json.loads(l) for l in run("alice", "room", "read", room, "--json").stdout.splitlines() if l.strip()]
    sent = next((x for x in rows if MARK in (x.get("text") or "")), None)
    to = (sent or {}).get("envelope", {}).get("to")
    if to != [fp["carol"]]:
        print(f"{TAG} RED: the message must carry exactly carol's fingerprint in `to`, never alice's "
              f"name for her: {to!r}")
        raise Red

    stop(daemons["bob"])
    stage("bob's tui")
    bob_rows = screen_of("bob")
    stop(daemons["alice"])
    stage("alice's tui")
    alice_rows = screen_of("alice")

    want_fp = fp["carol"][:26]
    bob_all, alice_all = "\n".join(bob_rows), "\n".join(alice_rows)
    bob_ok = f"alice to {want_fp}:" in bob_all and "to mom" not in bob_all
    alice_ok = "you to mom:" in alice_all
    print(f"{TAG} bob shown 'alice to <carol's fingerprint>:' and never 'to mom': {bob_ok}; "
          f"alice shown 'you to mom:': {alice_ok}")
    if not (bob_ok and alice_ok):
        print(f"{TAG} PRODUCT: each node's TUI must show the addressee by its own name for her, or "
              f"her fingerprint where it has none, never another node's name")

    # ADR-028 K-4 (#474): Bob trusts Carol as "Alice", an alias his "alice" differs from only by
    # case. His TUI must tell the two apart by a fingerprint suffix, and his composer's "@alice"
    # must address Alice's whole fingerprint.
    stage("lookalike aliases, and @alias in the composer")
    # Bob's daemon was stopped for his TUI: a keyring change asks the node, so it runs again for it.
    daemons["bob"] = spawn("bob", "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                           "--passphrase-file", f"{S}/idpass", out="bob-again")
    if not until(lambda: run("bob", "room", "list").returncode == 0, 60):
        staging("bob's daemon, started again, never answered `vox room list` within 60 s: "
                + open(f"{S}/bob-again.err").read())
    trust("bob", "carol", "Alice")
    stop(daemons["bob"])
    t = Tui([VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec], env("bob"))
    try:
        t.pump(4)
        t.key("id pass\r", 4)
        t.key("\r", 2)
        t.key("room pass\r", 4)
        t.key("\r", 2)
        t.until(lambda: MARK in "\n".join(t.display()), 60, 1)
        t.key("\t", 1)  # timeline -> composer
        t.key(f"@alice {AT_MARK} for you", 1)
        t.key("\r", 3)
        def sent_to():
            r = run("bob", "room", "read", room, "--json")
            rows = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
            got = next((x for x in rows if AT_MARK in (x.get("text") or "")), None)
            return None if got is None else (got.get("envelope") or {}).get("to")
        t.until(lambda: sent_to() is not None, 30, 1)
        to_at = sent_to()
        t.pump(3)
        lookalike = [r.rstrip() for r in t.display()]
        print(f"{TAG} bob's TUI with alice and Alice (carol) in his keyring:")
        for r in lookalike:
            if "lice" in r:
                print(f"  |{r}")
        print(f"{TAG} its members pane:")
        for r in pane(lookalike, "Members"):
            if r.strip():
                print(f"  |{r.rstrip()}")
    finally:
        if not t.stop():
            print(f"{TAG} APPARATUS: bob's vox tui (pid {t.pid}) outlived SIGKILL and could not be reaped")
            sys.exit(2)
    a6, c6 = fp["alice"][:6], fp["carol"][:6]
    members = [r.strip() for r in pane(lookalike, "Members")]
    # Each member's row is its trust glyph and name; neither alias may stand there without its
    # suffix, and the timeline names alice's message to carol by both suffixed names.
    told_apart = (any(r.endswith(f"alice#{a6}") for r in members)
                  and any(r.endswith(f"Alice#{c6}") for r in members)
                  and not any(re.search(r"\b[aA]lice$", r) for r in members)
                  and f"alice#{a6} to Alice#{c6}:" in "\n".join(lookalike))
    at_ok = to_at == [fp["alice"]]
    print(f"{TAG} bob's TUI shows alice#{fp['alice'][:6]} and Alice#{fp['carol'][:6]}, and neither "
          f"bare: {told_apart}; bob's '@alice' went to alice's whole fingerprint: {at_ok} ({to_at!r})")
    if not told_apart:
        print(f"{TAG} PRODUCT: two aliases that differ only by case must each be shown with a "
              f"fingerprint suffix")
    if not at_ok:
        print(f"{TAG} PRODUCT: '@alice' typed in the composer must address alice's whole fingerprint")
    code = 0 if (bob_ok and alice_ok and told_apart and at_ok) else 1
    print(f"{TAG} {'PASS' if code == 0 else 'RED'}")
except Red:
    code = 1
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
    for p in PROCS:
        if p.poll() is None:
            stop(p)
    stage(f"done, exit {code}")
sys.exit(code)
