#!/usr/bin/env python3
"""tui_room_truth.py <vox> <tag> — V210-82 (#273), through the shipped `vox tui`.

Alice creates a room; Bob and Carol join it, all through real daemons. Alice and Bob trust each
other, so each consents to the other; nobody trusts Carol, and Carol trusts Bob. Alice posts 70 lines, more than Bob's
timeline pane holds. Bob's daemon is stopped and his real `vox tui` is opened in a pty (pyte at
160x50). Each claim prints one `CLAIM <name> ok|RED` line:

  newest    the timeline shows the room's newest message (m-070), not its first (m-001);
  follows   a message Alice posts while it is open (m-071) is shown when it arrives;
  scrolls   PageUp brings m-001 into view, and End returns to m-071;
  clamp     PageUp well past the oldest line, then one PageDown, moves the view one page (10
            lines): m-011 is the first line shown, not m-001 still;
  consent   Carol, whom Bob never consented to, is not shown "consented"; Alice, whom he did, is;
  verify    `:verify` on Carol does not show her "verified" (the node has nothing to compare);
  sync      the status bar says how many peers the node is connected to: the anchor and at least
            one member, so 2 or more (it said "idle" always);
  target    with Carol selected, Dave joins and sorts in above her; `:consent grant` then
            consents to Carol (her row becomes "consented") and not to whoever took her place;
  delivers  the grant is the node's: a line Bob then posts from the composer reaches Carol's
            `vox room read` (a pane that only drew "consented" would pass `target`, not this);
  revoke    `:consent revoke`, with Carol still selected and not first in the pane, takes her
            back to "← in-only" and leaves Alice "↔ consented"; a line Bob then posts reaches
            Alice's `vox room read` and not Carol's;
  reach     back on the channel list, the room reads "● online" while Bob's node is connected to
            its other members;
  unreach   once Alice's, Carol's and Dave's daemons are stopped, it reads "○ offline";
  fewer     and the status bar then says "connected to 1 peer": only the anchor is left;
  idle      once the anchor is stopped too, it says "idle", with no count.

`vox room join` is given JOIN_SECS (490 s), what a member waits for a joiner's proof of work plus
its slack; every other verb 120 s. A verb past its time is a named RED, not a hang.

Exit 0 = pass, 1 = red, 2 = apparatus (CANNOT MEASURE). Every process is recorded and killed by
PID. Bounded throughout (`vox_pty.py`, V210-54).
"""
import base64, os, re, subprocess, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, TAG = sys.argv[1], sys.argv[2]
# Sized for the debug build, whose joins grind their proof of work for minutes: two joins at
# JOIN_SECS each, and the rest (about 150 s in debug). The Rust wrapper's bound sits above it.
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "1170"))
# A member waits 480 s for a joiner's proof of work (V210-87), plus its 5 s slack: a join that has
# not returned by then is past what the product allows, and is a named RED.
JOIN_SECS = 490
SP = os.environ.get("VOX_PTY_SCRATCH") or __import__("tempfile").mkdtemp(prefix="vox-tui-truth-")
S = f"{SP}/tuit-{TAG}"
POSTS = 70  # the timeline pane holds 43 lines at 160x50
subprocess.run(["rm", "-rf", S])
WHO = ["anchor", "alice", "bob", "carol", "dave"]
for w in WHO:
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
    raise Apparatus(why)

class Apparatus(Exception):
    pass

def digest(fp):
    """The 32 bytes a 52-character base32 fingerprint spells: the order the members pane sorts by."""
    return base64.b32decode(fp.upper() + "====")[:32]

tui = None
code = 2
results = {}
def claim(name, ok, detail):
    results[name] = ok
    print(f"{TAG} CLAIM {name} {'ok' if ok else 'RED'}: {detail}")

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
    for w in WHO[1:]:
        r = run(w, "id", "--identity-passphrase-file", f"{S}/idpass")
        if r.returncode != 0: apparatus(f"{w} id: {r.stderr}")
        fp[w] = re.search(r"[a-z2-7]{52}", r.stdout).group(0)
    # Dave must sort in above Carol, so that his join moves her down the pane: of two fresh
    # identities, Carol is the one that sorts later.
    if digest(fp["dave"]) > digest(fp["carol"]):
        os.rename(f"{S}/carol", f"{S}/swap"); os.rename(f"{S}/dave", f"{S}/carol"); os.rename(f"{S}/swap", f"{S}/dave")
        fp["carol"], fp["dave"] = fp["dave"], fp["carol"]
    dave = "dave"
    daemons = {w: spawn(w, "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                        "--passphrase-file", f"{S}/idpass", out=w) for w in ("alice", "bob", "carol", dave)}
    for w in daemons:
        if not until(lambda: run(w, "room", "list").returncode == 0, 60): apparatus(f"{w} daemon")
    stage("room create, invite, join, trust")
    if run("alice", "room", "create", "--name", "m", stdin="room pass").returncode != 0: apparatus("create")
    room = run("alice", "room", "list").stdout.split()[0]
    link = run("alice", "room", "invite", room).stdout.strip()
    # Bob and Carol join at once, as two people given the link might: so the budget holds two
    # joins' worth of JOIN_SECS in a row (theirs, then Dave's), not three.
    joins = {w: subprocess.Popen([VOX, "room", "join", link, "--name", "m"], env=env(w),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True) for w in ("bob", "carol")}
    PROCS.extend(joins.values())
    t_join = time.time()
    for w, p in joins.items():
        try:
            _, err = p.communicate("room pass", timeout=max(1, JOIN_SECS - (time.time() - t_join)))
        except subprocess.TimeoutExpired as t:
            t.cmd = [VOX, "room", "join"]
            raise
        if p.returncode != 0: apparatus(f"{w} join: {err.strip()}")
    print(f"{TAG} bob's and carol's joins took {time.time() - t_join:.1f} s")
    # Carol trusts Bob, so what `delivers` and `revoke` measure is Bob's consent alone: a node reads
    # only whom its owner trusts (V210-118).
    for (w, other, name) in (("bob", "alice", "alice"), ("alice", "bob", "bob"), ("carol", "bob", "bob")):
        t = run(w, "trust", "add", fp[other], "--name", name, "--identity-passphrase-file", f"{S}/idpass")
        if t.returncode != 0: apparatus(f"{w} trust add: {t.stderr}")
    stage("alice posts")
    for i in range(1, POSTS + 1):
        p = run("alice", "room", "post", room, f"m-{i:03d}")
        if p.returncode != 0: apparatus(f"post m-{i:03d}: {p.stderr.strip()}")
    stage("bob reads them and lists everyone")
    def bob_ready():
        r = run("bob", "room", "read", room, "--limit", "500")
        ro = run("bob", "room", "roster", room)
        return (r.returncode == 0 and f"m-{POSTS:03d}" in r.stdout and ro.returncode == 0
                and fp["alice"] in ro.stdout and fp["carol"] in ro.stdout)
    if not until(bob_ready, 120, 1):
        apparatus("bob never read m-%03d and listed alice and carol: %s" % (POSTS, run("bob", "room", "read", room, "--limit", "500").stdout[-300:]))
    stop(daemons["bob"])

    stage("bob's tui: unlock and open the room")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec], env("bob"))
    tui.pump(4)
    tui.key("id pass\r", 4)
    tui.key("\r", 2)
    tui.key("room pass\r", 4)
    tui.key("\r", 2)
    screen = lambda: "\n".join(tui.display())
    # The timeline is the left-hand column (cols 0-111), the members pane the right (112+).
    timeline = lambda: "\n".join(row[:112] for row in tui.display())
    def has(text, s):
        return re.search(rf"(^|[^0-9]){re.escape(s)}([^0-9]|$)", text, re.M) is not None
    if not tui.until(lambda: "m-0" in timeline(), 30, 1): apparatus("the room's timeline never drew a message")

    stage("newest")
    newest = tui.until(lambda: has(timeline(), f"m-{POSTS:03d}"), 20, 1)
    t = timeline()
    claim("newest", newest and not has(t, "m-001"),
          f"m-{POSTS:03d} shown: {has(t, f'm-{POSTS:03d}')}; m-001 shown: {has(t, 'm-001')}")

    stage("follows")
    if run("alice", "room", "post", room, f"m-{POSTS + 1:03d}").returncode != 0: apparatus("post while open")
    follows = tui.until(lambda: has(timeline(), f"m-{POSTS + 1:03d}"), 60, 1)
    claim("follows", follows, f"m-{POSTS + 1:03d} shown within 60 s: {follows}")

    stage("scrolls")
    for _ in range((POSTS + 10) // 10):
        tui.key("\x1b[5~", 0.3)  # PageUp
    tui.pump(1)
    up = timeline()
    tui.key("\x1b[F", 1)  # End
    back = timeline()
    claim("scrolls", has(up, "m-001") and has(back, f"m-{POSTS + 1:03d}") and not has(back, "m-001"),
          f"after PageUp m-001 shown: {has(up, 'm-001')}; after End m-{POSTS + 1:03d} shown: "
          f"{has(back, f'm-{POSTS + 1:03d}')}")

    stage("clamp")
    def first_shown():
        n = [int(x) for x in re.findall(r"(?<![0-9])m-([0-9]{3})(?![0-9])", timeline())]
        return min(n) if n else None
    for _ in range((POSTS + 10) // 10):
        tui.key("\x1b[5~", 0.2)  # PageUp, well past the oldest line
    if not tui.until(lambda: first_shown() == 1, 5, 0.2):
        apparatus(f"PageUp past the top did not show m-001 first (first shown: {first_shown()})")
    tui.key("\x1b[6~", 0)  # PageDown, once
    tui.until(lambda: first_shown() == 11, 3, 0.2)
    moved = first_shown()
    claim("clamp", moved == 11, f"first line after one PageDown from past the top: m-{moved or 0:03d}")
    tui.key("\x1b[F", 0)  # End
    tui.until(lambda: has(timeline(), f"m-{POSTS + 1:03d}"), 5, 0.2)

    tui.key("\t", 1)   # timeline -> composer
    tui.key("\t", 1)   # composer -> members
    pane = lambda: [row[112:].rstrip() for row in tui.display()]
    def label_of(who):
        """The state line under `who`'s name in the members pane, and whether the marker is on it."""
        rows = pane()
        key = "alice" if who == "alice" else fp[who][:26]
        for i, r in enumerate(rows):
            if key in r:
                return (rows[i + 1] if i + 1 < len(rows) else ""), "▶" in r, i
        return None, False, None

    stage("consent")
    # Bob consents to Alice on his own (he trusts her): wait for that before judging Carol.
    alice_ok = tui.until(lambda: "consented" in (label_of("alice")[0] or ""), 60, 1)
    if label_of("carol")[0] is None: apparatus("carol is not in bob's members pane:\n" + "\n".join(pane()))
    if not alice_ok:
        apparatus("bob's pane never showed alice consented, so a 'not consented' for carol shows "
                  "nothing: " + repr(label_of("alice")[0]))
    carol_label = label_of("carol")[0]
    claim("consent", "consented" not in carol_label,
          f"alice: {label_of('alice')[0].strip()!r}; carol: {carol_label.strip()!r}")

    stage("select carol")
    for _ in range(8):
        if label_of("carol")[1]:
            break
        tui.key("\x1b[B", 0.5)  # Down
    if not label_of("carol")[1]: apparatus("could not put the marker on carol:\n" + "\n".join(pane()))

    stage("verify")
    tui.key(":verify\r", 2)
    v = label_of("carol")[0]
    claim("verify", "verified" in v and "unverified" in v and "✓" not in v, f"carol after :verify: {v.strip()!r}")

    stage("sync")
    def peers():
        """The count the status bar gives, or None when it gives none."""
        m = re.search(r"connected to (\d+) peers?\b", tui.display()[-2])
        return int(m.group(1)) if m else None
    bar = tui.display()[-2]
    # The anchor and at least one member (the room reads online): two peers or more.
    claim("sync", (peers() or 0) >= 2, f"status bar: {bar.strip()!r}")

    stage("dave joins while carol is selected")
    before = label_of("carol")[2]
    j = run(dave, "room", "join", link, "--name", "m", stdin="room pass")
    if j.returncode != 0: apparatus(f"{dave} join: {j.stderr.strip()}")
    if not tui.until(lambda: fp[dave][:26] in "\n".join(pane()), 90, 1):
        apparatus(f"{dave} never appeared in bob's pane")
    after = label_of("carol")[2]
    if not (before is not None and after is not None and after > before):
        apparatus(f"dave's join did not move carol down the pane (row {before} -> {after}), so it "
                  "tests nothing:\n" + "\n".join(pane()))
    print(f"{TAG} carol moved from pane row {before} to {after}; marker on carol: {label_of('carol')[1]}")

    stage("target")
    tui.key(":consent grant\r", 3)
    granted = tui.until(lambda: "consented" in (label_of("carol")[0] or ""), 30, 1)
    dave_label = label_of(dave)[0] or ""
    claim("target", granted and "consented" not in dave_label,
          f"carol: {label_of('carol')[0].strip()!r}; {dave}: {dave_label.strip()!r}")

    stage("delivers")
    # The grant is the node's, not the pane's: Carol reads what Bob posts after it.
    tui.key("\t", 0.5)  # members -> timeline
    tui.key("\t", 0.5)  # timeline -> composer
    tui.key("b-after-grant\r", 1)
    got = until(lambda: "b-after-grant" in run("carol", "room", "read", room, "--limit", "500").stdout, 60, 1)
    claim("delivers", got, f"carol read bob's post after :consent grant within 60 s: {got}")

    stage("revoke")
    # Carol is still selected, and is not the pane's first member (Dave sorts in above her).
    tui.key("\t", 0.5)  # composer -> members
    if not label_of("carol")[1]: apparatus("the marker left carol before :consent revoke:\n" + "\n".join(pane()))
    first = next((r.strip("│ ▶") for r in pane() if r.strip("│ ") and "Members" not in r), "")
    tui.key(":consent revoke\r", 3)
    back = tui.until(lambda: "in-only" in (label_of("carol")[0] or ""), 30, 1)
    carol_label, alice_label = label_of("carol")[0] or "", label_of("alice")[0] or ""
    panes_ok = back and "consented" in alice_label
    leaked = None
    if panes_ok:
        # Then Bob posts again. Alice, still consented to, reads it, so it went out; Carol, who
        # syncs from the same peers, must not, 10 s after Alice has.
        tui.key("\t", 0.5)  # members -> timeline
        tui.key("\t", 0.5)  # timeline -> composer
        tui.key("b-after-revoke\r", 1)
        if not until(lambda: "b-after-revoke" in run("alice", "room", "read", room, "--limit", "500").stdout, 60, 1):
            apparatus("alice never read bob's post after the revoke, so carol not reading it shows nothing")
        time.sleep(10)
        leaked = "b-after-revoke" in run("carol", "room", "read", room, "--limit", "500").stdout
    claim("revoke", panes_ok and leaked is False,
          f"first in the pane: {first[:30]!r}; carol: {carol_label.strip()!r}; alice: "
          f"{alice_label.strip()!r}; carol read bob's post after the revoke: {leaked}")

    stage("reach")
    tui.key("\x1b", 2)  # Esc back to the channel list
    rows = lambda: [r.strip() for r in tui.display() if "online" in r or "offline" in r]
    tui.until(lambda: any("● online" in r for r in rows()), 20, 1)
    claim("reach", any("● online" in r for r in rows()), f"list rows: {rows()!r}")

    stage("unreach")
    for w in ("alice", "carol", dave):
        daemons[w].terminate()
    for w in ("alice", "carol", dave):
        stop(daemons[w])
    gone = tui.until(lambda: any("○ offline" in r for r in rows()), 30, 1)
    claim("unreach", gone, f"with every other member's daemon stopped, list rows: {rows()!r}")
    # Only the anchor is left to be connected to.
    tui.until(lambda: peers() == 1, 30, 1)
    claim("fewer", peers() == 1, f"with only the anchor left, status bar: {tui.display()[-2].strip()!r}")

    stage("idle")
    # Ctrl-C, how a person stops `vox node` (it takes no SIGTERM of its own).
    anchor.send_signal(__import__("signal").SIGINT)
    tui.until(lambda: "idle" in tui.display()[-2], 30, 1)
    bar = tui.display()[-2]
    claim("idle", "idle" in bar and peers() is None, f"with no peer left, status bar: {bar.strip()!r}")

    print(f"{TAG} the TUI drew {tui.bytes} bytes")
    print(f"{TAG} screen at the end:")
    for r in tui.display():
        if r.strip():
            print(f"  |{r.rstrip()}")
    print(f"{TAG} claims: {sum(results.values())}/{len(results)} ok")
    code = 0 if results and all(results.values()) else 1
    print(f"{TAG} {'PASS' if code == 0 else 'RED'}")
except Apparatus as a:
    print(f"{TAG} APPARATUS: {a}")
    code = 2
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
except subprocess.TimeoutExpired as t:
    # A `vox` verb that never returned is a red of its own, named, not a driver with no verdict.
    print(f"{TAG} RED: `vox {' '.join(t.cmd[1:3])}` did not return within {t.timeout:.0f} s")
    code = 1
finally:
    disarm()
    stage("stopping every process")
    if tui is not None and not tui.stop():
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
    for p in PROCS:
        if p.poll() is None:
            stop(p)
    stage(f"done, exit {code}")
sys.exit(code)
