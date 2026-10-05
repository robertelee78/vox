#!/usr/bin/env python3
"""tui_room_truth.py <vox> <tag> — V210-82 (#273), through the shipped `vox tui`.

Alice creates a room; Bob and Carol join it, all through real daemons. Alice and Bob trust each
other, so each holds the other's key; nobody trusts Carol, and Carol trusts Bob. Alice posts 70 lines, more than Bob's
timeline pane holds. Bob's daemon is stopped and his real `vox tui` is opened in a pty (pyte at
160x50). Each claim prints one `CLAIM <name> ok|RED` line:

  newest    the timeline shows the room's newest message (m-070), not its first (m-001);
  hidden    characters a reader cannot see are shown, not hidden (#331): Alice's tag characters,
            her zero-width-split word, her stray zero-width joiner and her bidi override each
            read as ⟨U+XXXX⟩ escapes, one style (#331); her family emoji 👨‍👩‍👧 is drawn whole: no escape on its row, and the TUI wrote
            the cluster to the terminal unbroken, joiners and all. pyte splits a cluster into
            cells and the TUI's next text overwrites the cells it does not count, so the family's
            three people are read from the bytes the TUI wrote, not from pyte's cells, and how a
            real terminal draws the glyph is not seen here;
  follows   a message Alice posts while it is open (m-071) is shown when it arrives;
  scrolls   PageUp brings m-001 into view, and End returns to m-071;
  clamp     PageUp well past the oldest line, then one PageDown, moves the view one page (10
            lines): m-011 is the first line shown, not m-001 still;
  consent   Carol, whom Bob never trusted, reads "not trusted · you don't read each other"; Alice,
            whom he did, "trusted · reads you" (V210-155: once "? unverified" on every row and
            "← in-only" for Carol, though nothing comes in from her);
  words     `:link` says "room link: vox://…" and `:join` asks for a "room link (vox://…)": the
            decider's words, never "invite link" (#406);
  unknown   `:show`, `:hide`, `:block`, `:unblock` and `:verify` each answer "unknown command", and
            the help line names none of them: the TUI offers only what vox supports (V210-155);
  sync      the status bar says how many peers the node is connected to: the anchor and at least
            one member, so 2 or more (it said "idle" always);
  reach     back on the channel list, the room reads "● online" while Bob's node is connected to
            its other members;
  notify    with no room on screen, three messages Alice posts raise one notification (bob's
            `notify-command`, as `VOX_NOTIFY_COMMAND` sets it): titled with the room, naming Alice,
            and holding none of their text (ADR-028 R-10, #486); none more follows for the same
            room while it stays off screen;
  unreach   once Alice's and Carol's daemons are stopped, it reads "○ offline";
  fewer     and the status bar then says "connected to 1 peer": only the anchor is left;
  idle      once the anchor is stopped too, it says "idle", with no count.

`vox room join` is given JOIN_SECS (490 s), what a member waits for a joiner's proof of work plus
its slack; every other verb 120 s. A verb past its time is a named RED, not a hang.

Exit 0 = pass, 1 = red, 2 = apparatus (CANNOT MEASURE). A `vox` step on the way that fails (an
identity, a daemon, create, invite, join, trust, a post, the roster, the TUI drawing the room or
answering a command it supports) is the product's red: it prints `PRODUCT:` with what `vox` said
and exits 1. An exception in the driver itself prints `APPARATUS: driver crashed` with its
traceback and exits 2. Every process is recorded and killed by PID. Bounded throughout
(`vox_pty.py`, V210-54).
"""
import os, re, subprocess, sys, time, traceback

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
WHO = ["anchor", "alice", "bob", "carol"]
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

def product(why):
    raise Product(why)

class Product(Exception):
    pass

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
    if not until(got_spec, 30):
        product("the anchor `vox node` printed no spec within 30 s: " + open(f"{S}/anchor.err").read())
    stage("identities and daemons")
    fp = {}
    for w in WHO[1:]:
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
    stage("room create, invite, join, trust")
    c = run("alice", "room", "create", "--passphrase-file", "-", "--name", "m", stdin="room pass")
    if c.returncode != 0: product(f"alice's `vox room create` failed: {c.stderr.strip()}")
    listed = run("alice", "room", "list")
    if not listed.stdout.split(): product(f"alice's `vox room list` shows no room after create: {listed.stderr.strip()}")
    room = listed.stdout.split()[0]
    inv = run("alice", "room", "link", room)
    if inv.returncode != 0: product(f"alice's `vox room link` failed: {inv.stderr.strip()}")
    link = inv.stdout.strip()
    # Bob and Carol join at once, as two people given the link might: so the budget holds one
    # join's worth of JOIN_SECS, not two.
    joins = {w: subprocess.Popen([VOX, "room", "join", "--passphrase-file", "-", link, "--name", "m"], env=env(w),
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
        if p.returncode != 0: product(f"{w}'s `vox room join` failed: {err.strip()}")
    print(f"{TAG} bob's and carol's joins took {time.time() - t_join:.1f} s")
    # Carol trusts Bob, so what her label says is Bob's trust alone: a node reads only whom its
    # owner trusts (V210-118).
    for (w, other, name) in (("bob", "alice", "alice"), ("alice", "bob", "bob"), ("carol", "bob", "bob")):
        t = run(w, "trust", "add", fp[other], "--name", name, "--identity-passphrase-file", f"{S}/idpass")
        if t.returncode != 0: product(f"{w}'s `vox trust add` failed: {t.stderr.strip()}")
    stage("alice posts")
    for i in range(1, POSTS + 1):
        p = run("alice", "room", "post", room, f"m-{i:03d}")
        if p.returncode != 0: product(f"alice's `vox room post` of m-{i:03d} failed: {p.stderr.strip()}")
    # Hidden characters (#331), after the numbered posts so the pane shows them with m-070.
    HIDDEN = {
        "h-1": "h-1 tags \U000E0068\U000E0069 end",
        "h-2": "h-2 pa\u200bss\u200cword end",
        "h-3": "h-3 a\u200db end",
        "h-4": "h-4 fam \U0001F468\u200d\U0001F469\u200d\U0001F467 end",
        "h-5": "h-5 rlo \u202egnp.exe end",
    }
    for key, text in HIDDEN.items():
        p = run("alice", "room", "post", room, text)
        if p.returncode != 0: product(f"alice's `vox room post` of {key} failed: {p.stderr.strip()}")
    stage("bob reads them and lists everyone")
    def bob_ready():
        r = run("bob", "room", "read", room, "--limit", "500")
        ro = run("bob", "room", "roster", room)
        return (r.returncode == 0 and f"m-{POSTS:03d}" in r.stdout and "h-5" in r.stdout and ro.returncode == 0
                and fp["alice"] in ro.stdout and fp["carol"] in ro.stdout)
    if not until(bob_ready, 120, 1):
        last = run("bob", "room", "roster", room)
        product("bob's node never read m-%03d and listed alice and carol within 120 s: read %r; roster %r"
                % (POSTS, run("bob", "room", "read", room, "--limit", "500").stdout[-300:], last.stdout + last.stderr))
    stop(daemons["bob"])

    stage("bob's tui: unlock and open the room")
    # Bob's notifications go to a script that writes each one to a file, so what is judged is the
    # TUI's own decision to notify and what it put in the notification.
    NOTES = f"{S}/bob-notes"
    open(f"{S}/note.sh", "w").write(f"#!/bin/sh\nprintf '%s | %s\\n' \"$1\" \"$2\" >> {NOTES}\n")
    os.chmod(f"{S}/note.sh", 0o755)
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec],
              {**env("bob"), "VOX_NOTIFY_COMMAND": f"{S}/note.sh"})
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
    if not tui.until(lambda: "m-0" in timeline(), 30, 1): product("bob's `vox tui` never drew a message in the room's timeline within 30 s of unlocking")

    stage("newest")
    newest = tui.until(lambda: has(timeline(), f"m-{POSTS:03d}"), 20, 1)
    t = timeline()
    claim("newest", newest and not has(t, "m-001"),
          f"m-{POSTS:03d} shown: {has(t, f'm-{POSTS:03d}')}; m-001 shown: {has(t, 'm-001')}")

    stage("hidden")
    def row_of(key):
        """The timeline row holding `key`, without trailing blanks."""
        for r in tui.display():
            if key in r[:112]:
                return r[:112].rstrip()
        return None
    tui.until(lambda: row_of("h-5") is not None, 20, 1)
    rows = {k: row_of(k) for k in HIDDEN}
    if any(v is None for v in rows.values()):
        product(f"bob's `vox tui` does not show every h- message: {rows!r}")
    want = {
        "h-1": "tags \u27e8U+E0068\u27e9\u27e8U+E0069\u27e9 end",
        "h-2": "pa\u27e8U+200B\u27e9ss\u27e8U+200C\u27e9word end",
        "h-3": "a\u27e8U+200D\u27e9b end",
        "h-5": "rlo \u27e8U+202E\u27e9gnp.exe end",
    }
    shown = {k: want[k] in rows[k] for k in want}
    fam = rows["h-4"]
    cluster = "\U0001F468\u200d\U0001F469\u200d\U0001F467"
    written = cluster.encode() in bytes(tui.raw)
    family_whole = "\u27e8" not in fam and "fam \U0001F468" in fam and " end" in fam
    claim("hidden", all(shown.values()) and family_whole and written,
          f"escapes shown: {shown!r}; family row {fam.strip()!r} has no escape: {family_whole}; the "
          f"TUI wrote the whole cluster with its joiners: {written} (pyte keeps only its first "
          f"person in the cells; the glyph a real terminal draws is not seen here)")

    stage("follows")
    p = run("alice", "room", "post", room, f"m-{POSTS + 1:03d}")
    if p.returncode != 0: product(f"alice's `vox room post` while bob's TUI is open failed: {p.stderr.strip()}")
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
        product(f"bob's `vox tui`: PageUp past the top did not show m-001 first within 5 s "
                f"(first shown: {first_shown()})")
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
    # Bob's node releases its key to Alice on its own (he trusts her): wait for that before
    # judging Carol.
    ALICE, CAROL = "trusted · reads you", "not trusted · you don't read each other"
    # The pane's border is part of the row: the label is what sits between its edges.
    bare = lambda row: (row or "").strip().strip("│").strip()
    alice_ok = tui.until(lambda: bare(label_of("alice")[0]) == ALICE, 60, 1)
    if label_of("carol")[0] is None: product("bob's node listed carol, and his `vox tui` members pane does not show her:\n" + "\n".join(pane()))
    if not alice_ok:
        product(f"bob trusts alice, and his `vox tui` members pane never showed her {ALICE!r} "
                "within 60 s: " + repr(label_of("alice")[0]))
    carol_label = label_of("carol")[0]
    claim("consent", bare(carol_label) == CAROL,
          f"alice: {label_of('alice')[0].strip()!r}; carol: {carol_label.strip()!r}")

    stage("words")
    # Before `unknown`, whose short answers leave the line under the status bar one row again.
    # The decider's words (#406): a room link and a passphrase, never an "invite link". `:link`
    # names what it gives a person, and `:join` asks for what a person was given.
    tui.key(":link\r", 2)
    tui.until(lambda: "vox://" in "\n".join(tui.display()), 10, 0.5)
    # The link wraps over the rows under the status bar: read them as one.
    invite_said = " ".join(r.strip() for r in tui.display()[-4:])
    tui.key(":join\r", 2)
    join_prompt = "\n".join(r.rstrip() for r in tui.display() if r.strip())
    tui.key("\x1b", 1)  # Esc: the prompt is left unanswered
    said_both = invite_said + "\n" + join_prompt
    claim("words", "room link: vox://" in invite_said and "room link (vox://" in join_prompt
          and "invite link" not in said_both.lower(),
          f":link says {invite_said.strip()[:90]!r}; :join asks for "
          f"{[r.strip() for r in join_prompt.splitlines() if 'link' in r][:2]!r}; "
          f"'invite link' anywhere: {'invite link' in said_both.lower()}")

    stage("unknown")
    # Each answer is read after `:link`, a command vox supports, has replaced the status line, so
    # an "unknown command" seen is this command's answer and not the one before it.
    def bottom():
        return "\n".join(r.rstrip() for r in tui.display()[-3:])
    REMOVED = ("show", "hide", "block", "unblock", "verify")
    answers = {}
    for c in REMOVED:
        tui.key(":link\r", 2)
        if "unknown command" in bottom():
            product(f"bob's `vox tui` answered :link, a command it supports, with unknown command:\n{bottom()}")
        tui.key(f":{c}\r", 2)
        answers[c] = bottom().split("\n")[-1].strip()
    screen = "\n".join(tui.display())
    named = [c for c in REMOVED if f":{c}" in screen]
    claim("unknown", all("unknown command" in v for v in answers.values()) and not named,
          f"answers: {answers!r}; the help line names: {named!r}")

    stage("sync")
    def peers():
        """The count the status bar gives, or None when it gives none."""
        m = re.search(r"connected to (\d+) peers?\b", tui.display()[-2])
        return int(m.group(1)) if m else None
    bar = tui.display()[-2]
    # The anchor and at least one member (the room reads online): two peers or more.
    claim("sync", (peers() or 0) >= 2, f"status bar: {bar.strip()!r}")

    stage("reach")
    tui.key("\x1b", 2)  # Esc back to the channel list
    rows = lambda: [r.strip() for r in tui.display() if "online" in r or "offline" in r]
    tui.until(lambda: any("● online" in r for r in rows()), 20, 1)
    claim("reach", any("● online" in r for r in rows()), f"list rows: {rows()!r}")

    stage("notify")
    def notes():
        try:
            return [l for l in open(NOTES).read().splitlines() if l.strip()]
        except FileNotFoundError:
            return []
    before = len(notes())
    for i in (1, 2, 3):
        p = run("alice", "room", "post", room, f"secret-n{i} do not show this")
        if p.returncode != 0: product(f"alice's `vox room post` of secret-n{i} failed: {p.stderr.strip()}")
    tui.until(lambda: len(notes()) > before, 30, 0.5)
    tui.pump(6)  # time for a second notification, were the room's messages not grouped
    raised = notes()[before:]
    claim("notify", len(raised) == 1 and raised[0].startswith("Vox: m |") and "alice" in raised[0]
          and "secret" not in raised[0] and "do not show" not in raised[0],
          f"notifications for three messages in a room off screen: {raised!r}")

    stage("unreach")
    for w in ("alice", "carol"):
        daemons[w].terminate()
    for w in ("alice", "carol"):
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
except Product as e:
    print(f"{TAG} PRODUCT: {e}")
    print(f"{TAG} RED")
    code = 1
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
except subprocess.TimeoutExpired as t:
    # A `vox` verb that never returned is a red of its own, named, not a driver with no verdict.
    print(f"{TAG} RED: `vox {' '.join(t.cmd[1:3])}` did not return within {t.timeout:.0f} s")
    code = 1
except Exception:
    print(f"{TAG} APPARATUS: driver crashed: {traceback.format_exc()}")
    code = 2
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
