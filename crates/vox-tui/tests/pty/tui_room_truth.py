#!/usr/bin/env python3
"""tui_room_truth.py <vox> <tag> — V210-82 (#273), through the shipped `vox tui`.

Alice creates a room; Bob, Carol and Dave join it, all through real daemons. Alice and Bob trust
each other, so each holds the other's key; nobody trusts Carol, and Carol trusts Bob; Bob trusts
Dave, who trusts nobody. Alice posts 70 lines, more than Bob's
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
  shown     what Bob's TUI has drawn is read, and only that (ADR-028 RR-1, #504): Alice's
            `vox room read --json` says m-071, on Bob's screen, is "read by" bob, and m-001, which
            his TUI has not drawn yet, is read by nobody;
  scrolls   PageUp brings m-001 into view, and End returns to m-071;
  clamp     PageUp well past the oldest line, then one PageDown, moves the view one page (10
            lines): the oldest line is "alice named the room m", above m-001, so m-010 is the first
            message shown, not m-001 still;
  renamed   Alice renames the room while Bob's TUI is open, and his timeline says so in one
            line, by his name for her: "alice renamed the room to family" (ADR-028 R-1, E-5);
  quote     Alice posts q-root, then q-mid replying to it (`--re`, in q-root's thread), then 50
            lines. Bob selects q-mid (Up), presses Ctrl-R and sends q-answer: his post's `re` names
            q-mid, and the TUI shows it under "┆ alice: q-mid…", one level, not q-root, with q-mid
            itself off screen (ADR-028 R-9, #485);
  jump      Bob selects q-answer and presses Enter: the view moves to q-mid, selected;
  consent   Carol, whom Bob never trusted, reads "not in keyring: trust to read each other";
            Dave, whom he trusts and who trusts nobody, "waiting for the other side"; Alice,
            whom he did and who trusts him, "trusted both ways" (ADR-028 R-5, #481;
            V210-155: once
            "? unverified" on every row and "← in-only" for Carol, though nothing comes in from her);
            and no row of the members pane names a verified, TOFU or key-changed state, a consent
            or a block: one trust state, in the keyring or not (ADR-028 K-2, K-6, #473);
  look      in truecolour, Alice's row is "⇄ alice" (each trusts the other) and Dave's "→ dave" (only
            Bob trusts him), both in text.primary bold, and Carol's "· <her fingerprint>" in
            text.secondary, not bold (ADR-028 L-4); the accent is on the focused
            members pane's border and nowhere else (L-3);
  readby    under a message Bob posts, his TUI says nothing of readers until Alice's agent drains it
            into its turn, and then says exactly "read by alice": from the read record Alice's node
            posted, which Bob can open because she trusts him. Carol, who cannot read Bob, is
            named neither as having read it nor as not (ADR-028 R-6, RR-3, #505);
  nostorm   read records never answer read records (the decider; ADR-028 RR-2): Alice's daemon is
            stopped and her real `vox tui` opened on the room beside Bob's; each posts, and once
            each TUI says the other has read its post, with both TUIs on the room and both agents
            draining, the entries `vox status --json` says each node holds stay the same for 15 s;
            Alice's TUI and the daemon it started are then stopped and her `vox daemon` started
            again;
  serve     Bob's `:serve <port>` for a service the driver listens on, on every interface, says
            what sharing it does before it is shared: its address, that alice can reach it, and
            the warning that it listens on every interface; Enter shares it, and Alice's `vox
            service list` lists it (ADR-028 S-4, #491);
  retention while both TUIs are open, Alice runs `vox room retention <room> 1w`: each header,
            which said "⏱ forever", says "⏱ 1 week", and each timeline gains one line, "you set
            the room's retention to 1 week: messages older than 1 week are removed from now on"
            on Alice's and the same naming alice on Bob's (ADR-028 R-7, #483); and a focused
            pane's border names it once ("Members [focus]", never "MembersMembers [focus]");
  words     `:link` says "room link: vox://…" and `:join` asks for a "room link (vox://…)": the
            decider's words, never "invite link" (#406);
  unknown   `:show`, `:hide`, `:block`, `:unblock`, `:verify`, `:consent`, `:grant` and `:revoke`
            each answer "unknown command", and
            the help line names none of them: the TUI offers only what vox supports (V210-155);
  sync      the status bar says how many peers the node is connected to: the anchor and at least
            one member, so 2 or more (it said "idle" always);
  reach     back on the channel list, the room reads "● online" while Bob's node is connected to
            its other members;
  notify    with no room on screen, three messages Alice posts raise one notification (bob's
            `notify-command`, as `VOX_NOTIFY_COMMAND` sets it): titled with the room, naming Alice,
            and holding none of their text (ADR-028 R-10, #486); none more follows for the same
            room while it stays off screen;
  regions   the sidebar names bob's node attached; once Alice writes to him there, the room is
            listed under "needs you (1)" reading "to you 1"; and the nodes on this machine are
            listed, his attached and a second one detached (ADR-028 W-1, W-2, #511);
  newcomer  Frank joins while Bob's TUI is open, through Alice: Bob's TUI says "<frank> joined. No
            one you trust trusts it yet." and, once Alice (whom Bob trusts) trusts Frank, "<frank>
            joined. alice trusts it.", naming neither Erin, whom Bob trusts and who never granted
            Frank, nor anyone outside Bob's keyring (ADR-028 K-7, #476); Frank is in no keyring of
            Bob's after;
  trust     the join's line offers ":trust <frank's first 8>" (ADR-028 K-5, #475); `t` on Frank
            in Bob's members pane opens the trust prompt, showing his fingerprint; Dave's pasted
            there adds nothing and shows both fingerprints; Frank's own, pasted through the hint's
            `:trust`, in groups and upper case, adds him once the identity passphrase is typed
            into the prompt (Bob's keyring window is a minute, and has closed): a wrong one adds
            nothing and is never shown;
  onenode   `:node spare` is refused, naming the one node this window acts as, and the window
            still acts as default: its status bar and sidebar say so (ADR-028 E-4, #470);
  unreach   once Alice's, Carol's, Dave's and Frank's daemons are stopped, it reads "○ offline";
  fewer     and the status bar then says "connected to 1 peer": only the anchor is left;
  where     with Alice's, Carol's and Dave's daemons stopped, under a message Bob then posts his TUI says
            "only on this machine"; once Alice's daemon is started again and has synced, "on 1 of
            3 members' nodes" (ADR-028 R-6, #482); Alice's daemon is then stopped again;
  accent    there, the accent marks only the focused list's border and the live "● online";
  idle      once the anchor is stopped too, it says "idle", with no count;
  depths    Bob's TUI opened again three ways (L-5): under NO_COLOR with an ASCII locale (LC_ALL=C)
            it draws no colour at all and Alice reads "<> alice" and Dave "-> dave", bold, and Carol
            ". <fingerprint>";
            in 16 colours (TERM=xterm) every colour drawn is one of the 16 and the trust glyphs,
            weights and words are as in truecolour; in 256 colours (TERM=xterm-256color) Alice's
            name is index 255 and Carol's 247. In each the accent is on the focused border alone.
  copies    Alice shares an ssh stand-in; in Bob's TUI the room's Shared pane lists it, and `y` on it
            puts `ssh $USER@<its canonical address>` on the clipboard by OSC 52, prints it in full
            under the service and says "copied" on the status line, the address the one Alice's
            `vox service list --json` gives
            (ADR-028 S-3, #490);
  inline    in a TUI run as kitty: an image bob's node pulled and verified, whose copy this driver
            then overwrites on bob's disk, and one alice shares to carol (not pulled by bob's node)
            are each named "image <name> <w>×<h> — drawn once it is pulled and verified", and no
            kitty graphics are written; one she shares to the room is drawn as kitty graphics once
            bob's node has pulled and verified it (ADR-028 F-11, #502).

`vox room join` is given JOIN_SECS (490 s), what a member waits for a joiner's proof of work plus
its slack; every other verb 120 s. A verb past its time is a named RED, not a hang.

Exit 0 = pass, 1 = red, 2 = apparatus (CANNOT MEASURE). A `vox` step on the way that fails (an
identity, a daemon, create, invite, join, trust, a post, the roster, the TUI drawing the room or
answering a command it supports) is the product's red: it prints `PRODUCT:` with what `vox` said
and exits 1. An exception in the driver itself prints `APPARATUS: driver crashed` with its
traceback and exits 2. Every process is recorded and killed by PID. Bounded throughout
(`vox_pty.py`, V210-54).
"""
import base64, json, os, re, signal, socket, subprocess, sys, threading, time, traceback

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Gone, Hung, Tui, arm, disarm, pane, pyte, stage  # noqa: E402

# The colours the TUI is built from (ADR-028 L-1), read as pyte reads a cell: lowercase hex.
TOKENS = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "../../../../assets/theme/vox-tokens.json")))["color"]
HEX = {k: v["hex"].lstrip("#").lower() for k, v in TOKENS.items()}
BOX = set("─│┌┐└┘╭╮╰╯")

VOX, TAG = sys.argv[1], sys.argv[2]
# Sized for the debug build, whose joins grind their proof of work for minutes: three joins at
# JOIN_SECS each (two at once, then Frank's), and the rest (about 150 s in debug, and 90 s more for
# the depths' three TUIs). The Rust wrapper's bound sits above it.
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "1750"))
# A member waits 480 s for a joiner's proof of work (V210-87), plus its 5 s slack: a join that has
# not returned by then is past what the product allows, and is a named RED.
JOIN_SECS = 490
SP = os.environ.get("VOX_PTY_SCRATCH") or __import__("tempfile").mkdtemp(prefix="vox-tui-truth-")
S = f"{SP}/tuit-{TAG}"
POSTS = 70  # the timeline pane holds 43 lines at 160x50
subprocess.run(["rm", "-rf", S])
# Frank joins while Bob's TUI is open; Erin is a node Bob trusts that is never in the room: a join
# line may name only who granted.
WHO = ["anchor", "alice", "bob", "carol", "dave", "frank", "erin"]
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
TUIS = []  # every other `vox tui`, stopped at the end like the first
code = 2
results = {}
def claim(name, ok, detail):
    results[name] = ok
    print(f"{TAG} CLAIM {name} {'ok' if ok else 'RED'}: {detail}")

def cells_of(t, y):
    """Row `y` of `t`'s screen as cells, and its text with one character per column (the second
    column of a wide character is NUL), so an index into the text is a column."""
    row = t.screen.buffer[y]
    cs = [row[x] for x in range(t.screen.columns)]
    return cs, "".join(c.data or "\0" for c in cs)

def span(t, y, text):
    """The cells of the first `text` on row `y`, or None."""
    cs, line = cells_of(t, y)
    x = line.find(text)
    return None if x < 0 else cs[x:x + len(text)]

def stray(t, colours, live=(), cols=(0, 160)):
    """Every cell drawn in one of `colours` (fg or bg) that is not the focused pane's frame (a
    border character within `cols`, or its top row there, which holds the pane's title) nor inside
    one of the `live` texts: where the accent must not be (ADR-028 L-3)."""
    top = next((y for y in range(t.screen.lines) if cells_of(t, y)[1][cols[0]] in "┌╭"), None)
    out = []
    for y in range(t.screen.lines):
        cs, line = cells_of(t, y)
        ok = set()
        for text in live:
            for m in re.finditer(re.escape(text), line):
                ok.update(range(m.start(), m.end()))
        for x, c in enumerate(cs):
            frame = cols[0] <= x < cols[1] and (c.data in BOX or y == top)
            if (c.fg in colours or c.bg in colours) and x not in ok and not frame:
                out.append((y, x, c.data))
    return out

def tui_env(**extra):
    e = env("bob")
    e.update(extra)
    return e

def unlock(t):
    """Open bob's room in `t` as a person would: each passphrase is typed only when a prompt asks
    for it. Typed with no prompt up, its letters were commands: `d` opened the decisions."""
    # A prompt, as the TUI draws one ("identity passphrase (1/1):"): not the word anywhere, since
    # the status bar says "keyring asks for the passphrase" once its window has closed.
    asks = lambda: re.search(r"passphrase \(\d+/\d+\):", t.text()) is not None
    t.until(lambda: asks() or "attached: default" in t.text(), 20, 0.5)
    if asks():
        t.key("id pass\r", 4)
    t.key("\r", 2)
    if asks():
        t.key("room pass\r", 4)
    t.key("\r", 2)

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
                        "--passphrase-file", f"{S}/idpass", out=w) for w in ("alice", "bob", "carol", "dave", "frank")}
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
    joins = {w: subprocess.Popen([VOX, "room", "join", "--passphrase-file", "-", link], env=env(w),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True) for w in ("bob", "carol", "dave")}
    PROCS.extend(joins.values())
    t_join = time.time()
    for w, p in joins.items():
        try:
            _, err = p.communicate("room pass", timeout=max(1, JOIN_SECS - (time.time() - t_join)))
        except subprocess.TimeoutExpired as t:
            t.cmd = [VOX, "room", "join"]
            raise
        if p.returncode != 0: product(f"{w}'s `vox room join` failed: {err.strip()}")
    print(f"{TAG} bob's, carol's and dave's joins took {time.time() - t_join:.1f} s")
    # Carol trusts Bob, so what her label says is Bob's trust alone: a node reads only whom its
    # owner trusts (V210-118).
    # Bob trusts Dave, and Dave trusts nobody: the one way of the three (ADR-028 L-4's `→`).
    for (w, other, name) in (("bob", "alice", "alice"), ("alice", "bob", "bob"), ("carol", "bob", "bob"),
                             ("bob", "dave", "dave"), ("bob", "erin", "erin")):
        t = run(w, "trust", "add", fp[other], "--name", name, "--identity-passphrase-file", f"{S}/idpass")
        if t.returncode != 0: product(f"{w}'s `vox trust add` failed: {t.stderr.strip()}")
    stage("alice shares an ssh stand-in")
    # It greets as sshd does, so Alice's node detects it as ssh (ADR-028 S-2).
    ssh_srv = socket.socket()
    ssh_srv.bind(("127.0.0.1", 0)); ssh_srv.listen(8)
    def ssh_greets():
        while True:
            try:
                c, _ = ssh_srv.accept()
                c.sendall(b"SSH-2.0-VoxProofStandIn\r\n"); c.close()
            except OSError:
                return
    threading.Thread(target=ssh_greets, daemon=True).start()
    a = run("alice", "service", "add", room, "nas-ssh", f"127.0.0.1:{ssh_srv.getsockname()[1]}")
    if a.returncode != 0: product(f"alice's `vox service add` failed: {a.stderr.strip()}")
    def ssh_canonical():
        r = run("alice", "service", "list", room, "--json")
        if r.returncode != 0: return None
        return next((x["address"] for x in json.loads(r.stdout)["shared"]
                     if x["readable"].startswith("nas-ssh.") and x["kind"] == "ssh"), None)
    if not until(lambda: ssh_canonical() is not None, 60, 1):
        product("alice's `vox service list --json` never listed nas-ssh as ssh within 60 s: "
                + run("alice", "service", "list", room, "--json").stdout)
    SSH_COPY = f"ssh $USER@{ssh_canonical()}"
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
                and fp["alice"] in ro.stdout and fp["carol"] in ro.stdout and fp["dave"] in ro.stdout)
    if not until(bob_ready, 120, 1):
        last = run("bob", "room", "roster", room)
        product("bob's node never read m-%03d and listed alice and carol within 120 s: read %r; roster %r"
                % (POSTS, run("bob", "room", "read", room, "--limit", "500").stdout[-300:], last.stdout + last.stderr))
    stop(daemons["bob"])
    # A second node on bob's machine, never attached: the sidebar lists it detached (#511). Made
    # once his daemon has gone, so the TUI is told which node it acts as (`--node default`).
    r = run("bob", "node", "create", "spare", "--passphrase-file", f"{S}/idpass")
    if r.returncode != 0: product(f"bob's `vox node create spare` failed: {r.stderr.strip()}")

    stage("bob's tui: unlock and open the room")
    # Bob's notifications go to a script that writes each one to a file, so what is judged is the
    # TUI's own decision to notify and what it put in the notification.
    NOTES = f"{S}/bob-notes"
    open(f"{S}/note.sh", "w").write(f"#!/bin/sh\nprintf '%s | %s\\n' \"$1\" \"$2\" >> {NOTES}\n")
    os.chmod(f"{S}/note.sh", 0o755)
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec, "--node", "default"],
              tui_env(COLORTERM="truecolor", VOX_NOTIFY_COMMAND=f"{S}/note.sh",
                      VOX_TEST_KEYRING_WINDOW_SECS="60"))
    tui.pump(4)
    unlock(tui)
    screen = lambda: "\n".join(tui.display())
    # The timeline and the members pane, each found by its title (the sidebar is to their left).
    timeline = lambda: "\n".join(pane(tui.display(), "Timeline"))
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
        for r in pane(tui.display(), "Timeline"):
            if key in r:
                return r.rstrip()
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

    stage("shown")
    import json
    def alice_read_by():
        r = run("alice", "room", "read", room, "--json")
        if r.returncode != 0: product(f"alice's `vox room read --json` failed: {r.stderr.strip()}")
        rows = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
        return {row["text"]: row.get("read_by", []) for row in rows}
    newest_read = until(lambda: alice_read_by().get(f"m-{POSTS + 1:03d}") == ["bob"], 30, 1)
    seen = alice_read_by()
    claim("shown", newest_read and seen.get("m-001") == [],
          f"read by, on alice's node: m-{POSTS + 1:03d} {seen.get(f'm-{POSTS + 1:03d}')!r}; "
          f"m-001 {seen.get('m-001')!r}")

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
    # The room's oldest line is the one that says who named it (ADR-028 E-5), above m-001.
    named_on_top = "alice named the room m" in timeline()
    tui.key("\x1b[6~", 0)  # PageDown, once
    tui.until(lambda: first_shown() == 10, 3, 0.2)
    moved = first_shown()
    claim("clamp", named_on_top and moved == 10,
          f"the naming line above m-001 at the top: {named_on_top}; first message after one "
          f"PageDown from past the top: m-{moved or 0:03d}")
    tui.key("\x1b[F", 0)  # End
    tui.until(lambda: has(timeline(), f"m-{POSTS + 1:03d}"), 5, 0.2)

    stage("renamed")
    # The room's creator renames it; the room's one name reaches Bob's node, and his timeline says
    # who renamed it and to what, by his name for her (he trusts her as "alice").
    r = run("alice", "room", "rename", room, "family", "--identity-passphrase-file", f"{S}/idpass")
    if r.returncode != 0: product(f"alice's `vox room rename` failed: {r.stderr.strip()}")
    said = "alice renamed the room to family"
    renamed = tui.until(lambda: said in timeline(), 60, 1)
    claim("renamed", renamed, f"{said!r} in bob's timeline within 60 s: {renamed}; its last rows: "
          f"{[r.strip() for r in timeline().splitlines() if r.strip()][-3:]!r}")

    stage("quote")
    def alice_posts(*args):
        p = run("alice", "room", "post", room, "--json", "--session", "quote-proof", *args)
        if p.returncode != 0: product(f"alice's `vox room post {' '.join(args)}` failed: {p.stderr.strip()}")
        return json.loads(p.stdout.strip().splitlines()[-1])["entry_hash"]
    q_root = alice_posts("q-root what shall we build")
    q_mid = alice_posts("--re", q_root, "--thread", q_root, "q-mid the lexer first")
    FILL = 50  # more lines than the pane holds, so q-mid is off screen under the reply
    for i in range(1, FILL + 1):
        p = run("alice", "room", "post", room, f"f-{i:03d}")
        if p.returncode != 0: product(f"alice's `vox room post` of f-{i:03d} failed: {p.stderr.strip()}")
    if not tui.until(lambda: has(timeline(), f"f-{FILL:03d}"), 60, 1):
        product(f"bob's `vox tui` never drew f-{FILL:03d} within 60 s")
    rows = lambda: [r.rstrip() for r in pane(tui.display(), "Timeline")]
    selected = lambda: next((r for r in rows() if "▶ " in r), "")
    def focus(pane):
        """Tab until `pane`'s title says it has the focus."""
        for _ in range(4):
            # The title may say more after the pane's name (the timeline's retention, #483).
            if any(re.search(rf"\u250c{pane}[^\u2510]*\[focus\]", r) for r in tui.display()):
                return
            tui.key("\t", 0.3)
        product(f"Tab never gave bob's {pane} the focus; screen:\n" + tui.text())
    focus("Timeline")
    for _ in range(FILL + 5):
        tui.key("\x1b[A", 0.1)  # Up: an older message selected
        if "q-mid" in selected():
            break
    if "q-mid" not in selected():
        product(f"Up never selected q-mid in bob's timeline; selected row: {selected()!r}; screen:\n"
                + tui.text())
    tui.key("\x12", 0.3)  # Ctrl-R: reply to the message selected
    tui.key("q-answer on it", 0.3)
    tui.key("\r", 1)
    tui.key("\x1b[F", 0.5)  # End: the newest, nothing selected
    if not tui.until(lambda: any("you: q-answer" in r for r in rows()), 30, 0.5):
        product("bob's reply q-answer never appeared in his timeline within 30 s")
    shown = rows()
    at = next(i for i, r in enumerate(shown) if "you: q-answer" in r)
    above = shown[at - 1] if at else ""
    def bob_reply_re():
        r = run("bob", "room", "read", room, "--json", "--limit", "500")
        for line in r.stdout.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            env = row.get("envelope") or {}
            if env.get("body") == "q-answer on it":
                return env.get("re")
        return None
    wrote = bob_reply_re()
    mid_off = not any("alice: q-mid" in r and "┆" not in r for r in shown)
    claim("quote", wrote == q_mid and "┆ alice: q-mid the lexer first" in above and "q-root" not in above
          and mid_off,
          f"bob's reply's re names q-mid: {wrote == q_mid} (re {wrote!r}); the row above it: "
          f"{above.strip()!r}; q-mid itself off screen: {mid_off}")

    stage("jump")
    focus("Timeline")
    tui.key("\x1b[A", 0.5)  # Up: the newest, q-answer, selected
    sel_reply = selected()
    tui.key("\r", 0)  # Enter: to the message it quotes
    jumped = tui.until(lambda: "alice: q-mid" in selected() and "┆" not in selected(), 5, 0.2)
    claim("jump", "q-answer" in sel_reply and jumped,
          f"selected before Enter: {sel_reply.strip()!r}; after: {selected().strip()!r}")
    tui.key("\x1b[F", 0)  # End
    tui.until(lambda: has(timeline(), f"f-{FILL:03d}"), 5, 0.2)
    focus("Timeline")  # where the stages below begin

    tui.key("\t", 1)   # timeline -> composer
    tui.key("\t", 1)   # composer -> members
    members_pane = lambda: [row.rstrip() for row in pane(tui.display(), "Members")]
    def label_of(who):
        """The state line under `who`'s name in the members pane, and whether the marker is on it."""
        rows = members_pane()
        key = who if who in ("alice", "dave") else fp[who][:26]
        for i, r in enumerate(rows):
            if key in r:
                return (rows[i + 1] if i + 1 < len(rows) else ""), "▶" in r, i
        return None, False, None

    def members_box(t):
        """The members pane on `t`'s screen: (its top border's row, its first and past-last
        columns), found by its title as `pane` finds it (#511 sizes the panes to the window)."""
        for y, row in enumerate(t.display()):
            x = row.find("\u250cMembers")
            if x >= 0:
                end = row.find("\u2510", x)
                return y, x, (len(row) if end < 0 else end + 1)
        return None, 0, t.screen.columns
    def at(t, who):
        """The screen row of `who`'s name in the members pane, or None."""
        i, (top, _, _) = label_of(who)[2], members_box(t)
        return None if i is None or top is None else top + 1 + i
    def in_box(t, y):
        _, x0, x1 = members_box(t)
        return cells_of(t, y)[1][x0:x1].strip()

    def trust_look(t, glyphs, primary, secondary, accent):
        """What the members pane of `t` shows of Alice (`glyphs[0]`, each trusts the other), Dave
        (`glyphs[1]`, only Bob trusts him) and Carol (`glyphs[2]`, not in Bob's keyring) by glyph,
        weight and colour, and whether the accent strays off the focused pane's border:
        (ok, detail)."""
        want = {"alice": (glyphs[0], "alice", True), "dave": (glyphs[1], "dave", True),
                "carol": (glyphs[2], fp["carol"][:26], False)}
        ok, said = True, []
        for who, (glyph, name, strong) in want.items():
            y = at(t, who)
            cells = None if y is None else span(t, y, glyph + name)
            if cells is None:
                row = "" if y is None else in_box(t, y)
                ok = False
                said.append(f"{who}'s row {row!r} (want {glyph + name!r})")
                continue
            name_cells = cells[len(glyph):]
            colour = primary if strong else secondary
            good = all(x.bold == strong and x.fg == colour for x in name_cells)
            ok = ok and good
            said.append(f"{who} {glyph}name bold {name_cells[0].bold} fg {name_cells[0].fg!r} "
                        f"(want bold {strong}, {colour!r})")
        # The sidebar beside the room shows its live "● online", which the accent marks (L-3).
        off = stray(t, accent, live=("● online",), cols=members_box(t)[1:])
        said.append(f"accent cells off the focused border: {off[:6]!r}")
        return ok and not off, "; ".join(said)

    stage("consent")
    # Bob's node releases its key to Alice on its own (he trusts her): wait for that before
    # judging Carol.
    # Who reads whom, and what is still to do (ADR-028 R-5, #481).
    ALICE, CAROL = "trusted both ways", "not in keyring: trust to read each other"
    DAVE = "waiting for the other side"  # bob trusts dave, who trusts nobody
    # The pane's border is part of the row: the label is what sits between its edges.
    bare = lambda row: (row or "").strip().strip("│").strip()
    alice_ok = tui.until(lambda: bare(label_of("alice")[0]) == ALICE, 60, 1)
    if label_of("carol")[0] is None: product("bob's node listed carol, and his `vox tui` members pane does not show her:\n" + "\n".join(members_pane()))
    if not alice_ok:
        product(f"bob trusts alice, and his `vox tui` members pane never showed her {ALICE!r} "
                "within 60 s: " + repr(label_of("alice")[0]))
    carol_label, dave_label = label_of("carol")[0], label_of("dave")[0]
    # One trust state (ADR-028 K-2, K-6, #473): in the keyring or not. No row of the pane names a
    # verified, TOFU or key-changed state, a consent, or a block.
    STATES = ("verified", "tofu", "key changed", "consent", "block")
    stated = [r.strip() for r in members_pane() if any(w in r.lower() for w in STATES)]
    claim("consent", bare(carol_label) == CAROL and bare(dave_label) == DAVE and not stated,
          f"alice: {label_of('alice')[0].strip()!r}; carol: {carol_label.strip()!r}; "
          f"dave: {(dave_label or '').strip()!r}; rows naming another trust state: {stated!r}")

    stage("look")
    # Alice's key reaches Bob once her node has released it: wait for her ⇄ before judging.
    tui.until(lambda: at(tui, "alice") is not None and span(tui, at(tui, "alice"), "⇄ alice"), 60, 1)
    ok, detail = trust_look(tui, ("⇄ ", "→ ", "· "), HEX["text.primary"], HEX["text.secondary"],
                            {HEX["accent"]})
    claim("look", ok, f"in truecolour: {detail}")

    stage("copies")
    tui.key("\t", 1)   # members -> shared
    shared_pane = lambda: [row.rstrip() for row in pane(tui.display(), "Shared")]
    # Selected: its row is the one with "y copies:" under it (the marker can fall outside a
    # narrow pane's cut).
    if not tui.until(lambda: any("nas-ssh." in r for r in shared_pane())
                     and any("y copies:" in r for r in shared_pane()), 30, 1):
        product("bob's `vox tui` never showed alice's nas-ssh selected in the room's Shared pane: "
                + repr(shared_pane()))
    mark = len(tui.raw)
    tui.key("y", 2)
    sent = bytes(tui.raw[mark:])
    m = re.search(rb"\x1b\]52;c;([A-Za-z0-9+/=]*)(\x07|\x1b\\)", sent)
    copied = base64.b64decode(m.group(1)).decode() if m else None
    bar = tui.display()[-1] + tui.display()[-2]
    # The command, printed in full and wrapped under the selected service: the pane's rows, joined.
    printed = "".join(r.strip().strip("│").strip() for r in shared_pane())
    claim("copies", copied == SSH_COPY and "copied to the clipboard" in bar and SSH_COPY in printed,
          f"OSC 52 carried {copied!r}, want {SSH_COPY!r}; printed in the Shared pane: "
          f"{SSH_COPY in printed}; status line: {bar.strip()!r}")
    # Back round to the members pane, where the stages after this one expect focus.
    for _ in range(3):
        tui.key("\t", 0.5)

    stage("readby")
    p = run("bob", "room", "post", room, "r-001 read me")
    if p.returncode != 0: product(f"bob's `vox room post` while his TUI is open failed: {p.stderr.strip()}")
    if not tui.until(lambda: has(timeline(), "r-001"), 30, 1):
        product("bob's `vox tui` never showed his own post r-001 within 30 s")
    def under(key):
        """The timeline row under the one holding `key`, bare of the pane's border."""
        rows = pane(tui.display(), "Timeline")
        for i, r in enumerate(rows):
            if key in r:
                return bare(rows[i + 1]) if i + 1 < len(rows) else ""
        return None
    # Nobody has read it yet: nothing is said of readers.
    tui.pump(3)
    before = under("r-001")
    # Alice's agent drains it into its turn; the drain is bounded per turn, so turns are taken
    # until r-001 is in one. Carol's agent drains too, though Bob's posts are not hers to read.
    told = False
    for _ in range(20):
        h = run("alice", "agent", "hook", "--node", "default", "--room", room, "--format", "text",
                "--session", "alice-reader")
        if "r-001" in h.stdout:
            told = True
            break
        if not h.stdout.strip():
            break
    if not told: product(f"alice's agent was never told bob's r-001 by `vox agent hook`: {h.stdout[-300:]!r} {h.stderr.strip()!r}")
    run("carol", "agent", "hook", "--node", "default", "--room", room, "--format", "text",
        "--session", "carol-reader")
    tui.until(lambda: (under("r-001") or "").startswith("read by"), 30, 1)
    tui.pump(3)
    after = under("r-001")
    claim("readby", not (before or "").startswith("read by") and after == "read by alice",
          f"under r-001 before alice's drain: {before!r}; after it: {after!r}")

    stage("nostorm")
    # Read records never answer read records (the decider; ADR-028 RR-2): with both people's TUIs
    # on the room and both agents draining, what each node holds stays flat once the first
    # records are out. Counted as a person can: `vox status --json`'s entries held in the room.
    stop(daemons["alice"])
    atui = Tui([VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec], env("alice"))
    TUIS.append(atui)
    def both_until(pred, secs):
        """`pred` within `secs`, both TUIs drawn meanwhile: one not read stalls on its pty."""
        end = time.time() + secs
        while time.time() < end:
            tui.pump(0.5); atui.pump(0.5)
            if pred():
                return True
        return False
    # As unlock(), each passphrase typed only at its prompt, with both TUIs read meanwhile.
    asks = lambda: "passphrase" in atui.text().lower()
    for keys, secs, gated in (("", 4, False), ("id pass\r", 4, True), ("\r", 2, False),
                              ("room pass\r", 4, True), ("\r", 2, False)):
        if keys and (not gated or asks()):
            os.write(atui.fd, keys.encode())
        both_until(lambda: False, secs)
    # The room's newest lines are the `quote` stage's f- lines by now, m- ones before it ran.
    if not both_until(lambda: re.search(r"[mf]-0", "\n".join(pane(atui.display(), "Timeline"))), 30):
        product("alice's `vox tui` never drew a message in the room's timeline within 30 s of unlocking")
    def held(w):
        r = run(w, "status", "--json")
        if r.returncode != 0: product(f"{w}'s `vox status --json` failed: {r.stderr.strip()}")
        rooms = [x for x in json.loads(r.stdout)["rooms"] if x["id"].startswith(room)]
        if not rooms or "entries" not in rooms[0]:
            product(f"{w}'s `vox status --json` says no entries held for the room: {r.stdout[:300]!r}")
        return rooms[0]["entries"]
    def under_in(t, key):
        rows = pane(t.display(), "Timeline")
        for i, r in enumerate(rows):
            if key in r:
                return bare(rows[i + 1]) if i + 1 < len(rows) else ""
        return None
    for w, text in (("alice", "s-001 from alice"), ("bob", "s-002 from bob")):
        p = run(w, "room", "post", room, text)
        if p.returncode != 0: product(f"{w}'s `vox room post` of {text!r} with both TUIs open failed: {p.stderr.strip()}")
    # The first records: each TUI says its post was read by the other, whose TUI drew it.
    first = both_until(lambda: under("s-002") == "read by alice"
                       and under_in(atui, "s-001") == "read by bob", 60)
    if not first:
        product(f"the first read records never showed: under bob's s-002 {under('s-002')!r}, "
                f"under alice's s-001 {under_in(atui, 's-001')!r}")
    drains = lambda: [run(w, "agent", "hook", "--node", "default", "--room", room, "--format", "text",
                          "--session", f"{w}-storm") for w in ("alice", "bob")]
    drains()
    both_until(lambda: False, 6)  # a record held back by the 5-second batch goes out
    counts = [(held("alice"), held("bob"))]
    t0 = time.time()
    while time.time() - t0 < 15:
        drains()
        both_until(lambda: False, 1)  # both TUIs keep drawing the room
        counts.append((held("alice"), held("bob")))
    claim("nostorm", len(set(counts)) == 1,
          f"entries held (alice, bob) over 15 s, both TUIs on the room and both agents draining: "
          f"{counts[0]} to {counts[-1]} ({len(counts)} samples, {len(set(counts))} distinct)")
    stage("retention")
    # A retention change is one line in each member's timeline, saying who set what and what it
    # does from now on; the room's header always says the retention (ADR-028 R-7, #483).
    def header(t):
        return next((bare(r) for r in t.display() if "Timeline ·" in r), "")
    def says(t, want):
        # The line wraps across rows of the narrow timeline: read the pane as one text, without
        # the spaces a wrap may have taken from either side of a break.
        text = "".join(bare(r) for r in pane(t.display(), "Timeline")).replace(" ", "")
        return want.replace(" ", "") in text
    before = (header(atui), header(tui))
    r = run("alice", "room", "retention", room, "1w", "--identity-passphrase-file", f"{S}/idpass")
    if r.returncode != 0: product(f"alice's `vox room retention {room} 1w` failed: {r.stderr.strip()}")
    LINE = "set the room's retention to 1 week: messages older than 1 week are removed from now on"
    both_until(lambda: says(atui, f"you {LINE}") and says(tui, f"alice {LINE}")
               and "⏱ 1 week" in header(atui) and "⏱ 1 week" in header(tui), 60)
    after = (header(atui), header(tui))
    # A focused pane names itself once on its border: "Members [focus]", never "MembersMembers".
    once = all(h.count("Timeline") == 1 and h.count("Members") == 1 for h in after) \
        and any("[focus]" in h for h in after)
    claim("retention", all("⏱ forever" in h for h in before) and all("⏱ 1 week" in h for h in after)
          and says(atui, f"you {LINE}") and says(tui, f"alice {LINE}") and once,
          f"headers (alice, bob) before: {before!r}; after: {after!r}; alice's timeline says "
          f"'you {LINE}': {says(atui, f'you {LINE}')}; bob's says 'alice {LINE}': "
          f"{says(tui, f'alice {LINE}')}; each pane's title once on its border: {once}")

    if not atui.stop():
        product(f"alice's vox tui (pid {atui.pid}) outlived SIGKILL and could not be reaped")
    TUIS.remove(atui)
    # Her TUI started a daemon of its own, detached, that outlives it: stopped by its PID (its
    # argv names her data directory), so her `vox daemon` below is the one later stages stop.
    pids = [int(x) for x in subprocess.run(["pgrep", "-f", f"daemon .*--data-dir {S}/alice/"],
                                           capture_output=True, text=True).stdout.split()]
    if len(pids) != 1:
        apparatus(f"expected the one daemon alice's TUI started, found PIDs {pids}")
    os.kill(pids[0], __import__("signal").SIGTERM)
    def gone():
        try:
            os.kill(pids[0], 0)
            return False
        except ProcessLookupError:
            return True
    if not until(gone, 30):
        os.kill(pids[0], __import__("signal").SIGKILL)
        if not until(gone, 10): apparatus(f"the daemon alice's TUI started (pid {pids[0]}) outlived SIGKILL")
    daemons["alice"] = spawn("alice", "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                             "--passphrase-file", f"{S}/idpass", out="alice-after-tui")
    if not until(lambda: run("alice", "room", "list").returncode == 0, 60):
        product("alice's daemon, started again after her TUI, never answered `vox room list` within 60 s: "
                + open(f"{S}/alice-after-tui.err").read())

    stage("serve")
    # Sharing a service from the TUI is one step, as `vox serve` with no name is (ADR-028 S-4,
    # #491): the driver listens on every interface on a free port, and Bob's `:serve <port>`
    # says what sharing it does, warning that it listens on every interface, before it is shared.
    import socket
    svc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    svc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    svc.bind(("0.0.0.0", 0)); svc.listen(4)
    sport = svc.getsockname()[1]
    tui.key(f":serve {sport}\r", 3)
    def preview():
        return " ".join(" ".join(r.strip().strip("│").split()) for r in pane(tui.display(), "Share a service"))
    tui.until(lambda: "Enter: share it" in preview(), 30, 1)
    seen = preview()
    tag = (re.search(r"\bas (\S+): members will reach it as", seen) or [None, None])[1]
    tui.key("\r", 3)
    def offered():
        r = run("alice", "service", "list", room)
        return r.returncode == 0 and tag is not None and tag in r.stdout and "bob" in r.stdout
    shared = until(offered, 60, 1)
    listed = run("alice", "service", "list", room).stdout.strip()
    can = (re.search(r"who can reach it: (.*?) who cannot", seen) or [None, ""])[1]
    # The warning itself, not the listing's "(every interface)" note beside the address.
    warned = re.search(r"warning: `[^`]+` \([^)]*:" + str(sport) + r", tcp\) listens on every interface", seen)
    claim("serve", f":{sport}" in seen and warned is not None and "alice" in can
          and tag is not None and shared,
          f"bob's preview: {seen!r}; alice's `vox service list`: {listed!r}")
    if tag:
        run("bob", "service", "remove", room, tag)
    svc.close()

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
    REMOVED = ("show", "hide", "block", "unblock", "verify", "consent", "grant", "revoke")
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
    off = stray(tui, {HEX["accent"]}, live=("● online",))
    claim("accent", any("● online" in r for r in rows()) and not off,
          f"accent cells that are neither the list's border nor '● online': {off[:6]!r}")

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
    claim("notify", len(raised) == 1 and raised[0].startswith("Vox: family |") and "alice" in raised[0]
          and "secret" not in raised[0] and "do not show" not in raised[0],
          f"notifications for three messages in a room off screen: {raised!r}")

    stage("regions")
    # After `notify`: its post to bob would otherwise be the room's one notification.
    # Alice writes to bob in the room he just left: the sidebar lists it under "needs you" with
    # its count; and it lists the nodes on this machine, attached or detached (#511).
    p = run("alice", "room", "post", room, "--session", "alice-s", "--to", fp["bob"], "TO-BOB-511")
    if p.returncode != 0: product(f"alice's `vox room post --to bob` failed: {p.stderr.strip()}")
    side = lambda: [r.strip().strip("│").strip() for r in pane(tui.display(), "Rooms")]
    def regions():
        s = side()
        heads = [i for i, r in enumerate(s) if r == "needs you (1)"]
        under = s[heads[0] + 1] if heads and heads[0] + 1 < len(s) else ""
        return (bool(heads) and under.lstrip("▶ ").startswith("family ") and "to you 1" in under
                and "spare  detached" in s and "default  attached" in s
                and bool(s) and s[0] == "node default · attached")
    tui.until(regions, 30, 1)
    claim("regions", regions(), f"sidebar: {side()!r}")

    stage("newcomer")
    # Frank joins through Alice's link while Bob's TUI is open. Bob trusts Alice; nobody trusts Frank
    # yet, so Bob's TUI must say so, and must not name Alice until her node has granted Frank.
    frank_name = f"{fp['frank'][:26]} (not in keyring)"
    alone = f"{frank_name} joined. No one you trust trusts it yet."
    trusted = f"{frank_name} joined. alice trusts it."
    flat = lambda: " ".join(r.strip() for r in tui.display())
    j = run("frank", "room", "join", "--passphrase-file", "-", link, stdin="room pass")
    if j.returncode != 0: product(f"frank's `vox room join` failed: {j.stderr.strip()}")
    said_alone = tui.until(lambda: alone in flat(), 120, 1)
    before_grant = [r.strip() for r in tui.display() if "joined" in r]
    t = run("alice", "trust", "add", fp["frank"], "--name", "frank", "--identity-passphrase-file", f"{S}/idpass")
    if t.returncode != 0: product(f"alice's `vox trust add` of frank failed: {t.stderr.strip()}")
    said_trusted = tui.until(lambda: trusted in flat(), 120, 1)
    after_grant = [r.strip() for r in tui.display() if "joined" in r]
    ring = run("bob", "trust", "list")
    if ring.returncode != 0: product(f"bob's `vox trust list` failed: {ring.stderr.strip()}")
    unadded = fp["frank"] not in ring.stdout
    claim("newcomer", said_alone and said_trusted and unadded,
          f"before alice trusted frank, bob's TUI said {before_grant!r} (wanted {alone!r}); after, "
          f"{after_grant!r} (wanted {trusted!r}); frank absent from bob's keyring: {unadded}")

    stage("trust")
    # ADR-028 K-5 (#475): the join's line offers the one trust action, ":trust <frank's first 8>";
    # `t` on Frank in the members pane opens the same prompt. A fingerprint pasted that is not
    # Frank's adds nothing and shows both; Frank's own, pasted in groups and upper case, adds him.
    flat_ws = lambda: re.sub(r"\s+", " ", flat())
    hint = f":trust {fp['frank'][:8]}"
    hinted = hint in flat_ws()
    grouped = lambda f: " ".join(f[i:i + 4] for i in range(0, len(f), 4))
    in_ring = lambda: fp["frank"] in run("bob", "trust", "list").stdout
    tui.key("\r", 2)   # into the room
    tui.key("\t", 1)   # timeline -> composer
    tui.key("\t", 1)   # composer -> members
    for _ in range(8):
        if label_of("frank")[1]:
            break
        tui.key("\x1b[B", 1)  # Down: the next member
    tui.key("t", 2)
    prompt_seen = "Trust this node?" in flat() and grouped(fp["frank"])[:24] in flat_ws()
    tui.key(grouped(fp["dave"]).upper() + "\r", 1)
    tui.key("frank\r", 1)
    tui.key("\r", 3)
    mismatch_said = (f"given: {grouped(fp['dave'])}" in flat_ws()
                     and f"this node: {grouped(fp['frank'])}" in flat_ws()
                     and "do not trust it" in flat_ws())
    mismatch_added = in_ring()
    # Bob's keyring window (a minute here) has closed: the prompt's passphrase field is typed into.
    closed = tui.until(lambda: "keyring asks for the passphrase" in run("bob", "status").stdout, 90, 2)
    tui.key(":" + hint[1:] + "\r", 2)
    tui.key(grouped(fp["frank"]).upper() + "\r", 1)
    tui.key("frank\r", 1)
    tui.key("not the pass\r", 3)
    wrong_pass_added = in_ring()
    wrong_pass_said = [l for l in tui.display()[-6:] if l.strip()]
    shown_secret = "not the pass" in flat()
    tui.key(":" + hint[1:] + "\r", 2)
    tui.key(grouped(fp["frank"]).upper() + "\r", 1)
    tui.key("frank\r", 1)
    tui.key("id pass\r", 3)
    matched = tui.until(in_ring, 30, 1)
    match_said = "you now trust frank" in flat_ws()
    tui.key("\x1b", 2)  # back to the room list
    claim("trust", hinted and prompt_seen and mismatch_said and not mismatch_added and closed
          and not wrong_pass_added and not shown_secret and matched and match_said,
          f"the join offered {hint!r}: {hinted}; `t` on frank opened the prompt with his "
          f"fingerprint: {prompt_seen}; dave's pasted: both shown and told not to trust: "
          f"{mismatch_said}, frank added anyway: {mismatch_added}; with the keyring closed "
          f"({closed}), a wrong passphrase added him: {wrong_pass_added}, was shown: {shown_secret}, "
          f"the TUI said {wrong_pass_said!r}; frank's own pasted through {hint!r} with the "
          f"passphrase: added {matched}, said so {match_said}")

    stage("onenode")
    # After `trust`: its refusal takes the status line, where the join's offer to trust is read.
    # One node per window (ADR-028 E-4, #470): `:node` acts as no other node.
    tui.key(":node spare\r", 0)
    said = tui.until(lambda: "acts only as node default" in tui.display()[-1], 10, 0.5)
    tui.pump(3)  # time for the window to have taken spare, were it going to
    bar, top = tui.display()[-2], (side() or [""])[0]
    claim("onenode", said and "node default" in bar and "node spare" not in bar
          and top == "node default · attached",
          f"answer: {tui.display()[-1].strip()!r}; status bar: {bar.strip()!r}; sidebar: {top!r}")
    stage("unreach")
    for w in ("alice", "carol", "dave", "frank"):
        daemons[w].terminate()
    for w in ("alice", "carol", "dave", "frank"):
        stop(daemons[w])
    gone = tui.until(lambda: any("○ offline" in r for r in rows()), 30, 1)
    claim("unreach", gone, f"with every other member's daemon stopped, list rows: {rows()!r}")
    # Only the anchor is left to be connected to.
    tui.until(lambda: peers() == 1, 30, 1)
    claim("fewer", peers() == 1, f"with only the anchor left, status bar: {tui.display()[-2].strip()!r}")

    stage("where")
    tui.key("\r", 2)  # back into the room
    p = run("bob", "room", "post", room, "d-001 where am i")
    if p.returncode != 0: product(f"bob's `vox room post` with every other member offline failed: {p.stderr.strip()}")
    if not tui.until(lambda: has(timeline(), "d-001"), 30, 1):
        product("bob's `vox tui` never showed his own post d-001 within 30 s")
    tui.until(lambda: under("d-001") == "only on this machine", 10, 0.5)
    alone = under("d-001")
    daemons["alice"] = spawn("alice", "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                             "--passphrase-file", f"{S}/idpass", out="alice-again")
    if not until(lambda: run("alice", "room", "list").returncode == 0, 60):
        product("alice's daemon, started again, never answered `vox room list` within 60 s: "
                + open(f"{S}/alice-again.err").read())
    WHERE = "on 1 of 4 members' nodes"  # alice of alice, carol, dave and frank
    tui.until(lambda: under("d-001") == WHERE, 90, 1)
    synced = under("d-001")
    claim("where", alone == "only on this machine" and synced == WHERE,
          f"under d-001 with every other member offline: {alone!r}; once alice's daemon is back: {synced!r}")
    stop(daemons["alice"])
    tui.key("\x1b", 2)  # Esc back to the channel list

    stage("idle")
    # Ctrl-C, how a person stops `vox node` (it takes no SIGTERM of its own).
    anchor.send_signal(__import__("signal").SIGINT)
    tui.until(lambda: "idle" in tui.display()[-2], 30, 1)
    bar = tui.display()[-2]
    claim("idle", "idle" in bar and peers() is None, f"with no peer left, status bar: {bar.strip()!r}")

    stage("depths")
    # Bob's TUI again, as three terminals would run it (ADR-028 L-5): the room is read from his
    # node's own log, so it needs no peer, and no anchor is given.
    if not tui.stop():
        apparatus(f"the first `vox tui` (pid {tui.pid}) could not be stopped before the next")
    p256 = pyte.graphics.FG_BG_256
    depths = {}
    for name, extra, glyphs, colours in (
        ("no colour", dict(NO_COLOR="1", LC_ALL="C"), ("<> ", "-> ", ". "), None),
        ("16 colours", dict(TERM="xterm"), ("⇄ ", "→ ", "· "), "16"),
        ("256 colours", dict(TERM="xterm-256color"), ("⇄ ", "→ ", "· "), "256"),
    ):
        tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], tui_env(**extra))
        tui.pump(4)
        unlock(tui)
        tui.key("\t", 1)   # timeline -> composer
        tui.key("\t", 1)   # composer -> members
        if not tui.until(lambda: all(label_of(w)[0] is not None for w in ("alice", "carol", "dave")), 30, 1):
            product(f"bob's `vox tui` ({name}) never drew alice, carol and dave in its members pane:\n{tui.text()}")
        words = bare(label_of("alice")[0]) == ALICE and bare(label_of("carol")[0]) == CAROL
        if colours is None:
            drawn = {c for y in range(tui.screen.lines) for c in
                     ((x.fg, x.bg) for x in cells_of(tui, y)[0])} - {("default", "default")}
            ya, yd, yc = at(tui, "alice"), at(tui, "dave"), at(tui, "carol")
            a = span(tui, ya, glyphs[0] + "alice")
            dv = span(tui, yd, glyphs[1] + "dave")
            c = span(tui, yc, glyphs[2] + fp["carol"][:26])
            bold = a is not None and dv is not None and all(x.bold for x in a[3:] + dv[3:])
            ok = bold and c is not None and not drawn
            detail = (f"alice {in_box(tui, ya)!r}, dave {in_box(tui, yd)!r}, bold {bold}; carol "
                      f"{in_box(tui, yc)!r}; colours drawn: {sorted(drawn)[:4]!r}")
        elif colours == "16":
            sixteen = set(p256[:16]) | {"default", "black", "red", "green", "brown", "blue", "magenta",
                                        "cyan", "white"} | {f"bright{n}" for n in
                                        ("black", "red", "green", "brown", "blue", "magenta", "cyan", "white")}
            other = {v for y in range(tui.screen.lines) for x in cells_of(tui, y)[0]
                     for v in (x.fg, x.bg)} - sixteen
            ok, detail = trust_look(tui, glyphs, "default", "default", {p256[14], "brightcyan"})
            ok = ok and not other
            detail += f"; colours drawn outside the 16: {sorted(other)[:4]!r}"
        else:
            ok, detail = trust_look(tui, glyphs, p256[255], p256[247], {p256[81]})
        depths[name] = ok and words
        print(f"{TAG} depth {name}: {'ok' if depths[name] else 'RED'}: words {words}; {detail}")
        if not tui.stop():
            apparatus(f"`vox tui` ({name}, pid {tui.pid}) could not be stopped")
    claim("depths", all(depths.values()), f"{depths!r}")

    stage("inline")
    # Images drawn inline, only once verified (ADR-028 F-11, #502). The anchor comes back on its
    # port, and alice's daemon with it; bob's TUI runs as kitty would, on the room list.
    # - ours.png, to the room: bob's node pulls and verifies it while the room is off screen; then
    #   this driver, as an attacker on bob's disk, overwrites the pulled copy. Opened, the room
    #   must name it unverified and draw nothing: what is on disk is not what was announced.
    # - carols.png, addressed to carol: bob's node does not pull it; named, never drawn.
    # - theirs.png, to the room, shared with the room open: drawn once pulled and verified.
    def png(path, w, h, salt=0):
        import struct, zlib
        raw = b"".join(b"\x00" + bytes(v for x in range(w) for v in (x * 255 // w, y * 255 // h, (x ^ y ^ salt) & 255))
                       for y in range(h))
        chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
        open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                               + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
    port = spec.rsplit("/", 1)[1]
    anchor = spawn("anchor", "node", "--listen", f"127.0.0.1:{port}", out="anchor-again")
    daemons["alice"] = spawn("alice", "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                             "--passphrase-file", f"{S}/idpass", out="alice-inline")
    if not until(lambda: run("alice", "room", "list").returncode == 0, 60):
        product("alice's daemon, started for the images, never answered `vox room list` within 60 s: "
                + open(f"{S}/alice-inline.err").read())
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec],
              tui_env(TERM="xterm-kitty", COLORTERM="truecolor"))
    tui.pump(4)
    tui.key("id pass\r", 4)
    tui.key("\r", 2)
    tui.key("room pass\r", 4)
    tui.key("\r", 2)
    tui.key("\x1b", 2)  # Esc: the room list, the room off screen
    KITTY = b"\x1b_G"
    # The pane's rows run together, as the TUI wrapped one line over them.
    flat = lambda: "".join(r.strip() for r in pane(tui.display(), "Timeline"))
    for name, w, h, salt in (("ours", 120, 80, 0), ("carols", 96, 64, 1), ("theirs", 88, 56, 2), ("forged", 120, 80, 3)):
        png(f"{S}/{name}.png", w, h, salt)
    p = run("alice", "share", room, f"{S}/ours.png")
    if p.returncode != 0: product(f"alice's `vox share` of ours.png failed: {p.stderr.strip()}")
    pulls = f"{S}/bob/data/nodes/default/pulls"
    def pulled(name):
        import glob
        for f in glob.glob(f"{pulls}/*.json"):
            try:
                path = json.load(open(f))["path"]
            except (OSError, ValueError, KeyError):
                continue
            if path.endswith(name) and os.path.exists(path):
                return path
        return None
    if not until(lambda: pulled("ours.png"), 90, 1):
        product("bob's node never pulled ours.png within 90 s (no pull record names it): "
                + repr(os.listdir(pulls) if os.path.isdir(pulls) else "no pulls directory"))
    os.replace(f"{S}/forged.png", pulled("ours.png"))  # the attacker's bytes, in place
    p = run("alice", "share", room, f"{S}/carols.png", "--to", fp["carol"])
    if p.returncode != 0: product(f"alice's `vox share` of carols.png failed: {p.stderr.strip()}")
    tui.key("\r", 2)  # into the room
    said = {n: f"image {n} {wh} — drawn once it is pulled and verified"
            for n, wh in (("ours.png", "120×80"), ("carols.png", "96×64"))}
    named = tui.until(lambda: all(v in flat() for v in said.values()), 60, 1)
    tui.pump(5)  # time for a drawing, were the TUI to draw what is not verified
    before = KITTY in bytes(tui.raw)
    p = run("alice", "share", room, f"{S}/theirs.png")
    if p.returncode != 0: product(f"alice's `vox share` of theirs.png failed: {p.stderr.strip()}")
    # Read from the bytes the TUI wrote from here on: pyte does not draw kitty graphics, and
    # prints their payload over its screen.
    drew = tui.until(lambda: KITTY in bytes(tui.raw), 90, 1)
    claim("inline", named and not before and drew,
          f"named unverified (ours.png overwritten on bob's disk, carols.png not pulled here): {named}; "
          f"kitty graphics written before theirs.png was shared: {before}; after, once bob's node "
          f"had pulled and verified it: {drew}")
    stop(daemons["alice"])

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
except Gone as g:
    # The driver stops a TUI only through `Tui.stop`, never while it still drives it: a signal
    # that ended one came from outside the product (APPARATUS); a TUI that exited on its own, a
    # panic included, is the product's red, quoted.
    if g.signal is not None and g.signal in (signal.SIGTERM, signal.SIGKILL, signal.SIGHUP, signal.SIGINT):
        print(f"{TAG} APPARATUS: the TUI was stopped from outside the driver: {g}")
        code = 2
    else:
        print(f"{TAG} PRODUCT: a `vox tui` ended while in use: {g}")
        print(f"{TAG} RED")
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
    # A TUI already stopped (the depths) has closed its pty.
    for t in [tui, *TUIS]:
        if t is not None and t.fd is not None and not t.stop():
            print(f"{TAG} RED: vox tui (pid {t.pid}) outlived SIGKILL and could not be reaped")
            code = 1
    for p in PROCS:
        if p.poll() is None:
            stop(p)
    stage(f"done, exit {code}")
sys.exit(code)
