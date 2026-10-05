#!/usr/bin/env python3
"""opencode_wake.py <vox> <data_dir> <config_dir> <room> <project> <xdg_config> <plugin_log> <tmpdir> <sandbox_profile> <sandbox_home> <tag> <other_node> <own_node>

A plain `opencode`, opened by hand with no flags, interrupted by an urgent message addressed to it
(ADR-020 §6, ADR-021 F17). The caller runs the `vox daemon` holding `<room>` and has installed
the plugin `vox agent plugin opencode` prints in `<project>/.opencode/plugin/`, as a person does;
`<project>/opencode.json` names the model and lets the shell tool run.

What a person does, in order:

1. opens `opencode` in `<project>` — `VOX_ROOM` and `VOX_AGENT_NAME=bobby` exported, nothing
   else — and asks it to run `sleep` and then reply, so a turn is running;
2. while it runs, posts an urgent message addressed to **someone else** — `<other_node>`, another
   member's node (`vox room post --to <fingerprint> --urgent`) — then an urgent one addressed to
   **bobby's own node**, `<own_node>`: a message is addressed to a node, and wakes its sessions.
   The caller's data root holds the other member's node too, so every `vox` here names its node
   (`default`).

The screen is read through pyte, as the person sees it. Prints, each on its own line:
- `<tag> REGISTERED: <harness>: <how it is woken>` — the session its drain registered with the
  daemon, as the product lists it (`vox agent doctor --json`, its `session <id>` checks, those not
  there before it opened): `opencode: its wake endpoint answers` for a session the plugin's wake
  socket reaches; `REGISTERED: none` when the turn ran and no session registered, which the caller
  judges;
- `<tag> OTHER: shown|absent` — whether the message addressed to carol reached the screen before
  the one addressed to bobby was posted;
- `<tag> WAKE: shown mid-turn|shown after the turn|absent` — whether the wake for the message
  addressed to bobby reached the screen (Vox's notice, which carries no message, or the message
  itself in the read that follows it), and whether the running turn's reply had appeared yet;
- `<tag> TURN: completed|never completed` — whether the tool that was running when the wake
  arrived still ran to its end (its output, `SLEPT-42`, reached the screen): an interrupt queues
  into the running turn, and must not abort it;
- `<tag> RECEIVED: woken=<n> other=<n> envelope=yes|no` — once the turn the wake started has
  answered, what the model was given, from the session as OpenCode stored it (`opencode export`;
  a user message is stored as the plugin left it): how many times the message addressed to bobby
  appears in it (the wake carries none of it: only the `<vox-room>` read does), how many times
  the one addressed to carol does
  (only a `<vox-room>` read carries it), and whether any of it is a message's envelope JSON
  rather than its words; `<tag> RECEIVED: never` if that turn never answered, or `skipped (no wake arrived)` when there
  was no wake and so no woken turn to wait for;
- `<tag> SCREEN:` and the screen, whenever anything above is not clean.

Then the person quits, and the plugin's wake directory (`vox-oc-*` in `<tmpdir>`, this run's own
`TMPDIR`) must go with each session (ADR-021 F17). The session above is quit by closing its
terminal (SIGHUP), and three more plain `opencode`s are opened, each with no turn at all:
- `<tag> QUIT <how>: removed|left <dir>` — whether that session's directory was gone within
  `GONE_SECS` of `opencode` exiting, for `hup`, `ctrl+c` (pressed twice) and `/exit`;
- `<tag> SWEPT: removed|left <dir>` — a fourth session is SIGKILLed **together with** the helper
  that would have removed its directory, so the directory is left as a crash leaves it; the next
  `opencode` opened must remove it when it starts.

- `<tag> NODIR: <where>` — the plugin made no wake directory, where one was due; the driver
  stops there, and the caller judges it as the product's.

Exit 0 = it ran to the end, or to a NODIR or `REGISTERED: none` (the caller judges the lines); 2 =
apparatus (pyte missing, the TUI never drew, the turn never started, a post or `vox agent doctor`
failed); 1 = the driver hung (`HUNG at <stage>`, `vox_pty.py`) or could not reap OpenCode. Every
line the driver says of itself is APPARATUS; what the product did, it reports and the caller judges.
OpenCode is stopped by its PID, with bounded waits.
"""
import glob, json, os, re, shutil, signal, subprocess, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, reap, stage  # noqa: E402

VOX, DATA, CFG, ROOM, PROJECT, XDG, PLUGIN_LOG, TMP, SANDBOX, SB_HOME, TAG, OTHER_NODE, OWN_NODE = \
    sys.argv[1:14]
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "300"))
# How Vox's wake notice reads (V030-15): a count and the senders, never the message.
NOTICE = "urgent message addressed to you"
GONE_SECS = 5  # the helper removes it the moment the pipe closes; this is slack, not a wait
SLEEP = 45  # long enough that the wake is posted and relayed while the tool still runs
# The tool's own output, computed by the shell so the command's text cannot match it: on screen
# only once `sleep` has run to its end, whatever the model chooses to say afterwards.
SLEPT = "SLEPT-42"
nonce = f"{int(time.time() * 1000) % 100000:05d}"
OTHER = f"OTHERADDR-{nonce}"
# Not ASCII, so the wake is shown only if every multi-byte character survives the relay.
WAKE = f"WAKEMARK-çüé-{nonce}"
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
opencode = shutil.which("opencode")
opencode = os.path.realpath(opencode) if opencode else None
if opencode is None or not os.path.isfile(SANDBOX):
    print(f"{TAG} APPARATUS: opencode is not on PATH, or there is no sandbox profile at {SANDBOX}")
    sys.exit(2)
arm(BUDGET, TAG)

# A cleared environment: an inherited one (cargo test's) silently disables plugin hooks, and a
# real Claude Code session's variables must never reach anything here.
# A fixed, minimal environment: the operator's PATH names their home and other agents' scratch
# directories, and USER names them; a model that ran `env` would send both to its provider.
# OpenCode is started by its absolute path, so nothing here needs the real PATH.
env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SHELL": "/bin/zsh"}
if "LANG" in os.environ:
    env["LANG"] = os.environ["LANG"]
# **Every OpenCode here is confined** (the caller's `sandbox-exec` profile): a turn runs a
# shell, and an unconfined one could read the operator's files and send them to the model's
# provider. Its HOME is the sandbox's own, so nothing it keeps is the operator's.
env.update(HOME=SB_HOME, XDG_DATA_HOME=os.path.join(SB_HOME, ".local/share"),
           XDG_CACHE_HOME=os.path.join(SB_HOME, ".cache"),
           XDG_STATE_HOME=os.path.join(SB_HOME, ".local/state"))
OPENCODE = ["/usr/bin/sandbox-exec", "-f", SANDBOX, opencode]
env.update(TERM="xterm-256color", XDG_CONFIG_HOME=XDG, VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG,
           TMPDIR=TMP,  # this run's own, so its wake directories are exactly the ones counted
           VOX_BIN=VOX, VOX_PLUGIN_LOG=PLUGIN_LOG,
           # What a person exports before opening `opencode`; nothing else is configured.
           VOX_ROOM=ROOM, VOX_AGENT_NAME="bobby")


def post(to, body):
    """`vox room post` by the person, on the daemon's profile."""
    out = subprocess.run(
        [VOX, "room", "post", ROOM, "--node", "default", "--session", "person", "--type", "ask",
         "--to", to, "--urgent", body],
        env={**{k: v for k, v in env.items() if not k.startswith("VOX_")},
             "VOX_DATA_DIR": DATA, "VOX_CONFIG_DIR": CFG},
        capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        print(f"{TAG} APPARATUS: vox room post failed: {out.stderr.strip()}")
        sys.exit(2)


def sessions():
    """Every session registered on the daemon's node, as `vox agent doctor --json` lists it (it
    only reads, and wakes no one): {session: (harness, how it is woken)}. Asked of the product, not
    read from its files, whose layout is the product's to change (it moved under `nodes/`, and a
    glob of the old place found nothing)."""
    out = subprocess.run(
        [VOX, "agent", "doctor", "--node", "default", "--json"],
        env={**{k: v for k, v in env.items() if not k.startswith("VOX_")},
             "VOX_DATA_DIR": DATA, "VOX_CONFIG_DIR": CFG},
        capture_output=True, text=True, timeout=60)
    try:
        checks = json.loads(out.stdout)["checks"]
    except (ValueError, KeyError):
        print(f"{TAG} APPARATUS: `vox agent doctor --json` gave no checks (exit {out.returncode}): "
              f"{out.stderr.strip()}")
        sys.exit(2)
    found = {}
    for c in checks:
        sid = c.get("check", "")
        if not sid.startswith("session "):
            continue
        detail = c.get("detail", "")
        found[sid[len("session "):]] = (detail.split(" ", 1)[0], detail.rsplit("; ", 1)[-1])
    return found


def registered():
    """The sessions registered since this driver started: (harness, how it is woken, session)
    for each."""
    return [(h, how, sid) for sid, (h, how) in sorted(sessions().items()) if sid not in BEFORE]


# A message's envelope as `vox room post` writes it, rather than its words.
ENVELOPE = re.compile(r'"v"\s*:\s*1\b|"type"\s*:\s*"ask"')


def received(session):
    """What the model was given in `session`, once the turn the wake started has answered: the
    text of every user message, as OpenCode stored it — after the plugin rewrote it — or `None`
    while that turn has not answered yet. `--pure`: reading the session needs no plugin."""
    out = subprocess.run([*OPENCODE, "export", "--pure", session], env=env, cwd=PROJECT,
                         capture_output=True, text=True, timeout=60)
    try:
        messages = json.loads(out.stdout[out.stdout.index("{"):])["messages"]
    except (ValueError, KeyError):
        return None
    users = [" ".join(p.get("text", "") for p in m["parts"] if p.get("type") == "text")
             for m in messages if m["info"]["role"] == "user"]
    last = messages[-1]["info"] if messages else {}
    woke = any(WAKE in u for u in users)
    if not woke or last.get("role") != "assistant" or not last.get("time", {}).get("completed"):
        return None
    return users


def wake_dirs():
    return set(glob.glob(os.path.join(TMP, "vox-oc-*")))


def open_plain(known):
    """A plain `opencode` opened by hand in the project, and the wake directory its plugin made
    (the one in `<tmpdir>` not in `known`, holding its socket); `None` for the directory if none
    appeared."""
    t = Tui(OPENCODE, env, rows=60, cols=200)
    ok = t.until(lambda: any(os.path.exists(os.path.join(d, "wake.sock"))
                             for d in wake_dirs() - known), 60)
    new = sorted(wake_dirs() - known)
    return t, (new[0] if ok and len(new) == 1 else None)


def quit(t, how):
    """The person quits `opencode`: `hup` closes its terminal, `ctrl+c` presses ctrl+C (twice,
    unless the first already ended it), `/exit` types the command. Whether it exited."""
    if how == "hup":
        t.close()  # the terminal goes away: the kernel hangs up its session
        return reap(t.pid, 15)
    try:
        if how == "ctrl+c":
            t.key("\x03", 1)
            if not reap(t.pid, 0, t.drain):
                t.key("\x03", 1)
        else:
            t.key("/exit", 1)
            t.key("\r", 1)
    except OSError:
        pass  # its terminal already closed under the key: it is exiting
    return reap(t.pid, 15, t.drain)


def gone(d):
    end = time.time() + GONE_SECS
    while os.path.exists(d) and time.time() < end:
        time.sleep(0.1)
    return not os.path.exists(d)


def helper_of(d):
    """The pid of the process that is to remove `d` when its `opencode` exits, if one runs."""
    ps = subprocess.run(["ps", "-axww", "-o", "pid=,args="], capture_output=True, text=True).stdout
    for line in ps.splitlines():
        pid, _, args = line.strip().partition(" ")
        if "vox-oc-cleanup" in args and args.rstrip().endswith(d):
            return int(pid)
    return None


class NoDir(Exception):
    """The plugin made no wake directory: the product's failure, reported as `NODIR`."""


BEFORE = set(sessions())  # earlier sessions
code = 2
tui = None
try:
    stage("open opencode")
    os.chdir(PROJECT)  # opened in the project, as a person does; the pty's child inherits it
    tui, first = open_plain(wake_dirs())
    flat = lambda: " ".join(tui.text().split())  # noqa: E731 — wrapped text, as one line
    if not tui.until(lambda: len(tui.text().strip()) > 0, 60):
        print(f"{TAG} APPARATUS: opencode never drew its screen")
        sys.exit(2)
    tui.pump(5)  # its prompt takes keys once it has finished starting

    stage("start a turn that runs a tool")
    tui.key(f"Use the bash tool to run exactly `sleep {SLEEP}; echo SLEPT-$((6*7))`, then reply "
            "with just OK.", 1)
    tui.key("\r", 1)
    if not tui.until(lambda: f"sleep {SLEEP}" in flat(), 90):
        print(f"{TAG} APPARATUS: the turn never started (the model never ran its tool)")
        print(f"{TAG} SCREEN:\n{tui.text()}")
        sys.exit(2)
    # The turn runs, so its drain ran: whether that registered the session is the product's, and
    # the caller judges it.
    tui.until(lambda: registered(), 30)
    regs = registered()
    if not regs:
        print(f"{TAG} REGISTERED: none")
        print(f"{TAG} SCREEN:\n{tui.text()}")
        sys.exit(0)
    print(f"{TAG} REGISTERED: " + "; ".join(f"{h}: {how}" for h, how, _ in regs))
    t_turn = time.time()

    stage("post an urgent message addressed to someone else")
    post(OTHER_NODE, f"carol: {OTHER} is for you.")
    tui.pump(8)
    other = OTHER in flat()
    print(f"{TAG} OTHER: {'shown' if other else 'absent'}")

    stage("post an urgent message addressed to bobby")
    post(OWN_NODE, f"bobby: {WAKE} please acknowledge.")
    shown = tui.until(lambda: WAKE in flat() or NOTICE in flat(), SLEEP + 60, step=0.25)
    turn_done = SLEPT in flat()
    took = time.time() - t_turn
    if not shown:
        print(f"{TAG} WAKE: absent")
    elif not turn_done and took < SLEEP:
        print(f"{TAG} WAKE: shown mid-turn ({took:.1f}s into a {SLEEP}s tool)")
    else:
        print(f"{TAG} WAKE: shown after the turn ({took:.1f}s)")
    print(f"[receipt] the screen as the wake arrived:\n{tui.text()}", file=sys.stderr)
    if other or not shown or turn_done:
        print(f"{TAG} SCREEN:\n{tui.text()}")

    stage("let the running turn finish")
    # An interrupt queues into the running turn; it must not abort it.
    finished = tui.until(lambda: SLEPT in flat(), SLEEP + 90)
    print(f"{TAG} TURN: {'completed' if finished else 'never completed'}")
    if not finished:
        print(f"{TAG} SCREEN:\n{tui.text()}")

    stage("let the woken turn answer, and read what the model was given")
    users = None
    # No wake, no woken turn to wait for: (3) is already the verdict, and waiting would spend
    # the driver's whole budget before it reaches the wake directories.
    end = time.time() + (120 if shown else 0)
    while users is None and time.time() < end and regs:
        users = received(regs[0][2])
        if users is None:
            tui.pump(2)
    if not shown:
        print(f"{TAG} RECEIVED: skipped (no wake arrived)")
    elif users is None:
        print(f"{TAG} RECEIVED: never")
        print(f"{TAG} SCREEN:\n{tui.text()}")
    else:
        given = "\n".join(users)
        woken, others = given.count(WAKE), given.count(OTHER)
        envelope = ENVELOPE.search(given) is not None
        print(f"{TAG} RECEIVED: woken={woken} other={others} "
              f"envelope={'yes' if envelope else 'no'}")
        if woken != 1 or others != 1 or envelope:
            print(f"{TAG} GIVEN:\n" + "\n----\n".join(users))

    # ---- the person quits, and each session's wake directory goes with it ----
    stage("close the terminal of the session above")
    if first is None:
        raise NoDir(f"the first session's plugin made none in {TMP}: {sorted(wake_dirs())}")
    if not quit(tui, "hup"):
        print(f"{TAG} APPARATUS: opencode outlived its terminal closing")
        sys.exit(2)
    tui = None
    print(f"{TAG} QUIT hup: {'removed' if gone(first) else 'left'} {first}")
    for how in ("ctrl+c", "/exit"):
        stage(f"open a plain opencode and quit it by {how}")
        tui, d = open_plain(wake_dirs())
        if d is None:
            raise NoDir(f"the plugin of the opencode to quit by {how} made none in {TMP} within "
                        f"60s: {sorted(wake_dirs())}")
        tui.pump(3)  # its prompt takes keys once it has finished starting
        if not quit(tui, how):
            print(f"{TAG} APPARATUS: opencode did not exit on {how}")
            print(f"{TAG} SCREEN:\n{tui.text()}")
            sys.exit(2)
        tui = None
        print(f"{TAG} QUIT {how}: {'removed' if gone(d) else 'left'} {d}")

    stage("kill an opencode and its cleanup together, then open another")
    tui, crashed = open_plain(wake_dirs())
    if crashed is None:
        raise NoDir(f"the plugin of the opencode to kill made none in {TMP}")
    helper = helper_of(crashed)
    if helper is not None:
        os.kill(helper, signal.SIGKILL)
    os.kill(tui.pid, signal.SIGKILL)
    if not reap(tui.pid, 15, tui.drain):
        print(f"{TAG} APPARATUS: opencode outlived SIGKILL")
        sys.exit(2)
    tui.close()
    tui = None
    if not os.path.exists(crashed):
        print(f"{TAG} APPARATUS: {crashed} went with the kill, so it cannot show the next "
              f"start removing it (helper pid {helper})")
        sys.exit(2)
    time.sleep(11)  # older than the plugin's guard for a socket bound and not yet listening
    tui, d = open_plain(wake_dirs())
    if d is None:
        raise NoDir(f"the plugin of the opencode opened after the kill made none in {TMP}")
    print(f"{TAG} SWEPT: {'removed' if gone(crashed) else 'left'} {crashed}")
    tui.pump(3)
    if not quit(tui, "/exit"):
        print(f"{TAG} APPARATUS: opencode did not exit on /exit")
        sys.exit(2)
    tui = None
    code = 0
except NoDir as e:
    # Not the apparatus: only the plugin makes the directory. The caller judges this line.
    print(f"{TAG} NODIR: {e}")
    code = 0
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
finally:
    disarm()
    if tui is not None and not tui.stop():
        print(f"{TAG} APPARATUS: opencode (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
sys.exit(code)
