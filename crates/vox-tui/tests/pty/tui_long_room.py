#!/usr/bin/env python3
"""tui_long_room.py <vox> <tag> <data dir> <config dir> <room name> <posts> <identity passphrase>
<room passphrase> — V210-120, through the
shipped `vox tui`.

Opens the real `vox tui` in a pty (pyte at 160x50) on a profile whose daemon has been stopped,
unlocks it, opens the room named <room name> (the first in its list), moves to the composer, and
then sends <posts> short messages from it one after another without waiting, timed from the
moment they are written to the pty until the timeline pane shows every one as the sender's own.
Prints `<tag> SENTALL <ms>`. The verdict on the time is the Rust proof's.

Exit 0 = every message measured, 2 = apparatus (CANNOT MEASURE): pyte missing, or the driver's
own budget. A TUI that never lists or opens the room after the unlock is exit 1, `PRODUCT
(staging)`, and so is a message that never appears: both are the product's. Every process is killed by PID; bounded throughout (`vox_pty.py`, V210-54).
"""
import os, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, TAG, DATA, CFG, ROOM, POSTS, IDPASS, ROOMPASS = sys.argv[1:9]
POSTS = int(POSTS)
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "600"))
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)"); sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")

def apparatus(why):
    print(f"{TAG} APPARATUS: {why}"); sys.exit(2)

def staging(why):
    """A step the product performs while the proof is set up, not done: the product's red."""
    print(f"{TAG} RED: PRODUCT (staging): {why}"); sys.exit(1)


def paged_order():
    import re
    tui = None
    code = 2
    try:
        stage("paged Order: opening attached node")
        node = sys.argv[10]
        tui = Tui([VOX, "tui", "--node", node], env)
        if not tui.until(lambda: ROOM in tui.text(), 60, .2):
            staging(f"room absent from TUI: {tui.text()}")
        tui.key("\r", 1)
        if not tui.until(lambda: "ORDER-PAGE-5999" in tui.text(), 60, .2):
            staging(f"newest Order page absent from TUI: {tui.text()}")
        stage("paged Order: reading each timeline page")
        seen = set()
        for _ in range(1400):
            # Only the timeline is the verdict; matching a sidebar preview cannot count.
            from vox_pty import pane
            visible = [int(n) for n in re.findall(r"ORDER-PAGE-(\d{4})", "\n".join(pane(tui.display(), "Timeline")))]
            if visible != sorted(visible):
                print(f"{TAG} RED: PRODUCT: timeline rows are out of Order: {visible}")
                return 1
            seen.update(visible)
            if len(seen) == 6000:
                break
            tui.key("\x1b[5~", .08)
        if seen != set(range(6000)):
            missing = sorted(set(range(6000)) - seen)
            print(f"{TAG} RED: PRODUCT: TUI lost {len(missing)} of6000 Order rows; first missing {missing[:20]}; screen:\n{tui.text()}")
            return 1
        tui.key("\x1b[F", 1)
        if "ORDER-PAGE-5999" not in tui.text():
            print(f"{TAG} RED: PRODUCT: End did not restore newest row after paging:\n{tui.text()}")
            return 1
        print(f"{TAG} PASS: TUI showed all6000 entries in Order across pages; End returned to newest")
        code = 0
    except Hung as h:
        print(f"{TAG} APPARATUS: driver watchdog at {h}")
    finally:
        disarm()
        if tui is not None and not tui.stop():
            print(f"{TAG} APPARATUS: TUI did not stop")
            code = 2
    return code

if len(sys.argv) > 9 and sys.argv[9] == "order":
    sys.exit(paged_order())


def paged_members():
    import re
    from vox_pty import pane
    tui = None
    code = 2
    try:
        stage("70 members: opening attached node")
        tui = Tui([VOX, "tui", "--node", sys.argv[10]], env)
        if not tui.until(lambda: ROOM in tui.text(), 60, .2):
            staging(f"70-member room absent: {tui.text()}")
        tui.key("\r", 1)
        if not tui.until(lambda: "READ-MARK-69" in tui.text(), 60, .2):
            staging(f"70-member timeline did not open: {tui.text()}")
        stage("70 members: read marks in the timeline")
        seen, readers = set(), set()
        for _ in range(300):
            shown = "\n".join(pane(tui.display(), "Timeline"))
            seen.update(int(n) for n in re.findall(r"READ-MARK-(\d{2})", shown))
            readers.update(int(n) for n in re.findall(r"member-(\d{2})", shown))
            if len(seen) == 70 and readers >= set(range(1, 70)):
                break
            tui.key("\x1b[5~", .1)
        if seen != set(range(70)) or not readers >= set(range(1, 70)):
            print(f"{TAG} RED: PRODUCT: TUI lost read marks: {len(seen)}/70 rows, {len(readers)}/69 readers; screen:\n{tui.text()}")
            return 1
        stage("70 members: each member's trust in the member pane")
        tui.key("\t", .2)
        tui.key("\t", .2)
        trusted = set()
        for _ in range(150):
            lines = pane(tui.display(), "Members")
            for i, line in enumerate(lines):
                for number in re.findall(r"member-(\d{2})", line):
                    if "trusted both ways" in " ".join(lines[i:i+4]):
                        trusted.add(int(number))
            if trusted >= set(range(1, 70)):
                break
            tui.key("\x1b[B", .1)
        if not trusted >= set(range(1, 70)):
            print(f"{TAG} RED: PRODUCT: TUI lost member trust: missing {sorted(set(range(1,70))-trusted)}; screen:\n{tui.text()}")
            return 1
        print(f"{TAG} PASS: 70-member TUI opened, every reader's mark and every peer's trust were shown")
        code = 0
    except Hung as h:
        print(f"{TAG} APPARATUS: driver watchdog at {h}")
    finally:
        disarm()
        if tui is not None and not tui.stop():
            print(f"{TAG} APPARATUS: TUI did not stop")
            code = 2
    return code

if len(sys.argv) > 9 and sys.argv[9] == "members":
    sys.exit(paged_members())

tui = None
code = 2
try:
    stage("tui: unlock")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)
    tui.pump(4)
    tui.key(f"{IDPASS}\r", 4)
    if not tui.until(lambda: ROOM in tui.text(), 120, 1):
        staging(f"`vox tui` never listed the room {ROOM!r} after the unlock:\n{tui.text()}")
    stage("tui: open the room")
    tui.key("\r", 2)
    # A room that was not reopened by itself asks for its passphrase.
    if "assphrase" in tui.text():
        tui.key(f"{ROOMPASS}\r", 4)
    if not tui.until(lambda: "Timeline" in tui.text(), 120, 1):
        staging(f"`vox tui` never showed the room's timeline:\n{tui.text()}")
    tui.key("\t", 1)   # timeline -> composer
    # Settle first: opening a room re-verifies its whole log and the node then catches up on what
    # it held, a one-off cost of opening, not of each message.
    tui.pump(10)
    stage("tui: send and time")
    # Sent as a person sends a run of short messages, one after another without waiting, and
    # timed until the timeline shows every one of them as theirs ("you: ..."): a frame that cost
    # the room's history is paid once per message here. (Matching the bare text would match the
    # composer's own echo of it, before anything was sent.)
    texts = [f"tui-{TAG}-{k:02d}" for k in range(POSTS)]
    t0 = time.time()
    os.write(tui.fd, "".join(f"{t}\r" for t in texts).encode())
    shown = lambda: all(f"you: {t}" in tui.text() for t in texts)
    if tui.until(shown, 60, 0.01):
        print(f"{TAG} SENTALL {(time.time() - t0) * 1000:.1f}")
        code = 0
        print(f"{TAG} PASS: every message measured; the verdict on the time is the proof's")
    else:
        missing = [t for t in texts if f"you: {t}" not in tui.text()]
        print(f"{TAG} RED: {len(missing)} of {POSTS} messages sent from the composer were not on "
              f"screen 60 s later: {missing}")
        code = 1
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    print(f"{TAG} APPARATUS: the driver ran past its {BUDGET} s budget at {h}")
    code = 2
finally:
    disarm()
    stage("stopping the tui")
    if tui is not None and not tui.stop():
        print(f"{TAG} APPARATUS: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 2 if code == 0 else code
    stage(f"done, exit {code}")
sys.exit(code)
