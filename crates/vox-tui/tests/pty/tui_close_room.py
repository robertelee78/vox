#!/usr/bin/env python3
"""tui_close_room.py <vox> <data_dir> <config_dir> <identity_pass> <room_pass> <tag> [<member>]

Closes a profile's only room through the shipped `vox tui`, as a person would: unlock, open the
room, `:close`. It is the one way to close a room on purpose (a daemon reopens every room it held
open), and V210-49's proof needs a room closed across a trust decision.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator: raw
ANSI cannot be grepped, because the TUI repaints only what changed. The status line is reset with
an unknown command (`:zzz`) first, so "done" afterwards can only be the close's answer.

Exit 0 = the TUI said "done" to `:close`. 1 = a product red, with its screen: `RED: vox tui
exited before it asked to unlock`, `RED: the TUI never unlocked`, `RED: no "done" after
:close`, or `RED: vox tui exited at <stage>`, `RED: PRODUCT (staging): the status line still says done after
:zzz` (an unknown command must replace it, or a later "done" proves nothing); or `HUNG at <stage>` with the driver's stack (`vox_pty.py`, V210-54) — every wait here is
bounded, so a driver past its budget is a TUI that stopped reading what was typed. 2 = apparatus
only: pyte missing, or the driver's own error. The caller confirms the room is closed on its own, with `vox room list`. The
TUI is killed by its PID, with bounded waits.

**A TUI that never unlocks is the product, not the apparatus** (V210-107). It was reported as
`APPARATUS`, so a `vox tui` that sat waiting for an anchor that does not exist, with the right
passphrase typed, read as a broken test. The person typed the right thing and the product did not
do it: that is a product red, and so is a room that never answers `:close`.

**A TUI that is gone is the product, too** (V210-107, ac-ver302's verdict on 3b790e64). Once
`vox tui` has exited, a keystroke written to its pty raises `OSError(EIO)`; the catch-all for the
driver's own errors read that as `APPARATUS`, and a `:q` sent after a `RED` overwrote it the same
way. So a TUI found gone — its pty at EOF, or EIO on a write — is `RED: vox tui exited at
<stage>`, with its screen; and the first verdict stands: nothing after a `RED` replaces it.
"""
import errno, os, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import STAGE, Hung, Tui, arm, disarm, pyte, stage, is_attached  # noqa: E402

VOX, DATA, CFG, IDPASS, ROOMPASS, TAG = sys.argv[1:7]
# Optional: a member, by the first characters of its fingerprint, to select in this room and type
# `:consent grant` at before the close. There is no such command (V210-148): a key goes only to a
# member the owner trusts. What the TUI answered, and the member's row after it, are printed for
# the caller to judge; the close goes on either way, so the caller can also see what the node did.
GRANT = sys.argv[7] if len(sys.argv) > 7 else None
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "180"))
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")


class Verdict(Exception):
    """A verdict was given: the rest of the run is skipped, and nothing replaces it."""


code = None  # the first verdict's exit code; once set, it stands
tui = None


def give(c, line):
    """Give the run's verdict, unless one was already given; then stop the run."""
    global code
    if code is None:
        print(f"{TAG} {line}")
        code = c
    raise Verdict()


def gone_check():
    """A TUI whose pty is at EOF has exited: that is the product, at whatever stage it was."""
    if tui is not None and tui.closed:
        give(1, f"RED: vox tui exited at {STAGE[0]!r}:\n{tui.text()}")


def key(s, wait):
    """A keystroke; EIO on the write means the TUI is gone, which is the product."""
    try:
        tui.key(s, wait)
    except OSError as e:
        if e.errno == errno.EIO:
            tui.closed = True
            gone_check()
        raise
    gone_check()


def status():
    """The bottom rows, where the TUI's status line is."""
    return "\n".join(r.rstrip() for r in tui.display()[-3:])


try:
    stage("unlock")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)
    tui.pump(3)
    if tui.closed:
        # Gone before it asked for anything: the product stopped, and its screen says why.
        give(1, f"RED: vox tui exited before it asked to unlock:\n{tui.text()}")
    key(IDPASS + "\r", 1)
    # Production Argon2id: the unlock takes seconds. Unlocked, the rooms list names the room.
    unlocked = tui.until(lambda: tui.closed or is_attached(status()), 60)
    gone_check()
    if not unlocked:
        give(1, f"RED: the TUI never unlocked, with the right passphrase typed:\n{tui.text()}")
    stage("open the room")
    tui.pump(3)
    gone_check()
    key("\r", 3)  # open the room under the cursor (the profile holds one)
    if "passphrase" in tui.text().lower():
        # Closed on this node: the TUI asks for the room's passphrase to open it.
        key(ROOMPASS + "\r", 6)
    if GRANT:
        stage(":consent grant")
        key("\t", 0.5)  # timeline -> composer
        key("\t", 0.5)  # composer -> members
        members = lambda: [r[100:] if len(r) > 100 else "" for r in tui.display()]
        def label_of(prefix):
            rows = members()
            for i, r in enumerate(rows):
                if prefix in r:
                    return (rows[i + 1] if i + 1 < len(rows) else ""), "\u25b6" in r
            return None, False
        if not tui.until(lambda: label_of(GRANT)[0] is not None, 60, 1):
            give(1, f"RED: PRODUCT (staging): {GRANT} is not in the members pane:\n{tui.text()}")
        for _ in range(8):
            if label_of(GRANT)[1]:
                break
            key("\x1b[B", 0.5)  # Down
        if not label_of(GRANT)[1]:
            give(1, f"RED: PRODUCT (staging): Down never put the marker on {GRANT}:\n{tui.text()}")
        # The TUI's node must be connected before the grant, or a grant that existed could fail for
        # want of a session and the proof would show nothing: wait for the member it trusts to show
        # trusted (its key went out, so sessions are up), then 15 s more (V29-19 measured a first
        # grant failing for want of a session for up to 15 s after a room opened).
        rows_all = lambda: "\n".join(members())
        if not tui.until(lambda: "trusted" in rows_all(), 60, 1):
            give(1, f"RED: PRODUCT (staging): the TUI's node never showed a trusted member, so it never connected:\n{tui.text()}")
        tui.pump(15)
        gone_check()
        if "unknown command" in status():
            give(2, f"APPARATUS: the status line says unknown command before :consent grant:\n{tui.text()}")
        key(":consent grant\r", 2)
        answer = status()
        tui.pump(5)
        gone_check()
        row = label_of(GRANT)[0] or ""
        print(f"{TAG} :consent grant answered {answer.strip()!r}; {GRANT}'s row then: {row.strip()!r}")
        if "unknown command" in answer:
            print(f"{TAG} :consent grant is not a command")
        # Then a post from the composer, with the TUI's node up long enough to deliver it: what the
        # caller reads of it shows what the node did with the grant, not only what the TUI drew.
        stage("post after :consent grant")
        key("\t", 0.5)  # members -> timeline
        key("\t", 0.5)  # timeline -> composer
        key("BOB-AFTER-GRANT\r", 1)
        key("\t", 0.5)  # composer -> members, where `:` opens the command line again
        tui.pump(20)
        gone_check()
        print(f"{TAG} posted BOB-AFTER-GRANT")
    before = tui.text()
    stage(":close")
    key(":zzz\r", 1.5)
    if "done" in status():
        give(1, f"RED: PRODUCT (staging): the status line still says done after :zzz, an unknown "
                f"command:\n{tui.text()}")
    key(":close\r", 1)
    closed = tui.until(lambda: tui.closed or "done" in status(), 20)
    gone_check()
    if not closed:
        give(1, f"RED: no \"done\" after :close; before it:\n{before}\nafter:\n{tui.text()}")
    code = 0
    print(f"{TAG} the TUI said done to :close")
    stage(":q")
    try:
        tui.key(":q\r", 1)  # leaving after the verdict: nothing it does changes the verdict
    except OSError:
        pass
except Verdict:
    pass
except Hung as h:
    if code is None:
        print(f"{TAG} HUNG at {h}")
        code = 1
except Exception as e:  # the driver's own fault, not the TUI's
    if code is None:
        print(f"{TAG} APPARATUS: the driver failed: {e!r}")
        code = 2
finally:
    disarm()
    if tui is not None and not tui.stop():
        # A driver that cannot stop what it started has leaked it, and is how a job hangs (#240).
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
sys.exit(2 if code is None else code)
