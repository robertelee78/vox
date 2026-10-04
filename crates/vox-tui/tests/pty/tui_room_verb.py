#!/usr/bin/env python3
"""tui_room_verb.py <vox> <data_dir> <config_dir> <identity_pass> <room_pass> <tag> <verb> <hold_secs>

Runs one room verb (`:leave` or `:end`, V030-08) on a profile's only room through the
shipped `vox tui`, as a person would: unlock, open the room, `:<verb>`. Then it keeps the TUI
running for `hold_secs`, because a leave or an end is passed to the other members by this node
while it runs, as a person's TUI would stay open.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator: raw
ANSI cannot be grepped, because the TUI repaints only what changed. The status line is reset with
an unknown command (`:zzz`) first, so "done" afterwards can only be the verb's answer.

Shaped as `tui_close_room.py` (V210-107, #302): **a TUI that does not do what the person typed is
the product, not the apparatus.**

Exit 0 = the TUI said "done" to the verb. 1 = a product red, with its screen: `RED: vox tui exited
before it asked to unlock`, `RED: the TUI never unlocked`, `RED: the TUI refused :<verb>: <its
words>` (the status line names an error, read from its words, not from any change on screen),
`RED: no answer to :<verb>`, or `RED: vox tui exited at <stage>`; or `HUNG at <stage>` with the
driver's stack (`vox_pty.py`, V210-54) — every wait here is bounded, so a driver past its budget is
a TUI that stopped reading what was typed. 2 = apparatus only: pyte missing, the status line not
reset by `:zzz` (the staging this driver needs), or the driver's own error. The first verdict
stands: nothing after it replaces it. The TUI is killed by its PID, with bounded waits.
"""
import errno, os, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import STAGE, Hung, Tui, arm, disarm, pyte, stage, is_attached  # noqa: E402

VOX, DATA, CFG, IDPASS, ROOMPASS, TAG, VERB, HOLD = sys.argv[1:9]
HOLD = int(HOLD)
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "240")) + HOLD
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")

# What the TUI's status line says when it refused a room verb (`UiError::message`): its words, so
# an echo of the command box or any other repaint is never read as a refusal.
REFUSALS = (
    "only the room's creator",
    "this room has ended",
    "you left this room",
    "joined a moment ago",
    "this room is not open",
    "internal error",
    "could not write this node's files",
    "could not be written",
    "not connected",
    "locked — :unlock",
)


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


def refusal():
    """The refusal the status line states, if it states one."""
    s = status()
    return next((r for r in REFUSALS if r in s), None)


try:
    stage("unlock")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)
    tui.pump(3)
    if tui.closed:
        give(1, f"RED: vox tui exited before it asked to unlock:\n{tui.text()}")
    key(IDPASS + "\r", 1)
    # Production Argon2id: the unlock takes seconds. Unlocked, the rooms list names the room.
    unlocked = tui.until(lambda: tui.closed or is_attached(tui.text()), 90)
    gone_check()
    if not unlocked:
        give(1, f"RED: the TUI never unlocked, with the right passphrase typed:\n{tui.text()}")
    stage("open the room")
    tui.pump(3)
    gone_check()
    key("\r", 3)  # open the room under the cursor (the profile holds one)
    if "passphrase" in tui.text().lower():
        key(ROOMPASS + "\r", 6)
    stage(f":{VERB}")
    key(":zzz\r", 1.5)
    if "done" in status():
        give(2, f"APPARATUS: the status line still says done after :zzz:\n{tui.text()}")
    key(f":{VERB}\r", 1)
    answered = tui.until(lambda: tui.closed or "done" in status() or refusal(), 30)
    gone_check()
    said = refusal()
    if said:
        give(1, f"RED: the TUI refused :{VERB}: {said}:\n{tui.text()}")
    if not answered:
        give(1, f"RED: no answer to :{VERB} within 30s:\n{tui.text()}")
    code = 0
    print(f"{TAG} the TUI said done to :{VERB}")
    stage(f"hold {HOLD}s")
    tui.pump(HOLD)
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
