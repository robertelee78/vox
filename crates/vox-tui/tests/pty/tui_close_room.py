#!/usr/bin/env python3
"""tui_close_room.py <vox> <data_dir> <config_dir> <identity_pass> <room_pass> <tag>

Closes a profile's only room through the shipped `vox tui`, as a person would: unlock, open the
room, `:close`. It is the one way to close a room on purpose (a daemon reopens every room it held
open), and V210-49's proof needs a room closed across a trust decision.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator: raw
ANSI cannot be grepped, because the TUI repaints only what changed. The status line is reset with
an unknown command (`:zzz`) first, so "done" afterwards can only be the close's answer.

Exit 0 = the TUI said "done" to `:close`. 1 = a product red, with its screen: `RED: vox tui
exited before it asked to unlock`, `RED: the TUI never unlocked`, or `RED: no "done" after
:close`; or `HUNG at <stage>` with the driver's stack (`vox_pty.py`, V210-54) — every wait here is
bounded, so a driver past its budget is a TUI that stopped reading what was typed. 2 = apparatus
only: pyte missing, the status line not reset by `:zzz` (the staging this driver needs), or the
driver's own error. The caller confirms the room is closed on its own, with `vox room list`. The
TUI is killed by its PID, with bounded waits.

**A TUI that never unlocks is the product, not the apparatus** (V210-107). It was reported as
`APPARATUS`, so a `vox tui` that sat waiting for an anchor that does not exist, with the right
passphrase typed, read as a broken test. The person typed the right thing and the product did not
do it: that is a product red, and so is a room that never answers `:close`.
"""
import os, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, DATA, CFG, IDPASS, ROOMPASS, TAG = sys.argv[1:7]
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "180"))
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")

code = 2
tui = None
try:
    stage("unlock")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)

    def status():
        """The bottom rows, where the TUI's status line is."""
        return "\n".join(r.rstrip() for r in tui.display()[-3:])

    tui.pump(3)
    if tui.closed:
        # Gone before it asked for anything: the product stopped, and its screen says why.
        print(f"{TAG} RED: vox tui exited before it asked to unlock:\n{tui.text()}")
        code = 1
        sys.exit(code)
    tui.key(IDPASS + "\r", 1)
    # Production Argon2id: the unlock takes seconds. Unlocked, the rooms list names the room.
    if not tui.until(lambda: "unlocked" in status(), 60):
        print(f"{TAG} RED: the TUI never unlocked, with the right passphrase typed:\n{tui.text()}")
        code = 1
        sys.exit(code)
    stage("open the room")
    tui.pump(3)
    tui.key("\r", 3)  # open the room under the cursor (the profile holds one)
    if "passphrase" in tui.text().lower():
        # Closed on this node: the TUI asks for the room's passphrase to open it.
        tui.key(ROOMPASS + "\r", 6)
    before = tui.text()
    stage(":close")
    tui.key(":zzz\r", 1.5)
    if "done" in status():
        print(f"{TAG} APPARATUS: the status line still says done after :zzz:\n{tui.text()}")
        sys.exit(2)
    tui.key(":close\r", 1)
    if tui.until(lambda: "done" in status(), 20):
        code = 0
        print(f"{TAG} the TUI said done to :close")
    else:
        print(f"{TAG} RED: no \"done\" after :close; before it:\n{before}\nafter:\n{tui.text()}")
        code = 1
    tui.key(":q\r", 1)
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
except Exception as e:  # the driver's own fault, not the TUI's
    print(f"{TAG} APPARATUS: the driver failed: {e!r}")
    code = 2
finally:
    disarm()
    if tui is not None and not tui.stop():
        # A driver that cannot stop what it started has leaked it, and is how a job hangs (#240).
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
sys.exit(code)
