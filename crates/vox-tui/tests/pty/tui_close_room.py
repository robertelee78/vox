#!/usr/bin/env python3
"""tui_close_room.py <vox> <data_dir> <config_dir> <identity_pass> <room_pass> <tag>

Closes a profile's only room through the shipped `vox tui`, as a person would: unlock, open the
room, `:close`. It is the one way to close a room on purpose (a daemon reopens every room it held
open), and V210-49's proof needs a room closed across a trust decision.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator: raw
ANSI cannot be grepped, because the TUI repaints only what changed. The status line is reset with
an unknown command (`:zzz`) first, so "done" afterwards can only be the close's answer.

Exit 0 = the TUI said "done" to `:close`; 2 = apparatus (pyte missing, no unlock, no room, no
"done"); 1 = the driver hung (`HUNG at <stage>`, with its stack: `vox_pty.py`, V210-54). The
caller confirms the room is closed on its own, with `vox room list`. The TUI is killed by its PID,
with bounded waits.
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
    tui.key(IDPASS + "\r", 1)
    # Production Argon2id: the unlock takes seconds. Unlocked, the rooms list names the room.
    if not tui.until(lambda: "unlocked" in status(), 60):
        print(f"{TAG} APPARATUS: the TUI never unlocked:\n{tui.text()}")
        sys.exit(2)
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
        print(f"{TAG} APPARATUS: no \"done\" after :close; before it:\n{before}\nafter:\n{tui.text()}")
    tui.key(":q\r", 1)
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
finally:
    disarm()
    if tui is not None and not tui.stop():
        # A driver that cannot stop what it started has leaked it, and is how a job hangs (#240).
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
sys.exit(code)
