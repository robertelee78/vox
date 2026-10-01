#!/usr/bin/env python3
"""tui_room_verb.py <vox> <data_dir> <config_dir> <identity_pass> <room_pass> <tag> <verb> <hold_secs>

Runs one room verb (`:leave`, `:end` or `:forget`, V030-08) on a profile's only room through the
shipped `vox tui`, as a person would: unlock, open the room, `:<verb>`. Then it keeps the TUI
running for `hold_secs`, because a leave or an end is passed to the other members by this node
while it runs, as a person's TUI would stay open.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator (see
`tui_close_room.py`). The status line is reset with an unknown command (`:zzz`) first, so "done"
afterwards can only be the verb's answer.

Exit 0 = the TUI said "done" to the verb; 3 = the TUI refused it (its status line is printed, for
the caller to judge as the product's answer); 2 = apparatus (pyte missing, no unlock, no answer at
all); 1 = the driver hung (`HUNG at <stage>`). The TUI is killed by its PID, with bounded waits.
"""
import os, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, DATA, CFG, IDPASS, ROOMPASS, TAG, VERB, HOLD = sys.argv[1:9]
HOLD = int(HOLD)
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "240")) + HOLD
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
    if not tui.until(lambda: "unlocked" in status(), 90):
        print(f"{TAG} APPARATUS: the TUI never unlocked:\n{tui.text()}")
        sys.exit(2)
    stage("open the room")
    tui.pump(3)
    tui.key("\r", 3)  # open the room under the cursor (the profile holds one)
    if "passphrase" in tui.text().lower():
        tui.key(ROOMPASS + "\r", 6)
    stage(f":{VERB}")
    tui.key(":zzz\r", 1.5)
    if "done" in status():
        print(f"{TAG} APPARATUS: the status line still says done after :zzz:\n{tui.text()}")
        sys.exit(2)
    reset = status()
    tui.key(f":{VERB}\r", 1)
    if tui.until(lambda: "done" in status(), 30):
        code = 0
        print(f"{TAG} the TUI said done to :{VERB}")
    elif tui.until(lambda: status() != reset, 5):
        code = 3
        print(f"{TAG} the TUI refused :{VERB}: {status()}")
    else:
        print(f"{TAG} APPARATUS: no answer to :{VERB}:\n{tui.text()}")
    stage(f"hold {HOLD}s")
    tui.pump(HOLD)
    tui.key(":q\r", 1)
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
finally:
    disarm()
    if tui is not None and not tui.stop():
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
sys.exit(code)
