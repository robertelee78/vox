#!/usr/bin/env python3
"""tui_equivocation.py <vox> <tag> <data> <cfg> <room-name> — V210-66, the TUI half, through the shipped `vox tui`.

Called by `an_equivocation_is_detected_and_said_proof` at its end state: a room in which the member
whose profile is at <data>/<cfg> holds two others back for equivocating (eve and frank, the names
it gave them), with every node stopped. Its real `vox tui` is opened in a pty (pyte at 160x50), the
room opened, and the timeline pane read: **each** held-back member must be said on a line of its
own, by the keyring name — `! eve signed two different messages at the same place …` and the same
for frank. Exit 0 = pass, 1 = red, 2 = apparatus. Every process is recorded and killed by PID.

Bounded throughout (`vox_pty.py`, V210-54): past its budget the driver says `HUNG at <stage>` with
its stack, stops everything and exits red.
"""
import os, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, TAG, DATA, CFG, ROOM = sys.argv[1:6]
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "180"))
IDENTITY = "identity passphrase"
ROOM_PASS = "room pass"
NAMES = ("eve", "frank")
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)"); sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")

tui = None
code = 2
try:
    stage("the tui: unlock and open the room")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)
    tui.pump(4)
    tui.key(f"{IDENTITY}\r", 4)
    tui.key("\r", 2)
    tui.key(f"{ROOM_PASS}\r", 4)
    tui.key("\r", 2)

    # The timeline is the left-hand 70% of the screen; its notices are the rows that start "! ".
    def timeline():
        return [row[:112] for row in tui.display()]
    def said(name):
        return any(f"! {name} signed two different messages at the same place" in r for r in timeline())
    stage("the timeline pane")
    tui.until(lambda: all(said(n) for n in NAMES), 30, 1)
    pane = [r.rstrip() for r in timeline() if r.strip()]
    print(f"{TAG} the TUI drew {tui.bytes} bytes")
    print(f"{TAG} timeline pane (cols 0-111):")
    for r in pane:
        print(f"  |{r}")
    if not any(ROOM in r for r in tui.display()) and not any("Timeline" in r for r in pane):
        print(f"{TAG} APPARATUS: the room {ROOM!r} never opened")
        code = 2
    else:
        seen = {n: said(n) for n in NAMES}
        print(f"{TAG} said on a line of its own: {seen}")
        code = 0 if all(seen.values()) else 1
        print(f"{TAG} {'PASS' if code == 0 else 'RED'}")
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
finally:
    disarm()
    stage("stopping every process")
    if tui is not None and not tui.stop():
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
    stage(f"done, exit {code}")
sys.exit(code)
