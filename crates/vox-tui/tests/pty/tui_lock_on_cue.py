#!/usr/bin/env python3
"""tui_lock_on_cue.py <vox> <data_dir> <config_dir> <identity_pass> <cue_dir> <tag>

Runs the shipped `vox tui` as a person does and locks it with `:lock` when the proof says so
(V210-76). The proof talks to it through files in <cue_dir>:

- this driver writes `unlocked` once the TUI is unlocked, so its control socket serves `vox room`;
- the proof writes `lock`; this driver then types `:lock` and writes `locked` once the TUI shows
  LOCKED;
- the proof writes `stop`; this driver quits the TUI.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator.

Exit 0 = the TUI unlocked, locked on cue and was stopped; 2 = apparatus (pyte missing, no unlock,
no cue, never showed LOCKED); 1 = the driver hung (`HUNG at <stage>`, with its stack: `vox_pty.py`,
V210-54). The TUI is killed by its PID, with bounded waits.
"""
import os, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, DATA, CFG, IDPASS, CUE, TAG = sys.argv[1:7]
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "300"))
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")


def cue(name):
    with open(os.path.join(CUE, name), "w") as f:
        f.write(f"{time.time():.3f}")


def wait_cue(tui, name, secs):
    return tui.until(lambda: os.path.exists(os.path.join(CUE, name)), secs, 0.1)


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
    # Production Argon2id: the unlock takes seconds.
    if not tui.until(lambda: "unlocked" in status(), 60):
        print(f"{TAG} APPARATUS: the TUI never unlocked:\n{tui.text()}")
        sys.exit(2)
    cue("unlocked")
    stage("wait for the lock cue")
    if not wait_cue(tui, "lock", 180):
        print(f"{TAG} APPARATUS: no lock cue")
        sys.exit(2)
    stage(":lock")
    tui.key(":lock\r", 0.2)
    if not tui.until(lambda: "LOCKED" in tui.text(), 20, 0.1):
        print(f"{TAG} APPARATUS: the TUI never showed LOCKED after :lock:\n{tui.text()}")
        sys.exit(2)
    cue("locked")
    stage("wait for the stop cue")
    if not wait_cue(tui, "stop", 180):
        print(f"{TAG} APPARATUS: no stop cue")
        sys.exit(2)
    code = 0
    print(f"{TAG} PASS: the TUI locked on cue")
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
