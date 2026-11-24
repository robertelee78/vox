#!/usr/bin/env python3
"""tui_marks_read.py <vox> <data_dir> <config_dir> <cue_dir> <want> <tag> <mode>

`vox tui` on a node that is attached already (so it asks for nothing), on its one room: once its
timeline shows <want> and a message shown as "(not received yet)", this driver prints
`<tag> SHOWN:` with the timeline and writes `shown` in <cue_dir>; then it keeps the TUI open,
drawing, until the caller writes `done` there (at most 120 s), and quits it. What the TUI marked
read meanwhile is the caller's to judge, from the node. <mode> other than `-` is given to the TUI
as `VOX_TEST_OWED_ROW` (a proof's mutant, `test-knobs` builds only).

Exit 0 = the TUI showed both and was kept open; 1 = no result (`<tag> APPARATUS NO RESULT: <what>`:
never attached, or never showed both, within the driver's bound: elapsed time is no verdict on the
TUI) or the driver hung (`HUNG at <stage>`: `vox_pty.py`, V210-54); 2 = apparatus (pyte missing).
The TUI is killed by its PID, with bounded waits.
"""
import os, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, is_attached, pane, pyte, stage  # noqa: E402

VOX, DATA, CFG, CUE, WANT, TAG, MODE = sys.argv[1:8]
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "240"))
NOT_RECEIVED_YET = "(not received yet)"
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")
if MODE != "-":
    env["VOX_TEST_OWED_ROW"] = MODE


def cue(name):
    path = os.path.join(CUE, name)
    with open(path + ".tmp", "w") as f:
        f.write(f"{time.time():.3f}")
    os.rename(path + ".tmp", path)


code = 2
tui = None
try:
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)

    def bottom():
        return " ".join(" ".join(r.split()) for r in tui.display()[-6:])

    def timeline():
        return "\n".join(pane(tui.display(), "Timeline"))

    stage("attached")
    if not tui.until(lambda: tui.closed or is_attached(bottom()), 60):
        print(f"{TAG} APPARATUS NO RESULT: the TUI never showed its node attached within 60 s:\n"
              f"{tui.text()}")
        code = 1
        sys.exit(code)
    stage("open the room")
    # The sidebar selects the node's one room; Enter opens it, as a person opens it.
    tui.until(lambda: "No room open" in tui.text() or WANT in timeline(), 30, 0.5)
    if WANT not in timeline():
        tui.key("\r", 1)
    stage("the room's timeline shows both")
    both = lambda: WANT in timeline() and NOT_RECEIVED_YET in timeline()
    if not tui.until(both, 60, 0.5):
        print(f"{TAG} APPARATUS NO RESULT: the TUI's timeline never showed {WANT!r} and a message "
              f"{NOT_RECEIVED_YET} within 60 s:\n{tui.text()}")
        code = 1
        sys.exit(code)
    print(f"{TAG} SHOWN:\n{timeline()}")
    sys.stdout.flush()
    cue("shown")
    stage("kept open while the caller watches the node")
    tui.until(lambda: os.path.exists(os.path.join(CUE, "done")), 120, 0.5)
    code = 0
    print(f"{TAG} PASS: the timeline showed {WANT!r} beside a message {NOT_RECEIVED_YET}")
    tui.key("q", 1)
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
finally:
    disarm()
    if tui is not None and not tui.stop():
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
sys.exit(code)
