#!/usr/bin/env python3
"""tui_watch_notice.py <vox> <data_dir> <config_dir> <cue_dir> <want> <tag>

`vox tui` on a node that is attached already (so it asks for nothing), watched for a notice: once
it shows its node attached this driver writes `ready` in <cue_dir>; then it reads the TUI's bottom
rows until they contain <want>, for at most 90 s, as a person would read them.

Prints `<tag> SAID: <text>` with the bottom rows joined, and `<tag> SCREEN:` with the whole
screen. Then it presses `d` for the node's decision record (ADR-028 D-3) and prints each of its
rows as `<tag> DECISION: <row>`, top first. Exit 0 = the TUI attached and the screen was read (the caller judges the words); 1 = the
TUI failed (`<tag> RED: PRODUCT: <what>`: never showed its node attached) or the driver hung
(`HUNG at <stage>`: `vox_pty.py`, V210-54); 2 = apparatus (pyte missing). The TUI is killed by its
PID, with bounded waits.
"""
import os, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, is_attached, pyte, stage  # noqa: E402

VOX, DATA, CFG, CUE, WANT, TAG = sys.argv[1:7]
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
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)

    def bottom():
        """The status bar and the line under it, which a long notice wraps onto several rows."""
        return " ".join(" ".join(r.split()) for r in tui.display()[-6:])

    stage("attached")
    if not tui.until(lambda: tui.closed or is_attached(bottom()), 60):
        print(f"{TAG} RED: PRODUCT: the TUI never showed its node attached:\n{tui.text()}")
        code = 1
        sys.exit(code)
    path = os.path.join(CUE, "ready")
    with open(path + ".tmp", "w") as f:
        f.write(f"{time.time():.3f}")
    os.rename(path + ".tmp", path)
    stage("watch for the notice")
    tui.until(lambda: WANT in bottom(), 90, 0.2)
    print(f"{TAG} SAID: {bottom()}")
    print(f"{TAG} SCREEN:\n{tui.text()}")
    stage("the decision record")
    # `d` on the channel list: what the node decided, newest first (ADR-028 D-3).
    tui.key("d", 1)
    tui.until(lambda: "Decisions (newest first" in tui.text(), 10, 0.2)
    tui.pump(2)
    rows = [" ".join(r.strip().strip("│").split()) for r in tui.display()]
    print(f"{TAG} DECISIONS:")
    for r in rows:
        if " ago " in r:
            print(f"{TAG} DECISION: {r}")
    code = 0
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
