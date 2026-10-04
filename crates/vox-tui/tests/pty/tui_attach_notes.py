#!/usr/bin/env python3
"""tui_attach_notes.py <vox> <data_dir> <config_dir> <identity_pass> <tag>

`vox tui` attaches its node itself, as a person does: the node is on disk and not attached, the TUI
asks for its passphrase at its "Attach node" prompt, and the passphrase is typed there. What
attaching the node said (a skipped anchors line, "carrying on with no anchor") is then read off the
TUI's screen, where a person would read it.

Prints `<tag> ATTACHED`, then `<tag> SAID: <text>` with the TUI's bottom rows joined (its status
bar, its notice line), and `<tag> SCREEN:` with the whole screen. Exit 0 = the TUI attached its node
and the screen was read; 1 = the TUI failed (`<tag> RED: PRODUCT: <what>`, with its screen: no
attach prompt, never attached) or the driver hung (`HUNG at <stage>`: `vox_pty.py`, V210-54); 2 =
apparatus, the driver's own machinery only (pyte missing). The caller judges the words. The TUI is
killed by its PID, with bounded waits.
"""
import os, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, is_attached, pyte, stage  # noqa: E402

VOX, DATA, CFG, IDPASS, TAG = sys.argv[1:6]
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
        """The bottom rows: the status bar and the line under it, which a long notice wraps onto
        several rows of."""
        return " ".join(" ".join(r.split()) for r in tui.display()[-6:])

    stage("the attach prompt")
    if not tui.until(lambda: tui.closed or "attach node" in tui.text().lower(), 60):
        print(f"{TAG} RED: PRODUCT: the TUI never asked to attach its node:\n{tui.text()}")
        sys.exit(1)
    stage("attach")
    tui.key(IDPASS + "\r", 0.5)
    if not tui.until(lambda: is_attached(bottom()), 90):
        print(f"{TAG} RED: PRODUCT: the TUI never showed its node attached:\n{tui.text()}")
        sys.exit(1)
    print(f"{TAG} ATTACHED")
    tui.pump(2)
    print(f"{TAG} SAID: {bottom()}")
    print(f"{TAG} SCREEN:\n{tui.text()}")
    code = 0
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
