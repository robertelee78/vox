#!/usr/bin/env python3
"""tui_identity_file_unwritable.py <vox> <data_dir> <config_dir> <identity_pass> <tag>

A `vox tui` whose identity file cannot be written, as a person would meet it: the TUI opens on its
first-run "Create identity" prompt on a node whose directory holds a directory where the vault's
temporary file must go (`nodes/default/vault.tmp/`, staged by the caller), so the create cannot
write `vault.cbor`. The passphrase is typed and confirmed, and whatever the TUI answers is read off
its status line.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator.

Prints `<tag> FIRST RUN: <the prompt's rows>`, what the first-run prompt says before anything is
typed (ADR-028 K-8: that a node has no backup), then `<tag> SAID: <status line>`. Exit 0 = it answered; 1 = the TUI failed (`<tag> RED:
PRODUCT: <what>`, with its screen) or the driver hung (`HUNG at <stage>`); 2 = apparatus (pyte
missing). The caller judges the words. The TUI is killed by its PID, with a bounded wait.
"""
import os, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

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
    stage("the first-run prompt")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)

    def status():
        """The bottom rows, where the TUI's status line is."""
        return "\n".join(r.rstrip() for r in tui.display()[-3:])

    if not tui.until(lambda: "create identity" in tui.text().lower(), 60):
        print(f"{TAG} RED: PRODUCT: the TUI never asked to create an identity:\n{tui.text()}")
        sys.exit(1)

    # The prompt's rows, joined: what a person reads before typing anything.
    rows = tui.display()
    top = next((i for i, r in enumerate(rows) if "Create identity" in r), len(rows))
    print(f"{TAG} FIRST RUN: {' '.join(' '.join(r.strip('│ ').split()) for r in rows[top:])}")

    stage("the create")
    before = status()
    tui.key(IDPASS + "\r", 1)
    tui.key(IDPASS + "\r", 1)
    answered = ("could not", "error", "already", "busy")
    # Production Argon2id: sealing takes seconds before the write is tried.
    if tui.until(lambda: status() != before and any(w in status() for w in answered), 90):
        code = 0
        print(f"{TAG} SAID: {' '.join(status().split())}")
    else:
        code = 1
        print(f"{TAG} RED: PRODUCT: no answer to the create; the screen:\n{tui.text()}")
    tui.key("\x1b", 0.5)
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
