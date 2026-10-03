#!/usr/bin/env python3
"""tui_create_race.py <vox> <data_dir> <config_dir> <identity_pass> <tag>

A `vox tui` that loses the race to create a profile's identity, as a person would meet it: two
`vox tui`s are started on one profile with no identity, and both open on the first-run "Create
identity" prompt. The first is given a passphrase (typed and confirmed) and makes the identity;
only then is the second given one. Whatever the second says to that is read off its status line.
(Two TUIs, because a one-shot `vox id` started while a TUI runs asks the TUI's node instead of
creating anything.)

Each TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator:
raw ANSI cannot be grepped, because the TUI repaints only what changed.

Prints `<tag> SAID: <status line>` with what the second TUI answered. Exit 0 = it answered; 1 =
the TUI failed (`<tag> RED: PRODUCT: <what>`, with its screen: no first-run prompt, the first TUI
made nothing, no answer to the second create) or the driver hung (`HUNG at <stage>`, with its
stack: `vox_pty.py`, V210-54); 2 = apparatus, the driver's own machinery only (pyte missing). The
caller judges the words. Both TUIs are killed by their PIDs, with bounded waits.
"""
import os, sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, DATA, CFG, IDPASS, TAG = sys.argv[1:6]
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "240"))
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")

code = 2
tuis = []
try:
    stage("two first-run prompts")
    first = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)
    tuis.append(first)
    second = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)
    tuis.append(second)

    def status(t):
        """The bottom rows, where the TUI's status line is."""
        return "\n".join(r.rstrip() for r in t.display()[-3:])

    for name, t in (("first", first), ("second", second)):
        if not t.until(lambda: "create identity" in t.text().lower(), 60):
            print(f"{TAG} RED: PRODUCT: the {name} TUI never asked to create an identity:\n{t.text()}")
            sys.exit(1)

    stage("the first TUI creates")
    first_before = status(first)
    first.key(IDPASS + "\r", 1)
    first.key(IDPASS + "\r", 1)
    # Production Argon2id: sealing takes seconds. Made, the prompt is gone and the status changes.
    if not first.until(lambda: status(first) != first_before
                       and "create identity" not in first.text().lower(), 90):
        print(f"{TAG} RED: PRODUCT: the first TUI made no identity:\n{first.text()}")
        sys.exit(1)
    first.pump(2)
    print(f"{TAG} the first TUI made it: {' '.join(status(first).split())}")

    stage("the second TUI creates")
    second.pump(1)
    before = status(second)
    second.key(IDPASS + "\r", 1)
    second.key(IDPASS + "\r", 1)
    answered = ("another vox", "already", "error", "could not", "busy")
    if second.until(lambda: status(second) != before
                    and any(w in status(second) for w in answered), 60):
        code = 0
        print(f"{TAG} SAID: {' '.join(status(second).split())}")
    else:
        code = 1
        print(f"{TAG} RED: PRODUCT: no answer to the second create; the screen:\n{second.text()}")
    for t in tuis:
        t.key("\x1b", 0.5)
        t.key(":q\r", 1)
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
finally:
    disarm()
    for t in tuis:
        if not t.stop():
            # A driver that cannot stop what it started has leaked it, and is how a job hangs.
            print(f"{TAG} RED: vox tui (pid {t.pid}) outlived SIGKILL and could not be reaped")
            code = 1
sys.exit(code)
