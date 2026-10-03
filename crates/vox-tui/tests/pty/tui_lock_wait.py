#!/usr/bin/env python3
"""tui_lock_wait.py <vox> <data_dir> <config_dir> <identity_pass> <tag> <create|unlock> <holder_pid>

A `vox tui` that has to wait for another vox holding the profile's lock, as a person would meet
it: the holder (started by the caller, which has stopped it with SIGSTOP while it holds the lock)
is in the middle of creating the identity, or of migrating a v0.2.9 profile. The TUI is given the
passphrase at its first-run "Create identity" prompt (`create`) or its "Unlock" prompt (`unlock`),
and so waits on the lock. Its screen is read while it waits, then the holder is resumed with
SIGCONT (by the PID the caller recorded), and what the TUI says afterwards is read too.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator.

Prints, each on its own line:
- `<tag> NOTICE after <secs>: <status line>` — the status line once it said it is waiting, or
  `<tag> NOTICE none: <status line>` if it never did within 15 s;
- `<tag> STRAY: <yes|no>` — whether a CLI-only line ("vox: waiting …", "resume it") is anywhere
  on the screen, which is stderr written into the TUI;
- `<tag> FRAME: ok (<n> rows)` or `<tag> FRAME: broken: <rows>` — every row that starts a box
  border (`│`, `┌`, `└`) ends with its partner;
- `<tag> AFTER: <status line>` — the status line once the TUI answered, after SIGCONT;
- `<tag> SCREEN:` and the screen while waiting, when anything above is not clean.

Exit 0 = it ran to the end (the caller judges the lines); 1 = the TUI failed (`<tag> RED:
PRODUCT: <what>`, with its screen: no prompt, no answer after SIGCONT) or the driver hung (`HUNG
at <stage>`, `vox_pty.py`); 2 = apparatus, the driver's own machinery only (pyte missing). The TUI
is killed by its PID, with bounded waits.
"""
import os, signal, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, DATA, CFG, IDPASS, TAG, MODE, HOLDER = sys.argv[1:8]
HOLDER = int(HOLDER)
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "300"))
TUI_NOTICE = "another vox is using this profile"
CLI_ONLY = ("vox: waiting", "resume it", "Ctrl-Z")
PAIRS = {"│": "│", "┌": "┐", "└": "┘"}
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")

code = 2
tui = None
resumed = False
try:
    stage("prompt")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)

    def status():
        """The bottom rows, where the TUI's status line is."""
        return " ".join(" ".join(r.split()) for r in tui.display()[-3:])

    want = "create identity" if MODE == "create" else "unlock"
    if not tui.until(lambda: want in tui.text().lower(), 60):
        print(f"{TAG} RED: PRODUCT: the TUI never showed its {want!r} prompt:\n{tui.text()}")
        sys.exit(1)
    tui.pump(1)

    stage("give the passphrase, and wait on the lock")
    tui.key(IDPASS + "\r", 0.5)
    if MODE == "create":
        tui.key(IDPASS + "\r", 0.5)
    t0 = time.time()
    if tui.until(lambda: TUI_NOTICE in status(), 15, step=0.2):
        print(f"{TAG} NOTICE after {time.time() - t0:.2f}: {status()}")
    else:
        print(f"{TAG} NOTICE none: {status()}")
    tui.pump(3)
    screen = tui.display()
    text = "\n".join(r.rstrip() for r in screen)
    stray = any(w in text for w in CLI_ONLY)
    framed, broken = 0, []
    for i, row in enumerate(screen):
        row = row.rstrip()
        if row[:1] in PAIRS:
            framed += 1
            if not row.endswith(PAIRS[row[0]]):
                broken.append(f"row {i}: {row!r}")
    print(f"{TAG} STRAY: {'yes' if stray else 'no'}")
    print(f"{TAG} FRAME: " + (f"ok ({framed} rows)" if not broken else "broken: " + "; ".join(broken)))
    if stray or broken or framed == 0:
        print(f"{TAG} SCREEN:\n{text}")

    stage("resume the holder")
    os.kill(HOLDER, signal.SIGCONT)
    resumed = True
    waiting = status()
    answered = ("another vox created", "done", "unlocked", "holds this profile", "error",
                "wrong", "could not")
    if tui.until(lambda: status() != waiting and any(w in status() for w in answered), 180):
        code = 0
        print(f"{TAG} AFTER: {status()}")
    else:
        code = 1
        print(f"{TAG} RED: PRODUCT: no answer after SIGCONT; the screen:\n{tui.text()}")
    tui.key(":q\r", 1)
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
finally:
    disarm()
    if not resumed:
        try:
            os.kill(HOLDER, signal.SIGCONT)  # never leave the caller's holder stopped
        except ProcessLookupError:
            pass
    if tui is not None and not tui.stop():
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
sys.exit(code)
