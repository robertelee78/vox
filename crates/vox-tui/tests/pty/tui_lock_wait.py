#!/usr/bin/env python3
"""tui_lock_wait.py <vox> <data_dir> <config_dir> <identity_pass> <tag> <create|startup> <holder_pid>

A `vox tui` that has to wait for another vox holding the profile's lock, as a person would meet
it: the holder (started by the caller, which has stopped it with SIGSTOP while it holds the lock)
is in the middle of creating the identity, or of migrating a v0.2.9 profile.
- `create`: the profile has no identity yet, so the TUI starts, and waits on the lock when it is
  given a passphrase at its first-run "Create identity" prompt; that wait is said in its status line.
- `startup`: the profile has one, and the holder has it open, so the TUI waits when it opens the
  profile — before it takes the screen — and says so as a CLI verb does; once the holder is
  resumed and done, the TUI starts and is given the passphrase at its "Unlock" prompt. Its screen is read while it waits, then the holder is resumed with
SIGCONT (by the PID the caller recorded), and what the TUI says afterwards is read too.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator.

Prints, each on its own line:
- `<tag> NOTICE after <secs>: <status line>` — the status line once it said it is waiting, or
  `<tag> NOTICE none: <status line>` if it never did within 15 s;
- `<tag> STRAY: no`, or `<tag> STRAY: yes: <rows>` quoting every screen row that holds a CLI-only
  line ("vox: waiting …", "resume it"), which is stderr written into the TUI;
- `<tag> FRAME: ok (<n> rows)` or `<tag> FRAME: broken: <rows>` — every row that starts a box
  border (`│`, `┌`, `└`) ends with its partner;
- `<tag> AFTER: <status line>` — the status line once the TUI answered, after SIGCONT;
- `<tag> SCREEN:` and the screen while waiting, when anything above is not clean.

Exit 0 = it ran to the end (the caller judges the lines); 1 = the TUI failed (`<tag> RED:
PRODUCT: <what>`, with its screen: no prompt, no answer to the unlock or after SIGCONT) or the driver hung (`HUNG
at <stage>`, `vox_pty.py`); 2 = apparatus, the driver's own machinery only (pyte missing). The TUI
is killed by its PID, with bounded waits.
"""
import os, signal, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, is_attached, pyte, stage  # noqa: E402

VOX, DATA, CFG, IDPASS, TAG, MODE, HOLDER = sys.argv[1:8]
HOLDER = int(HOLDER)
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "300"))
TUI_NOTICE = "waiting: another vox holds this profile open"
CLI_ONLY = ("vox: waiting", "resume it", "Ctrl-Z")
# What `vox tui` says on the terminal, before it takes the screen, while the daemon has not greeted
# it (ADR-026: the daemon is moving or attaching the node).
CLI_WAITING = "vox: waiting: the vox daemon here has not answered yet"
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


def check_screen():
    """STRAY and FRAME lines for the screen as it is now."""
    screen = tui.display()
    text = "\n".join(r.rstrip() for r in screen)
    stray_rows = [r.strip() for r in text.splitlines() if any(w in r for w in CLI_ONLY)]
    framed, broken = 0, []
    for i, row in enumerate(screen):
        row = row.rstrip()
        if row[:1] in PAIRS:
            framed += 1
            if not row.endswith(PAIRS[row[0]]):
                broken.append(f"row {i}: {row!r}")
    print(f"{TAG} STRAY: " + ("yes: " + " | ".join(stray_rows) if stray_rows else "no"))
    print(f"{TAG} FRAME: " + (f"ok ({framed} rows)" if not broken else "broken: " + "; ".join(broken)))
    if stray_rows or broken or framed == 0:
        print(f"{TAG} SCREEN:\n{text}")


def resume():
    global resumed
    os.kill(HOLDER, signal.SIGCONT)
    resumed = True


try:
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)

    def status():
        """The bottom rows, where the TUI's status line is."""
        return " ".join(" ".join(r.split()) for r in tui.display()[-3:])

    answered = ("another vox created", "done", "unlocked", "holds this profile", "error",
                "wrong", "could not")
    if MODE == "startup":
        # The holder is the daemon, stopped while it moves and attaches the node: the TUI waits for
        # its greeting at its start, before it takes the screen, and says so as a CLI verb does, on
        # the terminal.
        stage("wait at start-up")
        t0 = time.time()
        if tui.until(lambda: CLI_WAITING in tui.text(), 15, step=0.2):
            print(f"{TAG} NOTICE after {time.time() - t0:.2f}: (before the TUI started) "
                  + " ".join(l.strip() for l in tui.text().splitlines() if CLI_WAITING in l))
        else:
            print(f"{TAG} NOTICE none: {tui.text().strip()[:300]}")
        stage("resume the holder")
        resume()
        # Its node attached by the daemon already, or attaching: the TUI uses it, or asks for its
        # passphrase once (ADR-026 N-2).
        if not tui.until(lambda: "attach node" in tui.text().lower() or is_attached(status()), 120):
            print(f"{TAG} RED: PRODUCT: the TUI never showed its node, nor asked to attach it:\n"
                  f"{tui.text()}")
            sys.exit(1)
        tui.pump(1)
        check_screen()
        if "attach node" in tui.text().lower():
            stage("attach")
            tui.key(IDPASS + "\r", 0.5)
        if tui.until(lambda: is_attached(status()), 180):
            code = 0
            print(f"{TAG} AFTER: {status()}")
        else:
            code = 1
            print(f"{TAG} RED: PRODUCT: its node never showed attached; the screen:\n{tui.text()}")
    else:
        stage("prompt")
        if not tui.until(lambda: "create identity" in tui.text().lower(), 60):
            print(f"{TAG} RED: PRODUCT: the TUI never showed its create prompt:\n{tui.text()}")
            sys.exit(1)
        tui.pump(1)
        stage("give the passphrase, and wait on the lock")
        tui.key(IDPASS + "\r", 0.5)
        tui.key(IDPASS + "\r", 0.5)
        t0 = time.time()
        if tui.until(lambda: TUI_NOTICE in status(), 15, step=0.2):
            print(f"{TAG} NOTICE after {time.time() - t0:.2f}: {status()}")
        else:
            print(f"{TAG} NOTICE none: {status()}")
        tui.pump(3)
        check_screen()
        stage("resume the holder")
        resume()
        waiting = status()
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
