#!/usr/bin/env python3
"""tui_lock_for_scan.py <vox> <data_dir> <config_dir> <identity_pass> <cue_dir> <tag> [K=V ...]

Runs the shipped `vox tui` as a person does, with the environment the proof names (each K=V), and
locks it with `:lock` when the proof says so (V210-94). The proof talks to it through files in
<cue_dir>:

- this driver writes `pid` (the TUI's process id) once the TUI runs, then types the identity
  passphrase, and writes `unlocked` if the TUI shows itself unlocked;
- the proof writes `lock`, holding `key` or `hup`; this driver then types `:lock`, or sends the
  TUI SIGHUP (which locks it, ADR-015), and writes `locked` once the TUI shows itself locked:
  LOCKED on its status bar, with an empty passphrase prompt. The node publishes a locked view only
  once the lock is done, and a TUI still waiting on its unlock (a SIGHUP while rooms reopen) shows
  the prompt it was typed into, dots and all, until the node answers it. The cue holds
  `said-locking` if the TUI showed "locking…" while it waited, else `silent`, then how many
  seconds it waited;
- the proof writes `stop`; this driver quits the TUI.

`VOX_PTY_DYLD_INSERT=<path>` among the K=V becomes the TUI's `DYLD_INSERT_LIBRARIES`: named
otherwise so that no protected binary on the way (a system Python) drops it.

Exit 0 = the TUI started, locked on cue and was stopped; 1 = the TUI never said locked (`<tag>
RED: PRODUCT: …`, with its screen) or the driver hung (`HUNG at <stage>`, with its stack:
`vox_pty.py`, V210-54); 2 = apparatus, the driver's own machinery only (pyte missing, no cue from
the proof). The
TUI is killed by its PID, with bounded waits.
"""
import os, signal, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage, is_attached  # noqa: E402

VOX, DATA, CFG, IDPASS, CUE, TAG = sys.argv[1:7]
EXTRA = dict(kv.split("=", 1) for kv in sys.argv[7:])
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "300"))
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")
insert = EXTRA.pop("VOX_PTY_DYLD_INSERT", None)
if insert:
    env["DYLD_INSERT_LIBRARIES"] = insert
env.update(EXTRA)


def cue(name, text=None):
    # Written beside and renamed into place, so the proof never reads a cue half written.
    path = os.path.join(CUE, name)
    with open(path + ".tmp", "w") as f:
        f.write(text if text is not None else f"{time.time():.3f}")
    os.rename(path + ".tmp", path)


def has_cue(name):
    return os.path.exists(os.path.join(CUE, name))


code = 2
tui = None
try:
    stage("start")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)
    cue("pid", str(tui.pid))

    def bottom():
        """The bottom rows: the status bar and the line a command's answer is shown on."""
        return "\n".join(r.rstrip() for r in tui.display()[-3:])

    tui.pump(3)
    stage("unlock")
    tui.key(IDPASS + "\r", 0.5)
    stage("wait for the lock cue")
    said_unlocked = False
    end = time.time() + 240
    while not has_cue("lock"):
        if has_cue("stop"):
            print(f"{TAG} APPARATUS: stopped before the lock cue; the screen:\n{tui.text()}")
            sys.exit(2)
        if time.time() >= end:
            print(f"{TAG} APPARATUS: no lock cue:\n{tui.text()}")
            sys.exit(2)
        tui.pump(0.1)
        if not said_unlocked and is_attached(bottom()):
            cue("unlocked")
            said_unlocked = True
    with open(os.path.join(CUE, "lock")) as f:
        how = f.read().strip()
    if how == "hup":
        stage("SIGHUP")
        os.kill(tui.pid, signal.SIGHUP)
    else:
        stage(":lock")
        tui.key(":lock\r", 0.05)
    said_locking = []
    asked = time.time()

    def locked_now():
        b = bottom()
        if "locking\u2026" in b and not said_locking:
            said_locking.append(True)
        return "LOCKED" in b and "\u2022" not in b

    if not tui.until(locked_now, 120, 0.05):
        print(f"{TAG} RED: PRODUCT: the TUI never showed itself locked ({how}):\n{tui.text()}")
        sys.exit(1)
    # Whether the TUI said "locking…" while it waited: the proof checks it for a typed `:lock`.
    waited = time.time() - asked
    cue("locked", f"{'said-locking' if said_locking else 'silent'} {waited:.3f}")
    stage("wait for the stop cue")
    if not tui.until(lambda: has_cue("stop"), 240, 0.2):
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
