#!/usr/bin/env python3
"""tui_attach_for_scan.py <vox> <data_dir> <config_dir> <identity_pass> <cue_dir> <tag> [K=V ...]

Runs the shipped `vox tui` as a person does, a client of the account's daemon (ADR-026 S-4), with
the environment the proof names (each K=V), and gives its node's passphrase at the prompt that
attaches it (V210-94, ADR-026 N-2). The proof talks to it through files in <cue_dir>:

- this driver writes `pid` (the TUI's process id) once the TUI runs, then types the identity
  passphrase at its "Attach node" prompt, and writes `attached` once the TUI's status bar names its
  node attached;
- the proof may write `hup`: this driver then sends the TUI SIGHUP, which stops it cleanly and
  does nothing to its node (S-4), and writes `gone` once the TUI has exited;
- the proof writes `stop`; this driver quits the TUI (`q`) if it still runs.

`VOX_PTY_DYLD_INSERT=<path>` among the K=V becomes the TUI's `DYLD_INSERT_LIBRARIES`: named
otherwise so that no protected binary on the way (a system Python) drops it.

Exit 0 = the TUI started, did what it was cued to and was stopped; 1 = the TUI failed (`<tag> RED:
PRODUCT: …`, with its screen) or the driver hung (`HUNG at <stage>`, with its stack:
`vox_pty.py`, V210-54); 2 = apparatus, the driver's own machinery only (pyte missing, no cue from
the proof). The TUI is killed by its PID, with bounded waits.
"""
import os, signal, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, is_attached, pyte, stage  # noqa: E402

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

    stage("the attach prompt")
    if not tui.until(lambda: tui.closed or "Attach node" in tui.text(), 60, 0.1):
        print(f"{TAG} RED: PRODUCT: the TUI never asked for its node's passphrase:\n{tui.text()}")
        code = 1
        sys.exit(code)
    tui.key(IDPASS + "\r", 0.2)
    stage("wait for a cue")
    said_attached = False
    end = time.time() + 240
    while not (has_cue("hup") or has_cue("stop")):
        if time.time() >= end:
            print(f"{TAG} APPARATUS: no cue:\n{tui.text()}")
            sys.exit(2)
        tui.pump(0.1)
        if not said_attached and is_attached(bottom()):
            cue("attached")
            said_attached = True
    if has_cue("hup"):
        stage("SIGHUP")
        os.kill(tui.pid, signal.SIGHUP)
        if not tui.until(lambda: tui.closed, 30, 0.1):
            print(f"{TAG} RED: PRODUCT: the TUI did not stop on SIGHUP:\n{tui.text()}")
            code = 1
            sys.exit(code)
        cue("gone")
    stage("wait for the stop cue")
    if not tui.until(lambda: has_cue("stop"), 240, 0.2):
        print(f"{TAG} APPARATUS: no stop cue")
        sys.exit(2)
    if not tui.closed:
        tui.key("q", 1)
    code = 0
    print(f"{TAG} PASS: the TUI did what it was cued to")
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
