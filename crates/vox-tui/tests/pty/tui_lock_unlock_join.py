#!/usr/bin/env python3
"""tui_lock_unlock_join.py <vox> <data_dir> <config_dir> <identity_pass> <room_pass> <link> <hold_secs> <stopped_delay_ms> <tag>

Locks and unlocks a profile's node back to back through the shipped `vox tui`, as a person would
(`:lock`, then the passphrase at the prompt), then joins a room through that same node with
`vox room join`, which attaches to the TUI's control socket. V210-80's proof uses it: a lock takes
the network down and the unlock starts a new one, and the old network's "stopped" must not take
the new one with it.

The TUI runs with `VOX_DATA_DIR` and `VOX_CONFIG_DIR` set to the profile given, and with the
test-only `VOX_TEST_STOPPED_DELAY_MS=<stopped_delay_ms>` (the old network says it stopped that
late; see the proof). The join waits `hold_secs` after the lock first, so it runs only once
anything the lock left in flight has landed.

Prints, for the caller to assert on:
  `<tag> locked after <s>s`, `<tag> unlocked again after <s>s` (seconds from the `:lock`),
  `<tag> join ok` or `<tag> join failed: <what vox said>`.

Exit 0 = the steps ran and the join's verdict is printed (whichever it was); 2 = apparatus (pyte
missing, no unlock, no lock, no second unlock); 1 = the driver hung (`HUNG at <stage>`, with its
stack: `vox_pty.py`). The TUI is killed by its PID, with bounded waits.
"""
import os, subprocess, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import DEBUG_EXTRA, Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, DATA, CFG, IDPASS, ROOMPASS, LINK, HOLD, DELAY, TAG = sys.argv[1:10]
HOLD = float(HOLD)
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "240"))
# The join's own wait: 180 s, and a debug build's measured join cost on top (vox_pty.DEBUG_EXTRA).
JOIN_WITHIN = 180 + DEBUG_EXTRA
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")
env["VOX_TEST_STOPPED_DELAY_MS"] = DELAY

code = 2
tui = None
try:
    stage("unlock")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)

    def status():
        """The bottom rows, where the TUI's status bar is: `LOCKED` or `unlocked`."""
        return "\n".join(r.rstrip() for r in tui.display()[-3:])

    tui.pump(3)
    tui.key(IDPASS + "\r", 1)
    # Production Argon2id: the unlock takes seconds.
    if not tui.until(lambda: "unlocked" in status(), 60, 0.1):
        print(f"{TAG} APPARATUS: the TUI never unlocked:\n{tui.text()}")
        sys.exit(2)
    tui.pump(2)

    stage(":lock, then unlock at once")
    t0 = time.time()
    tui.key(":lock\r", 0)
    if not tui.until(lambda: "LOCKED" in status(), 30, 0.05):
        print(f"{TAG} APPARATUS: the TUI never said LOCKED after :lock:\n{tui.text()}")
        sys.exit(2)
    print(f"{TAG} locked after {time.time() - t0:.2f}s", flush=True)
    tui.key(IDPASS + "\r", 0)
    if not tui.until(lambda: "unlocked" in status(), 60, 0.05):
        print(f"{TAG} APPARATUS: the TUI never unlocked again:\n{tui.text()}")
        sys.exit(2)
    print(f"{TAG} unlocked again after {time.time() - t0:.2f}s", flush=True)

    stage("hold")
    tui.until(lambda: False, max(0.0, HOLD - (time.time() - t0)), 0.2)

    stage("join through the unlocked node")
    jenv = dict(env)
    jenv["VOX_IDENTITY_PASSPHRASE"] = IDPASS
    j = subprocess.run(
        [VOX, "room", "join", "--passphrase-file", "-", LINK, "--name", "r"],
        input=ROOMPASS + "\n",
        env=jenv,
        capture_output=True,
        text=True,
        timeout=JOIN_WITHIN,
    )
    tui.pump(0.5)
    if j.returncode == 0:
        print(f"{TAG} join ok", flush=True)
    else:
        said = (j.stderr.strip() or j.stdout.strip()).replace("\n", " | ")
        print(f"{TAG} join failed: {said}", flush=True)
    code = 0
    tui.key(":q\r", 1)
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
except subprocess.TimeoutExpired:
    print(f"{TAG} join failed: vox room join did not answer within {JOIN_WITHIN}s")
    code = 0
finally:
    disarm()
    if tui is not None and not tui.stop():
        # A driver that cannot stop what it started has leaked it, and is how a job hangs (#240).
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
sys.exit(code)
