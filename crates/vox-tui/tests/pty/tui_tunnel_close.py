#!/usr/bin/env python3
"""tui_tunnel_close.py <vox> <data_dir> <config_dir> <identity_pass> <room_pass> <cue_dir> <tag>

Lists a guest's live tunnels in the shipped `vox tui` and closes the one selected, as a person
would (V030-11). The proof talks to it through files in <cue_dir>:

- this driver unlocks the TUI, opens the profile's room (typing its passphrase) and goes back to
  the channel list, then writes `open`, so the TUI's control socket can carry a forward;
- the proof opens two sessions through a forward of the TUI's node and writes `tunnel`, holding
  the service they go to;
- this driver presses `t`, waits for both tunnels' lines, writes `listed` (the screen), moves the
  selection with Down, presses `x`, waits for that tunnel's line saying it was closed, and writes
  `closed`: the closed tunnel's number on its first line, then the screen. On any RED it writes
  `red` (the screen) instead and exits, so the proof stops before asking the TUI anything more;
- the proof writes `stop`; this driver quits the TUI.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator.

Exit 0 = the TUI listed the tunnel and closed it; 3 = RED, the TUI did not list or close it
(`<tag> RED: …`); 2 = apparatus (pyte missing, no unlock, no room, no cue); 1 = the driver hung
(`HUNG at <stage>`, with its stack: `vox_pty.py`, V210-54). The TUI is killed by its PID, with
bounded waits.
"""
import os, sys, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage, is_attached  # noqa: E402

VOX, DATA, CFG, IDPASS, ROOMPASS, CUE, TAG = sys.argv[1:8]
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "300"))
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

# VOX_MUTANT_V03011 is passed on so a mutant build's TUI runs as the mutant it is (it is unset
# in every real run, and a shipped binary reads no such variable).
env = {
    k: os.environ[k]
    for k in ("PATH", "HOME", "TMPDIR", "USER", "VOX_MUTANT_V03011")
    if k in os.environ
}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")


def cue(name, body=""):
    with open(os.path.join(CUE, name), "w") as f:
        f.write(body or f"{time.time():.3f}")


def wait_cue(tui, name, secs):
    return tui.until(lambda: os.path.exists(os.path.join(CUE, name)), secs, 0.1)


code = 2
tui = None
try:
    stage("unlock")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)

    def status():
        """The bottom rows, where the TUI's status line is."""
        return "\n".join(r.rstrip() for r in tui.display()[-3:])

    tui.pump(3)
    tui.key(IDPASS + "\r", 1)
    # Production Argon2id: the unlock takes seconds.
    if not tui.until(lambda: is_attached(status()), 60):
        print(f"{TAG} APPARATUS: the TUI never unlocked:\n{tui.text()}")
        sys.exit(2)
    stage("open the room")
    tui.pump(3)
    tui.key("\r", 3)  # open the room under the cursor (the profile holds one)
    if "passphrase" in tui.text().lower():
        # Closed on this node: the TUI asks for the room's passphrase to open it.
        tui.key(ROOMPASS + "\r", 6)
    tui.key("\x1b", 1)  # back to the channel list
    cue("open")
    stage("wait for the tunnel cue")
    if not wait_cue(tui, "tunnel", 240):
        print(f"{TAG} APPARATUS: no tunnel cue")
        sys.exit(2)
    with open(os.path.join(CUE, "tunnel")) as f:
        service = f.read().strip()
    line = f"for {service}: open"
    import re
    def live_rows():
        """The live tunnel rows to `service`: (number, selected?) in the order drawn."""
        rows = []
        for r in tui.display():
            m = re.search(r"(▶ |  )tunnel (\d+) \S+ \S+ " + re.escape(line), r)
            if m:
                rows.append((int(m.group(2)), m.group(1) == "▶ "))
        return rows
    stage("list the tunnels")
    tui.key("t", 1)
    # The proof opens two sessions to the service, so the close below has one to leave alone.
    if not tui.until(lambda: len(live_rows()) >= 2, 20, 0.25):
        cue("red", tui.text())
        print(f"{TAG} RED: the TUI's tunnel list never showed two tunnels {line!r}:\n{tui.text()}")
        code = 3
        sys.exit(3)
    cue("listed", tui.text())
    stage("move the selection and close it")
    before = [n for n, sel in live_rows() if sel]
    tui.key("\x1b[B", 0.5)  # Down: the selection moves off the one the list opened on
    after = [n for n, sel in live_rows() if sel]
    if len(after) != 1 or after == before:
        cue("red", tui.text())
        print(f"{TAG} RED: Down did not move the selection to another tunnel (selected before "
              f"{before}, after {after}):\n{tui.text()}")
        code = 3
        sys.exit(3)
    chosen = after[0]
    tui.key("x", 1)
    said = f"tunnel {chosen} "
    gone = "was closed by a person in the TUI"
    if not tui.until(lambda: any(said in r and gone in r for r in tui.display()), 20, 0.25):
        cue("red", f"{chosen}\n{tui.text()}")
        print(f"{TAG} RED: after `x`, the TUI never said tunnel {chosen} {gone!r}:\n{tui.text()}")
        code = 3
        sys.exit(3)
    cue("closed", f"{chosen}\n{tui.text()}")
    stage("wait for the stop cue")
    if not wait_cue(tui, "stop", 180):
        print(f"{TAG} APPARATUS: no stop cue")
        sys.exit(2)
    code = 0
    print(f"{TAG} PASS: the TUI listed two tunnels, and closed the one selected with Down")
    tui.key(":q\r", 1)
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
