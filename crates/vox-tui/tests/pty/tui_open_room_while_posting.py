#!/usr/bin/env python3
"""tui_open_room_while_posting.py <vox> <data_dir> <config_dir> <identity_pass> <room_pass>
<post_room> <open_room> <tag>

Opens a closed room with its passphrase through the shipped `vox tui`, as a person does (Enter on
the closed room, the masked prompt, the passphrase), while posting to another room of the same
node through its control socket (`vox room post`, which attaches to the TUI's socket as an agent
session does). V210-71's finding 3: the open's unwrap (production Argon2id) and its re-verify of
the room's log ran on the node's actor, so every other room's posts waited for it.

It prints, for the caller to judge (nothing is asserted here):
- `<tag> POST <start> <latency_ms> <ok>` for every post, `start` in seconds since the driver began;
- `<tag> OPEN <start> <end>`: from the passphrase's Enter to the first `vox room read <open_room>`
  that succeeded (the room is open on the node).

Exit 0 = staged and measured; 1 = the product's red (`RED: PRODUCT (staging):` the TUI never
unlocked, the post room never answered through its socket, the closed room was already open, no
room asked for its passphrase, or the room never opened), or the driver hung (`vox_pty.py`);
2 = apparatus (pyte missing). The TUI is killed by its PID, with bounded waits; every `vox` it
runs is bounded too.
"""
import os, subprocess, sys, threading, time

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vox_pty import Hung, Tui, arm, disarm, pyte, stage  # noqa: E402

VOX, DATA, CFG, IDPASS, ROOMPASS, POST_ROOM, OPEN_ROOM, TAG = sys.argv[1:9]
BUDGET = int(os.environ.get("VOX_PTY_BUDGET_SECS", "300"))
# Posts are made this often, before, during and after the open.
EVERY = 0.15
# Posting runs this long before the open starts, and this long after it ended.
AROUND = 2.0
# The open must finish within this, or it is reported as never opening.
OPEN_CAP = 90.0
if pyte is None:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)
arm(BUDGET, TAG)

T0 = time.time()
env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")


def vox(*argv, cap=60):
    """A one-shot `vox` against this profile (so, the TUI's socket); (ok, seconds)."""
    t = time.time()
    try:
        r = subprocess.run([VOX, *argv], env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=cap)
        return r.returncode == 0, time.time() - t
    except subprocess.TimeoutExpired:
        return False, time.time() - t


posting = threading.Event()
posts = []


def poster():
    n = 0
    while posting.is_set():
        n += 1
        start = time.time() - T0
        ok, took = vox("room", "post", POST_ROOM, f"post while opening {n}")
        posts.append((start, took * 1000.0, ok))
        time.sleep(max(0.0, EVERY - took))


code = 2
tui = None
worker = None
try:
    stage("unlock")
    tui = Tui([VOX, "tui", "--listen", "127.0.0.1:0"], env)

    def status():
        return "\n".join(r.rstrip() for r in tui.display()[-3:])

    tui.pump(3)
    tui.key(IDPASS + "\r", 1)
    if not tui.until(lambda: "unlocked" in status(), 90):
        print(f"{TAG} RED: PRODUCT (staging): the TUI never unlocked within 90 s:\n{tui.text()}")
        sys.exit(1)
    stage("the post room answers through the TUI's socket")
    end = time.time() + 60
    while not vox("room", "read", POST_ROOM, cap=20)[0]:
        if time.time() > end:
            print(f"{TAG} RED: PRODUCT (staging): `vox room read {POST_ROOM}` never answered "
                  "through the TUI's socket within 60 s")
            sys.exit(1)
        tui.pump(0.5)
    if vox("room", "read", OPEN_ROOM, cap=20)[0]:
        print(f"{TAG} RED: PRODUCT (staging): {OPEN_ROOM}, closed on purpose, was opened by "
              "the unlock on its own")
        sys.exit(1)

    stage("post before the open")
    posting.set()
    worker = threading.Thread(target=poster, daemon=True)
    worker.start()
    tui.pump(AROUND)

    stage("find the closed room")
    prompted = False
    for _ in range(8):
        tui.key("\r", 1.5)
        if "passphrase" in tui.text().lower():
            prompted = True
            break
        tui.key("\x1b", 0.8)  # back to the list from an open room
        tui.key("\x1b[B", 0.8)  # down
    if not prompted:
        print(f"{TAG} RED: PRODUCT (staging): Enter on each room in the list, closed one "
              f"included, never asked for a passphrase:\n{tui.text()}")
        sys.exit(1)

    stage("open it")
    for c in ROOMPASS:
        tui.key(c, 0.02)
    open_start = time.time() - T0
    os.write(tui.fd, b"\r")
    open_end = None
    deadline = time.time() + OPEN_CAP
    while time.time() < deadline:
        tui.pump(0.05)
        if vox("room", "read", OPEN_ROOM, cap=OPEN_CAP)[0]:
            open_end = time.time() - T0
            break
    if open_end is None:
        print(f"{TAG} RED: PRODUCT (staging): {OPEN_ROOM} never opened within {OPEN_CAP}s of "
              f"its passphrase:\n{tui.text()}")
        sys.exit(1)

    stage("post after the open")
    tui.pump(AROUND)
    posting.clear()
    worker.join(timeout=70)
    for start, ms, ok in posts:
        print(f"{TAG} POST {start:.3f} {ms:.1f} {int(ok)}")
    print(f"{TAG} OPEN {open_start:.3f} {open_end:.3f}")
    print(f"{TAG} PASS staged and measured (the caller judges the numbers)")
    code = 0
    tui.key(":q\r", 1)
except Hung as h:
    print(f"{TAG} HUNG at {h}")
    code = 1
finally:
    disarm()
    posting.clear()
    if tui is not None and not tui.stop():
        print(f"{TAG} RED: vox tui (pid {tui.pid}) outlived SIGKILL and could not be reaped")
        code = 1
sys.exit(code)
