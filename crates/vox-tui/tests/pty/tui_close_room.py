#!/usr/bin/env python3
"""tui_close_room.py <vox> <data_dir> <config_dir> <identity_pass> <room_pass> <tag>

Closes a profile's only room through the shipped `vox tui`, as a person would: unlock, open the
room, `:close`. It is the one way to close a room on purpose (a daemon reopens every room it held
open), and V210-49's proof needs a room closed across a trust decision.

The TUI runs in a pty at 160x50 and its screen is read through the `pyte` terminal emulator: raw
ANSI cannot be grepped, because the TUI repaints only what changed. The status line is reset with
an unknown command (`:zzz`) first, so "done" afterwards can only be the close's answer.

Exit 0 = the TUI said "done" to `:close`; 2 = apparatus (pyte missing, no unlock, no room, no
"done"). The caller confirms the room is closed on its own, with `vox room list`. The TUI is
killed by its PID.
"""
import fcntl, os, pty, select, signal, struct, sys, termios, time

VOX, DATA, CFG, IDPASS, ROOMPASS, TAG = sys.argv[1:7]
PY = os.environ.get("VOX_PYTE_PATH", "")  # where `pyte` is importable from, if not installed
if PY:
    sys.path.insert(0, PY)
try:
    import pyte
except ImportError:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)")
    sys.exit(2)

env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
env.update(VOX_DATA_DIR=DATA, VOX_CONFIG_DIR=CFG, TERM="xterm-256color")

raw = bytearray()


def pump(fd, secs):
    end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                raw.extend(os.read(fd, 65536))
            except OSError:
                return


def screen():
    scr = pyte.Screen(160, 50)
    pyte.ByteStream(scr).feed(bytes(raw))
    return scr.display


def text():
    return "\n".join(r.rstrip() for r in screen())


def status():
    """The bottom rows, where the TUI's status line is."""
    return "\n".join(r.rstrip() for r in screen()[-3:])


def until(fd, pred, secs):
    end = time.time() + secs
    while time.time() < end:
        pump(fd, 0.5)
        if pred():
            return True
    return False


pid, fd = pty.fork()
if pid == 0:
    os.execve(VOX, [VOX, "tui", "--listen", "127.0.0.1:0"], env)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 160, 0, 0))
code = 2


def key(s, wait=1.0):
    os.write(fd, s.encode())
    pump(fd, wait)


try:
    pump(fd, 3)
    key(IDPASS + "\r", 1)
    # Production Argon2id: the unlock takes seconds. Unlocked, the rooms list names the room.
    if not until(fd, lambda: "unlocked" in status(), 60):
        print(f"{TAG} APPARATUS: the TUI never unlocked:\n{text()}")
        sys.exit(2)
    pump(fd, 3)
    key("\r", 3)  # open the room under the cursor (the profile holds one)
    if "passphrase" in text().lower():
        # Closed on this node: the TUI asks for the room's passphrase to open it.
        key(ROOMPASS + "\r", 6)
    before = text()
    key(":zzz\r", 1.5)
    if "done" in status():
        print(f"{TAG} APPARATUS: the status line still says done after :zzz:\n{text()}")
        sys.exit(2)
    key(":close\r", 1)
    if until(fd, lambda: "done" in status(), 20):
        code = 0
        print(f"{TAG} the TUI said done to :close")
    else:
        print(f"{TAG} APPARATUS: no \"done\" after :close; before it:\n{before}\nafter:\n{text()}")
    key(":q\r", 1)
finally:
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
sys.exit(code)
