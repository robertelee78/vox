"""A harness's interactive terminal UI, under a pty, driven a line at a time (apparatus).

    python3 live_tui.py <screen log> <program> [args…]

Starts the program on a pty in the environment and directory it was given, keeps everything it
draws in <screen log> (raw bytes), answers its cursor-position queries as a terminal does, and
reads one command per line on stdin, answering each with one JSON line on stdout:

    type <text>        the text, typed (no Enter)                       {"ok": true}
    key <name>         one key: enter, esc, ctrl-c                      {"ok": true}
    wait <secs> <re>   until what it drew (escape codes taken out)      {"found": bool}
                       matches the regular expression <re>
    quit               close the pty and stop the program               {"code": N}

**Never a login or trust screen.** Whenever what it drew looks like one (a sign-in, an API key, a
"do you trust this folder"), every later command answers {"login": "<what it saw>"} and types
nothing: the proof stops and says APPARATUS. Nothing here ever answers such a screen.
"""

import json
import os
import pty
import re
import select
import signal
import sys
import time

LOGIN = re.compile(
    r"(sign in with|log in with|login with|api key|enter your api|paste your|"
    r"do you trust|trust this folder|trust the files)",
    re.IGNORECASE,
)
ANSI = re.compile(
    rb"\x1b\[[0-9;?<>=]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[78=>DEHMNOZc]"
)
KEYS = {"enter": b"\r", "esc": b"\x1b", "ctrl-c": b"\x03"}


def say(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    log_path, argv = sys.argv[1], sys.argv[2:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    log = open(log_path, "ab")
    drawn = bytearray()
    login = [None]

    def pump(secs):
        end = time.time() + secs
        while True:
            left = end - time.time()
            r, _, _ = select.select([fd], [], [], max(0.0, min(0.2, left)))
            if r:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    return False
                if not data:
                    return False
                log.write(data)
                log.flush()
                drawn.extend(data)
                if b"\x1b[6n" in data:
                    os.write(fd, b"\x1b[1;1R")
                text = ANSI.sub(b"", bytes(drawn[-20000:])).decode("utf-8", "replace")
                m = LOGIN.search(text)
                if m and not login[0]:
                    login[0] = m.group(0)
            if left <= 0:
                return True

    pump(2)
    for line in sys.stdin:
        cmd, _, arg = line.rstrip("\n").partition(" ")
        pump(0.2)
        if login[0] and cmd != "quit":
            say({"login": login[0]})
            continue
        try:
            if cmd == "type":
                for ch in arg:
                    os.write(fd, ch.encode())
                    pump(0.01)
                say({"ok": True})
            elif cmd == "key":
                os.write(fd, KEYS[arg])
                pump(0.3)
                say({"ok": True})
            elif cmd == "wait":
                secs, _, pattern = arg.partition(" ")
                rx = re.compile(pattern)
                end = time.time() + float(secs)
                found = False
                while time.time() < end and not login[0]:
                    # A terminal UI moves the cursor where a space would be, so what it drew is
                    # read twice: escape codes taken out, and escape codes read as a space.
                    raw = bytes(drawn)
                    text = ANSI.sub(b"", raw).decode("utf-8", "replace")
                    spaced = ANSI.sub(b" ", raw).decode("utf-8", "replace")
                    # And with every space taken out: a UI that draws a character at a time (Codex
                    # saves and restores the cursor around each) leaves no words to read.
                    squeezed = re.sub(r"\s+", "", text)
                    if rx.search(text) or rx.search(spaced) or rx.search(squeezed):
                        found = True
                        break
                    if not pump(0.5):
                        break
                say({"login": login[0]} if login[0] and not found else {"found": found})
            elif cmd == "quit":
                break
            else:
                say({"error": "unknown command " + cmd})
        except OSError as e:
            say({"error": str(e)})
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    end = time.time() + 5
    code = None
    while time.time() < end:
        pump(0.2)
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            code = os.waitstatus_to_exitcode(st)
            break
    if code is None:
        try:
            os.kill(pid, signal.SIGKILL)
            _, st = os.waitpid(pid, 0)
            code = os.waitstatus_to_exitcode(st)
        except ChildProcessError:
            pass
    say({"code": code})


if __name__ == "__main__":
    main()
