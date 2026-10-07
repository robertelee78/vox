#!/usr/bin/env python3
"""Apparatus: a stand-in for Claude Code in a tmux pane (ADR-029 DR-1, DR-5 proofs).

It draws what the injector reads, Claude Code's input box between two horizontal rules, and
records every key it receives, one JSON line each, in --log:
  {"typed": "<text submitted with Enter>"}   a line, slash commands included
  {"key": "Escape"} / {"key": "C-c"}         those keys alone

It runs the session's hook as Claude Code does, as its own child, so the hook's ancestry is this
process's: the proof writes a JSON hook event to a file and names it on a line of --control
("hook <path>"); "exit" ends the stand-in. Nothing here is product.
"""
import argparse, json, os, select, subprocess, sys, termios, tty

ap = argparse.ArgumentParser()
ap.add_argument("--log", required=True)
ap.add_argument("--control", required=True)
ap.add_argument("--hook", required=True, help="the hook command, as JSON argv")
args = ap.parse_args()
hook_argv = json.loads(args.hook)

RULE = "─" * 60
buf = ""

def record(obj):
    with open(args.log, "a") as f:
        f.write(json.dumps(obj) + "\n")

def draw():
    sys.stdout.write("\x1b[2J\x1b[H")
    # Raw mode: a line feed alone does not return the cursor.
    sys.stdout.write("stand-in Claude Code\r\n\r\n" + RULE + "\r\n❯ " + buf + "\r\n" + RULE + "\r\n")
    sys.stdout.flush()

def run_hook(path):
    with open(path, "rb") as f:
        event = f.read()
    p = subprocess.run(hook_argv, input=event, capture_output=True)
    record({"hook": os.path.basename(path), "exit": p.returncode,
            "stdout": p.stdout.decode(errors="replace"), "stderr": p.stderr.decode(errors="replace")[-400:]})

fd = sys.stdin.fileno()
old = termios.tcgetattr(fd)
tty.setraw(fd)
done = 0
try:
    record({"started": os.getpid()})
    draw()
    while True:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            data = os.read(fd, 4096).decode(errors="replace")
            for ch in data:
                if ch == "\r":
                    record({"typed": buf})
                    buf = ""
                elif ch == "\x1b":
                    record({"key": "Escape"})
                elif ch == "\x03":
                    record({"key": "C-c"})
                elif ch in ("\x7f", "\x08"):
                    buf = buf[:-1]
                elif ch >= " ":
                    buf += ch
            draw()
        try:
            with open(args.control) as f:
                lines = f.read().splitlines()
        except FileNotFoundError:
            lines = []
        for line in lines[done:]:
            done += 1
            if line == "exit":
                record({"exited": os.getpid()})
                sys.exit(0)
            if line.startswith("hook "):
                run_hook(line[5:])
finally:
    termios.tcsetattr(fd, termios.TCSADRAIN, old)
