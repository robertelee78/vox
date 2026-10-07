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

def run_hook(path, via=None):
    with open(path, "rb") as f:
        event = f.read()
    # `via` puts another process between the stand-in and its hook, as a script or tool a session
    # runs would be: then the hook's parent is not the harness.
    argv = (via + hook_argv) if via else hook_argv
    p = subprocess.run(argv, input=event, capture_output=True)
    record({"hook": os.path.basename(path), "exit": p.returncode,
            "stdout": p.stdout.decode(errors="replace"), "stderr": p.stderr.decode(errors="replace")[-400:]})

tools = []

def run_hook_via_tool(path):
    # A tool the session runs, still running after it started the hook (as a test runner beneath
    # a person's pane is): the hook's parent is the tool, alive, not the harness.
    done = path + ".done"
    with open(path, "rb") as f:
        event = f.read()
    tool = subprocess.Popen(
        ["/usr/bin/perl", "-e",
         "system(@ARGV); open(my $f, '>', $ENV{HOOK_DONE}); close($f); sleep 600"] + hook_argv,
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=dict(os.environ, HOOK_DONE=done))
    tool.stdin.write(event)
    tool.stdin.close()
    tools.append(tool)
    import time
    for _ in range(200):
        if os.path.exists(done):
            break
        time.sleep(0.1)
    record({"hook": os.path.basename(path), "via": "tool", "tool": tool.pid})

fd = sys.stdin.fileno()
# Outside a terminal (started by the proof itself, not in a pane) there is no tty to set raw.
interactive = os.isatty(fd)
old = termios.tcgetattr(fd) if interactive else None
if interactive:
    tty.setraw(fd)
done = 0
try:
    record({"started": os.getpid()})
    draw()
    while True:
        r, _, _ = select.select([fd] if interactive else [], [], [], 0.1)
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
                for t in tools:
                    t.kill()
                record({"exited": os.getpid()})
                sys.exit(0)
            if line.startswith("hook "):
                run_hook(line[5:])
            if line.startswith("hookvia "):
                run_hook_via_tool(line[8:])
finally:
    for t in tools:
        t.kill()
    if interactive:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
