#!/usr/bin/env python3
"""Run a `vox` verb at a terminal, typing the identity passphrase at its prompt, as a person does.

A keyring change takes its passphrase from nothing else (ADR-028 K-13): not a file, not
VOX_IDENTITY_PASSPHRASE. The app's screenshot demo and its walkthrough stage trust with this, as
the Rust proofs do with crates/vox-tui/tests/support/typed.rs.

    type-passphrase.py BOUND_SECONDS VOX ARGS... < passphrase-file

The passphrase is the first line of stdin, never in argv or the environment. Everything the
terminal showed is printed; the exit status is vox's (124 if it ran past BOUND_SECONDS and was
killed).
"""
import os
import select
import signal
import sys
import time

bound = float(sys.argv[1])
argv = sys.argv[2:]
secret = sys.stdin.readline().rstrip("\n").encode()
pid, fd = os.forkpty()
if pid == 0:
    os.environ.pop("VOX_IDENTITY_PASSPHRASE", None)
    os.execv(argv[0], argv)
out, sent, deadline, killed = b"", False, time.time() + bound, False
while True:
    if time.time() > deadline and not killed:
        os.kill(pid, signal.SIGKILL)
        killed = True
    r, _, _ = select.select([fd], [], [], 0.2)
    if not r:
        if killed:
            break
        continue
    try:
        d = os.read(fd, 4096)
    except OSError:
        break
    if not d:
        break
    out += d
    if not sent and out.rstrip().endswith(b"passphrase:"):
        time.sleep(0.5)  # as a person reads the prompt: never before its terminal is raw
        os.write(fd, secret + b"\r")
        sent = True
_, st = os.waitpid(pid, 0)
sys.stdout.write(out.decode("utf-8", "replace"))
if killed:
    sys.stdout.write("\ntype-passphrase: killed after %g s\n" % bound)
    sys.exit(124)
sys.exit(os.waitstatus_to_exitcode(st))
