"""vox_pty.py — what every pty driver of the shipped `vox tui` shares, bounded (V210-54, #240).

`tui_member_names.py` hung for 40 minutes on the macOS CI runner (run 36397085576) and took the
whole job past its limit, with no word of where. So nothing here waits without a bound, and a
driver that is still running past its budget says which stage it was at and where in the driver
it stood, then cleans up and exits red:

- `arm(secs, tag)` bounds the whole driver. At `secs` (or on SIGTERM, which the Rust wrapper sends
  at its own bound) it prints `<tag> HUNG at <stage>` with the driver's Python stack, and raises
  `Hung` so the driver's `finally` stops every process it started. A `faulthandler` backstop
  dumps the stack and exits outright if even that cannot run.
- `stage(name)` names what the driver is doing, on stderr as it happens, which the Rust wrapper
  passes through live, so a CI log shows how far a driver got even if everything after is lost.
- `Tui` starts `vox tui` on a pty that is **already** `cols`x`rows` when it starts (not resized
  after the fork, which raced the TUI's first read of its size), feeds pyte **only the new bytes**
  (re-feeding the whole history on every look costs more per look the longer the TUI runs), and
  stops it with bounded waits.
"""
import faulthandler, fcntl, os, select, signal, struct, sys, termios, time

PY = os.environ.get("VOX_PYTE_PATH", "")  # where `pyte` is importable from, if not installed
if PY:
    sys.path.insert(0, PY)
try:
    import pyte
except ImportError:
    pyte = None

T0 = time.time()
STAGE = ["start"]


class Hung(Exception):
    """The driver ran past its budget, or was told to stop."""


def stage(name):
    STAGE[0] = name
    print(f"[pty {time.time() - T0:6.1f}s] {name}", file=sys.stderr, flush=True)


def arm(secs, tag):
    """Bound the whole driver to `secs`; see the module docs."""
    def hung(signum, _frame):
        why = "ran past its budget" if signum == signal.SIGALRM else "was told to stop"
        print(f"{tag} HUNG at {STAGE[0]!r}: the driver {why} after {time.time() - T0:.0f}s; "
              "its stack:", file=sys.stderr, flush=True)
        faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
        sys.stderr.flush()
        signal.alarm(0)
        raise Hung(STAGE[0])
    signal.signal(signal.SIGALRM, hung)
    signal.signal(signal.SIGTERM, hung)
    signal.alarm(secs)
    faulthandler.dump_traceback_later(secs + 60, exit=True)


def reap(pid, secs):
    """Wait for `pid` at most `secs`; whether it was reaped."""
    end = time.time() + secs
    while True:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        if done:
            return True
        if time.time() >= end:
            return False
        time.sleep(0.05)


class Tui:
    """`vox tui` in a pty of `cols`x`rows`, its screen read through pyte."""

    def __init__(self, argv, env, rows=50, cols=160):
        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        pid = os.fork()
        if pid == 0:
            try:
                os.close(master)
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                for n in (0, 1, 2):
                    os.dup2(slave, n)
                if slave > 2:
                    os.close(slave)
                os.execve(argv[0], argv, env)
            finally:
                os._exit(127)  # never run the rest of the driver in the child
        os.close(slave)
        self.pid, self.fd = pid, master
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.bytes = 0
        self.closed = False

    def pump(self, secs):
        """Read what the TUI draws for `secs`, feeding it to the screen as it comes."""
        end = time.time() + secs
        while time.time() < end and not self.closed:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if not r:
                continue
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                data = b""
            if not data:
                self.closed = True  # the TUI is gone: nothing more will come
                return
            self.bytes += len(data)
            self.stream.feed(data)

    def key(self, s, wait=1.0):
        os.write(self.fd, s.encode())
        self.pump(wait)

    def display(self):
        return self.screen.display

    def text(self):
        return "\n".join(r.rstrip() for r in self.display())

    def until(self, pred, secs, step=0.5):
        end = time.time() + secs
        while time.time() < end:
            self.pump(step)
            if pred():
                return True
        return False

    def stop(self):
        """SIGTERM, then SIGKILL, each waited for with a bound; whether it was reaped."""
        for sig, secs in ((signal.SIGTERM, 3), (signal.SIGKILL, 5)):
            try:
                os.kill(self.pid, sig)
            except ProcessLookupError:
                return reap(self.pid, 1)
            if reap(self.pid, secs):
                return True
        return False
