#!/usr/bin/env python3
"""tui_member_names.py <vox> <tag> — #198 (V210-24), the TUI half, through the shipped `vox tui`.

Alice creates a room; Bob and Carol join it, all through real daemons. Bob trusts Alice as
"alice" and does not trust Carol. Bob's daemon is stopped and his real `vox tui` is opened in a
pty (pyte at 160x50). His members pane must name Alice "alice" (not her fingerprint), and Carol by
26 characters of her fingerprint followed by "(not in keyring)", whole. Exit 0 = pass, 1 = red,
2 = apparatus. Every process is recorded and killed by PID.
"""
import fcntl, os, pty, re, select, signal, struct, subprocess, sys, termios, time

VOX, TAG = sys.argv[1], sys.argv[2]
SP = os.environ.get("VOX_PTY_SCRATCH") or __import__("tempfile").mkdtemp(prefix="vox-tui-names-")
PY = os.environ.get("VOX_PYTE_PATH", "")  # where `pyte` is importable from, if not installed
S = f"{SP}/tuin-{TAG}"
subprocess.run(["rm", "-rf", S])
for w in ("anchor", "alice", "bob", "carol"):
    for d in ("data", "cfg"):
        os.makedirs(f"{S}/{w}/{d}")
open(f"{S}/idpass", "w").write("id pass")
PROCS = []
if PY:
    sys.path.insert(0, PY)
try:
    import pyte
except ImportError:
    print(f"{TAG} APPARATUS: pyte is not importable (install it, or set VOX_PYTE_PATH)"); sys.exit(2)

def env(w):
    e = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER") if k in os.environ}
    e.update(VOX_DATA_DIR=f"{S}/{w}/data", VOX_CONFIG_DIR=f"{S}/{w}/cfg", TERM="xterm-256color")
    return e

def run(w, *args, stdin=None):
    return subprocess.run([VOX, *args], env=env(w), input=stdin, capture_output=True, text=True, timeout=120)

def spawn(w, *args, out):
    p = subprocess.Popen([VOX, *args], env=env(w), stdin=subprocess.DEVNULL,
                         stdout=open(f"{S}/{out}.out", "w"), stderr=open(f"{S}/{out}.err", "w"))
    PROCS.append(p)
    return p

def stop(p):
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait()

def until(pred, secs, step=0.5):
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False

def apparatus(why):
    print(f"{TAG} APPARATUS: {why}"); sys.exit(2)

tui_pid = None
code = 2
try:
    anchor = spawn("anchor", "node", "--listen", "127.0.0.1:0", out="anchor")
    spec = None
    def got_spec():
        global spec
        m = re.search(r"[a-z2-7]{52}@/ip4/127\.0\.0\.1/udp/\d+", open(f"{S}/anchor.out").read())
        spec = m.group(0) if m else None
        return spec
    if not until(got_spec, 30): apparatus("anchor spec")
    fp = {}
    for w in ("alice", "bob", "carol"):
        r = run(w, "id", "--identity-passphrase-file", f"{S}/idpass")
        if r.returncode != 0: apparatus(f"{w} id: {r.stderr}")
        fp[w] = re.search(r"[a-z2-7]{52}", r.stdout).group(0)
    daemons = {w: spawn(w, "daemon", "--listen", "127.0.0.1:0", "--anchor", spec,
                        "--passphrase-file", f"{S}/idpass", out=w) for w in ("alice", "bob", "carol")}
    for w in daemons:
        if not until(lambda: run(w, "room", "list").returncode == 0, 60): apparatus(f"{w} daemon")
    if run("alice", "room", "create", "--name", "m", stdin="room pass").returncode != 0: apparatus("create")
    room = run("alice", "room", "list").stdout.split()[0]
    link = run("alice", "room", "invite", room).stdout.strip()
    for w in ("bob", "carol"):
        j = run(w, "room", "join", link, "--name", "m", stdin="room pass")
        if j.returncode != 0: apparatus(f"{w} join: {j.stderr.strip()}")
    t = run("bob", "trust", "add", fp["alice"], "--name", "alice", "--identity-passphrase-file", f"{S}/idpass")
    if t.returncode != 0: apparatus(f"trust add: {t.stderr}")
    # Bob's node must know both members before its TUI is opened.
    def roster():
        r = run("bob", "room", "roster", room)
        return r.returncode == 0 and fp["alice"] in r.stdout and fp["carol"] in r.stdout
    if not until(roster, 90, 1): apparatus("bob never listed both alice and carol: " + run("bob", "room", "roster", room).stdout)
    stop(daemons["bob"])

    tui_pid, fd = pty.fork()
    if tui_pid == 0:
        os.execve(VOX, [VOX, "tui", "--listen", "127.0.0.1:0", "--anchor", spec], env("bob"))
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 160, 0, 0))
    raw = bytearray()
    def pump(secs):
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                try:
                    raw.extend(os.read(fd, 65536))
                except OSError:
                    return
    def key(s, wait=1.0):
        os.write(fd, s.encode()); pump(wait)
    def screen():
        scr = pyte.Screen(160, 50); pyte.ByteStream(scr).feed(bytes(raw))
        return scr.display
    pump(4)
    key("id pass\r", 4)
    key("\r", 2)
    key("room pass\r", 4)
    key("\r", 2)
    key("\t", 1)   # timeline -> composer
    key("\t", 1)   # composer -> members
    # The members pane is the right-hand column; read every row of it from the emulated screen.
    def members():
        rows = []
        for row in screen():
            m = re.search(r"│([^│]*)│?\s*$", row)
            seg = row[100:] if len(row) > 100 else ""
            rows.append(seg)
        return rows
    want_carol = fp["carol"][:26]
    def seen():
        txt = "\n".join(members())
        return "alice" in txt and want_carol in txt
    end = time.time() + 30
    while time.time() < end and not seen():
        pump(1)
    pane = [r.rstrip() for r in members() if r.strip()]
    open(f"{S}/tui.raw", "wb").write(bytes(raw))
    print(f"{TAG} members pane (cols 100+):")
    for r in pane:
        print(f"  |{r}")
    txt = "\n".join(pane)
    alice_ok = re.search(r"(^|[^a-z2-7])alice([^a-z2-7]|$)", txt, re.M) is not None
    alice_fp_shown = fp["alice"][:8] in txt
    carol_row = next((r for r in pane if want_carol in r), None)
    carol_ok = carol_row is not None and "(not in keyring)" in carol_row
    print(f"{TAG} alice named 'alice': {alice_ok}; alice's fingerprint shown: {alice_fp_shown}; "
          f"carol by 26 chars + marker: {carol_ok}")
    code = 0 if (alice_ok and not alice_fp_shown and carol_ok) else 1
    print(f"{TAG} {'PASS' if code == 0 else 'RED'}")
finally:
    if tui_pid:
        try:
            os.kill(tui_pid, signal.SIGTERM); time.sleep(1); os.kill(tui_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(tui_pid, 0)
        except ChildProcessError:
            pass
    for p in PROCS:
        if p.poll() is None:
            stop(p)
sys.exit(code)
