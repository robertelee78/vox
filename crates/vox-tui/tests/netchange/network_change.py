#!/usr/bin/env python3
"""network_change.py <vox> — ADR-012 N-49–N-52 (#413, #414), through the shipped `vox`.

A move to another network, staged as a real interface change the operating system says, and two
daemons that live through it:

  D, the daemon whose network changes: listens on every address (0.0.0.0), and advertises its
     routable address A = 10.77.0.2, the one the operating system routes by;
  P, its peer: listens on 10.99.0.2 alone, which the change leaves as it was. A socket bound there
     cannot send to loopback, so P dials D at A.

D makes a room, P joins it by the invite link (it dials D at A, so D's connection to P is one D
accepted at A), they trust each other, and P reads a post of D's. Then the machine gains address
B = 10.88.0.2, routes by it, and loses A: a move to another network. Each claim prints one
`CLAIM <name> ok|RED` line:

  said       D's log says the change exactly once, within 1 s of it (N-49, N-50, N-52);
  status     D's `vox status --json` names the change, and lists B and not A among the addresses it
             listens on, within 2 s (N-51, N-52);
  redial     with nothing sent by either, D holds a new connection to P within 3 s: it found the
             connection it accepted stranded, closed it and dialled P again (N-51);
  reads      P reads a post D sends after that within 5 s of the change, not after
             SILENCE_IS_DEATH (30 s);
  router     (Linux) before the move, the default route alone changes its next hop, no address
             coming or going: D says that one change, naming the route, within 1 s (N-50, N-53).
             The macOS form does not stage it: it would have to change the machine's own
             default route; there the next hop is read by the reader `vox status` is proved
             against (`vox_status_names_the_router_proof`).

The staging forces what `reads` is about: P can reach D only at A, so the move strands the
connection D accepted. D's log line for it (`accepted here) did not answer a probe after the
network changed`) is printed with the claim.

**Linux** (the proof): inside an unprivileged user and network namespace (`unshare --user
--map-current-user --keep-caps --net`, which this script enters itself), whose own interfaces are
the machine's network: A on dummy d0 with the default route, B on d1, P's address on d2; the move
is one `ip -batch`. Nothing outside the namespace is touched and no privilege is needed.

**macOS** (opt-in heavy, the operator runs it): the addresses are aliases on `lo0`, and the
operating system routes by A because a host route to 192.0.2.1 (TEST-NET-1, the address
`local_route_ips` asks the route to) goes through A; the move adds B, points that route at B and
removes A. Every change is made with `sudo` (the operator's prompt; run `sudo -v` first) and
undone at the end. The machine's own default route and real interfaces are never touched. `vox`
itself runs as the operator, never as root: a daemon refuses a control connection from uid 0.

Exit 0 = pass, 1 = red, 2 = apparatus or CANNOT MEASURE. A `vox` step that fails is the product's
red: `PRODUCT (staging):` before the move (the scene was not reached, and what vox said is quoted),
`PRODUCT:` after it. Every process is recorded and stopped by PID.
"""
import json, os, re, subprocess, sys, tempfile, threading, time, traceback

VOX = os.path.abspath(sys.argv[1])
LINUX = sys.platform.startswith("linux")
if LINUX and os.environ.get("VOX_NETNS_INSIDE") != "1":
    # Whether the namespace was entered at all: a host that refuses unprivileged user namespaces
    # (an AppArmor restriction, say) is the apparatus failing, not the product.
    entered = tempfile.mktemp(prefix="vox-netchange-entered-")
    env = dict(os.environ, VOX_NETNS_INSIDE="1", VOX_NETNS_ENTERED=entered)
    try:
        # The caller's own uid, not root: a daemon refuses a control connection from uid 0. The
        # namespace's capabilities are kept as ambient ones, so `ip` can change its network.
        r = subprocess.run(["unshare", "--user", "--map-current-user", "--keep-caps", "--net",
                            sys.executable, __file__, VOX], env=env)
    except FileNotFoundError:
        print("netchange APPARATUS: unshare is not installed"); sys.exit(2)
    if not os.path.exists(entered):
        print("netchange APPARATUS, CANNOT MEASURE: this host refused an unprivileged user and "
              "network namespace (`unshare --user --net`)")
        sys.exit(2)
    os.remove(entered)
    sys.exit(r.returncode)
if LINUX:
    open(os.environ["VOX_NETNS_ENTERED"], "w").close()

TAG = "netchange"
S = tempfile.mkdtemp(prefix="vox-netchange-")
MOVED = False  # set at the move: a product red before it is one of the staging's steps
PROCS = []
code = 2
results = {}

def claim(name, ok, detail):
    results[name] = ok
    print(f"{TAG} CLAIM {name} {'ok' if ok else 'RED'}: {detail}", flush=True)

class Apparatus(Exception): pass
class Product(Exception): pass

def sh(*cmd):
    r = subprocess.run(list(cmd), capture_output=True, text=True)
    if r.returncode != 0:
        raise Apparatus(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r.stdout

def setup():
    """The network before the move: A routed by, P's address beside it, nothing else changed."""
    if LINUX:
        for cmd in (["link", "set", "lo", "up"],
                    ["link", "add", "d0", "type", "dummy"],
                    ["addr", "add", "10.77.0.2/24", "dev", "d0"],
                    ["link", "set", "d0", "up"],
                    ["route", "add", "default", "via", "10.77.0.1", "dev", "d0"],
                    ["link", "add", "d1", "type", "dummy"],
                    ["link", "set", "d1", "up"],
                    ["link", "add", "d2", "type", "dummy"],
                    ["addr", "add", "10.99.0.2/24", "dev", "d2"],
                    ["link", "set", "d2", "up"]):
            sh("ip", *cmd)
    else:
        UNDO.append(["sudo", "ifconfig", "lo0", "-alias", "10.99.0.2"])
        sh("sudo", "ifconfig", "lo0", "alias", "10.99.0.2/32")
        UNDO.append(["sudo", "ifconfig", "lo0", "-alias", "10.77.0.2"])
        sh("sudo", "ifconfig", "lo0", "alias", "10.77.0.2/32")
        UNDO.append(["sudo", "route", "-n", "delete", "-host", "192.0.2.1"])
        sh("sudo", "route", "-n", "add", "-host", "192.0.2.1", "10.77.0.2")

def move():
    """Gain B, route by it, lose A: as close together as the platform allows."""
    if LINUX:
        batch = f"{S}/move"
        open(batch, "w").write(
            "address add 10.88.0.2/24 dev d1\n"
            "route replace default via 10.88.0.1 dev d1\n"
            "address del 10.77.0.2/24 dev d0\n")
        sh("ip", "-batch", batch)
    else:
        UNDO.append(["sudo", "ifconfig", "lo0", "-alias", "10.88.0.2"])
        sh("sudo", "ifconfig", "lo0", "alias", "10.88.0.2/32")
        sh("sudo", "route", "-n", "change", "-host", "192.0.2.1", "10.88.0.2")
        sh("sudo", "ifconfig", "lo0", "-alias", "10.77.0.2")

UNDO = []

def env(w):
    e = {k: os.environ[k] for k in ("PATH", "TMPDIR") if k in os.environ}
    e.update(HOME=f"{S}/{w}", VOX_DATA_DIR=f"{S}/{w}/data", VOX_CONFIG_DIR=f"{S}/{w}/cfg")
    return e

def run(w, *args, stdin=None, secs=120):
    return subprocess.run([VOX, *args], env=env(w), input=stdin, capture_output=True, text=True, timeout=secs)

def ok(w, *args, stdin=None, secs=120):
    r = run(w, *args, stdin=stdin, secs=secs)
    if r.returncode != 0:
        raise Product(f"{w}'s `vox {' '.join(args[:2])}` failed: {r.stderr.strip()}")
    return r.stdout

def until(pred, secs, step=0.1):
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()

def log(w):
    return open(f"{S}/{w}.err").read()

try:
    setup()
    for w in ("d", "p"):
        for d in ("data", "cfg"):
            os.makedirs(f"{S}/{w}/{d}")
    open(f"{S}/idpass", "w").write("id pass\n")
    fp = {}
    for w in ("d", "p"):
        out = ok(w, "id", "--identity-passphrase-file", f"{S}/idpass")
        m = re.search(r"[a-z2-7]{52}", out)
        if m is None:
            raise Product(f"{w}'s `vox id` printed no fingerprint: {out!r}")
        fp[w] = m.group(0)
    listen = {"d": "0.0.0.0:0", "p": "10.99.0.2:0"}
    for w in ("d", "p"):
        p = subprocess.Popen([VOX, "daemon", "--listen", listen[w], "--passphrase-file", f"{S}/idpass"],
                             env=env(w), stdin=subprocess.DEVNULL,
                             stdout=open(f"{S}/{w}.out", "w"), stderr=open(f"{S}/{w}.err", "w"))
        PROCS.append(p)
        if not until(lambda: run(w, "room", "list").returncode == 0, 60, 0.25):
            raise Product(f"{w}'s daemon never answered within 60 s: {log(w)}")

    # ---- D's room, P in it, each trusting the other ----
    ok("d", "room", "create", "--passphrase-file", "-", "--name", "r", stdin="room pass\n")
    room = ok("d", "room", "list").split()[0]
    link = ok("d", "room", "link", room).strip()
    if "10.77.0.2" not in link:
        raise Apparatus(f"D's invite link does not name A (10.77.0.2), so P would not dial it there: {link}")
    ok("p", "room", "join", "--passphrase-file", "-", link, "--name", "r", stdin="room pass\n", secs=490)
    ok("d", "trust", "add", fp["p"], "--name", "p", "--identity-passphrase-file", f"{S}/idpass")
    ok("p", "trust", "add", fp["d"], "--name", "d", "--identity-passphrase-file", f"{S}/idpass")
    ok("d", "room", "post", room, "BEFORE-THE-MOVE")
    if not until(lambda: "BEFORE-THE-MOVE" in run("p", "room", "read", room).stdout, 60, 0.5):
        raise Product("P never read D's post before the change, within 60 s")
    print(f"{TAG} P reads D before the change", flush=True)
    time.sleep(2)
    SAID = "vox: the network changed:"
    def said_lines():
        return [l for l in log("d").splitlines() if l.startswith(SAID)]
    if LINUX:
        # ---- router: the default route's next hop moves, and no address does ----
        router_before = len(said_lines())
        sh("ip", "route", "replace", "default", "via", "10.77.0.3", "dev", "d0")
        rerouted = time.time()
        WANT = "IPv4 default route 10.77.0.1 \u2192 10.77.0.3"
        heard = until(lambda: len(said_lines()) > router_before, 1.0, 0.02)
        took = time.time() - rerouted
        time.sleep(2)
        said = said_lines()[router_before:]
        claim("router", heard and len(said) == 1 and WANT in said[0],
              f"D said {len(said)} change(s) for a next-hop move alone"
              + (f", the first {took:.2f} s after it" if heard else " within 1 s")
              + f": {said}")
    said_before = len(said_lines())
    # When D first says a change, watched from before the move, every 20 ms.
    first_said = []
    def watch_log():
        end = time.time() + 15
        while time.time() < end and not first_said:
            if len(said_lines()) > said_before:
                first_said.append(time.time())
                return
            time.sleep(0.02)
    watcher = threading.Thread(target=watch_log, daemon=True)
    watcher.start()
    def held_to_p():
        r = run("d", "status", "--json")
        if r.returncode != 0:
            return None
        for row in json.loads(r.stdout).get("reach", []):
            if row.get("peer") == fp["p"]:
                return row.get("connection")
        return None
    before = held_to_p()
    if before is None:
        raise Product("D holds no connection to P before the change, though P reads D")

    # ---- the move ----
    move()
    MOVED = True
    moved = time.time()
    # ---- redial: with nothing sent, D holds a new connection to P within 3 s ----
    redialled = until(lambda: held_to_p() not in (None, before), 3, 0.1)
    now = held_to_p()
    claim("redial", redialled,
          f"D's connection to P before the change {before}, {time.time() - moved:.2f} s after it {now}")
    ok("d", "room", "post", room, "AFTER-THE-MOVE")
    posted = time.time()

    # ---- reads: P reads the post within 5 s ----
    read = until(lambda: "AFTER-THE-MOVE" in run("p", "room", "read", room).stdout, 40, 0.2)
    took = time.time() - moved
    # ---- said: exactly one change, within 1 s; looked at again 3 s after it for a second ----
    watcher.join()
    first = first_said[0] - moved if first_said else None
    time.sleep(max(0.0, moved + 3 - time.time()))
    lines = said_lines()[said_before:]
    stranded = [l for l in log("d").splitlines() if "accepted here) did not answer a probe after the network changed" in l]
    claim("said", len(lines) == 1 and first is not None and first <= 1.0,
          f"D said {len(lines)} change(s), the first {first if first is None else round(first, 2)} s after it: {lines}")
    # ---- status: the change's time, B listed and A not, within 2 s of the change ----
    def status():
        r = run("d", "status", "--json")
        return json.loads(r.stdout) if r.returncode == 0 else {}
    st = {}
    def shows():
        st.clear()
        st.update(status())
        l = " ".join(st.get("listening", []))
        return bool(st.get("network_changed")) and "10.88.0.2" in l and "10.77.0.2" not in l
    shown = until(shows, max(0.0, moved + 2 - time.time()), 0.1)
    claim("status", shown,
          f"within 2 s: network_changed {st.get('network_changed')!r}; listening {st.get('listening')!r}")
    claim("reads", read and took <= 5.0,
          f"P read the post sent {posted - moved:.2f} s after the change {took:.2f} s after the change"
          + ("" if read else " (never, within 40 s)")
          + f"; D: {stranded[0].strip() if stranded else 'said no stranded connection'}")
    print(f"{TAG} claims: {sum(results.values())}/{len(results)} ok", flush=True)
    code = 0 if results and all(results.values()) else 1
    print(f"{TAG} {'PASS' if code == 0 else 'RED'}", flush=True)
except Apparatus as a:
    print(f"{TAG} APPARATUS: {a}", flush=True)
    code = 2
except Product as e:
    print(f"{TAG} {'PRODUCT' if MOVED else 'PRODUCT (staging)'}: {e}", flush=True)
    print(f"{TAG} RED", flush=True)
    code = 1
except subprocess.TimeoutExpired as t:
    print(f"{TAG} RED: `vox {' '.join(t.cmd[1:3])}` did not return within {t.timeout:.0f} s", flush=True)
    code = 1
except Exception:
    print(f"{TAG} APPARATUS: driver crashed: {traceback.format_exc()}", flush=True)
    code = 2
finally:
    for cmd in reversed(UNDO):
        subprocess.run(cmd, capture_output=True)
    for p in PROCS:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill(); p.wait()
    for w in ("d", "p"):
        if os.path.exists(f"{S}/{w}.err"):
            print(f"{TAG} ---- {w}'s daemon log (tail) ----")
            for l in log(w).splitlines()[-40:]:
                print(f"{TAG} {w}| {l}")
    __import__("shutil").rmtree(S, ignore_errors=True)
sys.exit(code)
