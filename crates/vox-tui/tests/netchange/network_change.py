#!/usr/bin/env python3
"""network_change.py <vox> — ADR-012 N-34, N-49–N-52 (#413, #414, #937), through real `vox`.

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
  flap       (Linux) active interface down/up inside 500 ms, with identical final addresses and
             gateway, is noticed and a new message arrives;
  anchor-cache (Linux) the anchor supplies its own alternate over an authenticated connection;
             after losing its sole configured LAN address, a restarted node still reaches that
             anchor and delivers a new message, without reconfiguration;
  anchor-assisted (Linux) an established direct peer becomes reachable only through that known
             anchor; current status says relayed and a new message arrives;
  direct-restored (Linux) direct reach returns, a new message arrives, and stopping the now
             unnecessary anchor does not interrupt it. Identity, trust and room membership stay.

The Linux extension uses the existing test-knobs build only to stage the anchor's own advertised
endpoints (its real socket serves both). Client configuration contains only its LAN endpoint.
The final path loss is an nftables rule inside this disposable namespace, never the host.

The staging forces what `reads` is about: P can reach D only at A, so the move strands the
connection D accepted. D's log line for it (`accepted here) did not answer a probe after the
network changed`) is printed with the claim.

**Linux** (the proof): inside an unprivileged user and network namespace (`unshare --user
--map-current-user --keep-caps --net`, which this script enters itself), whose own interfaces are
the machine's network: A on dummy d0 with the default route, B on d1, P's address on d2; the move
is one `ip -batch`. Nothing outside the namespace is touched and no privilege is needed.

**macOS** (opt-in heavy, the operator runs it): the addresses are aliases on `lo0`, and the
operating system routes by A because a host route to 192.0.2.1 (TEST-NET-1, the address
`local_route_ips` asks the route to) goes through A; the move adds B, deletes that route and adds
it afresh through B, and removes A. Every change is made with `sudo` (the operator's prompt; run
`sudo -v` first) and undone at the end. The machine's own default route and real interfaces are
never touched. `vox` itself runs as the operator, never as root: a daemon refuses a control
connection from uid 0.

**Why this mirrors a real move.** What vox reads of the network is what it would read on Wi-Fi:
the routing socket's messages (`RTM_NEWADDR`, `RTM_DELADDR`, `RTM_ADD`, `RTM_DELETE`, whatever the
interface) and the source address the kernel picks for a probe to 192.0.2.1. A real move deletes
the old route and adds a new one, so the steering route is deleted and added, never changed in
place: `route change` moved its gateway and left it the old source (`rt_ifa`), so the probe still
read A after the move, the network had not changed in the one way vox reads, and the run judged
the product on a scene it had not staged.

**No other proof runs while the macOS staging is in place**: its aliases and host route change every
vox's routable address on the machine, so the driver holds every slot of the shared
`run-slot.sh` queue from before the first change until after the last is undone, on every way
out, signals included.

**Every staged step is checked from the OS's own view** before any claim is judged, and quoted:
the addresses the OS shows, the route to 192.0.2.1, and the source a connected UDP probe to it
gets (what `local_route_ips` reads). A before the move, B after it, A gone: anything else is
APPARATUS, CANNOT MEASURE, quoting what the OS showed, and no claim is made.

Exit 0 = pass, 1 = red, 2 = apparatus or CANNOT MEASURE. A `vox` step that fails is the product's
red: `PRODUCT (staging):` before the move (the scene was not reached, and what vox said is quoted),
`PRODUCT:` after it. Every process is recorded and stopped by PID.
"""
import json, os, re, select, socket, subprocess, sys, tempfile, threading, time, traceback

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
DAEMONS = {}
ANCHOR_SPEC = None
ANCHOR_ID = None
ANCHOR_PROC = None
ANCHOR_PORT = None
code = 2
results = {}

def claim(name, ok, detail):
    results[name] = ok
    print(f"{TAG} CLAIM {name} {'ok' if ok else 'RED'}: {'' if ok else 'PRODUCT: '}{detail}", flush=True)

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
                    ["addr", "add", "10.99.0.3/24", "dev", "d2"],
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
        # Deleted and added, as a real move does: a route changed in place keeps its old source.
        sh("sudo", "route", "-n", "delete", "-host", "192.0.2.1")
        sh("sudo", "route", "-n", "add", "-host", "192.0.2.1", "10.88.0.2")
        sh("sudo", "ifconfig", "lo0", "-alias", "10.77.0.2")

TEST_ADDRS = ("10.77.0.2", "10.88.0.2", "10.99.0.2", "10.99.0.3")

def os_view():
    """What the OS shows of the staging: which test addresses it has, its route to 192.0.2.1, and
    the source a connected UDP probe to 192.0.2.1:9 gets (what vox's `local_route_ips` reads; no
    datagram is sent)."""
    import socket
    if LINUX:
        listed = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True).stdout
        route = subprocess.run(["ip", "route", "get", "192.0.2.1"], capture_output=True, text=True)
    else:
        listed = subprocess.run(["ifconfig", "lo0"], capture_output=True, text=True).stdout
        route = subprocess.run(["route", "-n", "get", "192.0.2.1"], capture_output=True, text=True)
    have = {a for a in TEST_ADDRS if re.search(rf"inet {re.escape(a)}[/ ]", listed)}
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.connect(("192.0.2.1", 9))
        probe = u.getsockname()[0]
        u.close()
    except OSError as e:
        probe = f"no route ({e})"
    route_said = " ".join((route.stdout + route.stderr).split())
    return {"have": sorted(have), "probe": probe, "route": route_said}

def staged(when, probe, present, absent):
    """The staging is what the claims assume, from the OS's own view, or APPARATUS."""
    v = os_view()
    print(f"{TAG} OS view {when}: addresses {v['have']}; a probe to 192.0.2.1 leaves from "
          f"{v['probe']}; route: {v['route'][:300]}", flush=True)
    wrong = []
    if v["probe"] != probe:
        wrong.append(f"a probe to 192.0.2.1 leaves from {v['probe']}, not {probe}")
    wrong += [f"{a} is missing" for a in present if a not in v["have"]]
    wrong += [f"{a} is still there" for a in absent if a in v["have"]]
    if wrong:
        raise Apparatus(f"CANNOT MEASURE, staging not achieved {when}: " + "; ".join(wrong))

UNDO = []

# ---- the box, held while the macOS staging is in place ----
# Its lo0 aliases and its host route to 192.0.2.1 change the routable address of every vox on the
# machine: `local_route_ips` reads the source of a probe to 192.0.2.1. A proof running beside it saw
# "the network changed" and went red. So, from before the first change until after the last is
# undone, no other proof may run: the driver holds every run slot of the shared `run-slot.sh`
# (the queue every proof run takes a slot from, timing proofs included), as its exclusive mode
# does, counting a slot its own caller holds as its own. Linux stays inside its own namespace and
# takes nothing.
HELD = []
BOX_TICKET = []

def coord():
    """The shared slots' directory and count, as `~/vox-coord/run-slot.sh` names them; None where
    this machine has no shared queue."""
    try:
        # The real home, from the user database: the proof runs this driver with a temporary HOME,
        # where `~` would name a directory that has no queue.
        import pwd
        text = open(os.path.join(pwd.getpwuid(os.getuid()).pw_dir, "vox-coord/run-slot.sh")).read()
    except OSError:
        return None, 0
    d = re.search(r"^S=(\S+)", text, re.M)
    n = re.search(r"VOX_RUN_SLOTS:-(\d+)", text)
    return (d.group(1) if d else None), int(os.environ.get("VOX_RUN_SLOTS", n.group(1) if n else 6))

def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True

def owner(slot):
    try:
        return int(open(f"{slot}/pid").read().strip())
    except (OSError, ValueError):
        return None

def ancestors():
    """This process and its ancestors: the `run-slot.sh` that started this proof holds a slot."""
    pids, pid = set(), os.getpid()
    while pid > 1 and pid not in pids:
        pids.add(pid)
        up = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        if not up.isdigit():
            break
        pid = int(up)
    return pids

def take_the_box():
    import glob, shutil
    base, n = coord()
    if base is None:
        print(f"{TAG} no shared run-slot queue on this machine (~/vox-coord/run-slot.sh): nothing to hold", flush=True)
        return
    slots, tickets = f"{base}/run.slots", f"{base}/run.tickets"
    os.makedirs(slots, exist_ok=True)
    os.makedirs(tickets, exist_ok=True)
    name = f"{time.time_ns()}000000-X-{os.getpid()}"
    BOX_TICKET.append(f"{tickets}/{name}")
    open(BOX_TICKET[0], "w").close()
    mine, began, said = ancestors(), time.time(), 0.0
    print(f"{TAG} waiting to hold all {n} run slots, so no other proof runs while the staging changes this machine's routes", flush=True)
    while True:
        for s in glob.glob(f"{slots}/slot*"):
            o = owner(s)
            if o is None or not alive(o):
                shutil.rmtree(s, ignore_errors=True)
        for t in glob.glob(f"{tickets}/*"):
            pid = t.rsplit("-", 1)[-1]
            if pid.isdigit() and not alive(int(pid)):
                os.remove(t)
        if not os.path.exists(BOX_TICKET[0]):
            open(BOX_TICKET[0], "w").close()
        if sorted(os.listdir(tickets))[:1] == [name]:
            for i in range(1, n + 1):
                try:
                    os.mkdir(f"{slots}/slot{i}")
                except FileExistsError:
                    continue
                open(f"{slots}/slot{i}/pid", "w").write(f"{os.getpid()}\n")
                open(f"{slots}/slot{i}/cmd", "w").write("network_change.py: holding the box for the macOS staging\n")
                HELD.append(f"{slots}/slot{i}")
            others = [s for s in glob.glob(f"{slots}/slot*") if s not in HELD and owner(s) not in mine]
            if not others:
                break
        if time.time() - said >= 30:
            said = time.time()
            print(f"{TAG} still waiting for the run slots after {time.time() - began:.0f} s", flush=True)
        time.sleep(2)
    os.remove(BOX_TICKET[0])
    BOX_TICKET.clear()
    print(f"{TAG} holding every run slot after {time.time() - began:.0f} s; no other proof runs until the staging is undone", flush=True)

def release_the_box():
    import shutil
    for s in HELD:
        if owner(s) == os.getpid():
            shutil.rmtree(s, ignore_errors=True)
    HELD.clear()
    for t in BOX_TICKET:
        try:
            os.remove(t)
        except OSError:
            pass
    BOX_TICKET.clear()

def interrupted(signum, _frame):
    # A stop by signal runs the same cleanup as any other end: routes, aliases, the slots.
    raise KeyboardInterrupt(f"signal {signum}")

import signal
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)

def env(w):
    e = {k: os.environ[k] for k in ("PATH", "TMPDIR") if k in os.environ}
    e.update(HOME=f"{S}/{w}", VOX_DATA_DIR=f"{S}/{w}/data", VOX_CONFIG_DIR=f"{S}/{w}/cfg", VOX_PROXY="127.0.0.1:0")
    return e

def run(w, *args, stdin=None, secs=120):
    return subprocess.run([VOX, *args], env=env(w), input=stdin, capture_output=True, text=True, timeout=secs)

def ok(w, *args, stdin=None, secs=120):
    r = run(w, *args, stdin=stdin, secs=secs)
    if r.returncode != 0:
        raise Product(f"{w}'s `vox {' '.join(args[:2])}` failed: {r.stderr.strip()}")
    return r.stdout

def trust(w, peer, name):
    # Same terminal interaction as support/typed.rs: a current keyring change accepts no
    # passphrase file/environment fallback. This proof controls only its own scratch identities.
    pid, fd = os.forkpty()
    if pid == 0:
        os.execve(VOX, [VOX, "trust", "add", peer, "--name", name], env(w))
    out, sent, deadline = b"", False, time.monotonic() + 120
    try:
        while True:
            if time.monotonic() >= deadline:
                os.kill(pid, signal.SIGKILL)
                raise Apparatus(f"mutual-trust staging watchdog expired after 120 s for {w}: {out!r}")
            ready, _, _ = select.select([fd], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            prompt = out.rstrip().rsplit(b"\n", 1)[-1]
            if not sent and (prompt.endswith(b"passphrase:") or
                             (prompt.startswith(b"passphrase for ") and prompt.endswith(b":"))):
                time.sleep(0.5)  # the same read-the-prompt pause as the existing typed driver
                os.write(fd, b"id pass\r")
                sent = True
        _, status = os.waitpid(pid, 0)
        pid = None
        if os.waitstatus_to_exitcode(status) != 0:
            raise Apparatus(f"mutual-trust setup was not achieved: {w}'s terminal trust add said: {out.decode('utf-8', 'replace')}")
    finally:
        os.close(fd)
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)

def until(pred, secs, step=0.1):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if pred():
            return time.monotonic() <= end
        time.sleep(min(step, max(0, end - time.monotonic())))
    return False

def log(w):
    return open(f"{S}/{w}.err").read()

def status_of(w):
    result = run(w, "status", "--json", secs=10)
    if result.returncode != 0:
        raise Product(f"{w}'s public status observation failed (exit {result.returncode}): stdout={result.stdout!r}; stderr={result.stderr!r}")
    try:
        return json.loads(result.stdout)
    except ValueError as error:
        raise Product(f"{w}'s status returned invalid JSON: {result.stdout!r}: {error}")

def peer_path(w, peer):
    return next((row.get("path") for row in status_of(w).get("reach", []) if row.get("peer") == peer), None)

def start_daemon(w, listen):
    argv = [VOX, "daemon", "--listen", listen, "--passphrase-file", f"{S}/idpass"]
    if ANCHOR_SPEC:
        argv += ["--anchor", ANCHOR_SPEC]
    child = subprocess.Popen(argv, env=env(w), stdin=subprocess.DEVNULL,
                             stdout=open(f"{S}/{w}.out", "a"), stderr=open(f"{S}/{w}.err", "a"))
    PROCS.append(child)
    DAEMONS[w] = child
    if not until(lambda: run(w, "room", "list").returncode == 0, 60, 0.25):
        raise Product(f"{w}'s daemon never answered within 60 s: {log(w)}")

def start_anchor():
    global ANCHOR_SPEC, ANCHOR_ID, ANCHOR_PROC, ANCHOR_PORT
    if b"VOX_TEST_ADVERTISE" not in open(VOX, "rb").read():
        raise Apparatus("anchor alternate staging needs the existing test-knobs build (VOX_TEST_ADVERTISE)")
    for directory in ("data", "cfg"):
        os.makedirs(f"{S}/anchor/{directory}")
    reserve = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    reserve.bind(("0.0.0.0", 0))
    port = reserve.getsockname()[1]
    ANCHOR_PORT = port
    reserve.close()
    anchor_env = env("anchor")
    # The real anchor's own published list, standing for its LAN and mapped public endpoint.
    # Clients receive only the LAN bootstrap; the alternate must come from authenticated Vox.
    anchor_env["VOX_TEST_ADVERTISE"] = f"10.99.0.3:{port},10.77.0.2:{port}"
    child = subprocess.Popen([VOX, "node", "--listen", f"0.0.0.0:{port}"], env=anchor_env,
                             stdin=subprocess.DEVNULL, stdout=open(f"{S}/anchor.out", "w"),
                             stderr=open(f"{S}/anchor.err", "w"))
    PROCS.append(child)
    ANCHOR_PROC = child
    anchor_file = f"{S}/anchor/cfg/anchors"
    def wrote():
        return os.path.exists(anchor_file) and "@" in open(anchor_file).read()
    if not until(wrote, 60, 0.1):
        if child.poll() is not None and "already in use" in log("anchor"):
            raise Apparatus("the reserved anchor port was taken before its process bound it")
        raise Product(f"anchor never published its initial address: {log('anchor')}")
    text = open(anchor_file).read()
    match = re.search(r"([a-z2-7]{52})@", text)
    if not match:
        raise Product(f"anchor file has no fingerprint: {text!r}")
    ANCHOR_ID = match.group(1)
    ANCHOR_SPEC = f"{ANCHOR_ID}@/ip4/10.77.0.2/udp/{port}"
    print(f"{TAG} only bootstrap supplied to clients: {ANCHOR_SPEC}; anchor advertises its alternate itself", flush=True)


try:
    if not LINUX:
        take_the_box()
    else:
        sh("nft", "--version")
    setup()
    staged("before the move", "10.77.0.2", ["10.77.0.2", "10.99.0.2"], ["10.88.0.2"])
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
    if LINUX:
        start_anchor()
    listen = {"d": "0.0.0.0:0", "p": "10.99.0.2:0"}
    if LINUX:
        reserve = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        reserve.bind(("0.0.0.0", 0))
        d_port = reserve.getsockname()[1]
        reserve.close()
        listen["d"] = f"0.0.0.0:{d_port}"
        # D may learn the alternate address, but cannot ever authenticate a connection there
        # before its cold restart. Otherwise the ordinary peer book could mask broken hint
        # persistence. This is external packet staging, with no cache inspection or deletion.
        rules = f"{S}/unreached-anchor-alternate.nft"
        open(rules, "w").write(
            "table inet vox_anchor_bootstrap {\n chain output {\n  type filter hook output priority 0; policy accept;\n"
            f"  ip daddr 10.99.0.3 udp sport {d_port} udp dport {ANCHOR_PORT} counter drop;\n"
            f"  ip saddr 10.99.0.3 udp sport {ANCHOR_PORT} udp dport {d_port} counter drop;\n" + " }\n}\n")
        sh("nft", "-f", rules)
        print(f"{TAG} D cannot reach the advertised alternate until its cold restart: " +
              sh("nft", "list", "table", "inet", "vox_anchor_bootstrap"), flush=True)
    for w in ("d", "p"):
        start_daemon(w, listen[w])

    # ---- D's room, P in it, each trusting the other ----
    ok("d", "room", "create", "--passphrase-file", "-", "--name", "r", stdin="room pass\n")
    room = ok("d", "room", "list").split()[0]
    link = ok("d", "room", "link", room).strip()
    if ANCHOR_ID and f"a={ANCHOR_ID}" in link:
        raise Apparatus(f"the learned-endpoint claim needs LAN-only machine bootstrap, but the room link also carries the anchor: {link}")
    if "10.77.0.2" not in link:
        raise Apparatus(f"D's invite link does not name A (10.77.0.2), so P would not dial it there: {link}")
    ok("p", "room", "join", "--passphrase-file", "-", link, stdin="room pass\n", secs=490)
    trust("d", fp["p"], "p")
    trust("p", fp["d"], "d")
    ok("d", "room", "post", room, "BEFORE-THE-MOVE")
    if not until(lambda: "BEFORE-THE-MOVE" in run("p", "room", "read", room).stdout, 60, 0.5):
        raise Product("P never read D's post before the change, within 60 s")
    print(f"{TAG} P reads D before the change", flush=True)
    trust_before = {w: ok(w, "trust", "list").strip() for w in ("d", "p")}
    if fp["p"] not in trust_before["d"] or fp["d"] not in trust_before["p"]:
        raise Apparatus("mutual-trust setup was not achieved: the public trust lists do not contain both peer fingerprints")
    if LINUX:
        for w in ("d", "p"):
            inventory = json.loads(ok(w, "anchor", "list", "--json"))
            item = next((a for a in inventory.get("anchors", []) if a.get("fingerprint") == ANCHOR_ID), None)
            if item is None or not item.get("addresses") or any("10.77.0.2" not in a for a in item["addresses"]) or item.get("sources") != [{"kind": "added-by-hand"}]:
                raise Apparatus(f"{w}'s anchor inputs do not stage only a manual LAN bootstrap: {inventory!r}")
            print(f"{TAG} {w}'s public anchor inventory confirms only the LAN bootstrap and manual source: {item}", flush=True)
    time.sleep(2)
    SAID = "vox: node default: the network changed:"
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
        # A down/up inside one settle interval ends with identical addresses and next hop.
        # The real kernel events, not a final-snapshot difference, must cause recovery.
        flap_before = len(said_lines())
        flap_batch = f"{S}/flap"
        open(flap_batch, "w").write(
            "link set d0 down\nlink set d0 up\n"
            "route replace default via 10.77.0.3 dev d0\n")
        flap_started = time.monotonic()
        sh("ip", "-batch", flap_batch)
        if time.monotonic() - flap_started >= 0.5:
            raise Apparatus("down/up batch did not finish within NETWORK_SETTLE (500 ms)")
        staged("after rapid path restoration", "10.77.0.2", ["10.77.0.2", "10.99.0.2"], [])
        heard = until(lambda: len(said_lines()) > flap_before, 2, 0.02)
        after_flap = said_lines()[flap_before:]
        ok("d", "room", "post", room, "AFTER-RAPID-PATH-RESTORATION")
        delivered = until(lambda: "AFTER-RAPID-PATH-RESTORATION" in run("p", "room", "read", room).stdout, 5, 0.1)
        claim("flap", heard and len(after_flap) == 1
              and "active path interrupted" in after_flap[0] and delivered,
              f"identical final addresses/next hop, recorded path loss {after_flap}, new post delivered={delivered}")
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
    status_observations = []
    def held_to_p():
        r = run("d", "status", "--json")
        if r.returncode != 0:
            return None
        report = json.loads(r.stdout)
        listening = " ".join(report.get("listening", []))
        if not status_observations and report.get("network_changed") and "10.88.0.2" in listening and "10.77.0.2" not in listening:
            status_observations.append((time.time(), report))
        for row in report.get("reach", []):
            if row.get("peer") == fp["p"]:
                return row.get("connection")
        return None
    before = held_to_p()
    if before is None:
        raise Product("D holds no connection to P before the change, though P reads D")

    # ---- the move ----
    move()
    moved = time.time()
    # Checked before any claim is judged; the claims' clocks start at the move itself.
    staged("after the move", "10.88.0.2", ["10.88.0.2", "10.99.0.2"], ["10.77.0.2"])
    MOVED = True
    # ---- redial: with nothing sent, D holds a new connection to P within 3 s ----
    redial_observed = []
    def new_connection():
        current = held_to_p()
        if current not in (None, before):
            redial_observed.append((time.time(), current))
            return True
        return False
    redialled = until(new_connection, max(0, moved + 3 - time.time()), 0.1)
    observed, now = redial_observed[0] if redial_observed else (None, None)
    claim("redial", redialled and observed is not None and observed - moved <= 3,
          f"D's connection to P before the change {before}, first new connection {now} at {None if observed is None else round(observed - moved, 2)} s after it")
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
    # ---- status: retain the actual observation time from the public redial polls above ----
    # A late final snapshot cannot prove that the addresses were shown within the bound.
    observed_at, st = status_observations[0] if status_observations else (None, {})
    shown = observed_at is not None and observed_at - moved <= 2
    claim("status", shown,
          f"observed {None if observed_at is None else round(observed_at - moved, 2)} s after the move: network_changed {st.get('network_changed')!r}; listening {st.get('listening')!r}")
    claim("reads", read and took <= 5.0,
          f"P read the post sent {posted - moved:.2f} s after the change {took:.2f} s after the change"
          + ("" if read else " (never, within 40 s)")
          + f"; D: {stranded[0].strip() if stranded else 'said no stranded connection'}")
    if LINUX:
        staged("before hotspot restart", "10.88.0.2", ["10.88.0.2", "10.99.0.2", "10.99.0.3"], ["10.77.0.2"])
        # A fresh process on the new network must reach the same anchor from the sealed hint
        # cache. The only configured address is still the now-absent LAN address. No rejoin,
        # trust change, address-file edit or new infrastructure is supplied at this boundary.
        DAEMONS["d"].kill()
        DAEMONS["d"].wait(timeout=10)
        print(f"{TAG} alternate remained blocked until D stopped: " +
              sh("nft", "list", "table", "inet", "vox_anchor_bootstrap"), flush=True)
        sh("nft", "delete", "table", "inet", "vox_anchor_bootstrap")
        start_daemon("d", listen["d"])
        ready_at = time.monotonic()
        restart_addresses = []
        def restart_has_addresses():
            report = status_of("d")
            restart_addresses[:] = [(time.monotonic(), report)]
            addresses = report.get("listening", [])
            return (any("/ip4/10.88.0.2/udp/" in address for address in addresses)
                    and not any("/ip4/10.77.0.2/udp/" in address for address in addresses))
        addresses_ready = until(restart_has_addresses, 2, 0.1)
        address_at, restart_status = restart_addresses[-1] if restart_addresses else (ready_at, {})
        anchor_reached = until(lambda: any(row.get("id") == ANCHOR_ID and row.get("reached")
                              for row in status_of("d").get("node_anchors", [])), 20, 0.1)
        ok("d", "room", "post", room, "AFTER-HOTSPOT-RESTART")
        delivered = until(lambda: "AFTER-HOTSPOT-RESTART" in run("p", "room", "read", room).stdout, 10, 0.1)
        claim("anchor-cache", addresses_ready and anchor_reached and delivered,
              f"same LAN-only bootstrap {ANCHOR_SPEC}, obsolete address absent, restarted node reached anchor={anchor_reached}, new message delivered={delivered}; current listening addresses within 2 s of Ready={addresses_ready}, observed after {address_at - ready_at:.2f} s: {restart_status.get('listening')!r}")
        if not addresses_ready:
            raise Product(f"Ready node did not publish its current local address within 2 s, while gateway work is pending: {restart_status!r}")
        if not until(lambda: peer_path("d", fp["p"]) == "direct", 20, 0.1):
            raise Product("the established peer was not direct before staging its loss")
        def udp_port(w):
            report = status_of(w)
            for address in report.get("listening", []):
                match = re.search(r"(?:/udp/|:)([0-9]+)$", address)
                if match:
                    return int(match.group(1))
            raise Apparatus(f"cannot stage the direct-path filter: {w}'s public status did not name its listening port: {report!r}")
        d_port, p_port = udp_port("d"), udp_port("p")
        rules = f"{S}/direct-path-loss.nft"
        open(rules, "w").write(
            "table inet vox_netchange {\n chain output {\n  type filter hook output priority 0; policy accept;\n"
            f"  udp sport {d_port} udp dport {p_port} counter drop;\n"
            f"  udp sport {p_port} udp dport {d_port} counter drop;\n" + " }\n}\n")
        sh("nft", "-f", rules)  # this process's disposable user/net namespace only
        print(f"{TAG} direct packets blocked only between the two peer UDP ports: " +
              sh("nft", "list", "table", "inet", "vox_netchange"), flush=True)
        sh("ip", "route", "replace", "default", "via", "10.88.0.3", "dev", "d1")
        relayed = until(lambda: peer_path("d", fp["p"]) == "relayed", 15, 0.1)
        ok("d", "room", "post", room, "THROUGH-KNOWN-ANCHOR-AFTER-MOVE")
        delivered = until(lambda: "THROUGH-KNOWN-ANCHOR-AFTER-MOVE" in run("p", "room", "read", room).stdout, 10, 0.1)
        claim("anchor-assisted", relayed and delivered,
              f"established direct peer now relayed={relayed}; actual new room message delivered={delivered}; same identities/trust/membership")
        sh("nft", "delete", "table", "inet", "vox_netchange")
        sh("ip", "route", "replace", "default", "via", "10.88.0.1", "dev", "d1")
        direct = until(lambda: peer_path("d", fp["p"]) == "direct", 15, 0.1)
        ok("d", "room", "post", room, "BACK-TO-DIRECT-AFTER-MOVE")
        delivered = until(lambda: "BACK-TO-DIRECT-AFTER-MOVE" in run("p", "room", "read", room).stdout, 10, 0.1)
        ANCHOR_PROC.terminate()
        ANCHOR_PROC.wait(timeout=10)
        ok("d", "room", "post", room, "DIRECT-WITHOUT-ANCHOR")
        without_anchor = until(lambda: "DIRECT-WITHOUT-ANCHOR" in run("p", "room", "read", room).stdout, 10, 0.1)
        direct_without_anchor = peer_path("d", fp["p"]) == "direct"
        continuity = all(fp[w] in ok(w, "id", "--identity-passphrase-file", f"{S}/idpass")
                         and ok(w, "trust", "list").strip() == trust_before[w]
                         and room in ok(w, "room", "list") for w in ("d", "p"))
        claim("direct-restored", direct and delivered and without_anchor and direct_without_anchor and continuity,
              f"same peers returned to direct={direct}; new message delivered={delivered}; after stopping unneeded anchor direct={direct_without_anchor}, message delivered={without_anchor}; identities/trust/room unchanged={continuity}; no Vox restart/rejoin/config/trust action during path loss/restoration")
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
    print(f"{TAG} APPARATUS: subprocess watchdog expired for {t.cmd!r} after {t.timeout:.0f} s; no result from this observation", flush=True)
    code = 2
except Exception:
    print(f"{TAG} APPARATUS: driver crashed: {traceback.format_exc()}", flush=True)
    code = 2
except KeyboardInterrupt as k:
    print(f"{TAG} APPARATUS: stopped ({k}); the staging is undone", flush=True)
    code = 2
finally:
    for cmd in reversed(UNDO):
        subprocess.run(cmd, capture_output=True)
    release_the_box()
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
