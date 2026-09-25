#!/bin/bash
# family-lan-proof.sh — PRD-001 R28 (ADR-013 §"The family LAN") on REAL interfaces.
#
# Three members of one room on this Mac, each with its own `vox lan up` and its own utun:
# alice and bob trust each other; carol is a member nobody trusts (and she trusts both of
# them, so she tries). The script proves, printing counts and a PASS/FAIL per line:
#
#   1. ping      alice's interface pings bob's LAN address, and the echo requests cross
#                both LAN engines (bob's counters show them arriving from alice).
#   2. udp echo  a UDP echo both ways between sockets bound to alice's and bob's
#                interfaces; both directions cross both engines.
#   3. mdns      an mDNS query for vox-lan-proof.local sent on alice's interface is
#                answered by a responder on bob's, and carol's interface hears nothing.
#   4. broadcast a UDP subnet broadcast from alice reaches bob and not carol.
#   5. untrusted nothing carol sends — unicast or broadcast — reaches alice or bob, and
#                carol has no link at all.
#   6. whitelist every node runs `--allow 47010,47011,47030`: a UDP datagram and a
#                TCP connect to bob's unlisted ports get nothing (bob's LAN counts them
#                filtered), a TCP connect to a listed port succeeds — while the discovery
#                in 3 and 4 went to unlisted ports and crossed anyway.
#   7. teardown  after everything stops, no utun the proof made exists and no route to
#                the room's /24 or /64 remains (`ifconfig -l` and `netstat -rn` diffs).
#
# Run it, from the repository, as:
#
#     cargo build --release -p vox-tui
#     sudo scripts/family-lan-proof.sh
#
# or `sudo scripts/family-lan-proof.sh /path/to/vox` for another binary.
#
# What runs as root, and why: `vox lan helper` (it creates the utun interfaces — that is
# its whole job) and this script's own bookkeeping (killing what it started, `ifconfig`
# and `netstat` snapshots). Every `vox` node, every profile and every probe socket runs as
# the account that invoked sudo, with profiles in a fresh temporary directory: this never
# opens ~/Library/Application Support/vox. A trap stops everything it started, by PID, on
# any exit, and prints the before/after either way.
#
# Why not `dns-sd -B`: this Mac has ONE mDNSResponder, which listens on every interface at
# once, so a service registered "on bob" is browsable "from alice" without a packet
# crossing anything. A browse here would pass with the LAN switched off. The mDNS check
# below uses sockets bound to one utun each, so the only way a query or an answer gets from
# one to the other is through the LAN. On two machines, `dns-sd -B` is the real check.
#
# Why ping proves one direction: on one machine every address belongs to one kernel, and
# the kernel's own ICMP reply to alice's address is delivered inside that kernel. Only
# sockets bound to an interface (checks 2 and 3) force a packet out of a chosen utun, so
# they are what prove the return direction.

set -uo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "run it with sudo: sudo $0 ${*:-}" >&2
    exit 2
fi
if [[ -z ${SUDO_USER:-} || $SUDO_USER == root ]]; then
    echo "run it with sudo from your own account (it needs SUDO_USER to run the nodes as you)" >&2
    exit 2
fi
if [[ $(uname) != Darwin ]]; then
    echo "this proof is for macOS (utun); the Linux device is not built yet" >&2
    exit 2
fi

REPO=$(cd "$(dirname "$0")/.." && pwd)
VOX=${1:-$REPO/target/release/vox}
PY=/usr/bin/python3
[[ -x $VOX ]] || { echo "no vox binary at $VOX — cargo build --release -p vox-tui" >&2; exit 2; }
[[ -x $PY ]] || { echo "no $PY (install the Xcode command line tools)" >&2; exit 2; }

AS_USER=(sudo -u "$SUDO_USER")
WORK=$("${AS_USER[@]}" mktemp -d /tmp/vox-lan-proof.XXXXXX)
IDENTITY="lan proof identity"
PIDS=()
IFACES=()
RESULTS=()
FAILED=0
TORN_DOWN=0

say() { printf '\n== %s\n' "$*"; }
pass() { RESULTS+=("PASS  $*"); printf 'PASS  %s\n' "$*"; }
fail() { RESULTS+=("FAIL  $*"); printf 'FAIL  %s\n' "$*"; FAILED=1; }

snapshot() { # $1 = before|after
    ifconfig -l | tr ' ' '\n' | sort >"$WORK/$1.ifaces"
    # Destination, gateway, flags, interface: the Expire column changes by itself.
    netstat -rn | awk 'NF>=4 {print $1, $2, $3, $4}' | sort >"$WORK/$1.routes"
}

# Every `vox` a member runs: as the invoking account, in that member's own temporary
# profile. Never the real one. `voxcmd` fills VOXCMD rather than running anything, so a
# background `vox` is started as a plain command and `$!` is its own PID (sudo, which
# passes a TERM on to vox) — never a subshell that would leave it orphaned when killed.
voxcmd() { # member
    VOXCMD=("${AS_USER[@]}" env
        VOX_DATA_DIR="$WORK/$1/data" VOX_CONFIG_DIR="$WORK/$1/cfg"
        VOX_IDENTITY_PASSPHRASE="$IDENTITY" VOX_ROOM_PASSPHRASE="${ROOM_PP:-}"
        "$VOX")
}
vox_as() { # member args... — in the foreground
    voxcmd "$1"
    shift
    "${VOXCMD[@]}" "$@"
}

bg() { # name command... — background, output to $WORK/<name>.log, PID recorded
    local name=$1
    shift
    "$@" >"$WORK/$name.log" 2>&1 &
    PIDS+=($!)
    eval "PID_$name=$!"
}

wait_line() { # log pattern seconds — print the first matching line
    local log=$1 pat=$2 secs=$3 i
    for ((i = 0; i < secs * 10; i++)); do
        if grep -m1 -E "$pat" "$log" 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    echo "timed out after ${secs}s waiting for /$pat/ in $log:" >&2
    sed 's/^/    /' "$log" >&2
    return 1
}

stop_pid() {
    local p=$1 i
    kill -TERM "$p" 2>/dev/null || return 0
    for ((i = 0; i < 50; i++)); do
        kill -0 "$p" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -KILL "$p" 2>/dev/null
}

teardown() {
    [[ $TORN_DOWN == 1 ]] && return
    TORN_DOWN=1
    say "teardown: stopping ${#PIDS[@]} processes by PID"
    local p
    # The LANs and the helper first, then the rest.
    for p in "${PIDS[@]}"; do stop_pid "$p"; done
    wait 2>/dev/null
    local left=0
    for p in "${PIDS[@]}"; do kill -0 "$p" 2>/dev/null && left=$((left + 1)); done
    echo "processes still running: $left"
    rm -f "$WORK/helper.sock"
    sleep 1
    snapshot after
    say "interfaces before -> after"
    echo "before: $(tr '\n' ' ' <"$WORK/before.ifaces")"
    echo "after:  $(tr '\n' ' ' <"$WORK/after.ifaces")"
    diff "$WORK/before.ifaces" "$WORK/after.ifaces" >/dev/null && echo "(identical)" \
        || diff "$WORK/before.ifaces" "$WORK/after.ifaces" | sed 's/^/    /'
    say "routes: diff of \`netstat -rn\` before -> after (anything here is not ours unless flagged)"
    diff "$WORK/before.routes" "$WORK/after.routes" | sed 's/^/    /' || true
    local stale=""
    for i in "${IFACES[@]}"; do
        grep -qx "$i" "$WORK/after.ifaces" && stale+=" interface:$i"
        grep -qw "$i" "$WORK/after.routes" && stale+=" route-via:$i"
    done
    if [[ -n ${SUBNET4:-} ]] && grep -q "^${SUBNET4%.0/24}" "$WORK/after.routes"; then stale+=" route:$SUBNET4"; fi
    if [[ -n ${PREFIX6:-} ]] && grep -qi "^${PREFIX6%%::*}" "$WORK/after.routes"; then stale+=" route:$PREFIX6"; fi
    if [[ ${#IFACES[@]} -eq 0 ]]; then
        fail "teardown: no interface was ever made, so there was nothing to tear down"
    elif [[ -z $stale && $left == 0 ]]; then
        pass "teardown: ${#IFACES[@]} utuns (${IFACES[*]}) gone, no route to ${SUBNET4:-?} or ${PREFIX6:-?} left, 0 processes left"
    else
        fail "teardown: left behind:$stale (processes: $left)"
    fi
    say "summary"
    printf '%s\n' "${RESULTS[@]}"
    echo
    echo "logs and profiles (test passphrases only): $WORK"
}
trap 'rc=$?; teardown; [[ $rc != 0 ]] && FAILED=1; exit $FAILED' EXIT
trap 'echo "interrupted"; FAILED=1; exit 1' INT TERM

snapshot before
say "before: $(wc -l <"$WORK/before.ifaces" | tr -d ' ') interfaces, $(wc -l <"$WORK/before.routes" | tr -d ' ') routes"

# ---- the probe: sockets bound to one interface each (IP_BOUND_IF) ----
cat >"$WORK/probe.py" <<'PYEOF'
import json, socket, struct, sys, time
IP_BOUND_IF = 25          # <netinet/in.h>, macOS
NAME = b"vox-lan-proof"

def bind_if(s, ifname):
    s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(ifname))

def udp(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    bind_if(s, ifname)
    return s

def qname(name):
    return b"".join(bytes([len(p)]) + p for p in name.split(b".")) + b"\0"

def mdns(ifname, addr):
    s = udp(ifname)
    s.bind(("", 5353))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                 socket.inet_aton("224.0.0.251") + socket.inet_aton(addr))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(addr))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    return s

def until(s, secs):
    end = time.time() + secs
    while time.time() < end:
        s.settimeout(max(0.05, end - time.time()))
        try:
            yield s.recvfrom(65535)
        except socket.timeout:
            return

cmd, a = sys.argv[1], sys.argv[2:]
if cmd == "udp-listen":          # ifname port secs tag
    ifname, port, secs, tag = a[0], int(a[1]), float(a[2]), a[3].encode()
    s = udp(ifname); s.bind(("", port))
    got = [src[0] for data, src in until(s, secs) if data.startswith(tag)]
    print(json.dumps({"got": len(got), "from": sorted(set(got))}))
elif cmd == "udp-send":          # ifname src dst port count tag
    ifname, src, dst, port, n, tag = a[0], a[1], a[2], int(a[3]), int(a[4]), a[5].encode()
    s = udp(ifname); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.bind((src, 0))
    sent = 0
    for i in range(n):
        try:
            s.sendto(tag + b" %d" % i, (dst, port)); sent += 1
        except OSError as e:
            print(json.dumps({"error": str(e)}), file=sys.stderr)
        time.sleep(0.05)
    print(json.dumps({"sent": sent}))
elif cmd == "udp-echo-server":   # ifname port secs
    ifname, port, secs = a[0], int(a[1]), float(a[2])
    s = udp(ifname); s.bind(("", port)); n = 0
    for data, src in until(s, secs):
        s.sendto(data, src); n += 1
    print(json.dumps({"echoed": n}))
elif cmd == "udp-echo-client":   # ifname src dst port count
    ifname, src, dst, port, n = a[0], a[1], a[2], int(a[3]), int(a[4])
    s = udp(ifname); s.bind((src, 0)); back = 0
    for i in range(n):
        s.sendto(b"echo %d" % i, (dst, port))
        for data, _ in until(s, 0.5):
            if data == b"echo %d" % i:
                back += 1
                break
    print(json.dumps({"sent": n, "echoed_back": back}))
elif cmd == "tcp-listen":        # ifname port secs
    ifname, port, secs = a[0], int(a[1]), float(a[2])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_if(s, ifname); s.bind(("", port)); s.listen(8); n = 0
    end = time.time() + secs
    while time.time() < end:
        s.settimeout(max(0.05, end - time.time()))
        try:
            c, _ = s.accept(); n += 1; c.close()
        except socket.timeout:
            break
    print(json.dumps({"accepted": n}))
elif cmd == "tcp-connect":       # ifname src dst port timeout
    ifname, src, dst, port, t = a[0], a[1], a[2], int(a[3]), float(a[4])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind_if(s, ifname); s.bind((src, 0)); s.settimeout(t)
    try:
        s.connect((dst, port)); ok = True
    except OSError:
        ok = False
    print(json.dumps({"connected": ok}))
elif cmd == "mdns-respond":      # ifname addr secs
    ifname, addr, secs = a[0], a[1], float(a[2])
    s = mdns(ifname, addr); answered = 0
    for data, src in until(s, secs):
        flags = struct.unpack("!H", data[2:4])[0] if len(data) >= 12 else 0x8000
        if flags & 0x8000 == 0 and qname(NAME + b".local") in data:
            ans = (struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + qname(NAME + b".local")
                   + struct.pack("!HHIH", 1, 0x8001, 120, 4) + socket.inet_aton(addr))
            s.sendto(ans, ("224.0.0.251", 5353)); answered += 1
    print(json.dumps({"answered": answered}))
elif cmd == "mdns-query":        # ifname addr secs
    ifname, addr, secs = a[0], a[1], float(a[2])
    s = mdns(ifname, addr)
    q = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + qname(NAME + b".local") + struct.pack("!HH", 1, 1)
    answers, end = set(), time.time() + secs
    while time.time() < end and not answers:
        s.sendto(q, ("224.0.0.251", 5353))
        for data, src in until(s, 1.0):
            flags = struct.unpack("!H", data[2:4])[0] if len(data) >= 12 else 0
            name = qname(NAME + b".local")
            if flags & 0x8000 and name in data:
                i = data.index(name) + len(name)
                if data[i:i + 2] == b"\0\1" and len(data) >= i + 14:
                    answers.add(socket.inet_ntoa(data[i + 10:i + 14]))
    print(json.dumps({"answers": sorted(answers)}))
elif cmd == "mdns-listen":       # ifname addr secs
    ifname, addr, secs = a[0], a[1], float(a[2])
    s = mdns(ifname, addr)
    heard = sum(1 for data, _ in until(s, secs) if NAME in data)
    print(json.dumps({"heard": heard}))
PYEOF
chown "$SUDO_USER" "$WORK/probe.py"
PROBE=("${AS_USER[@]}" "$PY" "$WORK/probe.py")
probe() { "${PROBE[@]}" "$@"; }
jget() { # file python-expression-over-d
    "$PY" -c "import json,sys; d=json.load(open(sys.argv[1])); print($2)" "$1"
}

# ---- the room: an anchor, alice's room, bob and carol joined ----
say "setting up the room (production Argon2id and a real proof of work: a few minutes)"
for m in anchor alice bob carol; do "${AS_USER[@]}" mkdir -p "$WORK/$m/cfg"; done
voxcmd anchor
bg anchor "${VOXCMD[@]}" node --listen 127.0.0.1:0
ANCHOR=$(wait_line "$WORK/anchor.log" '^ *[A-Za-z0-9]+@/ip4/' 180 | tr -d '[:space:]') || exit 1
echo "anchor $ANCHOR"
for m in alice bob carol; do
    FP=$(vox_as "$m" id | tr -d '[:space:]') || { fail "vox id ($m)"; exit 1; }
    eval "FP_$m=$FP"
    echo "$m $FP"
done
vox_as alice trust add "$FP_bob" --name bob >/dev/null && vox_as bob trust add "$FP_alice" --name alice >/dev/null \
    && vox_as carol trust add "$FP_alice" --name alice >/dev/null && vox_as carol trust add "$FP_bob" --name bob >/dev/null \
    || { fail "trust add"; exit 1; }
echo "alice <-> bob trust each other; carol trusts both; nobody trusts carol"
voxcmd alice
bg serve "${VOXCMD[@]}" serve 9/udp --name lan --anchor "$ANCHOR" --listen 127.0.0.1:0
# Everything after the label: a generated passphrase may hold spaces.
ROOM=$(wait_line "$WORK/serve.log" '^room ' 300 | sed -E 's/^room +//') || exit 1
ADDRESS=$(wait_line "$WORK/serve.log" '^address ' 60 | sed -E 's/^address +//') || exit 1
ROOM_PP=$(wait_line "$WORK/serve.log" '^passphrase ' 60 | sed -E 's/^passphrase +//') || exit 1
echo "room $ROOM"
for m in bob carol; do
    vox_as "$m" connect "$ADDRESS" --passphrase "$ROOM_PP" --anchor "$ANCHOR" --listen 127.0.0.1:0 \
        >"$WORK/connect-$m.log" 2>&1 || { fail "vox connect ($m): $(tail -3 "$WORK/connect-$m.log")"; exit 1; }
    echo "$m joined"
    # PRD-001 D8: a one-shot `vox connect` leaves the host deaf for up to its 30 s
    # handshake bound, so the next join waits it out (as the proofs' harness does).
    [[ $m == bob ]] && sleep 35
done
stop_pid "$PID_serve"

# ---- the helper (root) and three LANs (not root) ----
# The decider's rule: nothing is reachable over the LAN unless its port is listed. The
# checks' own ports are listed; 47040 and 47041 are the unlisted ones check 6 knocks on.
ALLOW=47010,47011,47030
say "vox lan helper (root) and three vox lan up (as $SUDO_USER), each --allow $ALLOW"
bg helper "$VOX" lan helper --socket "$WORK/helper.sock"
wait_line "$WORK/helper.log" 'serving uid' 30 || exit 1
for m in alice bob carol; do
    voxcmd "$m"
    bg "lan_$m" "${VOXCMD[@]}" lan up "$ROOM" --anchor "$ANCHOR" --listen 127.0.0.1:0 \
        --helper-socket "$WORK/helper.sock" --stats-file "$WORK/$m.json" \
        --allow "$ALLOW"
done
for m in alice bob carol; do
    LINE=$(wait_line "$WORK/lan_$m.log" '^vox lan up on utun' 300) || exit 1
    IF=$(echo "$LINE" | awk '{print $5}')
    IFACES+=("$IF")
    eval "IF_$m=$IF"
    echo "$m: $LINE"
done
for m in alice bob carol; do
    for ((i = 0; i < 100; i++)); do
        [[ -s $WORK/$m.json ]] && break
        sleep 0.1
    done
    eval "V4_$m=$(jget "$WORK/$m.json" 'd["addresses"]["v4"]')"
done
SUBNET4=$(jget "$WORK/alice.json" 'd["subnet_v4"]')
PREFIX6=$(jget "$WORK/alice.json" 'd["prefix_v6"]')
BCAST=${SUBNET4%.0/24}.255
echo "LAN $SUBNET4 $PREFIX6 — alice $V4_alice on $IF_alice, bob $V4_bob on $IF_bob, carol $V4_carol on $IF_carol"
say "helper said"
sed 's/^/    /' "$WORK/helper.log"
say "the interfaces"
for i in "${IFACES[@]}"; do ifconfig "$i" | sed 's/^/    /'; done
netstat -rn | grep -E "$(IFS='|'; echo "${IFACES[*]}")" | sed 's/^/    /'

say "waiting for alice and bob to link (carol must not)"
for ((i = 0; i < 1200; i++)); do
    A=$(jget "$WORK/alice.json" "'$FP_bob' in d['links']")
    B=$(jget "$WORK/bob.json" "'$FP_alice' in d['links']")
    [[ $A == True && $B == True ]] && break
    sleep 0.1
done
[[ $A == True && $B == True ]] || { fail "alice and bob never linked"; exit 1; }
sleep 3
CAROL_LINKS=$(jget "$WORK/carol.json" 'len(d["links"])')
echo "alice<->bob linked; carol's links: $CAROL_LINKS"

counter() { jget "$WORK/$1.json" "d['$2']"; }

# ---- 1. ping ----
say "1. ping -b $IF_alice -S $V4_alice $V4_bob"
# What arrives on bob's interface is what bob's LAN wrote into it: the capture is the
# evidence the requests crossed, not the ping's success.
tcpdump -l -n -i "$IF_bob" icmp >"$WORK/ping-capture.txt" 2>/dev/null &
TCPDUMP=$!
PIDS+=("$TCPDUMP")
sleep 1
B0=$(counter bob from_peers)
ping -c 5 -i 0.2 -t 10 -b "$IF_alice" -S "$V4_alice" "$V4_bob" | sed 's/^/    /'
PING=${PIPESTATUS[0]}
sleep 1
stop_pid "$TCPDUMP"
SEEN=$(grep -c "$V4_alice > $V4_bob: ICMP echo request" "$WORK/ping-capture.txt")
DB=$(($(counter bob from_peers) - B0))
echo "on $IF_bob: $SEEN echo requests from $V4_alice; bob's LAN: +$DB packets from alice"
if [[ $PING == 0 && $SEEN -ge 5 && $DB -ge 5 ]]; then
    pass "ping: 5/5 answered, and all 5 requests arrived on bob's interface through the LAN"
else
    fail "ping: exit $PING, $SEEN requests on $IF_bob, bob's LAN +$DB (0 means the kernel answered without the LAN)"
fi

# ---- 2. UDP echo, both directions through the LAN ----
say "2. UDP echo: alice ($IF_alice) -> bob ($IF_bob) and back"
A0=$(counter alice from_peers); B0=$(counter bob from_peers)
"${PROBE[@]}" udp-echo-server "$IF_bob" 47010 8 >"$WORK/echo-server.json" &
PIDS+=($!)
sleep 1
ECHO=$(probe udp-echo-client "$IF_alice" "$V4_alice" "$V4_bob" 47010 10)
sleep 1
DA=$(($(counter alice from_peers) - A0)); DB=$(($(counter bob from_peers) - B0))
echo "client: $ECHO; alice's LAN +$DA from bob, bob's LAN +$DB from alice"
BACK=$(echo "$ECHO" | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["echoed_back"])')
if [[ $BACK -ge 9 && $DA -ge 9 && $DB -ge 9 ]]; then
    pass "udp echo: $BACK/10 came back, crossing both ways (bob's LAN +$DB, alice's LAN +$DA)"
else
    fail "udp echo: $BACK/10 back, bob's LAN +$DB, alice's LAN +$DA"
fi

# ---- 3. mDNS ----
say "3. mDNS: query vox-lan-proof.local on alice, responder on bob, carol listening"
"${PROBE[@]}" mdns-respond "$IF_bob" "$V4_bob" 12 >"$WORK/mdns-respond.json" &
PIDS+=($!)
"${PROBE[@]}" mdns-listen "$IF_carol" "$V4_carol" 12 >"$WORK/mdns-carol.json" &
PIDS+=($!)
sleep 1
Q=$(probe mdns-query "$IF_alice" "$V4_alice" 8)
sleep 4
echo "alice's query: $Q; bob's responder: $(cat "$WORK/mdns-respond.json"); carol heard: $(cat "$WORK/mdns-carol.json")"
GOT=$(echo "$Q" | "$PY" -c "import json,sys; print('$V4_bob' in json.load(sys.stdin)['answers'])")
HEARD=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["heard"])' "$WORK/mdns-carol.json" 2>/dev/null || echo "?")
if [[ $GOT == True && $HEARD == 0 ]]; then
    pass "mdns: alice resolved vox-lan-proof.local to bob's $V4_bob; carol heard 0 packets"
else
    fail "mdns: answer from bob: $GOT; carol heard: $HEARD"
fi

# ---- 4. broadcast ----
say "4. UDP broadcast to $BCAST from alice; bob and carol listening"
"${PROBE[@]}" udp-listen "$IF_bob" 47020 6 "vox-bcast" >"$WORK/bcast-bob.json" &
PIDS+=($!)
"${PROBE[@]}" udp-listen "$IF_carol" 47020 6 "vox-bcast" >"$WORK/bcast-carol.json" &
PIDS+=($!)
sleep 1
probe udp-send "$IF_alice" "$V4_alice" "$BCAST" 47020 10 "vox-bcast" >/dev/null
sleep 5
BB=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["got"])' "$WORK/bcast-bob.json")
BC=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["got"])' "$WORK/bcast-carol.json")
echo "bob got $BB/10, carol got $BC/10"
if [[ $BB -ge 9 && $BC == 0 ]]; then
    pass "broadcast: bob got $BB/10, carol 0"
else
    fail "broadcast: bob $BB/10, carol $BC"
fi

# ---- 5. the untrusted member ----
say "5. carol sends to alice and bob, unicast and broadcast"
CO0=$(counter carol from_os)
"${PROBE[@]}" udp-listen "$IF_alice" 47030 6 "vox-carol" >"$WORK/carol-alice.json" &
PIDS+=($!)
"${PROBE[@]}" udp-listen "$IF_bob" 47030 6 "vox-carol" >"$WORK/carol-bob.json" &
PIDS+=($!)
sleep 1
probe udp-send "$IF_carol" "$V4_carol" "$V4_alice" 47030 10 "vox-carol" >/dev/null
probe udp-send "$IF_carol" "$V4_carol" "$V4_bob" 47030 10 "vox-carol" >/dev/null
probe udp-send "$IF_carol" "$V4_carol" "$BCAST" 47030 10 "vox-carol" >/dev/null
sleep 4
CA=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["got"])' "$WORK/carol-alice.json")
CB=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["got"])' "$WORK/carol-bob.json")
CL=$(jget "$WORK/carol.json" 'len(d["links"])'); CC=$(counter carol flood_copies); CP=$(counter carol to_peers)
CO=$(($(counter carol from_os) - CO0))
echo "alice got $CA/20, bob got $CB/20; carol's LAN: took $CO from carol's kernel, $CL links, $CP unicast sent, $CC flood copies"
# The attempt must be real: carol's packets entered carol's LAN (CO), and went nowhere.
if [[ $CO -ge 30 && $CA == 0 && $CB == 0 && $CL == 0 && $CC == 0 && $CP == 0 ]]; then
    pass "untrusted: carol's LAN took her 30 packets and delivered 0; she has 0 links"
else
    fail "untrusted: carol's LAN took $CO, alice got $CA, bob $CB, carol links $CL, sent $CP, flood copies $CC"
fi

# ---- 6. the port whitelist ----
say "6. whitelist: alice knocks on bob's unlisted 47040/udp and 47041/tcp, and on listed 47011/tcp"
F0=$(counter bob filtered)
"${PROBE[@]}" udp-listen "$IF_bob" 47040 5 "vox-unlisted" >"$WORK/wl-udp.json" &
PIDS+=($!)
"${PROBE[@]}" tcp-listen "$IF_bob" 47041 8 >"$WORK/wl-tcp-unlisted.json" &
PIDS+=($!)
"${PROBE[@]}" tcp-listen "$IF_bob" 47011 8 >"$WORK/wl-tcp-listed.json" &
PIDS+=($!)
sleep 1
probe udp-send "$IF_alice" "$V4_alice" "$V4_bob" 47040 10 "vox-unlisted" >/dev/null
UNLISTED=$(probe tcp-connect "$IF_alice" "$V4_alice" "$V4_bob" 47041 3)
LISTED=$(probe tcp-connect "$IF_alice" "$V4_alice" "$V4_bob" 47011 5)
sleep 5
WU=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["got"])' "$WORK/wl-udp.json")
DF=$(($(counter bob filtered) - F0))
echo "unlisted udp: bob got $WU/10; unlisted tcp: $UNLISTED; listed tcp: $LISTED; bob's LAN filtered +$DF"
if [[ $WU == 0 && $UNLISTED == *false* && $LISTED == *true* && $DF -ge 11 ]]; then
    pass "whitelist: unlisted ports got 0 (bob's LAN filtered $DF), the listed port connected, discovery (3, 4) crossed on unlisted ports"
else
    fail "whitelist: unlisted udp $WU/10, unlisted tcp $UNLISTED, listed tcp $LISTED, filtered +$DF"
fi

say "counters"
for m in alice bob carol; do
    echo "$m: $(jget "$WORK/$m.json" '{k: v for k, v in d.items() if isinstance(v, int)}')"
done

# ---- 6. teardown (the trap runs it, and prints the summary) ----
exit 0
