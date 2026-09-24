#!/bin/bash
# PRD-001 R40 after a restart: how long does a message posted after a peer's daemon restarts
# take to become readable on that peer?
#
# Two `vox daemon`s (alice, bob), optionally a separate `vox node` anchor. Alice creates a room,
# bob joins, both trust each other, one message crosses. Then bob's daemon is stopped and
# started again (new process, new port), the script waits $WAIT seconds, alice posts, and the
# time until bob's `vox room read` shows the post is printed.
#
#   VOX=target/release/vox ANCHOR=1 WAIT=10 scripts/restart-latency-scenario.sh
#
# ANCHOR=1 puts a separate anchor in the path (the case that is slow: without it alice is bob's
# anchor and the post crosses directly). WAIT=10 posts after bob's first sync on reconnect; WAIT=0
# lands the post inside it. VOX_TRACE_SYNC is passed through to the daemons if a build reads it.
#
# Measured 2026-09-24/25, ANCHOR=1 WAIT=10, nine runs each:
#   main before v0.2.8        4 runs at 20.3-20.6 s, the rest 1.3-2.2 s
#   v0.2.8 (accept-loop-split) 0.64-2.08 s, 5 of 9 over 1 s
# Every process is stopped by its recorded PID; the script prints "0 remain" when it verified it.
set -u
VOX=${VOX:-target/release/vox}
VOX=$(cd "$(dirname "$VOX")" && pwd)/$(basename "$VOX")
WAIT=${WAIT:-10}
ANCHOR=${ANCHOR:-}
T=$(mktemp -d "${TMPDIR:-/tmp}/vox-restart.XXXX")
export VOX_IDENTITY_PASSPHRASE="an identity passphrase"
now() { python3 -c 'import time; print("%.2f" % time.time())'; }
A=$T/a; B=$T/b; mkdir -p "$A/cfg" "$B/cfg"
va() { VOX_DATA_DIR=$A VOX_CONFIG_DIR=$A/cfg "$VOX" "$@"; }
vb() { VOX_DATA_DIR=$B VOX_CONFIG_DIR=$B/cfg "$VOX" "$@"; }
FA=$(va id); FB=$(vb id)
PA=""; PB=""; PN=""
trap 'kill $PA $PB $PN 2>/dev/null' EXIT
ANC=""
if [ -n "$ANCHOR" ]; then
  N=$T/n; mkdir -p "$N/cfg"
  VOX_DATA_DIR=$N VOX_CONFIG_DIR=$N/cfg "$VOX" node --listen 127.0.0.1:0 >"$N/out" 2>"$N/err" </dev/null & PN=$!
  until grep -q "@" "$N/out"; do sleep 0.2; done
  SPEC=$(grep -m1 "@" "$N/out" | tr -d ' '); ANC="--anchor $SPEC"; echo "anchor $SPEC"
fi
startd() {
  local D=$1
  printf '%s\n' "an identity passphrase" "$2" > "$D/pass"
  VOX_DATA_DIR=$D VOX_CONFIG_DIR=$D/cfg "$VOX" daemon --listen 127.0.0.1:0 $ANC \
    --passphrase-file "$D/pass" >>"$D/out" 2>>"$D/err" </dev/null &
  echo $!
}
PA=$(startd "$A" ""); PB=$(startd "$B" "")
until grep -q "control socket" "$A/out" && grep -q "control socket" "$B/out"; do sleep 0.2; done
echo "room pass" | va room create --name mission >/dev/null
ROOM=$(va room list | awk '{for(i=1;i<=NF;i++) if(length($i)>=12 && $i ~ /^[a-z0-9]+$/) {print $i; exit}}')
LINK=$(va room invite "$ROOM")
echo "room pass" | vb room join "$LINK" --name mission >/dev/null
va trust add "$FB" --name bob >/dev/null; vb trust add "$FA" --name alice >/dev/null
va room post "$ROOM" "before restart"
until vb room read "$ROOM" | grep -q "before restart"; do sleep 0.2; done
echo "crossed before restart"

echo "stopping bob at $(now)"; kill "$PB"; while kill -0 "$PB" 2>/dev/null; do sleep 0.1; done
: > "$B/out"
PB=$(startd "$B" "room pass")
until grep -q "control socket" "$B/out"; do sleep 0.2; done
echo "bob restarted: $(grep 'holding room' "$B/out")"
sleep "$WAIT"

POSTED=$(now); echo "posting at $POSTED"
va room post "$ROOM" "after restart"
for _ in $(seq 1 300); do
  if vb room read "$ROOM" 2>/dev/null | grep -q "after restart"; then
    python3 -c "import time; print('after-restart post crossed in %.2fs' % (time.time() - $POSTED))"
    break
  fi
  sleep 0.1
done
vb room read "$ROOM" | grep -q "after restart" || echo "after-restart post NOT crossed in 30s"
kill $PA $PB $PN 2>/dev/null; sleep 1
if ps -p "$PA,$PB${PN:+,$PN}" >/dev/null; then echo "LEFTOVER"; else echo "0 remain"; fi
echo "logs in $T"
