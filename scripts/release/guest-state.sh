#!/usr/bin/env bash
# One guest state, then stop and release it for the other proof owners.
set -euo pipefail
apparatus=$(cd "$(dirname "$0")" && pwd)
cd "${VOX_JOURNEY_SOURCE:?exact integrated proof source required}"
state=${1:?absolute evidence directory}
name=${2:?asset label}
journey=${3:?install|update|busy|controlled-update|readiness}
dist=${4:?absolute asset directory}
expected=${5:-}
candidate=${6:-}
slot=/opt/vox-evidence/v0431/exec/with-build-slot.sh
if [[ $journey == readiness ]]; then
  mkdir /tmp/vox-guest.lock 2>/dev/null || { echo 'APPARATUS: guest lock held; readiness did not start'; exit 2; }
else
  until mkdir /tmp/vox-guest.lock 2>/dev/null; do sleep 20; done
fi
printf 'rg15 %s\n' "$$" >/tmp/vox-guest.lock/owner
cleanup() {
  rc=$?
  if [[ -f $state/started-here ]]; then
    if ! VOX_SLOT_PRIORITY=3 "$slot" rg15 -- python3 "$apparatus/guest.py" stop --state "$state"; then
      echo 'APPARATUS: guest stop unconfirmed; keeping its ownership lock' >&2
      exit 2
    fi
  fi
  rm /tmp/vox-guest.lock/owner
  rmdir /tmp/vox-guest.lock
  exit "$rc"
}
trap cleanup EXIT
start=(python3 "$apparatus/guest.py" start --state "$state" --dist "$dist" --name "$name")
[[ $journey != readiness ]] || start+=(--readiness-only)
[[ ${VOX_PROOF_CLEAN_GUEST_BUILDS:-0} != 1 ]] || start+=(--clean-old-builds)
[[ -z $candidate ]] || start+=(--candidate-name "$name-current" --candidate-dist "$candidate")
VOX_SLOT_PRIORITY=3 "$slot" rg15 -- "${start[@]}"
[[ $journey != readiness ]] || exit 0
if [[ ! -f $state/built ]]; then
  VOX_SLOT_PRIORITY=3 "$slot" rg15 -- python3 "$apparatus/guest.py" build --state "$state"
  touch "$state/built"
fi
args=(python3 "$apparatus/guest.py" run --state "$state" --name "$name" --journey "$journey")
[[ -z $expected ]] || args+=(--expected-version "$expected")
[[ -z $candidate ]] || args+=(--candidate-name "$name-current")
if [[ $journey == busy ]]; then
  VOX_SLOT_PRIORITY=3 VOX_SLOT_EXCLUSIVE=2 "$slot" rg15 -- "${args[@]}"
else
  VOX_SLOT_PRIORITY=3 "$slot" rg15 -- "${args[@]}"
fi
