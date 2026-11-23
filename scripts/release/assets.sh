#!/usr/bin/env bash
# Default is DRY: print exact commands. Execute only after the coordinator authorizes journeys.
set -euo pipefail
harness=${1:?compiled host install_sh_proof harness from integrated RG-11 source}
dist=${2:?candidate asset directory}
out=${3:?new evidence directory}
execute=${4:---dry-run}
[[ $execute == --dry-run || $execute == --execute ]] || exit 2
slot=/opt/vox-evidence/v0431/exec/with-build-slot.sh
for arm in the_linux_release_asset_installs_only_where_it_runs the_linux_release_installer_refuses_below_its_floor the_linux_release_installer_names_a_missing_loader; do
  cmd=(env VOX_SLOT_PRIORITY=3 VOX_PROOF_DIST="$dist" "$slot" rg11assets -- "$harness" "$arm" --ignored --exact --nocapture)
  printf '%q ' "${cmd[@]}"; printf '\n'
  [[ $execute == --execute ]] || continue
  mkdir -p "$out"
  "$harness" --list | grep -Fx "$arm: test" >/dev/null || { echo "APPARATUS: exact asset arm absent: $arm" >&2; exit 2; }
  printf '%q ' "${cmd[@]}" >"$out/$arm.command"; printf '\n' >>"$out/$arm.command"
  set +e
  "${cmd[@]}" >"$out/$arm.log" 2>&1
  rc=$?
  set -e
  printf '%s\n' "$rc" >"$out/$arm.exit"
  cat "$out/$arm.log"
  [[ $rc == 0 ]] || exit "$rc"
done
