#!/bin/sh
# Run one FX-29 mutant against its shipped-binary journey. Success
# means the causal staging line precedes this mutant's exact PRODUCT red; any other stop is an
# apparatus failure, not mutant evidence.
set -eu

case "${VOX_TEST_WATCHDOG_SECS-}" in
  ''|*[!0-9]*|0)
    printf '%s\n' \
      'APPARATUS: set VOX_TEST_WATCHDOG_SECS to an operator-chosen positive whole-proof deadman; it never decides a PRODUCT verdict' >&2
    exit 2
    ;;
esac

case "${1-}" in
  drop-resume-owed)
    mutant=$1
    verdict='PRODUCT [FX29 archive-resume-owner]:'
    staging='[proof] FX-29 archive authorization-stale Control-busy apparatus staged:'
    ;;
  finish-control-after-effect)
    mutant=$1
    verdict='PRODUCT [FX29 sparse-control-publication]:'
    staging='[proof] FX-29 sparse control publication apparatus staged:'
    ;;
  *)
    printf '%s\n' "usage: $0 {drop-resume-owed|finish-control-after-effect}" >&2
    exit 2
    ;;
esac

artifact_dir=${VOX_FX29_MUTANT_ARTIFACTS:-target/fx29-mutants}
mkdir -p "$artifact_dir"
artifact="$artifact_dir/$mutant.log"
export VOX_TEST_FX29_MUTANT=$mutant

set +e
cargo test --release -p vox-tui \
  --features optional-proofs,test-knobs \
  --test a_newcomer_reads_the_whole_history_proof \
  a_quiet_room_costs_no_rounds_and_says_when_it_last_synced \
  -- --ignored --exact --nocapture >"$artifact" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
  printf 'APPARATUS: FX-29 mutant %s stayed green; output: %s\n' "$mutant" "$artifact" >&2
  exit 1
fi
staging_line=$(grep -nF "$staging" "$artifact" | head -n 1 | cut -d: -f1 || true)
verdict_line=$(grep -nF "$verdict" "$artifact" | head -n 1 | cut -d: -f1 || true)
if [ -z "$staging_line" ] || [ -z "$verdict_line" ] || [ "$staging_line" -ge "$verdict_line" ]; then
  printf 'APPARATUS: FX-29 mutant %s did not reach its causally staged verdict %s; output: %s\n' \
    "$mutant" "$verdict" "$artifact" >&2
  exit 1
fi
printf 'FX-29 mutant %s: intended independent verdict %s (%s)\n' \
  "$mutant" "$verdict" "$artifact"
