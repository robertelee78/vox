#!/bin/sh
# Run one FX-28 mutant against the shipped-binary journey. A useful mutant run succeeds only when
# that one faulty behavior makes the journey terminate with an attributed PRODUCT red.
set -eu

case "${1-}" in
  preview-approval-not-durable|stopped-reader-fresh-write|stale-flight-clears-newer|stale-tick-authority)
    mutant=$1
    ;;
  *)
    printf '%s\n' "usage: $0 preview-approval-not-durable|stopped-reader-fresh-write|stale-flight-clears-newer|stale-tick-authority" >&2
    exit 2
    ;;
esac

artifact_dir=${VOX_FX28_MUTANT_ARTIFACTS:-target/fx28-mutants}
mkdir -p "$artifact_dir"
artifact="$artifact_dir/$mutant.log"
export VOX_TEST_FX28_MUTANT=$mutant

set +e
cargo test --release -p vox-tui \
  --features optional-proofs,test-knobs \
  --test nodes_of_one_daemon_proof \
  two_paired_computers_that_are_idle_exchange_nothing \
  -- --ignored --exact --nocapture >"$artifact" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
  printf 'APPARATUS: FX-28 mutant %s stayed green; output: %s\n' "$mutant" "$artifact" >&2
  exit 1
fi
if ! grep -q 'PRODUCT:' "$artifact"; then
  printf 'APPARATUS: FX-28 mutant %s stopped without an attributed PRODUCT red; output: %s\n' "$mutant" "$artifact" >&2
  exit 1
fi
printf 'FX-28 mutant %s: independent PRODUCT red (%s)\n' "$mutant" "$artifact"
