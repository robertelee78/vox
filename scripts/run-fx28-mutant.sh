#!/bin/sh
# Run one FX-28 mutant against the shipped-binary journey. A useful mutant run succeeds only when
# that one faulty behavior makes the journey terminate with an attributed PRODUCT red.
set -eu

case "${1-}" in
  preview-approval-not-durable)
    mutant=$1
    journey=computer_preview_and_approval_survive_a_crash
    verdict='PRODUCT [FX28 preview-approval-crash]:'
    staging='[proof] FX-28 preview-approval-crash apparatus staged:'
    ;;
  stopped-reader-fresh-write)
    mutant=$1
    journey=two_paired_computers_that_are_idle_exchange_nothing
    verdict='PRODUCT [FX28 stopped-reader-write]:'
    staging='[proof] FX-28 stopped-reader apparatus staged:'
    ;;
  stale-tick-authority)
    mutant=$1
    journey=two_paired_computers_that_are_idle_exchange_nothing
    verdict='PRODUCT [FX28 stale-tick-authority]:'
    staging='[proof] FX-28 stale-tick-authority apparatus staged:'
    ;;
  late-application-abandons-work)
    mutant=$1
    journey=two_paired_computers_that_are_idle_exchange_nothing
    verdict='PRODUCT [FX28 late-application]:'
    staging='[proof] FX-28 late-application apparatus staged:'
    ;;
  stale-join-authority)
    mutant=$1
    journey=two_paired_computers_that_are_idle_exchange_nothing
    verdict='PRODUCT [FX28 stale-join-authority]:'
    staging='[proof] FX-28 stale-join-authority apparatus staged:'
    ;;
  ready-fence-accepts-unsettled)
    mutant=$1
    journey=computer_pairing_uses_an_anchor_without_room_membership_and_reconnects
    verdict='PRODUCT [FX28 startup-ready-state-lock]:'
    staging='[proof] FX-28 startup Ready state-lock apparatus staged:'
    ;;
  stale-post-authority)
    mutant=$1
    journey=two_paired_computers_that_are_idle_exchange_nothing
    verdict='PRODUCT [FX28 stale-post-authority]:'
    staging='[proof] FX-28 stale-post-authority apparatus staged:'
    ;;
  stale-room-create-authority)
    mutant=$1
    journey=two_paired_computers_that_are_idle_exchange_nothing
    verdict='PRODUCT [FX28 stale-room-create-authority]:'
    staging='[proof] FX-28 stale-room-create-authority apparatus staged:'
    ;;
  stale-trust-projection)
    mutant=$1
    journey=two_paired_computers_that_are_idle_exchange_nothing
    verdict='PRODUCT [FX28 stale-trust-projection]:'
    staging='[proof] FX-28 stale-trust-projection apparatus staged:'
    ;;
  stale-rekey-authority)
    mutant=$1
    journey=two_paired_computers_that_are_idle_exchange_nothing
    verdict='PRODUCT [FX28 stale-rekey-authority]:'
    staging='[proof] FX-28 stale-rekey-authority apparatus staged:'
    ;;
  legacy-ended-unanswered-not-selected)
    mutant=$1
    journey=two_paired_computers_that_are_idle_exchange_nothing
    verdict='PRODUCT [FX28 legacy-rekey-route]:'
    staging='[proof] FX-28 legacy rekey route apparatus staged:'
    ;;
  *)
    printf '%s\n' "usage: $0 preview-approval-not-durable|stopped-reader-fresh-write|stale-tick-authority|late-application-abandons-work|stale-join-authority|ready-fence-accepts-unsettled|stale-post-authority|stale-room-create-authority|stale-trust-projection|stale-rekey-authority|legacy-ended-unanswered-not-selected" >&2
    exit 2
    ;;
esac

artifact_dir=${VOX_FX28_MUTANT_ARTIFACTS:-target/fx28-mutants}
mkdir -p "$artifact_dir"
run_dir=$(mktemp -d "$artifact_dir/$mutant.XXXXXXXX")
artifact="$run_dir/proof.log"
# The proof's pre-main isolation scrubs inherited product knobs. This is a proof-run setting;
# its daemon helper explicitly maps it to VOX_TEST_FX28_MUTANT only on scratch product children.
export VOX_MUTANT_FX28="$mutant"

set +e
cargo test --release -p vox-tui \
  --features optional-proofs,test-knobs \
  --test nodes_of_one_daemon_proof \
  "$journey" \
  -- --ignored --exact --nocapture >"$artifact" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
  printf 'APPARATUS: FX-28 mutant %s stayed green; output: %s\n' "$mutant" "$artifact" >&2
  exit 1
fi
count_fixed() {
  awk -v needle="$1" '
    {
      rest = $0
      while ((at = index(rest, needle)) != 0) {
        count++
        rest = substr(rest, at + length(needle))
      }
    }
    END { print count + 0 }
  ' "$artifact"
}

intended_count=$(count_fixed "$verdict")
product_count=$(count_fixed 'PRODUCT')
apparatus_count=$(count_fixed 'APPARATUS')
panic_count=$(count_fixed "panicked at")
if [ "$intended_count" -ne 1 ] || [ "$product_count" -ne 1 ] || \
   [ "$apparatus_count" -ne 0 ] || [ "$panic_count" -ne 1 ]; then
  printf 'APPARATUS: FX-28 mutant %s did not stop at its sole exact PRODUCT verdict (intended=%s PRODUCT=%s APPARATUS=%s panics=%s); output: %s\n' \
    "$mutant" "$intended_count" "$product_count" "$apparatus_count" "$panic_count" "$artifact" >&2
  exit 1
fi
staging_count=$(count_fixed "$staging")
staging_line=$(grep -nF "$staging" "$artifact" | head -n 1 | cut -d: -f1 || true)
verdict_line=$(grep -nF "$verdict" "$artifact" | head -n 1 | cut -d: -f1 || true)
if [ "$staging_count" -ne 1 ] || [ -z "$staging_line" ] || [ -z "$verdict_line" ] || \
   [ "$staging_line" -ge "$verdict_line" ]; then
  printf 'APPARATUS: FX-28 mutant %s did not prove its one exact causal staging event before its PRODUCT verdict; output: %s\n' "$mutant" "$artifact" >&2
  exit 1
fi
printf 'FX-28 mutant %s: intended independent verdict %s (%s)\n' "$mutant" "$verdict" "$artifact"
