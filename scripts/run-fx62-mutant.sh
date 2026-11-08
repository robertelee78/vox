#!/bin/sh
# Each mutation must fail its own native-consumer assertion, not staging or a watchdog.
set -eu
case "${1-}" in
  pairwise-equality-only)
    journey=a_queued_key_and_history_debt_cannot_cross_room_removal
    verdict='PRODUCT [FX62 queued-key]:' ;;
  old-entitlement|readmission-full-plan)
    journey=a_queued_key_and_history_debt_cannot_cross_room_removal
    verdict='PRODUCT [FX62 history-debt]:' ;;
  nonadmin-remove)
    journey=an_admin_removes_one_member_and_the_creator_readmits_it_forward_only
    verdict='PRODUCT [FX62 nonadmin]:' ;;
  skip-reconnect-removal-check)
    journey=an_admin_removes_one_member_and_the_creator_readmits_it_forward_only
    verdict='PRODUCT [FX62 reconnect]:' ;;
  admit-removed-fingerprint)
    journey=an_admin_removes_one_member_and_the_creator_readmits_it_forward_only
    verdict='PRODUCT [FX62 old-passphrase]:' ;;
  *) printf 'usage: sh scripts/run-fx62-mutant.sh {pairwise-equality-only|old-entitlement|readmission-full-plan|nonadmin-remove|skip-reconnect-removal-check|admit-removed-fingerprint}\n' >&2; exit 2 ;;
esac
mutant=$1
artifacts=${VOX_FX62_MUTANT_ARTIFACTS:-target/fx62-mutants}
case "$artifacts" in
  /*) ;;
  *) artifacts="$PWD/$artifacts" ;;
esac
CARGO_HOME=${CARGO_HOME:-"$HOME/.cargo"}
RUSTUP_HOME=${RUSTUP_HOME:-"$HOME/.rustup"}
mkdir -p "$artifacts/home"
artifact="$artifacts/$mutant.log"
set +e
env -u PI_SESSION_ID -u PI_SESSION_FILE -u PI_TOOL_CALL_ID -u VOX_NODE -u CLAUDECODE \
  CARGO_HOME="$CARGO_HOME" RUSTUP_HOME="$RUSTUP_HOME" HOME="$artifacts/home" \
  VOX_DATA_DIR="$artifacts/home/data" VOX_CONFIG_DIR="$artifacts/home/config" \
  VOX_MUTANT_FX62="$mutant" cargo test --release -p vox-tui --features test-knobs \
  --test a_room_can_be_left_and_ended_proof "$journey" -- --ignored --exact --nocapture \
  >"$artifact" 2>&1
status=$?
set -e
if [ "$status" -eq 0 ] || ! grep -F "$verdict" "$artifact" >/dev/null; then
  printf 'APPARATUS: FX62 mutant %s did not reach its own %s; transcript %s\n' "$mutant" "$verdict" "$artifact" >&2
  exit 1
fi
printf 'FX62 mutant %s: intended consumer verdict %s (%s)\n' "$mutant" "$verdict" "$artifact"
