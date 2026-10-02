#!/bin/sh
# Build the **mutant sender** that ADR-025's P9 and P10 proofs run as a faulty peer, and print its
# path on stdout (everything else goes to stderr).
#
#   VOX_MUTANT_SENDER=$(scripts/build-mutant-sender.sh) && export VOX_MUTANT_SENDER
#
# It is `vox` built from this tree with the `mutant-sender` feature of vox-core (see
# `vox_core::log::sync::mutant`): a daemon started with `VOX_MUTANT_SENDER_MODE=serve-nothing` or
# `serve-unasked` breaks the sync protocol in the way the proof needs, which no `vox` command can
# make a correct node do. It is a **separate binary that never ships**: it is copied out to
# `<target>/mutant-sender/vox`, the shipped `<target>/release/vox` is rebuilt with the default
# features at once, and both are checked for the mutant's marker, `VOX-MUTANT-SENDER` —
# present in the mutant, absent from the shipped binary. release.yml builds `--bin vox` with the
# default features, and scripts/package-release.sh refuses any binary that carries the marker.
#
# The feature flip reuses the release build's dependencies, so this costs a rebuild of vox-core and
# vox-tui, not of the workspace. Run by CI (ci.yml, before the `--ignored` gate) and by
# scripts/release-gate.sh. POSIX sh; runs on both GitHub runners.
set -eu

target=${CARGO_TARGET_DIR:-target}
out="$target/mutant-sender"
marker=VOX-MUTANT-SENDER

cargo build --release -p vox-tui --bin vox --features vox-core/mutant-sender >&2
mkdir -p "$out"
cp "$target/release/vox" "$out/vox"
grep -aq "$marker" "$out/vox" || {
  printf 'build-mutant-sender: %s does not carry %s: the feature did not take\n' "$out/vox" "$marker" >&2
  exit 1
}
# Put the shipped binary back before anything runs it.
cargo build --release -p vox-tui --bin vox >&2
if grep -aq "$marker" "$target/release/vox"; then
  printf 'build-mutant-sender: the shipped %s still carries %s\n' "$target/release/vox" "$marker" >&2
  exit 1
fi
# Nor a test-only knob (V210-105): those are compiled in only by `test-knobs`.
if grep -aq 'VOX_TEST_' "$target/release/vox"; then
  printf 'build-mutant-sender: the shipped %s carries a test-only knob (VOX_TEST_)\n' "$target/release/vox" >&2
  exit 1
fi
(cd "$out" && printf '%s/vox\n' "$(pwd -P)")
