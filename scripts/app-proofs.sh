#!/usr/bin/env bash
# Run Vox.app's proofs (ADR-014 M-30, ADR-018): an XCUITest suite, apps/macos/VoxAppProofs, that
# launches the built Vox.app with a scratch data root and config directory, against a real
# `vox daemon` run from the same bundle, and asserts what is on screen through accessibility.
#
#   scripts/app-proofs.sh                     # every proof
#   scripts/app-proofs.sh FirstRunProof       # one class (xcodebuild's -only-testing)
#   scripts/app-proofs.sh LaunchProof         # scripts/app-launch-proof.py alone: no UI automation
#
# It builds the macOS slice of VoxFFI.xcframework, the release `vox`, and the app; puts `vox` in
# the bundle at Contents/Helpers/vox and signs the bundle ad hoc, inside out; then runs the suite.
# Optional: it blocks nothing, and needs UI automation allowed on this Mac (developer mode, and
# the approval macOS asks for on the first run).
#
# Local macOS hosts with Xcode 27 / sccache: set CARGO_PROFILE_RELEASE_STRIP=none and
# RUSTC_WRAPPER= (see scripts/build-xcframework.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DERIVED="$ROOT/target/xcode"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/vox-app-proofs.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT

XCFRAMEWORK_SLICES=macos scripts/build-xcframework.sh
cargo build --release --bin vox

xcodebuild -project apps/macos/Vox.xcodeproj -scheme Vox -configuration Release \
    -derivedDataPath "$DERIVED" ARCHS=arm64 CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual \
    build-for-testing

APP="$DERIVED/Build/Products/Release/Vox.app"
mkdir -p "$APP/Contents/Helpers"
cp target/release/vox "$APP/Contents/Helpers/vox"
codesign --force --sign - --options runtime --identifier us.vox.cli "$APP/Contents/Helpers/vox"
codesign --force --sign - --options runtime --preserve-metadata=entitlements "$APP"

# The launch proof (#438) drives no UI, so it needs no automation approval: it runs first, alone
# when asked for by name.
launch_status=0
if [ "$#" -eq 0 ] || [ "$*" = "LaunchProof" ]; then
    python3 scripts/app-launch-proof.py "$APP" || launch_status=$?
    if [ "$*" = "LaunchProof" ]; then
        exit "$launch_status"
    fi
else
    # Loud when not run: an optional proof never reads as a pass.
    echo "app-proofs: OPTIONAL PROOF NOT RUN: LaunchProof (scripts/app-launch-proof.py);" \
        "run it with: scripts/app-proofs.sh LaunchProof" >&2
fi

only=()
for class in "$@"; do
    only+=("-only-testing:VoxAppProofs/$class")
done
# Every red names its side: a red the suite reports is the product's or the proof's own, said in
# its failure message (PRODUCT: or APPARATUS:); a runner that never started is the machine's.
status=0
TEST_RUNNER_VOX_PROOF_APP="$APP" TEST_RUNNER_VOX_PROOF_SCRATCH="$SCRATCH" \
    xcodebuild -project apps/macos/Vox.xcodeproj -scheme Vox -configuration Release \
    -derivedDataPath "$DERIVED" ${only[@]+"${only[@]}"} test-without-building \
    2>&1 | tee "$SCRATCH/xcodebuild.log" || status=$?
if grep -q "enabling automation mode" "$SCRATCH/xcodebuild.log"; then
    echo "app-proofs: APPARATUS (precondition unmet): UI automation is not allowed on this Mac, so" \
        "no proof ran. Allow it once: sudo DevToolsSecurity -enable, then approve the prompt" \
        "macOS shows on the next run." >&2
    exit 2
fi
[ "$status" -ne 0 ] && exit "$status"
exit "$launch_status"
