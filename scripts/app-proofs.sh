#!/usr/bin/env bash
# Run Vox.app's proofs (ADR-014 M-30, ADR-018): an XCUITest suite, apps/macos/VoxAppProofs, that
# launches the built Vox.app with a scratch data root and config directory, against a real
# `vox daemon` run from the same bundle, and asserts what is on screen through accessibility.
#
#   scripts/app-proofs.sh                     # every proof
#   scripts/app-proofs.sh FirstRunProof       # one class (xcodebuild's -only-testing)
#   scripts/app-proofs.sh LaunchProof         # scripts/app-launch-proof.py alone: no UI automation
#   VOX_PROOF_APP=/path/to/Vox.app scripts/app-proofs.sh
#                                             # against that app: the signed release candidate
#
# It builds the macOS slice of VoxFFI.xcframework, the release `vox`, and the app; puts `vox` in
# the bundle at Contents/Helpers/vox and signs the bundle ad hoc, inside out; then runs the suite.
# With VOX_PROOF_APP it still builds the proofs, but proves that app, unchanged (ADR-014 M-30: the
# signed release build).
# Optional: it blocks nothing. Preconditions, the person's to arrange, never the suite's:
#   - UI automation allowed on this Mac (developer mode, and the approval macOS asks for once);
#   - Vox allowed to notify (System Settings, Notifications), and no Focus on, for the
#     notification step;
#   - nothing else of the person's listening on what the proofs bind (they bind free ports).
# The real data root is never touched: every node, daemon and the app run in a scratch data root
# and config directory, removed at the end.
#
# Local macOS hosts with Xcode 27 / sccache: set CARGO_PROFILE_RELEASE_STRIP=none and
# RUSTC_WRAPPER= (see scripts/build-xcframework.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DERIVED="$ROOT/target/xcode"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/vox-app-proofs.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT

# **Never the person's own Vox** (APPARATUS before anything runs). A login item registered on this
# Mac runs the bundle's `vox daemon` under launchd, with none of this run's scratch directories:
# on the person's real profile. And whatever the run does, the real data root and config
# directory must be as they were: listed (names, sizes, times; never contents) before and after.
REAL="$HOME/Library/Application Support/vox"
if launchctl print "gui/$(id -u)/us.vox.daemon" >/dev/null 2>&1; then
    echo "app-proofs: APPARATUS (precondition unmet): a Vox login item (us.vox.daemon) is loaded on" \
        "this Mac, and it runs on the real profile; turn it off (System Settings, General, Login" \
        "Items, Vox) before a run" >&2
    exit 2
fi
real_listing() {
    if [ -e "$REAL" ]; then find "$REAL" -exec stat -f '%N %z %m' {} + | sort; else echo absent; fi
}
REAL_BEFORE="$(real_listing)"
check_real() {
    if [ "$(real_listing)" != "$REAL_BEFORE" ]; then
        echo "app-proofs: APPARATUS: the run changed the real profile ($REAL): a Vox started without" \
            "this run's scratch directories (a crash dialog's Reopen does that: click Ignore), or" \
            "the person used Vox meanwhile. Before:" >&2
        echo "$REAL_BEFORE" >&2
        echo "After:" >&2
        real_listing >&2
        return 1
    fi
}

XCFRAMEWORK_SLICES=macos scripts/build-xcframework.sh
cargo build --release --bin vox

xcodebuild -project apps/macos/Vox.xcodeproj -scheme Vox -configuration Release \
    -derivedDataPath "$DERIVED" ARCHS=arm64 CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual \
    build-for-testing

if [ -n "${VOX_PROOF_APP:-}" ]; then
    APP="$(cd "$VOX_PROOF_APP" && pwd)"
    [ -x "$APP/Contents/Helpers/vox" ] || {
        echo "app-proofs: APPARATUS: $APP holds no Contents/Helpers/vox" >&2
        exit 2
    }
    codesign --verify --strict "$APP" || {
        echo "app-proofs: APPARATUS: $APP's signature does not check out" >&2
        exit 2
    }
else
    APP="$DERIVED/Build/Products/Release/Vox.app"
    mkdir -p "$APP/Contents/Helpers"
    cp target/release/vox "$APP/Contents/Helpers/vox"
    codesign --force --sign - --options runtime --identifier us.vox.cli "$APP/Contents/Helpers/vox"
    codesign --force --sign - --options runtime --preserve-metadata=entitlements "$APP"
fi

# The launch proof (#438) drives no UI, so it needs no automation approval: it runs first, alone
# when asked for by name.
launch_status=0
if [ "$#" -eq 0 ] || [ "$*" = "LaunchProof" ]; then
    python3 scripts/app-launch-proof.py "$APP" || launch_status=$?
    if [ "$*" = "LaunchProof" ]; then
        check_real || exit 2
        exit "$launch_status"
    fi
else
    # Loud when not run: an optional proof never reads as a pass.
    echo "app-proofs: OPTIONAL PROOF NOT RUN: LaunchProof (scripts/app-launch-proof.py);" \
        "run it with: scripts/app-proofs.sh LaunchProof" >&2
fi

# The stager (apparatus): Xcode signs the UI-test runner into the app sandbox, and whatever a test
# starts inherits it, so a test's `vox daemon` could not write its scratch data root. The stager
# runs, outside the sandbox, what the proofs stage, on loopback, for whoever holds its token.
TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
python3 scripts/app-proof-stager.py "$SCRATCH/stager.port" "$TOKEN" &
STAGER=$!
trap 'kill "$STAGER" 2>/dev/null; wait "$STAGER" 2>/dev/null; rm -rf "$SCRATCH"' EXIT
for _ in $(seq 1 100); do [ -s "$SCRATCH/stager.port" ] && break; sleep 0.1; done
[ -s "$SCRATCH/stager.port" ] || {
    echo "app-proofs: APPARATUS: the stager did not start" >&2
    exit 2
}

only=()
for class in "$@"; do
    only+=("-only-testing:VoxAppProofs/$class")
done
# Every red names its side: a red the suite reports is the product's or the proof's own, said in
# its failure message (PRODUCT: or APPARATUS:); a runner that never started is the machine's.
status=0
TEST_RUNNER_VOX_PROOF_APP="$APP" TEST_RUNNER_VOX_PROOF_SCRATCH="$SCRATCH" \
    TEST_RUNNER_VOX_PROOF_STAGER_PORT="$(cat "$SCRATCH/stager.port")" \
    TEST_RUNNER_VOX_PROOF_STAGER_TOKEN="$TOKEN" \
    xcodebuild -project apps/macos/Vox.xcodeproj -scheme Vox -configuration Release \
    -derivedDataPath "$DERIVED" ${only[@]+"${only[@]}"} test-without-building \
    2>&1 | tee "$SCRATCH/xcodebuild.log" || status=$?
check_real || exit 2
if grep -q "enabling automation mode" "$SCRATCH/xcodebuild.log"; then
    echo "app-proofs: APPARATUS (precondition unmet): UI automation is not allowed on this Mac, so" \
        "no proof ran. Allow it once: sudo DevToolsSecurity -enable, then approve the prompt" \
        "macOS shows on the next run." >&2
    exit 2
fi
[ "$status" -ne 0 ] && exit "$status"
exit "$launch_status"
