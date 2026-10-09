#!/usr/bin/env bash
# Run Vox.app's proofs (ADR-014 M-30, ADR-018): an XCUITest suite, apps/macos/VoxAppProofs, that
# launches the built Vox.app with a scratch data root and config directory, against a real
# `vox daemon` run from the same bundle, and asserts what is on screen through accessibility.
#
#   scripts/app-proofs.sh                     # every proof
#   scripts/app-proofs.sh FirstRunProof       # one class (xcodebuild's -only-testing)
#   scripts/app-proofs.sh LaunchProof         # scripts/app-launch-proof.py alone: no UI automation
#   VOX_PROOF_APP=<any other Vox.app>         # refused before anything runs (see below)
#
# It builds the macOS slice of VoxFFI.xcframework, the release `vox`, and the app; puts `vox` in
# the bundle at Contents/Helpers/vox and signs the bundle ad hoc, inside out; then runs the suite.
# It proves only the app it builds: XCTest launches any other bundle without the proofs'
# environment, on the account's real data root, so VOX_PROOF_APP naming one is refused.
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
# **The person's clipboard is put back as it was** (v0.4.1): the proofs paste and copy through the
# general pasteboard. Every item and type is kept here and restored at exit, red, green or a crash
# of the runner (each case restores it too, in its tearDown).
osascript -l JavaScript "$ROOT/scripts/pasteboard-keep.js" save "$SCRATCH/pasteboard.plist" >/dev/null || {
    echo "app-proofs: APPARATUS: cannot keep the clipboard to put it back after the run; not running" >&2
    exit 2
}
trap 'osascript -l JavaScript "$ROOT/scripts/pasteboard-keep.js" restore "$SCRATCH/pasteboard.plist" >/dev/null \
          || echo "app-proofs: the clipboard could not be put back: $SCRATCH/pasteboard.plist is lost with the scratch" >&2
      rm -rf "$SCRATCH"' EXIT

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
# Nor one that is registered and allowed but not loaded yet: launchd would start it at the next
# login, or as soon as anything enables it. `sfltool dumpbtm` reads the background items without
# privileges; a us.vox.daemon item whose disposition says "allowed" (not "disallowed") refuses.
if /usr/bin/sfltool dumpbtm </dev/null 2>/dev/null | awk '
    /Disposition:/ { d = $0 }
    /Identifier:[ \t]+8\.us\.vox\.daemon$/ && d !~ /disallowed/ { found = 1 }
    END { exit !found }'; then
    echo "app-proofs: APPARATUS (precondition unmet): a Vox login item (us.vox.daemon) is" \
        "registered and allowed on this Mac, and it runs on the real profile; switch Vox off under" \
        "System Settings, General, Login Items & Extensions, Allow in the Background, before a run" >&2
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

# **Preflight: everything this run needs, checked in seconds, before any build.**
# The app this run proves: the one it builds here, only. XCTest launches any other bundle (a
# release, signed or re-signed ad hoc, at any other path) through NSWorkspace and drops its
# environment, so that app opens the account's real data root: refused before anything is built
# or launched (APPARATUS), fail closed. VOX_PROOF_APP naming this build's own product is the same
# as not setting it.
APP="$DERIVED/Build/Products/Release/Vox.app"
if [ -n "${VOX_PROOF_APP:-}" ]; then
    given="$(cd "$VOX_PROOF_APP" 2>/dev/null && pwd -P || true)"
    product="$(mkdir -p "$DERIVED/Build/Products/Release" && cd "$DERIVED/Build/Products/Release" && pwd -P)/Vox.app"
    if [ "$given" != "$product" ]; then
        echo "app-proofs: APPARATUS (precondition unmet): VOX_PROOF_APP=$VOX_PROOF_APP is not this" \
            "build's own Vox.app ($product); XCTest would launch it without this run's environment," \
            "on the account's real data root, so nothing was built or launched" >&2
        exit 2
    fi
    unset VOX_PROOF_APP
fi
# **A proof build is not Vox** (#571): it is built as us.vox.app.proof, named "Vox Proof" (its
# share extension us.vox.app.proof.share), so the person's own Vox.app (us.vox.app), which may be
# installed and running, is never the one a lookup, a notification or XCTest reaches. No other
# proof build may be registered (APPARATUS before anything runs): LaunchServices opens a
# registered one for a notification click, Spotlight or Launchpad with none of this run's scratch
# directories. Only this run's own build may be, and it is unregistered when the run ends.
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
vox_registrations() {
    "$LSREGISTER" -dump 2>/dev/null \
        | awk '/^path:/{p=$0} /identifier: +us\.vox\.app\.proof$/{print p}' \
        | sed -E 's/^path: *//; s/ \(0x[0-9a-f]+\)$//' | sort -u
}
STRAY="$(vox_registrations | grep -vxF "$APP" || true)"
if [ -n "$STRAY" ]; then
    echo "app-proofs: APPARATUS (precondition unmet): other Vox Proof builds (us.vox.app.proof)" \
        "are registered with LaunchServices, and any of them can be opened on the real profile;" \
        "unregister them" \
        "(lsregister -u <path>, registration only) before a run:" >&2
    echo "$STRAY" >&2
    exit 2
fi
# UI automation: developer mode on (the one-time approval macOS asks for is not readable here;
# without it xcodebuild says so at once, below).
if ! DevToolsSecurity -status 2>/dev/null | grep -q "enabled"; then
    echo "app-proofs: APPARATUS (precondition unmet): developer mode is off, so UI automation cannot" \
        "run; turn it on (DevToolsSecurity -enable, the person's own step), then run again" >&2
    exit 2
fi
# The build: the commit it is made from, said first, and refused if it is not the one asked for.
HEAD_SHA="$(git rev-parse --short=8 HEAD)"
DIRTY="$(git status --porcelain --untracked-files=no | wc -l | tr -d ' ')"
echo "app-proofs: preflight: building $HEAD_SHA ($DIRTY file(s) changed since it); no login item" \
    "loaded; no other Vox.app registered; developer mode on"
if [ -n "${VOX_PROOF_SHA:-}" ] && [ "${HEAD_SHA}" != "${VOX_PROOF_SHA:0:8}" -o "$DIRTY" != 0 ]; then
    echo "app-proofs: APPARATUS (precondition unmet): asked to prove $VOX_PROOF_SHA, and the tree is" \
        "$HEAD_SHA with $DIRTY file(s) changed" >&2
    exit 2
fi
# Notifications: whether Vox may notify is not readable from a script on this macOS; the
# notification case (FirstRunProof/testNotificationSaysWhoWroteNeverWhat) asks the app first
# and stops at once, APPARATUS, if the app says notifications are off.
echo "app-proofs: preflight: whether Vox may notify is checked first by the notification case"

XCFRAMEWORK_SLICES=macos scripts/build-xcframework.sh
cargo build --release --bin vox

# **The app under proof registers no background item** (#571): built with
# VOX_PROOF_STUB_SERVICES, its login item and its LAN helper are stand-ins that record what was
# asked and register nothing. A real login item runs `vox daemon` under launchd on the real
# profile, and a real LAN helper is a root daemon. A release is never built this way, and
# scripts/assemble-macos-app.sh refuses a bundle carrying the stand-ins.
xcodebuild -project apps/macos/Vox.xcodeproj -scheme Vox -configuration Release \
    -derivedDataPath "$DERIVED" ARCHS=arm64 CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual \
    SWIFT_ACTIVE_COMPILATION_CONDITIONS='$(inherited) VOX_PROOF_STUB_SERVICES' \
    VOX_APP_ID=us.vox.app.proof VOX_APP_NAME="Vox Proof" \
    build-for-testing
built_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
    "$DERIVED/Build/Products/Release/Vox.app/Contents/Info.plist" 2>/dev/null || true)"
[ "$built_id" = us.vox.app.proof ] || {
    echo "app-proofs: APPARATUS: the app under proof is $built_id, not us.vox.app.proof, so it" \
        "would share the person's Vox's identity; not running" >&2
    exit 2
}
grep -q vox-proof-service-stand-in "$DERIVED/Build/Products/Release/Vox.app/Contents/MacOS/Vox" || {
    echo "app-proofs: APPARATUS: the app was built without its stand-in login item and LAN" \
        "helper, so a proof could register real ones; not running" >&2
    exit 2
}

APP="$DERIVED/Build/Products/Release/Vox.app"
mkdir -p "$APP/Contents/Helpers"
cp target/release/vox "$APP/Contents/Helpers/vox"
codesign --force --sign - --options runtime --identifier us.vox.cli "$APP/Contents/Helpers/vox"
codesign --force --sign - --options runtime --preserve-metadata=entitlements "$APP"

trap_unregister() {
    # Any of the app's processes still running are stopped by pid, and its share extension is
    # unregistered with it, so no later LaunchServices lookup or share sheet opens this build.
    for pid in $(pgrep -f "$APP/Contents/MacOS/Vox" || true); do kill "$pid" 2>/dev/null || true; done
    for ext in "$APP"/Contents/PlugIns/*.appex; do
        [ -e "$ext" ] && pluginkit -r "$ext" >/dev/null 2>&1 || true
    done
    "$LSREGISTER" -u "$APP" >/dev/null 2>&1 || true
}

# The launch proof (#438) drives no UI, so it needs no automation approval: it runs first, alone
# when asked for by name.
launch_status=0
if [ "$#" -eq 0 ] || [ "$*" = "LaunchProof" ]; then
    python3 scripts/app-launch-proof.py "$APP" || launch_status=$?
    if [ "$*" = "LaunchProof" ]; then
        trap_unregister
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
# The walkthrough types a keyring change's passphrase at a terminal, as a person does (ADR-028
# K-13), with this driver, run by the stager from the scratch directory.
cp scripts/type-passphrase.py "$SCRATCH/type-passphrase.py"
python3 scripts/app-proof-stager.py "$SCRATCH/stager.port" "$TOKEN" &
STAGER=$!
# A run that goes red keeps its scratch data root (the daemon's log, every node's files) for
# reading the red; a green run removes it.
finish() {
    local status=$?
    kill "$STAGER" 2>/dev/null; wait "$STAGER" 2>/dev/null
    trap_unregister
    if [ "$status" -ne 0 ]; then
        echo "app-proofs: kept for reading the red: $SCRATCH" >&2
    else
        rm -rf "$SCRATCH"
    fi
}
trap finish EXIT
for _ in $(seq 1 100); do [ -s "$SCRATCH/stager.port" ] && break; sleep 0.1; done
[ -s "$SCRATCH/stager.port" ] || {
    echo "app-proofs: APPARATUS: the stager did not start" >&2
    exit 2
}

only=()
for class in "$@"; do
    only+=("-only-testing:VoxAppProofs/$class")
done
# The notification case needs a person at the Mac (Vox allowed to notify, no Focus on): left out
# of a run that names nothing, and said so; run alone, in about a minute, by naming it.
NOTIFY=FirstRunProof/testNotificationSaysWhoWroteNeverWhat
if [ "$#" -eq 0 ]; then
    only+=("-skip-testing:VoxAppProofs/$NOTIFY")
    echo "app-proofs: OPTIONAL PROOF NOT RUN: $NOTIFY (it needs a person at the Mac); run it" \
        "alone with: scripts/app-proofs.sh $NOTIFY" >&2
fi
# Every red names its side: a red the suite reports is the product's or the proof's own, said in
# its failure message (PRODUCT: or APPARATUS:); a runner that never started is the machine's.
status=0
TEST_RUNNER_VOX_PROOF_APP="$APP" TEST_RUNNER_VOX_PROOF_SCRATCH="$SCRATCH" \
    TEST_RUNNER_VOX_PROOF_STAGER_PORT="$(cat "$SCRATCH/stager.port")" \
    TEST_RUNNER_VOX_PROOF_STAGER_TOKEN="$TOKEN" \
    TEST_RUNNER_VOX_PROOF_FROM="${VOX_PROOF_FROM:-}" \
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
