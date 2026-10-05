#!/usr/bin/env bash
# Build Vox.app for release, ad-hoc signed with each target's entitlements embedded, and print
# its path (ADR-014 M-27). The Developer ID signature is applied later, inside-out, by
# scripts/sign_notarize_app.sh, after scripts/assemble-macos-app.sh has put the release's
# signed `vox` at Contents/Helpers/vox; the Xcode project copies no vox and has no Developer ID
# settings.
#
#   scripts/build-macos-app.sh DERIVED_DATA_DIR
#
# Apple Silicon only, macOS 13 floor (M-26a): the XCFramework is built with its macOS slice
# alone, and xcodebuild with ARCHS=arm64. The Rust library is built here, not by Xcode.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 DERIVED_DATA_DIR" >&2
  exit 2
fi
derived=$1
fail() {
  echo "build Vox.app: $*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ $(uname -s) == Darwin ]] || fail "needs macOS"
[[ -d apps/macos/Vox.xcodeproj ]] || fail "apps/macos/Vox.xcodeproj is missing"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
[[ "$MACOSX_DEPLOYMENT_TARGET" == 13.0 ]] || \
  fail "MACOSX_DEPLOYMENT_TARGET is $MACOSX_DEPLOYMENT_TARGET; the macOS floor is 13.0"

# The macOS slice only: a release builds nothing for iOS and nothing for Intel.
XCFRAMEWORK_SLICES=macos scripts/build-xcframework.sh >&2

# Every line of xcodebuild's output goes to stderr: stdout carries only the app's path.
xcodebuild -project apps/macos/Vox.xcodeproj -scheme Vox -configuration Release \
  -derivedDataPath "$derived" ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
  MACOSX_DEPLOYMENT_TARGET="$MACOSX_DEPLOYMENT_TARGET" \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual build >&2

app="$derived/Build/Products/Release/Vox.app"
[[ -d "$app" ]] || fail "xcodebuild finished but $app is missing"
printf '%s\n' "$app"
