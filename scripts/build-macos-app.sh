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

# **No build log may carry the environment.** By default Xcode prints a script phase's whole
# environment (`export …` lines) into the build log, and in release.yml that environment is the
# runner's. Every script phase must say `showEnvVarsInLog = 0`, or the build stops here.
python3 - apps/macos/Vox.xcodeproj/project.pbxproj <<'EOF' || fail "a script phase would print the environment into the build log"
import re, sys
text = open(sys.argv[1]).read()
bad = []
# Each object is `<id> /* name */ = { … };`; a script phase says `isa = PBXShellScriptBuildPhase;`.
for m in re.finditer(r'(\w+)(?: /\* ([^*]*) \*/)? = \{\s*isa = PBXShellScriptBuildPhase;(.*?)\n\t\t\};', text, re.S):
    if not re.search(r'\bshowEnvVarsInLog = 0;', m.group(3)):
        bad.append(m.group(2) or m.group(1))
phases = len(re.findall(r'isa = PBXShellScriptBuildPhase;', text))
seen = len(list(re.finditer(r'= \{\s*isa = PBXShellScriptBuildPhase;', text)))
if seen != phases:
    print(f"build Vox.app: {phases - seen} script phase(s) could not be read; refusing", file=sys.stderr)
    sys.exit(1)
for name in bad:
    print(f"build Vox.app: script phase {name!r} lacks showEnvVarsInLog = 0", file=sys.stderr)
sys.exit(1 if bad else 0)
EOF

# The workspace version is the single source of truth (package-release.sh): the app is built as
# that version whatever the project's MARKETING_VERSION says, so the tag, vox and Vox.app agree.
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "cannot read the workspace version from Cargo.toml"

# The macOS slice only: a release builds nothing for iOS and nothing for Intel.
XCFRAMEWORK_SLICES=macos scripts/build-xcframework.sh >&2

# Quiet (warnings and errors only), and to stderr: stdout carries only the app's path.
xcodebuild -quiet -project apps/macos/Vox.xcodeproj -scheme Vox -configuration Release \
  -derivedDataPath "$derived" ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
  MACOSX_DEPLOYMENT_TARGET="$MACOSX_DEPLOYMENT_TARGET" \
  MARKETING_VERSION="$VERSION" \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual build >&2

app="$derived/Build/Products/Release/Vox.app"
[[ -d "$app" ]] || fail "xcodebuild finished but $app is missing"
printf '%s\n' "$app"
