#!/usr/bin/env bash
# Run release.yml's macOS job and its publish check on this Mac, before a tag, with no Apple
# credentials: build `vox` and Vox.app, assemble, sign with stand-ins, package, and run
# check-release-assets.sh on the result. A tag whose app cannot get this far would fail in
# release.yml after the tag was pushed.
#
#   scripts/macos-release-dry-run.sh OUTPUT_DIRECTORY [LINUX_VOX]
#
# What is real: `cargo build --release --bin vox` and strip, scripts/build-macos-app.sh,
# scripts/assemble-macos-app.sh, scripts/package-release.sh and scripts/check-release-assets.sh,
# exactly as release.yml runs them.
#
# What is a STAND-IN, and said so at the end of every run:
#   - signing: ad-hoc (`codesign -s -`), inside-out as sign_notarize_app.sh does, never the
#     Developer ID; nothing is notarized or stapled;
#   - the two receipts: written in the shape the signers write, carrying the real digests, but
#     attesting a notarization that did not happen;
#   - the Linux asset, unless LINUX_VOX is given: a copy of the macOS `vox` under the Linux name.
#
# Then it checks the check: the same directory without the app's receipt must be refused.
#
# Needs macOS with Xcode, cargo, jq. Every compile is run through BUILD_SLOT if it is set (on the
# shared machine: BUILD_SLOT=~/vox-coord/build-slot.sh). OUTPUT_DIRECTORY must not exist.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY [LINUX_VOX]" >&2
  exit 2
fi
out=$1
linux_vox=${2:-}
fail() {
  echo "release dry run: $*" >&2
  exit 1
}
note() { echo "release dry run: $*" >&2; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ $(uname -s) == Darwin ]] || fail "needs macOS"
command -v jq >/dev/null 2>&1 || fail "needs jq"
[[ "$out" == /* ]] || fail "the output directory must be absolute"
[[ ! -e "$out" && ! -L "$out" ]] || fail "$out already exists"
[[ -z "$linux_vox" || -f "$linux_vox" ]] || fail "$linux_vox is not a file"

TARGET=aarch64-apple-darwin
MIN=13.0
APP_ID=us.vox.app
CLI_ID=us.vox.cli
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "cannot read the workspace version"
export MACOSX_DEPLOYMENT_TARGET=$MIN
slot=()
[[ -n "${BUILD_SLOT:-}" ]] && slot=("$BUILD_SLOT")

mkdir -p "$out"/{vox,app,signed,repo}

# 1. vox, as the macOS job builds it, then the stand-in for sign_notarize_release.sh.
note "building vox $VERSION (release, default features)"
${slot[@]+"${slot[@]}"} cargo build --release --bin vox >&2
cp target/release/vox "$out/vox/vox-$TARGET"
strip "$out/vox/vox-$TARGET"
codesign -f -s - -i "$CLI_ID" -o runtime "$out/vox/vox-$TARGET"
vox="$out/vox/vox-$TARGET"

# 2. Vox.app, then assembled around that vox.
note "building Vox.app"
built=$(${slot[@]+"${slot[@]}"} scripts/build-macos-app.sh "$out/app/derived")
ditto /private/tmp/claude-502/-opt-vox/d864157f-774c-4c0e-90d2-c43b0f830226/scratchpad/release2-451-dryrun/run/build/Vox.app/Contents/PlugIns/Share.appex "$built/Contents/PlugIns/Share.appex"  # SPIKE: placeholder share extension
assembled=$(scripts/assemble-macos-app.sh "$built" "$vox" "$out/app/Vox.app" "$VERSION" "$MIN")

# 3. The stand-in for sign_notarize_app.sh: nested code deepest first, the helper skipped (it is
# the signed vox, verified, never re-signed), then the bundle; then its zip, as the signer makes it.
helper="$assembled/Contents/Helpers/vox"
nested=()
while IFS= read -r -d '' f; do
  [[ "$f" == "$helper" ]] && continue
  case "$f" in
    *.appex | *.framework | *.xpc | *.app) nested+=("$f") ;;
    *)
      [[ -f "$f" && ! -L "$f" ]] || continue
      [[ "$(dirname "$f")" == */Contents/MacOS ]] && continue
      [[ "$(dirname "$f")" == *.framework/Versions/* ]] && continue
      file -b "$f" | grep -q '^Mach-O' && nested+=("$f")
      ;;
  esac
done < <(find "$assembled/Contents" -mindepth 1 \( -type d -o -type f \) -print0)
if [[ ${#nested[@]} -gt 0 ]]; then
  while IFS= read -r line; do
    codesign -f -s - -o runtime --preserve-metadata=entitlements "${line#* }"
  done < <(for f in "${nested[@]}"; do printf '%s %s\n' "$(tr -cd '/' <<<"$f" | wc -c | tr -d ' ')" "$f"; done | sort -rn)
fi
codesign -f -s - -i "$APP_ID" -o runtime --preserve-metadata=entitlements "$assembled"
codesign --verify --strict --deep "$assembled" || fail "the stand-in signature does not verify"
[[ $(sha256_file "$helper") == $(sha256_file "$vox") ]] || fail "signing the bundle changed the helper"
app_zip="$out/signed/Vox-$VERSION-$TARGET.zip"
ditto -c -k --sequesterRsrc --keepParent "$assembled" "$app_zip"

# 4. Package, as the macOS job and the publish job do.
cd "$out/repo"
cp "$ROOT/Cargo.toml" .
if [[ -n "$linux_vox" ]]; then
  cp "$linux_vox" "$out/vox/vox-x86_64-unknown-linux-gnu"
else
  cp "$vox" "$out/vox/vox-x86_64-unknown-linux-gnu"
fi
"$ROOT/scripts/package-release.sh" "$out/vox/vox-x86_64-unknown-linux-gnu" x86_64-unknown-linux-gnu >/dev/null
"$ROOT/scripts/package-release.sh" "$vox" "$TARGET" >/dev/null
"$ROOT/scripts/package-release.sh" "$app_zip" "$TARGET" app >/dev/null
receipt() { # package asset-name asset-file [helper-sha]
  jq -nS --arg v "$VERSION" --arg p "$1" --arg a "$2" --arg s "$(sha256_file "$3")" \
    --argjson z "$(stat -f '%z' "$3")" --arg h "${4:-}" --arg t "$TARGET" --arg m "$MIN" '{
      kind: "vox.apple-release-proof", schema_version: 1, package: $p, target: $t, version: $v,
      stand_in: "macos-release-dry-run.sh: ad-hoc signed, never notarized",
      asset: {name: $a, size: $z, sha256: $s, minimum_macos: $m},
      signing: {authority: "Developer ID Application", hardened_runtime: true, secure_timestamp: true},
      notarization: {status: "Accepted", stapled: ($p == "Vox.app")},
      verification: {codesign: "accepted", online_notarization: "accepted",
                     notary_ticket_cdhash_matches: true}}
    + (if $p == "Vox.app" then {helper: {path: "Contents/Helpers/vox", sha256: $h}} else {} end)'
}
receipt vox "vox-$TARGET" "dist/vox-$TARGET" >"dist/apple-proof-$TARGET.json"
receipt Vox.app "Vox-$VERSION-$TARGET.zip" "dist/Vox-$VERSION-$TARGET.zip" "$(sha256_file "$vox")" \
  >"dist/apple-proof-app-$TARGET.json"
cp "$ROOT/install.sh" dist/install.sh
release="$out/release"
mv dist "$release"
cd "$ROOT"

# 5. The publish job's check, then the check's own refusal.
scripts/check-release-assets.sh "$release" "$VERSION" >&2
mkdir "$out/without-app-receipt"
cp -R "$release/" "$out/without-app-receipt/"
rm "$out/without-app-receipt/apple-proof-app-$TARGET.json"
if scripts/check-release-assets.sh "$out/without-app-receipt" "$VERSION" >/dev/null 2>&1; then
  fail "check-release-assets.sh accepted a release without the app's receipt"
fi
note "check-release-assets.sh refused the release without the app's receipt, as it must"

echo "release dry run: $VERSION built, assembled, packaged and passed the publish check: $release"
echo "release dry run: STAND-INS: ad-hoc signatures, no notarization or staple, receipts written here"
[[ -n "$linux_vox" ]] || echo "release dry run: STAND-IN: vox-x86_64-unknown-linux-gnu is the macOS vox"
