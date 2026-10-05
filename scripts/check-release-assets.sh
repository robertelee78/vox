#!/bin/sh
# Refuse to publish a release whose assets are not exactly what ADR-015 §17 and ADR-014 §5 say a
# release is. release.yml's publish job runs this on the assembled release directory; it runs the
# same on a Mac against a locally packaged directory.
#
#   scripts/check-release-assets.sh <release-dir> <version>
#
# A release is, per target, `vox-<triple>`, its `.sha256`, `stable-<triple>.json` and
# `proof-<triple>.json`, for x86_64-unknown-linux-gnu and aarch64-apple-darwin and nothing else
# (ADR-014 M-26a: no Intel macOS asset at all). On macOS it is also Vox.app, as
# `Vox-<version>-aarch64-apple-darwin.zip` with `app-stable-` and `app-proof-` records, and two
# signing receipts: `apple-proof-aarch64-apple-darwin.json` for vox and
# `apple-proof-app-aarch64-apple-darwin.json` for the app. Each receipt must attest a notarized
# build of this version, each record's digest must be its receipt's, and the app's helper must be
# the published vox. Either macOS artifact without the other is a refusal (ADR-028 I-3).
#
# POSIX sh and jq; runs on the ubuntu publish runner and on a Mac.
set -eu

DIR="${1:?usage: check-release-assets.sh <release-dir> <version>}"
VERSION="${2:?usage: check-release-assets.sh <release-dir> <version>}"
MAC=aarch64-apple-darwin
TARGETS="x86_64-unknown-linux-gnu $MAC"
APP_ZIP="Vox-${VERSION}-${MAC}.zip"

fail() { printf 'release assets: %s\n' "$*" >&2; ls -l "$DIR" >&2 || true; exit 1; }
command -v jq >/dev/null 2>&1 || fail "need jq"
[ -d "$DIR" ] || fail "$DIR is not a directory"

# Exactly the expected set of names, so an Intel asset, a stray file or a missing one all refuse.
want=$(
  for t in $TARGETS; do
    printf '%s\n' "vox-$t" "vox-$t.sha256" "stable-$t.json" "proof-$t.json"
  done
  printf '%s\n' "$APP_ZIP" "$APP_ZIP.sha256" "app-stable-$MAC.json" "app-proof-$MAC.json" \
    "apple-proof-$MAC.json" "apple-proof-app-$MAC.json" install.sh
)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
printf '%s\n' "$want" | sort >"$TMP/want"
find "$DIR" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort >"$TMP/got"
missing=$(comm -23 "$TMP/want" "$TMP/got")
extra=$(comm -13 "$TMP/want" "$TMP/got")
[ -z "$missing" ] || fail "missing: $(printf "%s" "$missing" | tr "\n" " ")"
[ -z "$extra" ] || fail "not part of a release: $(printf "%s" "$extra" | tr "\n" " ")"

# Every record carries this version, or `vox update` would resolve the wrong tag.
for r in "$DIR"/stable-*.json "$DIR"/proof-*.json "$DIR"/app-stable-*.json "$DIR"/app-proof-*.json; do
  grep -q "\"version\":\"${VERSION}\"" "$r" || fail "$(basename "$r") is not for ${VERSION}: $(cat "$r")"
done
jq -e '.kind == "vox.app-release" and .package == "Vox.app"' "$DIR/app-stable-$MAC.json" >/dev/null \
  || fail "app-stable-$MAC.json is not a Vox.app record"

# Both receipts attest a Developer ID signed, notarized build of this version. A missing or
# unattested receipt is a macOS artifact nobody can show was notarized (ADR-018 §3).
for r in "apple-proof-$MAC.json:vox:vox-$MAC" "apple-proof-app-$MAC.json:Vox.app:$APP_ZIP"; do
  file=${r%%:*}; rest=${r#*:}; package=${rest%%:*}; asset=${rest#*:}
  jq -e --arg v "$VERSION" --arg asset "$asset" '
    .kind == "vox.apple-release-proof"
    and .version == $v
    and .asset.name == $asset
    and .asset.minimum_macos == "13.0"
    and .signing.authority == "Developer ID Application"
    and .signing.hardened_runtime == true
    and .signing.secure_timestamp == true
    and .notarization.status == "Accepted"
    and .verification.codesign == "accepted"
    and .verification.online_notarization == "accepted"
    and .verification.notary_ticket_cdhash_matches == true
  ' "$DIR/$file" >/dev/null || fail "$file does not attest a notarized $package ${VERSION}: $(cat "$DIR/$file")"
done
jq -e '(.package // "vox") == "vox"' "$DIR/apple-proof-$MAC.json" >/dev/null \
  || fail "apple-proof-$MAC.json is not vox's receipt"
jq -e '.package == "Vox.app" and .notarization.stapled == true
       and .helper.path == "Contents/Helpers/vox"' "$DIR/apple-proof-app-$MAC.json" >/dev/null \
  || fail "apple-proof-app-$MAC.json does not attest a stapled Vox.app carrying vox"

# Each record's digest describes the signed bytes that shipped.
vox_signed=$(jq -er .asset.sha256 "$DIR/apple-proof-$MAC.json")
[ "$(jq -er .sha256 "$DIR/stable-$MAC.json")" = "$vox_signed" ] \
  || fail "stable-$MAC.json's digest is not the signed vox's"
[ "$(jq -er .sha256 "$DIR/app-stable-$MAC.json")" = "$(jq -er .asset.sha256 "$DIR/apple-proof-app-$MAC.json")" ] \
  || fail "app-stable-$MAC.json's digest is not the signed app's"
# One binary of one version: the app's helper is the published vox.
[ "$(jq -er .helper.sha256 "$DIR/apple-proof-app-$MAC.json")" = "$vox_signed" ] \
  || fail "the app's Contents/Helpers/vox is not the published vox-$MAC"

printf 'release assets: %s holds a complete %s release\n' "$DIR" "$VERSION"
