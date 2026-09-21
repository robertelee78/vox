#!/bin/sh
# Package one target's release assets — ADR-015 §"Install and update".
#
#   scripts/package-release.sh <built-binary> <target-triple>
#
# Writes into ./dist:
#   vox-<triple>          the binary, mode 0755
#   vox-<triple>.sha256   the digest, for a human checking by hand
#   stable-<triple>.json  the release record `vox update` and install.sh read
#   proof-<triple>.json   the same record with a deliberately wrong digest
#
# The `proof` record is not a mistake. ADR-018 §3 requires that a refusal be proved rather
# than assumed, and the updater's "this download does not match the record" refusal cannot be
# proved against a record that is correct. It is published on its own channel, which nothing
# selects by default, so no install can ever resolve it by accident. `vox update`'s digest
# check is what it exists to exercise.
#
# POSIX sh; runs on both GitHub runners.
set -eu

BIN="${1:?usage: package-release.sh <binary> <triple>}"
TRIPLE="${2:?usage: package-release.sh <binary> <triple>}"
ASSET="vox-${TRIPLE}"

if command -v sha256sum >/dev/null 2>&1; then
  sha_of() { sha256sum "$1" | cut -d' ' -f1; }
  sha_file() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  sha_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
  sha_file() { shasum -a 256 "$1"; }
else
  printf 'package-release: need sha256sum or shasum\n' >&2; exit 1
fi

mkdir -p dist
cp "$BIN" "dist/$ASSET"
chmod 0755 "dist/$ASSET"
( cd dist && sha_file "$ASSET" > "${ASSET}.sha256" )

# The workspace version is the single source of truth; the publish job checks it against the tag.
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
SIZE=$(stat -c %s "dist/$ASSET" 2>/dev/null || stat -f %z "dist/$ASSET")
SHA=$(sha_of "dist/$ASSET")
[ -n "$VERSION" ] && [ -n "$SIZE" ] && [ -n "$SHA" ] \
  || { printf 'package-release: could not determine version/size/sha\n' >&2; exit 1; }

record() {
  printf '{"kind":"vox.standalone-release","schema_version":1,"package":"vox","channel":"%s","target":"%s","version":"%s","size":%s,"sha256":"%s"%s}\n' \
    "$1" "$TRIPLE" "$VERSION" "$SIZE" "$2" "$3"
}
record stable "$SHA" '' > "dist/stable-${TRIPLE}.json"
record proof "$(printf '0%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64)" \
  ',"note":"deliberately wrong sha256 so vox update mismatch refusal can be proved (ADR-018)"' \
  > "dist/proof-${TRIPLE}.json"

cat "dist/stable-${TRIPLE}.json"
cat "dist/proof-${TRIPLE}.json"
ls -l dist
