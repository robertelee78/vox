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
# Both records therefore carry EXACTLY the schema-1 fields and nothing else. `ReleaseRecord`
# is `deny_unknown_fields`, so one extra key makes `vox update` refuse at the parser instead
# of at the digest -- which is how v0.1.0 and v0.2.0 shipped a `proof` record with a `note`
# field that no released binary could read, leaving the mismatch refusal unproved for two
# releases. The explanation belongs in this comment; the record is for machines.
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
  printf '{"kind":"vox.standalone-release","schema_version":1,"package":"vox","channel":"%s","target":"%s","version":"%s","size":%s,"sha256":"%s"}\n' \
    "$1" "$TRIPLE" "$VERSION" "$SIZE" "$2"
}
record stable "$SHA" > "dist/stable-${TRIPLE}.json"
record proof "$(printf '0%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64)" \
  > "dist/proof-${TRIPLE}.json"

# Refuse to ship a record the shipped binary cannot read. The key set must be EXACTLY
# schema-1's, in any order -- an extra key is the v0.2.0 bug, a missing one is worse.
# jq is required, not optional: a check that quietly skips itself is the "absent evidence
# reads as success" failure ADR-018 §3 forbids. Both GitHub runners ship it.
command -v jq >/dev/null 2>&1 \
  || { printf 'package-release: need jq to validate the release records\n' >&2; exit 1; }
want='channel,kind,package,schema_version,sha256,size,target,version'
for r in "dist/stable-${TRIPLE}.json" "dist/proof-${TRIPLE}.json"; do
  got=$(jq -r 'keys_unsorted | sort | join(",")' "$r")
  [ "$got" = "$want" ] || {
    printf 'package-release: %s has fields %s, want exactly %s\n' "$r" "$got" "$want" >&2
    exit 1
  }
done

cat "dist/stable-${TRIPLE}.json"
cat "dist/proof-${TRIPLE}.json"
ls -l dist
