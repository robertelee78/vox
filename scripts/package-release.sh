#!/bin/sh
# Package one target's release assets — ADR-015 §"Install and update", ADR-014 M-27.
#
#   scripts/package-release.sh <built-binary> <target-triple>
#   scripts/package-release.sh <Vox-version-triple.zip> <target-triple> app
#
# Writes into ./dist:
#   vox-<triple>          the binary, mode 0755
#   vox-<triple>.sha256   the digest, for a human checking by hand
#   stable-<triple>.json  the release record `vox update` and install.sh read
#   proof-<triple>.json   the same record with a deliberately wrong digest
#
# With `app`, the input is the signed, stapled Vox.app zip, and ./dist gets:
#   Vox-<version>-<triple>.zip      the app, carrying vox at Contents/Helpers/vox
#   app-stable-<triple>.json        its record: kind `vox.app-release`, package `Vox.app`
#   app-proof-<triple>.json         the same with a deliberately wrong digest
# The app is packaged after `vox` in the same job: the helper inside the zip must be
# byte-for-byte dist/vox-<triple>, or the two would not be one binary of one version.
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

BIN="${1:?usage: package-release.sh <binary|app zip> <triple> [app]}"
TRIPLE="${2:?usage: package-release.sh <binary|app zip> <triple> [app]}"
MODE="${3:-vox}"

if command -v sha256sum >/dev/null 2>&1; then
  sha_of() { sha256sum "$1" | cut -d' ' -f1; }
  sha_file() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  sha_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
  sha_file() { shasum -a 256 "$1"; }
else
  printf 'package-release: need sha256sum or shasum\n' >&2; exit 1
fi

# The workspace version is the single source of truth; the publish job checks it against the tag.
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
[ -n "$VERSION" ] || { printf 'package-release: could not determine the version\n' >&2; exit 1; }

case "$MODE" in
  vox)
    ASSET="vox-${TRIPLE}"
    KIND=vox.standalone-release PACKAGE=vox PREFIX=
    ;;
  app)
    ASSET="Vox-${VERSION}-${TRIPLE}.zip"
    KIND=vox.app-release PACKAGE=Vox.app PREFIX=app-
    [ "$(basename "$BIN")" = "$ASSET" ] \
      || { printf 'package-release: the app zip must be named %s, not %s\n' "$ASSET" "$(basename "$BIN")" >&2; exit 1; }
    [ -f "dist/vox-${TRIPLE}" ] \
      || { printf 'package-release: package vox-%s first; the app must carry that same binary\n' "$TRIPLE" >&2; exit 1; }
    command -v unzip >/dev/null 2>&1 || { printf 'package-release: need unzip\n' >&2; exit 1; }
    HELPER_DIR=$(mktemp -d)
    trap 'rm -rf "$HELPER_DIR"' EXIT
    unzip -p "$BIN" Vox.app/Contents/Helpers/vox > "$HELPER_DIR/vox" \
      || { printf 'package-release: %s has no Vox.app/Contents/Helpers/vox\n' "$BIN" >&2; exit 1; }
    [ "$(sha_of "$HELPER_DIR/vox")" = "$(sha_of "dist/vox-${TRIPLE}")" ] \
      || { printf 'package-release: the app'"'"'s Contents/Helpers/vox is not dist/vox-%s\n' "$TRIPLE" >&2; exit 1; }
    # The checks below then read the helper, which is what the app runs.
    BIN_CHECKED="$HELPER_DIR/vox"
    ;;
  *) printf 'package-release: unknown mode %s (want vox or app)\n' "$MODE" >&2; exit 2 ;;
esac

# **No mutant ships.** ADR-025's P9 and P10 proofs run a deliberately misbehaving sync sender, built
# from this tree with the `mutant-sender` feature (scripts/build-mutant-sender.sh). The release jobs
# build `--bin vox` with the default features, so it cannot be this binary; this makes sure of it.
# The mutant says its marker on stderr, so the string is in every mutant build and in no other.
if grep -aq 'VOX-MUTANT-SENDER' "${BIN_CHECKED:-$BIN}"; then
  printf 'package-release: %s is a mutant sender build (it carries VOX-MUTANT-SENDER); refusing\n' "$BIN" >&2
  exit 1
fi

# **No test-only knob ships** (V210-105, #300). The `VOX_TEST_*` variables the proofs stage races
# with are compiled into `vox` only with the `test-knobs` feature, which the release jobs do not
# enable. A knob's read carries its name, so a binary with any knob compiled in carries `VOX_TEST_`.
if grep -aq 'VOX_TEST_' "${BIN_CHECKED:-$BIN}"; then
  printf 'package-release: %s carries test-only knobs (%s); refusing\n' "$BIN" \
    "$(grep -ao 'VOX_TEST_[A-Z0-9_]*' "${BIN_CHECKED:-$BIN}" | sort -u | tr '\n' ' ')" >&2
  exit 1
fi

mkdir -p dist
cp "$BIN" "dist/$ASSET"
if [ "$MODE" = app ]; then chmod 0644 "dist/$ASSET"; else chmod 0755 "dist/$ASSET"; fi
( cd dist && sha_file "$ASSET" > "${ASSET}.sha256" )

SIZE=$(stat -c %s "dist/$ASSET" 2>/dev/null || stat -f %z "dist/$ASSET")
SHA=$(sha_of "dist/$ASSET")
[ -n "$SIZE" ] && [ -n "$SHA" ] \
  || { printf 'package-release: could not determine size/sha\n' >&2; exit 1; }

record() {
  printf '{"kind":"%s","schema_version":1,"package":"%s","channel":"%s","target":"%s","version":"%s","size":%s,"sha256":"%s"}\n' \
    "$KIND" "$PACKAGE" "$1" "$TRIPLE" "$VERSION" "$SIZE" "$2"
}
record stable "$SHA" > "dist/${PREFIX}stable-${TRIPLE}.json"
record proof "$(printf '0%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64)" \
  > "dist/${PREFIX}proof-${TRIPLE}.json"

# Refuse to ship a record the shipped binary cannot read. The key set must be EXACTLY
# schema-1's, in any order -- an extra key is the v0.2.0 bug, a missing one is worse.
# jq is required, not optional: a check that quietly skips itself is the "absent evidence
# reads as success" failure ADR-018 §3 forbids. Both GitHub runners ship it.
command -v jq >/dev/null 2>&1 \
  || { printf 'package-release: need jq to validate the release records\n' >&2; exit 1; }
want='channel,kind,package,schema_version,sha256,size,target,version'
for r in "dist/${PREFIX}stable-${TRIPLE}.json" "dist/${PREFIX}proof-${TRIPLE}.json"; do
  got=$(jq -r 'keys_unsorted | sort | join(",")' "$r")
  [ "$got" = "$want" ] || {
    printf 'package-release: %s has fields %s, want exactly %s\n' "$r" "$got" "$want" >&2
    exit 1
  }
done

cat "dist/${PREFIX}stable-${TRIPLE}.json"
cat "dist/${PREFIX}proof-${TRIPLE}.json"
ls -l dist
