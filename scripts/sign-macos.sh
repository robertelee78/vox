#!/bin/sh
# Sign and notarize one macOS binary with a Developer ID — ADR-015 §"Install and update".
#
#   scripts/sign-macos.sh <mach-o-binary>
#
# Run AFTER `strip`, which rewrites the Mach-O and invalidates any earlier signature, and
# BEFORE packaging, so the release record's digest covers the signed bytes.
#
# Without a trusted Developer ID signature, a binary downloaded over the web is quarantined
# by Gatekeeper, and "clear the quarantine flag by hand" is not an acceptable first run for a
# tool whose purpose is confidentiality. On a cross-built x86_64 binary `strip` removes the
# ad-hoc signature entirely, so signing is what makes the Intel package runnable at all.
#
# Gated on the secrets being present, so forks and pull requests still build: without them the
# binary is ad-hoc signed and the job warns loudly rather than failing.
#
# Required secrets: APPLE_CERT_P12_BASE64, APPLE_CERT_PASSWORD, APPLE_SIGNING_IDENTITY,
# APPLE_ID, APPLE_TEAM_ID, APPLE_NOTARY_PASSWORD.
set -eu

BIN="${1:?usage: sign-macos.sh <binary>}"

if [ -z "${APPLE_SIGNING_IDENTITY:-}" ] || [ -z "${APPLE_CERT_P12_BASE64:-}" ]; then
  printf '::warning::Apple signing secrets are not set — shipping an ad-hoc-signed binary that Gatekeeper will quarantine. Set the APPLE_* secrets to notarize.\n'
  codesign --force --sign - --timestamp=none "$BIN" || true
  codesign -dvvv "$BIN" 2>&1 || true
  exit 0
fi

KEYCHAIN="${RUNNER_TEMP:-/tmp}/vox-signing.keychain-db"
KEYCHAIN_PW="$(openssl rand -hex 20)"
CERT="${RUNNER_TEMP:-/tmp}/vox-cert.p12"
ZIP="${RUNNER_TEMP:-/tmp}/vox-notarize.zip"
# The private key must not outlive this script even if a step fails.
trap 'rm -f "$CERT" "$ZIP"' EXIT INT TERM

security create-keychain -p "$KEYCHAIN_PW" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PW" "$KEYCHAIN"
printf '%s' "$APPLE_CERT_P12_BASE64" | base64 --decode > "$CERT"
security import "$CERT" -k "$KEYCHAIN" -P "${APPLE_CERT_PASSWORD:-}" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PW" "$KEYCHAIN"
security list-keychains -d user -s "$KEYCHAIN"

# Hardened runtime + a secure timestamp are both required for notarization.
codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$BIN"
codesign --verify --strict --verbose=2 "$BIN"

# A bare CLI Mach-O cannot be stapled, so it is notarized via a zip and Gatekeeper validates
# the registered cdhash online.
ditto -c -k --keepParent "$BIN" "$ZIP"
xcrun notarytool submit "$ZIP" \
  --apple-id "${APPLE_ID:?APPLE_ID is required to notarize}" \
  --team-id "${APPLE_TEAM_ID:?APPLE_TEAM_ID is required to notarize}" \
  --password "${APPLE_NOTARY_PASSWORD:?APPLE_NOTARY_PASSWORD is required to notarize}" \
  --wait

codesign -dvvv "$BIN" 2>&1 | grep -E 'Authority|TeamIdentifier' || true
