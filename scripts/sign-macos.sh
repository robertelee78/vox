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
# **Signing is mandatory for a release.** If the secrets are absent this script FAILS, so a tagged
# release cannot be published unsigned. Decided 2026-09-21: an unsigned macOS artifact is not
# shipped at all, rather than shipped with a footnote — a confidentiality tool that teaches its
# users to wave Gatekeeper through has already lost the argument.
#
# `VOX_ALLOW_UNSIGNED=1` permits the ad-hoc fallback, and the release workflow sets it **only**
# for non-tag runs (a manual dispatch, a fork, a pull request) so those still build. A tag never
# sets it.
#
# Required secrets: APPLE_CERT_P12_BASE64, APPLE_CERT_PASSWORD, APPLE_SIGNING_IDENTITY,
# APPLE_ID, APPLE_TEAM_ID, APPLE_NOTARY_PASSWORD. The certificate MUST be a **Developer ID
# Application** certificate; an "Apple Development" certificate is for local development and
# notarytool rejects it.
#
# To set them up (needs a paid Apple Developer Program membership — a free personal team cannot
# issue a Developer ID):
#
#   1. Create the certificate. Xcode → Settings → Accounts → your Apple ID → Manage
#      Certificates → + → "Developer ID Application". It lands in the login keychain.
#      Confirm with:  security find-identity -v -p codesigning
#      The name it prints, in full, is APPLE_SIGNING_IDENTITY, e.g.
#      "Developer ID Application: YOUR NAME (TEAMID)". The parenthesised part is APPLE_TEAM_ID.
#   2. Export it. Keychain Access → My Certificates → right-click that identity → Export …
#      → .p12, with a password (that password is APPLE_CERT_PASSWORD).
#   3. Create an app-specific password for notarytool at appleid.apple.com → Sign-In and
#      Security → App-Specific Passwords. That is APPLE_NOTARY_PASSWORD; APPLE_ID is the Apple
#      ID's email address.
#   4. Set them on the repository:
#        base64 -i cert.p12 | tr -d "\n" | gh secret set APPLE_CERT_P12_BASE64 -R robertelee78/vox
#        gh secret set APPLE_CERT_PASSWORD   -R robertelee78/vox
#        gh secret set APPLE_SIGNING_IDENTITY -R robertelee78/vox
#        gh secret set APPLE_ID              -R robertelee78/vox
#        gh secret set APPLE_TEAM_ID         -R robertelee78/vox
#        gh secret set APPLE_NOTARY_PASSWORD -R robertelee78/vox
#        rm -f cert.p12
#   5. Tag the release:  git tag -a v0.1.0 -m "vox v0.1.0" && git push origin v0.1.0
set -eu

BIN="${1:?usage: sign-macos.sh <binary>}"

if [ -z "${APPLE_SIGNING_IDENTITY:-}" ] || [ -z "${APPLE_CERT_P12_BASE64:-}" ]; then
  if [ "${VOX_ALLOW_UNSIGNED:-}" = 1 ]; then
    printf '::warning::Apple signing secrets are not set — ad-hoc signing this build. It MUST NOT be published as a release (ADR-015).\n'
    codesign --force --sign - --timestamp=none "$BIN" || true
    codesign -dvvv "$BIN" 2>&1 || true
    exit 0
  fi
  printf '::error::Apple signing secrets are not set, so this macOS binary cannot be signed and notarized, and ADR-015 forbids publishing an unsigned one.\n' >&2
  printf 'Set APPLE_CERT_P12_BASE64, APPLE_CERT_PASSWORD, APPLE_SIGNING_IDENTITY, APPLE_ID, APPLE_TEAM_ID and APPLE_NOTARY_PASSWORD\n' >&2
  printf 'on the repository (a Developer ID Application certificate, not an Apple Development one), then re-run this tag.\n' >&2
  exit 1
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
