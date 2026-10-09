#!/usr/bin/env bash
# Sign Vox.app inside-out with the Developer ID, notarize it, staple the ticket, and publish it
# as `Vox-<version>-<triple>.zip` with a bounded proof receipt (ADR-014 M-27, ADR-028 I-1).
#
#   scripts/sign_notarize_app.sh ASSEMBLED_APP OUTPUT_DIRECTORY VERSION TARGET_TRIPLE \
#     APP_IDENTIFIER CLI_IDENTIFIER MIN_MACOS
#
# ASSEMBLED_APP is scripts/assemble-macos-app.sh's output: Contents/Helpers/vox is already the
# release's signed, notarized `vox`. It is verified here, not re-signed, so its bytes stay the
# published `vox-<triple>`'s and the receipt can say so.
#
# Same credential handling as sign_notarize_release.sh (ADR-015 17.17, 17.18, 17.20): a 0700
# directory deleted on exit, an ephemeral keychain holding exactly one identity, signing by
# fingerprint, an App Store Connect API key for the notary. Differences from that script:
#   - nested code is signed deepest first, each keeping the entitlements the app build gave it
#     (--preserve-metadata=entitlements), then the bundle itself; never --deep;
#   - a bundle can carry a stapled ticket, so it is stapled and the staple validated;
#   - the notary log must bind the CDHash of every piece of code in the bundle.
set -euo pipefail

if [[ $# -ne 7 ]]; then
  echo "usage: $0 ASSEMBLED_APP OUTPUT_DIRECTORY VERSION TARGET_TRIPLE APP_IDENTIFIER CLI_IDENTIFIER MIN_MACOS" >&2
  exit 2
fi

input_app=${1%/}
output_directory=$2
version=$3
target=$4
app_identifier=$5
cli_identifier=$6
expected_min_macos=$7
asset_name="Vox-${version}-${target}.zip"

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fail() {
  echo "app signing: $*" >&2
  exit 1
}
plist() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }

[[ $(uname -s) == Darwin ]] || fail "signing requires a macOS runner"
# One macOS target (ADR-014 M-26a).
[[ "$target" == aarch64-apple-darwin ]] || fail "$target is not the macOS target"
[[ -d "$input_app" && ! -L "$input_app" && $(basename "$input_app") == Vox.app ]] || \
  fail "input must be an assembled Vox.app"
[[ "$output_directory" == /* ]] || fail "output directory must be absolute"
[[ ! -e "$output_directory" && ! -L "$output_directory" ]] || \
  fail "output directory already exists"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || \
  fail "version must be canonical stable SemVer"
[[ "$app_identifier" =~ ^[A-Za-z0-9.-]+$ ]] || fail "app identifier is not canonical"
[[ "$cli_identifier" =~ ^[A-Za-z0-9.-]+$ ]] || fail "CLI identifier is not canonical"
[[ "$expected_min_macos" =~ ^[0-9]+\.[0-9]+$ ]] || fail "expected minimum macOS is not canonical"
[[ $(plist "$input_app/Contents/Info.plist" CFBundleIdentifier) == "$app_identifier" ]] || \
  fail "bundle identifier is not $app_identifier"
[[ $(plist "$input_app/Contents/Info.plist" CFBundleShortVersionString) == "$version" ]] || \
  fail "bundle version is not $version"
[[ $(plist "$input_app/Contents/Info.plist" LSMinimumSystemVersion) == "$expected_min_macos" ]] || \
  fail "bundle floor is not $expected_min_macos"
helper_rel=Contents/Helpers/vox
[[ -f "$input_app/$helper_rel" && ! -L "$input_app/$helper_rel" ]] || fail "$helper_rel is missing"
helper_sha=$(sha256_file "$input_app/$helper_rel")

signing_identity=${APPLE_DEVELOPER_ID_APPLICATION:?APPLE_DEVELOPER_ID_APPLICATION is required}
team_id=${APPLE_TEAM_ID:?APPLE_TEAM_ID is required}
p12_base64=${APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64:?APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64 is required}
p12_password=${APPLE_DEVELOPER_ID_APPLICATION_P12_PASSWORD:?APPLE_DEVELOPER_ID_APPLICATION_P12_PASSWORD is required}
notary_key_base64=${APPLE_NOTARY_KEY_P8_BASE64:?APPLE_NOTARY_KEY_P8_BASE64 is required}
notary_key_id=${APPLE_NOTARY_KEY_ID:?APPLE_NOTARY_KEY_ID is required}
notary_issuer_id=${APPLE_NOTARY_ISSUER_ID:?APPLE_NOTARY_ISSUER_ID is required}
unset APPLE_DEVELOPER_ID_APPLICATION APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64 \
  APPLE_DEVELOPER_ID_APPLICATION_P12_PASSWORD APPLE_NOTARY_KEY_P8_BASE64 \
  APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID

[[ "$team_id" =~ ^[A-Z0-9]{10}$ ]] || fail "Apple Team ID is not canonical"
[[ "$signing_identity" == "Developer ID Application: "*" ($team_id)" ]] || \
  fail "Developer ID identity does not bind the expected Team ID"
[[ "$signing_identity" != *$'\n'* && ${#signing_identity} -le 255 ]] || \
  fail "Developer ID identity is not canonical"
[[ "$notary_key_id" =~ ^[A-Z0-9]{10}$ ]] || fail "notary key ID is not canonical"
[[ "$notary_issuer_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || \
  fail "notary issuer ID is not canonical"

runner_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
[[ "$runner_temp" == /* && -d "$runner_temp" ]] || \
  fail "RUNNER_TEMP must be an existing absolute directory"
secret_directory=$(mktemp -d "$runner_temp/vox-apple-app-secrets.XXXXXX")
chmod 0700 "$secret_directory"
keychain="$secret_directory/release.keychain-db"
p12="$secret_directory/developer-id.p12"
notary_key="$secret_directory/AuthKey_${notary_key_id}.p8"
work="$secret_directory/work"
candidate="$work/Vox.app"
submission_archive="$secret_directory/vox-app-notary.zip"
submission_json="$output_directory/notary-submission.json"
notary_wait="$output_directory/notary-wait.json"
notary_log="$secret_directory/notary-log.json"
codesign_log="$secret_directory/codesign.txt"
helper_log="$secret_directory/helper-codesign.txt"
notarization_check_log="$secret_directory/notarization-check.txt"
staple_log="$secret_directory/staple.txt"
keychain_password="$(/usr/bin/uuidgen)-$(/usr/bin/uuidgen)"
original_user_keychains=()
while IFS= read -r original_keychain; do
  original_keychain=${original_keychain#"${original_keychain%%[![:space:]]*}"}
  original_keychain=${original_keychain#\"}
  original_keychain=${original_keychain%\"}
  [[ "$original_keychain" == /* ]] || fail "user keychain search list is noncanonical"
  original_user_keychains+=("$original_keychain")
done < <(/usr/bin/security list-keychains -d user)
[[ ${#original_user_keychains[@]} -gt 0 ]] || fail "user keychain search list is empty"
user_keychain_list_modified=false

cleanup() {
  if [[ "$user_keychain_list_modified" == true ]]; then
    /usr/bin/security list-keychains -d user -s \
      "${original_user_keychains[@]}" >/dev/null 2>&1 || true
  fi
  /usr/bin/security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -f -- "$p12" "$notary_key" "$submission_archive" "$notary_log" "$codesign_log" \
    "$helper_log" "$notarization_check_log" "$staple_log"
  rm -rf -- "$work"
  rmdir "$secret_directory" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

umask 077
printf '%s' "$p12_base64" | /usr/bin/base64 -D >"$p12" || \
  fail "Developer ID secret is not valid base64"
printf '%s' "$notary_key_base64" | /usr/bin/base64 -D >"$notary_key" || \
  fail "notary key secret is not valid base64"
[[ -s "$p12" && -s "$notary_key" ]] || fail "Apple credential material is empty"
unset p12_base64 notary_key_base64

/usr/bin/security create-keychain -p "$keychain_password" "$keychain"
/usr/bin/security set-keychain-settings -lut 21600 "$keychain"
/usr/bin/security unlock-keychain -p "$keychain_password" "$keychain"
/usr/bin/security import "$p12" -k "$keychain" -P "$p12_password" \
  -T /usr/bin/codesign >/dev/null
/usr/bin/security set-key-partition-list -S apple-tool:,apple: -s \
  -k "$keychain_password" "$keychain" >/dev/null
unset p12_password
user_keychain_list_modified=true
/usr/bin/security list-keychains -d user -s "$keychain" "${original_user_keychains[@]}"

identities=$(/usr/bin/security find-identity -v -p codesigning "$keychain")
[[ $(grep -Fc -- "\"$signing_identity\"" <<<"$identities") -eq 1 ]] || \
  fail "ephemeral keychain does not contain exactly the intended signing identity"
[[ $(grep -Ec '^[[:space:]]*1 valid identities found$' <<<"$identities") -eq 1 ]] || \
  fail "ephemeral keychain contains an ambiguous signing identity set"
signing_fingerprint=$(grep -F -- "\"$signing_identity\"" <<<"$identities" | awk '{print $2}')
[[ "$signing_fingerprint" =~ ^[0-9A-F]{40}$ ]] || \
  fail "Developer ID signing fingerprint is not canonical"

mkdir -m 0700 "$work"
/usr/bin/ditto "$input_app" "$candidate"
[[ $(sha256_file "$candidate/$helper_rel") == "$helper_sha" ]] || \
  fail "private signing copy changed the helper"

# The helper is the release's vox, already signed by this same identity: verify, never re-sign.
/usr/bin/codesign --verify --strict --verbose=2 "$candidate/$helper_rel"
/usr/bin/codesign --display --verbose=4 "$candidate/$helper_rel" 2>"$helper_log"
[[ $(grep -Fxc -- "Identifier=$cli_identifier" "$helper_log") -eq 1 ]] || \
  fail "the helper's identifier is not $cli_identifier"
[[ $(grep -Fxc -- "TeamIdentifier=$team_id" "$helper_log") -eq 1 ]] || \
  fail "the helper is not signed by Team ID $team_id"
[[ $(grep -Fxc -- "Authority=$signing_identity" "$helper_log") -eq 1 ]] || \
  fail "the helper is not signed by $signing_identity"
grep -Eq '^CodeDirectory .* flags=0x[0-9a-f]+\(runtime\)( |$)' "$helper_log" || \
  fail "the helper lacks the hardened runtime"
helper_cdhash=$(sed -n 's/^CDHash=//p' "$helper_log")
[[ "$helper_cdhash" =~ ^[0-9a-f]{40,64}$ ]] || fail "the helper's CDHash is not canonical"

sign() {
  /usr/bin/codesign --force --sign "$signing_fingerprint" --keychain "$keychain" \
    --options runtime --timestamp --preserve-metadata=entitlements "$1"
}

# Inside-out: every nested bundle and loose Mach-O, deepest path first, then the app. A nested
# bundle's own contents are signed before it because they are deeper. The helper is skipped.
nested=()
while IFS= read -r -d '' f; do
  rel=${f#"$candidate/"}
  [[ "$rel" == "$helper_rel" ]] && continue
  case "$f" in
    *.appex | *.framework | *.xpc | *.app) nested+=("$f") ;;
    *)
      [[ -f "$f" && ! -L "$f" ]] || continue
      # A bundle's main executable is signed with its bundle.
      [[ "$(dirname "$f")" == */Contents/MacOS ]] && continue
      [[ "$(dirname "$f")" == *.framework/Versions/* ]] && continue
      /usr/bin/file -b "$f" | grep -q '^Mach-O' && nested+=("$f")
      ;;
  esac
done < <(find "$candidate/Contents" -mindepth 1 \( -type d -o -type f \) -print0)
sign_order=()
if [[ ${#nested[@]} -gt 0 ]]; then
  while IFS= read -r line; do sign_order+=("${line#* }"); done < <(
    for f in "${nested[@]}"; do
      depth=$(tr -cd '/' <<<"$f" | wc -c | tr -d ' ')
      printf '%s %s\n' "$depth" "$f"
    done | sort -rn
  )
fi
for f in "${sign_order[@]}"; do
  echo "app signing: ${f#"$candidate/"}"
  sign "$f"
done
/usr/bin/codesign --force --sign "$signing_fingerprint" --keychain "$keychain" \
  --identifier "$app_identifier" --options runtime --timestamp \
  --preserve-metadata=entitlements "$candidate"

/usr/bin/codesign --verify --strict --deep --verbose=2 "$candidate"
/usr/bin/codesign --display --verbose=4 "$candidate" 2>"$codesign_log"
[[ $(grep -Fxc -- "Identifier=$app_identifier" "$codesign_log") -eq 1 ]] || \
  fail "signed identifier does not match"
[[ $(grep -Fxc -- "TeamIdentifier=$team_id" "$codesign_log") -eq 1 ]] || \
  fail "signed Team ID does not match"
[[ $(grep -Fxc -- "Authority=$signing_identity" "$codesign_log") -eq 1 ]] || \
  fail "signed authority does not match"
grep -Eq '^CodeDirectory .* flags=0x[0-9a-f]+\(runtime\)( |$)' "$codesign_log" || \
  fail "hardened runtime is absent from the signature"
grep -Eq '^Timestamp=.+$' "$codesign_log" || fail "secure timestamp is absent from the signature"
cdhash=$(sed -n 's/^CDHash=//p' "$codesign_log")
[[ "$cdhash" =~ ^[0-9a-f]{40,64}$ ]] || fail "signed CDHash is not canonical"
[[ $(grep -c '^CDHash=' "$codesign_log") -eq 1 ]] || fail "signed CDHash is ambiguous"
[[ $(sha256_file "$candidate/$helper_rel") == "$helper_sha" ]] || \
  fail "signing the bundle changed the helper"

/usr/bin/ditto -c -k --keepParent "$candidate" "$submission_archive"
archive_sha=$(sha256_file "$submission_archive")
mkdir -m 0700 "$output_directory"

if ! /usr/bin/xcrun notarytool submit "$submission_archive" \
  --key "$notary_key" --key-id "$notary_key_id" --issuer "$notary_issuer_id" \
  --output-format json >"$submission_json"; then
  fail "Apple notarization upload did not complete successfully"
fi
submission_id=$(jq -er .id "$submission_json") || \
  fail "Apple notarization upload did not return a submission ID"
[[ "$submission_id" =~ ^[0-9a-fA-F-]{36}$ ]] || fail "notary submission ID is not canonical"
if ! /usr/bin/xcrun notarytool wait "$submission_id" \
  --key "$notary_key" --key-id "$notary_key_id" --issuer "$notary_issuer_id" \
  --timeout 30m --output-format json >"$notary_wait"; then
  fail "Apple notarization wait did not complete; resume the recorded submission ID"
fi
jq -e --arg submission_id "$submission_id" \
  'select(.id == $submission_id and .status == "Accepted")' "$notary_wait" >/dev/null || \
  fail "Apple notarization status was not Accepted"
/usr/bin/xcrun notarytool log "$submission_id" \
  --key "$notary_key" --key-id "$notary_key_id" --issuer "$notary_issuer_id" "$notary_log"
jq -e --arg cdhash "$cdhash" --arg helper "$helper_cdhash" '
  .status == "Accepted"
  and ((.issues // []) | length) == 0
  and any(.ticketContents[]?; .digestAlgorithm == "SHA-256" and .cdhash == $cdhash)
  and any(.ticketContents[]?; .digestAlgorithm == "SHA-256" and .cdhash == $helper)
' "$notary_log" >/dev/null || fail "notary log does not bind the accepted app and its helper"

# A bundle can carry its ticket, so it does: Gatekeeper then needs no network on first launch.
/usr/bin/xcrun stapler staple "$candidate" >"$staple_log" 2>&1 || \
  fail "stapling the ticket failed: $(cat "$staple_log")"
/usr/bin/xcrun stapler validate "$candidate" >>"$staple_log" 2>&1 || \
  fail "the stapled ticket does not validate: $(cat "$staple_log")"
notarization_verified=0
for _ in $(seq 1 12); do
  if /usr/bin/codesign --verify --strict --deep \
    --check-notarization --test-requirement '=notarized' --verbose=4 "$candidate" \
    >"$notarization_check_log" 2>&1; then
    notarization_verified=1
    break
  fi
  sleep 5
done
[[ $notarization_verified -eq 1 ]] || \
  fail "online notarization ticket verification did not accept the app"

output_zip="$output_directory/$asset_name"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$candidate" "$output_zip"
/bin/chmod 0444 "$output_zip"
zip_size=$(stat -f '%z' "$output_zip")
zip_sha=$(sha256_file "$output_zip")

submission_sha=$(sha256_file "$submission_json")
notary_wait_sha=$(sha256_file "$notary_wait")
notary_log_sha=$(sha256_file "$notary_log")
codesign_log_sha=$(sha256_file "$codesign_log")
notarization_check_log_sha=$(sha256_file "$notarization_check_log")
staple_log_sha=$(sha256_file "$staple_log")

/bin/mv "$notary_log" "$output_directory/notary-log.json"
/bin/mv "$codesign_log" "$output_directory/codesign.txt"
/bin/mv "$helper_log" "$output_directory/helper-codesign.txt"
/bin/mv "$notarization_check_log" "$output_directory/notarization-check.txt"
/bin/mv "$staple_log" "$output_directory/staple.txt"
jq -nS \
  --arg version "$version" \
  --arg target "$target" \
  --arg asset_name "$asset_name" \
  --arg sha256 "$zip_sha" \
  --arg minimum_macos "$expected_min_macos" \
  --arg helper_identifier "$cli_identifier" \
  --arg helper_sha256 "$helper_sha" \
  --arg helper_cdhash "$helper_cdhash" \
  --arg team_id "$team_id" \
  --arg identifier "$app_identifier" \
  --arg cdhash "$cdhash" \
  --arg submission_id "$submission_id" \
  --arg submission_archive_sha256 "$archive_sha" \
  --arg submission_sha256 "$submission_sha" \
  --arg wait_sha256 "$notary_wait_sha" \
  --arg notary_log_sha256 "$notary_log_sha" \
  --arg codesign_log_sha256 "$codesign_log_sha" \
  --arg notarization_check_log_sha256 "$notarization_check_log_sha" \
  --arg staple_log_sha256 "$staple_log_sha" \
  --argjson size "$zip_size" \
  '{
    kind:"vox.apple-release-proof",
    schema_version:1,
    package:"Vox.app",
    target:$target,
    version:$version,
    asset:{name:$asset_name,size:$size,sha256:$sha256,minimum_macos:$minimum_macos},
    helper:{path:"Contents/Helpers/vox",identifier:$helper_identifier,
            sha256:$helper_sha256,cdhash:$helper_cdhash},
    signing:{
      authority:"Developer ID Application",
      team_id:$team_id,
      identifier:$identifier,
      cdhash:$cdhash,
      hardened_runtime:true,
      secure_timestamp:true
    },
    notarization:{
      status:"Accepted",
      submission_id:$submission_id,
      submission_archive_sha256:$submission_archive_sha256,
      submission_sha256:$submission_sha256,
      wait_sha256:$wait_sha256,
      log_sha256:$notary_log_sha256,
      stapled:true,
      staple_log_sha256:$staple_log_sha256
    },
    verification:{
      codesign:"accepted",
      codesign_log_sha256:$codesign_log_sha256,
      online_notarization:"accepted",
      online_notarization_log_sha256:$notarization_check_log_sha256,
      notary_ticket_cdhash_matches:true
    }
  }' >"$output_directory/apple-proof-app-${target}.json"
/bin/chmod 0444 "$output_directory"/{"apple-proof-app-${target}.json",notary-submission.json,notary-wait.json,notary-log.json,codesign.txt,helper-codesign.txt,notarization-check.txt,staple.txt}

for required in \
  "$asset_name" \
  "apple-proof-app-${target}.json" \
  notary-submission.json \
  notary-wait.json \
  notary-log.json \
  codesign.txt \
  helper-codesign.txt \
  notarization-check.txt \
  staple.txt; do
  [[ -f "$output_directory/$required" && ! -L "$output_directory/$required" ]] || \
    fail "signed app output is incomplete or unsafe: $required"
done

printf '%s\n' "$output_zip"
