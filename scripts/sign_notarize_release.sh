#!/usr/bin/env bash
# Produce one Developer-ID-signed, notarized macOS `vox` executable for one target, plus a
# bounded proof receipt. The ZIP exists only to submit a standalone Mach-O to Apple's notary
# service; Apple cannot staple tickets to standalone binaries.
#
# Ported from hf2q's scripts/sign_notarize_standalone_release.sh, which is the reference
# implementation in this account: ephemeral keychain, sign by fingerprint after asserting the
# keychain holds exactly one identity, verify every signature property out of
# `codesign --display`, notarize with an App Store Connect API key, bind the CDHash in the
# notary log, verify the online ticket, and emit receipts. Differences from hf2q: vox ships two
# macOS architectures rather than one, so the expected arch is a parameter; and vox pins no
# minimum macOS version, so `minos` is recorded in the receipt rather than asserted against a
# value nobody chose.
#
# Credentials (same names and the same vars/secrets split hf2q uses):
#   vars    APPLE_DEVELOPER_ID_APPLICATION, APPLE_NOTARY_KEY_ID, APPLE_NOTARY_ISSUER_ID,
#           APPLE_TEAM_ID, APPLE_CODESIGN_IDENTIFIER
#   secrets APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64,
#           APPLE_DEVELOPER_ID_APPLICATION_P12_PASSWORD, APPLE_NOTARY_KEY_P8_BASE64
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: $0 INPUT_BINARY OUTPUT_DIRECTORY VERSION TARGET_TRIPLE IDENTIFIER MIN_MACOS" >&2
  exit 2
fi

input_binary=$1
output_directory=$2
version=$3
target=$4
identifier=$5
expected_min_macos=$6
asset_name="vox-${target}"

case "$target" in
  aarch64-apple-darwin) expected_arch=arm64 ;;
  x86_64-apple-darwin)  expected_arch=x86_64 ;;
  *) echo "sign: $target is not a macOS target" >&2; exit 2 ;;
esac

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fail() {
  echo "release signing: $*" >&2
  exit 1
}

[[ $(uname -s) == Darwin ]] || fail "signing requires a macOS runner"
[[ -f "$input_binary" && -x "$input_binary" && ! -L "$input_binary" ]] || \
  fail "input must be a regular executable"
[[ "$output_directory" == /* ]] || fail "output directory must be absolute"
[[ ! -e "$output_directory" && ! -L "$output_directory" ]] || \
  fail "output directory already exists"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || \
  fail "version must be canonical stable SemVer"
[[ "$identifier" =~ ^[A-Za-z0-9.-]+$ ]] || fail "signing identifier is not canonical"
[[ $(/usr/bin/lipo -archs "$input_binary" 2>/dev/null) == "$expected_arch" ]] || \
  fail "input is not an exact thin $expected_arch Mach-O"
input_sha=$(sha256_file "$input_binary")
# Asserted, not merely recorded. rustc's DEFAULT deployment target differs per Apple
# architecture — 10.12 for x86_64-apple-darwin, 11.0 for aarch64-apple-darwin — so an
# unpinned build ships two artifacts claiming two different floors, one of which
# (10.12) nobody has ever tested. Worse, below 10.14 the linker emits
# LC_VERSION_MIN_MACOSX instead of LC_BUILD_VERSION and `vtool -show-build` prints no
# `minos` line at all, which is how this was found: the x86_64 job failed here while
# arm64 passed. The workflow now pins MACOSX_DEPLOYMENT_TARGET and this checks it held.
[[ "$expected_min_macos" =~ ^[0-9]+\.[0-9]+$ ]] || fail "expected minimum macOS is not canonical"
minimum_macos=$(/usr/bin/vtool -show-build "$input_binary" 2>/dev/null | \
  awk '$1 == "minos" {print $2}')
[[ "$minimum_macos" == "$expected_min_macos" ]] || \
  fail "input declares minimum macOS '${minimum_macos:-none}', expected $expected_min_macos"

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
secret_directory=$(mktemp -d "$runner_temp/vox-apple-release-secrets.XXXXXX")
chmod 0700 "$secret_directory"
keychain="$secret_directory/release.keychain-db"
p12="$secret_directory/developer-id.p12"
notary_key="$secret_directory/AuthKey_${notary_key_id}.p8"
candidate="$secret_directory/$asset_name"
submission_archive="$secret_directory/vox-notary.zip"
submission_json="$output_directory/notary-submission.json"
notary_wait="$output_directory/notary-wait.json"
notary_log="$secret_directory/notary-log.json"
codesign_log="$secret_directory/codesign.txt"
notarization_check_log="$secret_directory/notarization-check.txt"
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
  rm -f -- "$p12" "$notary_key" "$candidate" "$submission_archive" \
    "$notary_log" "$codesign_log" "$notarization_check_log"
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

/bin/cp "$input_binary" "$candidate"
/bin/chmod 0755 "$candidate"
[[ $(sha256_file "$candidate") == "$input_sha" ]] || \
  fail "private signing copy changed the exact unsigned input"
/usr/bin/codesign --force --sign "$signing_fingerprint" --keychain "$keychain" \
  --identifier "$identifier" --options runtime --timestamp "$candidate"
/usr/bin/codesign --verify --strict --all-architectures --verbose=2 "$candidate"
/usr/bin/codesign --display --verbose=4 "$candidate" 2>"$codesign_log"
[[ $(grep -Fxc -- "Identifier=$identifier" "$codesign_log") -eq 1 ]] || \
  fail "signed identifier does not match"
[[ $(grep -Fxc -- "TeamIdentifier=$team_id" "$codesign_log") -eq 1 ]] || \
  fail "signed Team ID does not match"
[[ $(grep -Fxc -- "Authority=$signing_identity" "$codesign_log") -eq 1 ]] || \
  fail "signed authority does not match"
# `codesign --display --verbose=4` emits flags inside its CodeDirectory line, e.g.
# `CodeDirectory ... flags=0x10000(runtime) hashes=...`.
grep -Eq '^CodeDirectory .* flags=0x[0-9a-f]+\(runtime\)( |$)' "$codesign_log" || \
  fail "hardened runtime is absent from the signature"
grep -Eq '^Timestamp=.+$' "$codesign_log" || fail "secure timestamp is absent from the signature"
cdhash=$(sed -n 's/^CDHash=//p' "$codesign_log")
[[ "$cdhash" =~ ^[0-9a-f]{40,64}$ ]] || fail "signed CDHash is not canonical"
[[ $(grep -c '^CDHash=' "$codesign_log") -eq 1 ]] || fail "signed CDHash is ambiguous"

/usr/bin/ditto -c -k --keepParent "$candidate" "$submission_archive"
archive_sha=$(sha256_file "$submission_archive")
mkdir -m 0700 "$output_directory"
output_binary="$output_directory/$asset_name"
/bin/cp "$candidate" "$output_binary"
/bin/chmod 0555 "$output_binary"
binary_size=$(stat -f '%z' "$output_binary")
binary_sha=$(sha256_file "$output_binary")

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
jq -e --arg cdhash "$cdhash" '
  .status == "Accepted"
  and ((.issues // []) | length) == 0
  and any(.ticketContents[]?; .digestAlgorithm == "SHA-256" and .cdhash == $cdhash)
' "$notary_log" >/dev/null || fail "notary log does not bind the accepted binary"

# `spctl --assess --type execute` is an app-bundle assessment and rejects a valid raw CLI as
# "not an app". For a standalone Mach-O, combine the purpose-built online-ticket check with the
# explicit notarized code requirement. Neither is sufficient alone: `--check-notarization` can
# accept platform/ad-hoc code, while the requirement alone need not force an online lookup.
notarization_verified=0
for _ in $(seq 1 12); do
  if /usr/bin/codesign --verify --strict --all-architectures \
    --check-notarization --test-requirement '=notarized' --verbose=4 "$candidate" \
    >"$notarization_check_log" 2>&1; then
    notarization_verified=1
    break
  fi
  sleep 5
done
[[ $notarization_verified -eq 1 ]] || \
  fail "online notarization ticket verification did not accept the binary"

submission_sha=$(sha256_file "$submission_json")
notary_wait_sha=$(sha256_file "$notary_wait")
notary_log_sha=$(sha256_file "$notary_log")
codesign_log_sha=$(sha256_file "$codesign_log")
notarization_check_log_sha=$(sha256_file "$notarization_check_log")

/bin/mv "$notary_log" "$output_directory/notary-log.json"
/bin/mv "$codesign_log" "$output_directory/codesign.txt"
/bin/mv "$notarization_check_log" "$output_directory/notarization-check.txt"
jq -nS \
  --arg version "$version" \
  --arg target "$target" \
  --arg unsigned_sha256 "$input_sha" \
  --arg asset_name "$asset_name" \
  --arg sha256 "$binary_sha" \
  --arg minimum_macos "$minimum_macos" \
  --arg team_id "$team_id" \
  --arg identifier "$identifier" \
  --arg cdhash "$cdhash" \
  --arg submission_id "$submission_id" \
  --arg submission_archive_sha256 "$archive_sha" \
  --arg submission_sha256 "$submission_sha" \
  --arg wait_sha256 "$notary_wait_sha" \
  --arg notary_log_sha256 "$notary_log_sha" \
  --arg codesign_log_sha256 "$codesign_log_sha" \
  --arg notarization_check_log_sha256 "$notarization_check_log_sha" \
  --argjson size "$binary_size" \
  '{
    kind:"vox.apple-release-proof",
    schema_version:1,
    package:"vox",
    target:$target,
    version:$version,
    input:{unsigned_sha256:$unsigned_sha256},
    asset:{name:$asset_name,size:$size,sha256:$sha256,minimum_macos:$minimum_macos},
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
      standalone_ticket_stapled:false
    },
    verification:{
      codesign:"accepted",
      codesign_log_sha256:$codesign_log_sha256,
      online_notarization:"accepted",
      online_notarization_log_sha256:$notarization_check_log_sha256,
      notary_ticket_cdhash_matches:true
    }
  }' >"$output_directory/apple-proof-${target}.json"
/bin/chmod 0444 "$output_directory"/{"apple-proof-${target}.json",notary-submission.json,notary-wait.json,notary-log.json,codesign.txt,notarization-check.txt}

for required in \
  "$asset_name" \
  "apple-proof-${target}.json" \
  notary-submission.json \
  notary-wait.json \
  notary-log.json \
  codesign.txt \
  notarization-check.txt; do
  [[ -f "$output_directory/$required" && ! -L "$output_directory/$required" ]] || \
    fail "signed release output is incomplete or unsafe: $required"
done

printf '%s\n' "$output_binary"
