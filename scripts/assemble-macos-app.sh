#!/usr/bin/env bash
# Put the release's signed `vox` into an unsigned Vox.app and check the bundle's shape before it
# is signed (ADR-014 M-26, M-26a, M-27).
#
#   scripts/assemble-macos-app.sh UNSIGNED_APP SIGNED_VOX OUTPUT_APP VERSION MIN_MACOS
#
# UNSIGNED_APP is what xcodebuild produced (ad-hoc signed, entitlements embedded). SIGNED_VOX is
# the Developer ID signed, notarized `vox` that sign_notarize_release.sh made; it goes in
# unchanged at Contents/Helpers/vox, so the CLI, the daemon and the app are one binary and the
# helper's bytes are the published `vox-<triple>`'s bytes. OUTPUT_APP must not exist.
#
# Checked here, because a bundle that fails any of these must not reach the signer:
#   - identifier us.vox.app, version VERSION, LSMinimumSystemVersion MIN_MACOS;
#   - the launch agent and LAN helper plists of M-8 and M-10, and the share extension;
#   - every Mach-O in the bundle is thin arm64 and declares minos MIN_MACOS: the Intel target is
#     not built at all (M-26a), so a fat or x86_64 slice anywhere is a refusal, not a strip.
# Needs no credentials; it runs the same on a developer's Mac as in release.yml.
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 UNSIGNED_APP SIGNED_VOX OUTPUT_APP VERSION MIN_MACOS" >&2
  exit 2
fi
unsigned_app=${1%/}
signed_vox=$2
output_app=${3%/}
version=$4
min_macos=$5

fail() {
  echo "assemble Vox.app: $*" >&2
  exit 1
}
plist() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }

[[ $(uname -s) == Darwin ]] || fail "needs macOS"
[[ -d "$unsigned_app" && ! -L "$unsigned_app" && $(basename "$unsigned_app") == Vox.app ]] || \
  fail "$unsigned_app is not a Vox.app directory"
[[ -f "$signed_vox" && -x "$signed_vox" && ! -L "$signed_vox" ]] || \
  fail "$signed_vox is not a regular executable"
[[ $(basename "$output_app") == Vox.app ]] || fail "the output must be named Vox.app"
[[ ! -e "$output_app" && ! -L "$output_app" ]] || fail "$output_app already exists"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || \
  fail "version must be canonical stable SemVer"
[[ "$min_macos" =~ ^[0-9]+\.[0-9]+$ ]] || fail "minimum macOS is not canonical"

/usr/bin/codesign --verify --strict "$signed_vox" 2>/dev/null || \
  fail "$signed_vox is not signed; sign vox before it goes into the bundle"

mkdir -p "$(dirname "$output_app")"
/usr/bin/ditto "$unsigned_app" "$output_app"
contents="$output_app/Contents"
info="$contents/Info.plist"
[[ -f "$info" ]] || fail "Contents/Info.plist is missing"

[[ $(plist "$info" CFBundleIdentifier) == us.vox.app ]] || \
  fail "bundle identifier is '$(plist "$info" CFBundleIdentifier)', want us.vox.app"
[[ $(plist "$info" CFBundleShortVersionString) == "$version" ]] || \
  fail "bundle version is '$(plist "$info" CFBundleShortVersionString)', want $version"
[[ $(plist "$info" LSMinimumSystemVersion) == "$min_macos" ]] || \
  fail "LSMinimumSystemVersion is '$(plist "$info" LSMinimumSystemVersion)', want $min_macos"
executable=$(plist "$info" CFBundleExecutable) || fail "CFBundleExecutable is missing"
[[ -f "$contents/MacOS/$executable" ]] || fail "the app's executable $executable is missing"

for required in \
  Library/LaunchAgents/us.vox.daemon.plist \
  Library/LaunchDaemons/us.vox.lanhelper.plist; do
  [[ -f "$contents/$required" ]] || fail "Contents/$required is missing (ADR-014 M-8, M-10)"
done
shopt -s nullglob
extensions=("$contents"/PlugIns/*.appex)
shopt -u nullglob
[[ ${#extensions[@]} -ge 1 ]] || fail "the share extension (Contents/PlugIns/*.appex) is missing"

# The release's vox, byte for byte. Anything the app build put there is replaced.
mkdir -p "$contents/Helpers"
rm -f "$contents/Helpers/vox"
/usr/bin/ditto "$signed_vox" "$contents/Helpers/vox"
[[ $(sha256_file "$contents/Helpers/vox") == $(sha256_file "$signed_vox") ]] || \
  fail "Contents/Helpers/vox is not the signed vox"

# Every Mach-O, wherever it sits: thin arm64, built for the floor.
machos=0
while IFS= read -r -d '' f; do
  /usr/bin/file -b "$f" | grep -q '^Mach-O' || continue
  machos=$((machos + 1))
  archs=$(/usr/bin/lipo -archs "$f" 2>/dev/null) || fail "${f#"$output_app/"}: lipo cannot read it"
  [[ "$archs" == arm64 ]] || fail "${f#"$output_app/"} is '$archs', not thin arm64"
  minos=$(/usr/bin/vtool -show-build "$f" 2>/dev/null | awk '$1 == "minos" {print $2; exit}')
  [[ "$minos" == "$min_macos" ]] || \
    fail "${f#"$output_app/"} declares minimum macOS '${minos:-none}', want $min_macos"
done < <(find "$contents" -type f -print0)
[[ $machos -ge 3 ]] || fail "found $machos Mach-O files; the app, its extension and vox make three"

printf '%s\n' "$output_app"
