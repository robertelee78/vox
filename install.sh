#!/bin/sh
# Vox Lux installer — ADR-015 §"Install and update".
#
#   curl -fsSL https://raw.githubusercontent.com/robertelee78/vox/main/install.sh | sh
#
# Installs the latest `vox` release for this machine into ~/.local/bin (override with
# VOX_INSTALL_DIR). On macOS it installs Vox.app instead, to /Applications when that is writable
# and ~/Applications otherwise (VOX_APPLICATIONS_DIR overrides /Applications), and makes
# ~/.local/bin/vox a link to the vox inside it: the CLI, the daemon and the app are one binary of
# one version (ADR-014 M-28). macOS needs Apple Silicon and macOS 13 or later (M-26a). Fetches the per-target release record through GitHub's
# releases/latest/download redirect, downloads the matching binary from that exact
# release, verifies size and SHA-256 before anything is put in place, installs it
# atomically, then runs `vox shell-setup` so PATH and tab completion work in your next
# shell (one marker-delimited block at the end of your rc; VOX_NO_SHELL_SETUP=1 skips it).
#
# GitHub only: no vanity domain, no package manager, no account, no token.
#
# POSIX sh only (no bashisms) so it runs under dash, macOS sh, and busybox.
set -eu

REPO="robertelee78/vox"
# ADR-015: every macOS release is signed by this team under this identifier, and notarized.
# Pinned HERE rather than read from the record: a first install has no previously-trusted vox to
# compare against, so the expectation has to live in the installer. (`vox update` does not need
# this — it requires the candidate to carry the same Developer ID as the binary it replaces.)
APPLE_TEAM_ID="3T2D2YNTVW"
APPLE_IDENTIFIER="us.vox.cli"
APPLE_APP_IDENTIFIER="us.vox.app"
# VOX_RELEASE_BASE exists for the installer's own end-to-end test against a local
# stand-in server; the origin check below still applies to redirects from it.
BASE="${VOX_RELEASE_BASE:-https://github.com/${REPO}/releases}"
INSTALL_DIR="${VOX_INSTALL_DIR:-$HOME/.local/bin}"
CHANNEL="${VOX_CHANNEL:-stable}"
MARKER=".vox-standalone.json"
SYSTEM_APPS="${VOX_APPLICATIONS_DIR:-/Applications}"
# TLS is mandatory except against an explicit loopback test base.
case "$BASE" in
  https://*) CURL_PROTO="--proto =https --proto-redir =https --tlsv1.2" ;;
  http://127.0.0.1:*|http://localhost:*) CURL_PROTO="--proto =http" ;;
  *) printf 'vox install: VOX_RELEASE_BASE must be https:// (or a loopback http:// test server)\n' >&2; exit 1 ;;
esac

say()  { printf '%s\n' "$*"; }
fail() { printf 'vox install: %s\n' "$*" >&2; exit 1; }

# --- target triple -----------------------------------------------------------------
os=$(uname -s) ; arch=$(uname -m)
case "$os" in
  Darwin) os_t="apple-darwin" ;;
  Linux)  os_t="unknown-linux-gnu" ;;
  *)      fail "unsupported OS: $os (vox ships macOS and Linux)" ;;
esac
# On macOS, only Apple Silicon on macOS 13 or later, and said before anything is downloaded
# (ADR-014 M-26a). A shell under Rosetta reports x86_64 on an Apple Silicon Mac; that Mac is
# supported, so the hardware is asked rather than the shell.
if [ "$os" = Darwin ]; then
  if [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
    arch=arm64
  fi
  macos=$(sw_vers -productVersion 2>/dev/null || true)
  major=${macos%%.*}
  case "$major" in ''|*[!0-9]*) major=0 ;; esac
  if [ "$arch" != arm64 ]; then
    fail "this Mac is not supported: Vox needs a Mac with Apple Silicon and macOS 13 or later, and this is an Intel Mac. Nothing was downloaded or installed."
  fi
  if [ "$major" -lt 13 ]; then
    fail "this Mac is not supported: Vox needs a Mac with Apple Silicon and macOS 13 or later, and this one runs macOS ${macos:-of an unknown version}. Nothing was downloaded or installed."
  fi
fi
case "$arch" in
  arm64|aarch64) arch_t="aarch64" ;;
  x86_64|amd64)  arch_t="x86_64" ;;
  *)             fail "unsupported architecture: $arch" ;;
esac
TARGET="${arch_t}-${os_t}"
case "$TARGET" in
  aarch64-unknown-linux-gnu) fail "there is no aarch64 Linux release yet; build from source: cargo build --release" ;;
esac
ASSET="vox-${TARGET}"
RECORD="${CHANNEL}-${TARGET}.json"
APP_RECORD="app-${CHANNEL}-${TARGET}.json"

# --- tools --------------------------------------------------------------------------
command -v curl >/dev/null 2>&1 || fail "curl is required"
if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "need sha256sum or shasum to verify the download"
fi

# --- release record ------------------------------------------------------------------
# One small JSON per target on every release: {"kind","schema_version","package","channel",
# "target","version","size","sha256"}. `latest/download` 302s to the newest release's copy,
# so this one line is the whole "what is current" lookup.
#
# `-f` is not optional: without it a 404 exits 0 and writes the body ("Not Found") into the
# output file, which would then be read as the release record.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vox-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
curl -fsSL $CURL_PROTO --max-filesize 4096 \
  -o "$tmp/record.json" "${BASE}/latest/download/${RECORD}" \
  || fail "could not fetch release record ${RECORD} (no ${CHANNEL} release for ${TARGET} yet?)"

# Minimal field extraction without jq: every value is a simple scalar.
field() { sed -n "s/.*\"$1\":[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" "${2:-$tmp/record.json}" | head -1; }
kind=$(field kind); schema=$(field schema_version); pkg=$(field package)
rchannel=$(field channel); rtarget=$(field target)
version=$(field version); size=$(field size); sha256=$(field sha256)
[ "$kind" = "vox.standalone-release" ] && [ "$schema" = "1" ] && [ "$pkg" = "vox" ] \
  && [ "$rchannel" = "$CHANNEL" ] && [ "$rtarget" = "$TARGET" ] \
  || fail "release record identity mismatch (kind=$kind schema=$schema package=$pkg channel=$rchannel target=$rtarget)"
[ -n "$version" ] && [ -n "$size" ] && [ -n "$sha256" ] || fail "release record incomplete"
say "vox ${version} for ${TARGET}"

# --- download, pinned and confined to GitHub --------------------------------------------
# Pinned to the exact release the record came from — not `latest`, which could move between
# the two requests — and refused if the download leaves GitHub's origins.
fetch_asset() { # <asset name> <size> <sha256> <output>
  url="${BASE}/download/v${version}/$1"
  curl -fsSL $CURL_PROTO --max-filesize "$2" \
    -w '%{url_effective}\n' -o "$4" "$url" >"$tmp/final_url" \
    || fail "download failed: $url"
  final=$(cat "$tmp/final_url")
  case "$final" in
    https://github.com/*|https://release-assets.githubusercontent.com/*|https://objects.githubusercontent.com/*) ;;
    "$BASE"/*) ;;  # the configured base itself (test stand-in)
    *) fail "download redirected off GitHub: $final" ;;
  esac
  got_size=$(wc -c <"$4" | tr -d ' ')
  [ "$got_size" = "$2" ] || fail "size mismatch: expected $2, got $got_size"
  got_sha=$(sha "$4")
  [ "$got_sha" = "$3" ] || fail "sha256 mismatch: expected $3, got $got_sha"
}

# --- Apple Developer ID + notarization (macOS) -------------------------------------------
# The bytes must carry a valid Developer ID signature from our team, under our identifier, with
# the hardened runtime — and Apple must confirm the notarization ticket online. None of this is
# optional, and none of it is read from the release record: the record is served by the same
# origin as the binary, so trusting it to describe its own signer would be circular.
# Against the loopback test base the bytes are a fixture, not a release, so the gate is
# meaningless there and is skipped. `VOX_PROOF_APPLE_VERIFY=1` turns it back on, which is how
# the proof measures that it refuses unsigned bytes — an override that can only ever *enable* a
# check is safe by construction.
apple_verify=0
[ "$os" = Darwin ] && case "$BASE" in https://*) apple_verify=1 ;; esac
[ "$os" = Darwin ] && [ -n "${VOX_PROOF_APPLE_VERIFY:-}" ] && apple_verify=1

apple_signed() { # <path> <identifier> <what>
  /usr/bin/codesign --verify --strict --deep --all-architectures "$1" 2>/dev/null \
    || fail "$3: Apple code-signature verification failed"
  info=$(/usr/bin/codesign --display --verbose=4 "$1" 2>&1)
  printf '%s\n' "$info" | grep -qx "TeamIdentifier=$APPLE_TEAM_ID" \
    || fail "$3 is not signed by team $APPLE_TEAM_ID"
  printf '%s\n' "$info" | grep -qx "Identifier=$2" \
    || fail "$3 is not signed as $2"
  printf '%s\n' "$info" | grep -q "^Authority=Developer ID Application: .* ($APPLE_TEAM_ID)$" \
    || fail "$3 is not signed with a Developer ID Application certificate"
  printf '%s\n' "$info" | grep -q '^CodeDirectory .*flags=0x[0-9a-f]*(runtime' \
    || fail "$3's signature lacks the hardened runtime"
  /usr/bin/codesign --verify --strict --deep --all-architectures --check-notarization \
    --test-requirement '=notarized' "$1" 2>/dev/null \
    || fail "Apple did not confirm $3's notarization ticket (is this machine online?)"
}

if [ "$os" = Darwin ]; then
  # --- Vox.app (macOS) ---------------------------------------------------------------------
  # Its own record, from the same release as vox's: the two are one version or neither installs.
  curl -fsSL $CURL_PROTO --max-filesize 4096 \
    -o "$tmp/app-record.json" "${BASE}/latest/download/${APP_RECORD}" \
    || fail "could not fetch release record ${APP_RECORD} (no ${CHANNEL} release of Vox.app for ${TARGET} yet?)"
  a_kind=$(field kind "$tmp/app-record.json"); a_schema=$(field schema_version "$tmp/app-record.json")
  a_pkg=$(field package "$tmp/app-record.json"); a_channel=$(field channel "$tmp/app-record.json")
  a_target=$(field target "$tmp/app-record.json"); a_version=$(field version "$tmp/app-record.json")
  a_size=$(field size "$tmp/app-record.json"); a_sha256=$(field sha256 "$tmp/app-record.json")
  [ "$a_kind" = "vox.app-release" ] && [ "$a_schema" = "1" ] && [ "$a_pkg" = "Vox.app" ] \
    && [ "$a_channel" = "$CHANNEL" ] && [ "$a_target" = "$TARGET" ] \
    || fail "app release record identity mismatch (kind=$a_kind schema=$a_schema package=$a_pkg channel=$a_channel target=$a_target)"
  [ -n "$a_size" ] && [ -n "$a_sha256" ] || fail "app release record incomplete"
  [ "$a_version" = "$version" ] \
    || fail "the release offers vox $version but Vox.app ${a_version:-of no version}; they install together or not at all"

  # Where the app goes, and what is already there, are settled before anything is downloaded.
  if [ -d "$SYSTEM_APPS" ] && [ -w "$SYSTEM_APPS" ]; then
    APPS="$SYSTEM_APPS"
  else
    APPS="$HOME/Applications"
  fi
  if [ -e "$APPS/Vox.app" ] && [ ! -e "$APPS/$MARKER" ]; then
    fail "$APPS/Vox.app exists but was not installed by this installer; remove it first"
  fi
  if [ -e "$INSTALL_DIR/vox" ] && [ ! -e "$INSTALL_DIR/$MARKER" ]; then
    case "$(readlink "$INSTALL_DIR/vox" 2>/dev/null || true)" in
      */Vox.app/Contents/Helpers/vox) ;;  # a link this installer made
      *) fail "$INSTALL_DIR/vox exists but was not installed by this installer; remove it or set VOX_INSTALL_DIR" ;;
    esac
  fi

  APP_ZIP="Vox-${version}-${TARGET}.zip"
  fetch_asset "$APP_ZIP" "$a_size" "$a_sha256" "$tmp/$APP_ZIP"
  mkdir "$tmp/app"
  /usr/bin/ditto -x -k "$tmp/$APP_ZIP" "$tmp/app" || fail "$APP_ZIP did not unpack"
  [ "$(ls -A "$tmp/app")" = Vox.app ] && [ -d "$tmp/app/Vox.app" ] \
    || fail "$APP_ZIP does not hold exactly Vox.app"
  new_app="$tmp/app/Vox.app"
  helper="$new_app/Contents/Helpers/vox"
  [ -f "$helper" ] || fail "Vox.app carries no Contents/Helpers/vox"
  # One binary of one version: the vox inside is the vox this release published.
  [ "$(wc -c <"$helper" | tr -d ' ')" = "$size" ] && [ "$(sha "$helper")" = "$sha256" ] \
    || fail "the vox inside Vox.app is not the vox ${version} the release record names"
  app_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$new_app/Contents/Info.plist" 2>/dev/null || true)
  [ "$app_version" = "$version" ] \
    || fail "Vox.app says it is version ${app_version:-unknown}, not $version"
  if [ "$apple_verify" = 1 ]; then
    apple_signed "$new_app" "$APPLE_APP_IDENTIFIER" "Vox.app"
    apple_signed "$helper" "$APPLE_IDENTIFIER" "Vox.app's vox"
    say "verified: Vox.app and its vox, Developer ID $APPLE_TEAM_ID, notarized"
  fi

  # --- install the bundle --------------------------------------------------------------
  # Copied beside its destination, then renamed into place; the bundle it replaces is kept as
  # .Vox.app.previous. Leftovers of a run that was cut short may be read-only, so they are made
  # writable before they are removed.
  mkdir -p "$APPS"
  for leftover in "$APPS/.Vox.app.partial" "$APPS/.Vox.app.previous.partial"; do
    if [ -e "$leftover" ]; then chmod -R u+w "$leftover" && rm -rf "$leftover"; fi
  done
  /usr/bin/ditto "$new_app" "$APPS/.Vox.app.partial" || fail "could not copy Vox.app into $APPS"
  if [ -e "$APPS/Vox.app" ]; then
    if [ -e "$APPS/.Vox.app.previous" ]; then
      chmod -R u+w "$APPS/.Vox.app.previous" && rm -rf "$APPS/.Vox.app.previous"
    fi
    mv "$APPS/Vox.app" "$APPS/.Vox.app.previous"
  fi
  printf '{"kind":"vox.install-channel","schema_version":1,"package":"vox","channel":"%s"}\n' \
    "$CHANNEL" >"$APPS/$MARKER"
  mv "$APPS/.Vox.app.partial" "$APPS/Vox.app"
  say "installed: $APPS/Vox.app (Vox $version)"

  # --- link the CLI into it --------------------------------------------------------------
  mkdir -p "$INSTALL_DIR"
  rm -f "$INSTALL_DIR/.vox-link.partial"
  ln -s "$APPS/Vox.app/Contents/Helpers/vox" "$INSTALL_DIR/.vox-link.partial"
  mv -f "$INSTALL_DIR/.vox-link.partial" "$INSTALL_DIR/vox"
  # A standalone vox installed here before belongs to no bundle; its marker and previous go.
  rm -f "$INSTALL_DIR/$MARKER" "$INSTALL_DIR/.vox-previous" \
    "$INSTALL_DIR/.vox-candidate.partial" "$INSTALL_DIR/.vox-previous.partial"
  installed=$("$INSTALL_DIR/vox" --version 2>/dev/null || true)
  [ "$installed" = "vox $version" ] \
    || fail "$INSTALL_DIR/vox reports ${installed:-nothing}, not vox $version (on macOS see: codesign -dv $APPS/Vox.app)"
  say "linked: $INSTALL_DIR/vox -> $APPS/Vox.app/Contents/Helpers/vox ($installed)"
else
  # --- vox (Linux, unchanged by ADR-014) -----------------------------------------------------
  fetch_asset "$ASSET" "$size" "$sha256" "$tmp/$ASSET"
  chmod 0755 "$tmp/$ASSET"

  # --- install (atomic) ------------------------------------------------------------------
  mkdir -p "$INSTALL_DIR"
  if [ -e "$INSTALL_DIR/vox" ] && [ ! -e "$INSTALL_DIR/$MARKER" ]; then
    fail "$INSTALL_DIR/vox exists but was not installed by this installer; remove it or set VOX_INSTALL_DIR"
  fi
  # Written on the destination's own filesystem, so the final rename is atomic.
  #
  # **A partial left by a run that was cut short is removed first** (V210-117). A partial name only
  # ever holds scratch, and one can be read-only: `vox update` before v0.2.10 left a 0555
  # `.vox-candidate.partial` when interrupted, and `cp` cannot open that for writing, so every later
  # run of this installer stopped at a bare "Permission denied". The previous binary is copied to a
  # partial of its own and renamed into place, for the same reason: a rename replaces a file that
  # cannot be written to, and a copy onto it does not.
  rm -f "$INSTALL_DIR/.vox-candidate.partial" "$INSTALL_DIR/.vox-previous.partial"
  cp "$tmp/$ASSET" "$INSTALL_DIR/.vox-candidate.partial"
  chmod 0755 "$INSTALL_DIR/.vox-candidate.partial"
  if [ -e "$INSTALL_DIR/vox" ]; then
    cp -p "$INSTALL_DIR/vox" "$INSTALL_DIR/.vox-previous.partial"
    mv -f "$INSTALL_DIR/.vox-previous.partial" "$INSTALL_DIR/.vox-previous"
  fi
  # The marker says "this install is ours" and names the channel `vox update` resolves the next
  # release on. Strict schema-1 JSON, the same shape the binary parses with deny_unknown_fields.
  printf '{"kind":"vox.install-channel","schema_version":1,"package":"vox","channel":"%s"}\n' \
    "$CHANNEL" >"$INSTALL_DIR/$MARKER"
  mv -f "$INSTALL_DIR/.vox-candidate.partial" "$INSTALL_DIR/vox"

  installed=$("$INSTALL_DIR/vox" --version 2>/dev/null || true)
  [ -n "$installed" ] || fail "the installed binary did not run"
  say "installed: $INSTALL_DIR/vox ($installed)"
fi

# --- shell integration (PATH first, then tab completion) --------------------------------
# Run through the installed binary so the rc block records the real install path. It appends
# ONE marker-delimited block at the end of your shell's rc — at the end, so it wins the PATH
# race against version managers that prepend their shims earlier in the same file — and writes
# completion scripts into each shell's own autoload directory. Idempotent;
# `vox shell-setup --remove` undoes it exactly; VOX_NO_SHELL_SETUP=1 skips it.
if [ -z "${VOX_NO_SHELL_SETUP:-}" ]; then
  "$INSTALL_DIR/vox" shell-setup </dev/null || say "warning: shell setup reported a problem (vox itself is installed)"
fi

say ""
say "next:"
say "  vox                 the interactive client"
say "  vox serve 22        offer this machine's ssh to a new room, and print the invite"
say "  vox update          install the next release"
