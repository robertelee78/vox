#!/bin/sh
# Vox Lux installer — ADR-015 §"Install and update".
#
#   curl -fsSL https://raw.githubusercontent.com/robertelee78/vox/main/install.sh | sh
#
# Installs the latest `vox` release for this machine into ~/.local/bin (override with
# VOX_INSTALL_DIR). Fetches the per-target release record through GitHub's
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
# VOX_RELEASE_BASE exists for the installer's own end-to-end test against a local
# stand-in server; the origin check below still applies to redirects from it.
BASE="${VOX_RELEASE_BASE:-https://github.com/${REPO}/releases}"
INSTALL_DIR="${VOX_INSTALL_DIR:-$HOME/.local/bin}"
CHANNEL="${VOX_CHANNEL:-stable}"
MARKER=".vox-channel"
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
field() { sed -n "s/.*\"$1\":[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" "$tmp/record.json" | head -1; }
kind=$(field kind); schema=$(field schema_version); pkg=$(field package)
rchannel=$(field channel); rtarget=$(field target)
version=$(field version); size=$(field size); sha256=$(field sha256)
[ "$kind" = "vox.standalone-release" ] && [ "$schema" = "1" ] && [ "$pkg" = "vox" ] \
  && [ "$rchannel" = "$CHANNEL" ] && [ "$rtarget" = "$TARGET" ] \
  || fail "release record identity mismatch (kind=$kind schema=$schema package=$pkg channel=$rchannel target=$rtarget)"
[ -n "$version" ] && [ -n "$size" ] && [ -n "$sha256" ] || fail "release record incomplete"
say "vox ${version} for ${TARGET}"

# --- binary ---------------------------------------------------------------------------
# Pinned to the exact release the record came from — not `latest`, which could move between
# the two requests — and refused if the download leaves GitHub's origins.
url="${BASE}/download/v${version}/${ASSET}"
curl -fsSL $CURL_PROTO --max-filesize "$size" \
  -w '%{url_effective}\n' -o "$tmp/$ASSET" "$url" >"$tmp/final_url" \
  || fail "download failed: $url"
final=$(cat "$tmp/final_url")
case "$final" in
  https://github.com/*|https://release-assets.githubusercontent.com/*|https://objects.githubusercontent.com/*) ;;
  "$BASE"/*) ;;  # the configured base itself (test stand-in)
  *) fail "download redirected off GitHub: $final" ;;
esac
got_size=$(wc -c <"$tmp/$ASSET" | tr -d ' ')
[ "$got_size" = "$size" ] || fail "size mismatch: expected $size, got $got_size"
got_sha=$(sha "$tmp/$ASSET")
[ "$got_sha" = "$sha256" ] || fail "sha256 mismatch: expected $sha256, got $got_sha"
chmod 0755 "$tmp/$ASSET"

# --- install (atomic) ------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
if [ -e "$INSTALL_DIR/vox" ] && [ ! -e "$INSTALL_DIR/$MARKER" ]; then
  fail "$INSTALL_DIR/vox exists but was not installed by this installer; remove it or set VOX_INSTALL_DIR"
fi
# Written on the destination's own filesystem, so the final rename is atomic.
cp "$tmp/$ASSET" "$INSTALL_DIR/.vox-candidate.partial"
chmod 0755 "$INSTALL_DIR/.vox-candidate.partial"
if [ -e "$INSTALL_DIR/vox" ]; then
  cp -p "$INSTALL_DIR/vox" "$INSTALL_DIR/.vox-previous"
fi
# The marker says "this install is ours", and its first line names the channel `vox update`
# will look the next release up on.
printf '%s\n' "$CHANNEL" >"$INSTALL_DIR/$MARKER"
mv -f "$INSTALL_DIR/.vox-candidate.partial" "$INSTALL_DIR/vox"

installed=$("$INSTALL_DIR/vox" --version 2>/dev/null || true)
[ -n "$installed" ] || fail "the installed binary did not run (on macOS see: codesign -dv $INSTALL_DIR/vox)"
say "installed: $INSTALL_DIR/vox ($installed)"

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
say "  vox update          replace this binary with the next release"
