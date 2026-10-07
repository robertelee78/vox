#!/usr/bin/env bash
# Screenshots of Vox.app for documentation and release notes (ADR-014 M-34): rendered offscreen
# from demo data, in a scratch data root this script makes, never from a real data root. They show
# the look; they are not product proof.
#
#   scripts/app-screenshots.sh [out dir]     # default: target/screenshots
#
# It makes a demo data root (VOX_DATA_DIR and VOX_CONFIG_DIR both scratch) with a daemon and three
# nodes — ann, the node the screenshots act as; ben, a person; and builder, an agent — in a room
# "family" with messages, a file share, a service, a claim and a refused join; builds
# apps/macos/Screenshots with the app's view sources against VoxFFI; renders each window into
# PNGs; stops everything it started, by PID; and says where the demo root is.
#
# Local macOS hosts with Xcode 27 / sccache: set CARGO_PROFILE_RELEASE_STRIP=none and
# RUSTC_WRAPPER= (see scripts/build-xcframework.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="$(mkdir -p "${1:-target/screenshots}" && cd "${1:-target/screenshots}" && pwd)"
DEMO="$(mktemp -d "${TMPDIR:-/tmp}/vox-demo.XXXXXX")"
BUILD="$DEMO/build"
mkdir -p "$BUILD"
export VOX_DATA_DIR="$DEMO/data" VOX_CONFIG_DIR="$DEMO/config"
# The demo's own: no agent session of whoever runs this posts in it, and its daemon's .vox proxy
# takes a free port, never another daemon's 1080.
unset CODEX_HOME CLAUDE_CONFIG_DIR OPENCODE_CONFIG_DIR VOX_SESSION CLAUDE_CODE_SESSION_ID \
    CODEX_THREAD_ID CLAUDE_CODE_MESSAGING_SOCKET CLAUDE_CODE_MESSAGING_TOKEN VOX_HARNESS \
    VOX_OPENCODE_WAKE_SOCKET VOX_OPENCODE_WAKE_TOKEN
export VOX_PROXY=127.0.0.1:0
# Never the real data root: both are under the scratch directory made just now.
case "$VOX_DATA_DIR$VOX_CONFIG_DIR" in
    "$DEMO/data$DEMO/config") ;;
    *) echo "app-screenshots: refusing: the data root is not the scratch one" >&2; exit 2 ;;
esac

XCFRAMEWORK_SLICES=macos OUT="$BUILD/xcf" scripts/build-xcframework.sh >/dev/null
# The demo's own `vox`, built for proofs only (test-knobs: it may fetch a link card from the
# demo's local page, VOX_TEST_CARD_ALLOW), into the demo's directory; never the one shipped.
cargo build -q --release --bin vox --features vox-tui/test-knobs --target-dir "$BUILD/target"
cargo run -q -p vox-theme -- swift assets/theme/vox-tokens.json "$BUILD/theme"
VOX="$BUILD/target/release/vox"

DAEMON=""
PAGE=""
# Stop one process this script started, by its PID: asked first, killed after 10 s, and said so.
stop() {
    local pid=$1
    [ -n "$pid" ] || return 0
    kill "$pid" 2>/dev/null || return 0
    for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null
        echo "app-screenshots: pid $pid did not stop in 10 s; killed it" >&2
    fi
    wait "$pid" 2>/dev/null || true
}
cleanup() {
    stop "$PAGE"
    stop "$DAEMON"
    echo "app-screenshots: the demo data root was $DEMO (scratch; remove it when done)"
}
# However the script ends, its demo daemon and page server stop: a signal exits through the
# EXIT trap too (bash runs no EXIT trap for a signal it does not trap). One left behind ran 7 h.
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- the demo data -------------------------------------------------------------------------
# Every node has an identity passphrase (ADR-028 K-11): the demo's are this one.
printf 'demo identity\n' >"$DEMO/identity"
printf 'family room\n' >"$DEMO/room"
printf 'not it\n' >"$DEMO/wrong"
# A page on this machine for a link card (title, description, image), so the demo contacts no
# site; and a photo to share, so its card carries a preview.
python3 - "$DEMO" <<'PY'
import struct, sys, zlib
demo = sys.argv[1]
def png(w, h, px):
    rows = b"".join(b"\0" + bytes(c for x in range(w) for c in px(x, y)) for y in range(h))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))
open(f"{demo}/hike.png", "wb").write(png(240, 160, lambda x, y: (40 + y // 2, 120 + x // 4, 200 - y // 2)))
open(f"{demo}/soup.png", "wb").write(png(64, 64, lambda x, y: (200, 140 + x, 60 + y)))
open(f"{demo}/recipe.html", "w").write(
    '<html><head><title>Leek and potato soup</title>'
    '<meta property="og:title" content="Leek and potato soup">'
    '<meta property="og:description" content="Forty minutes, one pot, serves six.">'
    '<meta property="og:image" content="/soup.png"></head><body>soup</body></html>')
PY
python3 -u -m http.server 0 --bind 127.0.0.1 --directory "$DEMO" >"$DEMO/page.log" 2>&1 &
PAGE=$!
for _ in $(seq 1 50); do grep -q "Serving HTTP" "$DEMO/page.log" && break; sleep 0.1; done
PAGE_AT=$(sed -n 's/.*port \([0-9]*\).*/127.0.0.1:\1/p' "$DEMO/page.log" | head -1)
[ -n "$PAGE_AT" ] || { echo "app-screenshots: the demo's page server did not start" >&2; exit 2; }
VOX_TEST_CARD_ALLOW="$PAGE_AT" "$VOX" daemon --listen 127.0.0.1:0 >"$DEMO/daemon.log" 2>&1 &
DAEMON=$!
for _ in $(seq 1 100); do grep -q "control socket" "$DEMO/daemon.log" && break; sleep 0.1; done
for n in ann ben builder stranger; do
    "$VOX" node create "$n" --passphrase-file "$DEMO/identity" >/dev/null
    "$VOX" node attach "$n" --passphrase-file "$DEMO/identity" >/dev/null
done
fp() { "$VOX" id --node "$1" | tail -1; }
ANN=$(fp ann) BEN=$(fp ben) BUILDER=$(fp builder)
"$VOX" room create --node ann --passphrase-file "$DEMO/room" --name family >/dev/null
ROOM=$("$VOX" room list --node ann | awk 'NR==1{print $1}')
LINK=$("$VOX" room link --node ann "$ROOM" | grep '^vox://')
for n in ben builder; do
    "$VOX" room join --node "$n" --passphrase-file "$DEMO/room" "$LINK" >/dev/null
done
# A keyring change's passphrase is typed at a terminal (ADR-028 K-13): typed here, as a person does.
trust() {
    python3 scripts/type-passphrase.py 120 "$VOX" trust add --node "$1" "$2" --name "$3" \
        <"$DEMO/identity" >"$DEMO/trust.log" 2>&1 ||
        { echo "app-screenshots: trusting $3 as $1 failed:" >&2; cat "$DEMO/trust.log" >&2; exit 2; }
}
trust ann "$BEN" ben; trust ann "$BUILDER" builder
trust ben "$ANN" ann; trust builder "$ANN" ann; trust ben "$BUILDER" builder; trust builder "$BEN" ben
for i in $(seq 1 30); do
    "$VOX" room post --node ben "$ROOM" "Dinner at seven? I can bring the bread." >/dev/null
    sleep 1
    "$VOX" room read --node ann "$ROOM" 2>/dev/null | grep -q "Dinner" && break
done
"$VOX" room post --node ann "$ROOM" "Seven works. I'll make the soup." >/dev/null
# ann keeps the room's messages a week: the timeline says so among them, and in its title.
"$VOX" room retention --node ann "$ROOM" 1w >/dev/null
printf 'Shopping: leeks, potatoes, cream, bread.\n' >"$DEMO/shopping-list.txt"
"$VOX" share --node ben "$ROOM" "$DEMO/shopping-list.txt" --to "$ANN" -m "the list for Saturday" >/dev/null
"$VOX" share --node ben "$ROOM" "$DEMO/hike.png" -m "the view from Sunday's hike" >/dev/null
"$VOX" room post --node ann "$ROOM" "The soup: http://$PAGE_AT/recipe.html" >/dev/null
printf 'Leeks, potatoes, stock, cream. Forty minutes.\n' >"$DEMO/soup-recipe.txt"
"$VOX" share --node ann "$ROOM" "$DEMO/soup-recipe.txt" --to "$BEN" -m "the recipe, for Saturday" >/dev/null
# ben collects it, so ann's view says who pulled it; the render waits until ann's node says so.
for i in $(seq 1 30); do
    "$VOX" room get --node ben "$ROOM" soup-recipe.txt >/dev/null 2>&1 &&
        "$VOX" room read --node ann "$ROOM" 2>/dev/null | grep -q "pulled by" && break
    sleep 1
done
"$VOX" room read --node ann "$ROOM" | grep -q "pulled by" ||
    { echo "APPARATUS: ben's pull of soup-recipe.txt never showed as pulled by in ann's room read" >&2; exit 1; }
# The agent's own session, named here: a claim is owned per session.
VOX_SESSION=builder-demo "$VOX" room claim --node builder "$ROOM" photo-album >/dev/null
VOX_SESSION=builder-demo "$VOX" room post --node builder --type working "$ROOM" \
    "Sorting the holiday photos into the album." >/dev/null
"$VOX" service add --node ben "$ROOM" photos 127.0.0.1:8080 >/dev/null
# `vox room post --to` speaks for a session, and refuses without one: ben's, named.
VOX_SESSION=ben-demo "$VOX" room post --node ben --to "$ANN" "$ROOM" \
    "Can you check the photo album when it's done?" >/dev/null
"$VOX" room join --node stranger --passphrase-file "$DEMO/wrong" "$LINK" >/dev/null 2>&1 || true
sleep 3

# ---- the renderer: the app's views, offscreen ------------------------------------------------
LIB="$BUILD/xcf/VoxFFI.xcframework/macos-arm64"
APP="$BUILD/VoxScreens.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
sources=()
for f in apps/macos/Vox/*.swift; do
    [ "$(basename "$f")" = VoxApp.swift ] || sources+=("$f")
done
swiftc -O -target arm64-apple-macos13.0 -o "$APP/Contents/MacOS/VoxScreens" \
    apps/macos/Screenshots/main.swift "${sources[@]}" "$BUILD/theme/VoxTokens.swift" \
    "$BUILD/xcf/swift/vox_ffi.swift" -I "$LIB/Headers" -L "$LIB" \
    -lvox_ffi -framework Security -framework SystemConfiguration
xcrun actool --compile "$APP/Contents/Resources" --platform macosx --minimum-deployment-target 13.0 \
    apps/macos/Vox/Assets.xcassets "$BUILD/theme/VoxTokens.xcassets" >/dev/null
cp apps/macos/Vox/Fonts/*.otf "$APP/Contents/Resources/"
cat >"$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>us.vox.screenshots</string>
<key>CFBundleExecutable</key><string>VoxScreens</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST
"$APP/Contents/MacOS/VoxScreens" "$OUT" "$VOX_DATA_DIR" ann family
echo "app-screenshots: screenshots in $OUT"
