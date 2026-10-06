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
cargo build -q --release --bin vox
cargo run -q -p vox-theme -- swift assets/theme/vox-tokens.json "$BUILD/theme"
VOX="$ROOT/target/release/vox"

DAEMON=""
cleanup() {
    [ -n "$DAEMON" ] && kill "$DAEMON" 2>/dev/null && wait "$DAEMON" 2>/dev/null
    echo "app-screenshots: the demo data root was $DEMO (scratch; remove it when done)"
}
trap cleanup EXIT

# ---- the demo data -------------------------------------------------------------------------
: >"$DEMO/empty"
printf 'family room\n' >"$DEMO/room"
printf 'not it\n' >"$DEMO/wrong"
"$VOX" daemon --listen 127.0.0.1:0 >"$DEMO/daemon.log" 2>&1 &
DAEMON=$!
for _ in $(seq 1 100); do grep -q "control socket" "$DEMO/daemon.log" && break; sleep 0.1; done
for n in ann ben builder stranger; do
    "$VOX" node create "$n" --passphrase-file "$DEMO/empty" >/dev/null
    "$VOX" node attach "$n" --passphrase-file "$DEMO/empty" >/dev/null
done
fp() { "$VOX" id --node "$1" | tail -1; }
ANN=$(fp ann) BEN=$(fp ben) BUILDER=$(fp builder)
"$VOX" room create --node ann --passphrase-file "$DEMO/room" --name family >/dev/null
ROOM=$("$VOX" room list --node ann | awk 'NR==1{print $1}')
LINK=$("$VOX" room link --node ann "$ROOM" | grep '^vox://')
for n in ben builder; do
    "$VOX" room join --node "$n" --passphrase-file "$DEMO/room" "$LINK" --name family >/dev/null 2>&1
done
trust() { "$VOX" trust add --node "$1" "$2" --name "$3" --identity-passphrase-file "$DEMO/empty" >/dev/null; }
trust ann "$BEN" ben; trust ann "$BUILDER" builder
trust ben "$ANN" ann; trust builder "$ANN" ann; trust ben "$BUILDER" builder; trust builder "$BEN" ben
for i in $(seq 1 30); do
    "$VOX" room post --node ben "$ROOM" "Dinner at seven? I can bring the bread." >/dev/null
    sleep 1
    "$VOX" room read --node ann "$ROOM" 2>/dev/null | grep -q "Dinner" && break
done
"$VOX" room post --node ann "$ROOM" "Seven works. I'll make the soup." >/dev/null
printf 'Shopping: leeks, potatoes, cream, bread.\n' >"$DEMO/shopping-list.txt"
"$VOX" share --node ben "$ROOM" "$DEMO/shopping-list.txt" --to "$ANN" -m "the list for Saturday" >/dev/null
# The agent's own session, named here: a claim is owned per session.
VOX_SESSION=builder-demo "$VOX" room claim --node builder "$ROOM" photo-album >/dev/null
VOX_SESSION=builder-demo "$VOX" room post --node builder --type working "$ROOM" \
    "Sorting the holiday photos into the album." >/dev/null
"$VOX" service add --node ben "$ROOM" photos 127.0.0.1:8080 >/dev/null
# `vox room post --to` speaks for a session, and refuses without one: ben's, named.
VOX_SESSION=ben-demo "$VOX" room post --node ben --to "$ANN" "$ROOM" \
    "Can you check the photo album when it's done?" >/dev/null
"$VOX" room join --node stranger --passphrase-file "$DEMO/wrong" "$LINK" --name family >/dev/null 2>&1 || true
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
