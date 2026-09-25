#!/usr/bin/env bash
# Link the iOS-simulator slice of VoxFFI.xcframework into a small Swift program and run it
# inside an iOS simulator (PRD-001 R31). Run `scripts/build-xcframework.sh` first.
#
#   scripts/ios-sim-smoke.sh [<simulator name or udid>]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/target/xcframework}"
DEVICE="${1:-iPhone 17}"
SLICE="$OUT/VoxFFI.xcframework/ios-arm64-simulator"
BIN="$OUT/ios-smoke"
SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"

xcrun --sdk iphonesimulator swiftc -O \
    -target arm64-apple-ios15.0-simulator -sdk "$SDK" \
    -o "$BIN" \
    "$ROOT/crates/vox-ffi/ios-smoke/main.swift" "$OUT/swift/vox_ffi.swift" \
    -I "$SLICE/Headers" -L "$SLICE" -lvox_ffi \
    -framework Security -framework SystemConfiguration
echo "ios-sim-smoke: linked $BIN for the simulator"

# Boot the device if it is not already; leave it as found otherwise.
state="$(xcrun simctl list devices | grep -F "$DEVICE (" | head -1 || true)"
booted_here=0
if ! grep -q "(Booted)" <<<"$state"; then
    xcrun simctl boot "$DEVICE"
    booted_here=1
fi
xcrun simctl spawn "$DEVICE" "$BIN"
if [ "$booted_here" = 1 ]; then
    xcrun simctl shutdown "$DEVICE"
fi
