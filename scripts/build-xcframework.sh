#!/usr/bin/env bash
# Build VoxFFI.xcframework: the embedded Vox node for iOS and macOS apps (PRD-001 R30/R31,
# ADR-014), with its UniFFI-generated Swift bindings.
#
#   scripts/build-xcframework.sh            # -> target/xcframework/
#   OUT=/some/dir scripts/build-xcframework.sh
#
# Slices: aarch64-apple-ios (devices), aarch64-apple-ios-sim (Apple-silicon simulators),
# and one macOS slice holding aarch64 and x86_64. Each is a static library: an app links
# the node in, nothing is loaded at run time.
#
# Needs the four Rust targets (`rustup target add aarch64-apple-ios aarch64-apple-ios-sim
# aarch64-apple-darwin x86_64-apple-darwin`) and Xcode's command-line tools.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/target/xcframework}"
PROFILE=release
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin x86_64-apple-darwin)
# The iOS floor. Rust's own default for the ios targets is older; state it once, here,
# so the objects and the xcframework agree.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"

cd "$ROOT"
installed="$(rustup target list --installed)"
for t in "${TARGETS[@]}"; do
    if ! grep -qx "$t" <<<"$installed"; then
        echo "build-xcframework: Rust target $t is not installed; run: rustup target add $t" >&2
        exit 1
    fi
done

for t in "${TARGETS[@]}"; do
    echo "build-xcframework: building $t"
    cargo build -p vox-ffi --lib --"$PROFILE" --target "$t"
done

rm -rf "$OUT"
mkdir -p "$OUT/swift" "$OUT/headers" "$OUT/macos"

# The bindings come from the built library itself (UniFFI's library mode), so they cannot
# drift from what was compiled.
echo "build-xcframework: generating Swift bindings"
# The generator's templates find their config by a path relative to the crate's source
# directory, which breaks when CARGO_HOME is reached through a symlink (it is on at least
# one development machine, into iCloud Drive). The physical path is the same directory.
CARGO_HOME="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)" \
cargo run -q -p vox-ffi --features bindgen --bin uniffi-bindgen -- generate \
    --library "target/aarch64-apple-darwin/$PROFILE/libvox_ffi.a" \
    --language swift --out-dir "$OUT/swift"

cp "$OUT/swift/vox_ffiFFI.h" "$OUT/headers/"
# An xcframework's headers directory carries a `module.modulemap` by that exact name.
cp "$OUT/swift/vox_ffiFFI.modulemap" "$OUT/headers/module.modulemap"

lipo -create \
    "target/aarch64-apple-darwin/$PROFILE/libvox_ffi.a" \
    "target/x86_64-apple-darwin/$PROFILE/libvox_ffi.a" \
    -output "$OUT/macos/libvox_ffi.a"

xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/$PROFILE/libvox_ffi.a" -headers "$OUT/headers" \
    -library "target/aarch64-apple-ios-sim/$PROFILE/libvox_ffi.a" -headers "$OUT/headers" \
    -library "$OUT/macos/libvox_ffi.a" -headers "$OUT/headers" \
    -output "$OUT/VoxFFI.xcframework"

echo "build-xcframework: $OUT/VoxFFI.xcframework"
echo "build-xcframework: Swift bindings in $OUT/swift/vox_ffi.swift"
