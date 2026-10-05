#!/usr/bin/env bash
# Build VoxFFI.xcframework: the embedded Vox node for iOS and macOS apps (PRD-001 R30/R31,
# ADR-014), with its UniFFI-generated Swift bindings.
#
#   scripts/build-xcframework.sh            # -> target/xcframework/
#   OUT=/some/dir scripts/build-xcframework.sh
#
#   XCFRAMEWORK_SLICES=macos scripts/build-xcframework.sh   # the macOS slice only
#
# Slices: aarch64-apple-ios (devices), aarch64-apple-ios-sim (Apple-silicon simulators),
# and aarch64-apple-darwin. Each is a static library: an app links the node in, nothing is
# loaded at run time. There is no Intel macOS slice: on macOS Vox supports Apple Silicon
# on macOS 13 or later only (ADR-014 M-26a). With XCFRAMEWORK_SLICES=macos only the macOS
# slice is built, which is all Vox.app links (the release job needs no iOS target).
#
# Needs those Rust targets (`rustup target add aarch64-apple-ios aarch64-apple-ios-sim
# aarch64-apple-darwin`, or only the last for the macOS slice) and Xcode's command-line
# tools.
#
# Local macOS hosts with Xcode 27 / sccache: set
#   CARGO_PROFILE_RELEASE_STRIP=none   Xcode 27's strip corrupts release proc-macro dylibs
#                                      ("mis-aligned LINKEDIT string pool"; rustc then says
#                                      "can't find crate for `time_macros`" or similar)
#   RUSTC_WRAPPER=                     sccache mixed in rlibs from rustup's default toolchain
#                                      during the bindings step (E0514, "compiled by an
#                                      incompatible version of rustc")
# Neither is needed where neither tool is (CI).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/target/xcframework}"
PROFILE=release
case "${XCFRAMEWORK_SLICES:-all}" in
    all) TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin) ;;
    macos) TARGETS=(aarch64-apple-darwin) ;;
    *)
        echo "build-xcframework: XCFRAMEWORK_SLICES is all or macos, not ${XCFRAMEWORK_SLICES}" >&2
        exit 1
        ;;
esac
# The iOS floor. Rust's own default for the ios targets is older; state it once, here,
# so the objects and the xcframework agree.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

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
mkdir -p "$OUT/swift" "$OUT/headers"

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

libraries=()
for t in "${TARGETS[@]}"; do
    libraries+=(-library "target/$t/$PROFILE/libvox_ffi.a" -headers "$OUT/headers")
done
xcodebuild -create-xcframework "${libraries[@]}" -output "$OUT/VoxFFI.xcframework"

echo "build-xcframework: $OUT/VoxFFI.xcframework"
echo "build-xcframework: Swift bindings in $OUT/swift/vox_ffi.swift"
