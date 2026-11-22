#!/bin/sh
# ADR-051 LB-2: run inside the pinned glibc 2.28 release image.
set -eu
out=${1:?usage: linux-release-steps.sh OUT_DIR}
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
cd "$root"
toolchain=$(sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml)
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/vox-rustup.sh
  sh /tmp/vox-rustup.sh -y --profile minimal --default-toolchain "$toolchain"
  rm /tmp/vox-rustup.sh
fi
rustup toolchain install "$toolchain" --profile minimal
command -v jq >/dev/null 2>&1 || dnf install -y jq
cargo build --release --bin vox
cp target/release/vox target/release/vox-symbols
strip target/release/vox
floor=$(sed -n 's/^LINUX_GLIBC_FLOOR=//p' "$root/install.sh")
need=$(readelf -V target/release/vox | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -Vu | tail -n 1)
[ -n "$need" ] && [ -n "$floor" ]
if [ "$(printf '%s\n%s\n' "$need" "$floor" | sort -V | tail -n 1)" != "$floor" ]; then
  echo "linux-release-steps: vox needs glibc $need; floor $floor: above the floor"; exit 1
fi
echo "linux-release-steps: vox needs glibc $need; floor $floor: ok"
package=$(mktemp -d)
trap 'rm -rf "$package"' EXIT
cp Cargo.toml "$package/"
(cd "$package" && "$root/scripts/package-release.sh" "$root/target/release/vox" x86_64-unknown-linux-gnu && "$root/scripts/package-release.sh" "$root/target/release/vox-symbols" x86_64-unknown-linux-gnu symbols)
mkdir -p "$out"
cp -R "$package/dist/." "$out/"
