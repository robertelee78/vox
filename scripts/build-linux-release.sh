#!/bin/sh
# ADR-051 LB-2: the same image and steps as the release job.
set -eu
out=${1:?usage: build-linux-release.sh OUT_DIR}
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
image=$(sed -n 's/^    container: \(quay.io\/pypa\/manylinux_2_28_x86_64@sha256:[0-9a-f]*\)$/\1/p' "$root/.github/workflows/release.yml")
[ -n "$image" ] || { echo 'build-linux-release: release.yml has no pinned Linux build image' >&2; exit 1; }
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
mkdir -p "$out"
if command -v podman >/dev/null 2>&1; then engine=podman; else engine=docker; fi
"$engine" run --rm --platform linux/amd64 -v "$root:/source:ro" -v "$out:/dist" -w /vox "$image" \
  sh -c 'cp -a /source/. /vox/; cd /vox; sh scripts/linux-release-steps.sh /dist'
