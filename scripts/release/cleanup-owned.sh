#!/usr/bin/env bash
# Run only after bg695's active busy proof has ended; this is cleanup, never a rehearsal.
# Exact names below were created by this worker and recorded in owned-container.txt.
set -euo pipefail
p=(podman --connection podman-machine-default-root)
for name in vox-rg15-busy-76332 vox-rg15-busy-28186 vox-rg15-compiler; do
  if "${p[@]}" container exists "$name"; then
    "${p[@]}" stop --time 20 "$name"
    "${p[@]}" rm --volumes "$name"
  fi
done
# The compiler image was recorded EXISTING: never remove it here.
# Successful per-journey runners remove images only when absent at their own start.
# A timed-out runner may not have reached finally; inspect its original pull receipt
# before image removal. Never force removal of an image borrowed elsewhere.
