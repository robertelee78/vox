#!/usr/bin/env bash
# Nonshipping Linux updater fixture only. Each action is a separate shared slot hold.
set -euo pipefail
action=${1:?prepare-next|current|next}
state=${2:?absolute evidence directory}
root=${VOX_JOURNEY_SOURCE:?exact integrated proof source required}
p=(podman --connection podman-machine-default-root)
name=vox-rg15-compiler
mkdir -p "$state"
base=$("${p[@]}" exec "$name" awk -F '"' '/^version =/ {print $2; exit}' /src/Cargo.toml)
next="9${base:1}"
if [[ $action == prepare-next ]]; then
  "${p[@]}" exec "$name" sh -ec 'mkdir /next; cd /src; tar --exclude=target --exclude=.git -cf /tmp/next-source.tar .; tar -xf /tmp/next-source.tar -C /next'
  "${p[@]}" exec "$name" python3 -c 'from pathlib import Path; import re,sys; p=Path("/next/Cargo.toml"); s=p.read_text(); s,n=re.subn(r"(\[workspace.package\]\nversion = \u0022)[^\u0022]+", r"\g<1>"+sys.argv[1], s); assert n==1; p.write_text(s)' "$next"
  "${p[@]}" exec --workdir /next -e CARGO_BUILD_JOBS=6 "$name" cargo update --workspace
  exit
fi
case "$action" in
  current) dir=/src; version=$base;;
  next) dir=/next; version=$next;;
  *) exit 2;;
esac
"${p[@]}" exec --workdir "$dir" -e CARGO_BUILD_JOBS=6 -e CARGO_TARGET_DIR=/src/target \
  -e CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
  -e CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
  -e CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++ \
  "$name" cargo build --release --target x86_64-unknown-linux-gnu --bin vox --features vox-tui/test-knobs
out="$state/$action"
mkdir "$out"
"${p[@]}" cp "$name:/src/target/x86_64-unknown-linux-gnu/release/vox" "$out/vox-x86_64-unknown-linux-gnu"
cp "$root/install.sh" "$out/install.sh"
python3 - "$out" "$version" <<'PY'
import hashlib, json, pathlib, sys
out=pathlib.Path(sys.argv[1]); binary=out/'vox-x86_64-unknown-linux-gnu'; data=binary.read_bytes()
assert b'VOX_TEST_RELEASE_BASE' in data, 'APPARATUS: nonshipping pair lacks test-knobs'
record=dict(kind='vox.standalone-release',schema_version=1,package='vox',channel='stable',target='x86_64-unknown-linux-gnu',version=sys.argv[2],size=len(data),sha256=hashlib.sha256(data).hexdigest())
(out/'stable-x86_64-unknown-linux-gnu.json').write_text(json.dumps(record)+'\n')
(out/'source.json').write_text(json.dumps(dict(shipping=False,fixture=True,version=sys.argv[2],features='test-knobs',note='Genuinely compiled source pair; not a published updater or floor-built dist'))+'\n')
PY
