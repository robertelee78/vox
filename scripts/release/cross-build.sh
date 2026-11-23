#!/usr/bin/env bash
# One preparation, build or cleanup action per shared hold. Only the harness is cross-built;
# the binary under proof always comes from --dist through its own installer.
set -euo pipefail
root=${VOX_JOURNEY_SOURCE:?exact integrated proof source required}
action=${1:?setup|build|cleanup}
state=${2:?absolute evidence directory}
name=vox-rg15-compiler
image=docker.io/library/rust@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55
p=(podman --connection podman-machine-default-root)
mkdir -p "$state"
case "$action" in
  setup)
    "${p[@]}" image exists "$image" && echo existing >"$state/compiler-image" || echo acquired >"$state/compiler-image"
    "${p[@]}" create --platform linux/arm64 --cpus 4 --memory 8g --name "$name" "$image" sleep infinity
    "${p[@]}" start "$name"
    "${p[@]}" exec "$name" sh -ec 'apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y gcc-x86-64-linux-gnu g++-x86-64-linux-gnu pkg-config cmake python3; mkdir -p /src'
    tar --exclude=.git --exclude=target --exclude=.env -cf "$state/source.tar" -C "$root" .
    "${p[@]}" cp "$state/source.tar" "$name:/source.tar"
    "${p[@]}" exec "$name" tar -xf /source.tar -C /src
    if [[ -n ${VOX_PROOF_COMPILER_CACHE:-} ]]; then
      "${p[@]}" cp "$VOX_PROOF_COMPILER_CACHE/cargo/." "$name:/usr/local/cargo/"
      "${p[@]}" cp "$VOX_PROOF_COMPILER_CACHE/rustup/." "$name:/usr/local/rustup/"
      "${p[@]}" exec "$name" mkdir -p /src/target/x86_64-unknown-linux-gnu
      "${p[@]}" cp "$VOX_PROOF_COMPILER_CACHE/target/release" "$name:/src/target/release"
      "${p[@]}" cp "$VOX_PROOF_COMPILER_CACHE/target/x86_64-unknown-linux-gnu/release" "$name:/src/target/x86_64-unknown-linux-gnu/release"
    fi
    "${p[@]}" exec "$name" rustup target add --toolchain 1.94.0 x86_64-unknown-linux-gnu
    ;;
  refresh)
    # Resume this task's owned compiler after a cache-copy fault, without recreating it.
    tar --exclude=.git --exclude=target --exclude=.env -cf "$state/source.tar" -C "$root" .
    "${p[@]}" cp "$state/source.tar" "$name:/source.tar"
    "${p[@]}" exec "$name" sh -ec 'tar -xf /source.tar -C /src; mkdir -p /src/target/x86_64-unknown-linux-gnu/release'
    "${p[@]}" cp "${VOX_PROOF_COMPILER_CACHE:?}/target/x86_64-unknown-linux-gnu/release/." "$name:/src/target/x86_64-unknown-linux-gnu/release/"
    "${p[@]}" exec "$name" rustup target add --toolchain 1.94.0 x86_64-unknown-linux-gnu
    ;;
  build)
    "${p[@]}" exec --workdir /src -e CARGO_BUILD_JOBS=6 \
      -e CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
      -e CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
      -e CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++ \
      "$name" cargo test --release --target x86_64-unknown-linux-gnu -p vox-tui \
      --features test-knobs,optional-proofs --test a_newcomer_reads_the_whole_history_proof \
      --test install_sh_proof --test update_proof --no-run --message-format=json >"$state/build.jsonl"
    for target in a_newcomer_reads_the_whole_history_proof install_sh_proof update_proof; do
      binary=$(python3 -c 'import json,sys; rows=[json.loads(s) for s in open(sys.argv[1])]; print(next(r["executable"] for r in rows if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")==sys.argv[2] and r.get("profile",{}).get("test") and r.get("executable")))' "$state/build.jsonl" "$target")
      "${p[@]}" cp "$name:$binary" "$state/$target"
    done
    ;;
  cleanup)
    "${p[@]}" stop --time 20 "$name"
    "${p[@]}" rm --volumes "$name"
    if [[ $(cat "$state/compiler-image") == acquired ]]; then "${p[@]}" rmi "$image"; fi
    ;;
  *) exit 2;;
esac
