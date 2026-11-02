#!/usr/bin/env bash
# Produce non-published, source-bound macOS candidates using the release signers.
# Invoked in separate uncredentialed build and credentialed signing workflow steps.
set -euo pipefail

[[ $# -eq 1 && ( $1 == build || $1 == sign ) ]] || {
  echo "usage: $0 build|sign" >&2; exit 2; }
: "${RUNNER_TEMP:?}" "${EXPECTED_SHA:?}" "${MACOSX_DEPLOYMENT_TARGET:?}"
[[ $EXPECTED_SHA =~ ^[0-9a-f]{40}$ && $(git rev-parse HEAD) == "$EXPECTED_SHA" ]] || {
  echo 'candidate: checkout differs from the supplied SHA' >&2; exit 1; }
root="$RUNNER_TEMP/vox-candidates"
prior=753b17529c96efa84b6c89a3236b0348aff54559
triple=aarch64-apple-darwin
source_version=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')

if [[ $1 == build ]]; then
  [[ ! -e $root ]] || { echo "candidate: $root already exists" >&2; exit 1; }
  [[ $(git rev-parse 'refs/tags/v0.4.13^{commit}') == "$prior" ]] || {
    echo 'candidate: v0.4.13 does not resolve to its pinned commit' >&2; exit 1; }
  mkdir -p "$root/source" "$root/output" "$root/scratch/data" "$root/scratch/config"
  export VOX_DATA_DIR="$root/scratch/data" VOX_CONFIG_DIR="$root/scratch/config"
  for variant in normal lower-version-test-knobs current-test-knobs; do
    version="$source_version"
    feature=default
    if [[ $variant == lower-version-test-knobs ]]; then version=0.4.13; fi
    if [[ $variant != normal ]]; then feature=vox-tui/test-knobs; fi
    src="$root/source/$variant"
    out="$root/output/$variant"
    mkdir -p "$src" "$out"
    git archive "$EXPECTED_SHA" | tar -x -C "$src"
    (
      cd "$src"
      if [[ $variant == lower-version-test-knobs ]]; then
        cp Cargo.toml "$out/base-Cargo.toml"
        cp Cargo.lock "$out/base-Cargo.lock"
        SOURCE_VERSION="$source_version" python3 - <<'PY'
import os
from pathlib import Path
path = Path("Cargo.toml")
text = path.read_text()
old = f'[workspace.package]\nversion = "{os.environ["SOURCE_VERSION"]}"'
new = '[workspace.package]\nversion = "0.4.13"'
if text.count(old) != 1:
    raise SystemExit(f'candidate: expected exactly one {os.environ["SOURCE_VERSION"]} workspace version')
path.write_text(text.replace(old, new, 1))
PY
        echo '+ cargo update --workspace'
        cargo update --workspace
        git diff --no-index -- "$out/base-Cargo.toml" Cargo.toml > "$out/version.patch" || {
          status=$?; [[ $status == 1 ]] || exit "$status"; }
        git diff --no-index -- "$out/base-Cargo.lock" Cargo.lock > "$out/lock.patch" || {
          status=$?; [[ $status == 1 ]] || exit "$status"; }
        cp Cargo.lock "$out/Cargo.lock"
        rm "$out/base-Cargo.toml" "$out/base-Cargo.lock"
      fi
      actual=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
      [[ $actual == "$version" ]] || { echo "candidate: $variant workspace version is $actual, expected $version" >&2; exit 1; }
      if [[ $feature == default ]]; then
        echo '+ cargo build --locked --release --bin vox'
        cargo build --locked --release --bin vox
      else
        echo '+ cargo build --locked --release --bin vox --features vox-tui/test-knobs'
        cargo build --locked --release --bin vox --features vox-tui/test-knobs
      fi
      strip target/release/vox
      echo '+ target/release/vox --version'
      target/release/vox --version > "$out/compiled-version.txt"
      [[ $(cat "$out/compiled-version.txt") == "vox $version" ]] || {
        echo "candidate: compiled $variant version does not match $version" >&2; exit 1; }
      echo '+ scripts/build-macos-app.sh <isolated-derived-data>'
      scripts/build-macos-app.sh "$root/build/$variant" > "$out/app-build-path.txt"
    )
    if [[ $variant == lower-version-test-knobs ]]; then
      patch_sha=$(shasum -a 256 "$out/version.patch" | cut -d' ' -f1)
      lock_patch_sha=$(shasum -a 256 "$out/lock.patch" | cut -d' ' -f1)
      lock_sha=$(shasum -a 256 "$out/Cargo.lock" | cut -d' ' -f1)
    delta=$(jq -n --arg source_version "$source_version" --arg patch_sha "$patch_sha" --arg lock_patch_sha "$lock_patch_sha" \
        --arg lock_sha "$lock_sha" \
        '{from:$source_version,to:"0.4.13",patch:"version.patch",patch_sha256:$patch_sha,lock_patch:"lock.patch",lock_patch_sha256:$lock_patch_sha,generated_lock:"Cargo.lock",generated_lock_sha256:$lock_sha}')
    else
      delta=null
    fi
    jq -nS --arg source_sha "$EXPECTED_SHA" --arg public_prior_sha "$prior" \
      --arg version "$version" --arg features "$feature" --arg variant "$variant" \
      --argjson version_delta "$delta" \
      '{base_source_sha:$source_sha,public_prior_v0_4_13_reference_sha:$public_prior_sha,version:$version,features:$features,variant:$variant,shipping:false,version_delta:$version_delta}' \
      > "$out/source.json"
  done
  exit 0
fi

: "${APPLE_CODESIGN_IDENTIFIER:?}"
[[ -d $root/source && -d $root/output ]] || { echo 'candidate: build outputs are missing' >&2; exit 1; }
for variant in normal lower-version-test-knobs current-test-knobs; do
  src="$root/source/$variant"
  out="$root/output/$variant"
  version="$source_version"
  if [[ $variant == lower-version-test-knobs ]]; then version=0.4.13; fi
  (
    cd "$src"
    echo "+ scripts/sign_notarize_release.sh target/release/vox <cli-output> $version $triple <identifier> $MACOSX_DEPLOYMENT_TARGET"
    scripts/sign_notarize_release.sh target/release/vox "$out/cli" "$version" "$triple" \
      "$APPLE_CODESIGN_IDENTIFIER" "$MACOSX_DEPLOYMENT_TARGET"
    app=$(cat "$out/app-build-path.txt")
    echo "+ scripts/assemble-macos-app.sh <built-app> <signed-vox> <assembled-app> $version $MACOSX_DEPLOYMENT_TARGET"
    scripts/assemble-macos-app.sh "$app" "$out/cli/vox-$triple" \
      "$root/assembled/$variant/Vox.app" "$version" "$MACOSX_DEPLOYMENT_TARGET"
    echo "+ scripts/sign_notarize_app.sh <assembled-app> <app-output> $version $triple us.vox.app <identifier> $MACOSX_DEPLOYMENT_TARGET"
    scripts/sign_notarize_app.sh "$root/assembled/$variant/Vox.app" "$out/app" "$version" "$triple" \
      us.vox.app "$APPLE_CODESIGN_IDENTIFIER" "$MACOSX_DEPLOYMENT_TARGET"
  )
  rm "$out/app-build-path.txt"
  (cd "$out" && shasum -a 256 "cli/vox-$triple" "app/Vox-$version-$triple.zip" > SHA256SUMS)
done
