#!/bin/sh
# The local release gate: run on a real Mac, on the commit to be tagged, before `git tag`.
#
#   GH_TOKEN=$(gh auth token --user robertelee78) scripts/release-gate.sh
#
# A tag is not cut unless this exits 0. It is the one place where:
#
# - **the live-model proofs run** (ADR-018, "No proof is excluded by name, and one gap remains").
#   CI keeps one accepted gap, `opencode`: its runners have neither OpenCode nor a model account.
#   The decider chose (2026-09-26) "Only on this Mac": those proofs run here, with the decider's
#   OpenCode account, and must be green before every tag. Here VOX_PROOF_ALLOW_UNPROVEN is unset,
#   so a live-model proof that cannot run is red, not excused;
# - **R41's WAN link is gated on real hardware** (decider, 2026-09-26). CI reports it on the
#   macOS runner, whose VM stalls, and gates it only on ubuntu;
# - **the CI run on this commit is checked** to have passed, with every job inside two-thirds of its
#   `timeout-minutes` (V210-14, #187). release.yml publishes only a commit whose CI passed on main
#   (#186); this refuses earlier, and says which job is near its limit.
#
# It runs what CI's build-test and transport-gates run, with nothing skipped but the gap-free
# set: fmt, clippy -D warnings, the debug suite, rustdoc -D warnings, and the release `--ignored`
# suite including the transport proofs.
#
# Needs: macOS; `opencode` on PATH, logged in; `pyte` importable, or VOX_PYTE_PATH set (the TUI
# proof); `gh`; GH_TOKEN for the repository's account. Builds are polite (nice, 4 jobs) because
# other work shares the machine; the proofs are timing-sensitive, so run nothing heavy alongside.
set -u

fail=0
note() { printf '%s\n' "release-gate: $*"; }
bad() { note "RED: $*"; fail=1; }

[ "$(uname -s)" = Darwin ] || { note "run this on a real Mac (the macOS gate); this is $(uname -s)"; exit 2; }
command -v opencode >/dev/null 2>&1 || { note "opencode is not on PATH: the live-model proofs cannot run"; exit 2; }
command -v gh >/dev/null 2>&1 || { note "gh is not on PATH: the CI run cannot be checked"; exit 2; }
[ -n "${GH_TOKEN:-}" ] || { note "set GH_TOKEN for the repository's account"; exit 2; }
if [ -z "${VOX_PYTE_PATH:-}" ] && ! python3 -c 'import pyte' >/dev/null 2>&1; then
  note "pyte is not importable and VOX_PYTE_PATH is unset: the TUI proof cannot run"; exit 2
fi
[ -z "$(git status --porcelain)" ] || { note "the tree is not clean; gate the commit you will tag"; exit 2; }

head=$(git rev-parse HEAD)
note "gating $head"

# Nothing excused, and no live session leaks into the proofs (the harness strips these too).
unset VOX_PROOF_ALLOW_UNPROVEN VOX_PERF_REPORT_ONLY VOX_PERF_ONLY VOX_PERF_MIN_RATIO
unset CLAUDE_CODE_MESSAGING_SOCKET CLAUDE_CODE_MESSAGING_TOKEN OPENCODE_SERVER_URL VOX_HARNESS

polite() { nice -n 10 env CARGO_BUILD_JOBS=4 "$@"; }

step() {
  name=$1; shift
  note "$name ..."
  if "$@"; then note "$name: ok"; else bad "$name"; fi
}

step "fmt" cargo fmt --all --check
step "clippy" polite cargo clippy --all-targets -- -D warnings
# The proofs build with the test-only knobs (V210-105); no shipped build has them.
step "clippy (test knobs)" polite cargo clippy --all-targets --features vox-tui/test-knobs -- -D warnings
step "debug suite" polite cargo test --workspace --no-fail-fast --features vox-tui/test-knobs
step "rustdoc" env RUSTDOCFLAGS="-D warnings" nice -n 10 cargo doc --workspace --no-deps
# ADR-025 P9 and P10 run against the mutant sender, built from this commit (as CI builds it).
if VOX_MUTANT_SENDER=$(polite scripts/build-mutant-sender.sh); then
  export VOX_MUTANT_SENDER
  note "mutant sender: $VOX_MUTANT_SENDER"
else
  bad "building the mutant sender"
fi
step "release suite (all proofs, live-model and transport included)" \
  polite cargo test --release --workspace --no-fail-fast --features vox-tui/test-knobs -- --ignored

# ---- the CI run on this commit: passed, and every job well inside its limit ----
note "CI on $head ..."
python3 - "$head" <<'PY' || fail=1
import json, re, subprocess, sys
from datetime import datetime
head = sys.argv[1]
def gh(*a):
    return json.loads(subprocess.check_output(["gh", *a], text=True))
runs = gh("run", "list", "--workflow", "ci.yml", "--commit", head,
          "--json", "databaseId,status,conclusion,event,headBranch")
runs = [r for r in runs if r["event"] == "push" and r["headBranch"] == "main"]
if not runs:
    print(f"release-gate: RED: no CI run on main for {head}: push it to main and let CI finish")
    sys.exit(1)
run = runs[0]
if run["status"] != "completed" or run["conclusion"] != "success":
    print(f"release-gate: RED: CI run {run['databaseId']} is {run['status']}/{run['conclusion']}")
    sys.exit(1)
# timeout-minutes per job, by the job's display name prefix, from ci.yml itself.
limits, name = {}, None
for line in open(".github/workflows/ci.yml"):
    m = re.match(r"\s{4}name:\s*(.+)", line)
    if m:
        name = m.group(1).strip()
    m = re.match(r"\s{4}timeout-minutes:\s*(\d+)", line)
    if m and name:
        limits[name.split("(")[0].strip()] = int(m.group(1))
jobs = gh("run", "view", str(run["databaseId"]), "--json", "jobs")["jobs"]
ok = True
for j in jobs:
    t = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
    took = (t(j["completedAt"]) - t(j["startedAt"])).total_seconds() / 60
    limit = next((v for k, v in limits.items() if j["name"].startswith(k)), None)
    if limit is None:
        print(f"release-gate: RED: no timeout-minutes found for CI job {j['name']!r}")
        ok = False
        continue
    share = took / limit
    flag = "ok" if share <= 2 / 3 else "RED: over two-thirds of its limit"
    print(f"release-gate: CI {j['name']}: {took:.1f} of {limit} min ({share:.0%}) {flag}")
    ok = ok and share <= 2 / 3
sys.exit(0 if ok else 1)
PY

if [ "$fail" -eq 0 ]; then
  note "GREEN: $head may be tagged"
  exit 0
fi
note "not green: do not tag $head"
exit 1
