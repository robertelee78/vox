#!/usr/bin/env python3
"""CI's release suite, split across runners, with nothing skipped silently (V210-116).

    scripts/ci_shard.py list  <list.tsv>                  build the release test binaries; list them
    scripts/ci_shard.py run   <list.tsv> <k> <n> <ran>    run shard k of n (`--ignored`); record each
    scripts/ci_shard.py union <dir>                       every listed binary ran, in exactly one shard

`list` builds with `cargo test --release --workspace --no-run`, plus the cargo arguments in
`CI_SHARD_CARGO_ARGS` (split on spaces), so a feature the suite needs is named once, where the
binaries are built. `union` reads every `list-*.tsv` and `ran-*.tsv` under `<dir>` (one pair per
shard, as each shard uploads them).

**Why it is split.** The release `--ignored` suite ran as one `cargo test` of about 124 binaries,
one after another: 90–104 minutes on the runners, which put `build · clippy · fmt · test` at
89–117 of its 120 minutes. `scripts/release-gate.sh` refuses a CI job over two-thirds of its limit
(V210-14's guard against creep), so no tag could pass it.

**Why the union is checked.** A split is where a binary can silently fall out: a shard that died,
a pattern that matched nothing (`--skip perf_` once skipped nothing, and the inverse is as easy).
So each shard writes the name of every binary it ran and how it ended, and a final job requires
the shards' lists to be the full list, each binary exactly once. A missing or doubled binary is
red, naming it.

A binary is run as cargo runs it: from its package's directory, with `--ignored`. Every binary
runs whatever the others did (`--no-fail-fast`): one red must not hide the rest.
"""
import json
import os
import subprocess
import sys


def die(msg):
    print(f"ci_shard: {msg}", file=sys.stderr)
    sys.exit(2)


def read_list(path):
    rows = []
    with open(path) as f:
        for line in f:
            name, exe, cwd = line.rstrip("\n").split("\t")
            rows.append((name, exe, cwd))
    if not rows:
        die(f"{path} lists no test binaries")
    return rows


def cmd_list(out):
    extra = os.environ.get("CI_SHARD_CARGO_ARGS", "").split()
    proc = subprocess.run(
        ["cargo", "test", "--release", "--workspace", *extra, "--no-run", "--message-format=json"],
        stdout=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        die(f"building the release test binaries failed (exit {proc.returncode})")
    rows = {}
    for line in proc.stdout.decode().splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") != "compiler-artifact" or not msg.get("profile", {}).get("test"):
            continue
        exe = msg.get("executable")
        if not exe:
            continue
        pkg_dir = os.path.dirname(msg["manifest_path"])
        kinds = msg["target"]["kind"]
        # One name per binary, stable across runners: package, kind and target name.
        name = f"{os.path.basename(pkg_dir)}/{'+'.join(kinds)}/{msg['target']['name']}"
        rows[name] = (exe, pkg_dir)
    if not rows:
        die("cargo built no test binaries")
    with open(out, "w") as f:
        for name in sorted(rows):
            exe, cwd = rows[name]
            f.write(f"{name}\t{exe}\t{cwd}\n")
    print(f"ci_shard: {len(rows)} test binaries listed in {out}")


def cmd_run(listing, k, n, ran):
    k, n = int(k), int(n)
    if not 0 <= k < n:
        die(f"shard {k} of {n} does not exist")
    rows = read_list(listing)
    mine = [r for i, r in enumerate(rows) if i % n == k]
    mine = mine[1:]  # MUTANT-V210-116: every shard drops one binary; the union must go red
    print(f"ci_shard: shard {k} of {n} runs {len(mine)} of {len(rows)} binaries")
    failed = []
    with open(ran, "w") as rec:
        for name, exe, cwd in mine:
            print(f"::group::{name}", flush=True)
            code = subprocess.run([exe, "--ignored"], cwd=cwd, check=False).returncode
            print("::endgroup::", flush=True)
            rec.write(f"{name}\t{'ok' if code == 0 else f'exit {code}'}\n")
            rec.flush()
            if code != 0:
                failed.append(f"{name} (exit {code})")
    if failed:
        print(f"ci_shard: shard {k} of {n}: {len(failed)} binaries red:")
        for f in failed:
            print(f"  {f}")
        sys.exit(1)
    print(f"ci_shard: shard {k} of {n}: all {len(mine)} binaries green")


def cmd_union(directory):
    lists, rans = [], []
    for root, _, files in os.walk(directory):
        for f in sorted(files):
            if f.startswith("list-") and f.endswith(".tsv"):
                lists.append(os.path.join(root, f))
            elif f.startswith("ran-") and f.endswith(".tsv"):
                rans.append(os.path.join(root, f))
    if not lists or not rans:
        die(f"{directory} holds {len(lists)} shard lists and {len(rans)} shard records")
    # Every shard built the same suite, so every shard's list must be the same list.
    want = [r[0] for r in read_list(lists[0])]
    for other in lists[1:]:
        theirs = [r[0] for r in read_list(other)]
        if theirs != want:
            print(f"ci_shard: RED: {other} lists {len(theirs)} binaries, {lists[0]} lists {len(want)}")
            for name in sorted(set(want) ^ set(theirs)):
                print(f"ci_shard: RED: {name} is in one shard's list and not the other's")
            sys.exit(1)
    seen = {}
    for path in rans:
        with open(path) as f:
            for line in f:
                name = line.split("\t", 1)[0]
                seen.setdefault(name, []).append(path)
    missing = [w for w in want if w not in seen]
    doubled = {s: p for s, p in seen.items() if len(p) > 1}
    unknown = [s for s in seen if s not in set(want)]
    print(
        f"ci_shard: {len(want)} binaries listed; {len(seen)} ran across {len(rans)} shard records"
    )
    for label, items in (("never ran", missing), ("ran twice", doubled), ("not listed", unknown)):
        for item in items:
            print(f"ci_shard: RED: {item} {label}")
    if missing or doubled or unknown:
        sys.exit(1)
    print("ci_shard: every listed binary ran, in exactly one shard")


def main(argv):
    if len(argv) == 3 and argv[1] == "list":
        cmd_list(argv[2])
    elif len(argv) == 6 and argv[1] == "run":
        cmd_run(*argv[2:])
    elif len(argv) == 3 and argv[1] == "union":
        cmd_union(argv[2])
    else:
        die(__doc__.strip().splitlines()[2])


if __name__ == "__main__":
    main(sys.argv)
