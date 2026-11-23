#!/usr/bin/env python3
"""One real-asset journey per disposable x86_64 container; invoke through a shared slot."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import time

ROOT = Path(os.environ["VOX_JOURNEY_SOURCE"]).resolve()
APPARATUS = Path(__file__).resolve().parent
IMAGE = "docker.io/library/ubuntu@sha256:f64b2ffc2f10ab8f8505aa56b2664bd846cbb9df87c7e2532e30f7667021c0e6"


def call(argv, **kw):
    print("$", shlex.join(map(str, argv)), flush=True)
    return subprocess.run(list(map(str, argv)), check=True, **kw)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("journey", choices=("install", "update", "busy", "controlled-update"))
    p.add_argument("--dist", required=True, type=Path)
    p.add_argument("--receipt", required=True, type=Path)
    p.add_argument("--expected-version")
    p.add_argument("--candidate-dist", type=Path)
    p.add_argument("--modern", action="store_true", help="Debian trixie/glibc 2.41 for published binaries and the cross-built harness")
    p.add_argument("--harness", type=Path, help="release-built x86_64 busy-room test harness")
    args = p.parse_args()
    if args.journey == "busy" and not args.harness:
        p.error("APPARATUS: busy requires --harness; build it in a separate shared hold")
    if args.journey == "controlled-update" and args.candidate_dist is None:
        p.error("APPARATUS: controlled-update requires --candidate-dist")
    receipt = args.receipt.resolve()
    image = ("docker.io/library/debian@sha256:bfc36aecdece0387418759dba474aa856c026ca8087da3606b41b90ab0509c99"
             if args.modern else IMAGE)
    receipt.mkdir(parents=True, exist_ok=False)
    name = f"vox-rg15-{args.journey}-{os.getpid()}"
    podman = ["podman", "--connection", "podman-machine-default-root"]
    existed = subprocess.run([*podman, "image", "exists", image]).returncode == 0
    created = False
    result = 1
    started = time.monotonic()
    try:
        call([*podman, "create", "--init", "--platform", "linux/amd64", "--cpus", "4", "--memory", "8g", "--name", name,
              image, "sleep", "infinity"])
        created = True
        (receipt / "owned-container.txt").write_text(name + "\n")
        call([*podman, "start", name])
        call([*podman, "exec", name, "sh", "-ec",
              "apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y python3 curl xz-utils zsh passwd util-linux procps; useradd -m -u 11015 proof; mkdir -p /journey /opt/vox-proof-node; chown 11015:11015 /journey; cd /tmp; curl -fsSLO https://nodejs.org/dist/v22.16.0/node-v22.16.0-linux-x64.tar.xz; curl -fsSLO https://nodejs.org/dist/v22.16.0/SHASUMS256.txt; grep ' node-v22.16.0-linux-x64.tar.xz$' SHASUMS256.txt | sha256sum -c -; tar -xJf node-v22.16.0-linux-x64.tar.xz --strip-components=1 -C /opt/vox-proof-node"])
        call([*podman, "cp", args.dist.resolve(), f"{name}:/dist"])
        if args.candidate_dist:
            call([*podman, "cp", args.candidate_dist.resolve(), f"{name}:/candidate-dist"])
        call([*podman, "cp", APPARATUS / "journey.py", f"{name}:/journey.py"])
        call([*podman, "cp", ROOT / "crates/vox-tui/tests/support/omp_turn_host.mjs", f"{name}:/omp_turn_host.mjs"])
        command = ["python3", "/journey.py", "prepare-busy" if args.journey == "busy" else args.journey,
                   "--dist", "/dist", "--work", "/journey/run", "--support", "/"]
        if args.expected_version:
            command += ["--expected-version", args.expected_version]
        if args.candidate_dist:
            command += ["--candidate-dist", "/candidate-dist"]
        if args.journey == "busy":
            call([*podman, "cp", args.harness.resolve(), f"{name}:/busy-test"])
            command = ["sh", "-ec", shlex.join(command) + "; export VOX_PROOF_SHIPPED_BINARY=$(cat /journey/run/installed-binary.txt) VOX_PROOF_KEEP_DIRS=1 VOX_PROOF_RG1_EVIDENCE=/journey; /busy-test --list | grep -Fx 'a_busy_room_newcomer_reads_every_member_with_a_paused_member: test' >/dev/null || { echo 'APPARATUS: exact busy-room journey was not compiled'; exit 2; }; /busy-test a_busy_room_newcomer_reads_every_member_with_a_paused_member --ignored --exact --nocapture"]
            print("APPARATUS LIMIT: QEMU cannot judge this journey's real-time posting/pause cadence; any cadence/time-bound failure is not a PRODUCT verdict.", flush=True)
        try:
            result = subprocess.run([*podman, "exec", "--user", "11015", "--workdir", "/journey", name, *command],
                                    timeout=1800).returncode
        except subprocess.TimeoutExpired:
            print("VERDICT RED APPARATUS: journey watchdog; no time-bound product verdict under emulation", flush=True)
            result = 124
    finally:
        if created:
            copied = subprocess.run([*podman, "cp", f"{name}:/journey/.", str(receipt / "scratch")])
            stopped = subprocess.run([*podman, "stop", "--time", "20", name])
            removed = subprocess.run([*podman, "rm", "--volumes", name])
            if copied.returncode or stopped.returncode or removed.returncode:
                print("VERDICT RED: APPARATUS: receipt copy or owned-container cleanup failed", flush=True)
                result = 2
            else:
                print(f"CLEANUP CONFIRMED: {name} stopped and removed with its volumes", flush=True)
        if not existed:
            # Do not force: an image concurrently borrowed elsewhere is left intact.
            removed = subprocess.run([*podman, "rmi", image])
            if removed.returncode:
                print("APPARATUS: image removal refused; no unrelated container was touched", flush=True)
                result = 2
        (receipt / "exit.txt").write_text(f"exit={result} wall_seconds={time.monotonic() - started:.2f}\n")
    return result


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"VERDICT RED: APPARATUS: {error}", flush=True)
        raise SystemExit(2)
