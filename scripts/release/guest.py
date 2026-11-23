#!/usr/bin/env python3
"""Transport only. Invoke start/build/run/stop through the shared build-slot wrapper."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

VM = "vox-app-proofs"
ROOT = Path(os.environ["VOX_JOURNEY_SOURCE"]).resolve()
APPARATUS = Path(__file__).resolve().parent


def call(argv, **kw):
    print("$", shlex.join(map(str, argv)), flush=True)
    return subprocess.run(list(map(str, argv)), check=True, **kw)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("start", "copy", "build", "run", "stop"))
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--dist", type=Path)
    p.add_argument("--name", default="candidate")
    p.add_argument("--journey", choices=("install", "update", "busy", "controlled-update"))
    p.add_argument("--expected-version")
    p.add_argument("--candidate-name")
    p.add_argument("--candidate-dist", type=Path)
    p.add_argument("--readiness-only", action="store_true")
    args = p.parse_args()
    lock = Path("/tmp/vox-guest.lock/owner")
    if not lock.is_file() or not lock.read_text().startswith("rg15 "):
        raise RuntimeError("APPARATUS: acquire the rg15 guest-state lock before using the guest")
    state = args.state.resolve()
    state.mkdir(parents=True, exist_ok=True)
    if args.action == "start":
        rows = json.loads(subprocess.check_output(["tart", "list", "--source", "local", "--format", "json"]))
        machine = next(row for row in rows if row.get("Name", row.get("name")) == VM)
        if str(machine.get("State", machine.get("state"))).lower() != "stopped":
            raise RuntimeError("APPARATUS: guest already running; do not borrow an unowned run")
        log = (state / "tart.log").open("wb")
        child = subprocess.Popen(["tart", "run", VM, "--no-graphics", "--no-clipboard", "--no-audio", "--no-usb-accessories"],
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        (state / "tart.pid").write_text(str(child.pid))
        (state / "started-here").write_text(str(child.pid))
        for _ in range(120):
            ip = subprocess.run(["tart", "ip", VM], capture_output=True, text=True)
            if ip.returncode == 0 and ip.stdout.strip():
                (state / "ip").write_text(ip.stdout.strip())
                break
            time.sleep(1)
        else:
            raise RuntimeError("APPARATUS: guest address unavailable")
    if args.action == "stop":
        if not (state / "tart.pid").exists():
            raise RuntimeError("APPARATUS: this invocation did not start the guest")
        call(["tart", "stop", VM])
        (state / "started-here").unlink(missing_ok=True)
        return
    ip = (state / "ip").read_text().strip()
    keydir = Path.home() / "Library/Caches/vox-app-proofs/vox-app-proofs"
    options = ["-i", str(keydir / "id_ed25519"), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", f"UserKnownHostsFile={keydir / 'known_hosts'}", "-o", f"HostKeyAlias={VM}", "-o", "ConnectTimeout=10"]
    ssh = ["ssh", *options, f"admin@{ip}"]
    remote = "/Users/admin/vox-rg15-release"
    if args.action in ("start", "copy"):
        for _ in range(60):
            if subprocess.run([*ssh, "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("APPARATUS: guest SSH did not become ready with existing proof key")
        if args.readiness_only:
            command = (
                'set -u; export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"; '
                'echo SSH_NODE_PATH; command -v node; node --version; '
                'node -e \'Promise.withResolvers(); console.log("ok")\'; a=$?; echo SSH_NODE_FEATURE_EXIT=$a; '
                'echo JOURNEY_NODE_PATH; export PATH=/opt/vox-proof-node/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin; '
                'command -v node; node --version; node -e \'Promise.withResolvers(); console.log("ok")\'; b=$?; echo JOURNEY_NODE_FEATURE_EXIT=$b; '
                'df -Pk "$HOME"; '
                'python3 -c \'import os,shutil; n=shutil.disk_usage(os.path.expanduser("~")).free; print("FREE_BYTES="+str(n)); raise SystemExit(0 if n >= 10*1024**3 else "APPARATUS: guest has less than10GiB free")\'; c=$?; '
                'test "$a" -eq 0 && test "$b" -eq 0 && test "$c" -eq 0'
            )
            call([*ssh, command])
            return
        call([*ssh, f"mkdir -p {remote}/source {remote}/assets {remote}/receipts"])
        if args.action == "start":
            source = state / "source.tar"
            call(["tar", "--exclude=.git", "--exclude=target", "--exclude=target-nofeat", "--exclude=.env", "-cf", source, "-C", ROOT, "."])
            call(["tar", "-rf", source, "-C", APPARATUS.parent.parent, "scripts/release"])
            call(["scp", *options, source, f"admin@{ip}:{remote}/source.tar"])
            call([*ssh, f"tar -xf {remote}/source.tar -C {remote}/source; export PATH=\"$HOME/.cargo/bin:/opt/homebrew/bin:$PATH\"; command -v cargo; command -v node; df -Pk {remote}"])
        if args.dist:
            call([*ssh, f"mkdir -p {remote}/assets/{shlex.quote(args.name)}"])
            call(["scp", *options, "-r", str(args.dist.resolve()) + "/.", f"admin@{ip}:{remote}/assets/{args.name}/"])
        if args.candidate_dist:
            if not args.candidate_name:
                raise RuntimeError("APPARATUS: --candidate-name is required")
            call([*ssh, f"mkdir -p {remote}/assets/{shlex.quote(args.candidate_name)}"])
            call(["scp", *options, "-r", str(args.candidate_dist.resolve()) + "/.", f"admin@{ip}:{remote}/assets/{args.candidate_name}/"])
        return
    if args.action == "build":
        command = f"cd {remote}/source; export PATH=\"$HOME/.cargo/bin:/opt/homebrew/bin:$PATH\"; CARGO_BUILD_JOBS=6 cargo test --release -p vox-tui --features test-knobs,optional-proofs --test a_newcomer_reads_the_whole_history_proof --test install_sh_proof --test update_proof --no-run --message-format=json >{remote}/receipts/build.jsonl"
    else:
        dist = f"{remote}/assets/{args.name}"
        work = f"{remote}/receipts/{args.name}-{args.journey}-{int(time.time())}"
        script = f"{remote}/source/scripts/release/journey.py"
        env = f"export PATH=\"$HOME/.cargo/bin:/opt/homebrew/bin:$PATH\" VOX_PROOF_DIST={shlex.quote(dist)} VOX_PROOF_JOURNEY_WORK={shlex.quote(work)}; "
        if os.environ.get("VOX_PROOF_INSPECT_REFUSED_UPDATE") == "1":
            env += "export VOX_PROOF_INSPECT_REFUSED_UPDATE=1; "
        target, function = {
            "install": ("install_sh_proof", "a_shipped_release_installs_and_serves_a_fresh_node"),
            "update": ("update_proof", "a_published_install_updates_through_github_with_its_agent_turn"),
            "controlled-update": ("update_proof", "a_candidate_source_pair_updates_with_its_agent_turn"),
            "busy": ("a_newcomer_reads_the_whole_history_proof", "a_busy_room_newcomer_reads_every_member_with_a_paused_member"),
        }[args.journey]
        if args.expected_version:
            env += f"export VOX_PROOF_EXPECTED_VERSION={shlex.quote(args.expected_version)}; "
        if args.candidate_name:
            env += f"export VOX_PROOF_CANDIDATE_DIST={shlex.quote(remote + '/assets/' + args.candidate_name)}; "
        prepare = ""
        if args.journey == "busy":
            prepare = f"python3 {script} prepare-busy --dist {dist} --work {work}; export VOX_PROOF_SHIPPED_BINARY=$(cat {work}/installed-binary.txt) VOX_PROOF_KEEP_DIRS=1 VOX_PROOF_RG1_EVIDENCE={remote}/receipts; "
        command = (f"set -eu; cd {remote}/source; {env}{prepare}"
                   f"harness=$(python3 -c 'import json; rows=[json.loads(s) for s in open(\"{remote}/receipts/build.jsonl\")]; print(next(r[\"executable\"] for r in rows if r.get(\"reason\")==\"compiler-artifact\" and r.get(\"target\",{{}}).get(\"name\")==\"{target}\" and r.get(\"profile\",{{}}).get(\"test\") and r.get(\"executable\")))'); "
                   f"\"$harness\" --list | grep -Fx '{function}: test' >/dev/null || {{ echo 'APPARATUS: exact journey was not compiled'; exit 2; }}; "
                   f"\"$harness\" {function} --ignored --exact --nocapture")
    result = subprocess.run([*ssh, command])
    call(["scp", *options, "-r", f"admin@{ip}:{remote}/receipts/.", state / "guest-receipts"])
    if args.action == "run":
        # Only this invocation's scratch home, and only after its complete host copy.
        cleanup = (
            "import pathlib,shutil,subprocess; "
            f"home=pathlib.Path({(work + '/home')!r}); "
            "print('OWNED_SCRATCH_HOME='+str(home)); "
            "subprocess.run(['du','-sk',str(home)],check=True) if home.exists() else None; "
            "safe=home.is_dir() and (home.parent/'cleanup-confirmed').is_file() and not (home/'data/.daemon/lock').exists(); "
            "shutil.rmtree(home) if safe else None; "
            "print('CLEANUP CONFIRMED: copied owned scratch home removed' if safe else "
            "'RETAINED: daemon ownership/lifetime not proved; no shared receipt sweep'); "
            "print('FREE_BYTES='+str(shutil.disk_usage(home.parent).free))"
        )
        cleaned = subprocess.run([*ssh, "python3 -c " + shlex.quote(cleanup)], capture_output=True, text=True)
        (state / "guest-scratch-cleanup.log").write_text(cleaned.stdout + cleaned.stderr)
        print(cleaned.stdout + cleaned.stderr, end="", flush=True)
        if cleaned.returncode:
            print("VERDICT RED: APPARATUS: owned scratch receipt cleanup failed", flush=True)
            raise SystemExit(2)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
