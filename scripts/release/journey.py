#!/usr/bin/env python3
"""Real release assets, private profiles; run only inside the authorized guest/container."""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import threading
import time


def require(ok, side, detail):
    if not ok:
        print(f"VERDICT RED: {side}: {detail}", flush=True)
        raise AssertionError(f"{side}: {detail}")


def run(argv, env=None, text=None, check=True):
    print("$", " ".join(map(str, argv)), flush=True)
    p = subprocess.run(list(map(str, argv)), env=env, input=text, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    print(p.stdout + p.stderr, end="", flush=True)
    if check:
        require(p.returncode == 0, "PRODUCT", f"exit {p.returncode}: {p.stdout}{p.stderr}")
    return p


def guest_only():
    if platform.system() == "Darwin":
        require(run(["/usr/sbin/sysctl", "-n", "hw.model"]).stdout.strip().startswith("VirtualMac"),
                "APPARATUS", "macOS journeys run only in the Tart guest")
    else:
        require(Path("/run/.containerenv").exists() or Path("/.dockerenv").exists(),
                "APPARATUS", "Linux journeys run only in a disposable container")
        require(platform.machine() == "x86_64", "APPARATUS", "the shipped Linux asset is x86_64")


class Release:
    def __init__(self, dist, root):
        self.dist = dist.resolve()
        triple = "aarch64-apple-darwin" if platform.system() == "Darwin" else "x86_64-unknown-linux-gnu"
        self.record = json.loads((dist / f"stable-{triple}.json").read_text())
        self.version = self.record["version"]
        tree = root / "releases"
        pinned = tree / "download" / f"v{self.version}"
        latest = tree / "latest/download"
        pinned.mkdir(parents=True)
        latest.mkdir(parents=True)
        for file in dist.iterdir():
            if file.is_file():
                (pinned / file.name).symlink_to(file.resolve())
                (latest / file.name).symlink_to(file.resolve())
        for prefix, asset in [("stable-", f"vox-{triple}")] + (
                [("app-stable-", f"Vox-{self.version}-{triple}.zip")] if platform.system() == "Darwin" else []):
            record = json.loads((dist / f"{prefix}{triple}.json").read_text())
            data = (dist / asset).read_bytes()
            require(record["sha256"] == hashlib.sha256(data).hexdigest() and record["size"] == len(data),
                    "APPARATUS", f"asset bytes disagree with {prefix}{triple}.json")
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}/releases"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Installed:
    def __init__(self, release, root):
        self.home = root / "home"
        self.home.mkdir()
        self.env = {"PATH": "/opt/vox-proof-node/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                    "HOME": str(self.home), "SHELL": "/bin/zsh", "TERM": "dumb",
                    "VOX_DATA_DIR": str(self.home / "data"), "VOX_CONFIG_DIR": str(self.home / "config"),
                    "VOX_INSTALL_DIR": str(self.home / ".local/bin"),
                    "VOX_APPLICATIONS_DIR": str(self.home / "Applications"),
                    "VOX_NO_SHELL_SETUP": "1", "VOX_NO_SKILL_INSTALL": "1",
                    "VOX_PROXY": "127.0.0.1:0", "VOX_LISTEN": "127.0.0.1:0",
                    "VOX_RELEASE_BASE": release.base, "VOX_PROOF_APPLE_VERIFY": "1"}
        self.bin = self.home / ".local/bin/vox"
        self.version = release.version
        self.children = []
        run(["/bin/sh", release.dist / "install.sh"], self.env)
        self.assert_version(self.version)
        self.passfile = self.home / "empty.pass"
        self.passfile.write_text("\n")

    def vox(self, *args, text=None, check=True, extra=None):
        return run([self.bin, *args], dict(self.env, **(extra or {})), text, check)

    def assert_version(self, expected):
        p = self.vox("--version")
        require(p.stdout.strip() == f"vox {expected}", "PRODUCT", f"installed version is not {expected}: {p.stdout}")

    def ready(self):
        p = self.vox("status", "--node", "agent", "--json")
        require(json.loads(p.stdout)["status"] == "Ready", "PRODUCT", "installed node is not Ready")

    def stage(self):
        self.vox("node", "create", "agent", "--passphrase-file", self.passfile)
        self.ready()
        self.vox("room", "create", "--node", "agent", "--name", "release-journey",
                 "--passphrase-file", "-", text="release room passphrase\n")
        self.room = self.vox("room", "list", "--node", "agent").stdout.split()[0]
        self.vox("room", "post", self.room, "release-journey-before-update", "--node", "agent")
        shown = self.vox("room", "read", self.room, "--node", "agent").stdout
        require("release-journey-before-update" in shown, "PRODUCT", "fresh installed node cannot read its post")

    def person(self):
        self.vox("node", "create", "person", "--passphrase-file", self.passfile)
        link = self.vox("room", "link", self.room, "--node", "agent").stdout.strip()
        self.vox("room", "join", link, "--node", "person", "--passphrase-file", "-",
                 text="release room passphrase\n")
        person = self.vox("id", "--node", "person").stdout.strip()
        agent = self.vox("id", "--node", "agent").stdout.strip()
        self.vox("trust", "add", person, "--node", "agent", "--name", "person", text="\n")
        self.vox("trust", "add", agent, "--node", "person", "--name", "agent", text="\n")

    def cleanup(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        lock = self.home / "data/.daemon/lock"
        # Linux cleanup is the outer runner's owned-container stop/removal, not PID guessing.
        if platform.system() == "Darwin" and lock.exists():
            pid = int(lock.read_text().strip())
            owner = subprocess.run(["ps", "eww", "-p", str(pid), "-o", "command="],
                                   capture_output=True, text=True).stdout
            if owner.strip():
                require("VOX_DATA_DIR=" + self.env["VOX_DATA_DIR"] in owner,
                        "APPARATUS", f"refusing to signal pid{pid}: private-profile ownership unconfirmed")
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        if platform.system() == "Darwin":
            register = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
            for app in (self.home / "Applications").glob("*.app"):
                subprocess.run([register, "-u", str(app)], check=True)
                for extension in app.glob("Contents/PlugIns/*.appex"):
                    subprocess.run(["/usr/bin/pluginkit", "-r", str(extension)], check=True)


def wait(pred, what):
    end = time.monotonic() + 120
    while not pred():
        require(time.monotonic() < end, "APPARATUS", f"staging did not finish: {what}")
        time.sleep(0.1)


class Turn:
    """The repository's OMP host stand-in drives the extension emitted by this asset."""
    def __init__(self, installed, root, support):
        runtime = run(["node", "-p", "typeof Promise.withResolvers"], installed.env)
        require(runtime.stdout.strip() == "function", "APPARATUS", "native extension requires Node22+ (Promise.withResolvers)")
        self.installed = installed
        self.lines = []
        self.hold = root / "turn-hold"
        self.extension = root / "extension.mjs"
        self.extension.write_text(installed.vox("agent", "plugin", "omp", "--node", "agent").stdout)
        self.session = "rg15-" + os.urandom(8).hex()
        self.proc = subprocess.Popen(["node", str(support / "omp_turn_host.mjs"), str(self.extension),
                                      self.session, str(root)], cwd=root,
                                     env=dict(installed.env, VOX_BIN=str(installed.bin),
                                              VOX_ROOM=installed.room, RCA_HOLD_FILE=str(self.hold)),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, bufsize=1)
        installed.children.append(self.proc)
        def pump():
            for line in self.proc.stdout:
                print("[extension]", line, end="", flush=True)
                self.lines.append(line)
        threading.Thread(target=pump, daemon=True).start()
        wait(lambda: any("session_start-done" in line for line in self.lines), "native extension starts")

    def turn(self, text):
        before = len(self.lines)
        self.proc.stdin.write("turn " + text + "\n")
        self.proc.stdin.flush()
        wait(lambda: any("turn-end: prompt" in line for line in self.lines[before:]), "native prompt completes")

    def hold_across_update(self):
        self.hold.with_suffix(".arm").write_text("hold")
        agent = self.installed.vox("id", "--node", "agent").stdout.strip()
        self.installed.vox("room", "post", self.installed.room, "--node", "person",
                           "--type", "ask", "--to", agent, "--session", "rg15-person",
                           "rg15-turn-spans-update")
        wait(lambda: any("hold-begin" in line for line in self.lines), "native turn holds room news")
        require(any("INJECTED" in line and "rg15-turn-spans-update" in line for line in self.lines),
                "APPARATUS", "held native turn did not carry the room post")

    def release_after_update(self):
        self.hold.with_suffix(".arm").unlink()
        self.hold.write_text("release")
        wait(lambda: any("turn-end: aside" in line for line in self.lines), "held turn finishes after update")

    def finish(self):
        marker = "rg15-after-update-" + os.urandom(6).hex()
        self.installed.vox("room", "post", self.installed.room, "--node", "person", marker)
        wait(lambda: any(("STAGED:" in line and marker in line)
                         or "delivery in this conversation is uncertain" in line for line in self.lines),
             "later room news staged or native conversation refused")
        self.turn("read after update")
        require(sum("STAGED:" in line and marker in line for line in self.lines) == 1
                and any("INJECTED" in line and marker in line for line in self.lines),
                "PRODUCT", "same native conversation did not show later news exactly once")
        require(not any("delivery in this conversation is uncertain" in line for line in self.lines),
                "PRODUCT", "update made the native conversation uncertain")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("journey", choices=("install", "prepare-busy", "update", "controlled-update"))
    p.add_argument("--dist", required=True, type=Path)
    p.add_argument("--work", required=True, type=Path)
    p.add_argument("--expected-version")
    p.add_argument("--candidate-dist", type=Path)
    p.add_argument("--support", type=Path, default=Path(__file__).resolve().parent / "../../crates/vox-tui/tests/support")
    args = p.parse_args()
    guest_only()
    args.work.mkdir(parents=True, exist_ok=False)
    release = Release(args.dist, args.work / "server")
    installed = None
    candidate = None
    try:
        installed = Installed(release, args.work)
        if args.journey == "prepare-busy":
            (args.work / "installed-binary.txt").write_text(str(installed.bin) + "\n")
            print(f"PREPARED installed binary: {installed.bin}; vox {release.version}", flush=True)
            return
        if args.journey == "controlled-update":
            require(args.candidate_dist is not None, "APPARATUS", "--candidate-dist is required")
            candidate = Release(args.candidate_dist, args.work / "candidate-server")
            args.expected_version = candidate.version
            for dist in (args.dist, args.candidate_dist):
                triple = "aarch64-apple-darwin" if platform.system() == "Darwin" else "x86_64-unknown-linux-gnu"
                data = (dist / f"vox-{triple}").read_bytes()
                require(b"VOX_TEST_RELEASE_BASE" in data, "APPARATUS", "controlled pair is not built with test-knobs")
            installed.env["VOX_TEST_RELEASE_BASE"] = candidate.base
            installed.env["VOX_TEST_APPLE_VERIFY"] = "1"
            if platform.system() == "Darwin":
                keychain = args.work / "private.keychain-db"
                run(["/usr/bin/security", "create-keychain", "-p", "", keychain])
                installed.env["VOX_TEST_KEYCHAIN"] = str(keychain)
            print("NONSHIPPING: candidate-source test-knobs pair; not the published v0.4.30 updater or real endpoint", flush=True)
        installed.stage()
        if args.journey in ("update", "controlled-update"):
            require(bool(args.expected_version), "APPARATUS", "--expected-version is required")
            installed.person()
            turn = Turn(installed, args.work, args.support)
            turn.turn("before update")
            turn.hold_across_update()
            print("UPDATE_ORIGIN=" + (candidate.base if candidate else "https://github.com/robertelee78/vox/releases/latest"), flush=True)
            update = installed.vox("update", check=False)
            if update.returncode and os.environ.get("VOX_PROOF_INSPECT_REFUSED_UPDATE") == "1":
                print(f"VERDICT RED: PRODUCT: original update exit {update.returncode}: {update.stdout}{update.stderr}", flush=True)
                print("DIAGNOSTIC RECOVERY ONLY: original refusal remains RED; inspect before closing the native conversation", flush=True)
                installed.vox("--version", check=False)
                installed.vox("status", "--node", "agent", "--json", check=False)
                installed.vox("room", "read", installed.room, "--node", "agent", check=False)
                turn.proc.stdin.write("quit\n")
                turn.proc.stdin.flush()
                turn.proc.wait(timeout=10)
                print("DIAGNOSTIC RECOVERY: native conversation closed; retry published updater once", flush=True)
                installed.vox("update", check=False)
                installed.vox("daemon", "--restart", check=False)
                installed.vox("--version", check=False)
                installed.vox("status", "--node", "agent", "--json", check=False)
                installed.vox("room", "read", installed.room, "--node", "agent", check=False)
            require(update.returncode == 0, "PRODUCT",
                    f"original update exit {update.returncode}: {update.stdout}{update.stderr}")
            turn.release_after_update()
            installed.assert_version(args.expected_version)
            installed.ready()
            old = installed.vox("room", "read", installed.room, "--node", "agent").stdout
            require("release-journey-before-update" in old, "PRODUCT", "update lost the saved room post")
            turn.finish()
        transport = "candidate-source nonshipping pair" if candidate else "real GitHub updater"
        print(f"VERDICT GREEN: {args.journey}; installed vox {release.version}"
              + (f" -> {args.expected_version}; {transport} and native agent turn" if args.journey.endswith("update") else "; Ready node creates, posts and reads a room"), flush=True)
    finally:
        if installed:
            installed.cleanup()
        release.close()
        if candidate:
            candidate.close()


if __name__ == "__main__":
    try:
        main()
    except AssertionError:
        raise SystemExit(1)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"VERDICT RED APPARATUS: {error}", flush=True)
        raise SystemExit(1)
