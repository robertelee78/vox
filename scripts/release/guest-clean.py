#!/usr/bin/env python3
"""Owner-authorized cleanup: old Vox proof build outputs only; never profiles or keychains."""
import datetime
import os
from pathlib import Path
import shutil
import subprocess
import time

home = Path.home()
roots = sorted(p for p in home.iterdir() if p.is_dir() and (
    p.name == "vox-app-proofs" or p.name.startswith(("vox-rg7", "vox-rg9"))))
cutoff = time.time() - 3 * 3600
candidates = []
print("Inventory before deletion (UTC modification times):", flush=True)
for root in roots:
    print(datetime.datetime.fromtimestamp(root.stat().st_mtime, datetime.timezone.utc).isoformat(), root, flush=True)
    subprocess.run(["du", "-sh", str(root)], check=True)
    for base, dirs, files in os.walk(root, followlinks=False):
        path = Path(base)
        if path.name in ("target", "build-cache"):
            for child in path.iterdir():
                if child.is_dir() and not child.is_symlink() and child.name in ("release", "debug", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin"):
                    candidates.append(child)
            dirs[:] = []
        elif path.name in ("DerivedData", "derived-data"):
            candidates.append(path)
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if not (path / d).is_symlink() and d not in (".git", "node_modules")]
eligible = []
for path in candidates:
    newest = path.stat().st_mtime
    keychain = False
    for base, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            child = Path(base) / name
            newest = max(newest, child.lstat().st_mtime)
            keychain |= "keychain" in name.lower()
    subprocess.run(["du", "-sh", str(path)], check=True)
    stamp = datetime.datetime.fromtimestamp(newest, datetime.timezone.utc).isoformat()
    print(f"candidate={path} newest={stamp} keychain_name={keychain} eligible={newest < cutoff and not keychain}", flush=True)
    if newest < cutoff and not keychain:
        eligible.append((newest, path))
for _, path in sorted(eligible):
    if shutil.disk_usage(home).free >= 20 * 1024**3:
        break
    print(f"REMOVE old build output: {path}", flush=True)
    shutil.rmtree(path)
free = shutil.disk_usage(home).free
print(f"FINAL free_bytes={free}; free_GiB={free / 1024**3:.2f}", flush=True)
if free < 10 * 1024**3:
    raise SystemExit("APPARATUS: safely removable old build outputs did not reach10GiB; coordinator must decide")
