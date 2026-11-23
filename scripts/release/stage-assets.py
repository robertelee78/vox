#!/usr/bin/env python3
"""Package exact signed candidate bytes for installer apparatus; never alter/re-sign them."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("artifact", type=Path)
p.add_argument("output", type=Path)
p.add_argument("--installer", type=Path, required=True,
               help="installer from the candidate's exact source SHA (not a different checkout)")
args = p.parse_args()
source = json.loads((args.artifact / "source.json").read_text())
version = source["version"]
triple = "aarch64-apple-darwin"
args.output.mkdir(parents=True, exist_ok=False)
for directory, asset, prefix, kind, package in (
        (args.artifact / "cli", f"vox-{triple}", "", "vox.standalone-release", "vox"),
        (args.artifact / "app", f"Vox-{version}-{triple}.zip", "app-", "vox.app-release", "Vox.app")):
    binary = directory / asset
    data = binary.read_bytes()
    shutil.copy2(binary, args.output / asset)
    digest = hashlib.sha256(data).hexdigest()
    (args.output / (asset + ".sha256")).write_text(f"{digest}  {asset}\n")
    record = dict(kind=kind, schema_version=1, package=package, channel="stable",
                  target=triple, version=version, size=len(data), sha256=digest)
    (args.output / f"{prefix}stable-{triple}.json").write_text(json.dumps(record, separators=(",", ":")) + "\n")
    for receipt in directory.glob("apple-proof-*.json"):
        shutil.copy2(receipt, args.output / receipt.name)
shutil.copy2(args.artifact / "source.json", args.output / "source.json")
shutil.copy2(args.installer, args.output / "install.sh")
receipt = {"artifact": str(args.artifact.resolve()), "installer": str(args.installer.resolve()),
           "installer_sha256": hashlib.sha256(args.installer.read_bytes()).hexdigest(),
           "source": source,
           "note": "Exact workflow signed bytes; schema1 stable records generated as HARNESS apparatus from their size/digest, not published records. Original Apple/source receipts retained; ancillary signer logs remain in the input artifact."}
(args.output / "staging.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt, indent=2))
