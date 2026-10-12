# App proofs in a macOS guest

`scripts/app-proofs.sh` runs in a headless macOS guest on this Apple Silicon Mac by
default. It remains an optional developer tool; it runs in no CI workflow.
The guest owns the screen, keyboard focus and pasteboard used by XCTest. Tart uses
Virtualization.framework. The runner disables its host window, clipboard sharing,
audio and USB accessories. No administrator command is needed.

Install [Tart](https://github.com/openai/tart/blob/main/docs/quick-start.md), then
clone an image with Xcode already installed:

```sh
brew install openai/tools/tart
tart clone ghcr.io/cirruslabs/macos-tahoe-xcode:latest vox-app-proofs
scripts/app-proofs.sh FirstRunProof
```

The official release archive is an alternative to Homebrew. Keep `tart.app` intact
and set `VOX_TART` to its `Contents/MacOS/tart` executable. The VM image is large:
check its reported download size and available disk space before cloning.

Commit the source first. The runner bundles that exact commit, transfers it to the
guest over SSH, installs the repository's Rust toolchain in the guest account, and
builds the app there. It uses its own SSH key and known-hosts file under
`~/Library/Caches/vox-app-proofs/vox-app-proofs`, without changing the person's SSH
configuration. Cirrus images have the public bootstrap account `admin` with password
`admin`; `VOX_PROOF_VM_USER` and `VOX_PROOF_VM_PASSWORD` select another guest account.
`VOX_PROOF_VM` selects another already-cloned VM. Only a VM started by this runner
with its isolation flags may be reused.

The preflight checks developer mode in the guest. If macOS requests UI automation
approval, or Vox needs notification permission, approve it **inside the guest**.
The guest's VNC endpoint is recorded in its `vm.log` under the cache directory.
Use a VNC client confined to the guest for interactive UI evaluation; do not open
Tart's host window or turn on clipboard sharing. Notification cases need permission
and Focus off in the guest, just as on a physical Mac.

Results come back to `target/app-proof-results/<time>-<commit>/`, including the
guest log, source identity, and `AppProofs.xcresult` with XCTest's screenshots and
attachments. A red still copies its results. The guest remains running for a UI
evaluation; stop it with `tart stop vox-app-proofs` when finished. A concurrent run
is refused by the cache's `run.lock`; inspect a stopped runner before removing a
stale lock.

```sh
scripts/app-proofs.sh                         # suite, with its stated optional omissions
scripts/app-proofs.sh FirstRunProof           # all FirstRunProof cases
scripts/app-proofs.sh FirstRunProof/testANewPersonMakesTheirNodeAndARoomInTheApp
VOX_PROOF_FROM=6 scripts/app-proofs.sh FirstRunProof
```

For a deliberate physical-host run, name it explicitly:

```sh
scripts/app-proofs.sh --host FirstRunProof
```

It prints the screen/focus/clipboard notice before reading the pasteboard. This
mode takes the physical desktop. `VOX_PROOF_VM_GUEST=1` is internal to the runner
and is refused on a physical Mac. Every Vox process in either mode still uses the
existing suite's scratch data and config directories.

The suite builds its own isolated proof app. `VOX_PROOF_APP` naming an installed
release is refused; it is not a way to prove an installed app.
