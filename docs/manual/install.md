# Install and update

Applies to: v0.3.0. The installer may select a later published release; check the resulting
version and its release notes before using version-specific instructions.

## Install

The supported release targets are Intel Linux, Apple Silicon macOS and Intel macOS. The macOS
release requires macOS 11 or later. Run this as your own user:

```sh
curl -fsSL https://voxlux.us/install.sh | sh
```

The vanity address is the installation entry point. **GitHub Releases remains the source of
the executable and its release record**; the domain is not a second binary distributor.
The installer checks the downloaded executable's size and SHA-256 against the record and installs
atomically into `~/.local/bin`. On macOS it also requires the expected Developer ID signature
and Apple's notarization check. Do not bypass a failed integrity or signature check.

This command executes the script it downloads. If you prefer to inspect it first, download it
without running it, read it, then run that inspected file. An example with a new local filename:

```sh
curl -fL https://voxlux.us/install.sh -o vox-install-review.sh
less vox-install-review.sh
sh vox-install-review.sh
```

Choose an unused filename; `curl -o` replaces an existing file. Inspection is an alternative
workflow, not an additional step needed after the one-line installation.

## Confirm the installed command

```sh
command -v vox
vox --version
vox --help
```

`command -v` should name the binary you intended to install. The installer runs
`vox shell-setup`, which adds a marked PATH/completion block to the end of your zsh, bash or fish
startup file. Open a new shell if the current shell does not see the updated PATH. If several
Vox binaries exist, select the intended one before diagnosing a version mismatch.

For a deliberate alternative location, `VOX_INSTALL_DIR` selects the destination and
`VOX_NO_SHELL_SETUP=1` suppresses shell setup. The destination must be writable by your user.
Do not solve a PATH problem by running Vox as root.

## Update deliberately

```sh
vox update --check
vox update
vox --version
```

The first command checks without replacing the binary. The second downloads and verifies the
published replacement, saves the previous binary and updates shell integration. A source build
is not overwritten; update its source and rebuild instead.

On macOS, an update must carry the same Developer ID as the binary being replaced. On Linux,
the transport and release digest do not provide an equivalent Apple signing identity; do not
describe the two as the same assurance.

After an update, running processes can still be the old version. Plan a restart of the affected
Vox process when it is safe to interrupt its rooms and services. Agent coordination requires
participants to run the same Vox version; update the group deliberately, not one worker in
the middle of a claim.

## Upgrading from v0.2.10

v0.3.0 changes how identities are stored and selected. The first v0.3.0 command run against a
v0.2.10 data root moves each profile to a node of the same name and says so, for example
`vox: moved …/data/family to …/data/nodes/family (from v0.3.0 each node lives under nodes/)`.
The node keeps its identity: `vox id` prints the same fingerprint as before. Commands then take
`--node` instead of `--profile`; [Coming from v0.2.10](development.md) lists every change.

Rooms are not carried over. A room made by v0.2.10 is refused when v0.3.0 opens it, because
its message format changed: make the room again with `vox room create` and share its new link.
The move takes the profile's whole directory, keyring included, as it is. Stop every v0.2.10
Vox process before the first v0.3.0 command, and update every member and agent of a room
together: rooms do not carry across the two versions.

## Roll back the binary

```sh
vox update --rollback
```

This restores the binary retained by the updater. It is **not a state-directory rollback**,
and does not guarantee that an older binary understands data migrated by a newer one: v0.2.10
does not look for nodes under `nodes/`, where v0.3.0 moved them. Read
the target release's compatibility notes before crossing a format or major command-surface
change. Do not open valuable state with a guessed older executable.

## Remove shell integration or the executable

```sh
vox shell-setup --remove
```

This removes the marked shell setup and completion files. It does not erase your identity or
rooms. To remove the executable as well, first identify it with `command -v vox`, stop the Vox
processes you intend to stop, and remove that exact installation file through your file manager.
An installation may also retain update metadata and a previous binary beside it.

Do not delete the Vox data directory as an ordinary uninstall step. It contains identities and
room state, and deleting it is not recoverable through a central Vox account. See
[local state](reference.md#local-state) before making any deliberate data-removal decision.

## Next

Follow [Your first shared room](first-room.md). If installation fails, keep the exact error and
use [Get help safely](getting-help.md); never paste signing bypasses or secrets into a retry.

Source: [installer](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/install.sh),
[update implementation](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/update.rs),
[profile-to-node move](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-core/src/node/layout.rs)
and [the pre-v0.3.0 room refusal](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-core/src/node/api.rs).
