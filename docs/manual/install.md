# Install and update

Applies to: v0.4.0. The installer may select a later published release; check the resulting
version and its release notes before using version-specific instructions.

## Install

From v0.4.0 the release targets are:

- **Linux** on x86_64 (`x86_64-unknown-linux-gnu`): the `vox` binary.
- **macOS 13 or later on Apple Silicon** (`aarch64-apple-darwin`): `Vox.app` with `vox` inside it.

Other Macs are refused: on an Intel Mac, or on macOS before 13, the installer stops before
downloading anything and says `this Mac is not supported: Vox needs a Mac with Apple Silicon and
macOS 13 or later`. (v0.3.1 and earlier also built for Intel Macs and macOS 11.)

Run this as your own user:

```sh
curl -fsSL https://voxlucis.us/install.sh | sh
```

The vanity address is the installation entry point. **GitHub Releases remains the source of
the executable and its release record**; the domain is not a second binary distributor.
The installer checks what it downloads, its size and SHA-256, against the record. On Linux it
installs `vox` atomically into `~/.local/bin`. On macOS it installs `Vox.app` into
`/Applications` (or `~/Applications` when it cannot write there), after checking that the app and
the `vox` inside it carry the expected Developer ID signature and passed Apple's notarization, and
makes `~/.local/bin/vox` a link to the `vox` inside the app, so the app, the daemon and the CLI
are one binary of one version. It refuses to replace a `Vox.app` it did not install. Do not bypass
a failed integrity or signature check. See [The Vox app on a Mac](app.md) for the app itself.

This command executes the script it downloads. If you prefer to inspect it first, download it
without running it, read it, then run that inspected file. An example with a new local filename:

```sh
curl -fL https://voxlucis.us/install.sh -o vox-install-review.sh
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
`vox shell-setup`, which adds a marked PATH/completion section to the end of your zsh, bash or fish
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
published replacement, saves the previous binary and updates shell integration. On macOS it
replaces the whole `Vox.app`, with the `vox` inside it, and keeps the previous app for
`--rollback`. A source build is not overwritten; update its source and rebuild instead.

On macOS, an update must carry the same Developer ID as the binary being replaced. On Linux,
the transport and release digest do not provide an equivalent Apple signing identity; do not
describe the two as the same assurance.

After an update, `vox update` restarts the vox daemon onto the new version, so update when it is
safe to interrupt your rooms and services. Every node detaches as the daemon stops; the new daemon
attaches again each node whose passphrase it keeps (`vox node attach --keep`, or the Keychain from
the app), and the update names any other node with `vox node attach NAME` to attach it again. A
daemon you started yourself in a terminal is left running the old version, and the update says so.
An open `vox tui` or Vox app keeps running the old version until you restart it. Agent coordination requires
participants to run the same Vox version; update the group deliberately, not one worker in
the middle of a claim.

## Roll back the binary

```sh
vox update --rollback
```

This restores the binary retained by the updater. It is **not a state-directory rollback**:
your nodes and rooms stay as the replaced binary left them, and the restored binary is not
guaranteed to read them. Do not open valuable state with a guessed executable.

## Run Vox in a container

Vox runs in a container such as Podman or Docker like any other program, with two conditions.

**Run it as an ordinary user, not root.** The daemon admits no control connection from root, so
nothing run as root can use it, and `vox daemon` will not start as root. A command run as root says:

```text
vox: this is running as root (uid 0), and the vox daemon refuses every control connection from root, so nothing run as root can use it. Run vox as an ordinary user: in a container, set a non-root USER (for example `podman run --user 1000 …`)
```

Set a non-root `USER` in the image, or start the container with `--user 1000` (any non-root
user ID). Give `VOX_DATA_DIR` and `VOX_CONFIG_DIR` a directory that user can write, on a volume
if the node must outlive the container.

**On a Linux host, raise `net.core.rmem_max` on the host to at least 4 MiB.** Vox asks for a 4 MiB
UDP receive buffer. Linux caps it at `net.core.rmem_max`, about 208 KiB on a stock host, and a
container cannot raise that limit. With the smaller buffer a busy host can cut Vox's throughput to
about a tenth of the link. When the buffer it gets is short, the daemon says so once in its log:

```text
vox: UDP receive buffer 416 KiB: path-MTU ceiling 1452 bytes, not 8192 — the OS granted a smaller receive buffer than 8192-byte datagrams need (on Linux, raise net.core.rmem_max to at least 4 MiB)
```

Set it on the host, as root there, not inside the container:

```sh
sysctl -w net.core.rmem_max=4194304
```

That lasts until the host restarts. To keep it, put the line `net.core.rmem_max = 4194304` in a
file such as `/etc/sysctl.d/90-vox.conf` on the host, then run `sysctl --system`. Check the value
with `sysctl net.core.rmem_max`. After the daemon's next start, its log should not show the
line above.

On macOS, Podman runs containers in a Linux virtual machine. Check that machine's limit with
`podman machine ssh sysctl net.core.rmem_max`; the one checked for this manual already had
`net.core.rmem_max = 4194304`.

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

Source: [installer](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/install.sh),
and [update implementation](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/update.rs).
