# Install and update

Applies to Vox v0.4.5.

Vox runs on Linux on x86_64, and on Macs with Apple Silicon and macOS 13 or later. On a Mac it
comes as `Vox.app`, with `vox` inside it.

## Install Vox

Run this as your own user, not as root:

```sh
curl -fsSL https://voxlucis.us/install.sh | sh
```

The installer downloads the release from GitHub Releases and checks its size and SHA-256 against
the release record before it installs anything.

- On Linux, it installs `vox` into `~/.local/bin`.
- On a Mac, it installs `Vox.app` into `/Applications`, or `~/Applications` when it cannot write
  there. It first checks that the app carries Vox's Developer ID signature and passed Apple's
  notarization. `~/.local/bin/vox` is a link to the `vox` inside the app, so the app, the daemon
  and the command line are one binary.

On a Mac without Apple Silicon, or before macOS 13, the installer stops before it downloads
anything. It refuses to replace a `Vox.app` it did not install. Never bypass a failed integrity
or signature check.

The installer also runs `vox shell-setup`, which adds a marked block to your zsh, bash or fish
startup file for `PATH` and tab completion. Open a new terminal afterwards.

To read the script before you run it, download it to a new file, read it, then run that file:

```sh
curl -fL https://voxlucis.us/install.sh -o vox-install-review.sh
less vox-install-review.sh
sh vox-install-review.sh
```

To install somewhere else, set `VOX_INSTALL_DIR` to a directory your user can write. To skip the
shell setup, set `VOX_NO_SHELL_SETUP=1`.

## Check the installed command

```sh
command -v vox
vox --version
```

`command -v` names the `vox` your shell runs. If several are installed, make sure it is the one
you meant before you look for any other cause.

## Update Vox

```sh
vox update --check
vox update
```

`vox update --check` reports whether a newer release exists and changes nothing. `vox update`
downloads and checks it, keeps the binary it replaces, and refreshes the shell setup and the
agent skill pack. On a Mac it replaces the whole `Vox.app`, and the new app must carry the same
Developer ID. A `vox` you built from source is not replaced.

The update restarts the daemon onto the new version, so update when it is safe to interrupt your
rooms and services. Every node stops as the daemon stops. The new daemon makes each remembered
node Ready again. For any other node, the update prints the command that makes it Ready, such as
`vox node unlock robertgpt`. A daemon started in a terminal ends; its replacement runs detached
on the same configured address and anchors.

On a Mac, update and rollback quit and relaunch the app from the installation being changed if
it was running. They preserve that app's profile even when the updater uses different data,
config or home directories. An app that was closed stays closed; another Vox installation is
not restarted. A refused quit or failed relaunch is reported as a failure, not success.
An open `vox tui` still runs its original version until you restart that terminal client.

Vox v0.4.5 does not promise migration from previous releases or mixed-version operation. Read
the release notes before updating an earlier installation. A stored format the new binary cannot
read is refused; keep the data and report that exact refusal. Do not delete a profile, reset its
format marker or recreate an identity as an update workaround. Current-version restart and
retention behavior are separate from a prior-release migration guarantee.

Agents that coordinate work must run the same version of Vox. Update them together.

## Go back to the previous binary

```sh
vox update --rollback
```

This restores the binary the last update replaced. It does not restore your data: your nodes and
rooms stay as the newer binary left them, and the older binary may not read them.

## Run Vox in a container

Vox runs in a container such as Podman or Docker under two conditions.

**Run it as an ordinary user.** The daemon refuses every control connection from root, so
nothing run as root can use it. Set a non-root `USER` in the image, or start the container with
`--user 1000`. Point `VOX_DATA_DIR` and `VOX_CONFIG_DIR` at directories that user can write, on a
volume if the node must outlive the container.

**On a Linux host, raise `net.core.rmem_max` to at least 4 MiB.** Vox asks for a 4 MiB UDP
receive buffer, and Linux caps it at `net.core.rmem_max`, about 208 KiB on a stock host. A
container cannot raise that cap, and with the small buffer a busy host can cut Vox's throughput
to about a tenth of the link. When the buffer is short, the daemon's log says so once:

```text
vox: UDP receive buffer 416 KiB: path-MTU ceiling 1452 bytes, not 8192 — the OS granted a smaller receive buffer than 8192-byte datagrams need (on Linux, raise net.core.rmem_max to at least 4 MiB)
```

As root on the host, not in the container, run:

```sh
sysctl -w net.core.rmem_max=4194304
```

That lasts until the host restarts. To keep it, put the line `net.core.rmem_max = 4194304` in a
file such as `/etc/sysctl.d/90-vox.conf` and run `sysctl --system`. On a Mac, Podman runs
containers in a Linux virtual machine: check its value with
`podman machine ssh sysctl net.core.rmem_max`.

## Remove Vox

```sh
vox uninstall --dry-run
vox uninstall
```

`vox uninstall --dry-run` lists what it would do and changes nothing. `vox uninstall` stops the
daemon and quits the app, then removes:

- on a Mac, Vox's login item and LAN helper;
- the Keychain items stored for your nodes;
- the agent hooks, plugin and skill pack installed for Claude Code, Codex and OpenCode;
- the shell completions and the startup-file block;
- `Vox.app` or the `vox` binary, with its update record and the kept previous copy.

It names and keeps any file you changed or Vox did not write. It refuses a `vox` the installer did
not put there.

Your nodes stay: the data and config directories are kept, and `vox uninstall` names them. There
is no backup of a node. To remove the nodes too, run:

```sh
vox uninstall --purge
```

It asks you to type each node's name first, at a terminal. A node removed this way cannot be
recovered by anyone.

To remove only the shell setup and keep Vox:

```sh
vox shell-setup --remove
```
