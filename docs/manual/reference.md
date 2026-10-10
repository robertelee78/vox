# Commands and local state

Applies to: v0.4.1. This is a map to the real command help, not a substitute for the parser
in your installed version.

## Find the right help

```sh
vox --version
vox --help
vox node --help
vox room --help
vox room join --help
vox trust --help
vox service --help
vox agent --help
vox man
```

`vox man` prints a man page generated from the same command definitions as the CLI. Use a
subcommand's `--help` when checking a particular argument; an example from a different release
is not an alias for your parser.

| Intent | Entry point | Prerequisite |
|---|---|---|
| Make, attach, list, detach or sign out a node | `vox node create`, `attach`, `list`, `detach`, `signout` | Node passphrase, if it has one |
| Interactive client | `vox` or `vox tui` | Terminal; a client of the daemon |
| Run the daemon in a terminal | `vox daemon` | Optional: attaching a node starts one |
| Run an anchor | `vox node` with no subcommand | A headless node; reachable infrastructure |
| Ask a node about rooms | `vox room list`, `read`, `roster` | The node attached |
| Inspect runtime | `vox status`, `vox status --json` | The node attached |
| Change peer trust | `vox trust add`, `rename`, `remove` | Compared fingerprint; passphrase after 30 minutes (`vox status` shows the minutes left) |
| List peer trust | `vox trust list` | The node attached |
| Room lifecycle | `vox room retention`, `admin`, `leave`, `end` | Creator or admin for the room-wide ones |
| Share a port in a new room | `vox serve NAME=PORT` | Existing local service |
| Join a service room | `vox connect ROOM_LINK` | Room link and passphrase |
| Reach services | the daemon's proxy (`vox up` says where), `vox forward SERVICE.NODE.ROOM.vox` | Host's trust; a node attached, or the forward running |
| Close live tunnels | `vox tunnel close` | `vox status` lists them |
| Share and pull files | `vox share`, `vox share list`, `vox share stop`, `vox room get` | Attached node; the sharer's daemon serving it |
| A room's family LAN | `vox lan up` | `sudo vox lan helper` running |
| Wire a harness | `vox agent plugin`, `skill`, `trust`, `doctor` | `--node` for plugin and hook |

## Select the node

A node is chosen per command, in this order: `--node NAME`, then `VOX_NODE`, then the only
attached node, then the only node on disk. When none of these settles it, the command refuses
and lists the nodes; that is not a corrupt node. Name the node explicitly in scripts and agent
integrations, so nothing acts as your person's node by accident.

Session-holding commands (`serve`, `connect`, `up`, `forward`, `lan up`) and `vox node attach`
start the daemon in the background when none runs and attach their node. One-shot commands
(`room`, `status`, `trust`, `share`, `service`) only ask an attached node, and say so when it is
not: `vox node attach NAME` first.

A `vox daemon` started while the daemon holding the data root is stopping says so, waits until it
has stopped, and then serves its node itself. `vox tui` exits when its terminal goes away, and
SIGHUP or SIGTERM stop it cleanly.

Data/config selection follows explicit flags, then `VOX_DATA_DIR` / `VOX_CONFIG_DIR`, then
XDG/platform defaults. Each data root has its own daemon and nodes, so two shells with different
roots see different nodes even when both say `--node robertgpt`. A command may create
directories while resolving paths; do not treat a guessed node name as a harmless diagnostic
probe.

## Local state

On Linux the usual data root is `~/.local/share/vox/`, unless XDG or Vox overrides select
another. On macOS the default root is `~/Library/Application Support/vox/`. Config uses the
corresponding XDG/platform config location; it is not necessarily the same root as data on Linux.

Inside the data root:

- `nodes/NAME/` holds one node: identity material such as `vault.cbor`, the room store
  `store.redb`, and that node's own `config/`, cursors and agent sessions. `files/ROOM_ID/` holds
  the shares it pulled (see [Send and receive files](files.md)), and `decisions/` its decision
  record (below).
- `.daemon/` holds the daemon's lock, its control socket `vox.sock`, the port it reuses, the list
  of nodes kept attached (`attach`), its `config`, and `log`, where a daemon started in the
  background writes its output. `format` says the data root's format and the version of vox that
  last served it, two lines such as `format 1` and `written-by vox 0.4.1`, so a later release knows
  what to upgrade (see [Install and update](install.md#update-deliberately)).

A data root an earlier release left with a node's files directly in it, outside `nodes/` (any
release before v0.3.0), is refused by every command, and nothing in it is changed: `… is not a Vox
data directory this version reads: …/default is not a node (a node lives under …/nodes)`. Move it
aside, or use another data root (`--data-dir` or `VOX_DATA_DIR`).

### The decision record

`vox status` lists the most recent refusals near its top, newest first:

```text
recent refusals
  4s ago  refused 34rtzgeq333h to join a room: answering 34rtzgeq333h: join proof-of-possession failed
```

In the TUI, `d` on the room list, or `:decisions`, shows the whole record, newest first, titled
`Decisions (newest first · kept 14 days · Esc: back)`. (`vox status` also begins with this node's
own fingerprint, in groups beside its art.)

Each node writes down every refusal and every change of access it decides: a join or a tunnel it
refused, a session it cut, a node added to or removed from its keyring, a share it stopped. Each
decision says what was decided, what was asked, who it was about (your name for them, or the
start of their fingerprint), when, and why, in the node's own words, for example `join
proof-of-possession failed` for a wrong room passphrase. It never holds message text, a file's
name or contents, a passphrase or a key. A refusal that can repeat many times a minute, such as a
refused stream, is written the first time; its repeats in the next hour are counted and written
as one.

The record is sealed at rest under the node's identity, in
`nodes/NAME/decisions/YYYY-MM-DD.sealed`, one file per UTC day, readable by your account only, and
it is read only through the node: in the TUI with `d`, in the app's Decision record view, and its
latest refusals in `vox status`. Files older than 14 days are deleted, and the record is never
sent anywhere. A record an earlier build wrote in plain text (`.jsonl`) is sealed into its day's
file, and the plain file removed, the next time the node is attached.

These are not caches to remove when a join is refused. The source creates private
directories/files on supported Unix systems; still protect the account and machine that can use
them. Never attach a state directory, vault, passphrase file or unreviewed config to a bug
report.

## Passphrase input

The identity passphrase protects a node's key material. Every node has one: `node create` refuses
an empty one and creates nothing. A room passphrase is a separate join factor, and it may be
empty. At a terminal, use the masked prompt. For an unattended
command, use its supported passphrase-file option and restrict the file to the intended OS user.

`node create` and `node attach` read the identity passphrase from `--passphrase-file`; `room
create` and `room join` read the room passphrase from `--passphrase-file`, where `-` selects
stdin. Without a terminal or that explicit input, they fail rather than wait on an unattended
prompt. A keyring change (`vox trust add`, `remove`, `rename`, `drive`, `read`) takes the identity
passphrase only typed at a terminal, never from a file or the environment; a room's retention or
name asks for none (see [when the passphrase is asked for](keyring.md#when-the-passphrase-is-asked-for)).

`vox node attach robertgpt` remembers the node: its passphrase is stored in the Keychain, and the
daemon attaches it again whenever it starts. `--no-remember` stores nothing; `vox node
forget-passphrase robertgpt` removes what is stored. Where there is no Keychain (Linux), keep a
node by a file instead:

```sh
vox node attach robertgpt --keep --passphrase-file PATH_TO_PRIVATE_FILE
```

The daemon then reads that file at each start. A foreground daemon also takes a passphrase file
with the identity passphrase on its first line. For explicit room selection, each additional
room line can be the room ID, one space, and that room's passphrase. The named-room form splits
at the first space; later spaces belong to the room passphrase. The parser also tries a whole
line as a passphrase for closed rooms before the named form. A schematic file, not literal
secrets:

```text
IDENTITY_PASSPHRASE
ROOM_ID ROOM_PASSPHRASE
ANOTHER_ROOM_ID ANOTHER_ROOM_PASSPHRASE
```

Use `vox daemon --node robertgpt --passphrase-file PATH_TO_PRIVATE_FILE` with the intended file,
owned by your user and readable only by that user. Store it outside shared repositories; do not
create it by typing secrets into a shell command that remains in history. This format is
source-reviewed in the daemon parser, not exercised by the manual's command check.

`--identity-passphrase` and room `--passphrase` are intentionally refused: process arguments
and shell history expose secrets. `VOX_ROOM_PASSPHRASE` is also refused.
`VOX_IDENTITY_PASSPHRASE` is supported for attaching a node, never for a keyring change, but an
environment can be read by same-user processes and inherited by children. A supported mechanism is not a promise that it is equally private.

Do not write a real passphrase into a documentation example, paste it to a model, or capture
it in a screenshot. An empty room passphrase leaves the room's link as its only join factor; an
example should not silently opt you into that choice.

## Output, cursors and status

Room/member selectors can accept unambiguous prefixes where help says so. A `--since` cursor
uses the full entry hash returned by a successful read; do not shorten it. `--json` selects
structured output for commands that advertise it; it is not a universal top-level switch.

A nonzero exit status means inspect the command's explanation. Coordination commands have
the specific [claim status meanings](agents.md#coordinate-ownership-not-a-second-progress-tracker).
A hook's zero exit is deliberately not a delivery assertion.

`vox status` shows the node's rooms with each member's trust, connection and last sync, its
peers with their path (`direct` or relayed) and round-trip time, its tunnels, and anything that
needs attention.

Its `gateway` section says, for IPv4 and IPv6, which router the machine's default route names,
which routers the daemon asked for a port mapping, and which method answered: PCP, NAT-PMP,
UPnP-IGD or an IPv6 pinhole. For example:

```text
gateway
  ipv4  next hop 192.168.1.1 via en0
        asked 192.168.1.1:5351, 192.0.0.9:5351: PCP answered at 192.168.1.1:5351
  ipv6  no default route
        no gateway asked
```

`asked …: none answered` means no router granted a mapping; `no gateway asked` means there was
none to ask. `vox status --json` carries the same under `gateway.ipv4` and `gateway.ipv6`
(`next_hop`, `asked`, and `answered` with the method as `rung`, the outside address as
`external` and the mapping's `lifetime` in seconds), and the machine's last network change under
`network_changed`. The daemon renews a mapping before it lapses and deletes every mapping it holds
when it stops; its log names each one, for example `vox daemon: deleted the port mapping UDP 53277
at 192.168.1.1:5351 (PCP)`. When gathering support evidence, use the smallest relevant status excerpt.
Paths, aliases, peer addresses, session IDs and even public fingerprints can expose private
relationships.

Source: [CLI parser](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/cli.rs),
[node selection](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/client.rs),
[path resolution](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-core/src/node/paths.rs)
and [the daemon and its files](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/docs/adr/ADR-026-daemon-and-nodes.md).
The [daemon parser](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/app.rs)
defines the passphrase-file lines.
