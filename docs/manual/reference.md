# Commands and local state

Applies to: v0.2.10. This is a map to the real command help, not a substitute for the parser
in your installed version.

## Find the right help

```sh
vox --version
vox --help
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

| Intent | Released entry point | Prerequisite |
|---|---|---|
| Interactive client | `vox` or `vox tui` | Terminal; exclusive profile holder |
| Keep rooms online without a TUI | `vox daemon` | Identity passphrase as needed |
| Run an anchor | `vox node` | Reachable infrastructure; not a room client |
| Ask a running node about rooms | `vox room list`, `read`, `roster` | Same profile as daemon/TUI |
| Inspect runtime | `vox status`, `vox status --json` | Running node |
| Change peer trust | `vox trust add`, `remove` | Compared fingerprint and authorization |
| List peer trust | `vox trust list` | Correct profile |
| Offer a TCP port in a new room | `vox serve PORT` | Existing local service |
| Enter a service room | `vox connect INVITE` | Correct invitation/passphrase |
| Reach its services | `vox up ROOM_ID`, `vox forward …` | Host's trust; correct proxy/forward |
| Exchange file bytes | `vox room send`, `vox room get` | Running node and live offer |
| Wire a harness | `vox agent plugin`, `skill`, `trust` | Supported existing harness |

## Select the same profile

Released commands select a profile with `--profile`; `VOX_PROFILE` supplies a default.
The command's explicit flag wins. Use one selection consistently for the daemon, CLI and
agent integration. The default profile is `default`, not the room you last visited.

Data/config selection follows explicit flags, then `VOX_DATA_DIR` / `VOX_CONFIG_DIR`, then
XDG/platform defaults. Two shells with different roots can select different identities even
when both say `--profile family`. A command may create directories while resolving paths;
do not treat a guessed profile name as a harmless diagnostic probe.

## Local state

On Linux the usual data path is `~/.local/share/vox/<profile>/`, unless XDG or Vox overrides
select another root. On macOS the default root is `~/Library/Application Support/vox/`, with
the profile beneath it. Config uses the corresponding XDG/platform config location; it is
not necessarily the same root as data on Linux.

The profile holds identity material such as `vault.cbor` and the room store `store.redb`.
The running node exposes its local control socket. These are not caches to remove when a
join is refused. The source creates private directories/files on supported Unix systems;
still protect the account and machine that can use them.

Never attach a state directory, vault, passphrase file or unreviewed config to a bug report.
The [development layout](development.md#nodes-and-the-daemon) adds `nodes/` and `.daemon/`;
it must not be assumed for this release.

## Passphrase input

The identity passphrase protects local key material. A room passphrase is a separate join
factor. At a terminal, use the masked prompt. For an unattended command, use its supported
passphrase-file option and restrict the file to the intended OS user.

`room create` and `room join` accept `--passphrase-file -` for explicit stdin. Without a
terminal or that explicit input, they fail rather than wait on an unattended prompt. A
daemon passphrase file contains the identity passphrase on its first line. For explicit room
selection, each additional room line can be the room ID, one space, and that room's passphrase.
The named-room form splits at the first space; later spaces belong to the room passphrase.
The parser also tries a whole line as a passphrase for closed rooms before the named form.
A schematic named-room file, not literal secrets:

```text
IDENTITY_PASSPHRASE
ROOM_ID ROOM_PASSPHRASE
ANOTHER_ROOM_ID ANOTHER_ROOM_PASSPHRASE
```

Use `vox daemon --profile family --passphrase-file PATH_TO_PRIVATE_FILE` with the intended
file, owned by your user and readable only by that user. Store it outside shared repositories;
do not create it by typing secrets into a shell command that remains in history. This format
is source-verified in the released daemon parser, not a claim that every unattended service
manager setup has been exercised by the manual's first-room check.

`--identity-passphrase` and room `--passphrase` are intentionally refused: process arguments
and shell history expose secrets. `VOX_ROOM_PASSPHRASE` is also refused. Some identity paths
support `VOX_IDENTITY_PASSPHRASE`, but an environment can be read by same-user processes and
inherited by children. A supported mechanism is not a promise that it is equally private.

Do not write a real passphrase into a documentation example, paste it to a model, or capture
it in a screenshot. Empty passphrases change at-rest/join protection; an example should not
silently opt you into that choice.

## Output, cursors and status

Room/member selectors can accept unambiguous prefixes where help says so. A `--since` cursor
uses the full entry hash returned by a successful read; do not shorten it. `--json` selects
structured output for commands that advertise it; it is not a universal top-level switch.

A nonzero exit status means inspect the command's explanation. Coordination commands have
the specific [claim status meanings](agents.md#coordinate-ownership-not-a-second-progress-tracker).
A hook's zero exit is deliberately not a delivery assertion.

When gathering support evidence, use the smallest relevant status excerpt. Paths, aliases,
peer addresses, session IDs and even public fingerprints can expose private relationships.

Source: [released CLI parser](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/cli.rs)
and [released path resolution](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-core/src/node/paths.rs).
The [released daemon parser](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/app.rs)
defines the passphrase-file lines.
