# Coming from v0.2.10

Applies to: v0.3.0, for readers who used v0.2.10. The node-based surface this page once
described as development (`rearch/v030`) is what v0.3.0 ships; the task chapters now describe
it. This page lists what changed, so v0.2.10 habits do not lead you astray.

## Nodes and the daemon

v0.2.10 selected local identity state with `--profile` and allowed one process to hold a
profile. In v0.3.0 a node is an identity with its own keys, rooms, keyring, services and agent
sessions, and one daemon per data root hosts every node concurrently. Choosing a node identifies
the actor for one command; it does not pause the others or designate a machine-wide “active
node”.

```sh
vox node create robertgpt
vox node attach robertgpt
vox node list
vox room list --node robertgpt
```

Node names are case-folded to lower case; `robertGPT` remains a suitable **alias** another
node uses for this fingerprint. One-shot commands such as room/status/trust need the selected
node attached. An error saying `node robertgpt is not attached` is fixed by
`vox node attach robertgpt`, not by creating a second identity. With several nodes, name one
explicitly using `--node`; a refusal listing choices is not a corrupt node.

Your v0.2.10 profiles become nodes of the same name the first time v0.3.0 runs against the data
root, and keep their fingerprints; see [upgrading](install.md#upgrading-from-v0210). The data
layout gains `nodes/<name>/` and `.daemon/`; see [local state](reference.md#local-state). There
is no rollback of that move.

## Other changed commands

| v0.2.10 | v0.3.0 |
|---|---|
| `--profile family`, `VOX_PROFILE` | `--node NAME`, `VOX_NODE`; with one node attached, neither is needed |
| `vox id --profile family` creates an identity | `vox node create NAME`; `vox id` prints the fingerprint |
| Keep `vox daemon --profile family` running | `vox node attach NAME` starts the daemon in the background |
| `vox tui` only with the daemon stopped; `:lock`, `:unlock` | The TUI is a daemon client and runs alongside everything; no lock |
| `vox room invite ROOM_ID` | `vox room link ROOM_ID`; in the TUI `:link` |
| `vox serve 22` | `vox serve ssh=22`: every service is named |
| `vox up ROOM_ID` | `vox up` carries every room the node holds |
| `vox forward ROOM_ID HOST TAG LOCAL` | `vox forward SERVICE.NODE.ROOM.vox LOCAL` |
| `vox room send ROOM_ID FILE` | Unchanged; `vox share` also offers a folder as a tar, for a count or a time |
| trust add/list/remove | Also `trust rename`, and `trust add --history now\|full` |
| room leave | Also `room retention`, `room admin`, `room end`, `room create --idle-end` |
| `vox agent hook --profile NAME` | `vox agent hook --node NAME`, required; `vox agent plugin HARNESS --node NAME` |
| — | `vox agent doctor`, `vox room ping`, `vox tunnel close`, `vox lan up` |

Do not carry service addresses across viewers: their node and room parts are each viewer's own
names. Copy the exact address printed for your node by `vox service list`.

Retention and room-ending operations can remove data and stop services. Read their exact
scope in [Rooms and messages](rooms.md) before running them. An ordinary leave is not an
instruction to end the room for everyone, and disappearing messages are not proof that nobody
retained an external copy.

## A message says not received yet

This symptom moved to [Troubleshooting](troubleshooting.md#a-message-says-not-received-yet).

## Agent diagnostics

`vox agent doctor` and `vox room ping` are part of v0.3.0. See
[check the wiring](agents.md#check-the-wiring) and
[the agent does not respond](troubleshooting.md#the-agent-does-not-respond).

Sources: [v0.3.0 CLI](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/cli.rs),
[node client and migration](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/client.rs)
and [the daemon and node model](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/docs/adr/ADR-026-daemon-and-nodes.md).
