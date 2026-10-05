# Development version guide

Applies to: **development only**, `rearch/v030` at
`2d8385d4f90891c96843f32d6d002bc1b69aac1e`. This chapter is a version boundary and operator
guide, not a claim that v0.3.0 has been released. Do not use these commands with v0.2.10.

The older `integrate/v0.3.0` branch is not this surface. Branch names and matching version
strings alone are insufficient: check the source commit and command help of your build.

## Nodes and the daemon

A node is an identity with its own keys, rooms, keyring, services and agent sessions. One
daemon can host several nodes concurrently. Choosing a node identifies the actor for one
command; it does not pause the others or designate a machine-wide “active node”.

The data layout has `nodes/<name>/` and `.daemon/`. A first client access can migrate an old
profile layout. Do not try a development binary against valuable released state merely to
see whether a help page works; there is no implied migration rollback guarantee.

For a deliberately isolated development installation, open a new shell and select fresh
data **and** config roots before running any development Vox command:

```sh
vox_dev_root="$(mktemp -d)"
export VOX_DATA_DIR="$vox_dev_root/data"
export VOX_CONFIG_DIR="$vox_dev_root/config"
vox node create robertgpt
vox node attach robertgpt
vox node list
vox room list --node robertgpt
```

Keep using that same shell and those roots for the development examples below. This shell
is now selected for disposable development state, not your personal installation; do not
substitute your existing data directory. Keep any temporary state you need for diagnosis,
and close the shell when finished so its selection does not leak into unrelated work.

Node names are case-folded to lower case; `robertGPT` remains a suitable **alias** another
node uses for this fingerprint, not a promise that this path component preserves capitals.
Create writes identity state; attach starts/uses the daemon and keeps the node running.
An empty identity passphrase is allowed, but choosing one is a protection decision, not an
automatic setup recommendation.

One-shot commands such as room/status/trust need the selected node attached. An error saying
`node NAME is not attached` is fixed by `vox node attach NAME`, not by creating a second
identity. With several nodes, name one explicitly using `--node`; a refusal listing choices
is not a corrupt profile.

Before detaching, consider the connections, services and sessions it will interrupt:

```sh
vox node detach robertgpt
```

Other nodes attached to the daemon are not supposed to be stopped by this action. To keep a
node attached across daemon starts, `node attach --keep` uses the documented passphrase-file
mechanism; retain that file securely and understand that automatic attachment retains access
to its passphrase. Consult this build's help rather than copying an unattended setup blindly.

The background daemon writes `<data root>/.daemon/log`. The TUI migration has separately
recorded limitations in ADR-026; do not assume every older TUI lifecycle operation has been
replaced merely because CLI clients use the daemon.

## Agent diagnostics

An agent uses its own explicit node, for example `claude-mbp`:

```sh
vox agent plugin claude --node claude-mbp
vox agent plugin codex --node codex-mbp
vox agent plugin opencode --node opencode-mbp
```

These generate configuration for already chosen/created nodes; they do not authorize agents
to use the person's node. Hooks require `--node`; they do not fall back to the environment
or whichever node happens to be attached. Install the generated skill separately.

Local diagnosis:

```sh
vox agent doctor --node claude-mbp --room ROOM_ID
vox agent doctor --node claude-mbp --room ROOM_ID --json
```

The doctor inspects runtime, room, integration settings, session records, trust and versions.
`warn` means not configured or not determined; `fail` means a configured piece will not work.
It exits nonzero on failures. The diagnostic itself starts no harness/model, posts no room
messages and wakes nobody. Common path resolution can still perform first-use layout migration,
so this is not a guarantee of zero filesystem changes on an old installation.

Some fallback wording in this source still says “profile”. If the specific cause is a
detached node, use `vox node attach NAME`; a daemon process with no selected node attached
does not make every node available.

To ask another node about its agent sessions:

```sh
vox room ping --node robertgpt ROOM_ID claude-mbp
```

The final argument is **your local alias for the peer**, or its fingerprint; substitute the
name actually in your keyring. Ping sends a room diagnostic answered by the peer's daemon,
not a model. Ping/pong are not injected into agent context and do not wake sessions.

A timeout cannot distinguish an offline peer, no running daemon, or missing trust in either
direction. A reply saying a session is next-turn-only is not a failed wake; Codex remains
next-turn-only. Verify actual message delivery in the real receiving session before declaring
its integration complete.

## A message says not received yet

**Symptom:** `(not received yet)` occupies a position in the timeline.

**Meaning:** this node holds the signed envelope, but its unexpired message body is still
owed. It is not a blanket label for an untrusted sender and does not expose that sender's
plaintext. The row has no arrival cursor until the body arrives.

**Check:** inspect `vox status --node NAME`, the affected room and peer connectivity. Compare
whether another available member actually holds the missing message. Do not infer wrong
trust or a broken signature from this placeholder alone.

**Fix:** restore the relevant peers' availability and let the node request the body. Do not
reset identity, change trust indiscriminately or use the placeholder as a `--since` cursor.
If the body is no longer available, do not promise a central server can recover it.

**Verify:** the placeholder is replaced by the received message, or the actual retention
state explains its removal. If it persists despite a reachable holder, report the exact
versions and sanitized sync observations using [Get help safely](getting-help.md).

## Other changed commands

| v0.2.10 | This development surface |
|---|---|
| `--profile family` | `--node NAME` for actions |
| `vox serve 22` | `vox serve ssh=22` with a declared local name |
| `vox up ROOM_ID` | Check this build's `vox up --help`; proxy/address model changed |
| `vox forward ROOM_ID HOST TAG LOCAL` | `vox forward SERVICE.NODE.ROOM.vox LOCAL` |
| `vox room send ROOM_ID FILE` | Still available; `vox share` also supports a folder as a tar |
| trust add/list/remove | Also trust rename; different history options |
| room leave | Also explicit room lifecycle/admin/retention operations |

Do not carry service addresses across viewers: their node/room aliases can differ. Copy
the exact address printed for your node by `vox service list`.

Retention and room-ending operations can remove data and stop services. Read their exact
scope before running them. An ordinary leave is not an instruction to end the room for
everyone, and disappearing messages are not proof that nobody retained an external copy.

Sources: [development CLI](https://github.com/robertelee78/vox/blob/2d8385d4f90891c96843f32d6d002bc1b69aac1e/crates/vox-tui/src/cli.rs),
[node client and migration boundary](https://github.com/robertelee78/vox/blob/2d8385d4f90891c96843f32d6d002bc1b69aac1e/crates/vox-tui/src/client.rs),
[doctor](https://github.com/robertelee78/vox/blob/2d8385d4f90891c96843f32d6d002bc1b69aac1e/crates/vox-tui/src/doctor.rs),
[ping](https://github.com/robertelee78/vox/blob/2d8385d4f90891c96843f32d6d002bc1b69aac1e/crates/vox-tui/src/ping.rs),
and [message-body state](https://github.com/robertelee78/vox/blob/2d8385d4f90891c96843f32d6d002bc1b69aac1e/crates/vox-core/src/node/api.rs).
