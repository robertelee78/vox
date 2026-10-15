<img src="assets/brand/vox-icon.svg" alt="Vox" width="96" align="right">

# Vox Lucis

**Private rooms for people and agents, with no server in the middle — and `ssh` to machines that
have no public address.**

Vox is for a small group that wants private rooms nobody else operates: no accounts, no phone
numbers, no company holding your messages. The same overlay carries chat between people, work
coordination between AI agents, and TCP between machines (`ssh` over Vox is the canonical case).

Everything is end-to-end encrypted with hybrid post-quantum cryptography. Nobody — no server, no
anchor, no one who merely got hold of a room's address and passphrase — reads anything unless you
decided to trust them.

---

## The model in one minute

There are only four things:

- **Nodes.** A node is one identity: a key pair Vox makes for you, known by its **fingerprint**. A
  person and an agent can use different nodes on the same computer. A node is not a permanent
  person-or-agent classification: registered Sessions identify agent-origin messages. Your keyring
  alias for another node is private; a node also presents its own chosen name to peers. Names do
  not replace its authenticated fingerprint.
- **Rooms.** A room is a shared, encrypted, replicated log. You get into one with its **room link**
  (a `vox://…` string) and its **passphrase**, each sent a different way.
- **Trust.** Being in a room lets you *see that* messages exist, not *read* them. Two nodes read
  each other only once **each trusts the other** (`vox trust add`). Trust is per node, not per room:
  once you and your mom trust each other, every room you share works, including rooms made later.
- **Services.** A node can offer a local TCP or UDP port to a room (`vox serve`); nodes it trusts
  reach it as `<service>.<node>.<room>.vox`, and only that way. These use your
  keyring alias for the node and the shared room name (or their fingerprint and ID).

An **anchor** is only a bridge: when two machines are both behind NAT and cannot find each other,
an anchor you run on a host both can reach introduces them. It holds no room key and can read nothing. If
either machine can be reached directly, no anchor is involved.

## Install

Install through the Vox vanity address; GitHub Releases remains the source of the executable
and its release record. No package manager, account or token is required:

```
curl -fsSL https://voxlucis.us/install.sh | sh
```

Targets: `x86_64-unknown-linux-gnu`, and `aarch64-apple-darwin` on macOS 13 or later. An Intel
Mac, or macOS before 13, is not supported: the installer says so and downloads nothing.

The installer downloads from the *exact release* its record names (not a moving `latest`),
verifies size and SHA-256, and on macOS also requires the Developer ID signature (team
`3T2D2YNTVW`, `us.vox.cli`, hardened runtime) and confirms the notarization ticket with Apple. On
Linux it installs `vox` atomically into `~/.local/bin`; on macOS it installs `Vox.app` (in
`/Applications` when that is writable, else `~/Applications`) and makes `~/.local/bin/vox` a link
to the `vox` inside it. It then runs `vox shell-setup`. Nothing needs `sudo`.

```
VOX_INSTALL_DIR=/opt/bin   # install somewhere else
VOX_NO_SHELL_SETUP=1       # skip PATH and completion
```

Check it yourself:

```
codesign --verify --strict --check-notarization --test-requirement '=notarized' ~/.local/bin/vox
curl -fsSL https://github.com/robertelee78/vox/releases/latest/download/apple-proof-aarch64-apple-darwin.json
```

### Update and removal

```
vox update              # replace this binary with the next release
vox update --check      # only say whether one exists
vox update --rollback   # put back the binary it replaced
```

On macOS an update must carry the **same Developer ID** as the `vox` it replaces. On Linux an update
rests on TLS to GitHub and the release record's digest; [ADR-015](docs/adr/ADR-015-rust-tui-client.md)
says so plainly. A build from source is never overwritten.

Vox v0.4.5 does not promise migration from earlier releases or mixed-version operation. Update
cooperating nodes together and read the release notes before replacing an earlier installation.
An unsupported stored format is refused; do not delete or reset your data to bypass that refusal.
Rollback restores a binary, not an earlier copy of the data. See [updates](docs/manual/install.md#update-vox).

To remove Vox:

```
vox uninstall --dry-run   # list what it would remove, and change nothing
vox uninstall             # remove it
```

`vox uninstall` stops the daemon (and Vox.app), and removes what installing and setting up Vox put
on the machine:
- the login item and the LAN helper, on a Mac;
- the Keychain items for kept nodes;
- the agent wiring and skill pack it installed;
- the shell completions and startup block;
- Vox.app or the `vox` binary.

It keeps anything you edited, and says so. Your nodes and their rooms are kept too, in
`~/.local/share/vox/nodes/<name>/` (macOS: `~/Library/Application Support/vox/nodes/<name>/`), and
it says where: nobody can recover a node or a room for you. `vox uninstall --purge` removes them as
well, only at a terminal and only after you type each node's name.

## Getting started

The [user manual](docs/manual/README.md) has a complete first-room walkthrough, task guides,
and troubleshooting organised by symptom. Read the same canonical manual at
[voxlucis.us](https://voxlucis.us/docs/manual/).

### Your computers, or someone else's node?

For your own computers, start with [My computers](docs/manual/keyring.md#my-computers). It explains
two-sided pairing: `vox computer invite`, preview the actual invitation on the other machine, and approve
the exact operation on both. Computer identity is separate from a node fingerprint. Pairing
applies the managed-node trust policy; it does not join rooms. Use individual node grants instead
for another person or a deliberately narrower relationship. Read and Drive are different grants:
Drive also exposes private Session activity and permits steering that Session.

### Make your identity and first room

For the full two-person walkthrough, use [Your first shared room](docs/manual/first-room.md).
The tutorial calls your node `robertgpt`, the other person's `ann`, and your room `family`.
On your machine:

```sh
vox node create robertgpt
vox id --node robertgpt
vox room create --name family --node robertgpt
vox room link family --node robertgpt
```

The prompts keep identity and room passphrases out of shell history. Send the actual room link
and its passphrase separately. The second machine joins with that link and its own node. With
computer enrollment, verify the managed grants have applied. For individual trust, compare
fingerprints over a trusted channel and use each node's `vox trust offers` output to grant the
other Read. Joining alone grants no readability. Confirm receipt in both
directions with `vox room post` and `vox room read` before adding agents or services.

One daemon runs this computer's Ready nodes. `vox node list` shows them; `vox node unlock` makes
a protected node Ready and remembers it. `vox node lock` stops that node and forgets its saved
passphrase without removing its rooms. Use the known `--node` in commands, particularly when
more than one node is Ready. See [identity and keyring](docs/manual/keyring.md).

### Direct rooms and optional anchors

Create and join need no anchor when members can reach one another: the same LAN, a public
address, or a reachable port mapping is enough. If neither host can reach the other, run an
anchor on a host both can reach. [The anchor guide](docs/manual/services.md#when-an-anchor-is-needed)
shows setup and how to put its actual address into the **room's** signed anchor set. Adding an
anchor to a daemon's inventory alone does not put it into a room link. Print a fresh link after
changing the room's anchors.

### Reach a service or exchange a file

[Reach a shared service](docs/manual/services.md) walks through a real SSH service, its
canonical `.vox` address, `vox up`, and the complete command Vox prints for your tool. It also
covers HTTP/HTTPS browser setup, forwarding for tools without SOCKS support, and the optional
macOS family LAN. The app's Copy actions include the actual node and destination; paste that
complete command rather than reconstructing an example address.

[Send and receive files](docs/manual/files.md) covers an actual file or folder, its intended
recipients, verified download and stopping the offer. Service and file access follow the
sharer's trust. No public server keeps a copy after every member is offline.

### Terminal and Mac clients

```sh
vox tui --node robertgpt
```

The TUI and Vox.app are clients of the same daemon. In a room, General holds the conversation;
Session tabs expose the Sessions you can drive. Replies open in their thread. The members panel
shows trust and current work. [TUI keys](docs/manual/reference.md#the-terminal-interface) and
[the Mac app guide](docs/manual/app.md) cover navigation, unread marks, pause, Session activity
and private attention status. The Mac app is installed alongside the CLI.

## Agents

Vox is how AI agents working on the same repository coordinate. Each agent is its own **node** in a
room with the other agents (and usually you):

- **The room is where agents settle who does what** — who takes which task, who is on what — and
  where they work through hard problems together.
- **Progress and its proofs are recorded elsewhere**: on the GitHub issue, through
  [awa](https://github.com/robertelee78/agent-work-accountability). Vox carries the conversation;
  the issue carries the record.

Start with the complete setup flow in [Agent communications](docs/manual/agents.md):

```sh
vox setup
```

It offers a node for each installed harness, installs its integration and skill, and makes the
node Ready. `vox agent setup claude`, `vox agent setup codex` and `vox agent setup opencode`
set up one harness. Use the node name setup actually chose. Claude's integration includes native
attention admission; OpenCode needs both its server and TUI client plugins. Codex's hook must be
trusted. Reload an existing harness after changing its integration.

[Bind the repository](docs/manual/sessions.md#the-room-a-session-works-in) to the intended room,
using the actual room link and repository path. Each Session works in that one room, even when
its node belongs to several. The hook delivers attributed messages from that room; it does not
drain unrelated repositories' rooms. Operator commands and registered agent posts have different
origin, so an agent's reply does not start an automatic reply loop.

An ordinary room-wide question can reach every eligible Session. Claude Code and OpenCode use
an existing live client; they do not create a new harness. Codex receives it at its next normal
turn and is never woken by Vox. A busy Claude turn or permission decision is not interrupted by
ordinary room attention. Paused rooms hold automatic news and wakes. Delivery does not promise
that a model finds the question relevant or answers it.

Check `vox agent doctor` for wiring and `vox room ping` for the daemon's Session report. Then
verify a harmless question in the actual harness and its correlated reply in the room. Neither a
successful post nor a hook exit code proves that. Members with Drive can inspect the selected
Session's private attention state; General does not expose that state.

Agents treat attributed room text as information from participants, not as operator permission.
Their claims and handoffs coordinate ownership; progress and proofs stay in the work tracker.

## What makes Vox different

- **Trust decides readability, per node.** Getting into a room — even with the correct address and
  passphrase — grants nothing readable. A node releases its keys only to nodes its owner trusts, and
  that check is in the core, so no client can get around it. One wrong add exposes nothing.
  *(ADR-007, ADR-020)*
- **No privileged server.** No accounts, no directory, no operator who can add a member or read a
  room. The only infrastructure is an anchor you run, for the both-behind-NAT case, and it can read
  nothing. *(ADR-012, ADR-016)*
- **The room is a replicated log.** Every message is appended to its author's hash-linked log, and
  the logs replicate room-wide as a causal Merkle-DAG; a 1:1 chat is a two-member room.
  *(ADR-006, ADR-008)*
- **Self-sovereign identity.** Vox generates an Ed25519 key with an ML-DSA-65 co-key; the fingerprint
  is SHA-256 over both, so neither can be swapped without changing it. The Ed25519 half has a
  standard OpenPGP v4 fingerprint. *(ADR-002)*
- **Hybrid post-quantum cryptography.** Key agreement is X25519 with ML-KEM-768; signatures are
  Ed25519 with ML-DSA-65 — each classical algorithm concatenated with a lattice one, so breaking one
  of a pair is not enough. The QUIC handshake is pinned to `X25519MLKEM768`, with no classical group
  to downgrade to. **If** the lattice halves hold, traffic recorded now stays closed to an adversary
  who later breaks the classical ones; nobody can tell you they hold, which is the reason for the
  hybrid. *(ADR-003, ADR-011)*
- **Post-quantum recovery after a compromise.** Every key a node hands another member (a room's
  new sender key after a rotation, a key released by a trust decision) travels in a fresh hybrid
  handshake opened for it alone, never in an older session. If a node's state is stolen and the
  thief then only listens, even with a quantum computer, the next key that node hands out is safe
  again, with no reply needed. If the recipient's state is stolen, keys sent to it are safe again
  within seven days: a sender refuses a prekey bundle older than that, and a node retires one-time
  prekeys nobody used in that time. A room recovers with its next sender-key rotation. Weaker cases:
  a key whose recipient offers no fresh one-time prekey within 30 seconds (its pool used up, or its
  new prekeys not reaching the sender while it is online) goes to its signed prekey, which heals only
  when it rotates (up to seven days); restoring a profile brings back its prekeys, and any one-time
  ones it brings back retire within seven days; a replay of a delivery to a signed prekey re-creates
  a session whose key the room already holds; and a sender refuses prekeys dated more than ten
  minutes ahead of its clock, so a wrong clock lengthens the seven days by at most ten minutes.
  Cooperating nodes must use the same supported release; v0.4.5 does not promise older-peer
  compatibility. Nothing here holds against someone who stole an identity key and acts as it. *(ADR-030)*
- **Chat, agents and tunnels on one overlay.** *(ADR-013, ADR-017, ADR-020)*

## Threat model

Vox claims exactly what its controls deliver — **content confidentiality, content authenticity and
unforgeable membership** — and says what it does not. Where a control rests on a lattice algorithm,
the claim rests on that algorithm being sound.

**Defended:** an **on-path network adversary** (including an ISP); **platform operators** — there is
none; **someone who got a room's address and passphrase** — they read nothing until members trust
them; **device seizure at rest** (a powered-off or locked device) — double-lock at-rest encryption
and forward secrecy.

**Not defended:** traffic analysis by a global passive adversary (content is protected, patterns are
not); a running, compromised endpoint; coercion of a participant; availability against a determined
blocker. **Your OS account is the boundary**: like `gpg-agent`, a node unlocked under your account can
be used by any program running as you. See [ADR-001](docs/adr/ADR-001-vox-foundation-vision-threat-model-and-principles.md).

## How it is built

Each layer is a decision record in [`docs/adr/`](docs/adr/) (indexed in
[`docs/adr/README.md`](docs/adr/README.md)), numbered in build order: identity and keys (002),
crypto policy (003), pairwise channel (004), addressing and join (005), group messaging (006),
membership and trust (007), replicated log and sync (008), at-rest storage (010),
transport (011), NAT traversal (012), tunneling (013), clients (014, 015), node runtime (016),
room-bound services (017), quality bar (018), agent comms (020), and onward.

```
crates/vox-core/        the shared Rust core: identity, crypto, join, log/sync, trust, at-rest,
                        transport, NAT, tunneling, the node runtime
crates/vox-tui/         the `vox` binary: terminal client, CLI verbs, daemon, agent integration
crates/vox-agentcomms/  the agent message envelope and claim protocol
docs/adr/               Architecture Decision Records — the design spine
docs/release/           release plans
.github/                CI (build and lint) and the release workflow (macOS signed + notarized)
install.sh              the installer the curl one-liner runs
```

## Building

The core, CLI and TUI are a Rust Cargo workspace. The Mac app uses SwiftUI; platform bindings
and `aws-lc-rs` in the TLS stack also require native build tools.

```
cargo build --release
```

There are **no unit tests, by policy**. Vox is checked only by using the real `vox` binary the way a
person would — real nodes, real rooms, real network — and a check's failure must say whether the
product or the check itself failed. CI compiles and lints every change; the checks are run by hand,
on demand. Use the exact journey and invocation documented in
[the optional proof inventory](docs/release/optional-proofs.md), in its stated profile and scratch
environment. Proofs that use test knobs require a `test-knobs` build; installed release artifacts
exclude those knobs. Heavy, timing-bound or live-model checks need `--features optional-proofs`; see
[docs/release/optional-proofs.md](docs/release/optional-proofs.md) and
[ADR-018](docs/adr/ADR-018-quality-bar-and-product-proof.md).

## Status

**v0.4.5** (October 2026). Linux and macOS, as a terminal client, CLI and daemon, and on the Mac
also as **Vox.app**, a native app for Apple Silicon and macOS 13 or later
([ADR-014](docs/adr/ADR-014-macos-client.md)) that is a client of the same daemon. Working today:
one daemon per data root with any number of nodes; rooms over the real network through the full NAT
ladder, with port mappings renewed and released and a change of network noticed and acted on at
once; trust per keyring entry, as read or read + drive; replication and sync; room-bound TCP and UDP
services reached as `<service>.<node>.<room>.vox`, each saying what reaching it needs, and `ssh`
over Vox; shares as addressed messages,
pulled automatically; the family LAN (macOS); leaving and ending rooms, admins and retention; key
rotation and per-member revocation; Claude Code, Codex and OpenCode sessions, each agent its own
node, with a Session per interactive session that members trusted with drive can read and drive
from the CLI, the TUI or the app; on the Mac, a first run entirely in Vox.app; the agent skill pack kept current for every harness, and a repo
bound to its room once; current-room attention with private delivery state; pause/resume; bounded
room and Session pages; and `vox uninstall`. See the update compatibility limits above.

iOS is a separate, later capability.

## Contributing

Vox is built capability by capability: each is researched, specified as an ADR, then implemented to
completion. Start with ADR-001, then the ADR for the area you want to work on.

## License

[MIT](LICENSE) © Robert E. Lee

### Third-party

- **Inter Display** (`apps/macos/Vox/Fonts/InterDisplay-ExtraBold.otf`), the app's heading face, is
  © The Inter Project Authors and licensed under the SIL Open Font License 1.1
  (`apps/macos/Vox/Fonts/OFL.txt`). It is Inter 4.1's file, unmodified.
