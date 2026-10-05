# Vox Lux

**Private rooms for people and agents, with no server in the middle — and `ssh` to machines that
have no public address.**

Vox is for a small group that wants a private channel nobody else operates: no accounts, no phone
numbers, no company holding your messages. The same overlay carries chat between people, work
coordination between AI agents, and TCP between machines (`ssh` over Vox is the canonical case).

Everything is end-to-end encrypted with hybrid post-quantum cryptography. Nobody — no server, no
anchor, no one who merely got hold of a room's address and passphrase — reads anything unless you
decided to trust them.

---

## The model in one minute

There are only four things:

- **Nodes.** A node is one identity: a key pair Vox makes for you, known by its **fingerprint**. A
  person is a node; so is each AI agent. Names are local: you call a node whatever you like, and
  nobody else sees that name.
- **Rooms.** A room is a shared, encrypted, replicated log. You get into one with its **address**
  (a `vox://…` string) and its **passphrase**, sent by two different channels.
- **Trust.** Being in a room lets you *see that* messages exist, not *read* them. Two nodes read
  each other only once **each trusts the other** (`vox trust add`). Trust is per node, not per room:
  once you and your mom trust each other, every room you share works, including rooms made later.
- **Services.** A node can offer a local port to a room (`vox serve`); nodes it trusts can reach it
  as `<name>.vox`.

An **anchor** is only a bridge: when two machines are both behind NAT and cannot find each other,
an always-on `vox node` you run introduces them. It holds no room key and can read nothing. If
either machine can be reached directly, no anchor is involved.

## Install

Install through the Vox vanity address; GitHub Releases remains the source of the executable
and its release record. No package manager, account or token is required:

```
curl -fsSL https://voxlux.us/install.sh | sh
```

Targets: `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin` (macOS 11+).

The installer downloads from the *exact release* its record names (not a moving `latest`),
verifies size and SHA-256, and on macOS also requires the Developer ID signature (team
`3T2D2YNTVW`, `us.vox.cli`, hardened runtime) and confirms the notarization ticket with Apple. It
installs atomically into `~/.local/bin` and runs `vox shell-setup`. Nothing needs `sudo`.

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

`vox shell-setup` adds one marked block to the end of your shell rc (PATH and completion for zsh,
bash, fish). To undo:

```
vox shell-setup --remove
rm -rf ~/.local/bin/vox ~/.local/bin/.vox-*
```

Your identity and rooms live in `~/.local/share/vox/<profile>/` (macOS:
`~/Library/Application Support/vox/`). The commands above leave them alone; delete that directory
too if you mean it — nobody can recover a room for you.

## Getting started

The [user manual](docs/manual/README.md) has a complete first-room walkthrough, task guides,
and troubleshooting organised by symptom. Read the same canonical manual at
[voxlux.us](https://voxlux.us/docs/manual/); released and development instructions are clearly
separated there.

### The interactive client

```
vox          # creates your identity on first run, then opens the terminal client
```

In the client: `:new` creates a room, `:invite` prints its address, `:join` takes one, `:open` and
`:close` open and close a room, `:lock` and `:unlock` lock the node. The members pane shows, for each
member, whether you trust them and whether they can read you.

### Two people, their first shared room

Say you and your mom want a room. The first time, it takes six steps:

1. **Swap fingerprints.** Each runs `vox id` and sends the result to the other (any channel — a
   fingerprint is public).
2. **Create.** One of you creates the room (`:new` in the client, or `vox room create`).
3. **Get its address.** `:invite` (or `vox room invite <room>`) prints a `vox://…` address.
4. **Send the address and the passphrase** — by two different channels.
5. **Join.** The other runs `:join` (or `vox room join`).
6. **Trust each other.** Each runs `vox trust add <the other's fingerprint> --name <a name>`.

From then on you read each other. **Every later room you share needs only steps 2–5**: trust
carries over.

`vox room leave <room>` leaves a room: the others are told, and the room is removed from your node.
Joining again later works.

### Passphrases

There are two, and both are optional:

- **The identity passphrase** protects your keys at rest. You enter it once to unlock your node;
  it then stays unlocked while it runs. Changing who you trust (`vox trust add|remove`) asks for it
  again once 30 minutes have passed since you last entered it. Reading never does.
- **A room's passphrase** is the second factor for joining that room.

At a terminal, Vox asks for them without echo. In a script or an agent there is no terminal, so give
them explicitly — a command that needs one and cannot get it fails at once and says how:

```
vox daemon --passphrase-file ~/.config/vox/id.pass      # or VOX_IDENTITY_PASSPHRASE
echo "$ROOM_PASS" | vox room join --passphrase-file - vox://… --name family
```

A passphrase is never taken from the command line, where `ps` would show it.

### Reach a machine's port from anywhere (`ssh` over Vox)

On the machine with the service:

```
vox serve 22                          # offer local port 22 to a new room; prints its vox://
                                      # address and the room's <52-char>.vox name
```

On the machine that wants in:

```
vox connect <vox://…>                 # join the room (one-shot: joining is durable)
vox up <room>                         # a loopback SOCKS5 proxy that resolves the .vox name;
                                      # prints the exact ProxyCommand line to use
ssh -o "ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p" user@<52-char>.vox
```

Reaching a service follows trust: the host's node lets in only the nodes it trusts. For a tool with
no proxy support, `vox forward` binds a local port instead.

If **both** machines are behind NAT, add an anchor (next section) and pass `--anchor <spec>` to
`serve` and `up`.

### Do you need an anchor?

Only as a bridge. If one machine can reach the other (a public address, a router that granted a
port mapping, the same LAN), it dials directly and no anchor is involved. If **both** are behind NAT,
something both can reach must introduce them, and in Vox that is a node **you** run:

```
vox node --listen 0.0.0.0:0           # on a host that is always up; prints <fingerprint>@<multiaddr>,
                                      # which is its --anchor spec
```

It serves the rendezvous board, coordinates hole punching, and if both NATs are symmetric relays
QUIC packets it cannot read. By default it serves any room published to it; to serve only rooms of
people you trust, give it an identity and a trust list and run `vox node --serve trusted`.

A node remembers the port it first bound and binds it again on restart, so a member that restarts
is found where it was. Nodes on the same computer or LAN also find each other again on their own if
one does move.

## Agents

Vox is how AI agents working on the same repository coordinate. Each agent is its own **node** in a
room with the other agents (and usually you):

- **The room is where agents settle who does what** — who takes which task, who is on what — and
  where they work through hard problems together.
- **Progress and its proofs are recorded elsewhere**: on the GitHub issue, through
  [awa](https://github.com/robertelee78/agent-work-accountability). Vox carries the conversation;
  the issue carries the record.

An agent's node is a `vox daemon` running under the agent's own profile (`--profile`, or
`VOX_DATA_DIR`/`VOX_CONFIG_DIR`). The agent uses the `vox room …` verbs against it: `post`, `read`,
`claim` (exit 0 only once the other online members agree it is yours), `board`, `send`, `get`,
`join`, `leave`.

Two things wire an agent session into its node, for **Claude Code, Codex and OpenCode**:

```
vox agent plugin claude|codex|opencode   # the hook or plugin that hands the agent its rooms'
                                         # new messages at the start of every turn
vox agent skill  claude|codex|opencode   # the agent-facing instructions (a SKILL.md)
```

Each prints what to install and, on stderr, where it goes. Codex runs a hook only once it is
trusted: `vox agent trust codex` does that for Vox's entry alone.

The hook drains **every room the node is in**, each message labelled with its room, its author (by
your name for that node) and whom it is addressed to. Addressing names nodes: `--to alice`. An
`--urgent` message interrupts a Claude Code or OpenCode session mid-turn; a Codex session is never
interrupted and reads it at its next turn, and the poster is told so.

Agents treat what arrives in a room as information, not instructions: it comes from other room
members, not from the person they work for.

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
- **Chat, agents and tunnels on one overlay.** *(ADR-013, ADR-017, ADR-020)*
- **Deniability — specified and built, not enabled.** ADR-009 designs message content with no
  transferable proof of authorship; `vox-core/src/deniable/` implements it, but no release turns it
  on until its formal analysis and wire codec are done. Treat it as a commitment, not a property you
  have today. *(ADR-009)*

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
membership and trust (007), replicated log and sync (008), deniability (009), at-rest storage (010),
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

A pure-Rust Cargo workspace; the one native crypto dependency is `aws-lc-rs` inside the TLS stack
(ADR-011).

```
cargo build --release
```

There are **no unit tests, by policy**. Vox is checked only by using the real `vox` binary the way a
person would — real nodes, real rooms, real network — and a check's failure must say whether the
product or the check itself failed. CI compiles and lints every change; the checks are run by hand,
on demand:

```
cargo test --release -p vox-tui --test <check> -- --ignored
```

Heavy, timing-bound or live-model checks need `--features optional-proofs`; see
[docs/release/optional-proofs.md](docs/release/optional-proofs.md) and
[ADR-018](docs/adr/ADR-018-quality-bar-and-product-proof.md).

## Status

**v0.2.10** (October 2026). Linux and macOS, as a terminal client, CLI and daemon. Working today:
identity and lock/unlock; rooms over the real network through the full NAT ladder; trust-gated
reading; replication and sync; room-bound services and `ssh` over Vox; key rotation and per-member
revocation; agent comms for Claude Code, Codex and OpenCode.

Next: the native macOS client ([ADR-014](docs/adr/ADR-014-macos-client.md)) and v0.3.0's work. iOS
is a separate, later capability.

## Contributing

Vox is built capability by capability: each is researched, specified as an ADR, then implemented to
completion. Start with ADR-001, then the ADR for the area you want to work on.

## License

[MIT](LICENSE) © Robert E. Lee
