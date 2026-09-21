# Vox Lux

**An end-to-end-encrypted peer-to-peer overlay for private communication and tunneling.**

Vox is for a small group that wants a private channel nobody else operates — no central server, no
accounts, no phone numbers — and for anyone who wants `ssh` into a machine with no public address.

A channel ID and passphrase get a newcomer *into* a room and nothing further: each member decides
independently whose messages that newcomer may read, so an unapproved joiner decrypts none of them.
Vox generates your identity on first run — an Ed25519 key paired with an ML-DSA-65 one — and
exports the Ed25519 half in OpenPGP format, so a peer can compare fingerprints with
tooling they already trust. Beyond chat, the overlay carries arbitrary TCP between members.

Key agreement is X25519 with ML-KEM-768; signatures are Ed25519 with ML-DSA-65 — each a classical
algorithm concatenated with a lattice one, so breaking either alone is not enough. The point of
building it that way is that nobody, including us, can tell you the lattice halves are sound: they
are young, and hybrids exist because neither half is trusted on its own.

---

## The problem

Mainstream secure messengers force trade-offs Vox refuses to make:

- **They depend on central servers** for prekey distribution, identity, and routing — a metadata
  chokepoint, a censorship target, and a trust anchor you do not control.
- **They tie identity to a phone number or account**, binding your secure identity to a SIM and a
  real-world persona.
- **Admission is room-level.** Add someone to a group and they read everything said from then on;
  membership itself is not cryptographically authenticated, so one wrong add exposes all new traffic
  from everyone. March 2025's "Signalgate" was that failure by human error rather than a protocol
  break — the model is what made a misclick sufficient. For the cryptographic case in a comparable
  system, see Albrecht, Celi, Dowling and Jones, *Practically-exploitable Cryptographic
  Vulnerabilities in Matrix*, IEEE S&P 2023.

## What makes Vox different

- **Per-sender consent admission ("anti-Signalgate").** Joining a channel — even with the correct
  channel ID and passphrase — grants you *nothing readable*. Each existing member *individually*
  consents to a newcomer; until a member consents, their messages stay undecryptable to that
  newcomer, forever if they never consent. Visibility fills in monotonically, per sender. No single
  wrong add can expose the room. *(ADR-007)*
- **No privileged server.** There is no account system, no directory and no operator who can add a
  member or read a room. There *is* infrastructure: reaching a peer behind symmetric NAT needs an
  always-on **anchor**, which is a `vox node` you run yourself — it serves the rendezvous board and
  relays encrypted packets, and by construction holds no room key and can read nothing. Discovery is
  magnet-link style over a P2P swarm. *(ADR-012, ADR-016)*
- **The channel is the unit.** Every message is appended to its author's own hash-linked log, and
  the logs replicate channel-wide as a causal Merkle-DAG; a 1:1 chat is simply a two-member channel.
  Messages you cannot decrypt replicate but are not rendered. *(ADR-006, ADR-008)*
- **Self-sovereign identity.** Vox generates the root itself — an Ed25519 key plus an ML-DSA-65
  co-key, 1984 bytes of public key — and the fingerprint peers compare is SHA-256 over *both* halves,
  so the second key cannot be swapped without changing it. The Ed25519 half carries a
  standard OpenPGP v4 fingerprint, checkable with PGP tooling. No accounts, no phone numbers, no
  directory; per-channel pseudonymous identities are your choice. Adopting an *existing* GPG key as
  the root is specified but not built. *(ADR-002)*
- **Hybrid key agreement and signatures.** X25519 with ML-KEM-768, and Ed25519 with ML-DSA-65,
  concatenated — so breaking one algorithm of a pair is not enough. **If** the lattice halves hold,
  traffic recorded now stays closed to an adversary who later breaks the classical ones; nobody can
  tell you they hold, and that conditional is the whole reason for the hybrid. The QUIC handshake is
  pinned to the single group `X25519MLKEM768`, so there is no classical group to downgrade to.
  *(ADR-003, ADR-011)*
- **Per-channel deniability — specified and built, not yet enabled.** ADR-009 designs message
  content that carries no transferable proof of authorship to outsiders while membership and
  governance stay verifiable, and `vox-core/src/deniable/` implements it. **No release turns it on**:
  its formal analysis and its `0x000B` wire codec are outstanding. Treat it as a design commitment,
  not a property you have today. *(ADR-009)*
- **Chat *and* tunneling.** The same overlay carries arbitrary TCP between members — `ssh` over Vox
  is the canonical case — alongside messaging. UDP and an IP-level interface are designed and
  unbuilt. *(ADR-011, ADR-013)*

## How it works

Each layer is a decision record in `docs/adr/`, built in dependency order:

1. **Identity & keys** *(ADR-002)* — a generated Ed25519 + ML-DSA-65 root, OpenPGP-representable;
   role-separated keys (governance vs message
   vs key-agreement), per-channel identity selection, hybrid PQ co-keys.
2. **Crypto-agility policy** *(ADR-003)* — hybrid everywhere (X25519+ML-KEM, Ed25519+ML-DSA),
   versioned/negotiable ciphersuites, two normative PQXDH hardening rules.
3. **Pairwise secure channel** *(ADR-004)* — PQXDH key agreement + Double Ratchet, forward secrecy.
4. **Channel addressing & join** *(ADR-005)* — channelID (rendezvous) + passphrase (CPace PAKE,
   offline-dictionary-resistant), cleanly separated so the DHT lookup never leaks the passphrase.
5. **Group messaging** *(ADR-006)* — channel-scoped Sender Keys, per-author distribution,
   (channelID, epoch) binding.
6. **Membership, consent & governance** *(ADR-007)* — per-sender consent, a signed admin/membership
   certificate tree rooted at channel creation, admin-set policy, revocation via key rotation and
   passphrase-epoch.
7. **Replicated log & sync** *(ADR-008)* — per-author hash-linked logs in a causal Merkle-DAG (not a
   consensus blockchain), render-gating, anti-entropy sync, TTL pruning via payload-hash signing.
8. **Deniability** *(ADR-009)* — per-channel content-authorship deniability via per-epoch ephemeral
   signing keys.
9. **At-rest storage** *(ADR-010)* — double-lock encryption (GPG key *and* channel passphrase),
   admin-set retention, app-lock for device seizure.
10. **Transport** *(ADR-011)* — QUIC substrate with stream multiplexing + datagrams; interactive and
    bulk traffic isolated.
11. **NAT traversal & bootstrap** *(ADR-012)* — IPv6-first, then automatic port-mapping, then
    DCUtR hole-punching, with a user-runnable rendezvous; honest about the limits.
12. **Overlay tunneling** *(ADR-013)* — arbitrary TCP/IP between members (`ssh` over Vox), authorized
    by channel membership and consent.
13. **Rust TUI client** *(ADR-015)* — the first client surface over the Rust core: a terminal-native
    home client for Linux/servers/SSH (chat, consent, verification, tunneling).
14. **macOS client** *(ADR-014)* — the native SwiftUI client over the same core (not started).

## Threat model

Vox claims exactly what its controls deliver — **content confidentiality, content authenticity, and
unforgeable membership** — and is explicit about what it does not. Where a control rests on a lattice
algorithm, the claim rests on that algorithm being sound, which is an assumption and not a result.

**Defended:** an **on-path network adversary** (including a resourced ISP) — content is end-to-end,
hybrid-encrypted and authenticated, and channel membership cannot be forged;
**platform / server operators** — there is none to trust or be deplatformed by; a **wrongly-added
participant / passphrase holder** (the "Signalgate" case) — per-sender consent gates readability per
author; and **device seizure at rest** (a powered-off or locked device) — double-lock at-rest
encryption plus forward secrecy.

**Explicit non-goals (absent until a future ADR builds them):** metadata privacy / traffic analysis
against a global passive adversary (content is protected, communication *patterns* are not); a
running, compromised endpoint (malware/keylogger); coercion of a participant; and availability
against a determined blocker. Vox therefore does **not** claim resistance to a nation-state as a
holistic adversary — that would require all of the above. See ADR-001 for the full model.

## Availability

Availability is emergent, with no always-on infrastructure required: a two-member channel needs both
members reachable; a 3+-member channel needs any two online to propagate the log; a lone online
member is an outbox. A strictly zero-infrastructure overlay is provably impossible for cold-start
discovery and worst-case NAT, so Vox reduces the unavoidable minimum to a decentralized, user-runnable
bootstrap/rendezvous any node can provide. See ADR-001 and ADR-012.

## Architecture decisions

All decisions live in [`docs/adr/`](docs/adr/) and are indexed in
[`docs/adr/README.md`](docs/adr/README.md). The series is dependency-ordered: the numbering is the
build order. Every ADR is grounded in a multi-pass, citation-backed research effort.

## Repository layout

```
crates/vox-core/   The shared Rust core: identity, crypto, join, group, log/sync, governance,
                   deniability, at-rest, transport, NAT, tunneling (milestones M0–M11)
crates/vox-tui/    The Rust TUI client, binary `vox` (M12, ADR-015)
docs/adr/          Architecture Decision Records (the design spine; each records its
                   implementation status and Implementation notes)
.github/           CI and the release workflow (three targets, macOS signed + notarized)
scripts/           release helpers: package-release.sh, sign_notarize_release.sh
install.sh         the installer the curl one-liner runs
Cargo.toml         Workspace manifest (Rust 1.94, pinned in rust-toolchain.toml)
README.md          This file
LICENSE            MIT
```

## Install

GitHub Releases are the distribution — no vanity domain, no package manager, no account, no token:

```
curl -fsSL https://raw.githubusercontent.com/robertelee78/vox/main/install.sh | sh
```

Targets: `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin` (macOS 11+).

It fetches the release record for your target and downloads from the *exact release that record
names* — not `latest`, which could move between the two requests — verifying size and SHA-256 before
anything is put in place. On macOS it also requires a Developer ID signature from team `3T2D2YNTVW`
under `us.vox.cli` with the hardened runtime, and asks Apple to confirm the notarization ticket
online; it refuses to install if any of that fails. Installation is atomic into `~/.local/bin`,
followed by `vox shell-setup`. Nothing needs `sudo`.

```
VOX_INSTALL_DIR=/opt/bin   # install somewhere else
VOX_NO_SHELL_SETUP=1       # skip PATH and completion
```

Verify it yourself — the release publishes the notarization receipt it was built with:

```
codesign --verify --strict --check-notarization --test-requirement '=notarized' ~/.local/bin/vox
curl -fsSL https://github.com/robertelee78/vox/releases/latest/download/apple-proof-aarch64-apple-darwin.json
```

### Update

```
vox update              # replace this binary with the next release
vox update --check      # only say whether one exists
vox update --rollback   # put back the binary it replaced
```

On macOS an update must carry the **same Developer ID as the vox it is replacing** — a correct
digest only proves the bytes are what GitHub is serving, whereas this proves they were signed by
whoever signed what you already trust. On Linux there is no equivalent; an update there rests on TLS
to GitHub and the record's digest, which is stated plainly in
[ADR-015](docs/adr/ADR-015-rust-tui-client.md) rather than glossed.

A build from source is never overwritten: `vox update` says so and tells you to
`git pull && cargo build --release` instead.

### Shell integration and removal

`vox shell-setup` puts `vox` on `PATH` and installs completion for zsh, bash and fish. It appends
one marked block at the *end* of your rc — at the end, so it wins the `PATH` race against version
managers that prepend their shims earlier in the same file — and it is exactly reversible:

```
vox shell-setup --remove    # undo the block and the completion files
rm -rf ~/.local/bin/vox ~/.local/bin/.vox-*   # and the binary
```

Your rooms and identity live in `~/.local/share/vox/<profile>/` (macOS:
`~/Library/Application Support/vox/`) and are **not** removed by the above — delete that directory
too if you mean it, and note that nobody can recover a room for you.

## Getting started

### Chat

```
vox                                  # the interactive client; creates an identity on first run
```

Inside it, `:new` creates a room, `:invite` prints a `vox://…` address to hand to someone, `:join`
takes one. A newcomer with the correct address and passphrase can read **nothing** until each
member individually consents (`:grant`), which is the point of ADR-007.

### Reach a machine's port from anywhere (`ssh` over Vox)

Four commands, no port forwarding, no public IP, no privilege. On the machine with the service:

```
vox node --listen 0.0.0.0:0          # once, on a host that is always up: your anchor.
                                      # prints <fingerprint>@<multiaddr> — that is its --anchor spec
vox serve 22 --anchor <spec>          # offer local port 22 to a NEW room; prints the vox:// address
                                      # and the room's <52-char>.vox hostname
```

On the machine that wants in:

```
vox connect <vox://…>                 # join the room (one-shot: joining is durable)
vox up <room> --anchor <spec>         # a loopback SOCKS5 proxy that resolves the .vox name;
                                      # prints the exact ProxyCommand line to use
ssh -o "ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p" user@<52-char>.vox
```

The port you choose names the service; it does not have to be free on either machine, and nothing
binds it. The whole shape is Tor's, deliberately: a SOCKS proxy is the only client mechanism that
needs no privilege on any platform.

**Read this before you rely on it.** In the shipped binary, a room created by `vox serve` authorizes
**every admitted member** to reach its services — joining *is* the authorization. So today, an
address and its passphrase together are the reach grant, and you should treat them that way.
[ADR-017](docs/adr/ADR-017-room-bound-services.md) withdrew that model on 2026-09-21: authorization
becomes the host's own per-member decision, so an unapproved member reaches nothing and cannot learn
a service exists. That work is landing now and is not in `v0.1.0`.

For a tool with no proxy support, `vox forward` binds a local port instead.

### Do you need an anchor?

Only for reachability. Two peers that can already reach each other do not need one. If either is
behind a symmetric NAT — most home and mobile networks — something stable must introduce them, and
in Vox that is a `vox node` **you** run. It serves the rendezvous board, coordinates hole punching,
and relays QUIC packets it cannot read: it holds no room key, and its own log is ciphertext.

## Building

A pure-Rust Cargo workspace. No C or C++ of its own; the one ecosystem-forced native crypto is
`aws-lc-rs` inside the TLS stack (ADR-011).

```
cargo build --workspace
cargo test --release --workspace -- --ignored     # the proofs
```

There are no unit tests, by policy. A proof whose prover is missing — an uninstalled shell, a
release that does not exist yet — is reported **unproven and fails**, rather than skipped quietly;
accepting a gap means naming it in `VOX_PROOF_ALLOW_UNPROVEN`
([ADR-018](docs/adr/ADR-018-quality-bar-and-product-proof.md)).

## Status

Every layer in `vox-core` is implemented to its ADR, and the node runtime has landed through M17.

- **One device.** Identity behind a masked passphrase, channels double-locked under a channel
  passphrase, messages appended and rendered, lock and unlock, all surviving restart as sealed
  segments in a redb store.
- **Two machines over the real network.** Join, per-sender consent and log sync between separate
  hosts over QUIC, through the NAT ladder — pinhole, UPnP-IGD mapping, hole punch, and relay through
  an anchor you run yourself, which holds no room key and can read nothing.
- **Room-bound services.** `vox serve` offers a local port and prints an invite, `vox connect` joins
  from it, and `vox up` runs a loopback SOCKS5 proxy resolving the room's `<52-char>.vox` name, so
  `ssh` reaches the port with one `ProxyCommand` line. Proved by running the real binaries against a
  real service; also run by hand against a real `sshd` between two clients behind symmetric NAT.
- **Rotation and per-member revocation.** Revocation is rotation with one member left out, re-keyed
  at the new generation's origin, so an offline member loses nothing.

Not yet: golden wire-byte vectors for the ADR-008 struct tags (they start mattering now that
`v0.1.0`'s bytes are what `v0.2.0` must not break), and the macOS client
([ADR-014](docs/adr/ADR-014-macos-client.md)). Linux and macOS are supported as TUI hosts; iOS is a
separate future capability.

## Contributing

Vox is developed capability by capability: each capability is researched, specified as an ADR, and
only then implemented to completion. Start by reading ADR-001, then the ADR that covers the area you
want to work on. Discussion of a decision belongs in (or alongside) its ADR.

## License

[MIT](LICENSE) © Robert E. Lee
