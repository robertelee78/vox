# Vox Lux

**A serverless, end-to-end-encrypted peer-to-peer overlay for private communication and tunneling.**

Vox lets a small, trusted group hold a private channel by sharing a channel ID and passphrase —
no central server, no accounts, no phone numbers. Identity is rooted in your own GPG/Ed25519 keys.
Beyond messaging, Vox is an overlay *transport*: it carries arbitrary TCP/IP between members
(e.g. `ssh` over Vox), not just chat. Key agreement and signatures are hybrid — a classical and a
post-quantum algorithm side by side — so a recording made today is not opened by a later quantum
computer unless *both* are broken.

---

## The problem

Mainstream secure messengers force trade-offs Vox refuses to make:

- **They depend on central servers** for prekey distribution, identity, and routing — a metadata
  chokepoint, a censorship target, and a trust anchor you do not control.
- **They tie identity to a phone number or account**, binding your secure identity to a SIM and a
  real-world persona.
- **Admission is room-level.** In Signal/Matrix/WhatsApp, group membership is not cryptographically
  authenticated: a single wrong add instantly exposes *all new* traffic from *everyone* (the
  March-2025 "Signalgate" failure; Albrecht et al., IEEE S&P 2023).

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
- **The channel is the unit.** Every message is broadcast to a channel's append-only, hash-linked
  log; a 1:1 chat is simply a two-member channel. Messages you cannot decrypt replicate but are not
  rendered. *(ADR-006, ADR-008)*
- **Self-sovereign identity.** GPG/Ed25519 keys with manual fingerprint verification — no accounts,
  no phone numbers, no directory. Per-channel pseudonymous identities are your choice. *(ADR-002)*
- **Hybrid post-quantum key agreement and signatures.** Key agreement combines X25519 with
  ML-KEM-768 and signatures combine Ed25519 with ML-DSA, so an attacker must break both to read or
  forge — which is what makes recorded traffic no easier to open later than it is now. The QUIC
  handshake is restricted to the single hybrid group `X25519MLKEM768`, so there is no classical
  group to downgrade to. What this does *not* claim: the post-quantum algorithms are young, and
  hybrids exist precisely because neither half is trusted alone. *(ADR-003, ADR-011)*
- **Per-channel deniability — specified and built, not yet enabled.** ADR-009 designs message
  content that carries no transferable proof of authorship to outsiders while membership and
  governance stay verifiable, and `vox-core/src/deniable/` implements it. **No release turns it on**:
  its formal analysis and its `0x000B` wire codec are outstanding. Treat it as a design commitment,
  not a property you have today. *(ADR-009)*
- **Chat *and* tunneling.** A first-class encrypted overlay for arbitrary byte streams — `ssh` over
  Vox and beyond — alongside messaging. *(ADR-011, ADR-013)*

## How it works

Each layer is a decision record in `docs/adr/`, built in dependency order:

1. **Identity & keys** *(ADR-002)* — GPG/Ed25519 root, role-separated keys (governance vs message
   vs key-agreement), per-channel identity selection, hybrid PQ co-keys.
2. **Post-quantum policy** *(ADR-003)* — hybrid everywhere (X25519+ML-KEM, Ed25519+ML-DSA),
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

Vox claims exactly what its controls deliver — **post-quantum content confidentiality, content
authenticity, and unforgeable membership** — and is explicit about what it does not.

**Defended:** an **on-path network adversary** (including a resourced ISP) — content is end-to-end,
post-quantum-hybrid encrypted and authenticated, and channel membership cannot be forged;
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

**What the installer does, and why each step is there.** It fetches the release record for your
target, downloads the binary from the *exact release the record names* — not `latest`, which could
move between the two requests — and verifies its size and SHA-256 **before** anything is put in
place. On macOS it additionally requires a Developer ID signature from team `3T2D2YNTVW` under the
identifier `us.vox.cli`, with the hardened runtime, and asks Apple to confirm the notarization
ticket online; it refuses to install if any of that fails. Then it installs atomically into
`~/.local/bin` and runs `vox shell-setup`. Nothing needs `sudo`.

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
binds it. A service is **dark by default** — offering it grants nobody reach — and `vox grant` is
what puts a member's `dial:` capability on the room's log. The whole shape is Tor's, deliberately:
a SOCKS proxy is the only client mechanism that needs no privilege on any platform
([ADR-017](docs/adr/ADR-017-room-bound-services.md)).

For a tool with no proxy support, `vox forward` binds a local port instead.

### Do you need an anchor?

Only for reachability. Two peers that can already reach each other do not need one. If either is
behind a symmetric NAT — most home and mobile networks — something stable must introduce them, and
in Vox that is a `vox node` **you** run. It serves the rendezvous board, coordinates hole punching,
and relays QUIC packets it cannot read: it holds no room key, and its own log is ciphertext.

## Building

Vox is a Cargo workspace, pure Rust (no C/C++ dependencies of its own; the one ecosystem-forced
native crypto is `aws-lc-rs` inside the TLS stack, documented in ADR-011).

```
cargo build --workspace                 # core library + the `vox` binary
cargo run --release -p vox-tui -- --help

# The proofs (ADR-018); there are no unit tests. The whitelist names the gaps accepted on a
# machine without `fish` — a bare `cargo test` fails on them, deliberately. CI installs the
# shells and so excuses fewer; its list is the one that gates the repository.
VOX_PROOF_ALLOW_UNPROVEN=fish,journey.update_replaces_an_older_install,verify.digest_mismatch_is_refused,install.apple_gate_refuses_unsigned_bytes \
  cargo test --workspace
```

A proof whose prover is missing — an uninstalled shell, a release that does not exist yet — is
reported as **unproven** and **fails**, rather than being skipped quietly. Accepting a gap means
naming it, which is why the command above is the length it is
([ADR-018](docs/adr/ADR-018-quality-bar-and-product-proof.md) §3).

**What works today.** Every layer in `vox-core` is implemented to its ADR (including real loopback
QUIC, a real TCP-over-Vox tunnel, and a real `(200,9)` Equihash solve cross-checked by the
librustzcash verifier), and the node runtime ([ADR-016](docs/adr/ADR-016-node-runtime.md)) has
landed through M17:

- **One device (M13).** `vox` creates an identity behind a masked passphrase, creates channels
  double-locked under a channel passphrase, appends and renders messages, locks (`:lock`, idle,
  `SIGHUP`) and unlocks, and everything survives a restart as sealed segments in a redb store under
  `~/.local/share/vox/<profile>/` (macOS: `~/Library/Application Support/vox/`).
- **Two machines over the real network (M14, M15).** Join, per-sender consent and log sync run
  between separate hosts, over QUIC, through the NAT ladder — pinhole, UPnP-IGD mapping, hole
  punch, and relay through an anchor you run yourself ([`vox node`](docs/adr/ADR-016-node-runtime.md)),
  which holds no room and can read nothing.
- **Room-bound services (M17).** `vox serve 22` offers a local port to a new room and prints the
  invite; `vox connect` joins from it; `vox up` runs a loopback SOCKS5 proxy that resolves the
  room's `<52-char-base32>.vox` name. `ssh` then reaches the offered port with one `ProxyCommand`
  line — the same shape a Tor user reaches a `.onion` through, and needing no privilege of any kind
  ([ADR-017](docs/adr/ADR-017-room-bound-services.md)). This has been run end to end against a real
  `sshd` between two clients behind symmetric NAT, relayed by their own anchor.
- **Sender-key rotation and per-member revocation (M18.1).** Revocation is rotation with one member
  left out, re-keyed at the new generation's origin so an offline member loses nothing.

What does **not** exist yet: the product-proof harness that will qualify releases
([ADR-018](docs/adr/ADR-018-quality-bar-and-product-proof.md) M18.3), golden **wire-byte** vectors
for the ADR-008 struct tags (they start mattering now that `v0.1.0`'s bytes are what `v0.2.0` must
not break), and the macOS client ([ADR-014](docs/adr/ADR-014-macos-client.md)). Linux and macOS are
supported today as TUI hosts; iOS is a separate future capability.

## Contributing

Vox is developed capability by capability: each capability is researched, specified as an ADR, and
only then implemented to completion. Start by reading ADR-001, then the ADR that covers the area you
want to work on. Discussion of a decision belongs in (or alongside) its ADR.

## Engineering principles

These are binding on all work in this repository:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a
  feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it:
  no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in
  front of a client.

## License

[MIT](LICENSE) © Robert E. Lee
