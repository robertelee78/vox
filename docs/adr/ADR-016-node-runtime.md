# ADR-016: Node Runtime — Composing the Core

**Status**: accepted (2026-09-19) — implementation in progress: M13 single-device node
**Date**: 2026-09-19
**Updated**: 2026-09-19 — accepted by the decider; M13 started.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: runtime, node, integration, persistence, rendezvous, sync, headless

## Context

Every layer of the core is implemented to its ADR and tested — identity (002), the pairwise channel
(004), authenticated join (005), sender keys (006), governance (007), the replicated log and sync
(008), deniability (009, not enabled), at-rest storage (010), QUIC transport (011), the NAT primitives
(012), tunneling (013) — and the Rust TUI client (015) is a tested shell over a `CoreHandle` trait.
**Nothing composes them.** `join_initiate`/`join_accept` have no caller outside their tests;
`transport`, `nat` and `tunnel` are consumed only by `examples/spike_*.rs`; the rendezvous "server"
is an in-memory `RendezvousStore` with no wire protocol; the TUI binds `OfflineCore` and says so at
startup. A user cannot create, join, or chat in a channel over the network. The 2026-09-19 swarm
review, the ADR index status table, and the per-ADR "Known gaps" bullets record this precisely.

This ADR specifies the node runtime that turns those layers into Vox. It re-decides nothing the
series has already fixed:

- **The client embeds the node** (ADR-014, ADR-015). The TUI and the macOS app run the node
  in-process; secrets never cross a process boundary; there is no IPC control plane.
- **The headless node is a ciphertext-only sync peer, store, rendezvous point and relay anchor**
  (ADR-012, ADR-014, ADR-015 §"headless node is a sync peer, not a control plane"). It holds no
  user secrets and is never remote-controlled.
- **No DHT.** Cold start uses a user-controlled bootstrap set, by default the user's own always-on
  node (ADR-012 §Bootstrap).
- **The at-rest unit is the sealed segment** (ADR-010): `log-db | plaintext-cache | index |
  key-material`, sealed under the channel SEK; the store is a durable blob map.
- **Rust-maximal** (ADR-001 #10): no native code enters the tree.

Decisions taken by the decider on 2026-09-19 for this ADR: the persistence engine is **redb**; member
prekey bundles are published as a **new rendezvous record kind**; the invite link **never carries the
passphrase**; and delivery is **single-device first, network second**.

## Decision

### The `Node`: one actor, one writer, one secrets boundary

`vox_core::node::Node` is a single asynchronous actor on a multi-threaded tokio runtime. It owns, and
nothing else touches: the unlocked identity (`VaultRootSigner` from the `IdentityVault`), every
channel's `Sek`, the log `Dag`s, the governance `Evaluator`s, pairwise `Session`s, `SenderChain`s and
`ReceiverChain`s, and the store handle. It is the **single writer** of every DAG and of the store
(the ADR-008 single-writer rule and the redb single-writer transaction coincide). Everything outside
the actor — connection tasks, sync tasks, the UI — communicates through typed messages:

- **UI → node**: ADR-015's `Command` over an `mpsc`; **node → UI**: `ViewModel` snapshots over a
  `watch` (latest wins) and ordered `Event`s over an `mpsc`. These types already exist in
  `vox-tui::viewmodel` and carry only fingerprints, nicknames, decrypted display text and enum
  state — never keys, SKDMs, SEK or `self_seed`. `NodeHandle` implements `CoreHandle`; `OfflineCore`
  remains the no-node binding.
- **Network → node**: per-connection tasks own the QUIC streams and hand the actor *parsed, verified*
  wire structures; the actor decides (admission, acceptance, consent), never the transport task.
- **Node → network**: the actor emits outbound work (sync sessions to run, records to publish, SKDMs
  to deliver) that a connection manager executes.

Two hosts run the same type. **`vox`** (ADR-015) embeds a *full* node: unlocked vault, channel
secrets, decryption. **`vox node`** (the headless binary, ADR-014) embeds a node **constructed without
a vault**: it has a transport identity of its own (an ephemeral or file-backed composite key so peers
can pin it) but no channel SEK, no sender keys and no pairwise sessions, so it can store, sync and
serve ciphertext and rendezvous records and can never decrypt. The absence is structural — the
secret-bearing fields are `Option`s that the headless constructor leaves `None` and the actor's
decrypt/author paths require — not a configuration flag.

### Persistence: redb, sealed segments, XDG layout

- **Engine.** `redb` (pure Rust, copy-on-write B-tree, ACID, single writer / MVCC readers, single
  file, stable on-disk format). It was chosen over `fjall` (pure-Rust LSM): Vox's write rate is
  bounded by design (ADR-008 quotas), every stored value is an already-sealed blob, the single-writer
  constraint matches the actor, and a two-crate dependency with no background threads and a
  one-sentence crash model ("the last committed state is what you get") is the right posture for a
  file that holds sealed key material. Space reclamation is an explicit `compact()` the node runs
  after TTL pruning.
- **What is stored, and how.** One redb file per profile. Tables: `segments` keyed by
  `(channel_id, SegmentKind, segment_id)` → `SealedSegment` bytes (ADR-010: log entries, plaintext
  cache pages, indices and key material are sealed under the channel `Sek` before they touch the
  store; the store never sees plaintext or a raw key); `sek_wraps` keyed by `channel_id` →
  `SekWrap` bytes (double-locked, ADR-010); `rendezvous` keyed by `(channel_id, epoch, kind,
  author_id)` → record bytes with expiry (public, unsealed — it is what the node serves); `meta`
  (schema version, profile id). The identity vault is a separate file (`vault.cbor`, the
  `IdentityVault` codec) so a store can be discarded without touching identity.
- **Layout (ADR-015 §XDG).** Config `$XDG_CONFIG_HOME/vox/config.toml`; data
  `$XDG_DATA_HOME/vox/<profile>/{vault.cbor, store.redb}`; files `0600`, directories `0700`; one
  profile per identity. The headless node uses the same layout without a vault.
- **App-lock.** `Lock` drops every `Sek` (`lock_now`) and pairwise/sender state from memory, closes
  nothing on disk; unlock re-derives from the vault passphrase and the wraps. Idle and `SIGHUP`
  triggers are ADR-015's and are wired here.

### Channel lifecycle and the invite link

- **Create.** `Genesis::create` at the day-one suite floor (ADR-003) → `channel_id`; a fresh `Sek`
  sealed under (identity factor, channel passphrase); epoch 0; the creator is root admin
  (`CapabilitySet::admin()`); the creator's first `SenderChain` for `(channel_id, epoch 0)`; the
  genesis and the creator's first governance entries appended to the DAG; a member address record
  published (below).
- **Invite link.** `vox://<channel_id-base32>?b=<multiaddr>[&b=…][&r=<responder-fingerprint>]`. It
  carries the **rendezvous half** of ADR-005's magnet-link design only: the channelID and the
  bootstrap multiaddrs of one or more anchor nodes, plus an optional pin of the responder's
  fingerprint. **The passphrase is never in the link** — the joining client collects it through the
  masked prompt (ADR-015) and it travels out-of-band, so a leaked link is a leaked rendezvous, not a
  leaked channel (the ADR-005 separation). The pre-join and join flows below need nothing else.

### The rendezvous service and the member bundle record

Any node serves the rendezvous service on its `VoxEndpoint` (ALPN `vox/1`, mutually authenticated,
ADR-011); the configured bootstrap set (`BootstrapSet`) is simply the anchors a client publishes to
and reads from. It is a request/response protocol on one QUIC bi-stream (u32-BE length-prefixed
canonical-CBOR frames, the ADR-011 stream convention): `PUT <record>` for the three record kinds and
`GET <channel_id, epoch, kinds>` returning every live record, each gated by the existing
`RendezvousStore` policy (member-only via the channel's membership oracle, `MIN_REFRESH_SECS`,
`MAX_TTL_SECS`, clock skew, per-bucket caps). The three kinds:

1. **Member address record** (`0x0007`, exists): endpoints, refreshed as reachability changes.
2. **Pre-join record** (`0x0008`, exists): a joiner's asserted identity + prekey bundle + endpoints.
3. **Member bundle record** (new struct tag `0x0012`, `vox/member-bundle-record/v1`): a member's
   current `PrekeyBundlePublic`, root-signed like `0x0007`, body
   `[author_id, channelID, epoch, prekey_bundle, seq, timestamp, ttl_secs, [sign_algo]]`, default and
   maximum TTL 7 days (the ADR-002 signed-prekey cadence), refreshed on rotation and when the
   one-time pool crosses its low-water mark. This is the answer to the one gap the series left open:
   after a join, every consenting member seals its SKDM to the newcomer using the newcomer's
   pre-join bundle, and the newcomer seals *its* SKDM to each member using that member's bundle
   record. Bundles are root-signed and verified against the out-of-band fingerprint, so the board
   only has to be *available*, not trusted — the same property the address records already rely on.
   It is a separate kind because the address record is refreshed on a minutes scale and is tiny,
   while a bundle changes weekly and is ~10–20 KB with signatures.

The `wire::StructTag` registry grows to `0x0012` in M14; the registry-coverage test and the ADR-008
golden-vector obligation extend with it.

### Join over the network

The joiner resolves the link's anchors, fetches the channel's records, publishes its pre-join record,
and dials a member (the pinned responder if given, else any member with live endpoints) with
`connect_direct`. On a dedicated `join` bi-stream the two sides exchange, in order, the ADR-005
messages the existing state machine already produces and consumes — the signed `ResponderNonce`
(difficulty from `Difficulty::adapted_for_load(pending_joins)` against the responder's live queue,
capped at `MAX`), the `PowToken`, the CPace shares, the sealed proofs of possession, the
`InitialMessage` — driving `join_initiate` / `join_accept` / `complete_cpace` / `verify_peer_sealed`
/ `bootstrap` unchanged. The result is a pairwise `Session` between joiner and responder, over which
the responder delivers its SKDM. Every other member learns of the newcomer from the responder's
consent grant on the log and from the pre-join record, opens its own session to the newcomer's
bundle, and delivers its SKDM when — and only when — its user consents (`Command::ConsentGrant` →
`issue_consent_grant` appended to the log). The newcomer opens sessions to members via their bundle
records and delivers its own SKDM. Consent remains per-sender and human-initiated (ADR-007); the
runtime automates delivery, never the decision.

### Connections, reachability and sync

- **Connection manager.** One `VoxConnection` per peer fingerprint, dialed with `connect_direct`
  from the peer's address record and accepted with `Admission::Callback` over the union of the
  channels' current memberships (plus the anchors and any pending pre-join identity for the join
  stream only). Streams are typed by their first frame: `sync`, `join`, `pairwise` (SKDM and other
  sealed control messages), `rendezvous`, `tunnel` (ADR-013), `coord` (hole-punch signaling).
- **Reachability ladder (ADR-012), composed here.** On start: bind; if IPv6 is available publish it;
  if IPv4-only, attempt `map_port` (PCP → NAT-PMP) against the configured or discovered gateway and
  publish the mapped endpoint; the anchor reports the observed address on connect so the node
  learns its reflexive endpoint. To reach a peer: `connect_direct` over its candidates; on failure,
  if both are connected to a common anchor, run the DCUtR `Coordinator` exchange over a `coord`
  stream *through the anchor* (the anchor forwards `CoordMessage` frames between the two peers and
  nothing else) and fire the synchronized `connect_direct`. **Relay of the data plane** (a live
  tunnel or stream through the anchor when both direct and punched paths fail) remains ADR-013's
  mechanism and is a named later capability; ADR-012's availability model does not need it —
  a channel's log reaches an offline member through the anchor's *store*, not through a live relay.
- **Sync scheduling (ADR-008).** On every new connection, a frontier session for each channel both
  peers hold; every 30 seconds while connected; and a push immediately after a local append. Range
  reconciliation (`range_reconcile_exchange`) is wired over `QuicStreamTransport` and selected when a
  channel exceeds 100 authors, as the ADR requires at scale. The anchor participates as an ordinary
  peer whose `AuthorResolver` is built from the channel's genesis, admin certificates and the
  stored pre-join / bundle records (each embeds the full composite key), so it verifies and stores
  entries it can never read.

### Milestones and gates

Each milestone ships complete and is proven by an automated test that exercises the composed
behavior, not by unit tests of its parts; the manual `examples/spike_*.rs` harnesses remain for
cross-process checks.

- **M13 — the single-device node.** `vox_core::node` with the actor, redb store, vault unlock/lock,
  channel create, local log append + render-gating + governance, own sender chain, the `NodeHandle`
  `CoreHandle`, and the ADR-015 runtime the TUI declares (tokio runtime, blocking crossterm task,
  `CancellationToken`, `watch`/`mpsc` channels). The TUI's composer, create-channel onboarding with
  the masked passphrase prompt, and the member pane become real for one device. **Gate:** an
  integration test creates a profile, creates a channel, appends and renders messages, locks,
  unlocks, and finds the same state after a process restart; the TUI's declared-but-unused
  dependencies are used or removed; ADR-015's lock/zeroize and primary-buffer gates are met.
- **M14 — two machines chat.** Rendezvous service, member bundle records (`0x0012`), the `join`
  stream, SKDM delivery, consent, the connection manager, frontier sync, and the invite link; the
  reachability ladder's direct and port-mapped rungs. **Gate:** an integration test runs two nodes
  in one process over loopback QUIC — create, invite, join with the passphrase, consent, exchange
  messages both ways, and a third node that joins and is *not* consented reads nothing; a
  cross-process spike does the same over two `vox` binaries.
- **M15 — the anchor and the tunnel surface.** `vox node` headless (store, rendezvous, sync peer,
  hole-punch signaling), range-mode sync over transport, and the ADR-013 CLI (`vox service add`,
  `vox forward`) over the tunnel module. **Gate:** two nodes that are never simultaneously online
  converge through an anchor; a hole-punch between two NATed loopback endpoints succeeds through
  the anchor's `coord` stream; `ssh` over Vox through `vox forward` end to end.

## Consequences

### Positive
- Turns twelve finished layers into a usable product without a single new cryptographic mechanism:
  every arrow in the composition already exists as a tested function.
- Preserves the series' strongest invariants by construction: single writer, secrets in one actor, a
  typed UI boundary, and a headless node that structurally cannot decrypt.
- The rendezvous board closes the last open protocol gap (member prekeys) with the trust model and
  cap regime the board already has.

### Negative
- The node is a large, stateful actor; its correctness rests on the integration tests the gates
  demand, not on the unit suite alone.
- Anchors see channel *metadata* — who publishes what, when — which ADR-001 already lists as a
  non-goal; nothing here changes the threat model.
- redb's file does not shrink without an explicit compaction; pruning must schedule it.

### Neutral
- The relay data plane, a DHT, iOS, and the macOS GUI (ADR-014) remain distinct capabilities; M15's
  anchor is the "always-on box" ADR-014 assumes.

## Links
**Depends on**: ADR-002, ADR-003, ADR-005, ADR-006, ADR-007, ADR-008, ADR-010, ADR-011, ADR-012,
ADR-013, ADR-015.
- Enables: ADR-014 (the macOS client embeds this node), a future relay-data-plane ADR, a future DHT
  ADR.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
