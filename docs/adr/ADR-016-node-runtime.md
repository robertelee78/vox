# ADR-016: Node Runtime — Composing the Core

**Status**: accepted (2026-09-19) — **M13 (single-device node) complete 2026-09-20**; M14 (network) in progress — M14.1–M14.5a done 2026-09-20
**Date**: 2026-09-19
**Updated**: 2026-09-20 — M13 complete: paths, store, profile, channel state, actor + API, live TUI, and the M13 gate test (production Argon2id, run in release by CI).
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

## Implementation notes (M13)

These record the concrete decisions made building this ADR (`crates/vox-core/src/node/`), so the spec and code stay in lockstep:

- **Paths (`node::paths`, M13.1).** `Paths::resolve(profile, data_override, config_override)` applies
  the ADR-015 precedence (explicit > `VOX_DATA_DIR`/`VOX_CONFIG_DIR` > `XDG_*` > platform default,
  macOS `~/Library/Application Support/vox`, Linux `~/.local/share/vox` + `~/.config/vox`), creates
  `<data>/vox/<profile>/` and the config dir `0700`, and rejects a profile name that is not a single
  path component. `write_private_file` is temp-file + rename with `0600`; the store file the engine
  creates is set `0600` after creation. Modes are enforced on Unix (the ADR-015 client scope); on other
  platforms the calls are no-ops, stated in the docs.
- **Store (`node::store`, M13.1).** `redb` tables `segments (channel_id, kind_code, id) → SealedSegment
  bytes`, `sek_wraps channel_id → SekWrap bytes`, `meta` (schema version, checked on open; a newer or
  garbage file is `Error::Storage`, never a panic). The write API accepts only `&SealedSegment` and
  `&SekWrap` — the store cannot be handed plaintext or a raw key. `Batch` wraps one write
  transaction so a log append and its chain-state advance commit together; a dropped batch writes
  nothing (tested). Kind codes `LogDb=1, PlaintextCache=2, Index=3, KeyMaterial=4` are part of the
  on-disk key and never reordered. `compact()` is the explicit space-reclamation call. `put_meta` /
  `get_meta` hold public facts only (schema version, identity fingerprint, creation time).
- **Profile (`node::profile`, M13.2).** `Profile::create` generates the native root
  (`SoftwareRootSigner`), the X25519 identity key and the `self_seed`, records the root's **OpenPGP v4
  fingerprint** (ADR-002 §GPG *Generate*; computed by `identity::openpgp`, verified against the
  draft-bre "Alice" sample key and a GnuPG-2.5.20-generated key) in the `IdentityBackup`, seals the
  vault under the production Argon2id profile, writes `vault.cbor` (`0600`, atomic), opens the store
  and records the public fingerprint + creation time in `meta`. `open` starts **locked**; `unlock`
  yields the `VaultRootSigner` (and refuses a vault whose identity disagrees with the store's
  fingerprint — the two must never silently diverge); `lock` drops it, zeroizing on drop. Every
  identity-needing operation goes through `Profile::signer()`, which is `Error::Profile("locked")`
  while locked. One identity per profile; a second `create` is refused. The passphrase is a `&[u8]`
  the caller owns and wipes.
- **Channel state (`node::channel`, M13.3).** A channel at rest is: the SEK wrap (`sek_wraps`),
  `KeyMaterial 0` = manifest `[1, genesis_wire, local_name, created, epoch]`, `KeyMaterial 1` = this
  identity's sealed sender-chain state (`SenderChain::to_state`, a new ADR-006 codec:
  `[1, cid, epoch, author, chain_id, chain_key, next_iteration, ed_seed, mldsa_seed, created]`),
  `LogDb n` = one ADR-008 entry's wire bytes in arrival order, `PlaintextCache n` = the rendered row
  `[1, entry_hash, author, created_secs, text]`. Message plaintext is the `node::content` envelope
  `[1, kind=text, created_secs, text]` (≤ 64 KiB) inside the ADR-006 sender-key message, which is the
  entry payload. `create` mints the genesis at the day-one floor (forward-only, attributable, no TTL),
  a fresh SEK double-locked under (identity factor, channel passphrase), and the first sender chain,
  persisting wrap + manifest + chain in one batch. `open` needs the unlocked identity **and** the
  channel passphrase (tested: wrong passphrase, locked identity, and a stolen wrap under another
  identity all fail), then **rebuilds the DAG from the log segments through `Dag::accept`** — the
  store is a cache of verified entries, never trusted as such — and accepts a cache row only if its
  entry is in the DAG. `append_text` validates against the DAG first, then commits entry + cache +
  advanced chain state in **one batch**; a failed commit **poisons** the channel (further appends
  refused until reopened) because the in-memory chain has already advanced and reusing a sender-key
  iteration for a different plaintext would be key/nonce reuse. M13 membership is `{creator}` and the
  evaluator is built over the genesis alone; M14 layers other authors, SKDMs, consent and sync onto
  the same layout. `lock_now` wipes the SEK; the state is then dropped.
- **The node's own typed boundary (`node::api`, M13.4) — a refinement of the Decision.** The
  Decision says the UI talks to the node through ADR-015's `ViewModel`/`Command`/`Event`. Those
  types live in `vox-tui`, and `vox-core` must not depend on a UI, so the node exposes its **own**
  client-agnostic types — `NodeView` (identity, locked, `mlock_active`, channel summaries, open
  channels' detail), `NodeCommand` (create/unlock/lock identity; create/open/close channel; send
  text; shutdown), `NodeEvent` (new entry, locked/unlocked, channel opened/closed, shutdown) and a
  closed, `Copy` `Outcome`/`Fault` (no free text) — and each client projects its own UI model from
  them: the TUI maps `NodeView` → `ViewModel` and `Command` → `NodeCommand` in its live `CoreHandle`
  (M13.5); the macOS client (ADR-014) consumes the same API over UniFFI. Passphrases enter as a
  zeroizing `Secret`; nothing else that crosses is secret-bearing (asserted by type: `Outcome` is
  `Copy`). A channel's *local name* is under the channel lock (it lives in the sealed manifest), so
  a closed channel is listed by id only.
- **The actor (`node::actor`, M13.4).** `Node::spawn` (system clock, production Argon2id) /
  `spawn_with` (injected clock + profile, for tests) opens an existing profile **locked** and runs one
  tokio task that owns the `Profile` and every open `ChannelState`, processing commands strictly in
  order with a per-command `oneshot` reply, publishing the latest `NodeView` on a `watch` after every
  command, and emitting ordered `NodeEvent`s on an `mpsc`. KDF-heavy commands run inline in the
  actor (later commands queue for the ~1 s an Argon2id unlock takes) — serialization is the design.
  `Lock` and `Shutdown`, and the close of the last `NodeHandle`, wipe every open channel's SEK and
  drop the signer before the task exits. Tests drive the whole single-device lifecycle through the
  handle, including a simulated process restart (identity present and locked, channels listed
  closed, timeline restored after unlock + open) and last-handle-drop locking.
- **The live client (M13.5).** `vox-tui::live::LiveCore` is the TUI's `CoreHandle` over a
  `NodeHandle`: `NodeView` → `ViewModel` projection, `Command` → `NodeCommand` mapping with the UI
  thread blocking on the node's typed reply, and UI-local state (channel on screen, unread counts
  from `NodeEvent`s, verification marks). `app::run_live` owns the runtime: multi-threaded tokio,
  node spawned on it, the UI loop as the blocking crossterm task, `CancellationToken` for auxiliary
  tasks, `SIGHUP` → `Lock`, and `Shutdown` on every exit path. Masked prompts collect every
  passphrase; M13's network verbs (join, consent, visibility, block) report "not available yet"
  rather than pretending. The production-Argon2id live-core lifecycle test is `#[ignore]`d in the
  debug suite and run in release by CI, alongside the real-parameter PoW gate.
- **The M13 gate (M13.6).** `crates/vox-core/tests/node_m13_gate.rs` — linked without `cfg(test)`,
  so it runs the **production** Argon2id profile — creates a profile, creates a channel, appends and
  renders three messages (observing the ordered `NewEntry` events), locks (channel closed, name
  hidden), rejects a wrong passphrase, unlocks and reopens, shuts down, then starts a **fresh runtime
  and a fresh node over the same directory**: the identity is the same, the profile starts locked, the
  channel is listed closed, a send is refused, unlock + open restores the local name, members and all
  three messages, and a fourth message appends (the sender chain continued from disk). File modes are
  asserted (`0600` vault/store, `0700` profile dir). ≈ 2.4 s in release; `#[ignore]`d in the debug
  suite and run by CI's release step with the other real-parameter gates. The TUI's
  declared-but-unused dependencies are now used (`tokio`, `zeroize`) or removed (`tui-textarea`), and
  ADR-015's primary-buffer and lock/zeroize gates are met (ADR-015 Implementation notes). **M13 is
  complete; M14 begins.**

## Implementation notes (M14)

- **Member bundle record (M14.1).** `wire::StructTag::MemberBundleRecord = 0x0012`
  (`vox/member-bundle-record/v1`) is registered — the registry table, `ALL` and the coverage test now
  span `0x0001..=0x0012`, and ADR-008's normative tables carry the tag and label.
  `nat::record::MemberBundleRecord` is the `0x0007` shape with `endpoints` replaced by the canonical
  `PrekeyBundlePublic` bytes; `verify` binds `prekey_bundle.root_pub` to the resolved member key and
  checks the bundle's internal signatures, and `build` refuses to sign a foreign bundle.
  `RendezvousStore` gained `BUNDLE_MAX_TTL_SECS` (7 days), `accept_bundle`, `current_bundles`,
  `bundle`, and a third bucket family pruned with the others (ADR-012 Implementation notes). The
  ADR-008 golden-vector obligation is still **UNMET** and now extends to `0x0012`; a pinned vector
  for this tag needs the fixed-seed X25519/ML-KEM prekey generation the rest of the suite also lacks.
- **Rendezvous service (M14.2).** `nat::service::{RendezvousService, RendezvousClient,
  MembershipOracle, RendezvousRequest, RendezvousResponse, RejectReason, RecordKinds, RecordSet}`
  over a bi-stream typed `StreamKind::Rendezvous` — the protocol exactly as the Decision states it
  (`PUT`/`GET`, u32-BE length-prefixed canonical-CBOR frames, every PUT through the existing store
  policy). Two things the Decision left implicit are now stated (ADR-012 Implementation notes):
  reading is open to any authenticated peer that knows the channelID, and a PUT's author need not
  be the connection's peer because the record is self-authenticating. The transport grew the shared
  async framing and the typed-stream kind frame (ADR-011 Implementation notes), and the clock moved
  to `crate::time` (re-exported from `node::actor`) because `nat` must not depend on `node`. Proven
  by a loopback QUIC test: a member publishes all three kinds and reads them back, a replay is
  refused with the coded reason on the same stream, a stranger reads the board but cannot publish a
  member record, a garbage frame is reset with ADR-008 code `0x05` as observed by the peer, and
  clean half-closes end the server task with `Ok`. Sizes measured (spike, then deleted): bundle
  record 18 084 B, pre-join record 20 211 B, address record 3 634 B → `MAX_RENDEZVOUS_FRAME` 48 KiB.
  The `MembershipOracle` for a node comes from its open channels' state (M14.5 wires it); the
  anchor's oracle from stored genesis/admin/bundle material is M15.
- **Prekey ring (M14.3).** M13's node could sign, seal and append but held **no key-agreement keys**:
  nothing to put in a bundle record and nothing to answer PQXDH with. `node::prekeys::PrekeyRing` is
  that state — identity DH key, current and retained-previous signed prekey, one-time pool, and the
  bounded consumed set ADR-004's serverless semantics require — persisted in a new
  `SegmentKind::PrekeyRing` segment sealed under an identity-factor-derived key (ADR-010 Implementation
  notes explain why identity-level material needed a third at-rest home). Policy lands where it belongs:
  the ADR-002 §2 rotation cadence, retain-previous window, pool low-water refill and one-shot consumption
  are all here, closing that ADR's "no rotation cadence" gap (ADR-002/ADR-004 Implementation notes).
  `load_or_create` is the single entry point: the node calls it after `CreateIdentity` and after every
  `Unlock`, so the cadence is applied on unlock, and it drops the ring on lock (no prekey secret behind a
  lock — an actor test pins it). Proven by nine module tests (bundle verification, depleted-pool
  fallback, restart survival, wrong-identity and tamper refusal, one-shot consumption across a restart,
  the concurrent-duplicate window and its expiry, the drain cap, rotation retaining the previous prekey
  for exactly one cadence, low-water refill at the real 64-prekey size) plus the M13 restart gate, which
  now also asserts the ring reloads and its bundle verifies at production Argon2id parameters.
- **Connection manager and the join stream (M14.4).** `node::net::ConnectionManager` keeps one
  `VoxConnection` per peer fingerprint whichever side dialled, dials through the ADR-012 ladder
  (`connect_direct` over the record's candidates), reaps closed connections, and closes a simultaneous
  second connection so the invariant holds. **One deviation from the Decision, recorded:** accepting with
  `Admission::Callback` over the union of memberships would reject the unknown peers ADR-012 requires a
  rendezvous server to serve, so admission stays open (ADR-011's default) and the membership rule moves
  to the **stream kind** — `PeerPolicy` classifies member / anchor / pending joiner / unknown and
  `accept_authorized` refuses a kind that class may not open, which is where "pending pre-join identity,
  for the join stream only" is now enforced exactly (ADR-012 Implementation notes). `node::joinstream` is
  the join exchange: seven ordered frames driving the ADR-005 state machine unchanged, with the
  authenticated transport identity as the PoP's expected identity, one opaque refusal reason, and the
  one-time prekey consumed *and persisted* before the handshake completes (ADR-004/ADR-005 Implementation
  notes). The ADR-005 structs' borrowed signer became `Send + Sync` so the exchange can be driven on a
  spawned task — a type-level tightening, no cryptographic change. Proven over loopback QUIC: a full join
  yields two sessions that encrypt and decrypt both ways, a wrong passphrase is refused opaquely, an
  unknown peer's `sync` stream is reset with the coded rejection, and the whole join runs at **production
  (200,9)** PoW in 1.95 s (release, `#[ignore]`d in debug like the other real-parameter gates).
- **Multi-author channel state and consent on the log (M14.5a).** `ChannelState` stops being
  single-author: `join_channel` builds a joiner's state from the board's genesis (hash-checked against the
  channelID), `admit_author` records a verified key as a log author in a sealed `SEG_AUTHORS` segment,
  `accept_entry` takes a peer's entry through the ADR-008 predicate and classifies it by payload, and
  `issue_consent` appends the ADR-007 consent grant as a governance entry that the evaluator folds in.
  The load-bearing distinction is that admission grants *log authorship only*: an admitted author's
  content entry is stored as ciphertext and never rendered, which is ADR-007's "credentials release no
  keys" made structural rather than promised. `classify_payload` also gives ADR-008's `kind_for` the
  discriminator it lacked (governance = struct-tagged frame, content = `vox/group-msg/v1` prefix,
  anything else refused); wiring it into the sync resolver is M14.6. SKDM delivery — the half that makes
  an admitted, consented author actually *readable* — is M14.5b.

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
