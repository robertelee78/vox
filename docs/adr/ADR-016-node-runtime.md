# ADR-016: Node Runtime — Composing the Core

**Status**: accepted (2026-09-19) — **M13 (single-device node), M14 (two machines chat), M15 (anchors: symmetric-NAT swarm formation *and* convergence between members never online together) and M16.1 (a TCP service reached across the overlay) are all gated in `crates/vox-core/tests/` and run in CI's release step**; the person-facing service surface moves to ADR-017
**Date**: 2026-09-19
**Updated**: 2026-09-22 (second note) — **OPEN DEFECT: a cross-process join through an anchor fails roughly
half the time, at the responder dial.** Named here rather than left as a flaky gate, because it is a product
defect and the gate is telling the truth.

`service_rehearsal_proof`'s untrusted-joiner control fails ~40–50% of runs with
`vox: cannot join: Failed(Unreachable)`, after **250–285 seconds**. Instrumented, so this is measured and
not inferred:

```
JDIAG: board ok, peer=uhjrm6v4…
JDIAG: responder=uucpadv6… board_is_responder=false eps=1 members=2 bundles=2
JDIAG: dialling responder with 1 endpoints
vox: cannot join: Failed(Unreachable)
```

What that rules out: the board is reached, so `reach_a_board` is not implicated; and `eps=1`, so the
responder's **address record had propagated** — the first note below fixed that and it is working. What
remains is that a dial to an endpoint **we hold** fails. The 250s is one dial, not a loop: the ADR-012
ladder tries direct, then a punch, then a circuit, each with its own budget.

Leading hypothesis, **not yet confirmed**: the responder advertises an endpoint the joiner cannot use.
`local_endpoints()` enumerates interfaces, so a LAN address can land in the record while the reachable
loopback one does not — which would make this the third instance in one day of "the address we have is not
the address that works". It did not reproduce in the three runs made after the endpoint text was added to
the instrumentation, so the next step is more runs, not a fix.

**This blocks a release.** It is the join path, so it is not confined to services: agent comms joins too,
and ADR-020's premise is sessions on remote hosts. Note also that `service_rehearsal_proof` is currently
the **only** gate in the tree that joins across processes through an anchor, which is why it is the only one
that catches this — an argument for more proofs of that shape, not for distrusting this one.

Two related items, neither blocking: a user's **first** `ssh` into a fresh room can wait minutes inside
`up::reach_host_with_patience` (working as designed, bad as an experience, same family one layer up); and
the dial ladder reports `Unreachable` **without naming which rung failed**, which is ADR-018 §8b and is why
this took instrumentation to narrow at all.

**Updated**: 2026-09-22 — **a join no longer reports "I do not know your address yet" as "you are unreachable."**
Two fixes to `join_channel`, one of which was a real ~40% failure on `main`:

1. *The responder's address record.* The joiner read the responder's endpoints from the board with
   `unwrap_or_default()` and dialled whatever came back; an empty list fails at once, and that surfaced as
   `Fault::Unreachable` in under three seconds for a member who was online. Measured cause, from instrumenting
   the join: on a failing run the board held `members=1, bundles=2` — the responder's *bundle* record had
   propagated but its *address* record had not. The two travel separately, so a joiner arriving in that window
   held a key for a member it had no way to reach, and concluded the member was gone. It now waits up to 20s,
   re-fetching the board, because a deadline is what separates "not yet" from "not there". `node_m15_session_from_bundle_gate`
   went from ~2 failures in 5 to **10/10**, and setting the patience to zero puts it back to 3 failures in 6 —
   so the gate measures the fix rather than the weather.
2. *Routes to a board are hints, not the only route.* The joiner tried only the anchors embedded in the invite
   link, once each, and refused. A room address is a magnet link and its trackers are hints, so it now tries the
   link's anchors, then the node's configured anchors, then any anchor it already holds a connection to, and
   retries against a deadline. **Stated honestly: this did not fix the failure above** — it was written first on
   the wrong diagnosis, and the instrumentation is what corrected it. It is kept because one stale or not-yet-ready
   hint ending a join is still the wrong shape.

2026-09-21 — the M15 "sessions to members we have not met" gap is **half closed**: members now open ADR-004 sessions from one another's bundle records (`PairwiseFrame::Hello`, `NodeNet::board_bundle`, `Actor::ensure_session`), so consent and re-key reach a member admitted through somebody else; the restart half stays open because the board is in-memory too. 2026-09-21 — M18.1: the node enforces ADR-006's rotation bound and carries ADR-007's
per-member revocation end to end (`vox revoke`), with two new sealed segments and a re-key retry on the
tick; gated by `node_m18_revocation_gate`. 2026-09-20 — M13 complete: paths, store, profile, channel state, actor + API, live TUI, and the M13 gate test (production Argon2id, run in release by CI).
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
- **M18.1 — sender-key rotation and per-member revocation.** The node drives what ADR-006 and ADR-007
  already specified: every append consults the rotation bound; a revocation rotates, records the fact and
  re-keys the remaining consenters; two sealed `KeyMaterial` segments carry the retained origins
  (`SEG_ORIGINS = 6`) and the delivery ledger (`SEG_DELIVERED = 7`); the tick retries a re-key owed to a
  peer that was unreachable. **Gate:** three nodes over loopback QUIC — after one member is revoked, his
  log catches up with the author's and he can open none of it, while the member who kept consent reads
  the whole conversation across the rotation boundary (`node_m18_revocation_gate`).

  **Reach, stated exactly (updated 2026-09-21).** A re-key travels over an ADR-004 pairwise session.
  The node now opens one **from the member's bundle record** when the join path never made one, which is
  what this ADR always specified above and what the runtime previously did not do — so consenting to,
  and re-keying, a member admitted through somebody else works. Gated by
  `node_m15_session_from_bundle_gate`, where Carol joins *Bob* and Alice — who shares no join, no CPace
  and no PQXDH with her — consents and is read.

  **What remains open is the restart half, and only that.** A restarted node has no session *and no
  board*: `nat::store::RendezvousStore` is in-memory and nothing refetches it at startup, so there is no
  bundle record to open a session from. Closing it means pulling the board from an anchor on start
  (the anchor already persists one, M15.2b). Until then a re-key owed to a member this process has not
  learned of stays owed and the tick keeps offering it. The security half is unaffected either way: the
  rotation is what excludes the revoked member, and it takes effect with no delivery at all.

  **Wire.** The initiator's PQXDH opening message has no join stream to travel on, so it rides the
  `pairwise` stream itself as `PairwiseFrame::Hello` (op `2`), immediately before the SKDM it enables.
  This is an **addition**: `v0.1.0` peers do not know op `2` and reject the frame, so a `v0.1.1` node
  consenting to a never-met member across such a peer degrades to the old `Unreachable` rather than
  failing in any new way. No existing frame changed.
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
- **SKDM delivery (M14.5b).** `node::pairwise_stream` is the `pairwise` stream kind's first content: one
  frame carrying an SKDM sealed into the peer's ADR-004 session, delivered without a round trip
  (`deliver_skdm` / `recv_skdm`). `ChannelState::accept_skdm` verifies it against the author's admitted
  key, keeps it as a `ReceiverChain` in a sealed `SEG_RECEIVERS` segment, and **backfills**: every content
  entry already stored from that author is retried, so the common ordering (entries arrive before the key)
  renders correctly. Rendering applies both gates — the sender key must be held *and* the author must have
  consented on the log — so a decryptable message from a non-consenting author still does not render.
  `ReceiverChain` gained `to_state`/`from_state` so the head and skipped-key cache survive a restart
  (ADR-006/ADR-010 Implementation notes); a decrypt's chain advance and its plaintext row are persisted in
  one batch, and a failed persist poisons the channel rather than allowing a consumed iteration to be
  re-derived. Proven by an in-process test (ciphertext before the key, backfill on arrival, forward-only
  history releasing nothing earlier, replay refused, survives a reopen) and a loopback QUIC test (the SKDM
  crosses a real pairwise stream sealed in a real PQXDH session and then decrypts the author's broadcast).
- **Frontier sync over QUIC (M14.6).** `node::syncstream::open_sync` / `accept_sync` put the ADR-008
  engine on a **typed** `sync` stream, and `ChannelState::sync_over` is the reconciliation the runtime owes
  after a session: sync applies entries to the log itself, then the channel seals each new entry into a
  `LogDb` segment, folds governance into the evaluator, and renders content subject to *both* gates (key
  held **and** author consented). Whatever arrived is reconciled even when the session then fails, so a
  partial session makes durable progress; the coded ADR-008 reason is preserved rather than collapsed.
  `SyncSchedule` is the §"Sync scheduling" policy as a pure function — a session on connect, on a local
  append, and every `SYNC_INTERVAL_SECS` (30) otherwise — and `should_use_range_mode` is the >100-author
  rule; wiring them to the actor's timers is M14.7/M14.8. The session's resolver
  (`ChannelState::resolver`) closes ADR-008's `kind_for` gap for sync. One constraint surfaced and is now
  documented rather than discovered later: a member must admit the channel's current members before it can
  sync, because an entry from an unadmitted author is an unverifiable entry and hard-fails the session —
  the test asserts the failure, then admits and succeeds. Proven over loopback QUIC: two members converge
  and each renders the other's post-consent message (and *not* what was written before consent, under
  forward-only history), while a third member syncs the entire log and renders nothing.
- **The `vox://` invite link (M14.7a).** `node::link::InviteLink` is the format above, parsed and rendered.
  The 32-byte digests are lowercase unpadded RFC 4648 base32 (52 chars, case-insensitive on input, so a
  link survives being re-typed or lower-cased by a chat client, and needs no percent-encoding); anchors use
  the exact ADR-012 multiaddr text form, for which `Multiaddr::parse` now round-trips `Display`. The
  structure enforces the decision that matters: **there is no field for a secret**, so the passphrase
  cannot be in the link even by accident, and a leaked link is a leaked rendezvous — which ADR-012 already
  opens to any authenticated peer that knows the channelID. Parsing is strict because a link is untrusted
  input from a chat message: an unknown query key is refused rather than ignored (an older client must not
  silently drop a future field), as are a duplicate `r`, a missing `b`, more anchors than `MAX_ENDPOINTS`,
  a non-canonical base32 tail, or any malformed component.
- **The genesis goes on the board (M14.7b).** The service's three record kinds could not answer the one
  question a cold joiner asks first — *what is this channel?* — so `RecordKinds::GENESIS` was added
  (ADR-012 Implementation notes explain why it needs neither a membership check nor a TTL). Without it the
  §"Join over the network" flow could dial the anchors and read the board but never construct
  `ChannelState`, since that needs the genesis whose hash is the channelID.
- **The network surface (M14.7c).** `node::network::NodeNet` composes M14.1–M14.7b into the flows a node
  performs, while keeping the actor the single writer of channel state: `accept_stream` authorizes an
  inbound stream and **serves the board itself** (it needs no channel state), handing every other kind back
  as an `Inbound` for the actor; `publish_local` / `own_records` file this node's genesis, address record
  and bundle on its own board (a node is its own first anchor, and dialing itself would be absurd);
  `publish_channel_records` and `publish_genesis` do the same to a remote anchor; `fetch_channel` reads the
  board; `start_join` / `answer_join` run the two sides of the ADR-005 exchange. `SharedMembership` is the
  seam the served board reads: the actor publishes a membership snapshot whenever it changes, and staleness
  fails **closed** — a member missing from the snapshot is refused and retries, never wrongly admitted.
  Two decisions are recorded in the ADRs they belong to: a node **retains the channel passphrase** while a
  channel is open, because CPace needs it live to answer a join (ADR-005 Implementation notes; ADR-010
  explains why the group factor may sit in memory while the individual one may not), and the join's binding
  parameters are passed explicitly rather than re-derived on each side, since both ends must land on
  identical values. The flow is proven over loopback QUIC end to end: the member files its genesis and
  records, the joiner reads the board through the parsed `vox://` link, joins with an out-of-band
  passphrase, both ends encrypt and decrypt over the resulting session, and the joiner then builds local
  channel state that reads **nothing** — joining released no keys.
- **The actor owns the network (M14.7d).** `Node` gained a second input: client commands and the network's
  inbound work are interleaved in one `select!`, so channel state still has exactly one writer. The
  network's lifetime is the *unlocked* identity's — binding the endpoint needs the identity's signer, so a
  locked node has no network identity to present and `Lock` closes every connection and the endpoint
  (`NodeView::listening` shows what it is bound to, which is public information). Creating or opening a
  channel files its genesis and this node's address record and bundle on its own board, so a joiner can
  learn what the channel is and how to reach us; a refusal there is normal (the ADR-012 refresh floor
  declining a faster refresh), not an error. Inbound joins are answered, and inbound SKDMs are taken and
  backfilled, emitting `PeerJoined` / `SenderKeyReceived`.
  Wiring this surfaced **three gaps in the Decision, all now closed**, each of which only appears once one
  connection carries many channels:
  1. **A join stream never said which channel it was for.** The Decision's frame list starts with the
     responder's challenge, which assumes the responder knows. It cannot: a connection is per *peer*. The
     joiner now opens with a `WANT {channelID, epoch}` frame and the responder answers only for a channel
     it holds open and can answer for (ADR-005 Implementation notes).
  2. **A pairwise SKDM never said which session sealed it.** A session is bound to a `(channelID, epoch)`,
     so the recipient could not pick one. The frame now carries the channelID outside the sealed message —
     not a secret, and inside the authenticated stream regardless (ADR-006 is unaffected).
  3. **"Any pending pre-join identity, for the join stream only" needed a source of truth.** It is a
     *board* fact: a joiner announces itself by publishing its pre-join record (`0x0008`, self-signed,
     publishable by anyone), and `accept_stream` consults the board, so ADR-007's **open passphrase join**
     works without anyone maintaining a list. An identity with no record stays `Unknown` and reaches the
     board and nothing else.
  Inbound **sync** is refused with the coded reason for now rather than left to hang: ADR-008's engine is
  synchronous and a session needs its own blocking thread plus shared access to the channel's store, which
  is M14.7e along with the client-side `JoinChannel` / `Consent` / `Invite` commands. A test drives the
  whole inbound path: a networked node binds on unlock, publishes its channel to its own board, a peer
  fetches the genesis and bundle, announces itself with a pre-join record, completes a real join, is
  admitted as a log author while reading nothing, and the endpoint is gone after `Lock`.
- **The client commands, and the M14 gate (M14.7e).** `Invite`, `JoinChannel`, `Consent` and `Sync` complete
  the client API, and inbound sync now runs for real: the ADR-008 engine is synchronous, so a session moves
  the channel out of the actor's map onto a `spawn_blocking` thread with a shared store handle
  (`Profile::store_handle`) and back. While a channel is away, commands naming it answer `UnknownChannel` —
  the session is short and the client retries, which beats blocking the whole actor or mutating channel
  state from two threads. To make that possible the channel's persistence-only methods now take `&Store`
  rather than `&Profile` (signing still needs the signer), and `ChannelState::me` comes from its own sender
  chain, so rendering needs no signer at all.
  **The gate is met** (`tests/node_m14_gate.rs`, production Argon2id + `(200,9)` PoW, ≈ 11 s in release):
  three nodes create, invite, join with an out-of-band passphrase, consent, exchange messages both ways,
  and the third — which joined and was consented to by nobody — receives the entire log and renders
  **nothing**. Writing it exposed four more things the Decision had wrong or unstated, all now fixed:
  1. **A sync stream did not name its channel either** (the same gap as join and pairwise): a frontier
     session reconciles one log, so the initiator now sends a `(channelID, epoch)` preamble before handing
     the stream to the engine. ADR-008's frames are untouched.
  2. **The ADR-004 responder cannot speak first.** It has no sending chain until it has *received*, so a
     member could never answer a newcomer. ADR-007 step 2 already says the newcomer broadcasts its own
     sender key — that is now done as part of joining (and recorded with a grant, since a key without a
     grant is a key the recipient must not use), which also unblocks the responder.
  3. **A pending joiner needed the `pairwise` stream too**, not "the join stream only": the instant a join
     completes the newcomer must deliver that key, before the responder has reclassified it as a member.
  4. **A node must publish its records to the *anchors*, not only to its own board**, and must **learn the
     current members from the board before syncing**. A key nobody can find cannot be admitted, and an
     ADR-008 session hard-fails on the first entry from an unadmitted author — so a member who joined after
     us would otherwise make every later session fail. Both are now part of join and sync.
  And one bug worth recording because the fix is a rule, not a patch: **authorization must be evaluated
  when a stream arrives, not when the accept loop iteration began.** Snapshotting the peer policy before
  awaiting `accept_bi` refused exactly the stream that mattered — a member delivering its sender key on a
  connection we had dialled before we knew it was a member.
- **Sync happens on its own (M14.7f).** `SyncSchedule` is now driven: the actor ticks once a second and
  applies §"Sync scheduling" — a session per shared channel on a new connection, a push when a local append
  is pending, and the 30-second interval otherwise. "Immediately after a local append" is realized as
  *within one tick*, so authoring never waits on the network. The M14 gate no longer issues a single `Sync`
  command; it waits for the messages to arrive by themselves, which is the property that matters.
  Two structural changes were forced, and both are improvements:
  1. **A session must not be awaited inside the actor loop.** Two nodes whose schedules fire together each
     awaited their own outbound session while the peer waited for *them* to serve the responder side —
     a deadlock, and the gate reproduced it the moment sync became automatic. A session now runs on its own
     task and reports back through `NetEvent::SyncDone`, so the actor stays free to serve the peer.
  2. **A channel is shared, not moved.** Handing ownership to the session made the channel invisible to
     everything else, so a join, a send or a key delivery arriving mid-session found no channel and failed —
     three symptoms of one cause (the gate hit the join one). Channels now live behind
     `Arc<tokio::sync::Mutex<ChannelState>>`: the actor is still the only thing that adds or removes them,
     but a session *guards* a channel for a few milliseconds instead of hiding it, and anything else waits
     rather than failing. The session takes the guard with `blocking_lock` from its blocking thread.
- **The client can do it too (M14.7g).** The TUI's network verbs stop reporting "not available yet":
  `:join` opens a masked prompt whose **first** field is the `vox://` link — typed in the clear, because it
  carries no secret — followed by the local name and the masked passphrase, which is the one thing the link
  deliberately omits; `:invite` is a one-line command, since a link is public; and `consent grant` is the
  ADR-007 human act, which the node turns into a sender-key delivery plus a grant. `verify` stays local
  (TOFU marking). The ADR-007 revocation and ADR-015 visibility verbs still report "not available yet",
  which is honest rather than silently accepted. A `ViewModel::notice` carries the short public lines the
  network produces — an invite link, "X joined — they read nothing until you consent", "X consented to
  you", a backfill count — and a synced channel's rendered count feeds the unread badge.
  **The binary now listens.** It spawned a non-networked node, which would have left all of M14 dead in
  `vox` itself; `run_live` takes a listen address (`--listen`, `VOX_LISTEN`, default `127.0.0.1:0`). The
  default is loopback rather than a wildcard on purpose: the bound address is what an invite link
  advertises, and `0.0.0.0` would advertise an address nobody can dial. Reaching another machine needs an
  address peers can reach until automatic address discovery lands.
- **The node advertises what the ladder composes, not what it bound (M14.8a).** The previous note had this
  backwards, and the `--listen` default with it. Binding is just binding: `--listen` now defaults to the
  wildcard, and what a node *publishes* comes from the ADR-012 ladder's publish side — its routable
  address, a gateway-mapped address when one can be had, loopback last (ADR-012 Implementation notes).
  Discovery runs on its own task at network start, because it touches the network (a route probe and a
  gateway request) and must not delay the unlock; when it finishes, every open channel's records are
  re-published, since the ones written before it may name only loopback. A granted mapping is held so it can
  be renewed inside its lifetime.
  This matters for the use case the ADRs are actually built for (ADR-013: "the overlay carries arbitrary
  TCP/IP between channel members", and a single swarm carries comms *and* tunnels): a client inside a
  private network with only outbound access must be able to form and join a swarm. Its own address is not
  what an invite link is for, and the remaining rungs — hole punching through a coordinator and a relay
  fallback — are what close that case.
- **Rung 1 of the ladder, and mappings that stay alive (M14.8b).** The publish side advertised an IPv6
  address without asking the firewall in front of it to let anything in, guessed the IPv4 gateway, and
  held a granted mapping without ever renewing it. Now: a PCP **identity mapping** opens the IPv6 pinhole,
  the real default route is read from the OS (with the RFC 7723 PCP anycast address as the portable
  fallback), candidates and families are raced so the whole publish side costs one retransmission
  schedule, and the actor re-runs discovery at half the shortest granted lifetime — republishing the
  address records, because a renewal may come back on a different external port. The details are in
  ADR-012's Implementation notes; what changes here is that a node's advertised addresses now stay true
  for as long as the node runs, instead of only for the first two hours.

- **Rung 3: the node punches through a coordinator (M14.9).** A node could only reach peers that were
  already dialable, which for the use case this runtime exists to serve — a client inside a private
  network, forming a swarm other things ride on — is most of the time nobody. `NodeNet::reach` is now the
  whole ADR-012 ladder, so the actor's one dial site climbs it: live connection, direct dial, then a
  DCUtR hole punch coordinated over the `coord` stream by any connected peer that will relay signaling.
  The responder side arrives as `Inbound::Punch` and is answered on its own task, because the exchange
  plus the synchronized dial takes seconds and must not block the coordinator's other streams; the
  connection it produces is adopted with the same bookkeeping a dialled one gets (a stream loop and a sync
  schedule). Every connection also asks its peer what address it is seen at, on its own task, so a punch
  has a mapped address to offer. The details and the NAT simulation that proves it are in ADR-012's
  Implementation notes.

- **Rung 4: the relay of last resort, and the ladder is complete (M14.10).** The earlier note on this
  page said the relay data plane "remains ADR-013's mechanism"; it does not — a relay carries a
  *connection*, not a consented plaintext path, and the two must not be confused. Every `VoxEndpoint` now
  runs on a socket multiplexer with **circuits**, and `NodeNet::reach` climbs all four ADR-012 rungs: a
  peer that a direct dial and a punch cannot reach is dialled through a circuit that a connected member,
  anchor or pending joiner carries, and the connection that results is the same authenticated
  `VoxConnection` as any other — so every stream kind this runtime has, and every application above it,
  works over it unchanged. The relay forwards QUIC packets it cannot read, bounded in number and by
  idleness. Details and the symmetric-NAT proof are in ADR-012's Implementation notes.

- **Anchors, and the swarm forms for two clients that nothing can reach (M15.1, 2026-09-20).** The
  ladder was complete and had nobody to climb through: a punch or a circuit needs a helper already
  connected to both peers, and a node's helpers were whichever peers it happened to have dialled. For two
  clients inside private networks that is nobody. ADR-012's answer is the user's own always-on node, and
  this wires it in as the runtime's `BootstrapSet`:
  - **Configuration.** `NodeConfig { clock, argon2, bind, pow_params, anchors }` is the one constructor
    (`Node::spawn_config`); the older ones are shorthands. `Bind` is an address or a caller-supplied
    datagram socket, so the same actor runs on a simulated network. `vox --anchor <fingerprint>@<multiaddr>`
    (repeatable; `VOX_ANCHORS` comma-separated) is the CLI; `node::link::{parse_anchor_spec,
    merge_anchor_spec, anchor_specs}` is the text form. Configured anchors are dialled — pinned — the
    moment the network starts, each on its own task; an anchor that answers is adopted, classified
    `Anchor` (carried into every policy rebuild), and given every open channel's genesis and records.
  - **Anchors are named in links and persisted per channel.** ADR-011 pins the identity on every dial and
    there is no "connect to whoever answers", so a link's anchors carry their fingerprints:
    `vox://<cid>?a=<fp>&b=<multiaddr>…[&a=…&b=…][&r=<responder>]`, each `b=` belonging to the `a=` before
    it, at most `MAX_LINK_ANCHORS = 4`. An invite names the channel's anchors first, the configured set
    next and the inviting node last — an anchor is reachable by design, the node's own addresses may not
    be, and a joiner tries them in that order. The anchors a channel was joined through, merged with the
    configured set, are persisted in a new sealed segment (`SEG_ANCHORS = 4`, `ChannelState::anchors` /
    `add_anchors`), because a node that forgot them after a restart could not republish its address and
    would fall off the swarm.
  - **The join is board-first.** The joiner dials the link's anchors in order until one answers, reads the
    channel from that board, **announces its pre-join record there before anything else** — on the anchor
    it is what lets the anchor coordinate a punch or carry a circuit for it, on the responder it is what
    authorizes the join stream — then `reach`es the responder (the `r=` pin, else any member the board has
    an address record for; the record's endpoints are dial hints, the identity is pinned) through the
    whole ladder, announces itself on the responder's own board, and runs the join. This retires the
    M14-era conflation of the anchor's address with the responder's identity.
  - **What an anchor that holds no channel can do.** Its membership oracle is empty, so three things were
    added: the board's own genesis names the channel **creator**, whose records the oracle now admits on
    the strength of it (`RendezvousService::resolve`); `NodeNet::classify` consults the board when the
    policy has no answer — a member of an anchored channel, or a joiner with a live pre-join record — and
    every stream authorization goes through it; and a session **relayed by a node's own anchor** is
    accepted whoever the far peer is (`coordstream::accepts_relayed`), because the anchor already applied
    its own rule and is the node the user configured to introduce peers. Without the last, a newcomer whose
    pre-join is on the anchor's board could never be punched or relayed to by a member that has not seen
    it yet — which is every member behind a NAT.
  - **Gate** (`tests/node_m15_anchor_gate.rs`, release): an anchor holding no channel; Alice, behind a
    symmetric NAT and configured with it, creates a channel and invites; Bob, behind another symmetric NAT
    and knowing only the link, joins — through the anchor's board, a defeated punch and a relayed
    circuit — Alice consents, and messages cross both ways by automatic sync. The anchor ends with no
    channel open and nothing but the board. Twenty-three seconds, ten of them the honest cost of the direct
    dial and the punch each timing out first.
  - **Two defects the gate found, both older than it.** `connect_direct` **spun hot** when an attempt
    failed faster than its 250 ms stagger: waiting on an empty `JoinSet` returns at once, and the loop
    re-armed a fresh timer around it every time — a busy loop that starved the runtime and, because M14.8b
    made dual-stack advertising real, was reachable by any IPv4-bound node dialling a peer with an IPv6
    entry (quinn refuses an IPv6 destination on an IPv4 socket instantly). Now an empty set launches the
    next candidate at once, and candidates the socket cannot address are dropped up front. And the sync
    transport had **no bound**: a session runs with the channel's lock held, so a peer that stopped
    answering held that lock — and everything else on the channel — for as long as it liked;
    `SYNC_FRAME_TIMEOUT = 20 s` on both directions ends such a session honestly.
  - **Still open (as of M15.1; the first item closed by M15.2a below).** ~~The anchor admits only the
    *creator's* records for a channel it is not a member of~~ — closed by vouching (M15.2a). The actor is
    single-threaded over commands, so a join's dial ladder holds it (now seconds, after M15.1b); the sync
    bound keeps that from deadlocking anyone, but the join should run off the actor.

- **Relay-first, upgrade later (M15.1b, 2026-09-20).** The cold start through an anchor took ~25 s
  because the ladder waited for a direct dial and then a punch to time out before trying the relay.
  Now `reach` races the rungs and the actor's one dial site takes whatever lands first — a round trip
  through the anchor — then, if that path was relayed, spawns `NodeNet::upgrade` and adopts the better
  connection it lands (`NetEvent::BetterPath`, which the answered-punch path also uses). The manager's
  one-per-peer rule became a preference with retirement, so the swap happens underneath in-flight
  streams on both sides; stream loops are keyed by connection rather than by peer, because an upgrade
  gives a peer a second connection that needs its own. The tick closes retired connections whose grace
  is up. ADR-012's Implementation notes carry the mechanism; the M15.1 gate now bounds the join at 12 s
  and runs in ~8 s. The spike behind it (`node::net::upgrade_tests`) showed the old rule closing every
  upgrade on both sides — a defect no upgrade could have survived.

- **UPnP-IGD (M15.1c, 2026-09-20).** The decider reopened ADR-012's omission: an anchor on a home
  router should forward its own port, and two peers with no anchor should find each other when one has a
  cooperative router. The node's publish side now tries UPnP after PCP and NAT-PMP; a mapping the router
  would only grant permanently is never renewed and is deleted when the network stops (`stop_network`,
  best-effort on its own task). Mechanism, hardening and the pending real-router validation are in
  ADR-012's Implementation notes.

- **`vox node`, the headless anchor, and how it learns a room's members (M15.2a, 2026-09-20).** The
  anchor the user runs is now what this ADR said it would be: `vox node` embeds a node **constructed
  without a vault**. `NodeConfig::headless(signer)` gives it a transport identity that is a
  file-backed composite key (`node::headless`, two seeds in a `0600` file, rebuilt identically at every
  start so peers keep pinning it) and no profile at all, so every path that would need a channel secret
  finds none — the absence is structural, as designed. It is on the network from spawn (nothing to
  unlock), serves the board, coordinates and relays, and prints the `<fingerprint>@<multiaddr>` a client
  gives as `--anchor`. Ctrl-C shuts it down. `NodeView::anchoring` is what it can say about itself: the
  rooms it serves and how many members it knows of each, never what any of them said.
  **Superseded on the member side, 2026-09-21 (M17.6).** Vouching is trust-on-first-use — the key comes
  from the record itself, which is only self-signed, and the sole evidence is *who relayed it*. ADR-020
  decision 3 forbids TOFU in as many words, and `accept_entry` admits an entry from any admitted author
  **without requiring the author to hold the room passphrase**, so admission is what turns "entry
  rejected" into "entry stored" for an arbitrary key. A **member** now admits a board key only on an
  `Admission` the record carries: `Creator`, checked against the genesis it already holds, or a
  `JoinWitness` signed by a member it already admits. The **anchor** keeps vouching — it is not a member,
  holds no passphrase and can never produce a join proof, so it has no other way to learn a channel's
  membership; it reads nothing either way, and a member rejects entries from authors *it* has not
  admitted, so an anchor's looser view does not propagate. The original text follows.

  **Membership is a board fact**, not a log fact — a member learns new members from the boards of
  members who witnessed the join — and the anchor now learns it the same way, by **vouching**: a bundle
  record from an author the anchor does not know, published over an authenticated connection by a peer
  it *does* know as a member of that channel, is admitted with the key the record carries
  (`RendezvousService::put` takes the publisher; `known_key` resolves an author through the oracle, the
  genesis creator, or a bundle already held). The record's own verification binds key to author; the
  vouch only says "one of us". An address record cannot precede its bundle (it carries no key), a stranger
  cannot vouch, and a vouched member vouches in turn. On the member's side, a node **mirrors its board**
  to its anchors: when it answers a join, and whenever learning members from a peer's board gains its own
  board a record — bundles first. The M15.1 gate now runs against a headless anchor and ends with the
  anchor knowing both members: the creator by her genesis, the joiner by her vouch.
  **Not yet (closed by M15.2b below):** ~~the anchor stores no log, so two members never online at once do
  not converge through it~~; a headless node that receives `Lock` stops its network with nothing to
  unlock it.
- **The anchor keeps the log, and the M15 convergence gate is met (M15.2b, 2026-09-20).** `node::anchor`
  gives a node a **ciphertext log with no secrets** for every channel whose genesis lands on its board:
  the genesis, the authors the board can vouch for, and the entries — sender-key ciphertext for content,
  signed frames for governance. That is all the ADR-008 engine needs on either side of a session, because
  the engine is secret-free: it verifies authorship and ordering, never plaintext. What is structurally
  absent is everything else — no SEK, no sender chain, no receiver chains, no timeline; there is nothing
  to render and no way to. The pages are sealed anyway, under a key derived per channel from the node's
  own identity (`anchor_sek`, HKDF over ADR-010's `factor_id` with `vox/anchor-log-sek/v1`), in segment
  kinds of their own (`AnchorLog`, `AnchorMeta`), so a stolen disk yields neither membership nor traffic
  shape without the identity file, and a node that later *joins* a room it anchored never mistakes these
  pages for its own.
  `NodeConfig::anchor_logs(true)` is the role — `vox node` sets it, a client does not, so a stranger's
  genesis on a client's board costs it nothing. The actor adopts an anchored channel when its board has
  the genesis (on the tick, or on the spot when a member opens a sync stream for it), admits the authors
  the board vouches for so their entries verify, reopens what the store holds after a restart and
  republishes each genesis, and reconciles each anchored channel with that channel's known members.
  Members reciprocate: a member now syncs with its **anchors** as well as its co-authors. Anchors are
  redialled from the tick (`ANCHOR_REDIAL_SECS`), so a restarted anchor is picked back up.
  **Gate** (`node_m15_anchor_gate.rs`, release): Alice and Bob meet once through the anchor, consent, and
  Bob leaves; Alice speaks into an empty room and the anchor takes the whole log; Alice leaves; Bob comes
  back to a room with nobody in it, configured with no anchor of his own — the one the link named was
  persisted with the room (M15.1) — and reads what Alice said. The anchor ends having rendered nothing,
  because it cannot.
  **Two things the gate itself taught.** Its first wait was `held >= 1`, which a *governance* entry
  already satisfied, so it shut Alice down before her message was pushed and then blamed the convergence:
  a gate must wait for the peer to hold **everything it is about to be asked to serve**, not merely
  something. And a session whose transport dies is reported as `sync failed: protocol version`, because
  ADR-008's engine maps every send failure onto `ProtocolVersionUnsupported` — harmless here (a peer went
  away mid-session and the next pass succeeded) but a misleading diagnostic, recorded as a known gap
  rather than papered over.
  **Still not yet:** the anchor tracks epoch 0 only (an epoch change is not yet carried on the board —
  unreachable today, since nothing removes a member, and a landmine for the day something does).
- **Two small refusals, and an honest error code (M15.2c, 2026-09-20).** Both gaps the M15.2b note left
  behind, closed:
  - **`Lock` is refused on a headless node.** It has no vault to lock and no passphrase to unlock with, so
    obeying `Lock` took the anchor off the network permanently — until a human noticed and restarted it.
    Nothing sends it today; that is what made it worth closing before something does.
  - **A transport failure is no longer reported as a protocol-version mismatch.** The ADR-005/008 registry
    gains `0x09 TransportFailed`, and ADR-008's engine uses it for a failed send, a failed receive, and a
    clean end-of-stream where a frame was due. A peer that closed its laptop now says so. Genuine version
    mismatches still map to `0x01`. Recorded in ADR-008's Implementation notes with the registry table
    updated; the behaviour is unchanged, the diagnosis is true.

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
