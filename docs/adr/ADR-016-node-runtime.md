# ADR-016: Node Runtime — Composing the Core

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: accepted. M13, M14, M15, M15.1–M15.2c and M18.1 are built in `crates/vox-core/src/node/` and proven through the shipped `vox` binary in `crates/vox-tui/tests/`. Requirements marked **planned** are not built; §"Open defects and limits" lists what is known wrong or missing.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: runtime, node, integration, persistence, rendezvous, sync, headless

## Context

Identity (ADR-002), the pairwise channel (004), join (005), sender keys (006), governance (007), the log and sync (008), at-rest storage (010), transport (011), NAT traversal (012) and tunnelling (013) are each specified in their own ADR. This ADR specifies the node that composes them into one process a person runs: what it owns, how it stores, how a room is created and joined over the network, how it connects, syncs and anchors, and how it reports what it is doing.

Decided by the decider on 2026-09-19: the persistence engine is **redb**; member prekey bundles are a **new rendezvous record kind**; the invite link **never carries the passphrase**; delivery is **single-device first, network second**. Carried from ADR-014 and ADR-015: **the client embeds the node**, and **a headless node is ciphertext-only**.

## Requirements

### Principles

- **NR-P1.** No native code enters the tree (ADR-001 #10, Rust-maximal).
- **NR-P2.** A headless node MUST NOT be remote-controlled. `vox node` serves no control socket.

### The `Node`

- **NR-1.** `vox_core::node::Node` MUST be a single asynchronous actor. It owns the unlocked identity, every open room's SEK, the log DAGs, the governance evaluators, the pairwise sessions, the sender and receiver chains, and the store handle. It MUST be the single writer of every DAG and of the store.
- **NR-2.** Everything outside the actor MUST talk to it through typed messages:
  - clients send `NodeCommand` and receive `NodeView` snapshots (latest wins) and ordered `NodeEvent`s;
  - network tasks hand it parsed, verified wire structures, and the actor makes every admission, acceptance and consent decision.

  `NodeView`, `NodeEvent` and `Outcome`/`Fault` MUST carry no keys, SKDMs, SEKs or `self_seed`. `Outcome` and `Fault` MUST be closed `Copy` types with no free text. A passphrase MUST enter as a zeroizing `Secret`.
- **NR-3.** The client MUST embed the node in its own process: the TUI runs it in-process (ADR-015), and the macOS client is to (ADR-014).
- **NR-4.** `vox node`, the headless node, MUST be constructed without a vault (`NodeConfig::headless`). It has a transport identity in a `0600` file of two seeds, rebuilt identically at every start so peers keep pinning it, and no profile, SEK, sender keys or pairwise sessions. The absence MUST be structural: the secret-bearing fields are `Option`s the headless constructor leaves `None`. A headless node MUST NOT be able to decrypt (ADR-015 requirement 1.2).
- **NR-5.** Commands MUST be processed in order, each answered on its own `oneshot`.
- **NR-5a.** The actor MUST tick once a second (`TICK`). "Within one tick" in this ADR means within that second.

### Persistence: redb, sealed segments, XDG layout

- **NR-6.** The store MUST be one `redb` file per profile (`store.redb`). The identity vault MUST be a separate file (`vault.cbor`), so a store can be discarded without touching identity.
- **NR-7.** The store's write API MUST accept only sealed segments and SEK wraps (ADR-010); it MUST NOT be handed plaintext or a raw key.
  - Segments are keyed by `(channel_id, kind_code, segment_id)`. Kind codes are part of the on-disk key and MUST NOT be reordered or reused: `LogDb=1`, `PlaintextCache=2`, `Index=3`, `KeyMaterial=4`, `PrekeyRing=5`, `AnchorLog=6`, `AnchorMeta=7`, `Trust=8`.
  - `meta` MUST hold public facts only (schema version, identity fingerprint, creation time), except for blobs ADR-010 seals there.
  - A newer or unreadable schema MUST be `Error::Storage`, never a panic.
- **NR-8.** A log append, its plaintext row and its chain-state advance MUST commit in one write transaction. A dropped batch writes nothing. A failed commit MUST poison the room until it is reopened, because reusing a sender-key iteration for different plaintext is key/nonce reuse.
- **NR-9.** On open, the node MUST rebuild a room's DAG from its log segments through `Dag::accept`, because the store is a cache of verified entries and is never trusted as such. It MUST accept a cache row only if its entry is in the DAG.
- **NR-10.** Paths MUST follow ADR-015 requirement 12.1 and its precedence: explicit, then `VOX_DATA_DIR`/`VOX_CONFIG_DIR`, then `XDG_*`, then the platform default. Data lives in `<data>/vox/<profile>/`. Files MUST be `0600` and directories `0700` (Unix). A profile name MUST be a single path component.
- **NR-11.** A profile holds one identity, and a second create MUST be refused. An existing profile MUST open locked. Unlock MUST refuse a vault whose identity disagrees with the store's recorded fingerprint.
- **NR-12. Planned.** The node is to reclaim space with `redb` compaction after pruning. `Profile::compact_store` exists, but nothing calls it.

### App-lock and signals

- **NR-13.** `Lock` MUST drop every SEK, the signer, the prekey ring and the pairwise and sender state, and close the network. A lock MUST be answered once it has settled (V210-94). The actor MUST keep answering other commands while it settles.
- **NR-13a.** Dropping the last `NodeHandle` MUST lock the node exactly as `Lock` does, then end the actor.
- **NR-13b.** The TUI MUST lock after `IDLE_LOCK_SECS` (5 minutes) without input (ADR-015).
- **NR-14 (M15.2c).** A headless node MUST refuse `Lock`.
- **NR-15.** `vox daemon`, `vox node` and every long-running verb MUST stop cleanly on SIGINT, SIGTERM, SIGHUP and SIGQUIT (V210-108).

### Channel lifecycle

- **NR-16.** Creating a room MUST:
  - mint the genesis at ADR-003's day-one floor (forward-only history, attributable, retention 0), giving `channel_id`;
  - double-lock a fresh SEK (ADR-010);
  - make the creator root admin;
  - start the creator's first sender chain;
  - append the genesis and the creator's governance entries;
  - publish the room's records (NR-23).
- **NR-17.** Opening a room MUST require the unlocked identity **and** the room passphrase. A node MUST retain a room's passphrase while the room is open, because answering a join needs it (ADR-005).
- **NR-17a.** A room's local name MUST live only in its sealed manifest, so a closed room is listed by id only.
- **NR-17b.** A text message's body MUST NOT exceed `MAX_TEXT_LEN` (64 KiB).
- **NR-17c.** An entry MUST be classified before it is stored: a struct-tagged governance frame is governance, a `vox/group-msg/v1` sender-key message is content, and anything else MUST be refused (`classify_payload`).

### Invite link

- **NR-18.** The invite link MUST be `vox://<channelID-base32>?a=<fp>&b=<multiaddr>[&b=…][&a=…&b=…][&r=<responder-fp>]`.
  - Each `b=` belongs to the `a=` before it, and there are at most `MAX_LINK_ANCHORS` (4) `a=` entries.
  - Digests MUST be lowercase unpadded RFC 4648 base32, accepted in either case.
  - An invite MUST name the room's anchors first, the configured anchors next, and the inviting node last.
- **NR-19.** The link MUST NOT carry the passphrase; it has no field for a secret. The joiner collects the passphrase at a masked prompt, and the passphrase travels out of band.
- **NR-20.** Parsing MUST be strict: an unknown key, a duplicate `r`, a `b=` before any `a=`, an anchor with no `b=`, too many anchors or addresses, or a non-canonical base32 tail MUST be refused.

### The rendezvous service and the member bundle record

- **NR-21 (M14.2).** Every node MUST serve the rendezvous service on its endpoint, on a typed `Rendezvous` stream: `PUT <record>` and `GET <channel_id, epoch, kinds>`, framed as u32-BE length-prefixed canonical CBOR, at most `MAX_RENDEZVOUS_FRAME`.
  - Every `PUT` MUST pass the `RendezvousStore` policy: members only through the room's membership oracle, the refresh floor `MIN_REFRESH_SECS`, `MAX_TTL_SECS`, bounded clock skew, and per-bucket caps.
  - A `PUT`'s author need not be the connection's peer, because a record is self-authenticating.
  - Any authenticated peer that knows the channelID MAY read.
  - A garbage frame MUST be reset with ADR-008 code `0x05`.
- **NR-22 (M14.1).** The record kinds MUST include:
  - the member address record (`0x0007`);
  - the pre-join record (`0x0008`);
  - the member bundle record (`0x0012`, `vox/member-bundle-record/v1`):
    - a member's root-signed `PrekeyBundlePublic`;
    - body `[author_id, channelID, epoch, prekey_bundle, seq, timestamp, ttl_secs, [sign_algo]]`;
    - default and maximum TTL 7 days (`BUNDLE_MAX_TTL_SECS`);
    - refreshed on rotation and at the one-time pool's low-water mark;
    - `verify` MUST bind `prekey_bundle.root_pub` to the resolved member key and check the bundle's own signatures, and `build` MUST refuse to sign a foreign bundle;
  - the room genesis (M14.7b).
- **NR-23.** A node MUST file its rooms' genesis, address record and bundle on its own board, and on every anchor it has (M14.7d, M14.7e). The served board MUST read membership from the actor's `SharedMembership` snapshot, and a stale snapshot MUST fail closed: a member missing from it is refused and retries, and is never wrongly admitted.
- **NR-23a.** The prekey ring MUST be loaded or created after `CreateIdentity` and after every `Unlock` (`load_or_create`), which applies the ADR-002 cadence. It MUST be dropped on lock (ADR-010).
- **NR-24 (M17.6).** A member MUST admit a key from a board only on an `Admission` the record carries: `Creator`, checked against the genesis, or a `JoinWitness` signed by a member it already admits.
- **NR-25 (M15.2a).** An anchor MAY admit a member's key by vouching: a bundle record published over an authenticated connection by a peer it already knows as a member of that room.
  - An address record MUST NOT precede its bundle.
  - A stranger MUST NOT vouch.
  - A vouched member MAY vouch in turn.
  - A member MUST NOT accept vouching.
  - An anchor that holds no room MUST admit the creator's records through the genesis on its board (`RendezvousService::known_key`).
- **NR-26.** When a member-kind record arrives from a peer and is admitted, the node MUST mirror that room to its anchors (`NetEvent::BoardGrew`). The cascade is bounded by the refresh floor: a re-put of a current record is declined.
  - When a node's board gains a bundle from an author it has not seen, it MUST push the room to its connected members at once (`note_new_members`). Only a new author triggers this push.
  - A sync MUST offer the peer the board records the peer lacks, bundles before addresses (`board_records_missing_from`).
- **NR-27.** A node MUST fetch and file a peer's board in every outbound session, so a restarted node relearns its rooms' members on its first sync. **Planned:** a node does not refetch its board at start-up; the in-process `RendezvousStore` is in memory.

### Join over the network

- **NR-28 (M15.1).** A join MUST be board-first:
  - dial the link's entries in order;
  - read the room from a board that holds it;
  - publish the pre-join record there before anything else;
  - reach the responder through the whole ADR-012 ladder;
  - publish on the responder's board;
  - run the ADR-005 exchange on a `join` stream.

  More rules:
  - The responder is the `r=` pin, else a member with an address record. The joiner MAY try up to `MAX_JOIN_RESPONDERS` (3).
  - The joiner MUST open with `WANT {channelID, epoch}`.
  - Routes MUST be tried in this order: the link's anchors, the configured anchors, any anchor already connected.
  - A board with no address record for the responder MUST be re-read until `JOIN_ADDRESS_PATIENCE` (20 s) runs out, not treated as unreachable at once.
  - Joining a room this node already holds MUST update the room's stored address (and anchors) from the new link. **Planned:** decider ruling of 2026-10-03; not built on this tree.
- **NR-28a.** An identity with no live pre-join record MUST be classed `Unknown`, and MUST reach the board and nothing else.
- **NR-29.** The joiner side of a join MUST run off the actor (V29-08).
- **NR-30.** Joining grants log authorship only.
  - Every member MUST deliver its sender key to a newcomer only when its own user consents (ADR-007).
  - An admitted author's entries MUST NOT render until both gates hold: the key is held and the author has consented.
  - When a sender key arrives, every stored entry from that author MUST be retried (backfill).
  - There MUST be no lobby step for a member to approve a join.
- **NR-31.** As part of joining, the newcomer MUST open its session with `PairwiseFrame::Open` (an empty sealed message) and MUST NOT release its sender key; a key is released only to members its owner trusts (ADR-007 G-15 step 2, M17.6). Between the exchange and `JoinerDone`, a joiner MUST classify its responder as `JoinResponder`, which MAY open `pairwise`.
- **NR-31a.** The join stream MUST give one opaque refusal reason. The responder MUST consume and persist the one-time prekey before the handshake completes.

#### Answering a join runs off the actor

- **NR-32.** Answering a join MUST run off the actor.
  - The actor decides admissibility and takes a slot, and the outcome returns as `NetEvent::JoinAnswered`.
  - Past `JOINS_IN_FLIGHT` (16) a join MUST be refused, not queued, and the refusal MUST be sent.
  - The PoW difficulty MUST adapt to the live slot count.
  - The prekey ring MUST be taken only at the two points the exchange needs it.

### Connections, reachability and sync

- **NR-33.** The node MUST keep one preferred `VoxConnection` per peer fingerprint, whichever side dialled.
  - A better connection MUST retire the old one with a grace, not close it, wherever a caller reads it.
  - The tick MUST close retired connections whose grace is over.
  - A displaced connection still carrying a stream MUST NOT be closed at the grace's end (RP-26).
- **NR-34.** Admission at the transport MUST stay open: a connection is admitted on its authenticated identity alone (ADR-011, its accept loop). Authorization MUST be by stream kind against `PeerPolicy`: member, anchor, pending joiner, join responder, unknown.
  - Authorization MUST be evaluated when a stream arrives.
  - When the policy has no answer, `NodeNet::classify` MUST consult the board.
  - A session relayed by the node's own anchor MAY be accepted whoever the far peer is (`coordstream::accepts_relayed`).
- **NR-35.** Streams MUST be typed by their first frame (ADR-011, typed streams): `sync` 1, `join` 2, `pairwise` 3, `rendezvous` 4, `tunnel` 5, `coord` 6, `circuit` 7, `goodbye` 8, `app` 9. A `sync`, `join` or `pairwise` stream MUST name its room.
- **NR-36 (M14.8–M14.10, M15.1b, V210-122).** `NodeNet::reach` MUST climb the whole ADR-012 ladder: a live connection, a direct dial, a hole punch over a coordinator's `coord` stream, then a relayed circuit.
  - It MUST race the rungs and adopt whichever lands first.
  - A pair that can only be relayed MUST take its relay circuit at once. A dial-back MAY race the circuit, and MUST NOT hold it or delay it. **Planned:** decider ruling of 2026-10-03. On this tree a circuit still waits `DIRECT_HEAD_START` (500 ms, `node/network.rs:108`) and, after a join, the dial-back (V030-27, 17b262ed).
  - A pair that is not relay-only MAY give a direct path up to `DIRECT_HEAD_START` before asking a relay, and MUST yield to a direct path that lands in that time.
  - A relayed connection MUST then try to upgrade (`NetEvent::BetterPath`).
  - Candidates the socket cannot address MUST be dropped before dialling.
  - A hole punch MAY be coordinated by any connected peer that will relay signalling. An inbound punch MUST be answered on its own task.
  - Every connection MUST ask its peer, on its own task, what address it is seen at.
  - A relay MUST forward only QUIC packets it cannot read, bounded by `MAX_RELAYED_CIRCUITS`, by `MAX_CIRCUITS_PER_ASKER` and by `CIRCUIT_IDLE_TIMEOUT`.
- **NR-37 (M14.8a, M14.8b, M15.1c).** What a node advertises MUST come from the ladder's publish side, not from its bind address: routable addresses (both families, IPv6 first), a gateway mapping by PCP, NAT-PMP or UPnP-IGD, and loopback last.
  - Discovery MUST run off the unlock path.
  - Records MUST be republished when discovery completes.
  - Mappings MUST be renewed at half the shortest granted lifetime.
  - A mapping a router grants only permanently MUST NOT be renewed, and MUST be deleted when the network stops.
  - `--listen` MUST default to the wildcard.
- **NR-38.** Configured anchors (`--anchor <fp>@<multiaddr>`, repeatable, or `VOX_ANCHORS`, comma-separated) MUST be dialled pinned when the network starts, adopted as `Anchor`, and given every open room's records.
  - Anchors MUST be redialled from the tick (`ANCHOR_REDIAL_SECS`).
  - The anchors a room was joined through MUST be persisted with the room (`SEG_ANCHORS` = 4).
- **NR-39.** On an orderly stop, a node MUST close its relayed connections first, wait `RELAYED_CLOSE_LEAD` (50 ms), then close the rest.

### Sync scheduling

- **NR-40.** A node MUST start a frontier session for each shared room on a new connection, push within one tick of a local append, and sync every `SYNC_INTERVAL_SECS` (30) otherwise.
  - A session MUST NOT be awaited on the actor; it reports `NetEvent::SyncDone`.
  - A node MUST learn a room's current members from the board before syncing it.
- **NR-41.** A session for a room MUST run only with a peer that is an admitted author of that room or one of its anchors (ADR-008 §"Who is served", PRD-001 R5):
  - sessions it answers are checked after the stream-kind gate (V29-03);
  - sessions it starts are checked through `ensure_port` → `shares_room` → `may_sync` (V29-04).
- **NR-42.** Sessions MUST run on ports (ADR-025 D4, D6):
  - per `(room, peer)`, at most one outbound session and up to `INBOUND_PER_PORT` (3) inbound sessions;
  - at most `OUTBOUND_SLOTS` (16) outbound sessions at once;
  - at most `OUTBOUND_PER_PEER` (4) outbound sessions per peer.

  Sessions with different peers MAY run side by side, each taking the room's lock one protocol step at a time. What a push owes MUST be tracked per pair. An explicit consent's retry MUST ride the next `SyncDone` of a session with its target.
- **NR-43.** A sync frame MUST time out after `SYNC_FRAME_TIMEOUT` (20 s) in either direction.
  - A transport failure MUST be reported as `TransportFailed` (`0x09`), not as a version mismatch.
  - What a session applied MUST be kept even if the session then fails, with its coded reason preserved.
- **NR-44. Planned.** Range reconciliation is to be selected for a room with more than 100 authors (ADR-008). `should_use_range_mode` exists, but the runtime does not call it.

### The anchor

- **NR-45 (M15.2b, ADR-023 decision 6).** An anchor MUST NOT keep pages of a room it is not a member of. It serves the board (genesis, address and bundle records) and bridges hosts that cannot otherwise reach each other (ADR-012). Segment kind codes `AnchorLog=6` and `AnchorMeta=7` stay reserved and MUST NOT be reused.
  - After a restart, an anchor MUST republish the records on its board.
- **NR-45a.** `vox node` MUST print the `<fingerprint>@<multiaddr>` a client gives as `--anchor`. `NodeView::anchoring` MUST report only the rooms it serves and how many members it knows of each.
- **NR-46 (R45, M23.5).** An anchor started on a store written by an older release MUST delete the room pages it kept (`Store::delete_retired_anchor_pages`), with no migration and no copy kept. Proof: `crates/vox-tui/tests/an_upgraded_anchor_drops_the_pages_it_kept_proof.rs`.

### Reporting

- **NR-47.** When handling one command or inbound event exceeds `STALL_BUDGET`, the node MUST emit `NodeEvent::Stalled { what, millis }`, where `what` comes from an exhaustive match over both enums. A verb waiting on events MUST report each event that explains a failure, and MUST NOT discard it.

### Rotation and revocation

- **NR-48 (M18.1).** Every append MUST consult ADR-006's rotation bound.
  - A revocation MUST rotate, record the fact, and re-key the remaining consenters.
  - Retained origins (`SEG_ORIGINS` = 6) and the delivery ledger (`SEG_DELIVERED` = 7) MUST be sealed segments.
  - A re-key owed to an unreachable peer MUST be retried from the tick.
  - A re-key MUST travel over an ADR-004 pairwise session, opened from the member's bundle record when no join made one (`PairwiseFrame::Hello`, op `2`).

### Gates

- **NR-49.** Each milestone MUST be proven through the shipped binary, as a person uses it (ADR-018):
  - **M13:** a profile, a room, messages, lock, unlock and a restart;
  - **M14:** create, invite, join with the passphrase, consent, both ways, and an unconsented member reading nothing (`a_room_admits_the_passphrase_and_authors_decide_readers`), across processes (`cross_process_join_proof`);
  - **M15:** two members never online together converge through an anchor; a hole punch through the anchor's `coord` stream; `ssh` over Vox through `vox forward` (`service_rehearsal_proof`);
  - **M18.1:** a revoked member reads nothing after the rotation.

### Open defects and limits

These are known and not fixed. Each stays until it is fixed, with the fixing commit or proof cited.

| # | Defect or limit | Where | Tracked |
|---|---|---|---|
| D1 | An anchor tracks epoch 0 only, so an epoch change is not carried on its board. | `node/anchor.rs:123`, `:154` | #356 |
| D2 | Member→anchor sessions are proved on a relayed path on loopback only. Whether the `sync failed: transport` seen in the deleted `node_m15_anchor_gate` occurs behind real NATs is not measured. | — | untracked (see the V030-29 report) |
| D4 | ADR-008's golden-vector obligation is unmet, including for `0x0012`: no golden-vector test exists. | ADR-008 | open, awaiting the decider (V030-29 question 19) |
| L1 | A first `ssh` into a fresh room can wait up to `HOST_PATIENCE` (300 s). | `node/up.rs:214` | limit, by design |

Fixed since the old text, with evidence:
- A cross-process join through an anchor failing about half the time: `cross_process_join_proof` is back in the blocking gate (fb2f3618, V210-19, #192).
- Opening a stream had no deadline: `OPEN_STREAM_PATIENCE` (2afa020b).
- A failed join did not name the rung that refused: it prints its steps and what each responder said (79ece6f4, #192).
- Sessions this node starts were not checked: NR-41 (ce4a55f2, V29-04).
- Member→anchor sessions failing on a relayed path: measured working through the shipped binary on loopback, with a mutant that turns it red (a568ac2d, V210-139, #358).
- A member that restarts under the same identity was refused as the same pair while its old session waited: the newcomer's first connection now closes every connection to the old process (`ConnectionManager::file_inner`, V210-57), measured 12 of 12 under 0.15 s (a568ac2d, V210-139, #358).

## Consequences

- Every layer composes without a new cryptographic mechanism.
- The node is a large stateful actor, so its correctness rests on the shipped-binary proofs.
- Anchors see room metadata (who publishes when), which ADR-001 already accepts.
- No DHT: cold start uses the link's addresses, and an always-on node is needed only to bridge hosts that cannot otherwise reach each other (ADR-012).

## Related ADRs

Depends on ADR-001, ADR-002, ADR-003, ADR-004, ADR-005, ADR-006, ADR-007, ADR-008, ADR-010, ADR-011, ADR-012, ADR-013, ADR-015, ADR-025. Enables ADR-014, ADR-017, ADR-020, ADR-023.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
