# ADR-016: Node Runtime — Composing the Core

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: accepted. M13, M14, M15, M15.1–M15.2c and M18.1 are built in `crates/vox-core/src/node/` and proven through the shipped `vox` binary in `crates/vox-tui/tests/`. Requirements marked **planned** are not built.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: runtime, node, integration, persistence, rendezvous, sync, headless

## Context

Identity (ADR-002), the pairwise channel (004), join (005), sender keys (006), governance (007), the log and sync (008), at-rest storage (010), transport (011), NAT traversal (012) and tunnelling (013) are each specified in their own ADR. This ADR specifies the node that composes them into one process a person runs: what it owns, how it stores, how a room is created and joined over the network, how it connects, syncs and anchors, and how it reports what it is doing.

Decided by the decider on 2026-09-19: the persistence engine is **redb**; member prekey bundles are a **new rendezvous record kind**; the invite link **never carries the passphrase**; delivery is **single-device first, network second**. Carried from ADR-014 and ADR-015: **the client embeds the node**, and **a headless node is ciphertext-only**.

## Requirements

### The `Node`

- **NR-1.** `vox_core::node::Node` MUST be a single asynchronous actor. It owns the unlocked identity, every open room's SEK, the log DAGs, the governance evaluators, the pairwise sessions, the sender and receiver chains, and the store handle. It MUST be the single writer of every DAG and of the store.
- **NR-2.** Everything outside the actor MUST talk to it through typed messages:
  - clients send `NodeCommand` and receive `NodeView` snapshots (latest wins) and ordered `NodeEvent`s;
  - network tasks hand it parsed, verified wire structures, and the actor makes every admission, acceptance and consent decision.

  `NodeView`, `NodeEvent` and `Outcome`/`Fault` MUST carry no keys, SKDMs, SEKs or `self_seed`. `Outcome` and `Fault` MUST be closed `Copy` types with no free text. A passphrase MUST enter as a zeroizing `Secret`.
- **NR-3.** The client MUST embed the node in its own process: the TUI runs it in-process (ADR-015), and the macOS client is to (ADR-014).
- **NR-4.** `vox node`, the headless node, MUST be constructed without a vault (`NodeConfig::headless`). It has a file-backed transport identity, rebuilt identically at every start, and no SEK, no sender keys and no pairwise sessions. The absence MUST be structural: the secret-bearing fields are `Option`s the headless constructor leaves `None`. A headless node MUST NOT be able to decrypt.
- **NR-5.** Commands MUST be processed in order, each answered on its own `oneshot`.

### Persistence: redb, sealed segments, XDG layout

- **NR-6.** The store MUST be one `redb` file per profile (`store.redb`). The identity vault MUST be a separate file (`vault.cbor`), so a store can be discarded without touching identity.
- **NR-7.** The store's write API MUST accept only sealed segments and SEK wraps (ADR-010); it MUST NOT be handed plaintext or a raw key.
  - Segments are keyed by `(channel_id, kind_code, segment_id)`. Kind codes are part of the on-disk key and MUST NOT be reordered: `LogDb=1`, `PlaintextCache=2`, `Index=3`, `KeyMaterial=4`.
  - `meta` MUST hold public facts only: schema version, identity fingerprint, creation time.
  - A newer or unreadable schema MUST be `Error::Storage`, never a panic.
- **NR-8.** A log append, its plaintext row and its chain-state advance MUST commit in one write transaction. A dropped batch writes nothing. A failed commit MUST poison the room until it is reopened.
- **NR-9.** On open, the node MUST rebuild a room's DAG from its log segments through `Dag::accept`, and MUST accept a cache row only if its entry is in the DAG.
- **NR-10.** Paths MUST follow ADR-015's precedence: explicit, then `VOX_DATA_DIR`/`VOX_CONFIG_DIR`, then `XDG_*`, then the platform default. Data lives in `<data>/vox/<profile>/`. Files MUST be `0600` and directories `0700` (Unix). A profile name MUST be a single path component.
- **NR-11.** A profile holds one identity, and a second create MUST be refused. An existing profile MUST open locked. Unlock MUST refuse a vault whose identity disagrees with the store's recorded fingerprint.
- **NR-12. Planned.** The node is to reclaim space with `redb` compaction after pruning. `Profile::compact_store` exists, but nothing calls it.

### App-lock and signals

- **NR-13.** `Lock` MUST drop every SEK, the signer, the prekey ring and the pairwise and sender state, and close the network. A lock MUST be answered once it has settled (V210-94). The actor MUST keep answering other commands while it settles.
- **NR-14 (M15.2c).** A headless node MUST refuse `Lock`.
- **NR-15.** `vox daemon`, `vox node` and every long-running verb MUST stop cleanly on SIGINT, SIGTERM, SIGHUP and SIGQUIT (V210-108).

### Channel lifecycle

- **NR-16.** Creating a room MUST:
  - mint the genesis at ADR-003's day-one floor, giving `channel_id`;
  - double-lock a fresh SEK (ADR-010);
  - make the creator root admin;
  - start the creator's first sender chain;
  - append the genesis and the creator's governance entries;
  - publish the room's records (NR-23).
- **NR-17.** Opening a room MUST require the unlocked identity **and** the room passphrase. A node MUST retain a room's passphrase while the room is open, because answering a join needs it (ADR-005).

### Invite link

- **NR-18.** The invite link MUST be `vox://<channelID-base32>?a=<fp>&b=<multiaddr>[&b=…][&a=…&b=…][&r=<responder-fp>]`.
  - Each `b=` belongs to the `a=` before it, and there are at most `MAX_LINK_ANCHORS` (4) `a=` entries.
  - Digests MUST be lowercase unpadded RFC 4648 base32, accepted in either case.
  - An invite MUST name the room's anchors first, the configured anchors next, and the inviting node last.
- **NR-19.** The link MUST NOT carry the passphrase; it has no field for a secret. The joiner collects the passphrase at a masked prompt, and the passphrase travels out of band.
- **NR-20.** Parsing MUST be strict: an unknown key, a duplicate `r`, a `b=` before any `a=`, an anchor with no `b=`, too many anchors or addresses, or a non-canonical base32 tail MUST be refused.

### The rendezvous service and the member bundle record

- **NR-21 (M14.2).** Every node MUST serve the rendezvous service on its endpoint, on a typed `Rendezvous` stream: `PUT <record>` and `GET <channel_id, epoch, kinds>`, framed as u32-BE length-prefixed canonical CBOR, at most `MAX_RENDEZVOUS_FRAME`. Every `PUT` MUST pass the `RendezvousStore` policy. Any authenticated peer that knows the channelID MAY read.
- **NR-22 (M14.1).** The record kinds MUST include:
  - the member address record (`0x0007`);
  - the pre-join record (`0x0008`);
  - the member bundle record (`0x0012`, `vox/member-bundle-record/v1`), a member's root-signed `PrekeyBundlePublic` with a default and maximum TTL of 7 days (`BUNDLE_MAX_TTL_SECS`), refreshed on rotation and at the one-time pool's low-water mark;
  - the room genesis (M14.7b).
- **NR-23.** A node MUST file its rooms' genesis, address record and bundle on its own board, and on every anchor it has (M14.7d, M14.7e).
- **NR-24 (M17.6).** A member MUST admit a key from a board only on an `Admission` the record carries: `Creator`, checked against the genesis, or a `JoinWitness` signed by a member it already admits.
- **NR-25 (M15.2a).** An anchor MAY admit a member's key by vouching: a bundle record published over an authenticated connection by a peer it already knows as a member of that room. A member MUST NOT accept vouching.
- **NR-26.** When a member-kind record arrives from a peer and is admitted, the node MUST mirror that room to its anchors (`NetEvent::BoardGrew`). When a node's board gains a bundle from an author it has not seen, it MUST push the room to its connected members at once (`note_new_members`). A sync MUST offer the peer the board records the peer lacks, bundles before addresses (`board_records_missing_from`).
- **NR-27. Planned.** A restarted node is to refetch its board: the in-process `RendezvousStore` is in memory, so until then a re-key owed to a member this process has not relearned stays owed.

### Join over the network

- **NR-28 (M15.1).** A join MUST be board-first:
  - dial the link's entries in order;
  - read the room from a board that holds it;
  - publish the pre-join record there before anything else;
  - reach the responder (the `r=` pin, else any member with an address record) through the whole ADR-012 ladder;
  - publish on the responder's board;
  - run the ADR-005 exchange on a `join` stream.

  The joiner MUST open with `WANT {channelID, epoch}`. Routes MUST be tried in this order: the link's anchors, the configured anchors, any anchor already connected. A board with no address record for the responder MUST be retried until a deadline, not treated as unreachable at once.
- **NR-29.** The joiner side of a join MUST run off the actor (V29-08).
- **NR-30.** Joining grants log authorship only. Every member MUST deliver its sender key to a newcomer only when its own user consents (ADR-007), and an admitted author's entries MUST NOT render until both gates hold: the key is held and the author has consented. There MUST be no lobby step for a member to approve a join.
- **NR-31.** The newcomer MUST broadcast its own sender key as part of joining, with a grant (ADR-007 step 2). Between the exchange and `JoinerDone`, a joiner MUST classify its responder as `JoinResponder`, which may open `pairwise`.

#### Answering a join runs off the actor

- **NR-32.** Answering a join MUST run off the actor.
  - The actor decides admissibility and takes a slot, and the outcome returns as `NetEvent::JoinAnswered`.
  - Past `JOINS_IN_FLIGHT` (16) a join MUST be refused, not queued, and the refusal MUST be sent.
  - The PoW difficulty MUST adapt to the live slot count.
  - The prekey ring MUST be taken only at the two points the exchange needs it.

### Connections, reachability and sync

- **NR-33.** The node MUST keep one preferred `VoxConnection` per peer fingerprint, whichever side dialled.
  - A better connection MUST retire the old one with a grace, not close it, wherever a caller reads it.
  - A displaced connection still carrying a stream MUST NOT be closed at the grace's end (RP-26).
- **NR-34.** Admission at the transport MUST stay open: a connection is admitted on its authenticated identity alone, and its handshake bounded as ADR-011 requirement 20 states. Authorization MUST be by stream kind against `PeerPolicy` (member, anchor, pending joiner, join responder, unknown).
  - Authorization MUST be evaluated when a stream arrives.
  - A session relayed by the node's own anchor MAY be accepted whoever the far peer is (`coordstream::accepts_relayed`).
- **NR-35.** Streams MUST be typed by their first frame (ADR-011 requirement 19): `sync`, `join`, `pairwise`, `rendezvous`, `tunnel`, `coord`. A `sync`, `join` or `pairwise` stream MUST name its room.
- **NR-36 (M14.8–M14.10, M15.1b).** `NodeNet::reach` MUST climb the whole ADR-012 ladder: a live connection, a direct dial, a hole punch over a coordinator's `coord` stream, then a relayed circuit. It MUST race the rungs and adopt whichever lands first. A relayed connection MUST then try to upgrade (`NetEvent::BetterPath`).
- **NR-37 (M14.8a, M14.8b, M15.1c).** A node MUST advertise what the ladder's publish side composes: routable addresses, both families with IPv6 first, a gateway mapping by PCP, NAT-PMP or UPnP-IGD, and loopback last. It MUST NOT advertise what it bound.
  - Discovery MUST run off the unlock path.
  - Records MUST be republished when it completes.
  - Mappings MUST be renewed at half the shortest granted lifetime.
- **NR-38.** Configured anchors MUST be dialled pinned when the network starts, adopted as `Anchor`, and given every open room's records. Anchors MUST be redialled from the tick (`ANCHOR_REDIAL_SECS`). The anchors a room was joined through MUST be persisted with the room (`SEG_ANCHORS`).
- **NR-39.** On an orderly stop, a node MUST close its relayed connections first, wait `RELAYED_CLOSE_LEAD` (50 ms), then close the rest.

### Sync scheduling

- **NR-40.** A node MUST start a frontier session for each shared room on a new connection, push within one tick of a local append, and sync every `SYNC_INTERVAL_SECS` (30) otherwise. A session MUST NOT be awaited on the actor; it reports `NetEvent::SyncDone`.
- **NR-41.** An inbound session for a room MUST be answered only for an admitted author of that room or one of its anchors (ADR-008 §"Who is served", PRD-001 R5). **Planned:** sessions this node starts are not checked the same way.
- **NR-42.** At most one session per `(room, peer)` pair MUST run at once. Sessions with different peers MAY run side by side, each taking the room's lock one protocol step at a time. What a push owes MUST be tracked per pair.
- **NR-43.** A sync frame MUST time out after `SYNC_FRAME_TIMEOUT` (20 s) in either direction. A transport failure MUST be reported as `TransportFailed` (`0x09`), not as a version mismatch.
- **NR-44. Planned.** Range reconciliation is to be selected for a room with more than 100 authors (ADR-008). `should_use_range_mode` exists, but the runtime does not call it.

### The anchor

- **NR-45 (M15.2b).** A node run as an anchor (`NodeConfig::anchor_logs(true)`, set by `vox node`) MUST keep a ciphertext log for every room whose genesis lands on its board.
  - The log holds the genesis, the vouched authors and the entries, with no SEK, no chains and no timeline.
  - The pages MUST be sealed under `HKDF(factor_id, "vox/anchor-log-sek/v1")`, in segment kinds `AnchorLog` and `AnchorMeta`.
  - An anchor MUST reconcile each room with its known members, and members MUST sync with their anchors.
- **NR-46. Planned.** ADR-023 decision 6 is to remove the anchor's log store.

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
  - **M14:** create, invite, join with the passphrase, consent, both ways, and an unconsented member reading nothing (`a_room_admits_the_passphrase_and_authors_decide_readers`);
  - **M15:** two members never online together converge through an anchor;
  - **M18.1:** a revoked member reads nothing after the rotation.

## Consequences

- Every layer composes without a new cryptographic mechanism.
- The node is a large stateful actor, so its correctness rests on the shipped-binary proofs.
- Anchors see room metadata (who publishes when), which ADR-001 already accepts.
- No DHT: cold start uses the link's addresses, and an always-on node is needed only to bridge hosts that cannot otherwise reach each other (ADR-012).

## Related ADRs

Depends on ADR-002, ADR-003, ADR-004, ADR-005, ADR-006, ADR-007, ADR-008, ADR-010, ADR-011, ADR-012, ADR-013, ADR-015. Enables ADR-014, ADR-017, ADR-020, ADR-023.
