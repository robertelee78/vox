# ADR-008: Replicated Authenticated Log and Sync

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted. Built on integrate/v0.3.0 (`crates/vox-core/src/log/`,
`crates/vox-core/src/node/syncstream.rs`, `crates/vox-core/src/wire.rs`), except where a
requirement says otherwise. Not built: range reconciliation over the network (LS-27), the personal
self-channel's runtime (LS-43), and recording a fork proof as a room entry (LS-35). The golden-vector
obligation (LS-20) is unmet.
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: log, merkle-dag, crdt, sync, anti-entropy, render-gating

## Context

Vox carries asynchronous and interactive messaging over one replicated, authenticated message store
(ADR-001). The store has to replicate ciphertext a node cannot decrypt without rendering it, keep
integrity and causal order, let retention drop bodies (ADR-010, ADR-023), and carry governance state
consistently under partition. The integrity wanted is blockchain-like, from the right primitive, not a
consensus blockchain. Messaging needs per-feed integrity and a causal merge, which a
CRDT-style DAG gives with strong eventual consistency and availability under partition, with no
consensus (shown for the Matrix Event Graph, arXiv 2011.06488). That result assumes
honest-but-unreliable replicas. Resistance to adversarial authors (equivocation, Sybil, withholding)
comes from per-author signatures, membership (ADR-007) and the fork handling below, not from the DAG.

## Requirements

### Decision: per-author logs merged into a Merkle-DAG

- **LS-1.** Each identity MUST own, per room, a single-writer, append-only, hash-linked log (Secure
  Scuttlebutt / Hypercore style). The logs of a room's authors MUST merge into a causally ordered
  Merkle-DAG.
- **LS-2.** Vox MUST NOT use a consensus blockchain: no mining, no proof of work or stake for
  ordering, no agreed global order. The room's order (LS-11) is computed from the entry set, never
  agreed.
- **LS-3. Render-gating = replicate-all, decrypt-what-you-can.** Ciphertext MUST replicate to every
  member that syncs the room, whoever can read it. A node MUST attempt decryption and render an entry
  only when decryption succeeds. Trust decides which keys a node holds (ADR-006, ADR-007); the log
  replicates everything.

### Entry format

- **LS-4.** A log entry's signed skeleton MUST be the 12-element array `[author_id, seq, prev_hash,
  lipmaa_backlink, channelID, epoch, algo_ids, payload_hash, payload_len, end_of_feed_flag,
  claimed_ms, seen]`. `seq` MUST start at 1 and rise strictly per author. An entry in the earlier
  10-field shape MUST be refused at decode.
- **LS-5.** The authenticator MUST commit to `payload_hash`, not to the payload bytes, so that a
  node MAY drop a payload body (retention, ADR-010) while the signed, hash-linked skeleton stays
  verifiable.
- **LS-6.** `lipmaa_backlink` for `seq = n` MUST target the standard Bamboo `lipmaa(n)`. Every entry
  MUST carry both `prev_hash` (the `seq − 1` link) and the `lipmaa_backlink` hash. The format is
  specified here; Bamboo, Reed and Hypercore MUST NOT be runtime dependencies.
- **LS-7.** The signed body and the wire frame MUST share one encoder and one decoder of the
  skeleton's fields (`EntrySkeleton::encode_fields` / `decode_fields`).

### Per-entry-type authentication

- **LS-8.** Every entry, governance and content alike, MUST be root-composite-signed
  (Ed25519 + ML-DSA, ADR-003). Governance entries (genesis, admin delegations, consent grants and
  revocations, policy updates) MUST also keep their payloads.
- **LS-9.** The entry wire's authenticator type MUST be `1` (composite) or `0` ("dropped under a
  checkpoint", an empty byte string, LS-38). Every other value MUST be refused. Type `2`, the ADR-009
  deniable authenticator, is removed with deniable mode (PRD-001 R43, ADR-009 withdrawn) and MUST be
  refused.

### Cross-author edges and the one order

Amended 2026-09-24 by ADR-023 decision 1 (PRD-001 R13).

- **LS-10. `seen` and `claimed_ms`.**
  - `seen` MUST list the heads of *other* authors' feeds that the author had applied when it wrote
    the entry: at most `MAX_SEEN` (16) 32-byte entry hashes, strictly ascending. A decoder MUST
    refuse an unsorted, duplicated or longer list before reading it.
  - A head the author already named, or an older entry of that feed, MUST be left out. When more
    than 16 feeds moved, the most recent by the order MUST be named and the rest wait for the next
    entry (`Dag::seen_for`).
  - `claimed_ms` MUST be the author's clock in milliseconds, the same value its content envelope
    carries.
  - Both MUST sit in the signed skeleton, so that a node places entries it cannot read (an author
    whose key it lacks, a pruned body). Anyone holding skeletons therefore sees the claimed send
    time, as they already see arrival time.
- **LS-11. The room's order.** Every node MUST order a room's entries by a hybrid logical clock
  over the DAG:
  `clock(e) = max(min(claimed_ms(e), latest(e) + MAX_LEAD_MS), latest(e) + 1)`,
  where `latest(e)` is the highest clock of the held parents (the author's own `seq − 1` and `seen`),
  or the room's genesis time for an entry with none, and `MAX_LEAD_MS` is ten minutes. Entries MUST
  sort ascending by `(clock, entry_hash)`.
  - The cap MUST be relative to the parents, never to the receiving node's clock.
  - The order MUST be a function of the entry set alone, so every node holding the same entries
    shows the same sequence.
- **LS-12.** A `seen` hash a node does not hold MUST NOT block acceptance. When it arrives, the
  clocks of what named it, and of their descendants, MUST be raised to what the full set requires,
  giving the same result as if everything had arrived in causal order.
- **LS-13.** `Dag::happened_before(a, b)` MUST be the causal relation (ancestor through feeds and
  `seen`). Claims stay in Vox: agent comms tracks who does what (ADR-020). A claim's order MAY use
  this relation. On this tree nothing consumes it. Vox MUST NOT lock a claim or enforce a takeover
  (PRD-001 R17).

### Canonical serialization

Normative for every ADR that signs a structure: log entries, SKDMs (ADR-006), certificates and
consent grants (ADR-007), rendezvous records (ADR-012), the transport identity extension (ADR-011).

- **LS-14.** Every signed or authenticated structure MUST be deterministic CBOR (RFC 8949 §4.2.1:
  definite lengths, shortest-form integers, map keys sorted bytewise), prefixed with a 2-byte
  struct-type tag and a 1-byte format version.
- **LS-15.** Each signed struct MUST be a definite-length CBOR array whose element order is exactly
  the field order listed for it (COSE-style, RFC 9052). Bytewise map-key sorting applies only to a
  CBOR map nested inside a payload.
- **LS-16.** A decoder MUST be strict. It MUST reject a non-shortest integer, an indefinite length,
  a reserved additional-info value, unsorted or duplicate map keys, and trailing bytes.
- **LS-17.** Integer fields (`seq`, `iteration`, `epoch`, `payload_len`) MUST be CBOR unsigned
  integers with no fixed width.
- **LS-18.** The authenticator MUST be computed over `domain_sep ‖ canonical_bytes`, where
  `domain_sep` is the struct's label (LS-21).
- **LS-19.** Every hash (`prev_hash`, `payload_hash`, CID per ADR-010) MUST be SHA-256 (ADR-003)
  over those canonical bytes.
- **LS-20. Golden vectors.** Every struct's field order MUST be pinned by golden vectors, and the
  frontier and Negentropy exchanges by interop bytes against a reference. *Status:* unmet. No golden
  vector exists on this tree, and the obligation awaits the decider.

### Struct-type tag registry

- **LS-21.** The 2-byte tag MUST identify the structure, so that the same canonical bytes are never
  read as another structure. Each tag MUST have exactly the label below as its `domain_sep`
  (`StructTag::domain_sep`); labels are pinned, not derived from struct names.

  | Tag | Struct | Label | Owner |
  |---|---|---|---|
  | `0x0001` | log-entry | `vox/log-entry/v1` | ADR-008 |
  | `0x0002` | SKDM | `vox/skdm/v1` | ADR-006 |
  | `0x0003` | admin/governance cert | `vox/admin-cert/v2` | ADR-007 |
  | `0x0004` | consent-grant | `vox/consent-grant/v1` | ADR-007 |
  | `0x0005` | consent-revocation | `vox/consent-revocation/v1` | ADR-007 |
  | `0x0006` | policy/passphrase-rotation | `vox/policy-rotation/v2` | ADR-007 |
  | `0x0007` | rendezvous-record | `vox/rendezvous-record/v2` | ADR-012 |
  | `0x0008` | pre-join-record | `vox/pre-join-record/v2` | ADR-012 |
  | `0x0009` | tls-identity-extension | `vox/tls-identity-extension/v1` | ADR-011 |
  | `0x000A` | chunk-manifest | `vox/chunk-manifest/v1` | ADR-020 §11.1 (reserved, not implemented) |
  | `0x000B` | dgka-setup (removed) | `vox/dgka-setup/v1` | ADR-009 |
  | `0x000C` | self-channel-entry | `vox/self-channel-entry/v1` | ADR-008 |
  | `0x000D` | genesis-record | `vox/genesis/v2` | ADR-007 |
  | `0x000E` | admin-delegation-revocation | `vox/admin-delegation-revocation/v1` | ADR-007 |
  | `0x000F` | service-advertisement | `vox/service-advertisement/v1` | ADR-013 |
  | `0x0010` | esk-publication (removed) | `vox/esk-publication/v1` | ADR-009 |
  | `0x0011` | session-establishment | `vox/session-establishment/v2` | ADR-011 |
  | `0x0012` | member-bundle-record | `vox/member-bundle-record/v2` | ADR-016 |
  | `0x0013` | service-grant-exclusion | `vox/service-grant-exclusion/v1` | ADR-007, ADR-017 |
  | `0x0014` | join-witness | `vox/join-witness/v2` | ADR-016 M17.6 |
  | `0x0015` | presence | `vox/presence/v1` | V210-164 (`governance/presence.rs`) |
  | `0x0016` | checkpoint | `vox/checkpoint/v1` | ADR-023 decision 3 (`log/checkpoint.rs`) |
  | `0x0017` | key-package | `vox/key-package/v1` | ADR-023 decision 4 (`node/keypackage.rs`) |
  | `0x0018` | service-share | `vox/service-share/v1` | ADR-017 decision 12 (`governance/share.rs`) |
  | `0x0019` | room-lifecycle | `vox/room-lifecycle/v2` | ADR-023 RL-8 (`governance/lifecycle.rs`) |
  | `0x001A` | board-withdraw | `vox/board-withdraw/v2` | ADR-023 RL-8 (`nat/withdraw.rs`) |
  | `0x001B` | admin-roster | `vox/admin-roster/v1` | ADR-023 RL-8 (`nat/withdraw.rs`) |
  | `0x001C` | identity ask | — (never signed) | ADR-011 req 28 (ADR-026; decided, not built on this tree) |
  | `0x001D` | identity prove | `vox-id/v2/resp` | ADR-011 req 28 (ADR-026; decided, not built on this tree) |
  | `0x001E` | identity claim | `vox-id/v2/init` | ADR-011 req 28 (ADR-026; decided, not built on this tree) |

- **LS-21a.** A struct that carries a time MUST carry it in milliseconds, at format version 2 (the
  frame's version byte) under its `/v2` label (#562). A board record, pre-join, join witness or board
  withdraw at format 1 MUST be refused with the reason that it is from a Vox whose times were seconds; a
  logged struct at format 1 is read as ADR-007 G-1a says.
- **LS-22.** New struct types MUST be appended, versioned, and a tag MUST NOT be reused. `0x000B`
  and `0x0010` belong to removed deniable mode: they stay registered and MUST NOT be produced.
  `0x0006` carries only a room's retention; policy updates beyond retention and passphrase rotation
  are removed (ADR-007 G-6).
- **LS-23.** This tag space is disjoint from the ADR-003 ciphersuite-ID space. The two never
  co-occur on the wire, so a numeric overlap (`0x0001` here and there) is not a collision.

### Sync = anti-entropy

- **LS-24. Frames.** Every sync frame MUST be canonical CBOR prefixed by a 1-byte frame ID:
  `0x01 HELLO {mode_bitmap}`, `0x02 HAVE {feeds: [(author_id, max_seq, head_hash)]}`,
  `0x03 WANT {ranges: [(author_id, from_seq, to_seq)]}`, `0x04 ENTRY {entry, payload?}`,
  `0x05 NEG {negentropy_msg}`. An unknown frame ID MUST be rejected (`decode_frame`).
- **LS-25. The stream names its room.** A sync stream (ADR-016) MUST open with a preamble naming
  `(channelID, epoch)` before the first ADR-008 frame.
- **LS-26. Mode.** `HELLO`'s mode bitmap MUST use bit 0 for frontier and bit 1 for range
  reconciliation. Both peers MUST use the highest bit both set. Frontier mode MUST be supported by
  every peer.
- **LS-27. Range reconciliation.** Above about 100 active authors (`RANGE_MODE_AUTHOR_THRESHOLD`),
  where `HAVE` size dominates, peers that both set bit 1 MUST use range reconciliation. `NEG` MUST
  carry Negentropy v1 keyed by the full 32-byte SHA-256 entry hash, with no truncation. *Status:*
  planned. `range_reconcile_exchange` exists and nothing calls it; `should_use_range_mode` is never
  called; every session offers frontier only.
- **LS-28. Frontier mode.** `HAVE` MUST list the feeds a peer holds. The receiver MUST reply `WANT`
  with the missing ranges, asking from its own head (not past it) so that the peer's entry at that
  position is compared with its own (V210-63). The holder MUST stream `ENTRY` frames (skeleton and
  any retained payload) over a reliable QUIC stream (ADR-011).
- **LS-29. A `WANT` is bounded by what is held (PRD-001 R4).** The holder MUST trust nothing in a
  `WANT` for size: each author's ranges MUST be sorted and merged, and each merged range MUST walk
  only the entries actually held. One session MUST serve at most `MAX_SERVE_ENTRIES` (1,024) entries
  and `MAX_SERVE_BYTES` (64 MiB) within `SERVE_BUDGET` (30 s), and always at least one entry. A
  requester that applied entries MUST sync again at once for the rest. That bounds one session,
  never a history. Proof: `crates/vox-tui/tests/one_want_cannot_stop_a_room_proof.rs`.
- **LS-30. The drain phase.** The whole drain phase MUST be bounded by `DRAIN_BUDGET` (30 s), not
  only per frame. A non-entry frame during the drain MUST fail the session. **Known limit:** the
  deadline is checked when a frame arrives, so the real bound is 30 s plus one frame timeout.
- **LS-31. No lock across I/O.** A session MUST NOT hold the room's lock across a network wait. It
  MUST lock the room per protocol step and apply what it drained a batch at a time
  (`frontier_session_room`).
- **LS-32. Partial progress is kept.** Entries a session applied before it failed MUST stay stored.
- **LS-33. Bodies owed, not expired (V030-10, the decider 2026-10-01).** A skeleton whose signature
  verifies MUST be taken whether or not its body came with it. Whether a missing body is expired
  MUST be the receiver's own computation, from the entry's signed `claimed_ms` and the room's signed
  retention (or the receiver's shorter one, ADR-023 decision 2); nothing a peer says or omits makes
  a body expired. Otherwise the body is owed: the entry MUST be shown as "not received yet" and the
  body MUST be asked of every peer until one supplies it. A node MUST NOT ship a body it no longer
  holds; a peer asking for one gets the skeleton. *Status:* built (`ChannelState::shown_timeline`);
  V030-10 (#276) awaits acceptance.

### Who is served

PRD-001 R5.

- **LS-34.** A node MUST serve a room's log only to that room's admitted authors and to that room's
  anchors, for sessions it answers (V29-03) and sessions it starts (V29-04). The stream-kind gate
  (ADR-016) decides only whether a peer may open a `sync` stream. The room named in the preamble
  MUST then be checked against the peer, after the node admits authors from its own board's bundle
  records. A refusal MUST be the same coded reset as a stream kind the peer may not open. An anchor
  keeps no copy of a room it is not a member of and refuses every session for it (ADR-023
  decision 6). Proof: `crates/vox-tui/tests/a_member_of_one_room_is_not_served_another_proof.rs`.

### Fork / equivocation handling

- **LS-35.** Two validly signed entries at the same `(author_id, seq)` with different hashes are a
  self-authenticating fork proof. Because every entry is signed (LS-8), a fork proof always
  incriminates its author. On a fork proof a node MUST:
  - freeze that author and refuse its later entries;
  - keep the proof durably, and re-verify it when the room opens (`SEG_FORKS`,
    `Dag::restore_fork`);
  - surface it in `vox status --json` (`equivocations`), in `vox room read`, and in the TUI's notice
    line, in these words: "<name> signed two different messages at the same place in this
    room (their message <seq>). Their later messages are held back."
  - record the proof as a room entry. *Status:* planned; no entry type exists.

  Members exclude an equivocator by withdrawing trust (ADR-007).
- **LS-36.** A fork MUST be detected wherever two histories part, not only at equal heads: when the
  peer's history is shorter, its head MUST be compared with this node's entry at that `seq` (V210-63).
  Proof: `crates/vox-tui/tests/an_equivocation_is_detected_and_said_proof.rs`.
- **LS-37. Acceptance order (`Dag::accept`).** Frozen-author refusal → duplicate → admission →
  authenticator and structure verification → equivocation → feed link. Equivocation MUST be
  classified only for an entry that is admitted and verifies, so that a peer holding no valid key
  cannot raise a fork proof. An entry at or below its author's checkpoint that is not already held
  MUST be refused as `Rejected::PreCheckpoint`, never as a fork, and a session MUST continue past it.
- **Partition limit.** During a partition an equivocator can present different heads to disjoint
  partitions. This cannot be prevented without consensus, but it is permanently detectable and
  attributable on heal. Admin grants and revocations made during a partition MUST be treated as
  provisional until their causal neighbourhood reconciles (ADR-007).

### Checkpoints and shed signatures

ADR-023 decision 3 (M23.6).

- **LS-38.** Authenticator type `0` ("dropped under a checkpoint") MUST carry an empty byte string.
- **LS-39.** Struct tag `0x0016` is an author's checkpoint on its own feed, `[seq, entry_hash]`,
  carried as the payload of an ordinary signed entry of that feed.
- **LS-40. What `Dag::accept` does with them.**
  - An unsigned entry MUST be taken only body-less and only provisionally. It becomes authentic when
    a signed entry of the same feed chains to it. `Dag::discard_unverified` MUST take back whatever
    never does, at the end of every sync session and of every reload. A reload that finds one MUST
    refuse the store.
  - A checkpoint that names a position its own feed does not hold, with that hash, MUST be refused.
- **LS-41. Shedding.** A node MUST shed signatures only as ADR-023 decision 3 allows
  (`Dag::drop_checkpointed_signatures`, `drop_signature_if_checkpointed`).
  `Feed::verify_all_signatures` MUST accept an unsigned run only when a signed entry follows it.

### Abuse resistance

- **LS-42.** There is no membership roster or admission gate (ADR-007). An entry MUST be accepted
  only if:
  - (a) its author completed the authenticated room join (CPace, ADR-005) for the current
    `(channelID, epoch)` and is admitted on that evidence;
  - (b) it carries a valid composite signature (LS-8);
  - (c) it links into its author's feed (`seq`, `prev_hash`, skip link, no fork).

  An entry from an author this node has not admitted MUST NOT be stored; in a node's session it is
  counted and skipped, and the session goes on (`EntryClass::Unadmitted`). A member SHOULD admit the
  room's current members from the board (ADR-012) before it syncs.
- **No rate or volume limit (PRD-001 R1/R3, decided 2026-09-24).** A node MUST NOT limit the rate
  or volume of an admitted author's entries. The per-author quota (1,000 entries/hour, 50 MiB/epoch)
  is removed, and wire code `0x06` stays reserved (LS-45). Proof:
  `crates/vox-tui/tests/a_long_room_reopens_proof.rs`.
- **Known limit, render-gating amplification.** Every ciphertext replicates to every member (LS-3),
  so an admitted member can make every member store as much as it writes. This ADR does not bound
  it. The remedy for a member who abuses it is membership: withdraw trust (ADR-007). Agent loop
  control is out of scope (PRD-001 R3).
- Pruning is authenticated: a body MAY be dropped by retention, but its signed skeleton MUST remain,
  so pruning cannot silently rewrite history.

### Consent and governance state

- Admin and policy certificates, consent grants and consent revocations MUST be log entries, so
  they replicate and converge causally (ADR-007). Membership is emergent from join and consent;
  there MUST NOT be a membership-roster certificate.

### Personal self-channel

- **LS-43.** A user's shared-root devices (ADR-002) share state through a single-author self-log,
  keyed by a dedicated random 256-bit `self_seed` generated at identity creation, kept in the
  identity vault and the encrypted backup:
  - `K_self = HKDF-SHA-256(self_seed, info = "vox/self-channel/v1")`;
  - `rendezvous_self = HKDF-SHA-256(self_seed, info = "vox/self-rzv/v1")` (the ADR-005
    construction, seeded by the private `self_seed`).

  Both MUST derive from the private seed, never from a signature over a public constant and never
  from the public identity key. The self-log MUST be replicated only among that identity's own
  devices, each proving possession by the ADR-005 PoP. It carries nicknames and verification state,
  the SKDMs consent-granted to the identity (ADR-006), and per-room join material, so that adding or
  restoring a shared-root device needs no re-consent. Per-device-key users hold no self-channel.
  *Status:* planned. The KDFs, `self_channel_id` (`vox/self-channel-id/v1`, not named above) and the
  self-log type exist in `log/selfchannel.rs`; nothing in the node calls them, and `K_self` is never
  applied.

### Abort / error signalling

- **LS-44.** Every hard failure in the wire ADRs (a floor violation, ADR-003; an unknown struct tag
  or algorithm ID; a sync-mode mismatch; an authenticator failure) MUST be surfaced, never silently
  downgraded, by closing the QUIC stream or connection with a Vox application error code. The peer
  MUST log the coded reason and surface it (ADR-014). This is the single wire-error contract that
  ADR-003 and ADR-011 cite.
- **LS-45.** The codes (`WireError`):

  | Code | Meaning |
  |---|---|
  | `0x01` | protocol version unsupported (a frame that decodes to an unsupported version) |
  | `0x02` | suite below floor (ADR-003) |
  | `0x03` | unknown struct tag |
  | `0x04` | unknown algorithm ID |
  | `0x05` | authenticator invalid |
  | `0x06` | reserved: was quota exceeded; MUST NOT be reused |
  | `0x07` | sync mode unsupported |
  | `0x08` | epoch mismatch |
  | `0x09` | transport failed: a failed send or receive, or end of stream where a frame was due |
  | `0x0A` | unresponsive: an unanswered liveness probe or `SILENCE_IS_DEATH` (ADR-012) |
  | `0x0B` | session busy (ADR-025) |
  | `0x0C` | not yet a member, sent only to a pending joiner (#217) |
  | `0x0D` | shutting down (V210-93) |
  | `0x0E` | superseded duplicate connection (V210-93) |

## Known gaps

- Range reconciliation is not wired to the network (LS-27).
- A fork proof is kept in the node's own store, not recorded as a room entry (LS-35).
- The self-channel has no runtime (LS-43).
- No golden vectors or interop bytes exist (LS-20).
- The drain bound is 30 s plus one frame timeout (LS-30).

## Consequences

- Asynchronous and interactive messaging come from one replicated structure; an offline node heals
  on reconnect.
- Render-gating makes trust and storage compose with no extra mechanism; the cost is that a node
  stores and carries ciphertext it cannot read.
- Payload-hash signing reconciles append-only integrity with retention pruning and large post-quantum
  signatures (ADR-003).
- Every node shows one order, derived from the causal DAG with no coordination; concurrent entries
  are ordered by a tie-break, not by agreement.
- DAG convergence is proven for non-adversarial replicas; Sybil and withholding resistance comes from
  signatures and membership (ADR-002, ADR-007).
- Vox sits alongside SSB, Hypercore, Berty and the Matrix event DAG; its difference is the trust and
  cryptography layered on top.

## Related ADRs

Depends on ADR-002 (identity) and ADR-006 (sender keys). Used by ADR-007 (governance), ADR-010
(at-rest storage and retention), ADR-011 (transport), ADR-012 (rendezvous records), ADR-016 (sync
scheduling), ADR-020 (agent comms), ADR-023 (one order, checkpoints, key packages) and ADR-025 (sync
ports). ADR-009 (deniability) is withdrawn.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
