# ADR-008: Replicated Authenticated Log and Sync

**Status**: implemented (M5, `crates/vox-core/src/log/`)
**Date**: 2026-06-19
**Updated**: 2026-09-19 — Implementation notes (M5) added; acceptance order fixed so equivocation is classified only after admission + authenticator verification; self-channel KDF errors propagate. 2026-09-20 — struct tag `0x0012` (member-bundle-record, ADR-016 M14.1) appended to the registry; the golden-vector range is now `0x0001–0x0012`; sync runs over QUIC with a real `kind_for` and a documented author-admission precondition (M14.6). 2026-09-24 — PRD-001 R5: a node answers a sync session for a room only from that room's members and anchors (§"Who is served"). 2026-09-24 — PRD-001 R1/R3: the per-author quota is **removed** (wire code `0x06` reserved). See §"Abuse resistance" and the 2026-09-24 Implementation note. 2026-09-24 — PRD-001 D2/R4: a `WANT` is served clamped to what is held, merged, and bounded per session (see the 2026-09-24 Implementation note).
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: log, merkle-dag, crdt, sync, anti-entropy, render-gating

## Context

Vox needs both asynchronous and interactive messaging with a replicated, authenticated message
store (ADR-001). The store must: replicate ciphertext a node cannot decrypt and simply not render
it (the data-side of per-sender consent, ADR-007); preserve integrity and causal ordering; support
both signed (attributable) and MAC-based (deniable) entries (ADR-009); honor admin TTL (ADR-010);
and carry consent + certificate state consistently under partition. The author described it as
"blockchain-like" but explicitly wants the *right* primitive, not a consensus blockchain.

## Decision

**Per-author hash-linked logs merged into a Merkle-DAG.** Each identity owns a single-writer,
append-only, hash-linked log (Secure Scuttlebutt / Hypercore style); logs merge across authors
into a causally-ordered Merkle-DAG (a CRDT for causal histories). This gives tamper-evidence and
*causal* (not total) ordering with Strong Eventual Consistency and availability under partition.

**Explicitly NOT a consensus blockchain.** A blockchain exists to impose a single global total
order among mutually-untrusting writers (PoW/PoS cost; BFT only n>3f). Messaging needs only
per-feed integrity + causal merge, which a CRDT-style DAG delivers with Strong Eventual Consistency
and availability under partition, with no consensus (proven for the Matrix Event Graph, arXiv
2011.06488). No mining, no global order. This convergence result assumes honest-but-unreliable
replicas; resistance to *adversarial* authors — equivocation, Sybil, withholding — comes from
per-author signatures, membership/consent (ADR-007), and the fork handling below, **not** from the
DAG alone (so no unqualified "n>f Byzantine" claim is made).

**Render-gating = replicate-all, decrypt-what-you-can.** Ciphertext replicates to all interested
members regardless of who can read it; a node attempts decryption and renders only on success.
This is exactly how per-sender consent (ADR-007) manifests in storage: consent decides which keys
you hold; the log replicates everything.

**Concrete entry format (Bamboo-derived, no external log dependency).** A Vox log entry is a signed
struct:
`{ author_id, seq (per-author, strictly monotonic from 1), prev_hash, lipmaa_backlink, channelID,
epoch, algo_ids, payload_hash, payload_len, end_of_feed_flag }`, authenticated **per entry type**
(see "Per-entry-type authentication" below): governance/control entries are *always* composite
Ed25519+ML-DSA root-signed (in every channel); message-content entries are composite-signed in
attributable channels and authenticated by the ADR-009 deniable authenticator in deniable channels.
The authenticator is computed over all preceding fields. Because the signature commits to the *payload hash*,
not the bytes, a peer can delete old payload bodies (honoring admin TTL, ADR-010) while the signed,
hash-linked skeleton stays fully verifiable; **lipmaa skip-links** give logarithmic-length
verification certificates for partial replication. This is the Bamboo design adapted to Vox's
composite-PQ signatures and `(channelID, epoch)` binding — specified directly here, not pulled from
an external library (Bamboo/Reed/Hypercore inform it but are not a runtime dependency).

**Canonical serialization (normative, series-wide — the one encoding every ADR signs over).** Every
signed/authenticated structure in Vox — log entries (here), SKDMs (ADR-006), certificates and consent
grants (ADR-007), rendezvous records (ADR-012), the transport identity extension (ADR-011) — is encoded
as **deterministic CBOR** (RFC 8949 §4.2.1: definite-length items, shortest-form integers, map keys
sorted bytewise), prefixed with a **2-byte struct-type tag** + **1-byte format version**. Each signed
struct is a **definite-length CBOR array** whose element order is exactly the field order listed for that
struct (COSE-style, RFC 9052) — arrays are unambiguously deterministic with no key-ordering question and
are smaller; the "map keys sorted bytewise" rule therefore applies only to a CBOR *map* nested inside a
payload, not to the signed skeleton. Every struct's field order is **normative** and pinned by golden
vectors. A conforming decoder is **strict**: it rejects any non-canonical encoding (non-shortest integer,
indefinite length, reserved additional-info, unsorted/duplicate map keys, trailing bytes), since a
malleable encoding would let two distinct byte strings verify under one signature. Integer
fields (`seq`, `iteration`, `epoch`, `payload_len`) are CBOR unsigned integers (no fixed width). The
authenticator is computed over `domain_sep ‖ canonical_bytes`, where `domain_sep` is a per-struct ASCII
label (e.g. `"vox/log-entry/v1"`). All hashes (`prev_hash`, `payload_hash`, CID = ADR-010) are
**SHA-256** (ADR-003 registry) over those canonical bytes. Two correct implementations therefore
produce **byte-identical** signed input — the precondition for signature verification, CID dedup, and
the byte-equality fork-proof below. The **`lipmaa_backlink`** for entry `seq = n` targets the standard
Bamboo `lipmaa(n)` (the largest certificate-pool predecessor of the form `(3^k − 1)/2`); every entry
carries both `prev_hash` (the seq−1 link) and the `lipmaa_backlink` hash.

**Struct-type tag registry (normative).** The 2-byte leading tag identifies the structure so the same
canonical bytes are never cross-interpreted (the serialization analogue of ADR-003's algorithm prefixes):

| Tag | Struct | Tag | Struct |
|---|---|---|---|
| `0x0001` | log-entry | `0x000A` | chunk-manifest (ADR-014) |
| `0x0002` | SKDM (ADR-006) | `0x000B` | dgka-setup (ADR-009) |
| `0x0003` | admin/governance cert (ADR-007) | `0x000C` | self-channel-entry |
| `0x0004` | consent-grant (ADR-007) | `0x000D` | genesis-record (ADR-007) |
| `0x0005` | consent-revocation (ADR-007) | `0x000E` | admin-delegation-revocation (ADR-007) |
| `0x0006` | policy/passphrase-rotation (ADR-007) | `0x000F` | service-advertisement (ADR-013) |
| `0x0007` | rendezvous-record (ADR-012) | `0x0010` | esk-publication (ADR-009) |
| `0x0008` | pre-join-record (ADR-012) | `0x0011` | session-establishment (ADR-011) |
| `0x0009` | tls-identity-extension (ADR-011) | `0x0012` | member-bundle-record (ADR-016) |

Each tag has an **explicit, normative** domain-separation label (the prefix of its signing input,
`domain_sep ‖ canonical_bytes`). The labels are pinned exactly — they are not mechanically derived from
the struct name, so two implementations cannot disagree on the bytes that get signed:

| Tag | Label | Tag | Label |
|---|---|---|---|
| `0x0001` | `vox/log-entry/v1` | `0x000A` | `vox/chunk-manifest/v1` |
| `0x0002` | `vox/skdm/v1` | `0x000B` | `vox/dgka-setup/v1` |
| `0x0003` | `vox/admin-cert/v1` | `0x000C` | `vox/self-channel-entry/v1` |
| `0x0004` | `vox/consent-grant/v1` | `0x000D` | `vox/genesis/v1` |
| `0x0005` | `vox/consent-revocation/v1` | `0x000E` | `vox/admin-delegation-revocation/v1` |
| `0x0006` | `vox/policy-rotation/v1` | `0x000F` | `vox/service-advertisement/v1` |
| `0x0007` | `vox/rendezvous-record/v1` | `0x0010` | `vox/esk-publication/v1` |
| `0x0008` | `vox/pre-join-record/v1` | `0x0011` | `vox/session-establishment/v1` |
| `0x0009` | `vox/tls-identity-extension/v1` | `0x0012` | `vox/member-bundle-record/v1` |

New struct types are appended here (versioned), preserving the single canonical encoding. (Note: this struct-tag space is **disjoint from**
the ADR-003 ciphersuite-ID space — `0x0001` here = `log-entry`, `0x0001` there = `vox-suite-1`; they
never co-occur on the wire, so the numeric overlap is not a collision.)

**Sync = anti-entropy (concrete frames).** All sync frames are canonical-CBOR (above), each prefixed by
a **1-byte frame ID**. Mode is negotiated by the opening `HELLO` frame's **mode bitmap** (bit 0 =
frontier, bit 1 = range-reconciliation); both peers use the highest bit both set.
- Frame IDs: `0x01 HELLO {mode_bitmap}`, `0x02 HAVE {feeds: [(author_id, max_seq, head_hash)]}`,
  `0x03 WANT {ranges: [(author_id, from_seq, to_seq)]}`, `0x04 ENTRY {entry, payload?}`,
  `0x05 NEG {negentropy_msg}` (range-reconciliation payload).
- **Frontier mode (default; required of every peer).** `HAVE` lists the feeds a peer holds; the receiver
  replies `WANT` with the missing `(author_id, from_seq..to_seq)` ranges; the holder streams `ENTRY`
  frames (skeleton + any retained payloads) over a reliable QUIC stream (ADR-011). A `WANT` is the
  peer's to write, so the holder trusts nothing in it for size: each author's ranges are merged and each
  merged range walks only the entries actually held, and one session serves at most `MAX_SERVE_ENTRIES`
  (1,024) entries / `MAX_SERVE_BYTES` (64 MiB) within `SERVE_BUDGET` (30 s). That bounds one session,
  never a history: a requester that applied entries syncs again at once and asks for the rest.
- **Who is served (normative, PRD-001 R5).** A node serves a room's log only to that room's
  **admitted authors** and to **that room's anchors**. The stream-kind gate (ADR-016) only decides
  whether a peer may open a `sync` stream at all; the room is named afterwards, in the stream's
  preamble, and must be checked against the peer. Built for sessions the node **answers** (V29-03) and
  for sessions it **starts** (V29-04): a fresh connection is pushed only the rooms the peer belongs to.
- **Range-reconciliation mode (used when both peers set bit 1; the default *above ~100 active authors*,
  where `HAVE` size dominates).** `NEG` frames carry Negentropy range-based set reconciliation over entry
  hashes (logarithmic rounds). The `NEG` body is **Negentropy v1** keyed by the **full 32-byte SHA-256
  entry hash** (no truncation), wrapped in the Vox `NEG` frame so the Vox wire contract is fully
  self-described here. Frontier is mandatory; range-reconciliation is an additional required capability
  for scale.

**Abort / error signalling (normative).** Every hard-fail in the wire ADRs (floor-violation, ADR-003;
unknown struct tag or algo ID; sync mode mismatch; signature/authenticator failure) is
surfaced — never silently downgraded — by **closing the QUIC stream (or connection) with a Vox
application error code**: `0x01` protocol-version-unsupported, `0x02` suite-below-floor (ADR-003),
`0x03` unknown-struct-tag, `0x04` unknown-algo-id, `0x05` authenticator-invalid, `0x06` **reserved**
(was quota-exceeded; the quota was removed 2026-09-24 and the code is never reused), `0x07` sync-mode-unsupported, `0x08` epoch-mismatch, `0x09` transport-failed (the peer went away or the
stream reset — nothing about the protocol was wrong; added 2026-09-20, see Implementation notes). The peer logs the coded reason and surfaces it
(ADR-014). This is the single wire-error contract referenced by ADR-003/ADR-011.

**Per-entry-type authentication (binding — resolves the deniable/governance split).** Authentication
is chosen by entry TYPE, not merely by channel mode:
- **Governance/control entries are ALWAYS root-composite-signed (Ed25519+ML-DSA), even in deniable
  channels:** genesis, admin delegations, consent grants, consent revocations,
  policy/passphrase-rotation updates, and the deniable-mode **DGKA/DSKE setup** entries (ADR-009 —
  participation is attributable; only message content is deniable). They must stay attributable — membership is attributable by design (ADR-001/ADR-009),
  and ADR-007's single-writer consent guarantee requires that a consent grant be unforgeably authored
  by its issuer. Non-negotiable in both modes.
- **Message-content entries:** attributable channels → root-composite-signed; deniable channels →
  authenticated by the ADR-009 deniable construction (content authorship forgeable by any member).
The hash-chain provides ordering and tamper-evidence regardless of the authenticator. Because
governance entries are always signed, the governance plane — and its fork-attribution — stays intact
even in deniable channels; only message-content authorship is deniable. The exact deniable
content authenticator and how it preserves per-author single-writer ordering are specified in ADR-009.

**Consent + governance state lives here.** Admin/policy certificates, consent grants, and consent
revocations are log entries, so they replicate and converge causally across the overlay (ADR-007).
(Membership is emergent from join + consent — there is no membership-roster cert; ADR-007.)

**Personal self-channel (multi-device state, including received consent).** A user's own shared-root
devices (ADR-002) share state through a **single-author self-log**: a log authored by the user's
identity, keyed by a **dedicated random `self_seed`** (256-bit, generated at identity creation, stored
in the identity vault and included in the encrypted identity backup, ADR-002; synced to a new device at
enrollment alongside the root). Both the encryption key and the rendezvous derive from this **private**
seed — never from a signature over a public constant (which a signing oracle could reproduce) and never
from the *public* identity key (which would make the rendezvous locatable by anyone who knows it):
`K_self = HKDF-SHA-256(self_seed, info="vox/self-channel/v1")` and
`rendezvous_self = HKDF-SHA-256(self_seed, info="vox/self-rzv/v1")` (the ADR-005 rendezvous construction,
seeded by the private `self_seed`). Replicated **only among that identity's own devices**; a device
proves possession via the ADR-005 PoP to peer. It carries: local
nicknames + verification state, and — load-bearing — **the SKDMs the identity has been consent-granted**
(ADR-006) and per-channel join material. Because consent binds to an *identity* (ADR-006), syncing
received SKDMs over the self-channel lets every shared-root device read what was consented to the
identity, so **adding or restoring a shared-root device needs no re-consent**. First-device→second-device
bootstrap: a new device is enrolled by presenting the identity key (out-of-band root sync, ADR-002),
then discovers siblings at `rendezvous_self`. Per-device-key users have no shared root, so they hold no
self-channel and their state is device-local (no special case). This is the sole spec of the
self-channel; ADR-014 only surfaces its results.

**Fork / equivocation handling.** A single-writer log must not fork; two distinct entries by the
same author at the same `seq` are an equivocation. Handling differs by authentication type (above),
because automated punishment is only safe when the conflicting entries are *attributable*:

- **Attributable entries (all governance entries always; all entries in attributable channels)** are
  root-composite-signed, so two validly-signed entries at the same `(author_id, seq)` with different
  hashes are a **self-authenticating fork proof** that genuinely incriminates that author. Anti-entropy
  gossips **signed log heads** `(author_id, seq, hash)`; on a fork proof clients **freeze that author**,
  record the proof as a channel entry, surface it in the UI (ADR-014), and members revoke consent /
  rotate to exclude the equivocator (ADR-007). Because governance is always attributable, the
  membership/admin plane always gets this strong remedy.
- **Deniable message-content entries** use a forgeable authenticator (ADR-009), so a "fork proof" does
  **NOT** incriminate a specific author — any member could mint a second entry at a victim's
  `(author_id, seq)`. Automated freeze/eviction is therefore **disabled** for deniable content forks
  (it would be a framing/DoS primitive). Instead a deniable-content fork raises a **non-attributable
  fork *alarm*** surfaced for manual, out-of-band resolution; the per-author ordering/anti-equivocation
  guarantee that still holds in deniable mode (without enabling framing) is specified in ADR-009.
- Honest partition limit: during a partition an equivocator can present different heads to disjoint
  partitions; this cannot be *prevented* without consensus, but for attributable entries it is
  **permanently detectable and attributable on heal** (the fork proof is durable). Partition-time
  authority actions (admin grant/revoke) are treated as *provisional* until their causal neighborhood
  reconciles (ADR-007).

**Abuse resistance.** There is no membership roster or admission gate (ADR-007); the log
acceptance predicate is instead **identity- and signature-bound**: an entry is accepted only if (a) it
is authored by an identity that completed the authenticated channel join (CPace, ADR-005) for the
current `(channelID, epoch)`, (b) it carries a valid per-author authenticator for its entry type
(governance → root composite signature; content → composite or ADR-009 deniable), and (c) it links
into that author's feed (seq, `prev_hash`, skip-link, no fork). Unauthenticated or wrong-epoch floods
therefore cannot enter.

**There is no rate or volume limit on an admitted author** (PRD-001 R1/R3, decided 2026-09-24). An
earlier revision bounded replication by per-author quotas — ≤ 1000 entries/hour and ≤ 50 MiB/epoch —
and that is withdrawn: invitees are trusted, agents in a room must not be throttled, and the quota as
built was also *wrong*, because it charged every stored entry again when a room was reopened, so a room
could not be opened at all once one author had written a thousand entries (PRD-001 D1). The
consequence is stated plainly: the **render-gating amplification** vector is not bounded by this ADR —
every ciphertext replicates to all members (§"Render-gating"), so an admitted member can make every
member store as much as it writes. The remedy for a member who abuses that is membership, not a quota:
revoke consent and rotate (ADR-007). Agent loop control is out of scope for now (PRD-001 R3).
Pruning is *authenticated*: a payload may be dropped per TTL, but its signed
skeleton entry remains, so pruning can never silently rewrite history.

## Consequences

### Positive
- Async + interactive both fall out of one replicated structure; offline nodes self-heal on reconnect.
- Render-gating makes consent and storage compose with zero friction.
- Payload-hash signing reconciles append-only integrity with TTL pruning and large PQ signatures (ADR-003).

### Negative
- Causal (not total) order means no global "one true sequence"; application must tolerate concurrency.
- DAG convergence is proven for non-adversarial replicas; Sybil/withholding resistance must come
  from signatures + membership (ADR-002, ADR-007), not the DAG alone.
- Ciphertext a node cannot read still consumes its storage/bandwidth (the cost of render-gating).
- **Build coupling with ADR-009:** the deniable-content fork branch here checks the authenticator that
  ADR-009 supplies, so 008's deniable path and ADR-009 are co-built (not 008-complete-then-009). The
  dependency graph stays acyclic (009 → 008); only the *build order* is coupled.

### Neutral
- Positions Vox alongside SSB / Hypercore / Berty / Matrix-event-DAG; differentiator remains the
  consent + crypto layered on top.

## Implementation notes (M5)

These record the concrete decisions made building this ADR (`crates/vox-core/src/log/`), so the spec and code stay in lockstep:

- **Acceptance order (`Dag::accept_with_deniable`).** governance-must-be-attributable → frozen-author
  refusal → duplicate → **admission → authenticator/structure verification → equivocation** → feed link.
  (The trailing quota step was removed 2026-09-24.) Equivocation is classified only for an entry that is admitted *and* authenticates, so an
  attributable fork proof is self-authenticating by construction (both entries verified under the
  author's root) and a deniable-content alarm is raised only by an entry the ADR-009 epoch verifier
  accepts. A conflicting entry from an unadmitted author, one whose composite signature does not verify,
  or a deniable one the verifier rejects (or with no verifier available) is rejected as
  `NotAdmitted` / `Verification` and never surfaces as a fork. *(2026-09-19 review, HIGH: classifying
  before verification let a peer holding no valid key raise fork proofs and alarms — a framing /
  attention-DoS primitive.)* `sync::apply_entry` still reports a genuine fork as the non-fatal
  `ApplyOutcome::Fork`; the forged case now closes the stream with wire error `0x05` like any other
  authenticator failure.
- **Self-channel KDFs have no zero-fill fallback.** `derive_k_self`, `derive_rendezvous_self` and
  `self_channel_id` return `Result`; the shared HKDF-Expand helper propagates the ceiling error
  (output > 255·32 bytes) and leaves the caller's buffer untouched instead of zero-filling it. The
  three fixed 32-byte outputs can never hit it, but the helper's contract is general and a test pins
  the oversize case. *(2026-09-19 review.)*
- **Known gaps (recorded 2026-09-19).** (1) Negentropy range reconciliation is implemented and tested
  in memory (`range_reconcile_exchange`) but never runs over a `Transport`: `frontier_session*` offer
  frontier mode only — the ~100-author range mode this ADR calls required at scale is unwired. (2) Only
  an equal-`max_seq` divergent head is pulled and proven as a fork; a fork below the remote's head
  surfaces as a `prev_hash` failure (wire error `0x05`), so "permanently detectable on heal" holds only
  for equal-length forks. (3) Fork proofs live in the in-memory `frozen` map; the ADR's "record the
  proof as a channel entry" has no entry type yet. (4) `AuthorResolver::kind_for` defaults to
  `Content` and nothing overrides it, so governance entries received via **sync** still get the content
  fork remedy — but the discriminator now exists: `node::channel::classify_payload` (2026-09-20, ADR-016
  M14.5) types an entry from its payload, which is self-describing and disjoint (a governance payload is a
  struct-tagged frame, a sender-key message is domain-prefixed `vox/group-msg/v1`, anything else is
  refused), and every entry the node accepts or reloads is classified that way. **Closed for sync
  (2026-09-20, M14.6):** `node::channel::ChannelAuthors` is the resolver a channel hands to a session, and
  its `kind_for` uses that discriminator, so a governance entry received via sync is classified as
  governance rather than given the content fork remedy. Only a *pruned* payload still falls back to
  `Content`, and governance entries must retain their payload, so that case is not governance.
- **Sync presupposes that every author has been admitted (recorded 2026-09-20, M14.6).** `apply_entry`
  turns an author the resolver cannot resolve into `WireError::AuthenticatorInvalid`, which is a **hard**
  failure that closes the session — correctly, since an unverifiable entry must not be stored. The
  operational consequence is worth stating plainly: a member must admit the channel's current members
  (whose full composite keys are on the ADR-012 board) *before* it can sync, or the first entry from an
  unadmitted author kills the session. A test pins this exact behaviour rather than papering over it, and
  `ChannelState::sync_over` persists everything that arrived **before** surfacing the coded failure, so a
  partial session still makes durable progress instead of leaving entries only in the in-memory DAG. (5) `K_self` is derived but never applied (the self-log test stores plaintext);
  `self_channel_id` (`vox/self-channel-id/v1`) is an addition not in the Decision. (6) Transport I/O
  errors map to `0x01`, which the M0 table defines as "version". (7) The authenticator type sits outside
  the signed skeleton and `algo_ids[0]` is pinned to the composite id even for deniable entries.
  Test-vector obligation: only the log-entry skeleton is byte-pinned; there is no golden canonical-CBOR
  suite for tags `0x0001–0x0012` and no frontier/Negentropy interop bytes against a reference.

- **A secret-free peer is a real peer (2026-09-20, ADR-016 M15.2b).** The engine's independence from
  plaintext is load-bearing, not incidental: an **anchor** that holds no key for a channel runs
  `frontier_session_peer` over that channel's log as either side, because the session verifies authorship
  and ordering and nothing else. `node::anchor::AnchorState` is that peer — genesis, vouched authors,
  entries — and it is what lets two members who are never online together converge.
- **A transport failure is not a protocol failure (2026-09-20, ADR-016 M15.2c).** Observed while gating
  the anchor: every transport failure inside a session was reported as
  `WireError::ProtocolVersionUnsupported`, because the engine mapped all send and receive errors onto that
  code — so a peer that simply closed its laptop was diagnosed as speaking the wrong version. The registry
  gains `0x09 TransportFailed` and the engine uses it for a failed send, a failed receive, and a clean
  end-of-stream where a frame was due (the peer hung up mid-session). Genuine version mismatches — a frame
  that decodes to an unsupported version — still map to `0x01`, which is what that code is for. The
  behaviour is unchanged (the session still hard-fails and the next pass succeeds); what changes is that
  the reason no longer lies, which matters because the ADR's own words are that a peer "logs the coded
  reason and surfaces it".

- **The drain phase is bounded in total, not only per frame (2026-09-23).** A session holds the
  room's lock for its whole length, so a peer sending one frame just inside the per-frame timeout,
  for ever, held that lock for ever — every other operation on the room stopped by one member at no
  cost to it. `DRAIN_BUDGET` bounds the whole phase at thirty seconds. The honest bound is thirty
  seconds *plus* one frame timeout, because the deadline is only checked when a frame arrives; the
  engine is synchronous over channel state and cannot be wrapped in a timeout from outside. The
  references separate the two for the same reason: go-libp2p's relay sets a per-stream timeout *and*
  an absolute `Duration` cap, and Tor reclaims a circuit on total idle.
- **A non-entry frame in the drain phase is now a protocol violation, not something to ignore
  (2026-09-23).** This phase is defined as entries only, and tolerating anything else is what made
  the hold above free: a non-entry frame costs the sender nothing, never reaches `apply_entry`, and
  so never touches the quota that then bounded the exchange (since removed). This is a **wire-visible behaviour
  change**, recorded as such: a sender that emits a non-entry frame mid-drain now has the session
  failed rather than the frame skipped. Unknown frame *ids* are still rejected separately by
  `decode_frame`, so this is not the RFC 9000 §12.4 "ignore what you do not know" case.
- **The root cause both of these bound rather than fix (2026-09-23).** A sync runs with the channel's
  lock held, so every network wait inside it is a wait the rest of the node serves behind. A naive
  three-second bound on the *publish* path was written and **withdrawn before landing** for exactly
  this reason: publishing also takes that lock, so a budget shorter than a sync's lock-hold would
  have dropped records systematically whenever a sync was in flight — trading a visible stall for a
  silent loss. The fix is for the exchange not to hold the lock across network waits, which is a
  change to this ADR's implementation and not to a constant.

- **An answered sync is bound to the room (2026-09-24, PRD-001 D5/R5).** `run_sync_session`
  received the peer's identity and discarded it, so any member of any room this node held could name
  another room's channel id in the preamble and be served its log. It now refuses — with the same coded
  reset as a stream kind the peer may not open — unless the peer is an admitted author of *that* room
  or in *that* room's anchor set (`ChannelState::anchors`: the node's configured anchors and those the
  room's link named); for a room the node only anchors, an author its board knows. Before refusing, the
  node admits from its own board's bundle records (the M17.6 evidence, as everywhere), so a member who
  joined through somebody else is not refused for being new. The check is one early return below the
  in-flight (`syncing`) refusal.
  **Gate** (`crates/vox-tui/tests/a_member_of_one_room_is_not_served_another_proof.rs`, release, `--ignored`, since V29-17/RP-29 driving the **shipped `vox daemon`** as the victim; v0.2.8 leaks 25 of bravo's entries to it, `f5a1fe8` none):
  the victim holds rooms A and B; a member of A only, using its own identity over a real connection, is
  served all 5 of A's entries (the control) and asks for B five times — 0 sessions answered, 0 entries;
  a member of B still holds all 5 of B's. On 0844943 it is red: 25 of B's entries over 5 answered
  sessions; with the check removed, the same.
  **The outbound direction is closed too (V29-04):** a session this node *starts* pushes a room only
  to that room's members (admitted from the board first, as above) and to this node's own anchors,
  and an anchor forwards a kept room only to its authors. Before, a fresh connection was pushed every
  open room. Gate: the same file, step 4 — the victim's own push, answered by a member of A only:
  1 session and 5 of B's entries before; 0 and 0 after, with A's 5 still pushed (the control).
- **The per-author quota is removed (2026-09-24, PRD-001 D1/R1/R3).** `log/quota.rs` is deleted, both
  its limits with it: the 1,000-entries-per-hour rate *and* the 50 MiB-per-epoch byte total, because the
  byte total was a cumulative per-author cap on history within an epoch — a lifetime limit, which R1
  forbids. `Dag::accept` no longer takes a clock. `WireError::QuotaExceeded` is gone and `0x06` is
  reserved: `from_code(0x06)` is `None`, like any unknown code. The defect it closes was worse than
  throttling: replaying a room's stored log on open charged every entry to the quota in one burst, so a
  room with more than a thousand entries from one author failed to open, and the 1,001st post was
  refused outright.
  **Gates** (release, `--ignored`): `crates/vox-tui/tests/a_long_room_reopens_proof.rs` drives the
  shipped `vox` binary — 1,500 `vox room post`s from one author all succeed, the daemon is killed and
  restarted and the room opens with all 1,500 rows readable, and a newcomer who joins with `vox room
  join` holds every entry alice's log does (1,502: the posts and two consents, counted off both stores).
  On v0.2.8 (0844943) it is red at post 1,001; with the quota restored on the reopen path only it is red
  at the reopen (`[closed]`). `crates/vox-core/tests/a_room_has_no_history_limit.rs` was the same claim
  on in-process nodes; it was deleted in V29-17 because `a_long_room_reopens_proof` proves it through
  the shipped binary.
  **Observed alongside, not fixed or diagnosed here:** through the CLI the newcomer rendered none of
  the pre-join history, and — the part that matters for R1 — did not render alice's *next* post within
  180 s once the history was 1,500 long, where with 5 posts it did. A likely cause, **not verified**, is
  that the key a newcomer receives sits at the chain's origin and the sender-key chain refuses a gap
  over `MAX_SKIP` (1,000). That belongs to ADR-006 and R12 (per-grant history); the gate above counts
  the newcomer's log for this reason rather than what it renders.
- **A `WANT` is bounded by what is held (2026-09-24, PRD-001 D2/R4).** `entries_for_wants` looped
  `from_seq..=to_seq` — one lookup per *number* — collecting into memory with the room's lock held, so
  `WANT (author, 1, u64::MAX)` from any member spun for ever and nothing else could touch the room. Now
  each author's ranges are sorted and merged (duplicates and overlaps cost nothing and serve nothing
  twice), each merged range walks `Feed::range` over the entries actually held, and a session serves at
  most `MAX_SERVE_ENTRIES` / `MAX_SERVE_BYTES` within `SERVE_BUDGET`, always at least one entry. The
  continuation is the existing one: a sync that applied entries marks a push, so the requester comes
  straight back for the rest.
  **Gate** (`crates/vox-core/tests/a_want_cannot_wedge_a_room.rs`, release, `--ignored`): a real
  member's identity, over a real connection, sends `WANT` with 1,000 copies of `(victim, 1, u64::MAX)`
  plus an unheld feed and an inverted range; an ordinary post into the room on the victim completes
  (6.6, 10.8 and 6.7 ms over three runs) and the attacker receives each of the 50 held entries exactly
  once. On v0.2.8 (3cac220) the post gets no answer in 5 s in three runs of three; with the old loop
  restored, the same; with ranges not merged, 1,024 entries are served for 50 held.

## Links
**Depends on**: ADR-002, ADR-006.
- Depended on by: ADR-007, ADR-009, ADR-010, ADR-011.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
