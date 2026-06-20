# ADR-008: Replicated Authenticated Log and Sync

**Status**: proposed
**Date**: 2026-06-19
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
| `0x0009` | tls-identity-extension (ADR-011) | | |

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
| `0x0009` | `vox/tls-identity-extension/v1` | | |

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
  frames (skeleton + any retained payloads) over a reliable QUIC stream (ADR-011).
- **Range-reconciliation mode (used when both peers set bit 1; the default *above ~100 active authors*,
  where `HAVE` size dominates).** `NEG` frames carry Negentropy range-based set reconciliation over entry
  hashes (logarithmic rounds). The `NEG` body is **Negentropy v1** keyed by the **full 32-byte SHA-256
  entry hash** (no truncation), wrapped in the Vox `NEG` frame so the Vox wire contract is fully
  self-described here. Frontier is mandatory; range-reconciliation is an additional required capability
  for scale.

**Abort / error signalling (normative).** Every hard-fail in the wire ADRs (floor-violation, ADR-003;
unknown struct tag or algo ID; sync mode mismatch; signature/authenticator failure; quota breach) is
surfaced — never silently downgraded — by **closing the QUIC stream (or connection) with a Vox
application error code**: `0x01` protocol-version-unsupported, `0x02` suite-below-floor (ADR-003),
`0x03` unknown-struct-tag, `0x04` unknown-algo-id, `0x05` authenticator-invalid, `0x06` quota-exceeded,
`0x07` sync-mode-unsupported, `0x08` epoch-mismatch. The peer logs the coded reason and surfaces it
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

**Abuse resistance (quantified).** There is no membership roster or admission gate (ADR-007); the log
acceptance predicate is instead **identity- and signature-bound**: an entry is accepted only if (a) it
is authored by an identity that completed the authenticated channel join (CPace, ADR-005) for the
current `(channelID, epoch)`, (b) it carries a valid per-author authenticator for its entry type
(governance → root composite signature; content → composite or ADR-009 deniable), and (c) it is within
that author's quota. Unauthenticated or wrong-epoch floods therefore cannot enter. Replication is
bounded by **per-author quotas each peer enforces locally** — **defaults (channel-policy-tunable):
≤ 1000 entries/hour and ≤ 50 MB/epoch per author**; over-quota entries from that author are dropped
(not relayed) and the over-quota event is surfaced as an abuse signal (like revocation churn). This
directly bounds the **render-gating amplification** vector — because every ciphertext replicates to
all members (§"Render-gating"), a joined author could otherwise force O(members) storage; the
per-author byte
cap is what makes that cost finite, and a member may always decline to relay/store beyond a peer's
own configured ceiling. Pruning is *authenticated*: a payload may be dropped per TTL, but its signed
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
