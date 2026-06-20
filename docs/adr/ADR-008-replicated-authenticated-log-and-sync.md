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
epoch, algo_ids, payload_hash, payload_len, end_of_feed_flag }`, authenticated by a composite
Ed25519+ML-DSA signature (attributable channels) or the ADR-009 deniable authenticator (deniable
channels), computed over all preceding fields. Because the signature commits to the *payload hash*,
not the bytes, a peer can delete old payload bodies (honoring admin TTL, ADR-010) while the signed,
hash-linked skeleton stays fully verifiable; **lipmaa skip-links** give logarithmic-length
verification certificates for partial replication. This is the Bamboo design adapted to Vox's
composite-PQ signatures and `(channelID, epoch)` binding — specified directly here, not pulled from
an external library (Bamboo/Reed/Hypercore inform it but are not a runtime dependency).

**Sync = anti-entropy.** Frontier have/want exchange for the simple case; range-based set
reconciliation (Willow/Negentropy, logarithmic rounds) at scale (plain SSB degrades past ~100
members).

**Dual authentication modes.** Attributable channels use per-author signatures on entries;
deniable channels authenticate via the ADR-009 mechanism. The hash-chain itself is
signature-agnostic, so ordering/tamper-evidence hold in both modes; deniable-mode integrity
detail is specified in ADR-009.

**Consent + certificate state lives here.** Membership certificates, consent grants, and
revocations are log entries, so they replicate and converge causally across the overlay (ADR-007).

**Fork / equivocation handling.** A single-writer log must not fork; two distinct entries by the
same author at the same `seq` are an equivocation. Vox makes this detectable and attributable:
- Every entry binds `seq` + `prev_hash`, so any peer holding two validly-signed entries with the
  same `(author_id, seq)` but different hashes possesses a **self-authenticating fork proof**.
- Anti-entropy gossips **signed log heads** `(author_id, seq, hash)`; a head that rewrites or skips a
  known `seq` surfaces the conflict immediately.
- On a fork proof, clients **freeze that author** (stop accepting/rendering their further entries),
  record the fork proof as a channel log entry, surface it in the UI (ADR-014), and members revoke
  consent / rotate to exclude the equivocator (ADR-007).
- Honest partition limit: during a partition an equivocator can present different heads to disjoint
  partitions; this cannot be *prevented* without consensus, but it is **permanently detectable and
  attributable on heal** (the fork proof is durable). Accordingly, partition-time authority actions
  (admin grant/revoke) are treated as *provisional* until their causal neighborhood reconciles.

**Abuse resistance.** Only entries from admitted members (ADR-007) are accepted into a channel's log,
so unauthenticated floods cannot enter. Replication is bounded by per-author rate/size quotas (each
peer caps what it stores/relays per author per epoch). Pruning is *authenticated*: a payload may be
dropped per TTL, but its signed skeleton entry remains, so pruning can never silently rewrite history.

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
