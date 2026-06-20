# ADR-005: Channel Addressing and Authenticated Join

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: channel, addressing, pake, cpace, rendezvous, join

## Context

A channel is addressed magnet-link style by a channel ID + passphrase shared out-of-band
(ADR-001). Two distinct jobs are bundled in that string and must be separated: *rendezvous*
(finding the swarm) and *authentication* (proving you may join). The passphrase is low-entropy
and human-chosen, so it must resist offline dictionary attack. Discovery rides the P2P swarm/DHT
(ADR-012). Joining must yield a real authenticated pairwise channel (ADR-004), and — critically —
joining must grant *no* readable content by itself (per-sender consent, ADR-007).

## Decision

**Authenticated join = CPace + identity proof-of-possession.** CPace (the CFRG-recommended
*balanced* PAKE) is symmetric (no server, no fixed roles), gives implicit mutual authentication, and
limits an attacker to one online guess per interaction — provably resisting offline dictionary
attack on the low-entropy passphrase (UC proof, eprint 2021/114). **CPace alone only proves "this
party holds the passphrase," not *which identity* it is.** Vox therefore composes two factors:
1. **CPace** establishes a session keyed by the passphrase, with the `channelID`, `epoch`, and the
   transcript bound into CPace's `CI`/`sid`/`AD`.
2. **Identity proof-of-possession.** Inside that CPace-protected session, each party signs the CPace
   `sid` (and transcript hash) with its **composite Ed25519+ML-DSA identity key** (ADR-002) and sends
   its identity public keys; the peer verifies the signature and matches the derived identity
   fingerprint against the expected one (verified out-of-band per ADR-014). Merely *naming* an
   identity string in CPace inputs is not sufficient — possession of the identity private key must be
   proven, and it is, here.

Pairwise CPace-on-meet between members; no bespoke group PAKE (GPAKE is immature/unstandardized).

**Separate rendezvous from authentication.**
- **channelID → rendezvous address.** Derive the DHT/PubSub lookup key from the channel ID via a
  one-way (and slow/memory-hard) KDF. Use a *distinct, high-entropy* channel ID for rendezvous;
  do **not** derive the public lookup key directly from the human passphrase, or passive DHT
  observers could offline-guess it (this derivation is outside CPace's proof).
- **passphrase → CPace secret only.**

**Post-join.** A successful CPace run bootstraps a PQXDH/Double-Ratchet pairwise session (ADR-004).
Membership and any readable content still require the consent + certificate machinery of ADR-007;
a joined node that no member has consented to sees only ciphertext.

**Anti-abuse (layered, not just rate-limiting).** PAKE does not stop *online* guessing (one per run),
and naive rate-limiting is Sybil-bypassable in a decentralized setting. Vox therefore relies on three
concrete, non-bypassable layers rather than rate-limiting alone:
1. **The real gate is consent.** A successful join grants *nothing readable* — no sender keys — until
   members individually consent (ADR-007). There is no admin admission step; the passphrase gates the
   swarm and per-sender consent gates reading. Online passphrase-guessing therefore buys an attacker
   only the ability to sit in the swarm receiving ciphertext; it never yields readable content.
2. **Channel/epoch-bound proof-of-work join tokens (concrete).** Each join attempt carries a PoW token
   bound to `(channelID, epoch, responder-nonce)` so tokens cannot be precomputed or replayed across
   channels/epochs. **Concrete function:** a *memory-hard* PoW (Argon2id over the bound tuple, ~64 MB)
   to deny GPU/ASIC advantage; **default target solve ≈ 1–2 s on a mobile CPU**, with the responder
   advertising a difficulty it adapts upward under load and downward when idle (difficulty is itself in
   the signed responder-nonce so the prover cannot lie about it); **verifier cost is a single Argon2id
   check (~ms)**, so verification never becomes the DoS. Accessibility note: difficulty caps keep
   low-end devices usable; an invite-only channel may set difficulty to zero (admission is the gate).
3. **Admission is admin-signed.** Final entry to the member set requires an admin-signed membership
   certificate (ADR-007); no amount of passphrase guessing produces one.

Rate-limiting by peers remains a cheap first filter but is explicitly **not** the security boundary.
**Bandwidth abuse beyond join** (an admitted member spamming the log or rendezvous, or forcing
render-gating amplification) is bounded by the per-author log quotas (ADR-008) and rendezvous-record
caps (ADR-012), not by join PoW.

## Consequences

### Positive
- The passphrase becomes a real cryptographic gate, not mere obscurity.
- Serverless: no prekey server; peers authenticate as equals.
- Separating rendezvous-ID from auth-passphrase closes the offline-guessing leak on the DHT.

### Negative
- A leaked passphrase lets an attacker complete the join (but still yields only ciphertext until
  members consent — ADR-007); passphrase rotation is the mitigation (ADR-007 epoch).
- Out-of-band exchange of channelID + passphrase is a usability burden the user owns.

### Neutral
- Group PAKE / affiliation-hiding (partitioned GPAKE) is deferred to the metadata-privacy phase.

## Links
**Depends on**: ADR-002, ADR-003, ADR-004.
- Depended on by: ADR-007, ADR-012.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
