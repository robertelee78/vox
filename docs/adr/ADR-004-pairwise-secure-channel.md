# ADR-004: Pairwise Secure Channel (PQXDH + Double Ratchet)

- **Status**: proposed
- **Date**: 2026-06-19
- **Deciders**: Robert E. Lee <robert@agidreams.us>
- **Tags**: crypto-core, pqxdh, double-ratchet, forward-secrecy, pcs

## Context

Even though the channel is the unit of communication (ADR-001), members need a secure *pairwise*
channel underneath: to exchange Sender-Key distribution messages (ADR-006), run the channel-join
handshake (ADR-005), and deliver consent/admin material (ADR-007). This is the cryptographic core
and must satisfy the post-quantum policy (ADR-003). The Signal primitives (X3DH, Double Ratchet)
are well-analyzed and the correct conventional base (ADR-001 principle 5).

## Decision

**Key agreement = PQXDH** (Signal's design; formally verified, USENIX'24). Augment X3DH by mixing
an ML-KEM shared secret into the KDF: `SK = KDF(DH1 || DH2 || DH3 || [DH4] || SS)`, where `SS` is
the ML-KEM encapsulation against the peer's signed KEM prekey. Hybrid X25519 + ML-KEM-768 (ADR-003).
The two ADR-003 defensive requirements (type-confusion prevention; KEM-secret binding into AEAD
AD) are mandatory here.

**Message encryption = Double Ratchet** (X25519 DH-ratchet + symmetric KDF-chain ratchet, AEAD
envelopes). Provides forward secrecy and classical post-compromise security for pairwise traffic.
Use HMAC-based chain KDFs per the Signal spec (the old Go prototype's bare-SHA256 chain KDF is
explicitly rejected).

**Post-quantum PCS (phased).** PQXDH gives PQ confidentiality but not PQ post-compromise security.
A PQ continuous-key-agreement layer (Signal SPQR / "Triple Ratchet" with ML-KEM-768, or Apple
PQ3's amortized re-KEM every ~50 messages) is a later increment over the day-one ratchet, gated
by its bandwidth cost (ADR-003).

**Context binding.** Every handshake and ratchet message binds the negotiated ciphersuite
(ADR-003) and, where applicable, the channel/epoch context (ADR-006) into its transcript/AD.

## Consequences

### Positive
- Strong, formally-verified pairwise confidentiality with forward secrecy, PQ-safe from day one.
- Reuses the most-analyzed secure-messaging construction in existence.

### Negative
- PQXDH protects only *passive* quantum adversaries; active-quantum security is out of scope (per spec).
- Asynchronous X3DH normally assumes a prekey server; serverless operation changes prekey
  availability (handled via channel rendezvous + the log, ADR-005/ADR-008) and may reduce the
  classic async-to-an-offline-peer property.
- PQ-PCS deferral means full post-compromise healing against a quantum adversary is not day-one.

### Neutral
- The pairwise channel is an internal substrate; users only ever see "the channel" (ADR-001).

## Links
- Depends on: ADR-002, ADR-003.
- Depended on by: ADR-005, ADR-006, ADR-007, ADR-011.
