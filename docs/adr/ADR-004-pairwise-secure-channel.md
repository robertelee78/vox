# ADR-004: Pairwise Secure Channel (PQXDH + Double Ratchet)

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: crypto-core, pqxdh, double-ratchet, forward-secrecy, pcs

## Context

Even though the channel is the unit of communication (ADR-001), members need a secure *pairwise*
channel underneath: to exchange Sender-Key distribution messages (ADR-006), run the channel-join
handshake (ADR-005), and deliver consent/admin material (ADR-007). This is the cryptographic core
and must satisfy the post-quantum policy (ADR-003). The Signal primitives (X3DH, Double Ratchet)
are well-analyzed and the correct conventional base (ADR-001 principle 5).

## Decision

**Key agreement = PQXDH** (Signal's design; formally verified, USENIX'24). Augment X3DH by mixing
an ML-KEM shared secret into the KDF, instantiated concretely as
`SK = HKDF-SHA-256(ikm = F ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ SS, salt = 0x00…00 (32 B), info = "vox/pqxdh/v1" ‖ suite_id)`,
where `F = 0xFF ✕ 32` is the X3DH/PQXDH curve domain-separation prefix (retained for fidelity to the
USENIX'24-verified construction) and `SS` is the ML-KEM-768 encapsulation against the peer's signed
KEM prekey (hybrid X25519 + ML-KEM-768, ADR-003). The two ADR-003 defensive requirements are mandatory and made concrete here:
**(1) type-confusion prevention** — every key carries its ADR-003 class-prefixed algorithm ID, so a
curve key can never be parsed as a KEM key; **(2) KEM-secret binding** — the KEM public key and
ciphertext are bound into the first ratchet message's AEAD associated data,
`AD = transcript_hash ‖ kem_pub ‖ kem_ct ‖ suite_id ‖ channelID ‖ epoch` (canonical encoding, ADR-008),
defeating the re-encapsulation attack.

**Message encryption = Double Ratchet** (X25519 DH-ratchet + symmetric KDF-chain ratchet, AEAD
envelopes). Provides forward secrecy and classical post-compromise security for pairwise traffic.
Use HMAC-based chain KDFs per the Signal spec (a bare-SHA256 chain KDF is explicitly rejected).

**Post-quantum PCS (phased).** PQXDH gives PQ confidentiality but not PQ post-compromise security.
A PQ continuous-key-agreement layer (Signal SPQR / "Triple Ratchet" with ML-KEM-768, or Apple
PQ3's amortized re-KEM every ~50 messages) is a later increment over the day-one ratchet, gated
by its bandwidth cost (ADR-003).

**Context binding.** Every handshake and ratchet message binds the negotiated ciphersuite
(ADR-003) and, where applicable, the channel/epoch context (ADR-006) into its transcript/AD.

**Wire format & operational rules (so the ratchet is actually buildable):**
- **Message header:** `{ ratchet_pubkey (DH), PN (previous-chain length), N (message number), algo_ids }`,
  bound into the AEAD associated data along with the ciphersuite and `(channelID, epoch)`. **AD state
  transition:** the *first* message of a session uses the KEM-binding AD from §Decision
  (`transcript_hash ‖ kem_pub ‖ kem_ct ‖ suite_id ‖ channelID ‖ epoch`); *every subsequent* message uses
  this header AD. The switch is exactly once, on the first post-handshake message.
- **Out-of-order / skipped messages:** a receiver derives and **caches skipped message keys** up to a
  bounded `MAX_SKIP` per chain (with a total cap and expiry); messages beyond the bound are rejected
  rather than forcing unbounded computation (DoS guard). This is the standard Double Ratchet
  skipped-key store, made explicitly bounded. **Normative defaults** (channel-policy-tunable within
  required bounds): `MAX_SKIP` = 1000 keys per chain; total skipped-key cache = 2000 keys per session;
  skipped-key expiry = 7 days. A gap larger than `MAX_SKIP` forces a new ratchet step, not unbounded
  derivation.
- **Replay protection:** a `(ratchet_pubkey, N)` pair already consumed is rejected; message keys are
  deleted after use so a replay cannot re-derive plaintext.
- **Prekey publication (serverless).** There is no prekey *server*. A member publishes its signed
  prekey bundle (ADR-002: X25519 + ML-KEM-768 signed prekey, one-time prekeys) as **signed records at
  the channel rendezvous / on the log** (ADR-005/ADR-008); initiators fetch a bundle there and consume
  a one-time prekey. One-time-prekey exhaustion falls back to the signed last-resort prekey — never to
  no-prekey. **Serverless consume semantics (no atomic server arbiter):** one-time prekeys are a
  *best-effort* forward-secrecy bonus, not a guarantee — two initiators may consume the same OTP
  concurrently. The recipient performs **reuse detection** (an OTP seen twice is logged and the second
  session treated as last-resort-grade), and a deliberate **drain attack** can only downgrade *new*
  sessions to last-resort-prekey FS (a documented, bounded residual), never break confidentiality.
  Pre-join peers publish prekeys in a **separate pre-join rendezvous record class** (ADR-012)
  that conveys no log authority (ADR-008 accepts log entries only from identities that completed the
  authenticated join for the current `(channelID, epoch)`).

**Security-property taxonomy (stated precisely to avoid conflation):**
- **Forward secrecy** — from the symmetric KDF-chain ratchet (past keys unrecoverable from current).
- **Classical post-compromise security** — from the DH ratchet (healing after compromise, classical).
- **PQ confidentiality** — from PQXDH's ML-KEM leg (harvest-now-decrypt-later defeated), against a
  **passive** quantum adversary only (active-quantum auth is out of scope per the PQXDH spec).
- **PQ post-compromise security** — NOT day-one; the phased PQ-CKA layer above provides it later.

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
**Depends on**: ADR-002, ADR-003.
- Depended on by: ADR-005, ADR-006, ADR-007, ADR-011.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
