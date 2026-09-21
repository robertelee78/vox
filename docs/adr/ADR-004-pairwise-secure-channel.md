# ADR-004: Pairwise Secure Channel (PQXDH + Double Ratchet)

**Status**: implemented (M2, `crates/vox-core/src/pairwise/`)
**Date**: 2026-06-19
**Updated**: 2026-09-21 — a session may now be opened **outside a join**, from a member's ADR-016 bundle record; its `InitialMessage` travels as `PairwiseFrame::Hello` on the `pairwise` stream instead of the join stream. The responder path is unchanged and unchanged in strength: the message must name a signed prekey (and optionally a one-time prekey) from the responder's own ring, the one-time consume is persisted before the handshake completes, and a replay is graded last-resort exactly as `joinstream` grades it. **Updated**: 2026-09-19 — Implementation notes (M2) added; uncommitted DH-ratchet secrets are wiped when a decrypt plan is dropped; nonce KDF error propagates instead of an all-zero nonce. 2026-09-20 — serverless one-time-prekey consume semantics implemented (`node::prekeys`, ADR-016 M14.3) and reconciled with the per-process reuse tracker at the point sessions are established (`node::joinstream`, M14.4).
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
  skipped-key expiry = 7 days. A message whose counter gap exceeds `MAX_SKIP` is **rejected** (the
  sender must ratchet before the receiver will accept it), never unbounded
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

## Implementation notes (M2)

These record the concrete decisions made building this ADR (`crates/vox-core/src/pairwise/`), so the spec and code stay in lockstep:

- **Transactional decrypt wipes what it does not commit.** `Ratchet::decrypt` computes the whole
  inbound transition (skipped keys, new root/chain keys, and — on a DH step — the new local ratchet
  secret) into a plan, opens the AEAD, and commits only on success. Every secret in that plan is a
  zeroize-on-drop type, including the candidate DH ratchet secret, so a forged or corrupt packet that
  fails the AEAD leaves no secret residue behind when the plan is dropped. Enforced at the type level
  by a compile-time check in `pairwise::ratchet`. *(2026-09-19 review: the candidate secret was a bare
  `[u8; 32]` and was not wiped on the failure path.)* `Ratchet::init_responder` takes the signed-prekey
  secret as a `Zeroizing` buffer for the same reason.
- **Serverless one-time-prekey consume semantics: two halves, and they must be reconciled (M14.3).**
  The **downgrade** half has existed since M2: `OtpReuseTracker` records accepted one-time-prekey ids and
  `Session::accept` flags the second use `is_last_resort_grade`. It is in-memory, per-process, and holds
  no key material. What was missing is the half that makes serving a duplicate *possible at all* — the
  responder needs the consumed secret to complete PQXDH, and nothing retained it — plus persistence of
  the consumption itself. [`crate::node::prekeys::PrekeyRing`] supplies both: `use_one_time` returns
  `Fresh` / `Reused` / `Unknown` and moves a consumed prekey into a bounded **retained set**
  (`ONE_TIME_CONSUMED_RETAIN_SECS` = 1 h, `ONE_TIME_CONSUMED_MAX` = 256, oldest dropped first, pruned by
  `maintain`, persisted at rest) instead of destroying it, so `ResponderPrekeys` can still be built for
  a concurrent duplicate. Once retention elapses the secret is dropped — restoring forward secrecy — and
  a late duplicate gets `Unknown`, so it cannot establish and must refetch a bundle. The Decision
  specifies only the *concurrent* case; bounding retention to genuine concurrency is a deliberate
  refinement recorded here, because retaining for the full ADR-016 bundle TTL (7 days) would extend this
  ADR's documented forward-secrecy residual by a week to serve an initiator that can simply refetch.
  Exhaustion is proven by a test: a drained pool still publishes a verifying bundle, without a one-time
  prekey.
- **The two records are reconciled where sessions are established (done, M14.4).** The ring is the
  *persistent* record of what was consumed; `OtpReuseTracker` is a *per-process* one, so a node that
  restarted and then accepted a duplicate could have seen `use_one_time` → `Reused` while a fresh
  tracker reported first use, and would not have flagged the session last-resort-grade. The join
  responder (`node::joinstream`) therefore **seeds the tracker from the ring's verdict**: on `Reused` it
  calls `observe(id)` before `Session::accept`, so the downgrade survives a restart; on `Unknown` — a
  prekey this identity never issued, or one whose retention has elapsed — it refuses the handshake
  outright rather than completing a session it cannot key. It also **persists the ring the moment the
  prekey is consumed**, before the handshake completes, so a crash cannot leave it re-offerable. Any
  future session-establishment path (M14.5 onwards) must do the same; a `debug_assert` pins that the
  session's own `is_last_resort_grade` equals the ring's verdict.
- **The responder cannot speak first, which orders the join flow (M14.7e).** A session created by
  `Session::accept` has no sending chain until it has received the initiator's first message — the DH
  ratchet step that creates one needs the initiator's ratchet public key, which arrives in that message.
  So after an ADR-005 join the **joiner** must send first, and ADR-007 step 2 (the newcomer broadcasts its
  own sender key) is not merely politeness: without it no member can answer at all. The node does it as
  part of joining.
- **Message nonce KDF has no fallback.** The per-message AEAD nonce is `HMAC-SHA-256(mk, 0x03)[..12]`;
  HMAC keying cannot fail for a 32-byte key, but the error is propagated (`Result`) rather than
  replaced by an all-zero nonce. *(2026-09-19 review.)*

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
