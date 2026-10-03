# ADR-004: Pairwise Secure Channel (PQXDH + Double Ratchet)

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status:** accepted and built in `crates/vox-core/src/pairwise/`, `node::prekeys` and
`node::joinstream`, except: PQ post-compromise security (§"Post-quantum PCS (phased)") is not built;
the skipped-key bounds (W3) are fixed constants, not channel-policy settings; prekey bundles are
published only at the rendezvous, not on the log (P1).
**Deciders:** Robert E. Lee <robert@agidreams.us>

## Context

The channel is the unit of communication (ADR-001), but members still need a secure pairwise channel
underneath: to carry Sender-Key distribution messages (ADR-006), run the join (ADR-005) and deliver
consent and admin material (ADR-007). It follows the post-quantum policy (ADR-003). Signal's
X3DH/PQXDH and Double Ratchet are the analyzed, conventional base (ADR-001 principle 5). Users never
see this layer; they see only the channel.

## Requirements

### §Decision Key agreement and message encryption

- **K1.** Key agreement MUST be PQXDH (Signal's design, formally verified, USENIX Security 2024):
  `SK = HKDF-SHA-256(ikm = F ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ SS, salt = 0x00 × 32, info = "vox/pqxdh/v1" ‖
  suite_id (u16 BE))`, where `F = 0xFF × 32` and `SS` is the ML-KEM-768 encapsulation against the
  peer's signed KEM prekey.
- **K2.** Every key MUST carry its ADR-003 class-prefixed algorithm ID, so a curve key can never be
  parsed as a KEM key (ADR-003 requirement 1).
- **K3.** The first ratchet message MUST bind the KEM public key and ciphertext into its AEAD
  associated data: `AD = transcript_hash ‖ kem_pub ‖ kem_ct ‖ suite_id ‖ channelID ‖ epoch` (canonical
  encoding, ADR-008), defeating re-encapsulation (ADR-003 requirement 2).
- **K4.** Messages MUST be encrypted with the Double Ratchet (an X25519 DH ratchet and a symmetric KDF
  chain, AEAD envelopes). Chain KDFs MUST be HMAC-based per the Signal specification; a bare SHA-256
  chain KDF MUST NOT be used.
- **K5.** Every handshake and ratchet message MUST bind the negotiated ciphersuite (ADR-003) and, where
  applicable, the `(channelID, epoch)` context (ADR-006) into its transcript or associated data.
- **K6.** The per-message AEAD nonce MUST be `HMAC-SHA-256(mk, 0x03)[..12]`. A KDF error MUST be
  propagated; a zero or fallback nonce MUST NOT be used.

### §Wire Format and operational rules

- **W1.** A message header MUST be `{ratchet_pubkey, PN, N}` with the curve and AEAD algorithm IDs in
  force, canonical body `[curve_algo, aead_algo, ratchet_pubkey, pn, n]`. It travels in the clear and
  MUST be bound into the AEAD associated data with the ciphersuite and `(channelID, epoch)`.
- **W2.** The first message of a session MUST use the K3 associated data; every later message MUST use
  the W1 header associated data. The switch MUST happen exactly once, on the first post-handshake
  message.
- **W3.** A receiver MUST cache skipped message keys up to `MAX_SKIP` = 1000 per chain, at most
  `MAX_CACHE` = 2000 per session, expiring after `SKIP_EXPIRY_SECS` = 7 days. A message whose counter
  gap exceeds `MAX_SKIP` MUST be rejected, never derived without bound.
- **W4.** A `(ratchet_pubkey, N)` already consumed MUST be rejected, and message keys MUST be deleted
  after use, so a replay cannot re-derive plaintext.
- **W5.** Decryption MUST be transactional: the whole inbound transition (skipped keys, new root and
  chain keys and, on a DH step, the new local ratchet secret) MUST be computed into a plan and
  committed only if the AEAD opens. Every secret in the plan MUST be zeroize-on-drop, so a packet that
  fails leaves no secret behind. `Ratchet::init_responder` MUST take the signed-prekey secret as a
  zeroizing buffer.
- **W6.** A session created by `Session::accept` has no sending chain until it receives the
  initiator's first message, so after an ADR-005 join the joiner MUST send first. The node MUST do
  this as part of joining with `PairwiseFrame::Open`, one sealed message with an empty plaintext
  that releases no sender key (ADR-007 G-15 step 2, M17.6).

### §Prekey Publication (serverless)

- **P1.** There MUST be no prekey server. A member MUST publish its signed prekey bundle (ADR-002 §2)
  as a signed record at the channel rendezvous (ADR-005, ADR-016 member bundle record) or on the log
  (ADR-008); an initiator fetches a bundle there and consumes a one-time prekey. Today bundles are
  published only as rendezvous records; publication on the log is not built.
- **P2.** One-time-prekey exhaustion MUST fall back to the signed last-resort prekey, never to no
  prekey.
- **P3.** Pre-join peers MUST publish prekeys in the separate pre-join rendezvous record class
  (ADR-012), which carries no log authority (ADR-008).

### §"Serverless consume semantics"

One-time prekeys are a best-effort forward-secrecy bonus, not a guarantee: without a server, two
initiators can consume the same one-time prekey concurrently.

- **C1.** The responder MUST detect reuse: a one-time prekey seen twice MUST be logged and the second
  session MUST be graded last-resort. A drain attack can only downgrade new sessions to last-resort
  forward secrecy and MUST NOT break confidentiality.
- **C2.** `PrekeyRing::use_one_time` MUST answer `Fresh`, `Reused` or `Unknown`. A consumed prekey
  MUST move to a bounded retained set (`ONE_TIME_CONSUMED_RETAIN_SECS` = 1 h,
  `ONE_TIME_CONSUMED_MAX` = 256, oldest dropped first, pruned by `maintain`, persisted at rest) so a
  concurrent duplicate can still complete. After retention the secret MUST be dropped, and a late
  duplicate gets `Unknown`.
- **C3.** On `Reused`, the responder MUST seed the per-process `OtpReuseTracker` (`observe(id)`)
  before `Session::accept`, so the downgrade survives a restart. On `Unknown` (a prekey never issued,
  or past retention) it MUST refuse the handshake.
- **C4.** The responder MUST persist the ring the moment a prekey is consumed, before the handshake
  completes, so a crash cannot leave it re-offerable. Every session-establishment path MUST do C3 and
  C4.
- **C5.** The prekey ring MUST be shared behind a lock taken only twice per exchange (to read the
  bundle for the `Challenge`, and after the last frame for the consume, its save and the session
  bootstrap). The holder MUST NOT wait on the network while holding the lock; the consume and its save MUST
  stay in one critical section.

### §Session Sessions outside a join

- **O1.** A session MAY be opened outside a join, from a member's ADR-016 bundle record. Its
  `InitialMessage` MUST travel as `PairwiseFrame::Hello` on the `pairwise` stream. The responder MUST
  apply the same checks as a join: the message names a signed prekey (and optionally a one-time
  prekey) from its own ring, C1 to C4 apply, and a replay is graded last-resort.

### §"Post-quantum PCS (phased)"

- **Q1.** PQ post-compromise security is not provided today. It MUST be added as a separate
  capability (a PQ continuous-key-agreement layer, such as Signal SPQR's ML-KEM-768 Triple Ratchet or
  Apple PQ3's amortized re-KEM), gated by its bandwidth cost (ADR-003 §Scope).

### Security properties provided

- **S1.** This layer provides: forward secrecy (the KDF-chain ratchet); classical post-compromise
  security (the DH ratchet); PQ confidentiality against a passive quantum adversary (PQXDH's ML-KEM
  leg). It MUST NOT be described as providing PQ post-compromise security (Q1) or security against an
  active quantum adversary (out of scope per the PQXDH specification).

## Consequences

- Formally verified pairwise confidentiality with forward secrecy, hybrid from the first release.
- Serverless prekey availability depends on the rendezvous and the log, which can weaken the classic
  asynchronous send to an offline peer.
- Full post-compromise healing against a quantum adversary is not provided until Q1 is built.

## Related ADRs

Depends on ADR-002 and ADR-003. Depended on by ADR-005, ADR-006, ADR-007, ADR-011. Cited: ADR-008,
ADR-012, ADR-016.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
