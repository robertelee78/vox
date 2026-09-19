# ADR-005: Channel Addressing and Authenticated Join

**Status**: implemented (M3, `crates/vox-core/src/join/`)
**Date**: 2026-06-19
**Updated**: 2026-09-19 — KDF error paths (`K_pop`, rendezvous) now surface as errors instead of an all-zero key; `K_pop` returned zeroizing. C++ solver carve-out rejected (Rust only); PoW cost measured; difficulty defaults, cap and load-adaptation policy added; tromp-class pure-Rust solver is the next PoW milestone.
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
1. **CPace, instantiated as Ristretto255 + SHA-512** (the CFRG primary instantiation: group =
   Ristretto255, hash = SHA-512, generator via the CPace `calculate_generator`/`map_to_group`
   procedure — registry `0x07/0x01`, ADR-003). Ristretto255 removes cofactor/point-validation
   foot-guns and reuses the X25519 stack (`curve25519-dalek`). It establishes a session keyed by the
   passphrase, with `CI = "vox/cpace/v1" ‖ channelID ‖ epoch`, `sid` = the fresh per-run nonce, and
   `AD = suite_id` bound into CPace's inputs.
2. **Identity proof-of-possession.** Inside that CPace-protected session, each party signs the CPace
   `sid` (and transcript hash) with its **composite Ed25519+ML-DSA identity key** (ADR-002) and sends
   its identity public keys; the peer verifies the signature and matches the derived identity
   fingerprint against the expected one (verified out-of-band per ADR-014). Merely *naming* an
   identity string in CPace inputs is not sufficient — possession of the identity private key must be
   proven, and it is, here.

Pairwise CPace-on-meet between members; no bespoke group PAKE (GPAKE is immature/unstandardized).

**Separate rendezvous from authentication.**
- **channelID is high-entropy and self-certifying.** The `channelID` is `SHA-256(canonical genesis
  record)` (ADR-007 genesis, which carries a 128-bit random nonce) — 256-bit, high-entropy, and bound
  to exactly one genesis (a cold-joiner fetches genesis from the rendezvous and accepts it only if its
  hash equals the `channelID`, so there is one true genesis per channel).
- **channelID → rendezvous address.** `rendezvous_key = HKDF-SHA-256(channelID, info = "vox/rendezvous/v1" ‖ epoch)`,
  truncated to the DHT key width. A plain (fast) KDF is sufficient and correct **because the channelID
  is already high-entropy** — a memory-hard KDF would add cost without benefit (knowing the channelID,
  an observer computes the key once regardless; swarm-presence unlinkability is the later
  metadata-privacy phase, ADR-001). The passphrase is **never** an input to rendezvous. ADR-012 uses
  this exact derivation.
- **Same construction, other seeds.** The rendezvous KDF generalizes: any high-entropy seed `S` yields
  `rendezvous = HKDF-SHA-256(S, info=<label>)`. The personal self-channel (ADR-008) uses this with
  `S = self_seed` — the **private** per-identity self-channel secret (ADR-002), *not* the public
  identity key — so a user's own shared-root devices meet at a rendezvous no third party can locate.
- **passphrase → CPace secret only.**

**Post-join.** A successful CPace run bootstraps a PQXDH/Double-Ratchet pairwise session (ADR-004).
Joining yields **no readable content**: membership is emergent (join + per-sender consent, ADR-007)
and a joined node sees only ciphertext until individual members consent to it. There is no admin
admission step and no membership certificate.

**Anti-abuse (layered, not just rate-limiting).** PAKE does not stop *online* guessing (one per run),
and naive rate-limiting is Sybil-bypassable in a decentralized setting. Vox therefore relies on three
concrete, non-bypassable layers rather than rate-limiting alone:
1. **The real gate is consent.** A successful join grants *nothing readable* — no sender keys — until
   members individually consent (ADR-007). There is no admin admission step; the passphrase gates the
   swarm and per-sender consent gates reading. Online passphrase-guessing therefore buys an attacker
   only the ability to sit in the swarm receiving ciphertext; it never yields readable content.
2. **Channel/epoch-bound proof-of-work join tokens (concrete).** Each join attempt carries a PoW token
   bound to `(channelID, epoch, responder-nonce)` so tokens cannot be precomputed or replayed across
   channels/epochs. **Concrete function:** an *asymmetric memory-hard* PoW — **Equihash `(n=200, k=9)`**
   (Zcash parameters) — chosen precisely because it is **memory-hard to *solve* (denies GPU/ASIC
   advantage) yet cheap to *verify*** (a few hashes + XOR checks, sub-millisecond), so verification is
   never itself the DoS (a plain Argon2id PoW does **not** have this property — verifying it costs the
   same memory-hard work as solving it, which is why Equihash is used here). **Default target solve
   ≈ 1–2 s on a mobile CPU**; the responder advertises a difficulty (Equihash effective-difficulty
   filter on the solution hash) it adapts upward under load and downward when idle, carried in the
   signed responder-nonce so the prover cannot lie about it. Accessibility note: difficulty caps keep
   low-end devices usable. An **identity-bound (invite) channel defaults to a *low but non-zero* PoW
   (≈200–500 ms)** — not zero — so a leaked channelID cannot cheaply flood the swarm; literal zero is
   reserved for explicitly LAN/closed deployments. Per-sender consent remains the real read-gate
   regardless.
3. **Identity-bound log acceptance + per-author quotas.** Joining the swarm grants no authority to be
   *rendered*: the causal log accepts entries only from identities that completed the authenticated
   join and carry valid per-author composite signatures, each bounded by per-author entry/byte quotas
   (ADR-008). No amount of passphrase guessing yields readable content or unbounded write authority —
   there is no admin-signed membership certificate to forge (ADR-007), because there is no membership
   certificate at all.

Rate-limiting by peers remains a cheap first filter but is explicitly **not** the security boundary.
**Bandwidth abuse beyond join** (a joined member spamming the log or rendezvous, or forcing
render-gating amplification) is bounded by the per-author log quotas (ADR-008) and rendezvous-record
caps (ADR-012), not by join PoW.

### Implementation notes (normative)

- **PoW verification is pure-Rust and cheap.** Equihash solution validity is checked with the
  `equihash` (librustzcash) crate's pure-Rust verifier plus the difficulty-filter hash; verification
  is sub-millisecond and is always the path a responder runs. The signed responder-nonce carries the
  difficulty so the prover cannot understate it, and a token is bound to `(channelID, epoch,
  responder_nonce)` so it cannot be precomputed or replayed across channels/epochs.
- **PoW solving — pure Rust only; the C++ carve-out is rejected.** The solve path is Vox's own
  pure-Rust generalized-Wagner solver (`join::pow::wagner`), the *only* prover at every parameter set;
  the librustzcash crate is used solely as the verifier. The optional C++ `tromp` solver this note once
  carved out as "pending deciders' confirmation" was **rejected by the decider on 2026-09-19** ("Vox is
  Rust only", ADR-001 principle 10): the `equihash-solver` feature and its CI job were removed. A
  performance gap is an algorithm/implementation problem to be solved in Rust, never grounds for a
  non-Rust exception.
- **Measured cost (2026-09-19, `examples/spike_pow.rs`, release build, Apple-silicon laptop core).**
  Pure-Rust Wagner at the real `(200,9)`: **≈ 7.5 s per nonce, 1.65 GB peak RSS, 2.0 solutions per
  nonce**. Reduced CI parameters `(48,5)`: sub-millisecond; `(96,5)`: 0.09 s. (`(144,5)` was also
  measured — 115 s and 10 GB — and is not a candidate.) The ≈ 1–2 s mobile-join target above is therefore
  **not met today**: the base solve alone is 4–8× over it on a desktop-class core before any
  difficulty filter. The target stands; the gap is closed by the solver milestone below, not by
  weakening `(n,k)`.
- **Difficulty is calibrated in base-solve multiples, not seconds.** A `(200,9)` solve yields ≈ 2
  solutions per nonce and a `d`-bit filter passes each with probability `2^-d`, so a join costs
  `max(1, 2^d / 2)` base solves (`Difficulty::expected_solves`). Defaults (`join::pow::Difficulty`):
  `DEFAULT_INVITE` = 1 bit (≈ 1 solve; the smallest *non-zero* filter, so a leaked channelID still
  costs a full memory-hard solve per attempt), `DEFAULT_OPEN` = 2 bits (≈ 2 solves), and the
  accessibility cap `MAX` = 8 bits (≈ 128 solves) — a joiner **refuses** a challenge above the cap
  before grinding (`join_initiate`), which also bounds the work an attacker-signed challenge can
  extract. `ZERO` remains explicit LAN/closed mode. Once the solver milestone lands, the same bit
  values map onto the wall-clock targets (1 solve ≈ 0.5–1 s ⇒ invite ≈ 0.5–1 s, open ≈ 1–2 s).
- **Load adaptation is a pure function.** `Difficulty::adapted_for_load(pending_joins)` adds one bit
  per doubling of the pending-join queue at or above a small threshold (4) and saturates at `MAX`;
  it is monotone in load and falls back as the queue drains, so a responder node calls it with its
  live queue depth each time it mints a signed challenge. The node runtime that supplies the queue
  depth is the integration milestone (no such runtime exists yet); the policy itself is complete.
- **Next PoW milestone — a tromp-class pure-Rust `(200,9)` solver.** The present solver stores
  parent-pointer nodes and hard-caps each round's list, which is why it needs 1.65 GB and ≈ 7.5 s.
  The reference design (tromp's `equi_miner`) runs the *same* Wagner algorithm in ≈ 144 MB and well
  under a second per nonce on a modern core by (i) bucket-sorting each round's list by the round's
  collision prefix into fixed-capacity buckets, (ii) storing each entry as a compact 32-bit slot that
  packs the surviving hash bits with the two parent slot indices (no 64-bit pointers), (iii) reusing
  two layer buffers round to round, and (iv) recovering the `2^k` leaf indices by walking slot pairs
  only for the final collisions. Acceptance gates for the port: every emitted solution accepted by
  the librustzcash verifier for the same `(seed, nonce)`; on this machine ≤ 2 s per nonce and
  ≤ 256 MB peak RSS at `(200,9)` (measured by `spike_pow`); reduced-parameter CI round-trip unchanged.

- **Proof-of-possession confidentiality.** The identity PoP exchanged inside the CPace-protected
  session is AEAD-sealed (AES-256-GCM) under a key derived from the CPace ISK,
  `K_pop = HKDF-SHA-256(ISK, info="vox/cpace-pop/v1")`, so the identity public keys and signature are
  not exposed on the wire before the pairwise session exists.
- **PoW precedes CPace.** A responder verifies the join PoW token *before* performing any CPace work,
  so unauthenticated peers cannot force PAKE computation.
- **No zero-key fallback.** `derive_pop_key` and the rendezvous derivation return `Result` and
  propagate the (unreachable for a 32-byte OKM) HKDF-Expand error as `MalformedJoin`; they never
  substitute an all-zero key. `K_pop` is returned in a `Zeroizing` buffer. *(2026-09-19 review: both
  previously zero-filled on the error path — a key no honest peer derives is still a key.)*

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
