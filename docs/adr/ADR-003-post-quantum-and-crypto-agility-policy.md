# ADR-003: Post-Quantum and Crypto-Agility Policy

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status:** accepted and built. The registry is `crates/vox-core/src/suite.rs`; the floor is in the
signed genesis policy (`ChannelPolicy::min_suite`) and enforced in `pairwise::pqxdh` and the ADR-005
join. PQ post-compromise security (§Scope) is not built.
**Deciders:** Robert E. Lee <robert@agidreams.us>

## Context

ADR-001 defends content confidentiality against an on-path adversary, including harvest now, decrypt
later. That is the one defended property that is time-sensitive, so post-quantum readiness is needed
from the start. FIPS 203 (ML-KEM), 204 (ML-DSA) and 205 (SLH-DSA) are final, and mature Rust
implementations exist. This policy constrains ADR-004 through ADR-009. Metadata and traffic analysis
stay non-goals (ADR-001).

## Requirements

### Hybrid everywhere

- **H1.** Every primitive MUST combine a classical and a post-quantum algorithm, so the construction
  holds if either assumption holds. Vox MUST NOT use a pure-PQ construction.
- **H2.** Key agreement MUST be X25519 + ML-KEM-768 (PQXDH-style, ADR-004).
- **H3.** Signatures MUST be composite Ed25519 + ML-DSA-65. SLH-DSA MAY be used only where its
  statelessness justifies its size.
- **H4.** Symmetric encryption MUST be AES-256-GCM or ChaCha20-Poly1305.

### PQXDH defensive requirements (Bhargavan et al., USENIX Security 2024)

- **Requirement 1 (no public-key type confusion).** Curve keys and KEM keys MUST have pairwise-disjoint
  encoding ranges and algorithm-identifying prefixes, so a curve key can never be read as a KEM key.
  The registry class byte (§Registry) is that prefix.
- **Requirement 2 (KEM shared-secret binding).** The KEM public key and ciphertext MUST be bound into
  the AEAD associated data (ADR-004 §Decision); IND-CCA alone MUST NOT be relied on.

### Crypto-agility and downgrade rejection

- **G1.** Every handshake, certificate and log entry MUST carry explicit, versioned algorithm
  identifiers from §Registry, so primitives can be upgraded without breaking the wire format.
- **G2.** Negotiation MUST be floor-gated: a party MUST advertise only suites at or above the channel's
  minimum, MUST abort (no fallback) on a proposal below it with `Error::SuiteBelowFloor`, MUST bind the
  negotiated suite into the transcript, and MUST re-check it after the handshake.
- **G3.** There MUST NOT be a downgrade-to-classical path: hybrid PQ is the floor.

### §Registry (normative: the one source of every `algo_ids`)

- **K1.** An algorithm ID MUST be a big-endian `u16` whose high byte is the class and low byte the
  member:

  | Class (hi) | Members (lo → algorithm) |
  |---|---|
  | `0x01` curve/KEX | `01` X25519 |
  | `0x02` KEM | `01` ML-KEM-768 |
  | `0x03` signature | `01` Ed25519 · `02` ML-DSA-65 · `03` SLH-DSA-SHA2-128s · `04` composite Ed25519+ML-DSA-65 |
  | `0x04` AEAD | `01` AES-256-GCM · `02` ChaCha20-Poly1305 |
  | `0x05` hash | `01` SHA-256 · `02` BLAKE3-256 |
  | `0x06` KDF | `01` HKDF-SHA-256 · `02` Argon2id |
  | `0x07` PAKE | `01` CPace-Ristretto255-SHA-512 |
  | `0x08` TLS group | `01` X25519MLKEM768 (`0x11EC` on the TLS wire) |

- **K2.** A ciphersuite MUST be a named, versioned registry entry with an explicit strength rank:

  | Suite | Composition |
  |---|---|
  | `vox-suite-1` (`0x0001`, rank 1) | X25519 · ML-KEM-768 · composite Ed25519+ML-DSA-65 · AES-256-GCM · SHA-256 · HKDF-SHA-256 · CPace-Ristretto255-SHA-512 |

- **K3.** The hash MUST be SHA-256 series-wide (`prev_hash`, `payload_hash`, CID, fingerprint) unless a
  future suite names otherwise.
- **K4.** Every signed structure MUST use the one canonical serialization of ADR-008.
- **K5.** A shipped build MUST register only production suites: a suite ranked below `vox-suite-1` MUST NOT
  exist in it, so no production peer can propose, accept or set a floor at one.

### §Floor relation

- **F1.** A suite's strength MUST be its registry rank, not its numeric ID. A suite meets a floor iff
  its rank is at or above the floor suite's rank. There is no per-component rank: a suite stronger in
  one class and weaker in another MUST be ranked when it is registered.
- **F2.** New suites MUST be appended with an assigned rank, so the floor advances only deliberately.
- **F3.** A channel's minimum suite MUST be the `min_suite` field of its signed genesis policy
  (ADR-007, tag `0x000D`) and MUST name a registered suite. New channels MUST default to
  `vox-suite-1` (`SuiteFloor::DAY_ONE`).
- **F4.** The floor is fixed at creation. Since ADR-007's 2026-10-02 amendment (V030-32) a policy update
  carries retention only, and an update carrying `min_suite` MUST be refused.
- **F5.** The floor MUST be enforced in every handshake that carries a suite:
  `pairwise::pqxdh::{initiate, accept}` (and so `Session::{initiate, accept}`), and the ADR-005 join
  (`JoinContext::new`, `join_initiate`, `join_accept`), before any PoW or CPace work. `SuiteFloor`
  MUST be a distinct type from a proposed suite ID.
- **F6.** The TLS group is outside the suite: the transport (ADR-011) MUST pin X25519MLKEM768 on both
  sides as a build-time floor.

### §Scope

- **S1.** PQ confidentiality (hybrid PQXDH) and PQ authentication (composite signatures) MUST be
  present everywhere from the first release.
- **S2.** PQ post-compromise security in the ratchet (ADR-004) is a separate capability with its own
  ADR, built complete when built. It MUST NOT be described as a deferred part of confidentiality.

## Consequences

- Confidentiality is designed to survive a future quantum adversary, provided the lattice half holds.
- ML-DSA signatures (about 2.4–4.6 KB against Ed25519's 64 B) inflate the log and certificate chains;
  ADR-008 signs payload hashes for this reason.
- ML-KEM has no static-static DH and larger messages, which complicates Sender-Key distribution
  (ADR-006).

## Related ADRs

Depends on ADR-001 and ADR-002. Depended on by ADR-004, ADR-005, ADR-006, ADR-007, ADR-008, ADR-009,
ADR-011.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
