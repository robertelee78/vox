# ADR-003: Post-Quantum and Crypto-Agility Policy

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: post-quantum, ml-kem, ml-dsa, crypto-agility, hybrid

## Context

The threat model (ADR-001) includes a nation-state adversary and "harvest now, decrypt later":
traffic recorded today could be decrypted by a future quantum computer. Post-quantum readiness
is therefore required from the start, not retrofitted. This policy constrains every cryptographic
ADR (004, 005, 006, 007, 008, 009). FIPS 203 (ML-KEM), 204 (ML-DSA), and 205 (SLH-DSA) are
finalized, and mature Rust implementations exist (RustCrypto `ml-kem`, libsignal's PQXDH, liboqs/
oqs-rs, composite KEM/signature crates).

## Decision

**Hybrid everywhere — never pure-PQ.** Every primitive combines a classical and a PQ algorithm
so the construction is secure if *either* assumption holds. This defeats harvest-now-decrypt-later
while retaining decades of classical assurance.

- **Key agreement:** X25519 + ML-KEM (PQXDH-style; ADR-004). Normative parameter ML-KEM-768
  (libsignal ships Kyber-768; Signal's spec example is -1024).
- **Signatures:** Ed25519 + ML-DSA (composite). SLH-DSA only where statelessness/conservatism
  justifies its size. Affects log/cert sizes (ADR-007, ADR-008).
- **Symmetric:** AES-256-GCM / ChaCha20-Poly1305 (already PQ-resistant at 256-bit).

**Two normative PQXDH defensive requirements** (from the USENIX'24 formal verification of PQXDH,
Bhargavan et al.; Cryspen):
1. **No public-key type confusion** — curve keys and KEM keys must have *pairwise-disjoint*
   encoding ranges plus algorithm-identifying prefix bytes, so a curve key can never be
   substituted for a KEM key.
2. **KEM shared-secret binding** — bind the KEM public key (and ciphertext) into the AEAD
   associated data; IND-CCA alone is insufficient (re-encapsulation attack).

**Crypto-agility (with an explicit downgrade-rejection rule).** All handshakes, certificates, and log
entries carry explicit, versioned algorithm identifiers and negotiable ciphersuites, so primitives
can be upgraded (e.g. PQ-PCS ratchet, new KEMs) without breaking the wire format. Negotiation is
**floor-gated, not best-effort**: each party advertises only suites at or above the channel's minimum
policy, **rejects** (aborts, no fallback) any proposal below it, binds the negotiated suite into the
transcript, and re-checks it after the handshake — so a network attacker cannot force a weaker suite.
There is no "downgrade to classical" path: hybrid PQ is the floor.

### Algorithm & ciphersuite registry (normative — the single source for every `algo_ids`)

Every algorithm-identified field across the series (`algo_ids` in ADR-004/006/008 headers, suite IDs
in ADR-005/011 handshakes, ADR-007 certs) draws from **this one registry**. An algorithm ID is a
`u16` big-endian: the **high byte is the class** (this *is* the pairwise-disjoint encoding range +
self-describing algorithm-prefix that ADR-002/§requirement-1 mandate) and the low byte is the member.

| Class (hi) | Members (lo → algorithm) |
|---|---|
| `0x01` curve/KEX | `01` X25519 |
| `0x02` KEM | `01` ML-KEM-768 |
| `0x03` signature | `01` Ed25519 · `02` ML-DSA-65 · `03` SLH-DSA-SHA2-128s · `04` **composite** Ed25519+ML-DSA-65 |
| `0x04` AEAD | `01` AES-256-GCM · `02` ChaCha20-Poly1305 |
| `0x05` hash | `01` SHA-256 · `02` BLAKE3-256 |
| `0x06` KDF | `01` HKDF-SHA-256 · `02` Argon2id |
| `0x07` PAKE | `01` CPace-Ristretto255-SHA-512 |
| `0x08` TLS group | `01` X25519MLKEM768 (`0x11EC` on the TLS wire) |

A **ciphersuite** is a named, versioned tuple over these classes — itself a registry entry:

| Suite | Composition |
|---|---|
| `vox-suite-1` (`0x0001`, rank 1) | X25519 · ML-KEM-768 · composite-Ed25519+ML-DSA-65 · AES-256-GCM · SHA-256 · HKDF-SHA-256 · CPace-Ristretto255-SHA-512 |

**Hash is SHA-256 series-wide** (all `prev_hash`/`payload_hash`/CID/fingerprint uses) unless a future
suite names otherwise. **Floor relation:** each suite carries an explicit total **strength rank** (the
column above, *not* the numeric ID). A channel policy names a **minimum suite**; a peer advertises only
suites whose every component rank ≥ the minimum's and **rejects** (aborts) any proposal below it. New
suites are appended with an assigned rank, so the floor advances deliberately and never silently
downgrades. The canonical byte serialization shared by every signed structure is specified once in
**ADR-008** and referenced everywhere, so the same bytes are signed and verified across all ADRs.

**Phasing.** Day-one: PQ *confidentiality* (hybrid PQXDH) and hybrid signatures. Later increment:
post-quantum *post-compromise security* in the ratchet (ADR-004), whose dominant cost is
bandwidth (~2.3 KB per PQ ratchet message vs ~32 B), mitigated by chunking.

## Consequences

### Positive
- Confidentiality survives a future quantum adversary from day one (harvest-now-decrypt-later defeated).
- Hybrid means a flaw in any single PQ primitive does not break security.
- Versioned suites allow upgrading primitives without a flag-day.

### Negative
- Larger keys/signatures: ML-DSA signatures ~2.4–4.6 KB vs Ed25519's 64 B — materially inflates
  the hash-linked log and certificate chains (drives the "sign the payload-hash" design in ADR-008).
- ML-KEM has no static-static DH and bigger messages, complicating Sender-Key distribution (ADR-006).
- More code, larger handshake/storage footprint, more test surface.

### Neutral
- Aligns with the industry direction (Signal PQXDH, Apple PQ3, IETF MLS PQ ciphersuites).

## Links
**Depends on**: ADR-001, ADR-002.
- Depended on by: ADR-004, ADR-005, ADR-006, ADR-007, ADR-008, ADR-009.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
