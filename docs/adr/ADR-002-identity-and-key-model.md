# ADR-002: Identity and Key Model

- **Status**: proposed
- **Date**: 2026-06-19
- **Deciders**: Robert E. Lee <robert@agidreams.us>
- **Tags**: identity, keys, gpg, ed25519, multi-device, pseudonymity

## Context

Vox has no accounts and no central key directory (ADR-001). Identity must be self-sovereign,
verifiable peer-to-peer, and able to root every other cryptographic mechanism: key agreement
(ADR-004), channel join (ADR-005), the signed admin/membership certificate tree (ADR-007), and
the per-author log (ADR-008). It must also support per-channel pseudonymity and a
member-chosen multi-device strategy, and co-exist with the post-quantum policy (ADR-003).

## Decision

**Identity root = GPG/Ed25519.** A member's long-term identity is their Ed25519 key (GPG-
compatible), verified out-of-band by manual fingerprint comparison. No accounts, no phone
numbers, no central directory.

**Role-separated keys (control plane vs data plane).** Distinct keys for distinct jobs, so that
deniability (ADR-009) and governance (ADR-007) do not entangle:
- **Identity/governance key** (signing) — roots the signed membership/admin certificate tree;
  always attributable.
- **Message-authentication key(s)** — per-channel/per-epoch keys for message content; in a
  deniable channel these are deliberately *not* the identity key (ADR-009).
- **Key-agreement keys** — X25519 + ML-KEM prekeys for PQXDH (ADR-003, ADR-004).

**Pseudonymity is operational, by key choice.** Membership is attributable (ADR-009), so a
member wanting unlinkability joins a channel with a *dedicated/pseudonymous* identity key rather
than their main one. Vox must make per-channel identity-key selection easy and explicit.

**Multi-device is the member's choice; Vox does not attest device↔identity links.** A member may
share one identity key across devices or use a unique key per device. Vox provides no
cryptographic device-linking attestation. Consequence: with per-device keys, consent and
membership operate on device keys as identities unless the member links them out of band.

**Post-quantum identity.** The Ed25519 root gains a hybrid PQ co-signature capability
(Ed25519 + ML-DSA) per ADR-003; the GPG/Ed25519 root remains the human-verified anchor.

## Consequences

### Positive
- No central trust anchor; identity is fully user-controlled and portable.
- Role separation cleanly enables both attributable governance and deniable content.
- Per-channel key selection gives strong, simple pseudonymity without a protocol-level anonymity system.

### Negative
- Manual fingerprint verification is a UX burden and a foot-gun if skipped.
- No device-linking means per-device-key users must manage identity coherence themselves; consent
  UX must represent device-keys clearly (ADR-014).
- Key management (backup, rotation, loss) is the user's responsibility; losing the root key is unrecoverable.

### Neutral
- Reuses existing PGP key material and fingerprint-verification culture rather than minting an
  app-specific identity system.

## Links
- Depends on: ADR-001.
- Depended on by: ADR-003, ADR-004, ADR-005, ADR-007, ADR-008, ADR-009.
