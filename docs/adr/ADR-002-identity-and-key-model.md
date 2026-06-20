# ADR-002: Identity and Key Model

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: identity, keys, gpg, ed25519, multi-device, pseudonymity, post-quantum

## Context

Vox has no accounts and no central key directory (ADR-001). Identity must be self-sovereign,
verifiable peer-to-peer, and must root every other mechanism: key agreement (ADR-004), channel
join (ADR-005), the signed admin/governance certificate tree (ADR-007), per-author log
authentication (ADR-008), and deniable content authentication (ADR-009). It must satisfy the
hybrid post-quantum policy (ADR-003), support per-channel pseudonymity, and accommodate a
member-chosen multi-device strategy. This ADR specifies the complete key model: every key, its
purpose, its lifecycle, and its representation.

## Decision

### Key hierarchy

A Vox identity is a set of keys with strictly separated roles. Role separation is load-bearing:
it is what lets governance be attributable (ADR-007) while message content can be deniable
(ADR-009), and it limits blast radius on compromise.

1. **Identity / governance key (root).** A long-term **Ed25519** signing key, paired for hybrid
   PQ with an **ML-DSA-65** signing key (ADR-003). The pair is the root of trust: it signs
   sub-keys, admin-delegation and governance certificates and per-sender consent grants (ADR-007;
   there is no membership certificate), and — in attributable channels — message
   metadata. The human-verifiable **identity fingerprint** is `SHA-256(Ed25519_pub ‖ ML-DSA_pub)`,
   rendered for manual verification (UX in ADR-014). Both components are always verified together;
   a signature is valid only if *both* the Ed25519 and ML-DSA signatures verify (composite
   signature `sig = Ed25519.sign ‖ ML-DSA.sign`).

2. **Key-agreement keys** (for ADR-004 PQXDH):
   - **X25519 identity DH key**, used in the DH legs of PQXDH.
   - **Signed prekey**: an X25519 key plus an **ML-KEM-768** KEM keypair, both signed by the root.
     Rotated on a fixed cadence (default: every 7 days; previous signed prekey retained one cadence
     period to decrypt in-flight sessions).
   - **One-time prekeys**: a replenished pool of X25519 one-time keys and ML-KEM-768 one-time KEM
     keys, each signed by the root, consumed once per inbound session and never reused. The pool is
     refilled whenever it drops below a low-water mark; depletion falls back to the signed
     (last-resort) prekey, never to no-prekey.

3. **Message-authentication keys** (per channel, ADR-006/ADR-009):
   - **Attributable mode**: the Sender-Key signing key (per author, per channel) — an
     Ed25519+ML-DSA pair bound to `(channelID, epoch)` (ADR-006), cross-signed by the root so
     recipients tie it to the identity.
   - **Deniable mode**: a **per-epoch ephemeral** signing key, bootstrapped through a deniable
     exchange (ADR-009), *not* cross-signed by the root in a transferable way — so message content
     carries no transferable proof of authorship to outsiders.

All keys carry explicit, versioned algorithm identifiers with pairwise-disjoint encoding ranges
and algorithm-prefix bytes (the ADR-003 type-confusion rule).

### GPG integration

The root identity is an OpenPGP-representable Ed25519 key, so it interoperates with existing PGP
key material and fingerprint-verification culture (ADR-001 principle 3):

- **Import**: a user may bind an existing GPG Ed25519 primary (or signing subkey) as the Vox root;
  signing operations are delegated to `gpg-agent`, so the private key need never leave the agent /
  smartcard / Secure Enclave.
- **Generate**: otherwise Vox generates a native Ed25519 root and exports it in OpenPGP format for
  backup and external verification.
- The ML-DSA co-key is a Vox-managed companion key, committed to alongside the OpenPGP key via a
  signed binding statement (the identity fingerprint covers both).

### Lifecycle

- **Prekey rotation** is automatic on cadence; **one-time prekeys** are replenished continuously.
- **Root-key rotation is identity replacement, migrated by TOFU-on-succession (never silently).**
  A new root is a new identity. Vox supports a root-signed *succession statement* (old root signs the
  new root's fingerprint), but peers MUST **surface it as a key-change event requiring explicit user
  acknowledgement** (ADR-014) — never auto-migrate trust on the signature alone. This is critical
  because the root can be *compromised*: a leaked old root can sign a succession to an
  attacker-controlled key, so silent auto-migration would convert "lose this identity" into "attacker
  silently inherits all your channel trust." Therefore a succession only *prompts* migration; genuine
  recovery against a compromised root is out-of-band re-verification of the new fingerprint. Root
  compromise remains unrecoverable by design — there is no central authority to appeal to.
- **Backup** of the root (and its OpenPGP representation) is the user's responsibility; Vox
  provides an explicit, encrypted export.

### Multi-device

Per the project decision, the multi-device strategy is the member's choice and Vox provides **no
device↔identity attestation**:

- **Shared-root**: the same root identity on multiple devices (root key synced by the user out of
  band, e.g. via the OpenPGP export). Devices are indistinguishable; consent/membership operate on
  the one identity.
- **Per-device keys**: each device a distinct identity. Consent and membership then operate on
  device keys as identities. A member who wants their devices recognized as one persona MAY publish
  device sub-keys cross-signed by a shared root and present that linkage to peers — but this is
  member-managed convention, not a Vox-enforced attestation. Clients MUST represent device-keys
  clearly so consent is never granted to an unrecognized device by accident (ADR-014).

### Pseudonymity

Membership is attributable (ADR-009), so unlinkability is achieved operationally: a member joins a
channel under a **dedicated identity key** rather than their main one. Per-channel identity-key
selection is a first-class, explicit client operation (ADR-014); Vox never reuses an identity
across channels without the user choosing to.

## Consequences

### Positive
- No central trust anchor; identity is fully user-controlled, portable, and interoperates with PGP.
- Strict role separation enables attributable governance and deniable content simultaneously, and
  contains compromise blast radius.
- Operational pseudonymity needs no protocol-level anonymity system — just key choice.
- Hybrid Ed25519+ML-DSA root and ML-KEM prekeys make identity post-quantum from day one.

### Negative
- Manual fingerprint verification is a real UX burden and a foot-gun if skipped (mitigated in ADR-014).
- No device attestation means per-device-key users manage persona coherence themselves.
- Root-key loss is unrecoverable; backup discipline is on the user.
- Composite (Ed25519+ML-DSA) signatures and ML-KEM prekeys are larger and slower than classical
  alone (sizing addressed in ADR-003/ADR-008).

### Neutral
- Reuses OpenPGP key material and fingerprint culture instead of minting an app-specific identity.

## Links
**Depends on**: ADR-001.
- Depended on by: ADR-003, ADR-004, ADR-005, ADR-007, ADR-008, ADR-009, ADR-010, ADR-011, ADR-014.

> Note: ADR-002 names the concrete PQ algorithms (ML-DSA, ML-KEM) as direct references; the hybrid
> and crypto-agility *policy* that governs them is ADR-003, which builds on this key model. The
> dependency is one-directional (003 → 002) to keep the ADR graph acyclic.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
