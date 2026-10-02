# ADR-002: Identity and Key Model

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status:** accepted; built in `crates/vox-core/src/identity/` and `node::prekeys` except where a
requirement says planned:
- §GPG: import and `gpg-agent` delegation are planned. The only `RootSigner` backends are
  `SoftwareRootSigner` and the at-rest `VaultRootSigner`. Armored OpenPGP export with a user ID and
  self-signature is planned (ADR-015).
- §Lifecycle: the succession statement (L2) is planned; no code exists.
- §Backup: the backup bundle is built in the core (`identity::backup`); a user-facing encrypted export
  is planned (ADR-015).
- §Multi-device: shared-root sync over the self-channel (D2) is planned; only the strategy model
  (`identity::device`) exists.
- §Pseudonymity: per-channel identity selection as a client operation is planned.
- §3: deniable mode was removed (PRD-001 R43).

**Deciders:** Robert E. Lee <robert@agidreams.us>

## Context

Vox has no accounts and no central key directory (ADR-001). Identity roots key agreement (ADR-004),
channel join (ADR-005), governance (ADR-007) and per-author log authentication (ADR-008), and follows
the hybrid policy (ADR-003). This ADR specifies every key, its role, its lifecycle and its
encoding. Role separation limits the blast radius of a compromise.

## Requirements

### §1 Root (identity and governance) key

- **R1.1.** The root MUST be a long-term Ed25519 signing key paired with an ML-DSA-65 signing key
  (ADR-003). It signs sub-keys, admin-delegation and governance certificates, and per-sender consent
  grants (ADR-007); there is no membership certificate.
- **R1.2.** The identity fingerprint MUST be `SHA-256(Ed25519_pub ‖ ML-DSA_pub)`.
- **R1.3.** A composite signature MUST be accepted only if both the Ed25519 and the ML-DSA signatures
  verify.
- **R1.4.** The composite public key and signature MUST be the ADR-003 registry type `0x0304`,
  serialized canonically (ADR-008) in fixed component order: `composite_pubkey = Ed25519_pub (32 B) ‖
  ML-DSA-65_pub (1952 B)` and `composite_sig = Ed25519_sig (64 B) ‖ ML-DSA-65_sig (3309 B)`, carried
  inside the canonical struct tag with no separate length prefix.
- **R1.5.** Every key MUST carry an explicit, versioned ADR-003 algorithm identifier (ADR-003
  requirement 1).

### §2 Key-agreement keys (for ADR-004 PQXDH)

- **R2.1.** An identity MUST hold an X25519 identity DH key, used in PQXDH's DH legs. It is part of the
  identity: a prekey ring MUST take it from the identity's secret, not generate its own, so an identity
  restored from backup advertises the same key.
- **R2.2.** A signed prekey MUST be an X25519 key plus an ML-KEM-768 keypair, both signed by the root.
  It MUST rotate every 7 days (`SIGNED_PREKEY_CADENCE_SECS`), and the previous signed prekey MUST be
  retained for one cadence to complete in-flight sessions.
- **R2.3.** One-time prekeys MUST be X25519 and ML-KEM-768 keys, each signed by the root. Each one-time
  prekey MUST be offered for at most one inbound session and MUST NOT be offered again once consumed; a
  concurrent duplicate is graded per ADR-004 C1. The pool MUST be refilled when it drops below its low-water mark
  (`ONE_TIME_PREKEY_LOW_WATER`). When the pool is empty a session MUST fall back to the signed
  (last-resort) prekey, never to no prekey.
- **R2.4.** A restored prekey ring MUST re-derive each public key from its stored secret and refuse a
  mismatch, re-verify each root signature over the canonical body, and refuse a one-time prekey id at
  or above `next_id` or a duplicate id, so a tampered ring is refused and no published id is reissued.

### §3 Message-authentication keys (ADR-006)

- **R3.1.** Each author MUST hold, per channel, a Sender-Key signing key: an Ed25519 + ML-DSA-65 pair
  bound to `(channelID, epoch)` and cross-signed by the root.
- **R3.2.** There is no deniable mode (PRD-001 R43). The per-epoch ephemeral signing key of ADR-009 is
  withdrawn with it.

### §Domain labels (identity-layer signing inputs)

- **R4.1.** Identity-layer artifacts MUST NOT take an ADR-008 struct tag. Each MUST be signed over
  `domain ‖ canonical_body`, with these labels and bodies (ADR-008 arrays, fixed order):

  | Artifact | Domain label | Canonical body | Signer |
  |---|---|---|---|
  | ML-DSA binding statement | `vox/ml-dsa-binding/v1` | `[openpgp_fpr, mldsa_pub, created]` | OpenPGP Ed25519 primary |
  | Identity DH key (IK_B) | `vox/identity-dh-key/v1` | `[algo_X25519, x25519_pub, created]` | composite root |
  | Signed prekey | `vox/signed-prekey/v1` | `[algo_X25519, algo_ML_KEM_768, prekey_id, created, x25519_pub, ml_kem_pub]` | composite root |
  | One-time prekey | `vox/one-time-prekey/v1` | `[algo_X25519, algo_ML_KEM_768, prekey_id, created, x25519_pub, ml_kem_pub]` | composite root |

- **R4.2.** The X25519 identity DH key MUST be root-signed, because ADR-004 consumes it as the
  authenticated `IK_B`.
- **R4.3.** `created` MUST be inside each signed body, so a key cannot be re-dated.

### §GPG OpenPGP integration

- **R5.1.** The Ed25519 root MUST be representable as an OpenPGP key. For a generated root, Vox MUST
  build the v4 public-key packet (algorithm 22 EdDSALegacy, the Ed25519 OID, the `0x40`-prefixed
  263-bit MPI) and its v4 fingerprint (`identity::openpgp`), and the backup MUST carry that
  fingerprint.
- **R5.2. (planned)** A user MAY bind an existing GPG Ed25519 primary or signing subkey as the root;
  its signing MUST then be delegated to `gpg-agent`, so the private key never leaves the agent,
  smartcard or Secure Enclave.
- **R5.3. (planned)** Vox MUST export a generated root in armored OpenPGP form, with a user ID and
  self-signature (ADR-015).
- **R5.4.** The ML-DSA key MUST be committed to the OpenPGP key by a signed binding statement (R4.1).
- **R5.5.** A verifier of a binding statement MUST check both that its `openpgp_fpr` equals the
  fingerprint of the OpenPGP key it trusts and that the Ed25519 signature verifies. Checking the
  signature alone MUST NOT be accepted.

### §Lifecycle

- **L1.** Prekey rotation and one-time-prekey replenishment MUST be automatic (R2.2, R2.3).
- **L2. (planned)** Root-key rotation is identity replacement. Vox MAY carry a succession statement
  (the old root signing the new root's fingerprint). A peer MUST surface a succession as a key-change
  event that needs explicit user acknowledgement (ADR-014), and MUST NOT migrate trust on the signature
  alone.
- **L3.** Root compromise is unrecoverable: recovery MUST be out-of-band re-verification of a new
  fingerprint.

### §Backup

- **B1.** Backing up the root is the user's responsibility; Vox MUST provide an explicit, encrypted
  export (the user-facing export is planned, ADR-015).
- **B2.** The backup MUST include the `self_seed`: a 256-bit random secret generated once at identity
  creation, kept in the identity vault, that keys the personal self-channel (ADR-008). It MUST NOT be
  derived from the public identity key.

### §Multi-device

- **D1.** The multi-device strategy MUST be the member's choice, and Vox MUST NOT attest a link
  between a device and an identity.
- **D2. (planned)** Shared root: the same root on several devices. Devices MUST share received consent
  (SKDMs) and channel state over the identity-keyed self-channel (ADR-008), so adding a device needs no
  re-consent by peers. The `self_seed` (B2) MUST be synced to a new device at enrollment.
- **D3.** Per-device keys: each device is a distinct identity. A member MAY publish device sub-keys
  cross-signed by a shared root as a convention Vox does not enforce. Clients MUST represent device
  keys so consent is never granted to an unrecognized device by accident (ADR-014).

### §Pseudonymity

- **Y1. (planned)** A member MAY join a channel under a dedicated identity key, chosen explicitly per
  channel (ADR-014). Vox MUST NOT reuse an identity across channels unless the user chooses to.

### §Secret hygiene

- **H1.** Every accessor that returns private key material (root seeds, X25519 scalars, ML-KEM seeds,
  backup secrets) MUST return a non-`Copy` zeroize-on-drop buffer, never a bare array.

## Consequences

- No central trust anchor; identity is user-controlled and interoperates with OpenPGP fingerprints.
- Manual fingerprint verification is a UX burden (ADR-014).
- Root loss is unrecoverable; backup is on the user.
- With no device attestation, per-device-key users manage persona coherence themselves.
- Composite signatures and ML-KEM prekeys are larger and slower than classical keys alone (ADR-003,
  ADR-008).

## Related ADRs

Depends on ADR-001. Depended on by ADR-003, ADR-004, ADR-005, ADR-007, ADR-008, ADR-009, ADR-010,
ADR-011, ADR-014. ADR-002 names ML-DSA and ML-KEM directly; the policy governing them is ADR-003
(one-directional, ADR-003 → ADR-002).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
