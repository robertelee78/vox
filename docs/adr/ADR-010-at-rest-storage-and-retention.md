# ADR-010: At-Rest Storage and Retention

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: storage, at-rest, encryption, retention, ttl, device-seizure, app-lock

## Context

Device seizure / local compromise is in the threat model (ADR-001). The local store holds the
replicated log (ADR-008) — including private keys (ADR-002), decrypted plaintext caches, and
indexes — a goldmine if a device is taken. Retention is also channel policy (admin-set TTL,
ADR-007). At-rest protection must co-exist with the content-addressed, de-duplicated, sparsely-
replicated log and must not weaken it. This ADR specifies the key hierarchy, the double-lock,
its interaction with passphrase rotation and dedup, app-lock, retention, and the honest limits.

## Decision

### Two distinct encryption layers

These are kept separate and must not be conflated:

1. **Log/transport content encryption (shared).** Each message payload is encrypted **once, by its
   author**, under that author's Sender-Key-derived content key (ADR-006), using AEAD with a
   **fresh random nonce per payload**. Deterministic/convergent encryption is explicitly rejected
   (it leaks plaintext equality). The author's single `(nonce ‖ ciphertext)` object is then
   replicated **byte-for-byte** to all members, so content-addressing (CID = hash of that exact
   object) de-duplicates and enables sparse replication (ADR-008) **by replication of identical
   bytes, not by deterministic encryption**. Per-recipient gating is achieved purely by gating key
   *distribution* (ADR-007), never by per-recipient re-encryption — so dedup is never broken by
   consent.

2. **Local at-rest encryption (the double-lock).** The per-channel local store — the log database, the
   decrypted plaintext/index caches, and **per-channel key material (sender keys, received SKDMs, and
   the SEK wrap itself)** — is encrypted at rest under a per-channel **Store Encryption Key (SEK)**,
   AEAD per segment. This is a strictly local layer; it does not affect the wire/log format and
   therefore cannot break dedup or replication. **The root identity private key is NOT in any per-channel
   SEK store** — it lives in a *separate* protection domain (below). This is deliberate and load-bearing:
   the identity key is an *input* to deriving the SEK (§Double-lock), so it cannot itself sit behind the
   SEK — otherwise unlocking would be circular.

### Double-lock key derivation

The SEK is wrapped under **two independent factors, both required** to unlock (the "double-lock").
The identity factor is derived **without ever reading raw private-key material** — so it works with
non-exportable keys in `gpg-agent`, a smartcard, or the Secure Enclave.

**Where the identity key lives (resolves the would-be unlock circularity).** The identity root is held
in a **separate identity domain**, unlocked once at app start, independent of any per-channel SEK:
- **Imported keys** (GPG/smartcard/YubiKey): in `gpg-agent`/the card; signing is delegated, the private
  key never leaves it.
- **Generated keys**: in an **identity vault** — the root wrapped under an *identity* factor
  (`Argon2id` over an identity passphrase, or a Secure-Enclave-gated random secret), **not** under any
  channel SEK (ADR-014 generate path).
Because the identity key is available once the identity domain is unlocked, deriving each channel's SEK
via `id_proof` below is well-defined and non-circular.

```
// identity factor — reproducible, never exposes the private key
challenge = "vox/sek-id-factor/v1" || channelID
id_proof  = Ed25519_sign(identity, challenge)   // deterministic (RFC 8032) via gpg-agent/Enclave
factor_id = HKDF(id_proof, info="vox/sek-id/v1")

factor_pass = Argon2id(channel_passphrase, per-channel-salt, hardened-params)   // memory-hard
KEK         = HKDF(factor_id || factor_pass, info="vox/sek-wrap/v1")
wrap        = AEAD_KEK(SEK, nonce = random)     // only the small wrap is stored
```

Ed25519 signatures are deterministic (RFC 8032), so `id_proof` is reproducible across unlocks
without exporting the key. For randomized or hardware-bound keys (some ML-DSA/smartcard configs)
the identity factor instead **unwraps a Secure-Enclave/hardware-stored random secret** released only
to that identity — again never touching raw private-key bytes. A device thief with the device **and**
the identity key still cannot read a channel's store without that channel's passphrase; the
passphrase alone is useless without the identity. SEK is per-channel, so one channel's passphrase
never opens another's store.

**Post-quantum strength of the at-rest factors (stated, not assumed).** The Ed25519 `id_proof` is
*classical* — a future quantum adversary with the device could forge it — so the at-rest scheme's
**post-quantum strength rests on the `factor_pass` (Argon2id over the channel passphrase)**, which is
PQ-resistant. This is acceptable because device-seizure at rest requires the passphrase regardless;
but it is stated explicitly so the at-rest boundary is not mis-sold as PQ-from-the-identity-key. Where
a fully-PQ at-rest identity factor is wanted, use the hardware-stored-secret variant above (the secret,
not a quantum-forgeable signature, gates unlock). `factor_pass` parameters: **Argon2id, ≥256 MB,
≥3 passes, per-channel random 128-bit salt**; the wrap AEAD is per-segment with random nonces; the
store records a KDF-profile version so parameters can be raised over time with transparent re-wrap.

### Passphrase rotation interaction

The local SEK is **independent of the channel passphrase value**, so rotation never re-encrypts the
bulk store — each device stores its SEK wrap under the passphrase factor it currently knows. When the
admin rotates the passphrase (new epoch, ADR-007):

- An **online** device re-wraps its existing SEK under the new `factor_pass` immediately (only the
  small wrap changes; SEK and bulk store are untouched) and deletes the old wrap.
- An **offline** device cannot re-wrap until it returns. Stated honestly: until then its store is
  unlockable **only under the old passphrase it still holds** (its old wrap is still on disk). On
  reconnect it rejoins under the new passphrase (ADR-005), re-wraps the SEK, and deletes the old
  wrap. There is no remote/"magic" rewrap of an offline device.

This is the deliberate trade-off: history stays readable across rotation without re-encrypting the
store, at the cost that an offline device's old wrap is invalidated only once that device returns and
re-wraps. Crucially, new-epoch *content* keys are obtained only on rejoin (ADR-006), so a **revoked**
device gains nothing from a stale local wrap — it can read its old local history but no new traffic.

### App-lock and memory hygiene

- The SEK lives **only in memory** while the app is unlocked. Lock (manual, idle-timeout, or on
  sleep) zeroizes the SEK and derived material from memory, requiring re-authentication (identity
  key + passphrase, or — on platforms with a Secure Enclave — a biometric-gated re-wrap of the
  identity factor so biometrics never replace the passphrase factor, only the identity factor's
  unlock).
- Secrets use locked, zeroized memory (`mlock`/`zeroize`); plaintext caches are themselves inside
  the SEK-encrypted store, never written unencrypted.
- Screen-security and disappearing-message UX are specified in ADR-014.

### Retention / TTL

Admin-set TTL (ADR-007); default **never expire**; changeable anytime. Clients are expected to honor
it by pruning payload bytes — the log's payload-hash signing keeps the hash-skeleton verifiable
after pruning (ADR-008). "Disappearing" deletes both the plaintext cache and the payload bytes at
TTL. This is **client-honored, not enforceable**: a malicious client can retain data; we state this
plainly rather than implying a guarantee we cannot make.

## Consequences

### Positive
- Reading a channel's history at rest requires device **and** identity key **and** channel
  passphrase — strong defense-in-depth against seizure.
- The two-layer design keeps dedup/sparse-replication intact while still encrypting everything local.
- Passphrase rotation preserves history without re-encrypting the bulk store and without retaining
  old passphrases.
- App-lock plus memory hygiene bounds exposure of a warm device.

### Negative
- The double-lock adds key-management complexity (two factors, per-channel SEK, wrap re-derivation on
  rotation).
- The channel passphrase is shared among members, so as a second factor it raises the bar against an
  outsider/thief, not against a malicious *member*.
- A warm, unlocked device with SEK in memory is exposed — hence mandatory lock/timeout — and no
  at-rest scheme defends a fully compromised OS/root.

### Neutral
- Mechanically adjacent to ADR-008, but kept as a separate decision because it is a distinct security
  boundary (local-at-rest vs replicated-log).

## Links
**Depends on**: ADR-002, ADR-007, ADR-008.
- Depended on by: ADR-014.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
