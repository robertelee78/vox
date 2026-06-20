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

1. **Log/transport content encryption (shared).** Message payloads in the log are encrypted under
   channel-shared content keys derived from the Sender-Key material (ADR-006). This is what
   replicates between members; encrypting under shared keys is what preserves cross-member
   de-duplication (same key → same ciphertext → same CID) and sparse replication (ADR-008).
   Per-recipient gating is achieved by gating key *distribution* (ADR-007), never by per-recipient
   payload re-encryption — so dedup is never broken by consent.

2. **Local at-rest encryption (the double-lock).** The entire local store — the log database, the
   decrypted plaintext/index caches, and the private key material — is encrypted at rest under a
   per-channel **Store Encryption Key (SEK)**, AEAD per segment. This is a strictly local layer; it
   does not affect the wire/log format and therefore cannot break dedup or replication.

### Double-lock key derivation

The SEK is wrapped under **two independent factors, both required** to unlock (the "double-lock"):

```
factor_id   = KDF_HKDF(identity-key-material)            // requires the GPG/Ed25519 root,
                                                          // via gpg-agent / Secure Enclave where present
factor_pass = Argon2id(channel_passphrase, salt, params) // memory-hard; per-channel salt
KEK         = HKDF(factor_id || factor_pass, info="vox-sek-wrap/v1")
stored:       wrap = AEAD_KEK(SEK)                        // only the small wrap is stored
```

A device thief who has the device **and** the GPG key still cannot read a channel's store without
that channel's passphrase; conversely the passphrase alone is useless without the identity key.
SEK is per-channel, so compromise of one channel's passphrase never opens another channel's store.

### Passphrase rotation interaction

When an admin rotates the channel passphrase (new epoch, ADR-007), `factor_pass` changes, so the
SEK **wrap** is re-derived and re-stored under the new KEK at rotation time. Only the small wrap is
re-encrypted — the bulk store is *not* re-encrypted, since the SEK itself is unchanged — so history
encrypted under the existing SEK stays readable after rotation. A member offline during rotation
rejoins under the new passphrase (ADR-005) and re-derives the wrap. The prior passphrase no longer
unlocks the new wrap; history readability is preserved deliberately and explicitly, not by
retaining the old passphrase.

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
