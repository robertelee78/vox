# ADR-010: At-Rest Storage and Retention

**Status**: implemented (M8, `crates/vox-core/src/atrest/`)
**Date**: 2026-06-19
**Updated**: 2026-09-24 — retention is switched on (ADR-023 M23.1): the room's policy-update `ttl` and the node's own `retention` file, shortest wins, applied retroactively by a sweep; see §"Retention / TTL". 2026-09-20 — identity-level key material (the prekey ring) given its at-rest home and derivation (ADR-016 M14.3); admitted channel authors and received sender keys sealed as key material (M14.5); the two factors' compromise populations stated explicitly (M14.7c). 2026-09-19 — Implementation notes (M8) added; Argon2id profile floor made structural (test-only reduced profile no longer resolvable in production); unknown-profile oracle collapsed on every unlock path.
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

**As built (2026-09-24, ADR-023 M23.1, PRD-001 R6–R10).**
- The room's retention is the ADR-007 policy-update `ttl`, authored with `vox room retention <room>
  1h|1w|1m|<secs>|forever` by a holder of `policy` (refused to anyone else, and gated on the identity
  passphrase over the control socket because shortening it deletes stored history). The node's own is
  the `retention` file in its config directory (`default <dur>` and `<room-prefix> <dur>` lines),
  re-read every minute. The effective retention is the shorter; `0` is forever.
- A sweep runs on every tick (1 s) and after `vox room retention`: every content entry whose age is at
  or past the effective retention loses its payload body (`LogDb` page rewritten with the skeleton),
  its plaintext cache row and its first-seen record, and leaves the timeline. It is retroactive by
  construction and costs what it prunes: bodies are indexed by age.
- Age runs from the author's claimed time clamped to no later than first sight; the first-seen time
  is kept per entry in a sealed `Index` segment beside its `LogDb` page. An entry this node cannot
  read ages from first sight.
- Reload keeps a body-less entry (it verifies and links the feed), and a synced skeleton is stored
  like any other entry; a body that arrives already expired is pruned instead of rendered.
- **Gates** (`crates/vox-tui/tests/retention_proof.rs`, shipped binary, release, `--ignored`):
  retroactive — 40 + 60 messages, the room set to 30 s with the 40 at 47 s: both members' `vox room
  read` show exactly the 60, both stores hold 60 cache rows and 107 log pages, the restarted node
  opens the room, and the 60 go at 28 s; shortest wins — room 1 week, one node 60 s: that node shows
  0 of 10 at 59 s while the other shows 10; late arrival — 5 messages synced to that node after 65 s
  never shown in 248 reads. Mutations: sweep disabled (104 rows stay), reload refusing a pruned entry
  (room comes back `[closed]`), node retention ignored (alice keeps 12 rows), arrival check removed
  (the 5 shown).
- **Not built:** the genesis `ttl` is still `0` at creation (a room is created forever and set after);
  an anchor's log store keeps bodies regardless of retention (ADR-023 decision 6 removes that store);
  a peer is served the skeleton of a pruned entry because the DAG holds only the skeleton, but no gate
  isolates that.

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

## Implementation notes (M8)

These record the concrete decisions made building this ADR (`crates/vox-core/src/atrest/`), so the spec and code stay in lockstep:

- **The two factors have disjoint compromise populations (stated 2026-09-20).** §"Double-lock key
  derivation" says the factors are independent; what makes that true in practice is *who knows each one*.
  The **identity factor** is known to exactly one person — it is the passphrase on that person's private
  key, in the same sense as an SSH or GPG key passphrase. The **channel passphrase** is known to the
  channel's quorum and to nobody else: group-confidential, not public. Breaking one therefore tells an
  attacker nothing about the other, and the case this most protects is the obvious one — a member (or a
  former member) who knows the channel passphrase still cannot open *another* member's store without that
  device's identity factor. A further property worth keeping: one factor lives **off the device**, in
  people's heads and out-of-band channels, which a device-local secret would not — so device compromise
  alone does not hand over both. Only the *group* factor is ever held in memory, and only while a channel
  is open (ADR-016 M14.7c); the identity credential unlocks the vault and is dropped, never retained.
- **Received sender keys are per-channel key material (M14.5b).** The `ReceiverChain`s built from other
  members' SKDMs are sealed under the channel SEK as a `KeyMaterial` segment (`SEG_RECEIVERS`) — this is
  §"Two distinct encryption layers"'s "received SKDMs" clause, made concrete. The **live** chain state is
  what is stored (chain key, next iteration, skipped-key cache), not the originating SKDM, because the
  head and the cache are the replay defence (ADR-006 Implementation notes). A decrypt that advances a
  chain persists the advance in the same batch as the rendered plaintext row, and a failed persist
  **poisons** the channel rather than leaving an in-memory advance the next open would undo — an
  unpersisted advance would let a consumed iteration decrypt again.
- **Admitted authors are per-channel key material (M14.5).** The composite keys of the identities whose
  entries a channel accepts are sealed under that channel's SEK as a `KeyMaterial` segment
  (`SEG_AUTHORS`), alongside the sender chain and the manifest — they are public keys, but *which*
  identities a device admits is exactly the kind of metadata §"Two distinct encryption layers" puts
  behind the double-lock. On open, each stored pair is re-checked (the fingerprint must be the key's own)
  and the genesis creator is re-inserted unconditionally, so a tampered segment can neither admit an
  identity under another's name nor exclude the creator whose signature the channelID commits to.
- **Identity-level key material: a third home, single-factor by design (M14.3).** §"Two distinct
  encryption layers" names two homes — the per-channel SEK store for *per-channel* material, and the
  separate identity domain (the passphrase-sealed vault) for the root. The ADR-002 §2 key-agreement keys
  are neither: they are **identity-level** (shared by every channel) and they rotate automatically while
  the app runs. Both existing homes are wrong for them: re-sealing the vault needs the identity
  passphrase, which is deliberately never retained (ADR-015), so automatic rotation would have to
  re-prompt; and a per-channel SEK would make prekeys unavailable exactly when that channel is closed.
  So the ring is a `SegmentKind::PrekeyRing` segment (new kind, AAD tag `vox/seg/prekey-ring/v1`, stable
  code 5) in the profile store, sealed under a key derived from the **identity factor alone**:
  `ring_channel = SHA-256("vox/prekey-ring-pseudo-channel/v1")` (a reserved pseudo-channel, not a real
  channelID), then `factor_id` exactly as §"Double-lock key derivation" defines it, then
  `ring_key = HKDF-SHA-256(factor_id, info = "vox/prekey-ring-sek/v1")` — the extra step keeping the ring
  key domain-separated from every other `factor_id` consumer. This is single-factor **and not a
  weakening**: the identity factor requires the unlocked identity domain, which requires the identity
  passphrase, so the ring is gated by the same secret as the root it belongs to; it is derived without
  reading raw private-key bytes (so a delegated `gpg-agent`/Enclave signer works); and it is non-circular
  for the same reason per-channel SEKs are — the identity domain unlocks first. The node holds the ring
  only while unlocked and drops it on app-lock, so no key-agreement secret sits behind a lock. A ring
  sealed to another identity, or tampered with, fails as `AtRestUnlockFailed` and is **never** silently
  regenerated (that would invalidate every published bundle); on decode every stored secret must re-derive
  its recorded public key and every root signature must verify (ADR-002 Implementation notes). The
  ADR-016 M13 restart gate proves the whole composed path at production Argon2id parameters.
- **Argon2id profile floor is structural (`atrest::sek::Argon2Profile`).** The "≥256 MB, ≥3 passes"
  floor above is encoded as `ADR_MIN_M_COST_KIB` / `ADR_MIN_T_COST` and enforced at **compile time**
  against the production profile (256 MiB / 3 passes / p=1, id 1, the default) by a `const` assertion.
  The profile's fields are private, so the only profiles a production build can construct or resolve
  from a stored id are the floor-meeting constants; there is no runtime "is this profile strong enough"
  check to forget. The fast reduced profile (8 KiB / 1 pass, id 2) that keeps the unit suite cheap
  exists only under `cfg(test)` — a wrap or vault naming id 2 is un-openable in a production build. An
  integration test (`crates/vox-core/tests/atrest_profile_floor.rs`), which links the crate without
  `cfg(test)`, proves that every id a production build resolves meets the floor. *(2026-09-19 review:
  previously id 2 resolved in production, so an 8 KiB/1-pass wrap unlocked.)* Should a non-test
  consumer ever need a cheaper profile (e.g. a client integration test), that is a deliberate,
  feature-gated decision recorded here — never a change to `from_id`.
- **Unknown stored profile id is an unlock failure everywhere.** `profile_id` is a persisted field of
  the SEK wrap and the identity vault; distinguishing "unknown profile" from "wrong factor / tamper"
  would hand whoever holds the file an oracle. `SekWrap::profile()` is the single resolver (used by
  unwrap, rotation re-wrap and KDF upgrade) and `IdentityVault::unlock` applies the same collapse, so
  all of them surface `AtRestUnlockFailed`; only a structurally malformed wrap/vault encoding is
  `MalformedAtRest`.
- **Opened segment plaintext is a secret.** `store::open_segment` returns the decrypted segment in a
  `Zeroizing<Vec<u8>>` — it is exactly what the double-lock protects — so a caller that drops it does
  not leave the cleartext in freed memory. `EpochKey` (ADR-009) likewise has no `Clone`, matching the
  `Sek` posture: one owner, one wipe point. *(2026-09-19 secret-hygiene sweep.)* Both are pinned as
  non-`Clone` by an autoref-specialization check (`test_support::is_clone!`) with a positive control —
  replacing a test that compiled for any type and proved nothing.
- **Known gaps (recorded 2026-09-19).** There is no persistence layer: no file I/O, segment map, or
  database — `SekWrap`, `IdentityVault`, `SealedSegment` are codecs and mechanisms the node runtime
  will drive. Only the SEK is `mlock`ed; derived factors, the KEK, the vault key and opened plaintext
  are zeroizing but not pinned. The SEK never rotates and segment re-seals use random 96-bit nonces
  with no nonce-count accounting (the 2^32 random-nonce GCM bound is not enforced). The
  hardware-stored-secret identity factor, gpg-agent/smartcard signers and biometric-gated re-wrap are
  trait seams only. TTL evaluation lives in governance policy; `retention` provides the prune
  mechanism. *(The node runtime now drives it — see §"Retention / TTL", 2026-09-24.)*

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
