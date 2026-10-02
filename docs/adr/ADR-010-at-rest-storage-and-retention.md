# ADR-010: At-Rest Storage and Retention

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: accepted. Built in `crates/vox-core/src/atrest/` and `crates/vox-core/src/node/`, except where a requirement is marked **planned**.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: storage, at-rest, encryption, retention, ttl, device-seizure, app-lock

## Context

Device seizure and local compromise are in the threat model (ADR-001). The local store holds the replicated log (ADR-008), its decrypted plaintext cache and indexes, and key material (ADR-002, ADR-006). At-rest protection has to coexist with the content-addressed, de-duplicated, sparsely replicated log without weakening it. Retention is room policy (ADR-007) and node policy (ADR-023), and deleting history is a person's decision, not a guarantee the network can make for them.

## Requirements

### Two distinct encryption layers

- **AR-1.** A message payload MUST be encrypted once, by its author, under the author's sender-key content key (ADR-006), with a fresh random nonce per payload. Deterministic or convergent encryption MUST NOT be used.
- **AR-2.** The author's `(nonce ‖ ciphertext)` object MUST be replicated byte for byte, so content-addressing (CID = hash of that object, ADR-008) de-duplicates by replicating identical bytes. Per-recipient gating MUST be done by gating key distribution (ADR-007), and MUST NOT be done by re-encrypting per recipient.
- **AR-3.** Each room's local store MUST be sealed at rest under that room's Store Encryption Key (SEK), AEAD per segment. This covers the log, the plaintext cache, the indexes and per-channel key material: the sender chain, received sender keys, admitted authors, and the other per-room key-material segments. This layer MUST NOT change the wire or log format.
- **AR-4.** The root identity private key MUST NOT be stored in any per-room SEK store. It MUST live in a separate identity domain that is unlocked first, because the identity is an input to every SEK.

### Where the identity key lives

- **AR-5.** A generated identity MUST be held in an identity vault (`vault.cbor`), wrapped under an identity factor: Argon2id over the identity passphrase. An imported identity (gpg-agent, smartcard) MAY delegate signing to its agent; the private key then never leaves it.
- **AR-5a.** For a key that cannot sign deterministically (some ML-DSA or smartcard configurations), the identity factor MUST instead unwrap a hardware-stored random secret released only to that identity, never touching raw private-key bytes. That variant is also the fully post-quantum identity factor (AR-9).
- **AR-5b.** Where a platform gates unlock with biometrics, the biometric MAY replace only the identity factor's unlock. It MUST NOT replace the room-passphrase factor.
- **AR-5c. Planned.** The gpg-agent and smartcard signers (AR-5), the hardware-stored secret (AR-5a) and biometric unlock (AR-5b) exist as trait seams only: a design limit, put to the decider (V030-29).

### Double-lock key derivation

- **AR-6.** A room's SEK MUST be wrapped under two independent factors, and both MUST be required to unwrap it:

  ```
  challenge   = "vox/sek-id-factor/v1" || channelID
  id_proof    = Ed25519_sign(identity, challenge)          // deterministic, RFC 8032
  factor_id   = HKDF-SHA-256(id_proof, info = "vox/sek-id/v1")
  factor_pass = Argon2id(room_passphrase, per-room random 128-bit salt, profile)
  KEK         = HKDF(factor_id || factor_pass, info = "vox/sek-wrap/v1")
  wrap        = AEAD_KEK(SEK, random nonce)                // only the wrap is stored
  ```

- **AR-7.** The identity factor MUST be derived without reading raw private-key bytes, so a delegated signer works.
- **AR-8.** A SEK MUST be per room: one room's passphrase MUST NOT open another room's store.

### Post-quantum strength

- **AR-9.** The post-quantum strength of a room store rests on `factor_pass` (Argon2id over the room passphrase). The Ed25519 `id_proof` is classical: a quantum adversary holding the device could forge it. Device seizure needs the passphrase regardless, so this is acceptable; it is stated so the at-rest boundary is not mistaken for post-quantum strength from the identity key.
- **AR-10.** The Argon2id profile MUST be at least 256 MiB, at least 3 passes, with a per-room random 128-bit salt. The floor MUST be enforced at compile time against the production profile (`ADR_MIN_M_COST_KIB`, `ADR_MIN_T_COST`, a `const` assertion). A production build MUST NOT be able to construct or resolve a profile below it. A reduced profile MAY exist under `cfg(test)` only. A cheaper profile for any non-test consumer MUST be a recorded, feature-gated decision, and MUST NOT be a change to `from_id`.
- **AR-11.** A wrap and a vault MUST record their KDF profile id, so the parameters can be raised later by re-wrapping. An unknown stored profile id MUST fail as `AtRestUnlockFailed`, the same as a wrong factor or tampering, on every unlock path. Only a structurally malformed encoding is `MalformedAtRest`.

### Passphrase rotation interaction

- **AR-12.** A SEK MUST be independent of the room passphrase's value. Rotating the passphrase MUST NOT re-encrypt the store.
- **AR-13.** On rotation, an online device MUST re-wrap its existing SEK under the new `factor_pass` and delete the old wrap.
- **AR-14.** An offline device keeps its old wrap until it returns, rejoins (ADR-005), re-wraps and deletes the old wrap. There is no remote re-wrap. A revoked device's stale wrap MUST NOT yield new-epoch content keys, which come only on rejoin (ADR-006).

### App-lock and memory hygiene

- **AR-15.** A SEK MUST be held only in memory, and only while the identity is unlocked. A lock (manual, idle timeout, or on sleep; ADR-015 maps sleep to its triggers) MUST zeroize every SEK and the derived material.
- **AR-16.** Secret memory MUST be zeroized when it is freed. The SEK MUST be `mlock`ed where the platform allows (best effort). **Not built:** derived factors, the KEK, the vault key and opened plaintext are zeroizing but not `mlock`ed.
- **AR-17.** An opened segment's plaintext MUST be returned zeroizing (`store::open_segment` returns `Zeroizing<Vec<u8>>`). `Sek` MUST NOT implement `Clone`.
- **AR-18.** Plaintext caches MUST live inside the SEK-sealed store and MUST NOT be written unencrypted.
- **AR-19.** The two factors have disjoint compromise populations: the identity passphrase is known to one person, and a room passphrase to that room's members. Only the room factor MAY be held in memory, and only while that room is open (ADR-005, ADR-016). The identity passphrase MUST be dropped once the vault is unlocked.

### Per-channel key material

- **AR-20.** Received sender keys MUST be stored as live `ReceiverChain` state (chain key, next iteration, skipped-key cache) in a sealed `KeyMaterial` segment (`SEG_RECEIVERS`). A decrypt that advances a chain MUST persist the advance in the same batch as its rendered row. If that persist fails, the room MUST be poisoned (ADR-006).
- **AR-21.** The composite keys of the authors a room admits MUST be sealed as a `KeyMaterial` segment (`SEG_AUTHORS`). On open, each stored key MUST be checked against its fingerprint, and the genesis creator MUST be re-admitted unconditionally.

### Identity-level key material

- **AR-22.** Key material that belongs to the identity and not to any room MUST be sealed in the profile store under `HKDF-SHA-256(self_seed, info = <its own label>)`, where `self_seed` is the random secret held only inside the identity vault. This covers:
  - the prekey ring (`vox/prekey-ring-sek/v2`, segment kind `PrekeyRing`, AAD `vox/seg/prekey-ring/v1`, code 5);
  - the trust keyring (`vox/trust-keyring-sek/v2`);
  - pending consents (`vox/pending-consent-sek/v1`);
  - the consent order (`vox/consent-order-sek/v1`).

  These blobs MUST NOT be sealed under the Ed25519 `id_proof`, which a quantum adversary with the public key could compute.
- **AR-23.** A version-1 vault's blobs, sealed under the identity factor (`vox/prekey-ring-sek/v1`, `vox/trust-keyring-sek/v1`), MAY be read only by the one-time migration (`node::seal_migration`).
- **AR-24.** The prekey ring MUST be held only while the identity is unlocked and dropped on lock. A ring sealed to another identity, or tampered with, MUST fail as `AtRestUnlockFailed` and MUST NOT be silently regenerated.

### Remembered open rooms

- **AR-25.** A `vox daemon` MUST reopen every room it held open (#208, V210-35). Each such room's SEK and passphrase MUST be kept in store meta under `open-rooms`, sealed with AES-256-GCM under `HKDF-SHA-256(self_seed, info = "vox/open-rooms-sek/v1")`. A room enters the set when it is created, joined or opened. It MUST leave the set only when it is closed on purpose; a stop, crash or reboot keeps it.
- **AR-26.** This deliberately weakens the double-lock for rooms in the set: the disk plus the identity passphrase opens them. A room closed on purpose MUST keep the full double-lock.

### Retention / TTL

R-numbers are PRD-001's.

- **AR-27 (R6).** A room's retention MUST default to forever.
- **AR-28 (R7).** A room's retention MUST be its ADR-007 policy-update `ttl`, set with `vox room retention <room> 1h|1w|1m|<secs>|forever`.
  - Only a holder of `policy` MAY set it.
  - Over the control socket the request MUST be gated on the identity passphrase, because shortening it deletes history.
  - **Planned:** a genesis carries `ttl` 0 (forever) at creation; a room's retention is set only after it is created.
- **AR-29 (R8).** A node MUST also honour its own retention: the `retention` file in its config directory, with `default <dur>` and `<room-prefix> <dur>` lines. It MUST re-read the file every `RETENTION_REREAD_SECS`. If the file is unreadable, it MUST keep the last policy it read.
- **AR-30 (R9).** The effective retention of a room on a node MUST be the shorter of the room's and the node's, where `0` means forever.
  - The node's retention MUST be set on a room when the room is opened (create, join or open), before anything can start a session on it.
  - `vox status --json` MUST report each room's effective retention.
- **AR-31 (R10).** Retention MUST apply retroactively.
  - A sweep MUST run on every tick and after `vox room retention`.
  - Every content entry at or past the effective retention MUST lose its payload body (the `LogDb` page rewritten as the skeleton), its plaintext cache row and its first-seen record, and leave the timeline.
  - The signed hash skeleton MUST remain verifiable (ADR-008).
- **AR-32.** An entry's age MUST run from its author's claimed time, clamped to no later than first sight. An entry this node cannot read MUST age from first sight. The first-seen time MUST be kept per entry in a sealed `Index` segment.
- **AR-33.** On reload, a body-less entry MUST be kept: it verifies and links the feed. A body that arrives already expired MUST be pruned and MUST NOT be rendered.
- **AR-34.** Retention is honoured by clients, not enforced: a malicious client can keep data. This is stated plainly, not implied to be a guarantee.
- **AR-35. Planned.** An anchor's log store keeps bodies regardless of retention, until ADR-023 decision 6 removes that store.

### Gates

- **AR-36.** Retention is proven through the shipped binary by `crates/vox-tui/tests/retention_proof.rs`, which covers retroactive pruning, shortest wins, a late arrival never shown, and the node's retention applied at open. Each case has a mutation that turns it red (ADR-018).

### Open defects and limits

These are known and not fixed. Each stays until it is fixed, with the fixing commit or proof cited.

| # | Defect or limit | Where | Tracked |
|---|---|---|---|
| D1 | Segment seals use random 96-bit GCM nonces with no nonce-count accounting, so the 2^32 random-nonce bound is not enforced. | `atrest/store.rs:145` | #355 |
| D2 | A room's SEK never rotates: it is generated only at create and at join. | `node/channel.rs:1195`, `:1865` | #355 |
| D3 | A peer is served the skeleton of a pruned entry, because the DAG holds only the skeleton. No proof isolates it. | `log/sync.rs` | #357 (v0.3.0) |
| L1 | Only the SEK is `mlock`ed. Derived factors, the KEK, the vault key and opened plaintext are zeroizing but not pinned (AR-16). | `atrest/sek.rs` | design limit; decider question (V030-29) |

## Consequences

- Reading a room's history from a seized device requires the device, the identity passphrase and the room passphrase, except for rooms remembered under AR-25.
- Dedup and sparse replication are untouched, because the at-rest layer is local.
- Rotation preserves history without re-encrypting the store.
- A warm, unlocked device is exposed, and no at-rest scheme protects against a compromised OS.
- The room passphrase raises the bar against outsiders, not against a member.

## Related ADRs

Depends on ADR-002, ADR-005, ADR-006, ADR-007, ADR-008, ADR-023. Depended on by ADR-014, ADR-015, ADR-016.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
