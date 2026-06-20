//! At-rest storage & retention (ADR-010) — milestone M8.
//!
//! Device seizure / local compromise is in the Vox threat model (ADR-001). The
//! local store holds the replicated log (ADR-008), decrypted plaintext caches,
//! indexes, and per-channel key material — a goldmine on a seized device. This
//! module is the **local at-rest security boundary**: it encrypts everything local
//! under a per-channel key gated by a **double-lock**, keeps the root identity in a
//! separate **vault**, and provides retention/TTL pruning that does not break the
//! signed log. It deliberately does **not** re-encrypt message content (that is the
//! shared layer-1 encryption already done by M4/M6).
//!
//! ## The two layers, kept separate (ADR-010 §"Two distinct encryption layers")
//! 1. **Content encryption (shared, layer 1) — M4/M6, not redone here.** Each
//!    payload is encrypted once by its author under a Sender-Key-derived content
//!    key with a fresh random nonce (ADR-006). M8 adds only the **content-addressed
//!    object store** ([`store`]): `CID = SHA-256(exact author (nonce ‖ ciphertext)
//!    object)`, dedup **by identical bytes**, never by deterministic encryption
//!    (which ADR-010 rejects).
//! 2. **Local at-rest encryption (the double-lock, layer 2) — M8's core.** The
//!    per-channel store (log DB, plaintext/index caches, per-channel key material
//!    incl. the SEK wrap itself) is AEAD-encrypted per **segment** under a
//!    per-channel **Store Encryption Key** ([`sek::Sek`]).
//!
//! ## The double-lock ([`sek`], [`idfactor`])
//! The SEK is wrapped under **two independent, both-required** factors:
//! - **identity factor** — `factor_id = HKDF(id_proof)` where
//!   `id_proof = Ed25519_sign(identity, "vox/sek-id-factor/v1" ‖ channelID)`,
//!   deterministic (RFC 8032) so it reproduces across unlocks without exporting the
//!   key, and so it works through a delegated gpg-agent/Enclave backend
//!   ([`idfactor::IdentityFactor`] is the seam; the hardware-secret variant is the
//!   PQ-strong alternative for keys that cannot sign deterministically).
//! - **passphrase factor** — `factor_pass = Argon2id(channel_passphrase, salt,
//!   profile)`, memory-hard. The **production** profile is **256 MiB / 3 passes**
//!   ([`sek::Argon2Profile::PRODUCTION`], the default); tests use a tiny reduced
//!   profile so the suite stays fast (the same production-vs-test discipline M3
//!   uses for Equihash). The post-quantum strength of the at-rest scheme rests on
//!   this Argon2id factor, stated plainly in ADR-010.
//!
//! `KEK = HKDF(factor_id ‖ factor_pass)`, `wrap = AEAD_KEK(SEK)`. Only the small
//! wrap (+ salt + profile id) is stored. Either factor alone is useless, and the
//! SEK is per-channel, so one channel's passphrase never opens another's store.
//!
//! ## The identity vault ([`vault`]) — the M1-deferred backend
//! The root identity lives in a **separate protection domain**, unlocked once at app
//! start, never under any channel SEK (that would make unlock circular, since the
//! identity is an *input* to deriving the SEK). [`vault::IdentityVault`] is the
//! complete software generated-key path: the M1 [`crate::identity::backup::IdentityBackup`]
//! bundle wrapped under an Argon2id identity-passphrase factor → AES-256-GCM, with
//! [`vault::IdentityVault::unlock_signer`] yielding a vault-backed
//! [`vault::VaultRootSigner`] that signs verifiably. The gpg-agent/smartcard
//! (imported-key) backend is a delegated [`crate::identity::composite::RootSigner`]
//! over agent IPC — **platform integration**, a documented seam, not a stub.
//!
//! ## App-lock & memory hygiene ([`lock`])
//! The SEK and derived material live **only in memory while unlocked**;
//! [`lock::SecretBuf::lock_now`] zeroizes them on manual lock / idle / sleep,
//! requiring re-auth. Secret memory is **best-effort `mlock`-ed** via the `region`
//! crate's *safe* API (so `#![forbid(unsafe_code)]` holds) with a **defined
//! zeroize-only fallback** when `mlock` is unavailable. Plaintext caches live inside
//! SEK-sealed segments, never written unencrypted.
//!
//! ## Rotation & retention ([`retention`])
//! Because the SEK is independent of the passphrase value, passphrase rotation
//! (ADR-007/M6) re-wraps only the small wrap and deletes the old one
//! ([`retention::rewrap_for_new_passphrase`]); an offline device keeps its old wrap
//! until it returns (no remote rewrap). Admin TTL (default never expire) prunes
//! payload bytes via M5's authenticated pruning so the signed skeleton stays
//! verifiable, and "disappearing" also erases the plaintext cache
//! ([`retention::prune_entry_at_ttl_disappearing`]). Retention is **client-honored,
//! not enforceable** — stated plainly. The KDF profile can be raised over time with
//! a transparent re-wrap ([`retention::upgrade_kdf_profile`]).
//!
//! ## Documented seams (not stubs)
//! - gpg-agent / smartcard / Secure-Enclave **IPC** (release of the identity-gated
//!   secret, or delegated signing): platform integration. The traits
//!   ([`idfactor::IdentityFactor`], [`crate::identity::composite::RootSigner`]) and
//!   the complete software backends ship here.
//! - Screen-security & disappearing-message **UX**: ADR-014/M12. M8 provides the
//!   prune *mechanism* ([`retention`]).
//! - Content encryption: M4/M6 (the shared layer-1, not redone).

pub mod idfactor;
pub mod lock;
pub mod retention;
pub mod sek;
pub mod store;
pub mod vault;

pub use idfactor::{IdentityFactor, SignatureIdentityFactor};
pub use lock::SecretBuf;
pub use retention::{
    prune_entry_at_ttl_disappearing, prune_entry_payload, rewrap_for_new_passphrase,
    upgrade_kdf_profile, PlaintextCacheStore, Rewrap,
};
pub use sek::{Argon2Profile, Sek, SekWrap};
pub use store::{
    content_id, open_segment, seal_segment, Cid, ContentObject, SealedSegment, SegmentKind,
};
pub use vault::{IdentityVault, VaultRootSigner};
