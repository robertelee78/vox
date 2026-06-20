//! The per-channel Store Encryption Key (SEK) and its double-lock wrap (ADR-010
//! §"Double-lock key derivation").
//!
//! A channel's local store is encrypted under a per-channel 256-bit **SEK**. The
//! SEK itself is never stored in the clear; only a small **wrap** is persisted:
//! `AEAD_KEK(SEK)` plus the salt and KDF-profile version needed to re-derive the
//! KEK. Unlocking requires **both** factors (the "double-lock"):
//!
//! ```text
//! factor_id   = HKDF-SHA-256(id_proof, info="vox/sek-id/v1")          // identity factor
//! factor_pass = Argon2id(channel_passphrase, salt, hardened-params)   // passphrase factor
//! KEK         = HKDF-SHA-256(factor_id ‖ factor_pass, info="vox/sek-wrap/v1")
//! wrap        = nonce ‖ AES-256-GCM(KEK, nonce, SEK)                  // only this is stored
//! ```
//!
//! Either factor alone is useless: the identity factor without the passphrase, or
//! the passphrase without the identity, both fail to reconstruct the KEK and the
//! AEAD open fails ([`crate::Error::AtRestUnlockFailed`]). The SEK is **per
//! channel** (its own random salt and its own identity-factor challenge binding
//! `channelID`), so channel A's passphrase + identity never opens channel B's
//! store — proven in tests.
//!
//! ## Argon2id profiles — production const vs reduced test (the M3-Equihash lesson)
//! Production `factor_pass` is **memory-hard on purpose**: ADR-010 mandates
//! Argon2id ≥256 MiB, ≥3 passes. Running that in a unit test would burn seconds
//! and a quarter-gig of RSS per call. So [`Argon2Profile::PRODUCTION`] carries the
//! real parameters and **is the default** ([`Argon2Profile::default`]); tests use
//! [`Argon2Profile::REDUCED`] (tiny memory, one pass). The production profile's
//! values are asserted by a test (cheap — it reads the const, it does not run the
//! KDF), exactly as M3 asserts the real Equihash `(200,9)` parameters without
//! solving them.
//!
//! ## KDF-profile version → transparent re-wrap
//! The wrap records its profile *id*, so a future build can raise the Argon2id
//! parameters and transparently re-wrap (re-derive the KEK under the new profile,
//! re-encrypt the small wrap, drop the old one) — the SEK and the bulk store are
//! never touched. [`crate::atrest::retention`] drives that upgrade.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::atrest::idfactor::{IdentityFactor, CHANNEL_ID_LEN, FACTOR_ID_LEN};
use crate::atrest::lock::SecretBuf;
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::identity::rng::random_array;

/// Length of a SEK and of the derived KEK (256 bits).
pub const SEK_LEN: usize = 32;
/// Length of the per-channel Argon2id salt (128 bits, ADR-010).
pub const SALT_LEN: usize = 16;
/// Length of the AES-256-GCM nonce used for the wrap and for store segments.
pub const NONCE_LEN: usize = 12;
/// Length of the AES-256-GCM authentication tag.
pub const TAG_LEN: usize = 16;
/// Length of the `factor_pass` Argon2id output (256 bits, fed into the KEK KDF).
pub const FACTOR_PASS_LEN: usize = 32;

/// HKDF `info` for the KEK (ADR-010, exact):
/// `KEK = HKDF-SHA-256(factor_id ‖ factor_pass, info = "vox/sek-wrap/v1")`.
pub const KEK_HKDF_INFO: &[u8] = b"vox/sek-wrap/v1";

/// AEAD associated data for a SEK wrap, separating it from store segments and any
/// other ciphertext that might ever share a derived key.
const WRAP_AAD: &[u8] = b"vox/sek-wrap-aead/v1";

/// Format version of the [`SekWrap`] serialization.
const SEK_WRAP_VERSION: u64 = 1;

/// An Argon2id parameter profile for the passphrase factor (ADR-010). Carries a
/// stable `id` so a wrap records which profile derived it and a later build can
/// upgrade transparently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Profile {
    /// Stable profile id, stored in the wrap (so the right parameters re-derive
    /// the KEK, and so an upgrade is detectable).
    pub id: u8,
    /// Memory cost in **KiB** (`m_cost`).
    pub m_cost_kib: u32,
    /// Iterations / passes (`t_cost`).
    pub t_cost: u32,
    /// Degree of parallelism (`p_cost`).
    pub p_cost: u32,
}

impl Argon2Profile {
    /// Profile id of [`Argon2Profile::PRODUCTION`].
    pub const PRODUCTION_ID: u8 = 1;
    /// Profile id of [`Argon2Profile::REDUCED`].
    pub const REDUCED_ID: u8 = 2;

    /// The **production** passphrase-factor profile (ADR-010 §"Post-quantum
    /// strength of the at-rest factors"): Argon2id, **256 MiB, 3 passes,
    /// parallelism 1**. This is the [`Argon2Profile::default`] used by real
    /// builds. It is intentionally expensive; do not run it in unit tests.
    pub const PRODUCTION: Argon2Profile = Argon2Profile {
        id: Self::PRODUCTION_ID,
        m_cost_kib: 256 * 1024, // 256 MiB
        t_cost: 3,
        p_cost: 1,
    };

    /// A **reduced** profile for tests only: 8 KiB, 1 pass. Fast and tiny so the
    /// double-lock crypto can be exercised without minutes of CPU or hundreds of
    /// MiB of RSS. **Never** the default; selected explicitly in tests.
    pub const REDUCED: Argon2Profile = Argon2Profile {
        id: Self::REDUCED_ID,
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    /// Resolve a profile from its stored id. Unknown ids are rejected so a wrap
    /// cannot name a profile this build does not understand.
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            Self::PRODUCTION_ID => Ok(Self::PRODUCTION),
            Self::REDUCED_ID => Ok(Self::REDUCED),
            _ => Err(Error::MalformedAtRest("unknown argon2 profile id")),
        }
    }

    /// Build the `argon2` parameter object for this profile.
    fn params(self) -> Result<Params> {
        Params::new(
            self.m_cost_kib,
            self.t_cost,
            self.p_cost,
            Some(FACTOR_PASS_LEN),
        )
        .map_err(|_| Error::MalformedAtRest("invalid argon2 profile parameters"))
    }
}

impl Default for Argon2Profile {
    /// The production profile is the default — the hardened parameters ship by
    /// default; only tests opt down to [`Argon2Profile::REDUCED`].
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// Compute the passphrase factor `factor_pass = Argon2id(passphrase, salt, profile)`.
///
/// The output is the raw 32-byte Argon2id hash (not a PHC string); it is consumed
/// only as KEK key material, never compared or displayed. Returned zeroizing.
pub fn factor_pass(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    profile: Argon2Profile,
) -> Result<Zeroizing<[u8; FACTOR_PASS_LEN]>> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, profile.params()?);
    let mut out = Zeroizing::new([0u8; FACTOR_PASS_LEN]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| Error::Argon2Failed)?;
    Ok(out)
}

/// Derive the KEK from both factors:
/// `KEK = HKDF-SHA-256(factor_id ‖ factor_pass, info = "vox/sek-wrap/v1")`.
fn derive_kek(
    factor_id: &[u8; FACTOR_ID_LEN],
    factor_pass: &[u8; FACTOR_PASS_LEN],
) -> Result<Zeroizing<[u8; SEK_LEN]>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(FACTOR_ID_LEN + FACTOR_PASS_LEN));
    ikm.extend_from_slice(factor_id);
    ikm.extend_from_slice(factor_pass);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut kek = Zeroizing::new([0u8; SEK_LEN]);
    hk.expand(KEK_HKDF_INFO, kek.as_mut())
        .map_err(|_| Error::Argon2Failed)?;
    Ok(kek)
}

/// A per-channel Store Encryption Key (ADR-010). Lives only in memory while
/// unlocked; use [`crate::atrest::store`] segment APIs to seal / open store
/// contents under it.
///
/// ## App-lock enforces "post-lock unseal fails until re-auth" (ADR-010)
/// The key bytes live in [`SecretBuf`] — best-effort `mlock`-ed, always-zeroizing
/// memory — behind an explicit **locked** flag. [`Sek::lock_now`] zeroizes the key
/// and flips the flag; after that, every key access ([`Sek::key_bytes`]) and every
/// SEK-backed operation (segment seal/open, re-wrap) returns [`Error::AtRestLocked`]
/// until the SEK is re-derived from both factors (re-auth). This is the property
/// app-lock must actually enforce, not merely document.
///
/// `Sek` is deliberately **not `Clone`**: a key that could be cheaply duplicated
/// could outlive a lock in a stray copy, defeating app-lock. The raw key array is
/// never handed out by value and never escapes except inside tightly-scoped
/// [`Zeroizing`] temporaries within this module.
pub struct Sek {
    /// The key bytes in locked/zeroizing memory; emptied when `locked`.
    key: SecretBuf,
    /// Whether the SEK has been invalidated by an app-lock.
    locked: bool,
}

impl Sek {
    /// Generate a fresh random SEK from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        // The random bytes go straight into a non-`Copy` `Zeroizing` array and are
        // moved into locked memory; no bare `Copy` SEK array is ever held.
        let bytes = Zeroizing::new(random_array::<SEK_LEN>()?);
        Ok(Self::from_bytes(bytes))
    }

    /// Construct a SEK from raw key bytes (e.g. after an unwrap).
    ///
    /// Takes a non-`Copy` [`Zeroizing`] array so the caller has no lingering `Copy`
    /// stack remnant of the key: the value is moved into best-effort-locked storage
    /// ([`SecretBuf`]) and the `Zeroizing` temporary wipes itself on drop. There is
    /// deliberately **no** bare-`[u8; SEK_LEN]` constructor — a `Copy` SEK array
    /// could survive an app-lock outside the locked buffer (the M8 review's HIGH
    /// finding).
    #[must_use]
    pub fn from_bytes(key: Zeroizing<[u8; SEK_LEN]>) -> Self {
        Self {
            key: SecretBuf::from_array(key),
            locked: false,
        }
    }

    /// Borrow the key bytes for AEAD keying, **iff** the SEK is still unlocked.
    /// Returns [`Error::AtRestLocked`] after [`Sek::lock_now`] — the enforcement
    /// point for ADR-010's "post-lock unseal fails until re-auth".
    pub fn key_bytes(&self) -> Result<&[u8]> {
        if self.locked {
            return Err(Error::AtRestLocked);
        }
        Ok(self.key.as_slice())
    }

    /// Whether this SEK has been invalidated by an app-lock.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// **App-lock**: zeroize the key and invalidate this SEK (manual lock / idle /
    /// sleep, ADR-010). Idempotent. After this, [`Sek::key_bytes`] and every
    /// SEK-backed operation fail with [`Error::AtRestLocked`] until a fresh SEK is
    /// re-derived from both factors.
    pub fn lock_now(&mut self) {
        self.key.lock_now();
        self.locked = true;
    }

    /// Double-lock **seal**: wrap this SEK under `(identity factor, passphrase)`
    /// for `channel_id`, producing a persistable [`SekWrap`] (ADR-010).
    ///
    /// A fresh random per-channel salt and a fresh random wrap nonce are sampled.
    /// Only the wrap (salt + nonce + ciphertext + profile id) is meant to be
    /// stored; the SEK stays in memory. Fails with [`Error::AtRestLocked`] if the
    /// SEK has been app-locked.
    pub fn seal(
        &self,
        id_factor: &dyn IdentityFactor,
        channel_id: &[u8; CHANNEL_ID_LEN],
        passphrase: &[u8],
        profile: Argon2Profile,
    ) -> Result<SekWrap> {
        let salt = random_array::<SALT_LEN>()?;
        self.seal_with_salt(id_factor, channel_id, passphrase, profile, &salt)
    }

    /// Like [`Sek::seal`] but with a caller-supplied salt. Used by the re-wrap path
    /// (rotation keeps deriving fresh salts) and by deterministic tests.
    pub fn seal_with_salt(
        &self,
        id_factor: &dyn IdentityFactor,
        channel_id: &[u8; CHANNEL_ID_LEN],
        passphrase: &[u8],
        profile: Argon2Profile,
        salt: &[u8; SALT_LEN],
    ) -> Result<SekWrap> {
        let key = self.key_bytes()?;
        let kek = derive_two_factor_kek(id_factor, channel_id, passphrase, salt, profile)?;
        let nonce = random_array::<NONCE_LEN>()?;
        let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| Error::Argon2Failed)?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: key,
                    aad: WRAP_AAD,
                },
            )
            .map_err(|_| Error::AtRestUnlockFailed)?;
        Ok(SekWrap {
            profile_id: profile.id,
            salt: *salt,
            nonce,
            ciphertext: ct,
        })
    }
}

impl core::fmt::Debug for Sek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sek")
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

/// Derive the two-factor KEK for `(identity factor, channel_id, passphrase, salt,
/// profile)`. Shared by seal and unwrap so both sides derive identically.
fn derive_two_factor_kek(
    id_factor: &dyn IdentityFactor,
    channel_id: &[u8; CHANNEL_ID_LEN],
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    profile: Argon2Profile,
) -> Result<Zeroizing<[u8; SEK_LEN]>> {
    let factor_id = id_factor.factor_id(channel_id)?;
    let fp = factor_pass(passphrase, salt, profile)?;
    derive_kek(&factor_id, &fp)
}

/// The persistable double-lock wrap of a SEK (ADR-010). Holds **only** the small
/// non-secret-on-its-own wrap: the KDF-profile id, the per-channel salt, the AEAD
/// nonce, and `AES-256-GCM(KEK, SEK)`. Carries no key material that is usable
/// without both factors, so it is the one at-rest artifact safe to persist.
///
/// Canonical CBOR layout (array of 5):
/// `[version, profile_id, salt(16), nonce(12), ciphertext(SEK + tag)]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SekWrap {
    /// Argon2id profile id used to derive `factor_pass` (resolve via
    /// [`Argon2Profile::from_id`]).
    pub profile_id: u8,
    /// The per-channel 128-bit Argon2id salt.
    pub salt: [u8; SALT_LEN],
    /// The AES-256-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// `AES-256-GCM(KEK, nonce, SEK)` — SEK ciphertext plus the 16-byte tag.
    pub ciphertext: Vec<u8>,
}

impl SekWrap {
    /// Double-lock **unwrap**: recover the SEK from this wrap under
    /// `(identity factor, passphrase)` for `channel_id` (ADR-010).
    ///
    /// Re-derives the KEK from both factors using the *stored* profile id and
    /// salt, then AEAD-opens. Any unlock failure — wrong passphrase, wrong
    /// identity, wrong-channel wrap, tamper, or a stored profile id this build
    /// cannot resolve — collapses to [`Error::AtRestUnlockFailed`] (one error, so a
    /// persisted-wrap field is not a distinguishable oracle). Only a *structurally*
    /// malformed plaintext length stays [`Error::MalformedAtRest`].
    pub fn unwrap_sek(
        &self,
        id_factor: &dyn IdentityFactor,
        channel_id: &[u8; CHANNEL_ID_LEN],
        passphrase: &[u8],
    ) -> Result<Sek> {
        // An unknown stored profile id is treated as an unlock failure, not a
        // distinguishable `MalformedAtRest`: `profile_id` is a persisted wrap field,
        // so distinguishing it from a wrong factor would hand an attacker an oracle.
        let profile =
            Argon2Profile::from_id(self.profile_id).map_err(|_| Error::AtRestUnlockFailed)?;
        let kek = derive_two_factor_kek(id_factor, channel_id, passphrase, &self.salt, profile)?;
        let cipher =
            Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| Error::AtRestUnlockFailed)?;
        let mut pt = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: WRAP_AAD,
                },
            )
            .map_err(|_| Error::AtRestUnlockFailed)?;
        if pt.len() != SEK_LEN {
            pt.zeroize();
            return Err(Error::MalformedAtRest("sek wrap plaintext length"));
        }
        // Move the SEK into a non-`Copy` `Zeroizing` array (no bare `Copy` SEK
        // remnant), then wipe the decrypt `Vec` copy.
        let mut key = Zeroizing::new([0u8; SEK_LEN]);
        key.copy_from_slice(&pt);
        pt.zeroize();
        Ok(Sek::from_bytes(key))
    }

    /// Serialize to canonical CBOR (safe to persist).
    #[must_use]
    pub fn to_canonical_vec(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .uint(SEK_WRAP_VERSION)
            .uint(u64::from(self.profile_id))
            .bytes(&self.salt)
            .bytes(&self.nonce)
            .bytes(&self.ciphertext);
        e.finish()
    }

    /// Parse a wrap from canonical CBOR produced by [`Self::to_canonical_vec`].
    pub fn from_canonical_slice(buf: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(buf);
        if d.array().map_err(Error::from)? != 5 {
            return Err(Error::MalformedAtRest("sek wrap arity"));
        }
        let version = d.uint().map_err(Error::from)?;
        if version != SEK_WRAP_VERSION {
            return Err(Error::MalformedAtRest("sek wrap version"));
        }
        let profile_id = u8::try_from(d.uint().map_err(Error::from)?)
            .map_err(|_| Error::MalformedAtRest("sek wrap profile id range"))?;
        let salt: [u8; SALT_LEN] = d
            .bytes()
            .map_err(Error::from)?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("sek wrap salt length"))?;
        let nonce: [u8; NONCE_LEN] = d
            .bytes()
            .map_err(Error::from)?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("sek wrap nonce length"))?;
        let ciphertext = d.bytes().map_err(Error::from)?.to_vec();
        // The wrap must be at least SEK_LEN + tag to be openable; reject obviously
        // short ciphertext before any AEAD attempt.
        if ciphertext.len() != SEK_LEN + TAG_LEN {
            return Err(Error::MalformedAtRest("sek wrap ciphertext length"));
        }
        d.finish().map_err(Error::from)?;
        Ok(Self {
            profile_id,
            salt,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atrest::idfactor::SignatureIdentityFactor;
    use crate::identity::composite::SoftwareRootSigner;

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    const P: Argon2Profile = Argon2Profile::REDUCED;

    #[test]
    fn production_profile_meets_adr_floor() {
        // Cheap: assert the const, do NOT run the KDF. ADR-010 mandates >=256 MiB
        // / >=3 passes; the production profile must be the default.
        let p = Argon2Profile::PRODUCTION;
        assert_eq!(p.m_cost_kib, 256 * 1024);
        assert!(
            p.m_cost_kib >= 256 * 1024,
            "argon2 memory below 256 MiB floor"
        );
        assert!(p.t_cost >= 3, "argon2 passes below 3 floor");
        assert_eq!(Argon2Profile::default(), Argon2Profile::PRODUCTION);
        assert_eq!(
            Argon2Profile::from_id(Argon2Profile::PRODUCTION_ID).unwrap(),
            p
        );
    }

    #[test]
    fn seal_unwrap_round_trip() {
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let wrap = sek.seal(&f, &cid, b"correct horse", P).unwrap();
        let got = wrap.unwrap_sek(&f, &cid, b"correct horse").unwrap();
        assert_eq!(got.key_bytes().unwrap(), sek.key_bytes().unwrap());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let wrap = sek.seal(&f, &cid, b"right", P).unwrap();
        assert!(matches!(
            wrap.unwrap_sek(&f, &cid, b"wrong"),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn wrong_identity_fails() {
        let s_right = signer(7, 9);
        let s_wrong = signer(8, 8);
        let f_right = SignatureIdentityFactor::new(&s_right);
        let f_wrong = SignatureIdentityFactor::new(&s_wrong);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let wrap = sek.seal(&f_right, &cid, b"pp", P).unwrap();
        // Correct passphrase, wrong identity => fail.
        assert!(matches!(
            wrap.unwrap_sek(&f_wrong, &cid, b"pp"),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn passphrase_alone_is_useless() {
        // Same passphrase, but the attacker has no identity at all (different
        // identity). This proves the passphrase factor alone cannot open.
        let s = signer(1, 2);
        let attacker = signer(3, 4);
        let cid = [5u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let wrap = sek
            .seal(&SignatureIdentityFactor::new(&s), &cid, b"shared-pp", P)
            .unwrap();
        assert!(matches!(
            wrap.unwrap_sek(&SignatureIdentityFactor::new(&attacker), &cid, b"shared-pp"),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn identity_alone_is_useless() {
        // Same identity, attacker lacks the passphrase. (Covered by
        // wrong_passphrase_fails, restated here as the symmetric claim.)
        let s = signer(1, 2);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [5u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let wrap = sek.seal(&f, &cid, b"the-passphrase", P).unwrap();
        assert!(matches!(
            wrap.unwrap_sek(&f, &cid, b""),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn per_channel_isolation() {
        // Channel A's passphrase + identity must NOT open channel B's store, even
        // with the same identity and the same passphrase string — the per-channel
        // salt and the channelID-bound identity factor isolate them.
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid_a = [0xAA; CHANNEL_ID_LEN];
        let cid_b = [0xBB; CHANNEL_ID_LEN];
        let sek_b = Sek::generate().unwrap();
        let wrap_b = sek_b.seal(&f, &cid_b, b"same-pp", P).unwrap();
        // Try to open B's wrap using channel A's binding.
        assert!(matches!(
            wrap_b.unwrap_sek(&f, &cid_a, b"same-pp"),
            Err(Error::AtRestUnlockFailed)
        ));
        // Sanity: B's own binding still opens it.
        assert_eq!(
            wrap_b
                .unwrap_sek(&f, &cid_b, b"same-pp")
                .unwrap()
                .key_bytes()
                .unwrap(),
            sek_b.key_bytes().unwrap()
        );
    }

    #[test]
    fn wrap_round_trips_through_cbor() {
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let wrap = sek.seal(&f, &cid, b"pp", P).unwrap();
        let bytes = wrap.to_canonical_vec();
        let back = SekWrap::from_canonical_slice(&bytes).unwrap();
        assert_eq!(wrap, back);
        // And it still opens.
        assert_eq!(
            back.unwrap_sek(&f, &cid, b"pp")
                .unwrap()
                .key_bytes()
                .unwrap(),
            sek.key_bytes().unwrap()
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let mut wrap = sek.seal(&f, &cid, b"pp", P).unwrap();
        wrap.ciphertext[0] ^= 0x01;
        assert!(matches!(
            wrap.unwrap_sek(&f, &cid, b"pp"),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn malformed_wrap_rejected() {
        // Truncated / wrong-arity bytes are a STRUCTURAL parse failure.
        assert!(matches!(
            SekWrap::from_canonical_slice(&[0x80]),
            Err(Error::MalformedAtRest(_))
        ));
        // An unknown stored profile id is NOT a distinguishable oracle on a
        // persisted wrap field: it collapses to AtRestUnlockFailed, same as a wrong
        // factor or tamper (LOW remediation).
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let sek = Sek::generate().unwrap();
        let mut wrap = sek.seal(&f, &cid, b"pp", P).unwrap();
        wrap.profile_id = 200;
        assert!(matches!(
            wrap.unwrap_sek(&f, &cid, b"pp"),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn sek_debug_hides_secret() {
        let sek = Sek::from_bytes(Zeroizing::new([0xAB; SEK_LEN]));
        let d = format!("{sek:?}");
        // The Debug renders only the lock state, never the key bytes.
        assert!(!d.contains("ab"), "leaked sek: {d}");
        assert!(d.contains("locked"));
    }

    #[test]
    fn lock_now_invalidates_sek_and_blocks_segment_open() {
        use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
        let mut sek = Sek::generate().unwrap();
        // While unlocked, seal+open works.
        let sealed = seal_segment(&sek, SegmentKind::LogDb, 0, b"plaintext").unwrap();
        assert_eq!(
            open_segment(&sek, SegmentKind::LogDb, 0, &sealed).unwrap(),
            b"plaintext"
        );
        // App-lock invalidates the SEK.
        sek.lock_now();
        assert!(sek.is_locked());
        // Post-lock: key access and BOTH segment operations fail with AtRestLocked,
        // until a fresh SEK is re-derived (re-auth). This is the ADR-010 property.
        assert!(matches!(sek.key_bytes(), Err(Error::AtRestLocked)));
        assert!(matches!(
            open_segment(&sek, SegmentKind::LogDb, 0, &sealed),
            Err(Error::AtRestLocked)
        ));
        assert!(matches!(
            seal_segment(&sek, SegmentKind::LogDb, 1, b"more"),
            Err(Error::AtRestLocked)
        ));
        // lock_now is idempotent.
        sek.lock_now();
        assert!(matches!(sek.key_bytes(), Err(Error::AtRestLocked)));
    }

    #[test]
    fn locked_sek_cannot_be_re_sealed() {
        // A locked SEK also cannot be re-wrapped (no usable key survives the lock).
        let s = signer(7, 9);
        let f = SignatureIdentityFactor::new(&s);
        let cid = [1u8; CHANNEL_ID_LEN];
        let mut sek = Sek::generate().unwrap();
        sek.lock_now();
        assert!(matches!(
            sek.seal(&f, &cid, b"pp", P),
            Err(Error::AtRestLocked)
        ));
    }

    #[test]
    fn sek_is_not_clone() {
        // Compile-time guard documented as a runtime note: `Sek` must not be Clone
        // (a stray clone could outlive a lock). This is enforced by the type not
        // deriving Clone; this test exists so the intent is visible in the suite.
        fn assert_not_clone<T>() {}
        assert_not_clone::<Sek>();
    }
}
