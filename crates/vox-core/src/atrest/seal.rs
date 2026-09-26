//! The key a node-wide blob is sealed under at rest (V210-40, #214).
//!
//! Four blobs belong to the identity rather than to any channel: the trust keyring, the pending
//! consents, the prekey ring, and the pages of a log this node anchors. Each used to be sealed
//! under `HKDF(id_proof)`, the ADR-010 identity factor. The `id_proof` is an Ed25519 signature,
//! and Ed25519 falls to a quantum adversary who holds only the public key: such an adversary
//! with the disk could open all four without the identity passphrase. For the prekey ring that
//! means the ML-KEM prekey secrets, which defeats the post-quantum half of every recorded
//! handshake. A per-channel SEK is not affected, because its second factor is the room
//! passphrase through Argon2id.
//!
//! Each is now sealed under `HKDF(self_seed, info = <its own label>)`. `self_seed` lives inside
//! the identity vault, so only the identity passphrase releases it, the same as the open-room
//! set (#208). The label keeps every blob's key apart from every other key taken over
//! `self_seed`.
//!
//! [`legacy`] derives the old keys. Only the one-time migration of a version-1 vault may use it
//! ([`crate::node::seal_migration`]).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::atrest::sek::{Sek, SEK_LEN};
use crate::error::{Error, Result};
use crate::identity::composite::RootSigner;

/// The sealing key for the blob labelled `info`, from the unlocked identity's `self_seed`.
///
/// # Errors
/// [`Error::AtRestUnlockFailed`] for a signer that holds no vault.
pub fn sek(signer: &dyn RootSigner, info: &[u8]) -> Result<Sek> {
    let seed = signer.at_rest_seed().ok_or(Error::AtRestUnlockFailed)?;
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut key = Zeroizing::new([0u8; SEK_LEN]);
    hk.expand(info, key.as_mut())
        .map_err(|_| Error::AtRestUnlockFailed)?;
    Ok(Sek::from_bytes(key))
}

/// The keys a version-1 vault's blobs were sealed under, `HKDF(HKDF(id_proof(context)), info)`.
/// **Migration only**: anything a quantum adversary can compute from the public key.
pub mod legacy {
    use super::*;
    use crate::atrest::idfactor::{IdentityFactor, SignatureIdentityFactor};
    use crate::hash::Digest32;

    /// The old key for a blob whose identity factor was taken over `context`.
    ///
    /// # Errors
    /// The signer cannot sign.
    pub fn sek(signer: &dyn RootSigner, context: &Digest32, info: &[u8]) -> Result<Sek> {
        let factor_id = SignatureIdentityFactor::new(signer).factor_id(context)?;
        let hk = Hkdf::<Sha256>::new(None, factor_id.as_ref());
        let mut key = Zeroizing::new([0u8; SEK_LEN]);
        hk.expand(info, key.as_mut())
            .map_err(|_| Error::AtRestUnlockFailed)?;
        Ok(Sek::from_bytes(key))
    }
}
