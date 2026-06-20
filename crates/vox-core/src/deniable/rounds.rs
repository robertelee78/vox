//! The DGKA broadcast bodies and the round-1 commitment (ADR-009 §"Concrete
//! protocol", steps 1–4). The state machine that produces/consumes these lives in
//! [`crate::deniable::dgka`]; this module holds the wire-shaped message types so
//! that file stays focused on the protocol logic.

use crate::hash::{sha256_concat, Digest32};
use crate::identity::composite::{CompositePublicKey, CompositeSignature};

use crate::deniable::key::CONFIRM_LEN;
use crate::deniable::share::SHARE_LEN;

/// Domain-separation label for the round-1 commitment (ADR-009 step 1).
pub const COMMIT_LABEL: &[u8] = b"vox/dgka-commit/v1";
/// Length of the round-1 commitment nonce (128-bit, ADR-009 step 1).
pub const NONCE_LEN: usize = 16;

/// The round-1 commitment for a member:
/// `SHA-256(label ‖ author_pubkey ‖ epk_i ‖ z_i ‖ n_i)`. Binding `author_pubkey`
/// means a member is locked to its static identity at commit time — it cannot swap
/// to a different (e.g. a victim's) identity at reveal.
#[must_use]
pub fn commitment(
    author_pubkey: &CompositePublicKey,
    epk: &CompositePublicKey,
    share: &[u8; SHARE_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Digest32 {
    let author_bytes = author_pubkey.to_bytes();
    let epk_bytes = epk.to_bytes();
    sha256_concat(&[
        COMMIT_LABEL,
        &author_bytes,
        &epk_bytes,
        &share[..],
        &nonce[..],
    ])
}

/// A member's round-2 reveal body: `(author_pubkey, epk_i, z_i, n_i)` plus the
/// member's **static** signature over the canonical `dgka-setup` body. Checked
/// against the stored round-1 commit by every other member, and the static
/// signature binds `epk_i`/`z_i` to the static identity (defeats the
/// `(victim_author_id, attacker_epk)` impersonation).
#[derive(Clone)]
pub struct Reveal {
    /// The member's static identity fingerprint (the admitted-set / author key).
    pub author_id: Digest32,
    /// The member's static identity composite public key (the ordering key; its
    /// fingerprint MUST equal `author_id`).
    pub author_pubkey: CompositePublicKey,
    /// The revealed ephemeral verification key.
    pub epk: CompositePublicKey,
    /// The revealed ephemeral DH share `z_i`.
    pub share: [u8; SHARE_LEN],
    /// The revealed 128-bit commitment nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The member's **static** composite signature over the canonical `dgka-setup`
    /// reveal body — the root-signed envelope (participation attributable).
    pub reveal_sig: CompositeSignature,
}

impl core::fmt::Debug for Reveal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reveal")
            .field("author_id", &crate::hash::Hex(&self.author_id))
            .field("share", &crate::hash::Hex(&self.share))
            .finish_non_exhaustive()
    }
}

/// A member's round-3+4 confirmation body: the Burmester–Desmedt round-2 value
/// `X_i`, the DSKE bind signature over the bind transcript `T_bind`, and the HMAC
/// confirmation over `T_bind`. All three are checked by every other member before
/// the session opens.
#[derive(Clone)]
pub struct Confirm {
    /// The confirming member's static identity fingerprint.
    pub author_id: Digest32,
    /// The BD round-2 value `X_i = x_i·(z_{i+1} − z_{i-1})` (compressed Ristretto).
    /// Unused for `m == 2` (the BD degeneracy) but always carried for a uniform
    /// wire shape; verifiers ignore it when `m == 2`.
    pub round2: [u8; SHARE_LEN],
    /// The DSKE bind: a composite signature by `esk_i` over the bind transcript
    /// `T_bind` (ADR-009 step 3) — live PQ origin auth of `epk_i` to peers.
    pub bind_sig: CompositeSignature,
    /// The key-confirmation MAC `HMAC(K_confirm, T_bind)` (ADR-009 step 4).
    pub confirm_mac: [u8; CONFIRM_LEN],
}

impl core::fmt::Debug for Confirm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Confirm")
            .field("author_id", &crate::hash::Hex(&self.author_id))
            .finish_non_exhaustive()
    }
}
