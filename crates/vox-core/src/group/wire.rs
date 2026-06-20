//! Group-layer wire constants and canonical encodings (ADR-006, ADR-008).
//!
//! Two kinds of authenticated bytes live in the group layer:
//!
//! - The **SKDM** is a first-class ADR-008 log/wire struct: it uses the registry
//!   tag [`crate::wire::StructTag::Skdm`] (`0x0002`) and the domain label
//!   `vox/skdm/v1`, signed via [`crate::wire::signing_input`]. Its canonical
//!   body lives in [`crate::group::skdm`].
//! - The **broadcast message header / AD** and the **Sender-Key cross-signature
//!   binding** are group *payloads* (like the M2 ratchet message), so they carry
//!   their own ASCII domain labels prefixed directly onto a canonical-CBOR body,
//!   not a struct-tag — exactly the pattern [`crate::pairwise::header`] uses.
//!
//! All five fields that ADR-006 names as the cross-group-confusion guard
//! (`channelID, epoch, author_id, chain_id, iteration`) are bound here so a
//! message or key authorized for one channel/epoch/generation cannot be replayed
//! into another (eprint 2023/1385).

use crate::cbor::Encoder;
use crate::hash::{Digest32, COMPOSITE_PUB_LEN};

/// Serialized length of a Sender-Key signing public key: the composite
/// Ed25519+ML-DSA-65 public key (ADR-002 §3).
pub const SENDER_KEY_SIGNING_PUB_LEN: usize = COMPOSITE_PUB_LEN;

/// Domain label for the identity-root cross-signature authorizing a Sender-Key
/// signing key for one `(channelID, epoch, author_id, chain_id)` (ADR-002 §3).
pub const SENDER_KEY_SIGN_DOMAIN: &str = "vox/sender-key-sign/v1";

/// Domain label for the broadcast-message associated data (the AEAD AD binding
/// the message header to its channel/epoch/author/generation, ADR-006).
pub const GROUP_MSG_AD_DOMAIN: &str = "vox/group-msg-ad/v1";

/// Domain label for the broadcast-message *signed input* — the composite
/// signature by the Sender-Key signing key covers this (ADR-006).
pub const GROUP_MSG_SIGN_DOMAIN: &str = "vox/group-msg/v1";

/// Build the identity-root cross-signature input over the canonical tuple
/// `[channelID, epoch, author_id, chain_id, signing_pubkey]`, domain-prefixed
/// with [`SENDER_KEY_SIGN_DOMAIN`].
#[must_use]
pub fn sender_key_binding_input(
    channel_id: &Digest32,
    epoch: u64,
    author_id: &Digest32,
    chain_id: u64,
    signing_pubkey: &[u8; SENDER_KEY_SIGNING_PUB_LEN],
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .bytes(channel_id)
        .uint(epoch)
        .bytes(author_id)
        .uint(chain_id)
        .bytes(signing_pubkey);
    domain_prefixed(SENDER_KEY_SIGN_DOMAIN, &e.finish())
}

/// Prefix `body` with an ASCII `domain` label (`domain ‖ body`), the same
/// signing-input shape the identity and pairwise layers use for non-struct-tag
/// payloads.
#[must_use]
pub fn domain_prefixed(domain: &str, body: &[u8]) -> Vec<u8> {
    let d = domain.as_bytes();
    let mut out = Vec::with_capacity(d.len().saturating_add(body.len()));
    out.extend_from_slice(d);
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_input_is_domain_then_canonical_array() {
        let cid = [1u8; 32];
        let author = [2u8; 32];
        let spk = [3u8; SENDER_KEY_SIGNING_PUB_LEN];
        let got = sender_key_binding_input(&cid, 9, &author, 4, &spk);
        // Starts with the domain label.
        assert!(got.starts_with(SENDER_KEY_SIGN_DOMAIN.as_bytes()));
        // Body is a 5-element canonical array (0x85 array header after the label).
        let body = &got[SENDER_KEY_SIGN_DOMAIN.len()..];
        assert_eq!(body[0], 0x85);
    }

    #[test]
    fn binding_input_is_sensitive_to_every_field() {
        let cid = [1u8; 32];
        let author = [2u8; 32];
        let spk = [3u8; SENDER_KEY_SIGNING_PUB_LEN];
        let base = sender_key_binding_input(&cid, 9, &author, 4, &spk);
        assert_ne!(
            base,
            sender_key_binding_input(&[9u8; 32], 9, &author, 4, &spk)
        );
        assert_ne!(base, sender_key_binding_input(&cid, 10, &author, 4, &spk));
        assert_ne!(base, sender_key_binding_input(&cid, 9, &[8u8; 32], 4, &spk));
        assert_ne!(base, sender_key_binding_input(&cid, 9, &author, 5, &spk));
        let mut spk2 = spk;
        spk2[0] ^= 1;
        assert_ne!(base, sender_key_binding_input(&cid, 9, &author, 4, &spk2));
    }
}
