//! Per-sender consent grants and revocations (ADR-007 §"Per-type body schemas",
//! §"Join and per-sender consent flow", §"Revocation and epochs").
//!
//! Consent is **the** Vox differentiator: membership is *emergent* (join +
//! consent), with **no roster, no admin admission, no membership cert**. Each of
//! these structs is authored **only by `A`** about `A`'s own sender key, so `A`'s
//! consent timeline is single-writer and totally ordered within `A`'s log — there
//! is no cross-writer race on "can `N` read `A`" (ADR-007 §"Conflict resolution").
//!
//! - **Consent grant** (tag `0x0004`, domain `vox/consent-grant/v1`): `A`
//!   releasing `A`'s Sender Key to a target `N`. The SKDM itself (ADR-006/M4)
//!   travels in the pairwise session ([`crate::pairwise`]); the entry carries only
//!   `skdm_ref` — the SHA-256 hash of that delivered SKDM — plus the history mode
//!   at grant time. Body:
//!   `{ target_id(composite fpr), skdm_ref(32 B), history_mode_at_grant }`.
//! - **Consent revocation** (tag `0x0005`, domain `vox/consent-revocation/v1`):
//!   `A` withdrawing `N`'s access to `A`'s *future* messages by rotating `A`'s own
//!   `chain_id` (excluding `N`); `N` keeps old (uncallable) keys. Body:
//!   `{ target_id(composite fpr), new_chain_id }`. The actual sender-key rotation
//!   + SKDM redistribution is M4; M6 authors the log entry that records it.
//!
//! Both are composite-signed by **`A`'s identity root** and `(channelID, epoch)`
//! bound, and ride the causal log as `EntryKind::Governance` payloads.
//!
//! ## Inbound visibility opt-out is *not here*
//! The inbound "do I want to see them?" control is purely receiver-side: it
//! creates **no** governance entry, performs no rotation, and affects no one else
//! (ADR-007). It is modeled in [`crate::governance::visibility`], deliberately
//! outside this signed-struct module, because it is not a log fact at all.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::genesis::HistoryMode;
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// The unsigned consent-grant body (every field except the signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrantBody {
    /// The channel this grant is valid in (ADR-005).
    pub channel_id: Digest32,
    /// The membership epoch this grant is bound to (ADR-007).
    pub epoch: u64,
    /// The granting member `A`'s identity fingerprint (the single writer).
    pub author_id: Digest32,
    /// The target `N`'s identity fingerprint — who is being consented to read `A`.
    pub target_id: Digest32,
    /// SHA-256 of the SKDM (ADR-006) `A` delivered to `N` over the pairwise
    /// session. The SKDM travels out-of-band; the entry carries only this hash.
    pub skdm_ref: Digest32,
    /// The history mode in force when `A` consented (decides whether `A` released
    /// its origin or current chain key, ADR-006/M4).
    pub history_mode_at_grant: HistoryMode,
}

impl ConsentGrantBody {
    /// Canonical-CBOR body
    /// `[channelID, epoch, author_id, target_id, skdm_ref, history_mode_at_grant]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.author_id)
            .bytes(&self.target_id)
            .bytes(&self.skdm_ref)
            .uint(self.history_mode_at_grant.as_u64());
        e.finish()
    }

    /// The signing input: `vox/consent-grant/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::ConsentGrant, &self.canonical_body())
    }

    fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 6 {
            return Err(Error::MalformedGovernance("consent-grant arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let author_id = take_digest(&mut d)?;
        let target_id = take_digest(&mut d)?;
        let skdm_ref = take_digest(&mut d)?;
        let history_mode_at_grant = HistoryMode::from_u64(d.uint()?)?;
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            author_id,
            target_id,
            skdm_ref,
            history_mode_at_grant,
        })
    }
}

/// A complete, root-signed consent grant: the body plus `A`'s composite root
/// signature over [`ConsentGrantBody::signing_input`].
#[derive(Debug, Clone)]
pub struct ConsentGrant {
    /// The signed body.
    pub body: ConsentGrantBody,
    /// `A`'s composite root signature.
    pub signature: CompositeSignature,
}

impl ConsentGrant {
    /// Build and root-sign a consent grant. `author_root`'s fingerprint becomes
    /// the body's `author_id` (the single writer of `A`'s consent timeline).
    pub fn build(
        author_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        target_id: Digest32,
        skdm_ref: Digest32,
        history_mode_at_grant: HistoryMode,
    ) -> Result<Self> {
        let body = ConsentGrantBody {
            channel_id: *channel_id,
            epoch,
            author_id: author_root.fingerprint(),
            target_id,
            skdm_ref,
            history_mode_at_grant,
        };
        let signature = author_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0004`): the 6 signed body fields then
    /// the composite signature as a 7th element.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(7)
            .bytes(&b.channel_id)
            .uint(b.epoch)
            .bytes(&b.author_id)
            .bytes(&b.target_id)
            .bytes(&b.skdm_ref)
            .uint(b.history_mode_at_grant.as_u64())
            .bytes(&self.signature.to_bytes());
        frame(StructTag::ConsentGrant, &e.finish())
    }

    /// Parse a framed consent grant (does NOT verify — call [`ConsentGrant::verify`]).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::ConsentGrant {
            return Err(Error::MalformedGovernance("consent-grant wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 7 {
            return Err(Error::MalformedGovernance("consent-grant wire arity"));
        }
        let channel_id = d.bytes()?.to_vec();
        let epoch = d.uint()?;
        let author_id = d.bytes()?.to_vec();
        let target_id = d.bytes()?.to_vec();
        let skdm_ref = d.bytes()?.to_vec();
        let history_mode = d.uint()?;
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;

        let mut be = Encoder::new();
        be.array(6)
            .bytes(&channel_id)
            .uint(epoch)
            .bytes(&author_id)
            .bytes(&target_id)
            .bytes(&skdm_ref)
            .uint(history_mode);
        let body = ConsentGrantBody::from_canonical_body(&be.finish())?;
        let signature = parse_sig(&sig_bytes)?;
        Ok(Self { body, signature })
    }

    /// Verify `A`'s signature and the `author_id`↔signer binding (so the single
    /// writer of `A`'s consent really is `A`).
    pub fn verify(&self, author_root: &CompositePublicKey) -> Result<()> {
        if author_root.fingerprint() != self.body.author_id {
            return Err(Error::MalformedGovernance(
                "consent-grant author_id != signer fingerprint",
            ));
        }
        author_root.verify(&self.body.signing_input(), &self.signature)
    }
}

/// The unsigned consent-revocation body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRevocationBody {
    /// The channel this revocation is valid in.
    pub channel_id: Digest32,
    /// The membership epoch this revocation is bound to.
    pub epoch: u64,
    /// The revoking member `A`'s identity fingerprint (the single writer).
    pub author_id: Digest32,
    /// The target `N` whose access to `A`'s *future* messages is withdrawn.
    pub target_id: Digest32,
    /// `A`'s new `chain_id` after rotation — the generation `N` does not receive
    /// (ADR-006). `N` keeps the old, now-uncallable keys.
    pub new_chain_id: u64,
}

impl ConsentRevocationBody {
    /// Canonical-CBOR body
    /// `[channelID, epoch, author_id, target_id, new_chain_id]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.author_id)
            .bytes(&self.target_id)
            .uint(self.new_chain_id);
        e.finish()
    }

    /// The signing input: `vox/consent-revocation/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::ConsentRevocation, &self.canonical_body())
    }

    fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 5 {
            return Err(Error::MalformedGovernance("consent-revocation arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let author_id = take_digest(&mut d)?;
        let target_id = take_digest(&mut d)?;
        let new_chain_id = d.uint()?;
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            author_id,
            target_id,
            new_chain_id,
        })
    }
}

/// A complete, root-signed consent revocation.
#[derive(Debug, Clone)]
pub struct ConsentRevocation {
    /// The signed body.
    pub body: ConsentRevocationBody,
    /// `A`'s composite root signature.
    pub signature: CompositeSignature,
}

impl ConsentRevocation {
    /// Build and root-sign a consent revocation.
    pub fn build(
        author_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        target_id: Digest32,
        new_chain_id: u64,
    ) -> Result<Self> {
        let body = ConsentRevocationBody {
            channel_id: *channel_id,
            epoch,
            author_id: author_root.fingerprint(),
            target_id,
            new_chain_id,
        };
        let signature = author_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0005`): body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(6)
            .bytes(&b.channel_id)
            .uint(b.epoch)
            .bytes(&b.author_id)
            .bytes(&b.target_id)
            .uint(b.new_chain_id)
            .bytes(&self.signature.to_bytes());
        frame(StructTag::ConsentRevocation, &e.finish())
    }

    /// Parse a framed consent revocation (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::ConsentRevocation {
            return Err(Error::MalformedGovernance(
                "consent-revocation wrong struct tag",
            ));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 6 {
            return Err(Error::MalformedGovernance("consent-revocation wire arity"));
        }
        let channel_id = d.bytes()?.to_vec();
        let epoch = d.uint()?;
        let author_id = d.bytes()?.to_vec();
        let target_id = d.bytes()?.to_vec();
        let new_chain_id = d.uint()?;
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;

        let mut be = Encoder::new();
        be.array(5)
            .bytes(&channel_id)
            .uint(epoch)
            .bytes(&author_id)
            .bytes(&target_id)
            .uint(new_chain_id);
        let body = ConsentRevocationBody::from_canonical_body(&be.finish())?;
        let signature = parse_sig(&sig_bytes)?;
        Ok(Self { body, signature })
    }

    /// Verify `A`'s signature and the `author_id`↔signer binding.
    pub fn verify(&self, author_root: &CompositePublicKey) -> Result<()> {
        if author_root.fingerprint() != self.body.author_id {
            return Err(Error::MalformedGovernance(
                "consent-revocation author_id != signer fingerprint",
            ));
        }
        author_root.verify(&self.body.signing_input(), &self.signature)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("consent digest length"))
}

fn parse_sig(bytes: &[u8]) -> Result<CompositeSignature> {
    let arr: [u8; COMPOSITE_SIG_LEN] = bytes
        .try_into()
        .map_err(|_| Error::MalformedGovernance("consent signature length"))?;
    CompositeSignature::from_bytes(&arr)
}

// Note: consent grants/revocations carry no algorithm field — unlike the genesis
// record and admin cert, the signature class is fixed by the composite root and
// the domain label alone, so there is no `algo_ids` element to validate.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    const CID: Digest32 = [0xC0; 32];

    #[test]
    fn consent_grant_round_trip_and_verify() {
        let a = root(1, 2);
        let n = root(3, 4);
        let grant = ConsentGrant::build(
            &a,
            &CID,
            1,
            n.public_key().fingerprint(),
            [0xAB; 32],
            HistoryMode::FullHistory,
        )
        .unwrap();
        assert!(grant.verify(&a.public_key()).is_ok());
        let decoded = ConsentGrant::from_wire(&grant.to_wire()).unwrap();
        assert_eq!(decoded.body, grant.body);
        assert_eq!(decoded.body.history_mode_at_grant, HistoryMode::FullHistory);
        assert!(decoded.verify(&a.public_key()).is_ok());
    }

    #[test]
    fn consent_grant_single_writer_binding() {
        // Only A's key authors A's grant: verifying against a different root fails.
        let a = root(5, 6);
        let other = root(7, 8);
        let n = root(9, 10);
        let grant = ConsentGrant::build(
            &a,
            &CID,
            1,
            n.public_key().fingerprint(),
            [0x01; 32],
            HistoryMode::ForwardOnly,
        )
        .unwrap();
        assert!(grant.verify(&other.public_key()).is_err());
    }

    #[test]
    fn consent_grant_tamper_rejected() {
        let a = root(1, 1);
        let n = root(2, 2);
        let grant = ConsentGrant::build(
            &a,
            &CID,
            1,
            n.public_key().fingerprint(),
            [0x01; 32],
            HistoryMode::ForwardOnly,
        )
        .unwrap();
        let mut decoded = ConsentGrant::from_wire(&grant.to_wire()).unwrap();
        decoded.body.skdm_ref = [0xFF; 32];
        assert!(decoded.verify(&a.public_key()).is_err());
    }

    #[test]
    fn consent_revocation_round_trip_and_verify() {
        let a = root(1, 2);
        let n = root(3, 4);
        let rev = ConsentRevocation::build(&a, &CID, 1, n.public_key().fingerprint(), 7).unwrap();
        assert!(rev.verify(&a.public_key()).is_ok());
        let decoded = ConsentRevocation::from_wire(&rev.to_wire()).unwrap();
        assert_eq!(decoded.body.new_chain_id, 7);
        assert!(decoded.verify(&a.public_key()).is_ok());
    }

    #[test]
    fn consent_revocation_tamper_rejected() {
        let a = root(5, 5);
        let n = root(6, 6);
        let rev = ConsentRevocation::build(&a, &CID, 1, n.public_key().fingerprint(), 2).unwrap();
        let mut decoded = ConsentRevocation::from_wire(&rev.to_wire()).unwrap();
        decoded.body.new_chain_id = 99;
        assert!(decoded.verify(&a.public_key()).is_err());
    }
}
