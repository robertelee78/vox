//! The **service-grant exclusion** (tag `0x0013`, domain
//! `vox/service-grant-exclusion/v1`): the log fact that withdraws a room's genesis
//! service grant from one member (ADR-007 §Revocation, ADR-017 decision 3).
//!
//! ## Why this exists at all
//! A genesis service grant ([`crate::governance::genesis::GenesisBody::service_grant`])
//! confers capabilities on every admitted member **without issuing anyone a
//! certificate**. That is the point — it deletes the "wait for the guest, then grant
//! them something" step — but it also removes the handle ADR-007's
//! admin-delegation-revocation grabs, because that names the *entry hash of a
//! delegation* and here there is no delegation to name. Without this entry, adding a
//! genesis grant would take away a control the channel already had: today
//! `vox grant` issues a real certificate per member and revoking it works per member.
//! A capability-bearing room must not be a one-way door.
//!
//! So an exclusion names the **identity**, the way consent grants and revocations do
//! (ADR-007 §"Per-type body schemas"), rather than an entry hash. Body:
//! `{ channelID, epoch, issuer_id, target_id }`.
//!
//! ## What it does and does not touch
//! An exclusion suppresses **only** the genesis-conferred capabilities. An explicit
//! [`AdminCert`](crate::governance::cert::AdminCert) issued to the same identity is
//! governed by its own revocation and is unaffected — so an admin who excluded a
//! member and then deliberately certified them again has done exactly that, and the
//! later act stands. Keeping the two axes separate is what makes the composition
//! predictable; collapsing them would mean an exclusion silently outranked a
//! certificate an admin issued afterwards.
//!
//! ## Authority
//! Issued by a holder of `delegate` — the same authority that may revoke a
//! delegation, since this withdraws capabilities in exactly the same sense. The
//! evaluator checks that in the exclusion's **strict causal past**, never from
//! concurrent or later facts, identically to
//! [`crate::governance::cert::AdminRevocation`].
//!
//! `(channelID, epoch)`-bound like every other governance fact, so a passphrase
//! rotation (a new epoch, ADR-007) clears every exclusion along with every
//! certificate — the room starts again from its genesis.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// The unsigned service-grant-exclusion body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceGrantExclusionBody {
    /// The channel this exclusion is valid in.
    pub channel_id: Digest32,
    /// The membership epoch this exclusion is bound to.
    pub epoch: u64,
    /// The excluding admin's identity fingerprint.
    pub issuer_id: Digest32,
    /// The member whose genesis-conferred capabilities are withdrawn.
    pub target_id: Digest32,
}

impl ServiceGrantExclusionBody {
    /// Canonical-CBOR body `[channelID, epoch, issuer_id, target_id]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .bytes(&self.target_id);
        e.finish()
    }

    /// The signing input: `vox/service-grant-exclusion/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::ServiceGrantExclusion, &self.canonical_body())
    }

    fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 4 {
            return Err(Error::MalformedGovernance("service-grant-exclusion arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let issuer_id = take_digest(&mut d)?;
        let target_id = take_digest(&mut d)?;
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            issuer_id,
            target_id,
        })
    }
}

/// A complete, root-signed service-grant exclusion.
#[derive(Debug, Clone)]
pub struct ServiceGrantExclusion {
    /// The signed body.
    pub body: ServiceGrantExclusionBody,
    /// The issuer's composite root signature.
    pub signature: CompositeSignature,
}

impl ServiceGrantExclusion {
    /// Build and root-sign an exclusion.
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        target_id: Digest32,
    ) -> Result<Self> {
        let body = ServiceGrantExclusionBody {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
            target_id,
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0013`): body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(5)
            .bytes(&b.channel_id)
            .uint(b.epoch)
            .bytes(&b.issuer_id)
            .bytes(&b.target_id)
            .bytes(&self.signature.to_bytes());
        frame(StructTag::ServiceGrantExclusion, &e.finish())
    }

    /// Parse a framed exclusion (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::ServiceGrantExclusion {
            return Err(Error::MalformedGovernance(
                "service-grant-exclusion wrong struct tag",
            ));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 5 {
            return Err(Error::MalformedGovernance(
                "service-grant-exclusion wire arity",
            ));
        }
        let channel_id = d.bytes()?.to_vec();
        let epoch = d.uint()?;
        let issuer_id = d.bytes()?.to_vec();
        let target_id = d.bytes()?.to_vec();
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;

        // Re-encode the signed fields and decode strictly, so the reconstructed
        // signing input is byte-identical to the issuer's.
        let mut be = Encoder::new();
        be.array(4)
            .bytes(&channel_id)
            .uint(epoch)
            .bytes(&issuer_id)
            .bytes(&target_id);
        let body = ServiceGrantExclusionBody::from_canonical_body(&be.finish())?;
        let sig: [u8; COMPOSITE_SIG_LEN] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedGovernance("service-grant-exclusion sig length"))?;
        let signature = CompositeSignature::from_bytes(&sig)?;
        Ok(Self { body, signature })
    }

    /// Verify the issuer's signature and the `issuer_id`↔signer binding.
    pub fn verify(&self, issuer_root: &CompositePublicKey) -> Result<()> {
        if issuer_root.fingerprint() != self.body.issuer_id {
            return Err(Error::MalformedGovernance(
                "service-grant-exclusion issuer_id != signer fingerprint",
            ));
        }
        issuer_root.verify(&self.body.signing_input(), &self.signature)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("service-grant-exclusion digest length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    #[test]
    fn round_trips_and_verifies() {
        let admin = root(1, 2);
        let x = ServiceGrantExclusion::build(&admin, &[7u8; 32], 3, [9u8; 32]).unwrap();
        let back = ServiceGrantExclusion::from_wire(&x.to_wire()).unwrap();
        assert_eq!(back.body, x.body);
        back.verify(&admin.public_key()).unwrap();
    }

    #[test]
    fn a_tampered_target_fails_verification() {
        let admin = root(3, 4);
        let x = ServiceGrantExclusion::build(&admin, &[7u8; 32], 1, [9u8; 32]).unwrap();
        let mut tampered = x.clone();
        tampered.body.target_id = [0xAA; 32];
        assert!(tampered.verify(&admin.public_key()).is_err());
    }

    #[test]
    fn a_signature_by_another_key_is_rejected() {
        let admin = root(5, 6);
        let other = root(7, 8);
        let x = ServiceGrantExclusion::build(&admin, &[7u8; 32], 1, [9u8; 32]).unwrap();
        // The binding check fires before the signature check: a different key is not
        // the issuer this body names.
        assert!(x.verify(&other.public_key()).is_err());
    }

    #[test]
    fn a_wrong_struct_tag_is_rejected() {
        let admin = root(9, 10);
        let x = ServiceGrantExclusion::build(&admin, &[7u8; 32], 1, [9u8; 32]).unwrap();
        let mut wire = x.to_wire();
        // Rewrite the 2-byte tag to the consent-revocation tag.
        wire[0..2].copy_from_slice(&StructTag::ConsentRevocation.as_u16().to_be_bytes());
        assert!(ServiceGrantExclusion::from_wire(&wire).is_err());
    }
}
