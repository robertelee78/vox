//! Passphrase-rotation entries — the only admin-side removal (ADR-007
//! §"Revocation and epochs"). Shares tag `0x0006` / domain `vox/policy-rotation/v1`
//! with [`crate::governance::policy`], distinguished by the body *kind*
//! discriminant.
//!
//! Passphrase rotation is the **bulk** eviction primitive: an admin (holding the
//! `passphrase-rotate` capability) changes the channel passphrase, **incrementing
//! the channel-global `epoch`**. All members must rejoin with the new passphrase;
//! anyone not given it is thereby evicted. It is deliberately all-or-nothing —
//! there is **no** admin facility to remove one member (targeted removal is
//! member-driven consent revocation, [`crate::governance::consent`]).
//!
//! ## What M6 owns vs what other milestones own
//! - **M6 (here):** authors the signed rotation *entry* that records the epoch
//!   bump (`old_epoch → new_epoch`), so the governance log carries an
//!   attributable record of who rotated and to which epoch. The
//!   [`PassphraseRotation::new_epoch`] is the authoritative new
//!   channel-global epoch ([`crate::governance::genesis`] §normative: `epoch` is
//!   set only by genesis + policy/passphrase-rotation entries; per-author rotation
//!   is always `chain_id`).
//! - **M3/M5:** the actual CPace passphrase re-key and the re-bind of all sender
//!   keys to the new `(channelID, epoch)` (ADR-005/ADR-006). M6 does **not**
//!   perform the re-key; it records the boundary.
//!
//! ## Body (signing input)
//! `[kind(=KIND_PASSPHRASE_ROTATION), channelID, old_epoch, issuer_id, new_epoch]`.
//! `new_epoch` MUST be strictly greater than `old_epoch` (monotonic epoch).

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::policy::{KIND_PASSPHRASE_ROTATION, KIND_POLICY_UPDATE};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// The unsigned passphrase-rotation body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseRotationBody {
    /// The channel this rotation is valid in (ADR-005).
    pub channel_id: Digest32,
    /// The epoch in force *before* this rotation (the entry is authored under it).
    pub old_epoch: u64,
    /// The rotating admin's identity fingerprint.
    pub issuer_id: Digest32,
    /// The new channel-global epoch — strictly greater than `old_epoch`.
    pub new_epoch: u64,
}

impl PassphraseRotationBody {
    /// Canonical-CBOR body
    /// `[kind, channelID, old_epoch, issuer_id, new_epoch]` with
    /// `kind == KIND_PASSPHRASE_ROTATION`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .uint(KIND_PASSPHRASE_ROTATION)
            .bytes(&self.channel_id)
            .uint(self.old_epoch)
            .bytes(&self.issuer_id)
            .uint(self.new_epoch);
        e.finish()
    }

    /// The signing input: `vox/policy-rotation/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::PolicyRotation, &self.canonical_body())
    }

    fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 5 {
            return Err(Error::MalformedGovernance("passphrase-rotation arity"));
        }
        let kind = d.uint()?;
        if kind == KIND_POLICY_UPDATE {
            return Err(Error::MalformedGovernance(
                "passphrase-rotation wrong body kind",
            ));
        }
        if kind != KIND_PASSPHRASE_ROTATION {
            return Err(Error::MalformedGovernance(
                "passphrase-rotation unknown body kind",
            ));
        }
        let channel_id = take_digest(&mut d)?;
        let old_epoch = d.uint()?;
        let issuer_id = take_digest(&mut d)?;
        let new_epoch = d.uint()?;
        d.finish()?;
        if new_epoch <= old_epoch {
            return Err(Error::MalformedGovernance(
                "passphrase-rotation new_epoch not monotonic",
            ));
        }
        Ok(Self {
            channel_id,
            old_epoch,
            issuer_id,
            new_epoch,
        })
    }
}

/// A complete, root-signed passphrase-rotation entry.
#[derive(Debug, Clone)]
pub struct PassphraseRotation {
    /// The signed body.
    pub body: PassphraseRotationBody,
    /// The issuer's composite root signature.
    pub signature: CompositeSignature,
}

impl PassphraseRotation {
    /// Build and root-sign a passphrase-rotation entry bumping the epoch from
    /// `old_epoch` to `new_epoch`. Rejects a non-monotonic epoch
    /// (`new_epoch <= old_epoch`).
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        old_epoch: u64,
        new_epoch: u64,
    ) -> Result<Self> {
        if new_epoch <= old_epoch {
            return Err(Error::MalformedGovernance(
                "passphrase-rotation new_epoch not monotonic",
            ));
        }
        let body = PassphraseRotationBody {
            channel_id: *channel_id,
            old_epoch,
            issuer_id: issuer_root.fingerprint(),
            new_epoch,
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// The new channel-global epoch this rotation establishes (authoritative).
    #[must_use]
    pub fn new_epoch(&self) -> u64 {
        self.body.new_epoch
    }

    /// Frame for the wire/storage (tag `0x0006`): the 5 signed body fields then
    /// the composite signature as the 6th element.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(6)
            .uint(KIND_PASSPHRASE_ROTATION)
            .bytes(&b.channel_id)
            .uint(b.old_epoch)
            .bytes(&b.issuer_id)
            .uint(b.new_epoch)
            .bytes(&self.signature.to_bytes());
        frame(StructTag::PolicyRotation, &e.finish())
    }

    /// Parse a framed passphrase-rotation entry (does NOT verify). Rejects a
    /// policy-update body kind, keeping the two `0x0006` structs unambiguous.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::PolicyRotation {
            return Err(Error::MalformedGovernance(
                "passphrase-rotation wrong struct tag",
            ));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 6 {
            return Err(Error::MalformedGovernance("passphrase-rotation wire arity"));
        }
        let kind = d.uint()?;
        if kind != KIND_PASSPHRASE_ROTATION {
            return Err(Error::MalformedGovernance(
                "passphrase-rotation wrong body kind",
            ));
        }
        let channel_id = d.bytes()?.to_vec();
        let old_epoch = d.uint()?;
        let issuer_id = d.bytes()?.to_vec();
        let new_epoch = d.uint()?;
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;

        let mut be = Encoder::new();
        be.array(5)
            .uint(KIND_PASSPHRASE_ROTATION)
            .bytes(&channel_id)
            .uint(old_epoch)
            .bytes(&issuer_id)
            .uint(new_epoch);
        let body = PassphraseRotationBody::from_canonical_body(&be.finish())?;
        let signature = parse_sig(&sig_bytes)?;
        Ok(Self { body, signature })
    }

    /// Verify the issuer's signature and `issuer_id`↔signer binding (structural;
    /// whether the issuer holds `passphrase-rotate` is the evaluator's job).
    pub fn verify(&self, issuer_root: &CompositePublicKey) -> Result<()> {
        if issuer_root.fingerprint() != self.body.issuer_id {
            return Err(Error::MalformedGovernance(
                "passphrase-rotation issuer_id != signer fingerprint",
            ));
        }
        issuer_root.verify(&self.body.signing_input(), &self.signature)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("passphrase-rotation digest length"))
}

fn parse_sig(bytes: &[u8]) -> Result<CompositeSignature> {
    let arr: [u8; COMPOSITE_SIG_LEN] = bytes
        .try_into()
        .map_err(|_| Error::MalformedGovernance("passphrase-rotation signature length"))?;
    CompositeSignature::from_bytes(&arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::policy::PolicyUpdate;
    use crate::identity::composite::SoftwareRootSigner;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    const CID: Digest32 = [0xC0; 32];

    #[test]
    fn round_trip_and_verify() {
        let r = root(1, 2);
        let rot = PassphraseRotation::build(&r, &CID, 1, 2).unwrap();
        assert_eq!(rot.new_epoch(), 2);
        assert!(rot.verify(&r.public_key()).is_ok());
        let decoded = PassphraseRotation::from_wire(&rot.to_wire()).unwrap();
        assert_eq!(decoded.body, rot.body);
        assert!(decoded.verify(&r.public_key()).is_ok());
    }

    #[test]
    fn non_monotonic_epoch_rejected() {
        let r = root(3, 4);
        assert!(PassphraseRotation::build(&r, &CID, 5, 5).is_err());
        assert!(PassphraseRotation::build(&r, &CID, 5, 4).is_err());
    }

    #[test]
    fn tamper_rejected() {
        let r = root(5, 6);
        let rot = PassphraseRotation::build(&r, &CID, 1, 2).unwrap();
        let mut decoded = PassphraseRotation::from_wire(&rot.to_wire()).unwrap();
        decoded.body.new_epoch = 99;
        assert!(decoded.verify(&r.public_key()).is_err());
    }

    #[test]
    fn policy_update_and_rotation_are_unambiguous() {
        // A passphrase-rotation frame must not parse as a policy-update and vice
        // versa, even though they share tag 0x0006.
        let r = root(7, 8);
        let rot = PassphraseRotation::build(&r, &CID, 1, 2).unwrap();
        assert!(PolicyUpdate::from_wire(&rot.to_wire()).is_err());

        let pu = PolicyUpdate::build(&r, &CID, 1, None, Some(60)).unwrap();
        assert!(PassphraseRotation::from_wire(&pu.to_wire()).is_err());
    }
}
