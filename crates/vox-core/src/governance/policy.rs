//! Policy-update entries (ADR-007 §"Per-type body schemas", tag `0x0006`, domain
//! `vox/policy-rotation/v1`).
//!
//! A policy-update, issued by a holder of the `policy` capability — the room's creator or an
//! admin (#319) — changes the room's **retention** (TTL) from its causal position forward.
//!
//! **Retention is the only governance a room has** (V030-32, the decider, 2026-10-02: "creator or
//! admin"). The history-mode and suite-floor updates, which no command ever wrote, are removed:
//! the wire layout keeps their presence flags, always written as absent, and an update that
//! carries either is refused. Both stay as the genesis set them.
//!
//! The tag (`0x0006`) and domain label are shared with the passphrase-rotation kind (body kind 2),
//! which is removed too and reserved: a body of that kind is refused as the wrong kind.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// Body kind discriminant of a policy-update under the `PolicyRotation` tag (`0x0006`). Kind 2,
/// the passphrase rotation, is reserved: never written, refused on decode (V030-32).
pub(crate) const KIND_POLICY_UPDATE: u64 = 1;

/// The unsigned policy-update body (every field except the signature).
///
/// `ttl` is optional: `None` means "unchanged", which is structurally valid but inert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUpdateBody {
    /// The channel this update is valid in (ADR-005).
    pub channel_id: Digest32,
    /// The membership epoch this update is bound to (ADR-007).
    pub epoch: u64,
    /// The issuing `policy`-holder's identity fingerprint.
    pub issuer_id: Digest32,
    /// New retention in seconds (`0` = forever), or `None` to leave it unchanged.
    pub ttl: Option<u64>,
}

/// The elements a body or wire array holds: kind, channel, epoch, issuer, the history flag
/// (always 0), the ttl flag, the ttl if present, and the suite flag (always 0).
fn arity_for(ttl_present: bool) -> usize {
    7 + usize::from(ttl_present)
}

impl PolicyUpdateBody {
    /// Canonical-CBOR body `[kind, channelID, epoch, issuer_id, 0, ttl_present, ttl?, 0]`, where
    /// `kind == KIND_POLICY_UPDATE` and the two zeros are the removed history-mode and suite
    /// presence flags.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(arity_for(self.ttl.is_some()));
        self.encode_fields(&mut e);
        e.finish()
    }

    fn encode_fields(&self, e: &mut Encoder) {
        e.uint(KIND_POLICY_UPDATE)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .uint(0)
            .uint(u64::from(self.ttl.is_some()));
        if let Some(ttl) = self.ttl {
            e.uint(ttl);
        }
        e.uint(0);
    }

    /// The signing input: `vox/policy-rotation/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::PolicyRotation, &self.canonical_body())
    }

    /// Decode the fields after the array header from `d`, which is positioned at the kind. A
    /// wrong kind (the reserved rotation), a history-mode or suite-floor update, and any
    /// presence or arity inconsistency are refused.
    fn decode_fields(d: &mut Decoder<'_>, arity: usize) -> Result<Self> {
        if d.uint()? != KIND_POLICY_UPDATE {
            return Err(Error::MalformedGovernance("policy-update wrong body kind"));
        }
        let channel_id = take_digest(d)?;
        let epoch = d.uint()?;
        let issuer_id = take_digest(d)?;
        if d.uint()? != 0 {
            return Err(Error::MalformedGovernance(
                "a policy update may change only the retention (history mode was removed)",
            ));
        }
        let ttl = match d.uint()? {
            0 => None,
            1 => Some(d.uint()?),
            _ => return Err(Error::MalformedGovernance("policy-update ttl_present")),
        };
        if d.uint()? != 0 {
            return Err(Error::MalformedGovernance(
                "a policy update may change only the retention (the suite floor is the genesis's)",
            ));
        }
        if arity != arity_for(ttl.is_some()) {
            return Err(Error::MalformedGovernance(
                "policy-update presence/arity mismatch",
            ));
        }
        Ok(Self {
            channel_id,
            epoch,
            issuer_id,
            ttl,
        })
    }
}

/// A complete, root-signed policy-update.
#[derive(Debug, Clone)]
pub struct PolicyUpdate {
    /// The signed body.
    pub body: PolicyUpdateBody,
    /// The issuer's composite root signature.
    pub signature: CompositeSignature,
}

impl PolicyUpdate {
    /// Build and root-sign a policy-update setting the room's retention to `ttl` seconds
    /// (`0` = forever).
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        ttl: u64,
    ) -> Result<Self> {
        let body = PolicyUpdateBody {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
            ttl: Some(ttl),
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0006`): the signed body fields then the
    /// composite signature appended as the final element.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(arity_for(self.body.ttl.is_some()) + 1);
        self.body.encode_fields(&mut e);
        e.bytes(&self.signature.to_bytes());
        frame(StructTag::PolicyRotation, &e.finish())
    }

    /// Parse a framed policy-update (does NOT verify — call [`PolicyUpdate::verify`]).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::PolicyRotation {
            return Err(Error::MalformedGovernance("policy-update wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        let wire_arity = d.array()?;
        if !(8..=9).contains(&wire_arity) {
            return Err(Error::MalformedGovernance("policy-update wire arity"));
        }
        let body = PolicyUpdateBody::decode_fields(&mut d, wire_arity - 1)?;
        let signature = parse_sig(d.bytes()?)?;
        d.finish()?;
        Ok(Self { body, signature })
    }

    /// Verify the issuer's signature and `issuer_id`↔signer binding (structural;
    /// whether the issuer *holds* the `policy` capability is the evaluator's job).
    pub fn verify(&self, issuer_root: &CompositePublicKey) -> Result<()> {
        if issuer_root.fingerprint() != self.body.issuer_id {
            return Err(Error::MalformedGovernance(
                "policy-update issuer_id != signer fingerprint",
            ));
        }
        issuer_root.verify(&self.body.signing_input(), &self.signature)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("policy-update digest length"))
}

fn parse_sig(bytes: &[u8]) -> Result<CompositeSignature> {
    let arr: [u8; COMPOSITE_SIG_LEN] = bytes
        .try_into()
        .map_err(|_| Error::MalformedGovernance("policy-update signature length"))?;
    CompositeSignature::from_bytes(&arr)
}
