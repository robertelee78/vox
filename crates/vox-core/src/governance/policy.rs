//! Policy-update entries (ADR-007 §"Per-type body schemas", tag `0x0006`, domain
//! `vox/policy-rotation/v1`).
//!
//! A policy-update, issued by a holder of the `policy` capability
//! ([`crate::governance::capability::Capability::Policy`]), changes the channel's
//! **history-mode and/or TTL** from its causal position forward. Body:
//! `{ history_mode?, ttl? }` — both optional.
//!
//! ## The deniability axis is genesis-immutable
//! A policy-update **MUST NOT** change `deniability_mode`: it is set once in the
//! genesis record ([`crate::governance::genesis`]) and never moves. There is no
//! `deniability_mode` field in this struct *at all*, so the prohibition is
//! enforced at the schema level — there is nothing to set. The strict body
//! decoder only ever reads the history/ttl fields, so a malformed body cannot
//! smuggle a deniability change in either.
//! Rationale (ADR-007): members join under a fixed authorship-accountability
//! contract; flipping attributable↔deniable mid-life would change the threat
//! model under existing members and the fork-handling split (ADR-008). History
//! and TTL are retention conveniences with no such trust-contract inversion.
//!
//! The same domain label (`vox/policy-rotation/v1`) and tag (`0x0006`) cover both
//! a policy-update and a passphrase-rotation entry (the M0 wire registry collapses
//! them into one `PolicyRotation` tag); the two are distinguished by a leading
//! *kind* discriminant in the body so neither can be reinterpreted as the other.
//! The passphrase-rotation (epoch-bump) entry lives in
//! [`crate::governance::rotation`].

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::genesis::HistoryMode;
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// Body kind discriminant distinguishing a policy-update from a
/// passphrase-rotation under the shared `PolicyRotation` tag (`0x0006`).
pub(crate) const KIND_POLICY_UPDATE: u64 = 1;
/// Body kind discriminant for a passphrase-rotation (epoch bump),
/// [`crate::governance::rotation`].
pub(crate) const KIND_PASSPHRASE_ROTATION: u64 = 2;

/// The unsigned policy-update body (every field except the signature).
///
/// Both `history_mode` and `ttl` are optional: `None` means "unchanged". A
/// policy-update that changes *nothing* (both `None`) is structurally valid but
/// inert; callers normally set at least one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUpdateBody {
    /// The channel this update is valid in (ADR-005).
    pub channel_id: Digest32,
    /// The membership epoch this update is bound to (ADR-007).
    pub epoch: u64,
    /// The issuing `policy`-holder's identity fingerprint.
    pub issuer_id: Digest32,
    /// New history mode, or `None` to leave it unchanged.
    pub history_mode: Option<HistoryMode>,
    /// New payload TTL in seconds (`0` = never), or `None` to leave unchanged.
    pub ttl: Option<u64>,
}

impl PolicyUpdateBody {
    /// Canonical-CBOR body
    /// `[kind, channelID, epoch, issuer_id, history_present, history_mode?,
    ///   ttl_present, ttl?]` where `kind == KIND_POLICY_UPDATE`. An absent optional
    /// field omits its value element (presence flag only), so two implementations
    /// encode the identical bytes for the identical logical update.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let hist_present = self.history_mode.is_some();
        let ttl_present = self.ttl.is_some();
        // Fixed leading fields: kind, channel, epoch, issuer, hist_present.
        // Then optional history value, ttl_present, optional ttl value.
        let arity = 5 + usize::from(hist_present) + 1 + usize::from(ttl_present);
        let mut e = Encoder::new();
        e.array(arity)
            .uint(KIND_POLICY_UPDATE)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .uint(u64::from(hist_present));
        if let Some(hm) = self.history_mode {
            e.uint(hm.as_u64());
        }
        e.uint(u64::from(ttl_present));
        if let Some(ttl) = self.ttl {
            e.uint(ttl);
        }
        e.finish()
    }

    /// The signing input: `vox/policy-rotation/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::PolicyRotation, &self.canonical_body())
    }

    /// Decode a policy-update body. Rejects a wrong kind discriminant (so a
    /// passphrase-rotation body cannot be parsed as a policy-update) and any
    /// presence/arity inconsistency. There is no `deniability_mode` element to
    /// decode — the genesis-immutability of that axis is enforced by the schema.
    fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        let arity = d.array()?;
        // Min arity: kind, channel, epoch, issuer, hist_present, ttl_present = 6.
        if !(6..=8).contains(&arity) {
            return Err(Error::MalformedGovernance("policy-update arity"));
        }
        let kind = d.uint()?;
        if kind != KIND_POLICY_UPDATE {
            return Err(Error::MalformedGovernance("policy-update wrong body kind"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let issuer_id = take_digest(&mut d)?;
        let hist_present = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedGovernance("policy-update hist_present")),
        };
        let history_mode = if hist_present {
            Some(HistoryMode::from_u64(d.uint()?)?)
        } else {
            None
        };
        let ttl_present = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedGovernance("policy-update ttl_present")),
        };
        let ttl = if ttl_present { Some(d.uint()?) } else { None };
        d.finish()?;

        // Arity must exactly match the presence flags (no extra/missing elements).
        let expected = 5 + usize::from(hist_present) + 1 + usize::from(ttl_present);
        if arity != expected {
            return Err(Error::MalformedGovernance(
                "policy-update presence/arity mismatch",
            ));
        }
        Ok(Self {
            channel_id,
            epoch,
            issuer_id,
            history_mode,
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
    /// Build and root-sign a policy-update. At least one of `history_mode`/`ttl`
    /// is normally set; both `None` is permitted but inert. (`deniability_mode`
    /// cannot be expressed — the struct has no such field, ADR-007.)
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        history_mode: Option<HistoryMode>,
        ttl: Option<u64>,
    ) -> Result<Self> {
        let body = PolicyUpdateBody {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
            history_mode,
            ttl,
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0006`): the signed body fields then the
    /// composite signature appended as the final element.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let hist_present = b.history_mode.is_some();
        let ttl_present = b.ttl.is_some();
        let signed_arity = 5 + usize::from(hist_present) + 1 + usize::from(ttl_present);
        let mut e = Encoder::new();
        e.array(signed_arity + 1)
            .uint(KIND_POLICY_UPDATE)
            .bytes(&b.channel_id)
            .uint(b.epoch)
            .bytes(&b.issuer_id)
            .uint(u64::from(hist_present));
        if let Some(hm) = b.history_mode {
            e.uint(hm.as_u64());
        }
        e.uint(u64::from(ttl_present));
        if let Some(ttl) = b.ttl {
            e.uint(ttl);
        }
        e.bytes(&self.signature.to_bytes());
        frame(StructTag::PolicyRotation, &e.finish())
    }

    /// Parse a framed policy-update (does NOT verify — call [`PolicyUpdate::verify`]).
    ///
    /// Rejects a frame whose body kind is a passphrase-rotation (wrong kind),
    /// keeping the two `0x0006` structs unambiguous.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::PolicyRotation {
            return Err(Error::MalformedGovernance("policy-update wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        let wire_arity = d.array()?;
        if !(7..=9).contains(&wire_arity) {
            return Err(Error::MalformedGovernance("policy-update wire arity"));
        }
        // Read the leading kind to fail fast on a passphrase-rotation body.
        let kind = d.uint()?;
        if kind != KIND_POLICY_UPDATE {
            return Err(Error::MalformedGovernance("policy-update wrong body kind"));
        }
        let channel_id = d.bytes()?.to_vec();
        let epoch = d.uint()?;
        let issuer_id = d.bytes()?.to_vec();
        let hist_present = d.uint()?;
        let history_mode = if hist_present == 1 {
            Some(d.uint()?)
        } else {
            None
        };
        let ttl_present = d.uint()?;
        let ttl = if ttl_present == 1 {
            Some(d.uint()?)
        } else {
            None
        };
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;

        // Rebuild the signed body bytes and decode strictly.
        let mut be = Encoder::new();
        let signed_arity = 5 + usize::from(hist_present == 1) + 1 + usize::from(ttl_present == 1);
        be.array(signed_arity)
            .uint(KIND_POLICY_UPDATE)
            .bytes(&channel_id)
            .uint(epoch)
            .bytes(&issuer_id)
            .uint(hist_present);
        if let Some(hm) = history_mode {
            be.uint(hm);
        }
        be.uint(ttl_present);
        if let Some(t) = ttl {
            be.uint(t);
        }
        let body = PolicyUpdateBody::from_canonical_body(&be.finish())?;
        let signature = parse_sig(&sig_bytes)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    const CID: Digest32 = [0xC0; 32];

    #[test]
    fn both_fields_round_trip() {
        let r = root(1, 2);
        let pu =
            PolicyUpdate::build(&r, &CID, 1, Some(HistoryMode::FullHistory), Some(3600)).unwrap();
        assert!(pu.verify(&r.public_key()).is_ok());
        let decoded = PolicyUpdate::from_wire(&pu.to_wire()).unwrap();
        assert_eq!(decoded.body, pu.body);
        assert_eq!(decoded.body.history_mode, Some(HistoryMode::FullHistory));
        assert_eq!(decoded.body.ttl, Some(3600));
        assert!(decoded.verify(&r.public_key()).is_ok());
    }

    #[test]
    fn only_history_round_trips() {
        let r = root(3, 4);
        let pu = PolicyUpdate::build(&r, &CID, 1, Some(HistoryMode::ForwardOnly), None).unwrap();
        let decoded = PolicyUpdate::from_wire(&pu.to_wire()).unwrap();
        assert_eq!(decoded.body.history_mode, Some(HistoryMode::ForwardOnly));
        assert_eq!(decoded.body.ttl, None);
        assert!(decoded.verify(&r.public_key()).is_ok());
    }

    #[test]
    fn only_ttl_round_trips() {
        let r = root(5, 6);
        let pu = PolicyUpdate::build(&r, &CID, 1, None, Some(0)).unwrap();
        let decoded = PolicyUpdate::from_wire(&pu.to_wire()).unwrap();
        assert_eq!(decoded.body.history_mode, None);
        assert_eq!(decoded.body.ttl, Some(0));
    }

    #[test]
    fn empty_update_round_trips() {
        let r = root(7, 8);
        let pu = PolicyUpdate::build(&r, &CID, 1, None, None).unwrap();
        let decoded = PolicyUpdate::from_wire(&pu.to_wire()).unwrap();
        assert_eq!(decoded.body.history_mode, None);
        assert_eq!(decoded.body.ttl, None);
        assert!(decoded.verify(&r.public_key()).is_ok());
    }

    #[test]
    fn tamper_rejected() {
        let r = root(9, 10);
        let pu = PolicyUpdate::build(&r, &CID, 1, Some(HistoryMode::ForwardOnly), None).unwrap();
        let mut decoded = PolicyUpdate::from_wire(&pu.to_wire()).unwrap();
        decoded.body.history_mode = Some(HistoryMode::FullHistory);
        assert!(decoded.verify(&r.public_key()).is_err());
    }

    #[test]
    fn rejects_passphrase_rotation_kind() {
        // A body with KIND_PASSPHRASE_ROTATION must not parse as a policy-update,
        // so the two structs sharing tag 0x0006 stay unambiguous.
        let mut be = Encoder::new();
        be.array(6)
            .uint(KIND_PASSPHRASE_ROTATION)
            .bytes(&CID)
            .uint(1)
            .bytes(&[0u8; 32])
            .uint(0)
            .uint(0);
        assert!(matches!(
            PolicyUpdateBody::from_canonical_body(&be.finish()),
            Err(Error::MalformedGovernance("policy-update wrong body kind"))
        ));
    }

    #[test]
    fn deniability_mode_is_unrepresentable() {
        // There is no API to set deniability_mode on a policy-update — the struct
        // has no such field. This test documents the schema-level enforcement: the
        // builder signature simply has no deniability parameter.
        let r = root(1, 1);
        let pu = PolicyUpdate::build(&r, &CID, 1, Some(HistoryMode::FullHistory), Some(1)).unwrap();
        // The canonical body has the fixed layout with no deniability element; a
        // round-trip preserves exactly history+ttl and nothing else.
        let decoded = PolicyUpdate::from_wire(&pu.to_wire()).unwrap();
        assert_eq!(decoded.body.history_mode, Some(HistoryMode::FullHistory));
        assert_eq!(decoded.body.ttl, Some(1));
    }
}
