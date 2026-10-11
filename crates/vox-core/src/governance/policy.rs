//! Policy-update entries (ADR-007 §"Per-type body schemas", tag `0x0006`, domain
//! `vox/policy-rotation/v2`; `v1` for a format-1 update, whose retention was in seconds and is
//! read as milliseconds, encoded and verified as it was written).
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
use crate::wire::{frame_at, parse_frame, signing_input_at, time_decoded, time_encoded, StructTag};

/// Body kind discriminant of a policy-update under the `PolicyRotation` tag (`0x0006`). Kind 2,
/// the passphrase rotation, is reserved: never written, refused on decode (V030-32).
pub(crate) const KIND_POLICY_UPDATE: u64 = 1;

/// The room's Session-step lifetime before any step policy update (ADR-031 SA-6). It is not
/// part of genesis, so adding independent retention never changes an existing room's identity.
pub const DEFAULT_STEP_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// The unsigned policy-update body (every field except the signature).
///
/// Each TTL is optional: `None` means "unchanged"; a body with both absent is inert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUpdateBody {
    /// The channel this update is valid in (ADR-005).
    pub channel_id: Digest32,
    /// The membership epoch this update is bound to (ADR-007).
    pub epoch: u64,
    /// The issuing `policy`-holder's identity fingerprint.
    pub issuer_id: Digest32,
    /// New retention in milliseconds (`0` = forever), or `None` to leave it unchanged.
    pub ttl_ms: Option<u64>,
    /// New Session-step retention in milliseconds (`0` forever), or no change. This optional
    /// extension is omitted entirely when absent, preserving every older signed byte.
    pub step_ttl_ms: Option<u64>,
    /// The format it was written in (see [`crate::governance::genesis`]).
    pub format: u8,
}

/// The elements a body or wire array holds: kind, channel, epoch, issuer, the history flag
/// (always 0), the ttl flag, the ttl if present, and the suite flag (always 0).
fn arity_for(ttl_present: bool, steps_present: bool) -> usize {
    7 + usize::from(ttl_present) + if steps_present { 2 } else { 0 }
}

impl PolicyUpdateBody {
    /// Canonical-CBOR body `[kind, channelID, epoch, issuer_id, 0, ttl_present, ttl?, 0]`, where
    /// `kind == KIND_POLICY_UPDATE` and the two zeros are the removed history-mode and suite
    /// presence flags. A step change alone appends `[1, step_ttl]`; no extension bytes are written
    /// for an older message-only policy.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(arity_for(self.ttl_ms.is_some(), self.step_ttl_ms.is_some()));
        self.encode_fields(&mut e);
        e.finish()
    }

    fn encode_fields(&self, e: &mut Encoder) {
        e.uint(KIND_POLICY_UPDATE)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .uint(0)
            .uint(u64::from(self.ttl_ms.is_some()));
        if let Some(ttl) = self.ttl_ms {
            e.uint(time_encoded(ttl, self.format));
        }
        e.uint(0);
        if let Some(ttl) = self.step_ttl_ms {
            e.uint(1).uint(time_encoded(ttl, self.format));
        }
    }

    /// The signing input: `vox/policy-rotation/v2 ‖ canonical_body` (ADR-008), or the `v1` label
    /// for a format-1 update.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input_at(
            StructTag::PolicyRotation,
            self.format,
            &self.canonical_body(),
        )
    }

    /// Decode the fields after the array header from `d`, which is positioned at the kind. A
    /// wrong kind (the reserved rotation), a history-mode or suite-floor update, and any
    /// presence or arity inconsistency are refused.
    fn decode_fields(d: &mut Decoder<'_>, arity: usize, format: u8) -> Result<Self> {
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
            1 => Some(time_decoded(d.uint()?, format)),
            _ => return Err(Error::MalformedGovernance("policy-update ttl_present")),
        };
        if d.uint()? != 0 {
            return Err(Error::MalformedGovernance(
                "a policy update may change only the retention (the suite floor is the genesis's)",
            ));
        }
        let base = arity_for(ttl.is_some(), false);
        let step_ttl_ms = if arity == base {
            None
        } else if arity == base + 2 && d.uint()? == 1 {
            Some(time_decoded(d.uint()?, format))
        } else {
            return Err(Error::MalformedGovernance(
                "policy-update presence/arity mismatch",
            ));
        };
        Ok(Self {
            channel_id,
            epoch,
            issuer_id,
            ttl_ms: ttl,
            step_ttl_ms,
            format,
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
    /// Build and root-sign a policy-update setting the room's retention to `ttl_ms` milliseconds
    /// (`0` = forever).
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        ttl_ms: u64,
    ) -> Result<Self> {
        let body = PolicyUpdateBody {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
            ttl_ms: Some(ttl_ms),
            step_ttl_ms: None,
            format: StructTag::PolicyRotation.format_version(),
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Build and root-sign an independent Session-step policy without changing message TTL.
    /// `step_ttl_ms` is milliseconds, with zero meaning forever (still clamped by messages).
    pub fn build_steps(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        step_ttl_ms: u64,
    ) -> Result<Self> {
        let body = PolicyUpdateBody {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
            ttl_ms: None,
            step_ttl_ms: Some(step_ttl_ms),
            format: StructTag::PolicyRotation.format_version(),
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0006`): the signed body fields then the
    /// composite signature appended as the final element.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(arity_for(self.body.ttl_ms.is_some(), self.body.step_ttl_ms.is_some()) + 1);
        self.body.encode_fields(&mut e);
        e.bytes(&self.signature.to_bytes());
        frame_at(StructTag::PolicyRotation, self.body.format, &e.finish())
    }

    /// Parse a framed policy-update (does NOT verify — call [`PolicyUpdate::verify`]).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::PolicyRotation {
            return Err(Error::MalformedGovernance("policy-update wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        let wire_arity = d.array()?;
        if !(8..=11).contains(&wire_arity) {
            return Err(Error::MalformedGovernance("policy-update wire arity"));
        }
        let body = PolicyUpdateBody::decode_fields(&mut d, wire_arity - 1, parsed.version)?;
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
