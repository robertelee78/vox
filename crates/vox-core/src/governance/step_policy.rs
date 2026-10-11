//! Independent Session retention (ADR-031 SA-9), in a public content carrier.
//!
//! Published readers accept this existing carrier's signed log entry and skip its unknown
//! subtype. Extending PolicyUpdate's exact CBOR arity would make them reject the author's feed.
//! New readers position this separately signed fact in the ordinary governance evaluator, so
//! policy authority is checked in its strict causal past, with the same revocation and ordering
//! rules as message retention. The record itself is never subject to content retention.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::wire::GROUP_MSG_SIGN_DOMAIN;
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};

const DOMAIN: &str = "vox/step-policy/v1";

/// Default Session activity lifetime (SA-9); kept outside genesis so room identities stay fixed.
pub const DEFAULT_STEP_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// A root-signed step policy, bound again to its enclosing log entry by `GovEntry`.
#[derive(Debug, Clone)]
pub struct StepPolicyUpdate {
    /// The room whose Session activity lifetime changes.
    pub channel_id: Digest32,
    /// The room epoch at this update's causal position.
    pub epoch: u64,
    /// The issuing identity; the evaluator requires its policy authority.
    pub issuer_id: Digest32,
    /// New lifetime in milliseconds; zero is forever, still capped by message retention.
    pub ttl_ms: u64,
    /// Separate domain-bound root signature over the canonical body.
    pub signature: CompositeSignature,
}

impl StepPolicyUpdate {
    fn signing_input(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .uint(self.ttl_ms);
        let mut input = DOMAIN.as_bytes().to_vec();
        input.extend(e.finish());
        input
    }

    /// Sign a step lifetime. Authority is evaluated at the signed log entry's causal position.
    pub fn build(
        issuer: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        ttl_ms: u64,
    ) -> Result<Self> {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(channel_id)
            .uint(epoch)
            .bytes(&issuer.fingerprint())
            .uint(ttl_ms);
        let mut input = DOMAIN.as_bytes().to_vec();
        input.extend(e.finish());
        Ok(Self {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer.fingerprint(),
            ttl_ms,
            signature: issuer.sign(&input)?,
        })
    }

    /// Existing content carrier, with a distinct canonical six-field control body.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6)
            .text(DOMAIN)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .uint(self.ttl_ms)
            .bytes(&self.signature.to_bytes());
        let mut wire = GROUP_MSG_SIGN_DOMAIN.as_bytes().to_vec();
        wire.extend(e.finish());
        wire
    }

    /// Decode a canonical control; the enclosing entry and this body's signature are checked
    /// independently before it can influence the evaluator.
    pub fn from_wire(wire: &[u8]) -> Result<Self> {
        let body = wire
            .strip_prefix(GROUP_MSG_SIGN_DOMAIN.as_bytes())
            .ok_or(Error::MalformedGovernance("step policy carrier"))?;
        let mut d = Decoder::new(body);
        if d.array()? != 6 || d.text()? != DOMAIN {
            return Err(Error::MalformedGovernance("step policy subtype"));
        }
        let channel_id = digest(&mut d)?;
        let epoch = d.uint()?;
        let issuer_id = digest(&mut d)?;
        let ttl_ms = d.uint()?;
        let sig: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("step policy signature length"))?;
        d.finish()?;
        let value = Self {
            channel_id,
            epoch,
            issuer_id,
            ttl_ms,
            signature: CompositeSignature::from_bytes(&sig)?,
        };
        if value.to_wire() != wire {
            return Err(Error::MalformedGovernance("noncanonical step policy"));
        }
        Ok(value)
    }

    /// Check the declared issuer and the policy-specific root signature.
    pub fn verify(&self, issuer: &CompositePublicKey) -> Result<()> {
        if issuer.fingerprint() != self.issuer_id {
            return Err(Error::MalformedGovernance(
                "step policy issuer differs from signer",
            ));
        }
        issuer.verify(&self.signing_input(), &self.signature)
    }
}

/// Recognize only canonical policy controls, never a user message containing the marker.
#[must_use]
pub fn is_step_policy(wire: &[u8]) -> bool {
    StepPolicyUpdate::from_wire(wire).is_ok()
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("step policy digest length"))
}
