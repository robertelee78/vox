//! Admin-delegation certificates and their revocations (ADR-007
//! §"Per-type body schemas").
//!
//! - **Admin-delegation cert** (tag `0x0003`, domain `vox/admin-cert/v1`): an
//!   admin names a *delegate* identity key and a granted capability set,
//!   optionally attenuated and optionally with an expiry. Delegations chain to
//!   genesis, forming an SPKI/SDSI/UCAN-style capability tree the client verifies
//!   independently; no capability can exceed its issuer's (monotonic attenuation,
//!   enforced by [`crate::governance::evaluator`]).
//! - **Admin-delegation revocation** (tag `0x000E`, domain
//!   `vox/admin-delegation-revocation/v1`): the first-class revocation the
//!   conflict rules reference — revocation-wins, ordered by the ascending
//!   entry-hash tie-break (ADR-007 §"Conflict resolution").
//!
//! Both are composite-signed by the **issuer's identity root** and bound to
//! `(channelID, epoch)` so a cert minted for one channel/epoch cannot be replayed
//! into another (cross-group-confusion guard, ADR-006/ADR-007). They ride the
//! causal log as `EntryKind::Governance` payloads ([`crate::governance::entry`]).
//!
//! ## The cert body (signing input, ADR-007)
//! `[channelID, epoch, issuer_id, delegate_pubkey, capability_set[], expiry,
//!   [sign_algo]]` where `expiry == 0` means *no expiry* and a non-zero value is
//! the epoch-seconds deadline. `capability_set` is the canonical (sorted) token
//! array from [`crate::governance::capability`]. The wire body appends the
//! composite signature as a final element.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::capability::CapabilitySet;
use crate::hash::{Digest32, COMPOSITE_PUB_LEN, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::suite::{algo, validate_algo};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// Hard cap on the number of capabilities in one delegation cert, enforced
/// before interning the token array (anti-abuse, ADR-008): a cert grants a small
/// set, never thousands.
pub const MAX_CAPABILITY_SET: usize = 64;

/// Reason codes for an admin-delegation revocation (ADR-007 `reason?` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationReason {
    /// No specific reason given (the `reason?` field is absent on the wire).
    Unspecified,
    /// The delegate's key is believed compromised.
    Compromise,
    /// The delegation is no longer needed (routine de-provisioning).
    NoLongerNeeded,
}

impl RevocationReason {
    /// The wire discriminant. [`RevocationReason::Unspecified`] is encoded as the
    /// *absence* of the optional field, so it has no positive discriminant here.
    const fn as_u64(self) -> u64 {
        match self {
            // Unspecified never reaches here (encoded as field absence); map to 0
            // for totality.
            RevocationReason::Unspecified => 0,
            RevocationReason::Compromise => 1,
            RevocationReason::NoLongerNeeded => 2,
        }
    }

    fn from_u64(v: u64) -> Result<Self> {
        match v {
            1 => Ok(RevocationReason::Compromise),
            2 => Ok(RevocationReason::NoLongerNeeded),
            _ => Err(Error::MalformedGovernance(
                "revocation reason out of domain",
            )),
        }
    }
}

/// The unsigned admin-delegation cert body (every field except the signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCertBody {
    /// The channel this cert is valid in (ADR-005).
    pub channel_id: Digest32,
    /// The membership epoch this cert is bound to (ADR-007).
    pub epoch: u64,
    /// The issuing admin's identity fingerprint.
    pub issuer_id: Digest32,
    /// The delegate's composite root public key being granted authority.
    pub delegate_pubkey: CompositePublicKey,
    /// The granted capability set (attenuated; never exceeding the issuer's).
    pub capability_set: CapabilitySet,
    /// Expiry in epoch-seconds; `0` means no expiry (ADR-007 `expiry?`).
    pub expiry: u64,
}

impl AdminCertBody {
    /// Canonical-CBOR body in the ADR-007 field order
    /// `[channelID, epoch, issuer_id, delegate_pubkey, capability_tokens[],
    ///   expiry, [sign_algo]]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let tokens = self.capability_set.to_tokens();
        let mut e = Encoder::new();
        e.array(7)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .bytes(&self.delegate_pubkey.to_bytes())
            .array(tokens.len());
        for t in &tokens {
            e.text(t);
        }
        e.uint(self.expiry)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.finish()
    }

    /// The signing input: `vox/admin-cert/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::AdminCert, &self.canonical_body())
    }

    /// The delegate's identity fingerprint (the key the grant authorizes).
    #[must_use]
    pub fn delegate_id(&self) -> Digest32 {
        self.delegate_pubkey.fingerprint()
    }

    fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 7 {
            return Err(Error::MalformedGovernance("admin-cert arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let issuer_id = take_digest(&mut d)?;
        let pk_bytes: [u8; COMPOSITE_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("admin-cert delegate_pubkey length"))?;
        let set_len = d.array()?;
        if set_len > MAX_CAPABILITY_SET {
            return Err(Error::SizeLimitExceeded("admin-cert capability set"));
        }
        let mut tokens = Vec::with_capacity(set_len);
        for _ in 0..set_len {
            tokens.push(d.text()?.to_owned());
        }
        let expiry = d.uint()?;
        if d.array()? != 1 {
            return Err(Error::MalformedGovernance("admin-cert algo_ids arity"));
        }
        let sign_algo = u16_from(d.uint()?)?;
        d.finish()?;

        validate_algo(sign_algo)?;
        if sign_algo != algo::COMPOSITE_ED25519_ML_DSA_65 {
            return Err(Error::UnexpectedAlgo {
                got: sign_algo,
                expected: algo::COMPOSITE_ED25519_ML_DSA_65,
            });
        }
        let delegate_pubkey = CompositePublicKey::from_bytes(&pk_bytes)?;
        let capability_set = CapabilitySet::from_tokens(&tokens)?;
        Ok(Self {
            channel_id,
            epoch,
            issuer_id,
            delegate_pubkey,
            capability_set,
            expiry,
        })
    }
}

/// A complete, root-signed admin-delegation cert: the body plus the issuer's
/// composite root signature over [`AdminCertBody::signing_input`].
#[derive(Debug, Clone)]
pub struct AdminCert {
    /// The signed body.
    pub body: AdminCertBody,
    /// The issuer's composite root signature.
    pub signature: CompositeSignature,
}

impl AdminCert {
    /// Build and root-sign a delegation cert. `issuer_root`'s fingerprint MUST be
    /// the `issuer_id` in the body (enforced here so the signer matches the claim).
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        delegate_pubkey: CompositePublicKey,
        capability_set: CapabilitySet,
        expiry: u64,
    ) -> Result<Self> {
        let body = AdminCertBody {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
            delegate_pubkey,
            capability_set,
            expiry,
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0003`): the 7 signed body fields then
    /// the composite signature as an 8th element. The signed canonical body is a
    /// 7-element array; the wire body re-emits those fields with arity 8 (we
    /// cannot append to a finished CBOR array), so the signing input is recovered
    /// exactly on parse.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let tokens = self.body.capability_set.to_tokens();
        let mut e = Encoder::new();
        e.array(8)
            .bytes(&self.body.channel_id)
            .uint(self.body.epoch)
            .bytes(&self.body.issuer_id)
            .bytes(&self.body.delegate_pubkey.to_bytes())
            .array(tokens.len());
        for t in &tokens {
            e.text(t);
        }
        e.uint(self.body.expiry)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.bytes(&self.signature.to_bytes());
        frame(StructTag::AdminCert, &e.finish())
    }

    /// Parse a framed admin-delegation cert (does NOT verify — call
    /// [`AdminCert::verify`]).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::AdminCert {
            return Err(Error::MalformedGovernance("admin-cert wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 8 {
            return Err(Error::MalformedGovernance("admin-cert wire arity"));
        }
        let channel_id = d.bytes()?.to_vec();
        let epoch = d.uint()?;
        let issuer_id = d.bytes()?.to_vec();
        let delegate_pubkey = d.bytes()?.to_vec();
        let set_len = d.array()?;
        if set_len > MAX_CAPABILITY_SET {
            return Err(Error::SizeLimitExceeded("admin-cert capability set"));
        }
        let mut tokens = Vec::with_capacity(set_len);
        for _ in 0..set_len {
            tokens.push(d.text()?.to_owned());
        }
        let expiry = d.uint()?;
        if d.array()? != 1 {
            return Err(Error::MalformedGovernance("admin-cert algo_ids arity"));
        }
        let sign_algo = d.uint()?;
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;

        // Rebuild the 7-field signed body and decode strictly.
        let mut be = Encoder::new();
        be.array(7)
            .bytes(&channel_id)
            .uint(epoch)
            .bytes(&issuer_id)
            .bytes(&delegate_pubkey)
            .array(tokens.len());
        for t in &tokens {
            be.text(t);
        }
        be.uint(expiry).array(1).uint(sign_algo);
        let body = AdminCertBody::from_canonical_body(&be.finish())?;

        let signature = parse_sig(&sig_bytes)?;
        Ok(Self { body, signature })
    }

    /// Verify the issuer's signature and the `issuer_id`↔signer binding.
    ///
    /// `issuer_root` is the *claimed issuer's* composite root public key; the
    /// check passes only if its fingerprint equals the body's `issuer_id` and the
    /// composite signature verifies over the signing input. (Whether the issuer is
    /// *authorized* to delegate — the chain-to-genesis + attenuation check — is the
    /// evaluator's job, not this structural verify.)
    pub fn verify(&self, issuer_root: &CompositePublicKey) -> Result<()> {
        if issuer_root.fingerprint() != self.body.issuer_id {
            return Err(Error::MalformedGovernance(
                "admin-cert issuer_id != signer fingerprint",
            ));
        }
        issuer_root.verify(&self.body.signing_input(), &self.signature)
    }
}

/// The unsigned admin-delegation-revocation body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRevocationBody {
    /// The channel this revocation is valid in.
    pub channel_id: Digest32,
    /// The membership epoch this revocation is bound to.
    pub epoch: u64,
    /// The revoking admin's identity fingerprint.
    pub issuer_id: Digest32,
    /// The entry hash (SHA-256 of the canonical log entry, ADR-008) of the
    /// admin-delegation being revoked.
    pub revoked_delegation_hash: Digest32,
    /// The reason (ADR-007 `reason?`); [`RevocationReason::Unspecified`] omits it.
    pub reason: RevocationReason,
}

impl AdminRevocationBody {
    /// Canonical-CBOR body
    /// `[channelID, epoch, issuer_id, revoked_delegation_hash, reason_present,
    ///   reason?, [sign_algo]]`. `reason_present` is 0/1; the `reason?` element is
    /// present iff `reason_present == 1` (so [`RevocationReason::Unspecified`]
    /// genuinely omits the field, per ADR-007 `reason?`).
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        let has_reason = !matches!(self.reason, RevocationReason::Unspecified);
        let arity = if has_reason { 7 } else { 6 };
        e.array(arity)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .bytes(&self.revoked_delegation_hash)
            .uint(u64::from(has_reason));
        if has_reason {
            e.uint(self.reason.as_u64());
        }
        e.array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.finish()
    }

    /// The signing input: `vox/admin-delegation-revocation/v1 ‖ canonical_body`.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::AdminDelegationRevocation, &self.canonical_body())
    }

    fn decode(d: &mut Decoder<'_>, arity: usize) -> Result<Self> {
        if arity != 6 && arity != 7 {
            return Err(Error::MalformedGovernance("admin-revocation arity"));
        }
        let channel_id = take_digest(d)?;
        let epoch = d.uint()?;
        let issuer_id = take_digest(d)?;
        let revoked_delegation_hash = take_digest(d)?;
        let has_reason = match d.uint()? {
            0 => false,
            1 => true,
            _ => {
                return Err(Error::MalformedGovernance(
                    "admin-revocation reason_present",
                ))
            }
        };
        let reason = if has_reason {
            if arity != 7 {
                return Err(Error::MalformedGovernance("admin-revocation reason arity"));
            }
            RevocationReason::from_u64(d.uint()?)?
        } else {
            if arity != 6 {
                return Err(Error::MalformedGovernance("admin-revocation reason arity"));
            }
            RevocationReason::Unspecified
        };
        if d.array()? != 1 {
            return Err(Error::MalformedGovernance(
                "admin-revocation algo_ids arity",
            ));
        }
        let sign_algo = u16_from(d.uint()?)?;
        validate_algo(sign_algo)?;
        if sign_algo != algo::COMPOSITE_ED25519_ML_DSA_65 {
            return Err(Error::UnexpectedAlgo {
                got: sign_algo,
                expected: algo::COMPOSITE_ED25519_ML_DSA_65,
            });
        }
        Ok(Self {
            channel_id,
            epoch,
            issuer_id,
            revoked_delegation_hash,
            reason,
        })
    }
}

/// A complete, root-signed admin-delegation revocation.
#[derive(Debug, Clone)]
pub struct AdminRevocation {
    /// The signed body.
    pub body: AdminRevocationBody,
    /// The issuer's composite root signature.
    pub signature: CompositeSignature,
}

impl AdminRevocation {
    /// Build and root-sign an admin-delegation revocation.
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        revoked_delegation_hash: Digest32,
        reason: RevocationReason,
    ) -> Result<Self> {
        let body = AdminRevocationBody {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
            revoked_delegation_hash,
            reason,
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x000E`): the signed body fields then the
    /// composite signature. The signed body has arity 6 (no reason) or 7 (with
    /// reason); the wire body re-emits those fields with arity+1 so the signing
    /// input is recovered exactly on parse.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let has_reason = !matches!(self.body.reason, RevocationReason::Unspecified);
        let signed_arity = if has_reason { 7 } else { 6 };
        let mut e = Encoder::new();
        e.array(signed_arity + 1);
        e.bytes(&self.body.channel_id)
            .uint(self.body.epoch)
            .bytes(&self.body.issuer_id)
            .bytes(&self.body.revoked_delegation_hash)
            .uint(u64::from(has_reason));
        if has_reason {
            e.uint(self.body.reason.as_u64());
        }
        e.array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.bytes(&self.signature.to_bytes());
        frame(StructTag::AdminDelegationRevocation, &e.finish())
    }

    /// Parse a framed admin-delegation revocation (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::AdminDelegationRevocation {
            return Err(Error::MalformedGovernance(
                "admin-revocation wrong struct tag",
            ));
        }
        let mut d = Decoder::new(parsed.body);
        let wire_arity = d.array()?;
        // The wire body is the signed body's arity + 1 (the signature). Signed
        // arity is 6 (no reason) or 7 (with reason), so wire arity is 7 or 8.
        let signed_arity = match wire_arity {
            7 => 6,
            8 => 7,
            _ => return Err(Error::MalformedGovernance("admin-revocation wire arity")),
        };
        let body = AdminRevocationBody::decode(&mut d, signed_arity)?;
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;
        let signature = parse_sig(&sig_bytes)?;
        Ok(Self { body, signature })
    }

    /// Verify the issuer's signature and `issuer_id`↔signer binding (structural;
    /// authorization is the evaluator's job).
    pub fn verify(&self, issuer_root: &CompositePublicKey) -> Result<()> {
        if issuer_root.fingerprint() != self.body.issuer_id {
            return Err(Error::MalformedGovernance(
                "admin-revocation issuer_id != signer fingerprint",
            ));
        }
        issuer_root.verify(&self.body.signing_input(), &self.signature)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("governance digest length"))
}

fn parse_sig(bytes: &[u8]) -> Result<CompositeSignature> {
    let arr: [u8; COMPOSITE_SIG_LEN] = bytes
        .try_into()
        .map_err(|_| Error::MalformedGovernance("governance signature length"))?;
    CompositeSignature::from_bytes(&arr)
}

fn u16_from(v: u64) -> Result<u16> {
    u16::try_from(v).map_err(|_| Error::MalformedGovernance("governance algo id out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::capability::Capability;
    use crate::identity::composite::SoftwareRootSigner;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    const CID: Digest32 = [0xC0; 32];

    #[test]
    fn admin_cert_round_trip_and_verify() {
        let issuer = root(1, 2);
        let delegate = root(3, 4);
        let caps = CapabilitySet::from_iter_caps([Capability::Invite, Capability::Policy]);
        let cert =
            AdminCert::build(&issuer, &CID, 1, delegate.public_key(), caps.clone(), 0).unwrap();
        assert!(cert.verify(&issuer.public_key()).is_ok());
        let decoded = AdminCert::from_wire(&cert.to_wire()).unwrap();
        assert_eq!(decoded.body, cert.body);
        assert_eq!(decoded.body.capability_set, caps);
        assert!(decoded.verify(&issuer.public_key()).is_ok());
    }

    #[test]
    fn admin_cert_tamper_rejected() {
        let issuer = root(5, 6);
        let delegate = root(7, 8);
        let cert = AdminCert::build(
            &issuer,
            &CID,
            1,
            delegate.public_key(),
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        )
        .unwrap();
        let mut decoded = AdminCert::from_wire(&cert.to_wire()).unwrap();
        decoded.body.epoch = 999;
        assert!(decoded.verify(&issuer.public_key()).is_err());
    }

    #[test]
    fn admin_cert_issuer_must_match_signer() {
        let issuer = root(1, 1);
        let other = root(2, 2);
        let delegate = root(3, 3);
        let cert = AdminCert::build(
            &issuer,
            &CID,
            1,
            delegate.public_key(),
            CapabilitySet::admin(),
            0,
        )
        .unwrap();
        assert!(cert.verify(&other.public_key()).is_err());
    }

    #[test]
    fn admin_cert_with_expiry_round_trips() {
        let issuer = root(9, 9);
        let delegate = root(8, 8);
        let cert = AdminCert::build(
            &issuer,
            &CID,
            2,
            delegate.public_key(),
            CapabilitySet::from_iter_caps([Capability::Delegate]),
            1_700_000_500,
        )
        .unwrap();
        let decoded = AdminCert::from_wire(&cert.to_wire()).unwrap();
        assert_eq!(decoded.body.expiry, 1_700_000_500);
    }

    #[test]
    fn admin_cert_rejects_unknown_capability_token() {
        // Hand-build a body with an unknown token and confirm the strict decoder
        // rejects it (closed vocabulary).
        let mut be = Encoder::new();
        be.array(7)
            .bytes(&CID)
            .uint(1)
            .bytes(&[0u8; 32])
            .bytes(&[0u8; COMPOSITE_PUB_LEN])
            .array(1)
            .text("superuser");
        be.uint(0)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        assert!(matches!(
            AdminCertBody::from_canonical_body(&be.finish()),
            Err(Error::UnknownCapability)
        ));
    }

    #[test]
    fn admin_revocation_round_trip_with_reason() {
        let issuer = root(1, 2);
        let rev =
            AdminRevocation::build(&issuer, &CID, 1, [0xAB; 32], RevocationReason::Compromise)
                .unwrap();
        assert!(rev.verify(&issuer.public_key()).is_ok());
        let decoded = AdminRevocation::from_wire(&rev.to_wire()).unwrap();
        assert_eq!(decoded.body.reason, RevocationReason::Compromise);
        assert_eq!(decoded.body.revoked_delegation_hash, [0xAB; 32]);
        assert!(decoded.verify(&issuer.public_key()).is_ok());
    }

    #[test]
    fn admin_revocation_round_trip_without_reason() {
        let issuer = root(3, 4);
        let rev =
            AdminRevocation::build(&issuer, &CID, 1, [0xCD; 32], RevocationReason::Unspecified)
                .unwrap();
        let decoded = AdminRevocation::from_wire(&rev.to_wire()).unwrap();
        assert_eq!(decoded.body.reason, RevocationReason::Unspecified);
        assert!(decoded.verify(&issuer.public_key()).is_ok());
    }

    #[test]
    fn admin_revocation_tamper_rejected() {
        let issuer = root(5, 6);
        let rev = AdminRevocation::build(
            &issuer,
            &CID,
            1,
            [0x01; 32],
            RevocationReason::NoLongerNeeded,
        )
        .unwrap();
        let mut decoded = AdminRevocation::from_wire(&rev.to_wire()).unwrap();
        decoded.body.revoked_delegation_hash = [0xFF; 32];
        assert!(decoded.verify(&issuer.public_key()).is_err());
    }
}
