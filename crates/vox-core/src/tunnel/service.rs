//! Tunnel service advertisements and discovery-gating (ADR-013 §"Authorization
//! gates discovery" and §"Channel-scoped resolution").
//!
//! A service advertisement names a tunnelable service hosted by a Bind holder:
//! `{ member_id, service_tag, endpoint }`, signed by the host's composite identity
//! (ADR-002) and framed under [`StructTag::ServiceAdvertisement`] (`0x000F`).
//!
//! ## Discovery is gated by *encryption*, not by a responder filter
//! The replicated log (ADR-008) delivers every entry to every member, so an
//! advertisement must never sit in cleartext there — that would make
//! discovery-gating illusory. Instead the host **seals** the signed advertisement
//! to each member holding the matching `dial:<service-tag>` capability, over that
//! member's authenticated pairwise channel (ADR-004) — [`seal_to_recipient`]. A
//! member can decrypt only the ads sealed to it ([`open_from_recipient`]); an
//! unauthorized member sees at most opaque ciphertext and cannot even learn the
//! service exists. There is no responder-side per-requester filter (the log has no
//! responder). On a Dial-set change the host re-seals to the new audience.
//!
//! An address grants no reachability and an advertisement grants no authorization:
//! receiving an ad means you were sealed a copy *because* you already hold the Dial
//! capability; the host still enforces that capability at stream setup
//! ([`crate::tunnel::authz`]).

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::capability::MAX_CAPABILITY_LEN;
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::pairwise::message::Message;
use crate::pairwise::session::Session;
use crate::suite::algo;
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// Maximum length of a service-endpoint descriptor (e.g. `"tcp/22"`). A short,
/// bounded label; the bound rejects a hostile oversized field before allocation.
pub const MAX_ENDPOINT_LEN: usize = 256;

/// A signed advertisement of a hosted tunnel service (ADR-013).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceAdvertisement {
    /// The hosting member's composite-identity fingerprint (the Bind holder).
    pub member_id: Digest32,
    /// The service tag (the `<tag>` of `bind:<tag>` / `dial:<tag>`), held without
    /// its capability prefix — e.g. `"ssh-hosts"`.
    pub service_tag: String,
    /// The endpoint descriptor the host will connect to locally on behalf of an
    /// authorized dialer (e.g. `"tcp/22"`). Opaque to the dialer; meaningful to the
    /// host's local resolution.
    pub endpoint: String,
    /// The host's composite signature over [`ServiceAdvertisement::signing_input`].
    pub signature: CompositeSignature,
}

impl ServiceAdvertisement {
    /// Canonical signed body (arity 4): `[member_id, service_tag, endpoint,
    /// [sign_algo]]`.
    fn canonical_body(member_id: &Digest32, service_tag: &str, endpoint: &str) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(member_id)
            .text(service_tag)
            .text(endpoint)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.finish()
    }

    /// The signing input: `vox/service-advertisement/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(
            StructTag::ServiceAdvertisement,
            &Self::canonical_body(&self.member_id, &self.service_tag, &self.endpoint),
        )
    }

    /// Build and sign an advertisement. `member_id` is taken from the signer, so the
    /// signed `member_id` always matches the key that signed it. Rejects an empty or
    /// over-long `service_tag`/`endpoint`.
    pub fn build(
        signer: &dyn RootSigner,
        service_tag: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Result<Self> {
        let service_tag = service_tag.into();
        let endpoint = endpoint.into();
        if service_tag.is_empty() || service_tag.len() > MAX_CAPABILITY_LEN {
            return Err(Error::MalformedGovernance(
                "service advertisement tag length",
            ));
        }
        if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_LEN {
            return Err(Error::MalformedGovernance(
                "service advertisement endpoint length",
            ));
        }
        let member_id = signer.fingerprint();
        let body = Self::canonical_body(&member_id, &service_tag, &endpoint);
        let signature = signer.sign(&signing_input(StructTag::ServiceAdvertisement, &body))?;
        Ok(Self {
            member_id,
            service_tag,
            endpoint,
            signature,
        })
    }

    /// Frame for the wire (tag `0x000F`, arity 5): the 3 payload fields, the algo
    /// array, then the composite signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .bytes(&self.member_id)
            .text(&self.service_tag)
            .text(&self.endpoint)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65))
            .bytes(&self.signature.to_bytes());
        frame(StructTag::ServiceAdvertisement, &e.finish())
    }

    /// Parse a framed advertisement (does **not** verify — call
    /// [`ServiceAdvertisement::verify`]).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::ServiceAdvertisement {
            return Err(Error::MalformedGovernance("service-ad wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 5 {
            return Err(Error::MalformedGovernance("service-ad wire arity"));
        }
        let member_id: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("service-ad member_id length"))?;
        let service_tag = d.text()?.to_owned();
        let endpoint = d.text()?.to_owned();
        if service_tag.is_empty() || service_tag.len() > MAX_CAPABILITY_LEN {
            return Err(Error::MalformedGovernance("service-ad tag length"));
        }
        if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_LEN {
            return Err(Error::MalformedGovernance("service-ad endpoint length"));
        }
        if d.array()? != 1 {
            return Err(Error::MalformedGovernance("service-ad algo arity"));
        }
        let sign_algo = u16::try_from(d.uint()?)
            .map_err(|_| Error::MalformedGovernance("service-ad sign_algo range"))?;
        if sign_algo != algo::COMPOSITE_ED25519_ML_DSA_65 {
            return Err(Error::UnexpectedAlgo {
                got: sign_algo,
                expected: algo::COMPOSITE_ED25519_ML_DSA_65,
            });
        }
        let sig_bytes: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("service-ad signature length"))?;
        d.finish()?;
        let signature = CompositeSignature::from_bytes(&sig_bytes)?;
        Ok(Self {
            member_id,
            service_tag,
            endpoint,
            signature,
        })
    }

    /// Verify the advertisement against the hosting member's composite public key:
    /// the key's fingerprint must equal `member_id` and the signature must verify.
    pub fn verify(&self, host_pubkey: &CompositePublicKey) -> Result<()> {
        if host_pubkey.fingerprint() != self.member_id {
            return Err(Error::MalformedGovernance(
                "service-ad member_id != signer fingerprint",
            ));
        }
        host_pubkey.verify(&self.signing_input(), &self.signature)
    }
}

/// Seal a signed advertisement to one authorized (Dial-holding) recipient over its
/// authenticated pairwise channel (ADR-004). The host calls this once per member in
/// the current Dial-grant set; the resulting [`Message`] carries no cleartext on
/// the log. (The host is responsible for sealing *only* to Dial-grant holders —
/// that is the discovery-gate; [`crate::tunnel::authz::can_dial`] decides the set.)
pub fn seal_to_recipient(ad: &ServiceAdvertisement, session: &mut Session) -> Result<Message> {
    session.encrypt(&ad.to_wire())
}

/// Open an advertisement sealed to us, verifying it under the advertiser's known
/// composite key (the pairwise peer's identity, ADR-004).
///
/// Decrypts the pairwise message, parses the advertisement, verifies its signature,
/// and confirms its `member_id` is the expected advertiser — so a peer cannot seal
/// an ad attributing a service to someone else.
pub fn open_from_recipient(
    session: &mut Session,
    message: &Message,
    advertiser_pubkey: &CompositePublicKey,
    now: u64,
) -> Result<ServiceAdvertisement> {
    let plaintext = session.decrypt(message, now)?;
    let ad = ServiceAdvertisement::from_wire(&plaintext)?;
    ad.verify(advertiser_pubkey)?;
    Ok(ad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    #[test]
    fn advertisement_round_trips_and_verifies() {
        let s = signer(1, 2);
        let ad = ServiceAdvertisement::build(&s, "ssh-hosts", "tcp/22").unwrap();
        let parsed = ServiceAdvertisement::from_wire(&ad.to_wire()).unwrap();
        assert_eq!(parsed, ad);
        assert!(parsed.verify(&s.public_key()).is_ok());
        assert_eq!(parsed.member_id, s.fingerprint());
    }

    #[test]
    fn advertisement_rejects_wrong_host_key_and_tamper() {
        let s = signer(1, 2);
        let other = signer(9, 9);
        let ad = ServiceAdvertisement::build(&s, "ssh-hosts", "tcp/22").unwrap();
        assert!(matches!(
            ad.verify(&other.public_key()),
            Err(Error::MalformedGovernance(_))
        ));
        let mut t = ad.clone();
        t.endpoint = "tcp/2222".to_owned();
        assert!(t.verify(&s.public_key()).is_err());
    }

    #[test]
    fn advertisement_rejects_empty_fields() {
        let s = signer(1, 2);
        assert!(ServiceAdvertisement::build(&s, "", "tcp/22").is_err());
        assert!(ServiceAdvertisement::build(&s, "ssh", "").is_err());
    }

    #[test]
    fn wrong_tag_is_rejected() {
        let s = signer(1, 2);
        let ad = ServiceAdvertisement::build(&s, "ssh-hosts", "tcp/22").unwrap();
        let wire = ad.to_wire();
        let parsed = parse_frame(&wire).unwrap();
        let bad = frame(StructTag::RendezvousRecord, parsed.body);
        assert!(matches!(
            ServiceAdvertisement::from_wire(&bad),
            Err(Error::MalformedGovernance(_))
        ));
    }
}
