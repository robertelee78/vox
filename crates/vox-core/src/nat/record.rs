//! Signed rendezvous records (ADR-012 §"Rendezvous").
//!
//! Two clearly-typed, tag-disjoint record classes published at the rendezvous key
//! ([`mod@crate::join::rendezvous`]):
//!
//! 1. [`RendezvousRecord`] — a **channel member** advertises its current endpoints,
//!    signed by its composite identity key (ADR-002). The body carries only the
//!    member's `author_id` *fingerprint*; verification therefore *requires* the
//!    member's composite public key, supplied by the caller from the authenticated
//!    membership set (ADR-007) — so a record can only be verified for an actual
//!    member, structurally enforcing ADR-012's "accept records only from channel
//!    members".
//! 2. [`PreJoinRecord`] — a peer that has **not yet joined** advertises a prekey
//!    bundle + endpoints, self-signed by its *asserted* identity (the full
//!    composite public key is embedded, since no reader has a prior key for a
//!    non-member). It conveys **no log authority** (ADR-008 accepts log entries
//!    only from joined identities); readers treat it solely as join-bootstrap
//!    material — a candidate prekey bundle + endpoints to attempt CPace against
//!    (ADR-005).
//!
//! Type-disjointness is by ADR-008 struct tag: member records frame under
//! [`StructTag::RendezvousRecord`] (`0x0007`), pre-join under
//! [`StructTag::PreJoinRecord`] (`0x0008`). The tag *is* the `kind` discriminant
//! (ADR-012 `kind: "pre-join"`): a verifier that mis-tags a record fails on the
//! tag and never cross-interprets the bytes.
//!
//! These types are pure data + signature verification. The freshness / anti-replay
//! / rate / membership / TTL **policy** lives in [`crate::nat::store`], which is the
//! reader-side gate ADR-012 specifies (a poisoner cannot inject or replay
//! endpoints, a stale record cannot be replayed after rotation).

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_PUB_LEN, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::identity::keyagreement::PrekeyBundlePublic;
use crate::nat::multiaddr::EndpointList;
use crate::suite::algo;
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// Hard ceiling on a pre-join record's embedded prekey-bundle byte length, checked
/// before the bundle is decoded (anti-abuse: bound allocation before trusting an
/// attacker-declared length). A full bundle is ~root key + three composite
/// signatures + key material (~15 KiB); this leaves generous headroom while still
/// rejecting an absurd declared length.
pub const MAX_PREKEY_BUNDLE_BYTES: usize = 32 * 1024;

/// Decode the trailing `[sign_algo]` 1-element array and require the composite
/// signature algorithm (mirrors the ADR-007 governance structs).
fn take_and_check_algo(d: &mut Decoder<'_>, ctx: &'static str) -> Result<()> {
    if d.array()? != 1 {
        return Err(Error::MalformedRendezvous(ctx));
    }
    let sign_algo = u16::try_from(d.uint()?)
        .map_err(|_| Error::MalformedRendezvous("rendezvous sign_algo range"))?;
    if sign_algo != algo::COMPOSITE_ED25519_ML_DSA_65 {
        return Err(Error::UnexpectedAlgo {
            got: sign_algo,
            expected: algo::COMPOSITE_ED25519_ML_DSA_65,
        });
    }
    Ok(())
}

fn take_digest(d: &mut Decoder<'_>, ctx: &'static str) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedRendezvous(ctx))
}

// ===========================================================================
// Member rendezvous record (0x0007)
// ===========================================================================

/// A channel member's signed endpoint advertisement (ADR-012).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RendezvousRecord {
    /// The publishing member's composite-identity fingerprint (ADR-002).
    pub author_id: Digest32,
    /// The channel this record belongs to (ADR-005 channelID).
    pub channel_id: Digest32,
    /// The membership epoch (ADR-007). The record is only valid at the
    /// `(channelID, epoch)` rendezvous address; a rotated channel meets elsewhere.
    pub epoch: u64,
    /// The advertised endpoints, in reachability-ladder preference order.
    pub endpoints: EndpointList,
    /// A per-`(author, channel, epoch)` monotonic sequence number — the primary
    /// anti-replay handle (readers reject a non-increasing `seq`).
    pub seq: u64,
    /// Wall-clock publication time (epoch-seconds). Bounds TTL and rate, and
    /// breaks ties when `seq` is equal.
    pub timestamp: u64,
    /// Requested time-to-live in seconds; the store caps it at
    /// [`crate::nat::store::MAX_TTL_SECS`]. After `timestamp + ttl_secs` the record
    /// is expired and pruned.
    pub ttl_secs: u64,
    /// The author's composite signature over [`RendezvousRecord::signing_input`].
    pub signature: CompositeSignature,
}

impl RendezvousRecord {
    /// The canonical signed body (arity 8): `[author_id, channelID, epoch,
    /// endpoints, seq, timestamp, ttl_secs, [sign_algo]]`.
    fn canonical_body(
        author_id: &Digest32,
        channel_id: &Digest32,
        epoch: u64,
        endpoints: &EndpointList,
        seq: u64,
        timestamp: u64,
        ttl_secs: u64,
    ) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(8).bytes(author_id).bytes(channel_id).uint(epoch);
        endpoints.encode_into(&mut e);
        e.uint(seq)
            .uint(timestamp)
            .uint(ttl_secs)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.finish()
    }

    /// The signing input: `vox/rendezvous-record/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(
            StructTag::RendezvousRecord,
            &Self::canonical_body(
                &self.author_id,
                &self.channel_id,
                self.epoch,
                &self.endpoints,
                self.seq,
                self.timestamp,
                self.ttl_secs,
            ),
        )
    }

    /// Build and sign a member rendezvous record. `author_id` is taken from the
    /// signer's fingerprint, so the signed `author_id` always matches the key that
    /// signed it.
    pub fn build(
        signer: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        endpoints: EndpointList,
        seq: u64,
        timestamp: u64,
        ttl_secs: u64,
    ) -> Result<Self> {
        let author_id = signer.fingerprint();
        let body = Self::canonical_body(
            &author_id, channel_id, epoch, &endpoints, seq, timestamp, ttl_secs,
        );
        let signature = signer.sign(&signing_input(StructTag::RendezvousRecord, &body))?;
        Ok(Self {
            author_id,
            channel_id: *channel_id,
            epoch,
            endpoints,
            seq,
            timestamp,
            ttl_secs,
            signature,
        })
    }

    /// Frame for the wire (tag `0x0007`): the 7 signed fields then the algo array
    /// then the composite signature (arity 9). The signed 8-element body is
    /// reconstructed on parse so the signing input is recovered exactly.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(9)
            .bytes(&self.author_id)
            .bytes(&self.channel_id)
            .uint(self.epoch);
        self.endpoints.encode_into(&mut e);
        e.uint(self.seq)
            .uint(self.timestamp)
            .uint(self.ttl_secs)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65))
            .bytes(&self.signature.to_bytes());
        frame(StructTag::RendezvousRecord, &e.finish())
    }

    /// Parse a framed member record (does **not** verify — call
    /// [`RendezvousRecord::verify`]).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::RendezvousRecord {
            return Err(Error::MalformedRendezvous("rendezvous wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 9 {
            return Err(Error::MalformedRendezvous("rendezvous wire arity"));
        }
        let author_id = take_digest(&mut d, "rendezvous author_id length")?;
        let channel_id = take_digest(&mut d, "rendezvous channel_id length")?;
        let epoch = d.uint()?;
        let endpoints = EndpointList::decode_from(&mut d)?;
        let seq = d.uint()?;
        let timestamp = d.uint()?;
        let ttl_secs = d.uint()?;
        take_and_check_algo(&mut d, "rendezvous algo arity")?;
        let sig_bytes: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedRendezvous("rendezvous signature length"))?;
        d.finish()?;
        let signature = CompositeSignature::from_bytes(&sig_bytes)?;
        Ok(Self {
            author_id,
            channel_id,
            epoch,
            endpoints,
            seq,
            timestamp,
            ttl_secs,
            signature,
        })
    }

    /// Verify the record against the author's composite public key.
    ///
    /// `author_pubkey` MUST be the public key of the member named by `author_id`
    /// — supplied by the caller from the authenticated membership set. The check
    /// passes only if its fingerprint equals `author_id` **and** the composite
    /// signature verifies over the signing input. Requiring a caller-supplied
    /// member key means a non-member's record cannot be verified at all (ADR-012
    /// "accept records only from channel members").
    pub fn verify(&self, author_pubkey: &CompositePublicKey) -> Result<()> {
        if author_pubkey.fingerprint() != self.author_id {
            return Err(Error::MalformedRendezvous(
                "rendezvous author_id != signer fingerprint",
            ));
        }
        author_pubkey.verify(&self.signing_input(), &self.signature)
    }
}

// ===========================================================================
// Pre-join rendezvous record (0x0008)
// ===========================================================================

/// A not-yet-joined peer's self-signed join-bootstrap advertisement (ADR-012).
///
/// Carries the asserted composite identity, a prekey bundle, and endpoints. It
/// conveys **no** channel/log authority — readers use it only as candidate CPace
/// material (ADR-004/ADR-005).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreJoinRecord {
    /// The asserted composite identity public key (full key, since the reader has
    /// no prior key for a non-member). `asserted_id == asserted_pubkey.fingerprint()`.
    pub asserted_pubkey: CompositePublicKey,
    /// The channel the peer wants to join (ADR-005 channelID).
    pub channel_id: Digest32,
    /// The candidate prekey bundle to attempt PQXDH/CPace against (ADR-004).
    pub prekey_bundle: PrekeyBundlePublic,
    /// The peer's advertised endpoints.
    pub endpoints: EndpointList,
    /// Monotonic per-`(asserted_id, channel)` sequence number (anti-replay).
    pub seq: u64,
    /// Wall-clock publication time (epoch-seconds).
    pub timestamp: u64,
    /// The self-signature over [`PreJoinRecord::signing_input`].
    pub signature: CompositeSignature,
}

impl PreJoinRecord {
    /// The asserted identity fingerprint (`asserted_id`, ADR-012).
    #[must_use]
    pub fn asserted_id(&self) -> Digest32 {
        self.asserted_pubkey.fingerprint()
    }

    /// The canonical signed body (arity 7): `[asserted_pubkey, channelID,
    /// prekey_bundle, endpoints, seq, timestamp, [sign_algo]]`.
    fn canonical_body(
        asserted_pubkey: &CompositePublicKey,
        channel_id: &Digest32,
        prekey_bundle_bytes: &[u8],
        endpoints: &EndpointList,
        seq: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(7)
            .bytes(&asserted_pubkey.to_bytes())
            .bytes(channel_id)
            .bytes(prekey_bundle_bytes);
        endpoints.encode_into(&mut e);
        e.uint(seq)
            .uint(timestamp)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.finish()
    }

    /// The signing input: `vox/pre-join-record/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(
            StructTag::PreJoinRecord,
            &Self::canonical_body(
                &self.asserted_pubkey,
                &self.channel_id,
                &self.prekey_bundle.encode_canonical(),
                &self.endpoints,
                self.seq,
                self.timestamp,
            ),
        )
    }

    /// Build and self-sign a pre-join record. The asserted identity is the signer's
    /// own composite key.
    pub fn build(
        signer: &dyn RootSigner,
        channel_id: &Digest32,
        prekey_bundle: PrekeyBundlePublic,
        endpoints: EndpointList,
        seq: u64,
        timestamp: u64,
    ) -> Result<Self> {
        let asserted_pubkey = signer.public_key();
        let bundle_bytes = prekey_bundle.encode_canonical();
        let body = Self::canonical_body(
            &asserted_pubkey,
            channel_id,
            &bundle_bytes,
            &endpoints,
            seq,
            timestamp,
        );
        let signature = signer.sign(&signing_input(StructTag::PreJoinRecord, &body))?;
        Ok(Self {
            asserted_pubkey,
            channel_id: *channel_id,
            prekey_bundle,
            endpoints,
            seq,
            timestamp,
            signature,
        })
    }

    /// Frame for the wire (tag `0x0008`): arity 8 — the 6 signed payload fields,
    /// the algo array, then the self-signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(8)
            .bytes(&self.asserted_pubkey.to_bytes())
            .bytes(&self.channel_id)
            .bytes(&self.prekey_bundle.encode_canonical());
        self.endpoints.encode_into(&mut e);
        e.uint(self.seq)
            .uint(self.timestamp)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65))
            .bytes(&self.signature.to_bytes());
        frame(StructTag::PreJoinRecord, &e.finish())
    }

    /// Parse a framed pre-join record (does **not** verify — call
    /// [`PreJoinRecord::verify`]).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::PreJoinRecord {
            return Err(Error::MalformedRendezvous("pre-join wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 8 {
            return Err(Error::MalformedRendezvous("pre-join wire arity"));
        }
        let pub_bytes: [u8; COMPOSITE_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedRendezvous("pre-join asserted_pubkey length"))?;
        let channel_id = take_digest(&mut d, "pre-join channel_id length")?;
        let bundle_bytes = d.bytes()?;
        if bundle_bytes.len() > MAX_PREKEY_BUNDLE_BYTES {
            return Err(Error::SizeLimitExceeded("pre-join prekey bundle"));
        }
        let prekey_bundle = PrekeyBundlePublic::decode_canonical(bundle_bytes)?;
        let endpoints = EndpointList::decode_from(&mut d)?;
        let seq = d.uint()?;
        let timestamp = d.uint()?;
        take_and_check_algo(&mut d, "pre-join algo arity")?;
        let sig_bytes: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedRendezvous("pre-join signature length"))?;
        d.finish()?;
        let asserted_pubkey = CompositePublicKey::from_bytes(&pub_bytes)?;
        let signature = CompositeSignature::from_bytes(&sig_bytes)?;
        Ok(Self {
            asserted_pubkey,
            channel_id,
            prekey_bundle,
            endpoints,
            seq,
            timestamp,
            signature,
        })
    }

    /// Verify the record is internally consistent and self-signed.
    ///
    /// Checks, all of which must pass:
    /// 1. the self-signature verifies over the signing input under the embedded
    ///    asserted key;
    /// 2. the embedded prekey bundle's root key **is** the asserted identity
    ///    (`prekey_bundle.root_pub == asserted_pubkey`) — so a peer cannot
    ///    self-sign as `A` while advertising someone else's prekey bundle, which
    ///    would point a joiner's PQXDH at the wrong identity's keys;
    /// 3. every signature inside the prekey bundle verifies against that root.
    ///
    /// This proves the presenter controls the asserted identity *and* owns the
    /// advertised prekeys — it does **not** grant any channel authority (ADR-012:
    /// no log authority).
    pub fn verify(&self) -> Result<()> {
        self.asserted_pubkey
            .verify(&self.signing_input(), &self.signature)?;
        if self.prekey_bundle.root_pub != self.asserted_pubkey.to_bytes() {
            return Err(Error::MalformedRendezvous(
                "pre-join prekey bundle root != asserted identity",
            ));
        }
        self.prekey_bundle.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::identity::keyagreement::{SignedIdentityDhKey, SignedPrekey};
    use crate::nat::multiaddr::Multiaddr;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn endpoints() -> EndpointList {
        EndpointList::new(vec![Multiaddr::Ip4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 9),
            4433,
        ))])
        .unwrap()
    }

    fn bundle(s: &SoftwareRootSigner) -> PrekeyBundlePublic {
        let idk = SignedIdentityDhKey::generate(s, 1_700_000_000).unwrap();
        let spk = SignedPrekey::generate(s, 1, 1_700_000_000).unwrap();
        PrekeyBundlePublic {
            root_pub: s.public_key().to_bytes(),
            identity_dh_key: idk.public().clone(),
            identity_dh_key_sig: idk.signature().to_bytes(),
            signed_prekey: spk.public().clone(),
            signed_prekey_sig: spk.signature().to_bytes(),
            one_time_prekey: None,
            one_time_prekey_sig: None,
        }
    }

    #[test]
    fn member_record_round_trips_and_verifies() {
        let s = signer(1, 2);
        let cid = [7u8; 32];
        let rec =
            RendezvousRecord::build(&s, &cid, 3, endpoints(), 5, 1_700_000_100, 7200).unwrap();
        let wire = rec.to_wire();
        let parsed = RendezvousRecord::from_wire(&wire).unwrap();
        assert_eq!(parsed, rec);
        assert!(parsed.verify(&s.public_key()).is_ok());
        assert_eq!(parsed.author_id, s.fingerprint());
    }

    #[test]
    fn member_record_rejects_wrong_author_key() {
        let s = signer(1, 2);
        let other = signer(9, 9);
        let rec = RendezvousRecord::build(&s, &[7u8; 32], 0, endpoints(), 1, 100, 60).unwrap();
        // A different member's key cannot verify it (fingerprint mismatch).
        assert!(matches!(
            rec.verify(&other.public_key()),
            Err(Error::MalformedRendezvous(_))
        ));
    }

    #[test]
    fn member_record_rejects_tampered_endpoints() {
        let s = signer(1, 2);
        let mut rec = RendezvousRecord::build(&s, &[7u8; 32], 0, endpoints(), 1, 100, 60).unwrap();
        // Swap in different endpoints without re-signing → signature must fail.
        rec.endpoints = EndpointList::new(vec![Multiaddr::Relay([1u8; 32])]).unwrap();
        assert!(rec.verify(&s.public_key()).is_err());
    }

    #[test]
    fn member_record_wrong_tag_is_rejected() {
        let s = signer(1, 2);
        let rec = RendezvousRecord::build(&s, &[7u8; 32], 0, endpoints(), 1, 100, 60).unwrap();
        // Re-frame the body under the pre-join tag → from_wire must reject on tag.
        let wire = rec.to_wire();
        let parsed = parse_frame(&wire).unwrap();
        let bad = frame(StructTag::PreJoinRecord, parsed.body);
        assert!(matches!(
            RendezvousRecord::from_wire(&bad),
            Err(Error::MalformedRendezvous(_))
        ));
    }

    #[test]
    fn pre_join_record_round_trips_and_verifies() {
        let s = signer(3, 4);
        let cid = [8u8; 32];
        let rec =
            PreJoinRecord::build(&s, &cid, bundle(&s), endpoints(), 2, 1_700_000_200).unwrap();
        let wire = rec.to_wire();
        let parsed = PreJoinRecord::from_wire(&wire).unwrap();
        assert_eq!(parsed, rec);
        assert!(parsed.verify().is_ok());
        assert_eq!(parsed.asserted_id(), s.fingerprint());
    }

    #[test]
    fn pre_join_record_rejects_tampered_self_signature() {
        let s = signer(3, 4);
        let mut rec =
            PreJoinRecord::build(&s, &[8u8; 32], bundle(&s), endpoints(), 1, 100).unwrap();
        rec.seq = 999; // changes signing input; signature no longer matches
        assert!(rec.verify().is_err());
    }

    #[test]
    fn pre_join_record_rejects_foreign_bundle() {
        // A record self-signed by A but advertising B's (internally-valid) prekey
        // bundle MUST be rejected: the bundle root must be the asserted identity, so
        // a joiner's PQXDH can never be pointed at a different identity's prekeys.
        let s = signer(3, 4);
        let other = signer(5, 6);
        let rec =
            PreJoinRecord::build(&s, &[8u8; 32], bundle(&other), endpoints(), 1, 100).unwrap();
        assert!(
            matches!(rec.verify(), Err(Error::MalformedRendezvous(_))),
            "foreign (other-rooted) bundle must be rejected"
        );

        // A genuinely self-consistent record (bundle rooted at the asserted id)
        // verifies.
        let ok = PreJoinRecord::build(&s, &[8u8; 32], bundle(&s), endpoints(), 1, 100).unwrap();
        assert!(ok.verify().is_ok());

        // A bundle whose root field is tampered to not match its component sigs is
        // also rejected (here the root no longer equals the asserted id either).
        let mut bad = bundle(&s);
        bad.root_pub = other.public_key().to_bytes();
        let rec2 = PreJoinRecord::build(&s, &[8u8; 32], bad, endpoints(), 1, 100).unwrap();
        assert!(rec2.verify().is_err());
    }
}
