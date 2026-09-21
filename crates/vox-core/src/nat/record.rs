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

// ===========================================================================
// Member prekey-bundle record (0x0012) — ADR-016 M14
// ===========================================================================

/// **How a key earned its place on a board** (ADR-016 M17.6).
///
/// Every member bundle record carries one. There are exactly two ways to be a member
/// and they are not interchangeable, so they are distinct variants rather than an
/// `Option` — "the creator" and "malformed" must never look alike on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// This key created the channel. The genesis names its creator and the genesis
    /// hash **is** the channelID, so any node holding the room can check this against
    /// data it already has, with nothing relayed and nobody to trust.
    Creator,
    /// A member verified this key's ADR-005 passphrase proof and signed that it did.
    ///
    /// Boxed: a witness carries a composite signature, which dwarfs the other variant,
    /// and this enum is held inside every member bundle record.
    Witnessed(Box<JoinWitness>),
}

impl Admission {
    /// The CBOR body: `[0]` for a creator, `[1, witness]` for a witnessed join.
    #[must_use]
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Admission::Creator => {
                e.array(1).uint(0);
            }
            Admission::Witnessed(w) => {
                e.array(2).uint(1).bytes(&w.body_bytes());
            }
        }
        e.finish()
    }

    /// Parse from a bare CBOR body.
    pub fn from_body(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let n = d.array()?;
        let kind = d.uint()?;
        let out = match (n, kind) {
            (1, 0) => Admission::Creator,
            (2, 1) => Admission::Witnessed(Box::new(JoinWitness::from_body(d.bytes()?)?)),
            _ => return Err(Error::MalformedRendezvous("admission wire shape")),
        };
        d.finish()?;
        Ok(out)
    }

    /// The witness, if this key was admitted by one.
    #[must_use]
    pub fn witness(&self) -> Option<&JoinWitness> {
        match self {
            Admission::Creator => None,
            Admission::Witnessed(w) => Some(w),
        }
    }
}

/// **A join witness** (ADR-016 M17.6, `0x0014`): the member that actually verified a
/// joiner's ADR-005 passphrase proof, signing that it did.
///
/// ## Why this exists
///
/// A member bundle record is **self-signed**: it says "here is my key" and proves only
/// that its publisher holds that key. Anyone can mint one for a key they hold. Before
/// this, a node admitted such a record as an author on the strength of *who relayed it*
/// — trust-on-first-use, which ADR-020 decision 3 forbids in as many words, and which
/// let one compromised member inject arbitrary identities into every other member's
/// author table.
///
/// Admission is not a privilege: an admitted key still reads nothing (that needs its
/// holder's sender key) and reaches no service (that needs the host's trust keyring).
/// What it grants is that entries signed by that key are **accepted and stored**, and
/// that the key occupies one of [`MAX_AUTHORS`](crate::node::channel::MAX_AUTHORS)
/// slots — so injection is a durable denial of new membership that outlives the
/// attacker, repairable only by a passphrase rotation.
///
/// A witness is therefore evidence, not an introduction. Only a node that ran the
/// CPace exchange can honestly produce one, because only it saw the proof.
///
/// ## What it does not do
///
/// **It does not make injection impossible.** A malicious member can sign a witness for
/// a key that never joined — nothing forces a witness to correspond to a real exchange.
/// What it does is make every admission **attributable** to the member that vouched for
/// it, and stop any *other* member's board from being a vector. The exhaustion attack is
/// bounded separately, by a per-source quota on admissions.
///
/// ## The chain is rooted in the genesis
///
/// The channel's creator needs no witness: the genesis names it, and the genesis hash is
/// the channelID, so the creator is self-evident to anyone holding the room. The creator
/// witnesses the first joiner, that joiner may witness the next, and so on. There is no
/// point at which a node must trust a key it has no path to.
///
/// Witnesses are **epoch-bound**: a passphrase rotation starts a new epoch, and ADR-007
/// already specifies that a rotation resets the room, so witnesses do not carry across.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinWitness {
    /// The channel the join was to (ADR-005 channelID).
    pub channel_id: Digest32,
    /// The membership epoch the join was under (ADR-007).
    pub epoch: u64,
    /// The joiner whose passphrase proof was verified.
    pub joiner_id: Digest32,
    /// The member that verified it and is signing this statement.
    pub witness_id: Digest32,
    /// Wall-clock time of the join (epoch-seconds).
    pub timestamp: u64,
    /// The witness's composite signature over [`JoinWitness::signing_input`].
    pub signature: CompositeSignature,
}

impl JoinWitness {
    /// The canonical signed body (arity 6): `[channel_id, epoch, joiner_id, witness_id,
    /// timestamp, [sign_algo]]`.
    fn canonical_body(
        channel_id: &Digest32,
        epoch: u64,
        joiner_id: &Digest32,
        witness_id: &Digest32,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6)
            .bytes(channel_id)
            .uint(epoch)
            .bytes(joiner_id)
            .bytes(witness_id)
            .uint(timestamp)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.finish()
    }

    /// The signing input: `vox/join-witness/v1 ‖ canonical_body`.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(
            StructTag::JoinWitness,
            &Self::canonical_body(
                &self.channel_id,
                self.epoch,
                &self.joiner_id,
                &self.witness_id,
                self.timestamp,
            ),
        )
    }

    /// Sign a witness for `joiner_id`. The caller MUST have verified the joiner's
    /// ADR-005 proof of possession first — this type carries the claim, it cannot
    /// check it.
    ///
    /// A witness for oneself is refused: the creator's self-evidence comes from the
    /// genesis (see the type docs), never from a key asserting its own admission.
    pub fn build(
        signer: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        joiner_id: &Digest32,
        timestamp: u64,
    ) -> Result<Self> {
        let witness_id = signer.fingerprint();
        if witness_id == *joiner_id {
            return Err(Error::MalformedRendezvous(
                "join-witness cannot witness itself",
            ));
        }
        let body = Self::canonical_body(channel_id, epoch, joiner_id, &witness_id, timestamp);
        let signature = signer.sign(&signing_input(StructTag::JoinWitness, &body))?;
        Ok(Self {
            channel_id: *channel_id,
            epoch,
            joiner_id: *joiner_id,
            witness_id,
            timestamp,
            signature,
        })
    }

    /// Encode as a framed wire record (arity 7).
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        frame(StructTag::JoinWitness, &self.body_bytes())
    }

    /// The CBOR body, without the frame — used both by [`JoinWitness::to_wire`] and
    /// when a witness is carried inside another record's signed body.
    #[must_use]
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(7)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.joiner_id)
            .bytes(&self.witness_id)
            .uint(self.timestamp)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65))
            .bytes(&self.signature.to_bytes());
        e.finish()
    }

    /// Parse a witness from a bare CBOR body (no frame).
    pub fn from_body(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 7 {
            return Err(Error::MalformedRendezvous("join-witness wire arity"));
        }
        let channel_id = take_digest(&mut d, "join-witness channel_id length")?;
        let epoch = d.uint()?;
        let joiner_id = take_digest(&mut d, "join-witness joiner_id length")?;
        let witness_id = take_digest(&mut d, "join-witness witness_id length")?;
        let timestamp = d.uint()?;
        take_and_check_algo(&mut d, "join-witness algo arity")?;
        let sig_bytes: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedRendezvous("join-witness signature length"))?;
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            joiner_id,
            witness_id,
            timestamp,
            signature: CompositeSignature::from_bytes(&sig_bytes)?,
        })
    }

    /// Parse a framed witness (does **not** verify — call [`JoinWitness::verify`]).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::JoinWitness {
            return Err(Error::MalformedRendezvous("join-witness wrong struct tag"));
        }
        Self::from_body(parsed.body)
    }

    /// Verify the witness's signature under `witness_pubkey`, and that it binds the
    /// channel, epoch and joiner the caller expects.
    ///
    /// The caller supplies `witness_pubkey` from its **own** admitted membership — that
    /// is the whole point: a witness is only evidence if the key that signed it is one
    /// this node already accepts, which roots the chain in the genesis creator.
    pub fn verify(
        &self,
        witness_pubkey: &CompositePublicKey,
        channel_id: &Digest32,
        epoch: u64,
        joiner_id: &Digest32,
    ) -> Result<()> {
        if witness_pubkey.fingerprint() != self.witness_id {
            return Err(Error::MalformedRendezvous(
                "join-witness witness_id != signer fingerprint",
            ));
        }
        if self.channel_id != *channel_id {
            return Err(Error::MalformedRendezvous(
                "join-witness binds another channel",
            ));
        }
        if self.epoch != epoch {
            return Err(Error::MalformedRendezvous(
                "join-witness binds another epoch",
            ));
        }
        if self.joiner_id != *joiner_id {
            return Err(Error::MalformedRendezvous(
                "join-witness binds another joiner",
            ));
        }
        if self.witness_id == self.joiner_id {
            return Err(Error::MalformedRendezvous(
                "join-witness cannot witness itself",
            ));
        }
        witness_pubkey.verify(&self.signing_input(), &self.signature)
    }
}

/// A channel member's root-signed **prekey bundle** on the rendezvous board
/// (ADR-016 §"The rendezvous service and the member bundle record").
///
/// After a join, every consenting member seals its SKDM to the newcomer using
/// the newcomer's pre-join bundle; the newcomer seals *its* SKDM to each member
/// using that member's bundle record — this one. Like the member address record
/// it is member-only (the store resolves the author's key from the authenticated
/// membership), `(channelID, epoch)`-scoped, `seq`/`timestamp` anti-replayed and
/// TTL'd — but its TTL is the ADR-002 signed-prekey cadence (7 days) rather than
/// the address record's 2 hours, and it is refreshed on rotation and when the
/// one-time pool crosses its low-water mark. It is a separate kind because the
/// address record is tiny and refreshed on a minutes scale while a bundle is
/// ~10–20 KB and changes weekly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberBundleRecord {
    /// The publishing member's composite-identity fingerprint.
    pub author_id: Digest32,
    /// The channel (ADR-005 channelID).
    pub channel_id: Digest32,
    /// The membership epoch (ADR-007).
    pub epoch: u64,
    /// The member's current prekey bundle; its `root_pub` MUST be the member's
    /// own composite root (checked in [`MemberBundleRecord::verify`]).
    pub prekey_bundle: PrekeyBundlePublic,
    /// Monotonic per-`(author, channel, epoch)` sequence (anti-replay).
    pub seq: u64,
    /// Wall-clock publication time (epoch-seconds).
    pub timestamp: u64,
    /// Requested time-to-live in seconds; the store caps it at
    /// [`crate::nat::store::BUNDLE_MAX_TTL_SECS`].
    pub ttl_secs: u64,
    /// How this key earned its place on the board: it created the channel, or a member
    /// verified its ADR-005 passphrase proof and signed that it did (ADR-016 M17.6).
    ///
    /// **Required**, and inside the signed body. A record without one is malformed —
    /// there is no legitimate way to be on a board without having joined or created.
    pub admission: Admission,
    /// The author's composite signature over [`MemberBundleRecord::signing_input`].
    pub signature: CompositeSignature,
}

impl MemberBundleRecord {
    /// The canonical signed body (arity 9): `[author_id, channelID, epoch,
    /// prekey_bundle, seq, timestamp, ttl_secs, admission, [sign_algo]]`.
    ///
    /// The admission is **inside** the signed body so the publisher cannot be given one
    /// witness and publish under another, and so a witness cannot be lifted off one
    /// record and stapled to a different key's.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per signed field; grouping them would hide what is signed"
    )]
    fn canonical_body(
        author_id: &Digest32,
        channel_id: &Digest32,
        epoch: u64,
        prekey_bundle_bytes: &[u8],
        seq: u64,
        timestamp: u64,
        ttl_secs: u64,
        admission_bytes: &[u8],
    ) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(9)
            .bytes(author_id)
            .bytes(channel_id)
            .uint(epoch)
            .bytes(prekey_bundle_bytes)
            .uint(seq)
            .uint(timestamp)
            .uint(ttl_secs)
            .bytes(admission_bytes)
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.finish()
    }

    /// The signing input: `vox/member-bundle-record/v1 ‖ canonical_body`.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(
            StructTag::MemberBundleRecord,
            &Self::canonical_body(
                &self.author_id,
                &self.channel_id,
                self.epoch,
                &self.prekey_bundle.encode_canonical(),
                self.seq,
                self.timestamp,
                self.ttl_secs,
                &self.admission.body_bytes(),
            ),
        )
    }

    /// Build and sign a member bundle record. `author_id` is the signer's
    /// fingerprint, and the bundle's root MUST be the signer's key (else
    /// [`Error::MalformedRendezvous`] — a member cannot publish someone else's
    /// bundle under its own name).
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per signed field; grouping them would hide what is signed"
    )]
    pub fn build(
        signer: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        prekey_bundle: PrekeyBundlePublic,
        seq: u64,
        timestamp: u64,
        ttl_secs: u64,
        admission: Admission,
    ) -> Result<Self> {
        if prekey_bundle.root_pub != signer.public_key().to_bytes() {
            return Err(Error::MalformedRendezvous(
                "member-bundle prekey bundle root != signer",
            ));
        }
        let author_id = signer.fingerprint();
        // A witness must be *this* key's, for *this* room and epoch. Checked at build
        // as well as at verify, so a caller cannot publish a record it knows is junk.
        // `Creator` carries nothing to check here; the genesis is what checks it, at
        // admission, where the verifier holds it.
        if let Some(w) = admission.witness() {
            if w.joiner_id != author_id || w.channel_id != *channel_id || w.epoch != epoch {
                return Err(Error::MalformedRendezvous(
                    "member-bundle witness does not bind this author, channel and epoch",
                ));
            }
        }
        let bundle_bytes = prekey_bundle.encode_canonical();
        if bundle_bytes.len() > MAX_PREKEY_BUNDLE_BYTES {
            return Err(Error::SizeLimitExceeded("member-bundle prekey bundle"));
        }
        let body = Self::canonical_body(
            &author_id,
            channel_id,
            epoch,
            &bundle_bytes,
            seq,
            timestamp,
            ttl_secs,
            &admission.body_bytes(),
        );
        let signature = signer.sign(&signing_input(StructTag::MemberBundleRecord, &body))?;
        Ok(Self {
            author_id,
            channel_id: *channel_id,
            epoch,
            prekey_bundle,
            seq,
            timestamp,
            ttl_secs,
            admission,
            signature,
        })
    }

    /// Frame for the wire (tag `0x0012`): the 8 signed fields, the algo array,
    /// then the composite signature (arity 10).
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(10)
            .bytes(&self.author_id)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.prekey_bundle.encode_canonical())
            .uint(self.seq)
            .uint(self.timestamp)
            .uint(self.ttl_secs)
            .bytes(&self.admission.body_bytes())
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65))
            .bytes(&self.signature.to_bytes());
        frame(StructTag::MemberBundleRecord, &e.finish())
    }

    /// Parse a framed member bundle record (does **not** verify — call
    /// [`MemberBundleRecord::verify`]).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::MemberBundleRecord {
            return Err(Error::MalformedRendezvous("member-bundle wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 10 {
            return Err(Error::MalformedRendezvous("member-bundle wire arity"));
        }
        let author_id = take_digest(&mut d, "member-bundle author_id length")?;
        let channel_id = take_digest(&mut d, "member-bundle channel_id length")?;
        let epoch = d.uint()?;
        let bundle_bytes = d.bytes()?;
        if bundle_bytes.len() > MAX_PREKEY_BUNDLE_BYTES {
            return Err(Error::SizeLimitExceeded("member-bundle prekey bundle"));
        }
        let prekey_bundle = PrekeyBundlePublic::decode_canonical(bundle_bytes)?;
        let seq = d.uint()?;
        let timestamp = d.uint()?;
        let ttl_secs = d.uint()?;
        let admission = Admission::from_body(d.bytes()?)?;
        take_and_check_algo(&mut d, "member-bundle algo arity")?;
        let sig_bytes: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedRendezvous("member-bundle signature length"))?;
        d.finish()?;
        let signature = CompositeSignature::from_bytes(&sig_bytes)?;
        Ok(Self {
            author_id,
            channel_id,
            epoch,
            prekey_bundle,
            seq,
            timestamp,
            ttl_secs,
            admission,
            signature,
        })
    }

    /// Verify against the member's composite public key (supplied by the caller
    /// from the authenticated membership, as for [`RendezvousRecord::verify`]):
    /// fingerprint == `author_id`, the record signature verifies, the bundle's
    /// root **is** this member, and every signature inside the bundle verifies.
    pub fn verify(&self, author_pubkey: &CompositePublicKey) -> Result<()> {
        if author_pubkey.fingerprint() != self.author_id {
            return Err(Error::MalformedRendezvous(
                "member-bundle author_id != signer fingerprint",
            ));
        }
        author_pubkey.verify(&self.signing_input(), &self.signature)?;
        if self.prekey_bundle.root_pub != author_pubkey.to_bytes() {
            return Err(Error::MalformedRendezvous(
                "member-bundle prekey bundle root != author",
            ));
        }
        self.prekey_bundle.verify()
    }
}
