//! The channel genesis record — the trust anchor (ADR-007 §"Trust anchor",
//! tag `0x000D`, domain `vox/genesis/v1`).
//!
//! A channel *begins* with a genesis record: its own canonical struct (not a
//! generic governance cert), self-signed by the creator's composite identity key
//! (ADR-002). The **`channelID` is `SHA-256(canonical genesis record)`** — so it
//! is 256-bit, high-entropy (the 128-bit nonce guarantees it), self-certifying,
//! and bound to exactly one genesis. The genesis hash is simultaneously the
//! channelID, the rendezvous seed (ADR-005/M3), and the root of every certificate
//! chain: every authority claim verifies back to it, and the creator is the root
//! admin (ADR-007).
//!
//! ## Pinned field list (ADR-007, exact order)
//! `{ nonce(16 B random), created(uint epoch-seconds),
//!    policy{ history_mode(enum), deniability_mode(enum), ttl(uint, 0=never) },
//!    creator_pubkey(composite, ADR-002), algo_ids }`
//!
//! encoded as the canonical-CBOR array
//! `[nonce, created, [history_mode, deniability_mode, ttl], creator_pubkey,
//!   [sign_algo]]` (ADR-008 COSE-style arrays). `algo_ids` is a 1-element array
//! holding the composite signature class (`0x0304`) — the only algorithm a
//! genesis record commits to (there is no AEAD or KEM at the genesis layer).
//!
//! ## Self-signature and the cold-join check
//! The creator signs `vox/genesis/v1 ‖ canonical_body`
//! ([`crate::wire::signing_input`]) with its composite root. A cold-joining node
//! fetches genesis from the rendezvous (ADR-012) and accepts it **only if**
//! `SHA-256(canonical bytes) == the channelID it joined with`
//! ([`Genesis::matches_channel_id`]) **and** the creator self-signature verifies
//! ([`Genesis::verify`]). M3's [`crate::join::channelid::channel_id`] hashes the
//! *same* canonical bytes — [`Genesis::channel_id`] is the authoritative producer
//! of those bytes, so the two milestones derive the identical channelID.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32, COMPOSITE_PUB_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::identity::rng::fill_random;
use crate::suite::{algo, validate_algo};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// Length of the genesis nonce in bytes (128-bit, ADR-007).
pub const GENESIS_NONCE_LEN: usize = 16;

/// The channel **history mode** (ADR-007 policy axis; mutable by a policy-update).
///
/// Governs whether a consenting member releases its *origin* sender key (so the
/// recipient can read retained history) or only the *current* iteration
/// (forward-only). The actual key-release mechanism is M4
/// ([`crate::group::history`]); this enum is the channel-policy value that
/// decides which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HistoryMode {
    /// New members read only messages from their consent point forward (the
    /// consenter releases the *current* chain key).
    ForwardOnly,
    /// New members may read the consenter's retained history (the consenter
    /// releases the *origin* chain key).
    FullHistory,
}

impl HistoryMode {
    /// The wire discriminant (a canonical-CBOR uint).
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        match self {
            HistoryMode::ForwardOnly => 0,
            HistoryMode::FullHistory => 1,
        }
    }

    /// Resolve from the wire discriminant, rejecting out-of-domain values.
    pub fn from_u64(v: u64) -> Result<Self> {
        match v {
            0 => Ok(HistoryMode::ForwardOnly),
            1 => Ok(HistoryMode::FullHistory),
            _ => Err(Error::MalformedGovernance("history_mode out of domain")),
        }
    }
}

/// The channel **deniability mode** (ADR-007 policy axis; **genesis-immutable**).
///
/// Set once in the genesis record. A policy-update MUST NOT change it (the
/// evaluator and [`crate::governance::policy`] reject any attempt): members join
/// under a fixed authorship-accountability contract, and flipping
/// attributable↔deniable mid-life would change the threat model under existing
/// members and the fork-handling split (ADR-007/ADR-008).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeniabilityMode {
    /// Message content is composite-signed and attributable (ADR-008). Governance
    /// is always attributable regardless of this axis.
    Attributable,
    /// Message content carries the ADR-009 deniable (forgeable) authenticator
    /// (the crypto is M7); governance stays attributable.
    Deniable,
}

impl DeniabilityMode {
    /// The wire discriminant (a canonical-CBOR uint).
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        match self {
            DeniabilityMode::Attributable => 0,
            DeniabilityMode::Deniable => 1,
        }
    }

    /// Resolve from the wire discriminant, rejecting out-of-domain values.
    pub fn from_u64(v: u64) -> Result<Self> {
        match v {
            0 => Ok(DeniabilityMode::Attributable),
            1 => Ok(DeniabilityMode::Deniable),
            _ => Err(Error::MalformedGovernance("deniability_mode out of domain")),
        }
    }
}

/// The channel policy carried in the genesis record (ADR-007).
///
/// `history_mode` and `ttl` are *mutable* by a later policy-update
/// ([`crate::governance::policy`]); `deniability_mode` is **genesis-immutable**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelPolicy {
    /// History retention/release mode (mutable).
    pub history_mode: HistoryMode,
    /// Attributable vs deniable content authorship (genesis-immutable).
    pub deniability_mode: DeniabilityMode,
    /// Payload time-to-live in seconds; `0` means never expire (mutable). The
    /// actual erasure is M8 (ADR-010); this is the policy value.
    pub ttl: u64,
}

/// The unsigned genesis body — every field except the self-signature.
///
/// Held separately so [`GenesisBody::signing_input`] is the exact bytes the
/// creator signs and a verifier checks, and so [`GenesisBody::channel_id`] hashes
/// the exact canonical body that defines the channelID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisBody {
    /// 128-bit random nonce — the entropy that makes each channelID unique.
    pub nonce: [u8; GENESIS_NONCE_LEN],
    /// Channel creation time (epoch seconds).
    pub created: u64,
    /// The channel policy (history / deniability / ttl).
    pub policy: ChannelPolicy,
    /// The creator's composite root public key — the root admin (ADR-007).
    pub creator_pubkey: CompositePublicKey,
}

impl GenesisBody {
    /// Canonical-CBOR body in the ADR-007 field order:
    /// `[nonce, created, [history_mode, deniability_mode, ttl], creator_pubkey,
    ///   [sign_algo]]`. `sign_algo` is the composite signature class (the only
    /// algorithm a genesis record commits to).
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .bytes(&self.nonce)
            .uint(self.created)
            .array(3)
            .uint(self.policy.history_mode.as_u64())
            .uint(self.policy.deniability_mode.as_u64())
            .uint(self.policy.ttl);
        e.bytes(&self.creator_pubkey.to_bytes())
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.finish()
    }

    /// The signing input: `vox/genesis/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::GenesisRecord, &self.canonical_body())
    }

    /// The channelID: `SHA-256(canonical genesis body)` (ADR-007/ADR-005). This
    /// is the authoritative derivation; M3's
    /// [`crate::join::channelid::channel_id`] hashes these same canonical bytes.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        sha256(&self.canonical_body())
    }

    /// Decode a genesis body from its canonical bytes, validating arity, the
    /// policy enums' domains, the composite key encoding, and the algo-id (must be
    /// the composite signature class).
    fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 5 {
            return Err(Error::MalformedGovernance("genesis arity"));
        }
        let nonce: [u8; GENESIS_NONCE_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("genesis nonce length"))?;
        let created = d.uint()?;
        if d.array()? != 3 {
            return Err(Error::MalformedGovernance("genesis policy arity"));
        }
        let history_mode = HistoryMode::from_u64(d.uint()?)?;
        let deniability_mode = DeniabilityMode::from_u64(d.uint()?)?;
        let ttl = d.uint()?;
        let pk_bytes: [u8; COMPOSITE_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("genesis creator_pubkey length"))?;
        if d.array()? != 1 {
            return Err(Error::MalformedGovernance("genesis algo_ids arity"));
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
        let creator_pubkey = CompositePublicKey::from_bytes(&pk_bytes)?;
        Ok(Self {
            nonce,
            created,
            policy: ChannelPolicy {
                history_mode,
                deniability_mode,
                ttl,
            },
            creator_pubkey,
        })
    }
}

/// A complete genesis record: the body plus the creator's composite
/// self-signature over [`GenesisBody::signing_input`] (ADR-007).
#[derive(Debug, Clone)]
pub struct Genesis {
    /// The signed body.
    pub body: GenesisBody,
    /// The creator's composite self-signature.
    pub signature: CompositeSignature,
}

impl Genesis {
    /// Build and self-sign a genesis record with a freshly-sampled 128-bit nonce.
    ///
    /// `creator_root` is the channel creator's identity root (becomes the root
    /// admin). Returns [`Error::Rng`] if the OS CSPRNG is unavailable.
    pub fn create(
        creator_root: &dyn RootSigner,
        created: u64,
        policy: ChannelPolicy,
    ) -> Result<Self> {
        let mut nonce = [0u8; GENESIS_NONCE_LEN];
        fill_random(&mut nonce)?;
        Self::create_with_nonce(creator_root, created, policy, nonce)
    }

    /// Build and self-sign a genesis record with an explicit nonce (deterministic
    /// — used by golden vectors and tests; production uses [`Genesis::create`]).
    pub fn create_with_nonce(
        creator_root: &dyn RootSigner,
        created: u64,
        policy: ChannelPolicy,
        nonce: [u8; GENESIS_NONCE_LEN],
    ) -> Result<Self> {
        let body = GenesisBody {
            nonce,
            created,
            policy,
            creator_pubkey: creator_root.public_key(),
        };
        let signature = creator_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// The channelID this genesis defines: `SHA-256(canonical body)`.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        self.body.channel_id()
    }

    /// The creator's composite root public key (the root admin).
    #[must_use]
    pub fn creator_pubkey(&self) -> &CompositePublicKey {
        &self.body.creator_pubkey
    }

    /// The 6-field wire body: the 5 signed body fields, with the composite
    /// self-signature appended as the 6th element (ADR-008). Framed by
    /// [`Genesis::to_wire`].
    #[must_use]
    fn wire_body(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(6)
            .bytes(&b.nonce)
            .uint(b.created)
            .array(3)
            .uint(b.policy.history_mode.as_u64())
            .uint(b.policy.deniability_mode.as_u64())
            .uint(b.policy.ttl);
        e.bytes(&b.creator_pubkey.to_bytes())
            .array(1)
            .uint(u64::from(algo::COMPOSITE_ED25519_ML_DSA_65));
        e.bytes(&self.signature.to_bytes());
        e.finish()
    }

    /// Frame for the wire/storage per ADR-008: `tag(2 BE) ‖ version(1) ‖
    /// canonical_cbor_6field_body` (tag [`StructTag::GenesisRecord`] = `0x000D`).
    /// The `vox/genesis/v1` domain label is the *signing* prefix, **not** the wire
    /// frame (ADR-008 §Struct framing).
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        frame(StructTag::GenesisRecord, &self.wire_body())
    }

    /// Parse a framed genesis record, rejecting a wrong/unknown struct tag,
    /// unsupported version, arity, or malformed body/signature. Does NOT verify
    /// the self-signature — call [`Genesis::verify`].
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::GenesisRecord {
            return Err(Error::MalformedGovernance("genesis wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 6 {
            return Err(Error::MalformedGovernance("genesis wire arity"));
        }
        // Read all six wire elements, then re-encode the first five into the
        // body-only canonical buffer and decode strictly, so the reconstructed
        // signing input is byte-identical to the creator's.
        let nonce = d.bytes()?.to_vec();
        let created = d.uint()?;
        if d.array()? != 3 {
            return Err(Error::MalformedGovernance("genesis policy arity"));
        }
        let history_mode = d.uint()?;
        let deniability_mode = d.uint()?;
        let ttl = d.uint()?;
        let creator_pubkey = d.bytes()?.to_vec();
        if d.array()? != 1 {
            return Err(Error::MalformedGovernance("genesis algo_ids arity"));
        }
        let sign_algo = d.uint()?;
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;

        let mut be = Encoder::new();
        be.array(5)
            .bytes(&nonce)
            .uint(created)
            .array(3)
            .uint(history_mode)
            .uint(deniability_mode)
            .uint(ttl);
        be.bytes(&creator_pubkey).array(1).uint(sign_algo);
        let body = GenesisBody::from_canonical_body(&be.finish())?;

        let sig_arr: [u8; crate::hash::COMPOSITE_SIG_LEN] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedGovernance("genesis signature length"))?;
        let signature = CompositeSignature::from_bytes(&sig_arr)?;
        Ok(Self { body, signature })
    }

    /// Verify the creator's self-signature over the canonical body.
    ///
    /// A genesis record is *self-certifying*: the creator key it carries signs
    /// itself, so verification needs no external trust anchor — but a verifier
    /// MUST additionally check [`Genesis::matches_channel_id`] against the
    /// channelID it joined with, or use [`Genesis::accept_for_channel`].
    pub fn verify(&self) -> Result<()> {
        self.body
            .creator_pubkey
            .verify(&self.body.signing_input(), &self.signature)
    }

    /// Whether this genesis hashes to `expected_channel_id` — the cold-join check
    /// (ADR-007): a node accepts a fetched genesis only if its hash equals the
    /// channelID it joined with.
    #[must_use]
    pub fn matches_channel_id(&self, expected_channel_id: &Digest32) -> bool {
        &self.channel_id() == expected_channel_id
    }

    /// The full cold-join acceptance: the self-signature verifies **and** the
    /// canonical hash equals `expected_channel_id`. Either failure rejects the
    /// genesis (ADR-007).
    pub fn accept_for_channel(&self, expected_channel_id: &Digest32) -> Result<()> {
        if !self.matches_channel_id(expected_channel_id) {
            return Err(Error::MalformedGovernance(
                "genesis hash != expected channelID",
            ));
        }
        self.verify()
    }
}

fn u16_from(v: u64) -> Result<u16> {
    u16::try_from(v).map_err(|_| Error::MalformedGovernance("genesis algo id out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::join::channelid;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn sample_policy() -> ChannelPolicy {
        ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
        }
    }

    #[test]
    fn build_verify_round_trip() {
        let r = root(1, 2);
        let g = Genesis::create_with_nonce(&r, 1_700_000_000, sample_policy(), [0xAB; 16]).unwrap();
        assert!(g.verify().is_ok());
        let decoded = Genesis::from_wire(&g.to_wire()).unwrap();
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded.body, g.body);
        assert_eq!(decoded.channel_id(), g.channel_id());
    }

    #[test]
    fn channel_id_is_sha256_of_canonical_body() {
        let r = root(3, 4);
        let g = Genesis::create_with_nonce(&r, 100, sample_policy(), [7; 16]).unwrap();
        assert_eq!(g.channel_id(), sha256(&g.body.canonical_body()));
    }

    #[test]
    fn m3_channel_id_is_consistent() {
        // M3's channelid::channel_id hashes the same canonical genesis bytes M6
        // produces — the two milestones MUST derive the identical channelID.
        let r = root(5, 6);
        let g = Genesis::create_with_nonce(&r, 100, sample_policy(), [9; 16]).unwrap();
        assert_eq!(
            g.channel_id(),
            channelid::channel_id(&g.body.canonical_body())
        );
    }

    #[test]
    fn cold_join_accepts_matching_hash() {
        let r = root(7, 8);
        let g = Genesis::create_with_nonce(&r, 100, sample_policy(), [1; 16]).unwrap();
        let cid = g.channel_id();
        assert!(g.accept_for_channel(&cid).is_ok());
        // Wrong channelID is rejected.
        assert!(g.accept_for_channel(&[0xFF; 32]).is_err());
    }

    #[test]
    fn tamper_rejected_by_signature_and_hash() {
        let r = root(9, 10);
        let g = Genesis::create_with_nonce(&r, 100, sample_policy(), [2; 16]).unwrap();
        let cid = g.channel_id();
        let mut tampered = g.clone();
        tampered.body.created = 999; // changes both the signing input AND the hash
        assert!(tampered.verify().is_err());
        assert!(!tampered.matches_channel_id(&cid));
    }

    #[test]
    fn distinct_nonces_distinct_channel_ids() {
        let r = root(11, 12);
        let a = Genesis::create_with_nonce(&r, 100, sample_policy(), [1; 16]).unwrap();
        let b = Genesis::create_with_nonce(&r, 100, sample_policy(), [2; 16]).unwrap();
        assert_ne!(a.channel_id(), b.channel_id());
    }

    #[test]
    fn policy_enums_round_trip_all_values() {
        for hm in [HistoryMode::ForwardOnly, HistoryMode::FullHistory] {
            assert_eq!(HistoryMode::from_u64(hm.as_u64()).unwrap(), hm);
        }
        for dm in [DeniabilityMode::Attributable, DeniabilityMode::Deniable] {
            assert_eq!(DeniabilityMode::from_u64(dm.as_u64()).unwrap(), dm);
        }
        assert!(HistoryMode::from_u64(2).is_err());
        assert!(DeniabilityMode::from_u64(2).is_err());
    }

    #[test]
    fn from_wire_rejects_wrong_tag() {
        let r = root(1, 1);
        let g = Genesis::create_with_nonce(&r, 1, sample_policy(), [0; 16]).unwrap();
        let reframed = crate::wire::frame(StructTag::Skdm, &g.to_wire()[3..]);
        assert!(matches!(
            Genesis::from_wire(&reframed),
            Err(Error::MalformedGovernance("genesis wrong struct tag"))
        ));
    }

    #[test]
    fn deniable_genesis_round_trips() {
        let r = root(2, 2);
        let policy = ChannelPolicy {
            history_mode: HistoryMode::FullHistory,
            deniability_mode: DeniabilityMode::Deniable,
            ttl: 3600,
        };
        let g = Genesis::create_with_nonce(&r, 100, policy, [3; 16]).unwrap();
        let decoded = Genesis::from_wire(&g.to_wire()).unwrap();
        assert_eq!(decoded.body.policy, policy);
        assert!(decoded.verify().is_ok());
    }
}
