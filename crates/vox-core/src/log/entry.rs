//! The Vox log entry (ADR-008, tag `0x0001`, domain `vox/log-entry/v1`).
//!
//! Every identity owns a single-writer, append-only, hash-linked log; a log
//! entry is its unit. The entry is a *signed skeleton* over a payload **hash**,
//! not the payload bytes — so a peer may prune an old payload (honoring admin
//! TTL, ADR-010) while the hash-linked, signed skeleton stays fully verifiable
//! (ADR-008 §"payload-hash signing").
//!
//! ## Fields (ADR-008, exact order — pinned by [`EntrySkeleton::canonical_body`])
//! `{ author_id, seq, prev_hash, lipmaa_backlink, channelID, epoch, algo_ids,
//!    payload_hash, payload_len, end_of_feed_flag }`, a 10-element canonical-CBOR
//! array (ADR-008 §"Canonical serialization"). `seq` is the per-author sequence,
//! strictly monotonic from 1. `prev_hash` is the SHA-256 of the seq−1 entry's
//! canonical bytes; `lipmaa_backlink` is the SHA-256 of the entry at the Bamboo
//! `lipmaa(seq)` predecessor ([`crate::log::feed`]). The genesis entry (seq 1)
//! carries all-zero `prev_hash` and `lipmaa_backlink` — there is no predecessor.
//!
//! ## Authenticator (per entry TYPE, ADR-008 §"Per-entry-type authentication")
//! The authenticator is computed over `vox/log-entry/v1 ‖ canonical_body`
//! ([`crate::wire::signing_input`]). Governance/control entries are **always**
//! composite Ed25519+ML-DSA root-signed; message-content entries are
//! composite-signed in attributable channels and carry the ADR-009 deniable
//! authenticator in deniable channels. The entry wire carries an **authenticator-
//! type discriminant** so composite vs deniable is distinguishable and
//! forward-compatible. M5 builds the **attributable (composite) path fully** and
//! the **deniable wire seam** ([`Authenticator::Deniable`]) — the deniable
//! *crypto* is M7 (ADR-009), so [`Entry::verify`] returns a clear boundary error
//! ([`Error::DeniableVerificationUnavailable`]) for a deniable authenticator
//! rather than faking verification. Because the authenticator commits to
//! `payload_hash`, the skeleton verifies whether or not the payload is retained.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32, COMPOSITE_SIG_LEN, DIGEST_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::suite::{algo, validate_algo};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// A 32-byte all-zero hash, used for the genesis entry's `prev_hash` and
/// `lipmaa_backlink` (there is no predecessor to hash).
pub const ZERO_HASH: Digest32 = [0u8; DIGEST_LEN];

/// Hard upper bound on a deniable authenticator's serialized length (bytes),
/// enforced **before** allocation so a hostile `auth_type = Deniable` frame with
/// a huge declared length cannot force a large copy (ADR-008 anti-abuse). The
/// composite signature is fixed-length ([`COMPOSITE_SIG_LEN`]); the deniable
/// authenticator (ADR-009/M7) is bounded generously here and tightened by M7.
pub const MAX_AUTHENTICATOR_LEN: usize = 8 * 1024;

/// Hard upper bound on a retained payload body (bytes) accepted from a single
/// framed entry, enforced **before** `to_vec`. This is a per-*entry* structural
/// ceiling so a hostile frame cannot force a multi-megabyte allocation before the
/// per-author byte quota ([`crate::log::quota`]) is even consulted; the quota is
/// the policy limit, this is the pre-allocation guard (ADR-008 anti-abuse).
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// Wire discriminant for [`Authenticator::Composite`] (attributable).
const AUTH_TYPE_COMPOSITE: u64 = 1;
/// Wire discriminant for [`Authenticator::Deniable`] (ADR-009/M7; non-attributable).
const AUTH_TYPE_DENIABLE: u64 = 2;

/// The kind of entry, which fixes how it is authenticated (ADR-008
/// §"Per-entry-type authentication"). Authentication is chosen by entry TYPE,
/// not merely by channel mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind {
    /// Governance/control: genesis, admin delegations, consent grants/revocations,
    /// policy/passphrase-rotation, deniable-mode DGKA/DSKE setup. **Always**
    /// root-composite-signed, in every channel (ADR-008). Two validly-signed
    /// conflicting governance entries are a self-authenticating fork proof.
    Governance,
    /// Message content. In an attributable channel this is root-composite-signed;
    /// in a deniable channel it carries the ADR-009 forgeable authenticator (M7),
    /// in which case a conflict is *not* self-authenticating.
    Content,
}

/// The authenticator over an entry's signing input.
///
/// M5 ships the [`Authenticator::Composite`] (attributable) variant in full and
/// the [`Authenticator::Deniable`] **wire seam** (opaque bytes; ADR-009 crypto is
/// M7). The enum (rather than always a [`CompositeSignature`]) is what lets the
/// fork logic distinguish a *self-authenticating* conflict (composite) from a
/// *forgeable* one (deniable) directly from the authenticator type — no caller
/// hint — and lets the wire carry a forward-compatible type discriminant.
#[derive(Clone)]
#[non_exhaustive]
pub enum Authenticator {
    /// A composite Ed25519+ML-DSA-65 root signature (ADR-002). Attributable: it
    /// genuinely incriminates the author on a fork. Boxed because the composite
    /// signature is multi-kilobyte while the deniable variant is small, so the
    /// enum stays compact (clippy `large_enum_variant`).
    Composite(Box<CompositeSignature>),
    /// The ADR-009 **deniable** content authenticator (M7). Held opaquely in M5:
    /// the bytes round-trip on the wire and are classified non-attributable, but
    /// M5 does not verify them (the construction is M7). Verification is delegated
    /// to a [`DeniableVerifier`]; without one, [`Entry::verify`] returns
    /// [`Error::DeniableVerificationUnavailable`] (an honest boundary, not a stub).
    Deniable(Vec<u8>),
}

impl Authenticator {
    /// Whether this authenticator is attributable (a conflict under it is a
    /// self-authenticating fork proof). Composite signatures are attributable; the
    /// deniable authenticator (forgeable by any member, ADR-009) is not.
    #[must_use]
    pub fn is_attributable(&self) -> bool {
        match self {
            Authenticator::Composite(_) => true,
            Authenticator::Deniable(_) => false,
        }
    }

    /// The wire type discriminant for this authenticator.
    fn type_id(&self) -> u64 {
        match self {
            Authenticator::Composite(_) => AUTH_TYPE_COMPOSITE,
            Authenticator::Deniable(_) => AUTH_TYPE_DENIABLE,
        }
    }

    /// The serialized bytes of this authenticator: the composite signature's
    /// fixed-length encoding, or the opaque deniable bytes verbatim.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Authenticator::Composite(sig) => sig.to_bytes().to_vec(),
            Authenticator::Deniable(bytes) => bytes.clone(),
        }
    }
}

impl core::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Authenticator::Composite(_) => f.write_str("Authenticator::Composite(..)"),
            Authenticator::Deniable(b) => write!(f, "Authenticator::Deniable({} bytes)", b.len()),
        }
    }
}

/// The verification seam for the ADR-009 **deniable** content authenticator,
/// implemented by milestone M7. M5 defines the trait so the entry verification
/// path is type-complete and forward-compatible; M5 itself ships **no**
/// implementation (the deniable construction is M7) — an [`Entry`] carrying a
/// deniable authenticator therefore fails verification with
/// [`Error::DeniableVerificationUnavailable`] until an M7 verifier is supplied.
///
/// This is the acyclic 009→008 coupling ADR-008 §Consequences describes: 008
/// owns the *shape* of the check (the trait + the non-attributable classification
/// + the alarm fork path); 009/M7 owns the *crypto*.
pub trait DeniableVerifier {
    /// Verify a deniable authenticator's `auth_bytes` over `signing_input` for the
    /// entry authored by `author_id`. Returns `Ok(())` iff the (forgeable, but
    /// per-author-ordered) authenticator is valid per ADR-009.
    fn verify_deniable(
        &self,
        author_id: &Digest32,
        signing_input: &[u8],
        auth_bytes: &[u8],
    ) -> Result<()>;
}

/// A [`DeniableVerifier`] placeholder used only to name a concrete type for the
/// `None` case of [`Entry::verify`] (which performs no deniable verification).
/// Its method is never called — a `None::<&NoDeniableVerifier>` short-circuits to
/// the boundary error — so it deliberately has no real implementation.
enum NoDeniableVerifier {}

impl DeniableVerifier for NoDeniableVerifier {
    fn verify_deniable(&self, _: &Digest32, _: &[u8], _: &[u8]) -> Result<()> {
        // Unconstructible (empty enum): this arm is unreachable. Returning the
        // boundary error keeps the function total without a panic.
        Err(Error::DeniableVerificationUnavailable)
    }
}

/// The unsigned entry skeleton — every field except the authenticator.
///
/// Held separately so [`EntrySkeleton::signing_input`] is the exact bytes the
/// author signs and a verifier checks. The 10 fields are in the ADR-008 order.
#[derive(Clone, PartialEq, Eq)]
pub struct EntrySkeleton {
    /// The author's identity fingerprint (ADR-002 `SHA-256(Ed25519 ‖ ML-DSA)`).
    pub author_id: Digest32,
    /// Per-author sequence number, strictly monotonic from 1.
    pub seq: u64,
    /// SHA-256 of the seq−1 entry's canonical bytes (all-zero at seq 1).
    pub prev_hash: Digest32,
    /// SHA-256 of the `lipmaa(seq)` entry's canonical bytes (all-zero at seq 1).
    pub lipmaa_backlink: Digest32,
    /// The 32-byte channel identifier (ADR-005), or the self-channel id.
    pub channel_id: Digest32,
    /// The membership epoch (passphrase-rotation generation, ADR-007).
    pub epoch: u64,
    /// `[sign_algo, aead_algo]` — the authenticator class and payload AEAD class
    /// in force (ADR-003 algorithm IDs).
    pub algo_ids: [u16; 2],
    /// SHA-256 of the (encrypted) payload bytes. The authenticator commits to
    /// this, not the bytes, so the payload can be pruned (ADR-008/ADR-010).
    pub payload_hash: Digest32,
    /// The byte length of the payload the `payload_hash` covers.
    pub payload_len: u64,
    /// Whether this entry terminates the feed (Bamboo end-of-feed marker): no
    /// entry at `seq + 1` may ever be authored.
    pub end_of_feed: bool,
}

impl core::fmt::Debug for EntrySkeleton {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EntrySkeleton")
            .field("author_id", &crate::hash::Hex(&self.author_id))
            .field("seq", &self.seq)
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("epoch", &self.epoch)
            .field("payload_len", &self.payload_len)
            .field("end_of_feed", &self.end_of_feed)
            .finish_non_exhaustive()
    }
}

impl EntrySkeleton {
    /// Canonical-CBOR body in the ADR-008 field order: a 10-element array
    /// `[author_id, seq, prev_hash, lipmaa_backlink, channelID, epoch,
    ///   [sign_algo, aead_algo], payload_hash, payload_len, end_of_feed_flag]`.
    /// `end_of_feed_flag` is a CBOR unsigned integer 0/1 (the codec has no bool;
    /// 0 and 1 are the canonical shortest forms).
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(10)
            .bytes(&self.author_id)
            .uint(self.seq)
            .bytes(&self.prev_hash)
            .bytes(&self.lipmaa_backlink)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .array(2)
            .uint(u64::from(self.algo_ids[0]))
            .uint(u64::from(self.algo_ids[1]));
        e.bytes(&self.payload_hash)
            .uint(self.payload_len)
            .uint(u64::from(self.end_of_feed));
        e.finish()
    }

    /// The signing/authentication input: `vox/log-entry/v1 ‖ canonical_body`
    /// (ADR-008 §"Canonical serialization").
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::LogEntry, &self.canonical_body())
    }

    /// The SHA-256 over the canonical body — the entry's identity used by
    /// `prev_hash`/`lipmaa_backlink` chaining, by the DAG, and as the
    /// Negentropy reconciliation key (ADR-008 §Sync, "full 32-byte SHA-256 entry
    /// hash"). Hashing the *body* (not the framed/signed input) means two
    /// implementations agree byte-for-byte regardless of the authenticator.
    #[must_use]
    pub fn entry_hash(&self) -> Digest32 {
        sha256(&self.canonical_body())
    }

    /// Decode a skeleton from its 10-element canonical body, validating arity,
    /// digest lengths, the algo-id registry membership and classes, and the
    /// end-of-feed flag domain (0 or 1 only).
    fn from_canonical_body(body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        if d.array()? != 10 {
            return Err(Error::MalformedBundle("log-entry arity"));
        }
        let author_id = take_digest(&mut d)?;
        let seq = d.uint()?;
        // Bound seq so the lipmaa power-of-three arithmetic stays overflow-free
        // (ADR-008; see `crate::log::feed::MAX_SEQ`).
        if seq > crate::log::feed::MAX_SEQ {
            return Err(Error::SizeLimitExceeded("log-entry seq exceeds MAX_SEQ"));
        }
        let prev_hash = take_digest(&mut d)?;
        let lipmaa_backlink = take_digest(&mut d)?;
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("log-entry algo_ids arity"));
        }
        let sign_algo = u16_from(d.uint()?)?;
        let aead_algo = u16_from(d.uint()?)?;
        let payload_hash = take_digest(&mut d)?;
        let payload_len = d.uint()?;
        let end_of_feed = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedBundle("log-entry end_of_feed flag")),
        };
        d.finish()?;

        // Registry + class guards (ADR-003 type-confusion): the sign slot holds a
        // signature algo and the aead slot an AEAD algo.
        validate_algo(sign_algo)?;
        validate_algo(aead_algo)?;
        if sign_algo != algo::COMPOSITE_ED25519_ML_DSA_65 {
            return Err(Error::UnexpectedAlgo {
                got: sign_algo,
                expected: algo::COMPOSITE_ED25519_ML_DSA_65,
            });
        }
        if aead_algo != algo::AES_256_GCM {
            return Err(Error::UnexpectedAlgo {
                got: aead_algo,
                expected: algo::AES_256_GCM,
            });
        }

        Ok(Self {
            author_id,
            seq,
            prev_hash,
            lipmaa_backlink,
            channel_id,
            epoch,
            algo_ids: [sign_algo, aead_algo],
            payload_hash,
            payload_len,
            end_of_feed,
        })
    }
}

/// A complete log entry: the signed skeleton plus its authenticator, and
/// optionally the retained payload body.
///
/// `payload` is `Some` while the body is retained and `None` once pruned
/// (ADR-008/ADR-010). The skeleton — and thus the whole entry's verifiability —
/// is independent of `payload`, because the authenticator commits to
/// `payload_hash`.
#[derive(Clone)]
pub struct Entry {
    /// The signed 10-field skeleton.
    pub skeleton: EntrySkeleton,
    /// The authenticator over [`EntrySkeleton::signing_input`].
    pub authenticator: Authenticator,
    /// The retained payload body, or `None` if pruned.
    pub payload: Option<Vec<u8>>,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("skeleton", &self.skeleton)
            .field("authenticator", &self.authenticator)
            .field("payload_retained", &self.payload.is_some())
            .finish()
    }
}

impl Entry {
    /// Build and **composite-sign** an attributable entry, retaining `payload`.
    ///
    /// The signer's fingerprint MUST equal `skeleton.author_id` (the build
    /// enforces this so the signed `author_id` always matches the signer). The
    /// caller hashes the payload into `skeleton.payload_hash`; this checks the
    /// supplied `payload` matches, so a caller cannot retain a body inconsistent
    /// with its own skeleton. Governance and attributable-channel content entries
    /// both take this path; the [`EntryKind`] governing the fork remedy is
    /// supplied to the DAG at acceptance ([`crate::log::dag`]), not stored in the
    /// signed bytes (the channel context decides it, not the author).
    pub fn build_signed(
        author_root: &dyn RootSigner,
        skeleton: EntrySkeleton,
        payload: Vec<u8>,
    ) -> Result<Self> {
        let authenticator = Self::sign_skeleton(author_root, &skeleton)?;
        if sha256(&payload) != skeleton.payload_hash || payload.len() as u64 != skeleton.payload_len
        {
            return Err(Error::MalformedBundle(
                "log-entry payload hash/len mismatch",
            ));
        }
        Ok(Self {
            skeleton,
            authenticator,
            payload: Some(payload),
        })
    }

    /// Build a composite-signed entry whose payload body is **not** retained
    /// (skeleton-only). Used when authoring a record whose body lives elsewhere,
    /// or when reconstructing the signed skeleton during pruning. The
    /// `payload_hash`/`payload_len` in `skeleton` still bind the (absent) body.
    pub fn build_signed_skeleton_only(
        author_root: &dyn RootSigner,
        skeleton: EntrySkeleton,
    ) -> Result<Self> {
        let auth = Self::sign_skeleton(author_root, &skeleton)?;
        Ok(Self {
            skeleton,
            authenticator: auth,
            payload: None,
        })
    }

    /// Construct a **content** entry carrying an opaque ADR-009 *deniable*
    /// authenticator (the M7 crypto produces `auth_bytes`; M5 only carries them).
    /// The entry round-trips on the wire and is classified non-attributable; M5
    /// does not verify it ([`Entry::verify`] returns
    /// [`Error::DeniableVerificationUnavailable`] without an M7
    /// [`DeniableVerifier`]). Rejects an over-limit authenticator before storing.
    /// Governance entries MUST be composite, so this is content-only by contract.
    pub fn with_deniable_authenticator(
        skeleton: EntrySkeleton,
        auth_bytes: Vec<u8>,
        payload: Option<Vec<u8>>,
    ) -> Result<Self> {
        if auth_bytes.len() > MAX_AUTHENTICATOR_LEN {
            return Err(Error::SizeLimitExceeded("log-entry authenticator"));
        }
        let entry = Self {
            skeleton,
            authenticator: Authenticator::Deniable(auth_bytes),
            payload,
        };
        entry.verify_payload_binding()?;
        Ok(entry)
    }

    fn sign_skeleton(
        author_root: &dyn RootSigner,
        skeleton: &EntrySkeleton,
    ) -> Result<Authenticator> {
        if author_root.fingerprint() != skeleton.author_id {
            return Err(Error::MalformedBundle("log-entry author_id != signer"));
        }
        let sig = author_root.sign(&skeleton.signing_input())?;
        Ok(Authenticator::Composite(Box::new(sig)))
    }

    /// Verify the entry's authenticator against the claimed author's composite
    /// root public key, and (if a payload is retained) that it matches the
    /// committed `payload_hash`/`payload_len`.
    ///
    /// Checks, in order: (a) `author_root`'s fingerprint equals the skeleton's
    /// `author_id`; (b) the composite signature verifies over the signing input;
    /// (c) any retained payload hashes to `payload_hash` and has `payload_len`
    /// bytes. Any mismatch is a hard failure. Render-gating (ADR-008) is *not*
    /// here: this verifies authorship/integrity; decryption/rendering is M4/M6.
    ///
    /// A **deniable** authenticator ([`Authenticator::Deniable`]) cannot be
    /// verified by M5 (the construction is ADR-009/M7); this returns
    /// [`Error::DeniableVerificationUnavailable`]. Use
    /// [`Entry::verify_with_deniable`] with an M7 [`DeniableVerifier`] to verify
    /// such an entry.
    pub fn verify(&self, author_root: &CompositePublicKey) -> Result<()> {
        self.verify_with_deniable(author_root, None::<&NoDeniableVerifier>)
    }

    /// Verify as [`Entry::verify`], but verify a [`Authenticator::Deniable`]
    /// authenticator with the supplied `deniable` verifier (M7/ADR-009) when one
    /// is provided. A composite authenticator is verified against `author_root`
    /// regardless of `deniable`.
    pub fn verify_with_deniable<V: DeniableVerifier>(
        &self,
        author_root: &CompositePublicKey,
        deniable: Option<&V>,
    ) -> Result<()> {
        if author_root.fingerprint() != self.skeleton.author_id {
            return Err(Error::MalformedBundle(
                "log-entry author_id != root fingerprint",
            ));
        }
        match &self.authenticator {
            Authenticator::Composite(sig) => {
                author_root.verify(&self.skeleton.signing_input(), sig)?;
            }
            Authenticator::Deniable(bytes) => match deniable {
                Some(v) => {
                    v.verify_deniable(
                        &self.skeleton.author_id,
                        &self.skeleton.signing_input(),
                        bytes,
                    )?;
                }
                None => return Err(Error::DeniableVerificationUnavailable),
            },
        }
        self.verify_payload_binding()
    }

    /// Check that any retained payload matches the committed hash and length.
    /// A skeleton-only entry (`payload == None`) trivially satisfies this — the
    /// skeleton stays verifiable after pruning (ADR-008).
    pub fn verify_payload_binding(&self) -> Result<()> {
        if let Some(p) = &self.payload {
            if sha256(p) != self.skeleton.payload_hash
                || p.len() as u64 != self.skeleton.payload_len
            {
                return Err(Error::MalformedBundle(
                    "log-entry payload hash/len mismatch",
                ));
            }
        }
        Ok(())
    }

    /// Drop the retained payload body, keeping the signed skeleton. This is
    /// *authenticated pruning* (ADR-008): the skeleton — and the whole feed's
    /// hash chain — stays verifiable, so pruning can never silently rewrite
    /// history. Returns whether a body was actually dropped.
    pub fn prune_payload(&mut self) -> bool {
        self.payload.take().is_some()
    }

    /// The entry's hash (over the canonical body) — its DAG/Negentropy key.
    #[must_use]
    pub fn entry_hash(&self) -> Digest32 {
        self.skeleton.entry_hash()
    }

    /// Frame the entry for the wire/storage per ADR-008: `tag(2 BE) ‖
    /// version(1) ‖ canonical_cbor_body`. The body is a flat CBOR array — the 10
    /// skeleton fields, then `auth_type` (1 = composite, 2 = deniable),
    /// `authenticator_bytes`, `payload_present` (0/1), and the payload byte string
    /// iff present. The skeleton fields are inlined (not a nested array) so the
    /// strict decoder reads them directly; a pruned entry omits the body but still
    /// carries the verifiable skeleton + typed authenticator.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let sk = &self.skeleton;
        let auth = self.authenticator.to_bytes();
        let has_payload = self.payload.is_some();
        // 10 skeleton fields (algo_ids inner array counts as one element) +
        // auth_type + authenticator + payload_present (+ payload).
        let arity = if has_payload { 14 } else { 13 };
        let mut e = Encoder::new();
        e.array(arity)
            .bytes(&sk.author_id)
            .uint(sk.seq)
            .bytes(&sk.prev_hash)
            .bytes(&sk.lipmaa_backlink)
            .bytes(&sk.channel_id)
            .uint(sk.epoch)
            .array(2)
            .uint(u64::from(sk.algo_ids[0]))
            .uint(u64::from(sk.algo_ids[1]));
        e.bytes(&sk.payload_hash)
            .uint(sk.payload_len)
            .uint(u64::from(sk.end_of_feed))
            .uint(self.authenticator.type_id())
            .bytes(&auth)
            .uint(u64::from(has_payload));
        if let Some(p) = &self.payload {
            e.bytes(p);
        }
        frame(StructTag::LogEntry, &e.finish())
    }

    /// Parse a framed entry from the wire/storage. Rejects a wrong/unknown
    /// struct tag, unsupported version, arity, an unknown authenticator type, an
    /// over-limit authenticator/payload length (rejected **before** allocation —
    /// ADR-008 anti-abuse), or a malformed skeleton/authenticator/payload. Does
    /// NOT verify the signature — call [`Entry::verify`]. A retained payload, if
    /// present, is checked against the committed hash/len so a tampered body is
    /// rejected at parse.
    ///
    /// The 10 skeleton fields are re-encoded into a body-only buffer and decoded
    /// through the strict skeleton decoder (which enforces the algo classes), so
    /// the reconstructed signing input is byte-identical to the author's — the
    /// precondition for signature verification.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::LogEntry {
            return Err(Error::MalformedBundle("log-entry wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        let arity = d.array()?;
        if arity != 13 && arity != 14 {
            return Err(Error::MalformedBundle("log-entry wire arity"));
        }
        let author_id = take_digest(&mut d)?;
        let seq = d.uint()?;
        let prev_hash = take_digest(&mut d)?;
        let lipmaa_backlink = take_digest(&mut d)?;
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("log-entry algo_ids arity"));
        }
        let sign_algo = d.uint()?;
        let aead_algo = d.uint()?;
        let payload_hash = take_digest(&mut d)?;
        let payload_len = d.uint()?;
        let end_of_feed = d.uint()?;
        let auth_type = d.uint()?;
        let authenticator = decode_authenticator(&mut d, auth_type)?;
        let present = d.uint()?;
        let payload = match (present, arity) {
            (1, 14) => {
                // `d.bytes()` returns a BORROWED slice (length already bounded by
                // the remaining input — no allocation yet). Check the *actual*
                // byte-string length against the cap BEFORE `to_vec`, so a hostile
                // wire that declares a small `payload_len` but carries a large
                // byte string cannot force the large copy.
                let slice = d.bytes()?;
                if slice.len() > MAX_PAYLOAD_LEN {
                    return Err(Error::SizeLimitExceeded("log-entry payload"));
                }
                // The actual byte-string length MUST equal the signed
                // `payload_len`; otherwise the payload_hash/skeleton binding is
                // inconsistent (the signature commits to `payload_len`).
                if slice.len() as u64 != payload_len {
                    return Err(Error::MalformedBundle(
                        "log-entry payload length != signed payload_len",
                    ));
                }
                Some(slice.to_vec())
            }
            (0, 13) => None,
            _ => {
                return Err(Error::MalformedBundle(
                    "log-entry payload presence mismatch",
                ))
            }
        };
        d.finish()?;

        // Rebuild the 10-field skeleton body and decode strictly (class checks,
        // end_of_feed domain, digest lengths).
        let mut be = Encoder::new();
        be.array(10)
            .bytes(&author_id)
            .uint(seq)
            .bytes(&prev_hash)
            .bytes(&lipmaa_backlink)
            .bytes(&channel_id)
            .uint(epoch)
            .array(2)
            .uint(sign_algo)
            .uint(aead_algo);
        be.bytes(&payload_hash).uint(payload_len).uint(end_of_feed);
        let skeleton = EntrySkeleton::from_canonical_body(&be.finish())?;

        let entry = Self {
            skeleton,
            authenticator,
            payload,
        };
        entry.verify_payload_binding()?;
        Ok(entry)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("log-entry digest length"))
}

/// Decode the typed authenticator. The codec's `bytes()` returns a borrowed slice
/// (length already bounded against the remaining input), so an over-limit
/// authenticator is rejected by checking the borrowed length **before** any owned
/// allocation (`to_vec` / `from_bytes`). An unknown `auth_type` is a hard fail.
fn decode_authenticator(d: &mut Decoder<'_>, auth_type: u64) -> Result<Authenticator> {
    let auth_bytes = d.bytes()?;
    if auth_bytes.len() > MAX_AUTHENTICATOR_LEN {
        return Err(Error::SizeLimitExceeded("log-entry authenticator"));
    }
    match auth_type {
        AUTH_TYPE_COMPOSITE => {
            let auth_arr: [u8; COMPOSITE_SIG_LEN] = auth_bytes
                .try_into()
                .map_err(|_| Error::MalformedBundle("log-entry authenticator length"))?;
            Ok(Authenticator::Composite(Box::new(
                CompositeSignature::from_bytes(&auth_arr)?,
            )))
        }
        AUTH_TYPE_DENIABLE => Ok(Authenticator::Deniable(auth_bytes.to_vec())),
        _ => Err(Error::MalformedBundle(
            "log-entry unknown authenticator type",
        )),
    }
}

fn u16_from(v: u64) -> Result<u16> {
    u16::try_from(v).map_err(|_| Error::MalformedBundle("log-entry algo id out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn skeleton_for(r: &SoftwareRootSigner, seq: u64, payload: &[u8]) -> EntrySkeleton {
        EntrySkeleton {
            author_id: r.fingerprint(),
            seq,
            prev_hash: if seq == 1 { ZERO_HASH } else { [seq as u8; 32] },
            lipmaa_backlink: if seq == 1 {
                ZERO_HASH
            } else {
                [(seq + 1) as u8; 32]
            },
            channel_id: [0xC1; 32],
            epoch: 7,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(payload),
            payload_len: payload.len() as u64,
            end_of_feed: false,
        }
    }

    #[test]
    fn canonical_body_is_10_element_array() {
        let r = root(1, 2);
        let body = skeleton_for(&r, 1, b"hi").canonical_body();
        // 0x8a = array(10).
        assert_eq!(body[0], 0x8a);
    }

    #[test]
    fn golden_byte_layout_of_skeleton() {
        // A fully-pinned skeleton with all-zero hashes and small ints, so the
        // byte layout of the 10-field array is exact and hand-verifiable.
        let sk = EntrySkeleton {
            author_id: ZERO_HASH,
            seq: 1,
            prev_hash: ZERO_HASH,
            lipmaa_backlink: ZERO_HASH,
            channel_id: ZERO_HASH,
            epoch: 0,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: ZERO_HASH,
            payload_len: 0,
            end_of_feed: false,
        };
        let body = sk.canonical_body();
        let mut expect = Vec::new();
        expect.push(0x8a); // array(10)
        let zero32 = |v: &mut Vec<u8>| {
            v.push(0x58); // bytes, 1-byte length follows
            v.push(0x20); // length 32
            v.extend_from_slice(&[0u8; 32]);
        };
        zero32(&mut expect); // author_id
        expect.push(0x01); // seq = 1
        zero32(&mut expect); // prev_hash
        zero32(&mut expect); // lipmaa_backlink
        zero32(&mut expect); // channel_id
        expect.push(0x00); // epoch = 0
        expect.push(0x82); // array(2) algo_ids
        expect.push(0x19); // uint16 follows: 0x0304
        expect.extend_from_slice(&0x0304u16.to_be_bytes());
        expect.push(0x19); // uint16 follows: 0x0401
        expect.extend_from_slice(&0x0401u16.to_be_bytes());
        zero32(&mut expect); // payload_hash
        expect.push(0x00); // payload_len = 0
        expect.push(0x00); // end_of_feed = 0
        assert_eq!(body, expect);
    }

    #[test]
    fn build_verify_round_trip() {
        let r = root(3, 4);
        let sk = skeleton_for(&r, 1, b"payload");
        let e = Entry::build_signed(&r, sk, b"payload".to_vec()).unwrap();
        assert!(e.verify(&r.public_key()).is_ok());
        assert!(e.authenticator.is_attributable());
    }

    #[test]
    fn governance_entry_composite_verify_and_tamper_rejected() {
        let r = root(5, 6);
        let sk = skeleton_for(&r, 1, b"gov");
        let e = Entry::build_signed(&r, sk, b"gov".to_vec()).unwrap();
        assert!(e.verify(&r.public_key()).is_ok());

        // Tamper a skeleton field after signing: the signature no longer covers it.
        let mut tampered = e.clone();
        tampered.skeleton.epoch = 999;
        assert!(tampered.verify(&r.public_key()).is_err());
    }

    #[test]
    fn wire_round_trip_with_and_without_payload() {
        let r = root(7, 8);
        let sk = skeleton_for(&r, 2, b"body");
        let e = Entry::build_signed(&r, sk, b"body".to_vec()).unwrap();
        let decoded = Entry::from_wire(&e.to_wire()).unwrap();
        assert_eq!(decoded.skeleton, e.skeleton);
        assert_eq!(decoded.payload.as_deref(), Some(&b"body"[..]));
        assert!(decoded.verify(&r.public_key()).is_ok());

        // Skeleton-only frames and still verifies (pruned payload).
        let mut pruned = decoded;
        assert!(pruned.prune_payload());
        let reparsed = Entry::from_wire(&pruned.to_wire()).unwrap();
        assert!(reparsed.payload.is_none());
        assert!(reparsed.verify(&r.public_key()).is_ok());
    }

    #[test]
    fn payload_hash_binding_survives_pruning() {
        // The signature commits to payload_hash, so the skeleton verifies whether
        // or not the body is retained (ADR-008 payload-hash signing).
        let r = root(9, 10);
        let sk = skeleton_for(&r, 1, b"the-body");
        let mut e = Entry::build_signed(&r, sk, b"the-body".to_vec()).unwrap();
        let with = e.entry_hash();
        e.prune_payload();
        let without = e.entry_hash();
        // Pruning the body does not change the entry's identity (hash over body).
        assert_eq!(with, without);
        assert!(e.verify(&r.public_key()).is_ok());
    }

    #[test]
    fn build_rejects_mismatched_payload() {
        let r = root(1, 1);
        let sk = skeleton_for(&r, 1, b"declared");
        // Pass a different body than the one the hash commits to.
        assert!(matches!(
            Entry::build_signed(&r, sk, b"actual".to_vec()),
            Err(Error::MalformedBundle(_))
        ));
    }

    #[test]
    fn build_rejects_wrong_signer() {
        let r = root(1, 2);
        let other = root(3, 4);
        let sk = skeleton_for(&r, 1, b"x"); // author_id = r's fingerprint
        assert!(matches!(
            Entry::build_signed_skeleton_only(&other, sk),
            Err(Error::MalformedBundle(_))
        ));
    }

    #[test]
    fn from_wire_rejects_tampered_payload() {
        let r = root(2, 3);
        let sk = skeleton_for(&r, 1, b"orig");
        let e = Entry::build_signed(&r, sk, b"orig".to_vec()).unwrap();
        let mut wire = e.to_wire();
        // Flip the last payload byte; the committed hash no longer matches.
        *wire.last_mut().unwrap() ^= 0xff;
        assert!(matches!(
            Entry::from_wire(&wire),
            Err(Error::MalformedBundle(_)) | Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn from_wire_rejects_wrong_tag() {
        let r = root(1, 2);
        let sk = skeleton_for(&r, 1, b"x");
        let e = Entry::build_signed(&r, sk, b"x".to_vec()).unwrap();
        let reframed = crate::wire::frame(StructTag::Skdm, &e.to_wire()[3..]);
        assert!(matches!(
            Entry::from_wire(&reframed),
            Err(Error::MalformedBundle("log-entry wrong struct tag"))
        ));
    }

    // ---- deniable authenticator wire seam (M7/ADR-009 crypto deferred) ----

    #[test]
    fn deniable_entry_round_trips_and_is_non_attributable() {
        let r = root(2, 4);
        let sk = skeleton_for(&r, 1, b"deniable-body");
        // M7 would produce these bytes; M5 carries them opaquely.
        let auth = vec![0xDEu8; 96];
        let e =
            Entry::with_deniable_authenticator(sk, auth.clone(), Some(b"deniable-body".to_vec()))
                .unwrap();
        assert!(!e.authenticator.is_attributable());

        let decoded = Entry::from_wire(&e.to_wire()).unwrap();
        assert!(!decoded.authenticator.is_attributable());
        match &decoded.authenticator {
            Authenticator::Deniable(b) => assert_eq!(b, &auth),
            other => panic!("expected deniable, got {other:?}"),
        }
        assert_eq!(decoded.skeleton, e.skeleton);
        assert_eq!(decoded.payload.as_deref(), Some(&b"deniable-body"[..]));
    }

    #[test]
    fn deniable_verify_returns_boundary_error_without_m7() {
        let r = root(5, 7);
        let sk = skeleton_for(&r, 1, b"x");
        let e =
            Entry::with_deniable_authenticator(sk, vec![0x01; 64], Some(b"x".to_vec())).unwrap();
        // M5 has no deniable verifier: an honest boundary error, not a fake pass.
        assert!(matches!(
            e.verify(&r.public_key()),
            Err(Error::DeniableVerificationUnavailable)
        ));
    }

    #[test]
    fn deniable_verify_uses_supplied_m7_verifier() {
        // A stand-in M7 verifier that accepts iff the bytes start with 0xAA.
        struct StubM7;
        impl DeniableVerifier for StubM7 {
            fn verify_deniable(&self, _: &Digest32, _: &[u8], auth: &[u8]) -> Result<()> {
                if auth.first() == Some(&0xAA) {
                    Ok(())
                } else {
                    Err(Error::SignatureInvalid)
                }
            }
        }
        let r = root(6, 8);
        let sk = skeleton_for(&r, 1, b"x");
        let good =
            Entry::with_deniable_authenticator(sk.clone(), vec![0xAA, 0x01], Some(b"x".to_vec()))
                .unwrap();
        assert!(good
            .verify_with_deniable(&r.public_key(), Some(&StubM7))
            .is_ok());
        let bad =
            Entry::with_deniable_authenticator(sk, vec![0x00, 0x01], Some(b"x".to_vec())).unwrap();
        assert!(bad
            .verify_with_deniable(&r.public_key(), Some(&StubM7))
            .is_err());
    }

    #[test]
    fn from_wire_rejects_unknown_authenticator_type() {
        let r = root(1, 9);
        let sk = skeleton_for(&r, 1, b"x");
        let e = Entry::build_signed(&r, sk, b"x".to_vec()).unwrap();
        // Re-encode with an out-of-range auth_type (3). Rebuild the wire array by
        // hand from the parsed fields is complex; instead corrupt the auth_type
        // byte: locate it is fiddly, so assert via a constructed malformed body.
        let mut wire = e.to_wire();
        // The auth_type uint sits right before the composite-sig byte string
        // (0x59 0x0d 0x2d length prefix for 3373 bytes). Find that prefix and set
        // the preceding uint (a single byte 0x01) to 0x03.
        // 3373 = 0x0D2D -> header 0x59 0x0D 0x2D.
        if let Some(pos) = wire.windows(3).position(|w| w == [0x59, 0x0D, 0x2D]) {
            assert!(pos >= 1);
            wire[pos - 1] = 0x03; // auth_type = 3 (unknown)
            assert!(matches!(
                Entry::from_wire(&wire),
                Err(Error::MalformedBundle(
                    "log-entry unknown authenticator type"
                ))
            ));
        } else {
            panic!("could not locate composite signature length prefix");
        }
    }

    #[test]
    fn from_wire_rejects_oversized_payload_before_alloc() {
        // A hand-built entry frame whose payload byte-string declares more bytes
        // than MAX_PAYLOAD_LEN must be rejected with SizeLimitExceeded, not copied.
        // We build a minimal valid prefix then a hostile payload length header.
        let r = root(3, 3);
        let sk = skeleton_for(&r, 1, b"");
        let e = Entry::build_signed(&r, sk, Vec::new()).unwrap();
        // Start from a real (payload-bearing) wire and rewrite the payload length.
        // Easiest robust check: a synthetic frame with payload_len far over limit.
        // Build the 14-element body up to the payload, then a 0x5A (4-byte len)
        // header claiming 2^31 bytes.
        let mut body = {
            use crate::cbor::Encoder;
            let mut enc = Encoder::new();
            let skb = e.skeleton.clone();
            enc.array(14)
                .bytes(&skb.author_id)
                .uint(skb.seq)
                .bytes(&skb.prev_hash)
                .bytes(&skb.lipmaa_backlink)
                .bytes(&skb.channel_id)
                .uint(skb.epoch)
                .array(2)
                .uint(u64::from(skb.algo_ids[0]))
                .uint(u64::from(skb.algo_ids[1]));
            enc.bytes(&skb.payload_hash)
                .uint(u64::from(u32::MAX)) // payload_len declared huge
                .uint(0)
                .uint(1) // auth_type composite
                .bytes(&e.authenticator.to_bytes())
                .uint(1); // payload present
            enc.finish()
        };
        // Append a CBOR byte-string header claiming u32::MAX bytes (no data).
        body.push(0x5A);
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        let wire = crate::wire::frame(StructTag::LogEntry, &body);
        assert!(matches!(
            Entry::from_wire(&wire),
            Err(Error::SizeLimitExceeded("log-entry payload")) | Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn from_wire_rejects_payload_len_mismatch() {
        // A hostile wire that declares a small `payload_len` but carries a LARGER
        // actual byte string must be rejected (the signature commits to
        // `payload_len`, so the actual length must equal it). This is the
        // small-declared / large-actual attack — caught before the binding check
        // would otherwise pass a tampered body. Kept tiny to bound RSS.
        let r = root(4, 4);
        let real = b"the-real-body";
        let sk = skeleton_for(&r, 1, real);
        let e = Entry::build_signed(&r, sk, real.to_vec()).unwrap();
        // Rebuild the wire with the SAME signed skeleton (payload_len = 13) but an
        // actual payload byte string of a DIFFERENT length.
        let body = {
            use crate::cbor::Encoder;
            let skb = e.skeleton.clone();
            let mut enc = Encoder::new();
            enc.array(14)
                .bytes(&skb.author_id)
                .uint(skb.seq)
                .bytes(&skb.prev_hash)
                .bytes(&skb.lipmaa_backlink)
                .bytes(&skb.channel_id)
                .uint(skb.epoch)
                .array(2)
                .uint(u64::from(skb.algo_ids[0]))
                .uint(u64::from(skb.algo_ids[1]));
            enc.bytes(&skb.payload_hash)
                .uint(skb.payload_len) // signed payload_len = 13
                .uint(u64::from(skb.end_of_feed))
                .uint(1) // composite
                .bytes(&e.authenticator.to_bytes())
                .uint(1) // payload present
                .bytes(b"a-longer-actual-payload-than-declared"); // len != 13
            enc.finish()
        };
        let wire = crate::wire::frame(StructTag::LogEntry, &body);
        assert!(matches!(
            Entry::from_wire(&wire),
            Err(Error::MalformedBundle(
                "log-entry payload length != signed payload_len"
            ))
        ));
    }
}
