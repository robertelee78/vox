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
//!    payload_hash, payload_len, end_of_feed_flag, claimed_ms, seen }`, a 12-element
//! canonical-CBOR array (ADR-008 §"Canonical serialization"). `seq` is the per-author sequence,
//! strictly monotonic from 1. `prev_hash` is the SHA-256 of the seq−1 entry's
//! canonical bytes; `lipmaa_backlink` is the SHA-256 of the entry at the Bamboo
//! `lipmaa(seq)` predecessor ([`crate::log::feed`]). The genesis entry (seq 1)
//! carries all-zero `prev_hash` and `lipmaa_backlink` — there is no predecessor.
//!
//! `claimed_ms` and `seen` are the room's one order (ADR-023 decision 1, PRD-001 R13).
//! `seen` names the heads of **other** authors' feeds the author had applied when it
//! wrote the entry, so the log is a causal DAG across authors rather than parallel
//! chains; `claimed_ms` is the author's clock, which only breaks ties between entries
//! that did not see each other ([`crate::log::dag`]). Both sit in the signed skeleton,
//! not in the encrypted payload, because the order must be computable by a node that
//! cannot read an entry: a node without an author's key, or holding a pruned skeleton,
//! still has to place that entry, or every entry after it lands somewhere else than it
//! does on a node that can read it.
//!
//! ## Authenticator (per entry TYPE, ADR-008 §"Per-entry-type authentication")
//! The authenticator is computed over `vox/log-entry/v1 ‖ canonical_body`
//! ([`crate::wire::signing_input`]). Governance/control entries are **always**
//! composite Ed25519+ML-DSA root-signed; message-content entries are
//! composite-signed too: every entry is attributable. The entry wire carries an
//! **authenticator-type discriminant**, and composite (`1`) is the only value accepted.
//! Type `2` was the ADR-009 deniable authenticator; deniable rooms were removed
//! (PRD-001 R43), so an entry carrying it is refused like any unknown type. Because the
//! authenticator commits to `payload_hash`, the skeleton verifies whether or not the
//! payload is retained.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32, COMPOSITE_SIG_LEN, DIGEST_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::suite::{algo, validate_algo};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// A 32-byte all-zero hash, used for the genesis entry's `prev_hash` and
/// `lipmaa_backlink` (there is no predecessor to hash).
pub const ZERO_HASH: Digest32 = [0u8; DIGEST_LEN];

/// Hard upper bound on an authenticator's serialized length (bytes), enforced
/// **before** allocation so a hostile frame with a huge declared length cannot force a
/// large copy (ADR-008 anti-abuse). The composite signature is fixed-length
/// ([`COMPOSITE_SIG_LEN`]); this bound is checked before the length is compared.
pub const MAX_AUTHENTICATOR_LEN: usize = 8 * 1024;

/// Hard upper bound on a retained payload body (bytes) accepted from a single
/// framed entry, enforced **before** `to_vec`. This is a per-*entry* structural
/// ceiling so a hostile frame cannot force an allocation larger than any real entry
/// before the entry is even parsed (ADR-008 anti-abuse). It bounds one entry, never
/// how many an author may write: a room's history has no size limit (PRD-001 R1).
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// At most this many hashes in an entry's `seen` (ADR-023 decision 1). Enforced at
/// decode, before the hashes are read, and by the author when it picks them.
pub const MAX_SEEN: usize = 16;

/// The number of elements in the canonical skeleton array.
const SKELETON_ARITY: usize = 12;

/// Wire discriminant for [`Authenticator::Composite`] (attributable).
const AUTH_TYPE_COMPOSITE: u64 = 1;

/// Wire discriminant for [`Authenticator::Dropped`]: no signature bytes follow (an empty
/// byte string). `0`, not the removed deniable type `2`, which stays refused.
const AUTH_TYPE_DROPPED: u64 = 0;

/// The kind of entry, which fixes how it is authenticated (ADR-008
/// §"Per-entry-type authentication"). Authentication is chosen by entry TYPE,
/// not merely by channel mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind {
    /// Governance/control: genesis, admin delegations, consent grants/revocations,
    /// policy/passphrase-rotation. **Always**
    /// root-composite-signed, in every channel (ADR-008). Two validly-signed
    /// conflicting governance entries are a self-authenticating fork proof.
    Governance,
    /// Message content, root-composite-signed like governance.
    Content,
    /// An author's checkpoint on its own feed (ADR-023 decision 3,
    /// [`crate::log::checkpoint`]). Control, not governance: it grants nothing, so it never
    /// reaches the ADR-007 evaluator, and like governance it is never pruned.
    Checkpoint,
}

/// The authenticator over an entry's signing input.
///
/// An enum rather than a bare [`CompositeSignature`] because the wire carries a type
/// discriminant; composite is the only type there is.
#[derive(Clone)]
#[non_exhaustive]
pub enum Authenticator {
    /// A composite Ed25519+ML-DSA-65 root signature (ADR-002). Attributable: it
    /// genuinely incriminates the author on a fork. Boxed because the composite
    /// signature is multi-kilobyte.
    Composite(Box<CompositeSignature>),
    /// The signature was **dropped under a checkpoint** (ADR-023 decision 3): the entry's
    /// body expired, and its author's own signed checkpoint names a position at or above it.
    /// Such an entry is authentic only through the hash chain — its hash is the `prev_hash`
    /// (or checkpoint hash) of a signed entry above it — so it never verifies on its own
    /// ([`Entry::verify`] refuses it) and the DAG accepts it only as a chain-authenticated
    /// skeleton ([`crate::log::dag::Dag::accept`]).
    Dropped,
}

impl Authenticator {
    /// The wire type discriminant for this authenticator.
    fn type_id(&self) -> u64 {
        match self {
            Authenticator::Composite(_) => AUTH_TYPE_COMPOSITE,
            Authenticator::Dropped => AUTH_TYPE_DROPPED,
        }
    }

    /// The serialized bytes of this authenticator: the composite signature's
    /// fixed-length encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Authenticator::Composite(sig) => sig.to_bytes().to_vec(),
            Authenticator::Dropped => Vec::new(),
        }
    }
}

impl core::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Authenticator::Composite(_) => f.write_str("Authenticator::Composite(..)"),
            Authenticator::Dropped => f.write_str("Authenticator::Dropped"),
        }
    }
}

/// The unsigned entry skeleton — every field except the authenticator.
///
/// Held separately so [`EntrySkeleton::signing_input`] is the exact bytes the
/// author signs and a verifier checks. The 12 fields are in the ADR-008 order.
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
    /// The author's clock when it wrote the entry, **milliseconds** since the Unix
    /// epoch. Only a tie-break between entries that did not see each other: it can
    /// never place an entry ahead of anything in its `seen` or its own feed
    /// ([`crate::log::dag`]). The same value the content envelope carries.
    pub claimed_ms: u64,
    /// The heads of other authors' feeds the author had applied when it wrote this
    /// entry, at most [`MAX_SEEN`], strictly ascending (canonical: no duplicates, one
    /// encoding). May name entries a receiving node does not hold yet; that never
    /// blocks acceptance (ADR-023 decision 1).
    pub seen: Vec<Digest32>,
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
            .field("claimed_ms", &self.claimed_ms)
            .field("seen", &self.seen.len())
            .finish_non_exhaustive()
    }
}

impl EntrySkeleton {
    /// Canonical-CBOR body in the ADR-008 field order: a 12-element array
    /// `[author_id, seq, prev_hash, lipmaa_backlink, channelID, epoch,
    ///   [sign_algo, aead_algo], payload_hash, payload_len, end_of_feed_flag,
    ///   claimed_ms, [seen…]]`.
    /// `end_of_feed_flag` is a CBOR unsigned integer 0/1 (the codec has no bool;
    /// 0 and 1 are the canonical shortest forms).
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(SKELETON_ARITY);
        self.encode_fields(&mut e);
        e.finish()
    }

    /// The 12 skeleton fields, in order, into `e`. The one encoder of them: the
    /// canonical body (what is signed and hashed) and the wire frame (which inlines the
    /// same fields ahead of the authenticator) both call it, so the two can never
    /// disagree about a field — which would fail three layers away as "record
    /// rejected", not here.
    fn encode_fields(&self, e: &mut Encoder) {
        e.bytes(&self.author_id)
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
            .uint(u64::from(self.end_of_feed))
            .uint(self.claimed_ms)
            .array(self.seen.len());
        for h in &self.seen {
            e.bytes(h);
        }
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

    /// Decode the 12 skeleton fields from `d`, validating digest lengths, the
    /// algo-id registry membership and classes, the end-of-feed flag domain (0 or 1
    /// only), and `seen` (at most [`MAX_SEEN`], strictly ascending). The one decoder of
    /// them, for the same reason [`Self::encode_fields`] is the one encoder.
    fn decode_fields(d: &mut Decoder<'_>) -> Result<Self> {
        let author_id = take_digest(d)?;
        let seq = d.uint()?;
        // Bound seq so the lipmaa power-of-three arithmetic stays overflow-free
        // (ADR-008; see `crate::log::feed::MAX_SEQ`).
        if seq > crate::log::feed::MAX_SEQ {
            return Err(Error::SizeLimitExceeded("log-entry seq exceeds MAX_SEQ"));
        }
        let prev_hash = take_digest(d)?;
        let lipmaa_backlink = take_digest(d)?;
        let channel_id = take_digest(d)?;
        let epoch = d.uint()?;
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("log-entry algo_ids arity"));
        }
        let sign_algo = u16_from(d.uint()?)?;
        let aead_algo = u16_from(d.uint()?)?;
        let payload_hash = take_digest(d)?;
        let payload_len = d.uint()?;
        let end_of_feed = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedBundle("log-entry end_of_feed flag")),
        };
        let claimed_ms = d.uint()?;
        // The count is checked before anything is read or allocated.
        let n = d.array()?;
        if n > MAX_SEEN {
            return Err(Error::SizeLimitExceeded("log-entry seen"));
        }
        let mut seen: Vec<Digest32> = Vec::with_capacity(n);
        for _ in 0..n {
            let h = take_digest(d)?;
            // Strictly ascending: one encoding per set, so two honest authors listing
            // the same heads sign the same bytes, and a duplicate cannot pad the list.
            if seen.last().is_some_and(|last| *last >= h) {
                return Err(Error::MalformedBundle("log-entry seen not canonical"));
            }
            seen.push(h);
        }

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
            claimed_ms,
            seen,
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
    pub fn verify(&self, author_root: &CompositePublicKey) -> Result<()> {
        if author_root.fingerprint() != self.skeleton.author_id {
            return Err(Error::MalformedBundle(
                "log-entry author_id != root fingerprint",
            ));
        }
        match &self.authenticator {
            Authenticator::Composite(sig) => {
                author_root.verify(&self.skeleton.signing_input(), sig)?;
            }
            Authenticator::Dropped => {
                return Err(Error::MalformedBundle(
                    "log-entry signature was dropped under a checkpoint",
                ));
            }
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

    /// Whether the entry still carries its signature (it was not dropped under a checkpoint).
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !matches!(self.authenticator, Authenticator::Dropped)
    }

    /// Drop the signature (ADR-023 decision 3), keeping the skeleton — and so the entry's
    /// hash and its links. Only a caller holding the author's checkpoint above it may: after
    /// this the entry is authentic only through the hash chain. Returns whether a signature
    /// was actually dropped.
    pub fn drop_signature(&mut self) -> bool {
        let had = self.is_signed();
        self.authenticator = Authenticator::Dropped;
        had
    }

    /// The entry's hash (over the canonical body) — its DAG/Negentropy key.
    #[must_use]
    pub fn entry_hash(&self) -> Digest32 {
        self.skeleton.entry_hash()
    }

    /// Frame the entry for the wire/storage per ADR-008: `tag(2 BE) ‖
    /// version(1) ‖ canonical_cbor_body`. The body is a flat CBOR array — the 12
    /// skeleton fields, then `auth_type` (1 = composite; 2 was the removed deniable type),
    /// `authenticator_bytes`, `payload_present` (0/1), and the payload byte string
    /// iff present. The skeleton fields are inlined (not a nested array) so the
    /// strict decoder reads them directly; a pruned entry omits the body but still
    /// carries the verifiable skeleton + typed authenticator.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let auth = self.authenticator.to_bytes();
        let has_payload = self.payload.is_some();
        // 12 skeleton fields (algo_ids and seen each count as one element) +
        // auth_type + authenticator + payload_present (+ payload).
        let arity = if has_payload {
            SKELETON_ARITY + 4
        } else {
            SKELETON_ARITY + 3
        };
        let mut e = Encoder::new();
        e.array(arity);
        self.skeleton.encode_fields(&mut e);
        e.uint(self.authenticator.type_id())
            .bytes(&auth)
            .uint(u64::from(has_payload));
        if let Some(p) = &self.payload {
            e.bytes(p);
        }
        frame(StructTag::LogEntry, &e.finish())
    }

    /// Parse a framed entry from the wire/storage. Rejects a wrong/unknown
    /// struct tag, unsupported version, arity, an unknown authenticator type, an
    /// over-limit authenticator/payload/`seen` length (rejected **before** allocation —
    /// ADR-008 anti-abuse), or a malformed skeleton/authenticator/payload. Does
    /// NOT verify the signature — call [`Entry::verify`]. A retained payload, if
    /// present, is checked against the committed hash/len so a tampered body is
    /// rejected at parse.
    ///
    /// The skeleton fields go through the same strict decoder as the canonical body
    /// (which enforces the algo classes and `seen`'s canonical form), so the
    /// re-encoded signing input is byte-identical to the author's — the precondition
    /// for signature verification.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::LogEntry {
            return Err(Error::MalformedBundle("log-entry wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        let arity = d.array()?;
        if arity != SKELETON_ARITY + 3 && arity != SKELETON_ARITY + 4 {
            return Err(Error::MalformedBundle("log-entry wire arity"));
        }
        let skeleton = EntrySkeleton::decode_fields(&mut d)?;
        let auth_type = d.uint()?;
        let authenticator = decode_authenticator(&mut d, auth_type)?;
        let present = d.uint()?;
        let payload = match (present, arity == SKELETON_ARITY + 4) {
            (1, true) => {
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
                if slice.len() as u64 != skeleton.payload_len {
                    return Err(Error::MalformedBundle(
                        "log-entry payload length != signed payload_len",
                    ));
                }
                Some(slice.to_vec())
            }
            (0, false) => None,
            _ => {
                return Err(Error::MalformedBundle(
                    "log-entry payload presence mismatch",
                ))
            }
        };
        d.finish()?;

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
        AUTH_TYPE_DROPPED if auth_bytes.is_empty() => Ok(Authenticator::Dropped),
        _ => Err(Error::MalformedBundle(
            "log-entry unknown authenticator type",
        )),
    }
}

fn u16_from(v: u64) -> Result<u16> {
    u16::try_from(v).map_err(|_| Error::MalformedBundle("log-entry algo id out of range"))
}
