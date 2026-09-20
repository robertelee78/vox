//! The identity's **prekey ring** at rest (ADR-016 M14.3; ADR-002 §2 key-agreement
//! keys; ADR-010 at-rest layers).
//!
//! M13's node could sign, seal and append, but it held **no key-agreement keys**:
//! nothing to publish in a [`PrekeyBundlePublic`] and nothing to answer an inbound
//! PQXDH handshake with. This module is that missing state, persisted so it
//! survives a restart:
//!
//! - the long-term **X25519 identity DH key** (`IK_B`),
//! - the **current signed prekey** and the **previous** one (ADR-002: rotated every
//!   7 days, the previous retained one cadence so sessions in flight still open),
//! - the **one-time prekey pool**, refilled when it drops below its low-water mark
//!   and consumed once per inbound session, never reused.
//!
//! ## Where identity-level key material lives at rest (new ground for ADR-010)
//! ADR-010 defines two homes: the per-channel SEK store (per-channel material) and
//! the identity domain — the passphrase-sealed vault — for the root. Prekeys are
//! neither: they are **identity-level**, shared by every channel, and they rotate
//! automatically while the app runs.
//!
//! - The vault is the wrong home: re-sealing it needs the identity passphrase,
//!   which is deliberately never retained (ADR-015), so automatic rotation would
//!   have to re-prompt.
//! - A per-channel SEK is the wrong home: prekeys are not channel-scoped, so
//!   binding them to one channel's passphrase would make them unavailable exactly
//!   when that channel is closed.
//!
//! So the ring is a [`SegmentKind::PrekeyRing`] segment in the profile store,
//! sealed under a key derived from the **identity factor alone**:
//!
//! ```text
//! ring_channel = SHA-256("vox/prekey-ring-pseudo-channel/v1")   // reserved, not a real channelID
//! factor_id    = HKDF-SHA-256(id_proof(ring_channel), info = "vox/sek-id/v1")   // ADR-010
//! ring_key     = HKDF-SHA-256(factor_id,              info = "vox/prekey-ring-sek/v1")
//! ```
//!
//! This is **single-factor by design**, and it is not a weakening: the identity
//! factor requires the unlocked identity domain, which requires the identity
//! passphrase, so the ring is gated by exactly the same secret as the root it
//! belongs to — and, like every SEK, it is derived without ever reading raw
//! private-key bytes (it works with a delegated `gpg-agent`/Enclave signer). It is
//! also non-circular for the same reason per-channel SEKs are: the identity domain
//! unlocks first. A second, extra HKDF step keeps `ring_key` domain-separated from
//! anything else that consumes `factor_id`.
//!
//! ## Consuming a one-time prekey (ADR-002 one-shot + ADR-004 serverless semantics)
//! [`PrekeyRing::use_one_time`] moves the prekey out of the pool into a bounded
//! **consumed set**, so it is never advertised or issued again (ADR-002 "consumed
//! once per inbound session and never reused"), and reports which case it was:
//!
//! - [`OneTimeUse::Fresh`] — first use.
//! - [`OneTimeUse::Reused`] — a *concurrent duplicate*. ADR-004 §"Prekey
//!   publication" is explicit that with no atomic server arbiter two initiators may
//!   consume the same one-time prekey, and that the second session must still
//!   establish while being **treated as last-resort-grade**. That is only possible
//!   if the responder can still complete the handshake, which needs the consumed
//!   secret — so it is retained for [`ONE_TIME_CONSUMED_RETAIN_SECS`] (and at most
//!   [`ONE_TIME_CONSUMED_MAX`] entries) and served from the consumed set, flagged.
//!   The ring is the **persistent** record of consumption;
//!   [`crate::pairwise::OtpReuseTracker`] is the per-process one that
//!   `Session::accept` turns into the `is_last_resort_grade` flag. M14.5 must derive
//!   that flag from this verdict (or seed the tracker from the retained set), or a
//!   restart would silently lose the downgrade — recorded in ADR-004.
//! - [`OneTimeUse::Unknown`] — never issued by this ring, or retained no longer.
//!   The handshake cannot be completed and the initiator must refetch a bundle.
//!   ADR-004 specifies only the *concurrent* case, so bounding retention to genuine
//!   concurrency is a deliberate refinement of it: retaining for the full bundle
//!   TTL (7 days) would extend the documented forward-secrecy residual by a week to
//!   serve a stale-bundle initiator that can simply refetch.
//!
//! The prekey material stays owned by the ring ([`PrekeyRing::consumed_one_time`]
//! hands out a borrow), the ring is deliberately not `Clone` so no consumed secret
//! survives in a copy, and [`save`] **must** be called after a consume: until it
//! is, a crash would re-offer the prekey on the next start (a test pins this).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::atrest::idfactor::{IdentityFactor, SignatureIdentityFactor, FACTOR_ID_LEN};
use crate::atrest::sek::{Sek, SEK_LEN};
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::identity::keyagreement::{
    OneTimePrekey, OneTimePrekeyPool, OneTimePrekeyPublic, PrekeyBundlePublic, SignedIdentityDhKey,
    SignedPrekey, SignedPrekeyPublic, X25519IdentityKey, X25519IdentityKeyPublic,
};
use crate::node::store::Store;

/// Domain label whose digest is the reserved pseudo-channel the ring is filed and
/// key-derived under. It is not a real channelID (no genesis hashes to it).
pub const PREKEY_RING_CHANNEL_DOMAIN: &str = "vox/prekey-ring-pseudo-channel/v1";

/// HKDF `info` separating the ring key from every other `factor_id` consumer.
pub const PREKEY_RING_SEK_INFO: &[u8] = b"vox/prekey-ring-sek/v1";

/// The ring's segment id within its pseudo-channel (one segment, latest-wins).
pub const SEG_PREKEY_RING: u64 = 1;

/// At-rest encoding version of the ring.
const RING_VERSION: u64 = 1;

/// Signed-prekey rotation cadence (ADR-002 §2: "every 7 days").
pub const SIGNED_PREKEY_CADENCE_SECS: u64 = 7 * 24 * 60 * 60;

/// One-time prekey pool target size (refilled up to this).
pub const ONE_TIME_PREKEY_TARGET: usize = 64;

/// One-time prekey low-water mark: at or below this, the pool is refilled to
/// [`ONE_TIME_PREKEY_TARGET`] (ADR-002 §2 "refilled whenever it drops below a
/// low-water mark").
pub const ONE_TIME_PREKEY_LOW_WATER: usize = 16;

/// How long a **consumed** one-time prekey is retained so a concurrent duplicate
/// use can still establish (ADR-004 §"Serverless consume semantics"). One hour
/// covers a genuine race; see the module docs for why it is not the bundle TTL.
pub const ONE_TIME_CONSUMED_RETAIN_SECS: u64 = 60 * 60;

/// Hard cap on retained consumed one-time prekeys (oldest dropped first), so a
/// drain attack cannot grow the ring without bound.
pub const ONE_TIME_CONSUMED_MAX: usize = 256;

/// The reserved pseudo-channel the ring is filed and key-derived under.
#[must_use]
pub fn ring_channel() -> Digest32 {
    sha256(PREKEY_RING_CHANNEL_DOMAIN.as_bytes())
}

/// Derive the ring's sealing key from the identity factor (see the module docs).
fn ring_sek(signer: &dyn RootSigner) -> Result<Sek> {
    let factor = SignatureIdentityFactor::new(signer);
    let channel = ring_channel();
    let factor_id: Zeroizing<[u8; FACTOR_ID_LEN]> = factor.factor_id(&channel)?;
    let hk = Hkdf::<Sha256>::new(None, factor_id.as_ref());
    let mut key = Zeroizing::new([0u8; SEK_LEN]);
    hk.expand(PREKEY_RING_SEK_INFO, key.as_mut())
        .map_err(|_| Error::Argon2Failed)?;
    Ok(Sek::from_bytes(key))
}

/// What [`PrekeyRing::maintain`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Maintenance {
    /// The signed prekey was rotated (the old one became `previous`).
    pub rotated: bool,
    /// How many one-time prekeys were added.
    pub one_time_added: usize,
    /// How many consumed one-time prekeys were dropped (retention elapsed or the
    /// cap was exceeded) — their secrets are gone, restoring forward secrecy.
    pub consumed_pruned: usize,
}

impl Maintenance {
    /// Whether anything changed (so the caller knows it must [`save`]).
    #[must_use]
    pub fn changed(self) -> bool {
        self.rotated || self.one_time_added > 0 || self.consumed_pruned > 0
    }
}

/// The outcome of [`PrekeyRing::use_one_time`] (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneTimeUse {
    /// First use: the prekey moved from the pool into the consumed set.
    Fresh,
    /// A concurrent duplicate use: served from the consumed set. The session may
    /// establish but is **last-resort-grade** (ADR-004).
    Reused,
    /// Never issued by this ring, or retained no longer. The handshake cannot be
    /// completed; the initiator must refetch a bundle.
    Unknown,
}

/// A consumed one-time prekey, retained so a concurrent duplicate can still be
/// served (ADR-004). Its secrets zeroize on drop with the prekey.
struct ConsumedOneTime {
    prekey: OneTimePrekey,
    consumed_at: u64,
}

/// The identity's key-agreement keys. Not `Clone` (see the module docs); every
/// component zeroizes its secrets on drop.
pub struct PrekeyRing {
    identity_dh: SignedIdentityDhKey,
    current: SignedPrekey,
    previous: Option<SignedPrekey>,
    next_signed_prekey_id: u64,
    pool: OneTimePrekeyPool,
    /// Recently consumed one-time prekeys, oldest first.
    consumed: Vec<ConsumedOneTime>,
}

impl std::fmt::Debug for PrekeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrekeyRing")
            .field("signed_prekey_id", &self.current.public().prekey_id)
            .field(
                "previous_signed_prekey_id",
                &self.previous.as_ref().map(|p| p.public().prekey_id),
            )
            .field("one_time_prekeys", &self.pool.len())
            .field("consumed_retained", &self.consumed.len())
            .finish_non_exhaustive()
    }
}

impl PrekeyRing {
    /// Generate a fresh ring: the **identity's** DH key, a first signed prekey
    /// (id 1) and a full one-time pool ([`ONE_TIME_PREKEY_TARGET`]), all root-signed.
    ///
    /// `identity_dh_secret` is the X25519 identity DH scalar from the identity itself
    /// (the vault's `x25519_identity_secret`, part of the ADR-002 backup) — **not** a
    /// freshly generated one. The identity DH key is an identity-level artifact: an
    /// identity restored from its backup must advertise the *same* one, or every
    /// bundle published before the restore would name a key the identity no longer
    /// holds.
    pub fn generate(
        signer: &dyn RootSigner,
        identity_dh_secret: &[u8; 32],
        now_secs: u64,
    ) -> Result<Self> {
        Self::generate_sized(signer, identity_dh_secret, now_secs, ONE_TIME_PREKEY_TARGET)
    }

    /// [`PrekeyRing::generate`] with an explicit initial pool size. Private: the
    /// production size is the constant, and tests use a small pool so the debug
    /// suite does not pay for 64 ML-KEM keygens plus composite signatures per ring
    /// (one test still exercises the real size).
    fn generate_sized(
        signer: &dyn RootSigner,
        identity_dh_secret: &[u8; 32],
        now_secs: u64,
        one_time: usize,
    ) -> Result<Self> {
        let identity_dh = SignedIdentityDhKey::from_key(
            signer,
            X25519IdentityKey::from_secret_bytes(*identity_dh_secret),
            now_secs,
        )?;
        let current = SignedPrekey::generate(signer, 1, now_secs)?;
        let pool = OneTimePrekeyPool::generate(signer, one_time, 1, now_secs)?;
        Ok(Self {
            identity_dh,
            current,
            previous: None,
            next_signed_prekey_id: 2,
            pool,
            consumed: Vec::new(),
        })
    }

    /// The publishable bundle (ADR-004 §Prekey publication): the identity DH key,
    /// the current signed prekey, and the next one-time prekey if the pool is
    /// non-empty (depletion falls back to the signed prekey, never to no prekey).
    pub fn bundle(&self, root: &CompositePublicKey) -> Result<PrekeyBundlePublic> {
        let otp = self.pool.first();
        let bundle = PrekeyBundlePublic {
            root_pub: root.to_bytes(),
            identity_dh_key: self.identity_dh.public().clone(),
            identity_dh_key_sig: self.identity_dh.signature().to_bytes(),
            signed_prekey: self.current.public().clone(),
            signed_prekey_sig: self.current.signature().to_bytes(),
            one_time_prekey: otp.map(|o| o.public().clone()),
            one_time_prekey_sig: otp.map(|o| o.signature().to_bytes()),
        };
        Ok(bundle)
    }

    /// The identity DH key (`IK_B`) for the PQXDH responder.
    #[must_use]
    pub fn identity_dh(&self) -> &X25519IdentityKey {
        self.identity_dh.key()
    }

    /// The signed prekey an initial message targeted: the current one, or the
    /// retained previous one (a session started just before a rotation).
    #[must_use]
    pub fn signed_prekey_for(&self, prekey_id: u64) -> Option<&SignedPrekey> {
        if self.current.public().prekey_id == prekey_id {
            return Some(&self.current);
        }
        self.previous
            .as_ref()
            .filter(|p| p.public().prekey_id == prekey_id)
    }

    /// The current signed prekey's id.
    #[must_use]
    pub fn signed_prekey_id(&self) -> u64 {
        self.current.public().prekey_id
    }

    /// **Consume** the one-time prekey an initial message used (see the module
    /// docs for the three outcomes). On [`OneTimeUse::Fresh`] or
    /// [`OneTimeUse::Reused`] the material is available from
    /// [`PrekeyRing::consumed_one_time`]; the caller must [`save`] the ring.
    pub fn use_one_time(&mut self, prekey_id: u64, now_secs: u64) -> OneTimeUse {
        if let Some(prekey) = self.pool.take_by_id(prekey_id) {
            self.consumed.push(ConsumedOneTime {
                prekey,
                consumed_at: now_secs,
            });
            self.enforce_consumed_cap();
            return OneTimeUse::Fresh;
        }
        if self.consumed_one_time(prekey_id).is_some() {
            return OneTimeUse::Reused;
        }
        OneTimeUse::Unknown
    }

    /// The material for a consumed one-time prekey still inside its retention
    /// window (ADR-004), for the PQXDH responder.
    #[must_use]
    pub fn consumed_one_time(&self, prekey_id: u64) -> Option<&OneTimePrekey> {
        self.consumed
            .iter()
            .find(|c| c.prekey.public().prekey_id == prekey_id)
            .map(|c| &c.prekey)
    }

    /// How many consumed one-time prekeys are retained.
    #[must_use]
    pub fn consumed_len(&self) -> usize {
        self.consumed.len()
    }

    /// Drop the oldest consumed entries beyond [`ONE_TIME_CONSUMED_MAX`].
    fn enforce_consumed_cap(&mut self) -> usize {
        if self.consumed.len() <= ONE_TIME_CONSUMED_MAX {
            return 0;
        }
        let excess = self.consumed.len() - ONE_TIME_CONSUMED_MAX;
        self.consumed.drain(..excess);
        excess
    }

    /// How many one-time prekeys remain.
    #[must_use]
    pub fn one_time_len(&self) -> usize {
        self.pool.len()
    }

    /// Rotate the signed prekey if the cadence has elapsed and refill the one-time
    /// pool if it is at or below the low-water mark (ADR-002 §2). Call on start and
    /// periodically; [`save`] afterwards iff [`Maintenance::changed`].
    pub fn maintain(&mut self, signer: &dyn RootSigner, now_secs: u64) -> Result<Maintenance> {
        let mut out = Maintenance::default();
        let due = self
            .current
            .public()
            .created
            .saturating_add(SIGNED_PREKEY_CADENCE_SECS);
        if now_secs >= due {
            let id = self.next_signed_prekey_id;
            let fresh = SignedPrekey::generate(signer, id, now_secs)?;
            self.next_signed_prekey_id = id
                .checked_add(1)
                .ok_or(Error::MalformedAtRest("signed prekey id overflow"))?;
            // The outgoing current becomes `previous`; the older `previous` is
            // dropped — it has now been retained one full cadence (ADR-002).
            self.previous = Some(std::mem::replace(&mut self.current, fresh));
            out.rotated = true;
        }
        out.one_time_added = self.pool.refill_to(
            signer,
            ONE_TIME_PREKEY_LOW_WATER,
            ONE_TIME_PREKEY_TARGET,
            now_secs,
        )?;
        // Retention elapsed: drop the consumed secrets (forward secrecy restored).
        let before = self.consumed.len();
        self.consumed
            .retain(|c| now_secs < c.consumed_at.saturating_add(ONE_TIME_CONSUMED_RETAIN_SECS));
        out.consumed_pruned = before - self.consumed.len() + self.enforce_consumed_cap();
        Ok(out)
    }

    /// Encode the ring (**secrets included**) for sealing:
    /// `[version, idk, current, previous(0|1), next_signed_prekey_id,
    ///  pool_next_id, pool, consumed]`, where a signed/one-time prekey is
    /// `[canonical_body, signature, x25519_secret, ml_kem_seed]` and the identity
    /// DH key is `[canonical_body, signature, x25519_secret]`. Reusing the ADR-002
    /// canonical bodies means the at-rest form pins exactly the bytes the root
    /// signature covers.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(8).uint(RING_VERSION);
        // Identity DH key.
        e.array(3)
            .bytes(&self.identity_dh.public().canonical_body())
            .bytes(&self.identity_dh.signature().to_bytes())
            .bytes(self.identity_dh.x25519_secret_bytes().as_ref());
        encode_signed_prekey(&mut e, &self.current);
        match &self.previous {
            None => {
                e.array(0);
            }
            Some(p) => {
                e.array(1);
                encode_signed_prekey(&mut e, p);
            }
        }
        e.uint(self.next_signed_prekey_id).uint(self.pool.next_id());
        e.array(self.pool.len());
        for otp in self.pool.iter() {
            encode_one_time(&mut e, otp);
        }
        // Consumed entries carry their consume time (arity 5) so retention survives
        // a restart.
        e.array(self.consumed.len());
        for c in &self.consumed {
            e.array(5);
            encode_one_time_fields(&mut e, &c.prekey);
            e.uint(c.consumed_at);
        }
        Zeroizing::new(e.finish())
    }

    /// Decode a ring, re-verifying every root signature and that every stored
    /// secret derives exactly its recorded public key (a tampered or swapped
    /// segment is refused, not silently adopted).
    fn decode(root: &CompositePublicKey, buf: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(buf);
        if d.array()? != 8 {
            return Err(Error::MalformedAtRest("prekey ring arity"));
        }
        if d.uint()? != RING_VERSION {
            return Err(Error::MalformedAtRest("prekey ring version"));
        }
        if d.array()? != 3 {
            return Err(Error::MalformedAtRest("prekey ring identity dh arity"));
        }
        let idk_public = X25519IdentityKeyPublic::from_canonical_body(d.bytes()?)?;
        let idk_sig = take_sig(&mut d)?;
        let idk_secret = take32(&mut d)?;
        let identity_dh = SignedIdentityDhKey::from_parts(
            root,
            idk_public,
            idk_sig,
            X25519IdentityKey::from_secret_bytes(*idk_secret),
        )?;
        let current = decode_signed_prekey(root, &mut d)?;
        let previous = match d.array()? {
            0 => None,
            1 => Some(decode_signed_prekey(root, &mut d)?),
            _ => return Err(Error::MalformedAtRest("prekey ring previous arity")),
        };
        let next_signed_prekey_id = d.uint()?;
        let pool_next_id = d.uint()?;
        let n = d.array()?;
        if n > ONE_TIME_PREKEY_TARGET {
            return Err(Error::MalformedAtRest("prekey ring pool too large"));
        }
        let mut prekeys = Vec::with_capacity(n);
        for _ in 0..n {
            if d.array()? != 4 {
                return Err(Error::MalformedAtRest("prekey ring one-time arity"));
            }
            prekeys.push(decode_one_time(root, &mut d)?);
        }
        let c = d.array()?;
        if c > ONE_TIME_CONSUMED_MAX {
            return Err(Error::MalformedAtRest("prekey ring consumed set too large"));
        }
        let mut consumed = Vec::with_capacity(c);
        for _ in 0..c {
            if d.array()? != 5 {
                return Err(Error::MalformedAtRest("prekey ring consumed arity"));
            }
            let prekey = decode_one_time(root, &mut d)?;
            let consumed_at = d.uint()?;
            consumed.push(ConsumedOneTime {
                prekey,
                consumed_at,
            });
        }
        d.finish()?;
        let pool = OneTimePrekeyPool::from_parts(pool_next_id, prekeys)?;
        if next_signed_prekey_id <= current.public().prekey_id {
            return Err(Error::MalformedAtRest("prekey ring signed prekey id"));
        }
        // A consumed prekey must never also be in the pool (it would be re-issued)
        // and must be one this ring actually issued.
        let mut ids: std::collections::HashSet<u64> =
            pool.iter().map(|o| o.public().prekey_id).collect();
        for c in &consumed {
            let id = c.prekey.public().prekey_id;
            if id >= pool_next_id || !ids.insert(id) {
                return Err(Error::MalformedAtRest("prekey ring consumed ids"));
            }
        }
        Ok(Self {
            identity_dh,
            current,
            previous,
            next_signed_prekey_id,
            pool,
            consumed,
        })
    }
}

fn encode_one_time_fields(e: &mut Encoder, otp: &OneTimePrekey) {
    e.bytes(&otp.public().canonical_body())
        .bytes(&otp.signature().to_bytes())
        .bytes(otp.x25519_secret_bytes().as_ref())
        .bytes(otp.ml_kem_seed_bytes().as_ref());
}

fn encode_one_time(e: &mut Encoder, otp: &OneTimePrekey) {
    e.array(4);
    encode_one_time_fields(e, otp);
}

fn decode_one_time(root: &CompositePublicKey, d: &mut Decoder<'_>) -> Result<OneTimePrekey> {
    let public = OneTimePrekeyPublic::from_canonical_body(d.bytes()?)?;
    let sig = take_sig(d)?;
    let x = take32(d)?;
    let seed = take64(d)?;
    OneTimePrekey::from_parts(root, public, sig, &x, &seed)
}

fn encode_signed_prekey(e: &mut Encoder, spk: &SignedPrekey) {
    e.array(4)
        .bytes(&spk.public().canonical_body())
        .bytes(&spk.signature().to_bytes())
        .bytes(spk.x25519_secret_bytes().as_ref())
        .bytes(spk.ml_kem_seed_bytes().as_ref());
}

fn decode_signed_prekey(root: &CompositePublicKey, d: &mut Decoder<'_>) -> Result<SignedPrekey> {
    if d.array()? != 4 {
        return Err(Error::MalformedAtRest("prekey ring signed prekey arity"));
    }
    let public = SignedPrekeyPublic::from_canonical_body(d.bytes()?)?;
    let sig = take_sig(d)?;
    let x = take32(d)?;
    let seed = take64(d)?;
    SignedPrekey::from_parts(root, public, sig, &x, &seed)
}

fn take_sig(d: &mut Decoder<'_>) -> Result<CompositeSignature> {
    let bytes: [u8; COMPOSITE_SIG_LEN] = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("prekey ring signature length"))?;
    CompositeSignature::from_bytes(&bytes)
}

fn take32(d: &mut Decoder<'_>) -> Result<Zeroizing<[u8; 32]>> {
    let b: [u8; 32] = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("prekey ring secret length"))?;
    Ok(Zeroizing::new(b))
}

fn take64(d: &mut Decoder<'_>) -> Result<Zeroizing<[u8; 64]>> {
    let b: [u8; 64] = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("prekey ring seed length"))?;
    Ok(Zeroizing::new(b))
}

/// Seal and store the ring (latest-wins in its one segment).
pub fn save(store: &Store, signer: &dyn RootSigner, ring: &PrekeyRing) -> Result<()> {
    let sek = ring_sek(signer)?;
    let sealed = seal_segment(
        &sek,
        SegmentKind::PrekeyRing,
        SEG_PREKEY_RING,
        ring.encode().as_ref(),
    )?;
    store.put_segment(
        &ring_channel(),
        SegmentKind::PrekeyRing,
        SEG_PREKEY_RING,
        &sealed,
    )
}

/// Load the stored ring, or `Ok(None)` if this profile has none yet. A ring
/// sealed to a different identity, or tampered with, fails with
/// [`Error::AtRestUnlockFailed`] — never a silently regenerated ring, which would
/// invalidate every published bundle.
pub fn load(store: &Store, signer: &dyn RootSigner) -> Result<Option<PrekeyRing>> {
    let Some(sealed) =
        store.get_segment(&ring_channel(), SegmentKind::PrekeyRing, SEG_PREKEY_RING)?
    else {
        return Ok(None);
    };
    let sek = ring_sek(signer)?;
    let plain = open_segment(&sek, SegmentKind::PrekeyRing, SEG_PREKEY_RING, &sealed)?;
    PrekeyRing::decode(&signer.public_key(), &plain).map(Some)
}

/// Load the ring, generating and storing one on first use (from the identity's own
/// DH secret — see [`PrekeyRing::generate`]), then run
/// [`PrekeyRing::maintain`] and persist if anything changed. This is the single
/// entry point the node calls after unlocking. Returns the ring and whether it was
/// freshly generated.
pub fn load_or_create(
    store: &Store,
    signer: &dyn RootSigner,
    identity_dh_secret: &[u8; 32],
    now_secs: u64,
) -> Result<(PrekeyRing, bool)> {
    match load(store, signer)? {
        Some(mut ring) => {
            if ring.maintain(signer, now_secs)?.changed() {
                save(store, signer, &ring)?;
            }
            Ok((ring, false))
        }
        None => {
            let ring = PrekeyRing::generate(signer, identity_dh_secret, now_secs)?;
            save(store, signer, &ring)?;
            Ok((ring, true))
        }
    }
}
