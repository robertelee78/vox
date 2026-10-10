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
//! sealed under a key derived from the vault's **`self_seed`**:
//!
//! ```text
//! ring_key = HKDF-SHA-256(self_seed, info = "vox/prekey-ring-sek/v2")
//! ```
//!
//! This is single-factor by design: `self_seed` is released only by the identity
//! passphrase, so the ring is gated by exactly the same secret as the root it
//! belongs to, and it is non-circular because the identity domain unlocks first.
//!
//! **It used to be the identity factor,** `HKDF(HKDF(id_proof(ring_channel)))`, on the
//! reasoning that computing `id_proof` requires the unlocked identity. That holds
//! classically and fails against a quantum adversary: `id_proof` is an Ed25519
//! signature, and Ed25519's private key falls to such an adversary from the public key
//! alone. With the disk, that adversary opened the ring, whose ML-KEM prekey secrets
//! undo the post-quantum half of every handshake recorded against them (V210-40, #214).
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
//!   secret — so it is retained for [`ONE_TIME_CONSUMED_RETAIN_MS`] (and at most
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
//! ## Retiring unused one-time prekeys (ADR-030 P-1)
//! A one-time prekey nobody used within one signed-prekey cadence ([`SIGNED_PREKEY_CADENCE_MS`],
//! by its root-signed creation time) is **retired** by [`PrekeyRing::maintain`]: taken out of the
//! pool, so it is never advertised again, and its secret kept, unadvertised, for
//! [`ONE_TIME_RETIRED_GRACE_MS`], so a delivery already in flight against it still opens
//! ([`PrekeyRing::use_one_time`] takes it as [`OneTimeUse::Fresh`]). Then it is dropped. Without
//! this a one-time prekey a thief copied stayed usable until some initiator happened to consume
//! it, which bounded nothing: a recipient's compromise healed only as fast as its pool turned over.
//!
//! The prekey material stays owned by the ring ([`PrekeyRing::consumed_one_time`]
//! hands out a borrow), the ring is deliberately not `Clone` so no consumed secret
//! survives in a copy, and [`save`] **must** be called after a consume: until it
//! is, a crash would re-offer the prekey on the next start (a test pins this).

use zeroize::Zeroizing;

use crate::atrest::sek::Sek;
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
pub const PREKEY_RING_SEK_INFO: &[u8] = b"vox/prekey-ring-sek/v2";

/// The ring's segment id within its pseudo-channel (one segment, latest-wins).
pub const SEG_PREKEY_RING: u64 = 1;

/// At-rest encoding version of the ring: 3, which adds the retired one-time prekeys (ADR-030
/// P-1); every time in it in milliseconds.
const RING_VERSION: u64 = 3;

/// The ring's version 2: no retired one-time prekeys. Still read (see [`PrekeyRing::decode`]).
const RING_VERSION_NO_RETIRED: u64 = 2;

/// The ring's version 1, its times in seconds: still read (see [`PrekeyRing::decode`]).
const RING_VERSION_SECONDS: u64 = 1;

/// Signed-prekey rotation cadence (ADR-002 §2: "every 7 days").
pub const SIGNED_PREKEY_CADENCE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// One-time prekey pool target size (refilled up to this).
pub const ONE_TIME_PREKEY_TARGET: usize = 64;

/// One-time prekey low-water mark: at or below this, the pool is refilled to
/// [`ONE_TIME_PREKEY_TARGET`] (ADR-002 §2 "refilled whenever it drops below a
/// low-water mark").
pub const ONE_TIME_PREKEY_LOW_WATER: usize = 16;

/// **Test-only**: a smaller one-time pool, so a proof crosses it in a dozen sessions rather than
/// 64 (V210-77). Its value is the pool's target, from 1 to [`ONE_TIME_PREKEY_TARGET`], and the
/// low-water mark is a quarter of it. Unset, empty, unparsable or out of range is the production
/// pool: nothing in a real deployment sets it, and without the `test-knobs` feature (V210-105) it is
/// not compiled in.
#[cfg(feature = "test-knobs")]
pub const TEST_ONE_TIME_PREKEYS_ENV: &str = "VOX_TEST_ONE_TIME_PREKEYS";

/// The one-time pool's `(low-water mark, target)`: the production pair, or
/// [`TEST_ONE_TIME_PREKEYS_ENV`]'s.
#[cfg(feature = "test-knobs")]
fn one_time_pool() -> (usize, usize) {
    static POOL: std::sync::OnceLock<(usize, usize)> = std::sync::OnceLock::new();
    *POOL.get_or_init(|| {
        std::env::var(TEST_ONE_TIME_PREKEYS_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|n| (1..=ONE_TIME_PREKEY_TARGET).contains(n))
            .map_or((ONE_TIME_PREKEY_LOW_WATER, ONE_TIME_PREKEY_TARGET), |n| {
                (n / 4, n)
            })
    })
}

/// The one-time pool's production `(low-water mark, target)`.
#[cfg(not(feature = "test-knobs"))]
const fn one_time_pool() -> (usize, usize) {
    (ONE_TIME_PREKEY_LOW_WATER, ONE_TIME_PREKEY_TARGET)
}

/// How long a **consumed** one-time prekey is retained so a concurrent duplicate
/// use can still establish (ADR-004 §"Serverless consume semantics"). One hour
/// covers a genuine race; see the module docs for why it is not the bundle TTL.
pub const ONE_TIME_CONSUMED_RETAIN_MS: u64 = 60 * 60 * 1_000;

/// How long a **retired** one-time prekey's secret is kept, unadvertised, so a delivery already in
/// flight against it still opens (ADR-030 P-1: one hour).
pub const ONE_TIME_RETIRED_GRACE_MS: u64 = 60 * 60 * 1_000;

/// Hard cap on retired one-time prekeys held in their grace (oldest dropped first): one cadence
/// retires at most the pool, and a stored ring holding more is refused as malformed.
pub const ONE_TIME_RETIRED_MAX: usize = 4 * ONE_TIME_PREKEY_TARGET;

/// Hard cap on retained consumed one-time prekeys (oldest dropped first), so a
/// drain attack cannot grow the ring without bound.
pub const ONE_TIME_CONSUMED_MAX: usize = 256;

/// The reserved pseudo-channel the ring is filed and key-derived under.
#[must_use]
pub fn ring_channel() -> Digest32 {
    sha256(PREKEY_RING_CHANNEL_DOMAIN.as_bytes())
}

/// The ring's sealing key, from the vault's `self_seed` (see the module docs).
pub fn ring_sek(signer: &dyn RootSigner) -> Result<Sek> {
    crate::atrest::seal::sek(signer, PREKEY_RING_SEK_INFO)
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
    /// How many unused one-time prekeys were retired: older than one cadence, no longer
    /// advertised (ADR-030 P-1).
    pub retired: usize,
    /// How many retired one-time prekeys were dropped, their grace over: their secrets are gone.
    pub retired_pruned: usize,
}

impl Maintenance {
    /// Whether anything changed (so the caller knows it must [`save`]).
    #[must_use]
    pub fn changed(self) -> bool {
        self.rotated
            || self.one_time_added > 0
            || self.consumed_pruned > 0
            || self.retired > 0
            || self.retired_pruned > 0
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

/// A one-time prekey retired unused (ADR-030 P-1), kept unadvertised for its grace so a delivery
/// already in flight against it still opens. Its secrets zeroize on drop with the prekey.
struct RetiredOneTime {
    prekey: OneTimePrekey,
    retired_at: u64,
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
    /// One-time prekeys retired unused, in their grace, oldest first (ADR-030 P-1).
    retired: Vec<RetiredOneTime>,
    /// Initial messages this process answered with a retired one-time prekey, in its grace: a
    /// delivery in flight when the prekey was retired. Not persisted; `vox status --json` reports
    /// it.
    retired_used: std::sync::atomic::AtomicU64,
    /// Initial messages this process answered with the **previous** signed prekey: sessions
    /// started just before a rotation. Not persisted; `vox status --json` reports it.
    previous_used: std::sync::atomic::AtomicU64,
    /// Read from an earlier at-rest version: [`load_or_create`] saves it at once in this one, so
    /// no ring of an earlier release lingers on disk.
    older_version: bool,
    /// The current signed prekey was read from a version-1 ring, its creation time in seconds
    /// under its signature: it is rotated at the next [`PrekeyRing::maintain`] rather than read in
    /// the wrong unit.
    rotate_now: bool,
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
            .field("retired_retained", &self.retired.len())
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
        now_ms: u64,
    ) -> Result<Self> {
        Self::generate_sized(signer, identity_dh_secret, now_ms, one_time_pool().1)
    }

    /// [`PrekeyRing::generate`] with an explicit initial pool size. Private: the
    /// production size is the constant, and tests use a small pool so the debug
    /// suite does not pay for 64 ML-KEM keygens plus composite signatures per ring
    /// (one test still exercises the real size).
    fn generate_sized(
        signer: &dyn RootSigner,
        identity_dh_secret: &[u8; 32],
        now_ms: u64,
        one_time: usize,
    ) -> Result<Self> {
        let identity_dh = SignedIdentityDhKey::from_key(
            signer,
            X25519IdentityKey::from_secret_bytes(*identity_dh_secret),
            now_ms,
        )?;
        let current = SignedPrekey::generate(signer, 1, now_ms)?;
        let pool = OneTimePrekeyPool::generate(signer, one_time, 1, now_ms)?;
        Ok(Self {
            identity_dh,
            current,
            previous: None,
            next_signed_prekey_id: 2,
            pool,
            consumed: Vec::new(),
            retired: Vec::new(),
            retired_used: std::sync::atomic::AtomicU64::new(0),
            previous_used: std::sync::atomic::AtomicU64::new(0),
            rotate_now: false,
            older_version: false,
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
        let previous = self
            .previous
            .as_ref()
            .filter(|p| p.public().prekey_id == prekey_id);
        if previous.is_some() {
            self.previous_used
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        previous
    }

    /// How many initial messages this process answered with the previous signed prekey.
    #[must_use]
    pub fn previous_used(&self) -> u64 {
        self.previous_used
            .load(std::sync::atomic::Ordering::Relaxed)
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
    pub fn use_one_time(&mut self, prekey_id: u64, now_ms: u64) -> OneTimeUse {
        if let Some(prekey) = self.pool.take_by_id(prekey_id) {
            self.consumed.push(ConsumedOneTime {
                prekey,
                consumed_at: now_ms,
            });
            self.enforce_consumed_cap();
            return OneTimeUse::Fresh;
        }
        // Retired unused, and still in its grace: a delivery in flight when it was retired (ADR-030
        // P-1). It was never consumed, so this is its first use.
        if let Some(at) = self
            .retired
            .iter()
            .position(|r| r.prekey.public().prekey_id == prekey_id)
        {
            let RetiredOneTime { prekey, .. } = self.retired.remove(at);
            self.consumed.push(ConsumedOneTime {
                prekey,
                consumed_at: now_ms,
            });
            self.enforce_consumed_cap();
            self.retired_used
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    /// How many retired one-time prekeys are held in their grace (ADR-030 P-1).
    #[must_use]
    pub fn retired_len(&self) -> usize {
        self.retired.len()
    }

    /// How many initial messages this process answered with a retired one-time prekey in its
    /// grace (ADR-030 P-1).
    #[must_use]
    pub fn retired_used(&self) -> u64 {
        self.retired_used.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// What [`PrekeyRing::bundle`] names now: the signed prekey's id and the one-time prekey's, if
    /// any. When it changes, the bundle on the boards is out of date.
    #[must_use]
    pub fn offered(&self) -> (u64, Option<u64>) {
        (
            self.current.public().prekey_id,
            self.pool.first().map(|o| o.public().prekey_id),
        )
    }

    /// The root-signed creation time of the oldest one-time prekey offered, or `None` with none to
    /// offer. After [`PrekeyRing::maintain`], never older than one cadence (ADR-030 P-1).
    #[must_use]
    pub fn oldest_one_time_created(&self) -> Option<u64> {
        self.pool.iter().map(|o| o.public().created).min()
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
    pub fn maintain(&mut self, signer: &dyn RootSigner, now_ms: u64) -> Result<Maintenance> {
        let mut out = Maintenance::default();
        let due = self
            .current
            .public()
            .created
            .saturating_add(SIGNED_PREKEY_CADENCE_MS);
        if self.rotate_now || now_ms >= due {
            let id = self.next_signed_prekey_id;
            let fresh = SignedPrekey::generate(signer, id, now_ms)?;
            self.next_signed_prekey_id = id
                .checked_add(1)
                .ok_or(Error::MalformedAtRest("signed prekey id overflow"))?;
            // The outgoing current becomes `previous`; the older `previous` is
            // dropped — it has now been retained one full cadence (ADR-002).
            self.previous = Some(std::mem::replace(&mut self.current, fresh));
            self.rotate_now = false;
            out.rotated = true;
        }
        // Unused for a whole cadence: retired, never advertised again, its secret kept for the grace
        // (ADR-030 P-1). Before the refill, so the pool is refilled with fresh ones.
        let stale: Vec<u64> = self
            .pool
            .iter()
            .filter(|o| now_ms >= o.public().created.saturating_add(SIGNED_PREKEY_CADENCE_MS))
            .map(|o| o.public().prekey_id)
            .collect();
        for id in stale {
            if let Some(prekey) = self.pool.take_by_id(id) {
                self.retired.push(RetiredOneTime {
                    prekey,
                    retired_at: now_ms,
                });
                out.retired += 1;
            }
        }
        out.one_time_added =
            self.pool
                .refill_to(signer, one_time_pool().0, one_time_pool().1, now_ms)?;
        // Grace over: the retired secrets go.
        let held = self.retired.len();
        self.retired
            .retain(|r| now_ms < r.retired_at.saturating_add(ONE_TIME_RETIRED_GRACE_MS));
        if self.retired.len() > ONE_TIME_RETIRED_MAX {
            let excess = self.retired.len() - ONE_TIME_RETIRED_MAX;
            self.retired.drain(..excess);
        }
        out.retired_pruned = held - self.retired.len();
        // Retention elapsed: drop the consumed secrets (forward secrecy restored).
        let before = self.consumed.len();
        self.consumed
            .retain(|c| now_ms < c.consumed_at.saturating_add(ONE_TIME_CONSUMED_RETAIN_MS));
        out.consumed_pruned = before - self.consumed.len() + self.enforce_consumed_cap();
        Ok(out)
    }

    /// Encode the ring (**secrets included**) for sealing:
    /// `[version, idk, current, previous(0|1), next_signed_prekey_id,
    ///  pool_next_id, pool, consumed, retired]`, where a signed/one-time prekey is
    /// `[canonical_body, signature, x25519_secret, ml_kem_seed]` and the identity
    /// DH key is `[canonical_body, signature, x25519_secret]`. Reusing the ADR-002
    /// canonical bodies means the at-rest form pins exactly the bytes the root
    /// signature covers.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::for_secrets();
        e.array(9).uint(RING_VERSION);
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
        // Retired entries carry their retire time (arity 5) so the grace survives a restart.
        e.array(self.retired.len());
        for r in &self.retired {
            e.array(5);
            encode_one_time_fields(&mut e, &r.prekey);
            e.uint(r.retired_at);
        }
        Zeroizing::new(e.finish())
    }

    /// Decode a ring, re-verifying every root signature and that every stored
    /// secret derives exactly its recorded public key (a tampered or swapped
    /// segment is refused, not silently adopted).
    fn decode(root: &CompositePublicKey, buf: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(buf);
        let arity = d.array()?;
        // A version-1 ring's times are seconds. Its consume times convert; a prekey's creation
        // time is under its root signature, and only the current signed prekey's is ever read,
        // so that one is rotated at once instead (the others' are never compared with anything).
        // Versions 1 and 2 hold no retired one-time prekeys (ADR-030 P-1): an empty set, and
        // `load_or_create` saves the ring as version 3 at once.
        let (seconds, has_retired) = match (d.uint()?, arity) {
            (RING_VERSION, 9) => (false, true),
            (RING_VERSION_NO_RETIRED, 8) => (false, false),
            (RING_VERSION_SECONDS, 8) => (true, false),
            (RING_VERSION | RING_VERSION_NO_RETIRED | RING_VERSION_SECONDS, _) => {
                return Err(Error::MalformedAtRest("prekey ring arity"))
            }
            _ => return Err(Error::MalformedAtRest("prekey ring version")),
        };
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
            let consumed_at = if seconds {
                consumed_at.saturating_mul(1_000)
            } else {
                consumed_at
            };
            consumed.push(ConsumedOneTime {
                prekey,
                consumed_at,
            });
        }
        let mut retired = Vec::new();
        if has_retired {
            let r = d.array()?;
            if r > ONE_TIME_RETIRED_MAX {
                return Err(Error::MalformedAtRest("prekey ring retired set too large"));
            }
            retired.reserve(r);
            for _ in 0..r {
                if d.array()? != 5 {
                    return Err(Error::MalformedAtRest("prekey ring retired arity"));
                }
                let prekey = decode_one_time(root, &mut d)?;
                let retired_at = d.uint()?;
                retired.push(RetiredOneTime { prekey, retired_at });
            }
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
        // Nor a retired one (it would be advertised again, or opened twice).
        for r in &retired {
            let id = r.prekey.public().prekey_id;
            if id >= pool_next_id || !ids.insert(id) {
                return Err(Error::MalformedAtRest("prekey ring retired ids"));
            }
        }
        Ok(Self {
            identity_dh,
            current,
            previous,
            next_signed_prekey_id,
            pool,
            consumed,
            retired,
            retired_used: std::sync::atomic::AtomicU64::new(0),
            previous_used: std::sync::atomic::AtomicU64::new(0),
            rotate_now: seconds,
            older_version: !has_retired,
        })
    }
}

/// How far ahead of a sender's clock a prekey's root-signed creation time may be before the
/// bundle naming it is refused (ADR-030 P-2): ten minutes. A recipient whose clock runs fast makes
/// its prekeys look newer than they are; this bounds how much longer than a cadence that keeps a
/// stolen prekey in use.
pub const PREKEY_FUTURE_TOLERANCE_MS: u64 = 10 * 60 * 1_000;

/// Which prekey in a peer's bundle a key delivery refused (ADR-030 P-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalePrekey {
    /// Its signed prekey: its owner rotates it every cadence.
    Signed,
    /// Its one-time prekey: its owner retires an unused one after a cadence (P-1).
    OneTime,
}

impl StalePrekey {
    fn word(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::OneTime => "one-time",
        }
    }
}

/// What to do with a bundle whose one-time prekey this node has already named in a delivery, or
/// the peer refused (ADR-030 P-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpentOneTime {
    /// Wait for the peer's next bundle, which names a fresh one-time prekey: what a key delivery
    /// does first.
    Wait,
    /// Open against the signed prekey alone, which heals only when it rotates (S-5).
    SignedPrekey,
}

/// Why a key delivery to a peer waits for its bundle (ADR-030 D-5): never sealed in an older
/// session instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleWait {
    /// This node's board holds no bundle of the peer.
    NoBundle,
    /// The bundle's signatures do not verify against its own root.
    Unverified,
    /// The bundle names a prekey created, by its root-signed time, a cadence or more ago (P-2).
    Stale {
        /// Which prekey.
        part: StalePrekey,
        /// How old it is, in milliseconds.
        age_ms: u64,
    },
    /// The bundle names a prekey whose root-signed creation time is more than
    /// [`PREKEY_FUTURE_TOLERANCE_MS`] ahead of this node's clock (P-2).
    FromTheFuture {
        /// Which prekey.
        part: StalePrekey,
        /// How far ahead, in milliseconds.
        ahead_ms: u64,
    },
    /// The bundle's one-time prekey was already named by a delivery to the peer, or refused by it
    /// (P-3); its next bundle names a fresh one.
    OneTimeSpent {
        /// The one-time prekey's id.
        prekey_id: u64,
    },
}

impl BundleWait {
    /// The reason, as a person reads it after "your key for it in room … waits: ".
    #[must_use]
    pub fn why(self) -> String {
        const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
        match self {
            Self::NoBundle => "this node's board holds no prekey bundle of it yet; it is sent \
                               once one arrives"
                .to_owned(),
            Self::Unverified => "its prekey bundle on this node's board does not verify; it is \
                                 sent once a valid one arrives"
                .to_owned(),
            Self::Stale { part, age_ms } => format!(
                "its prekey bundle is stale: its {} prekey is {} days old, and a key sealed to it \
                 could be read by whoever copied that prekey before it was replaced; it is sent \
                 once its next bundle arrives (bundles republish about hourly)",
                part.word(),
                age_ms / DAY_MS
            ),
            Self::FromTheFuture { part, ahead_ms } => format!(
                "its prekey bundle says its {} prekey was made {} minutes from now: its clock, or \
                 this node's, is wrong, and a prekey dated ahead would be used longer than seven \
                 days; it is sent once a bundle dated within {} minutes of this node's clock \
                 arrives",
                part.word(),
                ahead_ms.div_ceil(60_000),
                PREKEY_FUTURE_TOLERANCE_MS / 60_000
            ),
            Self::OneTimeSpent { .. } => "its prekey bundle names a one-time prekey this node has \
                                           already used; it is sent once its next bundle, naming a \
                                           fresh one, arrives (about a second when it is online)"
                .to_owned(),
        }
    }
}

/// The bundle a key delivery opens its session against (ADR-030 P-2, P-3), or why it waits.
///
/// The signatures are checked first, so the creation times judged are the root-signed ones, never
/// the record's own publication fields. A bundle whose signed prekey, or whose one-time prekey, was
/// created a cadence ([`SIGNED_PREKEY_CADENCE_MS`]) or more before `now_ms` is refused: its owner
/// has rotated or retired it (P-1), so only a stale or replayed bundle still names it. So is one
/// dated more than [`PREKEY_FUTURE_TOLERANCE_MS`] after `now_ms`, which would otherwise stay
/// acceptable for longer than a cadence. A one-time prekey in `spent` (one a delivery already
/// named, or the peer answered it does not hold) is never named again (P-3): with
/// [`SpentOneTime::Wait`] the delivery waits for the next bundle; with
/// [`SpentOneTime::SignedPrekey`] it is taken out and the session opens against the signed prekey.
pub fn delivery_bundle(
    bundle: &PrekeyBundlePublic,
    now_ms: u64,
    spent: &[u64],
    on_spent: SpentOneTime,
) -> std::result::Result<PrekeyBundlePublic, BundleWait> {
    bundle.verify().map_err(|_| BundleWait::Unverified)?;
    let judge = |part: StalePrekey, created: u64| {
        if created > now_ms.saturating_add(PREKEY_FUTURE_TOLERANCE_MS) {
            return Err(BundleWait::FromTheFuture {
                part,
                ahead_ms: created - now_ms,
            });
        }
        let age_ms = now_ms.saturating_sub(created);
        if age_ms >= SIGNED_PREKEY_CADENCE_MS {
            return Err(BundleWait::Stale { part, age_ms });
        }
        Ok(())
    };
    judge(StalePrekey::Signed, bundle.signed_prekey.created)?;
    let mut out = bundle.clone();
    if let Some(otp) = &bundle.one_time_prekey {
        judge(StalePrekey::OneTime, otp.created)?;
        if spent.contains(&otp.prekey_id) {
            match on_spent {
                SpentOneTime::Wait => {
                    return Err(BundleWait::OneTimeSpent {
                        prekey_id: otp.prekey_id,
                    })
                }
                SpentOneTime::SignedPrekey => {
                    out.one_time_prekey = None;
                    out.one_time_prekey_sig = None;
                }
            }
        }
    }
    Ok(out)
}

/// One-time prekey ids of a peer never targeted again (ADR-030 P-3): each one a key delivery named,
/// which the peer consumes on receipt, and each one the peer answered it does not hold. At most
/// [`ONE_TIME_PREKEY_TARGET`] per peer, oldest dropped first. A ring issues ids in increasing order
/// and never reissues one, so a dropped id is targeted again only if its owner still offers it: the
/// delivery naming it never arrived, and the prekey is still unused.
#[derive(Debug, Default)]
pub struct RefusedOneTime {
    by_peer: std::collections::BTreeMap<Digest32, std::collections::VecDeque<u64>>,
}

impl RefusedOneTime {
    /// Record that a delivery named `peer`'s `prekey_id`, or that `peer` refused it.
    pub fn note(&mut self, peer: Digest32, prekey_id: u64) {
        let ids = self.by_peer.entry(peer).or_default();
        if ids.contains(&prekey_id) {
            return;
        }
        ids.push_back(prekey_id);
        while ids.len() > ONE_TIME_PREKEY_TARGET {
            ids.pop_front();
        }
    }

    /// The ids `peer` refused.
    #[must_use]
    pub fn of(&self, peer: &Digest32) -> Vec<u64> {
        self.by_peer
            .get(peer)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
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
    now_ms: u64,
) -> Result<(PrekeyRing, bool)> {
    match load(store, signer)? {
        Some(mut ring) => {
            if ring.maintain(signer, now_ms)?.changed() || ring.older_version {
                save(store, signer, &ring)?;
                ring.older_version = false;
            }
            Ok((ring, false))
        }
        None => {
            let ring = PrekeyRing::generate(signer, identity_dh_secret, now_ms)?;
            save(store, signer, &ring)?;
            Ok((ring, true))
        }
    }
}
