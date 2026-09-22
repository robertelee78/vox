//! The authenticated rendezvous store — the reader-side policy gate (ADR-012
//! §"Rendezvous (authenticated, fresh, epoch-scoped)").
//!
//! [`crate::nat::record`] gives the record types and their *signature* checks; this
//! module is the **policy** ADR-012 mandates so that "a poisoner cannot inject or
//! replay endpoints, and a stale record cannot be replayed after rotation":
//!
//! - **Member-only.** The store resolves the record's `author_id` against a
//!   membership oracle (the authenticated membership set, ADR-007); a non-member
//!   `author_id` resolves to no key and the record is rejected. Membership is
//!   enforced by the store, not by caller discipline.
//! - **One current record per `(author, channel, epoch)`.** A newly admitted record
//!   replaces the prior one; there is never more than one current record per author.
//! - **Monotone freshness.** A replacement must strictly advance both `seq` and
//!   `timestamp`; an equal-or-older `(seq, timestamp)` is a replay and is rejected.
//! - **Rate floor.** A refresh faster than [`MIN_REFRESH_SECS`] is rejected
//!   (bounds rendezvous-record spam even from a joined member).
//! - **TTL.** Member records carry a `ttl_secs` capped at [`MAX_TTL_SECS`]; pre-join
//!   records (no TTL field, ADR-012) get [`DEFAULT_TTL_SECS`]. Expired records are
//!   never served and are pruned.
//! - **Bounded clock skew.** A `timestamp` more than [`MAX_CLOCK_SKEW_SECS`] in the
//!   future is rejected, so a forged far-future timestamp cannot pin a stale record
//!   forever or evade TTL.
//! - **Epoch-scoping.** Member records bucket by `(channelID, epoch)`; after a
//!   passphrase rotation (new epoch, ADR-007) readers query the new bucket and
//!   prior-epoch records are simply never consulted (and expire). That, not any
//!   per-member rendezvous revocation, is how the swarm sheds a party (ADR-012).
//! - **Anti-spam capacity.** Pre-join records (whose `asserted_id` is unbounded —
//!   anyone may assert an identity) are capped per channel at
//!   [`MAX_PREJOIN_PER_CHANNEL`]; member buckets are bounded by
//!   [`MAX_AUTHORS_PER_BUCKET`] as defense in depth.
//!
//! All time is caller-supplied `now` (epoch-seconds): the store is deterministic
//! and has no ambient clock, which keeps it unit-testable and side-effect-free.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::governance::genesis::Genesis;
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::nat::record::{MemberBundleRecord, PreJoinRecord, RendezvousRecord};

/// Minimum seconds between successive accepted records for one
/// `(author, channel, epoch)` — the ADR-012 refresh cap (≥ 60 s).
pub const MIN_REFRESH_SECS: u64 = 60;

/// Default record TTL in seconds (ADR-012 "short TTL (default 2 h)"). Applied to
/// pre-join records, which carry no TTL field of their own.
pub const DEFAULT_TTL_SECS: u64 = 2 * 60 * 60;

/// Hard ceiling on a member record's requested `ttl_secs`. A record asking for more
/// is rejected (ADR-012 "short TTL"): a member cannot pin a long-lived stale
/// advertisement.
pub const MAX_TTL_SECS: u64 = 2 * 60 * 60;

/// Hard ceiling on a member **bundle** record's requested `ttl_secs` (ADR-016
/// M14): the ADR-002 signed-prekey rotation cadence, 7 days. A bundle is
/// republished on rotation and when the one-time pool runs low, so a longer
/// pin would only serve a stale bundle.
pub const BUNDLE_MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Maximum seconds a record's `timestamp` may lead `now` before it is rejected as
/// implausibly future-dated (clock-skew tolerance).
pub const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;

/// Maximum distinct pre-join `asserted_id`s retained per channel (anti-spam: a
/// pre-join author is unauthenticated-as-member, so the count is otherwise
/// unbounded). PoW join tokens (ADR-005) are the upstream gate; this bounds store
/// memory regardless.
pub const MAX_PREJOIN_PER_CHANNEL: usize = 256;

/// Maximum distinct member authors retained per `(channel, epoch)` bucket. Member
/// records are already membership-bounded; this is defense in depth against a
/// permissive membership lookup.
pub const MAX_AUTHORS_PER_BUCKET: usize = 1024;

/// Maximum distinct channels whose **genesis** this store retains (M14.7b). A
/// genesis is immutable and self-validating (its hash *is* the channelID), so it
/// needs no TTL and no author check — only a bound, so an unknown peer cannot grow
/// the board without limit by inventing channels.
pub const MAX_GENESIS_CHANNELS: usize = 4096;

/// The expiry instant of a member record (epoch-seconds).
fn member_expiry(rec: &RendezvousRecord) -> u64 {
    rec.timestamp.saturating_add(rec.ttl_secs)
}

/// The expiry instant of a pre-join record (epoch-seconds): store-applied default
/// TTL, since pre-join records carry no TTL field (ADR-012).
fn prejoin_expiry(rec: &PreJoinRecord) -> u64 {
    rec.timestamp.saturating_add(DEFAULT_TTL_SECS)
}

/// The expiry instant of a member bundle record (epoch-seconds).
fn bundle_expiry(rec: &MemberBundleRecord) -> u64 {
    rec.timestamp.saturating_add(rec.ttl_secs)
}

/// Shared freshness checks for a replacement against the current record's
/// `(seq, timestamp)`. Enforces strict monotonicity and the refresh-rate floor.
fn check_replacement(new_seq: u64, new_ts: u64, cur_seq: u64, cur_ts: u64) -> Result<()> {
    if new_seq <= cur_seq {
        return Err(Error::RendezvousRejected("non-increasing seq (replay)"));
    }
    if new_ts <= cur_ts {
        return Err(Error::RendezvousRejected(
            "non-increasing timestamp (replay)",
        ));
    }
    if new_ts < cur_ts.saturating_add(MIN_REFRESH_SECS) {
        return Err(Error::RendezvousRejected(
            "refresh faster than minimum interval",
        ));
    }
    Ok(())
}

/// Common time-sanity checks applied to every incoming record before it can be
/// stored: not implausibly future-dated, and not already expired.
fn check_time_validity(timestamp: u64, expiry: u64, now: u64) -> Result<()> {
    if timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(Error::RendezvousRejected("timestamp too far in the future"));
    }
    if now >= expiry {
        return Err(Error::RendezvousRejected("record already expired"));
    }
    Ok(())
}

/// The authenticated rendezvous store.
///
/// Holds the current member advertisements and member prekey bundles per
/// `(channelID, epoch)` and the current pre-join advertisements per `channelID`.
/// Construct with [`RendezvousStore::new`], feed records through
/// [`RendezvousStore::accept_member`] / [`RendezvousStore::accept_bundle`] /
/// [`RendezvousStore::accept_prejoin`], and read current endpoints and bundles
/// through the query methods.
#[derive(Debug, Default)]
pub struct RendezvousStore {
    /// `(channelID, epoch)` → (`author_id` → current member record).
    members: HashMap<(Digest32, u64), HashMap<Digest32, RendezvousRecord>>,
    /// `(channelID, epoch)` → (`author_id` → current member bundle record).
    bundles: HashMap<(Digest32, u64), HashMap<Digest32, MemberBundleRecord>>,
    /// `channelID` → (`asserted_id` → current pre-join record).
    prejoins: HashMap<Digest32, HashMap<Digest32, PreJoinRecord>>,
    /// `channelID` → that channel's genesis (ADR-007: a cold-joining node fetches
    /// the genesis from the rendezvous and accepts it only if its hash equals the
    /// channelID it joined with).
    genesis: HashMap<Digest32, Genesis>,
}

impl RendezvousStore {
    /// A fresh, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit (or refresh) a **member** rendezvous record, enforcing the full
    /// ADR-012 reader policy.
    ///
    /// `resolve_member` is the membership oracle for the record's channel/epoch: the
    /// store calls it with the record's `author_id` and admits the record **only**
    /// if it returns that member's composite public key (ADR-007 authenticated
    /// membership). A non-member `author_id` resolves to `None` and the record is
    /// rejected — so member-only admission is enforced by the store itself, not left
    /// to caller discipline. Returns:
    /// - [`Error::RendezvousRejected`] if the author is not a member, or the bytes
    ///   are valid but policy refuses them (replay, too-fast refresh, expired,
    ///   future-dated, over-long TTL, bucket full);
    /// - [`Error::MalformedRendezvous`] if the resolved key does not match the
    ///   record's signature/author binding;
    /// - `Ok(())` on admission (the record becomes the current one for its author).
    pub fn accept_member(
        &mut self,
        record: RendezvousRecord,
        resolve_member: impl FnOnce(&Digest32) -> Option<CompositePublicKey>,
        now: u64,
    ) -> Result<()> {
        // 1. Member-only: resolve the author's authenticated membership key. No key
        //    for this author_id ⇒ not a channel member ⇒ rejected.
        let author_pubkey = resolve_member(&record.author_id)
            .ok_or(Error::RendezvousRejected("author is not a channel member"))?;
        // 2. Cryptographic authenticity + author binding.
        record.verify(&author_pubkey)?;

        // 3. TTL bounds and time sanity.
        if record.ttl_secs == 0 {
            return Err(Error::RendezvousRejected("zero ttl"));
        }
        if record.ttl_secs > MAX_TTL_SECS {
            return Err(Error::RendezvousRejected("ttl exceeds maximum"));
        }
        check_time_validity(record.timestamp, member_expiry(&record), now)?;

        let bucket_key = (record.channel_id, record.epoch);
        let bucket = self.members.entry(bucket_key).or_default();

        // 4. Freshness vs the current record for this author (if any).
        if let Some(cur) = bucket.get(&record.author_id) {
            check_replacement(record.seq, record.timestamp, cur.seq, cur.timestamp)?;
        } else if bucket.len() >= MAX_AUTHORS_PER_BUCKET {
            // New author would exceed the bucket cap: only admit if pruning expired
            // entries frees room.
            bucket.retain(|_, r| now < member_expiry(r));
            if bucket.len() >= MAX_AUTHORS_PER_BUCKET {
                return Err(Error::RendezvousRejected("member bucket at capacity"));
            }
        }

        // 5. Admit: replace the author's current record (one current per author).
        bucket.insert(record.author_id, record);
        Ok(())
    }

    /// Admit (or refresh) a **member bundle** record (ADR-016 M14), enforcing the
    /// same member-only, anti-replay, time-sanity and capacity policy as
    /// [`RendezvousStore::accept_member`], with the TTL capped at
    /// [`BUNDLE_MAX_TTL_SECS`] instead of [`MAX_TTL_SECS`]. Bundles are keyed
    /// per `(channelID, epoch)` like address records but live in their own
    /// buckets: a member's address refresh never displaces its bundle and vice
    /// versa.
    ///
    /// `resolve_member` is the membership oracle exactly as for
    /// [`RendezvousStore::accept_member`]; the resolved key must be the bundle's
    /// root (checked by [`MemberBundleRecord::verify`]), so a member cannot
    /// publish another identity's prekeys under its own name.
    pub fn accept_bundle(
        &mut self,
        record: MemberBundleRecord,
        resolve_member: impl FnOnce(&Digest32) -> Option<CompositePublicKey>,
        now: u64,
    ) -> Result<()> {
        // 1. Member-only.
        let author_pubkey = resolve_member(&record.author_id)
            .ok_or(Error::RendezvousRejected("author is not a channel member"))?;
        // 2. Record signature, author binding, bundle root == author, bundle
        //    self-signatures.
        record.verify(&author_pubkey)?;

        // 3. TTL bounds and time sanity.
        if record.ttl_secs == 0 {
            return Err(Error::RendezvousRejected("zero ttl"));
        }
        if record.ttl_secs > BUNDLE_MAX_TTL_SECS {
            return Err(Error::RendezvousRejected("ttl exceeds maximum"));
        }
        check_time_validity(record.timestamp, bundle_expiry(&record), now)?;

        let bucket_key = (record.channel_id, record.epoch);
        let bucket = self.bundles.entry(bucket_key).or_default();

        // 4. Freshness vs the current bundle for this author (if any).
        if let Some(cur) = bucket.get(&record.author_id) {
            check_replacement(record.seq, record.timestamp, cur.seq, cur.timestamp)?;
        } else if bucket.len() >= MAX_AUTHORS_PER_BUCKET {
            bucket.retain(|_, r| now < bundle_expiry(r));
            if bucket.len() >= MAX_AUTHORS_PER_BUCKET {
                return Err(Error::RendezvousRejected("bundle bucket at capacity"));
            }
        }

        // 5. Admit: one current bundle per author.
        bucket.insert(record.author_id, record);
        Ok(())
    }

    /// Admit a channel's **genesis** (ADR-007 §Genesis; M14.7b).
    ///
    /// This kind needs neither a membership check nor a TTL, and that is not a gap:
    /// the genesis is immutable and **self-validating** — its hash *is* the
    /// channelID, so a wrong or forged genesis cannot be filed under a channelID
    /// anyone asked for, and a reader re-checks the hash against the channelID it
    /// joined with regardless. Anyone may therefore publish it (a joiner that has
    /// one, an anchor restoring its store), which is exactly what makes a cold join
    /// possible when no member is online. Re-publishing the same genesis is a no-op;
    /// the only bound is [`MAX_GENESIS_CHANNELS`].
    pub fn accept_genesis(&mut self, genesis: Genesis) -> Result<()> {
        genesis.verify()?;
        let channel_id = genesis.channel_id();
        if let Some(existing) = self.genesis.get(&channel_id) {
            // Two different genesis structures cannot share a channelID unless
            // SHA-256 collided; keep the one already verified and filed.
            if existing.to_wire() == genesis.to_wire() {
                return Ok(());
            }
            return Err(Error::RendezvousRejected("genesis already present"));
        }
        if self.genesis.len() >= MAX_GENESIS_CHANNELS {
            return Err(Error::RendezvousRejected("genesis board at capacity"));
        }
        self.genesis.insert(channel_id, genesis);
        Ok(())
    }

    /// The stored genesis for `channel_id`, if any.
    #[must_use]
    pub fn genesis(&self, channel_id: &Digest32) -> Option<&Genesis> {
        self.genesis.get(channel_id)
    }

    /// Every channel this board holds a genesis for — the channels it anchors, in
    /// no particular order.
    #[must_use]
    pub fn channels_with_genesis(&self) -> Vec<Digest32> {
        self.genesis.keys().copied().collect()
    }

    /// Admit (or refresh) a **pre-join** rendezvous record, enforcing the ADR-012
    /// reader policy. The record is self-verifying (the asserted identity and the
    /// embedded prekey bundle are checked); it conveys no channel authority.
    ///
    /// Returns the same error taxonomy as [`RendezvousStore::accept_member`].
    pub fn accept_prejoin(&mut self, record: PreJoinRecord, now: u64) -> Result<()> {
        // 1. Self-signature + embedded-bundle authenticity.
        record.verify()?;

        // 2. Time sanity (store-applied default TTL).
        check_time_validity(record.timestamp, prejoin_expiry(&record), now)?;

        // 2a. A pre-join is only meaningful for a channel this board actually serves.
        //
        // Without this, `entry(...).or_default()` created a bucket for **any** channelID an
        // unauthenticated peer named, and the peer was then classified `PendingJoiner` for it
        // (`node::network::classify` → `peer_has_prejoin`), which is what lets it open a
        // `Join` or `Pairwise` stream. A pre-join needs no membership, no passphrase and no
        // proof of work — by design, since a joiner has none of those yet — so that
        // classification was self-service, and a channelID is public: it is the 52-character
        // `.vox` name, and it is in every invite link.
        //
        // Requiring the genesis costs a legitimate joiner nothing. The board it publishes to
        // is an anchor for that room or a member of it, and both hold the genesis; a board
        // that does not is not one that could answer the join anyway. It also stops an
        // unauthenticated peer making this node allocate a bucket per fabricated channelID.
        if self.genesis(&record.channel_id).is_none() {
            return Err(Error::RendezvousRejected(
                "pre-join for a channel this board does not serve",
            ));
        }

        let asserted_id = record.asserted_id();
        let bucket = self.prejoins.entry(record.channel_id).or_default();

        // 3. Freshness vs the current record for this asserted identity.
        if let Some(cur) = bucket.get(&asserted_id) {
            check_replacement(record.seq, record.timestamp, cur.seq, cur.timestamp)?;
        } else if bucket.len() >= MAX_PREJOIN_PER_CHANNEL {
            bucket.retain(|_, r| now < prejoin_expiry(r));
            if bucket.len() >= MAX_PREJOIN_PER_CHANNEL {
                return Err(Error::RendezvousRejected("pre-join channel at capacity"));
            }
        }

        // 4. Admit.
        bucket.insert(asserted_id, record);
        Ok(())
    }

    /// The current, non-expired member records for `(channelID, epoch)`, in
    /// unspecified order. These are the live endpoint advertisements a dialer
    /// consumes for the reachability ladder.
    #[must_use]
    pub fn current_members(
        &self,
        channel_id: &Digest32,
        epoch: u64,
        now: u64,
    ) -> Vec<&RendezvousRecord> {
        self.members
            .get(&(*channel_id, epoch))
            .map(|b| b.values().filter(|r| now < member_expiry(r)).collect())
            .unwrap_or_default()
    }

    /// The current member record for one specific author in `(channelID, epoch)`,
    /// if present and unexpired.
    #[must_use]
    pub fn member(
        &self,
        channel_id: &Digest32,
        epoch: u64,
        author_id: &Digest32,
        now: u64,
    ) -> Option<&RendezvousRecord> {
        self.members
            .get(&(*channel_id, epoch))
            .and_then(|b| b.get(author_id))
            .filter(|r| now < member_expiry(r))
    }

    /// The current, non-expired member bundle records for `(channelID, epoch)`, in
    /// unspecified order — the material a newcomer needs to seal its SKDM to each
    /// consenting member (ADR-016 M14).
    #[must_use]
    pub fn current_bundles(
        &self,
        channel_id: &Digest32,
        epoch: u64,
        now: u64,
    ) -> Vec<&MemberBundleRecord> {
        self.bundles
            .get(&(*channel_id, epoch))
            .map(|b| b.values().filter(|r| now < bundle_expiry(r)).collect())
            .unwrap_or_default()
    }

    /// The current bundle record for one specific author in `(channelID, epoch)`,
    /// if present and unexpired.
    #[must_use]
    pub fn bundle(
        &self,
        channel_id: &Digest32,
        epoch: u64,
        author_id: &Digest32,
        now: u64,
    ) -> Option<&MemberBundleRecord> {
        self.bundles
            .get(&(*channel_id, epoch))
            .and_then(|b| b.get(author_id))
            .filter(|r| now < bundle_expiry(r))
    }

    /// The current, non-expired pre-join records for `channelID`, in unspecified
    /// order — candidate join-bootstrap material (ADR-004/ADR-005).
    #[must_use]
    pub fn current_prejoins(&self, channel_id: &Digest32, now: u64) -> Vec<&PreJoinRecord> {
        self.prejoins
            .get(channel_id)
            .map(|b| b.values().filter(|r| now < prejoin_expiry(r)).collect())
            .unwrap_or_default()
    }

    /// Drop every expired record (member, bundle and pre-join) and any bucket left
    /// empty. Idempotent; call periodically to reclaim memory. Returns the number
    /// of records removed.
    pub fn prune_expired(&mut self, now: u64) -> usize {
        let mut removed = 0;
        for bucket in self.members.values_mut() {
            let before = bucket.len();
            bucket.retain(|_, r| now < member_expiry(r));
            removed += before - bucket.len();
        }
        self.members.retain(|_, b| !b.is_empty());
        for bucket in self.bundles.values_mut() {
            let before = bucket.len();
            bucket.retain(|_, r| now < bundle_expiry(r));
            removed += before - bucket.len();
        }
        self.bundles.retain(|_, b| !b.is_empty());
        for bucket in self.prejoins.values_mut() {
            let before = bucket.len();
            bucket.retain(|_, r| now < prejoin_expiry(r));
            removed += before - bucket.len();
        }
        self.prejoins.retain(|_, b| !b.is_empty());
        removed
    }
}
