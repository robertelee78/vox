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
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::nat::record::{PreJoinRecord, RendezvousRecord};

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

/// The expiry instant of a member record (epoch-seconds).
fn member_expiry(rec: &RendezvousRecord) -> u64 {
    rec.timestamp.saturating_add(rec.ttl_secs)
}

/// The expiry instant of a pre-join record (epoch-seconds): store-applied default
/// TTL, since pre-join records carry no TTL field (ADR-012).
fn prejoin_expiry(rec: &PreJoinRecord) -> u64 {
    rec.timestamp.saturating_add(DEFAULT_TTL_SECS)
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
/// Holds the current member advertisements per `(channelID, epoch)` and the current
/// pre-join advertisements per `channelID`. Construct with [`RendezvousStore::new`],
/// feed records through [`RendezvousStore::accept_member`] /
/// [`RendezvousStore::accept_prejoin`], and read current endpoints through the
/// query methods.
#[derive(Debug, Default)]
pub struct RendezvousStore {
    /// `(channelID, epoch)` → (`author_id` → current member record).
    members: HashMap<(Digest32, u64), HashMap<Digest32, RendezvousRecord>>,
    /// `channelID` → (`asserted_id` → current pre-join record).
    prejoins: HashMap<Digest32, HashMap<Digest32, PreJoinRecord>>,
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

    /// The current, non-expired pre-join records for `channelID`, in unspecified
    /// order — candidate join-bootstrap material (ADR-004/ADR-005).
    #[must_use]
    pub fn current_prejoins(&self, channel_id: &Digest32, now: u64) -> Vec<&PreJoinRecord> {
        self.prejoins
            .get(channel_id)
            .map(|b| b.values().filter(|r| now < prejoin_expiry(r)).collect())
            .unwrap_or_default()
    }

    /// Drop every expired record (member and pre-join) and any bucket left empty.
    /// Idempotent; call periodically to reclaim memory. Returns the number of
    /// records removed.
    pub fn prune_expired(&mut self, now: u64) -> usize {
        let mut removed = 0;
        for bucket in self.members.values_mut() {
            let before = bucket.len();
            bucket.retain(|_, r| now < member_expiry(r));
            removed += before - bucket.len();
        }
        self.members.retain(|_, b| !b.is_empty());
        for bucket in self.prejoins.values_mut() {
            let before = bucket.len();
            bucket.retain(|_, r| now < prejoin_expiry(r));
            removed += before - bucket.len();
        }
        self.prejoins.retain(|_, b| !b.is_empty());
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::identity::keyagreement::{PrekeyBundlePublic, SignedIdentityDhKey, SignedPrekey};
    use crate::nat::multiaddr::{EndpointList, Multiaddr};
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn eps(d: u8) -> EndpointList {
        EndpointList::new(vec![Multiaddr::Ip4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, d),
            4433,
        ))])
        .unwrap()
    }

    fn member(
        s: &SoftwareRootSigner,
        cid: &Digest32,
        epoch: u64,
        seq: u64,
        ts: u64,
    ) -> RendezvousRecord {
        RendezvousRecord::build(s, cid, epoch, eps(1), seq, ts, MAX_TTL_SECS).unwrap()
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
    fn accepts_then_refreshes_a_member_record() {
        let s = signer(1, 2);
        let cid = [7u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        store
            .accept_member(member(&s, &cid, 0, 1, now), |_| Some(s.public_key()), now)
            .unwrap();
        assert_eq!(store.current_members(&cid, 0, now).len(), 1);
        // A later refresh (higher seq + ts >= +60) replaces it.
        let now2 = now + MIN_REFRESH_SECS;
        store
            .accept_member(member(&s, &cid, 0, 2, now2), |_| Some(s.public_key()), now2)
            .unwrap();
        let cur = store.member(&cid, 0, &s.fingerprint(), now2).unwrap();
        assert_eq!(cur.seq, 2);
        assert_eq!(
            store.current_members(&cid, 0, now2).len(),
            1,
            "still one current per author"
        );
    }

    #[test]
    fn rejects_replayed_lower_or_equal_seq() {
        let s = signer(1, 2);
        let cid = [7u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        store
            .accept_member(member(&s, &cid, 0, 5, now), |_| Some(s.public_key()), now)
            .unwrap();
        // Same seq (a replay) → rejected.
        let err = store
            .accept_member(
                member(&s, &cid, 0, 5, now + 100),
                |_| Some(s.public_key()),
                now + 100,
            )
            .unwrap_err();
        assert!(matches!(err, Error::RendezvousRejected(_)));
        // Lower seq → rejected.
        assert!(matches!(
            store.accept_member(
                member(&s, &cid, 0, 4, now + 200),
                |_| Some(s.public_key()),
                now + 200
            ),
            Err(Error::RendezvousRejected(_))
        ));
    }

    #[test]
    fn rejects_refresh_faster_than_minimum() {
        let s = signer(1, 2);
        let cid = [7u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        store
            .accept_member(member(&s, &cid, 0, 1, now), |_| Some(s.public_key()), now)
            .unwrap();
        // Higher seq but only +59s → below the 60s floor → rejected.
        let err = store
            .accept_member(
                member(&s, &cid, 0, 2, now + 59),
                |_| Some(s.public_key()),
                now + 59,
            )
            .unwrap_err();
        assert!(matches!(err, Error::RendezvousRejected(_)));
    }

    #[test]
    fn rejects_overlong_ttl_and_future_timestamp() {
        let s = signer(1, 2);
        let cid = [7u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        // Over-long TTL is rejected.
        let over = RendezvousRecord::build(&s, &cid, 0, eps(1), 1, now, MAX_TTL_SECS + 1).unwrap();
        assert!(matches!(
            store.accept_member(over, |_| Some(s.public_key()), now),
            Err(Error::RendezvousRejected(_))
        ));
        // Future timestamp beyond skew is rejected.
        let rec =
            RendezvousRecord::build(&s, &cid, 0, eps(1), 1, now + MAX_CLOCK_SKEW_SECS + 1, 60)
                .unwrap();
        assert!(matches!(
            store.accept_member(rec, |_| Some(s.public_key()), now),
            Err(Error::RendezvousRejected(_))
        ));
    }

    #[test]
    fn expired_records_are_not_served_and_pruned() {
        let s = signer(1, 2);
        let cid = [7u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        let rec = RendezvousRecord::build(&s, &cid, 0, eps(1), 1, now, 60).unwrap();
        store
            .accept_member(rec, |_| Some(s.public_key()), now)
            .unwrap();
        let later = now + 61; // past timestamp + ttl
        assert_eq!(
            store.current_members(&cid, 0, later).len(),
            0,
            "expired not served"
        );
        assert_eq!(store.prune_expired(later), 1);
        assert!(store.current_members(&cid, 0, later).is_empty());
    }

    #[test]
    fn epochs_are_separate_buckets() {
        let s = signer(1, 2);
        let cid = [7u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        store
            .accept_member(member(&s, &cid, 0, 1, now), |_| Some(s.public_key()), now)
            .unwrap();
        store
            .accept_member(member(&s, &cid, 1, 1, now), |_| Some(s.public_key()), now)
            .unwrap();
        // Each epoch holds its own current record; querying the other epoch is empty
        // of the rotated party once it stops publishing there.
        assert_eq!(store.current_members(&cid, 0, now).len(), 1);
        assert_eq!(store.current_members(&cid, 1, now).len(), 1);
        assert_eq!(store.current_members(&cid, 2, now).len(), 0);
    }

    #[test]
    fn non_member_record_cannot_be_admitted() {
        // A correctly self-signed record from `s` is still rejected when the
        // membership oracle does not recognize `s` as a member (resolves to None).
        // Member-only is enforced by the store, not caller discipline.
        let s = signer(1, 2);
        let cid = [7u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        let err = store
            .accept_member(member(&s, &cid, 0, 1, now), |_| None, now)
            .unwrap_err();
        assert!(matches!(err, Error::RendezvousRejected(_)));
    }

    #[test]
    fn resolver_returning_mismatched_key_is_rejected() {
        // A membership oracle that returns the *wrong* key for an author_id (a
        // misconfiguration or a forged author_id) fails the signature/author
        // binding inside record.verify().
        let s = signer(1, 2);
        let other = signer(8, 8);
        let cid = [7u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        let err = store
            .accept_member(
                member(&s, &cid, 0, 1, now),
                |_| Some(other.public_key()),
                now,
            )
            .unwrap_err();
        assert!(matches!(err, Error::MalformedRendezvous(_)));
    }

    #[test]
    fn prejoin_accepts_verifies_and_refreshes() {
        let s = signer(3, 4);
        let cid = [8u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        let rec = PreJoinRecord::build(&s, &cid, bundle(&s), eps(2), 1, now).unwrap();
        store.accept_prejoin(rec, now).unwrap();
        assert_eq!(store.current_prejoins(&cid, now).len(), 1);
        // Replay (same seq) rejected.
        let replay = PreJoinRecord::build(&s, &cid, bundle(&s), eps(2), 1, now + 100).unwrap();
        assert!(matches!(
            store.accept_prejoin(replay, now + 100),
            Err(Error::RendezvousRejected(_))
        ));
    }

    #[test]
    fn prejoin_channel_capacity_is_enforced() {
        let cid = [8u8; 32];
        let mut store = RendezvousStore::new();
        let now = 1_000_000;
        // Fill to capacity with distinct asserted identities.
        for i in 0..MAX_PREJOIN_PER_CHANNEL {
            let s = signer((i % 250) as u8 + 1, (i / 250) as u8 + 1);
            let rec = PreJoinRecord::build(&s, &cid, bundle(&s), eps(1), 1, now).unwrap();
            store.accept_prejoin(rec, now).unwrap();
        }
        assert_eq!(
            store.current_prejoins(&cid, now).len(),
            MAX_PREJOIN_PER_CHANNEL
        );
        // One more distinct identity is refused (no expired entries to evict).
        let extra = signer(200, 200);
        let rec = PreJoinRecord::build(&extra, &cid, bundle(&extra), eps(1), 1, now).unwrap();
        assert!(matches!(
            store.accept_prejoin(rec, now),
            Err(Error::RendezvousRejected(_))
        ));
    }
}
