//! Per-channel state for the single-device node (ADR-016 M13.3): create a
//! channel, open it from the store, append and render messages, and persist
//! every step as sealed segments.
//!
//! ## What a channel is, at rest
//! Under the channel's SEK (ADR-010), sealed segments in the profile store:
//! - `KeyMaterial 0` — the **manifest**: `[1, genesis_wire, local_name, created,
//!   epoch]`. The genesis is the trust anchor (ADR-007); `local_name` is this
//!   device's label, never protocol state.
//! - `KeyMaterial 1` — this identity's **sender chain** state
//!   ([`SenderChain::to_state`]), advanced and re-sealed on every append.
//! - `LogDb n` (`n ≥ 1`, arrival order) — one ADR-008 log entry's wire bytes.
//! - `PlaintextCache n` — the rendered form of entry `n`: `[1, entry_hash,
//!   author_id, created_secs, text]` (ADR-010 permits a plaintext cache only
//!   inside a sealed segment; on open, each cache row is accepted only if its
//!   `entry_hash` is in the rebuilt DAG).
//!
//! The SEK wrap itself lives in the store's `sek_wraps` table.
//!
//! ## Invariants
//! - The DAG is rebuilt from the log segments on every open through the full
//!   ADR-008 acceptance predicate (`Dag::accept`): the store is a cache of
//!   *verified* entries, never trusted as such.
//! - An append is atomic: entry, plaintext cache and the advanced chain state
//!   commit in one [`crate::node::store::Batch`]. If the commit fails the channel
//!   is marked **poisoned** and refuses further appends until reopened — the
//!   in-memory chain has already advanced, and re-using a sender-key iteration for
//!   a different plaintext would be a key/nonce reuse (ADR-006), so the only safe
//!   continuation is the on-disk state.
//! - Double-lock (ADR-010): opening needs the unlocked identity (the identity
//!   factor) *and* the channel passphrase; there is no path to the SEK without both.
//!
//! M13 is single-device: the only author is this identity, membership is
//! `{self}`, and the channel's governance evaluator is built over the genesis
//! alone. M14 adds other authors' entries, SKDMs, consent and sync on top of the
//! same layout.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::atrest::idfactor::SignatureIdentityFactor;
use crate::atrest::sek::{Argon2Profile, Sek};
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::evaluator::Evaluator;
use crate::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use crate::group::state::SenderChain;
use crate::hash::{sha256, Digest32};
use crate::identity::composite::{CompositePublicKey, RootSigner};
use crate::log::dag::{AdmissionPolicy, Dag};
use crate::log::entry::{Entry, EntryKind, EntrySkeleton, ZERO_HASH};
use crate::log::feed::lipmaa;
use crate::node::content::Content;
use crate::node::profile::Profile;
use crate::suite::{algo, SuiteFloor};

/// Segment id of the manifest in `KeyMaterial`.
const SEG_MANIFEST: u64 = 0;
/// Segment id of this identity's sender chain in `KeyMaterial`.
const SEG_SENDER: u64 = 1;
/// Manifest encoding version.
const MANIFEST_VERSION: u64 = 1;
/// Plaintext-cache row encoding version.
const CACHE_VERSION: u64 = 1;
/// Cap on a local channel name.
pub const MAX_LOCAL_NAME_LEN: usize = 128;

/// A rendered (decrypted, render-gated) message in the timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The ADR-008 entry hash this rendering belongs to.
    pub entry_hash: Digest32,
    /// The author's identity fingerprint.
    pub author: Digest32,
    /// The author's recorded send time (seconds).
    pub created_secs: u64,
    /// The text.
    pub text: String,
}

/// An open (SEK-unlocked) channel on this device.
pub struct ChannelState {
    channel_id: Digest32,
    genesis: Genesis,
    local_name: String,
    created: u64,
    epoch: u64,
    sek: Sek,
    /// Author fingerprint → composite root key (M13: the creator only).
    authors: BTreeMap<Digest32, CompositePublicKey>,
    admission: AdmissionPolicy,
    dag: Dag,
    evaluator: Evaluator,
    sender: SenderChain,
    /// The next `LogDb` / `PlaintextCache` segment id.
    next_log_id: u64,
    timeline: Vec<Rendered>,
    poisoned: bool,
}

impl std::fmt::Debug for ChannelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelState")
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("local_name", &self.local_name)
            .field("epoch", &self.epoch)
            .field("entries", &self.dag.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

fn manifest_bytes(genesis: &Genesis, local_name: &str, created: u64, epoch: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(MANIFEST_VERSION)
        .bytes(&genesis.to_wire())
        .text(local_name)
        .uint(created)
        .uint(epoch);
    e.finish()
}

fn parse_manifest(bytes: &[u8]) -> Result<(Genesis, String, u64, u64)> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 5 {
        return Err(Error::MalformedAtRest("channel manifest arity"));
    }
    if d.uint()? != MANIFEST_VERSION {
        return Err(Error::MalformedAtRest("channel manifest version"));
    }
    let genesis = Genesis::from_wire(d.bytes()?)?;
    let name = d.text()?;
    if name.len() > MAX_LOCAL_NAME_LEN {
        return Err(Error::SizeLimitExceeded("channel local name"));
    }
    let name = name.to_owned();
    let created = d.uint()?;
    let epoch = d.uint()?;
    d.finish()?;
    Ok((genesis, name, created, epoch))
}

fn cache_bytes(r: &Rendered) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(CACHE_VERSION)
        .bytes(&r.entry_hash)
        .bytes(&r.author)
        .uint(r.created_secs)
        .text(&r.text);
    e.finish()
}

fn parse_cache(bytes: &[u8]) -> Result<Rendered> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 5 {
        return Err(Error::MalformedAtRest("plaintext cache arity"));
    }
    if d.uint()? != CACHE_VERSION {
        return Err(Error::MalformedAtRest("plaintext cache version"));
    }
    let entry_hash: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("plaintext cache entry hash"))?;
    let author: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("plaintext cache author"))?;
    let created_secs = d.uint()?;
    let text = d.text()?.to_owned();
    d.finish()?;
    Ok(Rendered {
        entry_hash,
        author,
        created_secs,
        text,
    })
}

impl ChannelState {
    /// Create a new channel on this device: genesis at the day-one suite floor
    /// with the default policy (forward-only history, attributable content, no
    /// TTL), a fresh SEK double-locked under (identity factor, `channel_passphrase`)
    /// with the production Argon2id profile, and this identity's first sender
    /// chain. Persists the wrap, manifest and chain atomically.
    pub fn create(
        profile: &Profile,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
    ) -> Result<Self> {
        Self::create_with_profile(
            profile,
            local_name,
            channel_passphrase,
            now_secs,
            Argon2Profile::default(),
        )
    }

    /// [`ChannelState::create`] with an explicit Argon2id profile (tests).
    pub fn create_with_profile(
        profile: &Profile,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
        argon2: Argon2Profile,
    ) -> Result<Self> {
        if local_name.len() > MAX_LOCAL_NAME_LEN {
            return Err(Error::SizeLimitExceeded("channel local name"));
        }
        let signer = profile.signer()?;
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: SuiteFloor::DAY_ONE.id(),
        };
        let genesis = Genesis::create(signer, now_secs, policy)?;
        let channel_id = genesis.channel_id();
        let epoch = 0u64;
        let me = signer.fingerprint();

        let sek = Sek::generate()?;
        let factor = SignatureIdentityFactor::new(signer);
        let wrap = sek.seal(&factor, &channel_id, channel_passphrase, argon2)?;
        let sender = SenderChain::new(&channel_id, epoch, &me, 0, now_secs)?;

        let manifest = manifest_bytes(&genesis, local_name, now_secs, epoch);
        let manifest_seg = seal_segment(&sek, SegmentKind::KeyMaterial, SEG_MANIFEST, &manifest)?;
        let sender_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender.to_state(),
        )?;
        let mut batch = profile.store().batch()?;
        batch.put_sek_wrap(&channel_id, &wrap)?;
        batch.put_segment(
            &channel_id,
            SegmentKind::KeyMaterial,
            SEG_MANIFEST,
            &manifest_seg,
        )?;
        batch.put_segment(
            &channel_id,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender_seg,
        )?;
        batch.commit()?;

        let mut authors = BTreeMap::new();
        authors.insert(me, signer.public_key());
        let mut admission = AdmissionPolicy::new();
        admission.admit(channel_id, epoch, me);
        let evaluator = Self::build_evaluator(&genesis, &authors, now_secs)?;
        Ok(Self {
            channel_id,
            genesis,
            local_name: local_name.to_owned(),
            created: now_secs,
            epoch,
            sek,
            authors,
            admission,
            dag: Dag::new(),
            evaluator,
            sender,
            next_log_id: 1,
            timeline: Vec::new(),
            poisoned: false,
        })
    }

    /// Open a channel from the store: double-lock unwrap of the SEK, then rebuild
    /// the DAG from the log segments through the full acceptance predicate, load
    /// the timeline from the plaintext cache (rows whose entry is not in the DAG
    /// are dropped), and restore the sender chain.
    pub fn open(
        profile: &Profile,
        channel_id: &Digest32,
        channel_passphrase: &[u8],
        now_secs: u64,
    ) -> Result<Self> {
        let signer = profile.signer()?;
        let store = profile.store();
        let wrap = store
            .get_sek_wrap(channel_id)?
            .ok_or(Error::Profile("no such channel in this profile"))?;
        let factor = SignatureIdentityFactor::new(signer);
        let sek = wrap.unwrap_sek(&factor, channel_id, channel_passphrase)?;

        let manifest_seg = store
            .get_segment(channel_id, SegmentKind::KeyMaterial, SEG_MANIFEST)?
            .ok_or(Error::MalformedAtRest("channel manifest missing"))?;
        let manifest = open_segment(&sek, SegmentKind::KeyMaterial, SEG_MANIFEST, &manifest_seg)?;
        let (genesis, local_name, created, epoch) = parse_manifest(&manifest)?;
        genesis.verify()?;
        if genesis.channel_id() != *channel_id {
            return Err(Error::MalformedAtRest("channel manifest genesis mismatch"));
        }

        let mut authors = BTreeMap::new();
        authors.insert(
            genesis.body.creator_pubkey.fingerprint(),
            genesis.body.creator_pubkey.clone(),
        );
        let mut admission = AdmissionPolicy::new();
        for author in authors.keys() {
            admission.admit(*channel_id, epoch, *author);
        }

        // Rebuild the DAG: every stored entry re-passes the acceptance predicate.
        let mut dag = Dag::new();
        let mut next_log_id = 1u64;
        for (id, seg) in store.segments(channel_id, SegmentKind::LogDb)? {
            let wire = open_segment(&sek, SegmentKind::LogDb, id, &seg)?;
            let entry = Entry::from_wire(&wire)?;
            let key = authors
                .get(&entry.skeleton.author_id)
                .ok_or(Error::MalformedAtRest("stored entry from unknown author"))?;
            dag.accept(entry, EntryKind::Content, key, &admission, now_secs)
                .map_err(|_| Error::MalformedAtRest("stored entry failed acceptance"))?;
            next_log_id = id.saturating_add(1);
        }

        // Timeline from the sealed plaintext cache, render-gated by the DAG.
        let mut timeline = Vec::new();
        for (id, seg) in store.segments(channel_id, SegmentKind::PlaintextCache)? {
            let row = open_segment(&sek, SegmentKind::PlaintextCache, id, &seg)?;
            let rendered = parse_cache(&row)?;
            if dag.contains(&rendered.entry_hash) {
                timeline.push(rendered);
            }
        }

        let sender_seg = store
            .get_segment(channel_id, SegmentKind::KeyMaterial, SEG_SENDER)?
            .ok_or(Error::MalformedAtRest("sender chain missing"))?;
        let sender_state = open_segment(&sek, SegmentKind::KeyMaterial, SEG_SENDER, &sender_seg)?;
        let sender = SenderChain::from_state(&sender_state)?;
        drop(sender_state);

        let evaluator = Self::build_evaluator(&genesis, &authors, now_secs)?;
        Ok(Self {
            channel_id: *channel_id,
            genesis,
            local_name,
            created,
            epoch,
            sek,
            authors,
            admission,
            dag,
            evaluator,
            sender,
            next_log_id,
            timeline,
            poisoned: false,
        })
    }

    fn build_evaluator(
        genesis: &Genesis,
        authors: &BTreeMap<Digest32, CompositePublicKey>,
        now_secs: u64,
    ) -> Result<Evaluator> {
        Evaluator::build(genesis, &[], now_secs, |id| authors.get(id).cloned())
    }

    /// Author a text message: encrypt under this identity's sender chain, wrap in
    /// a signed ADR-008 log entry, accept it into the DAG, and persist entry +
    /// rendering + advanced chain state atomically. Returns the rendered message.
    pub fn append_text(
        &mut self,
        profile: &Profile,
        text: &str,
        now_secs: u64,
    ) -> Result<&Rendered> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.authors.contains_key(&me) {
            return Err(Error::Profile(
                "this identity is not an author of the channel",
            ));
        }
        let content = Content::text(now_secs, text)?;
        let plaintext = Zeroizing::new(content.to_canonical_vec());
        let msg = self.sender.encrypt(&plaintext)?;
        let payload = msg.to_wire();

        let skeleton = self.next_skeleton(&me, &payload);
        let entry = Entry::build_signed(signer, skeleton, payload)?;
        let entry_hash = entry.entry_hash();
        let wire = entry.to_wire();
        let rendered = Rendered {
            entry_hash,
            author: me,
            created_secs: now_secs,
            text: content.text,
        };

        let id = self.next_log_id;
        let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
        let cache_seg = seal_segment(
            &self.sek,
            SegmentKind::PlaintextCache,
            id,
            &cache_bytes(&rendered),
        )?;
        let sender_seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &self.sender.to_state(),
        )?;

        // Validate against the DAG first (structural), then persist, then commit
        // to memory. A persist failure poisons the channel (see module docs).
        let key = signer.public_key();
        self.dag
            .accept(entry, EntryKind::Content, &key, &self.admission, now_secs)
            .map_err(|_| Error::Profile("authored entry failed the acceptance predicate"))?;
        let persisted = (|| -> Result<()> {
            let mut batch = profile.store().batch()?;
            batch.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg)?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::PlaintextCache,
                id,
                &cache_seg,
            )?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_SENDER,
                &sender_seg,
            )?;
            batch.commit()
        })();
        if let Err(e) = persisted {
            self.poisoned = true;
            return Err(e);
        }
        self.next_log_id = id.saturating_add(1);
        self.timeline.push(rendered);
        self.timeline
            .last()
            .ok_or(Error::Profile("timeline empty after push"))
    }

    /// The next entry skeleton for `author`'s feed in this DAG.
    fn next_skeleton(&self, author: &Digest32, payload: &[u8]) -> EntrySkeleton {
        let feed = self.dag.feed(author);
        let max = feed.map_or(0, |f| f.max_seq());
        let seq = max + 1;
        let hash_of = |s: u64| -> Digest32 {
            feed.and_then(|f| f.get(s))
                .map_or(ZERO_HASH, |e| e.entry_hash())
        };
        let prev_hash = if seq == 1 {
            ZERO_HASH
        } else {
            hash_of(seq - 1)
        };
        let lipmaa_backlink = if seq == 1 {
            ZERO_HASH
        } else {
            hash_of(lipmaa(seq))
        };
        EntrySkeleton {
            author_id: *author,
            seq,
            prev_hash,
            lipmaa_backlink,
            channel_id: self.channel_id,
            epoch: self.epoch,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(payload),
            payload_len: payload.len() as u64,
            end_of_feed: false,
        }
    }

    /// The channelID.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        self.channel_id
    }

    /// The local (device-only) channel name.
    #[must_use]
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// Creation time recorded in the manifest.
    #[must_use]
    pub fn created(&self) -> u64 {
        self.created
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The genesis record.
    #[must_use]
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    /// The render-gated timeline, oldest first.
    #[must_use]
    pub fn timeline(&self) -> &[Rendered] {
        &self.timeline
    }

    /// Known authors (M13: the creator), in fingerprint order.
    #[must_use]
    pub fn members(&self) -> Vec<Digest32> {
        self.authors.keys().copied().collect()
    }

    /// Number of accepted log entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.dag.len()
    }

    /// The governance evaluator over this channel's log.
    #[must_use]
    pub fn evaluator(&self) -> &Evaluator {
        &self.evaluator
    }

    /// Whether a failed persist has poisoned this channel (reopen to continue).
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Whether this channel's SEK is `mlock`ed (ADR-010 best-effort; surfaced to
    /// the UI as the memory-protection honesty flag).
    #[must_use]
    pub fn mlock_active(&self) -> bool {
        self.sek.is_mlocked()
    }

    /// App-lock this channel: wipe the SEK now. The state should be dropped
    /// afterwards; any further seal/open fails with [`Error::AtRestLocked`].
    pub fn lock_now(&mut self) {
        self.sek.lock_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::paths::Paths;

    fn profile(tmp: &tempfile::TempDir, name: &str) -> Profile {
        let p = Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
        Profile::create_with_profile(p, b"identity-pp", 1_700_000_000, Argon2Profile::REDUCED)
            .unwrap()
    }

    #[test]
    fn create_append_render_and_survive_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let mut ch = ChannelState::create_with_profile(
            &prof,
            "family",
            b"channel-pp",
            1_700_000_100,
            Argon2Profile::REDUCED,
        )
        .unwrap();
        let cid = ch.channel_id();
        assert_eq!(ch.local_name(), "family");
        assert_eq!(ch.epoch(), 0);
        assert_eq!(ch.members(), vec![prof.fingerprint()]);
        assert!(ch.evaluator().is_admin(&prof.fingerprint()));
        assert!(ch.timeline().is_empty());

        let r1 = ch
            .append_text(&prof, "hello", 1_700_000_200)
            .unwrap()
            .clone();
        let r2 = ch
            .append_text(&prof, "world", 1_700_000_300)
            .unwrap()
            .clone();
        assert_eq!(ch.entry_count(), 2);
        assert_eq!(ch.timeline().len(), 2);
        assert_eq!(r1.text, "hello");
        assert_eq!(r2.text, "world");
        assert_eq!(r1.author, prof.fingerprint());
        assert_ne!(r1.entry_hash, r2.entry_hash);
        drop(ch);

        // Reopen from the store with the right channel passphrase.
        let ch = ChannelState::open(&prof, &cid, b"channel-pp", 1_700_000_400).unwrap();
        assert_eq!(ch.local_name(), "family");
        assert_eq!(ch.entry_count(), 2);
        assert_eq!(ch.timeline(), &[r1.clone(), r2.clone()]);
        // The restored sender chain continues where it left off (iteration 2).
        let mut ch = ch;
        let r3 = ch
            .append_text(&prof, "again", 1_700_000_500)
            .unwrap()
            .clone();
        assert_eq!(ch.entry_count(), 3);
        drop(ch);
        let ch = ChannelState::open(&prof, &cid, b"channel-pp", 1_700_000_600).unwrap();
        assert_eq!(ch.timeline(), &[r1, r2, r3]);
        assert_eq!(ch.entry_count(), 3);
    }

    #[test]
    fn double_lock_needs_both_factors() {
        let tmp = tempfile::tempdir().unwrap();
        let mut prof = profile(&tmp, "alice");
        let ch =
            ChannelState::create_with_profile(&prof, "c", b"channel-pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        let cid = ch.channel_id();
        drop(ch);
        // Wrong channel passphrase.
        assert!(matches!(
            ChannelState::open(&prof, &cid, b"wrong", 2),
            Err(Error::AtRestUnlockFailed)
        ));
        // Locked identity: no identity factor, no SEK.
        prof.lock();
        assert!(matches!(
            ChannelState::open(&prof, &cid, b"channel-pp", 2),
            Err(Error::Profile("locked"))
        ));
        prof.unlock(b"identity-pp").unwrap();
        // Another identity with the right channel passphrase: wrong identity factor.
        let other = profile(&tmp, "mallory");
        // Copy the wrap into mallory's store to simulate file theft.
        let wrap = prof.store().get_sek_wrap(&cid).unwrap().unwrap();
        other.store().put_sek_wrap(&cid, &wrap).unwrap();
        for (id, seg) in prof
            .store()
            .segments(&cid, SegmentKind::KeyMaterial)
            .unwrap()
        {
            other
                .store()
                .put_segment(&cid, SegmentKind::KeyMaterial, id, &seg)
                .unwrap();
        }
        assert!(matches!(
            ChannelState::open(&other, &cid, b"channel-pp", 2),
            Err(Error::AtRestUnlockFailed)
        ));
        // Unknown channel.
        assert!(matches!(
            ChannelState::open(&prof, &[0u8; 32], b"channel-pp", 2),
            Err(Error::Profile("no such channel in this profile"))
        ));
    }

    #[test]
    fn stored_entries_are_re_verified_on_open() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let mut ch =
            ChannelState::create_with_profile(&prof, "c", b"pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        let cid = ch.channel_id();
        ch.append_text(&prof, "one", 2).unwrap();
        ch.append_text(&prof, "two", 3).unwrap();
        // Corrupt entry 2's sealed segment: the SEK open fails, so the open fails
        // (never silently drops or trusts a bad entry).
        let (id, mut seg) = prof
            .store()
            .segments(&cid, SegmentKind::LogDb)
            .unwrap()
            .pop()
            .unwrap();
        let last = seg.ciphertext.len() - 1;
        seg.ciphertext[last] ^= 1;
        prof.store()
            .put_segment(&cid, SegmentKind::LogDb, id, &seg)
            .unwrap();
        drop(ch);
        assert!(matches!(
            ChannelState::open(&prof, &cid, b"pp", 4),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn cache_rows_without_a_dag_entry_are_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let mut ch =
            ChannelState::create_with_profile(&prof, "c", b"pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        let cid = ch.channel_id();
        ch.append_text(&prof, "one", 2).unwrap();
        // Delete the log entry but keep the cache row: the row must not render.
        assert!(prof
            .store()
            .delete_segment(&cid, SegmentKind::LogDb, 1)
            .unwrap());
        drop(ch);
        let ch = ChannelState::open(&prof, &cid, b"pp", 3).unwrap();
        assert_eq!(ch.entry_count(), 0);
        assert!(ch.timeline().is_empty());
    }

    #[test]
    fn local_name_and_text_are_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let long = "n".repeat(MAX_LOCAL_NAME_LEN + 1);
        assert!(matches!(
            ChannelState::create_with_profile(&prof, &long, b"pp", 1, Argon2Profile::REDUCED),
            Err(Error::SizeLimitExceeded(_))
        ));
        let mut ch =
            ChannelState::create_with_profile(&prof, "c", b"pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        let big = "x".repeat(crate::node::content::MAX_TEXT_LEN + 1);
        assert!(matches!(
            ch.append_text(&prof, &big, 2),
            Err(Error::SizeLimitExceeded(_))
        ));
        assert_eq!(
            ch.entry_count(),
            0,
            "a rejected message must not advance anything"
        );
    }

    #[test]
    fn locked_channel_refuses_to_seal() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let mut ch =
            ChannelState::create_with_profile(&prof, "c", b"pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        ch.lock_now();
        assert!(matches!(
            ch.append_text(&prof, "after lock", 2),
            Err(Error::AtRestLocked)
        ));
    }
}
