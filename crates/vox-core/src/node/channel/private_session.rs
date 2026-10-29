//! Session payloads live outside the public room log. Each sealed record commits its verified
//! wire, rendered row and first-seen time together with the consumed drive chain.

use std::time::{Duration, Instant};

use super::session_projection::{floor_index, private_index};
use super::*;

pub(crate) mod pending_control;
pub(crate) mod pending_upgrade;

/// Activity for a Session this node has not opened yet: it waits, queued, for the opening.
pub(crate) const SESSION_NOT_OPEN: &str = "the Session is not open yet; its activity waits for it";
use crate::node::sessionstream::{
    Ask, Cursor, Locator, Page, Query as PrivateQuery, Record, MAX_RECORD,
};

const SUPPORT: &str = "vox/private-session-stream/v1";
pub(super) const CONTROL_REFRESHING: &str = "Session control facts are refreshing";
const SEG_LEGACY_DRIVE_GENERATIONS: u64 = 19;
const SEG_PRIVATE_PULLS: u64 = 23;
const WORK_ROWS: usize = 32;
const WORK_BYTES: usize = 1024 * 1024;
const TRUST_CHANGED: &str = "private trust incarnation changed";
type TrustNonce = Option<[u8; crate::atrest::sek::NONCE_LEN]>;

pub(super) fn expired(saved: &Stored, now: u64, retention: (u64, u64)) -> bool {
    let ttl = if saved
        .row
        .as_ref()
        .is_some_and(|row| crate::node::sessions::is_record(&row.body))
    {
        retention.0
    } else {
        retention.1
    };
    let claimed = saved
        .row
        .as_ref()
        .map(|row| row.created_millis)
        .or_else(|| saved.record.legacy_claimed_ms())
        .unwrap_or(saved.first_seen);
    ttl != 0 && saved.first_seen.min(claimed) <= now.saturating_sub(ttl.saturating_mul(1_000))
}

/// Callers only signal that committed public steps need inspection. The actual work is a
/// disk cursor, not one resident hash for every historical step.
#[derive(Default)]
pub(super) struct LegacyPending(bool);
/// What one bounded turn of a Session-record refresh did (ADR-038 FX-24).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionRefresh {
    /// The records are current.
    Complete,
    /// Bounded work was done and more remains: the next turn comes at once.
    Progressed,
    /// Nothing could be done yet; what it waits for, in the words a person reads.
    Waiting(&'static str),
}

/// `VOX_TEST_PRIVATE_POLICY_HOLD_FILE`: while the named file exists, no room's private-Session
/// policy is ready, as while its Session-floor index refreshes. Read only by a `test-knobs`
/// build; a release `vox` holds nothing (#300).
#[cfg(feature = "test-knobs")]
pub const TEST_PRIVATE_POLICY_HOLD_ENV: &str = "VOX_TEST_PRIVATE_POLICY_HOLD_FILE";
#[cfg(feature = "test-knobs")]
fn private_policy_held() -> bool {
    std::env::var_os(TEST_PRIVATE_POLICY_HOLD_ENV)
        .filter(|path| !path.is_empty())
        .is_some_and(|path| std::path::Path::new(&path).exists())
}

/// What one bounded step of a room's private-Session work was; see
/// `ChannelState::prepare_pending_private_upgrade`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionAdvance {
    /// Work this turn did; more may remain.
    Advanced,
    /// Nothing could be done yet: the policy, the floor index or a peer's control receipt.
    Waiting,
    /// Nothing is left.
    Complete,
}

impl LegacyPending {
    pub(super) fn insert(&mut self, _hash: Digest32) {
        self.0 = true;
    }
    pub(super) fn is_empty(&self) -> bool {
        !self.0
    }
}

struct LegacyWork {
    through: u64,
    after: Option<u64>,
    migrating: bool,
}

struct RefreshWork {
    grant: Digest32,
    public: u64,
    private: u64,
    through: u64,
    public_after: Option<(u64, u64, Digest32)>,
    private_after: Option<[u8; 64]>,
    stage: u8,
}

pub(super) fn support_body(room: &Digest32, author: &Digest32) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(3).text(SUPPORT).bytes(room).bytes(author);
    let mut body = GROUP_MSG_SIGN_DOMAIN.as_bytes().to_vec();
    body.extend(e.finish());
    body
}

pub(super) fn is_support(body: &[u8]) -> bool {
    let Some(bytes) = body.strip_prefix(GROUP_MSG_SIGN_DOMAIN.as_bytes()) else {
        return false;
    };
    let mut d = Decoder::new(bytes);
    d.array().ok() == Some(3)
        && d.text().ok() == Some(SUPPORT)
        && d.bytes().is_ok_and(|b| b.len() == 32)
        && d.bytes().is_ok_and(|b| b.len() == 32)
        && d.finish().is_ok()
}

#[derive(Clone, Copy)]
pub(super) struct AttentionOpening {
    pub(super) after: crate::node::api::HistoryCursor,
    pub(super) identity: Digest32,
}

pub(super) struct Stored {
    pub(super) record: Record,
    // An authorized legacy body can arrive before its drive key package is installed.
    pub(super) row: Option<SessionRow>,
    pub(super) first_seen: u64,
    // Own lifecycle records retain the public arrival boundary of their publication.
    // This stays local, is copied on grant refresh, and is never transmitted to peers.
    attention_after: Option<AttentionOpening>,
}

#[derive(Default)]
pub(super) struct PrivateSessions {
    pub(super) legacy_pending: LegacyPending,
    legacy_work: Option<LegacyWork>,
    restoring: bool,
    restore_after: Option<u64>,
    pending_active: bool,
    pending_after: Option<u64>,
    pending_through: u64,
    refresh: Option<RefreshWork>,
    invalid_noted: bool,
    pub(super) upgrading: bool,
    // Verified input from one bounded receive batch, cleared only after its effects commit.
    observed_generations: BTreeMap<Digest32, (Digest32, u64)>,
    controls_import: bool,
    controls_import_after: Option<(usize, u64, Digest32)>,
    controls_after: Option<Digest32>,
    next: u64,
    incarnation: Option<Digest32>,
    cursors: BTreeMap<Digest32, Cursor>,
    observed_tips: BTreeMap<Digest32, Cursor>,
    pulling: BTreeSet<Digest32>,
    attempted: BTreeMap<Digest32, Instant>,
    revision: u64,
    // Admission and open retain a capability recheck. Sparse controls deliver the existing
    // authenticated statement to later members; this obligation cannot force a duplicate.
    // Non-sparse rooms retain their existing live reannouncement behavior.
    support_owed: bool,
    // A missing first announcement must not append from a restored older own head.
    // Only automatic capability publication waits for a current recipient's authenticated
    // own-head discovery; ordinary offline user actions do not.
    support_rediscovery: bool,
}

impl Stored {
    fn bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(7)
            .uint(2)
            .bytes(&self.record.wire())
            .bytes(&self.row.as_ref().map_or_else(Vec::new, session_cache_bytes))
            .uint(self.first_seen);
        if let Some(after) = self.attention_after {
            e.bytes(&after.after.instance)
                .uint(after.after.arrival)
                .bytes(&after.identity);
        } else {
            e.bytes(&[]).uint(0).bytes(&[]);
        }
        Zeroizing::new(e.finish())
    }

    pub(super) fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let fields = d.array()?;
        let version = d.uint()?;
        if !matches!((fields, version), (4, 1) | (7, 2)) {
            return Err(Error::MalformedAtRest("private Session state version"));
        }
        let record = Record::read(d.bytes()?)?;
        let row = match d.bytes()? {
            [] => None,
            bytes => {
                let CacheRow::Session(row) = parse_cache(bytes)? else {
                    return Err(Error::MalformedAtRest("private Session cache kind"));
                };
                Some(row)
            }
        };
        let first_seen = d.uint()?;
        let attention_after = if version == 2 {
            let instance = d.bytes()?;
            let arrival = d.uint()?;
            let identity = d.bytes()?;
            match (instance, identity) {
                ([], []) if arrival == 0 => None,
                (bytes, identity) => Some(AttentionOpening {
                    after: crate::node::api::HistoryCursor {
                        instance: bytes.try_into().map_err(|_| {
                            Error::MalformedAtRest("private Session attention instance")
                        })?,
                        arrival,
                    },
                    identity: identity.try_into().map_err(|_| {
                        Error::MalformedAtRest("private Session attention identity")
                    })?,
                }),
            }
        } else {
            None
        };
        d.finish()?;
        if row.as_ref().is_some_and(|row| {
            row.entry_hash != record.hash() || row.author != record.message.header.author_id
        }) {
            return Err(Error::MalformedAtRest("private Session cache binding"));
        }
        Ok(Self {
            record,
            row,
            first_seen,
            attention_after,
        })
    }
}

impl ChannelState {
    pub(super) fn private_contains_in(
        &self,
        batch: &crate::node::store::Batch<'_>,
        hash: &Digest32,
    ) -> Result<bool> {
        private_index::find_in(batch, &self.sek, &self.channel_id, hash).map(|id| id.is_some())
    }

    pub(super) fn private_id(&self, store: &Store, hash: &Digest32) -> Result<Option<u64>> {
        let snapshot = store.snapshot()?;
        private_index::find(&snapshot, &self.sek, &self.channel_id, hash)
    }

    pub(super) fn private_attention_after(
        &self,
        store: &Store,
        opening: &Digest32,
    ) -> Result<Option<AttentionOpening>> {
        self.private_attention_after_in(&store.snapshot()?, opening)
    }

    pub(super) fn private_attention_after_in(
        &self,
        snapshot: &crate::node::store::Snapshot,
        opening: &Digest32,
    ) -> Result<Option<AttentionOpening>> {
        let Some(id) = private_index::find(snapshot, &self.sek, &self.channel_id, opening)? else {
            return Ok(None);
        };
        let saved = self
            .private_at_in(snapshot, id)?
            .ok_or(Error::MalformedAtRest(
                "Session attention opening source missing",
            ))?;
        if saved.record.hash() != *opening || saved.record.message.header.author_id != self.me() {
            return Err(Error::MalformedAtRest("Session attention opening binding"));
        }
        Ok(saved.attention_after)
    }

    fn private_at_in(
        &self,
        snapshot: &crate::node::store::Snapshot,
        id: u64,
    ) -> Result<Option<Stored>> {
        snapshot
            .get_segment_bounded(
                &self.channel_id,
                SegmentKind::PrivateSession,
                id,
                2 * MAX_RECORD,
            )?
            .map(|segment| self.read_private(id, &segment))
            .transpose()
    }

    pub(super) fn read_private(
        &self,
        id: u64,
        segment: &crate::atrest::store::SealedSegment,
    ) -> Result<Stored> {
        if segment.ciphertext.len()
            > 2 * crate::node::sessionstream::MAX_RECORD + crate::atrest::sek::TAG_LEN
        {
            return Err(Error::MalformedAtRest(
                "private Session stored row exceeds format",
            ));
        }
        Stored::read(&open_segment(
            &self.sek,
            SegmentKind::PrivateSession,
            id,
            segment,
        )?)
    }

    /// A ready sealed observation is a denial boundary, never a grant. Missing evidence is
    /// meaningful only after the published feed has been inspected through its current head.
    pub(super) fn legacy_drive_generation(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<Option<u64>> {
        self.legacy_drive_generation_in(&store.snapshot()?, author)
    }

    pub(super) fn legacy_drive_generation_in(
        &self,
        snapshot: &crate::node::store::Snapshot,
        author: &Digest32,
    ) -> Result<Option<u64>> {
        let fact = private_index::control(snapshot, &self.sek, &self.channel_id, author)?;
        if self.private_sessions.controls_import
            || self.private_sessions.restoring
            || fact.through < self.dag.verified_head(author)
        {
            return Err(Error::StreamRefused("Session control facts are refreshing"));
        }
        Ok(fact
            .generation
            .into_iter()
            .chain(
                self.private_sessions
                    .observed_generations
                    .values()
                    .filter(|(a, _)| a == author)
                    .map(|(_, generation)| *generation)
                    .max(),
            )
            .max())
    }

    /// Called only for an authenticated input in the current bounded receive batch, before
    /// withholding can remove its payload. No uncommitted observation survives a restart.
    pub(super) fn observe_legacy_drive_generation(&mut self, entry: &Entry) -> Result<()> {
        let Some(message) = entry
            .payload
            .as_deref()
            .and_then(|p| GroupMessage::from_wire(p).ok())
        else {
            return Ok(());
        };
        let h = message.header;
        if h.channel_id != drive_channel(&self.channel_id)
            || h.author_id != entry.skeleton.author_id
            || h.epoch != entry.skeleton.epoch
        {
            return Ok(());
        }
        let hash = entry.entry_hash();
        if !self
            .private_sessions
            .observed_generations
            .contains_key(&hash)
            && self.private_sessions.observed_generations.len() >= crate::log::sync::MAX_STAGED
        {
            return Err(Error::SizeLimitExceeded(
                "Session received control observations",
            ));
        }
        self.private_sessions
            .observed_generations
            .insert(hash, (h.author_id, h.chain_id));
        Ok(())
    }

    /// Queue compact evidence with the received entries' own effects. Do not clear on failure.
    pub(super) fn queue_private_generations(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
    ) -> Result<bool> {
        let mut queued = false;
        for (hash, (author, generation)) in &self.private_sessions.observed_generations {
            if self
                .entries
                .in_batch(batch, &self.sek, &self.channel_id)?
                .log_id(hash)?
                .is_some()
            {
                // Drive generations are keys: flush only a transaction that actually queues one
                // (ADR-038 FX-30). Marking an empty migration Ruled caused a needless full sync.
                batch.ruled();
                private_index::observe_control(
                    batch,
                    &self.sek,
                    &self.channel_id,
                    author,
                    private_index::Control {
                        generation: Some(*generation),
                        ..Default::default()
                    },
                )?;
                queued = true;
            }
        }
        Ok(queued)
    }

    pub(super) fn private_controls_committed(&mut self, store: &Store) -> Result<()> {
        let result = (|| {
            let read = self.entries.read(store, &self.sek, &self.channel_id)?;
            let mut after = None;
            loop {
                let next = match after {
                    Some(hash) => self
                        .private_sessions
                        .observed_generations
                        .range((std::ops::Bound::Excluded(hash), std::ops::Bound::Unbounded))
                        .next(),
                    None => self.private_sessions.observed_generations.first_key_value(),
                }
                .map(|(hash, _)| *hash);
                let Some(hash) = next else {
                    break;
                };
                if read.log_id(&hash)?.is_some() {
                    self.private_sessions.observed_generations.remove(&hash);
                }
                after = Some(hash);
            }
            Ok(())
        })();
        if let Err(error) = &result {
            self.private_save_failed(error);
        }
        result
    }

    /// Whether the legacy indexes have scanned every public position. Encrypted legacy drive
    /// generations can live in ordinary Content, so missing bodies leave this predicate pending.
    fn legacy_private_controls_ready(&self, store: &Store) -> Result<bool> {
        if self.private_sessions.controls_import || self.private_sessions.restoring {
            return Ok(false);
        }
        let snapshot = store.snapshot()?;
        for author in self.authors.keys() {
            if private_index::control(&snapshot, &self.sek, &self.channel_id, author)?.through
                < self.dag.verified_head(author)
                || self
                    .floor_author(Transaction::Snapshot(&snapshot), author)?
                    .through
                    < self.dag.verified_head(author)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether the current Session control effects are complete at one author's exact head.
    /// Sparse control proofs deliberately omit ordinary/archive bodies, so their durable receipt
    /// replaces sequence contiguity only for signed Session floors and support declarations.
    pub(super) fn current_session_control_ready(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<bool> {
        if self.private_sessions.controls_import || self.private_sessions.restoring {
            return Ok(false);
        }
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        self.current_session_control_ready_in(&read, author)
    }

    pub(super) fn current_session_control_ready_in(
        &self,
        read: &entry_store::Read<'_>,
        author: &Digest32,
    ) -> Result<bool> {
        pending_upgrade::control_ready(
            read,
            &self.sek,
            &self.channel_id,
            author,
            self.dag.verified_head(author),
            self.private_sessions.controls_import || self.private_sessions.restoring,
        )
    }

    pub(super) fn current_session_controls_ready(&self, store: &Store) -> Result<bool> {
        for author in self.authors.keys() {
            if !self.current_session_control_ready(store, author)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn needs_session_upgrade(&self) -> bool {
        self.private_sessions.upgrading
            || self.private_sessions.restoring
            || self.private_sessions.controls_import
            || !self.private_sessions.legacy_pending.is_empty()
            || self.private_sessions.legacy_work.is_some()
            || self.private_sessions.pending_active
    }

    /// Session upgrade work this node finishes alone: restoring its index, importing its legacy
    /// controls, migrating legacy steps. What can remain after it (an author's control receipt,
    /// a pending private pull) needs a peer, and a peer is reached only once the room is
    /// published (ADR-037 R1): a room's preparation must not wait on it. Measured on the shipped
    /// candidate: a reopened sparse room waited here for a receipt no sync could bring it, and
    /// stayed "preparing history" for as long as the daemon ran.
    pub(crate) fn session_upgrade_local_work(&self) -> bool {
        self.private_sessions.upgrading
            || self.private_sessions.restoring
            || self.private_sessions.controls_import
            || !self.private_sessions.legacy_pending.is_empty()
            || self.private_sessions.legacy_work.is_some()
    }

    // An incomplete governance projection must neither expire saved Session bodies nor
    // release them using a policy sampled before the current canonical room history.
    pub(super) fn private_policy_ready(&self, store: &Store, now: u64) -> Result<bool> {
        #[cfg(feature = "test-knobs")]
        if private_policy_held() {
            // A proof holds the room here, as a Session-floor index behind its authors' heads
            // does at a restart, to stage a peer's key that arrives while the policy is not
            // ready: its pass is saved as pending and not run (ADR-038 FX-26).
            return Ok(false);
        }
        match self.require_governance_ready(store, crate::time::Ms(now)) {
            Ok(_) => Ok(true),
            Err(error)
                if super::governance::refreshing(&error) || floor_index::refreshing(&error) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn supports_private(&mut self, store: &Store, peer: &Digest32) -> Result<bool> {
        if !self.current_session_control_ready(store, peer)? {
            return Err(Error::StreamRefused(CONTROL_REFRESHING));
        }
        Ok(
            private_index::control(&store.snapshot()?, &self.sek, &self.channel_id, peer)?
                .support
                .is_some(),
        )
    }

    pub(super) fn restore_private_sessions(&mut self, store: &Store) -> Result<()> {
        let snapshot = store.snapshot()?;
        let state = private_index::restart(&snapshot, &self.sek, &self.channel_id)?;
        self.private_sessions.controls_import = snapshot
            .get_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_LEGACY_DRIVE_GENERATIONS,
            )?
            .is_some();
        self.private_sessions.controls_import_after = None;
        self.private_sessions.controls_after = None;
        self.private_sessions.restoring = !state.complete;
        self.private_sessions.restore_after = state.after;
        self.private_sessions.next = state.next;
        self.private_sessions.pending_active = state.pending;
        self.private_sessions.pending_after = state.pending_after;
        self.private_sessions.pending_through = state.pending_through;
        // A restart may follow admission but precede the first capability announcement.
        // Retain its recheck; sparse history consults durable support before appending.
        self.private_sessions.support_owed = true;
        self.private_sessions.support_rediscovery = self.uses_sparse_history(store)?;
        self.restore_private_pulls(store)?;
        Ok(())
    }

    pub(crate) fn private_support_discovery_pending(&self) -> bool {
        self.private_sessions.support_rediscovery
    }
    pub(crate) fn private_support_discovery_hint(
        &self,
        store: &Store,
        peer: &Digest32,
    ) -> Result<Option<(Digest32, Digest32, u64)>> {
        if !self.private_sessions.support_rediscovery || self.own_behind || !self.is_member(peer) {
            return Ok(None);
        }
        let read = self.history_read(store)?;
        let Some(id) = read
            .sparse_author(&self.me(), crate::log::history::LogScope::Public)?
            .and_then(|state| state.committed)
        else {
            return Ok(None);
        };
        let head = read
            .history_head(&id)?
            .ok_or(Error::MalformedAtRest("own discovery head missing"))?;
        // This is a fresh connection-scoped metadata probe, distinct from the old
        // Control receipt and exact-target proof operations. Port owns its unavailable
        // disposition; neither durable refusal domain is erased or reinterpreted here.
        Ok(Some((self.me(), id, head.root.leaves)))
    }
    /// Caller carries an actual useful Head response on the exact current recipient port,
    /// after refreshing the higher-head write fence. This is not a universal rollback verdict.
    pub(crate) fn private_support_discovery_reply_valid(
        &self,
        store: &Store,
        hint: crate::node::history_stream::HeadHint,
    ) -> Result<bool> {
        if !self.private_sessions.support_rediscovery || hint.author != self.me() {
            return Ok(false);
        }
        let read = self.history_read(store)?;
        let Some(head) = read.history_head(&hint.head)? else {
            return Ok(false);
        };
        if head.binding.room != self.channel_id
            || head.binding.author != self.me()
            || head.root.leaves != hint.size
            || !read.history_head_accepted(&hint.head, head.binding)?
        {
            return Ok(false);
        }
        Ok(true)
    }

    pub(crate) fn owe_private_support(&mut self) {
        self.private_sessions.support_owed = true;
    }

    // Cursor scope follows held grant generations, not ratchet iterations. A grant saved
    // immediately before a crash invalidates the old cursor even if its reset was not saved.
    fn private_pull_binding(&self) -> Digest32 {
        let mut e = Encoder::new();
        e.array(3)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .array(self.drive.receivers.len());
        for (author, generation) in self.drive.receivers.keys() {
            e.array(2).bytes(author).uint(*generation);
        }
        crate::hash::sha256(&e.finish())
    }

    fn restore_private_pulls(&mut self, store: &Store) -> Result<()> {
        let Some(segment) = store.get_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_PRIVATE_PULLS,
        )?
        else {
            return Ok(());
        };
        if segment.ciphertext.len() > AUTHORS_HARD_LIMIT * 96 + 256 {
            return Err(Error::MalformedAtRest("private pull cursor bound"));
        }
        let bytes = open_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_PRIVATE_PULLS,
            &segment,
        )?;
        let mut d = Decoder::new(&bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("private pull cursor version"));
        }
        self.private_sessions.incarnation = match d.bytes()? {
            [] => None,
            b => Some(
                b.try_into()
                    .map_err(|_| Error::MalformedAtRest("private stream incarnation"))?,
            ),
        };
        let binding: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("private pull grant binding"))?;
        let count = d.array()?;
        if count > AUTHORS_HARD_LIMIT {
            return Err(Error::MalformedAtRest("private pull peer bound"));
        }
        let mut cursors = BTreeMap::new();
        for _ in 0..count {
            if d.array()? != 3 {
                return Err(Error::MalformedAtRest("private pull peer cursor"));
            }
            let peer = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("private pull peer"))?;
            let incarnation = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("private pull incarnation"))?;
            let after = d.uint()?;
            if cursors
                .insert(peer, Cursor { incarnation, after })
                .is_some()
            {
                return Err(Error::MalformedAtRest("duplicate private pull peer"));
            }
        }
        d.finish()?;
        if binding == self.private_pull_binding() {
            self.private_sessions.cursors = cursors;
        }
        Ok(())
    }

    pub(super) fn private_expiry_ready(&self, store: &Store, now: u64) -> Result<bool> {
        if !self.private_policy_ready(store, now)? {
            return Ok(false);
        }
        if self.needs_session_upgrade() {
            return Ok(false);
        }
        Ok(private_index::next_expired(
            &store.snapshot()?,
            &self.sek,
            &self.channel_id,
            now,
            self.effective_retention(),
            self.effective_step_retention(),
        )?
        .is_none())
    }

    fn private_save_failed(&mut self, error: &Error) {
        if super::governance::refreshing(error) || Self::authorization_refreshing(error) {
            return;
        }
        self.poisoned = true;
        self.save_error = Some(error.to_string());
    }
}

#[path = "pending_session.rs"]
pub(crate) mod pending_session;

impl ChannelState {
    /// Cheap actor-side selection before taking a slot, worker or disk envelope. The actor owns
    /// the corresponding attempt token; this snapshot only says which current policy revision a
    /// later room/store operation must still match.
    pub(crate) fn private_pull_intent(&self, peer: Digest32) -> Option<u64> {
        (!self.poisoned
            && !self.drive.receivers.is_empty()
            && !self.private_sessions.pulling.contains(&peer)
            && self
                .private_sessions
                .attempted
                .get(&peer)
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(1)))
        .then_some(self.private_sessions.revision)
    }

    pub(crate) fn start_private_pull(
        &mut self,
        store: &Store,
        peer: Digest32,
        revision: u64,
    ) -> Result<Option<Ask>> {
        if revision != self.private_sessions.revision
            || !self.private_policy_ready(store, self.now_hint)?
        {
            return Ok(None);
        }
        if self.poisoned
            || self.drive.receivers.is_empty()
            || !self.supports_private(store, &peer)?
            || !self.drive_members().contains(&peer)
            || (self.private_sessions.pulling.contains(&peer)
                && self
                    .private_sessions
                    .attempted
                    .get(&peer)
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(30)))
            || self
                .private_sessions
                .attempted
                .get(&peer)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
        {
            return Ok(None);
        }
        self.private_sessions.pulling.insert(peer);
        self.private_sessions.attempted.insert(peer, Instant::now());
        Ok(Some(Ask {
            revision,
            room: self.channel_id,
            epoch: self.epoch,
            query: PrivateQuery::LiveTail,
            cursor: self
                .private_sessions
                .cursors
                .get(&peer)
                .cloned()
                .unwrap_or_default(),
        }))
    }

    /// Cancel only the selected policy revision. A stale task must not clear a newer pull.
    pub(crate) fn cancel_private_pull(&mut self, peer: Digest32, revision: u64) {
        if self.private_sessions.revision == revision {
            self.private_sessions.pulling.remove(&peer);
        }
    }

    /// Stable generation scope for explicit private history. Ratchet iteration advances do
    /// not change it; a durable receiver generation or membership change does.
    pub(crate) fn private_history_scope(
        &self,
        store: &Store,
        peer: &Digest32,
    ) -> Result<(Cursor, Digest32)> {
        self.require_governance_ready(store, crate::time::Ms(self.now_hint))?;
        if self.poisoned
            || !self.drive_members().contains(peer)
            || !self.current_session_controls_ready(store)?
        {
            return Err(Error::StreamRefused(
                "private history authority is unavailable",
            ));
        }
        let boundary = self
            .private_sessions
            .observed_tips
            .get(peer)
            .or_else(|| self.private_sessions.cursors.get(peer))
            .cloned()
            .ok_or(Error::StreamRefused(
                "current private donor boundary is not available yet",
            ))?;
        Ok((boundary, self.private_pull_binding()))
    }

    pub(crate) fn private_history_ask(
        &self,
        store: &Store,
        bounds: crate::node::history_demand::Bounds,
        plan: &crate::node::history_demand::PrivatePlan,
    ) -> Result<Ask> {
        let (boundary, grant) = self.private_history_scope(store, &plan.donor)?;
        if boundary.incarnation != bounds.head || grant != plan.grant || bounds.hi > boundary.after
        {
            return Err(Error::StreamRefused(
                "private history donor or Drive generation changed",
            ));
        }
        let query = if !plan.inventory_done {
            PrivateQuery::ArchiveInventory {
                lo: bounds.lo,
                hi: bounds.hi,
                before: bounds
                    .hi
                    .checked_add(1)
                    .ok_or(Error::SizeLimitExceeded("private history boundary"))?,
            }
        } else {
            PrivateQuery::ArchiveRecords {
                lo: bounds.lo,
                hi: bounds.hi,
                positions: plan.positions.clone(),
            }
        };
        Ok(Ask {
            revision: self.private_sessions.revision,
            room: self.channel_id,
            epoch: self.epoch,
            cursor: Cursor {
                incarnation: bounds.head,
                after: bounds.hi,
            },
            query,
        })
    }

    pub(crate) fn private_recovery_after(&self, peer: &Digest32, incarnation: Digest32) -> u64 {
        self.private_sessions
            .cursors
            .get(peer)
            .filter(|c| c.incarnation == incarnation)
            .map_or(0, |c| c.after)
    }

    pub(super) fn reset_private_pulls(&mut self) {
        self.private_sessions.revision = self.private_sessions.revision.wrapping_add(1);
        self.private_sessions.cursors.clear();
        self.private_sessions.observed_tips.clear();
        self.private_sessions.pulling.clear();
        self.private_sessions.attempted.clear();
    }
}
