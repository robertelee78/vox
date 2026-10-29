//! Revocable committed read publication: compact metadata and a bounded sealed-page cache,
//! never sender keys, receiver chains, or a plaintext history mirror. Ordinary queries own
//! short snapshots; one admitted-save MVCC lease preserves committed roots through pending
//! I/O and failed-write recovery. A client never owns that lease.
use super::*;
use std::sync::{Mutex, Weak};

pub(super) struct ReadFacts {
    pub gen: Arc<std::sync::atomic::AtomicU64>,
    pub generation: u64,
    pub projection_ready: bool,
    pub display_rewrite: u64,
    pub reorder_generation: u64,
    pub body_generation: u64,
    pub classification_revision: u64,
    pub incarnation: u64,
    pub now_hint: u64,
    // Selection-only freshness state, guarded by the publication mutex. It neither
    // changes committed roots nor invalidates a caller's read-authority revision.
    pub member_hello_epoch: std::cell::Cell<u64>,
    pub member_hello_expiry: std::cell::Cell<Option<u64>>,
    channel: Digest32,
    me: Digest32,
    retention: u64,
    step_retention: u64,
    pub verified: BTreeMap<Digest32, u64>,
    members: Vec<Digest32>,
    pub held: BTreeMap<Digest32, u64>,
    pub legacy_cache_trusted: Option<BTreeSet<Digest32>>,
    consent: Option<Arc<governance::ConsentFacts>>,
    governance_ready: bool,
    governance_until: u64,
}
impl ReadFacts {
    pub(super) fn capture(ch: &ChannelState) -> Self {
        let members = ch.members();
        Self {
            gen: ch.gen.clone(),
            generation: ch.gen.load(std::sync::atomic::Ordering::Relaxed),
            projection_ready: !ch.projection_state.pending
                && ch.projection_state.policy
                    == Some([
                        ch.effective_retention(),
                        ch.effective_step_retention(),
                        ch.legacy_sessions.display_revision(),
                    ]),
            display_rewrite: ch.display_rewrite,
            reorder_generation: ch.dag.reorder_generation(),
            body_generation: ch.dag.body_generation(),
            classification_revision: ch.legacy_sessions.display_revision(),
            incarnation: ch.projection_state.incarnation,
            now_hint: ch.now_hint,
            member_hello_epoch: std::cell::Cell::new(0),
            member_hello_expiry: std::cell::Cell::new(None),
            channel: ch.channel_id,
            me: ch.me(),
            retention: ch.effective_retention(),
            step_retention: ch.effective_step_retention(),
            verified: members
                .iter()
                .map(|author| (*author, ch.dag.verified_head(author)))
                .collect(),
            members,
            held: ch.held.clone(),
            legacy_cache_trusted: ch.legacy_cache_trusted.clone(),
            consent: ch.consent_facts().ok(),
            governance_ready: ch.governance_ready,
            governance_until: ch.governance_display.valid_until,
        }
    }
    pub(super) fn channel_id(&self) -> &Digest32 {
        &self.channel
    }
    pub(super) fn me(&self) -> Digest32 {
        self.me
    }
    pub(super) fn members(&self) -> &[Digest32] {
        &self.members
    }
    pub(super) fn effective_retention(&self) -> u64 {
        self.retention
    }
    pub(super) fn effective_step_retention(&self) -> u64 {
        self.step_retention
    }
    pub(super) fn governance_current(&self, now: u64) -> bool {
        self.governance_ready && (self.governance_until == 0 || now < self.governance_until)
    }
    pub(super) fn require_governance_display(&self, now: u64) -> Result<()> {
        if self.governance_current(now) {
            Ok(())
        } else {
            Err(Error::Profile("room governance is refreshing"))
        }
    }
    pub(super) fn consent_facts(&self) -> Result<Arc<governance::ConsentFacts>> {
        self.consent
            .clone()
            .ok_or(Error::Profile("room governance is refreshing"))
    }
    fn same_publication(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.gen, &other.gen)
            && self.generation == other.generation
            && self.projection_ready == other.projection_ready
            && self.display_rewrite == other.display_rewrite
            && self.reorder_generation == other.reorder_generation
            && self.body_generation == other.body_generation
            && self.classification_revision == other.classification_revision
            && self.incarnation == other.incarnation
            && self.retention == other.retention
            && self.step_retention == other.step_retention
            && self.members == other.members
            && self.held == other.held
            && self.verified == other.verified
            && self.legacy_cache_trusted == other.legacy_cache_trusted
            && self.governance_ready == other.governance_ready
            && self.governance_until == other.governance_until
            && match (&self.consent, &other.consent) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
    }
}

struct Publication {
    facts: ReadFacts,
    entries: entry_store::EntryIndex,
    directory_revision: u64,
    cache_only: bool,
    revision: u64,
    /// The pending save owns this one MVCC lease, never a client or cursor.
    pending_snapshot: Option<Arc<crate::node::store::Snapshot>>,
}
impl Publication {
    fn render<'a>(&'a self, store: &Store, sek: &'a Sek) -> Result<entry_store::RenderView<'a>> {
        match &self.pending_snapshot {
            Some(snapshot) => {
                self.entries
                    .render_snapshot(snapshot.clone(), sek, &self.facts.channel)
            }
            None => self.entries.render_view(store, sek, &self.facts.channel),
        }
    }
}

/// One open-room incarnation. Readers have weak SEK/Store access; closing or locking the
/// room revokes the resource and drains its bounded active reads before clearing its cache.
pub(crate) struct ReadResource {
    publication: Mutex<Option<Publication>>,
    sek: crate::atrest::sek::WeakSek,
    store: Weak<Store>,
}
impl std::fmt::Debug for ReadResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadResource").finish_non_exhaustive()
    }
}
impl PartialEq for ReadResource {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}
impl Eq for ReadResource {}

/// The admitted save carries this lease through physical completion and delta installation.
/// Its native snapshot contains sealed storage only and is never held by a waiting client.
/// Failed republication leaves the preceding view with the resource until replacement or revoke.
pub(crate) struct PendingHistoryRead {
    resource: Arc<ReadResource>,
    snapshot: Arc<crate::node::store::Snapshot>,
    release_snapshot: bool,
}
impl PendingHistoryRead {
    /// Keep the prior committed view in its resource until republication or revocation.
    pub(crate) fn retain_saved_read(&mut self) {
        self.release_snapshot = false;
    }
}
impl Drop for PendingHistoryRead {
    fn drop(&mut self) {
        if self.release_snapshot {
            self.resource.release_pending_snapshot(&self.snapshot);
        }
    }
}

impl ReadResource {
    /// Only an admitted physical save may retain the preceding committed snapshot.
    pub(crate) fn has_pending_snapshot(&self) -> bool {
        self.publication
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .is_some_and(|publication| publication.pending_snapshot.is_some())
    }

    pub(crate) fn revision(&self) -> u64 {
        self.publication
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(0, |publication| publication.revision)
    }
    /// A pinned saved view freezes roots, never permission or lifetime policy. Only these
    /// current read-authority facts may overlay it; pending DAG/sender/render facts cannot.
    fn refresh_pinned_authority(&self, ch: &ChannelState, trusted: Option<&BTreeSet<Digest32>>) {
        let mut publication = self.publication.lock().unwrap_or_else(|e| e.into_inner());
        let Some(publication) = publication.as_mut() else {
            return;
        };
        if publication.pending_snapshot.is_none() {
            return;
        }
        let facts = &mut publication.facts;
        let retention = ch.effective_retention();
        let step_retention = ch.effective_step_retention();
        let classification = ch.legacy_sessions.display_revision();
        let projection_ready = facts.projection_ready
            && facts.retention == retention
            && facts.step_retention == step_retention
            && facts.classification_revision == classification
            && !ch.projection_state.pending
            && ch.projection_state.policy == Some([retention, step_retention, classification]);
        let members = ch.members();
        // This pin belongs to the admitted save, whose unpublished delta never enters
        // ChannelState. A failed write closes writer admission, not the already-committed
        // consent projection. Read its current cache directly; rebuilding governance still
        // fails closed, and its current expiry/membership fences remain mandatory below.
        let consent = if ch.governance_ready {
            ch.governance_semantic
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .consent_facts()
        } else {
            None
        };
        let same_consent = match (&facts.consent, &consent) {
            (Some(old), Some(current)) => Arc::ptr_eq(old, current),
            (None, None) => true,
            _ => false,
        };
        let changed = facts.retention != retention
            || facts.step_retention != step_retention
            || facts.classification_revision != classification
            || facts.projection_ready != projection_ready
            || facts.members != members
            || facts.governance_ready != ch.governance_ready
            || facts.governance_until != ch.governance_display.valid_until
            || !same_consent
            || trusted.is_some_and(|trusted| facts.legacy_cache_trusted.as_ref() != Some(trusted));
        facts.retention = retention;
        facts.step_retention = step_retention;
        facts.classification_revision = classification;
        facts.projection_ready = projection_ready;
        facts.members = members;
        facts.consent = consent;
        facts.governance_ready = ch.governance_ready;
        facts.governance_until = ch.governance_display.valid_until;
        facts.now_hint = facts.now_hint.max(ch.now_hint);
        if let Some(trusted) = trusted {
            if facts.legacy_cache_trusted.as_ref() != Some(trusted) {
                facts.legacy_cache_trusted = Some(trusted.clone());
            }
        }
        if changed {
            publication.revision = publication.revision.wrapping_add(1).max(1);
        }
    }

    fn release_pending_snapshot(&self, snapshot: &Arc<crate::node::store::Snapshot>) {
        if let Some(publication) = self
            .publication
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            if publication
                .pending_snapshot
                .as_ref()
                .is_some_and(|pending| Arc::ptr_eq(pending, snapshot))
            {
                publication.pending_snapshot = None;
            }
        }
    }

    pub(crate) fn revoke(&self) {
        self.publication
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }

    /// The closure must finish its bounded read before returning: no snapshot/key escapes.
    /// Both history and read-only attention select against these same committed roots.
    /// Retention is captured with the publication, never sampled from a pending room delta.
    pub(crate) fn with_snapshot<T>(
        &self,
        read: impl FnOnce(&Sek, &entry_store::RenderView<'_>, (u64, u64)) -> Result<T>,
    ) -> Result<T> {
        let publication = self.publication.lock().unwrap_or_else(|e| e.into_inner());
        let publication = publication.as_ref().ok_or(Error::AtRestLocked)?;
        let store = self.store.upgrade().ok_or(Error::AtRestLocked)?;
        self.sek.with(|sek| {
            let rendered = publication.render(&store, sek)?;
            if rendered.directory_revision() != publication.directory_revision {
                return Err(Error::Profile(CHANGED));
            }
            let answer = read(
                sek,
                &rendered,
                (
                    publication.facts.retention,
                    publication.facts.step_retention,
                ),
            )?;
            // A concurrent lock may have wiped the sole owner between decryptions.
            sek.key_bytes()?;
            Ok(answer)
        })
    }

    pub(crate) fn query(
        &self,
        query: Query,
        bytes: usize,
        now_ms: u64,
    ) -> std::result::Result<Reply, String> {
        self.query_inner(None, query, bytes, now_ms)
    }
    pub(crate) fn query_at(
        &self,
        revision: u64,
        query: Query,
        bytes: usize,
        now_ms: u64,
    ) -> std::result::Result<Reply, String> {
        self.query_inner(Some(revision), query, bytes, now_ms)
    }
    fn query_inner(
        &self,
        revision: Option<u64>,
        query: Query,
        bytes: usize,
        now_ms: u64,
    ) -> std::result::Result<Reply, String> {
        let mut publication = self.publication.lock().unwrap_or_else(|e| e.into_inner());
        let publication = publication
            .as_mut()
            .ok_or_else(|| "the room is locked".to_owned())?;
        if revision.is_some_and(|revision| revision != publication.revision) {
            return Err(CHANGED.to_owned());
        }
        let store = self
            .store
            .upgrade()
            .ok_or_else(|| "the node has stopped".to_owned())?;
        publication.facts.now_hint = publication.facts.now_hint.max(now_ms);
        let result = self.sek.with(|sek| {
            let rendered = publication.render(&store, sek)?;
            if rendered.directory_revision() != publication.directory_revision {
                return Err(Error::Profile(CHANGED));
            }
            let view = View {
                ch: &publication.facts,
                provisional: !publication.facts.governance_current(now_ms),
                rendered,
            };
            let answer = if publication.cache_only {
                view.accepted_cache_answer(query, bytes)
            } else {
                view.saved_answer(query, bytes)
            }
            .map_err(|failure| match failure {
                Failure::Storage(error) => error,
                Failure::Request(why) => Error::Profile(why),
            })?;
            sek.key_bytes()?;
            Ok(answer)
        });
        result.map_err(|error| error.to_string())
    }
}

impl ChannelState {
    /// Publish only after the committed mutation has been applied to this room. A pending
    /// authored transaction leaves the preceding publication untouched.
    pub(crate) fn publish_history_read(&mut self, store: Arc<Store>) -> Result<Arc<ReadResource>> {
        self.publish_history_read_inner(store, None, false)
    }
    pub(crate) fn publish_history_read_trusted(
        &mut self,
        store: Arc<Store>,
        trusted: &BTreeSet<Digest32>,
    ) -> Result<Arc<ReadResource>> {
        self.publish_history_read_inner(store, Some(trusted), false)
    }
    fn publish_history_read_inner(
        &mut self,
        store: Arc<Store>,
        trusted: Option<&BTreeSet<Digest32>>,
        retain_snapshot: bool,
    ) -> Result<Arc<ReadResource>> {
        if self.poisoned {
            // A definitive failed write cannot certify whatever roots redb exposes after
            // its error. The actor retains this exact save's pre-preparation MVCC lease
            // until reopen/revoke; poisoned writers cannot grow that retained view.
            // This is not a fallback for an ordinary directory mismatch.
            if let Some(resource) = &self.history_read {
                resource.refresh_pinned_authority(self, trusted);
            }
            return Err(self.save_failure());
        }
        if self.post_pending() {
            if retain_snapshot {
                return Err(Error::Profile(
                    "room publication is busy; retry this operation",
                ));
            }
            let resource = self
                .history_read
                .clone()
                .ok_or(Error::Profile("saved history publication unavailable"))?;
            resource.refresh_pinned_authority(self, trusted);
            return Ok(resource);
        }
        let entries = self.entries.fork_reader();
        // Admission derives its publication and retained roots from one MVCC generation.
        let pending_snapshot = if retain_snapshot {
            Some(Arc::new(store.snapshot()?))
        } else {
            None
        };
        let rendered = match &pending_snapshot {
            Some(snapshot) => {
                entries.render_snapshot(Arc::clone(snapshot), &self.sek, &self.channel_id)?
            }
            None => entries.render_view(&store, &self.sek, &self.channel_id)?,
        };
        let directory_revision = rendered.directory_revision();
        let cache_only = rendered.legacy_cache_only();
        drop(rendered);
        let mut publication = Publication {
            facts: ReadFacts::capture(self),
            entries,
            directory_revision,
            cache_only,
            revision: 1,
            pending_snapshot,
        };
        if let Some(trusted) = trusted {
            publication.facts.legacy_cache_trusted = Some(trusted.clone());
        }
        if let Some(resource) = &self.history_read {
            let mut current = resource
                .publication
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(previous) = current.as_mut() {
                if trusted.is_none() {
                    publication.facts.legacy_cache_trusted =
                        previous.facts.legacy_cache_trusted.clone();
                }
                publication.facts.now_hint =
                    publication.facts.now_hint.max(previous.facts.now_hint);
                publication
                    .facts
                    .member_hello_epoch
                    .set(previous.facts.member_hello_epoch.get());
                publication
                    .facts
                    .member_hello_expiry
                    .set(previous.facts.member_hello_expiry.get());
                let changed = publication.directory_revision != previous.directory_revision
                    || publication.cache_only != previous.cache_only
                    || !publication.facts.same_publication(&previous.facts);
                publication.revision = if changed {
                    previous.revision.wrapping_add(1).max(1)
                } else {
                    previous.revision
                };
                previous
                    .entries
                    .copy_reader_visibility(&publication.entries);
                std::mem::swap(&mut publication.entries, &mut previous.entries);
            }
            *current = Some(publication);
            return Ok(resource.clone());
        }
        let resource = Arc::new(ReadResource {
            publication: Mutex::new(Some(publication)),
            sek: self.sek.reader(),
            store: Arc::downgrade(&store),
        });
        self.history_read = Some(resource.clone());
        Ok(resource)
    }
    pub(crate) fn pin_history_read(&mut self, store: Arc<Store>) -> Result<PendingHistoryRead> {
        let resource = self.publish_history_read_inner(store, None, true)?;
        let snapshot = resource
            .publication
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .and_then(|publication| publication.pending_snapshot.clone())
            .ok_or(Error::Profile("saved history snapshot unavailable"))?;
        Ok(PendingHistoryRead {
            resource,
            snapshot,
            release_snapshot: true,
        })
    }
    pub(crate) fn history_read_resource(&self) -> Option<Arc<ReadResource>> {
        self.history_read.clone()
    }
}
