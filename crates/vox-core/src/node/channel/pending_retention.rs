//! Bounded maintenance candidates keep the published room unchanged during native saves.
use super::*;
use crate::atrest::sek::WeakSek;
use crate::log::entry::EntryWrite;
use crate::node::channel::entry_store::sparse::Obligation;

/// Existing retention turn order. The actor retains this cursor across owned completions;
/// backfill precedes Prune and the authored checkpoint follows HistoricalKeys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    OwedCleanup,
    KeyDebt,
    Projection,
    Prune,
    PrivateExpiry,
    HistoricalKeys,
    Signatures,
}

struct Pruned {
    entry: Entry,
    tracked: Tracked,
    shed_signature: bool,
    legacy_kind: Option<bool>,
}

/// `test-knobs` mutant: a lengthening is projected without keeping what the shorter lifetime
/// had made due. Never selectable in a build without the feature.
fn lengthening_unfenced() -> bool {
    #[cfg(feature = "test-knobs")]
    if std::env::var_os("VOX_TEST_RETENTION_FLOOR_MUTANT").is_some() {
        eprintln!("test-knobs: retention floor mutant engaged: a lengthening un-dues what was due");
        return true;
    }
    false
}

/// The `test-knobs` switch of the checkpoint walk's mutants (`checkpoint_proof`'s quiet-room act).
#[cfg(feature = "test-knobs")]
const CHECKPOINT_MUTANT: &str = "VOX_TEST_CHECKPOINT_MUTANT";

/// `test-knobs` mutant (`VOX_TEST_CHECKPOINT_MUTANT=own-uncounted`): the walk does not count this
/// node's own earlier checkpoint, ledger 145's fault, so an idle node writes the same one again on
/// every turn. Never selectable in a build without the feature.
#[cfg_attr(not(feature = "test-knobs"), allow(unused_variables))]
fn own_checkpoint_uncounted(named: u64) -> bool {
    #[cfg(feature = "test-knobs")]
    if std::env::var(CHECKPOINT_MUTANT).as_deref() == Ok("own-uncounted") {
        eprintln!(
            "test-knobs: own-checkpoint-uncounted mutant engaged: this node's own checkpoint \
             naming {named} closes nothing"
        );
        return true;
    }
    false
}

/// `test-knobs` mutant (`VOX_TEST_CHECKPOINT_MUTANT=unwritten`): a checkpoint the walk owes is
/// not written. Never selectable in a build without the feature.
#[cfg_attr(not(feature = "test-knobs"), allow(unused_variables))]
fn checkpoint_unwritten(seq: u64) -> bool {
    #[cfg(feature = "test-knobs")]
    if std::env::var(CHECKPOINT_MUTANT).as_deref() == Ok("unwritten") {
        eprintln!(
            "test-knobs: checkpoint-unwritten mutant engaged: the checkpoint owed at {seq} is \
             not written"
        );
        return true;
    }
    false
}

/// `test-knobs` hold: while the file `VOX_TEST_HOLD_RETENTION_REMOVAL_FILE` names exists, no
/// cleanup removes anything, messages or private Session items. Its turns still complete, so the
/// room opens and answers as usual, and the room's Session work does not wait for a removal
/// (`prepare_pending_private_upgrade`). Never selectable in a build without the feature.
pub(crate) fn removal_held() -> bool {
    #[cfg(feature = "test-knobs")]
    if let Some(path) = std::env::var_os("VOX_TEST_HOLD_RETENTION_REMOVAL_FILE") {
        return std::path::Path::new(&path).exists();
    }
    false
}

/// `test-knobs` hold: while the file `VOX_TEST_HOLD_LENGTHENING_FILE` names exists, a projection
/// turn that would switch to a longer lifetime waits, and marks `<file>.engaged`: the longer
/// lifetime is configured and the shorter one still in force. Never in a build without the
/// feature.
fn lengthening_held() -> bool {
    #[cfg(feature = "test-knobs")]
    if let Some(path) = std::env::var_os("VOX_TEST_HOLD_LENGTHENING_FILE") {
        let path = std::path::PathBuf::from(path);
        if path.exists() {
            let _ = std::fs::write(
                path.with_extension("engaged"),
                b"lengthening projection held",
            );
            return true;
        }
    }
    false
}

enum Work {
    Cleanup {
        remove: Vec<(Digest32, u64, Option<Digest32>)>,
        /// "Not received yet" rows of signed messages to write (`Some`: owed to this node, no
        /// row yet) or take away (`None`: refused as not for this node, or not decidable yet),
        /// and the removal generation those decisions were made under. The missing position
        /// itself is kept, so an undecided one is decided again on a later turn.
        rows: Vec<(Digest32, Option<(u64, u64)>)>,
        generation: u64,
        next: Option<(Digest32, u64)>,
        /// The governance turn this page was decided in (`None`: no current authority view),
        /// and whether it is the first page of a pass (`history::OwedDecided`).
        turn: Option<u64>,
        first: bool,
    },
    KeyDebt {
        debts: Vec<Obligation>,
        more: bool,
    },
    Projection {
        state: history::State,
        before: Vec<u8>,
        owed: Vec<(Digest32, Option<(u64, u64)>)>,
        idle: bool,
        /// The lifetimes, fences or stop instant changed: flushed (`history::State::retention`).
        flush: bool,
    },
    Prune {
        due: Vec<Pruned>,
        /// `due` is everything due now: once removed, no stored row is covered.
        complete: bool,
        legacy: legacy_session::LegacyProjectionContext,
    },
    /// `None`: removal held (`removal_held`).
    PrivateExpiry(Option<crate::node::retention::Expiry>),
    HistoricalKeys {
        state: own_historical_keys::Retirement,
        retire: Option<([u8; 64], u64)>,
    },
    Signatures {
        entries: Vec<Entry>,
        swept: Vec<(Digest32, u64)>,
    },
}

pub(crate) struct PendingCheckpoint {
    append: pending_text::PendingText,
    sek: WeakSek,
    room: Digest32,
    me: Digest32,
    already: u64,
    head: u64,
    last_pruned_at: u64,
    idle_seconds: u64,
    now: crate::time::Ms,
}

pub(crate) struct PendingRetention {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    sek: WeakSek,
    index: entry_store::EntryIndex,
    next_log_id: u64,
    now: u64,
    work: Work,
    pin: Option<history::PendingHistoryRead>,
}

#[derive(Default)]
pub(crate) struct Installed {
    pub(crate) pruned: usize,
    /// The private expiry walked everything due and removed it (`history::State::clean`).
    pub(crate) private_clean: bool,
    pub(crate) pruned_hashes: Vec<Digest32>,
    pub(crate) changed: bool,
    pub(crate) more_key_debt: bool,
    pub(crate) projection_ready: bool,
}

pub(crate) struct CompletedRetention {
    pending: PendingRetention,
    pub(crate) result: Result<Installed>,
    committed: bool,
    body_changes: u64,
    display_changed: bool,
}

impl CompletedRetention {
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.pin.take()
    }

    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.pending.owner, owner)
            && channel.channel_id == self.pending.room
            && channel.epoch == self.pending.epoch
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
}

type HistoricalRetirement = (own_historical_keys::Retirement, Option<([u8; 64], u64)>);

impl ChannelState {
    /// Policy setters cleaned settled debt at the room's prior observation time. The
    /// ordinary sweep advances that time separately; neither cleanup invents a clock.
    pub(crate) fn retention_cleanup_hint(&self) -> crate::time::Ms {
        crate::time::Ms(self.now_hint)
    }

    /// Read-only preparation, apart from the shared publication reservation and a lengthening's
    /// switch (`Self::switch_lifetimes`). Policy cleanup can remove settled debt before
    /// governance is ready; expiry still needs current policy. `fresh` is this node's clock now:
    /// `now` may be a turn's retained instant.
    pub(crate) fn prepare_pending_retention(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        step: Step,
        now: crate::time::Ms,
        fresh: crate::time::Ms,
    ) -> Result<Option<PendingRetention>> {
        if self.poisoned.get() {
            return Err(self.save_failure());
        }
        if self.post_pending() || self.legacy_cache_only(store)? {
            return Ok(None);
        }
        if step != Step::OwedCleanup {
            match self.require_governance_ready(store, now) {
                Ok(_) if self.governance_display_current(now.get()) => {}
                Ok(_) => return Ok(None),
                Err(error) if governance::refreshing(&error) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        let now_ms = self.now_hint.max(now.get());
        if self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .publication_busy()
        {
            return Ok(None);
        }
        if step == Step::Projection && self.lengthening_waits() {
            if lengthening_held() {
                return Ok(None);
            }
            let fresh = fresh.get().max(now_ms);
            if let Err(error) = self.with_readers_held(store, |room, batch, watermark| {
                room.switch_lifetimes(batch, fresh.max(watermark))
            }) {
                self.poison(&error);
                return Err(error);
            }
        }
        let retention = (self.effective_retention(), self.effective_step_retention());
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        let work = match step {
            Step::OwedCleanup => {
                let start = self.projection_state.cleanup_cursor;
                let (positions, next) = read.missing_page(start, 64)?;
                // ADR-036 H-4: a signed message's body is owed until held, expired or refused as
                // not for this node, by this node's own decision; undecided, its row is taken
                // away and its missing position kept for a later turn. Without a current
                // authority view nothing is decided here.
                let generation = self.removal_generation(store)?;
                let view = match self.checked_governance(store, now_ms) {
                    Ok(view) => Some(view),
                    Err(error) if governance::refreshing(&error) => None,
                    Err(error) => return Err(error),
                };
                let turn = view.is_some().then(|| self.owed_decided.turn());
                let mut rendered = None;
                let mut remove = Vec::new();
                let mut rows = Vec::new();
                for (author, seq) in positions {
                    let entry = read.get(&author, seq)?;
                    // The place's age and the lifetimes and fences in force: a body-less place
                    // expires as its body would, by its lifetime or by a lengthening's fence.
                    let age = match entry.as_ref() {
                        Some(entry) if entry.payload.is_none() => {
                            Some(self.place_age_in(read.transaction(), entry)?)
                        }
                        _ => None,
                    };
                    let expiry = self.expiry();
                    let keep = match (entry.as_ref(), age) {
                        (Some(entry), Some(age)) => {
                            self.private_id(store, &entry.entry_hash())?.is_none()
                                && !(self.governance_display_current(now_ms)
                                    && history::owed_window(entry, now_ms, expiry, age).is_none())
                        }
                        _ => false,
                    };
                    let signed_content = entry.as_ref().is_some_and(|entry| {
                        entry.skeleton.v2.as_ref().is_some_and(|v2| {
                            v2.kind == crate::log::history::SignedEntryKind::Content
                        })
                    });
                    let owed = match (&view, entry.as_ref()) {
                        (Some(view), Some(entry)) if keep && signed_content => {
                            self.signed_body_owed_to_me(view, generation, entry, now_ms)?
                        }
                        _ => None,
                    };
                    if !keep {
                        remove.push((author, seq, entry.map(|entry| entry.entry_hash())));
                        continue;
                    }
                    let (Some(entry), Some(age)) = (&entry, age) else {
                        continue;
                    };
                    if !signed_content {
                        continue;
                    }
                    let owed = match owed {
                        Some(owed) => owed,
                        None if history::owed_rows_shown_undecided() => continue,
                        None => false,
                    };
                    if owed && history::owed_rows_unwritten() {
                        continue;
                    }
                    let hash = entry.entry_hash();
                    if rendered.is_none() {
                        rendered = Some(self.entries.render_view(
                            store,
                            &self.sek,
                            &self.channel_id,
                        )?);
                    }
                    let written = match &rendered {
                        Some(view) => view.is_owed(&hash)?,
                        None => false,
                    };
                    match (owed, written) {
                        (true, false) => {
                            if let Some(window) = history::owed_window(entry, now_ms, expiry, age) {
                                rows.push((hash, Some(window)));
                            }
                        }
                        (false, true) => rows.push((hash, None)),
                        _ => {}
                    }
                }
                Work::Cleanup {
                    remove,
                    rows,
                    generation,
                    next,
                    turn,
                    first: start.is_none(),
                }
            }
            Step::KeyDebt => {
                let debts = if retention.0 == 0 {
                    Vec::new()
                } else {
                    read.expired_key_debts(
                        now_ms.saturating_sub(retention.0.saturating_mul(1_000)),
                        16,
                    )?
                };
                for debt in &debts {
                    let Some((head, entry)) =
                        read.history_validated_header(&debt.author, debt.from)?
                    else {
                        return Err(Error::MalformedAtRest("expired key debt source missing"));
                    };
                    let log = read
                        .log_id(&debt.object)?
                        .ok_or(Error::MalformedAtRest("expired key debt log missing"))?;
                    let first_seen = history_first_seen_at(
                        &store.snapshot()?,
                        &self.sek,
                        &self.channel_id,
                        log,
                    )?;
                    if debt.from != debt.through
                        || head != debt.head
                        || entry.entry_hash() != debt.object
                        || !entry.skeleton.v2.as_ref().is_some_and(|v| {
                            v.kind == crate::log::history::SignedEntryKind::KeyPackage
                        })
                        || !expired_at(
                            entry.skeleton.claimed_ms.min(first_seen),
                            now_ms,
                            retention.0,
                        )
                    {
                        return Err(Error::MalformedAtRest("expired key debt binding"));
                    }
                }
                let more = debts.len() == 16;
                Work::KeyDebt { debts, more }
            }
            Step::Projection => {
                let mut state = self.projection_state.clone();
                let before = state.to_bytes();
                // The configured lifetimes, not those in force: this turn is what makes them so.
                let configured = self.configured_lifetimes();
                let policy = [
                    configured[0],
                    configured[1],
                    self.legacy_sessions.display_revision(),
                ];
                let idle = if state.policy == Some(policy) && !state.pending && state.stopped == 0 {
                    if let Ok(rendered) =
                        self.entries.render_view(store, &self.sek, &self.channel_id)
                    {
                        rendered.next_owed_expiry()?.is_none_or(|at| at > now_ms)
                    } else {
                        false
                    }
                } else {
                    false
                };
                // A longer lifetime was switched to before this read (`switch_lifetimes`); what
                // is left is a shorter one, or none: it applies once this turn's save, flushed,
                // is installed.
                // This node is running again: a later stop says when for itself.
                state.stopped = 0;
                if state.policy != Some(policy) {
                    state.policy = Some(policy);
                    state.pending = true;
                    state.cursor = None;
                    state.through = None;
                }
                let mut owed = Vec::new();
                if state.pending {
                    // A signed message's row stands only where its body is for this node
                    // (ADR-036 H-4); undecided, none, and the owed sweep writes it later.
                    let decider = match self.checked_governance(store, now_ms) {
                        Ok(view) => Some((view, self.removal_generation(store)?)),
                        Err(error) if governance::refreshing(&error) => None,
                        Err(error) => return Err(error),
                    };
                    let (positions, next) =
                        read.missing_page(state.cursor, entry_store::DUE_ENTRIES)?;
                    let mut through = false;
                    for (author, seq) in positions {
                        if state.through.is_some_and(|end| (author, seq) > end) {
                            through = true;
                            break;
                        }
                        state.cursor = Some((author, seq));
                        let entry = read
                            .get(&author, seq)?
                            .ok_or(Error::MalformedAtRest("owed entry missing"))?;
                        let hash = entry.entry_hash();
                        let signed_owed = match (&entry.skeleton.v2, &decider) {
                            (None, _) => Some(true),
                            (Some(_), Some((view, generation))) => {
                                self.signed_body_owed_to_me(view, *generation, &entry, now_ms)?
                            }
                            (Some(_), None) => None,
                        };
                        let visibility = if entry.payload.is_some()
                            || signed_owed != Some(true)
                            || (entry.skeleton.v2.is_some() && history::owed_rows_unwritten())
                            || self.private_id(store, &hash)?.is_some()
                            || self.legacy_is_session_in(read.transaction(), &hash)?
                        {
                            None
                        } else {
                            // The lifetimes this turn saves and the fences it keeps: a place a
                            // shorter lifetime had expired stays expired under a longer one.
                            let expiry = crate::node::retention::Expiry {
                                ttl: configured,
                                fence: state.fence,
                            };
                            let age = self.place_age_in(read.transaction(), &entry)?;
                            history::owed_window(&entry, now_ms, expiry, age)
                        };
                        owed.push((hash, visibility));
                    }
                    state.pending = !through
                        && next.is_some()
                        && state.through.is_none_or(|end| state.cursor < Some(end));
                }
                Work::Projection {
                    flush: state.retention() != self.projection_state.retention(),
                    state,
                    before,
                    owed,
                    idle,
                }
            }
            Step::Prune => {
                let held = removal_held();
                let (selected, more) = if held {
                    (Vec::new(), true)
                } else {
                    read.retention_due(
                        now_ms,
                        retention.0,
                        retention.1,
                        self.walk_expiry(0).fence,
                        entry_store::DUE_ENTRIES,
                    )?
                };
                let selected_len = selected.len();
                let mut due = Vec::new();
                let mut bytes = 0usize;
                for (hash, tracked) in selected {
                    let entry = self
                        .dag
                        .get_by_hash(&read, &hash)?
                        .ok_or(Error::MalformedAtRest("pruned entry missing"))?;
                    let size = entry.payload.as_ref().map_or(0, Vec::len);
                    if !due.is_empty()
                        && bytes.saturating_add(size) > entry_store::DUE_PAYLOAD_BYTES
                    {
                        break;
                    }
                    bytes = bytes.saturating_add(size);
                    if entry.payload.as_deref().is_some_and(retained_control) {
                        return Err(Error::MalformedAtRest(
                            "retained control indexed for expiry",
                        ));
                    }
                    let shed_signature = retention.0 != 0
                        && self
                            .dag
                            .checkpoint(&entry.skeleton.author_id)
                            .is_some_and(|(below, _)| entry.skeleton.seq <= below);
                    let legacy_kind = self.available_legacy_kind(&entry);
                    due.push(Pruned {
                        entry,
                        tracked,
                        shed_signature,
                        legacy_kind,
                    });
                }
                // Everything due was selected and fits this pass: once it is removed, no stored
                // row is covered by the fences any more.
                let complete = !more && due.len() == selected_len;
                Work::Prune {
                    due,
                    complete,
                    legacy: self.legacy_projection_context(store)?,
                }
            }
            Step::PrivateExpiry => {
                if !self.private_policy_ready(store, now_ms)? {
                    return Ok(None);
                }
                Work::PrivateExpiry((!removal_held()).then(|| self.walk_expiry(1)))
            }
            Step::HistoricalKeys => {
                let (state, retire) = self.prepare_historical_retirement(store, now_ms)?;
                Work::HistoricalKeys { state, retire }
            }
            Step::Signatures => {
                if retention == (0, 0) {
                    return Ok(None);
                }
                let (entries, swept) = self
                    .dag
                    .retention_signature_page(&read, SIGNATURE_SWEEP_PAGE)?;
                Work::Signatures { entries, swept }
            }
        };
        drop(read);
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(Some(PendingRetention {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            index: entry_store::EntryIndex::default(),
            next_log_id: self.next_log_id,
            now: now_ms,
            work,
            pin: Some(pin),
        }))
    }

    /// Whether a configured lifetime keeps longer than the saved one: a lengthening waits for
    /// its switch.
    pub(crate) fn lengthening_waits(&self) -> bool {
        let configured = self.configured_lifetimes();
        self.projection_state.policy.is_some_and(|saved| {
            (0..2).any(|kind| crate::node::retention::longer(saved[kind], configured[kind]))
        })
    }

    /// A room about to open without a projection turn first (a join, new or resumed): save,
    /// flushed, the lifetimes it is about to apply, so that no read or arrival ever applies
    /// lifetimes its saved record does not name. Nothing reads it yet, so it switches at once.
    pub(crate) fn save_lifetimes_before_opening(&mut self, store: &Store, now: u64) -> Result<()> {
        let configured = self.configured_lifetimes();
        let policy = [
            configured[0],
            configured[1],
            self.legacy_sessions.display_revision(),
        ];
        if self.projection_state.policy == Some(policy) && self.projection_state.stopped == 0 {
            return Ok(());
        }
        self.switch_lifetimes(store.batch()?, self.now_hint.max(now))
    }

    /// Switch this room to its configured lifetimes, longer ones among them, with readers held
    /// out (`Self::with_readers_held`): save the lifetimes and the fence of what the shorter
    /// ones had made due up to `boundary`, flushed, in `batch`, then install them. `boundary` is
    /// no earlier than any clock the shorter lifetimes were applied at here: a reader's (the
    /// publication's watermark), or a reader, arrival or cleanup under the room lock (this
    /// node's clock now; all of them ran before this turn, one at a time). A kill leaves either
    /// the old record, under which readers still were, or this one. Opening after a clean stop,
    /// the fence runs until that stop instead (`history::State::fence_in_force`). The caller
    /// begins `batch` before it takes the publication: the writer always comes first.
    pub(crate) fn switch_lifetimes(
        &mut self,
        mut batch: crate::node::store::Batch<'_>,
        boundary: u64,
    ) -> Result<()> {
        let configured = self.configured_lifetimes();
        let mut state = self.projection_state.clone();
        let fence = state.fence_in_force(configured, boundary);
        if !lengthening_unfenced() {
            state.fence = fence;
        }
        state.policy = Some([
            configured[0],
            configured[1],
            self.legacy_sessions.display_revision(),
        ]);
        state.pending = true;
        state.cursor = None;
        state.through = None;
        state.stopped = 0;
        // A new pair may cover stored rows: the next cleanup passes walk for them again.
        state.clean = [false; 2];
        batch.ruled();
        let mut index =
            entry_store::EntryIndex::default().write(&mut batch, &self.sek, &self.channel_id)?;
        index.note_projection(state.to_bytes())?;
        index.seal()?;
        batch.commit()?;
        self.entries.committed();
        self.projection_state = state;
        self.now_hint = self.now_hint.max(boundary);
        Ok(())
    }

    fn prepare_historical_retirement(
        &self,
        store: &Store,
        now: u64,
    ) -> Result<HistoricalRetirement> {
        let me = self.me();
        let head = self.dag.verified_head(&me);
        let retention = (self.effective_retention(), self.effective_step_retention());
        let generation = self.entries.commit_generation();
        let mut scan = self.historical_retirement.clone();
        if self.own_behind {
            scan.reset();
            return Ok((scan, None));
        }
        // Another epoch or retention policy can change any verdict: everything again. A commit
        // in the room, an own post or a wake can change only the position each key stopped at
        // (a body arrived, an effect finished, a body expired): every key again, each from its
        // place (`Retirement::checked`), never from position 1.
        if scan.epoch != self.epoch || scan.retention != retention {
            scan.reset();
            scan.epoch = self.epoch;
            scan.retention = retention;
        }
        if scan.head != head
            || scan.entry_generation != generation
            || scan.wake_at.is_some_and(|at| now >= at)
        {
            scan.new_pass();
            scan.head = head;
            scan.entry_generation = generation;
        }
        if scan.complete || head == 0 {
            return Ok((scan, None));
        }
        let (key, id, mut next) = match scan.current {
            Some(current) => current,
            None => {
                let Some((key, id)) = own_historical_keys::first_after(
                    &store.snapshot()?,
                    &self.sek,
                    &self.channel_id,
                    scan.after,
                )?
                else {
                    scan.complete = true;
                    return Ok((scan, None));
                };
                (
                    key,
                    id,
                    scan.checked.get(&key).map_or(1, |through| through + 1),
                )
            }
        };
        let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
        let Some(feed) = self.dag.feed(&me) else {
            return Ok((scan, None));
        };
        if feed
            .get(&entries, head)?
            .is_none_or(|entry| entry.skeleton.epoch != self.epoch)
        {
            scan.complete = true;
            return Ok((scan, None));
        }
        let epoch = u64::from_be_bytes(
            key[..8]
                .try_into()
                .map_err(|_| Error::MalformedAtRest("own historical epoch key width"))?,
        );
        let chain = u64::from_be_bytes(
            key[8..16]
                .try_into()
                .map_err(|_| Error::MalformedAtRest("own historical chain key width"))?,
        );
        if epoch >= self.epoch {
            scan.after = Some(key);
            scan.current = None;
            return Ok((scan, None));
        }
        for _ in 0..64 {
            if next > head {
                scan.checked.remove(&key);
                scan.after = Some(key);
                scan.current = None;
                return Ok((scan, Some((key, id))));
            }
            let Some((_source, header)) = entries.history_validated_header(&me, next)? else {
                scan.checked.insert(key, next - 1);
                scan.after = Some(key);
                scan.current = None;
                return Ok((scan, None));
            };
            next += 1;
            if header.skeleton.epoch != epoch
                || !header
                    .skeleton
                    .v2
                    .as_ref()
                    .is_some_and(|v2| v2.kind == crate::log::history::SignedEntryKind::Content)
            {
                continue;
            }
            let hash = header.entry_hash();
            let entry = entries.history_entry(&hash)?;
            let Some(payload) = entry.as_ref().and_then(|entry| entry.payload.as_deref()) else {
                if entries.history_effect_finished(&hash)? {
                    if let Some(log) = entries.log_id(&hash)? {
                        let first_seen = history_first_seen_at(
                            &store.snapshot()?,
                            &self.sek,
                            &self.channel_id,
                            log,
                        )?;
                        let base = header.skeleton.claimed_ms.min(first_seen);
                        if expired_at(base, now, retention.0) && expired_at(base, now, retention.1)
                        {
                            continue;
                        }
                        if retention.0 != 0 && retention.1 != 0 {
                            let due = base
                                .saturating_add(retention.0.max(retention.1).saturating_mul(1_000));
                            if due > now {
                                scan.wait_until(due);
                            }
                        }
                    }
                }
                scan.checked.insert(key, next - 2);
                scan.after = Some(key);
                scan.current = None;
                return Ok((scan, None));
            };
            let message = GroupMessage::from_wire(payload)?;
            if message.header.author_id != me || message.header.epoch != epoch {
                return Err(Error::MalformedAtRest(
                    "own historical receiver entry binding",
                ));
            }
            if message.header.channel_id == self.channel_id && message.header.chain_id == chain {
                scan.checked.insert(key, next - 2);
                scan.after = Some(key);
                scan.current = None;
                return Ok((scan, None));
            }
        }
        scan.checked.insert(key, next - 1);
        scan.current = Some((key, id, next));
        Ok((scan, None))
    }

    /// Reserve the existing authored capsule without scanning the expired backlog under the
    /// room lock. Selection and the ordinary durable control append run on its native worker.
    pub(crate) fn prepare_pending_checkpoint(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        me: Digest32,
        now: crate::time::Ms,
    ) -> Result<Option<PendingCheckpoint>> {
        if self.poisoned.get()
            || !self.governance_display_current(now.get())
            || (self.room_retention() == 0 && self.room_step_retention() == 0)
        {
            return Ok(None);
        }
        let head = self.dag.feed(&me).map_or(0, |feed| feed.max_seq());
        let already = self.dag.checkpoint(&me).map_or(0, |(seq, _)| seq);
        if head <= already {
            return Ok(None);
        }
        let append = self.prepare_pending_control(store, owner, now)?;
        Ok(Some(PendingCheckpoint {
            append,
            sek: self.sek.reader(),
            room: self.channel_id,
            me,
            already,
            head,
            last_pruned_at: self.last_pruned_at,
            idle_seconds: self.checkpoint_idle,
            now,
        }))
    }

    pub(crate) fn finish_pending_retention(
        &mut self,
        store: &Store,
        completed: CompletedRetention,
    ) -> Result<Installed> {
        let CompletedRetention {
            pending,
            mut result,
            committed,
            body_changes,
            display_changed,
            ..
        } = completed;
        if self.channel_id != pending.room
            || self.epoch != pending.epoch
            || !self
                .pending_text
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &pending.owner))
        {
            return result;
        }
        // Even a later failure must acknowledge already committed native transactions. The
        // pin is held by the common completion until all these component facts are installed.
        if committed {
            if !matches!(
                &pending.work,
                Work::PrivateExpiry(_) | Work::HistoricalKeys { .. }
            ) {
                self.entries.committed();
            }
            self.dag.install_retention_delta(
                body_changes,
                match &pending.work {
                    Work::Signatures { swept, .. } => swept.as_slice(),
                    _ => &[],
                },
            );
        }
        if let Work::Prune { legacy, .. } = &pending.work {
            // The context retains its last real commit independently of a later failed
            // candidate. Its pre-prune pass can commit even if pruning itself then fails.
            self.install_legacy_projection_context(legacy);
        }
        if result.is_ok() {
            self.now_hint = self.now_hint.max(pending.now);
            match pending.work {
                Work::Cleanup {
                    next, turn, first, ..
                } => {
                    self.projection_state.cleanup_cursor = next;
                    self.owed_decided.page(turn, first, next.is_none());
                }
                Work::Projection { state, .. } => self.projection_state = state,
                Work::KeyDebt { more, .. } => {
                    self.key_debt_retention_pending = more;
                }
                Work::HistoricalKeys { state, .. } => self.historical_retirement = state,
                Work::Prune { complete: true, .. } => self.note_clean(0),
                Work::PrivateExpiry(Some(_))
                    if result
                        .as_ref()
                        .is_ok_and(|installed| installed.private_clean) =>
                {
                    self.note_clean(1);
                }
                _ => {}
            }
            if result.as_ref().is_ok_and(|installed| installed.pruned != 0) {
                self.last_pruned_at = pending.now;
            }
        }
        if display_changed {
            self.remove_display_rows();
            match self
                .entries
                .render_view(store, &self.sek, &self.channel_id)
                .and_then(|view| view.step(None, true, None, true))
            {
                Ok(row) => self.display_tail = row.map(|(key, _)| key),
                Err(error) => result = Err(error),
            }
        }
        if let Err(error) = &result {
            self.poison(error);
        }
        self.pending_text = None;
        self.history_publication_changed.notify_waiters();
        result
    }
}

impl PendingRetention {
    /// Only the native owned worker calls this. No actor, room or Computer state lock is held.
    pub(crate) fn save(mut self, store: &Store) -> CompletedRetention {
        #[cfg(feature = "test-knobs")]
        if matches!(&self.work, Work::Prune { due, .. } if !due.is_empty()) {
            if let Some(path) = std::env::var_os("VOX_TEST_HOLD_EXPIRY_PRUNE_FILE") {
                let path = std::path::PathBuf::from(path);
                if path.exists() {
                    let _ =
                        std::fs::write(path.with_extension("engaged"), b"expiry prune admitted");
                    while path.exists() {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
            }
        }
        let mut committed = false;
        let mut body_changes = 0;
        let mut display_changed = false;
        let result = self.sek.with(|sek| -> Result<Installed> {
            let mut installed = Installed::default();
            match &mut self.work {
                Work::Cleanup {
                    remove,
                    rows,
                    generation,
                    ..
                } => {
                    if !remove.is_empty() || !rows.is_empty() {
                        let mut batch = store.batch()?;
                        batch.derived();
                        // A removal applied since the decision leaves the rows to the next turn.
                        let current =
                            governance::removal_generation_in(&batch, &self.room)? == *generation;
                        let mut index = self.index.write(&mut batch, sek, &self.room)?;
                        let mut changed = false;
                        for (author, seq, hash) in remove {
                            if let Some(hash) = hash {
                                index.set_owed(*hash, None)?;
                            }
                            changed |= index.set_missing(author, *seq, false)?;
                        }
                        for (hash, window) in rows.iter() {
                            if window.is_none() || current {
                                index.set_owed(*hash, *window)?;
                                changed = true;
                            }
                        }
                        index.seal()?;
                        batch.commit()?;
                        committed = true;
                        display_changed |= changed;
                    }
                }
                Work::KeyDebt { debts, more } => {
                    if !debts.is_empty() {
                        let mut batch = store.batch()?;
                        batch.derived();
                        let mut index = self.index.write(&mut batch, sek, &self.room)?;
                        for debt in debts {
                            index.finish_history_obligation(debt)?;
                        }
                        index.seal()?;
                        batch.commit()?;
                        committed = true;
                    }
                    installed.more_key_debt = *more;
                }
                Work::Projection {
                    state,
                    before,
                    owed,
                    idle,
                    flush,
                } => {
                    if *idle {
                        installed.projection_ready = true;
                        return Ok(installed);
                    }
                    let mut batch = store.batch()?;
                    batch.derived();
                    if *flush {
                        batch.ruled();
                    }
                    let mut index = self.index.write(&mut batch, sek, &self.room)?;
                    let mut changed = false;
                    for (hash, visibility) in owed {
                        index.set_owed(*hash, *visibility)?;
                        changed = true;
                    }
                    for _ in 0..entry_store::DUE_ENTRIES {
                        let Some(hash) = index.first_expired_owed(self.now)? else {
                            break;
                        };
                        index.set_owed(hash, None)?;
                        changed = true;
                    }
                    installed.projection_ready =
                        !state.pending && index.first_expired_owed(self.now)?.is_none();
                    let progress = state.to_bytes();
                    if changed || *before != progress {
                        index.note_projection(progress)?;
                        index.seal()?;
                        batch.commit()?;
                        committed = true;
                        display_changed |= changed;
                    }
                }
                Work::Prune { due, legacy, .. } => {
                    // Keep both existing bounded classification passes: the first learns
                    // declarations before expiry, the second shares the prune transaction.
                    if !due.is_empty() {
                        legacy.reconcile(store, sek, self.now)?;
                        legacy.prepare_reconcile(store, sek, self.now, None, |legacy, batch| {
                            for selected in due.iter() {
                                if selected.entry.skeleton.v2.is_none() {
                                    if let Some(kind) = selected.legacy_kind {
                                        legacy.remember(
                                            batch,
                                            sek,
                                            selected.entry.entry_hash(),
                                            selected.entry.skeleton.author_id,
                                            kind,
                                        )?;
                                    }
                                }
                            }
                            Ok(())
                        })?;
                        let mut batch = store.batch()?;
                        batch.derived();
                        semantic_projection::SelectedReceiverInput::check(&batch)?;
                        let mut dropped = 0;
                        let mut shown = false;
                        for selected in due.iter_mut() {
                            let hash = selected.entry.entry_hash();
                            session_projection::private_index::observe_public(
                                &mut batch,
                                sek,
                                &self.room,
                                &selected.entry,
                                self.epoch,
                            )?;
                            if selected.entry.skeleton.v2.is_none() {
                                if let Some(kind) = selected.legacy_kind {
                                    legacy.remember(
                                        &mut batch,
                                        sek,
                                        hash,
                                        selected.entry.skeleton.author_id,
                                        kind,
                                    )?;
                                }
                            }
                            {
                                let mut index = self.index.write(&mut batch, sek, &self.room)?;
                                index.committing(self.next_log_id);
                                shown |= index.has_rendered(&hash)?;
                                index.remove_rendered(&hash)?;
                                index.remove_read_receipt(&hash)?;
                                index.set_retention(hash, None)?;
                                if selected.entry.prune_payload() {
                                    dropped += 1;
                                }
                                if selected.shed_signature {
                                    selected.entry.drop_signature();
                                }
                                index.put(&selected.entry)?;
                                index.seal()?;
                            }
                            let tracked = selected.tracked;
                            let age = seal_segment(
                                sek,
                                SegmentKind::Index,
                                tracked.log_id,
                                &first_seen_bytes(tracked.first_seen_ms, tracked.steps),
                            )?;
                            batch.put_segment(
                                &self.room,
                                SegmentKind::Index,
                                tracked.log_id,
                                &age,
                            )?;
                            if let Some(cache) = tracked.cache_id {
                                batch.delete_segment(
                                    &self.room,
                                    SegmentKind::PlaintextCache,
                                    cache,
                                )?;
                            }
                        }
                        legacy.reconcile_in(&mut batch, sek, self.now)?;
                        legacy.require_inputs()?;
                        batch.commit()?;
                        committed = true;
                        legacy.committed();
                        body_changes += dropped;
                        display_changed |= shown;
                        installed.pruned = due.len();
                        installed
                            .pruned_hashes
                            .extend(due.iter().map(|selected| selected.entry.entry_hash()));
                    }
                }
                Work::PrivateExpiry(expiry) => {
                    if let Some(expiry) = *expiry {
                        let (_, complete) = private_session::pending_upgrade::sweep_private(
                            store,
                            sek,
                            &self.room,
                            self.now,
                            expiry,
                            |hash| {
                                committed = true;
                                installed.pruned += 1;
                                installed.pruned_hashes.push(hash);
                            },
                        )?;
                        installed.private_clean = complete;
                    }
                }
                Work::HistoricalKeys { retire, .. } => {
                    if let Some((key, id)) = retire {
                        // Key deletion remains an ordinary durable commit, never Derived.
                        let mut batch = store.batch()?;
                        own_historical_keys::retire(&mut batch, sek, &self.room, *key, *id)?;
                        batch.commit()?;
                        committed = true;
                    }
                }
                Work::Signatures { entries, swept } => {
                    if !swept.is_empty() {
                        let mut batch = store.batch()?;
                        batch.derived();
                        let mut index = self.index.write(&mut batch, sek, &self.room)?;
                        index.committing(self.next_log_id);
                        for entry in entries {
                            if entry.drop_signature() {
                                index.put(entry)?;
                            }
                        }
                        index.note_swept_delta(swept)?;
                        index.seal()?;
                        batch.commit()?;
                        committed = true;
                    }
                }
            }
            installed.changed = committed || display_changed;
            Ok(installed)
        });
        CompletedRetention {
            pending: self,
            result,
            committed,
            body_changes,
            display_changed,
        }
    }
}

impl PendingCheckpoint {
    pub(crate) fn save(
        mut self,
        store: &Store,
        signer: &dyn RootSigner,
    ) -> pending_text::CompletedText {
        let selected = self.sek.with(|sek| {
            let index = entry_store::EntryIndex::default();
            let entries = index.read(store, sek, &self.room)?;
            // The expired positions since the last checkpoint this node holds as authority. A v2
            // checkpoint is none (ADR-036; `Dag::accept`, `restart::advance` take only v1), so
            // the author's own earlier checkpoints, met on the way, close what they name here.
            let mut expired: Vec<(u64, Digest32)> = Vec::new();
            for seq in self.already.saturating_add(1)..=self.head {
                let Some(entry) = entries.get(&self.me, seq)? else {
                    break;
                };
                let Some(payload) = entry.payload.as_deref() else {
                    expired.push((seq, entry.entry_hash()));
                    continue;
                };
                match classify_payload(payload) {
                    // A message still held ends the expired prefix. A retained record (a Session
                    // support, floor or step policy) is never expired, like a governance entry,
                    // and does not hold the checkpoint back (ADR-023 RL-3.3).
                    Ok(EntryKind::Content) if !retained_control(payload) => break,
                    Ok(EntryKind::Checkpoint) => {
                        let named = crate::log::checkpoint::Checkpoint::from_payload(payload);
                        if let Ok(Some(cp)) = named {
                            if !own_checkpoint_uncounted(cp.seq) {
                                expired.retain(|(at, _)| *at > cp.seq);
                            }
                        }
                    }
                    _ => {}
                }
            }
            let Some(&(seq, entry_hash)) = expired.last() else {
                return Ok(None);
            };
            let idle = self.now.get().saturating_sub(self.last_pruned_at)
                >= self.idle_seconds.saturating_mul(1_000);
            if seq <= self.already || (expired.len() < CHECKPOINT_EVERY && !idle) {
                return Ok(None);
            }
            if checkpoint_unwritten(seq) {
                return Ok(None);
            }
            Ok(Some((
                seq,
                crate::log::checkpoint::Checkpoint { seq, entry_hash }.to_wire(),
            )))
        });
        let result = match selected {
            Ok(Some((seq, payload))) => self
                .append
                .append_control_owned(
                    store,
                    signer,
                    payload,
                    EntryKind::Checkpoint,
                    crate::log::history::SignedEntryKind::Checkpoint,
                    self.now,
                )
                .map(|hash| {
                    // Said for a proof (`test-knobs` only): this node wrote a checkpoint.
                    #[cfg(feature = "test-knobs")]
                    eprintln!(
                        "test-knobs: checkpoint written in room {}: it closes this node's own \
                         feed through position {seq}",
                        crate::node::link::b32_encode(&self.room)
                    );
                    #[cfg(not(feature = "test-knobs"))]
                    let _ = seq;
                    pending_text::Saved::Governance(Some(hash))
                }),
            Ok(None) => Ok(pending_text::Saved::Governance(None)),
            Err(error) => Err(error),
        };
        self.append.complete_control(result)
    }
}
