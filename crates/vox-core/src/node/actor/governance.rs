//! One bounded governance turn, shared with the actor's ordinary command loop.

use super::*;

/// **Test-only**: the named marker contains one raw room id. When a bounded governance sweep
/// selects that room, rename the marker with `.engaged` appended and park with the cursor already
/// after it. The FX-22 journey then lets that room's real authority deadline supply the only wake,
/// proving an expiry behind an in-progress cursor cannot be lost.
#[cfg(feature = "test-knobs")]
pub const TEST_HOLD_SWEEP_AFTER_ENV: &str = "VOX_TEST_HOLD_GOVERNANCE_SWEEP_AFTER_FILE";

#[cfg(feature = "test-knobs")]
fn hold_sweep_after(room: &Digest32) -> bool {
    let Some(path) = std::env::var_os(TEST_HOLD_SWEEP_AFTER_ENV).filter(|path| !path.is_empty())
    else {
        return false;
    };
    let path = std::path::PathBuf::from(path);
    let Ok(held) = std::fs::read(&path) else {
        return false;
    };
    if held.as_slice() != room {
        return false;
    }
    let mut engaged = path.as_os_str().to_owned();
    engaged.push(".engaged");
    std::fs::rename(path, engaged).is_ok()
}

#[derive(Default)]
pub(super) struct Maintenance {
    pub pending: bool,
    after: Option<Digest32>,
    pub(super) again: bool,
    /// Rooms whose checked governance fold is current. Other retained room work must not reopen
    /// and re-evaluate the same sealed facts; an exact governance input or authority deadline
    /// removes only its room from this set.
    settled: BTreeSet<Digest32>,
    consent_after: BTreeMap<Digest32, Digest32>,
    deadlines: BTreeMap<Digest32, u64>,
    deadline_order: BTreeSet<(u64, Digest32)>,
    /// Admin changes already committed to the room log whose board roster still owes a
    /// successful projection.  A refresh or Computer-policy handoff is retryable, not a reason
    /// to report that the durable admin change failed.
    pub(super) admin_rosters: BTreeSet<Digest32>,
    pub(super) removal: Option<Removal>,
}

impl Maintenance {
    /// Whether bounded governance maintenance is queued. This is current actor state for
    /// `vox status`, not an inference from a room's last published semantic revision.
    pub(super) fn pending(&self) -> bool {
        self.pending || self.again || self.removal.is_some()
    }

    pub(super) fn next_deadline(&self) -> Option<u64> {
        self.deadline_order.first().map(|(deadline, _)| *deadline)
    }

    pub(super) fn set_deadline(&mut self, room: Digest32, deadline: Option<u64>) {
        if let Some(old) = self.deadlines.remove(&room) {
            self.deadline_order.remove(&(old, room));
        }
        if let Some(deadline) = deadline {
            self.deadlines.insert(room, deadline);
            self.deadline_order.insert((deadline, room));
        }
    }

    pub(super) fn wake_expired(&mut self, now: u64) {
        let mut woke = false;
        while let Some((deadline, room)) = self.deadline_order.first().copied() {
            if deadline > now {
                break;
            }
            self.deadline_order.remove(&(deadline, room));
            self.deadlines.remove(&room);
            self.settled.remove(&room);
            // A deadline can expire while a bounded sweep is already beyond this room.  The
            // current sweep cannot observe it, and its completion replaces `pending` with
            // `again`; carry a second sweep explicitly instead of waiting for unrelated work.
            if self.after.is_some_and(|after| room <= after) {
                self.again = true;
            }
            woke = true;
        }
        self.pending |= woke;
    }

    fn retain_deadlines(&mut self, rooms: &BTreeSet<Digest32>) {
        let stale: Vec<_> = self
            .deadlines
            .keys()
            .filter(|room| !rooms.contains(*room))
            .copied()
            .collect();
        for room in stale {
            self.set_deadline(room, None);
        }
    }

    /// Wake the exact room whose governance input changed. This is deliberately separate from
    /// `pending`: render, sparse-history and key-package continuations need actor maintenance but
    /// do not invalidate an already checked governance fold.
    pub(super) fn wake_room(&mut self, room: Digest32) {
        self.settled.remove(&room);
        // If the active ordered sweep has already visited this room, its completion replaces
        // `pending` with `again`. Carry the wake across that boundary instead of losing it.
        if self.after.is_some_and(|after| room <= after) {
            self.again = true;
        }
        self.pending = true;
    }
}

pub(super) struct Removal {
    room: Digest32,
    member: Digest32,
    instance: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
    after: Option<Digest32>,
    count: usize,
    done: bool,
    reply: oneshot::Sender<Outcome>,
}

impl Node {
    pub(super) fn begin_admin_removal(
        &mut self,
        room: Digest32,
        member: Digest32,
        reply: oneshot::Sender<Outcome>,
    ) {
        let failure = if self.profile.is_none() {
            Some(Fault::NoIdentity)
        } else if self.governance_work.removal.is_some() {
            Some(Fault::AdminChangePending)
        } else if !self.channels.contains_key(&room) {
            Some(Fault::ChannelNotOpen)
        } else {
            None
        };
        if let Some(fault) = failure {
            let _ = reply.send(Outcome::Failed(fault));
            return;
        }
        let Some(shared) = self.channels.get(&room) else {
            return;
        };
        self.governance_work.removal = Some(Removal {
            room,
            member,
            instance: Arc::downgrade(shared),
            after: None,
            count: 0,
            done: false,
            reply,
        });
        self.governance_work.pending = true;
    }

    /// At most one certificate is inspected and one revocation written. The weak room
    /// reference fences close/reopen and retains no room secrets across lock.
    async fn advance_admin_removal(&mut self) {
        let Some(mut work) = self.governance_work.removal.take() else {
            return;
        };
        let Some(profile) = self.profile.as_ref() else {
            let _ = work.reply.send(Outcome::Failed(Fault::Locked));
            return;
        };
        let shared = match (self.channels.get(&work.room), work.instance.upgrade()) {
            (Some(current), Some(old)) if Arc::ptr_eq(current, &old) => Arc::clone(current),
            _ => {
                let _ = work.reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                return;
            }
        };
        let Ok(mut channel) = shared.try_lock() else {
            self.governance_work.removal = Some(work);
            return; // The regular tick retries a busy room; do not spin on its mutex.
        };
        if work.done {
            match channel.is_admin(profile.store(), &work.member, self.now_ms()) {
                Err(error) if ChannelState::governance_refreshing(&error) => {
                    self.governance_work.removal = Some(work);
                    return;
                }
                Err(error) => {
                    let _ = work.reply.send(Outcome::Failed(fault_of(&error)));
                    return;
                }
                Ok(true) => {
                    // Another effective certificate may have arrived while the removal was
                    // being folded. Finish only after the current authority says it is gone.
                    work.after = None;
                    work.done = false;
                    self.governance_work.removal = Some(work);
                    self.governance_work.again = true;
                    return;
                }
                Ok(false) => {}
            }
            drop(channel);
            if let Err(fault) = self.publish_admin_roster(&work.room).await {
                // The certificate removal is already durable. Report that truthfully and retain
                // the board projection as owed work; a failed secondary publication must not
                // turn a successful removal into a false command failure.
                self.governance_work.admin_rosters.insert(work.room);
                self.governance_work.again |= matches!(fault, Fault::GovernanceRefreshing);
                eprintln!(
                    "vox node: removed the room admin; its board roster remains pending: {}",
                    fault.explain()
                );
            }
            self.publish().await;
            let _ = work.reply.send(Outcome::Done);
            return;
        }
        let result = self.with_current_computer_authority(|| {
            channel.remove_admin(profile, &work.member, work.after, self.now_ms())
        });
        let Some(result) = result else {
            // Keep the exact cursor and any already-durable certificates.  The queued policy
            // event (or the ordinary tick) retries after reconciliation; re-arming this
            // always-ready branch here would spin the actor and delay that very event.
            self.governance_work.removal = Some(work);
            return;
        };
        drop(channel);
        match result {
            Err(error) if ChannelState::governance_refreshing(&error) => {
                self.governance_work.removal = Some(work);
            }
            Err(error) => {
                let _ = work.reply.send(Outcome::Failed(fault_of(&error)));
            }
            Ok((count, next)) => {
                work.count = work.count.saturating_add(count);
                if count > 0 {
                    self.note_local_governance_append(&work.room);
                    self.governance_work.again = true;
                }
                if let Some(next) = next {
                    work.after = Some(next);
                    self.governance_work.removal = Some(work);
                    self.governance_work.again = true;
                } else if work.count == 0 {
                    let _ = work.reply.send(Outcome::Failed(Fault::NotAnAdmin));
                } else {
                    work.done = true;
                    self.governance_work.removal = Some(work);
                    self.governance_work.again = true;
                }
            }
        }
    }

    /// An already open room examines one consent page and commits at most one narrowing
    /// append per turn. Progress advances only after that append succeeds.
    async fn revoke_untrusted_consents(&mut self, room: &Digest32) -> crate::error::Result<bool> {
        let shared = self
            .channels
            .get(room)
            .map(Arc::clone)
            .ok_or(Error::Profile("room is not open"))?;
        let page = {
            let profile = self.profile.as_ref().ok_or(Error::AtRestLocked)?;
            let Ok(channel) = shared.try_lock() else {
                return Ok(true);
            };
            channel.consent_page(
                profile.store(),
                &channel.me(),
                self.governance_work.consent_after.get(room).copied(),
                64,
            )?
        };
        if let Some(member) = page
            .targets
            .iter()
            .find(|member| !self.trust.is_trusted(member))
            .copied()
        {
            self.withdraw_for_untrust_result(room, member).await?;
            self.governance_work.consent_after.insert(*room, member);
            Ok(true)
        } else if let Some(next) = page.next {
            self.governance_work.consent_after.insert(*room, next);
            Ok(true)
        } else {
            self.governance_work.consent_after.remove(room);
            Ok(false)
        }
    }

    /// One room's fixed-size disk work per selection. A cycle retains only its cursor and a
    /// retry bit; ordinary commands and network events remain eligible between turns.
    pub(super) async fn advance_governance_turn(&mut self) {
        self.advance_admin_removal().await;
        let Some(store) = self.profile.as_ref().map(Profile::store_handle) else {
            self.governance_work.pending = false;
            self.governance_work.after = None;
            self.governance_work.settled.clear();
            self.governance_work.deadlines.clear();
            self.governance_work.deadline_order.clear();
            return;
        };
        use std::ops::Bound::{Excluded, Unbounded};
        let next = match self.governance_work.after {
            Some(after) => self.channels.range((Excluded(after), Unbounded)).next(),
            None => self.channels.iter().next(),
        }
        .map(|(room, shared)| (*room, Arc::clone(shared)));
        let Some((room, shared)) = next else {
            self.governance_work.after = None;
            self.governance_work
                .consent_after
                .retain(|room, _| self.channels.contains_key(room));
            self.governance_work
                .settled
                .retain(|room| self.channels.contains_key(room));
            self.governance_work
                .admin_rosters
                .retain(|room| self.channels.contains_key(room));
            let rooms = self.channels.keys().copied().collect();
            self.governance_work.retain_deadlines(&rooms);
            self.governance_work.pending = std::mem::take(&mut self.governance_work.again);
            return;
        };
        self.governance_work.after = Some(room);
        #[cfg(feature = "test-knobs")]
        if hold_sweep_after(&room) {
            // The marker is apparatus. Leave the selected room behind the cursor and park; its
            // actual stored authority deadline is the only event that can resume this sweep.
            self.governance_work.pending = false;
            return;
        }
        let Ok(mut channel) = shared.try_lock() else {
            // This room's durable work was selected but not examined. Carry the wake into the
            // next round; a quiet room must not wait for a command, network event or timer tick
            // merely because another bounded operation held its lock for this turn.
            self.governance_work.again = true;
            return;
        };
        let (governance_ready, governance_pending, governance_changed) =
            if self.governance_work.settled.contains(&room) {
                (true, false, false)
            } else {
                match channel.advance_governance(&store, self.now_ms()) {
                    Ok(progress) => {
                        if progress.ready && !progress.pending {
                            self.governance_work.settled.insert(room);
                        }
                        (progress.ready, progress.pending, progress.changed)
                    }
                    Err(error) => {
                        channel.poison(&error);
                        return;
                    }
                }
            };
        if governance_ready {
            self.governance_work
                .set_deadline(room, channel.governance_deadline());
        }
        self.governance_work.again |= governance_pending;
        match channel.legacy_cache_only(&store) {
            Ok(true) => {
                // Current trust narrowing is still immediate; all publication-dependent
                // writes await explicit recovery. Never busy-loop on a parked cursor.
                if let Err(error) = channel.forget_keys_except(&store, &self.trust.trusted()) {
                    channel.poison(&error);
                }
                drop(channel);
                if governance_changed {
                    self.publish().await;
                }
                return;
            }
            Ok(false) => {}
            Err(error) => {
                channel.poison(&error);
                return;
            }
        }
        let backfilled = match channel.advance_governance_backfill(&store, self.now_ms()) {
            Ok(count) => count,
            Err(error) => {
                channel.poison(&error);
                0
            }
        };
        match channel.governance_backfill_pending(&store) {
            Ok(pending) => self.governance_work.again |= pending,
            Err(error) => channel.poison(&error),
        }
        #[cfg(feature = "test-knobs")]
        if channel.render_backfill_held_for_proof() {
            // The durable queue and shipped status remain pending. Apparatus owns the next wake
            // after it observes the causally held turn; do not spin while its marker is engaged.
            drop(channel);
            if governance_changed || backfilled > 0 {
                self.publish().await;
            }
            self.governance_work.pending = false;
            return;
        }
        // A settled suffix may span several bounded receipt-cursor pages. Continue it as
        // durable room work, reconstructed on restart, rather than waiting for a timer or a
        // fresh peer event. The channel rotates authors so one long suffix cannot starve another.
        match channel.advance_pending_sparse_contiguous(&store) {
            Ok(pending) => self.governance_work.again |= pending,
            Err(error) => channel.poison(&error),
        }
        // Classification has no authority until governance is current. Continue its
        // bounded sealed scan in this same round-robin room turn; a quiet room must not
        // need another sync to finish, and an unresolved absent target is not busy work.
        let mut legacy_finished = false;
        if governance_ready {
            let was_pending = channel.legacy_classification_pending(&store);
            match was_pending.and_then(|pending| {
                channel
                    .advance_legacy_sessions(&store, self.now_ms().get())
                    .map(|more| (pending, more))
            }) {
                Ok((was_pending, more)) => {
                    self.governance_work.again |= more;
                    legacy_finished = was_pending && !more;
                }
                Err(error) if ChannelState::legacy_classification_refreshing(&error) => {
                    self.governance_work.again = true;
                }
                Err(error) => channel.poison(&error),
            }
        }
        let mut views_finished = false;
        if governance_ready {
            match channel.advance_room_views(&store) {
                Ok((more, finished)) => {
                    self.governance_work.again |= more;
                    views_finished = finished;
                }
                Err(error) => channel.poison(&error),
            }
        }
        // An unsettled sparse room rechecks its durable exact own-head acknowledgement on
        // every ready governance turn. Volatile hint-queue occupancy is not settlement state.
        let settle_pending =
            !channel.is_settled() && channel.uses_sparse_history(&store).unwrap_or(false);
        drop(channel);
        if governance_ready && settle_pending {
            self.settle_sparse_room(&room).await;
        }
        // The own-history conflict detector (ADR-037 R5): a member seen holding more of this
        // node's own feed than this node does means a restored older profile. Said once, and
        // the room refuses this node's writes from here on, instead of letting it equivocate.
        if governance_ready {
            let noted = match shared.try_lock() {
                Ok(mut channel) => match channel.uses_sparse_history(&store) {
                    Ok(true) => match channel.own_history_conflict(&store) {
                        Ok(true) => channel.note_own_history_behind(&store).unwrap_or(false),
                        _ => false,
                    },
                    _ => false,
                },
                Err(_) => false,
            };
            if noted {
                // One fact, one sentence: the detector says what every refused write will say
                // (`Error::OwnHistoryBehind`), once. It used to say it in other words, and the
                // sentence a person then searched for appeared only where a refusal leaked.
                let _ = self.event_tx.send(NodeEvent::NodeNote {
                    note: format!(
                        "room {}: {}",
                        crate::node::link::b32_encode(&room),
                        crate::error::Error::OwnHistoryBehind
                    ),
                });
            }
        }
        if governance_ready
            && (governance_changed || self.governance_work.consent_after.contains_key(&room))
        {
            // A changed governance projection starts one bounded scan for stale consent; its
            // retained cursor finishes that scan even after the causal change has settled. Do
            // not restart a completed disk scan merely because unrelated room maintenance still
            // has work: that made every continuation decrypt the same consent entries again and
            // could monopolize the actor indefinitely. Reopen performs this scan during room
            // preparation, and an explicit trust removal narrows the affected member directly.
            match self.revoke_untrusted_consents(&room).await {
                Ok(more) => self.governance_work.again |= more,
                Err(error) => {
                    shared.lock().await.poison(&error);
                    return;
                }
            }
        }
        if governance_ready
            && (governance_changed || self.governance_work.admin_rosters.contains(&room))
        {
            self.adopt_channel_anchors(&room).await;
            self.refresh_network_view().await;
            match self.publish_admin_roster(&room).await {
                Ok(()) => {
                    self.governance_work.admin_rosters.remove(&room);
                }
                Err(fault) => {
                    self.governance_work.admin_rosters.insert(room);
                    // A policy handoff is woken by its own event.  Immediate self-requeue here
                    // can monopolize the actor while authority is necessarily stale. Permanent
                    // faults likewise remain visible as owed work without spinning this actor.
                    self.governance_work.again |= matches!(fault, Fault::GovernanceRefreshing);
                }
            }
        }
        if governance_changed || backfilled > 0 || legacy_finished || views_finished {
            self.publish().await;
        }
    }
}
