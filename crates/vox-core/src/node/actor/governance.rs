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
    pub(super) settled: BTreeSet<Digest32>,
    pub(super) consent_after: BTreeMap<Digest32, Digest32>,
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

    /// A completed Computer-policy application releases only work which explicitly retained
    /// that authority handoff. Preserve wakes for rooms already passed by the current sweep.
    pub(super) fn resume_after_computer_policy(&mut self) {
        let rooms: BTreeSet<_> = self
            .admin_rosters
            .iter()
            .copied()
            .chain(self.removal.as_ref().map(|removal| removal.room))
            .collect();
        for room in rooms {
            self.wake_room(room);
        }
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
    pub(super) room: Digest32,
    pub(super) member: Digest32,
    pub(super) instance: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
    pub(super) after: Option<Digest32>,
    pub(super) count: usize,
    pub(super) done: bool,
    pub(super) reply: oneshot::Sender<Outcome>,
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
        if self.pending_posts.contains_key(&work.room) {
            self.governance_work.removal = Some(work);
            return;
        }
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
        let Ok(channel) = shared.try_lock() else {
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
        drop(channel);
        let room = work.room;
        let native = governance_save::Work::AdminRemoval {
            member: work.member,
            after: work.after,
        };
        let continuation = governance_save::Continuation::admin(shared, self.delivery_epoch, work);
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Governance(native),
            maintenance_save::Continuation::Governance(continuation),
            None,
        )
        .await;
    }

    /// One room's fixed-size disk work per selection. A cycle retains only its cursor and a
    /// retry bit; ordinary commands and network events remain eligible between turns.
    pub(super) async fn advance_governance_turn(&mut self) {
        self.advance_admin_removal().await;
        if self.profile.is_none() {
            self.governance_work.pending = false;
            self.governance_work.after = None;
            self.governance_work.settled.clear();
            self.governance_work.deadlines.clear();
            self.governance_work.deadline_order.clear();
            return;
        }
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
        // A retained completion already owns this room's exact selected turn. Do not turn a
        // physical writer wait into another immediately runnable round-robin sweep.
        if self.pending_posts.contains_key(&room) {
            return;
        }
        let Ok(channel) = shared.try_lock() else {
            self.governance_work.again = true;
            return;
        };
        drop(channel);
        let continuation = governance_save::Continuation::turn(shared, self.delivery_epoch);
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Consent(consent_save::Work::ReceiverCleanup),
            maintenance_save::Continuation::Governance(continuation),
            None,
        )
        .await;
    }
}
