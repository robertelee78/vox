//! The existing R14 tick admits owned room saves; only their real completions publish counts.
use super::*;
use crate::node::channel::pending_key_prune;
use crate::node::store::Store;

pub(super) use pending_key_prune::{Completed, Prepared, Saved};
pub(super) struct Work {
    full: Arc<BTreeSet<Digest32>>,
    trusted: Arc<BTreeSet<Digest32>>,
    now: crate::time::Ms,
}
impl Work {
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        _now: crate::time::Ms,
    ) -> crate::error::Result<Option<Prepared>> {
        channel.prepare_pending_key_prune(store, owner, &self.full, &self.trusted, self.now)
    }
}

pub(super) struct Continuation {
    instance: SharedChannel,
    attachment: u64,
    lifetime: Option<Arc<maintenance_save::Lifetime>>,
}
impl Continuation {
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(super) fn lifetime(&self) -> Option<Arc<maintenance_save::Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(super) fn is_preparation(&self) -> bool {
        false
    }
    fn attached(&self, node: &Node, room: &Digest32) -> bool {
        self.attachment == node.delivery_epoch
            && node
                .channels
                .get(room)
                .is_some_and(|current| Arc::ptr_eq(current, &self.instance))
    }
}

impl Node {
    /// Keep the old tick's room traversal and skip an already-owned room until the next tick.
    /// Work waiting for a transient room publication is retained by the common native worker.
    pub(super) async fn schedule_superseded_key_prune(&mut self) {
        if self.locking != 0
            || self
                .profile
                .as_ref()
                .is_none_or(|profile| !profile.is_unlocked() || profile.signer().is_err())
        {
            return;
        }
        let full = Arc::new(
            self.trust
                .trusted()
                .into_iter()
                .filter(|identity| {
                    self.trust.history(identity) == crate::node::trust::HistoryGrant::Full
                })
                .collect::<BTreeSet<_>>(),
        );
        let trusted = Arc::new(self.trust.trusted().into_iter().collect::<BTreeSet<_>>());
        let now = self.now_ms();
        let rooms: Vec<_> = self
            .channels
            .iter()
            .map(|(room, instance)| (*room, Arc::clone(instance)))
            .collect();
        for (room, instance) in rooms {
            if self.pending_posts.contains_key(&room) {
                continue;
            }
            let work = Work {
                full: Arc::clone(&full),
                trusted: Arc::clone(&trusted),
                now,
            };
            let continuation = Continuation {
                instance,
                attachment: self.delivery_epoch,
                lifetime: None,
            };
            self.begin_pending_maintenance(
                room,
                maintenance_save::Work::KeyPrune(work),
                maintenance_save::Continuation::KeyPrune(continuation),
                None,
            )
            .await;
        }
    }

    pub(super) async fn finish_owned_key_prune(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        lifetime: Arc<maintenance_save::Lifetime>,
        continuation: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        let saved = match result {
            Ok(maintenance_save::Saved::KeyPrune(saved)) => saved,
            Ok(maintenance_save::Saved::Unavailable) => {
                self.reject_owned_key_prune(
                    room,
                    Error::Profile("key pruning is waiting for its room"),
                    continuation,
                    reply,
                );
                return;
            }
            Ok(_) => {
                self.reject_owned_key_prune(
                    room,
                    Error::Profile("key pruning result does not match retained work"),
                    continuation,
                    reply,
                );
                return;
            }
            Err(error) => {
                self.reject_owned_key_prune(room, error, continuation, reply);
                return;
            }
        };
        // A receiver commit can precede an origin-write error. Its real changed bit and wake
        // are still published; successful admission alone is never evidence of pruning.
        if continuation.attached(self, &room) && lifetime.publish(|| ()).is_some() {
            if saved.receivers != 0 {
                self.governance_work.wake_room(room);
            }
            if saved.changed() {
                self.publish().await;
            }
        }
        if let Some(reply) = reply {
            let _ = reply.send(
                saved
                    .result
                    .map(|_| Outcome::Done)
                    .unwrap_or_else(|error| Outcome::Failed(fault_of(&error))),
            );
        }
    }

    pub(super) fn reject_owned_key_prune(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if continuation.attached(self, &room) && ChannelState::governance_refreshing(&error) {
            self.governance_work.wake_room(room);
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault_of(&error)));
        }
    }
}
