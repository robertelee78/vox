//! Mark replies follow the real durable commit; receipt admission never claims an append.
use super::*;
use crate::node::channel::pending_text::read;
use crate::node::store::Store;

pub(super) use read::{Saved, Work};
pub(super) enum Prepared {
    Native(read::Prepared),
    Refused(Error),
}
pub(super) enum Completed {
    Native(Box<read::Completed>),
    Refused(Error),
}

pub(super) fn expected_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::RoomNotSynced
            | Error::OwnHistoryBehind
            | Error::SizeLimitExceeded(_)
            | Error::Profile(
                "read selection changed; refresh and retry"
                    | "this identity has left the room"
                    | "this identity is not an author of the room"
                    | "this room has ended"
                    | "room publication is busy; retry this operation"
                    | crate::node::channel::legacy_provisional::LEGACY_HISTORY_REQUIRED
            )
    ) || ChannelState::governance_refreshing(error)
        || ChannelState::legacy_classification_refreshing(error)
}
impl Work {
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> crate::error::Result<Prepared> {
        match channel.prepare_pending_read(store, owner, self, now) {
            Ok(pending) => Ok(Prepared::Native(pending)),
            Err(error) if expected_refusal(&error) => Ok(Prepared::Refused(error)),
            Err(error) => Err(error),
        }
    }
}
impl Prepared {
    pub(super) fn run(
        self,
        store: &Store,
        signer: &dyn crate::identity::composite::RootSigner,
    ) -> Completed {
        match self {
            Self::Native(pending) => Completed::Native(Box::new(pending.run(store, signer))),
            Self::Refused(error) => Completed::Refused(error),
        }
    }
}
impl Completed {
    pub(super) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        match self {
            Self::Native(done) => done.can_install(channel, owner),
            Self::Refused(_) => true,
        }
    }
    pub(super) fn take_history_pin(
        &mut self,
    ) -> Option<crate::node::channel::history::PendingHistoryRead> {
        match self {
            Self::Native(done) => done.take_history_pin(),
            Self::Refused(_) => None,
        }
    }
    pub(super) fn finish(self, channel: &mut ChannelState, store: &Store) -> Saved {
        match self {
            Self::Native(done) => done.finish(channel, store),
            Self::Refused(error) => Saved {
                result: Err(error),
                appended: false,
            },
        }
    }
    pub(super) fn into_result(self) -> Saved {
        match self {
            Self::Native(done) => done.into_result(),
            Self::Refused(error) => Saved {
                result: Err(error),
                appended: false,
            },
        }
    }
}

pub(super) struct Continuation {
    instance: SharedChannel,
    attachment: u64,
    mark: bool,
}
impl Continuation {
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(super) fn lifetime(&self) -> Option<Arc<maintenance_save::Lifetime>> {
        None
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

pub(super) fn outcome(saved: &Saved) -> Outcome {
    match &saved.result {
        Ok(_) => Outcome::Done,
        Err(error) => Outcome::Failed(fault_of(error)),
    }
}
pub(super) fn retire_detached(
    result: crate::error::Result<maintenance_save::Saved>,
    _next: Continuation,
    reply: Option<oneshot::Sender<Outcome>>,
) {
    let outcome = match result {
        Ok(maintenance_save::Saved::Read(saved)) => outcome(&saved),
        Err(error) => Outcome::Failed(fault_of(&error)),
        _ => Outcome::Failed(Fault::Internal),
    };
    if let Some(reply) = reply {
        let _ = reply.send(outcome);
    }
}

impl Node {
    pub(super) async fn begin_mark_read(
        &mut self,
        room: Digest32,
        entries: Vec<Digest32>,
        expected_instance: Option<[u8; 16]>,
        reply: oneshot::Sender<Outcome>,
    ) {
        let Some(instance) = self.channels.get(&room).cloned() else {
            let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            return;
        };
        let next = Continuation {
            instance,
            attachment: self.delivery_epoch,
            mark: true,
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Read(Work::Mark {
                shown: entries,
                expected_instance,
            }),
            maintenance_save::Continuation::Read(next),
            Some(reply),
        )
        .await;
    }

    /// Admission returns no publication progress. Only finish_owned_read notes a real append.
    pub(super) async fn flush_reads(&mut self) -> bool {
        use std::ops::Bound::{Excluded, Unbounded};
        let room = self
            .reads_after
            .and_then(|after| {
                self.channels
                    .range((Excluded(after), Unbounded))
                    .next()
                    .map(|(id, _)| *id)
            })
            .or_else(|| self.channels.first_key_value().map(|(id, _)| *id));
        let Some(room) = room else {
            return false;
        };
        self.reads_after = Some(room);
        if self
            .profile
            .as_ref()
            .is_none_or(|profile| !profile.is_unlocked())
            || self.pending_posts.contains_key(&room)
        {
            return false;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            return false;
        };
        let Ok(channel) = instance.try_lock() else {
            return false;
        };
        if channel.is_poisoned() {
            return false;
        }
        drop(channel);
        let next = Continuation {
            instance,
            attachment: self.delivery_epoch,
            mark: false,
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Read(Work::Flush {
                interval_ms: READ_RECORD_EVERY_MS,
            }),
            maintenance_save::Continuation::Read(next),
            None,
        )
        .await;
        false
    }

    pub(super) fn reject_owned_read(
        &mut self,
        room: Digest32,
        error: Error,
        next: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if !next.mark && !expected_refusal(&error) {
            let _ = self.event_tx.send(NodeEvent::NodeNote { note: format!("room {} could not publish its saved read marks: {error}; the marks remain saved", crate::node::link::b32_encode(&room)) });
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault_of(&error)));
        }
    }

    pub(super) async fn finish_owned_read(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        _lifetime: Arc<maintenance_save::Lifetime>,
        next: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if !next.attached(self, &room) {
            retire_detached(result, next, reply);
            return;
        }
        let saved = match result {
            Ok(maintenance_save::Saved::Read(saved)) => saved,
            Err(error) => {
                self.reject_owned_read(room, error, next, reply);
                return;
            }
            _ => {
                self.reject_owned_read(
                    room,
                    Error::Profile("unexpected read save completion"),
                    next,
                    reply,
                );
                return;
            }
        };
        if saved.appended {
            self.note_local_append(&room);
        }
        if let Err(error) = &saved.result {
            if !next.mark && !expected_refusal(error) {
                let _ = self.event_tx.send(NodeEvent::NodeNote { note: format!("room {} could not publish its saved read marks: {error}; the marks remain saved", crate::node::link::b32_encode(&room)) });
            }
        }
        if let Some(reply) = reply {
            let _ = reply.send(outcome(&saved));
        }
    }
}
