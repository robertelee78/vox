//! Native component saves share the authored-post reservation, result cell and actor wake.
use super::*;
use crate::atrest::vault::VaultRootSigner;
use crate::node::channel::pending_text::{CompletedText, Saved as AppendSaved};
use crate::node::channel::{pending_retention, pending_session, session_projection};
use crate::node::store::Store;

/// The original physical publication boundary follows every native child and continuation.
/// Managed policy children retain the same exclusive transition rather than acquiring a reader.
pub(super) struct Lifetime {
    pub(super) authority: computer::ComputerAuthority,
    pub(super) publication: Option<computer::ComputerPublication>,
    pub(super) exclusive: Option<Arc<crate::node::computer::ComputerPublicationTransition>>,
    pub(super) secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    pub(super) store: Arc<Store>,
    pub(super) signer: Arc<VaultRootSigner>,
}

impl Lifetime {
    /// Revalidate under the boundary already retained by this exact decision.
    pub(super) fn publish<T>(&self, publish: impl FnOnce() -> T) -> Option<T> {
        ((self.publication.is_some() || self.exclusive.is_some()) && self.authority.current())
            .then(publish)
    }
}

pub(super) enum Work {
    Projection(session_projection::ProjectionWork),
    Retention(pending_retention::Step),
    RetentionAt {
        step: pending_retention::Step,
        now: crate::time::Ms,
    },
    Checkpoint,
    Session(pending_session::SessionWrite),
    DirectSession(pending_session::SessionWrite),
    Consent(consent_save::Work),
    Trust(trust_save::Work),
    Private(private_save::Work),
    Governance(governance_save::Work),
    Packages(package_save::Work),
    Recovery(recovery_save::Work),
    Leave(leave_save::Work),
    Read(read_save::Work),
    Roster(roster_save::Work),
    KeyPrune(key_prune_save::Work),
    Metadata(metadata_save::Work),
}

pub(super) enum Saved {
    Projection(session_projection::ProjectionProgress),
    Retention(pending_retention::Installed),
    Checkpoint(AppendSaved),
    Session(pending_session::SessionSaved),
    SessionPrelude(pending_session::SessionWrite),
    SessionOutbound {
        package: Option<crate::node::keypackage::KeyPackage>,
        reservation: Option<crate::node::prekeys::OneTimeReservation>,
    },
    Consent(consent_save::Effect),
    Trust(crate::node::channel::pending_trust::TrustSaved),
    Private(private_save::Saved),
    Governance(governance_save::Saved),
    Packages(package_save::Saved),
    Recovery(recovery_save::Saved),
    Leave(leave_save::Saved),
    Read(read_save::Saved),
    Roster(roster_save::Saved),
    KeyPrune(key_prune_save::Saved),
    Metadata(metadata_save::Saved),
    /// The selected capsule could not proceed. This is never permission to advance readiness.
    Unavailable,
}

pub(super) enum Continuation {
    Session(session_save::SessionContinuation),
    Trust(trust_save::TrustContinuation),
    Private(private_save::Continuation),
    Governance(governance_save::Continuation),
    Preparation(preparation_save::Continuation),
    Packages(package_save::Continuation),
    Recovery(recovery_save::Continuation),
    Consent(consent_release::Continuation),
    Leave(leave_save::Continuation),
    Read(read_save::Continuation),
    Roster(roster_save::Continuation),
    KeyPrune(key_prune_save::Continuation),
    Metadata(metadata_save::Continuation),
    AfterMigration(Box<Migration>),
}

pub(super) struct Migration {
    next: Continuation,
    saved: Saved,
    lifetime: Arc<Lifetime>,
}

impl Continuation {
    fn instance(&self) -> &SharedChannel {
        match self {
            Self::Session(next) => next.instance(),
            Self::Trust(next) => next.instance(),
            Self::Private(next) => next.instance(),
            Self::Governance(next) => next.instance(),
            Self::Preparation(next) => next.instance(),
            Self::Packages(next) => next.instance(),
            Self::Recovery(next) => next.instance(),
            Self::Consent(next) => next.instance(),
            Self::Leave(next) => next.instance(),
            Self::Read(next) => next.instance(),
            Self::Roster(next) => next.instance(),
            Self::KeyPrune(next) => next.instance(),
            Self::Metadata(next) => next.instance(),
            Self::AfterMigration(next) => next.next.instance(),
        }
    }
    fn lifetime(&self) -> Option<Arc<Lifetime>> {
        match self {
            Self::Session(next) => next.lifetime(),
            Self::Trust(next) => next.lifetime().save.as_ref().map(Arc::clone),
            Self::Private(next) => next.lifetime(),
            Self::Governance(next) => next.lifetime(),
            Self::Preparation(next) => next.lifetime(),
            Self::Packages(next) => next.lifetime(),
            Self::Recovery(next) => next.lifetime(),
            Self::Consent(next) => next.lifetime(),
            Self::Leave(next) => next.lifetime(),
            Self::Read(next) => next.lifetime(),
            Self::Roster(next) => next.lifetime(),
            Self::KeyPrune(next) => next.lifetime(),
            Self::Metadata(next) => next.lifetime(),
            Self::AfterMigration(next) => Some(Arc::clone(&next.lifetime)),
        }
    }
    fn is_preparation(&self) -> bool {
        match self {
            Self::Session(_) => false,
            Self::Trust(next) => next.is_preparation(),
            Self::Private(next) => next.is_preparation(),
            Self::Governance(next) => next.is_preparation(),
            Self::Preparation(next) => next.is_preparation(),
            Self::Packages(next) => next.is_preparation(),
            Self::Recovery(next) => next.is_preparation(),
            Self::Consent(next) => next.is_preparation(),
            Self::Leave(next) => next.is_preparation(),
            Self::Read(next) => next.is_preparation(),
            Self::Roster(next) => next.is_preparation(),
            Self::KeyPrune(next) => next.is_preparation(),
            Self::Metadata(next) => next.is_preparation(),
            Self::AfterMigration(next) => next.next.is_preparation(),
        }
    }

    fn completed(
        self,
        result: crate::error::Result<Saved>,
    ) -> (Self, crate::error::Result<Saved>, bool) {
        match self {
            Self::AfterMigration(next) => {
                let Migration {
                    next,
                    saved: original,
                    ..
                } = *next;
                let result = result.and_then(|saved| match saved {
                    Saved::Private(
                        private_save::Saved::Migration | private_save::Saved::MigrationSkipped,
                    ) => Ok(original),
                    _ => Err(Error::Profile("unexpected legacy migration completion")),
                });
                (next, result, true)
            }
            other => (other, result, false),
        }
    }
}

enum Prepared {
    Projection(session_projection::PendingProjection),
    Retention(pending_retention::PendingRetention),
    Checkpoint(Box<pending_retention::PendingCheckpoint>),
    Session(session_save::Prepared),
    Consent(Box<consent_save::Prepared>),
    Trust(trust_save::Prepared),
    Private(private_save::Prepared),
    Governance(governance_save::Prepared),
    Packages(package_save::Prepared),
    Recovery(recovery_save::Prepared),
    Leave(leave_save::Prepared),
    Read(read_save::Prepared),
    Roster(roster_save::Prepared),
    KeyPrune(key_prune_save::Prepared),
    Metadata(metadata_save::Prepared),
    Unavailable,
}

enum Completed {
    Projection(session_projection::CompletedProjection),
    Retention(pending_retention::CompletedRetention),
    Checkpoint(Box<CompletedText>),
    Session(session_save::Completed),
    Consent(Box<consent_save::Completed>),
    Trust(trust_save::Completed),
    Private(private_save::Completed),
    Governance(governance_save::Completed),
    Packages(package_save::Completed),
    Recovery(recovery_save::Completed),
    Leave(leave_save::Completed),
    Read(read_save::Completed),
    Roster(roster_save::Completed),
    KeyPrune(key_prune_save::Completed),
    Metadata(metadata_save::Completed),
    Unavailable,
}

impl Work {
    fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        holders: &BTreeSet<Digest32>,
        now: crate::time::Ms,
    ) -> crate::error::Result<Prepared> {
        Ok(match self {
            Self::Projection(work) => {
                Prepared::Projection(channel.prepare_pending_projection(store, owner, work, now)?)
            }
            Self::Retention(step) => channel
                .prepare_pending_retention(store, owner, step, now)?
                .map_or(Prepared::Unavailable, Prepared::Retention),
            Self::RetentionAt { step, now } => channel
                .prepare_pending_retention(store, owner, step, now)?
                .map_or(Prepared::Unavailable, Prepared::Retention),
            Self::Checkpoint => channel
                .prepare_pending_checkpoint(store, owner, channel.me(), now)?
                .map_or(Prepared::Unavailable, |work| {
                    Prepared::Checkpoint(Box::new(work))
                }),
            Self::Session(work) => Prepared::Session(
                session_save::Work::new(work).prepare(channel, store, owner, holders, now)?,
            ),
            Self::DirectSession(work) => Prepared::Session(
                session_save::Work::direct_append(work)
                    .prepare(channel, store, owner, holders, now)?,
            ),
            Self::Consent(work) => work
                .prepare(channel, store, owner, now)?
                .map_or(Prepared::Unavailable, |work| {
                    Prepared::Consent(Box::new(work))
                }),
            Self::Trust(work) => Prepared::Trust(work.prepare(channel, store, owner)?),
            Self::Private(work) => work
                .prepare(channel, store, owner, now)?
                .map_or(Prepared::Unavailable, Prepared::Private),
            Self::Governance(work) => work
                .prepare(channel, store, owner, now)?
                .map_or(Prepared::Unavailable, Prepared::Governance),
            Self::Packages(work) => work
                .prepare(channel, store, owner, now)?
                .map_or(Prepared::Unavailable, Prepared::Packages),
            Self::Recovery(work) => work
                .prepare(channel, store, owner, now)?
                .map_or(Prepared::Unavailable, Prepared::Recovery),
            Self::Leave(work) => work
                .prepare(channel, store, owner, now)?
                .map_or(Prepared::Unavailable, Prepared::Leave),
            Self::Read(work) => Prepared::Read(work.prepare(channel, store, owner, now)?),
            Self::Roster(work) => Prepared::Roster(work.prepare(channel, store, owner, now)?),
            Self::KeyPrune(work) => work
                .prepare(channel, store, owner, now)?
                .map_or(Prepared::Unavailable, Prepared::KeyPrune),
            Self::Metadata(work) => work
                .prepare(channel, store, owner, now)?
                .map_or(Prepared::Unavailable, Prepared::Metadata),
        })
    }
}

impl Prepared {
    fn run(self, store: &Store, signer: &VaultRootSigner) -> Completed {
        match self {
            Self::Projection(work) => Completed::Projection(work.run(store)),
            Self::Retention(work) => Completed::Retention(work.save(store)),
            Self::Checkpoint(work) => Completed::Checkpoint(Box::new(work.save(store, signer))),
            Self::Session(work) => Completed::Session(work.run(store, signer)),
            Self::Consent(work) => Completed::Consent(Box::new(work.run(store, signer))),
            Self::Trust(work) => Completed::Trust(work.run(store, signer)),
            Self::Private(work) => Completed::Private(work.run(store, signer)),
            Self::Governance(work) => Completed::Governance(work.run(store, signer)),
            Self::Packages(work) => Completed::Packages(work.run(store, signer)),
            Self::Recovery(work) => Completed::Recovery(work.run(store, signer)),
            Self::Leave(work) => Completed::Leave(work.run(store, signer)),
            Self::Read(work) => Completed::Read(work.run(store, signer)),
            Self::Roster(work) => Completed::Roster(work.run(store, signer)),
            Self::KeyPrune(work) => Completed::KeyPrune(work.run(store, signer)),
            Self::Metadata(work) => Completed::Metadata(work.run(store, signer)),
            Self::Unavailable => Completed::Unavailable,
        }
    }
}

struct Receipt {
    result: crate::error::Result<Saved>,
    held: Option<(Digest32, Digest32)>,
}

impl Completed {
    fn mark_package_receipts(&self, continuation: &mut Continuation) {
        match (self, continuation) {
            (Self::Session(done), Continuation::Session(next)) => {
                if done.package_confirmed() {
                    next.mark_confirmed_package();
                } else if done.package_unconfirmed() {
                    next.mark_unconfirmed_package();
                }
            }
            (Self::Session(done), Continuation::Consent(next)) => {
                if done.package_confirmed() {
                    next.mark_confirmed_package();
                } else if done.package_unconfirmed() {
                    next.mark_unconfirmed_package();
                }
            }
            (Self::Consent(done), Continuation::Consent(next)) => {
                if done.package_confirmed() {
                    next.mark_confirmed_package();
                } else if done.package_unconfirmed() {
                    next.mark_unconfirmed_package();
                }
            }
            _ => {}
        }
    }

    fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        match self {
            Self::Projection(done) => done.can_install(channel, owner),
            Self::Retention(done) => done.can_install(channel, owner),
            Self::Checkpoint(done) => done.can_install(channel, owner),
            Self::Session(done) => done.can_install(channel, owner),
            Self::Consent(done) => done.can_install(channel, owner),
            Self::Trust(done) => done.can_install(channel, owner),
            Self::Private(done) => done.can_install(channel, owner),
            Self::Governance(done) => done.can_install(channel, owner),
            Self::Packages(done) => done.can_install(channel, owner),
            Self::Recovery(done) => done.can_install(channel, owner),
            Self::Leave(done) => done.can_install(channel, owner),
            Self::Read(done) => done.can_install(channel, owner),
            Self::Roster(done) => done.can_install(channel, owner),
            Self::KeyPrune(done) => done.can_install(channel, owner),
            Self::Metadata(done) => done.can_install(channel, owner),
            Self::Unavailable => true,
        }
    }
    fn take_history_pin(&mut self) -> Option<crate::node::channel::history::PendingHistoryRead> {
        match self {
            Self::Projection(done) => done.take_history_pin(),
            Self::Retention(done) => done.take_history_pin(),
            Self::Checkpoint(done) => done.take_history_pin(),
            Self::Session(done) => done.take_history_pin(),
            Self::Consent(done) => done.take_history_pin(),
            Self::Trust(done) => done.take_history_pin(),
            Self::Private(done) => done.take_history_pin(),
            Self::Governance(done) => done.take_history_pin(),
            Self::Packages(done) => done.take_history_pin(),
            Self::Recovery(done) => done.take_history_pin(),
            Self::Leave(done) => done.take_history_pin(),
            Self::Read(done) => done.take_history_pin(),
            Self::Roster(done) => done.take_history_pin(),
            Self::KeyPrune(done) => done.take_history_pin(),
            Self::Metadata(done) => done.take_history_pin(),
            Self::Unavailable => None,
        }
    }
    fn finish(self, channel: &mut ChannelState, store: &Store) -> Receipt {
        let mut held = None;
        let result = match self {
            Self::Projection(done) => channel
                .finish_pending_projection(store, done)
                .map(Saved::Projection),
            Self::Retention(done) => channel
                .finish_pending_retention(store, done)
                .map(Saved::Retention),
            Self::Checkpoint(done) => channel
                .finish_pending_text(store, *done)
                .map(Saved::Checkpoint),
            Self::Session(done) => done.finish(channel, store).map(Saved::from_session),
            Self::Consent(done) => {
                let receipt = done.finish(channel, store);
                held = receipt.held;
                receipt.result.map(Saved::Consent)
            }
            Self::Trust(done) => done.finish(channel).map(Saved::Trust),
            Self::Private(done) => done.finish(channel, store).map(Saved::Private),
            Self::Governance(done) => done.finish(channel, store).map(Saved::Governance),
            Self::Packages(done) => done.finish(channel, store).map(Saved::Packages),
            Self::Recovery(done) => done.finish(channel, store).map(Saved::Recovery),
            Self::Leave(done) => done.finish(channel, store).map(Saved::Leave),
            Self::Read(done) => Ok(Saved::Read(done.finish(channel, store))),
            Self::Roster(done) => Ok(Saved::Roster(done.finish(channel, store))),
            Self::KeyPrune(done) => done.finish(channel, store).map(Saved::KeyPrune),
            Self::Metadata(done) => done.finish(channel, store).map(Saved::Metadata),
            Self::Unavailable => Ok(Saved::Unavailable),
        };
        Receipt { result, held }
    }
    fn into_result(self) -> crate::error::Result<Saved> {
        match self {
            Self::Projection(done) => done.result.map(Saved::Projection),
            Self::Retention(done) => done.result.map(Saved::Retention),
            Self::Checkpoint(done) => done.result.map(Saved::Checkpoint),
            Self::Session(done) => done.into_result().map(Saved::from_session),
            Self::Consent(done) => done.into_result().map(Saved::Consent),
            Self::Trust(done) => done.into_result().map(Saved::Trust),
            Self::Private(done) => done.into_result().map(Saved::Private),
            Self::Governance(done) => done.into_result().map(Saved::Governance),
            Self::Packages(done) => done.into_result().map(Saved::Packages),
            Self::Recovery(done) => done.into_result().map(Saved::Recovery),
            Self::Leave(done) => done.into_result().map(Saved::Leave),
            Self::Read(done) => Ok(Saved::Read(done.into_result())),
            Self::Roster(done) => Ok(Saved::Roster(done.into_result())),
            Self::KeyPrune(done) => done.into_result().map(Saved::KeyPrune),
            Self::Metadata(done) => done.into_result().map(Saved::Metadata),
            Self::Unavailable => Ok(Saved::Unavailable),
        }
    }
}

impl Saved {
    fn from_session(saved: session_save::Saved) -> Self {
        match saved {
            session_save::Saved::Session(saved) => Self::Session(saved),
            session_save::Saved::Prelude(write) => Self::SessionPrelude(write),
            session_save::Saved::OutboundPackage {
                package,
                reservation,
            } => Self::SessionOutbound {
                package,
                reservation,
            },
        }
    }
}

type Returned = (Option<Arc<Lifetime>>, crate::error::Result<Completed>);
pub(super) struct Pending {
    instance: SharedChannel,
    owner: Arc<()>,
    store: Arc<Store>,
    epoch: u64,
    preparing: bool,
    retention_owed: bool,
    governance_owed: bool,
    result: Arc<std::sync::Mutex<Option<Returned>>>,
    task: tokio::task::JoinHandle<()>,
    continuation: Continuation,
    reply: Option<oneshot::Sender<Outcome>>,
}

impl Pending {
    pub(super) fn owe_governance(&mut self, instance: &SharedChannel, attachment: u64) {
        if attachment == self.epoch && Arc::ptr_eq(instance, &self.instance) {
            self.governance_owed = true;
        }
    }

    pub(super) fn owe_retention(&mut self, instance: &SharedChannel, attachment: u64) {
        if attachment == self.epoch && Arc::ptr_eq(instance, &self.instance) {
            self.retention_owed = true;
        }
    }

    pub(super) fn retention_request(&self) -> Option<(SharedChannel, u64)> {
        self.retention_owed
            .then(|| (Arc::clone(&self.instance), self.epoch))
    }

    /// Retirement cannot abort a native commit or turn its real result into an unsent claim.
    pub(super) async fn retire(mut self) {
        let _ = self.task.await;
        let returned = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let (_lifetime, result) = match returned {
            Some((lifetime, Ok(done))) => {
                done.mark_package_receipts(&mut self.continuation);
                (lifetime, done.into_result())
            }
            Some((lifetime, Err(error))) => (lifetime, Err(error)),
            None => (None, Err(Error::Profile("native save worker stopped"))),
        };
        let room = {
            let mut channel = self.instance.lock().await;
            channel.release_pending_text(&self.owner, result.is_err());
            channel.note_publication_complete();
            channel.channel_id()
        };
        let (continuation, result, _) = self.continuation.completed(result);
        match continuation {
            Continuation::Trust(next) => {
                trust_save::retire_detached(room, result, next, self.reply).await
            }
            Continuation::Governance(next) => {
                governance_save::retire_detached(result, next, self.reply)
            }
            Continuation::Consent(next) => {
                consent_release::retire_detached(result, next, self.reply)
            }
            Continuation::Leave(next) => leave_save::retire_detached(result, next, self.reply),
            Continuation::Read(next) => read_save::retire_detached(result, next, self.reply),
            Continuation::Roster(next) => roster_save::retire_detached(result, next, self.reply),
            Continuation::Metadata(next) => {
                metadata_save::retire_detached(room, result, next, self.reply).await
            }
            _ => {
                if let Some(reply) = self.reply {
                    let _ = reply.send(outcome(&result));
                }
            }
        }
    }
}

fn outcome(result: &crate::error::Result<Saved>) -> Outcome {
    match result {
        Ok(Saved::Session(pending_session::SessionSaved::Appended(hash))) => {
            Outcome::Appended(*hash)
        }
        Ok(Saved::SessionPrelude(_)) => Outcome::Failed(Fault::ChannelNotOpen),
        Ok(Saved::SessionOutbound { .. }) => Outcome::Failed(Fault::ChannelNotOpen),
        Ok(Saved::Consent(consent_save::Effect::Publication {
            result: Err(error), ..
        })) => Outcome::Failed(fault_of(error)),
        Ok(Saved::Unavailable) => Outcome::Failed(Fault::RoomChangePending),
        Ok(Saved::Leave(leave_save::Saved::Detached)) => Outcome::Failed(Fault::LeaveNotHeard),
        Ok(Saved::Read(saved)) => read_save::outcome(saved),
        Ok(Saved::Roster(roster_save::Saved {
            result: Err(error), ..
        })) => Outcome::Failed(fault_of(error)),
        Ok(Saved::KeyPrune(key_prune_save::Saved {
            result: Err(error), ..
        })) => Outcome::Failed(fault_of(error)),
        Ok(_) => Outcome::Done,
        Err(error) => Outcome::Failed(fault_of(error)),
    }
}

impl Node {
    pub(super) fn store_save_pending(&self) -> bool {
        !self.pending_posts.is_empty()
            || self.policy_save_pending()
            || self.metadata_save_pending()
            || self.pending_startup.is_some()
            || !self.own_key_leave_pending.is_empty()
            || !self.own_key_ended_pending.is_empty()
            || !self.room_publication_authority.is_empty()
            || self
                .publish_waiters
                .values()
                .any(|waiting| waiting.authority.is_some())
    }

    pub(super) async fn begin_pending_maintenance(
        &mut self,
        room: Digest32,
        work: Work,
        continuation: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) -> bool {
        if self.pending_posts.contains_key(&room) {
            self.reject_pending_maintenance(
                room,
                Error::Profile("room publication is busy; retry this operation"),
                continuation,
                reply,
            );
            return false;
        }
        let Some(profile) = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
        else {
            self.reject_pending_maintenance(room, Error::AtRestLocked, continuation, reply);
            return false;
        };
        let store = profile.store_handle();
        let signer = match profile.signer_arc() {
            Ok(signer) => signer,
            Err(error) => {
                self.reject_pending_maintenance(room, error, continuation, reply);
                return false;
            }
        };
        let retained = continuation.lifetime();
        let authority = retained
            .as_ref()
            .map(|held| held.authority.clone())
            .or_else(|| match &continuation {
                Continuation::Leave(next) => Some(next.authority()),
                _ => self.computer_authority(),
            });
        let Some(authority) = authority else {
            self.reject_pending_maintenance(
                room,
                Error::ComputerPolicySuperseded,
                continuation,
                reply,
            );
            return false;
        };
        let original_secret = match &continuation {
            Continuation::Private(next) => next.secret(),
            Continuation::Leave(next) => next.secret(),
            _ => None,
        };
        let secret = match retained
            .as_ref()
            .map(|held| Arc::clone(&held.secret))
            .or(original_secret)
        {
            Some(secret) => secret,
            None => match self.secret_work.clone().try_read_owned() {
                Ok(secret) => Arc::new(secret),
                Err(_) => {
                    self.reject_pending_maintenance(room, Error::AtRestLocked, continuation, reply);
                    return false;
                }
            },
        };
        let instance = Arc::clone(continuation.instance());
        let preparing = continuation.is_preparation();
        let current = if preparing {
            self.preparing_rooms
                .get(&room)
                .map(|prepared| &prepared.channel)
        } else {
            self.channels.get(&room)
        };
        if !current.is_some_and(|current| Arc::ptr_eq(current, &instance)) {
            self.reject_pending_maintenance(
                room,
                Error::Profile("room changed before save admission"),
                continuation,
                reply,
            );
            return false;
        }
        let prior_owner = match &continuation {
            Continuation::Trust(next) => next.policy_reservation_owner(),
            _ => None,
        };
        let owner = Arc::new(());
        let result = Arc::new(std::sync::Mutex::new(None));
        let worker_result = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let worker_instance = Arc::clone(&instance);
        let worker_owner = Arc::clone(&owner);
        let worker_store = Arc::clone(&store);
        let clock = Arc::clone(&self.millis_clock);
        let preparation_now = match &continuation {
            Continuation::Governance(next) => next.now(),
            _ => None,
        };
        let holders = self.drive_holders();
        let epoch = self.delivery_epoch;
        let attachment = self.pairwise_epoch.subscribe();
        let worker = tokio::spawn(async move {
            let lifetime = match retained {
                Some(held) => held,
                None => {
                    let Some(publication) = authority.acquire_publication().await else {
                        return (None, Err(Error::ComputerPolicySuperseded));
                    };
                    Arc::new(Lifetime {
                        authority,
                        publication: Some(publication),
                        exclusive: None,
                        secret,
                        store: worker_store,
                        signer,
                    })
                }
            };
            let held = Arc::clone(&lifetime);
            let saved = tokio::task::spawn_blocking(move || {
                let mut prior_owner = prior_owner;
                let input_owner = Arc::clone(&worker_owner);
                let (prepared, input_epoch, input_instance) = loop {
                    let mut channel = worker_instance.blocking_lock();
                    if held.publication.is_some() && !held.authority.current() {
                        return Err(Error::ComputerPolicySuperseded);
                    }
                    if *attachment.borrow() != epoch {
                        return Err(Error::AtRestLocked);
                    }
                    if let Some(prior) = prior_owner.take() {
                        channel.release_pending_text(&prior, false);
                    }
                    if !channel.post_pending() {
                        let input_epoch = channel.epoch();
                        let input_instance = channel.generation();
                        let prepared = work.prepare(
                            &mut channel,
                            &held.store,
                            worker_owner,
                            &holders,
                            preparation_now.unwrap_or_else(|| crate::time::Ms(clock())),
                        )?;
                        break (prepared, input_epoch, input_instance);
                    }
                    // Another native owner may win between causal stages. Keep the selected
                    // work intact and subscribe before releasing its room guard.
                    let changed = channel.history_publication_wake();
                    drop(channel);
                    tokio::runtime::Handle::current().block_on(changed);
                };
                let input_room = Arc::clone(&worker_instance);
                let input_attachment = attachment.clone();
                let check_attachment = attachment.clone();
                let check_held = Arc::clone(&held);
                let metadata_room = Arc::clone(&worker_instance);
                let metadata_attachment = attachment.clone();
                let metadata_owner = Arc::clone(&input_owner);
                let metadata_instance = Arc::clone(&input_instance);
                let input = crate::node::channel::semantic_projection::SelectedReceiverInput::new(
                    move |slot| {
                        if *input_attachment.borrow() != epoch {
                            return Err(Error::AtRestLocked);
                        }
                        let channel = input_room.blocking_lock();
                        channel.classification_receiver_bytes(
                            slot,
                            &input_owner,
                            input_epoch,
                            &input_instance,
                        )
                    },
                    move |slot, iteration| {
                        if *metadata_attachment.borrow() != epoch {
                            return Err(Error::AtRestLocked);
                        }
                        let channel = metadata_room.blocking_lock();
                        channel.classification_receiver_metadata(
                            slot,
                            iteration,
                            &metadata_owner,
                            input_epoch,
                            &metadata_instance,
                        )
                    },
                    move |_| {
                        if check_held.publication.is_some() && !check_held.authority.current() {
                            return Err(Error::ComputerPolicySuperseded);
                        }
                        if *check_attachment.borrow() != epoch {
                            return Err(Error::AtRestLocked);
                        }
                        Ok(())
                    },
                );
                // Only compact selected-input preparation reacquires the room, after its
                // probe dropped the writer. Native transactions never retain that guard.
                Ok(input.scope(|| prepared.run(&held.store, held.signer.as_ref())))
            })
            .await;
            (
                Some(lifetime),
                match saved {
                    Ok(saved) => saved,
                    Err(_) => Err(Error::Profile("native save worker stopped")),
                },
            )
        });
        let task = tokio::spawn(async move {
            let returned = worker
                .await
                .unwrap_or_else(|_| (None, Err(Error::Profile("native save owner stopped"))));
            *worker_result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(returned);
            wake.notify_one();
        });
        self.pending_posts.insert(
            room,
            post_save::Pending::Maintenance(Box::new(Pending {
                instance,
                owner,
                store,
                epoch,
                preparing,
                retention_owed: false,
                governance_owed: false,
                result,
                task,
                continuation,
                reply,
            })),
        );
        true
    }

    pub(super) async fn complete_pending_maintenance(&mut self, room: Digest32) {
        let Some(post_save::Pending::Maintenance(pending)) = self.pending_posts.get(&room) else {
            return;
        };
        let returned = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some((lifetime, returned)) = returned else {
            return;
        };
        let instance = Arc::clone(&pending.instance);
        let Ok(mut channel) = instance.try_lock() else {
            *pending
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((lifetime, returned));
            return;
        };
        let current = pending.epoch == self.delivery_epoch
            && if pending.preparing {
                self.preparing_rooms
                    .get(&room)
                    .is_some_and(|prepared| Arc::ptr_eq(&prepared.channel, &instance))
            } else {
                self.channels
                    .get(&room)
                    .is_some_and(|current| Arc::ptr_eq(current, &instance))
            };
        let Some(post_save::Pending::Maintenance(mut pending)) = self.pending_posts.remove(&room)
        else {
            return;
        };
        let mut held = None;
        let installable = current
            && returned
                .as_ref()
                .is_ok_and(|done| done.can_install(&channel, &pending.owner));
        if let Ok(completed) = &returned {
            completed.mark_package_receipts(&mut pending.continuation);
        }
        let result = match returned {
            Ok(mut completed) if installable => {
                let pin = completed.take_history_pin();
                let receipt = completed.finish(&mut channel, &pending.store);
                held = receipt.held;
                let publication = channel.publish_history_read(Arc::clone(&pending.store));
                if publication.is_err() {
                    if let Some(pin) = pin {
                        self.failed_post_reads.insert(
                            room,
                            post_save::FailedRead {
                                instance: Arc::downgrade(&instance),
                                store: Arc::clone(&pending.store),
                                _pin: pin,
                            },
                        );
                    }
                }
                #[cfg(feature = "test-knobs")]
                if publication.is_ok() {
                    if let Ok(Saved::Governance(governance_save::Saved::Backfill {
                        render_hold: Some(path),
                        ..
                    })) = &receipt.result
                    {
                        crate::node::channel::engage_render_hold(path);
                    }
                }
                receipt.result
            }
            Ok(completed) => {
                channel.release_pending_text(&pending.owner, false);
                completed.into_result()
            }
            Err(error) => {
                channel.release_pending_text(&pending.owner, true);
                Err(error)
            }
        };
        channel.note_publication_complete();
        drop(channel);
        if let Some((room, target)) = held {
            self.consent_keys.remove(&room, &target);
        }
        let _ = pending.task.await;
        let (continuation, result, migrated) = pending.continuation.completed(result);
        if !current || (!installable && result.is_ok()) {
            match continuation {
                Continuation::Trust(next) => {
                    self.retire_owned_trust(room, result, next, pending.reply)
                        .await
                }
                Continuation::Governance(next) => {
                    governance_save::retire_detached(result, next, pending.reply)
                }
                Continuation::Consent(next) => {
                    consent_release::retire_detached(result, next, pending.reply)
                }
                Continuation::Leave(next) => {
                    leave_save::retire_detached(result, next, pending.reply)
                }
                Continuation::Read(next) => read_save::retire_detached(result, next, pending.reply),
                Continuation::Roster(next) => {
                    roster_save::retire_detached(result, next, pending.reply)
                }
                Continuation::Metadata(next) => {
                    metadata_save::retire_detached(room, result, next, pending.reply).await
                }
                _ => {
                    if let Some(reply) = pending.reply {
                        let _ = reply.send(outcome(&result));
                    }
                }
            }
            return;
        }
        let Some(lifetime) = lifetime else {
            self.reject_pending_maintenance(
                room,
                result.err().unwrap_or(Error::AtRestLocked),
                continuation,
                pending.reply,
            );
            if pending.governance_owed {
                self.continue_deferred_governance(room, &instance, pending.epoch);
            }
            return;
        };
        if !migrated
            && result.as_ref().is_ok_and(
                |saved| matches!(saved, Saved::Governance(saved) if saved.needs_legacy_migration()),
            )
        {
            let saved = match result {
                Ok(saved) => saved,
                Err(_) => unreachable!(),
            };
            let next = Continuation::AfterMigration(Box::new(Migration {
                next: continuation,
                saved,
                lifetime,
            }));
            Box::pin(self.begin_pending_maintenance(
                room,
                Work::Private(private_save::Work::LegacyMigration),
                next,
                pending.reply,
            ))
            .await;
            if pending.governance_owed {
                self.continue_deferred_governance(room, &instance, pending.epoch);
            }
            return;
        }
        match continuation {
            Continuation::Session(next) => {
                let saved = result.and_then(|saved| match saved {
                    Saved::Session(saved) => Ok(session_save::Saved::Session(saved)),
                    Saved::SessionPrelude(write) => Ok(session_save::Saved::Prelude(write)),
                    Saved::SessionOutbound {
                        package,
                        reservation,
                    } => Ok(session_save::Saved::OutboundPackage {
                        package,
                        reservation,
                    }),
                    Saved::Packages(package_save::Saved::SealedOutbound {
                        package,
                        reservation,
                        ..
                    }) => Ok(session_save::Saved::OutboundPackage {
                        package,
                        reservation,
                    }),
                    Saved::Unavailable => {
                        Err(Error::Profile("Session save is waiting for its room"))
                    }
                    _ => Err(Error::Profile("unexpected Session save completion")),
                });
                self.finish_owned_session(room, saved, lifetime, next, pending.reply)
                    .await;
            }
            Continuation::Trust(next) => {
                self.resume_owned_trust(room, result, next, pending.reply)
                    .await
            }
            Continuation::Private(next) => {
                self.finish_owned_private(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::Governance(next) => {
                self.finish_owned_governance(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::Preparation(next) => {
                self.finish_owned_preparation(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::Packages(next) => {
                self.finish_owned_packages(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::Leave(next) => {
                self.finish_owned_leave(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::Recovery(next) => {
                self.finish_owned_recovery(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::Consent(next) => {
                self.finish_owned_consent(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::Read(next) => {
                self.finish_owned_read(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::Roster(next) => {
                self.finish_owned_roster(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::KeyPrune(next) => {
                self.finish_owned_key_prune(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::Metadata(next) => {
                self.finish_owned_metadata(room, result, lifetime, next, pending.reply)
                    .await
            }
            Continuation::AfterMigration(_) => unreachable!(),
        }
        if pending.governance_owed {
            self.continue_deferred_governance(room, &instance, pending.epoch);
        }
    }

    fn reject_pending_maintenance(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        match continuation {
            Continuation::Session(next) => self.reject_owned_session(room, error, next, reply),
            Continuation::Trust(next) => self.reject_owned_trust(room, error, next, reply),
            Continuation::Private(next) => self.reject_owned_private(error, next, reply),
            Continuation::Governance(next) => {
                self.reject_owned_governance(room, error, next, reply)
            }
            Continuation::Preparation(next) => {
                self.reject_owned_preparation(room, error, next, reply)
            }
            Continuation::Packages(next) => self.reject_owned_packages(room, error, next, reply),
            Continuation::Leave(next) => self.reject_owned_leave(room, error, next, reply),
            Continuation::Recovery(next) => self.reject_owned_recovery(room, error, next, reply),
            Continuation::Consent(next) => self.reject_owned_consent(room, error, next, reply),
            Continuation::Read(next) => self.reject_owned_read(room, error, next, reply),
            Continuation::Roster(next) => self.reject_owned_roster(room, error, next, reply),
            Continuation::KeyPrune(next) => self.reject_owned_key_prune(room, error, next, reply),
            Continuation::Metadata(next) => self.reject_owned_metadata(room, error, next, reply),
            Continuation::AfterMigration(next) => {
                self.reject_pending_maintenance(room, error, next.next, reply)
            }
        }
    }
}
