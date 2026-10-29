//! Reopen-map mutations and running prekey maintenance finish on actual native workers.
use super::*;
use crate::atrest::vault::VaultRootSigner;
use crate::node::channel::history::PendingHistoryRead;
use crate::node::open_rooms::RoomKeys;
use crate::node::store::{Batch, Store};

/// One room's owned reopen keys, never a replacement snapshot of the shared map.
pub(super) enum MapChange {
    Remember {
        channel_id: Digest32,
        keys: RoomKeys,
    },
    Forget(Digest32),
}

impl MapChange {
    pub(super) fn remember(channel: &ChannelState) -> crate::error::Result<Self> {
        let sek = channel.sek_bytes()?;
        let passphrase = channel.join_passphrase()?;
        if passphrase.len() > crate::node::open_rooms::MAX_ROOM_PASSPHRASE {
            return Err(Error::SizeLimitExceeded("open room passphrase"));
        }
        let sek = <[u8; crate::atrest::sek::SEK_LEN]>::try_from(sek.as_ref())
            .map_err(|_| Error::MalformedAtRest("open room SEK length"))?;
        Ok(Self::Remember {
            channel_id: channel.channel_id(),
            keys: RoomKeys {
                sek: zeroize::Zeroizing::new(sek),
                passphrase: zeroize::Zeroizing::new(passphrase.to_vec()),
            },
        })
    }

    /// The batch MUST already own the native writer. Loading afterwards observes every earlier
    /// room's committed change, including writers that won admission while this job waited.
    pub(super) fn queue(
        &self,
        store: &Store,
        signer: &VaultRootSigner,
        batch: &mut Batch<'_>,
    ) -> crate::error::Result<bool> {
        let mut rooms = OpenRooms::load(store, signer)?;
        let changed = match self {
            Self::Remember { channel_id, keys } => {
                rooms.remember(*channel_id, keys.sek.as_ref(), keys.passphrase.as_slice())?
            }
            Self::Forget(channel_id) => rooms.forget(channel_id),
        };
        if changed {
            rooms.queue_save(batch, signer)?;
        }
        Ok(changed)
    }

    pub(super) fn run(self, store: &Store, signer: &VaultRootSigner) -> crate::error::Result<()> {
        let mut batch = store.batch()?;
        if self.queue(store, signer, &mut batch)? {
            batch.commit()
        } else {
            Ok(())
        }
    }
}

pub(super) enum Work {
    Remember,
    Members(Vec<Digest32>),
}

/// Remembering is best effort AFTER the room itself exists. Its failure is not a failed create,
/// join or open; it is exactly RoomNotRemembered, delivered after the actual native attempt.
pub(super) struct Saved {
    pub(super) remembered: crate::error::Result<()>,
    journal: Option<JournalDelta>,
    members: bool,
}
impl Saved {
    fn remembered(remembered: crate::error::Result<()>) -> Self {
        Self {
            remembered,
            journal: None,
            members: false,
        }
    }
}

pub(super) struct Identity {
    room: Digest32,
    epoch: u64,
    owner: Arc<()>,
}
pub(super) enum Prepared {
    Remember {
        identity: Identity,
        change: crate::error::Result<MapChange>,
    },
    Members(crate::node::channel::pending_metadata::Prepared),
}
pub(super) enum Completed {
    Remember {
        pending: Identity,
        result: crate::error::Result<()>,
    },
    Members(crate::node::channel::pending_metadata::Completed),
}

impl Work {
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        _now: crate::time::Ms,
    ) -> crate::error::Result<Option<Prepared>> {
        Ok(Some(match self {
            Self::Remember => {
                if channel.post_pending() {
                    return Ok(None);
                }
                channel.reserve_pending_metadata(Arc::clone(&owner))?;
                Prepared::Remember {
                    identity: Identity {
                        room: channel.channel_id(),
                        epoch: channel.epoch(),
                        owner,
                    },
                    change: MapChange::remember(channel),
                }
            }
            Self::Members(members) => {
                Prepared::Members(channel.prepare_pending_known_members(store, owner, members)?)
            }
        }))
    }
}
impl Prepared {
    pub(super) fn run(self, store: &Store, signer: &VaultRootSigner) -> Completed {
        match self {
            Self::Remember { identity, change } => Completed::Remember {
                pending: identity,
                result: change.and_then(|change| change.run(store, signer)),
            },
            Self::Members(pending) => Completed::Members(pending.run(store)),
        }
    }
}
impl Completed {
    pub(super) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        match self {
            Self::Remember { pending, .. } => {
                Arc::ptr_eq(owner, &pending.owner)
                    && channel.metadata_write_owned(pending.room, pending.epoch, owner)
            }
            Self::Members(done) => done.can_install(channel, owner),
        }
    }
    pub(super) fn take_history_pin(&mut self) -> Option<PendingHistoryRead> {
        match self {
            Self::Remember { .. } => None,
            Self::Members(done) => done.take_history_pin(),
        }
    }
    pub(super) fn finish(
        self,
        channel: &mut ChannelState,
        _store: &Store,
    ) -> crate::error::Result<Saved> {
        match self {
            Self::Remember { pending, result } => {
                channel.release_pending_text(&pending.owner, false);
                Ok(Saved::remembered(result))
            }
            Self::Members(done) => done.finish(channel).map(|()| Saved {
                remembered: Ok(()),
                journal: None,
                members: true,
            }),
        }
    }
    pub(super) fn into_result(self) -> crate::error::Result<Saved> {
        match self {
            Self::Remember { result, .. } => Ok(Saved::remembered(result)),
            Self::Members(done) => done.into_result().map(|()| Saved {
                remembered: Ok(()),
                journal: None,
                members: true,
            }),
        }
    }
}

struct PrekeysSaved {
    usable: bool,
    persisted: bool,
    offered: (u64, Option<u64>),
    note: crate::node::status::PrekeyNote,
}

type PrekeysReturned = crate::error::Result<Option<PrekeysSaved>>;
struct PrekeysPending {
    epoch: u64,
    ring: Arc<tokio::sync::Mutex<PrekeyRing>>,
    result: Arc<std::sync::Mutex<Option<PrekeysReturned>>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PublicationTarget {
    Local,
    Anchor(Digest32),
    RoomCommand,
}
type PublicKey = (Digest32, PublicationTarget);

/// One typed book over existing real publication targets, not a second request queue. Remote
/// entries own the original `publishing` target; repeats still use `publish_again`.
#[derive(Default)]
pub(super) struct Pending {
    prekeys: Option<PrekeysPending>,
    publications: BTreeMap<PublicKey, PublicationPending>,
    journals: BTreeMap<Digest32, JournalPending>,
    join_replies: BTreeMap<Digest32, JoinPending>,
}
impl Pending {
    pub(super) async fn retire(self) {
        // Independent readers must retire concurrently: one initial publication can be waiting
        // behind the policy writer which another original continuation's retained reader blocks.
        let mut retiring = tokio::task::JoinSet::new();
        for (room, pending) in self.join_replies {
            match pending {
                JoinPending::Reply(pending) => {
                    retiring.spawn(pending.retire(room, Fault::Locked));
                }
                JoinPending::Adoption(pending) => {
                    retiring.spawn(pending.retire(room));
                }
            }
        }
        if let Some(prekeys) = self.prekeys {
            retiring.spawn(async move {
                let _ = prekeys.task.await;
            });
        }
        for (_, pending) in self.publications {
            retiring.spawn(pending.retire());
        }
        for (_, pending) in self.journals {
            retiring.spawn(pending.retire());
        }
        while retiring.join_next().await.is_some() {}
    }
}

impl Node {
    pub(super) fn metadata_save_pending(&self) -> bool {
        self.pending_metadata.as_ref().is_some_and(|pending| {
            pending.prekeys.is_some()
                || pending
                    .publications
                    .values()
                    .any(|pending| matches!(pending, PublicationPending::Native(_)))
                || !pending.journals.is_empty()
                || !pending.join_replies.is_empty()
        })
    }

    pub(super) fn note_room_remembered(&self, channel_id: Digest32, saved: Saved) {
        if let Err(error) = saved.remembered {
            let _ = self.event_tx.send(NodeEvent::RoomNotRemembered {
                channel_id,
                why: error.to_string(),
            });
        }
    }

    /// Retain the original running-maintenance semantics: a busy ring or failed maintenance is
    /// skipped; a failed SAVE leaves its actual generated ring usable and saved on next consume.
    /// No ring guard, crypto generation or native writer admission runs on the actor.
    pub(super) fn maintain_prekeys(&mut self) {
        if self
            .pending_metadata
            .as_ref()
            .is_some_and(|pending| pending.prekeys.is_some())
        {
            return;
        }
        let (Some(profile), Some(ring)) = (self.profile.as_ref(), self.prekeys.as_ref()) else {
            return;
        };
        let Ok(signer) = profile.signer_arc() else {
            return;
        };
        let Ok(secret) = self.secret_work.clone().try_read_owned() else {
            return;
        };
        let store = profile.store_handle();
        let ring = Arc::clone(ring);
        let worker_ring = Arc::clone(&ring);
        let now = self.now_ms().get();
        let epoch = self.delivery_epoch;
        let attachment = self.pairwise_epoch.subscribe();
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let task = tokio::spawn(async move {
            let saved = tokio::task::spawn_blocking(move || {
                let _secret = secret;
                if *attachment.borrow() != epoch {
                    return Ok(None);
                }
                // The former actor maintenance deliberately left a join holding the ring alone.
                let Ok(mut ring) = worker_ring.try_lock() else {
                    return Ok(None);
                };
                if *attachment.borrow() != epoch {
                    return Ok(None);
                }
                let done = ring.maintain(signer.as_ref(), now)?;
                if done.changed() {
                    prekeys::save(&store, signer.as_ref(), &ring)?;
                }
                Ok(Some(PrekeysSaved {
                    usable: done.rotated || done.one_time_added > 0,
                    persisted: done.changed(),
                    offered: ring.offered(),
                    note: crate::node::status::PrekeyNote {
                        one_time: ring.one_time_len(),
                        consumed: ring.consumed_len(),
                        signed_prekey: ring.signed_prekey_id(),
                        rotated: done.rotated,
                        added: done.one_time_added,
                        previous_used: ring.previous_used(),
                        retired: done.retired,
                        retired_held: ring.retired_len(),
                        retired_used: ring.retired_used(),
                        oldest_one_time: ring.oldest_one_time_created(),
                    },
                }))
            })
            .await
            .unwrap_or_else(|error| {
                Err(Error::Path {
                    op: "native prekey maintenance",
                    detail: error.to_string(),
                })
            });
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(saved);
            wake.notify_one();
        });
        self.pending_metadata
            .get_or_insert_with(Pending::default)
            .prekeys = Some(PrekeysPending {
            epoch,
            ring,
            result,
            task,
        });
    }

    fn complete_prekey_metadata(&mut self) {
        let Some(pending) = self
            .pending_metadata
            .as_ref()
            .and_then(|pending| pending.prekeys.as_ref())
        else {
            return;
        };
        let saved = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(saved) = saved else { return };
        let Some(pending) = self
            .pending_metadata
            .as_mut()
            .and_then(|pending| pending.prekeys.take())
        else {
            return;
        };
        let current = pending.epoch == self.delivery_epoch
            && self
                .prekeys
                .as_ref()
                .is_some_and(|ring| Arc::ptr_eq(ring, &pending.ring));
        if !current {
            return;
        }
        let saved = match saved {
            Ok(saved) => saved,
            Err(error) => {
                self.prekey_maintenance_error =
                    Some(format!("Native prekey maintenance stopped: {error}"));
                return;
            }
        };
        let Some(saved) = saved else { return };
        if saved.persisted {
            self.prekey_maintenance_error = None;
        }
        if saved.usable {
            for room in self.channels.keys() {
                self.key_package_rooms.insert(*room, true);
            }
            for prepared in self.preparing_rooms.values_mut() {
                prepared.retry_packages = true;
            }
        }
        let republish = self.prekeys_offered.is_some_and(|was| was != saved.offered);
        self.prekeys_offered = Some(saved.offered);
        crate::node::status::SyncBook::note_prekeys(&self.sync_book, saved.note);
        if republish {
            let now = self.now_ms().get();
            for (room, at) in &mut self.records_renew_at {
                *at = now;
                self.prekeys_changed.insert(*room);
                self.prekey_publish_owed
                    .retain(|(owed_room, _)| owed_room != room);
            }
        }
    }
}

/// The newly constructed room remains actor-owned until its real metadata completion. Nothing
/// below sends a ChannelState (or a live room mutex guard) into a native writer.
pub(super) enum RoomAfter {
    Create {
        channel: Box<ChannelState>,
        authority: computer::ComputerAuthority,
    },
    Join(Box<JoinTail>),
}
pub(super) struct JoinTail {
    pub(super) channel: Box<ChannelState>,
    pub(super) parsed: crate::node::link::InviteLink,
    pub(super) me: Digest32,
    pub(super) joined: crate::node::joinstream::JoinOutcome,
    pub(super) responder: Digest32,
    pub(super) conn: Arc<VoxConnection>,
    pub(super) authority: computer::ComputerAuthority,
}
impl RoomAfter {
    fn channel(&self) -> &ChannelState {
        match self {
            Self::Create { channel, .. } => channel,
            Self::Join(next) => &next.channel,
        }
    }
    fn authority(&self) -> &computer::ComputerAuthority {
        match self {
            Self::Create { authority, .. } => authority,
            Self::Join(next) => &next.authority,
        }
    }
}

enum RoomStage {
    Remember,
    Purge(Fault),
}
type RoomReturned = (
    Option<Arc<maintenance_save::Lifetime>>,
    crate::error::Result<Saved>,
);
pub(super) struct RoomPending {
    room: Digest32,
    epoch: u64,
    node: Digest32,
    store: Arc<Store>,
    signer: Arc<VaultRootSigner>,
    secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    result: Arc<std::sync::Mutex<Option<RoomReturned>>>,
    task: tokio::task::JoinHandle<()>,
    // Retain the unpublished room without requiring ChannelState itself to be Sync.
    // Only the actor consumes this owner; no guard crosses a native save or await.
    after: std::sync::Mutex<RoomAfter>,
    reply: oneshot::Sender<Outcome>,
    stage: RoomStage,
}

/// Rejecting an unpublished create/join changes the room rows and latest reopen map together.
pub(super) fn purge_unpublished(
    store: &Store,
    signer: &VaultRootSigner,
    node: Digest32,
    room: Digest32,
) -> crate::error::Result<()> {
    let mut batch = store.batch()?;
    MapChange::Forget(room).queue(store, signer, &mut batch)?;
    crate::node::history_demand::purge_own_recovery_in(&mut batch, node, room)?;
    batch.purge_channel(&room)?;
    batch.commit()
}

impl RoomPending {
    pub(super) async fn retire(self) {
        let _ = self.task.await;
        let returned = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let original = returned
            .as_ref()
            .map(|(_, result)| match result {
                Ok(saved) => saved
                    .remembered
                    .as_ref()
                    .err()
                    .map(fault_of)
                    .unwrap_or(Fault::Locked),
                Err(error) => fault_of(error),
            })
            .unwrap_or(Fault::Internal);
        let store = self.store;
        let signer = self.signer;
        let room = self.room;
        let node = self.node;
        let secret = self.secret;
        let after = self
            .after
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let joining = matches!(&after, RoomAfter::Join(_));
        let purged = tokio::task::spawn_blocking(move || {
            let _secret = secret;
            let _returned = returned;
            if joining {
                JournalWork::Abort { room, node }
                    .run(&store, &signer)
                    .map(|_| ())
            } else {
                purge_unpublished(&store, &signer, node, room)
            }
        })
        .await;
        let outcome = match purged {
            Ok(Ok(())) => Outcome::Failed(original),
            Ok(Err(error)) => Outcome::Failed(fault_of(&error)),
            Err(_) => Outcome::Failed(Fault::Internal),
        };
        let _ = self.reply.send(outcome);
    }
}

impl Node {
    pub(super) async fn begin_metadata_created(
        &mut self,
        mut channel: ChannelState,
        authority: computer::ComputerAuthority,
        reply: oneshot::Sender<Outcome>,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
    ) {
        let room = channel.channel_id();
        let retention = self.node_retention_for(&room);
        let step_retention = self.node_step_retention.for_room(&room);
        let mut install = || {
            channel.set_node_retention(retention);
            channel.set_node_step_retention(step_retention);
        };
        #[cfg(feature = "test-knobs")]
        let stale_creation = crate::node::computer::fx28_mutant("stale-room-create-authority");
        #[cfg(not(feature = "test-knobs"))]
        let stale_creation = false;
        let accepted = match &lifetime {
            Some(_) if stale_creation => {
                install();
                true
            }
            Some(held) => held.publish(install).is_some(),
            None => authority.publish_room_creation(install).is_some(),
        };
        self.begin_metadata_room(
            RoomAfter::Create {
                channel: Box::new(channel),
                authority,
            },
            reply,
            lifetime,
            accepted,
        )
        .await;
    }

    pub(super) async fn begin_metadata_room(
        &mut self,
        after: RoomAfter,
        reply: oneshot::Sender<Outcome>,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
        accepted: bool,
    ) {
        let room = after.channel().channel_id();
        // The original create/join completion owns this real-room reservation; its bounded
        // command/event admission is retained by reply, not copied into another command queue.
        let Some(profile) = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
        else {
            let _ = reply.send(Outcome::Failed(Fault::Locked));
            return;
        };
        let signer = match lifetime
            .as_ref()
            .map(|held| Arc::clone(&held.signer))
            .map(Ok)
            .unwrap_or_else(|| profile.signer_arc())
        {
            Ok(signer) => signer,
            Err(error) => {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
                return;
            }
        };
        let secret = match lifetime.as_ref().map(|held| Arc::clone(&held.secret)) {
            Some(secret) => secret,
            None => match self.secret_work.clone().try_read_owned() {
                Ok(secret) => Arc::new(secret),
                Err(_) => {
                    let _ = reply.send(Outcome::Failed(Fault::Locked));
                    return;
                }
            },
        };
        let store = lifetime
            .as_ref()
            .map(|held| Arc::clone(&held.store))
            .unwrap_or_else(|| profile.store_handle());
        let node = profile.fingerprint();
        let authority = after.authority().clone();
        let change = MapChange::remember(after.channel());
        let remove_withdrawal =
            matches!(&after, RoomAfter::Join(_)) && self.withdrawn.contains_key(&room);
        let epoch = self.delivery_epoch;
        let attachment = self.pairwise_epoch.subscribe();
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let worker_store = Arc::clone(&store);
        let worker_signer = Arc::clone(&signer);
        let worker_secret = Arc::clone(&secret);
        let task = tokio::spawn(async move {
            // Continuations retain their exact original physical reader/exclusive transition.
            let held = match lifetime {
                Some(held) => Some(held),
                None => authority.acquire_publication().await.map(|publication| {
                    Arc::new(maintenance_save::Lifetime {
                        authority,
                        publication: Some(publication),
                        exclusive: None,
                        secret: worker_secret,
                        store: Arc::clone(&worker_store),
                        signer: Arc::clone(&worker_signer),
                    })
                }),
            };
            let native_held = held.as_ref().map(Arc::clone);
            let saved = tokio::task::spawn_blocking(move || {
                if !accepted
                    || *attachment.borrow() != epoch
                    || native_held
                        .as_ref()
                        .is_none_or(|held| held.publish(|| ()).is_none())
                {
                    return Err(Error::ComputerPolicySuperseded);
                }
                let mut saved = Saved::remembered(
                    change.and_then(|change| change.run(&worker_store, &worker_signer)),
                );
                if remove_withdrawal {
                    saved.journal = Some(
                        JournalWork::RemoveWithdrawal { room }
                            .run(&worker_store, &worker_signer)?,
                    );
                }
                Ok(saved)
            })
            .await
            .unwrap_or_else(|_| Err(Error::Profile("native room metadata worker stopped")));
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((held, saved));
            wake.notify_one();
        });
        self.pending_posts.insert(
            room,
            post_save::Pending::Metadata(RoomPending {
                room,
                epoch,
                node,
                store,
                signer,
                secret,
                result,
                task,
                after: std::sync::Mutex::new(after),
                reply,
                stage: RoomStage::Remember,
            }),
        );
    }

    pub(super) async fn complete_room_metadata(&mut self, room: Digest32) {
        let Some(post_save::Pending::Metadata(pending)) = self.pending_posts.get(&room) else {
            return;
        };
        let returned = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some((lifetime, result)) = returned else {
            return;
        };
        let Some(post_save::Pending::Metadata(mut pending)) = self.pending_posts.remove(&room)
        else {
            return;
        };
        if let RoomStage::Purge(fault) = pending.stage {
            let outcome = match result {
                Ok(saved) => {
                    if let Some(delta) = &saved.journal {
                        self.install_metadata_journal(room, delta);
                    }
                    self.publish_metadata_withdrawal(room);
                    Outcome::Failed(fault)
                }
                Err(error) => Outcome::Failed(fault_of(&error)),
            };
            self.finish_metadata_original_reply(
                room,
                pending
                    .after
                    .into_inner()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                pending.reply,
                outcome,
                lifetime,
            )
            .await;
            return;
        }
        let current = pending.epoch == self.delivery_epoch
            && lifetime
                .as_ref()
                .is_some_and(|held| held.publish(|| ()).is_some());
        let result = match result {
            Ok(_) if !current => Err(Error::ComputerPolicySuperseded),
            result => result,
        };
        let saved = match result {
            Ok(saved) => saved,
            Err(error) => {
                let fault = fault_of(&error);
                let store = Arc::clone(&pending.store);
                let signer = Arc::clone(&pending.signer);
                let secret = Arc::clone(&pending.secret);
                let node = pending.node;
                let joining = matches!(
                    pending
                        .after
                        .get_mut()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                    RoomAfter::Join(_)
                );
                let output = Arc::clone(&pending.result);
                let wake = Arc::clone(&self.post_save_wake);
                pending.stage = RoomStage::Purge(fault);
                pending.task = tokio::spawn(async move {
                    let held = lifetime;
                    let saved = tokio::task::spawn_blocking(move || {
                        let _secret = secret;
                        if joining {
                            JournalWork::Abort { room, node }
                                .run(&store, &signer)
                                .map(|journal| {
                                    let mut saved = Saved::remembered(Ok(()));
                                    saved.journal = Some(journal);
                                    saved
                                })
                        } else {
                            purge_unpublished(&store, &signer, node, room)
                                .map(|()| Saved::remembered(Ok(())))
                        }
                    })
                    .await
                    .unwrap_or_else(|_| {
                        Err(Error::Profile("native unpublished-room cleanup stopped"))
                    });
                    *output
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((held, saved));
                    wake.notify_one();
                });
                self.pending_posts
                    .insert(room, post_save::Pending::Metadata(pending));
                return;
            }
        };
        if let Some(delta) = &saved.journal {
            self.install_metadata_journal(room, delta);
        }
        self.note_room_remembered(room, saved);
        let Some(lifetime) = lifetime else { return };
        let after = pending
            .after
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match after {
            RoomAfter::Create { channel, authority } => {
                self.finish_metadata_created(*channel, authority, lifetime, pending.reply)
                    .await;
            }
            RoomAfter::Join(next) => {
                match self
                    .prepare_metadata_joined(*next, Arc::clone(&lifetime))
                    .await
                {
                    Ok(joined) => {
                        let after = JoinAdoption {
                            authority: joined.authority,
                            responder: joined.responder,
                            conn: joined.conn,
                            members: joined.members,
                            reply: pending.reply,
                        };
                        self.begin_owned_join_adoption(
                            room,
                            joined.responder,
                            joined.session,
                            true,
                            lifetime,
                            after,
                        )
                        .await;
                    }
                    Err(fault) => self.begin_metadata_abort_join(
                        room,
                        fault,
                        Some(pending.reply),
                        Some(lifetime),
                    ),
                }
            }
        }
    }

    async fn finish_metadata_original_reply(
        &mut self,
        room: Digest32,
        after: RoomAfter,
        reply: oneshot::Sender<Outcome>,
        outcome: Outcome,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
    ) {
        match after {
            RoomAfter::Create { .. } => self.answer_when_published(room, reply, outcome).await,
            RoomAfter::Join(_) => {
                self.finish_metadata_join_reply(room, reply, outcome, lifetime, None)
                    .await
            }
        }
    }

    async fn finish_metadata_join_reply(
        &mut self,
        room: Digest32,
        reply: oneshot::Sender<Outcome>,
        outcome: Outcome,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
        completed: Option<Arc<CompletedJoinRollback>>,
    ) {
        self.joining.remove(&room);
        if self.joining.is_empty() {
            if let Some(net) = self.net.as_ref() {
                net.policy().forget_join_responders();
            }
        }
        self.pending_metadata
            .get_or_insert_with(Pending::default)
            .join_replies
            .insert(
                room,
                JoinPending::Reply(JoinReplyPending {
                    reply,
                    outcome,
                    lifetime,
                    completed,
                    phase: JoinReplyPhase::Held,
                }),
            );
        self.advance_metadata_join_replies().await;
    }

    async fn finish_metadata_created(
        &mut self,
        channel: ChannelState,
        authority: computer::ComputerAuthority,
        lifetime: Arc<maintenance_save::Lifetime>,
        reply: oneshot::Sender<Outcome>,
    ) {
        let room = channel.channel_id();
        if lifetime
            .publish(|| {
                self.role_wake.install(room, &channel.role_owed());
                self.own_key_room_set_changed.send_replace(());
                if let Some(net) = self.net.as_ref() {
                    net.forget_board_exchange_room(&room);
                }
                self.channels
                    .insert(room, Arc::new(tokio::sync::Mutex::new(channel)));
            })
            .is_none()
        {
            self.reject_metadata_publication(
                room,
                PublicationAfter::Created { authority, reply },
                Some(lifetime),
                Fault::ComputerPolicy,
            )
            .await;
            return;
        }
        self.adopt_channel_anchors(&room).await;
        self.refresh_network_view().await;
        self.begin_local_publication(
            room,
            Some(PublicationAfter::Created { authority, reply }),
            Some(lifetime),
        )
        .await;
    }

    async fn prepare_metadata_joined(
        &mut self,
        next: JoinTail,
        lifetime: Arc<maintenance_save::Lifetime>,
    ) -> Result<JoinedFields, Fault> {
        let JoinTail {
            channel,
            parsed,
            me,
            joined,
            responder,
            conn,
            authority,
        } = next;
        if self.profile.is_none() {
            return Err(Fault::NoIdentity);
        }
        if lifetime
            .publish(|| {
                self.role_wake
                    .install(parsed.channel_id, &channel.role_owed());
                self.own_key_room_set_changed.send_replace(());
                if let Some(net) = self.net.as_ref() {
                    net.forget_board_exchange_room(&parsed.channel_id);
                }
                self.channels.insert(
                    parsed.channel_id,
                    Arc::new(tokio::sync::Mutex::new(*channel)),
                );
            })
            .is_none()
        {
            return Err(Fault::ComputerPolicy);
        }
        self.governance_work.wake_room(parsed.channel_id);
        self.request_admitted_recovery(parsed.channel_id);
        self.refresh_reachers().await;
        let mut members = vec![responder];
        members.extend(parsed.members.into_iter().filter(|member| *member != me));
        Ok(JoinedFields {
            authority,
            responder,
            conn,
            members,
            session: joined.session,
        })
    }
}

#[derive(Clone)]
struct PublicBundle {
    pub(super) bundle: crate::identity::keyagreement::PrekeyBundlePublic,
    pub(super) offered: (u64, Option<u64>),
}
pub(super) struct ReadyPublicBundle {
    pub(super) bundle: crate::identity::keyagreement::PrekeyBundlePublic,
    pub(super) stamp: RecordStamp,
}
#[derive(Clone, Copy)]
pub(super) struct RecordStamp {
    pub(super) seq: u64,
    pub(super) stamp: u64,
}
pub(super) struct AnchorTarget {
    pub(super) conn: Arc<VoxConnection>,
    pub(super) cause: PublishCause,
    pub(super) serves_room: bool,
}
pub(super) struct OpenCallback {
    pub(super) reply: Option<oneshot::Sender<Outcome>>,
    pub(super) reopening: bool,
    pub(super) recovery: Option<String>,
}
pub(super) enum PublicationAfter {
    Created {
        authority: computer::ComputerAuthority,
        reply: oneshot::Sender<Outcome>,
    },
    Joined {
        authority: computer::ComputerAuthority,
        responder: Digest32,
        conn: Arc<VoxConnection>,
        reply: oneshot::Sender<Outcome>,
    },
    Opened {
        authority: computer::ComputerAuthority,
        callback: OpenCallback,
    },
    Revalidate {
        waiting: RoomPublication,
        authority: computer::ComputerAuthority,
    },
}
impl PublicationAfter {
    fn created_or_joined(&self) -> bool {
        matches!(self, Self::Created { .. } | Self::Joined { .. })
    }
    fn fail(self, fault: Fault) {
        let reply = match self {
            Self::Created { reply, .. } | Self::Joined { reply, .. } => Some(reply),
            Self::Opened { callback, .. } => callback.reply,
            Self::Revalidate { waiting, .. } => waiting.reply,
        };
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault));
        }
    }
}
enum PublicOutput {
    Extracted(PublicBundle),
    NoBundle {
        offered: (u64, Option<u64>),
        _error: Error,
    },
    Records {
        public: Option<PublicBundle>,
        stamps: Vec<Option<RecordStamp>>,
        journal: Option<JournalDelta>,
    },
}
type PublicReturned = (
    Option<Arc<maintenance_save::Lifetime>>,
    crate::error::Result<PublicOutput>,
);
enum PublicationPending {
    Native(Box<PublicPending>),
    Network(NetworkPending),
}
impl PublicationPending {
    async fn retire(self) {
        match self {
            Self::Native(pending) => pending.retire().await,
            Self::Network(pending) => {
                let _ = pending.task.await;
            }
        }
    }
}
struct NetworkPending {
    epoch: u64,
    instance: SharedChannel,
    result: Arc<std::sync::Mutex<Option<NetEvent>>>,
    task: tokio::task::JoinHandle<()>,
}

struct PublicPending {
    epoch: u64,
    room_epoch: u64,
    room_cancel: watch::Receiver<bool>,
    node: Digest32,
    instance: SharedChannel,
    net: Arc<crate::node::network::NodeNet>,
    store: Arc<Store>,
    signer: Arc<VaultRootSigner>,
    secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    local: bool,
    local_again: bool,
    targets: Vec<AnchorTarget>,
    after: Option<PublicationAfter>,
    result: Arc<std::sync::Mutex<Option<PublicReturned>>>,
    task: tokio::task::JoinHandle<()>,
}
impl PublicPending {
    async fn retire(self) {
        let _ = self.task.await;
        let returned = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let original = returned
            .as_ref()
            .and_then(|(_, result)| result.as_ref().err())
            .map(fault_of)
            .unwrap_or(Fault::Locked);
        if let Some(after) = self.after {
            let fault = if after.created_or_joined() {
                let held = returned.and_then(|(held, _)| held);
                let room = self.instance.lock().await.channel_id();
                let node = self.node;
                let store = self.store;
                let signer = self.signer;
                let secret = self.secret;
                let joining = matches!(&after, PublicationAfter::Joined { .. });
                match tokio::task::spawn_blocking(move || {
                    let _held = held;
                    let _secret = secret;
                    if joining {
                        JournalWork::Abort { room, node }
                            .run(&store, &signer)
                            .map(|_| ())
                    } else {
                        purge_unpublished(&store, &signer, node, room)
                    }
                })
                .await
                {
                    Ok(Ok(())) => original,
                    Ok(Err(error)) => fault_of(&error),
                    Err(_) => Fault::Internal,
                }
            } else {
                original
            };
            after.fail(fault);
        }
    }
}

impl Node {
    pub(super) fn metadata_publication_pending(&self, room: &Digest32) -> bool {
        self.pending_metadata.as_ref().is_some_and(|pending| {
            pending.journals.contains_key(room)
                || pending
                    .publications
                    .iter()
                    .any(|((pending_room, _), pending)| {
                        pending_room == room && matches!(pending, PublicationPending::Native(_))
                    })
        })
    }

    pub(super) async fn complete_pending_metadata(&mut self) {
        self.complete_metadata_publication_network().await;
        self.complete_metadata_journals().await;
        self.complete_prekey_metadata();
        self.advance_metadata_join_replies().await;
        let ready: Vec<_> = self
            .pending_metadata
            .as_ref()
            .map(|pending| {
                pending
                    .publications
                    .iter()
                    .filter_map(|(key, pending)| {
                        let PublicationPending::Native(pending) = pending else {
                            return None;
                        };
                        let result = pending
                            .result
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take();
                        result.map(|result| (*key, Arc::clone(&pending.result), result))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (key, cell, (lifetime, result)) in ready {
            let Some(candidate) = self
                .pending_metadata
                .as_mut()
                .and_then(|pending| pending.publications.remove(&key))
            else {
                continue;
            };
            let pending = match candidate {
                PublicationPending::Native(pending) if Arc::ptr_eq(&cell, &pending.result) => {
                    *pending
                }
                other => {
                    self.pending_metadata
                        .get_or_insert_with(Pending::default)
                        .publications
                        .insert(key, other);
                    continue;
                }
            };
            let room_current = pending.instance.lock().await.epoch() == pending.room_epoch;
            let current = room_current
                && !*pending.room_cancel.borrow()
                && pending.epoch == self.delivery_epoch
                && self
                    .channels
                    .get(&key.0)
                    .is_some_and(|channel| Arc::ptr_eq(channel, &pending.instance))
                && self
                    .net
                    .as_ref()
                    .is_some_and(|net| Arc::ptr_eq(net, &pending.net))
                && lifetime
                    .as_ref()
                    .is_some_and(|held| held.publish(|| ()).is_some());
            let result = match result {
                Ok(_) if !current => Err(Error::ComputerPolicySuperseded),
                result => result,
            };
            let output = match result {
                Ok(output) => output,
                Err(error) => {
                    let fault = fault_of(&error);
                    for target in pending.targets {
                        self.release_metadata_target(key.0, target).await;
                    }
                    if let Some(after) = pending.after {
                        self.reject_metadata_publication(key.0, after, lifetime, fault)
                            .await;
                    }
                    if pending.local_again {
                        self.begin_local_publication(key.0, None, None).await;
                    }
                    self.post_save_wake.notify_one();
                    continue;
                }
            };
            let Some(lifetime) = lifetime else { continue };
            let (public, stamps, journal) = match output {
                PublicOutput::Extracted(public) => {
                    let offered = public.offered;
                    self.begin_publication_records(key, pending, Some(public), offered, lifetime)
                        .await;
                    continue;
                }
                PublicOutput::NoBundle { offered, .. } => {
                    // own_records formerly refused this real bundle error without failing the
                    // create/join/open. Still complete its exact rollback-stamp attempts first.
                    self.begin_publication_records(key, pending, None, offered, lifetime)
                        .await;
                    continue;
                }
                PublicOutput::Records {
                    public,
                    stamps,
                    journal,
                } => (public, stamps, journal),
            };
            if let Some(delta) = journal {
                self.install_metadata_journal(key.0, &delta);
            }
            let mut stamps = stamps.into_iter();
            let mut public = public;
            if pending.local {
                if let Some(stamp) = stamps.next().flatten() {
                    let bundle = if pending.targets.is_empty() {
                        public.take()
                    } else {
                        public.clone()
                    };
                    if let Some(bundle) = bundle {
                        let ready = ReadyPublicBundle {
                            bundle: bundle.bundle,
                            stamp,
                        };
                        self.publish_channel_locally_ready(&key.0, ready, Arc::clone(&lifetime))
                            .await;
                    }
                }
            }
            let targets = pending.targets.len();
            for (index, target) in pending.targets.into_iter().enumerate() {
                let Some(stamp) = stamps.next().flatten() else {
                    self.release_metadata_target(key.0, target).await;
                    continue;
                };
                let bundle = if index + 1 == targets {
                    public.take()
                } else {
                    public.clone()
                };
                let Some(bundle) = bundle else {
                    self.release_metadata_target(key.0, target).await;
                    continue;
                };
                let ready = ReadyPublicBundle {
                    bundle: bundle.bundle,
                    stamp,
                };
                if !self
                    .publish_channel_to_anchor_ready(
                        &key.0,
                        &target.conn,
                        target.cause,
                        target.serves_room,
                        ready,
                        Arc::clone(&lifetime),
                    )
                    .await
                {
                    self.release_metadata_target(key.0, target).await;
                }
            }
            if let Some(after) = pending.after {
                self.finish_metadata_publication(key.0, after, Arc::clone(&lifetime))
                    .await;
            }
            if pending.local_again
                && self
                    .channels
                    .get(&key.0)
                    .is_some_and(|channel| Arc::ptr_eq(channel, &pending.instance))
            {
                self.begin_local_publication(key.0, None, None).await;
            }
        }
        if self.pending_metadata.as_ref().is_some_and(|pending| {
            pending.prekeys.is_none()
                && pending.publications.is_empty()
                && pending.journals.is_empty()
                && pending.join_replies.is_empty()
        }) {
            self.pending_metadata = None;
        }
    }

    pub(super) async fn begin_anchor_publication(
        &mut self,
        room: Digest32,
        conn: Arc<VoxConnection>,
        cause: PublishCause,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
    ) {
        let Some(target) = self.admit_metadata_anchor(room, conn, cause).await else {
            return;
        };
        let key = (room, PublicationTarget::Anchor(target.conn.peer_id()));
        self.begin_public_bundle(key, false, vec![target], None, lifetime)
            .await;
    }

    pub(super) async fn begin_local_publication(
        &mut self,
        room: Digest32,
        after: Option<PublicationAfter>,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
    ) {
        let key = (
            room,
            if after.is_some() {
                PublicationTarget::RoomCommand
            } else {
                PublicationTarget::Local
            },
        );
        if after.is_none() {
            if let Some(PublicationPending::Native(pending)) = self
                .pending_metadata
                .as_mut()
                .and_then(|pending| pending.publications.get_mut(&key))
            {
                pending.local_again = true;
                return;
            }
        }
        let mut targets = Vec::new();
        if after.is_some() {
            let cause = match &after {
                Some(PublicationAfter::Joined { .. }) => PublishCause::Join,
                _ => PublishCause::Opened,
            };
            let conns: Vec<_> = self
                .net
                .as_ref()
                .map(|net| {
                    self.anchor_ids
                        .iter()
                        .filter(|board| self.anchor_serves_room(&room, board))
                        .filter_map(|board| net.manager().existing(board))
                        .collect()
                })
                .unwrap_or_default();
            for conn in conns {
                if let Some(target) = self.admit_metadata_anchor(room, conn, cause).await {
                    targets.push(target);
                }
            }
            if let Some(PublicationAfter::Joined { conn, .. }) = &after {
                if !self.anchor_ids.contains(&conn.peer_id()) {
                    if let Some(target) = self
                        .admit_metadata_anchor(room, Arc::clone(conn), cause)
                        .await
                    {
                        targets.push(target);
                    }
                }
            }
        }
        self.begin_public_bundle(key, true, targets, after, lifetime)
            .await;
    }

    async fn admit_metadata_anchor(
        &mut self,
        room: Digest32,
        conn: Arc<VoxConnection>,
        cause: PublishCause,
    ) -> Option<AnchorTarget> {
        let serves_room = self.anchor_serves_room(&room, &conn.peer_id());
        if !serves_room {
            let instance = self.channels.get(&room)?;
            let channel = instance.lock().await;
            let member = match cause {
                PublishCause::Join => channel.is_known_member(&conn.peer_id()),
                PublishCause::Renewal | PublishCause::AskedAgain | PublishCause::Retry => {
                    channel.is_member(&conn.peer_id())
                }
                _ => false,
            };
            if !member {
                return None;
            }
        }
        if self.withdrawn.contains_key(&room)
            || self.net.is_none()
            || !self.channels.contains_key(&room)
        {
            return None;
        }
        let key = (room, conn.peer_id());
        if !self.publishing.insert(key) {
            match self.publish_again.entry(key) {
                std::collections::btree_map::Entry::Vacant(waiting) => {
                    waiting.insert(cause);
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    crate::node::status::SyncBook::note_publish_merged(&self.sync_book, cause)
                }
            }
            return None;
        }
        Some(AnchorTarget {
            conn,
            cause,
            serves_room,
        })
    }

    async fn begin_public_bundle(
        &mut self,
        key: PublicKey,
        local: bool,
        targets: Vec<AnchorTarget>,
        after: Option<PublicationAfter>,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
    ) {
        let lifetime = lifetime.or_else(|| {
            after
                .is_none()
                .then(|| self.inherit_room_publication_lifetime(&key.0))
                .flatten()
        });
        let captured = (|| {
            let profile = self
                .profile
                .as_ref()
                .filter(|profile| profile.is_unlocked())?;
            let instance = self.channels.get(&key.0).cloned()?;
            let net = self.net.as_ref().map(Arc::clone)?;
            let ring = self.prekeys.as_ref().map(Arc::clone)?;
            let authority = lifetime
                .as_ref()
                .map(|held| held.authority.clone())
                .or_else(|| {
                    after
                        .as_ref()
                        .map(|after| match after {
                            PublicationAfter::Created { authority, .. }
                            | PublicationAfter::Joined { authority, .. }
                            | PublicationAfter::Opened { authority, .. }
                            | PublicationAfter::Revalidate { authority, .. } => authority.clone(),
                        })
                        .or_else(|| self.computer_authority())
                })?;
            let signer = lifetime
                .as_ref()
                .map(|held| Arc::clone(&held.signer))
                .or_else(|| profile.signer_arc().ok())?;
            let secret = match lifetime.as_ref().map(|held| Arc::clone(&held.secret)) {
                Some(secret) => secret,
                None => Arc::new(self.secret_work.clone().try_read_owned().ok()?),
            };
            let store = lifetime
                .as_ref()
                .map(|held| Arc::clone(&held.store))
                .unwrap_or_else(|| profile.store_handle());
            Some((
                profile.fingerprint(),
                instance,
                net,
                ring,
                authority,
                signer,
                secret,
                store,
            ))
        })();
        let Some((node, instance, net, ring, authority, signer, secret, store)) = captured else {
            for target in targets {
                self.publishing.remove(&(key.0, target.conn.peer_id()));
            }
            if let Some(after) = after {
                after.fail(Fault::Locked);
            }
            return;
        };
        let room_epoch = instance.lock().await.epoch();
        let epoch = self.delivery_epoch;
        let attachment = self.pairwise_epoch.subscribe();
        let room_cancel = self.own_key_room_watch(key.0);
        let native_cancel = room_cancel.clone();
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let retire_store = Arc::clone(&store);
        let retire_signer = Arc::clone(&signer);
        let retire_secret = Arc::clone(&secret);
        let task = tokio::spawn(async move {
            let held = match lifetime {
                Some(held) => Some(held),
                None => authority.acquire_publication().await.map(|publication| {
                    Arc::new(maintenance_save::Lifetime {
                        authority,
                        publication: Some(publication),
                        exclusive: None,
                        secret,
                        store,
                        signer,
                    })
                }),
            };
            let native_held = held.as_ref().map(Arc::clone);
            let public = tokio::task::spawn_blocking(move || {
                let held = native_held.ok_or(Error::ComputerPolicySuperseded)?;
                if *native_cancel.borrow()
                    || *attachment.borrow() != epoch
                    || held.publish(|| ()).is_none()
                {
                    return Err(Error::ComputerPolicySuperseded);
                }
                // This dependency waits for the ACTUAL ring owner, never the actor. No cached
                // public bundle substitutes for a consume/maintenance that is still flushing.
                let ring = ring.blocking_lock();
                if *native_cancel.borrow()
                    || *attachment.borrow() != epoch
                    || held.publish(|| ()).is_none()
                {
                    return Err(Error::ComputerPolicySuperseded);
                }
                let offered = ring.offered();
                Ok(
                    match ring.bundle(&crate::identity::composite::RootSigner::public_key(
                        held.signer.as_ref(),
                    )) {
                        Ok(bundle) => PublicOutput::Extracted(PublicBundle { offered, bundle }),
                        Err(error) => PublicOutput::NoBundle {
                            offered,
                            _error: error,
                        },
                    },
                )
            })
            .await
            .unwrap_or_else(|_| Err(Error::Profile("native publication dependency stopped")));
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((held, public));
            wake.notify_one();
        });
        self.pending_metadata
            .get_or_insert_with(Pending::default)
            .publications
            .insert(
                key,
                PublicationPending::Native(Box::new(PublicPending {
                    epoch,
                    room_epoch,
                    room_cancel,
                    node,
                    instance,
                    net,
                    store: retire_store,
                    signer: retire_signer,
                    secret: retire_secret,
                    local,
                    local_again: false,
                    targets,
                    after,
                    result,
                    task,
                })),
            );
    }

    async fn reject_metadata_publication(
        &mut self,
        room: Digest32,
        after: PublicationAfter,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
        fault: Fault,
    ) {
        match after {
            PublicationAfter::Created { reply, .. } => {
                let Some(node) = self.profile.as_ref().map(Profile::fingerprint) else {
                    let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
                    return;
                };
                let publication = match self.channels.get(&room).cloned() {
                    Some(instance) => Some((
                        instance.lock().await.epoch(),
                        self.now_ms().get(),
                        self.withdrawal_routes(&room),
                    )),
                    None => None,
                };
                self.begin_metadata_journal(
                    room,
                    JournalWork::RejectCreated {
                        room,
                        node,
                        publication,
                    },
                    JournalAfter::Abort {
                        fault,
                        reply: Some(reply),
                        joining: false,
                    },
                    lifetime,
                );
            }
            PublicationAfter::Joined { reply, .. } => {
                self.begin_metadata_abort_join(room, fault, Some(reply), lifetime)
            }
            PublicationAfter::Opened { callback, .. } => {
                let outcome = self.reject_existing_live_channel(&room, fault);
                self.finish_metadata_open_reply(room, callback, outcome)
                    .await;
            }
            PublicationAfter::Revalidate { waiting, .. } => {
                self.fail_room_publication(room, waiting, fault)
            }
        }
    }

    async fn finish_metadata_publication(
        &mut self,
        room: Digest32,
        after: PublicationAfter,
        lifetime: Arc<maintenance_save::Lifetime>,
    ) {
        match after {
            PublicationAfter::Created { authority, reply } => {
                if lifetime
                    .publish(|| {
                        let _ = self
                            .event_tx
                            .send(NodeEvent::ChannelOpened { channel_id: room });
                        self.room_publication_authority.insert(
                            room,
                            (
                                authority.clone(),
                                RoomPublicationOwnership::Created,
                                Arc::clone(&lifetime),
                            ),
                        );
                    })
                    .is_some()
                {
                    self.answer_when_published(room, reply, Outcome::Done).await;
                } else {
                    self.reject_metadata_publication(
                        room,
                        PublicationAfter::Created { authority, reply },
                        Some(lifetime),
                        Fault::ComputerPolicy,
                    )
                    .await;
                }
            }
            PublicationAfter::Joined {
                authority,
                responder,
                reply,
                ..
            } => {
                #[cfg(feature = "test-knobs")]
                self.hold_room_join_after_board_for_proof().await;
                let Some(instance) = self.channels.get(&room).cloned() else {
                    self.begin_metadata_abort_join(
                        room,
                        Fault::ChannelNotOpen,
                        Some(reply),
                        Some(lifetime),
                    );
                    return;
                };
                let epoch = instance.lock().await.epoch();
                self.begin_metadata_journal(
                    room,
                    JournalWork::Complete {
                        room,
                        instance,
                        epoch,
                        lifetime: Arc::clone(&lifetime),
                    },
                    JournalAfter::Joined {
                        authority,
                        responder,
                        reply,
                    },
                    Some(lifetime),
                );
            }
            PublicationAfter::Opened {
                authority,
                callback,
            } => {
                self.begin_owned_package_turn(room, Some(Arc::clone(&lifetime)), None)
                    .await;
                self.reach_members_of(&room).await;
                let outcome = if lifetime
                    .publish(|| {
                        let _ = self
                            .event_tx
                            .send(NodeEvent::ChannelOpened { channel_id: room });
                        self.room_publication_authority.insert(
                            room,
                            (
                                authority.clone(),
                                RoomPublicationOwnership::Existing,
                                Arc::clone(&lifetime),
                            ),
                        );
                    })
                    .is_some()
                {
                    Outcome::Done
                } else {
                    self.reject_existing_live_channel(&room, Fault::ComputerPolicy)
                };
                self.finish_metadata_open_reply(room, callback, outcome)
                    .await;
            }
            PublicationAfter::Revalidate {
                mut waiting,
                authority,
            } => {
                waiting.authority = Some((authority, RoomPublicationOwnership::Existing, lifetime));
                self.publish_waiters.insert(room, waiting);
                self.publication_pending = true;
                self.publication_again = true;
            }
        }
    }
}

#[derive(Default)]
struct JournalDelta {
    join: Option<Option<PendingWithdrawal>>,
    withdrawal: Option<Option<PendingWithdrawal>>,
    completed_join: Option<Arc<CompletedJoinRollback>>,
    purged: bool,
}
// The original command owns this receipt through actor install, held-stream/consent completion,
// and its actual routing publication terminal; retirement must still withdraw and purge it.
pub(super) struct CompletedJoinRollback {
    wrap: crate::atrest::sek::SekWrap,
    instance: SharedChannel,
    epoch: u64,
    lifetime: Arc<maintenance_save::Lifetime>,
}
enum JournalWork {
    ForgetOpen {
        room: Digest32,
    },
    RemoveWithdrawal {
        room: Digest32,
    },
    Refresh {
        room: Digest32,
        epoch: u64,
        stamp: u64,
        board: Option<(Digest32, SocketAddr)>,
    },
    Complete {
        room: Digest32,
        instance: SharedChannel,
        epoch: u64,
        lifetime: Arc<maintenance_save::Lifetime>,
    },
    Abort {
        room: Digest32,
        node: Digest32,
    },
    AbortCompleted {
        room: Digest32,
        node: Digest32,
        completed: Arc<CompletedJoinRollback>,
    },
    AcceptCompleted {
        room: Digest32,
        completed: Arc<CompletedJoinRollback>,
    },
    PublicationReject {
        room: Digest32,
        node: Digest32,
        epoch: u64,
        now: u64,
        scope: crate::nat::withdraw::WithdrawScope,
        routes: BTreeMap<Digest32, Vec<SocketAddr>>,
    },
    PurgeUnpublished {
        room: Digest32,
        node: Digest32,
    },
    RejectCreated {
        room: Digest32,
        node: Digest32,
        publication: Option<(u64, u64, BTreeMap<Digest32, Vec<SocketAddr>>)>,
    },
    Retain {
        room: Digest32,
        board: Digest32,
        route: SocketAddr,
        wire: Vec<u8>,
        node: Digest32,
    },
    ForgetRefused {
        room: Digest32,
        board: Digest32,
        route: SocketAddr,
    },
}

fn load_journal(
    store: &Store,
    key: &str,
) -> crate::error::Result<BTreeMap<Digest32, PendingWithdrawal>> {
    store
        .get_meta(key)?
        .map(|bytes| read_pending_withdrawals(&bytes))
        .transpose()
        .map(Option::unwrap_or_default)
}
fn durable_withdrawals() -> bool {
    #[cfg(feature = "test-knobs")]
    {
        !crate::node::computer::fx28_mutant("withdrawal-not-durable")
    }
    #[cfg(not(feature = "test-knobs"))]
    {
        true
    }
}
fn add_rollback_route(pending: &mut PendingWithdrawal, board: Digest32, route: SocketAddr) {
    let routes = pending.routes.entry(board).or_default();
    if !routes.contains(&route) {
        if routes.len() == MAX_WITHDRAWAL_ROUTES {
            routes.remove(0);
        }
        routes.push(route);
    }
}

fn verify_join_rollback(
    cleanup: &PendingWithdrawal,
    signer: &VaultRootSigner,
    room: Digest32,
    epoch: u64,
) -> crate::error::Result<()> {
    let withdrawal = crate::nat::withdraw::BoardWithdraw::from_wire(&cleanup.wire)?;
    if withdrawal.channel_id != room
        || withdrawal.epoch != epoch
        || withdrawal.scope != crate::nat::withdraw::WithdrawScope::Member
        || withdrawal.author_id != crate::identity::composite::RootSigner::fingerprint(signer)
    {
        return Err(Error::Profile("join rollback identity changed"));
    }
    withdrawal.verify(&crate::identity::composite::RootSigner::public_key(signer))
}
impl JournalWork {
    fn run(self, store: &Store, signer: &VaultRootSigner) -> crate::error::Result<JournalDelta> {
        self.run_admitted(store, signer, || Ok(()))
    }

    fn run_admitted(
        self,
        store: &Store,
        signer: &VaultRootSigner,
        admitted: impl FnOnce() -> crate::error::Result<()>,
    ) -> crate::error::Result<JournalDelta> {
        // Every journal RMW observes the latest committed map after this exact writer admission.
        let mut batch = store.batch()?;
        admitted()?;
        let mut delta = JournalDelta::default();
        match self {
            Self::ForgetOpen { room } => {
                if MapChange::Forget(room).queue(store, signer, &mut batch)? {
                    batch.commit()?;
                }
                return Ok(delta);
            }
            Self::RejectCreated {
                room,
                node,
                publication,
            } => {
                if let Some((epoch, now, routes)) = publication {
                    let wire = crate::nat::withdraw::BoardWithdraw::build(
                        signer,
                        &room,
                        epoch,
                        crate::nat::withdraw::WithdrawScope::Room,
                        now,
                    )?
                    .to_wire();
                    let mut withdrawn = load_journal(store, PENDING_WITHDRAWALS_META_KEY)?;
                    withdrawn.insert(room, PendingWithdrawal { wire, routes });
                    delta.withdrawal = Some(withdrawn.get(&room).cloned());
                    if durable_withdrawals() {
                        batch.put_meta(
                            PENDING_WITHDRAWALS_META_KEY,
                            &pending_withdrawals_bytes(&withdrawn)?,
                        )?;
                    }
                }
                MapChange::Forget(room).queue(store, signer, &mut batch)?;
                crate::node::history_demand::purge_own_recovery_in(&mut batch, node, room)?;
                batch.purge_channel(&room)?;
                batch.commit()?;
                delta.purged = true;
                return Ok(delta);
            }
            Self::RemoveWithdrawal { room } => {
                let mut pending = load_journal(store, PENDING_WITHDRAWALS_META_KEY)?;
                pending.remove(&room);
                if durable_withdrawals() {
                    batch.put_meta(
                        PENDING_WITHDRAWALS_META_KEY,
                        &pending_withdrawals_bytes(&pending)?,
                    )?;
                    batch.commit()?;
                }
                delta.withdrawal = Some(None);
                return Ok(delta);
            }
            Self::Abort { room, node } => {
                delta = queue_abort_join(store, signer, &mut batch, node, room)?;
                if !delta.purged && store.get_sek_wrap(&room)?.is_some() {
                    return Err(Error::Profile("stored join has no rollback journal"));
                }
                if delta.purged {
                    batch.commit()?;
                }
                return Ok(delta);
            }
            Self::AbortCompleted {
                room,
                node,
                completed,
            } => {
                let epoch = completed.instance.blocking_lock().epoch();
                if epoch != completed.epoch
                    || store.get_sek_wrap(&room)?.as_ref() != Some(&completed.wrap)
                {
                    return Err(Error::Profile("completed join room incarnation changed"));
                }
                let mut unfinished = load_journal(store, PENDING_JOIN_CLEANUP_META_KEY)?;
                let cleanup = unfinished
                    .remove(&room)
                    .ok_or(Error::Profile("completed join has no rollback journal"))?;
                verify_join_rollback(&cleanup, signer, room, completed.epoch)?;
                delta = queue_join_rollback(
                    store, signer, &mut batch, node, room, cleanup, unfinished,
                )?;
                batch.commit()?;
                return Ok(delta);
            }
            Self::AcceptCompleted { room, completed } => {
                let epoch = completed.instance.blocking_lock().epoch();
                if epoch != completed.epoch
                    || store.get_sek_wrap(&room)?.as_ref() != Some(&completed.wrap)
                {
                    return Err(Error::Profile("accepted join room incarnation changed"));
                }
                let mut pending = load_journal(store, PENDING_JOIN_CLEANUP_META_KEY)?;
                let cleanup = pending
                    .remove(&room)
                    .ok_or(Error::Profile("accepted join has no rollback journal"))?;
                verify_join_rollback(&cleanup, signer, room, completed.epoch)?;
                if durable_withdrawals() {
                    batch.put_meta(
                        PENDING_JOIN_CLEANUP_META_KEY,
                        &pending_withdrawals_bytes(&pending)?,
                    )?;
                    batch.commit()?;
                }
                delta.join = Some(None);
                return Ok(delta);
            }
            Self::Complete {
                room,
                instance,
                epoch,
                lifetime,
            } => {
                let room_epoch = instance.blocking_lock().epoch();
                if room_epoch != epoch {
                    return Err(Error::Profile("join room epoch changed before completion"));
                }
                let mut pending = load_journal(store, PENDING_JOIN_CLEANUP_META_KEY)?;
                let cleanup = pending
                    .remove(&room)
                    .ok_or(Error::Profile("join completion has no rollback journal"))?;
                verify_join_rollback(&cleanup, signer, room, epoch)?;
                // A fresh join seals a fresh wrap. Compare that exact saved incarnation before
                // compensation, never just a room id that may already name a replacement join.
                let wrap = store
                    .get_sek_wrap(&room)?
                    .ok_or(Error::Profile("join completion has no saved room"))?;
                // Keep the durable journal through routing acceptance. A failed compensation
                // must leave its original recovery authority intact, not only a dropped receipt.
                delta.completed_join = Some(Arc::new(CompletedJoinRollback {
                    wrap,
                    instance,
                    epoch,
                    lifetime,
                }));
                return Ok(delta);
            }
            Self::PurgeUnpublished { room, node } => {
                queue_unpublished_purge(store, signer, &mut batch, node, room)?;
                batch.commit()?;
                delta.purged = true;
                return Ok(delta);
            }
            Self::PublicationReject {
                room,
                node,
                epoch,
                now,
                scope,
                routes,
            } => {
                if scope == crate::nat::withdraw::WithdrawScope::Member {
                    delta = queue_abort_join(store, signer, &mut batch, node, room)?;
                    if delta.purged {
                        batch.commit()?;
                        return Ok(delta);
                    }
                }
                let wire =
                    crate::nat::withdraw::BoardWithdraw::build(signer, &room, epoch, scope, now)?
                        .to_wire();
                let mut withdrawn = load_journal(store, PENDING_WITHDRAWALS_META_KEY)?;
                withdrawn.insert(room, PendingWithdrawal { wire, routes });
                delta.withdrawal = Some(withdrawn.get(&room).cloned());
                if durable_withdrawals() {
                    batch.put_meta(
                        PENDING_WITHDRAWALS_META_KEY,
                        &pending_withdrawals_bytes(&withdrawn)?,
                    )?;
                    batch.commit()?;
                }
                return Ok(delta);
            }
            work => {
                let mut pending = load_journal(store, PENDING_JOIN_CLEANUP_META_KEY)?;
                let room = match work {
                    Self::Refresh {
                        room,
                        epoch,
                        stamp,
                        board,
                    } => {
                        let Some(entry) = pending.get_mut(&room) else {
                            return Ok(delta);
                        };
                        let prior = crate::nat::withdraw::BoardWithdraw::from_wire(&entry.wire)?;
                        entry.wire = crate::nat::withdraw::BoardWithdraw::build(
                            signer,
                            &room,
                            epoch,
                            crate::nat::withdraw::WithdrawScope::Member,
                            stamp.max(prior.timestamp_ms),
                        )?
                        .to_wire();
                        if let Some((board, route)) = board {
                            add_rollback_route(entry, board, route);
                        }
                        room
                    }
                    Self::Retain {
                        room,
                        board,
                        route,
                        wire,
                        node,
                    } => {
                        if store.get_sek_wrap(&room)?.is_some() {
                            return Err(Error::Profile(
                                "an existing room cannot become join rollback state",
                            ));
                        }
                        let withdrawal = crate::nat::withdraw::BoardWithdraw::from_wire(&wire)?;
                        if withdrawal.channel_id != room
                            || withdrawal.scope != crate::nat::withdraw::WithdrawScope::Member
                            || withdrawal.author_id != node
                        {
                            return Err(Error::Profile(
                                "join rollback does not name this member and room",
                            ));
                        }
                        withdrawal
                            .verify(&crate::identity::composite::RootSigner::public_key(signer))?;
                        let entry = pending.entry(room).or_insert_with(|| PendingWithdrawal {
                            wire: wire.clone(),
                            routes: BTreeMap::new(),
                        });
                        let prior = crate::nat::withdraw::BoardWithdraw::from_wire(&entry.wire)?;
                        if withdrawal.timestamp_ms >= prior.timestamp_ms {
                            entry.wire = wire;
                        }
                        add_rollback_route(entry, board, route);
                        room
                    }
                    Self::ForgetRefused { room, board, route } => {
                        if let Some(entry) = pending.get_mut(&room) {
                            if let Some(routes) = entry.routes.get_mut(&board) {
                                routes.retain(|kept| *kept != route);
                                if routes.is_empty() {
                                    entry.routes.remove(&board);
                                }
                            }
                            if entry.routes.is_empty() {
                                pending.remove(&room);
                            }
                        }
                        room
                    }
                    Self::Abort { .. }
                    | Self::Complete { .. }
                    | Self::AbortCompleted { .. }
                    | Self::AcceptCompleted { .. }
                    | Self::RemoveWithdrawal { .. }
                    | Self::RejectCreated { .. }
                    | Self::ForgetOpen { .. }
                    | Self::PublicationReject { .. }
                    | Self::PurgeUnpublished { .. } => {
                        return Err(Error::Profile("unexpected join journal operation"));
                    }
                };
                delta.join = Some(pending.get(&room).cloned());
                if durable_withdrawals() {
                    batch.put_meta(
                        PENDING_JOIN_CLEANUP_META_KEY,
                        &pending_withdrawals_bytes(&pending)?,
                    )?;
                    batch.commit()?;
                }
            }
        }
        Ok(delta)
    }
}

impl Node {
    fn install_metadata_journal(&mut self, room: Digest32, delta: &JournalDelta) {
        if let Some(join) = &delta.join {
            match join {
                Some(join) => {
                    self.join_cleanup.insert(room, join.clone());
                }
                None => {
                    self.join_cleanup.remove(&room);
                }
            }
        }
        if let Some(withdrawal) = &delta.withdrawal {
            match withdrawal {
                Some(withdrawal) => {
                    self.withdrawn.insert(room, withdrawal.clone());
                }
                None => {
                    self.withdrawn.remove(&room);
                }
            }
        }
        if delta.purged {
            self.retract_live_channel(&room);
        }
    }
}

enum JournalAfter {
    Joined {
        authority: computer::ComputerAuthority,
        responder: Digest32,
        reply: oneshot::Sender<Outcome>,
    },
    AcceptedJoined {
        reply: oneshot::Sender<Outcome>,
        outcome: Outcome,
        completed: Arc<CompletedJoinRollback>,
    },
    Abort {
        fault: Fault,
        reply: Option<oneshot::Sender<Outcome>>,
        joining: bool,
    },
    Board {
        board: Digest32,
        retain: bool,
        ack: oneshot::Sender<crate::error::Result<()>>,
    },
    ForgetOpen,
    PublicationRejected(PublicationRejection),
    RoomWithdrawal(RoomWithdrawal),
}
type JournalReturned = (
    Option<Arc<maintenance_save::Lifetime>>,
    Option<crate::node::channel::own_writer_gate::Transition>,
    crate::error::Result<JournalDelta>,
);
struct JournalPending {
    room: Digest32,
    epoch: u64,
    node: Digest32,
    instance: Option<SharedChannel>,
    store: Arc<Store>,
    signer: Arc<VaultRootSigner>,
    secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    result: Arc<std::sync::Mutex<Option<JournalReturned>>>,
    task: tokio::task::JoinHandle<()>,
    after: JournalAfter,
    following_withdrawal: Option<RoomWithdrawal>,
}
impl JournalPending {
    async fn retire(mut self) {
        let _ = self.task.await;
        let mut returned = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let (JournalAfter::PublicationRejected(rejected), Some((_, transition, _))) =
            (&mut self.after, &mut returned)
        {
            rejected.transition = transition.take();
        }
        let room = self.room;
        let node = self.node;
        let store = self.store;
        let signer = self.signer;
        let secret = self.secret;
        match self.after {
            JournalAfter::AcceptedJoined {
                reply,
                outcome,
                completed,
            } => {
                let result = returned
                    .as_ref()
                    .map(|(_, _, result)| result.as_ref().map(|_| ()).map_err(fault_of))
                    .unwrap_or(Err(Fault::Internal));
                match result {
                    Ok(()) => {
                        let _ = reply.send(outcome);
                    }
                    Err(fault) => {
                        JoinReplyPending {
                            reply,
                            outcome,
                            lifetime: Some(Arc::clone(&completed.lifetime)),
                            completed: Some(completed),
                            phase: JoinReplyPhase::Held,
                        }
                        .retire(room, fault)
                        .await;
                    }
                }
            }
            JournalAfter::Joined { reply, .. } => {
                let original = returned
                    .as_ref()
                    .map(|(_, _, result)| match result {
                        Ok(_) => Fault::Locked,
                        Err(error) => fault_of(error),
                    })
                    .unwrap_or(Fault::Internal);
                let fault = match tokio::task::spawn_blocking(move || {
                    let _secret = secret;
                    let completed = returned
                        .as_mut()
                        .and_then(|(_, _, result)| result.as_mut().ok())
                        .and_then(|delta| delta.completed_join.take());
                    let _returned = returned;
                    match completed {
                        Some(completed) => JournalWork::AbortCompleted {
                            room,
                            node,
                            completed,
                        },
                        None => JournalWork::Abort { room, node },
                    }
                    .run(&store, &signer)
                })
                .await
                {
                    Ok(Ok(_)) => original,
                    Ok(Err(error)) => fault_of(&error),
                    Err(_) => Fault::Internal,
                };
                let _ = reply.send(Outcome::Failed(fault));
            }
            JournalAfter::Abort {
                reply: Some(reply), ..
            } => {
                let fault = returned
                    .map(|(_, _, result)| {
                        result
                            .err()
                            .map(|error| fault_of(&error))
                            .unwrap_or(Fault::Locked)
                    })
                    .unwrap_or(Fault::Internal);
                let _ = reply.send(Outcome::Failed(fault));
            }
            JournalAfter::Board { ack, .. } => {
                let error = returned
                    .and_then(|(_, _, result)| result.err())
                    .unwrap_or(Error::AtRestLocked);
                let _ = ack.send(Err(error));
            }
            JournalAfter::PublicationRejected(rejected) => {
                let fault = returned
                    .as_ref()
                    .map(|(_, _, result)| {
                        result
                            .as_ref()
                            .err()
                            .map(fault_of)
                            .unwrap_or(Fault::ComputerPolicy)
                    })
                    .unwrap_or(Fault::Internal);
                let needs_purge = returned
                    .as_ref()
                    .is_some_and(|(_, _, result)| result.as_ref().is_ok_and(|delta| !delta.purged))
                    && publication_superseded(&rejected.waiting);
                let fault = if needs_purge {
                    let authority = rejected
                        .waiting
                        .authority
                        .as_ref()
                        .map(|(authority, _, _)| authority.clone());
                    match tokio::task::spawn_blocking(move || {
                        let _secret = secret;
                        let _returned = returned;
                        JournalWork::PurgeUnpublished { room, node }
                            .run_admitted(&store, &signer, || {
                                if authority.as_ref().is_some_and(authority_superseded) {
                                    Ok(())
                                } else {
                                    Err(Error::ComputerPolicySuperseded)
                                }
                            })
                            .map(|_| ())
                    })
                    .await
                    {
                        Ok(Ok(())) => fault,
                        Ok(Err(error)) => fault_of(&error),
                        Err(_) => Fault::Internal,
                    }
                } else {
                    fault
                };
                if let Some(reply) = rejected.waiting.reply {
                    let _ = reply.send(Outcome::Failed(fault));
                }
                drop(rejected.transition);
            }
            JournalAfter::RoomWithdrawal(withdrawal) => {
                let result = returned
                    .as_ref()
                    .map(|(_, _, result)| result.as_ref().map(|_| 0).map_err(fault_of))
                    .unwrap_or(Err(Fault::Internal));
                withdrawal.purpose.answer(room, result);
            }
            JournalAfter::Abort { reply: None, .. } | JournalAfter::ForgetOpen => {}
        }
        if let Some(following) = self.following_withdrawal {
            following.purpose.answer(room, Err(Fault::Locked));
        }
    }
}

impl Node {
    fn begin_metadata_journal(
        &mut self,
        room: Digest32,
        work: JournalWork,
        mut after: JournalAfter,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
    ) {
        let captured = (|| {
            if let JournalAfter::RoomWithdrawal(withdrawal) = &after {
                return Some((
                    crate::identity::composite::RootSigner::fingerprint(withdrawal.signer.as_ref()),
                    Arc::clone(&withdrawal.store),
                    Arc::clone(&withdrawal.signer),
                    Arc::clone(&withdrawal.secret),
                ));
            }
            if let Some(held) = &lifetime {
                return Some((
                    crate::identity::composite::RootSigner::fingerprint(held.signer.as_ref()),
                    Arc::clone(&held.store),
                    Arc::clone(&held.signer),
                    Arc::clone(&held.secret),
                ));
            }
            let profile = self
                .profile
                .as_ref()
                .filter(|profile| profile.is_unlocked())?;
            let store = lifetime
                .as_ref()
                .map(|held| Arc::clone(&held.store))
                .unwrap_or_else(|| profile.store_handle());
            let signer = lifetime
                .as_ref()
                .map(|held| Arc::clone(&held.signer))
                .or_else(|| profile.signer_arc().ok())?;
            let secret = match lifetime.as_ref().map(|held| Arc::clone(&held.secret)) {
                Some(secret) => secret,
                None => Arc::new(self.secret_work.clone().try_read_owned().ok()?),
            };
            Some((profile.fingerprint(), store, signer, secret))
        })();
        let Some((node, store, signer, secret)) = captured else {
            match after {
                JournalAfter::Joined { reply, .. } | JournalAfter::AcceptedJoined { reply, .. } => {
                    let _ = reply.send(Outcome::Failed(Fault::Locked));
                }
                JournalAfter::Abort {
                    reply: Some(reply), ..
                } => {
                    let _ = reply.send(Outcome::Failed(Fault::Locked));
                }
                JournalAfter::Board { ack, .. } => {
                    let _ = ack.send(Err(Error::AtRestLocked));
                }
                JournalAfter::Abort { reply: None, .. } => {}
                JournalAfter::ForgetOpen => {}
                JournalAfter::RoomWithdrawal(withdrawal) => {
                    withdrawal.purpose.answer(room, Err(Fault::Locked))
                }
                JournalAfter::PublicationRejected(rejected) => {
                    self.fail_room_publication(room, rejected.waiting, Fault::Locked);
                    drop(rejected.transition);
                }
            }
            return;
        };
        let epoch = self.delivery_epoch;
        let instance = match &work {
            JournalWork::Complete { instance, .. } => Some(Arc::clone(instance)),
            JournalWork::AbortCompleted { completed, .. }
            | JournalWork::AcceptCompleted { completed, .. } => {
                Some(Arc::clone(&completed.instance))
            }
            _ => self.channels.get(&room).cloned(),
        };
        let mut attachment = self.pairwise_epoch.subscribe();
        let rejection = match &mut after {
            JournalAfter::PublicationRejected(rejected) => {
                let Some(authority) = rejected
                    .waiting
                    .authority
                    .as_ref()
                    .map(|(authority, _, _)| authority.clone())
                else {
                    if let JournalAfter::PublicationRejected(rejected) = after {
                        self.fail_room_publication(room, rejected.waiting, Fault::Internal);
                    }
                    return;
                };
                Some((
                    Arc::clone(&rejected.instance),
                    rejected.epoch,
                    authority,
                    rejected.transition.take(),
                    self.own_key_room_watch(room),
                ))
            }
            _ => None,
        };
        let withdrawal = match &after {
            JournalAfter::RoomWithdrawal(withdrawal) => Some((
                withdrawal.authority.clone(),
                self.own_key_room_watch(room),
                Arc::clone(&withdrawal.instance),
                withdrawal.room_epoch,
                withdrawal.now,
                matches!(&withdrawal.purpose, RoomWithdrawalPurpose::Idle { .. }),
            )),
            _ => None,
        };
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let worker_store = Arc::clone(&store);
        let worker_signer = Arc::clone(&signer);
        let worker_secret = Arc::clone(&secret);
        let strict = matches!(
            &after,
            JournalAfter::Joined { .. }
                | JournalAfter::AcceptedJoined { .. }
                | JournalAfter::Board { .. }
        );
        let requires_lifetime = matches!(
            &after,
            JournalAfter::Joined { .. } | JournalAfter::AcceptedJoined { .. }
        );
        let task = tokio::spawn(async move {
            let (lifetime, withdrawal_fence) =
                if let Some((authority, mut room_cancel, instance, room_epoch, now, idle)) =
                    withdrawal
                {
                    if *attachment.borrow() != epoch || *room_cancel.borrow() {
                        *output
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some((lifetime, None, Err(Error::AtRestLocked)));
                        wake.notify_one();
                        return;
                    }
                    let held = match lifetime {
                        Some(held) => Some(held),
                        None => {
                            let publication = tokio::select! {
                                biased;
                                _ = attachment.changed() => None,
                                _ = room_cancel.changed() => None,
                                publication = authority.acquire_publication() => publication,
                            };
                            publication.map(|publication| {
                                Arc::new(maintenance_save::Lifetime {
                                    authority: authority.clone(),
                                    publication: Some(publication),
                                    exclusive: None,
                                    secret: Arc::clone(&worker_secret),
                                    store: Arc::clone(&worker_store),
                                    signer: Arc::clone(&worker_signer),
                                })
                            })
                        }
                    };
                    if held.is_none() {
                        let error = if *attachment.borrow() != epoch || *room_cancel.borrow() {
                            Error::AtRestLocked
                        } else {
                            Error::ComputerPolicySuperseded
                        };
                        *output
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some((None, None, Err(error)));
                        wake.notify_one();
                        return;
                    }
                    (
                        held,
                        Some((room_cancel, instance, room_epoch, now, idle, authority)),
                    )
                } else {
                    (lifetime, None)
                };
            let (transition, fence) = if let Some((
                instance,
                expected_epoch,
                authority,
                provided,
                mut room_cancel,
            )) = rejection
            {
                let mut transition = provided;
                let acquired = async {
                    if *room_cancel.borrow() || *attachment.borrow() != epoch || !authority_superseded(&authority) {
                        return Err(Error::ComputerPolicySuperseded);
                    }
                    let gate = tokio::select! {
                        biased;
                        _ = room_cancel.changed() => return Err(Error::AtRestLocked),
                        _ = attachment.changed() => return Err(Error::AtRestLocked),
                        channel = instance.lock() => {
                            if channel.epoch() != expected_epoch { return Err(Error::AtRestLocked); }
                            transition.is_none().then(|| Arc::clone(&channel.own_writer_gate))
                        }
                    };
                    if let Some(gate) = gate {
                        transition = Some(tokio::select! {
                            biased;
                            _ = room_cancel.changed() => return Err(Error::AtRestLocked),
                            _ = attachment.changed() => return Err(Error::AtRestLocked),
                            transition = gate.transition(None) => transition,
                        });
                        // The previous room owner can finish a rekey while the gate is awaited.
                        // Recheck after acquiring it; no channel guard crosses native admission.
                        tokio::select! {
                            biased;
                            _ = room_cancel.changed() => return Err(Error::AtRestLocked),
                            _ = attachment.changed() => return Err(Error::AtRestLocked),
                            channel = instance.lock() => {
                                if channel.epoch() != expected_epoch { return Err(Error::AtRestLocked); }
                            }
                        }
                    }
                    if *room_cancel.borrow() || *attachment.borrow() != epoch || !authority_superseded(&authority) {
                        return Err(Error::ComputerPolicySuperseded);
                    }
                    Ok(())
                }.await;
                match acquired {
                    Ok(()) => (transition, Some((authority, room_cancel))),
                    Err(error) => {
                        *output
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some((lifetime, transition, Err(error)));
                        wake.notify_one();
                        return;
                    }
                }
            } else {
                (None, None)
            };
            let held = lifetime.as_ref().map(Arc::clone);
            let saved = tokio::task::spawn_blocking(move || {
                let _secret = worker_secret;
                if strict
                    && (*attachment.borrow() != epoch
                        || (requires_lifetime && held.is_none())
                        || held
                            .as_ref()
                            .is_some_and(|held| held.publish(|| ()).is_none()))
                {
                    return Err(Error::ComputerPolicySuperseded);
                }
                work.run_admitted(&worker_store, &worker_signer, || {
                    if strict
                        && (*attachment.borrow() != epoch
                            || (requires_lifetime && held.is_none())
                            || held
                                .as_ref()
                                .is_some_and(|held| held.publish(|| ()).is_none()))
                    {
                        return Err(Error::ComputerPolicySuperseded);
                    }
                    if let Some((room_cancel, instance, room_epoch, now, idle, authority)) =
                        &withdrawal_fence
                    {
                        if *room_cancel.borrow() || *attachment.borrow() != epoch {
                            return Err(Error::AtRestLocked);
                        }
                        {
                            let channel = instance.blocking_lock();
                            if channel.epoch() != *room_epoch {
                                return Err(Error::AtRestLocked);
                            }
                            if *idle
                                && (channel.genesis().creator_pubkey().fingerprint() != node
                                    || !matches!(
                                        channel.ended(*now),
                                        Some(crate::node::channel::RoomEnd::Idle { .. })
                                    ))
                            {
                                return Err(Error::Profile("idle room changed before withdrawal"));
                            }
                        }
                        if !authority.current()
                            || held
                                .as_ref()
                                .is_none_or(|held| held.publish(|| ()).is_none())
                        {
                            return Err(Error::ComputerPolicySuperseded);
                        }
                    }
                    if let Some((authority, room_cancel)) = &fence {
                        if *room_cancel.borrow()
                            || *attachment.borrow() != epoch
                            || !authority_superseded(authority)
                        {
                            return Err(Error::ComputerPolicySuperseded);
                        }
                    }
                    Ok(())
                })
            })
            .await
            .unwrap_or_else(|_| Err(Error::Profile("native join journal worker stopped")));
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some((lifetime, transition, saved));
            wake.notify_one();
        });
        self.pending_metadata
            .get_or_insert_with(Pending::default)
            .journals
            .insert(
                room,
                JournalPending {
                    room,
                    epoch,
                    node,
                    instance,
                    store,
                    signer,
                    secret,
                    result,
                    task,
                    after,
                    following_withdrawal: None,
                },
            );
    }

    pub(super) fn begin_metadata_join_board(
        &mut self,
        room: Digest32,
        attachment: u64,
        board: Arc<VoxConnection>,
        withdrawal: Option<Vec<u8>>,
        ack: oneshot::Sender<crate::error::Result<()>>,
    ) {
        if attachment != self.delivery_epoch || !self.joining.contains(&room) {
            let _ = ack.send(Err(Error::Profile(
                "the join no longer owns this attachment",
            )));
            return;
        }
        let Some(node) = self.profile.as_ref().map(Profile::fingerprint) else {
            let _ = ack.send(Err(Error::AtRestLocked));
            return;
        };
        if withdrawal.is_some() && self.channels.contains_key(&room) {
            let _ = ack.send(Err(Error::Profile(
                "an existing room cannot become join rollback state",
            )));
            return;
        }
        let peer = board.peer_id();
        let route = board.quinn().remote_address();
        let retain = withdrawal.is_some();
        let work = match withdrawal {
            Some(wire) => JournalWork::Retain {
                room,
                board: peer,
                route,
                wire,
                node,
            },
            None => JournalWork::ForgetRefused {
                room,
                board: peer,
                route,
            },
        };
        self.begin_metadata_journal(
            room,
            work,
            JournalAfter::Board {
                board: peer,
                retain,
                ack,
            },
            None,
        );
    }

    pub(super) fn begin_metadata_abort_join(
        &mut self,
        room: Digest32,
        fault: Fault,
        reply: Option<oneshot::Sender<Outcome>>,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
    ) {
        let Some(node) = lifetime
            .as_ref()
            .map(|held| crate::identity::composite::RootSigner::fingerprint(held.signer.as_ref()))
            .or_else(|| self.profile.as_ref().map(Profile::fingerprint))
        else {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::Locked));
            }
            return;
        };
        self.begin_metadata_journal(
            room,
            JournalWork::Abort { room, node },
            JournalAfter::Abort {
                fault,
                reply,
                joining: true,
            },
            lifetime,
        );
    }

    pub(super) fn begin_metadata_forget_gone(&mut self, room: Digest32) {
        self.begin_metadata_journal(
            room,
            JournalWork::ForgetOpen { room },
            JournalAfter::ForgetOpen,
            None,
        );
    }

    async fn complete_metadata_journals(&mut self) {
        let ready: Vec<_> = self
            .pending_metadata
            .as_ref()
            .map(|pending| {
                pending
                    .journals
                    .iter()
                    .filter_map(|(room, pending)| {
                        let result = pending
                            .result
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take();
                        result.map(|result| (*room, result))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let completed = !ready.is_empty();
        for (room, (lifetime, transition, result)) in ready {
            let Some(mut pending) = self
                .pending_metadata
                .as_mut()
                .and_then(|pending| pending.journals.remove(&room))
            else {
                continue;
            };
            let following = pending.following_withdrawal.take();
            if let JournalAfter::PublicationRejected(rejected) = &mut pending.after {
                rejected.transition = transition;
            }
            let current = pending.epoch == self.delivery_epoch
                && match &pending.instance {
                    Some(instance) => self
                        .channels
                        .get(&room)
                        .is_some_and(|current| Arc::ptr_eq(current, instance)),
                    None => !self.channels.contains_key(&room),
                };
            match pending.after {
                JournalAfter::RoomWithdrawal(withdrawal) => {
                    self.complete_metadata_room_withdrawal(room, current, withdrawal, result)
                        .await;
                }
                JournalAfter::Board { board, retain, ack } => {
                    let result = if current && self.joining.contains(&room) {
                        result
                    } else {
                        Err(Error::AtRestLocked)
                    };
                    let result = result.map(|delta| {
                        self.install_metadata_journal(room, &delta);
                        if retain {
                            self.on_board.insert((room, board));
                            if let Some(routes) = self
                                .join_cleanup
                                .get(&room)
                                .and_then(|entry| entry.routes.get(&board))
                            {
                                self.board_routes.insert((room, board), routes.clone());
                            }
                        } else {
                            self.board_routes.remove(&(room, board));
                            self.on_board.remove(&(room, board));
                        }
                    });
                    let _ = ack.send(result);
                }
                JournalAfter::AcceptedJoined {
                    reply,
                    outcome,
                    completed,
                } => match result {
                    Ok(delta) => {
                        if current {
                            self.install_metadata_journal(room, &delta);
                        }
                        let _ = reply.send(outcome);
                    }
                    Err(error) => self.begin_completed_join_abort(
                        room,
                        completed,
                        Some(reply),
                        fault_of(&error),
                    ),
                },
                JournalAfter::Joined {
                    authority,
                    responder,
                    reply,
                } => match result {
                    Ok(mut delta) => {
                        let channel = match &pending.instance {
                            Some(instance) => Some(instance.lock().await),
                            None => None,
                        };
                        let attached = current
                            && delta.completed_join.as_ref().is_some_and(|completed| {
                                channel
                                    .as_ref()
                                    .is_some_and(|channel| channel.epoch() == completed.epoch)
                            });
                        let installed = attached
                            && lifetime.as_ref().is_some_and(|held| {
                                held.publish(|| {
                                    self.install_metadata_journal(room, &delta);
                                    let _ = self.event_tx.send(NodeEvent::Joined {
                                        channel_id: room,
                                        responder,
                                    });
                                    self.room_publication_authority.insert(
                                        room,
                                        (
                                            authority,
                                            RoomPublicationOwnership::Joined,
                                            Arc::clone(held),
                                        ),
                                    );
                                })
                                .is_some()
                            });
                        drop(channel);
                        if installed {
                            self.finish_metadata_join_reply(
                                room,
                                reply,
                                Outcome::Done,
                                lifetime,
                                delta.completed_join.take(),
                            )
                            .await;
                        } else if let Some(completed) = delta.completed_join.take() {
                            self.begin_metadata_journal(
                                room,
                                JournalWork::AbortCompleted {
                                    room,
                                    node: pending.node,
                                    completed,
                                },
                                JournalAfter::Abort {
                                    fault: Fault::ComputerPolicy,
                                    reply: Some(reply),
                                    joining: true,
                                },
                                lifetime,
                            );
                        } else {
                            let _ = reply.send(Outcome::Failed(Fault::Internal));
                        }
                    }
                    Err(error) => self.begin_metadata_abort_join(
                        room,
                        fault_of(&error),
                        Some(reply),
                        lifetime,
                    ),
                },
                JournalAfter::ForgetOpen => {}
                JournalAfter::PublicationRejected(mut rejected) => {
                    let delta = match result {
                        Ok(delta) => delta,
                        Err(error) => {
                            self.fail_room_publication(room, rejected.waiting, fault_of(&error));
                            drop(rejected.transition);
                            self.resume_metadata_withdrawal(room, following);
                            continue;
                        }
                    };
                    let attached = current
                        && match rejected.stage {
                            PublicationRejectStage::Withdraw => {
                                self.channels.get(&room).is_some_and(|instance| {
                                    Arc::ptr_eq(instance, &rejected.instance)
                                }) && rejected.instance.lock().await.epoch() == rejected.epoch
                            }
                            PublicationRejectStage::Purge => !self.channels.contains_key(&room),
                        };
                    if !attached {
                        self.fail_room_publication(room, rejected.waiting, Fault::ChannelNotOpen);
                        drop(rejected.transition);
                        self.resume_metadata_withdrawal(room, following);
                        continue;
                    }
                    if matches!(rejected.stage, PublicationRejectStage::Withdraw) {
                        self.install_metadata_journal(room, &delta);
                    }
                    if delta.withdrawal.is_some() {
                        self.publish_metadata_withdrawal(room);
                    }
                    if delta.purged {
                        self.publish().await;
                        self.fail_room_publication(room, rejected.waiting, Fault::ComputerPolicy);
                        drop(rejected.transition);
                    } else if !publication_superseded(&rejected.waiting) {
                        self.fail_room_publication(room, rejected.waiting, Fault::ComputerPolicy);
                        drop(rejected.transition);
                    } else {
                        // Match the former purge failure projection: narrow the live room before
                        // attempting its durable deletion, while retaining its ORIGINAL fence.
                        self.retract_live_channel(&room);
                        rejected.stage = PublicationRejectStage::Purge;
                        self.begin_metadata_journal(
                            room,
                            JournalWork::PurgeUnpublished {
                                room,
                                node: pending.node,
                            },
                            JournalAfter::PublicationRejected(rejected),
                            lifetime,
                        );
                    }
                }
                JournalAfter::Abort {
                    fault,
                    reply,
                    joining,
                } => {
                    if !current {
                        if let Some(reply) = reply {
                            let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                        }
                        self.resume_metadata_withdrawal(room, following);
                        continue;
                    }
                    let outcome = match result {
                        Ok(delta) => {
                            self.install_metadata_journal(room, &delta);
                            if let (Some(net), Some(pending)) =
                                (self.net.as_ref(), self.withdrawn.get(&room))
                            {
                                let _ = net.publish_local(&pending.wire);
                                for board in pending.routes.keys() {
                                    if let Some(conn) = net.manager().existing(board) {
                                        Self::put_withdraws(&conn, vec![pending.wire.clone()]);
                                    }
                                }
                            }
                            Outcome::Failed(fault)
                        }
                        Err(error) => Outcome::Failed(fault_of(&error)),
                    };
                    if let Some(reply) = reply {
                        if joining {
                            self.finish_metadata_join_reply(room, reply, outcome, lifetime, None)
                                .await;
                        } else {
                            self.answer_when_published(room, reply, outcome).await;
                        }
                    }
                }
            }
            self.resume_metadata_withdrawal(room, following);
        }
        if completed && !self.publish_waiters.is_empty() {
            self.publication_pending = true;
            self.publication_again = true;
        }
    }
}

pub(super) struct Continuation {
    instance: SharedChannel,
    attachment: u64,
    lifetime: Option<Arc<maintenance_save::Lifetime>>,
    authority: computer::ComputerAuthority,
    responder: Digest32,
    conn: Arc<VoxConnection>,
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
                .is_some_and(|instance| Arc::ptr_eq(instance, &self.instance))
    }
}
impl Node {
    pub(super) fn reject_owned_metadata(
        &mut self,
        room: Digest32,
        error: Error,
        next: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if next.attached(self, &room) {
            self.begin_metadata_abort_join(room, fault_of(&error), reply, next.lifetime);
        } else if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
        }
    }

    pub(super) async fn finish_owned_metadata(
        &mut self,
        room: Digest32,
        result: crate::error::Result<maintenance_save::Saved>,
        lifetime: Arc<maintenance_save::Lifetime>,
        next: Continuation,
        reply: Option<oneshot::Sender<Outcome>>,
    ) {
        if !next.attached(self, &room) {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            }
            return;
        }
        match result {
            Ok(maintenance_save::Saved::Metadata(saved)) if saved.members => {
                self.adopt_channel_anchors(&room).await;
                self.refresh_network_view().await;
                if let Some(reply) = reply {
                    self.begin_local_publication(
                        room,
                        Some(PublicationAfter::Joined {
                            authority: next.authority,
                            responder: next.responder,
                            conn: next.conn,
                            reply,
                        }),
                        Some(lifetime),
                    )
                    .await;
                }
            }
            Err(error) => {
                self.begin_metadata_abort_join(room, fault_of(&error), reply, Some(lifetime))
            }
            _ => self.begin_metadata_abort_join(room, Fault::Internal, reply, Some(lifetime)),
        }
    }
}

impl Node {
    async fn release_metadata_target(&mut self, room: Digest32, target: AnchorTarget) {
        let key = (room, target.conn.peer_id());
        self.publishing.remove(&key);
        if let Some(cause) = self.publish_again.remove(&key) {
            let conn = self
                .net
                .as_ref()
                .and_then(|net| net.manager().existing(&key.1));
            if let Some(conn) = conn {
                Box::pin(self.begin_anchor_publication(room, conn, cause, None)).await;
            }
        }
    }

    async fn begin_publication_records(
        &mut self,
        key: PublicKey,
        mut pending: PublicPending,
        public: Option<PublicBundle>,
        offered: (u64, Option<u64>),
        lifetime: Arc<maintenance_save::Lifetime>,
    ) {
        let room = key.0;
        let epoch = pending.room_epoch;
        let mut plans = Vec::new();
        if pending.local {
            self.arm_record_renewal(&room);
            let seq = self.next_record_seq(&room);
            let base = self.record_timestamp(&room);
            let stamp = spaced_stamp(&mut self.records_stamped, room, base, offered);
            plans.push((RecordStamp { seq, stamp }, None));
        }
        for target in &pending.targets {
            let seq = self.next_record_seq(&room);
            let base = self.record_timestamp(&room);
            let stamp = spaced_stamp(&mut self.records_stamped, room, base, offered);
            plans.push((
                RecordStamp { seq, stamp },
                Some((target.conn.peer_id(), target.conn.quinn().remote_address())),
            ));
        }
        let output = Arc::clone(&pending.result);
        let wake = Arc::clone(&self.post_save_wake);
        let attachment = self.pairwise_epoch.subscribe();
        let attachment_epoch = pending.epoch;
        let room_cancel = pending.room_cancel.clone();
        pending.task = tokio::spawn(async move {
            let held = Arc::clone(&lifetime);
            let saved = tokio::task::spawn_blocking(move || {
                if *attachment.borrow() != attachment_epoch || held.publish(|| ()).is_none() {
                    return Err(Error::ComputerPolicySuperseded);
                }
                let mut stamps = Vec::with_capacity(plans.len());
                let mut journal = None;
                for (stamp, board) in plans {
                    match (JournalWork::Refresh { room, epoch, stamp: stamp.stamp, board })
                        .run_admitted(&held.store, &held.signer, || {
                            if *room_cancel.borrow() || *attachment.borrow() != attachment_epoch
                                || held.publish(|| ()).is_none() {
                                return Err(Error::ComputerPolicySuperseded);
                            }
                            Ok(())
                        }) {
                        Ok(delta) => {
                            if delta.join.is_some() { journal = Some(delta); }
                            stamps.push(Some(stamp));
                        }
                        Err(error) => {
                            if board.is_some() {
                                eprintln!("vox node: join publication could not retain its rollback: {error}");
                            } else {
                                eprintln!("vox node: local join publication could not retain its rollback: {error}");
                            }
                            stamps.push(None);
                        }
                    }
                }
                Ok(PublicOutput::Records { public, stamps, journal })
            }).await.unwrap_or_else(|_| Err(Error::Profile("native publication journal stopped")));
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((Some(lifetime), saved));
            wake.notify_one();
        });
        self.pending_metadata
            .get_or_insert_with(Pending::default)
            .publications
            .insert(key, PublicationPending::Native(Box::new(pending)));
    }
}

impl Node {
    fn publish_metadata_withdrawal(&self, room: Digest32) -> usize {
        let mut anchors = 0;
        if let (Some(net), Some(pending)) = (self.net.as_ref(), self.withdrawn.get(&room)) {
            let _ = net.publish_local(&pending.wire);
            for board in pending.routes.keys() {
                if let Some(conn) = net.manager().existing(board) {
                    Self::put_withdraws(&conn, vec![pending.wire.clone()]);
                    anchors += 1;
                }
            }
        }
        anchors
    }
}

pub(super) async fn retire_detached(
    room: Digest32,
    result: crate::error::Result<maintenance_save::Saved>,
    next: Continuation,
    reply: Option<oneshot::Sender<Outcome>>,
) {
    let original_fault = result
        .err()
        .map(|error| fault_of(&error))
        .unwrap_or(Fault::Locked);
    let fault = if let Some(held) = next.lifetime {
        let node = crate::identity::composite::RootSigner::fingerprint(held.signer.as_ref());
        match tokio::task::spawn_blocking(move || {
            (JournalWork::Abort { room, node }).run(&held.store, &held.signer)
        })
        .await
        {
            Ok(Ok(_)) => original_fault,
            Ok(Err(error)) => fault_of(&error),
            Err(_) => Fault::Internal,
        }
    } else {
        Fault::Internal
    };
    if let Some(reply) = reply {
        let _ = reply.send(Outcome::Failed(fault));
    }
}

impl Node {
    pub(super) async fn begin_metadata_recovered_open(
        &mut self,
        room: Digest32,
        channel: ChannelState,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
        reply: Option<oneshot::Sender<Outcome>>,
        reopening: bool,
    ) {
        let name = self
            .store_recovery
            .get(&room)
            .map(|retry| retry.name.clone())
            .unwrap_or_else(|| crate::node::link::b32_encode(&room));
        let peers = self
            .ports
            .keys()
            .filter(|(id, _)| *id == room)
            .map(|(_, peer)| *peer)
            .collect::<Vec<_>>();
        for peer in peers {
            self.drop_port(&room, &peer);
        }
        self.begin_publish_open_channel(
            channel,
            transition,
            lifetime,
            OpenCallback {
                reply,
                reopening,
                recovery: Some(name),
            },
        )
        .await;
    }

    pub(super) async fn finish_metadata_open_reply(
        &mut self,
        room: Digest32,
        callback: OpenCallback,
        outcome: Outcome,
    ) {
        if let Some(name) = callback.recovery {
            if outcome.is_done() {
                self.store_recovery.remove(&room);
                self.store_recovered
                    .insert(room, format!("{name} recovered; it can save again"));
                eprintln!(
                    "vox: node {} room {}: {name} recovered; it can save again",
                    self.paths
                        .profile_dir
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("unknown"),
                    crate::node::link::b32_encode(&room)
                );
            } else {
                let cause = match &outcome {
                    Outcome::Failed(fault) => fault.to_string(),
                    other => format!("room publication returned {other:?}"),
                };
                if self.channels.contains_key(&room) {
                    if let Some(retry) = self.store_recovery.get_mut(&room) {
                        retry.cause = cause;
                        retry.busy = false;
                        retry.due = std::time::Instant::now()
                            + std::time::Duration::from_secs(1u64 << retry.attempts.min(6));
                    }
                } else {
                    self.store_recovery.remove(&room);
                    let _ = self.event_tx.send(NodeEvent::NodeNote {
                        note: format!("room {} could not finish recovery: {cause}; it remains closed. Reopen it to try again.",
                            crate::node::link::b32_encode(&room)),
                    });
                }
            }
        }
        if outcome.is_done() {
            self.queue_room_publication(
                room,
                callback.reply,
                outcome,
                callback.reopening,
                RoomPublicationKind::Open,
            );
        } else {
            self.reopening.remove(&room);
            if let Some(reply) = callback.reply {
                self.answer_when_published(room, reply, outcome).await;
            } else {
                self.publish().await;
            }
        }
    }
}

/// Startup recovery calls this on its existing native identity worker, then reloads both ledgers.
pub(super) fn abort_join_cleanup_native(
    store: &Store,
    signer: &VaultRootSigner,
    node: Digest32,
    room: Digest32,
) -> crate::error::Result<()> {
    JournalWork::Abort { room, node }
        .run(store, signer)
        .map(|_| ())
}

enum JoinPending {
    Adoption(JoinAdoptionPending),
    Reply(JoinReplyPending),
}
struct JoinAdoptionPending {
    peer: Digest32,
    session: Box<crate::pairwise::session::Session>,
    mine: bool,
    lifetime: Arc<maintenance_save::Lifetime>,
    after: JoinAdoption,
}
impl JoinAdoptionPending {
    async fn retire(self, room: Digest32) {
        let lifetime = self.lifetime;
        let node = crate::identity::composite::RootSigner::fingerprint(lifetime.signer.as_ref());
        let returned = tokio::task::spawn_blocking(move || {
            let saved = JournalWork::Abort { room, node }.run(&lifetime.store, &lifetime.signer);
            (lifetime, saved)
        })
        .await;
        let fault = match &returned {
            Ok((_, Ok(_))) => Fault::Locked,
            Ok((_, Err(error))) => fault_of(error),
            Err(_) => Fault::Internal,
        };
        let _ = self.after.reply.send(Outcome::Failed(fault));
    }
}

enum JoinReplyPhase {
    Held,
    Consents(oneshot::Receiver<crate::error::Result<()>>),
}
struct JoinReplyPending {
    reply: oneshot::Sender<Outcome>,
    outcome: Outcome,
    lifetime: Option<Arc<maintenance_save::Lifetime>>,
    completed: Option<Arc<CompletedJoinRollback>>,
    phase: JoinReplyPhase,
}
impl JoinReplyPending {
    async fn retire(self, room: Digest32, original: Fault) {
        if !self.outcome.is_done() {
            let _ = self.reply.send(self.outcome);
            return;
        }
        // Held streams and consent releases precede answer_when_published. Even an installed
        // join cannot claim Done here while its first required anchor round is unfinished.
        let Some(completed) = self.completed else {
            let _ = self.reply.send(Outcome::Failed(Fault::Internal));
            return;
        };
        let lifetime = Arc::clone(&completed.lifetime);
        let node = crate::identity::composite::RootSigner::fingerprint(lifetime.signer.as_ref());
        let returned = tokio::task::spawn_blocking(move || {
            let saved = JournalWork::AbortCompleted {
                room,
                node,
                completed,
            }
            .run(&lifetime.store, &lifetime.signer);
            (lifetime, saved)
        })
        .await;
        let fault = match &returned {
            Ok((_, Ok(_))) => original,
            Ok((_, Err(error))) => fault_of(error),
            Err(_) => Fault::Internal,
        };
        let _ = self.reply.send(Outcome::Failed(fault));
    }
}
impl Node {
    pub(super) fn retire_metadata_publications(&mut self) {
        for (room, mut waiting) in std::mem::take(&mut self.publish_waiters) {
            let Some(completed) = waiting.join_rollback.take() else {
                if let Some(reply) = waiting.reply {
                    let _ = reply.send(Outcome::Failed(Fault::Locked));
                }
                continue;
            };
            if let Some(reply) = waiting.reply {
                let lifetime = Some(Arc::clone(&completed.lifetime));
                self.pending_metadata
                    .get_or_insert_with(Pending::default)
                    .join_replies
                    .insert(
                        room,
                        JoinPending::Reply(JoinReplyPending {
                            reply,
                            outcome: waiting.outcome,
                            lifetime,
                            completed: Some(completed),
                            phase: JoinReplyPhase::Held,
                        }),
                    );
            } else {
                self.begin_completed_join_abort(room, completed, None, Fault::Locked);
            }
        }
    }

    fn begin_completed_join_abort(
        &mut self,
        room: Digest32,
        completed: Arc<CompletedJoinRollback>,
        reply: Option<oneshot::Sender<Outcome>>,
        fault: Fault,
    ) {
        let lifetime = Arc::clone(&completed.lifetime);
        let node = crate::identity::composite::RootSigner::fingerprint(lifetime.signer.as_ref());
        self.begin_metadata_journal(
            room,
            JournalWork::AbortCompleted {
                room,
                node,
                completed,
            },
            JournalAfter::Abort {
                fault,
                reply,
                joining: false,
            },
            Some(lifetime),
        );
    }

    pub(super) fn abort_metadata_join_publication(
        &mut self,
        room: Digest32,
        waiting: &mut RoomPublication,
        fault: Fault,
    ) {
        if let Some(completed) = waiting.join_rollback.take() {
            self.begin_completed_join_abort(room, completed, waiting.reply.take(), fault);
        }
    }

    pub(super) fn finish_metadata_room_publication(
        &mut self,
        room: Digest32,
        mut waiting: RoomPublication,
    ) {
        if let Some(completed) = waiting.join_rollback.take() {
            if let Some(reply) = waiting.reply {
                let lifetime = Arc::clone(&completed.lifetime);
                self.begin_metadata_journal(
                    room,
                    JournalWork::AcceptCompleted {
                        room,
                        completed: Arc::clone(&completed),
                    },
                    JournalAfter::AcceptedJoined {
                        reply,
                        outcome: waiting.outcome,
                        completed,
                    },
                    Some(lifetime),
                );
            }
        } else if let Some(reply) = waiting.reply {
            let _ = reply.send(waiting.outcome);
        }
    }

    fn queue_metadata_join_publication(&mut self, room: Digest32, mut pending: JoinReplyPending) {
        let Some(completed) = pending.completed.take() else {
            let _ = pending.reply.send(Outcome::Failed(Fault::Internal));
            return;
        };
        if !self
            .channels
            .get(&room)
            .is_some_and(|instance| Arc::ptr_eq(instance, &completed.instance))
            || self
                .publish_waiters
                .get(&room)
                .is_some_and(|waiting| waiting.reply.is_some())
        {
            self.begin_completed_join_abort(
                room,
                completed,
                Some(pending.reply),
                Fault::ChannelNotOpen,
            );
            return;
        }
        self.queue_room_publication(
            room,
            Some(pending.reply),
            pending.outcome,
            false,
            RoomPublicationKind::Open,
        );
        if let Some(waiting) = self.publish_waiters.get_mut(&room) {
            waiting.join_rollback = Some(completed);
        }
    }

    pub(super) fn defer_metadata_join_adoption(
        &mut self,
        room: Digest32,
        peer: Digest32,
        session: crate::pairwise::session::Session,
        mine: bool,
        lifetime: Arc<maintenance_save::Lifetime>,
        after: JoinAdoption,
    ) {
        self.pending_metadata
            .get_or_insert_with(Pending::default)
            .join_replies
            .insert(
                room,
                JoinPending::Adoption(JoinAdoptionPending {
                    peer,
                    session: Box::new(session),
                    mine,
                    lifetime,
                    after,
                }),
            );
        if !self.pending_posts.contains_key(&room) {
            self.post_save_wake.notify_one();
        }
    }

    async fn advance_metadata_join_replies(&mut self) {
        let rooms: Vec<_> = self
            .pending_metadata
            .as_ref()
            .map(|pending| pending.join_replies.keys().copied().collect())
            .unwrap_or_default();
        for room in rooms {
            let Some(pending) = self
                .pending_metadata
                .as_mut()
                .and_then(|pending| pending.join_replies.remove(&room))
            else {
                continue;
            };
            let mut pending = match pending {
                JoinPending::Reply(pending) => pending,
                JoinPending::Adoption(pending) => {
                    if self.pending_posts.contains_key(&room) {
                        self.pending_metadata
                            .get_or_insert_with(Pending::default)
                            .join_replies
                            .insert(room, JoinPending::Adoption(pending));
                    } else {
                        self.begin_owned_join_adoption(
                            room,
                            pending.peer,
                            *pending.session,
                            pending.mine,
                            pending.lifetime,
                            pending.after,
                        )
                        .await;
                    }
                    continue;
                }
            };
            match &mut pending.phase {
                JoinReplyPhase::Held => {
                    // Keep the original held-stream collection and each transport's original
                    // admission. One real native terminal precedes the next stream, as before.
                    while !self.pending_posts.contains_key(&room) {
                        let Some(index) = self
                            .held_pairwise
                            .iter()
                            .position(|(held_room, _)| *held_room == room)
                        else {
                            break;
                        };
                        let (_, stream) = self.held_pairwise.remove(index);
                        self.begin_inbound_package(
                            stream,
                            pending.lifetime.as_ref().map(Arc::clone),
                        )
                        .await;
                    }
                    if self.pending_posts.contains_key(&room) {
                        self.pending_metadata
                            .get_or_insert_with(Pending::default)
                            .join_replies
                            .insert(room, JoinPending::Reply(pending));
                        continue;
                    }
                    if pending.outcome.is_done() {
                        let Some(lifetime) = pending.lifetime.as_ref().map(Arc::clone) else {
                            let _ = pending.reply.send(Outcome::Failed(Fault::Internal));
                            continue;
                        };
                        let (terminal, completed) = oneshot::channel();
                        pending.phase = JoinReplyPhase::Consents(completed);
                        self.pending_metadata
                            .get_or_insert_with(Pending::default)
                            .join_replies
                            .insert(room, JoinPending::Reply(pending));
                        self.begin_owned_owed_consents_for(lifetime, None, terminal)
                            .await;
                    } else {
                        self.answer_when_published(room, pending.reply, pending.outcome)
                            .await;
                    }
                }
                JoinReplyPhase::Consents(completed) => {
                    match completed.try_recv() {
                        Err(oneshot::error::TryRecvError::Empty) => {
                            self.pending_metadata
                                .get_or_insert_with(Pending::default)
                                .join_replies
                                .insert(room, JoinPending::Reply(pending));
                        }
                        // Ignore individual release failures as before; only the actual routing
                        // terminal may accept the original join and release its rollback receipt.
                        Ok(_) | Err(oneshot::error::TryRecvError::Closed) => {
                            self.queue_metadata_join_publication(room, pending);
                        }
                    }
                }
            }
        }
    }
}

impl Node {
    pub(super) async fn start_renew_room_publication(
        &mut self,
        room: Digest32,
        mut waiting: RoomPublication,
    ) {
        // The old physical decision must be released BEFORE a replacement reader is requested.
        drop(waiting.authority.take());
        let Some(authority) = self.computer_authority() else {
            self.fail_room_publication(room, waiting, Fault::ComputerPolicy);
            return;
        };
        self.begin_local_publication(
            room,
            Some(PublicationAfter::Revalidate { waiting, authority }),
            None,
        )
        .await;
    }
}

impl Node {
    fn inherit_room_publication_lifetime(
        &self,
        room: &Digest32,
    ) -> Option<Arc<maintenance_save::Lifetime>> {
        self.publish_waiters
            .get(room)
            .and_then(|waiting| waiting.authority.as_ref())
            .or_else(|| self.room_publication_authority.get(room))
            .map(|(_, _, lifetime)| Arc::clone(lifetime))
    }

    pub(super) fn retain_metadata_publication_network(
        &mut self,
        room: Digest32,
        board: Digest32,
        instance: SharedChannel,
        result: Arc<std::sync::Mutex<Option<NetEvent>>>,
        task: tokio::task::JoinHandle<()>,
    ) {
        self.pending_metadata
            .get_or_insert_with(Pending::default)
            .publications
            .insert(
                (room, PublicationTarget::Anchor(board)),
                PublicationPending::Network(NetworkPending {
                    epoch: self.delivery_epoch,
                    instance,
                    result,
                    task,
                }),
            );
    }

    async fn complete_metadata_publication_network(&mut self) {
        let ready: Vec<_> = self
            .pending_metadata
            .as_ref()
            .map(|pending| {
                pending
                    .publications
                    .iter()
                    .filter_map(|(key, pending)| {
                        let PublicationPending::Network(pending) = pending else {
                            return None;
                        };
                        let event = pending
                            .result
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take();
                        event.map(|event| (*key, Arc::clone(&pending.result), event))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (key, cell, event) in ready {
            let Some(candidate) = self
                .pending_metadata
                .as_mut()
                .and_then(|pending| pending.publications.remove(&key))
            else {
                continue;
            };
            let pending = match candidate {
                PublicationPending::Network(pending) if Arc::ptr_eq(&cell, &pending.result) => {
                    pending
                }
                other => {
                    self.pending_metadata
                        .get_or_insert_with(Pending::default)
                        .publications
                        .insert(key, other);
                    continue;
                }
            };
            let current = pending.epoch == self.delivery_epoch
                && self
                    .channels
                    .get(&key.0)
                    .is_some_and(|instance| Arc::ptr_eq(instance, &pending.instance));
            if current {
                // The event itself owns the SAME physical lifetime through its original callback.
                self.handle_net(event).await;
            } else {
                drop(event);
                drop(pending);
                if let PublicationTarget::Anchor(board) = key.1 {
                    self.publishing.remove(&(key.0, board));
                    if let Some(cause) = self.publish_again.remove(&(key.0, board)) {
                        let conn = self
                            .net
                            .as_ref()
                            .and_then(|net| net.manager().existing(&board));
                        if let Some(conn) = conn {
                            self.begin_anchor_publication(key.0, conn, cause, None)
                                .await;
                        }
                    }
                }
            }
        }
    }
}

struct JoinedFields {
    authority: computer::ComputerAuthority,
    responder: Digest32,
    conn: Arc<VoxConnection>,
    members: Vec<Digest32>,
    session: crate::pairwise::session::Session,
}
pub(super) struct JoinAdoption {
    pub(super) authority: computer::ComputerAuthority,
    pub(super) responder: Digest32,
    pub(super) conn: Arc<VoxConnection>,
    pub(super) members: Vec<Digest32>,
    pub(super) reply: oneshot::Sender<Outcome>,
}
impl Node {
    pub(super) async fn finish_metadata_join_adoption(
        &mut self,
        room: Digest32,
        after: JoinAdoption,
        lifetime: Arc<maintenance_save::Lifetime>,
    ) {
        let Some(instance) = self.channels.get(&room).cloned() else {
            let _ = after.reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            return;
        };
        let next = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: Some(lifetime),
            authority: after.authority,
            responder: after.responder,
            conn: after.conn,
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Metadata(Work::Members(after.members)),
            maintenance_save::Continuation::Metadata(next),
            Some(after.reply),
        )
        .await;
    }

    pub(super) fn reject_metadata_join_adoption(
        &mut self,
        room: Digest32,
        error: Error,
        after: JoinAdoption,
        lifetime: Arc<maintenance_save::Lifetime>,
    ) {
        self.begin_metadata_abort_join(room, fault_of(&error), Some(after.reply), Some(lifetime));
    }
}

fn queue_unpublished_purge(
    store: &Store,
    signer: &VaultRootSigner,
    batch: &mut Batch<'_>,
    node: Digest32,
    room: Digest32,
) -> crate::error::Result<()> {
    MapChange::Forget(room).queue(store, signer, batch)?;
    crate::node::history_demand::purge_own_recovery_in(batch, node, room)?;
    batch.purge_channel(&room).map(|_| ())
}

fn queue_abort_join(
    store: &Store,
    signer: &VaultRootSigner,
    batch: &mut Batch<'_>,
    node: Digest32,
    room: Digest32,
) -> crate::error::Result<JournalDelta> {
    let delta = JournalDelta::default();
    let mut unfinished = load_journal(store, PENDING_JOIN_CLEANUP_META_KEY)?;
    let Some(cleanup) = unfinished.remove(&room) else {
        return Ok(delta);
    };
    queue_join_rollback(store, signer, batch, node, room, cleanup, unfinished)
}

fn queue_join_rollback(
    store: &Store,
    signer: &VaultRootSigner,
    batch: &mut Batch<'_>,
    node: Digest32,
    room: Digest32,
    cleanup: PendingWithdrawal,
    unfinished: BTreeMap<Digest32, PendingWithdrawal>,
) -> crate::error::Result<JournalDelta> {
    let mut delta = JournalDelta::default();
    let mut withdrawn = load_journal(store, PENDING_WITHDRAWALS_META_KEY)?;
    let pending = withdrawn.entry(room).or_insert_with(|| cleanup.clone());
    for (board, routes) in &cleanup.routes {
        let kept = pending.routes.entry(*board).or_default();
        for route in routes {
            if !kept.contains(route) && kept.len() < MAX_WITHDRAWAL_ROUTES {
                kept.push(*route);
            }
        }
    }
    let old = crate::nat::withdraw::BoardWithdraw::from_wire(&pending.wire)?;
    let prepared = crate::nat::withdraw::BoardWithdraw::from_wire(&cleanup.wire)?;
    if old.scope != crate::nat::withdraw::WithdrawScope::Room
        && old.timestamp_ms < prepared.timestamp_ms
    {
        pending.wire = cleanup.wire;
    }
    delta.withdrawal = Some(withdrawn.get(&room).cloned());
    delta.join = Some(None);
    delta.purged = true;
    if durable_withdrawals() {
        batch.put_meta(
            PENDING_WITHDRAWALS_META_KEY,
            &pending_withdrawals_bytes(&withdrawn)?,
        )?;
    }
    batch.put_meta(
        PENDING_JOIN_CLEANUP_META_KEY,
        &pending_withdrawals_bytes(&unfinished)?,
    )?;
    queue_unpublished_purge(store, signer, batch, node, room)?;
    Ok(delta)
}

#[derive(Clone, Copy)]
enum PublicationRejectStage {
    Withdraw,
    Purge,
}
struct PublicationRejection {
    waiting: RoomPublication,
    transition: Option<crate::node::channel::own_writer_gate::Transition>,
    instance: SharedChannel,
    epoch: u64,
    stage: PublicationRejectStage,
}
fn publication_superseded(waiting: &RoomPublication) -> bool {
    waiting
        .authority
        .as_ref()
        .is_some_and(|(authority, _, _)| authority_superseded(authority))
}
fn authority_superseded(authority: &computer::ComputerAuthority) -> bool {
    match authority {
        computer::ComputerAuthority::Managed {
            computer, applied, ..
        } => computer.storage_ready().is_ok() && computer.policy_revision() > *applied,
        computer::ComputerAuthority::Unmanaged => false,
    }
}
impl Node {
    pub(super) async fn begin_metadata_publication_reject(
        &mut self,
        room: Digest32,
        mut waiting: RoomPublication,
        transition: Option<crate::node::channel::own_writer_gate::Transition>,
    ) {
        if !publication_superseded(&waiting) {
            self.fail_room_publication(room, waiting, Fault::ComputerPolicy);
            return;
        }
        if self
            .pending_metadata
            .as_ref()
            .is_some_and(|pending| pending.journals.contains_key(&room))
        {
            self.publish_waiters.insert(room, waiting);
            self.publication_pending = true;
            return;
        }
        let Some((_, ownership, held)) = waiting.authority.as_ref() else {
            self.fail_room_publication(room, waiting, Fault::ComputerPolicy);
            return;
        };
        let lifetime = Arc::clone(held);
        let ownership = *ownership;
        if ownership == RoomPublicationOwnership::Existing {
            self.fail_room_publication(room, waiting, Fault::ComputerPolicy);
            return;
        }
        let instance = self.channels.get(&room).cloned().filter(|instance| {
            waiting
                .instance
                .upgrade()
                .is_some_and(|original| Arc::ptr_eq(instance, &original))
        });
        let Some(instance) = instance else {
            self.fail_room_publication(room, waiting, Fault::ChannelNotOpen);
            return;
        };
        let epoch = instance.lock().await.epoch();
        let node = crate::identity::composite::RootSigner::fingerprint(lifetime.signer.as_ref());
        let scope = if ownership == RoomPublicationOwnership::Created {
            crate::nat::withdraw::WithdrawScope::Room
        } else {
            crate::nat::withdraw::WithdrawScope::Member
        };
        let work = match waiting.join_rollback.take() {
            Some(completed) => JournalWork::AbortCompleted {
                room,
                node,
                completed,
            },
            None => JournalWork::PublicationReject {
                room,
                node,
                epoch,
                now: self.now_ms().get(),
                scope,
                routes: self.withdrawal_routes(&room),
            },
        };
        self.begin_metadata_journal(
            room,
            work,
            JournalAfter::PublicationRejected(PublicationRejection {
                waiting,
                transition,
                instance,
                epoch,
                stage: PublicationRejectStage::Withdraw,
            }),
            Some(lifetime),
        );
    }
}

struct RoomWithdrawal {
    authority: computer::ComputerAuthority,
    instance: SharedChannel,
    attachment: u64,
    room_epoch: u64,
    now: u64,
    routes: BTreeMap<Digest32, Vec<SocketAddr>>,
    store: Arc<Store>,
    signer: Arc<VaultRootSigner>,
    secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    lifetime: Option<Arc<maintenance_save::Lifetime>>,
    purpose: RoomWithdrawalPurpose,
}
enum RoomWithdrawalPurpose {
    Idle {
        gen: u64,
    },
    #[cfg(feature = "mutant-sender")]
    UnauthorizedEnd {
        reply: oneshot::Sender<Outcome>,
        _slot: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
}
impl RoomWithdrawalPurpose {
    fn idle_generation(&self) -> Option<u64> {
        match self {
            Self::Idle { gen } => Some(*gen),
            #[cfg(feature = "mutant-sender")]
            Self::UnauthorizedEnd { .. } => None,
        }
    }
    fn answer(self, _room: Digest32, result: Result<usize, Fault>) {
        match self {
            Self::Idle { .. } => {
                let _ = result;
            }
            #[cfg(feature = "mutant-sender")]
            Self::UnauthorizedEnd { reply, _slot } => {
                let fault = match result {
                    Ok(anchors) => {
                        eprintln!("{}: put a room withdraw for {} to {anchors} anchor(s) though this node may not end it",
                            crate::log::sync::mutant::MARKER, crate::node::network::short_id(_room));
                        Fault::NotCreator
                    }
                    Err(fault) => fault,
                };
                let _ = reply.send(Outcome::Failed(fault));
                drop(_slot);
            }
        }
    }
}

#[cfg(feature = "mutant-sender")]
pub(super) struct MutantEndWithdrawal {
    pub(super) authority: computer::ComputerAuthority,
    pub(super) instance: SharedChannel,
    pub(super) attachment: u64,
    pub(super) store: Arc<Store>,
    pub(super) secret: tokio::sync::OwnedRwLockReadGuard<()>,
    pub(super) slot: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    pub(super) reply: oneshot::Sender<Outcome>,
}

impl Node {
    pub(super) fn metadata_room_journal_pending(&self, room: &Digest32) -> bool {
        self.pending_metadata
            .as_ref()
            .is_some_and(|pending| pending.journals.contains_key(room))
    }

    pub(super) async fn begin_metadata_idle_withdrawal(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        gen: u64,
        authority: computer::ComputerAuthority,
    ) {
        let captured = (|| {
            let profile = self
                .profile
                .as_ref()
                .filter(|profile| profile.is_unlocked())?;
            let lifetime = self.inherit_room_publication_lifetime(&room);
            let store = lifetime
                .as_ref()
                .map(|held| Arc::clone(&held.store))
                .unwrap_or_else(|| profile.store_handle());
            let signer = lifetime
                .as_ref()
                .map(|held| Arc::clone(&held.signer))
                .or_else(|| profile.signer_arc().ok())?;
            let secret = match lifetime.as_ref() {
                Some(held) => Arc::clone(&held.secret),
                None => Arc::new(self.secret_work.clone().try_read_owned().ok()?),
            };
            Some((store, signer, secret, lifetime))
        })();
        let Some((store, signer, secret, lifetime)) = captured else {
            // The original best-effort attempt also advanced wind-down after an immediate error.
            self.winding.entry(room).or_insert(Winding {
                gen,
                since: std::time::Instant::now(),
            });
            return;
        };
        let room_epoch = instance.lock().await.epoch();
        let withdrawal = RoomWithdrawal {
            authority,
            instance,
            attachment: self.delivery_epoch,
            room_epoch,
            now: self.now_ms().get(),
            routes: self.withdrawal_routes(&room),
            store,
            signer,
            secret,
            lifetime,
            purpose: RoomWithdrawalPurpose::Idle { gen },
        };
        self.resume_metadata_withdrawal(room, Some(withdrawal));
    }

    #[cfg(feature = "mutant-sender")]
    pub(super) async fn begin_metadata_mutant_withdrawal(
        &mut self,
        room: Digest32,
        request: MutantEndWithdrawal,
    ) {
        let MutantEndWithdrawal {
            authority,
            instance,
            attachment,
            store,
            secret,
            slot,
            reply,
        } = request;
        let purpose = RoomWithdrawalPurpose::UnauthorizedEnd { reply, _slot: slot };
        let signer = self
            .profile
            .as_ref()
            .and_then(|profile| profile.signer_arc().ok());
        let Some(signer) = signer else {
            self.publish().await;
            purpose.answer(room, Err(Fault::Locked));
            return;
        };
        let room_epoch = instance.lock().await.epoch();
        let lifetime = self.inherit_room_publication_lifetime(&room);
        let secret = Arc::new(secret);
        let withdrawal = RoomWithdrawal {
            authority,
            instance,
            attachment,
            room_epoch,
            now: self.now_ms().get(),
            routes: self.withdrawal_routes(&room),
            store,
            signer,
            secret,
            lifetime,
            purpose,
        };
        self.resume_metadata_withdrawal(room, Some(withdrawal));
    }

    fn resume_metadata_withdrawal(&mut self, room: Digest32, withdrawal: Option<RoomWithdrawal>) {
        let Some(mut withdrawal) = withdrawal else {
            return;
        };
        if withdrawal.attachment != self.delivery_epoch
            || !self
                .channels
                .get(&room)
                .is_some_and(|instance| Arc::ptr_eq(instance, &withdrawal.instance))
        {
            withdrawal.purpose.answer(room, Err(Fault::ChannelNotOpen));
            return;
        }
        if let Some(pending) = self
            .pending_metadata
            .as_mut()
            .and_then(|pending| pending.journals.get_mut(&room))
        {
            // Only the one original append owner can arrive while a room journal is in flight.
            // Idle maintenance coalesces at its caller; fresh commands remain behind this book.
            pending.following_withdrawal = Some(withdrawal);
            return;
        }
        let node = crate::identity::composite::RootSigner::fingerprint(withdrawal.signer.as_ref());
        let work = JournalWork::PublicationReject {
            room,
            node,
            epoch: withdrawal.room_epoch,
            now: withdrawal.now,
            scope: crate::nat::withdraw::WithdrawScope::Room,
            routes: std::mem::take(&mut withdrawal.routes),
        };
        let lifetime = withdrawal.lifetime.take();
        self.begin_metadata_journal(
            room,
            work,
            JournalAfter::RoomWithdrawal(withdrawal),
            lifetime,
        );
    }

    async fn complete_metadata_room_withdrawal(
        &mut self,
        room: Digest32,
        current: bool,
        withdrawal: RoomWithdrawal,
        result: crate::error::Result<JournalDelta>,
    ) {
        let attached = current
            && self
                .channels
                .get(&room)
                .is_some_and(|instance| Arc::ptr_eq(instance, &withdrawal.instance))
            && withdrawal.instance.lock().await.epoch() == withdrawal.room_epoch;
        let result = if attached {
            result
                .map(|delta| {
                    self.install_metadata_journal(room, &delta);
                    self.publish_metadata_withdrawal(room)
                })
                .map_err(|error| fault_of(&error))
        } else {
            Err(Fault::ChannelNotOpen)
        };
        if attached {
            if let Some(gen) = withdrawal.purpose.idle_generation() {
                // A failed save was always best effort. The wait, not success, precedes wind-down.
                let still_idle = matches!(
                    withdrawal.instance.lock().await.ended(self.now_ms().get()),
                    Some(crate::node::channel::RoomEnd::Idle { .. })
                );
                if still_idle {
                    self.winding.entry(room).or_insert(Winding {
                        gen,
                        since: std::time::Instant::now(),
                    });
                }
            }
        }
        self.publish().await;
        withdrawal.purpose.answer(room, result);
    }
}
