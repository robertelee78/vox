//! Actual Session side effects for the existing retained save owner; no second queue or wake.
use super::maintenance_save::Lifetime;
use super::*;
use crate::node::channel::pending_session::{
    CompletedSession, PendingSession, SessionSaved, SessionWrite,
};
use crate::node::channel::session_projection::{
    CompletedProjection, PendingProjection, ProjectionWork,
};
use crate::node::store::Store;
use std::collections::VecDeque;

/// Only the direct command has the original one-bounded-governance-turn fallback.
/// The original Session input moves through that prelude without copying its body.
pub(super) struct Work {
    write: SessionWrite,
    governance_fallback: bool,
}

pub(super) enum Prepared {
    Session(Box<PendingSession>),
    Prelude {
        projection: Box<PendingProjection>,
        write: SessionWrite,
    },
}

pub(super) enum Completed {
    Session(Box<CompletedSession>),
    Prelude {
        projection: Box<CompletedProjection>,
        write: SessionWrite,
    },
}

pub(super) enum Saved {
    Session(SessionSaved),
    Prelude(SessionWrite),
    OutboundPackage {
        package: Option<crate::node::keypackage::KeyPackage>,
        reservation: Option<crate::node::prekeys::OneTimeReservation>,
    },
}

/// Selected public inputs and a ring owner, never a ring guard. Only the native package
/// worker waits for the ring or seals against its identity key.
pub(super) struct OutboundPackage {
    bundle: Box<crate::identity::keyagreement::PrekeyBundlePublic>,
    context: crate::join::session::JoinContext,
    ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
    reservation: Option<crate::node::prekeys::OneTimeReservation>,
}

impl OutboundPackage {
    pub(super) fn into_work(
        self,
        target: Digest32,
        skdm: Box<crate::group::skdm::Skdm>,
    ) -> package_save::Work {
        package_save::Work::SealOutbound {
            ring: self.ring,
            bundle: self.bundle,
            context: self.context,
            target,
            skdm,
            reservation: self.reservation,
        }
    }

    pub(super) fn into_initiate_work(self) -> package_save::Work {
        package_save::Work::Initiate {
            ring: self.ring,
            bundle: self.bundle,
            context: self.context,
            reservation: self.reservation,
        }
    }

    pub(super) fn into_frame_work(self, skdm: Box<crate::group::skdm::Skdm>) -> package_save::Work {
        package_save::Work::FrameOutbound {
            ring: self.ring,
            bundle: self.bundle,
            context: self.context,
            skdm,
            reservation: self.reservation,
        }
    }
}

impl Work {
    pub(super) fn new(write: SessionWrite) -> Self {
        Self {
            write,
            governance_fallback: false,
        }
    }

    pub(super) fn direct_append(write: SessionWrite) -> Self {
        Self {
            write,
            governance_fallback: true,
        }
    }

    /// Original authority has already been admitted asynchronously. No native work occurs
    /// here: a refreshing direct append reserves the existing owned projection capsule.
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        holders: &BTreeSet<Digest32>,
        now: crate::time::Ms,
    ) -> crate::error::Result<Prepared> {
        // Direct/ingress append sampled this turn's clock when building its SessionEntry,
        // before asynchronous admission. The fallback must not resample eligibility,
        // rotation or first-seen time after its native fold has waited on durability.
        let now = match &self.write {
            SessionWrite::Append { content, .. } => crate::time::Ms(content.created_millis),
            _ => now,
        };
        if self.governance_fallback {
            match channel.require_governance_ready(store, now) {
                Err(error) if ChannelState::governance_refreshing(&error) => {
                    let projection = channel.prepare_pending_projection(
                        store,
                        owner,
                        ProjectionWork::Governance,
                        now,
                    )?;
                    return Ok(Prepared::Prelude {
                        projection: Box::new(projection),
                        write: self.write,
                    });
                }
                Err(error) => return Err(error),
                Ok(_) => {}
            }
        }
        channel
            .prepare_pending_session(store, owner, holders, self.write, now)
            .map(|pending| Prepared::Session(Box::new(pending)))
    }
}

impl Prepared {
    pub(super) fn run(
        self,
        store: &Store,
        signer: &dyn crate::identity::composite::RootSigner,
    ) -> Completed {
        match self {
            Self::Session(pending) => Completed::Session(Box::new(pending.run(store, signer))),
            Self::Prelude { projection, write } => Completed::Prelude {
                projection: Box::new(projection.run(store)),
                write,
            },
        }
    }
}

impl Completed {
    pub(super) fn package_confirmed(&self) -> bool {
        match self {
            Self::Session(completed) => completed.package_confirmed(),
            Self::Prelude { .. } => false,
        }
    }

    pub(super) fn package_unconfirmed(&self) -> bool {
        match self {
            Self::Session(completed) => completed.package_unconfirmed(),
            Self::Prelude { .. } => false,
        }
    }

    pub(super) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        match self {
            Self::Session(completed) => completed.can_install(channel, owner),
            Self::Prelude { projection, .. } => projection.can_install(channel, owner),
        }
    }

    pub(super) fn take_history_pin(
        &mut self,
    ) -> Option<crate::node::channel::history::PendingHistoryRead> {
        match self {
            Self::Session(completed) => completed.take_history_pin(),
            Self::Prelude { projection, .. } => projection.take_history_pin(),
        }
    }

    pub(super) fn finish(
        self,
        channel: &mut ChannelState,
        store: &Store,
    ) -> crate::error::Result<Saved> {
        match self {
            Self::Session(completed) => channel
                .finish_pending_session(store, *completed)
                .map(Saved::Session),
            Self::Prelude { projection, write } => channel
                .finish_pending_projection(store, *projection)
                .map(|_| Saved::Prelude(write)),
        }
    }

    pub(super) fn into_result(self) -> crate::error::Result<Saved> {
        match self {
            Self::Session(completed) => completed.result.map(Saved::Session),
            Self::Prelude { projection, write } => projection.result.map(|_| Saved::Prelude(write)),
        }
    }
}

type Reply = Option<oneshot::Sender<Outcome>>;

pub(super) struct SessionContinuation {
    pub(super) instance: SharedChannel,
    pub(super) attachment: u64,
    pub(super) lifetime: Option<Arc<Lifetime>>,
    after: After,
}

struct DriveRelease {
    member: Digest32,
    skdm: crate::group::skdm::Skdm,
    generation: u64,
}

struct DriveChain {
    remaining: VecDeque<DriveRelease>,
    ensure: bool,
    guard: Option<computer::ComputerPolicyGuard>,
    retry_owed: bool,
}

enum After {
    Append,
    Ingress,
    Drive {
        ensure: bool,
        guard: Option<computer::ComputerPolicyGuard>,
    },
    SealPackage {
        posted_as: (Digest32, Digest32, Digest32),
        member: Digest32,
        generation: u64,
        chain: DriveChain,
    },
    Package {
        posted_as: (Digest32, Digest32, Digest32),
        member: Digest32,
        generation: u64,
        chain: DriveChain,
        reservation: Option<crate::node::prekeys::OneTimeReservation>,
    },
    Delivered {
        chain: DriveChain,
    },
}

impl SessionContinuation {
    fn new(instance: SharedChannel, attachment: u64, after: After) -> Self {
        Self {
            instance,
            attachment,
            lifetime: None,
            after,
        }
    }

    pub(super) fn append(instance: SharedChannel, attachment: u64) -> Self {
        Self::new(instance, attachment, After::Append)
    }

    pub(super) fn ingress(instance: SharedChannel, attachment: u64) -> Self {
        Self::new(instance, attachment, After::Ingress)
    }

    pub(super) fn drive(
        instance: SharedChannel,
        attachment: u64,
        ensure: bool,
        guard: Option<computer::ComputerPolicyGuard>,
    ) -> Self {
        Self::new(instance, attachment, After::Drive { ensure, guard })
    }

    /// The generic owner calls this BEFORE attempting publication/secret admission.
    pub(super) fn lifetime(&self) -> Option<Arc<Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(super) fn instance(&self) -> &SharedChannel {
        &self.instance
    }

    /// A real committed package names this OTP even when its room/attachment is retired
    /// before actor cache bookkeeping. Keep that receipt on the exact original owner.
    pub(super) fn mark_confirmed_package(&mut self) {
        if let After::Package {
            reservation: Some(reservation),
            ..
        } = &self.after
        {
            reservation.mark_named();
        }
    }

    /// Actual native uncertainty follows the reservation's identity even after attachment
    /// retirement. No Node/current-room lookup can lose or misapply this ownership.
    pub(super) fn mark_unconfirmed_package(&mut self) {
        if let After::Package {
            reservation: Some(reservation),
            ..
        } = &self.after
        {
            reservation.mark_uncertain();
        }
    }

    pub(super) fn guard(&self) -> Option<&computer::ComputerPolicyGuard> {
        match &self.after {
            After::Drive { guard, .. } => guard.as_ref(),
            After::SealPackage { chain, .. }
            | After::Package { chain, .. }
            | After::Delivered { chain } => chain.guard.as_ref(),
            _ => None,
        }
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
    /// This is the old package selection unchanged, split BEFORE the prekey ring wait.
    /// Board/bundle eligibility stays on the actor; ring ownership and crypto are native work.
    pub(super) async fn select_owned_key_package(
        &mut self,
        room: &Digest32,
        target: Digest32,
    ) -> Option<OutboundPackage> {
        self.select_owned_prekey_delivery(room, target, true).await
    }

    pub(super) async fn select_owned_prekey_delivery(
        &mut self,
        room: &Digest32,
        target: Digest32,
        offline_to_signed: bool,
    ) -> Option<OutboundPackage> {
        self.net.as_ref()?;
        let shared = self.channels.get(room).cloned()?;
        let context = shared.lock().await.join_context().ok()?;
        let bundle = match self
            .delivery_bundle_waiting(room, target, offline_to_signed)
            .await
        {
            Ok(bundle) => bundle,
            Err(wait) => {
                self.say_key_waits(room, target, wait);
                return None;
            }
        };
        self.reserve_owned_outbound(context, bundle, target)
    }

    /// Legacy session initiation has always allowed immediate signed-prekey fallback;
    /// unlike a fresh key frame/package it does not start the one-time waiting clock.
    pub(super) async fn select_owned_legacy_session(
        &mut self,
        room: &Digest32,
        target: Digest32,
    ) -> Option<OutboundPackage> {
        self.net.as_ref()?;
        let shared = self.channels.get(room).cloned()?;
        let context = shared.lock().await.join_context().ok()?;
        let bundle = self.delivery_bundle_or_signed(room, target).await.ok()?;
        self.reserve_owned_outbound(context, bundle, target)
    }

    fn reserve_owned_outbound(
        &mut self,
        context: crate::join::session::JoinContext,
        bundle: crate::identity::keyagreement::PrekeyBundlePublic,
        target: Digest32,
    ) -> Option<OutboundPackage> {
        let ring = self.prekeys.as_ref().map(Arc::clone)?;
        let reservation = match &bundle.one_time_prekey {
            Some(otp) => Some(self.refused_otps.reserve(target, otp.prekey_id)?),
            None => None,
        };
        Some(OutboundPackage {
            bundle: Box::new(bundle),
            context,
            ring,
            reservation,
        })
    }

    /// Command dispatch routes here with the original reply/admission, not through an async
    /// helper that waits for the physical Session save to finish.
    pub(super) async fn begin_owned_session_append(
        &mut self,
        room: Digest32,
        session: String,
        body: String,
        reply: oneshot::Sender<Outcome>,
    ) {
        if self.profile.is_none() {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            return;
        };
        let write = match SessionWrite::append(&session, &body, (self.millis_clock)(), None) {
            Ok(write) => write,
            Err(error) => {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
                return;
            }
        };
        let continuation = SessionContinuation::append(instance, self.delivery_epoch);
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::DirectSession(write),
            maintenance_save::Continuation::Session(continuation),
            Some(reply),
        )
        .await;
    }

    /// One exact durable inbox head, just as before. Scheduling is not a committed receipt;
    /// only finish_owned_session clears the error/emits news. A rejected admission drops the
    /// capability, not the durable inbox item, which remains selectable by the existing turn.
    pub(super) async fn begin_owned_session_ingress(&mut self) -> bool {
        let Some(profile) = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
        else {
            return false;
        };
        let pending = match crate::node::session_ingress::pending(
            profile,
            &mut self.session_ingress_cursor,
        ) {
            Ok(pending) => {
                self.session_ingress_recovery_error = None;
                let Some(pending) = pending else { return false };
                pending
            }
            Err(error) => {
                self.session_ingress_recovery_error =
                    Some(format!("Session activity cannot be recovered: {error}"));
                return false;
            }
        };
        let Some(instance) = self.channels.get(&pending.room).cloned() else {
            return false;
        };
        if self.pending_posts.contains_key(&pending.room) {
            return false;
        }
        let write = match SessionWrite::append(
            &pending.session,
            &pending.body,
            (self.millis_clock)(),
            Some(pending.completion),
        ) {
            Ok(write) => write,
            Err(error) => {
                self.session_ingress_error = Some(format!(
                    "Session activity is saved and waiting for its room: {error}"
                ));
                return false;
            }
        };
        let continuation = SessionContinuation::ingress(instance, self.delivery_epoch);
        self.begin_pending_maintenance(
            pending.room,
            maintenance_save::Work::Session(write),
            maintenance_save::Continuation::Session(continuation),
            None,
        )
        .await
    }

    /// Called at the end of the existing drive prerequisite chain, after actual upgrade,
    /// projection, legacy announcement and private-support completions. `ensure` is its real
    /// committed HasOpen query answer, never a fabricated false from a failed query.
    /// A prerequisite chain or guarded policy owner transfers its existing lifetime here.
    /// Its terminal reply belongs to the completed physical chain, never its admission.
    pub(super) async fn begin_owned_session_drive_retained(
        &mut self,
        room: Digest32,
        ensure: bool,
        guard: Option<computer::ComputerPolicyGuard>,
        lifetime: Option<Arc<Lifetime>>,
        reply: Reply,
    ) -> bool {
        let Some(instance) = self.channels.get(&room).cloned() else {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            }
            return false;
        };
        if let Some(guard) = &guard {
            if let Err(error) = guard.active(self.computer.as_ref()) {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
                return false;
            }
        }
        let mut continuation =
            SessionContinuation::drive(instance, self.delivery_epoch, ensure, guard);
        continuation.lifetime = lifetime;
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Session(SessionWrite::Drive { ensure }),
            maintenance_save::Continuation::Session(continuation),
            reply,
        )
        .await
    }

    /// Pre-admission failures and native failures preserve the original result. The common
    /// owner invokes this if no lifetime could be admitted, instead of losing an ingress
    /// error or replying Done merely because a task was started.
    pub(super) fn reject_owned_session(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: SessionContinuation,
        reply: Reply,
    ) {
        let fault = fault_of(&error);
        if continuation.attached(self, &room)
            && matches!(continuation.after, After::Ingress)
            && !matches!(error, Error::RoomNotSynced)
        {
            self.session_ingress_error = Some(format!(
                "Session activity is saved and waiting for its room: {error}"
            ));
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault));
        }
    }

    /// Called only after exact matching component install, with ownership of the original
    /// lifetime (the generic book must not keep a second root through this callback).
    /// A stale attachment still receives the actual durable outcome but has no side effects.
    pub(super) async fn finish_owned_session(
        &mut self,
        room: Digest32,
        saved: crate::error::Result<Saved>,
        lifetime: Arc<Lifetime>,
        mut continuation: SessionContinuation,
        reply: Reply,
    ) {
        let saved = match saved {
            Ok(saved) => saved,
            Err(error) => {
                self.reject_owned_session(room, error, continuation, reply);
                return;
            }
        };
        if !continuation.attached(self, &room) {
            if let Some(reply) = reply {
                let outcome = match &saved {
                    Saved::Session(saved) => session_outcome(saved),
                    Saved::Prelude(_) | Saved::OutboundPackage { .. } => {
                        Outcome::Failed(Fault::ChannelNotOpen)
                    }
                };
                let _ = reply.send(outcome);
            }
            return;
        }
        let saved = match saved {
            Saved::Session(saved) => saved,
            Saved::Prelude(write) => {
                // The one bounded fold is installed. Recheck original eligibility and select
                // recipients under the SAME lifetime; ordinary Session work cannot fold again.
                continuation.lifetime = Some(lifetime);
                self.continue_owned_session(room, write, continuation, reply)
                    .await;
                return;
            }
            Saved::OutboundPackage {
                package,
                reservation,
            } => {
                let SessionContinuation {
                    instance,
                    attachment,
                    after,
                    ..
                } = continuation;
                let After::SealPackage {
                    posted_as,
                    member,
                    generation,
                    mut chain,
                } = after
                else {
                    if let Some(reply) = reply {
                        let _ = reply.send(Outcome::Failed(Fault::Internal));
                    }
                    return;
                };
                if let Some(package) = package {
                    let continuation = SessionContinuation {
                        instance,
                        attachment,
                        lifetime: Some(lifetime),
                        after: After::Package {
                            posted_as,
                            member,
                            generation,
                            chain,
                            reservation,
                        },
                    };
                    self.continue_owned_session(
                        room,
                        SessionWrite::Package { package },
                        continuation,
                        reply,
                    )
                    .await;
                } else {
                    drop(reservation);
                    chain.retry_owed = true;
                    self.next_owned_drive_release(
                        room, instance, attachment, lifetime, chain, reply,
                    )
                    .await;
                }
                return;
            }
        };
        // This continuation's root is replaced by the callback's same original lifetime.
        continuation.lifetime = None;
        let SessionContinuation {
            instance,
            attachment,
            after,
            ..
        } = continuation;
        let ingress = matches!(&after, After::Ingress);
        match (after, saved) {
            (After::Append, SessionSaved::Appended(hash))
            | (After::Ingress, SessionSaved::Appended(hash)) => {
                self.note_local_append(&room);
                self.say_session_news(&room).await;
                if ingress {
                    self.session_ingress_error = None;
                }
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Appended(hash));
                }
                // The append decision is now complete. The existing prerequisite chain may
                // choose a fresh drive decision; never recursively acquire under its old lease.
                drop(lifetime);
                let holders = self.drive_holders();
                Box::pin(self.tend_drive_keys_in(&room, &holders)).await;
            }
            (
                After::Drive { ensure, guard },
                SessionSaved::Drive {
                    refresh,
                    releases,
                    key_changed,
                },
            ) => {
                if key_changed.is_some() {
                    self.note_local_append(&room);
                }
                self.say_session_news(&room).await;
                if refresh == SessionRefresh::Progressed {
                    let continuation = SessionContinuation {
                        instance,
                        attachment,
                        lifetime: Some(lifetime),
                        after: After::Drive { ensure, guard },
                    };
                    self.continue_owned_session(
                        room,
                        SessionWrite::Drive { ensure },
                        continuation,
                        reply,
                    )
                    .await;
                } else if refresh == SessionRefresh::Complete && !releases.is_empty() {
                    let chain = DriveChain {
                        remaining: releases
                            .into_iter()
                            .map(|(member, skdm, generation)| DriveRelease {
                                member,
                                skdm,
                                generation,
                            })
                            .collect(),
                        ensure,
                        guard,
                        retry_owed: false,
                    };
                    self.next_owned_drive_release(
                        room, instance, attachment, lifetime, chain, reply,
                    )
                    .await;
                } else if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Done);
                }
            }
            (
                After::Package {
                    posted_as,
                    member,
                    generation,
                    chain,
                    reservation,
                },
                SessionSaved::Package { package, .. },
            ) => {
                // Only an actual successful package append consumes this OTP/cache identity.
                self.note_key_package_posted(posted_as, &package);
                drop(reservation);
                self.note_local_append(&room);
                let continuation = SessionContinuation {
                    instance,
                    attachment,
                    lifetime: Some(lifetime),
                    after: After::Delivered { chain },
                };
                self.continue_owned_session(
                    room,
                    SessionWrite::Delivered { member, generation },
                    continuation,
                    reply,
                )
                .await;
            }
            (After::Delivered { chain }, SessionSaved::Delivered) => {
                self.next_owned_drive_release(room, instance, attachment, lifetime, chain, reply)
                    .await;
            }
            _ => {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::Internal));
                }
            }
        }
    }

    async fn continue_owned_session(
        &mut self,
        room: Digest32,
        write: SessionWrite,
        continuation: SessionContinuation,
        reply: Reply,
    ) {
        self.continue_owned_session_work(
            room,
            maintenance_save::Work::Session(write),
            continuation,
            reply,
        )
        .await;
    }

    async fn continue_owned_session_work(
        &mut self,
        room: Digest32,
        work: maintenance_save::Work,
        continuation: SessionContinuation,
        reply: Reply,
    ) {
        if let Some(guard) = continuation.guard() {
            if let Err(error) = guard.active(self.computer.as_ref()) {
                self.reject_owned_session(room, error, continuation, reply);
                return;
            }
        }
        // Boxing breaks the callback/admission future type cycle; native work remains owned
        // by the existing result cell and never runs in this future.
        Box::pin(self.begin_pending_maintenance(
            room,
            work,
            maintenance_save::Continuation::Session(continuation),
            reply,
        ))
        .await;
    }

    async fn next_owned_drive_release(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        attachment: u64,
        lifetime: Arc<Lifetime>,
        mut chain: DriveChain,
        reply: Reply,
    ) {
        while let Some(release) = chain.remaining.pop_front() {
            if let Some(guard) = &chain.guard {
                if let Err(error) = guard.active(self.computer.as_ref()) {
                    let continuation = SessionContinuation {
                        instance,
                        attachment,
                        lifetime: Some(lifetime),
                        after: After::Delivered { chain },
                    };
                    self.reject_owned_session(room, error, continuation, reply);
                    return;
                }
            }
            if attachment != self.delivery_epoch
                || !self
                    .channels
                    .get(&room)
                    .is_some_and(|current| Arc::ptr_eq(current, &instance))
            {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                }
                return;
            }
            let posted_as = (
                room,
                release.member,
                crate::governance::membership::skdm_ref(&release.skdm),
            );
            if self.packages_posted.contains(&posted_as) {
                let continuation = SessionContinuation {
                    instance,
                    attachment,
                    lifetime: Some(lifetime),
                    after: After::Delivered { chain },
                };
                self.continue_owned_session(
                    room,
                    SessionWrite::Delivered {
                        member: release.member,
                        generation: release.generation,
                    },
                    continuation,
                    reply,
                )
                .await;
                return;
            }
            // Native package work remains with the exact policy/lifecycle owner. Its
            // continuation checks authority again before any irreversible publication.
            let selected = self.select_owned_key_package(&room, release.member).await;
            let Some(selected) = selected else {
                chain.retry_owed = true;
                continue;
            };
            let continuation = SessionContinuation {
                instance,
                attachment,
                lifetime: Some(lifetime),
                after: After::SealPackage {
                    posted_as,
                    member: release.member,
                    generation: release.generation,
                    chain,
                },
            };
            self.continue_owned_session_work(
                room,
                maintenance_save::Work::Packages(
                    selected.into_work(release.member, Box::new(release.skdm)),
                ),
                continuation,
                reply,
            )
            .await;
            return;
        }
        if chain.retry_owed {
            // Unavailable prekeys leave the original marks owed. Only an existing real
            // prekey/connection/ticker edge retries them; do not spin the same failed list.
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Done);
            }
            return;
        }
        // Every sent package's delivery mark is now durable. Revisit the real Drive state
        // under the same lease; only that worker can author KEY_CHANGED when nothing is owed.
        let ensure = chain.ensure;
        let continuation = SessionContinuation {
            instance,
            attachment,
            lifetime: Some(lifetime),
            after: After::Drive {
                ensure,
                guard: chain.guard,
            },
        };
        self.continue_owned_session(room, SessionWrite::Drive { ensure }, continuation, reply)
            .await;
    }
}

fn session_outcome(saved: &SessionSaved) -> Outcome {
    match saved {
        SessionSaved::Appended(hash) => Outcome::Appended(*hash),
        _ => Outcome::Done,
    }
}
