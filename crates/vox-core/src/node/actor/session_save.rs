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

pub(super) enum IngressReason {
    Native(std::sync::Weak<()>),
    Publication {
        token: u64,
        task: tokio::task::AbortHandle,
    },
    Room,
    Governance,
    Projection,
    Opening,
    Authority,
    Permanent,
}
#[derive(Clone, Copy)]
pub(super) enum IngressProgress {
    Room,
    Governance,
    Projection,
    Opening,
    Authority,
}

pub(super) struct IngressWait {
    instance: Option<std::sync::Weak<tokio::sync::Mutex<ChannelState>>>,
    attachment: u64,
    reason: IngressReason,
}
impl Drop for IngressWait {
    fn drop(&mut self) {
        if let IngressReason::Publication { task, .. } = &self.reason {
            task.abort();
        }
    }
}

/// One original command owns the existing deferred-command credit until native completion.
pub(super) struct Bookkeeping {
    room: Digest32,
    result: Arc<std::sync::Mutex<Option<bool>>>,
    _task: tokio::task::JoinHandle<()>,
}

/// The caller retains the room and original Computer publication through this commit.
pub(super) fn save_drive_admission(
    channel: &mut ChannelState,
    store: &Store,
    signer: &dyn crate::identity::composite::RootSigner,
    session: &str,
    drive: &crate::node::session_ingress::DriveAdmission,
    bodies: &[String],
    now: u64,
) -> crate::node::session_ingress::AdmissionResult {
    use crate::node::channel::session_projection::{Query, Reply};
    let refuse = || Error::Profile("Drive authority or Session opening changed; nothing was sent");
    if channel.is_poisoned()
        || !channel.is_member(&drive.author)
        || channel.history_instance(store).map_err(|_| refuse())? != drive.instance
    {
        return Err(refuse().into());
    }
    let answer = channel
        .session_query(
            store,
            Query::Exact {
                node: channel.me(),
                id: session.to_owned(),
            },
            crate::node::ipc::rows_budget(),
            now,
        )
        .map_err(|_| refuse())?;
    match answer {
        Reply::Page { rows, revision, .. }
            if !revision.provisional()
                && rows
                    .iter()
                    .any(|row| row.open && row.opening == drive.opening) => {}
        _ => return Err(refuse().into()),
    }
    crate::node::session_ingress::admit_drive(
        store,
        signer,
        channel.channel_id(),
        session,
        drive,
        bodies,
    )
}

impl Node {
    pub(super) fn session_bookkeeping_blocks_room(&self, room: &Digest32) -> bool {
        self.pending_session_bookkeeping
            .as_ref()
            .is_some_and(|pending| pending.room == *room)
    }

    pub(super) fn complete_session_bookkeeping(&mut self) -> bool {
        let Some(pending) = &self.pending_session_bookkeeping else {
            return false;
        };
        let saved = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(ingress) = saved {
            self.pending_session_bookkeeping = None;
            if ingress {
                self.ingress_scan_wake();
            }
            true
        } else {
            false
        }
    }

    pub(super) fn begin_session_admission(
        &mut self,
        room: Digest32,
        session: String,
        bodies: Vec<String>,
        drive: Option<crate::node::session_ingress::DriveAdmission>,
        reply: oneshot::Sender<crate::node::session_ingress::OwnedAdmission>,
    ) {
        use crate::node::session_ingress::{AdmissionError, OwnedAdmission};
        let prepared = (|| {
            if self
                .session_rooms_retiring
                .keys()
                .any(|item| item.room == room)
            {
                return Err(Error::Profile(
                    "this room was removed; its Session activity was not accepted",
                ));
            }
            let profile = self
                .profile
                .as_ref()
                .filter(|p| p.is_unlocked())
                .ok_or(Error::Profile("the node is locked"))?;
            let drive_room = if let Some(drive) = &drive {
                let refuse =
                    Error::Profile("Drive authority or Session opening changed; nothing was sent");
                if (drive.author != profile.fingerprint()
                    && (!self.trust.is_trusted(&drive.author)
                        || !self.trust.has_drive(&drive.author)))
                    || self.store_save_pending()
                    || self.failed_post_reads.contains_key(&room)
                {
                    return Err(refuse);
                }
                Some(self.channels.get(&room).ok_or(refuse)?.clone())
            } else {
                None
            };
            let secret = self.secret_work.clone().try_read_owned().map_err(|_| {
                Error::Profile("the node is locking; Session activity was not accepted")
            })?;
            let authority = if drive.is_some() {
                Some(
                    self.computer_authority()
                        .ok_or(Error::Profile("Drive authority changed; nothing was sent"))?,
                )
            } else {
                None
            };
            Ok((
                profile.store_handle(),
                profile.signer_arc()?,
                secret,
                authority,
                drive_room,
            ))
        })();
        let (store, signer, secret, authority, drive_room) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = reply.send(OwnedAdmission::NotCommitted { error, bodies });
                return;
            }
        };
        let epoch = self.delivery_epoch;
        let clock = Arc::clone(&self.millis_clock);
        let attachment = self.pairwise_epoch.subscribe();
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let task = tokio::spawn(async move {
            let publication = match authority {
                Some(authority) => match authority.try_acquire_publication() {
                    Ok(Some(publication)) => Some(publication),
                    Ok(None) | Err(_) => {
                        let _ = reply.send(OwnedAdmission::NotCommitted {
                            error: Error::Profile("Drive authority changed; nothing was sent"),
                            bodies,
                        });
                        *output
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(false);
                        wake.notify_one();
                        return;
                    }
                },
                None => None,
            };
            let mut drive_room = match drive_room {
                Some(channel) => Some(channel.lock_owned().await),
                None => None,
            };
            let saved = tokio::task::spawn_blocking(move || {
                let _secret = secret;
                let _publication = publication;
                let saved = if *attachment.borrow() != epoch {
                    Err(
                        Error::Profile("the node changed; Session activity was not accepted")
                            .into(),
                    )
                } else if let Some(drive) = drive {
                    match drive_room.as_mut() {
                        Some(channel) => save_drive_admission(
                            channel,
                            &store,
                            signer.as_ref(),
                            &session,
                            &drive,
                            &bodies,
                            clock(),
                        ),
                        None => Err(Error::Profile("the room is not open").into()),
                    }
                } else {
                    crate::node::session_ingress::admit(
                        &store,
                        signer.as_ref(),
                        room,
                        &session,
                        &bodies,
                    )
                };
                let committed = saved.is_ok();
                let receipt = match saved {
                    Ok(saved) => OwnedAdmission::Committed(saved),
                    Err(AdmissionError::NotCommitted(error)) => {
                        OwnedAdmission::NotCommitted { error, bodies }
                    }
                    Err(AdmissionError::Unconfirmed(error)) => OwnedAdmission::Unconfirmed(error),
                };
                let _ = reply.send(receipt);
                committed
            })
            .await
            .unwrap_or(false);
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(saved);
            wake.notify_one();
        });
        self.pending_session_bookkeeping = Some(Bookkeeping {
            room,
            result,
            _task: task,
        });
    }

    pub(super) fn begin_attention(
        &mut self,
        room: Digest32,
        by: Digest32,
        expected_instance: Option<[u8; 16]>,
        operation: crate::node::attention::Operation,
        reply: oneshot::Sender<Result<crate::node::attention::Reply, String>>,
    ) {
        let page = matches!(&operation, crate::node::attention::Operation::Page(_));
        let prepared = (|| {
            let profile = self
                .profile
                .as_ref()
                .filter(|p| p.is_unlocked())
                .ok_or("this node is locked")?;
            let owner = profile.fingerprint();
            if by != owner && (!page || !self.trust.has_drive(&by) || !self.trust.is_trusted(&by)) {
                return Err("attention requires current drive permission");
            }
            let authority = self
                .computer_authority()
                .filter(|authority| authority.current())
                .ok_or("attention waits for current computer trust")?;
            let channel = self
                .channels
                .get(&room)
                .ok_or("the room is not open")?
                .clone();
            let secret = self
                .secret_work
                .clone()
                .try_read_owned()
                .map_err(|_| "the node is locking; attention was not saved")?;
            Ok((profile.store_handle(), owner, channel, authority, secret))
        })();
        let (store, owner, channel, authority, secret) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = reply.send(Err(error.into()));
                return;
            }
        };
        let clock = Arc::clone(&self.millis_clock);
        let epoch = self.delivery_epoch;
        let attachment = self.pairwise_epoch.subscribe();
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let task = tokio::spawn(async move {
            let publication = if page {
                None
            } else {
                authority.try_acquire_publication().ok().flatten()
            };
            let mut channel = channel.lock_owned().await;
            let saved = tokio::task::spawn_blocking(move || {
                let _secret = secret;
                if *attachment.borrow() != epoch {
                    return Err("the node changed; attention was not saved".into());
                }
                if by != owner && !channel.is_member(&by) {
                    return Err("attention requires current room membership".into());
                }
                if (page && !authority.current()) || (!page && publication.is_none()) {
                    return Err("attention waits for current computer trust".into());
                }
                if !page {
                    if let Some(expected) = expected_instance {
                        if channel
                            .history_instance(&store)
                            .map_err(|error| error.to_string())?
                            != expected
                        {
                            return Err("the selected room changed; refresh and retry".into());
                        }
                    }
                }
                let saved = channel.attention(&store, owner, expected_instance, operation, clock());
                if page && !authority.current() {
                    Err("attention waits for current computer trust".into())
                } else {
                    saved
                }
            })
            .await
            .unwrap_or_else(|_| {
                Err("attention operation could not be confirmed; refresh before retrying".into())
            });
            let _ = reply.send(saved);
            if !page {
                *output
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(false);
                wake.notify_one();
            }
        });
        if !page {
            self.pending_session_bookkeeping = Some(Bookkeeping {
                room,
                result,
                _task: task,
            });
        }
    }
}

impl Node {
    pub(super) fn ingress_publication_ready(&mut self, room: Digest32, token: u64) {
        let key = self.session_ingress_waits.iter().find_map(|(key, wait)| {
            (key.0 == room && wait.attachment == self.delivery_epoch
                && matches!(&wait.reason, IngressReason::Publication { token: held, .. } if *held == token)
                && wait.instance.as_ref().and_then(std::sync::Weak::upgrade)
                    .zip(self.channels.get(&room))
                    .is_some_and(|(old, current)| Arc::ptr_eq(&old, current))).then(|| key.clone())
        });
        if let Some(key) = key {
            self.session_ingress_waits.remove(&key);
            self.ingress_scan_wake();
        }
    }

    pub(super) fn ingress_scan_wake(&mut self) {
        self.session_ingress_scan = 0;
        self.session_ingress_wake.notify_one();
    }

    pub(super) fn ingress_room_progress(&mut self, room: Digest32, progress: IngressProgress) {
        self.ingress_progress(room, progress, None);
    }

    fn ingress_progress(
        &mut self,
        room: Digest32,
        progress: IngressProgress,
        session: Option<&str>,
    ) {
        let mut wake = false;
        let attachment = self.delivery_epoch;
        let channels = &self.channels;
        self.session_ingress_waits.retain(|key, wait| {
            let matched = key.0 == room
                && wait.attachment == attachment
                && matches!(
                    (&wait.reason, progress),
                    (IngressReason::Room, IngressProgress::Room)
                        | (IngressReason::Governance, IngressProgress::Governance)
                        | (IngressReason::Projection, IngressProgress::Projection)
                        | (IngressReason::Opening, IngressProgress::Opening)
                        | (IngressReason::Authority, IngressProgress::Authority)
                )
                && (!matches!(progress, IngressProgress::Opening)
                    || session == Some(key.1.as_str()))
                && wait.instance.as_ref().is_none_or(|old| {
                    old.upgrade()
                        .zip(channels.get(&room))
                        .is_some_and(|(old, current)| Arc::ptr_eq(&old, current))
                });
            wake |= matched;
            !matched
        });
        if wake {
            self.ingress_scan_wake();
        }
    }

    pub(super) fn ingress_owner_finished(&mut self, room: Digest32, owner: &std::sync::Weak<()>) {
        let next = self.pending_posts.get(&room).map(post_save::Pending::owner);
        let mut wake = false;
        let attachment = self.delivery_epoch;
        let channels = &self.channels;
        self.session_ingress_waits.retain(|key, wait| {
            if key.0 != room {
                return true;
            }
            let IngressReason::Native(held) = &wait.reason else {
                return true;
            };
            if !std::sync::Weak::ptr_eq(held, owner) {
                return true;
            }
            if let Some(next) = &next {
                if !std::sync::Weak::ptr_eq(owner, next) {
                    wait.reason = IngressReason::Native(next.clone());
                }
                return true;
            }
            wake |= wait.attachment == attachment
                && wait
                    .instance
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                    .zip(channels.get(&room))
                    .is_some_and(|(old, current)| Arc::ptr_eq(&old, current));
            false
        });
        if wake {
            self.ingress_scan_wake();
        }
    }
}

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
        removal_generation: u64,
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
    retry_owed: BTreeSet<Digest32>,
}

enum After {
    Append(String),
    Ingress(String),
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

    pub(super) fn append(instance: SharedChannel, attachment: u64, session: String) -> Self {
        Self::new(instance, attachment, After::Append(session))
    }

    pub(super) fn ingress(instance: SharedChannel, attachment: u64, session: String) -> Self {
        Self::new(instance, attachment, After::Ingress(session))
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
        let selected = self.reserve_owned_outbound(context, bundle, target)?;
        self.one_time_waits.remove(&(*room, target));
        Some(selected)
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
        let continuation = SessionContinuation::append(instance, self.delivery_epoch, session);
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
        let key = (pending.room, pending.session.clone());
        if self.session_ingress_waits.contains_key(&key) {
            return false;
        }
        let Some(instance) = self.channels.get(&pending.room).cloned() else {
            self.session_ingress_waits.insert(
                key,
                IngressWait {
                    instance: None,
                    attachment: self.delivery_epoch,
                    reason: IngressReason::Room,
                },
            );
            return false;
        };
        if let Some(owner) = self
            .pending_posts
            .get(&pending.room)
            .map(post_save::Pending::owner)
        {
            self.session_ingress_waits.insert(
                key,
                IngressWait {
                    instance: Some(Arc::downgrade(&instance)),
                    attachment: self.delivery_epoch,
                    reason: IngressReason::Native(owner),
                },
            );
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
                self.session_ingress_waits.insert(
                    key,
                    IngressWait {
                        instance: Some(Arc::downgrade(&instance)),
                        attachment: self.delivery_epoch,
                        reason: IngressReason::Permanent,
                    },
                );
                return false;
            }
        };
        let room = pending.room;
        let continuation =
            SessionContinuation::ingress(instance.clone(), self.delivery_epoch, key.1.clone());
        let admitted = self
            .begin_pending_maintenance(
                room,
                maintenance_save::Work::Session(write),
                maintenance_save::Continuation::Session(continuation),
                None,
            )
            .await;
        if admitted {
            if let Some(owner) = self.pending_posts.get(&room).map(post_save::Pending::owner) {
                self.session_ingress_waits.insert(
                    key,
                    IngressWait {
                        instance: Some(Arc::downgrade(&instance)),
                        attachment: self.delivery_epoch,
                        reason: IngressReason::Native(owner),
                    },
                );
            }
        }
        admitted
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
        if continuation.attached(self, &room) && matches!(&continuation.after, After::Ingress(_)) {
            let After::Ingress(session) = &continuation.after else {
                unreachable!()
            };
            let reason = match (&error, fault) {
                (Error::OwnHistoryBehind | Error::RoomNotSynced, _) => IngressReason::Room,
                (
                    Error::StreamRefused("the Session is not open yet; its activity waits for it"),
                    _,
                ) => IngressReason::Opening,
                (Error::StreamRefused("the room is refreshing saved Sessions; retry"), _) => {
                    IngressReason::Projection
                }
                (_, Fault::GovernanceRefreshing) => IngressReason::Governance,
                (_, Fault::RoomPreparing) => IngressReason::Projection,
                (_, Fault::RoomChangePending) => {
                    let token = self.next_token;
                    self.next_token += 1;
                    let weak_room = Arc::downgrade(&continuation.instance);
                    let weak_store = self
                        .profile
                        .as_ref()
                        .map(|profile| Arc::downgrade(&profile.store_handle()));
                    let tx = self.net_tx.clone();
                    let task = self.spawn_join_housekeeping(async move {
                        let Some(room_state) = weak_room.upgrade() else {
                            return;
                        };
                        let Some(store) = weak_store.and_then(|store| store.upgrade()) else {
                            return;
                        };
                        let channel = room_state.lock().await;
                        let wake = channel.history_publication_wake();
                        let busy = channel.history_publication_busy(&store);
                        drop(channel);
                        drop(room_state);
                        drop(store);
                        match busy {
                            Ok(true) => wake.await,
                            Ok(false) => {}
                            Err(_) => return,
                        }
                        let _ = tx
                            .send(NetEvent::IngressPublicationReady { room, token })
                            .await;
                    });
                    IngressReason::Publication { token, task }
                }
                (_, Fault::ComputerPolicy) | (Error::ComputerPolicySuperseded, _) => {
                    IngressReason::Authority
                }
                _ => IngressReason::Permanent,
            };
            self.session_ingress_waits.insert(
                (room, session.clone()),
                IngressWait {
                    instance: Some(Arc::downgrade(&continuation.instance)),
                    attachment: continuation.attachment,
                    reason,
                },
            );
            if !matches!(error, Error::RoomNotSynced) {
                self.session_ingress_error = Some(format!(
                    "Session activity is saved and waiting for its room: {error}"
                ));
            }
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
                removal_generation,
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
                        SessionWrite::Package {
                            package,
                            removal_generation,
                        },
                        continuation,
                        reply,
                    )
                    .await;
                } else {
                    drop(reservation);
                    chain.retry_owed.insert(member);
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
        let ingress = matches!(&after, After::Ingress(_));
        match (after, saved) {
            (After::Append(session), SessionSaved::Appended(hash))
            | (After::Ingress(session), SessionSaved::Appended(hash)) => {
                self.note_local_append(&room);
                self.say_session_news(&room).await;
                if !ingress {
                    self.ingress_progress(room, IngressProgress::Opening, Some(&session));
                }
                if ingress {
                    self.session_ingress_error = None;
                    self.session_ingress_waits.remove(&(room, session));
                    self.ingress_scan_wake();
                }
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Appended(hash));
                }
                // The append decision is now complete. The existing prerequisite chain may
                // choose a fresh drive decision; never recursively acquire under its old lease.
                drop(lifetime);
                Box::pin(self.begin_owned_private_drive(room, true, None, None, None)).await;
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
                        retry_owed: BTreeSet::new(),
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
                chain.retry_owed.insert(release.member);
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
        if !chain.retry_owed.is_empty() {
            self.park_session_release(
                room,
                (instance, attachment, lifetime),
                chain.ensure,
                chain.guard,
                chain.retry_owed,
                reply,
            );
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
