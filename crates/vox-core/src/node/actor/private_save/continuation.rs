use super::*;
use crate::node::channel::session_projection::{
    ProjectionProgress, ProjectionWork, Query, Reply as SessionReply,
};
use crate::node::history_budget::{BufferCharge, Job};
use crate::node::ports::Token;
use crate::transport::quic::VoxConnection;

type ActorReply = Option<oneshot::Sender<Outcome>>;

pub(in crate::node::actor) struct ArchiveReceipt {
    pub(in crate::node::actor) plan: PrivatePlan,
    pub(in crate::node::actor) lifetime: Arc<maintenance_save::Lifetime>,
    pub(in crate::node::actor) charge: BufferCharge,
}

#[derive(Clone, Copy)]
enum DriveStage {
    Upgrade,
    Sessions,
    Legacy,
    Support,
    Query,
}
#[derive(Clone, Copy)]
enum DriveWait {
    Upgrade(pending_upgrade::UpgradeWait),
    Support,
    SupportPublication,
    Publication,
    Projection,
    Native,
}

type PublicationWait = (
    DriveWait,
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>,
);

struct ReleaseWait {
    instance: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
    attachment: u64,
    authority: computer::ComputerAuthority,
    guard: Option<computer::ComputerPolicyGuard>,
    reply: ActorReply,
    ensure: bool,
    missed: BTreeSet<Digest32>,
    ready: BTreeSet<Digest32>,
    deadlines: BTreeMap<Digest32, u64>,
    token: u64,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl Drop for ReleaseWait {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

struct RoomWake {
    token: u64,
    task: tokio::task::AbortHandle,
}

impl Drop for RoomWake {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct UpgradeObligation {
    stage: DriveStage,
    guard: Option<computer::ComputerPolicyGuard>,
    authority: computer::ComputerAuthority,
    prerequisite: DriveWait,
    reply: ActorReply,
    room_wait: Option<RoomWake>,
    ready: bool,
}

pub(in crate::node::actor) struct ParkedPrivateDrive {
    instance: std::sync::Weak<tokio::sync::Mutex<ChannelState>>,
    attachment: u64,
    stage: DriveStage,
    guard: Option<computer::ComputerPolicyGuard>,
    authority: computer::ComputerAuthority,
    releases: [Vec<ReleaseWait>; 2],
    upgrades: Vec<UpgradeObligation>,
    drive_active: bool,
    busy_owner: Option<std::sync::Weak<()>>,
    room_wait: Option<RoomWake>,
    prerequisite: DriveWait,
    reply: ActorReply,
}

impl ParkedPrivateDrive {
    fn activate_upgrade(&mut self, at: usize) {
        let next = self.upgrades.remove(at);
        if self.drive_active {
            self.upgrades.push(UpgradeObligation {
                stage: self.stage,
                guard: self.guard.take(),
                authority: self.authority.clone(),
                prerequisite: self.prerequisite,
                reply: self.reply.take(),
                room_wait: self.room_wait.take(),
                ready: false,
            });
        }
        self.stage = next.stage;
        self.guard = next.guard;
        self.authority = next.authority;
        self.prerequisite = next.prerequisite;
        self.reply = next.reply;
        self.room_wait = next.room_wait;
        self.drive_active = true;
    }

    fn retire(mut self, fault: Fault) {
        for upgrade in &mut self.upgrades {
            if let Some(reply) = upgrade.reply.take() {
                let _ = reply.send(Outcome::Failed(fault));
            }
        }
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(Outcome::Failed(fault));
        }
        for release in self.releases.iter_mut().flatten() {
            if let Some(reply) = release.reply.take() {
                let _ = reply.send(Outcome::Failed(fault));
            }
        }
    }
}
#[derive(Clone, Copy)]
enum SupportStage {
    Refresh,
    Publish,
}
enum After {
    Drive {
        stage: DriveStage,
        guard: Option<computer::ComputerPolicyGuard>,
    },
    SupportDiscovery(SupportStage),
    Serving {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        connection: Arc<VoxConnection>,
        job: Job,
        charge: BufferCharge,
        guard: history_demand::CurrentPrivateGuard,
    },
    Live {
        answer: oneshot::Sender<Result<pending_upgrade::LivePageResult>>,
        guard: history_demand::CurrentPrivateGuard,
        charge: BufferCharge,
    },
    Archive {
        answer: oneshot::Sender<std::result::Result<ArchiveReceipt, String>>,
        guard: history_demand::PrivateGuard,
        job: Job,
        charge: BufferCharge,
    },
    Admission {
        answer: oneshot::Sender<bool>,
        guard: history_demand::CurrentPrivateGuard,
    },
}

pub(in crate::node::actor) struct Continuation {
    pub(in crate::node::actor) instance: SharedChannel,
    pub(in crate::node::actor) attachment: u64,
    pub(in crate::node::actor) lifetime: Option<Arc<maintenance_save::Lifetime>>,
    after: After,
}
impl Continuation {
    pub(in crate::node::actor) fn instance(&self) -> &SharedChannel {
        &self.instance
    }
    pub(in crate::node::actor) fn lifetime(&self) -> Option<Arc<maintenance_save::Lifetime>> {
        self.lifetime.as_ref().map(Arc::clone)
    }
    pub(in crate::node::actor) fn is_preparation(&self) -> bool {
        false
    }
    pub(in crate::node::actor) fn secret(
        &self,
    ) -> Option<Arc<tokio::sync::OwnedRwLockReadGuard<()>>> {
        match &self.after {
            After::Serving { guard, .. }
            | After::Live { guard, .. }
            | After::Admission { guard, .. } => Some(guard.secret()),
            After::Archive { guard, .. } => Some(guard.secret()),
            After::Drive { .. } | After::SupportDiscovery(_) => None,
        }
    }
    fn attached(&self, node: &Node, room: &Digest32) -> bool {
        self.attachment == node.delivery_epoch
            && node
                .channels
                .get(room)
                .is_some_and(|current| Arc::ptr_eq(current, &self.instance))
    }
    fn flow_guard(&self) -> Option<FlowGuard> {
        match &self.after {
            After::Live { guard, .. } => Some(FlowGuard::Live {
                guard: guard.clone(),
                initial: false,
            }),
            After::Archive { guard, .. } => Some(FlowGuard::Archive {
                guard: guard.clone(),
                initial: false,
            }),
            _ => None,
        }
    }
}

impl Node {
    pub(in crate::node::actor) async fn resume_private_drive_room_ready(
        &mut self,
        room: Digest32,
        token: u64,
    ) {
        let busy = self.pending_posts.get(&room).map(post_save::Pending::owner);
        let Some(parked) = self.parked_private_drives.get_mut(&room) else {
            return;
        };
        if busy.is_some() {
            parked.busy_owner = busy;
        }
        if parked
            .room_wait
            .as_ref()
            .is_some_and(|wait| wait.token == token)
        {
            parked.room_wait = None;
        } else if let Some(at) = parked.upgrades.iter().position(|item| {
            item.room_wait
                .as_ref()
                .is_some_and(|wait| wait.token == token)
        }) {
            parked.upgrades[at].room_wait = None;
            parked.upgrades[at].ready = true;
            if parked.busy_owner.is_some() {
                return;
            }
            parked.activate_upgrade(at);
        } else {
            return;
        }
        self.resume_parked_private_drive(room).await;
    }

    pub(in crate::node::actor) fn release_private_busy_owner(
        &mut self,
        room: Digest32,
        owner: &std::sync::Weak<()>,
        next: Option<std::sync::Weak<()>>,
    ) -> bool {
        let Some(parked) = self.parked_private_drives.get_mut(&room) else {
            return false;
        };
        if parked
            .busy_owner
            .as_ref()
            .is_some_and(|held| std::sync::Weak::ptr_eq(held, owner))
        {
            parked.busy_owner = next;
            if parked.busy_owner.is_none() {
                if let Some(at) = parked.upgrades.iter().position(|item| item.ready) {
                    parked.activate_upgrade(at);
                } else if !parked.drive_active && !parked.upgrades.is_empty() {
                    parked.activate_upgrade(0);
                }
            }
            parked.busy_owner.is_none()
        } else {
            false
        }
    }

    pub(in crate::node::actor) fn session_release_recipients(
        &self,
        room: Digest32,
    ) -> Vec<Digest32> {
        self.parked_private_drives
            .get(&room)
            .map(|parked| {
                parked
                    .releases
                    .iter()
                    .flatten()
                    .flat_map(|release| release.missed.iter().copied())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default()
    }
    pub(in crate::node::actor) fn session_release_tokens_for_peer(
        &self,
        peer: Digest32,
    ) -> Vec<(Digest32, u64)> {
        self.parked_private_drives
            .iter()
            .flat_map(|(room, parked)| {
                parked
                    .releases
                    .iter()
                    .flatten()
                    .filter(move |release| release.missed.contains(&peer))
                    .map(move |release| (*room, release.token))
            })
            .collect()
    }

    pub(in crate::node::actor) fn ready_session_release_recipients(
        &self,
        room: Digest32,
    ) -> Vec<Digest32> {
        self.parked_private_drives
            .get(&room)
            .map(|parked| {
                parked
                    .releases
                    .iter()
                    .flatten()
                    .flat_map(|release| release.ready.iter().copied())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(in crate::node::actor) fn park_session_release(
        &mut self,
        room: Digest32,
        owner: (SharedChannel, u64, Arc<maintenance_save::Lifetime>),
        ensure: bool,
        guard: Option<computer::ComputerPolicyGuard>,
        missed: BTreeSet<Digest32>,
        reply: ActorReply,
    ) {
        let (instance, attachment, lifetime) = owner;
        if let Some(parked) = self.parked_private_drives.get(&room) {
            if parked.attachment != attachment
                || !parked
                    .instance
                    .upgrade()
                    .is_some_and(|held| Arc::ptr_eq(&held, &instance))
            {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                }
                return;
            }
        }
        let token = self.next_token;
        self.next_token += 1;
        let mut tasks = Vec::new();
        let mut deadlines = BTreeMap::new();
        for peer in &missed {
            let notify = self.refused_otps.release_notifier(*peer);
            let mut wake = Box::pin(Arc::clone(&notify).notified_owned());
            wake.as_mut().enable();
            let tx = self.net_tx.clone();
            let member = *peer;
            tasks.push(self.spawn_join_housekeeping(async move {
                loop {
                    wake.await;
                    wake = Box::pin(Arc::clone(&notify).notified_owned());
                    wake.as_mut().enable();
                    if tx
                        .send(NetEvent::PrivateReleaseDue {
                            room,
                            peer: member,
                            token,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }));
            if let Some(since) = self.one_time_waits.get(&(room, *peer)).copied() {
                deadlines.insert(*peer, since);
                let delay = since
                    .saturating_add(ONE_TIME_WAIT_MS)
                    .saturating_sub(self.now_ms().get());
                let tx = self.net_tx.clone();
                let peer = *peer;
                tasks.push(self.spawn_join_housekeeping(async move {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    let _ = tx
                        .send(NetEvent::PrivateReleaseDue { room, peer, token })
                        .await;
                }));
            }
        }
        let initial: Vec<_> = missed.iter().copied().collect();
        let tx = self.net_tx.clone();
        tasks.push(self.spawn_join_housekeeping(async move {
            for peer in initial {
                if tx
                    .send(NetEvent::PrivateReleaseDue { room, peer, token })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }));
        let release = ReleaseWait {
            instance: Arc::downgrade(&instance),
            attachment,
            authority: lifetime.authority.clone(),
            guard,
            reply,
            ensure,
            missed,
            ready: BTreeSet::new(),
            deadlines,
            token,
            tasks,
        };
        if let Some(parked) = self.parked_private_drives.get_mut(&room) {
            parked.releases[usize::from(ensure)].push(release);
        } else {
            self.parked_private_drives.insert(
                room,
                ParkedPrivateDrive {
                    instance: Arc::downgrade(&instance),
                    attachment,
                    stage: DriveStage::Query,
                    guard: None,
                    authority: lifetime.authority.clone(),
                    releases: if ensure {
                        [Vec::new(), vec![release]]
                    } else {
                        [vec![release], Vec::new()]
                    },
                    drive_active: false,
                    upgrades: Vec::new(),
                    busy_owner: None,
                    room_wait: None,
                    prerequisite: DriveWait::Projection,
                    reply: None,
                },
            );
        }
    }

    pub(in crate::node::actor) async fn wake_session_release(
        &mut self,
        room: Digest32,
        peer: Digest32,
        token: Option<u64>,
    ) {
        let matches = |release: &ReleaseWait| {
            release.missed.contains(&peer) && token.is_none_or(|token| token == release.token)
        };
        let Some(parked) = self.parked_private_drives.get_mut(&room) else {
            return;
        };
        if !parked.releases.iter().flatten().any(matches) {
            return;
        }
        for release in parked
            .releases
            .iter_mut()
            .flatten()
            .filter(|release| matches(release))
        {
            release.ready.insert(peer);
        }
        if let Some(owner) = self.pending_posts.get(&room).map(post_save::Pending::owner) {
            parked.busy_owner = Some(owner);
            return;
        }
        let fault = parked
            .releases
            .iter()
            .flatten()
            .find(|release| matches(release))
            .and_then(|release| {
                if release.attachment != self.delivery_epoch
                    || !release
                        .instance
                        .upgrade()
                        .zip(self.channels.get(&room))
                        .is_some_and(|(held, current)| Arc::ptr_eq(&held, current))
                {
                    Some(Fault::ChannelNotOpen)
                } else if !release.authority.current()
                    || release
                        .guard
                        .as_ref()
                        .is_some_and(|guard| guard.active(self.computer.as_ref()).is_err())
                {
                    Some(Fault::ComputerPolicy)
                } else {
                    None
                }
            })
            .or_else(|| (!self.computer_authority_current()).then_some(Fault::ComputerPolicy));
        if let Some(fault) = fault {
            if let Some(parked) = self.parked_private_drives.get_mut(&room) {
                if let Some((slot, at)) =
                    parked
                        .releases
                        .iter()
                        .enumerate()
                        .find_map(|(slot, entries)| {
                            entries.iter().position(matches).map(|at| (slot, at))
                        })
                {
                    let mut release = parked.releases[slot].remove(at);
                    if let Some(reply) = release.reply.take() {
                        let _ = reply.send(Outcome::Failed(fault));
                    }
                }
            }
            if self.parked_private_drives.get(&room).is_some_and(|parked| {
                !parked.drive_active
                    && parked.upgrades.is_empty()
                    && parked.releases.iter().all(Vec::is_empty)
            }) {
                self.parked_private_drives.remove(&room);
            }
            let next = self.parked_private_drives.get(&room).and_then(|parked| {
                parked
                    .releases
                    .iter()
                    .flatten()
                    .find(|release| release.ready.contains(&peer))
                    .map(|release| release.token)
            });
            if let Some(next) = next {
                let tx = self.net_tx.clone();
                self.spawn_join_housekeeping(async move {
                    let _ = tx
                        .send(NetEvent::PrivateReleaseDue {
                            room,
                            peer,
                            token: next,
                        })
                        .await;
                });
            }
            return;
        }
        if self.prekeys.is_none()
            || self
                .delivery_bundle_waiting(&room, peer, true)
                .await
                .is_err()
        {
            let since = self.one_time_waits.get(&(room, peer)).copied();
            let mut deadlines = Vec::new();
            if let Some(parked) = self.parked_private_drives.get_mut(&room) {
                for release in parked
                    .releases
                    .iter_mut()
                    .flatten()
                    .filter(|release| matches(release))
                {
                    release.ready.remove(&peer);
                    if let Some(since) = since {
                        if release.deadlines.get(&peer) != Some(&since) {
                            release.deadlines.insert(peer, since);
                            deadlines.push((release.token, since));
                        }
                    } else {
                        release.deadlines.remove(&peer);
                    }
                }
            }
            for (release_token, since) in deadlines {
                let delay = since
                    .saturating_add(ONE_TIME_WAIT_MS)
                    .saturating_sub(self.now_ms().get());
                let tx = self.net_tx.clone();
                let task = self.spawn_join_housekeeping(async move {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    let _ = tx
                        .send(NetEvent::PrivateReleaseDue {
                            room,
                            peer,
                            token: release_token,
                        })
                        .await;
                });
                if let Some(parked) = self.parked_private_drives.get_mut(&room) {
                    if let Some(release) = parked
                        .releases
                        .iter_mut()
                        .flatten()
                        .find(|release| release.token == release_token)
                    {
                        release.tasks.push(task);
                    } else {
                        task.abort();
                    }
                } else {
                    task.abort();
                }
            }
            return;
        }
        let Some(parked) = self.parked_private_drives.get_mut(&room) else {
            return;
        };
        let Some((slot, at)) = parked
            .releases
            .iter()
            .enumerate()
            .find_map(|(slot, entries)| entries.iter().position(matches).map(|at| (slot, at)))
        else {
            return;
        };
        let mut release = parked.releases[slot].remove(at);
        let ensure = release.ensure;
        let guard = release.guard.take();
        let reply = release.reply.take();
        if !parked.drive_active
            && parked.upgrades.is_empty()
            && parked.releases.iter().all(Vec::is_empty)
        {
            self.parked_private_drives.remove(&room);
        }
        drop(release);
        self.begin_owned_session_drive_retained(room, ensure, guard, None, reply)
            .await;
        let next = self.pending_posts.get(&room).map(post_save::Pending::owner);
        if let Some(parked) = self.parked_private_drives.get_mut(&room) {
            if next.is_some() {
                parked.busy_owner = next;
            }
        }
    }

    pub(in crate::node::actor) fn retire_parked_private_drive(
        &mut self,
        room: &Digest32,
        fault: Fault,
    ) {
        if let Some(parked) = self.parked_private_drives.remove(room) {
            parked.retire(fault);
        }
    }

    pub(in crate::node::actor) fn retire_parked_private_drives(&mut self, fault: Fault) {
        for (_, parked) in std::mem::take(&mut self.parked_private_drives) {
            parked.retire(fault);
        }
    }

    pub(in crate::node::actor) fn retire_stale_private_drives(&mut self) {
        let computer = self.computer.as_ref();
        self.parked_private_drives.retain(|_, parked| {
            if parked.drive_active
                && (!parked.authority.current()
                    || parked
                        .guard
                        .as_ref()
                        .is_some_and(|guard| guard.active(computer).is_err()))
            {
                parked.drive_active = false;
                parked.room_wait = None;
                if let Some(reply) = parked.reply.take() {
                    let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
                }
            }
            parked.upgrades.retain_mut(|upgrade| {
                if !upgrade.authority.current()
                    || upgrade
                        .guard
                        .as_ref()
                        .is_some_and(|guard| guard.active(computer).is_err())
                {
                    if let Some(reply) = upgrade.reply.take() {
                        let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
                    }
                    false
                } else {
                    true
                }
            });
            if !parked.drive_active && !parked.upgrades.is_empty() {
                parked.activate_upgrade(0);
            }
            for entries in &mut parked.releases {
                entries.retain_mut(|release| {
                    if !release.authority.current()
                        || release
                            .guard
                            .as_ref()
                            .is_some_and(|guard| guard.active(computer).is_err())
                    {
                        if let Some(reply) = release.reply.take() {
                            let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
                        }
                        false
                    } else {
                        true
                    }
                });
            }
            parked.drive_active
                || !parked.upgrades.is_empty()
                || parked.releases.iter().any(|entries| !entries.is_empty())
        });
    }

    pub(in crate::node::actor) async fn resume_parked_private_drive(&mut self, room: Digest32) {
        self.retire_stale_private_drives();
        if self
            .parked_private_drives
            .get(&room)
            .is_some_and(|parked| parked.busy_owner.is_some())
        {
            return;
        }
        if let Some(parked) = self.parked_private_drives.get_mut(&room) {
            if !parked.drive_active && !parked.upgrades.is_empty() {
                parked.activate_upgrade(0);
            }
            if !parked.drive_active {
                return;
            }
        }
        if let Some(owner) = self.pending_posts.get(&room).map(post_save::Pending::owner) {
            if let Some(parked) = self.parked_private_drives.get_mut(&room) {
                parked.busy_owner = Some(owner);
            }
            return;
        }
        let Some(mut parked) = self.parked_private_drives.remove(&room) else {
            return;
        };
        let Some(instance) = parked.instance.upgrade() else {
            parked.retire(Fault::ChannelNotOpen);
            return;
        };
        if parked.attachment != self.delivery_epoch
            || !self
                .channels
                .get(&room)
                .is_some_and(|current| Arc::ptr_eq(current, &instance))
        {
            parked.retire(Fault::ChannelNotOpen);
            return;
        }
        if !parked.authority.current()
            || !self.computer_authority_current()
            || parked
                .guard
                .as_ref()
                .is_some_and(|guard| guard.active(self.computer.as_ref()).is_err())
        {
            parked.drive_active = false;
            if let Some(reply) = parked.reply.take() {
                let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
            }
            if !parked.upgrades.is_empty()
                || parked.releases.iter().any(|entries| !entries.is_empty())
            {
                self.parked_private_drives.insert(room, parked);
            }
            return;
        }
        let Some(profile) = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
        else {
            parked.retire(Fault::Locked);
            return;
        };
        let store = profile.store_handle();
        let Ok(mut channel) = instance.try_lock() else {
            if parked.room_wait.is_none() {
                let token = self.next_token;
                self.next_token += 1;
                let weak = Arc::downgrade(&instance);
                let tx = self.net_tx.clone();
                let task = self.spawn_join_housekeeping(async move {
                    let Some(room_state) = weak.upgrade() else {
                        return;
                    };
                    drop(room_state.lock().await);
                    let _ = tx
                        .send(NetEvent::PrivateDriveRoomReady { room, token })
                        .await;
                });
                parked.room_wait = Some(RoomWake { token, task });
            }
            self.parked_private_drives.insert(room, parked);
            return;
        };
        let mut eligible_for = |prerequisite| match prerequisite {
            DriveWait::Native => Ok(true),
            DriveWait::Upgrade(pending_upgrade::UpgradeWait::Governance) => {
                channel.private_policy_ready(&store, self.now_ms().get())
            }
            DriveWait::Upgrade(pending_upgrade::UpgradeWait::LocalPreparation) => {
                Ok(!channel.session_upgrade_local_work())
            }
            DriveWait::Upgrade(pending_upgrade::UpgradeWait::ControlEntry { author, seq }) => {
                channel.private_control_entry_ready(&store, &author, seq)
            }
            DriveWait::Upgrade(pending_upgrade::UpgradeWait::ControlFrontier {
                author,
                through,
            }) => channel.private_control_frontier_ready(&store, &author, through),
            DriveWait::Support => self
                .support_recipients_checked(&room, &channel, &store)
                .map(|(ready, _)| ready),
            DriveWait::SupportPublication => Ok(channel.is_settled()
                && !channel.is_poisoned()
                && channel.is_author(&channel.me())
                && !channel.has_left(&channel.me())
                && !channel.private_support_discovery_pending()),
            DriveWait::Publication => channel.history_publication_busy(&store).map(|busy| !busy),
            DriveWait::Projection => {
                let me = channel.me();
                match channel.session_query(
                    &store,
                    Query::HasOpen { node: me },
                    1,
                    self.now_ms().get(),
                ) {
                    Ok(SessionReply::HasOpen(_)) => Ok(true),
                    Ok(_) => Err(Error::Profile(
                        "private Session query returned an unexpected reply",
                    )),
                    Err(_) if channel.is_poisoned() => {
                        Err(Error::Profile("private Session query failed"))
                    }
                    Err(_) => Ok(false),
                }
            }
        };
        let mut eligible = eligible_for(parked.prerequisite);
        if matches!(&eligible, Ok(false)) {
            for (at, upgrade) in parked.upgrades.iter().enumerate() {
                if !upgrade.authority.current()
                    || upgrade
                        .guard
                        .as_ref()
                        .is_some_and(|guard| guard.active(self.computer.as_ref()).is_err())
                {
                    continue;
                }
                if matches!(eligible_for(upgrade.prerequisite), Ok(true)) {
                    parked.activate_upgrade(at);
                    eligible = Ok(true);
                    break;
                }
            }
        }
        let readiness = channel.legacy_cache_only(&store).and_then(|legacy| {
            if legacy {
                Err(Error::StreamRefused("legacy history is not current"))
            } else {
                channel
                    .require_governance_ready(&store, self.now_ms())
                    .map(|_| ())
            }
        });
        drop(channel);
        match eligible {
            Ok(true) => {}
            Ok(false) => {
                self.parked_private_drives.insert(room, parked);
                return;
            }
            Err(error) => {
                parked.drive_active = false;
                if let Some(reply) = parked.reply.take() {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
                if !parked.upgrades.is_empty()
                    || parked.releases.iter().any(|entries| !entries.is_empty())
                {
                    self.parked_private_drives.insert(room, parked);
                }
                return;
            }
        }
        if let Err(error) = readiness {
            let fault = fault_of(&error);
            if matches!(
                fault,
                Fault::RoomNotSynced
                    | Fault::GovernanceRefreshing
                    | Fault::RoomPreparing
                    | Fault::RoomChangePending
            ) {
                self.parked_private_drives.insert(room, parked);
            } else {
                parked.drive_active = false;
                if let Some(reply) = parked.reply.take() {
                    let _ = reply.send(Outcome::Failed(fault));
                }
                if !parked.upgrades.is_empty()
                    || parked.releases.iter().any(|entries| !entries.is_empty())
                {
                    self.parked_private_drives.insert(room, parked);
                }
            }
            return;
        }
        let work = match parked.stage {
            DriveStage::Upgrade => maintenance_save::Work::Private(Work::Upgrade {
                finish_initial: false,
            }),
            DriveStage::Sessions => maintenance_save::Work::Projection(ProjectionWork::Sessions),
            DriveStage::Legacy => maintenance_save::Work::Private(Work::AnnounceLegacy),
            DriveStage::Support => {
                maintenance_save::Work::Consent(consent_save::Work::PrivateSupport {
                    discovery_ready: true,
                })
            }
            DriveStage::Query => maintenance_save::Work::Projection(ProjectionWork::Sessions),
        };
        let continuation = Continuation {
            instance,
            attachment: parked.attachment,
            lifetime: None,
            after: After::Drive {
                stage: parked.stage,
                guard: parked.guard.take(),
            },
        };
        let reply = parked.reply.take();
        if !parked.upgrades.is_empty() || parked.releases.iter().any(|entries| !entries.is_empty())
        {
            parked.drive_active = false;
            self.parked_private_drives.insert(room, parked);
        }
        self.begin_pending_maintenance(
            room,
            work,
            maintenance_save::Continuation::Private(continuation),
            reply,
        )
        .await;
        let next = self.pending_posts.get(&room).map(post_save::Pending::owner);
        if let Some(parked) = self.parked_private_drives.get_mut(&room) {
            if next.is_some() {
                parked.busy_owner = next;
            }
        }
    }

    fn park_private_drive(
        &mut self,
        room: Digest32,
        authority: computer::ComputerAuthority,
        continuation: Continuation,
        reply: ActorReply,
        prerequisite: DriveWait,
    ) {
        let After::Drive { stage, guard } = continuation.after else {
            return;
        };
        let busy_owner = self.pending_posts.get(&room).map(post_save::Pending::owner);
        if let Some(parked) = self.parked_private_drives.get_mut(&room) {
            if parked.attachment == continuation.attachment
                && parked
                    .instance
                    .upgrade()
                    .is_some_and(|held| Arc::ptr_eq(&held, &continuation.instance))
            {
                if parked.drive_active {
                    parked.upgrades.push(UpgradeObligation {
                        stage: parked.stage,
                        guard: parked.guard.take(),
                        authority: parked.authority.clone(),
                        prerequisite: parked.prerequisite,
                        reply: parked.reply.take(),
                        room_wait: parked.room_wait.take(),
                        ready: matches!(parked.prerequisite, DriveWait::Native),
                    });
                }
                parked.stage = stage;
                parked.guard = guard;
                parked.authority = authority;
                parked.prerequisite = prerequisite;
                parked.reply = reply;
                parked.drive_active = true;
                parked.busy_owner = busy_owner;
            } else if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            }
            return;
        }
        self.parked_private_drives.insert(
            room,
            ParkedPrivateDrive {
                instance: Arc::downgrade(&continuation.instance),
                attachment: continuation.attachment,
                stage,
                releases: [Vec::new(), Vec::new()],
                upgrades: Vec::new(),
                drive_active: true,
                busy_owner,
                room_wait: None,
                prerequisite,
                guard,
                authority,
                reply,
            },
        );
    }

    fn private_publication_wait(&self, instance: &SharedChannel) -> Option<PublicationWait> {
        match instance.try_lock() {
            Ok(channel) => {
                let profile = self.profile.as_ref()?;
                if channel
                    .history_publication_busy(&profile.store_handle())
                    .ok()?
                {
                    return Some((DriveWait::Publication, channel.history_publication_wake()));
                }
            }
            Err(_) => {
                let weak = Arc::downgrade(instance);
                return Some((
                    DriveWait::Native,
                    Box::pin(async move {
                        if let Some(instance) = weak.upgrade() {
                            drop(instance.lock().await);
                        }
                    }),
                ));
            }
        }
        if let Some(computer) = self.computer.as_ref().map(Arc::clone) {
            return Some((
                DriveWait::Native,
                Box::pin(async move { computer.wait_publication_writer().await }),
            ));
        }
        Some((DriveWait::Native, Box::pin(std::future::ready(()))))
    }

    pub(in crate::node::actor) fn checked_support_discovery(
        &mut self,
        room: Digest32,
        channel: &ChannelState,
        store: &Store,
    ) -> bool {
        if !channel.private_support_discovery_pending() {
            return false;
        }
        let Ok((ready, missing_port)) = self.support_recipients_checked(&room, channel, store)
        else {
            return false;
        };
        if missing_port {
            self.discover_rooms.insert(room);
            self.sched_rooms.insert(room);
        }
        ready
    }

    /// This connection/proof edge renews support only; it never starts a Drive release.
    pub(in crate::node::actor) async fn begin_owned_support_discovery(
        &mut self,
        room: Digest32,
    ) -> bool {
        let Some(profile) = self.profile.as_ref() else {
            return false;
        };
        if self.locking != 0 || profile.signer().is_err() {
            return false;
        }
        let node = profile.fingerprint();
        let store = profile.store_handle();
        let Some(instance) = self.channels.get(&room).cloned() else {
            return false;
        };
        let Ok(channel) = instance.try_lock() else {
            self.bounded_sync.wait_for_own_recovery_room(
                &self.net_tx,
                &mut self.next_token,
                node,
                room,
                instance.clone(),
            );
            return false;
        };
        if !channel.private_support_discovery_pending() {
            return false;
        }
        if self.pending_posts.contains_key(&room) || channel.post_pending() {
            let released = channel.history_publication_wake();
            drop(channel);
            self.bounded_sync.wait_for_support_discovery_publication(
                &self.net_tx,
                &mut self.next_token,
                node,
                room,
                instance,
                released,
            );
            return false;
        }
        if !self.checked_support_discovery(room, &channel, &store) {
            return false;
        }
        drop(channel);
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            after: After::SupportDiscovery(SupportStage::Refresh),
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Recovery(recovery_save::Work::support_refresh(self.now_ms())),
            maintenance_save::Continuation::Private(continuation),
            None,
        )
        .await
    }

    /// Active work validates its settled authority at each continuation. Parked work drops
    /// physical leases and reacquires admission before resuming.
    fn owned_private_drive_guard(
        &self,
        guard: Option<&computer::ComputerPolicyGuard>,
        lifetime: Option<&maintenance_save::Lifetime>,
    ) -> Result<()> {
        let Some(lifetime) = lifetime else {
            return self.computer_drive_guard(guard);
        };
        if let Some(guard) = guard {
            guard.active(self.computer.as_ref())?;
        }
        lifetime.publish(|| ()).ok_or(Error::Profile(
            "computer trust is pending application on this node",
        ))
    }

    /// Drive work keeps its original policy decision; a parked continuation retains no lease.
    pub(in crate::node::actor) async fn begin_owned_private_drive(
        &mut self,
        room: Digest32,
        fresh_projection: bool,
        guard: Option<computer::ComputerPolicyGuard>,
        lifetime: Option<Arc<maintenance_save::Lifetime>>,
        reply: ActorReply,
    ) -> bool {
        let stage = if fresh_projection {
            DriveStage::Sessions
        } else {
            DriveStage::Upgrade
        };
        if self
            .parked_private_drives
            .get(&room)
            .is_some_and(|parked| !parked.drive_active && parked.upgrades.is_empty())
        {
            let Some(instance) = self.channels.get(&room).cloned() else {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                }
                return false;
            };
            if let Err(error) = self.owned_private_drive_guard(guard.as_ref(), lifetime.as_deref())
            {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
                return false;
            }
            let Some(authority) = lifetime
                .as_ref()
                .map(|held| held.authority.clone())
                .or_else(|| self.computer_authority())
            else {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
                }
                return false;
            };
            let Some(parked) = self.parked_private_drives.get_mut(&room) else {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                }
                return false;
            };
            if parked.attachment != self.delivery_epoch
                || !parked
                    .instance
                    .upgrade()
                    .is_some_and(|held| Arc::ptr_eq(&held, &instance))
            {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                }
                return false;
            }
            parked.drive_active = true;
            parked.stage = stage;
            parked.guard = guard;
            parked.authority = authority;
            parked.reply = reply;
            parked.prerequisite = DriveWait::Native;
            parked.busy_owner = self.pending_posts.get(&room).map(post_save::Pending::owner);
            if fresh_projection {
                parked.room_wait = None;
            }
            drop(lifetime);
            if parked.busy_owner.is_none() {
                self.resume_parked_private_drive(room).await;
            }
            return true;
        }
        if self.parked_private_drives.contains_key(&room) {
            if let Err(error) = self.owned_private_drive_guard(guard.as_ref(), lifetime.as_deref())
            {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(fault_of(&error)));
                }
                return false;
            }
            let Some(authority) = lifetime
                .as_ref()
                .map(|held| held.authority.clone())
                .or_else(|| self.computer_authority())
            else {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
                }
                return false;
            };
            let Some(instance) = self.channels.get(&room) else {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                }
                return false;
            };
            let Some(parked) = self.parked_private_drives.get_mut(&room) else {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                }
                return false;
            };
            if parked.attachment != self.delivery_epoch
                || !parked
                    .instance
                    .upgrade()
                    .is_some_and(|held| Arc::ptr_eq(&held, instance))
            {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
                }
                return false;
            }
            if fresh_projection && guard.is_none() && reply.is_none() {
                // A local append or reopen must not coalesce behind peer support.
                // Reuse automatic work instead of accumulating displaced support stages.
                if parked.drive_active && parked.guard.is_none() && parked.reply.is_none() {
                    parked.stage = stage;
                    parked.authority = authority;
                    parked.prerequisite = DriveWait::Native;
                    parked.room_wait = None;
                } else if let Some(queued) = parked
                    .upgrades
                    .iter_mut()
                    .find(|item| item.guard.is_none() && item.reply.is_none())
                {
                    queued.stage = stage;
                    queued.authority = authority;
                    queued.prerequisite = DriveWait::Native;
                    queued.room_wait = None;
                    queued.ready = true;
                } else {
                    parked.upgrades.push(UpgradeObligation {
                        stage,
                        guard: None,
                        authority,
                        prerequisite: DriveWait::Native,
                        reply: None,
                        room_wait: None,
                        ready: true,
                    });
                }
                if let Some(owner) = self.pending_posts.get(&room).map(post_save::Pending::owner) {
                    parked.busy_owner = Some(owner);
                }
                let run = parked.busy_owner.is_none();
                drop(lifetime);
                if run {
                    self.resume_parked_private_drive(room).await;
                }
                return true;
            }
            if guard.is_none()
                && reply.is_none()
                && ((parked.drive_active && parked.guard.is_none() && parked.reply.is_none())
                    || parked
                        .upgrades
                        .iter()
                        .any(|item| item.guard.is_none() && item.reply.is_none()))
            {
                return true;
            }
            parked.upgrades.push(UpgradeObligation {
                stage,
                guard,
                authority,
                prerequisite: DriveWait::Native,
                reply,
                room_wait: None,
                ready: true,
            });
            let run = parked.busy_owner.is_none() && !self.pending_posts.contains_key(&room);
            if run {
                parked.activate_upgrade(parked.upgrades.len() - 1);
            }
            drop(lifetime);
            if run {
                self.resume_parked_private_drive(room).await;
            }
            return true;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::ChannelNotOpen));
            }
            return false;
        };
        if let Err(error) = self.owned_private_drive_guard(guard.as_ref(), lifetime.as_deref()) {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
            }
            return false;
        }
        if self.pending_posts.contains_key(&room) {
            let authority = lifetime
                .as_ref()
                .map(|held| held.authority.clone())
                .or_else(|| self.computer_authority());
            let Some(authority) = authority else {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
                }
                return false;
            };
            self.parked_private_drives.insert(
                room,
                ParkedPrivateDrive {
                    instance: Arc::downgrade(&instance),
                    attachment: self.delivery_epoch,
                    stage,
                    busy_owner: self.pending_posts.get(&room).map(post_save::Pending::owner),
                    room_wait: None,
                    prerequisite: DriveWait::Native,
                    releases: [Vec::new(), Vec::new()],
                    upgrades: Vec::new(),
                    drive_active: true,
                    guard,
                    authority,
                    reply,
                },
            );
            return true;
        }
        let Some(profile) = &self.profile else {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            }
            return false;
        };
        let readiness = {
            let channel = instance.lock().await;
            channel
                .legacy_cache_only(profile.store())
                .and_then(|legacy| {
                    if legacy {
                        Err(Error::StreamRefused("legacy history is not current"))
                    } else {
                        channel
                            .require_governance_ready(profile.store(), self.now_ms())
                            .map(|_| ())
                    }
                })
        };
        let readiness = readiness
            .and_then(|()| self.owned_private_drive_guard(guard.as_ref(), lifetime.as_deref()));
        if let Err(error) = readiness {
            let fault = fault_of(&error);
            if matches!(
                fault,
                Fault::RoomNotSynced
                    | Fault::GovernanceRefreshing
                    | Fault::RoomPreparing
                    | Fault::RoomChangePending
            ) {
                if let Some(authority) = lifetime
                    .as_ref()
                    .map(|held| held.authority.clone())
                    .or_else(|| self.computer_authority())
                {
                    self.parked_private_drives.insert(
                        room,
                        ParkedPrivateDrive {
                            instance: Arc::downgrade(&instance),
                            attachment: self.delivery_epoch,
                            stage,
                            releases: [Vec::new(), Vec::new()],
                            upgrades: Vec::new(),
                            drive_active: true,
                            busy_owner: None,
                            room_wait: None,
                            prerequisite: DriveWait::Upgrade(
                                pending_upgrade::UpgradeWait::Governance,
                            ),
                            guard,
                            authority,
                            reply,
                        },
                    );
                    return true;
                }
            }
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
            }
            return false;
        }
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime,
            after: After::Drive { stage, guard },
        };
        let work = if fresh_projection {
            maintenance_save::Work::Projection(ProjectionWork::Sessions)
        } else {
            maintenance_save::Work::Private(Work::Upgrade {
                finish_initial: false,
            })
        };
        self.begin_pending_maintenance(
            room,
            work,
            maintenance_save::Continuation::Private(continuation),
            reply,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::node::actor) async fn begin_owned_private_serving(
        &mut self,
        instance: SharedChannel,
        ask: Ask,
        peer: Digest32,
        holders: BTreeSet<Digest32>,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        connection: Arc<VoxConnection>,
        job: Job,
        charge: BufferCharge,
        page_charge: BufferCharge,
        guard: history_demand::CurrentPrivateGuard,
    ) -> bool {
        let room = ask.room;
        let work = Work::Serve {
            ask,
            peer,
            holders,
            charge: page_charge,
            guard: guard.clone(),
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            after: After::Serving {
                send,
                recv,
                connection,
                job,
                charge,
                guard,
            },
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Private(work),
            maintenance_save::Continuation::Private(continuation),
            None,
        )
        .await
    }

    /// Decide one image request through the private serving rule; any refusal answers `false`.
    pub(in crate::node::actor) async fn begin_owned_private_admission(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        admission: pending_upgrade::MediaAdmission,
        guard: history_demand::CurrentPrivateGuard,
        answer: oneshot::Sender<bool>,
    ) -> bool {
        let work = Work::Admit {
            admission,
            guard: guard.clone(),
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            after: After::Admission { answer, guard },
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Private(work),
            maintenance_save::Continuation::Private(continuation),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::node::actor) async fn begin_owned_private_live(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        peer: Digest32,
        _token: Token,
        revision: u64,
        page: Result<Page>,
        received_at: u64,
        charge: BufferCharge,
        guard: history_demand::CurrentPrivateGuard,
        answer: oneshot::Sender<Result<pending_upgrade::LivePageResult>>,
    ) -> bool {
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            after: After::Live {
                answer,
                guard: guard.clone(),
                charge,
            },
        };
        let work = Work::Live {
            peer,
            revision,
            page,
            received_at,
            guard,
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Private(work),
            maintenance_save::Continuation::Private(continuation),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::node::actor) async fn begin_owned_private_archive(
        &mut self,
        room: Digest32,
        instance: SharedChannel,
        bounds: Bounds,
        plan: PrivatePlan,
        page: Page,
        nonce: Option<[u8; crate::atrest::sek::NONCE_LEN]>,
        guard: history_demand::PrivateGuard,
        job: Job,
        charge: BufferCharge,
        answer: oneshot::Sender<std::result::Result<ArchiveReceipt, String>>,
    ) -> bool {
        let work = Work::Archive {
            bounds,
            plan,
            page: Box::new(page),
            nonce,
            guard: guard.clone(),
        };
        let continuation = Continuation {
            instance,
            attachment: self.delivery_epoch,
            lifetime: None,
            after: After::Archive {
                answer,
                guard,
                job,
                charge,
            },
        };
        self.begin_pending_maintenance(
            room,
            maintenance_save::Work::Private(work),
            maintenance_save::Continuation::Private(continuation),
            None,
        )
        .await
    }

    pub(in crate::node::actor) fn reject_owned_private(
        &mut self,
        room: Digest32,
        error: Error,
        continuation: Continuation,
        reply: ActorReply,
    ) {
        if continuation.attached(self, &room)
            && matches!(
                error,
                Error::Profile("room publication is busy; retry this operation")
            )
        {
            match &continuation.after {
                After::Drive { .. } => {
                    let authority = continuation
                        .lifetime
                        .as_ref()
                        .map(|held| held.authority.clone())
                        .or_else(|| self.computer_authority());
                    if let Some(authority) = authority {
                        let waiting = self
                            .parked_private_drives
                            .get(&room)
                            .filter(|parked| !parked.drive_active && parked.room_wait.is_some())
                            .map(|_| (DriveWait::Native, None))
                            .or_else(|| {
                                self.private_publication_wait(&continuation.instance)
                                    .map(|(prerequisite, released)| (prerequisite, Some(released)))
                            });
                        if let Some((prerequisite, waiting)) = waiting {
                            self.park_private_drive(
                                room,
                                authority,
                                continuation,
                                reply,
                                prerequisite,
                            );
                            if let Some(released) = waiting {
                                let token = self.next_token;
                                self.next_token += 1;
                                let tx = self.net_tx.clone();
                                let task = self.spawn_join_housekeeping(async move {
                                    released.await;
                                    let _ = tx
                                        .send(NetEvent::PrivateDriveRoomReady { room, token })
                                        .await;
                                });
                                if let Some(parked) = self.parked_private_drives.get_mut(&room) {
                                    parked.room_wait = Some(RoomWake { token, task });
                                } else {
                                    task.abort();
                                }
                            }
                            return;
                        }
                    }
                }
                After::SupportDiscovery(SupportStage::Refresh) => {
                    if let Some((node, (_, released))) = self
                        .profile
                        .as_ref()
                        .map(Profile::fingerprint)
                        .zip(self.private_publication_wait(&continuation.instance))
                    {
                        self.bounded_sync.wait_for_support_discovery_publication(
                            &self.net_tx,
                            &mut self.next_token,
                            node,
                            room,
                            Arc::clone(&continuation.instance),
                            released,
                        );
                        if let Some(reply) = reply {
                            let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
                        }
                        return;
                    }
                }
                _ => {}
            }
        }
        let fault = fault_of(&error);
        match continuation.after {
            After::Serving {
                mut send, mut recv, ..
            } => crate::transport::streams::refuse(&mut send, &mut recv),
            After::Live { answer, .. } => {
                let _ = answer.send(Err(error));
            }
            After::Archive { answer, .. } => {
                let _ = answer.send(Err(error.to_string()));
            }
            After::Admission { answer, .. } => {
                let _ = answer.send(false);
            }
            After::Drive { .. } | After::SupportDiscovery(_) => {}
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Failed(fault));
        }
    }

    pub(in crate::node::actor) async fn finish_owned_private(
        &mut self,
        room: Digest32,
        result: Result<maintenance_save::Saved>,
        lifetime: Arc<maintenance_save::Lifetime>,
        mut continuation: Continuation,
        reply: ActorReply,
    ) {
        let result = match result {
            Ok(saved) => saved,
            Err(error) => {
                self.reject_owned_private(room, error, continuation, reply);
                return;
            }
        };
        if !continuation.attached(self, &room) {
            self.reject_owned_private(
                room,
                Error::StreamRefused("private room attachment changed"),
                continuation,
                reply,
            );
            return;
        }
        continuation.lifetime = None;
        if let maintenance_save::Saved::Private(Saved::Flow(flow)) = result {
            let Some(guard) = continuation.flow_guard() else {
                self.reject_owned_private(
                    room,
                    Error::Profile("private flow continuation changed"),
                    continuation,
                    reply,
                );
                return;
            };
            continuation.lifetime = Some(lifetime);
            self.continue_private(
                room,
                maintenance_save::Work::Private(Work::Flow { flow, guard }),
                continuation,
                reply,
            )
            .await;
            return;
        }
        if let After::SupportDiscovery(stage) = &continuation.after {
            let stage = *stage;
            self.finish_support_discovery(room, result, lifetime, continuation, reply, stage)
                .await;
            return;
        }
        if let After::Drive { stage, guard } = &continuation.after {
            if let Err(error) =
                self.owned_private_drive_guard(guard.as_ref(), Some(lifetime.as_ref()))
            {
                self.reject_owned_private(room, error, continuation, reply);
                return;
            }
            let stage = *stage;
            self.finish_private_drive(room, result, lifetime, continuation, reply, stage)
                .await;
            return;
        }
        match (continuation.after, result) {
            (
                After::Serving {
                    send,
                    mut recv,
                    connection,
                    job,
                    charge,
                    guard,
                },
                maintenance_save::Saved::Private(Saved::Page(page)),
            ) => {
                self.spawn_join_housekeeping(async move {
                    let (_lifetime, _guard, _connection, _job, _charge) =
                        (lifetime, guard, connection, job, charge);
                    let _ = &mut recv;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(10),
                        crate::node::sessionstream::answer(send, page, &_lifetime.store, &room),
                    )
                    .await;
                });
            }
            (
                After::Live {
                    answer,
                    guard,
                    charge,
                },
                maintenance_save::Saved::Private(Saved::PageFinished(
                    pending_upgrade::PageResult::Live(result),
                )),
            ) => {
                drop((lifetime, guard, charge));
                let _ = answer.send(Ok(result));
            }
            (
                After::Archive {
                    answer,
                    guard,
                    job,
                    charge,
                },
                maintenance_save::Saved::Private(Saved::PageFinished(
                    pending_upgrade::PageResult::Archive(plan),
                )),
            ) => {
                let _ = answer.send(Ok(ArchiveReceipt {
                    plan,
                    lifetime,
                    charge,
                }));
                drop((guard, job));
            }
            (
                After::Admission { answer, guard },
                maintenance_save::Saved::Private(Saved::Admitted(admitted)),
            ) => {
                drop((lifetime, guard));
                let _ = answer.send(admitted);
            }
            (after, _) => {
                let continuation = Continuation {
                    after,
                    ..continuation
                };
                self.reject_owned_private(
                    room,
                    Error::Profile("private completion does not match its continuation"),
                    continuation,
                    reply,
                );
                return;
            }
        }
        if let Some(reply) = reply {
            let _ = reply.send(Outcome::Done);
        }
    }

    async fn continue_private(
        &mut self,
        room: Digest32,
        work: maintenance_save::Work,
        continuation: Continuation,
        reply: ActorReply,
    ) {
        Box::pin(self.begin_pending_maintenance(
            room,
            work,
            maintenance_save::Continuation::Private(continuation),
            reply,
        ))
        .await;
    }

    async fn finish_private_drive(
        &mut self,
        room: Digest32,
        result: maintenance_save::Saved,
        lifetime: Arc<maintenance_save::Lifetime>,
        mut continuation: Continuation,
        reply: ActorReply,
        stage: DriveStage,
    ) {
        let mut prerequisite = match stage {
            DriveStage::Sessions | DriveStage::Support => DriveWait::Support,
            DriveStage::Query => DriveWait::Projection,
            DriveStage::Upgrade | DriveStage::Legacy => {
                DriveWait::Upgrade(pending_upgrade::UpgradeWait::Governance)
            }
        };
        let next = match (stage, result) {
            (
                DriveStage::Query,
                maintenance_save::Saved::Projection(ProjectionProgress::Sessions { .. }),
            ) => {
                self.release_private_drive(room, lifetime, continuation, reply)
                    .await;
                return;
            }
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::Upgrade(saved))) => {
                if saved.advance == SessionAdvance::Waiting {
                    let Some(reason) = saved.wait else {
                        self.reject_owned_private(
                            room,
                            Error::Profile("private upgrade wait reason missing"),
                            continuation,
                            reply,
                        );
                        return;
                    };
                    prerequisite = DriveWait::Upgrade(reason);
                    None
                } else {
                    Some((
                        DriveStage::Upgrade,
                        maintenance_save::Work::Private(Work::Upgrade {
                            finish_initial: false,
                        }),
                    ))
                }
            }
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::ControlImport)) => {
                Some((
                    DriveStage::Upgrade,
                    maintenance_save::Work::Private(Work::Import),
                ))
            }
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::PrivateExpiry)) => {
                Some((
                    DriveStage::Upgrade,
                    maintenance_save::Work::Private(Work::Expiry),
                ))
            }
            (
                DriveStage::Upgrade,
                maintenance_save::Saved::Private(Saved::Imported | Saved::Expired),
            ) => Some((
                DriveStage::Upgrade,
                maintenance_save::Work::Private(Work::Upgrade {
                    finish_initial: false,
                }),
            )),
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::ExpiryUnavailable)) => {
                let publication = {
                    let channel = continuation.instance.lock().await;
                    match channel.history_publication_busy(&lifetime.store) {
                        Ok(true) => Some(channel.history_publication_wake()),
                        Ok(false) => None,
                        Err(error) => {
                            drop(channel);
                            self.reject_owned_private(room, error, continuation, reply);
                            return;
                        }
                    }
                };
                let reason = if publication.is_some() {
                    DriveWait::Publication
                } else {
                    DriveWait::Upgrade(pending_upgrade::UpgradeWait::Governance)
                };
                self.park_private_drive(
                    room,
                    lifetime.authority.clone(),
                    continuation,
                    reply,
                    reason,
                );
                drop(lifetime);
                let token = self.next_token;
                self.next_token += 1;
                let tx = self.net_tx.clone();
                let task = self.spawn_join_housekeeping(async move {
                    if let Some(wake) = publication {
                        wake.await;
                    }
                    let _ = tx
                        .send(NetEvent::PrivateDriveRoomReady { room, token })
                        .await;
                });
                if let Some(parked) = self.parked_private_drives.get_mut(&room) {
                    parked.room_wait = Some(RoomWake { token, task });
                } else {
                    task.abort();
                }
                return;
            }
            (DriveStage::Upgrade, maintenance_save::Saved::Private(Saved::UpgradeComplete)) => {
                Some((
                    DriveStage::Sessions,
                    maintenance_save::Work::Projection(ProjectionWork::Sessions),
                ))
            }
            (
                DriveStage::Upgrade,
                maintenance_save::Saved::Private(Saved::UpgradeWaiting(reason)),
            ) => {
                prerequisite = DriveWait::Upgrade(reason);
                None
            }
            (
                DriveStage::Sessions,
                maintenance_save::Saved::Projection(ProjectionProgress::Sessions {
                    advanced: true,
                }),
            ) => Some((
                DriveStage::Sessions,
                maintenance_save::Work::Projection(ProjectionWork::Sessions),
            )),
            (
                DriveStage::Sessions,
                maintenance_save::Saved::Projection(ProjectionProgress::Sessions {
                    advanced: false,
                }),
            ) => {
                let checked = {
                    let channel = continuation.instance.lock().await;
                    self.support_recipients_checked(&room, &channel, &lifetime.store)
                };
                let (ready, missing_port) = match checked {
                    Ok(checked) => checked,
                    Err(error) => {
                        self.reject_owned_private(room, error, continuation, reply);
                        return;
                    }
                };
                if missing_port {
                    self.discover_rooms.insert(room);
                    self.sched_rooms.insert(room);
                }
                ready.then_some((
                    DriveStage::Legacy,
                    maintenance_save::Work::Private(Work::AnnounceLegacy),
                ))
            }
            (
                DriveStage::Legacy,
                maintenance_save::Saved::Private(Saved::Announcement { count, complete }),
            ) => {
                if count != 0 {
                    self.note_local_append(&room);
                }
                Some(if complete {
                    (
                        DriveStage::Support,
                        maintenance_save::Work::Consent(consent_save::Work::PrivateSupport {
                            discovery_ready: true,
                        }),
                    )
                } else {
                    (
                        DriveStage::Legacy,
                        maintenance_save::Work::Private(Work::AnnounceLegacy),
                    )
                })
            }
            (
                DriveStage::Support,
                maintenance_save::Saved::Consent(consent_save::Effect::PrivateSupport(appended)),
            ) => {
                if appended {
                    self.note_local_append(&room);
                }
                self.release_private_drive(room, lifetime, continuation, reply)
                    .await;
                return;
            }
            (DriveStage::Support, maintenance_save::Saved::Unavailable) => {
                let ready = {
                    let channel = continuation.instance.lock().await;
                    channel.is_settled()
                        && !channel.is_poisoned()
                        && channel.is_author(&channel.me())
                        && !channel.has_left(&channel.me())
                        && !channel.private_support_discovery_pending()
                };
                if ready {
                    self.release_private_drive(room, lifetime, continuation, reply)
                        .await;
                    return;
                }
                prerequisite = DriveWait::SupportPublication;
                None
            }
            (_, maintenance_save::Saved::Unavailable) => None,
            _ => {
                self.reject_owned_private(
                    room,
                    Error::Profile("private drive prerequisite receipt changed"),
                    continuation,
                    reply,
                );
                return;
            }
        };
        if let Some((stage, work)) = next {
            if let After::Drive { stage: current, .. } = &mut continuation.after {
                *current = stage;
            }
            continuation.lifetime = Some(lifetime);
            self.continue_private(room, work, continuation, reply).await;
        } else {
            self.park_private_drive(
                room,
                lifetime.authority.clone(),
                continuation,
                reply,
                prerequisite,
            );
            drop(lifetime);
        }
    }

    async fn release_private_drive(
        &mut self,
        room: Digest32,
        lifetime: Arc<maintenance_save::Lifetime>,
        continuation: Continuation,
        reply: ActorReply,
    ) {
        let answer = {
            let mut channel = continuation.instance.lock().await;
            let me = channel.me();
            channel.session_query(
                &lifetime.store,
                Query::HasOpen { node: me },
                1,
                (self.millis_clock)(),
            )
        };
        let ensure = match answer {
            Ok(SessionReply::HasOpen(open)) => open,
            Err(_) => {
                let mut continuation = continuation;
                if let After::Drive { stage, .. } = &mut continuation.after {
                    *stage = DriveStage::Query;
                }
                self.park_private_drive(
                    room,
                    lifetime.authority.clone(),
                    continuation,
                    reply,
                    DriveWait::Projection,
                );
                drop(lifetime);
                return;
            }
            Ok(_) => {
                self.reject_owned_private(
                    room,
                    Error::Profile("private Session query returned an unexpected reply"),
                    continuation,
                    reply,
                );
                return;
            }
        };
        let After::Drive { guard, .. } = continuation.after else {
            return;
        };
        self.begin_owned_session_drive_retained(room, ensure, guard, Some(lifetime), reply)
            .await;
    }
}

impl Node {
    async fn finish_support_discovery(
        &mut self,
        room: Digest32,
        result: maintenance_save::Saved,
        lifetime: Arc<maintenance_save::Lifetime>,
        mut continuation: Continuation,
        reply: ActorReply,
        stage: SupportStage,
    ) {
        match (stage, result) {
            (
                SupportStage::Refresh,
                maintenance_save::Saved::Recovery(recovery_save::Saved::Fence(_)),
            ) => {
                let Ok(channel) = continuation.instance.try_lock() else {
                    self.bounded_sync.wait_for_own_recovery_room(
                        &self.net_tx,
                        &mut self.next_token,
                        crate::identity::composite::RootSigner::fingerprint(
                            lifetime.signer.as_ref(),
                        ),
                        room,
                        continuation.instance.clone(),
                    );
                    return;
                };
                if !self.checked_support_discovery(room, &channel, &lifetime.store) {
                    return;
                }
                drop(channel);
                continuation.after = After::SupportDiscovery(SupportStage::Publish);
                continuation.lifetime = Some(lifetime);
                self.continue_private(
                    room,
                    maintenance_save::Work::Consent(consent_save::Work::PrivateSupport {
                        discovery_ready: true,
                    }),
                    continuation,
                    reply,
                )
                .await;
            }
            (
                SupportStage::Publish,
                maintenance_save::Saved::Consent(consent_save::Effect::PrivateSupport(appended)),
            ) => {
                if appended {
                    self.note_local_append(&room);
                }
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Done);
                }
            }
            (_, maintenance_save::Saved::Unavailable) => {
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::RoomChangePending));
                }
            }
            _ => self.reject_owned_private(
                room,
                Error::Profile("private support receipt does not match its retained stage"),
                continuation,
                reply,
            ),
        }
    }
}
