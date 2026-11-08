//! Selected key delivery, receiver installation and cursor acknowledgement. No live room
//! state or retained history crosses native writer admission.
use super::*;
use crate::atrest::sek::WeakSek;
use crate::node::prekeys::OneTimeReservation;

pub(crate) use super::key_package_queue::{Pending as PendingPackage, Progress};
pub(crate) type SessionSlot = Arc<std::sync::Mutex<Option<crate::pairwise::session::Session>>>;

pub(crate) struct OutboundFrame {
    pub(crate) frame: Vec<u8>,
    pub(crate) one_time_prekey: Option<u64>,
    pub(crate) opening: Digest32,
}

pub(crate) enum Work {
    Select {
        trust_digest: Digest32,
        replay: bool,
        abandon_unopened: bool,
    },
    Open {
        pending: PendingPackage,
        context: crate::join::session::JoinContext,
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
        trusted: BTreeSet<Digest32>,
    },
    Respond {
        initial: Box<crate::pairwise::InitialMessage>,
        context: crate::join::session::JoinContext,
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
    },
    Initiate {
        bundle: Box<crate::identity::keyagreement::PrekeyBundlePublic>,
        context: crate::join::session::JoinContext,
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
        reservation: Option<OneTimeReservation>,
    },
    SealOutbound {
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
        bundle: Box<crate::identity::keyagreement::PrekeyBundlePublic>,
        context: crate::join::session::JoinContext,
        target: Digest32,
        skdm: Box<Skdm>,
        reservation: Option<OneTimeReservation>,
    },
    FrameOutbound {
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
        bundle: Box<crate::identity::keyagreement::PrekeyBundlePublic>,
        context: crate::join::session::JoinContext,
        skdm: Box<Skdm>,
        reservation: Option<OneTimeReservation>,
    },
    Unseal {
        session: SessionSlot,
        sealed: Vec<u8>,
        key: bool,
    },
    Attempt {
        locator: (Digest32, u64),
        skdm: Option<Box<Skdm>>,
    },
    Accept {
        skdm: Box<Skdm>,
    },
    Acknowledge(Attempt),
    Reoffer {
        target: Digest32,
        history: bool,
    },
    ResetDelivery {
        target: Digest32,
        history: bool,
    },
}

pub(crate) struct Attempt {
    pub(crate) locator: Option<(Digest32, u64)>,
    pub(crate) accepted: Option<AcceptedSkdm>,
    pub(crate) refusal: Option<Error>,
    pub(crate) author: Option<Digest32>,
    pub(crate) drive: bool,
    pub(crate) fresh: bool,
    pub(crate) package_pending: bool,
    pub(crate) floor_wait: Option<(u64, u64, u64, u64)>,
    floor_baseline: Option<(u64, u64, u64, u64)>,
    floor_resolved: bool,
}

pub(crate) enum Saved {
    Selected {
        progress: Progress,
        context: crate::join::session::JoinContext,
    },
    Opened {
        locator: (Digest32, u64),
        skdm: Option<Box<Skdm>>,
    },
    Responded(
        std::result::Result<
            Box<crate::pairwise::session::Session>,
            crate::node::pairwise_stream::KeyRefusal,
        >,
    ),
    Initiated {
        initiated: Option<(
            Box<crate::pairwise::InitialMessage>,
            Box<crate::pairwise::session::Session>,
        )>,
        reservation: Option<OneTimeReservation>,
    },
    SealedOutbound {
        package: Option<crate::node::keypackage::KeyPackage>,
        skdm: Box<Skdm>,
        removal_generation: u64,
        reservation: Option<OneTimeReservation>,
    },
    FramedOutbound {
        frame: Option<OutboundFrame>,
        skdm: Box<Skdm>,
        reservation: Option<OneTimeReservation>,
    },
    Unsealed {
        session: Box<crate::pairwise::session::Session>,
        result: std::result::Result<Option<Box<Skdm>>, crate::node::pairwise_stream::KeyRefusal>,
    },
    Installed(Attempt),
    Attempted(Attempt),
    Reoffered,
    /// A real native reset attempt; legacy session adoption ignores its storage error only
    /// after both original ledger attempts have finished. Other consumers keep the debt owed.
    DeliveryReset {
        error: Option<Error>,
    },
}

enum Native {
    Select {
        queue: key_package_queue::Queue,
        heads: BTreeMap<Digest32, u64>,
        trust: Digest32,
        context: crate::join::session::JoinContext,
    },
    Open {
        pending: PendingPackage,
        context: crate::join::session::JoinContext,
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
        trusted: BTreeSet<Digest32>,
        eligible: bool,
    },
    Respond {
        initial: Box<crate::pairwise::InitialMessage>,
        context: crate::join::session::JoinContext,
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
    },
    Initiate {
        bundle: Box<crate::identity::keyagreement::PrekeyBundlePublic>,
        context: crate::join::session::JoinContext,
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
        reservation: Option<OneTimeReservation>,
    },
    SealOutbound {
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
        bundle: Box<crate::identity::keyagreement::PrekeyBundlePublic>,
        context: crate::join::session::JoinContext,
        target: Digest32,
        skdm: Box<Skdm>,
        reservation: Option<OneTimeReservation>,
    },
    FrameOutbound {
        ring: Arc<tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>>,
        bundle: Box<crate::identity::keyagreement::PrekeyBundlePublic>,
        context: crate::join::session::JoinContext,
        skdm: Box<Skdm>,
        reservation: Option<OneTimeReservation>,
    },
    Unseal {
        session: SessionSlot,
        sealed: Vec<u8>,
        key: bool,
    },
    Install {
        receipt: Attempt,
        selected: Result<Option<Receiver>>,
    },
    Acknowledge {
        receipt: Attempt,
        queue: Option<key_package_queue::Queue>,
    },
    LedgerReset {
        target: Digest32,
        floor: Option<u64>,
        delivered: bool,
        write_history: bool,
        reoffer: bool,
    },
}

struct Receiver {
    skdm: Box<Skdm>,
    key: Box<CompositePublicKey>,
    existing: Option<Zeroizing<Vec<u8>>>,
    count: usize,
    normal: Result<receiver_overlay::Stamp>,
    drive_stamp: receiver_overlay::Stamp,
}

enum Delta {
    None,
    Queue(key_package_queue::Queue),
    Receiver {
        slot: (Digest32, u64),
        chain: Box<ReceiverChain>,
        drive: bool,
        retained: bool,
        changed: bool,
    },
    Reoffer {
        target: Digest32,
        history: Option<u64>,
        delivered: bool,
    },
}

pub(crate) struct Prepared {
    pending: Capsule,
    native: Native,
}

struct Capsule {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    me: Digest32,
    root: Digest32,
    membership: u64,
    now: u64,
    sek: WeakSek,
    removal_generation: Option<u64>,
    pin: Option<history::PendingHistoryRead>,
}

pub(crate) struct Completed {
    pending: Capsule,
    delta: Delta,
    committed: bool,
    poison: bool,
    result: Result<Saved>,
}

impl ChannelState {
    pub(crate) fn prepare_pending_package(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        work: Work,
    ) -> Result<Prepared> {
        // Delivery reset is debt metadata, not permission or a ratchet write. Its original
        // callers attempt both ledger saves even after a preceding storage failure.
        if self.poisoned && !matches!(&work, Work::ResetDelivery { .. }) {
            return Err(self.save_failure());
        }
        let removal_generation = if matches!(
            &work,
            Work::Open { .. }
                | Work::Attempt { .. }
                | Work::Accept { .. }
                | Work::SealOutbound { .. }
                | Work::FrameOutbound { .. }
                | Work::Reoffer { .. }
        ) {
            let generation = self.removal_generation(store)?;
            let me = self.me();
            if self.is_member_removed(store, &me)? {
                return Err(Error::StreamRefused("this node was removed from the room"));
            }
            let target = match &work {
                Work::SealOutbound { target, .. } => Some(*target),
                Work::Reoffer { target, .. } => Some(*target),
                Work::FrameOutbound { bundle, .. } => {
                    Some(CompositePublicKey::from_bytes(&bundle.root_pub)?.fingerprint())
                }
                _ => None,
            };
            if let Some(target) = target {
                if self.is_member_removed(store, &target)? {
                    return Err(Error::StreamRefused("key recipient is removed"));
                }
                match &work {
                    Work::SealOutbound { skdm, .. } | Work::FrameOutbound { skdm, .. }
                        if skdm.body.channel_id == self.channel_id
                            && !self
                                .validated_member_removals(
                                    store,
                                    &target,
                                    crate::time::Ms(self.now_hint),
                                )?
                                .is_empty() =>
                    {
                        let floor = self
                            .entitled_from(&target)
                            .map_or(self.sender.chain_id(), |(chain, _)| chain);
                        if self.room_removal_rotation_needed(store)? || skdm.body.chain_id < floor {
                            return Err(Error::Profile(governance::REFRESHING));
                        }
                    }
                    _ => {}
                }
            }
            governance::check_removal_generation(store, &self.sek, &self.channel_id, generation)?;
            Some(generation)
        } else {
            None
        };
        let native = match work {
            Work::Select {
                trust_digest,
                replay,
                abandon_unopened,
            } => {
                // Context is established before the durable selection cursor can advance.
                let context = self.join_context()?;
                let mut queue = self.key_packages.clone();
                if abandon_unopened {
                    queue.abandon_unopened();
                }
                if replay {
                    queue.retry_retained();
                }
                Native::Select {
                    queue,
                    heads: self.heads(),
                    trust: trust_digest,
                    context,
                }
            }
            Work::Open {
                pending,
                context,
                ring,
                trusted,
            } => {
                let segment = store
                    .get_segment(&self.channel_id, SegmentKind::LogDb, pending.log_id)?
                    .ok_or(Error::MalformedAtRest("key-package catalog body missing"))?;
                let wire = open_segment(&self.sek, SegmentKind::LogDb, pending.log_id, &segment)?;
                let entry = Entry::from_wire(&wire)?;
                if entry.skeleton.author_id != pending.author {
                    return Err(Error::MalformedAtRest("key-package catalog author differs"));
                }
                // #1171: once this node knows its own removal, a package whose signed causal
                // past lacks its cut is old key material, whichever peer relayed it.
                let eligible = if self.is_member_removed(store, &pending.author)? {
                    false
                } else {
                    match self.content_eligibility(store, &entry)? {
                        governance::ContentEligibility::Eligible => {
                            match self.recipient_body_eligibility(store, &self.me(), &entry)? {
                                governance::ContentEligibility::Eligible => true,
                                governance::ContentEligibility::Ineligible => false,
                                governance::ContentEligibility::Refreshing => {
                                    return Err(Error::Profile(governance::REFRESHING));
                                }
                            }
                        }
                        governance::ContentEligibility::Ineligible => false,
                        governance::ContentEligibility::Refreshing => {
                            return Err(Error::Profile(governance::REFRESHING));
                        }
                    }
                };
                Native::Open {
                    pending,
                    context,
                    ring,
                    trusted,
                    eligible,
                }
            }
            Work::Respond {
                initial,
                context,
                ring,
            } => Native::Respond {
                initial,
                context,
                ring,
            },
            Work::Initiate {
                bundle,
                context,
                ring,
                reservation,
            } => Native::Initiate {
                bundle,
                context,
                ring,
                reservation,
            },
            Work::SealOutbound {
                ring,
                bundle,
                context,
                target,
                skdm,
                reservation,
            } => Native::SealOutbound {
                ring,
                bundle,
                context,
                target,
                skdm,
                reservation,
            },
            Work::FrameOutbound {
                ring,
                bundle,
                context,
                skdm,
                reservation,
            } => Native::FrameOutbound {
                ring,
                bundle,
                context,
                skdm,
                reservation,
            },
            Work::Unseal {
                session,
                sealed,
                key,
            } => Native::Unseal {
                session,
                sealed,
                key,
            },
            Work::Attempt { locator, skdm } => self.package_install(store, Some(locator), skdm)?,
            Work::Accept { skdm } => self.package_install(store, None, Some(skdm))?,
            Work::Acknowledge(receipt) => {
                let queue = receipt.locator.map(|_| self.key_packages.clone());
                Native::Acknowledge { receipt, queue }
            }
            Work::Reoffer { target, history } => {
                let consented = !history || self.has_consented(store, &target)?;
                let floor = if history && consented {
                    self.entitled_from(&target)
                        .map(|(from, _)| from)
                        .filter(|from| *from < self.sender.chain_id())
                } else {
                    None
                };
                let write_history = floor
                    .is_some_and(|floor| self.history.get(&target).is_none_or(|old| *old >= floor));
                let owed = floor.map(|floor| {
                    self.history
                        .get(&target)
                        .copied()
                        .map_or(floor, |old| old.min(floor))
                });
                Native::LedgerReset {
                    target,
                    floor: owed,
                    delivered: consented && self.delivered.contains_key(&target),
                    write_history,
                    reoffer: true,
                }
            }
            Work::ResetDelivery { target, history } => {
                let floor = if history {
                    self.entitled_from(&target)
                        .map(|(from, _)| from)
                        .filter(|from| *from < self.sender.chain_id())
                } else {
                    None
                };
                let write_history = floor
                    .is_some_and(|floor| self.history.get(&target).is_none_or(|old| *old >= floor));
                Native::LedgerReset {
                    target,
                    floor,
                    delivered: self.delivered.contains_key(&target),
                    write_history,
                    reoffer: false,
                }
            }
        };
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(Prepared {
            pending: Capsule {
                owner,
                room: self.channel_id,
                epoch: self.epoch,
                me: self.me(),
                root: self.genesis.creator_pubkey().fingerprint(),
                membership: self.admission(&self.me()).0,
                now: self.now_hint,
                sek: self.sek.reader(),
                removal_generation,
                pin: Some(pin),
            },
            native,
        })
    }

    fn package_install(
        &self,
        store: &Store,
        locator: Option<(Digest32, u64)>,
        skdm: Option<Box<Skdm>>,
    ) -> Result<Native> {
        let author = skdm.as_ref().map(|skdm| skdm.body.author_id);
        let drive = skdm
            .as_ref()
            .is_some_and(|skdm| skdm.body.channel_id == drive_channel(&self.channel_id));
        let fresh = skdm.as_ref().is_some_and(|skdm| {
            !self
                .receivers
                .contains_key(&(skdm.body.author_id, skdm.body.chain_id))
        });
        let floor_wait = if let Some((author, log_id)) = locator {
            // Selection owns the evidence baseline through Open/Install/Acknowledge.
            // Capturing here would swallow an event that arrived while opening.
            let (revision, generation, membership) =
                self.key_packages.attempt_binding(&author, log_id)?;
            let chain = skdm.as_ref().map_or(u64::MAX, |skdm| skdm.body.chain_id);
            Some((chain, revision, generation, membership))
        } else {
            None
        };
        let selected = (|| {
            let Some(skdm) = skdm else { return Ok(None) };
            if self.is_member_removed(store, &skdm.body.author_id)? {
                return Err(Error::StreamRefused("sender key author is removed"));
            }
            if let Some((author, log)) = locator {
                if author != skdm.body.author_id {
                    return Err(Error::MalformedBundle("key package author differs"));
                }
                let segment = store
                    .get_segment(&self.channel_id, SegmentKind::LogDb, log)?
                    .ok_or(Error::MalformedAtRest("key-package catalog body missing"))?;
                let wire = open_segment(&self.sek, SegmentKind::LogDb, log, &segment)?;
                let entry = Entry::from_wire(&wire)?;
                if entry.skeleton.author_id != author {
                    return Err(Error::StreamRefused("key-package author is not eligible"));
                }
                match self.content_eligibility(store, &entry)? {
                    governance::ContentEligibility::Eligible => {}
                    governance::ContentEligibility::Ineligible => {
                        return Err(Error::StreamRefused("key-package author is not eligible"));
                    }
                    governance::ContentEligibility::Refreshing => {
                        return Err(Error::Profile(governance::REFRESHING));
                    }
                }
                // #1171: old key material for this once-removed node is never installed.
                match self.recipient_body_eligibility(store, &self.me(), &entry)? {
                    governance::ContentEligibility::Eligible => {}
                    governance::ContentEligibility::Ineligible => {
                        return Err(Error::StreamRefused(
                            "key package predates this node's readmission",
                        ));
                    }
                    governance::ContentEligibility::Refreshing => {
                        return Err(Error::Profile(governance::REFRESHING));
                    }
                }
            }
            self.require_legacy_current(store)?;
            let key = self
                .authors
                .get(&skdm.body.author_id)
                .ok_or(Error::MalformedGovernance("SKDM from an unadmitted author"))?
                .clone();
            let receivers = if drive {
                &self.drive.receivers
            } else {
                &self.receivers
            };
            let existing = receivers
                .get(&(skdm.body.author_id, skdm.body.chain_id))
                .map(ReceiverChain::to_state);
            Ok(Some(Receiver {
                skdm,
                key: Box::new(key),
                existing,
                count: receivers.len(),
                normal: if drive {
                    Ok(self.receiver_persistence.normal())
                } else {
                    self.receiver_persistence.next_normal()
                },
                drive_stamp: self.receiver_persistence.drive(),
            }))
        })();
        let selected = match selected {
            Err(error) if governance::refreshing(&error) => return Err(error),
            other => other,
        };
        Ok(Native::Install {
            receipt: Attempt {
                locator,
                accepted: None,
                refusal: None,
                author,
                drive,
                fresh,
                package_pending: self.key_packages.pending(),
                floor_wait,
                floor_baseline: floor_wait,
                floor_resolved: false,
            },
            selected,
        })
    }

    pub(crate) fn finish_pending_package(
        &mut self,
        store: &Store,
        mut completed: Completed,
    ) -> Result<Saved> {
        if !completed.can_install(self, &completed.pending.owner) {
            return completed.result;
        }
        if completed.committed {
            self.entries.committed();
        }
        let mut available = None;
        match completed.delta {
            Delta::Queue(queue) => self.key_packages = queue,
            Delta::Receiver {
                slot,
                chain,
                drive,
                retained,
                changed,
            } => {
                if changed {
                    if drive {
                        self.drive.receivers.insert(slot, *chain);
                        self.drive.told_unheld.remove(&slot.0);
                        self.reset_private_pulls();
                    } else {
                        self.receivers.insert(slot, *chain);
                        if let Err(error) = self.receiver_persistence.advance_normal() {
                            completed.result = Err(error);
                        }
                    }
                }
                if retained {
                    available = Some(slot.0);
                }
            }
            Delta::Reoffer {
                target,
                history,
                delivered,
            } => {
                if delivered {
                    self.delivered.remove(&target);
                }
                if let Some(floor) = history {
                    self.history.insert(target, floor);
                }
            }
            Delta::None => {}
        }
        self.release_pending_text(&completed.pending.owner, false);
        if let Some(author) = available {
            if let Err(error) = self.note_available(store, author) {
                completed.result = Err(error);
            }
        }
        if completed.poison {
            if let Err(error) = &completed.result {
                self.poison(error);
            }
        }
        if let Ok(Saved::DeliveryReset { error: Some(error) }) = &completed.result {
            self.poison(error);
        }
        completed.result
    }
}

impl Prepared {
    pub(crate) fn run(
        self,
        store: &Store,
        signer: &dyn RootSigner,
        now: crate::time::Ms,
    ) -> Completed {
        let Self { pending, native } = self;
        let mut delta = Delta::None;
        let mut committed = false;
        let mut poison = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pending.sek.with(|sek| {
                if let Some(generation) = pending.removal_generation {
                    governance::check_removal_generation(store, sek, &pending.room, generation)?;
                }
                match native {
                    Native::Select {
                        mut queue,
                        heads,
                        trust,
                        context,
                    } => {
                        poison = true;
                        let index = entry_store::EntryIndex::default();
                        let read = index.read(store, sek, &pending.room)?;
                        let progress = queue.next(
                            store,
                            sek,
                            &pending.room,
                            &pending.me,
                            &read,
                            trust,
                            |entry| {
                                Ok(entry.skeleton.channel_id == pending.room
                                    && entry.skeleton.epoch == pending.epoch
                                    && entry.skeleton.seq != 0
                                    && (entry.skeleton.seq
                                        <= heads
                                            .get(&entry.skeleton.author_id)
                                            .copied()
                                            .unwrap_or(0)
                                        || read.history_effect_finished(&entry.entry_hash())?))
                            },
                            (pending.root, pending.now, pending.membership),
                        )?;
                        delta = Delta::Queue(queue);
                        Ok(Saved::Selected { progress, context })
                    }
                    Native::Open {
                        pending,
                        context,
                        ring,
                        trusted,
                        eligible,
                    } => {
                        poison = true;
                        let locator = (pending.author, pending.log_id);
                        let skdm = if !eligible {
                            None
                        } else {
                            match pending.package.initial_message() {
                                Ok(initial) => {
                                    match respond(
                                        &initial,
                                        &context,
                                        &ring,
                                        store,
                                        signer,
                                        now.get(),
                                    )? {
                                        Ok(mut session) => pending
                                            .package
                                            .open(&mut session, now.get())
                                            .ok()
                                            .filter(|skdm| trusted.contains(&skdm.body.author_id))
                                            .map(Box::new),
                                        Err(_) => None,
                                    }
                                }
                                Err(_) => None,
                            }
                        };
                        Ok(Saved::Opened { locator, skdm })
                    }
                    Native::Respond {
                        initial,
                        context,
                        ring,
                    } => respond(&initial, &context, &ring, store, signer, now.get())
                        .map(|response| Saved::Responded(response.map(Box::new))),
                    Native::Initiate {
                        bundle,
                        context,
                        ring,
                        reservation,
                    } => {
                        let ring = ring.blocking_lock();
                        Ok(Saved::Initiated {
                            initiated: crate::pairwise::session::Session::initiate(
                                ring.identity_dh(),
                                &bundle,
                                &context.channel_id,
                                context.epoch,
                                context.suite_id,
                                context.floor,
                            )
                            .ok()
                            .map(|(initial, session)| (Box::new(initial), Box::new(session))),
                            reservation,
                        })
                    }
                    Native::SealOutbound {
                        ring,
                        bundle,
                        context,
                        target,
                        skdm,
                        reservation,
                    } => {
                        let ring = ring.blocking_lock();
                        Ok(Saved::SealedOutbound {
                            package: crate::node::keypackage::KeyPackage::seal(
                                ring.identity_dh(),
                                &bundle,
                                &context,
                                target,
                                &skdm,
                            )
                            .ok(),
                            skdm,
                            removal_generation: pending
                                .removal_generation
                                .ok_or(Error::Profile("key release authorization missing"))?,
                            reservation,
                        })
                    }
                    Native::FrameOutbound {
                        ring,
                        bundle,
                        context,
                        skdm,
                        reservation,
                    } => {
                        let opened = {
                            let ring = ring.blocking_lock();
                            crate::pairwise::session::Session::initiate(
                                ring.identity_dh(),
                                &bundle,
                                &context.channel_id,
                                context.epoch,
                                context.suite_id,
                                context.floor,
                            )
                            .ok()
                        };
                        let frame = opened.and_then(|(initial, mut session)| {
                            let frame = crate::node::pairwise_stream::rotation_hello_frame(
                                &context.channel_id,
                                &initial,
                                &mut session,
                                &skdm,
                            )
                            .ok()?;
                            drop(session);
                            Some(OutboundFrame {
                                opening: crate::hash::sha256(&frame),
                                frame,
                                one_time_prekey: initial.one_time_prekey_id,
                            })
                        });
                        Ok(Saved::FramedOutbound {
                            frame,
                            skdm,
                            reservation,
                        })
                    }
                    Native::Unseal {
                        session,
                        sealed,
                        key,
                    } => {
                        let mut session = session
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                            .ok_or(Error::Profile("pairwise session opening owner changed"))?;
                        let result = if key {
                            crate::node::pairwise_stream::open_skdm(
                                &mut session,
                                &sealed,
                                now.get(),
                            )
                            .map(|skdm| Some(Box::new(skdm)))
                            .map_err(|_| crate::node::pairwise_stream::KeyRefusal::CannotOpen)
                        } else {
                            if let Ok(message) =
                                crate::pairwise::message::Message::from_wire(&sealed)
                            {
                                let _ = session.decrypt(&message, now.get());
                            }
                            Ok(None)
                        };
                        Ok(Saved::Unsealed {
                            session: Box::new(session),
                            result,
                        })
                    }
                    Native::Acknowledge { mut receipt, queue } => {
                        if let (Some((author, log_id)), Some(mut queue)) = (receipt.locator, queue)
                        {
                            poison = true;
                            queue.attempted(
                                store,
                                sek,
                                &pending.room,
                                (&author, log_id),
                                receipt.floor_wait,
                                receipt.floor_resolved,
                            )?;
                            receipt.package_pending = queue.pending();
                            delta = Delta::Queue(queue);
                        }
                        Ok(Saved::Attempted(receipt))
                    }
                    Native::Install {
                        mut receipt,
                        selected,
                    } => {
                        let selected = match selected {
                            Ok(selected) => selected,
                            Err(
                                error @ (Error::Storage { .. }
                                | Error::MalformedAtRest(_)
                                | Error::AtRestUnlockFailed
                                | Error::AtRestLocked),
                            ) => {
                                poison = true;
                                return Err(error);
                            }
                            Err(error) => {
                                receipt.floor_wait = receipt.floor_baseline;
                                receipt.refusal = Some(error);
                                return Ok(Saved::Installed(receipt));
                            }
                        };
                        let Some(selected) = selected else {
                            receipt.floor_wait = receipt.floor_baseline;
                            return Ok(Saved::Installed(receipt));
                        };
                        let mut restored_drive = false;
                        if receipt.drive
                            && selected.skdm.body.iteration
                                >= crate::group::state::ROTATE_AFTER_MESSAGES
                        {
                            receipt.refusal = Some(Error::MalformedBundle(
                                "private drive iteration exceeds rotation bound",
                            ));
                            return Ok(Saved::Installed(receipt));
                        }
                        if receipt.drive {
                            let author = selected.skdm.body.author_id;
                            let snapshot = store.snapshot()?;
                            let view = governance::View::pinned(
                                &snapshot,
                                sek,
                                &pending.room,
                                pending.root,
                                pending.now,
                            )?;
                            let restored = !view.validated_member_removals(&author)?.is_empty()
                                || !view.validated_member_removals(&pending.me)?.is_empty();
                            restored_drive = restored;
                            drop(view);
                            drop(snapshot);
                            if restored {
                                let body = &selected.skdm.body;
                                let key = (author, pending.me, body.epoch, body.chain_id);
                                let floor = session_projection::floor_index::authorized_floor_step(
                                    store,
                                    sek,
                                    &pending.room,
                                    pending.root,
                                    pending.now,
                                    &key,
                                    pending.membership,
                                    true,
                                )?
                                .ok_or(Error::StreamRefused(
                                    session_projection::floor_index::REFRESHING,
                                ))?;
                                if floor.is_none_or(|(_, iteration, _)| body.iteration < iteration)
                                {
                                    if receipt.locator.is_none() {
                                        return Err(Error::StreamRefused(
                                            "drive key lacks restored floor authority",
                                        ));
                                    }
                                    receipt.floor_wait = receipt.floor_baseline;
                                    receipt.refusal = Some(Error::StreamRefused(
                                        "drive key awaits restored floor authority",
                                    ));
                                    return Ok(Saved::Installed(receipt));
                                }
                            }
                        }
                        let binding = if receipt.drive {
                            drive_channel(&pending.room)
                        } else {
                            pending.room
                        };
                        let mut incoming = match ReceiverChain::from_skdm(
                            &selected.skdm,
                            &selected.key,
                            &binding,
                            pending.epoch,
                        ) {
                            Ok(chain) => chain,
                            Err(error) => {
                                receipt.floor_wait = receipt.floor_baseline;
                                receipt.refusal = Some(error);
                                return Ok(Saved::Installed(receipt));
                            }
                        };
                        let existing = selected
                            .existing
                            .as_deref()
                            .map(|state| ReceiverChain::from_state(state))
                            .transpose()?;
                        if !receipt.drive
                            && existing
                                .as_ref()
                                .is_some_and(|chain| chain.epoch() != pending.epoch)
                        {
                            receipt.refusal = Some(Error::OwnHistoryBehind);
                            return Ok(Saved::Installed(receipt));
                        }
                        let (mut candidate, changed, covered) = if let Some(mut existing) = existing
                        {
                            use subtle::ConstantTimeEq;
                            let (iteration, held) = existing.history_release_binding();
                            let covered = if iteration < selected.skdm.body.iteration {
                                // Prove the held earlier release derives this exact
                                // offered body, within MAX_SKIP. Only the temporary
                                // incoming chain changes, never the live receiver.
                                incoming.retain_history_release(&existing).is_ok()
                            } else {
                                iteration == selected.skdm.body.iteration
                                    && bool::from(held.ct_eq(&crate::hash::sha256(
                                        &selected.skdm.body.canonical_body(),
                                    )))
                            };
                            if receipt.drive && !restored_drive {
                                receipt.floor_resolved = covered;
                                receipt.accepted = Some(AcceptedSkdm {
                                    rendered: 0,
                                    changed: false,
                                });
                                return Ok(Saved::Installed(receipt));
                            }
                            let changed = match existing.retain_history_release(&incoming) {
                                Ok(changed) => changed,
                                Err(error) => {
                                    receipt.floor_wait = receipt.floor_baseline;
                                    receipt.refusal = Some(error);
                                    return Ok(Saved::Installed(receipt));
                                }
                            };
                            (existing, changed, covered || changed)
                        } else {
                            let limit = if receipt.drive {
                                crate::node::drive::MAX_DRIVE_CHAINS
                            } else {
                                MAX_RECEIVER_CHAINS
                            };
                            if selected.count >= limit {
                                receipt.refusal =
                                    Some(Error::SizeLimitExceeded(if receipt.drive {
                                        "room drive keys"
                                    } else {
                                        "room receiver chains"
                                    }));
                                return Ok(Saved::Installed(receipt));
                            }
                            (incoming, true, true)
                        };
                        let snapshot = changed.then(|| store.snapshot()).transpose()?;
                        let mut batch = store.batch()?;
                        if let Some(generation) = pending.removal_generation {
                            governance::check_removal_generation_in(
                                &batch,
                                sek,
                                &pending.room,
                                generation,
                            )?;
                        }
                        poison = true;
                        let retained = if receipt.drive {
                            false
                        } else {
                            let existing = selected
                                .existing
                                .as_deref()
                                .map(|state| ReceiverChain::from_state(state))
                                .transpose()?;
                            match receiver_releases::remember(
                                &mut batch,
                                sek,
                                &pending.room,
                                &selected.key,
                                &selected.skdm,
                                existing.as_ref(),
                                &candidate,
                            )? {
                                receiver_releases::Remember::Busy { changed } => {
                                    if changed {
                                        batch.commit()?;
                                        committed = true;
                                    }
                                    poison = false;
                                    receipt.refusal = Some(Error::StreamRefused(
                                        receiver_releases::CLEANUP_PENDING,
                                    ));
                                    return Ok(Saved::Installed(receipt));
                                }
                                receiver_releases::Remember::Unchanged if !changed => {
                                    receipt.floor_resolved = covered;
                                    receipt.accepted = Some(AcceptedSkdm {
                                        rendered: 0,
                                        changed: false,
                                    });
                                    return Ok(Saved::Installed(receipt));
                                }
                                receiver_releases::Remember::Retained => true,
                                _ => false,
                            }
                        };
                        let slot = (selected.skdm.body.author_id, candidate.chain_id());
                        if changed {
                            let snapshot = snapshot
                                .as_ref()
                                .ok_or(Error::Profile("changed receiver snapshot missing"))?;
                            if !receipt.drive {
                                batch.ruled();
                            }
                            if receipt.drive {
                                let mut drive = match snapshot.get_segment(
                                    &pending.room,
                                    SegmentKind::KeyMaterial,
                                    SEG_DRIVE,
                                )? {
                                    Some(sealed) => DriveState::from_state(&open_segment(
                                        sek,
                                        SegmentKind::KeyMaterial,
                                        SEG_DRIVE,
                                        &sealed,
                                    )?)?,
                                    None => DriveState::default(),
                                };
                                drive.receivers.insert(slot, candidate);
                                let sealed = seal_segment(
                                    sek,
                                    SegmentKind::KeyMaterial,
                                    SEG_DRIVE,
                                    &drive.to_state(),
                                )?;
                                batch.put_segment(
                                    &pending.room,
                                    SegmentKind::KeyMaterial,
                                    SEG_DRIVE,
                                    &sealed,
                                )?;
                                receiver_overlay::wrote_drive(
                                    &mut batch,
                                    sek,
                                    &pending.room,
                                    selected.drive_stamp,
                                )?;
                                candidate = drive
                                    .receivers
                                    .remove(&slot)
                                    .ok_or(Error::Profile("selected drive receiver missing"))?;
                            } else {
                                let segment = snapshot.get_segment(
                                    &pending.room,
                                    SegmentKind::KeyMaterial,
                                    SEG_RECEIVERS,
                                )?;
                                let base = receiver_overlay::digest(segment.as_ref());
                                let mut receivers = match segment {
                                    Some(sealed) => parse_receivers(&open_segment(
                                        sek,
                                        SegmentKind::KeyMaterial,
                                        SEG_RECEIVERS,
                                        &sealed,
                                    )?)?,
                                    None => BTreeMap::new(),
                                };
                                receiver_overlay::merge(
                                    snapshot,
                                    sek,
                                    &pending.room,
                                    &pending.me,
                                    pending.epoch,
                                    base,
                                    &mut receivers,
                                )?;
                                let sealed = seal_segment(
                                    sek,
                                    SegmentKind::KeyMaterial,
                                    SEG_RECEIVERS,
                                    &receivers_bytes_with(&receivers, Some((&slot, &candidate))),
                                )?;
                                receiver_overlay::rewrite(
                                    &mut batch,
                                    sek,
                                    &pending.room,
                                    &sealed,
                                    selected.normal?,
                                )?;
                            }
                            let index = entry_store::EntryIndex::default();
                            let mut writer = index.write(&mut batch, sek, &pending.room)?;
                            writer.queue_backfill(slot.0, Some(1))?;
                            writer.seal()?;
                        }
                        batch.commit()?;
                        committed = true;
                        receipt.floor_resolved = covered;
                        if changed || retained {
                            delta = Delta::Receiver {
                                slot,
                                chain: Box::new(candidate),
                                drive: receipt.drive,
                                retained,
                                changed,
                            };
                        }
                        receipt.accepted = Some(AcceptedSkdm {
                            rendered: 0,
                            changed,
                        });
                        Ok(Saved::Installed(receipt))
                    }
                    Native::LedgerReset {
                        target,
                        floor,
                        delivered,
                        write_history,
                        reoffer,
                    } => {
                        poison = true;
                        let history = (SEG_HISTORY, floor, write_history);
                        let live = (SEG_DELIVERED, None, delivered);
                        let ordered = if reoffer {
                            [history, live]
                        } else {
                            [live, history]
                        };
                        let mut last_error = None;
                        let mut saved_history = None;
                        let mut saved_delivered = false;
                        for (segment, value, write) in ordered {
                            if !write {
                                continue;
                            }
                            let saved = (|| -> Result<()> {
                                let mut batch = store.batch()?;
                                if let Some(generation) = pending.removal_generation {
                                    governance::check_removal_generation_in(
                                        &batch,
                                        sek,
                                        &pending.room,
                                        generation,
                                    )?;
                                }
                                let mut values = match batch.get_segment(
                                    &pending.room,
                                    SegmentKind::KeyMaterial,
                                    segment,
                                )? {
                                    Some(sealed) => parse_delivered(&open_segment(
                                        sek,
                                        SegmentKind::KeyMaterial,
                                        segment,
                                        &sealed,
                                    )?)?,
                                    None => BTreeMap::new(),
                                };
                                if let Some(value) = value {
                                    values.insert(target, value);
                                } else {
                                    values.remove(&target);
                                }
                                let sealed = seal_segment(
                                    sek,
                                    SegmentKind::KeyMaterial,
                                    segment,
                                    &delivered_bytes(&values),
                                )?;
                                batch.put_segment(
                                    &pending.room,
                                    SegmentKind::KeyMaterial,
                                    segment,
                                    &sealed,
                                )?;
                                batch.commit()
                            })();
                            match saved {
                                Ok(()) => {
                                    if segment == SEG_HISTORY {
                                        saved_history = value;
                                    } else {
                                        saved_delivered = true;
                                    }
                                    delta = Delta::Reoffer {
                                        target,
                                        history: saved_history,
                                        delivered: saved_delivered,
                                    };
                                }
                                Err(error) if reoffer => return Err(error),
                                Err(error) => {
                                    last_error = Some(error);
                                }
                            }
                        }
                        if reoffer {
                            Ok(Saved::Reoffered)
                        } else {
                            Ok(Saved::DeliveryReset { error: last_error })
                        }
                    }
                }
            })
        }))
        .unwrap_or_else(|_| {
            poison = true;
            Err(Error::Profile("key package save worker stopped"))
        });
        Completed {
            pending,
            delta,
            committed,
            poison,
            result,
        }
    }
}

impl Completed {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.room == channel.channel_id
            && self.pending.epoch == channel.epoch
            && Arc::ptr_eq(owner, &self.pending.owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.pin.take()
    }
    pub(crate) fn into_result(self) -> Result<Saved> {
        match self.result? {
            Saved::DeliveryReset { error: Some(error) } => Err(error),
            saved => Ok(saved),
        }
    }
}

fn respond(
    initial: &crate::pairwise::InitialMessage,
    context: &crate::join::session::JoinContext,
    ring: &tokio::sync::Mutex<crate::node::prekeys::PrekeyRing>,
    store: &Store,
    signer: &dyn RootSigner,
    now: u64,
) -> Result<
    std::result::Result<
        crate::pairwise::session::Session,
        crate::node::pairwise_stream::KeyRefusal,
    >,
> {
    use crate::node::pairwise_stream::KeyRefusal;
    use crate::node::prekeys::{self, OneTimeUse};
    let mut reuse = crate::pairwise::OtpReuseTracker::new();
    let mut ring = ring.blocking_lock();
    if let Some(id) = initial.one_time_prekey_id {
        match ring.use_one_time(id, now) {
            OneTimeUse::Fresh => {}
            OneTimeUse::Reused => {
                reuse.observe(id);
            }
            OneTimeUse::Unknown => return Ok(Err(KeyRefusal::UnknownPrekey)),
        }
        prekeys::save(store, signer, &ring)?;
    }
    let Some(signed_prekey) = ring.signed_prekey_for(initial.signed_prekey_id) else {
        return Ok(Err(KeyRefusal::HelloRefused));
    };
    let one_time_prekey = initial
        .one_time_prekey_id
        .and_then(|id| ring.consumed_one_time(id));
    let prekeys = crate::pairwise::ResponderPrekeys {
        identity_dh_key: ring.identity_dh(),
        signed_prekey,
        one_time_prekey,
    };
    Ok(crate::pairwise::session::Session::accept(
        initial,
        &prekeys,
        &context.channel_id,
        context.epoch,
        &mut reuse,
        context.floor,
    )
    .map_err(|_| KeyRefusal::HelloRefused))
}
