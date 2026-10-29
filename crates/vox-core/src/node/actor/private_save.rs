//! Private component work uses the common retained save slot and its exact publication owner.
use super::*;
use crate::node::channel::{pending_control, pending_retention, pending_upgrade};
use crate::node::channel::{CompletedAnnouncement, PendingAnnouncement};
use crate::node::history_demand::{Bounds, PrivatePlan};
use crate::node::sessionstream::{Ask, Page};
use crate::node::store::Store;

type Native = pending_upgrade::Saved;
type Result<T, E = crate::error::Error> = std::result::Result<T, E>;

pub(super) enum Work {
    Upgrade {
        finish_initial: bool,
    },
    LegacyMigration,
    Import,
    Expiry,
    ScheduleReplay,
    AnnounceLegacy,
    Serve {
        ask: Ask,
        peer: Digest32,
        holders: BTreeSet<Digest32>,
        charge: crate::node::history_budget::BufferCharge,
        guard: history_demand::CurrentPrivateGuard,
    },
    Live {
        peer: Digest32,
        revision: u64,
        page: Result<Page>,
        received_at: u64,
        guard: history_demand::CurrentPrivateGuard,
    },
    Archive {
        bounds: Bounds,
        plan: PrivatePlan,
        page: Box<Page>,
        nonce: Option<[u8; crate::atrest::sek::NONCE_LEN]>,
        guard: history_demand::PrivateGuard,
    },
    Flow {
        flow: Box<pending_upgrade::PageFlow>,
        guard: FlowGuard,
    },
}

pub(super) enum Saved {
    Upgrade(Box<Native>),
    UpgradeComplete,
    UpgradeWaiting,
    Migration,
    MigrationSkipped,
    ControlImport,
    PrivateExpiry,
    Imported,
    Expired,
    Announcement { count: usize, complete: bool },
    Page(Page),
    Flow(Box<pending_upgrade::PageFlow>),
    PageFinished(pending_upgrade::PageResult),
}

pub(super) enum NativeKind {
    Upgrade,
    Migration,
    Serve,
    Flow(Box<pending_upgrade::PageFlow>),
}

#[derive(Clone)]
pub(super) enum FlowGuard {
    Live {
        guard: history_demand::CurrentPrivateGuard,
        initial: bool,
    },
    Archive {
        guard: history_demand::PrivateGuard,
        initial: bool,
    },
}
impl FlowGuard {
    fn prepare(&self, channel: &ChannelState, store: &Store) -> Result<()> {
        if let Self::Archive {
            guard,
            initial: true,
        } = self
        {
            guard.check(channel, store).map_err(Error::AppRefused)?;
        }
        Ok(())
    }
    fn boundary(&self, epoch: u64, finished: bool) -> Boundary {
        match self {
            Self::Live { guard, initial } => Boundary::Current {
                guard: guard.clone(),
                before: *initial,
                after: false,
            },
            Self::Archive { guard, initial } => Boundary::Archive {
                guard: guard.clone(),
                epoch,
                before: *initial,
                after: finished,
            },
        }
    }
}

pub(super) enum Boundary {
    Current {
        guard: history_demand::CurrentPrivateGuard,
        before: bool,
        after: bool,
    },
    Archive {
        guard: history_demand::PrivateGuard,
        epoch: u64,
        before: bool,
        after: bool,
    },
}
impl Boundary {
    fn check(&self, store: &Store, after_work: bool) -> Result<()> {
        match self {
            Self::Current {
                guard,
                before,
                after,
            } if if after_work { *after } else { *before } => guard.check_native(store),
            Self::Archive {
                guard,
                epoch,
                before,
                after,
            } if if after_work { *after } else { *before } => {
                guard.check_native(store, *epoch).map_err(Error::AppRefused)
            }
            _ => Ok(()),
        }
    }
}

pub(super) enum Prepared {
    Native {
        pending: Box<pending_upgrade::PendingUpgrade>,
        kind: NativeKind,
        boundary: Option<Boundary>,
    },
    Import(pending_control::PendingImport),
    Expiry(Box<pending_retention::PendingRetention>),
    Announcement(Box<PendingAnnouncement>),
    Ready {
        saved: Saved,
        boundary: Option<Boundary>,
    },
}
pub(super) enum Completed {
    Native {
        completed: pending_upgrade::CompletedUpgrade,
        kind: NativeKind,
    },
    Import(pending_control::CompletedImport),
    Expiry(pending_retention::CompletedRetention),
    Announcement(Box<CompletedAnnouncement>),
    Ready(Result<Saved>),
}

impl Work {
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> Result<Option<Prepared>> {
        let ready = |saved| {
            Some(Prepared::Ready {
                saved,
                boundary: None,
            })
        };
        Ok(match self {
            Self::Upgrade { finish_initial } => {
                match channel.prepare_pending_private_upgrade(store, owner, now, finish_initial)? {
                    pending_upgrade::Preparation::Work(pending) => Some(Prepared::Native {
                        pending,
                        kind: NativeKind::Upgrade,
                        boundary: None,
                    }),
                    pending_upgrade::Preparation::ControlImport => ready(Saved::ControlImport),
                    pending_upgrade::Preparation::PrivateExpiry => ready(Saved::PrivateExpiry),
                    pending_upgrade::Preparation::Waiting => ready(Saved::UpgradeWaiting),
                    pending_upgrade::Preparation::Complete => ready(Saved::UpgradeComplete),
                }
            }
            Self::LegacyMigration => {
                match channel.prepare_pending_legacy_migration(store, owner, now)? {
                    Some(pending) => Some(Prepared::Native {
                        pending,
                        kind: NativeKind::Migration,
                        boundary: None,
                    }),
                    None => ready(Saved::MigrationSkipped),
                }
            }
            Self::Import => channel
                .prepare_pending_control_import(store, owner)?
                .map(Prepared::Import),
            Self::Expiry => channel
                .prepare_pending_retention(
                    store,
                    owner,
                    pending_retention::Step::PrivateExpiry,
                    now,
                )?
                .map(|pending| Prepared::Expiry(Box::new(pending))),
            Self::ScheduleReplay => Some(Prepared::Native {
                pending: channel.prepare_pending_private_replay(store, owner, now)?,
                kind: NativeKind::Upgrade,
                boundary: None,
            }),
            Self::AnnounceLegacy => {
                match channel.prepare_pending_legacy_announcement(store, owner, now)? {
                    Some(pending) => Some(Prepared::Announcement(Box::new(pending))),
                    None => ready(Saved::Announcement {
                        count: 0,
                        complete: true,
                    }),
                }
            }
            Self::Serve {
                ask,
                peer,
                holders,
                charge,
                guard,
            } => Some(Prepared::Native {
                pending: channel
                    .prepare_pending_private_page(store, owner, ask, peer, &holders, charge)?,
                kind: NativeKind::Serve,
                boundary: Some(Boundary::Current {
                    guard,
                    before: true,
                    after: true,
                }),
            }),
            Self::Live {
                peer,
                revision,
                page,
                received_at,
                guard,
            } => {
                let flow = pending_upgrade::PageFlow::live(
                    channel,
                    store,
                    peer,
                    revision,
                    page,
                    received_at,
                    guard.nonce,
                )?;
                Self::Flow {
                    flow: Box::new(flow),
                    guard: FlowGuard::Live {
                        guard,
                        initial: true,
                    },
                }
                .prepare(channel, store, owner, now)?
            }
            Self::Archive {
                bounds,
                plan,
                page,
                nonce,
                guard,
            } => {
                guard.check(channel, store).map_err(Error::AppRefused)?;
                let flow =
                    pending_upgrade::PageFlow::archive(channel, store, bounds, plan, *page, nonce)?;
                Self::Flow {
                    flow: Box::new(flow),
                    guard: FlowGuard::Archive {
                        guard,
                        initial: true,
                    },
                }
                .prepare(channel, store, owner, now)?
            }
            Self::Flow { mut flow, guard } => {
                guard.prepare(channel, store)?;
                let epoch = channel.epoch();
                match flow.prepare(channel, store, owner.clone(), now)? {
                    pending_upgrade::PagePreparation::Work(pending) => Some(Prepared::Native {
                        pending,
                        kind: NativeKind::Flow(flow),
                        boundary: Some(guard.boundary(epoch, false)),
                    }),
                    pending_upgrade::PagePreparation::Finished(result) => Some(Prepared::Ready {
                        saved: Saved::PageFinished(result),
                        boundary: Some(guard.boundary(epoch, true)),
                    }),
                }
            }
        })
    }
}

impl Prepared {
    pub(super) fn run(
        self,
        store: &Store,
        signer: &dyn crate::identity::composite::RootSigner,
    ) -> Completed {
        match self {
            Self::Native {
                pending,
                kind,
                boundary,
            } => {
                let mut completed = match boundary
                    .as_ref()
                    .map(|boundary| boundary.check(store, false))
                    .transpose()
                {
                    Ok(_) => pending.run(store),
                    Err(error) => pending.refused(error),
                };
                if completed.result.is_ok() {
                    if let Some(boundary) = boundary {
                        if let Err(error) = boundary.check(store, true) {
                            completed.result = Err(error);
                        }
                    }
                }
                Completed::Native { completed, kind }
            }
            Self::Import(pending) => Completed::Import(pending.run(store)),
            Self::Expiry(pending) => Completed::Expiry(pending.save(store)),
            Self::Announcement(pending) => {
                Completed::Announcement(Box::new(pending.run(store, signer)))
            }
            Self::Ready { saved, boundary } => Completed::Ready(match boundary {
                Some(boundary) => boundary
                    .check(store, false)
                    .and_then(|_| boundary.check(store, true))
                    .map(|_| saved),
                None => Ok(saved),
            }),
        }
    }
}

impl Completed {
    pub(super) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        match self {
            Self::Native { completed, .. } => completed.can_install(channel, owner),
            Self::Import(completed) => completed.can_install(channel, owner),
            Self::Expiry(completed) => completed.can_install(channel, owner),
            Self::Announcement(completed) => completed.can_install(channel, owner),
            Self::Ready(_) => true,
        }
    }
    pub(super) fn take_history_pin(
        &mut self,
    ) -> Option<crate::node::channel::history::PendingHistoryRead> {
        match self {
            Self::Native { completed, .. } => completed.take_history_pin(),
            Self::Import(completed) => completed.take_history_pin(),
            Self::Expiry(completed) => completed.take_history_pin(),
            Self::Announcement(completed) => completed.take_history_pin(),
            Self::Ready(_) => None,
        }
    }
    pub(super) fn finish(self, channel: &mut ChannelState, store: &Store) -> Result<Saved> {
        match self {
            Self::Native { completed, kind } => {
                native_saved(channel.finish_pending_private_upgrade(completed)?, kind)
            }
            Self::Import(completed) => channel
                .finish_pending_control_import(completed)
                .map(|_| Saved::Imported),
            Self::Expiry(completed) => channel
                .finish_pending_retention(store, completed)
                .map(|_| Saved::Expired),
            Self::Announcement(completed) => channel
                .finish_pending_legacy_announcement(store, *completed)
                .map(|(count, complete)| Saved::Announcement { count, complete }),
            Self::Ready(result) => result,
        }
    }
    pub(super) fn into_result(self) -> Result<Saved> {
        match self {
            Self::Native { completed, kind } => native_saved(completed.result?, kind),
            Self::Import(completed) => completed.result.map(|_| Saved::Imported),
            Self::Expiry(completed) => completed.result.map(|_| Saved::Expired),
            Self::Announcement(completed) => completed
                .into_result()
                .map(|(count, complete)| Saved::Announcement { count, complete }),
            Self::Ready(result) => result,
        }
    }
}
fn native_saved(mut saved: Native, kind: NativeKind) -> Result<Saved> {
    match kind {
        NativeKind::Upgrade => Ok(Saved::Upgrade(Box::new(saved))),
        NativeKind::Migration => Ok(Saved::Migration),
        NativeKind::Serve => saved
            .page
            .take()
            .map(Saved::Page)
            .ok_or(Error::Profile("native private page receipt missing")),
        NativeKind::Flow(mut flow) => {
            flow.accept(saved)?;
            Ok(Saved::Flow(flow))
        }
    }
}

mod continuation;
pub(super) use continuation::{ArchiveReceipt, Continuation};
