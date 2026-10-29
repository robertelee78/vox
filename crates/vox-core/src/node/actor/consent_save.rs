//! Preparation/physical execution/install adapter for the existing retained save dispatcher.
//! This module deliberately owns no second queue, authority admission or wake convention.
use super::*;
use crate::atrest::vault::VaultRootSigner;
use crate::node::channel::pending_cleanup::{CompletedCleanup, PendingCleanup};
use crate::node::channel::pending_control::{
    CompletedImport, CompletedSupport, PendingImport, PendingSupport,
};
use crate::node::channel::pending_text::consent::{CompletedConsent, ConsentSaved, PendingConsent};
use crate::node::channel::pending_text::consent_delivery::{CompletedDelivery, PendingDelivery};
use crate::node::channel::pending_text::held_consent::{CompletedHeld, HeldConsent, PendingHeld};
use crate::node::store::Store;

pub(super) enum Work {
    Hold {
        target: Digest32,
        skdm: Box<crate::group::skdm::Skdm>,
    },
    Delivered {
        target: Digest32,
        generation: u64,
        history: bool,
    },
    Issue {
        target: Digest32,
        skdm: Box<crate::group::skdm::Skdm>,
        full_history: bool,
        entitled_from: (u64, u64),
        package: Option<crate::node::keypackage::KeyPackage>,
    },
    Withdraw {
        target: Digest32,
    },
    ReceiverCleanup,
    ControlImport,
    PrivateSupport {
        discovery_ready: bool,
    },
}

pub(super) enum Prepared {
    Hold(PendingHeld, Digest32),
    Delivered(PendingDelivery),
    Issue(PendingConsent),
    Consent(PendingConsent),
    Cleanup(PendingCleanup),
    Import(PendingImport),
    Support(PendingSupport),
}

pub(super) enum Completed {
    Hold(CompletedHeld),
    Delivered(CompletedDelivery),
    Issue(CompletedConsent),
    Consent(CompletedConsent),
    Cleanup(CompletedCleanup),
    Import(CompletedImport),
    Support(CompletedSupport),
}

pub(super) enum Effect {
    Held(HeldConsent),
    Delivered,
    Publication {
        result: crate::error::Result<ConsentSaved>,
        package_seq: Option<u64>,
        consent_seq: Option<u64>,
        package: Option<crate::node::keypackage::KeyPackage>,
        release: Option<Box<crate::group::skdm::Skdm>>,
    },
    Consent(ConsentSaved),
    Cleanup {
        more: bool,
        retry_ready: bool,
        own_retry_ready: bool,
    },
    ControlImport,
    PrivateSupport(bool),
}

pub(super) struct Receipt {
    pub(super) result: crate::error::Result<Effect>,
    pub(super) held: Option<(Digest32, Digest32)>,
}

impl Work {
    /// Called only after the original ComputerPublication is asynchronously acquired.
    pub(super) fn prepare(
        self,
        channel: &mut ChannelState,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> crate::error::Result<Option<Prepared>> {
        match self {
            Self::Hold { target, skdm } => channel
                .prepare_pending_held_consent(store, owner, skdm)
                .map(|pending| Some(Prepared::Hold(pending, target))),
            Self::Delivered {
                target,
                generation,
                history,
            } => channel
                .prepare_pending_consent_delivery(store, owner, target, generation, history)
                .map(|pending| Some(Prepared::Delivered(pending))),
            Self::Issue {
                target,
                skdm,
                full_history,
                entitled_from,
                package,
            } => channel
                .prepare_pending_consent(
                    store,
                    owner,
                    target,
                    skdm,
                    full_history,
                    entitled_from,
                    package,
                    now,
                )
                .map(|pending| Some(Prepared::Issue(pending))),
            Self::Withdraw { target } => channel
                .prepare_pending_withdrawal(store, owner, target, now)
                .map(|pending| Some(Prepared::Consent(pending))),
            Self::ReceiverCleanup => channel
                .prepare_pending_receiver_cleanup(store, owner)
                .map(|pending| pending.map(Prepared::Cleanup)),
            Self::ControlImport => channel
                .prepare_pending_control_import(store, owner)
                .map(|pending| pending.map(Prepared::Import)),
            Self::PrivateSupport { discovery_ready } => channel
                .prepare_pending_private_support(store, owner, now, discovery_ready)
                .map(|pending| pending.map(Prepared::Support)),
        }
    }
}

impl Prepared {
    /// The room guard must have been dropped before this call on the physical save worker.
    pub(super) fn run(self, store: &Store, signer: &VaultRootSigner) -> Completed {
        match self {
            Self::Hold(pending, target) => Completed::Hold(pending.run(store, signer, target)),
            Self::Delivered(pending) => Completed::Delivered(pending.run(store)),
            Self::Issue(pending) => Completed::Issue(pending.run(store, signer)),
            Self::Consent(pending) => Completed::Consent(pending.run(store, signer)),
            Self::Cleanup(pending) => Completed::Cleanup(pending.run(store)),
            Self::Import(pending) => Completed::Import(pending.run(store)),
            Self::Support(pending) => Completed::Support(pending.run(store, signer)),
        }
    }
}

impl Completed {
    pub(super) fn package_confirmed(&self) -> bool {
        matches!(self, Self::Issue(completed) if completed.package_seq.is_some() && completed.package.is_some())
    }

    pub(super) fn package_unconfirmed(&self) -> bool {
        matches!(self, Self::Issue(completed) if completed.package_unconfirmed())
    }

    pub(super) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        match self {
            Self::Hold(completed) => completed.can_install(channel, owner),
            Self::Delivered(completed) => completed.can_install(channel, owner),
            Self::Issue(completed) => completed.can_install(channel, owner),
            Self::Consent(completed) => completed.can_install(channel, owner),
            Self::Cleanup(completed) => completed.can_install(channel, owner),
            Self::Import(completed) => completed.can_install(channel, owner),
            Self::Support(completed) => completed.can_install(channel, owner),
        }
    }

    pub(super) fn take_history_pin(
        &mut self,
    ) -> Option<crate::node::channel::history::PendingHistoryRead> {
        match self {
            Self::Hold(completed) => completed.take_history_pin(),
            Self::Delivered(completed) => completed.take_history_pin(),
            Self::Issue(completed) => completed.take_history_pin(),
            Self::Consent(completed) => completed.take_history_pin(),
            Self::Cleanup(completed) => completed.take_history_pin(),
            Self::Import(completed) => completed.take_history_pin(),
            Self::Support(completed) => completed.take_history_pin(),
        }
    }

    /// The common completion owner checks attachment epoch and exact SharedChannel first,
    /// retains the original publication lease, then publishes the saved-history view.
    pub(super) fn finish(self, channel: &mut ChannelState, store: &Store) -> Receipt {
        let mut held = None;
        let result = match self {
            Self::Hold(completed) => channel
                .finish_pending_held_consent(completed)
                .map(Effect::Held),
            Self::Delivered(completed) => channel
                .finish_pending_consent_delivery(completed)
                .map(|()| Effect::Delivered),
            Self::Issue(mut completed) => {
                held = completed.held.take();
                let package_seq = completed.package_seq;
                let consent_seq = completed.consent_seq;
                let package = completed.package.take();
                let release = completed.release.take();
                let result = channel.finish_pending_consent(store, completed);
                Ok(Effect::Publication {
                    result,
                    package_seq,
                    consent_seq,
                    package,
                    release,
                })
            }
            Self::Consent(mut completed) => {
                held = completed.held.take();
                channel
                    .finish_pending_consent(store, completed)
                    .map(Effect::Consent)
            }
            Self::Cleanup(completed) => channel.finish_pending_receiver_cleanup(completed).map(
                |(more, retry_ready, own_retry_ready)| Effect::Cleanup {
                    more,
                    retry_ready,
                    own_retry_ready,
                },
            ),
            Self::Import(completed) => channel
                .finish_pending_control_import(completed)
                .map(|_| Effect::ControlImport),
            Self::Support(completed) => channel
                .finish_pending_private_support(store, completed)
                .map(Effect::PrivateSupport),
        };
        Receipt { result, held }
    }

    /// Stale attachments never enqueue key bytes or install a component. Preserve the real
    /// durable result for the retained caller; the detached room is released by its owner.
    pub(super) fn into_result(self) -> crate::error::Result<Effect> {
        match self {
            Self::Hold(completed) => completed.result.map(Effect::Held),
            Self::Delivered(completed) => completed.result.map(|()| Effect::Delivered),
            Self::Issue(completed) => Ok(Effect::Publication {
                result: completed.result,
                package_seq: completed.package_seq,
                consent_seq: completed.consent_seq,
                package: completed.package,
                release: completed.release,
            }),
            Self::Consent(completed) => completed.result.map(Effect::Consent),
            Self::Cleanup(completed) => {
                completed
                    .result
                    .map(|(more, retry_ready, own_retry_ready)| Effect::Cleanup {
                        more,
                        retry_ready,
                        own_retry_ready,
                    })
            }
            Self::Import(completed) => completed.result.map(|_| Effect::ControlImport),
            Self::Support(completed) => completed.into_result().map(Effect::PrivateSupport),
        }
    }
}
