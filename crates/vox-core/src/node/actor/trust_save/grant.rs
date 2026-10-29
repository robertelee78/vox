//! Ordinary/manual and automatic local keyring changes share one admitted native transaction.
use super::*;

pub(crate) enum GrantChange {
    Trust {
        target: Digest32,
        petname: String,
        history: HistoryGrant,
        capability: Option<Capability>,
    },
    Capability {
        target: Digest32,
        capability: Capability,
    },
    Rename {
        target: Digest32,
        petname: String,
    },
    Local {
        target: Digest32,
        name: String,
        capability: Capability,
    },
}
impl GrantChange {
    pub(in crate::node::actor) fn target(&self) -> Digest32 {
        match self {
            Self::Trust { target, .. }
            | Self::Capability { target, .. }
            | Self::Rename { target, .. }
            | Self::Local { target, .. } => *target,
        }
    }
    pub(in crate::node::actor) fn individual_choice(&self) -> bool {
        matches!(self, Self::Trust { .. } | Self::Capability { .. })
    }
    pub(in crate::node::actor) fn needs_decision(&self, trust: &Keyring) -> bool {
        match self {
            Self::Trust { target, .. } => !trust.is_trusted(target),
            Self::Local { target, .. } => {
                !trust.is_trusted(target) && !trust.local_removals().contains(target)
            }
            _ => false,
        }
    }
}

pub(crate) struct GrantSaved {
    pub(in crate::node::actor) target: Digest32,
    pub(in crate::node::actor) newly: bool,
    pub(in crate::node::actor) decision: Option<Stamp>,
    pub(in crate::node::actor) announce_support: bool,
    pub(in crate::node::actor) capability_only: bool,
}

pub(super) fn run(
    change: GrantChange,
    floor: u64,
    store: &Store,
    signer: &VaultRootSigner,
) -> crate::error::Result<PolicySaved> {
    let mut batch = store.batch()?;
    let mut trust = Keyring::load(store, signer)?;
    let target = change.target();
    let was = trust.is_trusted(&target);
    let had_drive = trust.has_drive(&target);
    let capability_only = matches!(&change, GrantChange::Capability { .. });
    match change {
        GrantChange::Trust {
            petname,
            history,
            capability,
            ..
        } => {
            let capability = capability
                .or_else(|| trust.capability(&target))
                .unwrap_or_default();
            trust.trust_as(target, &petname, history, capability)?;
        }
        GrantChange::Capability { capability, .. } => {
            if !trust.set_capability(&target, capability) {
                return Err(Error::Profile("identity is not trusted"));
            }
        }
        GrantChange::Rename { petname, .. } => {
            let capability = trust
                .capability(&target)
                .ok_or(Error::Profile("identity is not trusted"))?;
            let history = trust.history(&target);
            trust.trust_as(target, &petname, history, capability)?;
        }
        GrantChange::Local {
            name, capability, ..
        } => {
            if !trust.local_history_imported() {
                return Err(Error::Profile("local trust history has not been imported"));
            }
            if trust.local_removals().contains(&target)
                || trust
                    .capability(&target)
                    .is_some_and(|held| held >= capability)
            {
                return Ok(PolicySaved {
                    trust,
                    removed: Vec::new(),
                    changed_drive: Vec::new(),
                    grant: None,
                });
            }
            let name = trust.petname(&target).unwrap_or(&name).to_owned();
            let history = if was {
                trust.history(&target)
            } else {
                HistoryGrant::Now
            };
            trust.trust_as(target, &name, history, capability)?;
        }
    }
    // The stamp and keyring cannot be separated by a crash. Read order and locks only AFTER
    // writer admission; room-held deletion completions cannot be lost to an old replacement map.
    let changes = if !was {
        ConsentOrder::queue_policy(&mut batch, signer, &[], &[target], floor)?
    } else {
        Vec::new()
    };
    if !capability_only {
        let mut locks = PendingLocks::load(store, signer)?;
        if locks.forget(&target) {
            locks.queue_save(&mut batch, signer)?;
        }
    }
    trust.queue_save(&mut batch, signer)?;
    batch.commit()?;
    let grant = GrantSaved {
        target,
        newly: !was,
        decision: changes
            .iter()
            .find_map(|(peer, stamp)| (*peer == target).then_some(*stamp)),
        announce_support: capability_only || !was || trust.has_drive(&target) != had_drive,
        capability_only,
    };
    Ok(PolicySaved {
        trust,
        removed: Vec::new(),
        changed_drive: vec![(target, had_drive)],
        grant: Some(grant),
    })
}
