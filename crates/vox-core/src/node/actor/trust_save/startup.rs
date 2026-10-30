//! Startup keeps the actual Profile off actor until binding and policy really settle.
use super::*;

pub(crate) struct StartupPolicy {
    pub(in crate::node::actor) trust: Keyring,
    pub(in crate::node::actor) consent_keys: PendingConsents,
    pub(in crate::node::actor) revision: u64,
    pub(in crate::node::actor) expired: bool,
}

/// Native worker only; no live rooms exist. The caller retains the SAME exclusive transition
/// through Profile install and its real Ready/network continuation. No reader is acquired here.
pub(in crate::node::actor) fn settle_startup_policy(
    computer: Option<&Arc<crate::node::computer::Computer>>,
    profile: &Profile,
    name: &str,
    transition: Option<&Arc<crate::node::computer::ComputerPublicationTransition>>,
    observation_end: std::time::Instant,
) -> crate::error::Result<StartupPolicy> {
    let signer = profile.signer()?;
    let store = profile.store();
    let mut trust = Keyring::load(store, signer)?;
    let (mut revision, mut expired) = (0, false);
    if let Some(computer) = computer {
        let transition = transition.ok_or(Error::Profile(
            "startup policy has no original exclusive transition",
        ))?;
        loop {
            let change = crate::node::computer::ComputerChange::at(
                computer.policy_target(),
                observation_end,
                observation_end,
            );
            let guard = computer::ComputerPolicyGuard {
                change,
                superseded: Arc::new(computer::PolicySupersession::default()),
            };
            let attempt = (|| -> crate::error::Result<(u64, bool)> {
                // This is the original may_replace_expired=true startup binding, deliberately
                // unlike ordinary live reconciliation's expired-binding refusal.
                if computer.binding_group().is_some()
                    && !computer.bind_node_for_change(signer, name, change, transition)?
                {
                    return Err(Error::ComputerPolicySuperseded);
                }
                guard.active(Some(computer))?;
                computer.require_startup_binding(profile.fingerprint(), change.target())?;
                if !computer.grouped() {
                    return Ok((
                        computer.policy_revision(),
                        computer.current_revision_expired(),
                    ));
                }
                let Some(plan) = computer.plan(profile.fingerprint())? else {
                    return Ok((
                        computer.policy_revision(),
                        computer.current_revision_expired(),
                    ));
                };
                let aliases = plan
                    .grants
                    .iter()
                    .map(|(peer, _, _)| peer)
                    .chain(plan.denied.iter())
                    .filter_map(|peer| trust.petname(peer).map(|alias| (*peer, alias.to_owned())))
                    .collect();
                let native = Managed {
                    computer: Arc::clone(computer),
                    guard: guard.clone(),
                    transition: Arc::clone(transition),
                    plan,
                    aliases,
                    floor: 0,
                    node: profile.fingerprint(),
                    node_name: name.to_owned(),
                }
                .run(store, signer);
                if let Some(saved) = native.committed {
                    trust = saved.trust;
                }
                let settled = native.result?;
                guard.active(Some(computer))?;
                if !settled {
                    return Err(Error::ComputerPolicySuperseded);
                }
                computer.require_startup_binding(profile.fingerprint(), change.target())?;
                if computer.grouped() && std::time::Instant::now() >= observation_end {
                    computer.record_application_miss_with_transition(
                        profile.fingerprint(),
                        change,
                        Some(transition),
                    )?;
                }
                Ok((native.revision, native.expired))
            })();
            match attempt {
                Err(Error::ComputerPolicySuperseded) => continue,
                Err(error) => return Err(error),
                Ok(applied) => {
                    (revision, expired) = applied;
                    break;
                }
            }
        }
    }
    // The kernel can durably remove held keys. Never install an earlier startup snapshot of
    // that global map after its real policy commit. Admission precedes this final metadata read.
    let _admission = store.batch()?;
    let consent_keys = PendingConsents::load(store, signer)?;
    Ok(StartupPolicy {
        trust,
        consent_keys,
        revision,
        expired,
    })
}

/// The headless constructor is already a native host, but still needs the original physical
/// Computer boundary and actual binding/application receipts before its network becomes Ready.
pub(in crate::node::actor) fn settle_headless_startup_policy(
    computer: Option<&Arc<crate::node::computer::Computer>>,
    signer: &crate::identity::composite::SoftwareRootSigner,
    name: &str,
    transition: Option<&Arc<crate::node::computer::ComputerPublicationTransition>>,
    observation_end: std::time::Instant,
) -> crate::error::Result<(u64, bool)> {
    use crate::identity::composite::RootSigner as _;
    let Some(computer) = computer else {
        return Ok((0, false));
    };
    let transition = transition.ok_or(Error::Profile(
        "headless startup lost its original transition",
    ))?;
    loop {
        let change = crate::node::computer::ComputerChange::at(
            computer.policy_target(),
            observation_end,
            observation_end,
        );
        let guard = computer::ComputerPolicyGuard {
            change,
            superseded: Arc::new(computer::PolicySupersession::default()),
        };
        let (committed, result) =
            apply_headless_policy(computer, signer, name, transition, &guard, true);
        match result {
            Err(Error::ComputerPolicySuperseded) => continue,
            Err(error) => return Err(error),
            Ok(()) => {
                if computer.grouped() && std::time::Instant::now() >= observation_end {
                    computer.record_application_miss_with_transition(
                        signer.fingerprint(),
                        change,
                        Some(transition),
                    )?;
                }
                return committed.ok_or(Error::Profile(
                    "headless startup has no application receipt",
                ));
            }
        }
    }
}

/// Canonical native headless kernel, shared by constructor startup and the retained live owner.
/// `committed` survives a later causal-guard error: the live owner installs only that actual
/// receipt, never a projection inferred from scheduling or from the current Computer snapshot.
pub(in crate::node::actor) fn apply_headless_policy(
    computer: &Arc<crate::node::computer::Computer>,
    signer: &crate::identity::composite::SoftwareRootSigner,
    name: &str,
    transition: &Arc<crate::node::computer::ComputerPublicationTransition>,
    guard: &computer::ComputerPolicyGuard,
    startup: bool,
) -> (Option<(u64, bool)>, crate::error::Result<()>) {
    use crate::identity::composite::RootSigner as _;
    let node = signer.fingerprint();
    let mut committed = None;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        loop {
            guard.active(Some(computer))?;
            computer.storage_ready()?;
            let change = guard.change;
            let deadline = change.apply_deadline();
            if computer.binding_group().is_some()
                && (startup || !computer.current_revision_expired())
                && !computer.bind_node_for_change(signer, name, change, transition)?
            {
                return Err(Error::ComputerPolicySuperseded);
            }
            if startup {
                computer.require_startup_binding(node, change.target())?;
            }
            guard.active(Some(computer))?;
            let revision = computer.policy_revision();
            let expired = computer.current_revision_expired();
            let receipt = if !computer.grouped() {
                crate::node::computer::ApplicationReceipt::Current
            } else if expired {
                computer.mark_expired_until(node, revision, deadline, transition)?
            } else if !computer.applied(&node, revision) {
                computer.mark_applied_until(node, revision, &[], deadline, Some(transition))?
            } else {
                crate::node::computer::ApplicationReceipt::Current
            };
            if receipt == crate::node::computer::ApplicationReceipt::Current {
                committed = Some((revision, expired));
                if startup {
                    computer.require_startup_binding(node, change.target())?;
                }
                return guard.active(Some(computer));
            }
            // Only the real Reconcile receipt repeats, under this same original owner and guard.
        }
    }))
    .unwrap_or_else(|_| Err(Error::Profile("headless policy worker stopped")));
    (committed, result)
}
