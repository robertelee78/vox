//! Native trust command admission and durable decision replies. Room work uses governance.
use super::*;
use crate::node::actor::trust_save::{GrantChange, GrantSaved};
use crate::node::trust::Capability;

pub(crate) enum GrantCommand {
    Trust,
    Capability,
    Rename,
}

pub(crate) enum GrantSource {
    Command(GrantCommand),
    Local { capability: Capability },
}

impl Node {
    /// Called by the original command loop after its Computer journal admission. The fixed-policy
    /// and passphrase checks are the same original command checks, before any native effect.
    pub(in crate::node::actor) async fn begin_owned_trust_command(
        &mut self,
        command: NodeCommand,
        reply: oneshot::Sender<Outcome>,
    ) {
        if self.computer_change_refused(&command) {
            let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
            return;
        }
        let (inner, proved) = match command {
            NodeCommand::Proved { change } => (*change, true),
            command => (command, false),
        };
        let (change, kind) = match inner {
            NodeCommand::Trust {
                fingerprint,
                petname,
            } => (
                GrantChange::Trust {
                    target: fingerprint,
                    petname,
                    capability: None,
                },
                GrantCommand::Trust,
            ),
            NodeCommand::TrustWith {
                fingerprint,
                petname,
                capability,
            } => (
                GrantChange::Trust {
                    target: fingerprint,
                    petname,
                    capability,
                },
                GrantCommand::Trust,
            ),
            NodeCommand::SetCapability {
                fingerprint,
                capability,
            } => (
                GrantChange::Capability {
                    target: fingerprint,
                    capability,
                },
                GrantCommand::Capability,
            ),
            NodeCommand::Rename {
                fingerprint,
                petname,
            } => (
                GrantChange::Rename {
                    target: fingerprint,
                    petname,
                },
                GrantCommand::Rename,
            ),
            _ => {
                let _ = reply.send(Outcome::Failed(Fault::Internal));
                return;
            }
        };
        if proved && self.profile.as_ref().is_some_and(Profile::is_unlocked) {
            self.note_passphrase_entered();
        }
        if matches!(&change, GrantChange::Rename { .. }) && !self.trust.is_trusted(&change.target())
        {
            let _ = reply.send(Outcome::Failed(Fault::NotConsented));
            return;
        }
        let Some(profile) = self.profile.as_ref() else {
            let _ = reply.send(Outcome::Failed(Fault::NoIdentity));
            return;
        };
        if profile.is_unlocked() && !proved && !self.passphrase_entered_recently() {
            let _ = reply.send(Outcome::Failed(Fault::PassphraseNeeded));
            return;
        }
        let signer = match profile.signer_arc() {
            Ok(signer) => signer,
            Err(error) => {
                let _ = reply.send(Outcome::Failed(fault_of(&error)));
                return;
            }
        };
        if matches!(&change, GrantChange::Capability { .. })
            && !self.trust.is_trusted(&change.target())
        {
            let _ = reply.send(Outcome::Failed(Fault::NotConsented));
            return;
        }
        let Some(authority) = self.computer_authority() else {
            let _ = reply.send(Outcome::Failed(Fault::ComputerPolicy));
            return;
        };
        let secret = match self.secret_work.clone().try_read_owned() {
            Ok(secret) => Arc::new(secret),
            Err(_) => {
                let _ = reply.send(Outcome::Failed(Fault::Locked));
                return;
            }
        };
        let store = profile.store_handle();
        let lifetime = Lifetime {
            save: Some(Arc::new(maintenance_save::Lifetime {
                authority,
                publication: None,
                exclusive: None,
                secret,
                store,
                signer,
            })),
            transition: None,
            journal: self.computer_journal_writer.take(),
        };
        self.begin_pending_policy(
            Policy::Grant { change, floor: 0 },
            PolicyContinuation::Grant {
                lifetime,
                source: GrantSource::Command(kind),
            },
            Some(reply),
        )
        .await;
    }

    pub(super) async fn begin_owned_local_grant(
        &mut self,
        fingerprint: Digest32,
        name: String,
        capability: Capability,
        lifetime: Lifetime,
        reply: Reply,
    ) {
        self.begin_pending_policy(
            Policy::Grant {
                change: GrantChange::Local {
                    target: fingerprint,
                    name,
                    capability,
                },
                floor: 0,
            },
            PolicyContinuation::Grant {
                lifetime,
                source: GrantSource::Local { capability },
            },
            reply,
        )
        .await;
    }

    pub(super) async fn finish_grant_save(
        &mut self,
        lifetime: Lifetime,
        source: GrantSource,
        grant: Option<GrantSaved>,
        reply: Reply,
    ) {
        let Some(grant) = grant else {
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Done);
            }
            return;
        };
        self.publish().await;
        let decision = match &source {
            GrantSource::Local { capability } => Some(crate::node::decisions::Decision {
                asked: "to trust a node of this computer",
                by: grant.target,
                alias: self.trust.petname(&grant.target).map(str::to_owned),
                decided: crate::node::decisions::Decided::Trusted,
                why: format!(
                    "the daemon applied this computer's local trust rule: {}",
                    capability.words()
                ),
                room: None,
            }),
            GrantSource::Command(kind) => {
                if grant.newly && matches!(kind, GrantCommand::Trust) {
                    Some(crate::node::decisions::Decision {
                        asked: "to trust a member",
                        by: grant.target,
                        alias: self.trust.petname(&grant.target).map(str::to_owned),
                        decided: crate::node::decisions::Decided::Trusted,
                        why: "this node's person added them to the keyring".to_owned(),
                        room: None,
                    })
                } else {
                    None
                }
            }
        };
        if let Some(decision) = decision {
            self.begin_pending_policy(
                Policy::RecordDecision {
                    log: self.decisions.clone(),
                    now: (self.millis_clock)(),
                    decision,
                },
                PolicyContinuation::FinishGrant {
                    lifetime,
                    source,
                    grant,
                },
                reply,
            )
            .await;
        } else {
            drop(lifetime);
            self.finish_grant_reply(grant, reply).await;
        }
    }

    pub(super) async fn finish_grant_reply(&mut self, grant: GrantSaved, reply: Reply) {
        let consents = if grant.newly {
            let (terminal, finished) = oneshot::channel();
            self.begin_owned_consent_pass(Some(grant.target), None, Some(terminal), None)
                .await;
            Some(finished)
        } else {
            None
        };
        self.reply_after_room_trust(reply, consents);
    }
}
