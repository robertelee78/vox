//! The no-vault branch still owns real Computer journal/binding receipts off actor.
use super::*;
use crate::identity::composite::RootSigner as _;

type Saved = (Option<(u64, bool)>, crate::error::Result<()>);
pub(crate) struct HeadlessPending {
    computer: Arc<crate::node::computer::Computer>,
    node: Digest32,
    epoch: u64,
    result: Arc<std::sync::Mutex<Option<Saved>>>,
    task: tokio::task::JoinHandle<()>,
    work: computer::OwnKeyPolicyWork,
    _transition: Arc<crate::node::computer::ComputerPublicationTransition>,
    _transitions: Vec<crate::node::channel::own_writer_gate::Transition>,
    _secret: own_keys::SecretLease,
}
impl HeadlessPending {
    pub(super) async fn retire(self) {
        let _ = self.task.await;
        let result = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .map(|(_, result)| result)
            .unwrap_or(Err(Error::Profile("headless policy worker stopped")));
        let _ = self.work.reply.send(result);
    }
}
impl Node {
    pub(super) fn begin_headless_policy(
        &mut self,
        work: computer::OwnKeyPolicyWork,
        secret: own_keys::SecretLease,
        transition: crate::node::computer::ComputerPublicationTransition,
        transitions: Vec<crate::node::channel::own_writer_gate::Transition>,
    ) {
        if self.pending_policy.is_some() {
            let _ = work
                .reply
                .send(Err(Error::Profile("a node policy save is pending")));
            return;
        }
        let Some(computer) = self.computer.clone() else {
            let _ = work.reply.send(Ok(()));
            return;
        };
        let Some(signer) = self.headless.as_ref().map(Arc::clone) else {
            let _ = work.reply.send(Err(Error::Profile(
                "managed node needs an unlocked identity",
            )));
            return;
        };
        let Some(name) = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
        else {
            let _ = work
                .reply
                .send(Err(Error::Profile("managed node name is unreadable")));
            return;
        };
        let node = signer.fingerprint();
        let guard = work.guard.clone();
        let transition = Arc::new(transition);
        let worker_transition = Arc::clone(&transition);
        let worker_computer = Arc::clone(&computer);
        let worker_secret = Arc::clone(&secret);
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let task = tokio::spawn(async move {
            let saved = tokio::task::spawn_blocking(move || {
                let _secret = worker_secret;
                trust_save::apply_headless_policy(
                    &worker_computer,
                    signer.as_ref(),
                    &name,
                    &worker_transition,
                    &guard,
                    false,
                )
            })
            .await
            .unwrap_or_else(|_| (None, Err(Error::Profile("headless policy owner stopped"))));
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(saved);
            wake.notify_one();
        });
        self.pending_policy = Some(Pending::Headless(HeadlessPending {
            computer,
            node,
            epoch: self.delivery_epoch,
            result,
            task,
            work,
            _transition: transition,
            _transitions: transitions,
            _secret: secret,
        }));
    }

    pub(super) async fn complete_headless_policy(&mut self, pending: HeadlessPending) {
        let saved = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some((committed, result)) = saved else {
            self.pending_policy = Some(Pending::Headless(pending));
            return;
        };
        let _ = pending.task.await;
        let current = pending.epoch == self.delivery_epoch
            && self
                .computer
                .as_ref()
                .is_some_and(|computer| Arc::ptr_eq(computer, &pending.computer))
            && self
                .headless
                .as_ref()
                .is_some_and(|signer| signer.fingerprint() == pending.node);
        if current {
            if let Some((revision, expired)) = committed {
                self.computer_expired = expired;
                self.computer_revision
                    .store(revision, std::sync::atomic::Ordering::Release);
                self.publish_computer_trust_projection();
                self.publish().await;
            }
            if result.is_ok() {
                self.governance_work.resume_after_computer_policy();
                self.resume_own_key_interruptions();
                self.resume_own_key_donor_busy();
                self.resume_own_key_policy_waiting();
            }
        }
        let _ = pending.work.reply.send(result);
    }
}
