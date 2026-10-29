//! Identity startup owns the actual locked/new Profile until native preparation has finished.
//! No live room is extracted, and a command reply remains with its original startup attempt.
use super::*;
use crate::node::decisions::DecisionLog;

pub(super) enum Work {
    Create {
        passphrase: Secret,
    },
    Unlock {
        profile: Option<Box<Profile>>,
        passphrase: Secret,
    },
}

pub(super) struct Loaded {
    ring: PrekeyRing,
    dismissed: crate::node::offers::DismissedOffers,
    peers: crate::node::peer_book::PeerBook,
    peers_unsaved: bool,
    hints: BootstrapSet,
    hints_unreadable: bool,
    withdrawals: BTreeMap<Digest32, PendingWithdrawal>,
    joins: BTreeMap<Digest32, PendingWithdrawal>,
}

struct Returned {
    profile: Option<Profile>,
    loaded: std::result::Result<Loaded, Fault>,
    // This exact lease survives both physical I/O and the actor's installation callback.
    _secret: tokio::sync::OwnedRwLockReadGuard<()>,
    exclusive: Option<Arc<crate::node::computer::ComputerPublicationTransition>>,
    computer: Option<Arc<crate::node::computer::Computer>>,
    boundary: Option<(std::time::Instant, Digest32)>,
    policy: Option<trust_save::StartupPolicy>,
}

pub(super) struct Pending {
    epoch: u64,
    result: Arc<std::sync::Mutex<Option<Returned>>>,
    task: tokio::task::JoinHandle<()>,
    reply: Option<oneshot::Sender<Outcome>>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    // An exact generation plus the absent actor Profile fences installation against replacement.
    created: bool,
    decisions: DecisionLog,
}

fn ledgers(
    profile: &Profile,
) -> crate::error::Result<(
    BTreeMap<Digest32, PendingWithdrawal>,
    BTreeMap<Digest32, PendingWithdrawal>,
)> {
    let read = |key| -> crate::error::Result<BTreeMap<Digest32, PendingWithdrawal>> {
        profile
            .store()
            .get_meta(key)?
            .map(|bytes| read_pending_withdrawals(&bytes))
            .transpose()
            .map(Option::unwrap_or_default)
    };
    Ok((
        read(PENDING_WITHDRAWALS_META_KEY)?,
        read(PENDING_JOIN_CLEANUP_META_KEY)?,
    ))
}

/// Runs only on the native identity worker, never under Room or Computer.state guards.
fn prepare(profile: &Profile, decisions: &DecisionLog, now: u64) -> crate::error::Result<Loaded> {
    let signer = profile.signer()?;
    let dh_secret = *signer.x25519_identity_secret();
    let (ring, _) = prekeys::load_or_create(profile.store(), signer, &dh_secret, now)?;
    let dismissed =
        crate::node::offers::DismissedOffers::load(profile.store(), signer).unwrap_or_default();
    let (peers, peers_unsaved) =
        match crate::node::peer_book::PeerBook::load(profile.store(), signer) {
            Ok(peers) => (peers, false),
            Err(_) => (crate::node::peer_book::PeerBook::new(), true),
        };
    let (hints, hints_unreadable) =
        match crate::node::peer_book::load_anchor_hints(profile.store(), signer) {
            Ok(hints) => (hints, false),
            Err(error) => {
                eprintln!("vox: anchor endpoint cache could not be opened; preserving it: {error}");
                (BootstrapSet::new(), true)
            }
        };
    decisions.hold_for_local_trust_import(true);
    decisions.unlock(signer)?;
    // Reuse the canonical writer-admitted import; an unreadable diary disables automation,
    // not ordinary use of an otherwise authenticated identity.
    match (trust_save::Policy::ImportBlacklist {
        history: decisions.clone(),
    })
    .run(profile.store(), signer)
    {
        trust_save::PolicyCompleted::Saved(Ok(_)) => {
            decisions.hold_for_local_trust_import(false);
        }
        trust_save::PolicyCompleted::Saved(Err(error)) => {
            eprintln!("vox: automatic local trust waits for its removal history: {error}");
        }
        _ => return Err(Error::Profile("unexpected blacklist import completion")),
    }
    let unfinished = profile
        .store()
        .get_meta(PENDING_JOIN_CLEANUP_META_KEY)?
        .map(|bytes| read_pending_withdrawals(&bytes))
        .transpose()?
        .unwrap_or_default();
    for room in unfinished.keys() {
        metadata_save::abort_join_cleanup_native(
            profile.store(),
            signer,
            profile.fingerprint(),
            *room,
        )?;
    }
    // The helper merges the latest writer-admitted maps. Never reinstall the pre-abort snapshot.
    let (withdrawals, joins) = ledgers(profile)?;
    Ok(Loaded {
        ring,
        dismissed,
        peers,
        peers_unsaved,
        hints,
        hints_unreadable,
        withdrawals,
        joins,
    })
}

fn run(
    work: Work,
    paths: Paths,
    now: u64,
    argon2: Argon2Profile,
    decisions: &DecisionLog,
    events: &broadcast::Sender<NodeEvent>,
) -> (Option<Profile>, std::result::Result<Loaded, Fault>) {
    let waiting = || {
        let _ = events.send(NodeEvent::WaitingForProfile);
    };
    let (mut profile, unlock) = match work {
        Work::Create { passphrase } => {
            match Profile::create_noting(paths, &passphrase, now / 1_000, argon2, &waiting) {
                Ok(profile) => (profile, None),
                Err(error) => return (None, Err(fault_of(&error))),
            }
        }
        Work::Unlock {
            profile,
            passphrase,
        } => {
            if profile.is_none() && !Profile::exists(&paths) {
                return (None, Err(Fault::NoIdentity));
            }
            let profile = match profile
                .map(|profile| Ok(*profile))
                .unwrap_or_else(|| Profile::open_noting(paths, &waiting))
            {
                Ok(profile) => profile,
                Err(error) => return (None, Err(fault_of(&error))),
            };
            (profile, Some(passphrase))
        }
    };
    if let Some(passphrase) = unlock {
        if let Err(error) = profile.unlock(&passphrase) {
            return (Some(profile), Err(fault_of(&error)));
        }
    }
    let loaded = prepare(&profile, decisions, now).map_err(|error| match error {
        Error::AtRestUnlockFailed => Fault::SealedUnreadable,
        error => fault_of(&error),
    });
    if loaded.is_err() {
        profile.lock();
        decisions.lock();
    }
    (Some(profile), loaded)
}
impl Returned {
    fn settle_policy(&mut self, decisions: &DecisionLog) {
        if self.loaded.is_err() {
            return;
        }
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        let (end, _) = *self.boundary.get_or_insert_with(|| {
            (
                std::time::Instant::now() + crate::node::computer::COMPUTER_RETURN_SHOWN_WITHIN,
                profile.fingerprint(),
            )
        });
        let applied = profile
            .paths()
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::Profile("managed node name is unreadable"))
            .and_then(|name| {
                trust_save::settle_startup_policy(
                    self.computer.as_ref(),
                    profile,
                    name,
                    self.exclusive.as_ref(),
                    end,
                )
            });
        match applied {
            Ok(applied) => {
                self.policy = Some(applied);
            }
            Err(error) => {
                self.loaded = Err(match error {
                    Error::AtRestUnlockFailed => Fault::SealedUnreadable,
                    error => fault_of(&error),
                });
                if let Some(profile) = self.profile.as_mut() {
                    profile.lock();
                }
                decisions.lock();
            }
        }
    }
}

impl Pending {
    pub(super) async fn retire(self) {
        let Pending {
            task,
            result,
            decisions,
            reply,
            permit,
            ..
        } = self;
        let _ = task.await;
        let returned = result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let _ = tokio::task::spawn_blocking(move || {
            decisions.lock();
            if let Some(reply) = reply {
                let _ = reply.send(Outcome::Failed(Fault::Locked));
            }
            // Closing the actual Store belongs to the native worker too.
            drop(returned);
            drop(permit);
        })
        .await;
    }
}

impl Node {
    /// The synchronous constructor runs before the actor exists (the daemon already owns
    /// it on its blocking worker). Headless startup shares the canonical policy kernel too.
    pub(super) fn start_headless_network(&mut self) -> crate::error::Result<()> {
        let signer = self
            .headless
            .as_ref()
            .map(Arc::clone)
            .ok_or(Error::Profile("headless startup has no identity"))?;
        let computer = self.computer.clone();
        let transition = computer
            .as_ref()
            .map(|computer| {
                computer
                    .try_publication_transition()
                    .map(Arc::new)
                    .ok_or_else(|| Error::OwnKeyWriterDrainRequired(Vec::new()))
            })
            .transpose()?;
        let name = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::Profile("managed node name is unreadable"))?;
        let end = std::time::Instant::now() + crate::node::computer::COMPUTER_RETURN_SHOWN_WITHIN;
        let (revision, expired) = trust_save::settle_headless_startup_policy(
            computer.as_ref(),
            signer.as_ref(),
            name,
            transition.as_ref(),
            end,
        )?;
        self.computer_revision
            .store(revision, std::sync::atomic::Ordering::Release);
        self.computer_expired = expired;
        self.start_network_prepared((
            end,
            crate::identity::composite::RootSigner::fingerprint(signer.as_ref()),
        ))
    }

    pub(super) fn startup_identity_info(&self) -> Option<IdentityInfo> {
        self.profile
            .as_ref()
            .map(|profile| IdentityInfo {
                fingerprint: profile.fingerprint(),
                created: profile.created(),
            })
            .or_else(|| self.startup_identity.clone())
    }

    pub(super) fn begin_create_identity(
        &mut self,
        passphrase: Secret,
        reply: oneshot::Sender<Outcome>,
    ) {
        if self.profile.is_some() || self.startup_identity.is_some() {
            let _ = reply.send(Outcome::Failed(Fault::IdentityExists));
            return;
        }
        self.begin_identity_startup(Work::Create { passphrase }, reply, None);
    }

    pub(super) fn begin_native_unlock(
        &mut self,
        passphrase: Secret,
        reply: oneshot::Sender<Outcome>,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        if self.pending_startup.is_some() {
            self.unlock_after_lock
                .push_back((passphrase, reply, permit));
            return;
        }
        if self.profile.as_ref().is_some_and(Profile::is_unlocked) {
            let _ = reply.send(Outcome::Done);
            return;
        }
        self.startup_identity = self.startup_identity_info();
        let work = Work::Unlock {
            profile: self.profile.take().map(Box::new),
            passphrase,
        };
        self.begin_identity_startup(work, reply, Some(permit));
    }

    fn resume_waiting_identity_unlocks(&mut self) {
        while self.locking == 0 && self.pending_startup.is_none() {
            let Some((passphrase, reply, permit)) = self.unlock_after_lock.pop_front() else {
                break;
            };
            self.begin_native_unlock(passphrase, reply, permit);
        }
    }

    fn begin_identity_startup(
        &mut self,
        work: Work,
        reply: oneshot::Sender<Outcome>,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) {
        let secret = match Arc::clone(&self.secret_work).try_read_owned() {
            Ok(secret) => secret,
            Err(_) => {
                if let Work::Unlock { profile, .. } = work {
                    self.profile = profile.map(|profile| *profile);
                }
                let _ = reply.send(Outcome::Failed(Fault::Locked));
                return;
            }
        };
        let created = matches!(&work, Work::Create { .. });
        let paths = self.paths.clone();
        let now = self.now_ms().get();
        let argon2 = self.argon2;
        let decisions = self.decisions.clone();
        let worker_decisions = decisions.clone();
        let events = self.event_tx.clone();
        let computer = self.computer.clone();
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let task = tokio::spawn(async move {
            // Startup owns no live Room and no Computer.state guard. The same exclusive
            // transition crosses identity writes, native policy and the installation callback.
            let exclusive = match computer.as_ref() {
                Some(computer) => Some(Arc::new(computer.publication_transition().await)),
                None => None,
            };
            let physical_exclusive = exclusive.clone();
            let returned = tokio::task::spawn_blocking(move || {
                let (profile, loaded) = run(work, paths, now, argon2, &worker_decisions, &events);
                let mut returned = Returned {
                    profile,
                    loaded,
                    _secret: secret,
                    exclusive: physical_exclusive,
                    computer,
                    boundary: None,
                    policy: None,
                };
                returned.settle_policy(&worker_decisions);
                returned
            })
            .await;
            let returned = returned.ok();
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = returned;
            drop(exclusive);
            wake.notify_one();
        });
        self.pending_startup = Some(Pending {
            epoch: self.delivery_epoch,
            result,
            task,
            reply: Some(reply),
            permit,
            created,
            decisions,
        });
    }

    pub(super) fn retire_identity_startup(&mut self) {
        if let Some(pending) = self.pending_startup.take() {
            tokio::spawn(pending.retire());
        }
    }

    pub(super) async fn complete_identity_startup(&mut self) {
        let ready = self.pending_startup.as_ref().is_some_and(|pending| {
            pending
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some()
                || pending.task.is_finished()
        });
        if !ready {
            return;
        }
        let Some(mut pending) = self.pending_startup.take() else {
            return;
        };
        let returned = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let _ = (&mut pending.task).await;
        let Some(mut returned) = returned else {
            pending.decisions.lock();
            if let Some(reply) = pending.reply {
                let _ = reply.send(Outcome::Failed(Fault::Internal));
            }
            drop(pending.permit);
            self.resume_waiting_identity_unlocks();
            return;
        };
        let same_computer = match (self.computer.as_ref(), returned.computer.as_ref()) {
            (Some(current), Some(original)) => Arc::ptr_eq(current, original),
            (None, None) => true,
            _ => false,
        };
        let current = pending.epoch == self.delivery_epoch
            && self.profile.is_none()
            && same_computer
            && self.startup_identity.as_ref().is_none_or(|identity| {
                returned
                    .profile
                    .as_ref()
                    .is_none_or(|profile| profile.fingerprint() == identity.fingerprint)
            });
        if !current {
            let decisions = pending.decisions;
            let reply = pending.reply;
            let permit = pending.permit;
            let clear_decisions = self
                .profile
                .as_ref()
                .is_none_or(|profile| !profile.is_unlocked());
            tokio::task::spawn_blocking(move || {
                if clear_decisions {
                    decisions.lock();
                }
                if let Some(reply) = reply {
                    let _ = reply.send(Outcome::Failed(Fault::Locked));
                }
                drop(returned);
                drop(permit);
            });
            return;
        }
        let policy_moved = returned.loaded.is_ok()
            && returned
                .computer
                .as_ref()
                .zip(returned.policy.as_ref())
                .zip(returned.profile.as_ref())
                .is_some_and(|((computer, policy), profile)| {
                    !computer.policy_current(policy.revision, policy.expired, profile.fingerprint())
                });
        if policy_moved {
            // Only real policy/expiry movement repeats native settlement. This is the SAME
            // accepted owner, original observation end, secret and exclusive transition.
            let output = Arc::clone(&pending.result);
            let wake = Arc::clone(&self.post_save_wake);
            let decisions = pending.decisions.clone();
            pending.task = tokio::spawn(async move {
                let returned = tokio::task::spawn_blocking(move || {
                    returned.settle_policy(&decisions);
                    returned
                })
                .await
                .ok();
                *output
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = returned;
                wake.notify_one();
            });
            self.pending_startup = Some(pending);
            return;
        }
        self.profile = returned.profile.take();
        self.startup_identity = self.startup_identity_info();
        let outcome = match returned.loaded {
            Err(fault) => Outcome::Failed(fault),
            Ok(loaded) => {
                self.prekeys_offered = Some(loaded.ring.offered());
                self.prekeys = Some(Arc::new(tokio::sync::Mutex::new(loaded.ring)));
                self.prekey_maintenance_error = None;
                self.dismissed_offers = loaded.dismissed;
                self.peer_book = loaded.peers;
                self.peer_book_save = if loaded.peers_unsaved {
                    peer_book_save::State::Unsaved
                } else {
                    peer_book_save::State::Clean
                };
                self.anchor_hints = loaded.hints;
                self.anchor_hints_load_error = loaded.hints_unreadable;
                self.anchor_hints_save = peer_book_save::State::default();
                self.withdrawn = loaded.withdrawals;
                self.join_cleanup = loaded.joins;
                if let Some(policy) = returned.policy {
                    self.trust = policy.trust;
                    self.consent_keys = policy.consent_keys;
                    self.computer_revision
                        .store(policy.revision, std::sync::atomic::Ordering::Release);
                    self.computer_expired = policy.expired;
                }
                match returned
                    .boundary
                    .ok_or(Error::Profile("native startup has no identity boundary"))
                    .and_then(|boundary| self.start_network_prepared(boundary))
                {
                    Ok(()) => {
                        if !pending.created {
                            self.reopen_remembered().await;
                        }
                        self.resume_own_key_interruptions();
                        self.resume_own_key_donor_busy();
                        self.resume_own_key_policy_waiting();
                        Outcome::Done
                    }
                    Err(error) => {
                        drop(self.lock_all().await);
                        Outcome::Failed(fault_of(&error))
                    }
                }
            }
        };
        // The original exclusive transition and secret lease are still held here. Publishing
        // Ready and answering its original command are part of this exact startup attempt.
        self.publish().await;
        if let Some(reply) = pending.reply {
            let _ = reply.send(outcome);
        }
        drop(returned.exclusive);
        drop(returned._secret);
        drop(pending.permit);
        self.resume_waiting_identity_unlocks();
    }
}
