//! The `Node` actor and its handle (ADR-016 §"The `Node`: one actor, one writer,
//! one secrets boundary"; M13.4).
//!
//! One tokio task owns the [`Profile`] (the unlocked identity when unlocked) and
//! every open [`ChannelState`] (its SEK, DAG, chains). It is the **single
//! writer** of the store. Clients hold a [`NodeHandle`] and talk to it only
//! through the [`crate::node::api`] types:
//! - commands go in over an `mpsc` with a per-command `oneshot` reply
//!   ([`NodeHandle::apply`]);
//! - the latest [`NodeView`] comes out over a `watch` ([`NodeHandle::view`]);
//! - ordered [`NodeEvent`]s come out over an `mpsc` ([`NodeHandle::next_event`]).
//!
//! Commands are processed strictly in order; a KDF-heavy command (unlock, create
//! or open a channel — Argon2id at 256 MiB) runs inline in the actor, so later
//! commands queue behind it for the ~1 s it takes. That serialization is the
//! design, not a limitation: the actor is the one place secrets are handled.
//!
//! The clock is injected ([`Node::spawn_with`]) so tests are deterministic; the
//! default is the system clock — the node is the boundary where wall-clock time
//! legitimately enters (every library layer takes `now_secs` from its caller).
//!
//! Dropping the last [`NodeHandle`] closes the command channel; the actor then
//! locks (wiping every SEK and the signer) and exits.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, watch, Mutex};

use crate::atrest::sek::Argon2Profile;
use crate::error::Error;
use crate::hash::Digest32;
use crate::node::api::{
    ChannelDetail, ChannelSummary, Fault, IdentityInfo, MessageRow, NodeCommand, NodeEvent,
    NodeView, Outcome, Secret,
};
use crate::node::channel::{ChannelState, Rendered};
use crate::node::paths::Paths;
use crate::node::prekeys::{self, PrekeyRing};
use crate::node::profile::Profile;

/// Command queue depth (commands beyond it apply backpressure to the client).
const COMMAND_QUEUE: usize = 64;
/// Event queue depth. A client that stops draining events eventually blocks the
/// actor's event emission; the TUI drains continuously (ADR-015).
const EVENT_QUEUE: usize = 256;

// The clock lives in `crate::time` (M14.2: the rendezvous service needs it too and
// `nat` must not depend on `node`); re-exported so this path stays stable.
pub use crate::time::{system_clock, Clock};

/// A client's handle to a running node.
#[derive(Debug, Clone)]
pub struct NodeHandle {
    cmd_tx: mpsc::Sender<(NodeCommand, oneshot::Sender<Outcome>)>,
    view_rx: watch::Receiver<NodeView>,
    events: Arc<Mutex<mpsc::Receiver<NodeEvent>>>,
}

impl NodeHandle {
    /// The latest view (cheap clone of the watch value).
    #[must_use]
    pub fn view(&self) -> NodeView {
        self.view_rx.borrow().clone()
    }

    /// A receiver that resolves whenever the view changes.
    #[must_use]
    pub fn watch(&self) -> watch::Receiver<NodeView> {
        self.view_rx.clone()
    }

    /// Apply a command and await its outcome. [`Fault::ShuttingDown`] if the
    /// actor has stopped.
    pub async fn apply(&self, command: NodeCommand) -> Outcome {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send((command, tx)).await.is_err() {
            return Outcome::Failed(Fault::ShuttingDown);
        }
        rx.await.unwrap_or(Outcome::Failed(Fault::ShuttingDown))
    }

    /// The next ordered event, or `None` once the actor has stopped.
    pub async fn next_event(&self) -> Option<NodeEvent> {
        self.events.lock().await.recv().await
    }

    /// Non-blocking event poll (for a synchronous UI loop).
    pub fn try_next_event(&self) -> Option<NodeEvent> {
        self.events.try_lock().ok()?.try_recv().ok()
    }
}

/// The node actor's state (owned by its task).
pub struct Node {
    paths: Paths,
    profile: Option<Profile>,
    /// The identity's key-agreement keys (ADR-002 §2), held only while unlocked:
    /// loaded (or generated on first use) by [`crate::node::prekeys::load_or_create`]
    /// after the identity unlocks and dropped on lock, so no prekey secret is in
    /// memory behind a lock (ADR-010/015). M14.4+ publishes its bundle.
    prekeys: Option<PrekeyRing>,
    channels: BTreeMap<Digest32, ChannelState>,
    clock: Clock,
    argon2: Argon2Profile,
    view_tx: watch::Sender<NodeView>,
    event_tx: mpsc::Sender<NodeEvent>,
}

impl Node {
    /// Spawn the node for `paths` on the current tokio runtime with the system
    /// clock and the production Argon2id profile. An existing identity is
    /// opened **locked**; a profile without one waits for
    /// [`NodeCommand::CreateIdentity`].
    pub fn spawn(paths: Paths) -> crate::error::Result<NodeHandle> {
        Self::spawn_with(paths, system_clock(), Argon2Profile::default())
    }

    /// [`Node::spawn`] with an injected clock and Argon2id profile (tests use the
    /// reduced profile and a fixed clock).
    pub fn spawn_with(
        paths: Paths,
        clock: Clock,
        argon2: Argon2Profile,
    ) -> crate::error::Result<NodeHandle> {
        let profile = if Profile::exists(&paths) {
            Some(Profile::open(paths.clone())?)
        } else {
            None
        };
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_QUEUE);
        let (event_tx, event_rx) = mpsc::channel(EVENT_QUEUE);
        let node = Self {
            paths,
            profile,
            prekeys: None,
            channels: BTreeMap::new(),
            clock,
            argon2,
            view_tx: watch::Sender::new(NodeView::default()),
            event_tx,
        };
        let view_rx = node.view_tx.subscribe();
        node.publish();
        tokio::spawn(node.run(cmd_rx));
        Ok(NodeHandle {
            cmd_tx,
            view_rx,
            events: Arc::new(Mutex::new(event_rx)),
        })
    }

    async fn run(mut self, mut cmd_rx: mpsc::Receiver<(NodeCommand, oneshot::Sender<Outcome>)>) {
        while let Some((command, reply)) = cmd_rx.recv().await {
            let shutdown = matches!(command, NodeCommand::Shutdown);
            let outcome = self.handle(command).await;
            self.publish();
            // A dropped reply receiver is the caller's choice, not an error here.
            let _ = reply.send(outcome);
            if shutdown {
                break;
            }
        }
        // Channel closed or shutdown: lock (wipe every SEK + the signer) and stop.
        self.lock_all().await;
        self.publish();
        let _ = self.event_tx.send(NodeEvent::Shutdown).await;
    }

    async fn handle(&mut self, command: NodeCommand) -> Outcome {
        match command {
            NodeCommand::CreateIdentity { passphrase } => self.create_identity(&passphrase),
            NodeCommand::Unlock { passphrase } => self.unlock(&passphrase).await,
            NodeCommand::Lock => {
                self.lock_all().await;
                Outcome::Done
            }
            NodeCommand::CreateChannel {
                local_name,
                passphrase,
            } => self.create_channel(&local_name, &passphrase).await,
            NodeCommand::OpenChannel {
                channel_id,
                passphrase,
            } => self.open_channel(&channel_id, &passphrase).await,
            NodeCommand::CloseChannel { channel_id } => self.close_channel(&channel_id).await,
            NodeCommand::SendText { channel_id, text } => self.send_text(&channel_id, &text).await,
            NodeCommand::Shutdown => Outcome::Done,
        }
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    fn create_identity(&mut self, passphrase: &Secret) -> Outcome {
        if self.profile.is_some() {
            return Outcome::Failed(Fault::IdentityExists);
        }
        let now = self.now();
        match Profile::create_with_profile(self.paths.clone(), passphrase, now, self.argon2) {
            Ok(p) => {
                self.profile = Some(p);
                // A fresh identity gets its prekey ring immediately: without it the
                // node has nothing to publish and cannot answer PQXDH.
                if let Err(e) = self.load_prekeys(now) {
                    return Outcome::Failed(fault_of(&e));
                }
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    async fn unlock(&mut self, passphrase: &Secret) -> Outcome {
        let Some(profile) = self.profile.as_mut() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        match profile.unlock(passphrase) {
            Ok(()) => {
                let now = self.now();
                if let Err(e) = self.load_prekeys(now) {
                    // The identity is usable but the ring is not: lock again rather
                    // than run without key-agreement keys.
                    self.lock_all().await;
                    return Outcome::Failed(fault_of(&e));
                }
                let _ = self.event_tx.send(NodeEvent::Unlocked).await;
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Load (or, on first use, generate) the prekey ring for the unlocked
    /// identity, rotating the signed prekey and refilling the one-time pool if due
    /// (ADR-002 §2 cadence, applied on every unlock).
    fn load_prekeys(&mut self, now: u64) -> crate::error::Result<()> {
        let profile = self
            .profile
            .as_ref()
            .ok_or(crate::error::Error::Profile("no identity in this profile"))?;
        let signer = profile.signer()?;
        let (ring, _created) = prekeys::load_or_create(profile.store(), signer, now)?;
        self.prekeys = Some(ring);
        Ok(())
    }

    async fn lock_all(&mut self) {
        let was_unlocked = self.profile.as_ref().is_some_and(Profile::is_unlocked);
        for (_, mut ch) in std::mem::take(&mut self.channels) {
            ch.lock_now();
        }
        // Drop the prekey ring: its secrets zeroize on drop, so a locked node holds
        // no key-agreement material (ADR-015 lock/zeroize).
        self.prekeys = None;
        if let Some(p) = self.profile.as_mut() {
            p.lock();
        }
        if was_unlocked {
            let _ = self.event_tx.send(NodeEvent::Locked).await;
        }
    }

    async fn create_channel(&mut self, local_name: &str, passphrase: &Secret) -> Outcome {
        let now = self.now();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        match ChannelState::create_with_profile(profile, local_name, passphrase, now, self.argon2) {
            Ok(ch) => {
                let id = ch.channel_id();
                self.channels.insert(id, ch);
                let _ = self
                    .event_tx
                    .send(NodeEvent::ChannelOpened { channel_id: id })
                    .await;
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    async fn open_channel(&mut self, channel_id: &Digest32, passphrase: &Secret) -> Outcome {
        if self.channels.contains_key(channel_id) {
            return Outcome::Done;
        }
        let now = self.now();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        match ChannelState::open(profile, channel_id, passphrase, now) {
            Ok(ch) => {
                self.channels.insert(*channel_id, ch);
                let _ = self
                    .event_tx
                    .send(NodeEvent::ChannelOpened {
                        channel_id: *channel_id,
                    })
                    .await;
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    async fn close_channel(&mut self, channel_id: &Digest32) -> Outcome {
        match self.channels.remove(channel_id) {
            Some(mut ch) => {
                ch.lock_now();
                let _ = self
                    .event_tx
                    .send(NodeEvent::ChannelClosed {
                        channel_id: *channel_id,
                    })
                    .await;
                Outcome::Done
            }
            None => Outcome::Failed(Fault::ChannelNotOpen),
        }
    }

    async fn send_text(&mut self, channel_id: &Digest32, text: &str) -> Outcome {
        let now = self.now();
        let Some(profile) = self.profile.as_ref() else {
            return Outcome::Failed(Fault::NoIdentity);
        };
        let Some(ch) = self.channels.get_mut(channel_id) else {
            return Outcome::Failed(Fault::ChannelNotOpen);
        };
        match ch.append_text(profile, text, now) {
            Ok(r) => {
                let row = row_of(r);
                let _ = self
                    .event_tx
                    .send(NodeEvent::NewEntry {
                        channel_id: *channel_id,
                        row,
                    })
                    .await;
                Outcome::Done
            }
            Err(e) => Outcome::Failed(fault_of(&e)),
        }
    }

    /// Publish the current view (latest wins).
    fn publish(&self) {
        let view = self.view_of();
        self.view_tx.send_replace(view);
    }

    fn view_of(&self) -> NodeView {
        let identity = self.profile.as_ref().map(|p| IdentityInfo {
            fingerprint: p.fingerprint(),
            created: p.created(),
        });
        let locked = !self.profile.as_ref().is_some_and(Profile::is_unlocked);
        let known: Vec<Digest32> = self
            .profile
            .as_ref()
            .and_then(|p| p.store().channels().ok())
            .unwrap_or_default();
        let channels = known
            .iter()
            .map(|id| match self.channels.get(id) {
                Some(ch) => ChannelSummary {
                    channel_id: *id,
                    local_name: Some(ch.local_name().to_owned()),
                    open: true,
                    entries: ch.entry_count() as u64,
                },
                None => ChannelSummary {
                    channel_id: *id,
                    local_name: None,
                    open: false,
                    entries: 0,
                },
            })
            .collect();
        let open_channels = self
            .channels
            .values()
            .map(|ch| ChannelDetail {
                channel_id: ch.channel_id(),
                local_name: ch.local_name().to_owned(),
                epoch: ch.epoch(),
                members: ch.members(),
                timeline: ch.timeline().iter().map(row_of).collect(),
            })
            .collect();
        let mlock_active = self.channels.values().all(ChannelState::mlock_active);
        NodeView {
            identity,
            locked,
            mlock_active,
            channels,
            open_channels,
        }
    }
}

fn row_of(r: &Rendered) -> MessageRow {
    MessageRow {
        entry_hash: r.entry_hash,
        author: r.author,
        created_secs: r.created_secs,
        text: r.text.clone(),
    }
}

/// Map a library error to the closed, redaction-safe [`Fault`] set.
fn fault_of(e: &Error) -> Fault {
    match e {
        Error::Profile("no identity in this profile") => Fault::NoIdentity,
        Error::Profile("identity already exists in this profile") => Fault::IdentityExists,
        Error::Profile("locked") => Fault::Locked,
        Error::Profile("no such channel in this profile") => Fault::UnknownChannel,
        Error::AtRestUnlockFailed => Fault::WrongPassphrase,
        Error::AtRestLocked => Fault::Locked,
        Error::SizeLimitExceeded(_) => Fault::TooLong,
        Error::Storage { .. } | Error::Path { .. } => Fault::Storage,
        _ => Fault::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Secret {
        Secret::new(s.as_bytes().to_vec())
    }

    fn fixed_clock(t: u64) -> Clock {
        Arc::new(move || t)
    }

    fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
        Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
    }

    /// A node built directly (not spawned), so a test can observe private state
    /// the handle deliberately never exposes — here: that no prekey secret is
    /// retained behind a lock.
    fn unspawned(paths: Paths, t: u64) -> Node {
        let (event_tx, _event_rx) = mpsc::channel(EVENT_QUEUE);
        Node {
            paths,
            profile: None,
            prekeys: None,
            channels: BTreeMap::new(),
            clock: fixed_clock(t),
            argon2: Argon2Profile::REDUCED,
            view_tx: watch::Sender::new(NodeView::default()),
            event_tx,
        }
    }

    #[tokio::test]
    async fn the_prekey_ring_is_loaded_on_unlock_and_dropped_on_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let t = 1_700_000_000;
        let mut node = unspawned(paths(&tmp, "alice"), t);

        // A created identity gets a usable, root-signed ring straight away.
        assert_eq!(node.create_identity(&secret("id-pp")), Outcome::Done);
        let root = crate::identity::composite::RootSigner::public_key(
            node.profile.as_ref().unwrap().signer().unwrap(),
        );
        let ring = node.prekeys.as_ref().expect("ring after create");
        let first_spk = ring.signed_prekey_id();
        let bundle = ring.bundle(&root).unwrap();
        bundle.verify().unwrap();
        assert_eq!(bundle.root_pub, root.to_bytes());
        assert!(bundle.one_time_prekey.is_some());

        // Lock: the ring is dropped (its secrets zeroize on drop), like the
        // identity signer and every channel SEK.
        node.lock_all().await;
        assert!(node.prekeys.is_none(), "no prekey secrets behind a lock");
        assert!(!node.profile.as_ref().unwrap().is_unlocked());

        // A wrong passphrase leaves it locked and ringless.
        assert_eq!(
            node.unlock(&secret("wrong")).await,
            Outcome::Failed(Fault::WrongPassphrase)
        );
        assert!(node.prekeys.is_none());

        // The right passphrase reloads the *same* ring — not a fresh one, which
        // would invalidate every bundle already published.
        assert_eq!(node.unlock(&secret("id-pp")).await, Outcome::Done);
        let ring = node.prekeys.as_ref().expect("ring after unlock");
        assert_eq!(ring.signed_prekey_id(), first_spk);
        assert_eq!(ring.bundle(&root).unwrap(), bundle);
    }

    #[tokio::test]
    async fn full_single_device_lifecycle_through_the_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "alice");
        let h = Node::spawn_with(
            p.clone(),
            fixed_clock(1_700_000_000),
            Argon2Profile::REDUCED,
        )
        .unwrap();

        // Fresh profile: no identity, locked.
        let v = h.view();
        assert!(v.identity.is_none());
        assert!(v.locked);
        assert!(v.channels.is_empty());
        assert!(
            h.apply(NodeCommand::Unlock {
                passphrase: secret("x")
            })
            .await
                == Outcome::Failed(Fault::NoIdentity)
        );

        // Create identity → unlocked, identity visible.
        assert!(h
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("id-pp")
            })
            .await
            .is_done());
        assert!(matches!(
            h.apply(NodeCommand::CreateIdentity {
                passphrase: secret("id-pp")
            })
            .await,
            Outcome::Failed(Fault::IdentityExists)
        ));
        let v = h.view();
        let fp = v.identity.as_ref().unwrap().fingerprint;
        assert!(!v.locked);

        // Create a channel, send two messages, observe events and the view.
        assert!(h
            .apply(NodeCommand::CreateChannel {
                local_name: "family".into(),
                passphrase: secret("ch-pp")
            })
            .await
            .is_done());
        let v = h.view();
        assert_eq!(v.channels.len(), 1);
        let cid = v.channels[0].channel_id;
        assert_eq!(v.channels[0].local_name.as_deref(), Some("family"));
        assert!(v.channels[0].open);
        assert!(
            matches!(h.next_event().await, Some(NodeEvent::ChannelOpened { channel_id }) if channel_id == cid)
        );

        assert!(h
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "hello".into()
            })
            .await
            .is_done());
        assert!(h
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "world".into()
            })
            .await
            .is_done());
        match h.next_event().await {
            Some(NodeEvent::NewEntry { channel_id, row }) => {
                assert_eq!(channel_id, cid);
                assert_eq!(row.text, "hello");
                assert_eq!(row.author, fp);
                assert_eq!(row.created_secs, 1_700_000_000);
            }
            other => panic!("expected NewEntry, got {other:?}"),
        }
        assert!(matches!(
            h.next_event().await,
            Some(NodeEvent::NewEntry { .. })
        ));
        let v = h.view();
        assert_eq!(v.channels[0].entries, 2);
        let detail = &v.open_channels[0];
        assert_eq!(detail.local_name, "family");
        assert_eq!(detail.members, vec![fp]);
        assert_eq!(
            detail
                .timeline
                .iter()
                .map(|r| r.text.as_str())
                .collect::<Vec<_>>(),
            vec!["hello", "world"]
        );

        // Lock: channels close, identity locks, sends fail with Locked/ChannelNotOpen.
        assert!(h.apply(NodeCommand::Lock).await.is_done());
        assert!(matches!(h.next_event().await, Some(NodeEvent::Locked)));
        let v = h.view();
        assert!(v.locked);
        assert!(v.open_channels.is_empty());
        assert_eq!(v.channels.len(), 1);
        assert!(!v.channels[0].open);
        assert!(
            v.channels[0].local_name.is_none(),
            "name is under the channel lock"
        );
        assert!(matches!(
            h.apply(NodeCommand::SendText {
                channel_id: cid,
                text: "x".into()
            })
            .await,
            Outcome::Failed(Fault::ChannelNotOpen)
        ));
        assert!(matches!(
            h.apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("ch-pp")
            })
            .await,
            Outcome::Failed(Fault::Locked)
        ));

        // Unlock (wrong, then right), reopen the channel: timeline restored.
        assert!(matches!(
            h.apply(NodeCommand::Unlock {
                passphrase: secret("nope")
            })
            .await,
            Outcome::Failed(Fault::WrongPassphrase)
        ));
        assert!(h
            .apply(NodeCommand::Unlock {
                passphrase: secret("id-pp")
            })
            .await
            .is_done());
        assert!(matches!(h.next_event().await, Some(NodeEvent::Unlocked)));
        assert!(matches!(
            h.apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("wrong")
            })
            .await,
            Outcome::Failed(Fault::WrongPassphrase)
        ));
        assert!(h
            .apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("ch-pp")
            })
            .await
            .is_done());
        let v = h.view();
        assert_eq!(v.open_channels[0].timeline.len(), 2);
        assert!(matches!(
            h.apply(NodeCommand::OpenChannel {
                channel_id: [9u8; 32],
                passphrase: secret("ch-pp")
            })
            .await,
            Outcome::Failed(Fault::UnknownChannel)
        ));
        assert!(h
            .apply(NodeCommand::CloseChannel { channel_id: cid })
            .await
            .is_done());
        assert!(matches!(
            h.apply(NodeCommand::CloseChannel { channel_id: cid }).await,
            Outcome::Failed(Fault::ChannelNotOpen)
        ));

        // Shutdown: replies Done, then the actor stops and later commands fail.
        assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        // Drain to the Shutdown event.
        let mut saw_shutdown = false;
        while let Some(ev) = h.next_event().await {
            if ev == NodeEvent::Shutdown {
                saw_shutdown = true;
                break;
            }
        }
        assert!(saw_shutdown);
        assert!(matches!(
            h.apply(NodeCommand::Lock).await,
            Outcome::Failed(Fault::ShuttingDown)
        ));
    }

    #[tokio::test]
    async fn restart_reopens_locked_with_channels_listed() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "alice");
        let cid;
        {
            let h = Node::spawn_with(p.clone(), fixed_clock(1), Argon2Profile::REDUCED).unwrap();
            assert!(h
                .apply(NodeCommand::CreateIdentity {
                    passphrase: secret("id")
                })
                .await
                .is_done());
            assert!(h
                .apply(NodeCommand::CreateChannel {
                    local_name: "c".into(),
                    passphrase: secret("ch")
                })
                .await
                .is_done());
            cid = h.view().channels[0].channel_id;
            assert!(h
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: "persisted".into()
                })
                .await
                .is_done());
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
        // A new process: the identity is there, locked; the channel is listed but closed.
        let h = Node::spawn_with(p, fixed_clock(2), Argon2Profile::REDUCED).unwrap();
        let v = h.view();
        assert!(v.identity.is_some());
        assert!(v.locked);
        assert_eq!(v.channels.len(), 1);
        assert_eq!(v.channels[0].channel_id, cid);
        assert!(!v.channels[0].open);
        assert!(h
            .apply(NodeCommand::Unlock {
                passphrase: secret("id")
            })
            .await
            .is_done());
        assert!(h
            .apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("ch")
            })
            .await
            .is_done());
        let v = h.view();
        assert_eq!(v.open_channels[0].timeline[0].text, "persisted");
        assert_eq!(v.open_channels[0].timeline[0].created_secs, 1);
    }

    #[tokio::test]
    async fn dropping_the_last_handle_locks_and_stops_the_actor() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "alice");
        let h = Node::spawn_with(p.clone(), fixed_clock(1), Argon2Profile::REDUCED).unwrap();
        assert!(h
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("id")
            })
            .await
            .is_done());
        let mut w = h.watch();
        drop(h);
        // The actor observes the closed command channel, locks, publishes, exits.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if w.borrow().locked {
                    break;
                }
                if w.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(w.borrow().locked);
    }
}
