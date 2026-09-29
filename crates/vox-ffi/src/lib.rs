//! **The embedded node, for native apps** (PRD-001 R30/R31, ADR-014).
//!
//! A phone cannot run a daemon beside an app, so the app runs the node: this crate starts
//! a Vox node inside the app's own process and exposes what an app needs over UniFFI —
//! the boundary ADR-014 chose, because it is typed and memory-safe, it speaks Swift's
//! `async`/`await`, and the same bindings serve macOS and iOS.
//!
//! What crosses the boundary, and what does not:
//!
//! - **In:** a profile directory, passphrases (consumed by the core and never returned),
//!   room links, text, labels, bytes for app streams.
//! - **Out:** fingerprints and room ids as base32 text, rendered messages, event
//!   notices, and the bytes of app streams and datagrams. **No key material**: signing,
//!   sealing and unsealing stay inside the core (ADR-014's FFI contract).
//!
//! Every call that waits is `async`, so a UI thread never blocks on the core; the work
//! runs on the node's own runtime and the foreign side only awaits it. Events arrive
//! through an [`EventListener`] the app implements.
//!
//! **What is not here:** tunnels (`vox up`, forwards, services). An app that wants a
//! byte stream to another member's app uses the app API ([`VoxNode::app_open`],
//! [`VoxNode::app_listen`]) instead.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::runtime::{Handle, Runtime};
use vox_core::hash::Digest32;
use vox_core::node::actor::{EventStreamItem, Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Outcome, Secret};
use vox_core::node::link::{b32_decode, b32_encode};
use vox_core::node::paths::Paths;

uniffi::setup_scaffolding!();

/// Anything that went wrong, with the core's reason.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VoxError {
    /// The operation failed.
    #[error("{reason}")]
    Failed {
        /// Why, for a person.
        reason: String,
    },
}

fn failed(reason: impl Into<String>) -> VoxError {
    VoxError::Failed {
        reason: reason.into(),
    }
}

fn outcome(what: &str, out: Outcome) -> Result<(), VoxError> {
    match out {
        Outcome::Done => Ok(()),
        Outcome::Failed(f) => Err(failed(format!("{what}: {f:?}"))),
    }
}

fn digest(text: &str, what: &'static str) -> Result<Digest32, VoxError> {
    b32_decode(text.trim(), what).map_err(|e| failed(format!("{what}: {e}")))
}

/// A room this node holds.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Room {
    /// The room's id, base32.
    pub id: String,
    /// This device's name for it; empty while the room is closed.
    pub name: String,
    /// Whether it is open (its key unlocked) now.
    pub open: bool,
}

/// One rendered message.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Message {
    /// The entry's hash, base32 — also the read cursor.
    pub id: String,
    /// Its author's fingerprint, base32.
    pub author: String,
    /// When its author sent it, milliseconds since the Unix epoch.
    pub created_millis: u64,
    /// The text.
    pub text: String,
}

/// An incoming app stream, waiting for [`AppListener::accept`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct AppIncoming {
    /// What `accept` takes.
    pub id: u64,
    /// The room, base32.
    pub room: String,
    /// The opener's fingerprint, base32.
    pub peer: String,
    /// The label chosen.
    pub label: String,
}

/// What the app hears from its node.
#[uniffi::export(with_foreign)]
pub trait EventListener: Send + Sync {
    /// A message became readable in `room`.
    fn on_message(&self, room: String, message: Message);
    /// Anything else the node reports, as a sentence: a peer joined, a room opened, a
    /// peer unreachable.
    fn on_notice(&self, text: String);
}

/// A Vox node running inside this process.
#[derive(uniffi::Object)]
pub struct VoxNode {
    /// The node's own runtime. Held behind a lock so [`VoxNode::stop`] can shut it down.
    runtime: Mutex<Option<Runtime>>,
    rt: Handle,
    node: NodeHandle,
}

impl VoxNode {
    /// Run `fut` on the node's runtime and await it from wherever the caller is — the
    /// foreign executor, typically. The work never runs on the caller's thread.
    async fn on_node<T, F>(&self, fut: F) -> Result<T, VoxError>
    where
        T: Send + 'static,
        F: std::future::Future<Output = Result<T, VoxError>> + Send + 'static,
    {
        self.rt
            .spawn(fut)
            .await
            .map_err(|_| failed("the node stopped"))?
    }

    async fn apply(&self, what: &'static str, cmd: NodeCommand) -> Result<(), VoxError> {
        let node = self.node.clone();
        self.on_node(async move { outcome(what, node.apply(cmd).await) })
            .await
    }
}

#[uniffi::export]
impl VoxNode {
    /// Start a node on `data_dir`, creating its identity under `passphrase` on first use
    /// and unlocking it afterwards, listening on `listen` (e.g. `0.0.0.0:0`).
    ///
    /// # Errors
    /// A wrong passphrase, an unusable directory, or an address that will not bind.
    #[uniffi::constructor]
    pub async fn start(
        data_dir: String,
        passphrase: String,
        listen: String,
    ) -> Result<Arc<Self>, VoxError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vox-node")
            .enable_all()
            .build()
            .map_err(|e| failed(format!("starting the node's runtime: {e}")))?;
        let rt = runtime.handle().clone();
        let dir = std::path::PathBuf::from(&data_dir);
        let bind: std::net::SocketAddr = listen
            .parse()
            .map_err(|_| failed(format!("{listen:?} is not an address to listen on")))?;
        let node = rt
            .spawn(async move {
                let paths = Paths::resolve("default", Some(&dir), Some(&dir.join("config")))
                    .map_err(|e| failed(format!("profile directory: {e}")))?;
                let node = Node::spawn_networked(paths, bind)
                    .map_err(|e| failed(format!("starting the node: {e}")))?;
                let secret = Secret::new(passphrase.into_bytes());
                let out = if node.view().identity.is_none() {
                    node.apply(NodeCommand::CreateIdentity { passphrase: secret })
                        .await
                } else {
                    node.apply(NodeCommand::Unlock { passphrase: secret }).await
                };
                outcome("unlocking the identity", out)?;
                Ok::<_, VoxError>(node)
            })
            .await
            .map_err(|_| failed("the node's runtime stopped"))??;
        Ok(Arc::new(Self {
            runtime: Mutex::new(Some(runtime)),
            rt,
            node,
        }))
    }

    /// This node's identity fingerprint, base32 — what others `trust`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.node
            .view()
            .identity
            .map(|i| b32_encode(&i.fingerprint))
            .unwrap_or_default()
    }

    /// Stop the node: every room is locked and the network torn down. The object is
    /// unusable afterwards.
    pub async fn stop(&self) {
        let node = self.node.clone();
        let _ = self
            .on_node(async move {
                let _ = node.apply(NodeCommand::Shutdown).await;
                Ok(())
            })
            .await;
        if let Some(rt) = self
            .runtime
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            rt.shutdown_background();
        }
    }

    /// Every room this node holds.
    #[must_use]
    pub fn rooms(&self) -> Vec<Room> {
        self.node
            .view()
            .channels
            .into_iter()
            .map(|c| Room {
                id: b32_encode(&c.channel_id),
                name: c.local_name.unwrap_or_default(),
                open: c.open,
            })
            .collect()
    }

    /// Create a room; returns its id.
    ///
    /// # Errors
    /// If the node refuses.
    pub async fn create_room(&self, name: String, passphrase: String) -> Result<String, VoxError> {
        let before: Vec<Digest32> = self
            .node
            .view()
            .channels
            .iter()
            .map(|c| c.channel_id)
            .collect();
        self.apply(
            "creating the room",
            NodeCommand::CreateChannel {
                local_name: name,
                passphrase: Secret::new(passphrase.into_bytes()),
            },
        )
        .await?;
        self.node
            .view()
            .channels
            .iter()
            .find(|c| !before.contains(&c.channel_id))
            .map(|c| b32_encode(&c.channel_id))
            .ok_or_else(|| failed("the room was created but is not listed"))
    }

    /// Open a room this node already holds, after a restart.
    ///
    /// # Errors
    /// A wrong passphrase, or no such room.
    pub async fn open_room(&self, room: String, passphrase: String) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        self.apply(
            "opening the room",
            NodeCommand::OpenChannel {
                channel_id,
                passphrase: Secret::new(passphrase.into_bytes()),
            },
        )
        .await
    }

    /// Join a room from a `vox://` link; returns its id.
    ///
    /// # Errors
    /// A wrong passphrase, or no member could be reached.
    pub async fn join_room(
        &self,
        link: String,
        name: String,
        passphrase: String,
    ) -> Result<String, VoxError> {
        let before: Vec<Digest32> = self
            .node
            .view()
            .channels
            .iter()
            .map(|c| c.channel_id)
            .collect();
        self.apply(
            "joining the room",
            NodeCommand::JoinChannel {
                link,
                local_name: name,
                passphrase: Secret::new(passphrase.into_bytes()),
            },
        )
        .await?;
        self.node
            .view()
            .channels
            .iter()
            .find(|c| !before.contains(&c.channel_id))
            .map(|c| b32_encode(&c.channel_id))
            .ok_or_else(|| failed("joined, but the room is not listed"))
    }

    /// A `vox://` link for a room, for someone else to join with.
    ///
    /// # Errors
    /// If the room is not open.
    pub async fn invite(&self, room: String) -> Result<String, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let node = self.node.clone();
        self.on_node(async move {
            let mut events = node.subscribe();
            outcome(
                "inviting",
                node.apply(NodeCommand::Invite { channel_id }).await,
            )?;
            loop {
                match events.next().await {
                    Some(EventStreamItem::Event(NodeEvent::InviteLink { channel_id: c, url }))
                        if c == channel_id =>
                    {
                        return Ok(url)
                    }
                    Some(_) => {}
                    None => return Err(failed("the node stopped")),
                }
            }
        })
        .await
    }

    /// Post a message to a room.
    ///
    /// # Errors
    /// If the room is not open.
    pub async fn post(&self, room: String, text: String) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        self.apply("posting", NodeCommand::SendText { channel_id, text })
            .await
    }

    /// A room's readable messages, oldest first.
    ///
    /// # Errors
    /// If the room is not open.
    pub fn read(&self, room: String) -> Result<Vec<Message>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let view = self.node.view();
        let detail = view
            .open_channels
            .iter()
            .find(|d| d.channel_id == channel_id)
            .ok_or_else(|| failed("that room is not open"))?;
        Ok(detail.timeline.iter().map(message).collect())
    }

    /// Deliver this node's events to `listener` until the node stops.
    ///
    /// Every message that becomes readable is delivered once through
    /// [`EventListener::on_message`] — this node's own posts, and others' as sync brings
    /// them in or a sender key makes them readable. The node's own `NewEntry` event covers
    /// only local posts, so after every event the open rooms' timelines are compared with
    /// what was already delivered. Messages already readable when this is called are not
    /// delivered again: [`VoxNode::read`] has them.
    pub fn subscribe(&self, listener: Arc<dyn EventListener>) {
        let mut events = self.node.subscribe();
        let node = self.node.clone();
        let mut delivered: std::collections::HashSet<Digest32> = node
            .view()
            .open_channels
            .iter()
            .flat_map(|d| d.timeline.iter().map(|r| r.entry_hash))
            .collect();
        let mut view = node.watch();
        self.rt.spawn(async move {
            loop {
                // The view is republished after the event that changed it, so a new row
                // may appear with the view rather than with the event: watch both.
                tokio::select! {
                    item = events.next() => match item {
                        None => return,
                        Some(EventStreamItem::Event(NodeEvent::NewEntry { .. })) => {}
                        Some(EventStreamItem::Event(other)) => {
                            listener.on_notice(format!("{other:?}"));
                        }
                        Some(EventStreamItem::Lagged(n)) => listener.on_notice(format!(
                            "missed {n} events; read the rooms again for what is current"
                        )),
                    },
                    changed = view.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                let current = view.borrow_and_update().clone();
                for room in current.open_channels {
                    for row in &room.timeline {
                        if delivered.insert(row.entry_hash) {
                            listener.on_message(b32_encode(&room.channel_id), message(row));
                        }
                    }
                }
            }
        });
    }

    /// Trust an identity, node-wide, under `name` (ADR-020 §3): it may read what this
    /// node writes, and open app streams to it.
    ///
    /// # Errors
    /// A malformed fingerprint, or the keyring could not be saved.
    pub async fn trust(&self, fingerprint: String, name: String) -> Result<(), VoxError> {
        let fingerprint = digest(&fingerprint, "fingerprint")?;
        self.apply(
            "trusting",
            NodeCommand::Trust {
                fingerprint,
                petname: name,
            },
        )
        .await
    }

    /// Stop trusting an identity, and change the lock (ADR-017 M17.14).
    ///
    /// # Errors
    /// A malformed fingerprint, or one that was not trusted.
    pub async fn untrust(&self, fingerprint: String) -> Result<(), VoxError> {
        let fingerprint = digest(&fingerprint, "fingerprint")?;
        self.apply("untrusting", NodeCommand::Untrust { fingerprint })
            .await
    }

    /// Listen for app streams speaking `label`, in `room` or (empty) any room.
    ///
    /// # Errors
    /// A label that is not one, or another listener for it.
    pub fn app_listen(&self, room: String, label: String) -> Result<Arc<AppListener>, VoxError> {
        let room = if room.is_empty() {
            None
        } else {
            Some(digest(&room, "room id")?)
        };
        let inner = self
            .node
            .app()
            .listen(room, &label)
            .map_err(|e| failed(e.to_string()))?;
        Ok(Arc::new(AppListener {
            inner: Arc::new(tokio::sync::Mutex::new(inner)),
            hub: Arc::clone(self.node.app()),
            rt: self.rt.clone(),
        }))
    }

    /// Open an app stream to `peer` in `room`, speaking the first of `labels` it listens
    /// for, with a datagram flow if `datagrams`.
    ///
    /// # Errors
    /// The peer is not in this node's keyring, refused, or could not be reached.
    pub async fn app_open(
        &self,
        room: String,
        peer: String,
        labels: Vec<String>,
        datagrams: bool,
    ) -> Result<Arc<AppStream>, VoxError> {
        let (room, peer) = (digest(&room, "room id")?, digest(&peer, "fingerprint")?);
        let hub = Arc::clone(self.node.app());
        let stream = self
            .on_node(async move {
                hub.open(room, peer, labels, datagrams)
                    .await
                    .map_err(|e| failed(e.to_string()))
            })
            .await?;
        Ok(Arc::new(AppStream {
            inner: Arc::new(stream),
            rt: self.rt.clone(),
        }))
    }
}

fn message(row: &vox_core::node::api::MessageRow) -> Message {
    Message {
        id: b32_encode(&row.entry_hash),
        author: b32_encode(&row.author),
        created_millis: row.created_millis,
        text: row.text.clone(),
    }
}

/// A listening registration for app streams. Dropping it stops listening.
#[derive(uniffi::Object)]
pub struct AppListener {
    inner: Arc<tokio::sync::Mutex<vox_core::node::app::AppListener>>,
    hub: Arc<vox_core::node::app::AppHub>,
    rt: Handle,
}

#[uniffi::export]
impl AppListener {
    /// The next incoming stream, or `None` once the node has stopped.
    pub async fn next(&self) -> Option<AppIncoming> {
        let inner = Arc::clone(&self.inner);
        self.rt
            .spawn(async move { inner.lock().await.next().await })
            .await
            .ok()
            .flatten()
            .map(|i| AppIncoming {
                id: i.id,
                room: b32_encode(&i.channel_id),
                peer: b32_encode(&i.peer),
                label: i.label,
            })
    }

    /// Accept incoming stream `id`.
    ///
    /// # Errors
    /// If it is no longer waiting.
    pub async fn accept(&self, id: u64) -> Result<Arc<AppStream>, VoxError> {
        let hub = Arc::clone(&self.hub);
        let stream = self
            .rt
            .spawn(async move { hub.accept(id).await.map_err(|e| failed(e.to_string())) })
            .await
            .map_err(|_| failed("the node stopped"))??;
        Ok(Arc::new(AppStream {
            inner: Arc::new(stream),
            rt: self.rt.clone(),
        }))
    }
}

/// A live app stream to another member's app, with its datagram flow if one was asked
/// for. Ends when dropped, or when trust is withdrawn on either side.
#[derive(uniffi::Object)]
pub struct AppStream {
    inner: Arc<vox_core::node::app::AppStream>,
    rt: Handle,
}

#[uniffi::export]
impl AppStream {
    /// The label both sides speak.
    #[must_use]
    pub fn label(&self) -> String {
        self.inner.info().label.clone()
    }

    /// The other side's fingerprint, base32.
    #[must_use]
    pub fn peer(&self) -> String {
        b32_encode(&self.inner.info().peer)
    }

    /// Up to `max` bytes, or `None` at the peer's end of stream.
    ///
    /// # Errors
    /// The stream failed, or trust was withdrawn.
    pub async fn read(&self, max: u32) -> Result<Option<Vec<u8>>, VoxError> {
        let inner = Arc::clone(&self.inner);
        self.rt
            .spawn(async move {
                let mut buf = vec![0u8; max.max(1) as usize];
                match inner.read(&mut buf).await {
                    Ok(Some(n)) => {
                        buf.truncate(n);
                        Ok(Some(buf))
                    }
                    Ok(None) => Ok(None),
                    Err(e) => Err(failed(e.to_string())),
                }
            })
            .await
            .map_err(|_| failed("the node stopped"))?
    }

    /// Write all of `data`.
    ///
    /// # Errors
    /// The stream failed, or trust was withdrawn.
    pub async fn write(&self, data: Vec<u8>) -> Result<(), VoxError> {
        let inner = Arc::clone(&self.inner);
        self.rt
            .spawn(async move {
                inner
                    .write_all(&data)
                    .await
                    .map_err(|e| failed(e.to_string()))
            })
            .await
            .map_err(|_| failed("the node stopped"))?
    }

    /// End this side's half of the stream.
    pub async fn finish(&self) {
        let inner = Arc::clone(&self.inner);
        let _ = self.rt.spawn(async move { inner.finish().await }).await;
    }

    /// Send one datagram on the flow. Like UDP, delivery is not confirmed.
    ///
    /// # Errors
    /// No flow was asked for, it ended, or trust was withdrawn.
    pub fn send_datagram(&self, data: Vec<u8>) -> Result<(), VoxError> {
        self.inner
            .send_datagram(&data)
            .map_err(|e| failed(e.to_string()))
    }

    /// The next datagram, or `None` once the flow has ended.
    pub async fn recv_datagram(&self) -> Option<Vec<u8>> {
        let inner = Arc::clone(&self.inner);
        self.rt
            .spawn(async move { inner.recv_datagram().await })
            .await
            .ok()
            .flatten()
    }
}
