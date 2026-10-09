//! The daemon's router: which nodes are attached, and every change to that (ADR-026 §3).
//!
//! One [`Router`] per daemon. Each node is in exactly one state at a time, `detached → attaching →
//! attached → detaching → detached` (L-1), and every transition of one node goes through the
//! router's one table, so two clients attaching the same node end with one attach (L-2) and a
//! holder that arrives while the last one leaves never finds its node half gone (L-3).
//!
//! - **Attach** (L-2) opens the node's files, starts its actor as a task of its own, unlocks it with
//!   the passphrase it is given, reopens its rooms, starts its tasks ([`NodeTasks`]) and watches the
//!   actor. The table is never locked across any of that: the slot says `Attaching`, and anyone else
//!   who wants the node waits for the outcome.
//! - **Holders** (L-3): a node attached implicitly counts the connections that hold it and the agent
//!   sessions registered as it. The decision to detach it is taken in the same critical section as
//!   the release or the unregister that brought the count to zero, and moves the slot to
//!   `Detaching` there, so nothing can take a new hold on a node that is going.
//! - **Detach** (L-3) tells every connection acting as the node (they answer "node detached"),
//!   stops its tasks, stops its actor within the daemon's patience, and frees the slot.
//! - **A panic** in a node's actor (L-6) detaches that node, says so on stderr, counts it, and emits
//!   the event; the daemon and every other node go on.
//! - **`--keep`** (L-4) records a node in `.daemon/attach` with its passphrase source; the daemon
//!   attaches every kept node again when it starts.
//!
//! There is no locked state (N-2): a node takes its passphrase once, when it attaches.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::{broadcast, watch};
use vox_core::hash::Digest32;
use vox_core::nat::bootstrap::BootstrapSet;
use vox_core::node::actor::{ActorEnd, Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{Fault, NodeCommand, Outcome, Secret};
use vox_core::node::daemonipc::{
    DaemonEvent, DaemonFrame, DaemonRequest, DaemonStatus, DetachCause, KeepSource, NodeInfo,
    NodeState, Refusal, UseNode,
};
use vox_core::node::ipc::{Dispatch, Lease};
use vox_core::node::paths::{Account, NodeName, Paths};
use vox_core::node::status::DaemonMetrics;
use zeroize::Zeroizing;

use crate::node_tasks::NodeTasks;

/// How long an attach keeps retrying a node directory another process is still letting go of.
const PROFILE_RELEASE_PATIENCE: Duration = Duration::from_secs(5);

/// Where a node binds when it attaches, by its name.
pub type BindFor = Arc<dyn Fn(&NodeName) -> Option<Bind> + Send + Sync>;

/// What the daemon attaches every node with.
pub struct Defaults {
    /// Where a node binds when it attaches (ADR-026 D-3): the daemon's one presence once it is
    /// shared; `None` attaches a node off the network.
    pub bind: BindFor,
    /// The daemon's anchors (`--anchor`), given to every node beside its own anchors file.
    pub anchors: BootstrapSet,
    /// The specs the anchors came from, which a node's anchor follow re-resolves.
    pub anchor_specs: Vec<String>,
    /// The address the daemon listens on, as its status says it.
    pub listen: String,
    /// How long a node's stop may take before it is left (the daemon's shutdown patience).
    pub patience: Duration,
    /// Where the daemon's `.vox` proxy listens while a node is attached (ADR-028 S-5); `None`
    /// runs none.
    pub proxy: Option<std::net::SocketAddr>,
}

/// The daemon's router. Cheap to clone; every clone is the same router.
#[derive(Clone)]
pub struct Router {
    inner: Arc<Inner>,
}

struct Inner {
    account: Account,
    rt: Handle,
    defaults: Defaults,
    slots: Mutex<BTreeMap<NodeName, Slot>>,
    /// For a headless node in the anchor role, the creators whose rooms it serves; absent, any
    /// room (`vox node --serve`, ADR-026 N-5).
    serve_only: Mutex<BTreeMap<NodeName, BTreeSet<Digest32>>>,
    events: broadcast::Sender<DaemonEvent>,
    metrics: Arc<DaemonMetrics>,
    stopping: AtomicBool,
    next_generation: AtomicU64,
    stop_asked: tokio::sync::Notify,
    /// A node's stop that did not finish within the patience: the daemon's stop then says so.
    unfinished_stop: AtomicBool,
    /// Open connections to the account socket.
    connections: Arc<std::sync::atomic::AtomicUsize>,
    /// The daemon's `.vox` proxy, run while any node is attached (ADR-028 S-5).
    proxy: Option<Arc<crate::daemon_proxy::DaemonProxy>>,
    /// Held while `.daemon/attach` is rewritten and while a Keychain item is stored or removed:
    /// one writer at a time, and a removal never overtakes a later store of the same item.
    keep_file: tokio::sync::Mutex<()>,
    /// Each node's joins of its sessions' rooms under way (ADR-029 RB-3).
    joins: Mutex<BTreeMap<NodeName, Arc<vox_core::node::room_join::Joins>>>,
    /// Where harness sessions' activity is numbered and posted, and approvals wait (ADR-029).
    sink: Arc<crate::session_sink::Sink>,
    /// One queue per (node, session) into its Session, so its entries keep their order.
    posting: Mutex<BTreeMap<(NodeName, String), tokio::sync::mpsc::UnboundedSender<String>>>,
    /// Codex sessions' activity, read from Codex's app-server as a peer client (ADR-029 #541).
    codex: Arc<crate::codex_mirror::CodexMirror>,
    /// OpenCode sessions' activity, read through Vox's OpenCode plugin (ADR-029 #542).
    opencode: Arc<crate::opencode_mirror::OpenCodeMirror>,
}

/// A member's answer as the sink took it: handed to the harness, or why not.
fn handed(h: crate::session_sink::Handed) -> Result<String, String> {
    match h {
        crate::session_sink::Handed::ToHarness => Ok("handed to the session; it decides".into()),
        crate::session_sink::Handed::Refused(why) => Err(why),
    }
}

/// One node's place in its life (L-1). A node with no slot is detached.
enum Slot {
    /// Being attached; the outcome arrives here.
    Attaching(watch::Receiver<Option<Result<(), Refusal>>>),
    /// Running.
    Attached(Box<Attached>),
    /// Being detached; `true` arrives once it is gone.
    Detaching(watch::Receiver<bool>),
}

/// An attached node.
struct Attached {
    handle: NodeHandle,
    paths: Paths,
    /// Which attach this is: a release or a panic meant for an earlier one changes nothing.
    generation: u64,
    /// Attached implicitly: it detaches when its last holder goes (L-3).
    implicit: bool,
    /// Recorded in `.daemon/attach`, with its passphrase source (L-4).
    keep: Option<KeepSource>,
    /// Connections holding it (L-7).
    holders: u32,
    /// Agent sessions registered as it (ADR-020 6.10).
    sessions: BTreeSet<String>,
    tasks: Option<NodeTasks>,
    /// Turned `true` when it detaches: every connection acting as it answers "node detached".
    detached: watch::Sender<bool>,
    /// What attaching it said (a skipped anchors line, a node carrying on with no anchor): logged
    /// by the daemon, and handed to the `Use` that attached it, for its client to print.
    notes: Vec<String>,
    /// Turned `true` when its actor has ended, however.
    ended: watch::Receiver<bool>,
    fingerprint: Option<Digest32>,
}

/// How a node is wanted, and so how its attach counts.
enum Want {
    /// `vox node attach` (or `--keep` at start): stays until detached by hand (L-3).
    Explicit(Option<KeepSource>),
    /// A held connection: attached implicitly if need be, and held while the connection is open.
    Hold,
    /// An agent session: only if attached already (ADR-028 K-13), and held while it is
    /// registered.
    Session(Box<crate::wake::Session>),
    /// Kept with its passphrase in the Keychain: attached by hand when this request attaches it,
    /// which proves the passphrase; found attached, left as it is, for the asker to check the
    /// passphrase before anything changes.
    Checked,
    /// A one-shot verb: only if it is attached already (L-2).
    IfAttached,
}

/// What attaching, or finding attached, gave the asker.
struct Granted {
    info: NodeInfo,
    handle: NodeHandle,
    detached: watch::Receiver<bool>,
    hold: Option<HolderGuard>,
    /// What attaching the node said, when this request attached it; empty when it was attached.
    notes: Vec<String>,
    /// This request attached it, with its passphrase.
    attached_now: bool,
    /// Which attach it is.
    generation: u64,
}

/// A held connection's hold on its node (L-3): released when dropped, and the release that leaves
/// an implicit node with no holder detaches it.
pub struct HolderGuard {
    router: Weak<Inner>,
    node: NodeName,
    generation: u64,
}

impl Drop for HolderGuard {
    fn drop(&mut self) {
        let Some(inner) = self.router.upgrade() else {
            return;
        };
        let going = {
            let mut slots = lock(&inner.slots);
            match slots.get_mut(&self.node) {
                Some(Slot::Attached(a)) if a.generation == self.generation => {
                    a.holders = a.holders.saturating_sub(1);
                    if a.implicit && a.holders == 0 && a.sessions.is_empty() {
                        begin_detach(&mut slots, &self.node)
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };
        if let Some((a, done)) = going {
            let router = Router {
                inner: Arc::clone(&inner),
            };
            let node = self.node.clone();
            inner.rt.spawn(async move {
                router
                    .finish_detach(node, a, done, DetachCause::LastHolder)
                    .await;
            });
        }
    }
}

/// The table, even after a panic elsewhere poisoned it (L-6: process-wide state tolerates a
/// poisoned lock). Never held across an await.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Move `node` from `Attached` to `Detaching`, inside the critical section that decided it, and
/// hand back what is to be stopped and the sender that says it is gone.
fn begin_detach(
    slots: &mut BTreeMap<NodeName, Slot>,
    node: &NodeName,
) -> Option<(Box<Attached>, watch::Sender<bool>)> {
    let (tx, rx) = watch::channel(false);
    match slots.insert(node.clone(), Slot::Detaching(rx)) {
        Some(Slot::Attached(a)) => Some((a, tx)),
        Some(other) => {
            slots.insert(node.clone(), other);
            None
        }
        None => {
            slots.remove(node);
            None
        }
    }
}

impl Router {
    /// A router for `account`'s nodes, on `rt`.
    #[must_use]
    pub fn new(account: Account, rt: Handle, defaults: Defaults) -> Self {
        let proxy = defaults
            .proxy
            .map(|bind| Arc::new(crate::daemon_proxy::DaemonProxy::new(bind)));
        let router = Self {
            inner: Arc::new_cyclic(|weak: &std::sync::Weak<Inner>| {
                let (weak, weak_rename) = (weak.clone(), weak.clone());
                let sink = crate::session_sink::Sink::new(
                    Arc::new(move |node: &NodeName, session: &str, bodies: Vec<String>| {
                        if let Some(inner) = weak.upgrade() {
                            Router { inner }.post_session(node, session, bodies);
                        }
                    }),
                    Arc::new(move |node: &NodeName, session: &str, name: &str| {
                        if let Some(inner) = weak_rename.upgrade() {
                            Router { inner }.rename_session(node, session, name);
                        }
                    }),
                );
                let codex = crate::codex_mirror::CodexMirror::new(Arc::clone(&sink));
                let opencode = crate::opencode_mirror::OpenCodeMirror::new(Arc::clone(&sink));
                Inner {
                    codex,
                    opencode,
                    account,
                    rt,
                    defaults,
                    slots: Mutex::new(BTreeMap::new()),
                    events: broadcast::channel(256).0,
                    metrics: Arc::new(DaemonMetrics::default()),
                    stopping: AtomicBool::new(false),
                    next_generation: AtomicU64::new(1),
                    stop_asked: tokio::sync::Notify::new(),
                    serve_only: Mutex::default(),
                    unfinished_stop: AtomicBool::new(false),
                    connections: Arc::default(),
                    proxy,
                    keep_file: tokio::sync::Mutex::new(()),
                    sink,
                    posting: Mutex::default(),
                    joins: Mutex::default(),
                }
            }),
        };
        router.follow_attached_with_the_proxy();
        router
    }

    /// The proxy runs while any node is attached: bound at the first attach, stopped at the last
    /// detach. Driven by the router's own events, on a task of its own, so no attach or detach
    /// waits on a bind. It holds the router weakly, so it ends with the router.
    fn follow_attached_with_the_proxy(&self) {
        if self.inner.proxy.is_none() {
            return;
        }
        let mut events = self.inner.events.subscribe();
        let weak = Arc::downgrade(&self.inner);
        self.inner.rt.spawn(async move {
            proxy_follow(&weak);
            loop {
                match events.recv().await {
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => proxy_follow(&weak),
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    /// The daemon's own metrics (attached nodes, panics).
    #[must_use]
    pub fn metrics(&self) -> Arc<DaemonMetrics> {
        Arc::clone(&self.inner.metrics)
    }

    /// Wait until a client asks the daemon to stop ([`DaemonRequest::Stop`]).
    pub async fn stop_asked(&self) {
        self.inner.stop_asked.notified().await;
    }

    /// Serve only rooms made by `creators` from headless node `node`, the next time it attaches
    /// in the anchor role (`vox node --serve trusted`).
    pub fn serve_only(&self, node: &NodeName, creators: BTreeSet<Digest32>) {
        lock(&self.inner.serve_only).insert(node.clone(), creators);
    }

    /// The attached nodes and their handles, for the metrics endpoint.
    #[must_use]
    pub fn attached_handles(&self) -> Vec<(String, NodeHandle)> {
        lock(&self.inner.slots)
            .iter()
            .filter_map(|(n, s)| match s {
                Slot::Attached(a) => Some((n.as_str().to_owned(), a.handle.clone())),
                _ => None,
            })
            .collect()
    }

    /// Every node: each on disk, and any slot besides, with its state.
    #[must_use]
    pub fn nodes(&self) -> Vec<NodeInfo> {
        let slots = lock(&self.inner.slots);
        let mut names: BTreeSet<NodeName> =
            self.inner.account.nodes_on_disk().into_iter().collect();
        names.extend(slots.keys().cloned());
        names
            .into_iter()
            .map(|name| info_of(&name, slots.get(&name)))
            .collect()
    }

    /// The attached nodes, as the hello says them.
    #[must_use]
    pub fn attached(&self) -> Vec<NodeInfo> {
        let slots = lock(&self.inner.slots);
        slots
            .iter()
            .filter(|(_, s)| matches!(s, Slot::Attached(_)))
            .map(|(n, s)| info_of(n, Some(s)))
            .collect()
    }

    /// Attach `node` by hand (`vox node attach`), recording it in the attach file when `keep` is
    /// given (L-4). Idempotent: an attached node stays as it is, and is now held by hand.
    ///
    /// # Errors
    /// The [`Refusal`] that says why it could not be attached.
    pub async fn attach(
        &self,
        node: &NodeName,
        passphrase: Option<Zeroizing<String>>,
        keep: Option<KeepSource>,
        rooms: Vec<Zeroizing<String>>,
        anchors: Vec<String>,
    ) -> Result<NodeInfo, Refusal> {
        self.attach_noting(node, passphrase, keep, rooms, anchors)
            .await
            .map(|(info, _)| info)
    }

    /// [`Self::attach`], with what attaching the node said when this call attached it.
    ///
    /// # Errors
    /// As [`Self::attach`].
    pub async fn attach_noting(
        &self,
        node: &NodeName,
        passphrase: Option<Zeroizing<String>>,
        keep: Option<KeepSource>,
        rooms: Vec<Zeroizing<String>>,
        anchors: Vec<String>,
    ) -> Result<(NodeInfo, Vec<String>), Refusal> {
        if matches!(keep, Some(KeepSource::Keychain(_))) {
            return self
                .keep_in_keychain(node, passphrase, rooms, anchors)
                .await;
        }
        let g = self
            .want(node, Want::Explicit(keep), passphrase, rooms, anchors)
            .await?;
        self.write_attach_file(None).await;
        Ok((g.info, g.notes))
    }

    /// **Kept with its passphrase in the Keychain** (ADR-028 K-10, ADR-014 M-6): stored only once
    /// the passphrase is proved, so a passphrase nothing checked is never stored. Attaching the
    /// node with it proves it; a node attached already, by another client or by hand, has it
    /// checked against its vault first. A store that fails leaves the node attached but not
    /// kept, and nothing in the Keychain, so the same request can simply be made again. The
    /// daemon names the item by the node's own directory.
    async fn keep_in_keychain(
        &self,
        node: &NodeName,
        passphrase: Option<Zeroizing<String>>,
        rooms: Vec<Zeroizing<String>>,
        anchors: Vec<String>,
    ) -> Result<(NodeInfo, Vec<String>), Refusal> {
        let failed = |why: String| Refusal::Failed {
            node: node.clone(),
            why,
        };
        let Some(secret) = passphrase.clone() else {
            return Err(failed(
                "keeping a node with its passphrase in the Keychain needs the passphrase".into(),
            ));
        };
        let mut g = self
            .want(node, Want::Checked, passphrase, rooms, anchors)
            .await?;
        if !g.attached_now {
            match g
                .handle
                .apply(NodeCommand::VerifyPassphrase {
                    passphrase: Secret::new(secret.as_bytes().to_vec()),
                })
                .await
            {
                Outcome::Done => {}
                Outcome::Failed(Fault::WrongPassphrase) => {
                    return Err(failed(format!(
                        "that is not node {node}'s identity passphrase, so nothing was stored"
                    )))
                }
                other => {
                    return Err(failed(format!(
                        "its passphrase could not be checked ({other}), so nothing was stored"
                    )))
                }
            }
        }
        let account = self.keychain_account(node);
        let _file = self.inner.keep_file.lock().await;
        let stored = {
            let account = account.clone();
            tokio::task::spawn_blocking(move || crate::keychain::store(&account, &secret))
                .await
                .unwrap_or_else(|e| Err(format!("the store was cut short: {e}")))
        };
        let kept = {
            let mut slots = lock(&self.inner.slots);
            match slots.get_mut(node) {
                Some(Slot::Attached(a)) if a.generation == g.generation => {
                    if stored.is_ok() {
                        a.implicit = false;
                        a.keep = Some(KeepSource::Keychain(account.clone()));
                    }
                    g.info = info_of_attached(node, a);
                    true
                }
                _ => false,
            }
        };
        if !kept || stored.is_err() {
            // Nothing is left in the Keychain that the attach file does not name.
            forget_in_keychain(account).await;
        }
        if !kept {
            return Err(failed(format!(
                "node {node} was detached while it was being kept, so nothing is kept"
            )));
        }
        if let Err(e) = stored {
            g.notes.push(format!(
                "node {node} is attached, but not kept: its passphrase could not be stored in \
                 the Keychain: {e}"
            ));
        }
        self.write_attach_file_held(None).await;
        Ok((g.info, g.notes))
    }

    /// Stop keeping `node` (ADR-014 M-6, #571): Vox.app's Keep Running turned off. Its line leaves
    /// the attach file, and with it any Keychain item it names, so the daemon does not attach it
    /// again at its next start. Attached and held by a client, it becomes a held node, detached
    /// when its last holder goes; it is not detached now, so the app that turned Keep Running off
    /// goes on acting as it.
    ///
    /// # Errors
    /// [`Refusal::NoSuchNode`] for a node that is not on disk.
    pub async fn unkeep(&self, node: &NodeName) -> Result<(), Refusal> {
        if !self.inner.account.nodes_on_disk().contains(node) {
            return Err(Refusal::NoSuchNode { node: node.clone() });
        }
        let _file = self.inner.keep_file.lock().await;
        {
            let mut slots = lock(&self.inner.slots);
            if let Some(Slot::Attached(a)) = slots.get_mut(node) {
                if a.keep.take().is_some() && a.holders > 0 {
                    a.implicit = true;
                }
            }
        }
        self.write_attach_file_held(Some(node)).await;
        Ok(())
    }

    /// The Keychain account a kept node's passphrase is stored under: its directory.
    fn keychain_account(&self, node: &NodeName) -> String {
        self.inner
            .account
            .node_dir(node)
            .to_string_lossy()
            .into_owned()
    }

    /// Grant a connection's `Use` (C-2), attaching the node implicitly when the `Use` holds it.
    ///
    /// # Errors
    /// The [`Refusal`] the client is told.
    pub async fn use_node(&self, u: UseNode) -> Result<Lease, Refusal> {
        let want = match u.attach {
            vox_core::node::daemonipc::AttachMode::No => Want::IfAttached,
            vox_core::node::daemonipc::AttachMode::Hold => Want::Hold,
        };
        let g = self
            .want(&u.node, want, u.passphrase, Vec::new(), u.anchors)
            .await?;
        let drive = (Arc::downgrade(&self.inner), u.node.clone());
        Ok(Lease {
            node: u.node,
            handle: g.handle,
            detached: g.detached,
            hold: g
                .hold
                .map(|h| Box::new(h) as Box<dyn std::any::Any + Send + Sync>),
            // `vox lan up`: the daemon asks the root helper for the device itself (S-5); and
            // `vox up`: the daemon says where its proxy is (ADR-028 S-5).
            extension: Some(std::sync::Arc::new(DaemonExtension {
                drive,
                proxy: self.inner.proxy.as_ref().map(|proxy| {
                    let weak = Arc::downgrade(&self.inner);
                    crate::daemon_proxy::ProxyReport {
                        proxy: Arc::clone(proxy),
                        up: Arc::new(move || proxy_follow(&weak)),
                    }
                }),
            })),
            notes: g.notes,
        })
    }

    /// Register an agent session of `node` (ADR-020 6.10): store its record and count it as a
    /// holder. **A session never attaches its node** (ADR-028 K-13): one not attached is refused
    /// [`Refusal::NotAttached`], and its operator attaches it outside the session.
    ///
    /// # Errors
    /// The [`Refusal`] the hook is told.
    pub async fn session_register(
        &self,
        node: &NodeName,
        session: crate::wake::Session,
        join: Option<(String, Zeroizing<String>)>,
    ) -> Result<DaemonFrame, Refusal> {
        // A node that does not exist is said as that, not as one to attach.
        if !self.inner.account.nodes_on_disk().contains(node) {
            return Err(Refusal::NoSuchNode { node: node.clone() });
        }
        // Whether this node knew the session before this turn: its registration on disk.
        let known = self
            .inner
            .account
            .node_paths(node)
            .is_ok_and(|p| p.session_file(&session.session).is_file());
        let id = session.session.clone();
        let asked = session.room.clone();
        // The tmux pane the hook claims is proven here, from tmux and the process table, while the
        // hook waits (ADR-029 DR-5): never stored as claimed.
        let mut session = session;
        if let Some(claim) = session.tmux_claim.take() {
            let proven = {
                let config = self.inner.account.config_dir.clone();
                tokio::task::spawn_blocking(move || {
                    crate::claude_injector::prove(
                        &claim,
                        &crate::claude_injector::harnesses(&config),
                    )
                })
                .await
            };
            match proven {
                Ok(Ok(pane)) => session.tmux = Some(pane),
                Ok(Err(why)) => session.tmux_why = Some(why),
                Err(e) => session.tmux_why = Some(format!("the pane could not be proven: {e}")),
            }
        }
        let g = self
            .want(
                node,
                Want::Session(Box::new(session)),
                None,
                Vec::new(),
                Vec::new(),
            )
            .await?;
        let handle = self.handle_of(node);
        // A room the hook named by a prefix of its id is resolved against the node's rooms, now
        // that the node is attached, and kept by its whole id.
        if let (Some(h), Ok(paths)) = (handle.as_ref(), self.inner.account.node_paths(node)) {
            let named = crate::wake::registration(&paths, &id).and_then(|r| r.room);
            if let Some(prefix) =
                named.filter(|r| vox_core::node::link::b32_decode(r, "room").is_err())
            {
                let whole: Vec<String> = h
                    .view()
                    .channels
                    .iter()
                    .map(|c| vox_core::node::link::b32_encode(&c.channel_id))
                    .filter(|c| c.starts_with(prefix.trim()))
                    .collect();
                if let [one] = whole.as_slice() {
                    crate::wake::store_room(&paths, &id, one);
                }
            }
        }
        // The record as stored: the room a session works in is kept for its life (RB-4).
        let stored = self
            .inner
            .account
            .node_paths(node)
            .ok()
            .and_then(|p| crate::wake::registration(&p, &id));
        let room = stored.as_ref().and_then(|r| r.room.clone());
        let mut joining = None;
        // A join is for the room this turn named, and only when that is the session's room: a
        // session keeps the room it started with (RB-4), so a later lookup joins nothing.
        let join = join.filter(|_| asked.is_some() && asked == room);
        if let (Some(handle), Some(reg)) = (handle.as_ref(), stored.as_ref()) {
            joining = self.open_session(node, handle, reg, join).await;
        }
        // **New** is new to this node: no registration before, and no Session of it in any room
        // its log holds, so a daemon restarted mid-session still knows it (ADR-029 RB-5).
        let seen = handle.as_ref().is_some_and(|h| {
            let me = h.view().identity.as_ref().map(|i| i.fingerprint);
            h.view().open_channels.iter().any(|d| {
                vox_core::node::sessions::fold(d)
                    .iter()
                    .any(|s| Some(s.node) == me && s.id == id)
            })
        });
        Ok(DaemonFrame::SessionRegistered {
            info: g.info,
            room,
            new: !known && !seen,
            joining,
        })
    }

    /// Open `reg`'s Session in its room (ADR-029 SE-1): at once when the node is a member, or once
    /// a join from the room map (`join`) makes it one. A headless session gets none, and neither
    /// does a hook run by hand, with no harness behind it. What a join under way says, for the
    /// session.
    async fn open_session(
        &self,
        node: &NodeName,
        handle: &vox_core::node::actor::NodeHandle,
        reg: &crate::wake::Session,
        join: Option<(String, Zeroizing<String>)>,
    ) -> Option<String> {
        let room_b32 = reg.room.as_ref()?;
        if !reg.interactive || reg.harness == "unknown" {
            return None;
        }
        let room = vox_core::node::link::b32_decode(room_b32, "room").ok()?;
        let opening = vox_core::node::sessions::Opening {
            id: reg.session.clone(),
            harness: reg.harness.clone(),
            name: reg.name.clone(),
        };
        let member = handle.view().channels.iter().any(|c| c.channel_id == room);
        let joins = Arc::clone(lock(&self.inner.joins).entry(node.clone()).or_default());
        if member {
            joins.set_status(room_b32, None);
            if let Err(e) = vox_core::node::sessions::open_when_member(handle, room, &opening).await
            {
                return Some(format!(
                    "could not open this session's Session in its room: {e}"
                ));
            }
            return None;
        }
        if let Some((link, passphrase)) = join {
            vox_core::node::room_join::join_in_background(
                handle, &joins, room_b32, &link, passphrase, opening,
            );
        }
        joins.status(room_b32)
    }

    /// Move `session` of `node` to `room` (ADR-029 RB-5): its Session ends in the room it worked in,
    /// and one opens in `room`.
    ///
    /// # Errors
    /// The [`Refusal`] the caller is told.
    pub async fn session_room(
        &self,
        node: &NodeName,
        session: &str,
        room: &str,
    ) -> Result<DaemonFrame, Refusal> {
        let failed = |why: String| Refusal::Failed {
            node: node.clone(),
            why,
        };
        let paths = self
            .inner
            .account
            .node_paths(node)
            .map_err(|e| failed(e.to_string()))?;
        let handle = self
            .handle_of(node)
            .ok_or_else(|| Refusal::NotAttached { node: node.clone() })?;
        vox_core::node::link::b32_decode(room, "room").map_err(|e| failed(e.to_string()))?;
        let before = crate::wake::store_room(&paths, session, room)
            .ok_or_else(|| failed(format!("no session {session} is registered")))?;
        if let Some(old) = before.filter(|old| old != room) {
            if let Ok(old) = vox_core::node::link::b32_decode(&old, "room") {
                let _ = vox_core::node::sessions::end(&handle, old, session, "moved").await;
            }
        }
        let reg = crate::wake::registration(&paths, session)
            .ok_or_else(|| failed(format!("no session {session} is registered")))?;
        let joining = self.open_session(node, &handle, &reg, None).await;
        Ok(DaemonFrame::SessionRegistered {
            info: self
                .nodes()
                .into_iter()
                .find(|n| n.name == *node)
                .ok_or_else(|| Refusal::NotAttached { node: node.clone() })?,
            room: Some(room.to_owned()),
            new: false,
            joining,
        })
    }

    /// Listen for drive input to `node`'s sessions ([`crate::drive`]) until the node detaches.
    fn serve_drive(
        &self,
        node: &NodeName,
        handle: &NodeHandle,
        mut detached: watch::Receiver<bool>,
    ) {
        let hub = Arc::clone(handle.app());
        let mut listener = match hub.listen(None, crate::drive::LABEL) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("vox daemon: node {node} takes no drive input: {e}");
                return;
            }
        };
        let router = self.clone();
        let node = node.clone();
        let handle = handle.clone();
        tokio::spawn(async move {
            loop {
                let incoming = tokio::select! {
                    i = listener.next() => i,
                    _ = detached.wait_for(|d| *d) => None,
                };
                let Some(incoming) = incoming else { return };
                let (router, node, handle, hub) = (
                    router.clone(),
                    node.clone(),
                    handle.clone(),
                    Arc::clone(&hub),
                );
                tokio::spawn(async move {
                    let Ok(stream) = hub.accept(incoming.id).await else {
                        return;
                    };
                    router.drive_stream(&node, &handle, stream).await;
                });
            }
        });
    }

    /// Drive input for one of `node`'s own Sessions, from a client attached as `node` on its own
    /// socket ([`vox_core::node::drive_input::OwnDrive`]): the node is its Sessions' operator
    /// (ADR-029 SC-2), so it is handled as a member's stream is, from the node itself.
    async fn drive_own(
        &self,
        node: &NodeName,
        handle: &NodeHandle,
        own: vox_core::node::drive_input::OwnDrive,
        mut stream: tokio::net::UnixStream,
    ) {
        let answer = match handle.view().identity.map(|i| i.fingerprint) {
            Some(me) => {
                let info = vox_core::node::app::AppInfo {
                    channel_id: own.room,
                    peer: me,
                    label: crate::drive::LABEL.to_owned(),
                    datagrams: false,
                };
                self.drive(node, handle, &info, own.request).await
            }
            None => crate::drive::Answer {
                ok: false,
                said: "this node is locked; nothing was sent".into(),
                code: None,
            },
        };
        let _ = vox_core::node::ipc::write_frame(
            &mut stream,
            &vox_core::node::drive_input::own_answer(&answer),
        )
        .await;
    }

    /// One drive request on `stream`: read it, act on it, answer it, and say it in the Session.
    async fn drive_stream(
        &self,
        node: &NodeName,
        handle: &NodeHandle,
        stream: vox_core::node::app::AppStream,
    ) {
        use crate::drive::{Answer, MAX_REQUEST, PATIENCE};
        let info = stream.info().clone();
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 16 * 1024];
        let read = tokio::time::timeout(PATIENCE, async {
            while !buf.contains(&b'\n') && buf.len() <= MAX_REQUEST {
                match stream.read(&mut chunk).await {
                    Ok(Some(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                    _ => break,
                }
            }
        })
        .await;
        let line = buf.split(|b| *b == b'\n').next().unwrap_or_default();
        let answer = match (read, serde_json::from_slice::<crate::drive::Request>(line)) {
            (Err(_), _) => Answer {
                ok: false,
                said: "no drive request arrived in time".into(),
                code: None,
            },
            (_, Err(_)) if buf.len() > MAX_REQUEST => Answer {
                ok: false,
                said: "the drive request is too long".into(),
                code: None,
            },
            (_, Err(_)) => Answer {
                ok: false,
                said: "not a drive request this vox reads".into(),
                code: None,
            },
            (Ok(()), Ok(req)) => self.drive(node, handle, &info, req).await,
        };
        if let Ok(mut out) = serde_json::to_vec(&answer) {
            out.push(b'\n');
            let _ = stream.write_all(&out).await;
        }
        stream.finish().await;
    }

    /// Check a drive request and hand it to its session alone (ADR-029 DR-2, DR-5, DR-6, DR-7),
    /// writing what was driven and, when it was not delivered, why into the Session.
    async fn drive(
        &self,
        node: &NodeName,
        handle: &NodeHandle,
        info: &vox_core::node::app::AppInfo,
        req: crate::drive::Request,
    ) -> crate::drive::Answer {
        use crate::drive::{Action, Answer};
        let refuse = |said: String| Answer {
            ok: false,
            said,
            code: None,
        };
        if req.v != 1 {
            return refuse(format!(
                "drive protocol {} is not one this vox speaks",
                req.v
            ));
        }
        let view = handle.view();
        let me = view.identity.as_ref().map(|i| i.fingerprint);
        // DR-2: only a member this node trusts with drive, or the node itself, its Sessions'
        // operator (SC-2), which reaches here only from its own socket (`drive_own`).
        // Said without this node's name for itself, which the driver may not know it by: the
        // driver names it (`code`).
        if me != Some(info.peer) && !view.drive.contains(&info.peer) {
            return Answer {
                ok: false,
                said: vox_agentcomms::drive::no_drive("the session's node"),
                code: Some(vox_agentcomms::drive::NO_DRIVE.to_owned()),
            };
        }
        let Ok(paths) = self.inner.account.node_paths(node) else {
            return refuse("this node's files cannot be read".into());
        };
        // DR-5 and TA-5: exactly this session, open on this node, and none other.
        let Some(reg) = crate::wake::registration(&paths, &req.session) else {
            return refuse(
                "that session is not open on its node: it ended, or never registered there; nothing was sent to any other session"
                    .into(),
            );
        };
        let room = vox_core::node::link::b32_encode(&info.channel_id);
        if reg.room.as_deref() != Some(room.as_str()) {
            return refuse("that session does not work in this room; nothing was sent".into());
        }
        let by = vox_core::node::link::b32_encode(&info.peer);
        let alias = view
            .trusted
            .iter()
            .find(|(fp, _)| *fp == info.peer)
            .map_or_else(|| by.chars().take(8).collect(), |(_, n)| n.clone());
        let sink = &self.inner.sink;
        // What is driven, as this node's claim of who drove it (ADR-029 MD-3), written before it
        // is handed to the harness, so the Session shows it ahead of what it caused. An answer
        // shows on its request's line.
        let mut copy = serde_json::Map::new();
        copy.insert(
            "v".into(),
            serde_json::json!(vox_agentcomms::activity::VERSION),
        );
        copy.insert("session".into(), serde_json::json!(req.session));
        copy.insert("kind".into(), serde_json::json!("drive"));
        copy.insert("by".into(), serde_json::json!(by));
        copy.insert("action".into(), serde_json::json!(req.action.name()));
        match &req.action {
            Action::Text { text } => {
                copy.insert("text".into(), serde_json::json!(text));
            }
            Action::Slash { text } => {
                copy.insert("cmd".into(), serde_json::json!(crate::drive::slash(text).0));
                copy.insert("text".into(), serde_json::json!(text));
            }
            Action::Approve { r#ref }
            | Action::Reject { r#ref, .. }
            | Action::Answer { r#ref, .. } => {
                copy.insert("ref".into(), serde_json::json!(r#ref));
            }
            Action::Interrupt | Action::Stop => {}
            Action::File {
                name,
                size,
                sha256,
                tag,
                note,
            } => {
                copy.insert("name".into(), serde_json::json!(name));
                copy.insert("size".into(), serde_json::json!(size));
                copy.insert("sha256".into(), serde_json::json!(sha256));
                copy.insert("id".into(), serde_json::json!(tag));
                if let Some(note) = note {
                    copy.insert("note".into(), serde_json::json!(note));
                }
            }
        }
        sink.activity(
            node,
            &req.session,
            vox_agentcomms::activity::split(copy, "text", vox_core::node::content::MAX_TEXT_LEN),
            None,
        );
        let outcome: Result<String, String> = match &req.action {
            Action::Approve { r#ref } => handed(sink.answer(
                node,
                &req.session,
                r#ref,
                &by,
                &alias,
                crate::session_sink::Given::Approve {
                    allow: true,
                    why: None,
                },
            )),
            Action::Reject { r#ref, why } => handed(sink.answer(
                node,
                &req.session,
                r#ref,
                &by,
                &alias,
                crate::session_sink::Given::Approve {
                    allow: false,
                    why: why.clone(),
                },
            )),
            Action::Answer { r#ref, answers } => handed(sink.answer(
                node,
                &req.session,
                r#ref,
                &by,
                &alias,
                crate::session_sink::Given::Answer(answers.clone()),
            )),
            // **A file is pulled after the answer** (#546): its bytes may take longer than the
            // driver waits. The answer says it was accepted; its second outcome, when the pull
            // ends, is written beside the first.
            // **Not past the disk's reserve** (ADR-028 F-3: a pull never fills the disk): a driver
            // names the size, and a file that would leave less than the reserve is refused before
            // anything is pulled. The pull itself stops at the reserve too.
            Action::File { size, .. } => {
                use vox_core::node::pulls::{bytes, free_space, room_dir, RESERVE};
                let dir = room_dir(&paths, &info.channel_id);
                let _ = vox_core::node::paths::create_private_dir(&dir);
                let needs = size.saturating_add(RESERVE);
                match free_space(&dir) {
                    Ok(has) if has < needs => Err(format!(
                        "not enough free disk on {node}: needs {} (the file, and {} kept free), \
                         has {}",
                        bytes(needs),
                        bytes(RESERVE),
                        bytes(has)
                    )),
                    _ => Ok(format!("accepted, pulling {size} bytes")),
                }
            }
            input => self.steer(node, &reg, input).await,
        };
        // Every drive's outcome, beside it (DR-6): what happened, or why it was not delivered.
        let mut result = serde_json::json!({
            "v": vox_agentcomms::activity::VERSION, "session": req.session,
            "kind": "drive-result", "by": by, "action": req.action.name(),
            "ok": outcome.is_ok(),
        });
        match &outcome {
            Ok(said) => result["said"] = serde_json::json!(said),
            Err(why) => result["why"] = serde_json::json!(why),
        }
        if let Action::File { tag, .. } = &req.action {
            result["of"] = serde_json::json!(tag);
        }
        sink.activity(node, &req.session, vec![result.to_string()], None);
        if let Action::File {
            name,
            size,
            sha256,
            tag,
            note,
        } = &req.action
        {
            let driven = vox_core::node::pulls::Driven {
                room: info.channel_id,
                from: info.peer,
                name: name.clone(),
                size: *size,
                sha256: sha256.clone(),
                tag: tag.clone(),
            };
            let (router, handle, node) = (self.clone(), handle.clone(), node.clone());
            let (session, note) = (req.session.clone(), note.clone());
            tokio::spawn(async move {
                router
                    .land_driven(
                        &node, &handle, &paths, &reg, &session, &by, &alias, driven, note,
                    )
                    .await;
            });
        }
        match outcome {
            Ok(said) => Answer {
                ok: true,
                said,
                code: None,
            },
            Err(said) => Answer {
                ok: false,
                said,
                code: None,
            },
        }
    }

    /// A file driven into a Session (DR-1.7, #546): pulled from the driver's node, verified, put
    /// in the room's files directory (ADR-028 F-4), said in the Session as a `file` entry, and
    /// told to `reg`'s session alone as a typed line. Its second outcome, paired with the first by
    /// `of`, says where it landed or why it did not (DR-6). No retry, and no other session.
    #[allow(clippy::too_many_arguments)]
    async fn land_driven(
        &self,
        node: &NodeName,
        handle: &NodeHandle,
        paths: &vox_core::node::paths::Paths,
        reg: &crate::wake::Session,
        session: &str,
        by: &str,
        alias: &str,
        driven: vox_core::node::pulls::Driven,
        note: Option<String>,
    ) {
        let outcome: Result<String, String> = async {
            let path = vox_core::node::pulls::pull_driven(handle, paths, &driven)
                .await
                .map_err(|e| format!("not delivered: the file did not arrive whole: {e}"))?;
            let shown = path.display().to_string();
            let entry = serde_json::json!({
                "v": vox_agentcomms::activity::VERSION, "session": session, "kind": "file",
                "dir": "in", "by": by, "name": driven.name, "size": driven.size,
                "sha256": driven.sha256, "path": shown,
            });
            // Through the sink, numbered and in order with the Session's other entries.
            self.inner
                .sink
                .activity(node, session, vec![entry.to_string()], None);
            // Recorded so the copy goes when the room's retention says (ADR-028 F-5), which is
            // all a record's expiry reads; its id is the share's, the one the drive named.
            let _ = vox_core::node::pulls::record(
                paths,
                &vox_core::node::pulls::Pulled {
                    room: driven.room,
                    entry: vox_core::hash::sha256(driven.tag.as_bytes()),
                    path: path.clone(),
                    created_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                    folder: None,
                    files: Vec::new(),
                },
            );
            let line = match note.as_deref().map(str::trim) {
                Some(n) if !n.is_empty() => format!("{alias} sent you a file: {shown} — {n}"),
                _ => format!("{alias} sent you a file: {shown}"),
            };
            self.steer(node, reg, &crate::drive::Action::Text { text: line })
                .await
                .map(|_| format!("landed at {shown}, and the session was told"))
                .map_err(|e| format!("landed at {shown}, but the session was not told: {e}"))
        }
        .await;
        let mut result = serde_json::json!({
            "v": vox_agentcomms::activity::VERSION, "session": session,
            "kind": "drive-result", "by": by, "action": "file", "of": driven.tag,
            "ok": outcome.is_ok(),
        });
        match &outcome {
            Ok(said) => result["said"] = serde_json::json!(said),
            Err(why) => result["why"] = serde_json::json!(why),
        }
        self.inner
            .sink
            .activity(node, session, vec![result.to_string()], None);
    }

    /// Typed text, an interrupt, a stop or a slash command, to `reg`'s harness alone.
    async fn steer(
        &self,
        node: &NodeName,
        reg: &crate::wake::Session,
        action: &crate::drive::Action,
    ) -> Result<String, String> {
        use crate::codex_mirror::Steer;
        use crate::drive::Action;
        let steer = match action {
            Action::Text { text } => Steer::Text(text.clone()),
            Action::Interrupt => Steer::Interrupt,
            Action::Stop => Steer::Stop,
            Action::Slash { text } => {
                let (cmd, args) = crate::drive::slash(text);
                Steer::Slash { cmd, args }
            }
            _ => return Err("not an input for the session's terminal".into()),
        };
        let typed = match &steer {
            Steer::Text(t) => Some(t.clone()),
            _ => None,
        };
        let done = match reg.harness.as_str() {
            "codex" if !reg.codex_home.is_empty() => {
                self.inner
                    .codex
                    .steer(std::path::Path::new(&reg.codex_home), &reg.session, steer)
                    .await
            }
            "opencode" => self.inner.opencode.steer(&reg.session, steer).await,
            "claude" => {
                use crate::claude_injector::Act;
                let act = match steer {
                    Steer::Text(t) => Act::Text(t),
                    Steer::Interrupt => Act::Interrupt,
                    Steer::Stop => Act::Stop,
                    Steer::Slash { cmd, args } if args.is_empty() => Act::Slash(format!("/{cmd}")),
                    Steer::Slash { cmd, args } => Act::Slash(format!("/{cmd} {args}")),
                };
                let reg = reg.clone();
                tokio::task::spawn_blocking(move || crate::claude_injector::drive(&reg, &act))
                    .await
                    .unwrap_or_else(|_| Err("the delivery to the terminal failed".into()))
                    .map(|()| "delivered to its terminal".to_owned())
            }
            "codex" => Err(
                "this Codex session registered no CODEX_HOME, so Vox cannot reach its app-server"
                    .into(),
            ),
            other => Err(format!("Vox cannot drive a {other} session")),
        };
        if let (Ok(_), Some(t)) = (&done, typed) {
            self.inner.sink.delivered_text(node, &reg.session, &t);
        }
        done
    }

    /// Follow a registered session's activity where its harness offers it (ADR-029 SC-1): a
    /// Codex session from its `CODEX_HOME`'s app-server, an OpenCode session through Vox's
    /// plugin's socket. Claude Code's comes through its hooks.
    fn watch_harness(&self, node: &NodeName, s: &crate::wake::Session) {
        match s.harness.as_str() {
            "codex" if !s.codex_home.is_empty() => {
                self.inner
                    .codex
                    .watch(std::path::Path::new(&s.codex_home), node, &s.session);
            }
            "opencode" if !s.mirror.is_empty() => {
                self.inner
                    .opencode
                    .watch(node, &s.session, &s.mirror, &s.token);
            }
            _ => {}
        }
    }

    /// `session` of `node` is called `name` now, as its harness says (ADR-029 MD-1): its
    /// registration keeps the name, and its open Session is renamed at once, not at its next
    /// message.
    fn rename_session(&self, node: &NodeName, session: &str, name: &str) {
        let Ok(paths) = self.inner.account.node_paths(node) else {
            return;
        };
        let Some(reg) = crate::wake::store_name(&paths, session, name) else {
            return;
        };
        let Some(handle) = self.handle_of(node) else {
            return;
        };
        let (router, node) = (self.clone(), node.clone());
        self.inner.rt.spawn(async move {
            // A Session not open yet is opened under the new name when it is.
            let _ = router.open_session(&node, &handle, &reg, None).await;
        });
    }

    /// Post `bodies`, numbered, to `session`'s Session: sealed to the members `node` trusts with
    /// drive (ADR-029 SC-2), in the room the session works in. One task per session posts them in
    /// order, so a split entry's parts stay together.
    fn post_session(&self, node: &NodeName, session: &str, bodies: Vec<String>) {
        let mut posting = lock(&self.inner.posting);
        let key = (node.clone(), session.to_owned());
        let tx = match posting.get(&key).filter(|tx| !tx.is_closed()) {
            Some(tx) => tx.clone(),
            None => {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                let weak = Arc::downgrade(&self.inner);
                self.inner
                    .rt
                    .spawn(post_in_order(weak, key.0.clone(), key.1.clone(), rx));
                posting.insert(key, tx.clone());
                tx
            }
        };
        for b in bodies {
            let _ = tx.send(b);
        }
    }

    /// Unregister an agent session of `node`, and detach the node if it was attached implicitly
    /// and that session was its last holder, **in one decision** (L-3): the unregister and the
    /// move to `Detaching` happen in one critical section, so a session registering at the same
    /// moment either comes first (and the node stays) or finds the node detaching and waits.
    ///
    /// Returns whether the session was registered, and whether the node detached.
    pub async fn session_end(&self, node: &NodeName, session: &str, reason: &str) -> (bool, bool) {
        // **A resume is not an end** (ADR-029 SE-4): the session goes on, registered, its Session
        // open.
        if vox_core::node::sessions::keeps_open(reason) {
            return (true, false);
        }
        // Whatever it was asking, nobody can answer now.
        self.inner.sink.session_end(node, session);
        // Its queue closes once what it holds is posted.
        lock(&self.inner.posting).remove(&(node.clone(), session.to_owned()));
        // Its Session ends first, while the node is still attached to say so.
        if let (Some(handle), Ok(paths)) =
            (self.handle_of(node), self.inner.account.node_paths(node))
        {
            let room = crate::wake::registration(&paths, session).and_then(|r| r.room);
            if let Some(room) = room.and_then(|r| vox_core::node::link::b32_decode(&r, "room").ok())
            {
                let _ = vox_core::node::sessions::end(&handle, room, session, reason).await;
            }
        }
        self.inner.codex.end(session);
        self.inner.opencode.end(session);
        let going = {
            let mut slots = lock(&self.inner.slots);
            match slots.get_mut(node) {
                Some(Slot::Attached(a)) => {
                    let was = a.sessions.remove(session) || a.paths.session_file(session).is_file();
                    crate::wake::end(&a.paths, session);
                    let going = if a.implicit && a.holders == 0 && a.sessions.is_empty() {
                        begin_detach(&mut slots, node)
                    } else {
                        None
                    };
                    (was, going)
                }
                _ => {
                    // Not attached: the record is still removed, so the session is never woken.
                    let was = match self.inner.account.node_paths(node) {
                        Ok(paths) => {
                            let was = paths.session_file(session).is_file();
                            crate::wake::end(&paths, session);
                            was
                        }
                        Err(_) => false,
                    };
                    (was, None)
                }
            }
        };
        let (was, going) = going;
        match going {
            Some((a, done)) => {
                self.finish_detach(node.clone(), a, done, DetachCause::LastHolder)
                    .await;
                (was, true)
            }
            None => (was, false),
        }
    }

    /// Detach `node` (L-3), by hand or because the daemon stops.
    ///
    /// # Errors
    /// [`Refusal::NotAttached`] for a node that is not attached and not detaching.
    pub async fn detach(&self, node: &NodeName, cause: DetachCause) -> Result<(), Refusal> {
        loop {
            let step = {
                let mut slots = lock(&self.inner.slots);
                match slots.get(node) {
                    Some(Slot::Attached(_)) => match begin_detach(&mut slots, node) {
                        Some(going) => DStep::Go(going),
                        None => DStep::NotAttached,
                    },
                    Some(Slot::Attaching(rx)) => DStep::WaitAttach(rx.clone()),
                    Some(Slot::Detaching(rx)) => DStep::WaitDetach(rx.clone()),
                    None => DStep::NotAttached,
                }
            };
            match step {
                DStep::Go((a, done)) => {
                    self.finish_detach(node.clone(), a, done, cause).await;
                    return Ok(());
                }
                DStep::WaitAttach(mut rx) => {
                    let _ = rx.wait_for(Option::is_some).await;
                }
                DStep::WaitDetach(mut rx) => {
                    let _ = rx.wait_for(|d| *d).await;
                    return Ok(());
                }
                DStep::NotAttached => {
                    return Err(Refusal::NotAttached { node: node.clone() });
                }
            }
        }
    }

    /// The attached node `node`'s handle.
    #[must_use]
    pub fn handle_of(&self, node: &NodeName) -> Option<NodeHandle> {
        match lock(&self.inner.slots).get(node) {
            Some(Slot::Attached(a)) => Some(a.handle.clone()),
            _ => None,
        }
    }

    /// Whether the daemon has no node in any state and no client connected (L-8).
    #[must_use]
    pub fn idle(&self) -> bool {
        lock(&self.inner.slots).is_empty() && self.inner.connections.load(Ordering::SeqCst) == 0
    }

    /// Detach every node, the daemon stopping (S-1): nothing attaches after this. Whether every
    /// node's stop finished within the patience.
    pub async fn stop_all(&self) -> bool {
        self.inner.stopping.store(true, Ordering::SeqCst);
        // A proof of a daemon started while this one stops holds that moment open (test builds
        // only, V210-105).
        #[cfg(feature = "test-knobs")]
        if let Some(ms) = std::env::var("VOX_TEST_STOP_HOLD_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        let names: Vec<NodeName> = lock(&self.inner.slots).keys().cloned().collect();
        let mut all = tokio::task::JoinSet::new();
        for node in names {
            let router = self.clone();
            all.spawn_on(
                async move {
                    let _ = router.detach(&node, DetachCause::DaemonStopping).await;
                },
                &self.inner.rt,
            );
        }
        while all.join_next().await.is_some() {}
        !self.inner.unfinished_stop.load(Ordering::SeqCst)
    }

    /// Attach every node the attach file keeps (L-4), each in the background: a client that asks
    /// for one meanwhile waits for it, as for any attach.
    pub fn attach_kept(&self) {
        for (node, source) in read_attach_file(&self.inner.account.attach_file()) {
            let router = self.clone();
            self.inner.rt.spawn(async move {
                let (passphrase, rooms) = match &source {
                    KeepSource::None => (None, Vec::new()),
                    // Off the runtime's workers: a Keychain that asks (locked, or the item made by
                    // another vox) blocks until someone answers, and two of these would otherwise
                    // leave the daemon answering no one meanwhile.
                    KeepSource::Keychain(account) => {
                        match read_in_keychain(account.clone()).await {
                            Ok(p) => (Some(p), Vec::new()),
                            Err(e) => {
                                eprintln!(
                                "vox daemon: could not attach kept node {node}: its passphrase in \
                                 the Keychain: {e}"
                            );
                                return;
                            }
                        }
                    }
                    KeepSource::File(path) => match crate::tunnel_cli::passphrase_file_text(path) {
                        Ok(text) => split_passphrases(&text),
                        Err(e) => {
                            eprintln!(
                                "vox daemon: could not attach kept node {node}: its passphrase \
                                 file {}: {e}",
                                path.display()
                            );
                            return;
                        }
                    },
                };
                match router
                    .want(
                        &node,
                        Want::Explicit(Some(source)),
                        passphrase,
                        rooms,
                        Vec::new(),
                    )
                    .await
                {
                    Ok(_) => eprintln!("vox daemon: attached kept node {node}"),
                    Err(r) => eprintln!("vox daemon: could not attach kept node {node}: {r}"),
                }
            });
        }
    }

    /// Find `node` attached, or attach it, as `want` says, waiting out anyone else's attach or
    /// detach of it first.
    async fn want(
        &self,
        node: &NodeName,
        want: Want,
        passphrase: Option<Zeroizing<String>>,
        rooms: Vec<Zeroizing<String>>,
        anchors: Vec<String>,
    ) -> Result<Granted, Refusal> {
        let mut want = Some(want);
        loop {
            let step = {
                let mut slots = lock(&self.inner.slots);
                if self.inner.stopping.load(Ordering::SeqCst) {
                    return Err(Refusal::Stopping);
                }
                match slots.get_mut(node) {
                    Some(Slot::Attached(a)) => {
                        let w = match want.take() {
                            Some(Want::Checked) | None => Want::IfAttached,
                            Some(w) => w,
                        };
                        return Ok(self.grant(node, a, w));
                    }
                    Some(Slot::Attaching(rx)) => Step::WaitAttach(rx.clone()),
                    Some(Slot::Detaching(rx)) => Step::WaitDetach(rx.clone()),
                    // Neither a one-shot verb nor an agent's session attaches a node (L-2;
                    // ADR-028 K-13).
                    None if matches!(want, Some(Want::IfAttached | Want::Session(_))) => {
                        Step::NotAttached
                    }
                    None => {
                        let (tx, rx) = watch::channel(None);
                        slots.insert(node.clone(), Slot::Attaching(rx));
                        Step::Mine(tx)
                    }
                }
            };
            match step {
                Step::WaitAttach(mut rx) => {
                    let _ = rx.wait_for(Option::is_some).await;
                }
                // **Bounded** (#408): a detach waits for the node's secret work however long it
                // takes (L-3), and a hook asking for its node sits inside a model's turn. Past
                // the bound the request is refused, saying the node is still detaching.
                Step::WaitDetach(mut rx) => {
                    let waited = tokio::time::timeout(
                        vox_core::node::daemonipc::DETACHING_PATIENCE,
                        rx.wait_for(|d| *d),
                    )
                    .await;
                    if waited.is_err() {
                        return Err(Refusal::StillDetaching { node: node.clone() });
                    }
                }
                Step::NotAttached => return Err(Refusal::NotAttached { node: node.clone() }),
                Step::Mine(tx) => {
                    let w = match want.take() {
                        Some(Want::Checked) => Want::Explicit(None),
                        w => w.unwrap_or(Want::IfAttached),
                    };
                    let started = self
                        .start(node, passphrase.as_ref(), &rooms, &anchors)
                        .await;
                    let mut slots = lock(&self.inner.slots);
                    return match started {
                        Ok(mut a) => {
                            a.implicit = !matches!(w, Want::Explicit(_));
                            let mut granted = self.grant(node, &mut a, w);
                            // This request attached it: what that said goes back to its client.
                            granted.notes = a.notes.clone();
                            granted.attached_now = true;
                            let fingerprint = a.fingerprint;
                            // Codex sessions registered before this daemon started are read
                            // again from their app-server at once, not at their next turn.
                            for s in crate::wake::registered(&a.paths) {
                                self.watch_harness(node, &s);
                            }
                            // Drive input from members with drive (ADR-029 §3), while attached.
                            self.serve_drive(node, &a.handle, a.detached.subscribe());
                            slots.insert(node.clone(), Slot::Attached(a));
                            drop(slots);
                            self.inner
                                .metrics
                                .nodes_attached
                                .fetch_add(1, Ordering::Relaxed);
                            let _ = tx.send(Some(Ok(())));
                            eprintln!(
                                "vox daemon: node {node} attached{}",
                                if granted.info.implicit {
                                    " (implicitly)"
                                } else {
                                    ""
                                }
                            );
                            let _ = self.inner.events.send(DaemonEvent::Attached {
                                node: node.clone(),
                                fingerprint,
                            });
                            Ok(granted)
                        }
                        Err(r) => {
                            slots.remove(node);
                            drop(slots);
                            let _ = tx.send(Some(Err(r.clone())));
                            Err(r)
                        }
                    };
                }
            }
        }
    }

    /// Count `want` against the attached node `a`: a hold, a session, or attached by hand.
    fn grant(&self, node: &NodeName, a: &mut Attached, want: Want) -> Granted {
        let hold = match want {
            Want::Explicit(keep) => {
                a.implicit = false;
                // **"Keep it" with no passphrase source keeps a kept node as it is kept**: Vox.app
                // asks that of a node that may be attaching from its Keychain item at login, and
                // the item, no longer named by the attach file, would have stayed behind unused.
                match keep {
                    Some(KeepSource::None) if a.keep.is_some() => {}
                    Some(k) => a.keep = Some(k),
                    None => {}
                }
                None
            }
            Want::Hold => {
                a.holders += 1;
                Some(HolderGuard {
                    router: Arc::downgrade(&self.inner),
                    node: node.clone(),
                    generation: a.generation,
                })
            }
            Want::Session(s) => {
                crate::wake::store(&a.paths, &s);
                self.watch_harness(node, &s);
                a.sessions.insert(s.session.clone());
                None
            }
            Want::IfAttached | Want::Checked => None,
        };
        Granted {
            info: info_of_attached(node, a),
            handle: a.handle.clone(),
            detached: a.detached.subscribe(),
            hold,
            notes: Vec::new(),
            attached_now: false,
            generation: a.generation,
        }
    }

    /// Bring `node` up: open it, start its actor, unlock it, reopen its rooms, start its tasks and
    /// watch its actor. The table is not locked meanwhile; the slot says `Attaching`.
    async fn start(
        &self,
        node: &NodeName,
        passphrase: Option<&Zeroizing<String>>,
        rooms: &[Zeroizing<String>],
        anchors: &[String],
    ) -> Result<Box<Attached>, Refusal> {
        let failed = |why: String| Refusal::Failed {
            node: node.clone(),
            why,
        };
        if !self.inner.account.nodes_on_disk().contains(node) {
            return Err(Refusal::NoSuchNode { node: node.clone() });
        }
        let paths = self
            .inner
            .account
            .node_paths(node)
            .map_err(|e| failed(e.to_string()))?;
        // The daemon's anchors, the node's own anchors file, and what this attach names.
        //
        // **What the file could not give is said, here** (V210-107, under ADR-026): each skipped
        // line, and that a file naming no usable anchor leaves the node with none, which it
        // carries on without — or, for an anchor node (`vox node`), runs with none of its own. The
        // daemon is the one vox that reads the file now; dropping what it skipped left a person
        // whose file named a host that no longer resolves with nothing said anywhere (#410: the
        // wholly-bad anchors file proof). It is logged, and kept as the attach's notes, which go
        // back to the verb that attached the node, to print in its person's own terminal (R23).
        let mut set = self.inner.defaults.anchors.clone();
        let file = paths.anchors_file();
        let mut notes = vox_core::node::link::merge_anchors_file(&mut set, &file)
            .unwrap_or_else(|e| vec![e.to_string()]);
        let skipped = notes.len();
        for spec in anchors {
            let _ = vox_core::node::link::merge_anchor_spec(&mut set, spec);
        }
        if set.is_empty() && skipped > 0 {
            let is_anchor = !paths.vault_file().is_file()
                && vox_core::node::headless::identity_file(&paths).is_file();
            notes.push(format!(
                "node {node}: {}; {}",
                vox_core::error::Error::AnchorsFileUnusable {
                    path: file.display().to_string(),
                    skipped,
                },
                if is_anchor {
                    "running with no anchor of its own"
                } else {
                    "carrying on with no anchor"
                }
            ));
        }
        for line in &notes {
            eprintln!("vox daemon: {line}");
        }
        let started = std::time::Instant::now();
        let bind = (self.inner.defaults.bind)(node);
        let bind_addr = match &bind {
            Some(Bind::Addr(a)) => Some(*a),
            _ => None,
        };
        // **A node with a headless key and no vault is an anchor** (ADR-026 N-5, ADR-016): it
        // runs as that key from spawn, with no passphrase, serving its board for the rooms
        // published to it.
        let anchor_key = || {
            vox_core::node::headless::load_or_create_identity(&paths)
                .map_err(|e| failed(e.to_string()))
        };
        // Its fingerprint: the key is read again for each spawn, which takes it.
        let anchor: Option<Digest32> = if !paths.vault_file().is_file()
            && vox_core::node::headless::identity_file(&paths).is_file()
        {
            Some(vox_core::identity::composite::RootSigner::fingerprint(
                &anchor_key()?,
            ))
        } else {
            None
        };
        let serve_only = lock(&self.inner.serve_only).get(node).cloned();
        let (handle, actor) = loop {
            let mut cfg = NodeConfig::new()
                .anchors(set.clone())
                .on_profile_wait(crate::tunnel_cli::say_waiting);
            if let Some(bind) = &bind {
                cfg = cfg.bind(bind.clone());
            }
            if anchor.is_some() {
                cfg = cfg.headless(anchor_key()?).anchor_boards(true);
                if let Some(creators) = &serve_only {
                    cfg = cfg.serve_only(creators.clone());
                }
            }
            let p = paths.clone();
            let spawned = tokio::task::spawn_blocking(move || Node::spawn_supervised(p, cfg))
                .await
                .map_err(|e| failed(format!("its start was cut short: {e}")))?;
            match spawned {
                Err(vox_core::error::Error::ProfileBusy)
                    if started.elapsed() < PROFILE_RELEASE_PATIENCE =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(vox_core::error::Error::ProfileBusy) => {
                    return Err(Refusal::NodeInUse { node: node.clone() });
                }
                Err(e) => return Err(failed(e.to_string())),
                Ok(up) => break up,
            }
        };
        let (ended_tx, ended) = watch::channel(false);
        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        // Watched from the start, so a panic during the unlock is not lost either.
        {
            let router = Arc::downgrade(&self.inner);
            let node = node.clone();
            self.inner.rt.spawn(async move {
                let end = ActorEnd::of(actor).await;
                let _ = ended_tx.send(true);
                if let ActorEnd::Panicked(message) = end {
                    eprintln!("vox daemon: node {node} stopped: its actor panicked: {message}");
                    if let Some(inner) = router.upgrade() {
                        inner.metrics.node_panics.fetch_add(1, Ordering::Relaxed);
                        Router { inner }
                            .detach_generation(&node, generation, DetachCause::Panicked(message))
                            .await;
                    }
                }
            });
        }
        let empty = Zeroizing::new(String::new());
        let pass = passphrase.unwrap_or(&empty);
        // An anchor has nothing to unlock: it is networked from spawn.
        let outcome = if anchor.is_some() {
            Outcome::Done
        } else {
            crate::tunnel_cli::apply_saying_waits(
                &handle,
                NodeCommand::Unlock {
                    passphrase: Secret::new(pass.as_bytes().to_vec()),
                },
            )
            .await
        };
        if !outcome.is_done() {
            let outcome_text = outcome.to_string();
            let refusal = match outcome {
                Outcome::Failed(Fault::NoIdentity) => Refusal::NoIdentity { node: node.clone() },
                Outcome::Failed(Fault::WrongPassphrase) => {
                    Refusal::WrongPassphrase { node: node.clone() }
                }
                // Unlocking brings the node onto the network, so a bind that fails fails here; it
                // is named with the operating system's words (V210-134).
                Outcome::Failed(fault) if fault.is_bind() => match bind_addr {
                    Some(addr) => failed(format!(
                        "cannot listen on {addr}: {}",
                        crate::tunnel_cli::bind_failure(
                            addr,
                            crate::tunnel_cli::Socket::Udp,
                            fault
                        )
                        .unwrap_or_default()
                    )),
                    None => failed(format!("could not unlock its identity: {outcome_text}")),
                },
                other => failed(format!("could not unlock its identity: {other}")),
            };
            stop_actor_fully(&handle, ended.clone()).await;
            return Err(refusal);
        }
        for line in rooms {
            crate::app::open_rooms_by_line(&handle, line).await;
        }
        if *ended.borrow() {
            return Err(failed("its actor stopped while it attached".into()));
        }
        // An anchor wakes no agent, notifies nobody and follows no anchor of its own: it is one.
        let tasks = anchor.is_none().then(|| {
            NodeTasks::start(
                &self.inner.rt,
                &handle,
                &paths,
                self.inner.defaults.anchor_specs.clone(),
            )
        });
        let fingerprint = anchor.or_else(|| handle.view().identity.map(|i| i.fingerprint));
        Ok(Box::new(Attached {
            handle,
            paths,
            generation,
            implicit: true,
            keep: None,
            holders: 0,
            sessions: BTreeSet::new(),
            tasks,
            detached: watch::channel(false).0,
            notes,
            ended,
            fingerprint,
        }))
    }

    /// Detach `node` only if it is still the attach `generation` (a panic's detach, which must
    /// never take down a later attach of the same node).
    async fn detach_generation(&self, node: &NodeName, generation: u64, cause: DetachCause) {
        let going = {
            let mut slots = lock(&self.inner.slots);
            match slots.get(node) {
                Some(Slot::Attached(a)) if a.generation == generation => {
                    begin_detach(&mut slots, node)
                }
                _ => None,
            }
        };
        if let Some((a, done)) = going {
            self.finish_detach(node.clone(), a, done, cause).await;
        }
    }

    /// The rest of a detach, after the slot says `Detaching` (L-3): answer every connection acting
    /// as the node, stop its tasks and its actor, and free the slot.
    async fn finish_detach(
        &self,
        node: NodeName,
        mut a: Box<Attached>,
        done: watch::Sender<bool>,
        cause: DetachCause,
    ) {
        let _ = a.detached.send(true);
        // A panicked actor never ran its own stop (ADR-026 L-6): the presence takes the node off
        // the exchange and closes its connections, and only its own (D-5).
        if matches!(cause, DetachCause::Panicked(_)) {
            if let (Some(fp), Some(Bind::Shared(presence))) =
                (a.fingerprint, (self.inner.defaults.bind)(&node))
            {
                presence.evict(&fp);
            }
        }
        if let Some(tasks) = a.tasks.take() {
            tasks.stop().await;
        }
        // **A detach is done only when the node's actor has ended** (ADR-026 L-3): its keys
        // wiped, its store closed, its directory lock let go. A secret work still running (a room
        // sealed, a passphrase derived) holds the actor's stop until it ends, and a detach that
        // gave up after a patience freed the slot with the room's passphrase still in memory. So
        // there is no cutoff here; the slot stays `Detaching`, an attach of the node waits for it,
        // and the daemon answers every other request meanwhile. Only the daemon's own stop is
        // bounded (S-1, V210-93): the process leaves then, and its memory with it.
        let stopped = if matches!(cause, DetachCause::DaemonStopping) {
            stop_actor(&a.handle, a.ended.clone(), self.inner.defaults.patience).await
        } else {
            stop_actor_fully(&a.handle, a.ended.clone()).await;
            true
        };
        if !stopped {
            self.inner.unfinished_stop.store(true, Ordering::SeqCst);
        }
        let forget_keep = matches!(cause, DetachCause::Requested) && a.keep.is_some();
        drop(a);
        lock(&self.inner.slots).remove(&node);
        self.inner
            .metrics
            .nodes_attached
            .fetch_sub(1, Ordering::Relaxed);
        // Detached by hand: its line goes, and with it a passphrase kept for it in the Keychain,
        // before an attach waiting for this detach can keep it again.
        if forget_keep {
            self.write_attach_file(Some(&node)).await;
        }
        let _ = done.send(true);
        if !matches!(cause, DetachCause::DaemonStopping) {
            eprintln!("vox daemon: node {node} detached ({})", cause_words(&cause));
        }
        let _ = self
            .inner
            .events
            .send(DaemonEvent::Detached { node, cause });
    }

    /// Rewrite `.daemon/attach` from the kept nodes attached now and the lines already there for
    /// nodes not attached (a kept node that failed to attach stays kept), less `forget`: a node
    /// detached by hand.
    async fn write_attach_file(&self, forget: Option<&NodeName>) {
        let _file = self.inner.keep_file.lock().await;
        self.write_attach_file_held(forget).await;
    }

    /// [`Self::write_attach_file`], with `keep_file` held by the caller.
    ///
    /// **A Keychain item lives only while the attach file names it** (ADR-014 M-6): a line that
    /// goes, or now names another source, takes its item with it, whatever made it go (a detach
    /// by hand, a keep with a passphrase file, an attach that is not kept).
    async fn write_attach_file_held(&self, forget: Option<&NodeName>) {
        if self.inner.stopping.load(Ordering::SeqCst) {
            return;
        }
        let path = self.inner.account.attach_file();
        let was: BTreeMap<NodeName, KeepSource> = read_attach_file(&path).into_iter().collect();
        let mut kept = was.clone();
        {
            let slots = lock(&self.inner.slots);
            for (name, slot) in slots.iter() {
                if let Slot::Attached(a) = slot {
                    match &a.keep {
                        Some(k) => {
                            kept.insert(name.clone(), k.clone());
                        }
                        None => {
                            kept.remove(name);
                        }
                    }
                }
            }
            if let Some(name) = forget {
                kept.remove(name);
            }
        }
        let mut text = String::new();
        for (name, source) in &kept {
            text.push_str(name.as_str());
            text.push('\t');
            match source {
                KeepSource::None => text.push_str("none"),
                KeepSource::File(p) => {
                    text.push_str("file:");
                    text.push_str(&p.to_string_lossy());
                }
                KeepSource::Keychain(account) => {
                    text.push_str("keychain:");
                    text.push_str(account);
                }
            }
            text.push('\n');
        }
        if let Err(e) = vox_core::node::paths::create_private_dir(&self.inner.account.daemon_dir())
            .and_then(|()| vox_core::node::paths::write_private_file_unique(&path, text.as_bytes()))
        {
            eprintln!("vox daemon: could not write {}: {e}", path.display());
            return;
        }
        let named: BTreeSet<&str> = kept
            .values()
            .filter_map(|k| match k {
                KeepSource::Keychain(account) => Some(account.as_str()),
                _ => None,
            })
            .collect();
        for k in was.values() {
            if let KeepSource::Keychain(account) = k {
                if !named.contains(account.as_str()) {
                    forget_in_keychain(account.clone()).await;
                }
            }
        }
    }
}

/// What the Keychain holds for `account`, read off the runtime's workers.
async fn read_in_keychain(account: String) -> Result<Zeroizing<String>, String> {
    tokio::task::spawn_blocking(move || crate::keychain::read(&account))
        .await
        .unwrap_or_else(|e| Err(format!("the read was cut short: {e}")))
}

/// Remove what the Keychain holds for `account`, off the runtime's workers.
async fn forget_in_keychain(account: String) {
    let _ = tokio::task::spawn_blocking(move || crate::keychain::forget(&account)).await;
}

enum DStep {
    Go((Box<Attached>, watch::Sender<bool>)),
    WaitAttach(watch::Receiver<Option<Result<(), Refusal>>>),
    WaitDetach(watch::Receiver<bool>),
    NotAttached,
}

enum Step {
    WaitAttach(watch::Receiver<Option<Result<(), Refusal>>>),
    WaitDetach(watch::Receiver<bool>),
    NotAttached,
    Mine(watch::Sender<Option<Result<(), Refusal>>>),
}

/// Stop a node's actor and wait for its task to end, however long what it is doing takes.
async fn stop_actor_fully(handle: &NodeHandle, mut ended: watch::Receiver<bool>) {
    if !*ended.borrow() {
        let _ = handle.apply(NodeCommand::Shutdown).await;
    }
    let _ = ended.wait_for(|e| *e).await;
}

/// Stop a node's actor within `patience`, and wait (within it) for its task to end, so its store
/// and its directory lock are let go before its slot is freed.
async fn stop_actor(
    handle: &NodeHandle,
    mut ended: watch::Receiver<bool>,
    patience: Duration,
) -> bool {
    tokio::time::timeout(patience, async {
        if !*ended.borrow() {
            let _ = handle.apply(NodeCommand::Shutdown).await;
        }
        let _ = ended.wait_for(|e| *e).await;
    })
    .await
    .is_ok()
}

fn cause_words(cause: &DetachCause) -> String {
    match cause {
        DetachCause::Requested => "asked to".into(),
        DetachCause::LastHolder => "its last holder went".into(),
        DetachCause::DaemonStopping => "the daemon is stopping".into(),
        DetachCause::Panicked(m) => format!("its actor panicked: {m}"),
        DetachCause::Stopped => "its actor stopped".into(),
    }
}

fn info_of_attached(name: &NodeName, a: &Attached) -> NodeInfo {
    NodeInfo {
        name: name.clone(),
        state: NodeState::Attached,
        fingerprint: a.fingerprint,
        implicit: a.implicit,
        keep: a.keep.is_some(),
    }
}

fn info_of(name: &NodeName, slot: Option<&Slot>) -> NodeInfo {
    match slot {
        Some(Slot::Attached(a)) => info_of_attached(name, a),
        other => NodeInfo {
            name: name.clone(),
            state: match other {
                Some(Slot::Attaching(_)) => NodeState::Attaching,
                Some(Slot::Detaching(_)) => NodeState::Detaching,
                _ => NodeState::Detached,
            },
            fingerprint: None,
            implicit: false,
            keep: false,
        },
    }
}

/// The identity passphrase (the first line) and the room passphrases (the rest) of a passphrase
/// file's text, as a piped `vox daemon` reads them. Only line endings are stripped.
fn split_passphrases(text: &str) -> (Option<Zeroizing<String>>, Vec<Zeroizing<String>>) {
    let mut lines = text
        .lines()
        .map(|l| Zeroizing::new(l.trim_end_matches('\r').to_owned()));
    let identity = lines.next();
    (identity, lines.filter(|l| !l.is_empty()).collect())
}

/// `.daemon/attach`: one line per kept node, `<name>\t(none|file:<path>|keychain:<account>)`. A
/// line that does not parse is skipped.
fn read_attach_file(path: &std::path::Path) -> Vec<(NodeName, KeepSource)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let (name, source) = line.split_once('\t')?;
            let name = NodeName::parse(name).ok()?;
            let source = if source == "none" {
                KeepSource::None
            } else if let Some(account) = source.strip_prefix("keychain:") {
                KeepSource::Keychain(account.to_owned())
            } else {
                KeepSource::File(source.strip_prefix("file:")?.into())
            };
            Some((name, source))
        })
        .collect()
}

impl Dispatch for Router {
    fn hello(&self) -> DaemonFrame {
        DaemonFrame::Hello {
            protocol: vox_core::node::ipc::PROTOCOL_VERSION,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            pid: std::process::id(),
            attached: self.attached(),
        }
    }

    async fn use_node(&self, using: UseNode) -> Result<Lease, Refusal> {
        Router::use_node(self, using).await
    }

    async fn daemon(&self, request: DaemonRequest) -> DaemonFrame {
        let refused = DaemonFrame::Refused;
        match request {
            DaemonRequest::Nodes => DaemonFrame::Nodes(self.nodes()),
            DaemonRequest::Attach {
                node,
                passphrase,
                keep,
                rooms,
                anchors,
            } => match self
                .attach_noting(&node, passphrase, keep, rooms, anchors)
                .await
            {
                Ok((info, notes)) => DaemonFrame::Attached(info, notes),
                Err(r) => refused(r),
            },
            DaemonRequest::Detach { node } => {
                match self.detach(&node, DetachCause::Requested).await {
                    Ok(()) => DaemonFrame::Ok,
                    Err(r) => refused(r),
                }
            }
            DaemonRequest::Unkeep { node } => match self.unkeep(&node).await {
                Ok(()) => DaemonFrame::Ok,
                Err(r) => refused(r),
            },
            DaemonRequest::SessionRegister {
                node,
                session,
                record,
                join,
            } => {
                let record = match serde_json::from_str::<crate::wake::Session>(&record) {
                    Ok(r) if r.session == session => r,
                    _ => {
                        return refused(Refusal::Failed {
                            node,
                            why: "the session's record does not parse, or names another session"
                                .into(),
                        })
                    }
                };
                match self.session_register(&node, record, join).await {
                    Ok(frame) => frame,
                    Err(r) => refused(r),
                }
            }
            DaemonRequest::SessionRoom {
                node,
                session,
                room,
            } => match self.session_room(&node, &session, &room).await {
                Ok(frame) => frame,
                Err(r) => refused(r),
            },
            DaemonRequest::SessionEnd {
                node,
                session,
                reason,
            } => {
                let (was_registered, detached) = self.session_end(&node, &session, &reason).await;
                DaemonFrame::SessionEnded {
                    was_registered,
                    detached,
                }
            }
            DaemonRequest::Status => DaemonFrame::Status(DaemonStatus {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                pid: std::process::id(),
                listen: self.inner.defaults.listen.clone(),
                nodes: self.nodes(),
                panics: self.inner.metrics.node_panics.load(Ordering::Relaxed),
            }),
            DaemonRequest::Metrics => {
                let mut out = vox_core::node::status::Families::default();
                self.inner.metrics.to_prometheus_rows(&mut out);
                for (name, handle) in self.attached_handles() {
                    if let Ok(r) = handle.status().await {
                        r.to_prometheus_rows(&name, &mut out);
                    }
                }
                DaemonFrame::Metrics(out.render())
            }
            // Served by the socket itself, from `events`.
            DaemonRequest::Subscribe => DaemonFrame::Ok,
            DaemonRequest::Stop => {
                self.inner.stop_asked.notify_one();
                DaemonFrame::Ok
            }
            DaemonRequest::SessionActivity {
                node,
                session,
                bodies,
                call,
            } => {
                // A Codex session read from its app-server: its hooks' copy of the same activity
                // is not posted again. The prompt is the hook's alone (see codex_mirror).
                let bodies = if self.inner.codex.subscribed(&session) {
                    bodies
                        .into_iter()
                        .filter(|b| {
                            serde_json::from_str::<serde_json::Value>(b).is_ok_and(|v| {
                                v.get("kind").and_then(|k| k.as_str()) == Some("user")
                            })
                        })
                        .collect()
                } else {
                    bodies
                };
                self.inner.sink.activity(&node, &session, bodies, call);
                DaemonFrame::Ok
            }
            DaemonRequest::SessionAsk {
                node,
                session,
                body,
                call,
                transcript,
            } => DaemonFrame::SessionAnswer(
                self.inner
                    .sink
                    .ask(&node, &session, body, call, transcript)
                    .await,
            ),
        }
    }

    fn events(&self) -> broadcast::Receiver<DaemonEvent> {
        self.inner.events.subscribe()
    }

    fn connections(&self) -> Option<Arc<std::sync::atomic::AtomicUsize>> {
        Some(Arc::clone(&self.inner.connections))
    }
}

/// The router's lifecycle, in one process (ADR-026 §10 proofs 5 and 6, as far as they hold without
/// the daemon process): concurrent attaches, holders and the implicit detach, a session's end with
/// its detach, a detach answering connections "node detached", and one node's panic leaving the
/// other running. Production Argon2id: run in release.
/// Post one session's entries into its Session, in the order they were queued. Each goes to the
/// room its session works in now; a session in no room, or headless (ADR-029 SE-1), has no
/// Session, and its entries go nowhere.
///
/// **A Session keeps its start while its room is joined** (SC-1): while the node is joining the
/// room the room map gave the session, or the room is not open on it yet, entries are held, in
/// order, up to [`HELD_BYTES`] (the oldest dropped first), and appended once the room opens. A join
/// that fails drops them. Either way the Session's first entry after them says how many were
/// dropped. Any other failure is said in the daemon's log, naming the entry's kind, once until it
/// changes or entries reach the Session again: the session goes on.
async fn post_in_order(
    weak: std::sync::Weak<Inner>,
    node: NodeName,
    session: String,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let mut failing: Option<String> = None;
    let mut held = std::collections::VecDeque::<String>::new();
    let mut held_bytes = 0usize;
    let mut dropped = 0u64;
    loop {
        // Waiting on the room: look again each second, and take what arrives meanwhile.
        let next = if held.is_empty() {
            rx.recv().await
        } else {
            match tokio::time::timeout(HELD_RETRY, rx.recv()).await {
                Ok(None) => return,
                Ok(next) => next,
                Err(_) => None,
            }
        };
        if let Some(body) = next {
            held_bytes += body.len();
            held.push_back(body);
            while held_bytes > HELD_BYTES {
                let Some(old) = held.pop_front() else { break };
                held_bytes -= old.len();
                dropped += 1;
            }
        } else if held.is_empty() {
            return;
        }
        let Some(inner) = weak.upgrade() else {
            return;
        };
        let router = Router { inner };
        let Some(handle) = router.handle_of(&node) else {
            held.clear();
            held_bytes = 0;
            continue;
        };
        let reg = router
            .inner
            .account
            .node_paths(&node)
            .ok()
            .and_then(|p| crate::wake::registration(&p, &session));
        let Some((room_b32, room)) =
            reg.filter(|r| r.interactive)
                .and_then(|r| r.room)
                .and_then(|r| {
                    vox_core::node::link::b32_decode(&r, "room")
                        .ok()
                        .map(|d| (r, d))
                })
        else {
            held.clear();
            held_bytes = 0;
            continue;
        };
        let joins = lock(&router.inner.joins).get(&node).cloned();
        if joins.as_ref().is_some_and(|j| j.under_way(&room_b32)) {
            continue;
        }
        let member = handle.view().channels.iter().any(|c| c.channel_id == room);
        if !member && joins.as_ref().and_then(|j| j.status(&room_b32)).is_some() {
            // The join failed: what was held is dropped, and said once the Session opens.
            dropped += held.len() as u64;
            held.clear();
            held_bytes = 0;
            continue;
        }
        while let Some(body) = held.front().cloned() {
            if dropped > 0 {
                let notice = serde_json::json!({
                    "v": vox_agentcomms::activity::VERSION,
                    "session": session,
                    "kind": "notice",
                    "ts": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                    "text": format!(
                        "{dropped} {} of this session {} dropped before its room opened",
                        if dropped == 1 { "entry" } else { "entries" },
                        if dropped == 1 { "was" } else { "were" }
                    ),
                })
                .to_string();
                if append_entry(&handle, room, &session, &notice).await.is_ok() {
                    dropped = 0;
                }
            }
            match append_entry(&handle, room, &session, &body).await {
                Ok(()) => {
                    held.pop_front();
                    held_bytes -= body.len();
                    if failing.take().is_some() {
                        eprintln!(
                            "vox daemon: {node}: session {session}: entries reach its Session again"
                        );
                    }
                }
                // Not open yet: held, and tried again.
                Err(vox_core::node::api::Outcome::Failed(
                    vox_core::node::api::Fault::ChannelNotOpen,
                )) => break,
                Err(outcome) => {
                    held.pop_front();
                    held_bytes -= body.len();
                    if failing.as_deref() != Some(outcome.to_string().as_str()) {
                        failing = Some(outcome.to_string());
                        let kind = serde_json::from_str::<serde_json::Value>(&body)
                            .ok()
                            .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_owned))
                            .unwrap_or_default();
                        eprintln!(
                            "vox daemon: {node}: session {session}: a {kind} entry did not reach \
                             its Session: {outcome} (said once; later entries refused the same \
                             way are not said)"
                        );
                    }
                }
            }
        }
    }
}

/// How much of a session's activity is held while its room is not open yet.
const HELD_BYTES: usize = 4 * 1024 * 1024;

/// How often held entries look again for their room.
const HELD_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// Append one entry to `session`'s Session in `room`.
async fn append_entry(
    handle: &vox_core::node::actor::NodeHandle,
    room: vox_core::hash::Digest32,
    session: &str,
    body: &str,
) -> Result<(), vox_core::node::api::Outcome> {
    match handle
        .apply(vox_core::node::api::NodeCommand::AppendSession {
            channel_id: room,
            session_id: session.to_owned(),
            body: body.to_owned(),
        })
        .await
    {
        vox_core::node::api::Outcome::Done | vox_core::node::api::Outcome::Appended(_) => Ok(()),
        other => Err(other),
    }
}

/// Bring the proxy up if any node is attached, down if none is.
fn proxy_follow(weak: &std::sync::Weak<Inner>) {
    let Some(inner) = weak.upgrade() else {
        return;
    };
    let Some(proxy) = inner.proxy.clone() else {
        return;
    };
    let router = Router { inner };
    if router.attached_handles().is_empty() {
        proxy.down();
    } else {
        let nodes_of = Arc::downgrade(&router.inner);
        proxy.up(
            &router.inner.rt,
            crate::daemon_proxy::Nodes(Arc::new(move || {
                nodes_of
                    .upgrade()
                    .map(|inner| Router { inner }.attached_handles())
                    .unwrap_or_default()
            })),
        );
    }
}

/// The requests the daemon serves itself on a node's connection (ADR-026 S-5): `vox lan up`,
/// `vox up`'s question about the proxy, and drive input for the node's own Sessions.
struct DaemonExtension {
    /// The router and the node the connection is attached as: who drives a Session of this node
    /// from its own socket ([`vox_core::node::drive_input::OwnDrive`]).
    drive: (std::sync::Weak<Inner>, NodeName),
    proxy: Option<crate::daemon_proxy::ProxyReport>,
}

impl vox_core::node::ipc::Extension for DaemonExtension {
    fn claims(&self, body: &[u8]) -> bool {
        crate::lan_cli::LanUp.claims(body)
            || (self.proxy.is_some() && crate::daemon_proxy::ProxyReport::claims(body))
            || vox_core::node::drive_input::OwnDrive::parse(body).is_some()
    }

    fn serve(
        &self,
        body: Vec<u8>,
        stream: tokio::net::UnixStream,
        handle: NodeHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        if let Some(own) = vox_core::node::drive_input::OwnDrive::parse(&body) {
            let (inner, node) = self.drive.clone();
            return Box::pin(async move {
                // A daemon that is stopping drives nothing; the client hears no answer.
                if let Some(inner) = inner.upgrade() {
                    Router { inner }
                        .drive_own(&node, &handle, own, stream)
                        .await;
                }
            });
        }
        match &self.proxy {
            Some(report) if crate::daemon_proxy::ProxyReport::claims(&body) => {
                let report = report.clone();
                Box::pin(async move { report.serve(stream).await })
            }
            _ => crate::lan_cli::LanUp.serve(body, stream, handle),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vox_core::node::daemonipc::{AttachMode, Opening};
    use vox_core::node::ipc::{read_frame, write_frame, Frame};

    const PASS: &str = "identity passphrase";

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
    }

    /// An account in a fresh directory, with a node of each name holding an identity.
    async fn account(dir: &std::path::Path, names: &[&str]) -> Account {
        let account = Account::of(Some(&dir.join("d")), Some(&dir.join("c"))).unwrap();
        for name in names {
            let paths = account.node_paths(&NodeName::parse(name).unwrap()).unwrap();
            let (handle, actor) = tokio::task::spawn_blocking(move || {
                Node::spawn_supervised(paths, NodeConfig::new())
            })
            .await
            .unwrap()
            .unwrap();
            let made = handle
                .apply(NodeCommand::CreateIdentity {
                    passphrase: Secret::new(PASS.as_bytes().to_vec()),
                })
                .await;
            assert!(made.is_done(), "APPARATUS: create {name}: {made}");
            let _ = handle.apply(NodeCommand::Shutdown).await;
            drop(handle);
            let _ = actor.await;
        }
        account
    }

    fn router(account: Account) -> Router {
        Router::new(
            account,
            Handle::current(),
            Defaults {
                bind: Arc::new(|_| None),
                anchors: BootstrapSet::new(),
                anchor_specs: Vec::new(),
                listen: String::new(),
                patience: Duration::from_secs(5),
                proxy: None,
            },
        )
    }

    fn n(s: &str) -> NodeName {
        NodeName::parse(s).unwrap()
    }

    fn pass() -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(PASS.into()))
    }

    fn hold(node: &str) -> UseNode {
        UseNode {
            node: n(node),
            attach: AttachMode::Hold,
            passphrase: pass(),
            anchors: Vec::new(),
        }
    }

    fn state(r: &Router, node: &str) -> NodeState {
        r.nodes()
            .into_iter()
            .find(|i| i.name.as_str() == node)
            .map_or(NodeState::Detached, |i| i.state)
    }

    async fn settle(r: &Router, node: &str, want: NodeState) {
        let t0 = std::time::Instant::now();
        while state(r, node) != want && t0.elapsed() < Duration::from_secs(20) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            state(r, node),
            want,
            "PRODUCT: node {node} never became {want:?}"
        );
    }

    /// Two clients holding one node at the same moment both get it, from one attach; the node
    /// stays while either holds it, and detaches when the last lets go (L-2, L-3).
    #[test]
    fn two_holders_share_one_attach_and_the_last_to_go_detaches_it() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let r = router(account(dir.path(), &["alice"]).await);
            let (a, b) = tokio::join!(r.use_node(hold("alice")), r.use_node(hold("alice")));
            let (a, b) = (a.expect("PRODUCT: first"), b.expect("PRODUCT: second"));
            assert_eq!(
                r.inner.next_generation.load(Ordering::Relaxed),
                2,
                "PRODUCT: two attaches for one node"
            );
            assert_eq!(r.metrics().nodes_attached.load(Ordering::Relaxed), 1);
            drop(a);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                state(&r, "alice"),
                NodeState::Attached,
                "PRODUCT: detached with a holder left"
            );
            drop(b);
            settle(&r, "alice", NodeState::Detached).await;
            assert_eq!(r.metrics().nodes_attached.load(Ordering::Relaxed), 0);
        });
    }

    /// A one-shot `Use` of a node not attached is refused and attaches nothing (L-2); a wrong
    /// passphrase is refused and leaves the node detached.
    #[test]
    fn a_one_shot_use_never_attaches_and_a_wrong_passphrase_is_refused() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let r = router(account(dir.path(), &["alice"]).await);
            let once = r
                .use_node(UseNode {
                    attach: AttachMode::No,
                    ..hold("alice")
                })
                .await;
            assert!(matches!(once, Err(Refusal::NotAttached { .. })), "PRODUCT");
            let wrong = r
                .use_node(UseNode {
                    passphrase: Some(Zeroizing::new("wrong".into())),
                    ..hold("alice")
                })
                .await;
            assert!(
                matches!(wrong, Err(Refusal::WrongPassphrase { .. })),
                "PRODUCT"
            );
            assert_eq!(state(&r, "alice"), NodeState::Detached);
            let none = r.use_node(hold("bob")).await;
            assert!(matches!(none, Err(Refusal::NoSuchNode { .. })), "PRODUCT");
        });
    }

    /// An agent session never attaches its node (ADR-028 K-13); one attached by hand stays
    /// attached when the session ends (L-3, ADR-020 6.10).
    #[test]
    fn a_session_attaches_nothing_and_its_end_leaves_a_node_attached_by_hand() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let r = router(account(dir.path(), &["agent", "person"]).await);
            let s = crate::wake::Session::from_env("s-1", true);
            let refused = r.session_register(&n("agent"), s, None).await;
            assert!(
                matches!(refused, Err(Refusal::NotAttached { .. })),
                "PRODUCT: a session attached its node: {refused:?}"
            );
            assert_eq!(state(&r, "agent"), NodeState::Detached);

            r.attach(&n("person"), pass(), None, Vec::new(), Vec::new())
                .await
                .unwrap();
            let s = crate::wake::Session::from_env("s-2", true);
            r.session_register(&n("person"), s, None).await.unwrap();
            let (_, detached) = r.session_end(&n("person"), "s-2", "").await;
            assert!(
                !detached,
                "PRODUCT: a node attached by hand detached with a session"
            );
            assert_eq!(state(&r, "person"), NodeState::Attached);
        });
    }

    /// Over the account socket: a connection acting as a node is told "node detached" when the
    /// node is detached under it, and the connection ends (L-3, L-7).
    #[test]
    fn a_connection_is_told_its_node_detached() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let account = account(dir.path(), &["alice"]).await;
            let sock = account.socket();
            let r = router(account);
            let _server =
                vox_core::node::ipc::bind_account(Arc::new(r.clone()), sock.clone()).unwrap();
            let mut s = tokio::net::UnixStream::connect(&sock).await.unwrap();
            let hello = read_frame(&mut s).await.unwrap().unwrap();
            assert!(matches!(
                DaemonFrame::from_bytes(&hello).unwrap(),
                DaemonFrame::Hello { .. }
            ));
            write_frame(&mut s, &Opening::Use(hold("alice")).to_bytes())
                .await
                .unwrap();
            let using = read_frame(&mut s).await.unwrap().unwrap();
            assert!(
                matches!(
                    DaemonFrame::from_bytes(&using).unwrap(),
                    DaemonFrame::Using { .. }
                ),
                "PRODUCT: the Use was not taken"
            );
            r.detach(&n("alice"), DetachCause::Requested).await.unwrap();
            let told = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut s))
                .await
                .expect("PRODUCT: nothing said within 10 s")
                .unwrap()
                .map(|b| Frame::from_bytes(&b).unwrap());
            assert_eq!(
                told,
                Some(Frame::NodeDetached { node: n("alice") }),
                "PRODUCT: the connection was not told its node detached"
            );
            assert!(
                read_frame(&mut s).await.unwrap().is_none(),
                "PRODUCT: still open"
            );
        });
    }

    /// A panic in one node's actor detaches that node only, reports it, and counts it; the other
    /// node goes on answering (L-6).
    #[cfg(feature = "test-knobs")]
    #[test]
    fn one_nodes_panic_leaves_the_other_running() {
        std::env::set_var(vox_core::node::actor::TEST_PANIC_ON_TEXT_ENV, "BOOM-MARKER");
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let r = router(account(dir.path(), &["a", "b"]).await);
            let mut events = r.inner.events.subscribe();
            for node in ["a", "b"] {
                r.attach(&n(node), pass(), None, Vec::new(), Vec::new())
                    .await
                    .unwrap();
            }
            let a = r
                .use_node(UseNode {
                    attach: AttachMode::No,
                    ..hold("a")
                })
                .await
                .unwrap();
            let _ = a
                .handle
                .apply(NodeCommand::SendText {
                    channel_id: [0u8; 32],
                    text: "this holds BOOM-MARKER".into(),
                })
                .await;
            let ev = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Ok(DaemonEvent::Detached { node, cause }) = events.recv().await {
                        return (node, cause);
                    }
                }
            })
            .await
            .expect("PRODUCT: no detach event after the panic");
            assert_eq!(ev.0, n("a"));
            assert!(
                matches!(ev.1, DetachCause::Panicked(_)),
                "PRODUCT: {:?}",
                ev.1
            );
            assert_eq!(r.metrics().node_panics.load(Ordering::Relaxed), 1);
            settle(&r, "a", NodeState::Detached).await;
            assert_eq!(state(&r, "b"), NodeState::Attached);
            let b = r
                .use_node(UseNode {
                    attach: AttachMode::No,
                    ..hold("b")
                })
                .await
                .unwrap();
            assert!(
                b.handle.status().await.is_ok(),
                "PRODUCT: b stopped answering"
            );
            // The panicked node attaches again.
            r.attach(&n("a"), pass(), None, Vec::new(), Vec::new())
                .await
                .expect("PRODUCT: the panicked node could not attach again");
        });
    }

    /// `--keep` records a node with its passphrase source; a new router attaches it from the file;
    /// a detach by hand forgets it (L-4).
    #[test]
    fn a_kept_node_is_attached_again_and_forgotten_when_detached() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let account = account(dir.path(), &["alice"]).await;
            let file = dir.path().join("pass");
            std::fs::write(&file, format!("{PASS}\n")).unwrap();
            {
                let r = router(account.clone());
                r.attach(
                    &n("alice"),
                    pass(),
                    Some(KeepSource::File(file.clone())),
                    Vec::new(),
                    Vec::new(),
                )
                .await
                .unwrap();
                r.stop_all().await;
            }
            let kept = std::fs::read_to_string(account.attach_file()).unwrap();
            assert_eq!(kept, format!("alice\tfile:{}\n", file.display()), "PRODUCT");
            let r = router(account.clone());
            r.attach_kept();
            settle(&r, "alice", NodeState::Attached).await;
            r.detach(&n("alice"), DetachCause::Requested).await.unwrap();
            let kept = std::fs::read_to_string(account.attach_file()).unwrap();
            assert_eq!(kept, "", "PRODUCT: a node detached by hand stayed kept");
        });
    }
}
