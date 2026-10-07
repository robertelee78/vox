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
    /// Where harness sessions' activity is numbered and posted, and approvals wait (ADR-029).
    sink: Arc<crate::session_sink::Sink>,
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
    /// An agent session: attached implicitly if need be, and held while it is registered.
    Session(Box<crate::wake::Session>),
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
                let weak = weak.clone();
                let sink = crate::session_sink::Sink::new(Arc::new(
                    move |node: &NodeName, session: &str, bodies: Vec<String>| {
                        if let Some(inner) = weak.upgrade() {
                            Router { inner }.post_session(node, session, bodies);
                        }
                    },
                ));
                Inner {
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
                    sink,
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
        let g = self
            .want(node, Want::Explicit(keep), passphrase, rooms, anchors)
            .await?;
        self.write_attach_file(None);
        Ok((g.info, g.notes))
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
    /// holder, attaching the node implicitly if it is not attached.
    ///
    /// # Errors
    /// The [`Refusal`] the hook is told.
    pub async fn session_register(
        &self,
        node: &NodeName,
        session: crate::wake::Session,
        passphrase: Option<Zeroizing<String>>,
        anchors: Vec<String>,
    ) -> Result<NodeInfo, Refusal> {
        let g = self
            .want(
                node,
                Want::Session(Box::new(session)),
                passphrase,
                Vec::new(),
                anchors,
            )
            .await?;
        Ok(g.info)
    }

    /// Post `bodies`, numbered, to `session`'s Session: sealed to the members `node` trusts with
    /// drive (ADR-029 SC-2), in the room the session works in.
    // WIP(#540): reads2's `NodeCommand::AppendSession` and files2's session room are not on
    // integrate yet; until they are, nothing is posted. Never posted unsealed.
    fn post_session(&self, node: &NodeName, session: &str, bodies: Vec<String>) {
        let _ = (node, session, bodies);
    }

    /// Unregister an agent session of `node`, and detach the node if it was attached implicitly
    /// and that session was its last holder, **in one decision** (L-3): the unregister and the
    /// move to `Detaching` happen in one critical section, so a session registering at the same
    /// moment either comes first (and the node stays) or finds the node detaching and waits.
    ///
    /// Returns whether the session was registered, and whether the node detached.
    pub async fn session_end(&self, node: &NodeName, session: &str) -> (bool, bool) {
        self.inner.sink.session_end(node, session);
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
                        let w = want.take().unwrap_or(Want::IfAttached);
                        return Ok(self.grant(node, a, w));
                    }
                    Some(Slot::Attaching(rx)) => Step::WaitAttach(rx.clone()),
                    Some(Slot::Detaching(rx)) => Step::WaitDetach(rx.clone()),
                    None if matches!(want, Some(Want::IfAttached)) => Step::NotAttached,
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
                    let w = want.take().unwrap_or(Want::IfAttached);
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
                            let fingerprint = a.fingerprint;
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
                if keep.is_some() {
                    a.keep = keep;
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
                a.sessions.insert(s.session.clone());
                None
            }
            Want::IfAttached => None,
        };
        Granted {
            info: info_of_attached(node, a),
            handle: a.handle.clone(),
            detached: a.detached.subscribe(),
            hold,
            notes: Vec::new(),
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
        let _ = done.send(true);
        if forget_keep {
            self.write_attach_file(Some(&node));
        }
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
    fn write_attach_file(&self, forget: Option<&NodeName>) {
        if self.inner.stopping.load(Ordering::SeqCst) {
            return;
        }
        let path = self.inner.account.attach_file();
        let mut kept: BTreeMap<NodeName, KeepSource> =
            read_attach_file(&path).into_iter().collect();
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
            }
            text.push('\n');
        }
        if let Err(e) = vox_core::node::paths::create_private_dir(&self.inner.account.daemon_dir())
            .and_then(|()| vox_core::node::paths::write_private_file_unique(&path, text.as_bytes()))
        {
            eprintln!("vox daemon: could not write {}: {e}", path.display());
        }
    }
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

/// `.daemon/attach`: one line per kept node, `<name>\t(none|file:<path>)`. A line that does not
/// parse is skipped.
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
            DaemonRequest::SessionRegister {
                node,
                session,
                record,
                passphrase,
                anchors,
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
                match self
                    .session_register(&node, record, passphrase, anchors)
                    .await
                {
                    Ok(info) => DaemonFrame::Attached(info, Vec::new()),
                    Err(r) => refused(r),
                }
            }
            DaemonRequest::SessionEnd { node, session } => {
                let (was_registered, detached) = self.session_end(&node, &session).await;
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

/// The requests the daemon serves itself on a node's connection (ADR-026 S-5): `vox lan up`, and
/// `vox up`'s question about the proxy.
struct DaemonExtension {
    proxy: Option<crate::daemon_proxy::ProxyReport>,
}

impl vox_core::node::ipc::Extension for DaemonExtension {
    fn claims(&self, body: &[u8]) -> bool {
        crate::lan_cli::LanUp.claims(body)
            || (self.proxy.is_some() && crate::daemon_proxy::ProxyReport::claims(body))
    }

    fn serve(
        &self,
        body: Vec<u8>,
        stream: tokio::net::UnixStream,
        handle: NodeHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
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

    /// An agent session holds its node; the session's end is its last holder going, and the node
    /// detaches in the same decision (L-3, ADR-020 6.10). A node attached by hand stays.
    #[test]
    fn a_sessions_end_detaches_its_implicit_node_and_not_a_kept_one() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let r = router(account(dir.path(), &["agent", "person"]).await);
            let s = crate::wake::Session::from_env("s-1", true);
            r.session_register(&n("agent"), s, pass(), Vec::new())
                .await
                .expect("PRODUCT: register");
            let lease = r.use_node(hold("agent")).await.unwrap();
            drop(lease);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                state(&r, "agent"),
                NodeState::Attached,
                "PRODUCT: a registered session did not hold its node"
            );
            let (was, detached) = r.session_end(&n("agent"), "s-1").await;
            assert!(was && detached, "PRODUCT: end said {was} {detached}");
            assert_eq!(state(&r, "agent"), NodeState::Detached);

            r.attach(&n("person"), pass(), None, Vec::new(), Vec::new())
                .await
                .unwrap();
            let s = crate::wake::Session::from_env("s-2", true);
            r.session_register(&n("person"), s, None, Vec::new())
                .await
                .unwrap();
            let (_, detached) = r.session_end(&n("person"), "s-2").await;
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
