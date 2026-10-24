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

mod anchor_discovery;
mod attention;
mod computer;
mod local_trust;
pub(crate) mod room_pause;
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
    AnchorInfo, AnchorSource, DaemonEvent, DaemonFrame, DaemonRequest, DaemonStatus, DetachCause,
    KeepSource, NodeInfo, NodeState, NodeStatus, Refusal, UseNode,
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
    /// Account-owned management role and durable computer policy.
    pub computer: Arc<vox_core::node::computer::Management>,
    /// Where a node binds when it attaches (ADR-026 D-3): the daemon's one presence once it is
    /// shared; `None` attaches a node off the network.
    pub bind: BindFor,
    /// The startup command-line anchors, already validated.
    pub anchors: BootstrapSet,
    /// The command-line specs, which the machine refresh re-resolves.
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
    /// Archive and live/control reservations span every node this daemon hosts.
    history_budget: Arc<vox_core::node::history_budget::Budget>,
    account: Account,
    rt: Handle,
    defaults: Defaults,
    /// One machine set, serializing refresh and attachment so every node receives the same
    /// complete manual configuration. Room anchors remain owned by their rooms.
    manual_anchors: tokio::sync::Mutex<MachineAnchors>,
    /// At most one blocking DNS refresh, including one whose bounded caller has timed out.
    manual_refresh: Arc<tokio::sync::Mutex<()>>,
    slots: Mutex<BTreeMap<NodeName, Slot>>,
    /// For a headless node in the anchor role, the creators whose rooms it serves; absent, any
    /// room (`vox node --serve`, ADR-026 N-5).
    serve_only: Mutex<BTreeMap<NodeName, BTreeSet<Digest32>>>,
    events: broadcast::Sender<DaemonEvent>,
    metrics: Arc<DaemonMetrics>,
    stopping: AtomicBool,
    next_generation: AtomicU64,
    /// One search at a time; concurrent clients do not multiply sockets or network traffic.
    anchor_search: tokio::sync::Mutex<()>,
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
    /// The kept nodes this daemon's start is attaching and has not finished with (#666): listed
    /// as attaching from the moment the daemon serves, so a hook asking then is told the truth.
    starting: Mutex<BTreeSet<NodeName>>,
    /// Each node's joins of its sessions' rooms under way (ADR-029 RB-3).
    joins: Mutex<BTreeMap<NodeName, Arc<vox_core::node::room_join::Joins>>>,
    /// Where harness sessions' activity is numbered and posted, and approvals wait (ADR-029).
    sink: Arc<crate::session_sink::Sink>,
    /// Ordered admission and the bounded, explicitly volatile storage-failure tail.
    posting: tokio::sync::Mutex<SessionHolds>,
    session_admissions: Arc<tokio::sync::Semaphore>,
    /// The Claude Code sessions whose transcript is read for a new name (ADR-029 MD-1).
    titles: Mutex<BTreeSet<(NodeName, String)>>,
    /// Durable registrations whose idempotent room opening is in flight. Registration must
    /// answer a hook without waiting for room history/projection readiness; one detached worker
    /// per Session owns that later work, and a daemon restart rebuilds it from the saved records.
    session_openings: Mutex<BTreeSet<(NodeName, String)>>,
    /// A completed opening failure is told on the Session's next hook before that hook retries.
    session_open_failures: Mutex<BTreeMap<(NodeName, String), String>>,
    /// Codex sessions' activity, read from Codex's app-server as a peer client (ADR-029 #541).
    codex: Arc<crate::codex_mirror::CodexMirror>,
    /// OpenCode sessions' activity, read through Vox's OpenCode plugin (ADR-029 #542).
    opencode: Arc<crate::opencode_mirror::OpenCodeMirror>,
}

struct MachineAnchors {
    revision: u64,
    specs: Vec<String>,
    inputs: Vec<(String, String)>,
    set: BootstrapSet,
    skipped: Vec<String>,
}

/// A member's answer as the sink took it: handed to the harness, or why not.
fn handed(h: crate::session_sink::Handed) -> Result<String, String> {
    match h {
        crate::session_sink::Handed::ToHarness => Ok("handed to the session; it decides".into()),
        crate::session_sink::Handed::Refused(why) => Err(why),
    }
}

/// A detach is pending until its actor and remembered-state cleanup have an outcome.
type DetachOutcome = Option<Result<(), Refusal>>;

/// One node's place in its life (L-1). A node with no slot is detached.
enum Slot {
    /// Being attached; the outcome arrives here.
    Attaching(watch::Receiver<Option<Result<(), Refusal>>>),
    /// Running.
    Attached(Box<Attached>),
    /// Being detached; the outcome arrives after its remembered-state cleanup finishes.
    Detaching(watch::Receiver<DetachOutcome>),
}

/// An attached node.
struct ComputerReconciliation {
    target: vox_core::node::computer::ComputerPolicyTarget,
    pass: u64,
    superseded: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for ComputerReconciliation {
    fn drop(&mut self) {
        self.superseded
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

struct Attached {
    handle: NodeHandle,
    paths: Paths,
    /// Which attach this is: a release or a panic meant for an earlier one changes nothing.
    generation: u64,
    /// Exact policy target and pass currently reconciling this attach. Dropping it supersedes the
    /// actor future on policy movement, detach, or daemon shutdown; elapsed time never does.
    computer_reconciliation: Option<ComputerReconciliation>,
    /// Attached implicitly: it detaches when its last holder goes (L-3).
    implicit: bool,
    /// The actual credential that opened this identity was empty (or this is a headless node).
    /// Such a node cannot be Locked and does not end with its last client (ADR-031 CW-5).
    unprotected: bool,
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
    /// Drains bounded room-retirement notifications before a replacement actor may attach.
    session_retirements: Option<tokio::task::JoinHandle<()>>,
    fingerprint: Option<Digest32>,
    /// Only headless anchor roles answer an explicit LAN anchor search.
    anchor: bool,
}

/// How a node is wanted, and so how its attach counts.
enum Want {
    /// `vox node unlock` (or `--keep` at start): stays until detached by hand (L-3).
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
                        begin_detach(&mut slots, &self.node, &inner.defaults.computer)
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
                let _ = router
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
    management: &vox_core::node::computer::Management,
) -> Option<(Box<Attached>, watch::Sender<DetachOutcome>)> {
    let (tx, rx) = watch::channel(None);
    match slots.insert(node.clone(), Slot::Detaching(rx)) {
        Some(Slot::Attached(mut a)) => {
            // Lifecycle supersession belongs to this slot transition, not later actor cleanup.
            // Drop the exact owned flight now so its guard cannot keep publishing while detach
            // waits for other work. This same slot lock fences every pending-result writer and
            // prevents a replacement attachment from acquiring status that we could erase.
            #[cfg(feature = "test-knobs")]
            let keep_reconciliation = a.computer_reconciliation.as_ref().is_some_and(|flight| {
                management.keep_detach_reconciliation_for_proof(node.as_str(), flight.target)
                    && a.handle.computer_current()
            });
            #[cfg(not(feature = "test-knobs"))]
            let keep_reconciliation = false;
            if !keep_reconciliation {
                drop(a.computer_reconciliation.take());
                management.node_detached(node.as_str());
            }
            Some((a, tx))
        }
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
                let (weak, weak_room, weak_rename, weak_attention) =
                    (weak.clone(), weak.clone(), weak.clone(), weak.clone());
                let sink = crate::session_sink::Sink::new(
                    Arc::new(
                        move |node: NodeName,
                              session: String,
                              room: Digest32,
                              bodies: Vec<String>,
                              effects: Option<crate::session_sink::SourceEffects>| {
                            let weak = weak.clone();
                            Box::pin(async move {
                                match weak.upgrade() {
                                    Some(inner) => {
                                        let mut fresh = false;
                                        let admission = Router { inner }
                                            .post_session(&node, &session, room, bodies, effects, &mut fresh)
                                            .await;
                                        crate::session_sink::Posted { admission, fresh }
                                    }
                                    None => vox_core::node::daemonipc::SessionAdmission::Refused(
                                        "the daemon stopped".into(),
                                    )
                                    .into(),
                                }
                            })
                        },
                    ),
                    Arc::new(move |node: &NodeName, session: &str| {
                        let inner = weak_room.upgrade()?;
                        Router { inner }.session_destination(node, session)
                    }),
                    Arc::new(move |node: &NodeName, session: &str, name: &str| {
                        if let Some(inner) = weak_rename.upgrade() {
                            Router { inner }.rename_session(node, session, name);
                        }
                    }),
                    Arc::new(move |node, endpoint, token, observation| {
                        let weak = weak_attention.clone();
                        Box::pin(async move {
                            let inner = weak.upgrade().ok_or("the daemon stopped")?;
                            Router { inner }
                                .observe_attention(&node, &endpoint, &token, observation)
                                .await
                        })
                    }),
                );
                let codex = crate::codex_mirror::CodexMirror::new(Arc::clone(&sink));
                let opencode = crate::opencode_mirror::OpenCodeMirror::new(Arc::clone(&sink));
                Inner {
                    history_budget: vox_core::node::history_budget::Budget::new(),
                    codex,
                    opencode,
                    account,
                    rt,
                    manual_anchors: tokio::sync::Mutex::new(MachineAnchors {
                        revision: 0,
                        specs: defaults.anchor_specs.clone(),
                        inputs: Vec::new(),
                        set: defaults.anchors.clone(),
                        skipped: Vec::new(),
                    }),
                    manual_refresh: Arc::new(tokio::sync::Mutex::new(())),
                    defaults,
                    slots: Mutex::new(BTreeMap::new()),
                    events: broadcast::channel(256).0,
                    metrics: Arc::new(DaemonMetrics::default()),
                    stopping: AtomicBool::new(false),
                    next_generation: AtomicU64::new(1),
                    anchor_search: tokio::sync::Mutex::new(()),
                    stop_asked: tokio::sync::Notify::new(),
                    serve_only: Mutex::default(),
                    unfinished_stop: AtomicBool::new(false),
                    connections: Arc::default(),
                    proxy,
                    keep_file: tokio::sync::Mutex::new(()),
                    starting: Mutex::new(BTreeSet::new()),
                    sink,
                    posting: tokio::sync::Mutex::default(),
                    session_admissions: Arc::new(tokio::sync::Semaphore::new(64)),
                    titles: Mutex::default(),
                    session_openings: Mutex::default(),
                    session_open_failures: Mutex::default(),
                    joins: Mutex::default(),
                }
            }),
        };
        router.follow_attached_with_the_proxy();
        router.follow_machine_anchors();
        router.answer_anchor_searches();
        router.follow_local_trust();
        router.follow_computer_trust();
        router.follow_session_holds();
        router
    }

    /// Re-read and re-resolve manual inputs once for this daemon, including removals. DNS runs
    /// on a blocking worker. The task holds the router weakly and ends when the daemon stops.
    fn follow_machine_anchors(&self) {
        let weak = Arc::downgrade(&self.inner);
        let mut network = self.machine_network();
        self.inner.rt.spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                if inner.stopping.load(Ordering::SeqCst) {
                    return;
                }
                let (_, notes) = Router { inner }.refresh_manual_anchors(&[]).await;
                let retry = if notes.is_empty() { 30 } else { 5 };
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(retry)) => {},
                    () = async {
                        if let Some(network) = &mut network {
                            if network.changed().await.is_ok() { return; }
                        }
                        std::future::pending::<()>().await;
                    } => {},
                }
            }
        });
    }

    fn machine_network(&self) -> Option<watch::Receiver<u64>> {
        let name = NodeName::parse("default").ok()?;
        match (self.inner.defaults.bind)(&name)? {
            Bind::Shared(presence) => Some(presence.network_generation()),
            _ => None,
        }
    }

    /// Command-line anchors are manual machine inputs for this daemon's life. Every refreshed
    /// set replaces the previous set on every attached node, including an empty set.
    async fn refresh_manual_anchors(&self, extra: &[String]) -> (BootstrapSet, Vec<String>) {
        let (revision, specs, previous) = {
            let mut state = self.inner.manual_anchors.lock().await;
            for spec in extra.iter().filter(|spec| !spec.trim().is_empty()) {
                if !state.specs.contains(spec) {
                    state.specs.push(spec.clone());
                    state.revision = state.revision.wrapping_add(1);
                }
            }
            (state.revision, state.specs.clone(), state.set.clone())
        };
        let network = self.machine_network();
        let generation = network.as_ref().map(|network| *network.borrow());
        let account = self.inner.account.clone();
        // Read configuration independently of any outstanding DNS worker. A stuck hostname
        // must not prevent a newly added numeric candidate from becoming usable.
        let read = tokio::task::spawn_blocking(move || {
            let (mut inputs, skipped) = vox_core::node::link::machine_anchor_inputs(&account);
            inputs.extend(
                specs
                    .into_iter()
                    .map(|spec| (format!("anchor {spec}"), spec)),
            );
            (inputs, skipped)
        });
        let (inputs, mut skipped) = match tokio::time::timeout(Duration::from_secs(3), read).await {
            Ok(Ok(inputs)) => inputs,
            _ => {
                return (
                    previous,
                    vec![
                        "machine anchor inputs could not be read within 3 seconds; retrying".into(),
                    ],
                )
            }
        };
        let mut numeric = BootstrapSet::new();
        let mut names = Vec::new();
        for (label, spec) in &inputs {
            let address = spec
                .split_once('@')
                .map(|(_, addr)| addr.trim())
                .unwrap_or("");
            let hostname = address.starts_with("/dns")
                || (!address.is_empty()
                    && !address.starts_with('/')
                    && address.parse::<std::net::SocketAddr>().is_err());
            if hostname {
                names.push((label.clone(), spec.clone()));
            } else if let Err(error) = vox_core::node::link::merge_anchor_spec(&mut numeric, spec) {
                skipped.push(format!("{label} is skipped: {error}"));
            }
        }
        let (revision, interim) = {
            let mut state = self.inner.manual_anchors.lock().await;
            let mut interim = numeric.clone();
            {
                let current = network.as_ref().map(watch::Receiver::borrow);
                if state.revision != revision || current.as_deref().copied() != generation {
                    return (
                        state.set.clone(),
                        vec![
                            "machine anchors or network changed during input read; retrying".into(),
                        ],
                    );
                }
                // Keep still-authorized hostname hints from the latest published set, never
                // the pre-read snapshot: another refresh may have resolved a newer endpoint.
                for (_, spec) in &names {
                    if let Some(id) = spec.split_once('@').and_then(|(id, _)| {
                        vox_core::node::link::fingerprint_input(id, "anchor").ok()
                    }) {
                        if let Some(node) = state.set.get(&id) {
                            for spec in vox_core::node::link::anchor_specs(node) {
                                let _ =
                                    vox_core::node::link::merge_anchor_spec(&mut interim, &spec);
                            }
                        }
                    }
                }
                if state.inputs != inputs {
                    state.inputs = inputs;
                    state.revision = state.revision.wrapping_add(1);
                }
                if skipped != state.skipped {
                    for line in &skipped {
                        eprintln!("vox daemon: {line}");
                    }
                }
                state.set = interim.clone();
                state.skipped = skipped.clone();
            }
            self.deliver_manual_anchors(&state).await;
            (state.revision, interim)
        };
        if names.is_empty() {
            return (interim, skipped);
        }
        let Ok(refresh) = Arc::clone(&self.inner.manual_refresh).try_lock_owned() else {
            skipped.push(
                "machine anchor DNS is still in progress; numeric endpoints are available".into(),
            );
            return (interim, skipped);
        };
        let cached = interim.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            let mut set = numeric;
            for (label, spec) in names {
                if let Err(error) = vox_core::node::link::merge_anchor_spec(&mut set, &spec) {
                    skipped.push(format!("{label} is skipped: {error}"));
                    if let Some(id) = spec.split_once('@').and_then(|(id, _)| {
                        vox_core::node::link::fingerprint_input(id, "anchor").ok()
                    }) {
                        if let Some(node) = cached.get(&id) {
                            for spec in vox_core::node::link::anchor_specs(node) {
                                let _ = vox_core::node::link::merge_anchor_spec(&mut set, &spec);
                            }
                        }
                    }
                }
            }
            // Hold the refresh guard through publication, not just resolution. A completed
            // older refresh must not overwrite a newer same-revision refresh out of order.
            (set, skipped, refresh)
        });
        let (set, skipped, _refresh) = match tokio::time::timeout(Duration::from_secs(3), resolved).await {
            Ok(Ok(resolved)) => resolved,
            Ok(Err(error)) => return (interim, vec![format!("machine anchor refresh did not finish: {error}")]),
            Err(_) => return (interim, vec!["machine anchor DNS did not finish within 3 seconds; numeric endpoints are available, retrying".into()]),
        };
        let mut state = self.inner.manual_anchors.lock().await;
        {
            let current = network.as_ref().map(watch::Receiver::borrow);
            if state.revision != revision || current.as_deref().copied() != generation {
                return (
                    state.set.clone(),
                    vec!["machine anchors or network changed during resolution; retrying".into()],
                );
            }
            if skipped != state.skipped {
                for line in &skipped {
                    eprintln!("vox daemon: {line}");
                }
            }
            state.set = set;
            state.skipped = skipped;
        }
        self.deliver_manual_anchors(&state).await;
        (state.set.clone(), state.skipped.clone())
    }

    async fn deliver_manual_anchors(&self, state: &MachineAnchors) {
        // Keep the refresh lock until delivery finishes: no old set can overtake a mutation.
        for (_, node) in self.attached_handles() {
            let _ = node
                .apply(NodeCommand::SetAnchors {
                    anchors: state.set.clone(),
                })
                .await;
        }
    }

    async fn change_manual_anchor(
        &self,
        add: Option<String>,
        remove: Option<Digest32>,
    ) -> Result<Vec<AnchorInfo>, String> {
        // Lookup is bounded network work outside the writer lock; only its verified result is
        // committed. A supplied fingerprint is an offline configuration input, not reach proof.
        let network = self.machine_network();
        let generation = network.as_ref().map(|network| *network.borrow());
        let (add, resolved_add) = match add {
            Some(input) => {
                let (input, node) = self.resolve_anchor_input(&input).await?;
                (Some(input), Some(node))
            }
            None => (None, None),
        };
        let mut state = self.inner.manual_anchors.lock().await;
        let account = self.inner.account.clone();
        let extra = state.specs.clone();
        let result = tokio::task::spawn_blocking(move || {
            vox_core::node::link::change_manual_anchor(&account, &extra, add.as_deref(), remove)
        })
        .await
        .map_err(|error| format!("manual anchor update did not finish: {error}"))?
        .map_err(|error| error.to_string())?;
        // A removed transient input must not return on refresh, while unrelated startup
        // inputs remain daemon-only rather than silently becoming persistent.
        state.specs = result;
        state.revision = state.revision.wrapping_add(1);
        if let Some(remove) = remove {
            let mut set = BootstrapSet::new();
            for node in state.set.nodes().iter().filter(|node| node.id != remove) {
                let _ = set.add(node.clone());
            }
            state.set = set;
        }
        {
            let current = network.as_ref().map(watch::Receiver::borrow);
            if let Some(node) = resolved_add.filter(|_| current.as_deref().copied() == generation) {
                // The lookup finished before the writer lock. These are numeric multiaddrs,
                // so neither publication nor another node's attachment waits for DNS here.
                for spec in vox_core::node::link::anchor_specs(&node) {
                    vox_core::node::link::merge_anchor_spec(&mut state.set, &spec).map_err(
                        |error| format!("manual anchor saved but endpoint update failed: {error}"),
                    )?;
                }
            }
        }
        self.deliver_manual_anchors(&state).await;
        drop(state);
        self.refresh_manual_anchors(&[]).await;
        self.anchor_list().await.map_err(|error| {
            format!("manual anchors saved, but inventory could not be read: {error}")
        })
    }

    async fn resolve_anchor_input(
        &self,
        input: &str,
    ) -> Result<(String, vox_core::nat::bootstrap::BootstrapNode), String> {
        let mut input = input.trim().to_owned();
        if !input.contains('@') {
            input = self
                .inner
                .defaults
                .computer
                .lookup_anchor(&input)
                .await
                .map_err(|error| error.to_string())?;
        }
        let checked = input.clone();
        let node = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::task::spawn_blocking(move || vox_core::node::link::parse_anchor_spec(&checked)),
        )
        .await
        .map_err(|_| "anchor address resolution did not finish within 3 seconds".to_owned())?
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
        Ok((input, node))
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

    /// One machine display list, including last-known provenance from locked nodes and closed
    /// rooms. Saved observations never enter the manual set delivered to node actors.
    async fn anchor_list(&self) -> Result<Vec<AnchorInfo>, Refusal> {
        let manual = self.inner.manual_anchors.lock().await;
        let mut all = BTreeMap::new();
        for anchor in manual.set.nodes() {
            all.insert(
                anchor.id,
                AnchorInfo {
                    fingerprint: anchor.id,
                    addresses: anchor
                        .endpoints
                        .addrs()
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    sources: vec![AnchorSource::AddedByHand],
                    reach: None,
                },
            );
        }
        drop(manual);
        let attached: BTreeMap<_, _> = self.attached_handles().into_iter().collect();
        let mut rooms = Vec::new();
        let mut names = BTreeMap::<Digest32, (bool, u64, String)>::new();
        for node in self.nodes() {
            let inventory = if let Some(handle) = attached.get(node.name.as_str()) {
                let view = handle.view();
                if let Some(why) = view.anchor_inventory_error {
                    return Err(Refusal::Failed {
                        node: node.name,
                        why: format!("cannot read the anchor inventory: {why}"),
                    });
                }
                view.room_anchors
            } else {
                let paths = self.inner.account.node_paths_as_they_are(&node.name);
                vox_core::node::anchor_inventory::load(&paths).map_err(|error| Refusal::Failed {
                    node: node.name,
                    why: format!("cannot read the anchor inventory: {error}"),
                })?
            };
            for room in inventory {
                // Every saved local copy contributes its own observed anchors. One node leaving
                // must not remove another node's saved-room provenance. Prefer a live shared
                // name, then the latest observed change, without discarding either anchor set.
                let observation = (
                    !room.stale,
                    room.observed_at,
                    room.name.clone().unwrap_or_default(),
                );
                if names.get(&room.room).is_none_or(|old| observation > *old) {
                    names.insert(room.room, observation);
                }
                rooms.push(room);
            }
        }
        for room in rooms {
            for anchor in room.anchors.nodes() {
                let entry = all.entry(anchor.id).or_insert_with(|| AnchorInfo {
                    fingerprint: anchor.id,
                    addresses: Vec::new(),
                    sources: Vec::new(),
                    reach: None,
                });
                entry
                    .addresses
                    .extend(anchor.endpoints.addrs().iter().map(ToString::to_string));
                if let Some(AnchorSource::Room { stale, .. }) = entry.sources.iter_mut().find(
                    |source| matches!(source, AnchorSource::Room { room: id, .. } if *id == room.room),
                ) {
                    // A union that contains any last-known observation is marked as such,
                    // including an old address held by a locked local copy of the same room.
                    *stale |= room.stale;
                } else {
                    entry.sources.push(AnchorSource::Room {
                        room: room.room,
                        name: names.get(&room.room).map_or_else(String::new, |row| row.2.clone()),
                        stale: room.stale,
                    });
                }
            }
        }
        for (_, handle) in attached {
            for (id, reach) in handle.view().anchor_reach {
                if let Some(anchor) = all.get_mut(&id) {
                    match &mut anchor.reach {
                        None => anchor.reach = Some(reach),
                        Some(current) => {
                            current.connected |= reach.connected;
                            current.last_reached_ms =
                                current.last_reached_ms.max(reach.last_reached_ms);
                            current.unreached_since_ms = if current.connected {
                                None
                            } else {
                                current.unreached_since_ms.max(reach.unreached_since_ms)
                            };
                        }
                    }
                }
            }
        }
        Ok(all
            .into_values()
            .map(|mut anchor| {
                anchor.addresses.sort();
                anchor.addresses.dedup();
                anchor.sources.sort();
                anchor
            })
            .collect())
    }

    /// Every node: each on disk, and any slot besides, with its state.
    #[must_use]
    pub fn nodes(&self) -> Vec<NodeInfo> {
        let remembered: BTreeSet<NodeName> = read_attach_file(&self.inner.account.attach_file())
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let slots = lock(&self.inner.slots);
        let mut names: BTreeSet<NodeName> =
            self.inner.account.nodes_on_disk().into_iter().collect();
        names.extend(slots.keys().cloned());
        names
            .into_iter()
            .map(|name| {
                let mut info = info_of(&name, slots.get(&name));
                if !matches!(slots.get(&name), Some(Slot::Attached(_))) {
                    info.keep = remembered.contains(&name);
                }
                if slots.get(&name).is_none() && lock(&self.inner.starting).contains(&name) {
                    info.state = NodeState::Attaching;
                }
                // A node not attached: its public fingerprint file, for display only (P8).
                if info.fingerprint.is_none() {
                    info.fingerprint = self
                        .inner
                        .account
                        .node_paths(&name)
                        .ok()
                        .and_then(|p| p.shown_fingerprint());
                }
                info
            })
            .collect()
    }

    /// The public list verifies a stopped node's persisted fact before giving it a label.
    /// A passphrase-free node is made Ready by a real unlock, never by changing its label.
    async fn public_nodes(&self) -> Result<Vec<NodeInfo>, Refusal> {
        if let Err(e) = read_attach_file_checked(&self.inner.account.attach_file()) {
            let node = match self.inner.account.nodes_on_disk().into_iter().next() {
                Some(node) => node,
                None => NodeName::parse("default").map_err(|e| Refusal::BadName {
                    given: "default".into(),
                    why: e.to_string(),
                })?,
            };
            return Err(Refusal::Failed {
                node,
                why: format!("cannot read remembered nodes: {e}; the saved file was not changed"),
            });
        }
        let mut nodes = self.nodes();
        for info in &mut nodes {
            if info.state == NodeState::Detached {
                if self.no_passphrase(&info.name)? {
                    *info = self
                        .want(
                            &info.name,
                            Want::Explicit(None),
                            None,
                            Vec::new(),
                            Vec::new(),
                        )
                        .await?
                        .info;
                } else {
                    info.status = Some(NodeStatus::Locked);
                }
            }
        }
        Ok(nodes)
    }

    /// This persisted fact is only a hint to try no credential, never an unlock authority.
    fn no_passphrase(&self, node: &NodeName) -> Result<bool, Refusal> {
        let paths = self.inner.account.node_paths_as_they_are(node);
        if !paths.vault_file().is_file()
            && vox_core::node::headless::identity_file(&paths).is_file()
        {
            return Ok(true);
        }
        paths
            .requires_passphrase()
            .map(|required| !required)
            .map_err(|e| Refusal::Failed {
                node: node.clone(),
                why: e.to_string(),
            })
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

    /// Attach `node` by hand (`vox node unlock`), recording it in the attach file when `keep` is
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
        let mut g = self
            .want(node, Want::Checked, passphrase.clone(), rooms, anchors)
            .await?;
        if keep.is_some() {
            self.verify_kept_passphrase(node, &g, passphrase.as_deref().map_or("", |p| p))
                .await?;
        }
        // Never hold the file lock while waiting for an earlier detach: that detach may need
        // the same lock to forget its entry. Apply the explicit keep only after the read works.
        let _file = self.inner.keep_file.lock().await;
        let was = self.kept_record(node)?;
        {
            let mut slots = lock(&self.inner.slots);
            match slots.get_mut(node) {
                Some(Slot::Attached(a)) if a.generation == g.generation => {
                    g.info = self.grant(node, a, Want::Explicit(keep))?.info;
                }
                _ => {
                    return Err(Refusal::Failed {
                        node: node.clone(),
                        why: "its work ended before the unlock could be remembered; try again"
                            .into(),
                    })
                }
            }
        }
        self.write_attach_file_held(None, was)
            .await
            .map_err(|e| self.remember_failed(node, e))?;
        Ok((g.info, g.notes))
    }

    fn remember_failed(&self, node: &NodeName, why: String) -> Refusal {
        Refusal::Failed {
            node: node.clone(),
            why: format!(
                "node {node} is Ready, but remembering could not be confirmed: {why}; correct the storage problem and run `vox node unlock {node}` again"
            ),
        }
    }

    /// A Ready node still has to prove a replacement restart secret. A new attachment already
    /// checked it while opening the vault. Headless nodes have no vault or passphrase to check.
    async fn verify_kept_passphrase(
        &self,
        node: &NodeName,
        grant: &Granted,
        secret: &str,
    ) -> Result<(), Refusal> {
        if grant.attached_now {
            return Ok(());
        }
        let failed = |why: String| Refusal::Failed {
            node: node.clone(),
            why,
        };
        match grant
            .handle
            .apply(NodeCommand::VerifyPassphrase {
                passphrase: Secret::new(secret.as_bytes().to_vec()),
            })
            .await
        {
            Outcome::Done => Ok(()),
            Outcome::Failed(Fault::NoIdentity)
                if secret.is_empty()
                    && self.inner.account.node_paths(node).is_ok_and(|p| {
                        !p.vault_file().is_file()
                            && vox_core::node::headless::identity_file(&p).is_file()
                    }) =>
            {
                Ok(())
            }
            Outcome::Failed(Fault::WrongPassphrase) => Err(failed(format!(
                "that is not node {node}'s identity passphrase, so nothing was stored"
            ))),
            other => Err(failed(format!(
                "its passphrase could not be checked ({other}), so nothing was stored"
            ))),
        }
    }

    fn kept_record(&self, node: &NodeName) -> Result<BTreeMap<NodeName, KeepSource>, Refusal> {
        let path = self.inner.account.attach_file();
        read_attach_file_checked(&path)
            .map(|entries| entries.into_iter().collect())
            .map_err(|e| Refusal::Failed {
                node: node.clone(),
                why: format!("could not read remembered state at {}: {e}; it was not changed; correct the storage problem and retry", path.display()),
            })
    }

    /// **Kept with its passphrase in the Keychain** (ADR-028 K-10, ADR-014 M-6): stored only once
    /// the passphrase is proved, so a passphrase nothing checked is never stored. Attaching the
    /// node with it proves it; a node attached already, by another client or by hand, has it
    /// checked against its vault first. A failed store or cleanup reports what could not be
    /// confirmed, so the person can repair the storage and retry. The daemon names the item by
    /// the node's own directory.
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
        self.verify_kept_passphrase(node, &g, &secret).await?;
        let account = self.keychain_account(node);
        let _file = self.inner.keep_file.lock().await;
        // The verified grant may have ended while another writer held the file lock. Never
        // let that old Unlock store over credentials belonging to a newer generation.
        if !matches!(lock(&self.inner.slots).get(node),
            Some(Slot::Attached(a)) if a.generation == g.generation)
        {
            return Err(failed(format!(
                "node {node}'s state changed before its passphrase could be remembered; retry Unlock"
            )));
        }
        let was = self.kept_record(node)?;
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
                    } else {
                        // The failed store removes its Keychain item below. Do not retain a
                        // stale restart entry or tell the client this node is still remembered.
                        a.keep = None;
                    }
                    g.info = info_of_attached(node, a);
                    true
                }
                _ => false,
            }
        };
        if !kept {
            let cleanup = self.forget_unrecorded_keychain(&account).await;
            let mut why = format!("node {node}'s state changed while its passphrase was being remembered; retry Unlock");
            if let Err(e) = cleanup {
                why.push_str(&format!(
                    "; its saved passphrase could not be cleaned up: {e}"
                ));
            }
            return Err(failed(why));
        }
        // Persist before forgetting a Keychain item: a failed write may leave its old entry.
        let saved = self.write_attach_file_held(None, was).await;
        if let Err(e) = saved {
            let cleanup = self.forget_unrecorded_keychain(&account).await;
            let mut refusal = self.remember_failed(node, e);
            if let (Err(cleanup), Refusal::Failed { why, .. }) = (cleanup, &mut refusal) {
                why.push_str(&format!(
                    "; its saved passphrase could not be cleaned up: {cleanup}"
                ));
            }
            if let (Err(store), Refusal::Failed { why, .. }) = (&stored, &mut refusal) {
                // A failed Keychain store may itself have lost the secret. Retaining the
                // recorded entry is not a claim that its secret was restored.
                why.push_str(&format!("; the Keychain store also failed: {store}; its saved passphrase could not be confirmed"));
            }
            return Err(refusal);
        }
        if let Err(e) = stored {
            self.forget_unrecorded_keychain(&account).await.map_err(|cleanup| {
                failed(format!("node {node} is Ready, but its passphrase could not be stored ({e}) or cleaned up ({cleanup}); correct the Keychain problem and retry"))
            })?;
            g.notes.push(if e == crate::keychain::NO_KEYCHAIN {
                format!("node {node} is Ready; {e}")
            } else {
                format!(
                    "node {node} is Ready, but not remembered: its passphrase could not be stored \
                     in the Keychain: {e}"
                )
            });
        }
        Ok((g.info, g.notes))
    }

    async fn forget_unrecorded_keychain(&self, account: &str) -> Result<(), String> {
        let path = self.inner.account.attach_file();
        // An unreadable record is not evidence that its secret is unneeded.
        let recorded = read_attach_file_checked(&path).map_err(|e| {
            format!(
                "could not read {} before deleting its saved passphrase: {e}",
                path.display()
            )
        })?;
        if !recorded
            .iter()
            .any(|(_, source)| matches!(source, KeepSource::Keychain(saved) if saved == account))
        {
            forget_in_keychain(account.to_owned()).await?;
        }
        Ok(())
    }

    /// Forget `node`'s restart credentials (ADR-031 CW-4). Its line leaves the attach file and
    /// its saved Keychain item is deleted. This does not stop a held node: Lock and the app's
    /// Forget follow successful credential removal with a requested detach. A passphrase-free
    /// node stays Ready without stored credentials.
    ///
    /// # Errors
    /// [`Refusal::NoSuchNode`] for a node that is not on disk.
    pub async fn unkeep(&self, node: &NodeName) -> Result<(), Refusal> {
        if !self.inner.account.nodes_on_disk().contains(node) {
            return Err(Refusal::NoSuchNode { node: node.clone() });
        }
        let _file = self.inner.keep_file.lock().await;
        let was = self.kept_record(node)?;
        {
            let mut slots = lock(&self.inner.slots);
            if let Some(Slot::Attached(a)) = slots.get_mut(node) {
                if a.keep.take().is_some() && a.holders > 0 && !a.unprotected {
                    a.implicit = true;
                }
            }
        }
        self.write_attach_file_held(Some(node), was)
            .await
            .map_err(|why| Refusal::Failed {
                node: node.clone(),
                why: format!("could not forget node {node}'s remembered state: {why}; this request did not stop the node; correct the storage problem and retry"),
            })?;
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
        // **A node still attaching takes the registration now, and applies it once attached**
        // (#666): the hook, inside a model's turn, is answered at once with the node as attaching,
        // and the Session exists from this first turn.
        if let Some(info) = self.attaching(node) {
            // The reply says attachment is pending, but registration itself must already
            // be saved. A busy registration lock is a refusal, not a queued success.
            let paths = self
                .inner
                .account
                .node_paths(node)
                .map_err(|error| Refusal::Failed {
                    node: node.clone(),
                    why: error.to_string(),
                })?;
            crate::wake::store_checked(&paths, &session).map_err(|why| Refusal::Failed {
                node: node.clone(),
                why: format!("session was not registered: {why}"),
            })?;
            let router = self.clone();
            let queued = node.clone();
            let (id, asked) = (id.clone(), asked.clone());
            self.inner.rt.spawn(async move {
                router.started(&queued).await;
                let session_id = id.clone();
                if let Err(r) = router
                    .registered(&queued, session, id, asked, known, join)
                    .await
                {
                    eprintln!(
                        "vox daemon: session {session_id} of node {queued} was not registered \
                         once the node attached: {r}"
                    );
                }
            });
            return Ok(DaemonFrame::SessionRegistered {
                info,
                room: None,
                new: !known,
                joining: None,
            });
        }
        self.registered(node, session, id, asked, known, join).await
    }

    /// The node's info, as attaching, when the daemon is attaching it (its start's kept nodes, or
    /// an attach under way); `None` otherwise.
    fn attaching(&self, node: &NodeName) -> Option<NodeInfo> {
        self.nodes()
            .into_iter()
            .find(|n| &n.name == node && matches!(n.state, NodeState::Attaching))
    }

    /// Once the daemon's start is done with kept node `node` (attached, or given up), or at
    /// once for any other node; bounded, as nothing a start does takes minutes.
    async fn started(&self, node: &NodeName) {
        let t0 = std::time::Instant::now();
        while lock(&self.inner.starting).contains(node) && t0.elapsed() < Duration::from_secs(300) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The rest of [`Self::session_register`], for a node attached or about to be: the session
    /// holds the node, its room is resolved, its Session opened.
    async fn registered(
        &self,
        node: &NodeName,
        session: crate::wake::Session,
        id: String,
        asked: Option<String>,
        known: bool,
        join: Option<(String, Zeroizing<String>)>,
    ) -> Result<DaemonFrame, Refusal> {
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
            // The saved registration is the durable opening obligation. Projection can be
            // refreshing for tens of seconds after a sparse join; it must not hold the hook's
            // ten-second request open. One idempotent worker continues independently, and is
            // reconstructed from the same registration when the daemon restarts.
            joining = self.open_registered(node, handle, g.detached.clone(), reg);
            if let Some(room_b32) = reg.room.as_deref() {
                if let Ok(room_id) = vox_core::node::link::b32_decode(room_b32, "room") {
                    let member = handle
                        .view()
                        .open_channels
                        .iter()
                        .any(|c| c.channel_id == room_id);
                    let joins =
                        Arc::clone(lock(&self.inner.joins).entry(node.clone()).or_default());
                    if member {
                        joins.set_status(room_b32, None);
                    } else if let Some((link, passphrase)) = join {
                        vox_core::node::room_join::join_in_background(
                            handle, &joins, room_b32, &link, passphrase, None,
                        );
                        joining = joins.status(room_b32).or(joining);
                    }
                }
            }
        }
        if let Some(reg) = stored.as_ref() {
            self.watch_title(node, reg);
        }
        Ok(DaemonFrame::SessionRegistered {
            info: g.info,
            room,
            // This is new to the node's durable registrations. With a room, `new` produces no
            // first-run note; without one there can be no room Session to discover first.
            new: !known,
            joining,
        })
    }

    /// Continue one saved interactive Session opening without holding its hook request. The
    /// registration file is both the cancellation check and the daemon-restart retry source.
    /// Repeated hooks coalesce on `(node, session)` while the idempotent opening is in flight.
    fn open_registered(
        &self,
        node: &NodeName,
        handle: &vox_core::node::actor::NodeHandle,
        mut detached: watch::Receiver<bool>,
        reg: &crate::wake::Session,
    ) -> Option<String> {
        let room_b32 = reg.room.as_ref()?;
        if reg.harness == "unknown" || !reg.interactive {
            return None;
        }
        let room = vox_core::node::link::b32_decode(room_b32, "room").ok()?;
        let key = (node.clone(), reg.session.clone());
        let previous = lock(&self.inner.session_open_failures).remove(&key);
        if !lock(&self.inner.session_openings).insert(key.clone()) {
            return previous;
        }
        let router = self.clone();
        let handle = handle.clone();
        let opening = vox_core::node::sessions::Opening {
            id: reg.session.clone(),
            harness: reg.harness.clone(),
            name: reg.name.clone(),
            cwd: reg.start.clone().filter(|cwd| !cwd.is_empty()),
        };
        let expected_room = room_b32.clone();
        self.inner.rt.spawn(async move {
            let still_registered = || {
                router
                    .inner
                    .account
                    .node_paths(&key.0)
                    .ok()
                    .and_then(|paths| crate::wake::registration(&paths, &key.1))
                    .is_some_and(|current| {
                        current.interactive
                            && current.harness != "unknown"
                            && current.room.as_deref() == Some(expected_room.as_str())
                    })
            };
            while !*detached.borrow()
                && still_registered()
                && !handle
                    .view()
                    .open_channels
                    .iter()
                    .any(|c| c.channel_id == room)
            {
                tokio::select! {
                    _ = detached.changed() => {},
                    () = tokio::time::sleep(Duration::from_millis(200)) => {},
                }
            }
            let result = if *detached.borrow() || !still_registered() {
                Ok(())
            } else {
                loop {
                    // Recheck the durable binding while each bounded core attempt waits on
                    // projection work; an end or room move cancels this owner instead of
                    // reopening stale state. A readiness deadline bounds one attempt, not the
                    // durable obligation: the exact registration remains its retry source.
                    let future =
                        vox_core::node::sessions::open_when_member(&handle, room, &opening);
                    tokio::pin!(future);
                    let attempt = loop {
                        tokio::select! {
                            result = &mut future => break result,
                            _ = detached.changed() => {
                                if *detached.borrow() { break Ok(()); }
                            }
                            () = tokio::time::sleep(Duration::from_millis(200)) => {
                                if !still_registered() { break Ok(()); }
                            }
                        }
                    };
                    match attempt {
                        Err(why)
                            if vox_core::node::sessions::opening_refreshing(&why)
                                && !*detached.borrow()
                                && still_registered() =>
                        {
                            tokio::select! {
                                _ = detached.changed() => {},
                                () = tokio::time::sleep(Duration::from_millis(200)) => {},
                            }
                        }
                        result => break result,
                    }
                }
            };
            lock(&router.inner.session_openings).remove(&key);
            match result {
                Ok(()) => {
                    lock(&router.inner.session_open_failures).remove(&key);
                }
                Err(why) if still_registered() => {
                    let said = format!("could not open this session's Session in its room: {why}");
                    eprintln!("vox daemon: session {} of node {}: {said}", key.1, key.0);
                    lock(&router.inner.session_open_failures).insert(key, said);
                }
                Err(_) => {}
            }
        });
        previous
    }

    /// Open `reg`'s Session in its room (ADR-029 SE-1): at once when the node is a member, or once
    /// a join from the room map (`join`) makes it one. A headless session gets none, but its node
    /// still joins the room the map names (RB-3 has no headless exception: a `claude -p` in a bound
    /// repo works in that room, though no Session shows it). A hook run by hand, with no harness
    /// behind it, does neither. What a join under way says, for the session.
    async fn open_session(
        &self,
        node: &NodeName,
        handle: &vox_core::node::actor::NodeHandle,
        reg: &crate::wake::Session,
        join: Option<(String, Zeroizing<String>)>,
    ) -> Option<String> {
        let room_b32 = reg.room.as_ref()?;
        if reg.harness == "unknown" {
            return None;
        }
        let room = vox_core::node::link::b32_decode(room_b32, "room").ok()?;
        let opening = reg.interactive.then(|| vox_core::node::sessions::Opening {
            id: reg.session.clone(),
            harness: reg.harness.clone(),
            name: reg.name.clone(),
            cwd: reg.start.clone().filter(|cwd| !cwd.is_empty()),
        });
        let member = handle.view().channels.iter().any(|c| c.channel_id == room);
        let joins = Arc::clone(lock(&self.inner.joins).entry(node.clone()).or_default());
        if member {
            joins.set_status(room_b32, None);
            // A headless run joined and is in: it opens no Session.
            let opening = opening?;
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
        let handle = self.handle_of(node).ok_or_else(|| {
            failed("its work is not running; try again when the node is Ready".into())
        })?;
        vox_core::node::link::b32_decode(room, "room").map_err(|e| failed(e.to_string()))?;
        let mut ingress = self.inner.posting.lock().await;
        let before = crate::wake::store_room(&paths, session, room)
            .ok_or_else(|| failed(format!("no session {session} is registered")))?;
        if let Some(old) = before.filter(|old| old != room) {
            if let Ok(old) = vox_core::node::link::b32_decode(&old, "room") {
                enqueue_session_end(&handle, &mut ingress, node, old, session, "moved").await;
            }
        }
        drop(ingress);
        let reg = crate::wake::registration(&paths, session)
            .ok_or_else(|| failed(format!("no session {session} is registered")))?;
        let joining = self.open_session(node, &handle, &reg, None).await;
        Ok(DaemonFrame::SessionRegistered {
            info: self
                .nodes()
                .into_iter()
                .find(|n| n.name == *node)
                .ok_or_else(|| {
                    failed("its record disappeared before the session could be moved".into())
                })?,
            room: Some(room.to_owned()),
            new: false,
            joining,
        })
    }

    /// The asks of this data root (ADR-029 RB-5a), knowing which rooms each attached node is in,
    /// or is joining now for the first time.
    async fn room_asks(&self) -> Vec<vox_core::node::daemonipc::RoomAsk> {
        let mut held: BTreeMap<NodeName, BTreeSet<String>> = BTreeMap::new();
        for node in self.inner.account.nodes_on_disk() {
            if let Some(h) = self.handle_of(&node) {
                let rooms = h
                    .view()
                    .channels
                    .iter()
                    .map(|c| vox_core::node::link::b32_encode(&c.channel_id))
                    .collect();
                held.insert(node, rooms);
            }
        }
        let joins = lock(&self.inner.joins).clone();
        let account = self.inner.account.clone();
        tokio::task::spawn_blocking(move || {
            crate::room_ask::asks(&account, &|node, room| {
                // A join running now is waited for, unless one before it failed: a retry that
                // keeps failing must not hide the ask.
                held.get(node).is_some_and(|r| !r.contains(room))
                    && !joins.get(node).is_some_and(|j| {
                        j.under_way(room)
                            && !j
                                .status(room)
                                .is_some_and(|s| s.starts_with("could not join"))
                    })
            })
        })
        .await
        .unwrap_or_default()
    }

    /// The person's answer to the ask about `dir` (ADR-029 RB-5a, RB-6).
    ///
    /// With a `link`: bind `dir` to the room it names, what `vox room join <link> --node <node>
    /// --bind <dir>` does: each node of a session that asked joins the room, which checks the
    /// passphrase; an already-held room checks it through a separate real join. The map then
    /// binds `dir`, replacing a no or
    /// another room. With `link` empty: the room map binds `dir` already, to a room the sessions'
    /// nodes are not in, and they join it with the map's own link and passphrase. Either way every
    /// session that asked is then put in the room.
    async fn room_bind(&self, dir: &str, link: &str, passphrase: Zeroizing<String>) -> DaemonFrame {
        let no = |why: String| DaemonFrame::RoomAnswer {
            done: false,
            said: vec![why],
        };
        let Some(ask) = self.room_asks().await.into_iter().find(|a| a.dir == dir) else {
            return no(format!(
                "no session started in {dir} is waiting for a room now; nothing was changed"
            ));
        };
        let data_root = self.inner.account.data_root.clone();
        let (link, passphrase, bind) = if link.is_empty() {
            let mapped = crate::room_map::read(&data_root).ok().and_then(|entries| {
                crate::room_map::resolve(&entries, std::path::Path::new(dir))
                    .filter(|e| e.room != crate::room_map::DECLINED)
                    .map(|e| (e.room.clone(), e.passphrase.clone()))
            });
            let Some((link, passphrase)) = mapped else {
                return no(format!(
                    "the room map binds {dir} to no room, so there is no room to join; nothing \
                     was changed"
                ));
            };
            (link, passphrase, false)
        } else {
            (link.to_owned(), passphrase, true)
        };
        let parsed = match vox_core::node::link::InviteLink::parse(&link) {
            Ok(p) => p,
            Err(why) => return no(format!("that is not a room link (vox://…): {why}")),
        };
        let room_b32 = vox_core::node::link::b32_encode(&parsed.channel_id);
        let short: String = room_b32.chars().take(12).collect();
        let mut nodes: Vec<NodeName> = Vec::new();
        for s in &ask.sessions {
            if !nodes.contains(&s.node) {
                nodes.push(s.node.clone());
            }
        }
        let mut said = Vec::new();
        for node in &nodes {
            let Some(handle) = self.handle_of(node) else {
                return no(format!(
                    "node {node} is Locked, so it cannot join room {short}; nothing more \
                     was changed"
                ));
            };
            let member = handle
                .view()
                .channels
                .iter()
                .any(|c| c.channel_id == parsed.channel_id);
            if member {
                // Holding a room is not proof of the passphrase just typed (ADR-031 RM-3).
                // This validates through a real Join stream without admitting another member.
                let checked = handle
                    .apply(vox_core::node::api::NodeCommand::CheckRoomPassphrase {
                        channel_id: parsed.channel_id,
                        passphrase: vox_core::node::api::Secret::new(
                            passphrase.as_bytes().to_vec(),
                        ),
                    })
                    .await;
                if checked != vox_core::node::api::Outcome::Done {
                    return no(format!(
                        "the room passphrase was not authenticated by node {node}, so {dir} was \
                         not bound: {checked}"
                    ));
                }
                continue;
            }
            match handle
                .apply(vox_core::node::api::NodeCommand::JoinChannel {
                    link: link.clone(),
                    passphrase: vox_core::node::api::Secret::new(passphrase.as_bytes().to_vec()),
                })
                .await
            {
                vox_core::node::api::Outcome::Done => {
                    said.push(format!("node {node} joined room {short}"));
                }
                other => {
                    said.push(format!(
                        "node {node} could not join room {short}, so {dir} was not bound: {other}"
                    ));
                    return DaemonFrame::RoomAnswer { done: false, said };
                }
            }
        }
        if bind {
            // Said before it is written (ADR-028 E-5): who can read what is saved.
            let map = crate::room_map::path(&data_root);
            said.push(format!(
                "every agent session started in {dir}, from any harness, is to work in room \
                 {short}; every node of this data root can read the room map {}, the passphrase \
                 included",
                map.display()
            ));
            match crate::room_map::bind(&data_root, std::path::Path::new(dir), &link, &passphrase) {
                Ok(Some(was)) => said.push(format!(
                    "bound {dir}, replacing what the room map held for it: {was}"
                )),
                Ok(None) => said.push(format!("bound {dir}")),
                Err(e) => {
                    said.push(format!("{dir} was not bound: {e}"));
                    return DaemonFrame::RoomAnswer { done: false, said };
                }
            }
        }
        for s in &ask.sessions {
            let label: String = s.session.chars().take(8).collect();
            let who = crate::room_ask::harness_words(&s.harness);
            let Ok(paths) = self.inner.account.node_paths(&s.node) else {
                continue;
            };
            if crate::wake::store_room(&paths, &s.session, &room_b32).is_none() {
                continue;
            }
            let joining = match (
                self.handle_of(&s.node),
                crate::wake::registration(&paths, &s.session),
            ) {
                (Some(h), Some(reg)) => self.open_session(&s.node, &h, &reg, None).await,
                _ => None,
            };
            said.push(match joining {
                Some(j) => format!("{who} session {label} now works in room {short}: {j}"),
                None => format!("{who} session {label} now works in room {short}"),
            });
        }
        DaemonFrame::RoomAnswer { done: true, said }
    }

    /// Record the person's no for `dir` (ADR-029 RB-7): a block whose room is `none`, so no
    /// session started there is asked again, by the app or by its hook.
    fn room_decline(&self, dir: &str) -> DaemonFrame {
        let data_root = &self.inner.account.data_root;
        match crate::room_map::decline(data_root, std::path::Path::new(dir)) {
            Ok(true) => DaemonFrame::RoomAnswer {
                done: true,
                said: vec![format!(
                    "{dir} is to stay tied to no room: no session started there is asked again; \
                     remove its block from {} to be asked",
                    crate::room_map::path(data_root).display()
                )],
            },
            Ok(false) => DaemonFrame::RoomAnswer {
                done: false,
                said: vec![format!(
                    "the room map names {dir} already; nothing was changed"
                )],
            },
            Err(e) => DaemonFrame::RoomAnswer {
                done: false,
                said: vec![e.to_string()],
            },
        }
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
                pause: None,
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
                pause: None,
            },
            (_, _) if buf.len() > MAX_REQUEST => Answer {
                ok: false,
                said: "the drive request is too long".into(),
                code: None,
                pause: None,
            },
            (_, Err(_)) => Answer {
                ok: false,
                said: "not a drive request this vox reads".into(),
                code: None,
                pause: None,
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
            pause: None,
        };
        if req.v != 1 {
            return refuse(format!(
                "drive protocol {} is not one this vox speaks",
                req.v
            ));
        }
        // A fingerprint outlives locking in the actor's view. Bind this request to the
        // currently attached actor, not merely to the same identity after a replacement.
        let generation = {
            let slots = lock(&self.inner.slots);
            match slots.get(node) {
                Some(Slot::Attached(attached))
                    if Arc::ptr_eq(attached.handle.app(), handle.app())
                        && !*attached.detached.borrow() =>
                {
                    Some(attached.generation)
                }
                _ => None,
            }
        };
        let Some(generation) = generation else {
            return refuse("the Session node is no longer attached; nothing was sent".into());
        };
        let view = handle.view();
        if view.locked || view.locking {
            return refuse("the Session node is locking or Locked; nothing was sent".into());
        }
        let me = view.identity.as_ref().map(|i| i.fingerprint);
        // DR-2: only a member this node trusts with drive, or the node itself, its Sessions'
        // operator (SC-2), which reaches here only from its own socket (`drive_own`).
        // Said without this node's name for itself, which the driver may not know it by: the
        // driver names it (`code`).
        if !matches!(
            &req.action,
            Action::RoomPause {
                paused: None,
                expected_instance: None,
                after: None,
                expected: None
            }
        ) && me != Some(info.peer)
            && !view.drive.contains(&info.peer)
        {
            return Answer {
                ok: false,
                said: vox_agentcomms::drive::no_drive("the session's node"),
                code: Some(vox_agentcomms::drive::NO_DRIVE.to_owned()),
                pause: None,
            };
        }
        let Ok(paths) = self.inner.account.node_paths(node) else {
            return refuse("this node's files cannot be read".into());
        };
        if let Action::RoomPause {
            paused,
            expected_instance,
            after,
            expected,
        } = &req.action
        {
            if !req.session.is_empty() {
                return refuse("a room pause must not select a Session".into());
            }
            return self
                .pause_room(
                    node,
                    handle,
                    info,
                    generation,
                    *paused,
                    *expected_instance,
                    after.as_deref(),
                    *expected,
                )
                .await;
        }
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
            Action::Interrupt | Action::Stop | Action::RoomPause { .. } => {}
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
            vox_agentcomms::activity::split(
                copy,
                "text",
                vox_core::node::content::MAX_TEXT_LEN - 512,
            ),
            None,
        )
        .await;
        let same_attachment = {
            let slots = lock(&self.inner.slots);
            matches!(slots.get(node), Some(Slot::Attached(attached))
                if attached.generation == generation && !*attached.detached.borrow())
        };
        let current = handle.view();
        if !same_attachment
            || current.locked
            || current.locking
            || current
                .identity
                .as_ref()
                .map(|identity| identity.fingerprint)
                != me
        {
            return refuse(
                "the Session node stopped or changed while saving; nothing was sent".into(),
            );
        }
        if me != Some(info.peer) && !current.drive.contains(&info.peer) {
            return Answer {
                ok: false,
                said: vox_agentcomms::drive::no_drive("the session's node"),
                code: Some(vox_agentcomms::drive::NO_DRIVE.to_owned()),
                pause: None,
            };
        }
        let Some(current_reg) = crate::wake::registration(&paths, &req.session) else {
            return refuse("that Session ended while saving; nothing was sent".into());
        };
        if current_reg.room.as_deref() != Some(room.as_str())
            || current_reg.first_seen_ms != reg.first_seen_ms
        {
            return refuse(
                "that Session changed rooms or ended while saving; nothing was sent".into(),
            );
        }
        let reg = current_reg;
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
        sink.activity(node, &req.session, vec![result.to_string()], None)
            .await;
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
                pause: None,
            },
            Err(said) => Answer {
                ok: false,
                said,
                code: None,
                pause: None,
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
                .activity(node, session, vec![entry.to_string()], None)
                .await;
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
            .activity(node, session, vec![result.to_string()], None)
            .await;
    }

    /// Typed text, an interrupt, a stop or a slash command, to `reg`'s harness alone.
    async fn steer(
        &self,
        node: &NodeName,
        reg: &crate::wake::Session,
        action: &crate::drive::Action,
    ) -> Result<String, String> {
        self.steer_guarded(node, reg, action, None).await
    }

    async fn steer_guarded(
        &self,
        node: &NodeName,
        reg: &crate::wake::Session,
        action: &crate::drive::Action,
        guard: Option<room_pause::InterruptGuard>,
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
        // Reserve before the harness can emit its prompt echo. A full echo window refuses the
        // send, and an attempted send's unknown outcome retains the marker even on cancellation.
        let mut delivery = match &steer {
            Steer::Text(t) => Some(self.inner.sink.reserve_delivery(node, &reg.session, t)?),
            _ => None,
        };
        let done = match reg.harness.as_str() {
            "codex" if !reg.codex_home.is_empty() => {
                if let Some(reservation) = &mut delivery {
                    reservation.attempting();
                }
                self.inner
                    .codex
                    .steer_guarded(
                        std::path::Path::new(&reg.codex_home),
                        &reg.session,
                        steer,
                        guard,
                    )
                    .await
            }
            "opencode" => {
                if let Some(reservation) = &mut delivery {
                    reservation.attempting();
                }
                self.inner
                    .opencode
                    .steer_guarded(&reg.session, steer, guard)
                    .await
            }
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
                if let Some(reservation) = &mut delivery {
                    reservation.attempting();
                }
                tokio::task::spawn_blocking(move || {
                    crate::claude_injector::drive_guarded(&reg, &act, guard.as_ref())
                })
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
        // Backend string errors do not establish that no bytes reached the harness. Preserve
        // attempted markers for their full 30 seconds; only a never-attempted route rolls back.
        drop(delivery);
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

    /// A Claude Code session's name read from its transcript while it is registered (ADR-029 MD-1):
    /// its hooks read it each turn, but a `/rename` is a command with no turn, typed in the
    /// terminal or driven from Vox, so no hook runs after it and the Session kept its old name
    /// until the session's next prompt. The transcript's new lines are read every
    /// [`TITLE_EVERY`], from where the last read stopped; a new name renames the Session at once,
    /// as Codex's and OpenCode's do. One reader per session; it stops when the session's
    /// registration goes.
    ///
    /// **Only the title lines** (`custom-title`, `ai-title`) are taken from the transcript's new
    /// bytes: the reader keeps nothing else of it, logs nothing of it, and sends nothing of it
    /// anywhere. The transcript is the session's whole conversation; Vox needs its name alone.
    fn watch_title(&self, node: &NodeName, reg: &crate::wake::Session) {
        if reg.harness != "claude" || reg.transcript.is_empty() {
            return;
        }
        let key = (node.clone(), reg.session.clone());
        if !lock(&self.inner.titles).insert(key.clone()) {
            return;
        }
        let weak = Arc::downgrade(&self.inner);
        let path = std::path::PathBuf::from(&reg.transcript);
        self.inner.rt.spawn(async move {
            let (node, session) = key.clone();
            let mut titles = Titles::default();
            loop {
                tokio::time::sleep(TITLE_EVERY).await;
                let Some(inner) = weak.upgrade() else { return };
                let router = Router { inner };
                let Some(reg) = router
                    .inner
                    .account
                    .node_paths(&node)
                    .ok()
                    .and_then(|p| crate::wake::registration(&p, &session))
                else {
                    break;
                };
                let path = path.clone();
                titles = match tokio::task::spawn_blocking(move || titles.read(&path)).await {
                    Ok(t) => t,
                    Err(_) => break,
                };
                if let Some(name) = titles.name() {
                    if reg.name.as_deref() != Some(name.as_str()) {
                        router.rename_session(&node, &session, &name);
                    }
                }
            }
            if let Some(inner) = weak.upgrade() {
                lock(&inner.titles).remove(&key);
            }
        });
    }

    fn session_destination(&self, node: &NodeName, session: &str) -> Option<Digest32> {
        let paths = self.inner.account.node_paths(node).ok()?;
        let reg = crate::wake::registration(&paths, session)?;
        if !reg.interactive {
            return None;
        }
        vox_core::node::link::b32_decode(reg.room.as_deref()?, "room").ok()
    }

    /// The existing authenticated mirror observed an exact input's running step.
    /// Each bounded mutation retains the actor attachment, origin and room incarnation.
    async fn observe_attention(
        &self,
        node: &NodeName,
        endpoint: &str,
        token: &str,
        observation: vox_core::node::attention::InputObservation,
    ) -> Result<(), String> {
        use vox_core::node::attention::{Operation, Reply};
        observation.validate()?;
        let paths = self
            .inner
            .account
            .node_paths(node)
            .map_err(|e| e.to_string())?;
        let (handle, generation, mut detached) = {
            let slots = lock(&self.inner.slots);
            match slots.get(node) {
                Some(Slot::Attached(a)) if !*a.detached.borrow() => {
                    (a.handle.clone(), a.generation, a.detached.subscribe())
                }
                _ => return Err("attention observation node is no longer attached".into()),
            }
        };
        let owner = handle
            .view()
            .identity
            .map(|id| id.fingerprint)
            .ok_or("attention observation node is locked")?;
        let current = |room, instance| -> Result<(), String> {
            let attached = matches!(lock(&self.inner.slots).get(node),
                Some(Slot::Attached(a)) if a.generation == generation
                    && Arc::ptr_eq(a.handle.app(), handle.app()) && !*a.detached.borrow());
            let view = handle.view();
            let reg = crate::wake::pause_registration(&paths, &observation.session)?;
            let room_text = vox_core::node::link::b32_encode(&room);
            if !attached
                || view.locked
                || view.locking
                || view
                    .identity
                    .as_ref()
                    .is_none_or(|id| id.fingerprint != owner)
                || !view
                    .open_channels
                    .iter()
                    .any(|r| r.channel_id == room && r.history_instance == instance)
                || !reg.is_some_and(|reg| {
                    reg.session == observation.session
                        && reg.interactive
                        && reg.harness == "opencode"
                        && reg.room.as_deref() == Some(room_text.as_str())
                        && reg.mirror == endpoint
                        && reg.token == token
                })
            {
                return Err("attention observation attachment, mirror or room changed".into());
            }
            Ok(())
        };
        // Retain only this already validated native observation. Readiness
        // refusals precede mutation, so the same receipt can be checked again
        // without repeating an input or admitting another notice.
        let observe = async {
            for receipt in &observation.receipts {
                let recipient = &receipt.recipient;
                loop {
                    current(recipient.room, recipient.instance)?;
                    match handle
                        .attention(
                            recipient.room,
                            owner,
                            Some(recipient.instance),
                            Operation::Observed(receipt.clone()),
                        )
                        .await
                    {
                        Ok(Reply::Done) => break,
                        // Every Attention command publishes a view, even on
                        // refusal; that notification cannot prove readiness and
                        // would wake its own retry. Use the attention scanner's
                        // two-second cadence within the original total bound.
                        // Stale authority/openings and malformed observations are
                        // deliberately not retryable.
                        Err(reason)
                            if matches!(
                                reason.as_str(),
                                "the room is refreshing saved Sessions; retry"
                                    | "node: room governance is refreshing; try again when it is ready"
                            ) =>
                        {
                            let retry_at = tokio::time::Instant::now() + Duration::from_secs(2);
                            tokio::time::sleep_until(retry_at).await;
                        }
                        Err(reason) => return Err(reason),
                        _ => return Err("unexpected attention observation answer".into()),
                    }
                }
                current(recipient.room, recipient.instance)?;
            }
            Ok(())
        };
        tokio::select! {
            biased;
            _ = detached.wait_for(|d| *d) => Err("attention observation node detached; receipt outcome is unconfirmed".into()),
            result = tokio::time::timeout(Duration::from_secs(15), observe) =>
                result.map_err(|_| "attention observation did not finish; receipt outcome is unconfirmed".to_owned())?,
        }
    }

    /// Persist one complete batch before reporting committed acceptance. At most 64 bounded
    /// admissions can retain payloads while waiting for this local serialization boundary.
    async fn post_session(
        &self,
        node: &NodeName,
        session: &str,
        room: Digest32,
        bodies: Vec<String>,
        effects: Option<crate::session_sink::SourceEffects>,
        fresh: &mut bool,
    ) -> vox_core::node::daemonipc::SessionAdmission {
        use vox_core::node::{
            daemonipc::SessionAdmission,
            session_ingress::{MAX_BATCH_BYTES, MAX_BATCH_ITEMS},
        };
        if bodies.is_empty() {
            return SessionAdmission::Skipped;
        }
        if session.is_empty() || session.len() > vox_core::node::content::MAX_SESSION_ID_LEN {
            return SessionAdmission::Refused(
                "invalid Session identity; activity was not retained".into(),
            );
        }
        if bodies.len() > MAX_BATCH_ITEMS
            || bodies.iter().map(String::len).sum::<usize>() > MAX_BATCH_BYTES
        {
            return SessionAdmission::Refused("Session activity batch is too large".into());
        }
        let Ok(_permit) = self.inner.session_admissions.clone().try_acquire_owned() else {
            return SessionAdmission::Refused(
                "Session admission is busy; this batch was not retained".into(),
            );
        };
        let mut held = self.inner.posting.lock().await;
        if let Some(why) = held.blocked_nodes.get(node) {
            return SessionAdmission::Refused(why.clone());
        }
        let Some(handle) = self.handle_of(node) else {
            return SessionAdmission::Refused(
                "the node is Locked; activity was not retained".into(),
            );
        };
        // One split activity keeps its captured destination. A move/removal between parts
        // refuses the unsubmitted remainder rather than sending it into a different room.
        if self.session_destination(node, session) != Some(room) {
            return SessionAdmission::Refused(
                "the Session room changed; this batch was not retained".into(),
            );
        }
        let key = (node.clone(), session.to_owned());
        if let Some(session_hold) = held.sessions.get_mut(&key) {
            // Try the retained tail first after recovery. One bounded batch frees enough room
            // for one ordinary admission; if a room boundary needs more work, refuse the new
            // batch truthfully rather than evicting old work while saving is possible.
            let (removed, progressed, committed) =
                flush_session_hold(&handle, &key, session_hold).await;
            let empty = session_hold.items.is_empty();
            held.bytes -= removed;
            if empty {
                held.sessions.remove(&key);
            }
            if let Some((saved_room, effects)) = committed {
                let resolutions = self.inner.sink.committed_source(node, session, effects);
                save_source_resolutions(&handle, &mut held, &key, saved_room, resolutions).await;
            }
            if let Some(session_hold) = held.sessions.get(&key) {
                let would_overflow = session_hold.bytes
                    + bodies.iter().map(held_charge).sum::<usize>()
                    + effects
                        .as_ref()
                        .map_or(0, crate::session_sink::SourceEffects::charge)
                    > HELD_BYTES
                    || session_hold.items.len() + bodies.len() > HELD_ITEMS;
                if progressed && would_overflow {
                    return SessionAdmission::Refused(
                        "earlier Session activity is recovering; this batch was not retained"
                            .into(),
                    );
                }
                return held.hold(
                    key,
                    room,
                    bodies,
                    "earlier activity is held only in memory".into(),
                    effects,
                );
            }
        }
        // Reserve enough volatile capacity for a lost receipt before handing ownership to
        // the actor. An ambiguous copy must stay bounded and must never be retried.
        if !held.can_hold_new(&key, &bodies, effects.as_ref()) {
            return SessionAdmission::Refused(
                "Session admission recovery capacity is full; this batch was not retained".into(),
            );
        }
        match save_session_batch(&handle, room, session, bodies.clone()).await {
            Ok(saved) => {
                *fresh = saved.fresh;
                if saved.fresh {
                    if let Some(effects) = effects {
                        let resolutions = self.inner.sink.committed_source(node, session, effects);
                        save_source_resolutions(&handle, &mut held, &key, room, resolutions).await;
                    }
                }
                if saved.first == 0 && saved.last == 0 {
                    SessionAdmission::Skipped
                } else {
                    SessionAdmission::Committed {
                        first: saved.first,
                        last: saved.last,
                    }
                }
            }
            Err(SessionSaveError::Save(error))
                if matches!(error, vox_core::error::Error::Storage { .. }) =>
            {
                held.hold(key, room, bodies, error.to_string(), effects)
            }
            Err(SessionSaveError::Save(error)) => SessionAdmission::Refused(error.to_string()),
            Err(SessionSaveError::Unconfirmed(why)) => held.freeze(key, room, bodies, why, effects),
        }
    }

    /// One reliable room-retirement consumer per hosted actor. A notification is consumed
    /// before taking admission ordering; the actor never waits on that ordering to send it.
    fn follow_session_room_removals(
        &self,
        node: &NodeName,
        handle: &NodeHandle,
        paths: &Paths,
        mut removals: tokio::sync::mpsc::Receiver<vox_core::node::session_ingress::Retirement>,
        ended: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(&self.inner);
        let (node, handle, paths) = (node.clone(), handle.clone(), paths.clone());
        self.inner.rt.spawn(async move {
            // An ended actor still leaves saved registration bindings to clear. Drain every
            // reserved notification before permitting this node to attach again.
            while let Some(retirement) = removals.recv().await {
                let room = retirement.room;
                let mut bindings_cleared = false;
                loop {
                    let Some(inner) = weak.upgrade() else { return; };
                    let mut ingress = inner.posting.lock().await;
                    ingress.blocked_nodes.entry(node.clone()).or_insert_with(|| "a removed room's Session cleanup is pending".into());
                    let cleared = if bindings_cleared {
                        Ok(())
                    } else {
                        ingress.retire_room(&node, &room);
                        crate::wake::clear_room_bindings(
                            &paths, &vox_core::node::link::b32_encode(&room),
                        ).map(|_| { bindings_cleared = true; })
                    };
                    // Once bindings are cleared, retry only this exact durable completion.
                    // Its receipt may have been lost after a successful commit and rejoin.
                    let result = match cleared {
                        // The actor purged earlier rows before notification and refused later
                        // old-room admissions while retiring. After it ends there is no writer
                        // left to race this cleanup, and its volatile tail was released. Leave
                        // the durable marker for the next Unlock to complete; actor shutdown
                        // is not a durable retirement receipt.
                        Ok(_) if *ended.borrow() => Ok(()),
                        Ok(_) => retire_session_room(&handle, retirement).await,
                        Err(why) => Err(why),
                    };
                    match result {
                        Ok(()) => {
                            ingress.blocked_nodes.remove(&node);
                            break;
                        }
                        Err(why) => {
                            let why = format!("removed room cleanup cannot finish: {why}; activity is refused until cleanup succeeds");
                            if ingress.blocked_nodes.get(&node) != Some(&why) {
                                eprintln!("vox daemon: {node}: {why}");
                            }
                            ingress.blocked_nodes.insert(node.clone(), why);
                        }
                    }
                    drop(ingress);
                    drop(inner);
                    // One exact, idempotent cleanup can wait for storage to recover. It owns
                    // only this room id; it never buffers or replays transcript bodies.
                    tokio::time::sleep(HELD_RETRY).await;
                }
            }
        })
    }

    /// Only one retry loop for the daemon, carrying no queued payload of its own. Durable
    /// activity is drained by the node actor; this loop owns only the explicitly volatile tail.
    fn follow_session_holds(&self) {
        let weak = Arc::downgrade(&self.inner);
        self.inner.rt.spawn(async move {
            let mut cursor = None;
            let mut progressed = false;
            loop {
                if progressed { tokio::task::yield_now().await; }
                else { tokio::time::sleep(HELD_RETRY).await; }
                progressed = false;
                let Some(inner) = weak.upgrade() else { return; };
                let router = Router { inner };
                let mut holds = router.inner.posting.lock().await;
                let selected = holds.sessions.keys().find(|key| cursor.as_ref().is_none_or(|last| *key > last))
                    .or_else(|| holds.sessions.keys().next()).cloned();
                let Some(key) = selected else { cursor = None; continue; };
                cursor = Some(key.clone());
                if holds.blocked_nodes.contains_key(&key.0) { continue; }
                let Some(handle) = router.handle_of(&key.0) else {
                    // Locking releases volatile plaintext. A lost receipt is not evidence
                    // that the actor failed to save its copy.
                    if let Some(held) = holds.sessions.remove(&key) {
                        holds.bytes -= held.bytes;
                        if held.unconfirmed_room.is_some() {
                            eprintln!("vox daemon: {}: session {}: {} volatile bytes released when the node locked; acceptance was unconfirmed, and any committed copies remain saved", key.0, key.1, held.bytes);
                        } else {
                            eprintln!("vox daemon: {}: session {}: {} unsaved volatile bytes lost when the node locked", key.0, key.1, held.bytes);
                        }
                    }
                    continue;
                };
                let Some(held) = holds.sessions.get_mut(&key) else { continue; };
                let (removed, made_progress, committed) = flush_session_hold(&handle, &key, held).await;
                let empty = held.items.is_empty();
                holds.bytes -= removed;
                if empty { holds.sessions.remove(&key); }
                if let Some((room, effects)) = committed {
                    let resolutions = router.inner.sink.committed_source(&key.0, &key.1, effects);
                    save_source_resolutions(&handle, &mut holds, &key, room, resolutions).await;
                }
                progressed = made_progress;
            }
        });
    }

    /// Unregister an agent session of `node`, and detach the node if it was attached implicitly
    /// and that session was its last holder, **in one decision** (L-3): the unregister and the
    /// move to `Detaching` happen in one critical section, so a session registering at the same
    /// moment either comes first (and the node stays) or finds the node detaching and waits.
    ///
    /// Returns whether the session was registered, and whether the node detached.
    ///
    /// # Errors
    /// The saved registration could not be removed; no completed end is acknowledged.
    pub async fn session_end(
        &self,
        node: &NodeName,
        session: &str,
        reason: &str,
    ) -> Result<(bool, bool), Refusal> {
        // **A resume is not an end** (ADR-029 SE-4): the session goes on, registered, its Session
        // open.
        if vox_core::node::sessions::keeps_open(reason) {
            return Ok((true, false));
        }
        // Whatever it was asking, nobody can answer now.
        self.inner.sink.session_end(node, session).await;
        // Serialize against admissions/removal. Capture the room before removing the saved
        // registration, but do not enqueue an end or release its holder on a failed write.
        let mut ingress = self.inner.posting.lock().await;
        let handle = self.handle_of(node);
        let paths = self
            .inner
            .account
            .node_paths(node)
            .map_err(|e| Refusal::Failed {
                node: node.clone(),
                why: e.to_string(),
            })?;
        let room = crate::wake::registration(&paths, session)
            .and_then(|r| r.room)
            .and_then(|r| vox_core::node::link::b32_decode(&r, "room").ok());
        let failed = |why| Refusal::Failed {
            node: node.clone(),
            why: format!("session end was not confirmed: {why}"),
        };
        let going = {
            let mut slots = lock(&self.inner.slots);
            match slots.get_mut(node) {
                Some(Slot::Attached(a)) => {
                    let was =
                        a.sessions.contains(session) || a.paths.session_file(session).is_file();
                    crate::wake::end_checked(&a.paths, session).map_err(failed)?;
                    a.sessions.remove(session);
                    let going = if a.implicit && a.holders == 0 && a.sessions.is_empty() {
                        begin_detach(&mut slots, node, &self.inner.defaults.computer)
                    } else {
                        None
                    };
                    (was, going)
                }
                _ => {
                    // Not attached: the record is still removed, so the session is never woken.
                    let was = paths.session_file(session).is_file();
                    crate::wake::end_checked(&paths, session).map_err(failed)?;
                    (was, None)
                }
            }
        };
        let (was, going) = going;
        self.inner.codex.end(session);
        self.inner.opencode.end(session);
        if let (Some(handle), Some(room)) = (handle, room) {
            enqueue_session_end(&handle, &mut ingress, node, room, session, reason).await;
        }
        drop(ingress);
        match going {
            Some((a, done)) => {
                let _ = self
                    .finish_detach(node.clone(), a, done, DetachCause::LastHolder)
                    .await;
                Ok((was, true))
            }
            None => Ok((was, false)),
        }
    }

    /// Detach `node` (L-3), by hand or because the daemon stops.
    ///
    /// # Errors
    /// [`Refusal::NotAttached`] for a node that is not attached and not detaching.
    pub async fn detach(&self, node: &NodeName, cause: DetachCause) -> Result<(), Refusal> {
        let unprotected = match lock(&self.inner.slots).get(node) {
            Some(Slot::Attached(a)) => Some(a.unprotected),
            _ => None,
        };
        if matches!(cause, DetachCause::Requested)
            && match unprotected {
                Some(yes) => yes,
                None => self.no_passphrase(node)?,
            }
        {
            // Forget removes remembered credentials separately. With no credential to forget,
            // the node remains genuinely Ready; shutdown and rename still stop it normally.
            self.want(node, Want::Explicit(None), None, Vec::new(), Vec::new())
                .await?;
            return Ok(());
        }
        loop {
            let step = {
                let mut slots = lock(&self.inner.slots);
                match slots.get(node) {
                    Some(Slot::Attached(_)) => {
                        match begin_detach(&mut slots, node, &self.inner.defaults.computer) {
                            Some(going) => DStep::Go(going),
                            None => DStep::NotAttached,
                        }
                    }
                    Some(Slot::Attaching(rx)) => DStep::WaitAttach(rx.clone()),
                    Some(Slot::Detaching(rx)) => DStep::WaitDetach(rx.clone()),
                    None if matches!(cause, DetachCause::Requested) => {
                        // A previous cleanup may have failed after the actor stopped. Reserve
                        // its place while retrying, so a new Unlock cannot be erased by it.
                        let (tx, rx) = watch::channel(None);
                        slots.insert(node.clone(), Slot::Detaching(rx));
                        DStep::Forget(tx)
                    }
                    None => DStep::NotAttached,
                }
            };
            match step {
                DStep::Go((a, done)) => {
                    return self.finish_detach(node.clone(), a, done, cause).await;
                }
                DStep::Forget(done) => return self.finish_forgetting(node, done).await,
                DStep::WaitAttach(mut rx) => {
                    let _ = rx.wait_for(Option::is_some).await;
                }
                DStep::WaitDetach(mut rx) => {
                    return match rx.wait_for(Option::is_some).await {
                        Ok(result) => result
                            .clone()
                            .unwrap_or_else(|| Err(detach_interrupted(node))),
                        Err(_) => Err(detach_interrupted(node)),
                    };
                }
                DStep::NotAttached => {
                    return Err(Refusal::Failed {
                        node: node.clone(),
                        why: "its work was already stopped".into(),
                    });
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
        lock(&self.inner.slots).is_empty()
            && self.inner.connections.load(Ordering::SeqCst) == 0
            && !self.inner.defaults.computer.keeps_daemon_alive()
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
        let kept = self.mark_kept_attaching();
        for (node, source) in kept {
            let router = self.clone();
            self.inner.rt.spawn(async move {
                router.attach_one_kept(&node, source).await;
                lock(&router.inner.starting).remove(&node);
            });
        }
    }

    /// List every node the attach file keeps as attaching (#666), and return them with their
    /// keeps. **Called before the control socket serves**, so no client ever sees a kept node as
    /// detached in the moment before [`Self::attach_kept`] starts it; idempotent.
    pub fn mark_kept_attaching(&self) -> Vec<(NodeName, Option<KeepSource>)> {
        let mut kept: BTreeMap<_, _> = read_attach_file(&self.inner.account.attach_file())
            .into_iter()
            .map(|(node, source)| (node, Some(source)))
            .collect();
        for node in self.inner.account.nodes_on_disk() {
            match self.no_passphrase(&node) {
                Ok(true) => {
                    kept.entry(node).or_insert(None);
                }
                Ok(false) => {}
                Err(e) => eprintln!("vox daemon: {e}"),
            }
        }
        lock(&self.inner.starting).extend(kept.keys().cloned());
        kept.into_iter().collect()
    }

    /// Attach kept node `node` from its keep `source`, as [`Self::attach_kept`] does each.
    async fn attach_one_kept(&self, node: &NodeName, source: Option<KeepSource>) {
        let (passphrase, rooms) = match &source {
            None | Some(KeepSource::None) => (None, Vec::new()),
            // Off the runtime's workers: a Keychain that asks (locked, or the item made by
            // another vox) blocks until someone answers, and two of these would otherwise leave
            // the daemon answering no one meanwhile.
            Some(KeepSource::Keychain(account)) => match read_in_keychain(account.clone()).await {
                Ok(p) => (Some(p), Vec::new()),
                Err(e) => {
                    eprintln!(
                        "vox daemon: could not make remembered node {node} Ready: its passphrase in the \
                         Keychain: {e}"
                    );
                    self.needs_passphrase(node).await;
                    return;
                }
            },
            Some(KeepSource::File(path)) => match crate::tunnel_cli::passphrase_file_text(path) {
                Ok(text) => split_passphrases(&text),
                Err(e) => {
                    let command = vox_text::shell::command(&[
                        "vox",
                        "node",
                        "unlock",
                        node.as_str(),
                        "--passphrase-file",
                        &path.to_string_lossy(),
                    ]);
                    eprintln!(
                        "vox daemon: node {node} could not become Ready: its remembered passphrase file {} \
                         is unavailable: {e}; restore the file, then run `{command}`",
                        path.display()
                    );
                    return;
                }
            },
        };
        match self
            .want(node, Want::Explicit(source), passphrase, rooms, Vec::new())
            .await
        {
            Ok(_) => eprintln!("vox daemon: node {node} is Ready"),
            Err(r) => {
                eprintln!("vox daemon: could not make remembered node {node} Ready: {r}");
                self.needs_passphrase(node).await;
            }
        }
    }

    /// Tell the person that kept node `node` did not attach by itself and waits for them (#666):
    /// a notification with the command that attaches it, as the node's notifications are raised.
    async fn needs_passphrase(&self, node: &NodeName) {
        let Ok(paths) = self.inner.account.node_paths(node) else {
            return;
        };
        let node = node.clone();
        let _ = tokio::task::spawn_blocking(move || {
            crate::notify::needs_passphrase(
                &paths,
                node.as_str(),
                &format!("It could not become Ready by itself. Run in a terminal: vox node unlock {node}"),
            );
        })
        .await;
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
        if matches!(want, Want::IfAttached | Want::Session(_)) {
            self.started(node).await;
        }
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
                        Step::Have(Box::new(self.grant(node, a, w)?))
                    }
                    Some(Slot::Attaching(rx)) => Step::WaitAttach(rx.clone()),
                    Some(Slot::Detaching(rx)) => Step::WaitDetach(rx.clone()),
                    None => {
                        // A protected node needs the person's Unlock. A passphrase-free
                        // node can start only through the same real credential check below.
                        if matches!(want, Some(Want::IfAttached | Want::Session(_)))
                            && !self.no_passphrase(node)?
                        {
                            Step::NotAttached
                        } else {
                            let (tx, rx) = watch::channel(None);
                            slots.insert(node.clone(), Slot::Attaching(rx));
                            Step::Mine(tx)
                        }
                    }
                }
            };
            match step {
                Step::Have(mut granted) => {
                    if !anchors.is_empty() {
                        let (_, notes) = self.refresh_manual_anchors(&anchors).await;
                        granted.notes.extend(notes);
                    }
                    return Ok(*granted);
                }
                Step::WaitAttach(mut rx) => {
                    let _ = rx.wait_for(Option::is_some).await;
                }
                // **Bounded** (#408): a detach waits for the node's secret work however long it
                // takes (L-3), and a hook asking for its node sits inside a model's turn. Past
                // the bound the request is refused, saying the node is still detaching.
                Step::WaitDetach(mut rx) => {
                    let waited = tokio::time::timeout(
                        vox_core::node::daemonipc::DETACHING_PATIENCE,
                        rx.wait_for(Option::is_some),
                    )
                    .await;
                    match waited {
                        Err(_) => return Err(Refusal::StillDetaching { node: node.clone() }),
                        Ok(Err(_)) => return Err(detach_interrupted(node)),
                        Ok(Ok(result)) => result
                            .clone()
                            .unwrap_or_else(|| Err(detach_interrupted(node)))?,
                    }
                }
                Step::NotAttached => return Err(Refusal::NotAttached { node: node.clone() }),
                Step::Mine(tx) => {
                    let failed = |why: String| Refusal::Failed {
                        node: node.clone(),
                        why,
                    };
                    let w = match want.take() {
                        Some(Want::Checked) => Want::Explicit(None),
                        w => w.unwrap_or(Want::IfAttached),
                    };
                    let started = self
                        .start(node, passphrase.as_ref(), &rooms, &anchors)
                        .await;
                    // A failed attach must not change the machine inputs of running nodes.
                    if started.is_ok() && !anchors.is_empty() {
                        self.refresh_manual_anchors(&anchors).await;
                    }
                    let manual = self.inner.manual_anchors.lock().await;
                    if let Ok((a, _, _)) = &started {
                        let _ = a
                            .handle
                            .apply(NodeCommand::SetAnchors {
                                anchors: manual.set.clone(),
                            })
                            .await;
                    }
                    drop(manual);
                    return match started {
                        Ok((a, computer_deadline, startup_identity)) => {
                            let mut pending = Some((a, w));
                            loop {
                                let Some(handle) = pending
                                    .as_ref()
                                    .map(|(attached, _)| attached.handle.clone())
                                else {
                                    break Err(failed(
                                        "its Ready publication lost the attaching node".into(),
                                    ));
                                };
                                let published = {
                                    let mut slots = lock(&self.inner.slots);
                                    handle.with_computer_application_settled(
                                        startup_identity,
                                        || {
                                            let Some((mut a, w)) = pending.take() else {
                                                return Err(failed(
                                                    "its Ready publication lost the attaching node"
                                                        .into(),
                                                ));
                                            };
                                            a.implicit =
                                                !a.unprotected && !matches!(w, Want::Explicit(_));
                                            let mut granted = self.grant(node, &mut a, w);
                                            // Attaching succeeded even if session registration was
                                            // refused. Publish ownership before returning that refusal.
                                            if let Ok(granted) = &mut granted {
                                                granted.notes = a.notes.clone();
                                                granted.attached_now = true;
                                            }
                                            let implicit = a.implicit;
                                            let fingerprint = a.fingerprint;
                                            let registered = crate::wake::registered(&a.paths);
                                            let opening_handle = a.handle.clone();
                                            let opening_detached = a.detached.subscribe();
                                            // Drive input from members with drive (ADR-029 §3), while
                                            // attached.
                                            self.serve_drive(
                                                node,
                                                &a.handle,
                                                a.detached.subscribe(),
                                            );
                                            self.serve_attention(&a.handle, a.detached.subscribe());
                                            slots.insert(node.clone(), Slot::Attached(a));
                                            self.inner
                                                .metrics
                                                .nodes_attached
                                                .fetch_add(1, Ordering::Relaxed);
                                            let _ = tx.send(Some(Ok(())));
                                            eprintln!(
                                                "vox daemon: node {node} is Ready{}",
                                                if implicit { " (implicitly)" } else { "" }
                                            );
                                            Ok((
                                                granted,
                                                fingerprint,
                                                registered,
                                                opening_handle,
                                                opening_detached,
                                            ))
                                        },
                                    )
                                };
                                match published {
                                    Some(Ok((
                                        granted,
                                        fingerprint,
                                        registered,
                                        opening_handle,
                                        opening_detached,
                                    ))) => {
                                        let _ = self.inner.events.send(DaemonEvent::Attached {
                                            node: node.clone(),
                                            fingerprint,
                                        });
                                        // A saved registration is a durable opening obligation.
                                        for session in registered {
                                            self.watch_harness(node, &session);
                                            self.watch_title(node, &session);
                                            self.open_registered(
                                                node,
                                                &opening_handle,
                                                opening_detached.clone(),
                                                &session,
                                            );
                                        }
                                        break granted;
                                    }
                                    Some(Err(refusal)) => break Err(refusal),
                                    None => {}
                                }
                                if let Err(error) =
                                    handle.reconcile_computer_startup(computer_deadline).await
                                {
                                    let refusal = failed(format!(
                                        "its startup computer trust did not settle: {error}"
                                    ));
                                    let Some((mut a, _)) = pending.take() else {
                                        break Err(refusal);
                                    };
                                    if let Some(tasks) = a.tasks.take() {
                                        tasks.stop().await;
                                    }
                                    stop_actor_fully(&a.handle, a.ended.clone()).await;
                                    lock(&self.inner.slots).remove(node);
                                    let _ = tx.send(Some(Err(refusal.clone())));
                                    break Err(refusal);
                                }
                            }
                        }
                        Err(r) => {
                            let mut slots = lock(&self.inner.slots);
                            slots.remove(node);
                            let _ = tx.send(Some(Err(r.clone())));
                            Err(r)
                        }
                    };
                }
            }
        }
    }

    /// Count `want` against the attached node `a`: a hold, a session, or attached by hand.
    fn grant(&self, node: &NodeName, a: &mut Attached, want: Want) -> Result<Granted, Refusal> {
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
                crate::wake::store_checked(&a.paths, &s).map_err(|why| Refusal::Failed {
                    node: node.clone(),
                    why: format!("session was not registered: {why}"),
                })?;
                self.watch_harness(node, &s);
                a.sessions.insert(s.session.clone());
                None
            }
            Want::IfAttached | Want::Checked => None,
        };
        Ok(Granted {
            info: info_of_attached(node, a),
            handle: a.handle.clone(),
            detached: a.detached.subscribe(),
            hold,
            notes: Vec::new(),
            attached_now: false,
            generation: a.generation,
        })
    }

    /// Bring `node` up: open it, start its actor, unlock it, reopen its rooms, start its tasks and
    /// watch its actor. The table is not locked meanwhile; the slot says `Attaching`.
    async fn start(
        &self,
        node: &NodeName,
        passphrase: Option<&Zeroizing<String>>,
        rooms: &[Zeroizing<String>],
        anchors: &[String],
    ) -> Result<(Box<Attached>, std::time::Instant, Digest32), Refusal> {
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
        // The daemon's one manual machine set, freshly read for this attach.
        //
        // **What the file could not give is said, here** (V210-107, under ADR-026): each skipped
        // line, and that a file naming no usable anchor leaves the node with none, which it
        // carries on without — or, for an anchor node (`vox node`), runs with none of its own. The
        // daemon is the one vox that reads the file now; dropping what it skipped left a person
        // whose file named a host that no longer resolves with nothing said anywhere (#410: the
        // wholly-bad anchors file proof). It is logged, and kept as the attach's notes, which go
        // back to the verb that attached the node, to print in its person's own terminal (R23).
        let (set, notes) = self.refresh_manual_anchors(&[]).await;
        let specs = anchors.to_vec();
        let (set, mut notes) = tokio::task::spawn_blocking(move || {
            let (mut set, mut notes) = (set, notes);
            for spec in specs.iter().filter(|spec| !spec.trim().is_empty()) {
                if let Err(error) = vox_core::node::link::merge_anchor_spec(&mut set, spec) {
                    notes.push(format!("anchor {spec} is skipped: {error}"));
                }
            }
            (set, notes)
        })
        .await
        .map_err(|error| failed(format!("its anchor resolution did not finish: {error}")))?;
        let files = paths
            .account()
            .anchor_input_files()
            .iter()
            .map(|file| file.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let skipped = notes.len();
        if set.is_empty() && skipped > 0 {
            let is_anchor = !paths.vault_file().is_file()
                && vox_core::node::headless::identity_file(&paths).is_file();
            notes.push(format!(
                "node {node}: {}; {}",
                vox_core::error::Error::AnchorsFileUnusable {
                    path: files,
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
        let (room_removed, removals) = tokio::sync::mpsc::channel(1);
        let (handle, actor) = loop {
            let mut cfg = NodeConfig::new()
                .anchors(set.clone())
                .on_profile_wait(crate::tunnel_cli::say_waiting);
            cfg.history_budget = Arc::clone(&self.inner.history_budget);
            cfg.computer = Some(Arc::clone(&self.inner.defaults.computer.computer));
            cfg.session_room_removed = Some(room_removed.clone());
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
        let session_retirements =
            self.follow_session_room_removals(node, &handle, &paths, removals, ended.clone());
        drop(room_removed);
        // Logical retirement is visible before actual cleanup finishes. Keep the task-join
        // watcher independent: detach must never await a signal driven by its own waiter.
        let panic_reported = Arc::new(AtomicBool::new(false));
        {
            let router = Arc::downgrade(&self.inner);
            let node = node.clone();
            let mut termination = handle.termination();
            let panic_reported = Arc::clone(&panic_reported);
            self.inner.rt.spawn(async move {
                if let Some(ActorEnd::Panicked(message)) = termination.retiring().await {
                    if let Some(inner) = router.upgrade() {
                        if !panic_reported.swap(true, Ordering::AcqRel) {
                            eprintln!(
                                "vox daemon: node {node} stopped: its actor panicked: {message}"
                            );
                            inner.metrics.node_panics.fetch_add(1, Ordering::Relaxed);
                        }
                        Router { inner }
                            .detach_generation(&node, generation, DetachCause::Panicked(message))
                            .await;
                    }
                }
            });
        }
        // Also covers a panic outside the borrowed command loop, including failed cleanup.
        {
            let router = Arc::downgrade(&self.inner);
            let node = node.clone();
            self.inner.rt.spawn(async move {
                let end = ActorEnd::of(actor).await;
                let _ = ended_tx.send(true);
                if let ActorEnd::Panicked(message) = end {
                    if let Some(inner) = router.upgrade() {
                        if !panic_reported.swap(true, Ordering::AcqRel) {
                            eprintln!(
                                "vox daemon: node {node} stopped: its actor panicked: {message}"
                            );
                            inner.metrics.node_panics.fetch_add(1, Ordering::Relaxed);
                        }
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
        let Some((computer_deadline, startup_identity)) = handle.startup_computer_boundary() else {
            stop_actor_fully(&handle, ended.clone()).await;
            return Err(failed(
                "its successful startup exposed no computer-trust boundary".into(),
            ));
        };
        for line in rooms {
            crate::app::open_rooms_by_line(&handle, line).await;
        }
        if *ended.borrow() {
            return Err(failed("its work ended before it became Ready".into()));
        }
        // An anchor wakes no agent and notifies nobody. Manual machine anchors are followed by
        // the shared registry for every node; a node never dials its own identity.
        let tasks = anchor
            .is_none()
            .then(|| NodeTasks::start(&self.inner.rt, &handle, &paths));
        let fingerprint = Some(startup_identity);
        Ok((
            Box::new(Attached {
                handle,
                paths,
                generation,
                computer_reconciliation: None,
                implicit: true,
                unprotected: anchor.is_some() || pass.is_empty(),
                keep: None,
                holders: 0,
                sessions: BTreeSet::new(),
                tasks,
                detached: watch::channel(false).0,
                notes,
                ended,
                session_retirements: Some(session_retirements),
                fingerprint,
                anchor: anchor.is_some(),
            }),
            computer_deadline,
            startup_identity,
        ))
    }

    /// Detach `node` only if it is still the attach `generation` (a panic's detach, which must
    /// never take down a later attach of the same node).
    async fn detach_generation(&self, node: &NodeName, generation: u64, cause: DetachCause) {
        let going = {
            let mut slots = lock(&self.inner.slots);
            match slots.get(node) {
                Some(Slot::Attached(a)) if a.generation == generation => {
                    begin_detach(&mut slots, node, &self.inner.defaults.computer)
                }
                _ => None,
            }
        };
        if let Some((a, done)) = going {
            let _ = self.finish_detach(node.clone(), a, done, cause).await;
        }
    }

    /// The rest of a detach, after the slot says `Detaching` (L-3): answer every connection acting
    /// as the node, stop its tasks and its actor, and free the slot.
    async fn finish_detach(
        &self,
        node: NodeName,
        mut a: Box<Attached>,
        done: watch::Sender<DetachOutcome>,
        cause: DetachCause,
    ) -> Result<(), Refusal> {
        let mut physical_end = a.handle.termination();
        let _ = a.detached.send(true);
        {
            let mut ingress = self.inner.posting.lock().await;
            ingress.release_node(&node);
        }
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
        } else if matches!(cause, DetachCause::Panicked(_)) {
            // The borrowed command loop has stopped. Enqueuing Shutdown here would wait for a
            // command it can no longer service; its existing cleanup owner is already running.
            let mut ended = a.ended.clone();
            let _ = ended.wait_for(|ended| *ended).await;
            true
        } else {
            stop_actor_fully(&a.handle, a.ended.clone()).await;
            true
        };
        if !stopped {
            self.inner.unfinished_stop.store(true, Ordering::SeqCst);
        }
        if let Some(mut retirement) = a.session_retirements.take() {
            let finished = if matches!(cause, DetachCause::DaemonStopping) {
                match tokio::time::timeout(self.inner.defaults.patience, &mut retirement).await {
                    Ok(result) => Some(result),
                    Err(_) => {
                        retirement.abort();
                        self.inner.unfinished_stop.store(true, Ordering::SeqCst);
                        eprintln!("vox daemon: {node}: room registration cleanup did not finish before shutdown");
                        None
                    }
                }
            } else {
                Some(retirement.await)
            };
            if let Some(Err(error)) = finished {
                // A failed owner is not evidence that its saved bindings were cleared. Keep
                // this detach reservation; a new actor must not race incomplete cleanup.
                let refusal = Refusal::Failed {
                    node: node.clone(),
                    why: format!("Session room cleanup stopped unexpectedly: {error}; restart the daemon before attaching this node"),
                };
                let _ = done.send(Some(Err(refusal.clone())));
                return Err(refusal);
            }
        }
        drop(a);
        // This observer owns no profile resources. Releasing host handles first cannot make a
        // still-live Store/Snapshot/secret worker look physically closed.
        let physical = if stopped {
            physical_end.closed().await
        } else {
            Err("actual node work did not finish before daemon shutdown".to_owned())
        };
        if let Err(why) = physical {
            let refusal = Refusal::Failed {
                node: node.clone(),
                why: format!("node teardown is incomplete: {why}"),
            };
            let _ = done.send(Some(Err(refusal.clone())));
            return Err(refusal);
        }
        self.inner
            .metrics
            .nodes_attached
            .fetch_sub(1, Ordering::Relaxed);
        // Detached by hand: its line goes, and with it a passphrase kept for it in the Keychain,
        // before an attach waiting for this detach can keep it again.
        let result = if matches!(cause, DetachCause::Requested) {
            self.finish_forgetting(&node, done).await
        } else {
            lock(&self.inner.slots).remove(&node);
            let _ = done.send(Some(Ok(())));
            Ok(())
        };
        if !matches!(cause, DetachCause::DaemonStopping) {
            eprintln!(
                "vox daemon: node {node} finished its work ({})",
                cause_words(&cause)
            );
        }
        let _ = self
            .inner
            .events
            .send(DaemonEvent::Detached { node, cause });
        result
    }

    /// Finish a requested stop (or retry one), retaining its Detaching reservation until the
    /// registry and Keychain cleanup is over. A later Unlock may then keep its own generation.
    async fn finish_forgetting(
        &self,
        node: &NodeName,
        done: watch::Sender<DetachOutcome>,
    ) -> Result<(), Refusal> {
        let result = self.write_attach_file(Some(node)).await.map_err(|why| Refusal::Failed {
            node: node.clone(),
            why: format!("node {node} is Locked, but its remembered credentials could not be forgotten: {why}; correct the storage problem and retry"),
        });
        if let Err(e) = &result {
            eprintln!("vox daemon: {e}");
        }
        lock(&self.inner.slots).remove(node);
        let _ = done.send(Some(result.clone()));
        result
    }

    /// Rewrite `.daemon/attach` from the kept nodes attached now and the lines already there for
    /// nodes not attached (a kept node that failed to attach stays kept), less `forget`: a node
    /// detached by hand.
    async fn write_attach_file(&self, forget: Option<&NodeName>) -> Result<(), String> {
        let _file = self.inner.keep_file.lock().await;
        let path = self.inner.account.attach_file();
        let was = read_attach_file_checked(&path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?
            .into_iter()
            .collect();
        self.write_attach_file_held(forget, was).await
    }

    /// [`Self::write_attach_file`], with `keep_file` held by the caller.
    ///
    /// **A Keychain item lives only while the attach file names it** (ADR-014 M-6): a line that
    /// goes, or now names another source, takes its item with it, whatever made it go (a detach
    /// by hand, a keep with a passphrase file, an attach that is not kept).
    async fn write_attach_file_held(
        &self,
        forget: Option<&NodeName>,
        was: BTreeMap<NodeName, KeepSource>,
    ) -> Result<(), String> {
        if self.inner.stopping.load(Ordering::SeqCst) {
            return Err("the daemon is stopping".into());
        }
        let path = self.inner.account.attach_file();
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
            // Report what is actually persisted, not the requested keep/unkeep. Read again:
            // a failure flushing the directory can follow a successful atomic rename.
            let (recorded, uncertainty) = match read_attach_file_checked(&path) {
                Ok(entries) => (entries.into_iter().collect(), String::new()),
                Err(read) => (was, format!("; current remembered state could not be read ({read}); the previous entry is retained in memory")),
            };
            for (name, slot) in lock(&self.inner.slots).iter_mut() {
                if let Slot::Attached(a) = slot {
                    a.keep = recorded.get(name).cloned();
                    if a.keep.is_some() {
                        a.implicit = false;
                    }
                }
            }
            return Err(format!(
                "could not write {}: {e}{uncertainty}",
                path.display()
            ));
        }
        let named: BTreeSet<&str> = kept
            .values()
            .filter_map(|k| match k {
                KeepSource::Keychain(account) => Some(account.as_str()),
                _ => None,
            })
            .collect();
        let mut removed: BTreeSet<String> = was
            .values()
            .filter_map(|k| match k {
                KeepSource::Keychain(account) => Some(account.clone()),
                _ => None,
            })
            .collect();
        // The registry removal can succeed before Keychain deletion fails. Always retry the
        // node's canonical account, even when there is no longer a line naming its secret.
        if let Some(node) = forget {
            removed.insert(self.keychain_account(node));
        }
        let mut errors = Vec::new();
        for account in removed {
            if !named.contains(account.as_str()) {
                if let Err(e) = forget_in_keychain(account).await {
                    errors.push(e);
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok(())
    }
}

/// What the Keychain holds for `account`, read off the runtime's workers.
async fn read_in_keychain(account: String) -> Result<Zeroizing<String>, String> {
    tokio::task::spawn_blocking(move || crate::keychain::read(&account))
        .await
        .unwrap_or_else(|e| Err(format!("the read was cut short: {e}")))
}

/// Remove what the Keychain holds for `account`, off the runtime's workers.
async fn forget_in_keychain(account: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || crate::keychain::forget(&account))
        .await
        .unwrap_or_else(|e| Err(format!("the Keychain deletion was cut short: {e}")))
}

enum DStep {
    Go((Box<Attached>, watch::Sender<DetachOutcome>)),
    Forget(watch::Sender<DetachOutcome>),
    WaitAttach(watch::Receiver<Option<Result<(), Refusal>>>),
    WaitDetach(watch::Receiver<DetachOutcome>),
    NotAttached,
}

enum Step {
    Have(Box<Granted>),
    WaitAttach(watch::Receiver<Option<Result<(), Refusal>>>),
    WaitDetach(watch::Receiver<DetachOutcome>),
    NotAttached,
    Mine(watch::Sender<Option<Result<(), Refusal>>>),
}

fn detach_interrupted(node: &NodeName) -> Refusal {
    Refusal::Failed {
        node: node.clone(),
        why: "the stop was interrupted before its cleanup result was known; retry the request"
            .into(),
    }
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
        DetachCause::Rename => "its node is being renamed".into(),
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
        status: Some(NodeStatus::Ready),
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
            status: None,
            implicit: false,
            keep: false,
        },
    }
}

/// The identity passphrase (the first line) and the room passphrases (the rest) of a passphrase
/// file's text, as a piped `vox daemon` reads them. Only line endings are stripped.
pub(crate) fn split_passphrases(text: &str) -> (Option<Zeroizing<String>>, Vec<Zeroizing<String>>) {
    let mut lines = text
        .lines()
        .map(|l| Zeroizing::new(l.trim_end_matches('\r').to_owned()));
    let identity = lines.next();
    (identity, lines.filter(|l| !l.is_empty()).collect())
}

/// `.daemon/attach`: one line per kept node, `<name>\t(none|file:<path>|keychain:<account>)`. A
/// line that does not parse is skipped.
pub(crate) fn read_attach_file(path: &std::path::Path) -> Vec<(NodeName, KeepSource)> {
    read_attach_file_checked(path).unwrap_or_default()
}

fn read_attach_file_checked(
    path: &std::path::Path,
) -> std::io::Result<Vec<(NodeName, KeepSource)>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(i, line)| {
            let malformed = || {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{}: malformed remembered-node entry on line {}",
                        path.display(),
                        i + 1
                    ),
                )
            };
            let (name, source) = line.split_once('\t').ok_or_else(malformed)?;
            let name = NodeName::parse(name).map_err(|_| malformed())?;
            let source = if source == "none" {
                KeepSource::None
            } else if let Some(account) = source.strip_prefix("keychain:").filter(|s| !s.is_empty())
            {
                KeepSource::Keychain(account.to_owned())
            } else if let Some(file) = source.strip_prefix("file:").filter(|s| !s.is_empty()) {
                KeepSource::File(file.into())
            } else {
                return Err(malformed());
            };
            Ok((name, source))
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
            DaemonRequest::Anchors => match self.anchor_list().await {
                Ok(anchors) => DaemonFrame::Anchors(anchors),
                Err(why) => refused(why),
            },
            DaemonRequest::AnchorSearch => {
                let Ok(_search) = self.inner.anchor_search.try_lock() else {
                    return DaemonFrame::AnchorFailed(
                        "an anchor search is already running; try again when it finishes".into(),
                    );
                };
                match vox_core::node::nearby::anchors::search().await {
                    Ok(anchors) => DaemonFrame::AnchorsFound(anchors),
                    Err(e) => DaemonFrame::AnchorFailed(format!(
                        "the local anchor search could not finish: {e}"
                    )),
                }
            }
            DaemonRequest::AnchorResolve { input } => {
                match self.resolve_anchor_input(&input).await {
                    Ok((spec, _)) => DaemonFrame::AnchorResolved(spec),
                    Err(why) => DaemonFrame::AnchorFailed(why),
                }
            }
            DaemonRequest::AnchorAdd { input } => {
                match self.change_manual_anchor(Some(input), None).await {
                    Ok(anchors) => DaemonFrame::Anchors(anchors),
                    Err(why) => DaemonFrame::AnchorFailed(why),
                }
            }
            DaemonRequest::AnchorRemove { fingerprint } => {
                match self.change_manual_anchor(None, Some(fingerprint)).await {
                    Ok(anchors) => DaemonFrame::Anchors(anchors),
                    Err(why) => DaemonFrame::AnchorFailed(why),
                }
            }
            DaemonRequest::ComputerStatus
            | DaemonRequest::ComputerBegin
            | DaemonRequest::ComputerPreview { .. }
            | DaemonRequest::ComputerApprove { .. }
            | DaemonRequest::ComputerCancel { .. }
            | DaemonRequest::ComputerPersonal { .. }
            | DaemonRequest::ComputerBinding { .. }
            | DaemonRequest::ComputerRemove { .. } => self.computer_request(request).await,
            DaemonRequest::Nodes => match self.public_nodes().await {
                Ok(nodes) => DaemonFrame::Nodes(nodes),
                Err(r) => refused(r),
            },
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
            DaemonRequest::DetachForRename { node } => {
                match self.detach(&node, DetachCause::Rename).await {
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
            } => match self.session_end(&node, &session, &reason).await {
                Ok((was_registered, detached)) => DaemonFrame::SessionEnded {
                    was_registered,
                    detached,
                },
                Err(why) => refused(why),
            },
            DaemonRequest::RoomAsks => DaemonFrame::RoomAsks(self.room_asks().await),
            DaemonRequest::RoomBind {
                dir,
                link,
                passphrase,
            } => self.room_bind(&dir, &link, passphrase).await,
            DaemonRequest::RoomDecline { dir } => self.room_decline(&dir),
            DaemonRequest::Status => match self.public_nodes().await {
                Ok(nodes) => DaemonFrame::Status(DaemonStatus {
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    pid: std::process::id(),
                    listen: self.inner.defaults.listen.clone(),
                    nodes,
                    panics: self.inner.metrics.node_panics.load(Ordering::Relaxed),
                }),
                Err(r) => refused(r),
            },
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
                DaemonFrame::SessionActivity(
                    self.inner
                        .sink
                        .activity(&node, &session, bodies, call)
                        .await,
                )
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
/// Physical-write failures retain the existing 4 MiB per-session tail. The aggregate limit
/// prevents many sessions from turning that bounded tail into an unbounded daemon allocation.
const HELD_BYTES: usize = 4 * 1024 * 1024;
const ALL_HELD_BYTES: usize = 64 * 1024 * 1024;
const HELD_SESSIONS: usize = 256;
const HELD_ITEMS: usize = 4096;
const ALL_HELD_ITEMS: usize = 16384;

// Charge actual retained String allocation plus conservative deque-slot/allocator overhead.
// The separate item caps also bound metadata for valid tiny JSON objects.
fn held_charge(body: &String) -> usize {
    body.capacity()
        .saturating_add(4 * std::mem::size_of::<HeldItem>() + 32)
}
fn held_item_charge(item: &HeldItem) -> usize {
    held_charge(&item.body)
        + item
            .effects
            .as_ref()
            .map_or(0, crate::session_sink::SourceEffects::charge)
}
const HELD_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Default)]
struct SessionHolds {
    sessions: BTreeMap<(NodeName, String), HeldSession>,
    bytes: usize,
    blocked_nodes: BTreeMap<NodeName, String>,
}
#[derive(Default)]
struct HeldSession {
    items: std::collections::VecDeque<HeldItem>,
    bytes: usize,
    ordinal: u64,
    why: String,
    loss: Option<HeldLoss>,
    unconfirmed_room: Option<Digest32>,
}
struct HeldItem {
    room: vox_core::hash::Digest32,
    body: String,
    ordinal: u64,
    effects: Option<crate::session_sink::SourceEffects>,
}
struct HeldLoss {
    room: vox_core::hash::Digest32,
    count: u64,
    first: String,
    last: String,
    why: String,
}

impl SessionHolds {
    fn retire_room(&mut self, node: &NodeName, room: &Digest32) {
        self.sessions.retain(|(owner, session), held| {
            if owner != node { return true; }
            let before = held.bytes;
            held.items.retain(|item| item.room != *room);
            held.items.shrink_to_fit();
            held.bytes = held.items.iter().map(held_item_charge).sum();
            self.bytes -= before - held.bytes;
            if held.loss.as_ref().is_some_and(|loss| loss.room == *room) { held.loss = None; }
            if held.unconfirmed_room == Some(*room) { held.unconfirmed_room = None; }
            if before != held.bytes {
                eprintln!("vox daemon: {node}: session {session}: {} volatile bytes retired with their explicitly removed room", before - held.bytes);
            }
            !held.items.is_empty()
        });
    }

    fn release_node(&mut self, node: &NodeName) {
        self.sessions.retain(|(owner, session), held| {
            if owner != node { return true; }
            self.bytes -= held.bytes;
            if held.unconfirmed_room.is_some() {
                eprintln!("vox daemon: {node}: session {session}: {} volatile bytes released on detach; acceptance was unconfirmed, and any committed copies remain saved", held.bytes);
            } else {
                eprintln!("vox daemon: {node}: session {session}: {} unsaved volatile bytes released on detach", held.bytes);
            }
            false
        });
    }

    fn can_hold_new(
        &self,
        key: &(NodeName, String),
        bodies: &[String],
        effects: Option<&crate::session_sink::SourceEffects>,
    ) -> bool {
        let added = bodies.iter().map(held_charge).sum::<usize>()
            + effects.map_or(0, crate::session_sink::SourceEffects::charge);
        (self.sessions.contains_key(key) || self.sessions.len() < HELD_SESSIONS)
            && added <= HELD_BYTES
            && bodies.len() <= HELD_ITEMS
            && self.bytes + added <= ALL_HELD_BYTES
            && self
                .sessions
                .values()
                .map(|held| held.items.len())
                .sum::<usize>()
                + bodies.len()
                <= ALL_HELD_ITEMS
    }

    // Called only after can_hold_new reserved room under the same admission mutex.
    fn freeze(
        &mut self,
        key: (NodeName, String),
        room: vox_core::hash::Digest32,
        bodies: Vec<String>,
        why: String,
        effects: Option<crate::session_sink::SourceEffects>,
    ) -> vox_core::node::daemonipc::SessionAdmission {
        let _ = self.hold(key.clone(), room, bodies, why.clone(), effects);
        if let Some(held) = self.sessions.get_mut(&key) {
            held.unconfirmed_room = Some(room);
        }
        vox_core::node::daemonipc::SessionAdmission::Unconfirmed(why)
    }

    fn hold(
        &mut self,
        key: (NodeName, String),
        room: vox_core::hash::Digest32,
        bodies: Vec<String>,
        why: String,
        mut effects: Option<crate::session_sink::SourceEffects>,
    ) -> vox_core::node::daemonipc::SessionAdmission {
        use vox_core::node::daemonipc::SessionAdmission;
        if !self.sessions.contains_key(&key) && self.sessions.len() == HELD_SESSIONS {
            return SessionAdmission::Refused(format!(
                "the volatile Session hold is full; activity was not retained: {why}"
            ));
        }
        if let Some(held) = self.sessions.get(&key) {
            if held.unconfirmed_room.is_some() {
                return SessionAdmission::Unconfirmed(format!(
                    "earlier acceptance is unknown; this new batch was not retained: {}",
                    held.why
                ));
            }
        }
        let added = bodies.iter().map(held_charge).sum::<usize>()
            + effects
                .as_ref()
                .map_or(0, crate::session_sink::SourceEffects::charge);
        let prior = self.sessions.get(&key).map_or(0, |s| s.bytes);
        let retained = prior.saturating_add(added).min(HELD_BYTES);
        let prior_count = self.sessions.get(&key).map_or(0, |held| held.items.len());
        let retained_count = (prior_count + bodies.len()).min(HELD_ITEMS);
        let all_count = self
            .sessions
            .values()
            .map(|held| held.items.len())
            .sum::<usize>();
        if self.bytes - prior + retained > ALL_HELD_BYTES
            || all_count - prior_count + retained_count > ALL_HELD_ITEMS
        {
            return SessionAdmission::Refused(format!(
                "the volatile Session hold is full; activity was not retained: {why}"
            ));
        }
        // A loss notice belongs to the room whose items were lost. Refuse a new batch if
        // overflowing it would need a second room's loss report while the first cannot save;
        // never reveal old-room activity metadata in the new room or grow a report per move.
        if let Some(held) = self.sessions.get(&key) {
            let mut must_drop = prior.saturating_add(added).saturating_sub(HELD_BYTES);
            let mut must_drop_items = (prior_count + bodies.len()).saturating_sub(HELD_ITEMS);
            let mut loss_room = held.loss.as_ref().map(|loss| loss.room);
            for item in &held.items {
                if must_drop == 0 && must_drop_items == 0 {
                    break;
                }
                // Exact source admission requires every accepted split coordinate. Losing
                // an earlier part would pin later retained parts at the retry head forever.
                // This entire loop is preflight: refuse the newcomer before dropping even
                // an unkeyed row that precedes the protected source or its effects ticket.
                if serde_json::from_str::<serde_json::Value>(&item.body)
                    .is_ok_and(|value| value.get("_vox_source").is_some())
                {
                    return SessionAdmission::Refused(
                        "source activity fills the volatile hold; this new batch was not retained"
                            .into(),
                    );
                }
                if loss_room.is_some_and(|old| old != item.room) {
                    return SessionAdmission::Refused("unsaved activity from an earlier room fills the volatile hold; this batch was not retained".into());
                }
                loss_room = Some(item.room);
                must_drop = must_drop.saturating_sub(held_item_charge(item));
                must_drop_items = must_drop_items.saturating_sub(1);
            }
        }
        let held = self.sessions.entry(key.clone()).or_default();
        held.why = why.clone();
        for body in bodies {
            held.ordinal = held.ordinal.saturating_add(1);
            let item = HeldItem {
                room,
                body,
                ordinal: held.ordinal,
                effects: effects.take(),
            };
            held.bytes += held_item_charge(&item);
            self.bytes += held_item_charge(&item);
            held.items.push_back(item);
        }
        while held.bytes > HELD_BYTES || held.items.len() > HELD_ITEMS {
            let Some(old) = held.items.pop_front() else {
                break;
            };
            held.bytes -= held_item_charge(&old);
            self.bytes -= held_item_charge(&old);
            let v = serde_json::from_str::<serde_json::Value>(&old.body).unwrap_or_default();
            let named = format!(
                "{} at {} (uncommitted held item {})",
                vox_agentcomms::envelope::shown(v["kind"].as_str().unwrap_or("entry"), 128),
                v["ts"]
                    .as_u64()
                    .map_or_else(|| "unknown time".into(), |ts| ts.to_string()),
                old.ordinal
            );
            let loss = held.loss.get_or_insert_with(|| HeldLoss {
                room: old.room,
                count: 0,
                first: named.clone(),
                last: String::new(),
                why: why.clone(),
            });
            loss.count += 1;
            loss.last = named;
            eprintln!("vox daemon: {}: session {}: lost {} held entries, from {} through {}; its bounded 4 MiB hold filled (including allocations, or 4096 items) while {}", key.0, key.1, loss.count, loss.first, loss.last, loss.why);
        }
        held.items.shrink_to_fit();
        SessionAdmission::Held(why)
    }
}

/// Attempt one bounded local transaction, retaining ownership on a storage error. A lost
/// receipt freezes this queue: retrying it could duplicate a committed item.
async fn flush_session_hold(
    handle: &vox_core::node::actor::NodeHandle,
    key: &(NodeName, String),
    held: &mut HeldSession,
) -> (
    usize,
    bool,
    Option<(Digest32, crate::session_sink::SourceEffects)>,
) {
    if held.unconfirmed_room.is_some() {
        return (0, false, None);
    }
    let Some(front) = held.items.front() else {
        return (0, false, None);
    };
    let room = held.loss.as_ref().map_or(front.room, |loss| loss.room);
    let notice = held.loss.as_ref().map(|loss| serde_json::json!({
        "v":vox_agentcomms::activity::VERSION, "session":key.1, "kind":"notice",
        "ts":vox_core::transport::quic::unix_now_ms(),
        "text":format!("{} entries of this session were lost while held only in memory: from {} through {}; {}", loss.count, loss.first, loss.last, loss.why),
    }).to_string());
    let notice_only = notice.is_some();
    let mut bodies = Vec::new();
    let mut bytes = 0;
    if let Some(notice) = notice {
        bodies.push(notice);
    } else {
        for item in &held.items {
            if item.room != room
                // Freshness is one boolean for the admission. An item carrying source
                // effects gets its own receipt, never a duplicate/new-source mixture.
                || (!bodies.is_empty() && (front.effects.is_some() || item.effects.is_some()))
                || bytes + item.body.len() > vox_core::node::session_ingress::MAX_BATCH_BYTES
                || bodies.len() == vox_core::node::session_ingress::MAX_BATCH_ITEMS
            {
                break;
            }
            bytes += item.body.len();
            bodies.push(item.body.clone());
        }
    }
    let count = bodies.len();
    match save_session_batch(handle, room, &key.1, bodies).await {
        Ok(saved) => {
            if notice_only {
                held.loss = None;
                return (0, true, None);
            }
            let mut released = 0;
            let mut committed = None;
            for _ in 0..count {
                if let Some(mut item) = held.items.pop_front() {
                    released += held_item_charge(&item);
                    if saved.fresh {
                        committed = item.effects.take().map(|effects| (item.room, effects));
                    }
                }
            }
            // Returning credits also releases now-unused deque slots; a drained queue cannot
            // keep a history-sized allocation while lending those credits to another session.
            held.items.shrink_to_fit();
            held.bytes -= released;
            (released, true, committed)
        }
        Err(SessionSaveError::Save(error)) => {
            held.why = error.to_string();
            (0, false, None)
        }
        Err(SessionSaveError::Unconfirmed(why)) => {
            held.unconfirmed_room = Some(room);
            held.why = why;
            (0, false, None)
        }
    }
}

// Source admission has already committed. Retiring its exact request tickets is not undone
// by a later transcript-storage problem. Resolution rows use the existing charged hold and
// one bounded storage attempt; this path never re-enters the Poster/admission mutex.
async fn save_source_resolutions(
    handle: &NodeHandle,
    holds: &mut SessionHolds,
    key: &(NodeName, String),
    room: Digest32,
    bodies: Vec<String>,
) {
    use vox_core::node::daemonipc::SessionAdmission;
    if bodies.is_empty() {
        return;
    }
    // An ask may still be awaiting its own admission when the source snapshot is captured.
    // Refuse an unpublishable resolution explicitly rather than pinning the retry head with
    // a row that can never pass the same Session size/shape checks as ordinary activity.
    for body in &bodies {
        let checked = serde_json::from_str::<serde_json::Value>(body)
            .map_err(|error| error.to_string())
            .and_then(|mut value| {
                let object = value.as_object_mut().ok_or("resolution is not an object")?;
                object.insert("seq".into(), u64::MAX.into());
                object.insert("session".into(), key.1.clone().into());
                vox_core::node::content::SessionEntry::new(0, &key.1, &value.to_string())
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            });
        if let Err(why) = checked {
            eprintln!("vox daemon: {}: session {}: source activity is committed, but its request resolutions cannot be saved: {why}", key.0, key.1);
            return;
        }
    }
    let already_held = holds.sessions.contains_key(key);
    let outcome = holds.hold(
        key.clone(),
        room,
        bodies,
        "source activity committed; its request resolutions are awaiting storage".into(),
        None,
    );
    if !matches!(outcome, SessionAdmission::Held(_)) {
        eprintln!("vox daemon: {}: session {}: source activity is committed, but its request resolutions were not saved: {outcome:?}", key.0, key.1);
        return;
    }
    if !already_held {
        if let Some(held) = holds.sessions.get_mut(key) {
            let (removed, _, _) = flush_session_hold(handle, key, held).await;
            let empty = held.items.is_empty();
            holds.bytes -= removed;
            if empty {
                holds.sessions.remove(key);
            }
        }
    }
    if let Some(held) = holds.sessions.get(key) {
        eprintln!("vox daemon: {}: session {}: source activity is committed; request resolutions remain only in the bounded volatile hold: {}", key.0, key.1, held.why);
    }
}

enum SessionSaveError {
    Save(vox_core::error::Error),
    Unconfirmed(String),
}
impl From<vox_core::node::session_ingress::AdmissionError> for SessionSaveError {
    fn from(error: vox_core::node::session_ingress::AdmissionError) -> Self {
        use vox_core::node::session_ingress::AdmissionError;
        match error {
            AdmissionError::NotCommitted(error) => Self::Save(error),
            AdmissionError::Unconfirmed(error) => {
                Self::Unconfirmed(format!("the Session commit outcome is unknown: {error}"))
            }
        }
    }
}

async fn save_session_batch(
    handle: &vox_core::node::actor::NodeHandle,
    room: vox_core::hash::Digest32,
    session: &str,
    bodies: Vec<String>,
) -> Result<vox_core::node::session_ingress::Committed, SessionSaveError> {
    let (reply, mut received) = tokio::sync::oneshot::channel();
    // Waiting for the actor cannot monopolize admission for every other session. A timeout
    // can race a commit, so it is explicitly Unconfirmed; it must never enter a retry loop.
    match tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let applying = handle.apply(vox_core::node::api::NodeCommand::AcceptSessionBatch {
            channel_id: room,
            session_id: session.to_owned(),
            bodies,
            reply,
        });
        tokio::pin!(applying);
        // The durable receipt precedes the actor's display publication. Do not turn a saved
        // batch into an ambiguous outcome merely because an unrelated view update is slow.
        tokio::select! {
            result = &mut received => result
                .map_err(|_| SessionSaveError::Unconfirmed("the durable receipt disappeared; acceptance is unknown".into()))?
                .map_err(SessionSaveError::from),
            outcome = &mut applying => match received.await {
                Ok(result) => result.map_err(SessionSaveError::from),
                Err(_) => Err(SessionSaveError::Unconfirmed(format!(
                    "no durable receipt; acceptance is unknown: {outcome}"
                ))),
            }
        }
    }).await {
        Ok(result) => result,
        Err(_) => Err(SessionSaveError::Unconfirmed(
            "the node did not return its durable receipt within 2 seconds; acceptance is unknown".into(),
        )),
    }
}

async fn retire_session_room(
    handle: &NodeHandle,
    retirement: vox_core::node::session_ingress::Retirement,
) -> Result<(), String> {
    let (reply, mut received) = tokio::sync::oneshot::channel();
    tokio::time::timeout(Duration::from_secs(2), async {
        let applying = handle.apply(NodeCommand::RetireSessionRoom { retirement, reply });
        tokio::pin!(applying);
        tokio::select! {
            result = &mut received => result.map_err(|_| "the cleanup receipt disappeared".to_owned())?.map_err(|e| e.to_string()),
            outcome = &mut applying => received.await.map_err(|_| format!("cleanup was not confirmed: {outcome}"))?.map_err(|e| e.to_string()),
        }
    }).await.map_err(|_| "the node did not confirm cleanup within 2 seconds".to_owned())?
}

/// Lifecycle ends share the same ordered inbox; ending a registration does not jump ahead of
/// accepted transcript entries or make their delivery depend on a still-running harness.
async fn enqueue_session_end(
    handle: &vox_core::node::actor::NodeHandle,
    held: &mut SessionHolds,
    node: &NodeName,
    room: vox_core::hash::Digest32,
    session: &str,
    reason: &str,
) {
    let mut env =
        vox_agentcomms::envelope::Envelope::new(vox_agentcomms::envelope::SESSION_END, "");
    session.clone_into(&mut env.from);
    env.data = serde_json::json!({"reason": reason});
    let bodies = vec![env.to_text()];
    let key = (node.clone(), session.to_owned());
    let outcome = if held.sessions.contains_key(&key) {
        held.hold(
            key,
            room,
            bodies,
            "earlier activity is held only in memory".into(),
            None,
        )
    } else if !held.can_hold_new(&key, &bodies, None) {
        vox_core::node::daemonipc::SessionAdmission::Refused(
            "Session admission recovery capacity is full; end record was not retained".into(),
        )
    } else {
        match save_session_batch(handle, room, session, bodies.clone()).await {
            Ok(saved) => vox_core::node::daemonipc::SessionAdmission::Committed {
                first: saved.first,
                last: saved.last,
            },
            Err(SessionSaveError::Save(error))
                if matches!(error, vox_core::error::Error::Storage { .. }) =>
            {
                held.hold(key, room, bodies, error.to_string(), None)
            }
            Err(SessionSaveError::Save(error)) => {
                vox_core::node::daemonipc::SessionAdmission::Refused(error.to_string())
            }
            Err(SessionSaveError::Unconfirmed(why)) => held.freeze(key, room, bodies, why, None),
        }
    };
    if !matches!(
        outcome,
        vox_core::node::daemonipc::SessionAdmission::Committed { .. }
    ) {
        eprintln!(
            "vox daemon: {node}: session {session}: end record is not confirmed saved: {outcome:?}"
        );
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
            || vox_core::node::attention::OwnRequest::parse(body).is_some()
    }

    fn serve(
        &self,
        body: Vec<u8>,
        stream: tokio::net::UnixStream,
        handle: NodeHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        if let Some(request) = vox_core::node::attention::OwnRequest::parse(&body) {
            let weak = self.drive.0.clone();
            return Box::pin(async move {
                if let Some(inner) = weak.upgrade() {
                    Router { inner }
                        .attention_own(&handle, request, stream)
                        .await;
                }
            });
        }
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

/// How often a Claude Code session's transcript is read for a new name.
const TITLE_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// The titles a Claude Code transcript holds, read from where the last read stopped: a `/rename`
/// writes `{"type":"custom-title","customTitle":…}`, and Claude Code's own title is
/// `{"type":"ai-title","aiTitle":…}`. The name a person set wins, exactly as set, case and all;
/// Claude Code's own title only while there is none, as the hooks read them
/// (`agent_hook::session_name`).
///
/// Nothing else of the transcript is kept. The scanner retains offsets and a tiny marker
/// match, including across incomplete lines. A complete title line is parsed from the file;
/// unrelated JSON values are skipped, never collected as a transcript body.
#[derive(Default)]
struct Titles {
    /// Bytes scanned so far, including a line not yet ended.
    offset: u64,
    /// Start of the unfinished line. Its bytes remain in the transcript, not in memory.
    line_start: u64,
    marker_match: usize,
    has_title: bool,
    custom: Option<String>,
    made: Option<String>,
}

/// Deserialize just the current name fields. Unknown fields use Serde's streaming skip path,
/// so even a title record beside a large tool result does not allocate that result.
#[derive(serde::Deserialize)]
struct TranscriptTitle {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, rename = "customTitle")]
    custom: Option<String>,
    #[serde(default, rename = "aiTitle")]
    made: Option<String>,
}

/// A hook uses the same streaming title reader as the daemon. Tool-result lines are
/// skipped from fixed-size buffers, never allocated as a complete transcript line.
pub(crate) fn transcript_name(path: &std::path::Path) -> Option<String> {
    Titles::default().read(path).name()
}

impl Titles {
    fn read(mut self, path: &std::path::Path) -> Self {
        use std::io::{Read as _, Seek as _, SeekFrom};
        const MARKER: &[u8] = b"-title\"";
        let Ok(mut file) = std::fs::File::open(path) else {
            return self;
        };
        let Ok(metadata) = file.metadata() else {
            return self;
        };
        // A transcript that got shorter was written anew: read from its start.
        if metadata.len() < self.offset {
            self = Self::default();
        }
        // A fixed end avoids following a busy writer forever during this blocking read.
        let end = metadata.len();
        let mut bytes = [0_u8; 8192];
        while self.offset < end {
            if file.seek(SeekFrom::Start(self.offset)).is_err() {
                break;
            }
            let take = bytes
                .len()
                .min(usize::try_from(end - self.offset).unwrap_or(usize::MAX));
            let n = match file.read(&mut bytes[..take]) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            for byte in &bytes[..n] {
                self.offset += 1;
                if *byte != b'\n' {
                    if !self.has_title {
                        if *byte == MARKER[self.marker_match] {
                            self.marker_match += 1;
                            self.has_title = self.marker_match == MARKER.len();
                        } else {
                            // The marker has no '-' after its first byte, so this is also its
                            // only possible overlapping start.
                            self.marker_match = usize::from(*byte == MARKER[0]);
                        }
                    }
                    continue;
                }
                if self.has_title {
                    // Reread only a complete candidate, with fixed-size I/O buffers. There is
                    // no maximum line length that could silently discard a valid rename.
                    if file.seek(SeekFrom::Start(self.line_start)).is_err() {
                        self.offset = self.line_start;
                        self.marker_match = 0;
                        self.has_title = false;
                        return self;
                    }
                    let line = (&mut file).take(self.offset - self.line_start);
                    match serde_json::from_reader::<_, TranscriptTitle>(std::io::BufReader::new(
                        line,
                    )) {
                        Ok(title) => match title.kind.as_str() {
                            "custom-title" => self.custom = title.custom,
                            "ai-title" => self.made = title.made,
                            _ => {}
                        },
                        // Retry an I/O failure from this line's beginning on the next read.
                        Err(e) if e.is_io() => {
                            self.offset = self.line_start;
                            self.marker_match = 0;
                            self.has_title = false;
                            return self;
                        }
                        Err(_) => {}
                    }
                }
                self.line_start = self.offset;
                self.marker_match = 0;
                self.has_title = false;
            }
        }
        self
    }

    fn name(&self) -> Option<String> {
        self.custom
            .clone()
            .or_else(|| self.made.clone())
            .map(|n| n.trim().to_owned())
            .filter(|n| !n.is_empty())
    }
}
