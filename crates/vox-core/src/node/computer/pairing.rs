//! The bounded computer-group enrollment ceremony on the daemon's existing authenticated QUIC presence.
use super::*;
use crate::join::{cpace, pop};
use crate::nat::bootstrap::BootstrapSet;
use crate::nat::multiaddr::{EndpointList, Multiaddr};
use crate::node::network::NodeNet;
use crate::node::presence::NetPresence;
use crate::transport::{
    framing::{read_frame_within, write_frame},
    quic::VoxConnection,
    streams::{self, StreamKind},
};
use base64::Engine as _;
use quinn::{RecvStream, SendStream};
use std::time::Duration;

const PAIR_DOMAIN: &[u8] = b"vox/computer-pair/v1\0";
const PATIENCE: Duration = Duration::from_secs(15);
// An exchange carries retained records from the same bounded transaction, never a smaller
// unrelated limit that would strand an otherwise valid roster as nodes are added.
const MAX_FRAME: usize = MAX_STATE as usize;
fn now() -> u64 {
    static CLOCK: std::sync::OnceLock<crate::time::Clock> = std::sync::OnceLock::new();
    CLOCK.get_or_init(crate::time::clock_with_test_skew)()
}
fn text_id(id: &Digest32) -> String {
    crate::node::link::b32_encode(id)
}

/// Identity facts shown before approval; the fingerprint is authority, the name is presentation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerIdentity {
    /// Presented computer name.
    pub name: String,
    /// Full management fingerprint.
    pub fingerprint: String,
    /// Stable data-root discriminator; not physical hardware attestation.
    pub installation: String,
}
impl ComputerIdentity {
    fn of(d: &Description) -> Result<Self> {
        Ok(Self {
            name: d.name.clone(),
            fingerprint: text_id(&d.fingerprint()?),
            installation: text_id(&d.installation),
        })
    }
}
/// A PAKE-authenticated enrollment awaiting its exact operator approval or peer confirmation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PairingPreview {
    /// Exact immutable genesis operation being displayed and approved.
    pub operation_id: String,
    /// The other authenticated installation.
    pub peer: ComputerIdentity,
    /// This operator's approval is already durably recorded.
    pub approved_here: bool,
    /// The peer's composite approval is already durably recorded.
    pub approved_there: bool,
    /// Invitation expiry, Unix milliseconds.
    pub expires_ms: u64,
}
/// Signed application of the exact current group frontier, independent of present reachability.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerApplication {
    /// Enrolled installation.
    pub computer: ComputerIdentity,
    /// This member signed a complete applied receipt for the current frontier.
    pub confirmed: bool,
    /// When this node last exchanged pairing state with it, Unix milliseconds; `None` before the
    /// first exchange since the daemon started.
    pub last_exchange_ms: Option<u64>,
    /// Exchanges since the daemon started: with nothing to settle, a few per hour, not one every
    /// two seconds (ADR-038 FX-15; #989).
    pub exchanges: u64,
    /// Attempts in a row that could not reach it; the retry backs off with each.
    pub exchange_failures: u32,
}
/// A node identity proved by its node and managing computer, with current policy role.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerNode {
    /// Full management identity.
    pub computer: String,
    /// Full node identity, never inferred from its name.
    pub fingerprint: String,
    /// Authenticated presented name; local keyring aliases are separate.
    pub name: String,
    /// Saved selected personal node; drives non-personal nodes while enrolled.
    pub personal: bool,
}
/// One available explicit operation derived from retained authenticated binding evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerBindingAction {
    /// Full node identity.
    pub node: String,
    /// Authenticated presented node name.
    pub name: String,
    /// Previous/current managing computer identity.
    pub computer: String,
    /// release / transfer / recover.
    pub action: String,
}
/// Daemon-wide public state. A failed reach is not a rejection of the pairing code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerStatus {
    /// This installation's persistent identity.
    pub this_computer: ComputerIdentity,
    /// Exact fixed-policy explanation used by both app and CLI.
    pub policy: String,
    /// Individual, waiting, needs-approval, applying, or confirmed.
    pub state: String,
    /// Current one-time link, returned only over the account's private control socket.
    pub invite_link: Option<String>,
    /// Identifier used to cancel before a peer has presented itself.
    pub invite_id: Option<String>,
    /// Its expiry, Unix milliseconds.
    pub invite_expires_ms: Option<u64>,
    /// Authenticated candidate, never populated from an unproved name or fingerprint.
    pub pairing: Option<PairingPreview>,
    /// Explicitly enrolled computers.
    pub computers: Vec<ComputerIdentity>,
    /// Per-member application; unreachable members never get a fabricated acknowledgement.
    pub applications: Vec<ComputerApplication>,
    /// Current authenticated roster and personal roles.
    pub nodes: Vec<ComputerNode>,
    /// Explicit binding operations supported by retained signed evidence.
    pub binding_actions: Vec<ComputerBindingAction>,
    /// Former members retained as removal history, never acknowledgement of remote erasure.
    pub removed: Vec<ComputerIdentity>,
    /// Exact frontier to confirm when removing a computer; stale confirmations are refused.
    pub frontier: String,
    /// Saved local selection, including before a group is formed.
    pub selected_node: Option<String>,
    /// Local name captured from the same verified actor as the selection.
    pub selected_name: Option<String>,
    /// Managed nodes still needing attach/unlock or policy reconciliation.
    pub pending_nodes: Vec<String>,
    /// Last reach or protocol failure, without any secret or full link.
    pub problem: Option<String>,
}

struct Link {
    target: Digest32,
    invite: Digest32,
    secret: Zeroizing<[u8; 16]>,
    transport: Zeroizing<Digest32>,
    expires: u64,
    endpoints: EndpointList,
    anchors: BootstrapSet,
}
impl Link {
    fn url(&self) -> String {
        let mut e = Encoder::for_secrets();
        e.array(8)
            .uint(PROTOCOL)
            .bytes(&self.target)
            .bytes(&self.invite)
            .bytes(self.secret.as_ref())
            .uint(self.expires)
            .array(self.endpoints.len());
        for a in self.endpoints.addrs() {
            e.text(&a.to_string());
        }
        e.bytes(&self.anchors.to_bytes())
            .bytes(self.transport.as_ref());
        format!(
            "vox-computer://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e.finish())
        )
    }
    fn parse(text: &str) -> Result<Self> {
        let fail = || Error::Profile("invalid computer pairing link");
        let text = text.strip_prefix("vox-computer://").ok_or_else(fail)?;
        if text.len() > 16384 {
            return Err(fail());
        }
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(text)
                .map_err(|_| fail())?,
        );
        let mut d = Decoder::new(&bytes);
        arity(&mut d, 8)?;
        if d.uint()? != PROTOCOL {
            return Err(fail());
        }
        let target = digest(&mut d)?;
        let invite = digest(&mut d)?;
        let secret = Zeroizing::new(d.bytes()?.try_into().map_err(|_| fail())?);
        let expires = d.uint()?;
        let n = d.array()?;
        if n > 8 {
            return Err(fail());
        }
        let mut addrs = Vec::new();
        for _ in 0..n {
            addrs.push(Multiaddr::parse(d.text()?)?);
        }
        let endpoints = EndpointList::new(addrs)?;
        let anchors = BootstrapSet::from_bytes(d.bytes()?)?;
        let transport = Zeroizing::new(digest(&mut d)?);
        d.finish()?;
        Ok(Self {
            target,
            invite,
            secret,
            transport,
            expires,
            endpoints,
            anchors,
        })
    }
}

#[derive(Clone)]
struct TransportLease {
    registration: Digest32,
    token: Zeroizing<Digest32>,
    expires: u64,
    peer: Option<Digest32>,
    anchors: BootstrapSet,
}

#[derive(Clone, Copy)]
struct RegisteredLease {
    connection: u64,
    expires: u64,
    peer: Option<Digest32>,
}

/// Management network and ceremony. It never dispatches room streams, even for enrolled peers.
pub struct Management {
    /// The sole persistent transaction domain.
    pub computer: Arc<Computer>,
    net: Arc<NodeNet>,
    anchors: BootstrapSet,
    serving: Mutex<std::collections::BTreeSet<u64>>,
    /// Computers an exchange is in flight with: one at a time per computer, never a round that
    /// waits for every computer, so a slow one delays no other (#989).
    inflight: Mutex<BTreeMap<Digest32, Flight>>,
    /// Computers whose in-flight exchange was cut because this node changed meanwhile: its end
    /// is no failure, and the next tick exchanges again.
    superseded: Mutex<BTreeSet<Digest32>>,
    slots: Arc<tokio::sync::Semaphore>,
    problem: Mutex<Option<String>>,
    pending_nodes: Mutex<Vec<String>>,
    transport_cache: Mutex<BTreeMap<(Digest32, Digest32), RegisteredLease>>,
    revoked_transport: Mutex<std::collections::BTreeSet<(Digest32, Digest32, u64)>>,
    /// Per computer: when this node last exchanged state with it, and how many exchanges in a row
    /// failed since one succeeded. What `retry` keys its cadence on (ADR-038 FX-15; #989).
    exchanged: Mutex<BTreeMap<Digest32, Exchanged>>,
}

/// One computer's exchange record.
#[derive(Clone, Debug, Default)]
struct Exchanged {
    /// The last attempt, succeeded or not.
    last: Option<std::time::Instant>,
    /// The last completed exchange, Unix milliseconds, for the status a person reads.
    last_ms: Option<u64>,
    /// Exchanges completed since the daemon started.
    count: u64,
    /// Failures in a row since the last success; the backoff doubles with each.
    failures: u32,
    /// This node's state revision at the last attempt, and whether a pairing operation
    /// involving the computer was open then: a change in either is tried at once, backoff or
    /// not; the same state waits the backoff out.
    revision: u64,
    involved: bool,
    /// The last failure's words, while failures stand.
    problem: Option<String>,
}

/// One exchange attempt's bookkeeping: records its outcome when done, and a failure if the
/// task is torn down before (a panic), so a computer never stays in flight forever.
struct Attempt {
    me: Arc<Management>,
    peer: Digest32,
    revision: u64,
    involved: bool,
    recorded: bool,
}

impl Attempt {
    fn done(mut self, outcome: std::result::Result<(), String>) {
        self.recorded = true;
        self.me
            .record_exchange(self.peer, self.revision, self.involved, outcome);
        // Dropped here: the reservation is released by its owner, after the record.
    }
}

/// One exchange in flight: the state it carries, so a later change can cut it, and how.
struct Flight {
    revision: u64,
    involved: bool,
    abort: Option<tokio::task::AbortHandle>,
}

/// A computer reserved as in flight by the operator's pairing, released on drop.
struct Reserved {
    me: Arc<Management>,
    peer: Digest32,
}

impl Drop for Reserved {
    fn drop(&mut self) {
        lock(&self.me.inflight).remove(&self.peer);
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        let superseded = lock(&self.me.superseded).remove(&self.peer);
        if !self.recorded && !superseded {
            self.me.record_exchange(
                self.peer,
                self.revision,
                self.involved,
                Err("the exchange task failed".to_owned()),
            );
        }
        lock(&self.me.inflight).remove(&self.peer);
    }
}

/// Without a need, a computer whose receipt covers this node's current state is exchanged with
/// this often, so a lost message never leaves two computers apart for long.
const EXCHANGE_FALLBACK: Duration = Duration::from_secs(60);
/// A computer that could not be reached is tried again after this, doubling per failure.
const EXCHANGE_BACKOFF: Duration = Duration::from_secs(2);
/// The longest a failing computer waits between attempts.
const EXCHANGE_BACKOFF_MAX: Duration = Duration::from_secs(120);
/// An exchange that has not finished by then counts as failed and is tried again after its
/// backoff: a computer that hangs must not stay "in flight" forever. Generous, because a
/// slow but valid exchange of a long history must complete; no other computer waits on it.
const EXCHANGE_WITHIN: Duration = Duration::from_secs(600);
impl Management {
    /// The account's explicit host:port lookup uses its existing socket, but no management
    /// identity or authority. The returned fingerprint is proved; lookup persists no anchor source.
    pub async fn lookup_anchor(&self, input: &str) -> Result<String> {
        let input = input.to_owned();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            let resolve = input.clone();
            let addresses = tokio::task::spawn_blocking(move || {
                crate::node::link::parse_anchor_addrs(&resolve)
            })
            .await
            .map_err(|error| {
                Error::Handshake(format!("anchor address lookup stopped: {error}"))
            })??;
            let mut errors = Vec::new();
            for address in addresses.iter().filter_map(|a| a.socket_addr()).take(8) {
                match self
                    .net
                    .manager()
                    .endpoint()
                    .shared()
                    .lookup_anchor(address)
                    .await
                {
                    Ok(id) => return Ok(format!("{}@{input}", crate::node::link::b32_encode(&id))),
                    Err(error) => errors.push(format!("{address}: {error}")),
                }
            }
            Err(Error::Handshake(format!(
                "no anchor was verified at {input}: {}",
                errors.join("; ")
            )))
        })
        .await
        .map_err(|_| {
            Error::Handshake("anchor lookup did not finish within 20 s; nothing was added".into())
        })?
    }

    /// Sign a receipt only for the exact locally applied policy and authenticated roster frontier.
    /// The remote receipt is a separate statement: offline peers remain pending.
    pub fn record_application(&self) -> Result<()> {
        if !lock(&self.pending_nodes).is_empty() {
            return Ok(());
        }
        let local = self.computer.signer.fingerprint();
        let endpoints = self.net.local_endpoints()?;
        self.computer.change(|s| {
            if s.genesis.is_some() && s.grant(&local).is_some() && s.quarantined.is_empty() {
                let reach = Reach {
                    endpoints,
                    anchors: self.anchors.clone(),
                    token: s
                        .reaches
                        .get(&local)
                        .map(|r| r.token)
                        .unwrap_or(random_array()?),
                };
                if s.reaches.get(&local) != Some(&reach) {
                    let mut body = Encoder::new();
                    body.array(1).bytes(&reach.encode());
                    let event =
                        Control::sign(s, "reach", body.finish(), self.computer.signer.as_ref())?;
                    s.retain_roster(event)?;
                }
            }
            let Some(g) = &s.genesis else {
                return Ok(());
            };
            if !s.quarantined.is_empty() || !s.history_complete() || !s.binding_approvals.is_empty()
            {
                return Ok(());
            }
            if s.rosters.len() != s.descriptions().len() {
                return Ok(());
            }
            let Some(roster) = s.rosters.get(&local) else {
                return Ok(());
            };
            for b in roster.read(&local, &g.incarnation())?.2 {
                if !s
                    .applied
                    .get(&b.verify(&local, &g.incarnation())?)
                    .is_some_and(|a| a.revision == s.revision && a.interval == g.incarnation())
                {
                    return Ok(());
                }
            }
            let body = receipt_body(s, s.revision)?;
            if s.receipts.get(&local).is_some_and(|r| r.body == body) {
                return Ok(());
            }
            s.receipts.insert(
                local,
                Signed::create(
                    b"vox/computer-applied/v1\0",
                    body,
                    self.computer.signer.as_ref(),
                )?,
            );
            Ok(())
        })
    }
    /// Attach the management role to the existing presence, including a daemon with zero nodes.
    pub fn start(
        computer: Arc<Computer>,
        presence: Arc<NetPresence>,
        anchors: BootstrapSet,
    ) -> Result<Arc<Self>> {
        let mut link = presence.attach_management(Arc::clone(&computer.signer))?;
        let net = Arc::new(NodeNet::new(
            link.endpoint,
            presence,
            crate::time::clock_with_test_skew(),
        ));
        let mut policy = crate::node::net::PeerPolicy::new();
        for a in anchors.nodes() {
            policy.add_anchor(a.id);
        }
        net.policy().replace(policy);
        let me = Arc::new(Self {
            computer,
            net,
            anchors,
            serving: Mutex::new(Default::default()),
            inflight: Mutex::new(BTreeMap::new()),
            superseded: Mutex::new(BTreeSet::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(8)),
            problem: Mutex::new(None),
            pending_nodes: Mutex::new(Vec::new()),
            transport_cache: Mutex::new(BTreeMap::new()),
            revoked_transport: Mutex::new(Default::default()),
            exchanged: Mutex::new(BTreeMap::new()),
        });
        let weak = Arc::downgrade(&me);
        tokio::spawn(async move {
            while let Some(c) = link.inbound.recv().await {
                let Some(me) = weak.upgrade() else {
                    return;
                };
                let filed = me.net.manager().take_inbound(c).await;
                me.serve(filed.kept);
                if let Some(c) = filed.also_serve {
                    me.serve(c);
                }
            }
        });
        let weak = Arc::downgrade(&me);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(me) = weak.upgrade() else {
                    return;
                };
                if let Err(e) = me.retry().await {
                    *lock(&me.problem) = Some(e.to_string());
                }
            }
        });
        let weak = Arc::downgrade(&me);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(me) = weak.upgrade() else {
                    return;
                };
                // An optional unreachable anchor never holds up direct pairing, status or retry.
                let _ = me.refresh_transport().await;
            }
        });
        Ok(me)
    }
    fn serve(self: &Arc<Self>, conn: Arc<VoxConnection>) {
        if !lock(&self.serving).insert(conn.serial()) {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Ok((kind, mut send, mut recv)) = streams::accept_typed(&conn).await else {
                    break;
                };
                let Some(me) = weak.upgrade() else {
                    break;
                };
                if kind == StreamKind::Goodbye {
                    conn.mark_peer_stopped();
                    conn.close(crate::wire::WireError::ShuttingDown);
                    break;
                }
                if matches!(kind, StreamKind::Coord | StreamKind::Circuit)
                    && me.net.policy().snapshot().is_anchor(&conn.peer_id())
                {
                    let Ok(slot) = Arc::clone(&me.slots).try_acquire_owned() else {
                        streams::refuse(&mut send, &mut recv);
                        continue;
                    };
                    let c = Arc::clone(&conn);
                    tokio::spawn(async move {
                        let _slot = slot;
                        let _ = tokio::time::timeout(
                            Duration::from_secs(45),
                            me.transport_incoming(&c, kind, send, recv),
                        )
                        .await;
                    });
                    continue;
                }
                if kind != StreamKind::Computer {
                    streams::refuse(&mut send, &mut recv);
                    continue;
                }
                let Ok(slot) = Arc::clone(&me.slots).try_acquire_owned() else {
                    streams::refuse(&mut send, &mut recv);
                    continue;
                };
                let c = Arc::clone(&conn);
                tokio::spawn(async move {
                    let _slot = slot;
                    let result = tokio::time::timeout(
                        Duration::from_secs(45),
                        me.answer(&c, &mut send, &mut recv),
                    )
                    .await;
                    if let Ok(Err(e)) = result {
                        let mut f = Encoder::new();
                        f.array(2).uint(0).text(&e.to_string());
                        let _ = write_frame(&mut send, &f.finish()).await;
                    }
                    let _ = send.finish();
                });
            }
            if let Some(me) = weak.upgrade() {
                lock(&me.serving).remove(&conn.serial());
            }
        });
    }
    /// An active invitation or enrolled management endpoint keeps a zero-node daemon available.
    pub fn keeps_daemon_alive(&self) -> bool {
        let s = lock(&self.computer.state);
        s.genesis.is_some()
            || s.pending.is_some()
            || s.invitations
                .iter()
                .any(|i| !i.cancelled && i.expires > now())
    }
    /// Begin one bounded invitation. Existing pending approval must be cancelled explicitly first.
    pub fn begin(&self) -> Result<ComputerStatus> {
        let endpoints = self.net.local_endpoints()?;
        let id = random_array()?;
        let secret = Zeroizing::new(random_array()?);
        let transport = Zeroizing::new(random_array()?);
        let expires = now().saturating_add(INVITE_LIFETIME_MS);
        let nonce = random_array()?;
        let grants = [random_array()?, random_array()?];
        self.computer.change(|s| {
            if s.genesis.is_some()
                && (s.grant(&self.computer.signer.fingerprint()).is_none()
                    || !s.quarantined.is_empty())
            {
                return Err(Error::Profile(
                    "this computer cannot enroll another member while its authority is suspended",
                ));
            }
            if s.pending.as_ref().is_some_and(|p| !enrolled(s, p))
                || s.invitations
                    .iter()
                    .any(|i| !i.cancelled && i.expires > now() && i.target.is_none())
            {
                return Err(Error::Profile(
                    "a computer pairing is already pending; cancel it before making another code",
                ));
            }
            if s.invitations.len() >= MAX_RECORDS {
                return Err(Error::Profile(
                    "retained computer invitation history is full",
                ));
            }
            if let Some(link) = s.pair_link.take() {
                s.links.push(link);
            }
            s.pending = None;
            s.group_genesis = None;
            s.pending_expires = 0;
            s.invitations.push(Invitation {
                id,
                secret: secret.clone(),
                transport: transport.clone(),
                expires,
                nonce,
                grants,
                cancelled: false,
                target: None,
            });
            Ok(())
        })?;
        let mut status = self.status()?;
        status.invite_link = Some(
            Link {
                target: self.computer.signer.fingerprint(),
                invite: id,
                secret,
                transport,
                expires,
                endpoints,
                anchors: self.anchors.clone(),
            }
            .url(),
        );
        status.invite_expires_ms = Some(expires);
        Ok(status)
    }
    /// Cancel a current uncommitted operation. Signed completed enrollment is never undone here.
    pub fn cancel(&self, operation: &str) -> Result<ComputerStatus> {
        let id = crate::node::link::b32_decode(operation, "computer pairing operation")?;
        let closed_expired = self.computer.change(|s| {
            if s.pending.as_ref().is_some_and(|g| (g.operation()==id || s.invitations.iter().any(|i| i.id==id && i.nonce==g.nonce)) && enrolled(s,g)) || s.genesis.as_ref().is_some_and(|g|g.operation()==id) {
                return Err(Error::Profile("this pairing is established; cancellation does not remove computer trust"));
            }
            if s.cancelled.contains_key(&id) {
                return Ok(false);
            }
            let pending_nonce = s.pending.as_ref().and_then(|g| {
                (g.operation() == id || s.invitations.iter().any(|i| i.id == id && i.nonce == g.nonce))
                    .then_some(g.nonce)
            });
            let pending = pending_nonce.is_some();
            if s.invitations.iter().any(|i| i.id == id && i.cancelled) {
                return Ok(false);
            }
            let locally_approved = pending && s.pending.as_ref().is_some_and(|g| {
                side(g, &self.computer.signer.fingerprint())
                    .ok().is_some_and(|at| g.approvals[at].is_some())
            });
            if locally_approved && s.pending_expires > now() {
                return Err(Error::Profile("this approval is already signed and the other computer may complete it; wait for its result or close the incomplete attempt after it expires"));
            }
            let mut found = pending;
            for i in &mut s.invitations {
                if (i.id == id || pending_nonce == Some(i.nonce)) && !i.cancelled {
                    found = true;
                    i.cancelled = true;
                }
            }
            if !found {
                return Err(Error::Profile("that computer pairing is no longer current"));
            }
            if pending {
                if let Some(g) = s.pending.take() {
                    s.cancelled.insert(g.operation(), g);
                }
                if let Some(link) = s.pair_link.take() {
                    s.cancelled_links.push(link);
                }
                s.pending_expires = 0;
                if s.genesis.is_none() { s.rosters.clear(); s.members.clear(); s.reaches.clear(); s.group_genesis=None; }
                // Fault exclusion is permanent within this retired incarnation. Retain its
                // signed evidence, but do not carry its derived fault into a fresh enrollment.
                if s.genesis.is_none() { s.quarantined.clear(); s.receipts.clear(); }
            }
            Ok(locally_approved)
        })?;
        if closed_expired {
            *lock(&self.problem) = Some("Expired attempt closed on this computer. Its signed intent remains retained and cannot activate here. The other computer may have recorded approval; this does not remove trust there.".into());
        }
        self.status()
    }
    /// Authenticate a supplied code before exposing the peer as an approval candidate.
    pub async fn preview(self: &Arc<Self>, url: &str) -> Result<ComputerStatus> {
        let link = Link::parse(url)?;
        if lock(&self.computer.state)
            .pair_link
            .as_ref()
            .is_some_and(|l| l.as_str() == url)
        {
            return self.status();
        }
        if link.expires <= now() {
            return Err(Error::Profile(
                "computer pairing code expired; no trust was established",
            ));
        }
        if link.target == self.computer.signer.fingerprint() {
            return Err(Error::Profile(
                "that pairing code belongs to this installation",
            ));
        }
        {
            let s = lock(&self.computer.state);
            // A fresh authenticated invitation can carry a removal this offline computer
            // has not learned yet. The merge below still refuses an already-active target,
            // another group, and every unapproved enrollment.
            if s.genesis.is_none()
                && (s.pair_link.as_ref().is_some_and(|l| l.as_str() != url)
                    || (s.pending.is_some() && s.pair_link.is_none()))
            {
                return Err(Error::Profile(
                    "another computer pairing is pending; cancel it first",
                ));
            }
        }
        // The pairing handshake with the link's computer is this computer's exchange with it
        // for now: the retry leaves it alone meanwhile, and the reservation ends with the
        // handshake however it ends (a drop guard), so the computer never stays in flight.
        let target = link.target;
        // The state this handshake carries, read before the reservation: the state lock is
        // never taken under the in-flight lock (the retry takes them the other way round).
        let revision = lock(&self.computer.state).revision;
        {
            let mut inflight = lock(&self.inflight);
            if inflight.contains_key(&target) {
                return Err(Error::Profile(
                    "an exchange with that computer is in progress; try again in a moment",
                ));
            }
            inflight.insert(
                target,
                Flight {
                    revision,
                    involved: true,
                    abort: None,
                },
            );
        }
        let reserved = Reserved {
            me: Arc::clone(self),
            peer: target,
        };
        // Bounded like any exchange, by the same generous bound: a slow but valid handshake
        // of a long history completes, and a hung one never holds the reservation for good.
        // Run as a task the retry can cut like any exchange: should this node change
        // meanwhile, the handshake carries stale state, the retry supersedes it, and the
        // operator is told to try again (the next tick exchanges the current state).
        let me = Arc::clone(self);
        let (link_owned, url_owned) = (link, url.to_owned());
        let task = tokio::spawn(async move {
            tokio::time::timeout(EXCHANGE_WITHIN, me.pair(&link_owned, &url_owned)).await
        });
        if let Some(flight) = lock(&self.inflight).get_mut(&target) {
            flight.abort = Some(task.abort_handle());
        }
        let paired = match task.await {
            Ok(Ok(paired)) => paired,
            Ok(Err(_)) => Err(Error::Profile(
                "the computer pairing did not finish within ten minutes; try again",
            )),
            Err(_) => {
                lock(&self.superseded).remove(&target);
                Err(Error::Profile(
                    "this computer changed while the pairing ran, so the pairing was \
                     superseded; try again",
                ))
            }
        };
        // Recorded while still reserved, with the state it carried, so the record never
        // touches a reservation the retry may have taken meanwhile; the guard releases this
        // one after.
        let outcome = match &paired {
            // The handshake exchanged state: counted and dated like any exchange, and the
            // status's problem follows from every computer's record.
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        };
        self.record_exchange(target, revision, true, outcome);
        drop(reserved);
        paired?;
        self.status()
    }
    /// Record this operator's signature of exactly the previewed operation; retry is idempotent.
    pub fn approve(&self, operation: &str) -> Result<ComputerStatus> {
        let id = crate::node::link::b32_decode(operation, "computer pairing operation")?;
        let local = self.computer.signer.fingerprint();
        self.computer.change(|s| {
            if s.genesis.as_ref().is_some_and(|g| g.operation() == id)
                || s.history.values().any(|r| {
                    r.event()
                        .ok()
                        .and_then(|e| e.addition)
                        .is_some_and(|a| a.operation() == id)
                })
            {
                return Ok(());
            }
            if s.pending.as_ref().is_some_and(|g| {
                g.operation() == id
                    && side(g, &local)
                        .ok()
                        .is_some_and(|at| g.approvals[at].is_some())
            }) {
                return Ok(());
            }
            if s.pending_expires <= now() {
                return Err(Error::Profile(
                    "computer pairing code expired; no trust was established",
                ));
            }
            let g = s.pending.as_mut().ok_or(Error::Profile(
                "no authenticated computer pairing is awaiting approval",
            ))?;
            if g.operation() != id {
                return Err(Error::Profile(
                    "the displayed computer pairing has changed; review it again",
                ));
            }
            let at = side(g, &local)?;
            if g.approvals[at].is_none() {
                g.approvals[at] = Some(Signed::create(
                    b"vox/computer-genesis/v1\0",
                    g.body(),
                    self.computer.signer.as_ref(),
                )?);
            }
            activate(s, self.computer.signer.as_ref())?;
            Ok(())
        })?;
        self.status()
    }
    /// Explicit source release or destination approval. The destination's ordinary Unlock
    /// supplies the node signature later; no secret or copied fingerprint acts as a transfer.
    pub fn binding_update(
        &self,
        action: &str,
        node: &str,
        destination: &str,
        expected: &str,
    ) -> Result<ComputerStatus> {
        if action == "recover-group" {
            return self.recover_group(expected);
        }
        let node = crate::node::link::fingerprint_input(node, "node fingerprint")?;
        let local = self.computer.signer.fingerprint();
        self.computer.change(|s| {
            if frontier(s) != expected { return Err(Error::Profile("computer trust changed; review the binding operation again")); }
            let group = s.genesis.as_ref().map(Enrollment::incarnation).ok_or(Error::Profile("computer enrollment must finish before changing a management binding"))?;
            if s.grant(&local).is_none() { return Err(Error::Profile("an active computer manager must approve this binding operation")); }
            let bindings: Vec<_> = s.terminal_bindings()?.into_iter().filter(|(manager, binding)|
                binding.verify(manager, &group).ok() == Some(node)).collect();
            if bindings.len() != 1 { return Err(Error::Profile("the node has no unambiguous retained management binding; use a fresh node identity or resolve conflicting managers")); }
            let (manager, binding) = &bindings[0];
            match action {
                "release" => {
                    let destination = crate::node::link::fingerprint_input(destination, "destination computer fingerprint")?;
                    if *manager != local || destination == local || s.grant(&destination).is_none() {
                        return Err(Error::Profile("release requires this node's current manager and another active destination computer"));
                    }
                    let (_, personal, mut roster) = s.rosters.get(&local).ok_or_else(bad)?.read(&local, &group)?;
                    if !roster.iter().any(|b| b.id() == binding.id()) { return Err(Error::Profile("this node was already released")); }
                    let mut body = Encoder::new();
                    body.array(4).bytes(&node).bytes(&binding.id()).bytes(&destination).bytes(&random_array::<32>()?);
                    let release = Control::sign(s, "release", body.finish(), self.computer.signer.as_ref())?;
                    s.retain_roster(release)?;
                    roster.retain(|b| b.id() != binding.id());
                    let personal = personal.filter(|p| *p != node);
                    let update = Control::create(s, &roster, personal, self.computer.signer.as_ref())?;
                    s.retain_roster(update)?;
                    if s.selected == Some(node) { s.selected = None; s.selected_name.clear(); }
                }
                "transfer" | "recover" => {
                    if *manager == local { return Err(Error::Profile("this computer already holds this node's binding")); }
                    let authority = s.derive()?;
                    let proof = if action == "transfer" {
                        let releases: Vec<_> = authority.valid_releases.iter().filter(|id|
                            s.history[*id].event().ok().and_then(|e| e.release).is_some_and(|r|
                                r.previous == binding.id() && r.node == node && r.destination == local)).copied().collect();
                        if releases.len() != 1 { return Err(Error::Profile("no unique effective signed release names this destination; ask the previous manager to release it or explicitly recover after removal")); }
                        releases[0]
                    } else {
                        if s.grant(manager).is_some() { return Err(Error::Profile("recovery requires retained removal or fault evidence for the previous manager; an active manager must release the node")); }
                        [0; 32]
                    };
                    s.binding_approvals.insert(node, BindingApproval { kind: if action == "transfer" { 1 } else { 2 },
                        previous: binding.id(), proof, heads: s.heads() });
                }
                _ => return Err(Error::Profile("unknown computer binding operation")),
            }
            Ok(())
        })?;
        self.status()
    }

    /// Deliberate local abandonment after removal/fault. Retired history remains pinned against
    /// replay. Every old covered grant is journalled for purge before any new group can apply.
    fn recover_group(&self, expected: &str) -> Result<ComputerStatus> {
        let local = self.computer.signer.fingerprint();
        self.computer.change(|s| {
            if frontier(s) != expected {
                return Err(Error::Profile(
                    "computer trust changed; review local recovery again",
                ));
            }
            if s.grant(&local).is_some() {
                return Err(Error::Profile(
                    "remove this computer from the group before abandoning its incarnation",
                ));
            }
            let genesis = s
                .genesis
                .take()
                .ok_or(Error::Profile("there is no established group to retire"))?;
            s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
            for intervals in s.intervals.values_mut() {
                if let Some(interval) = intervals.last_mut().filter(|i| i.retirement.is_none()) {
                    interval.retirement = Some(s.revision);
                }
            }
            s.retired_groups.insert(genesis.incarnation(), genesis);
            s.members.clear();
            s.rosters.clear();
            s.reaches.clear();
            s.quarantined.clear();
            s.receipts.clear();
            s.pending = None;
            s.group_genesis = None;
            s.pair_link = None;
            s.links.clear();
            s.pending_expires = 0;
            s.binding_approvals.clear();
            for invitation in &mut s.invitations {
                invitation.cancelled = true;
            }
            Ok(())
        })?;
        self.status()
    }

    /// Confirm removal against the exact displayed signed frontier and affected roster.
    pub fn remove(&self, target: &str, expected: &str) -> Result<ComputerStatus> {
        let target = crate::node::link::fingerprint_input(target, "computer fingerprint")?;
        self.computer.change(|s| {
            if frontier(s) != expected { return Err(Error::Profile("computer trust changed; review the computer and affected nodes again before removing it")); }
            if s.genesis.is_none() { return Err(Error::Profile("computer enrollment must finish before removing a member")); }
            let mut grants: Vec<_> = s.members.iter().filter_map(|(id, g)|
                (g.computer.fingerprint().ok() == Some(target)).then_some(*id)).collect();
            grants.sort();
            if grants.is_empty() { return Err(Error::Profile("this computer is not an active group member")); }
            let mut body = Encoder::new();
            body.array(3).bytes(&target).array(grants.len());
            for grant in grants { body.bytes(&grant); }
            body.bytes(&s.rosters.get(&target).map(Control::id).unwrap_or([0; 32]));
            let event = Control::sign(s, "remove", body.finish(), self.computer.signer.as_ref())?;
            s.retain_roster(event)?;
            Ok(())
        })?;
        self.status()
    }

    /// Public readback; never treats a timeout or missing receipt as established policy.
    pub fn status(&self) -> Result<ComputerStatus> {
        let s = lock(&self.computer.state);
        let local = self.computer.signer.fingerprint();
        let pairing = s
            .pending
            .as_ref()
            .filter(|g| !enrolled(&s, g))
            .map(|g| -> Result<PairingPreview> {
                let at = side(g, &local)?;
                Ok(PairingPreview {
                    operation_id: text_id(&g.operation()),
                    peer: ComputerIdentity::of(&g.computers[1 - at])?,
                    approved_here: g.approvals[at].is_some(),
                    approved_there: g.approvals[1 - at].is_some(),
                    expires_ms: g.expires,
                })
            })
            .transpose()?;
        let busy = s.pending.as_ref().is_some_and(|g| !enrolled(&s, g));
        let invitation = s
            .invitations
            .iter()
            .rev()
            .find(|i| !busy && !i.cancelled && i.expires > now() && i.target.is_none());
        let invite_link = invitation
            .map(|i| {
                self.net.local_endpoints().map(|endpoints| {
                    Link {
                        target: local,
                        invite: i.id,
                        secret: i.secret.clone(),
                        transport: i.transport.clone(),
                        expires: i.expires,
                        endpoints,
                        anchors: self.anchors.clone(),
                    }
                    .url()
                })
            })
            .transpose()?;
        let mut pending_nodes = lock(&self.pending_nodes).clone();
        for node in s.binding_approvals.keys() {
            pending_nodes.push(format!(
                "{}: binding approved here; unlock its local vault to sign and apply it",
                text_id(node)
            ));
        }
        let storage_failed = self.computer.storage_ready().is_err();
        let descriptions = if s.genesis.is_some() {
            s.descriptions()
        } else {
            BTreeMap::new()
        };
        let exchanged = lock(&self.exchanged).clone();
        let applications: Vec<_> = descriptions
            .iter()
            .map(|(id, d)| {
                let record = exchanged.get(id).cloned().unwrap_or_default();
                Ok(ComputerApplication {
                    computer: ComputerIdentity::of(d)?,
                    confirmed: !storage_failed
                        && s.receipts
                            .get(id)
                            .is_some_and(|r| valid_receipt(&s, id, r).unwrap_or(false)),
                    last_exchange_ms: record.last_ms,
                    exchanges: record.count,
                    exchange_failures: record.failures,
                })
            })
            .collect::<Result<_>>()?;
        let mut nodes = Vec::new();
        let authority = s.derive()?;
        for (manager, roster) in &s.rosters {
            let e = roster.event()?;
            for binding in &e.bindings {
                let id = binding.verify(manager, &e.group)?;
                if authority.binding_owners.get(&id) != Some(&binding.id()) {
                    continue;
                }
                nodes.push(ComputerNode {
                    computer: text_id(manager),
                    fingerprint: text_id(&id),
                    name: binding.name.clone(),
                    personal: e.personal == Some(id),
                });
            }
        }
        let mut binding_actions = Vec::new();
        if s.genesis.is_some() && s.grant(&local).is_some() {
            for (manager, binding) in s.terminal_bindings()? {
                let node = binding.verify(&manager, &s.group().ok_or_else(bad)?)?;
                let released_here = authority.valid_releases.iter().any(|id| {
                    s.history[id]
                        .event()
                        .ok()
                        .and_then(|e| e.release)
                        .is_some_and(|r| r.previous == binding.id() && r.destination == local)
                });
                let action = if manager == local
                    && authority.binding_owners.get(&node) == Some(&binding.id())
                {
                    Some("release")
                } else if manager != local && released_here {
                    Some("transfer")
                } else if manager != local && s.grant(&manager).is_none() {
                    Some("recover")
                } else {
                    None
                };
                if let Some(action) = action {
                    binding_actions.push(ComputerBindingAction {
                        node: text_id(&node),
                        name: binding.name,
                        computer: text_id(&manager),
                        action: action.into(),
                    });
                }
            }
        }
        let mut former = BTreeMap::new();
        if let Some(g) = &s.genesis {
            for description in &g.computers {
                former.insert(description.fingerprint()?, description.clone());
            }
            for record in s.history.values() {
                if let Some(add) = record.event()?.addition {
                    former.insert(add.computers[1].fingerprint()?, add.computers[1].clone());
                }
            }
        }
        former.retain(|id, _| !descriptions.contains_key(id));
        let state = if storage_failed || !s.quarantined.is_empty() {
            "quarantined"
        } else if s.genesis.is_some() && s.grant(&local).is_none() && !busy {
            "removed"
        } else if busy && pairing.as_ref().is_some_and(|p| !p.approved_here) {
            "needs-approval"
        } else if busy || invitation.is_some() {
            "waiting"
        } else if s.genesis.is_some() {
            if !applications.is_empty()
                && applications.iter().all(|a| a.confirmed)
                && pending_nodes.is_empty()
            {
                "confirmed"
            } else {
                "applying"
            }
        } else {
            "individual"
        };
        Ok(ComputerStatus {
            this_computer: ComputerIdentity::of(&s.description)?,
            policy: POLICY.into(),
            state: state.into(),
            invite_link,
            invite_id: invitation.map(|i| text_id(&i.id)),
            invite_expires_ms: invitation.map(|i| i.expires),
            pairing,
            computers: descriptions
                .values()
                .map(ComputerIdentity::of)
                .collect::<Result<_>>()?,
            applications,
            nodes,
            binding_actions,
            removed: former
                .values()
                .map(ComputerIdentity::of)
                .collect::<Result<_>>()?,
            frontier: frontier(&s),
            selected_node: s.selected.as_ref().map(text_id),
            selected_name: s.selected.map(|_| s.selected_name.clone()),
            pending_nodes,
            problem: if storage_failed {
                Some(STORAGE_FAILED.into())
            } else if !s.quarantined.is_empty() {
                Some("Conflicting computer authority is quarantined; retained signed evidence requires operator recovery.".into())
            } else {
                lock(&self.problem).clone()
            },
        })
    }
    /// Report outstanding current-node application, never claiming success for detached vaults.
    pub fn pending_nodes(&self, nodes: Vec<String>) {
        *lock(&self.pending_nodes) = nodes;
    }
    fn transport_leases(&self, supplied: Option<&Link>) -> Result<Vec<TransportLease>> {
        let s = lock(&self.computer.state);
        let local = s.description.fingerprint()?;
        let mut leases = Vec::new();
        if let (Some(group), Some(here)) = (s.group(), s.reaches.get(&local)) {
            for (peer, there) in &s.reaches {
                if *peer == local
                    || s.grant(peer).is_none()
                    || s.grant(&local).is_none()
                    || s.quarantined.contains(peer)
                {
                    continue;
                }
                let (first, second, t1, t2) = if local < *peer {
                    (local, *peer, here.token, there.token)
                } else {
                    (*peer, local, there.token, here.token)
                };
                let registration =
                    sha256_concat(&[b"vox/computer-transport-pair/v1\0", &group, &first, &second]);
                let token = Zeroizing::new(sha256_concat(&[
                    b"vox/computer-transport-capability/v1\0",
                    &group,
                    &first,
                    &second,
                    &t1,
                    &t2,
                ]));
                let mut anchors = here.anchors.clone();
                for a in there.anchors.nodes() {
                    anchors.add(a.clone())?;
                }
                leases.push(TransportLease {
                    registration,
                    token,
                    expires: now()
                        .saturating_add(crate::nat::service::COMPUTER_TRANSPORT_TTL_MS / 2),
                    peer: Some(*peer),
                    anchors,
                });
            }
        }
        let mut links: Vec<_> = s
            .links
            .iter()
            .chain(s.pair_link.iter())
            .map(|l| Link::parse(l))
            .collect::<Result<_>>()?;
        if let Some(l) = supplied {
            links.push(Link::parse(&l.url())?);
        }
        for link in links {
            if leases.iter().any(|l| l.peer == Some(link.target)) {
                continue;
            }
            let established = s.grant(&link.target).is_some() && s.genesis.is_some();
            if !established && link.expires <= now() {
                continue;
            }
            let mut anchors = self.anchors.clone();
            for a in link.anchors.nodes() {
                anchors.add(a.clone())?;
            }
            leases.push(TransportLease {
                registration: link.invite,
                token: link.transport,
                expires: if established {
                    now().saturating_add(crate::nat::service::COMPUTER_TRANSPORT_TTL_MS / 2)
                } else {
                    link.expires
                },
                peer: Some(link.target),
                anchors,
            });
        }
        for i in &s.invitations {
            if i.cancelled
                || i.target
                    .is_some_and(|p| leases.iter().any(|l| l.peer == Some(p)))
            {
                continue;
            }
            let established =
                i.target.is_some_and(|p| s.grant(&p).is_some()) && s.genesis.is_some();
            if !established && i.expires <= now() {
                continue;
            }
            leases.push(TransportLease {
                registration: i.id,
                token: i.transport.clone(),
                expires: if established {
                    now().saturating_add(crate::nat::service::COMPUTER_TRANSPORT_TTL_MS / 2)
                } else {
                    i.expires
                },
                peer: i.target,
                anchors: self.anchors.clone(),
            });
        }
        Ok(leases)
    }
    fn configure_transport_anchors(&self, anchors: &BootstrapSet) {
        let mut policy = self.net.policy().snapshot();
        for a in anchors.nodes() {
            policy.add_anchor(a.id);
        }
        self.net.policy().replace(policy);
    }

    async fn transport_at(
        self: &Arc<Self>,
        anchor: crate::nat::bootstrap::BootstrapNode,
        lease: TransportLease,
        redeem: bool,
    ) -> Result<Arc<VoxConnection>> {
        let conn = self
            .net
            .manager()
            .connect(anchor.id, &anchor.endpoints)
            .await?;
        self.serve(Arc::clone(&conn));
        let cached = lock(&self.transport_cache)
            .get(&(anchor.id, lease.registration))
            .copied();
        if cached.is_none_or(|old| {
            old.connection != conn.serial()
                || old.expires <= now().saturating_add(60_000)
                || old.peer != lease.peer
        }) {
            self.net
                .register_computer_transport(
                    &conn,
                    lease.registration,
                    &lease.token,
                    lease.expires,
                    lease.peer,
                )
                .await?;
            lock(&self.transport_cache).insert(
                (anchor.id, lease.registration),
                RegisteredLease {
                    connection: conn.serial(),
                    expires: lease.expires,
                    peer: lease.peer,
                },
            );
        }
        if redeem {
            if let Some(peer) = lease.peer {
                let until = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    match self
                        .net
                        .redeem_computer_transport(&conn, peer, lease.registration, &lease.token)
                        .await
                    {
                        Ok(()) => break,
                        Err(Error::RendezvousRejected(_))
                            if tokio::time::Instant::now() < until =>
                        {
                            tokio::time::sleep(Duration::from_millis(200)).await
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        Ok(conn)
    }

    async fn refresh_transport(self: &Arc<Self>) -> Result<()> {
        let mut work = tokio::task::JoinSet::new();
        for lease in self.transport_leases(None)? {
            self.configure_transport_anchors(&lease.anchors);
            for anchor in lease.anchors.nodes() {
                let me = Arc::clone(self);
                let anchor = anchor.clone();
                let lease = lease.clone();
                work.spawn(async move { me.transport_at(anchor, lease, true).await.map(|_| ()) });
            }
        }
        // Cancellation remains retryable after either daemon or anchor restarts. These are
        // retained tombstones in the same management state, not another credential store.
        let revoked = {
            let s = lock(&self.computer.state);
            let mut revoked: Vec<_> = s
                .invitations
                .iter()
                .filter(|i| i.cancelled && i.expires > now())
                .map(|i| (i.id, self.anchors.clone()))
                .collect();
            for url in &s.cancelled_links {
                let link = Link::parse(url)?;
                if link.expires <= now() {
                    continue;
                }
                let mut anchors = self.anchors.clone();
                for a in link.anchors.nodes() {
                    anchors.add(a.clone())?;
                }
                revoked.push((link.invite, anchors));
            }
            revoked
        };
        for (registration, anchors) in revoked {
            self.configure_transport_anchors(&anchors);
            for anchor in anchors.nodes() {
                let me = Arc::clone(self);
                let anchor = anchor.clone();
                work.spawn(async move {
                    let conn = me
                        .net
                        .manager()
                        .connect(anchor.id, &anchor.endpoints)
                        .await?;
                    me.serve(Arc::clone(&conn));
                    let key = (anchor.id, registration, conn.serial());
                    if !lock(&me.revoked_transport).contains(&key) {
                        me.net
                            .revoke_computer_transport(&conn, registration)
                            .await?;
                        lock(&me.revoked_transport).insert(key);
                    }
                    Ok(())
                });
            }
        }
        while work.join_next().await.is_some() {}
        Ok(())
    }

    async fn transport_incoming(
        self: &Arc<Self>,
        conn: &Arc<VoxConnection>,
        kind: StreamKind,
        send: SendStream,
        recv: RecvStream,
    ) -> Result<()> {
        let mut origins = Vec::new();
        for lease in self.transport_leases(None)? {
            if lease.anchors.get(&conn.peer_id()).is_none() {
                continue;
            }
            if let Some(peer) = lease.peer {
                origins.push(peer);
            }
            if let Some(peer) = self
                .net
                .computer_transport_peer(conn, lease.registration)
                .await?
            {
                if lease.peer.is_none_or(|expected| expected == peer) {
                    origins.push(peer);
                }
            }
        }
        origins.sort();
        origins.dedup();
        let result = self
            .net
            .dispatch_computer_transport(conn, kind, send, recv, &origins)
            .await?;
        if let crate::node::network::Inbound::Punch {
            peer,
            coordinator,
            send,
            recv,
        } = result
        {
            let reached = self.net.answer_punch(peer, coordinator, send, recv).await?;
            self.serve(reached);
        }
        Ok(())
    }

    async fn connect(
        self: &Arc<Self>,
        target: Digest32,
        endpoints: &EndpointList,
        supplied: Option<&Link>,
    ) -> Result<Arc<VoxConnection>> {
        if let Some(conn) = self.net.manager().existing(&target) {
            return Ok(conn);
        }
        // The direct dial starts immediately. Anchor registration is a separate raced path and
        // neither its absence nor its refusal can delay or fail a directly reachable computer.
        let direct = self.net.manager().connect(target, endpoints);
        let relay = async {
            let lease = self
                .transport_leases(supplied)?
                .into_iter()
                .find(|l| l.peer == Some(target))
                .ok_or(Error::Unreachable(
                    "no current computer transport invitation or enrolled pair",
                ))?;
            self.configure_transport_anchors(&lease.anchors);
            let mut attempts = tokio::task::JoinSet::new();
            for anchor in lease.anchors.nodes() {
                let me = Arc::clone(self);
                let anchor = anchor.clone();
                let lease = lease.clone();
                attempts.spawn(async move {
                    // This transport lease authorizes its anchor for this computer reach only;
                    // it is neither a room source nor a machine-wide manual anchor.
                    let helpers = crate::node::network::HelperContext {
                        extra_helpers: [anchor.id].into_iter().collect(),
                        ..crate::node::network::HelperContext::default()
                    };
                    me.transport_at(anchor, lease, true).await?;
                    me.net
                        .reach(target, &EndpointList::default(), &helpers)
                        .await
                });
            }
            let mut last = Error::Unreachable("no anchor configured for this computer pairing");
            while let Some(result) = attempts.join_next().await {
                match result {
                    Ok(Ok(conn)) => return Ok(conn),
                    Ok(Err(e)) => last = e,
                    Err(_) => {}
                }
            }
            Err(last)
        };
        tokio::pin!(direct, relay);
        let result = tokio::select! {
            d = &mut direct => match d { Ok(c) => Ok(c), Err(d) => relay.await.map_err(|r| Error::Handshake(format!("direct: {d}; computer relay: {r}"))) },
            r = &mut relay => match r { Ok(c) => Ok(c), Err(r) => direct.await.map_err(|d| Error::Handshake(format!("direct: {d}; computer relay: {r}"))) },
        };
        let conn = result.map_err(|e| {
            Error::Handshake(format!(
                "computer could not be reached; the pairing code was not checked: {e}"
            ))
        })?;
        self.serve(Arc::clone(&conn));
        Ok(conn)
    }
    async fn pair(self: &Arc<Self>, link: &Link, url: &str) -> Result<()> {
        let conn = self
            .connect(link.target, &link.endpoints, Some(link))
            .await?;
        let (mut send, mut recv) = streams::open_typed(&conn, StreamKind::Computer).await?;
        write_frame(
            &mut send,
            &hello(1, &self.computer.description(), &link.invite),
        )
        .await?;
        let (_, peer, _) = read_hello(&mut recv, &conn).await?;
        let f = frame(&mut recv).await?;
        let mut d = Decoder::new(&f);
        arity(&mut d, 3)?;
        let sid = d.bytes()?.to_vec();
        if sid.len() != 16 {
            return Err(bad());
        }
        let mut g = Enrollment::decode(d.bytes()?)?;
        let remote_share: [u8; 32] = d.bytes()?.try_into().map_err(|_| bad())?;
        d.finish()?;
        if g.expires != link.expires
            || g.computers[0] != peer
            || g.computers[1] != self.computer.description()
            || g.approvals.iter().any(Option::is_some)
        {
            return Err(bad());
        }
        let ci = context(&link.invite, &link.transport, &g);
        let (state, share) = cpace::CpaceState::start_with_context(
            link.secret.as_ref(),
            &ci,
            conn.session().suite_id,
            &sid,
        )?;
        let isk = state.finish(&remote_share)?;
        let transcript = pop::transcript_hash(
            &[ci.as_slice(), &sid].concat(),
            isk.as_ref(),
            &share,
            &remote_share,
        );
        let proof = pop::IdentityProof::create(self.computer.signer.as_ref(), &ci, &transcript)?;
        let mut e = Encoder::new();
        e.array(2)
            .bytes(&share)
            .bytes(&pop::seal_pop(isk.as_ref(), &proof)?);
        write_frame(&mut send, &e.finish()).await?;
        let f = frame(&mut recv).await?;
        let mut d = Decoder::new(&f);
        arity(&mut d, 2)?;
        let proof = pop::open_pop(isk.as_ref(), d.bytes()?)?;
        pop::verify(&proof, &ci, &transcript, &link.target)?;
        let exchange = d.bytes()?.to_vec();
        d.finish()?;
        self.computer.change(|s| {
            if s.pending
                .as_ref()
                .is_some_and(|p| !enrolled(s, p) && p.body() != g.body())
            {
                return Err(Error::Profile(
                    "the pairing identity or policy changed; no approval was reused",
                ));
            }
            if let Some(p) = &s.pending {
                if p.body() == g.body() {
                    g.approvals = p.approvals.clone();
                }
            }
            s.pending = Some(g);
            s.pending_expires = link.expires;
            s.pair_link = Some(Zeroizing::new(url.to_owned()));
            merge(s, &exchange, link.target, self.computer.signer.as_ref())?;
            Ok(())
        })?;
        let _ = send.finish();
        Ok(())
    }
    async fn answer(
        &self,
        conn: &VoxConnection,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        let (op, peer, id) = read_hello(recv, conn).await?;
        write_frame(send, &hello(op, &self.computer.description(), &id)).await?;
        if op == 2 {
            let payload = frame(recv).await?;
            self.computer
                .change(|s| merge(s, &payload, conn.peer_id(), self.computer.signer.as_ref()))?;
            let payload = exchange(&lock(&self.computer.state))?;
            write_frame(send, &payload).await?;
            return Ok(());
        }
        if op != 1 {
            return Err(bad());
        }
        let (invite, mut g) = {
            let s = lock(&self.computer.state);
            let i=s.invitations.iter().find(|i|i.id==id&&!i.cancelled&&i.expires>now()).ok_or(Error::Profile("computer pairing code expired, cancelled, or unknown; no new trust was established"))?;
            if i.target.is_some_and(|t| t != conn.peer_id()) {
                return Err(Error::Profile(
                    "computer pairing code was already consumed by another identity",
                ));
            }
            let g = Enrollment {
                group: s.genesis.as_ref().map(Enrollment::incarnation),
                expires: i.expires,
                nonce: i.nonce,
                computers: [s.description.clone(), peer],
                grants: [
                    s.grant(&self.computer.signer.fingerprint())
                        .unwrap_or(i.grants[0]),
                    i.grants[1],
                ],
                approvals: [None, None],
            };
            if s.pending
                .as_ref()
                .is_some_and(|p| p.body() != g.body() && !enrolled(&s, p))
            {
                return Err(Error::Profile(
                    "another computer enrollment is already recorded",
                ));
            }
            (i.clone(), g)
        };
        let sid = cpace::fresh_sid()?;
        let ci = context(&id, &invite.transport, &g);
        let (state, share) = cpace::CpaceState::start_with_context(
            invite.secret.as_ref(),
            &ci,
            conn.session().suite_id,
            &sid,
        )?;
        let mut e = Encoder::new();
        e.array(3).bytes(&sid).bytes(&g.encode()).bytes(&share);
        write_frame(send, &e.finish()).await?;
        let f = frame(recv).await?;
        let mut d = Decoder::new(&f);
        arity(&mut d, 2)?;
        let remote_share: [u8; 32] = d.bytes()?.try_into().map_err(|_| bad())?;
        let sealed = d.bytes()?;
        d.finish()?;
        let isk = state.finish(&remote_share)?;
        let transcript = pop::transcript_hash(
            &[ci.as_slice(), &sid].concat(),
            isk.as_ref(),
            &share,
            &remote_share,
        );
        let proof = pop::open_pop(isk.as_ref(), sealed)?;
        pop::verify(&proof, &ci, &transcript, &conn.peer_id())?;
        self.computer.change(|s| {
            let i = s
                .invitations
                .iter_mut()
                .find(|i| i.id == id && !i.cancelled && i.expires > now())
                .ok_or(Error::Profile(
                    "computer pairing code expired or was cancelled",
                ))?;
            if i.target.is_some_and(|t| t != conn.peer_id()) {
                return Err(Error::Profile("computer pairing code was already consumed"));
            }
            if s.pending.as_ref().is_some_and(|p| p.body() != g.body()) {
                return Err(Error::Profile("another enrollment is already recorded"));
            }
            i.target = Some(conn.peer_id());
            if let Some(p) = s.pending.as_ref() {
                g.approvals = p.approvals.clone();
            }
            s.pending = Some(g);
            s.pending_expires = invite.expires;
            Ok(())
        })?;
        let proof = pop::IdentityProof::create(self.computer.signer.as_ref(), &ci, &transcript)?;
        let payload = exchange(&lock(&self.computer.state))?;
        let mut e = Encoder::new();
        e.array(2)
            .bytes(&pop::seal_pop(isk.as_ref(), &proof)?)
            .bytes(&payload);
        write_frame(send, &e.finish()).await?;
        Ok(())
    }
    async fn retry(self: &Arc<Self>) -> Result<()> {
        let (peers, attempted, revision) = {
            let s = lock(&self.computer.state);
            let local = self.computer.signer.fingerprint();
            let mut peers: std::collections::BTreeSet<_> = s
                .descriptions()
                .into_keys()
                .filter(|p| *p != local)
                .collect();
            if let Some(g) = &s.pending {
                peers.insert(g.computers[1 - side(g, &local)?].fingerprint()?);
            }
            // A computer needs an exchange when it has not acknowledged this node's current
            // state (it holds no valid receipt for this node's incarnation, rosters and heads;
            // each side counts its own revision, so the numbers are never compared), when a
            // pending operation involves it, or when the fallback interval passed; a computer
            // that could not be reached waits out its backoff. Measured before this (2026-10-20): every computer
            // was exchanged with every 2 s, the whole signed history sent and re-verified each
            // time, 47–95% of a core on the decider's daemon while nothing changed.
            // A pairing stays recorded as `pending` after it completes (its intent is part of
            // every exchange), so the other computer counts as involved only while the
            // operation is open: an approval is missing, or it has not activated here yet.
            let involved: Option<Digest32> = s
                .pending
                .as_ref()
                .filter(|g| {
                    g.approvals.iter().any(Option::is_none)
                        || (g.group.is_none() && s.genesis.is_none())
                        || (g.group.is_some() && !enrolled(&s, g))
                })
                .and_then(|g| {
                    side(g, &local)
                        .ok()
                        .map(|i| g.computers[1 - i].fingerprint().ok())
                })
                .flatten();
            let now = std::time::Instant::now();
            let revision = s.revision;
            let mut exchanged = lock(&self.exchanged);
            // A computer no longer paired (removed, or its pairing cancelled) keeps no record:
            // its failure must not stand in the status for good.
            let known: std::collections::BTreeSet<Digest32> = peers.iter().copied().collect();
            if exchanged.keys().any(|p| !known.contains(p)) {
                exchanged.retain(|p, _| known.contains(p));
                *lock(&self.problem) = exchanged
                    .values()
                    .filter(|r| r.failures > 0)
                    .find_map(|r| r.problem.clone());
            }
            peers.retain(|peer| {
                let record = exchanged.get(peer).cloned().unwrap_or_default();
                if let Some(last) = record.last {
                    if record.failures > 0 {
                        // 2 s after the first failure, doubling, at most EXCHANGE_BACKOFF_MAX;
                        // unless this node changed since that attempt, which is tried at once.
                        let wait = EXCHANGE_BACKOFF
                            .saturating_mul(1u32 << (record.failures - 1).min(6))
                            .min(EXCHANGE_BACKOFF_MAX);
                        let unchanged = record.revision == revision
                            && record.involved == (involved == Some(*peer));
                        if unchanged && now.duration_since(last) < wait {
                            return false;
                        }
                    } else {
                        let acknowledged = s
                            .receipts
                            .get(peer)
                            .is_some_and(|r| valid_receipt(&s, peer, r).unwrap_or(false));
                        if acknowledged
                            && involved != Some(*peer)
                            && now.duration_since(last) < EXCHANGE_FALLBACK
                        {
                            return false;
                        }
                    }
                }
                true
            });
            drop(exchanged);
            // Reserved under one lock, after every other filter: a computer already in
            // flight (with the retry or with the operator's pairing) is left alone, and no
            // two exchanges with one computer ever overlap. An exchange in flight that
            // carries state this node has since changed is cut: its payload is stale, its end
            // counts as no failure, and the next tick exchanges the current state.
            {
                let mut inflight = lock(&self.inflight);
                let mut superseded = lock(&self.superseded);
                for (peer, flight) in inflight.iter() {
                    let stale =
                        flight.revision != revision || flight.involved != (involved == Some(*peer));
                    if stale && !superseded.contains(peer) {
                        if let Some(abort) = &flight.abort {
                            superseded.insert(*peer);
                            abort.abort();
                        }
                    }
                }
                peers.retain(|peer| {
                    if inflight.contains_key(peer) {
                        return false;
                    }
                    inflight.insert(
                        *peer,
                        Flight {
                            revision,
                            involved: involved == Some(*peer),
                            abort: None,
                        },
                    );
                    true
                });
            }
            let attempted: Vec<(Digest32, bool)> =
                peers.iter().map(|p| (*p, involved == Some(*p))).collect();
            let peers = peers
                .into_iter()
                .map(|peer| {
                    let endpoints = s
                        .reaches
                        .get(&peer)
                        .map(|r| r.endpoints.clone())
                        .unwrap_or_default();
                    let url = s
                        .pair_link
                        .as_ref()
                        .filter(|l| Link::parse(l).ok().is_some_and(|l| l.target == peer))
                        .cloned()
                        .or_else(|| {
                            s.links
                                .iter()
                                .find(|l| Link::parse(l).ok().is_some_and(|l| l.target == peer))
                                .cloned()
                        });
                    (peer, endpoints, url)
                })
                .collect::<Vec<_>>();
            (peers, attempted, revision)
        };
        for (peer, endpoints, url) in peers {
            let me = Arc::clone(self);
            let involved = attempted
                .iter()
                .any(|(p, involved)| *p == peer && *involved);
            let task = tokio::spawn(async move {
                // Each computer's outcome is recorded by its own task the moment it ends,
                // dated then: a slow computer never delays another's record, status or next
                // attempt, and one that hangs counts as failed after EXCHANGE_WITHIN.
                let guard = Attempt {
                    me: Arc::clone(&me),
                    peer,
                    revision,
                    involved,
                    recorded: false,
                };
                let outcome =
                    match tokio::time::timeout(EXCHANGE_WITHIN, me.sync_peer(peer, endpoints, url))
                        .await
                    {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(e.to_string()),
                        Err(_) => Err(format!(
                            "the exchange did not finish within {EXCHANGE_WITHIN:?}"
                        )),
                    };
                guard.done(outcome);
            });
            if let Some(flight) = lock(&self.inflight).get_mut(&peer) {
                flight.abort = Some(task.abort_handle());
            }
        }
        Ok(())
    }
    /// Record one attempt's outcome for `peer`, now: `last` paces the next attempt whether it
    /// succeeded or not; `last_ms`, what a person reads as the last exchange, is set only by a
    /// completed one. The status's problem is then the words of a computer still failing, or
    /// none: it never clears while a failure stands, and never stands once every computer is
    /// exchanged with again.
    fn record_exchange(
        &self,
        peer: Digest32,
        revision: u64,
        involved: bool,
        outcome: std::result::Result<(), String>,
    ) {
        let mut exchanged = lock(&self.exchanged);
        let record = exchanged.entry(peer).or_default();
        record.last = Some(std::time::Instant::now());
        record.revision = revision;
        record.involved = involved;
        match outcome {
            Ok(()) => {
                record.last_ms = Some(now());
                record.count = record.count.saturating_add(1);
                record.failures = 0;
                record.problem = None;
            }
            Err(text) => {
                record.failures = record.failures.saturating_add(1);
                record.problem = Some(text);
            }
        }
        *lock(&self.problem) = exchanged
            .values()
            .filter(|r| r.failures > 0)
            .find_map(|r| r.problem.clone());
    }
    async fn sync_peer(
        self: &Arc<Self>,
        peer: Digest32,
        endpoints: EndpointList,
        url: Option<Zeroizing<String>>,
    ) -> Result<()> {
        let link = url.as_ref().map(|l| Link::parse(l)).transpose()?;
        let endpoints = link.as_ref().map(|l| &l.endpoints).unwrap_or(&endpoints);
        let conn = self.connect(peer, endpoints, link.as_ref()).await?;
        self.serve(Arc::clone(&conn));
        let payload = exchange(&lock(&self.computer.state))?;
        let (mut send, mut recv) = streams::open_typed(&conn, StreamKind::Computer).await?;
        write_frame(&mut send, &hello(2, &self.computer.description(), &[0; 32])).await?;
        let (op, _, _) = read_hello(&mut recv, &conn).await?;
        if op != 2 {
            return Err(bad());
        }
        write_frame(&mut send, &payload).await?;
        let f = frame(&mut recv).await?;
        self.computer
            .change(|s| merge(s, &f, peer, self.computer.signer.as_ref()))?;
        let _ = send.finish();
        Ok(())
    }
}
fn side(g: &Enrollment, id: &Digest32) -> Result<usize> {
    g.computers
        .iter()
        .position(|d| d.fingerprint().ok() == Some(*id))
        .ok_or(Error::SignatureInvalid)
}
fn context(invite: &Digest32, transport: &Digest32, g: &Enrollment) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .bytes(invite)
        .bytes(&sha256(transport))
        .bytes(&g.body())
        .uint(u64::from(crate::suite::VOX_SUITE_1.id))
        .uint(PROTOCOL);
    [PAIR_DOMAIN, &sha256(&e.finish())].concat()
}
fn hello(op: u64, d: &Description, id: &Digest32) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(PROTOCOL)
        .uint(u64::from(crate::suite::VOX_SUITE_1.id))
        .uint(op)
        .bytes(&d.encode())
        .bytes(id);
    e.finish()
}
async fn read_hello(
    recv: &mut RecvStream,
    conn: &VoxConnection,
) -> Result<(u64, Description, Digest32)> {
    let f = frame(recv).await?;
    let mut d = Decoder::new(&f);
    arity(&mut d, 5)?;
    if d.uint()? != PROTOCOL || d.uint()? != u64::from(conn.session().suite_id) {
        return Err(Error::Profile(
            "computer management protocol or suite is unsupported",
        ));
    }
    let op = d.uint()?;
    let desc = Description::decode(d.bytes()?)?;
    let id = digest(&mut d)?;
    d.finish()?;
    if desc.fingerprint()? != conn.peer_id() {
        return Err(Error::SignatureInvalid);
    }
    Ok((op, desc, id))
}
async fn frame(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let f = read_frame_within(recv, MAX_FRAME, PATIENCE)
        .await?
        .ok_or(Error::Profile(
            "computer pairing peer closed before answering",
        ))?;
    let mut d = Decoder::new(&f);
    if d.array().ok() == Some(2) && d.uint().ok() == Some(0) {
        let message = d.text()?.to_owned();
        d.finish()?;
        return Err(Error::Handshake(crate::transport::quic::peer_text(
            &message,
        )));
    }
    Ok(f)
}
fn enrolled(s: &State, g: &Enrollment) -> bool {
    if g.group.is_none() {
        s.genesis
            .as_ref()
            .is_some_and(|v| v.operation() == g.operation())
    } else {
        s.history.values().any(|r| {
            r.event()
                .ok()
                .and_then(|e| e.addition)
                .is_some_and(|a| a.operation() == g.operation())
        })
    }
}
fn activate(s: &mut State, signer: &dyn RootSigner) -> Result<()> {
    let Some(g) = s.pending.clone() else {
        return Ok(());
    };
    if s.cancelled.contains_key(&g.operation()) {
        return Err(Error::Profile(
            "this enrollment attempt was closed locally; its retained intent cannot activate",
        ));
    }
    if g.approvals.iter().any(Option::is_none) {
        return Ok(());
    }
    g.verify(true)?;
    if g.group.is_none() {
        if s.genesis.is_none() {
            s.genesis = Some(g);
            s.fold_history()?;
            s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
            s.receipts.clear();
        }
    } else {
        if !enrolled(s, &g) && signer.fingerprint() == g.computers[0].fingerprint()? {
            let mut body = Encoder::new();
            body.array(1).bytes(&g.encode());
            let event = Control::sign(s, "add", body.finish(), signer)?;
            s.retain_roster(event)?;
        }
        if enrolled(s, &g) && s.genesis.is_none() {
            s.genesis = s.group_genesis.take();
            if s.genesis.is_none() {
                return Err(bad());
            }
            s.fold_history()?;
            s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
            s.receipts.clear();
        }
    }
    Ok(())
}
fn exchange(s: &State) -> Result<Vec<u8>> {
    let group = s
        .group()
        .ok_or(Error::Profile("no computer pairing intent"))?;
    let mut e = Encoder::new();
    e.array(4)
        .bytes(
            &s.genesis
                .as_ref()
                .or(s.group_genesis.as_ref())
                .map(Enrollment::encode)
                .unwrap_or_default(),
        )
        .bytes(
            &s.pending
                .as_ref()
                .map(Enrollment::encode)
                .unwrap_or_default(),
        );
    let current: Vec<_> = s
        .history
        .iter()
        .filter(|(_, r)| r.event().ok().is_some_and(|v| v.group == group))
        .collect();
    e.array(current.len());
    for (id, r) in current {
        e.array(2).bytes(id).bytes(&r.signed.encode());
    }
    e.array(s.receipts.len());
    for (id, r) in &s.receipts {
        e.array(2).bytes(id).bytes(&r.encode());
    }
    Ok(e.finish())
}
fn merge(s: &mut State, bytes: &[u8], peer: Digest32, signer: &dyn RootSigner) -> Result<()> {
    let mut d = Decoder::new(bytes);
    arity(&mut d, 4)?;
    let read = |bytes: &[u8]| -> Result<Option<Enrollment>> {
        if bytes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Enrollment::decode(bytes)?))
        }
    };
    let genesis = read(d.bytes()?)?;
    let incoming = read(d.bytes()?)?;
    if genesis
        .iter()
        .chain(incoming.iter())
        .any(|g| s.retired_groups.contains_key(&g.incarnation()))
    {
        return Err(Error::Profile(
            "this group was retired locally; old signed state cannot reactivate it",
        ));
    }
    // A fresh invitation has no current intent to compare with. Recognize an exact retired
    // operation before the group/current-intent checks so its late result keeps the truthful
    // local-close outcome instead of turning into an unexplained authentication refusal.
    if genesis
        .iter()
        .chain(incoming.iter())
        .any(|g| s.cancelled.contains_key(&g.operation()))
    {
        return Err(Error::Profile(
            "this enrollment attempt was closed locally; its retained intent cannot activate",
        ));
    }
    let local = s.description.fingerprint()?;
    let candidate = s.pending.as_ref().is_some_and(|p| side(p, &peer).is_ok());
    // Former managers may carry retained negative/fork evidence and receive their removal.
    // This grants no positive authority: every event is independently checked at its prefix.
    let previously_enrolled = s.was_enrolled(&peer);
    if let Some(g) = genesis {
        g.verify(true)?;
        if g.group.is_some() || Some(g.incarnation()) != s.group() {
            return Err(Error::SignatureInvalid);
        }
        if let Some(current) = &s.genesis {
            if current != &g {
                return Err(Error::SignatureInvalid);
            }
        } else if s
            .pending
            .as_ref()
            .is_some_and(|p| p.group == Some(g.incarnation()))
        {
            s.group_genesis = Some(g);
        }
    }
    if let (Some(current), Some(incoming)) = (s.pending.clone(), incoming) {
        if incoming.operation() == current.operation() {
            if s.cancelled.contains_key(&incoming.operation()) {
                return Err(Error::Profile("this enrollment attempt was closed locally"));
            }
            let at = side(&current, &peer)?;
            let here = side(&current, &local)?;
            let mut g = current;
            if let Some(a) = &incoming.approvals[at] {
                if g.approvals[at].is_none() && g.expires <= now() {
                    return Err(Error::Profile("computer pairing expired before approval arrived; no new trust was established"));
                }
                g.approvals[at] = Some(a.clone());
            }
            if incoming.approvals[here].is_some() && incoming.approvals[here] != g.approvals[here] {
                return Err(Error::SignatureInvalid);
            }
            g.verify(false)?;
            s.pending = Some(g);
        }
    }
    // Union first, then fold once: wire order is not causal order.
    let group = s.group().ok_or_else(bad)?;
    let previous_len = s.history.len();
    let previous_revision = s.revision;
    for _ in 0..count(&mut d)? {
        arity(&mut d, 2)?;
        let id = digest(&mut d)?;
        let r = Control {
            signed: Signed::decode(d.bytes()?)?,
        };
        if id != r.id() {
            return Err(bad());
        }
        r.verify(&group)?;
        if !s.history.contains_key(&id) && s.history.len() >= MAX_RECORDS {
            return Err(Error::Profile(if previously_enrolled {
                HISTORY_FULL
            } else {
                "incoming computer history exceeds admission limit"
            }));
        }
        s.history.insert(id, r);
    }
    s.fold_history()?;
    if s.history.len() != previous_len && s.revision == previous_revision {
        s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
        s.receipts.clear();
    }
    if s.grant(&peer).is_none() && !candidate && !previously_enrolled {
        return Err(Error::SignatureInvalid);
    }
    // An unrelated active member may carry another member's signed receipt verbatim.
    let mut receipts = Vec::new();
    for _ in 0..count(&mut d)? {
        arity(&mut d, 2)?;
        receipts.push((digest(&mut d)?, Signed::decode(d.bytes()?)?));
    }
    d.finish()?;
    activate(s, signer)?;
    for (author, receipt) in receipts {
        if author != local && valid_receipt(s, &author, &receipt)? {
            s.receipts.insert(author, receipt);
        }
    }
    // Receiving the retained genesis is not enrollment: require the local operator's exact ADD.
    if let Some(p) = &s.pending {
        if p.group.is_some() && p.approvals[side(p, &local)?].is_none() && s.grant(&local).is_some()
        {
            return Err(Error::SignatureInvalid);
        }
    }
    Ok(())
}

fn receipt_body(s: &State, revision: u64) -> Result<Vec<u8>> {
    let g = s
        .genesis
        .as_ref()
        .ok_or(Error::Profile("computer enrollment is not established"))?;
    let mut e = Encoder::new();
    e.array(7)
        .uint(PROTOCOL)
        .bytes(&g.incarnation())
        .bytes(&sha256(&g.encode()))
        .array(s.rosters.len());
    for (id, r) in &s.rosters {
        e.array(2).bytes(id).bytes(&sha256(&r.signed.encode()));
    }
    let heads = s.heads();
    e.array(heads.len());
    for h in heads {
        e.bytes(&h);
    }
    e.uint(revision).array(0);
    Ok(e.finish())
}
fn valid_receipt(s: &State, author: &Digest32, r: &Signed) -> Result<bool> {
    r.verify(b"vox/computer-applied/v1\0", author)?;
    if !s.history_complete() || !s.quarantined.is_empty() {
        return Ok(false);
    }
    let Some(g) = s.genesis.as_ref() else {
        return Ok(false);
    };
    if s.grant(author).is_none() {
        return Ok(false);
    }
    let mut d = Decoder::new(&r.body);
    arity(&mut d, 7)?;
    if d.uint()? != PROTOCOL
        || digest(&mut d)? != g.incarnation()
        || digest(&mut d)? != sha256(&g.encode())
    {
        return Ok(false);
    }
    let n = count(&mut d)?;
    if n != s.rosters.len() || n != s.descriptions().len() {
        return Ok(false);
    }
    for (id, roster) in &s.rosters {
        arity(&mut d, 2)?;
        if digest(&mut d)? != *id || digest(&mut d)? != sha256(&roster.signed.encode()) {
            return Ok(false);
        }
    }
    let heads = s.heads();
    if count(&mut d)? != heads.len() {
        return Ok(false);
    }
    for head in heads {
        if digest(&mut d)? != head {
            return Ok(false);
        }
    }
    let revision = d.uint()?;
    if revision == 0 {
        return Err(bad());
    }
    if d.array()? != 0 {
        return Ok(false);
    }
    d.finish()?;
    Ok(true)
}

fn frontier(s: &State) -> String {
    let mut e = Encoder::new();
    e.array(2)
        .bytes(&s.group().unwrap_or([0; 32]))
        .array(s.heads().len());
    for head in s.heads() {
        e.bytes(&head);
    }
    text_id(&sha256(&e.finish()))
}
