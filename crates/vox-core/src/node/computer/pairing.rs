//! The bounded two-computer ceremony on the daemon's existing authenticated QUIC presence.
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
    exchanges: tokio::sync::Mutex<()>,
    slots: Arc<tokio::sync::Semaphore>,
    problem: Mutex<Option<String>>,
    pending_nodes: Mutex<Vec<String>>,
    transport_cache: Mutex<BTreeMap<(Digest32, Digest32), RegisteredLease>>,
    revoked_transport: Mutex<std::collections::BTreeSet<(Digest32, Digest32, u64)>>,
}
impl Management {
    /// Sign a receipt only for the exact locally applied policy and authenticated roster frontier.
    /// The remote receipt is a separate statement: offline peers remain pending.
    pub fn record_application(&self) -> Result<()> {
        if !lock(&self.pending_nodes).is_empty() {
            return Ok(());
        }
        let local = self.computer.signer.fingerprint();
        self.computer.change(|s| {
            let Some(g) = &s.genesis else {
                return Ok(());
            };
            if !s.quarantined.is_empty() || !s.history_complete() {
                return Ok(());
            }
            if s.rosters.len() != 2 {
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
            exchanges: tokio::sync::Mutex::new(()),
            slots: Arc::new(tokio::sync::Semaphore::new(8)),
            problem: Mutex::new(None),
            pending_nodes: Mutex::new(Vec::new()),
            transport_cache: Mutex::new(BTreeMap::new()),
            revoked_transport: Mutex::new(Default::default()),
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
            if s.genesis.is_some() {
                return Err(Error::Profile("this computer is already paired"));
            }
            if s.pending.is_some()
                || s.invitations
                    .iter()
                    .any(|i| !i.cancelled && i.expires > now())
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
            if s.genesis.is_some() {
                return Err(Error::Profile(
                    "this pairing is established; cancellation does not remove computer trust",
                ));
            }
            if s.cancelled.contains_key(&id) {
                return Ok(false);
            }
            let pending_nonce = s.pending.as_ref().and_then(|g| {
                (g.incarnation() == id || s.invitations.iter().any(|i| i.id == id && i.nonce == g.nonce))
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
                    s.cancelled.insert(g.incarnation(), g);
                }
                if let Some(link) = s.pair_link.take() {
                    s.cancelled_links.push(link);
                }
                s.pending_expires = 0;
                s.rosters.clear();
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
            if s.genesis.is_some() {
                return Err(Error::Profile("this computer is already paired"));
            }
            if s.pair_link.as_ref().is_some_and(|l| l.as_str() != url)
                || (s.pending.is_some() && s.pair_link.is_none())
            {
                return Err(Error::Profile(
                    "another computer pairing is pending; cancel it first",
                ));
            }
        }
        let _exchange = self.exchanges.lock().await;
        self.pair(&link, url).await?;
        *lock(&self.problem) = None;
        self.status()
    }
    /// Record this operator's signature of exactly the previewed operation; retry is idempotent.
    pub fn approve(&self, operation: &str) -> Result<ComputerStatus> {
        let id = crate::node::link::b32_decode(operation, "computer pairing operation")?;
        let local = self.computer.signer.fingerprint();
        self.computer.change(|s| {
            if s.genesis.as_ref().is_some_and(|g| g.incarnation() == id) {
                return Ok(());
            }
            if s.pending.as_ref().is_some_and(|g| {
                g.incarnation() == id
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
            if g.incarnation() != id {
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
            activate(s)?;
            Ok(())
        })?;
        self.status()
    }
    /// Public readback; never treats a timeout or missing receipt as established policy.
    pub fn status(&self) -> Result<ComputerStatus> {
        let s = lock(&self.computer.state);
        let local = self.computer.signer.fingerprint();
        let g = s.genesis.as_ref().or(s.pending.as_ref());
        let pairing = if let Some(g) = g {
            let at = side(g, &local)?;
            Some(PairingPreview {
                operation_id: text_id(&g.incarnation()),
                peer: ComputerIdentity::of(&g.computers[1 - at])?,
                approved_here: g.approvals[at].is_some(),
                approved_there: g.approvals[1 - at].is_some(),
                expires_ms: s.pending_expires,
            })
        } else {
            None
        };
        let invitation = s.invitations.iter().rev().find(|i| {
            s.genesis.is_none()
                && s.pending.is_none()
                && !i.cancelled
                && i.expires > now()
                && i.target.is_none()
        });
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
        let pending_nodes = lock(&self.pending_nodes).clone();
        let storage_failed = self.computer.storage_ready().is_err();
        let state = if storage_failed || !s.quarantined.is_empty() {
            "quarantined"
        } else if s.genesis.is_some() {
            if s.receipts.len() == 2
                && pending_nodes.is_empty()
                && s.receipts
                    .iter()
                    .all(|(author, r)| valid_receipt(&s, author, r).unwrap_or(false))
            {
                "confirmed"
            } else {
                "applying"
            }
        } else if pairing.as_ref().is_some_and(|p| !p.approved_here) {
            "needs-approval"
        } else if pairing.is_some() || invitation.is_some() {
            "waiting"
        } else {
            "individual"
        };
        Ok(ComputerStatus {
            this_computer: ComputerIdentity::of(&s.description)?,
            policy: POLICY.to_owned(),
            state: state.to_owned(),
            invite_link,
            invite_id: invitation.map(|i| text_id(&i.id)),
            invite_expires_ms: invitation.map(|i| i.expires),
            pairing,
            computers: s
                .genesis
                .as_ref()
                .map(|g| g.computers.iter().map(ComputerIdentity::of).collect())
                .transpose()?
                .unwrap_or_default(),
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
    fn transport_lease(&self, supplied: Option<&Link>) -> Result<Option<TransportLease>> {
        let s = lock(&self.computer.state);
        let local = s.description.fingerprint()?;
        let group = s.genesis.as_ref().or(s.pending.as_ref());
        let stored = s.pair_link.as_ref().map(|l| Link::parse(l)).transpose()?;
        let link = supplied.or(stored.as_ref());
        let mut anchors = self.anchors.clone();
        if let Some(link) = link {
            for a in link.anchors.nodes() {
                anchors.add(a.clone())?;
            }
        }
        let established = s.genesis.is_some();
        let peer = group
            .map(|g| side(g, &local).and_then(|at| g.computers[1 - at].fingerprint()))
            .transpose()?;
        let (registration, token, expires, peer) = if let Some(link) = link {
            (
                link.invite,
                link.transport.clone(),
                link.expires,
                Some(peer.unwrap_or(link.target)),
            )
        } else if let Some(invite) = s
            .invitations
            .iter()
            .rev()
            .find(|i| !i.cancelled && group.map_or(i.expires > now(), |g| i.nonce == g.nonce))
        {
            (
                invite.id,
                invite.transport.clone(),
                invite.expires,
                peer.or(invite.target),
            )
        } else {
            return Ok(None);
        };
        if !established && expires <= now() {
            return Ok(None);
        }
        let expires = if established {
            now().saturating_add(crate::nat::service::COMPUTER_TRANSPORT_TTL_MS / 2)
        } else {
            expires
        };
        Ok(Some(TransportLease {
            registration,
            token,
            expires,
            peer,
            anchors,
        }))
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
        if let Some(lease) = self.transport_lease(None)? {
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
        let lease = self.transport_lease(None)?.ok_or(Error::StreamRefused(
            "no current computer transport invitation or enrolled pair",
        ))?;
        if lease.anchors.get(&conn.peer_id()).is_none() {
            return Err(Error::StreamRefused(
                "not this computer pairing's configured anchor",
            ));
        }
        let mut origins = Vec::new();
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
            let lease = self.transport_lease(supplied)?.ok_or(Error::Unreachable(
                "no current computer transport invitation or enrolled pair",
            ))?;
            self.configure_transport_anchors(&lease.anchors);
            let mut attempts = tokio::task::JoinSet::new();
            for anchor in lease.anchors.nodes() {
                let me = Arc::clone(self);
                let anchor = anchor.clone();
                let lease = lease.clone();
                attempts.spawn(async move {
                    me.transport_at(anchor, lease, true).await?;
                    me.net.reach(target, &EndpointList::default()).await
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
        let mut g = Genesis::decode(d.bytes()?)?;
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
            if s.pending.as_ref().is_some_and(|p| p.body() != g.body()) {
                return Err(Error::Profile(
                    "the pairing identity or policy changed; no approval was reused",
                ));
            }
            if let Some(p) = &s.pending {
                g.approvals = p.approvals.clone();
            }
            s.pending = Some(g);
            s.pending_expires = link.expires;
            s.pair_link = Some(Zeroizing::new(url.to_owned()));
            merge(s, &exchange, link.target)?;
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
                .change(|s| merge(s, &payload, conn.peer_id()))?;
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
            let g = Genesis {
                expires: i.expires,
                nonce: i.nonce,
                computers: [s.description.clone(), peer],
                grants: i.grants,
                approvals: [None, None],
            };
            if s.genesis
                .as_ref()
                .or(s.pending.as_ref())
                .is_some_and(|p| p.body() != g.body())
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
            if s.genesis
                .as_ref()
                .or(s.pending.as_ref())
                .is_some_and(|p| p.body() != g.body())
            {
                return Err(Error::Profile("another enrollment is already recorded"));
            }
            i.target = Some(conn.peer_id());
            if let Some(p) = s.genesis.as_ref().or(s.pending.as_ref()) {
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
        let Ok(_exchange) = self.exchanges.try_lock() else {
            return Ok(());
        };
        let (peer, link) = {
            let s = lock(&self.computer.state);
            let Some(g) = s.genesis.as_ref().or(s.pending.as_ref()) else {
                return Ok(());
            };
            let at = side(g, &self.computer.signer.fingerprint())?;
            (g.computers[1 - at].fingerprint()?, s.pair_link.clone())
        };
        let conn = if let Some(c) = self.net.manager().existing(&peer) {
            c
        } else if let Some(url) = link {
            let l = Link::parse(&url)?;
            self.connect(peer, &l.endpoints, Some(&l)).await?
        } else {
            self.connect(peer, &EndpointList::default(), None).await?
        };
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
        self.computer.change(|s| merge(s, &f, peer))?;
        *lock(&self.problem) = None;
        let _ = send.finish();
        Ok(())
    }
}
fn side(g: &Genesis, id: &Digest32) -> Result<usize> {
    g.computers
        .iter()
        .position(|d| d.fingerprint().ok() == Some(*id))
        .ok_or(Error::SignatureInvalid)
}
fn context(invite: &Digest32, transport: &Digest32, g: &Genesis) -> Vec<u8> {
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
fn activate(s: &mut State) -> Result<()> {
    let Some(g) = s.pending.as_ref() else {
        return Ok(());
    };
    if s.cancelled.contains_key(&g.incarnation()) {
        return Err(Error::Profile(
            "this computer pairing attempt was closed locally; its retained intent cannot activate",
        ));
    }
    if g.approvals.iter().all(Option::is_some) && s.genesis.is_none() {
        g.verify(true)?;
        s.genesis = Some(g.clone());
        s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
        s.receipts.clear();
    }
    Ok(())
}
fn exchange(s: &State) -> Result<Vec<u8>> {
    let g = s
        .genesis
        .as_ref()
        .or(s.pending.as_ref())
        .ok_or(Error::Profile("no computer pairing intent"))?;
    let mut e = Encoder::new();
    let current: Vec<_> = s
        .history
        .iter()
        .filter(|(_, r)| r.event().ok().is_some_and(|e| e.group == g.incarnation()))
        .collect();
    e.array(3).bytes(&g.encode()).array(current.len());
    for (id, r) in current {
        e.array(2).bytes(id).bytes(&r.signed.encode());
    }
    e.array(s.receipts.len());
    for (id, r) in &s.receipts {
        e.array(2).bytes(id).bytes(&r.encode());
    }
    Ok(e.finish())
}
fn merge(s: &mut State, bytes: &[u8], peer: Digest32) -> Result<()> {
    let mut d = Decoder::new(bytes);
    arity(&mut d, 3)?;
    let incoming = Genesis::decode(d.bytes()?)?;
    if s.cancelled.contains_key(&incoming.incarnation()) {
        return Err(Error::Profile(
            "this computer pairing attempt was closed locally; its retained intent cannot activate",
        ));
    }
    let local = s.description.fingerprint()?;
    let current = s
        .genesis
        .as_ref()
        .or(s.pending.as_ref())
        .ok_or(Error::Profile("no authenticated computer pairing intent"))?;
    if incoming.body() != current.body() {
        return Err(Error::SignatureInvalid);
    }
    let at = side(current, &peer)?;
    let here = side(current, &local)?;
    let mut g = current.clone();
    if let Some(a) = &incoming.approvals[at] {
        if g.approvals[at].is_none() && g.expires <= now() {
            return Err(Error::Profile(
                "computer pairing expired before approval arrived; no new trust was established",
            ));
        }
        g.approvals[at] = Some(a.clone());
    }
    if incoming.approvals[here].is_some() && incoming.approvals[here] != g.approvals[here] {
        return Err(Error::SignatureInvalid);
    }
    g.verify(false)?;
    s.pending = Some(g.clone());
    let n = count(&mut d)?;
    for _ in 0..n {
        arity(&mut d, 2)?;
        let id = digest(&mut d)?;
        let r = Roster {
            signed: Signed::decode(d.bytes()?)?,
        };
        if id != r.id() {
            return Err(bad());
        }
        s.retain_roster(r)?;
    }
    let n = count(&mut d)?;
    for _ in 0..n {
        arity(&mut d, 2)?;
        let author = digest(&mut d)?;
        let receipt = Signed::decode(d.bytes()?)?;
        if author == peer {
            receipt.verify(b"vox/computer-applied/v1\0", &peer)?;
            if valid_receipt(s, &peer, &receipt)? {
                s.receipts.insert(peer, receipt);
            }
        } else if author != local {
            return Err(Error::SignatureInvalid);
        }
    }
    d.finish()?;
    s.pending = Some(g);
    activate(s)?;
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
    side(g, author)?;
    let mut d = Decoder::new(&r.body);
    arity(&mut d, 7)?;
    if d.uint()? != PROTOCOL
        || digest(&mut d)? != g.incarnation()
        || digest(&mut d)? != sha256(&g.encode())
    {
        return Ok(false);
    }
    let n = count(&mut d)?;
    if n != s.rosters.len() || n != 2 {
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
