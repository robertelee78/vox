//! What a client that draws a node's rooms needs of it, in one request (ADR-026 C-7): the TUI is a
//! client of the daemon and holds no node of its own (S-4), so the rooms, members, consents,
//! keyring, connected peers and tunnels it shows come from here. Governance is read
//! through selected pages, with explicit continuation.
//!
//! The node's [`NodeView`](crate::node::api::NodeView) minus everything a client draws no row of:
//! no timelines (a client reads the room on screen with [`crate::node::ipc::Request::Read`], one
//! page at a time), no order, no listening addresses. The tunnels are this node's own, kept in the
//! daemon's process (ADR-026 P-1), so they are listed here where they live.
//!
//! Sent on a connection that has taken its `Use`, like the status request, as a body of its own
//! tag: additive, and a node that does not know it answers with an error.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::transport::quic::{ClosedTunnel, LiveTunnel};

const T_SNAPSHOT: u64 = 4410;
const T_SNAPSHOT_REPLY: u64 = 4411;

/// A room the node holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomSnap {
    /// The room.
    pub channel_id: Digest32,
    /// Its shared name (ADR-028 R-1), known only while it is open (it is sealed under the room's
    /// key), and `None` for a room no admin has named.
    pub name: Option<String>,
    /// Whether it is open.
    pub open: bool,
    /// Saved room history is still preparing locally.
    pub preparing: bool,
    /// The daemon's failed automatic reopen reason, absent while open or preparing.
    pub open_failure: Option<String>,
}

/// An open room's detail, without its timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRoomSnap {
    /// The room.
    pub channel_id: Digest32,
    /// Published row-display token, stable on reuse and unique across this actor's room opens.
    /// Discard cached tokens when the node connection changes.
    pub display_revision: u64,
    /// Its shared name (ADR-028 R-1); `None` for a room no admin has named.
    pub name: Option<String>,
    /// Its members, in fingerprint order.
    pub members: Vec<Digest32>,
    /// Current members this identity consents to, for roster indicators only.
    pub member_consent: Vec<Digest32>,
    /// Checked governance revision for selected-page refresh.
    pub governance_revision: u64,
    /// The other members that consent to this identity reading them here, in fingerprint order:
    /// the inbound half of `member_consent`, so a client can show who trusts this node (ADR-028 L-4).
    pub consenting: Vec<Digest32>,
    /// The members held back for equivocating: `(author, seq)`.
    pub equivocations: Vec<(Digest32, u64)>,
    /// Who has read this node's own recent messages here: `(entry, readers)`, oldest first
    /// (ADR-028 R-6; [`crate::node::api::ChannelDetail::read_by`]).
    pub read_by: Vec<(Digest32, Vec<Digest32>)>,
    /// Where this node's own recent messages are: `(entry, how many of the other members' nodes
    /// hold it)` ([`crate::node::api::ChannelDetail::held`]).
    pub held: Vec<(Digest32, u64)>,
    /// Who trusts each member (ADR-028 K-7): `(member, the members that consent to it reading
    /// them)`.
    pub trusted_by: Vec<(Digest32, Vec<Digest32>)>,
    /// The retention this node applies here, seconds, `0` forever
    /// ([`crate::node::api::ChannelDetail::retention`]): what the room's header always shows
    /// (ADR-028 R-7).
    pub retention: u64,
    /// The room's configured message lifetime, before this node's shorter choice.
    pub room_retention: u64,
    /// The room's configured Session-step lifetime; zero means forever.
    pub room_step_retention: u64,
    /// This node's effective Session-step lifetime, clamped by message retention.
    pub step_retention: u64,
    /// This node's explicit shorter Session-step lifetime, if it has one.
    pub local_step_retention: Option<u64>,
    /// Opaque Session change token, including private activity and actor lifetime.
    pub session_revision: Digest32,
}

/// One node as a client draws it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeSnapshot {
    /// Its identity, or `None` before it has one.
    pub me: Option<Digest32>,
    /// Whether every open room's key is memory-locked.
    pub mlock_active: bool,
    /// Every room, in room-id order.
    pub rooms: Vec<RoomSnap>,
    /// The open rooms' detail, in room-id order.
    pub open: Vec<OpenRoomSnap>,
    /// The trust keyring: `(fingerprint, petname)`.
    pub trusted: Vec<(Digest32, String)>,
    /// The keyring entries that carry drive (ADR-028 K-14); every other entry grants read.
    pub drive: Vec<Digest32>,
    /// The members offered to its keyring (ADR-028 K-15 – K-18), in fingerprint order.
    pub offers: Vec<crate::node::api::Offer>,
    /// The peers it holds a connection to now, in fingerprint order.
    pub connected_peers: Vec<Digest32>,
    /// Its live tunnels.
    pub tunnels: Vec<LiveTunnel>,
    /// Its tunnels that ended for a reason a person should see.
    pub closed_tunnels: Vec<ClosedTunnel>,
    /// How many seconds a keyring change still goes without the identity passphrase, or `None`
    /// when the next one will ask for it (ADR-028 K-9).
    pub keyring_open_secs: Option<u64>,
}

impl NodeSnapshot {
    /// The snapshot of the node behind `handle`, read from its published view and this process's
    /// tunnel tables.
    #[must_use]
    pub fn of(handle: &NodeHandle) -> Self {
        let (nv, policy_current) = handle.coherent_view();
        let me = nv.identity.as_ref().map(|i| i.fingerprint);
        Self {
            me,
            mlock_active: nv.mlock_active,
            rooms: nv
                .channels
                .iter()
                .map(|c| RoomSnap {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    open: c.open,
                    preparing: c.preparing,
                    open_failure: c.open_failure.clone(),
                })
                .collect(),
            open: nv
                .open_channels
                .iter()
                .map(|d| OpenRoomSnap {
                    channel_id: d.channel_id,
                    display_revision: d.display_revision,
                    name: d.name.clone(),
                    members: d.members.clone(),
                    member_consent: d.member_consent.clone(),
                    governance_revision: d.governance_revision,
                    consenting: d.consenting.clone(),
                    equivocations: d.equivocations.clone(),
                    read_by: d.read_by.clone(),
                    held: d.held.clone(),
                    trusted_by: d.trusted_by.clone(),
                    retention: d.retention,
                    room_retention: d.room_retention,
                    room_step_retention: d.room_step_retention,
                    step_retention: d.step_retention,
                    local_step_retention: d.local_step_retention,
                    session_revision: handle.session_display_token(d, policy_current),
                })
                .collect(),
            trusted: if policy_current {
                nv.trusted.clone()
            } else {
                Vec::new()
            },
            drive: if policy_current {
                nv.drive.clone()
            } else {
                Vec::new()
            },
            offers: nv.offers.clone(),
            connected_peers: nv.connected_peers.clone(),
            tunnels: me
                .map(|me| crate::transport::quic::live_tunnels(&me))
                .unwrap_or_default(),
            closed_tunnels: me
                .map(|me| crate::transport::quic::closed_tunnels(&me))
                .unwrap_or_default(),
            keyring_open_secs: handle.keyring_open_secs(),
        }
    }

    /// Canonical CBOR body of the reply (unframed).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(12).uint(T_SNAPSHOT_REPLY);
        e.bytes(self.me.as_ref().map_or(&[][..], |d| &d[..]));
        e.uint(u64::from(self.mlock_active));
        e.array(self.rooms.len());
        for r in &self.rooms {
            e.array(6)
                .bytes(&r.channel_id)
                .uint(u64::from(r.name.is_some()))
                .text(r.name.as_deref().unwrap_or_default())
                .uint(u64::from(r.open))
                .uint(u64::from(r.preparing))
                .text(r.open_failure.as_deref().unwrap_or(""));
        }
        e.array(self.open.len());
        for o in &self.open {
            e.array(17)
                .bytes(&o.channel_id)
                .text(o.name.as_deref().unwrap_or_default());
            digests(&mut e, &o.members);
            digests(&mut e, &o.member_consent);
            e.uint(o.governance_revision);
            digests(&mut e, &o.consenting);
            e.array(o.equivocations.len());
            for (author, seq) in &o.equivocations {
                e.array(2).bytes(author).uint(*seq);
            }
            e.array(o.read_by.len());
            for (entry, readers) in &o.read_by {
                e.array(2).bytes(entry);
                digests(&mut e, readers);
            }
            e.array(o.held.len());
            for (entry, n) in &o.held {
                e.array(2).bytes(entry).uint(*n);
            }
            e.array(o.trusted_by.len());
            for (member, by) in &o.trusted_by {
                e.array(2).bytes(member);
                digests(&mut e, by);
            }
            e.uint(o.retention);
            e.uint(o.room_retention)
                .uint(o.room_step_retention)
                .uint(o.step_retention);
            e.array(usize::from(o.local_step_retention.is_some()));
            if let Some(seconds) = o.local_step_retention {
                e.uint(seconds);
            }
            e.uint(o.display_revision).bytes(&o.session_revision);
        }
        e.array(self.trusted.len());
        for (fp, name) in &self.trusted {
            e.array(2).bytes(fp).text(name);
        }
        digests(&mut e, &self.drive);
        crate::node::offers::put_offers(&mut e, &self.offers);
        digests(&mut e, &self.connected_peers);
        e.array(self.tunnels.len());
        for t in &self.tunnels {
            e.array(6)
                .uint(t.id)
                .bytes(&t.peer)
                .text(&t.service)
                .uint(u64::from(t.outbound))
                .uint(t.opened)
                .uint(t.last_moved);
        }
        e.array(self.closed_tunnels.len());
        for t in &self.closed_tunnels {
            e.array(8)
                .bytes(&t.owner)
                .uint(t.id)
                .bytes(&t.peer)
                .text(&t.service)
                .uint(u64::from(t.outbound))
                .uint(t.opened)
                .uint(t.closed)
                .text(&t.why);
        }
        // `[]` when a change will ask; else `[seconds left]`.
        match self.keyring_open_secs {
            Some(left) => e.array(1).uint(left),
            None => e.array(0),
        };
        e.finish()
    }

    /// Decode a reply body; `Ok(None)` when `body` is not a snapshot reply (an error frame).
    ///
    /// # Errors
    /// If it is a snapshot reply that does not decode.
    pub fn from_bytes(body: &[u8]) -> Result<Option<Self>> {
        let mut d = Decoder::new(body);
        if !matches!((d.array(), d.uint()), (Ok(12), Ok(T_SNAPSHOT_REPLY))) {
            return Ok(None);
        }
        let bad = |what: &'static str| move |_| Error::MalformedIpc(what);
        let me = {
            let b = d.bytes().map_err(bad("ipc snapshot me"))?;
            if b.is_empty() {
                None
            } else {
                Some(digest_of(b)?)
            }
        };
        let mlock_active = d.uint().map_err(bad("ipc snapshot mlock"))? != 0;
        let mut rooms = Vec::new();
        for _ in 0..d.array().map_err(bad("ipc snapshot rooms"))? {
            want(&mut d, 6, "ipc snapshot room")?;
            let channel_id = digest(&mut d)?;
            let named = d.uint().map_err(bad("ipc snapshot room named"))? != 0;
            let name = d.text().map_err(bad("ipc snapshot room name"))?.to_owned();
            let open = d.uint().map_err(bad("ipc snapshot room open"))? != 0;
            let preparing = d.uint().map_err(bad("ipc snapshot room preparing"))? != 0;
            let failure = d.text().map_err(bad("ipc snapshot room open failure"))?;
            let open_failure = (!failure.is_empty()).then(|| failure.to_owned());
            if open && preparing || open_failure.is_some() && (open || preparing) {
                return Err(Error::MalformedIpc("ipc snapshot room availability"));
            }
            rooms.push(RoomSnap {
                channel_id,
                name: named.then_some(name),
                open,
                preparing,
                open_failure,
            });
        }
        let mut open = Vec::new();
        for _ in 0..d.array().map_err(bad("ipc snapshot open rooms"))? {
            let fields = d.array().map_err(bad("ipc snapshot open room"))?;
            if fields != 17 {
                return Err(Error::MalformedIpc("ipc snapshot open room"));
            }
            let channel_id = digest(&mut d)?;
            let name = Some(d.text().map_err(bad("ipc snapshot open name"))?.to_owned())
                .filter(|n| !n.is_empty());
            let members = read_digests(&mut d)?;
            let member_consent = read_digests(&mut d)?;
            let governance_revision = d.uint().map_err(bad("ipc snapshot governance revision"))?;
            let consenting = read_digests(&mut d)?;
            let mut equivocations = Vec::new();
            for _ in 0..d.array().map_err(bad("ipc snapshot equivocations"))? {
                want(&mut d, 2, "ipc snapshot equivocation")?;
                let author = digest(&mut d)?;
                let seq = d.uint().map_err(bad("ipc snapshot equivocation seq"))?;
                equivocations.push((author, seq));
            }
            let mut read_by = Vec::new();
            for _ in 0..d.array().map_err(bad("ipc snapshot read by"))? {
                want(&mut d, 2, "ipc snapshot read by entry")?;
                let entry = digest(&mut d)?;
                read_by.push((entry, read_digests(&mut d)?));
            }
            let mut held = Vec::new();
            for _ in 0..d.array().map_err(bad("ipc snapshot held"))? {
                want(&mut d, 2, "ipc snapshot held entry")?;
                let entry = digest(&mut d)?;
                held.push((entry, d.uint().map_err(bad("ipc snapshot held count"))?));
            }
            let mut trusted_by = Vec::new();
            for _ in 0..d.array().map_err(bad("ipc snapshot trusted-by"))? {
                want(&mut d, 2, "ipc snapshot trusted-by entry")?;
                let member = digest(&mut d)?;
                trusted_by.push((member, read_digests(&mut d)?));
            }
            let retention = d.uint().map_err(bad("ipc snapshot retention"))?;
            let room_retention = d.uint().map_err(bad("ipc snapshot room retention"))?;
            let room_step_retention = d.uint().map_err(bad("ipc snapshot room step retention"))?;
            let step_retention = d.uint().map_err(bad("ipc snapshot step retention"))?;
            let local_step_retention = match d
                .array()
                .map_err(bad("ipc snapshot local step retention"))?
            {
                0 => None,
                1 => Some(
                    d.uint()
                        .map_err(bad("ipc snapshot local step retention seconds"))?,
                ),
                _ => return Err(Error::MalformedIpc("ipc snapshot local step retention")),
            };
            let display_revision = d.uint().map_err(bad("ipc snapshot display revision"))?;
            let session_revision = digest(&mut d)?;
            open.push(OpenRoomSnap {
                channel_id,
                display_revision,
                session_revision,
                name,
                members,
                member_consent,
                governance_revision,
                consenting,
                equivocations,
                read_by,
                held,
                trusted_by,
                retention,
                room_retention,
                room_step_retention,
                step_retention,
                local_step_retention,
            });
        }
        let mut trusted = Vec::new();
        for _ in 0..d.array().map_err(bad("ipc snapshot trusted"))? {
            want(&mut d, 2, "ipc snapshot trusted entry")?;
            let fp = digest(&mut d)?;
            let name = d.text().map_err(bad("ipc snapshot petname"))?.to_owned();
            trusted.push((fp, name));
        }
        let drive = read_digests(&mut d)?;
        let offers = crate::node::offers::read_offers(&mut d)?;
        let connected_peers = read_digests(&mut d)?;
        let mut tunnels = Vec::new();
        for _ in 0..d.array().map_err(bad("ipc snapshot tunnels"))? {
            want(&mut d, 6, "ipc snapshot tunnel")?;
            tunnels.push(LiveTunnel {
                id: d.uint().map_err(bad("ipc snapshot tunnel id"))?,
                peer: digest(&mut d)?,
                service: d
                    .text()
                    .map_err(bad("ipc snapshot tunnel service"))?
                    .to_owned(),
                outbound: d.uint().map_err(bad("ipc snapshot tunnel way"))? != 0,
                opened: d.uint().map_err(bad("ipc snapshot tunnel opened"))?,
                last_moved: d.uint().map_err(bad("ipc snapshot tunnel moved"))?,
            });
        }
        let mut closed_tunnels = Vec::new();
        for _ in 0..d.array().map_err(bad("ipc snapshot closed tunnels"))? {
            want(&mut d, 8, "ipc snapshot closed tunnel")?;
            closed_tunnels.push(ClosedTunnel {
                owner: digest(&mut d)?,
                id: d.uint().map_err(bad("ipc snapshot closed id"))?,
                peer: digest(&mut d)?,
                service: d
                    .text()
                    .map_err(bad("ipc snapshot closed service"))?
                    .to_owned(),
                outbound: d.uint().map_err(bad("ipc snapshot closed way"))? != 0,
                opened: d.uint().map_err(bad("ipc snapshot closed opened"))?,
                closed: d.uint().map_err(bad("ipc snapshot closed at"))?,
                why: d.text().map_err(bad("ipc snapshot closed why"))?.to_owned(),
            });
        }
        let keyring_open_secs = match d.array().map_err(bad("ipc snapshot keyring"))? {
            0 => None,
            1 => Some(d.uint().map_err(bad("ipc snapshot keyring left"))?),
            _ => return Err(Error::MalformedIpc("ipc snapshot keyring")),
        };
        d.finish().map_err(bad("ipc snapshot trailing"))?;
        Ok(Some(Self {
            me,
            mlock_active,
            rooms,
            open,
            trusted,
            drive,
            offers,
            connected_peers,
            tunnels,
            closed_tunnels,
            keyring_open_secs,
        }))
    }
}

/// The request's body (unframed).
#[must_use]
pub fn request_body() -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(1).uint(T_SNAPSHOT);
    e.finish()
}

/// Whether `body` is a snapshot request.
#[must_use]
pub fn is_request(body: &[u8]) -> bool {
    let mut d = Decoder::new(body);
    matches!((d.array(), d.uint()), (Ok(1), Ok(T_SNAPSHOT)))
}

/// The complete snapshot body. IPC carries it across cursor pages, including member read and
/// trust lists whose individual rows can cross a frame (ADR-034 FR-7).
#[must_use]
pub fn answer(handle: &NodeHandle) -> Vec<u8> {
    NodeSnapshot::of(handle).to_bytes()
}

fn digests(e: &mut Encoder, ds: &[Digest32]) {
    e.array(ds.len());
    for d in ds {
        e.bytes(d);
    }
}

fn want(d: &mut Decoder<'_>, n: usize, what: &'static str) -> Result<()> {
    match d.array() {
        Ok(got) if got == n => Ok(()),
        _ => Err(Error::MalformedIpc(what)),
    }
}

fn digest_of(b: &[u8]) -> Result<Digest32> {
    Digest32::try_from(b).map_err(|_| Error::MalformedIpc("ipc snapshot digest length"))
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    digest_of(
        d.bytes()
            .map_err(|_| Error::MalformedIpc("ipc snapshot digest"))?,
    )
}

fn read_digests(d: &mut Decoder<'_>) -> Result<Vec<Digest32>> {
    let n = d
        .array()
        .map_err(|_| Error::MalformedIpc("ipc snapshot digests"))?;
    (0..n).map(|_| digest(d)).collect()
}

/// The keyring window as every client says it (ADR-028 K-9): `keyring open 23m` while a keyring
/// change goes without the passphrase, rounded up so an open window never reads `0m`; `keyring asks
/// for the passphrase` once it will ask.
#[must_use]
pub fn keyring_label(open_secs: Option<u64>) -> String {
    match open_secs {
        Some(left) => format!("keyring open {}m", left.div_ceil(60).max(1)),
        None => "keyring asks for the passphrase".to_owned(),
    }
}
