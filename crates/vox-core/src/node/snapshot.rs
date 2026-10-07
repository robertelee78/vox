//! What a client that draws a node's rooms needs of it, in one request (ADR-026 C-7): the TUI is a
//! client of the daemon and holds no node of its own (S-4), so the rooms, members, consents,
//! shares, keyring, connected peers and tunnels it shows come from here.
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
}

/// An open room's detail, without its timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRoomSnap {
    /// The room.
    pub channel_id: Digest32,
    /// Its shared name (ADR-028 R-1); `None` for a room no admin has named.
    pub name: Option<String>,
    /// Its members, in fingerprint order.
    pub members: Vec<Digest32>,
    /// Who this identity consents to reading it here, in fingerprint order.
    pub consented: Vec<Digest32>,
    /// The other members that consent to this identity reading them here, in fingerprint order:
    /// the inbound half of `consented`, so a client can show who trusts this node (ADR-028 L-4).
    pub consenting: Vec<Digest32>,
    /// What every member shares here: `(sharer, name, udp, kind)`.
    pub shares: Vec<crate::node::channel::Share>,
    /// The members held back for equivocating: `(author, seq)`.
    pub equivocations: Vec<(Digest32, u64)>,
    /// Who has read this node's own recent messages here: `(entry, readers)`, oldest first
    /// (ADR-028 R-6; [`crate::node::api::ChannelDetail::read_by`]).
    pub read_by: Vec<(Digest32, Vec<Digest32>)>,
    /// Where this node's own recent messages are: `(entry, how many of the other members' nodes
    /// hold it)` ([`crate::node::api::ChannelDetail::held`]).
    pub held: Vec<(Digest32, u64)>,
    /// What a person is told happened to the room, in its order (ADR-028 E-5).
    pub notices: Vec<crate::node::channel::RoomNotice>,
    /// Who trusts each member (ADR-028 K-7): `(member, the members that consent to it reading
    /// them)`.
    pub trusted_by: Vec<(Digest32, Vec<Digest32>)>,
    /// Who has pulled each of this node's shares here whole: `(entry, members)` (ADR-028 F-7;
    /// [`crate::node::shares::Shares::pulled_by`]).
    pub pulled_by: Vec<(Digest32, Vec<Digest32>)>,
    /// The retention this node applies here, seconds, `0` forever
    /// ([`crate::node::api::ChannelDetail::retention`]): what the room's header always shows
    /// (ADR-028 R-7).
    pub retention: u64,
    /// The room's Sessions, oldest opening first (ADR-029;
    /// [`crate::node::sessions::fold`]).
    pub sessions: Vec<crate::node::sessions::SessionRow>,
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
        let nv = handle.view();
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
                })
                .collect(),
            open: nv
                .open_channels
                .iter()
                .map(|d| OpenRoomSnap {
                    channel_id: d.channel_id,
                    name: d.name.clone(),
                    members: d.members.clone(),
                    consented: d.consented.clone(),
                    consenting: d.consenting.clone(),
                    shares: d.shares.clone(),
                    equivocations: d.equivocations.clone(),
                    read_by: d.read_by.clone(),
                    held: d.held.clone(),
                    notices: d.notices.clone(),
                    trusted_by: d.trusted_by.clone(),
                    pulled_by: handle.shares().pulled_by(&d.channel_id),
                    retention: d.retention,
                    sessions: crate::node::sessions::fold(d),
                })
                .collect(),
            trusted: nv.trusted.clone(),
            drive: nv.drive.clone(),
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
        e.array(11).uint(T_SNAPSHOT_REPLY);
        e.bytes(self.me.as_ref().map_or(&[][..], |d| &d[..]));
        e.uint(u64::from(self.mlock_active));
        e.array(self.rooms.len());
        for r in &self.rooms {
            e.array(4)
                .bytes(&r.channel_id)
                .uint(u64::from(r.name.is_some()))
                .text(r.name.as_deref().unwrap_or_default())
                .uint(u64::from(r.open));
        }
        e.array(self.open.len());
        for o in &self.open {
            e.array(14)
                .bytes(&o.channel_id)
                .text(o.name.as_deref().unwrap_or_default());
            digests(&mut e, &o.members);
            digests(&mut e, &o.consented);
            digests(&mut e, &o.consenting);
            e.array(o.shares.len());
            for s in &o.shares {
                e.array(4)
                    .bytes(&s.host)
                    .text(&s.name)
                    .uint(u64::from(s.udp))
                    .text(s.kind.as_str());
            }
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
            e.array(o.notices.len());
            for n in &o.notices {
                e.array(4)
                    .bytes(&n.entry_hash)
                    .bytes(&n.author)
                    .uint(n.created_millis)
                    .text(&n.what);
            }
            e.array(o.trusted_by.len());
            for (member, by) in &o.trusted_by {
                e.array(2).bytes(member);
                digests(&mut e, by);
            }
            e.array(o.pulled_by.len());
            for (entry, who) in &o.pulled_by {
                e.array(2).bytes(entry);
                digests(&mut e, who);
            }
            e.uint(o.retention);
            crate::node::sessions::put_rows(&mut e, &o.sessions);
        }
        e.array(self.trusted.len());
        for (fp, name) in &self.trusted {
            e.array(2).bytes(fp).text(name);
        }
        digests(&mut e, &self.drive);
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
        if !matches!((d.array(), d.uint()), (Ok(11), Ok(T_SNAPSHOT_REPLY))) {
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
            want(&mut d, 4, "ipc snapshot room")?;
            let channel_id = digest(&mut d)?;
            let named = d.uint().map_err(bad("ipc snapshot room named"))? != 0;
            let name = d.text().map_err(bad("ipc snapshot room name"))?.to_owned();
            let open = d.uint().map_err(bad("ipc snapshot room open"))? != 0;
            rooms.push(RoomSnap {
                channel_id,
                name: named.then_some(name),
                open,
            });
        }
        let mut open = Vec::new();
        for _ in 0..d.array().map_err(bad("ipc snapshot open rooms"))? {
            want(&mut d, 14, "ipc snapshot open room")?;
            let channel_id = digest(&mut d)?;
            let name = Some(d.text().map_err(bad("ipc snapshot open name"))?.to_owned())
                .filter(|n| !n.is_empty());
            let members = read_digests(&mut d)?;
            let consented = read_digests(&mut d)?;
            let consenting = read_digests(&mut d)?;
            let mut shares = Vec::new();
            for _ in 0..d.array().map_err(bad("ipc snapshot shares"))? {
                want(&mut d, 4, "ipc snapshot share")?;
                let host = digest(&mut d)?;
                let name = d.text().map_err(bad("ipc snapshot share name"))?.to_owned();
                let udp = d.uint().map_err(bad("ipc snapshot share udp"))? != 0;
                let kind = crate::governance::share::ServiceKind::from_word(
                    d.text().map_err(bad("ipc snapshot share kind"))?,
                )
                .ok_or(Error::MalformedIpc("ipc snapshot share kind"))?;
                shares.push(crate::node::channel::Share {
                    host,
                    name,
                    udp,
                    kind,
                });
            }
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
            let mut notices = Vec::new();
            for _ in 0..d.array().map_err(bad("ipc snapshot notices"))? {
                want(&mut d, 4, "ipc snapshot notice")?;
                notices.push(crate::node::channel::RoomNotice {
                    entry_hash: digest(&mut d)?,
                    author: digest(&mut d)?,
                    created_millis: d.uint().map_err(bad("ipc snapshot notice time"))?,
                    what: d.text().map_err(bad("ipc snapshot notice"))?.to_owned(),
                });
            }
            let mut trusted_by = Vec::new();
            for _ in 0..d.array().map_err(bad("ipc snapshot trusted-by"))? {
                want(&mut d, 2, "ipc snapshot trusted-by entry")?;
                let member = digest(&mut d)?;
                trusted_by.push((member, read_digests(&mut d)?));
            }
            let mut pulled_by = Vec::new();
            for _ in 0..d.array().map_err(bad("ipc snapshot pulled by"))? {
                want(&mut d, 2, "ipc snapshot pulled by entry")?;
                let entry = digest(&mut d)?;
                pulled_by.push((entry, read_digests(&mut d)?));
            }
            let retention = d.uint().map_err(bad("ipc snapshot retention"))?;
            let sessions = crate::node::sessions::read_rows(&mut d)?;
            open.push(OpenRoomSnap {
                channel_id,
                name,
                members,
                consented,
                consenting,
                shares,
                equivocations,
                read_by,
                held,
                notices,
                trusted_by,
                pulled_by,
                retention,
                sessions,
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

/// The answer to a snapshot request for the node behind `handle`: the snapshot, or an error frame
/// saying it does not fit one frame (a client then says so; it never draws part of the node as
/// if it were all of it).
#[must_use]
pub fn answer(handle: &NodeHandle) -> Vec<u8> {
    let body = NodeSnapshot::of(handle).to_bytes();
    if body.len() > crate::node::ipc::frame_limit() {
        return crate::node::ipc::Frame::Error {
            reason: format!(
                "this node's rooms, members and tunnels take {} bytes, more than one control \
                 frame carries ({})",
                body.len(),
                crate::node::ipc::frame_limit()
            ),
        }
        .to_bytes();
    }
    body
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_round_trips() {
        let s = NodeSnapshot {
            me: Some([1; 32]),
            mlock_active: true,
            rooms: vec![
                RoomSnap {
                    channel_id: [2; 32],
                    name: Some("ops".into()),
                    open: true,
                },
                RoomSnap {
                    channel_id: [3; 32],
                    name: None,
                    open: false,
                },
            ],
            open: vec![OpenRoomSnap {
                channel_id: [2; 32],
                name: Some("ops".into()),
                members: vec![[1; 32], [4; 32]],
                consented: vec![[4; 32]],
                consenting: vec![[4; 32]],
                shares: vec![crate::node::channel::Share {
                    host: [4; 32],
                    name: "web".into(),
                    udp: true,
                    kind: crate::governance::share::ServiceKind::Dns,
                }],
                equivocations: vec![([4; 32], 7)],
                read_by: vec![([5; 32], vec![[4; 32]])],
                held: vec![([5; 32], 1)],
                notices: Vec::new(),
                trusted_by: vec![([4; 32], vec![[1; 32]])],
                pulled_by: vec![([6; 32], vec![[4; 32]])],
                retention: 604_800,
                sessions: Vec::new(),
            }],
            trusted: vec![([4; 32], "bob".into())],
            drive: vec![[4; 32]],
            connected_peers: vec![[4; 32]],
            tunnels: vec![LiveTunnel {
                id: 3,
                peer: [4; 32],
                service: "8080".into(),
                outbound: true,
                opened: 10,
                last_moved: 11,
            }],
            closed_tunnels: vec![ClosedTunnel {
                owner: [1; 32],
                id: 2,
                peer: [4; 32],
                service: "22".into(),
                outbound: false,
                opened: 5,
                closed: 6,
                why: "closed at the other end".into(),
            }],
            keyring_open_secs: Some(1380),
        };
        assert_eq!(
            NodeSnapshot::from_bytes(&s.to_bytes()).unwrap(),
            Some(s.clone())
        );
        assert!(is_request(&request_body()));
        let empty = NodeSnapshot::default();
        assert_eq!(
            NodeSnapshot::from_bytes(&empty.to_bytes()).unwrap(),
            Some(empty)
        );
    }
}
