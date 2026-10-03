//! Finding members on this computer and the local network (V210-167).
//!
//! A member is dialled at the address its board record gave, and a node that is not an anchor
//! keeps its board in memory: after a restart it knows another member's address only if that
//! member dials it first, or from the room's address it joined by, which names the host as it
//! was then. A node keeps its port across restarts (`Node::bind_endpoint`), but when another
//! program has taken it, the node listens elsewhere and nobody who knew the old port finds it.
//! An anchor carries the new address to everyone; without one, nothing did.
//!
//! So a node that holds a room in which some member is not connected says where it listens, to
//! an IPv4 multicast group that does not leave the local network (TTL 1), and to the same group
//! on the loopback interface, which reaches nodes on this computer with no network at all. A
//! node that hears it dials whichever of its rooms' unconnected members it names. The datagram
//! names members only as `tag(room, member)` — a hash nobody without the room's id can match —
//! and a dial is authenticated as the member it is for, so a forged or replayed datagram costs
//! a failed dial and nothing more.
//!
//! Datagram: [`MAGIC`], the sender's port (u16, big-endian), then up to [`TAGS_PER_DATAGRAM`]
//! tags of [`TAG_LEN`] bytes.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::hash::Digest32;

/// The multicast group: in the organization-local scope (RFC 2365), so routers do not carry it
/// off the site, and the TTL of 1 keeps it to the local network.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 86, 88);
/// The UDP port every node listens for the group on (shared, `SO_REUSEPORT`).
pub const PORT: u16 = 7392;
/// What every datagram starts with.
const MAGIC: &[u8] = b"vox-here/1";
/// Bytes of a tag.
pub const TAG_LEN: usize = 16;
/// The most tags one datagram carries (it stays under 1,100 bytes).
const TAGS_PER_DATAGRAM: usize = 64;

/// A member of a room, as a datagram names it.
pub type Tag = [u8; TAG_LEN];

/// How `member` of `room` is named in a datagram.
#[must_use]
pub fn tag(room: &Digest32, member: &Digest32) -> Tag {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(room);
    data[32..].copy_from_slice(member);
    let h = crate::hash::domain_hash("vox/nearby/v1", &data);
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&h[..TAG_LEN]);
    t
}

/// The socket a node says where it listens on, and hears others on.
pub struct Nearby {
    socket: tokio::net::UdpSocket,
}

impl Nearby {
    /// Join the group on the default interface and on loopback. Either join may fail (a machine
    /// with no network, a loopback without multicast); it fails only if neither works.
    ///
    /// # Errors
    /// If the port cannot be shared or bound, or neither interface takes the group.
    pub fn open() -> std::io::Result<Self> {
        let s = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        s.set_reuse_address(true)?;
        #[cfg(unix)]
        s.set_reuse_port(true)?;
        s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT)).into())?;
        let any = s.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED);
        let lo = s.join_multicast_v4(&GROUP, &Ipv4Addr::LOCALHOST);
        if let (Err(e), Err(_)) = (any, lo) {
            return Err(e);
        }
        s.set_multicast_ttl_v4(1)?;
        s.set_multicast_loop_v4(true)?;
        s.set_nonblocking(true)?;
        Ok(Self {
            socket: tokio::net::UdpSocket::from_std(s.into())?,
        })
    }

    /// Say that this node listens on `port` and holds the rooms `tags` name, on the default
    /// interface and on loopback. Best effort: a datagram that cannot leave is not retried here.
    pub fn say(&self, port: u16, tags: &[Tag]) {
        let sock = socket2::SockRef::from(&self.socket);
        for chunk in tags.chunks(TAGS_PER_DATAGRAM) {
            let mut d = Vec::with_capacity(MAGIC.len() + 2 + chunk.len() * TAG_LEN);
            d.extend_from_slice(MAGIC);
            d.extend_from_slice(&port.to_be_bytes());
            for t in chunk {
                d.extend_from_slice(t);
            }
            for via in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST] {
                if sock.set_multicast_if_v4(&via).is_ok() {
                    let _ = self.socket.try_send_to(&d, SocketAddr::from((GROUP, PORT)));
                }
            }
        }
    }

    /// The next datagram heard: where its sender listens, and the tags it names. Anything that
    /// is not one is skipped.
    pub async fn hear(&self) -> std::io::Result<(SocketAddr, Vec<Tag>)> {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = self.socket.recv_from(&mut buf).await?;
            if let Some(heard) = parse(&buf[..n], from.ip()) {
                return Ok(heard);
            }
        }
    }
}

/// A datagram from `ip`: the address its sender listens on, and its tags.
fn parse(d: &[u8], ip: IpAddr) -> Option<(SocketAddr, Vec<Tag>)> {
    let rest = d.strip_prefix(MAGIC)?;
    let (port, tags) = rest.split_first_chunk::<2>()?;
    let port = u16::from_be_bytes(*port);
    if port == 0 || tags.is_empty() || tags.len() % TAG_LEN != 0 {
        return None;
    }
    let tags = tags
        .chunks_exact(TAG_LEN)
        .filter_map(|c| <Tag>::try_from(c).ok())
        .take(TAGS_PER_DATAGRAM)
        .collect();
    Some((SocketAddr::new(ip, port), tags))
}

/// Where to dial a node heard at `at`: there, and on loopback too when `at` is an address of
/// this computer, since a node may listen on loopback alone.
#[must_use]
pub fn dial_at(at: SocketAddr) -> Vec<SocketAddr> {
    let mut out = vec![at];
    let local = at.ip().is_loopback() || std::net::UdpSocket::bind((at.ip(), 0)).is_ok();
    if local && !at.ip().is_loopback() {
        out.push(SocketAddr::from((Ipv4Addr::LOCALHOST, at.port())));
    }
    out
}
