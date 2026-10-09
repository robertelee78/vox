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
//! node that hears it dials whichever of its rooms' unconnected members it names. A dial is
//! authenticated as the member it is for, so a forged or replayed datagram costs a failed dial
//! and nothing more.
//!
//! **What a listener learns.** Each member is named by an [`Entry`]: a tag, `H(room, member,
//! window)`, and its port masked by more of the same hash. The window is [`WINDOW_MS`] of
//! wall-clock time, so the tag changes with it, and the port — which a node keeps across restarts
//! and networks — is never sent in the clear. Without the room's id, a listener cannot tell
//! which rooms or members a datagram names, nor link one window's datagrams to the next by their
//! contents. It does see the marker, the group, the sender's IP address, and how many entries
//! there are: that a vox node is on this network, and roughly how many rooms it holds.
//!
//! A hearer accepts the window before and after its own as well, so clocks a little apart still
//! match.
//!
//! Datagram: `MAGIC`, then up to `ENTRIES_PER_DATAGRAM` entries of `ENTRY_LEN` bytes.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::hash::Digest32;

/// The multicast group: in the organization-local scope (RFC 2365), so routers do not carry it
/// off the site, and the TTL of 1 keeps it to the local network.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 86, 88);
/// The UDP port every node listens for the group on (shared, `SO_REUSEPORT`).
pub const PORT: u16 = 7392;
/// What every datagram starts with.
const MAGIC: &[u8] = b"vox-here/2";
/// Bytes of a tag.
const TAG_LEN: usize = 16;
/// Bytes of an entry: the tag, then the masked port.
pub const ENTRY_LEN: usize = TAG_LEN + 2;
/// The most entries one datagram carries (it stays under 1,200 bytes).
const ENTRIES_PER_DATAGRAM: usize = 64;
/// How long a tag stays the same, in milliseconds: ten minutes. The window number is the same as
/// when it was counted in seconds, so nodes still match.
pub const WINDOW_MS: u64 = 600_000;

/// A member of a room listening on a port, as a datagram names it.
pub type Entry = [u8; ENTRY_LEN];

/// The hash an entry for `member` of `room` in `window` is made from.
fn key(room: &Digest32, member: &Digest32, window: u64) -> Digest32 {
    let mut data = [0u8; 72];
    data[..32].copy_from_slice(room);
    data[32..64].copy_from_slice(member);
    data[64..].copy_from_slice(&window.to_be_bytes());
    crate::hash::domain_hash("vox/nearby/v2", &data)
}

/// The window `now_ms` (milliseconds since the Unix epoch) falls in.
#[must_use]
pub fn window(now_ms: u64) -> u64 {
    now_ms / WINDOW_MS
}

/// How `member` of `room`, listening on `port`, is named in a datagram sent at `now_ms`.
#[must_use]
pub fn entry(room: &Digest32, member: &Digest32, port: u16, now_ms: u64) -> Entry {
    let h = key(room, member, window(now_ms));
    let mut e = [0u8; ENTRY_LEN];
    e[..TAG_LEN].copy_from_slice(&h[..TAG_LEN]);
    let masked = port ^ u16::from_be_bytes([h[TAG_LEN], h[TAG_LEN + 1]]);
    e[TAG_LEN..].copy_from_slice(&masked.to_be_bytes());
    e
}

/// The port of whichever of `entries` names `member` of `room`, heard at `now_ms`: its window, or
/// the one either side.
#[must_use]
pub fn port_of(entries: &[Entry], room: &Digest32, member: &Digest32, now_ms: u64) -> Option<u16> {
    let w = window(now_ms);
    for w in [w, w.saturating_sub(1), w + 1] {
        let h = key(room, member, w);
        if let Some(e) = entries.iter().find(|e| e[..TAG_LEN] == h[..TAG_LEN]) {
            let masked = u16::from_be_bytes([e[TAG_LEN], e[TAG_LEN + 1]]);
            let port = masked ^ u16::from_be_bytes([h[TAG_LEN], h[TAG_LEN + 1]]);
            return (port != 0).then_some(port);
        }
    }
    None
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

    /// Say `entries` (this node's, from [`entry`]) on the default interface and on loopback.
    /// Best effort: a datagram that cannot leave is not retried here.
    pub fn say(&self, entries: &[Entry]) {
        let sock = socket2::SockRef::from(&self.socket);
        for chunk in entries.chunks(ENTRIES_PER_DATAGRAM) {
            let mut d = Vec::with_capacity(MAGIC.len() + chunk.len() * ENTRY_LEN);
            d.extend_from_slice(MAGIC);
            for e in chunk {
                d.extend_from_slice(e);
            }
            for via in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST] {
                if sock.set_multicast_if_v4(&via).is_ok() {
                    let _ = self.socket.try_send_to(&d, SocketAddr::from((GROUP, PORT)));
                }
            }
        }
    }

    /// The next datagram heard: the address it came from, and its entries. Anything that is not
    /// one is skipped.
    pub async fn hear(&self) -> std::io::Result<(IpAddr, Vec<Entry>)> {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = self.socket.recv_from(&mut buf).await?;
            if let Some(entries) = parse(&buf[..n]) {
                return Ok((from.ip(), entries));
            }
        }
    }
}

/// A datagram's entries.
fn parse(d: &[u8]) -> Option<Vec<Entry>> {
    let rest = d.strip_prefix(MAGIC)?;
    if rest.is_empty() || rest.len() % ENTRY_LEN != 0 {
        return None;
    }
    Some(
        rest.chunks_exact(ENTRY_LEN)
            .filter_map(|c| <Entry>::try_from(c).ok())
            .take(ENTRIES_PER_DATAGRAM)
            .collect(),
    )
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
