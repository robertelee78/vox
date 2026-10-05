//! **Hearing the machine's network change** (ADR-012 N-49, N-50).
//!
//! The operating system says when an interface, an address or a route comes or goes: on macOS
//! on a `PF_ROUTE` socket, on Linux on an rtnetlink socket subscribed to the link, address and
//! route groups. Nothing is polled. Events come in bursts (an interface coming up adds its
//! addresses, then its routes, then a neighbour or two), so they are coalesced for
//! [`NETWORK_SETTLE`] after the last one, and only then is the machine's [`NetShape`] read and
//! compared with the one before: most events (a neighbour's route, a multicast address) change
//! nothing a peer dials, and those start nothing ([`NetChange::between`]).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use rustix::fd::OwnedFd;
use tokio::io::unix::AsyncFd;

/// How long the events of one change are gathered after the last of them (N-50).
pub const NETWORK_SETTLE: Duration = Duration::from_millis(500);

/// What of the machine's network a peer depends on: the routable addresses the operating system
/// would use ([`crate::nat::reachability::local_route_ips`]) and the default routes' next hops.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetShape {
    /// The routable addresses, IPv6 first.
    pub addrs: Vec<IpAddr>,
    /// The IPv4 default route's next hop, where the platform says it.
    pub route_v4: Option<Ipv4Addr>,
    /// The IPv6 default route's next hop, where the platform says it.
    pub route_v6: Option<Ipv6Addr>,
}

impl NetShape {
    /// The machine's shape now.
    pub async fn now() -> Self {
        Self {
            addrs: crate::nat::reachability::local_route_ips().await,
            route_v4: crate::nat::portmap::gateway::default_gateway_v4().ok(),
            route_v6: crate::nat::portmap::gateway::default_gateway_v6()
                .ok()
                .map(|(ip, _)| ip),
        }
    }
}

/// A real change of the machine's network (N-50): what came, what went, and which default
/// routes moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetChange {
    /// When it was found, unix seconds.
    pub at: u64,
    /// Routable addresses the machine has now and did not before.
    pub came: Vec<IpAddr>,
    /// Routable addresses it had and has no longer.
    pub went: Vec<IpAddr>,
    /// Each default route that moved, said as `IPv4 default route a → b`.
    pub routes: Vec<String>,
}

impl NetChange {
    /// The change from `before` to `after`, or `None` when neither the routable addresses nor a
    /// default route differ: a change that starts nothing (N-50).
    #[must_use]
    pub fn between(before: &NetShape, after: &NetShape, at: u64) -> Option<Self> {
        let (old, new): (BTreeSet<IpAddr>, BTreeSet<IpAddr>) = (
            before.addrs.iter().copied().collect(),
            after.addrs.iter().copied().collect(),
        );
        let came: Vec<IpAddr> = new.difference(&old).copied().collect();
        let went: Vec<IpAddr> = old.difference(&new).copied().collect();
        let mut routes = Vec::new();
        let said = |ip: Option<String>| ip.unwrap_or_else(|| "none".to_owned());
        if before.route_v4 != after.route_v4 {
            routes.push(format!(
                "IPv4 default route {} → {}",
                said(before.route_v4.map(|i| i.to_string())),
                said(after.route_v4.map(|i| i.to_string()))
            ));
        }
        if before.route_v6 != after.route_v6 {
            routes.push(format!(
                "IPv6 default route {} → {}",
                said(before.route_v6.map(|i| i.to_string())),
                said(after.route_v6.map(|i| i.to_string()))
            ));
        }
        if came.is_empty() && went.is_empty() && routes.is_empty() {
            return None;
        }
        Some(Self {
            at,
            came,
            went,
            routes,
        })
    }

    /// The change in one line, as the daemon's log and a client say it.
    #[must_use]
    pub fn summary(&self) -> String {
        let list = |ips: &[IpAddr]| {
            if ips.is_empty() {
                "none".to_owned()
            } else {
                ips.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        };
        let mut s = format!(
            "the network changed: addresses came: {}; went: {}",
            list(&self.came),
            list(&self.went)
        );
        if !self.routes.is_empty() {
            s += &format!("; {}", self.routes.join("; "));
        }
        s
    }
}

/// The operating system's network events, read from the socket it says them on (N-49).
pub struct NetWatch {
    fd: AsyncFd<OwnedFd>,
    buf: Vec<u8>,
}

impl NetWatch {
    /// Open the platform's event socket. `Err` says why this machine's changes are not heard: a
    /// platform with no such socket, or one the operating system refused.
    ///
    /// # Errors
    /// Why no socket could be opened.
    pub fn open() -> Result<Self, String> {
        let fd = open_socket()?;
        rustix::io::ioctl_fionbio(&fd, true)
            .map_err(|e| format!("cannot make the network event socket non-blocking: {e}"))?;
        let fd =
            AsyncFd::new(fd).map_err(|e| format!("cannot watch the network event socket: {e}"))?;
        Ok(Self {
            fd,
            buf: vec![0; 64 * 1024],
        })
    }

    /// Wait for one event that may change the machine's network shape, then for
    /// [`NETWORK_SETTLE`] with no further event: one call per burst.
    ///
    /// # Errors
    /// The socket failed: nothing more will be heard on it.
    pub async fn settled(&mut self) -> std::io::Result<()> {
        while !self.read_relevant().await? {}
        loop {
            match tokio::time::timeout(NETWORK_SETTLE, self.read_relevant()).await {
                Err(_) => return Ok(()),
                Ok(r) => {
                    r?;
                }
            }
        }
    }

    /// Read what is waiting: whether any of it is an event of the kinds N-49 names.
    async fn read_relevant(&mut self) -> std::io::Result<bool> {
        loop {
            let mut ready = self.fd.readable().await?;
            match ready.try_io(|fd| {
                rustix::io::read(fd.get_ref(), &mut self.buf[..]).map_err(std::io::Error::from)
            }) {
                Ok(Ok(0)) => {
                    return Err(std::io::Error::other("the network event socket closed"));
                }
                Ok(Ok(n)) => return Ok(relevant(&self.buf[..n])),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {}
                // A burst the kernel could not queue for us is still a burst.
                Ok(Err(e))
                    if e.raw_os_error() == Some(rustix::io::Errno::NOBUFS.raw_os_error()) =>
                {
                    return Ok(true);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

/// macOS: a `PF_ROUTE` socket, which every routing-table and interface change is written to.
#[cfg(target_os = "macos")]
fn open_socket() -> Result<OwnedFd, String> {
    use rustix::net::{socket, AddressFamily, SocketType};
    socket(AddressFamily::ROUTE, SocketType::RAW, None)
        .map_err(|e| format!("cannot open a PF_ROUTE socket: {e}"))
}

/// Linux: an rtnetlink socket subscribed to links, addresses and routes of both families.
#[cfg(target_os = "linux")]
fn open_socket() -> Result<OwnedFd, String> {
    use rustix::net::{bind, netlink, socket, AddressFamily, SocketType};
    /// `RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR |
    /// RTMGRP_IPV6_ROUTE` (`<linux/rtnetlink.h>`).
    const GROUPS: u32 = 0x1 | 0x10 | 0x40 | 0x100 | 0x400;
    // `NETLINK_ROUTE` is protocol 0, which rustix takes as `None`.
    let fd = socket(AddressFamily::NETLINK, SocketType::RAW, None)
        .map_err(|e| format!("cannot open an rtnetlink socket: {e}"))?;
    bind(&fd, &netlink::SocketAddrNetlink::new(0, GROUPS)).map_err(|e| {
        format!("cannot subscribe to rtnetlink's link, address and route groups: {e}")
    })?;
    Ok(fd)
}

/// Elsewhere there is no socket this build reads (N-49: said once, by the daemon).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn open_socket() -> Result<OwnedFd, String> {
    Err(format!(
        "network changes are not detected on {}",
        std::env::consts::OS
    ))
}

/// Whether `bytes`, one read of the socket, holds an event of a kind N-49 names.
///
/// macOS: each message starts with `rtm_msglen` (u16) and `rtm_type` (byte 3); the kinds are
/// `RTM_ADD` (1), `RTM_DELETE` (2), `RTM_CHANGE` (3), `RTM_NEWADDR` (0xc), `RTM_DELADDR` (0xd)
/// and `RTM_IFINFO` (0xe) (`<net/route.h>`).
#[cfg(target_os = "macos")]
fn relevant(bytes: &[u8]) -> bool {
    const KINDS: [u8; 6] = [0x1, 0x2, 0x3, 0xc, 0xd, 0xe];
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let len = usize::from(u16::from_ne_bytes([bytes[at], bytes[at + 1]]));
        if KINDS.contains(&bytes[at + 3]) {
            return true;
        }
        if len == 0 {
            break;
        }
        at += len;
    }
    false
}

/// Linux: each message starts with `nlmsg_len` (u32) and `nlmsg_type` (u16); the kinds are
/// `RTM_NEWLINK` (16), `RTM_DELLINK` (17), `RTM_NEWADDR` (20), `RTM_DELADDR` (21),
/// `RTM_NEWROUTE` (24) and `RTM_DELROUTE` (25) (`<linux/rtnetlink.h>`).
#[cfg(target_os = "linux")]
fn relevant(bytes: &[u8]) -> bool {
    const KINDS: [u16; 6] = [16, 17, 20, 21, 24, 25];
    let mut at = 0;
    while at + 6 <= bytes.len() {
        let len = u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let kind = u16::from_ne_bytes([bytes[at + 4], bytes[at + 5]]);
        if KINDS.contains(&kind) {
            return true;
        }
        // Messages are aligned to four bytes (`NLMSG_ALIGN`).
        let Ok(len) = usize::try_from(len) else { break };
        if len == 0 {
            break;
        }
        at += (len + 3) & !3;
    }
    false
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn relevant(_bytes: &[u8]) -> bool {
    false
}
