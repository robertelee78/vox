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
use std::net::IpAddr;
use std::time::Duration;

use rustix::fd::OwnedFd;
use tokio::io::unix::AsyncFd;

use crate::nat::portmap::gateway::Hop;

/// How long the events of one change are gathered after the last of them (N-50).
pub const NETWORK_SETTLE: Duration = Duration::from_millis(500);

/// What of the machine's network a peer depends on: the routable addresses the operating system
/// would use ([`crate::nat::reachability::local_route_ips`]) and the default routes' next hops.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetShape {
    /// The routable addresses, IPv6 first.
    pub addrs: Vec<IpAddr>,
    /// The IPv4 default route's next hop, where the platform says it.
    pub route_v4: Option<Hop>,
    /// The IPv6 default route's next hop, where the platform says it.
    pub route_v6: Option<Hop>,
    /// Whether the kernel answered for each route, IPv4 then IPv6. A lookup that got no answer
    /// is unknown, not "no route": compared as "none", it was a route that went away, and the
    /// node redialled everything for a network change that never happened.
    pub routes_known: (bool, bool),
}

impl NetShape {
    /// The machine's shape now.
    pub async fn now() -> Self {
        // The routes are asked of the kernel by a blocking read: off the async workers, so a slow
        // answer holds no worker (and with it the runtime's timers) while it comes.
        let (route_v4, route_v6) = tokio::task::spawn_blocking(|| {
            (
                route_v4_now(),
                known(crate::nat::portmap::gateway::default_path_result(true)),
            )
        })
        .await
        .unwrap_or((None, None));
        let routes_known = (route_v4.is_some(), route_v6.is_some());
        Self {
            addrs: crate::nat::reachability::local_route_ips().await,
            route_v4: route_v4.flatten(),
            route_v6: route_v6.flatten(),
            routes_known,
        }
    }

    /// This shape, with a route it does not know taken from `earlier`: what the watcher compares
    /// the next shape with, so an unanswered lookup does not hide a later change of that route.
    #[must_use]
    pub fn knowing(mut self, earlier: &NetShape) -> Self {
        if !self.routes_known.0 {
            self.route_v4.clone_from(&earlier.route_v4);
            self.routes_known.0 = earlier.routes_known.0;
        }
        if !self.routes_known.1 {
            self.route_v6.clone_from(&earlier.route_v6);
            self.routes_known.1 = earlier.routes_known.1;
        }
        self
    }
}

/// A route lookup's answer: `Some(Some(hop))`, `Some(None)` when the kernel said there is no
/// default route, and `None` when it said nothing (no answer, or a socket that would not open).
fn known<T>(r: crate::error::Result<T>) -> Option<Option<T>> {
    use crate::nat::portmap::gateway::{NO_NEXT_HOP, NO_ROUTE, NO_ROUTE_V6};
    match r {
        Ok(v) => Some(Some(v)),
        Err(crate::error::Error::PortMappingFailed(why))
            if why == NO_ROUTE || why == NO_ROUTE_V6 || why == NO_NEXT_HOP =>
        {
            Some(None)
        }
        Err(_) => None,
    }
}

/// The IPv4 default route's next hop now (see [`known`]), or the one a proof staged
/// ([`TEST_ROUTE_V4_FILE_ENV`]).
fn route_v4_now() -> Option<Option<Hop>> {
    #[cfg(feature = "test-knobs")]
    if let Some(staged) = test_route_v4() {
        return staged.map(|ip| {
            ip.map(|ip| Hop {
                addr: IpAddr::V4(ip),
                interface: None,
                index: 0,
            })
        });
    }
    known(crate::nat::portmap::gateway::default_path_result(false))
}

/// **Test-only: the IPv4 default route's next hop, read from a file** (`VOX_TEST_ROUTE_V4_FILE`, in a
/// build with the `test-knobs` feature; no shipped build reads it, V210-105). The file holds an
/// address or `none`; writing it stages a move of the machine's default route through the node's
/// own change path ([`NetWatch::settled`] wakes on it as on the operating system's event), with no
/// privilege and no real interface touched. `unanswered` stages a lookup the kernel did not
/// answer.
#[cfg(feature = "test-knobs")]
pub const TEST_ROUTE_V4_FILE_ENV: &str = "VOX_TEST_ROUTE_V4_FILE";

/// Optional real-binary apparatus: `unavailable` makes the OS observer fail at its
/// open/read boundary until the file changes. Packaged builds contain no such control.
#[cfg(feature = "test-knobs")]
pub const TEST_WATCH_FILE_ENV: &str = "VOX_TEST_NETWATCH_FILE";

#[cfg(feature = "test-knobs")]
fn test_watch_unavailable() -> bool {
    std::env::var_os(TEST_WATCH_FILE_ENV)
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_some_and(|value| value.trim() == "unavailable")
}

/// The lookup the [`TEST_ROUTE_V4_FILE_ENV`] file stages, as [`known`] gives it: `None` when the
/// knob is not set (the real route is read), `Some(None)` for `unanswered`, `Some(Some(None))` for
/// `none`.
#[cfg(feature = "test-knobs")]
fn test_route_v4() -> Option<Option<Option<std::net::Ipv4Addr>>> {
    let text = std::fs::read_to_string(std::env::var_os(TEST_ROUTE_V4_FILE_ENV)?).ok()?;
    match text.trim() {
        "unanswered" => Some(None),
        "none" => Some(Some(None)),
        ip => ip.parse().ok().map(|ip| Some(Some(ip))),
    }
}

/// A real change of the machine's network (N-50): what came, what went, and which default
/// routes moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetChange {
    /// When it was found, unix milliseconds.
    pub at: u64,
    /// Routable addresses the machine has now and did not before.
    pub came: Vec<IpAddr>,
    /// Routable addresses it had and has no longer.
    pub went: Vec<IpAddr>,
    /// Each default route that moved, said as `IPv4 default route a → b`.
    pub routes: Vec<String>,
    /// Families whose old path observations and gateway leases must be invalidated.
    pub affected: (bool, bool),
}

/// Evidence retained from a burst, including loss followed by restoration before its final
/// snapshot. Only losses of the active default path count; unrelated route chatter does not.
/// These sets summarize the event sequence without retaining an unbounded event log.
#[derive(Default)]
pub struct NetworkEvents {
    lost_links: BTreeSet<u32>,
    lost_routes: BTreeSet<(IpAddr, u32)>,
    lost_addrs: BTreeSet<IpAddr>,
    overflow: bool,
}

impl NetworkEvents {
    /// The watcher could not observe this interval. Revalidate active paths even if a move
    /// returned the same numeric addresses while no event reader was available.
    pub(crate) fn missed_interval() -> Self {
        Self {
            overflow: true,
            ..Self::default()
        }
    }

    fn lost(&self, route: &Option<Hop>) -> bool {
        route.as_ref().is_some_and(|hop| {
            self.overflow
                || self.lost_links.contains(&hop.index)
                || self.lost_routes.contains(&(hop.addr, hop.index))
        })
    }

    fn link_lost(&mut self, index: u32) {
        if self.lost_links.len() < 128 {
            self.lost_links.insert(index);
        } else {
            self.overflow = true;
        }
    }

    fn route_lost(&mut self, gateway: IpAddr, index: u32) {
        if self.lost_routes.len() < 128 {
            self.lost_routes.insert((gateway, index));
        } else {
            self.overflow = true;
        }
    }

    fn address_lost(&mut self, address: IpAddr) {
        if self.lost_addrs.len() < 128 {
            self.lost_addrs.insert(address);
        } else {
            self.overflow = true;
        }
    }
}

impl NetChange {
    /// The change from `before` to `after`, or `None` when neither the routable addresses nor a
    /// default route differ: a change that starts nothing (N-50).
    #[must_use]
    pub fn between(
        before: &NetShape,
        after: &NetShape,
        events: &NetworkEvents,
        at: u64,
    ) -> Option<Self> {
        let (old, new): (BTreeSet<IpAddr>, BTreeSet<IpAddr>) = (
            before.addrs.iter().copied().collect(),
            after.addrs.iter().copied().collect(),
        );
        let came: Vec<IpAddr> = new.difference(&old).copied().collect();
        let went: Vec<IpAddr> = old.difference(&new).copied().collect();
        let mut routes = Vec::new();
        let said = |route: &Option<Hop>| {
            route.as_ref().map_or_else(
                || "none".to_owned(),
                |hop| {
                    if hop.addr.is_unspecified() {
                        "on-link".into()
                    } else {
                        hop.addr.to_string()
                    }
                },
            )
        };
        let path =
            |route: &Option<Hop>| route.as_ref().map(|hop| (hop.interface.clone(), hop.index));
        let path_said = |route: &Option<Hop>| {
            route.as_ref().map_or_else(
                || "none".to_owned(),
                |hop| {
                    format!(
                        "{} (index {})",
                        hop.interface.as_deref().unwrap_or("unknown interface"),
                        hop.index
                    )
                },
            )
        };
        let lost_v4 = events.lost(&before.route_v4)
            || before
                .addrs
                .iter()
                .any(|a| a.is_ipv4() && events.lost_addrs.contains(a));
        let lost_v6 = events.lost(&before.route_v6)
            || before
                .addrs
                .iter()
                .any(|a| a.is_ipv6() && events.lost_addrs.contains(a));
        let moved_v4 =
            before.routes_known.0 && after.routes_known.0 && before.route_v4 != after.route_v4;
        let moved_v6 =
            before.routes_known.1 && after.routes_known.1 && before.route_v6 != after.route_v6;
        // A route compared only where both looks got an answer (see `NetShape::routes_known`).
        if moved_v4 {
            routes.push(format!(
                "IPv4 default route {} → {}",
                said(&before.route_v4),
                said(&after.route_v4)
            ));
        }
        if moved_v6 {
            routes.push(format!(
                "IPv6 default route {} → {}",
                said(&before.route_v6),
                said(&after.route_v6)
            ));
        }
        for (family, old, new, moved) in [
            ("IPv4", &before.route_v4, &after.route_v4, moved_v4),
            ("IPv6", &before.route_v6, &after.route_v6, moved_v6),
        ] {
            if moved && path(old) != path(new) {
                routes.push(format!(
                    "{family} default path {} → {}",
                    path_said(old),
                    path_said(new)
                ));
            }
        }
        if lost_v4 && !moved_v4 {
            routes.push(format!(
                "IPv4 active path {}: {}",
                if events.overflow {
                    "requires revalidation after missed events"
                } else {
                    "interrupted"
                },
                said(&before.route_v4)
            ));
        }
        if lost_v6 && !moved_v6 {
            routes.push(format!(
                "IPv6 active path {}: {}",
                if events.overflow {
                    "requires revalidation after missed events"
                } else {
                    "interrupted"
                },
                said(&before.route_v6)
            ));
        }
        if came.is_empty() && went.is_empty() && routes.is_empty() {
            return None;
        }
        let affected = (
            moved_v4 || lost_v4 || came.iter().chain(&went).any(IpAddr::is_ipv4),
            moved_v6 || lost_v6 || came.iter().chain(&went).any(IpAddr::is_ipv6),
        );
        Some(Self {
            at,
            came,
            went,
            routes,
            affected,
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
        #[cfg(feature = "test-knobs")]
        if test_watch_unavailable() {
            return Err("network observer unavailable (proof apparatus)".to_owned());
        }
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
    ///
    /// **Only a relevant event extends the wait** (#413). macOS writes the routing socket far more
    /// than the kinds counted here: measured idle, 143 reads in 20 s, mostly `RTM_LOSING` and
    /// `RTM_MISS`, 138 of them under 500 ms apart, and more while a connection to a removed
    /// address keeps missing. Any read restarted the wait, so a burst was not "settled" until
    /// the machine went quiet for [`NETWORK_SETTLE`], which it may not do for as long as that
    /// connection lasts: a move to another network was never noticed, and nothing was redialled.
    pub async fn settled(&mut self) -> std::io::Result<NetworkEvents> {
        #[cfg(feature = "test-knobs")]
        {
            let seen = test_route_v4();
            let staged = async {
                if std::env::var_os(TEST_ROUTE_V4_FILE_ENV).is_none() {
                    std::future::pending::<()>().await;
                }
                while test_route_v4() == seen {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            };
            let unavailable = async {
                if std::env::var_os(TEST_WATCH_FILE_ENV).is_none() {
                    std::future::pending::<()>().await;
                }
                while !test_watch_unavailable() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            };
            return tokio::select! {
                r = self.settled_os() => r,
                () = staged => Ok(NetworkEvents::default()),
                () = unavailable => Err(std::io::Error::other("network observer read failed (proof apparatus)")),
            };
        }
        #[cfg(not(feature = "test-knobs"))]
        self.settled_os().await
    }

    /// [`NetWatch::settled`] on the operating system's events alone.
    async fn settled_os(&mut self) -> std::io::Result<NetworkEvents> {
        let mut events = NetworkEvents::default();
        while !self.read_relevant(&mut events).await? {}
        let mut quiet_from = tokio::time::Instant::now() + NETWORK_SETTLE;
        loop {
            match tokio::time::timeout_at(quiet_from, self.read_relevant(&mut events)).await {
                Err(_) => return Ok(events),
                Ok(Ok(true)) => quiet_from = tokio::time::Instant::now() + NETWORK_SETTLE,
                Ok(Ok(false)) => {}
                Ok(Err(e)) => return Err(e),
            }
        }
    }

    /// Read what is waiting: whether any of it is an event of the kinds N-49 names.
    async fn read_relevant(&mut self, events: &mut NetworkEvents) -> std::io::Result<bool> {
        loop {
            let mut ready = self.fd.readable().await?;
            match ready.try_io(|fd| {
                rustix::io::read(fd.get_ref(), &mut self.buf[..]).map_err(std::io::Error::from)
            }) {
                Ok(Ok(0)) => {
                    return Err(std::io::Error::other("the network event socket closed"));
                }
                Ok(Ok(n)) => return Ok(relevant(&self.buf[..n], events)),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {}
                // A burst the kernel could not queue for us is still a burst.
                Ok(Err(e))
                    if e.raw_os_error() == Some(rustix::io::Errno::NOBUFS.raw_os_error()) =>
                {
                    events.overflow = true;
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
fn relevant(bytes: &[u8], events: &mut NetworkEvents) -> bool {
    const KINDS: [u8; 6] = [0x1, 0x2, 0x3, 0xc, 0xd, 0xe];
    let mut at = 0;
    let mut found = false;
    while at + 4 <= bytes.len() {
        let len = usize::from(u16::from_ne_bytes([bytes[at], bytes[at + 1]]));
        if len < 4 || at + len > bytes.len() {
            break;
        }
        let msg = &bytes[at..at + len];
        let kind = msg[3];
        if KINDS.contains(&kind) {
            found = true;
        }
        // if_msghdr: flags at 8, interface index at 12. Keep the down event even if a
        // later RTM_IFINFO restores the same address and interface in this read/batch.
        if kind == 0xe && msg.len() >= 14 {
            let flags = u32::from_ne_bytes(msg[8..12].try_into().unwrap_or_default());
            if flags & 0x41 != 0x41 {
                events.link_lost(u32::from(u16::from_ne_bytes([msg[12], msg[13]])));
            }
        }
        if let Some(path) = crate::nat::portmap::gateway::macos::withdrawn_default(msg) {
            events.route_lost(path.addr, path.index);
        }
        // ifa_msghdr is 20 bytes; RTA_IFA is bit 5. Preserve address removal even if the
        // address is restored before the settled snapshot and the interface never goes down.
        if kind == 0xd && msg.len() >= 20 {
            let addrs = u32::from_ne_bytes(msg[4..8].try_into().unwrap_or_default());
            let mut pos = 20;
            for bit in 0..8 {
                if addrs & (1 << bit) == 0 {
                    continue;
                }
                let Some(&len) = msg.get(pos) else {
                    break;
                };
                let len = usize::from(len);
                let Some(sa) = msg.get(pos..pos + len) else {
                    break;
                };
                if bit == 5 {
                    match sa.get(1).copied() {
                        Some(2) if sa.len() >= 8 => events.address_lost(IpAddr::V4(
                            std::net::Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]),
                        )),
                        Some(30) if sa.len() >= 24 => {
                            let mut bytes: [u8; 16] = sa[8..24].try_into().unwrap_or_default();
                            if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 {
                                bytes[2] = 0;
                                bytes[3] = 0;
                            }
                            events.address_lost(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
                        }
                        _ => {}
                    }
                }
                pos += if len == 0 { 4 } else { (len + 3) & !3 };
            }
        }
        if len == 0 {
            break;
        }
        at += len;
    }
    found
}

/// Linux: each message starts with `nlmsg_len` (u32) and `nlmsg_type` (u16); the kinds are
/// `RTM_NEWLINK` (16), `RTM_DELLINK` (17), `RTM_NEWADDR` (20), `RTM_DELADDR` (21),
/// `RTM_NEWROUTE` (24) and `RTM_DELROUTE` (25) (`<linux/rtnetlink.h>`).
#[cfg(target_os = "linux")]
fn relevant(bytes: &[u8], events: &mut NetworkEvents) -> bool {
    const KINDS: [u16; 6] = [16, 17, 20, 21, 24, 25];
    let mut at = 0;
    let mut found = false;
    while at + 6 <= bytes.len() {
        let len = u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let kind = u16::from_ne_bytes([bytes[at + 4], bytes[at + 5]]);
        // Messages are aligned to four bytes (`NLMSG_ALIGN`).
        let Ok(len) = usize::try_from(len) else { break };
        if len < 16 || at + len > bytes.len() {
            break;
        }
        let msg = &bytes[at..at + len];
        found |= KINDS.contains(&kind);
        if kind == 21 && msg.len() >= 24 {
            let mut pos = 24;
            while pos + 4 <= msg.len() {
                let size = usize::from(u16::from_ne_bytes([msg[pos], msg[pos + 1]]));
                let attr = u16::from_ne_bytes([msg[pos + 2], msg[pos + 3]]);
                if size < 4 || pos + size > msg.len() {
                    break;
                }
                let value = &msg[pos + 4..pos + size];
                if matches!(attr, 1 | 2) {
                    match (msg[16], value.len()) {
                        (2, 4) => events.address_lost(IpAddr::V4(std::net::Ipv4Addr::new(
                            value[0], value[1], value[2], value[3],
                        ))),
                        (10, 16) => events.address_lost(IpAddr::V6(std::net::Ipv6Addr::from(
                            <[u8; 16]>::try_from(value).unwrap_or_default(),
                        ))),
                        _ => {}
                    }
                }
                pos += (size + 3) & !3;
            }
        }
        if (kind == 16 || kind == 17) && msg.len() >= 32 {
            let index = u32::from_ne_bytes(msg[20..24].try_into().unwrap_or_default());
            let flags = u32::from_ne_bytes(msg[24..28].try_into().unwrap_or_default());
            if kind == 17 || flags & 0x41 != 0x41 {
                events.link_lost(index);
            }
        }
        // rtmsg: family, destination prefix length, table; RTA_OIF names the outgoing
        // interface. Only default-route withdrawals can interrupt that family's active path.
        if kind == 25 && msg.len() >= 28 && msg[17] == 0 && matches!(msg[16], 2 | 10) {
            let mut pos = 28;
            let mut table = u32::from(msg[20]);
            let mut interface = None;
            let mut gateway = if msg[16] == 10 {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            };
            while pos + 4 <= msg.len() {
                let size = usize::from(u16::from_ne_bytes([msg[pos], msg[pos + 1]]));
                let attr = u16::from_ne_bytes([msg[pos + 2], msg[pos + 3]]);
                if size < 4 || pos + size > msg.len() {
                    break;
                }
                let value = &msg[pos + 4..pos + size];
                match (attr, value.len()) {
                    (4, 4) => {
                        interface = Some(u32::from_ne_bytes(value.try_into().unwrap_or_default()))
                    }
                    (5, 4) if msg[16] == 2 => {
                        gateway = IpAddr::V4(std::net::Ipv4Addr::new(
                            value[0], value[1], value[2], value[3],
                        ))
                    }
                    (5, 16) if msg[16] == 10 => {
                        gateway = IpAddr::V6(std::net::Ipv6Addr::from(
                            <[u8; 16]>::try_from(value).unwrap_or_default(),
                        ))
                    }
                    (15, 4) => table = u32::from_ne_bytes(value.try_into().unwrap_or_default()),
                    _ => {}
                }
                pos += (size + 3) & !3;
            }
            if table == 254 {
                if let Some(index) = interface {
                    events.route_lost(gateway, index);
                }
            }
        }
        at += (len + 3) & !3;
    }
    found
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn relevant(_bytes: &[u8], _events: &mut NetworkEvents) -> bool {
    false
}
