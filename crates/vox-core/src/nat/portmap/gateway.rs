//! Default-gateway discovery for the port-mapping ladder (ADR-012, N-53).
//!
//! Port-mapping ([`crate::nat::portmap::map_port`]) needs the gateway address: the default
//! route's next hop, for IPv4 and IPv6. On Linux it is read from the kernel routing table at
//! `/proc/net/route` and `/proc/net/ipv6_route`; on macOS with an `RTM_GET` on a `PF_ROUTE`
//! socket ([`macos`]), as `route -n get default` asks. Both are safe code: a file parse, and a
//! routing message built and read as bytes. Elsewhere the RFC 7723 anycast address is the path.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

/// The PCP **anycast** address for IPv4 (RFC 7723 §2; IANA IPv4 Special-Purpose
/// Address Registry, `192.0.0.9/32` "Port Control Protocol Anycast").
///
/// A client that cannot read its routing table — or whose PCP server is not the
/// default router — sends here, and the on-path PCP server answers. This is what
/// keeps the port-mapping rungs alive on hosts where [`default_gateway_v4`] is
/// unavailable.
pub const PCP_ANYCAST_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 9);

/// The PCP **anycast** address for IPv6 (RFC 7723 §2; IANA IPv6 Special-Purpose
/// Address Registry, `2001:1::1/128` "Port Control Protocol Anycast").
pub const PCP_ANYCAST_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 1);

/// The conventional gateway address for a LAN IPv4: the same /24 with host `.1`.
///
/// RFC 6886 §3.2.1 notes clients commonly assume this; a wrong guess simply fails
/// that candidate (the request times out) and the next one is tried.
#[must_use]
pub fn conventional_gateway_v4(ip: Ipv4Addr) -> Ipv4Addr {
    let o = ip.octets();
    Ipv4Addr::new(o[0], o[1], o[2], 1)
}

/// The ordered addresses to try as the PCP/NAT-PMP server for a node whose IPv4
/// address is `ip`: the **real default route** first when the platform can be asked,
/// then the `.1` convention, then the RFC 7723 anycast address. Duplicates are
/// dropped, so a host whose real gateway *is* `.1` is asked once.
///
/// Every candidate is tried with the full retransmission schedule, so the list is
/// deliberately short: an unanswered candidate costs the schedule's ~3.75 s.
#[must_use]
pub fn server_candidates_v4(ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut out = Vec::with_capacity(3);
    if let Ok(gw) = default_gateway_v4() {
        out.push(gw);
    }
    for candidate in [conventional_gateway_v4(ip), PCP_ANYCAST_V4] {
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out
}

/// The ordered addresses to try as the PCP server for an IPv6 node, each with the
/// **scope id** to send it on (0 for a global address; the interface index for a
/// link-local next hop, which is what a router normally advertises).
///
/// There is no `.1` convention on IPv6 and no NAT-PMP: the real default route first,
/// then the RFC 7723 anycast address.
#[must_use]
pub fn server_candidates_v6() -> Vec<(Ipv6Addr, u32)> {
    let mut out = Vec::with_capacity(2);
    if let Ok(gw) = default_gateway_v6() {
        out.push(gw);
    }
    if !out.iter().any(|(ip, _)| *ip == PCP_ANYCAST_V6) {
        out.push((PCP_ANYCAST_V6, 0));
    }
    out
}

/// True for `fe80::/10`, the link-local unicast prefix.
///
/// `Ipv6Addr::is_unicast_link_local` is still unstable, and this is one mask.
// Linux-only: its one caller is the `/proc/net/ipv6_route` parser below, which is
// itself Linux-only.
#[cfg(target_os = "linux")]
#[must_use]
fn is_link_local(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// Discover the IPv6 default route's next hop from the OS routing table, with the
/// scope id needed to send to it.
///
/// On Linux, parses `/proc/net/ipv6_route` for the `::/0` route with the lowest
/// metric and returns its next hop; a link-local next hop is paired with the
/// kernel interface index read from `/sys/class/net/<iface>/ifindex`, because a
/// link-local address cannot be sent to without one. On other platforms the routing
/// table has no portable file interface and this returns
/// [`Error::PortMappingFailed`] — [`server_candidates_v6`] then relies on the RFC
/// 7723 anycast address, which exists for exactly this case.
#[cfg(target_os = "linux")]
pub fn default_gateway_v6() -> Result<(Ipv6Addr, u32)> {
    let table = std::fs::read_to_string("/proc/net/ipv6_route")
        .map_err(|_| Error::PortMappingFailed("gateway: cannot read /proc/net/ipv6_route"))?;
    let (gw, iface) = parse_proc_net_ipv6_route(&table).ok_or(Error::PortMappingFailed(
        "gateway: no IPv6 default route found",
    ))?;
    let scope = if is_link_local(gw) {
        interface_index(&iface).ok_or(Error::PortMappingFailed(
            "gateway: link-local next hop with no interface index",
        ))?
    } else {
        0
    };
    Ok((gw, scope))
}

/// The IPv6 default route's next hop on macOS, by `RTM_GET` ([`macos::default_route`]), with
/// the interface index a link-local next hop is sent on (N-53).
#[cfg(target_os = "macos")]
pub fn default_gateway_v6() -> Result<(Ipv6Addr, u32)> {
    match macos::default_route(true)? {
        Hop {
            addr: std::net::IpAddr::V6(a),
            index,
            ..
        } => Ok((a, if is_link_local_any(a) { index } else { 0 })),
        _ => Err(Error::PortMappingFailed(
            "gateway: no IPv6 default route found",
        )),
    }
}

/// Non-Linux, non-macOS fallback: see [`default_gateway_v6`].
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn default_gateway_v6() -> Result<(Ipv6Addr, u32)> {
    Err(Error::PortMappingFailed(
        "gateway: automatic IPv6 route discovery is Linux-only; the PCP anycast address is the portable path",
    ))
}

/// Parse the next hop and interface of the lowest-metric IPv6 default route from the
/// contents of `/proc/net/ipv6_route`.
///
/// Columns are whitespace-separated: `Destination DestPrefixLen Source
/// SrcPrefixLen NextHop Metric RefCnt Use Flags Iface`. Addresses are 32 hex digits
/// in **network** order (unlike the little-endian IPv4 table) and the metric is hex.
/// The default route has an all-zero destination with prefix length `00`; a route
/// with an unspecified next hop is on-link and cannot be a PCP server.
#[cfg(target_os = "linux")]
fn parse_proc_net_ipv6_route(contents: &str) -> Option<(Ipv6Addr, String)> {
    let mut best: Option<(u32, Ipv6Addr, String)> = None;
    for line in contents.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        if cols[0] != "00000000000000000000000000000000" || cols[1] != "00" {
            continue;
        }
        let Some(gw) = hex_to_ipv6(cols[4]) else {
            continue;
        };
        if gw.is_unspecified() {
            continue;
        }
        let Ok(metric) = u32::from_str_radix(cols[5], 16) else {
            continue;
        };
        match best {
            Some((bm, _, _)) if bm <= metric => {}
            _ => best = Some((metric, gw, cols[9].to_string())),
        }
    }
    best.map(|(_, gw, iface)| (gw, iface))
}

/// Decode 32 network-order hex digits (the `/proc/net/ipv6_route` field encoding)
/// into an [`Ipv6Addr`].
#[cfg(target_os = "linux")]
fn hex_to_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, o) in octets.iter_mut().enumerate() {
        *o = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(Ipv6Addr::from(octets))
}

/// The kernel interface index for `iface`, read from sysfs.
///
/// The name comes from the routing table, but it is still interpolated into a path,
/// so anything but a plain interface name is refused rather than escaped.
#[cfg(target_os = "linux")]
fn interface_index(iface: &str) -> Option<u32> {
    let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':');
    if iface.is_empty() || iface.len() > 16 || !iface.bytes().all(plain) {
        return None;
    }
    std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Discover the IPv4 default gateway from the OS routing table.
///
/// On Linux, parses `/proc/net/route` for the `0.0.0.0/0` default route and
/// returns its gateway address. On other platforms returns
/// [`Error::PortMappingFailed`] (the deployment supplies the gateway to
/// [`crate::nat::portmap::map_port`] directly).
#[cfg(target_os = "linux")]
pub fn default_gateway_v4() -> Result<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route")
        .map_err(|_| Error::PortMappingFailed("gateway: cannot read /proc/net/route"))?;
    parse_proc_net_route(&table).ok_or(Error::PortMappingFailed("gateway: no default route found"))
}

/// The IPv4 default route's next hop on macOS, by `RTM_GET` ([`macos::default_route`], N-53).
#[cfg(target_os = "macos")]
pub fn default_gateway_v4() -> Result<Ipv4Addr> {
    match macos::default_route(false)?.addr {
        std::net::IpAddr::V4(a) => Ok(a),
        std::net::IpAddr::V6(_) => Err(Error::PortMappingFailed("gateway: no default route found")),
    }
}

/// Non-Linux, non-macOS fallback: discovery is the deployment's responsibility.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn default_gateway_v4() -> Result<std::net::Ipv4Addr> {
    Err(Error::PortMappingFailed(
        "gateway: automatic discovery is Linux-only; supply the gateway explicitly",
    ))
}

/// Parse the gateway IPv4 of the default route (`Destination == 00000000`) from the
/// contents of `/proc/net/route`.
///
/// Each data line is tab-separated: `Iface Destination Gateway Flags RefCnt Use
/// Metric Mask MTU Window IRTT`. `Destination` and `Gateway` are little-endian hex
/// of the IPv4 address. The default route has `Destination == 00000000`; among
/// several, the lowest `Metric` wins.
#[cfg(target_os = "linux")]
fn parse_proc_net_route(contents: &str) -> Option<Ipv4Addr> {
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in contents.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _iface = cols.next()?;
        let dest = cols.next()?;
        let gateway = cols.next()?;
        let _flags = cols.next()?;
        let _refcnt = cols.next()?;
        let _use = cols.next()?;
        let metric = cols.next()?;
        if dest != "00000000" {
            continue;
        }
        let gw = hex_le_to_ipv4(gateway)?;
        let m: u32 = metric.parse().ok()?;
        if gw == Ipv4Addr::UNSPECIFIED {
            continue; // a default route with a 0.0.0.0 gateway is on-link, not a hop
        }
        match best {
            Some((bm, _)) if bm <= m => {}
            _ => best = Some((m, gw)),
        }
    }
    best.map(|(_, gw)| gw)
}

/// Decode an 8-hex-digit little-endian IPv4 (the `/proc/net/route` field encoding)
/// into an [`Ipv4Addr`].
#[cfg(target_os = "linux")]
fn hex_le_to_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    // Little-endian: the first hex pair is the lowest-order octet.
    Some(Ipv4Addr::from(raw.swap_bytes()))
}

/// A default route's next hop: its address, and the interface it leaves by (its name where the
/// platform says it, and its index).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    /// The next hop.
    pub addr: std::net::IpAddr,
    /// The interface's name (`en0`), when the platform names it.
    pub interface: Option<String>,
    /// The interface's index (0 when unknown).
    pub index: u32,
}

/// The default route's next hop for one family, as `vox status` names it (N-53, N-54): what the
/// operating system says, with its interface; `None` when there is no default route of that
/// family (or no way to ask).
#[must_use]
pub fn default_hop(v6: bool) -> Option<Hop> {
    #[cfg(target_os = "macos")]
    {
        macos::default_route(v6).ok()
    }
    #[cfg(not(target_os = "macos"))]
    {
        if v6 {
            default_gateway_v6().ok().map(|(a, index)| Hop {
                addr: std::net::IpAddr::V6(a),
                interface: None,
                index,
            })
        } else {
            default_gateway_v4().ok().map(|a| Hop {
                addr: std::net::IpAddr::V4(a),
                interface: None,
                index: 0,
            })
        }
    }
}

/// True for `fe80::/10`, on every platform (the Linux helper above is Linux-only).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn is_link_local_any(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// **The macOS routing table, asked as `route -n get default` asks it** (N-53): one `RTM_GET`
/// message written to a `PF_ROUTE` socket, naming the default destination (all zeros, netmask
/// all zeros), and the kernel's answer read back. The message is built and parsed as bytes, so
/// no `unsafe` is needed (the crate forbids it). Layouts are `<net/route.h>`'s and
/// `<net/if_dl.h>`'s, in the machine's byte order.
#[cfg(target_os = "macos")]
pub mod macos {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::Hop;
    use crate::error::{Error, Result};

    /// `struct rt_msghdr`'s size: ten 32-bit-aligned fields and `struct rt_metrics` (14 × u32).
    const RT_MSGHDR_LEN: usize = 92;
    const RTM_VERSION: u8 = 5;
    const RTM_GET: u8 = 4;
    const RTF_UP: i32 = 0x1;
    const RTF_GATEWAY: i32 = 0x2;
    const RTA_DST: i32 = 0x1;
    const RTA_GATEWAY: i32 = 0x2;
    const RTA_NETMASK: i32 = 0x4;
    const RTA_IFP: i32 = 0x10;
    const AF_INET: u8 = 2;
    const AF_LINK: u8 = 18;
    const AF_INET6: u8 = 30;
    /// How long the kernel's answer is waited for.
    const ANSWER_WITHIN: Duration = Duration::from_secs(1);

    /// A `sockaddr`'s space in a routing message: its length rounded up to 4 bytes, and 4 for a
    /// zero-length one (`ROUNDUP` in `<net/route.h>`).
    fn padded(len: usize) -> usize {
        if len == 0 {
            4
        } else {
            (len + 3) & !3
        }
    }

    /// The empty `sockaddr` of `family` (the destination and the netmask of a default route).
    fn zero_sockaddr(v6: bool) -> Vec<u8> {
        let len = if v6 { 28 } else { 16 };
        let mut sa = vec![0u8; len];
        sa[0] = u8::try_from(len).unwrap_or(16);
        sa[1] = if v6 { AF_INET6 } else { AF_INET };
        sa
    }

    /// The `RTM_GET` for the default route of one family, asking for its gateway and interface.
    fn request(v6: bool, seq: i32, pid: i32) -> Vec<u8> {
        let dst = zero_sockaddr(v6);
        let mask = zero_sockaddr(v6);
        // An empty link-level address, so the kernel answers with the route's interface (RTA_IFP).
        let mut ifp = vec![0u8; 20];
        ifp[0] = 20;
        ifp[1] = AF_LINK;
        let len = RT_MSGHDR_LEN + dst.len() + mask.len() + ifp.len();
        let mut m = vec![0u8; RT_MSGHDR_LEN];
        m[0..2].copy_from_slice(&u16::try_from(len).unwrap_or(0).to_ne_bytes());
        m[2] = RTM_VERSION;
        m[3] = RTM_GET;
        m[8..12].copy_from_slice(&(RTF_UP | RTF_GATEWAY).to_ne_bytes());
        m[12..16].copy_from_slice(&(RTA_DST | RTA_NETMASK | RTA_IFP).to_ne_bytes());
        m[16..20].copy_from_slice(&pid.to_ne_bytes());
        m[20..24].copy_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&dst);
        m.extend_from_slice(&mask);
        m.extend_from_slice(&ifp);
        m
    }

    /// Ask the routing table for the default route of one family (N-53).
    ///
    /// # Errors
    /// [`Error::PortMappingFailed`] when the socket cannot be opened, the kernel does not answer,
    /// there is no default route of that family (`route -n get` says "not in table"), or it leaves
    /// by an interface with no next hop.
    pub fn default_route(v6: bool) -> Result<Hop> {
        use rustix::net::{socket, sockopt, AddressFamily, SocketType};
        let fail = |what: &'static str| Error::PortMappingFailed(what);
        let fd = socket(AddressFamily::ROUTE, SocketType::RAW, None)
            .map_err(|_| fail("gateway: cannot open a routing socket"))?;
        sockopt::set_socket_timeout(&fd, sockopt::Timeout::Recv, Some(ANSWER_WITHIN))
            .map_err(|_| fail("gateway: cannot bound the routing socket"))?;
        let pid = i32::try_from(std::process::id()).unwrap_or(0);
        let seq = i32::from_ne_bytes(crate::identity::rng::random_array().unwrap_or([1, 0, 0, 0]))
            & 0x7fff_ffff;
        let msg = request(v6, seq, pid);
        rustix::io::write(&fd, &msg).map_err(|_| fail("gateway: no default route found"))?;
        let mut buf = vec![0u8; 2048];
        loop {
            let n = rustix::io::read(&fd, &mut buf[..])
                .map_err(|_| fail("gateway: the routing table did not answer"))?;
            let m = &buf[..n];
            if m.len() < RT_MSGHDR_LEN || m[2] != RTM_VERSION || m[3] != RTM_GET {
                continue;
            }
            let field = |at: usize| i32::from_ne_bytes([m[at], m[at + 1], m[at + 2], m[at + 3]]);
            if field(16) != pid || field(20) != seq {
                continue; // another process's answer, read on this socket too
            }
            if field(24) != 0 {
                return Err(fail("gateway: no default route found"));
            }
            return parse_answer(m);
        }
    }

    /// The gateway and interface out of a kernel `RTM_GET` answer.
    fn parse_answer(m: &[u8]) -> Result<Hop> {
        let fail = |what: &'static str| Error::PortMappingFailed(what);
        let addrs = i32::from_ne_bytes([m[12], m[13], m[14], m[15]]);
        let index = u32::from(u16::from_ne_bytes([m[4], m[5]]));
        let mut at = RT_MSGHDR_LEN;
        let (mut gateway, mut interface) = (None, None);
        for bit in 0..8 {
            if addrs & (1 << bit) == 0 {
                continue;
            }
            let Some(&len) = m.get(at) else { break };
            let len = usize::from(len);
            let sa = m.get(at..at + len.max(2)).unwrap_or(&[]);
            match (1 << bit, sa.get(1).copied()) {
                (RTA_GATEWAY, Some(AF_INET)) if sa.len() >= 8 => {
                    gateway = Some(IpAddr::V4(Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7])));
                }
                (RTA_GATEWAY, Some(AF_INET6)) if sa.len() >= 28 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&sa[8..24]);
                    // A link-local address carries its interface index in its second 16 bits
                    // inside the kernel (KAME): taken out, so the address is the one printed.
                    if o[0] == 0xfe && o[1] & 0xc0 == 0x80 {
                        o[2] = 0;
                        o[3] = 0;
                    }
                    gateway = Some(IpAddr::V6(Ipv6Addr::from(o)));
                }
                (RTA_IFP, Some(AF_LINK)) if sa.len() >= 8 => {
                    let nlen = usize::from(sa[5]);
                    interface = sa
                        .get(8..8 + nlen)
                        .and_then(|n| std::str::from_utf8(n).ok())
                        .map(str::to_owned);
                }
                _ => {}
            }
            at += padded(len);
        }
        let addr = gateway.ok_or(fail("gateway: the default route has no next hop"))?;
        Ok(Hop {
            addr,
            interface,
            index,
        })
    }
}

/// The environment variable [`test_gateways`] reads. **Test-only.**
#[cfg(feature = "test-knobs")]
pub const TEST_GATEWAY_ENV: &str = "VOX_TEST_GATEWAY";

/// **The gateway override, for proofs only** (ADR-012 N-58): a comma-separated list of PCP
/// server addresses (`127.0.0.1:40001,127.0.0.1:40002`) that replaces every candidate the
/// machine would ask — the default route, `.1`, the anycast addresses and UPnP's SSDP search —
/// so a proof's PCP stand-in is the only server asked. IPv4 entries are the IPv4 candidates and
/// IPv6 entries the pinhole's. Unset, empty or unparsable is `None`: the real candidates.
#[cfg(feature = "test-knobs")]
#[must_use]
pub fn test_gateways() -> Option<Vec<std::net::SocketAddr>> {
    let text = std::env::var(TEST_GATEWAY_ENV).ok()?;
    let list: Vec<std::net::SocketAddr> = text
        .split(',')
        .filter_map(|a| a.trim().parse().ok())
        .collect();
    (!list.is_empty()).then_some(list)
}

/// Without `test-knobs` there is no override: the real candidates, always.
#[cfg(not(feature = "test-knobs"))]
#[must_use]
pub fn test_gateways() -> Option<Vec<std::net::SocketAddr>> {
    None
}

/// The environment variable [`test_upnp`] reads. **Test-only.**
#[cfg(feature = "test-knobs")]
pub const TEST_UPNP_ENV: &str = "VOX_TEST_UPNP";

/// **The UPnP override, for proofs only** (ADR-012 N-58): the address (`127.0.0.1:40003`) of a
/// proof's SSDP stand-in, which UPnP's search is sent to by unicast in place of the multicast
/// group. With [`test_gateways`] set and this unset, UPnP is not asked at all.
#[cfg(feature = "test-knobs")]
#[must_use]
pub fn test_upnp() -> Option<std::net::SocketAddr> {
    std::env::var(TEST_UPNP_ENV).ok()?.trim().parse().ok()
}

/// Without `test-knobs` there is no override: UPnP searches the multicast group.
#[cfg(not(feature = "test-knobs"))]
#[must_use]
pub fn test_upnp() -> Option<std::net::SocketAddr> {
    None
}
