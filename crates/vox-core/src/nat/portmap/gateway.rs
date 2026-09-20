//! Default-gateway discovery for the port-mapping ladder (ADR-012).
//!
//! Port-mapping ([`crate::nat::portmap::map_port`]) needs the gateway address. On
//! Linux it can be read from the kernel routing table at `/proc/net/route` — a
//! pure file parse, no `unsafe`, no shelling out. On other platforms the routing
//! table has no portable file interface; the deployment supplies the gateway (the
//! host's default route or a config value), and `map_port` takes it explicitly, so
//! discovery is a convenience rather than a dependency.

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
#[cfg(any(target_os = "linux", test))]
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

/// Non-Linux fallback: see [`default_gateway_v6`].
#[cfg(not(target_os = "linux"))]
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

/// Non-Linux fallback: discovery is the deployment's responsibility.
#[cfg(not(target_os = "linux"))]
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

#[cfg(test)]
mod portable_tests {
    use super::*;

    #[test]
    fn anycast_addresses_are_the_registered_ones() {
        // RFC 7723 §2 / IANA special-purpose registries.
        assert_eq!(PCP_ANYCAST_V4, "192.0.0.9".parse::<Ipv4Addr>().unwrap());
        assert_eq!(PCP_ANYCAST_V6, "2001:1::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn conventional_gateway_is_the_first_host_of_the_slash_24() {
        assert_eq!(
            conventional_gateway_v4(Ipv4Addr::new(10, 42, 7, 93)),
            Ipv4Addr::new(10, 42, 7, 1)
        );
    }

    #[test]
    fn candidates_are_deduplicated_and_end_at_the_anycast_address() {
        let list = server_candidates_v4(Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(list.last(), Some(&PCP_ANYCAST_V4));
        assert!(list.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        let mut sorted = list.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            list.len(),
            "no candidate is asked twice: {list:?}"
        );

        let v6 = server_candidates_v6();
        assert_eq!(v6.last().map(|(ip, _)| *ip), Some(PCP_ANYCAST_V6));
        assert!(v6.iter().all(|(ip, _)| !ip.is_unspecified()));
    }

    #[test]
    fn link_local_prefix_is_recognised() {
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(is_link_local("febf::1".parse().unwrap()));
        assert!(!is_link_local("fec0::1".parse().unwrap()));
        assert!(!is_link_local("2001:db8::1".parse().unwrap()));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_default_route_gateway() {
        // 0102A8C0 little-endian = C0.A8.02.01 = 192.168.2.1.
        let table =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t0002A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            parse_proc_net_route(table),
            Some(Ipv4Addr::new(192, 168, 2, 1))
        );
    }

    #[test]
    fn lowest_metric_default_route_wins() {
        let table =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
            wlan0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
            eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        // eth0 (metric 100) → 0101A8C0 LE = 192.168.1.1 wins over wlan0 (metric 600).
        assert_eq!(
            parse_proc_net_route(table),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn no_default_route_returns_none() {
        let table =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
            eth0\t0002A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route(table), None);
    }

    #[test]
    fn parses_ipv6_default_route_and_prefers_the_lowest_metric() {
        let table = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000003 wlan0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000100 00000000 00000000 00000003 eth0
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0
";
        assert_eq!(
            parse_proc_net_ipv6_route(table),
            Some((
                "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
                "eth0".to_string()
            ))
        );
    }

    #[test]
    fn on_link_ipv6_default_route_is_not_a_next_hop() {
        let table = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000000 00000000 00000001 eth0
";
        assert_eq!(parse_proc_net_ipv6_route(table), None);
    }

    #[test]
    fn ipv6_hex_decoding_is_network_order() {
        assert_eq!(
            hex_to_ipv6("20010db8000000000000000000000001"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(hex_to_ipv6("2001"), None);
        assert_eq!(hex_to_ipv6("zz010db8000000000000000000000001"), None);
    }

    #[test]
    fn interface_names_that_could_escape_sysfs_are_refused() {
        assert_eq!(interface_index("../../etc/passwd"), None);
        assert_eq!(interface_index(""), None);
        // A real one: the loopback interface is index 1 on Linux.
        assert_eq!(interface_index("lo"), Some(1));
    }

    #[test]
    fn hex_le_decoding_is_correct() {
        assert_eq!(
            hex_le_to_ipv4("0100007F"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(hex_le_to_ipv4("bad"), None);
    }
}
