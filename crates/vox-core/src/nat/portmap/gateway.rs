//! Default-gateway discovery for the port-mapping ladder (ADR-012).
//!
//! Port-mapping ([`crate::nat::portmap::map_port`]) needs the gateway address. On
//! Linux it can be read from the kernel routing table at `/proc/net/route` — a
//! pure file parse, no `unsafe`, no shelling out. On other platforms the routing
//! table has no portable file interface; the deployment supplies the gateway (the
//! host's default route or a config value), and `map_port` takes it explicitly, so
//! discovery is a convenience rather than a dependency.

#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;

use crate::error::{Error, Result};

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
    fn hex_le_decoding_is_correct() {
        assert_eq!(
            hex_le_to_ipv4("0100007F"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(hex_le_to_ipv4("bad"), None);
    }
}
