//! Just enough of IPv4 and IPv6 to route a packet on the family LAN: its version, its
//! source and its destination. Nothing above IP is read or changed, with one exception
//! ([`to_limited_broadcast`]); the payload — TCP, UDP, ICMP, whatever it is — crosses as
//! the bytes the operating system wrote.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The two addresses of one packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Who sent it.
    pub src: IpAddr,
    /// Where it goes.
    pub dst: IpAddr,
}

/// Read a packet's addresses, or `None` if it is not a whole IPv4 or IPv6 header.
#[must_use]
pub fn parse(p: &[u8]) -> Option<Header> {
    match p.first()? >> 4 {
        4 => {
            let ihl = usize::from(p[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([*p.get(2)?, *p.get(3)?]));
            if ihl < 20 || p.len() < ihl || total < ihl || total > p.len() {
                return None;
            }
            let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
            let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
            Some(Header {
                src: src.into(),
                dst: dst.into(),
            })
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&p[8..24]);
            d.copy_from_slice(&p[24..40]);
            Some(Header {
                src: Ipv6Addr::from(s).into(),
                dst: Ipv6Addr::from(d).into(),
            })
        }
        _ => None,
    }
}

/// Whether `ip` is a group address: `224.0.0.0/4`, `ff00::/8`, or the limited broadcast
/// `255.255.255.255` — anything every member of a LAN may be listening for.
#[must_use]
pub fn is_group(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_multicast(),
    }
}

fn sum16(data: &[u8]) -> u32 {
    data.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)])))
        .sum()
}

fn fold(mut s: u32) -> u16 {
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    // `s` is at most 0xffff here, so the conversion cannot fail.
    u16::try_from(s).unwrap_or(u16::MAX)
}

/// RFC 1624 eqn. 3: the checksum `hc` after the 16-bit words `old` became `new`.
fn adjust(hc: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut s = u32::from(!hc);
    for (o, n) in old.chunks(2).zip(new.chunks(2)) {
        s += u32::from(!u16::from_be_bytes([o[0], o[1]]));
        s += u32::from(u16::from_be_bytes([n[0], n[1]]));
    }
    !fold(s)
}

/// Whether an IPv4 packet's header checksum is right.
#[must_use]
pub fn ipv4_header_ok(p: &[u8]) -> bool {
    let ihl = usize::from(p.first().map_or(0, |b| b & 0x0f)) * 4;
    ihl >= 20 && p.len() >= ihl && fold(sum16(&p[..ihl])) == 0xffff
}

/// Whether an IPv4 UDP packet's UDP checksum is right (or absent, which IPv4 allows).
/// `None` if it is not an unfragmented IPv4 UDP packet.
#[must_use]
pub fn ipv4_udp_ok(p: &[u8]) -> Option<bool> {
    let ihl = usize::from(p.first()? & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([*p.get(2)?, *p.get(3)?]));
    if p.get(9) != Some(&17) || p.len() < total || total < ihl + 8 {
        return None;
    }
    // A fragment carries only part of the datagram its checksum covers.
    if u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0 {
        return None;
    }
    let udp = &p[ihl..total];
    if udp[6..8] == [0, 0] {
        return Some(true);
    }
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&p[12..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&u16::try_from(udp.len()).ok()?.to_be_bytes());
    Some(fold(sum16(&pseudo) + sum16(udp)) == 0xffff)
}

/// Rewrite an IPv4 packet sent to a subnet's broadcast address (`x.y.z.255`) so that it is
/// sent to the limited broadcast `255.255.255.255` instead, fixing the header checksum and,
/// for UDP, the UDP checksum (whose pseudo-header covers the destination).
///
/// ## Why rewrite anything
/// A macOS `utun` is a point-to-point interface. It has no broadcast address, so the
/// kernel does not recognise `x.y.z.255` arriving on it as addressed to this host, and a
/// game's "anyone on the LAN?" packet would be dropped at the last step. The limited
/// broadcast is accepted on every interface. Every socket that would have received the
/// subnet broadcast — one bound to the wildcard address on that port — receives the
/// limited one, so the program sees what it would have seen on a real LAN.
///
/// Returns whether the packet was rewritten. Only the first fragment of a fragmented
/// datagram holds the UDP header; the others are rewritten at the IP layer only.
pub fn to_limited_broadcast(p: &mut [u8]) -> bool {
    let Some(first) = p.first() else { return false };
    let ihl = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || ihl < 20 || p.len() < ihl {
        return false;
    }
    let old: [u8; 4] = [p[16], p[17], p[18], p[19]];
    let new = [255u8; 4];
    let hc = adjust(u16::from_be_bytes([p[10], p[11]]), &old, &new);
    p[10..12].copy_from_slice(&hc.to_be_bytes());
    p[16..20].copy_from_slice(&new);
    let offset = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
    if p[9] == 17 && offset == 0 && p.len() >= ihl + 8 {
        let at = ihl + 6;
        let uc = u16::from_be_bytes([p[at], p[at + 1]]);
        // Zero means "no checksum" in IPv4 UDP, and must stay zero.
        if uc != 0 {
            let mut c = adjust(uc, &old, &new);
            // A computed zero is sent as all ones (RFC 768).
            if c == 0 {
                c = 0xffff;
            }
            p[at..at + 2].copy_from_slice(&c.to_be_bytes());
        }
    }
    true
}
