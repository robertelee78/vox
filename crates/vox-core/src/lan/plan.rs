//! The family LAN's addresses (ADR-013 §"The family LAN", PRD-001 R28): one IPv4 /24 and
//! one IPv6 /64 per room, and one address of each per member, computed by every node from
//! nothing but the room's id and its member list.
//!
//! ## Why computed, not allocated
//! There is nobody to allocate from. A DHCP server would be one member's node deciding for
//! everybody, and it would have to be up for anyone to get an address. Deriving the plan
//! from the room means any two nodes holding the same member list hold the same plan, with
//! no message exchanged — the same reason ADR-013's overlay address is derived.
//!
//! ## Why a room-scoped plan, not ADR-013's overlay address
//! ADR-013's `fd…/128` is one address per identity, the same in every room. A LAN needs the
//! opposite: an **on-link prefix** the room's members share, so that software which asks
//! "is this peer on my subnet?" — every discovery protocol does — says yes. And an address
//! derived per room does not tie one member's presence in two rooms together: the same
//! person has unrelated addresses in *family* and in *work*.
//!
//! ## IPv4: `100.64.0.0/10`, one /24 per room
//! The shared address space of RFC 6598 is the one IPv4 range that is neither public nor the
//! RFC 1918 space a home router hands out, so a LAN here collides with neither the Internet
//! nor the house. It is also Tailscale's range; a clash is a route that already exists,
//! which `vox lan up` reports rather than overwrites. The room picks one of its 16 384 /24s
//! by hash. Hosts `.1`–`.254` go to members; `.0` and `.255` are the network and the
//! broadcast address, as on any /24.
//!
//! 254 hosts is the one place a hash is not enough: ten members already collide on one
//! host number with a probability near one in six. So each member has a **preferred** host
//! from its own hash, and collisions are settled in a fixed order — members ranked by that
//! same hash, each taking its preferred host or the next free one. Every node computes the
//! same order, so every node settles every collision the same way. The cost is honest and
//! stated: a member whose preferred host was taken can be moved by a later joiner that ranks
//! before it. A member past the 254th has no IPv4 address; IPv6 has room for everyone.
//!
//! ## IPv6: an RFC 4193 /64 per room
//! `fd` ‖ 40 bits of the room's hash ‖ subnet 0, and a 64-bit interface id from the member's
//! hash. Unlike ADR-013's overlay address this one **is** RFC 4193-shaped, because here it
//! sits on a real interface next to other software's addresses. 64 bits of hash per room
//! make a collision negligible, so there is no probing.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::hash::{domain_hash, Digest32};

/// The IPv4 pool every room's /24 is taken from: `100.64.0.0/10` (RFC 6598).
pub const V4_POOL: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);

/// How many /24s the pool holds.
pub const V4_SUBNETS: u32 = 1 << 14;

/// The highest host number a member can hold (`.255` is the broadcast address).
pub const V4_HOSTS: u8 = 254;

const ROOM_V4: &str = "vox/lan/v4/room/v1";
const ROOM_V6: &str = "vox/lan/v6/room/v1";
const MEMBER_V4: &str = "vox/lan/v4/member/v1";
const MEMBER_V6: &str = "vox/lan/v6/member/v1";

/// One member's addresses on its room's LAN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberAddrs {
    /// `None` past the 254th member.
    pub v4: Option<Ipv4Addr>,
    /// Always present.
    pub v6: Ipv6Addr,
}

impl MemberAddrs {
    /// Whether `ip` is one of this member's addresses.
    #[must_use]
    pub fn holds(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => self.v4 == Some(a),
            IpAddr::V6(a) => self.v6 == a,
        }
    }
}

/// A room's LAN: its two prefixes and every member's addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanPlan {
    /// The room.
    pub channel_id: Digest32,
    /// The /24's network address.
    pub subnet_v4: Ipv4Addr,
    /// The /64's network address.
    pub prefix_v6: Ipv6Addr,
    /// Every member's addresses, in fingerprint order.
    pub members: BTreeMap<Digest32, MemberAddrs>,
}

fn rank(label: &str, channel_id: &Digest32, member: &Digest32) -> Digest32 {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(channel_id);
    data[32..].copy_from_slice(member);
    domain_hash(label, &data)
}

/// The room's /24: `100.64.0.0/10` plus the room's hash, modulo the 16 384 subnets.
#[must_use]
pub fn subnet_v4(channel_id: &Digest32) -> Ipv4Addr {
    let h = domain_hash(ROOM_V4, channel_id);
    let index = u32::from(u16::from_be_bytes([h[0], h[1]])) % V4_SUBNETS;
    Ipv4Addr::from(u32::from(V4_POOL) + (index << 8))
}

/// The room's /64: `fd` ‖ 40 bits of the room's hash ‖ subnet 0.
#[must_use]
pub fn prefix_v6(channel_id: &Digest32) -> Ipv6Addr {
    let h = domain_hash(ROOM_V6, channel_id);
    let mut o = [0u8; 16];
    o[0] = 0xfd;
    o[1..6].copy_from_slice(&h[..5]);
    Ipv6Addr::from(o)
}

/// A member's IPv6 address in the room: the room's /64 and 64 bits of the member's hash.
#[must_use]
pub fn member_v6(channel_id: &Digest32, member: &Digest32) -> Ipv6Addr {
    let mut o = prefix_v6(channel_id).octets();
    let h = rank(MEMBER_V6, channel_id, member);
    o[8..].copy_from_slice(&h[..8]);
    // The all-zero interface id is the subnet-router anycast address (RFC 4291 §2.6.1).
    if o[8..].iter().all(|b| *b == 0) {
        o[15] = 1;
    }
    Ipv6Addr::from(o)
}

impl LanPlan {
    /// The plan for `channel_id` with these members. Order and duplicates in `members` do
    /// not matter: the plan depends on the set.
    #[must_use]
    pub fn new(channel_id: Digest32, members: &[Digest32]) -> Self {
        let subnet = subnet_v4(&channel_id);
        let mut ranked: Vec<(Digest32, Digest32)> = members
            .iter()
            .map(|m| (rank(MEMBER_V4, &channel_id, m), *m))
            .collect();
        ranked.sort_unstable();
        ranked.dedup();
        let mut taken = [false; 256];
        let mut out = BTreeMap::new();
        for (h, m) in ranked {
            let preferred = u16::from_be_bytes([h[0], h[1]]) % u16::from(V4_HOSTS);
            let host = (0..u16::from(V4_HOSTS))
                .map(|k| 1 + (preferred + k) % u16::from(V4_HOSTS))
                .find(|host| !taken[usize::from(*host)]);
            let v4 = host.map(|host| {
                taken[usize::from(host)] = true;
                Ipv4Addr::from(u32::from(subnet) + u32::from(host))
            });
            out.insert(
                m,
                MemberAddrs {
                    v4,
                    v6: member_v6(&channel_id, &m),
                },
            );
        }
        Self {
            channel_id,
            subnet_v4: subnet,
            prefix_v6: prefix_v6(&channel_id),
            members: out,
        }
    }

    /// `member`'s addresses, if it is a member.
    #[must_use]
    pub fn of(&self, member: &Digest32) -> Option<&MemberAddrs> {
        self.members.get(member)
    }

    /// The member holding `ip`.
    #[must_use]
    pub fn owner(&self, ip: IpAddr) -> Option<Digest32> {
        self.members
            .iter()
            .find(|(_, a)| a.holds(ip))
            .map(|(m, _)| *m)
    }

    /// The /24's broadcast address (`.255`).
    #[must_use]
    pub fn broadcast_v4(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.subnet_v4) | 0xff)
    }

    /// Whether `ip` is inside the room's /24.
    #[must_use]
    pub fn in_subnet_v4(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & 0xffff_ff00 == u32::from(self.subnet_v4)
    }

    /// Whether `ip` is inside the room's /64.
    #[must_use]
    pub fn in_prefix_v6(&self, ip: Ipv6Addr) -> bool {
        ip.octets()[..8] == self.prefix_v6.octets()[..8]
    }
}
