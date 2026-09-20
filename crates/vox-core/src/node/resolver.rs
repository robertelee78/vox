//! Resolving `.vox` names on this machine (ADR-017 decisions 4 and 5, M17.3).
//!
//! `ssh user@<52-char-base32>.vox` reaches the local SOCKS proxy with the **name**, not
//! an address (`socks5h`: the proxy resolves it). This module is what the proxy resolves
//! it with.
//!
//! ## Nothing is looked up off the machine
//! A name resolves from data this node already holds, or not at all:
//!
//! 1. the 52 characters decode to a **channelID** — nothing is consulted to learn it,
//!    because the name *is* the identifier ([`crate::node::link::channel_of_hostname`]);
//! 2. that channelID names a room this node has joined, whose **genesis** it holds;
//! 3. the genesis names the room's creator, which is its host, and that is who to dial.
//!
//! So the chain is self-certifying end to end: the name commits to the room by hash and
//! the room commits to the host by the signed genesis. There is no directory, no
//! registration, no trust-on-first-use and no global namespace — and a name for a room
//! this machine has not joined does not resolve *at all*, which is strictly more than Tor
//! offers, where any `.onion` is resolvable by anyone.
//!
//! ## Why the host is the genesis creator
//! A service room is created by the machine that offers the service (`vox serve`,
//! ADR-017 decision 4), so its creator *is* its host — and the creator is the one fact
//! about a room that is immutable, self-validating and known to every member with no
//! extra state and no advertisement to wait for.
//!
//! This holds **only for a room that carries a genesis service grant**. In a chat room
//! with a service added later the host may be any member, which the genesis does not say,
//! so such a room has no `.vox` name and is reached with `vox forward <member>/<tag>`
//! (ADR-017 decision 4). [`VoxResolver`] therefore refuses to name a room without a grant
//! rather than guessing at its creator.
//!
//! ## No DNS, because the proxy does not need it
//! Tor's client side offers three mechanisms (`doc/man/tor.1.txt`): `SocksPort`,
//! unprivileged and requiring the tool to be proxy-aware; `DNSPort` +
//! `AutomapHostsOnResolve`, which hands out a virtual address per name; and `TransPort`,
//! which "requires OS support for transparent proxies, such as BSDs' pf or Linux's
//! IPTables". Vox takes the first, which is Tor's own documented default — and under it a
//! `.vox` name never goes near a resolver, because SOCKS5 carries the hostname itself.
//! The derived overlay address ([`ServiceRoom::addr`]) is kept because it is the stable
//! identifier for a host on the overlay (ADR-013), not because anything resolves to it.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use crate::governance::genesis::Genesis;
use crate::hash::Digest32;
use crate::node::link::channel_of_hostname;
use crate::tunnel::addr::overlay_addr;

/// A room that has a `.vox` name: the room itself, and the member its name resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRoom {
    /// The room.
    pub channel_id: Digest32,
    /// The member hosting it — the genesis creator (see the module docs).
    pub host: Digest32,
    /// The host's ADR-013 identity-derived overlay address, which is what the name
    /// resolves to and what the interface routes.
    pub addr: Ipv6Addr,
}

/// The `.vox` names this machine can resolve, and the reverse map the interface needs.
///
/// Built from the rooms a node holds; it is a snapshot, so a room joined afterwards is
/// not resolvable until the next one is taken. That is deliberate — the resolver must
/// never reach back into live channel state while answering an untrusted datagram.
#[derive(Debug, Clone, Default)]
pub struct VoxResolver {
    by_channel: BTreeMap<Digest32, ServiceRoom>,
    by_addr: BTreeMap<Ipv6Addr, ServiceRoom>,
}

impl VoxResolver {
    /// An empty resolver: every name is `NXDOMAIN`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a room by its genesis, if it is a service room.
    ///
    /// Returns whether it was added. A room whose genesis carries no service grant is
    /// **not** added: its host is not determined by the genesis, so there is no name to
    /// give it (see the module docs).
    pub fn insert(&mut self, genesis: &Genesis) -> bool {
        if genesis.body.service_grant.is_empty() {
            return false;
        }
        let key = genesis.creator_pubkey();
        let room = ServiceRoom {
            channel_id: genesis.channel_id(),
            host: key.fingerprint(),
            addr: overlay_addr(&key.to_bytes()),
        };
        self.by_channel.insert(room.channel_id, room);
        self.by_addr.insert(room.addr, room);
        true
    }

    /// The room a `.vox` hostname names, or `None` for a name this machine cannot
    /// resolve — a malformed one, or a room it has not joined.
    ///
    /// The whole room rather than just an address, because that is what a dial needs: the
    /// channel to claim a capability in and the member to dial.
    #[must_use]
    pub fn resolve(&self, hostname: &str) -> Option<&ServiceRoom> {
        let channel_id = channel_of_hostname(hostname).ok()?;
        self.by_channel.get(&channel_id)
    }

    /// The room an overlay address belongs to — the lookup the interface performs when
    /// a packet arrives for one of these addresses.
    #[must_use]
    pub fn route(&self, addr: &Ipv6Addr) -> Option<&ServiceRoom> {
        self.by_addr.get(addr)
    }

    /// Every address this resolver answers for, which is the set the interface must
    /// accept packets for.
    pub fn addresses(&self) -> impl Iterator<Item = &Ipv6Addr> {
        self.by_addr.keys()
    }

    /// How many rooms have a name here.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_channel.len()
    }

    /// Whether no room has a name here.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_channel.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::capability::{Capability, CapabilitySet};
    use crate::governance::genesis::{ChannelPolicy, DeniabilityMode, HistoryMode};
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::node::link::vox_hostname;
    use crate::suite::SuiteFloor;

    fn root(a: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0xFF; 32]).unwrap()
    }

    fn policy() -> ChannelPolicy {
        ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: SuiteFloor::DAY_ONE.id(),
        }
    }

    fn service_room(creator: &SoftwareRootSigner, nonce: u8) -> Genesis {
        Genesis::create_with_nonce_and_grant(
            creator,
            1_000,
            policy(),
            CapabilitySet::from_iter_caps([Capability::dial("22")]),
            [nonce; 16],
        )
        .unwrap()
    }

    #[test]
    fn a_name_resolves_to_the_room_and_its_host() {
        let creator = root(1);
        let g = service_room(&creator, 0xA1);
        let mut r = VoxResolver::new();
        assert!(r.insert(&g));

        let room = r
            .resolve(&vox_hostname(&g.channel_id()))
            .expect("a held service room resolves");
        // The host comes from the signed genesis, not from configuration or an
        // advertisement — which is why nothing has to be waited for.
        assert_eq!(room.channel_id, g.channel_id());
        assert_eq!(room.host, creator.public_key().fingerprint());
        // Its overlay address is the ADR-013 derivation of the host's key.
        assert_eq!(room.addr, overlay_addr(&creator.public_key().to_bytes()));
        assert_eq!(room.addr.octets()[0], 0xFD, "in the overlay prefix");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn a_room_without_a_service_grant_has_no_name() {
        // Its host is not determined by the genesis, so guessing at the creator would be
        // inventing a fact. That shape is reached with `vox forward <member>/<tag>`.
        let g = Genesis::create_with_nonce(&root(2), 1_000, policy(), [0xB2; 16]).unwrap();
        let mut r = VoxResolver::new();
        assert!(!r.insert(&g));
        assert!(r.resolve(&vox_hostname(&g.channel_id())).is_none());
        assert!(r.is_empty());
    }

    #[test]
    fn a_room_this_machine_has_not_joined_does_not_resolve() {
        // The failure is local and immediate: the proxy refuses, `ssh` reports it, and no
        // dial is attempted — so a mistyped name cannot be misdirected anywhere.
        let mine = service_room(&root(3), 0xC3);
        let theirs = service_room(&root(4), 0xC4);
        let mut r = VoxResolver::new();
        r.insert(&mine);
        assert!(r.resolve(&vox_hostname(&theirs.channel_id())).is_none());
        assert!(r.resolve(&vox_hostname(&mine.channel_id())).is_some());
    }

    #[test]
    fn a_name_that_is_not_a_vox_name_resolves_to_nothing() {
        let g = service_room(&root(5), 0xD5);
        let mut r = VoxResolver::new();
        r.insert(&g);
        for name in [
            "example.com",
            "localhost",
            "www.example.vox.com",
            "",
            ".vox",
            "short.vox",
        ] {
            assert!(r.resolve(name).is_none(), "{name:?} must not resolve");
        }
    }

    #[test]
    fn the_case_of_a_name_does_not_matter() {
        // A person may retype a name in any case, and a `.vox` name is passed through the
        // proxy as text.
        let g = service_room(&root(6), 0xE6);
        let mut r = VoxResolver::new();
        r.insert(&g);
        let host = vox_hostname(&g.channel_id());
        assert!(r.resolve(&host).is_some());
        assert!(r.resolve(&host.to_uppercase()).is_some());
        assert!(r.resolve(&format!("  {host}  ")).is_some());
    }

    #[test]
    fn several_rooms_each_keep_their_own_name() {
        let a = service_room(&root(7), 0xF7);
        let b = service_room(&root(8), 0xF8);
        let mut r = VoxResolver::new();
        r.insert(&a);
        r.insert(&b);
        assert_eq!(r.len(), 2);
        assert_eq!(
            r.resolve(&vox_hostname(&a.channel_id()))
                .unwrap()
                .channel_id,
            a.channel_id()
        );
        assert_eq!(
            r.resolve(&vox_hostname(&b.channel_id()))
                .unwrap()
                .channel_id,
            b.channel_id()
        );
    }
}
