//! **Where a peer comes from**, for sharing a bounded resource fairly between the peers that use it:
//! the rooms a full rendezvous board holds (`nat::store`, V210-70), and the join slots a node
//! answers joins in (V210-92). One definition for both, so the two never disagree about what one
//! source is.
//!
//! A source is three opaque keys, **coarse to fine**, compared level by level:
//! - an IPv4 address is that address at every level;
//! - an IPv6 address is its /48, its /56 and its /64. One host is routinely given a /64 whole and a
//!   home a /56, so grouping finer would let one machine appear as thousands of sources. Grouping
//!   only by the /48 would let one /56 tie out its neighbours in the same /48, so the finer levels
//!   decide between them;
//! - an IPv4-mapped IPv6 address is its IPv4 address;
//! - a peer reached over a relay circuit, whose address this node cannot see, is filed under the
//!   relay's own network and then where the relay says the peer is ([`Source::relayed_by`]); with
//!   no origin recorded, every such peer is **one shared source**, [`Source::relayed_unknown`].
//!   Keyed by an identity instead — the peer's or the relay's — a stranger would mint a source
//!   per identity it made, for nothing.
//!
//! Peers that share an address (one IPv4 address behind a NAT, one /64) share a source: by network
//! they cannot be told apart.

use std::net::IpAddr;

use crate::hash::{domain_hash, Digest32};
use crate::transport::quic::VoxConnection;

/// Where a peer comes from: three opaque keys, coarse to fine. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Source(pub [Digest32; 3]);

impl Source {
    /// The number of levels a source is compared at.
    pub const LEVELS: usize = 3;

    /// The source of a peer seen at `ip`.
    #[must_use]
    pub fn of_addr(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                let key = domain_hash("vox/source/v4", &v4.octets());
                Self([key, key, key])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                Self([
                    domain_hash("vox/source/v6/48", &o[..6]),
                    domain_hash("vox/source/v6/56", &o[..7]),
                    domain_hash("vox/source/v6/64", &o[..8]),
                ])
            }
        }
    }

    /// The source of whoever is at the far end of `conn`: its address, or, over a relay circuit
    /// (whose address is this node's own mux handle and says nothing), the origin recorded when
    /// the circuit was attached ([`Source::relayed_by`]), else the one shared source of peers whose
    /// origin is unknown.
    #[must_use]
    pub fn of_conn(conn: &VoxConnection) -> Self {
        if conn.via_circuit() {
            conn.circuit_origin()
                .map_or_else(Self::relayed_unknown, Self::from_levels)
        } else {
            Self::of_addr(conn.quinn().remote_address().ip())
        }
    }

    /// The source of a peer a relay carried here, from the relay's own source and the `tags` it
    /// said the peer has (its three levels as the relay sees them, keyed with a secret of the
    /// relay's). The coarsest level is the **relay's own network**, which the relay cannot choose:
    /// keyed by the relay's identity instead, a stranger that made relays — on an anchor that
    /// serves anyone, a relay is a member for the price of a genesis it minted — had a source per
    /// relay, for nothing. The finer levels are the peer's, as the relay says, kept apart under the
    /// relay's network: an honest relay tells a stranger it carries from a real member it carries,
    /// and a lying one can only split what it carries, all of it inside its own network's count.
    #[must_use]
    pub fn relayed_by(relay: &Self, tags: &[[u8; 16]; 3]) -> Self {
        let under = |label: &str, parts: &[&[u8]]| {
            let mut input = Vec::with_capacity(32 + 16 * parts.len());
            input.extend_from_slice(relay.level(0).as_ref());
            for part in parts {
                input.extend_from_slice(part);
            }
            domain_hash(label, &input)
        };
        Self([
            relay.level(0),
            under("vox/source/relayed/1", &[&tags[0]]),
            under("vox/source/relayed/2", &[&tags[0], &tags[2]]),
        ])
    }

    /// The source of every peer reached over a relay circuit with no origin recorded for it: one
    /// shared source at every level, so identities cost a stranger nothing here.
    #[must_use]
    pub fn relayed_unknown() -> Self {
        let key = domain_hash("vox/source/relayed-unknown", &[]);
        Self([key, key, key])
    }

    /// A source from three keys someone else derived, coarse to fine — a relay's report of where a
    /// circuit's peer comes from, kept apart per relay by whoever derives them.
    #[must_use]
    pub fn from_levels(levels: [Digest32; 3]) -> Self {
        Self(levels)
    }

    /// This source's key at `level` (0 coarsest).
    #[must_use]
    pub fn level(&self, level: usize) -> Digest32 {
        self.0[level]
    }
}
