//! The user-controlled bootstrap / rendezvous / relay set (ADR-012 §"Bootstrap").
//!
//! Cold-start onto the swarm uses "a configurable bootstrap set the user
//! controls": by default the user's own always-on node, optionally augmented with a
//! community/volunteer set. Crucially, **bootstrap nodes only introduce peers** —
//! they can neither read traffic nor forge membership (ADR-012) — so a hostile or
//! absent bootstrap degrades availability but never confidentiality or
//! authenticity. This type is therefore plain, user-owned configuration: an ordered
//! set of `(identity, endpoints)` entries to contact when joining the swarm.

use crate::cbor::{Decoder, Encoder};
use crate::error::Error;
use crate::error::Result;
use crate::hash::{Digest32, DIGEST_LEN};
use crate::nat::multiaddr::EndpointList;

/// The maximum number of bootstrap nodes one set may hold — a sanity bound on
/// user/community configuration (a node needs only a handful of introducers).
pub const MAX_BOOTSTRAP_NODES: usize = 64;

/// One bootstrap node: a known node willing to introduce peers (and, as the user's
/// own node, to serve as rendezvous/relay). Identified by its composite-identity
/// fingerprint (ADR-002) so a contacted node is authenticated as the expected one
/// over the M9 transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapNode {
    /// The node's composite-identity fingerprint (the expected peer on connect).
    pub id: Digest32,
    /// Where to reach the node (the M9 dial targets, ADR-011).
    pub endpoints: EndpointList,
}

impl BootstrapNode {
    /// Construct a bootstrap node. Rejects an entry with no endpoints (it could
    /// never be contacted).
    pub fn new(id: Digest32, endpoints: EndpointList) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(Error::MalformedRendezvous(
                "bootstrap node has no endpoints",
            ));
        }
        Ok(Self { id, endpoints })
    }

    /// Encode into an in-progress canonical-CBOR stream as `[id, endpoints]`.
    pub(crate) fn encode_into(&self, e: &mut Encoder) {
        e.array(2).bytes(&self.id);
        self.endpoints.encode_into(e);
    }

    /// Strictly decode one node from an in-progress stream.
    pub(crate) fn decode_from(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 2 {
            return Err(Error::MalformedRendezvous("bootstrap node arity"));
        }
        let raw = d.bytes()?;
        if raw.len() != DIGEST_LEN {
            return Err(Error::MalformedRendezvous("bootstrap node id length"));
        }
        let mut id = [0u8; DIGEST_LEN];
        id.copy_from_slice(raw);
        let endpoints = EndpointList::decode_from(d)?;
        Self::new(id, endpoints)
    }
}

/// An ordered, deduplicated, capped set of bootstrap nodes (ADR-012). Order is
/// preference order: the user's own node first, then any opted-in community set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootstrapSet {
    nodes: Vec<BootstrapNode>,
}

impl BootstrapSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a node in preference order. A node whose `id` is already present is
    /// ignored (the first, higher-preference entry wins). Rejects growth beyond
    /// [`MAX_BOOTSTRAP_NODES`].
    pub fn add(&mut self, node: BootstrapNode) -> Result<()> {
        if self.nodes.iter().any(|n| n.id == node.id) {
            return Ok(());
        }
        if self.nodes.len() >= MAX_BOOTSTRAP_NODES {
            return Err(Error::SizeLimitExceeded("bootstrap set"));
        }
        self.nodes.push(node);
        Ok(())
    }

    /// The nodes, in preference order.
    #[must_use]
    pub fn nodes(&self) -> &[BootstrapNode] {
        &self.nodes
    }

    /// `true` if the set holds no nodes (cold-start has nowhere to begin).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The number of bootstrap nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// The node with this fingerprint, if it is in the set.
    #[must_use]
    pub fn get(&self, id: &Digest32) -> Option<&BootstrapNode> {
        self.nodes.iter().find(|n| n.id == *id)
    }

    /// Canonical CBOR (`[[id, endpoints], …]`), the form a node persists per channel
    /// (ADR-016: the anchors a client publishes to and reads from).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(self.nodes.len());
        for n in &self.nodes {
            n.encode_into(&mut e);
        }
        e.finish()
    }

    /// Strictly decode a set: wrong arity, a bad node, a duplicate id, growth past
    /// the cap or trailing bytes are all refused.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let n = d.array()?;
        if n > MAX_BOOTSTRAP_NODES {
            return Err(Error::SizeLimitExceeded("bootstrap set"));
        }
        let mut set = Self::new();
        for _ in 0..n {
            let node = BootstrapNode::decode_from(&mut d)?;
            if set.get(&node.id).is_some() {
                return Err(Error::MalformedRendezvous("bootstrap set duplicate id"));
            }
            set.add(node)?;
        }
        d.finish()?;
        Ok(set)
    }

    /// Every node of `other` this set does not have, appended in `other`'s order
    /// (the set's own entries keep their higher preference).
    pub fn merge(&mut self, other: &BootstrapSet) -> Result<()> {
        for n in other.nodes() {
            self.add(n.clone())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::multiaddr::Multiaddr;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn a_set_round_trips_canonically_and_decodes_strictly() {
        let mut set = BootstrapSet::new();
        set.add(BootstrapNode::new([1u8; 32], eps(1)).unwrap())
            .unwrap();
        set.add(BootstrapNode::new([2u8; 32], eps(2)).unwrap())
            .unwrap();
        let bytes = set.to_bytes();
        assert_eq!(BootstrapSet::from_bytes(&bytes).unwrap(), set);
        assert_eq!(
            BootstrapSet::from_bytes(&BootstrapSet::new().to_bytes()).unwrap(),
            BootstrapSet::new()
        );
        assert_eq!(set.get(&[2u8; 32]).map(|n| &n.endpoints), Some(&eps(2)));
        assert!(set.get(&[3u8; 32]).is_none());

        // Trailing bytes.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(BootstrapSet::from_bytes(&extra).is_err());
        // A duplicate id on the wire is not a set.
        let mut e = Encoder::new();
        e.array(2);
        for _ in 0..2 {
            BootstrapNode::new([1u8; 32], eps(1))
                .unwrap()
                .encode_into(&mut e);
        }
        assert!(BootstrapSet::from_bytes(&e.finish()).is_err());
        // A node with no endpoints on the wire is not a node.
        let mut e = Encoder::new();
        e.array(1).array(2).bytes(&[1u8; 32]);
        EndpointList::default().encode_into(&mut e);
        assert!(BootstrapSet::from_bytes(&e.finish()).is_err());
        // A wrong-length id.
        let mut e = Encoder::new();
        e.array(1).array(2).bytes(&[1u8; 31]);
        eps(1).encode_into(&mut e);
        assert!(BootstrapSet::from_bytes(&e.finish()).is_err());

        // Merging keeps this set's order and skips what it already has.
        let mut other = BootstrapSet::new();
        other
            .add(BootstrapNode::new([2u8; 32], eps(9)).unwrap())
            .unwrap();
        other
            .add(BootstrapNode::new([3u8; 32], eps(3)).unwrap())
            .unwrap();
        set.merge(&other).unwrap();
        assert_eq!(set.len(), 3);
        assert_eq!(set.get(&[2u8; 32]).map(|n| &n.endpoints), Some(&eps(2)));
        assert_eq!(set.nodes()[2].id, [3u8; 32]);
    }

    fn eps(d: u8) -> EndpointList {
        EndpointList::new(vec![Multiaddr::Ip4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, d),
            4433,
        ))])
        .unwrap()
    }

    #[test]
    fn node_requires_endpoints() {
        assert!(BootstrapNode::new([1u8; 32], EndpointList::default()).is_err());
        assert!(BootstrapNode::new([1u8; 32], eps(1)).is_ok());
    }

    #[test]
    fn add_preserves_order_and_dedups_by_id() {
        let mut set = BootstrapSet::new();
        set.add(BootstrapNode::new([1u8; 32], eps(1)).unwrap())
            .unwrap();
        set.add(BootstrapNode::new([2u8; 32], eps(2)).unwrap())
            .unwrap();
        // Duplicate id ignored, first entry kept.
        set.add(BootstrapNode::new([1u8; 32], eps(9)).unwrap())
            .unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.nodes()[0].id, [1u8; 32]);
        assert_eq!(set.nodes()[0].endpoints, eps(1));
    }

    #[test]
    fn capacity_is_enforced() {
        let mut set = BootstrapSet::new();
        for i in 0..MAX_BOOTSTRAP_NODES {
            set.add(BootstrapNode::new([i as u8; 32], eps(1)).unwrap())
                .unwrap();
        }
        assert!(matches!(
            set.add(BootstrapNode::new([255u8; 32], eps(1)).unwrap()),
            Err(Error::SizeLimitExceeded(_))
        ));
    }
}
