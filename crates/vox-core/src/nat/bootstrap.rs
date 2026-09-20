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
