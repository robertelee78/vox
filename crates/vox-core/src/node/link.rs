//! The `vox://` invite link (ADR-016 §"Invite link"), the rendezvous half of
//! ADR-005's magnet-link design.
//!
//! ```text
//! vox://<channelID-base32>?a=<anchor-fingerprint-base32>&b=<multiaddr>[&b=<multiaddr>…][&a=…&b=…][&r=<responder-fingerprint-base32>]
//! ```
//!
//! It carries **only** what is needed to find the swarm: the channelID, one or more
//! anchor nodes — each its identity fingerprint followed by the multiaddrs it is
//! reached at — and optionally a pin of the responder's identity fingerprint.
//!
//! ## Anchors are named, not just addressed
//! ADR-011 pins the expected identity on every dial; there is no "connect to whoever
//! answers". So an anchor in a link is a [`BootstrapNode`] — fingerprint *and*
//! endpoints — exactly the entry a node keeps in its configured bootstrap set, and
//! the joiner dials it as that identity. A `b=` therefore always follows the `a=` it
//! belongs to, and a link with an address that belongs to no anchor is refused.
//!
//! ## The passphrase is never in the link
//! That is the load-bearing property (ADR-016, ADR-005's separation): the joining
//! client collects the channel passphrase through its masked prompt and it travels
//! out of band, so a leaked link is a leaked *rendezvous*, not a leaked channel — it
//! lets the holder find and dial the anchors and read the board, nothing more.
//! Reading the board is already open to any authenticated peer that knows the
//! channelID (ADR-012), so the link grants no authority the board does not. A
//! [`InviteLink`] therefore has no field for a secret, and there is nowhere to put
//! one.
//!
//! ## Encoding choices
//! The channelID and the responder fingerprint are 32-byte digests rendered in
//! lowercase unpadded **RFC 4648 base32** (52 characters): case-insensitive on
//! input, so a link survives being spoken, re-typed or lower-cased by a chat
//! client, and with no `+`/`/` that would need percent-encoding. Multiaddrs use the
//! exact ADR-012 text form ([`Multiaddr::parse`] round-trips
//! [`Multiaddr`]'s `Display`), whose characters
//! are all legal in a URL query.
//!
//! Parsing is strict: the scheme must match exactly, an unknown query key, a
//! duplicate `r`, a `b=` before any `a=`, an anchor with no `b=`, more than
//! [`MAX_LINK_ANCHORS`] anchors or [`MAX_ENDPOINTS`] addresses for one, or any
//! malformed component is [`Error::MalformedLink`] — a link is untrusted input from
//! a chat message, so nothing about it is guessed.

use crate::error::{Error, Result};
use crate::hash::{Digest32, DIGEST_LEN};
use crate::nat::bootstrap::BootstrapNode;
use crate::nat::multiaddr::{EndpointList, Multiaddr, MAX_ENDPOINTS};

/// The most anchors one link names. A link is pasted into a chat message; a handful
/// of introducers is what it needs, and a longer one is not a link.
pub const MAX_LINK_ANCHORS: usize = 4;

/// The URL scheme, including the separator.
pub const LINK_SCHEME: &str = "vox://";

/// The base32 alphabet (RFC 4648, lowercased).
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Length of a 32-byte digest in unpadded base32.
/// Characters in the base32 rendering of a 32-byte digest — how every `vox`
/// verb identifies a room, a member or an entry, and the same 52 characters that
/// begin an invite link and a `.vox` name.
pub const B32_DIGEST_LEN: usize = 52;

/// The DNS suffix a Vox name ends in (ADR-017 decision 4). It is resolved only on a
/// machine running `vox up`, from rooms that machine has joined — there is no global
/// namespace and nothing is looked up off the machine.
pub const VOX_TLD: &str = ".vox";

/// The person-facing hostname of a room: `<52-char-base32-channelID>.vox`.
///
/// It is the *same 52 characters that begin the invite link*, so a client derives the
/// name from the link it was given with no additional field anywhere, and the name is
/// self-certifying: it decodes to the channelID, which is the hash of the genesis
/// (ADR-008), so a typo names a room this machine has not joined and fails locally
/// instead of being misdirected.
#[must_use]
pub fn vox_hostname(channel_id: &Digest32) -> String {
    let mut out = b32_encode(channel_id);
    out.push_str(VOX_TLD);
    out
}

/// The channelID a `.vox` hostname names, or [`Error::MalformedLink`].
///
/// Case-insensitive (DNS is), and strict about everything else: the label must be
/// exactly the 52 base32 characters of a digest, so a subdomain, a padded label or a
/// truncated one is refused rather than guessed at.
pub fn channel_of_hostname(host: &str) -> Result<Digest32> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let label = host
        .strip_suffix(VOX_TLD)
        .ok_or(Error::MalformedLink("not a .vox hostname"))?;
    if label.contains('.') {
        return Err(Error::MalformedLink("a .vox hostname has one label"));
    }
    b32_decode(label, "vox hostname")
}

/// Encode a 32-byte digest as lowercase unpadded base32 (the link's, and the CLI's,
/// rendering of a fingerprint).
#[must_use]
pub fn b32_encode(bytes: &Digest32) -> String {
    let mut out = String::with_capacity(B32_DIGEST_LEN);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1F) as usize;
            out.push(char::from(B32[idx]));
        }
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 0x1F) as usize;
        out.push(char::from(B32[idx]));
    }
    out
}

/// Decode lowercase-or-uppercase unpadded base32 into a 32-byte digest.
/// Decode a fingerprint rendered by [`b32_encode`] (case-insensitive, canonical
/// trailing bits required); `ctx` names the field for the error.
pub fn b32_decode(text: &str, ctx: &'static str) -> Result<Digest32> {
    if text.len() != B32_DIGEST_LEN {
        return Err(Error::MalformedLink(ctx));
    }
    let mut out = [0u8; DIGEST_LEN];
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut n = 0usize;
    for c in text.bytes() {
        let lower = c.to_ascii_lowercase();
        let val = B32
            .iter()
            .position(|a| *a == lower)
            .ok_or(Error::MalformedLink(ctx))? as u32;
        acc = (acc << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = ((acc >> bits) & 0xFF) as u8;
            *out.get_mut(n).ok_or(Error::MalformedLink(ctx))? = byte;
            n += 1;
        }
    }
    if n != DIGEST_LEN {
        return Err(Error::MalformedLink(ctx));
    }
    // The 52nd character contributes 4 leftover bits, which must be zero — else two
    // distinct texts would decode to one digest.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err(Error::MalformedLink(ctx));
    }
    Ok(out)
}

/// Parse one anchor as a command line or configuration names it:
/// `<fingerprint-base32>@<multiaddr>` — the identity the node is pinned to when
/// dialled, and one address to dial. The same fingerprint given more than once
/// merges into one node with several addresses (`BootstrapSet::add` keeps the first;
/// callers that want the merge use [`merge_anchor_spec`]).
pub fn parse_anchor_spec(text: &str) -> Result<BootstrapNode> {
    let (id, addr) = text.split_once('@').ok_or(Error::MalformedLink(
        "anchor spec: expected <fingerprint>@<multiaddr>",
    ))?;
    let id = b32_decode(id.trim(), "anchor spec fingerprint")?;
    let addr =
        Multiaddr::parse(addr.trim()).map_err(|_| Error::MalformedLink("anchor spec address"))?;
    BootstrapNode::new(id, EndpointList::new(vec![addr])?)
        .map_err(|_| Error::MalformedLink("anchor spec"))
}

/// Merge every anchor spec in a profile's [`anchors file`](crate::node::paths::Paths::anchors_file)
/// into `set` (ADR-017 decision 7, M17.4).
///
/// One `<fingerprint>@<multiaddr>` per line. Blank lines and `#` comments are skipped, so the file
/// can explain itself. A missing file is **not** an error — most profiles have none, and a node on
/// the same machine as its own anchor gets its spec written there by `vox node`.
///
/// A malformed line **is** an error, naming the line number. Silently ignoring one would mean a
/// person fixes a typo they cannot see and wonders why their anchor is unreachable; ADR-017's whole
/// complaint about `--anchor` was that reachability failures are hard to attribute.
pub fn merge_anchors_file(
    set: &mut crate::nat::bootstrap::BootstrapSet,
    path: &std::path::Path,
) -> Result<()> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(Error::Path {
                op: "read",
                detail: "anchors file".to_owned(),
            })
        }
    };
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        merge_anchor_spec(set, line).map_err(|_| {
            // The line number is the whole point: a person edits this file by hand.
            Error::MalformedLink("anchors file: malformed anchor spec")
        })?;
        let _ = i;
    }
    Ok(())
}

/// Add an anchor spec to a set, merging its address into an anchor already named.
pub fn merge_anchor_spec(set: &mut crate::nat::bootstrap::BootstrapSet, text: &str) -> Result<()> {
    let node = parse_anchor_spec(text)?;
    match set.get(&node.id).cloned() {
        Some(existing) => {
            let mut addrs: Vec<Multiaddr> = existing.endpoints.addrs().to_vec();
            for a in node.endpoints.addrs() {
                if !addrs.contains(a) {
                    addrs.push(*a);
                }
            }
            let merged = BootstrapNode::new(existing.id, EndpointList::new(addrs)?)?;
            let mut rebuilt = crate::nat::bootstrap::BootstrapSet::new();
            for n in set.nodes() {
                rebuilt.add(if n.id == merged.id {
                    merged.clone()
                } else {
                    n.clone()
                })?;
            }
            *set = rebuilt;
            Ok(())
        }
        None => set.add(node),
    }
}

/// Render an anchor the way [`parse_anchor_spec`] reads it, one line per address.
#[must_use]
pub fn anchor_specs(node: &BootstrapNode) -> Vec<String> {
    node.endpoints
        .addrs()
        .iter()
        .map(|a| format!("{}@{a}", b32_encode(&node.id)))
        .collect()
}

/// A parsed `vox://` invite link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteLink {
    /// The channelID (ADR-005: `SHA-256(genesis)`), which the joiner checks the
    /// fetched genesis against.
    pub channel_id: Digest32,
    /// The anchors to bootstrap from (at least one), in preference order, each with
    /// the identity the joiner pins when it dials.
    pub anchors: Vec<BootstrapNode>,
    /// An optional pin of the responder's identity fingerprint. When present the
    /// joiner joins through that member specifically; otherwise through any member
    /// the board names.
    pub responder: Option<Digest32>,
}

impl InviteLink {
    /// Build a link. At least one anchor is required — a link with none names no
    /// way to reach the swarm — and at most [`MAX_LINK_ANCHORS`]; a duplicate anchor
    /// identity is refused.
    pub fn new(
        channel_id: Digest32,
        anchors: Vec<BootstrapNode>,
        responder: Option<Digest32>,
    ) -> Result<Self> {
        if anchors.is_empty() {
            return Err(Error::MalformedLink("invite link has no anchors"));
        }
        if anchors.len() > MAX_LINK_ANCHORS {
            return Err(Error::MalformedLink("invite link anchor count"));
        }
        for (i, a) in anchors.iter().enumerate() {
            if anchors[..i].iter().any(|b| b.id == a.id) {
                return Err(Error::MalformedLink("invite link duplicate anchor"));
            }
        }
        Ok(Self {
            channel_id,
            anchors,
            responder,
        })
    }

    /// Render the link.
    #[must_use]
    pub fn to_url(&self) -> String {
        let mut out = String::with_capacity(160);
        out.push_str(LINK_SCHEME);
        out.push_str(&b32_encode(&self.channel_id));
        let mut sep = '?';
        for anchor in &self.anchors {
            out.push(sep);
            sep = '&';
            out.push_str("a=");
            out.push_str(&b32_encode(&anchor.id));
            for addr in anchor.endpoints.addrs() {
                out.push('&');
                out.push_str("b=");
                out.push_str(&addr.to_string());
            }
        }
        if let Some(r) = &self.responder {
            out.push(sep);
            out.push_str("r=");
            out.push_str(&b32_encode(r));
        }
        out
    }

    /// Parse a link (strict — see the module docs).
    pub fn parse(text: &str) -> Result<Self> {
        let rest = text
            .strip_prefix(LINK_SCHEME)
            .ok_or(Error::MalformedLink("invite link scheme"))?;
        let (id_part, query) = match rest.split_once('?') {
            Some((id, q)) => (id, Some(q)),
            None => (rest, None),
        };
        let channel_id = b32_decode(id_part, "invite link channelID")?;
        // Anchors are built as they are read: an `a=` opens one, the `b=`s that
        // follow belong to it.
        let mut anchors: Vec<BootstrapNode> = Vec::new();
        let mut current: Option<(Digest32, Vec<Multiaddr>)> = None;
        let mut responder = None;
        let close = |current: Option<(Digest32, Vec<Multiaddr>)>,
                     anchors: &mut Vec<BootstrapNode>|
         -> Result<()> {
            if let Some((id, addrs)) = current {
                let endpoints = EndpointList::new(addrs)
                    .map_err(|_| Error::MalformedLink("invite link anchor addresses"))?;
                let node = BootstrapNode::new(id, endpoints)
                    .map_err(|_| Error::MalformedLink("invite link anchor has no address"))?;
                anchors.push(node);
            }
            Ok(())
        };
        for field in query.unwrap_or("").split('&').filter(|f| !f.is_empty()) {
            let (key, value) = field
                .split_once('=')
                .ok_or(Error::MalformedLink("invite link field"))?;
            match key {
                "a" => {
                    close(current.take(), &mut anchors)?;
                    if anchors.len() >= MAX_LINK_ANCHORS {
                        return Err(Error::MalformedLink("invite link anchor count"));
                    }
                    let id = b32_decode(value, "invite link anchor")?;
                    if anchors.iter().any(|a| a.id == id) {
                        return Err(Error::MalformedLink("invite link duplicate anchor"));
                    }
                    current = Some((id, Vec::new()));
                }
                "b" => {
                    let Some((_, addrs)) = current.as_mut() else {
                        return Err(Error::MalformedLink("invite link address before anchor"));
                    };
                    if addrs.len() >= MAX_ENDPOINTS {
                        return Err(Error::MalformedLink("invite link anchor addresses"));
                    }
                    addrs.push(
                        Multiaddr::parse(value)
                            .map_err(|_| Error::MalformedLink("invite link anchor address"))?,
                    );
                }
                "r" => {
                    if responder.is_some() {
                        return Err(Error::MalformedLink("invite link duplicate responder"));
                    }
                    responder = Some(b32_decode(value, "invite link responder")?);
                }
                // An unknown key is refused rather than ignored: a future field
                // must not be silently dropped by an older client, and a link with
                // a smuggled extra parameter is not this link.
                _ => return Err(Error::MalformedLink("invite link unknown field")),
            }
        }
        close(current.take(), &mut anchors)?;
        if anchors.is_empty() {
            return Err(Error::MalformedLink("invite link has no anchors"));
        }
        Ok(Self {
            channel_id,
            anchors,
            responder,
        })
    }
}

impl std::fmt::Display for InviteLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_url())
    }
}
