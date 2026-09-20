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
const B32_DIGEST_LEN: usize = 52;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn eps(list: Vec<Multiaddr>) -> EndpointList {
        EndpointList::new(list).unwrap()
    }

    fn anchor(id: u8, list: Vec<Multiaddr>) -> BootstrapNode {
        BootstrapNode::new([id; 32], eps(list)).unwrap()
    }

    fn v4(d: u8, port: u16) -> Multiaddr {
        Multiaddr::Ip4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, d), port))
    }

    #[test]
    fn base32_round_trips_every_byte_pattern_and_rejects_junk() {
        for seed in [0u8, 1, 0x7F, 0x80, 0xFF] {
            let d = [seed; 32];
            let text = b32_encode(&d);
            assert_eq!(text.len(), B32_DIGEST_LEN);
            assert_eq!(b32_decode(&text, "x").unwrap(), d);
            // Case-insensitive on input, so a re-typed or upper-cased link works.
            assert_eq!(b32_decode(&text.to_uppercase(), "x").unwrap(), d);
        }
        let mut counting = [0u8; 32];
        for (i, b) in counting.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(b32_decode(&b32_encode(&counting), "x").unwrap(), counting);
        // Wrong length, out-of-alphabet characters, and non-canonical trailing bits.
        assert!(b32_decode("", "x").is_err());
        assert!(b32_decode(&"a".repeat(51), "x").is_err());
        assert!(b32_decode(&"a".repeat(53), "x").is_err());
        assert!(b32_decode(&format!("{}1", "a".repeat(51)), "x").is_err());
        let mut noncanonical = b32_encode(&[0u8; 32]);
        noncanonical.pop();
        noncanonical.push('b'); // leftover bits nonzero
        assert!(matches!(
            b32_decode(&noncanonical, "x"),
            Err(Error::MalformedLink("x"))
        ));
    }

    #[test]
    fn links_round_trip_with_and_without_a_pinned_responder() {
        let cid = [0x11; 32];
        let responder = [0x22; 32];
        let ipv6 = Multiaddr::Ip6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7),
            4433,
            0,
            0,
        ));
        let with = InviteLink::new(
            cid,
            vec![
                anchor(0xA1, vec![ipv6, v4(9, 4433)]),
                anchor(0xA2, vec![v4(3, 1)]),
            ],
            Some(responder),
        )
        .unwrap();
        let url = with.to_url();
        assert!(url.starts_with("vox://"));
        assert!(url.contains(&format!(
            "?a={}&b=/ip6/2001:db8::7/udp/4433",
            b32_encode(&[0xA1; 32])
        )));
        assert!(url.contains("&b=/ip4/10.0.0.9/udp/4433"));
        assert!(url.contains(&format!(
            "&a={}&b=/ip4/10.0.0.3/udp/1",
            b32_encode(&[0xA2; 32])
        )));
        assert!(url.contains("&r="));
        assert!(
            !url.contains("pass") && url.len() < 400,
            "the link carries no secret: {url}"
        );
        assert_eq!(InviteLink::parse(&url).unwrap(), with);
        assert_eq!(with.to_string(), url);

        let without = InviteLink::new(cid, vec![anchor(1, vec![v4(1, 1234)])], None).unwrap();
        let url = without.to_url();
        assert_eq!(
            url,
            format!(
                "vox://{}?a={}&b=/ip4/10.0.0.1/udp/1234",
                b32_encode(&cid),
                b32_encode(&[1; 32])
            )
        );
        assert_eq!(InviteLink::parse(&url).unwrap(), without);
        // Anchor order, and address order within an anchor, are preserved: both are
        // the reachability preference (ADR-012).
        let ordered = InviteLink::new(
            cid,
            vec![
                anchor(2, vec![v4(2, 1), v4(1, 2)]),
                anchor(1, vec![v4(5, 5)]),
            ],
            None,
        )
        .unwrap();
        let back = InviteLink::parse(&ordered.to_url()).unwrap();
        assert_eq!(back.anchors[0].id, [2; 32]);
        assert_eq!(
            back.anchors[0].endpoints.addrs(),
            ordered.anchors[0].endpoints.addrs()
        );
        assert_eq!(back.anchors[1].id, [1; 32]);
        // A duplicate anchor, or too many, is not a link.
        assert!(InviteLink::new(
            cid,
            vec![anchor(1, vec![v4(1, 1)]), anchor(1, vec![v4(2, 2)])],
            None
        )
        .is_err());
        let many: Vec<BootstrapNode> = (0..=MAX_LINK_ANCHORS as u8)
            .map(|i| anchor(i, vec![v4(i, 1)]))
            .collect();
        assert!(InviteLink::new(cid, many, None).is_err());
        // Upper-cased digests still parse to the same link.
        let shouted = with
            .to_url()
            .replace(&b32_encode(&cid), &b32_encode(&cid).to_uppercase());
        assert_eq!(InviteLink::parse(&shouted).unwrap(), with);
    }

    #[test]
    fn anchor_specs_round_trip_and_merge_by_identity() {
        let node = anchor(0x5A, vec![v4(1, 4433), v4(2, 4433)]);
        let specs = anchor_specs(&node);
        assert_eq!(specs.len(), 2);
        assert!(specs[0].starts_with(&b32_encode(&[0x5A; 32])));
        assert!(specs[0].ends_with("@/ip4/10.0.0.1/udp/4433"));
        let mut set = crate::nat::bootstrap::BootstrapSet::new();
        for spec in &specs {
            merge_anchor_spec(&mut set, spec).unwrap();
        }
        assert_eq!(set.len(), 1, "one identity, two addresses");
        assert_eq!(set.nodes()[0], node);
        // Order of anchors is preserved across a merge into an existing one.
        merge_anchor_spec(&mut set, &anchor_specs(&anchor(0x5B, vec![v4(3, 1)]))[0]).unwrap();
        merge_anchor_spec(
            &mut set,
            &format!("{}@/ip4/10.0.0.9/udp/9", b32_encode(&[0x5A; 32])),
        )
        .unwrap();
        assert_eq!(set.nodes()[0].id, [0x5A; 32]);
        assert_eq!(set.nodes()[0].endpoints.len(), 3);
        assert_eq!(set.nodes()[1].id, [0x5B; 32]);
        for bad in ["", "nope", "@/ip4/10.0.0.1/udp/1", "zz@/ip4/10.0.0.1/udp/1"] {
            assert!(parse_anchor_spec(bad).is_err(), "accepted {bad:?}");
        }
        assert!(parse_anchor_spec(&format!("{}@/ip4/bad", b32_encode(&[1; 32]))).is_err());
    }

    #[test]
    fn malformed_links_are_refused_field_by_field() {
        let cid = b32_encode(&[0x33; 32]);
        let a = b32_encode(&[0x44; 32]);
        let ok = format!("vox://{cid}?a={a}&b=/ip4/10.0.0.1/udp/443");
        assert!(InviteLink::parse(&ok).is_ok());
        for (bad, why) in [
            ("http://x", "wrong scheme"),
            ("vox://", "no channelID"),
            (
                &format!("vox://short?a={a}&b=/ip4/10.0.0.1/udp/443"),
                "short channelID",
            ),
            (&format!("vox://{cid}"), "no anchors"),
            (&format!("vox://{cid}?"), "empty query"),
            (&format!("vox://{cid}?a={a}"), "anchor with no address"),
            (&format!("vox://{cid}?a={a}&b="), "empty address"),
            (
                &format!("vox://{cid}?b=/ip4/10.0.0.1/udp/443"),
                "address before any anchor",
            ),
            (
                &format!("vox://{cid}?a=zz&b=/ip4/10.0.0.1/udp/443"),
                "bad anchor id",
            ),
            (
                &format!("vox://{cid}?a={a}&b=/ip4/10.0.0.1/udp/443&a={a}&b=/ip4/10.0.0.2/udp/443"),
                "duplicate anchor",
            ),
            (
                &format!("vox://{cid}?a={a}&b=/ip4/10.0.0.1/udp/443&x=1"),
                "unknown field",
            ),
            (
                &format!("vox://{cid}?a={a}&b=/ip4/10.0.0.1/udp/443&r=zz"),
                "bad responder",
            ),
            (&format!("vox://{cid}?bogus"), "field without ="),
            (
                &format!("vox://{cid}?a={a}&b=/ip4/10.0.0.1/udp/443&r={cid}&r={cid}"),
                "duplicate r",
            ),
        ] {
            assert!(
                matches!(InviteLink::parse(bad), Err(Error::MalformedLink(_))),
                "accepted {why}: {bad}"
            );
        }
        // More addresses for one anchor than the ADR-012 cap.
        let many: Vec<String> = (0..MAX_ENDPOINTS + 1)
            .map(|i| format!("b=/ip4/10.0.0.{}/udp/443", i + 1))
            .collect();
        let over = format!("vox://{cid}?a={a}&{}", many.join("&"));
        assert!(matches!(
            InviteLink::parse(&over),
            Err(Error::MalformedLink("invite link anchor addresses"))
        ));
        // More anchors than a link may name.
        let many: Vec<String> = (0..=MAX_LINK_ANCHORS as u8)
            .map(|i| format!("a={}&b=/ip4/10.0.0.{}/udp/443", b32_encode(&[i; 32]), i + 1))
            .collect();
        let over = format!("vox://{cid}?{}", many.join("&"));
        assert!(matches!(
            InviteLink::parse(&over),
            Err(Error::MalformedLink("invite link anchor count"))
        ));
        // A link with no anchors cannot even be constructed.
        assert!(InviteLink::new([0; 32], Vec::new(), None).is_err());
    }
}
