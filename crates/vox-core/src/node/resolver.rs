//! Resolving `.vox` names on this machine (ADR-017 decisions 4 and 5, M17.3a).
//!
//! `ssh user@<52-char-base32>.vox` has to become an address the kernel will route to
//! the Vox interface. This module is the mapping and the DNS responder that serves it.
//!
//! ## Nothing is looked up off the machine
//! A name resolves from data this node already holds, or not at all:
//!
//! 1. the 52 characters decode to a **channelID** — nothing is consulted to learn it,
//!    because the name *is* the identifier ([`crate::node::link::channel_of_hostname`]);
//! 2. that channelID names a room this node has joined, whose **genesis** it holds;
//! 3. the genesis carries the creator's composite public key, and the ADR-013
//!    identity-derived address of that key ([`crate::tunnel::addr::overlay_addr`]) is
//!    the answer.
//!
//! So the chain is self-certifying end to end: the name commits to the room by hash,
//! the room commits to the host by the signed genesis, and the address commits to the
//! host's key by derivation. There is no directory, no registration, no
//! trust-on-first-use and no global namespace — and a name for a room this machine has
//! not joined does not resolve *at all*, which is strictly more than Tor offers, where
//! any `.onion` is resolvable by anyone.
//!
//! ## Why the host is the genesis creator
//! A service room is created by the machine that offers the service (`vox serve`,
//! ADR-017 decision 4), so its creator *is* its host — and the creator is the one fact
//! about a room that is immutable, self-validating and known to every member with no
//! extra state and no advertisement to wait for.
//!
//! This holds **only for a room that carries a genesis service grant**. In a chat room
//! with a service added to it later the host may be any member, which the genesis does
//! not say, so such a room has no `.vox` name and is reached with
//! `vox forward <member>/<tag>` instead (ADR-017 decision 4). [`VoxResolver`] therefore
//! refuses to name a room without a grant rather than guessing at its creator.
//!
//! ## The responder
//! [`answer`] is a deliberately small, strict DNS server: one question per message,
//! `IN` class only, `AAAA` answered, `A` answered with an empty `NOERROR` (the name
//! exists and has no IPv4 address — the truthful answer, and it stops a resolver
//! retrying), everything else refused. Compression pointers in a question are rejected:
//! a real query has no need of them, and accepting them in untrusted input buys a
//! pointer loop for nothing. It binds loopback only ([`serve`]).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::error::{Error, Result};
use crate::governance::genesis::Genesis;
use crate::hash::Digest32;
use crate::node::link::channel_of_hostname;
use crate::tunnel::addr::overlay_addr;

/// The loopback port the responder listens on by default. Not 53: that needs privilege
/// on every Unix, and the whole point of this design is that nothing on the data path
/// does (ADR-017 decision 5). The per-domain resolver entry the installer writes names
/// this port.
pub const DEFAULT_DNS_PORT: u16 = 5354;

/// The largest DNS message this responder will read or produce. A query for one name is
/// far smaller; the bound is what keeps an untrusted datagram from becoming an
/// allocation.
pub const MAX_DNS_MESSAGE: usize = 512;

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

    /// The address a `.vox` hostname resolves to, or `None` for a name this machine
    /// cannot resolve — a malformed one, or a room it has not joined.
    #[must_use]
    pub fn resolve(&self, hostname: &str) -> Option<Ipv6Addr> {
        let channel_id = channel_of_hostname(hostname).ok()?;
        self.by_channel.get(&channel_id).map(|r| r.addr)
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

// ---- The DNS wire format, only as much of it as one question needs. ----

/// DNS `QTYPE`/`TYPE` for an IPv6 address record.
const TYPE_AAAA: u16 = 28;
/// DNS `QTYPE`/`TYPE` for an IPv4 address record.
const TYPE_A: u16 = 1;
/// DNS `CLASS` for the internet.
const CLASS_IN: u16 = 1;

/// DNS `RCODE`s this responder emits.
mod rcode {
    /// No error — with or without answers.
    pub const NOERROR: u8 = 0;
    /// The query was malformed.
    pub const FORMERR: u8 = 1;
    /// The name does not exist.
    pub const NXDOMAIN: u8 = 3;
    /// This server will not answer that.
    pub const REFUSED: u8 = 5;
}

/// A parsed question: the name as text, its type and class.
struct Question {
    name: String,
    qtype: u16,
    qclass: u16,
}

/// Parse the single question of a query, strictly.
fn parse_question(body: &[u8]) -> Result<Question> {
    let mut labels: Vec<String> = Vec::new();
    let mut i = 0usize;
    loop {
        let len = *body
            .get(i)
            .ok_or(Error::MalformedLink("dns question truncated"))?;
        // 0b11 in the top bits is a compression pointer. A question does not need one,
        // and honouring one in untrusted input is how a pointer loop gets in.
        if len & 0xC0 != 0 {
            return Err(Error::MalformedLink("dns compressed question name"));
        }
        i += 1;
        if len == 0 {
            break;
        }
        let end = i
            .checked_add(usize::from(len))
            .ok_or(Error::MalformedLink("dns label overflow"))?;
        let label = body
            .get(i..end)
            .ok_or(Error::MalformedLink("dns label truncated"))?;
        // Names are compared case-insensitively and Vox names are ASCII base32, so a
        // non-ASCII label cannot be one of ours.
        if !label.is_ascii() {
            return Err(Error::MalformedLink("dns non-ascii label"));
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        i = end;
    }
    let tail = body
        .get(i..i + 4)
        .ok_or(Error::MalformedLink("dns question truncated"))?;
    Ok(Question {
        name: labels.join("."),
        qtype: u16::from_be_bytes([tail[0], tail[1]]),
        qclass: u16::from_be_bytes([tail[2], tail[3]]),
    })
}

/// Encode a name back into DNS label form.
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        // Every label here came from `parse_question`, which bounds each at 63 by the
        // length byte it read; truncation would still be wrong, so assert by clamping
        // the write rather than silently corrupting the name.
        let bytes = label.as_bytes();
        let len = u8::try_from(bytes.len()).unwrap_or(u8::MAX).min(63);
        out.push(len);
        out.extend_from_slice(&bytes[..usize::from(len)]);
    }
    out.push(0);
}

/// Build a reply header for `id` with `rcode`, `answers` answer records.
fn reply_header(id: u16, rcode: u8, questions: u16, answers: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&id.to_be_bytes());
    // QR=1 (response), Opcode=0 (query), AA=1 (this server is authoritative for `.vox`
    // — it *is* the whole of that namespace on this machine), TC=0, RD copied as 0,
    // RA=0 (no recursion offered, and none is needed: nothing is looked up elsewhere).
    out.extend_from_slice(&[0x84, rcode & 0x0F]);
    out.extend_from_slice(&questions.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
}

/// The TTL on an answer, in seconds. Short, because a room can be left: a stale answer
/// should stop working promptly rather than linger in a resolver cache.
const ANSWER_TTL: u32 = 30;

/// Answer one DNS query for a `.vox` name.
///
/// Returns the reply datagram, or `None` when the query is too malformed to reply to at
/// all (no readable header, so no id to answer with — the only case where silence is
/// right, since a reply would have to invent an id).
#[must_use]
pub fn answer(query: &[u8], resolver: &VoxResolver) -> Option<Vec<u8>> {
    if query.len() < 12 || query.len() > MAX_DNS_MESSAGE {
        return None;
    }
    let id = u16::from_be_bytes([query[0], query[1]]);
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    let mut out = Vec::with_capacity(64);

    // A response, or anything but a plain query opcode, is not ours to answer.
    if flags & 0x8000 != 0 || (flags >> 11) & 0x0F != 0 {
        reply_header(id, rcode::REFUSED, 0, 0, &mut out);
        return Some(out);
    }
    // Exactly one question. Zero is nothing to answer; more than one is legal on the
    // wire and implemented by nobody, so refusing is the honest response.
    if qdcount != 1 {
        reply_header(id, rcode::FORMERR, 0, 0, &mut out);
        return Some(out);
    }
    let Ok(q) = parse_question(&query[12..]) else {
        reply_header(id, rcode::FORMERR, 0, 0, &mut out);
        return Some(out);
    };
    if q.qclass != CLASS_IN || !(q.qtype == TYPE_AAAA || q.qtype == TYPE_A) {
        // Not refused: the question is well formed and this server simply has no such
        // record. `NOERROR` with no answers is the truthful reply, and it keeps a
        // resolver from treating the name as absent.
        let code = if resolver.resolve(&q.name).is_some() {
            rcode::NOERROR
        } else {
            rcode::NXDOMAIN
        };
        reply_header(id, code, 1, 0, &mut out);
        encode_name(&q.name, &mut out);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
        return Some(out);
    }
    let Some(addr) = resolver.resolve(&q.name) else {
        reply_header(id, rcode::NXDOMAIN, 1, 0, &mut out);
        encode_name(&q.name, &mut out);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
        return Some(out);
    };
    // A known name with no IPv4 address: `NOERROR`, no answer. A Vox address is IPv6 by
    // derivation (ADR-013), so this is a fact about the name, not a failure.
    let answers = u16::from(q.qtype == TYPE_AAAA);
    reply_header(id, rcode::NOERROR, 1, answers, &mut out);
    encode_name(&q.name, &mut out);
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());
    if q.qtype == TYPE_AAAA {
        encode_name(&q.name, &mut out);
        out.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ANSWER_TTL.to_be_bytes());
        out.extend_from_slice(&16u16.to_be_bytes());
        out.extend_from_slice(&addr.octets());
    }
    Some(out)
}

/// Serve `.vox` queries on `bind` until the returned future is dropped.
///
/// Loopback only, and enforced rather than assumed: this answers for a private
/// namespace built from rooms this machine has joined, and there is no version of that
/// which should be reachable from off the machine.
pub async fn serve(bind: SocketAddr, resolver: VoxResolver) -> Result<()> {
    if !bind.ip().is_loopback() {
        return Err(Error::MalformedLink(
            "the .vox resolver binds loopback only",
        ));
    }
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|_| Error::Unreachable("cannot bind the .vox resolver"))?;
    let mut buf = vec![0u8; MAX_DNS_MESSAGE];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        // Answer only what came from this machine. A datagram from elsewhere cannot
        // reach a loopback bind, but the check costs nothing and states the intent.
        if !from.ip().is_loopback() {
            continue;
        }
        if let Some(reply) = answer(&buf[..n], &resolver) {
            let _ = sock.send_to(&reply, from).await;
        }
    }
}

/// The address family a resolved name lands in, for the interface's route.
#[must_use]
pub fn is_overlay_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => v6.octets()[0] == crate::tunnel::addr::ULA_PREFIX_BYTE,
        IpAddr::V4(_) => false,
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

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        encode_name(name, &mut q);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn rcode_of(reply: &[u8]) -> u8 {
        reply[3] & 0x0F
    }

    fn answer_count(reply: &[u8]) -> u16 {
        u16::from_be_bytes([reply[6], reply[7]])
    }

    #[test]
    fn a_name_resolves_to_the_hosts_derived_address() {
        let creator = root(1);
        let g = service_room(&creator, 0xA1);
        let mut r = VoxResolver::new();
        assert!(r.insert(&g));
        let host = vox_hostname(&g.channel_id());

        // The answer is the ADR-013 derivation of the creator's key — not an allocation,
        // not a lookup.
        let expect = overlay_addr(&creator.public_key().to_bytes());
        assert_eq!(r.resolve(&host), Some(expect));
        assert_eq!(expect.octets()[0], 0xFD, "in the overlay prefix");
        // And the reverse direction, which is what the interface routes on.
        let room = r.route(&expect).expect("the address routes back");
        assert_eq!(room.channel_id, g.channel_id());
        assert_eq!(room.host, creator.public_key().fingerprint());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn a_room_without_a_service_grant_has_no_name() {
        // Its host is not determined by the genesis, so guessing at the creator would be
        // inventing a fact. It is reached with `vox forward <member>/<tag>` instead.
        let creator = root(2);
        let g = Genesis::create_with_nonce(&creator, 1_000, policy(), [0xB2; 16]).unwrap();
        let mut r = VoxResolver::new();
        assert!(!r.insert(&g));
        assert!(r.resolve(&vox_hostname(&g.channel_id())).is_none());
        assert!(r.is_empty());
    }

    #[test]
    fn a_room_this_machine_has_not_joined_does_not_resolve() {
        let mine = service_room(&root(3), 0xC3);
        let theirs = service_room(&root(4), 0xC4);
        let mut r = VoxResolver::new();
        r.insert(&mine);

        let reply = answer(&query(&vox_hostname(&theirs.channel_id()), TYPE_AAAA), &r).unwrap();
        assert_eq!(rcode_of(&reply), rcode::NXDOMAIN);
        assert_eq!(answer_count(&reply), 0);
        // `ssh` then says "could not resolve hostname" and never dials — the failure is
        // local and immediate, which is why a typo cannot be misdirected.
    }

    #[test]
    fn an_aaaa_query_for_a_held_room_is_answered_with_the_address() {
        let creator = root(5);
        let g = service_room(&creator, 0xD5);
        let mut r = VoxResolver::new();
        r.insert(&g);
        let host = vox_hostname(&g.channel_id());
        let reply = answer(&query(&host, TYPE_AAAA), &r).unwrap();

        assert_eq!(&reply[0..2], &[0x12, 0x34], "the query id is echoed");
        assert_eq!(reply[2] & 0x80, 0x80, "QR is set");
        assert_eq!(reply[2] & 0x04, 0x04, "AA is set");
        assert_eq!(rcode_of(&reply), rcode::NOERROR);
        assert_eq!(answer_count(&reply), 1);
        // The 16 trailing bytes are the address.
        let want = overlay_addr(&creator.public_key().to_bytes()).octets();
        assert_eq!(&reply[reply.len() - 16..], &want);
    }

    #[test]
    fn an_a_query_for_a_held_room_is_noerror_with_no_answer() {
        // A Vox address is IPv6 by derivation, so "this name has no IPv4 address" is a
        // fact about the name. Answering NXDOMAIN instead would tell the resolver the
        // name does not exist, which is false and makes clients retry.
        let g = service_room(&root(6), 0xE6);
        let mut r = VoxResolver::new();
        r.insert(&g);
        let reply = answer(&query(&vox_hostname(&g.channel_id()), TYPE_A), &r).unwrap();
        assert_eq!(rcode_of(&reply), rcode::NOERROR);
        assert_eq!(answer_count(&reply), 0);
    }

    #[test]
    fn a_non_vox_name_is_never_answered() {
        let g = service_room(&root(7), 0xF7);
        let mut r = VoxResolver::new();
        r.insert(&g);
        for name in ["example.com", "www.example.vox.com", "localhost"] {
            let reply = answer(&query(name, TYPE_AAAA), &r).unwrap();
            assert_eq!(rcode_of(&reply), rcode::NXDOMAIN, "{name}");
        }
    }

    #[test]
    fn malformed_and_hostile_queries_are_handled_without_panicking() {
        let r = VoxResolver::new();
        // Too short to hold a header: no id to answer with, so silence is correct.
        assert!(answer(&[], &r).is_none());
        assert!(answer(&[0u8; 11], &r).is_none());
        assert!(answer(&vec![0u8; MAX_DNS_MESSAGE + 1], &r).is_none());

        // A header with a truncated question.
        let reply = answer(&[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0], &r).unwrap();
        assert_eq!(rcode_of(&reply), rcode::FORMERR);

        // A compression pointer in the question: refused, not followed.
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&[0xC0, 0x0C, 0, 28, 0, 1]);
        assert_eq!(rcode_of(&answer(&q, &r).unwrap()), rcode::FORMERR);

        // A label whose length runs past the end of the datagram.
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&[40, b'a', b'b']);
        assert_eq!(rcode_of(&answer(&q, &r).unwrap()), rcode::FORMERR);

        // Two questions, and zero questions.
        for count in [0u8, 2] {
            let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, count, 0, 0, 0, 0, 0, 0];
            encode_name("x.vox", &mut q);
            q.extend_from_slice(&[0, 28, 0, 1]);
            assert_eq!(rcode_of(&answer(&q, &r).unwrap()), rcode::FORMERR);
        }

        // A response, not a query.
        let reply = answer(&[0x12, 0x34, 0x80, 0x00, 0, 1, 0, 0, 0, 0, 0, 0], &r).unwrap();
        assert_eq!(rcode_of(&reply), rcode::REFUSED);

        // A wrong class.
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        encode_name("x.vox", &mut q);
        q.extend_from_slice(&[0, 28, 0, 3]); // CLASS CH
        assert_eq!(rcode_of(&answer(&q, &r).unwrap()), rcode::NXDOMAIN);
    }

    #[test]
    fn the_case_of_a_name_does_not_matter() {
        let g = service_room(&root(8), 0xA8);
        let mut r = VoxResolver::new();
        r.insert(&g);
        let host = vox_hostname(&g.channel_id());
        for variant in [host.clone(), host.to_uppercase()] {
            let reply = answer(&query(&variant, TYPE_AAAA), &r).unwrap();
            assert_eq!(rcode_of(&reply), rcode::NOERROR, "{variant}");
            assert_eq!(answer_count(&reply), 1);
        }
    }

    #[tokio::test]
    async fn the_responder_answers_over_a_real_socket_and_refuses_a_public_bind() {
        let creator = root(9);
        let g = service_room(&creator, 0xB9);
        let mut r = VoxResolver::new();
        r.insert(&g);

        // It will not bind anything but loopback: this namespace is private to the
        // machine, and there is no version of it that should be reachable from off it.
        assert!(matches!(
            serve("0.0.0.0:0".parse().unwrap(), r.clone()).await,
            Err(Error::MalformedLink(_))
        ));

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bound = sock.local_addr().unwrap();
        drop(sock);
        let task = tokio::spawn(serve(bound, r));

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let q = query(&vox_hostname(&g.channel_id()), TYPE_AAAA);
        let mut buf = vec![0u8; MAX_DNS_MESSAGE];
        let n = loop {
            client.send_to(&q, bound).await.unwrap();
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                client.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((n, _))) => break n,
                // The responder may not have bound yet; retry rather than race.
                _ => continue,
            }
        };
        assert_eq!(rcode_of(&buf[..n]), rcode::NOERROR);
        assert_eq!(answer_count(&buf[..n]), 1);
        let want = overlay_addr(&creator.public_key().to_bytes()).octets();
        assert_eq!(&buf[n - 16..n], &want);
        task.abort();
    }
}
