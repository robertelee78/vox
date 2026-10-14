//! Explicit LAN anchor search (ADR-032 AN-6/7). Nothing is announced unasked.
//!
//! Questions use nearby's TTL-one group, with a random nonce and no room identity. Replies go
//! to the searcher's ephemeral port so the daemon's existing group listeners cannot consume
//! them. The result is only a pinned dial target: ordinary anchor transport must prove that
//! fingerprint before it is trusted. Neither search nor answering persists configuration.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::{Nearby, GROUP, PORT};
use crate::nat::bootstrap::{BootstrapNode, BootstrapSet, MAX_BOOTSTRAP_NODES};

const QUESTION: &[u8] = b"vox-anchor-search/1";
const ANSWER: &[u8] = b"vox-anchor-answer/1";
const NONCE: usize = 16;
// A padded question is at least as large as one response. The responder also rate-limits the
// complete attached-anchor set, so arbitrary LAN traffic cannot create an unbounded queue.
const DATAGRAM: usize = 1200;
/// One explicit search finishes after this listening window, including when nobody answers.
pub const SEARCH_WITHIN: Duration = Duration::from_secs(2);

/// A listener shared by the daemon's attached headless anchors.
pub struct Responder(Nearby);

impl Responder {
    /// Join nearby's existing local-network and loopback multicast group.
    pub fn open() -> std::io::Result<Self> {
        let nearby = Nearby::open()?;
        nearby.socket.set_ttl(1)?;
        Ok(Self(nearby))
    }

    /// Read exactly one datagram. Unrelated member discovery and malformed input have no answer.
    pub async fn question(&self) -> std::io::Result<Option<(SocketAddr, [u8; NONCE])>> {
        let mut bytes = [0u8; DATAGRAM + 1];
        let (n, from) = self.0.socket.recv_from(&mut bytes).await?;
        if n != DATAGRAM
            || !bytes.starts_with(QUESTION)
            || from.port() == 0
            || from.ip().is_unspecified()
            || from.ip().is_multicast()
        {
            return Ok(None);
        }
        let start = QUESTION.len();
        if bytes[start + NONCE..n].iter().any(|b| *b != 0) {
            return Ok(None);
        }
        let mut nonce = [0; NONCE];
        nonce.copy_from_slice(&bytes[start..start + NONCE]);
        Ok(Some((from, nonce)))
    }

    /// Best-effort bounded response; no task or retry is queued for an unavailable receiver.
    pub fn answer(&self, to: SocketAddr, nonce: &[u8; NONCE], anchor: &BootstrapNode) {
        let mut set = BootstrapSet::new();
        if set.add(anchor.clone()).is_err() {
            return;
        }
        let mut bytes = Vec::with_capacity(DATAGRAM);
        bytes.extend_from_slice(ANSWER);
        bytes.extend_from_slice(nonce);
        bytes.extend_from_slice(&set.to_bytes());
        if bytes.len() <= DATAGRAM {
            let _ = self.0.socket.try_send_to(&bytes, to);
        }
    }
}

/// Ask once on each nearby interface and collect bounded, nonce-matched answers. Only a person
/// choosing search calls this; an empty result is a completed search, never a failed create.
pub async fn search() -> std::io::Result<BootstrapSet> {
    let s = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    s.set_multicast_ttl_v4(1)?;
    s.set_multicast_loop_v4(true)?;
    s.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(s.into())?;
    let mut nonce = [0u8; NONCE];
    getrandom::fill(&mut nonce).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut question = [0u8; DATAGRAM];
    question[..QUESTION.len()].copy_from_slice(QUESTION);
    question[QUESTION.len()..QUESTION.len() + NONCE].copy_from_slice(&nonce);
    let mut sent = false;
    let mut last_error = None;
    for via in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST] {
        let sock = socket2::SockRef::from(&socket);
        if let Err(e) = sock.set_multicast_if_v4(&via) {
            last_error = Some(e);
            continue;
        }
        match socket
            .send_to(&question, SocketAddr::from((GROUP, PORT)))
            .await
        {
            Ok(_) => sent = true,
            Err(e) => last_error = Some(e),
        }
    }
    if !sent {
        return Err(
            last_error.unwrap_or_else(|| std::io::Error::other("no local search interface"))
        );
    }
    let until = tokio::time::Instant::now() + SEARCH_WITHIN;
    let mut result = BootstrapSet::new();
    let mut bytes = [0u8; DATAGRAM + 1];
    let mut packets = 0usize;
    loop {
        let n = match tokio::time::timeout_at(until, socket.recv_from(&mut bytes)).await {
            Err(_) => return Ok(result),
            Ok(Err(e)) => return Err(e),
            Ok(Ok((n, _))) => n,
        };
        // Bound work as well as retained data even if an unrelated sender floods this port.
        packets += 1;
        if packets.is_multiple_of(64) {
            tokio::task::yield_now().await;
        }
        if tokio::time::Instant::now() >= until {
            return Ok(result);
        }
        let prefix = ANSWER.len() + NONCE;
        if n > DATAGRAM
            || n < prefix
            || !bytes[..n].starts_with(ANSWER)
            || bytes[ANSWER.len()..prefix] != nonce
        {
            continue;
        }
        let Ok(set) = BootstrapSet::from_bytes(&bytes[prefix..n]) else {
            continue;
        };
        if set.len() != 1 {
            continue;
        }
        let anchor = &set.nodes()[0];
        // Searches only advertise concrete served endpoints, never a further relay to chase.
        if anchor.endpoints.addrs().iter().any(|a| {
            a.socket_addr()
                .is_none_or(|s| s.port() == 0 || s.ip().is_unspecified() || s.ip().is_multicast())
        }) {
            continue;
        }
        if result.get(&anchor.id).is_none() && result.len() == MAX_BOOTSTRAP_NODES {
            return Err(std::io::Error::other(
                "more than 64 anchors answered; narrow the search or enter an address",
            ));
        }
        result.add(anchor.clone()).map_err(std::io::Error::other)?;
    }
}
