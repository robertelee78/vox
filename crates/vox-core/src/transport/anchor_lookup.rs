//! Explicit host:port lookup for an anchor (ADR-032 AN-9), below QUIC on its existing socket.
//! Replies are untrusted candidates. They name only explicitly served anchors, never ordinary
//! nodes or rooms. The caller must verify the candidate's normal Identity PROVE at the requested
//! address before keeping it. No reply by itself is a reach, trust, or room-membership fact.

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::transport::identity::{AskLimiter, SourceKey};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::oneshot;

// First byte has QUIC's fixed bit clear; this exact marker is never a QUIC packet.
const MAGIC: &[u8] = b"\0vox-anchor/1";
const PACKET: usize = 512;
const MAX_ANCHORS: usize = 8;
const MAX_PENDING: usize = 16;
type Nonce = [u8; 16];
type PendingReply = (SocketAddr, oneshot::Sender<Candidates>);
fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A bounded, unauthenticated lookup answer. Useful to explicit lookup and later LAN search.
#[derive(Debug, Clone)]
pub struct Candidates {
    /// Candidates, sorted and unique; each must still prove its identity.
    pub fingerprints: Vec<Digest32>,
    /// More anchors exist than fit; never silently select one.
    pub truncated: bool,
}

/// Recognise only the reserved marker; malformed lookup packets are swallowed, never QUIC.
#[must_use]
pub fn is_packet(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Parse an answer for this request's unpredictable nonce. Source-address matching is separate.
#[must_use]
pub fn reply(bytes: &[u8], nonce: &[u8; 16]) -> Option<Candidates> {
    let at = MAGIC.len();
    if bytes.len() != PACKET
        || !is_packet(bytes)
        || bytes[at] != 1
        || &bytes[at + 1..at + 17] != nonce
    {
        return None;
    }
    let count = usize::from(bytes[at + 17]);
    if count > MAX_ANCHORS || bytes[at + 18] > 1 {
        return None;
    }
    let mut fingerprints = Vec::new();
    for chunk in bytes[at + 19..at + 19 + count * 32].chunks_exact(32) {
        fingerprints.push(chunk.try_into().ok()?);
    }
    if fingerprints.windows(2).any(|pair| pair[0] >= pair[1]) {
        return None;
    }
    if bytes[at + 19 + count * 32..].iter().any(|b| *b != 0) {
        return None;
    }
    Some(Candidates {
        fingerprints,
        truncated: bytes[at + 18] != 0,
    })
}

/// The existing socket's small lookup state. No identities or long-term keys are retained here.
pub struct Lookup {
    anchors: Mutex<Vec<Digest32>>,
    pending: Mutex<BTreeMap<Nonce, PendingReply>>,
    limiter: AskLimiter,
}
impl Default for Lookup {
    fn default() -> Self {
        Self {
            anchors: Mutex::default(),
            pending: Mutex::default(),
            limiter: AskLimiter::standard(),
        }
    }
}
impl Lookup {
    /// Replace only the explicitly served anchors on this socket.
    pub fn serve(&self, mut anchors: Vec<Digest32>) {
        anchors.sort_unstable();
        anchors.dedup();
        *lock(&self.anchors) = anchors;
    }
    /// Start one bounded lookup; dropping its pending handle removes its nonce.
    ///
    /// # Errors
    /// No random nonce or too many simultaneous lookups.
    pub fn begin(&self, target: SocketAddr) -> Result<(Vec<u8>, Pending<'_>)> {
        let nonce = crate::identity::rng::random_array()?;
        let (tx, rx) = oneshot::channel();
        let mut pending = lock(&self.pending);
        if pending.len() >= MAX_PENDING {
            return Err(Error::Profile("too many anchor lookups in progress"));
        }
        pending.insert(nonce, (target, tx));
        let mut packet = vec![0; PACKET];
        packet[..MAGIC.len()].copy_from_slice(MAGIC);
        packet[MAGIC.len() + 1..MAGIC.len() + 17].copy_from_slice(&nonce);
        Ok((
            packet,
            Pending {
                lookup: self,
                nonce,
                rx,
            },
        ))
    }
    /// Consume one packet; a response can be sent back to exactly its source. Same size as the
    /// request and rate-limited before inspecting configured anchors: no UDP amplification.
    pub fn receive(&self, from: SocketAddr, bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.len() != PACKET || !is_packet(bytes) {
            return None;
        }
        let at = MAGIC.len();
        let nonce: Nonce = bytes[at + 1..at + 17].try_into().ok()?;
        if bytes[at] == 1 {
            let candidate = reply(bytes, &nonce)?;
            let mut pending = lock(&self.pending);
            if pending.get(&nonce).is_some_and(|(target, _)| {
                target.ip().to_canonical() == from.ip().to_canonical()
                    && target.port() == from.port()
            }) {
                if let Some((_, tx)) = pending.remove(&nonce) {
                    let _ = tx.send(candidate);
                }
            }
            return None;
        }
        if bytes[at] != 0
            || bytes[at + 17..].iter().any(|b| *b != 0)
            || !self.limiter.admit(SourceKey::of_addr(from))
        {
            return None;
        }
        let anchors = lock(&self.anchors);
        if anchors.is_empty() {
            return None;
        }
        let mut out = bytes.to_vec();
        out[at] = 1;
        let count = anchors.len().min(MAX_ANCHORS);
        out[at + 17] = count as u8;
        out[at + 18] = u8::from(anchors.len() > MAX_ANCHORS);
        for (i, id) in anchors.iter().take(count).enumerate() {
            out[at + 19 + i * 32..at + 19 + (i + 1) * 32].copy_from_slice(id);
        }
        Some(out)
    }
}

/// One request's cancellation-safe bounded reply wait.
pub struct Pending<'a> {
    lookup: &'a Lookup,
    nonce: Nonce,
    rx: oneshot::Receiver<Candidates>,
}
impl Pending<'_> {
    /// Await the matching source and nonce.
    ///
    /// # Errors
    /// The endpoint does not answer within one second, or the socket closes.
    pub async fn wait(mut self) -> Result<Candidates> {
        tokio::time::timeout(Duration::from_secs(1), &mut self.rx)
            .await
            .map_err(|_| Error::Profile("that address did not answer the anchor lookup"))?
            .map_err(|_| Error::Profile("anchor lookup stopped"))
    }
}
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        lock(&self.lookup.pending).remove(&self.nonce);
    }
}
