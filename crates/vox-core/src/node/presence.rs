//! **The daemon's one network presence** (ADR-026 D-3, ADR-012 N-41–N-45): one UDP socket, one
//! QUIC endpoint ([`SharedEndpoint`]) and one inbound gate, shared by every node attached.
//!
//! A node attaches ([`NetPresence::attach`]) and gets its view of the endpoint and the connections
//! accepted for it. The presence accepts every inbound attempt under one gate — at most
//! [`HANDSHAKES_IN_FLIGHT`] handshakes and identity exchanges at once, a validated attempt past
//! that waiting a moment for a slot, an unvalidated one sent a Retry — runs the neutral handshake
//! and the identity exchange, and hands the connection to the node the exchange named. A node
//! sees only its own connections, and never one before its `CLAIM` verified (ADR-011
//! requirement 33).
//!
//! A node that detaches drops its [`NodeLink`]: it leaves the exchange (its signer with it), its
//! inbound queue closes, and nothing about the endpoint or any other node's connections changes
//! (D-5). Closing the presence ([`NetPresence::close`]) is the daemon stopping.
//!
//! A node that has the machine to itself (today's `vox daemon` and `vox serve`) runs on a presence
//! of its own, made for it and closed with it.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, Semaphore};

use crate::error::Result;
use crate::identity::composite::RootSigner;
use crate::transport::quic::{unix_now, SharedEndpoint, VoxConnection, VoxEndpoint};

/// How many inbound handshakes — the TLS handshake and the identity exchange after it — may run
/// at once (ADR-011 requirement 34): the cap pre-identity connections share.
///
/// Inline, the ceiling was one, which was the defect. Enough that ordinary use never reaches it,
/// small enough that an attacker cannot make a daemon hold unbounded state.
pub const HANDSHAKES_IN_FLIGHT: usize = 64;

/// How many validated attempts may wait for a handshake slot at once; past it, one is refused.
/// Twice the members of a large room (PRD-001), so a whole room redialling a restarted anchor
/// waits rather than being turned away, and still a bound on what a flood can make a node hold.
pub const HANDSHAKES_WAITING: usize = 1024;

/// How long a validated attempt may wait for a handshake slot before it is refused: half of what
/// a dialler gives one attempt (`nat::reachability::PER_ATTEMPT_TIMEOUT`, 10 s), so an attempt
/// given a slot still has a dialler waiting for it.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);

/// How many accepted connections may wait for a node to take them before more are closed.
const INBOUND_QUEUE: usize = 256;

/// How long the presence's close waits for the closes to leave: the node's stop budget for it.
const CLOSE_FLUSH: Duration = Duration::from_millis(600);

/// One burst of inbound attempts that had to wait for a handshake slot, from the first that
/// waited until none was waiting: what each node says of it (`NodeEvent::HandshakesQueued`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandshakeBurst {
    /// How many waited in all.
    pub waited: usize,
    /// The most that waited at once.
    pub most_waiting: usize,
    /// The most handshakes seen running at once.
    pub most_running: usize,
    /// How many were refused: no place to wait, or no slot within [`HANDSHAKE_WAIT`].
    pub refused: usize,
    /// The longest any waited.
    pub longest: Duration,
}

/// The burst being counted, with how many wait now.
#[derive(Default)]
struct Burst {
    waiting: usize,
    counted: HandshakeBurst,
}

impl Burst {
    /// A handshake took a slot of `gate`.
    fn ran(&mut self, gate: &Semaphore) {
        if self.waiting > 0 {
            self.counted.most_running = self
                .counted
                .most_running
                .max(HANDSHAKES_IN_FLIGHT - gate.available_permits());
        }
    }

    /// An attempt starts waiting for a slot of `gate`.
    fn enter(&mut self, gate: &Semaphore) {
        self.counted.most_running = self
            .counted
            .most_running
            .max(HANDSHAKES_IN_FLIGHT - gate.available_permits());
        self.waiting += 1;
        self.counted.waited += 1;
        self.counted.most_waiting = self.counted.most_waiting.max(self.waiting);
    }

    /// An attempt stops waiting after `waited`; when it was the last, the burst is over.
    fn leave(&mut self, waited: Duration) -> Option<HandshakeBurst> {
        self.waiting -= 1;
        self.counted.longest = self.counted.longest.max(waited);
        self.over()
    }

    /// When nothing is left waiting, the burst is over: what it came to. A refusal with nothing
    /// waiting is a burst of its own, so no refusal goes unsaid.
    fn over(&mut self) -> Option<HandshakeBurst> {
        (self.waiting == 0).then(|| std::mem::take(&mut self.counted))
    }
}

fn lock_burst(b: &Mutex<Burst>) -> std::sync::MutexGuard<'_, Burst> {
    b.lock().unwrap_or_else(PoisonError::into_inner)
}

/// **The machine's one presence**: the shared endpoint and the gate in front of it.
pub struct NetPresence {
    shared: Arc<SharedEndpoint>,
    bursts: broadcast::Sender<HandshakeBurst>,
    accept: tokio::task::AbortHandle,
}

/// A node's attachment to a [`NetPresence`]: its view of the endpoint, and the connections
/// accepted for it. Dropping the endpoint view takes the node off the exchange.
pub struct NodeLink {
    /// This node's view of the shared endpoint.
    pub endpoint: Arc<VoxEndpoint>,
    /// Connections accepted for this node, after their identity exchange.
    pub inbound: mpsc::Receiver<VoxConnection>,
}

impl NetPresence {
    /// Run the presence on `shared`: its accept loop starts now.
    #[must_use]
    pub fn start(shared: Arc<SharedEndpoint>) -> Arc<Self> {
        let (bursts, _) = broadcast::channel(16);
        let accept = spawn_accept_loop(Arc::clone(&shared), bursts.clone());
        Arc::new(Self {
            shared,
            bursts,
            accept,
        })
    }

    /// Bind a presence on `addr` ([`SharedEndpoint::bind`]).
    ///
    /// # Errors
    /// As [`SharedEndpoint::bind`].
    pub fn bind(addr: std::net::SocketAddr) -> Result<Arc<Self>> {
        Ok(Self::start(SharedEndpoint::bind(addr)?))
    }

    /// **Attach a node**: register it on the endpoint with a fresh instance, and give it its view
    /// and its inbound connections.
    ///
    /// # Errors
    /// As [`SharedEndpoint::register`]: the node is attached here already.
    pub fn attach(&self, signer: Arc<dyn RootSigner + Send + Sync>) -> Result<NodeLink> {
        let (tx, inbound) = mpsc::channel(INBOUND_QUEUE);
        let endpoint = self.shared.register(signer, Some(tx))?;
        Ok(NodeLink {
            endpoint: Arc::new(endpoint),
            inbound,
        })
    }

    /// The shared endpoint.
    #[must_use]
    pub fn shared(&self) -> &Arc<SharedEndpoint> {
        &self.shared
    }

    /// The handshake bursts the gate reports, for a node to say.
    #[must_use]
    pub fn bursts(&self) -> broadcast::Receiver<HandshakeBurst> {
        self.bursts.subscribe()
    }

    /// **Close the presence** — the daemon stopping: the accept loop ends, the endpoint and every
    /// connection on it close, and the closes are given a moment to leave.
    pub async fn close(&self) {
        self.accept.abort();
        self.shared.close();
        let _ = tokio::time::timeout(CLOSE_FLUSH, self.shared.wait_idle()).await;
    }
}

impl Drop for NetPresence {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// **The accept loop and its gate**, moved here from the node (it was `actor::spawn_accept_loop`):
/// one per presence, so the cap is the daemon's, not each node's.
///
/// - An attempt that finds a slot runs at once, on a task of its own.
/// - Past [`HANDSHAKES_IN_FLIGHT`], an attempt whose source address is **not yet validated** gets
///   a QUIC Retry, which a spoofed flood cannot answer and a real peer pays one round trip for.
/// - One that **is** validated waits for a slot on a task of its own, up to [`HANDSHAKE_WAIT`],
///   with at most [`HANDSHAKES_WAITING`] waiting; past either it is refused (V210-86, #278).
///
/// Each finished connection goes to the node its exchange named
/// ([`SharedEndpoint::route`]). **Residual, stated rather than implied:** 64 validated attempts
/// that stall still hold every slot for up to their handshake bound (30 s) plus the exchange's
/// (5 s).
fn spawn_accept_loop(
    shared: Arc<SharedEndpoint>,
    bursts: broadcast::Sender<HandshakeBurst>,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let gate = Arc::new(Semaphore::new(HANDSHAKES_IN_FLIGHT));
        let queue = Arc::new(Semaphore::new(HANDSHAKES_WAITING));
        let burst = Arc::new(Mutex::new(Burst::default()));
        while let Some(incoming) = shared.accept_incoming().await {
            if let Ok(permit) = Arc::clone(&gate).try_acquire_owned() {
                lock_burst(&burst).ran(&gate);
                spawn_handshake(Arc::clone(&shared), permit, incoming);
                continue;
            }
            if !incoming.remote_address_validated() {
                // `Err` means this attempt is already a retried one; retrying it again would
                // loop, so it is simply dropped.
                let _ = incoming.retry();
                continue;
            }
            let Ok(place) = Arc::clone(&queue).try_acquire_owned() else {
                let over = {
                    let mut b = lock_burst(&burst);
                    b.counted.refused += 1;
                    b.over()
                };
                incoming.refuse();
                if let Some(over) = over {
                    let _ = bursts.send(over);
                }
                continue;
            };
            lock_burst(&burst).enter(&gate);
            let (shared, gate, burst, bursts) = (
                Arc::clone(&shared),
                Arc::clone(&gate),
                Arc::clone(&burst),
                bursts.clone(),
            );
            tokio::spawn(async move {
                let since = std::time::Instant::now();
                let slot = tokio::time::timeout(HANDSHAKE_WAIT, Arc::clone(&gate).acquire_owned())
                    .await
                    .ok()
                    .and_then(std::result::Result::ok);
                drop(place);
                let over = {
                    let mut b = lock_burst(&burst);
                    if slot.is_some() {
                        b.ran(&gate);
                    } else {
                        b.counted.refused += 1;
                    }
                    b.leave(since.elapsed())
                };
                match slot {
                    Some(permit) => spawn_handshake(shared, permit, incoming),
                    None => incoming.refuse(),
                }
                if let Some(over) = over {
                    let _ = bursts.send(over);
                }
            });
        }
    })
    .abort_handle()
}

/// One inbound handshake and identity exchange on its own task, holding `permit` throughout,
/// then the connection handed to its node.
fn spawn_handshake(
    shared: Arc<SharedEndpoint>,
    permit: tokio::sync::OwnedSemaphorePermit,
    incoming: quinn::Incoming,
) {
    tokio::spawn(async move {
        let _permit = permit;
        if let Ok(conn) = shared.finish_incoming(incoming, unix_now()).await {
            shared.route(conn);
        }
    });
}

#[cfg(test)]
#[path = "presence_tests.rs"]
mod tests;
