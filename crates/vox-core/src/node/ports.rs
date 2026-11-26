//! Per-room, per-peer state and bounded inbound serving ownership.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use crate::hash::Digest32;
use crate::transport::quic::VoxConnection;
use crate::transport::stream_transport::Fence;

/// Inbound sessions a port admits at once (ADR-025 D4). A correct peer may hold one Public plus
/// one Background outbound; the third position covers a previous session still being applied.
/// Beyond it an inbound session is refused at once with `SessionBusy`, never held.
pub const INBOUND_PER_PORT: usize = 3;

/// A session attempt's identity within this node's life.
pub type Token = u64;

/// One running session (ADR-025 D1).
pub struct Attempt {
    /// Its token.
    pub token: Token,
    /// The connection it runs on; its death retires the attempt.
    pub conn: Arc<VoxConnection>,
    /// Its task, aborted on retirement (a task not spawned yet has none).
    pub abort: Option<tokio::task::AbortHandle>,
    /// Its fence (ADR-025 D1a).
    pub fence: Arc<Fence>,
    /// Live status registration, removed when the attempt is retired.
    pub _running: crate::node::status::Running,
    /// Set only after a bounded inbound request has decoded the exact
    /// `Control/Head(peer)` query. If that peer departs while the response is in flight,
    /// lifecycle cleanup may retain this attempt long enough to return its semantic receipt;
    /// it grants no inventory, body, proof, archive or membership access.
    pub departure_receipt: Option<Arc<AtomicBool>>,
    /// Inbound authenticated-history transport admitted only for own-author recovery.
    /// The server still binds and revalidates each query; this flag is not authority.
    pub limited_recovery: bool,
}

impl Attempt {
    /// Whether this inbound attempt has decoded the one query a departed peer may finish.
    #[must_use]
    pub fn is_departure_receipt(&self) -> bool {
        self.departure_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.load(Ordering::Acquire))
    }

    /// Stop it: the fence first, so a worker already running stops at its next step, then the
    /// task. Consumes the attempt, so this happens once.
    pub fn retire(self) {
        self.fence.retire();
        if let Some(a) = self.abort {
            a.abort();
        }
    }
}

/// Which room instance a port belongs to. Held weakly, so a port never keeps a locked room's
/// state alive, and compared by pointer: a room closed and held again is a new instance, and its
/// ports start over (a reopen after a poison, an unlock, a new epoch).
#[derive(Debug, Clone)]
pub enum RoomRef {
    /// A room this node is a member of: the only kind it syncs (ADR-023 decision 6).
    Channel(Weak<crate::node::channel::RoomLock>),
}

impl RoomRef {
    /// Whether this is the instance `current` names.
    #[must_use]
    pub fn is(&self, current: &RoomRef) -> bool {
        match (self, current) {
            (Self::Channel(a), Self::Channel(b)) => a.ptr_eq(b),
        }
    }
}

/// Useful authenticated own-head response, scoped to the actual recipient and connection.
/// This is not authority, a body receipt, or a certificate about an offline peer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SupportDiscovery {
    pub connection: u64,
    pub instance: [u8; 16],
    pub epoch: u64,
    pub authorization: Digest32,
}

/// One `(room, peer)`'s sync port (ADR-025 D1).
pub struct Port {
    /// The room instance it belongs to.
    pub room: RoomRef,
    /// Immutable epoch of this room instance.
    pub epoch: u64,
    /// Wire/history format of this room instance.
    pub sparse: bool,
    /// Inbound workers retain their fences until retirement or completion.
    pub inbound: BTreeMap<Token, Attempt>,
    /// The room is poisoned: no session until it is reopened.
    pub poisoned: bool,
    pub(crate) support_discovery: Option<SupportDiscovery>,
    /// The room generation credited to the peer: monotonic within the room instance.
    pub done_gen: u64,
}

impl Port {
    /// A fresh port for `room`.
    #[must_use]
    pub(crate) fn new(room: RoomRef, epoch: u64, sparse: bool) -> Self {
        Self {
            room,
            epoch,
            sparse,
            inbound: BTreeMap::new(),
            poisoned: false,
            support_discovery: None,
            done_gen: 0,
        }
    }

    /// Whether it holds any attempt.
    #[must_use]
    pub fn busy(&self) -> bool {
        !self.inbound.is_empty()
    }

    /// Take every attempt out, to be retired.
    pub fn take_attempts(&mut self) -> Vec<Attempt> {
        std::mem::take(&mut self.inbound).into_values().collect()
    }

    /// Take the attempt with `token`, if the port still holds it.
    pub fn take(&mut self, token: Token) -> Option<Attempt> {
        self.inbound.remove(&token)
    }
}
