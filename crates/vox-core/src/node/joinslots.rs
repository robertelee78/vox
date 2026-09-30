//! **Who holds this node's join slots, and who gives one up when they are all taken** (V210-92).
//!
//! A node answers inbound joins in a fixed number of slots (`JOINS_IN_FLIGHT` in the actor), and a
//! join past the cap is refused, not queued. Taking a slot needs nothing but the room's address:
//! the slot is taken before the joiner has done any work, and the member then waits for the
//! joiner's proof of work for as long as a slow device may need — 480s and up since V210-87. So a
//! stranger who opens joins and never finishes them held every slot for that long, first come
//! first served, and a real person joining through that member was refused on every try.
//!
//! **The slots are shared by source, and the heaviest source gives one up.** When a join arrives
//! and every slot is held, each hold is weighed by how many holds its source address has, then by
//! how many its identity has, counting the newcomer with its own. The newest hold of the heaviest
//! source is ended and its slot goes to the newcomer. If the newcomer is itself of the heaviest
//! source — being the newest, it is then that hold — it is refused, as every join past the cap was
//! before.
//!
//! - One address or one identity, however many joins it opens, keeps a joiner from anywhere else
//!   out of nothing: the newcomer weighs one, the flood weighs more, and the flood gives way. The
//!   flood's next join is then the heaviest and newest, so it is refused, and the joiner it made
//!   room for keeps its slot for as long as its own proof of work takes. That is what V210-87's
//!   long wait is for, and nothing here shortens it.
//! - Joins that weigh the same — sixteen people joining at once, each from their own address — are
//!   first come first served, exactly as before: the newcomer is refused and nobody is ended.
//! - The address counts before the identity because an identity costs nothing to make and an
//!   address does. An IPv6 source is its /64, which one host is routinely given whole. A join over
//!   a relay circuit arrives at an address the circuit made up for itself, a fresh one per circuit,
//!   so every relayed join counts as one source and the identity tells them apart.
//!
//! What a hold never becomes is *verified*: until the proof of work arrives a slow honest joiner
//! and a stalling stranger look the same, which is why the weighing is by where they come from and
//! who they say they are, not by what they have done.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use crate::hash::Digest32;
use crate::transport::quic::VoxConnection;

/// Where a join came from, as far as sharing the slots goes. See the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinSource {
    /// Over a relay circuit, whose address is made up per circuit and says nothing.
    Relayed,
    /// An IPv4 address.
    V4([u8; 4]),
    /// The /64 of an IPv6 address.
    V6([u8; 8]),
}

impl JoinSource {
    /// The source of a join arriving on `conn`.
    #[must_use]
    pub fn of(conn: &VoxConnection) -> Self {
        if conn.via_circuit() {
            return Self::Relayed;
        }
        match conn.quinn().remote_address().ip().to_canonical() {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => {
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&v6.octets()[..8]);
                Self::V6(prefix)
            }
        }
    }
}

struct Hold {
    source: JoinSource,
    peer: Digest32,
    /// Set as soon as the exchange is spawned; see [`JoinSlots::attach`].
    exchange: Option<tokio::task::AbortHandle>,
}

/// The holds on a node's join slots.
pub struct JoinSlots {
    cap: usize,
    next: u64,
    /// By serial, which is the order the holds were taken in.
    holds: BTreeMap<u64, Hold>,
}

/// One held join slot. Dropping it — the exchange ending, however it ends — frees the slot.
pub struct JoinSlot {
    slots: Arc<Mutex<JoinSlots>>,
    serial: u64,
}

impl Drop for JoinSlot {
    fn drop(&mut self) {
        lock(&self.slots).holds.remove(&self.serial);
    }
}

impl JoinSlot {
    /// Which hold this is, for [`JoinSlots::attach`].
    #[must_use]
    pub fn serial(&self) -> u64 {
        self.serial
    }
}

/// A slot was taken from a heavier source's join to make room.
#[derive(Debug)]
pub struct Ended {
    /// Whose join was ended.
    pub peer: Digest32,
    /// How many holds its source address had, and its identity, counting the newcomer.
    pub weight: (usize, usize),
}

fn lock(slots: &Mutex<JoinSlots>) -> std::sync::MutexGuard<'_, JoinSlots> {
    slots.lock().unwrap_or_else(PoisonError::into_inner)
}

impl JoinSlots {
    /// `cap` slots, none held.
    #[must_use]
    pub fn new(cap: usize) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            cap,
            next: 0,
            holds: BTreeMap::new(),
        }))
    }

    /// Record the task answering hold `serial`, so it can be ended in favour of a lighter
    /// newcomer. Called by the actor straight after the spawn and before it takes another slot,
    /// so a hold is never weighed without a way to end it.
    pub fn attach(slots: &Mutex<Self>, serial: u64, exchange: tokio::task::AbortHandle) {
        if let Some(hold) = lock(slots).holds.get_mut(&serial) {
            hold.exchange = Some(exchange);
        }
    }

    /// How many joins are being answered now.
    #[must_use]
    pub fn in_flight(slots: &Mutex<Self>) -> usize {
        lock(slots).holds.len()
    }

    /// Take a slot for a join from `peer` at `source`: a free one, or the newest hold of a
    /// heavier source, which is ended (and named in the second value). `None` is a refusal —
    /// every slot is held and the newcomer's own source is the heaviest.
    pub fn take(
        slots: &Arc<Mutex<Self>>,
        peer: Digest32,
        source: JoinSource,
    ) -> Option<(JoinSlot, Option<Ended>)> {
        let mut s = lock(slots);
        let mut ended = None;
        if s.holds.len() >= s.cap {
            let weight = |src: JoinSource, who: Digest32| {
                let from = s.holds.values().filter(|h| h.source == src).count();
                let by = s.holds.values().filter(|h| h.peer == who).count();
                (
                    from + usize::from(src == source),
                    by + usize::from(who == peer),
                )
            };
            let newcomer = weight(source, peer);
            // The heaviest, and of those the newest: the newcomer is newer than every hold, so a
            // tie with it is its own refusal.
            let heaviest = s
                .holds
                .iter()
                .map(|(serial, h)| (weight(h.source, h.peer), *serial))
                .max();
            match heaviest {
                Some((w, serial)) if w > newcomer => {
                    if let Some(hold) = s.holds.remove(&serial) {
                        if let Some(exchange) = hold.exchange {
                            exchange.abort();
                        }
                        ended = Some(Ended {
                            peer: hold.peer,
                            weight: w,
                        });
                    }
                }
                _ => return None,
            }
        }
        let serial = s.next;
        s.next += 1;
        s.holds.insert(
            serial,
            Hold {
                source,
                peer,
                exchange: None,
            },
        );
        drop(s);
        Some((
            JoinSlot {
                slots: Arc::clone(slots),
                serial,
            },
            ended,
        ))
    }
}
