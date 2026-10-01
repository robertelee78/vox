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
//!   address does. An IPv6 source is weighed **coarse to fine**: its /48, then its /56, then its
//!   /64, compared in that order. One host is routinely given a /64 whole and a home a /56, so a
//!   stranger with a /56 (or a /48 spread across /56s) weighs as one source and not as hundreds.
//!   An IPv4 source is its address at every level.
//! - **A join over a relay circuit counts from where it really comes from.** The circuit's own
//!   address is made up per circuit and says nothing, so the relay says where the asker is: its
//!   `INCOMING` frame carries three tags for the asker's address, coarse to fine, keyed per
//!   process so this node can group joiners by them but never learns a relayed joiner's address
//!   ([`crate::node::circuitstream::origin_tags`]). They are taken only from a relay this node
//!   trusts to say — its **anchor or a member** — and are kept apart per relay. A relay that is
//!   only a pending joiner is a stranger like any other, so what it carries counts as coming from
//!   the relay itself; otherwise a stranger could mint a source per relay identity it made.
//!   A relay that lies about its tags can only mis-group what it carries, which it could as well
//!   refuse to carry.
//! - What one host cannot do is be told apart from itself: a real joiner on the attacker's own
//!   host, under the attacker's own address, weighs what each of the attacker's joins weighs.
//!
//! **A hold that has done the work keeps its slot** (V210-92). Once a join's proof of work has
//! verified, the joiner has paid what the slot costs; it is never the hold ended for a newcomer,
//! because ending it mid-admission could leave the member admitting a joiner that has been told
//! nothing. It is not held for ever either: from then on the rest of the exchange must finish within
//! `ADMISSION_PATIENCE` (`node::joinstream`), so a stranger that pays sixteen solves and then stalls
//! gives every slot back within it.
//!
//! **An ended join is told why.** The exchange of a hold that is ended stops at once and tells its
//! joiner the member is busy answering other joins, the same `Busy` a join refused at the cap
//! hears — never the bare refusal a wrong passphrase gets.
//!
//! What a hold never becomes is *verified*: until the proof of work arrives a slow honest joiner
//! and a stalling stranger look the same, which is why the weighing is by where they come from and
//! who they say they are, not by what they have done.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::hash::{domain_hash, Digest32};
use crate::transport::mux::CircuitOrigin;
use crate::transport::quic::VoxConnection;

/// Where a join came from, as far as sharing the slots goes: three opaque keys, coarse to fine.
/// See the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinSource(pub [Digest32; 3]);

impl JoinSource {
    /// The source of a join arriving on `conn`: its address, or for a relayed join the origin
    /// recorded when its circuit was attached.
    #[must_use]
    pub fn of(conn: &VoxConnection) -> Self {
        Self(source_levels(conn))
    }
}

/// The three source keys of `ip`, coarse to fine: an IPv4 address at every level, an IPv6
/// address by its /48, /56 and /64.
#[must_use]
pub fn address_levels(ip: IpAddr) -> [Digest32; 3] {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let key = domain_hash("vox/join-source/v4", &v4.octets());
            [key, key, key]
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            [
                domain_hash("vox/join-source/v6/48", &o[..6]),
                domain_hash("vox/join-source/v6/56", &o[..7]),
                domain_hash("vox/join-source/v6/64", &o[..8]),
            ]
        }
    }
}

/// The source keys of whoever is at the far end of `conn`: its address, or, over a circuit, the
/// origin recorded for it. A circuit with **no origin recorded** is one source, the same for every
/// such circuit: nothing about it says where it comes from, and keying it on anything the far end
/// chooses — its identity, which is free — would hand every stranger a source of its own.
#[must_use]
pub fn source_levels(conn: &VoxConnection) -> [Digest32; 3] {
    if conn.via_circuit() {
        return conn.circuit_origin().unwrap_or_else(|| {
            let key = domain_hash("vox/join-source/relayed-unknown", &[]);
            [key, key, key]
        });
    }
    address_levels(conn.quinn().remote_address().ip())
}

/// The origin of a circuit `relay` carried here, from the `tags` it said the asker has. Kept
/// apart per relay, so two relays' tags never fall together.
#[must_use]
pub fn relayed_origin(relay: &Digest32, tags: &[[u8; 16]; 3]) -> CircuitOrigin {
    let level = |i: usize| {
        let mut input = Vec::with_capacity(32 + 1 + 16);
        input.extend_from_slice(relay.as_ref());
        input.push(u8::try_from(i).unwrap_or(u8::MAX));
        input.extend_from_slice(&tags[i]);
        domain_hash("vox/join-source/relayed", &input)
    };
    [level(0), level(1), level(2)]
}

struct Hold {
    source: JoinSource,
    peer: Digest32,
    /// Set once the joiner's proof of work has verified; see [`JoinSlot::worked`].
    worked: Arc<AtomicBool>,
    /// Told when this hold is ended for a newcomer; see [`JoinSlot::take_ended`].
    end: Option<tokio::sync::oneshot::Sender<()>>,
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
    worked: Arc<AtomicBool>,
    ended: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl Drop for JoinSlot {
    fn drop(&mut self) {
        lock(&self.slots).holds.remove(&self.serial);
    }
}

impl JoinSlot {
    /// Set by the exchange once the joiner's proof of work has verified. A hold so marked is
    /// never ended for a newcomer (see the module docs).
    #[must_use]
    pub fn worked(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.worked)
    }

    /// Resolves when this hold is ended for a newcomer, so the exchange can tell its joiner why
    /// before it stops. `None` after the first call.
    pub fn take_ended(&mut self) -> Option<tokio::sync::oneshot::Receiver<()>> {
        self.ended.take()
    }
}

/// A slot was taken from a heavier source's join to make room.
#[derive(Debug)]
pub struct Ended {
    /// Whose join was ended.
    pub peer: Digest32,
    /// How many holds its source had at each level, coarse to fine, and its identity, counting
    /// the newcomer.
    pub weight: Weight,
}

/// A hold's weight: how many holds share its source at each level, coarse to fine, then its
/// identity. Compared in that order.
pub type Weight = (usize, usize, usize, usize);

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

    /// How many joins are being answered now.
    #[must_use]
    pub fn in_flight(slots: &Mutex<Self>) -> usize {
        lock(slots).holds.len()
    }

    /// Take a slot for a join from `peer` at `source`: a free one, or the newest hold of a
    /// heavier source that has not yet done its work, which is ended (and named in the second
    /// value). `None` is a refusal — every slot is held and no hold that could give way is
    /// heavier than the newcomer.
    pub fn take(
        slots: &Arc<Mutex<Self>>,
        peer: Digest32,
        source: JoinSource,
    ) -> Option<(JoinSlot, Option<Ended>)> {
        let mut s = lock(slots);
        let mut ended = None;
        if s.holds.len() >= s.cap {
            let weight = |src: JoinSource, who: Digest32| -> Weight {
                let at = |level: usize| {
                    s.holds
                        .values()
                        .filter(|h| h.source.0[level] == src.0[level])
                        .count()
                        + usize::from(source.0[level] == src.0[level])
                };
                let by =
                    s.holds.values().filter(|h| h.peer == who).count() + usize::from(who == peer);
                (at(0), at(1), at(2), by)
            };
            let newcomer = weight(source, peer);
            // The heaviest of the holds that may give way, and of those the newest: the newcomer
            // is newer than every hold, so a tie with it is its own refusal. Every hold counts
            // towards every weight; a hold that has done its work is only never the one ended.
            let heaviest = s
                .holds
                .iter()
                .filter(|(_, h)| !h.worked.load(Ordering::Acquire))
                .map(|(serial, h)| (weight(h.source, h.peer), *serial))
                .max();
            match heaviest {
                Some((w, serial)) if w > newcomer => {
                    if let Some(mut hold) = s.holds.remove(&serial) {
                        if let Some(end) = hold.end.take() {
                            let _ = end.send(());
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
        let worked = Arc::new(AtomicBool::new(false));
        let (end, ended_rx) = tokio::sync::oneshot::channel();
        s.holds.insert(
            serial,
            Hold {
                source,
                peer,
                worked: Arc::clone(&worked),
                end: Some(end),
            },
        );
        drop(s);
        Some((
            JoinSlot {
                slots: Arc::clone(slots),
                serial,
                worked,
                ended: Some(ended_rx),
            },
            ended,
        ))
    }
}
