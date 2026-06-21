//! DCUtR-style hole-punch coordination (ADR-012 step 3: "DCUtR-style
//! hole-punching, coordinated over a peer/own-node relay (Connect/Sync, half-RTT
//! timer)").
//!
//! When neither peer has a directly-reachable advertised endpoint but a coordinator
//! (any online channel member, or the user's own node) can relay lightweight
//! signaling, the two peers synchronize a *simultaneous open* so each one's
//! outbound packets punch a hole the other's packets traverse. This module is the
//! coordination **state machine** and its **message codec**; the synchronized dial
//! itself is [`crate::nat::reachability::connect_direct`] on the shared QUIC
//! endpoint (so the punch leaves from the same local port the peer observed).
//!
//! ## Protocol (libp2p DCUtR)
//! 1. The **initiator** sends `Connect{observed_addrs}` over the relay and starts a
//!    timer.
//! 2. The **responder** replies `Connect{observed_addrs}`.
//! 3. The initiator measures the round-trip time (RTT) from its `Connect` to the
//!    responder's, sends `Sync`, waits **RTT/2**, then dials the responder.
//! 4. The responder, on receiving `Sync`, dials the initiator **immediately**.
//!
//! Because the initiator fires RTT/2 after sending `Sync` and the responder fires
//! when it *receives* `Sync` (also ~RTT/2 later), both dials hit the wire at the
//! same instant — the synchronization ADR-012 requires.
//!
//! ## Honest limit
//! Hole-punching cannot connect two peers both behind symmetric NAT (ADR-012); a
//! failed punch degrades to the relay rung, never a false success. The coordinator
//! relays only signaling, never traffic.

use std::net::SocketAddr;
use std::time::Duration;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::nat::multiaddr::EndpointList;

/// CBOR discriminant for a `Connect` coordination message.
const KIND_CONNECT: u64 = 0;
/// CBOR discriminant for a `Sync` coordination message.
const KIND_SYNC: u64 = 1;

/// A DCUtR coordination message exchanged over the relay (not an ADR-008 log
/// struct — it rides a dedicated relay stream, so it has its own compact,
/// strictly-decoded CBOR codec).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordMessage {
    /// Carries the sender's observed (reflexive) endpoints for the peer to dial.
    Connect {
        /// The sender's observed (reflexive) endpoints.
        observed: EndpointList,
    },
    /// The synchronization trigger (step 3/4).
    Sync,
}

impl CoordMessage {
    /// Canonical CBOR encoding: `Connect` → `[0, endpoints]`, `Sync` → `[1]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            CoordMessage::Connect { observed } => {
                e.array(2).uint(KIND_CONNECT);
                observed.encode_into(&mut e);
            }
            CoordMessage::Sync => {
                e.array(1).uint(KIND_SYNC);
            }
        }
        e.finish()
    }

    /// Strictly decode a coordination message; rejects unknown kinds, wrong arity,
    /// and trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let arity = d.array()?;
        let kind = d.uint()?;
        let msg = match (kind, arity) {
            (KIND_CONNECT, 2) => {
                let observed = EndpointList::decode_from(&mut d)?;
                CoordMessage::Connect { observed }
            }
            (KIND_SYNC, 1) => CoordMessage::Sync,
            (KIND_CONNECT | KIND_SYNC, _) => {
                return Err(Error::HolePunchFailed("coord message arity"))
            }
            _ => return Err(Error::HolePunchFailed("coord message unknown kind")),
        };
        d.finish()
            .map_err(|_| Error::HolePunchFailed("coord message trailing bytes"))?;
        Ok(msg)
    }
}

/// Which side of the punch this peer plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The peer that initiates: sends the first `Connect`, then `Sync`, then fires
    /// after RTT/2.
    Initiator,
    /// The peer that responds: replies `Connect`, then fires on `Sync`.
    Responder,
}

/// The fire instruction produced when coordination completes: which of the peer's
/// observed addresses to dial, and how long to wait before the synchronized open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PunchPlan {
    /// The peer's observed direct addresses to dial simultaneously (IPv6 first).
    pub targets: Vec<SocketAddr>,
    /// Delay before firing the simultaneous open (RTT/2 for the initiator, zero for
    /// the responder).
    pub fire_delay: Duration,
}

/// The action the caller must take after feeding an event to the state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Send this message over the relay, then keep waiting for the next event.
    Send(CoordMessage),
    /// Send this `Sync`, then after `plan.fire_delay` fire the simultaneous open
    /// (initiator path: combine the two so the caller never forgets the timer).
    SyncThenPunch {
        /// The `Sync` message to send over the relay before firing.
        sync: CoordMessage,
        /// The simultaneous-open plan (targets + RTT/2 fire delay).
        plan: PunchPlan,
    },
    /// Fire the simultaneous open now per `plan` (responder path, on `Sync`).
    Punch {
        /// The simultaneous-open plan (targets + zero fire delay).
        plan: PunchPlan,
    },
}

/// The hole-punch coordination state machine. Pure and deterministic: it consumes
/// coordination events and emits [`Step`]s; all I/O (relay send, the RTT clock, the
/// dial) is the caller's. This keeps the synchronization logic fully unit-testable.
#[derive(Clone, Debug)]
pub struct Coordinator {
    role: Role,
    local_observed: EndpointList,
    /// `true` once the peer's `Connect` has been processed (so a stray second
    /// `Connect` or an early `Sync` is rejected as out-of-sequence).
    connected: bool,
}

impl Coordinator {
    /// Create a coordinator for `role`, advertising `local_observed` to the peer.
    #[must_use]
    pub fn new(role: Role, local_observed: EndpointList) -> Self {
        Self {
            role,
            local_observed,
            connected: false,
        }
    }

    /// The initiator's first message (the opening `Connect`). Returns `None` for the
    /// responder, which speaks only in reply.
    #[must_use]
    pub fn initial_message(&self) -> Option<CoordMessage> {
        match self.role {
            Role::Initiator => Some(CoordMessage::Connect {
                observed: self.local_observed.clone(),
            }),
            Role::Responder => None,
        }
    }

    /// Feed the peer's `Connect` message.
    ///
    /// - **Responder**: replies with its own `Connect` ([`Step::Send`]).
    /// - **Initiator**: `measured_rtt` is the round trip from its opening `Connect`
    ///   to this reply; returns [`Step::SyncThenPunch`] carrying the `Sync` to send
    ///   and the RTT/2 fire delay.
    pub fn on_peer_connect(
        &mut self,
        peer_observed: &EndpointList,
        measured_rtt: Option<Duration>,
    ) -> Result<Step> {
        if self.connected {
            return Err(Error::HolePunchFailed("duplicate Connect"));
        }
        self.connected = true;
        let targets = peer_observed.direct_candidates();
        if targets.is_empty() {
            return Err(Error::HolePunchFailed("peer advertised no direct endpoint"));
        }
        match self.role {
            Role::Responder => Ok(Step::Send(CoordMessage::Connect {
                observed: self.local_observed.clone(),
            })),
            Role::Initiator => {
                let rtt = measured_rtt
                    .ok_or(Error::HolePunchFailed("initiator missing RTT measurement"))?;
                Ok(Step::SyncThenPunch {
                    sync: CoordMessage::Sync,
                    plan: PunchPlan {
                        targets,
                        fire_delay: rtt / 2,
                    },
                })
            }
        }
    }

    /// Feed the peer's `Sync` message (responder path only). Returns [`Step::Punch`]
    /// with a zero fire delay: the responder dials immediately, coinciding with the
    /// initiator's RTT/2-delayed dial.
    pub fn on_peer_sync(&mut self, peer_observed: &EndpointList) -> Result<Step> {
        if !self.connected {
            return Err(Error::HolePunchFailed("Sync before Connect"));
        }
        match self.role {
            Role::Responder => {
                let targets = peer_observed.direct_candidates();
                if targets.is_empty() {
                    return Err(Error::HolePunchFailed("peer advertised no direct endpoint"));
                }
                Ok(Step::Punch {
                    plan: PunchPlan {
                        targets,
                        fire_delay: Duration::ZERO,
                    },
                })
            }
            Role::Initiator => Err(Error::HolePunchFailed("initiator received Sync")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::multiaddr::Multiaddr;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn eps(d: u8) -> EndpointList {
        EndpointList::new(vec![Multiaddr::Ip4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, d),
            4433,
        ))])
        .unwrap()
    }

    #[test]
    fn coord_message_round_trips() {
        let c = CoordMessage::Connect { observed: eps(1) };
        assert_eq!(CoordMessage::from_bytes(&c.to_bytes()).unwrap(), c);
        let s = CoordMessage::Sync;
        assert_eq!(CoordMessage::from_bytes(&s.to_bytes()).unwrap(), s);
    }

    #[test]
    fn coord_message_rejects_unknown_kind_and_arity() {
        let mut e = Encoder::new();
        e.array(1).uint(99);
        assert!(matches!(
            CoordMessage::from_bytes(&e.finish()),
            Err(Error::HolePunchFailed(_))
        ));
        // Connect kind with wrong arity.
        let mut e2 = Encoder::new();
        e2.array(1).uint(KIND_CONNECT);
        assert!(matches!(
            CoordMessage::from_bytes(&e2.finish()),
            Err(Error::HolePunchFailed(_))
        ));
    }

    #[test]
    fn full_handshake_synchronizes_initiator_and_responder() {
        // Initiator opens.
        let mut ini = Coordinator::new(Role::Initiator, eps(1));
        let mut res = Coordinator::new(Role::Responder, eps(2));
        let open = ini.initial_message().unwrap();
        assert!(matches!(open, CoordMessage::Connect { .. }));
        assert!(res.initial_message().is_none());

        // Responder receives Connect → replies Connect.
        let CoordMessage::Connect { observed: ini_obs } = open else {
            unreachable!()
        };
        let reply = res.on_peer_connect(&ini_obs, None).unwrap();
        let Step::Send(CoordMessage::Connect { observed: res_obs }) = reply else {
            panic!("responder must reply Connect");
        };

        // Initiator receives responder's Connect with a measured RTT → Sync + punch.
        let rtt = Duration::from_millis(80);
        let step = ini.on_peer_connect(&res_obs, Some(rtt)).unwrap();
        let Step::SyncThenPunch { sync, plan } = step else {
            panic!("initiator must Sync then punch");
        };
        assert_eq!(sync, CoordMessage::Sync);
        assert_eq!(plan.fire_delay, Duration::from_millis(40), "RTT/2");
        assert_eq!(plan.targets.len(), 1);

        // Responder receives Sync → punch immediately (fire_delay zero) — coincides
        // with the initiator's RTT/2 delay.
        let punch = res.on_peer_sync(&ini_obs).unwrap();
        let Step::Punch { plan: rplan } = punch else {
            panic!("responder must punch on Sync");
        };
        assert_eq!(rplan.fire_delay, Duration::ZERO);
        assert_eq!(rplan.targets.len(), 1);
    }

    #[test]
    fn out_of_sequence_messages_are_rejected() {
        // Sync before Connect.
        let mut res = Coordinator::new(Role::Responder, eps(2));
        assert!(matches!(
            res.on_peer_sync(&eps(1)),
            Err(Error::HolePunchFailed(_))
        ));
        // Duplicate Connect.
        let mut res2 = Coordinator::new(Role::Responder, eps(2));
        res2.on_peer_connect(&eps(1), None).unwrap();
        assert!(matches!(
            res2.on_peer_connect(&eps(1), None),
            Err(Error::HolePunchFailed(_))
        ));
        // Initiator must not receive Sync.
        let mut ini = Coordinator::new(Role::Initiator, eps(1));
        ini.on_peer_connect(&eps(2), Some(Duration::from_millis(10)))
            .unwrap();
        assert!(matches!(
            ini.on_peer_sync(&eps(2)),
            Err(Error::HolePunchFailed(_))
        ));
    }

    #[test]
    fn initiator_without_rtt_is_rejected() {
        let mut ini = Coordinator::new(Role::Initiator, eps(1));
        assert!(matches!(
            ini.on_peer_connect(&eps(2), None),
            Err(Error::HolePunchFailed(_))
        ));
    }
}
