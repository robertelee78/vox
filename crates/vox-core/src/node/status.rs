//! PRD-001 R35 and R38 — **what this node is doing, and whether it is well**: the report
//! behind `vox status`, its JSON form, and the Prometheus text `vox daemon --metrics`
//! serves.
//!
//! Every fact here is **read** from state the node already keeps — the published view,
//! the connection manager, the sync schedules, the app layer and each connection's
//! datagram router — plus three small ledgers this module keeps for the purpose
//! ([`StatusBook`]): when each room last completed a sync, when each peer was last seen
//! connected, and which tunnels are being served right now. Nothing here decides
//! anything, and nothing the node does waits on it.
//!
//! ## What "unhealthy" means
//!
//! A line in [`StatusReport::unhealthy`] is something an operator should look at:
//!
//! - a room with other members that has not completed a sync in [`STALE_SYNC_SECS`];
//! - a **trusted** member of an open room this node was connected to and no longer is;
//! - an **anchor** this node keeps that it has not reached for [`ANCHOR_UNREACHABLE_SECS`], while
//!   this node needs one. An anchor only bridges hosts that cannot otherwise find each other
//!   (ADR-012), so an anchor this node does not need alarms no one: the line is raised only while
//!   an open room has a trusted member this node does not hold a direct connection to (one it
//!   reaches over a relay, or not at all). Every member reached directly, or no member at all,
//!   and a lost anchor costs nothing now. The line says what it costs and what it does not.
//!
//! An untrusted member that is offline is not flagged: nothing this node does depends on
//! reaching it. A trusted one is who this node reads, and is read by.
//!
//! ## What is not knowable yet
//!
//! Whether a room has an **always-on member** is ADR-023's question and nothing records
//! it yet, so the report says so and shows when each member was last seen instead.
//! "Direct" covers both a dialled and a hole-punched path: which rung won is not kept
//! once the connection is filed.
//!
//! ## ADR-025 S0b's sync counters
//!
//! Beside the report, `vox status --json` carries v0.2.10's **simple sync counters** (the
//! decider's decision 3, 2026-09-26): a `"sync"` row per `(room, peer)` — sessions opened,
//! admitted, refused busy, completed, partial, failed, stale, skipped at the cap, queued, and the
//! backoff a port is in — and a `"reach"` row per peer, counting reachability ladders and outbound
//! circuits (V210-53). They are what a person cannot see directly: that nothing was refused,
//! skipped or left stale. They live in a [`SyncBook`] the actor writes and every handle reads.
//!
//! `"tunnels"` lists every live tunnel (V210-81): the member, the service, which way it was
//! opened, and when it was opened and last moved a byte.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::app::AppStats;
use crate::node::ipc::{read_frame, write_frame, Frame};
use crate::node::link::b32_encode;
use crate::transport::router::DatagramStats;

/// A room with other members and no completed sync for this long is flagged.
pub const STALE_SYNC_SECS: u64 = 10 * 60;

/// An anchor this node keeps and has not reached for this long is flagged (PRD-001 R37). Long
/// enough that an anchor restarting, which members are back from within seconds (V210-86), never
/// interrupts anyone.
pub const ANCHOR_UNREACHABLE_SECS: u64 = 60;

/// The ledgers this module keeps beside the node's own state.
#[derive(Debug, Default)]
pub struct StatusBook {
    /// Room → when a sync this node ran there last completed.
    pub room_synced: BTreeMap<Digest32, u64>,
    /// Peer → when a sync session with it last completed, in any room.
    pub member_synced: BTreeMap<Digest32, u64>,
    /// Peer → when this node last saw a live connection to it.
    pub last_seen: BTreeMap<Digest32, u64>,
    /// When the node started, seconds since the epoch: a room that has not synced *yet*
    /// is not stale until it has had [`STALE_SYNC_SECS`] to do so.
    pub started: u64,
}

/// One member of a room, as this node sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberStatus {
    /// Its identity.
    pub id: Digest32,
    /// Whether it is this node.
    pub me: bool,
    /// Whether this node's keyring trusts it.
    pub trusted: bool,
    /// Whether this node has a live connection to it now.
    pub connected: bool,
    /// When this node last saw it connected (now, if it is).
    pub last_seen: Option<u64>,
    /// When a sync session with it last ran.
    pub last_sync: Option<u64>,
}

/// One open room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomStatus {
    /// The room.
    pub id: Digest32,
    /// Its local name.
    pub name: String,
    /// Its epoch.
    pub epoch: u64,
    /// When a sync this node ran there last completed.
    pub last_sync: Option<u64>,
    /// The retention this node applies here, seconds (`0` forever): the shorter of the room's
    /// and the node's own (ADR-023 decision 2).
    ///
    /// This and the three below come from the room as the node last published it, so they are
    /// answered while a sync session holds the room. Read from the room itself they were `null`
    /// for as long as a session ran: a person reading `vox status` saw no retention, "(busy)" for
    /// the keys held and no frozen member, with no reason (#58, #59).
    pub retention: u64,
    /// How many generations of this node's own sender key it still holds here (PRD-001
    /// R14: one, unless a full-history grant is still owed).
    pub key_generations: usize,
    /// How many generations of other members' sender keys it holds here (PRD-001 R14 on the
    /// receiving side: a generation read to the end is deleted).
    pub received_key_generations: usize,
    /// Authors this node froze here for signing two entries at one position (ADR-008).
    pub frozen: Vec<Digest32>,
    /// Entries this node refused here as at or below their author's checkpoint since it opened
    /// the room (ADR-023 decision 3).
    pub refused_below_checkpoint: u64,
    /// Its members.
    pub members: Vec<MemberStatus>,
}

/// One connected peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    /// Its identity.
    pub id: Digest32,
    /// `direct` (dialled or hole-punched) or `relayed`.
    pub path: &'static str,
    /// The relay carrying it, when relayed and known.
    pub relay: Option<Digest32>,
    /// QUIC's smoothed round-trip time, milliseconds.
    pub rtt_ms: u64,
    /// This connection's datagram counters.
    pub datagrams: DatagramStats,
    /// The TLS key-exchange group its handshake negotiated, as rustls observed it (V030-33).
    pub tls_group: u16,
}

/// A local port forwarded to a member's service (the dial side): a door, which carries a tunnel
/// only while something is connected through it. The tunnels themselves are in the one list of
/// live tunnels ([`crate::transport::quic::live_tunnels`], V210-81).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardStatus {
    /// The room.
    pub channel_id: Digest32,
    /// The member hosting it.
    pub host: Digest32,
    /// The service.
    pub service_tag: String,
    /// Where it listens locally.
    pub local: SocketAddr,
}

/// Everything `vox status` shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusReport {
    /// When this was taken, seconds since the epoch.
    pub now: u64,
    /// When the node started, seconds since the epoch.
    pub started: u64,
    /// This node.
    pub identity: Option<Digest32>,
    /// Whether it is on the network.
    pub networked: bool,
    /// When the machine's network last changed, unix seconds, and the change in one line
    /// (ADR-012 N-52); `None` if it has not since the daemon started.
    pub network_changed: Option<(u64, String)>,
    /// Where it listens.
    pub listening: Vec<String>,
    /// Its open rooms.
    pub rooms: Vec<RoomStatus>,
    /// Its live connections.
    pub peers: Vec<PeerStatus>,
    /// How many circuits it carries for others.
    pub relaying: usize,
    /// Ports it forwards to others' services.
    pub forwards: Vec<ForwardStatus>,
    /// Datagram counters, summed over every connection.
    pub datagrams: DatagramStats,
    /// The app layer's counters.
    pub app: AppStats,
    /// Every live UDP flow, hosted or dialled, with its own counters (ADR-022 6.9, V030-34).
    pub udp_flows: Vec<crate::tunnel::udp::FlowInfo>,
    /// The anchors this node keeps, and whether it reaches them.
    pub anchors: Vec<AnchorStatus>,
    /// What needs looking at.
    pub unhealthy: Vec<Unhealthy>,
    /// How long this node gives a tunnel whose bytes wait before closing it as stuck (V030-11):
    /// its own setting, not the process's (ADR-026 P-1). Said in the JSON's
    /// `tunnel_stuck_after`, by [`SyncBook::sections_json`].
    pub tunnel_stuck_after: std::time::Duration,
}

/// One anchor this node keeps: configured, or named by an open room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorStatus {
    /// Its identity.
    pub id: Digest32,
    /// Since when this node has not reached it (unix seconds); `None` while it is reached.
    pub unreached_since: Option<u64>,
}

/// One condition that needs looking at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unhealthy {
    /// A stable name for the condition — `peer-unreachable:<room>:<peer>`, `room-stale:<room>`
    /// or `anchor-unreachable:<anchor>` — the same for as long as the condition holds, so a notifier
    /// can tell it starting from it continuing (PRD-001 R37).
    pub key: String,
    /// What a person reads. May change while the condition holds ("last seen 12s ago").
    pub message: String,
}

fn short(d: &Digest32) -> String {
    b32_encode(d).chars().take(12).collect()
}

impl StatusReport {
    /// Work out the unhealthy lines from the rest of the report.
    pub fn diagnose(&mut self) {
        let mut out = Vec::new();
        for room in &self.rooms {
            let others = room.members.iter().filter(|m| !m.me).count();
            if others == 0 || !self.networked {
                continue;
            }
            // Measured from the last completed sync, or from the node's start when there
            // has been none: a daemon that has just started is not unhealthy for not
            // having synced in its first seconds, and would otherwise alarm on every start.
            let since = room.last_sync.unwrap_or(self.started);
            let stale = self.now.saturating_sub(since) > STALE_SYNC_SECS;
            if stale {
                out.push(Unhealthy {
                    key: format!("room-stale:{}", b32_encode(&room.id)),
                    message: format!(
                        "room {} ({}): no completed sync in {} minutes",
                        short(&room.id),
                        room.name,
                        STALE_SYNC_SECS / 60
                    ),
                });
            }
            for m in &room.members {
                if m.me || !m.trusted || m.connected {
                    continue;
                }
                if let Some(seen) = m.last_seen {
                    out.push(Unhealthy {
                        key: format!(
                            "peer-unreachable:{}:{}",
                            b32_encode(&room.id),
                            b32_encode(&m.id)
                        ),
                        message: format!(
                            "room {} ({}): trusted member {} unreachable, last seen {}s ago",
                            short(&room.id),
                            room.name,
                            short(&m.id),
                            self.now.saturating_sub(seen)
                        ),
                    });
                }
            }
        }
        // Whether this node needs an anchor now (ADR-012: an anchor only bridges): some open room
        // has a trusted member it holds no direct connection to.
        let direct = |id: &Digest32| self.peers.iter().any(|p| p.id == *id && p.path == "direct");
        let needs_a_bridge = self.rooms.iter().any(|room| {
            room.members
                .iter()
                .any(|m| !m.me && m.trusted && !direct(&m.id))
        });
        if self.networked && needs_a_bridge {
            for a in &self.anchors {
                let Some(since) = a.unreached_since else {
                    continue;
                };
                let for_secs = self.now.saturating_sub(since);
                if for_secs > ANCHOR_UNREACHABLE_SECS {
                    out.push(Unhealthy {
                        key: format!("anchor-unreachable:{}", b32_encode(&a.id)),
                        message: format!(
                            "anchor {} unreachable for {for_secs}s: a host that can find this \
                             node only through it cannot reach it until it is back; peers this \
                             node reaches directly are unaffected",
                            short(&a.id)
                        ),
                    });
                }
            }
        }
        self.unhealthy = out;
    }

    /// The report as JSON (what `vox status --json` prints). Hand-written, because the
    /// shape is small and fixed and the crate carries no serializer.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut j = String::from("{");
        let _ = write!(j, "\"now\":{},", self.now);
        let _ = write!(
            j,
            "\"identity\":{},",
            self.identity.map_or("null".into(), |d| q(&b32_encode(&d)))
        );
        let _ = write!(j, "\"networked\":{},", self.networked);
        let _ = write!(
            j,
            "\"network_changed\":{},",
            self.network_changed.as_ref().map_or_else(
                || "null".to_owned(),
                |(at, said)| format!("{{\"at\":{at},\"change\":{}}}", q(said))
            )
        );
        let _ = write!(
            j,
            "\"listening\":[{}],",
            list(self.listening.iter().map(|s| q(s)))
        );
        let _ = write!(
            j,
            "\"always_on_member\":{},",
            q("unknown: not recorded until ADR-023; see each member's last_seen")
        );
        let rooms = self.rooms.iter().map(|r| {
            let members = r.members.iter().map(|m| {
                format!(
                    "{{\"id\":{},\"me\":{},\"trusted\":{},\"connected\":{},\"last_seen\":{},\"last_sync\":{}}}",
                    q(&b32_encode(&m.id)),
                    m.me,
                    m.trusted,
                    m.connected,
                    opt(m.last_seen),
                    opt(m.last_sync)
                )
            });
            let frozen = list(r.frozen.iter().map(|d| q(&b32_encode(d))));
            format!(
                "{{\"id\":{},\"name\":{},\"epoch\":{},\"last_sync\":{},\"retention\":{},\"key_generations\":{},\"received_key_generations\":{},\"frozen\":[{}],\"refused_below_checkpoint\":{},\"members\":[{}]}}",
                q(&b32_encode(&r.id)),
                q(&r.name),
                r.epoch,
                opt(r.last_sync),
                r.retention,
                r.key_generations,
                r.received_key_generations,
                frozen,
                r.refused_below_checkpoint,
                list(members)
            )
        });
        let _ = write!(j, "\"rooms\":[{}],", list(rooms));
        let peers = self.peers.iter().map(|p| {
            format!(
                "{{\"id\":{},\"path\":{},\"relay\":{},\"rtt_ms\":{},\"tls_group\":{},\"datagrams\":{}}}",
                q(&b32_encode(&p.id)),
                q(p.path),
                p.relay.map_or("null".into(), |d| q(&b32_encode(&d))),
                p.rtt_ms,
                q(&format!("{:?}", rustls::NamedGroup::from(p.tls_group))),
                dgram_json(&p.datagrams)
            )
        });
        let _ = write!(j, "\"peers\":[{}],", list(peers));
        let _ = write!(j, "\"relaying\":{},", self.relaying);
        let forwards = self.forwards.iter().map(|t| {
            format!(
                "{{\"host\":{},\"room\":{},\"service\":{},\"local\":{}}}",
                q(&b32_encode(&t.host)),
                q(&b32_encode(&t.channel_id)),
                q(&t.service_tag),
                q(&t.local.to_string())
            )
        });
        let _ = write!(j, "\"forwards\":[{}],", list(forwards));
        let _ = write!(j, "\"datagrams\":{},", dgram_json(&self.datagrams));
        let a = &self.app;
        let _ = write!(
            j,
            "\"app\":{{\"inbound\":{},\"accepted\":{},\"opened\":{},\"refused_untrusted\":{},\"refused_busy\":{},\"refused_no_listener\":{},\"refused_unaccepted\":{},\"refused_locally\":{},\"withdrawn\":{}}},",
            a.inbound,
            a.accepted,
            a.opened,
            a.refused_untrusted,
            a.refused_busy,
            a.refused_no_listener,
            a.refused_unaccepted,
            a.refused_locally,
            a.withdrawn
        );
        // **Each UDP flow apart** (ADR-022 6.9, V030-34): the summed datagram counters above
        // cannot say which flow lost what, and a flow's own counts are what a person checks
        // against the packets their program sent.
        let flows = self.udp_flows.iter().map(|f| {
            format!(
                "{{\"peer\":{},\"service\":{},\"to\":{},\"from\":{},\"dropped\":{},\"idle_ms\":{}}}",
                q(&b32_encode(&f.peer)),
                q(&f.label),
                f.to_peer,
                f.from_peer,
                f.dropped,
                u64::try_from(f.idle.as_millis()).unwrap_or(u64::MAX)
            )
        });
        let _ = write!(j, "\"udp_flows\":[{}],", list(flows));
        let _ = write!(
            j,
            "\"anchors\":[{}],",
            list(self.anchors.iter().map(|a| format!(
                "{{\"id\":{},\"reached\":{},\"unreached_since\":{}}}",
                q(&b32_encode(&a.id)),
                a.unreached_since.is_none(),
                opt(a.unreached_since)
            )))
        );
        let _ = write!(
            j,
            "\"unhealthy\":[{}]",
            list(self.unhealthy.iter().map(|u| format!(
                "{{\"key\":{},\"message\":{}}}",
                q(&u.key),
                q(&u.message)
            )))
        );
        j.push('}');
        j
    }

    /// The report as Prometheus text exposition for the node named `node`, alone (see
    /// [`StatusReport::to_prometheus_rows`]).
    #[must_use]
    pub fn to_prometheus(&self, node: &str) -> String {
        let mut out = Families::default();
        self.to_prometheus_rows(node, &mut out);
        out.render()
    }

    /// Add this report's samples, each labelled `node="<node>"` (ADR-026 P-1), to `out`, which
    /// may already hold other nodes' samples of the same families: a scrape of a daemon is one
    /// exposition with each family's `HELP` and `TYPE` once, and every node's samples under it.
    pub fn to_prometheus_rows(&self, node: &str, out: &mut Families) {
        let me = node_label(node);
        let mut gauge = |name: &'static str, help: &'static str, rows: Vec<(String, u64)>| {
            out.family(name, help, Kind::Gauge);
            for (labels, v) in rows {
                out.sample(name, &me, &labels, v);
            }
        };
        gauge(
            "vox_up",
            "1 while the node answers.",
            vec![(String::new(), 1)],
        );
        gauge(
            "vox_networked",
            "1 when the node is on the network.",
            vec![(String::new(), u64::from(self.networked))],
        );
        gauge(
            "vox_peers_connected",
            "Live connections.",
            vec![(String::new(), self.peers.len() as u64)],
        );
        gauge(
            "vox_peer_relayed",
            "1 when the path to this peer runs through a relay, 0 when direct.",
            self.peers
                .iter()
                .map(|p| {
                    (
                        format!(
                            "{{peer=\"{}\",relay=\"{}\"}}",
                            b32_encode(&p.id),
                            p.relay.map(|r| b32_encode(&r)).unwrap_or_default()
                        ),
                        u64::from(p.path == "relayed"),
                    )
                })
                .collect(),
        );
        gauge(
            "vox_peer_rtt_milliseconds",
            "QUIC smoothed round-trip time per peer.",
            self.peers
                .iter()
                .map(|p| (format!("{{peer=\"{}\"}}", b32_encode(&p.id)), p.rtt_ms))
                .collect(),
        );
        gauge(
            "vox_room_members",
            "Members per open room.",
            self.rooms
                .iter()
                .map(|r| {
                    (
                        format!("{{room=\"{}\"}}", b32_encode(&r.id)),
                        r.members.len() as u64,
                    )
                })
                .collect(),
        );
        gauge(
            "vox_room_last_sync_seconds",
            "When a sync this node ran in the room last completed (0: never).",
            self.rooms
                .iter()
                .map(|r| {
                    (
                        format!("{{room=\"{}\"}}", b32_encode(&r.id)),
                        r.last_sync.unwrap_or(0),
                    )
                })
                .collect(),
        );
        gauge(
            "vox_relaying_circuits",
            "Circuits carried for other peers.",
            vec![(String::new(), self.relaying as u64)],
        );
        // Only this node's: a process may host several (ADR-026 P-1).
        let live = self
            .identity
            .map(|me| crate::transport::quic::live_tunnels(&me))
            .unwrap_or_default();
        gauge(
            "vox_tunnels_served",
            "Tunnels being served now.",
            vec![(
                String::new(),
                live.iter().filter(|t| !t.outbound).count() as u64,
            )],
        );
        gauge(
            "vox_tunnels_dialed",
            "Tunnels this node opened to members' services, now.",
            vec![(
                String::new(),
                live.iter().filter(|t| t.outbound).count() as u64,
            )],
        );
        gauge(
            "vox_forwards",
            "Local forwards to members' services.",
            vec![(String::new(), self.forwards.len() as u64)],
        );
        gauge(
            "vox_udp_flows",
            "Live UDP flows, hosted or dialled.",
            vec![(String::new(), self.udp_flows.len() as u64)],
        );
        // Per flow (ADR-022 6.9, V030-34). Counters of a live flow: a flow that ends leaves the
        // listing, as a tunnel does.
        let flow_labels = |f: &crate::tunnel::udp::FlowInfo| {
            format!(
                "{{peer=\"{}\",service=\"{}\"}}",
                b32_encode(&f.peer),
                f.label
            )
        };
        for (name, help, read) in [
            (
                "vox_udp_flow_to_peer",
                "Packets this UDP flow put on its tunnel toward the peer.",
                (|f: &crate::tunnel::udp::FlowInfo| f.to_peer) as fn(&_) -> u64,
            ),
            (
                "vox_udp_flow_from_peer",
                "Packets this UDP flow delivered from the peer to the local UDP side.",
                |f| f.from_peer,
            ),
            (
                "vox_udp_flow_dropped",
                "Packets this UDP flow dropped because the local socket or its queue was full.",
                |f| f.dropped,
            ),
        ] {
            gauge(
                name,
                help,
                self.udp_flows
                    .iter()
                    .map(|f| (flow_labels(f), read(f)))
                    .collect(),
            );
        }
        gauge(
            "vox_unhealthy",
            "Lines `vox status` flags as needing attention.",
            vec![(String::new(), self.unhealthy.len() as u64)],
        );
        let d = &self.datagrams;
        let mut counter = |name: &'static str, help: &'static str, v: u64| {
            out.family(name, help, Kind::Counter);
            out.sample(name, &me, "", v);
        };
        counter(
            "vox_datagrams_sent_total",
            "Datagrams handed to QUIC.",
            d.sent,
        );
        counter(
            "vox_datagrams_delivered_total",
            "Datagrams delivered to a flow.",
            d.delivered,
        );
        counter(
            "vox_datagrams_fragmented_total",
            "Packets sent as fragments.",
            d.fragmented,
        );
        counter(
            "vox_datagrams_dropped_total",
            "Datagrams dropped: unknown flow, full inbox, malformed, reassembly, or unsendable.",
            d.unknown_flow
                + d.inbox_full
                + d.malformed
                + d.unknown_context
                + d.reassembly_expired
                + d.reassembly_evicted
                + d.reassembly_rejected
                + d.send_dropped,
        );
        let a = &self.app;
        counter(
            "vox_app_streams_inbound_total",
            "App streams that arrived.",
            a.inbound,
        );
        counter(
            "vox_app_streams_accepted_total",
            "App streams accepted.",
            a.accepted,
        );
        counter(
            "vox_app_streams_opened_total",
            "App streams opened.",
            a.opened,
        );
        counter(
            "vox_app_streams_refused_total",
            "App streams refused, for any reason.",
            a.refused_untrusted
                + a.refused_busy
                + a.refused_no_listener
                + a.refused_unaccepted
                + a.refused_locally,
        );
    }
}

/// A metric family's type, as its `# TYPE` line says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A value that goes up and down.
    Gauge,
    /// A value that only goes up.
    Counter,
}

/// A Prometheus exposition being built from several nodes' reports and the daemon's own gauges:
/// each family's `HELP` and `TYPE` lines once, then every sample of it, in the order the
/// families were first named. Two `TYPE` lines for one family make a scraper refuse the whole
/// exposition, which is why a daemon's nodes cannot each render their own text and be joined.
#[derive(Debug, Default)]
pub struct Families {
    order: Vec<&'static str>,
    families: BTreeMap<&'static str, Family>,
}

#[derive(Debug)]
struct Family {
    help: &'static str,
    kind: Kind,
    samples: Vec<String>,
}

impl Families {
    /// Name the family `name`, so its `HELP` and `TYPE` are written even when no sample follows.
    /// A family named again keeps what it was first named with.
    pub fn family(&mut self, name: &'static str, help: &'static str, kind: Kind) {
        if !self.families.contains_key(name) {
            self.order.push(name);
            self.families.insert(
                name,
                Family {
                    help,
                    kind,
                    samples: Vec::new(),
                },
            );
        }
    }

    /// One sample of the family `name` (named first with [`Families::family`]): `node` is the
    /// node's own label (`node="…"`, or empty for a daemon-wide value) and comes first; `labels`
    /// is the rest, either `{a="…",b="…"}` or empty.
    pub fn sample(&mut self, name: &'static str, node: &str, labels: &str, value: u64) {
        let rest = labels
            .strip_prefix('{')
            .and_then(|l| l.strip_suffix('}'))
            .unwrap_or(labels);
        let set = match (node.is_empty(), rest.is_empty()) {
            (true, true) => String::new(),
            (false, true) => format!("{{{node}}}"),
            (true, false) => format!("{{{rest}}}"),
            (false, false) => format!("{{{node},{rest}}}"),
        };
        if let Some(f) = self.families.get_mut(name) {
            f.samples.push(format!("{name}{set} {value}"));
        }
    }

    /// The exposition text.
    #[must_use]
    pub fn render(&self) -> String {
        let mut m = String::new();
        for name in &self.order {
            let Some(f) = self.families.get(name) else {
                continue;
            };
            let kind = match f.kind {
                Kind::Gauge => "gauge",
                Kind::Counter => "counter",
            };
            let _ = writeln!(m, "# HELP {name} {}", f.help);
            let _ = writeln!(m, "# TYPE {name} {kind}");
            for line in &f.samples {
                let _ = writeln!(m, "{line}");
            }
        }
        m
    }
}

/// `node="<name>"`, with the value escaped as the exposition format asks (backslash, quote and
/// newline), since a profile's name is the person's.
fn node_label(node: &str) -> String {
    let mut v = String::with_capacity(node.len());
    for c in node.chars() {
        match c {
            '\\' => v.push_str("\\\\"),
            '"' => v.push_str("\\\""),
            '\n' => v.push_str("\\n"),
            c => v.push(c),
        }
    }
    format!("node=\"{v}\"")
}

/// What a daemon counts of itself, beside its nodes' reports (ADR-026 P-1): how many nodes are
/// attached, and how many of their actors have panicked since it started (L-6).
#[derive(Debug, Default)]
pub struct DaemonMetrics {
    /// Nodes attached now.
    pub nodes_attached: std::sync::atomic::AtomicU64,
    /// Node actors that panicked since the daemon started.
    pub node_panics: std::sync::atomic::AtomicU64,
}

impl DaemonMetrics {
    /// Add the daemon's own families to `out`, unlabelled.
    pub fn to_prometheus_rows(&self, out: &mut Families) {
        use std::sync::atomic::Ordering::Relaxed;
        out.family(
            "vox_daemon_nodes_attached",
            "Nodes attached to this daemon.",
            Kind::Gauge,
        );
        out.sample(
            "vox_daemon_nodes_attached",
            "",
            "",
            self.nodes_attached.load(Relaxed),
        );
        out.family(
            "vox_daemon_node_panics_total",
            "Node actors that panicked since the daemon started; each one detached its node.",
            Kind::Counter,
        );
        out.sample(
            "vox_daemon_node_panics_total",
            "",
            "",
            self.node_panics.load(Relaxed),
        );
    }
}

fn q(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn opt(v: Option<u64>) -> String {
    v.map_or("null".into(), |v| v.to_string())
}

fn list(items: impl Iterator<Item = String>) -> String {
    items.collect::<Vec<_>>().join(",")
}

fn dgram_json(d: &DatagramStats) -> String {
    format!(
        "{{\"sent\":{},\"delivered\":{},\"fragmented\":{},\"unknown_flow\":{},\"inbox_full\":{},\"malformed\":{},\"send_dropped\":{}}}",
        d.sent,
        d.delivered,
        d.fragmented,
        d.unknown_flow,
        d.inbox_full,
        d.malformed + d.unknown_context,
        d.send_dropped
    )
}

/// Add `b` into `a`, field by field.
pub fn add_stats(a: &mut DatagramStats, b: &DatagramStats) {
    a.delivered += b.delivered;
    a.unknown_flow += b.unknown_flow;
    a.inbox_full += b.inbox_full;
    a.malformed += b.malformed;
    a.unknown_context += b.unknown_context;
    a.reassembly_expired += b.reassembly_expired;
    a.reassembly_evicted += b.reassembly_evicted;
    a.reassembly_rejected += b.reassembly_rejected;
    a.sent += b.sent;
    a.fragmented += b.fragmented;
    a.send_dropped += b.send_dropped;
}

// ---- ADR-025 S0b: sync and reach counters ----------------------------------

/// The kinds of backoff a port can be in (ADR-025 D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffKind {
    /// A transport or stream-open failure.
    Unreachable,
    /// The peer refused with `SessionBusy` (only past its inbound limit), or has not yet admitted
    /// this just-joined member.
    Busy,
    /// A session that left requested positions unfilled and made no progress, or a protocol
    /// violation.
    NoProgress,
    /// The peer refuses by policy: another epoch, not a member, the room not held.
    Policy,
}

impl BackoffKind {
    /// The name `vox status --json` prints.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Busy => "busy",
            Self::NoProgress => "no_progress",
            Self::Policy => "policy",
        }
    }
}

/// One `(room, peer)`'s counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortCounters {
    /// Outbound sessions this node opened.
    pub opened: u64,
    /// Inbound sessions this node admitted.
    pub admitted: u64,
    /// Inbound sessions this node refused with `SessionBusy`.
    pub busy_refused: u64,
    /// Sessions (either direction) that completed with every requested entry received.
    pub completed: u64,
    /// Sessions that ended without error but left requested entries unreceived (a bounded serve).
    pub partial: u64,
    /// Sessions that failed.
    pub failed: u64,
    /// The last failure's reason.
    pub last_failure: Option<String>,
    /// Results that arrived for an attempt already retired (ADR-025 D1a).
    pub stale: u64,
    /// Entries this peer served that were refused rather than held (V210-74): without their
    /// payload, past a position not held, or signed but unclassifiable.
    pub refused: u64,
    /// Sessions that were due but skipped because every outbound slot was taken.
    pub skipped_at_cap: u64,
    /// Times a port waited in the outbound queue for a slot (ADR-025 D6).
    pub queued: u64,
    /// The backoff the port is in now, and its consecutive failures.
    pub backoff: Option<(BackoffKind, u32)>,
    /// The sessions running on the port now, by token: which end opened each, the step it is at,
    /// since when, and when it started (V210-110). A session that never ends was otherwise only a counter that did
    /// not move; with this, `vox status` says which session is stuck, and at which step.
    pub running: BTreeMap<u64, (bool, SyncStep, std::time::Instant, std::time::Instant)>,
}

/// The step a sync session is at (V210-110).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStep {
    /// Reading the peer's board for who has joined, and offering it what this node's holds (an
    /// outbound session's first step).
    Setup,
    /// Opening the sync stream (outbound).
    Opening,
    /// Exchanging entries (either direction).
    Exchanging,
}

impl SyncStep {
    /// The name `vox status --json` prints.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Opening => "opening",
            Self::Exchanging => "exchanging",
        }
    }
}

/// One running session's place in the book: it moves the session's step, and its drop removes
/// the session, however the session ends (it is held by the port's attempt, V210-110).
pub struct Running {
    book: SharedSyncBook,
    room: Digest32,
    peer: Digest32,
    token: u64,
}

impl Running {
    /// List a session as running on `(room, peer)` from now, at `step`.
    #[must_use]
    pub fn start(
        book: &SharedSyncBook,
        room: Digest32,
        peer: Digest32,
        token: u64,
        outbound: bool,
        step: SyncStep,
    ) -> Self {
        SyncBook::with(book, room, peer, |c| {
            let now = std::time::Instant::now();
            c.running.insert(token, (outbound, step, now, now));
        });
        Self {
            book: Arc::clone(book),
            room,
            peer,
            token,
        }
    }

    /// A handle that moves this session's step and never removes it, for the session's task.
    #[must_use]
    pub fn stepper(&self) -> Stepper {
        Stepper {
            book: Arc::clone(&self.book),
            room: self.room,
            peer: self.peer,
            token: self.token,
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let token = self.token;
        SyncBook::with(&self.book, self.room, self.peer, |c| {
            c.running.remove(&token);
        });
    }
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

/// Moves a running session's step (see [`Running::stepper`]). A session already gone stays gone.
pub struct Stepper {
    book: SharedSyncBook,
    room: Digest32,
    peer: Digest32,
    token: u64,
}

impl Stepper {
    /// The session is at `step` from now.
    pub fn step(&self, step: SyncStep) {
        let token = self.token;
        SyncBook::with(&self.book, self.room, self.peer, |c| {
            if let Some(r) = c.running.get_mut(&token) {
                *r = (r.0, step, std::time::Instant::now(), r.3);
            }
        });
    }
}

/// Why a publish round started (V210-68): one round per `(room, board)`, counted by what asked
/// for it, so a count of rounds can be accounted for in full.
///
/// A publish asked for while a round to the same board is in flight runs once that round ends,
/// and is counted under **what asked for it**, not as a cause of its own: "it was asked for during
/// another round" says when it ran, not why, and a round counted that way could not be accounted
/// for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublishCause {
    /// The scheduled renewal of the room's own records.
    Renewal,
    /// An anchor connected (or came back): it holds none of this node's records yet.
    AnchorReturned,
    /// A board passed on news of a record, which this node's anchors are given too.
    BoardNews,
    /// This node learned its public addresses, which its records must name.
    Addresses,
    /// A board refused one of this node's **own** records as stale, so the node republishes its
    /// records to that board (`NetEvent::RepublishTo`).
    AskedAgain,
    /// A round that failed, retried.
    Retry,
    /// A sync that brought governance, which changes the records.
    Governance,
    /// A join, on either side.
    Join,
    /// The room was created, opened, reopened or served.
    Opened,
}

impl PublishCause {
    /// Every cause, in the order `vox status --json` lists them.
    pub const ALL: [PublishCause; 9] = [
        Self::Renewal,
        Self::AnchorReturned,
        Self::BoardNews,
        Self::Addresses,
        Self::AskedAgain,
        Self::Retry,
        Self::Governance,
        Self::Join,
        Self::Opened,
    ];

    /// The name `vox status --json` uses.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Renewal => "renewal",
            Self::AnchorReturned => "anchor_returned",
            Self::BoardNews => "board_news",
            Self::Addresses => "addresses",
            Self::AskedAgain => "asked_again",
            Self::Retry => "retry",
            Self::Governance => "governance",
            Self::Join => "join",
            Self::Opened => "opened",
        }
    }
}

/// Every `(room, peer)`'s counters.
#[derive(Debug, Default)]
pub struct SyncBook {
    ports: BTreeMap<(Digest32, Digest32), PortCounters>,
    /// How many reachability ladders this node has run to each peer (`NodeNet::reach`): one per
    /// dial that found no connection to reuse and no other reach to the same peer under way to
    /// wait on (V210-53, #232). What no person can see directly — two dials where one would do.
    ladders: BTreeMap<Digest32, u64>,
    /// Publish rounds this node started (one per `(room, board)` round that went out): what no
    /// person can see directly, and what a storm of rounds looks like (#179).
    publish_rounds: u64,
    /// The same rounds by what asked for each (V210-68).
    publish_by_cause: BTreeMap<PublishCause, u64>,
    /// Asks for a publish folded into one already waiting on a round in flight, by what asked:
    /// they went out in that round and are counted under its cause, so without these a round
    /// could be accounted for and an ask could not.
    publish_merged: BTreeMap<PublishCause, u64>,
    /// Scheduled renewals of a room's own records (V210-68): one per room per half of the
    /// records' lifetime, whatever the traffic and however many boards the round then reaches.
    renewals: u64,
    /// Records by others that taught this node's board something and were passed on
    /// (`NetEvent::BoardGrew`, #179): a member's routine refresh is not one.
    board_news: u64,
    /// The prekey ring as the running node last maintained it (V210-77), or `None` while it
    /// holds no ring.
    prekeys: Option<PrekeyCounts>,
    /// Each open room's stored entries set aside when it opened (V210-74), as `author#seq: why`.
    set_aside: BTreeMap<Digest32, Vec<String>>,
    /// The node's connections, read when a status is asked for, so each peer's row can say which
    /// connection this node holds for it (V29-15, #50): two ends that name different ones are
    /// using connections the other has retired. Weak: the book outlives no network.
    connections: Option<std::sync::Weak<crate::node::net::ConnectionManager>>,
}

/// What the prekey ring holds, and what keeping it up has done since the node started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrekeyCounts {
    /// One-time prekeys left to offer.
    pub one_time: usize,
    /// Consumed one-time prekeys still retained for a concurrent duplicate use.
    pub consumed: usize,
    /// The id of the signed prekey offered now.
    pub signed_prekey: u64,
    /// Signed-prekey rotations the running node made.
    pub rotated: u64,
    /// One-time prekeys the running node added.
    pub refilled: u64,
    /// Sessions the running node set up with its previous signed prekey: started just before a
    /// rotation, completed after it.
    pub previous_used: u64,
}

/// The book as the actor and the handles share it.
pub type SharedSyncBook = Arc<Mutex<SyncBook>>;

impl SyncBook {
    /// Read, at each status request, which connection `manager` holds for each peer.
    pub fn read_connections_from(
        &mut self,
        manager: &std::sync::Arc<crate::node::net::ConnectionManager>,
    ) {
        self.connections = Some(std::sync::Arc::downgrade(manager));
    }

    /// A new shared, empty book.
    #[must_use]
    pub fn shared() -> SharedSyncBook {
        Arc::new(Mutex::new(Self::default()))
    }

    /// Update one port's counters.
    pub fn with(
        book: &SharedSyncBook,
        room: Digest32,
        peer: Digest32,
        f: impl FnOnce(&mut PortCounters),
    ) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        f(b.ports.entry((room, peer)).or_default());
    }

    /// Forget every count kept for `room`: this node left it (V210-164).
    pub fn forget_room(book: &SharedSyncBook, room: &Digest32) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        b.ports.retain(|(r, _), _| r != room);
        b.set_aside.remove(room);
    }

    /// Count one scheduled renewal of a room's own records (V210-68).
    pub fn note_renewal(book: &SharedSyncBook) {
        book.lock().unwrap_or_else(PoisonError::into_inner).renewals += 1;
    }

    /// Count one publish round started, and what asked for it.
    pub fn note_publish_round(book: &SharedSyncBook, cause: PublishCause) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        b.publish_rounds += 1;
        *b.publish_by_cause.entry(cause).or_default() += 1;
    }

    /// Count one ask for a publish folded into a round already waiting to run (see
    /// `publish_merged`).
    pub fn note_publish_merged(book: &SharedSyncBook, cause: PublishCause) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        *b.publish_merged.entry(cause).or_default() += 1;
    }

    /// What `room` set aside when it opened (V210-74); nothing, and the room is not listed.
    pub fn note_set_aside(book: &SharedSyncBook, room: Digest32, entries: &[String]) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.is_empty() {
            b.set_aside.remove(&room);
        } else {
            b.set_aside.insert(room, entries.to_vec());
        }
    }

    /// Count one record of news on this node's board, passed on.
    pub fn note_board_news(book: &SharedSyncBook) {
        book.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .board_news += 1;
    }

    /// Record the ring as it stands after a maintenance that `rotated` and added `added`, and
    /// how many sessions it has set up with its previous signed prekey.
    pub fn note_prekeys(
        book: &SharedSyncBook,
        one_time: usize,
        consumed: usize,
        signed_prekey: u64,
        rotated: bool,
        added: usize,
        previous_used: u64,
    ) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        let c = b.prekeys.get_or_insert_with(PrekeyCounts::default);
        c.one_time = one_time;
        c.consumed = consumed;
        c.signed_prekey = signed_prekey;
        c.rotated += u64::from(rotated);
        c.refilled += u64::try_from(added).unwrap_or(u64::MAX);
        c.previous_used = previous_used;
    }

    /// Count one reachability ladder run to `peer`.
    pub fn note_ladder(book: &SharedSyncBook, peer: Digest32) {
        let mut b = book.lock().unwrap_or_else(PoisonError::into_inner);
        *b.ladders.entry(peer).or_default() += 1;
    }

    /// The counters as `vox status --json` carries them: its `"sync"`, `"reach"`,
    /// `"equivocations"`, `"publish"`, `"prekeys"` and `"set_aside"` members, without the enclosing braces, for [`serve`] to add beside
    /// [`StatusReport::to_json`]'s. `equivocations` is each `(room, author, position)` the node
    /// holds back (V210-63). `me` is the node whose tunnels and counts are said, and
    /// `stuck_after` that node's stuck-tunnel setting (ADR-026 P-1).
    #[must_use]
    pub fn sections_json(
        book: &SharedSyncBook,
        equivocations: &[(Digest32, Digest32, u64)],
        me: &Digest32,
        stuck_after: std::time::Duration,
    ) -> String {
        // Read before the book is held: the manager takes a lock of its own.
        let manager = book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .connections
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        let held: BTreeMap<Digest32, (String, crate::node::net::PathClass)> = manager
            .as_ref()
            .map(|m| {
                m.held_connections()
                    .into_iter()
                    .map(|(peer, tag, path)| (peer, (tag, path)))
                    .collect()
            })
            .unwrap_or_default();
        let mut retired: BTreeMap<Digest32, Vec<String>> = BTreeMap::new();
        for (peer, tag) in manager.map(|m| m.retired_connections()).unwrap_or_default() {
            retired.entry(peer).or_default().push(q(&tag));
        }
        let b = book.lock().unwrap_or_else(PoisonError::into_inner);
        let mut s = String::from("\"sync\":[");
        for (i, ((room, peer), c)) in b.ports.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"room\":\"{}\",\"peer\":\"{}\",\"opened\":{},\"admitted\":{},\"busy_refused\":{},\
                 \"completed\":{},\"partial\":{},\"failed\":{},\"last_failure\":{},\"stale\":{},\
                 \"refused\":{},\"skipped_at_cap\":{},\"queued\":{},\"backoff\":{},\
                 \"running\":[{}]}}",
                b32_encode(room),
                b32_encode(peer),
                c.opened,
                c.admitted,
                c.busy_refused,
                c.completed,
                c.partial,
                c.failed,
                c.last_failure
                    .as_deref()
                    .map_or_else(|| "null".to_owned(), q),
                c.stale,
                c.refused,
                c.skipped_at_cap,
                c.queued,
                c.backoff.map_or_else(
                    || "null".to_owned(),
                    |(k, n)| format!("{{\"kind\":\"{}\",\"failures\":{n}}}", k.name())
                ),
                c.running
                    .values()
                    .map(|(outbound, step, since, started)| format!(
                        "{{\"dir\":\"{}\",\"step\":\"{}\",\"for_ms\":{},\"age_ms\":{}}}",
                        if *outbound { "out" } else { "in" },
                        step.name(),
                        since.elapsed().as_millis(),
                        started.elapsed().as_millis()
                    ))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        s.push_str("],\"reach\":[");
        // Ladders from this book; circuits counted where every outbound circuit is asked for
        // (`circuitstream::connect_through`). Every peer either names, in one row.
        // Dial-backs (V030-22) counted where each is asked for, in the ladder.
        let circuits = crate::node::circuitstream::outbound_circuits(me);
        let dial_backs = crate::node::coordstream::dial_backs(me);
        let peers: std::collections::BTreeSet<&Digest32> = b
            .ladders
            .keys()
            .chain(circuits.keys())
            .chain(dial_backs.keys())
            .chain(held.keys())
            .chain(retired.keys())
            .collect();
        for (i, peer) in peers.into_iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let (asked, answered) = dial_backs.get(peer).copied().unwrap_or((0, 0));
            // The connection held for the peer, by the tag both ends' notes use, and its path.
            let (connection, path) = held.get(peer).map_or_else(
                || ("null".to_owned(), "null".to_owned()),
                |(tag, path)| {
                    let path = match path {
                        crate::node::net::PathClass::Direct => "direct",
                        crate::node::net::PathClass::Relayed => "relayed",
                        crate::node::net::PathClass::Severed => "severed",
                    };
                    (q(tag), q(path))
                },
            );
            // And the ones displaced but still open, read until their grace ends (#335).
            let retired = retired.get(peer).map(|t| t.join(",")).unwrap_or_default();
            let _ = write!(
                s,
                "{{\"peer\":\"{}\",\"ladders\":{},\"circuits\":{},\"dial_backs\":{asked},\
                 \"dial_backs_answered\":{answered},\"connection\":{connection},\"path\":{path},\
                 \"retired\":[{retired}]}}",
                b32_encode(peer),
                b.ladders.get(peer).copied().unwrap_or(0),
                circuits.get(peer).copied().unwrap_or(0)
            );
        }
        // **Who this node holds back for equivocating, and where** (V210-63): each an author seen
        // signing two different messages at one position in a room. For agents, as full ids; a
        // person reads it in `vox room read`.
        s.push_str("],\"equivocations\":[");
        for (i, (room, author, position)) in equivocations.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"room\":\"{}\",\"author\":\"{}\",\"position\":{position}}}",
                b32_encode(room),
                b32_encode(author),
            );
        }
        let _ = write!(
            s,
            "],\"publish\":{{\"rounds\":{},\"by_cause\":{{",
            b.publish_rounds
        );
        for (i, cause) in PublishCause::ALL.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let n = b.publish_by_cause.get(cause).copied().unwrap_or(0);
            let _ = write!(s, "\"{}\":{n}", cause.name());
        }
        s.push_str("},\"merged\":{");
        for (i, cause) in PublishCause::ALL.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let n = b.publish_merged.get(cause).copied().unwrap_or(0);
            let _ = write!(s, "\"{}\":{n}", cause.name());
        }
        let _ = write!(
            s,
            "}},\"renewals\":{},\"board_news\":{}}},\"prekeys\":",
            b.renewals, b.board_news
        );
        match b.prekeys {
            Some(p) => {
                let _ = write!(
                    s,
                    "{{\"one_time\":{},\"consumed\":{},\"signed_prekey\":{},\"rotated\":{},\
                     \"refilled\":{},\"previous_used\":{}}}",
                    p.one_time, p.consumed, p.signed_prekey, p.rotated, p.refilled, p.previous_used
                );
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"set_aside\":[");
        for (i, (room, entries)) in b.set_aside.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let list: Vec<String> = entries.iter().map(|e| q(e)).collect();
            let _ = write!(
                s,
                "{{\"room\":\"{}\",\"entries\":[{}]}}",
                b32_encode(room),
                list.join(",")
            );
        }
        // **Every live tunnel** (V210-81): the member, the service, which way it was opened, and
        // when it was opened and last moved a byte (Unix seconds), so a stale one is visible.
        s.push_str("],\"tunnels\":[");
        // Only this node's tunnels: a process may host several (ADR-026 P-1).
        for (i, t) in crate::transport::quic::live_tunnels(me).iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"id\":{},\"peer\":\"{}\",\"service\":{},\"direction\":\"{}\",\
                 \"opened\":{},\"last_moved\":{}}}",
                t.id,
                b32_encode(&t.peer),
                q(&t.service),
                if t.outbound { "out" } else { "in" },
                t.opened,
                t.last_moved
            );
        }
        // **Tunnels that ended for a reason a person should see** (V030-11): closed here, closed
        // at the other end, or closed as stuck, with why; and how long a stuck tunnel is given.
        s.push_str("],\"closed_tunnels\":[");
        for (i, t) in crate::transport::quic::closed_tunnels(me)
            .iter()
            .enumerate()
        {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"id\":{},\"peer\":\"{}\",\"service\":{},\"direction\":\"{}\",\
                 \"opened\":{},\"closed\":{},\"why\":{}}}",
                t.id,
                b32_encode(&t.peer),
                q(&t.service),
                if t.outbound { "out" } else { "in" },
                t.opened,
                t.closed,
                q(&t.why)
            );
        }
        let _ = write!(s, "],\"tunnel_stuck_after\":{}", stuck_after.as_secs());
        s
    }
}

// ---- IPC -------------------------------------------------------------------
// Additive to protocol 6, away from the sequential tags as the other late ones are.

const T_STATUS: u64 = 2301;
const T_STATUS_REPORT: u64 = 2302;
const T_TUNNEL_CLOSE: u64 = 2303;
const T_TUNNEL_CLOSED: u64 = 2304;

/// What `vox tunnel close` says it closed (V030-11): each tunnel as `vox status` lists it.
#[must_use]
pub fn closed_said(closed: &[crate::transport::quic::LiveTunnel]) -> String {
    closed
        .iter()
        .map(|t| {
            format!(
                "tunnel {} {} {} for {}",
                t.id,
                if t.outbound { "to" } else { "from" },
                b32_encode(&t.peer).chars().take(12).collect::<String>(),
                t.service
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `body` is a tunnel-close request (V030-11), and if so what it names.
#[must_use]
pub fn close_request(body: &[u8]) -> Option<crate::transport::quic::TunnelSelector> {
    let mut d = Decoder::new(body);
    if !matches!((d.array(), d.uint()), (Ok(4), Ok(T_TUNNEL_CLOSE))) {
        return None;
    }
    let mut field = || d.text().ok().filter(|t| !t.is_empty()).map(str::to_owned);
    let (id, member, service) = (field(), field(), field());
    Some(crate::transport::quic::TunnelSelector {
        id: id.and_then(|i| i.parse().ok()),
        member,
        service,
    })
}

/// Close what `which` names, here in the node, and answer with what was closed.
///
/// # Errors
/// If the reply cannot be written.
pub async fn serve_close(
    stream: &mut UnixStream,
    owner: &Digest32,
    which: &crate::transport::quic::TunnelSelector,
) -> Result<()> {
    // Nothing closed and a reason: the selector named more than one member.
    let (n, said) = match crate::transport::quic::close_tunnels(
        owner,
        which,
        "closed by a person on this side",
    ) {
        Ok(closed) => (closed.len() as u64, closed_said(&closed)),
        Err(refused) => (0, refused),
    };
    let mut e = Encoder::new();
    e.array(3).uint(T_TUNNEL_CLOSED).uint(n).text(&said);
    write_frame(stream, &e.finish()).await
}

/// Ask the node `at` names to close the tunnels `which` names: how many it closed,
/// and each as `vox status` lists it — or none, and why not, when `which` named more than one
/// member.
///
/// # Errors
/// If the node cannot be reached, does not answer in time, or answers something else.
pub async fn request_close(
    at: &crate::node::ipc::NodeSocket,
    which: &crate::transport::quic::TunnelSelector,
) -> Result<(u64, String)> {
    let body = tokio::time::timeout(
        crate::node::ipc::ANSWER_WITHIN,
        exchange(at, close_body(which)),
    )
    .await
    .map_err(|_| crate::node::ipc::silent())??;
    close_reply(&body)
}

/// [`request_close`] on a connection already acting as a node on the daemon's account socket
/// (ADR-026 C-2): what a client of the daemon, the TUI first, closes a tunnel with.
///
/// # Errors
/// If the node cannot be reached or answers something else.
pub async fn request_close_on(
    client: &mut crate::node::ipc::IpcClient,
    which: &crate::transport::quic::TunnelSelector,
) -> Result<(u64, String)> {
    let body = client.exchange(&close_body(which)).await?;
    close_reply(&body)
}

fn close_body(which: &crate::transport::quic::TunnelSelector) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(4)
        .uint(T_TUNNEL_CLOSE)
        .text(&which.id.map(|i| i.to_string()).unwrap_or_default())
        .text(which.member.as_deref().unwrap_or_default())
        .text(which.service.as_deref().unwrap_or_default());
    e.finish()
}

fn close_reply(body: &[u8]) -> Result<(u64, String)> {
    let mut d = Decoder::new(body);
    if let (Ok(3), Ok(T_TUNNEL_CLOSED)) = (d.array(), d.uint()) {
        let n = d
            .uint()
            .map_err(|_| Error::MalformedIpc("ipc tunnel-close reply"))?;
        let said = d
            .text()
            .map_err(|_| Error::MalformedIpc("ipc tunnel-close reply"))?;
        return Ok((n, said.to_owned()));
    }
    Err(Error::MalformedIpc("ipc tunnel-close reply"))
}

/// Whether `body` is a status request.
#[must_use]
pub fn is_request(body: &[u8]) -> bool {
    let mut d = Decoder::new(body);
    matches!((d.array(), d.uint()), (Ok(1), Ok(T_STATUS)))
}

/// Answer a status request on the control socket.
///
/// # Errors
/// If the reply cannot be written.
pub async fn serve(stream: &mut UnixStream, handle: &NodeHandle) -> Result<()> {
    let body = match handle.status().await {
        Ok(report) => {
            // ADR-025 S0b's counters join the report as its `sync` and `reach` members, and the
            // rooms' equivocations as `equivocations` (V210-63).
            let equivocations: Vec<(Digest32, Digest32, u64)> = handle
                .view()
                .open_channels
                .iter()
                .flat_map(|d| {
                    d.equivocations
                        .iter()
                        .map(move |(author, seq)| (d.channel_id, *author, *seq))
                })
                .collect();
            let mut json = report.to_json();
            json.pop();
            json.push(',');
            let me = report.identity.unwrap_or_default();
            json.push_str(&SyncBook::sections_json(
                handle.sync_book(),
                &equivocations,
                &me,
                report.tunnel_stuck_after,
            ));
            json.push('}');
            let mut e = Encoder::new();
            e.array(2).uint(T_STATUS_REPORT).text(&json);
            e.finish()
        }
        Err(e) => Frame::Error {
            reason: e.to_string(),
        }
        .to_bytes(),
    };
    write_frame(stream, &body).await
}

/// Ask the node `at` names for its status, as JSON.
///
/// **Bounded by [`ANSWER_WITHIN`](crate::node::ipc::ANSWER_WITHIN)** (V210-83): a suspended node's
/// socket still accepts, and `vox status` against one waited for ever.
///
/// # Errors
/// If the node cannot be reached, does not answer in time, or answers something else.
pub async fn request(at: &crate::node::ipc::NodeSocket) -> Result<String> {
    tokio::time::timeout(crate::node::ipc::ANSWER_WITHIN, ask(at))
        .await
        .map_err(|_| crate::node::ipc::silent())?
}

async fn ask(at: &crate::node::ipc::NodeSocket) -> Result<String> {
    let mut e = Encoder::new();
    e.array(1).uint(T_STATUS);
    let body = exchange(at, e.finish()).await?;
    let mut d = Decoder::new(&body);
    if let (Ok(2), Ok(T_STATUS_REPORT)) = (d.array(), d.uint()) {
        return d
            .text()
            .map(str::to_owned)
            .map_err(|_| Error::MalformedIpc("ipc status reply"));
    }
    match Frame::from_bytes(&body)? {
        Frame::Error { reason } => Err(Error::Path {
            op: "vox status",
            detail: reason,
        }),
        _ => Err(Error::MalformedIpc("ipc status reply")),
    }
}

/// Greet the daemon as the node `at` names (ADR-026 C-2), send it `request`, and return its one
/// reply.
async fn exchange(at: &crate::node::ipc::NodeSocket, request: Vec<u8>) -> Result<Vec<u8>> {
    let (mut stream, _) = crate::node::ipc::open_as(at).await?;
    // A connection that ends is named as such, never as a malformed message (V210-101); and none
    // of this is an identity bundle, which `MalformedBundle` said.
    if let Err(e) = write_frame(&mut stream, &request).await {
        return Err(crate::node::ipc::named(&at.path, e).await);
    }
    let Some(body) = read_frame(&mut stream).await? else {
        return Err(crate::node::ipc::hung_up(&at.path).await);
    };
    Ok(body)
}

// ---- metrics endpoint ------------------------------------------------------

/// Bind the metrics endpoint, **loopback only**: the counters name every peer and room
/// this node talks to, which is exactly what a relay operator must not learn, so they
/// are not offered to the network. The same rule `vox forward` enforces.
///
/// # Errors
/// If `addr` is not a loopback address, or cannot be bound.
pub async fn bind_metrics(addr: SocketAddr) -> Result<tokio::net::TcpListener> {
    if !addr.ip().is_loopback() {
        return Err(Error::AppRefused(format!(
            "--metrics {addr}: the metrics endpoint binds loopback only (127.0.0.1 or ::1); \
             it names every peer and room this node talks to"
        )));
    }
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Path {
            op: "bind metrics endpoint",
            detail: format!("{addr}: {e}"),
        })
}

/// The most of a request's head [`read_request_head`] reads: far more than a scraper's request
/// line and headers, so a client cannot hold the reader on a head without end.
const REQUEST_HEAD_MAX: usize = 16 * 1024;

/// Read `sock` until the end of an HTTP request's head (`\r\n\r\n`), the peer's end of stream,
/// [`REQUEST_HEAD_MAX`] bytes, or `within`, whichever comes first (V210-126).
async fn read_request_head(sock: &mut tokio::net::TcpStream, within: std::time::Duration) {
    let deadline = tokio::time::Instant::now() + within;
    let mut head: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 2048];
    while head.len() < REQUEST_HEAD_MAX {
        match tokio::time::timeout_at(deadline, sock.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                // Only the last three bytes of what came before can begin the terminator.
                let from = head.len().saturating_sub(3);
                head.extend_from_slice(&chunk[..n]);
                if head[from..].windows(4).any(|w| w == b"\r\n\r\n") {
                    return;
                }
            }
            _ => return,
        }
    }
}

/// How long [`drain_after_answer`] goes on discarding what a client still sends.
const DRAIN_AFTER_ANSWER: std::time::Duration = std::time::Duration::from_secs(2);

/// After the answer and its FIN: read and discard what the client still sends, until it closes
/// its end or `within` passes (V030-23). Closing with unread input makes the OS reset the
/// connection, and on macOS that reset can overtake the answer, so a client whose head was cut
/// off at [`REQUEST_HEAD_MAX`] or never ended lost a response it had already been sent.
async fn drain_after_answer(sock: &mut tokio::net::TcpStream, within: std::time::Duration) {
    let deadline = tokio::time::Instant::now() + within;
    let mut chunk = [0u8; 2048];
    while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, sock.read(&mut chunk)).await {
        if n == 0 {
            return;
        }
    }
}

/// Serve Prometheus text for the one node `handle`, named `node`, on every connection to
/// `listener`, until it is dropped: a process that hosts one node and no daemon (`vox lan up`).
pub async fn serve_metrics(listener: tokio::net::TcpListener, node: String, handle: NodeHandle) {
    serve_metrics_for(listener, None, move || vec![(node.clone(), handle.clone())]).await;
}

/// Serve Prometheus text on every connection to `listener`, until it is dropped: the daemon's own
/// families from `daemon`, then those of every node `nodes` lists at the time of the scrape, each
/// sample labelled with its node's name. A node that does not answer is `vox_up 0` for that node.
pub async fn serve_metrics_for<F>(
    listener: tokio::net::TcpListener,
    daemon: Option<std::sync::Arc<DaemonMetrics>>,
    nodes: F,
) where
    F: Fn() -> Vec<(String, NodeHandle)> + Send + Sync + 'static,
{
    let nodes = std::sync::Arc::new(nodes);
    while let Ok((mut sock, _)) = listener.accept().await {
        let (daemon, nodes) = (daemon.clone(), std::sync::Arc::clone(&nodes));
        tokio::spawn(async move {
            // The request itself is not interpreted: every path answers the metrics. But it is
            // **read to its end** first, the blank line after its headers, within the same 2 s
            // (V210-126): one read took only the first segment of a request that arrived in
            // pieces, and closing with the rest unread made the OS reset the connection, so the
            // scraper lost the answer (`Connection reset by peer`).
            read_request_head(&mut sock, std::time::Duration::from_secs(2)).await;
            let mut out = Families::default();
            if let Some(d) = &daemon {
                d.to_prometheus_rows(&mut out);
            }
            for (name, handle) in nodes() {
                match handle.status().await {
                    Ok(r) => r.to_prometheus_rows(&name, &mut out),
                    Err(_) => {
                        out.family("vox_up", "1 while the node answers.", Kind::Gauge);
                        out.sample("vox_up", &node_label(&name), "", 0);
                    }
                }
            }
            let body = out.render();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body.as_bytes()).await;
            // Half-closed, so the answer is followed by a FIN, then drained, so whatever of the
            // request was never read cannot turn the close into a reset (V030-23).
            let _ = sock.shutdown().await;
            drain_after_answer(&mut sock, DRAIN_AFTER_ANSWER).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two nodes' reports in one exposition: each family's `HELP` and `TYPE` once, every sample
    /// labelled with its node first, and the daemon's own families unlabelled (ADR-026 P-1).
    #[test]
    fn two_nodes_share_one_help_and_type_per_family() {
        let mut out = Families::default();
        let daemon = DaemonMetrics::default();
        daemon
            .nodes_attached
            .store(2, std::sync::atomic::Ordering::Relaxed);
        daemon.to_prometheus_rows(&mut out);
        let a = StatusReport {
            networked: true,
            ..StatusReport::default()
        };
        a.to_prometheus_rows("alice", &mut out);
        StatusReport::default().to_prometheus_rows("bob", &mut out);
        let text = out.render();
        for family in ["vox_up", "vox_networked", "vox_datagrams_sent_total"] {
            assert_eq!(
                text.matches(&format!("# TYPE {family} ")).count(),
                1,
                "{family}:\n{text}"
            );
        }
        assert!(text.contains("vox_networked{node=\"alice\"} 1\n"), "{text}");
        assert!(text.contains("vox_networked{node=\"bob\"} 0\n"), "{text}");
        assert!(
            text.contains("vox_datagrams_sent_total{node=\"bob\"} 0\n"),
            "{text}"
        );
        assert!(text.contains("vox_daemon_nodes_attached 2\n"), "{text}");
        assert!(text.contains("vox_daemon_node_panics_total 0\n"), "{text}");
        // No sample of a node's family goes unlabelled.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            assert!(
                line.starts_with("vox_daemon_") || line.contains("{node=\""),
                "unlabelled: {line}"
            );
        }
    }

    /// A sample with labels of its own keeps them after the node's.
    #[test]
    fn a_labelled_sample_puts_the_node_first() {
        let mut out = Families::default();
        out.family("vox_x", "x", Kind::Gauge);
        out.sample("vox_x", &node_label("a\"b"), "{peer=\"P\"}", 3);
        assert_eq!(
            out.render(),
            "# HELP vox_x x\n# TYPE vox_x gauge\nvox_x{node=\"a\\\"b\",peer=\"P\"} 3\n"
        );
    }
}
