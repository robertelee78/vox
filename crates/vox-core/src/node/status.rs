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
//! - a **trusted** member of an open room this node was connected to and no longer is.
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

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::app::AppStats;
use crate::node::ipc::{read_frame, write_frame, Frame, PROTOCOL_VERSION};
use crate::node::link::b32_encode;
use crate::transport::router::DatagramStats;

/// A room with other members and no completed sync for this long is flagged.
pub const STALE_SYNC_SECS: u64 = 10 * 60;

/// One tunnel this node is serving right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedTunnel {
    /// The member reaching it.
    pub client: Digest32,
    /// The room it is bound to.
    pub channel_id: Digest32,
    /// The service.
    pub service_tag: String,
    /// When it was authorized, seconds since the epoch.
    pub since: u64,
}

/// The ledgers this module keeps beside the node's own state.
#[derive(Debug, Default)]
pub struct StatusBook {
    /// Room → when a sync this node ran there last completed.
    pub room_synced: BTreeMap<Digest32, u64>,
    /// Peer → when this node last saw a live connection to it.
    pub last_seen: BTreeMap<Digest32, u64>,
    /// Tunnels being served, by a local id; entries leave when the tunnel ends.
    pub served: Arc<Mutex<BTreeMap<u64, ServedTunnel>>>,
    /// When the node started, seconds since the epoch: a room that has not synced *yet*
    /// is not stale until it has had [`STALE_SYNC_SECS`] to do so.
    pub started: u64,
    next_tunnel: u64,
}

/// A place in [`StatusBook::served`], given back when the tunnel ends.
#[derive(Debug)]
pub struct ServedGuard {
    id: u64,
    served: Arc<Mutex<BTreeMap<u64, ServedTunnel>>>,
}

impl ServedGuard {
    /// The tunnel was authorized: it is now being served.
    pub fn serving(&self, tunnel: ServedTunnel) {
        self.served
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(self.id, tunnel);
    }
}

impl Drop for ServedGuard {
    fn drop(&mut self) {
        self.served
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl StatusBook {
    /// A guard for one inbound tunnel stream; it shows as served once
    /// [`ServedGuard::serving`] says so, and stops when the guard drops.
    pub fn tunnel(&mut self) -> ServedGuard {
        self.next_tunnel += 1;
        ServedGuard {
            id: self.next_tunnel,
            served: Arc::clone(&self.served),
        }
    }

    /// The tunnels being served now.
    #[must_use]
    pub fn served_now(&self) -> Vec<ServedTunnel> {
        self.served
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }
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
}

/// A local port forwarded to a member's service (the dial side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialedTunnel {
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
    /// Where it listens.
    pub listening: Vec<String>,
    /// Its open rooms.
    pub rooms: Vec<RoomStatus>,
    /// Its live connections.
    pub peers: Vec<PeerStatus>,
    /// How many circuits it carries for others.
    pub relaying: usize,
    /// Tunnels it serves now.
    pub tunnels_served: Vec<ServedTunnel>,
    /// Ports it forwards to others' services.
    pub tunnels_dialed: Vec<DialedTunnel>,
    /// Datagram counters, summed over every connection.
    pub datagrams: DatagramStats,
    /// The app layer's counters.
    pub app: AppStats,
    /// What needs looking at.
    pub unhealthy: Vec<Unhealthy>,
}

/// One condition that needs looking at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unhealthy {
    /// A stable name for the condition — `peer-unreachable:<room>:<peer>` or
    /// `room-stale:<room>` — the same for as long as the condition holds, so a notifier
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
            format!(
                "{{\"id\":{},\"name\":{},\"epoch\":{},\"last_sync\":{},\"members\":[{}]}}",
                q(&b32_encode(&r.id)),
                q(&r.name),
                r.epoch,
                opt(r.last_sync),
                list(members)
            )
        });
        let _ = write!(j, "\"rooms\":[{}],", list(rooms));
        let peers = self.peers.iter().map(|p| {
            format!(
                "{{\"id\":{},\"path\":{},\"relay\":{},\"rtt_ms\":{},\"datagrams\":{}}}",
                q(&b32_encode(&p.id)),
                q(p.path),
                p.relay.map_or("null".into(), |d| q(&b32_encode(&d))),
                p.rtt_ms,
                dgram_json(&p.datagrams)
            )
        });
        let _ = write!(j, "\"peers\":[{}],", list(peers));
        let _ = write!(j, "\"relaying\":{},", self.relaying);
        let served = self.tunnels_served.iter().map(|t| {
            format!(
                "{{\"client\":{},\"room\":{},\"service\":{},\"since\":{}}}",
                q(&b32_encode(&t.client)),
                q(&b32_encode(&t.channel_id)),
                q(&t.service_tag),
                t.since
            )
        });
        let _ = write!(j, "\"tunnels_served\":[{}],", list(served));
        let dialed = self.tunnels_dialed.iter().map(|t| {
            format!(
                "{{\"host\":{},\"room\":{},\"service\":{},\"local\":{}}}",
                q(&b32_encode(&t.host)),
                q(&b32_encode(&t.channel_id)),
                q(&t.service_tag),
                q(&t.local.to_string())
            )
        });
        let _ = write!(j, "\"tunnels_dialed\":[{}],", list(dialed));
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

    /// The report as Prometheus text exposition (what `vox daemon --metrics` serves).
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let mut m = String::new();
        let mut gauge = |name: &str, help: &str, rows: Vec<(String, u64)>| {
            let _ = writeln!(m, "# HELP {name} {help}");
            let _ = writeln!(m, "# TYPE {name} gauge");
            for (labels, v) in rows {
                let _ = writeln!(m, "{name}{labels} {v}");
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
        gauge(
            "vox_tunnels_served",
            "Tunnels being served now.",
            vec![(String::new(), self.tunnels_served.len() as u64)],
        );
        gauge(
            "vox_tunnels_dialed",
            "Local forwards to members' services.",
            vec![(String::new(), self.tunnels_dialed.len() as u64)],
        );
        gauge(
            "vox_unhealthy",
            "Lines `vox status` flags as needing attention.",
            vec![(String::new(), self.unhealthy.len() as u64)],
        );
        let d = &self.datagrams;
        let mut counter = |name: &str, help: &str, v: u64| {
            let _ = writeln!(m, "# HELP {name} {help}");
            let _ = writeln!(m, "# TYPE {name} counter");
            let _ = writeln!(m, "{name} {v}");
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
        m
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

// ---- IPC -------------------------------------------------------------------
// Additive to protocol 6, away from the sequential tags as the other late ones are.

const T_STATUS: u64 = 2301;
const T_STATUS_REPORT: u64 = 2302;

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
            let mut e = Encoder::new();
            e.array(2).uint(T_STATUS_REPORT).text(&report.to_json());
            e.finish()
        }
        Err(e) => Frame::Error {
            reason: e.to_string(),
        }
        .to_bytes(),
    };
    write_frame(stream, &body).await
}

/// Ask the node at `path` for its status, as JSON.
///
/// # Errors
/// If no node answers, or it refuses.
pub async fn request(path: &Path) -> Result<String> {
    let mut stream = UnixStream::connect(path).await.map_err(|e| Error::Path {
        op: "connect control socket",
        detail: format!("{}: {e}", path.display()),
    })?;
    let Some(hello) = read_frame(&mut stream).await? else {
        return Err(Error::MalformedBundle("ipc closed before hello"));
    };
    match Frame::from_bytes(&hello)? {
        Frame::Hello { protocol, .. } if protocol == PROTOCOL_VERSION => {}
        _ => return Err(Error::MalformedBundle("ipc protocol version")),
    }
    let mut e = Encoder::new();
    e.array(1).uint(T_STATUS);
    write_frame(&mut stream, &e.finish()).await?;
    let Some(body) = read_frame(&mut stream).await? else {
        return Err(Error::MalformedBundle("ipc closed before reply"));
    };
    let mut d = Decoder::new(&body);
    if let (Ok(2), Ok(T_STATUS_REPORT)) = (d.array(), d.uint()) {
        return d
            .text()
            .map(str::to_owned)
            .map_err(|_| Error::MalformedBundle("ipc status reply"));
    }
    match Frame::from_bytes(&body)? {
        Frame::Error { reason } => Err(Error::AppRefused(reason)),
        _ => Err(Error::MalformedBundle("ipc status reply")),
    }
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

/// Serve Prometheus text on every connection to `listener`, until it is dropped.
pub async fn serve_metrics(listener: tokio::net::TcpListener, handle: NodeHandle) {
    while let Ok((mut sock, _)) = listener.accept().await {
        let handle = handle.clone();
        tokio::spawn(async move {
            // The request itself is not interpreted: every path answers the metrics. A
            // bounded read is enough to consume a scraper's request line and headers.
            let mut buf = [0u8; 2048];
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(2), sock.read(&mut buf)).await;
            let body = match handle.status().await {
                Ok(r) => r.to_prometheus(),
                Err(_) => "vox_up 0\n".to_owned(),
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}
