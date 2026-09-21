//! The node's **tunnel surface** (ADR-013, M16.1): what turns the tunnel library
//! into something a person uses.
//!
//! - **Host side** — [`serve`]: an inbound `StreamKind::Tunnel` stream goes to
//!   [`session::accept`], which reads the request, asks the actor's snapshot about the
//!   `(channel, service)` it names, and enforces `dial:` against *that channel's*
//!   evaluator. Nothing here can grant reach: this supplies host configuration and
//!   the authority to ask, never a decision.
//! - **Dial side** — [`Forward`]: a local TCP listener. Every accepted connection
//!   opens its own tunnel stream and splices, so a forward carries as many
//!   connections as the application makes and a dead one takes nothing else with it
//!   (ADR-013: one QUIC stream per tunneled TCP connection).
//!
//! ## What is dark stays dark
//! A missing capability, a channel this node does not hold, a service it does not
//! offer, and a local service that refuses the connection all end the same way: the
//! accepted TCP connection closes. `TunnelStatus::Denied` distinguishes none of them,
//! and neither does this.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::governance::evaluator::Evaluator;
use crate::hash::Digest32;
use crate::node::api::NodeEvent;
use crate::transport::quic::VoxConnection;
use crate::transport::streams::{open_typed, StreamKind};
use crate::tunnel::session::{self, HostService};

/// One channel's host-side facts, as the actor snapshots them for the serving task:
/// the authority that decides, and the services this node offers there.
#[derive(Clone)]
pub struct ChannelServices {
    /// The channel's ADR-007 evaluator.
    pub evaluator: Arc<Evaluator>,
    /// `service_tag → local address` (this node's Bind configuration).
    pub services: BTreeMap<String, SocketAddr>,
    /// The identities that may reach this node's services **in this channel** (ADR-017
    /// decision 3, M17.7): the intersection of this node's trust keyring with this
    /// channel's current author set.
    ///
    /// Computed by the actor, which is the only place that holds both, and snapshotted
    /// per accept so the decision is current rather than cached across one.
    pub reachers: Arc<BTreeSet<Digest32>>,
}

impl std::fmt::Debug for ChannelServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelServices")
            .field("services", &self.services.len())
            .finish_non_exhaustive()
    }
}

/// The host-side snapshot a serving task needs: every channel this node holds, by id.
/// Taken by the actor (the only reader of channel state) and handed over whole, so a
/// tunnel that lives for hours never reaches back into the actor.
pub type HostSnapshot = BTreeMap<Digest32, ChannelServices>;

/// Serve one inbound tunnel stream against `snapshot`.
///
/// The request names the channel; a channel absent from the snapshot resolves to
/// `None` and is refused exactly as an unauthorized request is — telling the two
/// apart would leak which channels this node is in.
pub async fn serve(
    client: Digest32,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    snapshot: HostSnapshot,
) -> Result<()> {
    serve_reporting(client, send, recv, snapshot, None).await
}

/// [`serve`], emitting [`NodeEvent::TunnelServed`] for each authorized request.
///
/// The host cannot learn this from the service's own logs — every Vox client reaches it
/// from loopback, so `sshd` records `127.0.0.1` for all of them (ADR-017 decision 6).
/// The identity is known here, so this is where it is surfaced.
///
/// This runs inside the accept path, between authorization and the local connect, so a
/// client that has stopped draining events must not be able to stall a tunnel. Since
/// M19.1 that is the property of *every* node event, not a local workaround here:
/// emission is a non-blocking broadcast (ADR-020 §7), so the plain `send` below cannot
/// wait on anybody. The event remains best-effort for a live client and is **not** an
/// audit record — ADR-013's signed session events remain its own item.
pub async fn serve_reporting(
    client: Digest32,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    snapshot: HostSnapshot,
    events: Option<tokio::sync::broadcast::Sender<NodeEvent>>,
) -> Result<()> {
    session::accept_reporting(
        send,
        recv,
        &client,
        |channel_id, tag| {
            let channel = snapshot.get(channel_id)?;
            let endpoint = *channel.services.get(tag)?;
            Some(HostService {
                evaluator: Arc::clone(&channel.evaluator),
                endpoint,
                reachers: Arc::clone(&channel.reachers),
            })
        },
        |channel_id, tag| {
            if let Some(tx) = events {
                let _ = tx.send(NodeEvent::TunnelServed {
                    channel_id: *channel_id,
                    client,
                    service_tag: tag.to_owned(),
                });
            }
        },
    )
    .await
}

/// A live local port forwarded to a member's service over the overlay.
///
/// Dropping it stops the listener. Connections already spliced run to their own end:
/// a forward is a door, not a leash.
pub struct Forward {
    /// The channel whose capability this forward claims.
    pub channel_id: Digest32,
    /// The member hosting the service.
    pub host: Digest32,
    /// The service tag being reached.
    pub service_tag: String,
    /// Where the application connects locally.
    pub local: SocketAddr,
    listener: JoinHandle<()>,
}

impl std::fmt::Debug for Forward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forward")
            .field("host", &crate::hash::Hex(&self.host))
            .field("service_tag", &self.service_tag)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

impl Forward {
    /// Bind `local` and forward every connection to `service_tag` on `host`, over
    /// `conn` — the live connection to that member, which the ADR-012 ladder produced.
    ///
    /// Binding happens here, so a port already in use is an error the caller sees
    /// rather than a task that dies silently. Each accepted connection gets its own
    /// tunnel stream on its own task.
    ///
    /// `local` must be a loopback address. This is the structural backstop for the rule
    /// the node actor enforces on the way in: the socket is created here and nowhere
    /// else, so no caller can bind a forward where the network can reach it. Reaching
    /// this refusal means a caller bypassed the actor, which is a bug rather than user
    /// input — hence a fault rather than a message about what to type.
    pub async fn bind(
        conn: Arc<VoxConnection>,
        channel_id: Digest32,
        service_tag: String,
        local: SocketAddr,
    ) -> Result<Self> {
        if !local.ip().is_loopback() {
            return Err(Error::MalformedTunnel("a forward binds loopback only"));
        }
        let listener = TcpListener::bind(local)
            .await
            .map_err(|_| Error::TunnelDenied("forward: cannot bind the local port"))?;
        let bound = listener
            .local_addr()
            .map_err(|_| Error::TunnelDenied("forward: bound port unknown"))?;
        let host = conn.peer_id();
        let tag = service_tag.clone();
        let task = tokio::spawn(async move {
            while let Ok((app, _)) = listener.accept().await {
                let conn = Arc::clone(&conn);
                let tag = tag.clone();
                tokio::spawn(async move {
                    // One stream per connection. A refusal closes this connection and
                    // says nothing about why (dark services).
                    if let Ok((send, recv)) = open_typed(&conn, StreamKind::Tunnel).await {
                        let _ = session::dial(send, recv, &channel_id, &tag, app).await;
                    }
                });
            }
        });
        Ok(Self {
            channel_id,
            host,
            service_tag,
            local: bound,
            listener: task,
        })
    }
}
