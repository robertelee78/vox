//! The node's **tunnel surface** (ADR-013, M16.1): what turns the tunnel library
//! into something a person uses.
//!
//! - **Host side** — [`serve`]: an inbound `StreamKind::Tunnel` stream goes to
//!   [`session::accept`], which reads the request, asks the actor's snapshot about the
//!   `(channel, service)` it names, and checks the dialer against *that channel's* live
//!   reacher set (ADR-017 decision 3). Nothing here can grant reach: this supplies host
//!   configuration and the live sets, never a decision.
//! - **Dial side** — [`Forward`]: a local TCP listener. Every accepted connection
//!   reaches the host afresh, opens its own tunnel stream and splices, so a forward
//!   carries as many connections as the application makes, a dead one takes nothing
//!   else with it (ADR-013: one QUIC stream per tunneled TCP connection), and a host that
//!   restarted is reached again (PRD-001 R24).
//!
//! ## What is dark stays dark
//! An untrusted dialer, a channel this node does not hold, a service it does not offer,
//! and a local service that refuses the connection all end the same way on the wire:
//! `TunnelStatus::Denied`, which distinguishes none of them. The dialing node resets the
//! application's connection and says, locally, that the host refused (PRD-001 R23).

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::api::NodeEvent;
use crate::node::up;
use crate::tunnel::session::{self, HostService};

/// The set of identities that may reach a host's services in one channel, shared live
/// between the actor (which writes) and the serving tasks (which read).
///
/// A watch channel rather than a lock, because the serving tasks need two different
/// things from it and a watch gives both: the current value at any instant
/// (`borrow()`, for the dial gate) and a wake-up when it changes (`subscribe()`, for
/// tearing down a session whose reach has just been withdrawn). A lock would serve the
/// first and force polling for the second.
pub type Reachers = Arc<tokio::sync::watch::Sender<BTreeSet<Digest32>>>;

/// A fresh, empty reacher set: the state that denies everyone.
#[must_use]
pub fn empty_reachers() -> Reachers {
    Arc::new(tokio::sync::watch::Sender::new(BTreeSet::new()))
}

/// Publish a newly computed reacher set, waking the serving tasks **only if it changed**.
/// Returns whether it changed.
///
/// One named function because the rule it enforces is easy to lose and expensive to lose:
/// **a recompute is not a decision.** The actor re-derives these sets on every accept, and
/// `watch::Sender::send_replace` notifies unconditionally — so writing with that woke every
/// serving task in every room on every new tunnel stream, and each of those tasks answers a
/// wake by re-evaluating whether to tear down the live session it is carrying
/// ([`crate::tunnel::session`]). A person saw `Connection reset by peer` in the middle of
/// their work with nobody having withdrawn anything.
///
/// So the teardown path must only ever be woken by a real change, and the only way to keep
/// that true is to have exactly one place that writes these sets.
pub fn publish_reachers(handle: &Reachers, next: BTreeSet<Digest32>) -> bool {
    handle.send_if_modified(|current| {
        if *current == next {
            false
        } else {
            *current = next;
            true
        }
    })
}

/// One channel's host-side facts, as the actor snapshots them for the serving task:
/// the services this node offers there, and who may reach them.
#[derive(Clone)]
pub struct ChannelServices {
    /// `service_tag → local address` (this node's Bind configuration).
    pub services: BTreeMap<String, SocketAddr>,
    /// The identities that may reach this node's services **in this channel** (ADR-017
    /// decision 3, M17.7): the intersection of this node's trust keyring with this
    /// channel's current author set.
    ///
    /// A **live** handle, not a copy (M17.11). The actor owns the write side and keeps it
    /// current; serving tasks only read, so the rule that a serving task never reaches back
    /// into the actor still holds.
    ///
    /// It must be live because the authorization snapshot is taken when a tunnel *stream*
    /// opens, which is before its request is read. With a copied set, a peer could open a
    /// stream while authorized, hold it open saying nothing, wait for the host to withdraw
    /// trust, and only then send its request — and be authorized against a set captured
    /// before the withdrawal. No timing skill required; just patience.
    pub reachers: Reachers,
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
    /// The channel whose reach this forward uses.
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

/// How long an accept loop waits after the listener fails before trying again.
///
/// A failed `accept` is almost always the process running out of descriptors (`EMFILE`),
/// and retrying at once fails again at once: the loop spins a core and never gives the
/// connections holding those descriptors a chance to close. Exiting instead — which the
/// forward used to do, `while let Ok(..) = accept()` — turns a moment of pressure into a
/// port that is still bound and never answers again.
pub(crate) const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

impl Forward {
    /// Bind `local` and forward every connection to `service_tag` on `host`, reaching the
    /// host through `dialer` — **per connection**.
    ///
    /// Binding happens here, so a port already in use is an error the caller sees
    /// rather than a task that dies silently. Each accepted connection gets its own
    /// tunnel stream on its own task.
    ///
    /// Per connection, not once (PRD-001 R24). This used to take the one `VoxConnection`
    /// the ladder produced when the forward started and keep it for the forward's whole
    /// life, so when the host restarted, or the path to it changed, every later connection
    /// was opened on a connection that no longer went anywhere and the forward was dead
    /// while still bound. `vox up` already asked its dialer per request; the forward now
    /// does the same, through the same [`up::open_tunnel`].
    ///
    /// `report` hears, in words, why a connection was refused or cut — the application only
    /// sees its socket reset, and the host's refusal is uniform on purpose, but this node is
    /// the operator's own and knows what it was told (PRD-001 R23).
    ///
    /// `local` must be a loopback address. This is the structural backstop for the rule
    /// the node actor enforces on the way in: the socket is created here and nowhere
    /// else, so no caller can bind a forward where the network can reach it. Reaching
    /// this refusal means a caller bypassed the actor, which is a bug rather than user
    /// input — hence a fault rather than a message about what to type.
    pub async fn bind<D, F>(
        dialer: Arc<D>,
        host: Digest32,
        channel_id: Digest32,
        service_tag: String,
        local: SocketAddr,
        report: F,
    ) -> Result<Self>
    where
        D: up::HostDialer + 'static,
        F: Fn(String) + Send + Sync + 'static,
    {
        if !local.ip().is_loopback() {
            return Err(Error::MalformedTunnel("a forward binds loopback only"));
        }
        let listener = TcpListener::bind(local)
            .await
            .map_err(|_| Error::TunnelDenied("forward: cannot bind the local port"))?;
        let bound = listener
            .local_addr()
            .map_err(|_| Error::TunnelDenied("forward: bound port unknown"))?;
        let tag = service_tag.clone();
        let report = Arc::new(report);
        let task = tokio::spawn(async move {
            loop {
                let app = match listener.accept().await {
                    Ok((app, _)) => app,
                    Err(_) => {
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                };
                let dialer = Arc::clone(&dialer);
                let report = Arc::clone(&report);
                let tag = tag.clone();
                tokio::spawn(async move {
                    // One stream per connection, on whatever connection reaches the host now.
                    match up::open_tunnel(dialer.as_ref(), &host, &channel_id, &tag).await {
                        Ok((send, recv)) => {
                            if let Err(Error::TunnelRevoked(_)) =
                                session::splice(send, recv, app).await
                            {
                                report(format!(
                                    "the host withdrew access to {tag:?} — that session was cut"
                                ));
                            }
                        }
                        Err(e) => {
                            // Reset, not close: an application that sees a clean close after
                            // its connect succeeded reads it as the service hanging up, and
                            // retries a thing that will never work.
                            session::abort_local(&app);
                            report(up::refusal(&e, &format!("{tag:?}")));
                        }
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
