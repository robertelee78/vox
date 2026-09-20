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

use std::collections::BTreeMap;
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
/// `try_send`, not `send`: this runs inside the accept path, between authorization and
/// the local connect, and a client that has stopped draining its event queue must not
/// be able to stall a tunnel. The event is therefore best-effort for a live client and
/// is **not** an audit record — ADR-013's signed session events remain its own item.
pub async fn serve_reporting(
    client: Digest32,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    snapshot: HostSnapshot,
    events: Option<tokio::sync::mpsc::Sender<NodeEvent>>,
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
            })
        },
        |channel_id, tag| {
            if let Some(tx) = events {
                let _ = tx.try_send(NodeEvent::TunnelServed {
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
    pub async fn bind(
        conn: Arc<VoxConnection>,
        channel_id: Digest32,
        service_tag: String,
        local: SocketAddr,
    ) -> Result<Self> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::capability::{Capability, CapabilitySet};
    use crate::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::transport::quic::VoxEndpoint;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const NOW: u64 = 1_800_000_000;

    fn signer(seed: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0xFF; 32]).unwrap()
    }

    fn loopback() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    fn policy() -> ChannelPolicy {
        ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: crate::suite::SuiteFloor::DAY_ONE.id(),
        }
    }

    /// A TCP echo service that serves many connections.
    async fn spawn_echo() -> SocketAddr {
        let l = TcpListener::bind(loopback()).await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    /// A forward carries **many** connections, each on its own stream, and refuses
    /// what the log does not permit — without saying which reason applies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_forward_carries_many_connections_and_refuses_the_unauthorized() {
        let echo = spawn_echo().await;
        // The host's channel: the dialer is the root admin, so it holds dial:echo.
        let dialer_signer = signer(3);
        let genesis = Genesis::create_with_nonce(&dialer_signer, NOW, policy(), [7u8; 16]).unwrap();
        let cid = genesis.channel_id();
        let evaluator = Arc::new(Evaluator::build(&genesis, &[], NOW, |_| None).unwrap());
        let mut services = BTreeMap::new();
        services.insert("echo".to_owned(), echo);
        let snapshot: HostSnapshot = [(
            cid,
            ChannelServices {
                evaluator: Arc::clone(&evaluator),
                services,
            },
        )]
        .into_iter()
        .collect();

        // The host serves tunnels from its snapshot.
        let host_signer = signer(1);
        let host_ep = Arc::new(VoxEndpoint::bind(&host_signer, loopback()).unwrap());
        let host_addr = host_ep.local_addr().unwrap();
        let host_id = host_ep.local_id();
        {
            let host_ep = Arc::clone(&host_ep);
            tokio::spawn(async move {
                while let Ok(Some(conn)) = host_ep.accept(NOW).await {
                    let snapshot = snapshot.clone();
                    tokio::spawn(async move {
                        let client = conn.peer_id();
                        // The node's dispatch reads the kind frame first and routes by
                        // kind; this harness does the same, so `serve` sees exactly
                        // what it sees in production.
                        while let Ok((kind, send, recv)) =
                            crate::transport::streams::accept_typed(&conn).await
                        {
                            assert_eq!(kind, StreamKind::Tunnel);
                            let snapshot = snapshot.clone();
                            tokio::spawn(async move { serve(client, send, recv, snapshot).await });
                        }
                    });
                }
            });
        }

        // The dialer reaches the host and forwards a local port.
        let dialer_ep = VoxEndpoint::bind(&dialer_signer, loopback()).unwrap();
        let conn = Arc::new(
            dialer_ep
                .connect(host_addr, host_id, NOW)
                .await
                .expect("the dialer reaches the host"),
        );
        let fwd = Forward::bind(Arc::clone(&conn), cid, "echo".to_owned(), loopback())
            .await
            .expect("the local port binds");
        assert_ne!(fwd.local.port(), 0, "a concrete bound port is reported");
        assert_eq!(fwd.host, host_id);

        // Three applications at once, each its own stream, each echoed.
        for i in 0..3u8 {
            let mut app = tokio::net::TcpStream::connect(fwd.local).await.unwrap();
            let msg = format!("connection-{i}-over-vox");
            app.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; msg.len()];
            tokio::time::timeout(Duration::from_secs(10), app.read_exact(&mut buf))
                .await
                .expect("echo did not hang")
                .expect("the bytes came back");
            assert_eq!(buf, msg.as_bytes(), "connection {i}");
        }

        // A service the host does not offer, and a channel it does not hold, both just
        // close the connection — no reason is disclosed either way.
        for (cid, tag) in [(cid, "http"), ([0xAB; 32], "echo")] {
            let fwd = Forward::bind(Arc::clone(&conn), cid, tag.to_owned(), loopback())
                .await
                .unwrap();
            let mut app = tokio::net::TcpStream::connect(fwd.local).await.unwrap();
            let _ = app.write_all(b"knock").await;
            let mut buf = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(10), app.read(&mut buf)).await;
            assert!(
                matches!(read, Ok(Ok(0)) | Ok(Err(_))),
                "a dark service closes: {read:?}"
            );
        }

        // Dropping the forward stops the listener: nothing new is accepted.
        let closed_port = fwd.local;
        drop(fwd);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after = tokio::net::TcpStream::connect(closed_port).await;
        if let Ok(mut s) = after {
            // Some platforms accept into a closed backlog; the read must still end.
            let mut buf = [0u8; 1];
            let _ = s.write_all(b"x").await;
            let read = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await;
            assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");
        }
    }

    /// The capability is what decides, not the host's configuration: a peer holding no
    /// `dial:` grant is refused a service the host does offer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_peer_without_the_capability_is_refused_a_service_that_exists() {
        let echo = spawn_echo().await;
        // The channel admin is a third party; the dialer holds nothing.
        let admin = signer(9);
        let genesis = Genesis::create_with_nonce(&admin, NOW, policy(), [8u8; 16]).unwrap();
        let cid = genesis.channel_id();
        let evaluator = Arc::new(Evaluator::build(&genesis, &[], NOW, |_| None).unwrap());
        // The grant that *would* work, to prove the refusal is about the capability:
        // the admin could delegate dial:echo, and does not.
        let would_grant = CapabilitySet::from_iter_caps([Capability::dial("echo")]);
        assert!(!would_grant.is_empty());

        let mut services = BTreeMap::new();
        services.insert("echo".to_owned(), echo);
        let snapshot: HostSnapshot = [(
            cid,
            ChannelServices {
                evaluator,
                services,
            },
        )]
        .into_iter()
        .collect();

        let host_signer = signer(5);
        let host_ep = Arc::new(VoxEndpoint::bind(&host_signer, loopback()).unwrap());
        let host_addr = host_ep.local_addr().unwrap();
        let host_id = host_ep.local_id();
        {
            let host_ep = Arc::clone(&host_ep);
            tokio::spawn(async move {
                while let Ok(Some(conn)) = host_ep.accept(NOW).await {
                    let snapshot = snapshot.clone();
                    let client = conn.peer_id();
                    tokio::spawn(async move {
                        while let Ok((kind, send, recv)) =
                            crate::transport::streams::accept_typed(&conn).await
                        {
                            assert_eq!(kind, StreamKind::Tunnel);
                            let snapshot = snapshot.clone();
                            tokio::spawn(async move { serve(client, send, recv, snapshot).await });
                        }
                    });
                }
            });
        }

        let stranger = signer(6);
        assert_ne!(
            RootSigner::public_key(&stranger).fingerprint(),
            RootSigner::public_key(&admin).fingerprint()
        );
        let dialer_ep = VoxEndpoint::bind(&stranger, loopback()).unwrap();
        let conn = Arc::new(dialer_ep.connect(host_addr, host_id, NOW).await.unwrap());
        let fwd = Forward::bind(Arc::clone(&conn), cid, "echo".to_owned(), loopback())
            .await
            .unwrap();
        let mut app = tokio::net::TcpStream::connect(fwd.local).await.unwrap();
        let _ = app.write_all(b"let me in").await;
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(10), app.read(&mut buf)).await;
        assert!(
            matches!(read, Ok(Ok(0)) | Ok(Err(_))),
            "an unauthorized dial is refused: {read:?}"
        );
    }
}
