//! The per-stream tunnel data path (ADR-013 §"Mapping onto QUIC"): one QUIC stream
//! carries one tunneled TCP connection (ordered, reliable), isolated from messaging
//! and bulk-sync streams so interactive tunnels never suffer cross-stream
//! head-of-line blocking.
//!
//! This is the **primary**, ssh-style port-forward model. A dialer opens a stream
//! and sends a [`TunnelRequest`] naming a service tag; the host authorizes the
//! request against the **dial capability** of the *transport-authenticated* peer
//! (ADR-011 surfaced the peer identity; [`crate::tunnel::authz`] decides), resolves
//! the service to a local endpoint, replies [`TunnelStatus`], and then both sides
//! splice bytes between the QUIC stream and the local TCP socket.
//!
//! ## Dark services / default-deny
//! The host's resolver returns [`Error::TunnelDenied`] for any service the peer is
//! not authorized to Dial *or that does not exist* — the two are indistinguishable
//! on the wire (the same `Denied` status, no detail), so an unauthorized peer
//! cannot even confirm a service exists. The host connects to a local target only
//! **after** authorization succeeds; there is no open listening port reachable by
//! topology.

use std::net::SocketAddr;

use quinn::{RecvStream, SendStream};
use tokio::net::TcpStream;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::evaluator::Evaluator;
use crate::hash::Digest32;
use std::sync::Arc;

use crate::tunnel::authz::authorize_dial;

/// Maximum length of a service tag carried in a tunnel request (matches the
/// capability-token bound; rejects an oversized field before allocation).
pub const MAX_SERVICE_TAG_LEN: usize = 256;

/// Maximum length of a length-delimited tunnel control frame on the stream.
const MAX_CONTROL_FRAME: usize = 4 + MAX_SERVICE_TAG_LEN + 64;

/// The dialer's opening request on a fresh tunnel stream: **which channel's
/// authorization applies**, and which service to reach.
///
/// The channelID is not decoration. A QUIC connection is per *peer*, not per channel
/// (ADR-016), and authorization lives in a channel's ADR-007 evaluator — so a host
/// that was told only a service tag could not know which evaluator to ask, and two
/// members who share several channels would be ambiguous. The dialer names the
/// channel it claims the capability under, and the host checks that claim against
/// that channel's evaluator or refuses uniformly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelRequest {
    /// The channel whose evaluator authorizes this dial.
    pub channel_id: Digest32,
    /// The service tag to Dial (the `<tag>` of `dial:<tag>`), e.g. `"ssh-hosts"`.
    pub service_tag: String,
}

impl TunnelRequest {
    /// Canonical CBOR: `[channel_id, service_tag]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).bytes(&self.channel_id).text(&self.service_tag);
        e.finish()
    }

    /// Strictly decode a request (rejects wrong arity, a channelID that is not 32
    /// bytes, an oversized tag, trailing bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 2 {
            return Err(Error::MalformedTunnel("tunnel request arity"));
        }
        let channel_id: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedTunnel("tunnel request channelID"))?;
        let service_tag = d.text()?.to_owned();
        d.finish()
            .map_err(|_| Error::MalformedTunnel("tunnel request trailing bytes"))?;
        if service_tag.is_empty() || service_tag.len() > MAX_SERVICE_TAG_LEN {
            return Err(Error::MalformedTunnel("tunnel request tag length"));
        }
        Ok(Self {
            channel_id,
            service_tag,
        })
    }
}

/// The host's reply to a [`TunnelRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelStatus {
    /// The request is authorized and the host has connected the local endpoint;
    /// byte splicing follows.
    Accepted,
    /// The request is refused — unauthorized *or* no such service (deliberately
    /// indistinguishable, ADR-013 dark services).
    Denied,
}

impl TunnelStatus {
    fn as_byte(self) -> u8 {
        match self {
            TunnelStatus::Accepted => 1,
            TunnelStatus::Denied => 0,
        }
    }
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            1 => Ok(TunnelStatus::Accepted),
            0 => Ok(TunnelStatus::Denied),
            _ => Err(Error::MalformedTunnel("tunnel status byte")),
        }
    }
}

/// Write a length-delimited control frame (`u32` BE length ‖ body).
async fn write_frame(send: &mut SendStream, body: &[u8]) -> Result<()> {
    let len =
        u32::try_from(body.len()).map_err(|_| Error::MalformedTunnel("control frame too long"))?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|_| Error::MalformedTunnel("tunnel control write len"))?;
    send.write_all(body)
        .await
        .map_err(|_| Error::MalformedTunnel("tunnel control write body"))?;
    Ok(())
}

/// Read a length-delimited control frame, bounding the declared length.
async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|_| Error::MalformedTunnel("tunnel control read len"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_CONTROL_FRAME {
        return Err(Error::MalformedTunnel("tunnel control frame too long"));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|_| Error::MalformedTunnel("tunnel control read body"))?;
    Ok(body)
}

/// Dialer side: open a tunnel for `service_tag` on an already-opened QUIC stream
/// pair, then splice the local `local` TCP socket to it.
///
/// Sends the request, awaits the host's status, and on [`TunnelStatus::Accepted`]
/// splices bytes until either side closes. A [`TunnelStatus::Denied`] (or any other
/// status) returns [`Error::TunnelDenied`] without exposing whether the service
/// exists.
pub async fn dial(
    mut send: SendStream,
    mut recv: RecvStream,
    channel_id: &Digest32,
    service_tag: &str,
    local: TcpStream,
) -> Result<()> {
    let req = TunnelRequest {
        channel_id: *channel_id,
        service_tag: service_tag.to_owned(),
    };
    write_frame(&mut send, &req.to_bytes()).await?;
    let status_frame = read_frame(&mut recv).await?;
    if status_frame.len() != 1
        || TunnelStatus::from_byte(status_frame[0])? != TunnelStatus::Accepted
    {
        return Err(Error::TunnelDenied("dial refused"));
    }
    splice(send, recv, local).await
}

/// What the host knows about one `(channel, service)` pair a dialer named: the
/// channel's ADR-007 evaluator — the authority that decides — and where the service
/// lives locally. Returning one of these says only "I hold that channel and offer
/// that service"; whether the *peer* may reach it is still
/// [`accept`]'s to enforce.
pub struct HostService {
    /// The named channel's governance evaluator.
    pub evaluator: Arc<Evaluator>,
    /// The local address the service listens on.
    pub endpoint: SocketAddr,
}

/// Host side: accept a tunnel on a fresh inbound stream pair, **enforcing the Dial
/// capability** of the transport-authenticated peer before any local connection.
///
/// `client_id` is the composite-identity fingerprint the QUIC transport
/// authenticated for this connection (`VoxConnection::peer_id`, ADR-011). The host:
/// 1. reads the [`TunnelRequest`];
/// 2. asks `resolve` about the `(channel, service_tag)` it named — pure host
///    configuration: `Some(HostService)` if this node holds that channel and offers
///    that service, `None` otherwise, and *no* authorization logic;
/// 3. enforces `dial:<service_tag>` for `client_id` against **that channel's**
///    evaluator via [`authorize_dial`] — the authorization gate lives here, not in
///    the caller, so a misconfigured resolver cannot grant reach;
/// 4. connects the local endpoint and splices bytes.
///
/// The evaluator comes from the resolver rather than the caller because a QUIC
/// connection is per peer, not per channel: which authority applies is known only
/// once the request has been read (ADR-013 Implementation notes).
///
/// Steps 2 and 3 both fail to a **uniform** [`TunnelStatus::Denied`] (and
/// [`Error::TunnelDenied`]) — unauthorized, unknown channel, unknown service and
/// connect-failed are indistinguishable on the wire (dark services, default-deny).
/// The local connect happens only after authorization succeeds.
pub async fn accept<F>(
    mut send: SendStream,
    mut recv: RecvStream,
    client_id: &Digest32,
    resolve: F,
) -> Result<()>
where
    F: FnOnce(&Digest32, &str) -> Option<HostService>,
{
    let req = TunnelRequest::from_bytes(&read_frame(&mut recv).await?)?;

    // (2) Resolution is pure host config, asked about the channel the dialer named,
    //     so a service offered in one channel is not reachable by a capability
    //     granted in another. (3) Authorization is enforced here, against the
    //     authenticated peer and that channel's authority. Both denials are uniform.
    let decision = resolve(&req.channel_id, &req.service_tag).and_then(|h| {
        authorize_dial(&h.evaluator, client_id, &req.service_tag)
            .ok()
            .map(|()| h.endpoint)
    });
    let Some(target) = decision else {
        // Finish the stream so the status reaches the dialer before we drop it.
        write_frame(&mut send, &[TunnelStatus::Denied.as_byte()]).await?;
        let _ = send.finish();
        return Err(Error::TunnelDenied("service unauthorized or unknown"));
    };

    let tcp = match TcpStream::connect(target).await {
        Ok(t) => t,
        Err(_) => {
            write_frame(&mut send, &[TunnelStatus::Denied.as_byte()]).await?;
            let _ = send.finish();
            return Err(Error::TunnelDenied("local service connect failed"));
        }
    };
    write_frame(&mut send, &[TunnelStatus::Accepted.as_byte()]).await?;
    splice(send, recv, tcp).await
}

/// Splice bytes bidirectionally between a QUIC stream pair and a TCP socket until
/// **both** directions close.
///
/// The QUIC `(recv, send)` pair is adapted into one duplex via [`tokio::io::join`],
/// then [`tokio::io::copy_bidirectional`] handles half-close propagation correctly:
/// when one side reaches EOF it shuts down the opposite writer (a quinn `finish`
/// or a TCP FIN) and drains the other direction before returning, so neither a
/// one-way close nor an idle reverse path leaks the tunnel.
async fn splice(send: SendStream, recv: RecvStream, mut tcp: TcpStream) -> Result<()> {
    let mut quic = tokio::io::join(recv, send);
    tokio::io::copy_bidirectional(&mut tcp, &mut quic)
        .await
        .map_err(|_| Error::MalformedTunnel("tunnel splice"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_and_rejects_bad() {
        let r = TunnelRequest {
            channel_id: [0x5A; 32],
            service_tag: "ssh-hosts".to_owned(),
        };
        assert_eq!(TunnelRequest::from_bytes(&r.to_bytes()).unwrap(), r);
        // Empty tag rejected.
        let mut e = Encoder::new();
        e.array(2).bytes(&[0x5A; 32]).text("");
        assert!(matches!(
            TunnelRequest::from_bytes(&e.finish()),
            Err(Error::MalformedTunnel(_))
        ));
        // A channelID that is not 32 bytes is not a channelID.
        let mut e = Encoder::new();
        e.array(2).bytes(&[0x5A; 31]).text("ssh");
        assert!(matches!(
            TunnelRequest::from_bytes(&e.finish()),
            Err(Error::MalformedTunnel("tunnel request channelID"))
        ));
        // Wrong arity rejected, either way.
        let mut e2 = Encoder::new();
        e2.array(1).text("a");
        assert!(TunnelRequest::from_bytes(&e2.finish()).is_err());
        let mut e3 = Encoder::new();
        e3.array(3).bytes(&[0x5A; 32]).text("a").text("b");
        assert!(TunnelRequest::from_bytes(&e3.finish()).is_err());
        // Trailing bytes rejected.
        let mut bytes = r.to_bytes();
        bytes.push(0);
        assert!(TunnelRequest::from_bytes(&bytes).is_err());
    }

    #[test]
    fn status_byte_round_trips() {
        assert_eq!(
            TunnelStatus::from_byte(TunnelStatus::Accepted.as_byte()).unwrap(),
            TunnelStatus::Accepted
        );
        assert_eq!(
            TunnelStatus::from_byte(TunnelStatus::Denied.as_byte()).unwrap(),
            TunnelStatus::Denied
        );
        assert!(TunnelStatus::from_byte(7).is_err());
    }

    // --- End-to-end: real TCP carried over a real QUIC tunnel (loopback) ---
    use crate::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
    use crate::identity::composite::SoftwareRootSigner;
    use crate::transport::quic::VoxEndpoint;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::runtime::Runtime;

    fn policy() -> ChannelPolicy {
        ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: crate::suite::SuiteFloor::DAY_ONE.id(),
        }
    }

    /// An evaluator whose root admin is `admin` (admin covers every Dial), built
    /// from a genesis-only channel.
    /// An evaluator over a channel `admin` created, with that channel's id — which
    /// the dialer must name and the host must check (a connection is per peer, not
    /// per channel).
    fn evaluator_with_admin(admin: &SoftwareRootSigner) -> (Arc<Evaluator>, Digest32) {
        let genesis = Genesis::create_with_nonce(admin, 0, policy(), [0x55; 16]).unwrap();
        let cid = genesis.channel_id();
        (
            Arc::new(Evaluator::build(&genesis, &[], 1000, |_| None).unwrap()),
            cid,
        )
    }

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn loopback() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    /// A trivial TCP echo server; returns its address. Echoes one connection.
    async fn spawn_echo() -> SocketAddr {
        let l = TcpListener::bind(loopback()).await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });
        addr
    }

    #[test]
    fn real_tcp_echoes_through_the_quic_tunnel() {
        let rt = rt();
        rt.block_on(async {
            let echo_addr = spawn_echo().await;

            // The client identity is the channel's root admin, so it holds Dial for
            // every service via the ADR-007 lattice.
            let client_signer = signer(3, 4);
            let (evaluator, channel_id) = evaluator_with_admin(&client_signer);

            // Host QUIC endpoint with a one-shot accept that serves a tunnel to the
            // echo service, enforcing Dial for the authenticated peer.
            let host_signer = signer(1, 2);
            let host = VoxEndpoint::bind(&host_signer, loopback()).unwrap();
            let host_addr = host.local_addr().unwrap();
            let host_id = host.local_id();
            tokio::spawn(async move {
                if let Ok(Some(conn)) = host.accept(1000).await {
                    let client_id = conn.peer_id(); // transport-authenticated peer
                    if let Ok((send, recv)) = conn.accept_stream().await {
                        // Resolver is pure config: this host offers "echo".
                        let _ = accept(send, recv, &client_id, |cid, tag| {
                            (*cid == channel_id && tag == "echo").then_some(HostService {
                                evaluator: Arc::clone(&evaluator),
                                endpoint: echo_addr,
                            })
                        })
                        .await;
                    }
                }
            });

            // Client: a local listener stands in for the forwarded local port; an
            // app connects to it and its bytes are spliced through the tunnel.
            let app_listener = TcpListener::bind(loopback()).await.unwrap();
            let app_addr = app_listener.local_addr().unwrap();

            let client = VoxEndpoint::bind(&client_signer, loopback()).unwrap();
            let conn = tokio::time::timeout(
                Duration::from_secs(10),
                client.connect(host_addr, host_id, 1000),
            )
            .await
            .expect("dial did not hang")
            .expect("client connects to host");
            let (send, recv) = conn.open_stream().await.unwrap();

            // Accept the app-side socket and drive the dialer splice.
            tokio::spawn(async move {
                if let Ok((app_sock, _)) = app_listener.accept().await {
                    let _ = dial(send, recv, &channel_id, "echo", app_sock).await;
                }
            });

            // The "application": connect to the local forward, send, expect echo.
            let mut app = TcpStream::connect(app_addr).await.unwrap();
            app.write_all(b"hello-vox-tunnel").await.unwrap();
            let mut buf = [0u8; 16];
            tokio::time::timeout(Duration::from_secs(10), app.read_exact(&mut buf))
                .await
                .expect("echo did not hang")
                .expect("reads the echoed bytes");
            assert_eq!(&buf, b"hello-vox-tunnel");
        });
    }

    #[test]
    fn dial_is_refused_when_peer_lacks_capability() {
        let rt = rt();
        rt.block_on(async {
            // The channel admin is a THIRD party; the connecting client is a
            // stranger holding no `dial:` capability → authorization denies even
            // though the host offers the service.
            let admin = signer(9, 9);
            let (evaluator, channel_id) = evaluator_with_admin(&admin);

            let host_signer = signer(5, 6);
            let host = VoxEndpoint::bind(&host_signer, loopback()).unwrap();
            let host_addr = host.local_addr().unwrap();
            let host_id = host.local_id();
            tokio::spawn(async move {
                if let Ok(Some(conn)) = host.accept(1000).await {
                    let client_id = conn.peer_id();
                    if let Ok((send, recv)) = conn.accept_stream().await {
                        // Host *offers* "echo", but the peer is unauthorized.
                        let _ = accept(send, recv, &client_id, |cid, tag| {
                            (*cid == channel_id && tag == "echo").then_some(HostService {
                                evaluator: Arc::clone(&evaluator),
                                endpoint: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)),
                            })
                        })
                        .await;
                    }
                    // Hold the connection so the Denied status is delivered.
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    drop(conn);
                }
            });

            let client_signer = signer(7, 8);
            let client = VoxEndpoint::bind(&client_signer, loopback()).unwrap();
            let conn = tokio::time::timeout(
                Duration::from_secs(10),
                client.connect(host_addr, host_id, 1000),
            )
            .await
            .expect("dial did not hang")
            .expect("connect");
            let (send, recv) = conn.open_stream().await.unwrap();
            // No local socket needed: a closed TcpStream is fine since we expect
            // refusal before any splice. Use a connected pair to satisfy the type.
            let l = TcpListener::bind(loopback()).await.unwrap();
            let la = l.local_addr().unwrap();
            tokio::spawn(async move {
                let _ = l.accept().await;
            });
            let app = TcpStream::connect(la).await.unwrap();
            let res = tokio::time::timeout(
                Duration::from_secs(10),
                dial(send, recv, &channel_id, "echo", app),
            )
            .await
            .expect("did not hang");
            assert!(matches!(res, Err(Error::TunnelDenied(_))));
        });
    }
}
