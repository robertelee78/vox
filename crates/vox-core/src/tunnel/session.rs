//! The per-stream tunnel data path (ADR-013 §"Mapping onto QUIC"): one QUIC stream
//! carries one tunneled TCP connection (ordered, reliable), isolated from messaging
//! and bulk-sync streams so interactive tunnels never suffer cross-stream
//! head-of-line blocking.
//!
//! This is the **primary**, ssh-style port-forward model. A dialer opens a stream
//! and sends a [`TunnelRequest`] naming a service tag; the host authorizes the
//! *transport-authenticated* peer (ADR-011 surfaced the peer identity) against its own
//! live reacher set — its trust keyring intersected with the room's authors (ADR-017
//! decision 3) — resolves the service to a local endpoint, replies [`TunnelStatus`],
//! and then both sides splice bytes between the QUIC stream and the local TCP socket.
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
use crate::hash::Digest32;

/// Maximum length of a service tag carried in a tunnel request (matches the
/// capability-token bound; rejects an oversized field before allocation).
pub const MAX_SERVICE_TAG_LEN: usize = 256;

/// Maximum length of a length-delimited tunnel control frame on the stream.
const MAX_CONTROL_FRAME: usize = 4 + MAX_SERVICE_TAG_LEN + 64;

/// The dialer's opening request on a fresh tunnel stream: **which channel's
/// authorization applies**, and which service to reach.
///
/// The channelID is not decoration. A QUIC connection is per *peer*, not per channel
/// (ADR-016), and a service is offered in, and reached through, one channel — so a host
/// that was told only a service tag could not know which channel's reacher set to ask,
/// and two members who share several channels would be ambiguous. The dialer names the
/// channel, and the host checks the dialer against that channel's reachers or refuses
/// uniformly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelRequest {
    /// The channel whose reacher set decides this dial.
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
/// [`request`] then [`splice`].
pub async fn dial(
    mut send: SendStream,
    mut recv: RecvStream,
    channel_id: &Digest32,
    service_tag: &str,
    local: TcpStream,
) -> Result<()> {
    request(&mut send, &mut recv, channel_id, service_tag).await?;
    splice(send, recv, local).await
}

/// Dialer side, first half: send the [`TunnelRequest`] and wait for the host's verdict.
///
/// `Ok(())` means the host authorized the request **and** connected its local endpoint, so
/// the stream is ready to [`splice`]. [`Error::TunnelDenied`] is the host's refusal —
/// uniform, so it does not say whether the service exists (ADR-013 dark services). Any
/// other error is the path failing before the host answered, which a caller may retry on
/// a fresh connection; a refusal it must not, because the host has decided.
///
/// Split out of [`dial`] so a caller can tell the host's verdict from the path failing:
/// a forward that retries a dead connection on a fresh one must never retry a refusal.
pub async fn request(
    send: &mut SendStream,
    recv: &mut RecvStream,
    channel_id: &Digest32,
    service_tag: &str,
) -> Result<()> {
    let req = TunnelRequest {
        channel_id: *channel_id,
        service_tag: service_tag.to_owned(),
    };
    write_frame(send, &req.to_bytes()).await?;
    let status_frame = read_frame(recv).await?;
    if status_frame.len() != 1
        || TunnelStatus::from_byte(status_frame[0])? != TunnelStatus::Accepted
    {
        return Err(Error::TunnelDenied("dial refused"));
    }
    Ok(())
}

/// What the host knows about one `(channel, service)` pair a dialer named: where the
/// service lives locally, and who may reach it. Returning one of these says only "I
/// hold that channel and offer that service"; whether the *peer* may reach it is still
/// [`accept`]'s to enforce.
pub struct HostService {
    /// The local address the service listens on.
    pub endpoint: SocketAddr,
    /// The identities this host has decided may reach it: its **trust keyring** entries
    /// that are also **current authors of this room** (ADR-017 decision 3, M17.7).
    ///
    /// A set rather than a predicate because the actor owns both inputs — the node-wide
    /// ring and the channel's author table — and the serving task must not reach back
    /// into the actor to ask. It is rebuilt per accept from the host snapshot, so it is
    /// current rather than cached across a decision.
    ///
    /// Why not the log's consent set: `readers_of(host)` records signed consent *edges*
    /// and checks neither current room membership nor current ring membership, so a grant
    /// from epoch 0 still appears after an authorized rotation to epoch 1. Keying on the
    /// ring — which is local, current, and the host's own decision — means the epoch
    /// question never reaches this gate at all. Found by review before any code.
    pub reachers: crate::node::tunnel::Reachers,
}

/// Host side: accept a tunnel on a fresh inbound stream pair, **enforcing the host's
/// reach decision** about the transport-authenticated peer before any local connection.
///
/// `client_id` is the composite-identity fingerprint the QUIC transport
/// authenticated for this connection (`VoxConnection::peer_id`, ADR-011). The host:
/// 1. reads the [`TunnelRequest`];
/// 2. asks `resolve` about the `(channel, service_tag)` it named — pure host
///    configuration: `Some(HostService)` if this node holds that channel and offers
///    that service, `None` otherwise, and *no* authorization logic;
/// 3. checks `client_id` against that channel's **live reacher set** — the host's own
///    trust keyring intersected with the room's current author set (ADR-017 decision 3,
///    M17.7). The gate lives here, not in the caller, so a misconfigured resolver
///    cannot grant reach;
/// 4. connects the local endpoint and splices bytes, leaving the moment `client_id`
///    stops being a reacher (M17.11).
///
/// `service_tag` is **not** an authorization input. It was, as `dial:<tag>` against the
/// channel's evaluator, but that capability came from a genesis grant conferred on every
/// admitted member — which made joining the authorization, and was the vulnerability.
/// Reach is per (host, room): every service a host bound to a room goes to the same set.
///
/// Which channel's set applies comes from the resolver rather than the caller because a
/// QUIC connection is per peer, not per channel: the authority is known only once the
/// request has been read (ADR-013 Implementation notes).
///
/// Steps 2 and 3 both fail to a **uniform** [`TunnelStatus::Denied`] (and
/// [`Error::TunnelDenied`]) — unauthorized, unknown channel, unknown service and
/// connect-failed are indistinguishable on the wire (dark services, default-deny).
/// The local connect happens only after authorization succeeds.
pub async fn accept<F>(
    send: SendStream,
    recv: RecvStream,
    client_id: &Digest32,
    resolve: F,
) -> Result<()>
where
    F: FnOnce(&Digest32, &str) -> Option<HostService>,
{
    accept_reporting(send, recv, client_id, resolve, |_, _| {}).await
}

/// [`accept`], reporting each authorized request to `served` before the local connect.
///
/// The host needs this because the carried service cannot tell its Vox clients apart:
/// they all arrive from loopback, so `sshd`'s log says `127.0.0.1` and nothing else
/// (ADR-017 decision 6). The identity is right here — transport-authenticated and
/// checked against the room's reacher set — so this is where it can be surfaced.
///
/// `served` is called **only after authorization succeeds**, so it reports grants and
/// never attempts; a denial is silent to it, exactly as it is to the dialer. It runs
/// inside the accept path, so it must not block: the intended use is to hand an event
/// to a queue. It is informational for a live client, *not* an audit log — a durable,
/// signed record of session establishment is ADR-013's own open item.
pub async fn accept_reporting<F, S>(
    mut send: SendStream,
    mut recv: RecvStream,
    client_id: &Digest32,
    resolve: F,
    served: S,
) -> Result<()>
where
    F: FnOnce(&Digest32, &str) -> Option<HostService>,
    S: FnOnce(&Digest32, &str),
{
    let req = TunnelRequest::from_bytes(&read_frame(&mut recv).await?)?;

    // (2) Resolution is pure host config, asked about the channel the dialer named, so a
    //     service offered in one channel is not reachable through another. (3)
    //     Authorization is enforced here, against the transport-authenticated peer.
    //
    // **The gate is the host's own decision about that identity** (ADR-017 decision 3,
    // M17.7): is this client in the host's trust keyring, and a current author of the room
    // the service is bound to. Both conditions, neither sufficient alone — trust is
    // room-independent so it cannot name the room, and room membership is a passphrase and
    // a proof of work so it is not a decision about a person.
    //
    // It is no longer the capability lattice. `dial:<tag>` came from a genesis grant
    // conferred on every admitted member, which made joining the authorization; that is
    // the withdrawn model and the vulnerability. `service_tag` is therefore no longer an
    // authorization input at all — reach is per (host, room), so every service a host
    // bound to a room goes to the same set.
    // Read **after** the request, from the live set, so a stream parked open across a
    // withdrawal of trust is judged by the decision that holds now, not by one taken when
    // the stream opened (M17.11).
    let host = resolve(&req.channel_id, &req.service_tag)
        .filter(|h| h.reachers.borrow().contains(client_id));
    let Some(HostService {
        endpoint: target,
        reachers,
        ..
    }) = host
    else {
        // Finish the stream so the status reaches the dialer before we drop it.
        write_frame(&mut send, &[TunnelStatus::Denied.as_byte()]).await?;
        let _ = send.finish();
        return Err(Error::TunnelDenied("service unauthorized or unknown"));
    };
    // Authorized, and not before: the host learns who reached what, and learns nothing
    // about a refusal it did not grant.
    served(&req.channel_id, &req.service_tag);

    let tcp = match TcpStream::connect(target).await {
        Ok(t) => t,
        Err(_) => {
            write_frame(&mut send, &[TunnelStatus::Denied.as_byte()]).await?;
            let _ = send.finish();
            return Err(Error::TunnelDenied("local service connect failed"));
        }
    };
    write_frame(&mut send, &[TunnelStatus::Accepted.as_byte()]).await?;
    splice_until_withdrawn(send, recv, tcp, &reachers, client_id).await
}

/// The QUIC application error code a host resets a tunnel stream with when it withdraws
/// the dialer's reach mid-session (ADR-017 M17.11).
///
/// A code rather than an in-band message: once splicing starts the stream carries the
/// carried protocol's own bytes, so anything Vox wrote into it would corrupt them. QUIC's
/// reset code is the one channel that stays ours.
pub const REACH_WITHDRAWN_CODE: u32 = 0x1711;

/// Splice, but stop the moment `client_id` leaves `reachers`.
///
/// Withdrawing reach has to reach sessions that are **already running** — an `ssh` login
/// opened an hour ago is precisely what the operator means to cut — and the serving task
/// cannot ask the actor, so it watches the same live set the dial gate read.
async fn splice_until_withdrawn(
    send: SendStream,
    recv: RecvStream,
    tcp: TcpStream,
    reachers: &crate::node::tunnel::Reachers,
    client_id: &Digest32,
) -> Result<()> {
    let mut changed = reachers.subscribe();
    let mut quic = tokio::io::join(recv, send);
    let mut tcp = tcp;
    let outcome = {
        let copying = tokio::io::copy_bidirectional(&mut tcp, &mut quic);
        tokio::pin!(copying);
        loop {
            tokio::select! {
                done = &mut copying => break done
                    .map(|_| ())
                    .map_err(|_| Error::MalformedTunnel("tunnel splice")),
                res = changed.changed() => {
                    // The sender lives in the actor's map. If it is gone the channel is
                    // gone, and a channel this node no longer holds reaches nothing.
                    let still = res.is_ok() && reachers.borrow().contains(client_id);
                    if !still {
                        break Err(Error::TunnelRevoked("withdrawn mid-session"));
                    }
                }
            }
        }
    };
    if matches!(outcome, Err(Error::TunnelRevoked(_))) {
        // Reset rather than finish: a clean close is indistinguishable from the carried
        // service hanging up, and the dialer deserves to know this was a decision.
        let (_recv, mut send) = quic.into_inner();
        let _ = send.reset(quinn::VarInt::from_u32(REACH_WITHDRAWN_CODE));
    }
    outcome
}

/// Splice bytes bidirectionally between a QUIC stream pair and a TCP socket until
/// **both** directions close.
///
/// The QUIC `(recv, send)` pair is adapted into one duplex via [`tokio::io::join`],
/// then [`tokio::io::copy_bidirectional`] handles half-close propagation correctly:
/// when one side reaches EOF it shuts down the opposite writer (a quinn `finish`
/// or a TCP FIN) and drains the other direction before returning, so neither a
/// one-way close nor an idle reverse path leaks the tunnel.
pub async fn splice(send: SendStream, recv: RecvStream, mut tcp: TcpStream) -> Result<()> {
    let mut quic = tokio::io::join(recv, send);
    match tokio::io::copy_bidirectional(&mut tcp, &mut quic).await {
        Ok(_) => Ok(()),
        Err(e) if reset_reason(&e) == Some(REACH_WITHDRAWN_CODE) => Err(Error::TunnelRevoked(
            "the host withdrew access to this service",
        )),
        Err(_) => Err(Error::MalformedTunnel("tunnel splice")),
    }
}

/// The QUIC application error code a peer reset this stream with, if that is why the read
/// failed.
///
/// quinn reports a reset by wrapping [`quinn::ReadError`] in an [`std::io::Error`], so the
/// code survives the `AsyncRead` adapter but only behind a downcast. Any other failure —
/// a lost connection, a closed socket — returns `None` and stays a generic splice error,
/// which is the honest reading: those are not decisions anybody took.
fn reset_reason(e: &std::io::Error) -> Option<u32> {
    let read = e.get_ref()?.downcast_ref::<quinn::ReadError>()?;
    match read {
        quinn::ReadError::Reset(code) => u32::try_from(code.into_inner()).ok(),
        _ => None,
    }
}
