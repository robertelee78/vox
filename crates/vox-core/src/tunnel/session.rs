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

use noq::{RecvStream, SendStream};
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
/// [`request`] then [`splice`]. A caller that owes somebody an answer *before* bytes flow
/// — a SOCKS client waiting for its reply — calls the two halves itself, so that the
/// answer it gives is the host's.
pub async fn dial(
    mut send: SendStream,
    mut recv: RecvStream,
    channel_id: &Digest32,
    service_tag: &str,
    local: TcpStream,
) -> Result<()> {
    if let Err(e) = request(&mut send, &mut recv, channel_id, service_tag).await {
        abort_local(&local);
        return Err(e);
    }
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
/// Split out of [`dial`] because `vox up` used to tell its SOCKS client "succeeded"
/// **before** asking, on the belief that the host waited for the client's first bytes and
/// so a reply held back until the host answered would deadlock against `ssh`, which sends
/// nothing until it is told the connection is up. The host does no such thing: [`accept`]
/// writes its status straight after its own local connect. So every refused CONNECT looked
/// connected and then died, and nothing a person saw said it had been refused (PRD-001 R23).
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
    /// The services this host offers in the channel, live. A session ends the moment its
    /// service leaves this map (PRD-001 R22), exactly as it ends when its dialer leaves
    /// `reachers`.
    pub offered: crate::node::tunnel::Offered,
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
///    stops being a reacher (M17.11) or the service stops being offered (PRD-001 R22).
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
        offered,
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
    let cut = withdrawn(reachers, offered, *client_id, req.service_tag);
    splice_until(send, recv, tcp, cut).await
}

/// The QUIC application error code a host resets a tunnel stream with when it withdraws
/// the dialer's reach mid-session (ADR-017 M17.11) — by untrusting the dialer, or by no
/// longer offering the service (PRD-001 R22).
///
/// A code rather than an in-band message: once splicing starts the stream carries the
/// carried protocol's own bytes, so anything Vox wrote into it would corrupt them. QUIC's
/// reset code is the one channel that stays ours.
pub const REACH_WITHDRAWN_CODE: u32 = 0x1711;

/// The QUIC application error code either end resets a tunnel stream with when **its own
/// TCP side ended abortively** — the carried connection was reset, or could no longer be
/// written — so the far end resets its TCP side too (PRD-001 R22/R23).
///
/// Distinct from a clean close because a clean close is a statement: "everything was
/// sent". A backend that crashes mid-response and resets its socket has said the opposite,
/// and a tunnel that turns that into an orderly EOF hands the client a truncated reply that
/// looks complete. That is what quinn does to a `SendStream` dropped on an error path — it
/// finishes it — so the reset has to be explicit.
pub const TUNNEL_ABORT_CODE: u32 = 0x1712;

/// Resolves when `client` may no longer reach `tag`: it has left the host's reacher set,
/// or the host has stopped offering the service.
///
/// Withdrawing reach has to reach sessions that are **already running** — an `ssh` login
/// opened an hour ago is precisely what the operator means to cut — and the serving task
/// cannot ask the actor, so it watches the same live sets the dial gate read. Removing a
/// service is the same decision made about a port rather than a person, and used to cut
/// nothing: the offer went, and every session already carried on it stayed up (R22).
async fn withdrawn(
    reachers: crate::node::tunnel::Reachers,
    offered: crate::node::tunnel::Offered,
    client: Digest32,
    tag: String,
) {
    let mut who = reachers.subscribe();
    let mut what = offered.subscribe();
    loop {
        if !reachers.borrow().contains(&client) || !offered.borrow().contains_key(&tag) {
            return;
        }
        // The senders are held by the actor's maps *and* by this task, so a `changed`
        // error would mean neither exists any more; treat it as withdrawn rather than spin.
        tokio::select! {
            res = who.changed() => if res.is_err() { return },
            res = what.changed() => if res.is_err() { return },
        }
    }
}

/// Splice bytes bidirectionally between a QUIC stream pair and a TCP socket until
/// **both** directions close, carrying an **abortive** close as one (PRD-001 R22/R23).
///
/// A clean half-close is carried as one: TCP EOF becomes a QUIC `finish`, a QUIC finish
/// becomes a TCP FIN, and the other direction drains on. An abortive end on either side —
/// the local TCP connection reset or unwritable, or the far end resetting the stream —
/// tears down **both** directions: the stream is reset with [`TUNNEL_ABORT_CODE`], and the
/// local TCP socket is closed with a zero linger, which the kernel sends as an RST. So a
/// backend that resets reaches the far client as a reset, not as a clean EOF after a
/// truncated reply.
pub async fn splice(send: SendStream, recv: RecvStream, tcp: TcpStream) -> Result<()> {
    splice_until(send, recv, tcp, std::future::pending()).await
}

/// Write every byte of `chunks` to `w`, vectored, carrying a partial write over correctly.
async fn write_all_chunks<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    chunks: &mut [bytes::Bytes],
) -> std::io::Result<()> {
    use bytes::Buf as _;
    use tokio::io::AsyncWriteExt as _;
    let mut first = 0;
    while first < chunks.len() {
        if chunks[first].is_empty() {
            first += 1;
            continue;
        }
        let slices: Vec<std::io::IoSlice<'_>> = chunks[first..]
            .iter()
            .map(|c| std::io::IoSlice::new(c))
            .collect();
        let mut written = w.write_vectored(&slices).await?;
        drop(slices);
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        while written > 0 {
            let take = written.min(chunks[first].len());
            chunks[first].advance(take);
            written -= take;
            if chunks[first].is_empty() {
                first += 1;
            }
        }
    }
    Ok(())
}

/// How one direction of a splice ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leg {
    /// An orderly end of this direction; the other one carries on.
    Clean,
    /// This side of the carried connection ended abortively.
    Abort,
    /// The host reset the stream with [`REACH_WITHDRAWN_CODE`].
    Withdrawn,
}

/// [`splice`], ending early — and abortively, with [`REACH_WITHDRAWN_CODE`] — when `cut`
/// resolves.
async fn splice_until(
    mut send: SendStream,
    mut recv: RecvStream,
    mut tcp: TcpStream,
    cut: impl core::future::Future<Output = ()>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    // **Large chunks, handed over without a copy.** Every write to a QUIC send stream takes the
    // connection's lock, which the connection driver holds while it builds and sends packets.
    // Profiled on the shipped binary (a 2 GB transfer through `vox forward`), the sending node
    // spent most of its time waiting on that lock from `SendStream::write_all`, once per 16 KiB.
    // Reading the TCP side into a buffer and handing it to QUIC whole (`write_chunk`, which
    // takes ownership rather than copying) takes the lock once per chunk; the inbound side reads
    // QUIC's own buffers (`read_chunk`) instead of copying them into ours first.
    const CHUNK: usize = 256 * 1024;
    let outcome = {
        let (mut tcp_r, mut tcp_w) = tcp.split();
        let (send, recv) = (&mut send, &mut recv);
        // TCP → QUIC.
        let outbound = async move {
            let mut buf = bytes::BytesMut::with_capacity(CHUNK);
            loop {
                if buf.capacity() < CHUNK / 2 {
                    buf.reserve(CHUNK);
                }
                match tcp_r.read_buf(&mut buf).await {
                    Ok(0) => {
                        let _ = send.finish();
                        return Leg::Clean;
                    }
                    Ok(_) => {
                        // Take whatever else is already waiting on the socket, without waiting
                        // for more, so one chunk (one stream lock) carries a burst, not a
                        // single read's worth of it.
                        let mut eof = false;
                        while buf.len() < CHUNK {
                            match tcp_r.try_read_buf(&mut buf) {
                                Ok(0) => {
                                    eof = true;
                                    break;
                                }
                                Ok(_) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(_) => return Leg::Abort,
                            }
                        }
                        if send.write_chunk(buf.split().freeze()).await.is_err() {
                            return Leg::Abort;
                        }
                        if eof {
                            let _ = send.finish();
                            return Leg::Clean;
                        }
                    }
                    Err(_) => return Leg::Abort,
                }
            }
        };
        // QUIC → TCP.
        let inbound = async move {
            // Several of QUIC's buffers at once, written to TCP in one vectored write where the
            // socket takes them: one stream lock and, usually, one syscall per batch.
            let mut chunks: [bytes::Bytes; 16] = Default::default();
            loop {
                match recv.read_many_chunks(&mut chunks).await {
                    Ok(None) => {
                        let _ = tcp_w.shutdown().await;
                        return Leg::Clean;
                    }
                    Ok(Some(n)) => {
                        if write_all_chunks(&mut tcp_w, &mut chunks[..n])
                            .await
                            .is_err()
                        {
                            return Leg::Abort;
                        }
                    }
                    Err(noq::ReadError::Reset(code))
                        if code == noq::VarInt::from_u32(REACH_WITHDRAWN_CODE) =>
                    {
                        return Leg::Withdrawn
                    }
                    Err(_) => return Leg::Abort,
                }
            }
        };
        tokio::pin!(outbound, inbound, cut);
        let (mut out_done, mut in_done) = (false, false);
        loop {
            tokio::select! {
                leg = &mut outbound, if !out_done => match leg {
                    Leg::Clean => out_done = true,
                    other => break Some(other),
                },
                leg = &mut inbound, if !in_done => match leg {
                    Leg::Clean => in_done = true,
                    other => break Some(other),
                },
                () = &mut cut => break None,
            }
            if out_done && in_done {
                break Some(Leg::Clean);
            }
        }
    };
    match outcome {
        Some(Leg::Clean) => Ok(()),
        Some(Leg::Abort) => {
            let code = noq::VarInt::from_u32(TUNNEL_ABORT_CODE);
            let _ = send.reset(code);
            let _ = recv.stop(code);
            abort_local(&tcp);
            Err(Error::MalformedTunnel("tunnel splice aborted"))
        }
        Some(Leg::Withdrawn) => {
            let _ = recv.stop(noq::VarInt::from_u32(REACH_WITHDRAWN_CODE));
            let _ = send.reset(noq::VarInt::from_u32(REACH_WITHDRAWN_CODE));
            abort_local(&tcp);
            Err(Error::TunnelRevoked(
                "the host withdrew access to this service",
            ))
        }
        None => {
            // Reset rather than finish: a clean close is indistinguishable from the carried
            // service hanging up, and the dialer deserves to know this was a decision.
            let code = noq::VarInt::from_u32(REACH_WITHDRAWN_CODE);
            let _ = send.reset(code);
            let _ = recv.stop(code);
            abort_local(&tcp);
            Err(Error::TunnelRevoked("withdrawn mid-session"))
        }
    }
}

/// Make the imminent drop of `tcp` an RST rather than a FIN.
///
/// A zero linger is the portable way to ask for an abortive close, and it is the only
/// way a tunnel end can say "this connection failed" to the application holding the other
/// end of the TCP socket: anything gentler reads as the peer finishing normally.
pub fn abort_local(tcp: &TcpStream) {
    let _ = tcp.set_zero_linger();
}
