//! `vox up`: the local entry point, as a SOCKS5 proxy (ADR-017 decision 5, M17.3).
//!
//! A tool on this machine connects to this proxy and asks for `<52-char>.vox:22`. The
//! name is resolved here — from rooms this machine has joined, and nothing else — and the
//! connection is carried to that room's host as a tunnel, with **the port as the service
//! tag**.
//!
//! ## Why a proxy and not an interface
//! This is what Tor does, and Tor is the thing being replaced. Its client side offers
//! three mechanisms (`tor.1`): `SocksPort`, unprivileged but requiring the tool to be
//! proxy-aware; `DNSPort` + `AutomapHostsOnResolve`, which hands out a virtual address per
//! name; and `TransPort`, which "requires OS support for transparent proxies, such as
//! BSDs' pf or Linux's IPTables". The first is Tor's documented default, and `torify(1)`
//! ships precisely because tools need pointing at it.
//!
//! So the cost is real and is stated rather than engineered around: a tool has to be told
//! about the proxy once. For `ssh` that is a `ProxyCommand` line matched on `*.vox`,
//! written once for every room there will ever be; for most other tools it is
//! `ALL_PROXY=socks5h://127.0.0.1:1080`. In exchange, **nothing here needs privilege, on
//! any platform, ever** — no device, no route, no firewall rule, no port below 1024, and
//! no resolver entry.
//!
//! ## `socks5h`, not `socks5`
//! The `h` matters: it tells the client to send the **hostname** and let the proxy resolve
//! it. A `.vox` name has no meaning to the local resolver and must not be sent to one, so
//! a client configured for plain `socks5` will fail to resolve before it ever gets here —
//! which is the correct failure, just an opaque one. [`Error::MalformedTunnel`] on a
//! literal-address CONNECT says so.
//!
//! ## What it will not do
//! Only CONNECT, only to a `.vox` name in a room this machine holds. A literal IP is
//! refused rather than proxied: this is not a general-purpose proxy, and one that would
//! forward arbitrary traffic on loopback is an open relay for anything on the machine.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::resolver::VoxResolver;
use crate::transport::quic::VoxConnection;
use crate::tunnel::socks::{self, Reply, Target};

/// The loopback port `vox up` listens on by default. 1080 is the registered SOCKS port
/// and needs no privilege.
pub const DEFAULT_SOCKS_PORT: u16 = 1080;

/// How the proxy reaches a room's host.
///
/// The proxy does not know how to reach anybody — that is the ADR-012 ladder's job, and the
/// ladder lives in the node. It asks here, **per connection**, and the node decides whether
/// that means handing back a live connection or dialling one.
///
/// Asking per connection rather than once at startup is deliberate, and it is a correction:
/// an earlier version dialled the host *before* binding, so that a proxy which came up could
/// never refuse every request. That traded one failure for a worse one — a node that has only
/// just joined has not yet read the board, so it does not know where the host is, and
/// `vox up` refused to start on a race the user cannot see or avoid. Retrying inside the
/// actor would not help either: the actor is what fetches the board, so sleeping in a command
/// handler blocks the progress it is waiting for. Binding immediately and dialling on demand
/// removes the race instead of timing it.
pub trait HostDialer: Send + Sync {
    /// A connection to `host`, dialling if this node has none.
    ///
    /// The error carries **which rung failed** — no candidates, the relay refused, the target
    /// never answered. Every rung already produces a specific error, and a proxy that reduced
    /// them all to "cannot reach the host" left a person with five minutes of waiting and
    /// nothing to act on.
    fn connection(
        &self,
        host: &Digest32,
    ) -> impl core::future::Future<Output = Result<Arc<VoxConnection>>> + Send;
}

/// Serve SOCKS5 on `bind` until the task is dropped.
///
/// Loopback only, and enforced: this proxy carries traffic into rooms this machine is a
/// member of, so exposing it to the network would hand that membership to anyone who can
/// reach the port.
pub async fn serve<D>(
    listener: TcpListener,
    resolver: Arc<VoxResolver>,
    dialer: Arc<D>,
) -> Result<()>
where
    D: HostDialer + 'static,
{
    serve_reporting(listener, resolver, dialer, |_, _| {}, |_| {}).await
}

/// [`serve`], reporting each carried tunnel that was **cut by a withdrawal of reach**
/// (ADR-017 M17.11) as `(room, port)`.
///
/// A library cannot print, and one connection's failure is its own — the proxy keeps
/// serving either way — so the reason would otherwise die in a dropped `Result`. The node
/// turns these into [`crate::node::api::NodeEvent::ReachWithdrawn`], which is what puts
/// the sentence in front of the person whose `ssh` just died.
///
/// A **refusal** is reported too, through `refused`. The SOCKS reply the client gets stays
/// uniform, because which of unauthorized / no-such-service / could-not-get-there it was is not
/// the proxy's to disclose (ADR-013). But the operator's own node is not the peer: the ladder's
/// verdict was already kept specifically so it could be said, and returning it into a dropped
/// `Result` meant `ssh` failed with nothing to act on. An ordinary disconnect stays silent.
pub async fn serve_reporting<D, R, F>(
    listener: TcpListener,
    resolver: Arc<VoxResolver>,
    dialer: Arc<D>,
    withdrawn: R,
    refused: F,
) -> Result<()>
where
    D: HostDialer + 'static,
    R: Fn(&Digest32, u16) + Send + Sync + 'static,
    F: Fn(&str) + Send + Sync + 'static,
{
    let withdrawn = Arc::new(withdrawn);
    let refused = Arc::new(refused);
    // The caller binds and hands the live listener over, rather than passing an address
    // for this function to bind (M17.16). Binding here meant the caller had to bind once
    // to learn the port, **drop it**, and let this re-bind — which announced an address
    // twice over a window where nothing was listening, and let any other process steal the
    // port in between, with the failure invisible because this task's `Result` is dropped.
    //
    // Handing over a bound listener closes both: the kernel accepts into its backlog from
    // the moment of bind, so the address is connectable the instant the caller can name it.
    let bind = listener
        .local_addr()
        .map_err(|_| Error::Unreachable("the vox proxy listener has no address"))?;
    if !bind.ip().is_loopback() {
        return Err(Error::MalformedTunnel("vox up binds loopback only"));
    }
    loop {
        let (stream, from) = match listener.accept().await {
            Ok(accepted) => accepted,
            // Back off rather than spin: a failed accept is almost always `EMFILE`, and
            // retrying at once fails again at once (see `tunnel::ACCEPT_BACKOFF`).
            Err(_) => {
                tokio::time::sleep(crate::node::tunnel::ACCEPT_BACKOFF).await;
                continue;
            }
        };
        if !from.ip().is_loopback() {
            continue;
        }
        let resolver = Arc::clone(&resolver);
        let dialer = Arc::clone(&dialer);
        let withdrawn = Arc::clone(&withdrawn);
        let refused = Arc::clone(&refused);
        tokio::spawn(async move {
            // One connection's failure is its own; the proxy keeps serving.
            let _ = handle(
                stream,
                &resolver,
                dialer.as_ref(),
                withdrawn.as_ref(),
                refused.as_ref(),
            )
            .await;
        });
    }
}

/// How long one request waits for the host to become reachable before refusing.
///
/// The proxy binds before it can reach anybody, deliberately (see [`HostDialer`]), so the
/// first request can arrive before this node has read the board and learned where the host
/// is. Refusing immediately made that visible as a product defect: the automated rehearsal
/// (`service_rehearsal_proof`) sees **two** refusals over about four seconds before a
/// CONNECT succeeds, which for a person is `ssh` failing and then working if they try
/// again.
///
/// Waiting *inside one request* does not bring back the problem the eager dial had. That
/// one blocked **binding**, so a proxy which came up could refuse everything for ever;
/// this blocks only the request that is waiting, on its own task, while every other
/// request and the accept loop keep running.
///
/// **Why it is minutes rather than seconds.** The bound was 20s, then 90s, and both were
/// calibrated on an idle machine. The measured first-connect wait on a quiet box has been
/// 7.7s and 88s across runs — an order of magnitude apart for the same code — because what
/// the wait covers is a cold node connecting to an anchor, syncing a board and dialling a
/// peer through the ADR-012 ladder, possibly relayed. Under a loaded machine the 90s bound
/// expired and the *original* defect reappeared: the proxy refused a real request that would
/// have succeeded shortly after. A bound that turns into the bug it fixed whenever the
/// machine is busy is not a fix, so this is generous on purpose. A host that is genuinely
/// gone still refuses — it just takes a few minutes to say so, which is the right way round
/// for a wait a person only pays on their first connection.
/// Public so a proof can derive its own read timeout from it rather than restate it.
///
/// A rehearsal that waits on this has to wait *longer* than this, or it reports the
/// operating system's "would block" instead of what the proxy decided. That invariant used
/// to live in a comment beside a hand-written 150s, and when this constant was raised to
/// 300s the comment stayed true and the number stopped being: `service_rehearsal_proof`
/// then failed at ~155s with `Resource temporarily unavailable`, which reads like a product
/// race and is not one. Exported so the compiler carries the invariant instead of prose.
pub const HOST_PATIENCE: Duration = Duration::from_secs(300);

/// Poll interval while waiting. Short enough that a ready host costs a person nothing.
const HOST_POLL: Duration = Duration::from_millis(250);

/// A connection to `host`, waiting up to [`HOST_PATIENCE`] for one to become possible.
///
/// `None` means it stayed unreachable for the whole window, which is a refusal a person
/// should see — the room's host may genuinely be offline.
async fn reach_host_with_patience<D: HostDialer>(
    dialer: &D,
    host: &Digest32,
) -> Result<Arc<VoxConnection>> {
    let deadline = tokio::time::Instant::now() + HOST_PATIENCE;
    // The **last** reason, not a generic one. Every rung of the ladder already produces a
    // specific error — no candidates, the relay refused, the target never answered — and
    // this loop used to discard all of them and hand the caller `None`. A person then saw
    // "cannot reach that room's host" after five minutes with nothing to act on, and a
    // diagnosis needed a debugger. Keeping the last one costs a String and turns the same
    // five minutes into a sentence.
    loop {
        let last = match dialer.connection(host).await {
            Ok(conn) => return Ok(conn),
            Err(e) => e,
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(last);
        }
        tokio::time::sleep(HOST_POLL).await;
    }
}

/// Reach `host` and open a tunnel to `service_tag` in `channel_id`, returning the stream
/// pair **once the host has accepted** — so a caller can tell its application the truth.
///
/// Patient in the same way and for the same reasons as `reach_host_with_patience`, and
/// patient about the *path* too: an attempt that fails before the host answered — the
/// connection was stale because the host restarted, or the path changed under it — is
/// retried on whatever connection reaches the host now, until [`HOST_PATIENCE`] runs out
/// (PRD-001 R24). A **refusal** is never retried: the host has decided, and asking again
/// would only make a refused application wait five minutes to be told so.
///
/// **The connection comes back too, and the caller holds it for as long as it splices.**
/// Holding it is what marks the path as carrying: when a better path displaces this one,
/// `ConnectionManager::retire_expired` closes the old one only once nothing holds it, so a
/// tunnel that let go of it here would be cut the moment the retirement grace ran out.
///
/// # Errors
/// [`Error::TunnelDenied`] when the host refused; otherwise the last reason the host could
/// not be reached.
pub async fn open_tunnel<D: HostDialer>(
    dialer: &D,
    host: &Digest32,
    channel_id: &Digest32,
    service_tag: &str,
) -> Result<(quinn::SendStream, quinn::RecvStream, Arc<VoxConnection>)> {
    let deadline = tokio::time::Instant::now() + HOST_PATIENCE;
    loop {
        let attempt = async {
            let conn = reach_host_with_patience(dialer, host).await?;
            let (mut send, mut recv) = crate::transport::streams::open_typed(
                &conn,
                crate::transport::streams::StreamKind::Tunnel,
            )
            .await?;
            crate::tunnel::session::request(&mut send, &mut recv, channel_id, service_tag).await?;
            Ok::<_, Error>((send, recv, conn))
        };
        match attempt.await {
            Ok(streams) => return Ok(streams),
            Err(e @ Error::TunnelDenied(_)) => return Err(e),
            Err(e) if tokio::time::Instant::now() >= deadline => return Err(e),
            Err(_) => tokio::time::sleep(HOST_POLL).await,
        }
    }
}

/// What to tell the operator when [`open_tunnel`] failed for `what`.
///
/// Said on this node only. The host's refusal is deliberately uniform — untrusted, no such
/// service and a service that would not answer look the same on the wire (ADR-013) — so
/// this names all three rather than guessing, and says nothing the host did not say.
#[must_use]
pub fn refusal(e: &Error, what: &str) -> String {
    match e {
        Error::TunnelDenied(_) => format!(
            "the host refused {what} — it has not trusted this identity (`vox trust add`), \
             or offers nothing there, or its service did not answer"
        ),
        other => format!("could not reach the host for {what}: {other}"),
    }
}

/// The bound address reported back to a SOCKS client. The proxy does not bind a per-
/// connection address, and RFC 1928 lets a server report all-zeroes for that.
const UNSPECIFIED: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Negotiate, resolve, and carry one SOCKS5 connection.
async fn handle<D: HostDialer, R: Fn(&Digest32, u16), F: Fn(&str)>(
    mut stream: TcpStream,
    resolver: &VoxResolver,
    dialer: &D,
    withdrawn: &R,
    refused: &F,
) -> Result<()> {
    socks::negotiate(&mut stream).await?;
    let target = socks::read_connect(&mut stream).await?;
    let (name, port) = match target {
        Target::Domain(name, port) => (name, port),
        Target::Ip(_) => {
            // Not a Vox name. Refusing is the point: a proxy on loopback that forwarded
            // arbitrary addresses would be an open relay for anything on this machine.
            refused("a CONNECT to a bare address: vox up carries .vox names only");
            socks::write_reply(&mut stream, Reply::AddressNotSupported, UNSPECIFIED).await?;
            return Err(Error::MalformedTunnel(
                "vox up carries .vox names only; configure socks5h so the name reaches it",
            ));
        }
    };
    let Some(room) = resolver.resolve(&name).copied() else {
        // A room this machine has not joined, or not a `.vox` name at all. One uniform
        // refusal for both: which of the two it was is not the proxy's to disclose.
        refused(&format!("no room on this machine answers to {name}"));
        socks::write_reply(&mut stream, Reply::NotAllowed, UNSPECIFIED).await?;
        return Err(Error::MalformedTunnel("no such .vox name on this machine"));
    };
    // **Reply only once the host has answered** (PRD-001 R23). This used to say
    // "succeeded" before dialling, on the belief that the host waits for the client's
    // first bytes and so holding the reply would deadlock against `ssh`, which sends
    // nothing until it is told the connection is up. The host waits for nothing of the
    // kind — it writes its verdict straight after its own local connect — so the early
    // reply bought nothing and cost the truth: every refused CONNECT looked connected and
    // then hung up, and neither the tool nor the person could tell a refusal from a
    // network fault.
    //
    // **The port is the service tag** (ADR-017 decision 4), so nothing here invents a name,
    // and the **host** decides whether the dial is allowed — this side claims nothing.
    let tag = port.to_string();
    // `_carried` is held for the whole splice: see [`open_tunnel`].
    let (send, recv, _carried) = match open_tunnel(dialer, &room.host, &room.channel_id, &tag).await
    {
        Ok(streams) => streams,
        Err(why) => {
            // The SOCKS reply is a code, and a coarse one; the sentence goes to this node's
            // own operator. Neither says anything the host did not.
            refused(&refusal(&why, &format!("{name}:{port}")));
            let reply = match why {
                Error::TunnelDenied(_) => Reply::NotAllowed,
                _ => Reply::GeneralFailure,
            };
            socks::write_reply(&mut stream, reply, UNSPECIFIED).await?;
            return Err(why);
        }
    };
    socks::write_reply(&mut stream, Reply::Succeeded, UNSPECIFIED).await?;
    match crate::tunnel::session::splice(send, recv, stream).await {
        // The session was established and then cut by a decision. Report it; every other
        // ending is silent (M17.11).
        Err(Error::TunnelRevoked(why)) => {
            withdrawn(&room.channel_id, port);
            Err(Error::TunnelRevoked(why))
        }
        other => other,
    }
}

/// The `~/.ssh/config` block that makes `ssh user@<name>.vox` work, for `vox up` to print.
///
/// It is printed rather than written: this is the user's file, and a tool that edits it
/// unasked is a tool that will one day edit it wrongly.
#[must_use]
pub fn ssh_config_hint(bind: SocketAddr) -> String {
    format!(
        "Host *.vox\n    ProxyCommand nc -X 5 -x {} %h %p\n    # or, without nc:\n    #   ProxyCommand socat - SOCKS5:{}:%h:%p\n",
        bind, bind
    )
}
