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
use crate::node::resolver::{ServiceRoom, VoxResolver};
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
    /// A connection to `host`, dialling if this node has none. `None` when the host cannot be
    /// reached at all.
    fn connection(
        &self,
        host: &Digest32,
    ) -> impl core::future::Future<Output = Option<Arc<VoxConnection>>> + Send;
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
        let Ok((stream, from)) = listener.accept().await else {
            continue;
        };
        if !from.ip().is_loopback() {
            continue;
        }
        let resolver = Arc::clone(&resolver);
        let dialer = Arc::clone(&dialer);
        tokio::spawn(async move {
            // One connection's failure is its own; the proxy keeps serving.
            let _ = handle(stream, &resolver, dialer.as_ref()).await;
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
const HOST_PATIENCE: Duration = Duration::from_secs(90);

/// Poll interval while waiting. Short enough that a ready host costs a person nothing.
const HOST_POLL: Duration = Duration::from_millis(250);

/// A connection to `host`, waiting up to [`HOST_PATIENCE`] for one to become possible.
///
/// `None` means it stayed unreachable for the whole window, which is a refusal a person
/// should see — the room's host may genuinely be offline.
async fn reach_host_with_patience<D: HostDialer>(
    dialer: &D,
    host: &Digest32,
) -> Option<Arc<VoxConnection>> {
    let deadline = tokio::time::Instant::now() + HOST_PATIENCE;
    loop {
        if let Some(conn) = dialer.connection(host).await {
            return Some(conn);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(HOST_POLL).await;
    }
}

/// The bound address reported back to a SOCKS client. The proxy does not bind a per-
/// connection address, and RFC 1928 lets a server report all-zeroes for that.
const UNSPECIFIED: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Negotiate, resolve, and carry one SOCKS5 connection.
async fn handle<D: HostDialer>(
    mut stream: TcpStream,
    resolver: &VoxResolver,
    dialer: &D,
) -> Result<()> {
    socks::negotiate(&mut stream).await?;
    let target = socks::read_connect(&mut stream).await?;
    let (name, port) = match target {
        Target::Domain(name, port) => (name, port),
        Target::Ip(_) => {
            // Not a Vox name. Refusing is the point: a proxy on loopback that forwarded
            // arbitrary addresses would be an open relay for anything on this machine.
            socks::write_reply(&mut stream, Reply::AddressNotSupported, UNSPECIFIED).await?;
            return Err(Error::MalformedTunnel(
                "vox up carries .vox names only; configure socks5h so the name reaches it",
            ));
        }
    };
    let Some(room) = resolver.resolve(&name).copied() else {
        // A room this machine has not joined, or not a `.vox` name at all. One uniform
        // refusal for both: which of the two it was is not the proxy's to disclose.
        socks::write_reply(&mut stream, Reply::NotAllowed, UNSPECIFIED).await?;
        return Err(Error::MalformedTunnel("no such .vox name on this machine"));
    };
    let Some(conn) = reach_host_with_patience(dialer, &room.host).await else {
        socks::write_reply(&mut stream, Reply::GeneralFailure, UNSPECIFIED).await?;
        return Err(Error::Unreachable("no connection to that room's host"));
    };

    // Reply *before* the tunnel is dialled, because a SOCKS client sends nothing until it
    // has been told the connection succeeded — `ssh` waits for the reply before its
    // version banner, so a dial that waits for bytes would deadlock against a client that
    // waits for this.
    socks::write_reply(&mut stream, Reply::Succeeded, UNSPECIFIED).await?;
    carry(&conn, &room, port, stream).await
}

/// Open a tunnel stream to the room's host and splice `local` into it.
///
/// **The port is the service tag** (ADR-017 decision 4), so nothing here invents a name,
/// and the host's evaluator decides whether the dial is allowed — this side claims
/// nothing. A refusal closes the local connection, which the tool sees as the peer hanging
/// up, and says nothing about why (dark services, ADR-013).
async fn carry(
    conn: &Arc<VoxConnection>,
    room: &ServiceRoom,
    port: u16,
    local: TcpStream,
) -> Result<()> {
    let (send, recv) =
        crate::transport::streams::open_typed(conn, crate::transport::streams::StreamKind::Tunnel)
            .await?;
    crate::tunnel::session::dial(send, recv, &room.channel_id, &port.to_string(), local).await
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
