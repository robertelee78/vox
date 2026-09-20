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

use tokio::net::{TcpListener, TcpStream};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::resolver::{ServiceRoom, VoxResolver};
use crate::transport::quic::VoxConnection;
use crate::tunnel::socks::{self, Reply, Target};

/// The loopback port `vox up` listens on by default. 1080 is the registered SOCKS port
/// and needs no privilege.
pub const DEFAULT_SOCKS_PORT: u16 = 1080;

/// What the proxy needs in order to carry a connection: the room, and a live connection to
/// its host.
///
/// The proxy does not dial peers itself — reaching a member is the node's job, through the
/// ADR-012 ladder — so it asks for the connection and refuses if there is none.
pub trait HostDialer: Send + Sync {
    /// A live connection to `host`, or `None` if this node has none.
    fn connection(&self, host: &Digest32) -> Option<Arc<VoxConnection>>;
}

/// Serve SOCKS5 on `bind` until the task is dropped.
///
/// Loopback only, and enforced: this proxy carries traffic into rooms this machine is a
/// member of, so exposing it to the network would hand that membership to anyone who can
/// reach the port.
pub async fn serve<D>(bind: SocketAddr, resolver: Arc<VoxResolver>, dialer: Arc<D>) -> Result<()>
where
    D: HostDialer + 'static,
{
    if !bind.ip().is_loopback() {
        return Err(Error::MalformedTunnel("vox up binds loopback only"));
    }
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|_| Error::Unreachable("cannot bind the vox proxy"))?;
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
    let Some(conn) = dialer.connection(&room.host) else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct NoConnections;
    impl HostDialer for NoConnections {
        fn connection(&self, _host: &Digest32) -> Option<Arc<VoxConnection>> {
            None
        }
    }

    /// A SOCKS5 greeting plus a CONNECT for `name:port`, as a client sends them.
    async fn connect_request(stream: &mut TcpStream, name: &str, port: u16) {
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut selected = [0u8; 2];
        stream.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [0x05, 0x00], "no-auth selected");
        let mut req = vec![0x05, 0x01, 0x00, 0x03];
        req.push(u8::try_from(name.len()).unwrap());
        req.extend_from_slice(name.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&req).await.unwrap();
    }

    async fn reply_code(stream: &mut TcpStream) -> u8 {
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 0x05);
        // Drain the bound address so the stream is left at a frame boundary.
        let rest = match head[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            _ => panic!("unexpected ATYP {}", head[3]),
        };
        let mut buf = vec![0u8; rest];
        stream.read_exact(&mut buf).await.unwrap();
        head[1]
    }

    async fn proxy(resolver: VoxResolver) -> SocketAddr {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = probe.local_addr().unwrap();
        drop(probe);
        tokio::spawn(serve(bound, Arc::new(resolver), Arc::new(NoConnections)));
        // Wait for the bind rather than racing it.
        for _ in 0..200 {
            if TcpStream::connect(bound).await.is_ok() {
                return bound;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("the proxy never bound");
    }

    #[tokio::test]
    async fn it_binds_loopback_only() {
        // This proxy carries traffic into rooms this machine is a member of. Exposing it
        // would hand that membership to anyone who can reach the port.
        assert!(matches!(
            serve(
                "0.0.0.0:0".parse().unwrap(),
                Arc::new(VoxResolver::new()),
                Arc::new(NoConnections)
            )
            .await,
            Err(Error::MalformedTunnel("vox up binds loopback only"))
        ));
    }

    #[tokio::test]
    async fn an_unknown_name_is_refused_uniformly() {
        let bound = proxy(VoxResolver::new()).await;
        let mut c = TcpStream::connect(bound).await.unwrap();
        connect_request(
            &mut c,
            "f6wxkoxq36ofp5zxvmtlx6mg6gr2t2tfcr66aq3l5w5cctqmxg3q.vox",
            22,
        )
        .await;
        // 0x02 "not allowed by ruleset": the same answer for a room not joined and for a
        // name that was never a room, because which it was is not the proxy's to say.
        assert_eq!(reply_code(&mut c).await, 0x02);
    }

    #[tokio::test]
    async fn a_literal_address_is_refused_rather_than_proxied() {
        let bound = proxy(VoxResolver::new()).await;
        let mut c = TcpStream::connect(bound).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut selected = [0u8; 2];
        c.read_exact(&mut selected).await.unwrap();
        // CONNECT to 127.0.0.1:22 as a literal IPv4 address.
        c.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x16])
            .await
            .unwrap();
        // 0x08 "address type not supported": this is not a general-purpose proxy, and one
        // that forwarded arbitrary addresses on loopback would be an open relay.
        assert_eq!(reply_code(&mut c).await, 0x08);
    }

    #[test]
    fn the_ssh_hint_names_the_proxy_and_matches_vox_names_only() {
        let hint = ssh_config_hint("127.0.0.1:1080".parse().unwrap());
        assert!(hint.contains("Host *.vox"));
        assert!(hint.contains("127.0.0.1:1080"));
        assert!(hint.contains("ProxyCommand"));
    }
}
