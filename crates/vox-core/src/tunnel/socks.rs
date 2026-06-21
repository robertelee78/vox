//! A minimal SOCKS5 front-end (RFC 1928) for the proxy path (ADR-013 §"Interface
//! models", §"Rust building blocks").
//!
//! This lets a local application — `ssh -o ProxyCommand`, a browser, anything that
//! speaks SOCKS5 — route a connection through a Vox tunnel: the proxy performs the
//! SOCKS5 handshake, learns the requested target, and the caller maps that target
//! onto a Vox service and splices the client socket to the tunnel
//! ([`crate::tunnel::session::dial`]). Only the **no-authentication** method is
//! offered (the SOCKS hop is loopback-local; authorization happens in the Vox layer
//! via the Dial capability, ADR-013), and only the **CONNECT** command is
//! supported (TCP tunneling).
//!
//! The protocol codec is exercised both by byte-level unit tests and an in-memory
//! duplex handshake test; the functions are generic over the stream so they work
//! with a real `TcpStream` and with [`tokio::io::duplex`].

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// SOCKS protocol version 5.
const VER: u8 = 0x05;
/// "No authentication required" method.
const METHOD_NO_AUTH: u8 = 0x00;
/// "No acceptable methods" sentinel.
const METHOD_NONE: u8 = 0xFF;
/// CONNECT command.
const CMD_CONNECT: u8 = 0x01;
/// Address type: IPv4.
const ATYP_IP4: u8 = 0x01;
/// Address type: domain name.
const ATYP_DOMAIN: u8 = 0x03;
/// Address type: IPv6.
const ATYP_IP6: u8 = 0x04;

/// Maximum domain-name length in a SOCKS request (the field is a single length
/// byte, so ≤ 255; bounded explicitly for clarity).
pub const MAX_DOMAIN_LEN: usize = 255;

/// SOCKS5 reply codes (RFC 1928 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `0x00` succeeded.
    Succeeded,
    /// `0x01` general SOCKS server failure.
    GeneralFailure,
    /// `0x02` connection not allowed by ruleset (used for a denied Vox Dial).
    NotAllowed,
    /// `0x07` command not supported.
    CommandNotSupported,
    /// `0x08` address type not supported.
    AddressNotSupported,
}

impl Reply {
    fn code(self) -> u8 {
        match self {
            Reply::Succeeded => 0x00,
            Reply::GeneralFailure => 0x01,
            Reply::NotAllowed => 0x02,
            Reply::CommandNotSupported => 0x07,
            Reply::AddressNotSupported => 0x08,
        }
    }
}

/// The CONNECT target a client requested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A literal socket address (IPv4 or IPv6).
    Ip(SocketAddr),
    /// A domain name and port (resolved by the proxy / mapped to a Vox service).
    Domain(String, u16),
}

/// Perform the SOCKS5 method-negotiation handshake, offering only no-auth.
///
/// Reads the client greeting; if the client offers no-auth, replies selecting it
/// and returns `Ok(())`. Otherwise replies `0xFF` (no acceptable methods) and
/// returns [`Error::MalformedTunnel`].
pub async fn negotiate<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| Error::MalformedTunnel("socks: greeting read"))?;
    if head[0] != VER {
        return Err(Error::MalformedTunnel("socks: bad version"));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|_| Error::MalformedTunnel("socks: methods read"))?;
    if methods.contains(&METHOD_NO_AUTH) {
        stream
            .write_all(&[VER, METHOD_NO_AUTH])
            .await
            .map_err(|_| Error::MalformedTunnel("socks: method reply"))?;
        Ok(())
    } else {
        let _ = stream.write_all(&[VER, METHOD_NONE]).await;
        Err(Error::MalformedTunnel("socks: no acceptable auth method"))
    }
}

/// Read a CONNECT request after [`negotiate`], returning the requested target.
///
/// Rejects a non-CONNECT command (replying `0x07`) and an unknown address type
/// (replying `0x08`).
pub async fn read_connect<S>(stream: &mut S) -> Result<Target>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| Error::MalformedTunnel("socks: request head"))?;
    if head[0] != VER {
        return Err(Error::MalformedTunnel("socks: bad version"));
    }
    if head[1] != CMD_CONNECT {
        let _ = write_reply(stream, Reply::CommandNotSupported, unspecified()).await;
        return Err(Error::MalformedTunnel("socks: unsupported command"));
    }
    // head[2] is RSV (ignored). head[3] is ATYP.
    let target = match head[3] {
        ATYP_IP4 => {
            let mut a = [0u8; 4];
            read_exact(stream, &mut a).await?;
            let port = read_port(stream).await?;
            Target::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(a), port)))
        }
        ATYP_IP6 => {
            let mut a = [0u8; 16];
            read_exact(stream, &mut a).await?;
            let port = read_port(stream).await?;
            Target::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a),
                port,
                0,
                0,
            )))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            read_exact(stream, &mut name).await?;
            let port = read_port(stream).await?;
            let host = String::from_utf8(name)
                .map_err(|_| Error::MalformedTunnel("socks: domain utf8"))?;
            Target::Domain(host, port)
        }
        _ => {
            let _ = write_reply(stream, Reply::AddressNotSupported, unspecified()).await;
            return Err(Error::MalformedTunnel("socks: unsupported address type"));
        }
    };
    Ok(target)
}

/// Write a SOCKS5 reply with the given code and bound address.
pub async fn write_reply<S>(stream: &mut S, reply: Reply, bound: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = vec![VER, reply.code(), 0x00];
    match bound {
        SocketAddr::V4(v4) => {
            out.push(ATYP_IP4);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(ATYP_IP6);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    stream
        .write_all(&out)
        .await
        .map_err(|_| Error::MalformedTunnel("socks: reply write"))
}

fn unspecified() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
}

async fn read_exact<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> Result<()> {
    stream
        .read_exact(buf)
        .await
        .map(|_| ())
        .map_err(|_| Error::MalformedTunnel("socks: request body"))
}

async fn read_port<S: AsyncRead + Unpin>(stream: &mut S) -> Result<u16> {
    let mut p = [0u8; 2];
    read_exact(stream, &mut p).await?;
    Ok(u16::from_be_bytes(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn negotiate_selects_no_auth() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let cli = tokio::spawn(async move {
            // greeting: ver, nmethods=1, no-auth
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).await.unwrap();
            reply
        });
        negotiate(&mut server).await.unwrap();
        assert_eq!(cli.await.unwrap(), [0x05, 0x00]);
    }

    #[tokio::test]
    async fn negotiate_rejects_when_no_no_auth_offered() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let cli = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap(); // only user/pass
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).await.unwrap();
            reply
        });
        assert!(negotiate(&mut server).await.is_err());
        assert_eq!(cli.await.unwrap(), [0x05, 0xFF]);
    }

    #[tokio::test]
    async fn read_connect_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // CONNECT to 127.0.0.1:8080
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90])
                .await
                .unwrap();
        });
        let t = read_connect(&mut server).await.unwrap();
        assert_eq!(
            t,
            Target::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)))
        );
    }

    #[tokio::test]
    async fn read_connect_domain() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let host = b"vox.example";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
            req.extend_from_slice(host);
            req.extend_from_slice(&22u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });
        let t = read_connect(&mut server).await.unwrap();
        assert_eq!(t, Target::Domain("vox.example".to_owned(), 22));
    }

    #[tokio::test]
    async fn read_connect_rejects_non_connect_command() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let cli = tokio::spawn(async move {
            // BIND (0x02), not supported
            client
                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            reply[1]
        });
        assert!(read_connect(&mut server).await.is_err());
        assert_eq!(cli.await.unwrap(), Reply::CommandNotSupported.code());
    }

    #[tokio::test]
    async fn write_reply_success_is_well_formed() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let cli = tokio::spawn(async move {
            let mut buf = [0u8; 10];
            client.read_exact(&mut buf).await.unwrap();
            buf
        });
        write_reply(
            &mut server,
            Reply::Succeeded,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080)),
        )
        .await
        .unwrap();
        let buf = cli.await.unwrap();
        assert_eq!(buf[0], 0x05);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[3], ATYP_IP4);
        assert_eq!(&buf[8..10], &1080u16.to_be_bytes());
    }
}
