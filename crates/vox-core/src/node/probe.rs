//! What a service being shared **is** (ADR-028 S-2): `ssh`, `http`, `https`, `dns`, or plain
//! `tcp` or `udp`, recorded in the share statement so every member is offered the commands for
//! its kind.
//!
//! The kind is detected, never typed and never guessed from the port number or the service's
//! name:
//! - a probe on the wire, for every endpoint: an SSH banner, a TLS handshake, an HTTP response,
//!   a DNS answer;
//! - for an endpoint on this machine, also the listening process's command name (`lsof` on
//!   macOS, `ss` on Linux), when the probe could not tell. Unprivileged, neither can usually see
//!   a root-owned daemon's process, so the probe is what decides most of the time.
//!
//! Anything not identified is plain `tcp` or `udp`. Each step is bounded, so a share of a
//! service that never answers waits a few seconds at most, and never on the node's actor.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::governance::share::ServiceKind;

/// The longest one probe step waits: a connection, a banner, an answer.
const STEP: Duration = Duration::from_millis(1500);

/// The longest the listening process's name is waited for.
const LOOKUP: Duration = Duration::from_secs(3);

/// What the service at `endpoint` is: see the module documentation.
pub async fn detect(endpoint: SocketAddr, udp: bool) -> ServiceKind {
    let target = dialable(endpoint);
    let probed = if udp {
        probe_udp(target).await
    } else {
        probe_tcp(target).await
    };
    if let Some(kind) = probed {
        return kind;
    }
    if is_on_this_machine(endpoint.ip()) {
        let port = endpoint.port();
        let named = tokio::task::spawn_blocking(move || listener_command(port, udp))
            .await
            .ok()
            .flatten();
        if let Some(kind) = named.as_deref().and_then(|c| kind_of_command(c, udp)) {
            return kind;
        }
    }
    ServiceKind::plain(udp)
}

/// An unspecified address (`0.0.0.0`, `::`) is every interface of this machine: it is probed on
/// loopback.
fn dialable(endpoint: SocketAddr) -> SocketAddr {
    match endpoint.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), endpoint.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), endpoint.port())
        }
        _ => endpoint,
    }
}

/// Whether `ip` is one of this machine's own: loopback, unspecified, or an address a socket can
/// be bound to here (only an interface's own address can be).
fn is_on_this_machine(ip: IpAddr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// A stream service: an SSH banner, then a TLS handshake, then an HTTP response, each on its own
/// connection. TLS is tried before HTTP because a TLS server answers plain HTTP with an HTTP
/// error of its own (nginx's "400 The plain HTTP request was sent to HTTPS port").
async fn probe_tcp(target: SocketAddr) -> Option<ServiceKind> {
    // A server that speaks first: SSH.
    let mut s = connect(target).await?;
    let mut buf = [0u8; 256];
    if let Ok(Ok(n)) = tokio::time::timeout(STEP, s.read(&mut buf)).await {
        if buf[..n].starts_with(b"SSH-") {
            return Some(ServiceKind::Ssh);
        }
        if n > 0 {
            // It spoke first, and not SSH: nothing else here speaks first.
            return None;
        }
    }
    drop(s);
    if let Some(hello) = client_hello() {
        if let Some(mut s) = connect(target).await {
            if s.write_all(&hello).await.is_ok()
                && answer(&mut s).await.as_deref().is_some_and(is_tls_answer)
            {
                return Some(ServiceKind::Https);
            }
        }
    }
    let mut s = connect(target).await?;
    s.write_all(b"HEAD / HTTP/1.0\r\nUser-Agent: vox\r\n\r\n")
        .await
        .ok()?;
    let reply = answer(&mut s).await?;
    reply.starts_with(b"HTTP/").then_some(ServiceKind::Http)
}

/// Whether `reply` is a TLS server's answer to a ClientHello: a ServerHello (handshake record,
/// message type 2) or an alert record. A service that echoes what it is sent answers with the
/// ClientHello itself (message type 1), and that is no TLS server.
fn is_tls_answer(reply: &[u8]) -> bool {
    matches!(
        reply,
        [0x16, 0x03, _, _, _, 0x02, ..] | [0x15, 0x03, _, 0x00, 0x02, ..]
    )
}

async fn connect(target: SocketAddr) -> Option<TcpStream> {
    tokio::time::timeout(STEP, TcpStream::connect(target))
        .await
        .ok()?
        .ok()
}

/// The first bytes a stream answers with, within [`STEP`].
async fn answer(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(STEP, s.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    (n > 0).then(|| {
        buf.truncate(n);
        buf
    })
}

/// A real TLS ClientHello, as an ordinary client sends it: the handshake is never finished, so
/// nothing is verified.
fn client_hello() -> Option<Vec<u8>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let name = rustls_pki_types::ServerName::try_from("service.vox").ok()?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).ok()?;
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).ok()?;
    }
    Some(out)
}

/// A datagram service: a DNS query for the root's name servers, answered with the same id.
async fn probe_udp(target: SocketAddr) -> Option<ServiceKind> {
    let bind: SocketAddr = if target.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(target).await.ok()?;
    let mut id = [0u8; 2];
    getrandom::fill(&mut id).ok()?;
    // Header: id, RD set, one question; question: the root, type NS, class IN.
    let mut query = Vec::with_capacity(17);
    query.extend_from_slice(&id);
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend_from_slice(&[0, 0, 2, 0, 1]);
    sock.send(&query).await.ok()?;
    let deadline = Instant::now() + STEP;
    let mut buf = [0u8; 512];
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        let n = tokio::time::timeout(left, sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        // Same id, the response bit set, the one question echoed.
        if n >= 12 && buf[..2] == id && buf[2] & 0x80 != 0 && buf[4..6] == [0, 1] {
            return Some(ServiceKind::Dns);
        }
    }
}

/// The command name of the process listening on `port` on this machine, if it can be read.
fn listener_command(port: u16, udp: bool) -> Option<String> {
    if cfg!(target_os = "macos") {
        let spec = if udp {
            format!("-iUDP:{port}")
        } else {
            format!("-iTCP:{port}")
        };
        let mut args = vec!["-nP", spec.as_str(), "-Fc"];
        if !udp {
            args.push("-sTCP:LISTEN");
        }
        let out = run("lsof", &args)?;
        out.lines()
            .find_map(|l| l.strip_prefix('c'))
            .map(str::to_owned)
    } else if cfg!(target_os = "linux") {
        let filter = format!("sport = :{port}");
        let flags = if udp { "-Hlunp" } else { "-Hltnp" };
        let out = run("ss", &[flags, filter.as_str()])?;
        // `users:(("sshd",pid=812,fd=3))`
        let after = out.split("((\"").nth(1)?;
        after.split('"').next().map(str::to_owned)
    } else {
        None
    }
}

/// Run `program` with `args`, and its standard output if it finished within [`LOOKUP`].
fn run(program: &str, args: &[&str]) -> Option<String> {
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + LOOKUP;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut out).ok()?;
    Some(out)
}

/// The kind a listening program's command name says, for the programs whose name says one.
fn kind_of_command(command: &str, udp: bool) -> Option<ServiceKind> {
    let kind = match command {
        "sshd" | "sshd-session" | "dropbear" => ServiceKind::Ssh,
        "named" | "unbound" | "dnsmasq" | "mDNSResponder" | "coredns" | "systemd-resolve"
        | "systemd-resolved" => ServiceKind::Dns,
        _ => return None,
    };
    kind.fits(udp).then_some(kind)
}
