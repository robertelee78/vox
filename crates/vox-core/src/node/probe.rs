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

/// A service listening on this machine (ADR-028 S-4): what a person picks from to share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listening {
    /// The listening program's command name, where this user may read it: unprivileged, a
    /// root-owned daemon's usually cannot be.
    pub command: Option<String>,
    /// Its port.
    pub port: u16,
    /// Whether it takes datagrams rather than connections.
    pub udp: bool,
    /// Every address it listens on: `0.0.0.0` or `::` for every interface.
    pub addrs: Vec<IpAddr>,
}

impl Listening {
    /// Whether it listens on every interface of this machine, not just loopback or one address.
    #[must_use]
    pub fn on_every_interface(&self) -> bool {
        self.addrs.iter().any(IpAddr::is_unspecified)
    }

    /// The endpoint a share carries connections to: loopback where it listens there (every
    /// interface includes it), else its first address.
    #[must_use]
    pub fn endpoint(&self) -> SocketAddr {
        let v4_loop = self
            .addrs
            .iter()
            .any(|a| matches!(a, IpAddr::V4(ip) if ip.is_loopback() || ip.is_unspecified()));
        let v6_loop = self
            .addrs
            .iter()
            .any(|a| matches!(a, IpAddr::V6(ip) if ip.is_loopback() || ip.is_unspecified()));
        let ip = if v4_loop {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else if v6_loop {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            self.addrs
                .first()
                .copied()
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
        };
        SocketAddr::new(ip, self.port)
    }
}

/// The lowest port of the ephemeral range on every system Vox runs on (Linux starts there;
/// macOS higher): a UDP socket bound above it is a client's, not a service.
const EPHEMERAL: u16 = 32768;

/// The services listening on this machine, by port: every TCP listener, and every UDP socket on a
/// fixed port, other than Vox's own. Read with `lsof` on macOS and `ss` on Linux; empty where
/// neither can be run.
#[must_use]
pub fn listening() -> Vec<Listening> {
    let mut found: Vec<(Option<String>, IpAddr, u16, bool)> = Vec::new();
    for udp in [false, true] {
        if cfg!(target_os = "macos") {
            let args: &[&str] = if udp {
                &["-nP", "-iUDP", "-Fctn"]
            } else {
                &["-nP", "-iTCP", "-sTCP:LISTEN", "-Fctn"]
            };
            if let Some(out) = run("lsof", args) {
                found.extend(parse_lsof(&out, udp));
            }
        } else if cfg!(target_os = "linux") {
            let flags = if udp { "-Hlunp" } else { "-Hltnp" };
            if let Some(out) = run("ss", &[flags]) {
                found.extend(parse_ss(&out, udp));
            }
        }
    }
    let mut out: Vec<Listening> = Vec::new();
    for (command, ip, port, udp) in found {
        if command.as_deref() == Some("vox") || (udp && port >= EPHEMERAL) || port == 0 {
            continue;
        }
        match out.iter_mut().find(|l| l.port == port && l.udp == udp) {
            Some(l) => {
                if !l.addrs.contains(&ip) {
                    l.addrs.push(ip);
                }
                if l.command.is_none() {
                    l.command = command;
                }
            }
            None => out.push(Listening {
                command,
                port,
                udp,
                addrs: vec![ip],
            }),
        }
    }
    out.sort_by_key(|l| (l.udp, l.port));
    out
}

/// `lsof -F ctn` records: `c<command>`, then per file `t<IPv4|IPv6>` and `n<address>`.
fn parse_lsof(out: &str, udp: bool) -> Vec<(Option<String>, IpAddr, u16, bool)> {
    let (mut command, mut v6) = (None::<String>, false);
    let mut found = Vec::new();
    for line in out.lines() {
        let (tag, rest) = (line.get(..1).unwrap_or(""), line.get(1..).unwrap_or(""));
        match tag {
            "p" => command = None,
            "c" => command = Some(rest.to_owned()),
            "t" => v6 = rest == "IPv6",
            "n" if !rest.contains("->") => {
                if let Some((ip, port)) = split_address(rest, v6) {
                    found.push((command.clone(), ip, port, udp));
                }
            }
            _ => {}
        }
    }
    found
}

/// `ss -H -l -n -p` rows: the local address is the fourth column; the process, where this user
/// may see it, `users:(("sshd",pid=812,fd=3))`.
fn parse_ss(out: &str, udp: bool) -> Vec<(Option<String>, IpAddr, u16, bool)> {
    out.lines()
        .filter_map(|row| {
            let local = row.split_whitespace().nth(3)?;
            let v6 = local.starts_with('[');
            let (ip, port) = split_address(local, v6)?;
            let command = row
                .split("((\"")
                .nth(1)
                .and_then(|a| a.split('"').next())
                .map(str::to_owned);
            Some((command, ip, port, udp))
        })
        .collect()
}

/// `127.0.0.1:22`, `[::1]:22`, `*:22`, `127.0.0.53%lo:53`, `[fe80::1%en0]:22` → address and port;
/// `*` is every interface.
fn split_address(text: &str, v6: bool) -> Option<(IpAddr, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.split('%').next()?;
    let ip = if host == "*" {
        if v6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
    } else {
        host.parse().ok()?
    };
    Some((ip, port))
}

/// What a well-known sensitive port is, for a warning before it is shared (ADR-028 S-4): a
/// database or a machine's administration, which a share hands to every member its sharer
/// trusts. A warning only: the kind of a share is never taken from its port (S-2).
#[must_use]
pub fn sensitive_port(port: u16) -> Option<&'static str> {
    Some(match port {
        1433 => "SQL Server's",
        1521 => "Oracle's",
        2375 | 2376 => "the Docker API's",
        3306 => "MySQL's",
        3389 => "Remote Desktop's",
        5432 => "PostgreSQL's",
        5900 => "VNC's",
        5984 => "CouchDB's",
        6379 => "Redis's",
        9200 => "Elasticsearch's",
        11211 => "memcached's",
        27017 => "MongoDB's",
        _ => return None,
    })
}

// ---- What a person is told of what listens here, and of sharing it (ADR-028 S-4) ----
// One wording for `vox serve`, the TUI and the app.

/// Said under a list of what listens on this machine: unprivileged, `lsof` sees only this user's
/// sockets and `ss` hides another user's program.
pub const MAY_BE_MISSING: &str =
    "another user's services, root's among them, may be missing here or listed without their \
     program";

/// The name a listening service is offered under, unless the person gives another (ADR-028 S-4):
/// its detected kind, which is the best name; else its program's (S-2: the kind itself is never
/// taken from either). Shared by `vox serve`, the TUI's share flow and the app.
pub async fn suggested_name(chosen: &Listening) -> String {
    let kind = detect(chosen.endpoint(), chosen.udp).await;
    match kind {
        ServiceKind::Tcp | ServiceKind::Udp => chosen
            .command
            .as_deref()
            .map(crate::node::resolver::label_of)
            .filter(|n| !n.is_empty() && n.len() <= crate::governance::share::MAX_SERVICE_NAME)
            .unwrap_or_else(|| "service".to_owned()),
        other => other.as_str().to_owned(),
    }
}

/// A service's tag from its name: `udp/<name>` for one that takes datagrams.
pub fn tag_of(name: String, udp: bool) -> String {
    if udp {
        format!("udp/{name}")
    } else {
        name
    }
}

/// One listening service as the list shows it: its program, where it listens, and over what.
pub fn listing_line(l: &Listening) -> String {
    let program = l.command.as_deref().unwrap_or("(not visible to you)");
    let addrs: Vec<String> = l
        .addrs
        .iter()
        .map(|a| SocketAddr::new(*a, l.port).to_string())
        .collect();
    let proto = if l.udp { "udp" } else { "tcp" };
    let every = if l.on_every_interface() {
        "  (every interface)"
    } else {
        ""
    };
    format!("{program:<20} {}  {proto}{every}", addrs.join(", "))
}

/// One listening service as a sentence says it, with none of the list's column padding:
/// "python3.13 on 0.0.0.0:8080, tcp".
pub fn said_in_a_sentence(l: &Listening) -> String {
    let program = l
        .command
        .as_deref()
        .unwrap_or("a program not visible to you");
    let addrs: Vec<String> = l
        .addrs
        .iter()
        .map(|a| SocketAddr::new(*a, l.port).to_string())
        .collect();
    let proto = if l.udp { "udp" } else { "tcp" };
    format!("{program} on {}, {proto}", addrs.join(", "))
}

/// What a person must hear before `services` are shared (ADR-028 S-4): each one this machine
/// listens for on every interface, which its networks reach with no Vox at all, and each on a
/// well-known sensitive port.
pub async fn exposure_warnings(services: &[(u16, String)], at: Option<SocketAddr>) -> Vec<String> {
    let found = tokio::task::spawn_blocking(listening)
        .await
        .unwrap_or_default();
    let mut out = Vec::new();
    for (port, label) in services {
        let name = crate::node::channel::service_name(label);
        let udp = crate::tunnel::udp::is_udp(label);
        let port = at.map_or(*port, |a| a.port());
        if let Some(l) = found
            .iter()
            .find(|l| l.port == port && l.udp == udp && l.on_every_interface())
        {
            out.push(format!(
                "`{name}` ({}) listens on every interface of this machine, so its networks \
                 reach it without Vox; sharing it does not change that",
                said_in_a_sentence(l)
            ));
        }
        if let Some(what) = sensitive_port(port) {
            out.push(format!(
                "`{name}` is on port {port}, {what}: every node you trust in the room can \
                 reach it"
            ));
        }
    }
    out
}
