//! UPnP-IGD port mapping (ADR-012 rung 2's third fallback: PCP → NAT-PMP → **UPnP**).
//!
//! The port-mapping protocol most consumer routers actually speak. Three plain-text
//! exchanges, all on the LAN, none of them needing a library:
//!
//! 1. **SSDP** (UPnP Device Architecture §1.3): an `M-SEARCH` sent to
//!    `239.255.255.250:1900` asking for an `InternetGatewayDevice`; the router answers
//!    by unicast with a `LOCATION` URL.
//! 2. **Description**: an HTTP `GET` of that URL returns XML naming the device's
//!    services; the one this needs is `WANIPConnection` (or `WANPPPConnection` on
//!    a router that terminates PPPoE itself), whose `<controlURL>` is where commands
//!    go — relative to `<URLBase>` if the description has one, else to `LOCATION`.
//! 3. **SOAP** (IGD:1 *WANIPConnection:1* service): `AddPortMapping`,
//!    `GetExternalIPAddress`, `DeletePortMapping`, each an HTTP `POST` with a
//!    `SOAPAction` header and a small XML envelope.
//!
//! ## Why this was omitted, and why it is here now
//! ADR-012 first recorded UPnP as a deliberate omission: CallStranger
//! (CVE-2020-12695) and a large parser surface for what looked like marginal gain
//! over PCP. The gain is not marginal — on home routers UPnP is the *common* one of
//! the three, and it is what lets the user's own anchor forward its port without
//! touching the router, and what lets two peers with no anchor at all find a direct
//! path when one of them has a cooperative router (ADR-016 M15.1c). The security
//! posture is unchanged: nothing a router says is trusted for anything but a
//! mapping that can only waste a dial, and the client is hardened where it listens:
//!
//! - the `LOCATION` a responder hands out is followed **only on the responder's own
//!   address** — a device on the LAN cannot make this node fetch from anywhere else;
//! - every read is bounded (`MAX_DESCRIPTION_BYTES`, `MAX_SOAP_BYTES`) and timed;
//! - the XML is *scanned* for a handful of known elements, never parsed generally,
//!   so there is no XML parser to attack.
//!
//! ## Leases
//! A mapping is asked for with a lease so it dies with the node; a router that
//! answers `725 OnlyPermanentLeasesSupported` gets the request again with lease 0,
//! and the node then **deletes** that mapping when it locks or shuts down. A router
//! that ignores the lease silently is indistinguishable from one that honours it;
//! the node's renewal (at half the lifetime) re-adds either way.
//!
//! No real router answered SSDP on the network this was written on, so the proof is
//! an in-process gateway that follows the specifications exactly, plus the quirks
//! real routers are known for. Validation against real hardware is recorded as
//! pending in ADR-012.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::error::{Error, Result};
use crate::nat::portmap::Protocol;

/// The SSDP multicast group and port (UPnP Device Architecture 1.1 §1.2).
pub const SSDP_MULTICAST: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);

/// How long to collect SSDP answers. The `MX` a responder is given is 2 s; this is
/// slightly longer so a late one still lands.
pub const SSDP_TIMEOUT: Duration = Duration::from_millis(2500);

/// How long one HTTP exchange with the router may take, connect included.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest device description this will read. Real ones are a few KiB; a device
/// that sends more than this is not being asked for a port.
pub const MAX_DESCRIPTION_BYTES: usize = 64 * 1024;

/// The largest SOAP response this will read.
pub const MAX_SOAP_BYTES: usize = 16 * 1024;

/// The search target: the IGD root device. An IGD:2 router answers a version-1
/// search too (UDA §1.3.2: a device matches any lower version of its type).
const SEARCH_TARGET: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

/// What this node calls its mappings on the router, so a user looking at the
/// router's table knows whose they are.
const MAPPING_DESCRIPTION: &str = "Vox";

/// The IGD error a router that will not grant timed leases answers with
/// (WANIPConnection:1 §2.4.16).
const ONLY_PERMANENT_LEASES: u32 = 725;

/// A gateway whose control URL is known: where the SOAP requests go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IgdGateway {
    /// The router's address, as it answered SSDP — every request goes here.
    pub router: IpAddr,
    /// Host and port of the control URL (on `router`, by construction).
    pub control_host: SocketAddr,
    /// Path of the control URL.
    pub control_path: String,
    /// The exact service type string the description declared, e.g.
    /// `urn:schemas-upnp-org:service:WANIPConnection:1`; the SOAP namespace and
    /// action header quote it back.
    pub service_type: String,
}

/// Find an Internet Gateway Device by SSDP, sending the search to `target` —
/// [`SSDP_MULTICAST`] in production, a unicast address in tests — from a socket
/// bound to `bind`. Returns the first responder whose description names a usable
/// WAN connection service.
pub async fn discover(bind: Ipv4Addr, target: SocketAddr, timeout: Duration) -> Result<IgdGateway> {
    let socket = UdpSocket::bind((bind, 0))
        .await
        .map_err(|_| Error::PortMappingFailed("upnp: ssdp socket bind failed"))?;
    let search = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {}:{}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {SEARCH_TARGET}\r\n\r\n",
        SSDP_MULTICAST.ip(),
        SSDP_MULTICAST.port()
    );
    socket
        .send_to(search.as_bytes(), target)
        .await
        .map_err(|_| Error::PortMappingFailed("upnp: ssdp send failed"))?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    let mut last: Option<Error> = None;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok(Ok((n, from))) = tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        let Some(location) = ssdp_location(&buf[..n]) else {
            continue;
        };
        match describe(from.ip(), &location).await {
            Ok(gw) => return Ok(gw),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or(Error::PortMappingFailed("upnp: no gateway answered")))
}

/// The `LOCATION` header of an SSDP `200 OK`, if the datagram is one.
fn ssdp_location(datagram: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(datagram).ok()?;
    let mut lines = text.split("\r\n");
    let status = lines.next()?;
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return None;
    }
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("location") {
                return Some(value.trim().to_owned());
            }
        }
    }
    None
}

/// Fetch and scan a device description at `location`, which must be on
/// `responder`: the address that answered SSDP is the only one this will talk to.
async fn describe(responder: IpAddr, location: &str) -> Result<IgdGateway> {
    let (host, path) = parse_http_url(location)?;
    if host.ip() != responder {
        return Err(Error::PortMappingFailed(
            "upnp: location is not on the responder",
        ));
    }
    let (status, body) = http(host, "GET", &path, &[], b"", MAX_DESCRIPTION_BYTES).await?;
    if status != 200 {
        return Err(Error::PortMappingFailed("upnp: description not served"));
    }
    let text = String::from_utf8_lossy(&body);
    let (service_type, control) = wan_connection_service(&text)
        .ok_or(Error::PortMappingFailed("upnp: no WAN connection service"))?;
    // The control URL is absolute, or relative to URLBase, or relative to LOCATION.
    let base = element(&text, "URLBase")
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| location.to_owned());
    let (control_host, control_path) = if control.starts_with("http://") {
        parse_http_url(&control)?
    } else {
        let (base_host, base_path) = parse_http_url(&base)?;
        let path = if control.starts_with('/') {
            control
        } else {
            let dir = base_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
            format!("{dir}/{control}")
        };
        (base_host, path)
    };
    if control_host.ip() != responder {
        return Err(Error::PortMappingFailed(
            "upnp: control url is not on the responder",
        ));
    }
    Ok(IgdGateway {
        router: responder,
        control_host,
        control_path,
        service_type,
    })
}

/// The first `<service>` whose type is a WAN connection, as `(serviceType,
/// controlURL)`. IP connection is preferred over PPP when both are present.
fn wan_connection_service(description: &str) -> Option<(String, String)> {
    let mut ppp: Option<(String, String)> = None;
    let mut rest = description;
    while let Some(start) = rest.find("<service>") {
        let after = &rest[start + "<service>".len()..];
        let end = after.find("</service>")?;
        let block = &after[..end];
        rest = &after[end..];
        let (Some(st), Some(url)) = (element(block, "serviceType"), element(block, "controlURL"))
        else {
            continue;
        };
        let (st, url) = (st.trim().to_owned(), url.trim().to_owned());
        if st.contains(":service:WANIPConnection:") {
            return Some((st, url));
        }
        if st.contains(":service:WANPPPConnection:") && ppp.is_none() {
            ppp = Some((st, url));
        }
    }
    ppp
}

/// The text of the first `<name>…</name>` element, ignoring a namespace prefix on
/// the tag. This is a scan, not a parse: the elements looked for are leaf strings.
fn element<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = match text.find(&open) {
        Some(i) => i + open.len(),
        None => {
            // A prefixed form like `<u:name>`: find `:name>` preceded by `<`.
            let needle = format!(":{name}>");
            let i = text.find(&needle)?;
            i + needle.len()
        }
    };
    let rest = &text[start..];
    let end = rest.find(&close).or_else(|| {
        rest.find(&format!(":{name}>"))
            .and_then(|i| rest[..i].rfind('<'))
    })?;
    Some(&rest[..end])
}

/// `http://host[:port]/path` → (`host:port`, `/path`). Only plain HTTP, only a
/// literal IPv4 host: a router names itself by address, and a hostname would be
/// something to resolve — and to be lied to about.
fn parse_http_url(url: &str) -> Result<(SocketAddr, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or(Error::PortMappingFailed("upnp: url is not http"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_owned()),
        None => (rest, "/".to_owned()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| Error::PortMappingFailed("upnp: url port"))?,
        ),
        None => (hostport, 80),
    };
    let ip: Ipv4Addr = host
        .parse()
        .map_err(|_| Error::PortMappingFailed("upnp: url host is not an IPv4 address"))?;
    Ok((SocketAddr::new(IpAddr::V4(ip), port), path))
}

/// One bounded HTTP/1.x exchange: `Connection: close`, the body read to EOF (or to
/// `Content-Length`), `Transfer-Encoding: chunked` decoded. Returns the status and
/// the body.
async fn http(
    host: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    max_body: usize,
) -> Result<(u16, Vec<u8>)> {
    tokio::time::timeout(HTTP_TIMEOUT, async {
        let mut stream = TcpStream::connect(host)
            .await
            .map_err(|_| Error::PortMappingFailed("upnp: connect failed"))?;
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        for (k, v) in headers {
            req.push_str(k);
            req.push_str(": ");
            req.push_str(v);
            req.push_str("\r\n");
        }
        if !body.is_empty() || method == "POST" {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|_| Error::PortMappingFailed("upnp: write failed"))?;
        if !body.is_empty() {
            stream
                .write_all(body)
                .await
                .map_err(|_| Error::PortMappingFailed("upnp: write failed"))?;
        }
        // Read everything, bounded: headers plus body may not exceed the cap.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|_| Error::PortMappingFailed("upnp: read failed"))?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            if raw.len() > max_body + 8 * 1024 {
                return Err(Error::PortMappingFailed("upnp: response too large"));
            }
        }
        parse_http_response(&raw, max_body)
    })
    .await
    .map_err(|_| Error::PortMappingFailed("upnp: http timed out"))?
}

/// Split an HTTP response into status and decoded body.
fn parse_http_response(raw: &[u8], max_body: usize) -> Result<(u16, Vec<u8>)> {
    let split =
        find(raw, b"\r\n\r\n").ok_or(Error::PortMappingFailed("upnp: malformed response"))?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| Error::PortMappingFailed("upnp: malformed response"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(Error::PortMappingFailed("upnp: malformed status"))?;
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            if name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            } else if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.parse().ok();
            }
        }
    }
    let payload = &raw[split + 4..];
    let body = if chunked {
        dechunk(payload)?
    } else {
        match content_length {
            Some(n) if n <= payload.len() => payload[..n].to_vec(),
            _ => payload.to_vec(),
        }
    };
    if body.len() > max_body {
        return Err(Error::PortMappingFailed("upnp: response too large"));
    }
    Ok((status, body))
}

/// Decode a `Transfer-Encoding: chunked` body (RFC 9112 §7.1).
fn dechunk(mut payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find(payload, b"\r\n").ok_or(Error::PortMappingFailed("upnp: bad chunk"))?;
        let size_text = std::str::from_utf8(&payload[..line_end])
            .map_err(|_| Error::PortMappingFailed("upnp: bad chunk"))?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| Error::PortMappingFailed("upnp: bad chunk"))?;
        payload = &payload[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if payload.len() < size + 2 {
            return Err(Error::PortMappingFailed("upnp: truncated chunk"));
        }
        out.extend_from_slice(&payload[..size]);
        payload = &payload[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Send one SOAP action to the gateway and return the response body on success.
/// A UPnP error (HTTP 500 with a `<errorCode>`) is returned as `Err` with the code.
async fn soap(
    gw: &IgdGateway,
    action: &str,
    arguments: &str,
) -> std::result::Result<String, SoapFailure> {
    let envelope = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{st}\">{arguments}</u:{action}></s:Body></s:Envelope>\r\n",
        st = gw.service_type
    );
    let soap_action = format!("\"{}#{action}\"", gw.service_type);
    let (status, body) = http(
        gw.control_host,
        "POST",
        &gw.control_path,
        &[
            ("Content-Type", "text/xml; charset=\"utf-8\""),
            ("SOAPAction", &soap_action),
        ],
        envelope.as_bytes(),
        MAX_SOAP_BYTES,
    )
    .await
    .map_err(SoapFailure::Transport)?;
    let text = String::from_utf8_lossy(&body).into_owned();
    if status == 200 {
        return Ok(text);
    }
    let code = element(&text, "errorCode")
        .and_then(|c| c.trim().parse::<u32>().ok())
        .unwrap_or(0);
    Err(SoapFailure::Upnp(code))
}

/// Why a SOAP action did not succeed.
#[derive(Debug)]
enum SoapFailure {
    /// The exchange itself failed.
    Transport(Error),
    /// The gateway answered with a UPnP error code (0 if it gave none).
    Upnp(u32),
}

/// Ask the gateway to forward `external_port` to `internal_client:internal_port`
/// for `lease_secs`. Returns the lease the mapping was granted with: `lease_secs`,
/// or `0` (permanent) when the router only grants those — the caller must then
/// delete the mapping itself when it no longer wants it.
pub async fn add_port_mapping(
    gw: &IgdGateway,
    protocol: Protocol,
    external_port: u16,
    internal_port: u16,
    internal_client: Ipv4Addr,
    lease_secs: u32,
) -> Result<u32> {
    let request = |lease: u32| {
        format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>{}</NewProtocol><NewInternalPort>{internal_port}</NewInternalPort>\
             <NewInternalClient>{internal_client}</NewInternalClient><NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>{MAPPING_DESCRIPTION}</NewPortMappingDescription>\
             <NewLeaseDuration>{lease}</NewLeaseDuration>",
            protocol.upnp_name()
        )
    };
    match soap(gw, "AddPortMapping", &request(lease_secs)).await {
        Ok(_) => Ok(lease_secs),
        Err(SoapFailure::Upnp(ONLY_PERMANENT_LEASES)) if lease_secs != 0 => {
            match soap(gw, "AddPortMapping", &request(0)).await {
                Ok(_) => Ok(0),
                Err(_) => Err(Error::PortMappingFailed("upnp: mapping refused")),
            }
        }
        Err(SoapFailure::Transport(e)) => Err(e),
        Err(SoapFailure::Upnp(_)) => Err(Error::PortMappingFailed("upnp: mapping refused")),
    }
}

/// Remove a mapping this node added.
pub async fn delete_port_mapping(
    gw: &IgdGateway,
    protocol: Protocol,
    external_port: u16,
) -> Result<()> {
    let args = format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort>\
         <NewProtocol>{}</NewProtocol>",
        protocol.upnp_name()
    );
    match soap(gw, "DeletePortMapping", &args).await {
        Ok(_) => Ok(()),
        Err(SoapFailure::Transport(e)) => Err(e),
        Err(SoapFailure::Upnp(_)) => Err(Error::PortMappingFailed("upnp: delete refused")),
    }
}

/// The gateway's WAN address, as it reports it.
pub async fn get_external_ip(gw: &IgdGateway) -> Result<Ipv4Addr> {
    let body = soap(gw, "GetExternalIPAddress", "")
        .await
        .map_err(|e| match e {
            SoapFailure::Transport(e) => e,
            SoapFailure::Upnp(_) => Error::PortMappingFailed("upnp: external ip refused"),
        })?;
    element(&body, "NewExternalIPAddress")
        .and_then(|s| s.trim().parse::<Ipv4Addr>().ok())
        .filter(|ip| !ip.is_unspecified())
        .ok_or(Error::PortMappingFailed("upnp: no external ip"))
}

impl Protocol {
    /// The IGD protocol name (`UDP` / `TCP`).
    #[must_use]
    pub fn upnp_name(self) -> &'static str {
        match self {
            Protocol::Udp => "UDP",
            Protocol::Tcp => "TCP",
        }
    }
}
