//! **A UPnP Internet Gateway Device stand-in** that a proof runs on loopback and points `vox` at
//! with the test-knobs override `VOX_TEST_UPNP` (ADR-012 N-58): SSDP, the device description, and
//! the three WANIPConnection:1 actions `vox` uses — `AddPortMapping`, `GetExternalIPAddress` and
//! `DeletePortMapping`.
//!
//! An SSDP search is answered [`UpnpStandin::start`]'s `ssdp_delay` after it came: UPnP lets a
//! device wait up to the search's `MX` (2 s) before it answers, so a slow answer is a real
//! router's. Every search and every SOAP action is logged with when it came, so a proof can tell
//! a deletion that went straight to the control URL from one that searched first.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The WAN address the stand-in reports (RFC 5737 TEST-NET-3).
pub const EXTERNAL: &str = "203.0.113.9";
const SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

/// One thing the stand-in was asked.
#[derive(Clone, Debug)]
pub struct Asked {
    /// When it came.
    pub at: Instant,
    /// `search`, or the SOAP action's name.
    pub what: String,
    /// The external port a mapping action named, if any.
    pub port: Option<u16>,
}

/// A running stand-in; it stops when dropped.
pub struct UpnpStandin {
    /// The SSDP address: what `VOX_TEST_UPNP` names.
    pub ssdp: SocketAddr,
    /// The HTTP address of the description and the control URL.
    pub http: SocketAddr,
    log: Arc<Mutex<Vec<Asked>>>,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The text of `<name>…</name>` in `body`.
fn element(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{name}>"))?;
    Some(body[start..start + end].trim().to_owned())
}

impl UpnpStandin {
    /// Start a stand-in on IPv4 loopback that answers each SSDP search after `ssdp_delay`.
    pub fn start(ssdp_delay: Duration) -> Self {
        let udp = UdpSocket::bind("127.0.0.1:0")
            .unwrap_or_else(|e| panic!("APPARATUS: the UPnP stand-in cannot bind SSDP: {e}"));
        udp.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap_or_else(|e| panic!("APPARATUS: the UPnP stand-in's read timeout: {e}"));
        let tcp = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|e| panic!("APPARATUS: the UPnP stand-in cannot bind HTTP: {e}"));
        tcp.set_nonblocking(true)
            .unwrap_or_else(|e| panic!("APPARATUS: the UPnP stand-in's listener: {e}"));
        let ssdp = udp.local_addr().expect("APPARATUS: the SSDP address");
        let http = tcp.local_addr().expect("APPARATUS: the HTTP address");
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let (l, s) = (Arc::clone(&log), Arc::clone(&stop));
        let ssdp_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !s.load(Ordering::SeqCst) {
                let Ok((n, from)) = udp.recv_from(&mut buf) else {
                    continue;
                };
                if !buf[..n].starts_with(b"M-SEARCH") {
                    continue;
                }
                lock(&l).push(Asked {
                    at: Instant::now(),
                    what: "search".to_owned(),
                    port: None,
                });
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: \
                     urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: \
                     http://{http}/desc.xml\r\n\r\n"
                );
                let Ok(socket) = udp.try_clone() else {
                    continue;
                };
                std::thread::spawn(move || {
                    std::thread::sleep(ssdp_delay);
                    let _ = socket.send_to(reply.as_bytes(), from);
                });
            }
        });

        let (l, s) = (Arc::clone(&log), Arc::clone(&stop));
        let http_thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match tcp.accept() {
                    Ok((stream, _)) => {
                        let l = Arc::clone(&l);
                        std::thread::spawn(move || serve_http(stream, http, &l));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Self {
            ssdp,
            http,
            log,
            stop,
            threads: vec![ssdp_thread, http_thread],
        }
    }

    /// Everything asked so far, in order.
    pub fn log(&self) -> Vec<Asked> {
        lock(&self.log).clone()
    }
}

impl Drop for UpnpStandin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// One HTTP exchange: the description, or one SOAP action.
fn serve_http(stream: std::net::TcpStream, http: SocketAddr, log: &Mutex<Vec<Asked>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut length = 0usize;
    let mut action = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                length = value.parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("soapaction") {
                action = value
                    .trim_matches('"')
                    .rsplit('#')
                    .next()
                    .unwrap_or("")
                    .to_owned();
            }
        }
    }
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body).into_owned();
    let reply = if request_line.starts_with("GET") {
        format!(
            "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><URLBase>\
             http://{http}/</URLBase><device><deviceType>\
             urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><serviceList>\
             <service><serviceType>{SERVICE}</serviceType><controlURL>/ctl</controlURL>\
             </service></serviceList></device></root>"
        )
    } else {
        log.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Asked {
                at: Instant::now(),
                what: action.clone(),
                port: element(&body, "NewExternalPort").and_then(|p| p.parse().ok()),
            });
        let inner = if action == "GetExternalIPAddress" {
            format!("<NewExternalIPAddress>{EXTERNAL}</NewExternalIPAddress>")
        } else {
            String::new()
        };
        format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
             <s:Body><u:{action}Response xmlns:u=\"{SERVICE}\">{inner}</u:{action}Response>\
             </s:Body></s:Envelope>"
        )
    };
    let mut stream = reader.into_inner();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
}
