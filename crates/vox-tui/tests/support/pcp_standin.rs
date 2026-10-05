//! **A PCP server stand-in** (RFC 6887, the MAP opcode only) that a proof runs and points `vox` at
//! with the test-knobs gateway override, `VOX_TEST_GATEWAY` (ADR-012 N-58).
//!
//! It keeps the server's side of the Simple Threat Model as the RFC writes it, so the product is
//! held to what a real server would do:
//! - a MAP with a lifetime creates or renews the mapping for (client address, protocol, internal
//!   port), granting at most [`Standin::start`]'s `grant` seconds;
//! - a MAP for a mapping held under **another nonce** is refused `NOT_AUTHORIZED` (§11.3), as is a
//!   deletion with another nonce;
//! - a MAP with lifetime 0 and the mapping's nonce deletes it (§15.1); deleting what is not held
//!   succeeds;
//! - a mapping not renewed by the end of its lifetime is gone.
//!
//! Every datagram it receives is logged with **when it came**, its nonce, its lifetime and what it
//! answered, so a proof can assert the nonces, the renewal times and the deletions. A datagram
//! that is not PCP (a NAT-PMP request, version 0) is logged and not answered: this is a PCP-only
//! server. [`Standin::set_silent`] stops it answering anything, as a server gone away;
//! [`Standin::set_delay`] answers late, as a slow server, having made the mapping on receipt.
//!
//! [`Standin::start_natpmp`] is a **NAT-PMP-only** server instead (RFC 6886): a PCP request is
//! answered "unsupported version", a map request is granted per internal port (lifetime 0
//! deletes it), and the external-address request is answered with [`EXTERNAL`]. A NAT-PMP request
//! has no nonce; its log entries carry zeros.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The external address the stand-in grants (RFC 5737 TEST-NET-3): never routed anywhere.
pub const EXTERNAL: [u8; 4] = [203, 0, 113, 7];

/// What the stand-in did with one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Created or renewed, for this many seconds.
    Granted(u32),
    /// Deleted (or not held): SUCCESS with lifetime 0.
    Deleted,
    /// Refused: the mapping is held under another nonce (§11.3).
    NotAuthorized,
    /// Not answered: the stand-in was silent.
    Silent,
    /// Not a PCP MAP request (NAT-PMP, say): logged, not answered.
    NotPcp,
    /// A PCP request to the NAT-PMP-only server: answered "unsupported version".
    Unsupported,
}

/// One datagram the stand-in received.
#[derive(Clone, Debug)]
pub struct Request {
    /// When it came.
    pub at: Instant,
    /// The mapping nonce it carried.
    pub nonce: [u8; 12],
    /// The lifetime it asked for (0 is a deletion).
    pub lifetime: u32,
    /// The internal port it is for.
    pub internal_port: u16,
    /// What was answered.
    pub answer: Answer,
}

/// A held mapping: its nonce, external port and end.
struct Held {
    nonce: [u8; 12],
    external_port: u16,
    until: Instant,
}

/// A running stand-in; it stops when dropped.
pub struct Standin {
    /// Where it listens: what `VOX_TEST_GATEWAY` names.
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<Request>>>,
    silent: Arc<AtomicBool>,
    delay: Arc<Mutex<Duration>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Standin {
    /// Start a PCP stand-in on IPv4 loopback that grants at most `grant` seconds.
    pub fn start(grant: u32) -> Self {
        Self::start_as(grant, false)
    }

    /// Start a NAT-PMP-only stand-in on IPv4 loopback that grants at most `grant` seconds.
    pub fn start_natpmp(grant: u32) -> Self {
        Self::start_as(grant, true)
    }

    fn start_as(grant: u32, natpmp: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .unwrap_or_else(|e| panic!("APPARATUS: the PCP stand-in cannot bind: {e}"));
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap_or_else(|e| panic!("APPARATUS: the PCP stand-in's read timeout: {e}"));
        let addr = socket
            .local_addr()
            .unwrap_or_else(|e| panic!("APPARATUS: the PCP stand-in's address: {e}"));
        let log = Arc::new(Mutex::new(Vec::new()));
        let silent = Arc::new(AtomicBool::new(false));
        let delay = Arc::new(Mutex::new(Duration::ZERO));
        let stop = Arc::new(AtomicBool::new(false));
        let (l, q, d, s) = (
            Arc::clone(&log),
            Arc::clone(&silent),
            Arc::clone(&delay),
            Arc::clone(&stop),
        );
        let thread = std::thread::spawn(move || {
            let on = Server {
                socket: &socket,
                grant,
                log: &l,
                silent: &q,
                delay: &d,
                stop: &s,
            };
            if natpmp {
                on.serve_natpmp();
            } else {
                on.serve();
            }
        });
        Self {
            addr,
            log,
            silent,
            delay,
            stop,
            thread: Some(thread),
        }
    }

    /// Stop (or resume) answering; requests are still logged.
    pub fn set_silent(&self, silent: bool) {
        self.silent.store(silent, Ordering::SeqCst);
    }

    /// Answer each request `delay` after it came (the mapping is made when it comes).
    pub fn set_delay(&self, delay: Duration) {
        *lock(&self.delay) = delay;
    }

    /// Every request so far, in the order received.
    pub fn log(&self) -> Vec<Request> {
        lock(&self.log).clone()
    }
}

impl Drop for Standin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The stand-in's thread: its socket, settings and log.
struct Server<'a> {
    socket: &'a UdpSocket,
    grant: u32,
    log: &'a Mutex<Vec<Request>>,
    silent: &'a AtomicBool,
    delay: &'a Mutex<Duration>,
    stop: &'a AtomicBool,
}

impl Server<'_> {
    /// Where this stand-in's external ports start: from its own port, so two stand-ins grant
    /// different external ports, as two routers do.
    fn port_base(&self) -> u16 {
        let own = self.socket.local_addr().map_or(0, |a| a.port());
        20_000 + own % 40_000
    }

    /// Send `reply` to `to`, after the delay set, on a thread of its own.
    fn answer(&self, reply: Vec<u8>, to: SocketAddr) {
        let delay = *lock(self.delay);
        if delay.is_zero() {
            let _ = self.socket.send_to(&reply, to);
            return;
        }
        if let Ok(socket) = self.socket.try_clone() {
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                let _ = socket.send_to(&reply, to);
            });
        }
    }

    /// The NAT-PMP-only server (RFC 6886).
    fn serve_natpmp(&self) {
        let mut held: BTreeMap<(u8, u16), (u16, Instant)> = BTreeMap::new();
        let mut next_port = self.port_base();
        let epoch = Instant::now();
        let mut buf = [0u8; 1100];
        while !self.stop.load(Ordering::SeqCst) {
            let Ok((n, from)) = self.socket.recv_from(&mut buf) else {
                continue;
            };
            let at = Instant::now();
            let m = &buf[..n];
            let secs = u32::try_from(epoch.elapsed().as_secs()).unwrap_or(u32::MAX);
            let quiet = self.silent.load(Ordering::SeqCst);
            match (m.first(), m.get(1)) {
                // PCP: this server speaks NAT-PMP only (RFC 6887 §9).
                (Some(2), _) => {
                    lock(self.log).push(Request {
                        at,
                        nonce: [0; 12],
                        lifetime: 0,
                        internal_port: 0,
                        answer: if quiet {
                            Answer::Silent
                        } else {
                            Answer::Unsupported
                        },
                    });
                    if !quiet {
                        let mut r = vec![0u8; 8];
                        r[1] = 0x80 | m.get(1).copied().unwrap_or(0);
                        r[3] = 1; // UNSUPP_VERSION
                        r[4..8].copy_from_slice(&secs.to_be_bytes());
                        self.answer(r, from);
                    }
                }
                // The external address (RFC 6886 §3.2).
                (Some(0), Some(0)) if !quiet => {
                    let mut r = vec![0u8; 12];
                    r[1] = 0x80;
                    r[4..8].copy_from_slice(&secs.to_be_bytes());
                    r[8..12].copy_from_slice(&EXTERNAL);
                    self.answer(r, from);
                }
                // A map request (RFC 6886 §3.3).
                (Some(0), Some(&op @ (1 | 2))) if n >= 12 => {
                    let internal_port = u16::from_be_bytes([m[4], m[5]]);
                    let lifetime = u32::from_be_bytes([m[8], m[9], m[10], m[11]]);
                    held.retain(|_, (_, until)| *until > at);
                    let (answer, port, life) = if quiet {
                        (Answer::Silent, 0, 0)
                    } else if lifetime == 0 {
                        held.remove(&(op, internal_port));
                        (Answer::Deleted, 0, 0)
                    } else {
                        let port = held.get(&(op, internal_port)).map_or_else(
                            || {
                                next_port += 1;
                                next_port
                            },
                            |h| h.0,
                        );
                        let life = lifetime.min(self.grant);
                        held.insert(
                            (op, internal_port),
                            (port, at + Duration::from_secs(u64::from(life))),
                        );
                        (Answer::Granted(life), port, life)
                    };
                    lock(self.log).push(Request {
                        at,
                        nonce: [0; 12],
                        lifetime,
                        internal_port,
                        answer,
                    });
                    if !quiet {
                        let mut r = vec![0u8; 16];
                        r[1] = 0x80 | op;
                        r[4..8].copy_from_slice(&secs.to_be_bytes());
                        r[8..10].copy_from_slice(&internal_port.to_be_bytes());
                        // A deletion answers with the internal port and external port 0.
                        r[10..12].copy_from_slice(&port.to_be_bytes());
                        r[12..16].copy_from_slice(&life.to_be_bytes());
                        self.answer(r, from);
                    }
                }
                _ => {}
            }
        }
    }

    /// The PCP server (RFC 6887).
    fn serve(&self) {
        let (socket, grant, log, silent, stop) =
            (self.socket, self.grant, self.log, self.silent, self.stop);
        let mut held: BTreeMap<(Ipv6Addr, u8, u16), Held> = BTreeMap::new();
        // Each stand-in's external ports are its own, as two routers' are.
        let mut next_port = self.port_base();
        let epoch = Instant::now();
        let mut buf = [0u8; 1100];
        while !stop.load(Ordering::SeqCst) {
            let Ok((n, from)) = socket.recv_from(&mut buf) else {
                continue;
            };
            let at = Instant::now();
            let m = &buf[..n];
            // A PCP MAP request: version 2, opcode 1 with R = 0, 60 bytes (§7.1, §11.1).
            if n < 60 || m[0] != 2 || m[1] != 1 {
                lock(log).push(Request {
                    at,
                    nonce: [0; 12],
                    lifetime: 0,
                    internal_port: 0,
                    answer: Answer::NotPcp,
                });
                continue;
            }
            let lifetime = u32::from_be_bytes([m[4], m[5], m[6], m[7]]);
            let mut client = [0u8; 16];
            client.copy_from_slice(&m[8..24]);
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&m[24..36]);
            let protocol = m[36];
            let internal_port = u16::from_be_bytes([m[40], m[41]]);
            let key = (Ipv6Addr::from(client), protocol, internal_port);
            held.retain(|_, h| h.until > at);
            let (answer, result, granted, external_port) = if silent.load(Ordering::SeqCst) {
                (Answer::Silent, 0, 0, 0)
            } else {
                match held.get(&key) {
                    Some(h) if h.nonce != nonce => (Answer::NotAuthorized, 2u8, 30, 0),
                    Some(_) if lifetime == 0 => {
                        held.remove(&key);
                        (Answer::Deleted, 0, 0, 0)
                    }
                    None if lifetime == 0 => (Answer::Deleted, 0, 0, 0),
                    found => {
                        let port = found.map_or_else(
                            || {
                                next_port += 1;
                                next_port
                            },
                            |h| h.external_port,
                        );
                        let life = lifetime.min(grant);
                        held.insert(
                            key,
                            Held {
                                nonce,
                                external_port: port,
                                until: at + Duration::from_secs(u64::from(life)),
                            },
                        );
                        (Answer::Granted(life), 0, life, port)
                    }
                }
            };
            lock(log).push(Request {
                at,
                nonce,
                lifetime,
                internal_port,
                answer,
            });
            if answer == Answer::Silent {
                continue;
            }
            // The MAP response (§7.2, §11.1): the request's MAP fields echoed, the grant filled in.
            let mut r = [0u8; 60];
            r[0] = 2;
            r[1] = 0x81;
            r[3] = result;
            r[4..8].copy_from_slice(&granted.to_be_bytes());
            let secs = u32::try_from(epoch.elapsed().as_secs()).unwrap_or(u32::MAX);
            r[8..12].copy_from_slice(&secs.to_be_bytes());
            r[24..36].copy_from_slice(&nonce);
            r[36] = protocol;
            r[40..42].copy_from_slice(&internal_port.to_be_bytes());
            r[42..44].copy_from_slice(&external_port.to_be_bytes());
            let ext = std::net::Ipv4Addr::from(EXTERNAL).to_ipv6_mapped().octets();
            r[44..60].copy_from_slice(&ext);
            self.answer(r.to_vec(), from);
        }
    }
}
