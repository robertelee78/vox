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
//! server. [`Standin::set_silent`] stops it answering anything, as a server gone away.

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
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Standin {
    /// Start a stand-in on IPv4 loopback that grants at most `grant` seconds.
    pub fn start(grant: u32) -> Self {
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
        let stop = Arc::new(AtomicBool::new(false));
        let (l, q, s) = (Arc::clone(&log), Arc::clone(&silent), Arc::clone(&stop));
        let thread = std::thread::spawn(move || serve(&socket, grant, &l, &q, &s));
        Self {
            addr,
            log,
            silent,
            stop,
            thread: Some(thread),
        }
    }

    /// Stop (or resume) answering; requests are still logged.
    pub fn set_silent(&self, silent: bool) {
        self.silent.store(silent, Ordering::SeqCst);
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

fn serve(
    socket: &UdpSocket,
    grant: u32,
    log: &Mutex<Vec<Request>>,
    silent: &AtomicBool,
    stop: &AtomicBool,
) {
    let mut held: BTreeMap<(Ipv6Addr, u8, u16), Held> = BTreeMap::new();
    let mut next_port: u16 = 40_000;
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
        let _ = socket.send_to(&r, from);
    }
}
