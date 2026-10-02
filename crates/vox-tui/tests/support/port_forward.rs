//! A **port forward** the proof owns: a UDP socket on `[::1]` that carries datagrams to and from a
//! host bound to `127.0.0.1`, the way a router's port forward carries them to a machine on its LAN.
//! It adds no delay unless told to (`set_delay`, guest → host), and it can be **closed** (every datagram both ways is dropped) and opened
//! again while the processes behind it keep running.
//!
//! Why it exists: on loopback, split by address family, a host on `127.0.0.1` and a guest on `[::1]`
//! cannot send each other a datagram — an IPv4 socket cannot address `::1`, and a socket bound to
//! `::1` cannot send to `127.0.0.1` (see `relay.rs`). With the host told to advertise this forward's
//! address (`VOX_TEST_ADVERTISE`, the knob the R41 proof points a host at its link emulator with),
//! **the forward is the only direct path between them**: the host's own address and the one the
//! anchor observes for it are IPv4, which the guest cannot reach. So:
//!
//! - every byte that moves between them **not** through the anchor's circuit moves through here,
//!   which makes "the pair is on a direct path" something this file *counts*, not something a proof
//!   infers from timing or from the anchor's delayed circuit report;
//! - closing it takes the direct path away, and opening it gives it back, without touching either
//!   `vox` process — a network changing underneath a pair, which is what a path-upgrade retry is
//!   for.
//!
//! Each guest source address gets its own inside socket towards the host, so the host sees each
//! guest as a distinct peer address, as behind a real forward. The first datagram from each source
//! is timestamped where it arrives, so a proof can tell when a dial *began*, even one the node
//! started on its own before the proof asked it anything.
//!
//! **Every red here names its side** (V210-106), as in `world.rs`: the forward's own sockets are
//! the apparatus, and an `APPARATUS:` red names which one failed.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct State {
    open: AtomicBool,
    stop: AtomicBool,
    /// Datagram payload bytes carried guest → host.
    to_host: AtomicU64,
    /// Datagram payload bytes carried host → guest.
    to_guest: AtomicU64,
    /// Datagrams dropped (either way) while closed.
    dropped: AtomicU64,
    /// When the first datagram from each guest source arrived, open or not.
    first_seen: Mutex<HashMap<SocketAddr, Instant>>,
    /// How long each datagram guest → host is held before it is sent on, in microseconds; 0 sends
    /// at once. A path with latency, as a real one has (V210-122).
    delay_us: AtomicU64,
}

pub struct PortForward {
    /// The forward's public address — what the host advertises.
    pub public: SocketAddr,
    /// The host behind it.
    pub host: SocketAddr,
    state: Arc<State>,
}

impl PortForward {
    /// A forward from a fresh `[::1]` port to `host`, `open` or closed from the start.
    pub fn start(host: SocketAddr, open: bool) -> Self {
        let public_sock = UdpSocket::bind("[::1]:0").unwrap_or_else(|e| {
            panic!("APPARATUS: could not bind the port forward's public socket: {e}")
        });
        let public = public_sock
            .local_addr()
            .unwrap_or_else(|e| panic!("APPARATUS: the port forward's public socket: {e}"));
        public_sock
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap_or_else(|e| panic!("APPARATUS: the port forward's public socket: {e}"));
        let state = Arc::new(State::default());
        state.open.store(open, Ordering::SeqCst);
        let st = Arc::clone(&state);
        // Delayed datagrams guest → host, in arrival order: one constant delay keeps them in order.
        let (late, due) = std::sync::mpsc::channel::<(Arc<UdpSocket>, Vec<u8>, Instant)>();
        let late_st = Arc::clone(&state);
        std::thread::spawn(move || {
            while let Ok((sock, data, at)) = due.recv() {
                std::thread::sleep(at.saturating_duration_since(Instant::now()));
                if sock.send(&data).is_ok() {
                    late_st
                        .to_host
                        .fetch_add(data.len() as u64, Ordering::SeqCst);
                }
            }
        });
        std::thread::spawn(move || {
            let public_sock = Arc::new(public_sock);
            let mut inside: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut buf = vec![0u8; 65536];
            while !st.stop.load(Ordering::SeqCst) {
                let (n, from) = match public_sock.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let at = Instant::now();
                st.first_seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .entry(from)
                    .or_insert(at);
                if !st.open.load(Ordering::SeqCst) {
                    st.dropped.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                let sock = inside.entry(from).or_insert_with(|| {
                    let s = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| {
                        panic!("APPARATUS: could not bind a port forward inside socket: {e}")
                    });
                    s.connect(host).unwrap_or_else(|e| {
                        panic!(
                            "APPARATUS: could not aim a port forward inside socket at {host}: {e}"
                        )
                    });
                    s.set_read_timeout(Some(Duration::from_millis(50)))
                        .unwrap_or_else(|e| panic!("APPARATUS: a port forward inside socket: {e}"));
                    let s = Arc::new(s);
                    let (back, public, st) =
                        (Arc::clone(&s), Arc::clone(&public_sock), Arc::clone(&st));
                    std::thread::spawn(move || {
                        let mut buf = vec![0u8; 65536];
                        while !st.stop.load(Ordering::SeqCst) {
                            let Ok(n) = back.recv(&mut buf) else { continue };
                            if !st.open.load(Ordering::SeqCst) {
                                st.dropped.fetch_add(1, Ordering::SeqCst);
                                continue;
                            }
                            if public.send_to(&buf[..n], from).is_ok() {
                                st.to_guest.fetch_add(n as u64, Ordering::SeqCst);
                            }
                        }
                    });
                    s
                });
                let delay = Duration::from_micros(st.delay_us.load(Ordering::SeqCst));
                if !delay.is_zero() {
                    let _ = late.send((Arc::clone(sock), buf[..n].to_vec(), at + delay));
                } else if sock.send(&buf[..n]).is_ok() {
                    st.to_host.fetch_add(n as u64, Ordering::SeqCst);
                }
            }
        });
        Self {
            public,
            host,
            state,
        }
    }

    /// Hold every datagram guest → host for `delay` from now on (zero: none).
    pub fn set_delay(&self, delay: Duration) {
        self.state.delay_us.store(
            u64::try_from(delay.as_micros()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    pub fn open(&self) {
        self.state.open.store(true, Ordering::SeqCst);
    }

    pub fn close(&self) {
        self.state.open.store(false, Ordering::SeqCst);
    }

    /// Bytes carried guest → host so far.
    pub fn to_host(&self) -> u64 {
        self.state.to_host.load(Ordering::SeqCst)
    }

    /// Bytes carried host → guest so far.
    pub fn to_guest(&self) -> u64 {
        self.state.to_guest.load(Ordering::SeqCst)
    }

    /// Datagrams dropped while closed.
    pub fn dropped(&self) -> u64 {
        self.state.dropped.load(Ordering::SeqCst)
    }

    /// Every guest source seen so far, with when its first datagram arrived.
    pub fn sources(&self) -> HashMap<SocketAddr, Instant> {
        self.state
            .first_seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Drop for PortForward {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
    }
}

/// A free UDP port on `127.0.0.1`, for a host whose address the forward must know before the host
/// starts. Released before it is returned, so another process could take it first; the host then
/// fails to bind and says so, which is a loud failure, never a wrong measurement.
pub fn free_v4_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .unwrap_or_else(|e| panic!("APPARATUS: no free UDP port on 127.0.0.1: {e}"))
        .port()
}

/// One dual-stack anchor, a `vox serve` host on `127.0.0.1` behind a [`PortForward`] it advertises,
/// and a guest on `[::1]` that the host trusts and that has joined the host's room. The guest's
/// only direct path to the host is the forward; its other path is the anchor's circuit.
///
/// Needs `world.rs` and `relay.rs` included next to it.
pub struct ForwardedWorld {
    pub tmp: tempfile::TempDir,
    pub anchor: crate::relay::Anchor,
    pub forward: PortForward,
    pub host: crate::world::VoxProc,
    pub host_dir: std::path::PathBuf,
    pub guest_dir: std::path::PathBuf,
    pub host_fp: String,
    pub room: String,
    pub address: String,
    pub passphrase: String,
    pub service_port: u16,
    /// How long the guest's `vox connect` took, and what it said on stderr.
    pub joined_in: Duration,
    pub join_stderr: String,
}

impl ForwardedWorld {
    /// Refuses as CANNOT MEASURE, naming the `test-knobs` feature, a `vox` that does not read
    /// `VOX_TEST_ADVERTISE`: without it the host advertises its real address, the forward is never
    /// used, and the world is not the one its proofs measure (V210-105).
    pub fn new(forward_open: bool) -> Self {
        use crate::world::{
            after_label, args, echo_service, fingerprint, mkdir, vox_once, VoxProc,
        };
        crate::test_knobs::require(&["VOX_TEST_ADVERTISE"]);
        let tmp = crate::world::tempdir();
        let (anchor_dir, host_dir, guest_dir) = (
            tmp.path().join("anchor"),
            tmp.path().join("host"),
            tmp.path().join("guest"),
        );
        for d in [&anchor_dir, &host_dir, &guest_dir] {
            mkdir(&d.join("cfg"));
        }
        let anchor = crate::relay::Anchor::start(&anchor_dir);

        let guest_fp = fingerprint(&guest_dir, "guest");
        let host_fp = fingerprint(&host_dir, "host");
        let (ok, out, err) = vox_once(
            &host_dir,
            &args(&["trust", "add", &guest_fp, "--name", "the guest"]),
        );
        assert!(
            ok,
            "PRODUCT (staging): the host's `vox trust add` of the guest failed.\nstdout:\n{out}\nstderr:\n{err}"
        );

        let host_port = free_v4_udp_port();
        let host_addr = SocketAddr::from(([127, 0, 0, 1], host_port));
        let forward = PortForward::start(host_addr, forward_open);
        let advertise = forward.public.to_string();
        let service_port = echo_service();
        let mut host = VoxProc::spawn_env(
            "host",
            &host_dir,
            &args(&[
                "serve",
                &service_port.to_string(),
                "--anchor",
                &anchor.v4_spec,
                "--listen",
                &host_addr.to_string(),
            ]),
            &[("VOX_TEST_ADVERTISE", advertise.as_str())],
        );
        let room = after_label(
            &host.expect_line("room", |l| l.starts_with("room ")),
            "room",
        );
        let address = after_label(
            &host.expect_line("address", |l| l.starts_with("address ")),
            "address",
        );
        let passphrase = after_label(
            &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
            "passphrase",
        );
        let t0 = Instant::now();
        let (ok, out, err) = vox_once(
            &guest_dir,
            &args(&[
                "connect",
                &address,
                "--passphrase-file",
                &crate::world::room_pass_file(&guest_dir, &passphrase),
                "--anchor",
                &anchor.v6_spec,
                "--listen",
                "[::1]:0",
            ]),
        );
        let joined_in = t0.elapsed();
        assert!(
            ok,
            "PRODUCT (staging): the guest on [::1] could not join the host's room the moment \
             `vox serve` printed its address (after {joined_in:?}), which leads to the room when it \
             is printed (V210-96). `vox connect` said:\nstdout:\n{out}\nstderr:\n{err}\nhost:\n{}",
            host.transcript()
        );
        Self {
            tmp,
            anchor,
            forward,
            host,
            host_dir,
            guest_dir,
            host_fp,
            room,
            address,
            passphrase,
            service_port,
            joined_in,
            join_stderr: err,
        }
    }

    /// The name the host's service answers on through `vox up`.
    pub fn hostname(&self) -> String {
        format!("{}.vox", self.room)
    }

    /// Start the guest's `vox up` on `[::1]`; returns it, the SOCKS address it bound, and when it
    /// said so — the earliest moment a person could ask it for anything.
    pub fn up(&self, name: &str) -> (crate::world::VoxProc, SocketAddr, Instant) {
        use crate::world::{args, room_pass_file, VoxProc};
        let mut up = VoxProc::spawn(
            name,
            &self.guest_dir,
            &args(&[
                "up",
                &self.room,
                "--passphrase-file",
                &room_pass_file(&self.guest_dir, &self.passphrase),
                "--bind",
                "127.0.0.1:0",
                "--anchor",
                &self.anchor.v6_spec,
                "--listen",
                "[::1]:0",
            ]),
        );
        let line = up.expect_line("the proxy's bound address", |l| l.starts_with("vox up on "));
        let ready = Instant::now();
        let bound = crate::world::address_in(&mut up, &line, 3);
        (up, bound, ready)
    }
}

/// Stop a `vox` process the way a person does — Ctrl-C, by its PID — and wait up to `within` for it
/// to exit. A process that does not is killed by its handle when dropped. A Ctrl-C that could not
/// be sent is `APPARATUS:` — the process would be "still running" for a reason of the proof's own.
pub fn interrupt(p: &mut crate::world::VoxProc, within: Duration) -> bool {
    let pid = p.child.id().to_string();
    if let Ok(Some(status)) = p.child.try_wait() {
        eprintln!(
            "[harness] {} had already exited ({status}) before Ctrl-C",
            p.name
        );
        return true;
    }
    match std::process::Command::new("kill")
        .args(["-INT", &pid])
        .output()
    {
        Ok(o) if o.status.success() => {}
        Ok(o) => panic!(
            "APPARATUS: `kill -INT {pid}` did not take ({}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => panic!("APPARATUS: could not run `kill -INT {pid}`: {e}"),
    }
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(Some(_)) = p.child.try_wait() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// One echo round trip of `payload` over a SOCKS stream the proxy said succeeded on, with a read
/// deadline. Returns whether the echo came back whole.
pub fn echo_over(s: &mut std::net::TcpStream, payload: &[u8], within: Duration) -> bool {
    use std::io::{Read, Write};
    let _ = s.set_read_timeout(Some(within));
    if s.write_all(payload).is_err() {
        return false;
    }
    let mut back = vec![0u8; payload.len()];
    s.read_exact(&mut back).is_ok() && back == payload
}
