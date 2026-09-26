//! PRD-001 **R41** — a tunnel **must not throttle the network it runs over** (revised by the decider
//! on 2026-09-25: "we should figure out what the maximum throughput is for a network connection and we
//! should ensure that our overlay system doesn't completely nuke that").
//!
//! Driven entirely through the shipped binary, the way a person sets a tunnel up: `vox node` (an
//! anchor), `vox serve <port>` (the host, offering a **sink** that counts bytes and stamps the last
//! one), `vox connect` (the guest joins; the host trusts it beforehand) and `vox forward` (the guest's
//! local port into the tunnel).
//!
//! **The same emulated link for both.** PRD-001: "raw TCP and a Vox tunnel over the same emulated real
//! link". This process runs a link emulator: every packet of the tunnel's QUIC connection crosses a UDP
//! shaper, and the raw transfer crosses a TCP shaper, each holding the same rate and one-way delay
//! (and, on the lossy link, dropping the same share of the tunnel's packets). The host advertises only
//! the shaper (`VOX_TEST_ADVERTISE`), and the guest advertises nothing reachable, so the one connection
//! between them runs through it. The shaper counts what it carries, and the gate refuses to report a
//! ratio for a tunnel whose bytes did not cross it.
//!
//! **What must hold** (PRD-001 R41): at 1 Gbit/s, at LAN and at WAN round-trip time, the tunnel
//! reaches at least [`MIN_RATIO`] of raw. The 10 Gbit/s and lossy Wi-Fi-like links are reported, and
//! so is unshaped loopback, as a raw-efficiency figure, not the bar. The emulator is userspace, so
//! its own ceiling bounds the 10 Gbit/s figure; that is reported with it, not hidden.
//!
//! Mutation knob (test-side only): `VOX_PERF_MIN_RATIO` replaces the target ratio. Diagnostic knob:
//! `VOX_PERF_ONLY=<text>` runs only the links whose name contains it.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// Bytes per timed transfer.
const BYTES: u64 = 128 * 1024 * 1024;
const ROUNDS: usize = 3;
/// PRD-001 R41: "at least about 90% of raw at 1 Gbit/s".
const MIN_RATIO: f64 = 0.90;
const CHUNK: usize = 256 * 1024;

/// One emulated link: a rate, a one-way delay, and a share of packets lost.
#[derive(Clone, Copy, Debug)]
struct Link {
    name: &'static str,
    bits_per_sec: f64,
    one_way: Duration,
    loss: f64,
    gated: bool,
}

const LINKS: [Link; 4] = [
    Link {
        name: "1 Gbit/s, LAN (2 ms RTT)",
        bits_per_sec: 1e9,
        one_way: Duration::from_millis(1),
        loss: 0.0,
        gated: true,
    },
    Link {
        name: "1 Gbit/s, WAN (50 ms RTT)",
        bits_per_sec: 1e9,
        one_way: Duration::from_millis(25),
        loss: 0.0,
        gated: true,
    },
    Link {
        name: "10 Gbit/s, LAN (2 ms RTT)",
        bits_per_sec: 1e10,
        one_way: Duration::from_millis(1),
        loss: 0.0,
        gated: false,
    },
    Link {
        name: "Wi-Fi-like, 200 Mbit/s, 10 ms RTT, 1% loss",
        bits_per_sec: 2e8,
        one_way: Duration::from_millis(5),
        loss: 0.01,
        gated: false,
    },
];

/// Packets the emulator dropped because its queue was full (not the link's deliberate loss). A
/// loss-based congestion controller halves its window on each, and the raw arm (terminated at a
/// TCP proxy) never sees one, so they are reported beside every figure.
static TAIL_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The link both shapers apply now; `None` passes traffic through unshaped.
type Shared = Arc<Mutex<Option<Link>>>;

/// Holds `item`s and releases each once the link would have delivered it: no earlier than its
/// arrival plus the one-way delay, and no faster than the rate. Drop-tail past a queue of one
/// bandwidth-delay product plus 4 MB, as a router would; loss is applied by the caller.
struct Pacer {
    next_free: Instant,
}

impl Pacer {
    fn new() -> Self {
        Self {
            next_free: Instant::now(),
        }
    }
    /// When a packet of `len` bytes arriving `now` leaves the link.
    fn release(&mut self, link: &Link, now: Instant, len: usize) -> Instant {
        let serialise = Duration::from_secs_f64(len as f64 * 8.0 / link.bits_per_sec);
        let start = self.next_free.max(now);
        self.next_free = start + serialise;
        self.next_free + link.one_way
    }
}

fn sleep_until(t: Instant) {
    let now = Instant::now();
    if t > now {
        std::thread::sleep(t - now);
    }
}

/// A tiny deterministic PRNG for loss, so a run can be reproduced.
fn next_rand(state: &mut u64) -> f64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (*state >> 11) as f64 / (1u64 << 53) as f64
}

/// One direction of the UDP shaper: `rx` receives, `send` delivers after the link's delay and rate.
fn udp_direction(
    rx: std::net::UdpSocket,
    send: impl Fn(&[u8]) + Send + 'static,
    link: Shared,
    carried: Arc<std::sync::atomic::AtomicU64>,
    seed: u64,
) {
    let (tx, queue) = mpsc::channel::<(Instant, Vec<u8>)>();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let mut pacer = Pacer::new();
        let mut rng = seed | 1;
        while let Ok(n) = rx.recv(&mut buf) {
            let now = Instant::now();
            let l = *link.lock().unwrap();
            let due = match l {
                None => now,
                Some(l) => {
                    if l.loss > 0.0 && next_rand(&mut rng) < l.loss {
                        continue;
                    }
                    let bdp = l.bits_per_sec / 8.0 * l.one_way.as_secs_f64() * 2.0;
                    let backlog = pacer.next_free.saturating_duration_since(now).as_secs_f64()
                        * l.bits_per_sec
                        / 8.0;
                    if backlog > bdp + 4e6 {
                        TAIL_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue; // drop-tail
                    }
                    pacer.release(&l, now, n + 28)
                }
            };
            if tx.send((due, buf[..n].to_vec())).is_err() {
                return;
            }
        }
    });
    std::thread::spawn(move || {
        for (due, pkt) in queue {
            sleep_until(due);
            carried.fetch_add(pkt.len() as u64, std::sync::atomic::Ordering::Relaxed);
            send(&pkt);
        }
    });
}

/// A UDP shaper in front of `upstream`: whoever sends to the returned address reaches `upstream`, and
/// `upstream`'s replies go back, both ways across the link. Returns the address and a byte counter.
fn udp_shaper(
    upstream: SocketAddr,
    link: Shared,
) -> (SocketAddr, Arc<std::sync::atomic::AtomicU64>) {
    let front = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind the shaper");
    let back = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind the shaper's upstream side");
    back.connect(upstream).expect("connect the shaper upstream");
    let addr = front.local_addr().unwrap();
    let carried = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    // Toward the host: learn the client from its first packet.
    let (front_rx, back_tx) = (front.try_clone().unwrap(), back.try_clone().unwrap());
    let learn = Arc::clone(&client);
    let (tx, queue) = mpsc::channel::<(Instant, Vec<u8>)>();
    {
        let link = Arc::clone(&link);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            let mut pacer = Pacer::new();
            let mut rng = 0x9e37_79b9_7f4a_7c15u64;
            while let Ok((n, from)) = front_rx.recv_from(&mut buf) {
                *learn.lock().unwrap() = Some(from);
                let now = Instant::now();
                let due = match *link.lock().unwrap() {
                    None => now,
                    Some(l) => {
                        if l.loss > 0.0 && next_rand(&mut rng) < l.loss {
                            continue;
                        }
                        let bdp = l.bits_per_sec / 8.0 * l.one_way.as_secs_f64() * 2.0;
                        let backlog = pacer.next_free.saturating_duration_since(now).as_secs_f64()
                            * l.bits_per_sec
                            / 8.0;
                        if backlog > bdp + 4e6 {
                            TAIL_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            continue; // drop-tail
                        }
                        pacer.release(&l, now, n + 28)
                    }
                };
                if tx.send((due, buf[..n].to_vec())).is_err() {
                    return;
                }
            }
        });
        let carried = Arc::clone(&carried);
        std::thread::spawn(move || {
            for (due, pkt) in queue {
                sleep_until(due);
                carried.fetch_add(pkt.len() as u64, std::sync::atomic::Ordering::Relaxed);
                let _ = back_tx.send(&pkt);
            }
        });
    }
    // Toward the client.
    let front_tx = front;
    let who = Arc::clone(&client);
    udp_direction(
        back,
        move |pkt| {
            if let Some(to) = *who.lock().unwrap() {
                let _ = front_tx.send_to(pkt, to);
            }
        },
        link,
        Arc::clone(&carried),
        0x2545_f491_4f6c_dd1d,
    );
    (addr, carried)
}

/// What the emulator itself delivers at `link` (or unshaped): plain 1,350-byte datagrams sent
/// through a fresh UDP shaper for two seconds, counted where they land. A link the emulator cannot
/// carry is not a link Vox can be measured on, so a gated link below [`EMULATOR_FIDELITY`] of its
/// rate is reported as CANNOT MEASURE rather than blamed on the tunnel.
///
/// **On a link, the sender is paced at 1.05x its rate, and the best of three windows counts.** An
/// unpaced flood is a busy thread that competes with the emulator's own threads for the CPU, which
/// measures the emulator under an overload the real transfers never create (they are paced by
/// congestion control). On GitHub's 3-core macOS runner that competition alone took fidelity to
/// 91.9% and 88.2% in 5 of 12 windows, where a paced sender got 96.8-98.0%. A window that catches
/// the VM being preempted by its host loses a few percent more (2 of 18 paced windows there: 92.8%,
/// 89.7%), and that is interference, not capacity: the capacity of an emulator is its best window.
/// A genuinely slow emulator is slow in every window: slowed by 12 us per packet it delivered
/// 34-63% on both runners, far below the bar. Unshaped (`None`) there is no rate to pace at, so it
/// is one unpaced window, as before; it is reported, not gated.
///
/// Returns each window's rate, in bytes per second: three on a link, one unshaped.
fn calibrate_windows(link: Option<Link>) -> Vec<f64> {
    let n = if link.is_some() { 3 } else { 1 };
    (0..n).map(|_| calibrate_once(link)).collect()
}

/// What competed for the CPU when the emulator could not carry a link: the busiest processes.
fn busiest() -> String {
    Command::new("ps")
        .args(["-Ao", "pcpu,comm", "-r"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .take(7)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn calibrate_once(link: Option<Link>) -> f64 {
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sink.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let (front, _) = udp_shaper(sink.local_addr().unwrap(), Arc::new(Mutex::new(link)));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sender = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let pkt = [0x5au8; 1350];
            // 1,350 bytes plus the 28 the emulator charges per datagram, at 1.05x the link's rate,
            // sent as one batch per millisecond and then **asleep**: a sender that spins to pace
            // itself holds a whole core, which on GitHub's 3-core macOS runner was the emulator's.
            let per_ms = link.map(|l| l.bits_per_sec * 1.05 / 8.0 / 1378.0 / 1000.0);
            let start = Instant::now();
            let mut sent = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let Some(per_ms) = per_ms else {
                    let _ = s.send_to(&pkt, front);
                    continue;
                };
                let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                // A sleep that overshoots is made up in the next batch, never forgiven: the offered
                // load must stay at 1.05x the link or this measures the sender, not the emulator. On
                // a loaded runner VM, forgiving any backlog past 5 ms dropped fidelity to 60-70%. The
                // emulator's queue (bdp + 4 MB) absorbs the burst, as it absorbed the old flood.
                let due = (elapsed_ms * per_ms) as u64;
                while sent < due {
                    let _ = s.send_to(&pkt, front);
                    sent += 1;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    let mut buf = [0u8; 2048];
    // Past the link's delay, then count for two seconds.
    let warm = Instant::now() + Duration::from_millis(300);
    while Instant::now() < warm {
        let _ = sink.recv(&mut buf);
    }
    let t0 = Instant::now();
    let mut got = 0u64;
    while t0.elapsed() < Duration::from_secs(2) {
        if let Ok(n) = sink.recv(&mut buf) {
            got += n as u64;
        }
    }
    let rate = got as f64 / t0.elapsed().as_secs_f64();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = sender.join();
    rate
}

/// The share of a gated link's rate the emulator must deliver for the gate to measure on it.
const EMULATOR_FIDELITY: f64 = 0.95;

/// A TCP shaper in front of `upstream`, one way (client to upstream): the raw arm's link.
fn tcp_shaper(upstream: SocketAddr, link: Shared) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the TCP shaper");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(mut client) = client else { continue };
            let Ok(mut up) = TcpStream::connect(upstream) else {
                continue;
            };
            let link = Arc::clone(&link);
            let (tx, queue) = mpsc::sync_channel::<(Instant, Vec<u8>)>(1024);
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 64 * 1024];
                let mut pacer = Pacer::new();
                loop {
                    let n = match client.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let now = Instant::now();
                    let due = match *link.lock().unwrap() {
                        None => now,
                        // TCP/IP header overhead per 1448-byte segment, as on the wire.
                        Some(l) => pacer.release(&l, now, n + n.div_ceil(1448) * 52),
                    };
                    if tx.send((due, buf[..n].to_vec())).is_err() {
                        return;
                    }
                }
            });
            std::thread::spawn(move || {
                for (due, chunk) in queue {
                    sleep_until(due);
                    if up.write_all(&chunk).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn uptime() -> String {
    Command::new("uptime")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// A long-running `vox`, killed by its own PID however the test ends; stdout lines and
/// stderr collected so a failure can print what it said.
struct Proc {
    name: &'static str,
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proc {
    fn spawn(
        name: &'static str,
        dir: &std::path::Path,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> Self {
        let mut child = Command::new(VOX)
            .args(args)
            .envs(env.iter().copied())
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
        let lines = Arc::new(Mutex::new(Vec::new()));
        for stream in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let sink = Arc::clone(&lines);
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    sink.lock().unwrap().push(line);
                }
            });
        }
        Self { name, child, lines }
    }

    fn said(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    fn expect_line(&self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if let Some(l) = self.said().into_iter().find(|l| pred(l)) {
                return l;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "{}: never printed {what}. It said:\n{}",
            self.name,
            self.said().join("\n")
        );
    }
}

fn vox_once(dir: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    vox_once_env(dir, args, &[])
}

fn vox_once_env(
    dir: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (bool, String, String) {
    let out = Command::new(VOX)
        .args(args)
        .envs(env.iter().copied())
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
        .stdin(Stdio::null())
        .output()
        .expect("run vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn after_label(line: &str, label: &str) -> String {
    line.strip_prefix(label)
        .unwrap_or_else(|| panic!("line {line:?} does not start with {label:?}"))
        .trim()
        .to_owned()
}

/// A sink: counts each connection's bytes and reports two instants, when the first quarter of
/// `BYTES` has arrived and when the last byte has.
fn sink() -> (u16, mpsc::Receiver<(Instant, Instant)>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the sink");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; CHUNK];
                let mut got = 0u64;
                let mut quarter = None;
                while got < BYTES {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got += n as u64,
                    }
                    if quarter.is_none() && got >= BYTES / 4 {
                        quarter = Some(Instant::now());
                    }
                }
                let _ = tx.send((quarter.unwrap_or_else(Instant::now), Instant::now()));
            });
        }
    });
    (port, rx)
}

/// Push `BYTES` to `to` and return the **steady-state** throughput in bytes per second: the last
/// three quarters of the bytes over the time they took to land.
///
/// **Past the ramp, for both.** The raw arm crosses a TCP shaper that terminates the connection, so
/// raw TCP never pays slow start over the emulated round trip, while the tunnel's QUIC does. Clocked
/// from the connect, a transfer of about a second on a 50 ms link charged the tunnel for a ramp that
/// a real TCP flow over that link pays too, and that the raw arm here skipped: the first run read
/// 55% where the steady state was the question. The first quarter is the allowance for that ramp.
fn transfer(to: SocketAddr, done: &mpsc::Receiver<(Instant, Instant)>) -> f64 {
    let chunk = vec![0x5au8; CHUNK];
    let mut s = TcpStream::connect(to).expect("connect for the transfer");
    let mut sent = 0u64;
    while sent < BYTES {
        let n = usize::try_from((BYTES - sent).min(CHUNK as u64)).unwrap();
        s.write_all(&chunk[..n]).expect("write the transfer");
        sent += n as u64;
    }
    let (quarter, end) = done
        .recv_timeout(Duration::from_secs(300))
        .expect("the sink never received every byte");
    let secs = end.duration_since(quarter).as_secs_f64();
    drop(s);
    (BYTES - BYTES / 4) as f64 / secs
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

#[test]
#[ignore = "three real vox processes, production Argon2id and ~2 GB through an emulated link; CI runs it in release"]
fn r41_a_tunnel_does_not_throttle_the_link_it_runs_over() {
    watchdog::arm();
    let min_ratio = std::env::var("VOX_PERF_MIN_RATIO")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MIN_RATIO);
    eprintln!("uptime at start: {}", uptime());

    let tmp = tempfile::tempdir().unwrap();
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (port, done) = sink();
    let link: Shared = Arc::new(Mutex::new(None));

    let anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &["node", "--listen", "127.0.0.1:0"],
        &[],
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();

    let (ok, host_fp, err) = vox_once(&host_dir, &["id"]);
    assert!(ok, "host id: {err}");
    let (ok, guest_fp, err) = vox_once(&guest_dir, &["id"]);
    assert!(ok, "guest id: {err}");
    let (ok, _, err) = vox_once(
        &host_dir,
        &["trust", "add", guest_fp.trim(), "--name", "guest"],
    );
    assert!(ok, "host trusts guest: {err}");

    // The host listens on a known port behind the UDP shaper, and advertises only the shaper.
    let host_port = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let host_listen = format!("127.0.0.1:{host_port}");
    let (shaped, carried) = udp_shaper(host_listen.parse().unwrap(), Arc::clone(&link));
    let advertise = shaped.to_string();
    let port_s = port.to_string();
    let host = Proc::spawn(
        "host",
        &host_dir,
        &[
            "serve",
            &port_s,
            "--anchor",
            &spec,
            "--listen",
            &host_listen,
        ],
        &[("VOX_TEST_ADVERTISE", advertise.as_str())],
    );
    let room = after_label(
        &host.expect_line("the room id", |l| l.starts_with("room ")),
        "room",
    );
    let address = after_label(
        &host.expect_line("the address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("the passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    assert!(
        address.contains(&format!("/udp/{}", shaped.port())),
        "CANNOT MEASURE: the host did not advertise the shaper: {address}"
    );

    // The guest advertises nothing reachable, so the host cannot open a second, unshaped path.
    let nowhere = [("VOX_TEST_ADVERTISE", "127.0.0.1:9")];
    let (ok, out, err) = vox_once_env(
        &guest_dir,
        &[
            "connect",
            &address,
            "--passphrase",
            &passphrase,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        &nowhere,
    );
    assert!(ok, "CANNOT MEASURE: vox connect failed.\n{out}\n{err}");
    let forward = Proc::spawn(
        "forward",
        &guest_dir,
        &[
            "forward",
            &room,
            host_fp.trim(),
            &port_s,
            "127.0.0.1:0",
            "--passphrase",
            &passphrase,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        &nowhere,
    );
    let line = forward.expect_line("the forward's bound address", |l| {
        l.starts_with("vox: ") && l.contains(" → ")
    });
    let tunnel: SocketAddr = line
        .split_whitespace()
        .nth(1)
        .expect("an address")
        .parse()
        .expect("a socket address");
    let sink_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let raw = tcp_shaper(sink_addr, Arc::clone(&link));

    // Direct, asserted: the anchor must carry no circuit for the timed transfers.
    let carried_line = |l: &str| l.contains("circuit(s) carried") && !l.contains(" 0 circuit(s)");
    let circuit_lines = |a: &Proc| -> Vec<String> {
        a.said()
            .into_iter()
            .filter(|l| l.contains("circuit(s) carried"))
            .collect()
    };
    let _ = transfer(tunnel, &done);
    let settle = Instant::now();
    while circuit_lines(&anchor)
        .last()
        .is_some_and(|l| carried_line(l))
        && settle.elapsed() < Duration::from_secs(120)
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !circuit_lines(&anchor).last().is_some_and(|l| carried_line(l)),
        "CANNOT MEASURE a direct path: the anchor still carried a circuit 120 s after the forward came up"
    );
    let before = circuit_lines(&anchor).len();

    // Unshaped first: the raw-efficiency figure. The tunnel still crosses the emulator here, so this
    // is a floor on Vox's efficiency, not a ceiling. (An unpaced blast through the emulator overruns
    // its socket buffers and drops, so it cannot say what the emulator carries unshaped; the per-link
    // calibration below is paced by the link and can.)
    let mut report = Vec::new();
    let (t, r) = measure(tunnel, sink_addr, &done, &carried, None);
    report.push(format!(
        "unshaped (efficiency, not gated; bounded by the emulator): tunnel {:.1} MB/s, raw loopback TCP {:.1} MB/s, {:.1}%",
        t / 1e6,
        r / 1e6,
        100.0 * t / r
    ));

    let mut failed = Vec::new();
    // Diagnostic knob (test-side only): `VOX_PERF_ONLY` runs just the links whose name contains it.
    let only = std::env::var("VOX_PERF_ONLY").ok();
    for l in LINKS {
        if only.as_deref().is_some_and(|o| !l.name.contains(o)) {
            continue;
        }
        let windows = calibrate_windows(Some(l));
        let fidelity = windows.iter().copied().fold(0.0, f64::max) * 8.0 / l.bits_per_sec;
        let pct: Vec<String> = windows
            .iter()
            .map(|w| format!("{:.1}%", w * 8.0 / l.bits_per_sec * 100.0))
            .collect();
        assert!(
            !l.gated || fidelity >= EMULATOR_FIDELITY,
            "CANNOT MEASURE {}: the emulator itself delivers only {:.1}% of the link's rate \
             (windows {pct:?}; load: {})\nbusiest processes:\n{}",
            l.name,
            fidelity * 100.0,
            uptime(),
            busiest()
        );
        *link.lock().unwrap() = Some(l);
        std::thread::sleep(Duration::from_millis(500));
        let drops_before = TAIL_DROPS.load(std::sync::atomic::Ordering::Relaxed);
        let (t, r) = measure(tunnel, raw, &done, &carried, Some(l));
        let tail_drops = TAIL_DROPS.load(std::sync::atomic::Ordering::Relaxed) - drops_before;
        let ratio = t / r;
        let verdict = if !l.gated {
            "reported".to_owned()
        } else if ratio >= min_ratio {
            format!("ok (>= {:.0}%)", min_ratio * 100.0)
        } else {
            failed.push(format!("{}: {:.1}% of raw", l.name, ratio * 100.0));
            format!("BELOW {:.0}%", min_ratio * 100.0)
        };
        report.push(format!(
            "{}: tunnel {:.1} MB/s ({:.0} Mbit/s), raw {:.1} MB/s ({:.0} Mbit/s), {:.1}% — {verdict}; \
             emulator fidelity {:.1}%; queue drops {tail_drops}",
            l.name, t / 1e6, t * 8.0 / 1e6, r / 1e6, r * 8.0 / 1e6, 100.0 * ratio, fidelity * 100.0
        ));
    }
    *link.lock().unwrap() = None;
    let later: Vec<String> = circuit_lines(&anchor)
        .into_iter()
        .skip(before)
        .filter(|l| carried_line(l))
        .collect();
    for line in &report {
        eprintln!("R41: {line}");
    }
    eprintln!("uptime at end: {}", uptime());
    assert!(
        later.is_empty(),
        "CANNOT MEASURE: the tunnel fell back to a relay during the timed transfers: {later:?}"
    );
    assert!(
        failed.is_empty(),
        "R41: the tunnel throttles the link it runs over: {failed:?}\n{}",
        report.join("\n")
    );
    drop(forward);
    drop(host);
    drop(anchor);
}

/// Median throughput of the tunnel and of raw over `ROUNDS` interleaved transfers, and a check that
/// the tunnel's bytes crossed the shaper: a tunnel that bypassed it would score whatever it liked.
fn measure(
    tunnel: SocketAddr,
    raw: SocketAddr,
    done: &mpsc::Receiver<(Instant, Instant)>,
    carried: &std::sync::atomic::AtomicU64,
    link: Option<Link>,
) -> (f64, f64) {
    let mut t = Vec::new();
    let mut r = Vec::new();
    for _ in 0..ROUNDS {
        let before = carried.load(std::sync::atomic::Ordering::Relaxed);
        t.push(transfer(tunnel, done));
        let crossed = carried.load(std::sync::atomic::Ordering::Relaxed) - before;
        assert!(
            crossed >= BYTES,
            "CANNOT MEASURE {link:?}: only {crossed} of the tunnel's {BYTES} bytes crossed the emulated link"
        );
        r.push(transfer(raw, done));
    }
    (median(t), median(r))
}
