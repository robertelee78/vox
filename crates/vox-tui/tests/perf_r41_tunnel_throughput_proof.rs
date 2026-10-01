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
//! reaches at least [`MIN_RATIO`] of raw. The 10 Gbit/s link is reported, and so is unshaped
//! loopback, as a raw-efficiency figure, not the bar. The emulator is userspace, so its own ceiling
//! bounds the 10 Gbit/s figure; that is reported with it, not hidden.
//!
//! **ADR-024's arms** (the decider, 2026-10-01; see `taper_arms`): on a 200 Mbit/s, 10 ms Wi-Fi-like
//! link at 1% and at 5% loss the tunnel carries at least [`LOSSY_WIN`] of a Cubic flow on the same
//! loss; on a link it shares with a Cubic flow (200 Mbit/s through a one-BDP and a quarter-BDP queue,
//! and a 1 Gbit/s, 2 ms LAN through a one-BDP queue, each over [`CONGESTED_MEASURE`]), its rate is
//! between [`FAIR_LOW`] and [`FAIR_HIGH`] of that flow's; and on a link that goes clean, lossy and
//! clean again under one transfer, every second of each clean phase (past [`RECOVER_WITHIN`] after
//! the loss) is at the clean bar and the lossy phase clears the lossy bar. These are judged by the
//! speed a person sees, never by which controller the tunnel is running. The comparison flow is
//! quinn's stock Cubic over the same emulated link, not kernel TCP: see the comment above
//! `STREAM_MARK` for why.
//!
//! **Every red names its side** (V210-98). The emulator is part of the apparatus, and on a busy
//! machine it can fall behind the link it plays, which the raw arm (behind a TCP proxy and a deep
//! buffer) cannot feel and the tunnel's congestion control does. So:
//! - **APPARATUS** (CANNOT MEASURE, never green and never the tunnel's): the emulator fell short of
//!   [`EMULATOR_FIDELITY`] in any calibration window, or ran more than [`MAX_EMULATOR_LATENESS`] late
//!   during a timed tunnel transfer. The message names the window or the lateness: that run
//!   measured the emulator, not vox.
//! - **PRODUCT**: the emulator carried the link and was on time, and vox carried less than
//!   [`MIN_RATIO`] of raw. The message names the lateness it was on time within and the figure.
//! - On ADR-024's arms: **APPARATUS** when the emulator ran more than [`MAX_EMULATOR_LATENESS`] late
//!   in any judged second, or the comparison flow carried nothing (its connection never ran);
//!   **PRODUCT** when the emulator was on time and vox missed the arm's bar, quoting vox's rate, the
//!   comparison flow's and the bar.
//!
//! Every run, passing or not, prints each link's percentage, drops, calibration windows, lateness
//! and per-round figures.
//!
//! Mutation knob (test-side only): `VOX_PERF_MIN_RATIO` replaces the target ratio. Diagnostic knob:
//! `VOX_PERF_ONLY=<text>` runs only the links whose name contains it.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// Write the room passphrase `pass` beside the profile at `dir`, for `--passphrase-file`: a
/// room passphrase is never taken from argv or the environment (V210-72).
fn room_pass_file(dir: &std::path::Path, pass: &str) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let at = dir.join("room-passphrase");
    std::fs::write(&at, pass).unwrap();
    at.to_str().unwrap().to_owned()
}
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
    /// The emulator's queue, in bandwidth-delay products; `None` is a deep router buffer of one
    /// bandwidth-delay product plus 4 MB.
    queue_bdps: Option<f64>,
}

impl Link {
    /// The bytes the link's queue holds before it drops the tail.
    fn queue_limit(&self) -> f64 {
        let bdp = self.bits_per_sec / 8.0 * self.one_way.as_secs_f64() * 2.0;
        self.queue_bdps.map_or(bdp + 4e6, |n| n * bdp)
    }
}

const LINKS: [Link; 3] = [
    Link {
        name: "1 Gbit/s, LAN (2 ms RTT)",
        bits_per_sec: 1e9,
        one_way: Duration::from_millis(1),
        loss: 0.0,
        gated: true,
        queue_bdps: None,
    },
    Link {
        name: "1 Gbit/s, WAN (50 ms RTT)",
        bits_per_sec: 1e9,
        one_way: Duration::from_millis(25),
        loss: 0.0,
        gated: true,
        queue_bdps: None,
    },
    Link {
        name: "10 Gbit/s, LAN (2 ms RTT)",
        bits_per_sec: 1e10,
        one_way: Duration::from_millis(1),
        loss: 0.0,
        gated: false,
        queue_bdps: None,
    },
];

/// Packets the emulator dropped because its queue was full (not the link's deliberate loss). A
/// loss-based congestion controller halves its window on each, and the raw arm (terminated at a
/// TCP proxy) never sees one, so they are reported beside every figure.
static TAIL_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How late, in microseconds, the emulator released a packet past the instant the link would have
/// delivered it: the longest since the last [`take_lateness`], across both directions of the UDP
/// shaper, counted only while a link is applied (unshaped, a packet's wait is its queue, not
/// lateness).
///
/// **A stalled emulator is a stalled link that the raw arm cannot feel.** When the thread that
/// releases packets does not run, the link it plays stops, and then catches up in a burst. The raw
/// arm terminates at a TCP proxy behind a deep buffer and never sees it. The tunnel's congestion
/// control does: on GitHub's macOS runner, an emulator paused 10 of every 100 ms (lateness 41-92 ms)
/// took the tunnel to 84.9% of raw in one run of three, and 20 of every 100 ms (95-172 ms) to 60.7%
/// and 81.0%, while the calibration still read 98-100%. A gated figure measured across such a
/// stall measures the instrument, so it is CANNOT MEASURE (V210-98).
static LATENESS_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn note_lateness(shaped: bool, due: Instant) {
    if shaped {
        let late = Instant::now().saturating_duration_since(due).as_micros() as u64;
        LATENESS_US.fetch_max(late, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The longest lateness since the last call, and start counting afresh.
fn take_lateness() -> Duration {
    Duration::from_micros(LATENESS_US.swap(0, std::sync::atomic::Ordering::Relaxed))
}

/// The most an emulator may run late during a gated transfer and still be measuring the link.
/// Measured on GitHub's runners: 5-24 ms on macOS's VM in runs where the tunnel held the link's
/// full rate, under 7 ms on ubuntu. The stalls that moved the tunnel's figure were 41 ms and longer.
const MAX_EMULATOR_LATENESS: Duration = Duration::from_millis(25);

/// Write `line` to stderr directly, so it is shown on a passing run too: libtest captures
/// `eprintln!` on a pass, and a gate whose green runs print no figure hides its margin (V210-98).
fn shown(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{line}");
}

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
    let (tx, queue) = mpsc::channel::<(Instant, Vec<u8>, bool)>();
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
                    let backlog = pacer.next_free.saturating_duration_since(now).as_secs_f64()
                        * l.bits_per_sec
                        / 8.0;
                    if backlog > l.queue_limit() {
                        TAIL_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue; // drop-tail
                    }
                    pacer.release(&l, now, n + 28)
                }
            };
            if tx.send((due, buf[..n].to_vec(), l.is_some())).is_err() {
                return;
            }
        }
    });
    std::thread::spawn(move || {
        for (due, pkt, shaped) in queue {
            sleep_until(due);
            note_lateness(shaped, due);
            carried.fetch_add(pkt.len() as u64, std::sync::atomic::Ordering::Relaxed);
            send(&pkt);
        }
    });
}

/// A UDP shaper in front of `upstream`: whoever sends to the returned address reaches `upstream`, and
/// `upstream`'s replies go back, both ways across the link. Returns the address and a byte counter.
/// Give an emulator socket the largest buffers the OS grants, each way.
///
/// **The instrument must not drop what the link would carry.** With the OS default (786 KB receive
/// on macOS), the emulator's own sockets overflowed during WAN bursts: the kernel counted tens of
/// thousands of datagrams "dropped due to full socket buffers" in one R41 run on the macOS runner,
/// which the tunnel paid for as loss and the gate reported as the tunnel's throughput. The link it
/// emulates drops only at its queue (`bdp + 4 MB`, counted in `TAIL_DROPS`). Largest first, halving
/// until the OS accepts: macOS caps a socket at `kern.ipc.maxsockbuf` (6 MiB on the runner).
fn big_buffers(sock: &std::net::UdpSocket) {
    let s = socket2::SockRef::from(sock);
    let mut n = 64 << 20;
    while n >= 1 << 20 && s.set_recv_buffer_size(n).is_err() {
        n /= 2;
    }
    let mut n = 64 << 20;
    while n >= 1 << 20 && s.set_send_buffer_size(n).is_err() {
        n /= 2;
    }
}

/// `bottleneck` is the link's queue toward `upstream`: shapers given the same one share it, as flows
/// crossing one router do, so their packets wait behind each other and one flow's burst can drop
/// another's. `seed` draws the link's random loss.
fn udp_shaper(
    upstream: SocketAddr,
    link: Shared,
    bottleneck: Arc<Mutex<Pacer>>,
    seed: u64,
) -> (SocketAddr, Arc<std::sync::atomic::AtomicU64>) {
    let front = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind the shaper");
    let back = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind the shaper's upstream side");
    big_buffers(&front);
    big_buffers(&back);
    back.connect(upstream).expect("connect the shaper upstream");
    let addr = front.local_addr().unwrap();
    let carried = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    // Toward the host: learn the client from its first packet.
    let (front_rx, back_tx) = (front.try_clone().unwrap(), back.try_clone().unwrap());
    let learn = Arc::clone(&client);
    let (tx, queue) = mpsc::channel::<(Instant, Vec<u8>, bool)>();
    {
        let link = Arc::clone(&link);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            let mut rng = seed | 1;
            while let Ok((n, from)) = front_rx.recv_from(&mut buf) {
                *learn.lock().unwrap() = Some(from);
                let now = Instant::now();
                let shaped = link.lock().unwrap().is_some();
                let due = match *link.lock().unwrap() {
                    None => now,
                    Some(l) => {
                        if l.loss > 0.0 && next_rand(&mut rng) < l.loss {
                            continue;
                        }
                        let mut pacer = bottleneck.lock().unwrap();
                        let backlog = pacer.next_free.saturating_duration_since(now).as_secs_f64()
                            * l.bits_per_sec
                            / 8.0;
                        if backlog > l.queue_limit() {
                            TAIL_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            continue; // drop-tail
                        }
                        pacer.release(&l, now, n + 28)
                    }
                };
                if tx.send((due, buf[..n].to_vec(), shaped)).is_err() {
                    return;
                }
            }
        });
        let carried = Arc::clone(&carried);
        std::thread::spawn(move || {
            for (due, pkt, shaped) in queue {
                sleep_until(due);
                note_lateness(shaped, due);
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
        seed ^ 0x2545_f491_4f6c_dd1d,
    );
    (addr, carried)
}

/// What the emulator itself delivers at `link` (or unshaped): plain 1,350-byte datagrams sent
/// through a fresh UDP shaper for two seconds, counted where they land. A link the emulator cannot
/// carry is not a link Vox can be measured on, so a gated link below [`EMULATOR_FIDELITY`] of its
/// rate is reported as CANNOT MEASURE rather than blamed on the tunnel.
///
/// **On a link, the sender is paced at 1.05x its rate, and every one of three windows must hold.** An
/// unpaced flood is a busy thread that competes with the emulator's own threads for the CPU, which
/// measures the emulator under an overload the real transfers never create (they are paced by
/// congestion control). On GitHub's 3-core macOS runner that competition alone took fidelity to
/// 91.9% and 88.2% in 5 of 12 windows, where a paced sender got 96.8-98.0%. A window that catches
/// the VM being preempted by its host loses a few percent more (2 of 18 paced windows there: 92.8%,
/// 89.7%). Counting only the best window once hid exactly that: the run that put the tunnel at
/// 88.9% of raw had calibrated at 97.9%, 77.6% and 95.8%, and reported 97.9% (V210-98). An emulator
/// that could not carry the link for two seconds of the run may not carry it during the transfers
/// either, so a gated link needs [`EMULATOR_FIDELITY`] in every window. Unshaped (`None`) there is no rate to pace at, so it
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
    big_buffers(&sink);
    let (front, _) = udp_shaper(
        sink.local_addr().unwrap(),
        Arc::new(Mutex::new(link)),
        Arc::new(Mutex::new(Pacer::new())),
        SEED_TUNNEL,
    );
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sender = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            big_buffers(&s);
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
                // A stream (`stream_to`) is counted as it lands, for as long as it runs.
                let mut first = [0u8; 1];
                if s.read_exact(&mut first).is_err() {
                    return;
                }
                if first[0] == STREAM_MARK {
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 {
                            return;
                        }
                        STREAMED.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                    return;
                }
                got += 1;
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
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm();
    let min_ratio = std::env::var("VOX_PERF_MIN_RATIO")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MIN_RATIO);
    shown(&format!("uptime at start: {}", uptime()));

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
    // The tunnel's queue toward the host: the competing flow of the congested arm shares it.
    let bottleneck = Arc::new(Mutex::new(Pacer::new()));
    let (shaped, carried) = udp_shaper(
        host_listen.parse().unwrap(),
        Arc::clone(&link),
        Arc::clone(&bottleneck),
        SEED_TUNNEL,
    );
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
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
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
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
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
    let (t, r, _) = measure(tunnel, sink_addr, &done, &carried, None);
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
        // The weakest window, not the best (V210-98).
        let fidelity = windows.iter().copied().fold(f64::INFINITY, f64::min) * 8.0 / l.bits_per_sec;
        let pct: Vec<String> = windows
            .iter()
            .map(|w| format!("{:.1}%", w * 8.0 / l.bits_per_sec * 100.0))
            .collect();
        assert!(
            !l.gated || fidelity >= EMULATOR_FIDELITY,
            "CANNOT MEASURE {} (APPARATUS): the emulator itself delivered only {:.1}% of the link's \
             rate in a calibration window (windows {pct:?}; each must reach {:.0}%), so this run \
             would measure the emulator, not vox (load: {})\nbusiest processes:\n{}",
            l.name,
            fidelity * 100.0,
            EMULATOR_FIDELITY * 100.0,
            uptime(),
            busiest()
        );
        *link.lock().unwrap() = Some(l);
        std::thread::sleep(Duration::from_millis(500));
        let drops_before = TAIL_DROPS.load(std::sync::atomic::Ordering::Relaxed);
        let (t, r, rounds) = measure(tunnel, raw, &done, &carried, Some(l));
        let tail_drops = TAIL_DROPS.load(std::sync::atomic::Ordering::Relaxed) - drops_before;
        let ratio = t / r;
        let late = rounds.iter().map(|x| x.2).max().unwrap_or_default();
        let per_round: Vec<String> = rounds
            .iter()
            .map(|(t, r, late)| {
                format!(
                    "{:.1}/{:.1} MB/s late {} ms",
                    t / 1e6,
                    r / 1e6,
                    late.as_millis()
                )
            })
            .collect();
        assert!(
            !l.gated || late <= MAX_EMULATOR_LATENESS,
            "CANNOT MEASURE {} (APPARATUS): the emulator was {} ms late during a timed tunnel \
             transfer (at most {} ms measures the link), so this run measured the emulator, not vox; \
             rounds (tunnel/raw): {per_round:?}; calibration windows {pct:?}; load: {}",
            l.name,
            late.as_millis(),
            MAX_EMULATOR_LATENESS.as_millis(),
            uptime()
        );
        let verdict = if !l.gated {
            "reported".to_owned()
        } else if ratio >= min_ratio {
            format!("ok (>= {:.0}%)", min_ratio * 100.0)
        } else {
            failed.push(format!(
                "{}: the emulator carried the link (every calibration window >= {:.0}%) and was on \
                 time (max lateness {} ms), and vox carried {:.1}% of raw, under {:.0}%: vox is slow",
                l.name,
                EMULATOR_FIDELITY * 100.0,
                late.as_millis(),
                ratio * 100.0,
                min_ratio * 100.0
            ));
            format!("BELOW {:.0}%", min_ratio * 100.0)
        };
        report.push(format!(
            "{}: tunnel {:.1} MB/s ({:.0} Mbit/s), raw {:.1} MB/s ({:.0} Mbit/s), {:.1}% — {verdict}; \
             emulator fidelity {:.1}% (windows {pct:?}), lateness {} ms; queue drops {tail_drops}; \
             rounds (tunnel/raw) {per_round:?}",
            l.name, t / 1e6, t * 8.0 / 1e6, r / 1e6, r * 8.0 / 1e6, 100.0 * ratio, fidelity * 100.0,
            late.as_millis()
        ));
    }
    taper_arms(
        tunnel,
        &link,
        &bottleneck,
        raw,
        &done,
        &mut report,
        &mut failed,
    );
    *link.lock().unwrap() = None;
    let later: Vec<String> = circuit_lines(&anchor)
        .into_iter()
        .skip(before)
        .filter(|l| carried_line(l))
        .collect();
    for line in &report {
        shown(&format!("R41: {line}"));
    }
    shown(&format!("uptime at end: {}", uptime()));
    assert!(
        later.is_empty(),
        "CANNOT MEASURE: the tunnel fell back to a relay during the timed transfers: {later:?}"
    );
    assert!(
        failed.is_empty(),
        "R41 (PRODUCT): the tunnel throttles the link it runs over: {failed:?}\n{}",
        report.join("\n")
    );
    drop(forward);
    drop(host);
    drop(anchor);
}

/// One round: the tunnel's and raw's throughput, and the emulator's longest lateness during the
/// tunnel's transfer.
type Round = (f64, f64, Duration);

/// Median throughput of the tunnel and of raw over `ROUNDS` interleaved transfers, and a check that
/// the tunnel's bytes crossed the shaper: a tunnel that bypassed it would score whatever it liked.
/// Also each round's tunnel and raw figures, and how late the emulator ran during its tunnel
/// transfer.
fn measure(
    tunnel: SocketAddr,
    raw: SocketAddr,
    done: &mpsc::Receiver<(Instant, Instant)>,
    carried: &std::sync::atomic::AtomicU64,
    link: Option<Link>,
) -> (f64, f64, Vec<Round>) {
    let mut t = Vec::new();
    let mut r = Vec::new();
    let mut rounds = Vec::new();
    for _ in 0..ROUNDS {
        let before = carried.load(std::sync::atomic::Ordering::Relaxed);
        let _ = take_lateness();
        t.push(transfer(tunnel, done));
        let late = take_lateness();
        let crossed = carried.load(std::sync::atomic::Ordering::Relaxed) - before;
        assert!(
            crossed >= BYTES,
            "CANNOT MEASURE {link:?}: only {crossed} of the tunnel's {BYTES} bytes crossed the emulated link"
        );
        r.push(transfer(raw, done));
        rounds.push((t[t.len() - 1], r[r.len() - 1], late));
    }
    (median(t), median(r), rounds)
}

// ---- ADR-024's arms: a lossy link, a congested link, a link that changes ------------------------
//
// The decider, 2026-10-01: "fair race, clear win". On a lossy link the comparison sees the same
// loss, and Vox must carry at least [`LOSSY_WIN`] of it. On a congested link Vox shares fairly: its
// rate is between [`FAIR_LOW`] and [`FAIR_HIGH`] of a competing flow's. On a link that changes
// mid-transfer, Vox is judged by the speed a person sees in each phase, never by which controller it
// is running.
//
// **The comparison flow is TCP's algorithm on the same link, not the kernel's TCP.** A kernel TCP
// connection cannot see an emulated loss or share an emulated queue without root (dummynet or pf on
// macOS, netem on Linux), and nothing here runs as root. The raw arm above terminates TCP at a proxy,
// which is why it never loses a packet. So the comparison is a QUIC flow under quinn's stock Cubic
// (RFC 8312) with QUIC's selective acknowledgements: the algorithm macOS and Linux TCP run by
// default, with the loss recovery of a modern TCP (SACK), crossing the same emulated link, the same
// loss draw and, on the congested arm, the same queue as the tunnel. A userspace TCP without SACK
// recovery (smoltcp) would lose far more at 1% loss than real TCP does and flatter Vox.

/// The first byte of a stream (`stream_to`): the sink counts it into [`STREAMED`] for as long as it
/// runs, instead of timing a `BYTES` transfer.
const STREAM_MARK: u8 = 0xa5;
/// Bytes the sink has received on streams.
static STREAMED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Bytes the competing flow's receiver has received.
static COMPETED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Loss draws: the tunnel's shaper and the competing flow's shaper.
const SEED_TUNNEL: u64 = 0x9e37_79b9_7f4a_7c15;
const SEED_COMPETITOR: u64 = 0x1234_5678_9abc_def1;

/// The Wi-Fi-like link of the lossy and changing arms.
const WIFI: Link = Link {
    name: "Wi-Fi-like, 200 Mbit/s, 10 ms RTT, 1% loss",
    bits_per_sec: 2e8,
    one_way: Duration::from_millis(5),
    loss: 0.01,
    gated: true,
    queue_bdps: None,
};
/// The same link at 5% loss: past tier 2's loss cap, where only tier 3 (BBR) clears the bar.
const WIFI_HEAVY: Link = Link {
    name: "Wi-Fi-like, 200 Mbit/s, 10 ms RTT, 5% loss",
    loss: 0.05,
    ..WIFI
};
/// The congested arm's link: the same rate and round trip, no random loss, and a router queue of
/// one bandwidth-delay product, so loss comes only from the queue the two flows fill together.
const CONGESTED: Link = Link {
    name: "congested, 200 Mbit/s, 10 ms RTT, 1-BDP queue, shared with a Cubic flow",
    bits_per_sec: 2e8,
    one_way: Duration::from_millis(5),
    loss: 0.0,
    gated: true,
    queue_bdps: Some(1.0),
};
/// A congested LAN: 1 Gbit/s, 2 ms, one-BDP queue (250 KB) shared with the Cubic flow. A full queue
/// here is only 2 ms of delay, under tier 2's delay test, so only the loss signals can see this
/// congestion: tier 2 alone took 2.56x the Cubic flow here (ADR-024 M24.1).
const CONGESTED_LAN: Link = Link {
    name: "congested LAN, 1 Gbit/s, 2 ms RTT, 1-BDP queue, shared with a Cubic flow",
    bits_per_sec: 1e9,
    one_way: Duration::from_millis(1),
    loss: 0.0,
    gated: true,
    queue_bdps: Some(1.0),
};
/// The same, behind a shallow router buffer: a quarter of a bandwidth-delay product, 62.5 KB or
/// about 2.5 ms at the link's rate. Congestion here shows as loss with almost no rise in delay,
/// which is the case a delay-based reading of loss gets wrong: tier 2's guard is what keeps Vox
/// fair on it.
const CONGESTED_SHALLOW: Link = Link {
    name: "congested, shallow buffer, 200 Mbit/s, 10 ms RTT, 1/4-BDP queue, shared with a Cubic flow",
    queue_bdps: Some(0.25),
    ..CONGESTED
};

/// The decider: on the lossy link Vox must carry at least twice the comparison flow.
const LOSSY_WIN: f64 = 2.0;
/// The decider: on the congested link Vox's rate is between half and twice the competitor's.
const FAIR_LOW: f64 = 0.5;
const FAIR_HIGH: f64 = 2.0;
/// How long a flow runs on a link before it is judged. A connection that moves to a link of another
/// round trip keeps the old path's base round trip for 10 s (vox-core's `BASE_RTT_WINDOW`): a person
/// whose network changes under a live tunnel gets the new link's speed after that, and that is what
/// the arms judge. A fresh comparison flow pays only its own ramp, within the same allowance.
const SETTLE: Duration = Duration::from_secs(12);
/// How long each lossy arm measures, past the settle.
const MEASURE: Duration = Duration::from_secs(15);
/// How long each congested arm measures, past the settle: long enough that tier 3's trials (2 s each,
/// then a back-off of 30 s or more) run and fail inside it, so the share judged is the whole run's,
/// trials included, not a steady state between them.
const CONGESTED_MEASURE: Duration = Duration::from_secs(60);
/// The window a person's speed is read in.
const WINDOW: Duration = Duration::from_secs(1);
/// The changing arm: each phase's length, and how soon after the loss ends Vox must be back at the
/// clean bar.
const PHASE: Duration = Duration::from_secs(20);
const RECOVER_WITHIN: Duration = Duration::from_secs(5);
/// How long into the lossy phase Vox may take to find its lossy-link speed before it is judged: at
/// 5% loss that is a climb of two tiers (at least 1 s in tier 1, 2 s of dwell and 2 s of evidence in
/// tier 2, then tier 3's trial), as ADR-024's thresholds set it.
const CLIMB_WITHIN: Duration = Duration::from_secs(8);

/// The changing arm's name for a lossy phase on `lossy`.
fn changing_name(lossy: &Link) -> String {
    format!(
        "changing, 200 Mbit/s, 10 ms RTT: clean, {:.0}% loss, clean",
        lossy.loss * 100.0
    )
}

/// Write to the tunnel at `to` as fast as it takes, until `stop`.
fn stream_to(to: SocketAddr, stop: Arc<std::sync::atomic::AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = vec![0x5au8; CHUNK];
        chunk[0] = STREAM_MARK;
        let mut s = TcpStream::connect(to).expect("connect the stream");
        s.write_all(&chunk).expect("write the stream's first chunk");
        chunk[0] = 0x5a;
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            if s.write_all(&chunk).is_err() {
                return;
            }
        }
    })
}

/// One window: Vox's and the competitor's rates (bits per second) and how late the emulator ran.
#[derive(Clone, Copy, Debug)]
struct Window {
    vox: f64,
    other: f64,
    late: Duration,
}

/// Read both counters every [`WINDOW`] for `dur`; `at` runs before each window (to change the link).
fn windows(dur: Duration, mut at: impl FnMut(Duration)) -> Vec<Window> {
    use std::sync::atomic::Ordering::Relaxed;
    let start = Instant::now();
    let (mut v0, mut c0) = (STREAMED.load(Relaxed), COMPETED.load(Relaxed));
    let _ = take_lateness();
    let mut out = Vec::new();
    let mut k = 1u32;
    while WINDOW * (k - 1) < dur {
        at(WINDOW * (k - 1));
        sleep_until(start + WINDOW * k);
        let (v, c) = (STREAMED.load(Relaxed), COMPETED.load(Relaxed));
        let s = WINDOW.as_secs_f64();
        out.push(Window {
            vox: (v - v0) as f64 * 8.0 / s,
            other: (c - c0) as f64 * 8.0 / s,
            late: take_lateness(),
        });
        (v0, c0) = (v, c);
        k += 1;
    }
    out
}

fn mean_of(w: &[Window], f: impl Fn(&Window) -> f64) -> f64 {
    w.iter().map(f).sum::<f64>() / w.len().max(1) as f64
}

fn mbit(w: &[Window], f: impl Fn(&Window) -> f64) -> Vec<String> {
    w.iter().map(|x| format!("{:.0}", f(x) / 1e6)).collect()
}

/// A run measured the emulator, not vox, if the emulator ran late in any window judged.
fn assert_on_time(arm: &str, w: &[Window]) {
    let late = w.iter().map(|x| x.late).max().unwrap_or_default();
    assert!(
        late <= MAX_EMULATOR_LATENESS,
        "CANNOT MEASURE {arm} (APPARATUS): the emulator was {} ms late in a judged window (at most \
         {} ms measures the link), so this run measured the emulator, not vox; per-window lateness \
         {:?} ms; load: {}",
        late.as_millis(),
        MAX_EMULATOR_LATENESS.as_millis(),
        w.iter().map(|x| x.late.as_millis()).collect::<Vec<_>>(),
        uptime()
    );
}

/// The comparison flow's TLS: any certificate (it carries nothing secret, and runs only between
/// this test's own two endpoints), signatures still checked.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The comparison flow's transport: quinn's stock Cubic, with the tunnel's datagram ceiling and
/// windows, so the two differ only in their congestion control.
fn competitor_transport() -> Arc<quinn::TransportConfig> {
    let mut cfg = quinn::TransportConfig::default();
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.upper_bound(8192);
    cfg.mtu_discovery_config(Some(mtu));
    cfg.stream_receive_window(quinn::VarInt::from_u32(16 << 20));
    cfg.send_window(32 << 20);
    cfg.receive_window(quinn::VarInt::from_u32(32 << 20));
    cfg.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    Arc::new(cfg)
}

fn competitor_endpoint() -> quinn::Endpoint {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind the comparison flow");
    big_buffers(&sock);
    let mut ecfg = quinn::EndpointConfig::default();
    let _ = ecfg.max_udp_payload_size(8192);
    quinn::Endpoint::new(ecfg, None, sock, Arc::new(quinn::TokioRuntime))
        .expect("the comparison flow's endpoint")
}

/// The comparison flow's receiver: counts into [`COMPETED`]. Returns its address.
fn competitor_receiver(rt: &tokio::runtime::Runtime) -> SocketAddr {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let ck = rcgen::generate_simple_self_signed(vec!["comparison".into()]).expect("a certificate");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .expect("the receiver's TLS");
    tls.alpn_protocols = vec![b"r41".to_vec()];
    let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC TLS"),
    ));
    scfg.transport_config(competitor_transport());
    let _rt = rt.enter();
    let ep = competitor_endpoint();
    ep.set_server_config(Some(scfg));
    let addr = ep.local_addr().expect("the receiver's address");
    rt.spawn(async move {
        while let Some(inc) = ep.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = inc.await else { return };
                while let Ok(mut rx) = conn.accept_uni().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; CHUNK];
                        while let Ok(Some(n)) = rx.read(&mut buf).await {
                            COMPETED.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                        }
                    });
                }
            });
        }
    });
    addr
}

/// The comparison flow's sender: one stream to `to`, as fast as Cubic lets it, until `stop`.
fn competitor_sender(
    rt: &tokio::runtime::Runtime,
    to: SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"r41".to_vec()];
    let mut ccfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC TLS"),
    ));
    ccfg.transport_config(competitor_transport());
    let _rt = rt.enter();
    let ep = competitor_endpoint();
    rt.spawn(async move {
        let Ok(connecting) = ep.connect_with(ccfg, to, "comparison") else {
            return;
        };
        let Ok(conn) = connecting.await else { return };
        let Ok(mut tx) = conn.open_uni().await else {
            return;
        };
        let chunk = vec![0x5au8; CHUNK];
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            if tx.write_all(&chunk).await.is_err() {
                return;
            }
        }
        conn.close(0u32.into(), b"done");
        ep.wait_idle().await;
    });
}

/// The comparison flow must have run, or there was nothing to compare with.
fn assert_competed(arm: &str, w: &[Window]) {
    assert!(
        mean_of(w, |x| x.other) > 0.0,
        "CANNOT MEASURE {arm} (APPARATUS): the comparison flow carried nothing (harness error: its \
         QUIC connection never ran), so there is nothing to compare vox with"
    );
}

/// ADR-024's three arms, on the running tunnel. Each PRODUCT verdict goes into `failed`, each figure
/// into `report`; an APPARATUS fault panics as CANNOT MEASURE.
fn taper_arms(
    tunnel: SocketAddr,
    link: &Shared,
    bottleneck: &Arc<Mutex<Pacer>>,
    raw: SocketAddr,
    done: &mpsc::Receiver<(Instant, Instant)>,
    report: &mut Vec<String>,
    failed: &mut Vec<String>,
) {
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    let only = std::env::var("VOX_PERF_ONLY").ok();
    let wanted = |name: &str| only.as_deref().is_none_or(|o| name.contains(o));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("the comparison flow's runtime");
    let receiver = competitor_receiver(&rt);
    let (competitor, _) = udp_shaper(
        receiver,
        Arc::clone(link),
        Arc::clone(bottleneck),
        SEED_COMPETITOR,
    );
    let settle_and_measure = SETTLE + MEASURE;
    let judged = |w: &[Window]| w[w.len() - MEASURE.as_secs() as usize..].to_vec();

    // The lossy link: Vox alone, then the comparison flow alone, each over the same loss.
    let mut lossy_bars: Vec<(&str, f64)> = Vec::new();
    for lossy in [WIFI, WIFI_HEAVY] {
        let feeds_changing = wanted(&changing_name(&lossy));
        if !wanted(lossy.name) && !feeds_changing {
            continue;
        }
        *link.lock().unwrap() = Some(lossy);
        let stop = Arc::new(AtomicBool::new(false));
        let pump = stream_to(tunnel, Arc::clone(&stop));
        let v = judged(&windows(settle_and_measure, |_| {}));
        stop.store(true, Relaxed);
        let _ = pump.join();
        std::thread::sleep(Duration::from_secs(2));
        let stop = Arc::new(AtomicBool::new(false));
        competitor_sender(&rt, competitor, Arc::clone(&stop));
        let c = judged(&windows(settle_and_measure, |_| {}));
        stop.store(true, Relaxed);
        std::thread::sleep(Duration::from_secs(1));
        assert_on_time(lossy.name, &v);
        assert_on_time(lossy.name, &c);
        assert_competed(lossy.name, &c);
        let (vm, cm) = (mean_of(&v, |x| x.vox), mean_of(&c, |x| x.other));
        lossy_bars.push((lossy.name, cm * LOSSY_WIN));
        let ratio = vm / cm;
        let verdict = if ratio >= LOSSY_WIN {
            format!("ok (>= {LOSSY_WIN:.1}x)")
        } else {
            failed.push(format!(
                "{}: the emulator was on time and the comparison flow (Cubic, same loss) carried \
                 {:.1} Mbit/s; vox carried {:.1} Mbit/s, {ratio:.2}x of it, under {LOSSY_WIN:.1}x: \
                 vox is slow on a lossy link",
                lossy.name,
                cm / 1e6,
                vm / 1e6
            ));
            format!("BELOW {LOSSY_WIN:.1}x")
        };
        report.push(format!(
            "{}: vox {:.1} Mbit/s, Cubic on the same loss {:.1} Mbit/s, {ratio:.2}x — {verdict}; \
             per-second vox {:?}, Cubic {:?}",
            lossy.name,
            vm / 1e6,
            cm / 1e6,
            mbit(&v, |x| x.vox),
            mbit(&c, |x| x.other)
        ));
    }

    // The congested links: Vox and the comparison flow at once, through one queue, deep and shallow.
    for congested in [CONGESTED, CONGESTED_SHALLOW, CONGESTED_LAN] {
        if !wanted(congested.name) {
            continue;
        }
        *link.lock().unwrap() = Some(congested);
        let stop = Arc::new(AtomicBool::new(false));
        competitor_sender(&rt, competitor, Arc::clone(&stop));
        let pump = stream_to(tunnel, Arc::clone(&stop));
        let all = windows(SETTLE + CONGESTED_MEASURE, |_| {});
        let w = all[SETTLE.as_secs() as usize..].to_vec();
        stop.store(true, Relaxed);
        let _ = pump.join();
        std::thread::sleep(Duration::from_secs(1));
        assert_on_time(congested.name, &w);
        assert_competed(congested.name, &w);
        let (vm, cm) = (mean_of(&w, |x| x.vox), mean_of(&w, |x| x.other));
        let ratio = vm / cm;
        let verdict = if ratio < FAIR_LOW {
            failed.push(format!(
                "{}: the emulator was on time; vox carried {:.1} Mbit/s against the Cubic flow's \
                 {:.1}, {ratio:.2}x, under {FAIR_LOW:.1}x: vox gives way on a shared link",
                congested.name,
                vm / 1e6,
                cm / 1e6
            ));
            format!("BELOW {FAIR_LOW:.1}x")
        } else if ratio > FAIR_HIGH {
            failed.push(format!(
                "{}: the emulator was on time; vox carried {:.1} Mbit/s against the Cubic flow's \
                 {:.1}, {ratio:.2}x, over {FAIR_HIGH:.1}x: vox takes more than its share",
                congested.name,
                vm / 1e6,
                cm / 1e6
            ));
            format!("ABOVE {FAIR_HIGH:.1}x")
        } else {
            format!("fair ({FAIR_LOW:.1}x-{FAIR_HIGH:.1}x)")
        };
        // The cost of a failed tier-3 trial, made visible: the 2 s windows furthest from fair.
        let pairs: Vec<f64> = w
            .windows(2)
            .map(|p| (p[0].vox + p[1].vox) / (p[0].other + p[1].other).max(1.0))
            .collect();
        let worst_high = pairs.iter().copied().fold(0.0, f64::max);
        let worst_low = pairs.iter().copied().fold(f64::INFINITY, f64::min);
        report.push(format!(
            "{}: vox {:.1} Mbit/s, Cubic {:.1} Mbit/s, {ratio:.2}x over {} s — {verdict}; worst 2 s \
             windows {worst_low:.2}x and {worst_high:.2}x; per-second vox {:?}, Cubic {:?}",
            congested.name,
            vm / 1e6,
            cm / 1e6,
            CONGESTED_MEASURE.as_secs(),
            mbit(&w, |x| x.vox),
            mbit(&w, |x| x.other)
        ));
    }

    // The changing links: clean, lossy, clean, under one running transfer, at 1% loss (tier 2's
    // case) and at 5% (tier 3's).
    for lossy_link in [WIFI, WIFI_HEAVY] {
        let name = changing_name(&lossy_link);
        if !wanted(&name) {
            continue;
        }
        let clean = Link {
            loss: 0.0,
            ..lossy_link
        };
        // The clean bar: raw TCP over the same clean link, as for every gated link above.
        *link.lock().unwrap() = Some(clean);
        std::thread::sleep(Duration::from_millis(500));
        let raw_rate = transfer(raw, done) * 8.0;
        let bar = raw_rate * MIN_RATIO;
        let lossy_bar = lossy_bars
            .iter()
            .find(|(n, _)| *n == lossy_link.name)
            .map(|&(_, b)| b)
            .expect("the lossy arm for this link runs first");
        let stop = Arc::new(AtomicBool::new(false));
        let pump = stream_to(tunnel, Arc::clone(&stop));
        let l = Arc::clone(link);
        let all = windows(SETTLE + PHASE * 3, move |t| {
            let lossy = t >= SETTLE + PHASE && t < SETTLE + PHASE * 2;
            *l.lock().unwrap() = Some(if lossy { lossy_link } else { clean });
        });
        stop.store(true, Relaxed);
        let _ = pump.join();
        let n = PHASE.as_secs() as usize;
        let s = SETTLE.as_secs() as usize;
        let (clean1, lossy, clean2) = (
            &all[s..s + n],
            &all[s + n..s + 2 * n],
            &all[s + 2 * n..s + 3 * n],
        );
        assert_on_time(&name, &all[s..]);
        let below = |w: &[Window]| w.iter().filter(|x| x.vox < bar).count();
        let r = RECOVER_WITHIN.as_secs() as usize;
        let lossy_mean = mean_of(&lossy[CLIMB_WITHIN.as_secs() as usize..], |x| x.vox);
        let mut verdicts = Vec::new();
        if below(clean1) > 0 {
            verdicts.push(format!(
                "{} of the first clean phase's seconds below the clean bar",
                below(clean1)
            ));
        }
        if lossy_mean < lossy_bar {
            verdicts.push(format!(
                "the lossy phase carried {:.1} Mbit/s, under {LOSSY_WIN:.1}x the Cubic flow on the \
                 same loss ({:.1} Mbit/s)",
                lossy_mean / 1e6,
                lossy_bar / 1e6
            ));
        }
        if below(&clean2[r..]) > 0 {
            verdicts.push(format!(
                "{} of the second clean phase's seconds after the first {} s below the clean bar \
                 (not back to full speed {} s after the loss ended, or fell back again)",
                below(&clean2[r..]),
                RECOVER_WITHIN.as_secs(),
                RECOVER_WITHIN.as_secs()
            ));
        }
        let verdict = if verdicts.is_empty() {
            "ok".to_owned()
        } else {
            failed.push(format!(
                "{name}: the emulator was on time; {}: vox is slow when the link changes",
                verdicts.join("; ")
            ));
            "BELOW".to_owned()
        };
        report.push(format!(
            "{name}: clean bar {:.1} Mbit/s ({:.0}% of raw {:.1}), lossy bar {:.1} Mbit/s; \
             per-second clean {:?}, lossy {:?}, clean {:?} — {verdict}",
            bar / 1e6,
            MIN_RATIO * 100.0,
            raw_rate / 1e6,
            lossy_bar / 1e6,
            mbit(clean1, |x| x.vox),
            mbit(lossy, |x| x.vox),
            mbit(clean2, |x| x.vox)
        ));
    }
    drop(rt);
}
