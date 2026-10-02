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
//! **ADR-024's arms** (the decider, 2026-10-01; see `taper_arms`): on a clean 400 Mbit/s, 2 ms
//! LAN-like link, which the emulator carries under ordinary load, every 2 s window is at the clean bar
//! (90% of raw); on a 200 Mbit/s, 10 ms Wi-Fi-like
//! link at 1% and at 6% loss the tunnel carries at least [`LOSSY_WIN`] of a Cubic flow on the same
//! loss; on a link it shares with a Cubic flow (200 Mbit/s through a one-BDP and a quarter-BDP queue,
//! and a 400 Mbit/s, 2 ms LAN-like link through a one-BDP queue, each over [`CONGESTED_MEASURE`]), its rate is
//! between [`FAIR_LOW`] and [`FAIR_HIGH`] of that flow's; on a lossy link shared with a Cubic flow
//! (1% and 6% loss, one-BDP queue), and one that joins vox on a 6%-loss link with a deep queue, that
//! flow keeps at least [`SHARED_KEEP`] of its solo rate; and on
//! a link that goes clean, lossy and
//! clean again under one transfer, every 2 s window of each clean phase (past [`RECOVER_WITHIN`] after
//! the loss) is at the clean bar and the lossy phase clears the lossy bar. These are judged by the
//! speed a person sees, never by which controller the tunnel is running. The comparison flow is
//! quinn's stock Cubic over the same emulated link, not kernel TCP: see the comment above
//! `STREAM_MARK` for why.
//!
//! **Every red names its side** (V210-98). The emulator is part of the apparatus, and on a busy
//! machine it can fall behind the link it plays, which the raw arm (behind a TCP proxy and a deep
//! buffer) cannot feel and the tunnel's congestion control does. So:
//! - **CANNOT MEASURE** (never green and never the tunnel's): the emulator fell short of
//!   [`EMULATOR_FIDELITY`] in every calibration window; or vox fell under [`MIN_RATIO`] while the
//!   emulator ran more than [`MAX_EMULATOR_LATENESS`] late during the timed tunnel transfers; and in
//!   either case something other than vox was the machine's busiest process. The message names the windows or the lateness and the busiest processes: that run
//!   measured the emulator, not vox. So is a precondition this test sets up that never held.
//! - **PRODUCT**: the emulator carried the link and was on time, and vox carried less than
//!   [`MIN_RATIO`] of raw; or the emulator fell short or ran late because vox was the busiest
//!   process (vox took the CPU the link needed); or the tunnel refused, cut or never finished a
//!   transfer. The message says what vox did.
//! - **PRODUCT (staging)**: a step vox itself performs before the measurement (`vox id`, `vox trust
//!   add`, `vox connect`, advertising the address it was told to, printing what the proof waits
//!   for) failed. The message quotes what vox said.
//! - On ADR-024's arms: **APPARATUS** when the emulator ran more than [`MAX_EMULATOR_LATENESS`] late
//!   in any judged second, or the comparison flow carried nothing (its connection never ran);
//!   **PRODUCT** when the emulator was on time and vox missed the arm's bar, quoting vox's rate, the
//!   comparison flow's and the bar.
//!
//! Every run, passing or not, prints each link's percentage, drops, calibration windows, lateness
//! and per-round figures.
//!
//! Mutation knob (test-side only): `VOX_PERF_MIN_RATIO` replaces the target ratio. Diagnostic knob:
//! `VOX_PERF_ONLY=<text>` runs only the links and arms whose name contains it, or any of several
//! texts separated by `|`.

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
        RELEASED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if late >= 4_000 {
            RELEASED_LATE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Packets the emulator released on a shaped link, and how many of them at least 4 ms late (the
/// rise tier 2 reads as a queue): what share of a second's packets ran late, for ADR-024's arms.
static RELEASED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static RELEASED_LATE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The longest lateness since the last call, and start counting afresh.
fn take_lateness() -> Duration {
    Duration::from_micros(LATENESS_US.swap(0, std::sync::atomic::Ordering::Relaxed))
}

/// The most an emulator may run late during a gated transfer and still be measuring the link.
/// Measured on GitHub's runners: 5-24 ms on macOS's VM in runs where the tunnel held the link's
/// full rate, under 7 ms on ubuntu. The stalls that moved the tunnel's figure were 41 ms and longer.
///
/// **A late emulator withholds a red; it never voids a pass.** A late release can only slow the
/// tunnel, never speed it, so a tunnel that held [`MIN_RATIO`] across a late emulator held it in
/// spite of it.
///
/// **This bound, not a per-slice maximum** (an early ADR-024 draft's rule: a slice counted late
/// if its single latest release was 4 ms late, and the link CANNOT MEASURE if more than 10% of
/// judged slices or the median one were). This emulator releases each packet by sleeping until it is due, and a sleep
/// overshoots by a few ms when packets are sparse, so its lateness is largest exactly when vox is
/// slow. Measured in 100 ms slices (a spike; a transfer here lasts about a second), a tunnel held
/// to 1% of raw by a 64 KiB stream window ran with 714 of 768 slices 4 ms late (median 9.0 ms,
/// worst 16.9 ms): that rule would have called that product shortfall CANNOT MEASURE. A healthy
/// tunnel at 103% of raw on WAN, at load 7-10, ran with 12-25 of about 60 slices 4-10 ms late
/// (V210-98 c3). ADR-024's arms use a different rule, by packet share ([`LATE_PACKET_SHARE`]): a
/// second counts late only when most of its packets were released late, so a sleep's overshoot
/// on a few sparse packets does not count; that rule applies to those arms only, not to these
/// links.
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
/// **On a link, the sender is paced at 1.05x its rate, and the best of three windows must hold.** An
/// unpaced flood is a busy thread that competes with the emulator's own threads for the CPU, which
/// measures the emulator under an overload the real transfers never create (they are paced by
/// congestion control). On GitHub's 3-core macOS runner that competition alone took fidelity to
/// 91.9% and 88.2% in 5 of 12 windows, where a paced sender got 96.8-98.0%. A window that catches
/// the VM being preempted by its host loses a few percent more (2 of 18 paced windows there: 92.8%,
/// 89.7%).
///
/// **Calibration asks whether the emulator can carry the link here; the transfers ask whether it
/// did.** A window catches whatever else the machine did in those two seconds, not the transfers:
/// on a Mac doing ordinary work (load 31-66) one window in three fell to 64-83% while the others held
/// 95-98%, and requiring every window made the 1 Gbit/s LAN link unmeasurable there (V210-98 c3).
/// So the best window must reach [`EMULATOR_FIDELITY`], which still refuses an emulator that can
/// never carry the link; and the emulator's lateness is judged during each timed tunnel transfer
/// itself ([`MAX_EMULATOR_LATENESS`]). A release thread that falls behind the link releases its
/// packets late, so an emulator that stalled during a transfer shows there. (The run that once put
/// the tunnel at 88.9% of raw had calibrated at 97.9%, 77.6% and 95.8%; a window says nothing about
/// the transfer it did not overlap.) Unshaped (`None`) there is no rate to pace at, so it is one unpaced window,
/// as before; it is reported, not gated.
///
/// Returns each window's rate, in bytes per second: three on a link, one unshaped.
fn calibrate_windows(link: Option<Link>) -> Vec<f64> {
    let n = if link.is_some() { 3 } else { 1 };
    (0..n).map(|_| calibrate_once(link)).collect()
}

/// Every process as (%CPU, pid, command), busiest first. Sorted here, not by `ps`: macOS's `-r`
/// sorts by CPU, but procps on Linux reads `-r` as "running processes only".
fn processes() -> Vec<(f64, u32, String)> {
    let Ok(out) = Command::new("ps")
        .args(["-Ao", "pcpu=,pid=,comm="])
        .output()
    else {
        return Vec::new();
    };
    let mut rows: Vec<(f64, u32, String)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let cpu = f.next()?.parse().ok()?;
            let pid = f.next()?.parse().ok()?;
            Some((cpu, pid, f.collect::<Vec<_>>().join(" ")))
        })
        .collect();
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    rows
}

/// What competed for the CPU when the emulator could not carry a link: the busiest processes, or
/// why there is no list.
fn busiest(procs: &[(f64, u32, String)]) -> String {
    if procs.is_empty() {
        return "(ps printed no processes, so the busiest could not be read)".to_owned();
    }
    procs
        .iter()
        .take(6)
        .map(|(cpu, pid, comm)| format!("{cpu:5.1}% {pid:>7} {comm}"))
        .collect::<Vec<_>>()
        .join("\n")
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

/// **Every red names its side** (decider rule 1). A verdict on the product starts `PRODUCT` and
/// says what the product did; a precondition, emulator or harness failure starts
/// `CANNOT MEASURE`, and a staging step vox itself performs that fails is `PRODUCT (staging)`.
/// Anything else that panics (an `unwrap` on a socket, a file, a thread) is this proof's own
/// failure, and this hook says so before its message.
fn label_reds() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let payload = info.payload();
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("");
            if !(message.starts_with("PRODUCT") || message.starts_with("CANNOT MEASURE")) {
                shown(
                    "CANNOT MEASURE (harness error): the panic below is this proof's own, not a \
                     verdict on the product",
                );
            }
            previous(info);
        }));
    });
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
            "PRODUCT (staging): vox ({}) never printed {what} within 120 s. It said:\n{}",
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
///
/// `side` names who answers for a failure: `"PRODUCT"` for the tunnel (the forward's port, and every
/// byte it must carry), `"CANNOT MEASURE (harness error)"` for the raw arm (this test's own TCP shaper).
fn transfer(to: SocketAddr, done: &mpsc::Receiver<(Instant, Instant)>, side: &str) -> f64 {
    let chunk = vec![0x5au8; CHUNK];
    let mut s = TcpStream::connect(to)
        .unwrap_or_else(|e| panic!("{side}: connecting to {to} for a transfer failed: {e}"));
    let mut sent = 0u64;
    while sent < BYTES {
        let n = usize::try_from((BYTES - sent).min(CHUNK as u64)).unwrap();
        s.write_all(&chunk[..n]).unwrap_or_else(|e| {
            panic!("{side}: the connection to {to} failed {sent} bytes into a transfer: {e}")
        });
        sent += n as u64;
    }
    let (quarter, end) = done
        .recv_timeout(Duration::from_secs(300))
        .unwrap_or_else(|_| {
            panic!("{side}: {to} did not deliver all {BYTES} bytes to the sink within 300 s")
        });
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
    // The raw-TCP links take about 4 minutes; ADR-024's arms add about 10 (each runs a settle and a
    // judged stretch, 60 s on the congested ones). The watchdog bounds a hung run, so it gets both
    // and a margin: at 600 s it aborted a run that had measured every arm.
    watchdog::arm_for(Duration::from_secs(1800));
    label_reds();
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
    assert!(ok, "PRODUCT (staging): host: vox id failed: {err}");
    let (ok, guest_fp, err) = vox_once(&guest_dir, &["id"]);
    assert!(ok, "PRODUCT (staging): guest: vox id failed: {err}");
    let (ok, _, err) = vox_once(
        &host_dir,
        &["trust", "add", guest_fp.trim(), "--name", "guest"],
    );
    assert!(
        ok,
        "PRODUCT (staging): host: vox trust add guest failed: {err}"
    );

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
    let _ = TUNNEL_CARRIED.set(Arc::clone(&carried));
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
        "PRODUCT (staging): the host did not advertise the address it was told to: {address}"
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
    assert!(ok, "PRODUCT (staging): vox connect failed.\n{out}\n{err}");
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
    let _ = transfer(tunnel, &done, "PRODUCT");
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
        "CANNOT MEASURE (precondition unmet) a direct path: the anchor still carried a circuit 120 s after the forward came up"
    );

    // Unshaped first: the raw-efficiency figure. The tunnel still crosses the emulator here, so this
    // is a floor on Vox's efficiency, not a ceiling. (An unpaced blast through the emulator overruns
    // its socket buffers and drops, so it cannot say what the emulator carries unshaped; the per-link
    // calibration below is paced by the link and can.)
    // Each link's line is shown the moment it is measured, so a later link's red cannot hide an
    // earlier link's verdict.
    let mut report = Vec::new();
    let mut add = |line: String| {
        shown(&format!("R41: {line}"));
        report.push(line);
    };
    let mut failed = Vec::new();
    // An APPARATUS fault on one link or arm makes that one CANNOT MEASURE and the run goes on: one
    // late window must not void every other link's and arm's figures.
    let mut cannot = Vec::new();
    match measure(tunnel, sink_addr, &done, &carried, None) {
        Ok((t, r, _)) => add(format!(
            "unshaped (efficiency, not gated; bounded by the emulator): tunnel {:.1} MB/s, raw loopback TCP {:.1} MB/s, {:.1}%",
            t / 1e6,
            r / 1e6,
            100.0 * t / r
        )),
        Err(fault) => cant(&mut cannot, fault),
    }
    // Diagnostic knob (test-side only): `VOX_PERF_ONLY` runs just the links whose name contains it.
    // The vox processes of this run, for telling a starved emulator's cause: vox, or something else.
    let vox_pids = [forward.child.id(), host.child.id(), anchor.child.id()];
    for l in LINKS {
        if !perf_only(l.name) {
            continue;
        }
        let windows = calibrate_windows(Some(l));
        // The best window: it shows the emulator can carry this link on this machine. Whether it
        // did during the transfers is judged there ([`MAX_EMULATOR_LATENESS`]).
        let fidelity = windows.iter().copied().fold(0.0, f64::max) * 8.0 / l.bits_per_sec;
        let pct: Vec<String> = windows
            .iter()
            .map(|w| format!("{:.1}%", w * 8.0 / l.bits_per_sec * 100.0))
            .collect();
        if l.gated && fidelity < EMULATOR_FIDELITY {
            let procs = processes();
            let top = busiest(&procs);
            match procs.first().map(|(cpu, pid, _)| (*pid, *cpu)) {
                // vox took the CPU the emulator needed: the product starved the link.
                Some((pid, cpu)) if vox_pids.contains(&pid) => failed.push(format!(
                    "PRODUCT: {}: the emulator delivered at most {:.1}% of the link's rate in its \
                     calibration windows ({pct:?}) while vox (pid {pid}) was the busiest \
                     process on the machine at {cpu:.0}% CPU: vox starved the link it runs over \
                     (load: {})\nbusiest processes:\n{top}",
                    l.name,
                    fidelity * 100.0,
                    uptime()
                )),
                _ => cant(
                    &mut cannot,
                    format!(
                    "CANNOT MEASURE (emulator late) {}: the emulator itself delivered at most {:.1}% of \
                     the link's rate in its calibration windows ({pct:?}; one must reach {:.0}%), \
                     and vox (pids {vox_pids:?}) was not the busiest process, so this run would \
                     measure the emulator, not vox (load: {})\nbusiest processes:\n{top}",
                    l.name,
                    fidelity * 100.0,
                    EMULATOR_FIDELITY * 100.0,
                    uptime()
                    ),
                ),
            }
            continue;
        }
        *link.lock().unwrap() = Some(l);
        std::thread::sleep(Duration::from_millis(500));
        let drops_before = TAIL_DROPS.load(std::sync::atomic::Ordering::Relaxed);
        let (t, r, rounds) = match measure(tunnel, raw, &done, &carried, Some(l)) {
            Ok(m) => m,
            Err(fault) => {
                cant(&mut cannot, fault);
                continue;
            }
        };
        let tail_drops = TAIL_DROPS.load(std::sync::atomic::Ordering::Relaxed) - drops_before;
        let ratio = t / r;
        let late = rounds.iter().map(|x| x.2).max().unwrap_or_default();
        let per_round: Vec<String> = rounds
            .iter()
            .map(|(t, r, late, _)| {
                format!(
                    "{:.1}/{:.1} MB/s late {} ms",
                    t / 1e6,
                    r / 1e6,
                    late.as_millis()
                )
            })
            .collect();
        // A late emulator only ever costs the tunnel (its packets arrive later; nothing arrives
        // sooner), so it can withhold a red from the product but never void a pass.
        if l.gated && ratio < min_ratio && late > MAX_EMULATOR_LATENESS {
            // Whose fault is a late emulator? If a vox process is the busiest on the machine, vox
            // took the CPU the link needed: that is the product starving the link it runs over.
            // Otherwise something else did, and the run measured the emulator.
            // The processes during the latest round's tunnel transfer.
            let procs = rounds
                .iter()
                .max_by_key(|x| x.2)
                .map(|x| x.3.clone())
                .unwrap_or_default();
            let top = busiest(&procs);
            match procs.first().map(|(cpu, pid, _)| (*pid, *cpu)) {
                Some((pid, cpu)) if vox_pids.contains(&pid) => failed.push(format!(
                    "PRODUCT: {}: the emulator was {} ms late during a timed tunnel transfer while \
                     vox (pid {pid}) was the busiest process on the machine at {cpu:.0}% CPU: \
                     vox starved the link it runs over; rounds (tunnel/raw): {per_round:?}; \
                     calibration windows {pct:?}; load: {}\nbusiest processes during the latest \
                     transfer:\n{top}",
                    l.name,
                    late.as_millis(),
                    uptime()
                )),
                _ => cant(
                    &mut cannot,
                    format!(
                    "CANNOT MEASURE (emulator late) {}: vox carried {:.1}% of raw while the emulator \
                     was {} ms late during a timed tunnel transfer (at most {} ms measures the \
                     link), and vox (pids {vox_pids:?}) was not the busiest process, so this run \
                     measured the emulator, not vox; rounds (tunnel/raw): {per_round:?}; \
                     calibration windows {pct:?}; load: {}\nbusiest processes during the latest \
                     transfer:\n{top}",
                    l.name,
                    ratio * 100.0,
                    late.as_millis(),
                    MAX_EMULATOR_LATENESS.as_millis(),
                    uptime()
                    ),
                ),
            }
            continue;
        }
        let verdict = if !l.gated {
            "reported".to_owned()
        } else if ratio >= min_ratio {
            format!("ok (>= {:.0}%)", min_ratio * 100.0)
        } else {
            failed.push(format!(
                "{}: the emulator carried the link (a calibration window >= {:.0}%) and was on \
                 time (max lateness {} ms), and vox carried {:.1}% of raw, under {:.0}%: vox is slow",
                l.name,
                EMULATOR_FIDELITY * 100.0,
                late.as_millis(),
                ratio * 100.0,
                min_ratio * 100.0
            ));
            format!("BELOW {:.0}%", min_ratio * 100.0)
        };
        add(format!(
            "{}: tunnel {:.1} MB/s ({:.0} Mbit/s), raw {:.1} MB/s ({:.0} Mbit/s), {:.1}% — {verdict}; \
             emulator fidelity {:.1}% (windows {pct:?}), lateness {} ms; queue drops {tail_drops}; \
             rounds (tunnel/raw) {per_round:?}",
            l.name, t / 1e6, t * 8.0 / 1e6, r / 1e6, r * 8.0 / 1e6, 100.0 * ratio, fidelity * 100.0,
            late.as_millis()
        ));
    }
    taper_arms(
        Rig {
            tunnel,
            link: &link,
            bottleneck: &bottleneck,
            raw,
            done: &done,
        },
        &mut report,
        &mut failed,
        &mut cannot,
    );
    *link.lock().unwrap() = None;
    shown(&format!("uptime at end: {}", uptime()));
    // No check of the anchor's circuit count here: every link's transfers (`measure`) and every
    // ADR-024 arm (`crossed_fault`) assert that the tunnel's own bytes crossed its emulated link,
    // which a relay fallback would fail. The anchor's count also counts a joiner's raced duplicate
    // connection that lost the tie-break to the direct one and lingers for its 60 s grace, and it
    // called that a fallback while the tunnel stayed direct (host: "a new connection ... lost the
    // tie-break to the one held ... Direct against Relayed; retired, closed in 60s").
    assert!(
        failed.is_empty(),
        "PRODUCT: R41: the tunnel throttles the link it runs over: {failed:?}\nand CANNOT MEASURE \
         (APPARATUS) on {} other arm(s): {cannot:?}\n{}",
        cannot.len(),
        report.join("\n")
    );
    assert!(
        cannot.is_empty(),
        "CANNOT MEASURE (APPARATUS): R41: {} arm(s), and no product red on the arms that measured: \
         {cannot:?}\n{}",
        cannot.len(),
        report.join("\n")
    );
    drop(forward);
    drop(host);
    drop(anchor);
}

/// One round: the tunnel's and raw's throughput, the emulator's longest lateness during the
/// tunnel's transfer, and the processes as they stood during it, busiest first.
type Round = (f64, f64, Duration, Vec<(f64, u32, String)>);

/// Median throughput of the tunnel and of raw over `ROUNDS` interleaved transfers, and a check that
/// the tunnel's bytes crossed the shaper: a tunnel that bypassed it would score whatever it liked.
/// Also each round's tunnel and raw figures, and how late the emulator ran during its tunnel
/// transfer. A tunnel whose bytes did not cross the emulator (a relayed transfer: the anchor is not
/// behind it) is that link's CANNOT MEASURE, returned for the caller to collect.
fn measure(
    tunnel: SocketAddr,
    raw: SocketAddr,
    done: &mpsc::Receiver<(Instant, Instant)>,
    carried: &std::sync::atomic::AtomicU64,
    link: Option<Link>,
) -> Result<(f64, f64, Vec<Round>), String> {
    let mut t = Vec::new();
    let mut r = Vec::new();
    let mut rounds = Vec::new();
    for _ in 0..ROUNDS {
        let before = carried.load(std::sync::atomic::Ordering::Relaxed);
        let _ = take_lateness();
        // Who had the CPU is read while the tunnel carries the bytes, not after: once the transfer
        // ends vox is idle, and macOS's decaying %CPU no longer shows what it took.
        let stop = std::sync::atomic::AtomicBool::new(false);
        let (secs, during) = std::thread::scope(|s| {
            let sampler = s.spawn(|| {
                let mut last = Vec::new();
                loop {
                    std::thread::sleep(Duration::from_millis(250));
                    let now = processes();
                    if !now.is_empty() {
                        last = now;
                    }
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        return last;
                    }
                }
            });
            let secs = transfer(tunnel, done, "PRODUCT");
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            (secs, sampler.join().unwrap())
        });
        t.push(secs);
        let late = take_lateness();
        let crossed = carried.load(std::sync::atomic::Ordering::Relaxed) - before;
        if crossed < BYTES {
            return Err(format!(
                "CANNOT MEASURE (precondition unmet) {link:?}: only {crossed} of the tunnel's {BYTES} bytes crossed the emulated link"
            ));
        }
        r.push(transfer(raw, done, "CANNOT MEASURE (harness error)"));
        rounds.push((t[t.len() - 1], r[r.len() - 1], late, during));
    }
    Ok((median(t), median(r), rounds))
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
/// The same link at 6% loss: clearly past tier 2's 5% loss cap, where only tier 3 (BBR) clears the
/// bar. Not 5%: a link at exactly the cap is the boundary, and may stay in tier 2 (the decider,
/// 2026-10-01), so an arm there would test boundary noise, not the rule.
const WIFI_HEAVY: Link = Link {
    name: "Wi-Fi-like, 200 Mbit/s, 10 ms RTT, 6% loss",
    loss: 0.06,
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
/// A congested LAN-like link: 400 Mbit/s, 2 ms, one-BDP queue (100 KB) shared with the Cubic flow. A
/// full queue here is only 2 ms of delay, under tier 2's delay test, so only the loss signals can see
/// this congestion: at 1 Gbit/s, 2 ms, tier 2 without the loss trend took 2.56x the Cubic flow
/// (ADR-024 M24.1). 400 Mbit/s rather than 1 Gbit/s because the userspace emulator holds that rate
/// on a machine doing ordinary work; at 1 Gbit/s it ran up to 53 ms late.
/// The lossy links shared with the Cubic flow through a one-BDP queue: at 1% (tier 2's case) and at
/// 6% (tier 3's). The decider (2026-10-01): Vox never pushes a competing flow below its solo rate on
/// such a link; the Cubic flow keeps at least [`SHARED_KEEP`] of what it carries alone there. Vox
/// taking many times a loss-limited Cubic flow's rate is fair, as long as that flow keeps its own.
const LOSSY_SHARED: [Link; 2] = [
    Link {
        name: "lossy shared, 200 Mbit/s, 10 ms RTT, 1% loss, 1-BDP queue, with a Cubic flow",
        loss: 0.01,
        queue_bdps: Some(1.0),
        ..WIFI
    },
    Link {
        name: "lossy shared, 200 Mbit/s, 10 ms RTT, 6% loss, 1-BDP queue, with a Cubic flow",
        loss: 0.06,
        queue_bdps: Some(1.0),
        ..WIFI
    },
];
/// The joined arm's link: 6% loss and a deep (4-BDP) queue. Vox runs alone on it until it has had
/// time to reach tier 3, then a Cubic flow starts beside it: a second download starting while a
/// tunnel is already busy. The Cubic flow keeps at least [`SHARED_KEEP`] of its solo rate (the lead,
/// 2026-10-02: gated; fix-adr024-bbr's spike measured 55% here with tier 3 as it was then).
const JOINED: Link = Link {
    name: "joined, 200 Mbit/s, 10 ms RTT, 6% loss, 4-BDP queue, a Cubic flow joins vox",
    loss: 0.06,
    queue_bdps: Some(4.0),
    ..WIFI
};
/// How long vox runs alone on the joined link before the Cubic flow joins: tier 1's dwell, three
/// losses, tier 2's dwell and 32 MiB of trend at a few tens of Mbit/s, then tier 3's 20 rounds and
/// 2 s, with room to spare.
const JOINED_ALONE: Duration = Duration::from_secs(30);
/// The decider: on a lossy shared link the Cubic flow keeps at least this share of its solo rate.
const SHARED_KEEP: f64 = 0.90;
/// Beside the Cubic flow, vox must carry at least this share of that flow's solo rate on the same
/// link, or the arm has measured a stalled tunnel, not fairness (a mutant that never cut on loss
/// carried 0.0 Mbit/s there and left the flow its whole rate).
const SHARED_VOX_FLOOR: f64 = 0.5;
/// How long each half of the lossy shared arm (the Cubic flow alone, then both) is judged: long
/// enough that a loss-limited flow's mean is steady to a few percent. At 30 s, Cubic beside Cubic
/// read 89.8% of its solo rate on the 6% link, with the link far from full.
const SHARED_MEASURE: Duration = Duration::from_secs(60);
const CONGESTED_LAN: Link = Link {
    name: "congested LAN-like, 400 Mbit/s, 2 ms RTT, 1-BDP queue, shared with a Cubic flow",
    bits_per_sec: 4e8,
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
    name:
        "congested, shallow buffer, 200 Mbit/s, 10 ms RTT, 1/4-BDP queue, shared with a Cubic flow",
    queue_bdps: Some(0.25),
    ..CONGESTED
};

/// A clean LAN-like link at a rate the userspace emulator carries on a machine doing ordinary work
/// (the 1 Gbit/s LAN above often cannot calibrate under load): a clean link must never be held in a
/// tier that slows it, and BBR measured 28% of raw on a clean LAN.
const CLEAN_LAN: Link = Link {
    name: "clean LAN-like, 400 Mbit/s, 2 ms RTT",
    bits_per_sec: 4e8,
    one_way: Duration::from_millis(1),
    loss: 0.0,
    gated: true,
    queue_bdps: None,
};
/// How long the clean LAN-like arm is judged, every 2 s window of it.
const CLEAN_MEASURE: Duration = Duration::from_secs(30);

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
/// trials included, not a steady state between them. The 2 s windows are printed as a DIAGNOSTIC
/// line only: no claim is made about any window shorter than the run.
const CONGESTED_MEASURE: Duration = Duration::from_secs(60);
/// The window a person's speed is read in.
const WINDOW: Duration = Duration::from_secs(1);
/// The changing arm: each phase's length, and how soon after the loss ends Vox must be back at the
/// clean bar.
const PHASE: Duration = Duration::from_secs(20);
const RECOVER_WITHIN: Duration = Duration::from_secs(5);
/// The paused arm: the 1%-loss link, a transfer that stops for [`PAUSE`] and resumes.
const PAUSED_NAME: &str = "paused, Wi-Fi-like, 200 Mbit/s, 10 ms RTT, 1% loss, 3 s pause";
/// Longer than vox-core's `IDLE_RESTART` (1 s), so the connection's controller restarts.
const PAUSE: Duration = Duration::from_secs(3);
/// How long into the lossy phase Vox may take to find its lossy-link speed before it is judged: at
/// 6% loss that is a climb of two tiers (at least 1 s in tier 1, 2 s of dwell and 2 s of evidence in
/// tier 2, then tier 3's trial), as ADR-024's thresholds set it.
const CLIMB_WITHIN: Duration = Duration::from_secs(8);

/// Does `VOX_PERF_ONLY` (unset: everything) select the link or arm called `name`? It holds one text,
/// or several separated by `|`, and selects a name that contains any of them.
fn perf_only(name: &str) -> bool {
    std::env::var("VOX_PERF_ONLY")
        .ok()
        .is_none_or(|o| o.split('|').any(|t| name.contains(t)))
}

/// The changing arm's name for a lossy phase on `lossy`.
fn changing_name(lossy: &Link) -> String {
    format!(
        "changing, 200 Mbit/s, 10 ms RTT: clean, {:.0}% loss, clean",
        lossy.loss * 100.0
    )
}

/// Write to the tunnel at `to` as fast as it takes, until `stop`.
fn stream_to(
    to: SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
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
    /// Bits per second the tunnel's emulated link carried toward the host in this window.
    crossed: f64,
    /// The share of the packets released in this window at least 4 ms late.
    late_share: f64,
}

/// The byte counter of the tunnel's emulated link toward the host, set once the shaper is up.
static TUNNEL_CARRIED: std::sync::OnceLock<Arc<std::sync::atomic::AtomicU64>> =
    std::sync::OnceLock::new();

/// Read both counters every [`WINDOW`] for `dur`; `at` runs before each window (to change the link).
fn windows(dur: Duration, mut at: impl FnMut(Duration)) -> Vec<Window> {
    use std::sync::atomic::Ordering::Relaxed;
    let start = Instant::now();
    let carried = || TUNNEL_CARRIED.get().map_or(0, |c| c.load(Relaxed));
    let (mut v0, mut c0, mut x0) = (STREAMED.load(Relaxed), COMPETED.load(Relaxed), carried());
    let (mut r0, mut l0) = (RELEASED.load(Relaxed), RELEASED_LATE.load(Relaxed));
    let _ = take_lateness();
    let mut out = Vec::new();
    let mut k = 1u32;
    while WINDOW * (k - 1) < dur {
        at(WINDOW * (k - 1));
        sleep_until(start + WINDOW * k);
        let (v, c, x) = (STREAMED.load(Relaxed), COMPETED.load(Relaxed), carried());
        let s = WINDOW.as_secs_f64();
        out.push(Window {
            vox: (v - v0) as f64 * 8.0 / s,
            other: (c - c0) as f64 * 8.0 / s,
            late: take_lateness(),
            crossed: (x - x0) as f64 * 8.0 / s,
            late_share: {
                let (r, l) = (RELEASED.load(Relaxed), RELEASED_LATE.load(Relaxed));
                let share = (l - l0) as f64 / (r - r0).max(1) as f64;
                (r0, l0) = (r, l);
                share
            },
        });
        (v0, c0, x0) = (v, c, x);
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

/// An arm measured the emulator, not vox, if the emulator ran late in any window judged: the CANNOT
/// MEASURE for that arm, or `None` when the emulator was on time.
///
/// Also when the emulator ran at least [`QUEUE_SIGNAL_LATENESS`] late in more than
/// [`LATE_SECONDS_SHARE`] of the judged seconds, or in the median one: tier 2 reads a queue from a
/// 4 ms rise in a round's minimum round trip. A round's minimum is over every packet in it, so one
/// late release does not move it, but lateness that lasts can fake or hide it (ADR-024).
fn late_fault(arm: &str, w: &[Window]) -> Option<String> {
    let over = w
        .iter()
        .filter(|x| x.late_share >= LATE_PACKET_SHARE)
        .count();
    if over as f64 > LATE_SECONDS_SHARE * w.len() as f64 {
        return Some(format!(
            "CANNOT MEASURE {arm} (APPARATUS): in {over} of {} judged seconds the emulator released \
             at least {:.0}% of the packets {} ms or more late (more than {:.0}% of the seconds; \
             lateness that lasts across a round can fake or hide the 4 ms rise tier 2 reads as a \
             queue), so this arm measured the emulator, not vox; per-second late share {:?}; load: {}",
            w.len(),
            LATE_PACKET_SHARE * 100.0,
            QUEUE_SIGNAL_LATENESS.as_millis(),
            LATE_SECONDS_SHARE * 100.0,
            w.iter().map(|x| format!("{:.2}", x.late_share)).collect::<Vec<_>>(),
            uptime()
        ));
    }
    let late = w.iter().map(|x| x.late).max().unwrap_or_default();
    (late > MAX_EMULATOR_LATENESS).then(|| {
        format!(
            "CANNOT MEASURE {arm} (APPARATUS): the emulator was {} ms late in a judged window (at \
             most {} ms measures the link), so this arm measured the emulator, not vox; per-window \
             lateness {:?} ms; load: {}",
            late.as_millis(),
            MAX_EMULATOR_LATENESS.as_millis(),
            w.iter().map(|x| x.late.as_millis()).collect::<Vec<_>>(),
            uptime()
        )
    })
}

/// How late the emulator ran across an arm's judged seconds: the most, the median, and how many
/// seconds held a release at least [`QUEUE_SIGNAL_LATENESS`] late. Printed with every arm, because
/// tier 2 reads a queue from a 4 ms rise in a round's minimum round trip, and an emulator that runs
/// that late can fake or hide it.
fn lateness(w: &[Window]) -> String {
    let mut ms: Vec<u128> = w.iter().map(|x| x.late.as_millis()).collect();
    ms.sort_unstable();
    let at: Vec<usize> = w
        .iter()
        .enumerate()
        .filter(|(_, x)| x.late >= QUEUE_SIGNAL_LATENESS)
        .map(|(i, _)| i)
        .collect();
    let shares: Vec<String> = w.iter().map(|x| format!("{:.2}", x.late_share)).collect();
    format!(
        "emulator lateness per second: max {} ms, median {} ms, {} of {} seconds at or over {} ms \
         (judged seconds {at:?}, counted from 0); share of packets released {} ms or more late, per \
         second: {shares:?}",
        ms.last().copied().unwrap_or_default(),
        ms.get(ms.len() / 2).copied().unwrap_or_default(),
        at.len(),
        w.len(),
        QUEUE_SIGNAL_LATENESS.as_millis(),
        QUEUE_SIGNAL_LATENESS.as_millis()
    )
}

/// The rise in a round's minimum round trip that tier 2 reads as a queue (ADR-024,
/// `QUEUE_DELAY_MIN`): emulator lateness at this size can fake or hide the signal.
const QUEUE_SIGNAL_LATENESS: Duration = Duration::from_millis(4);
/// The share of an arm's judged seconds that may be late seconds (below) before the arm measures
/// the emulator, not vox (ADR-024; to be calibrated from the shares every arm prints).
const LATE_SECONDS_SHARE: f64 = 0.10;
/// A late second: at least this share of its packets released [`QUEUE_SIGNAL_LATENESS`] or more
/// late. A round's minimum round trip is over every packet in the round (about 25 at 200 Mbit/s),
/// so one late release does not move it: only lateness that holds across most of a round does.
const LATE_PACKET_SHARE: f64 = 0.5;

/// The tunnel's bytes must have crossed its emulated link, or the arm measured some other path (a
/// relay through the anchor, say) and the link's figures say nothing about it.
fn crossed_fault(arm: &str, w: &[Window]) -> Option<String> {
    let (sent, crossed) = (mean_of(w, |x| x.vox), mean_of(w, |x| x.crossed));
    (crossed < 0.95 * sent).then(|| {
        format!(
            "CANNOT MEASURE {arm} (APPARATUS): the tunnel delivered {:.1} Mbit/s but its emulated \
             link carried only {:.1} Mbit/s toward the host, so the rest took another path (a relay?) \
             and this arm did not measure the link",
            sent / 1e6,
            crossed / 1e6
        )
    })
}

/// Record an arm's CANNOT MEASURE as it happens: a product red on another arm ends the run first, and
/// must not hide it.
fn cant(cannot: &mut Vec<String>, fault: String) {
    shown(&format!("R41: {fault}"));
    cannot.push(fault);
}

/// Record an arm's line as it is measured, so an arm that ends the run early leaves the others'.
fn note(report: &mut Vec<String>, line: String) {
    shown(&format!("R41: {line}"));
    report.push(line);
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
        *COMPARISON_CONN.lock().unwrap() = Some(conn.clone());
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

/// What ADR-024's arms run on: the tunnel, the link both shapers apply, the tunnel's queue toward the
/// host (shared with the comparison flow), and the raw-TCP path with its sink's completions.
struct Rig<'a> {
    tunnel: SocketAddr,
    link: &'a Shared,
    bottleneck: &'a Arc<Mutex<Pacer>>,
    raw: SocketAddr,
    done: &'a mpsc::Receiver<(Instant, Instant)>,
}

/// How many 2 s windows of `w` (each pair of neighbouring seconds) average under `bar`.
///
/// A clean link is judged in 2 s windows, not single seconds: the sink's counters are read once a
/// second, and bytes that land just past a boundary move from one second to the next. On a clean
/// 200 Mbit/s phase, fix-adr024-bbr found every second under the bar beside one above the link's
/// own rate (166/230, 173/224, 169/229, 174/222: each pair about 2 x 199), which is when the bytes
/// landed, not how fast vox sent them.
fn windows_below(w: &[Window], bar: f64) -> usize {
    w.windows(2)
        .filter(|p| (p[0].vox + p[1].vox) / 2.0 < bar)
        .count()
}

/// The comparison flow's connection while it runs, for [`comparison_stats`].
static COMPARISON_CONN: Mutex<Option<quinn::Connection>> = Mutex::new(None);

/// What the comparison flow's own congestion control says, read from quinn as an arm ends: its
/// window, smoothed round trip, packets lost and congestion events. With it, a comparison flow that
/// carried little names its side. A small window with many congestion events means Vox's traffic
/// pressed it (the product); a large window with little carried means its own sender was short of
/// CPU in this test process (the apparatus).
fn comparison_stats() -> String {
    COMPARISON_CONN
        .lock()
        .unwrap()
        .as_ref()
        .map_or("the comparison flow's stats: not connected".to_owned(), |c| {
            let p = c.stats().path;
            format!(
                "the comparison flow's own controller: window {} KB, srtt {:.1} ms, {} packets lost, \
                 {} congestion events",
                p.cwnd / 1024,
                p.rtt.as_secs_f64() * 1000.0,
                p.lost_packets,
                p.congestion_events
            )
        })
}

/// The comparison flow must have run, or there was nothing to compare with.
fn competed_fault(arm: &str, w: &[Window]) -> Option<String> {
    (mean_of(w, |x| x.other) <= 0.0).then(|| {
        format!(
            "CANNOT MEASURE {arm} (APPARATUS): the comparison flow carried nothing (harness error: \
             its QUIC connection never ran), so there is nothing to compare vox with"
        )
    })
}

/// ADR-024's arms, on the running tunnel. Each PRODUCT verdict goes into `failed`, each APPARATUS
/// fault into `cannot` (that arm only: the others still measure), each figure into `report`.
fn taper_arms(
    rig: Rig<'_>,
    report: &mut Vec<String>,
    failed: &mut Vec<String>,
    cannot: &mut Vec<String>,
) {
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    let Rig {
        tunnel,
        link,
        bottleneck,
        raw,
        done,
    } = rig;
    let wanted = perf_only;
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

    // The clean LAN-like link: every 2 s window at the clean bar, so no tier slows a clean link.
    'clean: {
        if !wanted(CLEAN_LAN.name) {
            break 'clean;
        }
        let windows_cal = calibrate_windows(Some(CLEAN_LAN));
        let pct: Vec<String> = windows_cal
            .iter()
            .map(|w| format!("{:.1}%", w * 8.0 / CLEAN_LAN.bits_per_sec * 100.0))
            .collect();
        // The best window, as on the links above (V210-98 c3): it shows the emulator can carry
        // this link here; whether it did during the judged seconds is the lateness rule's.
        let fidelity =
            windows_cal.iter().copied().fold(0.0, f64::max) * 8.0 / CLEAN_LAN.bits_per_sec;
        if fidelity < EMULATOR_FIDELITY {
            cant(
                cannot,
                format!(
                "CANNOT MEASURE {} (APPARATUS): the emulator itself delivered only {:.1}% of the \
                 link's rate at best in its calibration windows (windows {pct:?}; one must reach {:.0}%), so \
                 this arm would measure the emulator, not vox (load: {})",
                CLEAN_LAN.name,
                fidelity * 100.0,
                EMULATOR_FIDELITY * 100.0,
                uptime()
            ),
            );
            break 'clean;
        }
        *link.lock().unwrap() = Some(CLEAN_LAN);
        std::thread::sleep(Duration::from_millis(500));
        let raw_rate = transfer(raw, done, "CANNOT MEASURE (harness error)") * 8.0;
        let bar = raw_rate * MIN_RATIO;
        let stop = Arc::new(AtomicBool::new(false));
        let pump = stream_to(tunnel, Arc::clone(&stop));
        let all = windows(SETTLE + CLEAN_MEASURE, |_| {});
        stop.store(true, Relaxed);
        let _ = pump.join();
        std::thread::sleep(Duration::from_secs(1));
        let w = &all[SETTLE.as_secs() as usize..];
        if let Some(e) = late_fault(CLEAN_LAN.name, w).or_else(|| crossed_fault(CLEAN_LAN.name, w))
        {
            cant(cannot, e);
            break 'clean;
        }
        let below = windows_below(w, bar);
        let verdict = if below == 0 {
            "ok".to_owned()
        } else {
            failed.push(format!(
                "{}: the emulator carried the link (calibration windows {pct:?}) and was on time; \
                 {below} of {} 2 s windows were under the clean bar of {:.1} Mbit/s ({:.0}% of raw \
                 {:.1}), slowest {:.1} Mbit/s: vox slows a clean link",
                CLEAN_LAN.name,
                w.len().saturating_sub(1),
                bar / 1e6,
                MIN_RATIO * 100.0,
                raw_rate / 1e6,
                w.iter().map(|x| x.vox).fold(f64::INFINITY, f64::min) / 1e6
            ));
            "BELOW".to_owned()
        };
        note(report, format!(
            "{}: clean bar {:.1} Mbit/s ({:.0}% of raw {:.1}); vox mean {:.1} Mbit/s, {below} 2 s windows \
             below — {verdict}; calibration {pct:?}; {}; per-second {:?}",
            CLEAN_LAN.name,
            bar / 1e6,
            MIN_RATIO * 100.0,
            raw_rate / 1e6,
            mean_of(w, |x| x.vox) / 1e6,
            lateness(w),
            mbit(w, |x| x.vox)
        ));
    }
    let judged = |w: &[Window]| w[w.len() - MEASURE.as_secs() as usize..].to_vec();

    // The lossy link: Vox alone, then the comparison flow alone, each over the same loss.
    let mut lossy_bars: Vec<(&str, f64)> = Vec::new();
    for lossy in [WIFI, WIFI_HEAVY] {
        let feeds_changing =
            wanted(&changing_name(&lossy)) || (lossy.name == WIFI.name && wanted(PAUSED_NAME));
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
        if let Some(e) = late_fault(lossy.name, &v)
            .or_else(|| crossed_fault(lossy.name, &v))
            .or_else(|| late_fault(lossy.name, &c))
            .or_else(|| competed_fault(lossy.name, &c))
        {
            cant(cannot, e);
            continue;
        }
        let (vm, cm) = (mean_of(&v, |x| x.vox), mean_of(&c, |x| x.other));
        lossy_bars.push((lossy.name, cm * LOSSY_WIN));
        let ratio = vm / cm;
        let verdict = if ratio >= LOSSY_WIN {
            format!("ok (>= {LOSSY_WIN:.1}x)")
        } else {
            failed.push(format!(
                "{}: the emulator was on time and the comparison flow (Cubic, same loss) carried \
                 {:.1} Mbit/s; vox carried {:.1} Mbit/s, {ratio:.3}x of it, under {LOSSY_WIN:.1}x: \
                 vox is slow on a lossy link",
                lossy.name,
                cm / 1e6,
                vm / 1e6
            ));
            format!("BELOW {LOSSY_WIN:.1}x")
        };
        note(
            report,
            format!(
            "{}: vox {:.1} Mbit/s, Cubic on the same loss {:.1} Mbit/s, {ratio:.3}x — {verdict}; \
             vox's {}; the Cubic flow's {}; per-second vox {:?}, Cubic {:?}",
            lossy.name,
            vm / 1e6,
            cm / 1e6,
            lateness(&v),
            lateness(&c),
            mbit(&v, |x| x.vox),
            mbit(&c, |x| x.other)
        ),
        );
    }

    // The changing and paused arms run before the lossy shared and congested arms: those fail
    // tier-3 trials on purpose, and a failed trial bars tier 3 for 30 s or more, which survives
    // from arm to arm on the one tunnel (ADR-024: the back-off is fairness memory). Run after
    // them, a changing arm's 20 s lossy phase can fall inside that bar (fix-adr024-bbr's trace:
    // tier 3 "locked" for about 90 s after the 6% lossy shared arm), and it would measure the
    // previous arm, not the change.
    // The changing links: clean, lossy, clean, under one running transfer, at 1% loss (tier 2's
    // case) and at 6% (tier 3's).
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
        let raw_rate = transfer(raw, done, "CANNOT MEASURE (harness error)") * 8.0;
        let bar = raw_rate * MIN_RATIO;
        let Some(lossy_bar) = lossy_bars
            .iter()
            .find(|(n, _)| *n == lossy_link.name)
            .map(|&(_, b)| b)
        else {
            cant(
                cannot,
                format!(
                "CANNOT MEASURE {name} (APPARATUS): the lossy arm it is judged against did not \
                 measure (precondition unmet)"
            ),
            );
            continue;
        };
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
        if let Some(e) = late_fault(&name, &all[s..]).or_else(|| crossed_fault(&name, &all[s..])) {
            cant(cannot, e);
            continue;
        }
        let below = |w: &[Window]| windows_below(w, bar);
        let r = RECOVER_WITHIN.as_secs() as usize;
        let lossy_mean = mean_of(&lossy[CLIMB_WITHIN.as_secs() as usize..], |x| x.vox);
        let mut verdicts = Vec::new();
        if below(clean1) > 0 {
            verdicts.push(format!(
                "phase CLEAN (first): {} of its 2 s windows below the clean bar",
                below(clean1)
            ));
        }
        if lossy_mean < lossy_bar {
            verdicts.push(format!(
                "phase LOSSY: it carried {:.1} Mbit/s, under {LOSSY_WIN:.1}x the Cubic flow on the \
                 same loss ({:.1} Mbit/s)",
                lossy_mean / 1e6,
                lossy_bar / 1e6
            ));
        }
        if below(&clean2[r..]) > 0 {
            verdicts.push(format!(
                "phase RECOVERY (second clean): {} of its 2 s windows after the first {} s below the clean \
                 bar (not back to full speed {} s after the loss ended, or fell back again)",
                below(&clean2[r..]),
                RECOVER_WITHIN.as_secs(),
                RECOVER_WITHIN.as_secs()
            ));
        }
        let verdict = if verdicts.is_empty() {
            "ok".to_owned()
        } else {
            failed.push(format!(
                "{name}: the emulator was on time; {}: vox is slow when the link changes; \
                 per-second clean {:?}, lossy {:?}, clean {:?} (Mbit/s)",
                verdicts.join("; "),
                mbit(clean1, |x| x.vox),
                mbit(lossy, |x| x.vox),
                mbit(clean2, |x| x.vox)
            ));
            "BELOW".to_owned()
        };
        note(
            report,
            format!(
                "{name}: clean bar {:.1} Mbit/s ({:.0}% of raw {:.1}), lossy bar {:.1} Mbit/s; \
             per-second clean {:?}, lossy {:?}, clean {:?} — {verdict}; {}",
                bar / 1e6,
                MIN_RATIO * 100.0,
                raw_rate / 1e6,
                lossy_bar / 1e6,
                mbit(clean1, |x| x.vox),
                mbit(lossy, |x| x.vox),
                mbit(clean2, |x| x.vox),
                lateness(&all[s..])
            ),
        );
    }

    // The paused link: one tunnel on the 1%-loss link that stops sending for longer than the
    // controller's idle restart (vox-core's `IDLE_RESTART`, 1 s), then resumes. Whatever the
    // controller keeps or forgets across that restart, a person's next transfer must find the
    // lossy link's speed again.
    'paused: {
        if !wanted(PAUSED_NAME) {
            break 'paused;
        }
        let Some(lossy_bar) = lossy_bars
            .iter()
            .find(|(n, _)| *n == WIFI.name)
            .map(|&(_, b)| b)
        else {
            cant(cannot, format!(
                "CANNOT MEASURE {PAUSED_NAME} (APPARATUS): the 1% lossy arm it is judged against did \
                 not measure (precondition unmet)"
            ));
            break 'paused;
        };
        *link.lock().unwrap() = Some(WIFI);
        let stop = Arc::new(AtomicBool::new(false));
        let pump = stream_to(tunnel, Arc::clone(&stop));
        let before = windows(SETTLE + MEASURE, |_| {});
        stop.store(true, Relaxed);
        let _ = pump.join();
        std::thread::sleep(PAUSE);
        let stop = Arc::new(AtomicBool::new(false));
        let pump = stream_to(tunnel, Arc::clone(&stop));
        let after = windows(CLIMB_WITHIN + MEASURE, |_| {});
        stop.store(true, Relaxed);
        let _ = pump.join();
        let judged_after = &after[CLIMB_WITHIN.as_secs() as usize..];
        if let Some(e) = late_fault(PAUSED_NAME, judged_after)
            .or_else(|| crossed_fault(PAUSED_NAME, judged_after))
        {
            cant(cannot, e);
            break 'paused;
        }
        let m = mean_of(judged_after, |x| x.vox);
        let verdict = if m >= lossy_bar {
            "ok".to_owned()
        } else {
            failed.push(format!(
                "{PAUSED_NAME}: the emulator was on time; after a {} s pause, past the first {} s, \
                 vox carried {:.1} Mbit/s, under the lossy bar of {:.1} Mbit/s ({LOSSY_WIN:.1}x the \
                 Cubic flow on the same loss): vox loses its lossy-link speed across a pause",
                PAUSE.as_secs(),
                CLIMB_WITHIN.as_secs(),
                m / 1e6,
                lossy_bar / 1e6
            ));
            "BELOW".to_owned()
        };
        note(report, format!(
            "{PAUSED_NAME}: lossy bar {:.1} Mbit/s; before the pause vox {:.1} Mbit/s, after it {:.1} \
             Mbit/s — {verdict}; {}; per-second after {:?}",
            lossy_bar / 1e6,
            mean_of(&before[before.len() - MEASURE.as_secs() as usize..], |x| x.vox) / 1e6,
            m / 1e6,
            lateness(judged_after),
            mbit(&after, |x| x.vox)
        ));
    }
    // The joined link: the Cubic flow alone (its solo rate), then vox alone long enough to climb,
    // then the Cubic flow joins vox.
    'joined: {
        if !wanted(JOINED.name) {
            break 'joined;
        }
        *link.lock().unwrap() = Some(JOINED);
        let stop_c = Arc::new(AtomicBool::new(false));
        competitor_sender(&rt, competitor, Arc::clone(&stop_c));
        let alone = windows(SETTLE + SHARED_MEASURE, |_| {});
        let alone = alone[SETTLE.as_secs() as usize..].to_vec();
        stop_c.store(true, Relaxed);
        std::thread::sleep(Duration::from_secs(2));
        let stop_v = Arc::new(AtomicBool::new(false));
        let pump = stream_to(tunnel, Arc::clone(&stop_v));
        let vox_alone = windows(JOINED_ALONE, |_| {});
        let stop_c = Arc::new(AtomicBool::new(false));
        competitor_sender(&rt, competitor, Arc::clone(&stop_c));
        let both = windows(SETTLE + SHARED_MEASURE, |_| {});
        let both = both[SETTLE.as_secs() as usize..].to_vec();
        let stats = comparison_stats();
        stop_c.store(true, Relaxed);
        stop_v.store(true, Relaxed);
        let _ = pump.join();
        std::thread::sleep(Duration::from_secs(1));
        if let Some(e) = late_fault(JOINED.name, &alone)
            .or_else(|| late_fault(JOINED.name, &both))
            .or_else(|| crossed_fault(JOINED.name, &both))
            .or_else(|| competed_fault(JOINED.name, &alone))
        {
            cant(cannot, e);
            break 'joined;
        }
        let (solo, kept, vm) = (
            mean_of(&alone, |x| x.other),
            mean_of(&both, |x| x.other),
            mean_of(&both, |x| x.vox),
        );
        let share = kept / solo;
        let verdict = if vm < solo * SHARED_VOX_FLOOR {
            failed.push(format!(
                "{}: the emulator was on time; beside the Cubic flow vox carried {:.1} Mbit/s, under \
                 {:.0}% of that flow's solo {:.1}: the tunnel stalls when a flow joins it",
                JOINED.name,
                vm / 1e6,
                SHARED_VOX_FLOOR * 100.0,
                solo / 1e6
            ));
            "BELOW (vox stalled)".to_owned()
        } else if share >= SHARED_KEEP {
            format!("ok (kept >= {:.0}%)", SHARED_KEEP * 100.0)
        } else {
            failed.push(format!(
                "{}: the emulator was on time; the Cubic flow carried {:.1} Mbit/s alone and {:.1} \
                 after joining vox, {:.1}% of its solo rate, under {:.0}%; vox carried {:.1}: vox \
                 pushes a joining flow below its own rate",
                JOINED.name,
                solo / 1e6,
                kept / 1e6,
                share * 100.0,
                SHARED_KEEP * 100.0,
                vm / 1e6
            ));
            format!("BELOW {:.0}%", SHARED_KEEP * 100.0)
        };
        note(
            report,
            format!(
            "{}: the Cubic flow alone {:.1} Mbit/s; vox alone before it joined {:.1}; after it \
             joined, the Cubic flow {:.1} ({:.1}%) and vox {:.1} — {verdict}; {stats}; alone: {}; \
             both: {}; per-second vox alone {:?}, Cubic joined {:?}, vox joined {:?}",
            JOINED.name,
            solo / 1e6,
            mean_of(&vox_alone[vox_alone.len() / 3..], |x| x.vox) / 1e6,
            kept / 1e6,
            share * 100.0,
            vm / 1e6,
            lateness(&alone),
            lateness(&both),
            mbit(&vox_alone, |x| x.vox),
            mbit(&both, |x| x.other),
            mbit(&both, |x| x.vox)
        ),
        );
    }

    // The lossy shared links: the Cubic flow alone, then with Vox, on the same link.
    for shared in LOSSY_SHARED {
        if !wanted(shared.name) {
            continue;
        }
        *link.lock().unwrap() = Some(shared);
        let stop = Arc::new(AtomicBool::new(false));
        competitor_sender(&rt, competitor, Arc::clone(&stop));
        let alone = windows(SETTLE + SHARED_MEASURE, |_| {});
        let alone = alone[SETTLE.as_secs() as usize..].to_vec();
        let pump = stream_to(tunnel, Arc::clone(&stop));
        let both = windows(SETTLE + SHARED_MEASURE, |_| {});
        let both = both[SETTLE.as_secs() as usize..].to_vec();
        let stats = comparison_stats();
        stop.store(true, Relaxed);
        let _ = pump.join();
        std::thread::sleep(Duration::from_secs(1));
        if let Some(e) = late_fault(shared.name, &alone)
            .or_else(|| late_fault(shared.name, &both))
            .or_else(|| crossed_fault(shared.name, &both))
            .or_else(|| competed_fault(shared.name, &alone))
        {
            cant(cannot, e);
            continue;
        }
        let (solo, kept, vm) = (
            mean_of(&alone, |x| x.other),
            mean_of(&both, |x| x.other),
            mean_of(&both, |x| x.vox),
        );
        let share = kept / solo;
        // A tunnel that carries nothing beside the flow makes the share say nothing about fairness;
        // a person sees a stalled tunnel.
        let verdict = if vm < solo * SHARED_VOX_FLOOR {
            failed.push(format!(
                "{}: the emulator was on time; beside the Cubic flow vox carried {:.1} Mbit/s, under \
                 {:.0}% of that flow's solo {:.1}: the tunnel stalls on a lossy shared link",
                shared.name,
                vm / 1e6,
                SHARED_VOX_FLOOR * 100.0,
                solo / 1e6
            ));
            "BELOW (vox stalled)".to_owned()
        } else if share >= SHARED_KEEP {
            format!("ok (kept >= {:.0}%)", SHARED_KEEP * 100.0)
        } else {
            failed.push(format!(
                "{}: the emulator was on time; the Cubic flow carried {:.1} Mbit/s alone and {:.1} with \
                 vox beside it, {:.1}% of its solo rate, under {:.0}%; vox carried {:.1}: vox pushes a \
                 competing flow below its own rate on a lossy shared link",
                shared.name,
                solo / 1e6,
                kept / 1e6,
                share * 100.0,
                SHARED_KEEP * 100.0,
                vm / 1e6
            ));
            format!("BELOW {:.0}%", SHARED_KEEP * 100.0)
        };
        note(report, format!(
            "{}: the Cubic flow alone {:.1} Mbit/s, beside vox {:.1} ({:.1}%), vox {:.1} — {verdict}; \
             {}; alone: {}; both: {}; per-second Cubic alone {:?}, Cubic beside vox {:?}, vox {:?}",
            shared.name,
            solo / 1e6,
            kept / 1e6,
            share * 100.0,
            vm / 1e6,
            stats,
            lateness(&alone),
            lateness(&both),
            mbit(&alone, |x| x.other),
            mbit(&both, |x| x.other),
            mbit(&both, |x| x.vox)
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
        let stats = comparison_stats();
        stop.store(true, Relaxed);
        let _ = pump.join();
        std::thread::sleep(Duration::from_secs(1));
        if let Some(e) = late_fault(congested.name, &w)
            .or_else(|| crossed_fault(congested.name, &w))
            .or_else(|| competed_fault(congested.name, &w))
        {
            cant(cannot, e);
            continue;
        }
        let (vm, cm) = (mean_of(&w, |x| x.vox), mean_of(&w, |x| x.other));
        let ratio = vm / cm;
        let verdict = if ratio < FAIR_LOW {
            failed.push(format!(
                "{}: the emulator was on time; vox carried {:.1} Mbit/s against the Cubic flow's \
                 {:.1}, {ratio:.3}x, under {FAIR_LOW:.1}x: vox gives way on a shared link",
                congested.name,
                vm / 1e6,
                cm / 1e6
            ));
            format!("BELOW {FAIR_LOW:.1}x")
        } else if ratio > FAIR_HIGH {
            failed.push(format!(
                "{}: the emulator was on time; vox carried {:.1} Mbit/s against the Cubic flow's \
                 {:.1}, {ratio:.3}x, over {FAIR_HIGH:.1}x: vox takes more than its share",
                congested.name,
                vm / 1e6,
                cm / 1e6
            ));
            format!("ABOVE {FAIR_HIGH:.1}x")
        } else {
            format!("fair ({FAIR_LOW:.1}x-{FAIR_HIGH:.1}x)")
        };
        // DIAGNOSTIC, not a verdict: the 2 s windows furthest from fair, where a failed tier-3 trial
        // would show. ADR-024 makes no claim about any window shorter than the whole run.
        let pairs: Vec<f64> = w
            .windows(2)
            .map(|p| (p[0].vox + p[1].vox) / (p[0].other + p[1].other).max(1.0))
            .collect();
        shown(&format!(
            "R41 DIAGNOSTIC (not a verdict) {}: 2 s windows from {:.2}x to {:.2}x",
            congested.name,
            pairs.iter().copied().fold(f64::INFINITY, f64::min),
            pairs.iter().copied().fold(0.0, f64::max)
        ));
        note(
            report,
            format!(
                "{}: vox {:.1} Mbit/s, Cubic {:.1} Mbit/s, {ratio:.3}x over {} s — {verdict}; {}; {}; \
             per-second vox {:?}, Cubic {:?}",
                congested.name,
                vm / 1e6,
                cm / 1e6,
                CONGESTED_MEASURE.as_secs(),
                stats,
                lateness(&w),
                mbit(&w, |x| x.vox),
                mbit(&w, |x| x.other)
            ),
        );
    }

    drop(rt);
}
