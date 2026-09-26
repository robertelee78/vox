//! PRD-001 R32 on R29/R30, ADR-022 — **the App API's datagram flows can carry a call.**
//!
//! Calls themselves are the decider's next project, a chat app. What Vox owes that app is
//! a datagram flow that behaves like the network a call expects: frames arrive, arrive
//! soon, and a late one is dropped instead of holding up the ones behind it (R27). This
//! proves it with the product exactly as the app will use it:
//!
//! - each member runs the shipped **`vox daemon`**;
//! - each "app" is a **separate process** (this test binary re-run in the `app_role`
//!   role) that speaks IPC protocol 6 to its own daemon's control socket — listen,
//!   accept, open with a datagram flow — the calls a chat app makes;
//! - the apps exchange synthetic media in both directions at once, every frame carrying
//!   its sequence number and the wall-clock time it was sent. Every process is on this
//!   machine, so one clock times both ends.
//!
//! The media:
//!
//! - **voice**: 160-byte frames every 20 ms, for 30 s;
//! - **video**, on a second flow at the same time: 1200-byte frames at 30 fps, with every
//!   30th frame a 24 000-byte **keyframe** — larger than any datagram, so it crosses only
//!   if R26 fragmentation works.
//!
//! Measured per direction and per stream: loss, one-way latency p50/p99/max, RFC 3550
//! interarrival jitter, reordered and duplicated frames, keyframes delivered.
//!
//! The bars, on loopback:
//!
//! - loss ≤ 1%;
//! - p99 one-way latency ≤ 20 ms direct and ≤ 40 ms relayed. Loopback adds nothing of
//!   its own, so this is the latency Vox adds;
//! - **no head-of-line stall**:
//!   - one sender pauses for 500 ms, and the other direction must be unaffected;
//!   - on the relayed path, the guest's leg to the anchor goes **black for 500 ms**. What
//!     it carried then must be lost, not delivered late. Nothing sent after it may wait
//!     behind it. The opposite direction must be unaffected. This is R27, and the sender
//!     pause cannot show it: a pause loses nothing a reliable stream would retransmit.
//!
//! The arms:
//!
//! 1. **direct**, two members;
//! 2. **relayed**: the host on IPv6 loopback only and the guest on IPv4 only, so only an
//!    anchor circuit joins them. The guest's leg runs through a proxy this test controls,
//!    which also counts what crossed, as evidence that the call went that way;
//! 3. **mesh**: four members, each calling the other three at once (twelve directions
//!    per stream), the same bars per direction. Every member opens its own flows to every
//!    other at the same moment, so each pair's daemons dial each other at once and the
//!    connection tie-break runs under live calls. The call lasts past the grace after which
//!    a displaced connection is closed unless something holds it (`RETIRE_GRACE_SECS` +
//!    15 s), and every direction must deliver its whole schedule.
//!
//! ## Why it is `#[ignore]`d
//! Production Argon2id per profile, a real proof of work per join, and the harness's
//! 35 s waits for D8 (see `support/world.rs`). CI runs it in release. The three arms take
//! turns (one lock): each measures timing, and running them side by side would measure
//! the other arms.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use vox_core::node::appipc::{self, read_splice, write_splice, SpliceFrame};
use vox_core::node::link::{b32_decode, b32_encode};
use vox_core::node::paths::Paths;
use world::{args, vox_once, PathKind, Setup, VoxProc, World, IDENTITY, LINE_TIMEOUT};

/// How long a pair's call lasts.
const CALL: Duration = Duration::from_secs(30);
/// How long the mesh's call lasts: past the grace after which a displaced connection is
/// closed unless something still holds it, so every call must survive that moment.
const MESH_CALL: Duration = Duration::from_secs(vox_core::node::net::RETIRE_GRACE_SECS + 15);

/// How the members of a call dial each other.
#[derive(Clone, Copy)]
enum Shape {
    Pairs,
    CrossingMesh,
}
const VOICE_BYTES: usize = 160;
const VOICE_EVERY: Duration = Duration::from_millis(20);
const VIDEO_BYTES: usize = 1200;
const VIDEO_EVERY: Duration = Duration::from_micros(33_333);
/// Larger than a datagram on any path here. Loopback's MTU is 16 KiB and QUIC discovers
/// it, so an 8000-byte keyframe crossed loopback whole and proved nothing about
/// fragmentation: mutation (b) stayed green with it.
const KEYFRAME_BYTES: usize = 24_000;
const KEYFRAME_EVERY: u32 = 30;
/// The injected stall: a sender pause, and on the relayed path a black leg.
const STALL: Duration = Duration::from_millis(500);
const PAUSE_AT: Duration = Duration::from_secs(10);
const BLACKOUT_AT: Duration = Duration::from_secs(20);
/// The part of the relayed call whose losses the blackout causes, left out of the loss bar
/// (its latency is not left out of anything). From just before the leg goes black — the
/// sender's clock and the switch's are one clock, but not one thread — to half a second
/// after it returns: QUIC backs its probe timer off while every probe is lost, so a sender
/// whose window filled learns the leg is back only at its next probe, measured up to 260 ms
/// after the leg returned, and the frames in between are dropped for age.
const BLACK_WINDOW: (Duration, Duration) = (
    Duration::from_millis(BLACKOUT_AT.as_millis() as u64 - 20),
    Duration::from_millis(BLACKOUT_AT.as_millis() as u64 + STALL.as_millis() as u64 + 500),
);

/// A frame this late is not a call frame any more: it was held, not carried.
const LATE: Duration = Duration::from_millis(150);

const MAX_LOSS: f64 = 0.01;
const P99_DIRECT_MS: f64 = 20.0;
const P99_RELAYED_MS: f64 = 40.0;

const ARMS: [(&str, &str); 2] = [
    ("voice", "calls-proof/voice/v1"),
    ("video", "calls-proof/video/v1"),
];

/// One arm at a time: each one measures timing.
static TURN: Mutex<()> = Mutex::new(());

fn now_ns() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap()
}

// =====================================================================================
// The app: one process per member, speaking IPC protocol 6 to its own daemon.
// =====================================================================================

/// What an app received on one flow: `(seq, sent_ns, received_ns, bytes)` per frame.
type Received = Vec<(u32, u64, u64, usize)>;

/// A frame: `seq u32 ‖ sent_ns u64 ‖ keyframe u8 ‖ padding`.
fn frame(seq: u32, key: bool, len: usize) -> Vec<u8> {
    let mut f = Vec::with_capacity(len);
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&now_ns().to_be_bytes());
    f.push(u8::from(key));
    f.resize(len, 0xa5);
    f
}

fn parse_frame(f: &[u8]) -> Option<(u32, u64)> {
    if f.len() < 13 {
        return None;
    }
    Some((
        u32::from_be_bytes(f[0..4].try_into().ok()?),
        u64::from_be_bytes(f[4..12].try_into().ok()?),
    ))
}

struct Flow {
    peer: String,
    arm: &'static str,
    stream: tokio::net::UnixStream,
    /// `both` for a pair's flows, which carry each direction; in the crossing mesh every
    /// member opens its own flow to every other, and sends only on those (`out`),
    /// receiving on the ones the others opened to it (`in`).
    dir: &'static str,
}

/// The app's side of one call on one flow: send this arm's frames on schedule from
/// `start`, and record every frame that arrives, until the call is over.
///
/// A frame that arrives as stream bytes, not as a datagram, is recorded too:
/// `[u32 length ‖ frame]` records in the stream. The product never does that, but the
/// proof's mutation (a) makes the daemon carry datagrams on the reliable stream, and the
/// app must still be able to see what that did to the call.
async fn run_flow(flow: Flow, start: u64, pause: Option<(u64, u64)>, call: Duration) -> Value {
    let (mut rd, mut wr) = flow.stream.into_split();
    let (arm, dir) = (flow.arm, flow.dir);
    let end = start + u64::try_from((call + Duration::from_secs(3)).as_nanos()).unwrap();
    let reader = tokio::spawn(async move {
        let mut got: Received = Vec::new();
        let mut spill: Vec<u8> = Vec::new();
        let record = |f: &[u8], got: &mut Received| {
            if let Some((seq, sent)) = parse_frame(f) {
                got.push((seq, sent, now_ns(), f.len()));
            }
        };
        loop {
            let left = end.saturating_sub(now_ns());
            if left == 0 {
                break;
            }
            match tokio::time::timeout(Duration::from_nanos(left), read_splice(&mut rd)).await {
                Ok(Ok(Some(SpliceFrame::Datagram(d)))) => record(&d, &mut got),
                Ok(Ok(Some(SpliceFrame::Data(d)))) => {
                    spill.extend_from_slice(&d);
                    while spill.len() >= 4 {
                        let n = u32::from_be_bytes(spill[..4].try_into().unwrap()) as usize;
                        if spill.len() < 4 + n {
                            break;
                        }
                        let f: Vec<u8> = spill.drain(..4 + n).skip(4).collect();
                        record(&f, &mut got);
                    }
                }
                Ok(Ok(Some(SpliceFrame::MaxAge(_)))) => {}
                // The peer finished, the daemon went, or the call is over.
                Ok(Ok(Some(SpliceFrame::Fin)) | Ok(None) | Err(_)) | Err(_) => break,
            }
        }
        got
    });
    let (every, bytes) = if arm == "voice" {
        (VOICE_EVERY, VOICE_BYTES)
    } else {
        (VIDEO_EVERY, VIDEO_BYTES)
    };
    let frames = if dir == "in" {
        0
    } else {
        u32::try_from(call.as_nanos() / every.as_nanos()).unwrap()
    };
    let mut sent = Vec::new();
    let mut keys = Vec::new();
    let t0 = tokio::time::Instant::now() + Duration::from_nanos(start.saturating_sub(now_ns()));
    for seq in 0..frames {
        let at = t0 + every * seq;
        tokio::time::sleep_until(at).await;
        let offset = u64::try_from((every * seq).as_nanos()).unwrap();
        if pause.is_some_and(|(from, to)| offset >= from && offset < to) {
            continue;
        }
        let key = arm == "video" && seq % KEYFRAME_EVERY == 0;
        let f = frame(seq, key, if key { KEYFRAME_BYTES } else { bytes });
        if write_splice(&mut wr, &SpliceFrame::Datagram(f))
            .await
            .is_err()
        {
            break;
        }
        sent.push(seq);
        if key {
            keys.push(seq);
        }
    }
    let got = reader.await.unwrap_or_default();
    json!({
        "peer": flow.peer,
        "arm": arm,
        "dir": dir,
        "sent": sent,
        "keyframes": keys,
        "got": got,
    })
}

/// The app process. Reads its orders from the environment, prints `ready` once every
/// flow is up, waits for `go <start_ns>` on stdin, runs the call, and writes what it saw
/// to `VOX_CALLS_OUT`.
#[test]
#[ignore = "the app process of calls_foundation_proof; run by it, not on its own"]
fn app_role() {
    let Ok(sock) = std::env::var("VOX_CALLS_SOCK") else {
        return;
    };
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let room = b32_decode(&env("VOX_CALLS_ROOM"), "room").unwrap();
    let open_to: Vec<String> = env("VOX_CALLS_OPEN")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let accepts: usize = env("VOX_CALLS_ACCEPT").parse().unwrap_or(0);
    // Leaked once for the process: every task logs under it.
    let call = Duration::from_secs(env("VOX_CALLS_SECS").parse().unwrap());
    let cross = env("VOX_CALLS_CROSS") == "1";
    let (out_dir, in_dir) = if cross {
        ("out", "in")
    } else {
        ("both", "both")
    };
    let me: &'static str = Box::leak(env("VOX_CALLS_NAME").into_boxed_str());
    let pause: Option<(u64, u64)> = env("VOX_CALLS_PAUSE_MS").parse::<u64>().ok().map(|ms| {
        let from = ms * 1_000_000;
        (from, from + u64::try_from(STALL.as_nanos()).unwrap())
    });
    let out = PathBuf::from(env("VOX_CALLS_OUT"));
    let sock = PathBuf::from(sock);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let mut flows = Vec::new();
        // Listen first, so a peer opening to us finds a listener.
        let mut listeners = Vec::new();
        for (arm, label) in ARMS {
            listeners.push((arm, appipc::listen(&sock, Some(room), label).await.unwrap()));
        }
        // One task per listener, each accepting the moment a stream is announced: a stream
        // nobody accepts within the node's accept deadline is refused, so an app that
        // waited on its voice listener while a video stream sat announced lost the video.
        //
        // And the listeners stay up until the call starts, keeping the **latest** stream
        // from each peer, as an app does. A caller may give up on an open the moment the
        // answer is late and place it again, and the stream this side accepted for the
        // first attempt is then dead; counting it as the call would lose the call.
        type Accepted = std::sync::Arc<tokio::sync::Mutex<HashMap<(String, &'static str), Flow>>>;
        let accepted: Accepted = Default::default();
        let arrived = std::sync::Arc::new(tokio::sync::Notify::new());
        let listening: Vec<_> = listeners
            .into_iter()
            .map(|(arm, mut l)| {
                let (sock, accepted, arrived) =
                    (sock.clone(), accepted.clone(), arrived.clone());
                tokio::spawn(async move {
                    while let Ok(Some(inc)) = l.next().await {
                        let peer = b32_encode(&inc.peer);
                        match appipc::accept(&sock, inc.id).await {
                            Ok((stream, info)) => {
                                assert!(info.datagrams, "an accepted flow without datagrams");
                                eprintln!("[app {me}] accepted {arm} from {peer}");
                                let flow = Flow {
                                    peer: peer.clone(),
                                    arm,
                                    stream,
                                    dir: in_dir,
                                };
                                if accepted.lock().await.insert((peer.clone(), arm), flow).is_some() {
                                    eprintln!("[app {me}] {arm} from {peer} again: the newer one is the call");
                                }
                                arrived.notify_one();
                            }
                            Err(e) => eprintln!("[app {me}] accept {arm} from {peer}: {e}"),
                        }
                    }
                })
            })
            .collect();
        eprintln!(
            "[app {me}] listening; opening to {} peer(s), accepting {accepts} per stream",
            open_to.len()
        );
        for peer in &open_to {
            let peer_id = b32_decode(peer, "peer").unwrap();
            for (arm, label) in ARMS {
                // The peer's daemon may still be coming up, or its listener: retry, as an
                // app placing a call would, for a bounded time.
                let deadline = Instant::now() + Duration::from_secs(180);
                let mut tries = 0u32;
                let stream = loop {
                    match appipc::open(&sock, room, peer_id, vec![label.to_owned()], true).await {
                        Ok((s, info)) => {
                            eprintln!("[app {me}] opened {arm} to {peer} after {tries} failed tries");
                            assert!(info.datagrams);
                            break s;
                        }
                        Err(e) => {
                            tries += 1;
                            if tries == 1 || tries.is_multiple_of(20) {
                                eprintln!("[app {me}] open {arm} to {peer}, try {tries}: {e}");
                            }
                            assert!(Instant::now() < deadline, "open to {peer}: {e}");
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    }
                };
                flows.push(Flow {
                    peer: peer.clone(),
                    arm,
                    stream,
                    dir: out_dir,
                });
            }
        }
        while accepted.lock().await.len() < accepts * ARMS.len() {
            arrived.notified().await;
        }
        for l in listening {
            l.abort();
        }
        flows.extend(std::mem::take(&mut *accepted.lock().await).into_values());
        println!("\nVOXCALLS ready {}", flows.len());
        std::io::stdout().flush().unwrap();
        let start: u64 = tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            line.trim().strip_prefix("go ").unwrap().parse().unwrap()
        })
        .await
        .unwrap();
        let runs: Vec<_> = flows
            .into_iter()
            .map(|f| tokio::spawn(run_flow(f, start, pause, call)))
            .collect();
        let mut results = Vec::new();
        for r in runs {
            results.push(r.await.unwrap());
        }
        std::fs::write(&out, serde_json::to_vec(&results).unwrap()).unwrap();
        println!("\nVOXCALLS done");
    });
}

// =====================================================================================
// The orchestrator.
// =====================================================================================

struct Member {
    name: String,
    dir: PathBuf,
    fp: String,
}

impl Member {
    fn socket(&self) -> PathBuf {
        Paths::resolve("default", Some(&self.dir), Some(&self.dir.join("cfg")))
            .unwrap()
            .socket_file()
    }
}

/// An app process, killed by PID however the test ends.
struct App {
    name: String,
    child: Child,
    lines: std::sync::mpsc::Receiver<String>,
    out: PathBuf,
    call: Duration,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl App {
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        m: &Member,
        room: &str,
        open: &[&Member],
        accepts: usize,
        pause: bool,
        tmp: &Path,
        call: Duration,
        cross: bool,
    ) -> App {
        let out = tmp.join(format!("{}-calls.json", m.name));
        let open: Vec<&str> = open.iter().map(|p| p.fp.as_str()).collect();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "app_role",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("VOX_CALLS_SOCK", m.socket())
            .env("VOX_CALLS_ROOM", room)
            .env("VOX_CALLS_OPEN", open.join(","))
            .env("VOX_CALLS_ACCEPT", accepts.to_string())
            .env("VOX_CALLS_NAME", &m.name)
            .env("VOX_CALLS_SECS", call.as_secs().to_string())
            .env("VOX_CALLS_CROSS", if cross { "1" } else { "0" })
            .env("VOX_CALLS_OUT", &out)
            .env(
                "VOX_CALLS_PAUSE_MS",
                if pause {
                    PAUSE_AT.as_millis().to_string()
                } else {
                    String::new()
                },
            )
            // The app never runs `vox`, but nothing it inherits may point one at a real
            // profile either.
            .env("VOX_DATA_DIR", &m.dir)
            .env("VOX_CONFIG_DIR", m.dir.join("cfg"))
            .env("VOX_TEST_WATCHDOG_SECS", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        App {
            name: m.name.clone(),
            child,
            lines,
            out,
            call,
        }
    }

    fn wait_for(&mut self, prefix: &str, within: Duration) -> String {
        self.try_wait_for(prefix, within)
            .unwrap_or_else(|e| panic!("{}: no `{prefix}` within {within:?}: {e}", self.name))
    }

    fn try_wait_for(&mut self, prefix: &str, within: Duration) -> Result<String, String> {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                // libtest prints `test app_role ... ` ahead of the role's first line, so the
                // marker is looked for anywhere in a line.
                Ok(l) if l.contains(&format!("VOXCALLS {prefix}")) => return Ok(l),
                Ok(_) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    fn go(&mut self, start: u64) {
        writeln!(self.child.stdin.as_mut().unwrap(), "go {start}").unwrap();
    }

    fn results(&mut self) -> Vec<Value> {
        self.wait_for("done", self.call + Duration::from_secs(60));
        serde_json::from_slice(&std::fs::read(&self.out).unwrap()).unwrap()
    }
}

/// A UDP proxy on IPv4 loopback in front of `upstream` that, while `black` is set, drops
/// everything its client sends. Counts what it forwarded from the client.
fn blackout_proxy(upstream: SocketAddr) -> (SocketAddr, Arc<AtomicBool>, Arc<AtomicU64>) {
    let front = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = front.local_addr().unwrap();
    let black = Arc::new(AtomicBool::new(false));
    let forwarded = Arc::new(AtomicU64::new(0));
    let (b, f) = (Arc::clone(&black), Arc::clone(&forwarded));
    let back = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    back.connect(upstream).unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let (front2, back2, client2) = (
        front.try_clone().unwrap(),
        back.try_clone().unwrap(),
        Arc::clone(&client),
    );
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, from)) = front.recv_from(&mut buf) {
            *client.lock().unwrap() = Some(from);
            if b.load(Ordering::SeqCst) {
                continue;
            }
            f.fetch_add(1, Ordering::Relaxed);
            let _ = back.send(&buf[..n]);
        }
    });
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65_535];
        while let Ok(n) = back2.recv(&mut buf) {
            if let Some(c) = *client2.lock().unwrap() {
                let _ = front2.send_to(&buf[..n], c);
            }
        }
    });
    (addr, black, forwarded)
}

/// One direction of one stream, measured.
#[derive(Debug)]
struct Direction {
    label: String,
    sent: usize,
    delivered: usize,
    loss: f64,
    p50_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    jitter_ms: f64,
    reordered: usize,
    duplicated: usize,
    keyframes: (usize, usize),
    /// Frames sent into an injected blackout, left out of `sent`, `loss` and `keyframes`:
    /// losing them is what the blackout is for.
    excluded: usize,
    /// `(sent_ns - start_ns, latency_ms)` per delivered frame, for the stall windows.
    timeline: Vec<(u64, f64)>,
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i]
}

/// A window of the call, as offsets from its start.
type Window = Option<(Duration, Duration)>;

fn measure(
    label: String,
    sender: &Value,
    receiver: &Value,
    start: u64,
    exclude: Window,
) -> Direction {
    let every = if label.starts_with("voice") {
        VOICE_EVERY
    } else {
        VIDEO_EVERY
    };
    let outside = |seq: &u32| exclude.is_none_or(|(a, b)| !(a..b).contains(&(every * *seq)));
    let all: Vec<u32> = serde_json::from_value(sender["sent"].clone()).unwrap();
    let sent: Vec<u32> = all.iter().copied().filter(outside).collect();
    let excluded = all.len() - sent.len();
    let keys: Vec<u32> = serde_json::from_value::<Vec<u32>>(sender["keyframes"].clone())
        .unwrap()
        .into_iter()
        .filter(outside)
        .collect();
    let got: Received = serde_json::from_value(receiver["got"].clone()).unwrap();
    let mut seen: HashMap<u32, usize> = HashMap::new();
    let (mut reordered, mut duplicated, mut highest) = (0usize, 0usize, None::<u32>);
    let (mut jitter, mut prev) = (0f64, None::<(u64, u64)>);
    let mut lat = Vec::new();
    let mut timeline = Vec::new();
    for &(seq, s, r, _) in &got {
        let n = seen.entry(seq).or_insert(0);
        *n += 1;
        if *n > 1 {
            duplicated += 1;
            continue;
        }
        if highest.is_some_and(|h| seq < h) {
            reordered += 1;
        }
        highest = Some(highest.map_or(seq, |h| h.max(seq)));
        let ms = (r.saturating_sub(s)) as f64 / 1e6;
        lat.push(ms);
        timeline.push((s.saturating_sub(start), ms));
        if let Some((ps, pr)) = prev {
            let d = (r as f64 - pr as f64) - (s as f64 - ps as f64);
            jitter += (d.abs() / 1e6 - jitter) / 16.0;
        }
        prev = Some((s, r));
    }
    let delivered = sent.iter().filter(|s| seen.contains_key(s)).count();
    let mut sorted = lat.clone();
    sorted.sort_by(f64::total_cmp);
    Direction {
        label,
        sent: sent.len(),
        delivered,
        loss: 1.0 - delivered as f64 / sent.len().max(1) as f64,
        p50_ms: pct(&sorted, 0.50),
        p99_ms: pct(&sorted, 0.99),
        max_ms: sorted.last().copied().unwrap_or(f64::NAN),
        jitter_ms: jitter,
        reordered,
        duplicated,
        keyframes: (
            keys.iter().filter(|k| seen.contains_key(k)).count(),
            keys.len(),
        ),
        excluded,
        timeline,
    }
}

/// Every direction of every stream among `results` (member name → its app's output).
fn directions(
    members: &[&Member],
    results: &BTreeMap<String, Vec<Value>>,
    start: u64,
    blacked: Option<&str>,
) -> Vec<Direction> {
    let black: Window = Some(BLACK_WINDOW);
    let mut out = Vec::new();
    for from in members {
        for to in members {
            if from.fp == to.fp {
                continue;
            }
            for (arm, _) in ARMS {
                // The sender's record of the flow it sent on, and the receiver's of the flow
                // it received on: one flow for a pair, two for a crossing mesh pair.
                let pick = |who: &Member, peer: &Member, dirs: [&str; 2]| {
                    results[&who.name]
                        .iter()
                        .find(|v| {
                            v["peer"] == peer.fp.as_str()
                                && v["arm"] == arm
                                && dirs.iter().any(|d| v["dir"] == *d)
                        })
                        .cloned()
                        .unwrap_or_else(|| {
                            panic!("{} has no {arm} flow with {}", who.name, peer.name)
                        })
                };
                let (s, r) = (
                    pick(from, to, ["out", "both"]),
                    pick(to, from, ["in", "both"]),
                );
                out.push(measure(
                    format!("{arm} {}->{}", from.name, to.name),
                    &s,
                    &r,
                    start,
                    // Both directions of the blacked member's calls: what the blackout did to
                    // them is measured on its own (`blackout_held_nothing`), and the bars
                    // measure the call around it.
                    if blacked == Some(from.name.as_str()) || blacked == Some(to.name.as_str()) {
                        black
                    } else {
                        None
                    },
                ));
            }
        }
    }
    out
}

fn report(d: &Direction) {
    eprintln!(
        "[{}] sent {} delivered {} loss {:.2}% | one-way p50 {:.2} ms p99 {:.2} ms max {:.2} ms | \
         jitter {:.2} ms | reordered {} duplicated {} | keyframes {}/{} | {} sent into the blackout, not counted",
        d.label,
        d.sent,
        d.delivered,
        d.loss * 100.0,
        d.p50_ms,
        d.p99_ms,
        d.max_ms,
        d.jitter_ms,
        d.reordered,
        d.duplicated,
        d.keyframes.0,
        d.keyframes.1,
        d.excluded
    );
}

/// When the slow frames were sent, as seconds into the call: to tell a stall that hit
/// every direction at once (one process held up) from one a direction had alone.
fn spikes(d: &Direction) {
    let slow: Vec<String> = d
        .timeline
        .iter()
        .filter(|(_, ms)| *ms > 10.0)
        .map(|(t, ms)| format!("{:.2}s:{ms:.0}ms", *t as f64 / 1e9))
        .collect();
    if !slow.is_empty() {
        eprintln!(
            "[spikes] {} over 10 ms: {} — {}",
            d.label,
            slow.len(),
            slow.join(" ")
        );
    }
}

/// The bars every direction must meet.
/// How many frames a sender puts on a flow in the whole call: every scheduled one, less
/// those its pause skips. What the sender runs is this same schedule.
fn scheduled(arm: &str, paused: bool, call: Duration) -> usize {
    let every = if arm == "voice" {
        VOICE_EVERY
    } else {
        VIDEO_EVERY
    };
    let frames = u32::try_from(call.as_nanos() / every.as_nanos()).unwrap();
    (0..frames)
        .filter(|seq| !(paused && (PAUSE_AT..PAUSE_AT + STALL).contains(&(every * *seq))))
        .count()
}

fn bars(ds: &[Direction], p99_bar: f64, pauser: Option<&str>, call: Duration) {
    for d in ds {
        report(d);
    }
    for d in ds {
        spikes(d);
    }
    for d in ds {
        // **The whole call was sent.** Loss is measured against what the sender put on the
        // flow, so a flow the daemon closed mid-call — the sender's writes failing from
        // then on — would read as a shorter call with no loss at all. It did: three mesh
        // directions stopped at about 16 s and passed every other bar.
        let (arm, from) = d.label.split_once(' ').unwrap();
        let from = from.split("->").next().unwrap();
        let want = scheduled(arm, pauser == Some(from), call);
        assert_eq!(
            d.sent + d.excluded,
            want,
            "{}: the sender put {} frames on the flow of {want} scheduled: the flow closed mid-call",
            d.label,
            d.sent + d.excluded
        );
        assert!(
            d.loss <= MAX_LOSS,
            "{}: loss {:.2}% over {}%",
            d.label,
            d.loss * 100.0,
            MAX_LOSS * 100.0
        );
        assert!(
            d.p99_ms <= p99_bar,
            "{}: p99 {:.2} ms over {p99_bar} ms",
            d.label,
            d.p99_ms
        );
        assert_eq!(
            d.keyframes.0, d.keyframes.1,
            "{}: {} of {} keyframes (each larger than a datagram) arrived",
            d.label, d.keyframes.0, d.keyframes.1
        );
    }
}

/// While `window` (offsets from the start) was on, what did `d` do? The worst latency of
/// frames sent in it, and how many.
fn window(d: &Direction, from: Duration, to: Duration) -> (usize, f64) {
    let (a, b) = (from.as_nanos() as u64, to.as_nanos() as u64);
    let hits: Vec<f64> = d
        .timeline
        .iter()
        .filter(|(t, _)| *t >= a && *t < b)
        .map(|(_, ms)| *ms)
        .collect();
    (hits.len(), hits.iter().copied().fold(0.0, f64::max))
}

/// The other direction must not notice the sender pause.
fn pause_unfelt(ds: &[Direction], paused: &str, other: &str, p99_bar: f64) {
    for arm in ["voice", "video"] {
        let label = format!("{arm} {other}");
        let d = ds.iter().find(|d| d.label == label).unwrap();
        let (n, worst) = window(d, PAUSE_AT, PAUSE_AT + STALL + Duration::from_secs(1));
        eprintln!("[pause] {paused} paused 500 ms; {label} during it and 1 s after: {n} frames, worst {worst:.2} ms");
        assert!(n > 0, "{label}: nothing sent while the other side paused");
        assert!(
            worst <= p99_bar,
            "{label}: {worst:.2} ms while the other side paused"
        );
    }
}

/// Start daemons for `members`, run the call among them, and return every direction.
#[allow(clippy::too_many_arguments)]
fn call(
    members: &[&Member],
    room: &str,
    anchor_for: &dyn Fn(&Member) -> (String, &'static str),
    tmp: &Path,
    pauser: Option<&str>,
    blacked: Option<&str>,
    shape: Shape,
    anchor: &mut VoxProc,
    during: impl FnOnce(u64),
) -> Vec<Direction> {
    let mut daemons: Vec<VoxProc> = Vec::new();
    for m in members {
        let pass = tmp.join(format!("{}-passphrases", m.name));
        // `<room> <passphrase>`: a generated passphrase may hold spaces, and a line is split
        // at its first one.
        std::fs::write(
            &pass,
            format!(
                "{IDENTITY}\n{room} {}\n",
                PASSPHRASE.lock().unwrap().clone()
            ),
        )
        .unwrap();
        let (anchor, listen) = anchor_for(m);
        let mut d = VoxProc::spawn(
            &format!("{}-daemon", m.name),
            &m.dir,
            &args(&[
                "daemon",
                "--passphrase-file",
                pass.to_str().unwrap(),
                "--anchor",
                &anchor,
                "--listen",
                listen,
            ]),
        );
        d.expect_line("the daemon to hold the room open", |l| {
            l.starts_with("vox daemon: holding room")
        });
        daemons.push(d);
        if daemons.len() == 1 {
            first_open_is_gated_not_refused(m, members[1], room);
        }
    }
    let mut apps: Vec<App> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let pause = pauser == Some(m.name.as_str());
            match shape {
                // Each member opens to the members after it and accepts from those before
                // it: one flow per pair, carrying both directions.
                Shape::Pairs => App::spawn(m, room, &members[i + 1..], i, pause, tmp, CALL, false),
                // Every member opens to every other at the same moment, so every pair's
                // daemons dial each other at once and the connection tie-break runs under
                // live calls; and the call outlasts the retire grace, so a call left on a
                // connection the tie-break retired has to survive that too.
                Shape::CrossingMesh => {
                    let others: Vec<&Member> =
                        members.iter().copied().filter(|o| o.fp != m.fp).collect();
                    App::spawn(m, room, &others, others.len(), pause, tmp, MESH_CALL, true)
                }
            }
        })
        .collect();
    for a in &mut apps {
        match a.try_wait_for("ready", LINE_TIMEOUT + Duration::from_secs(60)) {
            Ok(l) => eprintln!("[{}] {l}", a.name),
            Err(e) => {
                // What the daemons said is the only account of why a call could not be
                // placed; a bare timeout is not a diagnosis.
                for d in daemons.iter_mut().chain(std::iter::once(anchor)) {
                    let said = d.transcript();
                    eprintln!("---- {} said:\n{said}", d.name);
                }
                panic!("{}: its flows never came up: {e}", a.name);
            }
        }
    }
    let start = now_ns() + 2_000_000_000;
    for a in &mut apps {
        a.go(start);
    }
    during(start);
    let mut results = BTreeMap::new();
    for a in &mut apps {
        results.insert(a.name.clone(), a.results());
    }
    drop(apps);
    // What each daemon's router dropped for age, and how often it flushed a stalled path:
    // frames the call lost on purpose, counted where an app can read them (`vox status`).
    let mut drops = DROPS.lock().unwrap();
    drops.clear();
    for m in members {
        let (ok, out, err) = vox_once(&m.dir, &args(&["status", "--json"]));
        assert!(ok, "vox status ({}): {err}", m.name);
        let v: Value = serde_json::from_str(&out).unwrap();
        let d = &v["datagrams"];
        let (aged, flushes) = (
            d["aged_out"].as_u64().unwrap_or(0),
            d["late_dropped"].as_u64().unwrap_or(0),
        );
        eprintln!("[drops] {}: aged out {aged}, late on arrival {flushes}", m.name);
        drops.insert(m.name.clone(), (aged, flushes));
    }
    // The anchor has no status verb; it says its drops on change. Its relay legs stall like
    // anyone's when a member's acknowledgements stop.
    let said = anchor.transcript();
    let last = said
        .lines()
        .filter_map(|l| l.strip_prefix("vox node: datagrams dropped for age "))
        .next_back()
        .and_then(|rest| {
            let (aged, flushes) = rest.split_once(", late on arrival ")?;
            Some((aged.parse().ok()?, flushes.trim().parse().ok()?))
        })
        .unwrap_or((0, 0));
    eprintln!("[drops] anchor: aged out {}, late on arrival {}", last.0, last.1);
    drops.insert("anchor".into(), last);
    drop(drops);
    // Every warning a daemon printed during the call: a flow that dies is explained here
    // or nowhere.
    for d in &mut daemons {
        let said = d.transcript();
        for l in said.lines().filter(|l| l.starts_with("! ")) {
            eprintln!("[{}] {l}", d.name);
        }
    }
    if matches!(shape, Shape::CrossingMesh) {
        a_dead_peer_does_not_hold_up_a_live_one(members, &mut daemons, room);
    }
    drop(daemons);
    directions(members, &results, start, blacked)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

const PROBE_LABEL: &str = "calls-proof/probe/v1";

/// **The first daemon up, alone, is asked to call a member who is not up yet.** It must
/// try — and fail because that member cannot be reached — not refuse because it has not
/// yet computed who may be called.
///
/// A daemon computed its app gate only when trust or a room's authors changed, and a
/// room opening at startup changed neither. So an app on a daemon that had just started,
/// in a room with nothing new to sync, was told `this node does not hold that room` until
/// some sync applied an entry: minutes, measured, before a call could be placed. Alone,
/// with nobody to sync from, that is deterministic.
fn first_open_is_gated_not_refused(caller: &Member, callee: &Member, room: &str) {
    let room = b32_decode(room, "room").unwrap();
    let callee_id = b32_decode(&callee.fp, "peer").unwrap();
    let said = rt().block_on(async {
        match tokio::time::timeout(
            Duration::from_secs(60),
            appipc::open(
                &caller.socket(),
                room,
                callee_id,
                vec![PROBE_LABEL.into()],
                true,
            ),
        )
        .await
        {
            Ok(Ok(_)) => "opened".to_owned(),
            Ok(Err(e)) => e.to_string(),
            Err(_) => "no answer in 60 s".to_owned(),
        }
    });
    eprintln!(
        "[gate] {}'s daemon, alone, opening to {} (not up): {said}",
        caller.name, callee.name
    );
    assert!(
        !said.contains("does not hold that room"),
        "a freshly started daemon refused to place a call from a room it holds: {said}"
    );
}

/// **A call to a member who has gone must not hold up a call to one who is here.**
///
/// Reaching a peer runs the ADR-012 ladder, seconds per attempt for one that cannot be
/// reached. It ran on the node's actor, so while an app retried a member who had left,
/// the node answered nothing else — an app placing a call to a member who *was* there
/// waited behind it ("busy 10001ms — reaching a peer for an app stream"). One member
/// leaves (cleanly: its connections close), the first retries it, and the time to open a
/// call from the first to a member who is still here is measured.
fn a_dead_peer_does_not_hold_up_a_live_one(
    members: &[&Member],
    daemons: &mut [VoxProc],
    room: &str,
) {
    let (caller, live, gone) = (members[0], members[1], members[members.len() - 1]);
    let pid = daemons[daemons.len() - 1].child.id();
    let _ = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(20);
    while daemons[daemons.len() - 1]
        .child
        .try_wait()
        .ok()
        .flatten()
        .is_none()
    {
        assert!(
            Instant::now() < deadline,
            "{}'s daemon did not stop",
            gone.name
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let room = b32_decode(room, "room").unwrap();
    let (live_id, gone_id) = (
        b32_decode(&live.fp, "peer").unwrap(),
        b32_decode(&gone.fp, "peer").unwrap(),
    );
    let (sock, live_sock) = (caller.socket(), live.socket());
    let took = rt().block_on(async move {
        let mut listener = appipc::listen(&live_sock, Some(room), PROBE_LABEL)
            .await
            .unwrap();
        let accepting = tokio::spawn(async move {
            while let Ok(Some(inc)) = listener.next().await {
                let _ = appipc::accept(&live_sock, inc.id).await;
            }
        });
        let dead_sock = sock.clone();
        // Each attempt's start and, once it has one, its answer: the measurement below
        // counts only if an attempt at the gone member was in flight across it.
        type Attempts = Arc<Mutex<Vec<(Instant, Option<(Instant, String)>)>>>;
        let attempts: Attempts = Arc::default();
        let log = Arc::clone(&attempts);
        let retrying = tokio::spawn(async move {
            loop {
                let i = {
                    let mut l = log.lock().unwrap();
                    l.push((Instant::now(), None));
                    l.len() - 1
                };
                let r =
                    appipc::open(&dead_sock, room, gone_id, vec![PROBE_LABEL.into()], true).await;
                let said = r.map_or_else(|e| e.to_string(), |_| "opened".to_owned());
                log.lock().unwrap()[i].1 = Some((Instant::now(), said));
            }
        });
        // Wait until the retries are running the ladder: until one has come back
        // unreachable, which a connection that merely has not noticed its peer left does
        // not say. Then measure while the next one is in flight.
        let until = Instant::now() + Duration::from_secs(90);
        loop {
            let laddered = attempts.lock().unwrap().iter().any(|(_, e)| {
                e.as_ref()
                    .is_some_and(|(_, why)| why.contains("unreachable"))
            });
            if laddered {
                break;
            }
            assert!(
                Instant::now() < until,
                "the retries never reached the ladder"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let t0 = Instant::now();
        let opened = tokio::time::timeout(
            Duration::from_secs(60),
            appipc::open(&sock, room, live_id, vec![PROBE_LABEL.into()], true),
        )
        .await;
        let took = t0.elapsed();
        retrying.abort();
        accepting.abort();
        let log = attempts.lock().unwrap().clone();
        let across = log
            .iter()
            .filter(|(start, end)| *start <= t0 && end.as_ref().is_none_or(|(e, _)| *e > t0))
            .count();
        let answers: Vec<String> = log
            .iter()
            .filter_map(|(s, e)| {
                e.as_ref()
                    .map(|(e, why)| format!("{:.1}s: {why}", e.duration_since(*s).as_secs_f64()))
            })
            .collect();
        eprintln!(
            "[gate] {} attempts at the gone member; {across} in flight when it began; \
             answers: {answers:?}",
            log.len()
        );
        assert!(
            across >= 1,
            "no attempt at the gone member was in flight when the live call was placed"
        );
        assert!(
            matches!(opened, Ok(Ok(_))),
            "the call to the member still here did not open: {opened:?}"
        );
        took
    });
    eprintln!(
        "[gate] {} left; {} kept calling it; {} opened a call to {} in {took:?}",
        gone.name, caller.name, caller.name, live.name
    );
    assert!(
        took < Duration::from_secs(2),
        "a call to a member who is here waited {took:?} behind retries to one who left"
    );
}

/// Each member's `(aged_out, late_dropped)` after the last call.
static DROPS: Mutex<BTreeMap<String, (u64, u64)>> = Mutex::new(BTreeMap::new());

/// The room passphrase of the current world, for the daemons' passphrase files.
static PASSPHRASE: Mutex<String> = Mutex::new(String::new());

fn member(dir: &Path, name: &str) -> Member {
    let (ok, fp, err) = vox_once(dir, &args(&["id"]));
    assert!(ok, "vox id ({name}): {err}");
    Member {
        name: name.to_owned(),
        dir: dir.to_owned(),
        fp: fp.trim().to_owned(),
    }
}

fn trust_all(members: &[&Member]) {
    for a in members {
        for b in members {
            if a.fp != b.fp {
                let (ok, out, err) =
                    vox_once(&a.dir, &args(&["trust", "add", &b.fp, "--name", &b.name]));
                assert!(
                    ok || err.contains("already"),
                    "{} trust add {}: {out}{err}",
                    a.name,
                    b.name
                );
            }
        }
    }
}

/// Two members, on `path`: the host (who made the room) and the guest.
/// Stop the host's `vox serve` the way a person does — Ctrl-C, which it answers by
/// closing its connections — so its daemon can take over the profile.
///
/// **Not by SIGKILL**, which is what dropping the harness's process does. A killed node
/// never tells the anchor its connection is gone, the anchor keeps routing circuits for
/// that identity into the dead connection, and the daemon that replaces it cannot be
/// reached over the relay: both directions' circuits went quiet for the whole 180 s an
/// app retried, 2 relayed runs of 2 (full daemon and anchor logs kept). That is the
/// restart-liveness defect `prd1/restart-probe` owns (held connections that do not answer
/// a probe are closed), not the calls path, and this proof is to be run again with that
/// probe in once v0.3.0 carries it.
fn stop_serve(w: &mut World) {
    let Some(mut serve) = w.host.take() else {
        return;
    };
    let pid = serve.child.id();
    let _ = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = serve.child.try_wait() {
            eprintln!("[test] host `vox serve` pid {pid} stopped by SIGINT: {status}");
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Dropped: killed and reaped by PID.
    eprintln!("[test] host `vox serve` pid {pid} ignored SIGINT for 20 s; killing it");
    drop(serve);
}

/// The relay leg's blackout switch and its forwarded-datagram count.
type Leg = (Arc<AtomicBool>, Arc<AtomicU64>);

fn two(path: PathKind) -> (World, Option<Leg>) {
    let knob: Arc<Mutex<Option<Leg>>> = Arc::new(Mutex::new(None));
    let k = Arc::clone(&knob);
    let leg: Option<Box<dyn Fn(SocketAddr) -> Option<SocketAddr>>> = if path == PathKind::Relayed {
        Some(Box::new(move |anchor| {
            let (addr, black, fwd) = blackout_proxy(anchor);
            *k.lock().unwrap() = Some((black, fwd));
            Some(addr)
        }))
    } else {
        None
    };
    let w = World::build(&Setup {
        specs: vec!["9".into()],
        trusted: true,
        path,
        guest_leg: leg,
    });
    *PASSPHRASE.lock().unwrap() = w.passphrase.clone();
    let knob = knob.lock().unwrap().clone();
    (w, knob)
}

fn run_pair(path: PathKind) {
    let _turn = TURN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut w, knob) = two(path);
    // `vox serve` holds the host's profile; the call runs over daemons.
    stop_serve(&mut w);
    let host = Member {
        name: "host".into(),
        dir: w.host_dir.clone(),
        fp: w.host_fp.clone(),
    };
    let guest = Member {
        name: "guest".into(),
        dir: w.guest_dir.clone(),
        fp: w.guest_fp.clone(),
    };
    trust_all(&[&host, &guest]);
    let (host_anchor, guest_anchor) = (w.host_anchor.clone(), w.guest_anchor.clone());
    let anchor_for = move |m: &Member| {
        if m.name == "host" {
            (host_anchor.clone(), path.host_listen())
        } else {
            (guest_anchor.clone(), "127.0.0.1:0")
        }
    };
    let bar = if path == PathKind::Relayed {
        P99_RELAYED_MS
    } else {
        P99_DIRECT_MS
    };
    let black = knob.clone();
    let fwd_before = knob.as_ref().map(|(_, f)| f.load(Ordering::Relaxed));
    let ds = call(
        &[&host, &guest],
        &w.room,
        &anchor_for,
        w.tmp.path(),
        Some("host"),
        knob.as_ref().map(|_| "guest"),
        Shape::Pairs,
        &mut w.anchor,
        move |start| {
            if let Some((black, _)) = black {
                let until = |off: Duration| {
                    let at = start + off.as_nanos() as u64;
                    std::thread::sleep(Duration::from_nanos(at.saturating_sub(now_ns())));
                };
                until(BLACKOUT_AT);
                black.store(true, Ordering::SeqCst);
                until(BLACKOUT_AT + STALL);
                black.store(false, Ordering::SeqCst);
            }
        },
    );
    if let (Some((_, fwd)), Some(before)) = (&knob, fwd_before) {
        let crossed = fwd.load(Ordering::Relaxed) - before;
        eprintln!(
            "[relayed] the guest's leg to the anchor carried {crossed} datagrams during the call"
        );
        let guest_frames: usize = ds
            .iter()
            .filter(|d| d.label.contains("guest->"))
            .map(|d| d.sent)
            .sum();
        assert!(
            crossed as usize >= guest_frames,
            "the call did not cross the relay leg: {crossed} < {guest_frames}"
        );
    }
    if knob.is_some() {
        recovery(&ds);
    }
    bars(&ds, bar, Some("host"), CALL);
    pause_unfelt(&ds, "host", "guest->host", bar);
    if knob.is_some() {
        blackout_held_nothing(&ds);
    }
}

/// Every voice frame sent from just before the blackout to a second after it: how late it
/// arrived, or `-` for lost, one slot per 20 ms. To see recovery, not only its worst frame.
fn recovery(ds: &[Direction]) {
    for d in ds {
        if !d.label.starts_with("voice") {
            continue;
        }
        let got: HashMap<u64, f64> = d
            .timeline
            .iter()
            .map(|(t, ms)| (*t / 20_000_000, *ms))
            .collect();
        let from = (BLACKOUT_AT - Duration::from_millis(100)).as_millis() as u64 / 20;
        let to = (BLACKOUT_AT + STALL + Duration::from_millis(900)).as_millis() as u64 / 20;
        let row: Vec<String> = (from..to)
            .map(|slot| {
                got.get(&slot)
                    .map_or("-".to_owned(), |ms| format!("{ms:.0}"))
            })
            .collect();
        eprintln!(
            "[recovery] {} from {:.2}s, one per 20 ms: {}",
            d.label,
            from as f64 * 0.02,
            row.join(" ")
        );
    }
}

/// R27: frames sent while the guest's leg was black are lost, not delivered late; frames
/// after it are on time; the other direction is untouched.
fn blackout_held_nothing(ds: &[Direction]) {
    // The frames the opposite direction lost were dropped by the routers on purpose, and
    // counted where an app can read them.
    let (aged, flushes) = DROPS
        .lock()
        .unwrap()
        .values()
        .fold((0, 0), |(a, f), (x, y)| (a + x, f + y));
    eprintln!("[blackout] counted by the members' routers: {aged} aged out, {flushes} dropped late on arrival");
    for arm in ["voice", "video"] {
        let hit = ds
            .iter()
            .find(|d| d.label == format!("{arm} guest->host"))
            .unwrap();
        let late = hit
            .timeline
            .iter()
            .filter(|(_, ms)| *ms > LATE.as_secs_f64() * 1000.0)
            .count();
        let (n_in, worst_in) = window(hit, BLACKOUT_AT, BLACKOUT_AT + STALL);
        let (n_after, worst_after) = window(
            hit,
            BLACKOUT_AT + STALL + Duration::from_millis(100),
            BLACKOUT_AT + STALL + Duration::from_secs(2),
        );
        let other = ds
            .iter()
            .find(|d| d.label == format!("{arm} host->guest"))
            .unwrap();
        let (n_o, worst_o) = window(
            other,
            BLACKOUT_AT,
            BLACKOUT_AT + STALL + Duration::from_secs(1),
        );
        eprintln!(
            "[blackout] {arm} guest->host: {n_in} frames sent while black arrived (worst {worst_in:.2} ms), \
             {late} arrived later than {} ms in the whole call; after it {n_after} frames, worst {worst_after:.2} ms. \
             host->guest meanwhile: {n_o} frames, worst {worst_o:.2} ms",
            LATE.as_millis()
        );
        assert_eq!(
            late, 0,
            "{arm}: {late} frames were held and delivered late instead of dropped"
        );
        // After the leg returns, the first frames may have waited in the sender's queue for
        // QUIC to learn the leg is back: on time means within the max age, the same rule as
        // the other direction's.
        let after_bound =
            vox_core::transport::router::DEFAULT_MAX_AGE.as_secs_f64() * 1000.0 + hit.p50_ms;
        assert!(
            n_after > 0 && worst_after <= after_bound,
            "{arm}: after the blackout, worst {worst_after:.2} ms (bound {after_bound:.1} ms)"
        );
        // **The opposite direction is on time or dropped, never late.** With the black
        // leg's acknowledgements lost, QUIC's congestion window fills and datagrams cannot
        // go. They used to wait in quinn's queue and arrive together when the leg returned —
        // 20.14 s → 368 ms … 20.48 s → 27 ms in one run. The router now drops what waits
        // past its flow's max age, and flushes what quinn holds when it stalls
        // (`transport::router`). So no frame may arrive later than the max age plus this
        // direction's own one-way time, and the ones that did not are counted.
        let base = other.p50_ms;
        let bound = vox_core::transport::router::DEFAULT_MAX_AGE.as_secs_f64() * 1000.0 + base;
        let over: Vec<String> = other
            .timeline
            .iter()
            .filter(|(_, ms)| *ms > bound)
            .map(|(t, ms)| format!("{:.2}s:{ms:.0}ms", *t as f64 / 1e9))
            .collect();
        // The same window `directions` left out of the loss count.
        let (n_black, _) = window(other, BLACK_WINDOW.0, BLACK_WINDOW.1);
        eprintln!(
            "[blackout] {arm} host->guest: {n_o} frames in and 1 s after the blackout, \
             worst {worst_o:.2} ms; {} over the {bound:.1} ms bound in the whole call {over:?}; \
             of {} sent while the guest's leg was black, {n_black} arrived",
            over.len(),
            other.excluded
        );
        assert!(
            n_o > 0,
            "{arm} host->guest: nothing sent during the blackout"
        );
        // A frame the opposite direction did not deliver was dropped on purpose and counted:
        // aged out before quinn took it (the host's router, or the anchor's, whose leg to the
        // guest stalls too while the guest's acknowledgements are lost), or dropped as late on
        // arrival (the guest's router).
        assert!(
            other.excluded == n_black || aged + flushes > 0,
            "{arm} host->guest: {} of {} frames sent into the blackout never arrived, and no \
             router counted a drop",
            other.excluded - n_black,
            other.excluded
        );
        assert!(
            over.is_empty(),
            "{arm} host->guest: {} frames arrived later than max age + base ({bound:.1} ms): {over:?}",
            over.len()
        );
    }
}

#[test]
#[ignore = "real daemons, real app processes, production Argon2id; CI runs it in release"]
fn a_call_over_a_direct_path_meets_the_bars() {
    watchdog::arm();
    run_pair(PathKind::Direct);
}

#[test]
#[ignore = "real daemons, real app processes, production Argon2id; CI runs it in release"]
fn a_call_over_a_relay_meets_the_bars_and_a_black_leg_holds_nothing() {
    watchdog::arm();
    run_pair(PathKind::Relayed);
}

#[test]
#[ignore = "real daemons, real app processes, production Argon2id; CI runs it in release"]
fn a_four_member_mesh_call_meets_the_bars_on_every_direction() {
    watchdog::arm();
    let _turn = TURN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut w, _) = two(PathKind::Direct);
    let host = Member {
        name: "host".into(),
        dir: w.host_dir.clone(),
        fp: w.host_fp.clone(),
    };
    let guest = Member {
        name: "guest".into(),
        dir: w.guest_dir.clone(),
        fp: w.guest_fp.clone(),
    };
    let mut more = Vec::new();
    for name in ["m3", "m4"] {
        let dir = w.tmp.path().join(name);
        std::fs::create_dir_all(dir.join("cfg")).unwrap();
        let (ok, _, out, err) = w.join(&dir);
        assert!(ok, "{name} could not join: {out}{err}");
        more.push(member(&dir, name));
        // D8, as in `World::build`: the one-shot join leaves the host deaf for its
        // handshake bound. The host is not running now, but the anchor's view of the
        // joiner is; give the next join the same room the harness does.
        std::thread::sleep(world::ACCEPT_WINDOW);
    }
    stop_serve(&mut w);
    let all: Vec<&Member> = [&host, &guest].into_iter().chain(more.iter()).collect();
    trust_all(&all);
    let (host_anchor, guest_anchor) = (w.host_anchor.clone(), w.guest_anchor.clone());
    let anchor_for = move |m: &Member| {
        if m.name == "host" {
            (host_anchor.clone(), "127.0.0.1:0")
        } else {
            (guest_anchor.clone(), "127.0.0.1:0")
        }
    };
    let ds = call(
        &all,
        &w.room,
        &anchor_for,
        w.tmp.path(),
        None,
        None,
        Shape::CrossingMesh,
        &mut w.anchor,
        |_| {},
    );
    eprintln!("[mesh] {} directions measured", ds.len());
    assert_eq!(
        ds.len(),
        4 * 3 * 2,
        "every member to every other, both streams"
    );
    bars(&ds, P99_DIRECT_MS, None, MESH_CALL);
}
