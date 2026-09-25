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
//!    per stream), the same bars per direction.
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

/// How long each call lasts.
const CALL: Duration = Duration::from_secs(30);
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
}

/// The app's side of one call on one flow: send this arm's frames on schedule from
/// `start`, and record every frame that arrives, until the call is over.
///
/// A frame that arrives as stream bytes, not as a datagram, is recorded too:
/// `[u32 length ‖ frame]` records in the stream. The product never does that, but the
/// proof's mutation (a) makes the daemon carry datagrams on the reliable stream, and the
/// app must still be able to see what that did to the call.
async fn run_flow(flow: Flow, start: u64, pause: Option<(u64, u64)>) -> Value {
    let (mut rd, mut wr) = flow.stream.into_split();
    let arm = flow.arm;
    let end = start + u64::try_from((CALL + Duration::from_secs(3)).as_nanos()).unwrap();
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
    let frames = u32::try_from(CALL.as_nanos() / every.as_nanos()).unwrap();
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
                                let flow = Flow { peer: peer.clone(), arm, stream };
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
            .map(|f| tokio::spawn(run_flow(f, start, pause)))
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
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl App {
    fn spawn(
        m: &Member,
        room: &str,
        open: &[&Member],
        accepts: usize,
        pause: bool,
        tmp: &Path,
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
        self.wait_for("done", CALL + Duration::from_secs(60));
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
    // With a little room either side: the sender's clock and the switch's are one clock,
    // but not one thread.
    let black: Window = Some((
        BLACKOUT_AT - Duration::from_millis(20),
        BLACKOUT_AT + STALL + Duration::from_millis(50),
    ));
    let mut out = Vec::new();
    for from in members {
        for to in members {
            if from.fp == to.fp {
                continue;
            }
            for (arm, _) in ARMS {
                let pick = |who: &Member, peer: &Member| {
                    results[&who.name]
                        .iter()
                        .find(|v| v["peer"] == peer.fp.as_str() && v["arm"] == arm)
                        .cloned()
                        .unwrap_or_else(|| {
                            panic!("{} has no {arm} flow with {}", who.name, peer.name)
                        })
                };
                let (s, r) = (pick(from, to), pick(to, from));
                out.push(measure(
                    format!("{arm} {}->{}", from.name, to.name),
                    &s,
                    &r,
                    start,
                    if blacked == Some(from.name.as_str()) {
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

/// The bars every direction must meet.
/// How many frames a sender puts on a flow in the whole call: every scheduled one, less
/// those its pause skips. What the sender runs is this same schedule.
fn scheduled(arm: &str, paused: bool) -> usize {
    let every = if arm == "voice" {
        VOICE_EVERY
    } else {
        VIDEO_EVERY
    };
    let frames = u32::try_from(CALL.as_nanos() / every.as_nanos()).unwrap();
    (0..frames)
        .filter(|seq| !(paused && (PAUSE_AT..PAUSE_AT + STALL).contains(&(every * *seq))))
        .count()
}

fn bars(ds: &[Direction], p99_bar: f64, pauser: Option<&str>) {
    for d in ds {
        report(d);
    }
    for d in ds {
        // **The whole call was sent.** Loss is measured against what the sender put on the
        // flow, so a flow the daemon closed mid-call — the sender's writes failing from
        // then on — would read as a shorter call with no loss at all. It did: three mesh
        // directions stopped at about 16 s and passed every other bar.
        let (arm, from) = d.label.split_once(' ').unwrap();
        let from = from.split("->").next().unwrap();
        let want = scheduled(arm, pauser == Some(from));
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
fn call(
    members: &[&Member],
    room: &str,
    anchor_for: &dyn Fn(&Member) -> (String, &'static str),
    tmp: &Path,
    pauser: Option<&str>,
    blacked: Option<&str>,
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
    }
    // Each member opens to the members after it and accepts from those before it.
    let mut apps: Vec<App> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let pause = pauser == Some(m.name.as_str());
            App::spawn(m, room, &members[i + 1..], i, pause, tmp)
        })
        .collect();
    for a in &mut apps {
        match a.try_wait_for("ready", LINE_TIMEOUT + Duration::from_secs(60)) {
            Ok(l) => eprintln!("[{}] {l}", a.name),
            Err(e) => {
                // What the daemons said is the only account of why a call could not be
                // placed; a bare timeout is not a diagnosis.
                for d in &mut daemons {
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
    drop(daemons);
    directions(members, &results, start, blacked)
}

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
/// The relay leg's blackout switch and its forwarded-datagram count.
type Leg = (Arc<AtomicBool>, Arc<AtomicU64>);

fn two(path: PathKind) -> (World, Option<Leg>) {
    let knob: Arc<Mutex<Option<Leg>>> = Arc::new(Mutex::new(None));
    let k = Arc::clone(&knob);
    let leg: Option<Box<dyn Fn(SocketAddr) -> Option<SocketAddr>>> =
        if path == PathKind::Relayed {
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
    drop(w.host.take());
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
    bars(&ds, bar, Some("host"));
    pause_unfelt(&ds, "host", "guest->host", bar);
    if knob.is_some() {
        blackout_held_nothing(&ds, bar);
    }
}

/// R27: frames sent while the guest's leg was black are lost, not delivered late; frames
/// after it are on time; the other direction is untouched.
fn blackout_held_nothing(ds: &[Direction], bar: f64) {
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
        assert!(
            n_after > 0 && worst_after <= bar,
            "{arm}: after the blackout, worst {worst_after:.2} ms"
        );
        assert!(
            n_o > 0 && worst_o <= bar,
            "{arm} host->guest felt the blackout: worst {worst_o:.2} ms"
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
    drop(w.host.take());
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
    let ds = call(&all, &w.room, &anchor_for, w.tmp.path(), None, None, |_| {});
    eprintln!("[mesh] {} directions measured", ds.len());
    assert_eq!(
        ds.len(),
        4 * 3 * 2,
        "every member to every other, both streams"
    );
    bars(&ds, P99_DIRECT_MS, None);
}
