//! PRD-001 **R41** — a tunnel on a direct path runs **near line rate**: within about
//! 10–20% of raw.
//!
//! Driven entirely through the shipped binary, the way a person sets a tunnel up:
//!
//! 1. `vox node` — an anchor, so the host's address can be handed out at all;
//! 2. `vox serve <port>` — the host, offering a **sink**: a TCP server in this test that
//!    counts bytes and stamps the moment the last one lands;
//! 3. `vox connect <address>` — the guest joins; the host has trusted it beforehand;
//! 4. `vox forward <room> <host> <port>` — the guest's local port into the tunnel.
//!
//! Then [`BYTES`] are pushed through the forward to the sink, and the **same** bytes are
//! pushed from the same client straight to the same sink over plain loopback TCP. Each is
//! run [`ROUNDS`] times, interleaved so load on the box lands on both; throughput is bytes
//! over the time from the client's connect to the sink's last byte, and the gate compares
//! medians. The ratio must be at least [`MIN_RATIO`] — "within 20%" of raw.
//!
//! **What "raw" is here.** Loopback TCP is the fastest link this box has, so this is the
//! strictest possible reading of R41: it charges the overlay for everything it adds —
//! QUIC, encryption, the userspace hops through two nodes — against a kernel memcpy. On a
//! real network link the raw figure is far lower and the ratio correspondingly kinder.
//!
//! **Direct, asserted.** The anchor reports every change in how many circuits it carries.
//! A first connection may begin as a circuit and move to a direct path moments later, so
//! the timed rounds start only once the anchor reports carrying none, and the gate fails
//! if it reports carrying one at any point after that.
//!
//! Mutation knobs (test-side only): `VOX_PERF_MIN_RATIO` replaces the target ratio;
//! `VOX_PERF_INJECT_MS` sleeps that long inside every overlay transfer's timed window.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// At least 200 MB per transfer, per the task that set this gate.
const BYTES: u64 = 256 * 1024 * 1024;
const ROUNDS: usize = 3;
/// "Within 20%" of raw.
const MIN_RATIO: f64 = 0.80;
const CHUNK: usize = 256 * 1024;

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
    fn spawn(name: &'static str, dir: &std::path::Path, args: &[&str]) -> Self {
        let mut child = Command::new(VOX)
            .args(args)
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
    let out = Command::new(VOX)
        .args(args)
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

/// A sink: counts each connection's bytes and reports the instant the `BYTES`th arrives.
fn sink() -> (u16, mpsc::Receiver<Instant>) {
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
                while got < BYTES {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got += n as u64,
                    }
                }
                let _ = tx.send(Instant::now());
            });
        }
    });
    (port, rx)
}

/// Push `BYTES` to `to` and return the throughput in bytes per second, clocked from the
/// connect to the sink's last byte.
fn transfer(to: SocketAddr, done: &mpsc::Receiver<Instant>, inject: Duration) -> f64 {
    let chunk = vec![0x5au8; CHUNK];
    let t0 = Instant::now();
    std::thread::sleep(inject);
    let mut s = TcpStream::connect(to).expect("connect for the transfer");
    let mut sent = 0u64;
    while sent < BYTES {
        let n = usize::try_from((BYTES - sent).min(CHUNK as u64)).unwrap();
        s.write_all(&chunk[..n]).expect("write the transfer");
        sent += n as u64;
    }
    let end = done
        .recv_timeout(Duration::from_secs(300))
        .expect("the sink never received every byte");
    let secs = end.duration_since(t0).as_secs_f64();
    drop(s);
    BYTES as f64 / secs
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

#[test]
#[ignore = "three real vox processes, production Argon2id and 1.5 GB of traffic; CI runs it in release"]
fn r41_a_direct_tunnel_runs_within_twenty_percent_of_raw() {
    watchdog::arm();
    let min_ratio = std::env::var("VOX_PERF_MIN_RATIO")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MIN_RATIO);
    let inject = std::env::var("VOX_PERF_INJECT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or_default();
    eprintln!("uptime at start: {}", uptime());

    let tmp = tempfile::tempdir().unwrap();
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (port, done) = sink();

    let anchor = Proc::spawn("anchor", &anchor_dir, &["node", "--listen", "127.0.0.1:0"]);
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
            "127.0.0.1:0",
        ],
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

    let (ok, out, err) = vox_once(
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
    );
    let line = forward.expect_line("the forward's bound address", |l| {
        l.starts_with("vox: ") && l.contains(" → ")
    });
    let bound: SocketAddr = line
        .split_whitespace()
        .nth(1)
        .expect("an address")
        .parse()
        .expect("a socket address");
    let raw: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // One warm transfer each, untimed, so neither side pays a first-use cost in the figures.
    let _ = transfer(bound, &done, Duration::ZERO);
    let _ = transfer(raw, &done, Duration::ZERO);

    // A first connection may start as a circuit through the anchor and move to a direct
    // path moments later (the R42 gate measures that). What is measured here must be the
    // direct path, so wait until the anchor says it carries nothing, and then hold it to
    // that for every timed transfer.
    let carried = |l: &str| l.contains("circuit(s) carried") && !l.contains(" 0 circuit(s)");
    let circuit_lines = |a: &Proc| -> Vec<String> {
        a.said()
            .into_iter()
            .filter(|l| l.contains("circuit(s) carried"))
            .collect()
    };
    let settle = Instant::now();
    while circuit_lines(&anchor).last().is_some_and(|l| carried(l))
        && settle.elapsed() < Duration::from_secs(120)
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    // Measured either way, so a run that never reached a direct path still reports what
    // the relayed tunnel did; it fails below on the path, not silently.
    let direct_at_start = !circuit_lines(&anchor).last().is_some_and(|l| carried(l));
    let before = circuit_lines(&anchor).len();
    eprintln!(
        "anchor before the timed rounds: {:?} (settled after {:?})",
        circuit_lines(&anchor).last(),
        settle.elapsed()
    );

    let mut overlay = Vec::new();
    let mut loopback = Vec::new();
    for round in 0..ROUNDS {
        let o = transfer(bound, &done, inject);
        let l = transfer(raw, &done, Duration::ZERO);
        eprintln!(
            "round {round}: overlay {:.1} MB/s, loopback {:.1} MB/s ({})",
            o / 1e6,
            l / 1e6,
            uptime()
        );
        overlay.push(o);
        loopback.push(l);
    }
    let circuits: Vec<String> = circuit_lines(&anchor)
        .into_iter()
        .skip(before)
        .filter(|l| carried(l))
        .collect();
    let (o, l) = (median(overlay), median(loopback));
    assert!(
        direct_at_start && circuits.is_empty(),
        "CANNOT MEASURE a direct path: the anchor was still carrying a circuit {} 120 s after \
         the forward came up{}. The relayed tunnel ran at {:.1} MB/s against {:.1} MB/s raw.",
        if direct_at_start {
            "later, during the timed rounds,"
        } else {
            ""
        },
        if circuits.is_empty() {
            String::new()
        } else {
            format!(" ({circuits:?})")
        },
        o / 1e6,
        l / 1e6
    );
    let ratio = o / l;
    eprintln!(
        "R41: {} MiB per transfer, median overlay {:.1} MB/s, median loopback {:.1} MB/s, \
         ratio {ratio:.3} (target >= {min_ratio})",
        BYTES / (1024 * 1024),
        o / 1e6,
        l / 1e6
    );
    eprintln!("uptime at end: {}", uptime());
    assert!(
        ratio >= min_ratio,
        "R41: a direct tunnel ran at {:.1} MB/s against {:.1} MB/s raw — {:.1}% of raw, where \
         the target is at least {:.0}%",
        o / 1e6,
        l / 1e6,
        ratio * 100.0,
        min_ratio * 100.0
    );
    drop(forward);
    drop(host);
    drop(anchor);
}
