//! PRD-001 **R41** — a tunnel must not "nuke" the link it runs over.
//!
//! **What R41 means, in the decider's words (2026-09-25):** *"let's not be overly pedantic…
//! figure out what the maximum throughput is for a network connection and ensure that our
//! overlay system doesn't completely nuke that. We want vox to be as fast and efficient as
//! possible."* So the comparison is against a **real link**, not against loopback, which is a
//! kernel memcpy no network carries: raw TCP and a Vox tunnel are pushed over **the same
//! emulated path**, one after the other, and Vox must deliver at least [`MIN_RATIO`] of what
//! raw TCP gets at 1 Gbit/s. The other link classes are measured and reported.
//!
//! ## How the link is emulated — exactly
//! macOS **dummynet**, through `dnctl` and a `pf` anchor, on `lo0`, which needs root: the gate
//! runs `sudo -n` and says CANNOT MEASURE if that would prompt. Two pipes, one per direction,
//! each with the class's bandwidth, one-way delay, packet-loss rate and a 100-slot drop-tail
//! queue. The rules live in the sub-anchor `com.apple/vox-shaper` — which the stock
//! `/etc/pf.conf` already reaches through `dummynet-anchor "com.apple/*"` — so nothing in the
//! main ruleset changes, and they match **only two ports**: the Vox host's UDP port (every
//! packet between guest and host) and the raw sink's TCP port. The host's own hop to its
//! service, the anchor, and every other process on the machine are untouched. Everything is
//! removed when the test ends, however it ends.
//!
//! Both paths share the loopback MTU (16384), so both use large packets: raw TCP's MSS is
//! ~16 KB and Vox's path-MTU discovery climbs to its 8192 ceiling. On a real Ethernet link both
//! would be at ~1500. dummynet itself tops out at ~1.4 Gbit/s on this machine, so a
//! "10 Gbit/s" pipe measures dummynet, not the link, and that class is reported, not asserted.
//!
//! Driven through the shipped binary: `vox node`, `vox serve <port> --listen 127.0.0.1:<H>`,
//! `vox connect`, `vox forward`. Mutation knobs (test-side only): `VOX_PERF_MIN_RATIO`
//! replaces the target; `VOX_PERF_INJECT_MS` sleeps inside every overlay transfer's window.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const ROUNDS: usize = 3;
/// Vox must deliver at least this share of raw TCP's throughput on a 1 Gbit/s link.
const MIN_RATIO: f64 = 0.90;
const CHUNK: usize = 256 * 1024;

/// One emulated link: bandwidth, one-way delay each way, and packet loss per direction.
#[derive(Clone, Copy, Debug)]
struct Link {
    name: &'static str,
    mbit: u32,
    fwd_ms: u32,
    back_ms: u32,
    loss: f64,
    /// Whether the ratio is asserted (the 1 Gbit/s classes) or only reported.
    asserted: bool,
}

const LINKS: [Link; 4] = [
    Link {
        name: "1 Gbit/s, 1 ms RTT",
        mbit: 1000,
        fwd_ms: 1,
        back_ms: 0,
        loss: 0.0,
        asserted: true,
    },
    Link {
        name: "1 Gbit/s, 20 ms RTT",
        mbit: 1000,
        fwd_ms: 10,
        back_ms: 10,
        loss: 0.0,
        asserted: true,
    },
    Link {
        name: "Wi-Fi-like: 300 Mbit/s, 5 ms RTT, 0.1% loss",
        mbit: 300,
        fwd_ms: 3,
        back_ms: 2,
        loss: 0.001,
        asserted: false,
    },
    Link {
        name: "10 Gbit/s, 1 ms RTT (dummynet-limited)",
        mbit: 10_000,
        fwd_ms: 1,
        back_ms: 0,
        loss: 0.0,
        asserted: false,
    },
];

const PIPE_FWD: u32 = 4711;
const PIPE_BACK: u32 = 4712;
const ANCHOR: &str = "com.apple/vox-shaper";

fn sudo(args: &[&str], stdin: Option<&str>) -> bool {
    let mut child = Command::new("sudo")
        .arg("-n")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run sudo");
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(text.as_bytes());
    }
    child.wait().is_ok_and(|s| s.success())
}

/// The shaping for one link, on `ports`. Removed on drop.
struct Shaped;

impl Shaped {
    fn on(link: Link, ports: &[u16]) -> Self {
        for (pipe, ms) in [(PIPE_FWD, link.fwd_ms), (PIPE_BACK, link.back_ms)] {
            let (pipe, bw, ms, plr) = (
                pipe.to_string(),
                format!("{}Mbit/s", link.mbit),
                ms.to_string(),
                link.loss.to_string(),
            );
            assert!(
                sudo(
                    &[
                        "dnctl", "pipe", &pipe, "config", "bw", &bw, "delay", &ms, "plr", &plr,
                        "queue", "100"
                    ],
                    None
                ),
                "dnctl pipe config failed"
            );
        }
        let mut rules = String::new();
        for p in ports {
            rules += &format!(
                "dummynet out quick on lo0 proto {{tcp,udp}} from any to any port {p} pipe {PIPE_FWD}\n\
                 dummynet out quick on lo0 proto {{tcp,udp}} from any port {p} to any pipe {PIPE_BACK}\n"
            );
        }
        assert!(
            sudo(&["pfctl", "-a", ANCHOR, "-f", "-"], Some(&rules)),
            "loading the pf anchor failed"
        );
        Self
    }
}

impl Drop for Shaped {
    fn drop(&mut self) {
        let _ = sudo(&["pfctl", "-a", ANCHOR, "-F", "all"], None);
        let _ = sudo(&["dnctl", "pipe", "delete", &PIPE_FWD.to_string()], None);
        let _ = sudo(&["dnctl", "pipe", "delete", &PIPE_BACK.to_string()], None);
    }
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

/// A sink: reads each connection to its end and reports the instant the last byte landed.
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
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
                let _ = tx.send(Instant::now());
            });
        }
    });
    (port, rx)
}

/// Push `bytes` to `to`, and return the throughput in bits per second, clocked from the
/// connect to the sink's last byte.
fn transfer(to: SocketAddr, done: &mpsc::Receiver<Instant>, bytes: u64, inject: Duration) -> f64 {
    let chunk = vec![0x5au8; CHUNK];
    let t0 = Instant::now();
    std::thread::sleep(inject);
    let mut s = TcpStream::connect(to).expect("connect for the transfer");
    let mut sent = 0u64;
    while sent < bytes {
        let n = usize::try_from((bytes - sent).min(CHUNK as u64)).unwrap();
        s.write_all(&chunk[..n]).expect("write the transfer");
        sent += n as u64;
    }
    s.shutdown(std::net::Shutdown::Write).unwrap();
    let end = done
        .recv_timeout(Duration::from_secs(300))
        .expect("the sink never received every byte");
    bytes as f64 * 8.0 / end.duration_since(t0).as_secs_f64()
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
#[ignore = "real vox processes, production Argon2id, root for dummynet, and gigabytes of traffic; CI runs it in release"]
fn r41_a_tunnel_keeps_what_the_link_gives() {
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
    assert!(
        sudo(&["true"], None),
        "CANNOT MEASURE: emulating a link needs root for dummynet (`sudo -n` would prompt)"
    );
    eprintln!("uptime at start: {}", uptime());

    let tmp = tempfile::tempdir().unwrap();
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (service, service_done) = sink();
    let (raw_port, raw_done) = sink();
    let host_port = free_udp_port();

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
    let (service_s, listen) = (service.to_string(), format!("127.0.0.1:{host_port}"));
    let host = Proc::spawn(
        "host",
        &host_dir,
        &["serve", &service_s, "--anchor", &spec, "--listen", &listen],
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
            &service_s,
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
    let bound: SocketAddr = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    let raw: SocketAddr = format!("127.0.0.1:{raw_port}").parse().unwrap();
    // Unshaped warm-up, so the connection is up and direct before any link is emulated.
    let _ = transfer(bound, &service_done, 64 << 20, Duration::ZERO);

    let mut failures = Vec::new();
    for link in LINKS {
        // About two seconds of the link's capacity per transfer, at least 64 MiB.
        let bytes = (u64::from(link.mbit) * 1_000_000 / 8 * 2).max(64 << 20);
        let shaped = Shaped::on(link, &[host_port, raw_port]);
        let _ = transfer(bound, &service_done, bytes, Duration::ZERO);
        let (mut vox, mut tcp) = (Vec::new(), Vec::new());
        for _ in 0..ROUNDS {
            vox.push(transfer(bound, &service_done, bytes, inject));
            tcp.push(transfer(raw, &raw_done, bytes, Duration::ZERO));
        }
        drop(shaped);
        let (v, t) = (median(vox.clone()), median(tcp.clone()));
        let ratio = v / t;
        eprintln!(
            "R41 [{}]: vox {:?} Mbit/s, raw TCP {:?} Mbit/s — medians {:.0} / {:.0} Mbit/s \
             ({:.1} / {:.1} MB/s), ratio {ratio:.3}{}",
            link.name,
            vox.iter().map(|x| (x / 1e6).round()).collect::<Vec<_>>(),
            tcp.iter().map(|x| (x / 1e6).round()).collect::<Vec<_>>(),
            v / 1e6,
            t / 1e6,
            v / 8e6,
            t / 8e6,
            if link.asserted {
                format!(" (target >= {min_ratio})")
            } else {
                " (reported)".into()
            }
        );
        if link.asserted && ratio < min_ratio {
            failures.push(format!("{}: {ratio:.3}", link.name));
        }
    }
    // The measured path must have been direct: an anchor carrying a circuit means the Vox
    // numbers above were a relay's, not the link's.
    let carrying = anchor
        .said()
        .into_iter()
        .rfind(|l| l.contains("circuit(s) carried"));
    eprintln!(
        "anchor at the end: {carrying:?}; uptime at end: {}",
        uptime()
    );
    assert!(
        carrying
            .as_deref()
            .is_none_or(|l| l.contains(" 0 circuit(s)")),
        "CANNOT MEASURE a direct path: the anchor ended carrying a circuit ({carrying:?})"
    );
    assert!(
        failures.is_empty(),
        "R41: Vox kept less than {min_ratio} of raw TCP on {failures:?}"
    );
    drop(forward);
    drop(host);
    drop(anchor);
}
