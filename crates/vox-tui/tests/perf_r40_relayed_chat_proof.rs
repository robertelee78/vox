//! PRD-001 **R40, forced-relay path, on the shipped binary** (V29-07, #42) — a chat message
//! between two online nodes whose only path is a relay circuit is delivered, and within R40's
//! **1 s**.
//!
//! Until now the relayed half of R40 was proved only on the NAT simulator
//! (`vox-core/tests/perf_r40_relayed_chat_gate.rs`), because nothing in the binary forces a relay.
//! `support/relay.rs` forces one with the product's own `--listen`: a real `vox node` anchor on
//! `[::]`, alice's `vox daemon` on `127.0.0.1`, bob's on `[::1]`. Neither daemon can send a
//! datagram to the other, so the anchor's circuit is the only path.
//!
//! **Relayed is asserted, before and after the samples**, from the anchor's own count of circuits
//! carried, so a direct path cannot pass this silently. **The control** runs the same room, verbs
//! and samples with both daemons on `127.0.0.1`, and asserts the anchor carries nothing — which is
//! what shows the split, and nothing else, is what makes the first arm relayed.
//!
//! [`SAMPLES`] times: alice runs `vox room post`, and the clock stops when the text is readable on
//! bob's node over bob's own control socket, polled every [`POLL`]. Printed as min / median / p95
//! / max for end to end (post launched) and network (post returned); the target is asserted on
//! every end-to-end sample.
//!
//! ## Mutation knobs (test-side only)
//!
//! - `VOX_PERF_THRESHOLD_MS` replaces the target, so a bar below the measured minimum must turn
//!   this red;
//! - `VOX_PERF_INJECT_MS` sleeps inside the timed window before the post.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use relay::{Anchor, Split};
use vox_core::node::ipc::{Frame, IpcClient, Request};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
/// PRD-001 R40: "must arrive in under 1 s".
const TARGET: Duration = Duration::from_millis(1000);
const SAMPLES: usize = 25;
const POLL: Duration = Duration::from_millis(5);

fn env_ms(name: &str) -> Option<Duration> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
}

fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(text.as_bytes()).expect("write");
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn until(dir: &std::path::Path, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (_, out, err) = vox(dir, args, None);
        if ok(&out) {
            return out;
        }
        last = format!("stdout={out:?} stderr={err:?}");
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}; last saw {last}");
}

/// A daemon, killed by its own PID however the test ends, stderr drained.
struct Daemon(Child, Arc<Mutex<String>>);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn daemon(dir: &std::path::Path, listen: &str, anchor: &str) -> Daemon {
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", listen, "--anchor", anchor])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn a daemon");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(format!("{IDPASS}\n").as_bytes()).unwrap();
    drop(pipe);
    let said = Arc::new(Mutex::new(String::new()));
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
        let sink = Arc::clone(&said);
        let mut stream = stream;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink
                        .lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }
    let d = Daemon(child, said);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !d.1.lock().unwrap().contains("control socket") {
        assert!(
            Instant::now() < deadline,
            "a daemon never served its socket:\n{}",
            d.1.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

/// min / median / p95 / max, nearest-rank.
fn stats(label: &str, samples: &[Duration]) -> (Duration, Duration, Duration, Duration) {
    let mut s = samples.to_vec();
    s.sort();
    let at = |q: f64| s[((q * s.len() as f64).ceil() as usize).clamp(1, s.len()) - 1];
    let out = (s[0], at(0.5), at(0.95), s[s.len() - 1]);
    eprintln!(
        "{label}: n={} min={:?} median={:?} p95={:?} max={:?}",
        s.len(),
        out.0,
        out.1,
        out.2,
        out.3
    );
    out
}

fn uptime() -> String {
    Command::new("uptime")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// Two daemons in one room, trusting each other, split by `split`; `SAMPLES` posts from alice timed
/// to readable on bob. The anchor's circuit count is checked before and after by `check`.
fn run(split: Split, check: fn(&mut Anchor, &str)) -> (Vec<Duration>, Vec<Duration>) {
    let inject = env_ms("VOX_PERF_INJECT_MS").unwrap_or_default();
    eprintln!("uptime at start: {}", uptime());
    let tmp = tempfile::tempdir().unwrap();
    let alice_dir = tmp.path().join("alice");
    let bob_dir = tmp.path().join("bob");
    for d in [&alice_dir, &bob_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let mut anchor = Anchor::start(&tmp.path().join("anchor"));
    let mut fps = Vec::new();
    for dir in [&alice_dir, &bob_dir] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    let alice = daemon(&alice_dir, "127.0.0.1:0", &anchor.v4_spec);
    let bob_spec = split.guest_spec(&anchor).to_owned();
    let bob = daemon(&bob_dir, split.guest_listen(), &bob_spec);

    let (ok, _, err) = vox(
        &alice_dir,
        &["room", "create", "--name", "chat"],
        Some("room passphrase\n"),
    );
    assert!(ok, "room create: {err}");
    let listed = until(&alice_dir, "the room", &["room", "list"], |o| {
        o.contains("chat")
    });
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("a room id in `room list`")
        .to_owned();
    let (ok, link, err) = vox(&alice_dir, &["room", "invite", &room], None);
    assert!(ok, "invite: {err}");
    let (ok, _, err) = vox(
        &bob_dir,
        &["room", "join", link.trim(), "--name", "chat"],
        Some("room passphrase\n"),
    );
    assert!(
        ok,
        "CANNOT MEASURE ({split:?}): bob could not join — {err}\nalice:\n{}\nbob:\n{}",
        alice.1.lock().unwrap(),
        bob.1.lock().unwrap()
    );
    for (dir, fp, name) in [(&alice_dir, &fps[1], "bob"), (&bob_dir, &fps[0], "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "trust add {name}: {err}");
    }
    let (ok, _, err) = vox(&alice_dir, &["room", "post", &room, "warm-up"], None);
    assert!(ok, "warm-up post: {err}");
    until(
        &bob_dir,
        "the warm-up to cross",
        &["room", "read", &room],
        |o| o.contains("warm-up"),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let bob_paths = vox_core::node::paths::Paths::resolve(
        "default",
        Some(&bob_dir),
        Some(&bob_dir.join("cfg")),
    )
    .unwrap();
    let mut reader = rt
        .block_on(IpcClient::open(&bob_paths.socket_file()))
        .expect("attach to bob's node");
    let channel_id = match rt.block_on(reader.rooms()) {
        Ok(Frame::Rooms { rooms }) => rooms
            .iter()
            .map(|(id, _, _)| *id)
            .find(|id| vox_core::node::link::b32_encode(id).starts_with(&room))
            .expect("the room on bob's node"),
        other => panic!("rooms: {other:?}"),
    };
    let readable = |reader: &mut IpcClient, text: &str| -> bool {
        match rt.block_on(reader.request(&Request::Read {
            channel_id,
            since: None,
            limit: 0,
        })) {
            Ok(Frame::Rows { rows }) => rows.iter().any(|r| r.text == text),
            _ => false,
        }
    };

    check(&mut anchor, "before the samples");
    let mut end_to_end = Vec::new();
    let mut network = Vec::new();
    for i in 0..SAMPLES {
        let text = format!("r40 {split:?} sample {i:02}");
        let t0 = Instant::now();
        std::thread::sleep(inject);
        let (ok, _, err) = vox(&alice_dir, &["room", "post", &room, &text], None);
        let posted = Instant::now();
        assert!(ok, "post {i}: {err}");
        let deadline = t0 + Duration::from_secs(60);
        while !readable(&mut reader, &text) {
            assert!(
                Instant::now() < deadline,
                "sample {i} never arrived on bob's node within 60 s\nbob:\n{}",
                bob.1.lock().unwrap()
            );
            std::thread::sleep(POLL);
        }
        let seen = Instant::now();
        end_to_end.push(seen - t0);
        network.push(seen - posted);
    }
    check(&mut anchor, "after the samples");
    eprintln!("uptime at end: {}", uptime());
    drop((alice, bob));
    (end_to_end, network)
}

#[test]
#[ignore = "an anchor, two real daemons and production Argon2id; run in release"]
fn r40_a_message_between_two_online_nodes_arrives_in_under_a_second_relayed() {
    watchdog::arm();
    let target = env_ms("VOX_PERF_THRESHOLD_MS").unwrap_or(TARGET);
    let (end_to_end, network) = run(Split::Families, |a, when| a.assert_relayed(when));
    stats("R40 relayed, network (post returned -> readable)", &network);
    let (_, _, _, max) = stats(
        "R40 relayed, end to end (post launched -> readable)",
        &end_to_end,
    );
    let over = end_to_end.iter().filter(|d| **d >= target).count();
    assert!(
        max < target,
        "R40 (relayed): {over} of {SAMPLES} messages took {target:?} or longer end to end; the \
         slowest took {max:?}"
    );
}

/// **The control**: the same room and samples with both daemons on `127.0.0.1`. The anchor must
/// carry no circuit, before or after — the split is what makes the other arm relayed.
#[test]
#[ignore = "an anchor, two real daemons and production Argon2id; run in release"]
fn r40_control_without_the_split_the_same_pair_is_direct() {
    watchdog::arm();
    let (end_to_end, network) = run(Split::None, |a, when| a.assert_direct(when));
    stats("R40 control (direct), network", &network);
    stats("R40 control (direct), end to end", &end_to_end);
}
