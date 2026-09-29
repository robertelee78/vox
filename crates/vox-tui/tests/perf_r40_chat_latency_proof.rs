//! PRD-001 **R40, direct path** — a chat message between two online nodes arrives in
//! **under 1 s**, measured on the shipped binary.
//!
//! Two real `vox daemon`s with two identities, one room, both trusting each other — the
//! state two people are in once they are talking. Then, [`SAMPLES`] times: alice runs `vox
//! room post`, and the clock stops when the text is readable on **bob's** node, read over
//! bob's own control socket exactly as `vox room read` reads it, polled every
//! [`POLL`]. Nothing is in-process except that reader.
//!
//! Two figures per sample, both printed as min / median / p95 / max:
//!
//! - **end to end** — from the moment alice's `vox room post` is launched, which is what a
//!   person waits through, including the CLI starting and attaching;
//! - **network** — from the moment that command returns (the entry is appended on alice's
//!   node) to readable on bob's, which is the part the node owns.
//!
//! The PRD target is asserted on **every** end-to-end sample: "must arrive in under 1 s"
//! is a claim about each message, not an average.
//!
//! The forced-relay half of R40 cannot be driven from the binary — nothing in it forces a
//! relayed path — so it lives in `vox-core/tests/perf_r40_relayed_chat_gate.rs`, on the
//! NAT simulator, with real nodes behind symmetric NATs.
//!
//! ## Mutation knobs (test-side only; they never touch the product)
//!
//! - `VOX_PERF_THRESHOLD_MS` replaces the 250 ms bar, so setting it below the
//!   measured minimum must turn this red;
//! - `VOX_PERF_INJECT_MS` sleeps that long between starting the clock and launching the
//!   post, so a slower path must turn this red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vox_core::node::ipc::{Frame, IpcClient, Request};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
/// The bar this gate holds, which is **tighter than PRD-001 R40's 1 s on purpose.**
///
/// At 1 s the gate passed the defect it exists to catch. Pushes paced by the actor's 1 s tick
/// peaked at 992 ms over 25 samples, under the bar, so a tick-paced regression would have
/// stayed green. Measured by session `vox` on fix/push-on-append-v2: before, median 428–966 ms
/// and max 992 ms; after, median 27.5–30.8 ms and max 37.5 ms. 250 ms is far above the fixed
/// path and far below anything tick-paced, so it tells the two apart; R40's 1 s is still the
/// product promise.
const TARGET: Duration = Duration::from_millis(250);
/// At least 20, per the task that set these gates.
const SAMPLES: usize = 25;
/// How often bob's node is read. Well under the target, so resolution is not the story.
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

fn daemon(dir: &std::path::Path) -> Daemon {
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
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

#[test]
#[ignore = "two real daemons and production Argon2id; CI runs it in release"]
fn r40_a_message_between_two_online_nodes_arrives_in_under_a_second_direct() {
    watchdog::arm();
    let target = env_ms("VOX_PERF_THRESHOLD_MS").unwrap_or(TARGET);
    let inject = env_ms("VOX_PERF_INJECT_MS").unwrap_or_default();
    eprintln!("uptime at start: {}", uptime());

    let tmp = tempfile::tempdir().unwrap();
    let alice_dir = tmp.path().join("alice");
    let bob_dir = tmp.path().join("bob");
    for d in [&alice_dir, &bob_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let mut fps = Vec::new();
    for dir in [&alice_dir, &bob_dir] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    let alice = daemon(&alice_dir);
    let bob = daemon(&bob_dir);

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
        "CANNOT MEASURE: bob could not join — {err}\nalice:\n{}\nbob:\n{}",
        alice.1.lock().unwrap(),
        bob.1.lock().unwrap()
    );
    // Trust after the join: the order that delivers consent on this tree.
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

    let mut end_to_end = Vec::new();
    let mut network = Vec::new();
    for i in 0..SAMPLES {
        let text = format!("r40 direct sample {i:02}");
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
    eprintln!("uptime at end: {}", uptime());
    stats("R40 direct, network (post returned -> readable)", &network);
    let (_, _, _, max) = stats(
        "R40 direct, end to end (post launched -> readable)",
        &end_to_end,
    );
    let over = end_to_end.iter().filter(|d| **d >= target).count();
    assert!(
        max < target,
        "R40 (direct): {over} of {SAMPLES} messages took {target:?} or longer end to end; the \
         slowest took {max:?}"
    );

    drop(alice);
    drop(bob);
}
