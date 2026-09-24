//! MEASUREMENT (local experiment, not a gate): after alice has posted `N` messages, bob joins and
//! alice consents to him; does bob RENDER alice's next post? Driven through the shipped `vox`
//! binary. `N` comes from `BRACKET_N`.
//!
//! Signals, both read off the daemons' own control sockets (`IpcClient::connect`, the event
//! stream the TUI uses):
//! - alice's `Consented { target: bob }` — her node delivered the SKDM and appended the grant;
//! - bob's `SenderKeyReceived { peer: alice, backfilled }` — emitted only after bob's node
//!   opened the sealed SKDM (`open_skdm`) AND `accept_skdm` installed the receiver chain
//!   (actor.rs, `if let Some(n) = backfilled`). Both failures are silent returns, so absence of
//!   this event means one of them failed or the frame never arrived.
//! And the outcome: bob's `vox room read` output contains alice's post-consent marker.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vox_core::node::api::NodeEvent;
use vox_core::node::ipc::{Frame, IpcClient};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
const MARKER: &str = "marker-after-consent";

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn daemon(dir: &std::path::Path, tag: &str, stdin_lines: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn vox daemon");
    // Recorded so an aborted run can still be cleaned up by PID.
    if let Ok(f) = std::env::var("BRACKET_PIDFILE") {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(f)
            .unwrap();
        writeln!(f, "{}", child.id()).unwrap();
    }
    let mut pipe = child.stdin.take().unwrap();
    pipe.write_all(stdin_lines.as_bytes()).unwrap();
    drop(pipe);
    Daemon(child)
}

fn attached(dir: &std::path::Path, tag: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (ok, out, err) = vox(dir, &["room", "list"], None);
        if ok {
            return out;
        }
        last = err;
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("{tag}'s daemon never answered: {last}");
}

type Log = Arc<Mutex<Vec<(Duration, String)>>>;

/// Subscribe to a daemon's event stream on a background thread, logging every event that
/// bears on keys and consent with its time since `t0`.
fn watch(dir: &std::path::Path, t0: Instant) -> Log {
    let paths =
        vox_core::node::paths::Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
            .unwrap();
    let sock = paths.socket_file();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut c = IpcClient::connect(&sock).await.expect("subscribe");
            while let Ok(Some(frame)) = c.next().await {
                let line = match frame {
                    Frame::Event(NodeEvent::SenderKeyReceived { backfilled, .. }) => {
                        format!("SenderKeyReceived backfilled={backfilled}")
                    }
                    Frame::Event(NodeEvent::Consented { .. }) => "Consented".to_owned(),
                    Frame::Event(NodeEvent::PeerJoined { .. }) => "PeerJoined".to_owned(),
                    Frame::Event(NodeEvent::Joined { .. }) => "Joined".to_owned(),
                    Frame::Event(NodeEvent::Synced { rendered, .. }) => {
                        format!("Synced rendered={rendered}")
                    }
                    Frame::Lagged { missed } => format!("Lagged missed={missed}"),
                    _ => continue,
                };
                sink.lock().unwrap().push((t0.elapsed(), line));
            }
        });
    });
    log
}

fn has(log: &Log, what: &str) -> Option<Duration> {
    log.lock()
        .unwrap()
        .iter()
        .find(|(_, l)| l.starts_with(what))
        .map(|(t, _)| *t)
}

#[test]
#[ignore = "measurement: real vox daemons; BRACKET_N posts"]
fn bracket_newcomer_reads_next_post_after_n_prior() {
    watchdog::arm();
    let n: usize = std::env::var("BRACKET_N")
        .expect("BRACKET_N")
        .parse()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [(&alice, &fps[1], "bob"), (&bob, &fps[0], "alice")] {
        // BRACKET_NOTRUST=1: alice never trusts bob, so she never consents — the negative control.
        if name == "bob" && std::env::var("BRACKET_NOTRUST").as_deref() == Ok("1") {
            continue;
        }
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "vox trust add {name}: {err}");
    }

    let alice_d = daemon(&alice, "alice", &format!("{IDENTITY}\n"));
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap()
        .to_owned();
    let started = Instant::now();
    for i in 1..=n {
        let (ok, _, err) = vox(&alice, &["room", "post", &room, &format!("post {i}")], None);
        assert!(ok, "post {i}: {err}");
    }
    println!("BRACKET n={n} posted in {:?}", started.elapsed());
    // BRACKET_RESTART=1: stop alice's daemon by PID and start it again, as
    // a_long_room_reopens_proof does between the posts and bob's join.
    let alice_d = if std::env::var("BRACKET_RESTART").as_deref() == Ok("1") {
        drop(alice_d);
        let d = daemon(&alice, "alice2", &format!("{IDENTITY}\n{ROOMPASS}\n"));
        attached(&alice, "alice");
        println!("BRACKET alice restarted");
        d
    } else {
        alice_d
    };

    let t0 = Instant::now();
    let alice_log = watch(&alice, t0);
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "invite: {err}");
    let bob_d = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let bob_log = watch(&bob, t0);
    std::thread::sleep(Duration::from_millis(300));
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", link.trim(), "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "join: {err}");

    // Wait for alice's consent (her tick delivers it because she trusts bob).
    let deadline = Instant::now() + Duration::from_secs(120);
    while has(&alice_log, "Consented").is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    let consented = has(&alice_log, "Consented");
    // Give bob a moment to process the SKDM frame before the marker is authored.
    std::thread::sleep(Duration::from_secs(3));
    let (ok, _, err) = vox(&alice, &["room", "post", &room, MARKER], None);
    assert!(ok, "marker post: {err}");
    let posted = Instant::now();
    let mut rendered_at = None;
    let mut bob_rows = 0;
    while posted.elapsed() < Duration::from_secs(180) {
        let (ok, out, _) = vox(&bob, &["room", "read", &room], None);
        if ok {
            bob_rows = out.lines().filter(|l| l.contains(" post ")).count();
            if out.contains(MARKER) {
                rendered_at = Some(posted.elapsed());
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let skr = bob_log
        .lock()
        .unwrap()
        .iter()
        .find(|(_, l)| l.starts_with("SenderKeyReceived"))
        .cloned();
    println!(
        "BRACKET RESULT n={n} consented={consented:?} bob_sender_key_received={skr:?} \
         marker_rendered={rendered_at:?} bob_rendered_prior_rows={bob_rows}"
    );
    println!("BRACKET alice events: {:?}", alice_log.lock().unwrap());
    let bl = bob_log.lock().unwrap();
    println!(
        "BRACKET bob events ({} total, first 10): {:?}",
        bl.len(),
        &bl[..bl.len().min(10)]
    );
    drop(bl);
    drop(bob_d);
    drop(alice_d);
    println!(
        "BRACKET bob stderr: {}",
        std::fs::read_to_string(bob.join("daemon-bob.err")).unwrap_or_default()
    );
    println!(
        "BRACKET alice stderr: {}",
        std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default()
            + &std::fs::read_to_string(alice.join("daemon-alice2.err")).unwrap_or_default()
    );
}
