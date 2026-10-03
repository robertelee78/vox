//! **V210-30 — a member trusted while unreachable reads every post made from the moment of
//! trust**, once it is reached, through the shipped `vox` binary.
//!
//! Trusting a member releases this identity's sender key to it (a consent). Rooms are
//! forward-only: a member reads from the position the key is released at. When the member could
//! not be reached at the moment of trust, the release waited, and the key was built only when it
//! could finally be delivered — from the chain's position **then**. Every post made in between
//! was sealed before that position, so the member could never read it.
//!
//! What this drives: bob (`127.0.0.1`) and carol (`[::1]`) reach each other only through the
//! anchor's relay. With the anchor **frozen** (SIGSTOP), carol trusts bob — who cannot be reached
//! — and posts. The anchor is released; bob must come to read that post.
//!
//! Two defects stood between bob and that post, and both are fixed with this proof:
//!
//! 1. the key was built at delivery, from a later position. This proof forces it: with the key
//!    built at delivery it is red every run;
//! 2. a key that arrives before its consent grant left what bob already held unrendered, because
//!    rendering was retried when a key arrived and never when a grant did (#210). This proof
//!    exercises it only when bob holds the post before the grant arrives, which the relay does not
//!    force: with that half removed it went red 1 run in 2. #210 owns a proof that forces it.

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

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "room passphrase";
/// How long the relay is held frozen while both members open their sessions.
const FREEZE: Duration = Duration::from_secs(4);

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
        .expect("APPARATUS: could not spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("APPARATUS: vox's stdin");
        pipe.write_all(text.as_bytes())
            .expect("APPARATUS: write vox's stdin");
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn reads(dir: &std::path::Path, room: &str, text: &str) -> bool {
    vox(dir, &["room", "read", room], None).1.contains(text)
}

fn until(what: &str, secs: u64, ok: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("[proof] {what}: not within {secs} s");
    false
}

/// A daemon, killed by its own PID however the test ends, its output kept.
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
        .expect("APPARATUS: could not spawn a daemon");
    let mut pipe = child.stdin.take().expect("APPARATUS: the daemon's stdin");
    pipe.write_all(format!("{IDPASS}\n").as_bytes())
        .expect("APPARATUS: write the daemon's stdin");
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
                        .expect("APPARATUS: a lock the proof holds was poisoned")
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }
    let d = Daemon(child, said);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !d
        .1
        .lock()
        .expect("APPARATUS: a lock the proof holds was poisoned")
        .contains("control socket")
    {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): a daemon never served its control socket within 90 s:\n{}",
            d.1.lock()
                .expect("APPARATUS: a lock the proof holds was poisoned")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: `kill {sig} {pid}` failed");
}

#[test]
#[ignore = "three daemons and a relay anchor with production Argon2id; CI runs it in release"]
fn a_member_trusted_while_unreachable_reads_the_posts_made_meanwhile() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let dirs: Vec<std::path::PathBuf> = ["alice", "bob", "carol"]
        .iter()
        .map(|n| tmp.path().join(n))
        .collect();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: a profile dir");
    }
    let (alice_dir, bob_dir, carol_dir) = (&dirs[0], &dirs[1], &dirs[2]);
    let anchor = Anchor::start(&tmp.path().join("anchor"));
    let mut fps = Vec::new();
    for d in &dirs {
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
        fps.push(out.trim().to_owned());
    }
    let _alice = daemon(alice_dir, "127.0.0.1:0", &anchor.v4_spec);
    let bob_d = daemon(bob_dir, "127.0.0.1:0", &anchor.v4_spec);
    let carol_spec = Split::Families.guest_spec(&anchor).to_owned();
    let carol_d = daemon(carol_dir, Split::Families.guest_listen(), &carol_spec);

    for (i, name) in [(1usize, "bob"), (2, "carol")] {
        let (ok, _, err) = vox(alice_dir, &["trust", "add", &fps[i], "--name", name], None);
        assert!(
            ok,
            "PRODUCT (staging): alice's `vox trust add {name}` failed: {err}"
        );
        let (ok, _, err) = vox(
            &dirs[i],
            &["trust", "add", &fps[0], "--name", "alice"],
            None,
        );
        assert!(
            ok,
            "PRODUCT (staging): {name}'s `vox trust add alice` failed: {err}"
        );
    }
    let (ok, _, err) = vox(
        alice_dir,
        &["room", "create", "--name", "late"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room create` failed: {err}");
    let listed = vox(alice_dir, &["room", "list"], None).1;
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): `vox room list` names no room after `room create`: {listed:?}"
            )
        })
        .to_owned();
    let (ok, link, err) = vox(alice_dir, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): `vox room invite` failed: {err}");
    for d in [bob_dir, carol_dir] {
        let (ok, _, err) = vox(
            d,
            &["room", "join", link.trim(), "--name", "late"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "PRODUCT (staging): `vox room join` failed: {err}");
    }
    // Bob trusts carol from the start: a node reads only whom its owner trusts (V210-118), so
    // what this measures is carol's decision alone.
    let (ok, _, err) = vox(bob_dir, &["trust", "add", &fps[2], "--name", "carol"], None);
    assert!(ok, "PRODUCT (staging): bob trusts carol: {err}");
    // Both hold the room and each other's admission before carol decides anything.
    let (ok, _, err) = vox(
        carol_dir,
        &["room", "post", &room, "CAROL-BEFORE-TRUST"],
        None,
    );
    assert!(
        ok,
        "PRODUCT (staging): carol's first post was refused: {err}"
    );
    assert!(
        until("bob holds carol's entry (unreadable yet)", 60, || {
            vox(bob_dir, &["room", "read", &room, "--json"], None)
                .1
                .contains(&fps[2][..20])
                || reads(alice_dir, &room, "CAROL-BEFORE-TRUST")
        }),
        "PRODUCT (staging): carol's first post never reached the room in 60 s"
    );
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !reads(bob_dir, &room, "CAROL-BEFORE-TRUST"),
        "PRODUCT: forward-only: bob reads what carol posted before she trusted him"
    );

    // **Which arrived first at bob, carol's key or her consent**, from bob's own events: a key
    // that renders what bob held (`backfilled` ≥ 1) came after the consent; one that renders
    // nothing came before it, and then only a render on the consent's arrival shows the post
    // (#210). Printed per run, so a red can be tied to the order that produced it.
    let key_events = Arc::new(Mutex::new(Vec::<(Duration, u64)>::new()));
    {
        let sock = vox_core::node::paths::Paths::resolve(
            "default",
            Some(bob_dir),
            Some(&bob_dir.join("cfg")),
        )
        .expect("APPARATUS: bob's profile paths")
        .socket_file();
        let carol = vox_core::node::link::b32_decode(&fps[2], "carol")
            .expect("PRODUCT (staging): carol's `vox id` printed no fingerprint");
        let sink = Arc::clone(&key_events);
        let t0 = Instant::now();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("APPARATUS: a runtime for bob's event watch");
            rt.block_on(async move {
                let Ok(mut c) = vox_core::node::ipc::IpcClient::open(&sock).await else {
                    return;
                };
                if c.subscribe().await.is_err() {
                    return;
                }
                while let Ok(Some(frame)) = c.next().await {
                    if let vox_core::node::ipc::Frame::Event(
                        vox_core::node::api::NodeEvent::SenderKeyReceived {
                            peer, backfilled, ..
                        },
                    ) = frame
                    {
                        if peer == carol {
                            sink.lock()
                                .expect("APPARATUS: a lock the proof holds was poisoned")
                                .push((t0.elapsed(), backfilled));
                        }
                    }
                }
            });
        });
    }

    // ---- with bob unreachable, carol trusts him and posts ----
    let anchor_pid = anchor.proc.child.id();
    signal(anchor_pid, "-STOP");
    let frozen = Instant::now();
    let (ok, _, err) = vox(carol_dir, &["trust", "add", &fps[1], "--name", "bob"], None);
    assert!(
        ok,
        "PRODUCT (staging): carol's `vox trust add bob` failed: {err}"
    );
    let (ok, _, err) = vox(
        carol_dir,
        &["room", "post", &room, "CAROL-WHILE-UNREACHABLE"],
        None,
    );
    assert!(
        ok,
        "PRODUCT (staging): carol's post while bob was unreachable was refused: {err}"
    );
    std::thread::sleep(FREEZE.saturating_sub(frozen.elapsed()));
    signal(anchor_pid, "-CONT");
    eprintln!(
        "[proof] relay frozen {:?}: carol trusted bob, then posted",
        frozen.elapsed()
    );

    // ---- once reached, bob reads the post made after the trust ----
    let read = until("bob reads CAROL-WHILE-UNREACHABLE", 90, || {
        reads(bob_dir, &room, "CAROL-WHILE-UNREACHABLE")
    });
    for (at, backfilled) in key_events
        .lock()
        .expect("APPARATUS: a lock the proof holds was poisoned")
        .iter()
    {
        eprintln!(
            "[order] carol's key reached bob at +{at:.1?}, rendering {backfilled} held post(s): {}",
            if *backfilled == 0 {
                "the key came before the consent (the post can render only when the consent arrives)"
            } else {
                "the consent was already there"
            }
        );
    }
    let (ok, _, err) = vox(carol_dir, &["room", "post", &room, "CAROL-AFTER"], None);
    assert!(
        ok,
        "PRODUCT: carol's post after the trust was refused: {err}"
    );
    let later = until("bob reads CAROL-AFTER", 60, || {
        reads(bob_dir, &room, "CAROL-AFTER")
    });
    eprintln!(
        "[proof] bob reads the post made while unreachable = {read}; a post made after = {later}"
    );
    let said = || {
        format!(
            "\n--- bob's daemon said:\n{}\n--- carol's daemon said:\n{}",
            bob_d
                .1
                .lock()
                .expect("APPARATUS: a lock the proof holds was poisoned"),
            carol_d
                .1
                .lock()
                .expect("APPARATUS: a lock the proof holds was poisoned")
        )
    };
    assert!(
        later,
        "PRODUCT (staging): bob never read carol at all, even a post made after he was reached{}",
        said()
    );
    assert!(
        read,
        "PRODUCT: a member trusted while unreachable lost the post made between the trust and \
         reaching it{}",
        said()
    );
    assert!(
        !reads(bob_dir, &room, "CAROL-BEFORE-TRUST"),
        "PRODUCT: forward-only: bob must not read what carol posted before she trusted him{}",
        said()
    );
}
