//! RP-03 — **a silent stream cannot stop a node**, through the shipped binary.
//!
//! The node's actor is one task, the only writer of channel state (ADR-016), so anything it
//! awaits inline stops everything: commands, the tick, and once its queue fills, accepting
//! connections. A sync stream's preamble used to be read inside the actor, and a read on a
//! network stream is waited on for as long as `framing::FRAME_PATIENCE` (30 s) — the QUIC
//! keep-alive keeps the connection alive meanwhile. So a member who opened a `Sync` stream and
//! sent nothing held the whole node for 30 s, and could open another one every 30 s for ever.
//!
//! **Staging.** Every node is the real `vox` binary, set up as a person sets it up: an anchor
//! (`vox node`), a victim `vox daemon` that creates a room, and mallory, who gets an identity
//! with `vox id` and joins with `vox room join`. Mallory's daemon is then stopped, and the
//! attack is made **as mallory**, by a test-side client that opens mallory's profile (the one
//! the binary wrote) and speaks the Vox wire protocol to the victim's real daemon. No `vox`
//! command can open a stream and go silent, which is why a wire client plays the attacker; the
//! node under test is only ever the shipped binary.
//!
//! **Asserted.**
//! 1. The escalation: mallory's `Sync` stream reaches the victim's sync handler — an honest
//!    session over it is answered with the victim's `HAVE`, which lists the victim's feed. If
//!    this fails the attacker would be refused at the stream-kind gate and the rest would
//!    measure a refusal, so it is `CANNOT MEASURE`, never a pass.
//! 2. While mallory holds silent `Sync` streams open (a new one every 2 s, none of which ever
//!    carries a byte), **five `vox room post` on the victim, 2 s apart, each return in under
//!    5 s**, and the
//!    victim's `vox room read` shows all five.
//! 3. The attack was still holding at the end: mallory's connection was never closed, at
//!    least four silent streams were opened, and the first of them is still open at the
//!    victim's end (a read on it neither returns bytes nor ends) — accepted and waited on,
//!    not refused.
//!
//! **Mutation that must turn it red.** Put the sync-preamble read back on the actor: in
//! `node::actor`'s per-connection stream loop, forward `Inbound::Sync` to the actor unread,
//! and have the actor `read_sync_request(..).await` before `run_sync_session`. Each silent
//! stream then parks the actor for `FRAME_PATIENCE`, and the first post takes ~30 s.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/raw_sync.rs"]
mod raw_sync;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vox_core::node::paths::Paths;
use vox_core::transport::streams::{open_typed, StreamKind};
use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// An ordinary post must answer inside this while the attack holds. A loopback post takes
/// well under a second; the defect holds the node for 30 s per silent stream.
const PATIENCE: Duration = Duration::from_secs(5);
/// How many posts are measured.
const POSTS: usize = 5;
/// How often the attacker opens another silent stream.
const SILENT_EVERY: Duration = Duration::from_secs(2);
/// The pause between measured posts: five posts span 8 s, so at least four silent streams
/// are open by the last one.
const GAP: Duration = Duration::from_secs(2);
const SETUP: Duration = Duration::from_secs(120);
const ROOM_PASS: &str = "room passphrase";

fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run a one-shot `vox` verb, killing it (by PID) if it has not finished in `cap`. Returns
/// whether it succeeded, how long it ran, and what it printed. A verb still running at `cap`
/// is reported as a failure with its elapsed time, never waited on for ever.
fn vox_timed(data: &Path, argv: &[&str], cap: Duration) -> (bool, Duration, String) {
    let out_file = data.join(format!("timed-{}.out", std::process::id()));
    let t0 = Instant::now();
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(&out_file).unwrap()))
        .stderr(Stdio::from(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&out_file)
                .unwrap(),
        ))
        .spawn()
        .expect("run vox");
    let ok = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.success();
        }
        if t0.elapsed() >= cap {
            let _ = child.kill();
            let _ = child.wait();
            break false;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let took = t0.elapsed();
    (
        ok,
        took,
        std::fs::read_to_string(&out_file).unwrap_or_default(),
    )
}

/// The test-side client's runtime, shut down **without waiting** when dropped: a session
/// thread blocked on a victim that never answers must not hold the test open past its
/// verdict (ADR-018 §6).
struct Rt(Option<tokio::runtime::Runtime>);

impl std::ops::Deref for Rt {
    type Target = tokio::runtime::Runtime;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl Drop for Rt {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn daemon(name: &str, data: &Path, listen: &str, spec: &str, pass_file: &Path) -> VoxProc {
    let p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            listen,
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file.to_str().unwrap(),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("CANNOT MEASURE: {name}'s daemon never answered `vox room list`");
}

/// Stop a process with SIGTERM by its PID and reap it.
fn stop(mut p: VoxProc) {
    let _ = Command::new("kill")
        .args(["-TERM", &p.child.id().to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if matches!(p.child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Drop kills it by PID.
}

fn fingerprint(data: &Path) -> [u8; 32] {
    let (ok, out, err) = vox_once(data, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id: {err}");
    vox_core::node::link::b32_decode(out.trim(), "fingerprint")
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: vox id printed no fingerprint ({e:?}): {out}"))
}

#[test]
#[ignore = "real vox processes, production Argon2id and a real join; run in release"]
fn a_member_holding_silent_sync_streams_does_not_stop_the_node() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, victim_dir, mallory_dir) = (dir("anchor"), dir("victim"), dir("mallory"));
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();

    // ---- staging, all through the shipped binary ----------------------------------------
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("the anchor's spec", |l| l.contains("@/ip4/127.0.0.1/udp/"))
        .split_whitespace()
        .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        .unwrap()
        .to_owned();

    let victim_id = fingerprint(&victim_dir);
    let _ = fingerprint(&mallory_dir);
    let victim_port = free_udp_port();
    let victim_listen = format!("127.0.0.1:{victim_port}");
    let _victim = daemon("victim", &victim_dir, &victim_listen, &spec, &pass_file);
    let mallory = daemon("mallory", &mallory_dir, "127.0.0.1:0", &spec, &pass_file);

    let (ok, out, err) = vox_in(
        &victim_dir,
        &["room", "create", "--name", "team"],
        ROOM_PASS,
    );
    assert!(ok, "CANNOT MEASURE: room create: {out}\n{err}");
    let (_, list, _) = vox_once(&victim_dir, &args(&["room", "list"]));
    let prefix = list
        .split_whitespace()
        .next()
        .expect("CANNOT MEASURE: the new room in `vox room list`")
        .to_owned();
    let (ok, link, err) = vox_once(&victim_dir, &args(&["room", "invite", &prefix]));
    assert!(ok, "CANNOT MEASURE: room invite: {err}");
    let link = link.trim().to_owned();
    let joined = (1..=6).any(|attempt| {
        let (ok, out, err) = vox_in(
            &mallory_dir,
            &["room", "join", &link, "--name", "team"],
            ROOM_PASS,
        );
        if !ok {
            eprintln!("[proof] mallory's join attempt {attempt} refused: {out} {err}");
            std::thread::sleep(Duration::from_secs(5));
        }
        ok
    });
    assert!(joined, "CANNOT MEASURE: mallory could not join the room");

    // The room's full id, from a row the victim renders.
    let (ok, _, err) = vox_once(&victim_dir, &args(&["room", "post", &prefix, "hello"]));
    assert!(ok, "CANNOT MEASURE: first post: {err}");
    let (_, rows, _) = vox_once(&victim_dir, &args(&["room", "read", &prefix, "--json"]));
    let room = rows
        .lines()
        .find_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()?
                .get("room")?
                .as_str()
                .map(str::to_owned)
        })
        .expect("CANNOT MEASURE: the victim's read names its room");
    let cid = vox_core::node::link::b32_decode(&room, "room id").expect("a room id");

    // Mallory's node goes; her identity stays, in the profile the binary wrote.
    stop(mallory);

    let rt = Rt(Some(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap(),
    ));
    let _enter = rt.enter();
    let mallory_paths = Paths::resolve(
        "default",
        Some(&mallory_dir),
        Some(&mallory_dir.join("cfg")),
    )
    .unwrap();
    let (_endpoint, conn) = rt.block_on(async {
        let endpoint = raw_sync::endpoint_as_member(&mallory_paths, IDENTITY.as_bytes()).await;
        let conn = endpoint
            .connect(victim_listen.parse().unwrap(), victim_id, raw_sync::now())
            .await
            .expect("CANNOT MEASURE: mallory's identity did not connect to the victim");
        (endpoint, Arc::new(conn))
    });
    let _answered = raw_sync::answer_victim(Arc::clone(&conn));

    // ---- 1. the escalation: mallory's Sync stream reaches the sync handler --------------
    let mut reached = None;
    for attempt in 1..=20 {
        let y = rt.block_on(raw_sync::ask(
            &conn,
            cid,
            0,
            raw_sync::Ask::Everything,
            None,
        ));
        if y.hello && y.have.iter().any(|(a, _)| *a == victim_id) {
            reached = Some(y);
            break;
        }
        eprintln!("[proof] honest session attempt {attempt} not answered: {y:?}");
        std::thread::sleep(Duration::from_millis(500));
    }
    let honest = reached.expect(
        "CANNOT MEASURE: mallory's Sync stream was never answered with the victim's HAVE, so a \
         silent one would be refused at the stream-kind gate and this would measure a refusal",
    );
    println!(
        "[proof] escalation: mallory's Sync stream answered, HAVE lists {} feed(s), {} entries \
         served",
        honest.frontiers, honest.entries
    );

    // ---- 2. the attack holds while a person uses the node -------------------------------
    let silent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attack = {
        let (conn, silent, opened) = (Arc::clone(&conn), Arc::clone(&silent), Arc::clone(&opened));
        rt.spawn(async move {
            loop {
                match open_typed(&conn, StreamKind::Sync).await {
                    // Kept, never written to: zero bytes after the stream's kind.
                    Ok(pair) => {
                        silent.lock().unwrap().push(pair);
                        opened.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(e) => eprintln!("[proof] could not open a silent stream: {e:?}"),
                }
                tokio::time::sleep(SILENT_EVERY).await;
            }
        })
    };
    // The first silent stream is on the wire before the first post.
    let t0 = Instant::now();
    while opened.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "CANNOT MEASURE: no silent stream could be opened"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));

    let mut took = Vec::new();
    for i in 1..=POSTS {
        // Spaced, so the attack spans several silent streams rather than one.
        if i > 1 {
            std::thread::sleep(GAP);
        }
        let text = format!("posted while a member holds silent streams {i}");
        let (ok, t, said) = vox_timed(&victim_dir, &["room", "post", &room, &text], PATIENCE * 8);
        println!(
            "[proof] post {i}/{POSTS}: ok={ok} in {t:?} with {} silent stream(s) open",
            opened.load(std::sync::atomic::Ordering::SeqCst)
        );
        took.push(t);
        assert!(
            ok && t < PATIENCE,
            "post {i} of {POSTS} on the victim took {t:?} (ok={ok}; bound {PATIENCE:?}) while a \
             member held silent Sync streams open — a stream carrying zero bytes stops the \
             node. It said: {said}"
        );
    }
    let (ok, t, read) = vox_timed(&victim_dir, &["room", "read", &room], PATIENCE * 8);
    let shown = (1..=POSTS)
        .filter(|i| read.contains(&format!("posted while a member holds silent streams {i}")))
        .count();
    println!("[proof] read: ok={ok} in {t:?}, shows {shown}/{POSTS} posts");
    assert!(
        ok && t < PATIENCE && shown == POSTS,
        "the victim's `vox room read` took {t:?} (ok={ok}) and showed {shown} of {POSTS} posts \
         made during the attack:\n{read}"
    );

    // ---- 3. the attack was still holding ------------------------------------------------
    attack.abort();
    let streams = opened.load(std::sync::atomic::Ordering::SeqCst);
    let mut held = std::mem::take(&mut *silent.lock().unwrap());
    // The first silent stream is still open at the victim's end: it was accepted and is being
    // waited on, not refused. A read on it neither returns bytes nor ends.
    let first_still_held = rt.block_on(async {
        let (_send, recv) = held.first_mut().expect("a silent stream");
        let mut buf = [0u8; 16];
        tokio::time::timeout(Duration::from_millis(300), recv.read(&mut buf))
            .await
            .is_err()
    });
    assert!(
        first_still_held,
        "CANNOT MEASURE: the victim had already closed or refused the first silent stream, so \
         the attack was not holding"
    );
    assert!(
        conn.quinn().close_reason().is_none(),
        "CANNOT MEASURE: mallory's connection closed during the attack: {:?}",
        conn.quinn().close_reason()
    );
    assert!(
        streams >= 4,
        "CANNOT MEASURE: only {streams} silent stream(s) were opened"
    );
    println!(
        "[proof] {POSTS} posts, slowest {:?}, while {streams} silent Sync streams were held",
        took.iter().max().unwrap()
    );
    drop(held);
}
