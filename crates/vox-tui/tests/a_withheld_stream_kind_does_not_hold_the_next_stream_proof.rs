//! V210-80 (#271) — **a stream whose kind is withheld does not hold the peer's next stream**,
//! through the shipped binary.
//!
//! Every stream on a Vox connection starts with a frame naming its kind. The node's per-connection
//! stream loop read that frame **inline**, one stream at a time, and a read on a network stream
//! waits up to `framing::FRAME_PATIENCE` (30 s). So a peer that opened a stream and withheld its
//! kind held every stream it opened after it — its syncs, its keys, its board puts — for 30 s, and
//! could do it again every 30 s. Each stream's kind is now read on a task of its own, and a stream
//! still untyped past a short grace no longer holds the ones behind it.
//!
//! **Staging** (the same as `a_silent_stream_cannot_stop_a_node_proof`, whose helpers this copies).
//! Every node is the real `vox` binary: an anchor (`vox node`), a victim `vox daemon` that creates
//! a room, and mallory, who gets an identity with `vox id` and joins with `vox room join`. Mallory's
//! daemon is then stopped, and the attack is made **as mallory**, by a test-side client that opens
//! mallory's profile and speaks the Vox wire protocol to the victim's real daemon. No `vox` command
//! can open a stream and withhold its kind, which is why a wire client plays the attacker; the
//! node under test is only ever the shipped binary.
//!
//! **Asserted.**
//! 1. The escalation: an honest `Sync` session of mallory's is answered with the victim's `HAVE`
//!    (else `CANNOT MEASURE`: the rest would measure a refusal).
//! 2. In each of [`ROUNDS`] rounds, mallory opens a stream and sends **two bytes of its four-byte
//!    kind-frame length** and nothing else, then runs an honest `Sync` session on a new stream:
//!    it is answered with the victim's `HAVE` within [`BOUND`].
//! 3. The attack held: every withheld stream is still open at the victim's end at the last
//!    session's answer (a read on the first neither returns bytes nor ends), and mallory's
//!    connection was never closed.
//!
//! **Mutation that must turn it red:** hold a typed stream behind an untyped one for as long as its
//! read may take (`KIND_ORDER_GRACE` raised past `FRAME_PATIENCE`), which is what the inline read
//! did: each session is then answered only when the withheld stream's read gives up, ~30 s.

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
use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// An honest session behind a withheld stream is answered inside this. Unwithheld it takes well
/// under a second on loopback; the kind-order grace is 2 s; the defect holds it for 30 s.
const BOUND: Duration = Duration::from_secs(8);
/// How many withheld streams, each followed by an honest session.
const ROUNDS: usize = 3;
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
fn a_withheld_stream_kind_does_not_hold_the_next_stream() {
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

    // ---- 2. a withheld stream, then an honest session behind it, ROUNDS times ------------
    let mut withheld = Vec::new();
    let mut took = Vec::new();
    for round in 1..=ROUNDS {
        let pair = rt.block_on(async {
            let (mut send, recv) = conn
                .open_stream()
                .await
                .expect("CANNOT MEASURE: mallory could not open a stream");
            // Half of the kind frame's length prefix: the stream is announced to the victim, and
            // its kind can never be read.
            send.write_all(&[0u8, 0u8])
                .await
                .expect("CANNOT MEASURE: the withheld stream's two bytes did not go out");
            (send, recv)
        });
        withheld.push(pair);
        // Let the victim accept it, so the honest stream arrives behind it.
        std::thread::sleep(Duration::from_millis(300));
        let t = Instant::now();
        let y = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(60),
                raw_sync::ask(&conn, cid, 0, raw_sync::Ask::Everything, None),
            )
            .await
        });
        let t = t.elapsed();
        let answered = y
            .as_ref()
            .is_ok_and(|y| y.hello && y.have.iter().any(|(a, _)| *a == victim_id));
        println!(
            "[proof] round {round}/{ROUNDS}: the session behind {} withheld stream(s) answered={answered} in {t:?}",
            withheld.len()
        );
        took.push(t);
        assert!(
            answered && t < BOUND,
            "round {round}: an honest Sync session opened behind a stream whose kind was withheld \
             was answered={answered} after {t:?} (bound {BOUND:?}) — a withheld kind holds the \
             peer's next stream"
        );
    }

    // ---- 3. the attack held ---------------------------------------------------------------
    let first_still_held = rt.block_on(async {
        let (_send, recv) = withheld.first_mut().expect("a withheld stream");
        let mut buf = [0u8; 16];
        tokio::time::timeout(Duration::from_millis(300), recv.read(&mut buf))
            .await
            .is_err()
    });
    assert!(
        first_still_held,
        "CANNOT MEASURE: the victim had already closed or refused the first withheld stream, so \
         the attack was not holding"
    );
    assert!(
        conn.quinn().close_reason().is_none(),
        "CANNOT MEASURE: mallory's connection closed during the attack: {:?}",
        conn.quinn().close_reason()
    );
    println!(
        "[proof] {ROUNDS} honest sessions behind withheld streams, slowest {:?} (bound {BOUND:?})",
        took.iter().max().unwrap()
    );
    drop(withheld);
}
