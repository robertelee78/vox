//! RP-05 — **one `WANT` cannot stop a room** (PRD-001 R4), through the shipped binary.
//!
//! A sync session holds its room's lock, and the serve phase answered a peer's `WANT` by
//! looping `from_seq..=to_seq` — one lookup per *number*, not per entry held. The ranges are
//! the peer's to write, so `WANT (author, 1, u64::MAX)`, which any member can send, started a
//! loop that would not end in the life of the machine with the room locked: nothing could be
//! posted to that room again. A thousand duplicate ranges also multiplied what was served.
//!
//! **Staging.** Every node is the real `vox` binary, set up as a person sets it up: an anchor
//! (`vox node`), a victim `vox daemon` that creates a room and posts [`HELD`] messages into it
//! with `vox room post`, and mallory, who gets an identity with `vox id` and joins with
//! `vox room join`. Mallory's daemon is then stopped and the attack is made **as mallory**, by
//! a test-side sync peer (`vox-core/tests/support/raw_sync.rs`) that opens mallory's profile
//! (the one the binary wrote) and speaks the ADR-008 frame sequence to the victim's real
//! daemon, choosing its own `WANT`. The node's own session code only asks for what the other
//! side's `HAVE` lists, so no `vox` command can send this request.
//!
//! **Asserted.**
//! 1. The victim **answers** mallory's session — `HELLO`, then a `HAVE` listing its feed — and
//!    the hostile `WANT` is on the wire before the post starts. A refused session would make
//!    the timing measure nothing, so it is `CANNOT MEASURE`.
//! 2. The `WANT` is 1,000 copies of `(victim, 1, u64::MAX)`, plus one feed the victim does not
//!    hold and one inverted range. While it is being served, **`vox room post` into the same
//!    room on the victim returns in under 5 s**, and the victim's `vox room read` shows it.
//! 3. Mallory is served each entry the victim holds **exactly once**: no repeats, and between
//!    the feed's length when the session began and that plus the one post made during the
//!    attack. The session ends cleanly.
//!
//! **Mutation that must turn it red.** Put the per-number loop back in
//! `log::sync::entries_for_wants` (`for seq in from_seq..=to_seq { feed.get(seq) }` over the
//! unmerged ranges). The serve then never finishes with the room locked, and the post does not
//! return inside the bound.

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

use raw_sync::{Ask, Yield};
use vox_core::log::sync::WantRange;
use vox_core::node::paths::Paths;
use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// An ordinary post must answer inside this while the `WANT` is served. A loopback post takes
/// well under a second; the defect is unbounded.
const PATIENCE: Duration = Duration::from_secs(5);
/// Posts the victim makes before the attack, so there is something to serve.
const HELD: usize = 50;
/// Copies of the absurd range in the `WANT`.
const DUPLICATES: usize = 1_000;
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
fn an_absurd_want_does_not_stop_the_room_it_names() {
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
    let victim_listen = format!("127.0.0.1:{}", free_udp_port());
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
    for i in 1..=HELD {
        let (ok, _, err) = vox_once(
            &victim_dir,
            &args(&["room", "post", &prefix, &format!("held {i}")]),
        );
        assert!(ok, "CANNOT MEASURE: post {i}: {err}");
    }
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

    // The victim's own feed a thousand times over, to the end of time; a feed it does not
    // hold; and an inverted range.
    let mut ranges = vec![
        WantRange {
            author_id: victim_id,
            from_seq: 1,
            to_seq: u64::MAX,
        };
        DUPLICATES
    ];
    ranges.push(WantRange {
        author_id: [0xEE; 32],
        from_seq: 1,
        to_seq: u64::MAX,
    });
    ranges.push(WantRange {
        author_id: victim_id,
        from_seq: u64::MAX,
        to_seq: 1,
    });

    // ---- 1. an answered session with the hostile WANT on the wire ------------------------
    let mut attack = None;
    for attempt in 1..=20 {
        let (tx, rx) = std::sync::mpsc::channel();
        let conn = Arc::clone(&conn);
        let ask = Ask::Ranges(ranges.clone());
        let task = rt.spawn(async move { raw_sync::ask(&conn, cid, 0, ask, Some(tx)).await });
        // Either the WANT goes out, or the session ends first (refused: the victim was syncing
        // this room with mallory at that moment) and it is asked again.
        let sent = loop {
            if rx.try_recv().is_ok() {
                break true;
            }
            if task.is_finished() {
                break false;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if sent {
            attack = Some(task);
            break;
        }
        eprintln!(
            "[proof] session attempt {attempt} ended before the WANT: {:?}",
            rt.block_on(task).unwrap()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let attack = attack.expect(
        "CANNOT MEASURE: the victim never answered mallory's session far enough to take a WANT, \
         so the timing below would measure nothing",
    );
    println!(
        "[proof] WANT on the wire: {} ranges ({DUPLICATES} x (victim, 1, u64::MAX), one unheld \
         feed, one inverted), room holds {HELD}+ posts",
        ranges.len()
    );

    // ---- 2. the room still works --------------------------------------------------------
    let text = "posted while the WANT was being served";
    let (ok, took, said) = vox_timed(&victim_dir, &["room", "post", &room, text], PATIENCE * 6);
    println!("[proof] post during the attack: ok={ok} in {took:?}");
    assert!(
        ok && took < PATIENCE,
        "a post into the room on the victim took {took:?} (ok={ok}; bound {PATIENCE:?}) while \
         one member's WANT (author, 1, u64::MAX) was being served — one request stops the room \
         (PRD-001 D2/R4). It said: {said}"
    );
    let (ok, t, read) = vox_timed(&victim_dir, &["room", "read", &room], PATIENCE * 6);
    println!(
        "[proof] read: ok={ok} in {t:?}, shows the post: {}",
        read.contains(text)
    );
    assert!(
        ok && t < PATIENCE && read.contains(text),
        "the victim's `vox room read` took {t:?} (ok={ok}) and did not show the post made \
         during the attack:\n{read}"
    );

    // ---- 3. what was served: each held entry once ---------------------------------------
    let y: Yield = rt
        .block_on(async { tokio::time::timeout(Duration::from_secs(60), attack).await })
        .expect("mallory's session did not end within 60 s")
        .unwrap();
    let feed = y
        .have
        .iter()
        .find(|(a, _)| *a == victim_id)
        .map_or(0, |(_, max)| *max);
    println!(
        "[proof] mallory's session: hello={} feed={feed} served={} distinct={} ended={:?}",
        y.hello, y.entries, y.distinct, y.ended
    );
    assert!(y.hello, "CANNOT MEASURE: the session was not answered");
    assert!(
        feed >= HELD as u64,
        "CANNOT MEASURE: the victim's HAVE lists {feed} entries in its feed, fewer than the \
         {HELD} it posted"
    );
    assert_eq!(
        y.distinct,
        y.entries,
        "the WANT must serve each entry once — {DUPLICATES} duplicate ranges merged — but {} of \
         the {} entries served were repeats",
        y.entries - y.distinct,
        y.entries
    );
    assert!(
        (feed..=feed + 1).contains(&(y.entries as u64)),
        "the WANT must be served the {feed} entries held, plus at most the one posted during \
         the attack — got {}",
        y.entries
    );
    assert_eq!(y.ended, None, "the session must end cleanly");
}
