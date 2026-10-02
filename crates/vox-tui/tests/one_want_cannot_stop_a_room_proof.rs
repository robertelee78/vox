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
//! **A red names its side.** The claim's assertions (the post and the read during the attack,
//! each entry served once, a clean end) are PRODUCT and quote what vox did. A `vox` command
//! that fails while the scene is set (an identity, a daemon, the room, its posts, the invite,
//! the join) is the product failing: PRODUCT (staging). What the attacker itself must achieve
//! (its connection, an answered session with the `WANT` on the wire, a `HAVE` that lists the
//! feed) is CANNOT MEASURE. The test's own processes, files, ports and runtime are APPARATUS.
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
        .expect("APPARATUS: run vox");
    child
        .stdin
        .take()
        .expect("APPARATUS: vox's stdin")
        .write_all(stdin.as_bytes())
        .expect("APPARATUS: write to vox's stdin");
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// How a timed verb ended, for a red to quote.
#[derive(Debug)]
enum Ended {
    /// It exited, successfully or not, with this status.
    Exited(std::process::ExitStatus),
    /// It was still running at the cap and was killed.
    Killed,
}

impl std::fmt::Display for Ended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ended::Exited(st) => write!(f, "it exited with {st}"),
            Ended::Killed => write!(f, "it had not returned when it was killed at the cap"),
        }
    }
}

/// Run a one-shot `vox` verb, killing it (by PID) if it has not finished in `cap`. Returns
/// whether it succeeded, how long it ran, how it ended, and what it printed. A verb still
/// running at `cap` is reported as a failure with its elapsed time, never waited on for ever.
fn vox_timed(data: &Path, argv: &[&str], cap: Duration) -> (bool, Duration, Ended, String) {
    let out_file = data.join(format!("timed-{}.out", std::process::id()));
    let t0 = Instant::now();
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            std::fs::File::create(&out_file).expect("APPARATUS: the verb's output file"),
        ))
        .stderr(Stdio::from(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&out_file)
                .expect("APPARATUS: the verb's output file"),
        ))
        .spawn()
        .expect("APPARATUS: run vox");
    let ended = loop {
        if let Some(status) = child.try_wait().expect("APPARATUS: wait on vox") {
            break Ended::Exited(status);
        }
        if t0.elapsed() >= cap {
            let _ = child.kill();
            let _ = child.wait();
            break Ended::Killed;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let took = t0.elapsed();
    let ok = matches!(&ended, Ended::Exited(st) if st.success());
    (
        ok,
        took,
        ended,
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
        self.0.as_ref().expect("APPARATUS: the client's runtime")
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
        .and_then(|s| s.local_addr())
        .expect("APPARATUS: a free UDP port")
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
            pass_file.to_str().expect("APPARATUS: a UTF-8 path"),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("PRODUCT (staging): {name}'s daemon never answered `vox room list`");
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
    assert!(ok, "PRODUCT (staging): vox id: {err}");
    vox_core::node::link::b32_decode(out.trim(), "fingerprint").unwrap_or_else(|e| {
        panic!("PRODUCT (staging): vox id printed no fingerprint ({e:?}): {out}")
    })
}

#[test]
#[ignore = "real vox processes, production Argon2id and a real join; run in release"]
fn an_absurd_want_does_not_stop_the_room_it_names() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: a profile directory");
        d
    };
    let (anchor_dir, victim_dir, mallory_dir) = (dir("anchor"), dir("victim"), dir("mallory"));
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).expect("APPARATUS: the passphrase file");

    // ---- staging, all through the shipped binary ----------------------------------------
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("PRODUCT (staging): the anchor's spec", |l| {
            l.contains("@/ip4/127.0.0.1/udp/")
        })
        .split_whitespace()
        .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        .expect("PRODUCT (staging): the anchor's spec line holds no spec")
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
    assert!(ok, "PRODUCT (staging): vox room create: {out}\n{err}");
    let (_, list, _) = vox_once(&victim_dir, &args(&["room", "list"]));
    let prefix = list
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): the new room in `vox room list`")
        .to_owned();
    for i in 1..=HELD {
        let (ok, _, err) = vox_once(
            &victim_dir,
            &args(&["room", "post", &prefix, &format!("held {i}")]),
        );
        assert!(ok, "PRODUCT (staging): vox room post {i}: {err}");
    }
    let (ok, link, err) = vox_once(&victim_dir, &args(&["room", "invite", &prefix]));
    assert!(ok, "PRODUCT (staging): vox room invite: {err}");
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
    assert!(joined, "PRODUCT (staging): mallory could not join the room");
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
        .expect("PRODUCT (staging): the victim's `vox room read --json` names its room");
    let cid = vox_core::node::link::b32_decode(&room, "room id")
        .expect("PRODUCT (staging): the room id `vox room read --json` printed");

    // Mallory's node goes; her identity stays, in the profile the binary wrote.
    stop(mallory);

    let rt = Rt(Some(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("APPARATUS: the client's runtime"),
    ));
    let _enter = rt.enter();
    let mallory_paths = Paths::resolve(
        "default",
        Some(&mallory_dir),
        Some(&mallory_dir.join("cfg")),
    )
    .expect("APPARATUS: mallory's profile paths");
    let (_endpoint, conn) = rt.block_on(async {
        let endpoint = raw_sync::endpoint_as_member(&mallory_paths, IDENTITY.as_bytes()).await;
        let conn = endpoint
            .connect(
                victim_listen
                    .parse()
                    .expect("APPARATUS: the victim's address"),
                victim_id,
                raw_sync::now(),
            )
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
            rt.block_on(task)
                .expect("APPARATUS: the attacker's session task panicked")
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
    let (ok, took, ended, said) =
        vox_timed(&victim_dir, &["room", "post", &room, text], PATIENCE * 6);
    println!("[proof] post during the attack: ok={ok} in {took:?}; {ended}");
    assert!(
        ok && took < PATIENCE,
        "PRODUCT: a post into the room on the victim took {took:?} (ok={ok}; bound {PATIENCE:?}) \
         while one member's WANT (author, 1, u64::MAX) was being served — one request stops the \
         room (PRD-001 D2/R4). `vox room post`: {ended}, printing {said:?}"
    );
    let (ok, t, ended, read) = vox_timed(&victim_dir, &["room", "read", &room], PATIENCE * 6);
    println!(
        "[proof] read: ok={ok} in {t:?}; {ended}; shows the post: {}",
        read.contains(text)
    );
    assert!(
        ok && t < PATIENCE && read.contains(text),
        "PRODUCT: the victim's `vox room read` took {t:?} (ok={ok}; bound {PATIENCE:?}; {ended}) \
         and must show the post made during the attack; it printed {read:?}"
    );

    // ---- 3. what was served: each held entry once ---------------------------------------
    // The attacker's session only reads what the victim sends until the victim ends the stream,
    // and it has been answered (the WANT went out on an answered session, above). So a session
    // still open after 60 s is the victim never finishing its serve: PRODUCT. A session task that
    // panicked is the test's client: APPARATUS.
    let y: Yield = rt
        .block_on(async { tokio::time::timeout(Duration::from_secs(60), attack).await })
        .expect(
            "PRODUCT: the victim did not end mallory's answered session within 60 s of taking \
             her WANT — its serve never finished",
        )
        .expect("APPARATUS: the attacker's session task panicked");
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
        "PRODUCT: the WANT must serve each entry once — {DUPLICATES} duplicate ranges merged — but {} of \
         the {} entries served were repeats",
        y.entries - y.distinct,
        y.entries
    );
    assert!(
        (feed..=feed + 1).contains(&(y.entries as u64)),
        "PRODUCT: the WANT must be served the {feed} entries held, plus at most the one posted during \
         the attack — got {}",
        y.entries
    );
    assert_eq!(
        y.ended, None,
        "PRODUCT: the victim must end mallory's session cleanly"
    );
}
